"""MOAVI Desk: build results kept (pegaprox/vlab/artifacts.py) and CI connections (pegaprox/vlab/ci.py).

  GET    /api/vlab/admin/build-artifacts                  {default, pools}                       vlab.pool.view
  PUT    /api/vlab/admin/build-artifacts/<scope>          scope _default or a pool id; body null drops a pool's own   vlab.pool.manage
  GET    /api/vlab/me/build-jobs/<jid>/artifacts/<int:i>  the job owner's result file i           vlab.desk
  GET    /api/vlab/admin/build-jobs/<jid>/artifacts/<int:i>                                       vlab.pool.manage
  GET    /api/vlab/admin/ci-links                         the CI connections                      vlab.pool.view
  POST   /api/vlab/admin/ci-links                         {name, kind, pool_id, owner, command, workdir?, allow_command?, expires_at?} -> + token once  vlab.pool.manage
  PUT    /api/vlab/admin/ci-links/<lid>                                                           vlab.pool.manage
  DELETE /api/vlab/admin/ci-links/<lid>                                                           vlab.pool.manage
  POST   /api/vlab/admin/ci-links/<lid>/token             a new token (the old one stops)         vlab.pool.manage

The CI's own calls carry the connection token (Authorization: Bearer mci_..., or X-Moavi-CI-Token):

  POST   /api/vlab/ci/jobs                                {name?, command?, repo?, ref?, commit?, url?, pipeline?, author?, message?}
  GET    /api/vlab/ci/jobs/<jid>                          status, exit code, the output's end, result files
  GET    /api/vlab/ci/jobs/<jid>/artifacts/<int:i>        one result file
  POST   /api/vlab/ci/jobs/<jid>/cancel                   a queued job
"""
import base64
import json
import logging
import os

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.api import vlab_next as vn
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import artifacts, catalog, ci, nas, store

bp = Blueprint('vlab_builds', __name__)


def _user():
    return request.session.get('user', '')


def _bad(msg, status=400, **extra):
    return jsonify(dict({'error': msg}, **extra)), status


# --- collecting, at the end of a job -------------------------------------------------------

def collect(job, desk, mgr, node):
    """List (and keep on the NAS) the result files of an ended job. Never raises."""
    try:
        pool = store.get_pool(job['pool_id']) if job.get('pool_id') else None
        s = artifacts.get(job.get('pool_id'))
        if not pool or not s['enabled'] or not s['patterns'] or not job.get('workdir'):
            return
        cfg = vn.storage_config(pool['id'])
        user = nas.guest_name(job['username'])
        dest, root = artifacts.dest_for(cfg, user, job['id'])
        script = artifacts.collect_script(job['workdir'], dest, root, s)
        argv = ['/bin/sh', '-c', script]
        if user and cfg and job['workdir'].startswith(cfg['linux_path'] + '/'):
            argv = ['runuser', '-u', user, '--'] + argv
        code, out, err, e = vn._agent_run(mgr, node, desk['vmid'], argv, wait=30.0)
        if code is None or code != 0:
            logging.info(f"[VLAB] results of job {job['id']}: {e or (err or '').strip()[-200:] or code}")
            return
        kept, files = artifacts.parse_collect(out)
        catalog.update_build_job(job['id'], artifacts=json.dumps(files, ensure_ascii=False), artifacts_dir=kept)
    except Exception as ex:
        logging.warning(f"[VLAB] results of job {job.get('id')}: {ex}")


def job_extra_view(job):
    """What _job_view adds: the result files and where they came from."""
    files = artifacts.listed(job)
    return {'artifacts': files, 'artifacts_kept': ('nas' if '/artifacts/' in (job.get('artifacts_dir') or '') else
                                                    'workdir' if job.get('artifacts_dir') else ''),
            'source': ci.source_of(job) or None}


# --- downloading ---------------------------------------------------------------------------

def _download(job, i, username, check_rule=True):
    from pegaprox.api import vlab_data as vd
    from pegaprox.vlab import datasets as ds_mod
    files = artifacts.listed(job)
    if not 0 <= i < len(files) or not job.get('artifacts_dir'):
        return _bad('No such result file', 404)
    f = files[i]
    name = f['path'].rsplit('/', 1)[-1]
    pool = store.get_pool(job['pool_id']) if job.get('pool_id') else None
    if check_rule and pool:
        blocked = vd._rule_answer(ds_mod.get_policy(pool['id'])['export'])
        if blocked:
            return blocked
    guest_path = f"{job['artifacts_dir'].rstrip('/')}/{f['path']}"
    log = {'pool_id': job.get('pool_id') or '', 'folder': 'artifacts', 'path': guest_path, 'request_id': ''}
    cfg = vn.storage_config(pool['id']) if pool else None
    if cfg and cfg.get('admin_path') and guest_path.startswith(cfg['linux_path'].rstrip('/') + '/'):
        rel = guest_path[len(cfg['linux_path'].rstrip('/')) + 1:]
        try:
            root = vd._engine_root(cfg, rel)
        except ValueError:
            root = None
        if root and os.path.isfile(root):
            return vd._send_path(root, name, username, log)
    desk = store.get_desktop(job['desktop_id']) if job.get('desktop_id') else None
    mgr = cluster_managers.get(desk['cluster_id']) if desk else None
    if not desk or not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('The build VM that holds the file is not reachable', 409, code='NO_ROUTE')
    if f['size'] > ds_mod.AGENT_MAX_BYTES:
        return _bad(f"Larger than {ds_mod.AGENT_MAX_BYTES // 1048576} MB - take it from 데이터 › 내 폴더 or SFTP "
                    "(or ask the admin for the NAS admin mount)", 413, code='TOO_BIG')
    node = vn._job_node(desk)
    user = nas.guest_name(job['username'])
    q = vd._q
    sh = (f'P={q(guest_path)}; [ -f "$P" ] || {{ echo "not found" >&2; exit 21; }}; '
          f'S=$(stat -c %s "$P"); [ "$S" -le {ds_mod.AGENT_MAX_BYTES} ] || exit 22; base64 -w0 "$P"')
    argv = ['/bin/sh', '-c', sh]
    if user and cfg and guest_path.startswith(cfg['linux_path'] + '/'):
        argv = ['runuser', '-u', user, '--'] + argv
    code, out, err, e = vn._agent_run(mgr, node, desk['vmid'], argv, wait=60.0)
    if code is None:
        return _bad(e or 'the build VM did not answer in time', 504)
    if code != 0:
        return _bad('The file is not there any more (the work folder was cleaned)' if code == 21 else (err or 'guest agent error')[-300:],
                    404 if code == 21 else 502)
    try:
        data = base64.b64decode(out.strip() or b'')
    except ValueError:
        return _bad('the build VM sent something that is not base64', 502)
    return vd._send_bytes(data, name, username, log)


@bp.route('/api/vlab/me/build-jobs/<jid>/artifacts/<int:i>', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_artifact(jid, i):
    job = catalog.get_build_job(jid)
    if not job or job['username'] != _user():
        return _bad('Job not found', 404)
    return _download(job, i, _user())


@bp.route('/api/vlab/admin/build-jobs/<jid>/artifacts/<int:i>', methods=['GET'])
@require_auth(perms=['vlab.pool.manage'])
def admin_artifact(jid, i):
    job = catalog.get_build_job(jid)
    pool = store.get_pool(job['pool_id']) if job and job.get('pool_id') else None
    if not job or (pool and not core._can_reach(pool['cluster_id'])):
        return _bad('Job not found', 404)
    return _download(job, i, _user())


# --- settings of what is kept --------------------------------------------------------------

def _farm_pools():
    return [p for p in store.list_pools() if p['type'] == 'buildfarm' and core._can_reach(p['cluster_id'])]


@bp.route('/api/vlab/admin/build-artifacts', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_artifact_settings():
    own = artifacts.overrides()
    return jsonify({'default': artifacts.get(None), 'pools': [
        {'id': p['id'], 'name': p['name'], 'own': p['id'] in own, 'settings': artifacts.get(p['id']),
         'storage': bool(vn.storage_config(p['id']))} for p in _farm_pools()]})


@bp.route('/api/vlab/admin/build-artifacts/<scope>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_artifact_settings(scope):
    if scope != '_default' and scope not in {p['id'] for p in _farm_pools()}:
        return _bad('Build farm pool not found', 404)
    data = request.get_json(silent=True)
    try:
        s = artifacts.save(scope, None if data is None and scope != '_default' else (data if data is not None else {}))
    except ValueError as e:
        return _bad(str(e))
    log_audit(_user(), 'vlab.build.artifacts', f"result files of {scope}: {', '.join(s['patterns'])} for {s['keep_days']} days"
              + ('' if s['enabled'] else ' (off)'), get_client_ip())
    return get_artifact_settings()


# --- CI connections: the administrators' side ----------------------------------------------

def _link_view(l):
    pool = store.get_pool(l['pool_id'])
    return dict(l, pool=pool['name'] if pool else None)


def _check_link(fields):
    from pegaprox.utils.auth import load_users
    pool = store.get_pool(fields['pool_id'])
    if not pool or pool['type'] != 'buildfarm' or not core._can_reach(pool['cluster_id']):
        return _bad('Build farm pool not found', 404)
    if fields['owner'] not in (load_users() or {}):
        return _bad('No such user (the owner the builds run as)')
    if not vn.granted(pool['id'], fields['owner']):
        return _bad(f"{fields['owner']} may not use the pool '{pool['name']}' - grant it first (풀 > 이용 권한)", 409)
    return None


@bp.route('/api/vlab/admin/ci-links', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_ci_links():
    reach = {p['id'] for p in _farm_pools()}
    return jsonify({'links': [_link_view(l) for l in ci.list_links() if l['pool_id'] in reach],
                    'pools': [{'id': p['id'], 'name': p['name']} for p in _farm_pools()], 'kinds': list(ci.KINDS)})


@bp.route('/api/vlab/admin/ci-links', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_ci_link():
    try:
        fields = ci.clean(request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    err = _check_link(fields)
    if err:
        return err
    link = ci.save(None, fields, by=_user())
    token = ci.new_token(link['id'])
    log_audit(_user(), 'vlab.ci.create', f"CI connection '{link['name']}' ({link['kind']}) to pool {link['pool_id']} as {link['owner']}",
              get_client_ip())
    return jsonify({'link': _link_view(ci.get(link['id'])), 'token': token}), 201


def _link_or_404(lid):
    l = ci.get(lid)
    if not l or l['pool_id'] not in {p['id'] for p in _farm_pools()}:
        return None, _bad('CI connection not found', 404)
    return l, None


@bp.route('/api/vlab/admin/ci-links/<lid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_ci_link(lid):
    l, err = _link_or_404(lid)
    if err:
        return err
    try:
        fields = ci.clean(request.get_json(silent=True), l)
    except ValueError as e:
        return _bad(str(e))
    err = _check_link(fields)
    if err:
        return err
    out = ci.save(lid, fields)
    log_audit(_user(), 'vlab.ci.update', f"CI connection '{out['name']}'" + ('' if out['enabled'] else ' (off)'), get_client_ip())
    return jsonify({'link': _link_view(out)})


@bp.route('/api/vlab/admin/ci-links/<lid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_ci_link(lid):
    l, err = _link_or_404(lid)
    if err:
        return err
    ci.delete(lid)
    log_audit(_user(), 'vlab.ci.delete', f"CI connection '{l['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/ci-links/<lid>/token', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def renew_ci_token(lid):
    l, err = _link_or_404(lid)
    if err:
        return err
    token = ci.new_token(lid)
    log_audit(_user(), 'vlab.ci.token', f"CI connection '{l['name']}': new token", get_client_ip())
    return jsonify({'link': _link_view(ci.get(lid)), 'token': token})


# --- CI connections: the CI's side (the connection token) ----------------------------------

_WHY = {'UNKNOWN': 'Unknown CI token', 'OFF': 'This CI connection is switched off', 'EXPIRED': 'This CI token has expired'}


def _ci_link():
    """(link, None) from the request's token, or (None, error response)."""
    auth = request.headers.get('Authorization', '')
    token = auth[7:].strip() if auth.lower().startswith('bearer ') else request.headers.get('X-Moavi-CI-Token', '').strip()
    link, why = ci.by_token(token)
    if not link:
        if why == 'UNKNOWN':
            log_audit('ci', 'vlab.ci.refused', f"unknown CI token from {get_client_ip()}", get_client_ip())
        return None, (jsonify({'error': _WHY[why], 'code': why}), 401 if why == 'UNKNOWN' else 403)
    from pegaprox.vlab import features
    if not (features.enabled('fpga') or features.enabled('gpuai')):
        return None, _bad('The build farm is switched off on this site', 403, code='FEATURE_OFF')
    pool = store.get_pool(link['pool_id'])
    if not pool or pool['type'] != 'buildfarm':
        return None, _bad('The pool of this CI connection is gone', 409, code='NO_POOL')
    return dict(link, _pool=pool), None


def _ci_job(link, jid):
    job = catalog.get_build_job(jid)
    if not job or ci.source_of(job).get('link') != link['id']:
        return None
    return job


def _ci_view(job):
    files = artifacts.listed(job)
    base = request.host_url.rstrip('/')
    return {'id': job['id'], 'status': job['status'], 'exit_code': job.get('exit_code'), 'name': job['name'],
            'created_at': job['created_at'], 'started_at': job.get('started_at'), 'finished_at': job.get('finished_at'),
            'wait_reason': job.get('wait_reason') or '', 'error': (job.get('error') or '')[-2000:],
            'output_tail': (job.get('output') or '')[-4000:], 'source': ci.source_of(job),
            'artifacts': [dict(f, url=f"{base}/api/vlab/ci/jobs/{job['id']}/artifacts/{i}") for i, f in enumerate(files)],
            'done': job['status'] in ('done', 'failed', 'cancelled')}


@bp.route('/api/vlab/ci/jobs', methods=['POST'])
def ci_submit():
    link, err = _ci_link()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _bad('A JSON object is required')
    try:
        source = ci.clean_source(data)
    except ValueError as e:
        return _bad(str(e))
    command = link['command']
    if data.get('command'):
        if not link['allow_command']:
            return _bad('This connection runs its own command only - leave command out, or allow it in the connection', 403,
                        code='COMMAND_NOT_ALLOWED')
        command = str(data['command']).strip()[:2000]
    name = (str(data.get('name') or '').strip() or f"{link['name']} {source.get('ref', '')} {source.get('commit', '')[:8]}").strip()[:80]
    pool = link['_pool']
    queued = catalog.jobs_in('queued')
    if len(queued) >= 500:
        return _bad('The build queue is full', 429)
    job = vn._add_job(pool, link['owner'], name, ci.command_with_source(command, source, link), link['workdir'])
    catalog.update_build_job(job['id'], source=json.dumps(dict(source, link=link['id'], link_name=link['name'], kind=link['kind']),
                                                          ensure_ascii=False))
    ci.used(link['id'])
    log_audit(f"ci:{link['name']}", 'vlab.build.submit',
              f"build '{name}' to pool '{pool['name']}' as {link['owner']} from {link['kind']} "
              f"{source.get('repo', '')} {source.get('ref', '')} {source.get('commit', '')[:12]}".strip(), get_client_ip())
    vn.refresh_jobs(pool['id'])
    return jsonify({'job': _ci_view(catalog.get_build_job(job['id']))}), 201


@bp.route('/api/vlab/ci/jobs/<jid>', methods=['GET'])
def ci_status(jid):
    link, err = _ci_link()
    if err:
        return err
    job = _ci_job(link, jid)
    if not job:
        return _bad('Job not found', 404)
    if job['status'] in ('queued', 'running'):
        vn.refresh_jobs(job['pool_id'] or None)
        job = catalog.get_build_job(jid)
    return jsonify({'job': _ci_view(job)})


@bp.route('/api/vlab/ci/jobs/<jid>/artifacts/<int:i>', methods=['GET'])
def ci_artifact(jid, i):
    link, err = _ci_link()
    if err:
        return err
    job = _ci_job(link, jid)
    if not job:
        return _bad('Job not found', 404)
    return _download(job, i, link['owner'])


@bp.route('/api/vlab/ci/jobs/<jid>/cancel', methods=['POST'])
def ci_cancel(jid):
    link, err = _ci_link()
    if err:
        return err
    job = _ci_job(link, jid)
    if not job:
        return _bad('Job not found', 404)
    if job['status'] != 'queued':
        return _bad('Only a queued job can be cancelled', 409)
    catalog.update_build_job(jid, status='cancelled', finished_at=store.now())
    log_audit(f"ci:{link['name']}", 'vlab.build.cancel', f"build '{job['name']}' cancelled by CI", get_client_ip())
    return jsonify({'job': _ci_view(catalog.get_build_job(jid))})
