# -*- coding: utf-8 -*-
"""
MOAVI Desk - AI · GPU research: GPU jobs and their queue, quotas, GPU-hours, web IDEs.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GPU jobs are build jobs that ask for GPUs (POST /api/vlab/me/build-jobs with gpus, gpu_kind?,
  memory_gb?, max_minutes?, env?, notify?; pool_id may be left out - pegaprox/api/vlab_next.py).
  GET    /api/vlab/me/gpu                          my quota and this month's GPU-hours, the GPU pools I may use  vlab.desk
  POST   /api/vlab/me/build-jobs/<id>/stop         end my running job on its build VM                vlab.desk
  POST   /api/vlab/admin/build-jobs/<id>/stop      end anyone's running job                          vlab.pool.manage
  GET    /api/vlab/admin/gpu-queue                 the queue in the order it runs, why each waits, GPUs per pool  vlab.pool.view
  GET    /api/vlab/admin/gpu-quotas                quotas with what each subject uses now and this month  vlab.pool.view
  PUT    /api/vlab/admin/gpu-quotas                {subject_type: user|department|default, subject_id, max_gpus,
                                                    monthly_gpu_hours, hard?, note?}            vlab.pool.manage
  DELETE /api/vlab/admin/gpu-quotas                ?subject_type=&subject_id=                       vlab.pool.manage
  GET/PUT /api/vlab/admin/gpu-settings             {mail, channels, starve_minutes, default_max_minutes, max_queued_per_user,
                                                    quota_notice, quota_warn_pct, loan_remind_hours, loan_notice,
                                                    ide_notice, notice_webhook, queue_alert_hours}   vlab.pool.view / manage
  GET/PUT /api/vlab/admin/pools/<id>/gpu-jobs      {gpus_per_vm, kind, max_minutes, runtime}        vlab.pool.view / manage
  GET    /api/vlab/admin/reports/gpu-usage         ?days=|month=YYYY-MM &group=user|department &rollup=1 &format=csv
                                                   GPU-hours of jobs and card loans (GPU, NPU)       vlab.report.view

  Web IDE (JupyterLab, VS Code through jupyter-server-proxy) - the pool policy's web_ide says which:
  GET    /api/vlab/me/ide                          my IDE sessions, where I may open one            vlab.desk
  POST   /api/vlab/me/ide                          {desktop_id | pool_id, kind: jupyter|vscode, folder: home|scratch}
                                                   start it as me, or the one already running       vlab.desk
  GET    /api/vlab/me/ide/<id>                     how it is going (starting -> running)            vlab.desk
  POST   /api/vlab/me/ide/<id>/open                a one-time link /ide/<id>/...?moavi_ide=<60 s token>  vlab.desk
  DELETE /api/vlab/me/ide/<id>                     stop it                                          vlab.desk
  GET    /api/vlab/admin/ide-sessions, DELETE .../<id>   every IDE session                          vlab.pool.view / manage
  GET    /api/vlab/ide/auth                        vlab-proxy's auth_request for /ide/ (only with X-Moavi-Ide-Subrequest: 1,
                                                   which the proxy sets and clears on /api/): the link token once, then
                                                   the cookie; answers the VM address and the IDE's token in headers  public

The IDE listens on the desktop's own address, behind its token; users never get that address or
token - vlab-proxy adds the token on its way to the VM (deploy/nginx/vlab.conf, location /ide/).

Background: the minute loop (pegaprox/vlab/loans.py) calls gpu_tick -> vlab_next.refresh_jobs,
whose steps (a job's start, a stop past its time limit) confirm the lease (ha.confirm_step).
Everything else here is a request.
"""

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from flask import Blueprint, Response, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.api import vlab_next as nxt
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, nas, research, store
from pegaprox.vlab import policy as pool_policy

bp = Blueprint('vlab_research', __name__)

_bad = core._bad
_user = core._user

REASONS = {
    'quota_gpus': 'GPUs at once: your quota is in use',
    'quota_gpus_department': "GPUs at once: your department's quota is in use",
    'quota_hours': 'this month\'s GPU-hours are used up (hard quota)',
    'held_for_older': 'an older job is waiting for these GPUs',
    'no_free_gpu': 'no build VM has that many GPUs free',
    'no_free_vm': 'no build VM is free',
    'no_gpu_pool': 'no GPU pool you may use has that many GPUs of that kind',
}


# --- departments -----------------------------------------------------------------------------

def dep_chain(username, cache=None):
    """The user's department and every one above it, nearest first."""
    if cache is not None and username in cache:
        return cache[username]
    out, d = [], catalog.department_of(username)
    while d and d not in out:
        out.append(d)
        dep = catalog.get_department(d)
        d = dep.get('parent_id') if dep else None
    if cache is not None:
        cache[username] = out
    return out


def _dep_names():
    deps = {d['id']: d for d in catalog.list_departments()}

    def path(dep_id):
        names, d, seen = [], deps.get(dep_id), set()
        while d and d['id'] not in seen:
            seen.add(d['id'])
            names.append(d['name'])
            d = deps.get(d.get('parent_id'))
        return ' > '.join(reversed(names))
    return deps, path


def _top(dep_id, deps):
    d, seen = deps.get(dep_id), set()
    while d and d.get('parent_id') and d['parent_id'] in deps and d['id'] not in seen:
        seen.add(d['id'])
        d = deps[d['parent_id']]
    return d['id'] if d else dep_id


# --- usage now and this month ------------------------------------------------------------------

def _gpu_jobs_in(since, until):
    rows = catalog.db().query("SELECT * FROM vlab_build_jobs WHERE gpus > 0 AND started_at IS NOT NULL AND started_at <= ? "
                              "AND (finished_at IS NULL OR finished_at >= ?)", (until.isoformat(timespec='seconds'), since.isoformat(timespec='seconds')))
    return [dict(r) for r in rows]


def _loans():
    return [l for l in store.list_leases(active_only=False, limit=50000) if l['resource_type'] in research.LOAN_KINDS]


def month_usage(at=None):
    """{('user', name) | ('department', id): {'gpus': GPUs held now, 'hours': GPU-hours this month}}
    from GPU jobs and card loans; a department counts everyone in it and below it."""
    until = at or research.utcnow()
    since = research.month_start(until)
    out, cache = {}, {}

    def add(username, gpus, hours):
        for key in [('user', username)] + [('department', d) for d in dep_chain(username, cache)]:
            u = out.setdefault(key, {'gpus': 0, 'hours': 0.0})
            u['gpus'] += gpus
            u['hours'] += hours
    for j in _gpu_jobs_in(since, until):
        add(j['username'], int(j['gpus']) if j['status'] == 'running' else 0, research.job_gpu_hours(j, since, until))
    for l in _loans():
        h = research.loan_hours(l, since, until)
        if h > 0 or l['state'] == 'active':
            add(l['username'], 1 if l['state'] == 'active' else 0, h)
    return out


def _quotas_of_factory(quotas):
    cache, chains = {}, {}

    def quotas_of(job):
        u = job['username']
        if u not in cache:
            cache[u] = research.quotas_for(u, dep_chain(u, chains), quotas)
        return cache[u]
    return quotas_of


# --- the queue's view of the build farm -----------------------------------------------------

def _gpu_conf(pool):
    return research.pool_gpu_jobs(pool.get('settings'), core._gpu_policy(pool.get('settings')))


def candidate_pools(username, gpus, kind, pools=None):
    """Build farm pools granted to the user whose VMs have that many GPUs of that kind."""
    pools = pools if pools is not None else [p for p in store.list_pools() if p['type'] == 'buildfarm']
    out = []
    for p in pools:
        conf = _gpu_conf(p)
        if conf['gpus_per_vm'] >= max(1, int(gpus or 0)) and research.kind_matches(kind, conf['kind']) and nxt.granted(p['id'], username):
            out.append(p['id'])
    return out


def queue_context(queued):
    """What research.plan needs: the queued jobs with the pools each may run in, the running
    build VMs with what they hold, usage and quotas. Jobs of a removed pool are cancelled."""
    pools = {p['id']: p for p in store.list_pools() if p['type'] == 'buildfarm'}
    jobs, why = [], {}
    for job in queued:
        if job['pool_id'] and job['pool_id'] not in pools:
            catalog.update_build_job(job['id'], status='cancelled', error='pool removed', finished_at=store.now())
            continue
        gpus = int(job.get('gpus') or 0)
        if job['pool_id']:
            conf = _gpu_conf(pools[job['pool_id']])
            fits = not gpus or (conf['gpus_per_vm'] >= gpus and research.kind_matches(job.get('gpu_kind'), conf['kind']))
            cands = [job['pool_id']] if fits else []
        else:
            cands = candidate_pools(job['username'], gpus, job.get('gpu_kind'), list(pools.values()))
        if not cands:
            why[job['id']] = 'no_gpu_pool'
            continue
        jobs.append(dict(job, candidates=cands))
    wanted = {pid for j in jobs for pid in j['candidates']}
    running = catalog.jobs_in('running')
    sessions = store.open_session_desktops()
    vms, live = [], {}
    for pid in wanted:
        pool = pools[pid]
        mgr = cluster_managers.get(pool['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            continue
        if pool['cluster_id'] not in live:
            live[pool['cluster_id']] = core._vm_states(pool['cluster_id'])
        states = live[pool['cluster_id']]
        conf = _gpu_conf(pool)
        for d in store.list_desktops(pid):
            vm = states.get(int(d['vmid'])) or {}
            if d['vm_type'] != 'qemu' or vm.get('status') != 'running':
                continue
            on = [j for j in running if j['desktop_id'] == d['id']]
            used = {int(x) for j in on for x in str(j.get('gpu_index') or '').split(',') if x.strip().isdigit()}
            vms.append({'desktop_id': d['id'], 'pool_id': pid, 'desk': d, 'node': vm.get('node') or d['node'],
                        'gpus': conf['gpus_per_vm'], 'mem_gb': int((vm.get('maxmem') or 0) / 1024 ** 3),
                        'used': used, 'mem_used': sum(int(j.get('memory_gb') or 0) for j in on),
                        'cpu_job': any(not int(j.get('gpus') or 0) for j in on),
                        'busy': bool(d['assigned_user']) or d['id'] in sessions})
    needs_usage = any(j.get('gpus') for j in jobs)
    quotas = research.list_quotas()
    return {'jobs': jobs, 'all': queued, 'why': why, 'vms': vms, 'pools': pools,
            'usage': month_usage() if needs_usage and quotas else {},
            'quotas_of': _quotas_of_factory(quotas), 'settings': research.get_settings()}


def gpu_tick():
    """The minute loop: running jobs read, ended ones told, the queue run (vlab_next.refresh_jobs)."""
    if catalog.jobs_in('running') or catalog.jobs_in('queued'):
        nxt.refresh_jobs()


# --- notifications -----------------------------------------------------------------------------

_STATUS_KO = {'done': '완료', 'failed': '실패', 'cancelled': '취소'}


def notify_ended(job_ids):
    """The owner of each ended job hears of it as the job asked (mail to the account's address,
    the webhook channels the administrators chose). Once per job."""
    g = research.get_settings()
    for jid in job_ids:
        job = catalog.get_build_job(jid)
        if not job or job.get('notified_at'):
            continue
        want = research.loads(job.get('notify'), {})
        if not want:
            continue
        catalog.update_build_job(jid, notified_at=store.now())
        start, end = research.parse(job.get('started_at')), research.parse(job.get('finished_at'))
        took = f"{int((end - start).total_seconds() // 60)}분" if start and end else '-'
        title = f"[MOAVI Desk] 작업 {_STATUS_KO.get(job['status'], job['status'])}: {job['name']}"
        lines = [f"작업: {job['name']} ({job['id']})", f"상태: {_STATUS_KO.get(job['status'], job['status'])}"
                 + (f" (종료 코드 {job['exit_code']})" if job.get('exit_code') not in (None, 0) else ''),
                 f"GPU: {job.get('gpus') or 0}장" + (f" ({job['gpu_kind']})" if job.get('gpu_kind') else ''),
                 f"실행 시간: {took}", f"결과 폴더: {job.get('workdir') or '-'}"]
        if job.get('error'):
            lines.append(f"오류: {job['error'][:500]}")
        text = '\n'.join(lines)
        if want.get('webhook') and g['channels']:
            try:
                from pegaprox.utils.webhooks import send_to_channels
                send_to_channels({'title': title, 'message': text, 'source': 'moavi-desk',
                                  'severity': 'info' if job['status'] == 'done' else 'warning',
                                  'kind': f"gpu_job_{job['status']}", 'job_id': jid, 'owner': job['username']}, g['channels'])
            except Exception as e:
                logging.warning(f'[VLAB] GPU job webhook: {e}')
        if want.get('mail') and g['mail']:
            # the owner may have turned GPU job mails off in 내 계정 > 알림
            from pegaprox.vlab import notices
            notices.mail(job['username'], 'gpu_job', title, text)


# --- my GPU view, stopping a job -------------------------------------------------------------

def _quota_view(username, usage, quotas=None):
    out = []
    for st, sid, q in research.quotas_for(username, dep_chain(username), quotas):
        u = usage.get((st, sid), {'gpus': 0, 'hours': 0.0})
        out.append(dict(q, applies_as=st, applies_to=sid, gpus_now=u['gpus'], hours_month=round(u['hours'], 1)))
    return out


@bp.route('/api/vlab/me/gpu', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_gpu():
    usage = month_usage()
    mine = usage.get(('user', _user()), {'gpus': 0, 'hours': 0.0})
    pools = []
    for p in store.list_pools():
        if p['type'] != 'buildfarm' or not core._can_reach(p['cluster_id']) or not nxt.granted(p['id'], _user()):
            continue
        conf = _gpu_conf(p)
        if conf['gpus_per_vm']:
            pools.append({'id': p['id'], 'name': p['name'], 'gpus_per_vm': conf['gpus_per_vm'], 'kind': conf['kind'],
                          'max_minutes': conf['max_minutes'], 'runtime': conf['runtime'], 'workdir': nxt._scratch_dir(p, _user())})
    g = research.get_settings()
    return jsonify({'gpus_now': mine['gpus'], 'hours_month': round(mine['hours'], 1), 'quotas': _quota_view(_user(), usage),
                    'pools': pools, 'mail': g['mail'], 'webhook': bool(g['channels']),
                    'default_max_minutes': g['default_max_minutes']})


def _stop(job, by):
    if job['status'] != 'running':
        return _bad('Only a running job can be stopped', 409)
    desk = store.get_desktop(job['desktop_id']) if job['desktop_id'] else None
    mgr = cluster_managers.get(desk['cluster_id']) if desk else None
    if not desk or not mgr or not getattr(mgr, 'is_connected', False):
        return _bad("The job's build VM cannot be reached", 502)
    err = nxt._stop_job(job, desk, mgr, nxt._job_node(desk))
    if err:
        return _bad(f'The build VM did not stop the job: {err}', 502)
    job = catalog.update_build_job(job['id'], status='cancelled', finished_at=store.now(), error=f'stopped by {by}')
    log_audit(by, 'vlab.build.stop', f"job '{job['name']}' of {job['username']} on {desk['name']}", get_client_ip())
    notify_ended([job['id']])
    return jsonify({'job': nxt._job_view(job)})


@bp.route('/api/vlab/me/build-jobs/<jid>/stop', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def stop_my_job(jid):
    job = catalog.get_build_job(jid)
    if not job or job['username'] != _user():
        return _bad('Job not found', 404)
    return _stop(job, _user())


@bp.route('/api/vlab/admin/build-jobs/<jid>/stop', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def stop_job(jid):
    job = catalog.get_build_job(jid)
    if not job:
        return _bad('Job not found', 404)
    return _stop(job, _user())


# --- the queue and the quotas (관리 화면) ------------------------------------------------------

@bp.route('/api/vlab/admin/gpu-queue', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def gpu_queue():
    nxt.refresh_jobs()
    queued = catalog.jobs_in('queued')
    ctx = queue_context(queued)
    _, why, order = research.plan(ctx['jobs'], ctx['vms'], ctx['usage'], ctx['quotas_of'], ctx['settings']['starve_minutes'])
    why.update(ctx['why'])
    pos = {jid: i + 1 for i, jid in enumerate(order)}
    rows = []
    for j in sorted(ctx['all'], key=lambda j: pos.get(j['id'], 10 ** 6)):
        if j['status'] != 'queued':
            continue
        r = nxt._job_view(j)
        r['position'] = pos.get(j['id'])
        r['wait_reason'] = why.get(j['id'], '')
        r['wait_text'] = REASONS.get(r['wait_reason'], '')
        r['waited_min'] = int((research.utcnow() - (research.parse(j['created_at']) or research.utcnow())).total_seconds() // 60)
        rows.append(r)
    running = [nxt._job_view(j) for j in catalog.jobs_in('running') if int(j.get('gpus') or 0)]
    pools = []
    for p in store.list_pools():
        if p['type'] != 'buildfarm' or not core._can_reach(p['cluster_id']):
            continue
        conf = _gpu_conf(p)
        if not conf['gpus_per_vm']:
            continue
        states = core._vm_states(p['cluster_id'])
        desks = [d for d in store.list_desktops(p['id']) if (states.get(int(d['vmid'])) or {}).get('status') == 'running']
        used = sum(int(j['gpus']) for j in running if j['pool_id'] == p['id'])
        pools.append({'id': p['id'], 'name': p['name'], 'kind': conf['kind'], 'gpus_per_vm': conf['gpus_per_vm'],
                      'vms': len(desks), 'gpus': len(desks) * conf['gpus_per_vm'], 'gpus_used': used,
                      'max_minutes': conf['max_minutes'], 'runtime': conf['runtime']})
    return jsonify({'queued': rows, 'running': running, 'pools': pools, 'settings': ctx['settings']})


@bp.route('/api/vlab/admin/gpu-quotas', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_gpu_quotas():
    usage = month_usage()
    deps, path = _dep_names()
    out = []
    for q in research.list_quotas():
        u = usage.get((q['subject_type'], q['subject_id']), {'gpus': 0, 'hours': 0.0}) if q['subject_type'] != 'default' else None
        out.append(dict(q, name=path(q['subject_id']) if q['subject_type'] == 'department' else q['subject_id'],
                        gpus_now=u['gpus'] if u else None, hours_month=round(u['hours'], 1) if u else None))
    users = sorted(({'username': k[1], 'gpus_now': v['gpus'], 'hours_month': round(v['hours'], 1)}
                    for k, v in usage.items() if k[0] == 'user'), key=lambda r: -r['hours_month'])
    return jsonify({'quotas': out, 'users': users, 'month_start': research.month_start().isoformat()})


@bp.route('/api/vlab/admin/gpu-quotas', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_gpu_quota():
    from pegaprox.utils.auth import load_users
    try:
        st, sid, gpus, hours, hard, note = research.validate_quota(request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    if st == 'user' and sid not in load_users():
        return _bad('No such user', 404)
    if st == 'department' and not catalog.get_department(sid):
        return _bad('No such department', 404)
    q = research.save_quota(st, sid, gpus, hours, hard, note)
    log_audit(_user(), 'vlab.gpu.quota', f"{st} {sid or '(default)'}: {gpus} GPUs at once, {hours} GPU-h a month"
              + (' (hard)' if hard else ''), get_client_ip())
    return jsonify({'quota': q})


@bp.route('/api/vlab/admin/gpu-quotas', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_gpu_quota():
    st = request.args.get('subject_type') or ''
    sid = '' if st == 'default' else (request.args.get('subject_id') or '')
    if not research.get_quota(st, sid):
        return _bad('Quota not found', 404)
    research.delete_quota(st, sid)
    log_audit(_user(), 'vlab.gpu.quota.delete', f"{st} {sid or '(default)'}", get_client_ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/gpu-settings', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_gpu_settings():
    return jsonify({'settings': research.get_settings(), 'defaults': research.GLOBAL_DEFAULTS})


@bp.route('/api/vlab/admin/gpu-settings', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_gpu_settings():
    try:
        s = research.validate_settings(request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    s = research.save_settings(s)
    log_audit(_user(), 'vlab.gpu.settings', ', '.join(f'{k}={v}' for k, v in s.items()), get_client_ip())
    return jsonify({'settings': s})


@bp.route('/api/vlab/admin/pools/<pool_id>/gpu-jobs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_gpu_jobs(pool_id):
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    return jsonify({'gpu_jobs': _gpu_conf(pool), 'saved': bool((pool.get('settings') or {}).get('gpu_jobs')),
                    'gpu': core._gpu_policy(pool.get('settings'))})


@bp.route('/api/vlab/admin/pools/<pool_id>/gpu-jobs', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_pool_gpu_jobs(pool_id):
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    if pool['type'] != 'buildfarm':
        return _bad('GPU jobs run in build farm pools only')
    try:
        conf = research.validate_pool_gpu_jobs(request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, gpu_jobs=conf))
    log_audit(_user(), 'vlab.pool.gpujobs', f"pool '{pool['name']}': " + ', '.join(f'{k}={v}' for k, v in conf.items()),
              get_client_ip())
    return jsonify({'gpu_jobs': _gpu_conf(store.get_pool(pool['id']))})


# --- GPU-hours report (비용 배분) ---------------------------------------------------------------

def _window():
    """(since, until, label) from ?month=YYYY-MM or ?days=N (default 30). ValueError when bad."""
    month = request.args.get('month')
    now_ = research.utcnow()
    if month:
        try:
            first = datetime.strptime(month, '%Y-%m').astimezone()
        except ValueError:
            raise ValueError('month: YYYY-MM')
        nxt_month = (first.replace(day=28) + timedelta(days=4)).replace(day=1)
        return first.astimezone(timezone.utc), min(nxt_month.astimezone(timezone.utc), now_), month
    try:
        days = max(1, min(366, int(request.args.get('days') or 30)))
    except ValueError:
        raise ValueError('days must be a number')
    return now_ - timedelta(days=days), now_, f'{days}d'


@bp.route('/api/vlab/admin/reports/gpu-usage', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def gpu_usage_report():
    """GPU-hours per user or department: GPU jobs (GPUs x hours) and card loans (GPU and NPU, one
    card x hours). The basis of a cost split; a job counts to the department it was sent from."""
    from pegaprox.utils.auth import load_users
    try:
        since, until, label = _window()
    except ValueError as e:
        return _bad(str(e))
    group = request.args.get('group') or 'user'
    if group not in ('user', 'department'):
        return _bad('group must be user or department')
    rollup = request.args.get('rollup') in ('1', 'true')
    deps, path = _dep_names()
    used = research.usage(_gpu_jobs_in(since, until), _loans(), since, until, catalog.department_of)
    users = load_users() or {}
    if group == 'user':
        rows = [{'username': u, 'display_name': (users.get(u) or {}).get('display_name') or '',
                 'department_id': r['department_id'], 'department': path(r['department_id']) if r['department_id'] else '',
                 'job_gpu_hours': round(r['job_hours'], 2), 'loan_gpu_hours': round(r['loan_hours'], 2),
                 'total_gpu_hours': round(r['job_hours'] + r['loan_hours'], 2), 'jobs': r['jobs'], 'loans': r['loans']}
                for u, r in used.items()]
    else:
        agg = {}
        for u, r in used.items():
            for dep, h in r['by_department'].items():
                key = _top(dep, deps) if rollup and dep else dep
                a = agg.setdefault(key, {'job': 0.0, 'loan': 0.0, 'users': set()})
                a['job'] += h['job_hours']
                a['loan'] += h['loan_hours']
                a['users'].add(u)
        rows = [{'department_id': k, 'department': path(k) if k else '(부서 없음)', 'users': len(a['users']),
                 'job_gpu_hours': round(a['job'], 2), 'loan_gpu_hours': round(a['loan'], 2),
                 'total_gpu_hours': round(a['job'] + a['loan'], 2)} for k, a in agg.items()]
    rows.sort(key=lambda r: -r['total_gpu_hours'])
    total = round(sum(r['total_gpu_hours'] for r in rows), 2)
    for r in rows:
        r['share_pct'] = round(100 * r['total_gpu_hours'] / total, 1) if total else 0.0
    if request.args.get('format') == 'csv':
        if group == 'user':
            head = ['user', 'name', 'department', 'job_gpu_hours', 'loan_gpu_hours', 'total_gpu_hours', 'share_pct', 'jobs', 'loans']
            vals = lambda r: [r['username'], r['display_name'], r['department'], r['job_gpu_hours'], r['loan_gpu_hours'],   # noqa: E731
                              r['total_gpu_hours'], r['share_pct'], r['jobs'], r['loans']]
        else:
            head = ['department', 'users', 'job_gpu_hours', 'loan_gpu_hours', 'total_gpu_hours', 'share_pct']
            vals = lambda r: [r['department'], r['users'], r['job_gpu_hours'], r['loan_gpu_hours'], r['total_gpu_hours'], r['share_pct']]   # noqa: E731
        lines = [f"# MOAVI Desk GPU-hours {since.astimezone().strftime('%Y-%m-%d %H:%M')} ~ {until.astimezone().strftime('%Y-%m-%d %H:%M')}",
                 ','.join(head)] + [','.join(nxt._csv(v) for v in vals(r)) for r in rows]
        return Response('\ufeff' + '\n'.join(lines) + '\n', mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="gpu-usage-{group}-{label}.csv"'})
    return jsonify({'since': since.isoformat(), 'until': until.isoformat(), 'group': group, 'rows': rows,
                    'total_gpu_hours': total})


# --- web IDE ----------------------------------------------------------------------------------

def _ide_kinds(pool):
    return pool_policy.effective((pool or {}).get('settings'))['web_ide']


def _ide_targets(username):
    """Where the user may open an IDE: their own desktops and the build farm pools granted to them
    whose policy allows one. ([desktops], [pools])."""
    desks, pools, seen = [], [], {}
    for d in store.desktops_of_user(username):
        pool = seen.setdefault(d['pool_id'], store.get_pool(d['pool_id']))
        if pool and d['vm_type'] == 'qemu' and _ide_kinds(pool) and core._can_reach(d['cluster_id']):
            desks.append((d, pool))
    for p in store.list_pools():
        if p['type'] == 'buildfarm' and _ide_kinds(p) and core._can_reach(p['cluster_id']) and nxt.granted(p['id'], username):
            pools.append(p)
    return desks, pools


def _folders(pool, username):
    paths = nxt.storage_paths(pool, username) if pool else None
    f = (paths or {}).get('folders') or {}
    return {'home': (f.get('home') or {}).get('linux') or '', 'scratch': (f.get('scratch') or {}).get('linux') or ''}


def _ide_view(row):
    desk = store.get_desktop(row['desktop_id'])
    out = {k: row[k] for k in ('id', 'username', 'desktop_id', 'pool_id', 'kind', 'folder', 'workdir', 'state', 'error',
                               'created_at', 'started_at', 'last_seen', 'stopped_at')}
    out['desktop'] = desk['name'] if desk else None
    out['path'] = research.ide_path(row['id'], row['kind'])
    return out


def _ide_refresh(row):
    """starting -> running once the port answers; running/starting -> stopped/failed once its
    process has ended (an idle IDE ends by itself, a desktop that restarted takes it along)."""
    if row['state'] not in ('starting', 'running'):
        return row
    desk = store.get_desktop(row['desktop_id'])
    mgr = cluster_managers.get(desk['cluster_id']) if desk else None
    if not desk:
        return research.update_ide(row['id'], state='stopped', error='the desktop is gone', stopped_at=store.now())
    if not mgr or not getattr(mgr, 'is_connected', False):
        return row
    st, known = {}, False
    if row.get('pid'):
        try:
            resp = mgr._api_get(nxt._agent(mgr, nxt._job_node(desk), desk['vmid'], 'exec-status'), params={'pid': row['pid']})
            known = getattr(resp, 'status_code', 0) == 200
            st = (resp.json().get('data') or {}) if known else {}
        except Exception:
            st = {}
    if st.get('exited'):
        code = st.get('exitcode')
        said = research.ide_error(code)
        if code in (0, None) or code < 0:
            idle = code in (0, None) and _ended_idle(row, desk)
            out = research.update_ide(row['id'], state='stopped', stopped_at=store.now(),
                                      error=idle or ('' if code in (0, None) else 'ended'))
            if idle:
                from pegaprox.api.vlab_notices import ide_closed
                ide_closed(out, 'idle')
            return out
        return research.update_ide(row['id'], state='failed', stopped_at=store.now(),
                                   error=(said[1] if said else f'the IDE ended with code {code}') + (f": {st.get('err-data', '')[-300:]}" if st.get('err-data') else ''))
    ok, _, _ = nxt._tcp_probe(row['host'], row['port'], timeout=1.5)
    if ok and row['state'] == 'starting':
        return research.update_ide(row['id'], state='running', last_seen=store.now())
    if not ok and row['state'] == 'running' and not known:
        return research.update_ide(row['id'], state='stopped', stopped_at=store.now(), error='the desktop restarted')
    return row


def _ended_idle(row, desk):
    """An IDE that ended by itself (exit 0) after no use for its pool's idle minutes: the text
    kept as its error ('' when it was closed from inside, before that)."""
    pool = store.get_pool(desk['pool_id']) if desk else None
    idle_min = pool_policy.effective((pool or {}).get('settings'))['web_ide_idle_min']
    seen = research.parse(row.get('last_seen') or row.get('started_at') or row.get('created_at'))
    if not idle_min or not seen or (research.utcnow() - seen).total_seconds() < (idle_min - 2) * 60:
        return ''
    return f'closed after {idle_min} idle minutes'


def _my_ide(sid):
    row = research.get_ide(sid)
    return row if row and row['username'] == _user() else None


@bp.route('/api/vlab/me/ide', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_ide():
    desks, pools = _ide_targets(_user())
    sessions = [_ide_view(_ide_refresh(r)) for r in research.list_ide(_user())[:20]]
    return jsonify({
        'sessions': sessions,
        'desktops': [{'id': d['id'], 'name': d['name'], 'pool': p['name'], 'kinds': _ide_kinds(p),
                      'folders': {k: bool(v) for k, v in _folders(p, _user()).items()}, 'gpu': bool(core._gpu_policy(p.get('settings')))}
                     for d, p in desks],
        'pools': [{'id': p['id'], 'name': p['name'], 'kinds': _ide_kinds(p),
                   'folders': {k: bool(v) for k, v in _folders(p, _user()).items()}} for p in pools]})


def _pick_build_vm(pool):
    states = core._vm_states(pool['cluster_id'])
    live = research.list_ide(live=True)
    best = None
    for d in store.list_desktops(pool['id']):
        if d['vm_type'] != 'qemu' or d['assigned_user'] or (states.get(int(d['vmid'])) or {}).get('status') != 'running':
            continue
        n = sum(1 for r in live if r['desktop_id'] == d['id'])
        if best is None or n < best[0]:
            best = (n, d)
    return best[1] if best else None


@bp.route('/api/vlab/me/ide', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def start_ide():
    data = request.get_json(silent=True) or {}
    kind, folder = data.get('kind'), data.get('folder') or 'home'
    if kind not in research.IDE_KINDS:
        return _bad('kind must be jupyter or vscode')
    if folder not in research.IDE_FOLDERS:
        return _bad('folder must be home or scratch')
    desks, pools = _ide_targets(_user())
    desk = pool = None
    if data.get('desktop_id'):
        hit = next(((d, p) for d, p in desks if d['id'] == data['desktop_id']), None)
        if not hit:
            # a build VM of a pool granted to the caller may be named too
            d = store.get_desktop(str(data['desktop_id']))
            p = next((p for p in pools if d and p['id'] == d['pool_id']), None)
            hit = (d, p) if p and not d['assigned_user'] else None
        if not hit:
            return _bad('Desktop not found', 404)
        desk, pool = hit
    elif data.get('pool_id'):
        pool = next((p for p in pools if p['id'] == data['pool_id']), None)
        if not pool:
            return _bad('Pool not found', 404)
        desk = _pick_build_vm(pool)
        if not desk:
            return jsonify({'error': 'No build VM of this pool is running', 'code': 'NOT_RUNNING'}), 409
    else:
        return _bad('desktop_id or pool_id required')
    if kind not in _ide_kinds(pool):
        return jsonify({'error': f'This pool does not allow {kind}', 'code': 'NOT_ALLOWED'}), 403
    old = research.find_ide(_user(), desk['id'], kind)
    if old:
        old = _ide_refresh(old)
        if old['state'] in ('starting', 'running'):
            return jsonify({'session': _ide_view(old), 'reused': True})
    vm = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if vm.get('status') != 'running':
        return jsonify({'error': 'The desktop is not running - start it first', 'code': 'NOT_RUNNING'}), 409
    mgr = cluster_managers.get(desk['cluster_id'])
    node = vm.get('node') or desk['node']
    osname = nxt._guest_os(mgr, node, desk['vmid'])
    if osname is None:
        return jsonify({'error': "The desktop's guest agent does not answer", 'code': 'NO_AGENT'}), 409
    if osname == 'windows':
        return jsonify({'error': 'The web IDE runs on Linux desktops (use the desktop itself on Windows)', 'code': 'WINDOWS'}), 409
    ip = nxt._guest_ipv4(mgr, node, desk['vmid'])
    if not ip:
        return jsonify({'error': 'The desktop has no address yet', 'code': 'NO_IP'}), 409
    guest = nas.guest_name(_user())
    if not guest:
        return _bad('Your user name cannot be an account on the desktop')
    nxt.storage_on_connect(desk, pool, mgr, node, _user())
    folders = _folders(pool, _user())
    if folder == 'scratch' and not folders['scratch']:
        return jsonify({'error': 'This pool has no scratch folder on shared storage', 'code': 'NO_SCRATCH'}), 409
    workdir = folders[folder]
    port = research.free_port(desk['id'])
    if not port:
        return jsonify({'error': 'Every IDE port of this desktop is in use', 'code': 'BUSY'}), 409
    if len(research.list_ide(_user(), live=True)) >= 6:
        return _bad('You have as many IDEs open as one may - stop one first', 429)
    row, token = research.add_ide(_user(), desk, pool['id'], kind, folder, workdir, ip, port)
    pol = pool_policy.effective(pool.get('settings'))
    script = research.ide_script(row['id'], kind, port, workdir, pol['web_ide_idle_min'], hide_gpus=pool['type'] == 'buildfarm')
    argv = research.job_argv(script, guest)
    try:
        resp = mgr._api_post(nxt._agent(mgr, node, desk['vmid'], 'exec'), data={'command': argv, 'input-data': token + '\n'})
        pid = (resp.json().get('data') or {}).get('pid') if getattr(resp, 'status_code', 0) == 200 else None
        err = '' if pid else ((getattr(resp, 'text', '') or 'guest agent refused')[:300])
    except Exception as e:
        pid, err = None, str(e)[:300]
    if not pid:
        research.update_ide(row['id'], state='failed', error=err, stopped_at=store.now())
        return jsonify({'error': f'The desktop did not start the IDE: {err}', 'code': 'START_FAILED'}), 502
    row = research.update_ide(row['id'], pid=pid, started_at=store.now())
    log_audit(_user(), 'vlab.ide.start', f"{kind} on {desk['name']} (qemu/{desk['vmid']}) in {workdir or '~'}", get_client_ip())
    return jsonify({'session': _ide_view(row), 'reused': False}), 201


@bp.route('/api/vlab/me/ide/<sid>', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def ide_status(sid):
    row = _my_ide(sid)
    if not row:
        return _bad('IDE session not found', 404)
    return jsonify({'session': _ide_view(_ide_refresh(row))})


@bp.route('/api/vlab/me/ide/<sid>/open', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def ide_open(sid):
    row = _my_ide(sid)
    if not row:
        return _bad('IDE session not found', 404)
    row = _ide_refresh(row)
    if row['state'] != 'running':
        return jsonify({'error': 'The IDE is not ready yet' if row['state'] == 'starting' else 'The IDE has ended',
                        'code': 'NOT_READY' if row['state'] == 'starting' else 'ENDED', 'session': _ide_view(row)}), 409
    tok = research.new_link(sid)
    return jsonify({'url': f"{research.ide_path(sid, row['kind'])}?moavi_ide={tok}", 'expires_in': research.IDE_LINK_SECONDS})


def _ide_stop(row, by):
    desk = store.get_desktop(row['desktop_id'])
    mgr = cluster_managers.get(desk['cluster_id']) if desk else None
    if row['state'] in ('starting', 'running') and row.get('pid') and mgr and getattr(mgr, 'is_connected', False):
        try:
            mgr._api_post(nxt._agent(mgr, nxt._job_node(desk), desk['vmid'], 'exec'),
                          data={'command': research.stop_argv(row['pid'])})
        except Exception as e:
            logging.warning(f"[VLAB] IDE {row['id']} stop: {e}")
    research.forget_cookies(row['id'])
    live = row['state'] in ('starting', 'running')
    row = research.update_ide(row['id'], state='stopped', stopped_at=store.now(), error=f'stopped by {by}' if by != row['username'] else '')
    log_audit(by, 'vlab.ide.stop', f"{row['kind']} of {row['username']} on {desk['name'] if desk else row['desktop_id']}", get_client_ip())
    if live and by != row['username']:
        from pegaprox.api.vlab_notices import ide_closed
        ide_closed(row, 'admin', by)
    return row


@bp.route('/api/vlab/me/ide/<sid>', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def ide_stop(sid):
    row = _my_ide(sid)
    if not row:
        return _bad('IDE session not found', 404)
    return jsonify({'session': _ide_view(_ide_stop(row, _user()))})


@bp.route('/api/vlab/admin/ide-sessions', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def admin_ide_sessions():
    rows = [r for r in research.list_ide() if (store.get_desktop(r['desktop_id']) or {}).get('cluster_id') is None
            or core._can_reach(store.get_desktop(r['desktop_id'])['cluster_id'])]
    return jsonify({'sessions': [_ide_view(_ide_refresh(r) if r['state'] in ('starting', 'running') else r) for r in rows[:300]]})


@bp.route('/api/vlab/admin/ide-sessions/<sid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def admin_ide_stop(sid):
    row = research.get_ide(sid)
    desk = store.get_desktop(row['desktop_id']) if row else None
    if not row or (desk and not core._can_reach(desk['cluster_id'])):
        return _bad('IDE session not found', 404)
    return jsonify({'session': _ide_view(_ide_stop(row, _user()))})


COOKIE = 'moavi_ide'


@bp.route('/api/vlab/ide/auth', methods=['GET'])
def ide_auth():
    """vlab-proxy's auth_request for every request under /ide/<id>/. 200 with the upstream and
    the IDE's token in headers (the proxy keeps them), 401 otherwise. The first request brings
    the one-time ?moavi_ide= token and gets a cookie for that path; later ones bring the cookie."""
    if request.headers.get('X-Moavi-Ide-Subrequest') != '1':
        return _bad('Not found', 404)
    uri = request.headers.get('X-Original-URI') or ''
    m = research.SID.match(uri)
    if not m:
        return '', 401
    sid = m.group(1)
    row = research.get_ide(sid, token=True)
    if not row or row['state'] not in ('starting', 'running') or not row['token']:
        return '', 401
    from pegaprox.utils.auth import load_users
    owner = (load_users() or {}).get(row['username']) or {}
    if not owner or owner.get('enabled') is False:
        return '', 401
    set_cookie = ''
    if not research.cookie_ok(sid, request.cookies.get(COOKIE)):
        tok = (parse_qs(urlsplit(uri).query).get('moavi_ide') or [''])[0]
        cookie = research.take_link(sid, tok)
        if not cookie:
            return '', 401
        set_cookie = (f'{COOKIE}={cookie}; Path=/ide/{sid}/; Max-Age={research.IDE_COOKIE_SECONDS}; '
                      'HttpOnly; Secure; SameSite=Lax')
        log_audit(row['username'], 'vlab.ide.open', f"{row['kind']} {sid}", request.headers.get('X-Real-IP') or get_client_ip())
    seen = research.parse(row.get('last_seen'))
    if not seen or (research.utcnow() - seen).total_seconds() > 60:
        research.update_ide(sid, last_seen=store.now())
    resp = Response('', 200)
    resp.headers['X-Ide-Upstream'] = f"{row['host']}:{int(row['port'])}"
    resp.headers['X-Ide-Authorization'] = f"token {row['token']}"
    resp.headers['Cache-Control'] = 'no-store'
    if set_cookie:
        resp.headers['X-Ide-Set-Cookie'] = set_cookie
    return resp
