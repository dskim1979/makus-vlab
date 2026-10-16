# -*- coding: utf-8 -*-
"""
MOAVI Desk - research data (포털 > 데이터, 연구 데이터 > ...), pegaprox/vlab/datasets.py.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/datasets                         ?q= the datasets the caller may use, where they are on the desktops  vlab.desk
  GET    /api/vlab/datasets/<ds_id>/files           ?path= a folder of a dataset (engine mount)          vlab.desk
  GET    /api/vlab/datasets/<ds_id>/download        ?path= a file, Range answered - export rule allow    vlab.desk
  GET    /api/vlab/me/data                          the caller's folders per pool: paths, usage, quota, rules, how files move  vlab.desk
  GET    /api/vlab/me/data/files                    ?pool_id=&folder=&path= a folder                    vlab.desk
  GET    /api/vlab/me/data/download                 ?pool_id=&folder=&path= a file - export rule allow  vlab.desk
  POST   /api/vlab/me/data/mkdir                    {pool_id, folder, path, name}                       vlab.desk
  GET    /api/vlab/me/data/uploads                  uploads not finished (to resume)                    vlab.desk
  POST   /api/vlab/me/data/uploads                  {pool_id, folder, path, name, size, overwrite?} -> {id, offset, chunk}  vlab.desk
  GET    /api/vlab/me/data/uploads/<upload_id>      the offset to go on from                             vlab.desk
  PATCH  /api/vlab/me/data/uploads/<upload_id>      Upload-Offset header, application/offset+octet-stream part  vlab.desk
  DELETE /api/vlab/me/data/uploads/<upload_id>      give it up                                           vlab.desk
  GET    /api/vlab/me/data/requests                 the caller's export requests                         vlab.desk
  POST   /api/vlab/me/data/requests                 {pool_id, folder, path | dataset_id, path; reason}   vlab.desk
  POST   /api/vlab/me/data/requests/<rid>/cancel                                                          vlab.desk
  POST   /api/vlab/me/data/requests/<rid>/link      an approved request's one-time link (a new token)    vlab.desk
  GET    /api/vlab/data/links/<token>               the download; the requester only, once (then resume only), until it expires  vlab.desk
  GET    /api/vlab/admin/datasets                   the catalog with the pools                           vlab.data.manage
  POST   /api/vlab/admin/datasets                   {name, title, ..., kind, server, share, admin_path, pool_ids, access, export}  vlab.data.manage
  PUT    /api/vlab/admin/datasets/<ds_id>                                                                 vlab.data.manage
  DELETE /api/vlab/admin/datasets/<ds_id>                                                                 vlab.data.manage
  POST   /api/vlab/admin/datasets/<ds_id>/measure   size and file count (engine mount, else a desktop's agent)  vlab.data.manage
  GET    /api/vlab/admin/data/policies              per pool: export, upload, size limit, link hours, quota, SFTP  vlab.data.manage
  PUT    /api/vlab/admin/data/policies/<pool_id>                                                          vlab.data.manage
  GET    /api/vlab/admin/data/requests              ?status= export requests                            vlab.data.manage
  POST   /api/vlab/admin/data/requests/<rid>/approve  {hours?, note?}                                    vlab.data.manage
  POST   /api/vlab/admin/data/requests/<rid>/reject   {note}                                             vlab.data.manage
  GET    /api/vlab/admin/data/usage                 dataset sizes, user folders against their quota      vlab.data.manage
  GET    /api/vlab/admin/reports/data-transfers     ?days=&username=&format=csv exports and uploads per user and source  vlab.report.view

Files move through the pool's admin mount on the engine host (shared storage admin_path) when
it is there; else through the guest agent of one of the caller's running Linux desktops of the
pool, up to datasets.AGENT_MAX_BYTES. Guest agent calls run inside the request (no thread, no
background step), like ensure_storage.
"""

import base64
import csv
import hashlib
import io
import logging
import os
import re
import shlex
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, jsonify, request, send_file

from pegaprox.api import vlab as core
from pegaprox.api import vlab_next as vn
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, nas, store
from pegaprox.vlab import datasets as ds_mod

bp = Blueprint('vlab_data', __name__)

_bad = core._bad
_user = core._user
MANAGE = 'vlab.data.manage'
AGENT_WAIT = 60.0
PIECE = 46080                        # bytes per guest agent file-write (61440 base64 characters)
_q = shlex.quote


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _err(code, msg, status, **extra):
    return jsonify(dict({'error': msg, 'code': code}, **extra)), status


def _has(perm):
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    try:
        return has_permission(build_authz_user(_user(), request.session), perm)
    except Exception:
        return False


def _role(username):
    from pegaprox.utils.auth import load_users
    return ((load_users() or {}).get(username) or {}).get('role') or ''


def _ip():
    try:
        return get_client_ip()
    except Exception:
        return ''


# --- who reaches what ----------------------------------------------------------------------

def _my_pools(username):
    """{pool_id: pool} the caller has a desktop in or is granted (shared, build farm) - as /me/storage."""
    pools = {}
    for d in store.desktops_of_user(username):
        p = store.get_pool(d['pool_id'])
        if p and core._can_reach(p['cluster_id']):
            pools[p['id']] = p
    for p in store.list_pools():
        if (p['id'] not in pools and p['type'] in ('shared', 'buildfarm') and core._can_reach(p['cluster_id'])
                and vn.granted(p['id'], username)):
            pools[p['id']] = p
    return pools


def _who(username):
    return catalog.department_of(username), vn._user_groups(username)


def _may_use(ds, username, who=None):
    dep, groups = who or _who(username)
    return ds_mod.may_use(ds, username, dep, groups, catalog.descendants)


def datasets_for(pool_id, usernames):
    """The datasets a desktop of the pool mounts: in the pool, and one of `usernames` may use
    them (None: every one of the pool's, for the template's map)."""
    out = []
    for ds in ds_mod.list_datasets():
        if not ds_mod.in_pool(ds, pool_id):
            continue
        if usernames is None or any(_may_use(ds, u) for u in usernames if u):
            out.append(ds)
    return out


def _agent_desk(pool, username):
    """(desktop, manager, node) of one of the user's running VMs in the pool, or None."""
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None
    live = core._vm_states(pool['cluster_id'])
    for d in store.desktops_of_user(username):
        if d['pool_id'] != pool['id'] or d.get('vm_type') != 'qemu':
            continue
        vm = live.get(int(d['vmid'])) or {}
        if vm.get('status') == 'running':
            return d, mgr, vm.get('node') or d['node']
    return None


def _engine_root(cfg, rel):
    """The real folder under the pool's admin mount, or None when the mount is not there (the
    top folder - home/, scratch/ - must be: an empty mount point is not the NAS)."""
    if not cfg.get('admin_path'):
        return None
    admin = os.path.realpath(cfg['admin_path'])
    if not os.path.isdir(os.path.join(admin, rel.split('/')[0])):
        return None
    return ds_mod.resolve(admin, rel)


def _space(username, pool_id, folder, need_route=True):
    """The caller's folder in a pool: (space, None) or (None, error response). space: mode
    engine (root) or agent (guest path, desktop) - or none when need_route is False."""
    pools = _my_pools(username)
    pool = pools.get(str(pool_id or ''))
    if not pool:
        return None, _err('NOT_FOUND', 'Pool not found', 404)
    cfg = vn.storage_config(pool['id'])
    if not cfg:
        return None, _err('NO_STORAGE', 'This pool has no shared storage', 409)
    folders = vn._user_folders(cfg, pool, username) or {}
    if folder not in folders:
        return None, _err('NO_FOLDER', f'No {folder} folder for you in this pool', 404)
    sp = {'pool': pool, 'cfg': cfg, 'folder': folder, 'rel': folders[folder], 'mode': 'none',
          'policy': ds_mod.get_policy(pool['id']), 'user': nas.guest_name(username)}
    try:
        root = _engine_root(cfg, folders[folder])
    except ValueError:
        return None, _err('BAD_PATH', 'The folder is outside the admin mount', 400)
    if root:
        if not os.path.isdir(root):
            return None, _err('FOLDER_MISSING', 'Your folder is not there yet - connect to a desktop of the pool once', 409)
        sp.update(mode='engine', root=root)
        return sp, None
    a = _agent_desk(pool, username) if need_route else None
    if a:
        sp.update(mode='agent', guest=f"{cfg['linux_path']}/{folders[folder]}", desk=a[0], mgr=a[1], node=a[2])
    elif need_route:
        return None, _err('NO_ROUTE', 'Files move through the engine\'s NAS mount or one of your running Linux desktops of '
                                      'the pool - start a desktop, or ask the admin for the admin mount', 409)
    return sp, None


def _route(sp):
    return 'engine' if sp['mode'] == 'engine' else 'agent'


def _usage_kb(pool_id, username):
    rows = nas.results(pool_id=pool_id, username=username, limit=20)
    r = next((x for x in rows if x.get('usage')), None)
    return (r['usage'], r['usage_at']) if r else ({}, None)


def _quota_state(used_kb, quota_gb):
    if not quota_gb or used_kb is None:
        return None
    lim = quota_gb * 1024 * 1024
    return 'over' if used_kb > lim else 'near' if used_kb > lim * 0.9 else None


# --- the guest agent ---------------------------------------------------------------------

_AGENT_CODES = {20: ('OUTSIDE', 400), 21: ('NOT_FOUND', 404), 22: ('TOO_BIG', 413), 23: ('EXISTS', 409),
                24: ('NOT_A_FILE', 400)}


def _guard(base, rel, must_exist=True):
    """sh lines: R is the real path of base/rel, refused outside base (a link pointing out too)."""
    lines = ['set -u', f'B={_q(base)}', (f'P="$B"/{_q(rel)}' if rel else 'P="$B"'),
             'ls "$B" >/dev/null 2>&1',                                         # wake autofs
             'RB=$(readlink -f -- "$B") || { echo "no folder" >&2; exit 21; }',
             'R=$(readlink -f -- "$P") || { echo "not found" >&2; exit 21; }',
             'case "$R" in "$RB"|"$RB"/*) ;; *) echo "outside the folder" >&2; exit 20;; esac']
    if must_exist:
        lines.append('[ -e "$R" ] || { echo "not found" >&2; exit 21; }')
    return lines


def _run(sp, lines, wait=AGENT_WAIT):
    """Run sh on the desktop as root (the user's own steps go through runuser). (out, None) or (None, error response)."""
    if vn._guest_os(sp['mgr'], sp['node'], sp['desk']['vmid']) != 'linux':
        return None, _err('NO_AGENT', 'The desktop\'s guest agent does not answer, or it is not Linux', 409)
    code, out, err, e = vn._agent_run(sp['mgr'], sp['node'], sp['desk']['vmid'], ['/bin/sh', '-c', '\n'.join(lines) + '\n'], wait=wait)
    if code is None:
        return None, _err('AGENT_ERROR', e or 'the guest did not finish in time', 504 if not e else 502)
    if code != 0:
        label, status = _AGENT_CODES.get(code, ('AGENT_FAILED', 502))
        return None, _err(label, (err or '').strip()[-300:] or label, status)
    return out, None


def _agent_list(sp, rel):
    out, err = _run(sp, _guard(sp['guest'], rel) + [
        '[ -d "$R" ] || { echo "not a folder" >&2; exit 24; }',
        f'U={_q(sp["user"])}',
        "runuser -u \"$U\" -- find \"$R\" -mindepth 1 -maxdepth 1 -printf '%y\\t%s\\t%T@\\t%f\\n' 2>/dev/null | head -n 2000"], wait=20.0)
    if err:
        return None, err
    entries = []
    for line in out.splitlines():
        parts = line.split('\t', 3)
        if len(parts) != 4 or parts[3].startswith(ds_mod.PART):
            continue
        kind = {'d': 'dir', 'f': 'file', 'l': 'link'}.get(parts[0], 'file')
        try:
            mtime = datetime.fromtimestamp(float(parts[2]), timezone.utc).isoformat(timespec='seconds')
            size = int(parts[1]) if kind == 'file' else 0
        except ValueError:
            continue
        entries.append({'name': parts[3], 'type': kind, 'size': size, 'mtime': mtime})
    return sorted(entries, key=lambda x: (x['type'] != 'dir', x['name'].lower())), None


def _agent_read(sp, rel):
    out, err = _run(sp, _guard(sp['guest'], rel) + [
        '[ -f "$R" ] || { echo "not a file" >&2; exit 24; }',
        f'U={_q(sp["user"])}',
        'S=$(stat -c %s "$R")', 'echo "size=$S"',
        f'[ "$S" -le {ds_mod.AGENT_MAX_BYTES} ] || {{ echo "larger than {ds_mod.AGENT_MAX_BYTES // 1048576} MB - through the guest agent only small files move" >&2; exit 22; }}',
        'runuser -u "$U" -- base64 -w0 "$R"'])
    if err:
        return None, err
    head, _, b64 = out.partition('\n')
    try:
        return base64.b64decode(b64.strip() or b''), None
    except ValueError:
        return None, _err('AGENT_FAILED', 'the guest sent something that is not base64', 502)


def _agent_write(sp, rel_dir, name, data, overwrite, upload_id):
    """Put `data` into rel_dir/name as the user: parts into /tmp through file-write, then joined
    as the user and checked with sha256sum. (sha256, None) or (None, error response)."""
    digest = hashlib.sha256(data).hexdigest()
    tmp = f'/tmp/moavi-up-{upload_id}'
    mgr, node, vmid = sp['mgr'], sp['node'], sp['desk']['vmid']
    _, err = _run(sp, [f'rm -rf {_q(tmp)}; mkdir -m 755 {_q(tmp)}'], wait=15.0)
    if err:
        return None, err
    for i in range(0, max(len(data), 1), PIECE):
        piece = data[i:i + PIECE]
        try:
            resp = mgr._api_post(vn._agent(mgr, node, vmid, 'file-write'),
                                 data={'file': f'{tmp}/{i // PIECE:06d}', 'content': base64.b64encode(piece).decode('ascii'), 'encode': 0})
        except Exception as e:
            return None, _err('AGENT_ERROR', str(e)[:300], 502)
        if getattr(resp, 'status_code', 0) != 200:
            return None, _err('AGENT_ERROR', (getattr(resp, 'text', '') or 'file-write refused')[:300], 502)
    lines = _guard(sp['guest'], rel_dir) + [
        '[ -d "$R" ] || { echo "not a folder" >&2; exit 24; }',
        f'U={_q(sp["user"])}', f'T={_q(tmp)}', f'F="$R"/{_q(name)}',
        f'if [ -e "$F" ] && [ {int(bool(overwrite))} = 0 ]; then rm -rf "$T"; echo "$F exists" >&2; exit 23; fi',
        'chmod 644 "$T"/* 2>/dev/null',
        f'runuser -u "$U" -- sh -c \'cat "$1"/* > "$2{ds_mod.PART}$3" && mv -f "$2{ds_mod.PART}$3" "$2"\' sh "$T" "$F" {_q(upload_id)}; rc=$?',
        'rm -rf "$T"', '[ $rc = 0 ] || exit $rc',
        'echo "sha256=$(runuser -u "$U" -- sha256sum -- "$F" | cut -c1-64)"']
    out, err = _run(sp, lines)
    if err:
        return None, err
    got = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    if got.get('sha256') != digest:
        return None, _err('HASH_MISMATCH', 'the file on the desktop is not what was sent', 502)
    return digest, None


# --- downloads ---------------------------------------------------------------------------

def _range_start(size):
    m = re.match(r'^bytes=(\d*)-(\d*)$', (request.headers.get('Range') or '').strip())
    if not m:
        return 0, size
    a, b = m.group(1), m.group(2)
    if a == '':
        n = min(int(b or 0), size)
        return size - n, n
    start = int(a)
    end = min(int(b), size - 1) if b else size - 1
    return start, max(0, end - start + 1)


def _send_path(path, name, username, log):
    """A file of the engine mount, Range answered; logged (bytes sent, SHA-256) unless HEAD."""
    size = os.path.getsize(path)
    start, length = _range_start(size)
    digest = ds_mod.sha256_file(path, 0 if start else ds_mod.HASH_INLINE_MAX)
    resp = send_file(path, mimetype='application/octet-stream', as_attachment=True, download_name=name, conditional=True, max_age=0)
    resp.headers['Accept-Ranges'] = 'bytes'
    if digest:
        resp.headers['X-Content-SHA256'] = digest
    if request.method != 'HEAD' and resp.status_code in (200, 206):
        sent = length if resp.status_code == 206 else size
        ds_mod.log_transfer(username, 'download', size=sent, sha256=digest, ip=_ip(), via='engine', **log)
        log_audit(username, 'vlab.data.download',
                  f"{log.get('path')} ({sent} of {size} bytes{', from ' + str(start) if resp.status_code == 206 and start else ''}) "
                  f"sha256 {digest or 'not hashed (large)'}", _ip())
    return resp


def _send_bytes(data, name, username, log):
    digest = hashlib.sha256(data).hexdigest()
    resp = send_file(io.BytesIO(data), mimetype='application/octet-stream', as_attachment=True, download_name=name,
                     conditional=True, max_age=0)
    resp.headers['X-Content-SHA256'] = digest
    if request.method != 'HEAD':
        ds_mod.log_transfer(username, 'download', size=len(data), sha256=digest, ip=_ip(), via='agent', **log)
        log_audit(username, 'vlab.data.download', f"{log.get('path')} ({len(data)} bytes, guest agent) sha256 {digest}", _ip())
    return resp


def _probe():
    """?probe=1: every check of a download, nothing sent or logged - the portal asks before it
    hands the link to the browser, so a refusal shows as a message."""
    return request.args.get('probe') == '1'


def _fail(username, direction, code, msg, **log):
    ds_mod.log_transfer(username, direction, ok=False, error=f'{code}: {msg}'[:500], ip=_ip(), **log)
    log_audit(username, 'vlab.data.fail', f"{direction} {log.get('path', '')}: {code} {msg[:200]}", _ip())


def _rule_answer(rule):
    if rule == 'deny':
        return _err('EXPORT_DENIED', 'Downloads from here are not allowed (export control)', 403)
    if rule == 'approval':
        return _err('APPROVAL_REQUIRED', 'Downloads from here need approval - send a request with a reason', 403)
    return None


def _folder_file(sp, rel):
    """(real path, None) of a file in an engine space."""
    try:
        path = ds_mod.resolve(sp['root'], rel)
    except ValueError as e:
        return None, _err('BAD_PATH', str(e), 400)
    if not os.path.isfile(path):
        return None, _err('NOT_FOUND', 'No such file', 404)
    return path, None


def _download_folder(username, sp, rel, request_id=''):
    log = {'pool_id': sp['pool']['id'], 'folder': sp['folder'], 'path': ds_mod.join_rel(sp['rel'], rel), 'request_id': request_id}
    name = rel.rsplit('/', 1)[-1] or 'file'
    if sp['mode'] == 'engine':
        path, err = _folder_file(sp, rel)
        if err:
            return err
        if _probe():
            return jsonify({'ok': True, 'size': os.path.getsize(path)})
        return _send_path(path, name, username, log)
    if _probe():
        return jsonify({'ok': True, 'size': None})
    data, err = _agent_read(sp, rel)
    if err:
        _fail(username, 'download', err[0].get_json().get('code'), err[0].get_json().get('error', ''), via='agent', **log)
        return err
    return _send_bytes(data, name, username, log)


def _dataset_file(ds, rel):
    if not ds['admin_path'] or not os.path.isdir(ds['admin_path']):
        return None, _err('NO_ROUTE', 'This dataset is not mounted on the engine - use it from your desktop', 409)
    try:
        path = ds_mod.resolve(ds['admin_path'], rel)
    except ValueError as e:
        return None, _err('BAD_PATH', str(e), 400)
    return path, None


# --- portal: datasets --------------------------------------------------------------------

def _ds_portal(ds, pools):
    paths = []
    for p in pools.values():
        cfg = vn.storage_config(p['id'])
        if cfg and ds_mod.in_pool(ds, p['id']):
            paths.append(dict(ds_mod.desktop_paths(ds, cfg['linux_path']), pool_id=p['id'], pool=p['name'],
                              windows=ds_mod.desktop_paths(ds)['windows'] if cfg['kind'] == 'smb' else None))
    return {k: ds[k] for k in ('id', 'name', 'title', 'description', 'version', 'license', 'source', 'tags', 'size_bytes',
                               'files', 'measured_at', 'export', 'kind')} | {
        'paths': paths, 'browsable': bool(ds['admin_path'] and os.path.isdir(ds['admin_path'])), 'nas': ds_mod.nas_path(ds)}


@bp.route('/api/vlab/datasets', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def portal_datasets():
    username = _user()
    who, pools = _who(username), _my_pools(username)
    q = (request.args.get('q') or '').strip().lower()[:100]
    out = []
    for ds in ds_mod.list_datasets():
        if not ds['enabled'] or not _may_use(ds, username, who):
            continue
        hay = ' '.join([ds['name'], ds['title'], ds['description'], ds['license'], ds['source'], ' '.join(ds['tags'])]).lower()
        if q and q not in hay:
            continue
        out.append(_ds_portal(ds, pools))
    return jsonify({'datasets': out, 'manage': _has(MANAGE), 'windows_root': ds_mod.WINDOWS_ROOT})


def _portal_ds(ds_id):
    ds = ds_mod.get_dataset(ds_id)
    if not ds or not ds['enabled'] or not _may_use(ds, _user()):
        return None, _err('NOT_FOUND', 'Dataset not found', 404)
    return ds, None


@bp.route('/api/vlab/datasets/<ds_id>/files', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def portal_dataset_files(ds_id):
    ds, err = _portal_ds(ds_id)
    if err:
        return err
    path, err = _dataset_file(ds, request.args.get('path', ''))
    if err:
        return err
    if not os.path.isdir(path):
        return _err('NOT_FOUND', 'No such folder', 404)
    return jsonify({'path': ds_mod.clean_rel(request.args.get('path', '')), 'entries': ds_mod.listing(path), 'export': ds['export']})


@bp.route('/api/vlab/datasets/<ds_id>/download', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def portal_dataset_download(ds_id):
    ds, err = _portal_ds(ds_id)
    if err:
        return err
    blocked = _rule_answer(ds['export'])
    if blocked:
        return blocked
    rel = request.args.get('path', '')
    path, err = _dataset_file(ds, rel)
    if err:
        return err
    if not os.path.isfile(path):
        return _err('NOT_FOUND', 'No such file', 404)
    if _probe():
        return jsonify({'ok': True, 'size': os.path.getsize(path)})
    rel = ds_mod.clean_rel(rel)
    return _send_path(path, rel.rsplit('/', 1)[-1], _user(), {'dataset_id': ds['id'], 'path': f"{ds['name']}/{rel}"})


# --- portal: my folders ------------------------------------------------------------------

@bp.route('/api/vlab/me/data', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_data():
    username = _user()
    spaces = []
    for p in sorted(_my_pools(username).values(), key=lambda x: x['name']):
        paths = vn.storage_paths(p, username)
        if not paths:
            continue
        cfg = vn.storage_config(p['id'])
        usage, usage_at = _usage_kb(p['id'], username)
        folders = {}
        for key, f in paths['folders'].items():
            used = usage.get(key)
            folders[key] = dict(f, usage_kb=used, quota_state=_quota_state(used, f.get('quota_gb')))
        try:
            mode = 'engine' if _engine_root(cfg, next(iter(paths['folders'].values()))['folder']) else None
        except ValueError:
            mode = None
        if not mode:
            mode = 'agent' if _agent_desk(p, username) else 'none'
        pol = ds_mod.get_policy(p['id'])
        spaces.append({'pool_id': p['id'], 'pool': p['name'], 'pool_type': p['type'], 'kind': paths['kind'], 'folders': folders,
                       'usage_at': usage_at, 'mode': mode, 'policy': pol, 'data_on_nas_only': paths['data_on_nas_only']})
    return jsonify({'spaces': spaces, 'requests': ds_mod.list_requests(username=username, limit=50),
                    'uploads': ds_mod.uploads_of(username), 'chunk': ds_mod.CHUNK, 'agent_max': ds_mod.AGENT_MAX_BYTES})


@bp.route('/api/vlab/me/data/files', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_files():
    username = _user()
    sp, err = _space(username, request.args.get('pool_id'), request.args.get('folder'))
    if err:
        return err
    try:
        rel = ds_mod.clean_rel(request.args.get('path', ''))
    except ValueError as e:
        return _err('BAD_PATH', str(e), 400)
    if sp['mode'] == 'engine':
        path = ds_mod.resolve(sp['root'], rel)
        if not os.path.isdir(path):
            return _err('NOT_FOUND', 'No such folder', 404)
        entries = ds_mod.listing(path)
    else:
        entries, err = _agent_list(sp, rel)
        if err:
            return err
    return jsonify({'path': rel, 'entries': entries, 'mode': sp['mode'], 'export': sp['policy']['export']})


@bp.route('/api/vlab/me/data/download', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_download():
    username = _user()
    sp, err = _space(username, request.args.get('pool_id'), request.args.get('folder'))
    if err:
        return err
    blocked = _rule_answer(sp['policy']['export'])
    if blocked:
        return blocked
    try:
        rel = ds_mod.clean_rel(request.args.get('path', ''))
    except ValueError as e:
        return _err('BAD_PATH', str(e), 400)
    if not rel:
        return _err('BAD_PATH', 'path: a file', 400)
    return _download_folder(username, sp, rel)


@bp.route('/api/vlab/me/data/mkdir', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_mkdir():
    username, b = _user(), _body()
    sp, err = _space(username, b.get('pool_id'), b.get('folder'))
    if err:
        return err
    try:
        rel, name = ds_mod.clean_rel(b.get('path', '')), ds_mod.clean_name(b.get('name'))
    except ValueError as e:
        return _err('BAD_PATH', str(e), 400)
    if sp['mode'] == 'engine':
        parent = ds_mod.resolve(sp['root'], rel)
        if not os.path.isdir(parent):
            return _err('NOT_FOUND', 'No such folder', 404)
        target = os.path.join(parent, name)
        if os.path.exists(target):
            return _err('EXISTS', f'{name} exists', 409)
        os.mkdir(target)
        _give(target, username, sp, folder=True)
    else:
        _, err = _run(sp, _guard(sp['guest'], rel) + ['[ -d "$R" ] || exit 24', f'U={_q(sp["user"])}',
                                                      f'[ -e "$R"/{_q(name)} ] && exit 23',
                                                      f'runuser -u "$U" -- mkdir -- "$R"/{_q(name)}'], wait=15.0)
        if err:
            return err
    log_audit(username, 'vlab.data.mkdir', f"{sp['pool']['name']}: {ds_mod.join_rel(sp['rel'], rel, name)}", _ip())
    return jsonify({'ok': True}), 201


def _give(path, username, sp, folder=False):
    """Files the engine writes on the NAS belong to the user (the uid/gid the guest's SSSD gave)."""
    ids = nas.ids_of(username)
    try:
        if ids and hasattr(os, 'chown'):
            os.chown(path, int(ids['uid']), int(ids['gid']))
        os.chmod(path, (0o700 if sp['cfg'].get('private') else 0o755) if folder else (0o600 if sp['cfg'].get('private') else 0o644))
    except OSError as e:
        logging.warning(f'[VLAB] data: owner of {path}: {e}')


# --- portal: uploads ---------------------------------------------------------------------

def _my_upload(upload_id):
    up = ds_mod.get_upload(upload_id, raw=True)
    if not up or up['username'] != _user():
        return None, _err('NOT_FOUND', 'Upload not found', 404)
    return up, None


def _up_out(up, **extra):
    return dict({k: v for k, v in up.items() if k != 'temp'}, offset=up['received'], chunk=ds_mod.CHUNK, **extra)


@bp.route('/api/vlab/me/data/uploads', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_uploads():
    return jsonify({'uploads': ds_mod.uploads_of(_user()), 'chunk': ds_mod.CHUNK})


@bp.route('/api/vlab/me/data/uploads', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def start_upload():
    username, b = _user(), _body()
    sp, err = _space(username, b.get('pool_id'), b.get('folder'))
    if err:
        return err
    pol = sp['policy']
    if not pol['upload']:
        return _err('UPLOAD_OFF', 'Uploads are turned off for this pool', 403)
    try:
        rel, name = ds_mod.clean_rel(b.get('path', '')), ds_mod.clean_name(b.get('name'))
    except ValueError as e:
        return _err('BAD_PATH', str(e), 400)
    size = b.get('size')
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return _err('BAD_SIZE', 'size: the file size in bytes', 400)
    if pol['max_file_gb'] and size > pol['max_file_gb'] * 1024 ** 3:
        return _err('TOO_BIG', f"Files up to {pol['max_file_gb']} GB", 413)
    if sp['mode'] == 'agent' and size > ds_mod.AGENT_MAX_BYTES:
        return _err('TOO_BIG', f'Without the engine\'s NAS mount files up to {ds_mod.AGENT_MAX_BYTES // 1048576} MB move '
                               '(through your desktop) - use SFTP or the desktop for larger ones', 413)
    overwrite = b.get('overwrite') is True
    warn = None
    quota = sp['cfg']['folders'][sp['folder']].get('quota_gb') or 0
    if quota:
        used = _usage_kb(sp['pool']['id'], username)[0].get(sp['folder'])
        if used is not None and used * 1024 + size > quota * 1024 ** 3:
            if pol['quota_block']:
                return _err('QUOTA', f'This would go over your {quota} GB quota', 413)
            warn = 'OVER_QUOTA'
    if sp['mode'] == 'engine':
        parent = ds_mod.resolve(sp['root'], rel)
        if not os.path.isdir(parent):
            return _err('NOT_FOUND', 'No such folder', 404)
        if os.path.exists(os.path.join(parent, name)) and not overwrite:
            return _err('EXISTS', f'{name} exists', 409)
        temp = os.path.join(parent, ds_mod.PART + '{id}')
    else:
        from pegaprox.constants import CONFIG_DIR
        spool = os.path.join(CONFIG_DIR, 'vlab-uploads')
        os.makedirs(spool, exist_ok=True)
        temp = os.path.join(spool, '{id}.part')
    up = ds_mod.new_upload(username, sp['pool']['id'], sp['folder'], rel, name, size, sp['mode'], temp, overwrite,
                           sp.get('desk', {}).get('id', ''))
    try:
        open(up['temp'], 'wb').close()
    except OSError as e:
        ds_mod.drop_upload(up['id'])
        return _err('WRITE_FAILED', e.strerror or str(e), 500)
    log_audit(username, 'vlab.data.upload.start', f"{sp['pool']['name']}: {ds_mod.join_rel(sp['rel'], rel, name)} ({size} bytes)", _ip())
    if size == 0:
        return _finish(up, sp)
    return jsonify(_up_out(up, warning=warn)), 201


@bp.route('/api/vlab/me/data/uploads/<upload_id>', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def upload_state(upload_id):
    up, err = _my_upload(upload_id)
    if err:
        return err
    return jsonify(_up_out(_true_offset(up)))


def _true_offset(up):
    """What is really in the part file (a part cut short counts as far as it went)."""
    try:
        have = os.path.getsize(up['temp'])
    except OSError:
        have = 0
    if have != up['received']:
        ds_mod.set_received(up['id'], have)
        up = dict(up, received=have)
    return up


@bp.route('/api/vlab/me/data/uploads/<upload_id>', methods=['PATCH'])
@require_auth(perms=['vlab.desk'])
def upload_part(upload_id):
    up, err = _my_upload(upload_id)
    if err:
        return err
    up = _true_offset(up)
    try:
        offset = int(request.headers.get('Upload-Offset', ''))
    except ValueError:
        return _err('BAD_OFFSET', 'Upload-Offset header required', 400)
    if offset != up['received']:
        return _err('OFFSET', 'Go on from the offset the engine has', 409, offset=up['received'])
    length = request.content_length
    if length is None or length > ds_mod.MAX_CHUNK:
        return _err('BAD_PART', f'Content-Length up to {ds_mod.MAX_CHUNK} bytes', 400)
    if offset + length > up['size']:
        return _err('BAD_PART', 'More than the file\'s size', 400)
    n = 0
    try:
        with open(up['temp'], 'r+b') as fh:
            fh.seek(offset)
            while n < length:
                block = request.stream.read(min(1024 * 1024, length - n))
                if not block:
                    break
                fh.write(block)
                n += len(block)
            fh.truncate(offset + n)
    except OSError as e:
        return _err('WRITE_FAILED', e.strerror or str(e), 500)
    ds_mod.set_received(up['id'], offset + n)
    up = dict(up, received=offset + n)
    if up['received'] < up['size']:
        return jsonify(_up_out(up))
    sp, err = _space(up['username'], up['pool_id'], up['folder'])
    if err:
        return err
    return _finish(up, sp)


def _finish(up, sp):
    """The last part is in: hash it, give it its name (refused when it exists unless overwrite)."""
    username = up['username']
    target_rel = ds_mod.join_rel(sp['rel'], up['path'], up['name'])
    log = {'pool_id': up['pool_id'], 'folder': up['folder'], 'path': target_rel}
    try:
        if up['via'] == 'engine':
            if sp['mode'] != 'engine':
                raise _Stop('NO_ROUTE', 'the engine\'s NAS mount went away', 409)
            parent = ds_mod.resolve(sp['root'], up['path'])
            final = os.path.join(parent, up['name'])
            if os.path.exists(final) and not up['overwrite']:
                raise _Stop('EXISTS', f"{up['name']} exists", 409)
            digest = ds_mod.sha256_file(up['temp'])
            os.replace(up['temp'], final)
            st = os.stat(final)
            ds_mod.remember_hash(final, st.st_size, st.st_mtime, digest)
            _give(final, username, sp)
        else:
            if sp['mode'] != 'agent':
                raise _Stop('NO_ROUTE', 'no running desktop to put the file on', 409)
            with open(up['temp'], 'rb') as fh:
                data = fh.read()
            digest, err = _agent_write(sp, up['path'], up['name'], data, up['overwrite'], up['id'])
            if err:
                j = err[0].get_json()
                raise _Stop(j.get('code', 'AGENT_FAILED'), j.get('error', ''), err[1])
            os.remove(up['temp'])
    except _Stop as s:
        _fail(username, 'upload', s.code, s.msg, size=up['size'], via=up['via'], **log)
        if s.code == 'EXISTS':
            _drop(up)
        return _err(s.code, s.msg, s.status)
    except (OSError, ValueError) as e:
        _fail(username, 'upload', 'WRITE_FAILED', str(e), size=up['size'], via=up['via'], **log)
        return _err('WRITE_FAILED', getattr(e, 'strerror', None) or str(e), 500)
    ds_mod.drop_upload(up['id'])
    ds_mod.log_transfer(username, 'upload', size=up['size'], sha256=digest, ip=_ip(), via=up['via'], **log)
    log_audit(username, 'vlab.data.upload', f"{sp['pool']['name']}: {target_rel} ({up['size']} bytes) sha256 {digest}", _ip())
    return jsonify({'done': True, 'id': up['id'], 'offset': up['size'], 'size': up['size'], 'sha256': digest, 'path': target_rel}), 201


class _Stop(Exception):
    def __init__(self, code, msg, status):
        super().__init__(msg)
        self.code, self.msg, self.status = code, msg, status


def _drop(up):
    try:
        os.remove(up['temp'])
    except OSError:
        pass
    ds_mod.drop_upload(up['id'])


@bp.route('/api/vlab/me/data/uploads/<upload_id>', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def cancel_upload(upload_id):
    up, err = _my_upload(upload_id)
    if err:
        return err
    _drop(up)
    return jsonify({'ok': True})


# --- portal: export requests -------------------------------------------------------------

def _req_names(rows):
    names = {d['id']: d['name'] for d in ds_mod.list_datasets()}
    pools = {p['id']: p['name'] for p in store.list_pools()}
    return [dict(r, dataset=names.get(r['dataset_id']), pool=pools.get(r['pool_id'])) for r in rows]


@bp.route('/api/vlab/me/data/requests', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_requests():
    return jsonify({'requests': _req_names(ds_mod.list_requests(username=_user(), limit=200))})


@bp.route('/api/vlab/me/data/requests', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def new_request():
    username, b = _user(), _body()
    reason = b.get('reason')
    if not isinstance(reason, str) or not 2 <= len(reason.strip()) <= 1000:
        return _err('BAD_REASON', 'reason: why you need it outside (2 to 1000 characters)', 400)
    try:
        rel = ds_mod.clean_rel(b.get('path', ''))
    except ValueError as e:
        return _err('BAD_PATH', str(e), 400)
    if not rel:
        return _err('BAD_PATH', 'path: a file', 400)
    if b.get('dataset_id'):
        ds, err = _portal_ds(str(b['dataset_id']))
        if err:
            return err
        rule, label = ds['export'], f"dataset {ds['name']}/{rel}"
        path, err = _dataset_file(ds, rel)
        if err:
            return err
        if not os.path.isfile(path):
            return _err('NOT_FOUND', 'No such file', 404)
        pool_id, folder, dataset_id, size = '', '', ds['id'], os.path.getsize(path)
    else:
        sp, err = _space(username, b.get('pool_id'), b.get('folder'))
        if err:
            return err
        rule, label = sp['policy']['export'], f"{sp['pool']['name']}: {ds_mod.join_rel(sp['rel'], rel)}"
        if sp['mode'] == 'engine':
            path, err = _folder_file(sp, rel)
            if err:
                return err
            size = os.path.getsize(path)
        else:
            size = 0
        pool_id, folder, dataset_id = sp['pool']['id'], sp['folder'], ''
    if rule == 'allow':
        return _err('NOT_NEEDED', 'Downloads from here are allowed without a request', 409)
    if rule == 'deny':
        return _rule_answer('deny')
    if ds_mod.pending_like(username, pool_id, dataset_id, folder, rel):
        return _err('PENDING', 'A request for this file is waiting already', 409)
    r = ds_mod.create_request(username, pool_id, dataset_id, folder, rel, size, reason.strip())
    log_audit(username, 'vlab.data.request', f"{label} ({size} bytes): {reason.strip()[:200]}", _ip())
    vn._alert('데이터 반출 승인 요청', f"{username} 님이 {label} 반출을 요청했습니다: {reason.strip()[:300]}",
              {'kind': 'data_export_request', 'user': username, 'path': label, 'severity': 'info'})
    return jsonify({'request': _req_names([r])[0]}), 201


def _my_request(rid):
    r = ds_mod.get_request(rid)
    if not r or r['username'] != _user():
        return None, _err('NOT_FOUND', 'Request not found', 404)
    return r, None


@bp.route('/api/vlab/me/data/requests/<rid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def cancel_request(rid):
    r, err = _my_request(rid)
    if err:
        return err
    ds_mod.cancel(rid)
    log_audit(_user(), 'vlab.data.request.cancel', f"request {rid} ({r['path']})", _ip())
    return jsonify({'request': ds_mod.get_request(rid)})


@bp.route('/api/vlab/me/data/requests/<rid>/link', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def request_link(rid):
    r, err = _my_request(rid)
    if err:
        return err
    ds_mod.list_requests(username=_user(), limit=1)          # expire the old ones first
    r = ds_mod.get_request(rid)
    if r['status'] != 'approved':
        return _err('NOT_APPROVED', f"The request is {r['status']}", 409)
    if r['started_at']:
        return _err('USED', 'The link was used - a download that broke off goes on with the same link in the browser', 409)
    token = ds_mod.issue_link(rid)
    return jsonify({'url': f'/api/vlab/data/links/{token}', 'expires_at': r['expires_at']})


@bp.route('/api/vlab/data/links/<token>', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def link_download(token):
    username = _user()
    r = ds_mod.by_token(token)
    if not r or r['username'] != username:
        return _err('NOT_FOUND', 'No such link', 404)
    # the rule may have changed since the approval: a deny now wins
    if r['dataset_id']:
        ds = ds_mod.get_dataset(r['dataset_id'])
        if not ds or not ds['enabled']:
            return _err('NOT_FOUND', 'Dataset not found', 404)
        rule = ds['export']
    else:
        sp, err = _space(username, r['pool_id'], r['folder'])
        if err:
            return err
        rule = sp['policy']['export']
    if rule == 'deny':
        return _rule_answer('deny')
    start = _range_start(1 << 62)[0]
    if request.method != 'HEAD':
        why = ds_mod.link_state(r, resume=start > 0)
        if why:
            return _err(why, {'EXPIRED': 'The link expired', 'USED': 'The link was used', 'NOT_APPROVED': 'Not approved'}[why], 410)
    if r['dataset_id']:
        path, err = _dataset_file(ds, r['path'])
        if err:
            return err
        if not os.path.isfile(path):
            return _err('NOT_FOUND', 'No such file', 404)
        return _send_path(path, r['path'].rsplit('/', 1)[-1], username,
                          {'dataset_id': ds['id'], 'path': f"{ds['name']}/{r['path']}", 'request_id': r['id']})
    return _download_folder(username, sp, r['path'], request_id=r['id'])


# --- admin: the catalog ------------------------------------------------------------------

def _pools_view():
    out = []
    for p in store.list_pools():
        if core._can_reach(p['cluster_id']):
            cfg = vn.storage_config(p['id'])
            out.append({'id': p['id'], 'name': p['name'], 'type': p['type'], 'storage': bool(cfg),
                        'linux_path': cfg['linux_path'] if cfg else None, 'kind': cfg['kind'] if cfg else None,
                        'admin_mount': bool(cfg and cfg.get('admin_path'))})
    return out


def _ds_admin(ds):
    return dict(ds, nas=ds_mod.nas_path(ds), mounted=bool(ds['admin_path'] and os.path.isdir(ds['admin_path'])),
                linux=ds_mod.desktop_paths(ds)['linux'], windows=ds_mod.desktop_paths(ds)['windows'])


@bp.route('/api/vlab/admin/datasets', methods=['GET'])
@require_auth(perms=[MANAGE])
def admin_datasets():
    pending = ds_mod.list_requests(status='pending')
    return jsonify({'datasets': [_ds_admin(d) for d in ds_mod.list_datasets()], 'pools': _pools_view(),
                    'pending': len(pending), 'defaults': ds_mod.DATASET_DEFAULTS, 'windows_root': ds_mod.WINDOWS_ROOT})


def _ds_audit(action, ds):
    access = ', '.join(f"{s['subject_type']}:{s['subject_id']}" for s in ds['access']) or 'everyone in its pools'
    log_audit(_user(), action, f"dataset {ds['name']} ({ds_mod.nas_path(ds)}), export {ds['export']}, access {access}, "
                                f"pools {', '.join(ds['pool_ids']) or 'all with shared storage'}", _ip())


@bp.route('/api/vlab/admin/datasets', methods=['POST'])
@require_auth(perms=[MANAGE])
def admin_create_dataset():
    fields, err = ds_mod.validate_dataset(_body())
    if err:
        return _bad(err)
    try:
        ds = ds_mod.save_dataset(None, fields, _user())
    except ValueError as e:
        return _bad(str(e), 409)
    _ds_audit('vlab.data.dataset.create', ds)
    return jsonify({'dataset': _ds_admin(ds)}), 201


@bp.route('/api/vlab/admin/datasets/<ds_id>', methods=['PUT'])
@require_auth(perms=[MANAGE])
def admin_update_dataset(ds_id):
    cur = ds_mod.get_dataset(ds_id)
    if not cur:
        return _bad('Dataset not found', 404)
    fields, err = ds_mod.validate_dataset(_body(), cur)
    if err:
        return _bad(err)
    try:
        ds = ds_mod.save_dataset(ds_id, fields, _user())
    except ValueError as e:
        return _bad(str(e), 409)
    _ds_audit('vlab.data.dataset.update', ds)
    return jsonify({'dataset': _ds_admin(ds)})


@bp.route('/api/vlab/admin/datasets/<ds_id>', methods=['DELETE'])
@require_auth(perms=[MANAGE])
def admin_delete_dataset(ds_id):
    ds = ds_mod.get_dataset(ds_id)
    if not ds:
        return _bad('Dataset not found', 404)
    ds_mod.delete_dataset(ds_id)
    log_audit(_user(), 'vlab.data.dataset.delete', f"dataset {ds['name']} ({ds_mod.nas_path(ds)}) - the data on the NAS stays", _ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/datasets/<ds_id>/measure', methods=['POST'])
@require_auth(perms=[MANAGE])
def admin_measure_dataset(ds_id):
    """Size and file count: walked on the engine's mount (20 s at most), else `du` on a running
    Linux desktop of one of its pools that mounts it."""
    ds = ds_mod.get_dataset(ds_id)
    if not ds:
        return _bad('Dataset not found', 404)
    if ds['admin_path'] and os.path.isdir(ds['admin_path']):
        size, files, complete = ds_mod.measure(os.path.realpath(ds['admin_path']))
        ds_mod.set_measure(ds_id, size, files, '' if complete else 'partial: the walk took too long, the numbers are a floor')
        how = 'engine'
    else:
        size = files = None
        how, why = 'agent', 'no running Linux desktop of its pools to measure on'
        for p in store.list_pools():
            cfg = vn.storage_config(p['id'])
            if not cfg or not ds_mod.in_pool(ds, p['id']) or not core._can_reach(p['cluster_id']):
                continue
            mgr = cluster_managers.get(p['cluster_id'])
            if not mgr or not getattr(mgr, 'is_connected', False):
                continue
            live = core._vm_states(p['cluster_id'])
            for d in store.list_desktops(p['id']):
                vm = live.get(int(d['vmid'])) or {}
                if d['vm_type'] != 'qemu' or vm.get('status') != 'running':
                    continue
                node = vm.get('node') or d['node']
                if vn._guest_os(mgr, node, d['vmid']) != 'linux':
                    continue
                path = ds_mod.desktop_paths(ds, cfg['linux_path'])['linux']
                code, out, err, e = vn._agent_run(mgr, node, d['vmid'], ['/bin/sh', '-c',
                    f'P={_q(path)}; ls "$P" >/dev/null 2>&1 || {{ echo "{path} is not mounted on this desktop" >&2; exit 21; }}; '
                    'echo size=$(timeout 50 du -sb "$P" 2>/dev/null | cut -f1); echo files=$(timeout 50 find "$P" -type f 2>/dev/null | wc -l)'],
                    wait=AGENT_WAIT)
                if code == 0:
                    got = dict(line.split('=', 1) for line in (out or '').splitlines() if '=' in line)
                    if got.get('size', '').isdigit() and got.get('files', '').strip().isdigit():
                        size, files = int(got['size']), int(got['files'].strip())
                        break
                why = (err or e or f'exit {code}').strip()[-200:]
            if size is not None:
                break
        if size is None:
            ds_mod.set_measure(ds_id, ds['size_bytes'], ds['files'], why)
            return _bad(why, 409)
        ds_mod.set_measure(ds_id, size, files)
    ds = ds_mod.get_dataset(ds_id)
    log_audit(_user(), 'vlab.data.dataset.measure', f"dataset {ds['name']}: {ds['size_bytes']} bytes, {ds['files']} files ({how})", _ip())
    return jsonify({'dataset': _ds_admin(ds)})


# --- admin: export rules, requests, usage ------------------------------------------------

@bp.route('/api/vlab/admin/data/policies', methods=['GET'])
@require_auth(perms=[MANAGE])
def admin_policies():
    return jsonify({'policies': [dict(p, policy=ds_mod.get_policy(p['id'])) for p in _pools_view()],
                    'defaults': ds_mod.POLICY_DEFAULTS, 'agent_max': ds_mod.AGENT_MAX_BYTES})


@bp.route('/api/vlab/admin/data/policies/<pool_id>', methods=['PUT'])
@require_auth(perms=[MANAGE])
def admin_set_policy(pool_id):
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']):
        return _bad('Pool not found', 404)
    cfg, err = ds_mod.validate_policy(_body(), ds_mod.get_policy(pool_id))
    if err:
        return _bad(err)
    saved = ds_mod.save_policy(pool_id, cfg)
    log_audit(_user(), 'vlab.data.policy', f"pool '{pool['name']}': export {saved['export']}, upload {'on' if saved['upload'] else 'off'}, "
                                            f"max {saved['max_file_gb'] or '-'} GB, link {saved['link_hours']} h, "
                                            f"quota {'blocks' if saved['quota_block'] else 'warns'}", _ip())
    return jsonify({'policy': saved})


@bp.route('/api/vlab/admin/data/requests', methods=['GET'])
@require_auth(perms=[MANAGE])
def admin_requests():
    status = request.args.get('status') or None
    if status and status not in ds_mod.STATUSES:
        return _bad('status: pending, approved, rejected, cancelled or expired')
    return jsonify({'requests': _req_names(ds_mod.list_requests(status=status, limit=500))})


def _pending(rid):
    r = ds_mod.get_request(rid)
    if not r:
        return None, _bad('Request not found', 404)
    if r['status'] != 'pending':
        return None, _bad(f"The request is {r['status']}", 409)
    if r['pool_id']:
        pool = store.get_pool(r['pool_id'])
        if not pool or not core._can_reach(pool['cluster_id']):
            return None, _bad('Request not found', 404)
    return r, None


@bp.route('/api/vlab/admin/data/requests/<rid>/approve', methods=['POST'])
@require_auth(perms=[MANAGE])
def admin_approve(rid):
    r, err = _pending(rid)
    if err:
        return err
    b = _body()
    hours = b.get('hours', ds_mod.get_policy(r['pool_id'])['link_hours'] if r['pool_id'] else 24)
    if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 720:
        return _bad('hours: 1 to 720')
    note = b.get('note') or ''
    if not isinstance(note, str) or len(note) > 500:
        return _bad('note: at most 500 characters')
    if r['username'] == _user() and _role(_user()) != 'admin':
        return _bad('You cannot approve your own request', 403)
    ds_mod.approve(rid, _user(), hours, note.strip())
    log_audit(_user(), 'vlab.data.approve', f"request {rid} of {r['username']}: {r['path']} ({r['size']} bytes), link {hours} h", _ip())
    from pegaprox.api.vlab_notices import export_answered
    export_answered(r, True, note.strip(), hours)
    return jsonify({'request': _req_names([ds_mod.get_request(rid)])[0]})


@bp.route('/api/vlab/admin/data/requests/<rid>/reject', methods=['POST'])
@require_auth(perms=[MANAGE])
def admin_reject(rid):
    r, err = _pending(rid)
    if err:
        return err
    note = _body().get('note')
    if not isinstance(note, str) or not note.strip() or len(note) > 500:
        return _bad('note: why (at most 500 characters)')
    ds_mod.reject(rid, _user(), note.strip())
    log_audit(_user(), 'vlab.data.reject', f"request {rid} of {r['username']}: {r['path']}: {note.strip()[:200]}", _ip())
    from pegaprox.api.vlab_notices import export_answered
    export_answered(r, False, note.strip())
    return jsonify({'request': _req_names([ds_mod.get_request(rid)])[0]})


@bp.route('/api/vlab/admin/data/usage', methods=['GET'])
@require_auth(perms=[MANAGE])
def admin_usage():
    """Dataset sizes, and each user's folders as last measured (on a connect, 지금 확인) against the quota."""
    pools = {p['id']: p for p in store.list_pools() if core._can_reach(p['cluster_id'])}
    latest = {}
    for r in nas.results(limit=5000):
        if r['pool_id'] in pools and r.get('username') and r.get('usage'):
            key = (r['pool_id'], r['username'])
            if key not in latest or (r.get('usage_at') or '') > (latest[key].get('usage_at') or ''):
                latest[key] = r
    folders = []
    for (pool_id, username), r in sorted(latest.items(), key=lambda x: (pools[x[0][0]]['name'], x[0][1])):
        cfg = nas.get(pool_id)
        for key, kb in r['usage'].items():
            q = (cfg['folders'].get(key) or {}).get('quota_gb') or 0
            folders.append({'pool_id': pool_id, 'pool': pools[pool_id]['name'], 'username': username, 'folder': key,
                            'usage_kb': kb, 'quota_gb': q, 'state': _quota_state(kb, q), 'at': r.get('usage_at')})
    sets = [{k: d[k] for k in ('id', 'name', 'title', 'size_bytes', 'files', 'measured_at', 'measure_error')} for d in ds_mod.list_datasets()]
    return jsonify({'datasets': sets, 'folders': folders,
                    'totals': {'datasets_bytes': sum(d['size_bytes'] or 0 for d in sets),
                               'folders_kb': sum(f['usage_kb'] for f in folders),
                               'over': sum(1 for f in folders if f['state'] == 'over'),
                               'near': sum(1 for f in folders if f['state'] == 'near')}})


@bp.route('/api/vlab/admin/reports/data-transfers', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def report_transfers():
    try:
        days = max(1, min(366, int(request.args.get('days', 30))))
    except ValueError:
        return _bad('days: 1 to 366')
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')
    user = (request.args.get('username') or '').strip() or None
    rows = ds_mod.transfers(since=since, username=user, limit=50000)
    names = {d['id']: d['name'] for d in ds_mod.list_datasets()}
    pools = {p['id']: p['name'] for p in store.list_pools()}
    if request.args.get('format') == 'csv':
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['at', 'username', 'direction', 'source', 'path', 'bytes', 'sha256', 'ok', 'error', 'via', 'request_id', 'ip'])
        for r in reversed(rows):
            src = f"dataset:{names.get(r['dataset_id'], r['dataset_id'])}" if r['dataset_id'] else f"{pools.get(r['pool_id'], r['pool_id'])}/{r['folder']}"
            w.writerow([r['at'], r['username'], r['direction'], src, r['path'], r['size'], r['sha256'], int(r['ok']), r['error'],
                        r['via'], r['request_id'], r['ip']])
        log_audit(_user(), 'vlab.data.report', f'data transfers CSV, {days} days', _ip())
        return Response('﻿' + buf.getvalue(), mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="moavi-data-transfers-{days}d.csv"'})
    out = ds_mod.report(rows, names, pools)
    return jsonify(dict(out, days=days, since=since, recent=[dict(r, dataset=names.get(r['dataset_id']), pool=pools.get(r['pool_id']))
                                                              for r in rows[:200]]))
