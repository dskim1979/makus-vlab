"""MOAVI Desk: the support bundle (플랫폼 설정 > 지원).

  GET  /api/vlab/admin/support-bundle/preview   ?from=&to=&...   what the bundle would hold (counts)  admin.settings
  GET  /api/vlab/admin/support-bundle           ?from=&to=&...   the ZIP                               admin.settings

`from` / `to` are the server's local time, 'YYYY-MM-DDTHH:MM' (the console's datetime-local);
the period is at most MAX_DAYS long and defaults to the last 24 hours. Options (0/1):
  logs=1        engine and per-cluster log lines in the period
  audit=1       the audit log in the period
  sessions=1    vLAB sessions, card loans, build jobs, alerts in the period
  tasks=1       Proxmox tasks that started in the period
  config=1      pools, desktops, gateways, licence servers ... as they are now
  mask_ips=1    192.168.10.21 -> 192.x.x.x everywhere in the bundle
  mask_users=0  user names replaced by user-1, user-2 ... (one mapping for the whole bundle)

Passwords, tokens, keys and webhook secrets never go in: settings and rows are redacted by key
name, recursively, and log lines by pattern. The core's /api/support-bundle (PegaProx) is not
period-aware and has none of the MOAVI Desk tables; this one is what the console offers.
"""
import io
import json
import logging
import os
import platform
import re
import socket
import zipfile
from collections import deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, store

bp = Blueprint('vlab_support', __name__)
log = logging.getLogger(__name__)

MAX_DAYS = 31
MAX_ROWS = 20000                  # per table
MAX_TASKS = 2000
MAX_LOG_BYTES = 8 * 1024 * 1024   # per log file in the bundle
MAX_LOG_FILES = 12
SENSITIVE = ('password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'key_hash', 'private_key',
             'ssl_key', 'bind_pw', 'smtp_pass', 'webhook_url', 'otp', 'totp_secret', 'cookie')
_TS_RE = re.compile(r'^\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})')
_IP_RE = re.compile(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
_SECRET_RE = [re.compile(r'((?:password|passwd|token|secret|api[_-]?key|authorization)["\']?\s*[:=]\s*["\']?(?:bearer\s+)?)[^"\'&\s,}]+', re.I),
              re.compile(r'(PVEAPIToken=)[^\s"\']+', re.I)]


def _bad(msg, code=400):
    return jsonify({'error': msg}), code


def _flag(name, default):
    v = request.args.get(name)
    return default if v is None else v not in ('0', 'false', 'no', '')


def _period():
    """(start, end) as aware local datetimes, or an error response."""
    now = datetime.now().astimezone()
    try:
        end = datetime.fromisoformat(request.args['to']).astimezone() if request.args.get('to') else now
        start = datetime.fromisoformat(request.args['from']).astimezone() if request.args.get('from') else end - timedelta(hours=24)
    except ValueError:
        return None, _bad('from / to must look like 2026-10-16T09:00')
    if start >= end:
        return None, _bad('from must be before to')
    if end - start > timedelta(days=MAX_DAYS):
        return None, _bad(f'The period can be at most {MAX_DAYS} days')
    return (start, min(end, now + timedelta(minutes=1))), None


class _Mask:
    """IP and user-name masking with one consistent mapping per bundle."""

    def __init__(self, ips, users):
        self.ips, self.users, self.map = ips, users, {}
        self._re = None
        if users:
            names = {u for u in (r.get('assigned_user') for r in store.list_desktops()) if u}
            try:
                from pegaprox.utils.auth import load_users
                names |= set(load_users().keys())
            except Exception:
                pass
            for i, n in enumerate(sorted(names, key=lambda x: (-len(x), x)), 1):
                self.map[n] = f'user-{i}'
            self._re = re.compile(r'\b(' + '|'.join(re.escape(n) for n in self.map) + r')\b') if self.map else None

    def text(self, s):
        if not isinstance(s, str):
            return s
        if self.ips:
            s = _IP_RE.sub(r'\1.x.x.x', s)
        if self.users and self._re is not None:
            s = self._re.sub(lambda m: self.map[m.group(1)], s)
        return s

    def value(self, v):
        if isinstance(v, dict):
            return {k: ('[REDACTED]' if x not in (None, '', 0, False) and _sensitive(k) else self.value(x)) for k, x in v.items()}
        if isinstance(v, list):
            return [self.value(x) for x in v]
        return self.text(v)


def _sensitive(key):
    k = str(key).lower()
    return any(s in k for s in SENSITIVE) or k in ('key', 'pass', 'pwd')


def _redact_line(line, mask):
    for r in _SECRET_RE:
        line = r.sub(r'\1[REDACTED]', line)
    return mask.text(line)


def _rows(sql, args):
    try:
        return [dict(r) for r in store.db().query(sql + f' LIMIT {MAX_ROWS}', args)]
    except Exception as e:      # a table that does not exist on this install yet
        return [{'error': f'{type(e).__name__}: {e}'}]


def _utc(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds')


def _local(dt):
    return dt.replace(tzinfo=None).isoformat(timespec='seconds')


def _activity(start, end):
    """vLAB rows of the period. vLAB tables keep UTC ISO text; overlapping rows count."""
    a, b = _utc(start), _utc(end)
    return {
        'sessions.json': _rows('SELECT * FROM vlab_sessions WHERE started_at <= ? AND (ended_at IS NULL OR ended_at >= ?) ORDER BY started_at', (b, a)),
        'card_loans.json': _rows('SELECT * FROM vlab_leases WHERE starts_at <= ? AND (COALESCE(returned_at, ends_at) IS NULL OR COALESCE(returned_at, ends_at) >= ?) ORDER BY starts_at', (b, a)),
        'build_jobs.json': [dict(j, output=(j.get('output') or '')[-4000:]) for j in
                            _rows('SELECT * FROM vlab_build_jobs WHERE created_at <= ? AND (finished_at IS NULL OR finished_at >= ?) ORDER BY created_at', (b, a))],
        'alerts.json': _rows('SELECT * FROM active_alerts WHERE triggered_at <= ? AND (resolved_at IS NULL OR resolved_at >= ?) ORDER BY triggered_at', (_local(end), _local(start))),
    }


def _audit(start, end):
    # the core audit log keeps naive local ISO text
    return _rows('SELECT timestamp, user, action, details, ip_address, cluster, severity FROM audit_log '
                 'WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp', (_local(start), _local(end)))


def _config():
    out = {
        'pools.json': store.list_pools(),
        'desktops.json': store.list_desktops(),
        'labs.json': store.list_labs(),
        'terminals.json': [{k: v for k, v in t.items() if k not in ('key_hash',)} for t in store.list_terminals()],
        'lab_schedules.json': store.list_lab_schedules(),
        'gateways.json': catalog.list_gateways(secret=False),
        'external_desktops.json': catalog.list_external(),
        'golden_images.json': catalog.list_golden(),
        'boards.json': catalog.list_boards(),
        'license_servers.json': catalog.list_license_servers(),
        'usb_devices.json': catalog.list_usb_devices(),
        'departments.json': catalog.list_departments(),
    }
    try:
        from pegaprox.api.helpers import load_server_settings
        out['server_settings.json'] = load_server_settings()
    except Exception as e:
        out['server_settings_error.txt'] = f'{type(e).__name__}: {e}'
    return out


def _clusters(start, end, with_tasks):
    status, tasks = [], []
    t0, t1 = start.timestamp(), end.timestamp()
    for cid, mgr in list(cluster_managers.items()):
        cfg = getattr(mgr, 'config', None)
        status.append({'id': cid, 'name': getattr(cfg, 'name', ''), 'host': getattr(cfg, 'host', ''),
                       'connected': bool(getattr(mgr, 'is_connected', False)),
                       'connection_error': getattr(mgr, 'connection_error', None),
                       'current_host': getattr(mgr, 'current_host', None)})
        if with_tasks and getattr(mgr, 'is_connected', False):
            try:
                for t in mgr.get_tasks(limit=MAX_TASKS) or []:
                    st = float(t.get('starttime') or 0)
                    if t0 <= st < t1:
                        tasks.append(dict(t, cluster_id=cid,
                                          started=datetime.fromtimestamp(st).isoformat(timespec='seconds')))
            except Exception as e:
                tasks.append({'cluster_id': cid, 'error': f'{type(e).__name__}: {e}'})
    tasks.sort(key=lambda t: t.get('starttime') or 0)
    return status, tasks[:MAX_TASKS]


def _log_files():
    from pegaprox.constants import CONFIG_DIR, LOG_DIR
    seen, out = set(), []
    for p in [os.path.join(LOG_DIR, 'pegaprox.log'), os.path.join(CONFIG_DIR, 'pegaprox.log')] + \
            sorted((os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.endswith('.log')) if os.path.isdir(LOG_DIR) else [],
                   key=lambda f: -os.path.getmtime(f)):
        real = os.path.realpath(p)
        if os.path.isfile(p) and real not in seen:
            seen.add(real)
            out.append(p)
    return out[:MAX_LOG_FILES]


def _log_slice(path, start, end, mask):
    """Lines whose timestamp falls in the period (a line without one goes with the line
    above it - tracebacks). A log that carries no timestamps at all gives its last lines."""
    a, b = start.replace(tzinfo=None), end.replace(tzinfo=None)
    keep, size, stamped, inside = [], 0, False, False
    tail = deque(maxlen=2000)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _TS_RE.match(line)
            if m:
                stamped = True
                try:
                    inside = a <= datetime.fromisoformat(f'{m.group(1)}T{m.group(2)}') < b
                except ValueError:
                    pass
            elif not stamped:
                tail.append(line)
            if inside and size < MAX_LOG_BYTES:
                keep.append(line)
                size += len(line)
    if not stamped:
        return (f'# {os.path.basename(path)} has no timestamps (engine not in debug logging): its last {len(tail)} lines\n'
                + ''.join(_redact_line(l, mask) for l in tail)), len(tail)
    note = f'# truncated at {MAX_LOG_BYTES // (1024 * 1024)} MB\n' if size >= MAX_LOG_BYTES else ''
    return note + ''.join(_redact_line(l, mask) for l in keep), len(keep)


def _versions():
    try:
        from pegaprox.constants import PEGAPROX_BUILD, PEGAPROX_VERSION
    except Exception:
        PEGAPROX_VERSION = PEGAPROX_BUILD = 'unknown'
    return {'engine': PEGAPROX_VERSION, 'build': PEGAPROX_BUILD, 'python': platform.python_version(),
            'platform': platform.platform(), 'hostname': socket.gethostname()}


def _opts():
    return {'logs': _flag('logs', True), 'audit': _flag('audit', True), 'sessions': _flag('sessions', True),
            'tasks': _flag('tasks', True), 'config': _flag('config', True),
            'mask_ips': _flag('mask_ips', True), 'mask_users': _flag('mask_users', False)}


@bp.route('/api/vlab/admin/support-bundle/preview', methods=['GET'])
@require_auth(perms=['admin.settings'])
def support_bundle_preview():
    period, err = _period()
    if err:
        return err
    start, end = period
    o = _opts()
    counts = {}
    if o['sessions']:
        counts.update({k[:-5]: len(v) for k, v in _activity(start, end).items()})
    if o['audit']:
        counts['audit'] = len(_audit(start, end))
    if o['tasks']:
        counts['tasks'] = len(_clusters(start, end, True)[1])
    if o['logs']:
        counts['log_files'] = len(_log_files())
    return jsonify({'from': _local(start), 'to': _local(end), 'max_days': MAX_DAYS, 'options': o, 'counts': counts})


@bp.route('/api/vlab/admin/support-bundle', methods=['GET'])
@require_auth(perms=['admin.settings'])
def support_bundle():
    period, err = _period()
    if err:
        return err
    start, end = period
    o = _opts()
    mask = _Mask(o['mask_ips'], o['mask_users'])
    stamp = f"{start.strftime('%Y%m%d-%H%M')}_{end.strftime('%Y%m%d-%H%M')}"
    root = f'moavi-desk-support_{stamp}'
    user = request.session.get('user', '')
    contents = {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        def put(name, data):
            if isinstance(data, (dict, list)):
                data = json.dumps(mask.value(data), ensure_ascii=False, indent=2, default=str)
            zf.writestr(f'{root}/{name}', data)

        status, tasks = _clusters(start, end, o['tasks'])
        put('system/versions.json', _versions())
        put('clusters/status.json', status)
        if o['tasks']:
            put('clusters/tasks.json', tasks)
            contents['tasks'] = len(tasks)
        if o['sessions']:
            for name, rows in _activity(start, end).items():
                put(f'activity/{name}', rows)
                contents[name[:-5]] = len(rows)
        if o['audit']:
            rows = _audit(start, end)
            put('audit/audit_log.json', rows)
            contents['audit'] = len(rows)
        if o['config']:
            for name, rows in _config().items():
                put(f'config/{name}', rows)
        if o['logs']:
            n = 0
            for p in _log_files():
                try:
                    text, lines = _log_slice(p, start, end, mask)
                    zf.writestr(f'{root}/logs/{os.path.basename(p)}', text)
                    n += lines
                except Exception as e:
                    zf.writestr(f'{root}/logs/{os.path.basename(p)}.error.txt', f'{type(e).__name__}: {e}')
            contents['log_lines'] = n
        manifest = {
            'product': 'MOAVI Desk', 'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
            'generated_by': user, 'period': {'from': _local(start), 'to': _local(end), 'timezone': str(start.tzinfo)},
            'options': o, 'contents': contents,
            'redaction': 'passwords, tokens, keys and webhook secrets removed by key name and pattern'
                         + ('; IPv4 addresses masked' if o['mask_ips'] else '') + ('; user names replaced' if o['mask_users'] else ''),
            'not_included': 'container logs: on the server run '
                            f"docker compose logs --since {_local(start)} --until {_local(end)} > container-logs.txt",
        }
        zf.writestr(f'{root}/manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    log_audit(user, 'vlab.support.bundle', f"support bundle {_local(start)} - {_local(end)} "
              f"({', '.join(k for k, v in o.items() if v)})", get_client_ip())
    return Response(buf.getvalue(), mimetype='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="{root}.zip"', 'Cache-Control': 'no-store'})
