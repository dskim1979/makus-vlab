"""MOAVI Desk: what can be taken back (운영 > 자원 회수) - one list of what sits unused, why,
what to do about it, and what doing it gives back.

Kinds of item:
  unused     an assigned desktop its user has not connected to for `days` days
  oversized  a VM the right-sizing analysis finds too big (or idle) over the window
  stopped    a VM switched off for at least `days` days that still holds its disk
  orphan     a VM in no pool and not used by MOAVI Desk for anything else (golden image,
             JTAG gateway, licence server, template)
  snapshot   a snapshot older than `days` days (not a desktop's base snapshot)
  loan       an idle accelerator card loan (the reclaim suggestions of workload.py)

Each item: why (reason), what it gives back (free: vcpu / ram_gb / disk_gb / cards / seats),
the recommended action and the other actions, and whether an admin keeps it (exempt). An
exempt item stays in vlab_reclaim_exempt until the admin takes the exemption off; it is not
listed (nor counted) unless asked for.

Totals add up the non-exempt items whose step is known (an orphan to 확인 is left out),
counting a VM once (the largest of its items for each
resource), and say how many more desktops of the cluster's typical spec (the median of its
desktops) the freed vCPU and memory hold.

Nothing here acts: the routes (pegaprox/api/vlab_reclaim.py) apply one item when an admin
asks, through the routes that already do each step.
"""
import json
import math
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, now

KINDS = ('unused', 'oversized', 'stopped', 'orphan', 'snapshot', 'loan')
DAYS = (7, 14, 30, 60, 90)
GB = 1024 ** 3

# action id -> (Korean label, destructive: the target's name is typed to confirm)
ACTIONS = {
    'unassign': ('배정 해제', False),
    'shutdown': ('끄기', False),
    'resize': ('크기 줄이기', False),
    'delete_vm': ('VM 삭제', True),
    'delete_snapshot': ('스냅숏 삭제', True),
    'return_card': ('카드 반납', False),
    'review': ('확인', False),
}

FALLBACK_SPEC = {'vcpu': 2, 'ram_gb': 4.0, 'disk_gb': 64.0}

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_reclaim_exempt (
        key TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        cluster_id TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        by_user TEXT NOT NULL DEFAULT '',
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_reclaim_exempt',)
SETTINGS_KEY = 'vlab_reclaim_settings'
STATE_KEY = 'vlab_reclaim_state'
SETTINGS_DEFAULTS = {'weekly': False, 'weekday': 0, 'hour': 9, 'days': 30}
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_reclaim', False):
        with _lock:
            if not getattr(d, '_vlab_reclaim', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_reclaim = True
    return d


def ts(iso):
    try:
        t = datetime.fromisoformat(str(iso).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def utcnow():
    return datetime.now(timezone.utc)


# --- exemptions ------------------------------------------------------------------------------

def exemptions():
    return {r['key']: dict(r) for r in db().query('SELECT * FROM vlab_reclaim_exempt ORDER BY at DESC')}


def exempt(key, kind, cluster_id='', target='', note='', by=''):
    db().execute('''INSERT OR REPLACE INTO vlab_reclaim_exempt (key, kind, cluster_id, target, note, by_user, at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''', (key, kind, cluster_id or '', target or '', (note or '')[:200], by or '', now()))


def unexempt(key):
    db().execute('DELETE FROM vlab_reclaim_exempt WHERE key = ?', (key,))


def valid_key(key):
    if not isinstance(key, str) or not 3 <= len(key) <= 300:
        return False
    return key.split(':', 1)[0] in KINDS


# --- settings (the weekly summary) -----------------------------------------------------------

def effective_settings(saved):
    out = dict(SETTINGS_DEFAULTS)
    if isinstance(saved, dict):
        out.update({k: v for k, v in saved.items() if k in SETTINGS_DEFAULTS})
    return out


def validate_settings(data):
    if not isinstance(data, dict):
        raise ValueError('A JSON object is required')
    out = {}
    for k, v in data.items():
        if k == 'weekly':
            if not isinstance(v, bool):
                raise ValueError('weekly: true or false')
        elif k in ('weekday', 'hour'):
            hi = 6 if k == 'weekday' else 23
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= hi:
                raise ValueError(f'{k}: a whole number from 0 to {hi}')
        elif k == 'days':
            if v not in DAYS:
                raise ValueError('days: ' + ', '.join(map(str, DAYS)))
        else:
            raise ValueError(f'unknown field: {k}')
        out[k] = v
    return out


def weekly_due(settings, last_sent, at):
    """True when the weekly summary is due at `at` (local time of the server): on the set
    weekday, from the set hour, once per week."""
    if not settings.get('weekly'):
        return False
    if at.weekday() != settings.get('weekday', 0) or at.hour < settings.get('hour', 9):
        return False
    last = ts(last_sent) if last_sent else None
    if last is None:
        return True
    at_aware = at if at.tzinfo else at.astimezone()
    return (at_aware - last) > timedelta(days=6)


# --- one item --------------------------------------------------------------------------------

def key_of(kind, cluster_id='', vmid=None, extra=''):
    parts = [kind, str(cluster_id or '')]
    if vmid is not None:
        parts.append(str(vmid))
    if extra:
        parts.append(str(extra))
    return ':'.join(parts)


def _free(vcpu=0, ram_gb=0.0, disk_gb=0.0, cards=0, seats=0):
    return {'vcpu': int(vcpu or 0), 'ram_gb': round(float(ram_gb or 0), 1), 'disk_gb': round(float(disk_gb or 0), 1),
            'cards': int(cards or 0), 'seats': int(seats or 0)}


def _action(aid, **params):
    label, destructive = ACTIONS[aid]
    return {'id': aid, 'label': label, 'destructive': destructive, 'params': params}


def vm_alloc(vm):
    """(vcpu, ram GB, disk GB) of a resource row of /cluster/resources."""
    return (int(vm.get('maxcpu') or 0), round((vm.get('maxmem') or 0) / GB, 1), round((vm.get('maxdisk') or 0) / GB, 1))


def _base(kind, cluster_id, vm, desk=None, pool=None, extra=''):
    vmid = int(vm['vmid']) if vm and vm.get('vmid') is not None else (int(desk['vmid']) if desk else None)
    return {
        'key': key_of(kind, cluster_id, vmid, extra), 'kind': kind, 'cluster_id': cluster_id,
        'vmid': vmid, 'node': (vm or {}).get('node') or (desk or {}).get('node') or '',
        'vm_type': (vm or {}).get('type') or (desk or {}).get('vm_type') or 'qemu',
        # a desktop goes by its own name (what its delete asks to type); another VM by the VM's
        'name': (desk or {}).get('name') or (vm or {}).get('name') or (f'VM {vmid}' if vmid is not None else ''),
        'vm_name': (vm or {}).get('name') or '',
        'status': (vm or {}).get('status') or 'unknown',
        'desktop_id': desk['id'] if desk else None, 'desktop': desk['name'] if desk else None,
        'pool_id': pool['id'] if pool else None, 'pool': pool['name'] if pool else None,
        'user': (desk or {}).get('assigned_user') or None,
        'exempt': False,
    }


def days_since(iso, at):
    t = ts(iso)
    return None if t is None else max(0, (at - t).days)


# --- the kinds -------------------------------------------------------------------------------

def unused_desktops(cluster_id, desks, vms, pools, last_seen, at, days):
    """Assigned desktops whose user has not connected for `days` days. last_seen =
    {(desktop_id, username): started_at of the latest session}."""
    out = []
    for d in desks:
        user = d.get('assigned_user')
        if not user:
            continue
        seen = last_seen.get((d['id'], user))
        since = days_since(seen, at) if seen else None
        if seen and since is not None and since < days:
            continue
        if not seen:
            made = days_since(d.get('created_at'), at)
            if made is not None and made < days:
                continue         # new: not had the time to be used
        vm = vms.get(int(d['vmid'])) or {}
        vcpu, ram, _disk = vm_alloc(vm)
        running = vm.get('status') == 'running'
        it = _base('unused', cluster_id, vm or None, d, pools.get(d['pool_id']))
        it.update(
            reason=(f'{user} 님이 {since}일째 접속 안 함' if seen else f'{user} 님이 한 번도 접속 안 함'),
            detail={'last_connected': seen, 'idle_days': since},
            free=_free(vcpu if running else 0, ram if running else 0, seats=1),
            action=_action('unassign'),
            more=[_action('shutdown')] if running else [])
        out.append(it)
    return out


def oversized(cluster_id, recs, vms, desks_by_vmid, pools):
    """Right-sizing recommendations (insights.right_sizing) that give something back."""
    out = []
    for r in recs or []:
        try:
            vmid = int(r.get('vmid'))
        except (TypeError, ValueError):
            continue
        flags = {f.get('kind'): f for f in r.get('flags') or []}
        cpu, mem, idle = flags.get('oversized_cpu'), flags.get('oversized_mem'), flags.get('idle')
        if not (cpu or mem or idle):
            continue
        vm = vms.get(vmid) or {'vmid': vmid, 'name': r.get('name'), 'node': r.get('node'), 'type': r.get('type')}
        if vm.get('template'):
            continue
        desk = desks_by_vmid.get(vmid)
        it = _base('oversized', cluster_id, vm, desk, pools.get(desk['pool_id']) if desk else None)
        vcpu, ram, _disk = vm_alloc(vm)
        detail = {'cpu_avg': r.get('cpu_avg'), 'cpu_p95': r.get('cpu_p95'), 'mem_avg': r.get('mem_avg'),
                  'mem_max': r.get('mem_max')}
        if cpu or mem:
            new_cores = int(cpu['recommended']) if cpu else None
            new_gb = float(mem['recommended_gb']) if mem else None
            cur_cores = int(cpu.get('current') or vcpu) if cpu else vcpu
            cur_gb = float(mem.get('current_gb') or ram) if mem else ram
            why = []
            if cpu:
                why.append(f"CPU 평균 {r.get('cpu_avg')}% · p95 {r.get('cpu_p95')}%")
            if mem:
                why.append(f"메모리 평균 {r.get('mem_avg')}% · 최대 {r.get('mem_max')}%")
            params = {}
            if new_cores:
                params['cores'] = new_cores
            if new_gb:
                params['memory_mb'] = int(round(new_gb * 1024))
            detail.update(current={'vcpu': cur_cores, 'ram_gb': cur_gb},
                          recommended={'vcpu': new_cores or cur_cores, 'ram_gb': new_gb or cur_gb})
            it.update(reason=' / '.join(why),
                      free=_free(cur_cores - new_cores if new_cores else 0, cur_gb - new_gb if new_gb else 0),
                      action=_action('resize', **params), more=[])
        else:
            running = vm.get('status') == 'running'
            it.update(reason=f"거의 안 씀 (CPU 평균 {r.get('cpu_avg')}%)",
                      free=_free(vcpu if running else 0, ram if running else 0),
                      action=_action('shutdown'), more=[])
            if not running:
                continue
        it['detail'] = detail
        out.append(it)
    return out


def last_running(history):
    """({vmid: unix time of the last sample it ran in}, unix time of the first sample) from
    the core's metrics history [(ts, cluster data)]."""
    last, first = {}, None
    for t, cd in history or []:
        first = t if first is None else min(first, t)
        for vmid, m in ((cd or {}).get('vms') or {}).items():
            if isinstance(m, dict) and m.get('r'):
                try:
                    v = int(vmid)
                except (TypeError, ValueError):
                    continue
                last[v] = max(last.get(v, t), t)
    return last, first


def stopped_vms(cluster_id, vms, desks_by_vmid, pools, known, ran, first, at, days):
    """Switched-off VMs (not templates) that did not run in the last `days` days by the
    metrics history. Only when the history goes back that far; a VM never seen running is
    off for at least as long as the history."""
    if first is None:
        return []
    span = (at.timestamp() - first) / 86400
    if span < days * 0.9:
        return []
    out = []
    for vmid, vm in vms.items():
        if vm.get('template') or vm.get('status') != 'stopped':
            continue
        t = ran.get(vmid)
        off = (at.timestamp() - t) / 86400 if t else span
        if off < days:
            continue
        desk = desks_by_vmid.get(vmid)
        vcpu, ram, disk = vm_alloc(vm)
        it = _base('stopped', cluster_id, vm, desk, pools.get(desk['pool_id']) if desk else None)
        where = '' if desk or vmid in known else '풀 밖 · '
        it.update(reason=f"{where}{int(off)}일{'' if t else ' 넘게'} 꺼짐 · 디스크 {disk:g} GB",
                  detail={'off_days': int(off), 'last_ran': datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='seconds') if t else None,
                          'orphan': not desk and vmid not in known},
                  free=_free(disk_gb=disk), action=_action('delete_vm', confirm=it['name']), more=[])
        if desk and desk.get('assigned_user'):
            it['more'] = [_action('unassign')]
        out.append(it)
    return out


def orphans(cluster_id, vms, desks_by_vmid, known, skip):
    """VMs in no pool that MOAVI Desk does not use for anything else. `skip` = vmids listed
    already (a long-stopped orphan is a 'stopped' item)."""
    out = []
    for vmid, vm in vms.items():
        if vm.get('template') or vmid in desks_by_vmid or vmid in known or vmid in skip:
            continue
        vcpu, ram, disk = vm_alloc(vm)
        running = vm.get('status') == 'running'
        it = _base('orphan', cluster_id, vm)
        it.update(reason='어느 풀에도 없음' + (' · 켜져 있음' if running else ''),
                  detail={'vcpu': vcpu, 'ram_gb': ram, 'disk_gb': disk},
                  free=_free(vcpu if running else 0, ram if running else 0, disk),
                  action=_action('review'),
                  more=([_action('shutdown')] if running else []) + [_action('delete_vm', confirm=it['name'])])
        out.append(it)
    return out


def old_snapshots(cluster_id, snaps, vms, desks_by_vmid, pools, at, days):
    """snaps = {vmid: [snapshot rows of PVE]}. Base snapshots (what a reset goes back to) stay."""
    out = []
    for vmid, rows in snaps.items():
        vm = vms.get(vmid) or {'vmid': vmid}
        desk = desks_by_vmid.get(vmid)
        base = (desk or {}).get('base_snap') or ''
        for s in rows or []:
            name = s.get('name')
            if not name or name == 'current' or name == base or name == 'vlab-base':
                continue
            try:
                t = float(s.get('snaptime'))
            except (TypeError, ValueError):
                continue
            age = int((at.timestamp() - t) / 86400)
            if age < days:
                continue
            size = s.get('size_gb') if isinstance(s.get('size_gb'), (int, float)) else None
            it = _base('snapshot', cluster_id, vm, desk, pools.get(desk['pool_id']) if desk else None, extra=name)
            it.update(snapshot=name,
                      reason=f"'{name}' {age}일 지남" + (' · 메모리 포함' if s.get('vmstate') else ''),
                      detail={'age_days': age, 'taken': datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='seconds'),
                              'description': (s.get('description') or '')[:200], 'size_gb': size},
                      free=_free(disk_gb=size or 0), action=_action('delete_snapshot', confirm=name), more=[])
            out.append(it)
    return out


def loans(rows):
    """Idle card loans: list_reclaims rows (workload.reclaims with the loan beside it)."""
    out = []
    for r in rows or []:
        it = {
            'key': key_of('loan', r.get('cluster_id') or '', None, r['lease_id']), 'kind': 'loan',
            'cluster_id': r.get('cluster_id') or '', 'vmid': r.get('vmid'), 'node': '', 'vm_type': 'qemu',
            'name': r.get('card') or r['lease_id'], 'status': 'running',
            'desktop_id': r.get('desktop_id'), 'desktop': r.get('desktop'), 'pool_id': r.get('pool_id'), 'pool': r.get('pool'),
            'user': r.get('username'), 'lease_id': r['lease_id'], 'exempt': False,
            'reason': f"{days_since(r.get('idle_since'), utcnow()) or 0}일째 거의 안 씀"
                      + (f" (평균 {r['avg_util']:.0f}%)" if isinstance(r.get('avg_util'), (int, float)) else ''),
            'detail': {'idle_since': r.get('idle_since'), 'ends_at': r.get('ends_at'), 'avg_util': r.get('avg_util')},
            'free': _free(cards=1), 'action': _action('return_card'), 'more': [],
        }
        out.append(it)
    return out


# --- the report ------------------------------------------------------------------------------

def _median(xs):
    xs = sorted(x for x in xs if x)
    if not xs:
        return None
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def typical_spec(desks, vms):
    """The median vCPU / memory / disk of the desktops' VMs (FALLBACK_SPEC where none)."""
    rows = [vm_alloc(vms[int(d['vmid'])]) for d in desks if int(d['vmid']) in vms]
    cpu, ram, disk = (_median([r[i] for r in rows]) for i in range(3))
    return {'vcpu': int(cpu) if cpu else FALLBACK_SPEC['vcpu'],
            'ram_gb': round(float(ram), 1) if ram else FALLBACK_SPEC['ram_gb'],
            'disk_gb': round(float(disk), 1) if disk else FALLBACK_SPEC['disk_gb'],
            'from_desktops': len(rows)}


def mark_exempt(items, exempt_keys):
    for it in items:
        it['exempt'] = it['key'] in exempt_keys
    return items


def totals(items, spec):
    """What the non-exempt items give back, a VM counted once (its largest per resource)."""
    per_vm, other = {}, []
    snaps = 0
    review = 0
    for it in items:
        if it.get('exempt'):
            continue
        if (it.get('action') or {}).get('id') == 'review':
            review += 1            # a VM nobody has said what it is: not counted until an admin decides
            continue
        if it['kind'] == 'snapshot':
            snaps += 1
            other.append(it['free'])          # a snapshot's space is its own, not the VM's
            continue
        if it['kind'] == 'loan' or it.get('vmid') is None:
            other.append(it['free'])
            continue
        k = (it['cluster_id'], it['vmid'])
        cur = per_vm.setdefault(k, _free())
        for r, v in it['free'].items():
            cur[r] = max(cur[r], v)
    out = _free()
    for f in list(per_vm.values()) + other:
        for r, v in f.items():
            out[r] += v
    out['ram_gb'] = round(out['ram_gb'], 1)
    out['disk_gb'] = round(out['disk_gb'], 1)
    fits = [out['vcpu'] / spec['vcpu'] if spec.get('vcpu') else 0,
            out['ram_gb'] / spec['ram_gb'] if spec.get('ram_gb') else 0]
    out['more_desktops'] = int(math.floor(min(fits))) if fits else 0
    out['snapshots'] = snaps
    out['items'] = sum(1 for it in items if not it.get('exempt'))
    out['review'] = review
    return out


def counts(items):
    c = {k: 0 for k in KINDS}
    for it in items:
        if not it.get('exempt'):
            c[it['kind']] += 1
    return c


def summary_text(report):
    """The weekly mail / notice text."""
    t, c = report['totals'], report['counts']
    names = {'unused': '안 쓰는 배정 데스크톱', 'oversized': '큰 VM', 'stopped': '오래 꺼진 VM', 'orphan': '풀 밖 VM',
             'snapshot': '오래된 스냅숏', 'loan': '유휴 카드 대여'}
    lines = [f"회수할 수 있는 항목 {t['items']}건 (최근 {report['days']}일 기준)",
             f"vCPU {t['vcpu']} · 메모리 {t['ram_gb']:g} GB · 디스크 {t['disk_gb']:g} GB · 카드 {t['cards']}",
             f"표준 사양 데스크톱 약 {t['more_desktops']}대를 더 둘 수 있습니다."]
    lines += [f"- {names[k]}: {c[k]}건" for k in KINDS if c.get(k)]
    lines.append('관리 콘솔 운영 > 자원 회수에서 항목마다 적용하거나 제외하세요.')
    return '\n'.join(lines)


def dumps(v):
    return json.dumps(v, ensure_ascii=False)
