# -*- coding: utf-8 -*-
"""
MOAVI Desk: VM high availability and load balancing, as the console's 클러스터 > 고가용성 (HA) and
클러스터 > 부하 분산 pages see them (pegaprox/api/vlab_hadrs.py).

Kept here:
  vlab_balance        per cluster: the balancing mode ('off' | 'recommend' | 'auto'). The core's own
                      config.auto_migrate follows it (on only for 'auto'); a cluster with no row is
                      'auto' when auto_migrate is on, else 'recommend'
  vlab_balance_moves  the moves the balancer made or an administrator applied (부하 분산 > 이동 기록)
  vlab_ha_queue       new and cloned desktops of a pool whose policy has 'HA 사용' (ha_enabled), waiting
                      until the desktop is ready to be put under Proxmox HA (ha_tick, every minute)

Movability (what live migration cannot carry): PCI passthrough (GPU, FPGA cards), a host USB device,
disks on node-local storage unless the cluster balances local disks, containers unless it balances
containers. Those guests are left out of the recommendations and shown with the reason.
"""
import copy
import logging
import re
import threading
import time
import uuid

from pegaprox.vlab.store import db as _store_db, now

MODES = ('off', 'recommend', 'auto')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_balance (
        cluster_id TEXT PRIMARY KEY,
        mode TEXT NOT NULL DEFAULT 'recommend',
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_balance_moves (
        id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        at TEXT NOT NULL,
        vmid INTEGER NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        from_node TEXT NOT NULL DEFAULT '',
        to_node TEXT NOT NULL DEFAULT '',
        how TEXT NOT NULL DEFAULT '',
        by_user TEXT NOT NULL DEFAULT '',
        ok INTEGER NOT NULL DEFAULT 1,
        error TEXT NOT NULL DEFAULT '',
        source_key TEXT NOT NULL DEFAULT ''
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_balance_moves ON vlab_balance_moves(cluster_id, at DESC)',
    '''CREATE TABLE IF NOT EXISTS vlab_ha_queue (
        desktop_id TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_at REAL NOT NULL DEFAULT 0,
        since TEXT NOT NULL
    )''',
)
TABLES = ('vlab_balance', 'vlab_balance_moves', 'vlab_ha_queue')
MAX_MOVES_KEPT = 500
HA_MAX_ATTEMPTS = 10

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_hadrs', False):
        with _lock:
            if not getattr(d, '_vlab_hadrs', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_hadrs = True
    return d


# --- balancing mode ----------------------------------------------------------------------------

def mode_of(cluster_id, mgr=None):
    r = db().query_one('SELECT mode FROM vlab_balance WHERE cluster_id = ?', (cluster_id,))
    if r and r['mode'] in MODES:
        return r['mode']
    cfg = getattr(mgr, 'config', None)
    return 'auto' if cfg is not None and getattr(cfg, 'auto_migrate', False) else 'recommend'


def set_mode(cluster_id, mode, by=''):
    if mode not in MODES:
        raise ValueError(f"mode: one of {', '.join(MODES)}")
    db().execute('''INSERT INTO vlab_balance (cluster_id, mode, updated_at, updated_by) VALUES (?, ?, ?, ?)
                    ON CONFLICT(cluster_id) DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by''', (cluster_id, mode, now(), by))


# --- move history ------------------------------------------------------------------------------

def record_move(cluster_id, vmid, name, from_node, to_node, how, by='', ok=True, error='', at=None, source_key=''):
    if source_key and db().query_one('SELECT id FROM vlab_balance_moves WHERE cluster_id = ? AND source_key = ?',
                                     (cluster_id, source_key)):
        return False
    db().execute('''INSERT INTO vlab_balance_moves (id, cluster_id, at, vmid, name, from_node, to_node, how, by_user, ok, error, source_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (uuid.uuid4().hex[:16], cluster_id, at or now(), int(vmid), str(name or '')[:120], str(from_node or ''),
                  str(to_node or ''), how, by, 1 if ok else 0, str(error or '')[:300], source_key))
    db().execute('''DELETE FROM vlab_balance_moves WHERE cluster_id = ? AND id NOT IN
                    (SELECT id FROM vlab_balance_moves WHERE cluster_id = ? ORDER BY at DESC LIMIT ?)''',
                 (cluster_id, cluster_id, MAX_MOVES_KEPT))
    return True


def take_core_log(cluster_id, mgr):
    """The core keeps its balancer's moves in memory only (last_migration_log); copy the new
    ones here so the history outlives a restart."""
    for e in list(getattr(mgr, 'last_migration_log', None) or []):
        if not isinstance(e, dict) or e.get('dry_run') or not str(e.get('vmid', '')).isdigit():
            continue
        key = f"{e.get('timestamp', '')}:{e.get('vmid')}"
        record_move(cluster_id, int(e['vmid']), e.get('vm') or '', e.get('from_node'), e.get('to_node'), 'auto',
                    'system', bool(e.get('success')), e.get('error') or '', at=e.get('timestamp') or None, source_key=key)


def moves(cluster_id, limit=100):
    rows = db().query('SELECT * FROM vlab_balance_moves WHERE cluster_id = ? ORDER BY at DESC LIMIT ?',
                      (cluster_id, int(limit))) or []
    return [{'at': r['at'], 'vmid': r['vmid'], 'name': r['name'], 'from': r['from_node'], 'to': r['to_node'],
             'how': r['how'], 'by': r['by_user'], 'ok': bool(r['ok']), 'error': r['error']} for r in rows]


# --- movability --------------------------------------------------------------------------------

_USB_HOST = re.compile(r'(^|,)host=')


def passthrough_of(cfg):
    """'pci' | 'usb' | None from a guest's raw config."""
    if not isinstance(cfg, dict):
        return None
    if any(re.fullmatch(r'hostpci\d+', k) for k in cfg):
        return 'pci'
    for k, v in cfg.items():
        if re.fullmatch(r'usb\d+', k) and _USB_HOST.search(str(v)) and 'spice' not in str(v):
            return 'usb'
    return None


def why_stays(vm, cfg, storage_kind, balance_local_disks=False, balance_containers=False):
    """Why live migration leaves this guest where it is, or None. storage_kind: shared | local | unknown."""
    if vm.get('template'):
        return 'template'
    if vm.get('type') == 'lxc' and not balance_containers:
        return 'container'
    pt = passthrough_of(cfg)
    if pt:
        return pt
    if storage_kind == 'local' and not balance_local_disks:
        return 'local_disk'
    if storage_kind == 'unknown':
        return 'unknown_storage'
    return None


# --- recommendation planning (no move is made) -------------------------------------------------

def _vm_cpu_share(vm, node):
    """The node CPU percent the guest uses."""
    cpus = ((node.get('cpuinfo') or {}).get('cpus') or 0)
    if not cpus:
        return 0.0
    return 100.0 * float(vm.get('cpu') or 0) * float(vm.get('maxcpu') or 1) / cpus


def _rescore(node, w_cpu, w_mem, w_io):
    mem_pct = 100.0 * (node.get('mem_used') or 0) / (node.get('mem_total') or 1)
    node['mem_percent'] = round(mem_pct, 2)
    node['score'] = round((node.get('cpu_percent') or 0) * w_cpu + mem_pct * w_mem + (node.get('disk_percent') or 0) * w_io, 2)


def simulate_move(status, vm, src, dst, weights):
    """status after moving vm from src to dst (memory and CPU follow the guest)."""
    w_cpu, w_mem, w_io = weights
    a, b = status[src], status[dst]
    mem = int(vm.get('mem') or 0)
    cpu_a, cpu_b = _vm_cpu_share(vm, a), _vm_cpu_share(vm, b)
    a['mem_used'] = max(0, (a.get('mem_used') or 0) - mem)
    b['mem_used'] = (b.get('mem_used') or 0) + mem
    a['cpu_percent'] = max(0.0, (a.get('cpu_percent') or 0) - cpu_a)
    b['cpu_percent'] = (b.get('cpu_percent') or 0) + cpu_b
    _rescore(a, w_cpu, w_mem, w_io)
    _rescore(b, w_cpu, w_mem, w_io)
    return status


def weights_of(cfg):
    w = (getattr(cfg, 'balance_cpu_weight', 1.0) or 0, getattr(cfg, 'balance_mem_weight', 1.0) or 0,
         getattr(cfg, 'balance_io_weight', 0.0) or 0)
    return (1.0, 1.0, 0.0) if not any(w) else tuple(float(x) for x in w)


def plan(mgr, max_moves=5, node_status=None):
    """The moves the balancer would make now, without making them: [{vmid, name, type, from, to,
    mem, before, after}] where before/after are the score spread. Uses the core's own decisions
    (check_balance_needed, find_migration_candidate) on a copy of the node status that each
    proposed move updates."""
    status = copy.deepcopy(node_status if node_status is not None else (mgr.get_node_status() or {}))
    if not status:
        return []
    weights = weights_of(mgr.config)
    out, taken = [], []
    for _ in range(max_moves):
        needed, src, dst = mgr.check_balance_needed(status)
        if not needed or not src or not dst:
            break
        before = _spread(mgr, status)
        vm = mgr.find_migration_candidate(src, dst, exclude_vmids=taken, node_status=status)
        if not vm:
            break
        simulate_move(status, vm, src, dst, weights)
        taken.append(vm.get('vmid'))
        out.append({'vmid': int(vm.get('vmid')), 'name': vm.get('name') or '', 'type': vm.get('type') or 'qemu',
                    'from': src, 'to': dst, 'mem': int(vm.get('mem') or 0),
                    'local_disks': bool(vm.get('_has_local_disks')),
                    'before': before, 'after': _spread(mgr, status)})
    return out


def _spread(mgr, status):
    excluded = set(getattr(mgr.config, 'excluded_nodes', []) or [])
    scores = [d.get('score') or 0 for n, d in status.items()
              if d.get('status') == 'online' and not d.get('maintenance_mode') and n not in excluded]
    return round(max(scores) - min(scores), 1) if len(scores) >= 2 else 0.0


# --- the pool's 'HA 사용' ---------------------------------------------------------------------

def queue_new(desk):
    """A new or cloned desktop of a pool with ha_enabled waits to go under HA once it is ready."""
    try:
        from pegaprox.vlab import policy, store
        pool = store.get_pool(desk['pool_id']) if desk else None
        if not pool or desk.get('vm_type', 'qemu') != 'qemu':
            return False
        if not policy.effective(pool.get('settings'), pool.get('type')).get('ha_enabled'):
            return False
        db().execute('INSERT OR IGNORE INTO vlab_ha_queue (desktop_id, attempts, next_at, since) VALUES (?, 0, ?, ?)',
                     (desk['id'], time.time() + 60, now()))
        return True
    except Exception as e:
        logging.warning(f"[VLAB] HA for new desktop {desk and desk.get('id')}: not queued ({e.__class__.__name__})")
        return False


def ha_waiting():
    return [dict(r) for r in db().query('SELECT * FROM vlab_ha_queue ORDER BY since') or []]


def due(limit=10):
    return [dict(r) for r in db().query('SELECT * FROM vlab_ha_queue WHERE next_at <= ? ORDER BY next_at LIMIT ?',
                                        (time.time(), int(limit))) or []]


def later(desktop_id, attempts, delay):
    db().execute('UPDATE vlab_ha_queue SET attempts = ?, next_at = ? WHERE desktop_id = ?',
                 (attempts, time.time() + delay, desktop_id))


def done(desktop_id):
    db().execute('DELETE FROM vlab_ha_queue WHERE desktop_id = ?', (desktop_id,))
