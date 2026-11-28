# -*- coding: utf-8 -*-
"""
What the connect routes already did inside a desktop, kept over an engine restart (MAKUS).

The RDP connect prepares a Windows desktop through its guest agent - RDP on and tuned
(vlab_next.rdp_prepare), the pool's device switches (rdp_device_policy), RDP scoped to the gateways
with NLA off for desktop sign-in (vlab_logon.rdp_nla_off) - and remembers per desktop that it did,
so the next connect skips it. Kept in memory only, every engine restart (an update, a recreate)
made the first connect to each desktop run them all again: seconds on each.

Done(kind) behaves like the dicts it replaces (get, [] =, in, clear) and writes through to the
table vlab_rdp_done. Values are compared with what the caller wants now (the VM id, the values,
the gateway addresses), so a stale row only costs one run. A local cache of this engine: not
synced to the other HA members (core/ha.py LOCAL_TABLES) - a member taking over runs the steps once.
"""

import json
import threading

from pegaprox.vlab.store import db as _store_db, now

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_rdp_done (
        desktop_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        at TEXT NOT NULL,
        PRIMARY KEY (desktop_id, kind)
    )''',
)
TABLES = ('vlab_rdp_done',)

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_rdp_done', False):
        with _lock:
            if not getattr(d, '_vlab_rdp_done', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_rdp_done = True
    return d


def _tuples(v):
    """JSON gives lists back: the callers compare with tuples."""
    return tuple(_tuples(x) for x in v) if isinstance(v, list) else v


class Done:
    """desktop id -> value, in memory and in vlab_rdp_done under this kind."""

    def __init__(self, kind):
        self.kind = kind
        self._mem = {}

    def get(self, desktop_id, default=None):
        if desktop_id in self._mem:
            return self._mem[desktop_id]
        try:
            r = db().query_one('SELECT value FROM vlab_rdp_done WHERE desktop_id = ? AND kind = ?', (desktop_id, self.kind))
            v = _tuples(json.loads(r['value'])) if r else None
        except Exception:
            v = None
        if v is not None:
            self._mem[desktop_id] = v
        return default if v is None else v

    def __setitem__(self, desktop_id, value):
        self._mem[desktop_id] = value
        try:
            db().execute('INSERT OR REPLACE INTO vlab_rdp_done (desktop_id, kind, value, at) VALUES (?, ?, ?, ?)',
                         (desktop_id, self.kind, json.dumps(value), now()))
        except Exception:
            pass                                    # memory still has it for this run

    def __contains__(self, desktop_id):
        return self.get(desktop_id) is not None

    def pop(self, desktop_id, default=None):
        v = self.get(desktop_id, default)
        self._mem.pop(desktop_id, None)
        try:
            db().execute('DELETE FROM vlab_rdp_done WHERE desktop_id = ? AND kind = ?', (desktop_id, self.kind))
        except Exception:
            pass
        return v

    def clear(self):
        self._mem.clear()
        try:
            db().execute('DELETE FROM vlab_rdp_done WHERE kind = ?', (self.kind,))
        except Exception:
            pass

    def forget_memory(self):
        """As after an engine restart (tests)."""
        self._mem.clear()
