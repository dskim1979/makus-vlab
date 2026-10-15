# -*- coding: utf-8 -*-
"""
vLAB (MAKUS): give loaned cards back when their loan ends.

A background thread looks once a minute for active loans whose ends_at has passed and
returns them (pegaprox/api/vlab.py return_lease): the card's slot is taken off the
desktop VM - a running VM keeps the card until it stops - and the loan is closed.
Runs on the active instance only, like the task scheduler. docs/vlab-design.md 10-1.
"""

import logging
import threading
import time

_thread = None
INTERVAL = 60


def return_due():
    """Return every loan that is due. Returns (returned, failed) counts."""
    from pegaprox.api.vlab import return_lease
    from pegaprox.vlab import store
    done = failed = 0
    for lease in store.due_leases(store.now()):
        try:
            err = return_lease(lease)
        except Exception as e:
            err = str(e)
        if err:
            failed += 1
            logging.warning(f"[VLAB] loan {lease['id']} ({lease['resource_id']} on qemu/{lease['vmid']}) not returned: {err}")
        else:
            done += 1
    return done, failed


def _loop():
    from pegaprox.core import ha
    while True:
        try:
            if ha.is_active():
                return_due()
        except Exception as e:
            logging.error(f'[VLAB] loan return: {e}')
        time.sleep(INTERVAL)


def start_loan_thread():
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, daemon=True, name='vlab-loans')
        _thread.start()
        logging.info('[VLAB] loan return thread started')
