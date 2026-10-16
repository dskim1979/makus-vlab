# -*- coding: utf-8 -*-
"""
vLAB (MAKUS): give loaned cards back when their loan ends, and run the pool policies'
idle shutdown and session limit (pegaprox/api/vlab.py policy_tick) on the same minute.

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
    from pegaprox.core import ha
    from pegaprox.vlab import store
    done = failed = 0
    for lease in store.due_leases(store.now()):
        # each return changes a VM: a leader that lost its lease starts no new one (HA 5.2)
        if not ha.confirm_step(f"vLAB loan return {lease['id']}"):
            break
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
                # the pool policies' idle shutdown and session limit ride the same minute
                from pegaprox.api.vlab import lab_tick, policy_tick
                from pegaprox.vlab import features
                policy_tick()
                # and the LAB schedules: desktops ready before a session, put back after it
                if features.enabled('lab'):
                    lab_tick()
                # the clean-ups put off while a desktop was working; GPU / NPU use every few minutes
                from pegaprox.api.vlab_work import accel_tick, deferral_tick
                deferral_tick()
                if features.enabled('gpuai') or features.enabled('fpga'):
                    accel_tick()
                # boards whose loan ended come off their desktop; licence servers every 5 minutes
                from pegaprox.api.vlab_next import board_tick, license_tick
                board_tick()
                if features.enabled('fpga'):
                    license_tick()
                # accounts: the notice before the last day, expiry, deletion N days later
                from pegaprox.api.vlab_accounts import accounts_tick
                accounts_tick()
                # GPU jobs: ended ones read and told, past their time limit stopped, the queue run
                from pegaprox.api.vlab_research import gpu_tick
                if features.enabled('gpuai'):
                    gpu_tick()
        except Exception as e:
            logging.error(f'[VLAB] loan return / pool policy: {e}')
        time.sleep(INTERVAL)


def start_loan_thread():
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, daemon=True, name='vlab-loans')
        _thread.start()
        logging.info('[VLAB] loan return thread started')
