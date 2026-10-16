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
    from pegaprox.api import vlab_notices
    from pegaprox.api.vlab import return_lease
    from pegaprox.core import ha
    from pegaprox.vlab import notices, store
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
            # tried again every minute: the administrators hear of it once
            if notices.once(f"loan_fail:{lease['id']}:{lease['ends_at']}"):
                vlab_notices.loan_return_failed(lease, err)
        else:
            done += 1
            vlab_notices.loan_returned(lease)
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
                # per-user notices: loan reminders, GPU quota steps, idle IDEs, a GPU queue stuck
                from pegaprox.api.vlab_notices import notice_tick
                if features.enabled('gpuai') or features.enabled('fpga'):
                    notice_tick()
        except Exception as e:
            logging.error(f'[VLAB] loan return / pool policy: {e}')
        try:
            if ha.is_active():
                _side_ticks()
        except Exception as e:
            logging.error(f'[VLAB] side ticks: {e}')
        time.sleep(INTERVAL)


def _side_ticks():
    """The minute's other work, each on its own so one failing does not stop the rest."""
    from pegaprox.vlab import features

    def ops():
        from pegaprox.api.vlab_ops_notices import ops_tick      # the administrators' notices
        ops_tick()

    def bookings():
        from pegaprox.api.vlab_notices import booking_reminders  # the people of a LAB booking, before it starts
        booking_reminders()

    def cards():
        from pegaprox.api.vlab_accel_book import booking_tick    # card and board bookings: lent, given back
        booking_tick()

    def forecast():
        from pegaprox.api.vlab_forecast import forecast_tick     # the growth forecast's daily numbers (hourly)
        forecast_tick()

    for name, on, fn in (('operations notices', True, ops),
                         ('LAB booking reminders', features.enabled('lab'), bookings),
                         ('card / board bookings', features.enabled('gpuai') or features.enabled('fpga'), cards),
                         ('growth forecast', True, forecast)):
        if not on:
            continue
        try:
            fn()
        except Exception as e:
            logging.error(f'[VLAB] {name}: {e}')


def start_loan_thread():
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, daemon=True, name='vlab-loans')
        _thread.start()
        logging.info('[VLAB] loan return thread started')
