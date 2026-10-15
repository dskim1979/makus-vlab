"""Scheduled tasks (scheduler.py) drive power through vm_action().

They used to call start_vm/stop_vm/restart_vm/shutdown_vm, which only the XCP-ng manager
has, so on Proxmox every scheduled power task raised AttributeError and was logged as
failed. vLAB class schedules rely on these tasks (docs/vlab-design.md 12-1).
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.background.scheduler as sched


class _ProxmoxLike:
    """Only what the Proxmox manager really has - no start_vm & co."""

    def __init__(self, result=None):
        self.calls = []
        self.result = result if result is not None else {'success': True}

    def vm_action(self, node, vmid, vm_type, action, force=False):
        self.calls.append((node, vmid, vm_type, action))
        return self.result


@pytest.fixture
def audit(monkeypatch):
    seen = []
    monkeypatch.setattr(sched, 'log_audit', lambda user, action, *a, **k: seen.append(action))
    return seen


def _task(action):
    return {'name': 't', 'cluster_id': 'c1', 'action': action, 'target_type': 'qemu',
            'target_id': '300', 'target_node': 'pve1'}


@pytest.mark.parametrize('action,expected', [
    ('start', 'start'), ('stop', 'stop'), ('restart', 'reboot'), ('shutdown', 'shutdown')])
def test_power_actions_go_through_vm_action(monkeypatch, audit, action, expected):
    mgr = _ProxmoxLike()
    monkeypatch.setitem(sched.cluster_managers, 'c1', mgr)
    sched.execute_scheduled_task(_task(action))
    assert mgr.calls == [('pve1', 300, 'qemu', expected)]
    assert audit == ['scheduled_task.executed']


def test_a_refused_power_action_is_logged_as_failed(monkeypatch, audit):
    mgr = _ProxmoxLike({'success': False, 'error': 'VM is locked'})
    monkeypatch.setitem(sched.cluster_managers, 'c1', mgr)
    sched.execute_scheduled_task(_task('start'))
    assert audit == ['scheduled_task.failed']


def test_backup_on_a_manager_without_backup_vm_fails_cleanly(monkeypatch, audit):
    monkeypatch.setitem(sched.cluster_managers, 'c1', _ProxmoxLike())
    sched.execute_scheduled_task(_task('backup'))
    assert audit == ['scheduled_task.failed']


def test_unknown_action_is_not_reported_as_executed(monkeypatch, audit):
    monkeypatch.setitem(sched.cluster_managers, 'c1', _ProxmoxLike())
    sched.execute_scheduled_task(_task('explode'))
    assert audit == ['scheduled_task.failed']


def test_snapshot_still_uses_create_snapshot(monkeypatch, audit):
    mgr = MagicMock()
    monkeypatch.setitem(sched.cluster_managers, 'c1', mgr)
    sched.execute_scheduled_task(_task('snapshot'))
    assert mgr.create_snapshot.called
    assert audit == ['scheduled_task.executed']
