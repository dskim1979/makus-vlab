"""MOAVI Desk: 가속 자원 > 카드 · 패스스루 점검 (pegaprox/vlab/accel_checks.py).

  GET  /api/vlab/admin/accel/checks                       every finding                    vlab.accel.manage
  GET  /api/vlab/admin/desktops/<desktop_id>/accel-checks the findings of one desktop     vlab.accel.manage
"""
from flask import Blueprint, jsonify

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import accel_checks, store

bp = Blueprint('vlab_accel', __name__)


@bp.route('/api/vlab/admin/accel/checks', methods=['GET'])
@require_auth(perms=['vlab.accel.manage'])
def accel_checks_all():
    return jsonify(accel_checks.scan(cluster_managers, core._can_reach))


@bp.route('/api/vlab/admin/desktops/<desktop_id>/accel-checks', methods=['GET'])
@require_auth(perms=['vlab.accel.manage'])
def accel_checks_one(desktop_id):
    desk = store.get_desktop(desktop_id)
    if not desk or not core._can_reach(desk['cluster_id']):
        return jsonify({'error': 'Desktop not found'}), 404
    if desk['vm_type'] != 'qemu':
        return jsonify({'findings': []})
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return jsonify({'error': 'Cluster not connected'}), 503
    try:
        ha_sids = {r.get('sid') for r in mgr.get_proxmox_ha_resources() or []}
    except Exception:
        ha_sids = set()
    vm = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    return jsonify({'findings': accel_checks.for_vm(mgr, desk['cluster_id'], vm.get('node') or desk['node'], desk['vmid'],
                                                    desk=desk, ha_sids=ha_sids, watched_licence=accel_checks._watched_licence())})
