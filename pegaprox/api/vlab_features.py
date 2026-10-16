"""MOAVI Desk: the site profile and its feature groups (pegaprox/vlab/features.py).

  GET  /api/vlab/features          {profile, groups, chosen, catalog}   signed in
  PUT  /api/vlab/admin/features    {profile, groups}                    admin.settings
"""
from flask import Blueprint, jsonify, request

from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import features

bp = Blueprint('vlab_features', __name__)


def _catalog():
    return {'groups': list(features.GROUPS), 'bundles': list(features.BUNDLES),
            'profiles': {k: list(v) for k, v in features.PROFILES.items()}}


@bp.route('/api/vlab/features', methods=['GET'])
@require_auth()
def get_features():
    return jsonify(dict(features.get(), catalog=_catalog()))


@bp.route('/api/vlab/admin/features', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_features():
    data = request.get_json(silent=True) or {}
    profile = data.get('profile')
    if profile not in features.PROFILES:
        return jsonify({'error': 'profile must be one of ' + ', '.join(features.PROFILES)}), 400
    groups = data.get('groups')
    if groups is None:
        groups = features.defaults_for(profile, data.get('bundles') or ())
    if not isinstance(groups, list) or any(g not in features.GROUPS for g in groups):
        return jsonify({'error': 'groups: a list of ' + ', '.join(features.GROUPS)}), 400
    user = request.session.get('user', '')
    saved = features.save(profile, groups, by=user)
    log_audit(user, 'vlab.features', f"profile {saved['profile']}, groups {', '.join(saved['groups']) or '(core only)'}", get_client_ip())
    return jsonify(dict(saved, catalog=_catalog()))
