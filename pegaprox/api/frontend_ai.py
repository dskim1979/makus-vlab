# -*- coding: utf-8 -*-
"""
AI assistant settings of a trusted web front end (MAKUS).

A front end that runs its own AI assistant (for example the MOAVI Desk operations
assistant) keeps the model connection here: provider, address, model and API
key. The front end reads it server to server and calls the model itself.

  GET /api/frontend/ai   {enabled, provider, ollamaUrl, ollamaModel, openaiBaseUrl, openaiModel,
                          openaiKey, anthropicModel, anthropicKey}   (keys in clear: server use only)
  PUT /api/frontend/ai   same fields; a key sent as '********' or left out keeps the stored one,
                         an empty string clears it

Rules:
  * API token with admin.settings only; a browser session is refused.
  * Keys are stored encrypted (same as the LDAP / OIDC / SMTP secrets) under
    their own server-settings key, which save_server_settings leaves alone.
  * Addresses must be http(s); providers ollama, openai (or compatible), anthropic.
  * Every change is audited without the keys.
"""

from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth

bp = Blueprint('frontend_ai', __name__)

FRONTEND_AI_KEY = 'frontend_ai'
MASK = '********'
PROVIDERS = ('ollama', 'openai', 'anthropic')
DEFAULTS = {
    'enabled': False, 'provider': 'ollama',
    'ollamaUrl': '', 'ollamaModel': '',
    'openaiBaseUrl': '', 'openaiModel': '', 'openaiKey': '',
    'anthropicModel': '', 'anthropicKey': '',
}
_SECRETS = ('openaiKey', 'anthropicKey')


def _token_only():
    session = getattr(request, 'session', None) or {}
    if not session.get('api_token'):
        return jsonify({'error': 'API token required'}), 403
    return None


def _url(v):
    s = (v or '').strip()[:300] if isinstance(v, str) else ''
    if not s:
        return ''
    try:
        u = urlparse(s)
    except ValueError:
        return None
    return s.rstrip('/') if u.scheme in ('http', 'https') and u.netloc else None


def _stored():
    raw = get_db().get_server_setting(FRONTEND_AI_KEY, {})
    return raw if isinstance(raw, dict) else {}


@bp.route('/api/frontend/ai', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_frontend_ai():
    denied = _token_only()
    if denied:
        return denied
    s = {**DEFAULTS, **_stored()}
    db = get_db()
    for k in _SECRETS:
        try:
            s[k] = db._decrypt(s[k]) if s.get(k) else ''
        except Exception:
            s[k] = ''
    return jsonify({k: s.get(k, DEFAULTS[k]) for k in DEFAULTS})


@bp.route('/api/frontend/ai', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_frontend_ai():
    denied = _token_only()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    cur = {**DEFAULTS, **_stored()}
    out = dict(cur)
    if 'enabled' in data:
        out['enabled'] = bool(data['enabled'])
    if 'provider' in data:
        if data['provider'] not in PROVIDERS:
            return jsonify({'error': 'invalid provider'}), 400
        out['provider'] = data['provider']
    for k in ('ollamaUrl', 'openaiBaseUrl'):
        if k in data:
            u = _url(data[k])
            if u is None:
                return jsonify({'error': f'invalid {k}'}), 400
            out[k] = u
    for k in ('ollamaModel', 'openaiModel', 'anthropicModel'):
        if k in data:
            out[k] = str(data[k] or '').strip()[:120]
    db = get_db()
    changed_keys = []
    for k in _SECRETS:
        if k in data and data[k] != MASK:
            v = str(data[k] or '').strip()[:500]
            out[k] = db._encrypt(v) if v else ''
            changed_keys.append(k)
    db.save_server_setting(FRONTEND_AI_KEY, out)
    log_audit(request.session.get('user', ''), 'frontend.ai_settings',
              f"enabled={out['enabled']} provider={out['provider']} keys_changed={','.join(changed_keys) or '-'}",
              get_client_ip())
    return jsonify({'ok': True})
