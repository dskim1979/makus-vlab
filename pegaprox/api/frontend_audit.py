# -*- coding: utf-8 -*-
"""
Audit events of a trusted web front end (MAKUS).

A front end that performs actions itself (for example the MOAVI Desk screens, which
talk to Proxmox directly for many of them) sends its audit events here, so one
audit log holds both and the SIEM / syslog targets of this server forward them
too (log_audit -> SIEM queue).

  POST /api/frontend/audit   {source?, events: [{timestamp, userEmail, userId, action, category,
                                                  resourceType, resourceId, resourceName, status,
                                                  errorMessage, ipAddress, details}]}
       -> {accepted: n}

Rules:
  * API token with admin.settings only; a browser session is refused.
  * Every line is marked with its source: user '<source>:<user>', action
    '<source>.<action>', so it can never pass for an action of this server.
  * Up to 200 events per call, fields length-capped, CR/LF stripped by log_audit.
"""

import ipaddress
import json
import re

from flask import Blueprint, jsonify, request

from pegaprox.utils.audit import log_audit
from pegaprox.utils.auth import require_auth

bp = Blueprint('frontend_audit', __name__)

MAX_EVENTS = 200
_SOURCE = re.compile(r'^[a-z][a-z0-9_-]{0,19}$')
_ACTION = re.compile(r'[^a-z0-9._-]+')


def _s(v, n):
    return str(v).replace('\r', ' ').replace('\n', ' ').strip()[:n] if v not in (None, '') else ''


def _ip(v):
    s = _s(v, 64).split(',')[0].strip()
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _details(e):
    parts = []
    cat = _s(e.get('category'), 40)
    if cat:
        parts.append(f'category={cat}')
    res = ' '.join(x for x in (_s(e.get('resourceType'), 40), _s(e.get('resourceName') or e.get('resourceId'), 120)) if x)
    if res:
        parts.append(f'resource={res}')
    status = _s(e.get('status'), 20)
    if status and status != 'success':
        parts.append(f'status={status}')
    err = _s(e.get('errorMessage'), 300)
    if err:
        parts.append(f'error={err}')
    d = e.get('details')
    if d not in (None, '', {}, []):
        try:
            txt = json.dumps(d, ensure_ascii=False, default=str, separators=(',', ':'))
        except (TypeError, ValueError):
            txt = str(d)
        parts.append(f'details={_s(txt, 1000)}')
    ts = _s(e.get('timestamp'), 40)
    if ts:
        parts.append(f'at={ts}')
    return ' '.join(parts)


@bp.route('/api/frontend/audit', methods=['POST'])
@require_auth(perms=['admin.settings'])
def ingest_frontend_audit():
    session = getattr(request, 'session', None) or {}
    if not session.get('api_token'):
        return jsonify({'error': 'API token required'}), 403
    body = request.get_json(silent=True) or {}
    source = _s(body.get('source') or 'console', 20).lower()
    if not _SOURCE.match(source):
        return jsonify({'error': 'bad source'}), 400
    events = body.get('events')
    if not isinstance(events, list):
        return jsonify({'error': 'events must be a list'}), 400
    if len(events) > MAX_EVENTS:
        return jsonify({'error': f'at most {MAX_EVENTS} events per call'}), 413

    accepted = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        action = _ACTION.sub('_', _s(e.get('action'), 80).lower()).strip('._-')
        if not action:
            continue
        who = _s(e.get('userEmail') or e.get('userId') or 'system', 120)
        log_audit(f'{source}:{who}', f'{source}.{action}', _details(e), ip_address=_ip(e.get('ipAddress')) or '-')
        accepted += 1
    return jsonify({'accepted': accepted})
