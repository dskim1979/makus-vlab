# -*- coding: utf-8 -*-
"""
White label for a trusted web front end (MAKUS).

A front end that renders its own screens (for example the MOAVI Desk screens) keeps
its white label here: one record per front-end tenant with the app name,
colours, footer, login page texts and links, plus three images (sidebar logo,
login logo, favicon). The front end reads and writes it server to server and
serves the images to browsers itself.

  GET    /api/frontend/branding?tenant=<id>                 stored record (defaults when none)
  GET    /api/frontend/branding/resolved?tenant=<id>        what to display: the tenant's
                                                           record, else the 'default' one
  PUT    /api/frontend/branding        {tenant, branding}  save (cleaned, unknown keys dropped)
  POST   /api/frontend/branding/image  multipart tenant, slot, file -> {image_url}
  DELETE /api/frontend/branding/image  {tenant, slot}
  GET    /api/frontend/branding/image/<tenant>/<file>       the image bytes

Rules:
  * API token with admin.settings only; a browser session is refused. Who may
    edit which tenant is decided by the front end, which signs its users in.
  * Images: PNG, JPEG, WebP (ICO for the favicon only), 5 MB, type checked by
    content. SVG is refused: it can carry script.
  * Links must be http(s) or mailto; colours #rrggbb; image addresses only the
    ones this module hands out.
  * The record lives under its own server-settings key, written only here
    (helpers.save_server_settings leaves it alone, like the broadcast banners).
  * This does not touch this server's own branding (Settings > Server) nor the
    attribution notices, which stay as they are.
"""

import os
import re
import time
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request, Response

from pegaprox.constants import BRANDING_DIR
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth

bp = Blueprint('frontend_branding', __name__)

FRONTEND_BRANDING_KEY = 'frontend_branding'
DEFAULT_TENANT = 'default'
MAX_IMAGE_BYTES = 5 * 1024 * 1024
SLOTS = ('logo', 'loginLogo', 'favicon')

_TENANT = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_HEX = re.compile(r'^#[0-9a-fA-F]{6}$')
_ICON = re.compile(r'^ri-[a-z0-9-]{1,60}$')
_FILE = re.compile(r'^(logo|loginLogo|favicon)\.(png|jpg|webp|ico)$')

DEFAULTS = {
    'enabled': False, 'appName': 'MOAVI Desk', 'browserTitle': '', 'logoUrl': '', 'loginLogoUrl': '', 'faviconUrl': '',
    'primaryColor': '', 'footerText': '', 'poweredByVisible': True, 'showAbout': True, 'showSubscription': True,
    'loginTagline': '', 'loginHighlights': [], 'docsUrl': '', 'supportUrl': '', 'changelogUrl': '', 'hideVersion': False,
}

_TYPES = {
    'png': ('image/png', lambda b: b[:8] == b'\x89PNG\r\n\x1a\n'),
    'jpg': ('image/jpeg', lambda b: b[:3] == b'\xff\xd8\xff'),
    'webp': ('image/webp', lambda b: len(b) > 12 and b[:4] == b'RIFF' and b[8:12] == b'WEBP'),
    'ico': ('image/x-icon', lambda b: b[:4] == b'\x00\x00\x01\x00'),
}


def _token_only():
    session = getattr(request, 'session', None) or {}
    if not session.get('api_token'):
        return jsonify({'error': 'API token required'}), 403
    return None


def _tenant(value):
    t = str(value or DEFAULT_TENANT)
    if not _TENANT.match(t):
        raise ValueError('bad tenant')
    return t


def _str(v, n):
    return v.strip()[:n] if isinstance(v, str) else ''


def _url(v):
    s = _str(v, 500)
    if not s:
        return ''
    try:
        scheme = urlparse(s).scheme.lower()
    except ValueError:
        return ''
    return s if scheme in ('http', 'https', 'mailto') else ''


def _image_ref(v):
    """Only the image references this module hands out: '<tenant>/<slot>.<ext>?v=<n>'."""
    s = _str(v, 200)
    return s if re.match(r'^[A-Za-z0-9_-]{1,64}/(logo|loginLogo|favicon)\.(png|jpg|webp|ico)(\?v=\d+)?$', s) else ''


def _hex(v):
    s = _str(v, 16)
    if not s:
        return ''
    s = s if s.startswith('#') else '#' + s
    return s.lower() if _HEX.match(s) else ''


def clean(b):
    b = b if isinstance(b, dict) else {}
    highlights = []
    for h in b.get('loginHighlights') or []:
        if isinstance(h, dict) and isinstance(h.get('icon'), str) and isinstance(h.get('text'), str) \
                and _ICON.match(h['icon'].strip()) and h['text'].strip():
            highlights.append({'icon': h['icon'].strip(), 'text': h['text'].strip()[:120]})
        if len(highlights) == 3:
            break
    return {
        'enabled': bool(b.get('enabled')),
        'appName': _str(b.get('appName'), 60) or 'MOAVI Desk',
        'browserTitle': _str(b.get('browserTitle'), 80),
        'logoUrl': _image_ref(b.get('logoUrl')),
        'loginLogoUrl': _image_ref(b.get('loginLogoUrl')),
        'faviconUrl': _image_ref(b.get('faviconUrl')),
        'primaryColor': _hex(b.get('primaryColor')),
        'footerText': _str(b.get('footerText'), 200),
        'poweredByVisible': b.get('poweredByVisible') is not False,
        'showAbout': b.get('showAbout') is not False,
        'showSubscription': b.get('showSubscription') is not False,
        'loginTagline': _str(b.get('loginTagline'), 200),
        'loginHighlights': highlights,
        'docsUrl': _url(b.get('docsUrl')),
        'supportUrl': _url(b.get('supportUrl')),
        'changelogUrl': _url(b.get('changelogUrl')),
        'hideVersion': bool(b.get('hideVersion')),
    }


def _all():
    raw = get_db().get_server_setting(FRONTEND_BRANDING_KEY, {})
    return raw if isinstance(raw, dict) else {}


def _record(tenant):
    rec = _all().get(tenant)
    return clean(rec) if isinstance(rec, dict) else None


def _image_dir(tenant):
    return os.path.join(BRANDING_DIR, 'frontend', _tenant(tenant))


def record(tenant):
    """The stored record of a tenant (cleaned), or the defaults."""
    return _record(_tenant(tenant)) or dict(DEFAULTS)


def resolved(tenant=DEFAULT_TENANT):
    """What to display: the tenant's record, else the 'default' one; defaults when not enabled."""
    try:
        tenant = _tenant(tenant)
    except ValueError:
        tenant = DEFAULT_TENANT
    rec = _record(tenant) or _record(DEFAULT_TENANT)
    return rec if rec and rec['enabled'] else dict(DEFAULTS)


def save_record(tenant, branding, actor=''):
    tenant = _tenant(tenant)
    rec = clean(branding)
    allrec = _all()
    allrec[tenant] = rec
    get_db().save_server_setting(FRONTEND_BRANDING_KEY, allrec)
    log_audit(actor or '', 'frontend.branding_saved', f"tenant={tenant} enabled={rec['enabled']}", get_client_ip())
    return rec


def save_image(tenant, slot, buf, actor=''):
    """(image_url, None) or (None, (error, status)). Type checked by content; SVG refused."""
    tenant = _tenant(tenant)
    if slot not in SLOTS:
        return None, ('bad request', 400)
    if len(buf) > MAX_IMAGE_BYTES:
        return None, ('File too large (max 5MB)', 413)
    ext = next((e for e, (_, sig) in _TYPES.items() if sig(buf)), None)
    if ext is None or (ext == 'ico' and slot != 'favicon'):
        return None, ('Unsupported image (PNG, JPEG, WebP; ICO for the favicon)', 415)
    d = _image_dir(tenant)
    os.makedirs(d, exist_ok=True)
    remove_image(tenant, slot)
    with open(os.path.join(d, f'{slot}.{ext}'), 'wb') as fh:
        fh.write(buf)
    log_audit(actor or '', 'frontend.branding_image', f'tenant={tenant} slot={slot}', get_client_ip())
    return f'{tenant}/{slot}.{ext}?v={int(time.time())}', None


def remove_image(tenant, slot):
    d = _image_dir(tenant)
    for e in _TYPES:
        try:
            os.remove(os.path.join(d, f'{slot}.{e}'))
        except FileNotFoundError:
            pass


def read_image(tenant, name):
    """(bytes, mimetype) or None."""
    m = _FILE.match(name or '')
    if not m or not _TENANT.match(tenant or ''):
        return None
    try:
        with open(os.path.join(_image_dir(tenant), name), 'rb') as fh:
            return fh.read(MAX_IMAGE_BYTES + 1), _TYPES[m.group(2)][0]
    except FileNotFoundError:
        return None


@bp.route('/api/frontend/branding', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_frontend_branding():
    denied = _token_only()
    if denied:
        return denied
    try:
        tenant = _tenant(request.args.get('tenant'))
    except ValueError:
        return jsonify({'error': 'bad tenant'}), 400
    return jsonify(_record(tenant) or dict(DEFAULTS))


@bp.route('/api/frontend/branding/resolved', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_frontend_branding_resolved():
    denied = _token_only()
    if denied:
        return denied
    try:
        tenant = _tenant(request.args.get('tenant'))
    except ValueError:
        tenant = DEFAULT_TENANT
    rec = _record(tenant) or _record(DEFAULT_TENANT)
    if not rec or not rec['enabled']:
        return jsonify(dict(DEFAULTS))
    return jsonify(rec)


@bp.route('/api/frontend/branding', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_frontend_branding():
    denied = _token_only()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        tenant = _tenant(data.get('tenant'))
    except ValueError:
        return jsonify({'error': 'bad tenant'}), 400
    rec = clean(data.get('branding'))
    allrec = _all()
    allrec[tenant] = rec
    get_db().save_server_setting(FRONTEND_BRANDING_KEY, allrec)
    log_audit(request.session.get('user', ''), 'frontend.branding_saved',
              f"tenant={tenant} enabled={rec['enabled']} by={_str(data.get('actor'), 120) or '-'}", get_client_ip())
    return jsonify(rec)


@bp.route('/api/frontend/branding/image', methods=['POST'])
@require_auth(perms=['admin.settings'])
def post_frontend_branding_image():
    denied = _token_only()
    if denied:
        return denied
    if (request.content_length or 0) > MAX_IMAGE_BYTES + 64 * 1024:
        return jsonify({'error': 'File too large (max 5MB)'}), 413
    try:
        tenant = _tenant(request.form.get('tenant'))
    except ValueError:
        return jsonify({'error': 'bad tenant'}), 400
    slot = request.form.get('slot')
    f = request.files.get('file')
    if slot not in SLOTS or f is None:
        return jsonify({'error': 'bad request'}), 400
    buf = f.read(MAX_IMAGE_BYTES + 1)
    if len(buf) > MAX_IMAGE_BYTES:
        return jsonify({'error': 'File too large (max 5MB)'}), 413
    ext = next((e for e, (_, sig) in _TYPES.items() if sig(buf)), None)
    if ext is None or (ext == 'ico' and slot != 'favicon'):
        return jsonify({'error': 'Unsupported image (PNG, JPEG, WebP; ICO for the favicon)'}), 415
    d = _image_dir(tenant)
    os.makedirs(d, exist_ok=True)
    for e in _TYPES:
        try:
            os.remove(os.path.join(d, f'{slot}.{e}'))
        except FileNotFoundError:
            pass
    with open(os.path.join(d, f'{slot}.{ext}'), 'wb') as fh:
        fh.write(buf)
    log_audit(request.session.get('user', ''), 'frontend.branding_image', f'tenant={tenant} slot={slot}', get_client_ip())
    return jsonify({'image_url': f'{tenant}/{slot}.{ext}?v={int(time.time())}'})


@bp.route('/api/frontend/branding/image', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def delete_frontend_branding_image():
    denied = _token_only()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        tenant = _tenant(data.get('tenant'))
    except ValueError:
        return jsonify({'error': 'bad tenant'}), 400
    slot = data.get('slot')
    if slot not in SLOTS:
        return jsonify({'error': 'bad request'}), 400
    d = _image_dir(tenant)
    for e in _TYPES:
        try:
            os.remove(os.path.join(d, f'{slot}.{e}'))
        except FileNotFoundError:
            pass
    return jsonify({'success': True})


@bp.route('/api/frontend/branding/image/<tenant>/<name>', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_frontend_branding_image(tenant, name):
    denied = _token_only()
    if denied:
        return denied
    m = _FILE.match(name or '')
    if not m or not _TENANT.match(tenant or ''):
        return jsonify({'error': 'Not found'}), 404
    path = os.path.join(_image_dir(tenant), name)
    try:
        with open(path, 'rb') as fh:
            buf = fh.read(MAX_IMAGE_BYTES + 1)
    except FileNotFoundError:
        return jsonify({'error': 'Not found'}), 404
    return Response(buf, mimetype=_TYPES[m.group(2)][0], headers={'X-Content-Type-Options': 'nosniff'})
