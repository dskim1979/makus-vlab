"""MOAVI Desk: LAB 단말 대량 등록 - enrolment codes and the client's first start (pegaprox/vlab/enroll.py).

  GET    /api/vlab/admin/enroll-codes              codes (never the code itself: its last 4 characters)  vlab.pool.view
  POST   /api/vlab/admin/enroll-codes              {name, lab_id?, auto_approve?, max_uses?, days?} -> the code, shown once  vlab.pool.manage
  PUT    /api/vlab/admin/enroll-codes/<code_id>    {name?, enabled?, lab_id?, auto_approve?}  vlab.pool.manage
  DELETE /api/vlab/admin/enroll-codes/<code_id>    remove it (PCs it brought in stay)       vlab.pool.manage
  POST   /api/vlab/admin/terminals/approve         {ids, lab_id?} approve several, put them in a LAB  vlab.pool.manage
  POST   /api/vlab/terminals/enroll                {mac, name?, code} a PC's first start -> {token, state}  public (code)
  POST   /api/vlab/terminals/enroll/status         {token} -> pending, or approved with the kiosk key once  public (token)

The two public routes take no session: the code (then the token) is the credential. Failed
tries are counted per address and stop for a while after a few; every enrolment, refusal and
key hand-over is in the audit log. The token travels in the body, not the URL, so it is in no
access log, and a POST reaches the active instance from a standby like any other write.
"""
import logging

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.utils.ratelimit import SlidingWindow
from pegaprox.vlab import enroll, labs, store

bp = Blueprint('vlab_enroll', __name__)

# a wrong code: a few per address, then a pause (a mistyped code is fixed in one go)
_code_failures = SlidingWindow(limit=10, window=300, max_keys=4096, name='vlab-enroll-code')
# every enrolment from one address: a room behind one NAT enrols at once, a script does more
_enrolments = SlidingWindow(limit=300, window=300, max_keys=4096, name='vlab-enroll')
# a wrong poll token
_token_failures = SlidingWindow(limit=20, window=300, max_keys=4096, name='vlab-enroll-token')

# how often the client is asked to come back while it waits
POLL_SECONDS = 30
_REASONS = {
    'BAD_CODE': 'This enrolment code is not valid',
    'CODE_DISABLED': 'This enrolment code was switched off',
    'CODE_EXPIRED': 'This enrolment code has expired',
    'CODE_USED_UP': 'This enrolment code has been used by as many PCs as it allows',
    'BAD_TOKEN': 'This enrolment is not known or its key went out already',
    'TOKEN_EXPIRED': 'This enrolment waited too long - enrol again',
}


def _refuse(code, status):
    return jsonify({'error': _REASONS.get(code, code), 'code': code}), status


def _too_many():
    return jsonify({'error': 'Too many tries - wait a few minutes', 'code': 'TOO_MANY', 'retry_after': 300}), 429


def _lab_brief(lab_id):
    lab = store.get_lab(lab_id) if lab_id else None
    return {'id': lab['id'], 'name': lab['name']} if lab else None


# --- the PC -------------------------------------------------------------------------------

@bp.route('/api/vlab/terminals/enroll', methods=['POST'])
def enroll_terminal():
    """A MOAVI Desk Client's first start with the code its installer was given: {mac, name?, code}.
    A new PC becomes a terminal (pending, or approved in the code's LAB when the code says so);
    a known one waits for an admin again if it held a key, unless the code approves at once.
    Answers {token, state, lab, poll_seconds}; the token is for /enroll/status only."""
    ip = get_client_ip() or ''
    if _code_failures.full(ip):
        return _too_many()
    if not _enrolments.allow(ip):
        return _too_many()
    data = request.get_json(silent=True) or {}
    mac = labs.norm_mac(data.get('mac'))
    if not mac:
        return core._bad('A MAC address is required')
    name = str(data.get('name') or '').strip()[:80]
    code, why = enroll.code_for(data.get('code'))
    if not code:
        _code_failures.allow(ip)
        log_audit(f'terminal:{mac}', 'vlab.terminal.enroll_refused', f"terminal {mac} '{name}': {why}", ip)
        return _refuse(why, 403)

    lab_id = code['lab_id'] if code['lab_id'] and store.get_lab(code['lab_id']) else None
    t = store.terminal_by_mac(mac)
    if t:
        fields = {'ip': ip, 'last_seen': store.now()}
        if not t['name'] and name:
            fields['name'] = name
        if lab_id and not t.get('lab_id'):
            fields['lab_id'] = lab_id
        if code['auto_approve']:
            fields['state'] = 'approved'
        elif t['has_key']:
            # it held a key: a PC that comes back with the code gets a new one only once an
            # admin looks at it again (someone else could have sent this MAC address)
            fields['state'] = 'pending'
        t = store.update_terminal(t['id'], **fields)
        what = f"known terminal {mac} '{t['name']}' enrolled again ({t['state']})"
    else:
        t = store.add_terminal(mac, name, lab_id, ip, 'approved' if code['auto_approve'] else 'pending',
                               f"code:{code['name'] or code['hint']}")
        what = f"terminal {mac} '{t['name']}' enrolled ({t['state']})"
    enroll.count_use(code['id'])
    token = enroll.start(t['id'], code['id'])
    log_audit(f'terminal:{mac}', 'vlab.terminal.enroll',
              f"{what} with code '{code['name']}' (…{code['hint']})" + (f", LAB {t['lab_id']}" if t.get('lab_id') else ''), ip)
    return jsonify({'token': token, 'state': t['state'], 'lab': _lab_brief(t.get('lab_id')),
                    'terminal': {'id': t['id'], 'name': t['name']}, 'poll_seconds': POLL_SECONDS}), 201


@bp.route('/api/vlab/terminals/enroll/status', methods=['POST'])
def enroll_status():
    """The enrolled PC asks again: {token}. While it waits -> {state: pending}. Once approved ->
    {state: approved, key}: the key is made now and handed out this once; the token stops."""
    ip = get_client_ip() or ''
    if _token_failures.full(ip):
        return _too_many()
    data = request.get_json(silent=True) or {}
    e, why = enroll.by_token(data.get('token'))
    if not e:
        _token_failures.allow(ip)
        return _refuse(why, 410 if why == 'TOKEN_EXPIRED' else 404)
    t = store.get_terminal(e['terminal_id'])
    if not t:
        enroll.forget(e['terminal_id'])
        return jsonify({'error': 'This terminal was removed', 'code': 'GONE'}), 410
    store.update_terminal(t['id'], ip=ip or t.get('ip') or '', last_seen=store.now())
    if t['state'] != 'approved':
        enroll.polled(t['id'])
        return jsonify({'state': t['state'], 'lab': _lab_brief(t.get('lab_id')), 'poll_seconds': POLL_SECONDS})
    import secrets
    key = 'mdt_' + secrets.token_urlsafe(24)
    store.set_terminal_key(t['id'], core._key_hash(key))
    enroll.close(t['id'], 'delivered')
    log_audit(f"terminal:{t['mac']}", 'vlab.terminal.key_delivered',
              f"terminal {t['mac']} '{t['name']}': kiosk key handed to the enrolled client", ip)
    return jsonify({'state': 'approved', 'key': key, 'lab': _lab_brief(t.get('lab_id')),
                    'terminal': {'id': t['id'], 'name': t['name']}})


# --- the admin -----------------------------------------------------------------------------

@bp.route('/api/vlab/admin/enroll-codes', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_enroll_codes():
    labs_by_id = {l['id']: l['name'] for l in store.list_labs()}
    codes = enroll.list_codes()
    for c in codes:
        c['lab_name'] = labs_by_id.get(c['lab_id']) if c['lab_id'] else None
    return jsonify({'codes': codes})


def _int(value, lo, hi, what):
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        raise ValueError(f'{what} must be a number')
    if n < lo or n > hi:
        raise ValueError(f'{what} must be {lo}-{hi}')
    return n


@bp.route('/api/vlab/admin/enroll-codes', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_enroll_code():
    """A new code. max_uses 0 = any number of PCs, days 0 = no end. The code is in the answer
    this once; afterwards only its last four characters are shown."""
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    if not name or len(name) > 80:
        return core._bad('A name of 1-80 characters is required')
    try:
        max_uses = _int(data.get('max_uses'), 0, enroll.MAX_USES, 'max_uses')
        days = _int(data.get('days'), 0, enroll.MAX_DAYS, 'days')
    except ValueError as e:
        return core._bad(str(e))
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return core._bad('LAB not found', 404)
    row, code = enroll.make_code(name, lab_id, bool(data.get('auto_approve')), max_uses, days, core._user())
    log_audit(core._user(), 'vlab.enroll_code.create',
              f"enrolment code '{name}' (…{row['hint']}): LAB {lab_id or '-'}, "
              f"{'approved at once' if row['auto_approve'] else 'admin approves'}, "
              f"{max_uses or 'any number of'} PCs, {f'{days} days' if days else 'no end'}", get_client_ip())
    return jsonify({'code': code, 'enroll_code': row}), 201


@bp.route('/api/vlab/admin/enroll-codes/<code_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_enroll_code(code_id):
    c = enroll.get_code(code_id)
    if not c:
        return core._bad('Enrolment code not found', 404)
    data = request.get_json(silent=True) or {}
    fields = {}
    if 'name' in data:
        name = str(data.get('name') or '').strip()
        if not name or len(name) > 80:
            return core._bad('A name of 1-80 characters is required')
        fields['name'] = name
    if 'enabled' in data:
        fields['enabled'] = 1 if data.get('enabled') else 0
    if 'auto_approve' in data:
        fields['auto_approve'] = 1 if data.get('auto_approve') else 0
    if 'lab_id' in data:
        lab_id = data.get('lab_id') or None
        if lab_id and not store.get_lab(lab_id):
            return core._bad('LAB not found', 404)
        fields['lab_id'] = lab_id
    c = enroll.update_code(code_id, **fields)
    log_audit(core._user(), 'vlab.enroll_code.update', f"enrolment code '{c['name']}' (…{c['hint']}) {fields}", get_client_ip())
    return jsonify({'enroll_code': c})


@bp.route('/api/vlab/admin/enroll-codes/<code_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_enroll_code(code_id):
    c = enroll.get_code(code_id)
    if not c:
        return core._bad('Enrolment code not found', 404)
    enroll.delete_code(code_id)
    log_audit(core._user(), 'vlab.enroll_code.delete', f"enrolment code '{c['name']}' (…{c['hint']})", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/terminals/approve', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def approve_terminals():
    """{ids: [...], lab_id?}: approve these terminals (and put them in the LAB, when one is
    given). An enrolled client picks its key up on its next poll."""
    data = request.get_json(silent=True) or {}
    ids = data.get('ids')
    if not isinstance(ids, list) or not ids or len(ids) > 1000 or not all(isinstance(i, str) for i in ids):
        return core._bad('ids: a list of 1-1000 terminal ids is required')
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return core._bad('LAB not found', 404)
    done, missing = [], []
    for tid in dict.fromkeys(ids):
        t = store.get_terminal(tid)
        if not t:
            missing.append(tid)
            continue
        fields = {'state': 'approved'}
        if lab_id:
            fields['lab_id'] = lab_id
        done.append(store.update_terminal(tid, **fields))
    if done:
        log_audit(core._user(), 'vlab.terminal.approve',
                  f"{len(done)} terminals approved{f' into LAB {lab_id}' if lab_id else ''}: "
                  + ', '.join(t['name'] or t['mac'] for t in done[:50]) + (' …' if len(done) > 50 else ''),
                  get_client_ip())
    if missing:
        logging.info('[vlab] approve: %d unknown terminal ids', len(missing))
    return jsonify({'terminals': enroll.annotate(done), 'missing': missing})
