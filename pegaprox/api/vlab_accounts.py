# -*- coding: utf-8 -*-
"""
MOAVI Desk accounts for universities and labs (docs/vlab-design.md 4-2): password reset by
mail, mail verification and institution-mail auto approval of sign-ups, bulk import from
CSV, account expiry and the terms / privacy consent.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  POST   /api/vlab/password-reset                  {login} username or mail; always the same answer   public
  POST   /api/vlab/password-reset/check            {token} is the link still good                    public
  POST   /api/vlab/password-reset/confirm          {token, password} new password, every session ends public
  POST   /api/vlab/signup/verify                   {id, code | token} the mail of a sign-up request  public
  POST   /api/vlab/signup/resend                   {id} a new code (once a minute, 5 times)          public
  GET    /api/vlab/terms                           the terms and privacy text and version            public
  GET    /api/vlab/me/terms                        must the caller agree (again)                     signed in
  POST   /api/vlab/me/terms                        {version} agree                                   signed in
  GET/PUT /api/vlab/admin/terms                    {enabled, version, terms, privacy}                admin.settings
  GET    /api/vlab/admin/terms/consents            ?version=&username=&format=csv who agreed when    admin.users
  GET/PUT /api/vlab/admin/account-settings         {notice_days, delete_after_days, reclaim, public_url}  admin.settings
  PUT    /api/vlab/admin/users/<username>/expiry   {expires_at: YYYY-MM-DD | null}                   admin.users
  GET    /api/vlab/admin/users/import/example      an example CSV                                    admin.users
  POST   /api/vlab/admin/users/import/preview      {csv} rows with their errors and duplicates       admin.users
  POST   /api/vlab/admin/users/import              {csv, deliver: csv|mail, must_change_password?}   admin.users

The sign-up routes themselves (/api/vlab/signup, the review) stay in vlab_next.py and call
in here: after_signup() sends the code, create_from_signup() makes the account (approval
and auto approval alike). While terms are on, /api/vlab/me/* and the desktop connect answer
403 TERMS_REQUIRED to a session whose user has not agreed to the current version.
accounts_tick() runs on the minute loop (pegaprox/vlab/loans.py): the notice before an
account's last day, its expiry (signed out, disabled, desktops taken back) and, when set,
its deletion N days later; each change of an account or a VM confirms the lease first.
"""

import logging
import re
import threading
import time
from datetime import date, datetime, timedelta

from flask import Blueprint, Response, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.core import ha
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import accounts, catalog, directory, store

bp = Blueprint('vlab_accounts', __name__)

_bad = core._bad
_user = core._user

_ACCOUNTS_KEY = 'vlab_accounts'
_TERMS_KEY = 'vlab_terms'
_SIGNUP_KEY = 'vlab_signup'
_MAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_VERSION = re.compile(r'^[\w.\-]{1,40}$')
GENERIC_RESET = 'If the account exists and has a mail address, a link is on its way.'


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _settings():
    from pegaprox.api.helpers import load_server_settings
    return load_server_settings() or {}


def _save(key, value):
    from pegaprox.api.helpers import save_server_settings
    s = _settings()
    s[key] = value
    return save_server_settings(s)


# --- rate limits (this instance; a failover starts them over) --------------------------------

_hits = {}
_hits_lock = threading.Lock()


def _limited(kind, key, limit, window):
    t = time.time()
    with _hits_lock:
        recent = [x for x in _hits.get((kind, key), []) if t - x < window]
        if len(recent) >= limit:
            _hits[(kind, key)] = recent
            return True
        recent.append(t)
        _hits[(kind, key)] = recent
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v or t - v[-1] > 3600]:
                _hits.pop(k, None)
        return False


def reset_limits():
    with _hits_lock:
        _hits.clear()


# --- settings ------------------------------------------------------------------------------

ACCOUNT_DEFAULTS = {'notice_days': 7, 'delete_after_days': 0, 'reclaim': True, 'public_url': ''}


def account_settings():
    saved = _settings().get(_ACCOUNTS_KEY) or {}
    out = dict(ACCOUNT_DEFAULTS)
    out.update({k: saved[k] for k in ACCOUNT_DEFAULTS if k in saved})
    return out


def signup_settings():
    saved = _settings().get(_SIGNUP_KEY) or {}
    return {
        'enabled': bool(saved.get('enabled', False)),
        'verify_email': saved.get('verify_email') if saved.get('verify_email') in accounts.VERIFY_MODES else 'off',
        'auto_domains': list(saved.get('auto_domains') or []),
        'auto_role': saved.get('auto_role') or 'user',
        'auto_department_id': saved.get('auto_department_id') or None,
        'auto_pool_ids': list(saved.get('auto_pool_ids') or []),
        'auto_expires_at': saved.get('auto_expires_at') or None,
    }


def clean_signup_settings(data):
    """The sign-up settings after a PUT: keys left out stay. ValueError on a bad one."""
    out = signup_settings()
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            raise ValueError('enabled must be true or false')
        out['enabled'] = data['enabled']
    if 'verify_email' in data:
        if data['verify_email'] not in accounts.VERIFY_MODES:
            raise ValueError('verify_email must be off, optional or required')
        out['verify_email'] = data['verify_email']
    if 'auto_domains' in data:
        out['auto_domains'] = accounts.clean_domains(data['auto_domains'])
    if 'auto_role' in data:
        role = str(data['auto_role'] or 'user')
        _check_role(role)
        out['auto_role'] = role
    if 'auto_department_id' in data:
        dep = data['auto_department_id'] or None
        if dep is not None and (not isinstance(dep, str) or not catalog.get_department(dep)):
            raise ValueError('auto_department_id: no such department')
        out['auto_department_id'] = dep
    if 'auto_pool_ids' in data:
        ids = data['auto_pool_ids'] or []
        if not isinstance(ids, list) or len(ids) > 50 or not all(isinstance(p, str) and store.get_pool(p) for p in ids):
            raise ValueError('auto_pool_ids: a list of pool ids')
        out['auto_pool_ids'] = list(dict.fromkeys(ids))
    if 'auto_expires_at' in data:
        day = accounts.parse_day(data['auto_expires_at'])
        out['auto_expires_at'] = day.isoformat() if day else None
    return out


def _check_role(role):
    """A role sign-ups and imports may hand out: one that exists, not admin, and one the
    caller could grant themselves (the core's own checks)."""
    from pegaprox.api import users as core_users
    from pegaprox.models.permissions import ROLE_ADMIN
    if role == ROLE_ADMIN:
        raise ValueError('role: admin accounts are made one by one')
    if not core_users.is_valid_role(role):
        raise ValueError(f'role: no such role "{role}"')
    if not core_users._role_at_or_below_caller(role) or not core_users._caller_can_grant_role(role):
        raise ValueError(f'role: "{role}" grants more than you hold')


TERMS_DEFAULTS = {'enabled': False, 'version': '', 'terms': '', 'privacy': '', 'updated_at': None, 'updated_by': ''}


def terms_settings():
    saved = _settings().get(_TERMS_KEY) or {}
    out = dict(TERMS_DEFAULTS)
    out.update({k: saved[k] for k in TERMS_DEFAULTS if k in saved})
    out['enabled'] = bool(out['enabled'] and out['version'])
    return out


# --- mail ----------------------------------------------------------------------------------

def _base_url():
    url = (account_settings().get('public_url') or '').strip().rstrip('/')
    if url:
        return url
    try:
        return request.url_root.rstrip('/')
    except RuntimeError:
        return ''


def _product():
    try:
        from pegaprox.api import frontend_branding as fb
        rec = fb.resolved(fb.DEFAULT_TENANT)
        return (rec.get('enabled') and rec.get('appName')) or 'MOAVI Desk'
    except Exception:
        return 'MOAVI Desk'


def _mail(to, subject, text):
    """(sent, error). Mail goes through the platform SMTP settings."""
    if not to:
        return False, 'no mail address'
    try:
        from pegaprox.utils.email import send_email
        ok, err = send_email([to], f'[{_product()}] {subject}', text, None)
        return bool(ok), (None if ok else str(err or 'not sent'))
    except Exception as e:
        logging.warning(f'[VLAB] account mail: {e}')
        return False, str(e)


# --- 1) password reset -----------------------------------------------------------------------

def _local(u):
    return (u.get('auth_source') or 'local') == 'local'


def _resettable(u):
    """A reset link sets this account's password: a local one, or one of the bundled directory
    (the new password goes to the DC then, pegaprox/vlab/directory.py)."""
    return _local(u) or (directory.owns(u) and directory.active())


@bp.route('/api/vlab/password-reset', methods=['POST'])
def password_reset_request():
    """{login}: a username or a mail address. The answer is the same whether an account
    matched or not; a local account with a mail address gets a one-time link (30 minutes),
    an AD/LDAP or SSO account a note to use its institution's portal."""
    from pegaprox.utils.auth import load_users
    ip = get_client_ip() or ''
    login = str(_body().get('login') or '').strip().lower()[:120]
    if not login:
        return _bad('login: a username or a mail address')
    if _limited('reset-ip', ip, 10, 900):
        return jsonify({'error': 'Too many requests - try again in a few minutes', 'code': 'RATE_LIMITED'}), 429
    sent = 0
    if not _limited('reset-login', login, 3, 900):
        users = load_users() or {}
        if '@' in login:
            found = [(n, u) for n, u in users.items() if str(u.get('email') or '').strip().lower() == login][:5]
        else:
            found = [(login, users[login])] if login in users else []
        for name, u in found:
            if not u.get('enabled', True) or not u.get('email'):
                continue
            if not _resettable(u):
                _mail(u['email'], '비밀번호 변경 안내 / Password change',
                      f"{name} 계정은 기관 계정(AD/LDAP, SSO)으로 로그인합니다. 비밀번호는 기관 포털에서 바꾸세요.\n\n"
                      f"The account {name} signs in with your institution's directory. Change its password there.\n")
                log_audit(name, 'vlab.password_reset.external', 'reset asked for a directory account - pointed to the institution', ip)
                continue
            token = accounts.new_reset(name, ip)
            link = f"{_base_url()}/reset-password?token={token}"
            ok, err = _mail(u['email'], '비밀번호 재설정 / Password reset',
                            f"{u.get('display_name') or name} 님,\n\n"
                            f"아래 링크에서 새 비밀번호를 정하세요. 링크는 {accounts.RESET_MINUTES}분 동안 한 번만 쓸 수 있습니다.\n{link}\n\n"
                            f"요청하지 않았다면 이 메일을 무시하세요. 비밀번호는 바뀌지 않습니다.\n\n"
                            f"Set a new password for {name} at the link above. It works once, for {accounts.RESET_MINUTES} minutes.\n")
            sent += ok
            log_audit(name, 'vlab.password_reset.request', 'reset link mailed' if ok else f'reset link not mailed: {err}', ip)
    else:
        log_audit(login if '@' not in login else 'unknown', 'vlab.password_reset.limited', 'too many reset requests for one login', ip)
    return jsonify({'success': True, 'message': GENERIC_RESET})


def _policy():
    s = _settings()
    return {'min_length': int(s.get('password_min_length', 8) or 8),
            'uppercase': bool(s.get('password_require_uppercase', True)),
            'lowercase': bool(s.get('password_require_lowercase', True)),
            'numbers': bool(s.get('password_require_numbers', True)),
            'special': bool(s.get('password_require_special', False))}


@bp.route('/api/vlab/password-reset/check', methods=['POST'])
def password_reset_check():
    ip = get_client_ip() or ''
    if _limited('reset-check', ip, 30, 900):
        return jsonify({'error': 'Too many requests', 'code': 'RATE_LIMITED'}), 429
    r = accounts.reset_for(str(_body().get('token') or ''))
    if not r:
        return jsonify({'valid': False, 'policy': _policy()})
    return jsonify({'valid': True, 'username': r['username'], 'expires_at': r['expires_at'], 'policy': _policy()})


@bp.route('/api/vlab/password-reset/confirm', methods=['POST'])
def password_reset_confirm():
    """{token, password}: the policy holds; the link is spent; every session and API token
    of the account ends, and a sign-in lockout of it is lifted."""
    from pegaprox import globals as ppglobals
    from pegaprox.utils.auth import (hash_password, invalidate_all_user_sessions, load_users,
                                     revoke_user_api_tokens, save_single_user, validate_password_policy)
    ip = get_client_ip() or ''
    if _limited('reset-check', ip, 30, 900):
        return jsonify({'error': 'Too many requests', 'code': 'RATE_LIMITED'}), 429
    data = _body()
    r = accounts.reset_for(str(data.get('token') or ''))
    if not r:
        return jsonify({'error': 'This link has expired or was used already - ask for a new one', 'code': 'LINK_INVALID'}), 400
    password = str(data.get('password') or '')[:256]
    ok, why = validate_password_policy(password)
    if not ok:
        return _bad(why)
    name = r['username']
    u = (load_users() or {}).get(name)
    if not u or not u.get('enabled', True) or not _resettable(u):
        accounts.use_reset(r['id'])
        return jsonify({'error': 'This link has expired or was used already - ask for a new one', 'code': 'LINK_INVALID'}), 400
    if directory.owns(u):
        # the DC's own password set; the link is spent only once the DC took it
        try:
            directory.set_password(name, password, u)
        except directory.DirectoryError as e:
            if e.code == 'PASSWORD_REFUSED':
                return jsonify({'error': 'The directory refused the password - choose another one', 'code': e.code}), 400
            return jsonify({'error': 'The directory cannot be reached - try again later', 'code': e.code}), 503
        if not accounts.use_reset(r['id']):
            return jsonify({'error': 'This link has expired or was used already - ask for a new one', 'code': 'LINK_INVALID'}), 400
        u['force_password_change'] = False
        save_single_user(name, u)
    else:
        if not accounts.use_reset(r['id']):
            return jsonify({'error': 'This link has expired or was used already - ask for a new one', 'code': 'LINK_INVALID'}), 400
        salt, pw_hash = hash_password(password)
        u.update(password_salt=salt, password_hash=pw_hash, password_changed_at=datetime.now().isoformat(),
                 force_password_change=False)
        save_single_user(name, u)
    invalidate_all_user_sessions(name)
    revoke_user_api_tokens(name)
    ppglobals.login_attempts_by_user.pop(name, None)
    log_audit(name, 'vlab.password_reset.done', 'password set through a mailed link; every session ended', ip)
    return jsonify({'success': True, 'username': name})


# --- 2) / 3) sign-up mail verification and institution auto approval -------------------------

def needs_verify(email, s=None):
    s = s or signup_settings()
    return bool(email) and (s['verify_email'] != 'off' or accounts.domain_matches(email, s['auto_domains']))


def _send_code(req):
    code, token = accounts.new_verification(req['id'], req['email'])
    link = f"{_base_url()}/signup/verify?id={req['id']}&token={token}"
    ok, err = _mail(req['email'], '메일 인증 코드 / Mail verification code',
                    f"{req.get('display_name') or req['username']} 님,\n\n가입 신청의 메일 인증 코드: {code}\n"
                    f"또는 이 링크를 여세요: {link}\n({accounts.VERIFY_MINUTES}분 동안 유효)\n\n"
                    f"Verification code for your account request: {code} (or open the link; valid {accounts.VERIFY_MINUTES} minutes).\n")
    if not ok:
        logging.warning(f"[VLAB] sign-up {req['id']}: verification mail not sent: {err}")
    return ok


def after_signup(req):
    """Called by POST /api/vlab/signup once the request is stored: 'sent', 'failed' or 'none'."""
    if not needs_verify(req.get('email')):
        return 'none'
    return 'sent' if _send_code(req) else 'failed'


def create_from_signup(req, reviewer, role=None, department_id=None, pool_ids=(), expires_at=None):
    """Make the account of a request (with its secret). Returns an error text or None."""
    from pegaprox.core.db import DEFAULT_TENANT_ID
    from pegaprox.models.permissions import ROLE_USER
    from pegaprox.utils.auth import load_users, save_single_user
    if req['username'] in (load_users() or {}):
        catalog.review_signup(req['id'], 'rejected', reviewer, 'username taken meanwhile')
        return 'The username was taken meanwhile - the request is rejected'
    stamp = datetime.now().isoformat()
    row = {
        'password_salt': req['password_salt'], 'password_hash': req['password_hash'], 'password_changed_at': stamp,
        'role': role or ROLE_USER, 'display_name': req['display_name'] or req['username'], 'email': req['email'],
        'enabled': True, 'created_at': stamp, 'last_login': None, 'tenant_id': DEFAULT_TENANT_ID, 'permissions': [],
        'denied_permissions': [], 'portal_only': (role or ROLE_USER) == ROLE_USER,
    }
    in_directory = req.get('password_salt') == directory.SIGNUP_SALT
    if in_directory:
        # the password is on the DC already (signup_account): enable that account, keep no hash
        row.update(password_salt='', password_hash='')
        try:
            directory.approve_signup(req['username'], row)
        except directory.DirectoryError as e:
            return f'The directory cannot be reached ({e.code}) - the request stays waiting, try again later'
    else:
        save_single_user(req['username'], row)
    dep = department_id or req.get('department_id')
    if dep and catalog.get_department(dep):
        catalog.set_department(req['username'], dep)
    for pid in pool_ids or ():
        pool = store.get_pool(pid)
        if not pool:
            continue
        rows = [g for g in catalog.pool_grants(pid)]
        if not any(g['subject_type'] == 'user' and g['subject_id'] == req['username'] for g in rows):
            catalog.set_pool_grants(pid, rows + [{'subject_type': 'user', 'subject_id': req['username'], 'include_children': True}])
        try:
            from pegaprox.api.vlab_next import provision_granted
            provision_granted(pool, [req['username']])
        except Exception as e:
            logging.warning(f"[VLAB] shared storage folders of {req['username']}: {e}")
    if expires_at:
        accounts.set_expiry(req['username'], accounts.parse_day(expires_at), reviewer)
    catalog.review_signup(req['id'], 'approved', reviewer)
    if in_directory:
        directory.after_change(req['username'])     # its department group
    return None


def _auto_approve(req):
    """After the mail is verified: an institution address gets its account now."""
    s = signup_settings()
    if not s['enabled'] or not accounts.domain_matches(req['email'], s['auto_domains']):
        return False
    full = catalog.get_signup(req['id'], with_secret=True)
    if not full or full['status'] != 'pending':
        return False
    err = create_from_signup(full, 'auto', role=s['auto_role'], department_id=s['auto_department_id'],
                             pool_ids=s['auto_pool_ids'], expires_at=s['auto_expires_at'])
    if err:
        return False
    log_audit('system', 'user.created', f"Sign-up of {req['username']} approved automatically "
              f"({req['email'].rsplit('@', 1)[-1]}, role {s['auto_role']})", get_client_ip())
    return True


@bp.route('/api/vlab/signup/verify', methods=['POST'])
def signup_verify():
    """{id, code} or {id, token} (the mailed link): {verified, approved}."""
    data = _body()
    sid = str(data.get('id') or '')[:64]
    ip = get_client_ip() or ''
    if _limited('verify-ip', ip, 30, 900):
        return jsonify({'error': 'Too many tries - wait a few minutes', 'code': 'RATE_LIMITED'}), 429
    req = catalog.get_signup(sid)
    if not req or req['status'] == 'rejected':
        return _bad('Request not found', 404)
    if req['status'] == 'approved':
        return jsonify({'verified': True, 'approved': True})
    out = accounts.check_verification(sid, code=data.get('code'), token=data.get('token'))
    if out in ('wrong', 'expired', 'locked', 'none'):
        msg = {'wrong': 'The code is not right', 'expired': 'The code has expired - send a new one',
               'locked': 'Too many wrong codes - send a new one', 'none': 'No code was sent for this request'}[out]
        return jsonify({'error': msg, 'code': out.upper()}), 400
    approved = _auto_approve(req) if out == 'ok' else catalog.get_signup(sid)['status'] == 'approved'
    if out == 'ok':
        log_audit(req['username'], 'vlab.signup.verified', f"mail {req['email']} verified", ip)
        if not approved:
            from pegaprox.api.vlab_notices import signup_waiting
            signup_waiting(req)
    return jsonify({'verified': True, 'approved': bool(approved)})


@bp.route('/api/vlab/signup/resend', methods=['POST'])
def signup_resend():
    sid = str(_body().get('id') or '')[:64]
    ip = get_client_ip() or ''
    if _limited('verify-ip', ip, 30, 900) or _limited('resend', sid, 1, 60):
        return jsonify({'error': 'Wait a minute before asking for another code', 'code': 'RATE_LIMITED'}), 429
    req = catalog.get_signup(sid)
    if not req or req['status'] != 'pending' or not req['email'] or not needs_verify(req['email']):
        return _bad('Request not found', 404)
    v = accounts.verification(sid)
    if v and v['verified_at']:
        return jsonify({'sent': False, 'verified': True})
    if v and v['sends'] >= 5:
        return jsonify({'error': 'No more codes for this request - ask the administrator', 'code': 'RATE_LIMITED'}), 429
    return jsonify({'sent': _send_code(req)})


def signup_view(rows):
    """The review list gains the mail check: email_verified, verify_sent."""
    vs = accounts.verifications()
    for r in rows:
        v = vs.get(r['id'])
        r['email_verified'] = bool(v and v['verified_at'])
        r['verify_sent'] = bool(v)
    return rows


# --- 6) terms and privacy ------------------------------------------------------------------

@bp.route('/api/vlab/terms', methods=['GET'])
def public_terms():
    t = terms_settings()
    if not t['enabled']:
        return jsonify({'enabled': False})
    return jsonify({'enabled': True, 'version': t['version'], 'terms': t['terms'], 'privacy': t['privacy'],
                    'updated_at': t['updated_at']})


def terms_needed(username):
    t = terms_settings()
    return t['enabled'] and not accounts.has_consent(username, t['version'])


@bp.route('/api/vlab/me/terms', methods=['GET'])
@require_auth()
def my_terms():
    t = terms_settings()
    if not t['enabled']:
        return jsonify({'required': False, 'enabled': False})
    me = _user()
    mine = accounts.consents(username=me, limit=1)
    return jsonify({'required': not accounts.has_consent(me, t['version']), 'enabled': True, 'version': t['version'],
                    'terms': t['terms'], 'privacy': t['privacy'], 'updated_at': t['updated_at'],
                    'agreed_version': mine[0]['version'] if mine else None})


@bp.route('/api/vlab/me/terms', methods=['POST'])
@require_auth()
def agree_terms():
    t = terms_settings()
    if not t['enabled']:
        return jsonify({'required': False})
    if str(_body().get('version') or '') != t['version']:
        return jsonify({'error': 'The terms changed meanwhile - read them again', 'code': 'TERMS_CHANGED', 'version': t['version']}), 409
    me = _user()
    if not accounts.has_consent(me, t['version']):
        accounts.add_consent(me, t['version'], 'login', get_client_ip() or '')
        log_audit(me, 'vlab.terms.agree', f"agreed to terms version {t['version']}", get_client_ip())
    return jsonify({'required': False, 'version': t['version']})


_TERMS_GATED = ('/api/vlab/me/', '/api/vlab/desktops/')


def attach_terms_gate(app):
    """Run _terms_gate before the requests of the MOAVI Desk blueprints only (every route it
    gates lives there). Not app-wide: an app-level hook the HA lease fast path does not know
    turns that fast path off (pegaprox/app.py _hooks_known, tests/test_ha_guard_answers.py)."""
    for name in app.blueprints:
        if name == 'vlab' or name.startswith('vlab_'):
            hooks = app.before_request_funcs.setdefault(name, [])
            if _terms_gate not in hooks:
                hooks.append(_terms_gate)


def _terms_gate():
    """While terms are on, a signed-in user who has not agreed to this version reaches
    neither the portal's own routes nor a desktop. API tokens are machines: not asked."""
    p = request.path
    if not p.startswith(_TERMS_GATED) or p == '/api/vlab/me/terms' or request.method == 'OPTIONS':
        return None
    if request.headers.get('Authorization', '').startswith('Bearer '):
        return None
    sid = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    if not sid:
        return None
    try:
        t = terms_settings()
        if not t['enabled']:
            return None
        from pegaprox.utils.auth import active_sessions
        sess = active_sessions.get(sid) or {}
        name = sess.get('user')
        if name and not accounts.has_consent(name, t['version']):
            return jsonify({'error': 'Agree to the terms of use first', 'code': 'TERMS_REQUIRED', 'version': t['version']}), 403
    except Exception as e:
        logging.warning(f'[VLAB] terms gate: {e}')
    return None


@bp.route('/api/vlab/admin/terms', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_terms():
    t = terms_settings()
    counts = {}
    if t['version']:
        counts = {'agreed': len({c['username'] for c in accounts.consents(version=t['version'])})}
    return jsonify({'terms': t, **counts})


@bp.route('/api/vlab/admin/terms', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_terms():
    """{enabled?, version?, terms?, privacy?} - a new version asks everyone again."""
    data = _body()
    cur = terms_settings()
    out = dict(cur)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return _bad('enabled must be true or false')
        out['enabled'] = data['enabled']
    if 'version' in data:
        v = str(data['version'] or '').strip()
        if v and not _VERSION.match(v):
            return _bad('version: up to 40 letters, digits, ".", "_" or "-" (e.g. 2026-10 or v2)')
        out['version'] = v
    for k in ('terms', 'privacy'):
        if k in data:
            if not isinstance(data[k], str) or len(data[k]) > 60000:
                return _bad(f'{k}: text of at most 60000 characters')
            out[k] = data[k]
    if out['enabled'] and not out['version']:
        return _bad('Give the terms a version before turning them on')
    if out['enabled'] and not (out['terms'].strip() or out['privacy'].strip()):
        return _bad('The terms and the privacy policy are both empty')
    out['updated_at'] = store.now()
    out['updated_by'] = _user()
    if not _save(_TERMS_KEY, out):
        return _bad('Could not save the settings', 500)
    changed = out['version'] != cur['version']
    log_audit(_user(), 'vlab.terms.settings', f"terms {'on' if out['enabled'] else 'off'}, version {out['version'] or '-'}"
              + (' (new version: everyone agrees again)' if changed and out['enabled'] else ''), get_client_ip())
    return jsonify({'terms': terms_settings()})


@bp.route('/api/vlab/admin/terms/consents', methods=['GET'])
@require_auth(perms=['admin.users'])
def list_consents():
    version = (request.args.get('version') or '').strip() or None
    username = (request.args.get('username') or '').strip().lower() or None
    visible = core._visible_users()
    rows = [c for c in accounts.consents(version=version, username=username) if c['username'] in visible or c['via'] == 'signup']
    if request.args.get('format') == 'csv':
        text = accounts.csv_text(['username', 'display_name', 'version', 'via', 'agreed_at', 'client_ip'],
                                 [[c['username'], (visible.get(c['username']) or {}).get('display_name', ''), c['version'],
                                   c['via'], c['agreed_at'], c['client_ip']] for c in rows])
        return Response(text, mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': 'attachment; filename="terms-consents.csv"'})
    t = terms_settings()
    pending = sorted(n for n, u in visible.items() if t['enabled'] and u.get('enabled', True)
                     and not accounts.has_consent(n, t['version'])) if t['enabled'] else []
    return jsonify({'consents': rows, 'version': t['version'], 'not_yet': pending})


# --- 5) account expiry ---------------------------------------------------------------------

@bp.route('/api/vlab/admin/account-settings', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_account_settings():
    return jsonify({'accounts': account_settings()})


@bp.route('/api/vlab/admin/account-settings', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_account_settings():
    """{notice_days 0-60, delete_after_days 0-3650 (0 = keep), reclaim, public_url}"""
    data = _body()
    out = account_settings()
    for k, lo, hi in (('notice_days', 0, 60), ('delete_after_days', 0, 3650)):
        if k in data:
            try:
                v = int(data[k])
            except (TypeError, ValueError):
                return _bad(f'{k} must be a number')
            if not lo <= v <= hi:
                return _bad(f'{k} must be {lo} to {hi}')
            out[k] = v
    if 'reclaim' in data:
        if not isinstance(data['reclaim'], bool):
            return _bad('reclaim must be true or false')
        out['reclaim'] = data['reclaim']
    if 'public_url' in data:
        url = str(data['public_url'] or '').strip().rstrip('/')
        if url and not re.match(r'^https?://[^\s/]+(/[^\s]*)?$', url):
            return _bad('public_url: the address users open, like https://desk.univ.ac.kr')
        out['public_url'] = url[:200]
    if not _save(_ACCOUNTS_KEY, out):
        return _bad('Could not save the settings', 500)
    log_audit(_user(), 'vlab.accounts.settings', f"expiry notice {out['notice_days']}d, delete after "
              f"{out['delete_after_days'] or 'never'}, reclaim {out['reclaim']}", get_client_ip())
    return jsonify({'accounts': account_settings()})


def apply_expiry(username, value, by):
    """expires_at from a form: '' / None clears it. The day is the last one of use. An
    account that expired is enabled again when it gets a day still to come."""
    from pegaprox.models.permissions import ROLE_ADMIN
    from pegaprox.utils.auth import load_users, save_single_user
    day = accounts.parse_day(value)
    u = (load_users() or {}).get(username)
    if u is None:
        raise LookupError('User not found')
    if day and u.get('role') == ROLE_ADMIN:
        raise ValueError('expires_at: an administrator account does not expire')
    before = accounts.get_expiry(username)
    accounts.set_expiry(username, day, by)
    if before and before.get('expired_at') and (day is None or day >= date.today()) and not u.get('enabled', True):
        u['enabled'] = True
        save_single_user(username, u)
        directory.after_change(username)
        log_audit(by, 'vlab.account.unexpired', f"{username} usable again (until {day or 'no limit'})", get_client_ip())
    return accounts.get_expiry(username)


@bp.route('/api/vlab/admin/users/<username>/expiry', methods=['PUT'])
@require_auth(perms=['admin.users'])
def put_expiry(username):
    username = username.lower()
    if username not in core._visible_users():
        return _bad('User not found', 404)
    try:
        row = apply_expiry(username, _body().get('expires_at'), _user())
    except LookupError:
        return _bad('User not found', 404)
    except ValueError as e:
        return _bad(str(e))
    log_audit(_user(), 'vlab.account.expiry', f"{username}: last day {row['expires_at'] if row else 'none'}", get_client_ip())
    return jsonify({'username': username, 'expires_at': row['expires_at'] if row else None})


def expiry_fields():
    """{username: {expires_at, expired}} for the user list."""
    today = date.today()
    return {n: {'expires_at': r['expires_at'], 'expired': accounts.expiry_state(r, today) == 'expired'}
            for n, r in accounts.expiry_map().items()}


def _reclaim(username):
    """Take the account's desktops back: sessions closed, VM access removed, unassigned, and a
    desktop of a resetting pool back to its base. False when the lease was lost midway."""
    from pegaprox.vlab import policy as pool_policy
    for d in [d for d in store.list_desktops() if d['assigned_user'] == username]:
        if not ha.confirm_step(f"account expiry: desktop {d['id']} of {username}"):
            return False
        for s in store.open_sessions():
            if s['username'] == username and s.get('desktop_id') == d['id']:
                store.close_session(s['id'], result='terminated')
        core._acl_set(d['cluster_id'], d['vmid'], username, False)
        store.set_assignment(d['id'], None)
        pool = store.get_pool(d['pool_id']) or {}
        e = None
        if pool.get('type') in pool_policy.RESET_TYPES and d.get('base_snap'):
            e = core._reset_one(d)
        log_audit('system', 'vlab.desktop.assign', f"{d['vm_type']}/{d['vmid']}: {username} -> - (account expired)"
                  + (f'; reset failed: {e}' if e else ''), '')
    for s in store.open_sessions():
        if s['username'] == username:
            store.close_session(s['id'], result='terminated')
    return True


def _expire(username, u, settings):
    from pegaprox.utils.auth import invalidate_all_user_sessions, revoke_user_api_tokens, save_single_user
    u['enabled'] = False
    save_single_user(username, u)
    invalidate_all_user_sessions(username)
    revoke_user_api_tokens(username)
    accounts.mark_expiry(username, expired_at=store.now())
    log_audit('system', 'vlab.account.expired', f"{username}: past its last day - signed out and disabled", '')
    from pegaprox.api.vlab_notices import account_security
    account_security(username, 'expired', 'system')
    directory.after_change(username)
    if settings['reclaim']:
        return _reclaim(username)
    return True


def _delete(username):
    from pegaprox.core.db import get_db
    from pegaprox.utils.auth import invalidate_all_user_sessions
    db = get_db()
    db.execute('UPDATE api_tokens SET revoked = 1 WHERE username = ?', (username,))
    db.delete_user(username)
    invalidate_all_user_sessions(username)
    catalog.set_department(username, None)
    accounts.forget(username)
    from pegaprox.vlab import notices
    notices.forget_user(username)
    directory.after_delete(username)
    log_audit('system', 'user.deleted', f"Deleted user: {username} (expired account, kept the set days)", '')


def _notice(username, u, row):
    days = (accounts.parse_day(row['expires_at']) - date.today()).days
    ok, err = _mail(u.get('email'), '계정 사용 기한 안내 / Account expiry',
                    f"{u.get('display_name') or username} 님,\n\n{username} 계정은 {row['expires_at']}까지 쓸 수 있습니다"
                    f"({days}일 남음). 그 뒤에는 로그인할 수 없고 배정된 데스크톱이 회수됩니다. "
                    f"데스크톱의 파일은 미리 옮겨 두세요. 연장이 필요하면 관리자에게 문의하세요.\n\n"
                    f"The account {username} can be used until {row['expires_at']}. After that it cannot sign in "
                    f"and its desktops are taken back.\n")
    accounts.mark_expiry(username, notified_at=store.now())
    log_audit('system', 'vlab.account.expiry_notice', f"{username}: last day {row['expires_at']}"
              + ('' if ok else f' - mail not sent: {err}'), '')


def accounts_tick(today=None):
    """Once a minute on the active instance (pegaprox/vlab/loans.py). Returns what it did."""
    from pegaprox.models.permissions import ROLE_ADMIN
    from pegaprox.utils.auth import load_users
    today = today or date.today()
    s = account_settings()
    rows = accounts.expiry_map()
    if not rows:
        return {}
    users = load_users() or {}
    done = {'noticed': 0, 'expired': 0, 'deleted': 0}
    for name, row in rows.items():
        u = users.get(name)
        if u is None:
            accounts.forget(name)
            continue
        last = accounts.parse_day(row['expires_at'])
        if not row['expired_at']:
            if today > last:
                if u.get('role') == ROLE_ADMIN:
                    continue
                if not ha.confirm_step(f'account expiry of {name}'):
                    break
                if not _expire(name, u, s):
                    break
                done['expired'] += 1
            elif s['notice_days'] and not row['notified_at'] and (last - today).days <= s['notice_days'] \
                    and u.get('enabled', True) and u.get('email'):
                _notice(name, u, row)
                done['noticed'] += 1
        elif s['delete_after_days'] and not u.get('enabled', True) and u.get('role') != ROLE_ADMIN:
            since = datetime.fromisoformat(row['expired_at']).date()
            if today >= since + timedelta(days=s['delete_after_days']):
                if not ha.confirm_step(f'deleting the expired account {name}'):
                    break
                _delete(name)
                done['deleted'] += 1
    return done


# --- 4) bulk import ------------------------------------------------------------------------

@bp.route('/api/vlab/admin/users/import/example', methods=['GET'])
@require_auth(perms=['admin.users'])
def import_example():
    return Response('﻿' + accounts.EXAMPLE_CSV, mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="accounts-example.csv"'})


_USERNAME = re.compile(r'^[a-z0-9][a-z0-9._-]{2,31}$')


def _plan(text):
    """[{line, username, display_name, email, department_id, department, role, expires_at, errors}]"""
    from pegaprox.utils.auth import load_users
    rows = accounts.read_csv(text)
    users = load_users() or {}
    deps = catalog.list_departments()
    by_name = {}
    for d in deps:
        by_name.setdefault(d['name'].strip().lower(), []).append(d['id'])
    by_id = {d['id'] for d in deps}
    roles_ok = {}
    seen = {}
    out = []
    for line, r in rows:
        errs = []
        name = r.get('username', '').strip().lower()
        if not _USERNAME.match(name):
            errs.append('username: 3-32 lower-case letters, digits, ".", "_" or "-"')
        elif name in users:
            errs.append('exists')
        elif name in seen:
            errs.append(f'duplicate of line {seen[name]}')
        seen.setdefault(name, line)
        email = r.get('email', '').strip()
        if email and not _MAIL.match(email):
            errs.append('email is not valid')
        dep_txt = r.get('department', '').strip()
        dep = None
        if dep_txt:
            if dep_txt in by_id:
                dep = dep_txt
            else:
                ids = by_name.get(dep_txt.lower(), [])
                if len(ids) == 1:
                    dep = ids[0]
                else:
                    errs.append(f'department: {"more than one" if ids else "no"} department named "{dep_txt}"')
        role = r.get('role', '').strip() or 'user'
        if role not in roles_ok:
            try:
                _check_role(role)
                roles_ok[role] = None
            except ValueError as e:
                roles_ok[role] = str(e)
        if roles_ok[role]:
            errs.append(roles_ok[role])
        exp = None
        try:
            day = accounts.parse_day(r.get('expires_at'))
            if day and day < date.today():
                errs.append('expires_at: the day has passed')
            exp = day.isoformat() if day else None
        except ValueError as e:
            errs.append(str(e))
        display = r.get('display_name', '').strip()[:80]
        out.append({'line': line, 'username': name, 'display_name': display or name, 'email': email,
                    'department_id': dep, 'department': dep_txt, 'role': role, 'expires_at': exp, 'errors': errs,
                    'duplicate': any(e == 'exists' or e.startswith('duplicate') for e in errs)})
    return out


@bp.route('/api/vlab/admin/users/import/preview', methods=['POST'])
@require_auth(perms=['admin.users'])
def import_preview():
    try:
        rows = _plan(_body().get('csv'))
    except ValueError as e:
        return _bad(str(e))
    bad = sum(1 for r in rows if r['errors'])
    return jsonify({'rows': rows, 'ok': len(rows) - bad, 'errors': bad})


@bp.route('/api/vlab/admin/users/import', methods=['POST'])
@require_auth(perms=['admin.users'])
def import_accounts():
    """{csv, deliver: 'csv' | 'mail', must_change_password: true}: the rows without errors
    become accounts with a random password. deliver csv: the answer carries a CSV with the
    passwords - shown this once, never stored. deliver mail: each account with a mail
    address gets its own; the CSV then has a password only for those without one."""
    from pegaprox.core.db import DEFAULT_TENANT_ID
    from pegaprox.api import users as core_users
    from pegaprox.utils.auth import hash_password, load_users, save_single_user
    data = _body()
    deliver = data.get('deliver') or 'csv'
    if deliver not in ('csv', 'mail'):
        return _bad('deliver must be csv or mail')
    must_change = data.get('must_change_password', True) is not False
    try:
        rows = _plan(data.get('csv'))
    except ValueError as e:
        return _bad(str(e))
    tenant = core_users._caller_tenant_or_none() or DEFAULT_TENANT_ID
    s = _settings()
    created, skipped, result = [], [], []
    login_url = _base_url() + '/login'
    for r in rows:
        if r['errors']:
            skipped.append({'line': r['line'], 'username': r['username'], 'errors': r['errors']})
            continue
        if r['username'] in (load_users() or {}):
            skipped.append({'line': r['line'], 'username': r['username'], 'errors': ['exists']})
            continue
        role = r['role']
        home = tenant
        if role not in ('admin', 'user', 'viewer'):
            home = core_users._role_home_tenant(role, tenant) or tenant
        pw = accounts.make_password(s.get('password_min_length', 8), bool(s.get('password_require_special', False)))
        salt, pw_hash = hash_password(pw)
        stamp = datetime.now().isoformat()
        save_single_user(r['username'], {
            'password_salt': salt, 'password_hash': pw_hash, 'password_changed_at': stamp, 'role': role,
            'display_name': r['display_name'], 'email': r['email'], 'enabled': True, 'created_at': stamp,
            'last_login': None, 'tenant_id': home, 'permissions': [], 'denied_permissions': [],
            'portal_only': role == 'user', 'force_password_change': must_change,
        })
        if r['department_id']:
            catalog.set_department(r['username'], r['department_id'])
        if r['expires_at']:
            accounts.set_expiry(r['username'], accounts.parse_day(r['expires_at']), _user())
        # the bundled directory: the account with this first password goes there now
        directory.after_create(r['username'], pw)
        mailed = False
        if deliver == 'mail' and r['email']:
            mailed, _err = _mail(r['email'], '계정 안내 / Your account',
                                 f"{r['display_name']} 님,\n\n계정이 만들어졌습니다.\n주소: {login_url}\n아이디: {r['username']}\n"
                                 f"초기 비밀번호: {pw}\n" + ("처음 로그인할 때 새 비밀번호로 바꿉니다.\n" if must_change else '')
                                 + (f"사용 기한: {r['expires_at']}\n" if r['expires_at'] else '')
                                 + f"\nAn account was made for you: {r['username']} at {login_url}.\n")
        created.append({'username': r['username'], 'display_name': r['display_name'], 'email': r['email'],
                        'mailed': bool(mailed)})
        result.append([r['username'], r['display_name'], r['email'], r['department'], role, r['expires_at'] or '',
                       '' if mailed else pw, 'yes' if mailed else 'no'])
    text = accounts.csv_text(['username', 'display_name', 'email', 'department', 'role', 'expires_at', 'password', 'mailed'], result)
    log_audit(_user(), 'user.created', f"bulk import: {len(created)} account(s) made, {len(skipped)} row(s) skipped"
              f" ({'mailed' if deliver == 'mail' else 'passwords in the result CSV'})", get_client_ip())
    return jsonify({'created': created, 'skipped': skipped, 'csv': text,
                    'mailed': sum(1 for c in created if c['mailed'])})
