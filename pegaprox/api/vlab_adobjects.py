# -*- coding: utf-8 -*-
"""
MOAVI Desk - AD 디렉터리: the objects of the bundled DC or of the site's AD, browsed and changed
from the console (pegaprox/vlab/adobjects.py). Every change is written to the directory with the
source's bind account and to the audit log.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/admin/ad/sources                      the directories there are: bundled, ldap     admin.users
  POST   /api/vlab/admin/ad/test          {source}       bind, the base, what may be made there       admin.users
  GET    /api/vlab/admin/ad/tree          ?source&dn     the OUs / containers under dn                admin.users
  GET    /api/vlab/admin/ad/objects       ?source&dn&kind=users|groups|computers|ous|all&q&subtree=1   admin.users
  GET    /api/vlab/admin/ad/object        ?source&dn     one object; a group with direct and nested members  admin.users
  POST   /api/vlab/admin/ad/ous           {source, parent_dn, name, description?}                     admin.users
  POST   /api/vlab/admin/ad/groups        {source, parent_dn, name, scope, type, description?, sam?}  admin.users
  POST   /api/vlab/admin/ad/users         {source, parent_dn, sam, display_name?, given_name?, surname?,
                                           mail?, description?, password?, enabled?}                  admin.users
  PUT    /api/vlab/admin/ad/object        {source, dn, changes{...}}                                   admin.users
  PUT    /api/vlab/admin/ad/object/enabled  {source, dn, enabled}                                      admin.users
  PUT    /api/vlab/admin/ad/object/password {source, dn, password}  (not kept, not logged)             admin.users
  DELETE /api/vlab/admin/ad/object        {source, dn}   an OU only when empty                         admin.users
  POST   /api/vlab/admin/ad/members       {source, group_dn, member_dn, action: add|remove}            admin.users
"""

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import adobjects

bp = Blueprint('vlab_adobjects', __name__)
_bad = core._bad
_user = core._user

_STATUS = {'NOT_ON': 409, 'BAD_SOURCE': 400, 'BAD_DN': 400, 'OUTSIDE': 400, 'BAD_KIND': 400, 'BAD_NAME': 400,
           'BAD_SCOPE': 400, 'BAD_TYPE': 400, 'BAD_VALUE': 400, 'NOT_EDITABLE': 400, 'NOT_A_USER': 400,
           'NOT_A_GROUP': 400, 'SELF': 409, 'CYCLE': 409, 'NOT_EMPTY': 409, 'MANAGED': 409, 'EXISTS': 409,
           'NOT_FOUND': 404, 'DENIED': 403, 'REFUSED': 409, 'PASSWORD_REFUSED': 400, 'PASSWORD_POLICY': 400,
           'UNREACHABLE': 503, 'NO_SERVICE_ACCOUNT': 503, 'FAILED': 502}


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _fail(e):
    return jsonify({'error': e.detail or e.code, 'code': e.code}), _STATUS.get(e.code, 502)


def _src(v):
    return str(v or 'bundled')


def _audit(what, detail):
    log_audit(_user(), f'vlab.ad.{what}', detail, get_client_ip())


@bp.route('/api/vlab/admin/ad/sources', methods=['GET'])
@require_auth(perms=['admin.users'])
def ad_sources():
    return jsonify({'sources': adobjects.sources()})


@bp.route('/api/vlab/admin/ad/test', methods=['POST'])
@require_auth(perms=['admin.users'])
def ad_test():
    try:
        return jsonify({'test': adobjects.test(_src(_body().get('source')))})
    except adobjects.Error as e:
        return _fail(e)


@bp.route('/api/vlab/admin/ad/tree', methods=['GET'])
@require_auth(perms=['admin.users'])
def ad_tree():
    try:
        return jsonify(adobjects.tree(_src(request.args.get('source')), request.args.get('dn') or None))
    except adobjects.Error as e:
        return _fail(e)


@bp.route('/api/vlab/admin/ad/objects', methods=['GET'])
@require_auth(perms=['admin.users'])
def ad_objects():
    a = request.args
    try:
        return jsonify(adobjects.objects(_src(a.get('source')), a.get('dn') or None, a.get('kind') or 'all',
                                         a.get('q') or '', a.get('subtree') in ('1', 'true')))
    except adobjects.Error as e:
        return _fail(e)


@bp.route('/api/vlab/admin/ad/object', methods=['GET'])
@require_auth(perms=['admin.users'])
def ad_object():
    try:
        return jsonify({'object': adobjects.get_object(_src(request.args.get('source')), request.args.get('dn') or '')})
    except adobjects.Error as e:
        return _fail(e)


@bp.route('/api/vlab/admin/ad/ous', methods=['POST'])
@require_auth(perms=['admin.users'])
def ad_create_ou():
    d = _body()
    try:
        v = adobjects.create_ou(_src(d.get('source')), d.get('parent_dn'), d.get('name'), str(d.get('description') or ''))
    except adobjects.Error as e:
        return _fail(e)
    _audit('ou.create', f"{_src(d.get('source'))}: {v['dn']}")
    return jsonify({'object': v}), 201


@bp.route('/api/vlab/admin/ad/groups', methods=['POST'])
@require_auth(perms=['admin.users'])
def ad_create_group():
    d = _body()
    try:
        v = adobjects.create_group(_src(d.get('source')), d.get('parent_dn'), d.get('name'), d.get('scope') or 'global',
                                   d.get('type') or 'security', str(d.get('description') or ''), d.get('sam'))
    except adobjects.Error as e:
        return _fail(e)
    _audit('group.create', f"{_src(d.get('source'))}: {v['dn']} ({v['type']}, {v['scope']})")
    return jsonify({'object': v}), 201


@bp.route('/api/vlab/admin/ad/users', methods=['POST'])
@require_auth(perms=['admin.users'])
def ad_create_user():
    d = _body()
    pw = d.get('password') or None
    if pw is not None and not isinstance(pw, str):
        return _bad('password must be text')
    try:
        v = adobjects.create_user(_src(d.get('source')), d.get('parent_dn'), d.get('sam'), str(d.get('display_name') or ''),
                                  str(d.get('given_name') or ''), str(d.get('surname') or ''), str(d.get('mail') or ''),
                                  str(d.get('description') or ''), pw, d.get('enabled', True) is not False)
    except adobjects.Error as e:
        return _fail(e)
    finally:
        pw = None
    _audit('user.create', f"{_src(d.get('source'))}: {v['dn']}" + ('' if v.get('enabled') else ' (disabled)'))
    return jsonify({'object': v}), 201


@bp.route('/api/vlab/admin/ad/object', methods=['PUT'])
@require_auth(perms=['admin.users'])
def ad_update():
    d = _body()
    ch = d.get('changes')
    if not isinstance(ch, dict) or not ch:
        return _bad('changes: the attributes to set')
    try:
        v = adobjects.update_object(_src(d.get('source')), d.get('dn'), ch)
    except adobjects.Error as e:
        return _fail(e)
    _audit('object.update', f"{_src(d.get('source'))}: {v['dn']}: {', '.join(sorted(ch))}")
    return jsonify({'object': v})


@bp.route('/api/vlab/admin/ad/object/enabled', methods=['PUT'])
@require_auth(perms=['admin.users'])
def ad_enabled():
    d = _body()
    if not isinstance(d.get('enabled'), bool):
        return _bad('enabled must be true or false')
    try:
        v = adobjects.set_enabled(_src(d.get('source')), d.get('dn'), d['enabled'])
    except adobjects.Error as e:
        return _fail(e)
    _audit('object.enable' if d['enabled'] else 'object.disable', f"{_src(d.get('source'))}: {v['dn']}")
    return jsonify({'object': v})


@bp.route('/api/vlab/admin/ad/object/password', methods=['PUT'])
@require_auth(perms=['admin.users'])
def ad_password():
    d = _body()
    pw = d.get('password')
    if not isinstance(pw, str) or not pw:
        return _bad('password is needed')
    try:
        adobjects.set_password(_src(d.get('source')), d.get('dn'), pw)
    except adobjects.Error as e:
        return _fail(e)
    finally:
        pw = None
    _audit('object.password', f"{_src(d.get('source'))}: password set for {d.get('dn')} (not kept)")
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/ad/object', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def ad_delete():
    d = _body() or {'source': request.args.get('source'), 'dn': request.args.get('dn')}
    try:
        v = adobjects.delete_object(_src(d.get('source')), d.get('dn'))
    except adobjects.Error as e:
        return _fail(e)
    _audit('object.delete', f"{_src(d.get('source'))}: {v['dn']} ({v['kind']})")
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/ad/members', methods=['POST'])
@require_auth(perms=['admin.users'])
def ad_members():
    d = _body()
    action = d.get('action') or 'add'
    if action not in ('add', 'remove'):
        return _bad('action: add or remove')
    try:
        v = adobjects.change_member(_src(d.get('source')), d.get('group_dn'), d.get('member_dn'), action == 'add')
    except adobjects.Error as e:
        return _fail(e)
    _audit('member.' + action, f"{_src(d.get('source'))}: {d.get('member_dn')} {'->' if action == 'add' else '<-'} {v['dn']}")
    return jsonify({'object': v})
