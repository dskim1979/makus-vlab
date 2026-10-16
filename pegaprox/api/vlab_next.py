# -*- coding: utf-8 -*-
"""
MOAVI Desk - the next-phase screens of the console (docs/vlab-design.md 4-2, 7-3, 10-2..10-4).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/admin/departments                     the department tree, member counts   vlab.pool.view
  POST   /api/vlab/admin/departments                     {name, parent_id?, sort?}            admin.users
  PUT    /api/vlab/admin/departments/<id>                rename / move                        admin.users
  DELETE /api/vlab/admin/departments/<id>                one without sub-departments          admin.users
  GET    /api/vlab/admin/departments/<id>/members        ?children=1 includes sub-departments  vlab.pool.view
  PUT    /api/vlab/admin/users/<username>/department     {department_id|null}                 admin.users

  POST   /api/vlab/admin/users                           {username, password, display_name?, email?, role?, department_id?, must_change_password?}  admin.users
  PUT    /api/vlab/admin/users/<username>                {display_name?, email?, role?, enabled?, department_id?}  admin.users
  DELETE /api/vlab/admin/users/<username>                                                     admin.users
  PUT    /api/vlab/admin/users/<username>/password       {password, must_change_password?}    admin.users
  DELETE /api/vlab/admin/users/<username>/2fa            clear the account's TOTP             admin.users
  GET    /api/vlab/admin/locked-users, DELETE .../<username>   sign-in lockouts            security.lockout.view / manage
  GET    /api/vlab/admin/permissions, /roles, /roles/templates  the permission grid and roles  signed in
  POST   /api/vlab/admin/roles, PUT/DELETE .../<id>, POST .../templates/<id>/apply   custom roles  admin.roles
  (thin wrappers over the core routes of pegaprox/api/users.py)

  GET    /api/vlab/signup/config                         is sign-up open, the departments     public
  POST   /api/vlab/signup                                {username, password, display_name?, email?, department_id?, note?}  public
  GET    /api/vlab/admin/signups                         ?status=pending|approved|rejected     admin.users
  POST   /api/vlab/admin/signups/<id>/approve            makes the account (role user, portal only)  admin.users
  POST   /api/vlab/admin/signups/<id>/reject             {reason?}                            admin.users
  GET/PUT /api/vlab/admin/signup-settings                {enabled}                            admin.settings

  GET/POST /api/vlab/admin/usb-devices, PUT/DELETE .../<id>   the USB device library       vlab.pool.view / manage
  GET/POST /api/vlab/admin/gateways, PUT/DELETE .../<id>, POST .../<id>/check   gateways    vlab.pool.view / manage
  GET/POST /api/vlab/admin/external-desktops, PUT/DELETE .../<id>   physical PCs over RDP   vlab.pool.view / manage
  GET    /api/vlab/me/external                           the caller's external desktops       vlab.desk
  GET    /api/vlab/me/external/<id>/rdp                  an .rdp file for it                  vlab.desk

  GET    /api/vlab/admin/golden-images                   with their versions (snapshots)      vlab.pool.view
  POST   /api/vlab/admin/golden-images                   {cluster_id, vmid, name?, notes?}    vlab.pool.manage
  DELETE /api/vlab/admin/golden-images/<id>              stop treating the VM as one (VM kept) vlab.pool.manage
  POST   /api/vlab/admin/golden-images/<id>/versions     {description?} a new version = snapshot gold-<time>  vlab.pool.manage
  PUT    /api/vlab/admin/golden-images/<id>/current      {version}                            vlab.pool.manage
  POST   /api/vlab/admin/golden-images/<id>/deploy       {pool_id, count, name_prefix, start_vmid?} full clones of the current version  vlab.pool.manage

  GET/POST /api/vlab/admin/boards, PUT/DELETE .../<id>   the board lab (JTAG cables)          vlab.pool.view / vlab.accel.manage
  POST   /api/vlab/admin/boards/<id>/attach              {desktop_id} USB passthrough, slot usb4  vlab.accel.manage
  POST   /api/vlab/admin/boards/<id>/detach                                                    vlab.accel.manage

  GET    /api/vlab/admin/buildfarm                       build farm pools: size, in use, load  vlab.pool.view

  GET/POST /api/vlab/admin/license-servers, PUT/DELETE .../<id>, POST .../<id>/check   licence servers  vlab.pool.view / vlab.accel.manage
  (their seats - lmstat per feature, holders, report - are in pegaprox/api/vlab_license.py; license_tick reads them)

  GET/PUT /api/vlab/admin/pools/<id>/grants          who may claim / use a pool (user, department, group)  vlab.pool.view / manage
  GET    /api/vlab/me/pools, POST .../<id>/claim, POST .../<id>/route   claim a desktop, route into a shared pool  vlab.desk
  GET    /api/vlab/me/external/<id>/guac              browser RDP link (Guacamole) for an external desktop  vlab.desk
  POST   /api/vlab/admin/golden-images/<id>/rollout   desktops of an older version replaced by the current one  vlab.pool.manage
  GET/POST /api/vlab/me/build-jobs, POST .../<id>/cancel     the caller's build jobs                vlab.desk
  GET/POST /api/vlab/admin/build-jobs, POST .../<id>/cancel  every build job                        vlab.pool.view / manage
  GET    /api/vlab/admin/reports/cards                ?days=&format=csv card loans per card       vlab.report.view

  VM build (가상머신 > ISO · 이미지 관리, VM 만들기) - thin wrappers over the core routes; each needs
  vlab.pool.view (reads) or vlab.pool.manage (changes) besides the core permission named:
  GET    /api/vlab/admin/clusters/<id>/nodes/<node>/isos              ?storage=  the ISOs     storage.view
  POST   .../nodes/<node>/storage/<storage>/upload                    multipart file, node   storage.upload
  POST   .../nodes/<node>/storage/<storage>/download-url              {url, filename, checksum?}  storage.download
  DELETE .../nodes/<node>/storage/<storage>/isos/<volid>              ?node=                 storage.delete
  GET    .../nodes/<node>/tasks/<upid>                                download/upload/create progress  storage.view
  GET    .../nodes/<node>/networks                                    bridges for a new NIC  node.view
  GET    /api/vlab/admin/clusters/<id>/nextid                         the next free VMID     vm.create
  POST   .../nodes/<node>/vms                                         a new VM from an ISO   vm.create
  POST   /api/vlab/admin/clusters/<id>/vms/<vmid>/console             noVNC while installing vm.console
  POST   /api/vlab/admin/clusters/<id>/vms/<vmid>/template            make it a template     vm.template

  GET    /api/vlab/banners                            notices for the caller that run now     signed in
  GET    /api/vlab/admin/banners                      every notice (the core banner list)     admin.settings
  POST   /api/vlab/admin/banners                      {text, severity?, starts_at?, expires_at?, audience: all|admins}  admin.settings
  PUT    /api/vlab/admin/banners/<id>                 change it (fields left out stay)        admin.settings
  DELETE /api/vlab/admin/banners/<id>                 remove it                               admin.settings

  가상머신 > 데스크톱(VM) 관리 (thin wrappers over pegaprox/api/vms.py, see the block at the end):
  GET    /api/vlab/admin/desktops/<id>/vm                the VM config, bridges, storages, nodes to move to  vlab.pool.view
  PUT    /api/vlab/admin/desktops/<id>/vm/hardware       {cores?, sockets?, memory_mb?}       vlab.pool.manage
  POST   /api/vlab/admin/desktops/<id>/vm/disks          {storage, size_gb} a new disk        vlab.pool.manage
  POST   /api/vlab/admin/desktops/<id>/vm/disks/<disk>/resize   {grow_gb}                   vlab.pool.manage
  PUT    /api/vlab/admin/desktops/<id>/vm/networks/<net> {bridge, tag|null}                   vlab.pool.manage
  DELETE /api/vlab/admin/desktops/<id>/vm                {confirm_name, force?} VM deleted, out of the pool  vlab.pool.manage
  GET/POST /api/vlab/admin/desktops/<id>/snapshots, POST .../<name>/rollback, DELETE .../<name>  vlab.pool.view / manage
  POST   /api/vlab/admin/desktops/<id>/migrate           {target, online?} not with PCI/USB passthrough  vlab.pool.manage
  GET    /api/vlab/admin/desktops/<id>/task              ?upid= how its task is going         vlab.pool.view
  POST   /api/vlab/admin/desktops/<id>/template          shut down VM -> template, out of the pool  vlab.pool.manage
  POST   /api/vlab/admin/desktops/<id>/console           noVNC for support, audited           vlab.pool.manage

  운영 기본 (작업 진행 · 노드 유지보수 · Proxmox HA, the block at the end):
  GET    /api/vlab/tasks                                 ?cluster=&limit= running and recent Proxmox tasks: all of them
                                                         with vlab.pool.view, else the caller's own   signed in
  GET    /api/vlab/tasks/log                             ?cluster=&upid= its state and log, same scope  signed in
  GET    /api/vlab/admin/clusters/<id>/nodes/<node>/maintenance          its maintenance  vlab.pool.view + node.view
  GET    .../nodes/<node>/maintenance-preview            desktops and guests on it, room elsewhere, plan  + node.maintenance
  PUT    .../nodes/<node>/maintenance                    {enable, skip_evacuation?, migrate_templates?, relax_anti_affinity?}  vlab.pool.manage + node.maintenance
  POST   .../nodes/<node>/action                         {action: reboot|shutdown, confirm: <node>}  vlab.pool.manage + node.reboot
  GET    .../nodes/<node>/syslog, /sensors, /tasks       the node's log, sensors, task history   vlab.pool.view + node.view
  GET    /api/vlab/admin/clusters/<id>/ha                Proxmox HA resources, groups, quorum   vlab.pool.view + ha.view
  POST   .../ha/resources {vmid, state?, group?, ...}, DELETE .../ha/resources/<vmid>   vlab.pool.manage + ha.config
  POST   .../ha/groups {group, nodes, ...}, DELETE .../ha/groups/<group>               vlab.pool.manage + ha.config

  공유 저장소 (shared NAS storage, pegaprox/vlab/nas.py, the block at the end):
  GET    /api/vlab/admin/pools/<id>/storage              the setting (never the password), last results  vlab.pool.view
  PUT    /api/vlab/admin/pools/<id>/storage              {enabled, kind, server, share, ..., smb_password?}  vlab.pool.manage
  POST   /api/vlab/admin/pools/<id>/storage/check        {desktop_id?} apply it now on running VMs     vlab.pool.manage
  GET    /api/vlab/me/storage                            the caller's build folders                    vlab.desk
  (applied on connect, on a shared pool's routing and before a build job starts)
"""

import base64
import hashlib
import hmac
import json as _json
import logging
import re
import shlex
import socket
import time
from datetime import datetime
from urllib.parse import quote as _quote

from flask import Blueprint, has_request_context, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, datasets, envcat, nas, store

bp = Blueprint('vlab_next', __name__)

_bad = core._bad
_user = core._user


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _text(data, key, limit, required=False):
    v = str(data.get(key) or '').strip()
    if required and not v:
        raise ValueError(f'{key} is required')
    if len(v) > limit:
        raise ValueError(f'{key}: at most {limit} characters')
    return v


def _int(data, key, lo, hi, default=None):
    v = data.get(key, default)
    if v in (None, ''):
        if default is None:
            raise ValueError(f'{key} is required')
        v = default
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f'{key} must be a number')
    if not lo <= v <= hi:
        raise ValueError(f'{key} must be {lo} to {hi}')
    return v


_HOST = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]+\]?$')


def _host(data, key):
    v = _text(data, key, 253, required=True)
    if not _HOST.match(v):
        raise ValueError(f'{key} must be a host name or an IP address')
    return v.strip('[]')


def _tcp_probe(host, port, timeout=2.0):
    """Is something listening on host:port? Returns (ok, milliseconds, error)."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, int((time.monotonic() - t0) * 1000), ''
    except OSError as e:
        return False, int((time.monotonic() - t0) * 1000), (e.strerror or e.__class__.__name__)[:120]


# --- departments -------------------------------------------------------------------------

@bp.route('/api/vlab/admin/departments', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_departments():
    return jsonify({'departments': catalog.list_departments()})


def _department_body(dep_id=None):
    data = _body()
    name = _text(data, 'name', 80, required=True)
    parent = str(data.get('parent_id') or '').strip() or None
    if parent:
        if not catalog.get_department(parent):
            raise ValueError('parent_id: no such department')
        if dep_id and parent in catalog.descendants(dep_id):
            raise ValueError('A department cannot move under itself')
    return name, parent, _int(data, 'sort', 0, 10000, 0)


@bp.route('/api/vlab/admin/departments', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_department():
    try:
        name, parent, sort = _department_body()
    except ValueError as e:
        return _bad(str(e))
    dep = catalog.save_department(None, name, parent, sort)
    log_audit(_user(), 'vlab.department.create', f"department '{name}'", get_client_ip())
    return jsonify({'department': dep}), 201


@bp.route('/api/vlab/admin/departments/<dep_id>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_department(dep_id):
    if not catalog.get_department(dep_id):
        return _bad('Department not found', 404)
    try:
        name, parent, sort = _department_body(dep_id)
    except ValueError as e:
        return _bad(str(e))
    dep = catalog.save_department(dep_id, name, parent, sort)
    log_audit(_user(), 'vlab.department.update', f"department '{name}'", get_client_ip())
    return jsonify({'department': dep})


@bp.route('/api/vlab/admin/departments/<dep_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_department(dep_id):
    dep = catalog.get_department(dep_id)
    if not dep:
        return _bad('Department not found', 404)
    if len(catalog.descendants(dep_id)) > 1:
        return _bad('Move or delete its sub-departments first', 409)
    catalog.delete_department(dep_id)
    log_audit(_user(), 'vlab.department.delete', f"department '{dep['name']}' (its members now belong to none)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/departments/<dep_id>/members', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def department_members(dep_id):
    if not catalog.get_department(dep_id):
        return _bad('Department not found', 404)
    ids = catalog.descendants(dep_id) if request.args.get('children') in ('1', 'true') else {dep_id}
    return jsonify({'members': catalog.members(ids)})


@bp.route('/api/vlab/admin/users/<username>/department', methods=['PUT'])
@require_auth(perms=['admin.users'])
def set_user_department(username):
    from pegaprox.utils.auth import load_users
    if username not in load_users():
        return _bad('User not found', 404)
    dep = str(_body().get('department_id') or '').strip() or None
    if dep and not catalog.get_department(dep):
        return _bad('department_id: no such department')
    catalog.set_department(username, dep)
    log_audit(_user(), 'vlab.department.member', f"{username} -> {dep or '(none)'}", get_client_ip())
    return jsonify({'username': username, 'department_id': dep})


# --- accounts and roles (사용자 > 사용자 목록, 역할 관리) --------------------------------------
#
# The console speaks /api/vlab/* only (its README, 구조), and making, changing and deleting
# accounts, resetting a password or 2FA, unlocking and the custom roles were core routes
# (pegaprox/api/users.py). These wrappers stay thin: each accepts only the fields the
# console's forms have, refuses any other key - so the core never sees a tenant_id, a
# permission grant or portal_only on an account from here - and hands the request on to the
# core route, which keeps its own permission, tenant and outrank checks, the last-admin
# guard, the password policy, the session revocation and the audit. Two things the core does
# not do are added after it answers 200: the department (catalog) and "change the password
# at the next sign-in" (force_password_change, answered by the login as
# requires_password_change and cleared by /api/auth/change-password).

_USER_CREATE_KEYS = ('username', 'password', 'display_name', 'email', 'role', 'department_id', 'must_change_password')
_USER_UPDATE_KEYS = ('display_name', 'email', 'role', 'enabled', 'department_id')
_ROLE_KEYS = ('name', 'permissions', 'tenant_id')


def _only(data, allowed):
    extra = sorted(k for k in data if k not in allowed)
    if extra:
        raise ValueError('Not accepted here: ' + ', '.join(extra))
    for k in ('must_change_password', 'enabled'):
        if k in data and not isinstance(data[k], bool):
            raise ValueError(f'{k} must be true or false')
    for k in ('id', 'role_id', 'username', 'password', 'name', 'display_name', 'email', 'role', 'tenant_id'):
        if k in data and data[k] is not None and not isinstance(data[k], str):
            raise ValueError(f'{k} must be text')
    if 'permissions' in data and not (isinstance(data['permissions'], list)
                                      and all(isinstance(p, str) for p in data['permissions'])):
        raise ValueError('permissions must be a list of names')
    dep = data.get('department_id')
    if dep is not None and (not isinstance(dep, str) or (dep and not catalog.get_department(dep))):
        raise ValueError('department_id: no such department')


def _core_ok(resp):
    """The core route's answer as (ok, body)."""
    r = resp[0] if isinstance(resp, tuple) else resp
    status = resp[1] if isinstance(resp, tuple) and len(resp) > 1 else getattr(r, 'status_code', 200)
    try:
        body = r.get_json()
    except Exception:
        body = None
    return status == 200, body


def _force_password_change(username, on):
    from pegaprox.utils.auth import load_users, save_single_user
    rec = load_users().get(username)
    if rec is not None and bool(rec.get('force_password_change')) != on:
        rec['force_password_change'] = on
        save_single_user(username, rec)


@bp.route('/api/vlab/admin/users', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_account():
    """{username, password, display_name?, email?, role?, department_id?, must_change_password?}"""
    from pegaprox.api import users as core_users
    data = _body()
    try:
        _only(data, _USER_CREATE_KEYS)
    except ValueError as e:
        return _bad(str(e))
    resp = core_users.create_user()
    ok, body = _core_ok(resp)
    if not ok:
        return resp
    name = body['user']['username']
    if data.get('department_id'):
        catalog.set_department(name, data['department_id'])
    if data.get('must_change_password'):
        _force_password_change(name, True)
    return jsonify({'user': dict(body['user'], department_id=data.get('department_id') or None,
                                 must_change_password=bool(data.get('must_change_password')))}), 201


@bp.route('/api/vlab/admin/users/<username>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_account(username):
    """{display_name?, email?, role?, enabled?, department_id?} - a password goes to .../password"""
    from pegaprox.api import users as core_users
    username = username.lower()
    if username not in core._visible_users():
        return _bad('User not found', 404)
    data = _body()
    try:
        _only(data, _USER_UPDATE_KEYS)
    except ValueError as e:
        return _bad(str(e))
    if any(k in data for k in _USER_UPDATE_KEYS if k != 'department_id'):
        resp = core_users.update_user(username)
        if not _core_ok(resp)[0]:
            return resp
    if 'department_id' in data:
        catalog.set_department(username, data['department_id'] or None)
        log_audit(_user(), 'vlab.department.member', f"{username} -> {data['department_id'] or '(none)'}", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/users/<username>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_account(username):
    from pegaprox.api import users as core_users
    username = username.lower()
    if username not in core._visible_users():
        return _bad('User not found', 404)
    resp = core_users.delete_user(username)
    if _core_ok(resp)[0]:
        catalog.set_department(username, None)
    return resp


@bp.route('/api/vlab/admin/users/<username>/password', methods=['PUT'])
@require_auth(perms=['admin.users'])
def reset_account_password(username):
    """{password, must_change_password?} - every session and API token of the account ends"""
    from pegaprox.api import users as core_users
    username = username.lower()
    data = _body()
    try:
        _only(data, ('password', 'must_change_password'))
    except ValueError as e:
        return _bad(str(e))
    resp = core_users.admin_change_password(username)
    if _core_ok(resp)[0]:
        _force_password_change(username, bool(data.get('must_change_password')))
    return resp


@bp.route('/api/vlab/admin/users/<username>/2fa', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def reset_account_2fa(username):
    from pegaprox.api import users as core_users
    return core_users.admin_disable_2fa(username)


@bp.route('/api/vlab/admin/locked-users', methods=['GET'])
@require_auth(perms=['security.lockout.view'])
def locked_accounts():
    """Accounts locked after failed sign-ins: [{username, locked_until, remaining_seconds, attempt_count}]"""
    from pegaprox.api import users as core_users
    resp = core_users.get_locked_ips()
    ok, body = _core_ok(resp)
    if not ok:
        return resp
    return jsonify({'users': (body or {}).get('locked_users', [])})


@bp.route('/api/vlab/admin/locked-users/<username>', methods=['DELETE'])
@require_auth(perms=['security.lockout.manage'])
def unlock_account(username):
    from pegaprox.api import users as core_users
    return core_users.unlock_user(username)


@bp.route('/api/vlab/admin/permissions', methods=['GET'])
@require_auth()
def list_permissions():
    """[{permission, description, category, warning}] - the grid a role is ticked in"""
    from pegaprox.api import users as core_users
    return core_users.get_all_permissions()


@bp.route('/api/vlab/admin/roles', methods=['GET'])
@require_auth()
def list_roles():
    """Built-in and custom roles the caller may see: [{id, name, builtin, permissions, scope, tenant_id?}]"""
    from pegaprox.api import users as core_users
    return core_users.list_all_roles()


@bp.route('/api/vlab/admin/roles/templates', methods=['GET'])
@require_auth()
def list_role_templates():
    """[{id, name, description, permissions, permission_count}]"""
    from pegaprox.api import users as core_users
    return core_users.get_role_templates()


@bp.route('/api/vlab/admin/roles', methods=['POST'])
@require_auth(perms=['admin.roles'])
def create_role():
    """{id, name?, permissions[], tenant_id?}"""
    from pegaprox.api import users as core_users
    try:
        _only(_body(), _ROLE_KEYS + ('id',))
    except ValueError as e:
        return _bad(str(e))
    return core_users.create_custom_role()


@bp.route('/api/vlab/admin/roles/templates/<template_id>/apply', methods=['POST'])
@require_auth(perms=['admin.roles'])
def create_role_from_template(template_id):
    """{role_id?, name?, tenant_id?} - a new custom role with the template's permissions"""
    from pegaprox.api import users as core_users
    try:
        _only(_body(), ('role_id', 'name', 'tenant_id'))
    except ValueError as e:
        return _bad(str(e))
    return core_users.apply_role_template(template_id)


@bp.route('/api/vlab/admin/roles/<role_id>', methods=['PUT'])
@require_auth(perms=['admin.roles'])
def update_role(role_id):
    """{name?, permissions?, tenant_id?} - tenant_id says which tenant's role it is"""
    from pegaprox.api import users as core_users
    try:
        _only(_body(), _ROLE_KEYS)
    except ValueError as e:
        return _bad(str(e))
    return core_users.update_custom_role(role_id)


@bp.route('/api/vlab/admin/roles/<role_id>', methods=['DELETE'])
@require_auth(perms=['admin.roles'])
def delete_role(role_id):
    """?tenant_id= for a tenant's role; 409 with the holders while accounts still have it"""
    from pegaprox.api import users as core_users
    return core_users.delete_custom_role(role_id)


# --- sign-up requests --------------------------------------------------------------------

_SIGNUP_KEY = 'vlab_signup'
_USERNAME = re.compile(r'^[a-z0-9][a-z0-9._-]{2,31}$')
MAX_PENDING = 200
MAX_PENDING_PER_IP = 5


def _signup_settings():
    from pegaprox.api.helpers import load_server_settings
    saved = (load_server_settings() or {}).get(_SIGNUP_KEY) or {}
    return {'enabled': bool(saved.get('enabled', False))}


@bp.route('/api/vlab/signup/config', methods=['GET'])
def signup_config():
    """For the sign-in screen: whether to offer 가입 신청, and the departments to pick."""
    s = _signup_settings()
    deps = [{'id': d['id'], 'name': d['name'], 'parent_id': d['parent_id']} for d in catalog.list_departments()] if s['enabled'] else []
    return jsonify({'enabled': s['enabled'], 'departments': deps})


@bp.route('/api/vlab/signup', methods=['POST'])
def signup():
    """Ask for an account. An admin approves it under 사용자 > 가입 심사; approving gives no
    desktop by itself (pool rights are separate)."""
    from pegaprox.utils.auth import hash_password, load_users, validate_password_policy
    if not _signup_settings()['enabled']:
        return _bad('Sign-up is closed on this server', 403)
    data = _body()
    username = str(data.get('username') or '').strip().lower()
    if not _USERNAME.match(username):
        return _bad('username: 3-32 lower-case letters, digits, ".", "_" or "-", starting with a letter or digit')
    password = str(data.get('password') or '')
    ok, why = validate_password_policy(password)
    if not ok:
        return _bad(why)
    try:
        display = _text(data, 'display_name', 80) or username
        email = _text(data, 'email', 120)
        note = _text(data, 'note', 300)
    except ValueError as e:
        return _bad(str(e))
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return _bad('email is not valid')
    dep = str(data.get('department_id') or '').strip() or None
    if dep and not catalog.get_department(dep):
        return _bad('department_id: no such department')
    if username in load_users() or catalog.pending_signup_for(username):
        return _bad('This username is taken or already waiting for review', 409)
    ip = get_client_ip() or ''
    if catalog.count_pending() >= MAX_PENDING:
        return _bad('Too many requests are waiting - try again later', 429)
    if ip and sum(1 for s in catalog.list_signups('pending') if s['client_ip'] == ip) >= MAX_PENDING_PER_IP:
        return _bad('Too many requests from this address are waiting', 429)
    salt, pw_hash = hash_password(password)
    req = catalog.add_signup(username, display, email, dep, note, salt, pw_hash, ip)
    log_audit(username, 'vlab.signup.request', f"sign-up request {req['id']}", ip)
    return jsonify({'request': {'id': req['id'], 'status': req['status']}}), 201


@bp.route('/api/vlab/admin/signups', methods=['GET'])
@require_auth(perms=['admin.users'])
def list_signups():
    status = request.args.get('status') or None
    if status and status not in ('pending', 'approved', 'rejected'):
        return _bad('status must be pending, approved or rejected')
    return jsonify({'signups': catalog.list_signups(status), 'pending': catalog.count_pending()})


@bp.route('/api/vlab/admin/signups/<sid>/approve', methods=['POST'])
@require_auth(perms=['admin.users'])
def approve_signup(sid):
    from pegaprox.core.db import DEFAULT_TENANT_ID
    from pegaprox.models.permissions import ROLE_USER
    from pegaprox.utils.auth import load_users, save_users
    req = catalog.get_signup(sid, with_secret=True)
    if not req:
        return _bad('Request not found', 404)
    if req['status'] != 'pending':
        return _bad(f"This request is already {req['status']}", 409)
    users = load_users()
    if req['username'] in users:
        catalog.review_signup(sid, 'rejected', _user(), 'username taken meanwhile')
        return _bad('The username was taken meanwhile - the request is rejected', 409)
    stamp = datetime.now().isoformat()
    users[req['username']] = {
        'password_salt': req['password_salt'], 'password_hash': req['password_hash'], 'password_changed_at': stamp,
        'role': ROLE_USER, 'display_name': req['display_name'] or req['username'], 'email': req['email'], 'enabled': True,
        'created_at': stamp, 'last_login': None, 'tenant_id': DEFAULT_TENANT_ID, 'permissions': [], 'denied_permissions': [],
        'portal_only': True,
    }
    save_users(users)
    if req['department_id'] and catalog.get_department(req['department_id']):
        catalog.set_department(req['username'], req['department_id'])
    out = catalog.review_signup(sid, 'approved', _user())
    log_audit(_user(), 'user.created', f"Approved sign-up of {req['username']} (role: user, portal only)", get_client_ip())
    return jsonify({'signup': out})


@bp.route('/api/vlab/admin/signups/<sid>/reject', methods=['POST'])
@require_auth(perms=['admin.users'])
def reject_signup(sid):
    req = catalog.get_signup(sid)
    if not req:
        return _bad('Request not found', 404)
    if req['status'] != 'pending':
        return _bad(f"This request is already {req['status']}", 409)
    try:
        reason = _text(_body(), 'reason', 200)
    except ValueError as e:
        return _bad(str(e))
    out = catalog.review_signup(sid, 'rejected', _user(), reason)
    log_audit(_user(), 'vlab.signup.reject', f"sign-up of {req['username']} rejected" + (f': {reason}' if reason else ''), get_client_ip())
    return jsonify({'signup': out})


@bp.route('/api/vlab/admin/signup-settings', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_signup_settings():
    return jsonify({'signup': _signup_settings()})


@bp.route('/api/vlab/admin/signup-settings', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_signup_settings():
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    data = _body()
    if not isinstance(data.get('enabled'), bool):
        return _bad('enabled must be true or false')
    settings = load_server_settings() or {}
    settings[_SIGNUP_KEY] = {'enabled': data['enabled']}
    if not save_server_settings(settings):
        return _bad('Could not save the settings', 500)
    log_audit(_user(), 'vlab.signup.settings', f"sign-up {'open' if data['enabled'] else 'closed'}", get_client_ip())
    return jsonify({'signup': _signup_settings()})


# --- USB device library ------------------------------------------------------------------

def _usb_body():
    data = _body()
    name = _text(data, 'name', 80, required=True)
    vid = str(data.get('vid') or '').strip().lower()
    pid = str(data.get('pid') or '').strip().lower()
    if not catalog.HEX4.match(vid):
        raise ValueError('vid must be 4 hex digits')
    if pid and not catalog.HEX4.match(pid):
        raise ValueError('pid must be 4 hex digits, or empty for every device of the vendor')
    cat = str(data.get('category') or 'other')
    if cat not in catalog.USB_CATEGORIES:
        raise ValueError('category must be one of ' + ', '.join(catalog.USB_CATEGORIES))
    return name, vid, pid, cat, _text(data, 'notes', 300)


def _usb_refs():
    """How many pools name each library entry in their USB policy (settings.usb.devices)."""
    refs = {}
    for p in store.list_pools():
        for uid in ((p.get('settings') or {}).get('usb') or {}).get('devices') or []:
            refs[uid] = refs.get(uid, 0) + 1
    return refs


@bp.route('/api/vlab/admin/usb-devices', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_usb_devices():
    refs = _usb_refs()
    return jsonify({'devices': [dict(d, pools=refs.get(d['id'], 0)) for d in catalog.list_usb_devices()],
                    'categories': list(catalog.USB_CATEGORIES)})


@bp.route('/api/vlab/admin/usb-devices', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_usb_device():
    try:
        name, vid, pid, cat, notes = _usb_body()
    except ValueError as e:
        return _bad(str(e))
    if catalog.usb_device_by_ids(vid, pid):
        return _bad(f'{vid}:{pid or "*"} is already in the library', 409)
    dev = catalog.save_usb_device(None, name, vid, pid, cat, notes)
    log_audit(_user(), 'vlab.usb.create', f"USB {vid}:{pid or '*'} '{name}'", get_client_ip())
    return jsonify({'device': dev}), 201


@bp.route('/api/vlab/admin/usb-devices/<uid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_usb_device(uid):
    if not catalog.get_usb_device(uid):
        return _bad('Device not found', 404)
    try:
        name, vid, pid, cat, notes = _usb_body()
    except ValueError as e:
        return _bad(str(e))
    other = catalog.usb_device_by_ids(vid, pid)
    if other and other['id'] != uid:
        return _bad(f'{vid}:{pid or "*"} is already in the library', 409)
    dev = catalog.save_usb_device(uid, name, vid, pid, cat, notes)
    log_audit(_user(), 'vlab.usb.update', f"USB {vid}:{pid or '*'} '{name}'", get_client_ip())
    return jsonify({'device': dev})


@bp.route('/api/vlab/admin/usb-devices/<uid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_usb_device(uid):
    dev = catalog.get_usb_device(uid)
    if not dev:
        return _bad('Device not found', 404)
    if _usb_refs().get(uid):
        return _bad('Pools still use this device in their USB policy', 409)
    catalog.delete_usb_device(uid)
    log_audit(_user(), 'vlab.usb.delete', f"USB {dev['vid']}:{dev['pid'] or '*'} '{dev['name']}'", get_client_ip())
    return jsonify({'success': True})


# --- gateways ----------------------------------------------------------------------------

def _gateway_body():
    data = _body()
    kind = str(data.get('kind') or '')
    if kind not in catalog.GATEWAY_KINDS:
        raise ValueError('kind must be ' + ', '.join(catalog.GATEWAY_KINDS))
    key = data.get('secret_key')
    if key not in (None, ''):
        key = str(key).strip().lower()
        if kind != 'guacamole' or not re.match(r'^[0-9a-f]{32}$', key):
            raise ValueError('secret_key: 32 hex digits (the 128-bit key of guacamole-auth-json), Guacamole only')
    else:
        key = None
    return (_text(data, 'name', 80, required=True), kind, _host(data, 'address'),
            _int(data, 'port', 1, 65535, catalog.GATEWAY_KINDS[kind]), _text(data, 'notes', 300), data.get('enabled', True) is not False, key)


@bp.route('/api/vlab/admin/gateways', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_gateways():
    used = {}
    for e in catalog.list_external():
        if e['gateway_id']:
            used[e['gateway_id']] = used.get(e['gateway_id'], 0) + 1
    return jsonify({'gateways': [dict(g, external=used.get(g['id'], 0)) for g in catalog.list_gateways()],
                    'kinds': catalog.GATEWAY_KINDS})


@bp.route('/api/vlab/admin/gateways', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_gateway():
    try:
        args = _gateway_body()
    except ValueError as e:
        return _bad(str(e))
    gw = catalog.save_gateway(None, *args)
    log_audit(_user(), 'vlab.gateway.create', f"gateway '{gw['name']}' {gw['kind']} {gw['address']}:{gw['port']}", get_client_ip())
    return jsonify({'gateway': gw}), 201


@bp.route('/api/vlab/admin/gateways/<gid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_gateway(gid):
    if not catalog.get_gateway(gid):
        return _bad('Gateway not found', 404)
    try:
        args = _gateway_body()
    except ValueError as e:
        return _bad(str(e))
    gw = catalog.save_gateway(gid, *args)
    log_audit(_user(), 'vlab.gateway.update', f"gateway '{gw['name']}'", get_client_ip())
    return jsonify({'gateway': gw})


@bp.route('/api/vlab/admin/gateways/<gid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_gateway(gid):
    gw = catalog.get_gateway(gid)
    if not gw:
        return _bad('Gateway not found', 404)
    catalog.delete_gateway(gid)
    log_audit(_user(), 'vlab.gateway.delete', f"gateway '{gw['name']}' (external desktops on it go direct)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/gateways/<gid>/check', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def check_gateway(gid):
    gw = catalog.get_gateway(gid)
    if not gw:
        return _bad('Gateway not found', 404)
    if gid == catalog.BUILTIN_GUAC_ID:      # the bundled one: the engine reaches it inside compose
        ok, ms, err = _tcp_probe('guacamole', 8080)
    else:
        ok, ms, err = _tcp_probe(gw['address'], gw['port'])
    gw = catalog.mark_gateway(gid, ok, f'{ms} ms' if ok else err)
    return jsonify({'gateway': gw, 'ok': ok, 'ms': ms, 'error': err})


# --- external desktops -------------------------------------------------------------------

def _external_body():
    from pegaprox.utils.auth import load_users
    data = _body()
    user = str(data.get('assigned_user') or '').strip() or None
    if user and user not in load_users():
        raise ValueError('assigned_user: no such user')
    gw = str(data.get('gateway_id') or '').strip() or None
    if gw and not catalog.get_gateway(gw):
        raise ValueError('gateway_id: no such gateway')
    return (_text(data, 'name', 80, required=True), _host(data, 'address'), _int(data, 'port', 1, 65535, 3389),
            user, gw, _text(data, 'notes', 300))


@bp.route('/api/vlab/admin/external-desktops', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_external():
    return jsonify({'desktops': catalog.list_external()})


@bp.route('/api/vlab/admin/external-desktops', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_external():
    try:
        args = _external_body()
    except ValueError as e:
        return _bad(str(e))
    ext = catalog.save_external(None, *args)
    log_audit(_user(), 'vlab.external.create', f"external desktop '{ext['name']}' {ext['address']}:{ext['port']} -> {ext['assigned_user'] or '-'}", get_client_ip())
    return jsonify({'desktop': ext}), 201


@bp.route('/api/vlab/admin/external-desktops/<eid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_external(eid):
    if not catalog.get_external(eid):
        return _bad('External desktop not found', 404)
    try:
        args = _external_body()
    except ValueError as e:
        return _bad(str(e))
    ext = catalog.save_external(eid, *args)
    log_audit(_user(), 'vlab.external.update', f"external desktop '{ext['name']}' -> {ext['assigned_user'] or '-'}", get_client_ip())
    return jsonify({'desktop': ext})


@bp.route('/api/vlab/admin/external-desktops/<eid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_external(eid):
    ext = catalog.get_external(eid)
    if not ext:
        return _bad('External desktop not found', 404)
    catalog.delete_external(eid)
    log_audit(_user(), 'vlab.external.delete', f"external desktop '{ext['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/me/external', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external():
    return jsonify({'desktops': [{k: e[k] for k in ('id', 'name', 'address', 'port', 'notes')} for e in catalog.list_external(_user())]})


def rdp_file(ext, username):
    lines = [f"full address:s:{ext['address']}:{ext['port']}", f'username:s:{username}', 'prompt for credentials:i:1',
             'screen mode id:i:2', 'use multimon:i:1', 'redirectclipboard:i:1', 'audiomode:i:0', 'authentication level:i:2']
    gw = catalog.get_gateway(ext['gateway_id']) if ext.get('gateway_id') else None
    if gw and gw['enabled'] and gw['kind'] in ('rdpgw', 'msrdgw'):
        lines += [f"gatewayhostname:s:{gw['address']}:{gw['port']}", 'gatewayusagemethod:i:1', 'gatewaycredentialssource:i:4',
                  'gatewayprofileusagemethod:i:1']
    return '\r\n'.join(lines) + '\r\n'


@bp.route('/api/vlab/me/external/<eid>/rdp', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external_rdp(eid):
    ext = catalog.get_external(eid)
    if not ext or ext['assigned_user'] != _user():
        return _bad('External desktop not found', 404)
    log_audit(_user(), 'vlab.external.connect', f"RDP file for '{ext['name']}'", get_client_ip())
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', ext['name']).strip('-') or 'desktop'
    return jsonify({'filename': f'{safe}.rdp', 'rdp': rdp_file(ext, _user())})


# --- golden images -----------------------------------------------------------------------

GOLD_PREFIX = 'gold-'


def _versions(img):
    mgr = cluster_managers.get(img['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None
    try:
        snaps = mgr.get_snapshots(img['node'], int(img['vmid']), img['vm_type']) or []
    except Exception:
        return None
    out = [{'name': s.get('name'), 'description': s.get('description') or '', 'time': s.get('snaptime')}
           for s in snaps if isinstance(s, dict) and str(s.get('name') or '').startswith(GOLD_PREFIX)]
    return sorted(out, key=lambda v: v['time'] or 0, reverse=True)


def _golden_or_error(gid):
    img = catalog.get_golden(gid)
    if not img or not core._can_reach(img['cluster_id']):
        return None, _bad('Golden image not found', 404)
    return img, None


@bp.route('/api/vlab/admin/golden-images', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_golden():
    used = {}
    for p in store.list_pools():
        gid = (p.get('settings') or {}).get('golden_id')
        if gid:
            used.setdefault(gid, []).append(p['name'])
    out = []
    for img in catalog.list_golden():
        if not core._can_reach(img['cluster_id']):
            continue
        live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
        have = catalog.desktop_versions(img['id'])
        outdated = {}
        for p in store.list_pools():
            if (p.get('settings') or {}).get('golden_id') == img['id']:
                outdated[p['id']] = {'pool': p['name'], 'total': 0, 'outdated': 0}
                for d in store.list_desktops(p['id']):
                    outdated[p['id']]['total'] += 1
                    outdated[p['id']]['outdated'] += 1 if have.get(d['id']) != img['current_version'] else 0
        out.append(dict(img, versions=_versions(img), status=live.get('status') or 'unknown', pools=used.get(img['id'], []),
                        rollout=[dict(v, pool_id=k) for k, v in outdated.items()]))
    return jsonify({'images': out})


@bp.route('/api/vlab/admin/golden-images', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_golden():
    data = _body()
    cluster_id = str(data.get('cluster_id') or '')
    if not core._can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    try:
        vmid = _int(data, 'vmid', 100, 999999999)
        name = _text(data, 'name', 80)
        notes = _text(data, 'notes', 300)
    except ValueError as e:
        return _bad(str(e))
    vm = core._vm_states(cluster_id).get(vmid)
    if not vm:
        return _bad(f'Guest {vmid} not found on this cluster', 404)
    if vm.get('template'):
        return _bad('This guest is a template: use it from 템플릿 관리. A golden image is a normal VM you keep editing', 409)
    if (vm.get('type') or 'qemu') != 'qemu':
        return _bad('Golden images are virtual machines (QEMU) only')
    if catalog.golden_for_vm(cluster_id, vmid):
        return _bad('This VM is already a golden image', 409)
    if store.desktop_for_vm(cluster_id, vmid):
        return _bad('This VM is a desktop of a pool - take it out of the pool first', 409)
    img = catalog.add_golden(cluster_id, vm.get('node') or '', vmid, 'qemu', name or vm.get('name') or f'vm-{vmid}', notes, _user())
    log_audit(_user(), 'vlab.golden.create', f"golden image '{img['name']}' (qemu/{vmid})", get_client_ip())
    return jsonify({'image': img}), 201


@bp.route('/api/vlab/admin/golden-images/<gid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_golden(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    catalog.delete_golden(gid)
    envcat.delete(gid)
    log_audit(_user(), 'vlab.golden.delete', f"golden image '{img['name']}' (the VM and its snapshots are kept)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/golden-images/<gid>/versions', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def make_golden_version(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    try:
        desc = _text(_body(), 'description', 200)
    except ValueError as e:
        return _bad(str(e))
    mgr = cluster_managers.get(img['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
    node = live.get('node') or img['node']
    snap = GOLD_PREFIX + datetime.now().strftime('%Y%m%d-%H%M%S')
    r = mgr.create_snapshot(node, int(img['vmid']), img['vm_type'], snap, desc or 'MOAVI Desk golden image version')
    if not isinstance(r, dict) or not r.get('success'):
        return _bad(f"Snapshot failed: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    img = catalog.set_golden(gid, current_version=snap, node=node)
    log_audit(_user(), 'vlab.golden.version', f"golden image '{img['name']}': new version {snap}", get_client_ip())
    return jsonify({'image': img, 'version': snap}), 201


@bp.route('/api/vlab/admin/golden-images/<gid>/current', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_golden_current(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    version = str(_body().get('version') or '')
    versions = _versions(img)
    if versions is None:
        return _bad('Cluster not connected', 503)
    if version not in {v['name'] for v in versions}:
        return _bad('No such version of this image', 404)
    img = catalog.set_golden(gid, current_version=version)
    log_audit(_user(), 'vlab.golden.current', f"golden image '{img['name']}': deploys {version}", get_client_ip())
    return jsonify({'image': img})


@bp.route('/api/vlab/admin/golden-images/<gid>/deploy', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def deploy_golden(gid):
    """Full clones of the image's current version into a pool (a golden image is a normal VM,
    so its clones cannot be linked). New desktops start 'provisioning', as template clones do."""
    from pegaprox.api.helpers import acting_user
    from pegaprox.utils.rbac import TenantRangeUnknown, tenant_vmid_range
    img, err = _golden_or_error(gid)
    if err:
        return err
    if not img['current_version']:
        return _bad('Make a version of the image first', 409)
    data = _body()
    pool, err = core._pool_or_error(str(data.get('pool_id') or ''))
    if err:
        return err
    if pool['cluster_id'] != img['cluster_id']:
        return _bad('The pool is on another cluster than the image', 409)
    try:
        count = _int(data, 'count', 1, core.MAX_CLONES, 1)
        start_vmid = _int(data, 'start_vmid', 0, 999999999, 0)
    except ValueError as e:
        return _bad(str(e))
    prefix = str(data.get('name_prefix') or '').strip()
    if not core._NAME_OK.match(prefix):
        return _bad('name_prefix: letters, digits and "-", starting with a letter or digit (DNS name rules)')
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = core._vm_states(pool['cluster_id'])
    node = (live.get(int(img['vmid'])) or {}).get('node') or img['node']
    try:
        tenant_range = tenant_vmid_range((acting_user() or {}).get('tenant_id') or 'default')
    except TenantRangeUnknown:
        return _bad('Tenant settings unavailable - nothing created', 503)
    if not start_vmid and not tenant_range[0]:
        nxt = mgr.get_next_vmid()
        if isinstance(nxt, dict) and nxt.get('success'):
            start_vmid = int(nxt.get('vmid') or 0)
    vmids = core._free_vmids(pool['cluster_id'], count, start_vmid, tenant_range, live)
    if len(vmids) < count:
        return _bad(f'Only {len(vmids)} free VMIDs in range for {count} desktops', 409)
    taken = {d['name'] for d in store.list_desktops(pool['id'])}
    names, n = [], 1
    while len(names) < count:
        cand = f'{prefix}-{n:02d}'
        if cand not in taken:
            names.append(cand)
        n += 1
    created, failure = [], None
    for vmid, name in zip(vmids, names):
        r = mgr.clone_vm(node, int(img['vmid']), 'qemu', vmid, name=name, full=True, snapname=img['current_version'],
                         description=f"MOAVI Desk pool '{pool['name']}' from golden image '{img['name']}' {img['current_version']}")
        if not isinstance(r, dict) or not r.get('success'):
            failure = {'vmid': vmid, 'name': name, 'error': str((r or {}).get('error') if isinstance(r, dict) else r)[:300]}
            break
        desk = store.add_desktop(pool, node, vmid, name, 'qemu', state='provisioning')
        catalog.set_desktop_version(desk['id'], gid, img['current_version'])
        created.append({'id': desk['id'], 'vmid': vmid, 'name': name, 'task': r.get('data')})
    if created and (pool.get('settings') or {}).get('golden_id') != gid:
        store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, golden_id=gid))
    log_audit(_user(), 'vlab.golden.deploy', f"{len(created)}/{count} from golden image '{img['name']}' {img['current_version']} into pool '{pool['name']}'"
              + (f" - stopped at {failure['vmid']}: {failure['error'][:120]}" if failure else ''), get_client_ip())
    return jsonify({'created': created, 'failed': failure}), (201 if not failure else (207 if created else 502))


# --- board lab ---------------------------------------------------------------------------

BOARD_SLOT = 'usb4'     # the slot MOAVI Desk owns on a desktop VM (usb0-3 stay the admin's)
_USB_ID = re.compile(r'^([0-9a-f]{4}:[0-9a-f]{4}|\d+-\d+(\.\d+)*)$')


def _board_body():
    data = _body()
    cluster_id = str(data.get('cluster_id') or '')
    if not core._can_reach(cluster_id):
        raise LookupError('Cluster not found')
    usb = str(data.get('usb') or '').strip().lower()
    if not _USB_ID.match(usb):
        raise ValueError('usb: vendor:product (03fd:0008) or a port path (1-2.3)')
    node = _text(data, 'node', 64, required=True)
    return _text(data, 'name', 80, required=True), cluster_id, node, usb, _text(data, 'kind', 80), _text(data, 'notes', 300)


@bp.route('/api/vlab/admin/boards', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_boards():
    out = []
    for b in catalog.list_boards():
        if not core._can_reach(b['cluster_id']):
            continue
        desk = store.get_desktop(b['attached_desktop']) if b['attached_desktop'] else None
        out.append(dict(b, desktop=({'id': desk['id'], 'name': desk['name'], 'assigned_user': desk['assigned_user']} if desk else None)))
    return jsonify({'boards': out, 'slot': BOARD_SLOT})


@bp.route('/api/vlab/admin/boards', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def create_board():
    try:
        args = _board_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    b = catalog.save_board(None, *args)
    log_audit(_user(), 'vlab.board.create', f"board '{b['name']}' {b['node']} usb {b['usb']}", get_client_ip())
    return jsonify({'board': b}), 201


@bp.route('/api/vlab/admin/boards/<bid>', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def update_board(bid):
    old = catalog.get_board(bid)
    if not old or not core._can_reach(old['cluster_id']):
        return _bad('Board not found', 404)
    if old['attached_desktop']:
        return _bad('Detach the board before changing it', 409)
    try:
        args = _board_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    b = catalog.save_board(bid, *args)
    log_audit(_user(), 'vlab.board.update', f"board '{b['name']}'", get_client_ip())
    return jsonify({'board': b})


@bp.route('/api/vlab/admin/boards/<bid>', methods=['DELETE'])
@require_auth(perms=['vlab.accel.manage'])
def delete_board(bid):
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if b['attached_desktop']:
        return _bad('Detach the board first', 409)
    catalog.delete_board(bid)
    log_audit(_user(), 'vlab.board.delete', f"board '{b['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/boards/<bid>/attach', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def attach_board(bid):
    """Pass the board's USB device through to a desktop VM (slot usb4). The desktop must run
    on the node the board is plugged into."""
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if b['attached_desktop']:
        return _bad('The board is attached already - detach it first', 409)
    data = _body()
    desk = store.get_desktop(str(data.get('desktop_id') or ''))
    if not desk or desk['cluster_id'] != b['cluster_id']:
        return _bad('Desktop not found on the board\'s cluster', 404)
    lease_user = str(data.get('lease_user') or '').strip() or (desk['assigned_user'] or '')
    lease_until = str(data.get('lease_until') or '').strip() or None
    if lease_until:
        try:
            if datetime.fromisoformat(lease_until[:16]) <= datetime.now():
                return _bad('lease_until must be in the future')
            lease_until = lease_until[:16]
        except ValueError:
            return _bad('lease_until must look like 2026-10-20T18:00')
    if desk['vm_type'] != 'qemu':
        return _bad('USB passthrough needs a virtual machine (QEMU)')
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    node = live.get('node') or desk['node']
    if node != b['node']:
        return _bad(f"The desktop runs on {node}, the board is on {b['node']} - move the desktop first", 409)
    if any(o['attached_vmid'] == int(desk['vmid']) and o['cluster_id'] == desk['cluster_id'] for o in catalog.list_boards()):
        return _bad('Another board is attached to this desktop', 409)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    r = mgr.update_vm_config(node, int(desk['vmid']), 'qemu', {BOARD_SLOT: f"host={b['usb']}"})
    if not isinstance(r, dict) or not r.get('success'):
        return _bad(f"Could not attach: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    b = catalog.set_board_attachment(bid, desk['id'], desk['vmid'], _user(), lease_user, lease_until)
    log_audit(_user(), 'vlab.board.attach', f"board '{b['name']}' usb {b['usb']} -> {desk['name']} (qemu/{desk['vmid']})"
              + (f", lent to {lease_user} until {lease_until}" if lease_until else ''), get_client_ip())
    return jsonify({'board': b})


@bp.route('/api/vlab/admin/boards/<bid>/detach', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def detach_board(bid):
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if not b['attached_desktop']:
        return _bad('The board is not attached', 409)
    desk = store.get_desktop(b['attached_desktop'])
    if desk:
        mgr = cluster_managers.get(desk['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            return _bad('Cluster not connected', 503)
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        r = mgr.update_vm_config(live.get('node') or desk['node'], int(desk['vmid']), 'qemu', {'delete': BOARD_SLOT})
        if not isinstance(r, dict) or not r.get('success'):
            return _bad(f"Could not detach: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    b = catalog.set_board_attachment(bid, None, None, '')
    log_audit(_user(), 'vlab.board.detach', f"board '{b['name']}' from {desk['name'] if desk else 'a removed desktop'}", get_client_ip())
    return jsonify({'board': b})


# --- build farm --------------------------------------------------------------------------

@bp.route('/api/vlab/admin/buildfarm', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def buildfarm():
    """The build farm pools at a glance: desktops, how many are on and in use, their load."""
    busy = store.open_session_desktops()
    pools = []
    for p in store.list_pools():
        if p['type'] != 'buildfarm' or not core._can_reach(p['cluster_id']):
            continue
        live = core._vm_states(p['cluster_id'])
        desks = store.list_desktops(p['id'])
        rows, cpu, cpus, mem, maxmem = [], 0.0, 0, 0, 0
        for d in desks:
            v = live.get(int(d['vmid'])) or {}
            on = v.get('status') == 'running'
            used = bool(d['assigned_user']) or d['id'] in busy
            c = float(v.get('cpu') or 0) if on else 0.0
            rows.append({'id': d['id'], 'name': d['name'], 'status': v.get('status') or 'unknown', 'assigned_user': d['assigned_user'],
                         'in_session': d['id'] in busy, 'cpu': round(c * 100, 1), 'maxcpu': v.get('maxcpu'),
                         'mem': v.get('mem') if on else 0, 'maxmem': v.get('maxmem')})
            if on:
                cpu += c * float(v.get('maxcpu') or 1)
                cpus += int(v.get('maxcpu') or 1)
                mem += int(v.get('mem') or 0)
                maxmem += int(v.get('maxmem') or 0)
        running = sum(1 for r in rows if r['status'] == 'running')
        in_use = sum(1 for r in rows if r['assigned_user'] or r['in_session'])
        pools.append({'id': p['id'], 'name': p['name'], 'cluster_id': p['cluster_id'], 'total': len(rows), 'running': running,
                      'in_use': in_use, 'free': len(rows) - in_use, 'cpu_pct': round(100 * cpu / cpus, 1) if cpus else 0.0,
                      'mem_used': mem, 'mem_total': maxmem, 'desktops': rows})
    return jsonify({'pools': pools})


# --- licence servers ---------------------------------------------------------------------

def _license_body():
    data = _body()
    ports = data.get('ports')
    if isinstance(ports, str):
        ports = [p for p in re.split(r'[\s,]+', ports) if p]
    if not isinstance(ports, list) or not 1 <= len(ports) <= 10:
        raise ValueError('ports: 1 to 10 port numbers')
    try:
        ports = sorted({int(p) for p in ports})
    except (TypeError, ValueError):
        raise ValueError('ports must be numbers')
    if any(not 1 <= p <= 65535 for p in ports):
        raise ValueError('ports must be 1 to 65535')
    cluster_id = str(data.get('cluster_id') or '')
    vmid = data.get('vmid')
    if cluster_id or vmid not in (None, ''):
        if not core._can_reach(cluster_id):
            raise ValueError('cluster_id: cluster not found')
        vmid = _int(data, 'vmid', 100, 999999999)
    else:
        cluster_id, vmid = '', None
    mac = str(data.get('fixed_mac') or '').strip().lower()
    if mac and not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        raise ValueError('fixed_mac must look like 52:54:00:12:34:56')
    return (_text(data, 'name', 80, required=True), _host(data, 'host'), ports, cluster_id, vmid, mac, _text(data, 'notes', 300),
            data.get('watch', True) is not False)


def _license_view(s):
    out = dict(s)
    if s['cluster_id'] and s['vmid']:
        v = core._vm_states(s['cluster_id']).get(int(s['vmid'])) or {}
        out['vm_status'] = v.get('status') or 'unknown'
        out['vm_ha'] = bool(v.get('hastate'))
    return out


@bp.route('/api/vlab/admin/license-servers', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_license_servers():
    return jsonify({'servers': [_license_view(s) for s in catalog.list_license_servers()
                                if not s['cluster_id'] or core._can_reach(s['cluster_id'])],
                    'default_ports': [2100, 27000]})


@bp.route('/api/vlab/admin/license-servers', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def create_license_server():
    try:
        args = _license_body()
    except ValueError as e:
        return _bad(str(e))
    s = catalog.save_license_server(None, *args)
    log_audit(_user(), 'vlab.license.create', f"licence server '{s['name']}' {s['host']} ports {s['ports']}", get_client_ip())
    return jsonify({'server': s}), 201


@bp.route('/api/vlab/admin/license-servers/<lid>', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def update_license_server(lid):
    if not catalog.get_license_server(lid):
        return _bad('Licence server not found', 404)
    try:
        args = _license_body()
    except ValueError as e:
        return _bad(str(e))
    s = catalog.save_license_server(lid, *args)
    log_audit(_user(), 'vlab.license.update', f"licence server '{s['name']}'", get_client_ip())
    return jsonify({'server': s})


@bp.route('/api/vlab/admin/license-servers/<lid>', methods=['DELETE'])
@require_auth(perms=['vlab.accel.manage'])
def delete_license_server(lid):
    s = catalog.get_license_server(lid)
    if not s:
        return _bad('Licence server not found', 404)
    catalog.delete_license_server(lid)
    from pegaprox.vlab import license_usage
    license_usage.forget(lid)
    log_audit(_user(), 'vlab.license.delete', f"licence server '{s['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/license-servers/<lid>/check', methods=['POST'])
@require_auth(perms=['vlab.pool.view'])
def check_license_server(lid):
    """Does every licence port answer? (MOAVI Desk never reads or holds licence files.)"""
    s = catalog.get_license_server(lid)
    if not s or (s['cluster_id'] and not core._can_reach(s['cluster_id'])):
        return _bad('Licence server not found', 404)
    detail = []
    for port in s['ports']:
        ok, ms, err = _tcp_probe(s['host'], port)
        detail.append({'port': port, 'ok': ok, 'ms': ms, 'error': err})
    ok = bool(detail) and all(d['ok'] for d in detail)
    s = catalog.mark_license_server(lid, ok, detail)
    return jsonify({'server': _license_view(s), 'ok': ok})


# =========================================================================================
# Access and automation (docs/vlab-design.md 6-3, 7-1, 7-3, 9, 10-2, 10-4, 12 step 4)
#
#   GET/PUT /api/vlab/admin/pools/<id>/grants          {grants:[{subject_type, subject_id, include_children}], max_sessions?}
#   GET    /api/vlab/me/pools                           pools granted to the caller (claim / shared)    vlab.desk
#   POST   /api/vlab/me/pools/<id>/claim                a free desktop of the pool, assigned to the caller
#   POST   /api/vlab/me/pools/<id>/route                shared pool: the desktop to connect to now
#   GET    /api/vlab/me/external/<id>/guac              browser RDP (Guacamole) link for an external desktop
#   POST   /api/vlab/admin/golden-images/<id>/rollout   {pool_id, delete_old?} desktops of an older version -> current
#   GET    /api/vlab/admin/build-jobs, POST .../<id>/cancel; GET/POST /api/vlab/me/build-jobs
#   GET    /api/vlab/admin/reports/cards                ?days=30&format=csv card loans per card
# The minute loop (pegaprox/vlab/loans.py) also runs board_tick (due board loans) and
# license_tick (licence servers every 5 minutes, alerts on a change).
# =========================================================================================

MAX_SESSIONS_DEFAULT = 10


# --- pool grants -------------------------------------------------------------------------

def _user_groups(username):
    from pegaprox.core.db import get_db
    try:
        return {str(g).lower() for g in (get_db().get_user_directory_groups(username) or [])}
    except Exception:
        return set()


def granted(pool_id, username, grants=None, dep=None, groups=None):
    """Does a pool grant reach the user: by name, by department (and its sub-departments), or by directory group?"""
    grants = catalog.pool_grants(pool_id) if grants is None else grants
    if not grants:
        return False
    dep = catalog.department_of(username) if dep is None else dep
    for g in grants:
        if g['subject_type'] == 'user' and g['subject_id'] == username:
            return True
        if g['subject_type'] == 'department' and dep:
            if (dep == g['subject_id']) or (g['include_children'] and dep in catalog.descendants(g['subject_id'])):
                return True
        if g['subject_type'] == 'group':
            groups = _user_groups(username) if groups is None else groups
            if g['subject_id'].lower() in groups:
                return True
    return False


def shared_member(desk, username):
    """The core connect route asks this for a desktop not assigned to the caller: a shared pool's
    desktop is open to everyone the pool is granted to, and to whom a booking running now
    handed it (LAB > 예약)."""
    pool = store.get_pool(desk['pool_id']) or {}
    if pool.get('type') != 'shared':
        return False
    from pegaprox.api.vlab_reserve import reserved_desktop
    return granted(pool['id'], username) or reserved_desktop(desk, username)


def _max_sessions(pool):
    try:
        return max(1, min(500, int(((pool.get('settings') or {}).get('shared') or {}).get('max_sessions') or MAX_SESSIONS_DEFAULT)))
    except (TypeError, ValueError):
        return MAX_SESSIONS_DEFAULT


@bp.route('/api/vlab/admin/pools/<pool_id>/grants', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_grants(pool_id):
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    return jsonify({'grants': catalog.pool_grants(pool_id), 'max_sessions': _max_sessions(pool), 'types': list(catalog.GRANT_TYPES)})


@bp.route('/api/vlab/admin/pools/<pool_id>/grants', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_pool_grants(pool_id):
    from pegaprox.utils.auth import load_users
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    data = _body()
    rows = data.get('grants')
    if not isinstance(rows, list) or len(rows) > 500:
        return _bad('grants: a list of at most 500')
    users = load_users()
    clean = []
    for g in rows:
        if not isinstance(g, dict):
            return _bad('grants: objects with subject_type and subject_id')
        t, sid = str(g.get('subject_type') or ''), str(g.get('subject_id') or '').strip()
        if t not in catalog.GRANT_TYPES or not sid or len(sid) > 300:
            return _bad('subject_type must be user, department or group, with a subject_id')
        if t == 'user' and sid not in users:
            return _bad(f'No such user: {sid}')
        if t == 'department' and not catalog.get_department(sid):
            return _bad(f'No such department: {sid}')
        clean.append({'subject_type': t, 'subject_id': sid, 'include_children': g.get('include_children', True) is not False})
    if 'max_sessions' in data:
        try:
            ms = int(data['max_sessions'])
        except (TypeError, ValueError):
            return _bad('max_sessions must be a number')
        if not 1 <= ms <= 500:
            return _bad('max_sessions must be 1 to 500')
        settings = dict(pool.get('settings') or {})
        settings['shared'] = dict(settings.get('shared') or {}, max_sessions=ms)
        store.set_pool_settings(pool_id, settings)
    out = catalog.set_pool_grants(pool_id, clean)
    try:
        made = provision_granted(pool, [g['subject_id'] for g in clean if g['subject_type'] == 'user'])
        for u, why in made.items():
            if why:
                log_audit(_user(), 'vlab.storage.fail', f"pool '{pool['name']}': folders of {u} not made: {why}", get_client_ip())
    except Exception as e:
        logging.warning(f"[VLAB] shared storage folders on grant: {e}")
    log_audit(_user(), 'vlab.pool.grants', f"pool '{pool['name']}': {len(out)} grants "
              + ', '.join(f"{g['subject_type']}:{g['subject_id']}" for g in out[:10]), get_client_ip())
    return jsonify({'grants': out, 'max_sessions': _max_sessions(store.get_pool(pool_id))})


CLAIM_TYPES = ('dedicated', 'reset', 'buildfarm')


@bp.route('/api/vlab/me/pools', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_pools():
    """Pools granted to the caller: claim a desktop of a dedicated / reset / build farm pool, or
    connect to a shared pool (the engine picks its least busy desktop)."""
    username = _user()
    dep, groups = catalog.department_of(username), _user_groups(username)
    busy = store.open_session_desktops()
    envs, golden = envcat.all_envs(), {g['id']: g for g in catalog.list_golden()}
    by_pool = {}
    for g in catalog.pool_grants():
        by_pool.setdefault(g['pool_id'], []).append(g)
    out = []
    for pool in store.list_pools():
        if not pool.get('enabled', True) or not core._can_reach(pool['cluster_id']):
            continue
        if not granted(pool['id'], username, by_pool.get(pool['id'], []), dep, groups):
            continue
        desks = store.list_desktops(pool['id'])
        mine = [d for d in desks if d['assigned_user'] == username]
        free = [d for d in desks if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
        kind = 'shared' if pool['type'] == 'shared' else ('claim' if pool['type'] in CLAIM_TYPES else 'other')
        out.append({'id': pool['id'], 'name': pool['name'], 'type': pool['type'], 'description': pool.get('description', ''),
                    'action': kind, 'desktops': len(desks), 'free': len(free), 'mine': [d['id'] for d in mine],
                    'environment': envcat.portal_view(pool, envs, golden)})
    return jsonify({'pools': out})


@bp.route('/api/vlab/me/pools/<pool_id>/claim', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def claim_desktop(pool_id):
    username = _user()
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']) or not granted(pool_id, username):
        return _bad('Pool not found', 404)
    if not pool.get('enabled', True):
        return jsonify({'error': 'This pool is switched off', 'code': 'POOL_DISABLED'}), 409
    if pool['type'] not in CLAIM_TYPES:
        return _bad('Desktops of this pool are not handed out on request', 409)
    desks = store.list_desktops(pool_id)
    mine = next((d for d in desks if d['assigned_user'] == username), None)
    if mine:
        return jsonify({'desktop': {'id': mine['id'], 'name': mine['name']}, 'new': False})
    busy = store.open_session_desktops()
    free = [d for d in desks if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
    if not free:
        return jsonify({'error': 'Every desktop of this pool is taken', 'code': 'FULL'}), 409
    d = free[0]
    if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
        return _bad('VM access list unavailable - try again', 503)
    store.set_assignment(d['id'], username)
    log_audit(username, 'vlab.desktop.claim', f"{d['vm_type']}/{d['vmid']} '{d['name']}' from pool '{pool['name']}'", get_client_ip())
    return jsonify({'desktop': {'id': d['id'], 'name': d['name']}, 'new': True})


@bp.route('/api/vlab/me/pools/<pool_id>/route', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def route_shared(pool_id):
    """Shared pool: the running desktop with the fewest open sessions for its weight, under the
    pool's limit per desktop. The caller then connects to it like to their own desktop."""
    username = _user()
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']) or not granted(pool_id, username):
        return _bad('Pool not found', 404)
    if pool['type'] != 'shared':
        return _bad('Only shared pools are routed', 409)
    live = core._vm_states(pool['cluster_id'])
    weights = ((pool.get('settings') or {}).get('shared') or {}).get('weights') or {}
    counts = {}
    for s in store.open_sessions():
        counts[s['desktop_id']] = counts.get(s['desktop_id'], 0) + 1
    limit = _max_sessions(pool)
    best = None
    for d in store.list_desktops(pool_id):
        if (live.get(int(d['vmid'])) or {}).get('status') != 'running' or d.get('state') in ('provisioning', 'resetting', 'error'):
            continue
        n = counts.get(d['id'], 0)
        if n >= limit:
            continue
        try:
            w = max(1, int(weights.get(d['id'], 1)))
        except (TypeError, ValueError):
            w = 1
        key = (n / w, n, d['name'])
        if best is None or key < best[0]:
            best = (key, d)
    if not best:
        return jsonify({'error': 'Every desktop of this pool is full or off', 'code': 'FULL'}), 409
    d = best[1]
    if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
        return _bad('VM access list unavailable - try again', 503)
    out = {'desktop': {'id': d['id'], 'name': d['name']}, 'sessions': counts.get(d['id'], 0), 'limit': limit}
    st = storage_on_connect(d, pool, None, (live.get(int(d['vmid'])) or {}).get('node') or d['node'], username)
    if st:
        out['storage'] = st
    return jsonify(out)


# --- RDP files and Guacamole -------------------------------------------------------------

def _guest_ipv4(mgr, node, vmid):
    try:
        ips = mgr._fetch_qemu_ips(node, int(vmid)) or []
    except Exception:
        ips = []
    for ip in ips:
        ip = str(ip)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and not ip.startswith(('127.', '169.254.')):
            return ip
    return None


def _guac_gateway(pool=None):
    gid = ((pool or {}).get('settings') or {}).get('guac_gateway_id')
    for g in catalog.list_gateways(secret=True):
        if g['kind'] == 'guacamole' and g['enabled'] and g['secret_key'] and (not gid or g['id'] == gid):
            return g
    return None


def guac_link(gw, username, name, host, port, minutes=5):
    """A guacamole-auth-json login link: the JSON (one RDP connection) signed with HMAC-SHA256 and
    encrypted with AES-128-CBC (zero IV) under the gateway's 128-bit key, base64 in ?data=."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes.fromhex(gw['secret_key'])
    payload = _json.dumps({'username': username, 'expires': int((time.time() + minutes * 60) * 1000),
                           'connections': {name: {'protocol': 'rdp', 'parameters': {
                               'hostname': host, 'port': str(port), 'username': username,
                               'ignore-cert': 'true', 'security': 'any', 'resize-method': 'display-update'}}}},
                          separators=(',', ':')).encode()
    signed = hmac.new(key, payload, hashlib.sha256).digest() + payload
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16)).encryptor()
    data = enc.update(padder.update(signed) + padder.finalize()) + enc.finalize()
    q = _quote(base64.b64encode(data).decode())
    if gw['id'] == catalog.BUILTIN_GUAC_ID and has_request_context():
        # the bundled one sits behind the console's own address: use the name the user came in by
        return f"https://{request.host}/guacamole/?data={q}"
    scheme = 'http' if gw['port'] in (80, 8080) else 'https'
    return f"{scheme}://{gw['address']}:{gw['port']}/guacamole/?data={q}"


def desktop_rdp_answer(desk, mgr, node, vmid, username, protocol, pool):
    """The connect route's answer for rdp (an .rdp file) and guac (a browser RDP link).
    Returns (answer, None) or (None, error response)."""
    if desk['vm_type'] != 'qemu':
        return None, _bad('RDP needs a virtual machine (QEMU) with its guest agent')
    ip = _guest_ipv4(mgr, node, vmid)
    if not ip:
        return None, (jsonify({'error': 'The desktop has no address yet - is its guest agent running?', 'code': 'NO_IP'}), 409)
    port = 3389
    if protocol == 'rdp':
        ext = {'address': ip, 'port': port, 'gateway_id': ((pool or {}).get('settings') or {}).get('rdp_gateway_id')}
        return {'type': 'rdp', 'rdp': rdp_file(ext, username), 'filename': f"{desk['name']}.rdp"}, None
    gw = _guac_gateway(pool)
    if not gw:
        return None, (jsonify({'error': 'No browser RDP gateway (Guacamole with a key) is set up', 'code': 'NO_GATEWAY'}), 409)
    return {'type': 'guac', 'url': guac_link(gw, username, desk['name'], ip, port)}, None


@bp.route('/api/vlab/me/external/<eid>/guac', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external_guac(eid):
    ext = catalog.get_external(eid)
    if not ext or ext['assigned_user'] != _user():
        return _bad('External desktop not found', 404)
    gw = None
    if ext.get('gateway_id'):
        g = catalog.get_gateway(ext['gateway_id'], secret=True)
        if g and g['kind'] == 'guacamole' and g['enabled'] and g['secret_key']:
            gw = g
    gw = gw or _guac_gateway()
    if not gw:
        return jsonify({'error': 'No browser RDP gateway (Guacamole with a key) is set up', 'code': 'NO_GATEWAY'}), 409
    log_audit(_user(), 'vlab.external.connect', f"browser RDP to '{ext['name']}'", get_client_ip())
    return jsonify({'url': guac_link(gw, _user(), ext['name'], ext['address'], ext['port'])})


# --- golden image rollout ----------------------------------------------------------------

MAX_ROLLOUT = 20


@bp.route('/api/vlab/admin/golden-images/<gid>/rollout', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def rollout_golden(gid):
    """Bring a pool's desktops to the image's current version (design 6-3, method A): a new full
    clone per desktop, the user moved over (VM access too), the old desktop out of the pool.
    Desktops in a session now are left for the next run. With delete_old, a stopped old VM is deleted."""
    img, err = _golden_or_error(gid)
    if err:
        return err
    if not img['current_version']:
        return _bad('Make a version of the image first', 409)
    data = _body()
    pool, err = core._pool_or_error(str(data.get('pool_id') or ''))
    if err:
        return err
    if pool['cluster_id'] != img['cluster_id']:
        return _bad('The pool is on another cluster than the image', 409)
    delete_old = data.get('delete_old') is True
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    from pegaprox.api.helpers import acting_user
    from pegaprox.utils.rbac import TenantRangeUnknown, tenant_vmid_range
    versions = catalog.desktop_versions(gid)
    busy = store.open_session_desktops()
    todo, skipped = [], []
    for d in store.list_desktops(pool['id']):
        if versions.get(d['id']) == img['current_version']:
            continue
        if d['id'] in busy or d.get('state') in ('provisioning', 'resetting'):
            skipped.append(d['name'])
            continue
        todo.append(d)
    todo = todo[:MAX_ROLLOUT]
    if not todo:
        return jsonify({'replaced': [], 'skipped': skipped, 'failed': None})
    live = core._vm_states(pool['cluster_id'])
    node = (live.get(int(img['vmid'])) or {}).get('node') or img['node']
    try:
        tenant_range = tenant_vmid_range((acting_user() or {}).get('tenant_id') or 'default')
    except TenantRangeUnknown:
        return _bad('Tenant settings unavailable - nothing changed', 503)
    start = 0
    if not tenant_range[0]:
        nxt = mgr.get_next_vmid()
        if isinstance(nxt, dict) and nxt.get('success'):
            start = int(nxt.get('vmid') or 0)
    vmids = core._free_vmids(pool['cluster_id'], len(todo), start, tenant_range, live)
    replaced, failure = [], None
    for old, vmid in zip(todo, vmids):
        r = mgr.clone_vm(node, int(img['vmid']), 'qemu', vmid, name=old['name'], full=True, snapname=img['current_version'],
                         description=f"MOAVI Desk pool '{pool['name']}' from golden image '{img['name']}' {img['current_version']}")
        if not isinstance(r, dict) or not r.get('success'):
            failure = {'name': old['name'], 'error': str((r or {}).get('error') if isinstance(r, dict) else r)[:300]}
            break
        new = store.add_desktop(pool, node, vmid, old['name'], 'qemu', state='provisioning')
        catalog.set_desktop_version(new['id'], gid, img['current_version'])
        user = old['assigned_user']
        if user:
            core._acl_set(pool['cluster_id'], vmid, user, True)
            store.set_assignment(new['id'], user)
            core._acl_set(old['cluster_id'], old['vmid'], user, False)
        store.remove_desktop(old['id'])
        catalog.forget_desktop_version(old['id'])
        deleted = False
        if delete_old and (live.get(int(old['vmid'])) or {}).get('status') == 'stopped':
            dr = mgr.delete_vm(live.get(int(old['vmid']), {}).get('node') or old['node'], int(old['vmid']), old['vm_type'], purge=True)
            deleted = isinstance(dr, dict) and bool(dr.get('success'))
        replaced.append({'name': old['name'], 'old_vmid': old['vmid'], 'new_vmid': vmid, 'user': user, 'old_deleted': deleted})
    log_audit(_user(), 'vlab.golden.rollout', f"pool '{pool['name']}' -> {img['current_version']}: {len(replaced)} replaced, "
              f"{len(skipped)} in use" + (f", stopped at {failure['name']}" if failure else ''), get_client_ip())
    return jsonify({'replaced': replaced, 'skipped': skipped, 'failed': failure}), (200 if not failure else (207 if replaced else 502))


# --- board loans -------------------------------------------------------------------------

def _detach_board(b):
    """Take the board off its desktop. Returns an error text or None."""
    desk = store.get_desktop(b['attached_desktop']) if b['attached_desktop'] else None
    if desk:
        mgr = cluster_managers.get(desk['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            return 'cluster not connected'
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        r = mgr.update_vm_config(live.get('node') or desk['node'], int(desk['vmid']), 'qemu', {'delete': BOARD_SLOT})
        if not isinstance(r, dict) or not r.get('success'):
            return str((r or {}).get('error') if isinstance(r, dict) else r)[:200] or 'update failed'
    catalog.set_board_attachment(b['id'], None, None, '')
    return None


def board_tick(now_iso=None):
    """Detach the boards whose loan has ended (the minute loop). Returns (done, failed)."""
    from pegaprox.core import ha
    done = failed = 0
    for b in catalog.due_boards(now_iso or store.now()):
        if not ha.confirm_step(f"vLAB board loan end {b['id']}"):
            break
        err = _detach_board(b)
        if err:
            failed += 1
            logging.warning(f"[VLAB] board {b['name']} not detached at loan end: {err}")
        else:
            done += 1
            log_audit('system', 'vlab.board.return', f"board '{b['name']}': loan to {b['lease_user'] or '-'} ended", '')
    return done, failed


# --- licence server watch ----------------------------------------------------------------

LICENSE_EVERY = 300
_license_last = [0.0]


def _alert(title, text, data, channels=None):
    """Licence alerts go to the webhook channels (every one, or the ids in `channels`) and the
    alert mail recipients."""
    try:
        from pegaprox.utils.webhooks import send_to_channels
        send_to_channels(dict(data, title=title, message=text, source='moavi-desk', severity=data.get('severity', 'critical')), channels)
    except Exception as e:
        logging.warning(f'[VLAB] licence alert webhooks: {e}')
    try:
        from pegaprox.api.helpers import load_server_settings
        from pegaprox.utils.email import send_email
        rcpt = (load_server_settings() or {}).get('alert_email_recipients') or []
        if rcpt:
            send_email(rcpt, f'[MOAVI Desk] {title}', text, None)
    except Exception as e:
        logging.warning(f'[VLAB] licence alert mail: {e}')


def license_tick(force=False):
    """Check every watched licence server's ports (every 5 minutes); alert when one stops
    answering and again when it is back. Returns the number checked."""
    if not force and time.time() - _license_last[0] < LICENSE_EVERY:
        return 0
    _license_last[0] = time.time()
    n = 0
    for s in catalog.list_license_servers():
        if not s.get('watch', 1):
            continue
        detail = []
        for port in s['ports']:
            ok, ms, err = _tcp_probe(s['host'], port)
            detail.append({'port': port, 'ok': ok, 'ms': ms, 'error': err})
        ok = bool(detail) and all(d['ok'] for d in detail)
        was = s.get('last_ok')
        catalog.mark_license_server(s['id'], ok, detail)
        n += 1
        down = ', '.join(str(d['port']) for d in detail if not d['ok'])
        if not ok and not s.get('alerted_at'):
            _alert(f"라이선스 서버 응답 없음: {s['name']}", f"{s['name']} ({s['host']}) 포트 {down} 가 응답하지 않습니다.",
                   {'kind': 'license_down', 'server': s['name'], 'host': s['host'], 'ports': down})
            catalog.mark_license_alerted(s['id'], store.now())
            log_audit('system', 'vlab.license.down', f"licence server '{s['name']}' ports {down} not answering", '')
        elif ok and s.get('alerted_at'):
            _alert(f"라이선스 서버 복구: {s['name']}", f"{s['name']} ({s['host']}) 의 모든 포트가 다시 응답합니다.",
                   {'kind': 'license_up', 'server': s['name'], 'host': s['host'], 'severity': 'info'})
            catalog.mark_license_alerted(s['id'], None)
            log_audit('system', 'vlab.license.up', f"licence server '{s['name']}' answers again", '')
        elif ok and was is None:
            pass
    # the seats of the servers that read them (lmstat per feature, pegaprox/api/vlab_license.py)
    from pegaprox.api.vlab_license import usage_tick
    try:
        usage_tick()
    except Exception as e:
        logging.warning(f'[VLAB] licence seats: {e}')
    return n


# --- build job queue ---------------------------------------------------------------------

MAX_OUTPUT = 20000


def _agent(mgr, node, vmid, path):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{int(vmid)}/agent/{path}"


def _start_job(job, desk, mgr, node, as_user=None):
    """as_user: a job in the user's scratch folder runs as that user (their files, their uid on
    the NAS) and makes its own folder first."""
    wd = shlex.quote(job['workdir']) if job['workdir'] else ''
    cmd = job['command'] if not wd else (f"mkdir -p {wd} && cd {wd} && {job['command']}" if as_user else f"cd {wd} && {job['command']}")
    argv = ['/bin/bash', '-lc', cmd]
    if as_user:
        argv = ['runuser', '-u', as_user, '--'] + argv
    resp = mgr._api_post(_agent(mgr, node, desk['vmid'], 'exec'), data={'command': argv})
    if getattr(resp, 'status_code', 0) != 200:
        return None, (getattr(resp, 'text', '') or 'guest agent refused')[:300]
    try:
        pid = (resp.json().get('data') or {}).get('pid')
    except Exception:
        pid = None
    return pid, (None if pid else 'guest agent returned no pid')


def refresh_jobs(pool_id=None):
    """Bring the queue up to date: read the running jobs' state from the guest agent, then start
    queued jobs on free build VMs (running, unassigned, not in a session, no job). Runs when the
    job lists are read and when a job is sent."""
    for job in catalog.jobs_in('running', pool_id):
        desk = store.get_desktop(job['desktop_id']) if job['desktop_id'] else None
        mgr = cluster_managers.get(desk['cluster_id']) if desk else None
        if not desk or not mgr or not getattr(mgr, 'is_connected', False):
            continue
        node = (core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}).get('node') or desk['node']
        try:
            resp = mgr._api_get(_agent(mgr, node, desk['vmid'], 'exec-status'), params={'pid': job['pid']})
            st = (resp.json().get('data') or {}) if getattr(resp, 'status_code', 0) == 200 else {}
        except Exception:
            st = {}
        if st.get('exited'):
            code = st.get('exitcode')
            out = (st.get('out-data') or '')[-MAX_OUTPUT:]
            err = (st.get('err-data') or '')[-4000:]
            catalog.update_build_job(job['id'], status='done' if code in (0, None) else 'failed', exit_code=code,
                                     output=out, error=err, finished_at=store.now())
    for job in catalog.jobs_in('queued', pool_id):
        pool = store.get_pool(job['pool_id'])
        if not pool:
            catalog.update_build_job(job['id'], status='cancelled', error='pool removed', finished_at=store.now())
            continue
        mgr = cluster_managers.get(pool['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            continue
        live = core._vm_states(pool['cluster_id'])
        busy = store.open_session_desktops() | {j['desktop_id'] for j in catalog.jobs_in('running', pool['id'])}
        free = [d for d in store.list_desktops(pool['id'])
                if not d['assigned_user'] and d['id'] not in busy and d['vm_type'] == 'qemu'
                and (live.get(int(d['vmid'])) or {}).get('status') == 'running']
        if not free:
            continue
        d = free[0]
        node = (live.get(int(d['vmid'])) or {}).get('node') or d['node']
        st = storage_on_connect(d, pool, mgr, node, job['username'])
        cfg = storage_config(pool['id']) if st else None
        on_nas = bool(cfg and job['workdir'].startswith(cfg['linux_path'] + '/'))
        if on_nas and st['ok'] is False:
            # the job would start in a folder that is not there; say why instead
            catalog.update_build_job(job['id'], status='failed', desktop_id=d['id'], finished_at=store.now(),
                                     error=f"shared storage not ready on {d['name']}: {st['code']} {st['detail']}"[:300])
            continue
        scratch = _scratch_dir(pool, job['username'])
        mine = bool(on_nas and scratch and job['workdir'].startswith(scratch + '/'))
        pid, err = _start_job(job, d, mgr, node, as_user=nas.guest_name(job['username']) if mine else None)
        if err:
            catalog.update_build_job(job['id'], status='failed', desktop_id=d['id'], error=err, finished_at=store.now())
        else:
            catalog.update_build_job(job['id'], status='running', desktop_id=d['id'], pid=pid, started_at=store.now())
            log_audit(job['username'], 'vlab.build.start', f"build '{job['name']}' on {d['name']} (qemu/{d['vmid']})", '')


def _job_view(j):
    desk = store.get_desktop(j['desktop_id']) if j.get('desktop_id') else None
    pool = store.get_pool(j['pool_id'])
    return dict(j, desktop=desk['name'] if desk else None, pool=pool['name'] if pool else None)


def _add_job(pool, username, name, command, workdir):
    """A queued job; with no work folder and shared storage on, it gets scratch/<user>/<job id>."""
    job = catalog.add_build_job(pool['id'], username, name, command, workdir)
    base = '' if workdir else _scratch_dir(pool, username)
    return catalog.update_build_job(job['id'], workdir=f"{base}/{job['id']}") if base else job


def _job_body():
    data = _body()
    pool = store.get_pool(str(data.get('pool_id') or ''))
    if not pool or pool['type'] != 'buildfarm' or not core._can_reach(pool['cluster_id']):
        raise LookupError('Build farm pool not found')
    name = _text(data, 'name', 80, required=True)
    command = _text(data, 'command', 2000, required=True)
    workdir = _text(data, 'workdir', 300)
    return pool, name, command, workdir


@bp.route('/api/vlab/me/build-jobs', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_build_jobs():
    refresh_jobs()
    pools = [{'id': p['id'], 'name': p['name'], 'workdir': _scratch_dir(p, _user())} for p in store.list_pools()
             if p['type'] == 'buildfarm' and core._can_reach(p['cluster_id']) and granted(p['id'], _user())]
    return jsonify({'jobs': [_job_view(j) for j in catalog.list_build_jobs(username=_user(), limit=100)], 'pools': pools})


@bp.route('/api/vlab/me/build-jobs', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def submit_build_job():
    try:
        pool, name, command, workdir = _job_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    if not granted(pool['id'], _user()):
        return _bad('Build farm pool not found', 404)
    if len(catalog.jobs_in('queued')) >= 500:
        return _bad('The build queue is full', 429)
    job = _add_job(pool, _user(), name, command, workdir)
    log_audit(_user(), 'vlab.build.submit', f"build '{name}' to pool '{pool['name']}'", get_client_ip())
    refresh_jobs(pool['id'])
    return jsonify({'job': _job_view(catalog.get_build_job(job['id']))}), 201


def _cancel(job):
    if job['status'] != 'queued':
        return _bad('Only a queued job can be cancelled (a running build ends on its build VM)', 409)
    return jsonify({'job': _job_view(catalog.update_build_job(job['id'], status='cancelled', finished_at=store.now()))})


@bp.route('/api/vlab/me/build-jobs/<jid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def cancel_my_build_job(jid):
    job = catalog.get_build_job(jid)
    if not job or job['username'] != _user():
        return _bad('Job not found', 404)
    return _cancel(job)


@bp.route('/api/vlab/admin/build-jobs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_build_jobs():
    pool_id = request.args.get('pool_id') or None
    refresh_jobs(pool_id)
    jobs = catalog.list_build_jobs(pool_id=pool_id, limit=300)
    return jsonify({'jobs': [_job_view(j) for j in jobs],
                    'counts': {s: sum(1 for j in jobs if j['status'] == s) for s in catalog.JOB_STATES}})


@bp.route('/api/vlab/admin/build-jobs', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_submit_build_job():
    """Send a job on someone's behalf (or the admin's own)."""
    from pegaprox.utils.auth import load_users
    try:
        pool, name, command, workdir = _job_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    owner = str(_body().get('username') or '').strip() or _user()
    if owner not in load_users():
        return _bad('No such user')
    job = _add_job(pool, owner, name, command, workdir)
    log_audit(_user(), 'vlab.build.submit', f"build '{name}' for {owner} to pool '{pool['name']}'", get_client_ip())
    refresh_jobs(pool['id'])
    return jsonify({'job': _job_view(catalog.get_build_job(job['id']))}), 201


@bp.route('/api/vlab/admin/build-jobs/<jid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def cancel_build_job(jid):
    job = catalog.get_build_job(jid)
    if not job:
        return _bad('Job not found', 404)
    return _cancel(job)


# --- card usage report -------------------------------------------------------------------

@bp.route('/api/vlab/admin/reports/cards', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def card_report():
    """Loans per card over the last N days: how many, hours in the window, users, lent now."""
    from datetime import timedelta
    try:
        days = max(1, min(366, int(request.args.get('days') or 30)))
    except ValueError:
        return _bad('days must be a number')
    now = datetime.now()
    since = now - timedelta(days=days)
    parse = lambda s: datetime.fromisoformat(s[:19]) if s else None   # noqa: E731
    cards = {}
    for l in store.list_leases(active_only=False, limit=20000):
        start = parse(l['starts_at'])
        end = parse(l['returned_at']) or (now if l['state'] == 'active' else parse(l['ends_at']) or now)
        if not start or end < since:
            continue
        hours = max(0.0, (min(end, now) - max(start, since)).total_seconds() / 3600)
        key = l['resource_name'] or l['resource_id']
        c = cards.setdefault(key, {'card': key, 'resource_id': l['resource_id'], 'loans': 0, 'hours': 0.0, 'users': set(), 'active': 0})
        c['loans'] += 1
        c['hours'] += hours
        c['users'].add(l['username'])
        c['active'] += 1 if l['state'] == 'active' else 0
    rows = sorted(({**c, 'hours': round(c['hours'], 1), 'users': sorted(c['users']),
                    'use_pct': round(100 * c['hours'] / (days * 24), 1)} for c in cards.values()),
                  key=lambda r: -r['hours'])
    if request.args.get('format') == 'csv':
        from flask import Response
        lines = ['card,loans,hours,use_pct,users,lent_now']
        for r in rows:
            lines.append(','.join([_csv(r['card']), str(r['loans']), str(r['hours']), str(r['use_pct']), _csv(' '.join(r['users'])), str(r['active'])]))
        return Response('﻿' + '\n'.join(lines) + '\n', mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="card-usage-{days}d.csv"'})
    return jsonify({'days': days, 'cards': rows, 'total_hours': round(sum(r['hours'] for r in rows), 1)})


def _csv(v):
    v = str(v)
    return '"' + v.replace('"', '""') + '"' if any(ch in v for ch in ',"\n') else v


# --- VM build: the ISO library and new VMs (가상머신 > ISO · 이미지 관리, VM 만들기) -------
#
# The console speaks /api/vlab/* only (its README, 구조), and ISO upload, download from a
# URL and creating a VM from an ISO were core routes. These wrappers stay thin: each checks
# what the console may send, keeps it to ISOs and to the fields the wizard has, and hands
# the request on to the core route that does the work - so the core's permissions, its
# SSRF guard on URLs, the tenant quota and VMID range on a create, and its audit stay the
# one place they are. What the core has no route for (a VM's console outside a pool, turning
# a VM into a template, a task's progress) is a manager call here, gated like the core would.

_NODE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}')
_STORE_RE = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,63}')
_ISO_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,190}\.iso', re.I)
_BRIDGE_RE = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,15}')
_VM_NAME_RE = re.compile(r'[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?')
_CHECKSUM_ALGOS = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
# the task kinds this page follows: an ISO download, an upload, a create, a template
_BUILD_TASKS = ('download', 'imgcopy', 'qmcreate', 'qmtemplate')


def _build_target(cluster_id, node=None, storage=None):
    """The connected manager for the cluster, else the answer to give."""
    if not core._can_reach(cluster_id):
        return None, _bad('Cluster not found', 404)
    if node is not None and not _NODE_RE.fullmatch(node):
        return None, _bad('Invalid node')
    if storage is not None and not _STORE_RE.fullmatch(storage):
        return None, _bad('Invalid storage')
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, _bad('Cluster not connected', 503)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, _bad('Only Proxmox clusters build VMs here')
    return mgr, None


def _iso_volid(storage, volid):
    """A volid of an ISO on that storage, nothing else."""
    prefix = f'{storage}:iso/'
    return volid.startswith(prefix) and bool(_ISO_NAME_RE.fullmatch(volid[len(prefix):]))


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/isos', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'storage.view'])
def build_isos(cluster_id, node):
    """The ISOs a node sees (?storage= for one storage), newest first."""
    storage = request.args.get('storage') or None
    mgr, err = _build_target(cluster_id, node, storage)
    if err:
        return err
    rows = mgr.get_iso_list(node, storage) or []
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or not isinstance(r.get('volid'), str):
            continue
        vol = r['volid']
        out.append({'volid': vol, 'name': vol.split('/', 1)[-1], 'storage': r.get('storage') or vol.split(':', 1)[0],
                    'size': core._num(r.get('size')), 'ctime': core._num(r.get('ctime'))})
    out.sort(key=lambda x: (-x['ctime'], x['name']))
    return jsonify({'isos': out})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/storage/<storage>/upload', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'storage.upload'])
def build_upload_iso(cluster_id, node, storage):
    """multipart: file (an .iso), node (the same as the path). The core streams it on to
    the node; the request ends when the node has it."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node, storage)
    if err:
        return err
    if request.form.get('node') != node:
        return _bad('node: send the node of the path as a form field')
    if request.form.get('content', 'iso') != 'iso':
        return _bad('Only ISO images are uploaded here')
    f = request.files.get('file')
    if not f or not _ISO_NAME_RE.fullmatch(f.filename or ''):
        return _bad('file: an .iso with letters, digits, dot, dash, underscore or plus in its name')
    return core_vms.upload_to_datastore(cluster_id, storage)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/storage/<storage>/download-url', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'storage.download'])
def build_download_iso(cluster_id, node, storage):
    """{url, filename, content: 'iso', checksum?: 'sha256:<hex>'} - the node fetches the
    URL itself; the answer carries the task (upid) to follow."""
    from pegaprox.api import storage as core_storage
    _, err = _build_target(cluster_id, node, storage)
    if err:
        return err
    data = _body()
    url = data.get('url')
    if not isinstance(url, str) or not re.fullmatch(r'https?://\S{3,2000}', url):
        return _bad('url: an http or https address')
    if not isinstance(data.get('filename'), str) or not _ISO_NAME_RE.fullmatch(data['filename']):
        return _bad('filename: an .iso with letters, digits, dot, dash, underscore or plus in its name')
    if data.get('content', 'iso') != 'iso':
        return _bad('Only ISO images are downloaded here')
    checksum = data.get('checksum')
    if checksum not in (None, ''):
        algo, _, value = str(checksum).partition(':')
        if algo not in _CHECKSUM_ALGOS or not re.fullmatch(r'[0-9a-fA-F]{32,128}', value):
            return _bad(f"checksum: <algorithm>:<hex>, algorithm one of {', '.join(_CHECKSUM_ALGOS)}")
    if set(data) - {'url', 'filename', 'content', 'checksum'}:
        return _bad('Unknown field')
    return core_storage.download_from_url(cluster_id, node, storage)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/storage/<storage>/isos/<path:volid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage', 'storage.delete'])
def build_delete_iso(cluster_id, node, storage, volid):
    """Delete an ISO (?node= the node of the path); the core refuses while a VM still has it
    in a drive."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node, storage)
    if err:
        return err
    if not _iso_volid(storage, volid):
        return _bad('Only ISO images of this storage are deleted here')
    if request.args.get('node') != node:
        return _bad('node: send the node of the path as ?node=')
    return core_vms.delete_datastore_content(cluster_id, storage, volid)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/tasks/<path:upid>', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'storage.view'])
def build_task(cluster_id, node, upid):
    """How far a download, upload, create or template task is: {type, running, ok,
    exitstatus, percent, last}. Other kinds of task are not read here."""
    mgr, err = _build_target(cluster_id, node)
    if err:
        return err
    parts = upid.split(':')
    if len(parts) < 8 or parts[0] != 'UPID' or parts[1] != node or parts[5] not in _BUILD_TASKS:
        return _bad('Not a task of this page', 404)
    st = mgr.get_task_status(node, upid)
    if not isinstance(st, dict):
        return _bad('Task not found', 404)
    running = st.get('status') == 'running'
    out = {'type': parts[5], 'running': running, 'ok': (not running) and st.get('exitstatus') == 'OK',
           'exitstatus': None if running else str(st.get('exitstatus') or ''), 'percent': None, 'last': ''}
    log = mgr.get_task_log(node, upid, 50)
    lines = [ln for ln in (log.splitlines() if isinstance(log, str) else []) if ln.strip()]
    if lines:
        out['last'] = lines[-1][:300]
    for ln in reversed(lines):
        m = re.search(r'(\d{1,3}(?:\.\d+)?)\s*%', ln)
        if m:
            out['percent'] = min(100.0, float(m.group(1)))
            break
    if out['ok']:
        out['percent'] = 100.0
    return jsonify(out)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/networks', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.view'])
def build_networks(cluster_id, node):
    """The bridges (and SDN VNets) a new VM's network card can go on."""
    mgr, err = _build_target(cluster_id, node)
    if err:
        return err
    out = []
    for n in mgr.get_network_list(node) or []:
        if isinstance(n, dict) and isinstance(n.get('iface'), str):
            out.append({'iface': n['iface'], 'type': n.get('type') or '', 'comments': str(n.get('comments') or '').strip(),
                        'vlan_aware': str(n.get('bridge_vlan_aware') or n.get('vlanaware') or '') in ('1', 'True', 'true'),
                        'cidr': str(n.get('cidr') or '')})
    out.sort(key=lambda x: x['iface'])
    return jsonify({'networks': out})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nextid', methods=['GET'])
@require_auth(perms=['vlab.pool.manage', 'vm.create'])
def build_nextid(cluster_id):
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    r = mgr.get_next_vmid()
    if not isinstance(r, dict) or not r.get('success'):
        return _bad('Could not read the next free VMID', 502)
    return jsonify({'vmid': int(r['vmid'])})


def _whole(lo, hi):
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _flag(v):
    return isinstance(v, bool)


def _iso_ref(v):
    return isinstance(v, str) and _iso_volid(v.split(':', 1)[0], v)


# what the wizard sends, and what each may hold. The core writes several into drive strings
# (storage:size,..., bridge=..., <volid>,media=cdrom), so none may carry a comma or '='.
_CREATE_FIELDS = {
    'vmid': _whole(100, 999999999),
    'name': lambda v: isinstance(v, str) and bool(_VM_NAME_RE.fullmatch(v)),
    'ostype': lambda v: v in ('win11', 'win10', 'l26', 'other'),
    'iso': _iso_ref,
    'virtio_iso': _iso_ref,
    'sockets': _whole(1, 4),
    'cores': _whole(1, 128),
    'cpu': lambda v: v in ('host', 'x86-64-v2-AES', 'x86-64-v3', 'kvm64'),
    'memory': _whole(512, 4 * 1024 * 1024),
    'storage': lambda v: isinstance(v, str) and bool(_STORE_RE.fullmatch(v)),
    'disk_size': _whole(1, 65536),
    'disk_type': lambda v: v in ('scsi', 'virtio', 'sata'),
    'disk_discard': _flag,
    'disk_ssd': _flag,
    'disk_iothread': _flag,
    'scsihw': lambda v: v in ('virtio-scsi-single', 'virtio-scsi-pci'),
    'net_model': lambda v: v in ('virtio', 'e1000', 'e1000e', 'rtl8139'),
    'net_bridge': lambda v: isinstance(v, str) and bool(_BRIDGE_RE.fullmatch(v)),
    'net_tag': _whole(1, 4094),
    'net_firewall': _flag,
    'vga': lambda v: v in ('qxl', 'qxl2', 'std', 'virtio'),
    'agent': _flag,
    'bios': lambda v: v in ('seabios', 'ovmf'),
    'machine': lambda v: v in ('q35', 'pc'),
    'efi_storage': lambda v: isinstance(v, str) and bool(_STORE_RE.fullmatch(v)),
    'efi_pre_enroll': _flag,
    'tpm_storage': lambda v: isinstance(v, str) and bool(_STORE_RE.fullmatch(v)),
    'tpm_version': lambda v: v == 'v2.0',
    'onboot': _flag,
}


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/vms', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'vm.create'])
def build_create_vm(cluster_id, node):
    """A new VM from an ISO: the fields of _CREATE_FIELDS (name, ostype, iso, storage,
    disk_size and net_bridge required). Windows 11 needs UEFI with q35 and a TPM 2.0 state.
    The core creates it; the answer is the core's {success, vmid, task}."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    data = _body()
    unknown = sorted(set(data) - set(_CREATE_FIELDS))
    if unknown:
        return _bad(f"Unknown field: {', '.join(unknown)}")
    for key in ('name', 'ostype', 'iso', 'storage', 'disk_size', 'net_bridge'):
        if data.get(key) in (None, ''):
            return _bad(f'{key} is required')
    for key, ok in _CREATE_FIELDS.items():
        if data.get(key) is not None and not ok(data[key]):
            return _bad(f'Invalid {key}')
    if data['ostype'] == 'win11' and not (data.get('bios') == 'ovmf' and data.get('machine') == 'q35'
                                          and data.get('tpm_storage')):
        return _bad('Windows 11 needs UEFI (bios ovmf, machine q35) and a TPM 2.0 state (tpm_storage)')
    if data.get('vmid') is not None and data['vmid'] in core._vm_states(cluster_id):
        return _bad(f"VMID {data['vmid']} is taken", 409)
    return core_vms.create_vm_api(cluster_id, node)


def _build_vm(cluster_id, vmid):
    """The live guest for a VM-build call, else the answer to give."""
    vm = core._vm_states(cluster_id).get(vmid)
    if not vm:
        return None, _bad(f'VM {vmid} not found on this cluster', 404)
    if (vm.get('type') or 'qemu') != 'qemu':
        return None, _bad('Only virtual machines (QEMU)')
    if vm.get('template'):
        return None, _bad('This VM is a template', 409)
    return vm, None


@bp.route('/api/vlab/admin/clusters/<cluster_id>/vms/<int:vmid>/console', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'vm.console'])
def build_console(cluster_id, vmid):
    """noVNC to a VM being installed: {type: 'vnc', ws_path, password, node, name}. A
    stopped VM is started first (409 STARTING, ask again in a moment); one still locked by
    its create answers 409 BUSY."""
    from urllib.parse import quote

    from pegaprox.api.ha import standby_console_refusal
    from pegaprox.utils.auth import request_credential, resolve_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    from pegaprox.utils.realtime import create_ws_token

    refused = standby_console_refusal()
    if refused:
        return refused
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    vm, err = _build_vm(cluster_id, vmid)
    if err:
        return err
    user = resolve_authz_user(request.session)
    if not user or not user_can_access_vm(user, cluster_id, vmid, 'vm.console', 'qemu'):
        return _bad('Permission denied: vm.console', 403)
    node = vm.get('node') or ''
    if vm.get('status') != 'running':
        if vm.get('lock'):
            return jsonify({'error': f"The VM is locked ({vm.get('lock')}) - try again in a moment", 'code': 'BUSY'}), 409
        if not user_can_access_vm(user, cluster_id, vmid, 'vm.start', 'qemu'):
            return _bad('The VM is not running and you may not start it (vm.start)', 403)
        r = mgr.vm_action(node, vmid, 'qemu', 'start')
        if not isinstance(r, dict) or not r.get('success'):
            msg = str(r.get('error') if isinstance(r, dict) else r)[:200]
            return jsonify({'error': f'Start failed: {msg}', 'code': 'BUSY' if 'lock' in msg.lower() else 'START_FAILED'}), 409
        log_audit(_user(), 'vm.start', f"VM build: start qemu/{vmid} for its console", get_client_ip())
        return jsonify({'error': 'The VM is starting - connect again in a moment', 'code': 'STARTING'}), 409
    result = mgr.get_vnc_ticket(node, vmid, 'qemu')
    if not isinstance(result, dict) or not result.get('success'):
        return _bad(str(result.get('error', 'Console failed') if isinstance(result, dict) else 'Console failed'), 502)
    ws_token = create_ws_token(_user(), user.get('effective_role', user.get('role', 'viewer')), sid=request_credential()[0])
    ticket, port = result.get('ticket') or '', result.get('port') or ''
    ws_path = (f"/api/clusters/{quote(cluster_id, safe='')}/vms/{quote(str(node), safe='')}/"
               f"qemu/{vmid}/vncwebsocket?token={quote(ws_token, safe='')}")
    if ticket and port:
        # as on a desktop's connect: hand vncproxy's ticket/port on (PVE 9.1)
        ws_path += f"&pve_ticket={quote(str(ticket), safe='')}&pve_port={quote(str(port), safe='')}"
    log_audit(_user(), 'vm.console', f"VM build: console to qemu/{vmid}", get_client_ip())
    return jsonify({'type': 'vnc', 'ws_path': ws_path, 'password': ticket, 'node': node,
                    'name': vm.get('name') or f'vm-{vmid}'})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/vms/<int:vmid>/template', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'vm.template'])
def build_make_template(cluster_id, vmid):
    """Turn a finished, shut down VM into a template (템플릿 관리 clones from it). Not for a
    desktop of a pool or a golden image, which stay VMs."""
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    vm, err = _build_vm(cluster_id, vmid)
    if err:
        return err
    from pegaprox.api.vms import _require_vm_access
    denied = _require_vm_access(cluster_id, vmid, 'vm.template', 'qemu')   # per-VM ACLs, as the core routes
    if denied:
        return denied
    if vm.get('status') != 'stopped':
        return _bad('Shut the VM down first', 409)
    if store.desktop_for_vm(cluster_id, vmid):
        return _bad('This VM is a desktop of a pool', 409)
    if catalog.golden_for_vm(cluster_id, vmid):
        return _bad('This VM is a golden image - it stays a VM', 409)
    node = vm.get('node') or ''
    if not _NODE_RE.fullmatch(node):
        return _bad('The VM has no node', 502)
    resp = mgr._api_post(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{vmid}/template")
    if resp is None or getattr(resp, 'status_code', 0) != 200:
        return _bad(f"Proxmox refused: {str(getattr(resp, 'text', '') or '')[:200]}", 502)
    try:
        upid = (resp.json() or {}).get('data')
    except Exception:
        upid = None
    log_audit(_user(), 'vm.template', f"VM build: qemu/{vmid} ({vm.get('name') or ''}) made a template", get_client_ip())
    return jsonify({'success': True, 'vmid': vmid, 'task': upid})


# --- notices (플랫폼 설정 > 공지) -------------------------------------------------------
# The core broadcast banners (api/banners.py) with what the console asks of them: a start
# time, kept next to the list under its own key, and the audience everyone or the
# administrators (the core scope roles with the role admin). The core checks, limits and
# write lock are used as they are; a banner made elsewhere with another scope shows as
# audience 'other' and keeps its scope until the audience is set here.

BANNER_AUDIENCES = ('all', 'admins')
ADMIN_ROLE = 'admin'


def _banner_starts():
    from pegaprox.api import banners as bn
    from pegaprox.core.db import get_db
    try:
        raw = get_db().get_server_setting(bn.VLAB_STARTS_KEY, {})
    except Exception as e:
        logging.warning(f'[VLAB] notice start times unreadable: {e}')
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_banner_starts(starts):
    from pegaprox.api import banners as bn
    from pegaprox.core.db import get_db
    get_db().save_server_setting(bn.VLAB_STARTS_KEY, starts)


def _audience_of(b):
    if b.get('scope') == 'everyone':
        return 'all'
    if b.get('scope') == 'roles' and b.get('roles') == [ADMIN_ROLE]:
        return 'admins'
    return 'other'


def _not_started(start, now):
    from pegaprox.api import banners as bn
    try:
        return bool(start) and bn.parse_expiry(start) > now
    except ValueError:
        return False


def _notice(b, starts, now):
    from pegaprox.api import banners as bn
    start = starts.get(b['id'])
    expires, readable = bn._expiry(b)
    if not readable or (expires is not None and expires <= now):
        state = 'ended'
    elif _not_started(start, now):
        state = 'scheduled'
    else:
        state = 'running'
    return {'id': b['id'], 'text': b['text'], 'severity': b['severity'], 'audience': _audience_of(b),
            'starts_at': start or None, 'expires_at': b.get('expires_at'), 'rev': b['rev'], 'state': state,
            'created_at': b.get('created_at'), 'created_by': b.get('created_by'),
            'updated_at': b.get('updated_at'), 'updated_by': b.get('updated_by')}


def _notice_fields(data, current=None):
    """(core fields, start ISO or None, start given) from a request body over the current banner.
    Raises the core's _Refused."""
    from pegaprox.api import banners as bn
    merged = {k: current[k] for k in bn.FIELDS} if current else {}
    for k in ('text', 'severity', 'expires_at'):
        if k in data:
            merged[k] = data[k]
    if 'audience' in data or not current:
        audience = data.get('audience') or 'all'
        if audience not in BANNER_AUDIENCES:
            raise bn._Refused('audience is all or admins')
        if audience == 'all':
            merged.update(scope='everyone', tenants=[], roles=[])
        else:
            merged.update(scope='roles', tenants=[], roles=[ADMIN_ROLE])
    fields = bn._validated(merged, new_expiry=not current or 'expires_at' in data)
    start = None
    if data.get('starts_at'):
        try:
            start = bn.parse_expiry(data['starts_at'])
        except ValueError:
            raise bn._Refused('starts_at is an ISO 8601 time with a timezone, or empty')
        if fields['expires_at'] and start >= bn.parse_expiry(fields['expires_at']):
            raise bn._Refused('The notice must start before it ends')
    return fields, (bn._iso(start) if start else None), 'starts_at' in data


@bp.route('/api/vlab/banners', methods=['GET'])
@require_auth()
def my_notices():
    """The core's banners for the caller, less those that have not started yet."""
    from pegaprox.api import banners as bn
    resp = bn.list_my_banners()
    rows = (resp.get_json(silent=True) or {}).get('banners') or []
    starts, now = _banner_starts(), bn._now()
    out = []
    for b in rows:
        start = starts.get(b['id'])
        if _not_started(start, now):
            continue
        out.append(dict(b, starts_at=start or None))
    return jsonify({'banners': out})


@bp.route('/api/vlab/admin/banners', methods=['GET'])
@require_auth(perms=['admin.settings'])
def list_notices():
    from pegaprox.api import banners as bn
    refusal = bn._refuse_confined()
    if refusal:
        return refusal
    banners = bn.stored_banners()
    if banners is None:
        return _bad('The notices cannot be read right now', 503)
    starts, now = _banner_starts(), bn._now()
    return jsonify({'banners': [_notice(b, starts, now) for b in banners],
                    'limits': {'text': bn.TEXT_MAX, 'count': bn.MAX_BANNERS}})


@bp.route('/api/vlab/admin/banners', methods=['POST'])
@require_auth(perms=['admin.settings'])
def create_notice():
    import secrets
    from pegaprox.api import banners as bn
    refusal = bn._refuse_confined()
    if refusal:
        return refusal
    try:
        fields, start, _ = _notice_fields(_body())
    except bn._Refused as e:
        return _bad(str(e), e.status)
    user, now = _user(), bn._now()
    with bn._write_lock:
        banners = bn.stored_banners()
        if banners is None:
            return _bad('The notices cannot be read right now', 503)
        if len(banners) >= bn.MAX_BANNERS:
            return _bad(f'There are already {bn.MAX_BANNERS} notices - delete one first', 409)
        banner = dict(fields, id=secrets.token_hex(8), rev=1, created_at=bn._iso(now), created_by=user,
                      updated_at=bn._iso(now), updated_by=user)
        starts = _banner_starts()
        if start:
            starts[banner['id']] = start
        try:
            bn._save(banners + [banner])
            _save_banner_starts({k: v for k, v in starts.items() if k in {b['id'] for b in banners} | {banner['id']}})
        except Exception as e:
            logging.error(f'[VLAB] notice not saved: {e}')
            return _bad('The notice could not be saved', 500)
    log_audit(user, 'settings.banner_created', f"Notice {banner['id']} created ({banner['severity']}, "
              f"{_audience_of(banner)}{', from ' + start if start else ''}): {bn._preview(banner['text'])}", get_client_ip())
    return jsonify({'banner': _notice(banner, starts, now)}), 201


@bp.route('/api/vlab/admin/banners/<banner_id>', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def update_notice(banner_id):
    from pegaprox.api import banners as bn
    refusal = bn._refuse_confined()
    if refusal:
        return refusal
    data, user, now = _body(), _user(), bn._now()
    with bn._write_lock:
        banners = bn.stored_banners()
        if banners is None:
            return _bad('The notices cannot be read right now', 503)
        at = next((i for i, b in enumerate(banners) if b['id'] == banner_id), None)
        if at is None:
            return _bad('Notice not found', 404)
        current = banners[at]
        try:
            fields, start, start_given = _notice_fields(data, current)
        except bn._Refused as e:
            return _bad(str(e), e.status)
        starts = _banner_starts()
        if not start_given:
            start = starts.get(banner_id)
            if start and fields['expires_at'] and bn.parse_expiry(start) >= bn.parse_expiry(fields['expires_at']):
                return _bad('The notice must start before it ends')
        changed = [k for k in bn.FIELDS if fields[k] != current[k]]
        if start != starts.get(banner_id):
            changed.append('starts_at')
        if not changed:
            return jsonify({'banner': _notice(current, starts, now), 'changed': []})
        updated = dict(current, **fields, updated_at=bn._iso(now), updated_by=user)
        if 'text' in changed:
            updated['rev'] = current['rev'] + 1
        banners[at] = updated
        if start:
            starts[banner_id] = start
        else:
            starts.pop(banner_id, None)
        try:
            bn._save(banners)
            _save_banner_starts(starts)
        except Exception as e:
            logging.error(f'[VLAB] notice not saved: {e}')
            return _bad('The notice could not be saved', 500)
    log_audit(user, 'settings.banner_updated', f"Notice {banner_id} changed ({', '.join(changed)}): "
              f"{bn._preview(updated['text'])}", get_client_ip())
    return jsonify({'banner': _notice(updated, starts, now), 'changed': changed})


@bp.route('/api/vlab/admin/banners/<banner_id>', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def delete_notice(banner_id):
    from pegaprox.api import banners as bn
    refusal = bn._refuse_confined()
    if refusal:
        return refusal
    with bn._write_lock:
        banners = bn.stored_banners()
        if banners is None:
            return _bad('The notices cannot be read right now', 503)
        gone = next((b for b in banners if b['id'] == banner_id), None)
        if gone is None:
            return _bad('Notice not found', 404)
        starts = _banner_starts()
        starts.pop(banner_id, None)
        try:
            bn._save([b for b in banners if b['id'] != banner_id])
            _save_banner_starts(starts)
        except Exception as e:
            logging.error(f'[VLAB] notice not deleted: {e}')
            return _bad('The notice could not be deleted', 500)
    log_audit(_user(), 'settings.banner_deleted', f"Notice {banner_id} deleted: {bn._preview(gone['text'])}",
              get_client_ip())
    return jsonify({'success': True})


# --- 가상머신 > 데스크톱(VM) 관리: settings, snapshots, migration, template, delete, console -----
#
# Thin wrappers over the core VM routes (pegaprox/api/vms.py: config, disks, networks,
# snapshots, migrate, DELETE, vnc). They are here, under /api/vlab/admin/desktops/<id>/...,
# because the console only speaks /api/vlab/* (README of makus-vlab-console, 구조), and a pool
# desktop is more than its VM: deleting it or making it a template takes it out of the pool
# store (vlab_desktops) and off the VM ACL, a migration moves the node the store keeps, and the
# desktop's base snapshot is what a reset goes back to. (The VM-build routes above make a
# template of a VM that is no desktop; this one does it for a desktop and takes it out.) Every one of these is a request an
# administrator makes and waits for - no background step, so nothing here asks ha.confirm_step;
# the calls go through the manager's guarded exits like the core routes do.

_VM_NAME_OK = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$')
_DISK_KEY = re.compile(r'^(?:scsi|virtio|sata|ide)\d{1,2}$|^(?:rootfs|mp\d{1,3})$')
_NET_KEY = re.compile(r'^net\d{1,2}$')
_UPID = re.compile(r'^UPID:([A-Za-z0-9-]{1,63}):[^/?#%\s]{1,400}$')
_PASSTHROUGH = re.compile(r'^(?:hostpci\d+|usb\d+)$')


def _desk_vm(desktop_id):
    """(desk, mgr, live vm, node) or an error answer as the 5th item."""
    desk = store.get_desktop(desktop_id)
    if not desk or not core._can_reach(desk['cluster_id']):
        return None, None, None, None, _bad('Desktop not found', 404)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return desk, None, None, None, _bad('Cluster not connected', 503)
    vm = core._vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return desk, mgr, None, None, _bad("The desktop's VM is not on the cluster any more", 404)
    return desk, mgr, vm, vm.get('node') or desk['node'], None


def _failed(r, what):
    if isinstance(r, dict) and r.get('success'):
        return None
    err = r.get('error') if isinstance(r, dict) else None
    return _bad(str(err or f'{what} failed')[:300], 502)


def _raw_config(mgr, node, desk):
    r = mgr.get_vm_config(node, int(desk['vmid']), desk['vm_type'])
    if not isinstance(r, dict) or not r.get('success'):
        return None
    cfg = r.get('config') or {}
    return cfg.get('raw') if isinstance(cfg.get('raw'), dict) else {}


def _passthrough(raw):
    """The devices that tie the VM to its node: PCI (GPU, vGPU) and host USB. A USB slot
    that only redirects over SPICE does not."""
    out = []
    for k, v in sorted((raw or {}).items()):
        if _PASSTHROUGH.match(k) and not (k.startswith('usb') and str(v).startswith('spice')):
            out.append({'key': k, 'value': str(v)[:120]})
    return out


def _size_gb(size):
    m = re.match(r'^\s*([0-9.]+)\s*([KMGT]?)', str(size or ''), re.I)
    if not m:
        return 0
    n = float(m.group(1))
    return round(n * {'': 1 / 1024 ** 3, 'K': 1 / 1024 ** 2, 'M': 1 / 1024, 'G': 1, 'T': 1024}[m.group(2).upper()], 1)


def _vm_view(desk, vm, node, raw):
    disks, nets = [], []
    for k, v in sorted(raw.items()):
        v = str(v)
        if _DISK_KEY.match(k):
            if 'media=cdrom' in v:
                continue
            opts = dict(p.split('=', 1) for p in v.split(',')[1:] if '=' in p)
            vol = v.split(',')[0]
            disks.append({'key': k, 'storage': vol.split(':')[0] if ':' in vol else '', 'volume': vol,
                          'size_gb': _size_gb(opts.get('size'))})
        elif _NET_KEY.match(k):
            parts = v.split(',')
            opts = dict(p.split('=', 1) for p in parts if '=' in p)
            model = parts[0].split('=')[0] if parts else ''
            mac = parts[0].split('=', 1)[1] if parts and '=' in parts[0] else opts.get('hwaddr', '')
            nets.append({'key': k, 'model': opts.get('name', model) if desk['vm_type'] == 'lxc' else model,
                         'mac': mac, 'bridge': opts.get('bridge', ''), 'tag': int(opts['tag']) if str(opts.get('tag', '')).isdigit() else None,
                         'firewall': opts.get('firewall') == '1'})
    return {
        'vmid': int(desk['vmid']), 'type': desk['vm_type'], 'node': node, 'name': raw.get('name') or raw.get('hostname') or desk['name'],
        'status': vm.get('status') or 'unknown', 'lock': raw.get('lock') or vm.get('lock') or '',
        'cores': int(raw.get('cores') or 1), 'sockets': int(raw.get('sockets') or 1), 'memory_mb': int(raw.get('memory') or 512),
        'cpu': str(raw.get('cpu') or ''), 'ostype': str(raw.get('ostype') or ''),
        'disks': disks, 'networks': nets, 'passthrough': _passthrough(raw),
    }


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def desktop_vm(desktop_id):
    """The desktop's VM as configured, with what the settings forms choose from: the node's
    bridges and disk storages, and the online nodes it could move to."""
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    raw = _raw_config(mgr, node, desk)
    if raw is None:
        return _bad('Could not read the VM config', 502)
    view = _vm_view(desk, vm, node, raw)
    bridges = []
    try:
        for n in mgr.get_network_list(node) or []:
            name = n.get('iface') or n.get('name') if isinstance(n, dict) else None
            if name and name not in bridges:
                bridges.append(str(name))
    except Exception as e:
        logging.debug(f'[VLAB] bridges of {node}: {e}')
    storages = []
    try:
        for s in mgr.get_storage_list(node) or []:
            if isinstance(s, dict) and 'images' in str(s.get('content', '')).split(',') and s.get('active', 1):
                storages.append({'storage': s.get('storage'), 'type': s.get('type', ''),
                                 'avail': int(s.get('avail') or 0), 'shared': bool(s.get('shared'))})
    except Exception as e:
        logging.debug(f'[VLAB] storages of {node}: {e}')
    targets = []
    try:
        status = mgr.get_node_status() or {}
        for name, s in sorted(status.items() if isinstance(status, dict) else []):
            if name != node and isinstance(s, dict):
                targets.append({'node': name, 'online': not s.get('offline') and s.get('status') == 'online',
                                'maintenance': bool(s.get('maintenance_mode'))})
    except Exception as e:
        logging.debug(f'[VLAB] nodes of {desk["cluster_id"]}: {e}')
    view.update({'desktop_id': desk['id'], 'pool_id': desk['pool_id'], 'base_snap': desk.get('base_snap') or '',
                 'bridges': bridges, 'storages': storages, 'targets': targets})
    return jsonify({'vm': view})


def _vm_change(desk, vm, what):
    """Running VMs take a CPU/memory/NIC change on the next start: say so."""
    log_audit(_user(), 'vlab.desktop.vm', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}': {what}", get_client_ip())
    return jsonify({'success': True, 'needs_restart': vm.get('status') == 'running'})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm/hardware', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_vm_hardware(desktop_id):
    """{cores?, sockets?, memory_mb?} - vCPUs and memory."""
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = _body()
    upd = {}
    try:
        if data.get('cores') not in (None, ''):
            upd['cores'] = _int(data, 'cores', 1, 256)
        if data.get('sockets') not in (None, '') and desk['vm_type'] == 'qemu':
            upd['sockets'] = _int(data, 'sockets', 1, 8)
        if data.get('memory_mb') not in (None, ''):
            upd['memory'] = _int(data, 'memory_mb', 256, 4 * 1024 * 1024)
    except ValueError as e:
        return _bad(str(e))
    if not upd:
        return _bad('Nothing to change')
    e = _failed(mgr.update_vm_config(node, int(desk['vmid']), desk['vm_type'], upd), 'config update')
    if e:
        return e
    return _vm_change(desk, vm, ', '.join(f'{k}={v}' for k, v in upd.items()))


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm/disks/<disk>/resize', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_vm_disk_grow(desktop_id, disk):
    """{grow_gb} - a disk only grows (PVE cannot shrink one)."""
    if not _DISK_KEY.match(disk):
        return _bad('Unknown disk')
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    try:
        grow = _int(_body(), 'grow_gb', 1, 16384)
    except ValueError as e:
        return _bad(str(e))
    e = _failed(mgr.resize_vm_disk(node, int(desk['vmid']), desk['vm_type'], disk, f'+{grow}G'), 'resize')
    if e:
        return e
    log_audit(_user(), 'vlab.desktop.vm', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}': {disk} +{grow}G", get_client_ip())
    return jsonify({'success': True, 'needs_restart': False})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm/disks', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_vm_disk_add(desktop_id):
    """{storage, size_gb} - a new SCSI disk in the next free slot (QEMU)."""
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    if desk['vm_type'] != 'qemu':
        return _bad('Disks are added to QEMU VMs only')
    data = _body()
    storage = str(data.get('storage') or '').strip()
    if not _STORE_RE.fullmatch(storage):
        return _bad('storage is required')
    try:
        size = _int(data, 'size_gb', 1, 16384)
    except ValueError as e:
        return _bad(str(e))
    raw = _raw_config(mgr, node, desk)
    if raw is None:
        return _bad('Could not read the VM config', 502)
    slot = next((f'scsi{i}' for i in range(31) if f'scsi{i}' not in raw), None)
    if not slot:
        return _bad('No free SCSI slot', 409)
    e = _failed(mgr.add_disk(node, int(desk['vmid']), 'qemu', {'storage': storage, 'size': str(size), 'disk_id': slot}), 'add disk')
    if e:
        return e
    log_audit(_user(), 'vlab.desktop.vm', f"qemu/{desk['vmid']} '{desk['name']}': {slot} {size}G on {storage}", get_client_ip())
    return jsonify({'success': True, 'disk': slot, 'needs_restart': False})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm/networks/<net>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_vm_network(desktop_id, net):
    """{bridge, tag|null} - the NIC keeps its model, MAC and firewall flag."""
    if not _NET_KEY.match(net):
        return _bad('Unknown network device')
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = _body()
    bridge = str(data.get('bridge') or '').strip()
    if not _BRIDGE_RE.fullmatch(bridge):
        return _bad('bridge is required')
    tag = None
    if data.get('tag') not in (None, ''):
        try:
            tag = _int(data, 'tag', 1, 4094)
        except ValueError as e:
            return _bad(str(e))
    raw = _raw_config(mgr, node, desk)
    if raw is None:
        return _bad('Could not read the VM config', 502)
    cur = next((n for n in _vm_view(desk, vm, node, raw)['networks'] if n['key'] == net), None)
    if not cur:
        return _bad('Unknown network device', 404)
    cfg = {'bridge': bridge, 'tag': tag, 'firewall': cur['firewall'], 'macaddr': cur['mac']}
    if desk['vm_type'] == 'qemu':
        cfg['model'] = cur['model'] or 'virtio'
    else:
        cfg['name'] = cur['model'] or 'eth0'
    e = _failed(mgr.update_network(node, int(desk['vmid']), desk['vm_type'], net, cfg), 'network update')
    if e:
        return e
    return _vm_change(desk, vm, f"{net} bridge={bridge} vlan={tag or '-'}")


# snapshots

@bp.route('/api/vlab/admin/desktops/<desktop_id>/snapshots', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def desktop_snapshots(desktop_id):
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    out = []
    for s in mgr.get_snapshots(node, int(desk['vmid']), desk['vm_type']) or []:
        if not isinstance(s, dict) or s.get('name') in (None, 'current'):
            continue
        out.append({'name': s['name'], 'description': str(s.get('description') or ''), 'time': s.get('snaptime'),
                    'vmstate': bool(s.get('vmstate')), 'parent': s.get('parent') or '',
                    'base': s['name'] == (desk.get('base_snap') or '')})
    out.sort(key=lambda s: s['time'] or 0, reverse=True)
    return jsonify({'snapshots': out, 'running': vm.get('status') == 'running'})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/snapshots', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_snapshot_take(desktop_id):
    """{name, description?, vmstate?} - vmstate keeps the RAM of a running VM too."""
    from pegaprox.utils.sanitization import validate_snapshot_name
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = _body()
    name = str(data.get('name') or '').strip()
    if not _VM_NAME_OK.match(name) or not name[0].isalpha() or not validate_snapshot_name(name) or name == 'current':
        return _bad('name: letters, digits, "-", "_" and ".", starting with a letter (at most 40)')
    if name == core.BASE_SNAP:
        return _bad(f"'{core.BASE_SNAP}' is the base snapshot - take it from the pool's desktop list")
    try:
        description = _text(data, 'description', 200)
    except ValueError as e:
        return _bad(str(e))
    vmstate = bool(data.get('vmstate')) and desk['vm_type'] == 'qemu' and vm.get('status') == 'running'
    if vmstate:
        held = _passthrough(_raw_config(mgr, node, desk))
        if held:
            # PVE refuses it, and a rollback would restore device state the card no longer has
            return jsonify({'error': 'A snapshot with RAM is not possible with a passthrough device ('
                            + ', '.join(h['key'] for h in held) + ') - take it without RAM', 'code': 'PASSTHROUGH_RAM'}), 409
    e = _failed(mgr.create_snapshot(node, int(desk['vmid']), desk['vm_type'], name, description, vmstate), 'snapshot')
    if e:
        return e
    log_audit(_user(), 'vlab.desktop.snapshot', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}': took '{name}'"
              + (' with RAM' if vmstate else ''), get_client_ip())
    return jsonify({'success': True, 'name': name}), 201


def _snap_name(name):
    from pegaprox.utils.sanitization import validate_snapshot_name
    return name if name != 'current' and validate_snapshot_name(name) else None


@bp.route('/api/vlab/admin/desktops/<desktop_id>/snapshots/<name>/rollback', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_snapshot_rollback(desktop_id, name):
    """Back to the snapshot: what was done since is gone. Refused while someone is connected
    unless {force}."""
    if not _snap_name(name):
        return _bad('Invalid snapshot name')
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    if not bool(_body().get('force')) and desk['id'] in store.open_session_desktops():
        return jsonify({'error': 'Someone is connected to this desktop', 'code': 'IN_USE'}), 409
    e = _failed(mgr.rollback_snapshot(node, int(desk['vmid']), desk['vm_type'], name), 'rollback')
    if e:
        return e
    log_audit(_user(), 'vlab.desktop.snapshot', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}': back to '{name}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/snapshots/<name>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_snapshot_delete(desktop_id, name):
    """The base snapshot is what a reset goes back to: deleting it also clears it on the
    desktop (the pool's list then offers to take a new one)."""
    if not _snap_name(name):
        return _bad('Invalid snapshot name')
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    e = _failed(mgr.delete_snapshot(node, int(desk['vmid']), desk['vm_type'], name), 'delete snapshot')
    if e:
        return e
    if name == (desk.get('base_snap') or ''):
        store.set_base_snap(desk['id'], '')
    log_audit(_user(), 'vlab.desktop.snapshot', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}': deleted '{name}'", get_client_ip())
    return jsonify({'success': True})


# migration

@bp.route('/api/vlab/admin/desktops/<desktop_id>/migrate', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_migrate(desktop_id):
    """{target, online?} - to another node of the cluster. A VM with a PCI (GPU, vGPU) or host
    USB device stays where its device is: refused with the devices (code PASSTHROUGH)."""
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = _body()
    target = str(data.get('target') or '').strip()
    if not _NODE_RE.fullmatch(target):
        return _bad('target is required')
    if target == node:
        return _bad('The VM is already on that node')
    if vm.get('lock'):
        return _bad(f"The VM is busy ({vm['lock']}) - try again shortly", 409)
    raw = _raw_config(mgr, node, desk)
    if raw is None:
        return _bad('Could not read the VM config', 502)
    held = _passthrough(raw)
    if held:
        return jsonify({'error': 'The VM uses devices of its node: ' + ', '.join(h['key'] for h in held),
                        'code': 'PASSTHROUGH', 'devices': held}), 409
    online = bool(data.get('online', True)) and vm.get('status') == 'running'
    r = mgr.migrate_vm_manual(node, int(desk['vmid']), desk['vm_type'], target, online,
                              {'online': online, 'with_local_disks': bool(data.get('with_local_disks'))})
    e = _failed(r, 'migration')
    if e:
        return e
    upid = r.get('upid') or r.get('task') or r.get('data')
    store.set_node(desk['id'], target)
    log_audit(_user(), 'vm.migrated', f"vLAB: desktop '{desk['name']}' ({desk['vm_type']}/{desk['vmid']}) {node} -> {target}"
              + (' (online)' if online else ''), get_client_ip())
    return jsonify({'success': True, 'task': upid if isinstance(upid, str) else None, 'from': node, 'to': target, 'online': online})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/task', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def desktop_task(desktop_id):
    """?upid= - how a task of this desktop is going: {status: running|stopped, exitstatus}."""
    desk = store.get_desktop(desktop_id)
    if not desk or not core._can_reach(desk['cluster_id']):
        return _bad('Desktop not found', 404)
    upid = str(request.args.get('upid') or '')
    m = _UPID.match(upid)
    if not m or f":{int(desk['vmid'])}:" not in upid:
        return _bad('upid is not a task of this desktop')
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    st = mgr.get_task_status(m.group(1), upid)
    if not isinstance(st, dict):
        return jsonify({'status': 'unknown', 'exitstatus': ''})
    return jsonify({'status': st.get('status') or 'unknown', 'exitstatus': str(st.get('exitstatus') or '')})


# template, delete

def _ties(desk):
    """What still hangs on the desktop: a card loan or a board."""
    if store.active_lease_of_vm(desk['cluster_id'], desk['vmid']):
        return 'A card is lent to this desktop - return it first'
    if any(b.get('attached_desktop') == desk['id'] for b in catalog.list_boards()):
        return 'A board is attached to this desktop - detach it first'
    return None


def _leave_pool(desk):
    """Out of the pool store: the assigned user's grant first (False when the ACL store is
    unreadable), then the desktop and its golden-image version."""
    if desk['assigned_user'] and not core._acl_set(desk['cluster_id'], desk['vmid'], desk['assigned_user'], False):
        return False
    store.remove_desktop(desk['id'])
    catalog.forget_desktop_version(desk['id'])
    return True


@bp.route('/api/vlab/admin/desktops/<desktop_id>/template', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_to_template(desktop_id):
    """A shut down desktop VM becomes a template (템플릿 관리 clones from it). A template is no
    desktop: it leaves the pool, and its user loses access."""
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    if desk['vm_type'] != 'qemu':
        return _bad('Only QEMU VMs become templates here')
    if vm.get('status') != 'stopped':
        return _bad('Shut the VM down first', 409)
    tie = _ties(desk)
    if tie:
        return _bad(tie, 409)
    if not _NODE_RE.fullmatch(node):
        return _bad('The VM has no node', 502)
    resp = mgr._api_post(f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{int(desk['vmid'])}/template")
    if resp is None or getattr(resp, 'status_code', 0) != 200:
        return _bad(f"Proxmox refused: {str(getattr(resp, 'text', '') or '')[:200]}", 502)
    if not _leave_pool(desk):
        return _bad('The VM is a template now, but the VM access list was unavailable - take the desktop out of the pool', 503)
    log_audit(_user(), 'vm.template', f"vLAB: desktop '{desk['name']}' (qemu/{desk['vmid']}) made a template, out of its pool",
              get_client_ip())
    return jsonify({'success': True, 'vmid': int(desk['vmid'])})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/vm', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_vm_delete(desktop_id):
    """{confirm_name, force?} - delete the VM on Proxmox (disks too) and the desktop with it.
    The desktop's name is typed again to confirm. Refused while someone is connected unless
    force, and while a card or a board is on it."""
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import invalidate_vm_acls_cache
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = _body()
    if str(data.get('confirm_name') or '') != desk['name']:
        return _bad("confirm_name must be the desktop's name")
    if not bool(data.get('force')) and desk['id'] in store.open_session_desktops():
        return jsonify({'error': 'Someone is connected to this desktop', 'code': 'IN_USE'}), 409
    tie = _ties(desk)
    if tie:
        return _bad(tie, 409)
    if vm.get('lock'):
        return _bad(f"The VM is busy ({vm['lock']}) - try again shortly", 409)
    e = _failed(mgr.delete_vm(node, int(desk['vmid']), desk['vm_type'], purge=True), 'delete')
    if e:
        return e
    store.remove_desktop(desk['id'])
    catalog.forget_desktop_version(desk['id'])
    try:
        # a recycled VMID must not inherit the old grants (as the core delete route does)
        if get_db().delete_vm_acl(desk['cluster_id'], int(desk['vmid'])):
            invalidate_vm_acls_cache()
    except Exception as ex:
        logging.error(f"[VLAB] {desk['vm_type']}/{desk['vmid']} deleted but its VM ACL was not removed: {ex}")
        log_audit(_user(), 'vm.acl_cleanup_failed', f"{desk['vm_type']}/{desk['vmid']} deleted but its VM ACL is still there "
                  f"- remove it by hand, the next guest on this VMID would inherit it", get_client_ip())
    log_audit(_user(), 'vm.deleted', f"vLAB: desktop '{desk['name']}' ({desk['vm_type']}/{desk['vmid']}) deleted from {node}",
              get_client_ip())
    return jsonify({'success': True})


# console for support

@bp.route('/api/vlab/admin/desktops/<desktop_id>/console', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_admin_console(desktop_id):
    """An administrator opens the desktop's screen to help its user: {ws_path, password} for
    noVNC, as the portal's connect answers. Every opening is in the audit log; no vLAB session
    is recorded (the desktop does not count as in use)."""
    from urllib.parse import quote

    from pegaprox.api.ha import standby_console_refusal
    from pegaprox.utils.auth import request_credential, resolve_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    from pegaprox.utils.realtime import create_ws_token

    refused = standby_console_refusal()
    if refused:
        return refused
    desk, mgr, vm, node, err = _desk_vm(desktop_id)
    if err:
        return err
    user = resolve_authz_user(request.session)
    if not user or not user_can_access_vm(user, desk['cluster_id'], int(desk['vmid']), 'vm.console', desk['vm_type']):
        return _bad('Permission denied: vm.console', 403)
    if vm.get('status') != 'running':
        return jsonify({'error': 'The desktop is not running', 'code': 'VM_STOPPED'}), 409
    vmid, vm_type = int(desk['vmid']), desk['vm_type']
    result = mgr.get_vnc_ticket(node, vmid, vm_type)
    if not isinstance(result, dict) or not result.get('success'):
        return _bad(str((result or {}).get('error') if isinstance(result, dict) else 'Console failed')[:200], 502)
    ws_token = create_ws_token(_user(), user.get('effective_role', user.get('role', 'viewer')), sid=request_credential()[0])
    ticket, port = result.get('ticket') or '', result.get('port') or ''
    ws_path = (f"/api/clusters/{quote(desk['cluster_id'], safe='')}/vms/{quote(str(node), safe='')}/"
               f"{vm_type}/{vmid}/vncwebsocket?token={quote(ws_token, safe='')}")
    if ticket and port:
        ws_path += f"&pve_ticket={quote(str(ticket), safe='')}&pve_port={quote(str(port), safe='')}"
    log_audit(_user(), 'vlab.desktop.admin_console',
              f"vLAB: administrator console to desktop '{desk['name']}' ({vm_type}/{vmid})"
              + (f", user {desk['assigned_user']}" if desk['assigned_user'] else ''), get_client_ip())
    return jsonify({'type': 'vnc', 'ws_path': ws_path, 'password': ticket, 'clipboard': 'both'})


# --- 운영 기본: 작업 진행 · 노드 유지보수 · Proxmox HA -------------------------------------
#
# The long Proxmox tasks (clones, golden deploys and rollouts, migrations, backups), the
# nodes' maintenance and the guests Proxmox HA restarts were core routes only. The console
# speaks /api/vlab/* (its README, 구조), so these wrap them: the task list and logs are read
# here, scoped to the caller (an administrator with vlab.pool.view sees every cluster they
# reach - and only their VMs where the core confines them; anyone else only the tasks of their
# own desktops and the ones they started), and the node and HA changes are handed to the core
# routes, which keep their own permissions, their unconfined-caller rule and their audit.
# Every one of these is a request an administrator makes and waits for; the evacuation thread
# of a maintenance is the core's, with its own steps. Nothing here runs in the background, so
# nothing asks ha.confirm_step.
#
# MOAVI Desk's own server pair (활성 · 대기) is not wrapped: on a standby every write but the
# HA routes is handed on to the active (app.py refuse_writes_on_standby lets /api/ha/ through),
# and a promotion handed on would land on the wrong instance. The console calls /api/ha/*
# there, as it calls /api/auth/*.

_TASKS_PROGRESS = 8          # running tasks whose progress is read from their log per call


def _sees_all_tasks():
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    return has_permission(build_authz_user(_user(), request.session), 'vlab.pool.view')


def _task_vmid(t, parts):
    for v in (t.get('id'), parts[6] if len(parts) > 6 else None):
        if str(v or '').isdigit():
            return int(v)
    return None


def _task_row(cid, cname, t, desks):
    """A Proxmox task as the console lists it. status is the exit text once it ended."""
    upid = str(t.get('upid') or '')
    parts = upid.split(':')
    vmid = _task_vmid(t, parts)
    status = str(t.get('status') or '')
    running = not t.get('endtime') and status in ('', 'running')
    d = desks.get((cid, vmid)) if vmid is not None else None
    return {
        'cluster_id': cid, 'cluster': cname, 'node': str(t.get('node') or (parts[1] if len(parts) > 1 else '')),
        'upid': upid, 'type': str(t.get('type') or (parts[5] if len(parts) > 5 else '')), 'vmid': vmid,
        'running': running, 'ok': (not running) and (status == 'OK' or status.startswith('WARNINGS')),
        'status': '' if running else status[:300],
        'starttime': core._num(t.get('starttime')) or None, 'endtime': core._num(t.get('endtime')) or None,
        'user': str(t.get('pegaprox_user') or ''),
        'desktop': {'id': d['id'], 'name': d['name'], 'pool_id': d['pool_id']} if d else None,
        'percent': None,
    }


def _task_percent(mgr, node, upid):
    log = mgr.get_task_log(node, upid, 500)
    for ln in reversed(log.splitlines() if isinstance(log, str) else []):
        m = re.search(r'(\d{1,3}(?:\.\d+)?)\s*%', ln)
        if m:
            return min(100.0, float(m.group(1)))
    return None


def _task_clusters(only=None):
    for cid, mgr in list(cluster_managers.items()):
        if only and cid != only:
            continue
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not getattr(mgr, 'is_connected', False):
            continue
        if core._can_reach(cid):
            yield cid, mgr


@bp.route('/api/vlab/tasks', methods=['GET'])
@require_auth()
def vlab_tasks():
    """The long tasks of the clusters, running ones first, then the latest that ended:
    {scope: all|mine, running, tasks}. ?cluster= one cluster, ?limit= (1..500, 100)."""
    from pegaprox.api.helpers import caller_is_scoped
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    try:
        limit = max(1, min(500, int(request.args.get('limit') or 100)))
    except ValueError:
        return _bad('limit: a number')
    everything = _sees_all_tasks()
    me = _user()
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    mine = {(d['cluster_id'], int(d['vmid'])) for d in store.desktops_of_user(me)}
    authz = build_authz_user(me, request.session) if everything else None
    rows = []
    for cid, mgr in _task_clusters(request.args.get('cluster') or None):
        scoped = everything and caller_is_scoped(authz, cid)
        cname = core._cluster_name(cid, mgr)
        for t in mgr.get_tasks(limit=limit) or []:
            if not isinstance(t, dict) or not str(t.get('upid') or '').startswith('UPID:'):
                continue
            row = _task_row(cid, cname, t, desks)
            if everything:
                if scoped and (row['vmid'] is None or not user_can_access_vm(authz, cid, row['vmid'], 'vm.view')):
                    continue
            elif (cid, row['vmid']) not in mine and row['user'] != me:
                continue
            rows.append((row, mgr))
    rows.sort(key=lambda x: (not x[0]['running'], -(x[0]['starttime'] or 0)))
    rows = rows[:limit]
    for row, mgr in [x for x in rows if x[0]['running']][:_TASKS_PROGRESS]:
        try:
            row['percent'] = _task_percent(mgr, row['node'], row['upid'])
        except Exception as e:
            logging.debug(f"[VLAB] progress of {row['upid']}: {e}")
    out = [r for r, _ in rows]
    return jsonify({'scope': 'all' if everything else 'mine', 'running': sum(1 for r in out if r['running']),
                    'tasks': out})


@bp.route('/api/vlab/tasks/log', methods=['GET'])
@require_auth()
def vlab_task_log():
    """?cluster=&upid= - how the task is, and its log (the last 1000 lines)."""
    from pegaprox.api.helpers import caller_is_scoped, get_task_user
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    cid, upid = request.args.get('cluster') or '', request.args.get('upid') or ''
    m = _UPID.match(upid)
    if not m:
        return _bad('upid: a Proxmox task id')
    node = m.group(1)
    mgr = dict(_task_clusters(cid)).get(cid) if cid else None
    if not mgr:
        return _bad('Cluster not found', 404)
    parts = upid.split(':')
    vmid = _task_vmid({}, parts)
    me = _user()
    if _sees_all_tasks():
        authz = build_authz_user(me, request.session)
        if caller_is_scoped(authz, cid) and (vmid is None or not user_can_access_vm(authz, cid, vmid, 'vm.view')):
            return _bad('Task not found', 404)
    else:
        mine = {(d['cluster_id'], int(d['vmid'])) for d in store.desktops_of_user(me)}
        if (cid, vmid) not in mine and get_task_user(upid) != me:
            return _bad('Task not found', 404)
    st = mgr.get_task_status(node, upid)
    if not isinstance(st, dict):
        return _bad('Task not found', 404)
    running = st.get('status') == 'running'
    log = mgr.get_task_log(node, upid, 1000)
    lines = log.splitlines() if isinstance(log, str) else []
    return jsonify({'upid': upid, 'node': node, 'type': parts[5] if len(parts) > 5 else '', 'running': running,
                    'ok': (not running) and str(st.get('exitstatus') or '') == 'OK',
                    'status': '' if running else str(st.get('exitstatus') or '')[:300], 'lines': lines[-1000:]})


# nodes: maintenance, restart and shut down, the log, sensors and tasks of one node

@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/maintenance', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.view'])
def node_maintenance_status(cluster_id, node):
    """How the node's maintenance goes ({maintenance_mode: false} when it is in none)."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    return core_vms.get_maintenance_status(cluster_id, node)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/maintenance-preview', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.maintenance'])
def node_maintenance_preview(cluster_id, node):
    """Before maintenance: the pool desktops on the node (who is on them), its other guests,
    whether the other nodes have room for the running ones (the core's capacity preview) and
    what its templates and anti-affinity rules would do (the core's evacuation plan)."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    live = core._vm_states(cluster_id)
    pools = {p['id']: p for p in store.list_pools()}
    busy = store.open_session_desktops()
    desks, desk_vmids = [], set()
    for d in store.list_desktops():
        if d['cluster_id'] != cluster_id:
            continue
        vm = live.get(int(d['vmid'])) or {}
        if (vm.get('node') or d['node']) != node:
            continue
        desk_vmids.add(int(d['vmid']))
        desks.append({'id': d['id'], 'name': d['name'], 'vmid': int(d['vmid']), 'pool_id': d['pool_id'],
                      'pool': (pools.get(d['pool_id']) or {}).get('name', ''), 'status': vm.get('status') or 'unknown',
                      'assigned_user': d.get('assigned_user') or '', 'in_use': d['id'] in busy})
    guests = [{'vmid': int(v['vmid']), 'name': v.get('name') or '', 'type': v.get('type'), 'status': v.get('status') or ''}
              for v in live.values() if v.get('node') == node and v.get('type') in ('qemu', 'lxc')
              and not v.get('template') and str(v.get('vmid', '')).isdigit() and int(v['vmid']) not in desk_vmids]
    cap = core._core_body(core_vms.maintenance_capacity_preview_api(cluster_id, node))
    plan = core._core_body(core_vms.maintenance_evacuation_plan(cluster_id, node))
    summary = None
    if isinstance(plan, dict) and plan.get('supported'):
        summary = {'templates': len(plan.get('templates') or []),
                   'blocking_rules': [r['rule'] for r in plan.get('negative_rules') or [] if r.get('blocks')],
                   'online_nodes': plan.get('online_nodes')}
    return jsonify({'node': node, 'desktops': desks, 'guests': sorted(guests, key=lambda g: g['vmid']),
                    'capacity': cap if isinstance(cap, dict) else None, 'plan': summary})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/maintenance', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage', 'node.maintenance'])
def node_maintenance_set(cluster_id, node):
    """{enable, skip_evacuation?, migrate_templates?, relax_anti_affinity?} - the core moves the
    running guests off (in its own thread) and answers with its maintenance task."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    data = _body()
    if set(data) - {'enable', 'skip_evacuation', 'migrate_templates', 'relax_anti_affinity'}:
        return _bad('Unknown field')
    if any(not isinstance(v, bool) for v in data.values()) or 'enable' not in data:
        return _bad('enable, skip_evacuation, migrate_templates, relax_anti_affinity: true or false')
    return core_vms.set_maintenance_mode(cluster_id, node)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/action', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'node.reboot'])
def node_power(cluster_id, node):
    """{action: reboot|shutdown, confirm: <node name>} - only a node in maintenance whose
    guests have moved off (the core refuses anything else)."""
    from pegaprox.api import vms as core_vms
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    data = _body()
    action = data.get('action')
    if action not in ('reboot', 'shutdown'):
        return _bad('action: reboot or shutdown')
    if data.get('confirm') != node:
        return _bad("confirm: type the node's name")
    return core_vms.node_action_api(cluster_id, node, action)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/syslog', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.view'])
def node_syslog(cluster_id, node):
    """The node's system log, newest first (?limit= 1..5000, 500)."""
    from pegaprox.api import nodes as core_nodes
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    body = core._core_body(core_nodes.get_node_syslog_api(cluster_id, node))
    return jsonify({'lines': [str(x) for x in body] if isinstance(body, list) else []})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/sensors', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.view'])
def node_sensors(cluster_id, node):
    """Temperatures, fans and voltages over SSH: {sensors, error} (error says why there are none)."""
    from pegaprox.api import nodes as core_nodes
    _, err = _build_target(cluster_id, node)
    if err:
        return err
    resp = core_nodes.get_node_sensors_api(cluster_id, node)
    r = resp[0] if isinstance(resp, tuple) else resp
    body = r.get_json(silent=True) if hasattr(r, 'get_json') else None
    if not isinstance(body, dict):
        return _bad('Could not read the sensors', 502)
    if body.get('error'):
        return jsonify({'sensors': [], 'error': str(body['error'])[:300]})
    rows = [{k: s.get(k) for k in ('chip', 'label', 'kind', 'value', 'max', 'crit', 'alarm')}
            for s in body.get('sensors') or [] if isinstance(s, dict)]
    return jsonify({'sensors': rows, 'error': None})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/tasks', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'node.view'])
def node_tasks(cluster_id, node):
    """The node's task history (?errors=true failed ones only, ?limit= 1..1000, 50)."""
    from pegaprox.api import nodes as core_nodes
    mgr, err = _build_target(cluster_id, node)
    if err:
        return err
    body = core._core_body(core_nodes.get_node_tasks_api(cluster_id, node))
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    cname = core._cluster_name(cluster_id, mgr)
    rows = [_task_row(cluster_id, cname, dict(t, node=t.get('node') or node), desks)
            for t in body or [] if isinstance(t, dict) and str(t.get('upid') or '').startswith('UPID:')]
    return jsonify({'tasks': rows})


# Proxmox HA: the guests the cluster restarts elsewhere when their node fails

_HA_GROUP_RE = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,39}')
_HA_NODES_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}(:\d{1,4})?(,[A-Za-z0-9][A-Za-z0-9.-]{0,62}(:\d{1,4})?){0,63}')
_HA_SIDS_RE = re.compile(r'(vm|ct):\d{3,9}(,(vm|ct):\d{3,9}){0,255}')
_HA_STATES = ('started', 'stopped', 'ignored', 'disabled')


def _ha_current(mgr):
    """{sid: {node, state}}, quorate and the master node, from /cluster/ha/status/current."""
    out, quorate, master = {}, None, ''
    try:
        resp = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/ha/status/current")
        rows = resp.json().get('data', []) if resp is not None and resp.status_code == 200 else []
    except Exception as e:
        logging.debug(f'[VLAB] HA status: {e}')
        rows = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        if r.get('type') == 'service' and r.get('sid'):
            out[str(r['sid'])] = {'node': str(r.get('node') or ''), 'state': str(r.get('state') or r.get('crm_state') or '')}
        elif r.get('type') == 'quorum':
            quorate = str(r.get('status') or '').upper() == 'OK' or bool(r.get('quorate'))
        elif r.get('type') == 'master':
            master = str(r.get('node') or '')
    return out, quorate, master


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'ha.view'])
def cluster_ha(cluster_id):
    """The cluster's HA resources (where each one runs and how), its groups (node-affinity
    rules on PVE 9.1+) and whether the HA manager has quorum."""
    from pegaprox.api import clusters as core_clusters
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    res = core._core_body(core_clusters.get_proxmox_ha_resources(cluster_id))
    groups = core._core_body(core_clusters.get_proxmox_ha_groups(cluster_id))
    current, quorate, master = _ha_current(mgr)
    live = core._vm_states(cluster_id)
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    rows = []
    for r in res if isinstance(res, list) else []:
        if not isinstance(r, dict):
            continue
        sid = str(r.get('sid') or '')
        kind, _, num = sid.partition(':')
        if kind not in ('vm', 'ct') or not num.isdigit():
            continue
        vm = live.get(int(num)) or {}
        cur = current.get(sid) or {}
        d = desks.get((cluster_id, int(num)))
        rows.append({'sid': sid, 'vmid': int(num), 'type': kind, 'name': vm.get('name') or '',
                     'node': cur.get('node') or vm.get('node') or '', 'state': str(r.get('state') or 'started'),
                     'status': cur.get('state') or '', 'group': str(r.get('group') or ''),
                     'max_restart': r.get('max_restart', 1), 'max_relocate': r.get('max_relocate', 1),
                     'comment': str(r.get('comment') or ''),
                     'desktop': {'id': d['id'], 'name': d['name'], 'pool_id': d['pool_id']} if d else None})
    out_groups = [{'group': str(g.get('group') or ''), 'nodes': str(g.get('nodes') or ''),
                   'restricted': bool(g.get('restricted')), 'nofailback': bool(g.get('nofailback')),
                   'comment': str(g.get('comment') or ''), 'rule': bool(g.get('_pve_rule_id')),
                   'resources': str(g.get('_pve_rule_resources') or '')}
                  for g in (groups if isinstance(groups, list) else []) if isinstance(g, dict)]
    return jsonify({'resources': sorted(rows, key=lambda x: x['vmid']), 'groups': out_groups,
                    'quorate': quorate, 'master': master})


def _ha_guest(cluster_id, vmid):
    vm = core._vm_states(cluster_id).get(int(vmid))
    if not vm or vm.get('type') not in ('qemu', 'lxc') or vm.get('template'):
        return None
    return 'vm' if vm['type'] == 'qemu' else 'ct'


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/resources', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def cluster_ha_add(cluster_id):
    """{vmid, state?: started|stopped|ignored|disabled, group?, max_restart?, max_relocate?,
    comment?} - the guest goes under Proxmox HA."""
    from pegaprox.api import clusters as core_clusters
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    data = _body()
    if set(data) - {'vmid', 'state', 'group', 'max_restart', 'max_relocate', 'comment'}:
        return _bad('Unknown field')
    try:
        vmid = _int(data, 'vmid', 100, 999999999)
        restarts = _int(data, 'max_restart', 0, 10, 1)
        relocates = _int(data, 'max_relocate', 0, 10, 1)
        comment = _text(data, 'comment', 200)
    except ValueError as e:
        return _bad(str(e))
    state = data.get('state') or 'started'
    if state not in _HA_STATES:
        return _bad(f"state: one of {', '.join(_HA_STATES)}")
    group = data.get('group') or None
    if group is not None and not (isinstance(group, str) and _HA_GROUP_RE.fullmatch(group)):
        return _bad('group: letters, digits, "-" and "_"')
    kind = _ha_guest(cluster_id, vmid)
    if not kind:
        return _bad('No such VM or container on the cluster', 404)
    if not core_clusters._ha_sid_authorized(cluster_id, f'{kind}:{vmid}'):
        return _bad('Access denied to this VM', 403)
    failed = _failed(mgr.add_vm_to_proxmox_ha(vmid, kind, group, restarts, relocates, state, comment), 'Adding to HA')
    if failed:
        return failed
    log_audit(_user(), 'ha.vm_added', f"{kind.upper()} {vmid} added to HA" + (f" (group: {group})" if group else ''),
              cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'success': True, 'sid': f'{kind}:{vmid}'}), 201


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/resources/<int:vmid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def cluster_ha_remove(cluster_id, vmid):
    """The guest leaves Proxmox HA (it keeps running where it is)."""
    mgr, err = _build_target(cluster_id)
    if err:
        return err
    kind = _ha_guest(cluster_id, vmid)
    if not kind:
        return _bad('No such VM or container on the cluster', 404)
    from pegaprox.api.vms import _require_vm_access
    denied = _require_vm_access(cluster_id, vmid, 'vm.config', 'qemu' if kind == 'vm' else 'lxc')   # per-VM ACLs
    if denied:
        return denied
    failed = _failed(mgr.remove_vm_from_proxmox_ha(vmid, kind), 'Removing from HA')
    if failed:
        return failed
    log_audit(_user(), 'ha.vm_removed', f"{kind.upper()} {vmid} removed from HA", cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/groups', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def cluster_ha_group_add(cluster_id):
    """{group, nodes: 'pve1:2,pve2', restricted?, nofailback?, comment?, resources?: 'vm:100,...'}
    - an HA group (a node-affinity rule on PVE 9.1+, which wants its guests named)."""
    from pegaprox.api import clusters as core_clusters
    _, err = _build_target(cluster_id)
    if err:
        return err
    data = _body()
    if set(data) - {'group', 'nodes', 'restricted', 'nofailback', 'comment', 'resources'}:
        return _bad('Unknown field')
    if not isinstance(data.get('group'), str) or not _HA_GROUP_RE.fullmatch(data['group']):
        return _bad('group: letters, digits, "-" and "_", starting with a letter')
    if not isinstance(data.get('nodes'), str) or not _HA_NODES_RE.fullmatch(data['nodes']):
        return _bad('nodes: node names separated by commas, each with an optional :priority')
    res = data.get('resources') or ''
    if res and not (isinstance(res, str) and _HA_SIDS_RE.fullmatch(res)):
        return _bad('resources: vm:<vmid> or ct:<vmid>, separated by commas')
    if any(k in data and not isinstance(data[k], bool) for k in ('restricted', 'nofailback')):
        return _bad('restricted, nofailback: true or false')
    try:
        _text(data, 'comment', 200)
    except ValueError as e:
        return _bad(str(e))
    return core_clusters.create_proxmox_ha_group(cluster_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/groups/<group>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def cluster_ha_group_remove(cluster_id, group):
    """The HA group (or node-affinity rule) goes; its guests stay under HA without it."""
    from pegaprox.api import clusters as core_clusters
    _, err = _build_target(cluster_id)
    if err:
        return err
    if not _HA_GROUP_RE.fullmatch(group):
        return _bad('Invalid group')
    return core_clusters.delete_proxmox_ha_group(cluster_id, group)


# --- 공유 저장소 (shared NAS storage, pegaprox/vlab/nas.py) ---------------------------------
#
# Folders by purpose (home, project, scratch), reached through autofs on Linux and a sign-in
# script in the user's own session on Windows; the engine checks through the QEMU guest agent
# that the map and the folders are there and fixes only what is missing. It runs inside the
# request that asks for it - a connect, a shared pool's routing, a build job's start
# (refresh_jobs), a pool grant - so the exits go out as that request's (ha.guard asks for a round
# of its own there) and no background step is added: nothing here asks ha.confirm_step. A guest
# without an agent, or a check that fails, never stops the connect: the answer carries it, the
# pool page shows it, the audit trail keeps it, the alert channels hear of it (once an hour per
# pool) and the support bundle has it.

STORAGE_FRESH = 300      # seconds a good result stands before the guest is asked again
STORAGE_WAIT = 8.0       # seconds a connect waits for the guest script
STORAGE_ALERT_EVERY = 3600
USAGE_EVERY = 6 * 3600   # how often a folder's size is measured (du) on a connect
CLEAN_EVERY = 24 * 3600  # how often old build job folders in scratch are removed
DATA_ON_NAS_ONLY = ('reset', 'classroom')   # pools whose desktops go back to their base
_storage_alerted = {}


def storage_config(pool_id):
    cfg = nas.get(pool_id)
    return cfg if cfg['enabled'] and cfg['server'] and cfg['share'] else None


def _dept_name(username):
    dep = catalog.department_of(username)
    d = catalog.get_department(dep) if dep else None
    return d['name'] if d else ''


def _user_folders(cfg, pool, username):
    try:
        return nas.folders_for(cfg, username, _dept_name(username), pool['name'])
    except ValueError:
        return None


def storage_paths(pool, username):
    """The user's folders in the pool: {kind, folders: {home|project|scratch: {linux, windows,
    nas, folder, quota_gb, retention_days?}}, data_on_nas_only}; None without shared storage."""
    cfg = storage_config(pool['id'])
    folders = _user_folders(cfg, pool, username) if cfg else None
    if not folders:
        return None
    out = {}
    for key, p in nas.paths(cfg, folders).items():
        f = cfg['folders'][key]
        out[key] = dict(p, folder=folders[key], quota_gb=f['quota_gb'], **({'retention_days': f['retention_days']} if key == 'scratch' else {}))
    return {'kind': cfg['kind'], 'folders': out, 'data_on_nas_only': pool.get('type') in DATA_ON_NAS_ONLY}


def _scratch_dir(pool, username):
    """Where the user's build jobs start (a folder per job under it), '' when not on the NAS."""
    cfg = storage_config(pool['id'])
    if not cfg or not cfg['build_workdir'] or not cfg['folders']['scratch']['enabled']:
        return ''
    folders = _user_folders(cfg, pool, username)
    return f"{cfg['linux_path']}/{folders['scratch']}" if folders else ''


def _guest_os(mgr, node, vmid):
    """'windows' or 'linux' from the agent's get-osinfo, None when the agent does not answer."""
    try:
        resp = mgr._api_get(_agent(mgr, node, vmid, 'get-osinfo'))
        if getattr(resp, 'status_code', 0) != 200:
            return None
        info = ((resp.json() or {}).get('data') or {}).get('result') or {}
    except Exception:
        return None
    return 'windows' if str(info.get('id') or '').lower().startswith('mswindows') else 'linux'


def _agent_run(mgr, node, vmid, command, stdin=None, wait=STORAGE_WAIT):
    """Run a command through the guest agent and wait up to `wait` seconds.
    (exit code or None while it runs, stdout, stderr, error text)."""
    data = {'command': command}
    if stdin:
        data['input-data'] = stdin
    try:
        resp = mgr._api_post(_agent(mgr, node, vmid, 'exec'), data=data)
    except Exception as e:
        return None, '', '', str(e)[:300]
    if getattr(resp, 'status_code', 0) != 200:
        return None, '', '', (getattr(resp, 'text', '') or 'guest agent refused')[:300]
    try:
        pid = (resp.json().get('data') or {}).get('pid')
    except Exception:
        pid = None
    if not pid:
        return None, '', '', 'guest agent returned no pid'
    end = time.monotonic() + wait
    while True:
        try:
            st = mgr._api_get(_agent(mgr, node, vmid, 'exec-status'), params={'pid': pid})
            st = (st.json().get('data') or {}) if getattr(st, 'status_code', 0) == 200 else {}
        except Exception:
            st = {}
        if st.get('exited'):
            return st.get('exitcode'), st.get('out-data') or '', st.get('err-data') or '', ''
        if time.monotonic() >= end:
            return None, '', '', ''
        time.sleep(0.4)


def _age(iso):
    """Seconds since a store.now() time (UTC, with its offset)."""
    from datetime import timezone
    try:
        then = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return 1e9
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds()


def _storage_view(r, pool=None):
    if not r:
        return None
    v = {k: r[k] for k in ('ok', 'code', 'detail', 'path', 'os', 'at', 'changed', 'warnings', 'usage')}
    if pool and r.get('username'):
        p = storage_paths(pool, r['username'])
        if p:
            v['paths'] = p
    return v


def _storage_failed(pool, desk, username, code, detail):
    log_audit(username or 'system', 'vlab.storage.fail',
              f"shared storage on {desk['name']} (qemu/{desk['vmid']}) for {username or '-'}: {code} {detail[:200]}", '')
    if time.time() - _storage_alerted.get(pool['id'], 0) < STORAGE_ALERT_EVERY:
        return
    _storage_alerted[pool['id']] = time.time()
    _alert(f"공유 저장소 연결 실패: {pool['name']}",
           f"{desk['name']} 에서 {username or '-'} 사용자의 공유 저장소를 준비하지 못했습니다 ({code}). {detail[:300]}",
           {'kind': 'storage_failed', 'pool': pool['name'], 'desktop': desk['name'], 'code': code, 'severity': 'warning'})


def _storage_record(desk, pool, username, ok, code, detail, path, changed, os_kind, **extra):
    nas.record(desk['id'], username, pool['id'], ok, code, detail, path, changed, os_kind, **extra)
    return _storage_view(nas.last(desk['id'], username), pool)


def _desk_users(cfg, pool, desk, username):
    """{guest account: {template: folder}} of everyone who used the desktop, and the caller."""
    out = {}
    for u in set(nas.users_on(desk['id']) + ([username] if username else [])):
        n, f = nas.guest_name(u), _user_folders(cfg, pool, u)
        if n and f:
            out[n] = f
    return out


def _desk_datasets(pool, usernames):
    """The research datasets a desktop of the pool mounts read-only: those of the pool one of
    its users may use (usernames None: all of the pool's, for the template). Never raises."""
    try:
        from pegaprox.api.vlab_data import datasets_for
        return datasets_for(pool['id'], usernames)
    except Exception as e:
        logging.warning(f"[VLAB] datasets for pool {pool.get('name')}: {e}")
        return []


def _engine_folders(cfg, folders, keys, uid, gid):
    """create_by engine: make the missing folders on the engine host. Error text or None."""
    for key in keys:
        if key == 'project' or key not in folders:
            continue
        err = nas.engine_make(cfg, folders[key], uid, gid)
        if err:
            return err
    return None


def ensure_storage(desk, pool, username, mgr=None, node=None, force=False, wait=STORAGE_WAIT):
    """Check the pool's share on the desktop (the autofs map, or the sign-in script on Windows)
    and the user's folders; fix only what is missing. username '': the share alone. A good
    result less than STORAGE_FRESH old is answered without asking the guest. Returns the
    result view, None when the pool has no shared storage or the desktop is a container."""
    cfg = storage_config(pool['id'])
    if not cfg or desk.get('vm_type') != 'qemu':
        return None
    username = username or ''
    prev = nas.last(desk['id'], username)
    if not force and prev and prev['ok'] and _age(prev['at']) < STORAGE_FRESH:
        return _storage_view(prev, pool)
    name, folders = None, {}
    if username:
        name, folders = nas.guest_name(username), _user_folders(cfg, pool, username)
        if not name or not folders:
            return _storage_record(desk, pool, username, False, 'BAD_NAME',
                                   f'{username!r} cannot be an account or folder name on the guest', '', False, '')
    mgr = mgr or cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _storage_view(prev, pool)
    if not node:
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        if live.get('status') != 'running':
            return _storage_record(desk, pool, username, None, 'NOT_RUNNING', '', '', False, '')
        node = live.get('node') or desk['node']
    os_kind = _guest_os(mgr, node, desk['vmid'])
    if not os_kind:
        _storage_failed(pool, desk, username, 'NO_AGENT', '')
        return _storage_record(desk, pool, username, False, 'NO_AGENT',
                               'the QEMU guest agent does not answer (qemu-guest-agent installed, agent: 1 on the VM?)', '', False, '')
    first = next((folders[k] for k in ('home', 'scratch', 'project') if k in folders), '')
    users = _desk_users(cfg, pool, desk, username)
    sets = _desk_datasets(pool, set(nas.users_on(desk['id']) + ([username] if username else [])))
    if os_kind == 'windows':
        script = nas.windows_script(cfg, users, extra=datasets.windows_links(sets) if sets else ())
        command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script]
        path = (nas.paths(cfg, folders)[next(iter(folders))]['windows'] or '') if folders else ''
        secret, measure, clean = '', False, 0
    else:
        measure = bool(username) and (force or _age((prev or {}).get('usage_at')) > USAGE_EVERY)
        days = cfg['folders']['scratch'].get('retention_days') or 0
        clean = days if username and 'scratch' in folders and _age((prev or {}).get('cleaned_at')) > CLEAN_EVERY else 0
        script = nas.linux_script(cfg, name, folders, users=users, measure=measure, cleanup_days=clean,
                                  datasets_line=datasets.autofs_entry(sets))
        command = ['/bin/sh', '-c', script]
        path = f"{cfg['linux_path']}/{first}" if first else cfg['linux_path']
        secret = nas.password(pool['id']) if cfg['kind'] == 'smb' and cfg['smb_auth'] == 'service' else ''
    code, out, err, e = _agent_run(mgr, node, desk['vmid'], command, stdin=secret or None, wait=wait)
    if code is None:
        if e:
            _storage_failed(pool, desk, username, 'AGENT_ERROR', e)
            return _storage_record(desk, pool, username, False, 'AGENT_ERROR', e, path, False, os_kind)
        return _storage_record(desk, pool, username, None, 'PENDING', 'still running on the guest', path, False, os_kind)
    got = nas.parse_output(out)
    changed = got.get('changed') == '1'
    if code != 0:
        label = nas.CODES.get(code, 'FAILED')
        detail = (err or '').strip()[-500:] or f'exit {code}'
        _storage_failed(pool, desk, username, label, detail)
        return _storage_record(desk, pool, username, False, label, detail, path, False, os_kind)
    warnings = []
    if os_kind == 'windows':
        warnings.append('AT_SIGN_IN')        # the drives come with the user's next sign-in
    if got.get('autofs') == 'missing':
        warnings.append('NO_AUTOFS')
    if username and got.get('uid', '').isdigit() and got.get('gid', '').isdigit():
        local = got.get('local') == '1'
        nas.remember_ids(username, got['uid'], got['gid'], local)
        if local and cfg['kind'] == 'nfs':
            warnings.append('LOCAL_ACCOUNT')
        missing = [k for k in got['missing'] if k != 'project']
        if missing and cfg['create_by'] == 'engine':
            why = _engine_folders(cfg, folders, missing, got['uid'], got['gid'])
            if why:
                _storage_failed(pool, desk, username, 'ENGINE_FOLDER', why)
                return _storage_record(desk, pool, username, False, 'ENGINE_FOLDER', why, path, False, os_kind)
            changed = True
    if 'project' in got['missing']:
        warnings.append('PROJECT_MISSING')
    if got['atsignin']:
        warnings.append('AT_SIGN_IN')
    usage = got['usage']
    for key, kb in usage.items():
        q = (cfg['folders'].get(key) or {}).get('quota_gb') or 0
        if q and kb > q * 1024 * 1024 and 'OVER_QUOTA' not in warnings:
            warnings.append('OVER_QUOTA')
    if changed:
        log_audit(username or 'system', 'vlab.storage.mount', f"shared storage on {desk['name']} (qemu/{desk['vmid']}): {path}", '')
    if 'LOCAL_ACCOUNT' in warnings and not (prev and 'LOCAL_ACCOUNT' in (prev.get('warnings') or [])):
        log_audit(username, 'vlab.storage.warn', f"{desk['name']}: {name} is a local account - its uid is not the NAS's", '')
    return _storage_record(desk, pool, username, True, 'OK', '', path, changed, os_kind, warnings=sorted(set(warnings)),
                           usage=usage if measure else None, cleaned=bool(clean))


def storage_on_connect(desk, pool, mgr, node, username):
    """The connect route's step: never raises, never stops the connect."""
    try:
        return ensure_storage(desk, pool, username, mgr, node)
    except Exception as e:
        logging.warning(f"[VLAB] shared storage on {desk.get('name')}: {e}")
        return None


def provision_granted(pool, usernames):
    """create_by engine: make the folders of users a grant names, when a guest already told the
    engine their uid/gid (else at their first connect). Returns {username: error or None}."""
    cfg = storage_config(pool['id'])
    if not cfg or cfg['create_by'] != 'engine':
        return {}
    out = {}
    for u in usernames:
        ids, folders = nas.ids_of(u), _user_folders(cfg, pool, u)
        if ids and folders:
            out[u] = _engine_folders(cfg, folders, list(folders), ids['uid'], ids['gid'])
    return out


def _pool_storage_out(pool_id):
    cfg = nas.get(pool_id)
    rows = nas.results(pool_id=pool_id, limit=200)
    desks = {d['id']: d['name'] for d in store.list_desktops(pool_id)}
    for r in rows:
        r['desktop'] = desks.get(r['desktop_id'])
    status = {'ok': sum(1 for r in rows if r['ok'] is True), 'failed': sum(1 for r in rows if r['ok'] is False),
              'pending': sum(1 for r in rows if r['ok'] is None),
              'warnings': sum(1 for r in rows if r['ok'] and r['warnings']), 'last': rows[0] if rows else None}
    pool = store.get_pool(pool_id)
    files = None
    if storage_config(pool_id) and not (cfg['kind'] == 'smb' and cfg['smb_auth'] == 'service'):
        master, amap = nas.autofs_files(cfg, datasets.autofs_entry(_desk_datasets(pool or {'id': pool_id}, None)))
        files = {nas.AUTOFS_MASTER: master, nas.AUTOFS_MAP: amap}
    return {'storage': cfg, 'status': status, 'results': rows[:50], 'autofs': files,
            'data_on_nas_only': bool(pool and pool.get('type') in DATA_ON_NAS_ONLY)}


def _storage_pool(pool_id):
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']):
        return None, _bad('Pool not found', 404)
    return pool, None


@bp.route('/api/vlab/admin/pools/<pool_id>/storage', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_storage(pool_id):
    _, err = _storage_pool(pool_id)
    if err:
        return err
    return jsonify(dict(_pool_storage_out(pool_id), defaults=nas.DEFAULTS))


@bp.route('/api/vlab/admin/pools/<pool_id>/storage', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_pool_storage(pool_id):
    pool, err = _storage_pool(pool_id)
    if err:
        return err
    cfg, new_password, why = nas.validate(request.get_json(silent=True), nas.get(pool_id))
    if why:
        return _bad(why)
    saved = nas.save(pool_id, cfg, new_password)
    on = [k for k in nas.TEMPLATES if cfg['folders'][k]['enabled']]
    what = (f"{cfg['kind']} {cfg['server']}:{cfg['share']} -> {cfg['linux_path']}, folders {', '.join(on)}, "
            f"made by {cfg['create_by']}" if cfg['enabled'] else 'off')
    if new_password is not None:
        what += ', password changed' if new_password else ', password removed'
    log_audit(_user(), 'vlab.pool.storage', f"pool '{pool['name']}': {what}", get_client_ip())
    return jsonify({'storage': saved})


@bp.route('/api/vlab/admin/pools/<pool_id>/storage/check', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def check_pool_storage(pool_id):
    """Check and fix it now on the pool's running VMs (at most 10), folder sizes measured: each
    assigned user's folders, or the share alone on an unassigned one. {desktop_id?} for one."""
    pool, err = _storage_pool(pool_id)
    if err:
        return err
    if not storage_config(pool_id):
        return _bad('Shared storage is off for this pool', 409)
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    only = str(_body().get('desktop_id') or '')
    live = core._vm_states(pool['cluster_id'])
    out = []
    for d in store.list_desktops(pool_id):
        if (only and d['id'] != only) or d['vm_type'] != 'qemu':
            continue
        vm = live.get(int(d['vmid'])) or {}
        if vm.get('status') != 'running':
            continue
        r = ensure_storage(d, pool, d.get('assigned_user') or '', mgr, vm.get('node') or d['node'], force=True, wait=15.0)
        out.append(dict(r or {}, desktop=d['name'], desktop_id=d['id'], username=d.get('assigned_user') or ''))
        if len(out) >= 10:
            break
    log_audit(_user(), 'vlab.pool.storage.check', f"pool '{pool['name']}': {len(out)} VMs", get_client_ip())
    return jsonify(dict(_pool_storage_out(pool_id), checked=out))


@bp.route('/api/vlab/me/storage', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_storage():
    """The caller's folders on shared storage: every pool with it the caller has a desktop in or
    is granted (shared, build farm), the paths, quota, last measured size and last check."""
    username = _user()
    pools = {}
    for d in store.desktops_of_user(username):
        p = store.get_pool(d['pool_id'])
        if p and core._can_reach(p['cluster_id']):
            pools[p['id']] = p
    for p in store.list_pools():
        if (p['id'] not in pools and p['type'] in ('shared', 'buildfarm') and core._can_reach(p['cluster_id'])
                and granted(p['id'], username)):
            pools[p['id']] = p
    out = []
    for p in sorted(pools.values(), key=lambda x: x['name']):
        paths = storage_paths(p, username)
        if not paths:
            continue
        rows = nas.results(pool_id=p['id'], username=username, limit=20)
        measured = next((r for r in rows if r.get('usage')), None)
        out.append({'pool_id': p['id'], 'pool': p['name'], 'pool_type': p['type'], 'kind': paths['kind'],
                    'folders': paths['folders'], 'data_on_nas_only': paths['data_on_nas_only'],
                    'usage': measured['usage'] if measured else {}, 'usage_at': measured['usage_at'] if measured else None,
                    'last': _storage_view(rows[0]) if rows else None})
    return jsonify({'folders': out})
