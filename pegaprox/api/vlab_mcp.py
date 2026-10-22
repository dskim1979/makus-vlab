"""MOAVI Desk: the MCP server for administrators (pegaprox/vlab/mcp.py) - an AI client manages VMs.

  POST   /api/vlab/mcp                          MCP Streamable HTTP (JSON-RPC 2.0; JSON answers, no SSE stream)
  GET    /api/vlab/mcp                          405 - this server opens no stream of its own
  GET    /api/vlab/mcp/stdio.py                 the stdio bridge for clients that only start a local program
  GET    /api/vlab/admin/mcp                    {enabled, tokens, tools, url}           vlab.pool.view
  PUT    /api/vlab/admin/mcp                    {enabled}                               admin.settings
  POST   /api/vlab/admin/mcp/tokens             {name, scope, days} -> {token, record}  vlab.pool.view (own token)
  DELETE /api/vlab/admin/mcp/tokens/<id>        revoke (own token; any with admin.settings)

The MCP side takes `Authorization: Bearer mcp_...` only - no session cookie, so no page can make a
browser call it. A tool is a call of an existing admin route, made inside the engine as the token's
owner (require_auth reads the MCP identity from the WSGI environ, which no client can set), so every
permission and cluster check of the console applies. A `read` token gets the read tools only, and
require_auth refuses anything but GET for it as well. Tools that delete or roll back need confirm:
true. Every tool call is in the audit log ('vlab.mcp.call'), and the lines the routes write
themselves say they came through MCP. Passwords in an answer are not handed to the AI client.
"""
import json
import os
import re

from flask import Blueprint, Response, current_app, g, jsonify, request

from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import MCP_SESSION_ENVIRON, require_auth
from pegaprox.vlab import VLAB_API_VERSION
from pegaprox.vlab import mcp

bp = Blueprint('vlab_mcp', __name__)

PROTOCOL_VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05')
SERVER_INFO = {'name': 'moavi-desk', 'title': 'MOAVI Desk', 'version': str(VLAB_API_VERSION)}
INSTRUCTIONS = (
    'MOAVI Desk (Proxmox VDI) administration. Find ids with the list_* tools first (clusters, nodes, storage, '
    'pools, desktops). Desktops are VMs that belong to a pool; list_vms shows every VM of a cluster. Tools that '
    'delete, roll back or force a VM off need confirm: true - ask the administrator before you set it. Long jobs '
    '(create, clone, template builds) answer with a task or build id: follow them with get_task / '
    'get_template_build. Every call runs with the token owner\'s permissions and is audited.')
MAX_BODY = 1024 * 1024
MAX_TEXT = 60000

_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:@=-]{0,199}$')
_SECRET_KEY = re.compile(r'(password|passwd|secret|ticket|token)$', re.I)


def _bad(msg, status=400, **extra):
    return jsonify(dict({'error': msg}, **extra)), status


# --- the tools -----------------------------------------------------------------------------

class ToolError(Exception):
    def __init__(self, msg, code='INVALID_ARGUMENT'):
        super().__init__(msg)
        self.code = code


def _seg(args, key):
    """A path part from the arguments: an id, never a slash or '..' (the route is looked up again)."""
    v = args.get(key)
    if isinstance(v, bool) or v is None or v == '':
        raise ToolError(f'{key} is required')
    v = str(v)
    if not _ID.fullmatch(v) or '..' in v:
        raise ToolError(f'{key}: not a valid id')
    return v


def _pick(args, keys):
    return {k: args[k] for k in keys if k in args and args[k] is not None}


def _rest(args, drop):
    return {k: v for k, v in args.items() if k not in drop and k != 'confirm' and v is not None}


S = {
    'cluster_id': {'type': 'string', 'description': 'Cluster id (list_clusters)'},
    'node': {'type': 'string', 'description': 'Proxmox node name (list_nodes)'},
    'pool_id': {'type': 'string', 'description': 'Desktop pool id (list_pools)'},
    'desktop_id': {'type': 'string', 'description': 'Desktop id (list_desktops)'},
    'vmid': {'type': 'integer', 'minimum': 100, 'description': 'Proxmox VMID'},
    'confirm': {'type': 'boolean', 'description': 'Must be true. Ask the administrator first.'},
    'snapshot': {'type': 'string', 'description': 'Snapshot name (list_snapshots)'},
    'build_id': {'type': 'string', 'description': 'Template build id (list_template_builds)'},
}


def _obj(props, required=(), extra=False):
    return {'type': 'object', 'properties': {k: (S[k] if v is None else v) for k, v in props.items()},
            'required': list(required), 'additionalProperties': extra}


# name -> {scope, destructive, title, description, schema, call(args) -> (method, path, body, query)}
TOOLS = {}


def tool(name, scope, title, description, schema, destructive=False, idempotent=False):
    def deco(f):
        TOOLS[name] = {'scope': scope, 'destructive': destructive, 'idempotent': idempotent, 'title': title,
                       'description': description, 'schema': schema, 'call': f}
        return f
    return deco


A = '/api/vlab/admin'

# read ------------------------------------------------------------------------------------

tool('list_clusters', 'read', '클러스터 목록', 'Proxmox clusters this account reaches, with their connection state.',
     _obj({}))(lambda a: ('GET', f'{A}/clusters', None, None))
tool('list_nodes', 'read', '노드 목록', 'Nodes of a cluster: status, CPU, memory, uptime.',
     _obj({'cluster_id': None}, ['cluster_id']))(lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/nodes", None, None))
tool('list_storage', 'read', '스토리지 목록', 'Storage of a cluster: type, content, used and free space.',
     _obj({'cluster_id': None}, ['cluster_id']))(lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/storage", None, None))
tool('list_networks', 'read', '네트워크 브리지', 'Network bridges of a node (for net_bridge / bridge).',
     _obj({'cluster_id': None, 'node': None}, ['cluster_id', 'node']))(
    lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/nodes/{_seg(a, 'node')}/networks", None, None))
tool('list_isos', 'read', 'ISO 목록', 'ISO images on the storage of a node (volid for create_vm_from_iso).',
     _obj({'cluster_id': None, 'node': None}, ['cluster_id', 'node']))(
    lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/nodes/{_seg(a, 'node')}/isos", None, None))
tool('list_vms', 'read', 'VM 목록', 'Every VM and container of a cluster with its status; desktop_id is set for pool desktops.',
     _obj({'cluster_id': None}, ['cluster_id']))(lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/guests", None, None))
tool('list_templates', 'read', '템플릿 목록', 'VM templates of a cluster (template_vmid for create_desktops_from_template).',
     _obj({'cluster_id': None}, ['cluster_id']))(lambda a: ('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/templates", None, None))
tool('list_golden_images', 'read', '골든 이미지 목록', 'Golden images with their versions.',
     _obj({}))(lambda a: ('GET', f'{A}/golden-images', None, None))
tool('list_pools', 'read', '데스크톱 풀 목록', 'Desktop pools: id, name, type, cluster.',
     _obj({}))(lambda a: ('GET', f'{A}/pools', None, None))


@tool('list_desktops', 'read', '데스크톱 목록', 'Desktops (pool VMs) with status, assigned user and usage; pool_id narrows it.',
      _obj({'pool_id': None}))
def _list_desktops(a):
    if a.get('pool_id'):
        return 'GET', f"{A}/pools/{_seg(a, 'pool_id')}/desktops", None, None
    return 'GET', f'{A}/desktops', None, None


tool('get_desktop', 'read', '데스크톱 상세', "A desktop's VM: hardware, disks, networks, status.",
     _obj({'desktop_id': None}, ['desktop_id']))(lambda a: ('GET', f"{A}/desktops/{_seg(a, 'desktop_id')}/vm", None, None))
tool('list_snapshots', 'read', '스냅샷 목록', 'Snapshots of a desktop.',
     _obj({'desktop_id': None}, ['desktop_id']))(lambda a: ('GET', f"{A}/desktops/{_seg(a, 'desktop_id')}/snapshots", None, None))
tool('list_users', 'read', '사용자 목록', 'Accounts a desktop can be assigned to.',
     _obj({}))(lambda a: ('GET', f'{A}/users', None, None))
tool('list_template_builds', 'read', '템플릿 만들기 목록',
     'Template presets (preset_id, os choices, defaults) and the template builds with their status.',
     _obj({}))(lambda a: ('GET', f'{A}/desktop-templates', None, None))
tool('get_template_build', 'read', '템플릿 빌드 상태', 'One template build: status, step, log.',
     _obj({'build_id': None}, ['build_id']))(lambda a: ('GET', f"{A}/desktop-templates/builds/{_seg(a, 'build_id')}", None, None))


@tool('get_task', 'read', '작업 상태', 'How a Proxmox task (upid) is going. Give desktop_id for a desktop task, '
      'else cluster_id and node (create, clone, download, template).',
      _obj({'upid': {'type': 'string'}, 'desktop_id': None, 'cluster_id': None, 'node': None}, ['upid']))
def _get_task(a):
    upid = str(a.get('upid') or '')
    if not upid.startswith('UPID:') or '/' in upid or len(upid) > 300:
        raise ToolError('upid: a Proxmox task id (UPID:...)')
    if a.get('desktop_id'):
        return 'GET', f"{A}/desktops/{_seg(a, 'desktop_id')}/task", None, {'upid': upid}
    return 'GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/nodes/{_seg(a, 'node')}/tasks/{_seg({'u': upid}, 'u')}", None, None


# manage ----------------------------------------------------------------------------------

@tool('create_vm_from_iso', 'manage', 'ISO로 VM 만들기',
      'A new VM from an ISO on a node. Required: name, ostype (win11|win10|l26|other), iso (volid from list_isos), '
      'storage, disk_size (GB), net_bridge. Optional: vmid, cores, sockets, memory (MB), cpu, bios (ovmf|seabios), '
      'machine (q35|pc), efi_storage, tpm_storage, virtio_iso, vga, agent, onboot, disk_type, net_model, net_tag. '
      'Windows 11 needs bios ovmf, machine q35 and tpm_storage. Answers {vmid, task}.',
      _obj({'cluster_id': None, 'node': None, 'name': {'type': 'string'},
            'ostype': {'type': 'string', 'enum': ['win11', 'win10', 'l26', 'other']},
            'iso': {'type': 'string'}, 'storage': {'type': 'string'}, 'disk_size': {'type': 'integer', 'minimum': 1},
            'net_bridge': {'type': 'string'}, 'cores': {'type': 'integer'}, 'memory': {'type': 'integer'}},
           ['cluster_id', 'node', 'name', 'ostype', 'iso', 'storage', 'disk_size', 'net_bridge'], extra=True))
def _create_iso(a):
    return 'POST', f"{A}/clusters/{_seg(a, 'cluster_id')}/nodes/{_seg(a, 'node')}/vms", _rest(a, ('cluster_id', 'node')), None


tool('create_desktops_from_template', 'manage', '템플릿으로 데스크톱 만들기',
     'Clone desktops into a pool from a VM template (linked clones unless full). Names are name_prefix-01, -02, ...',
     _obj({'pool_id': None, 'template_vmid': {'type': 'integer'}, 'count': {'type': 'integer', 'minimum': 1},
           'name_prefix': {'type': 'string'}, 'full': {'type': 'boolean'}, 'start_vmid': {'type': 'integer'}},
          ['pool_id', 'template_vmid', 'count', 'name_prefix']))(
    lambda a: ('POST', f"{A}/pools/{_seg(a, 'pool_id')}/clone",
               _pick(a, ('template_vmid', 'count', 'name_prefix', 'full', 'start_vmid')), None))
tool('deploy_golden_image', 'manage', '골든 이미지로 데스크톱 만들기',
     "Full clones of a golden image's current version into a pool on the same cluster.",
     _obj({'golden_image_id': {'type': 'string'}, 'pool_id': None, 'count': {'type': 'integer', 'minimum': 1},
           'name_prefix': {'type': 'string'}, 'start_vmid': {'type': 'integer'}},
          ['golden_image_id', 'pool_id', 'count', 'name_prefix']))(
    lambda a: ('POST', f"{A}/golden-images/{_seg(a, 'golden_image_id')}/deploy",
               _pick(a, ('pool_id', 'count', 'name_prefix', 'start_vmid')), None))

_POWER = {'type': 'string', 'enum': ['start', 'shutdown', 'reboot', 'stop'],
          'description': 'shutdown = clean shutdown, stop = power off at once (needs confirm)'}


def _power_confirm(a):
    if a.get('action') not in ('start', 'shutdown', 'reboot', 'stop'):
        raise ToolError('action: start, shutdown, reboot or stop')
    if a['action'] == 'stop' and a.get('confirm') is not True:
        raise ToolError('stop powers the VM off at once (unsaved work is lost): ask the administrator, then send confirm: true',
                        'CONFIRM_REQUIRED')


@tool('power_desktop', 'manage', '데스크톱 전원', 'Start, shut down, restart or power off a desktop.',
      _obj({'desktop_id': None, 'action': _POWER, 'confirm': None}, ['desktop_id', 'action']))
def _power_desktop(a):
    _power_confirm(a)
    return 'POST', f"{A}/desktops/{_seg(a, 'desktop_id')}/power", {'action': a['action']}, None


@tool('power_vm', 'manage', 'VM 전원', 'Start, shut down, restart or power off any VM of a cluster by VMID.',
      _obj({'cluster_id': None, 'vmid': None, 'action': _POWER, 'confirm': None}, ['cluster_id', 'vmid', 'action']))
def _power_vm(a):
    _power_confirm(a)
    vm = _guest(a)
    return 'POST', f"/api/clusters/{_seg(a, 'cluster_id')}/vms/{_seg(vm, 'node')}/{_seg(vm, 'type')}/{vm['vmid']}/{a['action']}", {}, None


tool('take_snapshot', 'manage', '스냅샷 만들기', 'A snapshot of a desktop (vmstate keeps the RAM of a running VM).',
     _obj({'desktop_id': None, 'name': {'type': 'string'}, 'description': {'type': 'string'}, 'vmstate': {'type': 'boolean'}},
          ['desktop_id', 'name']))(
    lambda a: ('POST', f"{A}/desktops/{_seg(a, 'desktop_id')}/snapshots", _pick(a, ('name', 'description', 'vmstate')), None))
tool('rollback_snapshot', 'manage', '스냅샷으로 되돌리기', 'Roll a desktop back to a snapshot: changes since then are lost.',
     _obj({'desktop_id': None, 'snapshot': None, 'confirm': None}, ['desktop_id', 'snapshot', 'confirm']), destructive=True)(
    lambda a: ('POST', f"{A}/desktops/{_seg(a, 'desktop_id')}/snapshots/{_seg(a, 'snapshot')}/rollback", {}, None))
tool('delete_snapshot', 'manage', '스냅샷 삭제', 'Delete a snapshot of a desktop.',
     _obj({'desktop_id': None, 'snapshot': None, 'confirm': None}, ['desktop_id', 'snapshot', 'confirm']), destructive=True)(
    lambda a: ('DELETE', f"{A}/desktops/{_seg(a, 'desktop_id')}/snapshots/{_seg(a, 'snapshot')}", {}, None))
tool('delete_desktop', 'manage', '데스크톱 삭제',
     "Delete a desktop's VM on Proxmox (disks too) and the desktop. confirm_name is the desktop's name. "
     'Refused while someone is connected unless force.',
     _obj({'desktop_id': None, 'confirm_name': {'type': 'string'}, 'force': {'type': 'boolean'}, 'confirm': None},
          ['desktop_id', 'confirm_name', 'confirm']), destructive=True)(
    lambda a: ('DELETE', f"{A}/desktops/{_seg(a, 'desktop_id')}/vm", _pick(a, ('confirm_name', 'force')), None))


@tool('delete_vm', 'manage', 'VM 삭제',
      'Delete a VM that is not a pool desktop (use delete_desktop for those), disks too. confirm_vmid repeats the VMID.',
      _obj({'cluster_id': None, 'vmid': None, 'confirm_vmid': {'type': 'integer'}, 'confirm': None},
           ['cluster_id', 'vmid', 'confirm_vmid', 'confirm']), destructive=True)
def _delete_vm(a):
    if a.get('confirm_vmid') != a.get('vmid'):
        raise ToolError('confirm_vmid must repeat the vmid')
    vm = _guest(a)
    if vm.get('desktop_id'):
        raise ToolError(f"VM {vm['vmid']} is the desktop {vm['desktop_id']} of a pool - use delete_desktop", 'IS_DESKTOP')
    return ('DELETE', f"/api/clusters/{_seg(a, 'cluster_id')}/vms/{_seg(vm, 'node')}/{_seg(vm, 'type')}/{vm['vmid']}",
            {'purge': True}, None)


tool('assign_desktop', 'manage', '데스크톱 배정', 'Give a desktop to a user (username from list_users), or null to take it back.',
     _obj({'desktop_id': None, 'username': {'type': ['string', 'null']}}, ['desktop_id', 'username']))(
    lambda a: ('PUT', f"{A}/desktops/{_seg(a, 'desktop_id')}/assign", {'username': a.get('username')}, None))
tool('start_template_build', 'manage', '템플릿 만들기 시작',
     'Build a desktop template from a preset (list_template_builds) on a node: node, storage, bridge, and the '
     "preset's options (os, name, cores, memory_mb, disk_gb, windows_url or windows_iso, ...). Answers the build.",
     _obj({'cluster_id': None, 'preset_id': {'type': 'string'}, 'node': None, 'storage': {'type': 'string'},
           'bridge': {'type': 'string'}, 'os': {'type': 'string'}, 'name': {'type': 'string'}},
          ['cluster_id', 'preset_id', 'node', 'storage'], extra=True))(
    lambda a: ('POST', f"{A}/clusters/{_seg(a, 'cluster_id')}/desktop-templates/{_seg(a, 'preset_id')}/build",
               _rest(a, ('cluster_id', 'preset_id')), None))
tool('cancel_template_build', 'manage', '템플릿 만들기 취소', 'Stop a queued or running template build.',
     _obj({'build_id': None, 'confirm': None}, ['build_id', 'confirm']), destructive=True)(
    lambda a: ('POST', f"{A}/desktop-templates/builds/{_seg(a, 'build_id')}/cancel", {}, None))


def tools_for(scope):
    return [n for n, t in TOOLS.items() if t['scope'] == 'read' or scope == 'manage']


def _listing(scope):
    out = []
    for n in tools_for(scope):
        t = TOOLS[n]
        out.append({'name': n, 'title': t['title'], 'description': t['description'], 'inputSchema': t['schema'],
                    'annotations': {'title': t['title'], 'readOnlyHint': t['scope'] == 'read',
                                    'destructiveHint': t['destructive'], 'idempotentHint': t['scope'] == 'read',
                                    'openWorldHint': False}})
    return out


# --- calling a route as the token's owner --------------------------------------------------

def _ctx():
    """Who this MCP request is: the identity handed to the routes, the client's address, the base URL."""
    return g.vlab_mcp


def _route(method, path, body=None, query=None):
    """(status, json) of an engine route, called in-process as the MCP identity of this request."""
    c = current_app.test_client()
    ctx = _ctx()
    environ = {MCP_SESSION_ENVIRON: ctx['session'], 'REMOTE_ADDR': ctx['ip']}
    r = c.open(path, method=method, json=body if method != 'GET' else None, query_string=query,
               headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
               environ_base=environ, base_url=ctx['base'])
    return r.status_code, r.get_json(silent=True)


def _guest(a):
    """The VM of a cluster by vmid, from the VM list the owner may see."""
    vmid = a.get('vmid')
    if not isinstance(vmid, int) or isinstance(vmid, bool):
        raise ToolError('vmid: a number')
    status, body = _route('GET', f"{A}/clusters/{_seg(a, 'cluster_id')}/guests")
    if status != 200:
        raise _RouteError(status, body)
    for g in (body or {}).get('guests', []):
        if g.get('vmid') == vmid:
            return g
    raise ToolError(f'VM {vmid} not found on this cluster', 'NOT_FOUND')


class _RouteError(Exception):
    def __init__(self, status, body):
        super().__init__(str(status))
        self.status, self.body = status, body


def _scrub(v):
    if isinstance(v, dict):
        return {k: ('(콘솔에서만 볼 수 있음)' if _SECRET_KEY.search(str(k)) and isinstance(x, str) and x else _scrub(x))
                for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    return v


def _text_result(payload, error=False):
    text = json.dumps(payload, ensure_ascii=False, default=str)
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + ' ...(truncated)'
    out = {'content': [{'type': 'text', 'text': text}], 'isError': error}
    if isinstance(payload, dict) and not error:
        out['structuredContent'] = payload
    return out


def _call_tool(name, args, rec):
    """(result, audit status)."""
    t = TOOLS.get(name)
    if not t:
        raise _RpcError(-32602, f'Unknown tool: {name}')
    if name not in tools_for(rec['scope']):
        return _text_result({'error': 'This token is read-only: the tools that change things need a manage token',
                             'code': 'SCOPE'}, True), 'scope'
    if not isinstance(args, dict):
        raise _RpcError(-32602, 'arguments must be an object')
    try:
        if t['destructive'] and args.get('confirm') is not True:
            raise ToolError(f'{name} cannot be undone: ask the administrator, then call it again with confirm: true',
                            'CONFIRM_REQUIRED')
        allowed = set(t['schema']['properties'])
        if not t['schema'].get('additionalProperties'):
            unknown = sorted(set(args) - allowed)
            if unknown:
                raise ToolError(f"Unknown argument: {', '.join(unknown)}")
        method, path, body, query = t['call'](args)
        status, payload = _route(method, path, body, query)
    except ToolError as e:
        return _text_result({'error': str(e), 'code': e.code}, True), e.code.lower()
    except _RouteError as e:
        status, payload = e.status, e.body
    payload = _scrub(payload if payload is not None else {})
    if status >= 400:
        err = payload if isinstance(payload, dict) else {'error': str(payload)}
        return _text_result(dict(err, status=status), True), str(status)
    if isinstance(payload, dict) and name == 'start_template_build' and 'admin_user' in payload:
        payload['note'] = ("The template's local administrator password is not passed to AI clients; "
                           'set a new one on the template if it is needed.')
    return _text_result(payload if isinstance(payload, dict) else {'result': payload}), 'ok'


# --- JSON-RPC ------------------------------------------------------------------------------

class _RpcError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def _handle(msg, rec):
    """The answer to one JSON-RPC message, or None for a notification / a response."""
    if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid Request'}}
    if 'method' not in msg:
        return None                                   # a response to a request of ours (we send none)
    mid, method, params = msg.get('id'), msg.get('method'), msg.get('params') or {}
    if 'id' not in msg:
        return None                                   # notifications/initialized, cancelled, ...
    try:
        if not isinstance(params, dict):
            raise _RpcError(-32602, 'params must be an object')
        if method == 'initialize':
            asked = params.get('protocolVersion')
            result = {'protocolVersion': asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                      'capabilities': {'tools': {'listChanged': False}}, 'serverInfo': SERVER_INFO,
                      'instructions': INSTRUCTIONS}
        elif method == 'ping':
            result = {}
        elif method == 'tools/list':
            result = {'tools': _listing(rec['scope'])}
        elif method == 'tools/call':
            name = str(params.get('name') or '')
            result, status = _call_tool(name, params.get('arguments') or {}, rec)
            log_audit(rec['owner'], 'vlab.mcp.call', f"{name} ({rec['name']}, {rec['scope']}): {status}", _ctx()['ip'])
        elif method in ('resources/list', 'prompts/list'):
            result = {method.split('/')[0]: []}
        else:
            raise _RpcError(-32601, f'Method not found: {method}')
        return {'jsonrpc': '2.0', 'id': mid, 'result': result}
    except _RpcError as e:
        return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': e.code, 'message': str(e)}}


def _unauthorized(msg, code):
    resp = jsonify({'error': msg, 'code': code})
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = f'Bearer realm="MOAVI Desk MCP", error="invalid_token", error_description="{code}"'
    return resp


def _origin_ok():
    """A browser page may not drive the server (DNS rebinding): an Origin, when sent, is this host."""
    origin = request.headers.get('Origin')
    if not origin:
        return True
    from urllib.parse import urlparse
    try:
        return (urlparse(origin).hostname or '').lower() == (urlparse(request.host_url).hostname or '').lower()
    except ValueError:
        return False


@bp.route('/api/vlab/mcp', methods=['GET', 'DELETE'])
def mcp_no_stream():
    resp = jsonify({'error': 'This MCP server answers POST only (no server stream, no sessions)'})
    resp.status_code = 405
    resp.headers['Allow'] = 'POST'
    return resp


@bp.route('/api/vlab/mcp', methods=['POST'])
def mcp_endpoint():
    from pegaprox.core.db import get_db
    if not _origin_ok():
        return _bad('Origin not allowed', 403, code='ORIGIN')
    auth = request.headers.get('Authorization', '')
    token = auth[7:].strip() if auth.lower().startswith('bearer ') else ''
    if not token:
        return _unauthorized('Authorization: Bearer mcp_... is required', 'AUTH_REQUIRED')
    rec, why = mcp.by_token(token)
    if not rec:
        return _unauthorized({'UNKNOWN': 'Unknown token', 'REVOKED': 'The token was revoked',
                              'EXPIRED': 'The token has expired'}[why], f'TOKEN_{why}')
    if not mcp.settings()['enabled']:
        return _bad('MCP is switched off (플랫폼 설정 > MCP 연동)', 403, code='MCP_OFF')
    user = get_db().get_user(rec['owner'])
    if not user or not user.get('enabled', True):
        return _unauthorized('The account of this token is gone or disabled', 'ACCOUNT_DISABLED')
    if (request.content_length or 0) > MAX_BODY:
        return _bad('Request too large', 413)
    try:
        data = json.loads(request.get_data(cache=False, as_text=True) or 'null')
    except ValueError:
        return jsonify({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}), 400
    ip = get_client_ip()
    g.vlab_mcp = dict(session={'user': rec['owner'], 'role': user.get('role', 'viewer'), 'mcp_token': rec['id'],
                         'mcp_name': rec['name'], 'mcp_scope': rec['scope']},
                ip=ip, base=request.host_url)
    try:
        mcp.used(rec['id'], ip)
    except Exception:          # a standby refuses writes: the call itself still goes on
        pass
    batch = isinstance(data, list)
    answers = [a for a in (_handle(m, rec) for m in (data if batch else [data])) if a is not None]
    if not answers:
        return Response(status=202)
    resp = jsonify(answers if batch else answers[0])
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@bp.route('/api/vlab/mcp/stdio.py', methods=['GET'])
def stdio_bridge():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vlab', 'mcp_stdio.py')
    with open(path, encoding='utf-8') as f:
        return Response(f.read(), mimetype='text/x-python',
                        headers={'Content-Disposition': 'attachment; filename="moavi_mcp_stdio.py"'})


# --- admin: on / off, tokens ---------------------------------------------------------------

def _can(perm):
    from pegaprox.api.helpers import acting_user
    from pegaprox.utils.rbac import has_permission
    return has_permission(acting_user() or {}, perm)


@bp.route('/api/vlab/admin/mcp', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def admin_mcp():
    me = request.session.get('user', '')
    every = _can('admin.settings')
    tools = [{'name': n, 'title': t['title'], 'scope': t['scope'], 'destructive': t['destructive']} for n, t in TOOLS.items()]
    return jsonify(dict(mcp.settings(), tokens=mcp.list_tokens(None if every else me), all_tokens=every,
                        can_manage=_can('vlab.pool.manage'), tools=tools, path='/api/vlab/mcp',
                        protocol=PROTOCOL_VERSIONS[0]))


@bp.route('/api/vlab/admin/mcp', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def admin_mcp_switch():
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get('enabled'), bool):
        return _bad('enabled: true or false')
    me = request.session.get('user', '')
    saved = mcp.set_enabled(data['enabled'], by=me)
    log_audit(me, 'vlab.mcp.settings', f"MCP server {'on' if saved['enabled'] else 'off'}", get_client_ip())
    return jsonify(saved)


@bp.route('/api/vlab/admin/mcp/tokens', methods=['POST'])
@require_auth(perms=['vlab.pool.view'])
def admin_mcp_issue():
    data = request.get_json(silent=True) or {}
    me = request.session.get('user', '')
    name = str(data.get('name') or '').strip()
    if not 1 <= len(name) <= 60 or any(ord(ch) < 32 for ch in name):
        return _bad('name: 1 to 60 characters')
    scope = data.get('scope')
    if scope not in mcp.SCOPES:
        return _bad('scope: read or manage')
    if scope == 'manage' and not _can('vlab.pool.manage'):
        return _bad('A manage token needs the vlab.pool.manage permission', 403, code='MISSING_PERMISSION')
    days = data.get('days', 90)
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= mcp.MAX_DAYS:
        return _bad(f'days: a whole number from 1 to {mcp.MAX_DAYS}')
    if mcp.active_count(me) >= mcp.MAX_TOKENS_PER_USER:
        return _bad(f'At most {mcp.MAX_TOKENS_PER_USER} active tokens per account - revoke one first', 409)
    token, rec = mcp.issue(me, name, scope, days, by=me)
    log_audit(me, 'vlab.mcp.token', f"MCP token '{name}' ({scope}, {days} days, ...{rec['token_hint']}) issued", get_client_ip())
    return jsonify({'token': token, 'record': rec}), 201


@bp.route('/api/vlab/admin/mcp/tokens/<token_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.view'])
def admin_mcp_revoke(token_id):
    me = request.session.get('user', '')
    rec = mcp.get(token_id)
    if not rec or (rec['owner'] != me and not _can('admin.settings')):
        return _bad('Token not found', 404)
    rec = mcp.revoke(token_id, by=me)
    log_audit(me, 'vlab.mcp.token', f"MCP token '{rec['name']}' of {rec['owner']} (...{rec['token_hint']}) revoked", get_client_ip())
    return jsonify({'record': rec})
