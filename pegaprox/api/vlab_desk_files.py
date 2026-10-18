# -*- coding: utf-8 -*-
"""
MOAVI Desk - the portal's 파일 panel: files into and out of the user's own desktop, without
보안 게이트웨이 and without a network path to the desktop - through the QEMU guest agent.

  GET    /api/vlab/me/desktops/<id>/files?path=          list a folder of the user's MOAVI folder     vlab.desk
  GET    /api/vlab/me/desktops/<id>/files/download?path= the file, streamed (4 MiB reads)            vlab.desk
  POST   /api/vlab/me/desktops/<id>/files/mkdir          {path}                                       vlab.desk
  DELETE /api/vlab/me/desktops/<id>/files?path=          a file or a folder (with what is in it)     vlab.desk
  POST   /api/vlab/me/desktops/<id>/files/uploads        {path, name, size} -> {upload_id}            vlab.desk
  PATCH  /api/vlab/me/desktops/<id>/files/uploads/<uid>  Upload-Offset header, application/offset+octet-stream part (<= 8 MiB)
  POST   /api/vlab/me/desktops/<id>/files/uploads/<uid>/finish   sha-256 checked, put in place      vlab.desk
  DELETE /api/vlab/me/desktops/<id>/files/uploads/<uid>  abort

- Only the desktop's own user (assigned, or a shared pool's member): an administrator does not reach
  a user's files through this.
- The root is the user's own folder: Windows %USERPROFILE%\\Desktop\\MOAVI (the profile of that account -
  local or domain - found by its SID), Linux ~/MOAVI. Made when missing; everything in it belongs to
  the user (Linux: the steps run as the user through runuser; Windows: owner set to the user).
- Paths are relative to the root and checked twice: here (safe_rel: no .., no absolute paths, no drive
  or device names, no control characters) and in the guest (the resolved path stays under the root and
  passes no symbolic link / junction).
- Pool policy desktop_files: off / up / down / both, desktop_files_max_mb per file, desktop_files_day_mb
  per user per day (both ways). Every transfer is logged (vlab_desktop_file_log) and audited.
- Nothing is held whole in memory: an upload comes in parts that go on as guest agent file-write pieces
  and are joined in the desktop; a download is read 4 MiB at a time.
- A guest agent that blocks guest-exec / guest-file-* (RHEL / Rocky) answers AGENT_EXEC_DISABLED.
"""

import base64
import concurrent.futures
import hashlib
import logging
import re
import secrets
import threading
import time
import unicodedata

from flask import Blueprint, Response, jsonify, request, stream_with_context

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store

bp = Blueprint('vlab_desk_files', __name__)

_bad = core._bad
_user = core._user

PIECE = 46080                 # bytes per guest agent file-write (Proxmox takes 61440 base64 characters at most)
WRITERS = 6                   # file-writes in flight at once: each is a Proxmox API round trip, the agent itself is fast
PART_MAX = 8 * 1024 * 1024    # one upload request (the engine's request limit is 10 MB)
READ_CHUNK = 4 * 1024 * 1024  # one download read (base64 stays under the agent's 16 MiB output)
LIST_MAX = 2000
UPLOAD_TTL = 2 * 3600
PART_SUFFIX = '.moavi-part'

TEXT = {
    'OFF': '이 풀은 파일 전송을 쓰지 않습니다.',
    'DIRECTION': '이 풀에서는 그 방향의 파일 전송이 꺼져 있습니다.',
    'TOO_BIG': '파일이 너무 큽니다 (최대 {} MB).',
    'QUOTA': '오늘 전송 한도를 넘습니다 (하루 {} MB).',
    'BAD_PATH': '쓸 수 없는 경로입니다.',
    'NO_ACCOUNT': "이 데스크톱에 '{}' 계정(프로필)이 없습니다. 한 번 로그인한 뒤 다시 시도하세요.",
    'NOT_FOUND': '파일이나 폴더가 없습니다.',
    'EXISTS': '같은 이름이 이미 있습니다.',
    'NOT_RUNNING': '데스크톱이 켜져 있지 않습니다.',
    'NO_AGENT': '데스크톱의 게스트 에이전트가 응답하지 않습니다.',
    'FAILED': '데스크톱에서 파일 작업을 하지 못했습니다.',
    'HASH': '전송된 파일이 원본과 다릅니다. 다시 시도하세요.',
}

_SCHEMA = '''CREATE TABLE IF NOT EXISTS vlab_desktop_file_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    desktop_id TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    direction TEXT NOT NULL,
    result TEXT NOT NULL
)'''
TABLES = ('vlab_desktop_file_log',)
_lock = threading.Lock()
_uploads = {}   # upload id -> state (this engine; an upload restarts after a failover)


def db():
    d = store.db()
    if not getattr(d, '_vlab_desk_files', False):
        with _lock:
            if not getattr(d, '_vlab_desk_files', False):
                d.execute(_SCHEMA)
                d._vlab_desk_files = True
    return d


# --- paths -------------------------------------------------------------------------------

_WIN_DEVICES = {'con', 'prn', 'aux', 'nul', 'conin$', 'conout$', 'clock$',
                *(f'com{i}' for i in range(10)), *(f'lpt{i}' for i in range(10))}
_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"\\|?*]')


def safe_name(name):
    """One path component a user may name, or None. Rules of both systems at once: no separators, no
    . / .., no Windows reserved characters or device names, no trailing dot or space, <= 255 bytes."""
    n = unicodedata.normalize('NFC', str(name or ''))
    if not n or n in ('.', '..') or _BAD_CHARS.search(n) or '/' in n:
        return None
    if n != n.strip() or n.endswith('.') or len(n.encode('utf-8')) > 255:
        return None
    if n.split('.')[0].lower() in _WIN_DEVICES:
        return None
    if n.endswith(PART_SUFFIX):
        return None
    return n


def safe_rel(path):
    """A path under the user's root as 'a/b/c' ('' = the root itself), or None when it would leave it."""
    p = str(path or '').replace('\\', '/')
    if p.startswith('/') or re.match(r'^[A-Za-z]:', p) or len(p) > 1024:
        return None
    parts = [x for x in p.split('/') if x != '']
    out = []
    for x in parts:
        n = safe_name(x)
        if not n:
            return None
        out.append(n)
    if len(out) > 32:
        return None
    return '/'.join(out)


def _b64(s):
    return base64.b64encode(s.encode('utf-8')).decode('ascii')


# --- the guest side ------------------------------------------------------------------------
#
# Every script reads its arguments from stdin, never from its command line: line 1 the account,
# line 2 the path (base64 UTF-8), line 3 an operation argument. Exit codes:
#   3 no such account / profile, 23 exists, 24 not found / wrong kind, 26 outside the root or a link

_SH_HEAD = r'''read -r U; read -r P64; read -r X
H=$(getent passwd "$U" | cut -d: -f6); [ -n "$H" ] || { echo "no account" >&2; exit 3; }
R="$H/MOAVI"; [ -L "$R" ] && exit 26
runuser -u "$U" -- mkdir -p -- "$R" || exit 5
RR=$(realpath -e -- "$R") || exit 5
REL=$(printf %s "$P64" | base64 -d) || exit 26
P="$RR"; [ -n "$REL" ] && P="$RR/$REL"
inside() { case "$1" in "$RR"|"$RR"/*) return 0;; *) return 1;; esac; }
existing() { [ -e "$P" ] || exit 24; RP=$(realpath -e -- "$P") || exit 24; [ "$RP" = "$P" ] && inside "$RP" || exit 26; }
fresh() { PD=$(dirname -- "$P"); RPD=$(realpath -e -- "$PD") || exit 24; [ "$RPD" = "$PD" ] && inside "$RPD" || exit 26; [ -d "$PD" ] || exit 24; [ -L "$P" ] && exit 26; }
'''

_SH_OPS = {
    'list': r'''existing; [ -d "$P" ] || exit 24
runuser -u "$U" -- find "$P" -mindepth 1 -maxdepth 1 -printf '%y\t%s\t%T@\t%f\0' 2>/dev/null | head -z -n 2000''',
    'stat': r'''existing; [ -f "$P" ] || exit 24; stat -c %s -- "$P"''',
    'read': r'''existing; [ -f "$P" ] || exit 24; set -- $X
runuser -u "$U" -- dd if="$P" bs=65536 iflag=skip_bytes,count_bytes skip="$1" count="$2" status=none | base64 -w0''',
    'mkdir': r'''fresh; [ -e "$P" ] && exit 23; runuser -u "$U" -- mkdir -- "$P"''',
    'delete': r'''existing; [ "$P" = "$RR" ] && exit 26; runuser -u "$U" -- rm -rf --one-file-system -- "$P"''',
    'up-start': r'''fresh; [ -e "$P" ] && exit 23; T="/tmp/moavi-df-$X"
rm -rf "$T"; mkdir -m 755 "$T" && runuser -u "$U" -- sh -c ': > "$1"' sh "$P.moavi-part"''',
    'up-join': r'''fresh; T="/tmp/moavi-df-$X"; [ -f "$P.moavi-part" ] || exit 24
chmod 644 "$T"/* 2>/dev/null; runuser -u "$U" -- sh -c 'cat "$1"/* >> "$2"' sh "$T" "$P.moavi-part" || exit 5; rm -f "$T"/*''',
    'up-finish': r'''fresh; [ -e "$P" ] && exit 23; rm -rf "/tmp/moavi-df-$X"
runuser -u "$U" -- mv -- "$P.moavi-part" "$P" || exit 5
echo "sha256=$(runuser -u "$U" -- sha256sum -- "$P" | cut -c1-64)"''',
    'up-abort': r'''rm -rf "/tmp/moavi-df-$X"; PD=$(dirname -- "$P"); RPD=$(realpath -e -- "$PD") 2>/dev/null && inside "$RPD" && rm -f -- "$P.moavi-part"; exit 0''',
}

_PS_HEAD = r'''$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = [Text.Encoding]::UTF8; $OutputEncoding = [Text.Encoding]::UTF8
$U = [Console]::In.ReadLine(); $P64 = [Console]::In.ReadLine(); $X = [Console]::In.ReadLine()
try { $sid = (New-Object Security.Principal.NTAccount($U)).Translate([Security.Principal.SecurityIdentifier]).Value }
catch { [Console]::Error.WriteLine('no account'); exit 3 }
$prof = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Select-Object -First 1).LocalPath
if (-not $prof) { [Console]::Error.WriteLine('no profile'); exit 3 }
function Own($p) { icacls $p /setowner "*$sid" /Q | Out-Null }
$R = Join-Path $prof 'Desktop\MOAVI'
if (-not (Test-Path -LiteralPath $R)) { New-Item -ItemType Directory -Path $R -Force | Out-Null; Own $R }
$ri = Get-Item -LiteralPath $R -Force
if ($ri.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 26 }
$RR = $ri.FullName.TrimEnd('\')
$REL = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($P64))
$P = if ($REL) { [IO.Path]::GetFullPath((Join-Path $RR ($REL -replace '/', '\'))) } else { $RR }
function Inside($p) { ($p -ieq $RR) -or $p.StartsWith($RR + '\', [StringComparison]::OrdinalIgnoreCase) }
function NoLinks($p) { $c = $p; while ($c.Length -gt $RR.Length) { if (Test-Path -LiteralPath $c) {
  if ((Get-Item -LiteralPath $c -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false } }
  $c = [IO.Path]::GetDirectoryName($c) }; return $true }
if (-not (Inside $P) -or -not (NoLinks $P)) { exit 26 }
function Existing { if (-not (Test-Path -LiteralPath $P)) { exit 24 } }
function Fresh { $d = [IO.Path]::GetDirectoryName($P); if (-not (Test-Path -LiteralPath $d -PathType Container)) { exit 24 } }
$T = Join-Path $env:SystemRoot ('Temp\moavi-df-' + $X)
'''

_PS_OPS = {
    'list': r'''Existing; if (-not (Test-Path -LiteralPath $P -PathType Container)) { exit 24 }
Get-ChildItem -LiteralPath $P -Force | Select-Object -First 2000 | ForEach-Object {
  $k = if ($_.PSIsContainer) { 'd' } elseif ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { 'l' } else { 'f' }
  $n = if ($_.PSIsContainer) { 0 } else { $_.Length }
  [Console]::Out.Write("$k`t$n`t$(([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeSeconds())`t$($_.Name)`0") }''',
    'stat': r'''Existing; if (-not (Test-Path -LiteralPath $P -PathType Leaf)) { exit 24 }; (Get-Item -LiteralPath $P -Force).Length''',
    'read': r'''Existing; if (-not (Test-Path -LiteralPath $P -PathType Leaf)) { exit 24 }
$a = $X.Split(' '); $off = [long]$a[0]; $len = [int]$a[1]
$fs = [IO.File]::Open($P, 'Open', 'Read', 'ReadWrite'); try { [void]$fs.Seek($off, 'Begin'); $buf = New-Object byte[] $len
  $got = 0; while ($got -lt $len) { $r = $fs.Read($buf, $got, $len - $got); if ($r -le 0) { break }; $got += $r }
  [Console]::Out.Write([Convert]::ToBase64String($buf, 0, $got)) } finally { $fs.Close() }''',
    'mkdir': r'''Fresh; if (Test-Path -LiteralPath $P) { exit 23 }; New-Item -ItemType Directory -Path $P | Out-Null; Own $P''',
    'delete': r'''Existing; if ($P -ieq $RR) { exit 26 }; Remove-Item -LiteralPath $P -Recurse -Force''',
    'up-start': r'''Fresh; if (Test-Path -LiteralPath $P) { exit 23 }
if (Test-Path -LiteralPath $T) { Remove-Item -LiteralPath $T -Recurse -Force }; New-Item -ItemType Directory -Path $T | Out-Null
[IO.File]::Create($P + '.moavi-part').Close()''',
    'up-join': r'''Fresh; $part = $P + '.moavi-part'; if (-not (Test-Path -LiteralPath $part)) { exit 24 }
$out = [IO.File]::Open($part, 'Append', 'Write'); try { Get-ChildItem -LiteralPath $T -File | Sort-Object Name | ForEach-Object {
  $in = [IO.File]::OpenRead($_.FullName); try { $in.CopyTo($out) } finally { $in.Close() }; Remove-Item -LiteralPath $_.FullName -Force } }
finally { $out.Close() }''',
    'up-finish': r'''Fresh; if (Test-Path -LiteralPath $P) { exit 23 }
if (Test-Path -LiteralPath $T) { Remove-Item -LiteralPath $T -Recurse -Force }
Move-Item -LiteralPath ($P + '.moavi-part') -Destination $P; Own $P
"sha256=" + (Get-FileHash -LiteralPath $P -Algorithm SHA256).Hash.ToLower()''',
    'up-abort': r'''if (Test-Path -LiteralPath $T) { Remove-Item -LiteralPath $T -Recurse -Force }
if (Test-Path -LiteralPath ($P + '.moavi-part')) { Remove-Item -LiteralPath ($P + '.moavi-part') -Force }''',
}

_EXIT_CODES = {3: ('NO_ACCOUNT', 409), 23: ('EXISTS', 409), 24: ('NOT_FOUND', 404), 26: ('BAD_PATH', 400)}


def guest_script(guest_os, op):
    if guest_os == 'windows':
        return _PS_HEAD + _PS_OPS[op] + '\nexit 0\n'
    return _SH_HEAD + _SH_OPS[op] + '\n'


def _err(code, status, *fmt):
    return jsonify({'error': TEXT.get(code, TEXT['FAILED']).format(*fmt), 'code': code}), status


class _Fail(Exception):
    def __init__(self, response):
        super().__init__('guest file step failed')
        self.response = response


def agent_text(s):
    """The guest agent's output as Proxmox hands it over: the guest's UTF-8 bytes read as Latin-1
    (found on VM 117: a Korean file name came back as 'MOAVIì\x8b\x9c...'). Undone when that is what it is."""
    if not s:
        return s or ''
    try:
        return s.encode('latin-1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def _run(ctx, op, rel, arg='', wait=60.0):
    """Run one guest step. Returns stdout; raises _Fail(error response)."""
    from pegaprox.api import vlab_next as vn
    cmd = (['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
            guest_script('windows', op)] if ctx['os'] == 'windows' else ['/bin/sh', '-c', guest_script('linux', op)])
    stdin = f"{ctx['account']}\n{_b64(rel)}\n{arg}\n"
    code, out, err, e = vn._agent_run(ctx['mgr'], ctx['node'], ctx['vmid'], cmd, stdin=stdin, wait=wait)
    out, err = agent_text(out), agent_text(err)
    if code == 0:
        return out or ''
    if e and vn.agent_exec_disabled(e):
        raise _Fail((jsonify({'error': vn.AGENT_EXEC_DISABLED_TEXT, 'code': 'AGENT_EXEC_DISABLED'}), 409))
    if code is None:
        logging.warning(f"[VLAB] desktop files {op} on {ctx['desk']['name']}: {e or 'no answer in time'}")
        raise _Fail(_err('NO_AGENT', 502))
    if code in _EXIT_CODES:
        label, status = _EXIT_CODES[code]
        raise _Fail(_err(label, status, ctx['account']) if label == 'NO_ACCOUNT' else _err(label, status))
    logging.warning(f"[VLAB] desktop files {op} on {ctx['desk']['name']} exit {code}: {(err or out or '').strip()[:300]}")
    raise _Fail(_err('FAILED', 502))


def _file_write(ctx, path, data):
    from pegaprox.api import vlab_next as vn
    try:
        resp = ctx['mgr']._api_post(vn._agent(ctx['mgr'], ctx['node'], ctx['vmid'], 'file-write'),
                                    data={'file': path, 'content': base64.b64encode(data).decode('ascii'), 'encode': 0})
    except Exception as e:
        logging.warning(f"[VLAB] desktop files write on {ctx['desk']['name']}: {str(e)[:200]}")
        raise _Fail(_err('NO_AGENT', 502))
    if getattr(resp, 'status_code', 0) != 200:
        text = getattr(resp, 'text', '') or ''
        if vn.agent_exec_disabled(text):
            raise _Fail((jsonify({'error': vn.AGENT_EXEC_DISABLED_TEXT, 'code': 'AGENT_EXEC_DISABLED'}), 409))
        logging.warning(f"[VLAB] desktop files write on {ctx['desk']['name']}: {text[:200]}")
        raise _Fail(_err('FAILED', 502))


def _piece_path(ctx, upload_id, n):
    if ctx['os'] == 'windows':
        return f'C:\\Windows\\Temp\\moavi-df-{upload_id}\\{n:07d}'
    return f'/tmp/moavi-df-{upload_id}/{n:07d}'


# --- who, where, what may move ---------------------------------------------------------------

def _context(desktop_id):
    """(ctx, None) for the caller's own running desktop, or (None, error response)."""
    from pegaprox.api.vlab_next import _guest_os, shared_member
    from pegaprox.vlab.warpgate import ssh_login_name
    username = _user()
    desk = store.get_desktop(desktop_id)
    if not desk or (desk['assigned_user'] != username and not shared_member(desk, username)):
        return None, _bad('Desktop not found', 404)
    pol = pool_policy.effective((store.get_pool(desk['pool_id']) or {}).get('settings'))
    if pol.get('desktop_files', 'off') == 'off':
        return None, _err('OFF', 403)
    if desk.get('vm_type', 'qemu') != 'qemu':
        return None, _err('NO_AGENT', 409)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, _bad('Cluster not connected', 503)
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if live.get('status') != 'running':
        return None, _err('NOT_RUNNING', 409)
    node = live.get('node') or desk['node']
    guest_os = _guest_os(mgr, node, int(desk['vmid']))
    if not guest_os:
        return None, _err('NO_AGENT', 409)
    account = ssh_login_name(username)
    if not account:
        return None, _err('NO_ACCOUNT', 409, username)
    return {'desk': desk, 'pol': pol, 'mgr': mgr, 'node': node, 'vmid': int(desk['vmid']), 'os': guest_os,
            'user': username, 'account': account}, None


def _may(ctx, direction):
    return ctx['pol'].get('desktop_files', 'off') in ('both', direction)


def _today_bytes(username):
    from datetime import datetime, timezone
    day = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    r = db().query_one("SELECT COALESCE(SUM(size), 0) AS n FROM vlab_desktop_file_log WHERE username = ? AND result = 'ok' AND ts >= ?",
                       (username, day))
    return int(r['n'] or 0) if r else 0


def _limits(ctx, size):
    """None, or the error response when `size` breaks the pool's per-file or per-day limit."""
    cap = int(ctx['pol'].get('desktop_files_max_mb') or 500)
    if size > cap * 1024 * 1024:
        return _err('TOO_BIG', 413, cap)
    day = int(ctx['pol'].get('desktop_files_day_mb') or 0)
    if day and _today_bytes(ctx['user']) + size > day * 1024 * 1024:
        return _err('QUOTA', 409, day)
    return None


def _log(ctx, path, size, direction, result):
    db().execute('INSERT INTO vlab_desktop_file_log (id, ts, username, desktop_id, path, size, direction, result) '
                 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (secrets.token_hex(8), store.now(), ctx['user'], ctx['desk']['id'], path, int(size), direction, result))
    log_audit(ctx['user'], f'vlab.desktop.files.{direction}',
              f"'{ctx['desk']['name']}' MOAVI/{path} ({size} bytes) {result}", get_client_ip())


def _rel_arg(name='path', source=None):
    src = source if source is not None else request.args
    rel = safe_rel(src.get(name, ''))
    return rel


# --- routes ------------------------------------------------------------------------------------

@bp.route('/api/vlab/me/desktops/<desktop_id>/files', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def list_files(desktop_id):
    ctx, err = _context(desktop_id)
    if err:
        return err
    rel = _rel_arg()
    if rel is None:
        return _err('BAD_PATH', 400)
    try:
        out = _run(ctx, 'list', rel, wait=30.0)
    except _Fail as f:
        return f.response
    entries = []
    for item in out.split('\0'):
        parts = item.strip('\r\n').split('\t', 3)
        if len(parts) != 4 or not parts[3] or parts[3].endswith(PART_SUFFIX):
            continue
        try:
            entries.append({'name': parts[3], 'kind': {'d': 'dir', 'f': 'file'}.get(parts[0], 'link'),
                            'size': int(float(parts[1])) if parts[0] == 'f' else 0, 'mtime': int(float(parts[2]))})
        except ValueError:
            continue
    entries.sort(key=lambda e: (e['kind'] != 'dir', e['name'].lower()))
    return jsonify({'path': rel, 'entries': entries[:LIST_MAX], 'root': 'MOAVI',
                    'policy': {'desktop_files': ctx['pol']['desktop_files'], 'max_mb': ctx['pol']['desktop_files_max_mb']}})


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/mkdir', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def make_folder(desktop_id):
    ctx, err = _context(desktop_id)
    if err:
        return err
    if not _may(ctx, 'up'):
        return _err('DIRECTION', 403)
    rel = _rel_arg(source=request.get_json(silent=True) or {})
    if not rel:
        return _err('BAD_PATH', 400)
    try:
        _run(ctx, 'mkdir', rel, wait=20.0)
    except _Fail as f:
        return f.response
    log_audit(ctx['user'], 'vlab.desktop.files.mkdir', f"'{ctx['desk']['name']}' MOAVI/{rel}", get_client_ip())
    return jsonify({'path': rel}), 201


@bp.route('/api/vlab/me/desktops/<desktop_id>/files', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def delete_file(desktop_id):
    ctx, err = _context(desktop_id)
    if err:
        return err
    if not _may(ctx, 'up'):
        return _err('DIRECTION', 403)
    rel = _rel_arg()
    if not rel:
        return _err('BAD_PATH', 400)
    try:
        _run(ctx, 'delete', rel, wait=60.0)
    except _Fail as f:
        return f.response
    log_audit(ctx['user'], 'vlab.desktop.files.delete', f"'{ctx['desk']['name']}' MOAVI/{rel}", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/download', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def download_file(desktop_id):
    ctx, err = _context(desktop_id)
    if err:
        return err
    if not _may(ctx, 'down'):
        return _err('DIRECTION', 403)
    rel = _rel_arg()
    if not rel:
        return _err('BAD_PATH', 400)
    try:
        size = int((_run(ctx, 'stat', rel, wait=20.0) or '0').strip().splitlines()[-1])
    except _Fail as f:
        return f.response
    except ValueError:
        return _err('FAILED', 502)
    limit = _limits(ctx, size)
    if limit:
        return limit

    def stream():
        sent, result = 0, 'failed'
        try:
            while sent < size:
                n = min(READ_CHUNK, size - sent)
                data = base64.b64decode((_run(ctx, 'read', rel, f'{sent} {n}', wait=120.0) or '').strip())
                if not data:
                    break
                sent += len(data)
                yield data
            result = 'ok' if sent == size else 'short'
        except _Fail:
            result = 'failed'
        finally:
            _log(ctx, rel, sent, 'down', result)

    name = rel.rsplit('/', 1)[-1]
    from urllib.parse import quote
    resp = Response(stream_with_context(stream()), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(size)
    resp.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{quote(name)}"
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _sweep_uploads():
    now_t = time.time()
    with _lock:
        for k in [k for k, v in _uploads.items() if now_t - v['at'] > UPLOAD_TTL]:
            _uploads.pop(k, None)


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/uploads', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def start_upload(desktop_id):
    ctx, err = _context(desktop_id)
    if err:
        return err
    if not _may(ctx, 'up'):
        return _err('DIRECTION', 403)
    body = request.get_json(silent=True) or {}
    folder = safe_rel(body.get('path', ''))
    name = safe_name(body.get('name'))
    try:
        size = int(body.get('size'))
    except (TypeError, ValueError):
        size = -1
    if folder is None or not name or size < 0:
        return _err('BAD_PATH', 400)
    limit = _limits(ctx, size)
    if limit:
        return limit
    rel = f'{folder}/{name}' if folder else name
    uid = secrets.token_hex(12)
    try:
        _run(ctx, 'up-start', rel, uid, wait=30.0)
    except _Fail as f:
        return f.response
    _sweep_uploads()
    with _lock:
        _uploads[uid] = {'user': ctx['user'], 'desk': ctx['desk']['id'], 'rel': rel, 'size': size, 'received': 0,
                         'piece': 0, 'sha': hashlib.sha256(), 'at': time.time()}
    return jsonify({'upload_id': uid, 'path': rel, 'part_max': PART_MAX}), 201


def _upload_of(desktop_id, uid):
    with _lock:
        up = _uploads.get(uid)
    if not up or up['user'] != _user() or up['desk'] != desktop_id:
        return None
    return up


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/uploads/<uid>', methods=['PATCH'])
@require_auth(perms=['vlab.desk'])
def upload_part(desktop_id, uid):
    up = _upload_of(desktop_id, uid)
    if not up:
        return _bad('Upload not found', 404)
    ctx, err = _context(desktop_id)
    if err:
        return err
    try:
        offset = int(request.headers.get('Upload-Offset', '-1'))
    except ValueError:
        offset = -1
    if offset != up['received']:
        return jsonify({'error': 'Upload-Offset does not match', 'code': 'OFFSET', 'received': up['received']}), 409
    length = request.content_length or 0
    if length <= 0 or length > PART_MAX or up['received'] + length > up['size']:
        return _err('TOO_BIG', 413, ctx['pol']['desktop_files_max_mb'])
    got, jobs = 0, []
    while got < length:
        piece = request.stream.read(min(PIECE, length - got))
        if not piece:
            break
        jobs.append((_piece_path(ctx, uid, up['piece'] + len(jobs)), piece))
        got += len(piece)
    if got != length:
        return _bad('The part ended early', 400)
    try:
        # the pieces of one part (<= 8 MiB) go out several at a time, each to its own numbered file;
        # the join then takes them in order
        with concurrent.futures.ThreadPoolExecutor(max_workers=WRITERS) as pool:
            for f in [pool.submit(_file_write, ctx, path, data) for path, data in jobs]:
                f.result()
        _run(ctx, 'up-join', up['rel'], uid, wait=120.0)
    except _Fail as f:
        return f.response
    for _path, data in jobs:
        up['sha'].update(data)
    up['piece'] += len(jobs)
    up['received'] += got
    up['at'] = time.time()
    return jsonify({'received': up['received'], 'size': up['size']})


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/uploads/<uid>/finish', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def finish_upload(desktop_id, uid):
    up = _upload_of(desktop_id, uid)
    if not up:
        return _bad('Upload not found', 404)
    ctx, err = _context(desktop_id)
    if err:
        return err
    if up['received'] != up['size']:
        return jsonify({'error': 'The upload is not complete', 'code': 'INCOMPLETE', 'received': up['received']}), 409
    try:
        out = _run(ctx, 'up-finish', up['rel'], uid, wait=300.0)
    except _Fail as f:
        _log(ctx, up['rel'], up['received'], 'up', 'failed')
        return f.response
    with _lock:
        _uploads.pop(uid, None)
    got = dict(line.strip().split('=', 1) for line in out.splitlines() if '=' in line)
    if got.get('sha256') != up['sha'].hexdigest():
        _log(ctx, up['rel'], up['size'], 'up', 'hash mismatch')
        return _err('HASH', 502)
    _log(ctx, up['rel'], up['size'], 'up', 'ok')
    return jsonify({'path': up['rel'], 'size': up['size'], 'sha256': got['sha256']})


@bp.route('/api/vlab/me/desktops/<desktop_id>/files/uploads/<uid>', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def abort_upload(desktop_id, uid):
    up = _upload_of(desktop_id, uid)
    if not up:
        return _bad('Upload not found', 404)
    with _lock:
        _uploads.pop(uid, None)
    ctx, err = _context(desktop_id)
    if not err:
        try:
            _run(ctx, 'up-abort', up['rel'], uid, wait=30.0)
        except _Fail:
            pass
        _log(ctx, up['rel'], up['received'], 'up', 'aborted')
    return jsonify({'success': True})
