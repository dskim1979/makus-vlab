# -*- coding: utf-8 -*-
"""
MOAVI Desk - shared storage (공유 저장소): a NAS share the desktops and build VMs of a pool reach,
with folders by purpose (the Dell PowerScale EDA layout):

  home     <root>/home/{username}         small; snapshots and a daily backup on the NAS
  project  <root>/projects/{department}   the team's; snapshots and long-term backup; made by the admin
  scratch  <root>/scratch/{username}      big and fast; no backup; build job folders kept N days

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

One setting per pool (vlab_pool_storage; an SMB service account's password sealed with the core
DB key in password_encrypted, never in a read). The engine checks it through the QEMU guest agent
when a user connects, when a shared pool routes someone and before a build job starts
(pegaprox/api/vlab_next.py ensure_storage) and keeps the result per desktop and user
(vlab_storage_mounts).

How the guest reaches the share:

  Linux     autofs: /etc/auto.master.d/moavi.autofs + /etc/auto.moavi (one wildcard line: <root>/home
            is server:<export>/home, ...). Put once into the template or golden image; the engine
            only checks the map is there and the same, and writes it when not. A mount then comes
            and goes with use, also while the engine or the agent is away. NFSv3 (fast on
            metadata-heavy EDA trees) or NFSv4.1 with Kerberos (sec=krb5p). SMB: cifs multiuser
            with Kerberos - each user with their own ticket. Without autofs on the guest the
            share is mounted directly and the result says NO_AUTOFS.
            SMB without a domain (service account): each user's folders are mounted one by one
            with that user's uid, 0700 - the NAS sees one account, the VM keeps users apart.
  Windows   a sign-in script in the all-users Startup folder runs as the user who signs in and maps
            the drives (home H:, project P:, scratch S:) with that user's own sign-in - the agent
            runs as SYSTEM, a drive it maps is not in the user's session. With AD, a GPO drive map
            (\\\\server\\share\\home\\%USERNAME%) does the same; the engine's script is then
            harmless. NFS on Windows is not set up (UNSUPPORTED).

Who makes a user's folder - never root on the VM (NFS root_squash makes it nobody):

  user      in the user's own context: the sign-in scripts (profile.d on Linux, the Startup script
            on Windows) and the engine through `runuser -u <user>` on Linux. The admin makes only
            the top folders: NFS home/ and scratch/ mode 1777 (sticky, like /tmp); SMB the FSLogix
            rights (users: modify this folder only, CREATOR OWNER: modify subfolders and files).
  engine    NFS: on the engine host, under admin_path - the same export mounted there, no_root_squash
            for the engine's address only - made and given to the user's uid/gid (as the guest's
            SSSD reports them). At the first connect, and when a pool grant names a user whose ids
            the engine has seen.

Office desktops (Windows, SMB with a home folder):

  win_redirect      the sign-in script also points the user's 바탕 화면 · 문서 · 다운로드 · 사진
                    (HKCU User Shell Folders) at the home drive, so files land on the NAS; Explorer
                    reads it at the next sign-in. With AD a GPO folder redirection does the same.
  win_block_local   the engine (as SYSTEM) sets the Explorer policies NoDrives / NoViewOnDrive for
                    C: (HKLM, every account on the VM): C: is hidden and refused in Explorer and in
                    the open / save dialogs, programs still run. Only with win_redirect - the
                    folders a user saves to are then on the NAS. Turned off, the engine removes
                    the two values when they are still its own (4 = C:).

Project folders are the team's: the admin makes them with the team's group on the NAS; the engine
only says when one is missing (PROJECT_MISSING, a warning).

"Owner only" (700) means something on NFS only when every VM and the NAS agree on the user's
uid/gid (AD/LDAP with SSSD id mapping). A user known only from the VM's /etc/passwd is reported
(LOCAL_ACCOUNT, a warning): use all_squash + anonuid per user export, or one project group, then.
"""

import base64
import json
import os
import re
import shlex
import threading

from pegaprox.vlab.store import db as _store_db, now

KINDS = ('nfs', 'smb')
NFS_VERSIONS = ('3', '4.1', 'krb5')
SMB_AUTH = ('kerberos', 'service')
CREATE_BY = ('user', 'engine')
TEMPLATES = ('home', 'project', 'scratch')
TOKENS = ('{username}', '{department}', '{pool}')

FOLDER_DEFAULTS = {
    'home': {'enabled': True, 'rule': 'home/{username}', 'drive': 'H', 'quota_gb': 0},
    'project': {'enabled': False, 'rule': 'projects/{department}', 'drive': 'P', 'quota_gb': 0},
    'scratch': {'enabled': True, 'rule': 'scratch/{username}', 'drive': 'S', 'quota_gb': 0, 'retention_days': 14},
}

DEFAULTS = {
    'enabled': False,
    'kind': 'nfs',
    'server': '',
    'share': '',             # NFS: the export (/export/eda); SMB: the share (eda)
    'nfs_version': '3',
    'options': '',           # extra mount options (Linux)
    'linux_path': '/nas',    # the autofs root: /nas/home/alice, /nas/scratch/alice
    'create_by': 'user',
    'admin_path': '',        # engine host: where the export is mounted for create_by=engine
    'private': True,
    'build_workdir': True,   # build jobs start in scratch/{username}/{job id}
    'smb_auth': 'kerberos',
    'smb_domain': '',
    'smb_user': '',
    'win_redirect': False,   # Windows: 바탕 화면 · 문서 · 다운로드 · 사진 on the home drive
    'win_block_local': False,  # Windows: hide and refuse C: in Explorer and the file dialogs
    'folders': FOLDER_DEFAULTS,
}

# the user's folders redirected to the home drive: (HKCU User Shell Folders value, folder)
REDIRECTS = (('Desktop', 'Desktop'), ('Personal', 'Documents'), ('{374DE290-123F-4565-9164-39C4925E467B}', 'Downloads'),
             ('My Pictures', 'Pictures'))
EXPLORER_POLICY = r'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
DRIVE_C = 4   # the NoDrives / NoViewOnDrive bit of C:

# exit status of the guest scripts
CODES = {0: 'OK', 10: 'MOUNT_FAILED', 11: 'FOLDER_DENIED', 12: 'NO_USER', 13: 'NO_CLIENT',
         14: 'OWNER', 15: 'UNSUPPORTED', 16: 'NO_CREDENTIAL'}
# warnings that leave a result good
WARNINGS = ('LOCAL_ACCOUNT', 'NO_AUTOFS', 'PROJECT_MISSING', 'AT_SIGN_IN', 'OVER_QUOTA')

_HOST = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9A-Fa-f:]+$')
_NFS_EXPORT = re.compile(r'^/[A-Za-z0-9._/-]{0,250}$')
_SMB_SHARE = re.compile(r'^[A-Za-z0-9._$-]{1,80}(/[A-Za-z0-9._-]{1,80}){0,8}$')
_ABS_PATH = re.compile(r'^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,8}$')
_OPTIONS = re.compile(r'^[A-Za-z0-9=,._:-]{0,200}$')
_RULE = re.compile(r'^(\{username\}|\{department\}|\{pool\}|[A-Za-z0-9._-])+(/(\{username\}|\{department\}|\{pool\}|[A-Za-z0-9._-])+){0,4}$')
_ACCOUNT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_DOMAIN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_RESERVED = ('/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/opt', '/proc', '/root',
             '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr', '/var', '/mnt', '/media')
_OPTION_KEYS_REFUSED = ('credentials', 'password', 'pass', 'username', 'user', 'sec', 'multiuser', 'cruid', 'vers', 'nfsvers')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_pool_storage (
        id TEXT PRIMARY KEY,
        config TEXT NOT NULL DEFAULT '{}',
        password_encrypted TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_storage_mounts (
        desktop_id TEXT NOT NULL,
        username TEXT NOT NULL DEFAULT '',
        pool_id TEXT NOT NULL,
        ok INTEGER,
        code TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        changed INTEGER NOT NULL DEFAULT 0,
        os TEXT NOT NULL DEFAULT '',
        warnings TEXT NOT NULL DEFAULT '[]',
        usage TEXT NOT NULL DEFAULT '{}',
        usage_at TEXT,
        cleaned_at TEXT,
        at TEXT NOT NULL,
        PRIMARY KEY (desktop_id, username)
    )''',
    # the uid/gid a guest's SSSD gave a user: what create_by=engine gives folders to
    '''CREATE TABLE IF NOT EXISTS vlab_storage_ids (
        username TEXT PRIMARY KEY,
        uid INTEGER NOT NULL,
        gid INTEGER NOT NULL,
        local INTEGER NOT NULL DEFAULT 0,
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_pool_storage', 'vlab_storage_mounts', 'vlab_storage_ids')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_nas', False):
        with _lock:
            if not getattr(d, '_vlab_nas', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_nas = True
    return d


def _copy_defaults():
    return dict(DEFAULTS, folders={k: dict(v) for k, v in FOLDER_DEFAULTS.items()})


# --- the setting -------------------------------------------------------------------------

def _row(pool_id):
    r = db().query_one('SELECT * FROM vlab_pool_storage WHERE id = ?', (pool_id,))
    return dict(r) if r else None


def get(pool_id):
    """The pool's setting with defaults filled in, and has_password - never the password."""
    r = _row(pool_id)
    out = _copy_defaults()
    if r:
        try:
            stored = json.loads(r['config'] or '{}')
        except ValueError:
            stored = {}
        out.update({k: v for k, v in stored.items() if k in DEFAULTS and k != 'folders'})
        for k, f in (stored.get('folders') or {}).items():
            if k in out['folders'] and isinstance(f, dict):
                out['folders'][k].update({x: y for x, y in f.items() if x in FOLDER_DEFAULTS[k]})
    out['has_password'] = bool(r and r['password_encrypted'])
    return out


def password(pool_id):
    """The SMB service account's password, for the guest script only."""
    r = _row(pool_id)
    if not r or not r['password_encrypted']:
        return ''
    from pegaprox.core.db import get_db
    try:
        return get_db()._decrypt(r['password_encrypted'])
    except Exception:
        return ''


def save(pool_id, cfg, new_password=None):
    """new_password: None keeps the stored one, '' clears it."""
    cfg = {k: cfg[k] for k in DEFAULTS if k in cfg}
    r = _row(pool_id)
    sealed = r['password_encrypted'] if r else ''
    if new_password is not None:
        from pegaprox.core.db import get_db
        sealed = get_db()._encrypt(new_password) if new_password else ''
    db().execute('INSERT OR REPLACE INTO vlab_pool_storage (id, config, password_encrypted, updated_at) VALUES (?, ?, ?, ?)',
                 (pool_id, json.dumps(cfg, ensure_ascii=False), sealed, now()))
    return get(pool_id)


def forget_pool(pool_id):
    db().execute('DELETE FROM vlab_pool_storage WHERE id = ?', (pool_id,))
    db().execute('DELETE FROM vlab_storage_mounts WHERE pool_id = ?', (pool_id,))


def _folder(key, data, cur):
    """One folder template, merged over `cur`. (template, error)."""
    if not isinstance(data, dict):
        return None, f'folders.{key}: an object'
    out = dict(cur)
    for k, v in data.items():
        if k not in FOLDER_DEFAULTS[key]:
            return None, f'folders.{key}: unknown field {k}'
        if k == 'enabled' and not isinstance(v, bool):
            return None, f'folders.{key}.enabled must be true or false'
        if k in ('quota_gb', 'retention_days') and (not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 1000000):
            return None, f'folders.{key}.{k} must be a whole number, 0 for none'
        if k in ('rule', 'drive') and not isinstance(v, str):
            return None, f'folders.{key}.{k} must be text'
        out[k] = v.strip() if isinstance(v, str) else v
    out['drive'] = out['drive'].rstrip(':').upper()
    if not re.match(r'^[D-Z]$', out['drive']):
        return None, f'folders.{key}.drive: one letter from D to Z'
    if not _RULE.match(out['rule']) or '..' in out['rule']:
        return None, f'folders.{key}.rule: letters, digits, . _ - and / with {{username}}, {{department}} or {{pool}}'
    if key == 'project':
        if '{username}' in out['rule']:
            return None, 'folders.project.rule is the team\'s folder: {department} or {pool}, not {username}'
    elif '{username}' not in out['rule']:
        return None, f'folders.{key}.rule must contain {{username}}'
    return out, None


def validate(data, current):
    """(setting, new_password, None) or (None, None, error). Fields left out keep what
    `current` has; smb_password sets the password, clear_password removes it."""
    if not isinstance(data, dict):
        return None, None, 'JSON object required'
    unknown = sorted(set(data) - set(DEFAULTS) - {'smb_password', 'clear_password', 'has_password'})
    if unknown:
        return None, None, f"unknown fields: {', '.join(unknown)}"
    out = {k: current.get(k, v) for k, v in DEFAULTS.items() if k != 'folders'}
    folders = {k: dict((current.get('folders') or {}).get(k) or FOLDER_DEFAULTS[k]) for k in TEMPLATES}
    for k in DEFAULTS:
        if k not in data:
            continue
        v = data[k]
        if k == 'folders':
            if not isinstance(v, dict) or set(v) - set(TEMPLATES):
                return None, None, 'folders: home, project and scratch'
            for key, f in v.items():
                folders[key], err = _folder(key, f, folders[key])
                if err:
                    return None, None, err
            continue
        if isinstance(DEFAULTS[k], bool):
            if not isinstance(v, bool):
                return None, None, f'{k} must be true or false'
        elif not isinstance(v, str):
            return None, None, f'{k} must be text'
        else:
            v = v.strip()
        out[k] = v
    for key in TEMPLATES:
        folders[key], err = _folder(key, {}, folders[key])
        if err:
            return None, None, err
    out['folders'] = folders
    out['linux_path'] = out['linux_path'].rstrip('/') or '/'
    if out['kind'] not in KINDS:
        return None, None, 'kind must be nfs or smb'
    if out['nfs_version'] not in NFS_VERSIONS:
        return None, None, 'nfs_version must be 3, 4.1 or krb5'
    if out['smb_auth'] not in SMB_AUTH:
        return None, None, 'smb_auth must be kerberos or service'
    if out['create_by'] not in CREATE_BY:
        return None, None, 'create_by must be user or engine'
    if out['server'] and not _HOST.match(out['server'].strip('[]')):
        return None, None, 'server must be a host name or an IP address'
    out['server'] = out['server'].strip('[]')
    if out['share']:
        if out['kind'] == 'nfs' and (not _NFS_EXPORT.match(out['share']) or '..' in out['share']):
            return None, None, 'share: an NFS export path like /export/eda'
        if out['kind'] == 'smb':
            out['share'] = out['share'].replace('\\', '/').strip('/')
            if not _SMB_SHARE.match(out['share']) or '..' in out['share']:
                return None, None, 'share: an SMB share name like eda'
    if not _ABS_PATH.match(out['linux_path']) or '..' in out['linux_path'] or out['linux_path'] in _RESERVED:
        return None, None, 'linux_path: a folder like /nas (not a system folder)'
    if out['admin_path'] and (not _ABS_PATH.match(out['admin_path']) or '..' in out['admin_path'] or out['admin_path'] in _RESERVED):
        return None, None, 'admin_path: where the export is mounted on the engine host, like /srv/moavi-nas/eda'
    if not _OPTIONS.match(out['options']):
        return None, None, 'options: comma separated mount options'
    keys = {o.split('=', 1)[0].lower() for o in out['options'].split(',') if o}
    if keys & set(_OPTION_KEYS_REFUSED):
        return None, None, f"options: {', '.join(sorted(keys & set(_OPTION_KEYS_REFUSED)))} are set by MOAVI Desk"
    if out['smb_domain'] and not _DOMAIN.match(out['smb_domain']):
        return None, None, 'smb_domain: a domain like CORP or corp.example.com'
    if out['smb_user'] and not _ACCOUNT.match(out['smb_user']):
        return None, None, 'smb_user: an account name (letters, digits, . _ -)'
    new_password = None
    if data.get('clear_password') is True:
        new_password = ''
    pw = data.get('smb_password')
    if pw not in (None, ''):
        if not isinstance(pw, str) or len(pw) > 256 or any(c in pw for c in '\r\n\0'):
            return None, None, 'smb_password: at most 256 characters on one line'
        new_password = pw
    if out['enabled']:
        if not out['server'] or not out['share']:
            return None, None, 'server and share are required'
        if not any(folders[k]['enabled'] for k in TEMPLATES):
            return None, None, 'turn on at least one folder (home, project or scratch)'
        if out['create_by'] == 'engine':
            if out['kind'] != 'nfs':
                return None, None, 'create_by engine is for NFS; SMB folders are made by the user (FSLogix rights)'
            if not out['admin_path']:
                return None, None, 'create_by engine needs admin_path (the export mounted on the engine host)'
        if out['win_redirect'] and not folders['home']['enabled']:
            return None, None, 'win_redirect needs the home folder (the drive the folders go to)'
        if out['win_block_local'] and not out['win_redirect']:
            return None, None, 'win_block_local needs win_redirect - the folders users save to must be on the NAS first'
        if out['kind'] == 'smb' and out['smb_auth'] == 'service':
            have = current.get('has_password') if new_password is None else bool(new_password)
            if not out['smb_user'] or not have:
                return None, None, 'the SMB service account needs a user name and a password'
    return out, new_password, None


# --- names and paths ---------------------------------------------------------------------

def guest_name(username):
    """The account name on the guest: CORP\\alice and alice@corp.example.com are alice.
    None when it cannot be one safely."""
    name = str(username or '').split('\\')[-1].split('@')[0]
    return name if _NAME.match(name) else None


def _part(text, fallback):
    """A department or pool name as one folder name: letters (any script), digits, . _ -"""
    s = re.sub(r'[^\w.-]+', '_', str(text or ''), flags=re.UNICODE).strip('._')
    return s[:64] or fallback


def folders_for(cfg, username, department='', pool=''):
    """{template: folder under the share ('/' separated)} of the turned-on templates.
    ValueError for a user name that cannot be a folder."""
    name = guest_name(username)
    if not name:
        raise ValueError(f'{username!r} cannot be used as a folder name')
    out = {}
    for key in TEMPLATES:
        f = cfg['folders'][key]
        if f['enabled']:
            out[key] = (f['rule'].replace('{username}', name).replace('{department}', _part(department, 'no-department'))
                        .replace('{pool}', _part(pool, 'pool')))
    return out


def paths(cfg, folders):
    """{template: {linux, windows, nas}} - where the user finds each folder."""
    out = {}
    for key, folder in folders.items():
        win_sub = folder.replace('/', '\\')
        if cfg['kind'] == 'smb':
            nas = f"\\\\{cfg['server']}\\{cfg['share'].replace('/', chr(92))}\\{win_sub}"
        else:
            nas = f"{cfg['server']}:{cfg['share'].rstrip('/')}/{folder}"
        out[key] = {'linux': f"{cfg['linux_path']}/{folder}", 'nas': nas,
                    'windows': f"{cfg['folders'][key]['drive']}:\\" if cfg['kind'] == 'smb' else None}
    return out


# --- the guest scripts -------------------------------------------------------------------

def _q(s):
    return shlex.quote(str(s))


AUTOFS_MASTER = '/etc/auto.master.d/moavi.autofs'
AUTOFS_MAP = '/etc/auto.moavi'
PROFILE_SCRIPT = '/etc/profile.d/moavi-nas.sh'


def autofs_files(cfg, datasets_line=None):
    """(auto.master.d line, map) for Linux - the same files belong in the template image.
    datasets_line: the read-only `datasets` multi-mount of the research datasets
    (pegaprox/vlab/datasets.py autofs_entry); a key of its own wins over the wildcard."""
    opts = cfg['options']
    if cfg['kind'] == 'nfs':
        ver = {'3': 'vers=3', '4.1': 'vers=4.1', 'krb5': 'vers=4.1,sec=krb5p'}[cfg['nfs_version']]
        o = ','.join(x for x in ('-fstype=nfs', ver, 'hard', opts) if x)
        line = f"* {o} {cfg['server']}:{cfg['share'].rstrip('/')}/&"
    else:
        o = ','.join(x for x in ('-fstype=cifs', 'sec=krb5', 'multiuser', 'cruid=0', opts) if x)
        line = f"* {o} ://{cfg['server']}/{cfg['share']}/&"
    master = f"{cfg['linux_path']} {AUTOFS_MAP} --timeout=600\n"
    head = '# MOAVI Desk shared storage - written by the engine; put the same in the template image\n'
    return head + master, head + (datasets_line + '\n' if datasets_line else '') + line + '\n'


def profile_script(cfg, users):
    """/etc/profile.d: each user makes their own folders at sign-in (create_by user)."""
    out = ['# MOAVI Desk shared storage: your folders on the NAS (written by the engine)',
           'case "$(id -un 2>/dev/null)" in']
    for name in sorted(users):
        dirs = ' '.join(_q(f"{cfg['linux_path']}/{f}") for k, f in sorted(users[name].items()) if k != 'project')
        if dirs:
            out.append(f'  {name}) for d in {dirs}; do [ -d "$d" ] || {{ mkdir -p "$d" && chmod 700 "$d"; }} 2>/dev/null; done ;;')
    out += ['esac']
    return '\n'.join(out) + '\n'


def _write_if_changed(path, text, mode='644'):
    b = base64.b64encode(text.encode('utf-8')).decode('ascii')
    return (f'W=$(printf %s {_q(b)} | base64 -d); '
            f'if [ "$(cat {_q(path)} 2>/dev/null)" != "$W" ]; then mkdir -p "$(dirname {_q(path)})"; '
            f'printf "%s\\n" "$W" > {_q(path)}; chmod {mode} {_q(path)}; changed=1; fi')


def linux_script(cfg, user, folders, users=None, measure=False, cleanup_days=0, datasets_line=None):
    """sh for the guest agent (as root). user None: the share alone. Prints key=value lines
    (changed, uid, gid, local, missing, usage) and exits with CODES. Never makes a user's
    folder as root: create_by user goes through runuser, create_by engine reports `missing`."""
    m = cfg['linux_path']
    lines = ['set -u', 'changed=0', f'M={_q(m)}']
    per_user_smb = cfg['kind'] == 'smb' and cfg['smb_auth'] == 'service'
    pkg = 'mount.nfs' if cfg['kind'] == 'nfs' else 'mount.cifs'
    lines += [f'command -v {pkg} >/dev/null 2>&1 || {{ echo "{"nfs-common (nfs-utils)" if cfg["kind"] == "nfs" else "cifs-utils"} is not installed" >&2; exit 13; }}']
    if per_user_smb:
        src = f"//{cfg['server']}/{cfg['share']}"
        opts = cfg['options']
        lines += ['umask 077', 'mkdir -p /etc/moavi',
                  f"{{ printf 'username=%s\\n' {_q(cfg['smb_user'])}; "
                  + (f"printf 'domain=%s\\n' {_q(cfg['smb_domain'])}; " if cfg['smb_domain'] else '')
                  + "printf 'password='; cat; printf '\\n'; } > /etc/moavi/nas.cred", 'umask 022']
        if not user:
            o = ','.join(x for x in ('credentials=/etc/moavi/nas.cred', opts) if x)
            lines += ['R=/run/moavi/nas-root', 'mkdir -p "$R"', f'timeout 25 mount -t cifs -o {_q(o)} {_q(src)} "$R" || exit 10',
                      'umount "$R"', 'echo changed=$changed']
            return '\n'.join(lines) + '\n'
    else:
        master, amap = autofs_files(cfg, datasets_line)
        lines += [
            'if command -v automount >/dev/null 2>&1; then',
            '  ' + _write_if_changed(AUTOFS_MASTER, master.rstrip('\n')),
            '  ' + _write_if_changed(AUTOFS_MAP, amap.rstrip('\n')),
            '  if [ $changed = 1 ] || ! systemctl is-active -q autofs; then systemctl enable -q autofs 2>/dev/null; systemctl restart autofs || exit 10; fi',
            'else',
            '  echo autofs=missing',
            '  mkdir -p "$M"',
        ]
        if cfg['kind'] == 'nfs':
            ver = {'3': 'vers=3', '4.1': 'vers=4.1', 'krb5': 'vers=4.1,sec=krb5p'}[cfg['nfs_version']]
            o = ','.join(x for x in (ver, 'hard', cfg['options']) if x)
            src = f"{cfg['server']}:{cfg['share'].rstrip('/')}"
            tops = sorted({f.split('/')[0] for f in (folders or {}).values()} | {cfg['folders'][k]['rule'].split('/')[0] for k in TEMPLATES if cfg['folders'][k]['enabled']})
            for top in tops:
                lines += [f'  mkdir -p "$M"/{_q(top)}; mountpoint -q "$M"/{_q(top)} || {{ timeout 25 mount -t nfs -o {_q(o)} {_q(src + "/" + top)} "$M"/{_q(top)} || exit 10; changed=1; }}']
        else:
            o = ','.join(x for x in ('sec=krb5', 'multiuser', 'cruid=0', cfg['options']) if x)
            src = f"//{cfg['server']}/{cfg['share']}"
            lines += [f'  mountpoint -q "$M" || {{ timeout 25 mount -t cifs -o {_q(o)} {_q(src)} "$M" || exit 10; changed=1; }}']
        lines += ['fi']
    if users is not None and cfg['create_by'] == 'user' and not per_user_smb:
        lines += [_write_if_changed(PROFILE_SCRIPT, profile_script(cfg, users).rstrip('\n'))]
    if not user:
        lines += ['echo changed=$changed']
        return '\n'.join(lines) + '\n'
    lines += [f'U={_q(user)}',
              'getent passwd "$U" >/dev/null 2>&1 || { echo "no account $U on this machine" >&2; exit 12; }',
              'echo uid=$(id -u "$U"); echo gid=$(id -g "$U")',
              # in /etc/passwd only: its uid is this VM's, not the directory's
              'if grep -q "^$U:" /etc/passwd; then echo local=1; else echo local=0; fi']
    for key, folder in sorted(folders.items()):
        p = f'"$M"/{_q(folder)}'
        if per_user_smb:
            src = f"//{cfg['server']}/{cfg['share']}"
            mode = 'dir_mode=0700,file_mode=0600' if cfg['private'] else 'dir_mode=0755,file_mode=0644'
            o = f'credentials=/etc/moavi/nas.cred,uid=$(id -u "$U"),gid=$(id -g "$U"),{mode}' + (f",{cfg['options']}" if cfg['options'] else '')
            lines += [f'P={p}', 'mkdir -p "$P"',
                      'if ! mountpoint -q "$P"; then',
                      '  R=/run/moavi/nas-root; mkdir -p "$R"',
                      '  mountpoint -q "$R" || timeout 25 mount -t cifs -o ' + _q(','.join(x for x in ('credentials=/etc/moavi/nas.cred', cfg['options']) if x)) + f' {_q(src)} "$R" || exit 10',
                      f'  mkdir -p "$R"/{_q(folder)} 2>/dev/null; ok=$?; umount "$R" 2>/dev/null',
                      f'  [ $ok -eq 0 ] || {{ echo "the service account may not make {folder} on the share" >&2; exit 11; }}',
                      f'  timeout 25 mount -t cifs -o "{o}" {_q(src + "/" + folder)} "$P" || exit 10',
                      '  changed=1', 'fi']
            continue
        lines += [f'P={p}', f'ls -d "$P" >/dev/null 2>&1 || ls "$M"/{_q(folder.split("/")[0])} >/dev/null 2>&1']   # wake autofs
        if key == 'project':
            lines += [f'[ -d "$P" ] || echo missing=project']
            continue
        if cfg['create_by'] == 'engine':
            lines += [f'[ -d "$P" ] || echo missing={key}']
        else:
            # the user makes it: the export's top folders let users write (1777 / FSLogix rights)
            lines += ['if [ ! -d "$P" ]; then',
                      '  runuser -u "$U" -- mkdir -p "$P" 2>/dev/null && changed=1 || ' + (
                          'echo atsignin=' + key if cfg['kind'] == 'smb' else
                          f'{{ echo "{folder}: $U may not make it (the top folder needs mode 1777 or write for the users group)" >&2; exit 11; }}'),
                      'fi']
        if cfg['private'] and cfg['kind'] == 'nfs':
            lines += ['if [ -d "$P" ]; then',
                      '  [ "$(stat -c %U "$P")" = "$U" ] || { echo "$P belongs to $(stat -c %U "$P"), not $U" >&2; exit 14; }',
                      '  [ "$(stat -c %a "$P")" = 700 ] || runuser -u "$U" -- chmod 700 "$P" 2>/dev/null || true',
                      'fi']
        if key == 'scratch' and cleanup_days:
            lines += [f'[ -d "$P" ] && runuser -u "$U" -- find "$P" -mindepth 1 -maxdepth 1 -type d -name "job_*" -mtime +{int(cleanup_days)} -exec rm -rf {{}} + 2>/dev/null && echo cleaned=1']
        if measure:
            lines += [f'[ -d "$P" ] && echo usage={key}:$(timeout 10 du -sk "$P" 2>/dev/null | cut -f1)']
    lines += ['echo changed=$changed']
    return '\n'.join(lines) + '\n'


def parse_output(out):
    """The key=value lines of a guest script."""
    got = {'missing': [], 'usage': {}, 'atsignin': []}
    for line in (out or '').splitlines():
        if '=' not in line:
            continue
        k, v = line.strip().split('=', 1)
        if k in ('missing', 'atsignin'):
            got[k].append(v)
        elif k == 'usage' and ':' in v:
            key, kb = v.split(':', 1)
            if kb.strip().isdigit():
                got['usage'][key] = int(kb.strip())
        else:
            got[k] = v
    return got


LOGON_SCRIPT = r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\moavi-nas.cmd'


def windows_logon_script(cfg, users):
    """The all-users sign-in script: runs as whoever signs in and maps their drives with their
    own sign-in, making their own home/scratch folder first (FSLogix rights on the share).
    users: {guest account: {template: folder}}. UTF-8 (chcp 65001) for department names."""
    share = f"\\\\{cfg['server']}\\{cfg['share'].replace('/', chr(92))}"
    out = ['@echo off', 'rem MOAVI Desk shared storage - written by the engine, changes here are replaced',
           'rem With AD a GPO drive map does the same; this script then only repeats it.', 'chcp 65001 >nul']
    for name in sorted(users):
        sets = ' & '.join(f'set "{k.upper()}={v.replace("/", chr(92))}"' for k, v in sorted(users[name].items()))
        out.append(f'if /i "%USERNAME%"=="{name}" ({sets})')
    for key in TEMPLATES:
        f = cfg['folders'][key]
        if not f['enabled']:
            continue
        var = key.upper()
        if key != 'project':
            out.append(f'if defined {var} if not exist "{share}\\%{var}%" mkdir "{share}\\%{var}%" >nul 2>&1')
        out.append(f'if defined {var} (net use {f["drive"]}: /delete /y >nul 2>&1 & net use {f["drive"]}: "{share}\\%{var}%" /persistent:no >nul)')
    if cfg.get('win_redirect') and cfg['folders']['home']['enabled']:
        h = cfg['folders']['home']['drive']
        key = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        out.append('rem 바탕 화면 · 문서 · 다운로드 · 사진 on the home drive (Explorer reads it at the next sign-in)')
        for value, folder in REDIRECTS:
            out.append(f'if defined HOME if exist {h}:\\ ((if not exist "{h}:\\{folder}" mkdir "{h}:\\{folder}" >nul 2>&1) & '
                       f'reg add "{key}" /v "{value}" /t REG_EXPAND_SZ /d "{h}:\\{folder}" /f >nul 2>&1)')
    return '\r\n'.join(out) + '\r\n'


def windows_script(cfg, users, extra=()):
    """PowerShell for the guest agent (as SYSTEM): writes the sign-in script when it changed.
    The drives themselves are mapped in the user's session, never here. extra: more lines
    run as SYSTEM before the answer (the dataset links, datasets.windows_links)."""
    if cfg['kind'] != 'smb':
        return 'Write-Error "NFS is not set up on Windows desktops - use SMB"; exit 15'
    body = base64.b64encode(windows_logon_script(cfg, users).encode('utf-8')).decode('ascii')
    return '\n'.join([
        "$ErrorActionPreference = 'Stop'", '$changed = 0',
        f"$want = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{body}'))",
        "$path = '" + LOGON_SCRIPT.replace("'", "''") + "'",
        '$have = if (Test-Path -LiteralPath $path) { [IO.File]::ReadAllText($path) } else { $null }',
        'if ($have -ne $want) { [IO.File]::WriteAllText($path, $want, (New-Object Text.UTF8Encoding $false)); $changed = 1 }',
        *block_local_lines(cfg), *extra, '"changed=$changed"', 'exit 0']) + '\n'


def block_local_lines(cfg):
    """PowerShell (as SYSTEM): C: hidden and refused in Explorer and the file dialogs, or the
    engine's own values taken away again."""
    pk = EXPLORER_POLICY
    if cfg.get('win_block_local') and cfg.get('win_redirect'):
        return [f"$pk = '{pk}'", 'if (-not (Test-Path $pk)) { New-Item -Path $pk -Force | Out-Null }',
                "foreach ($n in 'NoDrives', 'NoViewOnDrive') { $v = (Get-ItemProperty -Path $pk -Name $n -ErrorAction SilentlyContinue).$n; "
                f"if ($v -ne {DRIVE_C}) {{ Set-ItemProperty -Path $pk -Name $n -Value {DRIVE_C} -Type DWord; $changed = 1 }} }}"]
    return [f"$pk = '{pk}'",
            "foreach ($n in 'NoDrives', 'NoViewOnDrive') { $v = (Get-ItemProperty -Path $pk -Name $n -ErrorAction SilentlyContinue).$n; "
            f"if ($v -eq {DRIVE_C}) {{ Remove-ItemProperty -Path $pk -Name $n; $changed = 1 }} }}"]


# --- create_by engine: folders made on the engine host -------------------------------------

def engine_make(cfg, folder, uid, gid):
    """Make <admin_path>/<folder> and give it to uid:gid (700 when private). Error text or None."""
    root = os.path.realpath(cfg['admin_path'])
    if not os.path.isdir(root):
        return f"admin_path {cfg['admin_path']} is not mounted on the engine host"
    target = os.path.realpath(os.path.join(root, *folder.split('/')))
    if not target.startswith(root + os.sep):
        return 'folder outside admin_path'
    try:
        os.makedirs(target, exist_ok=True)
        if hasattr(os, 'chown'):
            os.chown(target, int(uid), int(gid))
        os.chmod(target, 0o700 if cfg['private'] else 0o755)
    except OSError as e:
        return f'{folder}: {e.strerror or e} (no_root_squash for the engine on the export?)'
    return None


def remember_ids(username, uid, gid, local):
    db().execute('INSERT OR REPLACE INTO vlab_storage_ids (username, uid, gid, local, at) VALUES (?, ?, ?, ?, ?)',
                 (username, int(uid), int(gid), int(bool(local)), now()))


def ids_of(username):
    r = db().query_one('SELECT * FROM vlab_storage_ids WHERE username = ?', (username,))
    return dict(r) if r else None


# --- results -----------------------------------------------------------------------------

def record(desktop_id, username, pool_id, ok, code, detail, path, changed, os_kind, warnings=(), usage=None, cleaned=False):
    prev = last(desktop_id, username)
    usage_at = now() if usage else (prev or {}).get('usage_at')
    usage = usage if usage else (prev or {}).get('usage') or {}
    cleaned_at = now() if cleaned else (prev or {}).get('cleaned_at')
    db().execute('INSERT OR REPLACE INTO vlab_storage_mounts (desktop_id, username, pool_id, ok, code, detail, path, changed, os, '
                 'warnings, usage, usage_at, cleaned_at, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (desktop_id, username or '', pool_id, None if ok is None else int(ok), code, (detail or '')[:500],
                  path or '', int(bool(changed)), os_kind or '', json.dumps(list(warnings)), json.dumps(usage),
                  usage_at, cleaned_at, now()))


def last(desktop_id, username):
    r = db().query_one('SELECT * FROM vlab_storage_mounts WHERE desktop_id = ? AND username = ?', (desktop_id, username or ''))
    return _view(r) if r else None


def _view(r):
    v = dict(r)
    v['ok'] = None if v['ok'] is None else bool(v['ok'])
    v['changed'] = bool(v['changed'])
    for k, empty in (('warnings', []), ('usage', {})):
        try:
            v[k] = json.loads(v.get(k) or json.dumps(empty))
        except ValueError:
            v[k] = empty
    return v


def results(pool_id=None, username=None, desktop_id=None, limit=200):
    where, args = [], []
    for col, val in (('pool_id', pool_id), ('username', username), ('desktop_id', desktop_id)):
        if val is not None:
            where.append(f'{col} = ?')
            args.append(val)
    sql = 'SELECT * FROM vlab_storage_mounts' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY at DESC LIMIT ?'
    return [_view(r) for r in db().query(sql, tuple(args) + (int(limit),))]


def users_on(desktop_id):
    return [r['username'] for r in db().query('SELECT username FROM vlab_storage_mounts WHERE desktop_id = ? AND username != ?',
                                              (desktop_id, ''))]
