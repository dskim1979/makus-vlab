# -*- coding: utf-8 -*-
"""
MOAVI Desk desktop templates (가상머신 > 이미지 > 데스크톱 템플릿) - the build (pegaprox/vlab/desktpl.py
has the catalog and the texts).

  GET  /api/vlab/admin/desktop-templates                          the presets and the recent builds   vlab.pool.view
  POST /api/vlab/admin/clusters/<cid>/desktop-templates/<preset>/build
       {node, storage, bridge, name?, cores?, memory_mb?, disk_gb?, vmid?,
        windows_iso, virtio_iso, edition?, language?   (office-win11)
        vendor_dir?, accept_eula?, agree?              (npu / fpga),
        iso_storage?}                                  -> 202 {build, admin_password (Windows: shown once)}   vlab.pool.manage
  GET  /api/vlab/admin/desktop-templates/builds/<id>              one build with its log                vlab.pool.view
  POST /api/vlab/admin/desktop-templates/builds/<id>/cancel       stop after the current step; the VM stays   vlab.pool.manage

Linux: like pegaprox/api/templates_lib.py - download the cloud image on the node, qm create /
importdisk - plus a NoCloud CD (user-data + meta-data, volume cidata, made on the node with genisoimage on
a storage that keeps ISO images) that builds the desktop on the first boot (no Snippets storage needed); the engine follows the stage file through the guest agent, reads the versions (envcat probe),
seals the VM (cloud-init, machine id, host keys), shuts it down and registers a golden image with its
environment card. Windows: an unattended-setup CD (autounattend.xml + C:\\moavi scripts) built on the
node with genisoimage, the admin's Windows ISO and the virtio-win ISO, OVMF + TPM 2.0; first logon
installs the guest tools and apps, the engine runs sysprep and turns the VM into a template.
A build runs in a thread of this engine (vlab_desktpl_builds is local to it, ha.LOCAL_TABLES).
"""

import json
import logging
import re
import shlex
import threading
import time
import uuid

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, desktpl, envcat
from pegaprox.vlab.store import db as _store_db, now

bp = Blueprint('vlab_desktpl', __name__)

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_desktpl_builds (
        id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        node TEXT NOT NULL,
        preset TEXT NOT NULL,
        name TEXT NOT NULL,
        vmid INTEGER NOT NULL,
        options TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'queued',
        step TEXT NOT NULL DEFAULT '',
        progress INTEGER NOT NULL DEFAULT 0,
        log TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT '',
        result TEXT NOT NULL DEFAULT '{}',
        cancel INTEGER NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT
    )''',
)
TABLES = ('vlab_desktpl_builds',)
LOG_LIMIT = 20000
NODE = re.compile(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$')
STORAGE = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-]{0,99}$')
BRIDGE = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-]{0,15}$')
POLL = 30                      # seconds between looks into the building guest
LINUX_HOURS, WINDOWS_HOURS, VIVADO_HOURS = 3, 3, 8

_lock = threading.Lock()
_live = set()                  # build ids with a thread in this process


def db():
    d = _store_db()
    if not getattr(d, '_vlab_desktpl', False):
        with _lock:
            if not getattr(d, '_vlab_desktpl', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_desktpl = True
    return d


def _bad(msg, code=400, err_code=None):
    body = {'error': msg}
    if err_code:
        body['code'] = err_code
    return jsonify(body), code


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _row(r, with_log=False):
    if not r:
        return None
    out = {k: r[k] for k in ('id', 'cluster_id', 'node', 'preset', 'name', 'vmid', 'status', 'step', 'progress', 'error',
                             'created_by', 'created_at', 'updated_at', 'finished_at')}
    out['result'] = json.loads(r['result'] or '{}')
    opts = json.loads(r['options'] or '{}')
    out['options'] = {k: v for k, v in opts.items() if k not in ('admin_password',)}
    if out['status'] in ('queued', 'running') and r['id'] not in _live:
        out['status'] = 'interrupted'          # the engine restarted under it; the VM is left as it was
    if with_log:
        out['log'] = r['log']
    return out


def get_build(bid, with_log=False):
    return _row(db().query_one('SELECT * FROM vlab_desktpl_builds WHERE id = ?', (bid,)), with_log)


def list_builds(limit=30):
    return [_row(r) for r in db().query('SELECT * FROM vlab_desktpl_builds ORDER BY created_at DESC LIMIT ?', (limit,))]


def _update(bid, log=None, **fields):
    sets, args = [], []
    for k, v in fields.items():
        sets.append(f'{k} = ?')
        args.append(json.dumps(v) if k == 'result' else v)
    sets.append('updated_at = ?')
    args.append(now())
    if log:
        row = db().query_one('SELECT log FROM vlab_desktpl_builds WHERE id = ?', (bid,))
        text = ((row['log'] if row else '') + f"[{now()[11:19]}] {log}\n")[-LOG_LIMIT:]
        sets.append('log = ?')
        args.append(text)
    db().execute(f"UPDATE vlab_desktpl_builds SET {', '.join(sets)} WHERE id = ?", tuple(args) + (bid,))


def _cancelled(bid):
    r = db().query_one('SELECT cancel FROM vlab_desktpl_builds WHERE id = ?', (bid,))
    return bool(r and r['cancel'])


class BuildError(Exception):
    def __init__(self, msg, code=''):
        super().__init__(msg)
        self.code = code


class Cancelled(Exception):
    pass


# --- routes -------------------------------------------------------------------------------------

@bp.route('/api/vlab/admin/desktop-templates', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def presets():
    return jsonify({'presets': desktpl.preset_list(), 'builds': [b for b in list_builds() if core._can_reach(b['cluster_id'])]})


@bp.route('/api/vlab/admin/desktop-templates/builds/<bid>', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def build_detail(bid):
    b = get_build(bid, with_log=True)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Build not found', 404)
    return jsonify({'build': b})


@bp.route('/api/vlab/admin/desktop-templates/builds/<bid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def build_cancel(bid):
    b = get_build(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Build not found', 404)
    if b['status'] not in ('queued', 'running'):
        return _bad('The build is not running', 409)
    db().execute('UPDATE vlab_desktpl_builds SET cancel = 1 WHERE id = ?', (bid,))
    log_audit(core._user(), 'vlab.desktpl.cancel', f"desktop template build '{b['name']}' cancelled", get_client_ip())
    return jsonify({'build': get_build(bid)})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/desktop-templates/<preset_id>/build', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def start_build(cluster_id, preset_id):
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not core._can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    if not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    data = _body()
    opts, err = desktpl.validate(preset_id, data)
    if err:
        return _bad(err)
    node, storage, bridge = str(data.get('node') or ''), str(data.get('storage') or ''), str(data.get('bridge') or 'vmbr0')
    iso_storage = str(data.get('iso_storage') or '')
    if not NODE.fullmatch(node):
        return _bad('node: a node of the cluster')
    if not STORAGE.fullmatch(storage):
        return _bad('storage: the storage for the disk')
    if not BRIDGE.fullmatch(bridge):
        return _bad('bridge: a network bridge, e.g. vmbr0')
    if iso_storage and not STORAGE.fullmatch(iso_storage):
        return _bad('iso_storage: a storage with the ISO content')
    vmid = data.get('vmid')
    if vmid is not None and (not isinstance(vmid, int) or isinstance(vmid, bool) or not 100 <= vmid <= 999999999):
        return _bad('vmid: a number from 100')
    if vmid is not None and core._vm_states(cluster_id).get(vmid):
        return _bad(f'VMID {vmid} is in use', 409)
    opts.update(node=node, storage=storage, bridge=bridge, iso_storage=iso_storage)
    password = None
    if desktpl.PRESETS[preset_id]['os'] == 'windows':
        password = desktpl.random_password()
    bid = f'dtb_{uuid.uuid4().hex[:12]}'
    t = now()
    db().execute('INSERT INTO vlab_desktpl_builds (id, cluster_id, node, preset, name, vmid, options, created_by, created_at, updated_at) '
                 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (bid, cluster_id, node, preset_id, opts['name'], int(vmid or 0), json.dumps(opts), core._user(), t, t))
    with _lock:
        _live.add(bid)
    threading.Thread(target=_run, args=(bid, cluster_id, opts, vmid, password), daemon=True,
                     name=f'desktpl-{bid}').start()
    log_audit(core._user(), 'vlab.desktpl.build',
              f"desktop template '{opts['name']}' ({preset_id}) on {node}/{storage}", get_client_ip())
    body = {'build': get_build(bid)}
    if password:
        # the template keeps a local administrator (for sites without a directory); its password is not stored
        body['admin_password'] = password
        body['admin_user'] = desktpl.WIN_ADMIN
    return jsonify(body), 202


# --- the build ----------------------------------------------------------------------------------

class _Node:
    """One SSH session to the node, the commands logged (never a password)."""

    def __init__(self, mgr, node, bid):
        self.bid = bid
        try:
            ip = mgr._get_node_ip(node) if hasattr(mgr, '_get_node_ip') else None
        except Exception:
            ip = None
        self.ssh = mgr._ssh_connect(ip or mgr.host or mgr.config.host)
        if not self.ssh:
            raise BuildError('SSH to the node failed', 'NODE_SSH')

    def run(self, cmd, label, timeout=1800, quiet=False, ok=(0,)):
        from pegaprox.utils.ssh import read_capped
        if not quiet:
            _update(self.bid, log=f'$ {cmd}')
        _i, out, err = self.ssh.exec_command(cmd, get_pty=False, timeout=timeout)
        rc = out.channel.recv_exit_status()
        o, e = read_capped(out).strip(), read_capped(err).strip()
        if rc not in ok:
            raise BuildError(f'{label} failed (rc={rc}): {(e or o)[:400]}')
        return o

    def write(self, path, text):
        sftp = self.ssh.open_sftp()
        try:
            with sftp.open(path, 'w') as f:
                f.write(text.encode('utf-8'))
            sftp.chmod(path, 0o600)
        finally:
            sftp.close()

    def close(self):
        try:
            self.ssh.close()
        except Exception:
            pass


def _run(bid, cluster_id, opts, vmid, password):
    node = None
    try:
        mgr = cluster_managers.get(cluster_id)
        if not mgr:
            raise BuildError('Cluster not connected')
        _update(bid, status='running', step='prepare', progress=2, log=f"build {opts['preset']} '{opts['name']}' on {opts['node']}")
        node = _Node(mgr, opts['node'], bid)
        if not vmid:
            vmid = int(node.run('pvesh get /cluster/nextid', 'next VMID', quiet=True).strip().strip('"'))
        _update(bid, vmid=int(vmid))
        if desktpl.PRESETS[opts['preset']]['os'] == 'windows':
            _build_windows(bid, mgr, node, cluster_id, opts, int(vmid), password)
        else:
            _build_linux(bid, mgr, node, cluster_id, opts, int(vmid))
    except Cancelled:
        _update(bid, status='cancelled', finished_at=now(), log='cancelled - the VM is kept for a look; delete it when done')
    except BuildError as e:
        logging.warning(f'[VLAB] desktop template build {bid} failed: {e}')
        _update(bid, status='failed', error=str(e)[:500], finished_at=now(), log=f'FAILED: {e}')
    except Exception as e:
        logging.exception(f'[VLAB] desktop template build {bid} failed')
        _update(bid, status='failed', error=str(e)[:500], finished_at=now(), log=f'FAILED: {e}')
    finally:
        if node:
            node.close()
        with _lock:
            _live.discard(bid)


def _step(bid, step, progress, msg=None):
    if _cancelled(bid):
        raise Cancelled()
    _update(bid, step=step, progress=progress, log=msg)


def _content_storages(node, content):
    """Storages of the node with that content (pvesm status --content)."""
    out = node.run(f'pvesm status --content {shlex.quote(content)} --enabled 1', f'storages with {content}', quiet=True)
    names = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts and parts[1:2] != ['inactive'] and (len(parts) < 3 or parts[2] == 'active'):
            names.append(parts[0])
    return names


def _vm_status(node, vmid):
    out = node.run(f'qm status {int(vmid)}', 'qm status', quiet=True)
    return out.split(':', 1)[-1].strip()


def _agent(mgr, opts, vmid, argv, wait=60):
    from pegaprox.api.vlab_next import _agent_run
    return _agent_run(mgr, opts['node'], vmid, argv, wait=wait)


def _follow(bid, mgr, opts, vmid, argv, hours, progress_of):
    """Look into the guest every POLL seconds until it says ready (or failed); the stage moves the bar."""
    end = time.monotonic() + hours * 3600
    last = None
    while time.monotonic() < end:
        if _cancelled(bid):
            raise Cancelled()
        rc, out, _err, failure = _agent(mgr, opts, vmid, argv, wait=40)
        if rc is not None and not failure:
            state, detail = desktpl.parse_status(out)
            if state == 'ready':
                return
            if state == 'failed':
                raise BuildError(f'inside the guest: {detail}', 'GUEST_FAILED')
            if detail != last:
                last = detail
                _update(bid, step=detail, progress=progress_of(detail), log=f'guest: {detail}')
        time.sleep(POLL)
    raise BuildError(f'not ready after {hours} h (last stage: {last or "no guest agent yet"})', 'TIMEOUT')


def _wait_stopped(bid, node, vmid, minutes):
    end = time.monotonic() + minutes * 60
    while time.monotonic() < end:
        if _vm_status(node, vmid) == 'stopped':
            return
        if _cancelled(bid):
            raise Cancelled()
        time.sleep(10)
    raise BuildError(f'the VM did not shut down within {minutes} min', 'NO_SHUTDOWN')


def _build_linux(bid, mgr, node, cluster_id, opts, vmid):
    from pegaprox.api.templates_lib import CATALOG
    from pegaprox.utils.url_security import SsrfError, sanitize_outbound_url
    p = desktpl.PRESETS[opts['preset']]
    base = next((c for c in CATALOG if c['id'] == p['base']), None)
    if not base:
        raise BuildError(f"cloud image {p['base']} is not in the template library")
    q, v, st = shlex.quote, int(vmid), opts['storage']
    # the user-data goes in on a NoCloud CD (volume "cidata") made on the node, on a storage that keeps ISO
    # images - no Snippets content needed. The VM gets Proxmox's own cloud-init drive only at the end (clones)
    iso_store = opts.get('iso_storage') or ''
    have = _content_storages(node, 'iso')
    if not iso_store:
        iso_store = 'local' if 'local' in have else (have[0] if have else '')
    if not iso_store or iso_store not in have:
        raise BuildError('No storage on this node keeps ISO images (for the cloud-init CD).', 'NO_ISO_STORAGE')
    _step(bid, 'download', 5, f"{base['name']} from {base['image_url']}")
    try:
        sanitize_outbound_url(base['image_url'], allowed_schemes=('https', 'http'), allow_private=True, allow_loopback=False)
    except SsrfError as e:
        raise BuildError(f'image URL refused: {e}')
    tmp = f'/tmp/moavi-desktpl-{uuid.uuid4().hex}'
    img = f"{tmp}/{base['image_url'].rsplit('/', 1)[-1]}"
    node.run(f'mkdir -m 700 -p {q(tmp)}', 'staging dir', quiet=True)
    try:
        node.run(f"wget -q -O {q(img)} {q(base['image_url'])}", 'download', timeout=3600)
        _step(bid, 'create', 15)
        node.run(f"qm create {v} --name {q(opts['name'])} --memory {int(opts['memory_mb'])} --cores {int(opts['cores'])} --cpu host "
                 f"--machine q35 --net0 virtio,bridge={q(opts['bridge'])} --ostype l26 --agent 1 --serial0 socket --vga qxl "
                 f"--scsihw virtio-scsi-single --description {q('MOAVI Desk desktop template: ' + p['name'])}", 'qm create')
        out = node.run(f'qm importdisk {v} {q(img)} {q(st)}', 'qm importdisk', timeout=3600)
        m = re.findall(r"'([^']+:[^']*vm-%d-disk-\d+[^']*)'" % v, out)
        vol = m[-1] if m else f'{st}:vm-{v}-disk-0'
    finally:
        node.run(f'rm -rf {q(tmp)}', 'cleanup', quiet=True, ok=(0, 1))
    cd_name = f'moavi-cidata-{bid}.iso'
    cd_vol = f'{iso_store}:iso/{cd_name}'
    path = node.run(f'pvesm path {q(cd_vol)}', 'CD path', quiet=True).strip()
    work = f'/tmp/moavi-cidata-{uuid.uuid4().hex}'
    node.run(f'mkdir -m 700 -p {q(work)}', 'staging dir', quiet=True)
    try:
        node.write(f'{work}/user-data', desktpl.user_data(opts))
        node.write(f'{work}/meta-data', desktpl.meta_data(opts, bid))
        node.run(f'genisoimage -quiet -J -r -V cidata -o {q(path)} {q(work + "/user-data")} {q(work + "/meta-data")}', 'genisoimage')
    finally:
        node.run(f'rm -rf {q(work)}', 'cleanup', quiet=True, ok=(0, 1))
    node.run(f"qm set {v} --scsi0 {q(vol + ',discard=on,iothread=1,ssd=1')} --ide2 {q(cd_vol + ',media=cdrom')} "
             f"--boot order=scsi0", 'qm set')
    node.run(f"qm resize {v} scsi0 {int(opts['disk_gb'])}G", 'qm resize')
    _step(bid, 'start', 25)
    node.run(f'qm start {v}', 'qm start')
    hours = VIVADO_HOURS if opts.get('vendor_dir') and opts['preset'] == 'fpga' else LINUX_HOURS
    _follow(bid, mgr, opts, v, ['/bin/bash', '-c', desktpl.STATUS_LINUX], hours,
            lambda stage: desktpl.stage_progress(opts['preset'], stage))
    _step(bid, 'versions', 91, 'reading the versions for the environment card')
    rc, probe_out, _e, failure = _agent(mgr, opts, v, ['/bin/bash', '-c', envcat.PROBE_LINUX], wait=120)
    found = envcat.parse_probe(probe_out) if rc is not None and not failure else None
    _step(bid, 'seal', 93)
    _agent(mgr, opts, v, ['/bin/bash', '-c', desktpl.SEAL_LINUX], wait=120)
    node.run(f'qm shutdown {v} --timeout 300', 'qm shutdown', timeout=400, ok=(0, 255))
    _wait_stopped(bid, node, v, 10)
    # the build CD out; Proxmox's cloud-init drive in, so every clone gets its own name and address
    node.run(f'qm set {v} --delete ide2', 'qm set', quiet=True)
    node.run(f'rm -f {q(path)}', 'CD cleanup', quiet=True, ok=(0, 1))
    node.run(f"qm set {v} --ide2 {q(st + ':cloudinit')} --ipconfig0 ip=dhcp", 'cloud-init drive')
    node.run(f'qm set {v} --ciupgrade 0', 'no upgrade on each clone', quiet=True, ok=(0, 2, 255))
    _step(bid, 'register', 97)
    img_row = catalog.add_golden(cluster_id, opts['node'], v, 'qemu', opts['name'], p['summary'], 'desktop-template')
    env = envcat.save(img_row['id'], 'desktop-template', kind=p['kind'], description=p['summary'])
    if found:
        found['os_type'] = 'linux'
        envcat.set_probe(img_row['id'], found, 'desktop-template')
        envcat.save(img_row['id'], 'desktop-template', components=envcat.merge(env['components'], found['components']),
                    note='데스크톱 템플릿 빌드', version=img_row.get('current_version') or '')
    _update(bid, status='completed', step='done', progress=100, finished_at=now(), result={'golden_id': img_row['id'], 'vmid': v},
            log=f"golden image '{opts['name']}' (VMID {v}) ready")


def _build_windows(bid, mgr, node, cluster_id, opts, vmid, password):
    q, v, st = shlex.quote, int(vmid), opts['storage']
    iso_store = opts['windows_iso'].split(':', 1)[0]
    _step(bid, 'answer-file', 5, 'unattended setup CD')
    iso_path = node.run(f"pvesm path {q(opts['windows_iso'])}", 'ISO path', quiet=True).strip()
    iso_dir = iso_path.rsplit('/', 1)[0]
    cd_name = f'moavi-unattend-{bid}.iso'
    work = f'/tmp/moavi-unattend-{uuid.uuid4().hex}'
    node.run(f'mkdir -m 700 -p {q(work)}/moavi', 'staging dir', quiet=True)
    try:
        node.write(f'{work}/autounattend.xml', desktpl.autounattend(opts, password))
        node.write(f'{work}/moavi/firstlogon.ps1', desktpl.firstlogon_ps1())
        node.write(f'{work}/moavi/oobe.xml', desktpl.oobe_xml(opts['language']))
        node.run(f'genisoimage -quiet -J -r -V MOAVI -o {q(iso_dir + "/" + cd_name)} {q(work)}', 'genisoimage')
    finally:
        node.run(f'rm -rf {q(work)}', 'cleanup', quiet=True, ok=(0, 1))
    cd = f'{iso_store}:iso/{cd_name}'
    _step(bid, 'create', 10)
    node.run(f"qm create {v} --name {q(opts['name'])} --machine q35 --bios ovmf "
             f"--efidisk0 {q(st + ':1,efitype=4m,pre-enrolled-keys=1')} --tpmstate0 {q(st + ':1,version=v2.0')} "
             f"--cpu host --cores {int(opts['cores'])} --memory {int(opts['memory_mb'])} --ostype win11 --agent 1 --vga std "
             f"--scsihw virtio-scsi-single --scsi0 {q(st + ':' + str(int(opts['disk_gb'])) + ',discard=on,iothread=1,ssd=1')} "
             f"--net0 virtio,bridge={q(opts['bridge'])} --ide2 {q(opts['windows_iso'] + ',media=cdrom')} "
             f"--ide0 {q(opts['virtio_iso'] + ',media=cdrom')} --sata0 {q(cd + ',media=cdrom')} --boot {q('order=ide2;scsi0')} "
             f"--description {q('MOAVI Desk desktop template: ' + desktpl.PRESETS['office-win11']['name'])}", 'qm create')
    _step(bid, 'install', 15)
    node.run(f'qm start {v}', 'qm start')
    # OVMF asks "Press any key to boot from CD or DVD": answer it for the first half minute
    node.run(f'for i in $(seq 1 30); do qm sendkey {v} ret >/dev/null 2>&1; sleep 1; done', 'boot from CD', timeout=120, quiet=True)
    stages = {'boot': 30, 'guest-tools': 55, 'settings': 65, 'apps': 75, 'ready': 85}
    _follow(bid, mgr, opts, v, ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', desktpl.STATUS_WINDOWS],
            WINDOWS_HOURS, lambda s: stages.get(s, 40))
    _step(bid, 'sysprep', 88, 'generalising (sysprep) and shutting down')
    _agent(mgr, opts, v, ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
                          desktpl.SYSPREP_WINDOWS], wait=120)
    _wait_stopped(bid, node, v, 45)
    node.run(f"qm set {v} --delete ide0,ide2,sata0 --boot order=scsi0", 'qm set')
    node.run(f'rm -f {q(iso_dir + "/" + cd_name)}', 'answer CD cleanup', quiet=True, ok=(0, 1))
    _step(bid, 'template', 96)
    node.run(f'qm template {v}', 'qm template')
    _update(bid, status='completed', step='done', progress=100, finished_at=now(), result={'template_vmid': v},
            log=f"template '{opts['name']}' (VMID {v}) ready - make a pool from it under 데스크톱 풀")
