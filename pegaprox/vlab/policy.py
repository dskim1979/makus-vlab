# -*- coding: utf-8 -*-
"""
vLAB pool policy (MAKUS): how the desktops of a pool are reached and kept.

Kept in vlab_pools.settings['policy']; a pool without one gets DEFAULTS. Where each setting
takes effect:
  protocols, spice_fullscreen  connect route (allowed protocols, the .vv file)
  clipboard                    the browser console (noVNC), the .rdp file (on only for both -
                               mstsc has no one-way switch) and browser RDP (disable-copy / -paste);
                               SPICE leaves it to the guest agent
  usb_redirect, usb_autoshare  the .vv file (SPICE USB redirection); usb_redirect also the .rdp's USB and
                               plug-and-play devices on the devices route
  usb_mode, usb_classes,       USB 정책: which devices go over (usb_redirect is the master switch).
  usb_devices                  'deny' = all but the checked kinds and devices, 'allow' = only those.
                               SPICE: the .vv's usb-filter (usbredir rules: class,vid,pid,version,allow).
                               RDP (devices route): usbdevicestoredirect from device setup class GUIDs, and
                               the high-level switches for smart cards, cameras, microphone, printers and
                               drives (usb_rdp_lines). The .rdp key has no documented way to leave one class
                               out of '*', so in deny mode RDP keeps '*' and only those high-level kinds
                               are held back; allow mode lists the classes and is exact.
                               Nothing is written inside the desktop (no DeviceInstall restrictions): they
                               would also stop the TPM virtual smart card of 자동 로그인 and passthrough cards
  rdp_route                    the .rdp file's way to the desktop: 'record' = 보안 게이트웨이 (Warpgate:
                               recorded, no device channels), 'devices' = its device route (rdpgw: drives,
                               printers, USB as the switches here say, not recorded; pegaprox/vlab/rdpgw.py)
  device_route_for             who in this pool connects over the devices route anyway (drives, printers,
                               USB as the switches say) while the pool's own route stays as it is: a list of
                               {subject_type user|department|group, subject_id, include_children}. Nothing on
                               the user's side says which route a connection took (api/vlab_next.py
                               desktop_rdp_answer)
  client_drives                the .rdp file: the user's own PC drives in the desktop (off = files
                               cannot be carried in or out that way)
  client_printers              the .rdp file (the PC's printers) and browser RDP (print to PDF)
  rdp_tune                     a Windows desktop's first RDP connect: RDP on, its firewall rules, H.264/AVC
                               444 with hardware encoding when there is a GPU, UDP and TCP
                               (pegaprox/api/vlab_next.py rdp_prepare)
  start_on_connect             connect route: a stopped desktop is started, the user retries
  idle_shutdown_min            background tick: shut down after that long without a session
  reset_on_logout              session end: back to the base (reset and scheduled pools only)
  allow_power                  the user's power route and buttons
  max_session_hours            background tick: a session open longer is closed
  defer_when_busy              the idle shutdown, session limit, LAB / booking clean-up and a
                               scheduled stop first ask whether the desktop is working
                               (pegaprox/api/vlab_work.py) and wait while it is
  busy_gpu_pct, busy_cpu_pct   what counts as working (GPU use, CPU load; 0 = not judged by it)
  defer_max_hours              the longest the step waits; then it runs anyway
  web_ide                      the portal's 웹 IDE: JupyterLab and/or VS Code (code-server) through
                               vlab-proxy /ide/<session>/ (pegaprox/api/vlab_research.py)
  web_ide_idle_min             an IDE nobody used for that long ends by itself (Jupyter's own timer)
  screen_thumbnail             the portal card's screen picture (/api/vlab/desktops/<id>/screenshot). It is
                               the VM's console: a Windows desktop used over RDP shows its lock screen there.
                               Off by default except in dedicated pools - where desktops pass from user to
                               user the picture could be someone else's screen (defaults_for)
  net_isolation                네트워크 격리: the pool's desktops take inbound traffic only from the MOAVI
                               gateway (its addresses per cluster, pegaprox/vlab/netiso.py) and what
                               net_allow_in opens - not from users' PCs, not from other desktops. Proxmox
                               firewall (a security group per pool, NIC firewall=1, the VM's inbound policy
                               DROP), so nothing inside the desktop can take it back
  net_peers                    with isolation on, the pool's own desktops may still reach each other
  net_allow_in                 more sources let in: [{cidr, proto any|tcp|udp|icmp, port, note}]
  net_egress, net_allow_out    outbound: 'any' (as before) or 'list' = only the gateway, the pool's own
                               desktops when net_peers, and net_allow_out (DNS, AD, file servers ...)
  auto_domain_join             new, cloned and reset desktops join the bundled directory by themselves
                               (pegaprox/api/vlab_directory.py autojoin_round); None = on while the
                               bundled directory is in use
  ha_enabled                   'HA 사용': new and cloned desktops go under Proxmox HA once ready
                               (pegaprox/vlab/hadrs.py queue_new, ha_tick); existing ones only from
                               클러스터 > 고가용성. On by default in dedicated pools only - a reset,
                               classroom or shared desktop is simply handed out again elsewhere
"""

# browser RDP is no protocol of its own: with 보안 게이트웨이 (Warpgate) on, an 'rdp' pool opens in the browser too
PROTOCOLS = ('vnc', 'spice', 'rdp')
CLIPBOARD = ('both', 'to_desktop', 'from_desktop', 'off')
WEB_IDE = ('jupyter', 'vscode')
SSH_FILES = ('off', 'down', 'up', 'both')
# the portal's 파일 panel (files into / out of the user's own desktop through the guest agent): off / up / down / both
DESKTOP_FILES = ('off', 'up', 'down', 'both')   # browser SSH file transfer (SFTP): none / download / upload / both
RESET_TYPES = ('reset', 'classroom')
# pools whose desktops pass from one user to the next: the screen picture is off unless set
SHARED_SCREEN_TYPES = ('reset', 'shared', 'classroom', 'buildfarm')
RDP_ROUTES = ('record', 'devices')
NET_EGRESS = ('any', 'list')
NET_PROTOS = ('any', 'tcp', 'udp', 'icmp')
NET_RULES_MAX = 30
USB_MODES = ('deny', 'allow')
# the kinds 'USB 정책' lists: USB interface class codes (SPICE usbredir) and device setup classes (RDP)
USB_CLASSES = ('storage', 'printer', 'smartcard', 'camera', 'audio', 'imaging', 'serial', 'wireless')
USB_CLASS_CODES = {'storage': (0x08,), 'printer': (0x07,), 'smartcard': (0x0b,), 'camera': (0x0e,),
                   'audio': (0x01,), 'imaging': (0x06,), 'serial': (0x02, 0x0a), 'wireless': (0xe0,)}
# Microsoft "System-Defined Device Setup Classes Available to Vendors" (ClassGuid)
USB_CLASS_GUIDS = {
    'storage': ('{4d36e967-e325-11ce-bfc1-08002be10318}', '{eec5ad98-8080-425f-922a-dabf3de3f69a}'),   # DiskDrive, WPD
    'printer': ('{4d36e979-e325-11ce-bfc1-08002be10318}',),
    'smartcard': ('{50dd5230-ba8a-11d1-bf5d-0000f805f530}',),       # SmartCardReader
    'camera': ('{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}',),
    'audio': ('{4d36e96c-e325-11ce-bfc1-08002be10318}',),           # Media
    'imaging': ('{6bdd1fc6-810f-11d0-bec7-08002be2092f}',),         # Image
    'serial': ('{4d36e978-e325-11ce-bfc1-08002be10318}',),          # Ports
    'wireless': ('{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}',),        # Bluetooth
}
USB_DEVICES_MAX = 50

DEFAULTS = {
    # RDP first (H.264 · UDP, the lightest on a WAN for office work), SPICE / VNC as the choice;
    # a Linux desktop without an RDP server falls back to them by itself
    'protocols': ['vnc', 'spice', 'rdp'],
    'spice_fullscreen': False,
    'clipboard': 'both',
    'usb_redirect': True,
    'usb_autoshare': False,
    'usb_mode': 'deny',         # USB 정책: deny = all but the checked, allow = only the checked
    'usb_classes': [],
    'usb_devices': [],          # [{'name', 'vid', 'pid'}] (4 hex digits each)
    'client_drives': False,
    'client_printers': True,
    'rdp_route': 'record',
    'rdp_tune': True,
    'start_on_connect': True,
    'idle_shutdown_min': 0,
    'reset_on_logout': False,
    'allow_power': True,
    'max_session_hours': 0,
    'defer_when_busy': True,
    'busy_gpu_pct': 10,
    'busy_cpu_pct': 50,
    'defer_max_hours': 12,
    'web_ide': [],
    'web_ide_idle_min': 240,
    'browser_ssh': False,       # SSH for Linux desktops through 보안 게이트웨이 (Warpgate)
    'ssh_files': 'off',         # that terminal's file transfer (SFTP)
    'researcher_ssh': False,    # researchers' own SSH tools (PuTTY/scp/WinSCP/VS Code) through Warpgate
    'screen_thumbnail': True,   # the portal card shows the running desktop's screen
    'ha_enabled': True,         # new desktops go under Proxmox HA (dedicated pools; defaults_for)
    'auto_domain_join': None,
    'desktop_files': 'off',     # the portal's 파일 panel: off / up (to the desktop) / down / both (pegaprox/api/vlab_desk_files.py)
    'desktop_files_max_mb': 500,   # largest single file
    'desktop_files_day_mb': 0,     # per user per day, both ways; 0 = no limit
    'device_route_for': [],     # 장치 연결 허용 대상: these users / departments / groups take the devices route
    'net_isolation': False,     # 네트워크 격리 (pegaprox/vlab/netiso.py)
    'net_peers': False,
    'net_allow_in': [],
    'net_egress': 'any',
    'net_allow_out': [],
}
SUBJECT_TYPES = ('user', 'department', 'group')
MAX_DEVICE_ROUTE_FOR = 200

_BOOLS = ('spice_fullscreen', 'usb_redirect', 'usb_autoshare', 'client_drives', 'client_printers', 'rdp_tune', 'start_on_connect',
          'reset_on_logout', 'allow_power', 'defer_when_busy', 'browser_ssh', 'researcher_ssh', 'screen_thumbnail', 'ha_enabled',
          'net_isolation', 'net_peers')
_LIMITS = {'idle_shutdown_min': (0, 10080), 'max_session_hours': (0, 720),   # a week, a month
           'busy_gpu_pct': (1, 100), 'busy_cpu_pct': (0, 100), 'defer_max_hours': (1, 168),
           'web_ide_idle_min': (10, 10080), 'desktop_files_max_mb': (1, 10240), 'desktop_files_day_mb': (0, 1048576)}


def defaults_for(pool_type=None):
    """DEFAULTS for a pool of that type (None: the dedicated defaults)."""
    out = dict(DEFAULTS)
    if pool_type in SHARED_SCREEN_TYPES:
        out['screen_thumbnail'] = False
    if pool_type is not None and pool_type != 'dedicated':
        out['ha_enabled'] = False
    return out


def effective(settings, pool_type=None):
    """The pool's policy with defaults filled in (and the protocols of pools made before
    there was a policy). Pass the pool type where screen_thumbnail matters."""
    settings = settings if isinstance(settings, dict) else {}
    out = defaults_for(pool_type)
    if settings.get('protocols'):
        out['protocols'] = [p for p in settings['protocols'] if p in PROTOCOLS] or DEFAULTS['protocols']
    stored = settings.get('policy')
    if isinstance(stored, dict):
        out.update({k: v for k, v in stored.items() if k in DEFAULTS})
    # a policy saved before Guacamole went may still name 'guac' (retire_gateways cleans it at start)
    out['protocols'] = [p for p in out['protocols'] if p in PROTOCOLS] or ['rdp']
    return out


def _usb_devices(v):
    """([{'name', 'vid', 'pid'}], None) with vid/pid as 4 lower-case hex digits, or (None, error)."""
    if not isinstance(v, list) or len(v) > USB_DEVICES_MAX:
        return None, f'usb_devices: a list of at most {USB_DEVICES_MAX}'
    out, seen = [], set()
    for d in v:
        if not isinstance(d, dict):
            return None, 'usb_devices: each entry is {name, vid, pid}'
        vid, pid = str(d.get('vid', '')).strip().lower(), str(d.get('pid', '')).strip().lower()
        if any(len(x) != 4 or any(c not in '0123456789abcdef' for c in x) for x in (vid, pid)):
            return None, 'usb_devices: vid and pid are 4 hex digits (e.g. 046d)'
        if (vid, pid) in seen:
            continue
        seen.add((vid, pid))
        out.append({'name': str(d.get('name') or '').strip()[:40], 'vid': vid, 'pid': pid})
    return out, None


def usb_blocked(pol, kind):
    """True when the pool's USB 정책 keeps that kind of device on the user's PC."""
    if not pol.get('usb_redirect'):
        return True
    chosen = kind in (pol.get('usb_classes') or [])
    return chosen if pol.get('usb_mode', 'deny') == 'deny' else not chosen


def usb_spice_filter(pol):
    """The .vv's usb-filter (usbredir rules 'class,vid,pid,version,allow' joined by '|'); None when
    the policy has nothing to filter (every device may go)."""
    mode = pol.get('usb_mode', 'deny')
    classes, devices = pol.get('usb_classes') or [], pol.get('usb_devices') or []
    if mode == 'deny' and not classes and not devices:
        return None
    hit = 0 if mode == 'deny' else 1
    rules = [f'-1,0x{d["vid"]},0x{d["pid"]},-1,{hit}' for d in devices]
    rules += [f'0x{code:02x},-1,-1,-1,{hit}' for c in classes for code in USB_CLASS_CODES[c]]
    rules.append(f'-1,-1,-1,-1,{1 - hit}')
    return '|'.join(rules)


def usb_rdp_lines(pol):
    """The .rdp's device lines for the devices route (rdpgw or direct)."""
    if not pol.get('usb_redirect'):
        return []
    mode = pol.get('usb_mode', 'deny')
    if mode == 'allow':
        picks = [g for c in USB_CLASSES if c in (pol.get('usb_classes') or []) for g in USB_CLASS_GUIDS[c]]
        picks += [f"USB\\VID_{d['vid'].upper()}&PID_{d['pid'].upper()}" for d in pol.get('usb_devices') or []]
        usb = ';'.join(picks)
    else:
        usb = '*'           # no documented way to leave one class out of '*': the switches below do it
    lines = [f'usbdevicestoredirect:s:{usb}', f"devicestoredirect:s:{'' if usb_blocked(pol, 'storage') else '*'}"]
    # the high-level kinds: deny mode only says no to the blocked ones (a pool without a USB 정책 keeps
    # mstsc's own defaults); allow mode says yes or no to each
    for kind, off, on in (('smartcard', 'redirectsmartcards:i:0', 'redirectsmartcards:i:1'),
                          ('camera', 'camerastoredirect:s:', 'camerastoredirect:s:*'),
                          ('audio', 'audiocapturemode:i:0', 'audiocapturemode:i:1')):
        if usb_blocked(pol, kind):
            lines.append(off)
        elif mode == 'allow':
            lines.append(on)
    return lines


def _port_ok(port):
    """'' or ports '22', '80,443', '5000:5100' (at most 10 parts)."""
    if port == '':
        return True
    parts = port.split(',')
    if len(parts) > 10:
        return False
    for part in parts:
        ends = part.split(':')
        if len(ends) > 2 or not all(e.isdigit() and 1 <= int(e) <= 65535 for e in ends):
            return False
        if len(ends) == 2 and int(ends[0]) > int(ends[1]):
            return False
    return True


def net_rules(v, key):
    """([{'cidr', 'proto', 'port', 'note'}], None) or (None, error) for net_allow_in / net_allow_out."""
    import ipaddress
    if not isinstance(v, list) or len(v) > NET_RULES_MAX:
        return None, f'{key}: a list of at most {NET_RULES_MAX}'
    out = []
    for r in v:
        if not isinstance(r, dict):
            return None, f'{key}: each entry is {{cidr, proto, port, note}}'
        try:
            cidr = str(ipaddress.ip_network(str(r.get('cidr', '')).strip(), strict=False))
        except ValueError:
            return None, f"{key}: '{r.get('cidr')}' is not an address or network (e.g. 10.0.0.5, 10.0.0.0/24)"
        proto = r.get('proto') or 'any'
        if proto not in NET_PROTOS:
            return None, f"{key}: proto must be one of {', '.join(NET_PROTOS)}"
        port = str(r.get('port') or '').replace(' ', '')
        if port and proto not in ('tcp', 'udp'):
            return None, f'{key}: a port needs proto tcp or udp'
        if not _port_ok(port):
            return None, f"{key}: port '{port}' - e.g. 22, 80,443 or 5000:5100"
        out.append({'cidr': cidr, 'proto': proto, 'port': port, 'note': str(r.get('note') or '').strip()[:40]})
    return out, None


def validate(data, pool_type):
    """(policy, None) or (None, error text). Unknown keys are refused; missing ones keep
    their defaults."""
    if not isinstance(data, dict):
        return None, 'JSON object required'
    unknown = sorted(set(data) - set(DEFAULTS))
    if unknown:
        return None, f"unknown fields: {', '.join(unknown)}"
    out = dict(DEFAULTS)
    # not filled in: a pool that never set it keeps its type's default (defaults_for)
    out.pop('screen_thumbnail')
    out.pop('ha_enabled')
    for k, v in data.items():
        if k == 'protocols':
            if not isinstance(v, list) or not v or any(p not in PROTOCOLS for p in v):
                return None, 'protocols: a non-empty list of vnc, spice, rdp'
            out[k] = [p for p in PROTOCOLS if p in v]
        elif k == 'web_ide':
            if not isinstance(v, list) or any(x not in WEB_IDE for x in v):
                return None, 'web_ide: a list of jupyter, vscode'
            out[k] = [x for x in WEB_IDE if x in v]
        elif k == 'clipboard':
            if v not in CLIPBOARD:
                return None, f"clipboard must be one of {', '.join(CLIPBOARD)}"
            out[k] = v
        elif k == 'ssh_files':
            if v not in SSH_FILES:
                return None, f"ssh_files must be one of {', '.join(SSH_FILES)}"
            out[k] = v
        elif k == 'auto_domain_join':
            if v is not None and not isinstance(v, bool):
                return None, 'auto_domain_join must be true, false or null'
            out[k] = v
        elif k == 'rdp_route':
            if v not in RDP_ROUTES:
                return None, f"rdp_route must be one of {', '.join(RDP_ROUTES)}"
            out[k] = v
        elif k == 'usb_mode':
            if v not in USB_MODES:
                return None, f"usb_mode must be one of {', '.join(USB_MODES)}"
            out[k] = v
        elif k == 'usb_classes':
            if not isinstance(v, list) or any(x not in USB_CLASSES for x in v):
                return None, f"usb_classes: a list of {', '.join(USB_CLASSES)}"
            out[k] = [x for x in USB_CLASSES if x in v]
        elif k == 'usb_devices':
            devices, err = _usb_devices(v)
            if err:
                return None, err
            out[k] = devices
        elif k == 'device_route_for':
            if not isinstance(v, list) or len(v) > MAX_DEVICE_ROUTE_FOR:
                return None, f'device_route_for: a list of at most {MAX_DEVICE_ROUTE_FOR} entries'
            clean = []
            for x in v:
                if not isinstance(x, dict) or x.get('subject_type') not in SUBJECT_TYPES \
                        or not isinstance(x.get('subject_id'), str) or not x['subject_id'].strip():
                    return None, 'device_route_for: each entry needs subject_type (user, department, group) and subject_id'
                clean.append({'subject_type': x['subject_type'], 'subject_id': x['subject_id'].strip()[:200],
                              'include_children': bool(x.get('include_children'))})
            out[k] = clean
        elif k in ('net_allow_in', 'net_allow_out'):
            rules, err = net_rules(v, k)
            if err:
                return None, err
            out[k] = rules
        elif k == 'net_egress':
            if v not in NET_EGRESS:
                return None, f"net_egress must be one of {', '.join(NET_EGRESS)}"
            out[k] = v
        elif k == 'desktop_files':
            if v not in DESKTOP_FILES:
                return None, f"desktop_files must be one of {', '.join(DESKTOP_FILES)}"
            out[k] = v
        elif k in _BOOLS:
            if not isinstance(v, bool):
                return None, f'{k} must be true or false'
            out[k] = v
        elif k in _LIMITS:
            lo, hi = _LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                return None, f'{k} must be a whole number from {lo} to {hi}'
            out[k] = v
    if out['reset_on_logout'] and pool_type not in RESET_TYPES:
        return None, 'reset_on_logout is for reset and scheduled pools only'
    return out, None
