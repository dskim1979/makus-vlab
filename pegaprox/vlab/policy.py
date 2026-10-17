# -*- coding: utf-8 -*-
"""
vLAB pool policy (MAKUS): how the desktops of a pool are reached and kept.

Kept in vlab_pools.settings['policy']; a pool without one gets DEFAULTS. Where each setting
takes effect:
  protocols, spice_fullscreen  connect route (allowed protocols, the .vv file)
  clipboard                    the browser console (noVNC), the .rdp file (on only for both -
                               mstsc has no one-way switch) and browser RDP (disable-copy / -paste);
                               SPICE leaves it to the guest agent
  usb_redirect, usb_autoshare  the .vv file (SPICE USB redirection)
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
                               the VM's console: a Windows desktop used over RDP shows its lock screen there
  auto_domain_join             new, cloned and reset desktops join the bundled directory by themselves
                               (pegaprox/api/vlab_directory.py autojoin_round); None = on while the
                               bundled directory is in use
"""

# browser RDP is no protocol of its own: with 보안 게이트웨이 (Warpgate) on, an 'rdp' pool opens in the browser too
PROTOCOLS = ('vnc', 'spice', 'rdp')
CLIPBOARD = ('both', 'to_desktop', 'from_desktop', 'off')
WEB_IDE = ('jupyter', 'vscode')
SSH_FILES = ('off', 'down', 'up', 'both')   # browser SSH file transfer (SFTP): none / download / upload / both
RESET_TYPES = ('reset', 'classroom')

DEFAULTS = {
    # RDP first (H.264 · UDP, the lightest on a WAN for office work), SPICE / VNC as the choice;
    # a Linux desktop without an RDP server falls back to them by itself
    'protocols': ['vnc', 'spice', 'rdp'],
    'spice_fullscreen': False,
    'clipboard': 'both',
    'usb_redirect': True,
    'usb_autoshare': False,
    'client_drives': False,
    'client_printers': True,
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
    'auto_domain_join': None,
}

_BOOLS = ('spice_fullscreen', 'usb_redirect', 'usb_autoshare', 'client_drives', 'client_printers', 'rdp_tune', 'start_on_connect',
          'reset_on_logout', 'allow_power', 'defer_when_busy', 'browser_ssh', 'researcher_ssh', 'screen_thumbnail')
_LIMITS = {'idle_shutdown_min': (0, 10080), 'max_session_hours': (0, 720),   # a week, a month
           'busy_gpu_pct': (1, 100), 'busy_cpu_pct': (0, 100), 'defer_max_hours': (1, 168),
           'web_ide_idle_min': (10, 10080)}


def effective(settings):
    """The pool's policy with defaults filled in (and the protocols of pools made before
    there was a policy)."""
    settings = settings if isinstance(settings, dict) else {}
    out = dict(DEFAULTS)
    if settings.get('protocols'):
        out['protocols'] = [p for p in settings['protocols'] if p in PROTOCOLS] or DEFAULTS['protocols']
    stored = settings.get('policy')
    if isinstance(stored, dict):
        out.update({k: v for k, v in stored.items() if k in DEFAULTS})
    # a policy saved before Guacamole went may still name 'guac' (retire_gateways cleans it at start)
    out['protocols'] = [p for p in out['protocols'] if p in PROTOCOLS] or ['rdp']
    return out


def validate(data, pool_type):
    """(policy, None) or (None, error text). Unknown keys are refused; missing ones keep
    their defaults."""
    if not isinstance(data, dict):
        return None, 'JSON object required'
    unknown = sorted(set(data) - set(DEFAULTS))
    if unknown:
        return None, f"unknown fields: {', '.join(unknown)}"
    out = dict(DEFAULTS)
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
        elif k == 'auto_domain_join':
            if v is not None and not isinstance(v, bool):
                return None, 'auto_domain_join must be true, false or null'
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
