# -*- coding: utf-8 -*-
"""MOAVI Desk x a LIVE Warpgate (pegaprox/vlab/warpgate.py against the real admin API).

Skipped unless WARPGATE_URL and WARPGATE_TOKEN are set, so the normal suite is unaffected.
.github/workflows/warpgate-integration.yml starts a real Warpgate plus an OpenSSH and an xrdp
target in containers and runs this file. It drives the ENGINE's own code (not a separate SDK):
connection test, target sync create/update/remove, user + public-key registration, single-use
tickets, browser link, then the data path through Warpgate - SSH with a ticket and with the
registered key, scp, and an RDP ticket sign-in (verdict read server-side, like Warpgate's own
RDP tests, because the RDP client cannot tell a rejection from an unreachable backend).

Environment:
  WARPGATE_URL, WARPGATE_TOKEN      the gateway and an admin API token
  WG_SSH_PORT, WG_RDP_PORT          Warpgate's SSH / RDP listeners (on 127.0.0.1)
  SSH_TARGET_HOST/PORT/USER         the OpenSSH container, as Warpgate reaches it
  RDP_TARGET_HOST/PORT/USER/PASSWORD the xrdp container (the "NLA service account" slot)
Secrets (token, ticket secrets) are never printed.
"""
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

import pytest

URL = os.environ.get('WARPGATE_URL', '')
TOKEN = os.environ.get('WARPGATE_TOKEN', '')
pytestmark = pytest.mark.skipif(not (URL and TOKEN), reason='live Warpgate not configured (WARPGATE_URL/WARPGATE_TOKEN)')

WG_SSH = int(os.environ.get('WG_SSH_PORT', '2222'))
WG_RDP = int(os.environ.get('WG_RDP_PORT', '33389'))
SSH_HOST = os.environ.get('SSH_TARGET_HOST', '127.0.0.1')
SSH_PORT = int(os.environ.get('SSH_TARGET_PORT', '2201'))
SSH_USER = os.environ.get('SSH_TARGET_USER', 'moavi')
RDP_HOST = os.environ.get('RDP_TARGET_HOST', '127.0.0.1')
RDP_PORT = int(os.environ.get('RDP_TARGET_PORT', '3390'))
RDP_USER = os.environ.get('RDP_TARGET_USER', 'abc')
RDP_PASS = os.environ.get('RDP_TARGET_PASSWORD', 'abc')
RUN = uuid.uuid4().hex[:6]
USER = f'it-alice-{RUN}'
SSH_OPTS = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=20', '-p', str(WG_SSH)]


@pytest.fixture
def wg(db):
    from pegaprox.vlab import warpgate
    warpgate.save_config(URL, WG_SSH, WG_RDP, 5900, False, True, admin_token=TOKEN)
    return warpgate


@pytest.fixture
def cfg(wg):
    return wg.config(secret=True)


@pytest.fixture(scope='module')
def keypair():
    d = tempfile.mkdtemp(prefix='wg-it-')
    key = os.path.join(d, 'id_ed25519')
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'{USER}@ci', '-f', key], check=True)
    with open(key + '.pub', encoding='ascii') as f:
        return key, f.read().strip()


def _ssh_target(wg, cfg, ref='it-ssh'):
    role = wg.ensure_role(cfg)
    wg.ensure_user(cfg, USER, role)
    return wg.sync_target(cfg, ref, f'ssh-{RUN}', 'ssh', wg.ssh_target_options(SSH_HOST, SSH_PORT, SSH_USER), role)


def _run(cmd, timeout=60, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def _ssh_ticket(secret, command):
    """ssh through Warpgate with a ticket as the user name; the password is not used."""
    return _run(['sshpass', '-p', 'x', 'ssh', *SSH_OPTS, '-o', 'PreferredAuthentications=password,keyboard-interactive',
                 '-o', 'PubkeyAuthentication=no', f'ticket-{secret}@127.0.0.1', command])


# --- control plane (admin API) -----------------------------------------------------------

def test_api_connection(wg, cfg):
    ok, detail = wg.test_connection(cfg)
    assert ok, detail


def test_target_sync_create_update_remove(wg, cfg):
    role = wg.ensure_role(cfg)
    uid, name = wg.sync_target(cfg, 'it-sync', f'sync-{RUN}', 'ssh', wg.ssh_target_options(SSH_HOST, SSH_PORT, SSH_USER), role)
    got = wg._call(cfg, 'GET', f'/targets/{uid}')
    assert got['name'] == name and got['options']['host'] == SSH_HOST and got['options']['port'] == SSH_PORT
    # same desktop, new address: updated in place, same target
    uid2, _ = wg.sync_target(cfg, 'it-sync', f'sync-{RUN}', 'ssh', wg.ssh_target_options(SSH_HOST, SSH_PORT + 1, SSH_USER), role)
    assert uid2 == uid and wg._call(cfg, 'GET', f'/targets/{uid}')['options']['port'] == SSH_PORT + 1
    assert wg.remove_target(cfg, 'it-sync') == uid
    with pytest.raises(wg.WarpgateError):
        wg._call(cfg, 'GET', f'/targets/{uid}')
    assert wg.get_mapping('it-sync') is None


def test_user_and_public_key_registration(wg, cfg, keypair):
    _key, pub = keypair
    assert wg.is_public_key(pub)
    assert not wg.is_public_key('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----')
    wg.add_user_key(cfg, USER, 'ci', pub, wg.ensure_role(cfg))
    keys = wg.list_user_keys(cfg, USER)
    assert any(k['openssh_public_key'].split()[:2] == pub.split()[:2] for k in keys), keys


def test_ticket_is_single_use_for_user_and_target(wg, cfg):
    _uid, target = _ssh_target(wg, cfg)
    ticket, secret = wg.issue_ticket(cfg, USER, target)
    assert secret and ticket['username'] == USER and ticket['target'] == target
    assert ticket.get('uses_left') == 1 and ticket.get('expiry')


def test_web_ui_link_answers_and_carries_no_ticket(wg, cfg):
    import requests
    _uid, target = _ssh_target(wg, cfg)
    _ticket, secret = wg.issue_ticket(cfg, USER, target)
    link = wg.connection_coordinates(cfg, 'ssh', target, secret)['browser_url']
    assert link == URL.rstrip('/') + '/@warpgate#/' and secret not in link
    r = requests.get(link.split('#')[0], verify=False, timeout=20)
    assert r.status_code == 200, r.status_code


def test_a_ticket_opens_no_web_session_for_an_ssh_target_and_stays_unspent(wg, cfg):
    """Warpgate behaviour the design relies on: ?warpgate-ticket= signs a browser in only for HTTP
    targets. For SSH/RDP it opens nothing and does not spend the ticket - so the engine never puts a
    ticket in a browser link, and that ticket still works in a native client afterwards."""
    import requests
    _uid, target = _ssh_target(wg, cfg)
    _ticket, secret = wg.issue_ticket(cfg, USER, target)
    s = requests.Session()
    s.verify = False
    s.get(URL.rstrip('/') + f'/?warpgate-ticket={secret}', timeout=20, allow_redirects=False)
    info = s.get(URL.rstrip('/') + '/@warpgate/api/info', timeout=20).json()
    assert info.get('username') is None and not info.get('authorized_via_ticket')
    code, out = _ssh_ticket(secret, 'echo still-ok')
    assert code == 0 and 'still-ok' in out, out[-500:].replace(secret, '***')


# --- data plane (through Warpgate to the targets) ----------------------------------------

def test_ssh_with_a_ticket_and_the_ticket_is_spent(wg, cfg):
    _uid, target = _ssh_target(wg, cfg)
    _ticket, secret = wg.issue_ticket(cfg, USER, target)
    code, out = _ssh_ticket(secret, 'echo ok-$(whoami)')
    assert code == 0 and f'ok-{SSH_USER}' in out, out[-800:].replace(secret, '***')
    code2, out2 = _ssh_ticket(secret, 'echo again')
    assert code2 != 0 and 'again' not in out2, 'a single-use ticket worked twice'


def test_ssh_with_the_registered_public_key(wg, cfg, keypair):
    key, pub = keypair
    _uid, target = _ssh_target(wg, cfg)
    wg.add_user_key(cfg, USER, 'ci-ssh', pub)
    code, out = _run(['ssh', *SSH_OPTS, '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
                      '-o', f'User={wg.ssh_username(USER, target)}', '127.0.0.1', 'echo ok-$(whoami)'])
    assert code == 0 and f'ok-{SSH_USER}' in out, out[-800:]


def test_scp_through_warpgate(wg, cfg, keypair):
    key, pub = keypair
    _uid, target = _ssh_target(wg, cfg)
    wg.add_user_key(cfg, USER, 'ci-scp', pub)
    src = tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt')
    src.write(f'moavi-{RUN}\n'); src.close()
    base = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=20', '-P', str(WG_SSH), '-i', key, '-o', 'IdentitiesOnly=yes',
            '-o', f'User={wg.ssh_username(USER, target)}']
    code, out = _run(['scp', *base, src.name, f'127.0.0.1:/tmp/it-{RUN}.txt'])
    if code != 0:   # the SFTP subsystem may be off; try the legacy SCP protocol
        code, out = _run(['scp', '-O', *base, src.name, f'127.0.0.1:/tmp/it-{RUN}.txt'])
    assert code == 0, out[-800:]
    code, out = _run(['ssh', *SSH_OPTS, '-i', key, '-o', 'IdentitiesOnly=yes', '-o', f'User={wg.ssh_username(USER, target)}',
                      '127.0.0.1', f'cat /tmp/it-{RUN}.txt'])
    assert code == 0 and f'moavi-{RUN}' in out, out[-800:]


@pytest.mark.live_rdp
def test_rdp_ticket_sign_in(wg, cfg):
    """Best effort: drive Warpgate's RDP listener with xfreerdp and read the verdict server-side."""
    binary = shutil.which('xfreerdp3') or shutil.which('xfreerdp')
    if not binary:
        pytest.skip('xfreerdp not installed')
    role = wg.ensure_role(cfg)
    rdp_user = f'{USER}-rdp'
    wg.ensure_user(cfg, rdp_user, role)
    opts = wg.rdp_target_options(RDP_HOST, RDP_PORT, RDP_USER, RDP_PASS, interactive_logon=True)
    _uid, target = wg.sync_target(cfg, 'it-rdp', f'rdp-{RUN}', 'rdp', opts, role)
    _ticket, secret = wg.issue_ticket(cfg, rdp_user, target)
    coords = wg.connection_coordinates(cfg, 'rdp', target, secret)
    assert coords['username'] == f'ticket-{secret}' and coords['port'] == WG_RDP
    cmd = [binary, f'/v:127.0.0.1:{WG_RDP}', f'/u:ticket-{secret}', '/p:x', '/cert:ignore', '/sec:tls', '/log-level:INFO']
    if not os.environ.get('DISPLAY') and shutil.which('xvfb-run'):
        cmd = ['xvfb-run', '-a', *cmd]
    # own process group + a log file, not pipes: xvfb-run's xfreerdp child would keep a pipe open
    # past the timeout and hang the test; the whole group is killed instead
    log = open(os.path.join(os.environ.get('WG_OUT', tempfile.gettempdir()), 'xfreerdp.log'), 'w')
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        pass   # still connected after 25 s - fine, the verdict is read below
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        log.close()
    deadline = time.monotonic() + 20
    sessions = []
    while time.monotonic() < deadline:
        data = wg._call(cfg, 'GET', f'/sessions?username={rdp_user}')
        sessions = data.get('items', []) if isinstance(data, dict) else (data or [])
        if sessions:
            break
        time.sleep(0.5)
    assert sessions, 'Warpgate recorded no authorized RDP session for the ticket user'


@pytest.mark.live_rdp
def test_web_rdp_desktop_session_for_a_signed_in_user(wg, cfg):
    """Browser RDP through Warpgate (web-desktop): needs a signed-in Warpgate web session, so in
    production the user signs in with SSO/LDAP. Here the test user gets a throwaway password just for
    this sign-in. Starts a web-desktop session to the xrdp target and reads its first stream message."""
    import json as _json
    import requests
    import websocket
    role = wg.ensure_role(cfg)
    web_user = f'{USER}-web'
    uid = wg.ensure_user(cfg, web_user, role)
    pw = uuid.uuid4().hex
    wg._call(cfg, 'POST', f'/users/{uid}/credentials/passwords', {'password': pw})
    opts = wg.rdp_target_options(RDP_HOST, RDP_PORT, RDP_USER, RDP_PASS, interactive_logon=False)
    tid, _target = wg.sync_target(cfg, 'it-rdp-web', f'rdpweb-{RUN}', 'rdp', opts, role)
    s = requests.Session()
    s.verify = False
    host = URL.split('://', 1)[1].rstrip('/')
    s.headers['Host'] = host
    r = s.post(URL.rstrip('/') + '/@warpgate/api/auth/login', json={'username': web_user, 'password': pw}, timeout=20)
    assert r.status_code // 100 == 2, r.status_code
    r = s.post(URL.rstrip('/') + '/@warpgate/api/web-desktop/sessions', json={'target_id': tid}, timeout=30)
    assert r.status_code == 201, (r.status_code, r.text[:300])
    sid = r.json()['session_id']
    cookie = '; '.join(f'{c.name}={c.value}' for c in s.cookies)
    ws = websocket.create_connection(URL.replace('https:', 'wss:').rstrip('/') + f'/@warpgate/api/web-desktop/sessions/{sid}/stream',
                                     header=[f'Cookie: {cookie}', f'Host: {host}'], sslopt={'cert_reqs': 0}, timeout=30)
    try:
        first = ws.recv()
    finally:
        ws.close()
        s.delete(URL.rstrip('/') + f'/@warpgate/api/web-desktop/sessions/{sid}', timeout=20)
    if isinstance(first, str):
        msg = _json.loads(first)
        assert msg.get('type') != 'error', msg

