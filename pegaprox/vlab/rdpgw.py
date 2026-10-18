# -*- coding: utf-8 -*-
"""
보안 게이트웨이 · 장치 연결 방식 (MAKUS): the .rdp of a pool whose policy says rdp_route='devices'
goes through the bundled RD Gateway (rdpgw, github.com/bolkedebruin/rdpgw) instead of Warpgate.

Warpgate takes RDP apart to record it and drops the device channels on the way (drives, printers,
USB, audio input, smart cards). rdpgw only carries the client's encrypted RDP stream to the desktop
(MS-TSGU over HTTPS), so every channel the .rdp asks for works - and nothing is recorded; the
connect is in the audit log. The desktop's address stays behind the gateway as with Warpgate: the
client is let through only to the one desktop its token names.

The token (rdpgw "PAA cookie") is made here, not by rdpgw: an HS256 JWT signed with the key both
sides share (VLAB_RDPGW_KEY, 32 characters - rdpgw silently replaces any other length with a random
one), valid TOKEN_MINUTES, naming the user, the desktop (address:port) and the client address the
engine saw. rdpgw refuses a token for any other desktop, after its expiry or from another address.
Nothing of the user's password is in it.

Environment (deploy/docker-compose.yml, VLAB_RDPGW=1):
  VLAB_RDPGW              1 = on
  VLAB_RDPGW_KEY          the shared signing key (rdpgw: RDPGW_SECURITY__PAATOKENSIGNINGKEY)
  VLAB_RDPGW_HOST         host[:port] the user's PC reaches the gateway on (the console's HTTPS
                          address: vlab-proxy passes /remoteDesktopGateway/ on to rdpgw)
  VLAB_RDPGW_VERIFY_CLIENT_IP  0 = do not bind the token to the client address (must match rdpgw's
                          RDPGW_SECURITY__VERIFYCLIENTIP); default 1
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import time
import uuid

GATEWAY_PATH = '/remoteDesktopGateway/'
TOKEN_MINUTES = 5
KEY_LENGTH = 32
INTERNAL = ('rdpgw', 80)    # where the engine checks it answers (the compose network)

# devices the .rdp hands to the desktop when the pool allows them (pegaprox/vlab/policy.py usb_redirect)
USB_LINES = ('usbdevicestoredirect:s:*', 'devicestoredirect:s:*')


def config():
    key = os.environ.get('VLAB_RDPGW_KEY', '').strip()
    host = os.environ.get('VLAB_RDPGW_HOST', '').strip()
    on = os.environ.get('VLAB_RDPGW', '0').strip() == '1'
    problem = ''
    if on and len(key) != KEY_LENGTH:
        problem = f'VLAB_RDPGW_KEY must be {KEY_LENGTH} characters'
    elif on and not host:
        problem = 'VLAB_RDPGW_HOST is empty'
    return {'enabled': on and not problem, 'requested': on, 'problem': problem, 'host': host, 'key': key,
            'verify_client_ip': os.environ.get('VLAB_RDPGW_VERIFY_CLIENT_IP', '1').strip() != '0'}


def is_enabled():
    return config()['enabled']


def status():
    """For the console (no key in it)."""
    c = config()
    return {'enabled': c['enabled'], 'requested': c['requested'], 'problem': c['problem'], 'host': c['host'],
            'verify_client_ip': c['verify_client_ip'], 'token_minutes': TOKEN_MINUTES}


def reachable(timeout=2.0):
    """Does rdpgw answer inside the compose network (TCP)?"""
    try:
        with socket.create_connection(INTERNAL, timeout=timeout):
            return True
    except OSError:
        return False


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def paa_token(key, username, server, client_ip, now=None):
    """rdpgw's PAA token for one connect: `server` is 'address:port' exactly as the client will ask
    for it (rdpgw compares host:port), `client_ip` the address the engine saw."""
    now = int(now if now is not None else time.time())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    claims = {'iss': 'rdpgw', 'aud': ['rdpgw-paa'], 'sub': username, 'jti': uuid.uuid4().hex,
              'iat': now, 'nbf': now - 30, 'exp': now + TOKEN_MINUTES * 60,
              'remoteServer': server, 'clientIp': client_ip}
    signing_input = '.'.join(_b64(json.dumps(x, separators=(',', ':')).encode()) for x in (header, claims))
    sig = hmac.new(key.encode(), signing_input.encode('ascii'), hashlib.sha256).digest()
    return f'{signing_input}.{_b64(sig)}'


def rdp_file_text(cfg, token, address, port, username, redirect_lines=(), network_lines=()):
    """An .rdp aimed at the desktop through the gateway: the user signs in to the desktop itself
    (Windows asks), the gateway lets this client through with the token."""
    lines = [f'full address:s:{address}:{int(port)}', f'username:s:{username}', 'prompt for credentials:i:1',
             f"gatewayhostname:s:{cfg['host']}", 'gatewayusagemethod:i:1', 'gatewayprofileusagemethod:i:1',
             'gatewaycredentialssource:i:5', 'gatewaybrokeringtype:i:0', f'gatewayaccesstoken:s:{token}',
             'screen mode id:i:2', 'use multimon:i:1', *redirect_lines, 'audiomode:i:0', 'authentication level:i:2',
             *network_lines]
    return '\r\n'.join(lines) + '\r\n'
