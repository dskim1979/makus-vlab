# -*- coding: utf-8 -*-
"""
vLAB pool policy (MAKUS): how the desktops of a pool are reached and kept.

Kept in vlab_pools.settings['policy']; a pool without one gets DEFAULTS. Where each setting
takes effect:
  protocols, spice_fullscreen  connect route (allowed protocols, the .vv file)
  clipboard                    the browser console (noVNC) - SPICE leaves it to the guest agent
  usb_redirect, usb_autoshare  the .vv file (SPICE USB redirection)
  start_on_connect             connect route: a stopped desktop is started, the user retries
  idle_shutdown_min            background tick: shut down after that long without a session
  reset_on_logout              session end: back to the base (reset and scheduled pools only)
  allow_power                  the user's power route and buttons
  max_session_hours            background tick: a session open longer is closed
"""

PROTOCOLS = ('vnc', 'spice')
CLIPBOARD = ('both', 'to_desktop', 'from_desktop', 'off')
RESET_TYPES = ('reset', 'classroom')

DEFAULTS = {
    'protocols': ['vnc', 'spice'],
    'spice_fullscreen': False,
    'clipboard': 'both',
    'usb_redirect': True,
    'usb_autoshare': False,
    'start_on_connect': True,
    'idle_shutdown_min': 0,
    'reset_on_logout': False,
    'allow_power': True,
    'max_session_hours': 0,
}

_BOOLS = ('spice_fullscreen', 'usb_redirect', 'usb_autoshare', 'start_on_connect', 'reset_on_logout', 'allow_power')
_LIMITS = {'idle_shutdown_min': (0, 10080), 'max_session_hours': (0, 720)}   # a week, a month


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
                return None, 'protocols: a non-empty list of vnc, spice'
            out[k] = [p for p in PROTOCOLS if p in v]
        elif k == 'clipboard':
            if v not in CLIPBOARD:
                return None, f"clipboard must be one of {', '.join(CLIPBOARD)}"
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
