"""MOAVI Desk: which features a site uses (플랫폼 설정 > 기능, the first-setup wizard).

A site picks a profile - what kind of place it is - and may add bundles. The profile and the
bundles switch feature groups on; the console shows only the menus and portal links of the
groups that are on, and the background loop skips the work of groups that are off. Nothing
is deleted when a group goes off: switching it on again brings everything back.

Until an admin has chosen (`chosen` false) every group is on, so an existing install keeps
all its menus; the console then offers the wizard. A fresh install can also be told what it is
through the environment (VLAB_PROFILE, VLAB_FEATURES, docker compose .env): applied once, at the
first read, never over a choice an admin made.
"""
import os

from pegaprox.core.db import get_db

KEY = 'vlab_features'

# feature groups beyond the core (desktops, pools, images, users, cluster, alerts, backup,
# reports, audit, notices, client, support bundle), which are always on
GROUPS = ('lab', 'signup', 'org', 'external', 'data', 'ha', 'fpga', 'gpuai')
BUNDLES = ('fpga', 'gpuai')
PROFILES = {
    'general': ('org', 'external'),                 # 일반 업무 VDI (범용, ~100대)
    'small_lab': (),                                # 소규모 연구실
    'university': ('lab', 'signup', 'org'),         # 대학교 실습실
    'research': ('org', 'external', 'data', 'ha'),  # 연구소 · 기업 R&D
}


def _clean(profile, groups):
    profile = profile if profile in PROFILES else 'general'
    return profile, sorted({g for g in groups or () if g in GROUPS})


def defaults_for(profile, bundles=()):
    """The groups a profile switches on, with the chosen bundles."""
    profile, _ = _clean(profile, ())
    return sorted(set(PROFILES[profile]) | {b for b in bundles or () if b in BUNDLES})


def _from_env():
    profile = (os.environ.get('VLAB_PROFILE') or '').strip().lower().replace('-', '_')
    if profile not in PROFILES:
        return None
    extra = [x.strip().lower().replace('-', '') for x in (os.environ.get('VLAB_FEATURES') or '').split(',')]
    extra = [{'gpu_ai': 'gpuai', 'gpuai': 'gpuai'}.get(x, x) for x in extra]
    return {'profile': profile, 'groups': defaults_for(profile, extra), 'chosen': True, 'by': 'env'}


def get():
    """{profile, groups, chosen}. Not chosen yet: every group on."""
    raw = get_db().get_server_setting(KEY, None)
    if not isinstance(raw, dict) or not raw.get('chosen'):
        env = _from_env()
        if env is not None:
            try:
                get_db().save_server_setting(KEY, env)
            except Exception:       # a standby refuses writes: just answer with it
                pass
            return dict(env)
        return {'profile': None, 'groups': list(GROUPS), 'chosen': False}
    profile, groups = _clean(raw.get('profile'), raw.get('groups'))
    return {'profile': profile, 'groups': groups, 'chosen': True}


def save(profile, groups, by=''):
    profile, groups = _clean(profile, groups)
    value = {'profile': profile, 'groups': groups, 'chosen': True, 'by': by}
    get_db().save_server_setting(KEY, value)
    return {'profile': profile, 'groups': groups, 'chosen': True}


def enabled(group):
    """Is a feature group on. Core features are always on; an unreadable setting means on."""
    if group not in GROUPS:
        return True
    try:
        return group in get()['groups']
    except Exception:
        return True
