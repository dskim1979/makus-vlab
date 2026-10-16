# -*- coding: utf-8 -*-
"""
MOAVI Desk - the research environment catalogue (가상머신 > 환경 카탈로그).

A golden image carries an "environment": what it is for (AI framework, FPGA tools, NPU SDK or
general), the components in it with their versions (Ubuntu 22.04, NVIDIA driver 550, CUDA 12.4,
cuDNN 9, PyTorch 2.4, ROCm 6.x, Vivado 2024.2, FuriosaAI / Rebellions SDK...), the cards it is
made for (PCI mappings, vendors), a description and a change history.

What is here is plain data and rules, so the routes (pegaprox/api/vlab_env.py) and the tests can
use it without a cluster:

  * the table vlab_golden_env (one row per golden image, HA-synced like the image itself)
  * PROBE_LINUX / PROBE_WINDOWS: the script the guest agent runs to read the versions ("버전
    읽기"), and parse_probe() that turns its output into components - only what is installed
  * the compatibility rules: which NVIDIA driver a CUDA version needs, the driver branch of an
    NVIDIA vGPU release, and compat() that compares a node (host driver / vGPU manager) with an
    environment (guest driver / CUDA / the CUDA of the PyTorch build)

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).
"""

import json
import re
import threading

from pegaprox.vlab.store import db as _store_db, now

KINDS = ('ai', 'fpga', 'npu', 'general')

# the components the catalogue knows by key; any other key is kept as the administrator wrote it
COMPONENTS = {
    'os': 'OS',
    'nvidia_driver': 'NVIDIA driver',
    'cuda': 'CUDA',
    'cudnn': 'cuDNN',
    'pytorch': 'PyTorch',
    'tensorflow': 'TensorFlow',
    'jax': 'JAX',
    'python': 'Python',
    'rocm': 'ROCm',
    'vivado': 'Vivado',
    'vitis': 'Vitis',
    'quartus': 'Quartus',
    'furiosa': 'FuriosaAI SDK',
    'rbln': 'Rebellions RBLN SDK',
}
# the order a card shows its versions in, most telling first
HIGHLIGHT = ('cuda', 'pytorch', 'tensorflow', 'jax', 'rocm', 'vivado', 'vitis', 'quartus', 'furiosa', 'rbln',
             'nvidia_driver', 'cudnn', 'os', 'python')
KEY = re.compile(r'^[a-z][a-z0-9_]{0,31}$')
HISTORY_KEEP = 50

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_golden_env (
        golden_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL DEFAULT 'general',
        components TEXT NOT NULL DEFAULT '[]',
        cards TEXT NOT NULL DEFAULT '{}',
        description TEXT NOT NULL DEFAULT '',
        history TEXT NOT NULL DEFAULT '[]',
        probe TEXT NOT NULL DEFAULT '{}',
        probed_at TEXT,
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_golden_env',)

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_golden_env', False):
        with _lock:
            if not getattr(d, '_vlab_golden_env', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_golden_env = True
    return d


def _loads(v, default):
    try:
        out = json.loads(v or '')
    except (TypeError, ValueError):
        return default
    return out if isinstance(out, type(default)) else default


def _row(r):
    if not r:
        return None
    return {'golden_id': r['golden_id'], 'kind': r['kind'], 'components': _loads(r['components'], []),
            'cards': _loads(r['cards'], {}), 'description': r['description'], 'history': _loads(r['history'], []),
            'probe': _loads(r['probe'], {}), 'probed_at': r['probed_at'], 'updated_by': r['updated_by'],
            'updated_at': r['updated_at']}


def get(golden_id):
    return _row(db().query_one('SELECT * FROM vlab_golden_env WHERE golden_id = ?', (golden_id,)))


def all_envs():
    return {r['golden_id']: _row(r) for r in db().query('SELECT * FROM vlab_golden_env')}


def empty(golden_id):
    return {'golden_id': golden_id, 'kind': 'general', 'components': [], 'cards': {'mappings': [], 'vendors': []},
            'description': '', 'history': [], 'probe': {}, 'probed_at': None, 'updated_by': '', 'updated_at': None}


def changes(old, new):
    """[{key, from, to}] between two component lists (by key)."""
    a = {c['key']: c.get('version', '') for c in old or []}
    b = {c['key']: c.get('version', '') for c in new or []}
    out = []
    for k in list(a) + [k for k in b if k not in a]:
        if a.get(k) != b.get(k):
            out.append({'key': k, 'from': a.get(k), 'to': b.get(k)})
    return out


def save(golden_id, by, kind=None, components=None, cards=None, description=None, note='', version=''):
    """Write what is given; a change of the components (or a note) adds a history entry."""
    cur = get(golden_id) or empty(golden_id)
    new = dict(cur)
    if kind is not None:
        new['kind'] = kind
    if components is not None:
        new['components'] = components
    if cards is not None:
        new['cards'] = cards
    if description is not None:
        new['description'] = description
    diff = changes(cur['components'], new['components'])
    if diff or note or kind not in (None, cur['kind']):
        entry = {'at': now(), 'by': by, 'note': note, 'changes': diff, 'version': version}
        if kind not in (None, cur['kind']):
            entry['kind'] = {'from': cur['kind'], 'to': kind}
        new['history'] = ([entry] + list(cur['history']))[:HISTORY_KEEP]
    db().execute('INSERT OR REPLACE INTO vlab_golden_env (golden_id, kind, components, cards, description, history, probe, '
                 'probed_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (golden_id, new['kind'], json.dumps(new['components'], ensure_ascii=False),
                  json.dumps(new['cards'], ensure_ascii=False), new['description'],
                  json.dumps(new['history'], ensure_ascii=False), json.dumps(cur['probe'], ensure_ascii=False),
                  cur['probed_at'], by, now()))
    return get(golden_id)


def set_probe(golden_id, probe, by):
    if not get(golden_id):
        save(golden_id, by)
    db().execute('UPDATE vlab_golden_env SET probe = ?, probed_at = ? WHERE golden_id = ?',
                 (json.dumps(probe, ensure_ascii=False), now(), golden_id))
    return get(golden_id)


def delete(golden_id):
    db().execute('DELETE FROM vlab_golden_env WHERE golden_id = ?', (golden_id,))


def clean_components(items):
    """The components of a PUT: [{key, version, name?}], keys unique. Raises ValueError."""
    if not isinstance(items, list) or len(items) > 40:
        raise ValueError('components: a list of up to 40 {key, version}')
    out, seen = [], set()
    for c in items:
        if not isinstance(c, dict):
            raise ValueError('components: each one is {key, version}')
        key = str(c.get('key') or '').strip().lower()
        if not KEY.match(key):
            raise ValueError(f"component key '{key}': letters, digits and _, starting with a letter")
        if key in seen:
            raise ValueError(f"component '{key}' is listed twice")
        seen.add(key)
        version = str(c.get('version') or '').strip()
        name = str(c.get('name') or COMPONENTS.get(key) or key).strip()
        if not version or len(version) > 60 or len(name) > 60:
            raise ValueError(f"component '{key}': a version of up to 60 characters")
        item = {'key': key, 'name': name, 'version': version}
        if c.get('source') in ('probe', 'manual'):
            item['source'] = c['source']
        out.append(item)
    return out


def highlights(env, n=4):
    """'CUDA 12.4', 'PyTorch 2.4.1', ... in HIGHLIGHT order, for a card or the portal."""
    if not env:
        return []
    by = {c['key']: c for c in env.get('components') or []}
    keys = [k for k in HIGHLIGHT if k in by] + [k for k in by if k not in HIGHLIGHT]
    return [by[k]['version'] if k == 'os' else f"{by[k].get('name') or COMPONENTS.get(k, k)} {by[k]['version']}"
            for k in keys[:n]]


def version_of(env, key):
    for c in (env or {}).get('components') or []:
        if c.get('key') == key:
            return c.get('version') or ''
    return ''


# --- 버전 읽기: the script the guest agent runs, and its output ------------------------------
#
# Each section starts with a line '@@<key>'; a tool that is not there prints nothing, so its
# component is left out. Vivado and Vitis are looked for on PATH and in the usual install
# folders (/tools/Xilinx, /opt/Xilinx); `vivado -version` takes a few seconds.

PROBE_LINUX = r'''
q() { "$@" 2>/dev/null; }
py=$(command -v python3 || command -v python)
echo @@os; q . /etc/os-release && echo "$NAME $VERSION_ID"
echo @@nvidia_driver; q nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1
echo @@cuda_driver; q nvidia-smi | grep -o 'CUDA Version: [0-9.]*' | head -1
echo @@cuda; (q nvcc --version || q /usr/local/cuda/bin/nvcc --version) | grep -i release | head -1
echo @@cudnn; q cat /usr/include/cudnn_version.h /usr/include/x86_64-linux-gnu/cudnn_version_v*.h /usr/local/cuda/include/cudnn_version.h | grep -E '^#define CUDNN_(MAJOR|MINOR|PATCHLEVEL) ' | head -3
if [ -n "$py" ]; then
echo @@python; q "$py" --version
echo @@pytorch; q "$py" -c 'import torch;print(torch.__version__, torch.version.cuda or "", getattr(torch.version, "hip", "") or "")'
echo @@tensorflow; TF_CPP_MIN_LOG_LEVEL=3 q "$py" -c 'import tensorflow as t;print(t.__version__)'
echo @@jax; q "$py" -c 'import jax;print(jax.__version__)'
echo @@rbln; q "$py" -c 'import rebel;print(rebel.__version__)'
fi
echo @@rocm; q cat /opt/rocm/.info/version | head -1
echo @@vivado; for v in vivado /tools/Xilinx/Vivado/*/bin/vivado /opt/Xilinx/Vivado/*/bin/vivado; do if command -v "$v" >/dev/null 2>&1; then q timeout 60 "$v" -version | grep -m1 -i vivado; break; fi; done
echo @@vitis; for v in v++ /tools/Xilinx/Vitis/*/bin/v++ /opt/Xilinx/Vitis/*/bin/v++; do if command -v "$v" >/dev/null 2>&1; then q timeout 30 "$v" --version | grep -m1 -iE 'v\+\+|vitis'; break; fi; done
echo @@quartus; for v in quartus_sh /opt/intelFPGA*/*/quartus/bin/quartus_sh /opt/altera*/*/quartus/bin/quartus_sh; do if command -v "$v" >/dev/null 2>&1; then q timeout 30 "$v" --version | grep -m1 -i version; break; fi; done
echo @@furiosa; (q furiosa-smi --version || q furiosactl version || q furiosa --version) | head -1
echo @@rbln_driver; (q rbln-stat --version || q rbln-smi --version) | head -1
echo @@end
'''

PROBE_WINDOWS = r'''
$ErrorActionPreference = 'SilentlyContinue'
function Q($b) { try { & $b 2>$null } catch {} }
'@@os'; (Get-CimInstance Win32_OperatingSystem).Caption
'@@nvidia_driver'; Q { nvidia-smi --query-gpu=driver_version --format=csv,noheader } | Select-Object -First 1
'@@cuda_driver'; Q { nvidia-smi } | Select-String -Pattern 'CUDA Version: [0-9.]+' | ForEach-Object { $_.Matches[0].Value } | Select-Object -First 1
'@@cuda'; Q { nvcc --version } | Select-String -Pattern 'release' | Select-Object -First 1 | ForEach-Object { $_.Line }
'@@python'; Q { python --version }
'@@pytorch'; Q { python -c "import torch;print(torch.__version__, torch.version.cuda or '')" }
'@@tensorflow'; $env:TF_CPP_MIN_LOG_LEVEL='3'; Q { python -c "import tensorflow as t;print(t.__version__)" }
'@@vivado'; $v = Get-ChildItem 'C:\Xilinx\Vivado\*\bin\vivado.bat' | Select-Object -Last 1; if ($v) { Q { & $v.FullName -version } | Select-String -Pattern 'Vivado' | Select-Object -First 1 | ForEach-Object { $_.Line } }
'@@quartus'; $q = Get-ChildItem 'C:\intelFPGA*\*\quartus\bin64\quartus_sh.exe' | Select-Object -Last 1; if ($q) { Q { & $q.FullName --version } | Select-String -Pattern 'Version' | Select-Object -First 1 | ForEach-Object { $_.Line } }
'@@end'
'''


def _sections(out):
    cur, sec = None, {}
    for line in str(out or '').splitlines():
        s = line.strip()
        if s.startswith('@@'):
            cur = s[2:]
            sec.setdefault(cur, [])
        elif cur and s:
            sec[cur].append(s)
    return sec


_VER = re.compile(r'(\d+(?:\.\d+){0,3}[a-z0-9.+\-]*)', re.I)


def _first_version(text):
    m = _VER.search(text or '')
    return m.group(1) if m else ''


def parse_probe(out):
    """The output of PROBE_LINUX / PROBE_WINDOWS -> {'components': [...], 'driver_cuda': '12.4'|'',
    'pytorch_cuda': '12.4'|'', 'pytorch_hip': ''}. Only what was found is listed."""
    sec = _sections(out)
    comps = []

    def add(key, version):
        version = str(version or '').strip()[:60]
        if version:
            comps.append({'key': key, 'name': COMPONENTS.get(key, key), 'version': version, 'source': 'probe'})

    first = {k: (v[0] if v else '') for k, v in sec.items()}
    add('os', first.get('os', ''))
    add('nvidia_driver', _first_version(first.get('nvidia_driver', '')))
    m = re.search(r'release\s+([\d.]+)', first.get('cuda', ''), re.I)
    add('cuda', m.group(1) if m else '')
    nums = {}
    for line in sec.get('cudnn') or []:
        mm = re.match(r'#define CUDNN_(MAJOR|MINOR|PATCHLEVEL)\s+(\d+)', line)
        if mm:
            nums[mm.group(1)] = mm.group(2)
    if 'MAJOR' in nums:
        add('cudnn', '.'.join(nums[k] for k in ('MAJOR', 'MINOR', 'PATCHLEVEL') if k in nums))
    add('python', _first_version(first.get('python', '')))
    torch = first.get('pytorch', '').split()
    pytorch_cuda = torch[1] if len(torch) > 1 and re.match(r'^\d+\.\d+', torch[1]) else ''
    pytorch_hip = torch[2] if len(torch) > 2 else ''
    add('pytorch', torch[0] if torch else '')
    add('tensorflow', _first_version(first.get('tensorflow', '')))
    add('jax', _first_version(first.get('jax', '')))
    add('rocm', _first_version(first.get('rocm', '')))
    m = re.search(r'v?(\d{4}\.\d(?:\.\d+)?)', first.get('vivado', ''))
    add('vivado', m.group(1) if m else '')
    m = re.search(r'v?(\d{4}\.\d(?:\.\d+)?)', first.get('vitis', ''))
    add('vitis', m.group(1) if m else '')
    m = re.search(r'Version\s+([\d.]+)', first.get('quartus', ''), re.I)
    add('quartus', m.group(1) if m else '')
    add('furiosa', _first_version(first.get('furiosa', '')))
    rbln = _first_version(first.get('rbln', '')) or _first_version(first.get('rbln_driver', ''))
    add('rbln', rbln)
    m = re.search(r'CUDA Version:\s*([\d.]+)', first.get('cuda_driver', ''))
    return {'components': comps, 'driver_cuda': m.group(1) if m else '', 'pytorch_cuda': pytorch_cuda,
            'pytorch_hip': pytorch_hip, 'complete': 'end' in sec}


def merge(components, found):
    """The components with the probed versions written over those of the same key; components
    the probe does not know (or did not find) stay as they were."""
    out = [dict(c) for c in components or []]
    idx = {c['key']: i for i, c in enumerate(out)}
    for f in found or []:
        if f['key'] in idx:
            out[idx[f['key']]].update(version=f['version'], source='probe')
        else:
            idx[f['key']] = len(out)
            out.append(dict(f))
    return out


# --- compatibility -------------------------------------------------------------------------

# the minimum Linux driver of each CUDA toolkit (NVIDIA CUDA release notes, table 3)
CUDA_MIN_DRIVER = (
    ('13.0', '580.65'), ('12.9', '575.51'), ('12.8', '570.26'), ('12.6', '560.28'), ('12.5', '555.42'),
    ('12.4', '550.54'), ('12.3', '545.23'), ('12.2', '535.54'), ('12.1', '530.30'), ('12.0', '525.60'),
    ('11.8', '520.61'), ('11.7', '515.43'), ('11.6', '510.39'), ('11.5', '495.29'), ('11.4', '470.42'),
    ('11.3', '465.19'), ('11.2', '460.27'), ('11.1', '455.23'), ('11.0', '450.36'),
)
# minor version compatibility: an application of CUDA major X runs on a driver of at least this,
# without PTX JIT of newer code (the CUDA compatibility guide)
CUDA_MAJOR_FLOOR = {'11': '450.80', '12': '525.60', '13': '580.65'}
# the driver branch of each NVIDIA vGPU software release (host vGPU manager and guest driver)
VGPU_BRANCH = {'13': '470', '14': '510', '15': '525', '16': '535', '17': '550', '18': '570', '19': '580'}
BRANCH_VGPU = {v: k for k, v in VGPU_BRANCH.items()}
# the oldest driver branch that knows a GPU generation (by model name)
ARCH_MIN_DRIVER = (
    (re.compile(r'\b(B200|B100|GB200|RTX PRO 6000|RTX 50\d\d)', re.I), '570', 'Blackwell'),
    (re.compile(r'\b(H200|H100|H800|H20|GH200)\b', re.I), '525', 'Hopper'),
    (re.compile(r'\b(L40S?|L4|L20|RTX 6000 Ada|RTX 40\d\d)\b', re.I), '525', 'Ada'),
    (re.compile(r'\b(A100|A800|A30|A40|A16|A10|A2|RTX A\d000)\b', re.I), '450', 'Ampere'),
)


def vtuple(v):
    """'550.54.15' -> (550, 54, 15); '' -> ()."""
    return tuple(int(x) for x in re.findall(r'\d+', str(v or ''))[:4])


def branch(driver):
    t = vtuple(driver)
    return str(t[0]) if t else ''


def cuda_needs(cuda):
    """The minimum driver of a CUDA version ('12.4' -> '550.54'); '' when unknown."""
    t = vtuple(cuda)[:2]
    for c, d in CUDA_MIN_DRIVER:
        if vtuple(c) == t:
            return d
    for c, d in CUDA_MIN_DRIVER:          # a newer minor than the table knows: the newest of the major
        if t and vtuple(c)[0] == t[0] and vtuple(c) <= t:
            return d
    return ''


def driver_cuda(driver):
    """The newest CUDA a driver runs fully ('550.90' -> '12.4')."""
    t = vtuple(driver)
    for c, d in CUDA_MIN_DRIVER:
        if t and t >= vtuple(d):
            return c
    return ''


def arch_of(model):
    for rx, minimum, name in ARCH_MIN_DRIVER:
        if rx.search(model or ''):
            return name, minimum
    return '', ''


def _n(sev, ko, en, code):
    return {'severity': sev, 'code': code, 'ko': ko, 'en': en}


def cuda_check(driver, cuda, label=''):
    """Notes for running CUDA `cuda` on driver `driver`; `label` names what needs it."""
    need = cuda_needs(cuda)
    what = label or f'CUDA {cuda}'
    if not driver or not cuda or not need:
        return []
    if vtuple(driver) >= vtuple(need):
        return []
    floor = CUDA_MAJOR_FLOOR.get(str(vtuple(cuda)[0]))
    if floor and vtuple(driver) >= vtuple(floor):
        return [_n('warn', f'{what}에는 드라이버 {need} 이상이 맞습니다. 드라이버 {driver}에서는 부 버전 호환으로 돌지만 PTX JIT · 새 기능이 필요한 코드는 실패할 수 있습니다.',
                   f'{what} wants driver {need} or newer. Driver {driver} runs it through minor version compatibility, but code that needs PTX JIT or newer features may fail.',
                   'CUDA_MINOR_COMPAT')]
    return [_n('error', f'{what}에는 드라이버 {need} 이상이 필요합니다(지금 {driver}). CUDA 프로그램이 "driver version is insufficient"로 멈춥니다.',
               f'{what} needs driver {need} or newer (this is {driver}): CUDA programs stop with "driver version is insufficient".',
               'CUDA_DRIVER_OLD')]


def compat(env, node, use_vgpu=None):
    """One cell of the compatibility table: an environment on a node.

    env:  {'components': [...], 'probe': {...}}
    node: {'driver': host NVIDIA driver or '', 'vgpu_manager': bool, 'models': [GPU model names],
           'readable': bool}
    use_vgpu: True / False when the pools of the image say, None to follow the node.
    -> {'status': ok|warn|error|unknown, 'mode': vgpu|passthrough, 'notes': [...], ...}"""
    guest = version_of(env, 'nvidia_driver')
    cuda = version_of(env, 'cuda')
    torch_cuda = ((env or {}).get('probe') or {}).get('pytorch_cuda') or ''
    torch_v = version_of(env, 'pytorch')
    if not torch_cuda:
        m = re.search(r'\+cu(\d+)(\d)$', torch_v)
        torch_cuda = f'{m.group(1)}.{m.group(2)}' if m else ''
    vgpu = node.get('vgpu_manager') if use_vgpu is None else use_vgpu
    host = node.get('driver') or ''
    cell = {'mode': 'vgpu' if vgpu else 'passthrough', 'host_driver': host, 'host_branch': branch(host),
            'host_vgpu_release': BRANCH_VGPU.get(branch(host), '') if vgpu else '', 'guest_driver': guest,
            'guest_branch': branch(guest), 'cuda': cuda, 'pytorch_cuda': torch_cuda, 'notes': []}
    notes = cell['notes']
    if not node.get('readable', True):
        notes.append(_n('info', '노드의 NVIDIA 드라이버를 읽지 못했습니다(SSH).', 'The node\'s NVIDIA driver could not be read (SSH).', 'NODE_UNREAD'))
    if vgpu:
        if not host:
            notes.append(_n('warn', '노드에 vGPU 매니저(NVIDIA 호스트 드라이버)가 보이지 않습니다. vGPU 프로필을 쓰려면 노드에 vGPU 매니저를 설치하세요.',
                            'No vGPU manager (NVIDIA host driver) on the node. Install the vGPU manager to use vGPU profiles.', 'NO_VGPU_MANAGER'))
        elif guest:
            hb, gb = branch(host), branch(guest)
            if hb != gb:
                rel_h, rel_g = BRANCH_VGPU.get(hb, '?'), BRANCH_VGPU.get(gb, '?')
                newer = int(gb or 0) > int(hb or 0)
                notes.append(_n('error' if newer else 'warn',
                                f'NVIDIA vGPU는 호스트 vGPU 매니저와 게스트 드라이버의 릴리스 브랜치가 같아야 합니다. 호스트 {host}(vGPU {rel_h}, R{hb}) · 게스트 {guest}(vGPU {rel_g}, R{gb}). '
                                + ('게스트가 더 새것이라 vGPU가 붙지 않습니다.' if newer else '이전 브랜치 게스트는 NVIDIA 지원 조합일 때만 동작합니다. 게스트 드라이버를 호스트와 같은 브랜치로 맞추세요.'),
                                f'NVIDIA vGPU needs the host vGPU manager and the guest driver on the same release branch. Host {host} (vGPU {rel_h}, R{hb}), guest {guest} (vGPU {rel_g}, R{gb}). '
                                + ('The guest is newer: the vGPU will not come up.' if newer else 'An older guest branch only works in combinations NVIDIA supports; put the guest on the host\'s branch.'),
                                'VGPU_BRANCH'))
        else:
            notes.append(_n('info', '게스트 NVIDIA 드라이버 버전이 적혀 있지 않습니다. 버전 읽기로 채우면 vGPU 브랜치를 비교합니다.',
                            'The guest NVIDIA driver is not noted; read the versions to compare the vGPU branch.', 'NO_GUEST_DRIVER'))
    for model in sorted(set(node.get('models') or [])):
        arch, minimum = arch_of(model)
        if arch and guest and vtuple(guest) < vtuple(minimum):
            notes.append(_n('error', f'{model}({arch})은 드라이버 R{minimum} 이상이 필요합니다(게스트 {guest}).',
                            f'{model} ({arch}) needs driver R{minimum} or newer (guest {guest}).', 'ARCH_DRIVER'))
    notes += cuda_check(guest, cuda)
    if torch_cuda and torch_cuda != cuda:
        notes += cuda_check(guest, torch_cuda, f'PyTorch {torch_v} (CUDA {torch_cuda})')
    if not guest and not cuda:
        cell['status'] = 'unknown' if not notes else _worst(notes)
    else:
        cell['status'] = _worst(notes)
    return cell


def _worst(notes):
    sev = {n['severity'] for n in notes}
    return 'error' if 'error' in sev else ('warn' if 'warn' in sev else 'ok')


def portal_view(pool, envs=None, golden=None):
    """What 받을 수 있는 데스크톱 shows of a pool's environment: {name, kind, highlights} of the
    golden image the pool is deployed from, or None."""
    from pegaprox.vlab import catalog
    gid = ((pool or {}).get('settings') or {}).get('golden_id')
    if not gid:
        return None
    env = (envs if envs is not None else {}).get(gid) if envs is not None else get(gid)
    if not env:
        return None
    img = (golden or {}).get(gid) if golden is not None else catalog.get_golden(gid)
    return {'name': (img or {}).get('name') or '', 'kind': env['kind'], 'highlights': highlights(env, 3)}
