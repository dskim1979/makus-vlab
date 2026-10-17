"""MOAVI Desk: what a build job leaves behind (빌드 결과물) - kept and downloadable.

When a build or GPU job ends, its work folder is searched (through the build VM's guest agent,
as the job's user) for the files the pool keeps: bitstreams, reports, logs, models. They are
copied to the NAS beside the users' folders,

    <shared storage>/artifacts/<user>/<job id>/<path in the work folder>

and listed on the job (path, size). Without shared storage, or when the user cannot write the
artifacts/ folder (the admin makes it once, 1777 like scratch/), they are only listed where they
are, in the work folder, as long as it lasts. Folders of jobs older than keep_days are removed
at the next collection of that user.

A download goes through the pool's admin mount on the engine host when it is there, else
through the build VM's guest agent (small files, datasets.AGENT_MAX_BYTES). The pool's export
rule (연구 데이터 > 반출 · 업로드 규칙) applies, as to any file leaving the NAS.

Settings are a server setting: a default and per build farm pool (GPU · FPGA · NPU > 빌드 팜 > 결과물).
The routes are in pegaprox/api/vlab_builds.py.
"""
import json
import re
import shlex

from pegaprox.core.db import get_db

KEY = 'vlab_artifacts'
DEFAULTS = {
    'enabled': True,
    'patterns': ['*.bit', '*.bin', '*.xclbin', '*.xsa', '*.ltx', '*.sof', '*.pof', '*.rpt', '*.log'],
    'max_files': 50,
    'max_mb': 1024,          # a single file larger than this is left out
    'keep_days': 90,
}
_LIMITS = {'max_files': (1, 500), 'max_mb': (1, 100000), 'keep_days': (1, 3650)}
_PATTERN = re.compile(r'^[A-Za-z0-9_.*?\[\]\-/]{1,80}$')


def _db():
    return get_db()


def _all():
    raw = _db().get_server_setting(KEY, None)
    return dict(raw) if isinstance(raw, dict) else {}


def get(pool_id=None):
    """The settings a pool collects with: its own over the default."""
    raw = _all()
    out = dict(DEFAULTS)
    for scope in ('_default', pool_id):
        if scope and isinstance(raw.get(scope), dict):
            out.update({k: v for k, v in raw[scope].items() if k in DEFAULTS})
    return out


def overrides():
    return {k: v for k, v in _all().items() if k != '_default'}


def validate(data):
    if not isinstance(data, dict):
        raise ValueError('A JSON object is required')
    out = {}
    for k, v in data.items():
        if k == 'enabled':
            if not isinstance(v, bool):
                raise ValueError('enabled: true or false')
            out[k] = v
        elif k in _LIMITS:
            lo, hi = _LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f'{k}: a whole number from {lo} to {hi}')
            out[k] = v
        elif k == 'patterns':
            if not isinstance(v, list) or len(v) > 40 or any(not isinstance(p, str) or not _PATTERN.match(p.strip()) for p in v):
                raise ValueError('patterns: up to 40 file name patterns like *.bit (letters, digits, . _ - * ? [ ] /)')
            out[k] = list(dict.fromkeys(p.strip() for p in v if p.strip()))
        else:
            raise ValueError(f'Unknown setting: {k}')
    return out


def save(scope, data):
    """scope '_default' or a pool id; data None removes a pool's own settings."""
    raw = _all()
    if data is None:
        raw.pop(scope, None)
    else:
        cur = dict(raw.get(scope) or {})
        cur.update(validate(data))
        raw[scope] = cur
    _db().save_server_setting(KEY, raw)
    return get(None if scope == '_default' else scope)


# --- on the build VM -----------------------------------------------------------------------

def collect_script(workdir, dest, cleanup_root, settings):
    """sh (run as the job's user) that lists the kept files of `workdir` and copies them to
    `dest` (when given). Prints 'kept=<folder>' then 'f<TAB>size<TAB>relative path' lines."""
    q = shlex.quote
    names = ' -o '.join(f'-name {q(p)}' if '/' not in p else f'-path {q("*/" + p.lstrip("/"))}' for p in settings['patterns'])
    max_bytes = int(settings['max_mb']) * 1024 * 1024
    lines = ['set -u', f'W={q(workdir)}', '[ -d "$W" ] || { echo "no work folder" >&2; exit 21; }', 'cd "$W" || exit 21',
             f'LIST=$(find . -type f \\( {names} \\) -size -{max_bytes + 1}c -not -path "./.moavi*" -printf "%s\\t%P\\n" 2>/dev/null'
             f' | head -n {int(settings["max_files"])})']
    if dest:
        lines += [f'D={q(dest)}',
                  'if mkdir -p "$D" 2>/dev/null && [ -w "$D" ]; then',
                  '  echo "kept=$D"',
                  '  printf "%s\\n" "$LIST" | while IFS="$(printf \'\\t\')" read -r S P; do',
                  '    [ -n "$P" ] || continue',
                  '    mkdir -p "$D/$(dirname -- "$P")" && cp -p -- "$P" "$D/$P" && printf "f\\t%s\\t%s\\n" "$S" "$P"',
                  '  done',
                  f'  find {q(cleanup_root)} -mindepth 1 -maxdepth 1 -type d -mtime +{int(settings["keep_days"])} -exec rm -rf -- {{}} + 2>/dev/null',
                  '  exit 0',
                  'fi']
    lines += ['echo "kept=$W"', 'printf "%s\\n" "$LIST" | while IFS="$(printf \'\\t\')" read -r S P; do',
              '  [ -n "$P" ] && printf "f\\t%s\\t%s\\n" "$S" "$P"', 'done', 'exit 0']
    return '\n'.join(lines) + '\n'


def parse_collect(out):
    """(kept folder, [{path, size}]) from collect_script's output."""
    kept, files = '', []
    for line in (out or '').splitlines():
        if line.startswith('kept='):
            kept = line[5:].strip()
        elif line.startswith('f\t'):
            parts = line.split('\t', 2)
            if len(parts) == 3 and parts[2] and '..' not in parts[2].split('/'):
                try:
                    files.append({'path': parts[2], 'size': int(parts[1])})
                except ValueError:
                    continue
    return kept, files


def dest_for(cfg, guest_user, job_id):
    """(dest, cleanup root) on the NAS, or ('', '') without shared storage."""
    if not cfg or not cfg.get('linux_path') or not guest_user:
        return '', ''
    root = f"{cfg['linux_path'].rstrip('/')}/artifacts/{guest_user}"
    return f'{root}/{job_id}', root


def listed(job):
    try:
        return json.loads(job.get('artifacts') or '[]') or []
    except ValueError:
        return []
