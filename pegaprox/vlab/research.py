# -*- coding: utf-8 -*-
"""
MOAVI Desk for AI · GPU · NPU research: GPU jobs on the build farm, quotas with a fair queue,
web IDEs (JupyterLab, VS Code) on desktops and build VMs, and GPU-hours per user and department.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables (core DB, made on first use like store.py's; all HA-synced):
  vlab_gpu_quotas        per user, per department, and the default for everyone else:
                         GPUs at once, GPU-hours a month, whether the month is a hard stop
  vlab_research_settings '_global': who hears of a finished job, the wait after which the
                         oldest job holds its GPUs, the default time limit
  vlab_ide_sessions      one JupyterLab / VS Code server per user, desktop and kind: where it
                         listens, its token (sealed), the one-time link and the browser cookies

GPU jobs are build jobs (catalog.vlab_build_jobs) that ask for GPUs: the columns added in
catalog._COLUMNS say how many, of which kind, how much memory, how long, in which environment
and who to tell. The pure functions here order the queue, place jobs on build VMs and write the
shell scripts; pegaprox/api/vlab_research.py has the routes and pegaprox/api/vlab_next.py's
refresh_jobs runs the queue.
"""

import hashlib
import json
import re
import secrets
import shlex
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, new_id, now

SUBJECT_TYPES = ('user', 'department', 'default')
GLOBAL_KEY = '_global'
GLOBAL_DEFAULTS = {
    'mail': True,                 # a job's owner may ask for a mail when it ends
    'channels': [],               # webhook channel ids a job may notify (notify.webhook)
    'starve_minutes': 60,         # a GPU job waiting this long keeps the GPUs it needs free
    'default_max_minutes': 1440,  # a GPU job's time limit when it names none (0 = none)
    'max_queued_per_user': 50,
}
_GLOBAL_LIMITS = {'starve_minutes': (0, 10080), 'default_max_minutes': (0, 43200), 'max_queued_per_user': (1, 500)}

ENV_KINDS = ('conda', 'container')
RUNTIMES = ('docker', 'podman', 'apptainer')
IDE_KINDS = ('jupyter', 'vscode')
IDE_FOLDERS = ('home', 'scratch')
IDE_STATES = ('starting', 'running', 'stopped', 'failed')
IDE_PORTS = (8890, 8989)
IDE_LINK_SECONDS = 60
IDE_COOKIE_SECONDS = 12 * 3600
IDE_COOKIES_KEPT = 5
MAX_GPUS = 16

# what the guest scripts exit with when something is missing (the routes say it in words)
EXIT_NO_JUPYTER = 95
EXIT_NO_CODE_SERVER = 94
EXIT_NO_TOKEN = 96
EXIT_NO_FOLDER = 97
EXIT_NO_RUNTIME = 98
EXIT_TIMEOUT = 124                # GNU timeout

CONDA_NAME = re.compile(r'^[A-Za-z0-9_.\-]{1,64}$')
IMAGE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$')
KIND = re.compile(r'^[A-Za-z0-9 _.\-]{0,60}$')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_gpu_quotas (
        subject_type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        max_gpus INTEGER NOT NULL DEFAULT 0,
        monthly_gpu_hours REAL NOT NULL DEFAULT 0,
        hard INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (subject_type, subject_id)
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_research_settings (
        key TEXT PRIMARY KEY,
        settings TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_ide_sessions (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        desktop_id TEXT NOT NULL,
        pool_id TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL,
        folder TEXT NOT NULL DEFAULT 'home',
        workdir TEXT NOT NULL DEFAULT '',
        host TEXT NOT NULL DEFAULT '',
        port INTEGER NOT NULL DEFAULT 0,
        pid INTEGER,
        token_encrypted TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'starting',
        error TEXT NOT NULL DEFAULT '',
        link_hash TEXT NOT NULL DEFAULT '',
        link_expires TEXT,
        cookie_hashes TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        started_at TEXT,
        last_seen TEXT,
        stopped_at TEXT
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_ide_user ON vlab_ide_sessions(username, state)',
)
TABLES = ('vlab_gpu_quotas', 'vlab_research_settings', 'vlab_ide_sessions')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_research', False):
        with _lock:
            if not getattr(d, '_vlab_research', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_research = True
    return d


def _rows(sql, args=()):
    return [dict(r) for r in db().query(sql, args)]


def _one(sql, args=()):
    r = db().query_one(sql, args)
    return dict(r) if r else None


def _whole(v, lo, hi, name):
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ValueError(f'{name} must be a whole number from {lo} to {hi}')
    return v


# --- times ----------------------------------------------------------------------------------

def parse(iso):
    """A store.now() time (UTC with its offset; a naive one is taken as UTC) or None."""
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(str(iso))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def utcnow():
    return datetime.now(timezone.utc)


def month_start(at=None):
    """The first instant of the month of `at` on the server's own clock, in UTC."""
    local = (at or utcnow()).astimezone()
    return local.replace(day=1, hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)


def overlap_hours(start, end, since, until):
    """Hours of [start, end] inside [since, until]; start/end datetimes (end None = until)."""
    if not start:
        return 0.0
    end = end or until
    a, b = max(start, since), min(end, until)
    return max(0.0, (b - a).total_seconds() / 3600)


# --- settings -------------------------------------------------------------------------------

def get_settings():
    r = _one('SELECT settings FROM vlab_research_settings WHERE key = ?', (GLOBAL_KEY,))
    saved = {}
    if r:
        try:
            saved = json.loads(r['settings'] or '{}')
        except ValueError:
            saved = {}
    return {k: saved.get(k, v) for k, v in GLOBAL_DEFAULTS.items()}


def validate_settings(data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    unknown = sorted(set(data) - set(GLOBAL_DEFAULTS))
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(unknown)}")
    out = get_settings()
    for k, v in data.items():
        if k == 'mail':
            if not isinstance(v, bool):
                raise ValueError('mail must be true or false')
            out[k] = v
        elif k == 'channels':
            if not isinstance(v, list) or len(v) > 20 or any(not isinstance(c, str) or not 0 < len(c) <= 80 for c in v):
                raise ValueError('channels: a list of webhook channel ids')
            out[k] = list(dict.fromkeys(v))
        else:
            lo, hi = _GLOBAL_LIMITS[k]
            out[k] = _whole(v, lo, hi, k)
    return out


def save_settings(settings):
    db().execute('INSERT OR REPLACE INTO vlab_research_settings (key, settings, updated_at) VALUES (?, ?, ?)',
                 (GLOBAL_KEY, json.dumps(settings, ensure_ascii=False), now()))
    return get_settings()


# --- quotas ---------------------------------------------------------------------------------

def _quota_row(r):
    return {'subject_type': r['subject_type'], 'subject_id': r['subject_id'], 'max_gpus': int(r['max_gpus'] or 0),
            'monthly_gpu_hours': float(r['monthly_gpu_hours'] or 0), 'hard': bool(r['hard']),
            'note': r['note'] or '', 'updated_at': r['updated_at']}


def list_quotas():
    return [_quota_row(r) for r in _rows('SELECT * FROM vlab_gpu_quotas ORDER BY subject_type, subject_id')]


def get_quota(subject_type, subject_id):
    r = _one('SELECT * FROM vlab_gpu_quotas WHERE subject_type = ? AND subject_id = ?', (subject_type, subject_id))
    return _quota_row(r) if r else None


def validate_quota(data):
    """(subject_type, subject_id, max_gpus, monthly_gpu_hours, hard, note) or raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    unknown = sorted(set(data) - {'subject_type', 'subject_id', 'max_gpus', 'monthly_gpu_hours', 'hard', 'note'})
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(unknown)}")
    st = data.get('subject_type')
    if st not in SUBJECT_TYPES:
        raise ValueError('subject_type must be user, department or default')
    sid = '' if st == 'default' else str(data.get('subject_id') or '').strip()
    if st != 'default' and not 0 < len(sid) <= 120:
        raise ValueError('subject_id: the user name or the department id')
    gpus = _whole(data.get('max_gpus', 0), 0, 1024, 'max_gpus')
    hours = data.get('monthly_gpu_hours', 0)
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 0 <= hours <= 1_000_000:
        raise ValueError('monthly_gpu_hours must be a number from 0 to 1000000')
    hard = data.get('hard', False)
    if not isinstance(hard, bool):
        raise ValueError('hard must be true or false')
    note = data.get('note', '')
    if not isinstance(note, str) or len(note) > 200:
        raise ValueError('note: up to 200 characters')
    return st, sid, gpus, round(float(hours), 1), hard, note.strip()


def save_quota(subject_type, subject_id, max_gpus, monthly_gpu_hours, hard, note):
    db().execute('INSERT OR REPLACE INTO vlab_gpu_quotas (subject_type, subject_id, max_gpus, monthly_gpu_hours, hard, '
                 'note, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (subject_type, subject_id, int(max_gpus), float(monthly_gpu_hours), 1 if hard else 0, note, now()))
    return get_quota(subject_type, subject_id)


def delete_quota(subject_type, subject_id):
    db().execute('DELETE FROM vlab_gpu_quotas WHERE subject_type = ? AND subject_id = ?', (subject_type, subject_id))


def quotas_for(username, dep_chain, quotas=None):
    """The quotas a user's jobs answer to: their own (else the default) and every department
    from theirs up to the top that has one. [(subject_type, subject_id, quota)]."""
    by = {(q['subject_type'], q['subject_id']): q for q in (quotas if quotas is not None else list_quotas())}
    out = []
    own = by.get(('user', username)) or by.get(('default', ''))
    if own:
        out.append(('user', username, own))
    for dep in dep_chain:
        q = by.get(('department', dep))
        if q:
            out.append(('department', dep, q))
    return out


# --- GPU jobs: what a job asks for ----------------------------------------------------------

def job_extra(data, pool_cap=0, default_minutes=0):
    """The GPU job fields of a submit body: {gpus, gpu_kind, memory_gb, max_minutes, env, notify}.
    A job with no GPUs and none of these is a plain build job ({} back)."""
    keys = ('gpus', 'gpu_kind', 'memory_gb', 'max_minutes', 'env', 'notify')
    if not any(k in data for k in keys):
        return {}
    gpus = _whole(data.get('gpus', 0), 0, MAX_GPUS, 'gpus')
    kind = data.get('gpu_kind') or ''
    if not isinstance(kind, str) or not KIND.match(kind):
        raise ValueError('gpu_kind: up to 60 letters, digits, spaces, _ . -')
    mem = _whole(data.get('memory_gb', 0), 0, 4096, 'memory_gb')
    minutes = data.get('max_minutes')
    minutes = default_minutes if minutes is None else _whole(minutes, 0, 43200, 'max_minutes')
    if pool_cap and (not minutes or minutes > pool_cap):
        minutes = pool_cap
    env = data.get('env') or None
    if env is not None:
        if not isinstance(env, dict) or env.get('kind') not in ENV_KINDS:
            raise ValueError('env: {kind: conda, name} or {kind: container, image}')
        if env['kind'] == 'conda':
            name = env.get('name')
            if not isinstance(name, str) or not CONDA_NAME.match(name):
                raise ValueError('env.name: a conda environment name')
            env = {'kind': 'conda', 'name': name}
        else:
            image = env.get('image')
            if not isinstance(image, str) or not IMAGE.match(image) or '..' in image:
                raise ValueError('env.image: a container image such as nvcr.io/nvidia/pytorch:24.08-py3')
            env = {'kind': 'container', 'image': image}
    notify = data.get('notify') or {}
    if not isinstance(notify, dict) or set(notify) - {'mail', 'webhook'} or any(not isinstance(v, bool) for v in notify.values()):
        raise ValueError('notify: {mail: true|false, webhook: true|false}')
    return {'gpus': gpus, 'gpu_kind': kind.strip(), 'memory_gb': mem, 'max_minutes': minutes,
            'env': json.dumps(env) if env else '', 'notify': json.dumps({k: v for k, v in notify.items() if v}) if notify else ''}


def loads(v, default):
    try:
        out = json.loads(v) if v else default
    except (TypeError, ValueError):
        return default
    return out if isinstance(out, type(default)) else default


def is_gpu_job(job):
    """A job that goes through the GPU path: GPUs, a time limit or an environment."""
    return bool(job.get('gpus') or job.get('max_minutes') or job.get('env'))


# --- GPU jobs: the pools that can take them -------------------------------------------------

def pool_gpu_jobs(settings, gpu_policy=None):
    """A build farm pool's GPU job setting: {gpus_per_vm, kind, max_minutes, runtime}. With none
    saved, one GPU per VM when the pool has a GPU policy, named after its label or mapping."""
    settings = settings if isinstance(settings, dict) else {}
    saved = settings.get('gpu_jobs') if isinstance(settings.get('gpu_jobs'), dict) else {}
    label = ''
    if gpu_policy:
        label = gpu_policy.get('label') or gpu_policy.get('mdev_type') or gpu_policy.get('mapping') or ''
    return {'gpus_per_vm': int(saved.get('gpus_per_vm', 1 if gpu_policy else 0)),
            'kind': saved.get('kind') or label,
            'max_minutes': int(saved.get('max_minutes', 0)),
            'runtime': saved.get('runtime') if saved.get('runtime') in RUNTIMES else 'docker'}


def validate_pool_gpu_jobs(data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    unknown = sorted(set(data) - {'gpus_per_vm', 'kind', 'max_minutes', 'runtime'})
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(unknown)}")
    kind = data.get('kind', '')
    if not isinstance(kind, str) or not KIND.match(kind):
        raise ValueError('kind: up to 60 letters, digits, spaces, _ . -')
    runtime = data.get('runtime', 'docker')
    if runtime not in RUNTIMES:
        raise ValueError(f"runtime must be one of {', '.join(RUNTIMES)}")
    return {'gpus_per_vm': _whole(data.get('gpus_per_vm', 0), 0, MAX_GPUS, 'gpus_per_vm'), 'kind': kind.strip(),
            'max_minutes': _whole(data.get('max_minutes', 0), 0, 43200, 'max_minutes'), 'runtime': runtime}


def kind_matches(asked, kind):
    return not asked or asked.strip().lower() == (kind or '').strip().lower()


# --- GPU jobs: the queue --------------------------------------------------------------------

def plan(queued, vms, usage, quotas_of, starve_minutes=60, at=None):
    """Which queued jobs start now, and on which VM and GPUs.

    queued   jobs (created_at order), each with 'candidates': the pool ids it may run in
    vms      [{desktop_id, pool_id, gpus, mem_gb, used: set of GPU indices, mem_used, cpu_job,
              busy}] - busy: in a session or assigned (takes no job), cpu_job: a build job on it
    usage    {('user', name) | ('department', id): {'gpus': running, 'hours': this month}}
    quotas_of(job) -> [(subject_type, subject_id, quota)]

    Order: jobs of someone over a monthly quota last; then each user's first job before anyone's
    second (fair share); then the longest wait. A job over a GPUs-at-once quota or a hard monthly
    one waits. A GPU job that has waited starve_minutes and finds no room holds its pools: no
    later GPU job starts there, so the GPUs it needs come free.
    Returns ([(job, vm, [gpu indices])], {job id: why it waits}, [job ids in queue order]).
    """
    at = at or utcnow()
    usage = {k: dict(v) for k, v in usage.items()}
    vms = [dict(v, used=set(v.get('used') or ())) for v in vms]

    def over_month(job):
        for st, sid, q in quotas_of(job):
            if q['monthly_gpu_hours'] and usage.get((st, sid), {}).get('hours', 0) >= q['monthly_gpu_hours']:
                return q['hard'] and 2 or 1
        return 0

    nth, keyed = {}, []
    for j in queued:
        n = nth.get(j['username'], 0)
        nth[j['username']] = n + 1
        over = over_month(j) if j.get('gpus') else 0
        keyed.append(((1 if over else 0, n, j['created_at']), j, over))
    keyed.sort(key=lambda x: x[0])

    placed, why, held = [], {}, set()
    for _, job, over in keyed:
        gpus = int(job.get('gpus') or 0)
        if gpus and over == 2:
            why[job['id']] = 'quota_hours'
            continue
        if gpus:
            full = [(st, sid) for st, sid, q in quotas_of(job)
                    if q['max_gpus'] and usage.get((st, sid), {}).get('gpus', 0) + gpus > q['max_gpus']]
            if full:
                why[job['id']] = 'quota_gpus_department' if full[0][0] == 'department' else 'quota_gpus'
                continue
            if held & set(job['candidates']):
                why[job['id']] = 'held_for_older'
                continue
        best = None
        for v in vms:
            if v['pool_id'] not in job['candidates'] or v['busy']:
                continue
            if not gpus:
                if v['cpu_job'] or v['used']:
                    continue
                best = (0, v)
                break
            if v['cpu_job'] or v['gpus'] - len(v['used']) < gpus:
                continue
            mem = int(job.get('memory_gb') or 0)
            if mem and v['mem_gb'] and v['mem_gb'] - v['mem_used'] < mem:
                continue
            left = v['gpus'] - len(v['used']) - gpus
            if best is None or left < best[0]:
                best = (left, v)
        if best is None:
            why[job['id']] = 'no_free_vm' if not gpus else 'no_free_gpu'
            waited = (at - (parse(job['created_at']) or at)).total_seconds() / 60
            if gpus and starve_minutes and waited >= starve_minutes:
                held |= set(job['candidates'])
            continue
        v = best[1]
        if gpus:
            idx = [i for i in range(v['gpus']) if i not in v['used']][:gpus]
            v['used'] |= set(idx)
            v['mem_used'] += int(job.get('memory_gb') or 0)
            for st, sid, _ in quotas_of(job):
                usage.setdefault((st, sid), {'gpus': 0, 'hours': 0})['gpus'] += gpus
        else:
            idx = []
            v['cpu_job'] = True
        placed.append((job, v, idx))
    return placed, why, [j['id'] for _, j, _ in keyed]


# --- GPU jobs: the script on the build VM ---------------------------------------------------

LOG = 'moavi-job.log'
TAIL = 20000


def job_script(job, workdir, gpu_index, runtime='docker'):
    """The bash script of a GPU job: into its folder, the GPUs it was given, its environment, a
    time limit, the output to moavi-job.log in the folder and its end back to the engine."""
    q = shlex.quote
    devs = ','.join(str(i) for i in gpu_index)
    cmd = job['command']
    env = loads(job.get('env'), {})
    secs = int(job.get('max_minutes') or 0) * 60
    jid = job['id']
    lines = [f'wd={q(workdir)}', f'mkdir -p "$wd" && cd "$wd" || exit {EXIT_NO_FOLDER}',
             f'export MOAVI_JOB_ID={q(jid)} MOAVI_JOB_DIR="$wd" MOAVI_RESULT_DIR="$wd"']
    if gpu_index:
        lines.append(f'export CUDA_VISIBLE_DEVICES={devs} HIP_VISIBLE_DEVICES={devs} MOAVI_GPUS={devs}')
    limit = f'timeout -k 60 {secs} ' if secs else ''
    cleanup = ''
    if env.get('kind') == 'conda':
        lines.append('for c in "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3" /opt/conda /opt/miniconda3 /opt/miniforge3; do '
                     '[ -f "$c/etc/profile.d/conda.sh" ] && . "$c/etc/profile.d/conda.sh" && break; done')
        run = f"conda run --no-capture-output -n {q(env['name'])} bash -lc {q(cmd)}"
    elif env.get('kind') == 'container':
        name = f'moavi-{jid}'
        image = q(env['image'])
        if runtime == 'podman':
            gpu = ' '.join(f'--device nvidia.com/gpu={i}' for i in gpu_index)
            run = (f'podman run --rm --name {name} {gpu} --userns=keep-id -v "$wd:$wd" -w "$wd" '
                   f'-e MOAVI_JOB_ID -e MOAVI_JOB_DIR -e MOAVI_RESULT_DIR {image} bash -lc {q(cmd)}')
            cleanup = f'podman rm -f {name} >/dev/null 2>&1'
        elif runtime == 'apptainer':
            run = f'apptainer exec --nv --bind "$wd" --pwd "$wd" docker://{env["image"]} bash -lc {q(cmd)}'
        else:
            gpu = f"--gpus '\"device={devs}\"'" if gpu_index else ''
            run = (f'docker run --rm --name {name} {gpu} --user "$(id -u):$(id -g)" -v "$wd:$wd" -w "$wd" '
                   f'-e MOAVI_JOB_ID -e MOAVI_JOB_DIR -e MOAVI_RESULT_DIR {image} bash -lc {q(cmd)}')
            cleanup = f'docker rm -f {name} >/dev/null 2>&1'
        lines.append(f'command -v {runtime} >/dev/null 2>&1 || {{ echo "MOAVI: {runtime} is not installed on this build VM"; exit {EXIT_NO_RUNTIME}; }}')
    else:
        run = f'bash -lc {q(cmd)}'
    lines += [f'{limit}{run} >"$wd/{LOG}" 2>&1', 'rc=$?']
    if cleanup:
        lines.append(cleanup)
    lines += [f'[ $rc -eq {EXIT_TIMEOUT} ] && echo "MOAVI: time limit reached ({secs // 60} min)" >>"$wd/{LOG}"',
              f'tail -c {TAIL} "$wd/{LOG}"', 'exit $rc']
    return '\n'.join(lines)


def job_argv(script, as_user=None):
    """setsid: the job is a session of its own, so a stop ends all of it (pkill -s)."""
    argv = ['/bin/bash', '-lc', script]
    if as_user:
        argv = ['runuser', '-u', as_user, '--'] + argv
    return ['setsid', '-w'] + argv


def stop_argv(pid, container=None, runtime='docker'):
    """End a job's session: TERM, then KILL after 15 seconds; a container is removed too."""
    pid = int(pid)
    s = f'pkill -TERM -s {pid}; sleep 15; pkill -KILL -s {pid}'
    if container and runtime in ('docker', 'podman'):
        s += f'; {runtime} rm -f {shlex.quote(container)} >/dev/null 2>&1'
    return ['/bin/sh', '-c', s + '; exit 0']


def job_error(code):
    return {EXIT_TIMEOUT: 'time limit reached', EXIT_NO_FOLDER: 'the job folder could not be made',
            EXIT_NO_RUNTIME: 'the container runtime is not installed on the build VM'}.get(code)


# --- usage ----------------------------------------------------------------------------------

LOAN_KINDS = ('gpu', 'npu')


def job_gpu_hours(job, since, until):
    return int(job.get('gpus') or 0) * overlap_hours(parse(job.get('started_at')), parse(job.get('finished_at')), since, until)


def loan_hours(lease, since, until):
    end = parse(lease.get('returned_at'))
    if not end and lease.get('state') != 'active':
        end = parse(lease.get('ends_at'))
    return overlap_hours(parse(lease.get('starts_at')), end, since, until)


def usage(jobs, leases, since, until, dep_of):
    """GPU-hours per user from GPU jobs and card loans (GPU and NPU) in [since, until].
    {user: {department_id, job_hours, loan_hours, jobs, loans, by_department: {id: {job_hours,
    loan_hours}}}}. A job counts to the department it was sent from; a loan to the user's
    department now."""
    out = {}

    def row(u, dep):
        return out.setdefault(u, {'department_id': dep or '', 'job_hours': 0.0, 'loan_hours': 0.0, 'jobs': 0, 'loans': 0,
                                  'by_department': {}})
    for j in jobs:
        h = job_gpu_hours(j, since, until)
        if h <= 0:
            continue
        dep = j.get('department_id') or dep_of(j['username']) or ''
        r = row(j['username'], dep_of(j['username']))
        r['job_hours'] += h
        r['jobs'] += 1
        b = r['by_department'].setdefault(dep, {'job_hours': 0.0, 'loan_hours': 0.0})
        b['job_hours'] += h
    for l in leases:
        if l.get('resource_type') not in LOAN_KINDS:
            continue
        h = loan_hours(l, since, until)
        if h <= 0:
            continue
        dep = dep_of(l['username']) or ''
        r = row(l['username'], dep)
        r['loan_hours'] += h
        r['loans'] += 1
        b = r['by_department'].setdefault(dep, {'job_hours': 0.0, 'loan_hours': 0.0})
        b['loan_hours'] += h
    return out


# --- web IDE --------------------------------------------------------------------------------

def _hash(v):
    return hashlib.sha256(str(v).encode()).hexdigest()


def _ide_row(r, token=False):
    out = {k: r[k] for k in r.keys() if k not in ('token_encrypted', 'link_hash', 'cookie_hashes')}
    if token:
        try:
            from pegaprox.core.db import get_db
            out['token'] = get_db()._decrypt(r['token_encrypted']) if r['token_encrypted'] else ''
        except Exception:
            out['token'] = ''
    return out


def get_ide(sid, token=False):
    r = db().query_one('SELECT * FROM vlab_ide_sessions WHERE id = ?', (sid,))
    return _ide_row(r, token) if r else None


def list_ide(username=None, live=False):
    where, args = [], []
    if username:
        where.append('username = ?')
        args.append(username)
    if live:
        where.append("state IN ('starting', 'running')")
    sql = 'SELECT * FROM vlab_ide_sessions' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY created_at DESC LIMIT 500'
    return [_ide_row(r) for r in db().query(sql, tuple(args))]


def find_ide(username, desktop_id, kind):
    r = db().query_one("SELECT * FROM vlab_ide_sessions WHERE username = ? AND desktop_id = ? AND kind = ? "
                       "AND state IN ('starting', 'running') ORDER BY created_at DESC", (username, desktop_id, kind))
    return _ide_row(r) if r else None


def free_port(desktop_id):
    used = {int(r['port']) for r in db().query("SELECT port FROM vlab_ide_sessions WHERE desktop_id = ? "
                                                "AND state IN ('starting', 'running')", (desktop_id,))}
    for p in range(IDE_PORTS[0], IDE_PORTS[1] + 1):
        if p not in used:
            return p
    return None


def add_ide(username, desk, pool_id, kind, folder, workdir, host, port):
    """A new session row with a fresh token (sealed). Returns (row, token)."""
    from pegaprox.core.db import get_db
    sid = new_id('ide')
    token = secrets.token_hex(24)
    db().execute('INSERT INTO vlab_ide_sessions (id, username, desktop_id, pool_id, kind, folder, workdir, host, port, '
                 "token_encrypted, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'starting', ?)",
                 (sid, username, desk['id'], pool_id, kind, folder, workdir, host, int(port), get_db()._encrypt(token), now()))
    return get_ide(sid), token


def update_ide(sid, **fields):
    keys = [k for k in fields if k in ('state', 'error', 'pid', 'host', 'started_at', 'last_seen', 'stopped_at')]
    if keys:
        db().execute(f"UPDATE vlab_ide_sessions SET {', '.join(k + ' = ?' for k in keys)} WHERE id = ?",
                     tuple(fields[k] for k in keys) + (sid,))
    return get_ide(sid)


def new_link(sid):
    """A one-time link token for the session, good for IDE_LINK_SECONDS."""
    tok = secrets.token_urlsafe(24)
    until = (utcnow() + timedelta(seconds=IDE_LINK_SECONDS)).isoformat(timespec='seconds')
    db().execute('UPDATE vlab_ide_sessions SET link_hash = ?, link_expires = ? WHERE id = ?', (_hash(tok), until, sid))
    return tok


def take_link(sid, tok):
    """Spend a link token: a new browser cookie value when it was good (it is good once)."""
    r = db().query_one('SELECT link_hash, link_expires, cookie_hashes FROM vlab_ide_sessions WHERE id = ?', (sid,))
    if not r or not r['link_hash'] or not tok or not secrets.compare_digest(r['link_hash'], _hash(tok)):
        return None
    until = parse(r['link_expires'])
    if not until or until < utcnow():
        return None
    cookie = secrets.token_urlsafe(32)
    kept = (loads(r['cookie_hashes'], []) + [_hash(cookie)])[-IDE_COOKIES_KEPT:]
    db().execute("UPDATE vlab_ide_sessions SET link_hash = '', link_expires = NULL, cookie_hashes = ? WHERE id = ?",
                 (json.dumps(kept), sid))
    return cookie


def cookie_ok(sid, cookie):
    if not cookie:
        return False
    r = db().query_one('SELECT cookie_hashes FROM vlab_ide_sessions WHERE id = ?', (sid,))
    h = _hash(cookie)
    return bool(r) and any(secrets.compare_digest(h, c) for c in loads(r['cookie_hashes'], []))


def forget_cookies(sid):
    db().execute("UPDATE vlab_ide_sessions SET cookie_hashes = '[]', link_hash = '', link_expires = NULL WHERE id = ?", (sid,))


def ide_script(sid, kind, port, workdir, idle_min, hide_gpus=False):
    """The bash script that starts the user's JupyterLab, or Jupyter Server for VS Code through
    jupyter-server-proxy (jupyter-vscode-proxy, code-server on 127.0.0.1 only). The token comes
    on stdin, never on a command line; the log goes to ~/.moavi/ide-<sid>.log."""
    q = shlex.quote
    app = 'lab' if kind == 'jupyter' else 'server'
    lines = [f'read -r JUPYTER_TOKEN || exit {EXIT_NO_TOKEN}', 'export JUPYTER_TOKEN',
             'export PATH="$PATH:$HOME/.local/bin:$HOME/miniconda3/bin:$HOME/miniforge3/bin:/opt/conda/bin:/opt/jupyter/bin:/usr/local/bin"',
             f'command -v jupyter >/dev/null 2>&1 || {{ echo "MOAVI: jupyter is not installed" >&2; exit {EXIT_NO_JUPYTER}; }}']
    if kind == 'vscode':
        lines.append(f'command -v code-server >/dev/null 2>&1 || {{ echo "MOAVI: code-server is not installed" >&2; exit {EXIT_NO_CODE_SERVER}; }}')
    lines += [f'dir={q(workdir)}' if workdir else 'dir="$HOME"',
              'mkdir -p "$dir" 2>/dev/null; cd "$dir" 2>/dev/null || { dir="$HOME"; cd "$dir"; }',
              'mkdir -p "$HOME/.moavi"', f'log="$HOME/.moavi/ide-{sid}.log"']
    if kind == 'vscode':
        lines.append('export CODE_WORKINGDIR="$dir"')
    if hide_gpus:
        lines.append('export CUDA_VISIBLE_DEVICES= HIP_VISIBLE_DEVICES=')
    lines.append(f'exec jupyter {app} --no-browser --ip=0.0.0.0 --port={int(port)} --ServerApp.port_retries=0 '
                 f'--ServerApp.base_url=/ide/{sid}/ --ServerApp.root_dir="$dir" --ServerApp.allow_remote_access=True '
                 f'--ServerApp.shutdown_no_activity_timeout={int(idle_min) * 60} >"$log" 2>&1')
    return '\n'.join(lines)


def ide_path(sid, kind):
    return f"/ide/{sid}/" + ('lab' if kind == 'jupyter' else 'vscode/')


def ide_error(code):
    return {EXIT_NO_JUPYTER: ('NOT_INSTALLED', 'JupyterLab is not installed in this desktop'),
            EXIT_NO_CODE_SERVER: ('NOT_INSTALLED', 'code-server is not installed in this desktop'),
            EXIT_NO_TOKEN: ('START_FAILED', 'the IDE did not get its token')}.get(code)


SID = re.compile(r'^/ide/(ide_[0-9a-f]{12})/')
