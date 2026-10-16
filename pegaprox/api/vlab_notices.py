# -*- coding: utf-8 -*-
"""
MOAVI Desk - per-user notices: the mails a user gets of what happens to their jobs, quotas, loans,
IDEs, desktops and requests, and the alerts the administrators get of what waits for them.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/me/notices        {kinds: [{id, label_ko, label_en, on}], email}  which mails I take       vlab.desk
  PUT    /api/vlab/me/notices        {kind: true|false, ...}  turn a kind on or off              vlab.desk

  A notice is a mail to the account's own address (pegaprox/vlab/notices.py keeps who takes which
  kind and which notices went once). With research settings notice_webhook on, the same notice is
  a webhook event on the channels the administrators chose (research settings 'channels').
  Security notices (password or two-step sign-in reset by an administrator, account disabled or
  expired) go whatever the user chose.

Background: the minute loop (pegaprox/vlab/loans.py) calls notice_tick while GPU/AI or FPGA is on:
  - loans and boards: a reminder loan_remind_hours before the end (once per end time)
  - GPU quotas (every 10 minutes): quota_warn_pct and 100% of the monthly GPU-hours, once a month
    per user or department; a department's goes to its manager and those who used it this month
  - web IDEs: the live ones are read (an IDE that ended for being idle is told)
  - the GPU queue: a job waiting longer than queue_alert_hours is told to the administrators once
None of these changes a VM; the reads are the same guest agent exec-status GETs refresh_jobs does.
"""

import logging
import time

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import notices

bp = Blueprint('vlab_notices', __name__)

_bad = core._bad
_user = core._user
QUOTA_EVERY = 600
_last = {'quota': 0.0, 'prune': 0.0}


# --- 내 계정 > 알림 -------------------------------------------------------------------------

def _kinds_view(username):
    p = notices.prefs(username)
    return [{'id': k, 'label_ko': v[0], 'label_en': v[1], 'on': p[k]} for k, v in notices.KINDS.items()]


@bp.route('/api/vlab/me/notices', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_notices():
    return jsonify({'kinds': _kinds_view(_user()), 'email': notices.email_of(_user())})


@bp.route('/api/vlab/me/notices', methods=['PUT'])
@require_auth(perms=['vlab.desk'])
def put_my_notices():
    try:
        notices.save_prefs(_user(), request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    return jsonify({'kinds': _kinds_view(_user()), 'email': notices.email_of(_user())})


# --- sending -------------------------------------------------------------------------------

def _settings():
    from pegaprox.vlab import research
    try:
        return research.get_settings()
    except Exception:
        return dict(research.GLOBAL_DEFAULTS)


def tell(username, kind, title, text, event=None, severity='info', always=False, **data):
    """Mail the user (as they chose, or always for a security notice) and, with notice_webhook
    on, post the event to the chosen channels. Never raises."""
    try:
        if always:
            email = notices.email_of(username)
            if email:
                from pegaprox.utils.email import send_email
                send_email([email], f'[MOAVI Desk] {title}', text, None)
        else:
            notices.mail(username, kind, title, text)
        g = _settings()
        if event and g.get('notice_webhook') and g.get('channels'):
            notices.webhook(g['channels'], event, f'[MOAVI Desk] {title}', text, severity, owner=username, **data)
    except Exception as e:
        logging.warning(f'[VLAB] notice {event or kind} to {username}: {e}')


def admins(title, text, data):
    """The alert channels and the alert mail recipients (vlab_next._alert)."""
    try:
        from pegaprox.api.vlab_next import _alert
        _alert(title, text, dict(data, severity=data.get('severity', 'info')))
    except Exception as e:
        logging.warning(f'[VLAB] admin notice: {e}')


def _who(username):
    try:
        from pegaprox.utils.auth import load_users
        u = (load_users() or {}).get(username) or {}
        return u.get('display_name') or username
    except Exception:
        return username


# --- GPU jobs --------------------------------------------------------------------------------

def job_started(job, desk_name, gpu_index):
    """A GPU job left the queue: told when the job asked for it (notify.start)."""
    from pegaprox.vlab import research
    want = research.loads(job.get('notify'), {})
    if not want.get('start'):
        return
    g = _settings()
    gpus = f"GPU {len(gpu_index)}장 (번호 {','.join(str(i) for i in gpu_index)})" if gpu_index else 'GPU 없음'
    title = f"[MOAVI Desk] 작업 시작: {job['name']}"
    text = '\n'.join([f"작업: {job['name']} ({job['id']})", f"빌드 VM: {desk_name}", gpus,
                      f"시간 제한: {job.get('max_minutes') or 0}분" if job.get('max_minutes') else '시간 제한: 없음',
                      f"결과 폴더: {job.get('workdir') or '-'}",
                      f"대기 시간: {_waited(job)}"])
    if want.get('mail') and g['mail']:
        notices.mail(job['username'], 'gpu_job', title, text)
    if want.get('webhook') and g['channels']:
        notices.webhook(g['channels'], 'gpu_job_started', title, text, 'info', job_id=job['id'], owner=job['username'])


def _waited(job):
    from pegaprox.vlab import research
    t = research.parse(job.get('created_at'))
    if not t:
        return '-'
    m = int((research.utcnow() - t).total_seconds() // 60)
    return f'{m // 60}시간 {m % 60}분' if m >= 60 else f'{m}분'


# --- loans and boards ------------------------------------------------------------------------

_KIND_KO = {'gpu': 'GPU 카드', 'npu': 'NPU 카드', 'fpga': 'FPGA 카드', 'board': '보드'}


def _card(lease):
    return f"{_KIND_KO.get(lease.get('resource_type'), '카드')} {lease.get('resource_name') or lease.get('resource_id')}"


def _desk_of(lease):
    from pegaprox.vlab import store
    d = store.desktop_for_vm(lease['cluster_id'], lease['vmid']) if lease.get('vmid') is not None else None
    return d['name'] if d else f"qemu/{lease.get('vmid')}"


def loan_granted(lease, needs_restart=False):
    tail = ' 데스크톱이 켜져 있으면 다시 시작해야 카드가 보입니다.' if needs_restart else ''
    tell(lease['username'], 'loan', f"대여 시작: {_card(lease)}",
         f"{_card(lease)} 를 데스크톱 {_desk_of(lease)} 에 빌려 드렸습니다. 반납 시각: {notices.local_time(lease['ends_at'])}.{tail}",
         'loan_granted', lease_id=lease['id'])


def loan_extended(lease, ends_at):
    tell(lease['username'], 'loan', f"대여 연장: {_card(lease)}",
         f"{_card(lease)} (데스크톱 {_desk_of(lease)}) 의 대여가 {notices.local_time(ends_at)} 까지로 연장되었습니다.",
         'loan_extended', lease_id=lease['id'])


def loan_returned(lease, by='system'):
    """A card back: at its end (the minute loop) or by an administrator."""
    g = _settings()
    if by == 'system':
        if not g['loan_notice']:
            return
        title = f"대여 기간이 끝나 자동 반납: {_card(lease)}"
        text = (f"{_card(lease)} 의 대여 기간({notices.local_time(lease.get('ends_at'))})이 끝나 데스크톱 {_desk_of(lease)} 에서 "
                f"자동으로 반납했습니다. 켜져 있던 데스크톱은 다음에 끌 때까지 카드를 씁니다. 더 필요하면 관리자에게 대여를 요청하세요.")
        event = 'loan_returned'
    else:
        title = f"관리자가 대여를 반납 처리: {_card(lease)}"
        text = f"{_card(lease)} (데스크톱 {_desk_of(lease)}) 를 관리자({by})가 반납 처리했습니다."
        event = 'loan_returned_by_admin'
    tell(lease['username'], 'loan', title, text, event, lease_id=lease['id'])


def loan_return_failed(lease, err):
    admins(f"대여 자동 반납 실패: {_card(lease)}",
           f"{lease['username']} 님의 {_card(lease)} (qemu/{lease.get('vmid')}) 를 대여 종료 시각에 반납하지 못했습니다: {err}. "
           "가속 자원 > 카드 대여 현황에서 확인하세요. 매 분 다시 시도합니다.",
           {'kind': 'loan_return_failed', 'user': lease['username'], 'card': lease.get('resource_name'), 'severity': 'warning'})


def board_lent(board, desk_name, user, until):
    if not user:
        return
    tell(user, 'loan', f"보드 대여 시작: {board['name']}",
         f"보드 {board['name']} 를 데스크톱 {desk_name} 에 연결했습니다."
         + (f" 반납 시각: {str(until).replace('T', ' ')}." if until else ''), 'board_lent', board_id=board['id'])


def board_returned(board, user, by='system'):
    if not user:
        return
    if by == 'system':
        if not _settings()['loan_notice']:
            return
        title, event = f"보드 대여 기간이 끝나 자동 반납: {board['name']}", 'board_returned'
        text = f"보드 {board['name']} 의 대여 기간이 끝나 데스크톱에서 분리했습니다. 더 필요하면 관리자에게 요청하세요."
    else:
        title, event = f"관리자가 보드를 분리: {board['name']}", 'board_returned_by_admin'
        text = f"보드 {board['name']} 를 관리자({by})가 데스크톱에서 분리했습니다."
    tell(user, 'loan', title, text, event, board_id=board['id'])


def board_return_failed(board, err):
    admins(f"보드 자동 반납 실패: {board['name']}",
           f"{board.get('lease_user') or '-'} 님에게 빌려 준 보드 {board['name']} 를 대여 종료 시각에 분리하지 못했습니다: {err}. 매 분 다시 시도합니다.",
           {'kind': 'board_return_failed', 'board': board['name'], 'severity': 'warning'})


def loan_reminders(at=None):
    """loan_remind_hours before a card's or a board's end: once per end time (an extension
    brings a new reminder). Returns the number sent."""
    from datetime import datetime, timedelta, timezone
    from pegaprox.vlab import catalog, store
    hours = _settings()['loan_remind_hours']
    if not hours:
        return 0
    at = at or datetime.now(timezone.utc)
    n = 0
    for lease in store.list_leases(active_only=True, limit=5000):
        if not notices.due_soon(lease.get('ends_at'), hours, at):
            continue
        if not notices.once(f"loan_due:{lease['id']}:{lease['ends_at']}"):
            continue
        tell(lease['username'], 'loan', f"대여 종료 예정: {_card(lease)}",
             f"{_card(lease)} (데스크톱 {_desk_of(lease)}) 의 대여가 {notices.local_time(lease['ends_at'])} 에 끝납니다. "
             "그때 자동으로 반납되니 작업과 결과를 저장해 두세요. 연장이 필요하면 관리자에게 요청하세요.",
             'loan_due', lease_id=lease['id'], ends_at=lease['ends_at'])
        n += 1
    local_at = at.astimezone().replace(tzinfo=None)
    for b in catalog.list_boards():
        until = b.get('lease_until')
        if not b.get('attached_desktop') or not until or not b.get('lease_user'):
            continue
        # a board's lease_until is the server's local time without an offset (attach_board)
        try:
            end = datetime.fromisoformat(str(until)[:16])
        except ValueError:
            continue
        if not local_at < end <= local_at + timedelta(hours=hours):
            continue
        if not notices.once(f"board_due:{b['id']}:{until}"):
            continue
        tell(b['lease_user'], 'loan', f"보드 대여 종료 예정: {b['name']}",
             f"보드 {b['name']} 의 대여가 {str(until).replace('T', ' ')} 에 끝납니다. 그때 데스크톱에서 분리되니 작업을 저장해 두세요.",
             'board_due', board_id=b['id'], ends_at=until)
        n += 1
    return n


# --- GPU quotas ------------------------------------------------------------------------------

def _manager_of(dep_id):
    """The department's manager, else the nearest one above it."""
    from pegaprox.vlab import catalog
    d, seen = catalog.get_department(dep_id), set()
    while d and d['id'] not in seen:
        seen.add(d['id'])
        if d.get('manager'):
            return d['manager']
        d = catalog.get_department(d.get('parent_id')) if d.get('parent_id') else None
    return ''


def quota_tick(at=None, force=False):
    """quota_warn_pct and 100% of a monthly GPU-hours quota: once a month per user or department.
    Returns the number of notices sent."""
    from pegaprox.api import vlab_research as rsch
    from pegaprox.vlab import research
    if not force and time.time() - _last['quota'] < QUOTA_EVERY - 5:
        return 0
    _last['quota'] = time.time()
    g = _settings()
    if not g['quota_notice']:
        return 0
    quotas = research.list_quotas()
    if not any(q['monthly_gpu_hours'] for q in quotas):
        return 0
    by = {(q['subject_type'], q['subject_id']): q for q in quotas}
    usage = rsch.month_usage(at)
    month = research.month_start(at).astimezone().strftime('%Y-%m')
    deps, path = rsch._dep_names()
    sent = 0
    for (st, sid), u in sorted(usage.items()):
        q = (by.get(('user', sid)) or by.get(('default', ''))) if st == 'user' else by.get(('department', sid))
        level = notices.quota_level(u['hours'], q['monthly_gpu_hours'] if q else 0, g['quota_warn_pct'])
        if not level:
            continue
        key = f'quota:{st}:{sid}:{month}'
        if notices.was_sent(f'{key}:full') or not notices.once(f'{key}:{level}'):
            continue
        if level == 'full':
            notices.once(f'{key}:warn')
        limit = q['monthly_gpu_hours']
        pct = int(100 * u['hours'] / limit)
        then = ('새 작업은 다음 달까지 시작되지 않습니다(강제 한도).' if q['hard']
                else '이후 작업은 대기열에서 다른 사용자보다 뒤로 밀립니다.') if level == 'full' else '한도에 닿으면 ' + (
                '새 작업이 다음 달까지 시작되지 않습니다.' if q['hard'] else '작업이 대기열에서 뒤로 밀립니다.')
        sev = 'warning' if level == 'full' else 'info'
        if st == 'user':
            title = f"GPU 할당량 {'소진' if level == 'full' else f'{pct}% 사용'}: {month}"
            text = (f"{_who(sid)} 님, 이번 달({month}) GPU 사용량이 {u['hours']:.1f} / {limit:g} GPU-시간({pct}%)입니다. {then}\n"
                    "포털 > 내 자원에서 사용량을 볼 수 있습니다.")
            tell(sid, 'gpu_quota', title, text, f'gpu_quota_{level}', sev, scope='user', month=month, pct=pct)
            sent += 1
            continue
        name = path(sid) or sid
        title = f"부서 GPU 할당량 {'소진' if level == 'full' else f'{pct}% 사용'}: {name}"
        text = (f"부서 {name} 의 이번 달({month}) GPU 사용량이 {u['hours']:.1f} / {limit:g} GPU-시간({pct}%)입니다. "
                f"부서 전체에 적용됩니다. {then}")
        to = set()
        mgr = _manager_of(sid)
        if mgr:
            to.add(mgr)
        for (ust, uid), uu in usage.items():
            if ust == 'user' and uu['hours'] > 0 and sid in rsch.dep_chain(uid):
                to.add(uid)
        for i, who in enumerate(sorted(to)):
            # one webhook event for the department, a mail to each person
            tell(who, 'gpu_quota', title, text, f'gpu_quota_{level}' if i == 0 else None, sev,
                 scope='department', department=name, month=month, pct=pct)
        sent += len(to)
    return sent


# --- web IDEs --------------------------------------------------------------------------------

def ide_closed(row, why, by=''):
    """why: 'idle' (no use for the pool's idle minutes) or 'admin'."""
    if not _settings()['ide_notice']:
        return
    from pegaprox.vlab import store
    kind = 'JupyterLab' if row['kind'] == 'jupyter' else 'VS Code'
    desk = store.get_desktop(row['desktop_id'])
    where = desk['name'] if desk else row['desktop_id']
    if why == 'idle':
        title = f"웹 IDE 유휴 종료: {kind} ({where})"
        text = (f"{where} 의 {kind} 가 오랫동안 쓰이지 않아 종료되었습니다. 저장한 파일은 {row.get('workdir') or '홈 폴더'} 에 그대로 있습니다. "
                "포털에서 다시 열 수 있습니다.")
    else:
        title = f"관리자가 웹 IDE 종료: {kind} ({where})"
        text = (f"{where} 의 {kind} 를 관리자({by})가 종료했습니다. 저장하지 않은 내용은 사라졌을 수 있습니다. "
                "포털에서 다시 열 수 있습니다.")
    tell(row['username'], 'ide', title, text, f'ide_closed_{why}', 'info', ide_id=row['id'])


def ide_tick():
    """Read the live IDEs (the same exec-status GET as a request): an idle one that ended is told."""
    from pegaprox.api import vlab_research as rsch
    from pegaprox.vlab import research
    for row in research.list_ide(live=True):
        try:
            rsch._ide_refresh(row)
        except Exception as e:
            logging.debug(f"[VLAB] IDE {row['id']} refresh: {e}")


# --- the GPU queue (administrators) ------------------------------------------------------------

def queue_tick(at=None):
    """A GPU job waiting longer than queue_alert_hours: the administrators hear of it once."""
    from pegaprox.api import vlab_research as rsch
    from pegaprox.vlab import catalog, research
    hours = _settings()['queue_alert_hours']
    if not hours:
        return 0
    at = at or research.utcnow()
    late = []
    for j in catalog.jobs_in('queued'):
        if not int(j.get('gpus') or 0):
            continue
        t = research.parse(j['created_at'])
        if t and (at - t).total_seconds() >= hours * 3600 and notices.once(f"queue_late:{j['id']}"):
            late.append(j)
    if late:
        lines = [f"- {j['name']} ({j['username']}, GPU {j['gpus']}장): {rsch.REASONS.get(j.get('wait_reason') or '', j.get('wait_reason') or '-')}"
                 for j in late[:20]]
        admins(f"GPU 작업이 {hours}시간 넘게 대기 중 ({len(late)}건)",
               "다음 GPU 작업이 오래 기다리고 있습니다. 가속 자원 > GPU 작업 큐에서 이유를 확인하세요.\n" + '\n'.join(lines),
               {'kind': 'gpu_queue_late', 'jobs': len(late), 'severity': 'warning'})
    return len(late)


# --- desktops, requests, accounts (requests of the administrators) ------------------------------

def desktop_assigned(desk, previous, username):
    if username:
        tell(username, 'desktop', f"데스크톱 배정: {desk['name']}",
             f"데스크톱 {desk['name']} 가 배정되었습니다. 포털에서 접속할 수 있습니다.", 'desktop_assigned', desktop=desk['name'])
    if previous:
        tell(previous, 'desktop', f"데스크톱 회수: {desk['name']}",
             f"데스크톱 {desk['name']} 의 배정이 해제되어 더는 접속할 수 없습니다. 필요한 파일이 있으면 관리자에게 문의하세요.",
             'desktop_unassigned', desktop=desk['name'])


def desktop_reset(desk, by):
    if desk.get('assigned_user'):
        tell(desk['assigned_user'], 'desktop', f"데스크톱 초기화: {desk['name']}",
             f"관리자({by})가 데스크톱 {desk['name']} 를 기준 상태로 되돌렸습니다. 그 뒤에 데스크톱 안에 저장한 내용은 남아 있지 않습니다"
             " (공유 저장소의 홈·작업 폴더는 그대로입니다).", 'desktop_reset', desktop=desk['name'])


def signup_waiting(req):
    admins(f"가입 심사 대기: {req['username']}",
           f"{req.get('display_name') or req['username']} ({req['username']}, {req.get('email') or '메일 없음'}) 님이 가입을 신청했습니다. "
           "사용자 > 가입 심사에서 승인하거나 거절하세요." + (f"\n메모: {req['note']}" if req.get('note') else ''),
           {'kind': 'signup_waiting', 'user': req['username']})


def signup_answered(req, approved, reason=''):
    email = req.get('email')
    if not email:
        return
    try:
        from pegaprox.utils.email import send_email
        if approved:
            send_email([email], '[MOAVI Desk] 가입 승인 / Sign-up approved',
                       f"{req.get('display_name') or req['username']} 님,\n\n{req['username']} 계정의 가입이 승인되었습니다. "
                       "이제 신청할 때 정한 비밀번호로 로그인할 수 있습니다.\n\nYour sign-up was approved: sign in with the password you chose.\n", None)
        else:
            send_email([email], '[MOAVI Desk] 가입 거절 / Sign-up declined',
                       f"{req.get('display_name') or req['username']} 님,\n\n{req['username']} 계정의 가입 신청이 거절되었습니다."
                       + (f"\n사유: {reason}" if reason else '') + "\n문의는 관리자에게 해 주세요.\n\nYour sign-up request was declined.\n", None)
    except Exception as e:
        logging.warning(f"[VLAB] sign-up answer mail to {req['username']}: {e}")


def export_answered(r, approved, note='', hours=0):
    if approved:
        tell(r['username'], 'request', f"데이터 반출 승인: {r['path']}",
             f"{r['path']} 반출 요청이 승인되었습니다. 포털 > 데이터 > 반출 요청에서 {hours}시간 안에 내려받으세요 (한 번만 받을 수 있습니다)."
             + (f"\n메모: {note}" if note else ''), 'data_export_approved', request_id=r['id'])
    else:
        tell(r['username'], 'request', f"데이터 반출 거절: {r['path']}",
             f"{r['path']} 반출 요청이 거절되었습니다.\n사유: {note}", 'data_export_rejected', request_id=r['id'])


def account_security(username, what, by):
    """Always sent: the user should know of a change to how they sign in."""
    texts = {
        'password': ('비밀번호가 재설정되었습니다', f"관리자({by})가 {username} 계정의 비밀번호를 재설정했습니다. 모든 세션이 끝났습니다. "
                     "요청한 적이 없다면 바로 관리자에게 알려 주세요."),
        '2fa': ('2단계 인증이 해제되었습니다', f"관리자({by})가 {username} 계정의 2단계 인증을 해제했습니다. 다음 로그인 뒤 내 계정에서 다시 등록하세요. "
                "요청한 적이 없다면 바로 관리자에게 알려 주세요."),
        'disabled': ('계정이 사용 중지되었습니다', f"관리자({by})가 {username} 계정을 사용 중지했습니다. 문의는 관리자에게 해 주세요."),
        'enabled': ('계정을 다시 쓸 수 있습니다', f"관리자({by})가 {username} 계정을 다시 사용할 수 있게 했습니다."),
        'expired': ('계정 사용 기한이 지났습니다', f"{username} 계정의 사용 기한이 지나 로그인할 수 없게 되었습니다. 연장이 필요하면 관리자에게 문의하세요."),
    }
    title, text = texts[what]
    tell(username, 'account', title, text, f'account_{what}', 'warning' if what in ('password', '2fa') else 'info', always=True)


# --- LAB bookings, shared storage, desktops replaced / moved / disconnected, locked accounts ----

def _booking_people(r):
    """The requester, the participants named one by one and the members of the departments named."""
    from pegaprox.vlab import catalog
    people = [r['requester']]
    deps = set()
    for p in r.get('participants') or []:
        if p.get('subject_type') == 'user':
            people.append(p['subject_id'])
        elif p.get('subject_type') == 'department':
            deps.add(p['subject_id'])
    if deps:
        people += [u for u, d in catalog.user_departments().items() if d in deps]
    return list(dict.fromkeys(x for x in people if x))[:300]


def booking_reminders(at=None):
    """Approved LAB bookings that start within remind_min (reservation settings > 알림): each
    person in it hears once. Returns how many bookings were told."""
    from datetime import datetime, timedelta
    from pegaprox.vlab import reservations as rsv
    from pegaprox.vlab import store
    g = rsv.get_settings(rsv.GLOBAL_KEY)
    mins = int(g.get('remind_min') or 0)
    if mins <= 0:
        return 0
    at = at or datetime.now()
    t0, t1 = rsv.fmt(at), rsv.fmt(at + timedelta(minutes=mins))
    told = 0
    for r in rsv.between(t0, t1, statuses=['approved']):
        if not (t0 <= r['start_at'] <= t1):
            continue
        if not notices.once(f"booking:{r['id']}:{r['start_at']}"):
            continue
        lab = store.get_lab(r['lab_id']) if r.get('lab_id') else None
        where = (lab or {}).get('name') or (store.get_pool(r['pool_id']) or {}).get('name') or 'LAB'
        when = f"{r['start_at'].replace('T', ' ')} ~ {r['end_at'][11:]}"
        title = f"곧 시작하는 예약: {where} {r['start_at'][11:]}"
        text = (f"{where} 예약이 곧 시작합니다.\n일시: {when}\n목적: {r.get('purpose') or '-'}\n"
                "시작 시간에 포털 > 예약의 [데스크톱 열기]로 들어가거나, 실습실 PC 키오스크에서 로그인하세요.")
        for u in _booking_people(r):
            tell(u, 'booking', title, text, 'lab_booking_soon', reservation_id=r['id'])
        told += 1
    return told


def storage_usage(pool, username, usage):
    """After a storage check measured `username`'s folders ({template: KB}): 90 % and 100 % of a
    folder's quota are told once a month each."""
    from datetime import datetime
    from pegaprox.vlab import nas
    if not username or not usage:
        return
    cfg = nas.get(pool['id']) or {}
    names = {'home': '홈', 'project': '프로젝트', 'scratch': '스크래치'}
    month = datetime.now().strftime('%Y-%m')
    for key, kb in usage.items():
        quota = ((cfg.get('folders') or {}).get(key) or {}).get('quota_gb') or 0
        level = notices.storage_level(kb, quota)
        if not level or not notices.once(f"storage:{username}:{pool['id']}:{key}:{month}:{level}"):
            continue
        used = kb / 1024 / 1024
        name = names.get(key, key)
        if level == 'full':
            title = f"내 {name} 폴더가 가득 찼습니다 ({used:.1f} / {quota} GB)"
            text = (f"{pool['name']} 의 {name} 폴더가 할당량 {quota} GB 를 다 썼습니다 ({used:.1f} GB). "
                    "새 파일을 저장하지 못할 수 있습니다. 필요 없는 파일을 지우거나 관리자에게 늘려 달라고 요청하세요.")
        else:
            title = f"내 {name} 폴더 90% 사용 ({used:.1f} / {quota} GB)"
            text = (f"{pool['name']} 의 {name} 폴더가 할당량 {quota} GB 의 90% 를 넘었습니다 ({used:.1f} GB). "
                    "필요 없는 파일을 정리해 주세요." + (" 스크래치는 보관 기간이 지나면 지워집니다." if key == 'scratch' else ''))
        tell(username, 'storage', title, text, f'storage_{level}', 'warning', pool=pool['name'], folder=key, used_gb=round(used, 1), quota_gb=quota)


def desktop_replaced(user, name, image, version):
    tell(user, 'desktop', f"데스크톱 새 버전으로 교체: {name}",
         f"데스크톱 {name} 가 골든 이미지 {image} 의 새 버전({version})으로 바뀌었습니다. 같은 이름으로 그대로 접속하면 됩니다. "
         "예전 데스크톱 안에만 저장한 파일은 옮겨지지 않습니다 (공유 저장소의 홈 · 프로젝트 폴더는 그대로입니다).",
         'desktop_replaced', desktop=name, version=version)


def desktops_moving(cluster_id, node, by):
    """A node goes into maintenance with its guests moved off: the users of its running desktops hear."""
    from pegaprox.vlab import store
    try:
        live = core._vm_states(cluster_id)
    except Exception:
        return 0
    n = 0
    for d in store.list_desktops():
        if d['cluster_id'] != cluster_id or not d.get('assigned_user'):
            continue
        st = live.get(int(d['vmid'])) or {}
        if st.get('node') != node or st.get('status') != 'running':
            continue
        tell(d['assigned_user'], 'desktop', f"서버 점검으로 데스크톱 이동: {d['name']}",
             f"서버({node}) 점검 때문에 데스크톱 {d['name']} 를 다른 서버로 옮깁니다(관리자: {by}). 옮기는 동안 화면이 잠깐 멈추거나 "
             "접속이 끊길 수 있으니 작업을 저장해 두세요. 끊기면 잠시 뒤 다시 접속하면 됩니다.", 'desktop_moving', desktop=d['name'], node=node)
        n += 1
    return n


def session_ended(session, desk, by, record_only=False):
    name = (desk or {}).get('name') or '데스크톱'
    tell(session['username'], 'desktop', f"관리자가 접속을 끊었습니다: {name}",
         f"관리자({by})가 {name} 접속을 끊었습니다." + (" 열려 있는 화면은 닫아 주세요." if record_only else '')
         + " 저장하지 않은 작업이 있었다면 다시 접속해 확인하세요. 이유는 관리자에게 문의하세요.",
         'session_ended', desktop=name)


def account_locked(username, minutes, ip):
    """Too many wrong passwords: the user (always) and the administrators hear."""
    tell(username, 'account', '로그인 실패가 많아 계정이 잠시 잠겼습니다',
         f"{username} 계정에 비밀번호가 여러 번 틀려 {minutes}분 동안 로그인을 막았습니다 (접속한 곳: {ip or '-'}). "
         "본인이 아니라면 비밀번호를 바꾸고 관리자에게 알려 주세요.", 'account_locked', 'warning', always=True)
    admins(f"계정 잠김: {username}", f"{username} 계정이 로그인 실패로 {minutes}분 동안 잠겼습니다 (접속한 곳: {ip or '-'}).",
           {'kind': 'account_locked', 'user': username, 'ip': ip or '', 'severity': 'warning'})


# --- the minute loop ----------------------------------------------------------------------------

def notice_tick():
    """From the minute loop while GPU/AI or FPGA is on. Never raises."""
    from pegaprox.vlab import features
    gpu = features.enabled('gpuai')
    for name, fn in (('loan reminders', loan_reminders),
                     ('GPU quotas', quota_tick if gpu else None),
                     ('web IDEs', ide_tick if gpu else None),
                     ('GPU queue', queue_tick if gpu else None)):
        if fn is None:
            continue
        try:
            fn()
        except Exception as e:
            logging.warning(f'[VLAB] notices ({name}): {e}')
    if time.time() - _last['prune'] > 86400:
        _last['prune'] = time.time()
        try:
            notices.prune()
        except Exception as e:
            logging.debug(f'[VLAB] notices prune: {e}')
