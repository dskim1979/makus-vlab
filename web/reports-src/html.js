// MOAVI Desk 한국형 보고서 — 수집 데이터(collect.ts) → 공문서 형식 HTML (브라우저 인쇄로 PDF)
//
//  형식: A4 세로, 머리부·핵심 지표·보고 요지, Ⅰ/□/○/- 개조식, (단위: …) 표, 붙임, '끝.' 표시
//  글꼴: 나눔명조(본문)·나눔고딕(제목·표) — 설치돼 있으면 사용, 없으면 브라우저 기본 글꼴
//  브라우저 미리보기에서는 PC 글꼴(맑은 고딕·바탕)로 대체됨
//
// 외부 자원(이미지·URL)을 쓰지 않음: weasyprint 사이드카가 data: 외의 주소를 막음
// 원본: 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 (LICENSE·NOTICE)
// 빌드: web/reports-src/build.sh → static/js/makus-reports.js

//  언어: d.locale 이 'en' 이면 영문 보고서 (같은 양식, 영문 문구·날짜·숫자), 그 밖에는 한국어
export const REPORT_TYPES = {
  ops: {
    title: '가상화 인프라 운영 현황 보고',
    short: '운영 현황 보고',
    desc: '구성·자원 사용·백업·점검 결과와 조치 계획을 한 번에 정리한 종합 보고서',
    en: { title: 'Virtualization Infrastructure Operations Report', short: 'Operations report', desc: 'Configuration, resource usage, backups, findings and action plan in one report' },
  },
  resource: {
    title: '가상화 자원 사용 현황 및 증설 검토',
    short: '자원 사용 현황',
    desc: 'CPU·메모리·스토리지 사용률과 할당률, 증설 필요 여부 검토',
    en: { title: 'Resource Usage and Capacity Review', short: 'Resource usage', desc: 'CPU, memory and storage usage and allocation, with an expansion review' },
  },
  asset: {
    title: '가상서버 자원 현황(대장)',
    short: '가상서버 대장',
    desc: '가상서버(VM·컨테이너) 목록과 자원 할당 내역 — 정보자원 현황 관리용',
    en: { title: 'Virtual Server Inventory', short: 'VM inventory', desc: 'List of virtual servers (VMs and containers) with allocated resources' },
  },
}

/** 보고서 종류 문구 (locale 'en' 이면 영문) */
export function typeText(type, locale) {
  const t = REPORT_TYPES[type] || REPORT_TYPES.ops
  return locale === 'en' ? t.en : { title: t.title, short: t.short, desc: t.desc }
}

const ROMAN = ['Ⅰ', 'Ⅱ', 'Ⅲ', 'Ⅳ', 'Ⅴ', 'Ⅵ', 'Ⅶ', 'Ⅷ']
const WEEKDAY = ['일', '월', '화', '수', '목', '금', '토']
const WEEKDAY_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const MONTH_EN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

// 렌더링 중 언어 (renderReportHtml 이 동기적으로 설정·사용)
let LANG = 'ko'
const tt = (ko, en) => (LANG === 'en' ? en : ko)

// ---------- 형식 도우미 ----------
export function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

function kst(d) {
  // 서버(컨테이너)는 UTC 일 수 있으므로 한국 시간으로 계산
  return new Date(new Date(d).getTime() + 9 * 3600 * 1000)
}

/** 2026. 9. 30.(수) / 영문: Sep 30, 2026 (Wed) */
export function krDate(d, withDay = true) {
  const k = kst(d)
  if (LANG === 'en') {
    const s = `${MONTH_EN[k.getUTCMonth()]} ${k.getUTCDate()}, ${k.getUTCFullYear()}`
    return withDay ? `${s} (${WEEKDAY_EN[k.getUTCDay()]})` : s
  }
  const s = `${k.getUTCFullYear()}. ${k.getUTCMonth() + 1}. ${k.getUTCDate()}.`
  return withDay ? `${s}(${WEEKDAY[k.getUTCDay()]})` : s
}

function krDateTime(d) {
  const k = kst(d)
  const p = n => String(n).padStart(2, '0')
  return `${krDate(d, false)} ${p(k.getUTCHours())}:${p(k.getUTCMinutes())}`
}

const nf = (n, digits = 0) =>
  n === null || n === undefined || !Number.isFinite(n) ? '-' : n.toLocaleString(LANG === 'en' ? 'en-US' : 'ko-KR', { minimumFractionDigits: digits, maximumFractionDigits: digits })

const pct = n => (n === null || n === undefined || !Number.isFinite(n) ? '-' : `${nf(n, 1)}`)

function bytes(b) {
  if (!Number.isFinite(b) || b <= 0) return '-'
  const gb = b / 1024 ** 3
  return gb >= 1024 ? `${nf(gb / 1024, 1)} TB` : `${nf(gb, gb < 10 ? 1 : 0)} GB`
}

const gib = b => (Number.isFinite(b) && b > 0 ? nf(b / 1024 ** 3, b / 1024 ** 3 < 10 ? 1 : 0) : '-')

function days(sec) {
  if (!Number.isFinite(sec) || sec <= 0) return '-'
  const d = Math.floor(sec / 86400)
  return d >= 1 ? tt(`${nf(d)}일`, `${nf(d)} d`) : tt(`${Math.floor(sec / 3600)}시간`, `${Math.floor(sec / 3600)} h`)
}

const LV = { ok: ['양호', 'Good'], warn: ['주의', 'Caution'], crit: ['위험', 'Critical'] }
const lvLabel = cls => tt(LV[cls][0], LV[cls][1])
const scopeLabel = s => (s === '공유' ? tt('공유', 'Shared') : s)

/** 판정: 양호 / 주의 / 위험 */
export function grade(value, th) {
  if (value === null || value === undefined || !Number.isFinite(value)) return { label: '-', cls: '' }
  if (value >= th.crit) return { label: lvLabel('crit'), cls: 'crit' }
  if (value >= th.warn) return { label: lvLabel('warn'), cls: 'warn' }
  return { label: lvLabel('ok'), cls: 'ok' }
}

const badge = g => (g.cls ? `<span class="g ${g.cls}">${g.label}</span>` : '-')

// ---------- 집계 ----------
export function summarize(d) {
  const th = d.thresholds
  const nodesOnline = d.nodes.filter(n => n.status === 'online')
  const sum = (arr, f) => arr.reduce((s, x) => s + (f(x) || 0), 0)
  const avgOf = (arr, f) => {
    const v = arr.map(f).filter(x => Number.isFinite(x))
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null
  }
  const maxOf = (arr, f) => {
    const v = arr.map(f).filter(x => Number.isFinite(x))
    return v.length ? Math.max(...v) : null
  }

  const cpuCores = sum(nodesOnline, n => n.cpuCores)
  const memTotal = sum(nodesOnline, n => n.memTotal)
  const vms = d.vms.filter(v => !v.template)
  const running = vms.filter(v => v.status === 'running')
  const vcpuAlloc = sum(vms, v => v.cpus)
  const memAlloc = sum(vms, v => v.mem)
  const stTotal = sum(d.storages, s => s.total)
  const stUsed = sum(d.storages, s => s.used)

  const s = {
    clusters: d.clusters.length,
    nodes: d.nodes.length,
    nodesOnline: nodesOnline.length,
    nodesOffline: d.nodes.length - nodesOnline.length,
    vms: vms.length,
    qemu: vms.filter(v => v.type === 'qemu').length,
    lxc: vms.filter(v => v.type === 'lxc').length,
    running: running.length,
    stopped: vms.length - running.length,
    cpuCores,
    memTotal,
    vcpuAlloc,
    memAlloc,
    vcpuRatio: cpuCores ? (vcpuAlloc / cpuCores) * 100 : null,
    memAllocRatio: memTotal ? (memAlloc / memTotal) * 100 : null,
    cpuAvg: avgOf(nodesOnline, n => n.cpuAvg ?? n.cpuNow),
    cpuMax: maxOf(nodesOnline, n => n.cpuMax ?? n.cpuNow),
    memAvg: avgOf(nodesOnline, n => n.memAvg ?? n.memNow),
    memMax: maxOf(nodesOnline, n => n.memMax ?? n.memNow),
    stTotal,
    stUsed,
    stPct: stTotal ? (stUsed / stTotal) * 100 : null,
    stMaxPct: maxOf(d.storages, x => x.pct),
    backup: d.backups,
  }

  // 점검 결과(이슈) — 위험 먼저
  const issues = []
  for (const n of d.nodes) {
    if (n.status !== 'online') issues.push({ lv: 'crit', area: tt('노드', 'Node'), text: tt(`${n.cluster} / ${n.node} 노드 연결 끊김(오프라인)`, `Node ${n.cluster} / ${n.node} unreachable (offline)`), act: tt('노드 전원·네트워크 상태 점검 및 복구', 'Check node power and network, then restore') })
  }
  for (const n of nodesOnline) {
    const cpu = n.cpuMax ?? n.cpuNow
    const mem = n.memMax ?? n.memNow
    const gc = grade(cpu, th)
    const gm = grade(mem, th)
    if (gc.cls === 'crit' || gc.cls === 'warn') issues.push({ lv: gc.cls, area: 'CPU', text: tt(`${n.node} 노드 CPU 최대 사용률 ${pct(cpu)}%`, `Node ${n.node} peak CPU usage ${pct(cpu)}%`), act: tt('가상서버 재배치(부하 분산) 또는 CPU 증설 검토', 'Rebalance virtual servers or consider adding CPU') })
    if (gm.cls === 'crit' || gm.cls === 'warn') issues.push({ lv: gm.cls, area: tt('메모리', 'Memory'), text: tt(`${n.node} 노드 메모리 최대 사용률 ${pct(mem)}%`, `Node ${n.node} peak memory usage ${pct(mem)}%`), act: tt('미사용 가상서버 정리, 메모리 증설 검토', 'Remove unused virtual servers or consider adding memory') })
  }
  for (const st of d.storages) {
    const g = grade(st.pct, th)
    if (g.cls === 'crit' || g.cls === 'warn') issues.push({ lv: g.cls, area: tt('스토리지', 'Storage'), text: tt(`${st.name}(${scopeLabel(st.scope)}) 사용률 ${pct(st.pct)}% (여유 ${bytes(st.total - st.used)})`, `${st.name} (${scopeLabel(st.scope)}) usage ${pct(st.pct)}% (${bytes(st.total - st.used)} free)`), act: tt('불필요 백업·스냅샷 정리 및 용량 증설 검토', 'Clean up old backups and snapshots, or consider expanding capacity') })
  }
  if (d.backups && d.backups.fail > 0) {
    issues.push({ lv: 'crit', area: tt('백업', 'Backup'), text: tt(`백업 작업 실패 ${nf(d.backups.fail)}건`, `${nf(d.backups.fail)} failed backup job(s)`), act: tt('실패 원인(저장소 용량·네트워크) 확인 후 재수행', 'Check the cause (storage space, network) and run again') })
  }
  if (d.backups && d.backups.total === 0) {
    issues.push({ lv: 'warn', area: tt('백업', 'Backup'), text: tt('보고 기간 중 백업 작업 이력 없음', 'No backup jobs ran during the period'), act: tt('백업 일정(스케줄) 설정 여부 확인', 'Check that backup schedules are configured') })
  }
  if (s.memAllocRatio !== null && s.memAllocRatio > 100) {
    issues.push({ lv: 'warn', area: tt('할당', 'Allocation'), text: tt(`메모리 할당률 ${pct(s.memAllocRatio)}% (물리 메모리 초과 할당)`, `Memory allocation ${pct(s.memAllocRatio)}% (overcommitted)`), act: tt('동시 기동 시 성능 저하 가능 — 할당량 조정 검토', 'Performance may degrade when all run at once — review allocations') })
  }
  // 외부 시스템 AI 점검에서 찾은 항목도 종합 판정·점검 결과에 넣음
  // 하드웨어(BMC): 기간에 지금이 들어 있으면 현재 이상, 지난 기간이면 그 기간에 있었던 이상만 (기록이 없는 기간은 넣지 않음)
  const hwAct = key => key === 'unreachable' ? tt('BMC 관리 포트의 네트워크·계정 상태 확인', 'Check the BMC management port network and account') : tt('BMC 에서 해당 부품 상태 확인, 필요 시 제조사 기술지원 요청', 'Check the component in the BMC and contact the vendor if needed')
  const hwEnd = d.period.to + 1
  for (const h of d.hardware?.covered ? d.hardware.servers || [] : []) {
    const who = `${h.name}${h.node ? ` (${h.node})` : ''}`
    if (d.hardware.live) {
      for (const a of h.alarms) issues.push({ lv: a.severity === 'critical' ? 'crit' : 'warn', area: tt('하드웨어', 'Hardware'), text: `${who}: ${tt(a.text.ko, a.text.en)}`, act: hwAct(a.key) })
    } else {
      for (const it of h.incidents || []) {
        const fixed = it.recoveredAt !== null && it.recoveredAt < hwEnd
        issues.push({
          lv: fixed ? 'warn' : it.severity === 'critical' ? 'crit' : 'warn',
          area: tt('하드웨어', 'Hardware'),
          text: `${who}: ${tt(it.text.ko, it.text.en)} (${fixed ? tt(`${krDateTime(it.recoveredAt)} 복구`, `recovered ${krDateTime(it.recoveredAt)}`) : tt('기간 말 미복구', 'not recovered by period end')})`,
          act: fixed ? tt('재발 여부 관찰', 'Watch for recurrence') : hwAct(it.key),
        })
      }
    }
  }
  for (const f of d.externalChecks?.ok ? d.externalChecks.findings || [] : []) {
    issues.push({ lv: f.severity === 'critical' ? 'crit' : 'warn', area: f.system || tt('외부 시스템', 'External system'), text: `${f.target}: ${f.message}`, act: f.action || tt('AI 점검 결과 확인', 'Review the AI check result') })
  }
  for (const e of d.errors || []) {
    issues.push({ lv: 'warn', area: tt('수집', 'Collection'), text: tt(`${e.connection} 정보 수집 실패`, `Could not collect data from ${e.connection}`), act: tt('연결 상태(주소·토큰) 확인', 'Check the connection (address, token)') })
  }
  const order = { crit: 0, warn: 1 }
  issues.sort((a, b) => order[a.lv] - order[b.lv])
  s.issues = issues
  s.crit = issues.filter(i => i.lv === 'crit').length
  s.warn = issues.filter(i => i.lv === 'warn').length
  const ov = s.crit ? 'crit' : s.warn ? 'warn' : 'ok'
  s.overall = { label: lvLabel(ov), cls: ov }
  return s
}

// ---------- 공통 조각 ----------
function css(landscape, cls) {
  // 보안 등급 표시(오른쪽 위) — CSS 문자열에 들어가므로 따옴표·역슬래시·줄바꿈 제거
  const mark = String(cls || '').replace(/["'\\\r\n{}<>;]/g, '').slice(0, 20)
  const gothic = '"NanumGothic", "Nanum Gothic", "Malgun Gothic", sans-serif'
  return `
@page {
  size: A4 ${landscape ? 'landscape' : 'portrait'};
  margin: 20mm 17mm 18mm 17mm;
  @bottom-center { content: "- " counter(page) " -"; font-family: ${gothic}; font-size: 9pt; color: #333; }
  ${mark ? `@top-right { content: "${mark}"; font-family: ${gothic}; font-size: 9pt; font-weight: 700; color: #b00020; }` : ''}
}
:root {
  --gothic: "NanumGothic", "Nanum Gothic", "Malgun Gothic", "맑은 고딕", "Noto Sans CJK KR", sans-serif;
  --myeongjo: "NanumMyeongjo", "Nanum Myeongjo", "Batang", "바탕", "Noto Serif CJK KR", serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: #fff; color: #1d2433; }
body { font-family: var(--myeongjo); font-size: 11pt; line-height: 1.7; word-break: keep-all; }
h1, h2, h3, table, .gothic, .head, .kpi, .summary .ttl, .attach-ttl, .unit, .note, .end, .footer-note { font-family: var(--gothic); }

/* 머리부: 남색 띠 + 제목 */
.head { border-top: 5pt solid #1b2f5b; padding-top: 5mm; margin-bottom: 6mm; }
.head .kicker { font-size: 9pt; font-weight: 700; color: #1668e3; letter-spacing: 1.5pt; }
.head h1 { margin: 1.5mm 0 3mm; font-size: 21pt; font-weight: 800; letter-spacing: -0.5pt; color: #0f1d3d; line-height: 1.3; }
.head .info { border-top: 0.6pt solid #c9d1e0; border-bottom: 0.6pt solid #c9d1e0; padding: 2mm 0; font-size: 9.5pt; color: #3c4658; }
.head .info span { margin-right: 6mm; }
.head .info b { color: #0f1d3d; margin-right: 1.5mm; }

/* 핵심 지표 카드 */
table.kpi { width: 100%; border-collapse: separate; border-spacing: 2.5mm 0; margin: 0 -2.5mm 5mm; }
table.kpi td { width: 25%; background: #f3f6fb; border-top: 2.2pt solid #1668e3; padding: 3mm 3.5mm 3.2mm; vertical-align: top; }
table.kpi td.st-ok { border-top-color: #1a7f37; }
table.kpi td.st-warn { border-top-color: #d97706; }
table.kpi td.st-crit { border-top-color: #c1121f; }
.kpi .k { font-size: 8.5pt; color: #5a6477; }
.kpi .v { font-size: 17pt; font-weight: 800; color: #0f1d3d; line-height: 1.25; margin-top: 0.8mm; }
.kpi .v small { font-size: 9pt; font-weight: 700; color: #5a6477; margin-left: 0.8mm; }
.kpi .s { font-size: 8pt; color: #5a6477; margin-top: 0.5mm; }

/* 요약 */
.summary { background: #f8fafd; border-left: 3pt solid #1b2f5b; padding: 3mm 5mm 3.5mm; margin: 0 0 6mm; }
.summary .ttl { font-weight: 800; font-size: 10.5pt; color: #1b2f5b; margin-bottom: 1mm; }
.summary p { margin: 0.8mm 0; }

/* 제목 단계 */
h2 { font-size: 13.5pt; font-weight: 800; color: #0f1d3d; margin: 8mm 0 3mm; padding-bottom: 1.5mm; border-bottom: 0.8pt solid #1b2f5b; page-break-after: avoid; }
h2 .no { display: inline-block; text-indent: 0; width: 7.5mm; height: 7.5mm; line-height: 7.5mm; margin-right: 2.5mm; text-align: center; background: #1b2f5b; color: #fff; font-size: 11pt; border-radius: 1.2mm; }
p { margin: 1mm 0; }
.l1 { padding-left: 5mm; text-indent: -5mm; margin-top: 2.2mm; }
.l2 { padding-left: 10mm; text-indent: -5mm; }
.l3 { padding-left: 14mm; text-indent: -3.5mm; }
.note { padding-left: 4.5mm; text-indent: -4.5mm; font-size: 8.5pt; color: #5a6477; margin-top: 1.2mm; }
b, strong { font-weight: 700; }

/* 표 */
.unit { text-align: right; font-size: 8pt; color: #5a6477; margin: 2.5mm 0 0.8mm; }
table.t { width: 100%; border-collapse: collapse; font-size: 8.8pt; line-height: 1.4; }
table.t thead { display: table-header-group; }
table.t tr { page-break-inside: avoid; }
table.t th, table.t td { border-bottom: 0.5pt solid #d5dbe6; padding: 1.5mm 1.8mm; vertical-align: middle; }
table.t thead th { background: #1b2f5b; color: #fff; font-weight: 700; text-align: center; border-bottom: none; }
table.t tbody tr:nth-child(even) td { background: #f6f8fc; }
table.t tbody tr:last-child td { border-bottom: 1pt solid #1b2f5b; }
table.t td.c { text-align: center; }
table.t td.r { text-align: right; }
table.t tr.total td { background: #e8eef8 !important; font-weight: 700; }
/* 열이 많은 목록(가상서버 대장)을 세로 A4 에 */
table.t.dense { font-size: 8pt; line-height: 1.35; }
table.t.dense th, table.t.dense td { padding: 1.2mm 1.3mm; }
table.t.dense td.nm { word-break: break-all; }
.bar { display: inline-block; text-indent: 0; width: 16mm; height: 2mm; background: #e3e8f1; border-radius: 1mm; vertical-align: middle; margin-left: 1.5mm; }
.bar i { display: block; height: 2mm; border-radius: 1mm; background: #1668e3; }
.bar i.warn { background: #d97706; }
.bar i.crit { background: #c1121f; }
.g { display: inline-block; text-indent: 0; margin: 0 0.6mm; line-height: 1.5; font-weight: 700; font-size: 8pt; padding: 0.2mm 2mm; border-radius: 3mm; }
.g.ok { color: #1a7f37; background: #e6f4ea; }
.g.warn { color: #b45309; background: #fdf1e2; }
.g.crit { color: #c1121f; background: #fbe7e9; }

.end { text-align: right; font-weight: 700; margin-top: 4mm; }
.attach { page-break-before: always; }
.attach-ttl { font-size: 12.5pt; font-weight: 800; color: #0f1d3d; margin: 0 0 3mm; }
.attach-ttl .tag { display: inline-block; background: #1b2f5b; color: #fff; padding: 0.4mm 2.5mm; margin-right: 2.5mm; font-size: 9.5pt; border-radius: 1mm; }
.footer-note { margin-top: 8mm; font-size: 7.5pt; color: #8a93a5; text-align: center; }

/* 화면 미리보기: 회색 바탕 위 종이 모양 (PDF 에는 적용 안 됨) */
@media screen {
  html { background: #e9ecf2; padding: 16px 12px; }
  body { max-width: ${landscape ? '297mm' : '210mm'}; margin: 0 auto; padding: 16mm 15mm; box-shadow: 0 2px 12px rgba(15, 29, 61, 0.18); }
  .attach { margin-top: 12mm; padding-top: 8mm; border-top: 1px dashed #c9d1e0; }
}
`
}

function header(d, title) {
  const m = d.meta || {}
  const org = [m.org, m.dept].filter(Boolean).map(esc).join(' ')
  const writer = [m.author ? esc(m.author) : '', m.contact ? `☎ ${esc(m.contact)}` : ''].filter(Boolean).join(' · ')
  return `<div class="head">
<div class="kicker">${tt(`${org || 'MOAVI Desk 가상화 인프라'} 보고`, org ? `${org} Report` : 'MOAVI Desk Virtualization Infrastructure')}</div>
<h1>${esc(title)}</h1>
<div class="info"><span><b>${tt('보고 기간', 'Period')}</b>${krDate(d.period.from, false)} ~ ${krDate(d.period.to, false)}</span><span><b>${tt('작성일', 'Date')}</b>${krDate(d.generatedAt)}</span>${writer ? `<span><b>${tt('작성', 'Prepared by')}</b>${writer}</span>` : ''}</div>
</div>`
}

/** 핵심 지표 카드 4개: [{k, v, unit, s, st}] */
function kpis(items) {
  return `<table class="kpi"><tr>${items
    .map(x => `<td class="${x.st ? 'st-' + x.st : ''}"><div class="k">${x.k}</div><div class="v">${x.v}${x.unit ? `<small>${x.unit}</small>` : ''}</div>${x.s ? `<div class="s">${x.s}</div>` : ''}</td>`)
    .join('')}</tr></table>`
}

/** 사용률 수치 + 막대 */
function pbar(v, th) {
  if (v === null || v === undefined || !Number.isFinite(v)) return '-'
  const g = grade(v, th)
  return `${pct(v)}<span class="bar"><i class="${g.cls === 'ok' ? '' : g.cls}" style="width:${Math.max(0, Math.min(100, v)).toFixed(0)}%"></i></span>`
}

// 개조식 기호: 한국어 □ ○ - ※ / 영문 ■ • – *
const h2 = (i, text) => `<h2><span class="no">${ROMAN[i]}</span>${esc(text)}</h2>`
const b1 = () => tt('□', '■')
const l1 = t => `<p class="l1">${b1()} ${t}</p>`
const l2 = t => `<p class="l2">${tt('○', '•')} ${t}</p>`
const l3 = t => `<p class="l3">${tt('-', '–')} ${t}</p>`
const note = t => `<p class="note">${tt('※', '*')} ${t}</p>`
const endMark = () => (LANG === 'en' ? '' : '<p class="end">끝.</p>')

function table(headers, rows, opts = {}) {
  const align = opts.align || []
  return `${opts.unit ? `<div class="unit">(${tt('단위', 'Unit')}: ${esc(opts.unit)})</div>` : ''}<table class="t${opts.cls ? ` ${opts.cls}` : ''}">
<thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
<tbody>${rows
    .map(r => `<tr${r.cls ? ` class="${r.cls}"` : ''}>${(r.cells || r).map((c, i) => `<td class="${align[i] || ''}">${c}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`
}

function doc(d, title, body, landscape = false) {
  return `<!doctype html><html lang="${LANG}"><head><meta charset="utf-8"><title>${esc(title)}</title>
<style>${css(landscape, d.meta?.classification)}</style></head><body>
${header(d, title)}
${body}
<div class="footer-note">${tt(`본 보고서는 MOAVI Desk 가상화 통합 관리 플랫폼에서 ${krDateTime(d.generatedAt)}에 자동 생성되었습니다.`, `This report was generated automatically by the MOAVI Desk virtualization management platform on ${krDateTime(d.generatedAt)} (KST).`)}</div>
</body></html>`
}

// ---------- 공통 섹션 ----------
function sectionOverview(d, s) {
  const scope = d.clusters.map(c => esc(c.name)).join(', ') || '-'
  const w = d.thresholds.warn
  const c = d.thresholds.crit
  return LANG === 'en'
    ? l1(`<b>Purpose</b> : review the operating status of the virtualization infrastructure and resource usage trends, for stable operation and capacity planning`) +
      l1(`<b>Scope</b> : ${nf(s.clusters)} cluster(s) (${scope}), ${nf(s.nodes)} physical server(s) (nodes), ${nf(s.vms)} virtual server(s)`) +
      l1(`<b>Period</b> : ${krDate(d.period.from)} ~ ${krDate(d.period.to)}`) +
      l1(`<b>Criteria</b> : usage below ${w}% <span class="g ok">${lvLabel('ok')}</span>, ${w}% or more <span class="g warn">${lvLabel('warn')}</span>, ${c}% or more <span class="g crit">${lvLabel('crit')}</span>`)
    : l1(`<b>보고 목적</b> : 가상화 인프라의 운영 현황을 점검하고 자원 사용 추이를 파악하여 안정적 운영 및 증설 계획 수립에 활용`) +
      l1(`<b>점검 대상</b> : 클러스터 ${nf(s.clusters)}개(${scope}), 물리 서버(노드) ${nf(s.nodes)}대, 가상서버 ${nf(s.vms)}대`) +
      l1(`<b>점검 기간</b> : ${krDate(d.period.from)} ~ ${krDate(d.period.to)}`) +
      l1(`<b>판정 기준</b> : 사용률 ${w}% 미만 <span class="g ok">양호</span>, ${w}% 이상 <span class="g warn">주의</span>, ${c}% 이상 <span class="g crit">위험</span>`)
}

function compositionTable(s) {
  return table(
    [tt('구분', 'Item'), tt('클러스터', 'Clusters'), tt('노드(정상/전체)', 'Nodes (up/total)'), tt('가상서버', 'Virtual servers'), 'VM', tt('컨테이너', 'Containers'), tt('운영 중', 'Running'), tt('정지', 'Stopped')],
    [[
      `<b>${tt('합계', 'Total')}</b>`, nf(s.clusters), `${nf(s.nodesOnline)} / ${nf(s.nodes)}`, nf(s.vms), nf(s.qemu), nf(s.lxc), nf(s.running), nf(s.stopped),
    ]],
    { unit: tt('개, 대', 'count'), align: ['c', 'r', 'c', 'r', 'r', 'r', 'r', 'r'] },
  )
}

function usageTable(d, s) {
  const th = d.thresholds
  return table(
    [tt('구분', 'Resource'), tt('보유(물리)', 'Physical'), tt('할당(가상)', 'Allocated'), tt('할당률(%)', 'Alloc. (%)'), tt('평균 사용률(%)', 'Avg. usage (%)'), tt('최대 사용률(%)', 'Peak usage (%)'), tt('판정', 'Status')],
    [
      ['<b>CPU</b>', `${nf(s.cpuCores)} ${tt('코어', 'cores')}`, `${nf(s.vcpuAlloc)} vCPU`, pct(s.vcpuRatio), pct(s.cpuAvg), pbar(s.cpuMax, th), badge(grade(s.cpuMax, th))],
      [`<b>${tt('메모리', 'Memory')}</b>`, bytes(s.memTotal), bytes(s.memAlloc), pct(s.memAllocRatio), pct(s.memAvg), pbar(s.memMax, th), badge(grade(s.memMax, th))],
      [`<b>${tt('스토리지', 'Storage')}</b>`, bytes(s.stTotal), bytes(s.stUsed) + tt(' 사용', ' used'), '-', pct(s.stPct), pbar(s.stMaxPct, th), badge(grade(s.stMaxPct, th))],
    ],
    { unit: '%', align: ['c', 'r', 'r', 'r', 'r', 'r', 'c'] },
  ) + note(tt(
    'CPU·메모리 최대 사용률은 보고 기간 중 노드별 최대값(1분~1일 평균 구간 기준)이며, 스토리지 최대 사용률은 가장 많이 사용 중인 저장소 기준임',
    'CPU and memory peak usage is the highest per-node value in the period (1-minute to 1-day averages); storage peak usage is the fullest storage',
  ))
}

function backupPart(d) {
  const b = d.backups
  if (!b) return l2(tt('백업 이력 정보를 수집하지 못함', 'Backup history could not be collected'))
  const rate = b.total ? (b.ok / b.total) * 100 : null
  const r = rate === null ? '-' : pct(rate) + '%'
  let out = l2(tt(
    `백업 작업 <b>${nf(b.total)}건</b> 수행 : 성공 ${nf(b.ok)}건, 경고 ${nf(b.warn)}건, 실패 <b>${nf(b.fail)}건</b> (성공률 ${r})`,
    `<b>${nf(b.total)}</b> backup job(s) : ${nf(b.ok)} succeeded, ${nf(b.warn)} with warnings, <b>${nf(b.fail)} failed</b> (success rate ${r})`,
  ))
  if (b.failures && b.failures.length) {
    out += table(
      [tt('연번', 'No.'), tt('일시', 'Time'), tt('노드', 'Node'), tt('대상', 'Target'), tt('결과', 'Result')],
      b.failures.slice(0, 10).map((f, i) => [nf(i + 1), esc(krDateTime(f.time)), esc(f.node), esc(f.target || tt('전체', 'All')), `<span class="g crit">${esc(f.status)}</span>`]),
      { unit: tt('건', 'jobs'), align: ['c', 'c', 'c', 'c', ''] },
    )
    if (b.failures.length > 10) out += note(tt(`실패 ${nf(b.failures.length)}건 중 최근 10건만 표시`, `Showing the latest 10 of ${nf(b.failures.length)} failures`))
  }
  return out
}

function issuesPart(s) {
  if (!s.issues.length) {
    return l1(tt('점검 결과 <span class="g ok">특이사항 없음</span>', 'Result : <span class="g ok">no issues found</span>')) +
      l2(tt('전 항목 판정 기준 이내로 정상 운영 중', 'All items are within the criteria'))
  }
  return (
    l1(tt(
      `점검 결과 <span class="g crit">위험 ${nf(s.crit)}건</span>, <span class="g warn">주의 ${nf(s.warn)}건</span> 확인`,
      `Result : <span class="g crit">${nf(s.crit)} critical</span>, <span class="g warn">${nf(s.warn)} caution</span>`,
    )) +
    table(
      [tt('연번', 'No.'), tt('구분', 'Area'), tt('점검 내용', 'Finding'), tt('등급', 'Level'), tt('조치 방안', 'Action')],
      s.issues.map((it, i) => [nf(i + 1), esc(it.area), esc(it.text), badge({ label: lvLabel(it.lv), cls: it.lv }), esc(it.act)]),
      { unit: tt('건', 'items'), align: ['c', 'c', '', 'c', ''] },
    )
  )
}

function planPart(s) {
  const lines = []
  if (s.crit) lines.push(l1(tt('<b>(긴급)</b> 위험 등급 항목은 즉시 조치하고 결과를 별도 보고', '<b>(Urgent)</b> Fix critical items immediately and report the results separately')))
  if (s.warn) lines.push(l1(tt('<b>(단기)</b> 주의 등급 항목은 1개월 이내 원인 분석 및 개선', '<b>(Short term)</b> Analyze and improve caution items within one month')))
  if (s.memAllocRatio !== null && s.memAllocRatio > 80) lines.push(l1(tt('<b>(중기)</b> 메모리 할당률이 높아 차년도 예산에 서버(메모리) 증설 반영 검토', '<b>(Mid term)</b> Memory allocation is high — consider server (memory) expansion in next year’s budget')))
  if (s.stMaxPct !== null && s.stMaxPct > 70) lines.push(l1(tt('<b>(중기)</b> 스토리지 사용 증가 추세 감시 및 용량 증설 계획 수립', '<b>(Mid term)</b> Watch storage growth and plan capacity expansion')))
  lines.push(l1(tt('<b>(상시)</b> 월 1회 운영 현황 점검 및 보고 체계 유지', '<b>(Ongoing)</b> Keep a monthly operations review and report')))
  return lines.join('')
}

// 외부 시스템 AI 점검 (운영 현황 보고서) — 마지막 'AI 정기 점검' 결과 (설정 > MCP 연동, 벤더 무관)
const EXT_ITEM = { alert: ['알림', 'Alert'], capacity: ['용량', 'Capacity'], performance: ['성능', 'Performance'], health: ['상태', 'Health'], security: ['보안', 'Security'], hardware: ['하드웨어', 'Hardware'], replication: ['복제', 'Replication'], other: ['기타', 'Other'] }
function externalPart(d) {
  const x = d.externalChecks
  const servers = (x.servers || []).map(esc).join(', ') || '-'
  let out = l2(tt(`점검 일시 ${krDateTime(x.at)} · 대상 ${servers} (AI 운영 도우미 자동 점검)`, `Checked ${krDateTime(x.at)} (KST) · targets ${servers} (automatic AI check)`))
  if (!x.ok) return out + l2(tt(`점검 실패: ${esc(x.error || '')}`, `Check failed: ${esc(x.error || '')}`))
  if (x.summary) out += l2(esc(x.summary))
  if (!x.findings?.length) return out + l2(tt('<span class="g ok">특이사항 없음</span>', '<span class="g ok">No issues found</span>'))
  return out + table(
    [tt('연번', 'No.'), tt('시스템', 'System'), tt('대상', 'Target'), tt('구분', 'Area'), tt('점검 내용', 'Finding'), tt('등급', 'Level'), tt('조치 방안', 'Action')],
    x.findings.map((f, i) => {
      const cls = f.severity === 'critical' ? 'crit' : 'warn'
      const item = EXT_ITEM[f.item] || EXT_ITEM.other
      return [nf(i + 1), esc(f.system || '-'), esc(f.target), tt(item[0], item[1]), esc(f.message), badge({ label: lvLabel(cls), cls }), esc(f.action || '-')]
    }),
    { unit: tt('건', 'items'), align: ['c', 'c', 'c', 'c', '', 'c', ''] },
  )
}

// 하드웨어 상태 (운영 현황 보고서) — 하드웨어(BMC) 감시 기록 중 보고 기간에 해당하는 것 (설정 > 하드웨어(BMC))
//  지난 기간: 그 기간에 있었던 이상(발생·복구 시각)만 — 지금 상태는 넣지 않음
//  지금이 들어 있는 기간(이번 달 등): '현재 상태' 열을 더함
function hardwarePart(d) {
  const x = d.hardware
  if (!x.covered) {
    return l2(tt(`보고 기간에는 하드웨어 감시 기록이 없습니다 (감시 시작 ${krDateTime(x.coveredFrom)})`,
      `No hardware monitoring records for this period (monitoring started ${krDateTime(x.coveredFrom)} KST)`))
  }
  const end = d.period.to + 1
  const fixed = it => it.recoveredAt !== null && it.recoveredAt < end
  const all = x.servers.flatMap(h => h.incidents || [])
  const critN = all.filter(it => it.severity === 'critical').length
  const openN = all.filter(it => !fixed(it)).length
  let out = l2(x.live
    ? tt(`확인 일시 ${krDateTime(x.at)} · 서버 ${nf(x.servers.length)}대 · 보고 기간 중 하드웨어 이상 ${nf(all.length)}건(위험 ${nf(critN)}건), 미복구 ${nf(openN)}건 (BMC 자동 감시)`,
      `Checked ${krDateTime(x.at)} (KST) · ${nf(x.servers.length)} server(s) · ${nf(all.length)} hardware issue(s) during the period (${nf(critN)} critical), ${nf(openN)} not recovered (automatic BMC monitoring)`)
    : tt(`서버 ${nf(x.servers.length)}대 · 보고 기간 중 하드웨어 이상 ${nf(all.length)}건(위험 ${nf(critN)}건), 기간 말 미복구 ${nf(openN)}건 (BMC 자동 감시)`,
      `${nf(x.servers.length)} server(s) · ${nf(all.length)} hardware issue(s) during the period (${nf(critN)} critical), ${nf(openN)} not recovered by period end (automatic BMC monitoring)`))
  if (x.coveredFrom > d.period.from) {
    out += note(tt(`하드웨어 감시 기록은 ${krDateTime(x.coveredFrom)}부터 있습니다`, `Hardware monitoring records start at ${krDateTime(x.coveredFrom)} (KST)`))
  }
  const line = it => {
    const mark = it.severity === 'critical' ? '●' : '▲'
    const when = it.carried
      ? tt(`기간 전(${krDateTime(it.at)})부터 지속`, `ongoing since ${krDateTime(it.at)}`)
      : tt(`${krDateTime(it.at)} 발생`, `from ${krDateTime(it.at)}`)
    const rec = fixed(it) ? tt(`${krDateTime(it.recoveredAt)} 복구`, `recovered ${krDateTime(it.recoveredAt)}`) : tt('미복구', 'not recovered')
    return `${mark} ${esc(tt(it.text.ko, it.text.en))} — ${when}, ${rec}${it.count > 1 ? tt(` (${nf(it.count)}회)`, ` (${nf(it.count)} times)`) : ''}`
  }
  const head = [tt('연번', 'No.'), tt('서버', 'Server'), tt('노드', 'Node'), tt('판정', 'Status'), tt('보고 기간 중 이상 내역', 'Issues during the period')]
  if (x.live) head.push(tt('현재 상태', 'Now'))
  return out + table(
    head,
    x.servers.map((h, i) => {
      // 판정: 기간 말까지 복구되지 않은 이상 중 가장 나쁜 것 (기간 중 있었지만 모두 복구됐으면 주의, 없으면 양호)
      const inc = h.incidents || []
      const open = inc.filter(it => !fixed(it))
      const cls = open.some(it => it.severity === 'critical') ? 'crit' : inc.length ? 'warn' : 'ok'
      const row = [nf(i + 1), esc(h.name), esc(h.node || '-'), badge({ label: lvLabel(cls), cls }), inc.length ? inc.map(line).join('<br>') : tt('없음', 'None')]
      if (x.live) {
        const ncls = !h.checked ? '' : h.alarms.some(a => a.severity === 'critical') ? 'crit' : h.alarms.length ? 'warn' : 'ok'
        row.push(ncls ? badge({ label: lvLabel(ncls), cls: ncls }) : '-')
      }
      return row
    }),
    { unit: tt('대, 건', 'count'), align: x.live ? ['c', 'c', 'c', 'c', '', 'c'] : ['c', 'c', 'c', 'c', ''] },
  )
}

function nodeTable(d) {
  const th = d.thresholds
  return table(
    [tt('연번', 'No.'), tt('클러스터', 'Cluster'), tt('노드', 'Node'), tt('상태', 'State'), tt('CPU(코어)', 'CPU (cores)'), tt('메모리', 'Memory'), tt('가상서버', 'VMs'), tt('CPU 평균/최대(%)', 'CPU avg/peak (%)'), tt('메모리 평균/최대(%)', 'Mem. avg/peak (%)'), tt('가동 시간', 'Uptime'), tt('판정', 'Status')],
    d.nodes.map((n, i) => {
      const g = n.status !== 'online' ? { label: lvLabel('crit'), cls: 'crit' } : grade(Math.max(n.cpuMax ?? n.cpuNow ?? 0, n.memMax ?? n.memNow ?? 0), th)
      return [
        nf(i + 1), esc(n.cluster), esc(n.node), n.status === 'online' ? tt('정상', 'Online') : `<span class="g crit">${tt('중단', 'Offline')}</span>`,
        nf(n.cpuCores), bytes(n.memTotal), nf(n.vms),
        `${pct(n.cpuAvg ?? n.cpuNow)} / ${pct(n.cpuMax ?? n.cpuNow)}`,
        `${pct(n.memAvg ?? n.memNow)} / ${pct(n.memMax ?? n.memNow)}`,
        days(n.uptime), badge(g),
      ]
    }),
    { unit: tt('대, %', 'count, %'), align: ['c', 'c', 'c', 'c', 'r', 'r', 'r', 'c', 'c', 'r', 'c'] },
  )
}

function storageTable(d) {
  const th = d.thresholds
  return table(
    [tt('연번', 'No.'), tt('클러스터', 'Cluster'), tt('저장소', 'Storage'), tt('유형', 'Type'), tt('범위', 'Scope'), tt('전체 용량', 'Capacity'), tt('사용량', 'Used'), tt('여유', 'Free'), tt('사용률(%)', 'Usage (%)'), tt('판정', 'Status')],
    d.storages.map((st, i) => [
      nf(i + 1), esc(st.cluster), esc(st.name), esc(st.type), esc(scopeLabel(st.scope)), bytes(st.total), bytes(st.used), bytes(st.total - st.used), pbar(st.pct, th), badge(grade(st.pct, th)),
    ]),
    { unit: 'GB·TB, %', align: ['c', 'c', 'c', 'c', 'c', 'r', 'r', 'r', 'r', 'c'] },
  )
}

const summaryBox = lines => `<div class="summary"><div class="ttl">${tt('보고 요지', 'Summary')}</div>
${lines.map(x => `<p>${b1()} ${x}</p>`).join('\n')}
</div>`
const attach = (n, title, inner) => `<div class="attach"><div class="attach-ttl"><span class="tag">${tt(`붙임 ${n}`, `Appendix ${n}`)}</span>${title}</div>
${inner}</div>`

// ---------- 보고서 종류별 ----------
function renderOps(d) {
  const s = summarize(d)
  const t = typeText('ops', LANG).title
  const b = d.backups
  const body = `
${kpis([
    { k: tt('종합 판정', 'Overall'), v: s.overall.label, st: s.overall.cls, s: tt(`위험 ${nf(s.crit)}건 · 주의 ${nf(s.warn)}건`, `${nf(s.crit)} critical · ${nf(s.warn)} caution`) },
    { k: tt('가상서버', 'Virtual servers'), v: nf(s.vms), unit: tt('대', ''), s: tt(`운영 ${nf(s.running)} · 정지 ${nf(s.stopped)}`, `${nf(s.running)} running · ${nf(s.stopped)} stopped`) },
    { k: tt('CPU 평균 사용률', 'Avg. CPU usage'), v: pct(s.cpuAvg), unit: '%', st: grade(s.cpuMax, d.thresholds).cls, s: tt(`최대 ${pct(s.cpuMax)}%`, `peak ${pct(s.cpuMax)}%`) },
    { k: tt('스토리지 사용률', 'Storage usage'), v: pct(s.stPct), unit: '%', st: grade(s.stMaxPct, d.thresholds).cls, s: `${bytes(s.stUsed)} / ${bytes(s.stTotal)}` },
  ])}
${summaryBox(LANG === 'en'
    ? [
        `Overall : ${badge(s.overall)} — ${nf(s.crit)} critical, ${nf(s.warn)} caution`,
        `Scale : ${nf(s.clusters)} cluster(s), ${nf(s.nodes)} node(s) (${nf(s.nodesOnline)} online), ${nf(s.vms)} virtual server(s) (${nf(s.running)} running)`,
        `Resources : average CPU ${pct(s.cpuAvg)}%, average memory ${pct(s.memAvg)}%, storage ${pct(s.stPct)}% used`,
        `Backups : ${b ? `${nf(b.ok)} of ${nf(b.total)} succeeded, ${nf(b.fail)} failed` : 'no data'}`,
      ]
    : [
        `종합 판정 : ${badge(s.overall)} — 위험 ${nf(s.crit)}건, 주의 ${nf(s.warn)}건`,
        `운영 규모 : 클러스터 ${nf(s.clusters)}개, 노드 ${nf(s.nodes)}대(정상 ${nf(s.nodesOnline)}대), 가상서버 ${nf(s.vms)}대(운영 ${nf(s.running)}대)`,
        `자원 사용 : CPU 평균 ${pct(s.cpuAvg)}%, 메모리 평균 ${pct(s.memAvg)}%, 스토리지 ${pct(s.stPct)}% 사용`,
        `백업 : ${b ? `${nf(b.total)}건 중 성공 ${nf(b.ok)}건, 실패 ${nf(b.fail)}건` : '정보 없음'}`,
      ])}
${h2(0, tt('개 요', 'Overview'))}
${sectionOverview(d, s)}
${h2(1, tt('운영 현황', 'Operating Status'))}
${l1(`<b>${tt('인프라 구성 현황', 'Infrastructure')}</b>`)}
${compositionTable(s)}
${l1(`<b>${tt('자원 사용 현황', 'Resource usage')}</b>`)}
${usageTable(d, s)}
${l1(`<b>${tt('백업 수행 현황', 'Backups')}</b>`)}
${backupPart(d)}
${d.hardware ? `${l1(`<b>${tt('하드웨어 상태 (BMC)', 'Hardware health (BMC)')}</b>`)}
${hardwarePart(d)}` : ''}
${d.externalChecks ? `${l1(`<b>${tt('외부 시스템 점검 (AI)', 'External system checks (AI)')}</b>`)}
${externalPart(d)}` : ''}
${h2(2, tt('점검 결과', 'Findings'))}
${issuesPart(s)}
${h2(3, tt('조치 계획', 'Action Plan'))}
${planPart(s)}
${endMark()}

${attach(1, tt('노드(물리 서버)별 운영 현황', 'Status by node (physical server)'), nodeTable(d))}
${attach(2, tt('스토리지별 사용 현황', 'Usage by storage'), storageTable(d))}`
  return doc(d, t, body)
}

function renderResource(d) {
  const s = summarize(d)
  const t = typeText('resource', LANG).title
  const top = [...d.vms].filter(v => !v.template).sort((a, b) => (b.mem || 0) - (a.mem || 0)).slice(0, 10)
  const need = []
  if ((s.cpuMax ?? 0) >= d.thresholds.warn) need.push('CPU')
  if ((s.memMax ?? 0) >= d.thresholds.warn || (s.memAllocRatio ?? 0) > 100) need.push(tt('메모리', 'memory'))
  if ((s.stMaxPct ?? 0) >= d.thresholds.warn) need.push(tt('스토리지', 'storage'))
  const needTxt = need.join(tt('·', ', '))
  const body = `
${kpis([
    { k: tt('CPU 사용률(최대)', 'CPU usage (peak)'), v: pct(s.cpuMax), unit: '%', st: grade(s.cpuMax, d.thresholds).cls, s: tt(`평균 ${pct(s.cpuAvg)}% · 할당률 ${pct(s.vcpuRatio)}%`, `avg ${pct(s.cpuAvg)}% · alloc. ${pct(s.vcpuRatio)}%`) },
    { k: tt('메모리 사용률(최대)', 'Memory usage (peak)'), v: pct(s.memMax), unit: '%', st: grade(s.memMax, d.thresholds).cls, s: tt(`평균 ${pct(s.memAvg)}% · 할당률 ${pct(s.memAllocRatio)}%`, `avg ${pct(s.memAvg)}% · alloc. ${pct(s.memAllocRatio)}%`) },
    { k: tt('스토리지 사용률', 'Storage usage'), v: pct(s.stPct), unit: '%', st: grade(s.stMaxPct, d.thresholds).cls, s: `${bytes(s.stUsed)} / ${bytes(s.stTotal)}` },
    { k: tt('증설 검토', 'Expansion'), v: need.length ? tt('필요', 'Needed') : tt('불필요', 'Not needed'), st: need.length ? 'warn' : 'ok', s: need.length ? needTxt : tt('현 자원으로 운영 가능', 'Current capacity is sufficient') },
  ])}
${summaryBox(LANG === 'en'
    ? [
        `CPU : ${nf(s.cpuCores)} physical cores / ${nf(s.vcpuAlloc)} vCPU allocated (${pct(s.vcpuRatio)}%), usage avg ${pct(s.cpuAvg)}% · peak ${pct(s.cpuMax)}%`,
        `Memory : ${bytes(s.memTotal)} physical / ${bytes(s.memAlloc)} allocated (${pct(s.memAllocRatio)}%), usage avg ${pct(s.memAvg)}% · peak ${pct(s.memMax)}%`,
        `Storage : ${bytes(s.stUsed)} of ${bytes(s.stTotal)} used (${pct(s.stPct)}%)`,
        `Opinion : ${need.length ? `<span class="g warn">review ${needTxt} expansion</span>` : '<span class="g ok">current capacity is sufficient</span>'}`,
      ]
    : [
        `CPU : 물리 ${nf(s.cpuCores)}코어 / 할당 ${nf(s.vcpuAlloc)} vCPU(할당률 ${pct(s.vcpuRatio)}%), 사용률 평균 ${pct(s.cpuAvg)}%·최대 ${pct(s.cpuMax)}%`,
        `메모리 : 물리 ${bytes(s.memTotal)} / 할당 ${bytes(s.memAlloc)}(할당률 ${pct(s.memAllocRatio)}%), 사용률 평균 ${pct(s.memAvg)}%·최대 ${pct(s.memMax)}%`,
        `스토리지 : 전체 ${bytes(s.stTotal)} 중 ${bytes(s.stUsed)} 사용(${pct(s.stPct)}%)`,
        `검토 의견 : ${need.length ? `<span class="g warn">${needTxt} 증설 검토 필요</span>` : '<span class="g ok">현 자원으로 운영 가능</span>'}`,
      ])}
${h2(0, tt('개 요', 'Overview'))}
${sectionOverview(d, s)}
${h2(1, tt('자원 사용 총괄', 'Resource Usage Summary'))}
${usageTable(d, s)}
${h2(2, tt('노드별 사용 현황', 'Usage by Node'))}
${nodeTable(d)}
${h2(3, tt('스토리지 사용 현황', 'Storage Usage'))}
${storageTable(d)}
${h2(4, tt('자원 할당 상위 가상서버', 'Top Virtual Servers by Allocation'))}
${table(
    [tt('순위', 'Rank'), tt('가상서버', 'Virtual server'), 'ID', tt('노드', 'Node'), tt('상태', 'State'), 'vCPU', tt('메모리(GB)', 'Memory (GB)'), tt('디스크(GB)', 'Disk (GB)')],
    top.map((v, i) => [nf(i + 1), esc(v.name), nf(v.vmid), esc(v.node), v.status === 'running' ? tt('운영', 'Running') : tt('정지', 'Stopped'), nf(v.cpus), gib(v.mem), gib(v.disk)]),
    { unit: tt('개, GB', 'count, GB'), align: ['c', '', 'c', 'c', 'c', 'r', 'r', 'r'] },
  )}
${note(tt('메모리 할당 기준 상위 10대', 'Top 10 by allocated memory'))}
${h2(5, tt('증설 검토 의견', 'Expansion Review'))}
${need.length
    ? l1(tt(`<b>${needTxt}</b> 자원이 판정 기준(${d.thresholds.warn}%)을 넘어 증설 검토 필요`, `<b>${needTxt}</b> exceeded the criterion (${d.thresholds.warn}%) — expansion should be reviewed`)) +
      l2(tt('사용 추이를 1~3개월 추가 관찰 후 차년도 정보화 예산 반영 여부 결정', 'Observe the trend for another 1–3 months, then decide on next year’s budget')) +
      l2(tt('단기적으로 장기 미사용(정지) 가상서버 정리 및 자원 재배치 시행', 'In the short term, remove long-unused (stopped) virtual servers and rebalance resources'))
    : l1(tt('전 자원이 판정 기준 이내로 <b>현 자원으로 운영 가능</b>', 'All resources are within the criteria — <b>current capacity is sufficient</b>')) +
      l2(tt('월 1회 사용 추이 점검 지속', 'Keep reviewing usage monthly'))}
${issuesPart(s)}
${endMark()}`
  return doc(d, t, body)
}

function renderAsset(d) {
  const s = summarize(d)
  const t = typeText('asset', LANG).title
  const vms = [...d.vms].filter(v => !v.template).sort((a, b) => (a.cluster + a.node).localeCompare(b.cluster + b.node) || a.vmid - b.vmid)
  const byCluster = new Map()
  for (const v of vms) {
    const k = v.cluster
    const c = byCluster.get(k) || { n: 0, run: 0, cpu: 0, mem: 0, disk: 0 }
    c.n++; if (v.status === 'running') c.run++
    c.cpu += v.cpus || 0; c.mem += v.mem || 0; c.disk += v.disk || 0
    byCluster.set(k, c)
  }
  const totalDisk = vms.reduce((a, v) => a + (v.disk || 0), 0)
  const rows = [...byCluster.entries()].map(([k, c]) => [esc(k), nf(c.n), nf(c.run), nf(c.n - c.run), nf(c.cpu), gib(c.mem), gib(c.disk)])
  rows.push({ cls: 'total', cells: [tt('합계', 'Total'), nf(vms.length), nf(s.running), nf(s.stopped), nf(s.vcpuAlloc), gib(s.memAlloc), gib(totalDisk)] })
  const multiCluster = byCluster.size > 1
  const oneCluster = esc([...byCluster.keys()][0] || '-')
  const body = `
${kpis([
    { k: tt('가상서버', 'Virtual servers'), v: nf(vms.length), unit: tt('대', ''), s: tt(`VM ${nf(s.qemu)} · 컨테이너 ${nf(s.lxc)}`, `VM ${nf(s.qemu)} · containers ${nf(s.lxc)}`) },
    { k: tt('운영 / 정지', 'Running / stopped'), v: `${nf(s.running)} / ${nf(s.stopped)}`, unit: tt('대', '') },
    { k: tt('vCPU 할당', 'vCPU allocated'), v: nf(s.vcpuAlloc), unit: tt('개', ''), s: tt(`물리 ${nf(s.cpuCores)}코어`, `${nf(s.cpuCores)} physical cores`) },
    { k: tt('메모리 · 디스크 할당', 'Memory · disk allocated'), v: bytes(s.memAlloc), s: tt(`디스크 ${bytes(totalDisk)}`, `disk ${bytes(totalDisk)}`) },
  ])}
${h2(0, tt('현황 총괄', 'Summary'))}
${l1(tt(
    `기준일 ${krDate(d.generatedAt)} 현재 가상서버 <b>${nf(vms.length)}대</b> (VM ${nf(s.qemu)}대, 컨테이너 ${nf(s.lxc)}대) 운영 중`,
    `As of ${krDate(d.generatedAt)}: <b>${nf(vms.length)}</b> virtual server(s) (${nf(s.qemu)} VM, ${nf(s.lxc)} container)`,
  ))}
${table([tt('클러스터', 'Cluster'), tt('가상서버', 'Virtual servers'), tt('운영', 'Running'), tt('정지', 'Stopped'), 'vCPU', tt('메모리(GB)', 'Memory (GB)'), tt('디스크(GB)', 'Disk (GB)')], rows, { unit: tt('대, 개, GB', 'count, GB'), align: ['c', 'r', 'r', 'r', 'r', 'r', 'r'] })}
${h2(1, tt('가상서버 목록', 'Virtual Server List'))}
${table(
    [tt('연번', 'No.'), tt('가상서버명', 'Name'), 'ID', multiCluster ? tt('클러스터 / 노드', 'Cluster / node') : tt('노드', 'Node'), tt('유형', 'Type'), tt('상태', 'State'), 'vCPU', tt('메모리(GB)', 'Mem. (GB)'), tt('디스크(GB)', 'Disk (GB)'), tt('비고', 'Tags')],
    vms.map((v, i) => [
      nf(i + 1), esc(v.name), nf(v.vmid), esc(multiCluster ? `${v.cluster} / ${v.node}` : v.node), v.type === 'lxc' ? 'CT' : 'VM',
      v.status === 'running' ? tt('운영', 'Running') : `<span class="g warn">${tt('정지', 'Stopped')}</span>`, nf(v.cpus), gib(v.mem), gib(v.disk), esc(String(v.tags || '').replace(/;/g, ', ')),
    ]),
    { unit: tt('개, GB', 'count, GB'), align: ['c', 'nm', 'c', 'c', 'c', 'c', 'r', 'r', 'r', ''], cls: 'dense' },
  )}
${note(tt(
    `유형 VM: 가상머신, CT: 컨테이너 / 디스크는 할당 용량 기준 / 비고란은 가상서버 태그${multiCluster ? '' : ` / 클러스터: ${oneCluster}`}`,
    `Type VM: virtual machine, CT: container / disk is the allocated size / tags are the virtual server tags${multiCluster ? '' : ` / cluster: ${oneCluster}`}`,
  ))}
${endMark()}`
  return doc(d, t, body)
}

/** d: collect.ts 의 ReportData (+ locale: 'ko' | 'en') */
export function renderReportHtml(d) {
  LANG = d.locale === 'en' ? 'en' : 'ko'
  try {
    if (d.type === 'resource') return renderResource(d)
    if (d.type === 'asset') return renderAsset(d)
    return renderOps(d)
  } finally {
    LANG = 'ko'
  }
}

export function reportTitle(d) {
  return typeText(d.type, d.locale === 'en' ? 'en' : 'ko').title
}

export function reportFileName(d, ext = 'pdf') {
  const k = kst(d.generatedAt)
  const ymd = `${k.getUTCFullYear()}${String(k.getUTCMonth() + 1).padStart(2, '0')}${String(k.getUTCDate()).padStart(2, '0')}`
  const name = d.locale === 'en' ? reportTitle(d).replace(/\s+/g, '_') : reportTitle(d).replace(/[\s()]/g, '')
  return `${name}_${ymd}.${ext}`
}
