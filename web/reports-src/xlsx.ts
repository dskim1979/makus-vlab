// MOAVI Desk 한국형 보고서 → XLSX(엑셀 통합 문서, Office Open XML)
//
//  PDF·한글·워드와 같은 보고서 HTML(html.js)을 읽어 옮김 → 양식 수정은 html.js 한 곳에서
//  시트 구성: 첫 시트 '개요'(제목·작성 정보·핵심 지표·요약·본문 문장, 표 자리에는 해당 시트로 가는 링크)
//            + 표마다 시트 하나(시트 이름 = 그 표의 장 제목) — 머리글 행 고정·자동 필터, A4 폭 맞춤 인쇄
//  숫자·비율(1,234 · 12.5%)은 숫자 칸으로 넣어 합계·정렬·그래프에 바로 쓸 수 있게, 판정(정상·주의·위험)은 글자색
//  Microsoft Excel 2010 이후·한컴오피스 한셀·LibreOffice 에서 열림
//
// 원본: 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 (LICENSE·NOTICE)
// 빌드: web/reports-src/build.sh → static/js/makus-reports.js

import { clean, displayWidth, gradeOf, has, parse, textOf, xmlEsc as x, zip, type Node, enc } from "./htmlDoc"

// ---------------------------------------------------------------- 칸 모양 (필요한 조합만 styles.xml 에 등록)
type FontKey = "base" | "bold" | "th" | "title" | "h2" | "kicker" | "meta" | "note" | "ok" | "warn" | "crit" | "cls" | "link" | "kpiV"
const FONTS: Record<FontKey, { sz: number; color: string; bold?: boolean; underline?: boolean }> = {
  base: { sz: 10, color: "FF1D2433" },
  bold: { sz: 10, color: "FF1D2433", bold: true },
  th: { sz: 10, color: "FFFFFFFF", bold: true },
  title: { sz: 16, color: "FF0F1D3D", bold: true },
  h2: { sz: 12, color: "FF0F1D3D", bold: true },
  kicker: { sz: 9, color: "FF1668E3", bold: true },
  meta: { sz: 9, color: "FF3C4658" },
  note: { sz: 9, color: "FF5A6477" },
  ok: { sz: 10, color: "FF1A7F37", bold: true },
  warn: { sz: 10, color: "FFB45309", bold: true },
  crit: { sz: 10, color: "FFC1121F", bold: true },
  cls: { sz: 10, color: "FFB00020", bold: true },
  link: { sz: 10, color: "FF1668E3", underline: true },
  kpiV: { sz: 14, color: "FF0F1D3D", bold: true },
}
type FillKey = "none" | "th" | "total" | "kpi" | "box"
const FILL_COLORS: Record<Exclude<FillKey, "none">, string> = { th: "FF1B2F5B", total: "FFE8EEF8", kpi: "FFF3F6FB", box: "FFF4F6FA" }
type Style = { font?: FontKey; fill?: FillKey; border?: boolean; numFmt?: string; h?: "left" | "center" | "right"; indent?: number; wrap?: boolean }

const FONT_LIST = Object.keys(FONTS) as FontKey[]
const FILL_LIST: FillKey[] = ["none", "th", "total", "kpi", "box"]

class Styles {
  private xfs: string[] = []
  private ids = new Map<string, number>()
  private fmts = new Map<string, number>()
  constructor() { this.id({}) } // 0 = 기본

  id(s: Style) {
    const key = JSON.stringify(s)
    const hit = this.ids.get(key)
    if (hit !== undefined) return hit
    let fmtId = 0
    if (s.numFmt) {
      if (!this.fmts.has(s.numFmt)) this.fmts.set(s.numFmt, 164 + this.fmts.size)
      fmtId = this.fmts.get(s.numFmt)!
    }
    const font = FONT_LIST.indexOf(s.font || "base")
    // 채우기 0·1 은 엑셀 예약(없음·gray125) → 우리 목록은 2 부터
    const fill = s.fill && s.fill !== "none" ? FILL_LIST.indexOf(s.fill) + 1 : 0
    const align = s.h || s.indent || s.wrap
      ? `<alignment${s.h ? ` horizontal="${s.h}"` : ""} vertical="center"${s.indent ? ` indent="${s.indent}"` : ""}${s.wrap ? ` wrapText="1"` : ""}/>`
      : `<alignment vertical="center"/>`
    this.xfs.push(`<xf numFmtId="${fmtId}" fontId="${font}" fillId="${fill}" borderId="${s.border ? 1 : 0}" xfId="0"`
      + `${fmtId ? ` applyNumberFormat="1"` : ""} applyFont="1"${fill ? ` applyFill="1"` : ""}${s.border ? ` applyBorder="1"` : ""} applyAlignment="1">${align}</xf>`)
    const id = this.xfs.length - 1
    this.ids.set(key, id)
    return id
  }

  xml() {
    const numFmts = [...this.fmts].map(([code, id]) => `<numFmt numFmtId="${id}" formatCode="${x(code)}"/>`).join("")
    const fonts = FONT_LIST.map(k => {
      const f = FONTS[k]
      return `<font>${f.bold ? "<b/>" : ""}${f.underline ? "<u/>" : ""}<sz val="${f.sz}"/><color rgb="${f.color}"/><name val="맑은 고딕"/><family val="3"/><charset val="129"/></font>`
    }).join("")
    const fills = `<fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>`
      + FILL_LIST.slice(1).map(k => `<fill><patternFill patternType="solid"><fgColor rgb="${FILL_COLORS[k as Exclude<FillKey, "none">]}"/><bgColor indexed="64"/></patternFill></fill>`).join("")
    const side = (n: string) => `<${n} style="thin"><color rgb="FF8A93A3"/></${n}>`
    const borders = `<border><left/><right/><top/><bottom/><diagonal/></border><border>${side("left")}${side("right")}${side("top")}${side("bottom")}<diagonal/></border>`
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`
      + (this.fmts.size ? `<numFmts count="${this.fmts.size}">${numFmts}</numFmts>` : "")
      + `<fonts count="${FONT_LIST.length}">${fonts}</fonts><fills count="${FILL_LIST.length + 1}">${fills}</fills>`
      + `<borders count="2">${borders}</borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>`
      + `<cellXfs count="${this.xfs.length}">${this.xfs.join("")}</cellXfs>`
      + `<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`
  }
}

// ---------------------------------------------------------------- 시트
type CellV = { v: string | number; s: number }
class Sheet {
  rows: (CellV | null)[][] = []
  heights = new Map<number, number>()
  links: { ref: string; target: string; text: string }[] = []
  freezeRow = 0
  filter: string | null = null
  minWidths: number[] = []
  constructor(public name: string) {}
  add(cells: (CellV | null)[], height?: number) {
    this.rows.push(cells)
    if (height) this.heights.set(this.rows.length, height)
    return this.rows.length // 1부터
  }
}

const colName = (i: number) => { let s = ""; i += 1; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26) } return s }

/** 숫자처럼 보이는 글자 → 숫자 칸 (천 단위 쉼표·%만, 단위가 붙은 값은 글자 그대로) */
function asNumber(t: string): { n: number; fmt: string } | null {
  const s = t.replace(/\s+/g, "")
  const m = /^([-+−]?)(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?(%?)$/.exec(s)
  if (!m) return null
  const dec = m[3] || ""
  const n = Number(`${m[1] === "−" ? "-" : m[1]}${m[2].replace(/,/g, "")}${dec ? `.${dec}` : ""}`)
  if (!Number.isFinite(n)) return null
  // 앞자리 0(코드·번호 '007')은 글자로 둠
  if (/^0\d/.test(m[2])) return null
  const decFmt = dec ? `.${"0".repeat(Math.min(dec.length, 4))}` : ""
  if (m[4]) return { n: n / 100, fmt: `0${decFmt}%` }
  return { n, fmt: m[2].includes(",") || n >= 1000 ? `#,##0${decFmt}` : `0${decFmt}` }
}

/** 표 칸 글자 (사용률 막대 등 장식은 뺌) */
function cellText(n: Node): string {
  const walk = (k: Node): string => (k.tag === "#text" ? k.text || "" : has(k, "bar") ? "" : k.tag === "br" ? " " : k.kids.map(walk).join(""))
  return clean(walk(n))
}

function sheetName(base: string, used: Set<string>) {
  const root = clean(base.replace(/[\[\]:*?/\\]/g, " ")).replace(/^'+|'+$/g, "").slice(0, 31).trim() || "Sheet"
  const taken = (v: string) => [...used].some(u => u.toLowerCase() === v.toLowerCase())
  let name = root
  for (let i = 2; taken(name); i++) {
    const suffix = ` (${i})`
    name = `${root.slice(0, 31 - suffix.length).trim()}${suffix}`
  }
  used.add(name)
  return name
}

// ---------------------------------------------------------------- 보고서 → 시트들
function build(root: Node, en: boolean, st: Styles) {
  const used = new Set<string>()
  const overview = new Sheet(sheetName(en ? "Overview" : "개요", used))
  overview.minWidths = [16, 16, 16, 16]
  const sheets: Sheet[] = [overview]
  let section = ""  // 지금 장 제목 (표 시트 이름)
  let sectionNo = "" // 장 번호 (Ⅱ)
  let sub = ""      // 장 안의 소제목 (□ 가상서버 운영 현황) — 한 장에 표가 여럿일 때 시트 이름
  let unit = ""     // 바로 앞의 단위 표시 "(단위: GB)"
  const text = (v: string, s: Style) => ({ v, s: st.id(s) })
  const line = (v: string, s: Style, height?: number) => { if (v) overview.add([text(v, s)], height) }

  const addTable = (t: Node) => {
    const head = t.kids.find(k => k.tag === "thead")
    const headCells = head ? (head.kids.find(k => k.tag === "tr")?.kids || []).filter(k => k.tag === "th") : []
    const bodyRows = (t.kids.find(k => k.tag === "tbody")?.kids || t.kids).filter(k => k.tag === "tr")
    if (!headCells.length && !bodyRows.length) return
    const title = sub ? (sectionNo ? `${sectionNo}. ${sub}` : sub) : section
    const sh = new Sheet(sheetName(title || (en ? "Table" : "표"), used))
    sheets.push(sh)
    sh.add([text(sub && section ? `${section} · ${sub}` : title || sh.name, { font: "h2" })], 22)
    sh.add(unit ? [text(unit, { font: "note" })] : [])
    unit = ""
    if (headCells.length) {
      sh.add(headCells.map(th => text(cellText(th), { font: "th", fill: "th", border: true, h: "center", wrap: true })), 30)
      sh.freezeRow = sh.rows.length
    }
    const first = sh.rows.length + 1
    let cols = headCells.length
    for (const tr of bodyRows) {
      const tds = tr.kids.filter(k => k.tag === "td" || k.tag === "th")
      cols = Math.max(cols, tds.length)
      const total = has(tr, "total")
      sh.add(tds.map(td => {
        const t = cellText(td)
        const g = gradeOf(td)
        const font: FontKey = g || (total ? "bold" : "base")
        const fill: FillKey = total ? "total" : "none"
        const h = has(td, "c") ? "center" : has(td, "r") ? "right" : undefined
        const num = asNumber(t)
        if (num) return { v: num.n, s: st.id({ font, fill, border: true, numFmt: num.fmt, h: h === "center" ? "center" : "right" }) }
        return text(t, { font, fill, border: true, h })
      }))
    }
    if (headCells.length && sh.rows.length >= first) sh.filter = `A${first - 1}:${colName(cols - 1)}${sh.rows.length}`
    // 개요 시트에 표 자리 표시 + 시트로 가는 링크
    const r = overview.add([text(en ? `▶ Table: see sheet '${sh.name}'` : `▶ 표: '${sh.name}' 시트`, { font: "link" })])
    overview.links.push({ ref: `A${r}`, target: sh.name, text: sh.name })
  }

  const addKpi = (t: Node) => {
    const tds = (t.kids.find(k => k.tag === "tr") || t.kids.find(k => k.tag === "tbody")?.kids.find(k => k.tag === "tr"))?.kids.filter(k => k.tag === "td") || []
    for (const td of tds) {
      const part = (c: string) => td.kids.find(k => has(k, c))
      const k = part("k"), v = part("v"), s = part("s")
      const lv = has(td, "st-crit") ? "crit" : has(td, "st-warn") ? "warn" : has(td, "st-ok") ? "ok" : ""
      const vt = v ? clean(textOf(v)) : ""
      const num = asNumber(vt)
      overview.add([
        text(k ? clean(textOf(k)) : "", { font: "note", fill: "kpi", border: true }),
        num ? { v: num.n, s: st.id({ font: lv || "kpiV", fill: "kpi", border: true, numFmt: num.fmt, h: "right" }) } : text(vt, { font: lv || "kpiV", fill: "kpi", border: true, h: "right" }),
        text(s ? clean(textOf(s)) : "", { font: "note", fill: "kpi", border: true }),
      ], 22)
    }
    overview.add([])
  }

  const walk = (nodes: Node[]) => {
    for (const n of nodes) {
      if (n.tag === "#text" || n.tag === "style" || n.tag === "script") continue
      if (has(n, "head")) {
        const kicker = n.kids.find(k => has(k, "kicker"))
        const h1 = n.kids.find(k => k.tag === "h1")
        const info = n.kids.find(k => has(k, "info"))
        if (kicker) line(clean(textOf(kicker)), { font: "kicker" })
        if (h1) line(clean(textOf(h1)), { font: "title" }, 28)
        // "보고 기간 2026. 9. 1. ~" — 굵은 이름 뒤에 한 칸
        if (info) info.kids.filter(k => k.tag === "span").forEach(sp => line(clean(sp.kids.map(k => (k.tag === "b" || k.tag === "strong" ? `${textOf(k)} ` : textOf(k))).join("")), { font: "meta" }))
        overview.add([])
      } else if (n.tag === "table" && has(n, "kpi")) {
        addKpi(n)
      } else if (n.tag === "table") {
        addTable(n)
      } else if (has(n, "summary")) {
        for (const k of n.kids) {
          if (has(k, "ttl")) line(clean(textOf(k)), { font: "bold", fill: "box" })
          else if (k.tag === "p") line(clean(textOf(k)), { fill: "box" })
        }
        overview.add([])
      } else if (n.tag === "h2") {
        const no = n.kids.find(k => has(k, "no"))
        const rest = clean(n.kids.filter(k => k !== no).map(textOf).join(""))
        section = `${no ? `${clean(textOf(no))}. ` : ""}${rest}`
        sectionNo = no ? clean(textOf(no)) : ""
        sub = ""
        overview.add([])
        line(section, { font: "h2" }, 22)
      } else if (n.tag === "p") {
        // 문장은 판정 색을 넣지 않음 (한 문장에 양호·주의·위험이 섞이면 칸 전체가 한 색이 됨)
        const t = clean(textOf(n))
        if (has(n, "l1")) {
          line(t, { font: "base", indent: 1 })
          // 짧은 제목형 문장만 (숫자가 든 결과 문장은 장 제목을 씀)
          const head = t.replace(/^[□■○●◦◇◆▶·\-–—*\s]+/, "").trim()
          sub = head.length <= 24 && !/\d/.test(head) ? head : ""
        }
        else if (has(n, "l2")) line(t, { font: "base", indent: 2 })
        else if (has(n, "l3")) line(t, { font: "base", indent: 3 })
        else if (has(n, "note")) line(t, { font: "note", indent: 1 })
        else if (has(n, "end")) line(t, { font: "bold" })
        else line(t, { font: "base" })
      } else if (has(n, "unit")) {
        unit = clean(textOf(n))
      } else if (has(n, "attach-ttl")) {
        const tag = n.kids.find(k => has(k, "tag"))
        const rest = clean(n.kids.filter(k => k !== tag).map(textOf).join(""))
        section = `${tag ? `[${clean(textOf(tag))}] ` : ""}${rest}`
        sectionNo = ""
        sub = ""
        overview.add([])
        line(section, { font: "h2" }, 22)
      } else if (has(n, "footer-note")) {
        overview.add([])
        line(clean(textOf(n)), { font: "note" })
      } else {
        walk(n.kids)
      }
    }
  }
  walk(root.kids)
  return sheets
}

// 열 너비: 표 칸 글자 폭 기준 (개요의 긴 문장은 옆 칸으로 넘쳐 보이므로 너비에 넣지 않음)
function colWidths(sh: Sheet, isOverview: boolean) {
  const w: number[] = [...sh.minWidths]
  sh.rows.forEach((cells, r) => {
    if (isOverview && cells.length <= 1) return
    if (!isOverview && r < 2) return // 표 제목·단위
    cells.forEach((c, i) => {
      if (!c) return
      const len = typeof c.v === "number" ? String(c.v).length + 3 : displayWidth(String(c.v))
      w[i] = Math.max(w[i] || 6, Math.min(60, len + 2))
    })
  })
  return w
}

function sheetXml(sh: Sheet, isOverview: boolean, cls: string) {
  const widths = colWidths(sh, isOverview)
  const rows = sh.rows.map((cells, i) => {
    const r = i + 1
    const ht = sh.heights.get(r)
    const cs = cells.map((c, j) => {
      if (!c || c.v === "") return c ? `<c r="${colName(j)}${r}" s="${c.s}"/>` : ""
      if (typeof c.v === "number") return `<c r="${colName(j)}${r}" s="${c.s}"><v>${c.v}</v></c>`
      return `<c r="${colName(j)}${r}" s="${c.s}" t="inlineStr"><is><t xml:space="preserve">${x(c.v)}</t></is></c>`
    }).join("")
    return `<row r="${r}"${ht ? ` ht="${ht}" customHeight="1"` : ""}>${cs}</row>`
  }).join("")
  const lastCol = colName(Math.max(0, widths.length - 1))
  const pane = sh.freezeRow
    ? `<pane ySplit="${sh.freezeRow}" topLeftCell="A${sh.freezeRow + 1}" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A${sh.freezeRow + 1}" sqref="A${sh.freezeRow + 1}"/>`
    : ""
  const links = sh.links.length
    ? `<hyperlinks>${sh.links.map(l => `<hyperlink ref="${l.ref}" location="'${x(l.target.replace(/'/g, "''"))}'!A1" display="${x(l.text)}"/>`).join("")}</hyperlinks>`
    : ""
  // 머리글 오른쪽 보안 등급, 바닥글 가운데 쪽 번호 "- 1 -"
  const hf = `<headerFooter>${cls ? `<oddHeader>&amp;R&amp;"맑은 고딕,Bold"&amp;KB00020${x(cls)}</oddHeader>` : ""}<oddFooter>&amp;C- &amp;P -</oddFooter></headerFooter>`
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`
    + `<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr><dimension ref="A1:${lastCol}${Math.max(1, sh.rows.length)}"/>`
    + `<sheetViews><sheetView workbookViewId="0" showGridLines="${isOverview ? 0 : 1}"${isOverview ? ` tabSelected="1"` : ""}>${pane}</sheetView></sheetViews>`
    + `<sheetFormatPr defaultRowHeight="17"/>`
    + `<cols>${widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join("")}</cols>`
    + `<sheetData>${rows}</sheetData>`
    + (sh.filter ? `<autoFilter ref="${sh.filter}"/>` : "")
    + links
    + `<pageMargins left="0.67" right="0.67" top="0.79" bottom="0.71" header="0.31" footer="0.31"/>`
    + `<pageSetup paperSize="9" orientation="portrait" fitToWidth="1" fitToHeight="0"/>${hf}</worksheet>`
}

// ---------------------------------------------------------------- 공개 함수
export function reportHtmlToXlsx(html: string, opts: { title: string; classification?: string; author?: string; locale?: "ko" | "en" }) {
  const st = new Styles()
  const sheets = build(parse(html), opts.locale === "en", st)
  const cls = opts.classification || ""

  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`
    + `<bookViews><workbookView activeTab="0"/></bookViews><sheets>`
    + sheets.map((s, i) => `<sheet name="${x(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("")
    + `</sheets>`
    + (sheets.some(s => s.filter)
      ? `<definedNames>${sheets.map((s, i) => (s.filter
        ? `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">'${x(s.name.replace(/'/g, "''"))}'!$${s.filter.replace(/:/, ":$").replace(/([A-Z]+)(\d+)/g, "$1$$$2")}</definedName>`
        : "")).join("")}</definedNames>`
      : "")
    + `</workbook>`
  const wbRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
    + sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join("")
    + `<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`
  const types = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`
    + `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>`
    + `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`
    + sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join("")
    + `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`
    + `<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`
    + `<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`
  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
    + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>`
    + `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`
    + `<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`
  const iso = new Date().toISOString().replace(/\.\d+Z$/, "Z")
  const core = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
    + `<dc:title>${x(opts.title)}</dc:title><dc:creator>${x(opts.author || "MOAVI Desk")}</dc:creator><cp:lastModifiedBy>${x(opts.author || "MOAVI Desk")}</cp:lastModifiedBy>`
    + `<dcterms:created xsi:type="dcterms:W3CDTF">${iso}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${iso}</dcterms:modified></cp:coreProperties>`
  const app = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>MOAVI Desk</Application></Properties>`

  return zip([
    { name: "[Content_Types].xml", data: enc(types) },
    { name: "_rels/.rels", data: enc(rootRels) },
    { name: "xl/workbook.xml", data: enc(workbook) },
    { name: "xl/_rels/workbook.xml.rels", data: enc(wbRels) },
    // styles 는 시트를 만든 뒤에 (시트가 쓰는 칸 모양만 등록됨)
    ...sheets.map((s, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, data: enc(sheetXml(s, i === 0, cls)) })),
    { name: "xl/styles.xml", data: enc(st.xml()) },
    { name: "docProps/core.xml", data: enc(core) },
    { name: "docProps/app.xml", data: enc(app) },
  ])
}
