// MAKUS vLAB 한국형 보고서 → DOCX(워드 문서, Office Open XML)
//
//  PDF·한글과 같은 보고서 HTML(html.js)을 읽어 워드 문단·표로 옮김 → 양식 수정은 html.js 한 곳에서
//  모양은 한글 문서(hwpx.ts)와 같게: A4 세로·여백 17mm, 제목·개조식 들여쓰기, 머리글 색 표, 판정 색, 붙임 새 쪽,
//  머리말 오른쪽 보안 등급, 꼬리말 가운데 쪽 번호 "- 1 -". 글꼴은 맑은 고딕 (Windows·Office 기본)
//  Microsoft Word 2010 이후·한컴오피스·LibreOffice 에서 열림
//
// 원본: 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 (LICENSE·NOTICE)
// 빌드: web/reports-src/build.sh → static/js/makus-reports.js

import { clean, displayWidth, has, parse, textOf, xmlEsc as x, zip, type Node, enc } from "./htmlDoc"

// ---------------------------------------------------------------- 모양 정의 (hwpx.ts 의 CHARS 와 같은 값, 크기는 pt)
type CharDef = { pt: number; color: string; bold?: boolean }
const CHARS: Record<string, CharDef> = {
  body: { pt: 11, color: "111111" },
  bodyB: { pt: 11, color: "111111", bold: true },
  title: { pt: 18, color: "0F1D3D", bold: true },
  kicker: { pt: 9, color: "1668E3", bold: true },
  meta: { pt: 9.5, color: "3C4658" },
  metaB: { pt: 9.5, color: "0F1D3D", bold: true },
  h2: { pt: 13, color: "0F1D3D", bold: true },
  tbl: { pt: 9, color: "1D2433" },
  tblB: { pt: 9, color: "1D2433", bold: true },
  th: { pt: 9, color: "FFFFFF", bold: true },
  tblS: { pt: 8, color: "1D2433" },
  tblSB: { pt: 8, color: "1D2433", bold: true },
  thS: { pt: 8, color: "FFFFFF", bold: true },
  note: { pt: 8.5, color: "5A6477" },
  ok: { pt: 9, color: "1A7F37", bold: true },
  warn: { pt: 9, color: "B45309", bold: true },
  crit: { pt: 9, color: "C1121F", bold: true },
  okS: { pt: 8, color: "1A7F37", bold: true },
  warnS: { pt: 8, color: "B45309", bold: true },
  critS: { pt: 8, color: "C1121F", bold: true },
  okL: { pt: 11, color: "1A7F37", bold: true },
  warnL: { pt: 11, color: "B45309", bold: true },
  critL: { pt: 11, color: "C1121F", bold: true },
  kpiV: { pt: 15, color: "0F1D3D", bold: true },
  cls: { pt: 9.5, color: "B00020", bold: true },
  end: { pt: 11, color: "111111", bold: true },
}
type CharKey = keyof typeof CHARS

// 문단: 간격·들여쓰기는 pt (hwpx.ts 의 HWPUNIT ÷ 100), line 은 줄 간격 %
type ParaDef = { align: "left" | "center" | "right" | "both"; left?: number; hanging?: number; before?: number; after?: number; line?: number; keep?: boolean }
const PARAS: Record<string, ParaDef> = {
  left: { align: "left" },
  center: { align: "center" },
  right: { align: "right" },
  title: { align: "left", before: 2, after: 3, line: 130 },
  h2: { align: "left", before: 16, after: 5, keep: true },
  l1: { align: "both", left: 15, hanging: 15, before: 5 },
  l2: { align: "both", left: 30, hanging: 15, before: 1.5 },
  l3: { align: "both", left: 42, hanging: 11, before: 1 },
  note: { align: "left", left: 15, hanging: 15, before: 2, line: 130 },
  cellL: { align: "left", line: 115 },
  cellC: { align: "center", line: 115 },
  cellR: { align: "right", line: 115 },
  unit: { align: "right", before: 5, after: 1, line: 130 },
  end: { align: "right", before: 6 },
  gap: { align: "left", line: 100 },
}
type ParaKey = keyof typeof PARAS

const FONT = "맑은 고딕"
const tw = (pt: number) => Math.round(pt * 20) // pt → twip

function rPr(k: CharKey) {
  const d = CHARS[k]
  return `<w:rPr><w:rFonts w:ascii="${FONT}" w:hAnsi="${FONT}" w:eastAsia="${FONT}" w:cs="${FONT}"/>`
    + (d.bold ? "<w:b/><w:bCs/>" : "")
    + `<w:color w:val="${d.color}"/><w:sz w:val="${Math.round(d.pt * 2)}"/><w:szCs w:val="${Math.round(d.pt * 2)}"/></w:rPr>`
}

function pPr(k: ParaKey, opts: { pageBreakBefore?: boolean } = {}) {
  const d = PARAS[k]
  const ind = d.left ? `<w:ind w:left="${tw(d.left)}"${d.hanging ? ` w:hanging="${tw(d.hanging)}"` : ""}/>` : ""
  return `<w:pPr>${d.keep ? "<w:keepNext/>" : ""}${opts.pageBreakBefore ? "<w:pageBreakBefore/>" : ""}`
    + `<w:spacing w:before="${tw(d.before ?? 0)}" w:after="${tw(d.after ?? 0)}" w:line="${Math.round(((d.line ?? 160) / 100) * 240)}" w:lineRule="auto"/>`
    + `${ind}<w:jc w:val="${d.align}"/></w:pPr>`
}

// ---------------------------------------------------------------- 본문 생성
type Run = { t: string; c: CharKey }
type Ctx = "body" | "tbl" | "meta" | "note" | "end" | "th" | "kpi" | "tbls" | "ths" | "kpis"

/** 인라인 요소 → 글자 모양이 붙은 조각들 (hwpx.ts 와 같은 규칙) */
function runs(n: Node, ctx: Ctx): Run[] {
  const base: Record<Ctx, CharKey> = { body: "body", tbl: "tbl", meta: "meta", note: "note", end: "end", th: "th", kpi: "tblB", tbls: "tblS", ths: "thS", kpis: "tblSB" }
  const boldOf: Record<Ctx, CharKey> = { body: "bodyB", tbl: "tblB", meta: "metaB", note: "note", end: "end", th: "th", kpi: "tblB", tbls: "tblSB", ths: "thS", kpis: "tblSB" }
  const out: Run[] = []
  const walk = (k: Node, c: CharKey) => {
    if (k.tag === "#text") { if (k.text) out.push({ t: k.text.replace(/\s+/g, " "), c }); return }
    if (has(k, "bar")) return // 사용률 막대는 수치로 충분
    if (k.tag === "b" || k.tag === "strong") return k.kids.forEach(z => walk(z, boldOf[ctx]))
    if (k.tag === "span" && has(k, "g")) {
      const lv = has(k, "crit") ? "crit" : has(k, "warn") ? "warn" : "ok"
      const cc = (ctx === "body" ? `${lv}L` : ctx === "tbls" || ctx === "kpis" ? `${lv}S` : lv) as CharKey
      return k.kids.forEach(z => walk(z, cc))
    }
    k.kids.forEach(z => walk(z, c))
  }
  n.kids.forEach(k => walk(k, base[ctx]))
  const merged: Run[] = []
  for (const r of out) {
    const last = merged[merged.length - 1]
    if (last && last.c === r.c) last.t += r.t
    else merged.push({ ...r })
  }
  if (merged.length) { merged[0].t = merged[0].t.replace(/^\s+/, ""); merged[merged.length - 1].t = merged[merged.length - 1].t.replace(/\s+$/, "") }
  return merged.filter(r => r.t)
}

function para(p: ParaKey, rs: Run[], opts: { pageBreakBefore?: boolean; fallback?: CharKey } = {}) {
  const inner = rs.length
    ? rs.map(r => `<w:r>${rPr(r.c)}<w:t xml:space="preserve">${x(r.t)}</w:t></w:r>`).join("")
    : `<w:r>${rPr(opts.fallback ?? "body")}</w:r>`
  return `<w:p>${pPr(p, opts)}${inner}</w:p>`
}

type Fill = "cell" | "th" | "box" | "kpi" | "total"
const FILLS: Record<Fill, string | null> = { cell: null, th: "1B2F5B", box: "F4F6FA", kpi: "F3F6FB", total: "E8EEF8" }
type Cell = { paras: string; fill: Fill; header?: boolean }

function cellXml(cell: Cell, width: number, dense: boolean) {
  const borders = cell.fill === "kpi"
    ? `<w:tcBorders><w:top w:val="single" w:sz="12" w:color="1668E3"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/></w:tcBorders>`
    : ""
  const shd = FILLS[cell.fill] ? `<w:shd w:val="clear" w:color="auto" w:fill="${FILLS[cell.fill]}"/>` : ""
  const mar = dense
    ? `<w:tcMar><w:top w:w="17" w:type="dxa"/><w:left w:w="68" w:type="dxa"/><w:bottom w:w="17" w:type="dxa"/><w:right w:w="68" w:type="dxa"/></w:tcMar>`
    : `<w:tcMar><w:top w:w="40" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>`
  return `<w:tc><w:tcPr><w:tcW w:w="${width}" w:type="dxa"/>${borders}${shd}${mar}<w:vAlign w:val="center"/></w:tcPr>${cell.paras}</w:tc>`
}

/** 표 한 개. 표 바로 뒤에 빈 문단을 둠 (워드는 붙은 표를 하나로 합침) */
function table(rows: Cell[][], widths: number[], opts: { repeatHeader?: boolean; dense?: boolean; noBorder?: boolean } = {}) {
  const total = widths.reduce((a, b) => a + b, 0)
  const line = opts.noBorder ? `w:val="nil"` : `w:val="single" w:sz="4" w:space="0" w:color="555555"`
  const borders = `<w:tblBorders><w:top ${line}/><w:left ${line}/><w:bottom ${line}/><w:right ${line}/><w:insideH ${line}/><w:insideV ${line}/></w:tblBorders>`
  const grid = `<w:tblGrid>${widths.map(w => `<w:gridCol w:w="${w}"/>`).join("")}</w:tblGrid>`
  const trs = rows.map(cells => {
    const header = cells.some(c => c.header)
    const trPr = `<w:trPr><w:cantSplit/>${header && opts.repeatHeader ? "<w:tblHeader/>" : ""}<w:trHeight w:val="${opts.dense ? 230 : 280}"/></w:trPr>`
    return `<w:tr>${trPr}${cells.map((c, i) => cellXml(c, widths[i] ?? widths[widths.length - 1], !!opts.dense)).join("")}</w:tr>`
  }).join("")
  return `<w:tbl><w:tblPr><w:tblW w:w="${total}" w:type="dxa"/>${borders}<w:tblLayout w:type="fixed"/>`
    + `<w:tblCellMar><w:left w:w="100" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar><w:tblLook w:val="0000"/></w:tblPr>`
    + `${grid}${trs}</w:tbl>${para("gap", [], { fallback: "note" })}`
}

// 열 너비는 글자 폭에 비례 (한글은 영문·숫자의 약 1.7배 — 짧은 한글 칸이 '스토리/지'처럼 꺾이지 않게)
function widthsFor(texts: string[][], total: number) {
  const cols = Math.max(...texts.map(r => r.length))
  const w = Array.from({ length: cols }, (_, c) => Math.min(44, Math.max(5, ...texts.map(r => Math.ceil(displayWidth(r[c] || "") * 0.85)))) + 3)
  const sum = w.reduce((a, b) => a + b, 0)
  const out = w.map(v => Math.floor((v / sum) * total))
  out[out.length - 1] += total - out.reduce((a, b) => a + b, 0)
  return out
}

function convertTable(t: Node, total: number) {
  const head = t.kids.find(k => k.tag === "thead")
  const bodyRows = (t.kids.find(k => k.tag === "tbody")?.kids || t.kids).filter(k => k.tag === "tr")
  const headCells = head ? (head.kids.find(k => k.tag === "tr")?.kids || []).filter(k => k.tag === "th") : []
  const rows: Cell[][] = []
  const texts: string[][] = []
  const dense = has(t, "dense")
  if (headCells.length) {
    rows.push(headCells.map(th => ({ paras: para("cellC", runs(th, dense ? "ths" : "th"), { fallback: dense ? "thS" : "th" }), fill: "th" as Fill, header: true })))
    texts.push(headCells.map(th => clean(textOf(th))))
  }
  for (const tr of bodyRows) {
    const tds = tr.kids.filter(k => k.tag === "td" || k.tag === "th")
    const isTotal = has(tr, "total")
    const ctx: Ctx = isTotal ? (dense ? "kpis" : "kpi") : dense ? "tbls" : "tbl"
    rows.push(tds.map(td => ({
      paras: para(has(td, "c") ? "cellC" : has(td, "r") ? "cellR" : "cellL", runs(td, ctx), { fallback: dense ? "tblS" : "tbl" }),
      fill: (isTotal ? "total" : "cell") as Fill,
    })))
    texts.push(tds.map(td => clean(textOf(td))))
  }
  if (!rows.length) return ""
  return table(rows, widthsFor(texts, total), { repeatHeader: headCells.length > 0, dense })
}

function convertKpi(t: Node, total: number) {
  const tds = (t.kids.find(k => k.tag === "tr") || t.kids.find(k => k.tag === "tbody")?.kids.find(k => k.tag === "tr"))?.kids.filter(k => k.tag === "td") || []
  if (!tds.length) return ""
  const cells: Cell[] = tds.map(td => {
    const part = (c: string) => td.kids.find(k => has(k, c))
    const k = part("k"), v = part("v"), s = part("s")
    const lv = has(td, "st-crit") ? "crit" : has(td, "st-warn") ? "warn" : has(td, "st-ok") ? "ok" : ""
    return {
      paras: para("cellL", k ? [{ t: clean(textOf(k)), c: "note" }] : [], { fallback: "note" })
        + para("cellL", v ? [{ t: clean(textOf(v)), c: (lv ? `${lv}L` : "kpiV") as CharKey }] : [])
        + (s ? para("cellL", [{ t: clean(textOf(s)), c: "note" }]) : ""),
      fill: "kpi" as Fill,
    }
  })
  const w = Math.floor(total / cells.length)
  return table([cells], cells.map((_, i) => (i === cells.length - 1 ? total - w * (cells.length - 1) : w)), { noBorder: true })
}

function convertBlocks(nodes: Node[], total: number, out: string[], state: { pageBreakNext: boolean }) {
  const push = (xml: string) => {
    if (state.pageBreakNext) {
      // 붙임: 새 쪽에서 시작 — 첫 요소가 표여도 되게 쪽 나눔만 있는 문단을 먼저 둠
      out.push(`<w:p><w:pPr><w:spacing w:before="0" w:after="0"/></w:pPr><w:r><w:br w:type="page"/></w:r></w:p>`)
      state.pageBreakNext = false
    }
    out.push(xml)
  }
  for (const n of nodes) {
    if (n.tag === "#text" || n.tag === "style" || n.tag === "script") continue
    if (has(n, "head")) {
      const kicker = n.kids.find(k => has(k, "kicker"))
      const h1 = n.kids.find(k => k.tag === "h1")
      const info = n.kids.find(k => has(k, "info"))
      if (kicker) push(para("left", [{ t: clean(textOf(kicker)), c: "kicker" }]))
      if (h1) push(para("title", [{ t: clean(textOf(h1)), c: "title" }]))
      if (info) {
        const rs: Run[] = []
        info.kids.filter(k => k.tag === "span").forEach((sp, i) => {
          if (i) rs.push({ t: "   ·   ", c: "meta" })
          rs.push(...runs(sp, "meta").map(r => (r.c === "metaB" ? { ...r, t: `${r.t} ` } : r)))
        })
        push(para("left", rs))
      }
      push(para("gap", []))
    } else if (n.tag === "table" && has(n, "kpi")) {
      push(convertKpi(n, total))
    } else if (n.tag === "table") {
      push(convertTable(n, total))
    } else if (has(n, "summary")) {
      const inner: string[] = []
      for (const k of n.kids) {
        if (has(k, "ttl")) inner.push(para("cellL", [{ t: clean(textOf(k)), c: "bodyB" }]))
        else if (k.tag === "p") inner.push(para("cellL", runs(k, "body")))
      }
      if (inner.length) push(table([[{ paras: inner.join(""), fill: "box" }]], [total]))
    } else if (n.tag === "h2") {
      const no = n.kids.find(k => has(k, "no"))
      const rest = clean(n.kids.filter(k => k !== no).map(textOf).join(""))
      push(para("h2", [{ t: `${no ? `${clean(textOf(no))}. ` : ""}${rest}`, c: "h2" }]))
    } else if (n.tag === "p") {
      if (has(n, "l1")) push(para("l1", runs(n, "body")))
      else if (has(n, "l2")) push(para("l2", runs(n, "body")))
      else if (has(n, "l3")) push(para("l3", runs(n, "body")))
      else if (has(n, "note")) push(para("note", runs(n, "note")))
      else if (has(n, "end")) push(para("end", runs(n, "end")))
      else push(para("left", runs(n, "body")))
    } else if (has(n, "unit")) {
      push(para("unit", runs(n, "note")))
    } else if (has(n, "attach")) {
      state.pageBreakNext = true
      convertBlocks(n.kids, total, out, state)
    } else if (has(n, "attach-ttl")) {
      const tag = n.kids.find(k => has(k, "tag"))
      const rest = clean(n.kids.filter(k => k !== tag).map(textOf).join(""))
      push(para("left", [{ t: tag ? `[${clean(textOf(tag))}] ` : "", c: "h2" as CharKey }, { t: rest, c: "h2" as CharKey }].filter(r => r.t)))
      push(para("gap", []))
    } else if (has(n, "footer-note")) {
      push(para("gap", []))
      push(para("center", runs(n, "note")))
    } else {
      convertBlocks(n.kids, total, out, state)
    }
  }
}

// ---------------------------------------------------------------- 패키지 부품
const NS_W = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`
  + `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>`
  + `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`
  + `<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>`
  + `<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>`
  + `<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>`
  + `<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`
  + `<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`
  + `<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
  + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`
  + `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`
  + `<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
  + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`
  + `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>`
  + `<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>`
  + `<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles ${NS_W}><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="${FONT}" w:hAnsi="${FONT}" w:eastAsia="${FONT}" w:cs="${FONT}"/>`
  + `<w:sz w:val="22"/><w:szCs w:val="22"/><w:lang w:val="ko-KR" w:eastAsia="ko-KR"/></w:rPr></w:rPrDefault>`
  + `<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>`
  + `<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>`
  + `<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/>`
  + `<w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>`

const SETTINGS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings ${NS_W}><w:defaultTabStop w:val="800"/><w:characterSpacingControl w:val="compressPunctuation"/><w:compat>`
  + `<w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>`

const headerXml = (cls: string) => `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr ${NS_W}>${cls ? para("right", [{ t: cls, c: "cls" }]) : `<w:p>${pPr("right")}</w:p>`}</w:hdr>`

// 꼬리말: 가운데 쪽 번호 "- 1 -" (한글 문서와 같게)
const FOOTER = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr ${NS_W}><w:p>${pPr("center")}<w:r>${rPr("note")}<w:t xml:space="preserve">- </w:t></w:r>`
  + `<w:r>${rPr("note")}<w:fldChar w:fldCharType="begin"/></w:r><w:r>${rPr("note")}<w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>`
  + `<w:r>${rPr("note")}<w:fldChar w:fldCharType="separate"/></w:r><w:r>${rPr("note")}<w:t>1</w:t></w:r><w:r>${rPr("note")}<w:fldChar w:fldCharType="end"/></w:r>`
  + `<w:r>${rPr("note")}<w:t xml:space="preserve"> -</w:t></w:r></w:p></w:ftr>`

// ---------------------------------------------------------------- 공개 함수
export function reportHtmlToDocx(html: string, opts: { title: string; landscape?: boolean; classification?: string; author?: string }) {
  // A4 (twip) · 여백을 PDF(@page: 위 20·좌우 17·아래 18mm)·한글 문서와 같게
  const mm = (v: number) => Math.round(v * 56.6929)
  const pageW = opts.landscape ? 16838 : 11906
  const pageH = opts.landscape ? 11906 : 16838
  const marginLR = mm(17)
  const total = pageW - marginLR * 2

  const out: string[] = []
  convertBlocks(parse(html).kids, total, out, { pageBreakNext: false })
  out.push(`<w:p>${pPr("left")}</w:p>`)

  const sectPr = `<w:sectPr><w:headerReference w:type="default" r:id="rId3"/><w:footerReference w:type="default" r:id="rId4"/>`
    + `<w:pgSz w:w="${pageW}" w:h="${pageH}"${opts.landscape ? ` w:orient="landscape"` : ""}/>`
    + `<w:pgMar w:top="${mm(20)}" w:right="${marginLR}" w:bottom="${mm(18)}" w:left="${marginLR}" w:header="${mm(8)}" w:footer="${mm(8)}" w:gutter="0"/>`
    + `<w:cols w:space="720"/></w:sectPr>`
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document ${NS_W}><w:body>${out.join("")}${sectPr}</w:body></w:document>`

  const iso = new Date().toISOString().replace(/\.\d+Z$/, "Z")
  const core = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
    + `<dc:title>${x(opts.title)}</dc:title><dc:creator>${x(opts.author || "MAKUS vLAB")}</dc:creator><cp:lastModifiedBy>${x(opts.author || "MAKUS vLAB")}</cp:lastModifiedBy>`
    + `<dcterms:created xsi:type="dcterms:W3CDTF">${iso}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${iso}</dcterms:modified></cp:coreProperties>`
  const app = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>MAKUS vLAB</Application></Properties>`

  return zip([
    { name: "[Content_Types].xml", data: enc(CONTENT_TYPES) },
    { name: "_rels/.rels", data: enc(ROOT_RELS) },
    { name: "word/document.xml", data: enc(document) },
    { name: "word/_rels/document.xml.rels", data: enc(DOC_RELS) },
    { name: "word/styles.xml", data: enc(STYLES) },
    { name: "word/settings.xml", data: enc(SETTINGS) },
    { name: "word/header1.xml", data: enc(headerXml(opts.classification || "")) },
    { name: "word/footer1.xml", data: enc(FOOTER) },
    { name: "docProps/core.xml", data: enc(core) },
    { name: "docProps/app.xml", data: enc(app) },
  ])
}
