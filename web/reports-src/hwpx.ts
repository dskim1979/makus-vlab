// MAKUS vLAB 한국형 보고서 → HWPX(한글 문서, KS X 6101 OWPML)
//
//  PDF 와 같은 보고서 HTML(html.js)을 읽어 한글 문단·표로 옮김 → 양식 수정은 html.js 한 곳에서
//  뼈대(header·설정 등)는 한글에서 저장된 검증 파일(hwpxSkeleton.ts)을 쓰고, 글자·문단·테두리 모양을 덧붙인 뒤 본문(section0)만 생성
//  한글 2014 이후(HWPX 지원)에서 열리며, 필요하면 한글에서 'HWP 로 저장'
//
// 원본: 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 (LICENSE·NOTICE)
// 빌드: web/reports-src/build.sh → static/js/makus-reports.js

import { clean, has, parse, textOf, zip, type Node, enc } from "./htmlDoc"

import {
  COL_PR, CONTAINER_RDF, CONTAINER_XML, CONTENT_HPF, HEADER_XML, MANIFEST_XML, MIMETYPE, SEC_PR, SECTION_OPEN,
  SETTINGS_XML, VERSION_XML,
} from "./hwpxSkeleton"

// ---------------------------------------------------------------- 모양 정의
// 글꼴: 뼈대의 0 = 함초롬돋움, 1 = 함초롬바탕 (한글 기본 설치)
const DOTUM = 0
const BATANG = 1

type CharDef = { h: number; color: string; bold?: boolean; font: number }
const CHARS: Record<string, CharDef> = {
  body: { h: 1100, color: "#111111", font: BATANG },
  bodyB: { h: 1100, color: "#111111", font: BATANG, bold: true },
  title: { h: 1800, color: "#0F1D3D", font: DOTUM, bold: true },
  kicker: { h: 900, color: "#1668E3", font: DOTUM, bold: true },
  meta: { h: 950, color: "#3C4658", font: DOTUM },
  metaB: { h: 950, color: "#0F1D3D", font: DOTUM, bold: true },
  h2: { h: 1300, color: "#0F1D3D", font: DOTUM, bold: true },
  tbl: { h: 900, color: "#1D2433", font: DOTUM },
  tblB: { h: 900, color: "#1D2433", font: DOTUM, bold: true },
  th: { h: 900, color: "#FFFFFF", font: DOTUM, bold: true },
  // 촘촘한 표(html.js table.t.dense — 가상서버 대장 목록)
  tblS: { h: 800, color: "#1D2433", font: DOTUM },
  tblSB: { h: 800, color: "#1D2433", font: DOTUM, bold: true },
  thS: { h: 800, color: "#FFFFFF", font: DOTUM, bold: true },
  warnS: { h: 800, color: "#B45309", font: DOTUM, bold: true },
  note: { h: 850, color: "#5A6477", font: DOTUM },
  ok: { h: 900, color: "#1A7F37", font: DOTUM, bold: true },
  warn: { h: 900, color: "#B45309", font: DOTUM, bold: true },
  crit: { h: 900, color: "#C1121F", font: DOTUM, bold: true },
  okL: { h: 1100, color: "#1A7F37", font: DOTUM, bold: true },
  warnL: { h: 1100, color: "#B45309", font: DOTUM, bold: true },
  critL: { h: 1100, color: "#C1121F", font: DOTUM, bold: true },
  kpiV: { h: 1500, color: "#0F1D3D", font: DOTUM, bold: true },
  cls: { h: 950, color: "#B00020", font: DOTUM, bold: true },
  end: { h: 1100, color: "#111111", font: DOTUM, bold: true },
}
const CHAR_BASE = 7 // 뼈대 charPr 0~6 다음
const C: Record<string, number> = Object.fromEntries(Object.keys(CHARS).map((k, i) => [k, CHAR_BASE + i]))

type ParaDef = { align: "LEFT" | "CENTER" | "RIGHT" | "JUSTIFY"; left?: number; indent?: number; prev?: number; next?: number; line?: number; keep?: boolean }
const PARAS: Record<string, ParaDef> = {
  left: { align: "LEFT" },
  center: { align: "CENTER" },
  right: { align: "RIGHT" },
  title: { align: "LEFT", prev: 200, next: 300, line: 130 },
  h2: { align: "LEFT", prev: 1600, next: 500, keep: true },
  l1: { align: "JUSTIFY", left: 1500, indent: -1500, prev: 500 },
  l2: { align: "JUSTIFY", left: 3000, indent: -1500, prev: 150 },
  l3: { align: "JUSTIFY", left: 4200, indent: -1100, prev: 100 },
  note: { align: "LEFT", left: 1500, indent: -1500, prev: 200, line: 130 },
  cellL: { align: "LEFT", line: 130 },
  cellC: { align: "CENTER", line: 130 },
  cellR: { align: "RIGHT", line: 130 },
  unit: { align: "RIGHT", prev: 500, next: 100, line: 130 },
  end: { align: "RIGHT", prev: 600 },
  gap: { align: "LEFT", line: 100 },
}
const PARA_BASE = 20 // 뼈대 paraPr 0~19 다음
const P: Record<string, number> = Object.fromEntries(Object.keys(PARAS).map((k, i) => [k, PARA_BASE + i]))

type BorderDef = { line?: string; lineColor?: string; fill?: string; topOnly?: string }
const BORDERS: Record<string, BorderDef> = {
  cell: { line: "0.12 mm", lineColor: "#555555" },
  th: { line: "0.12 mm", lineColor: "#555555", fill: "#1B2F5B" },
  box: { line: "0.12 mm", lineColor: "#333333", fill: "#F4F6FA" },
  kpi: { topOnly: "0.5 mm", lineColor: "#1668E3", fill: "#F3F6FB" },
  total: { line: "0.12 mm", lineColor: "#555555", fill: "#E8EEF8" },
}
const BORDER_BASE = 3 // 뼈대 borderFill 1~2 다음
const B: Record<string, number> = Object.fromEntries(Object.keys(BORDERS).map((k, i) => [k, BORDER_BASE + i]))

const LANGS = ["hangul", "latin", "hanja", "japanese", "other", "symbol", "user"]
const all = (v: string | number) => LANGS.map(l => `${l}="${v}"`).join(" ")

function charPrXml(id: number, d: CharDef) {
  return `<hh:charPr id="${id}" height="${d.h}" textColor="${d.color}" shadeColor="none" useFontSpace="0" useKerning="0" symMark="NONE" borderFillIDRef="2">`
    + `<hh:fontRef ${all(d.font)}/><hh:ratio ${all(100)}/><hh:spacing ${all(0)}/><hh:relSz ${all(100)}/><hh:offset ${all(0)}/>`
    + (d.bold ? "<hh:bold/>" : "")
    + `<hh:underline type="NONE" shape="SOLID" color="#000000"/><hh:strikeout shape="NONE" color="#000000"/><hh:outline type="NONE"/>`
    + `<hh:shadow type="NONE" color="#C0C0C0" offsetX="10" offsetY="10"/></hh:charPr>`
}

function paraPrXml(id: number, d: ParaDef) {
  const margin = `<hh:margin><hc:intent value="${d.indent ?? 0}" unit="HWPUNIT"/><hc:left value="${d.left ?? 0}" unit="HWPUNIT"/>`
    + `<hc:right value="0" unit="HWPUNIT"/><hc:prev value="${d.prev ?? 0}" unit="HWPUNIT"/><hc:next value="${d.next ?? 0}" unit="HWPUNIT"/></hh:margin>`
    + `<hh:lineSpacing type="PERCENT" value="${d.line ?? 160}" unit="HWPUNIT"/>`
  return `<hh:paraPr id="${id}" tabPrIDRef="0" condense="0" fontLineHeight="0" snapToGrid="1" suppressLineNumbers="0" checked="0" textDir="LTR">`
    + `<hh:align horizontal="${d.align}" vertical="BASELINE"/><hh:heading type="NONE" idRef="0" level="0"/>`
    + `<hh:breakSetting breakLatinWord="KEEP_WORD" breakNonLatinWord="KEEP_WORD" widowOrphan="0" keepWithNext="${d.keep ? 1 : 0}" keepLines="0" pageBreakBefore="0" lineWrap="BREAK"/>`
    + `<hh:autoSpacing eAsianEng="0" eAsianNum="0"/>`
    + `<hp:switch><hp:case hp:required-namespace="http://www.hancom.co.kr/hwpml/2016/HwpUnitChar">${margin}</hp:case><hp:default>${margin}</hp:default></hp:switch>`
    + `<hh:border borderFillIDRef="2" offsetLeft="0" offsetRight="0" offsetTop="0" offsetBottom="0" connect="0" ignoreMargin="0"/></hh:paraPr>`
}

function borderFillXml(id: number, d: BorderDef) {
  const side = (name: string, on: boolean, w?: string) =>
    `<hh:${name} type="${on ? "SOLID" : "NONE"}" width="${on ? w : "0.1 mm"}" color="${on ? d.lineColor : "#000000"}"/>`
  const l = !!d.line
  return `<hh:borderFill id="${id}" threeD="0" shadow="0" centerLine="NONE" breakCellSeparateLine="0">`
    + `<hh:slash type="NONE" Crooked="0" isCounter="0"/><hh:backSlash type="NONE" Crooked="0" isCounter="0"/>`
    + side("leftBorder", l, d.line) + side("rightBorder", l, d.line)
    + side("topBorder", l || !!d.topOnly, d.line || d.topOnly) + side("bottomBorder", l, d.line)
    + `<hh:diagonal type="SOLID" width="0.1 mm" color="#000000"/>`
    + (d.fill ? `<hc:fillBrush><hc:winBrush faceColor="${d.fill}" hatchColor="#FF000000" alpha="0"/></hc:fillBrush>` : "")
    + `</hh:borderFill>`
}

/** 뼈대 header 에 모양 정의를 덧붙임 (itemCnt 갱신) */
function buildHeader() {
  const add = (xml: string, list: string, items: string[]) => xml.replace(
    new RegExp(`<hh:${list} itemCnt="(\\d+)">([\\s\\S]*?)</hh:${list}>`),
    (_m, cnt, body) => `<hh:${list} itemCnt="${Number(cnt) + items.length}">${body}${items.join("")}</hh:${list}>`,
  )
  let h = HEADER_XML
  h = add(h, "borderFills", Object.entries(BORDERS).map(([k, d]) => borderFillXml(B[k], d)))
  h = add(h, "charProperties", Object.entries(CHARS).map(([k, d]) => charPrXml(C[k], d)))
  h = add(h, "paraProperties", Object.entries(PARAS).map(([k, d]) => paraPrXml(P[k], d)))
  return h
}

// HTML 읽기·ZIP 은 htmlDoc.ts (워드·엑셀 변환과 공용)

// ---------------------------------------------------------------- 본문 생성
const x = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

type Run = { t: string; c: number }

/** 인라인 요소 → 글자 모양이 붙은 조각들 */
function runs(n: Node, ctx: "body" | "tbl" | "meta" | "note" | "end" | "th" | "kpi" | "tbls" | "ths" | "kpis"): Run[] {
  const base = { body: C.body, tbl: C.tbl, meta: C.meta, note: C.note, end: C.end, th: C.th, kpi: C.tblB, tbls: C.tblS, ths: C.thS, kpis: C.tblSB }[ctx]
  const boldOf = { body: C.bodyB, tbl: C.tblB, meta: C.metaB, note: C.note, end: C.end, th: C.th, kpi: C.tblB, tbls: C.tblSB, ths: C.thS, kpis: C.tblSB }[ctx]
  const out: Run[] = []
  const walk = (k: Node, c: number) => {
    if (k.tag === "#text") { if (k.text) out.push({ t: k.text.replace(/\s+/g, " "), c }); return }
    if (has(k, "bar")) return // 사용률 막대는 수치로 충분
    if (k.tag === "b" || k.tag === "strong") return k.kids.forEach(z => walk(z, boldOf))
    if (k.tag === "span" && has(k, "g")) {
      const lv = has(k, "crit") ? "crit" : has(k, "warn") ? "warn" : "ok"
      const cc = ctx === "body" ? C[`${lv}L`] : ctx === "tbls" && C[`${lv}S`] ? C[`${lv}S`] : C[lv]
      return k.kids.forEach(z => walk(z, cc))
    }
    k.kids.forEach(z => walk(z, c))
  }
  n.kids.forEach(k => walk(k, base))
  // 인접 같은 모양 합치기, 앞뒤 공백 정리
  const merged: Run[] = []
  for (const r of out) {
    const last = merged[merged.length - 1]
    if (last && last.c === r.c) last.t += r.t
    else merged.push({ ...r })
  }
  if (merged.length) { merged[0].t = merged[0].t.replace(/^\s+/, ""); merged[merged.length - 1].t = merged[merged.length - 1].t.replace(/\s+$/, "") }
  return merged.filter(r => r.t)
}

function para(p: number, rs: Run[], opts: { pageBreak?: boolean; fallbackChar?: number } = {}) {
  const inner = rs.length
    ? rs.map(r => `<hp:run charPrIDRef="${r.c}"><hp:t>${x(r.t)}</hp:t></hp:run>`).join("")
    : `<hp:run charPrIDRef="${opts.fallbackChar ?? C.body}"><hp:t/></hp:run>`
  return `<hp:p id="0" paraPrIDRef="${p}" styleIDRef="0" pageBreak="${opts.pageBreak ? 1 : 0}" columnBreak="0" merged="0">${inner}</hp:p>`
}

let tblSeq = 1

type Cell = { paras: string; border: number; header?: boolean }

/** 표 한 개 (행 × 열), 열 너비는 글자 수에 비례 */
function table(rows: Cell[][], widths: number[], opts: { repeatHeader?: boolean; dense?: boolean } = {}) {
  const rowCnt = rows.length
  const colCnt = widths.length
  // 행 높이는 최소값(글자가 넘치면 한글이 늘림) — 촘촘한 표는 PDF(8pt·여백 1.2mm)에 맞춰 낮게
  const rowH = opts.dense ? 1150 : 1400
  const cm = opts.dense ? `left="340" right="340" top="85" bottom="85"` : `left="510" right="510" top="141" bottom="141"`
  const trs = rows.map((cells, r) => `<hp:tr>${cells.map((cell, c) => `<hp:tc name="" header="${cell.header ? 1 : 0}" hasMargin="1" protect="0" editable="0" dirty="0" borderFillIDRef="${cell.border}">`
    + `<hp:subList id="" textDirection="HORIZONTAL" lineWrap="BREAK" vertAlign="CENTER" linkListIDRef="0" linkListNextIDRef="0" textWidth="0" textHeight="0" hasTextRef="0" hasNumRef="0">${cell.paras}</hp:subList>`
    + `<hp:cellAddr colAddr="${c}" rowAddr="${r}"/><hp:cellSpan colSpan="1" rowSpan="1"/><hp:cellSz width="${widths[c]}" height="${rowH}"/>`
    + `<hp:cellMargin ${cm}/></hp:tc>`).join("")}</hp:tr>`).join("")
  const width = widths.reduce((a, b) => a + b, 0)
  const id = 1000000000 + tblSeq++
  const tbl = `<hp:tbl id="${id}" zOrder="0" numberingType="TABLE" textWrap="TOP_AND_BOTTOM" textFlow="BOTH_SIDES" lock="0" dropcapstyle="None" pageBreak="CELL" repeatHeader="${opts.repeatHeader ? 1 : 0}" rowCnt="${rowCnt}" colCnt="${colCnt}" cellSpacing="0" borderFillIDRef="${B.cell}" noAdjust="0">`
    + `<hp:sz width="${width}" widthRelTo="ABSOLUTE" height="${rowH * rowCnt}" heightRelTo="ABSOLUTE" protect="0"/>`
    + `<hp:pos treatAsChar="1" affectLSpacing="0" flowWithText="1" allowOverlap="0" holdAnchorAndSO="0" vertRelTo="PARA" horzRelTo="COLUMN" vertAlign="TOP" horzAlign="LEFT" vertOffset="0" horzOffset="0"/>`
    + `<hp:outMargin left="0" right="0" top="0" bottom="0"/><hp:inMargin left="510" right="510" top="141" bottom="141"/>`
    + `${trs}</hp:tbl>`
  return `<hp:p id="0" paraPrIDRef="${P.left}" styleIDRef="0" pageBreak="0" columnBreak="0" merged="0"><hp:run charPrIDRef="${C.tbl}">${tbl}<hp:t/></hp:run></hp:p>`
}

function widthsFor(texts: string[][], total: number) {
  const cols = Math.max(...texts.map(r => r.length))
  const w = Array.from({ length: cols }, (_, c) => Math.min(28, Math.max(3, ...texts.map(r => [...(r[c] || "")].length))) + 2)
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
    rows.push(headCells.map(th => ({ paras: para(P.cellC, runs(th, dense ? "ths" : "th"), { fallbackChar: dense ? C.thS : C.th }), border: B.th, header: true })))
    texts.push(headCells.map(th => clean(textOf(th))))
  }
  for (const tr of bodyRows) {
    const tds = tr.kids.filter(k => k.tag === "td" || k.tag === "th")
    const isTotal = has(tr, "total")
    const ctx = isTotal ? (dense ? "kpis" : "kpi") : dense ? "tbls" : "tbl"
    rows.push(tds.map(td => ({
      paras: para(has(td, "c") ? P.cellC : has(td, "r") ? P.cellR : P.cellL, runs(td, ctx), { fallbackChar: dense ? C.tblS : C.tbl }),
      border: isTotal ? B.total : B.cell,
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
      paras: para(P.cellL, k ? [{ t: clean(textOf(k)), c: C.note }] : [])
        + para(P.cellL, v ? [{ t: clean(textOf(v)), c: lv ? C[`${lv}L`] : C.kpiV }] : [])
        + (s ? para(P.cellL, [{ t: clean(textOf(s)), c: C.note }]) : ""),
      border: B.kpi,
    }
  })
  const w = Math.floor(total / cells.length)
  return table([cells], cells.map((_, i) => (i === cells.length - 1 ? total - w * (cells.length - 1) : w)))
}

function convertBlocks(nodes: Node[], total: number, out: string[], state: { pageBreakNext: boolean }) {
  const push = (xml: string) => {
    if (state.pageBreakNext && xml.startsWith("<hp:p ")) {
      xml = xml.replace('pageBreak="0"', 'pageBreak="1"')
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
      if (kicker) push(para(P.left, [{ t: clean(textOf(kicker)), c: C.kicker }]))
      if (h1) push(para(P.title, [{ t: clean(textOf(h1)), c: C.title }]))
      if (info) {
        const rs: Run[] = []
        info.kids.filter(k => k.tag === "span").forEach((sp, i) => {
          if (i) rs.push({ t: "   ·   ", c: C.meta })
          rs.push(...runs(sp, "meta").map(r => (r.c === C.metaB ? { ...r, t: `${r.t} ` } : r)))
        })
        push(para(P.left, rs))
      }
      push(para(P.gap, []))
    } else if (n.tag === "table" && has(n, "kpi")) {
      push(convertKpi(n, total))
      push(para(P.gap, []))
    } else if (n.tag === "table") {
      push(convertTable(n, total))
    } else if (has(n, "summary")) {
      const inner: string[] = []
      for (const k of n.kids) {
        if (has(k, "ttl")) inner.push(para(P.cellL, [{ t: clean(textOf(k)), c: C.bodyB }]))
        else if (k.tag === "p") inner.push(para(P.cellL, runs(k, "body")))
      }
      push(table([[{ paras: inner.join(""), border: B.box }]], [total]))
    } else if (n.tag === "h2") {
      const no = n.kids.find(k => has(k, "no"))
      const rest = clean(n.kids.filter(k => k !== no).map(textOf).join(""))
      push(para(P.h2, [{ t: `${no ? `${clean(textOf(no))}. ` : ""}${rest}`, c: C.h2 }]))
    } else if (n.tag === "p") {
      if (has(n, "l1")) push(para(P.l1, runs(n, "body")))
      else if (has(n, "l2")) push(para(P.l2, runs(n, "body")))
      else if (has(n, "l3")) push(para(P.l3, runs(n, "body")))
      else if (has(n, "note")) push(para(P.note, runs(n, "note")))
      else if (has(n, "end")) push(para(P.end, runs(n, "end")))
      else push(para(P.left, runs(n, "body")))
    } else if (has(n, "unit")) {
      push(para(P.unit, runs(n, "note")))
    } else if (has(n, "attach")) {
      state.pageBreakNext = true
      convertBlocks(n.kids, total, out, state)
    } else if (has(n, "attach-ttl")) {
      const tag = n.kids.find(k => has(k, "tag"))
      const rest = clean(n.kids.filter(k => k !== tag).map(textOf).join(""))
      push(para(P.left, [{ t: tag ? `[${clean(textOf(tag))}] ` : "", c: C.h2 }, { t: rest, c: C.h2 }].filter(r => r.t)))
      push(para(P.gap, []))
    } else if (has(n, "footer-note")) {
      push(para(P.gap, []))
      push(para(P.center, runs(n, "note")))
    } else {
      convertBlocks(n.kids, total, out, state)
    }
  }
}

// ---------------------------------------------------------------- 공개 함수
export function reportHtmlToHwpx(html: string, opts: { title: string; landscape?: boolean; classification?: string; author?: string }) {
  tblSeq = 1
  const pageW = 59528
  const pageH = 84186
  // 여백을 PDF(@page: 위 20·좌우 17·아래 18mm)와 같게 — 한글 기본값(좌우 30mm, 위 35·아래 30mm)이면 쪽이 더 넘어감
  const mm = (v: number) => Math.round(v * 283.465)
  const marginLR = mm(17)
  const margin = `<hp:margin header="${mm(5)}" footer="${mm(10)}" gutter="0" left="${marginLR}" right="${marginLR}" top="${mm(15)}" bottom="${mm(8)}"/>`
  const total = (opts.landscape ? pageH : pageW) - marginLR * 2 // 본문 폭 (HWPUNIT, 1pt = 100)

  // 첫 문단: 쪽 설정(가로/세로·여백) + 쪽 번호 "- 1 -" + 보안 등급
  let secPr = SEC_PR.replace(/<hp:margin header="[^"]*"[^>]*\/>/, margin)
  if (opts.landscape) secPr = secPr.replace('landscape="WIDELY"', 'landscape="NARROWLY"')
  const first = `<hp:p id="0" paraPrIDRef="${P.right}" styleIDRef="0" pageBreak="0" columnBreak="0" merged="0">`
    + `<hp:run charPrIDRef="${C.cls}">${secPr}<hp:ctrl>${COL_PR}</hp:ctrl>`
    + `<hp:ctrl><hp:pageNum pos="BOTTOM_CENTER" formatType="DIGIT" sideChar="-"/></hp:ctrl></hp:run>`
    + `<hp:run charPrIDRef="${C.cls}"><hp:t>${x(opts.classification || "")}</hp:t></hp:run></hp:p>`

  const out: string[] = []
  convertBlocks(parse(html).kids, total, out, { pageBreakNext: false })
  const section = `${SECTION_OPEN}${first}${out.join("")}</hs:sec>`

  const iso = new Date().toISOString().replace(/\.\d+Z$/, "Z")
  const hpf = CONTENT_HPF
    .replace("<opf:title/>", `<opf:title>${x(opts.title)}</opf:title>`)
    .replace(/synthetic-fixture-author/g, x(opts.author || "MAKUS vLAB"))
    .replace(/(name="CreatedDate" content="text">)[^<]*/, `$1${iso}`)
    .replace(/(name="ModifiedDate" content="text">)[^<]*/, `$1${iso}`)
    .replace(/(name="date" content="text">)[^<]*/, `$1${iso}`)
  const prv = clean(parse(html).kids.map(textOf).join(" ")).slice(0, 1000)

  return zip([
    { name: "mimetype", data: enc(MIMETYPE), store: true },
    { name: "version.xml", data: enc(VERSION_XML) },
    { name: "Contents/header.xml", data: enc(buildHeader()) },
    { name: "Contents/section0.xml", data: enc(section) },
    { name: "Preview/PrvText.txt", data: enc(prv) },
    { name: "settings.xml", data: enc(SETTINGS_XML) },
    { name: "META-INF/container.rdf", data: enc(CONTAINER_RDF) },
    { name: "Contents/content.hpf", data: enc(hpf) },
    { name: "META-INF/container.xml", data: enc(CONTAINER_XML) },
    { name: "META-INF/manifest.xml", data: enc(MANIFEST_XML) },
  ])
}
