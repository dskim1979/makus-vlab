// MAKUS vLAB 한국형 보고서 — 문서 변환 공용: 보고서 HTML(html.js) 읽기 + ZIP 묶기 (브라우저용)
// 한글(hwpx.ts)·워드(docx.ts)·엑셀(xlsx.ts)이 같은 HTML 을 각 형식으로 옮길 때 씀 → 양식 수정은 html.js 한 곳에서
// 외부 라이브러리 없이 브라우저에서 동작 (격리망에서도 같게). ZIP 은 무압축(store) 항목 — HWPX·DOCX·XLSX 모두 그대로 열림
//
// 원본: MAKUS vLAB 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 — LICENSE·NOTICE 참고
// 빌드: web/reports-src/build.sh → static/js/makus-reports.js

// ---------------------------------------------------------------- 글자 → 바이트
const ENC = new TextEncoder()
export const enc = (s: string): Uint8Array => ENC.encode(s)

// ---------------------------------------------------------------- HTML 읽기 (html.js 가 만드는 범위만)
export type Node = { tag: string; cls: string[]; kids: Node[]; text?: string }

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", nbsp: " " }
const decode = (s: string) => s.replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (_m, e) => ENT[e]).replace(/&#(\d+);/g, (_m, n) => String.fromCharCode(Number(n)))
const VOID = new Set(["br", "meta", "img", "hr", "input", "link"])

export function parse(html: string): Node {
  const body = /<body[^>]*>([\s\S]*)<\/body>/i.exec(html)?.[1] ?? html
  const root: Node = { tag: "root", cls: [], kids: [] }
  const stack: Node[] = [root]
  const re = /<!--[\s\S]*?-->|<(\/?)([a-zA-Z0-9]+)([^>]*)>|([^<]+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(body))) {
    const top = stack[stack.length - 1]
    if (m[4] !== undefined) {
      top.kids.push({ tag: "#text", cls: [], kids: [], text: decode(m[4]) })
    } else if (m[2]) {
      const tag = m[2].toLowerCase()
      if (m[1]) {
        const i = stack.map(n => n.tag).lastIndexOf(tag)
        if (i > 0) stack.length = i
      } else {
        const cls = (/class\s*=\s*"([^"]*)"/.exec(m[3])?.[1] || "").split(/\s+/).filter(Boolean)
        const node: Node = { tag, cls, kids: [] }
        top.kids.push(node)
        if (!VOID.has(tag) && !m[3].trim().endsWith("/")) stack.push(node)
      }
    }
  }
  return root
}

export const has = (n: Node, c: string) => n.cls.includes(c)
export const textOf = (n: Node): string => (n.tag === "#text" ? n.text || "" : n.kids.map(textOf).join(""))
export const clean = (s: string) => s.replace(/\s+/g, " ").trim()

/** XML 글자 이스케이프 (XML 에 쓸 수 없는 제어 문자는 뺌) */
export const xmlEsc = (s: string) => s
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

/** 표 칸·문단의 판정(정상·주의·위험) — html.js 의 <span class="g ok|warn|crit"> */
export function gradeOf(n: Node): "ok" | "warn" | "crit" | "" {
  let lv: "ok" | "warn" | "crit" | "" = ""
  const walk = (k: Node) => {
    if (lv) return
    if (k.tag === "span" && has(k, "g")) lv = has(k, "crit") ? "crit" : has(k, "warn") ? "warn" : "ok"
    else k.kids.forEach(walk)
  }
  walk(n)
  return lv
}

/** 글자 수(한글 등 넓은 글자는 2)로 본 표시 폭 */
export const displayWidth = (s: string) => [...s].reduce((w, ch) => w + (/[ᄀ-ᇿ⺀-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦]/.test(ch) ? 2 : 1), 0)

// ---------------------------------------------------------------- ZIP (모든 항목 무압축 store)
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()
function crc32(buf: Uint8Array) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

export function zip(files: { name: string; data: Uint8Array; store?: boolean }[]): Uint8Array {
  const parts: Uint8Array[] = []
  const centrals: Uint8Array[] = []
  let offset = 0
  const now = new Date()
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)
  const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()
  for (const f of files) {
    const name = enc(f.name)
    const body = f.data
    const crc = crc32(body)
    const lh = new Uint8Array(30)
    const l = new DataView(lh.buffer)
    l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, 0x0800, true); l.setUint16(8, 0, true)
    l.setUint16(10, dosTime, true); l.setUint16(12, dosDate, true); l.setUint32(14, crc, true)
    l.setUint32(18, body.length, true); l.setUint32(22, body.length, true); l.setUint16(26, name.length, true); l.setUint16(28, 0, true)
    parts.push(lh, name, body)
    const ch = new Uint8Array(46)
    const c = new DataView(ch.buffer)
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true)
    c.setUint16(12, dosTime, true); c.setUint16(14, dosDate, true); c.setUint32(16, crc, true); c.setUint32(20, body.length, true)
    c.setUint32(24, body.length, true); c.setUint16(28, name.length, true); c.setUint32(42, offset, true)
    centrals.push(ch, name)
    offset += 30 + name.length + body.length
  }
  const cdLen = centrals.reduce((a, b) => a + b.length, 0)
  const end = new Uint8Array(22)
  const e = new DataView(end.buffer)
  e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true)
  e.setUint32(12, cdLen, true); e.setUint32(16, offset, true)
  const all = [...parts, ...centrals, end]
  const out = new Uint8Array(all.reduce((a, b) => a + b.length, 0))
  let p = 0
  for (const a of all) { out.set(a, p); p += a.length }
  return out
}
