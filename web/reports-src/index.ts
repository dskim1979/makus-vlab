// MOAVI Desk 한국형 보고서 — 브라우저 묶음 진입점 (window.MakusReports)
//  data: 백엔드 POST /api/korean-reports/data 가 돌려준 보고서 자료
//  html(data)             → 미리보기·인쇄(PDF)용 HTML
//  file(data, 'hwpx'|'docx'|'xlsx') → { blob, name }  내려받기
// 원본: MOAVI Desk 한국형 보고서 (Makus Systems). 이 저장소는 AGPL-3.0 (LICENSE·NOTICE)

import { REPORT_TYPES, renderReportHtml, reportFileName, reportTitle, typeText } from "./html.js"
import { reportHtmlToHwpx } from "./hwpx"
import { reportHtmlToDocx } from "./docx"
import { reportHtmlToXlsx } from "./xlsx"

const OFFICE = {
  hwpx: { type: "application/hwp+zip", make: reportHtmlToHwpx },
  docx: { type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", make: reportHtmlToDocx },
  xlsx: { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", make: reportHtmlToXlsx },
} as const

export const types = REPORT_TYPES
export { typeText }
export const html = (data: any) => renderReportHtml(data)
export const fileName = (data: any, ext = "pdf") => reportFileName(data, ext)

export function file(data: any, fmt: "hwpx" | "docx" | "xlsx") {
  const o = OFFICE[fmt]
  if (!o) throw new Error(`unknown format: ${fmt}`)
  const bytes = (o.make as any)(renderReportHtml(data), {
    title: reportTitle(data),
    landscape: false, // 보고서 3종 모두 A4 세로
    classification: data.meta?.classification,
    author: [data.meta?.dept, data.meta?.author].filter(Boolean).join(" ") || "MOAVI Desk",
    locale: data.locale === "en" ? "en" : "ko",
  })
  return { blob: new Blob([bytes], { type: o.type }), name: reportFileName(data, fmt) }
}
