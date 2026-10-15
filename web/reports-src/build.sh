#!/bin/bash
# MAKUS vLAB 한국형 보고서 — 브라우저 묶음 빌드
#   web/reports-src/*.ts·html.js → static/js/makus-reports.js (window.MakusReports)
#   보고서 양식·형식 변환을 고친 뒤 실행하고, 결과 파일도 함께 커밋 (설치본은 빌드 없이 static 을 그대로 씀)
#   필요: Node.js 18+ (esbuild 는 npx 로 받음)
set -e
cd "$(dirname "$0")/../.."
npx --yes esbuild@0.25.12 web/reports-src/index.ts --bundle --format=iife --global-name=MakusReports \
  --target=es2019 --charset=utf8 --minify --legal-comments=inline \
  --banner:js="/* MAKUS vLAB Korean reports — built from web/reports-src (AGPL-3.0, see LICENSE). HWPX skeleton: python-hwpx (Apache-2.0). */" \
  --outfile=static/js/makus-reports.js
echo "built static/js/makus-reports.js"
