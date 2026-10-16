#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# MOAVI Desk — 업스트림 PegaProx 새 릴리스 반영
#
#   scripts/upstream/sync.sh start [v1.4.0]   새 릴리스를 가져와 병합 시작 (태그 생략 = 최신)
#   scripts/upstream/sync.sh finish           충돌 해결 뒤: 화면 빌드 · API 문서 · 점검 · 커밋
#   scripts/upstream/sync.sh status           마지막으로 반영한 버전과 새 릴리스 목록
#
# 방식 (docs/upstream-sync.md):
#   vendor 브랜치 = 업스트림 릴리스를 손대지 않고 쌓은 것 ("Vendor: PegaProx X (unmodified upstream)").
#   새 릴리스마다 vendor 에 한 커밋 얹고, 그것을 MOAVI Desk 브랜치에 병합한다.
#   매번 충돌하는 파일은 자동 처리한다:
#     web/src/translations.js  scripts/upstream/build_ko.py 로 새로 만듦
#     version.json             scripts/upstream/merge_version.py 로 합침
#     web/index.html           빌드 결과물 — finish 에서 다시 빌드
#     docs/openapi.json        생성 결과물 — finish 에서 다시 생성
#     README.md                MOAVI Desk 것 유지, 버전 배지만 갱신
#   git rerere 를 켜 두어, 한 번 손으로 푼 충돌은 다음에 같은 모양이면 자동으로 풀린다.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

UPSTREAM_URL='https://github.com/PegaProx/project-pegaprox.git'
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
STATE=".git/vlab-upstream-sync"

say()  { printf '\033[1;34m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[0;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# python3 (Windows 에서는 python 만 있는 경우가 많다 — web/Dev/build.sh 도 python3 을 부른다)
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    if python3 -c 'import sys' >/dev/null 2>&1; then PY=python3
    elif python -c 'import sys' >/dev/null 2>&1; then PY=python
    else die 'python3 를 찾을 수 없습니다'; fi
fi
if ! python3 -c 'import sys' >/dev/null 2>&1; then
    SHIM="$(mktemp -d)"; printf '#!/bin/sh\nexec %s "$@"\n' "$PY" > "$SHIM/python3"; chmod +x "$SHIM/python3"
    export PATH="$SHIM:$PATH"
fi
export PYTHONIOENCODING=utf-8 PYTHONUTF8=1

vendor_ref() {
    if git rev-parse -q --verify refs/heads/vendor >/dev/null; then echo vendor
    elif git rev-parse -q --verify refs/remotes/origin/vendor >/dev/null; then
        git branch vendor origin/vendor >/dev/null; echo vendor
    else die 'vendor 브랜치가 없습니다 (git fetch origin vendor)'; fi
}

last_version() {
    git log -1 --format=%s "$(vendor_ref)" | sed -n 's/^Vendor: PegaProx \(.*\) (unmodified upstream)$/\1/p'
}

fetch_upstream() {
    git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
    # 업스트림 태그는 refs/upstream-tags 에 따로 — MOAVI Desk 의 같은 이름 태그와 섞이지 않게
    git fetch -q --no-tags upstream '+refs/tags/v*:refs/upstream-tags/v*'
}

# 마지막 반영 버전보다 새로운 정식 릴리스 (vX.Y.Z), 오래된 순
new_tags() {
    local last="$1" until="${2:-}"
    git for-each-ref --format='%(refname:strip=2)' refs/upstream-tags \
        | grep -E '^v[0-9]+(\.[0-9]+)*$' | sort -V \
        | awk -v last="v$last" -v until="$until" '
            function cmp(a, b,   x, y, i, n) {
                sub(/^v/, "", a); sub(/^v/, "", b); n = split(a, x, "."); split(b, y, ".")
                if (length(y) > n) n = length(y)
                for (i = 1; i <= n; i++) { if ((x[i] + 0) != (y[i] + 0)) return (x[i] + 0) < (y[i] + 0) ? -1 : 1 }
                return 0 }
            cmp($0, last) > 0 && (until == "" || cmp($0, until) <= 0)'
}

cmd_status() {
    fetch_upstream
    local last; last="$(last_version)"
    echo "마지막으로 반영한 PegaProx: $last"
    local tags; tags="$(new_tags "$last")"
    if [ -n "$tags" ]; then echo "새 릴리스:"; echo "$tags" | sed 's/^/  /'; else echo '새 릴리스 없음'; fi
}

cmd_start() {
    local target="${1:-}"
    [ -e "$STATE" ] && die "진행 중인 반영이 있습니다 ($(cat "$STATE")). 'finish' 하거나 git merge --abort 후 rm $STATE"
    git diff --quiet && git diff --cached --quiet || die '커밋하지 않은 변경이 있습니다. 먼저 커밋하거나 치워 주세요'

    say '업스트림 릴리스 확인'
    fetch_upstream
    local last; last="$(last_version)"
    [ -n "$last" ] || die 'vendor 브랜치 마지막 커밋에서 버전을 읽지 못했습니다'
    if [ -n "$target" ]; then
        git rev-parse -q --verify "refs/upstream-tags/$target" >/dev/null || die "업스트림에 $target 태그가 없습니다"
    fi
    local tags; tags="$(new_tags "$last" "$target")"
    [ -n "$tags" ] || { ok "이미 최신입니다 (PegaProx $last)"; exit 0; }
    local final; final="$(echo "$tags" | tail -1)"; final="${final#v}"
    echo "  PegaProx $last → $(echo "$tags" | tr '\n' ' ')"
    local branch="feature/upstream-$final"
    git rev-parse -q --verify "refs/heads/$branch" >/dev/null \
        && die "$branch 브랜치가 이미 있습니다 (다른 이름으로 옮기려면: git branch -m $branch $branch-old)"

    say 'vendor 브랜치에 업스트림 스냅숏 추가'
    local parent; parent="$(git rev-parse vendor)"
    local old_vendor="$parent"
    for t in $tags; do
        parent="$(git commit-tree "refs/upstream-tags/$t^{tree}" -p "$parent" -m "Vendor: PegaProx ${t#v} (unmodified upstream)")"
        echo "  ${t#v}  $(git rev-parse --short "$parent")"
    done
    git branch -f vendor "$parent"

    say "$branch 브랜치에서 병합"
    git config rerere.enabled true
    git config rerere.autoUpdate true
    git switch -q -c "$branch"
    echo "$final" > "$STATE"
    git merge --no-ff --no-commit vendor >/dev/null 2>&1 || true

    say '매번 충돌하는 파일 자동 처리'
    "$PY" scripts/upstream/build_ko.py vendor && git add web/src/translations.js
    "$PY" scripts/upstream/merge_version.py vendor "$old_vendor" && git add version.json
    if git diff --name-only --diff-filter=U | grep -qx web/index.html; then
        git checkout --ours web/index.html && git add web/index.html   # finish 에서 다시 빌드
    fi
    if git diff --name-only --diff-filter=U | grep -qx docs/openapi.json; then
        git checkout --theirs docs/openapi.json && git add docs/openapi.json   # finish 에서 다시 생성
    fi
    if git diff --name-only --diff-filter=U | grep -qx README.md; then
        git checkout --ours README.md && git add README.md
    fi
    sed -i.bak -E "s#badge/version-[0-9.]+-blue#badge/version-$final-blue#" README.md && rm -f README.md.bak && git add README.md

    local left; left="$(git diff --name-only --diff-filter=U || true)"
    if [ -z "$left" ]; then
        ok '남은 충돌 없음 — 바로 finish 하면 됩니다'
    else
        warn "손으로 풀어야 할 충돌 $(echo "$left" | wc -l)개:"
        for f in $left; do echo "  $f ($(grep -c '^<<<<<<< ' "$f" 2>/dev/null || echo '?')곳)"; done
        cat <<'EOF'

  충돌 해결 원칙 (자세한 것은 docs/upstream-sync.md):
   - 업스트림의 보안·버그 수정과 새 기능은 받는다
   - MOAVI Desk 것은 지킨다: 한국어 문구, MOAVI Desk 이름, 원화(KRW), GPU, 한국형 보고서, 하드웨어 이력,
     화이트라벨, MOAVI Desk 저장소 주소
   - 법적 고지(LegalNotice, 설정 > 정보의 고지, "Powered by PegaProx")는 업스트림 그대로
   - 해결한 파일은 git add, 다 끝나면: scripts/upstream/sync.sh finish
EOF
    fi
}

cmd_finish() {
    [ -e "$STATE" ] || die "진행 중인 반영이 없습니다 ('start' 먼저)"
    local final; final="$(cat "$STATE")"
    local left; left="$(git diff --name-only --diff-filter=U || true)"
    [ -z "$left" ] || die "아직 충돌이 남았습니다: $(echo $left)"
    if git diff --cached --name-only | xargs -r grep -l '^<<<<<<< ' 2>/dev/null | grep -v '^tests/' ; then
        die '위 파일에 충돌 표시(<<<<<<<)가 남아 있습니다'
    fi

    say '화면 빌드 (web/index.html)'
    bash web/Dev/build.sh >/dev/null && git add web/index.html && ok '빌드 완료'

    say 'API 문서 다시 생성 (docs/openapi.json)'
    if "$PY" -m pegaprox.cli.gen_openapi -o docs/openapi.json >/dev/null 2>&1; then
        git add docs/openapi.json && ok 'docs/openapi.json'
    else
        warn '이 PC 에서는 생성하지 못했습니다 (Linux 서버에서: python3 -m pegaprox.cli.gen_openapi -o docs/openapi.json)'
    fi

    say '화면에 남은 PegaProx 확인'
    "$PY" scripts/upstream/check_branding.py

    git add -A
    git commit -q -m "Merge PegaProx $final into MOAVI Desk $final

Upstream snapshot(s) on the vendor branch; merged with scripts/upstream/sync.sh.
translations.js rebuilt (build_ko.py), version.json merged (merge_version.py),
web/index.html and docs/openapi.json regenerated."
    rm -f "$STATE"
    ok "커밋: $(git log -1 --oneline)"
    cat <<EOF

다음:
  1. 테스트:  python3 -m pytest tests -q
  2. version.json 의 'MOAVI Desk $final' changelog 문구를 다듬기 (선택)
  3. 올리기:  git push -u origin $(git branch --show-current) vendor
EOF
}

case "${1:-}" in
    start)  shift; cmd_start "${1:-}" ;;
    finish) cmd_finish ;;
    status) cmd_status ;;
    *) sed -n '3,8p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
