#!/usr/bin/env python3
"""화면에 'PegaProx' 가 새로 보이는 곳을 찾는다 (업스트림 병합 뒤 확인용).

자동으로 바꾸지 않고 목록만 보여준다. 반드시 남겨야 하는 곳이 있기 때문이다:
  - AGPL-3.0 §7(b) 저작자 표시 (NOTICE): LegalNotice 줄, 설정 > 정보의 법적 고지, 고객 포털의
    "Powered by PegaProx" — 지우거나 바꾸면 라이선스 위반
  - 내부 이름 (PegaProxApiErrors, generatePegaProxPDF, PEGAPROX_*, pegaprox-theme 등)
남은 것 중 화면 문구만 MAKUS vLAB 로 바꾸면 된다.

사용: python3 scripts/upstream/check_branding.py
"""
import glob
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# 법적 고지 — 그대로 둔다
LEGAL = ('PegaProx Team', 'project-pegaprox', 'pegaprox.com', 'modified version of PegaProx',
         'PegaProx is free software', '>PegaProx</a>', 'Powered by PegaProx', 'opencollective.com/pegaprox')
# 내부 식별자
IDENT = re.compile(r'PegaProx(?=[A-Z_(])|[A-Za-z_]PegaProx|PEGAPROX|pegaprox')


def visible(line):
    s = line.strip()
    if s.startswith(('//', '*', '/*', '{/*')):
        return False
    if any(x in line for x in LEGAL):
        return False
    rest = IDENT.sub('', line)
    return 'PegaProx' in rest


def main():
    hits = []
    for path in sorted(glob.glob(os.path.join(ROOT, 'web', 'src', '*.js'))) + [os.path.join(ROOT, 'web', 'index.html.original')]:
        if os.path.basename(path) == 'translations.js':
            continue  # build_ko.py 가 처리
        with open(path, encoding='utf-8') as fh:
            for n, line in enumerate(fh, 1):
                if 'PegaProx' in line and visible(line):
                    hits.append(f'{os.path.relpath(path, ROOT)}:{n}: {line.strip()[:160]}')
    if hits:
        print(f'화면에 보일 수 있는 PegaProx {len(hits)}곳 — 법적 고지가 아니면 MAKUS vLAB 로 바꾸세요:')
        print('\n'.join(hits))
    else:
        print('화면 문구에 남은 PegaProx 없음 (법적 고지·내부 이름 제외)')


if __name__ == '__main__':
    main()
