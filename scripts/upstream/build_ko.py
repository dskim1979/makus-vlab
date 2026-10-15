#!/usr/bin/env python3
"""web/src/translations.js 를 업스트림 PegaProx 의 한국어(ko) 블록으로 다시 만든다.

MAKUS vLAB 는 한국어만 싣는다(web/src/contexts.js SUPPORTED_LANGS = ['ko']). 업스트림이 새 버전을
낼 때마다 이 파일은 충돌하므로 손으로 고치지 않고 매번 새로 만든다.
  - 업스트림 ko 블록을 그대로 가져온다 (새 문구가 자동으로 따라온다)
  - 중복 키 정리: 업스트림 ko 블록에는 이탈리아어·영어 사본이 뒤에 남아 있어 한국어를 덮어쓴다.
    한글이 든 쪽을 남긴다
  - 화면 문구의 'PegaProx' -> 'MAKUS vLAB'
  - KO_EXTRA: 업스트림에 한국어가 없어 MAKUS vLAB 가 채우는 키 (Cloud 화면의 cloud.* 등)

사용: python3 scripts/upstream/build_ko.py [업스트림 ref, 기본 vendor]
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
OUT = os.path.join(ROOT, 'web', 'src', 'translations.js')

# 업스트림이 영어 대체 문구로만 두는 키의 한국어. 업스트림 ko 블록에 같은 키가 생기면 그쪽이 쓰인다.
KO_EXTRA = {
    'cloud.overview': '개요', 'cloud.vms': '가상 머신', 'cloud.containers': '컨테이너',
    'cloud.datastores': '데이터스토어', 'cloud.pools': '리소스 풀', 'cloud.networks': '네트워크',
    'cloud.clustersTitle': '클러스터', 'cloud.hosts': '호스트', 'cloud.ha': '고가용성',
    'cloud.storageConfig': '스토리지', 'cloud.ceph': 'Ceph', 'cloud.sdn': 'SDN',
    'cloud.firewall': '방화벽', 'cloud.backups': '백업', 'cloud.replication': '복제',
    'cloud.pbs': '백업 서버', 'cloud.siteRecovery': '사이트 복구', 'cloud.monitoring': '모니터링',
    'cloud.tasks': '작업', 'cloud.users': '사용자', 'cloud.settings': '설정',
    'cloud.actions': '작업', 'cloud.addSubnet': '서브넷 추가', 'cloud.addVnet': 'VNet 추가',
    'cloud.addZone': '영역 추가', 'cloud.adjustFilters': '검색어나 필터를 조정해보세요.',
    'cloud.clear': '지우기',
    'cloud.confirmDelBackup': '이 백업 작업을 삭제하시겠습니까?',
    'cloud.confirmDelRule': '이 방화벽 규칙을 삭제하시겠습니까?',
    'cloud.confirmDelSchedule': '이 예약을 삭제하시겠습니까?',
    'cloud.confirmDelScript': '이 스크립트를 삭제하시겠습니까?',
    'cloud.confirmDelSubnet': '이 서브넷을 삭제하시겠습니까?',
    'cloud.confirmDelVnet': '이 VNet을 삭제하시겠습니까?',
    'cloud.confirmDelZone': '이 영역을 삭제하시겠습니까?',
    'cloud.crossMigrate': '클러스터로 마이그레이션…',
    'cloud.cveSub': '패키지 취약점 스캔 (debsecan)',
    'cloud.firewallSub': '데이터센터 방화벽 규칙', 'cloud.manageHost': '호스트 관리',
    'cloud.newRule': '새 방화벽 규칙', 'cloud.newSchedule': '새 예약', 'cloud.newScript': '새 스크립트',
    'cloud.noContainers': '아직 컨테이너가 없습니다', 'cloud.noMatch': '일치하는 항목 없음',
    'cloud.noVms': '아직 가상 머신이 없습니다', 'cloud.offline': '오프라인', 'cloud.online': '온라인',
    'cloud.profile': '프로필 및 환경설정', 'cloud.runNow': '지금 실행', 'cloud.runScan': '스캔 실행',
    'cloud.scanning': '노드 스캔 중…', 'cloud.schedulesSub': '시간 기반 VM 작업',
    'cloud.scriptsSub': '커스텀 클러스터 스크립트',
    'cloud.sdnNA': '이 클러스터엔 SDN이 구성되어 있지 않습니다',
    'cloud.sdnSubnets': '서브넷', 'cloud.sdnVnets': 'VNet', 'cloud.sdnZones': '영역',
    'cloud.searchUsers': '사용자 이름, 이름, 이메일 검색…', 'cloud.selected': '개 선택됨',
    'cloud.viewOutput': '출력',
}

KEY = re.compile(r"^ {16}([A-Za-z_$][\w$]*|'[^']+'|\"[^\"]+\"):")
HANGUL = re.compile('[가-힣]')


def git_show(ref, path):
    return subprocess.run(['git', '-C', ROOT, 'show', f'{ref}:{path}'],
                          capture_output=True, check=True).stdout.decode('utf-8')


def main():
    ref = sys.argv[1] if len(sys.argv) > 1 else 'vendor'
    src = git_show(ref, 'web/src/translations.js').replace('\r\n', '\n')
    version = json.loads(git_show(ref, 'version.json'))['version']
    lines = src.split('\n')
    start = next(i for i, l in enumerate(lines) if l == '            ko: {')
    end = next(i for i in range(start + 1, len(lines)) if re.match(r'^ {12}\},?$', lines[i]))
    body = lines[start + 1:end]

    occ = {}
    for i, l in enumerate(body):
        m = KEY.match(l)
        if m:
            occ.setdefault(m.group(1).strip('\'"'), []).append(i)
    drop = set()
    for idx in occ.values():
        if len(idx) > 1:
            ko = [i for i in idx if HANGUL.search(body[i])]
            keep = ko[-1] if ko else idx[-1]
            drop.update(i for i in idx if i != keep)
    body = [l.replace('PegaProx', 'MAKUS vLAB') for i, l in enumerate(body) if i not in drop]

    have = {KEY.match(l).group(1).strip('\'"') for l in body if KEY.match(l)}
    extra = [f"                '{k}': '{v}'," for k, v in KO_EXTRA.items() if k not in have]
    if extra:
        extra.insert(0, '                // MAKUS vLAB — 업스트림에 한국어가 없는 키 (scripts/upstream/build_ko.py KO_EXTRA)')

    out = ['        // ═══════════════════════════════════════════════',
           '        // MAKUS vLAB - Translations',
           f'        // 한국어 전용 — 업스트림 PegaProx {version} 의 ko 블록을 scripts/upstream/build_ko.py 로 만든 파일.',
           '        // 직접 고치지 말고 build_ko.py(KO_EXTRA)를 고친 뒤 다시 만드세요.',
           '        // ═══════════════════════════════════════════════',
           '        const translations = {',
           '            ko: {'] + body + extra + ['            }', '        };', '']
    with open(OUT, 'w', encoding='utf-8', newline='\r\n') as fh:
        fh.write('\n'.join(out))
    print(f'translations.js: PegaProx {version} ko, 키 {len(have)}개, 중복 {len(drop)}개 정리, MAKUS vLAB 추가 {len(extra) and len(extra) - 1}개')


if __name__ == '__main__':
    main()
