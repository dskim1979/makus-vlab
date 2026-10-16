#!/usr/bin/env python3
"""version.json 을 MOAVI Desk 쪽(HEAD)과 업스트림(vendor)에서 합친다.

  - 버전 번호·min_python 은 업스트림을 따른다 (MOAVI Desk 버전 = 병합한 PegaProx 버전)
  - 업데이트 주소(download_url, update_archive, update_mirror)는 MOAVI Desk 저장소 그대로
  - changelog: 맨 앞에 MOAVI Desk 항목(없으면 자동 문구), 업스트림의 새 항목은 기존 PegaProx 항목들 앞에
  - update_files: 업스트림 목록 + MOAVI Desk 에만 있는 파일(디스크에 있는 것만)

사용: python3 scripts/upstream/merge_version.py [업스트림 ref, 기본 vendor] [이전 vendor 커밋]
"""
import datetime
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def load(ref):
    out = subprocess.run(['git', '-C', ROOT, 'show', f'{ref}:version.json'], capture_output=True, check=True).stdout
    return json.loads(out)


def head_words(entry, n=2):
    return entry.split()[:n]


def main():
    ref = sys.argv[1] if len(sys.argv) > 1 else 'vendor'
    since = sys.argv[2] if len(sys.argv) > 2 else None  # 이번에 건너뛴 중간 릴리스의 changelog 도 모으려면
    ours, theirs = load('HEAD'), load(ref)
    # 업스트림 version.json 에는 그 릴리스 항목만 있다 — 중간 릴리스들은 vendor 커밋마다 하나씩 읽는다
    up_log = []
    if since:
        revs = subprocess.run(['git', '-C', ROOT, 'rev-list', f'{since}..{ref}'],
                              capture_output=True, check=True, text=True).stdout.split()
        for r in revs:  # 최신부터
            for c in load(r).get('changelog', []):
                if c.startswith('PegaProx') and c not in up_log:
                    up_log.append(c)
    for c in theirs.get('changelog', []):
        if c.startswith('PegaProx') and c not in up_log:
            up_log.append(c)
    v = theirs['version']
    d = dict(ours)
    for k, val in theirs.items():
        if k not in d:
            d[k] = val
    today = datetime.date.today()
    d['version'] = v
    d['build'] = today.strftime('%Y.%m.%d')
    d['release_date'] = today.isoformat()
    d['min_python'] = theirs.get('min_python', ours.get('min_python'))

    log = list(ours.get('changelog', []))
    new_up = [c for c in up_log if not any(head_words(c) == head_words(o) for o in log)]
    at = next((i for i, c in enumerate(log) if c.startswith('PegaProx')), len(log))
    log = log[:at] + new_up + log[at:]
    if not any(head_words(c) == ['MOAVI Desk', v] for c in log):
        log.insert(0, f'MOAVI Desk {v} — PegaProx {v} 업스트림 병합. 바뀐 내용은 아래 PegaProx {v} 항목을 보세요.')
    d['changelog'] = log

    files = list(theirs.get('update_files', []))
    seen = set(files)
    for f in ours.get('update_files', []):
        if f not in seen and os.path.exists(os.path.join(ROOT, f)):
            files.append(f)
            seen.add(f)
    d['update_files'] = files

    with open(os.path.join(ROOT, 'version.json'), 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(d, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
    print(f'version.json: {ours["version"]} -> {v}, 새 업스트림 changelog {len(new_up)}개, update_files {len(files)}개')


if __name__ == '__main__':
    main()
