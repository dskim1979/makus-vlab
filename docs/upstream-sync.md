# 업스트림(PegaProx) 새 버전 반영하기

MAKUS vLAB 는 PegaProx 를 바탕으로 한 포크입니다. PegaProx 가 새 버전을 내면 아래처럼 반영합니다.

## 한 줄 요약

```bash
scripts/upstream/sync.sh status          # 새 릴리스가 있는지
scripts/upstream/sync.sh start           # 최신 릴리스 병합 시작 (특정 버전: start v1.4.0)
#   → 남은 충돌이 있으면 풀고 git add
scripts/upstream/sync.sh finish          # 화면 빌드 · API 문서 · 점검 · 커밋
python3 -m pytest tests -q               # 테스트
git push -u origin feature/upstream-<버전> vendor
```

Linux 에서도, Windows 의 Git Bash 에서도 됩니다 (python3 · node 필요).

## 하는 일

| 단계 | 내용 |
|---|---|
| vendor 브랜치 | 업스트림 릴리스를 **손대지 않고** 쌓아 둔 브랜치. 커밋 제목 `Vendor: PegaProx X (unmodified upstream)` 로 마지막 반영 버전을 압니다 |
| start | 업스트림 태그를 받아 vendor 에 새 릴리스를 얹고, `feature/upstream-<버전>` 브랜치에서 병합 |
| 자동 처리 | `web/src/translations.js` 는 [build_ko.py](../scripts/upstream/build_ko.py)로 새로 만듦 · `version.json` 은 [merge_version.py](../scripts/upstream/merge_version.py)로 합침 · `web/index.html`, `docs/openapi.json` 은 다시 생성 · README 는 MAKUS vLAB 것 유지(버전 배지만 갱신) |
| git rerere | 한 번 손으로 푼 충돌을 기억했다가 다음에 같은 모양이면 자동으로 풉니다 (이 PC 의 `.git/rr-cache`) |
| finish | 화면 빌드, API 문서 생성, 화면에 남은 `PegaProx` 점검([check_branding.py](../scripts/upstream/check_branding.py)), 병합 커밋 |

## 충돌을 손으로 풀 때

- 업스트림의 **보안·버그 수정과 새 기능은 받습니다.**
- MAKUS vLAB 것은 지킵니다: 한국어 문구, MAKUS vLAB 이름, 원화(KRW), GPU, 한국형 보고서, 하드웨어 이력,
  화이트라벨, MAKUS vLAB 저장소 주소(update.sh · deploy.sh · version.json · .github).
- **법적 고지는 업스트림 그대로 둡니다.** `LegalNotice`(로그인·사이드바·하단·콘솔 창의
  "PegaProx · © PegaProx Team · AGPL-3.0 · Source"), 설정 > 정보의 고지, 고객 포털의
  "Powered by PegaProx" 는 NOTICE 의 AGPL-3.0 §7(b) 조건이라 지우거나 바꾸면 라이선스 위반입니다.
- 업스트림에 한국어가 없는 문구는 `build_ko.py` 의 `KO_EXTRA` 에 넣습니다 (translations.js 를 직접 고치지 않음).

## 병합 뒤 확인할 것

- 새 기능이 **POST 로 읽기만 하는 API** 를 만들었거나 MAKUS vLAB 가 그런 API 를 추가했다면 HA 대기 인스턴스용
  목록(`pegaprox/app.py` 의 `_STANDBY_LOCAL_WRITES`)에 넣었는지.
- MAKUS vLAB 가 **새 DB 테이블** 을 만들었다면 `pegaprox/core/ha.py` 의 `SYNC_TABLES`(공유 설정) 또는
  `LOCAL_TABLES`(인스턴스별) 에 넣었는지 — `tests/test_ha_core.py` 가 알려 줍니다.
- 테스트: MAKUS vLAB 는 한국어만 싣기 때문에 업스트림의 "9개 언어 모두에 있는지" 검사는
  `tests/conftest.py` 가 xfail 로 표시합니다. 그 밖의 실패는 진짜 문제입니다.
