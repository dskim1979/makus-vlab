# MOAVI Desk 에 기여하기

## PR 전에
- 작은 수정이 아니면 **이슈를 먼저** 열어 방향을 맞춥니다.
- **PR 하나에 한 가지**만 담습니다 (버그 수정·기능·정리를 섞지 않기).

## 품질 기준
- 직접 시험하고 방법을 적습니다: 어떤 클러스터·데스크톱·카드로 무엇을 확인했는지.
- vLAB 기능은 `pegaprox/vlab/`, `pegaprox/api/vlab.py` 에 둡니다. 코어 파일 수정은 최소화하고 이유를 적습니다.
- 새 API 는 `tests/test_vlab_*.py` 에 시험을 함께 넣고, `docs/openapi.json` 을 다시 만듭니다
  (`python -m pegaprox.cli.gen_openapi -o docs/openapi.json`).
- 화면 문구는 콘솔 저장소(`makus-vlab-console`)에서 다룹니다.

## AI 도구
써도 됩니다. 다만 모든 줄을 직접 읽고 시험한 뒤 제출합니다.

## 라이선스
기여한 코드는 AGPL-3.0 으로 배포됩니다. 저작권·라이선스 고지(LICENSE, NOTICE, 파일 머리말)는 지우지 않습니다.
