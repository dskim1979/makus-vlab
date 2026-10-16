<p align="center">
  <img src="images/vlab-logo.svg" alt="MOAVI Desk" height="56">
</p>

<h3 align="center">연구소·기업·교육 기관의 LAB과 FPGA 개발을 위한 가상 데스크톱(VDI) 플랫폼</h3>

<p align="center">
  <img alt="Engine version" src="https://img.shields.io/badge/version-1.3.0-blue">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-1559d6"></a>
  <img alt="Python 3.12" src="https://img.shields.io/badge/python-3.12-1559d6">
  <img alt="Proxmox VE" src="https://img.shields.io/badge/Proxmox%20VE-8.x-1559d6">
</p>

---

**MOAVI Desk** 은 Proxmox VE 위에서 동작하는 VDI 플랫폼입니다. 연구원·개발자·교육생·직원에게 데스크톱을 나눠 주고,
GPU·vGPU·FPGA 가속 카드를 필요한 만큼 빌려 쓰게 합니다. 이 저장소는 vLAB 의 **엔진(API 서버)** 입니다.
관리 콘솔과 사용자 작업 공간은 [makus-vlab-console](https://github.com/dskim1979/makus-vlab-console), 전용 클라이언트는 `makus-vlab-client` 입니다.

<p align="center"><img src="docs/images/portal.png" alt="사용자 작업 공간" width="900"></p>

| 관리 콘솔 대시보드 | GPU·가속 카드 재고 |
|---|---|
| ![대시보드](docs/images/admin-dashboard.png) | ![GPU·가속 카드](docs/images/accel-inventory.png) |

화면 전체는 [콘솔 저장소](https://github.com/dskim1979/makus-vlab-console#화면)에 있습니다.

## 주요 기능

| 영역 | 내용 |
|---|---|
| 데스크톱 풀 | 전용·초기화·공유·일정형·빌드 팜 풀, 템플릿 일괄 복제(VMID·이름 자동), 사용자 할당과 VM 권한 연동 |
| 초기화 | 기준 스냅숏 자동 생성, 데스크톱·풀 단위 초기화(접속 중인 데스크톱은 건너뜀) |
| 접속 | 브라우저 접속(noVNC), SPICE(`.vv`), 접속 기록, 사용자 전원 제어 |
| GPU·vGPU | GPU 재고, NVIDIA vGPU 프로필, PCI 리소스 매핑, 풀 단위 GPU 정책(전체 GPU / vGPU) |
| FPGA | AMD Xilinx·Intel FPGA 카드 인식, 카드 대여·연장·반납, 기간이 끝나면 자동 반납 |
| 사용자 | 로컬 계정, AD/LDAP, 유효 권한 조회(권한이 어디서 왔는지) |
| 운영 | 대시보드, 시스템 요약, 사용률 보고서(일·풀·사용자별, CSV), 작업 기록(감사), 플랫폼 설정(폐쇄망 모드 포함) |
| 클러스터 | Proxmox 클러스터 연결, 노드·스토리지 개요 |

## 구성

```
 사용자 브라우저 / vLAB Client
          │ HTTPS
 ┌────────▼──────────┐        ┌───────────────────────┐
 │ vlab-console       │  /api  │ vlab-engine (이 저장소) │──── Proxmox VE 클러스터
 │ nginx + 콘솔·포털  │───────▶│ API 전용 (WEB_UI=0)    │      (GPU·FPGA 노드)
 └───────────────────┘        └───────────────────────┘
```

- 엔진은 Flask·gevent, 설정은 SQLite(SQLCipher). vLAB 기능은 `pegaprox/vlab/` 와 `pegaprox/api/vlab.py` (`/api/vlab/*`).
- API 명세: [`docs/openapi.json`](docs/openapi.json)

## 빠르게 시작하기

설치 묶음(nginx·docker compose)은 콘솔 저장소의 `deploy/` 에 있습니다. 엔진만 띄우려면:

```bash
docker compose up -d --build
```

개발 환경에서 시험:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest tests/test_vlab_api.py tests/test_vlab_accel.py -q
```

## GPU·FPGA 준비

GPU·FPGA 카드는 Proxmox 의 **리소스 매핑**(데이터센터 > 리소스 매핑 > PCI 장치)을 통해 데스크톱에 붙습니다.
같은 모델의 카드를 여러 노드에서 한 매핑에 넣으면, 데스크톱이 어느 노드에서 켜지든 빈 카드를 씁니다.
vGPU 는 NVIDIA vGPU 호스트 드라이버와 라이선스 서버(DLS/CLS)가 필요합니다.

## 기여·보안

- 기여 방법: [CONTRIBUTING.md](CONTRIBUTING.md)
- 보안 문제 신고: [SECURITY.md](SECURITY.md)

## 라이선스와 출처

MOAVI Desk 은 GNU Affero General Public License v3.0([LICENSE](LICENSE))으로 배포합니다.

이 엔진은 오픈소스 프로젝트 **PegaProx**(© 2025-2026 PegaProx Team, AGPL-3.0)를 바탕으로 (주)매커스시스템즈가
수정·확장한 버전입니다. AGPL-3.0 제7조(b)에 따른 저작자 표시는 [NOTICE](NOTICE) 에 있으며, 제품 화면의
"Powered by PegaProx" 표시와 저작권 고지는 라이선스상 지우거나 가릴 수 없습니다.
네트워크로 서비스하는 경우 제13조에 따라 사용자에게 소스 코드를 제공해야 합니다.

Proxmox 는 Proxmox Server Solutions GmbH 의 상표이며, NVIDIA·AMD·Intel·Xilinx 는 각 회사의 상표입니다.
