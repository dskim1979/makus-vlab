# MOAVI Desk 프로토콜 벤치마크 (대역폭 · 지연)

제품 자료에 "RDP는 몇 Mbps로 충분하다" 같은 숫자를 쓰려면 **같은 조건에서 직접 잰 값**이 있어야
합니다. 이 폴더는 그 측정을 매번 같은 방법으로 반복하기 위한 도구입니다.

- 이 폴더에는 **측정 결과가 들어 있지 않습니다.** 실제 Proxmox 클러스터에서 돌린 뒤의
  `summary.md`만 인용할 수 있습니다. 자체 점검(`selftest`)의 표는 합성 데이터이므로 인용 금지.
- VMware Blast / Citrix HDX와 비교할 때도 같은 에뮬레이터·같은 워크로드·같은 해상도로 재야 공정합니다
  (분석기는 Blast 22443, HDX 1494/2598 포트도 분류합니다).

## 무엇을 재는가

| 항목 | 어떻게 | 대상 |
|---|---|---|
| 회선 위 바이트 (Mbps 평균 / p95, ↓·↑) | WAN 에뮬레이터에서 tcpdump, 서버 포트로 분류 | 모든 프로토콜 |
| RDP가 UDP를 실제로 썼는지 (UDP %) | 3389/udp 바이트 ÷ RDP 전체 | RDP |
| 프레임율, 건너뛴 프레임, 인코딩 시간, RTT | 데스크톱 안 RemoteFX 성능 카운터 (`counters.csv`) | RDP 세션만 |
| CPU | 같은 카운터 파일의 `cpu_pct` | 모든 프로토콜 |

포트 분류 (`analyze/benchstat.py`의 `CLASSES`):

| 클래스 | 포트 | 쓰는 것 |
|---|---|---|
| `rdp-tcp` / `rdp-udp` | 3389 tcp / 3389·3391 udp | mstsc (MOAVI 클라이언트의 RDP) |
| `spice` | 3128 tcp | remote-viewer → Proxmox spiceproxy |
| `web` | 443, 8006, 8080, 8443 tcp | noVNC 웹소켓, 브라우저 RDP(Guacamole), RD Gateway |
| `blast` / `hdx` | 22443 / 1494·2598 | 비교용 (Omnissa Blast, Citrix HDX) |
| `other` | 그 밖 (DNS, ARP …) | 합계에 넣지 않고 `other_mb`로만 표시 |

## 구성

```
 [테스트 클라이언트 PC] ── vmbr9 ──┤ WAN 에뮬레이터 VM ├── vmbr0 ── [Win11 데스크톱, MOAVI 엔진, PVE 노드]
   mstsc / remote-viewer /          eth1 ═ br-wan ═ eth0
   브라우저                         (tc netem 양방향, tcpdump는 eth1에서)
```

- 에뮬레이터는 **투명 브리지**입니다. IP·라우팅을 바꾸지 않으므로 클라이언트는 평소 주소 그대로 접속합니다.
- 캡처는 클라이언트 쪽 포트(eth1)에서 합니다. 클라이언트로 가는 패킷은 netem을 **통과한 뒤** 기록되므로
  "WAN 회선에 실제로 실린 바이트"가 됩니다.

## 1. Proxmox에 WAN 에뮬레이터 만들기

1. **클라이언트 쪽 브리지 만들기** — 노드의 *시스템 → 네트워크*에서 `vmbr9` 생성.
   - 실물 PC를 클라이언트로 쓸 때(권장): 남는 NIC 포트를 `vmbr9`의 브리지 포트로 지정하고 PC를 그 포트에 직결.
   - 클라이언트도 VM으로 할 때: 포트 없는 `vmbr9`, 클라이언트 VM의 NIC를 `vmbr9`에 연결
     (클라이언트 렌더링이 같은 호스트 CPU를 쓰므로 실물 PC보다 덜 정확합니다).
   - 어느 쪽이든 `vmbr9`에는 DHCP/게이트웨이가 없으므로 클라이언트는 `vmbr0` 대역 주소를 그대로 씁니다
     (브리지를 통과해 같은 L2가 됩니다).
2. **에뮬레이터 VM** — Debian 12 최소 설치, 2 vCPU · 2 GB, NIC 2개(+관리용 1개 권장):
   `net0 → vmbr0`, `net1 → vmbr9`, 둘 다 virtio, **방화벽 체크 해제**(PVE 방화벽이 브리지 프레임을 막지 않도록).
   CPU 유형은 `host`. `lan` 프로파일(1 Gbps)을 쓰려면 4 vCPU를 권장합니다.
3. VM 안에서:
   ```bash
   apt install -y iproute2 ethtool tcpdump python3 iputils-ping iperf3
   git clone <엔진 저장소> && cd makus-vlab/tools/bench
   ip -br link                         # NIC 이름 확인 (예: ens18=vmbr0, ens19=vmbr9)
   sudo wan/wan-bridge.sh setup ens19 ens18      # <클라이언트 쪽> <데스크톱 쪽>
   sudo wan/wan-profile.sh list
   sudo wan/wan-profile.sh home
   sudo wan/wan-profile.sh check <데스크톱 IP>   # RTT가 프로파일 값과 맞는지
   ```
4. **검증** — 클라이언트에서 `iperf3 -c <데스크톱쪽 iperf3 서버>`로 프로파일 속도가 나오는지,
   `ping`으로 RTT가 맞는지 확인합니다. `lan`에서 1 Gbps가 안 나오면 에뮬레이터 CPU가 한계이므로
   표에 "lan = 에뮬레이터 상한 N Mbps"로 같이 적습니다.

### 프로파일 (`wan/profiles.conf`)

| 이름 | 속도(양방향 각각) | RTT | 손실(각 방향) |
|---|---|---|---|
| `lan` | 1000 Mbps | 1 ms | 0 % |
| `branch` | 20 Mbps | 30 ms | 0.5 % |
| `home` | 10 Mbps | 50 ms | 1 % |
| `bad` | 3 Mbps | 100 ms | 2 % |

- RTT는 왕복 기준이며 방향마다 절반씩 지연을 겁니다. 손실은 방향마다 적용합니다.
- 큐 길이는 "지연 구간 + 50 ms" 분량으로 잡습니다(netem 기본 1000 패킷은 3 Mbps에서 4초 버퍼라
  프로토콜이 아니라 버퍼블로트를 재게 됩니다).
- 프로파일을 추가하려면 파일에 한 줄 넣으면 됩니다. 해제는 `wan-profile.sh off`.

## 2. 테스트 데스크톱 (Windows 11)

- MOAVI 풀에서 Windows 11 데스크톱 1대. **한 데스크톱에 한 세션만** (카운터가 세션 합계이므로).
- 해상도 **1920×1080 고정**, 배율 100 %. 모든 프로토콜에서 같은 해상도·전체 화면으로 접속합니다.
- 시간 동기화: `w32tm /resync` (에뮬레이터도 NTP). 워크로드 구간을 시각으로 자르므로 1초 이상 어긋나면
  `--clock-offset`으로 보정합니다.
- `tools/bench/guest` 폴더를 데스크톱에 복사 (예: `C:\bench\guest`).
- 1080p 영상 파일 1개를 로컬에 둡니다. 예: Blender 재단의 공개 영상 *Big Buck Bunny* 1080p
  (CC BY 3.0). 회차마다 **같은 파일**을 씁니다.
- 문서 스크롤은 기본으로 동봉된 `assets/scroll.html`(고정 시드로 만든 120쪽 보고서: 글·표·차트)을
  초당 900 px로 내립니다. 실제 PDF로 하고 싶으면 `-Document C:\bench\long.pdf` (0.4초마다 PageDown).
- 3D는 동봉된 `assets/webgl.html`(약 20만 삼각형 토러스 매듭, 초당 40° 회전, 외부 라이브러리 없음)입니다.
  GPU 없는 데스크톱에서는 Edge가 소프트웨어로 렌더링하므로 왼쪽 위 FPS는 "데스크톱이 그린 프레임"입니다.

## 3. 클라이언트

| 라벨 | 접속 방법 |
|---|---|
| `rdp` | MOAVI 클라이언트 → mstsc (엔진이 만든 .rdp: networkautodetect, bandwidthautodetect, connection type 7) |
| `rdpgw` | RD Gateway를 거치는 mstsc (443 + 3391/udp) |
| `spice` | MOAVI 클라이언트 → remote-viewer (.vv, spiceproxy 3128) |
| `novnc` | 웹 콘솔의 noVNC |
| `webrdp` | 웹 콘솔의 브라우저 RDP (Guacamole) |
| `blast` / `hdx` | 비교 제품의 클라이언트 |

브라우저 계열은 브라우저 창을 전체 화면(F11)으로. 클라이언트 PC에서 다른 큰 트래픽(업데이트, 동기화)은 꺼 둡니다.

## 4. 측정 절차

에뮬레이터에서 (데스크톱·엔진·PVE 노드·게이트웨이 주소만 남기도록 서버 목록을 지정하는 것을 권장):

```bash
export MOAVI_BENCH_SERVERS="10.0.0.21 10.0.0.5 10.0.0.11 10.0.0.12"   # 데스크톱, 엔진, PVE 노드들
sudo wan/wan-profile.sh home
sudo -E capture/capture.sh rdp 10.0.9.50        # 테스트 클라이언트 IP; Ctrl-C로 끝냄
```

데스크톱(측정하는 그 원격 세션 안)에서 바로 이어서:

```powershell
powershell -ExecutionPolicy Bypass -File C:\bench\guest\Invoke-BenchWorkload.ps1 -Video C:\bench\bbb_1080p.mp4
```

- 기본 `-Workload all`: idle → scroll → video → 3d를 각 60초, 사이에 10초 정지 화면. 약 5분 30초.
- 끝나면 `%USERPROFILE%\bench-out\`의 `markers.json`, `counters.csv`를 에뮬레이터의 해당 run 폴더
  (`runs/<시각>_<프로토콜>_<프로파일>/`)에 복사하고 캡처를 Ctrl-C로 멈춥니다.
- 매트릭스: 프로파일 4 × 프로토콜 4 = 16세션, **각 3회 반복** 권장 (약 4.5시간). 순서는
  프로파일 하나를 고정하고 프로토콜을 돌린 뒤 다음 프로파일로. 회차마다 클라이언트를 새로 접속합니다.
- 한 회차라도 중간에 팝업·업데이트 알림이 떴으면 그 회차는 버리고 다시 잽니다.

## 5. 분석

```bash
python3 analyze/benchstat.py run runs/20261020T010203Z_rdp_home   # 한 회차: per_second.csv, stats.csv
python3 analyze/benchstat.py summary runs/                        # 전체: runs/summary.csv, runs/summary.md
python3 analyze/benchstat.py selftest                             # 분석기 자체 점검 (합성 pcap/pcapng)
```

표준 라이브러리만 쓰므로 tshark 없이 어디서나 돌아갑니다. 데스크톱 시계가 에뮬레이터보다 2초 늦었다면
`--clock-offset 2`.

### 결과 읽는 법

`summary.md`의 열:

| 열 | 뜻 |
|---|---|
| 회 | 합친 반복 횟수 |
| 평균 Mbps | 워크로드 60초 동안 (↓+↑) 평균. **프로토콜 선택에 쓰는 값** |
| p95 Mbps | 1초 단위 값의 95번째 백분위. **회선 용량 산정에 쓰는 값** (사용자 수 × p95 가 아니라, 평균으로 합산하고 p95로 여유를 봄) |
| ↓평균 / ↑평균 | 서버→클라이언트 / 클라이언트→서버 |
| 반복 범위 | 회차별 평균의 최소~최대. 범위가 평균의 20 %를 넘으면 반복을 늘립니다 |
| RDP UDP % | RDP 바이트 중 UDP 비율. 0에 가까우면 UDP가 막혀 TCP로만 간 것 — 그 회차의 RDP 수치는 UDP 기준이 아님 |
| FPS | RemoteFX `Output Frames/Second` 평균 (RDP만) |
| RTT ms | RemoteFX가 잰 UDP RTT (없으면 TCP RTT) |

`stats.csv` / `summary.csv`에는 그 밖에 `skip_network`(네트워크 부족으로 버린 프레임/초),
`skip_client`, `encode_ms`, `cpu_pct`, `other_mb`도 있습니다.

**해석 주의**

- **낮은 Mbps가 곧 좋은 것은 아닙니다.** 대역이 모자라면 프로토콜은 프레임을 버리거나 화질을 내려서
  덜 보냅니다. Mbps는 반드시 FPS·`skip_network`와 같이 봅니다. `bad` 프로파일에서 숫자가 작은 것은
  대개 "덜 보여 준" 결과입니다.
- SPICE·noVNC·브라우저 RDP에는 같은 수준의 프레임 카운터가 없습니다. 이들은 바이트만 비교하고,
  화질·끊김은 클라이언트 화면 녹화(같은 구간, 같은 프로파일)로 따로 확인합니다.
  remote-viewer는 `G_MESSAGES_DEBUG=all remote-viewer --spice-debug file.vv 2> spice.log`로
  채널·압축 정보를 남길 수 있지만 FPS 수치는 아닙니다.
- mstsc의 "연결 품질" 막대는 화면 확인용일 뿐 기록되지 않습니다. 기록은 데스크톱 카운터로 합니다.
- 입력→화면 지연(클릭해서 보일 때까지)은 이 도구로 재지 않습니다. RTT는 네트워크 왕복일 뿐입니다.
- 3D는 소프트웨어 렌더링 기준입니다. GPU(vGPU/패스스루) 데스크톱 수치와 섞지 않습니다.
- 숫자를 인용할 때는 프로파일·해상도·워크로드·반복 횟수·측정 날짜·MOAVI 버전을 같이 적습니다.

## 파일

| 파일 | 하는 일 |
|---|---|
| `wan/wan-bridge.sh` | 두 NIC를 `br-wan`으로 묶고 오프로드(GRO/GSO/TSO) 끔 |
| `wan/wan-profile.sh` | 프로파일 적용 / 해제 / 확인 / RTT 점검 |
| `wan/profiles.conf` | 프로파일 정의 |
| `capture/capture.sh` | 한 세션 캡처 (`capture.pcap`, `run.json`) |
| `guest/Invoke-BenchWorkload.ps1` | 데스크톱 안 워크로드 실행, `markers.json` 기록 |
| `guest/Sample-Counters.ps1` | RemoteFX 카운터 1초 샘플링 (영문 카운터 이름으로 추가하므로 한국어 Windows에서도 동작) |
| `guest/assets/*.html` | 스크롤 문서, 영상 재생, WebGL 3D |
| `analyze/benchstat.py` | pcap/pcapng 분석, 요약 표, 자체 점검 |

`tests/test_bench_benchstat.py`가 CI에서 `selftest`를 돌려 분석기가 깨지지 않았는지 확인합니다.
