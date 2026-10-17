# 보드 LAB — 네트워크 JTAG와 JTAG 게이트웨이 VM

보드 LAB의 보드는 두 가지 방식(`target`)으로 등록합니다.

| target | 연결 방식 | 연구자 VM 설정 | 화면 프로토콜 |
|---|---|---|---|
| `usb` (기존) | 보드가 꽂힌 Proxmox 노드에서 데스크톱 VM으로 USB 패스스루(`usb4=host=...`) | 대여 때 바뀜, 반납 때 원복 | 무엇이든 (데스크톱이 그 노드에서 돌아야 함) |
| `network` (권장) | **JTAG 게이트웨이 VM**(또는 다른 케이블 호스트)의 hw_server · XVC · jtagd에 연구자 툴이 TCP로 접속 | **바뀌지 않음** | RDP · Warpgate · SPICE 무엇이든, Windows · Linux 게스트 모두 |

일반 USB 장치(보안 키, 시리얼, 카메라 등 JTAG가 아닌 것)를 사용자 자리에서 쓸 때만 SPICE USB 리디렉션을
씁니다 — 이 부분은 바뀌지 않았습니다.

## JTAG 게이트웨이 VM

케이블을 Proxmox 호스트가 아니라 **게이트웨이 VM**에 모읍니다. 게이트웨이 VM은 작은 Linux VM으로
Vivado **Lab Edition**(무료, hw_server 포함)과 필요하면 Quartus Programmer(jtagd) · XVC 서버만 돌립니다.

- **게이트웨이는 빌드하지 않습니다.** 프로그래밍 · 디버그 트래픽만 중계합니다. 합성 · 구현은 연구자 VM이나
  빌드 팜(작업 큐)에서 합니다. 게이트웨이에는 Lab Edition만 설치하고 전체 Vivado는 설치하지 마십시오.
- 크기: 2–4 vCPU, 4–8 GB 메모리, 작은 디스크. 병목은 CPU가 아니라 **JTAG 클럭과 USB 대역폭**입니다.
  늘릴 때는 CPU를 더하지 말고, 케이블을 여러 PCIe USB 컨트롤러나 여러 게이트웨이 VM(대당 10–20개 정도)으로 나눕니다.
- 노드마다(또는 보드 묶음마다) 하나. 데스크톱 · 인프라 네트워크에 두고, 연구자 VM이 3121(hw_server) ·
  1309(jtagd) · 보드별 XVC 포트에 닿게 합니다.

### 케이블을 게이트웨이에 연결

콘솔 › 가속 자원 › JTAG 게이트웨이에서 게이트웨이 VM을 등록하고 케이블을 넘깁니다.

- **USB 장치 하나씩**: `vid:pid` 또는 포트 경로(`1-4.2`)를 게이트웨이 VM의 빈 `usbN` 슬롯(usb0–usb13)에 넘깁니다.
  VM이 켜진 채로 됩니다. 같은 케이블이 여러 개면 포트 경로로 지정합니다.
- **PCIe USB 컨트롤러 통째로 (케이블이 많을 때 권장)**: `0000:05:00.0` 같은 주소를 빈 `hostpciN`에 넘깁니다
  (q35 머신이면 `pcie=1`). 컨트롤러에 꽂힌 모든 케이블이 게이트웨이 안에서 바로 보이고, Platform Cable USB II처럼
  펌웨어를 올리며 ID가 바뀌는(재열거) 케이블도 끊기지 않습니다. VM 재시작이 필요합니다. IOMMU 그룹이 분리되는
  카드를 쓰십시오.
- 기존 데스크톱 VM 대상 USB 패스스루(usb4)는 그대로 동작합니다.

### 케이블 찾기 · 보드에 매핑

게이트웨이에 qemu-guest-agent를 설치해 두면 **케이블 찾기**가 게스트의 USB 장치(sysfs: vid:pid · 시리얼 · 제조사 ·
제품 · 포트)를 읽어 보여 줍니다. JTAG 벤더(03fd Xilinx, 0403 FTDI/Digilent, 1443 Digilent, 09fb Intel)가 위에 옵니다.
케이블 시리얼을 골라 보드로 등록합니다. 게이트웨이에서는 아무것도 바꾸지 않습니다.

### 보드 = 게이트웨이 + 케이블 시리얼

| protocol | 연구자가 접속하는 곳 | 케이블 고르기 |
|---|---|---|
| `hw_server` | 게이트웨이 `host:3121` | 케이블 시리얼(필수). Vivado 대상 `*/xilinx_tcf/<벤더>/<시리얼>` |
| `xvc` | 게이트웨이 `host:<보드별 XVC 포트>` | 포트가 곧 케이블 (케이블마다 XVC 서버 하나) |
| `quartus` | 게이트웨이 jtagd `host:1309` | 케이블 이름/시리얼(선택), jtagd 원격 암호 |

- **한 케이블, 한 보드, 한 사람**: 같은 게이트웨이에서 같은 케이블 시리얼 · XVC 포트 · UART 포트는 보드 하나에만
  등록됩니다. 대여할 때도 같은 케이블이 이미 빌려져 있으면 거절합니다. 예약은 보드 단위로 겹침을 막습니다.
- 대여해도 연구자 VM 설정은 바뀌지 않고, 포털 › 내 자원 › 내 보드(JTAG)에 접속 주소 · 케이블 시리얼 · Tcl 명령 ·
  UART 주소가 복사 버튼과 함께 나옵니다.
  - hw_server: Open Target › Open New Target › Remote server `게이트웨이:3121` › 목록에서 시리얼이 맞는 케이블.
    Tcl `connect_hw_server -url gw:3121` → `open_hw_target [lindex [get_hw_targets */<시리얼>] 0]`
- 게이트웨이 없이 케이블 호스트 주소를 직접 적는 방식(`host`/`port`)도 그대로 됩니다.

### UART 콘솔 (선택)

보드의 USB-UART를 게이트웨이에서 **ser2net**으로 TCP 포트에 내보내고, 보드에 그 `uart_port`를 적으면 포털에
`게이트웨이:포트`가 표시됩니다. 예 (`/etc/ser2net.yaml`, ser2net 4.x):

```yaml
connection: &zcu102-1
  accepter: tcp,7001
  connector: serialdev,/dev/serial/by-id/usb-FTDI_..._210251A08870-if01-port0,115200n81,local
  options:
    max-connections: 1
```

`/dev/serial/by-id/...`를 쓰면 재부팅 · 재연결 뒤에도 같은 보드를 가리킵니다. 연구자는 VM 안에서
`telnet gw 7001`, PuTTY(Raw/Telnet) 등으로 붙습니다. hw_server처럼 인증이 없으니 방화벽으로 좁힙니다.

### 원격 전원 (확장 지점)

보드에 `power`(JSON, 예 `{"driver": "pdu-x", "outlet": 7}`)를 적고, 사이트가 드라이버를 등록하면
`POST /api/vlab/admin/boards/<id>/power {"action": "on"|"off"|"cycle"}`가 그 드라이버를 부릅니다.

```python
from pegaprox.vlab import jtag_gw
def my_pdu(board, action, cfg): ...      # 실패하면 예외
jtag_gw.register_power_driver('pdu-x', my_pdu)
```

드라이버는 기본 제공하지 않습니다. 등록 전에는 501을 돌려줍니다.

### 상태 감시

2분마다 게이트웨이 VM이 켜져 있는지, hw_server(보드가 쓸 때) · jtagd(Quartus 보드가 있을 때) · 각 XVC 포트가
응답하는지 봅니다. 응답하지 않으면 **그 게이트웨이의 보드는 대여할 수 없음**으로 표시되고(관리자 목록 · 예약 옵션 ·
포털) 대여가 거절됩니다. 내려갈 때와 돌아올 때 알림 채널로 한 번씩 알립니다. 콘솔에서 **지금 점검**도 됩니다.

## API

- `GET/POST /api/vlab/admin/jtag-gateways`, `PUT/DELETE .../<id>` — `{name, cluster_id, vmid, host, hw_port, jtagd_port, notes}`
- `POST .../<id>/passthrough` `{kind: "usb", usb}` 또는 `{kind: "pci", pci}`, `DELETE .../<id>/passthrough/<slot>`
- `POST .../<id>/discover` — 게이트웨이가 보는 케이블 (게스트 에이전트)
- `POST .../<id>/check` — 상태 지금 점검
- `POST/PUT /api/vlab/admin/boards` — 네트워크 보드: `{target: "network", protocol, gateway_id, cable_serial, port(XVC), uart_port, label, power}`
  또는 `{target: "network", host, port, ...}`
- `POST /api/vlab/admin/boards/<id>/attach` · `.../detach` · 대여 만료 · 예약 — 네트워크 보드는 기록만 바뀌고
  `connection {endpoint, cable_serial, tcl, uart, howto}`을 돌려줍니다.
- `GET /api/vlab/me/boards` — 내게 빌려준 보드와 접속 정보 · 사용 가능 여부
- `POST /api/vlab/admin/boards/<id>/power` — 원격 전원 확장 지점

## 네트워크 분리 · 방화벽 (필수)

1. 게이트웨이 VM은 데스크톱 또는 인프라 존에 둡니다. 연구자 개인 PC를 케이블 호스트로 쓰면 데스크톱 VLAN →
   사용자 VLAN 통신을 열어야 해서 접근 차단 설계와 맞지 않습니다.
2. 데스크톱 VM → 게이트웨이 `3121` · `1309` · XVC · UART 포트만 허용합니다(추가형). 기존 Proxmox 보안 그룹(데스크톱
   직접 접속 차단)은 들어오는 방향이므로 그대로 둡니다. 엔진은 대여 기간에 맞춰 방화벽을 자동으로 여닫지 않습니다.
3. **hw_server · XVC · ser2net에는 인증이 없습니다.** 게이트웨이 쪽에서 허용 출발지를 보드 LAB 데스크톱 대역으로 좁힙니다.

배포 절차(템플릿 만들기, 전원 공급 USB 허브, PCIe USB 카드, 케이블 라벨, 확장)는 콘솔 저장소
`deploy/board-lab-jtag.md`에 있습니다.

## 실제 장비로 확인해야 할 것

- 실제 게이트웨이 VM과 케이블로 hw_server(케이블 시리얼로 고르기) · XVC · `jtagconfig --addserver` 연결
- PCIe USB 컨트롤러 패스스루(IOMMU 그룹, 재시작 뒤 케이블 재열거), usbN 슬롯 상한(머신 타입)
- 게스트 에이전트로 케이블 찾기, ser2net UART, 상태 감시 알림
- 데스크톱 VLAN → 게이트웨이 방화벽 허용과 출발지 제한
