# 보드 LAB — 네트워크 JTAG (hw_server · XVC · Quartus jtagd)

보드 LAB의 보드는 이제 두 가지 방식(`target`)으로 등록합니다.

| target | 연결 방식 | VM 설정 | 화면 프로토콜 |
|---|---|---|---|
| `usb` (기존) | 보드가 꽂힌 Proxmox 노드에서 USB 패스스루(`usb4=host=...`) | 대여 때 바뀜, 반납 때 원복 | 무엇이든 (데스크톱이 그 노드에서 돌아야 함) |
| `network` (신규) | JTAG 케이블 호스트의 TCP 서버에 연구자 툴이 직접 접속 | **바뀌지 않음** | RDP · Warpgate · SPICE 무엇이든, Windows · Linux 게스트 모두 |

FPGA JTAG는 **네트워크 방식이 기본 권장**입니다. 일반 USB 장치(보안 키, 시리얼, 카메라 등 JTAG가 아닌 것)를
사용자 자리에서 쓸 때만 SPICE USB 리디렉션을 씁니다 — 이 부분은 바뀌지 않았습니다.

## 지원 프로토콜

| protocol | 서버 (케이블 호스트에서 실행) | 기본 포트 | 연구자 쪽 (VM 안) |
|---|---|---|---|
| `hw_server` | Xilinx `hw_server` (Vivado Lab Edition 포함) | 3121 | Vivado Hardware Manager › Open Target › Open New Target › Remote server `host:3121` · Tcl `connect_hw_server -url host:3121` |
| `xvc` | Xilinx Virtual Cable 서버 (보드의 XVC 서버, 또는 xvcserver/xvcd) | 2542 | Hardware Manager › Add Xilinx Virtual Cable (XVC) `host:2542` · Tcl `open_hw_target -xvc_url host:2542` |
| `quartus` | Intel `jtagd` (Quartus Programmer/Lab에 포함), `jtagconfig --enableremote <암호>` | 1309 | Programmer › Hardware Setup › JTAG Settings › Add Server · `jtagconfig --addserver host <암호>` |

포트는 등록 때 바꿀 수 있습니다(비우면 위 기본값).

## API

- `POST/PUT /api/vlab/admin/boards` — `{"target": "network", "name", "cluster_id", "host", "port", "protocol", "label", "kind", "notes"}`.
  네트워크 보드는 `usb` · `node`가 없습니다(빈 값으로 저장). `host`는 호스트 이름 또는 IPv4.
- `POST /api/vlab/admin/boards/<id>/attach` — 네트워크 보드면 VM 설정을 건드리지 않고 대여(누구에게 · 언제까지)만
  기록하고 `connection {endpoint, protocol, howto}`를 돌려줍니다. 데스크톱 노드 제한이 없고, 같은 데스크톱에
  USB 보드(usb4 슬롯)와 함께 빌려줄 수 있습니다.
- 반납(`.../detach`), 대여 기간 만료 자동 반납(분 단위 루프), 카드 · 보드 예약(시작 때 대여 · 끝에 반납)은
  USB 보드와 같은 흐름이고, 네트워크 보드는 기록만 지웁니다.
- `GET /api/vlab/me/boards` — 내게 빌려준 보드. 네트워크 보드는 `connection`(host:port와 사용법)을 담습니다.
  포털 › 내 자원에 복사 버튼과 함께 표시됩니다.

## 네트워크 분리 · 방화벽 (필수)

네트워크 보드는 **데스크톱 VM이 케이블 호스트의 해당 포트(TCP)에 닿아야** 동작합니다.

1. **케이블 호스트는 공용 랩 서버로 두십시오.** 보드와 케이블을 인프라/데스크톱 존(데스크톱 VLAN에서 닿는 랩 VLAN)의
   공용 서버(작은 Linux 서버, Vivado Lab Edition · Quartus Programmer만 설치)에 꽂는 것을 권장합니다.
   연구자 개인 PC를 케이블 호스트로 쓰면 데스크톱 VLAN → 사용자 VLAN 통신을 열어야 해서,
   "데스크톱은 MOAVI Desk 서버/게이트웨이를 통해서만 닿는다"는 접근 차단 설계와 맞지 않습니다.
2. **방화벽 허용을 추가하십시오(추가형).** 데스크톱 VM → 케이블 호스트 `host:port`(hw_server 3121, XVC 2542,
   jtagd 1309) 방향만 허용합니다. 기존의 Proxmox 보안 그룹(데스크톱 직접 접속 차단)은 들어오는 방향을 막는 것이므로
   그대로 두고, 나가는 방향에 이 허용만 더합니다. 이 브랜치의 엔진은 대여 기간에 맞춰 방화벽 규칙을 자동으로
   열고 닫지 않습니다 — 대여는 "누가 쓰는가"의 기록과 안내이고, 경로는 배포 방화벽이 정합니다.
3. **hw_server · XVC에는 인증이 없습니다.** 포트에 닿는 누구나 보드를 조작할 수 있으므로 케이블 호스트는
   랩 VLAN에 두고, 허용 출발지를 보드 LAB 데스크톱 풀의 대역으로 좁히십시오. jtagd는 원격 암호를 씁니다.
4. 한 hw_server에 여러 사용자가 동시에 붙으면 서로 방해합니다. 케이블(보드)마다 별도 등록 · 대여로 한 번에
   한 사람이 쓰게 하고, 케이블이 여러 개면 hw_server를 포트별로 따로 띄우거나 XVC 서버를 보드마다 둡니다.

## 실제 장비로 확인해야 할 것

- 실제 클러스터 · 실제 케이블에서 Vivado `connect_hw_server` / XVC / `jtagconfig --addserver` 연결
- 데스크톱 VLAN → 랩 VLAN 방화벽 허용(Proxmox 보안 그룹 또는 상위 방화벽)
- Versal 등에서 Vivado가 hw_server 외에 쓰는 디버그 포트가 있는지(현장 버전 기준) 확인
