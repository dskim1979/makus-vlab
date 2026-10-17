# Warpgate 접근 게이트웨이(bastion) 설계

MOAVI Desk의 데스크톱 접속을 **Warpgate**(github.com/warp-tech/warpgate, Apache-2.0, Rust)
하나로 중계한다. 모든 RDP/SSH/VNC가 Warpgate를 거치므로

- 데스크톱의 실제 IP가 사용자에게 보이지 않고(대상 주소 은닉),
- 세션이 녹화되며(session recordings),
- 접속할 때 **데스크톱 비밀번호를 저장·전달하지 않는다**(1회용 티켓).

Guacamole(브라우저 RDP/SSH), rdpGW/msrdGW(.rdp 게이트웨이), 그리고 방금 추가된
`/api/vlab/desktops/<id>/ssh`(Guacamole SSH)는 **그대로 두고**, Warpgate는 켜고 끌 수 있는
**추가(additive) · 전환(switchable)** 경로로 붙인다(`VLAB_WARPGATE=1`).

---

## 1. Warpgate API 확인 (소스 직접 확인)

Warpgate는 SSH·HTTP·RDP·VNC·MySQL·PostgreSQL·Kubernetes를 중계하는 bastion이다.
확인 근거는 repo의 OpenAPI 스키마(`warpgate-web/src/admin/lib/openapi-schema.json`),
DB 엔티티(`warpgate-db-entities/src/Ticket.rs`), 미들웨어(`warpgate-protocol-http/src/middleware/ticket.rs`),
프로토콜 테스트(`tests/test_*_user_auth_ticket.py`), SSO 설정(`warpgate-sso/src/config.rs`).

### 1-1. Admin HTTP API
- 인증: **`X-Warpgate-Token: <admin API 토큰>`** 헤더(OpenAPI `TokenSecurityScheme`). 토큰은
  Warpgate가 관리자 UI 또는 config에서 발급한다(사용자별 API 토큰, 역할로 admin 권한 부여).
- 주요 엔드포인트(관리자):
  - `POST /targets` (`TargetDataRequest`) → `Target` : 대상 등록(대상 종류별 옵션 kind=Ssh/Rdp/Vnc/...).
  - `GET/POST /roles`, `POST /targets/{id}/roles/{role_id}` : 역할과 대상-역할 연결.
  - `POST /users` (`CreateUserRequest{username, description}`) → `User`, `POST /users/{id}/roles/{role_id}`,
    `POST /users/{user_id}/credentials/sso` (`NewSsoCredential{provider, email}`) : 사용자·SSO 연결.
  - `POST /tickets` (`CreateTicketRequest`) → `TicketAndSecret{ticket, secret}` : **임시 접속 자격 발급**.
  - `GET /sessions`, `GET /sessions/{id}/recordings`, `GET /recordings/{id}` : 세션·녹화 조회.

### 1-2. 티켓(Access ticket) — 핵심
DB 엔티티 기준으로 티켓은 다음을 **모두** 만족한다.

| 속성 | 값 | 의미 |
|------|-----|------|
| `user_id` | UUID | **사용자 1명에 고정** |
| `target_id` | UUID | **대상 1개에 고정** |
| `uses_left` | `Option<i16>` | `number_of_uses=1` → **1회용**, 미지정 → 무제한 |
| `expiry` | `Option<datetime>` | **시간 제한** 가능 |
| `secret` | 생성 시 1회만 반환, DB엔 `secret_hash`만 | 평문 비저장 |

`spend_use()`가 `uses_left`를 **원자적으로 1 차감**(0이면 InvalidTicket)하므로 동시 재사용이 막힌다.
→ **"그 사용자 + 그 대상에만, 짧게, 1회"** 티켓을 엔진이 발급해 접속 좌표로 돌려준다.

### 1-3. 티켓 사용(redeem) — 비밀번호 불필요
Warpgate 프로토콜 테스트가 "티켓을 username으로 제시하고 **password는 쓰이지 않는다**"고 명시한다.

- **SSH(native)**: `ssh ticket-<secret>@<warpgate-host> -p <SSH 리스너 포트>` (비번 입력칸은 아무 값)
- **RDP**: RDP 사용자 이름 = `ticket-<secret>` (비번 무시). Warpgate RDP 리스너로 접속.
- **VNC**: VNC 사용자 이름 = `ticket-<secret>`.
- **HTTP 대상만**: `?warpgate-ticket=<secret>` 또는 헤더 `Authorization: Warpgate <secret>` 로 브라우저가
  로그인된다. **RDP/SSH 대상의 티켓으로는 웹 세션이 열리지 않고 티켓도 쓰이지 않는다** — 실제 Warpgate
  v0.29.2로 확인(아래 4-4, Warpgate 자체 테스트 `test_non_http_ticket_opens_no_session`).
- **브라우저 RDP/SSH (web-desktop/web-ssh)**: Warpgate 웹 UI(`/@warpgate#/`)에 **로그인한 사용자**가
  대상 목록에서 연다(`POST /@warpgate/api/web-desktop/sessions {target_id}` + 웹소켓). 그래서 엔진의
  브라우저 링크는 티켓 없는 웹 UI 주소이고, 사용자는 SSO/LDAP으로 로그인한다(비밀번호를 우리가 저장하지 않음).

### 1-4. 대상(Target) 옵션과 "비밀번호 저장 안 함" 처리
`TargetOptions`는 `kind`로 구분된다.

- **Vnc**: `auth`가 `None`을 허용 → 저장 자격 없이 대상 등록 가능(가장 깔끔).
- **Ssh**: `auth` = Password/**PublicKey**/Certificate. PublicKey면 Warpgate 자체 키를 대상에 심어
  비밀번호 저장을 피한다.
- **Rdp**: `auth`는 Password(스키마상 `password` **필수**) 뿐. 대신 `interactive_logon=true`로 두면
  **자동 로그인하지 않고 대상의 Windows 로그온 화면**을 띄운다 — 저장된 자격은 NLA/CredSSP 통과용으로만
  쓰이고 실제 사용자 로그인은 사용자가 자기 디렉터리 계정으로 직접 한다.
  → MOAVI Desk는 여기에 **사용자 비밀번호를 절대 넣지 않고**, NLA용 공용 **서비스 계정**(자동 로그인 아님)을
  쓰거나, 대상 Windows에서 NLA를 끄고 더미 값을 둔다. 엔진 DB엔 사용자 비번을 저장/전달하지 않는다.

### 1-5. SSO / 디렉터리 인증
- `config.yaml`의 `sso_providers[]`에 provider kind = `google`/`apple`/`azure`/**`custom`**(범용 OIDC:
  `issuer_url`·`client_id`·`client_secret`·`role_mappings`·`roles_claim`). → **외부 OIDC 인증 지원**.
- `auto_create_users: true`로 SSO 최초 로그인 시 사용자 자동 생성, `role_mappings`로 OIDC 그룹/클레임을
  Warpgate 역할에 매핑.
- admin API `/ldap-servers`(+`import-users`)로 **LDAP 인증**도 지원 → 번들 Samba AD에 직접 바인드 가능.
- MOAVI Desk 연동: 포털 계정 = 디렉터리 계정이므로 (a) Warpgate를 번들 디렉터리에 LDAP로 묶거나,
  (b) MOAVI Desk/디렉터리가 OIDC 공급자가 되면 `custom`으로 묶는다. 어느 쪽이든 **비밀번호 미저장** 원칙 유지.

---

## 2. 엔진 통합 설계

- 전용 모듈 `pegaprox/vlab/warpgate.py`(규칙·테이블·API 클라이언트)와
  블루프린트 `pegaprox/api/vlab_warpgate.py`.
- 테이블 `vlab_warpgate`(1행 설정): `base_url`, `admin_token_encrypted`(=`get_db()._encrypt`, nas.py 패턴),
  `ssh_port`/`rdp_port`/`vnc_port`(리스너), `enabled`, 점검 결과. 대상 매핑은 `vlab_warpgate_targets`
  (MOAVI Desk desktop/external id ↔ Warpgate target UUID + kind).
- HA: `vlab_warpgate`·`vlab_warpgate_targets`를 `ha.SYNC_TABLES`에, `admin_token_encrypted`를
  `ha.ENCRYPTED_COLUMNS`에 등록.
- 대상 동기화: 데스크톱/외부 데스크톱 ↔ Warpgate target을 맞춘다(없으면 생성, 주소·포트 바뀌면 갱신).
- 접속: 포털 사용자가 연결하면 엔진이 `POST /tickets`로 **그 사용자+그 대상**에 `number_of_uses=1`,
  짧은 `expiry` 티켓을 발급하고 접속 좌표(native SSH/RDP/VNC + 브라우저 URL)를 돌려준다.
  엔진은 secret을 응답에만 싣고 저장하지 않는다. **사용자 비밀번호는 절대 저장·전달하지 않는다.**

## 3. 직접 접속 차단
데스크톱의 22/3389(및 VNC)은 **Warpgate에서만** 닿게 한다 — 기존
`deploy/proxmox-firewall/`의 보안 그룹 방식을 재사용해 relay 집합(IPSET)에 Warpgate 주소를 추가한다.
(console 저장소 `deploy/proxmox-firewall/` 참조.)

## 4. 콘솔
- Warpgate 게이트웨이 설정 페이지(base URL·API 토큰·포트·연결 테스트),
- 포털 연결을 Warpgate 경유로 라우팅,
- 관리자에서 녹화 세션 링크.

## 4-1. 연구자 네이티브 SSH (자기 SSH 도구로 게이트웨이 통과)
연구자가 PuTTY·scp/pscp·WinSCP·VS Code Remote-SSH·git·rsync 를 **평소처럼** 쓰되 Warpgate를
투명하게 거치게 한다(풀 정책 `researcher_ssh`, 브라우저 SSH와 별개).

- **Warpgate는 점프 호스트가 아니다.** 저장소 README: "Not a jump host — forwards connection
  straight to the target ... receives connections with specifically formatted credentials."
  즉 `ssh -J`(ProxyJump)가 아니라 **SSH 사용자 이름에 대상을 넣어** 대상을 고른다:
  `User moavi-<아이디>:<target>` + `HostName <warpgate>` + `Port <ssh_port>`. 그래서 대상 IP가 드러나지
  않는다. (처음 피어 지시의 ProxyJump 대신 이 형식을 쓴 이유 — Warpgate가 그렇게 동작한다.)
- **공개키 등록(비밀번호·개인키 비저장)**: 사용자가 포털 "내 계정" 또는 MOAVI Desk 클라이언트로
  자기 **공개키**를 올리면 엔진이 Warpgate `POST /users/<id>/credentials/public-keys`
  (`NewPublicKeyCredential{label, openssh_public_key}`)로 등록한다. 엔진은 개인키처럼 보이면
  거부하고(`PRIVATE KEY`), 공개키를 자기 DB에 저장하지 않는다(보관은 Warpgate).
- **클라이언트 자동 구성**: `GET /api/vlab/me/ssh-config` 가 Warpgate host/port/login과 researcher_ssh
  데스크톱별 `~/.ssh/config` 항목(`Host moavi-<name>` 한 개 = `User moavi-<아이디>:<target>`)을 준다.
  MOAVI Desk Windows 클라이언트가 이를 `%USERPROFILE%\.ssh\config` 의 **관리 블록(BEGIN/END MOAVI)**
  안에만 써 넣어, PuTTY/WinSCP/VS Code가 데스크톱 이름만 고르면 바로 붙는다(블록 밖은 건드리지 않음).
- **파일 전송(scp/SFTP)**은 브라우저 SSH와 같은 `ssh_files`류 정책을 따르고 Warpgate가 기록한다.
  셸은 본질적으로 유출을 완전히 막지 못하므로, 엄격한 풀은 researcher_ssh를 끄고 브라우저 터미널만
  허용하거나 셸/scp를 제한한다(문서에 명시).

## 4-2. 공존과 전환 (web_rdp_provider)
- Warpgate는 **추가(additive)** 다. 내장 Guacamole 브라우저 RDP/SSH, 외부 데스크톱 "브라우저로 연결",
  방금 커밋한 `/ssh`(Guacamole SSH)는 **끄지 않고 그대로** 둔다 — 브라우저리스/원격/크롬북/태블릿
  사용자의 유일한 접속 수단이라 절대 끊기면 안 된다.
- 설정 `web_rdp_provider`(기본 `guac`)가 전환점이다. 브라우저 RDP는 실클러스터에서 Warpgate 웹 RDP가
  검증될 때까지 **Guacamole가 기본**이다. 포털의 기존 "브라우저 RDP로 열기"는 그대로 Guacamole로
  동작하고, Warpgate 연결은 **별도 메뉴**로 추가되어 둘 다 쓸 수 있다. → 기본 설정에서 브라우저 RDP는
  Guacamole가 서비스한다.
- **Warpgate로 전환한 경로는 장애 시 닫힌다(fail closed)**: `web_rdp_provider=warpgate` 이거나
  `rdp_via_warpgate` 가 켜진 상태에서 Warpgate가 응답하지 않으면, 엔진은 직접 `.rdp`나 Guacamole로 몰래
  돌리지 않고 `503 WG_DOWN`("보안 게이트웨이에 연결할 수 없습니다. 잠시 뒤 다시 시도하세요.")을 돌려준다
  (사용자 화면에는 Warpgate 대신 "보안 게이트웨이"로 표시). 몰래 돌리면 bastion을 우회하고, 직접 접속을 막은 현장에서는 어차피 실패한다.
  관리자가 **"Warpgate 장애 시 직접 접속 허용"**(`allow_direct_fallback`, 기본 꺼짐, 보안 약화)을 켠
  경우에만 그 접속을 직접 `.rdp`/Guacamole로 열고 감사 기록(`vlab.warpgate.fallback`)을 남긴다.
- `GET /api/vlab/me/warpgate` 가 `enabled`·`web_rdp_provider`를 주어 포털이 무엇을 보일지 정한다.
- **전용 앱·mstsc(.rdp)**: 설정 `rdp_via_warpgate`(기본 꺼짐). 켜면 `POST /api/vlab/desktops/<id>/connect
  {protocol:rdp}` 의 `.rdp`가 데스크톱 주소 대신 Warpgate RDP 리스너를 향하고, 사용자 이름에 그 사용자·
  데스크톱 전용 1회용 티켓(`ticket-<secret>`)이 들어간다(비밀번호 없음, 응답에 `via: warpgate`). 풀 정책의
  리디렉션·네트워크 자동 감지 줄은 그대로, `enablecredsspsupport:i:0`(Warpgate RDP는 NLA 없는 TLS),
  `prompt for credentials:i:0`, 자동 재연결 끔(티켓 1회용). 대상은 `interactive_logon` 이라 데스크톱
  로그온 화면에서 사용자가 본인(AD) 계정을 입력한다. Warpgate 오류 시 `503 WG_DOWN`(fail closed);
  `allow_direct_fallback` 을 켠 경우에만 그 접속을 직접 `.rdp`로 연다.
  클라이언트는 파일을 그대로 mstsc로 열고 "Warpgate 경유"를 안내한다.

## 4-3. 실(real) Warpgate + Proxmox 클러스터 검증 체크리스트
Warpgate 자체는 4-4의 CI 통합 테스트로 확인했다. 아래는 **실제 Proxmox 클러스터의 데스크톱**으로
사람이 확인해야 할 항목이다. 전부 통과하기 전에는 기본 경로(Guacamole)를 끄지 않는다.

- [ ] **브라우저 RDP (Warpgate)**: Warpgate 웹 UI에 SSO/LDAP으로 로그인 → 목록의 데스크톱을 열면
      화면이 뜬다(CI에서는 xrdp 컨테이너로 확인).
- [ ] **네이티브 RDP**: `ticket-<secret>` 사용자 이름으로 Warpgate RDP 포트에 붙어 접속된다
      (interactive_logon: 데스크톱 Windows 로그온 화면, 사용자 계정으로 로그인).
- [ ] **네이티브 SSH (자기 도구)**: `ssh moavi-<name>`, `scp`, WinSCP, VS Code Remote-SSH가
      `~/.ssh/config` 관리 블록으로 바로 붙고, 공개키로 인증된다(비밀번호 안 물음).
- [ ] **브라우저 SSH (Warpgate)**: Warpgate 웹 UI(로그인 사용자)에서 터미널이 열린다(티켓 아님).
- [ ] **사용자 본인 계정 로그인**: Windows/AD 데스크톱에서 `interactive_logon` + GPO "연결 시 항상
      암호 묻기"로 로그온 화면이 뜨고 사용자가 자기 AD 계정으로 들어간다(4-4 참조).
- [ ] **VNC**: (해당 풀이 있으면) VNC 접속이 된다.
- [ ] **세션 녹화**: 위 세션들이 Warpgate 관리자 녹화 페이지에서 재생된다.
- [ ] **직접 접속 차단**: 데스크톱 IP로 직접 RDP/SSH/VNC → 막힘(Proxmox 보안 그룹, relay=Warpgate).
- [ ] **1회용 티켓**: 한 번 쓴 티켓 재사용 불가, 만료 뒤 불가.
- [ ] **비밀번호 비저장**: 엔진 DB·로그에 사용자/데스크톱 비밀번호가 없다(봉인된 관리자 토큰·NLA
      서비스 계정만).
- [ ] **디렉터리 로그인**: Warpgate가 OIDC/LDAP로 포털·디렉터리 계정을 인증한다(config.yaml).
- [ ] **unattended-setup**: 컨테이너 첫 기동이 설정을 만들고 재기동이 안전하다(--if-config-exists skip).

통과하면 전환: `web_rdp_provider=warpgate` 로 바꾸고(필요 시) Guacamole 경로를 내린다. 제거 방법과
되돌리기는 아래 5절.

## 4-4. 실제 Warpgate 통합 테스트 결과 (GitHub Actions)
워크플로 `.github/workflows/warpgate-integration.yml`(브랜치 claude/warpgate 푸시·수동 실행)이 Warpgate
v0.29.2 바이너리(sha256 고정)를 unattended-setup으로 띄우고, OpenSSH 컨테이너(Warpgate 클라이언트 키
신뢰)와 xrdp 데스크톱 컨테이너를 대상으로 `tests/test_warpgate_live.py`를 돌린다. 엔진 코드 그대로
실제 관리자 API를 쓴다. 첫 통과: https://github.com/dskim1979/makus-vlab/actions/runs/39008519880

| 확인 | 결과 |
|---|---|
| 관리자 API 연결(토큰) | 통과 |
| 대상 동기화 생성·수정·제거 | 통과 (매핑이 없을 때 409 → 기존 대상 인수, 실제 테스트에서 발견해 고침) |
| 사용자·공개키 등록 | 통과 (사용자-역할 연결 API가 JSON 본문을 요구 — 실제 테스트에서 발견해 고침) |
| 1회용 티켓(그 사용자+그 대상) | 통과 |
| Warpgate 경유 SSH — 티켓 | 통과, 두 번째 사용은 거부(1회용) |
| Warpgate 경유 SSH — 등록한 공개키 | 통과 |
| scp(파일 전송) | 통과 |
| RDP 티켓 로그인 → 데스크톱 | 통과 (Warpgate 로그: `RDP target state=Connected`, 녹화됨) |
| 브라우저 RDP(web-desktop, 로그인 사용자) | 통과 (세션 생성·스트림·녹화) |
| 엔진이 만든 `.rdp`(앱·mstsc 경로)로 접속 | 통과 (xfreerdp가 그 파일 그대로 → `RDP target state=Connected`, 녹화) — run 39010002125 |
| 브라우저 링크 | 웹 UI 응답. **티켓으로는 RDP/SSH 웹 세션 불가**(Warpgate 설계) — 링크에 티켓을 넣지 않음 |

**누구 계정으로 데스크톱에 들어가나**: Warpgate는 대상마다 하나의 접속 자격(RDP는 사용자명·비밀번호,
SSH는 Warpgate 자체 키 + 대상 사용자명)으로 대상에 붙는다. 사용자 본인 계정으로 들어가려면
- **RDP(Windows/AD)**: `interactive_logon=true`로 자동 로그온을 끄고 데스크톱 GPO "연결 시 항상 암호
  묻기"를 켜면, 대상 계정(NLA 서비스 계정)은 네트워크 수준 인증에만 쓰이고 사용자가 로그온 화면에서
  자기 AD 계정을 입력한다. 우리는 사용자 비밀번호를 저장하지 않는다. 이 화면 흐름은 실제 Windows/AD
  데스크톱에서 확인해야 한다(CI의 xrdp는 NLA가 없어 같은 경로가 아님).
- **SSH**: 지금 대상 사용자명은 고정(`moavi`). 전용 풀은 데스크톱마다 사용자가 하나이므로, 대상
  사용자명을 배정된 사용자의 디렉터리 계정으로 하고 Warpgate 클라이언트 공개키를 그 계정(AD/sssd의
  authorized keys 또는 게스트 에이전트)으로 신뢰시키면 본인 계정으로 들어간다 — 후속 작업.

## 4-5. 실환경(VM 117) 테스트 뒤 고친 것

- **프로토콜마다 대상 1개**: Warpgate는 대상 종류(Ssh↔Rdp)를 바꿀 수 없다. 매핑 키는 `target_ref(ref, proto)` —
  RDP는 데스크톱 id 그대로, SSH/VNC는 `<id>-ssh` / `<id>-vnc`. 예전 엔진의 SSH 매핑(데스크톱 id 그대로)은
  시작할 때 `<id>-ssh`로 옮기고, 그 대상이 RDP가 쓸 이름을 갖고 있으면 다음 동기화 때 SSH 이름으로 바꾼 뒤
  RDP 대상을 새로 만든다(손으로 정리할 필요 없음).
- **SSH 호스트 키**: SSH 대상을 동기화할 때 엔진이 데스크톱 22번의 호스트 키를 읽어(ssh-keyscan과 같음)
  `POST /ssh/known-hosts`에 올린다. 같은 주소·같은 종류의 옛 키는 바꾼다. 실패해도 동기화는 계속(로그만).
- **대상 정리**: 데스크톱을 지우거나 사용자 배정이 풀리면 그 데스크톱의 모든 Warpgate 대상을 지운다(백그라운드).
- **웹 링크**: `#/web-desktop/start/<uuid>`(RDP/VNC), `#/web-ssh/start/<uuid>`(SSH) — 로그인 뒤 그 데스크톱으로 바로.
- **Warpgate 연결 실패**: 사용자에게는 `WG_DOWN`(503)과 짧은 문구만, 내부 주소가 든 원인은 서버 로그에만.
- **첫 기동 자동 연결**: `VLAB_WARPGATE=1`, `VLAB_WARPGATE_URL`(예: `https://<host>:8888`, 사용자에게 보이는 주소),
  `VLAB_WARPGATE_ADMIN_PASSWORD`가 있고 설정이 비어 있으면 엔진이 Warpgate 관리자로 로그인해 1년짜리 API 토큰을
  만들고 봉인해 저장한다(포트: SSH `VLAB_WARPGATE_SSH_PORT`=2222, RDP `VLAB_WARPGATE_RDP_PORT`=3389,
  VNC `VLAB_WARPGATE_VNC_PORT`=5900; 웹 RDP는 guac 유지). 선택: `VLAB_WARPGATE_ADMIN_USER`(admin),
  `VLAB_WARPGATE_VERIFY_TLS`. 기존 설정은 절대 덮어쓰지 않고, 토큰·비밀번호는 로그에 남기지 않는다.
  Warpgate가 늦게 뜨면 10초 간격으로 30번 다시 시도한다.

## 4-6. Warpgate 로그인 = MOAVI Desk 로그인 (OIDC, `pegaprox/vlab/wg_oidc.py`)

Warpgate 0.29.2는 RDP/SSH 대상 티켓으로 웹 세션을 열지 않으므로, 브라우저 경로는 Warpgate 로그인이 필요하다.
엔진이 Warpgate 하나만을 위한 최소 OIDC 공급자가 되어 그 로그인을 포털 세션으로 대신한다(비밀번호 없음).

- 켜기: `VLAB_WARPGATE_OIDC_SECRET`(엔진·Warpgate 같은 값). 비우면 꺼짐(엔드포인트 404).
- `warpgate.yaml`:
  ```yaml
  sso_providers:
    - name: moavi-desk
      label: MOAVI Desk
      provider:
        type: custom
        client_id: warpgate
        client_secret: <VLAB_WARPGATE_OIDC_SECRET>
        issuer_url: http://vlab-engine:5000/api/vlab/oidc   # VLAB_WARPGATE_OIDC_ISSUER와 같게
        scopes: [email, profile]
  ```
- 엔드포인트: `/api/vlab/oidc/.well-known/openid-configuration`, `/jwks`, `/token`, `/userinfo`(issuer 기준,
  Warpgate가 서버에서 부름), `/authorize`(콘솔 주소 `VLAB_PUBLIC_URL` 또는 `https://VLAB_HOSTNAME`, 브라우저가 포털
  세션 쿠키를 들고 옴). PKCE S256 필수, redirect_uri는 Warpgate 호스트의 `/@warpgate/api/sso/return`만.
- ID 토큰: RS256(키는 한 번 만들어 `vlab_wg_oidc`에 봉인, HA 동기화), `email`은 실제 주소가 아니라
  `<아이디>@moavi-desk.invalid`. 엔진이 Warpgate 사용자에 SSO 자격(provider `moavi-desk` + 그 이메일)을 붙인다.
  `warpgate_roles` 클레임을 보내지 않으므로 Warpgate는 역할을 건드리지 않는다.
- 코드는 1분·1회용, 액세스 토큰은 5분, 메모리에만.
- 한계: Warpgate 로그인 화면은 처음 들어올 때 SSO를 스스로 시작하지 않는다(사용자 이름 입력 뒤에만). 그래서
  첫 접속엔 **MOAVI Desk** 버튼 한 번이 남는다. 완전 무클릭은 Warpgate를 콘솔과 같은 출처(`/@warpgate/`)로
  프록시하고 콘솔 페이지가 `/@warpgate/api/sso/providers/moavi-desk/start`를 불러야 가능(후속).

## 4-7. 엔진이 만드는 Warpgate 사용자 (`moavi-<아이디>`)

실환경에서 발견: 포털 `admin`이 Warpgate 자체 슈퍼관리자 `admin`에 붙고, SSO 자격까지 달려 MOAVI Desk 로그인이
Warpgate 관리자 권한이 됐다. 지금은:
- 엔진이 만드는 Warpgate 사용자는 항상 `moavi-<포털 아이디>`이고 설명이 `MOAVI Desk managed user`로 시작한다.
  티켓·SSH 사용자 이름(`moavi-<아이디>:<대상>`)·공개키·SSO 자격 모두 이 사용자에게만 간다.
- 같은 이름이라도 엔진이 만들지 않은 사용자이거나 Warpgate 관리자 역할이 있으면 자격·역할을 붙이지 않고 거부한다.
- 업그레이드 때 한 번(`vlab_warpgate_state`): 접두어 없는 Warpgate 사용자에게서 엔진이 붙였던 것만 뗀다 —
  provider `moavi-desk` + `<그 이름>@moavi-desk.invalid` SSO 자격, `moavi-desk` 역할. 그 사용자들에 등록했던 공개키는
  남지만 역할이 없어 어떤 대상에도 못 붙는다. 연구자는 포털에서 공개키를 다시 등록한다(`moavi-<아이디>`로 감).

## 4-8. Windows 데스크톱의 NLA 서비스 계정 자동 설정 (`moavi-nla`)

실환경에서 발견: 콘솔에 NLA 계정이 없으면 Warpgate → Windows RDP가 CredSSP `STATUS_LOGON_FAILURE`로 실패했다.
지금은 Warpgate가 Windows 데스크톱으로 RDP를 열기 전(포털 보안 게이트웨이 연결, Warpgate .rdp, Warpgate 브라우저 RDP)
엔진이 게스트 에이전트(SYSTEM PowerShell)로:
- 로컬 계정 `moavi-nla`를 만들거나 비밀번호를 다시 넣는다(비밀번호 만료 없음). 비밀번호는 엔진이 데스크톱마다
  무작위로 만들어 `vlab_warpgate_nla`에 봉인하고, **stdin으로만** 넘긴다(명령줄·로그·사용자 응답에 없음).
- Remote Desktop Users(`S-1-5-32-555`)에 넣고, 로컬 콘솔 로그온은 막는다(SeDenyInteractiveLogonRight).
- `fPromptForPassword=1` — 세션은 Windows 로그온 화면에서 멈추고 사용자가 **자기 계정**으로 로그인한다.
- 도메인 컨트롤러는 건너뛴다(로컬 계정 없음). 도메인 구성원은 로컬 계정으로 동작하지만 GPO가
  `fPromptForPassword`를 덮을 수 있다.
- 그 데스크톱의 Warpgate RDP 대상에 이 계정을 넣는다. 콘솔의 전역 `rdp_nla_user/password`가 있으면 그것이 우선.
- 6시간마다 다시 확인하고, 초기화(기본 스냅숏 되돌리기)·재생성·삭제·배정 변경 때 비밀번호를 버려 다음 연결에서
  새로 만든다. 사용자·데스크톱 비밀번호가 아니라 이 데스크톱 전용 서비스 자격이다.

## 4-9. 웹 SSH 파일 패널 = 풀의 파일 전송 정책

MOAVI Desk Warpgate 빌드(포크 moavi4)는 웹 SSH에 파일 패널(SFTP)이 있고, SSH 대상 옵션 `web_file_transfer`(기본 켜짐)로
끈다. 엔진은 SSH 대상을 만들 때 풀 정책 `ssh_files`가 `off`면 `false`, 그 밖(down/up/both)이면 `true`를 넣는다(패널은
켜고 끄기만 있음 — 내려받기만/올리기만 구분은 아직 없음). 정책의 켜짐/꺼짐이 바뀌면 그 풀 데스크톱의 기존 SSH 대상도
다시 맞춘다(백그라운드). 이 옵션을 모르는 Warpgate가 400으로 거부하면 옵션을 빼고 대상을 만든다.

## 5. 무엇이 무엇을 대체하나
- **대체 대상(택일)**: 내장 Guacamole(브라우저 RDP/SSH), rdpGW/msrdGW(.rdp 게이트웨이),
  방금 커밋한 `/ssh`(Guacamole SSH). Warpgate 하나가 네 가지를 한 bastion으로 통합.
- **유지**: 위 경로들은 끄지 않고 그대로 둔다. Warpgate는 `VLAB_WARPGATE=1`일 때만 추가로 동작.
- **실제 검증 필요(클러스터 있어야 함)**: 실제 Warpgate 컨테이너에 대한 티켓 발급/사용,
  RDP `interactive_logon` + NLA 서비스 계정 동작, VNC None auth, 번들 디렉터리 LDAP/OIDC 연동,
  Proxmox 방화벽에서의 실제 차단, 세션 녹화 저장.

### 5-1. 제거(삭제)는 검증 후에만 — 별도 커밋
사용자가 실클러스터 검증(4-3)을 **문제없이** 확인한 뒤에만 대체 대상을 지운다. 그래서 삭제는
**main Warpgate 커밋에 섞지 않고**, 적용 준비가 된 **별도 커밋**(제목에 "apply only after
real-cluster verification passes")으로 브랜치 맨 위에 둔다. 그 커밋이 지우는 것:
- 번들 Guacamole 컨테이너·배선(docker-compose의 guacd/guacamole/vlab-guac-key/vlab-guac,
  `VLAB_GUACAMOLE`, 엔진의 내장 Guacamole 게이트웨이 등록),
- 방금 커밋한 Guacamole 브라우저-SSH 엔드포인트 `/api/vlab/desktops/<id>/ssh` 와 관련 정책 필드,
- 남아 있는 rdpGW 언급(번들하지 않음).

검증 전에는 이 커밋을 적용하지 않는다(브라우저 RDP가 끊길 수 있음). 되돌리기: 해당 커밋을
`git revert` 하거나, 적용 전이라면 단순히 적용하지 않는다. 커밋 해시·요약·롤백은 최종 보고 참조.
