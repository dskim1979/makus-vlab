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
- **HTTP/브라우저**: `https://<warpgate>/?warpgate-target=<대상이름>` + 헤더 `Authorization: Warpgate <secret>`,
  또는 `?warpgate-ticket=<secret>`. 브라우저 안에서 RDP/SSH 세션을 Warpgate가 직접 그려준다.

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

## 5. 무엇이 무엇을 대체하나
- **대체 대상(택일)**: 내장 Guacamole(브라우저 RDP/SSH), rdpGW/msrdGW(.rdp 게이트웨이),
  방금 커밋한 `/ssh`(Guacamole SSH). Warpgate 하나가 네 가지를 한 bastion으로 통합.
- **유지**: 위 경로들은 끄지 않고 그대로 둔다. Warpgate는 `VLAB_WARPGATE=1`일 때만 추가로 동작.
- **실제 검증 필요(클러스터 있어야 함)**: 실제 Warpgate 컨테이너에 대한 티켓 발급/사용,
  RDP `interactive_logon` + NLA 서비스 계정 동작, VNC None auth, 번들 디렉터리 LDAP/OIDC 연동,
  Proxmox 방화벽에서의 실제 차단, 세션 녹화 저장.
