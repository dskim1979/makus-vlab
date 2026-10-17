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

## 4-1. 연구자 네이티브 SSH (자기 SSH 도구로 게이트웨이 통과)
연구자가 PuTTY·scp/pscp·WinSCP·VS Code Remote-SSH·git·rsync 를 **평소처럼** 쓰되 Warpgate를
투명하게 거치게 한다(풀 정책 `researcher_ssh`, 브라우저 SSH와 별개).

- **Warpgate는 점프 호스트가 아니다.** 저장소 README: "Not a jump host — forwards connection
  straight to the target ... receives connections with specifically formatted credentials."
  즉 `ssh -J`(ProxyJump)가 아니라 **SSH 사용자 이름에 대상을 넣어** 대상을 고른다:
  `User <wguser>:<target>` + `HostName <warpgate>` + `Port <ssh_port>`. 그래서 대상 IP가 드러나지
  않는다. (처음 피어 지시의 ProxyJump 대신 이 형식을 쓴 이유 — Warpgate가 그렇게 동작한다.)
- **공개키 등록(비밀번호·개인키 비저장)**: 사용자가 포털 "내 계정" 또는 MOAVI Desk 클라이언트로
  자기 **공개키**를 올리면 엔진이 Warpgate `POST /users/<id>/credentials/public-keys`
  (`NewPublicKeyCredential{label, openssh_public_key}`)로 등록한다. 엔진은 개인키처럼 보이면
  거부하고(`PRIVATE KEY`), 공개키를 자기 DB에 저장하지 않는다(보관은 Warpgate).
- **클라이언트 자동 구성**: `GET /api/vlab/me/ssh-config` 가 Warpgate host/port/login과 researcher_ssh
  데스크톱별 `~/.ssh/config` 항목(`Host moavi-<name>` 한 개 = `User <wguser>:<target>`)을 준다.
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
  동작하고, Warpgate 연결은 **별도 메뉴**로 추가되어 둘 다 쓸 수 있다. → 브라우저 RDP는 항상
  {Guacamole, Warpgate} 중 적어도 하나가 서비스하며, 둘 다 꺼지는 상태가 없다.
- `GET /api/vlab/me/warpgate` 가 `enabled`·`web_rdp_provider`를 주어 포털이 무엇을 보일지 정한다.

## 4-3. 실(real) Warpgate + Proxmox 클러스터 검증 체크리스트
우리 작업은 **코드 + 모킹 테스트**뿐이다. 아래는 실제 Warpgate 컨테이너와 Proxmox 클러스터에서
사람이 확인해야 할 항목이다. 전부 통과하기 전에는 기본 경로(Guacamole)를 끄지 않는다.

- [ ] **브라우저 RDP (Warpgate)**: 포털 Warpgate 연결 → 새 탭에서 데스크톱 화면이 뜨고 로그인된다.
- [ ] **네이티브 RDP**: `ticket-<secret>` 사용자 이름으로 Warpgate RDP 포트에 붙어 접속된다
      (interactive_logon: 데스크톱 Windows 로그온 화면, 사용자 계정으로 로그인).
- [ ] **네이티브 SSH (자기 도구)**: `ssh moavi-<name>`, `scp`, WinSCP, VS Code Remote-SSH가
      `~/.ssh/config` 관리 블록으로 바로 붙고, 공개키로 인증된다(비밀번호 안 물음).
- [ ] **브라우저 SSH (Warpgate)**: 티켓으로 브라우저 터미널이 열린다.
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
