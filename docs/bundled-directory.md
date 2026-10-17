# 내장 디렉터리 설계 노트 (Samba AD DC)

## 왜

AD 가 있는 기관은 포털 로그인과 데스크톱 로그인이 같은 계정이다(기존 AD/LDAP 로그인 + AD 그룹 풀 권한).
AD 가 없는 곳은 포털 계정과 데스크톱(Windows · Linux) 계정이 따로라서, 사용자는 두 비밀번호를 갖고 관리자는 VM 마다 계정을 만들어야 했다.
내장 디렉터리는 설치 묶음에 **선택형 Samba AD DC** 를 넣어 AD 가 없는 곳도 **포털 계정 = 데스크톱 계정** 이 되게 한다.
AD 가 있는 기관은 쓰지 않는다(그 AD 를 그대로 쓴다).

## 결정

| 항목 | 결정 | 이유 |
|---|---|---|
| 디렉터리 | Samba 4.17 AD DC (Debian 12), 내부 DNS, RFC2307 | Windows 도메인 가입 · GPO · Kerberos 가 그대로 되고, Linux 는 sssd/realmd 표준 경로. RFC2307 로 uid/gid 가 모든 VM 에서 같다(NFS 소유자) |
| 켜기 | `.env` `VLAB_DIRECTORY=1` (기본 꺼짐), compose `replicas` | 내장 Guacamole 과 같은 방식 |
| 주인 | **포털이 정하고 디렉터리가 따른다** | 사용자 · 부서 · 사용 기한 · 승인은 이미 포털에 있다. DC 는 인증과 그룹만 |
| 엔진 권한 | `vlab-svc` 는 `OU=MOAVI` 전체 권한만, `vlab-join` 은 `OU=Desktops` 의 컴퓨터만 | 도메인 관리자 권한을 엔진에 두지 않는다 |
| 포털 행 표시 | `auth_source='ldap'`, `ldap_dn` 이 `OU=Users,OU=MOAVI,…` 아래 | 핵심 users 표에 열을 늘리지 않음(HA 동기화 · 스키마 그대로) |
| 로그인 | 기존 `ldap_authenticate` 를 내장 DC 로(LDAPS 636, DC 의 CA 로 인증서 확인). 사이트가 자기 LDAP 를 켜면 그쪽이 우선 | 로그인 경로를 새로 만들지 않음 |
| 역할 | 내장 계정의 역할 · 테넌트 · 권한은 로그인 때 DC 가 덮어쓰지 않음(그룹만 갱신) | 포털이 주인 |
| 관리자 | 기본은 포털 계정으로 남김(`include_admins`) | DC 가 멈춰도 콘솔에 들어올 수 있게 |

## 비밀번호 (가장 중요한 규칙)

- 엔진은 사용자 비밀번호를 **저장 · 기록하지 않는다**. 비밀번호는 그것을 실은 요청 안에서 DC 의 비밀번호 설정(LDAPS `unicodePwd`)으로만
  가고 요청과 함께 사라진다. 테스트(`tests/test_vlab_directory.py`)가 엔진 DB 의 모든 표에 그 문자열이 없음을 확인한다.
- 사용자가 정하는 순간: 가입 신청 · 비밀번호 찾기 링크 · 내 계정 변경(현재 비밀번호는 DC 가 직접 확인) · 관리자 초기화 · CSV 일괄 등록의 첫 비밀번호.
- 가입 신청: 신청 때 **사용 중지된 DC 계정**을 만들어 비밀번호를 거기 둔다. 신청 행에는 해시가 없다(`password_salt='directory'`).
  승인하면 켜고, 거절하면 지운다. DC 가 그때 멈춰 있으면 예전처럼 포털 해시로 받고, 승인 뒤 첫 로그인 때 옮긴다.
- 켜기 전부터 있던 포털 계정, DC 가 멈춰 있을 때 만든 계정: **다음 로그인 때** 맞는 비밀번호가 확인된 그 순간 DC 로 옮기고 포털 해시를 지운다.
- 데스크톱 자동 로그인을 위한 비밀번호 보관은 하지 않는다(만들지 않기로 함).
- 엔진 자신의 두 계정: `vlab-svc` 비밀번호는 DC 컨테이너가 만들어 공유 볼륨에 두고(엔진은 읽기 전용), 엔진은 HA 상대를 위해 봉인 사본을 둔다.
  `vlab-join` 비밀번호는 엔진이 만들어 DC 에 넣고 핵심 DB 키로 봉인한다(NAS 서비스 계정과 같은 방식, 키 교체 · HA 동기화 포함).

## 하나의 비밀번호 (포털 = 데스크톱)

- 포털이 받는 비밀번호는 DC 도 받아야 한다. 엔진은 포털 정책과 DC 정책(도메인 객체의 `minPwdLength`, `pwdProperties` 복잡도 비트,
  5분 캐시)을 합친 규칙을 `GET /api/vlab/password-policy` 로 내고(`unified`, `domain` 포함), DC 로 비밀번호를 보내는 모든 함수가
  보내기 전에 그 규칙으로 검사한다(`PASSWORD_POLICY`, 400). 복잡도는 AD 와 같다: 대문자 · 소문자 · 숫자 · 기호 중 셋, 아이디나 이름의 일부(3자 이상) 금지.
- 콘솔: 가입 · 비밀번호 찾기 · 내 계정 화면이 그 규칙을 보여 주고 같은 규칙으로 미리 검사하며, "이 비밀번호로 포털과 데스크톱 모두 로그인합니다" 를 알린다.
  DC 에서 실패하면 포털도 바꾸지 않고 사용자에게 그 이유를 보여 준다(엔진 로그 · 감사에도 남음).
- CSV 일괄 등록의 첫 비밀번호는 그 규칙에 맞게 만들고, 가입 승인은 신청 때 이미 규칙을 통과한 비밀번호를 켠다.

## AD 디렉터리 (관리 콘솔)

- 소스: 내장 DC(`vlab-svc`) 또는 도메인(AD/LDAP) 에 설정한 기관 AD(그 서비스 계정). "연결 확인" 은 바인드와 기준 DN 에서 만들 수 있는
  클래스(`allowedChildClassesEffective`)를 보여 준다 — 기관 AD 에서 바꾸려면 서비스 계정에 그 OU 의 권한을 위임해야 한다(읽기 전용 계정이면 DENIED).
- 트리(OU · 컨테이너), 목록(사용자 · 그룹 · 컴퓨터 · OU, 검색), 사용자 · 그룹(보안/메일 그룹, 전역/유니버설/도메인 로컬) · OU 만들기 · 바꾸기 · 사용 중지 ·
  삭제(OU 는 비었을 때만), 그룹 구성원 직접 · 중첩 보기, 추가 · 제거(자기 자신 · 순환 거부). 바꾸는 것마다 감사 기록(`vlab.ad.*`), 비밀번호는 기록하지 않음.
- 내장 DC 에서 엔진이 포털을 위해 둔 것(`info=moavi-desk`: 포털 계정, `moavi-users`, 부서 그룹)과 `OU=Users` 에 새 사용자 만들기는 여기서 막는다 — 포털이 주인.
  디렉터리에서 무엇을 바꿔도 포털 부서는 움직이지 않는다.

## 계정 흐름

| 포털에서 | DC 에서 |
|---|---|
| 계정 만들기 · CSV 등록 | 같은 이름의 계정(+ 그 비밀번호), `moavi-users` · 부서 그룹 |
| 가입 신청 / 승인 / 거절 | 사용 중지 계정 + 비밀번호 / 켬 / 지움 |
| 사용 중지 · 사용 기한 만료 / 다시 사용 | `userAccountControl` 사용 중지 / 켬 |
| 이름 · 메일 · 부서 바꿈 | `displayName` · `mail` · 그룹 구성원 |
| 삭제 · 만료 후 삭제 | 계정 삭제(엔진이 만든 것만, `info=moavi-desk`) |
| 부서 만들기 · 이름 · 상위 · 삭제 | `dep-<id>` 그룹(설명=이름), 하위 그룹은 상위 그룹의 구성원 / 삭제 |

- 즉시 반영하고, 실패하면 `vlab_directory_accounts` 에 남긴다. 활성 서버의 분 단위 루프가 10분마다 전체를 맞춘다
  (포털에 없는 엔진 계정은 지움, 대기 중인 가입 계정과 엔진이 만들지 않은 계정은 그대로).
- 사용자 이름: AD `sAMAccountName` 은 20자까지 — 더 긴 포털 계정은 포털 계정으로 남는다.

## 데스크톱 도메인 가입

- QEMU 게스트 에이전트, 요청 안에서 실행(백그라운드 스레드 없음). 비밀번호는 에이전트 stdin 으로만.
- Windows: DNS 를 DC 로(설정) → SRV 확인 → `Add-Computer -OUPath OU=Desktops -NewName MD-{vmid}` → `moavi-users` 를 원격 데스크톱 사용자에 → (선택) 15초 뒤 재시작.
  **템플릿은 sysprep /generalize 필수**.
- Linux: `realm join --computer-ou`, sssd 짧은 이름 · 홈 폴더, `realm permit -g moavi-users`. 템플릿에 realmd · sssd · adcli · mkhomedir.
- 상태는 데스크톱마다 `vlab_directory_joins`(joined / failed / other / not_joined / pending, 코드, 컴퓨터 이름). 가입한 데스크톱의 RDP 파일은 `도메인\아이디`.

## 이중화

- HA 상대 서버에 두 번째 DC(`VLAB_DIRECTORY_ROLE=replica`, `samba-tool domain join … DC`). DC 끼리 복제, 각 서버의 엔진은 자기 서버의 DC(`VLAB_DIRECTORY_HOSTNAME.<realm>` 별칭, 그 DC 가 만든 CA)를 쓴다. 두 번째 DC 쪽 엔진은 `vlab-svc` 비밀번호를 HA 동기화된 봉인 사본에서 읽는다.
- 엔진 쪽 상태(봉인된 계정, 계정 · 가입 상태 표)는 HA 동기화 표에 넣었다. 맞춤은 활성 서버만, 대기 서버는 DC 에 쓰지 않는다.
- DC 사이에는 실제 주소가 필요해서 macvlan 구성을 권한다(`docker-compose.directory-macvlan.yml`).
- 한계: Samba 는 SYSVOL 을 복제하지 않는다(GPO 파일은 rsync), FSMO 는 첫 DC.

## 실제 클러스터에서 확인할 것 (테스트는 모의)

- DC 컨테이너의 첫 시작(프로비저닝, `dsacl` 위임, `user.NTACL` xattr, `samba_dnsupdate --current-ip`), NAT 로 게시한 포트로 Windows 가입과 Kerberos 로그인.
- 엔진 → DC LDAPS: 인증서 확인(별칭 = 인증서 이름), `unicodePwd` 설정, `vlab-svc` 위임으로 계정 · 그룹 · `vlab-join` 비밀번호 설정.
- Windows 게스트 에이전트의 stdin 전달(`[Console]::In`), `Add-Computer -NewName`, 재시작 뒤 `MOAVI\아이디` RDP · Guacamole 로그인.
- Linux `realm join` 의 stdin 비밀번호, sssd 설정, NFS 소유자(RFC2307 uid).
- 두 번째 DC 합류와 `drs showrepl`, 첫 DC 정지 중 로그인.
