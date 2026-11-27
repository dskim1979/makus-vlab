# 데스크톱 SSO (비밀번호 없는 Windows 로그온) — Windows 모듈 개발 문서

> **실장비 결과 (2026-11-27, .55 / VM 119 Server 2022 + Samba 4.17) — 지금 결론: VM 안의 키로는 RDP SSO가 안 된다.**
>
> | 시도 | 결과 |
> |---|---|
> | 인증서 해시(`USE_CERTIFICATE_INFO`) | 항상 `STATUS_INVALID_PARAMETER` |
> | CSP 정보 + Software KSP 키(머신/SYSTEM) | `0xc0000384` NO_KEY_CONTAINER |
> | CSP 정보 + CAPI(Enhanced AES) 키 | `0xc0000321` SMARTCARD_SUBSYSTEM_FAILURE |
> | 자체 KSP(moavi-logon-ksp.dll) | LSASS가 아예 부르지 않음(카드 경로는 리더→카드→컨테이너) |
> | **TPM 가상 스마트카드(1.2.x)** — LsaLogonUser 직접(selftest, 세션 0) | **성공**(4624 MOAVI\test) |
> | TPM 가상 스마트카드 — 실제 RDP 로그온(LogonType 10) | `0xc0000321`, "스마트 카드 리소스 관리자가 실행되고 있지 않습니다", LSASS가 카드에 접근 안 함. 스마트카드 리디렉션 끔(`fEnableSmartCard=0`) + 재부팅 후도 같음 |
>
> 이유: RDP 세션의 로그온은 **클라이언트가 RDP 스마트카드 채널(MS-RDPESC)로 내주는 카드만** 쓴다. Warpgate는
> 그 채널을 내주지 않는다. → 남은 길은 **게이트웨이(Warpgate, IronRDP 클라이언트)가 RDP 스마트카드 채널로 가상
> 카드를 내주는 것**(Teleport Desktop Access와 같은 구조: 게이트웨이가 세션마다 키를 만들고 엔진이 짧은 인증서를
> 발급, 카드는 PIV 에뮬레이션). 이 저장소의 엔진 발급(`logon_ca`), CP(세션 바인딩·자동 제출, `mode=vsc`일 때
> reader/card/container/PIN을 CSP 정보로)와 CA 신뢰 설치는 그대로 쓴다. VM 안 TPM 카드 방식(설치 시 vTPM 필요)은
> 콘솔 로그온에서만 유효.
>
> **구현 상태 (2026-11-27, 브랜치 claude/moavi-logon)** — 아래 원래 규격(§1~§7)에서 바뀐 점:
>
> - **자체 KSP·상주 서비스 없음.** 키는 VM 안 **Microsoft Software KSP**의 머신 키(SYSTEM 전용 ACL,
>   내보내기 불가)로 만들고, CP는 `KERB_CERTIFICATE_LOGON` + `KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO`
>   (인증서 해시 → `MY` 저장소, SDK `NTSecAPI.h`에 문서화된 방식)로 제출한다. LSASS에는 Microsoft 자체
>   KSP만 들어가므로 **LSA 보호(RunAsPPL)가 켜진 VM에서도** 된다. 비상용으로 `mode=csp`
>   (`KERB_SMARTCARD_CSP_INFO`, CSP 이름 = Microsoft Software KSP, 컨테이너 = 키 이름)도 남겨 두었다.
> - Windows 쪽은 둘: `moavi-logon.exe`(엔진이 guest-exec로 SYSTEM으로 부름: `prepare` / `arm` / `status` /
>   `clear`)와 `moavi-logon-cp.dll`(LogonUI가 부르는 CP). 소스 `windows/moavi-logon/`, 빌드 `build.cmd`
>   (MSVC 2022, x64, 정적 CRT) → 결과물을 `pegaprox/vlab/logon_agent/`에 복사, 엔진이 그대로 배포한다.
> - 대기 로그온은 `C:\ProgramData\MoaviLogon\pending.txt`(폴더 ACL SYSTEM·Administrators만)에 키 이름,
>   인증서 해시, 만료, 게이트웨이 주소만 적는다(비밀 없음). CP는 원격 세션 + 클라이언트 주소가 게이트웨이 +
>   미사용 + 만료 전일 때만 타일을 내고, 넘기기 **전에** `used`로 바꿔 1회만 쓰이게 하고, 결과를 받으면 키와
>   인증서를 지운다. 기록 `C:\ProgramData\MoaviLogon\logon.log`(비밀 없음).
> - 엔진: `pegaprox/vlab/logon_ca.py`(CA 봉인 저장·서명·발급 기록), `pegaprox/api/vlab_logon.py`(API, 연결 훅,
>   설치), 풀 정책 `desktop_sso`(기본 꺼짐). 인증서: UPN SAN, EKU 스마트카드 로그온 + clientAuth, 유효 5분
>   (설정 1~30분, notBefore는 5분 앞당김), CDP `http://192.168.0.55:8089/moavi-logon.crl`(설정/`VLAB_LOGON_CRL_URL`).
>   발급마다 `vlab_logon_issued`와 감사 로그 `vlab.logon.issue`(사용자·데스크톱·포털 세션 해시·일련번호·만료).
> - 흐름: 풀에 `desktop_sso`가 켜져 있으면 포털 연결(.rdp via Warpgate, 브라우저 RDP)이 티켓을 내기 전에
>   `prepare → 서명 → arm`을 한다. 실패하면 로그만 남기고 평소 로그온 화면(= 지금 상태)으로 간다.
>   장치 연결 방식(rdpgw)은 mstsc가 NLA로 먼저 비밀번호를 묻기 때문에 아직 대상이 아니다.
> - API: `GET/PUT /api/vlab/admin/logon-sso`(설정: `gateway_ips` = VM이 보는 RDP 클라이언트 주소, `ttl_min`,
>   `crl_url`, `allow_admins`), `POST /api/vlab/admin/logon-sso/ca`(`{cert_pem,key_pem}` 또는 `{from_dir:true}` —
>   엔진 시작 때 `VLAB_LOGON_CA_DIR` 또는 디렉터리 파일 폴더 `/pki`의 `ca.pem`+`ca.key`를 한 번 가져옴),
>   `POST /api/vlab/admin/desktops/<id>/logon-sso/install`(모듈 + CA를 Root·NTAuth에, 게스트 에이전트로),
>   `GET …/logon-sso/status`, `POST /api/vlab/me/desktops/<id>/logon-sso`(포털 사용자가 직접 준비).

> 포털에 로그인한 사용자가 보안 게이트웨이(Warpgate)로 Windows 데스크톱을 열면, **비밀번호를
> 저장하지도 묻지도 않고** 바탕 화면까지 들어가게 한다. Citrix FAS / VMware Horizon True SSO와
> 같은 구조다. 이 문서는 **Windows VM 안에서 동작하는 모듈**(Credential Provider + KSP + 에이전트
> 서비스)을 만들 개발자를 위한 규격이다. 엔진·콘솔 쪽은 MOAVI 팀(또는 이 저장소)이 맡는다.

## 0. 지금 상태 (이 문서를 읽기 전 배경)

- 현재 기본 동작(이 문서로 바꾸지 않는 안전한 기본값): Warpgate가 RDP 대상을 `interactive_logon=true`로
  열어 **데스크톱 Windows 로그온 화면까지** 띄우고, 사용자가 자기 AD 비밀번호를 **한 번** 친다.
  비밀번호는 어디에도 저장하지 않는다. → `docs/warpgate-gateway.md`.
- NLA(CredSSP) 통과는 데스크톱별 로컬 서비스 계정 `moavi-nla`가 담당한다(사용자 계정 아님). 사용자는
  로그온 화면에서 자기 계정으로 로그인한다. → `pegaprox/api/vlab_warpgate.py` `prepare_windows_nla`,
  `pegaprox/vlab/warpgate.py` `NLA_USER`.
- 내장 디렉터리는 Samba AD DC(4.17, Heimdal KDC)다. → `docs/bundled-directory.md`.

### 이미 실제 장비에서 확인한 것 (2026-10-18 스파이크, 192.168.0.9 / VM 116 moavi.lan)

1. **Samba KDC의 PKINIT 동작**: `/var/lib/samba/private/krb5.conf`의 `[kdc]`에 `enable-pkinit`을 넣고
   DC를 재시작하면, Heimdal KDC가 **인증서만으로** TGT를 발급한다. 리눅스 클라이언트에서
   `kinit -X X509_user_identity=FILE:user.pem,user.key admin@MOAVI.LAN` → KINIT_OK, klist에
   `krbtgt/MOAVI.LAN` TGT 확인.
2. **Windows 콘솔 인증서 로그온**: VM 116에 vTPM을 붙이고, 로그온 CA를 Root + NTAuth에 넣고, TPM
   가상 스마트카드에 사용자 인증서(UPN SAN, Smartcard Logon EKU)를 **카드에서 키 생성** 방식으로
   넣으면(`certreq -new`, Microsoft Smart Card KSP), Proxmox 콘솔의 Windows 로그온 화면에서 **PIN만으로**
   `moavi\admin` 도메인 로그온이 된다. klist에 AES256 TGT, `\\dc1.moavi.lan\sysvol` 열림.
3. **RDP 세션에서는 VM 안 가상 카드가 안 보인다**: Warpgate 웹 RDP(시험 B)와 mstsc + `redirectsmartcards:i:0`
   (시험 C) 모두 로그온 화면에 스마트카드 타일이 뜨지 않았다. RDP 세션의 LogonUI는 **클라이언트에서
   리디렉션된** 카드만 본다. → **그래서 VM-상주 가상 카드(a안)로는 RDP SSO가 안 되고, 이 문서의
   b안(자체 CP+KSP)이 필요하다.**

### 스파이크에서 나온 제약 (설계에 반드시 반영)

- **NTLM 자격 없음**: 인증서 로그온 세션에는 NTLM 자격이 없다(`\\<IP>\sysvol` 실패). Samba KDC가
  PAC_CREDENTIAL_INFO를 주지 않기 때문으로 보인다(미확인). → IP/NTLM로 여는 자원은 다시 비밀번호를
  요구한다. 사용자에게 **이름(Kerberos)으로 접근**하도록 안내해야 하고, 홈드라이브 매핑 등도 FQDN으로.
- **시간 동기화**: 내장 DC에 NTP 서버가 없다. 인증서 수명을 수 분으로 짧게 하려면 VM 시계가 DC와
  5분 이내여야 한다 → DC가 NTP를 제공하거나 조인 스크립트가 신뢰 NTP 피어를 지정해야 한다(엔진 과제).
- **SCardSvr**: Server 2022는 Smart Card 서비스가 기본 Disabled다. 모듈 설치 시 Automatic으로 바꿔야 한다.

## 1. 전체 흐름

```
포털 로그인(사용자)                 엔진(makus-vlab)                 VM 안 모듈
     │                                   │                              │
     │ "연결" (RDP) ───────────────────▶ │                              │
     │                                   │ 1) Warpgate 티켓 발급          │
     │                                   │ 2) guest-exec: prepare ──────▶│ 세션 키 1쌍 생성(메모리)
     │                                   │                              │ CSR + nonce 반환
     │                                   │◀───── CSR, nonce ────────────│
     │                                   │ 3) 로그온 CA로 서명            │
     │                                   │   (UPN SAN, Smartcard Logon,  │
     │                                   │    유효 ~10분)                │
     │                                   │ 4) guest-exec: arm ──────────▶│ {cert, nonce, 만료,
     │                                   │                              │  게이트웨이 IP} 보관(메모리)
     │ ◀── 접속 좌표/.rdp ──────────────│                              │
     │                                   │                              │
     │ RDP 접속 (Warpgate, moavi-nla NLA)                              │
     │ ───────────────────────────────────────────────────────────────▶│ 로그온 화면: 우리 CP 활성
     │                                   │                              │ CP→서비스: "이 세션 대기 로그온?"
     │                                   │                              │ 서비스: 세션 검증(아래 §4)
     │                                   │                              │ CP: KERB_CERTIFICATE_LOGON 자동 제출
     │                                   │                              │ LSASS PKINIT → KSP가 서명
     │                                   │                              │ Samba KDC TGT → 바탕 화면
     │                                   │                              │ cert/키 즉시 폐기(1회용)
```

- **실패해도 연결은 막지 않는다**: prepare/arm이 실패하거나 서비스가 없으면, 로그온 화면은 평소대로
  비밀번호를 받는다(= 지금 상태, §0). SSO는 "되면 좋은" 추가 경로다. 절대 fail-closed로 로그온을 막지 말 것.

## 2. 구성 요소 (세 가지, 모두 이 모듈 개발 범위)

### 2-1. MoaviLogon 서비스 (`moavi-logon.exe`, SYSTEM, 상주)
- `prepare`, `arm` 명령을 guest-exec(=qemu-guest-agent, 엔진이 SYSTEM으로 호출)로 받는다.
  - **prepare**: RSA 2048 키쌍을 **메모리에** 생성. 디스크·레지스트리·TPM에 쓰지 않는다. 개인키는 프로세스
    메모리 밖으로 절대 나가지 않는다. 표준 PKCS#10 CSR(Subject 비워도 됨, 엔진이 SAN을 넣음)과 임의
    `nonce`(16바이트 이상)를 base64로 stdout에 돌려준다.
  - **arm**: stdin JSON `{cert_b64, nonce, not_after(UTC), gateway_ips:[...], session_hint?}`를 받아
    "대기 로그온"으로 보관. cert는 prepare의 그 키에 맞는 것만 받는다(공개키 일치 확인).
- 로컬 named pipe 서버(`\\.\pipe\MoaviLogon`, DACL: SYSTEM + 로그온 세션만). CP와 KSP가 여기에 붙는다.
  - CP용: `QueryPending(sessionId, clientAddr) → {has, upn, cspData}` / `Consume(id)`.
  - KSP용: `Sign(hash, padding) → sig` / `Decrypt(blob) → plain`. 메모리 키로 처리, 로직 없음.
- **대기 로그온은 1회용**: 소비되거나 `not_after`가 지나면 즉시 메모리에서 삭제(키·cert zero화).
- 상태 보고: 설치됨/LSA 보호로 비활성/준비됨을 레지스트리나 파일로 남겨 엔진 조인 체크가 읽게 한다.

### 2-2. 로그온 모듈 `moavi_cp.dll` (Credential Provider)
- 베이스 권장: **Microsoft Windows-classic-samples의 SampleV2CredentialProvider(MIT)**. 거기서
  "자격 수집 → 직렬화" 틀을 그대로 쓰고, 입력 UI 대신 서비스에서 받은 값을 넣는다.
- `CPUS_LOGON`/`CPUS_UNLOCK` 시나리오에서:
  - 서비스에 `QueryPending(WTSGetActiveConsoleSessionId 또는 현재 세션, WTSClientAddress)` 질의.
  - 대기 로그온이 **없으면 타일을 숨긴다**(`SetUsageScenario`에서 자격 0개). 그러면 평소 비밀번호
    화면이 그대로 → 안전한 기본값.
  - 있으면 자동 선택 타일 하나를 `cpgsrAutoLogon`으로 반환, `GetSerialization`에서
    **KERB_CERTIFICATE_LOGON**(`NTSecAPI.h`) 구조로 직렬화. `CspData`에는
    `KERB_SMARTCARD_CSP_INFO`(CSP 이름 = 우리 KSP, 컨테이너 이름 = nonce/세션 id, 인증서 참조)를 넣는다.
    `Pin`은 비운다(우리 KSP는 PIN 없이 서비스에 위임).
  - `UserName`/`DomainName`은 cert의 UPN에서(선택). `Flags`에 `KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO`.
- UI는 없어도 된다(자동 로그온). 단 실패 시 `SetSerialization` 오류를 LogonUI가 평소 화면으로 되돌리게.

### 2-3. 키 저장 공급자 `moavi_ksp.dll` (CNG KSP)
- LSASS가 PKINIT에서 개인키 연산을 요청할 때 호출된다. **로직 없는 전달자**다.
- CNG KSP는 공급자 쪽 함수 테이블(`NCRYPT_KEY_STORAGE_FUNCTION_TABLE`)을 export하는 `GetKeyStorageInterface`
  로 구현한다. 함수 테이블 시그니처는 Cryptographic Provider Development Kit(CPDK)의 `ncrypt_provider.h`에
  있다(Windows SDK엔 없음). 최소 구현 대상:
  - `OpenProvider`/`FreeProvider`, `OpenKey`/`FreeKey`(cert에서 공개키·컨테이너 식별), `GetKeyProperty`
    (`NCRYPT_ALGORITHM_PROPERTY`=RSA, `NCRYPT_KEY_USAGE_PROPERTY` 등),
  - `SignHash` → 서비스 `Sign`으로 위임, `Decrypt` → 서비스 `Decrypt`로 위임,
  - 나머지(Create/Import/Export/Enum 등)는 `NTE_NOT_SUPPORTED`로 충분(스파이크 로그로 실제 호출 순서 확인).
- 등록: `BCryptRegisterProvider` + `NCryptRegisterProvider`로 KEY_STORAGE 인터페이스 공급자 등록.
- **서명 정책 주의(§6)**: LSA 보호(RunAsPPL) 켜진 VM에선 MS 서명 없는 KSP가 LSASS에 로드되지 않는다.

## 3. 엔진 쪽 규격 (모듈이 기대하는 상대편; 엔진 팀이 구현)
- 로그온 CA: MOAVI Desk Logon CA, 봉인 저장. 발급 cert = Subject UPN SAN, EKU Smartcard Logon
  (1.3.6.1.4.1.311.20.2.2) + clientAuth, 유효 ~10분, CDP = `http://<engine>/pki/moavi-logon.crl`.
- KDC 인증서: EKU `1.3.6.1.5.2.3.5`(+serverAuth), SAN DNS=DC FQDN + krbtgt otherName, 같은 CDP.
- DC: entrypoint가 시작 때 `private/krb5.conf`에 `[kdc]` PKINIT 블록 병합(스파이크에서 `/etc` 수정은
  재시작에 사라짐 확인). CA를 Root+NTAuth, KDC 인증서는 KDC가 쓰게.
- guest-exec 명령 두 개(`prepare`/`arm`)의 입출력은 §2-1 그대로. 발급 대상 제한: OU=Users,OU=MOAVI 계정만.

## 4. 세션 바인딩 (아무 RDP나 통과하면 안 됨)
CP가 자동 제출하기 전, 서비스가 **모두** 만족할 때만 "대기 로그온 있음"으로 답한다:
1. 세션이 **원격 세션**이다(콘솔 세션엔 적용 안 함; 콘솔은 평소대로 비밀번호/스마트카드).
2. `WTSQuerySessionInformation(WTSClientAddress)`의 주소가 **arm으로 받은 gateway_ips**에 든다
   (Warpgate RDP 리스너의 주소). 직접 RDP는 이미 보안 그룹으로 게이트웨이만 허용(deploy proxmox-firewall).
3. 대기 로그온이 **미사용**이고 `not_after` 이전이다.
4. (선택) `session_hint`(연결 직전 엔진이 준 값)와 세션 속성 일치.
소비 즉시 폐기. 2번을 못 믿는 환경이면 로그온을 열지 말 것(그 경우 비밀번호 화면).

## 5. 단계별 개발과 판정 (M0가 관문)
- **M0 (관문, 2~3일)**: CP+KSP 최소판. 키·cert는 파일에서 읽는 **시험용**(서비스/엔진 없이).
  VM 116에 수동 설치(콘솔). **판정: Warpgate 웹 RDP와 mstsc 둘 다 비밀번호·PIN 없이 바탕 화면이 뜨면 통과.**
  ← 가장 큰 위험(LSASS가 KERB_CERTIFICATE_LOGON에서 우리 KSP를 부르는지). 실패하면 여기서 멈추고 보고.
  * M0 디버깅용: KSP의 모든 호출을 `C:\ProgramData\MoaviLogon\m0\ksp.log`에 남겨 LSASS 호출 순서를 본다.
- **M1**: 서비스(prepare/arm, 메모리 키, 파이프, §4 세션 검증) + 엔진 cert로 교체.
- **M2**: 엔진 연동(guest-exec 훅), 1회용·만료·재접속, 감사.
- **M3**: WiX MSI, 설치 시 SCardSvr=Automatic·CA 신뢰·LSA 보호 감지, 조인 스크립트에 설치 경로.
- **M4**: 192.168.0.9 / VM 116 검증표 — 웹 RDP / mstsc / 재접속(끊긴 세션) / 만료 후 거부 / 다른 세션(직접
  RDP) 거부 / 모듈 없음→비밀번호 화면 / 엔진 재시작.

## 6. 위험과 경계
- **KSP/CP 버그 = 그 VM의 로그온 장애**. 반드시 시험 VM에서만, 콘솔 비밀번호 로그온은 항상 남긴다.
  설치 전 시스템 복원/스냅샷.
- **LSA 보호(RunAsPPL)**: 켜진 VM(Win11 22H2+ 새 설치 등)은 MS 서명 없는 KSP 불가. 모듈은 감지해서
  "SSO 지원 안 함"으로 보고하고 CP를 끈다. 제품화 시 코드 서명(EV)·WHQL 검토.
- **엔진 CA 키 = MOAVI 사용자 누구로든 로그온할 수 있는 열쇠**. 봉인 저장, 발급 대상 제한, 감사 로그.
  (엔진은 이미 MOAVI OU 전체 권한 계정을 들고 있어 위험이 크게 늘지는 않는다.)
- **VM 로컬 관리자인 사용자**는 자기 세션 동안 메모리의 키를 들여다볼 수 있다 → 공유 데스크톱엔 쓰지 말고
  **개인 할당 데스크톱**만. 풀 재할당 시 초기화 전제.
- **NTLM 없음·시간 동기화**: §0 제약 그대로.
- 코드 서명 없으면 MSI는 SmartScreen 경고(관리 배포라 영향 작음). CP(LogonUI)는 서명 없어도 로드되나,
  KSP는 위 LSA 보호 조건을 받는다.

## 7. 베이스 코드·참고
- Microsoft Windows-classic-samples `Security/CredentialProvider` (SampleV2, MIT) — CP 베이스.
- Microsoft CPDK(Cryptographic Provider Development Kit)의 SampleKSP — KSP 함수 테이블·등록 참고.
- `NTSecAPI.h`: `KERB_CERTIFICATE_LOGON`, `KERB_SMARTCARD_CSP_INFO`, `KerbCertificateLogon`.
- Citrix FAS / VMware True SSO 공개 아키텍처 문서(설계 대조용).
- 스파이크 원본 기록·되돌리기 스크립트: side-session-notes의 `desktop-sso-spike-runbook.md`,
  설계 전반 `desktop-sso-phase1.md` / `desktop-sso-plan-b.md`.

> **이 저장소 경계**: 엔진(CA·발급·CRL·DC 설정·guest-exec 훅·감사)과 콘솔(풀 정책 스위치·상태 칩)은
> MOAVI 팀이 구현한다. §2의 Windows 3종(서비스·CP·KSP)은 Windows 시스템 개발자가 구현한다. 둘은 §2-1/§3의
> 규격(prepare/arm 입출력, 파이프 인터페이스, KERB_CERTIFICATE_LOGON 직렬화)으로만 맞물린다.
