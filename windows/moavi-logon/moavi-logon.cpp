// moavi-logon.exe - the engine's side of MOAVI Desk desktop sign-in, run as SYSTEM through the
// guest agent (qemu-guest-agent guest-exec).
//
//   moavi-logon.exe prepare   new RSA-2048 key for one logon (Microsoft Software KSP, machine key,
//                             not exportable); prints csr=<base64 PKCS#10> and nonce=<hex>.
//                             Any earlier pending key / certificate is removed first.
//   moavi-logon.exe arm       stdin key=value lines: nonce, cert (base64 DER, signed by the MOAVI
//                             Desk Logon CA for that key), not_after (unix), gateways (comma list
//                             of the gateway addresses the RDP session must come from), user,
//                             domain. The certificate is put next to its key; the credential
//                             provider then signs that one RDP session in, once.
//   moavi-logon.exe status    version, credential provider registration, pending state.
//   moavi-logon.exe clear     forget the pending logon (key and certificate removed).
//   moavi-logon.exe selftest [all]
//                             LsaLogonUser with the armed certificate, as the credential provider
//                             would hand it to LogonUI (not consumed; the token is closed at once).
//                             "all" tries every serialization variant and prints each NTSTATUS.
//
// The private key never leaves the VM and is never printed. Exit 0 = done, 2 = bad input,
// 3 = state mismatch (no prepare for this nonce), 4 = crypto failure.
#include "common.h"
#include "pack.h"
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sddl.h>
#include <stdio.h>
#include <winscard.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "winscard.lib")

using namespace moavi;

static const wchar_t* CP_CLSID = L"{6A1F2C3D-7E8B-4A90-9C1D-2B3E4F5A6B70}";

static void Out(const std::string& s) {
    DWORD put = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s.data(), (DWORD)s.size(), &put, nullptr);
}
static void OutW(const std::wstring& s) { Out(WToUtf8(s)); }

static std::string B64(const BYTE* p, DWORD n) {
    DWORD len = 0;
    CryptBinaryToStringA(p, n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::string s(len, '\0');
    CryptBinaryToStringA(p, n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &s[0], &len);
    s.resize(len);
    return s;
}

static bool UnB64(const std::wstring& s, std::vector<BYTE>& out) {
    DWORD len = 0;
    if (!CryptStringToBinaryW(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
        return false;
    out.resize(len);
    return CryptStringToBinaryW(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr) != FALSE;
}

static std::string ReadStdin() {
    std::string data;
    char buf[8192];
    DWORD got = 0;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0 && data.size() < (256 << 10))
        data.append(buf, got);
    return data;
}

static void ForgetPending() {
    KV old;
    if (ReadKV(PendingPath(), old)) {
        RemoveKeyAndCert(old[L"key"], old[L"thumb"]);
        DeleteFileW(PendingPath().c_str());
    }
}

// The public key of the pending key (CAPI container or KSP key).
static bool PublicKeyOf(const KV& stc, std::vector<BYTE>& out) {
    KV st = stc;
    DWORD len = 0;
    if (st[L"keyprov"] != L"capi") {
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE key = 0;
        bool ok = false;
        bool vscKey = st[L"keyprov"] == L"vsc";
        KV vsc;
        if (vscKey) ReadVsc(vsc);
        std::wstring name = vscKey ? VscContainer(vsc, st[L"key"]) : st[L"key"];
        if (NCryptOpenStorageProvider(&prov, vscKey ? MS_SMART_CARD_KEY_STORAGE_PROVIDER : MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS &&
            NCryptOpenKey(prov, &key, name.c_str(), vscKey ? AT_KEYEXCHANGE : 0,
                          (vscKey ? 0 : KeyScopeFlags(st[L"keyscope"])) | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
            CryptExportPublicKeyInfo(key, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, nullptr, &len);
            out.resize(len);
            ok = CryptExportPublicKeyInfo(key, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)out.data(), &len) != FALSE;
        }
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
        return ok;
    }
    HCRYPTPROV hp = 0;
    if (!CryptAcquireContextW(&hp, st[L"key"].c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                              CRYPT_SILENT | (st[L"keyscope"] == L"machine" ? CRYPT_MACHINE_KEYSET : 0)))
        return false;
    CryptExportPublicKeyInfo(hp, AT_KEYEXCHANGE, X509_ASN_ENCODING, nullptr, &len);
    out.resize(len);
    bool ok = CryptExportPublicKeyInfo(hp, AT_KEYEXCHANGE, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)out.data(), &len) != FALSE;
    CryptReleaseContext(hp, 0);
    return ok;
}

// A new RSA-2048 key (not exportable) and its PKCS#10 request.
static bool MakeKeyAndCsr(const std::wstring& keyprov, const std::wstring& scope, const std::wstring& keyName,
                          std::vector<BYTE>& csr, std::string& err) {
    char m[64];
    HCRYPTPROV hp = 0;
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE signer = 0;
    DWORD spec = AT_KEYEXCHANGE;
    if (keyprov == L"vsc") {
        // a key made on the VM's TPM virtual smart card itself (it never leaves the TPM)
        KV vsc;
        if (!ReadVsc(vsc)) { err = "no virtual smart card (vsc.txt)"; return false; }
        std::wstring full = VscContainer(vsc, keyName), pin = vsc[L"pin"];
        SECURITY_STATUS ss = NCryptOpenStorageProvider(&prov, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
        if (ss == ERROR_SUCCESS)
            ss = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, full.c_str(), AT_KEYEXCHANGE, 0);
        DWORD bits = 2048;
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, (PBYTE)pin.c_str(), (DWORD)((pin.size() + 1) * sizeof(wchar_t)), NCRYPT_SILENT_FLAG);
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (BYTE*)&bits, sizeof(bits), 0);
        if (ss == ERROR_SUCCESS) ss = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
        if (ss != ERROR_SUCCESS) {
            sprintf_s(m, "card key 0x%08lx", (unsigned long)ss); err = m;
            if (key) NCryptFreeObject(key);
            if (prov) NCryptFreeObject(prov);
            return false;
        }
        signer = key;
        spec = CERT_NCRYPT_KEY_SPEC;
    } else if (keyprov != L"capi") {
        SECURITY_STATUS ss = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
        if (ss == ERROR_SUCCESS)
            ss = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, keyName.c_str(), AT_KEYEXCHANGE,
                                          KeyScopeFlags(scope) | NCRYPT_OVERWRITE_KEY_FLAG);
        DWORD bits = 2048, usage = NCRYPT_ALLOW_ALL_USAGES, exportPolicy = 0;
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (BYTE*)&bits, sizeof(bits), 0);
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (BYTE*)&usage, sizeof(usage), 0);
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE*)&exportPolicy, sizeof(exportPolicy), NCRYPT_PERSIST_FLAG);
        if (ss == ERROR_SUCCESS) ss = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
        if (ss != ERROR_SUCCESS) {
            sprintf_s(m, "key 0x%08lx", (unsigned long)ss); err = m;
            if (key) NCryptFreeObject(key);
            if (prov) NCryptFreeObject(prov);
            return false;
        }
        signer = key;
        spec = CERT_NCRYPT_KEY_SPEC;
    } else {
        DWORD flags = CRYPT_NEWKEYSET | CRYPT_SILENT | (scope == L"machine" ? CRYPT_MACHINE_KEYSET : 0);
        HCRYPTKEY hk = 0;
        if (!CryptAcquireContextW(&hp, keyName.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, flags) ||
            !CryptGenKey(hp, AT_KEYEXCHANGE, (2048u << 16), &hk)) {     // no CRYPT_EXPORTABLE
            sprintf_s(m, "key 0x%08lx", GetLastError()); err = m;
            if (hp) CryptReleaseContext(hp, 0);
            return false;
        }
        CryptDestroyKey(hk);
        signer = hp;
    }
    DWORD pkLen = 0;
    CryptExportPublicKeyInfo(signer, spec, X509_ASN_ENCODING, nullptr, &pkLen);
    std::vector<BYTE> pkBuf(pkLen);
    PCERT_PUBLIC_KEY_INFO pk = (PCERT_PUBLIC_KEY_INFO)pkBuf.data();
    BYTE nameBuf[256];
    DWORD nameLen = sizeof(nameBuf);
    BOOL ok = CryptExportPublicKeyInfo(signer, spec, X509_ASN_ENCODING, pk, &pkLen) &&
              CertStrToNameW(X509_ASN_ENCODING, L"CN=MOAVI Logon", CERT_X500_NAME_STR, nullptr, nameBuf, &nameLen, nullptr);
    if (ok) {
        // PKCS#10: the engine ignores the subject and writes its own (CN + UPN SAN)
        CERT_REQUEST_INFO req = {};
        req.dwVersion = CERT_REQUEST_V1;
        req.Subject.cbData = nameLen;
        req.Subject.pbData = nameBuf;
        req.SubjectPublicKeyInfo = *pk;
        CRYPT_ALGORITHM_IDENTIFIER alg = {};
        alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
        DWORD csrLen = 0;
        ok = CryptSignAndEncodeCertificate(signer, spec, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
                                           &req, &alg, nullptr, nullptr, &csrLen);
        if (ok) {
            csr.resize(csrLen);
            ok = CryptSignAndEncodeCertificate(signer, spec, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
                                               &req, &alg, nullptr, csr.data(), &csrLen);
            csr.resize(csrLen);
        }
    }
    if (!ok) { sprintf_s(m, "csr 0x%08lx", GetLastError()); err = m; }
    if (key) NCryptFreeObject(key);
    if (prov) NCryptFreeObject(prov);
    if (hp) CryptReleaseContext(hp, 0);
    return ok != FALSE;
}

static int Prepare() {
    if (!EnsureDataDir()) { Out("error=datadir\n"); return 4; }
    ForgetPending();
    BYTE rnd[16];
    if (BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) { Out("error=rng\n"); return 4; }
    std::wstring nonce = Hex(rnd, sizeof(rnd));
    std::wstring keyName = std::wstring(MOAVI_KEY_PREFIX) + nonce;
    KV opt;
    ReadKV(DataDir() + L"\\cp-options.txt", opt);
    std::wstring scope = opt[L"keyscope"] == L"machine" ? L"machine" : L"user";

    // keyprov capi (default): Microsoft Enhanced RSA and AES CSP, the provider the Kerberos smart card
    // logon path opens a container with; ksp: Microsoft Software KSP (LSA does not find it there)
    // keyprov moavi (default): a Software KSP key that LSA reaches through the MOAVI Logon KSP (a smart
    // card provider to it); ksp / capi: the bare software key (LSA refuses both - kept as switches)
    KV vscInfo;
    std::wstring keyprov = !opt[L"keyprov"].empty() ? opt[L"keyprov"] : ReadVsc(vscInfo) ? L"vsc" : L"moavi";
    if (keyprov != L"ksp" && keyprov != L"capi" && keyprov != L"vsc") keyprov = L"moavi";
    std::vector<BYTE> csr;
    std::string err;
    if (!MakeKeyAndCsr(keyprov, scope, keyName, csr, err)) {
        Out("error=" + err + "\n");
        RemoveKeyAndCert(keyName, L"");
        return 4;
    }

    KV st;
    st[L"state"] = L"prepared";
    st[L"key"] = keyName;
    st[L"keyscope"] = scope;
    st[L"keyprov"] = keyprov;
    st[L"nonce"] = nonce;
    st[L"prepared_at"] = std::to_wstring(UnixNow());
    if (!WriteKV(PendingPath(), st)) { RemoveKeyAndCert(keyName, L""); Out("error=state\n"); return 4; }
    Log(L"prepare: key %s (%s, %s)", keyName.c_str(), keyprov.c_str(), scope.c_str());
    Out("csr=" + B64(csr.data(), (DWORD)csr.size()) + "\n");
    OutW(L"nonce=" + nonce + L"\nversion=" MOAVI_LOGON_VERSION L"\n");
    return 0;
}

static bool AddToStore(DWORD location, PCCERT_CONTEXT cert) {
    HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, location, L"MY");
    if (!st) return false;
    BOOL ok = CertAddCertificateContextToStore(st, cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    CertCloseStore(st, 0);
    return ok != FALSE;
}

static bool SafeField(const std::wstring& s, size_t maxLen) {
    if (s.size() > maxLen) return false;
    for (wchar_t c : s)
        if (c < 0x20 || c == L'\\' || c == L'/' || c == L'"') return false;
    return true;
}

static int Arm() {
    KV in = ParseKV(ReadStdin());
    KV st;
    if (!ReadKV(PendingPath(), st) || st[L"state"] != L"prepared" || st[L"nonce"].empty() || st[L"nonce"] != in[L"nonce"]) {
        Out("error=no prepare for this nonce\n");
        return 3;
    }
    long long notAfter = _wtoi64(in[L"not_after"].c_str());
    long long now = UnixNow();
    if (notAfter <= now || notAfter > now + 3600) { Out("error=not_after\n"); return 2; }
    std::wstring gateways = in[L"gateways"];
    if (gateways.empty() || !SafeField(gateways, 400) || !SafeField(in[L"user"], 104) || !SafeField(in[L"domain"], 64)) {
        Out("error=fields\n");
        return 2;
    }
    std::vector<BYTE> der;
    if (!UnB64(in[L"cert"], der) || der.empty()) { Out("error=cert\n"); return 2; }
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), (DWORD)der.size());
    if (!cert) { Out("error=cert\n"); return 2; }

    // the certificate must be for the key prepare made
    std::vector<BYTE> pkBuf;
    bool match = PublicKeyOf(st, pkBuf) &&
                 CertComparePublicKeyInfo(X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)pkBuf.data(),
                                          &cert->pCertInfo->SubjectPublicKeyInfo) != FALSE;
    if (!match) { CertFreeCertificateContext(cert); Out("error=cert is not for this key\n"); return 2; }

    if (st[L"keyprov"] == L"vsc") {
        // the card holds its certificate next to the key, as a real smart card does
        KV vsc;
        ReadVsc(vsc);
        NCRYPT_PROV_HANDLE p = 0;
        NCRYPT_KEY_HANDLE k = 0;
        std::wstring full = VscContainer(vsc, st[L"key"]), pin = vsc[L"pin"];
        SECURITY_STATUS ss = NCryptOpenStorageProvider(&p, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
        if (ss == ERROR_SUCCESS) ss = NCryptOpenKey(p, &k, full.c_str(), AT_KEYEXCHANGE, NCRYPT_SILENT_FLAG);
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(k, NCRYPT_PIN_PROPERTY, (PBYTE)pin.c_str(), (DWORD)((pin.size() + 1) * sizeof(wchar_t)), NCRYPT_SILENT_FLAG);
        if (ss == ERROR_SUCCESS) ss = NCryptSetProperty(k, NCRYPT_CERTIFICATE_PROPERTY, der.data(), (DWORD)der.size(), NCRYPT_SILENT_FLAG);
        if (k) NCryptFreeObject(k);
        if (p) NCryptFreeObject(p);
        if (ss != ERROR_SUCCESS) {
            CertFreeCertificateContext(cert);
            char m[64]; sprintf_s(m, "error=card certificate 0x%08lx\n", (unsigned long)ss); Out(m);
            return 4;
        }
    }
    CRYPT_KEY_PROV_INFO kpi = {};
    kpi.pwszContainerName = (LPWSTR)st[L"key"].c_str();
    bool ksp = st[L"keyprov"] != L"capi";
    kpi.pwszProvName = (LPWSTR)(st[L"keyprov"] == L"vsc" ? MS_SMART_CARD_KEY_STORAGE_PROVIDER :
                                st[L"keyprov"] == L"moavi" ? MOAVI_KSP_NAME : ksp ? MS_KEY_STORAGE_PROVIDER : MS_ENH_RSA_AES_PROV_W);
    kpi.dwProvType = ksp ? 0 : PROV_RSA_AES;  // 0 = CNG
    kpi.dwFlags = (ksp ? KeyScopeFlags(st[L"keyscope"]) | NCRYPT_SILENT_FLAG
                       : (st[L"keyscope"] == L"machine" ? CRYPT_MACHINE_KEYSET : 0) | CRYPT_SILENT);
    kpi.dwKeySpec = AT_KEYEXCHANGE;
    BYTE thumb[20];
    DWORD thumbLen = sizeof(thumb);
    bool ok = CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi) &&
              CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, thumb, &thumbLen) && thumbLen == 20;
    bool inMachine = ok && AddToStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, cert);
    bool inSystem = ok && AddToStore(CERT_SYSTEM_STORE_CURRENT_USER, cert);   // SYSTEM's own My
    CertFreeCertificateContext(cert);
    if (!inMachine && !inSystem) { Out("error=store\n"); return 4; }

    st[L"state"] = L"armed";
    st[L"thumb"] = Hex(thumb, 20);
    st[L"not_after"] = std::to_wstring(notAfter);
    st[L"gateways"] = gateways;
    st[L"user"] = in[L"user"];
    st[L"domain"] = in[L"domain"];
    if (!in[L"upn"].empty() && SafeField(in[L"upn"], 200) && in[L"upn"].find(L'@') != std::wstring::npos)
        st[L"upn"] = in[L"upn"];
    st[L"store"] = inMachine ? L"machine" : L"system";
    // switches for the logon serialization (defaults are the tested ones)
    if (!in[L"mode"].empty() && SafeField(in[L"mode"], 16)) st[L"mode"] = in[L"mode"];
    if (!in[L"pkg"].empty() && SafeField(in[L"pkg"], 32)) st[L"pkg"] = in[L"pkg"];
    st[L"armed_at"] = std::to_wstring(now);
    if (!WriteKV(PendingPath(), st)) { Out("error=state\n"); return 4; }
    Log(L"arm: %s\\%s until %lld via %s thumb %s", st[L"domain"].c_str(), st[L"user"].c_str(), notAfter,
        gateways.c_str(), st[L"thumb"].c_str());
    OutW(L"armed=ok\nthumb=" + st[L"thumb"] + L"\n");
    return 0;
}

static bool LsaPplOn() {
    DWORD v = 0, sz = sizeof(v);
    return RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL",
                        RRF_RT_REG_DWORD, nullptr, &v, &sz) == ERROR_SUCCESS && v != 0;
}

static int Status() {
    std::wstring k = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + CP_CLSID;
    HKEY h;
    bool cp = RegOpenKeyExW(HKEY_LOCAL_MACHINE, k.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS;
    if (cp) RegCloseKey(h);
    KV st;
    ReadKV(PendingPath(), st);
    std::wstring state = st[L"state"].empty() ? L"none" : st[L"state"];
    if (state == L"armed" && _wtoi64(st[L"not_after"].c_str()) <= UnixNow()) state = L"expired";
    OutW(L"version=" MOAVI_LOGON_VERSION L"\ncp=" + std::wstring(cp ? L"registered" : L"missing") +
         L"\nlsa_ppl=" + std::wstring(LsaPplOn() ? L"on" : L"off") + L"\nstate=" + state + L"\n");
    return 0;
}

static NTSTATUS TryLogon(const KV& st, bool unlock, NTSTATUS* sub) {
    std::vector<BYTE> buf;
    *sub = 0;
    if (!PackCertLogon(st, unlock, buf)) return (NTSTATUS)0xC000000DL;
    // LogonUI takes the buffer with offsets; LsaLogonUser from a process wants real pointers into it
    {
        BYTE* base = buf.data();
        KERB_CERTIFICATE_LOGON* kl = (KERB_CERTIFICATE_LOGON*)base;
        UNICODE_STRING* us[] = { &kl->DomainName, &kl->UserName, &kl->Pin };
        for (auto u : us)
            if (u->Buffer) u->Buffer = (PWSTR)(base + (ULONG_PTR)u->Buffer);
        kl->CspData = base + (ULONG_PTR)kl->CspData;
    }
    HANDLE lsa = nullptr;
    LSA_STRING name;
    char proc[] = "MoaviLogonSelftest";
    name.Buffer = proc; name.Length = (USHORT)strlen(proc); name.MaximumLength = name.Length + 1;
    LSA_OPERATIONAL_MODE mode = 0;
    NTSTATUS r = LsaRegisterLogonProcess(&name, &lsa, &mode);
    if (r != 0) return r;
    ULONG pkg = 0;
    std::string pn = WToUtf8(KV(st)[L"pkg"].empty() ? L"Negotiate" : KV(st)[L"pkg"]);
    LSA_STRING ps;
    ps.Buffer = (PCHAR)pn.c_str(); ps.Length = (USHORT)pn.size(); ps.MaximumLength = ps.Length + 1;
    r = LsaLookupAuthenticationPackage(lsa, &ps, &pkg);
    if (r == 0) {
        TOKEN_SOURCE src = {};
        memcpy(src.SourceName, "MOAVI\0\0\0", 8);
        AllocateLocallyUniqueId(&src.SourceIdentifier);
        PVOID profile = nullptr;
        ULONG profileLen = 0;
        LUID luid = {};
        HANDLE token = nullptr;
        QUOTA_LIMITS q = {};
        r = LsaLogonUser(lsa, &name, Interactive, pkg, buf.data(), (ULONG)buf.size(), nullptr, &src,
                         &profile, &profileLen, &luid, &token, &q, sub);
        if (profile) LsaFreeReturnBuffer(profile);
        if (token) CloseHandle(token);
    }
    LsaDeregisterLogonProcess(lsa);
    return r;
}

static int Selftest(bool all) {
    KV st;
    if (!ReadKV(PendingPath(), st) || st[L"state"] != L"armed") { Out("error=nothing armed\n"); return 3; }
    if (_wtoi64(st[L"not_after"].c_str()) <= UnixNow()) { Out("error=expired\n"); return 3; }
    KV opt;
    if (ReadKV(DataDir() + L"\\cp-options.txt", opt))
        for (auto& o : opt) st[o.first] = o.second;
    // csp with a PIN is the form LSA takes (hash and an empty PIN: STATUS_INVALID_PARAMETER); what varies
    // is how the key is named to it and the outer structure
    const wchar_t* softProviders[] = { MOAVI_KSP_NAME, MS_KEY_STORAGE_PROVIDER, MS_ENH_RSA_AES_PROV_W };
    const wchar_t* cardProviders[] = { MS_SCARD_PROV_W, MS_SMART_CARD_KEY_STORAGE_PROVIDER, L"" };
    const wchar_t** providers = st[L"keyprov"] == L"vsc" ? cardProviders : softProviders;
    const wchar_t* names[] = { L"upn", L"on", L"off" };
    const wchar_t* structs[] = { L"plain", L"unlock" };
    const wchar_t* pkgs[] = { L"Negotiate", L"Kerberos" };
    int rc = 1;
    for (int pi = 0; pi < 3; pi++) for (auto n : names) for (auto sct : structs) for (auto pk : pkgs) {
        KV t = st;
        if (all) { t[L"mode"] = L"csp"; t[L"provider"] = providers[pi]; if (!*providers[pi]) t[L"nocard"] = L"on"; t[L"names"] = n; t[L"struct"] = sct; t[L"pkg"] = pk; t[L"pin"] = L"0000"; }
        bool unlock = t[L"struct"] == L"unlock";
        NTSTATUS sub = 0;
        NTSTATUS r = TryLogon(t, unlock, &sub);
        wchar_t line[400];
        swprintf_s(line, L"try provider=%s names=%s struct=%s pkg=%s -> 0x%08lx / 0x%08lx\n",
                   t[L"provider"].empty() ? L"default" : t[L"provider"].c_str(), t[L"names"].empty() ? L"default" : t[L"names"].c_str(),
                   unlock ? L"unlock" : L"plain", t[L"pkg"].empty() ? L"Negotiate" : t[L"pkg"].c_str(),
                   (unsigned long)r, (unsigned long)sub);
        OutW(line);
        Log(L"selftest: %s", line);
        if (r == 0) { rc = 0; if (all) goto done; }
        if (!all) goto done;
    }
done:
    return rc;
}

// The CNG provider registration calls (bcrypt.dll; declared only in the CPDK's bcrypt_provider.h)
typedef NTSTATUS (WINAPI* RegisterProviderFn)(LPCWSTR, ULONG, PCRYPT_PROVIDER_REG);
typedef NTSTATUS (WINAPI* UnregisterProviderFn)(LPCWSTR);
typedef NTSTATUS (WINAPI* AddContextFunctionProviderFn)(ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI* RemoveContextFunctionProviderFn)(ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR);

static int RegisterKsp(bool on) {
    NTSTATUS r;
    HMODULE bc = LoadLibraryExW(L"bcrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto BCryptRegisterProvider = bc ? (RegisterProviderFn)GetProcAddress(bc, "BCryptRegisterProvider") : nullptr;
    auto BCryptUnregisterProvider = bc ? (UnregisterProviderFn)GetProcAddress(bc, "BCryptUnregisterProvider") : nullptr;
    auto BCryptAddContextFunctionProvider = bc ? (AddContextFunctionProviderFn)GetProcAddress(bc, "BCryptAddContextFunctionProvider") : nullptr;
    auto BCryptRemoveContextFunctionProvider = bc ? (RemoveContextFunctionProviderFn)GetProcAddress(bc, "BCryptRemoveContextFunctionProvider") : nullptr;
    if (!BCryptRegisterProvider || !BCryptUnregisterProvider || !BCryptAddContextFunctionProvider || !BCryptRemoveContextFunctionProvider) {
        Out("error=bcrypt registration functions missing\n");
        return 4;
    }
    if (!on) {
        BCryptRemoveContextFunctionProvider(CRYPT_LOCAL, nullptr, NCRYPT_KEY_STORAGE_INTERFACE, NCRYPT_KEY_STORAGE_ALGORITHM, MOAVI_KSP_NAME);
        r = BCryptUnregisterProvider(MOAVI_KSP_NAME);
        char m[64]; sprintf_s(m, "ksp=unregistered 0x%08lx\n", (unsigned long)r); Out(m);
        return 0;
    }
    PWSTR functions[] = { (PWSTR)NCRYPT_KEY_STORAGE_ALGORITHM };
    CRYPT_INTERFACE_REG iface = { NCRYPT_KEY_STORAGE_INTERFACE, CRYPT_LOCAL, 1, functions };
    PCRYPT_INTERFACE_REG ifaces[] = { &iface };
    CRYPT_IMAGE_REG image = { (PWSTR)MOAVI_KSP_IMAGE, 1, ifaces };
    CRYPT_PROVIDER_REG reg = { 0, nullptr, &image, nullptr };
    r = BCryptRegisterProvider(MOAVI_KSP_NAME, CRYPT_OVERWRITE, &reg);
    if (r != 0) { char m[64]; sprintf_s(m, "error=register 0x%08lx\n", (unsigned long)r); Out(m); return 4; }
    r = BCryptAddContextFunctionProvider(CRYPT_LOCAL, nullptr, NCRYPT_KEY_STORAGE_INTERFACE, NCRYPT_KEY_STORAGE_ALGORITHM,
                                         MOAVI_KSP_NAME, CRYPT_PRIORITY_BOTTOM);
    if (r != 0 && r != (NTSTATUS)0xC0000035L /* already there */) {
        char m[64]; sprintf_s(m, "error=context 0x%08lx\n", (unsigned long)r); Out(m); return 4;
    }
    NCRYPT_PROV_HANDLE p = 0;
    SECURITY_STATUS ss = NCryptOpenStorageProvider(&p, MOAVI_KSP_NAME, 0);
    if (p) NCryptFreeObject(p);
    char m[64]; sprintf_s(m, "ksp=registered open=0x%08lx\n", (unsigned long)ss); Out(m);
    return ss == ERROR_SUCCESS ? 0 : 4;
}

static int VscInfo() {
    SCARDCONTEXT ctx = 0;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx) != SCARD_S_SUCCESS) { Out("error=scard context\n"); return 4; }
    LPWSTR readers = nullptr;
    DWORD len = SCARD_AUTOALLOCATE;
    std::wstring reader;
    if (SCardListReadersW(ctx, nullptr, (LPWSTR)&readers, &len) == SCARD_S_SUCCESS) {
        for (LPWSTR r = readers; *r; r += wcslen(r) + 1)
            if (wcsstr(r, L"Virtual Smart Card") || wcsstr(r, L"Virtual Smartcard")) { reader = r; break; }
        SCardFreeMemory(ctx, readers);
    }
    if (reader.empty()) { SCardReleaseContext(ctx); Out("error=no virtual smart card reader\n"); return 3; }
    std::wstring card;
    SCARDHANDLE h = 0;
    DWORD proto = 0;
    if (SCardConnectW(ctx, reader.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &h, &proto) == SCARD_S_SUCCESS) {
        BYTE atr[36];
        DWORD atrLen = sizeof(atr), state = 0, rlen = 0;
        if (SCardStatusW(h, nullptr, &rlen, &state, &proto, atr, &atrLen) == SCARD_S_SUCCESS) {
            LPWSTR cards = nullptr;
            DWORD clen = SCARD_AUTOALLOCATE;
            if (SCardListCardsW(ctx, atr, nullptr, 0, (LPWSTR)&cards, &clen) == SCARD_S_SUCCESS) {
                if (cards && *cards) card = cards;
                SCardFreeMemory(ctx, cards);
            }
        }
        SCardDisconnect(h, SCARD_LEAVE_CARD);
    }
    SCardReleaseContext(ctx);
    KV vsc;
    ReadKV(DataDir() + L"\\vsc.txt", vsc);
    vsc[L"reader"] = reader;
    vsc[L"card"] = card;
    if (vsc[L"pin"].empty()) vsc[L"pin"] = L"12345678";   // tpmvscmgr /pin default (the card's PIN, VM-local)
    if (!EnsureDataDir() || !WriteKV(DataDir() + L"\\vsc.txt", vsc)) { Out("error=vsc.txt\n"); return 4; }
    OutW(L"vsc_reader=" + reader + L"\nvsc_card=" + card + L"\n");
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { Out("usage: moavi-logon prepare|arm|status|clear\n"); return 2; }
    std::wstring cmd = argv[1];
    if (cmd == L"prepare") return Prepare();
    if (cmd == L"arm") return Arm();
    if (cmd == L"status") return Status();
    if (cmd == L"vsc-info") return VscInfo();
    if (cmd == L"register-ksp") return RegisterKsp(true);
    if (cmd == L"unregister-ksp") return RegisterKsp(false);
    if (cmd == L"selftest") return Selftest(argc > 2 && std::wstring(argv[2]) == L"all");
    if (cmd == L"clear") { ForgetPending(); Log(L"clear"); Out("cleared=ok\n"); return 0; }
    Out("usage: moavi-logon prepare|arm|status|clear\n");
    return 2;
}
