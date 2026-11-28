// MOAVI Desk Logon - the KERB_CERTIFICATE_LOGON buffer, shared by the credential provider and
// moavi-logon.exe selftest. Pointers in the buffer are offsets from its start (LogonUI / LsaLogonUser
// unpack them that way).
#pragma once
#include "common.h"
#include <ncrypt.h>
#include <wincrypt.h>
#include <ntsecapi.h>
#include <stddef.h>
#include <vector>

namespace moavi {

// KERB_SMARTCARD_CSP_INFO (documented layout, not in the SDK headers) - for mode=csp
#pragma pack(push, 1)
struct KERB_SMARTCARD_CSP_INFO_ {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union { PVOID ContextInformation; ULONG64 SpaceHolderForWow64; };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    WCHAR bBuffer[sizeof(DWORD)];
};
#pragma pack(pop)


inline ULONG AuthPackage(const std::wstring& name) {
    HANDLE lsa = nullptr;
    ULONG pkg = 0;
    if (LsaConnectUntrusted(&lsa) != 0) return (ULONG)-1;
    std::string n = WToUtf8(name.empty() ? L"Negotiate" : name);
    LSA_STRING s;
    s.Buffer = (PCHAR)n.c_str();
    s.Length = (USHORT)n.size();
    s.MaximumLength = s.Length + 1;
    NTSTATUS r = LsaLookupAuthenticationPackage(lsa, &s, &pkg);
    LsaDeregisterLogonProcess(lsa);
    return r == 0 ? pkg : (ULONG)-1;
}

// KERB_CERTIFICATE_LOGON (or its unlock form) packed into one buffer, pointers as offsets
inline bool PackCertLogon(const KV& stc, bool unlock, std::vector<BYTE>& out) {
    KV st = stc;
    std::string thumb;
    if (!UnHex(st[L"thumb"], thumb) || thumb.size() != 20) return false;
    // mode csp (default): KERB_SMARTCARD_CSP_INFO naming the KSP and the key; hash: the certificate
    // by hash (LSA refuses that one with STATUS_INVALID_PARAMETER on Server 2022)
    bool cspMode = st[L"mode"] != L"hash";
    std::vector<BYTE> csp;
    if (cspMode) {
        std::wstring container = st[L"key"];
        bool vscKey = st[L"keyprov"] == L"vsc";
        KV vsc;
        if (vscKey) ReadVsc(vsc);
        std::wstring provider = !st[L"provider"].empty() ? st[L"provider"]
                              : vscKey ? std::wstring(MS_SCARD_PROV_W)
                              : st[L"keyprov"] == L"ksp" ? std::wstring(MS_KEY_STORAGE_PROVIDER)
                              : st[L"keyprov"] == L"capi" ? std::wstring(MS_ENH_RSA_AES_PROV_W)
                              : st[L"keyprov"] == L"mcsp" ? std::wstring(MOAVI_CSP_NAME)
                              : std::wstring(MOAVI_KSP_NAME);
        // bBuffer: card "", reader "", container, csp name (offsets in WCHARs)
        std::wstring payload;
        payload.assign(4, L'\0');                 // the first sizeof(DWORD) WCHARs of bBuffer stay unused
        ULONG cardOff = (ULONG)payload.size();
        if (vscKey && st[L"nocard"] != L"on") payload += vsc[L"card"];
        payload += L'\0';                         // card name ("" for a software key)
        ULONG readerOff = (ULONG)payload.size();
        if (vscKey) payload += vsc[L"reader"];
        payload += L'\0';                         // reader name
        ULONG contOff = (ULONG)payload.size();
        payload += container; payload += L'\0';
        ULONG cspOff = (ULONG)payload.size();
        payload += provider; payload += L'\0';
        size_t len = offsetof(KERB_SMARTCARD_CSP_INFO_, bBuffer) + payload.size() * sizeof(WCHAR);
        csp.assign(len, 0);
        KERB_SMARTCARD_CSP_INFO_* ci = (KERB_SMARTCARD_CSP_INFO_*)csp.data();
        ci->dwCspInfoLen = (DWORD)len;
        ci->MessageType = 1;
        ci->KeySpec = AT_KEYEXCHANGE;
        ci->nCardNameOffset = cardOff;
        ci->nReaderNameOffset = readerOff;
        ci->nContainerNameOffset = contOff;
        ci->nCSPNameOffset = cspOff;
        memcpy(csp.data() + offsetof(KERB_SMARTCARD_CSP_INFO_, bBuffer), payload.data(), payload.size() * sizeof(WCHAR));
    } else {
        std::wstring store = st[L"store"].empty() ? L"MY" : st[L"store"];
        USHORT storeBytes = (USHORT)((store.size() + 1) * sizeof(WCHAR));
        size_t len = sizeof(KERB_CERTIFICATE_INFO) + sizeof(KERB_CERTIFICATE_HASHINFO) + storeBytes + 20;
        csp.assign(len, 0);
        KERB_CERTIFICATE_INFO* ci = (KERB_CERTIFICATE_INFO*)csp.data();
        ci->CertInfoSize = (ULONG)len;
        ci->InfoType = CertHashInfo;
        KERB_CERTIFICATE_HASHINFO* hi = (KERB_CERTIFICATE_HASHINFO*)(csp.data() + sizeof(KERB_CERTIFICATE_INFO));
        hi->StoreNameLength = storeBytes;
        hi->HashLength = 20;
        BYTE* p = (BYTE*)(hi + 1);
        memcpy(p, store.c_str(), storeBytes);
        memcpy(p + storeBytes, thumb.data(), 20);
    }

    // a PIN must be there (an empty one is STATUS_INVALID_PARAMETER); the software key has none, so
    // any value does - not a secret
    std::wstring domain = st[L"domain"], user = st[L"user"], pin = stc.count(L"pin") ? st[L"pin"] : L"0000";
    if (st[L"keyprov"] == L"vsc" && !stc.count(L"pin")) { KV vsc; ReadVsc(vsc); pin = vsc[L"pin"]; }
    // names=upn (default when the engine sent one): UserName = the UPN, DomainName empty - LSA refuses
    // a certificate logon with a domain name (STATUS_INVALID_PARAMETER); on = DOMAIN + user; off = none
    std::wstring names = st[L"names"].empty() ? (st[L"upn"].empty() ? L"on" : L"upn") : st[L"names"];
    if (names == L"upn") { user = st[L"upn"]; domain.clear(); }
    else if (names == L"off") { domain.clear(); user.clear(); }
    size_t head = unlock ? sizeof(KERB_CERTIFICATE_UNLOCK_LOGON) : sizeof(KERB_CERTIFICATE_LOGON);
    size_t dBytes = domain.size() * sizeof(WCHAR), uBytes = user.size() * sizeof(WCHAR), pBytes = pin.size() * sizeof(WCHAR);
    // the CSP data starts 8-byte aligned (LSA checks the structures it unpacks)
    size_t cspAt = (head + dBytes + uBytes + pBytes + 7) & ~(size_t)7;
    out.assign(cspAt + csp.size(), 0);
    KERB_CERTIFICATE_LOGON* kl = (KERB_CERTIFICATE_LOGON*)out.data();
    kl->MessageType = KerbCertificateLogon;
    BYTE* base = out.data();
    BYTE* p = base + head;
    auto put = [&](UNICODE_STRING& us, const std::wstring& s) {
        us.Length = us.MaximumLength = (USHORT)(s.size() * sizeof(WCHAR));
        us.Buffer = s.empty() ? nullptr : (PWSTR)(p - base);
        if (!s.empty()) memcpy(p, s.data(), us.Length);
        p += us.Length;
    };
    put(kl->DomainName, domain);
    put(kl->UserName, user);
    put(kl->Pin, pin);
    kl->Flags = cspMode ? 0 : KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO;
    kl->CspDataLength = (ULONG)csp.size();
    kl->CspData = (PUCHAR)cspAt;
    memcpy(base + cspAt, csp.data(), csp.size());
    return true;
}


}  // namespace moavi
