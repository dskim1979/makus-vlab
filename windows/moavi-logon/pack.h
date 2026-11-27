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
    bool cspMode = st[L"mode"] == L"csp";
    std::vector<BYTE> csp;
    if (cspMode) {
        std::wstring container = st[L"key"], provider = MS_KEY_STORAGE_PROVIDER;
        // bBuffer: card "", reader "", container, csp name (offsets in WCHARs)
        std::wstring payload;
        payload += L'\0';                         // card name at 0
        payload += L'\0';                         // reader name at 1
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
        ci->nCardNameOffset = 0;
        ci->nReaderNameOffset = 1;
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

    std::wstring domain = st[L"domain"], user = st[L"user"], pin = st[L"pin"];
    if (st[L"names"] == L"off") { domain.clear(); user.clear(); }
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
