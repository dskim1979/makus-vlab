// MOAVI Desk Logon credential provider (moavi-logon-cp.dll), loaded by LogonUI as SYSTEM.
//
// It shows nothing - and Windows' own sign-in options stay as they are - unless all of these hold:
//   * this is a remote (RDP) session, never the console;
//   * moavi-logon.exe armed a logon (C:\ProgramData\MoaviLogon\pending.txt, SYSTEM / Administrators
//     only) that is not used yet and not past its not_after;
//   * the session's client address is one of the gateway addresses the engine armed it for.
// Then one tile signs that session in automatically with KERB_CERTIFICATE_LOGON: the engine's
// short-lived certificate (MOAVI Desk Logon CA, UPN SAN, smart card logon EKU) next to its key in the
// Microsoft Software KSP. Kerberos does PKINIT with the bundled DC. The logon is used once: consumed
// before it is handed to LogonUI, key and certificate removed when Windows reports the result.
// Any failure falls back to the normal sign-in screen.
#include "common.h"
#include "pack.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <shlguid.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <ntsecapi.h>
#include <wtsapi32.h>
#include <shlwapi.h>
#include <new>
#include <vector>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")


using namespace moavi;

// {6A1F2C3D-7E8B-4A90-9C1D-2B3E4F5A6B70}
static const CLSID CLSID_MoaviLogonCP = { 0x6a1f2c3d, 0x7e8b, 0x4a90, { 0x9c, 0x1d, 0x2b, 0x3e, 0x4f, 0x5a, 0x6b, 0x70 } };

static LONG g_refs = 0;
static HINSTANCE g_inst = nullptr;

enum { FI_LABEL = 0, FI_STATUS = 1, FI_COUNT = 2 };

// --- who is connected to the RDP listener ------------------------------------------------------

static DWORD RdpPort() {
    DWORD port = 3389, sz = sizeof(port);
    RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                 L"PortNumber", RRF_RT_REG_DWORD, nullptr, &port, &sz);
    return port ? port : 3389;
}

static std::wstring Ip4(DWORD addr) {     // network byte order
    wchar_t ip[32];
    const BYTE* b = (const BYTE*)&addr;
    swprintf_s(ip, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return ip;
}

static bool InList(const std::wstring& list, const std::wstring& item);

// True when there is at least one established TCP connection on the RDP port and every one of
// them comes from a gateway address. peers / bad: the addresses seen (for the log).
static bool RdpPeers(const std::wstring& gateways, std::wstring& peers, std::wstring& bad) {
    DWORD port = RdpPort();
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_BASIC_CONNECTIONS, 0);
    std::vector<BYTE> buf(size + 4096);
    size = (ULONG)buf.size();
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_BASIC_CONNECTIONS, 0) != NO_ERROR) {
        bad = L"tcp table";
        return false;
    }
    MIB_TCPTABLE* t = (MIB_TCPTABLE*)buf.data();
    int n = 0;
    for (DWORD i = 0; i < t->dwNumEntries; i++) {
        const MIB_TCPROW& r = t->table[i];
        DWORD lp = ((r.dwLocalPort & 0xff) << 8) | ((r.dwLocalPort >> 8) & 0xff);
        if (r.dwState != MIB_TCP_STATE_ESTAB || lp != port) continue;
        std::wstring ip = Ip4(r.dwRemoteAddr);
        if (!peers.empty()) peers += L",";
        peers += ip;
        n++;
        if (!InList(gateways, ip)) { if (!bad.empty()) bad += L","; bad += ip; }
    }
    // IPv6 connections on the RDP port are never from a gateway here
    size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_BASIC_CONNECTIONS, 0);
    if (size) {
        std::vector<BYTE> b6(size + 4096);
        size = (ULONG)b6.size();
        if (GetExtendedTcpTable(b6.data(), &size, FALSE, AF_INET6, TCP_TABLE_BASIC_CONNECTIONS, 0) == NO_ERROR) {
            MIB_TCP6TABLE* t6 = (MIB_TCP6TABLE*)b6.data();
            for (DWORD i = 0; i < t6->dwNumEntries; i++) {
                const MIB_TCP6ROW& r = t6->table[i];
                DWORD lp = ((r.dwLocalPort & 0xff) << 8) | ((r.dwLocalPort >> 8) & 0xff);
                if (r.State != MIB_TCP_STATE_ESTAB || lp != port) continue;
                if (!bad.empty()) bad += L",";
                bad += L"ipv6";
                n++;
            }
        }
    }
    return n > 0 && bad.empty();
}

// --- the pending logon ------------------------------------------------------------------------

static std::wstring SessionClientAddress() {
    LPWSTR buf = nullptr;
    DWORD len = 0;
    std::wstring out;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientAddress, &buf, &len) && buf) {
        WTS_CLIENT_ADDRESS* a = (WTS_CLIENT_ADDRESS*)buf;
        if (a->AddressFamily == AF_INET) {
            wchar_t ip[32];
            swprintf_s(ip, L"%u.%u.%u.%u", a->Address[2], a->Address[3], a->Address[4], a->Address[5]);
            out = ip;
        }
        WTSFreeMemory(buf);
    }
    return out;
}

static bool InList(const std::wstring& list, const std::wstring& item) {
    if (item.empty()) return false;
    size_t i = 0;
    while (i <= list.size()) {
        size_t e = list.find(L',', i);
        if (e == std::wstring::npos) e = list.size();
        std::wstring x = list.substr(i, e - i);
        while (!x.empty() && x.front() == L' ') x.erase(0, 1);
        while (!x.empty() && x.back() == L' ') x.pop_back();
        if (x == item) return true;
        i = e + 1;
    }
    return false;
}

// The pending logon for this session, or false with the reason (logged, never shown).
static bool PendingForSession(KV& st, std::wstring& why) {
    if (!GetSystemMetrics(SM_REMOTESESSION)) { why = L"console session"; return false; }
    if (!ReadKV(PendingPath(), st)) { why = L"nothing armed"; return false; }
    if (st[L"state"] != L"armed") { why = L"state " + st[L"state"]; return false; }
    if (_wtoi64(st[L"not_after"].c_str()) <= UnixNow()) { why = L"expired"; return false; }
    // The gateway check uses the TCP peers of the RDP listener, not WTSClientAddress: that one is what
    // the RDP client says about itself (Warpgate reports its container address there) and can be
    // anything. Every established connection on the RDP port must come from a gateway.
    std::wstring peers, bad;
    if (!RdpPeers(st[L"gateways"], peers, bad)) {
        why = L"rdp peers [" + peers + L"] not all gateways (" + (bad.empty() ? L"none" : bad) + L"), client says " +
              SessionClientAddress();
        return false;
    }
    return true;
}


// --- credential --------------------------------------------------------------------------------

class Credential : public ICredentialProviderCredential {
public:
    Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) : _refs(1), _cpus(cpus) {}

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_refs); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&_refs);
        if (!r) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
            *ppv = static_cast<ICredentialProviderCredential*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    IFACEMETHODIMP UnAdvise() override { return S_OK; }
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override { *pbAutoLogon = TRUE; return S_OK; }
    IFACEMETHODIMP SetDeselected() override { return S_OK; }
    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* s, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* is) override {
        if (id >= FI_COUNT || !s || !is) return E_INVALIDARG;
        *s = CPFS_DISPLAY_IN_BOTH;
        *is = CPFIS_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* ppsz) override {
        if (id == FI_LABEL) return SHStrDupW(L"MOAVI Desk", ppsz);
        if (id == FI_STATUS) return SHStrDupW(L"\uC790\uB3D9 \uB85C\uADF8\uC778 \uC911\u2026", ppsz);   // 자동 로그인 중…
        return E_INVALIDARG;
    }
    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppszStatus, CREDENTIAL_PROVIDER_STATUS_ICON* pIcon) override {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        if (ppszStatus) *ppszStatus = nullptr;
        if (pIcon) *pIcon = CPSI_NONE;
        KV st;
        std::wstring why;
        if (!PendingForSession(st, why)) {
            Log(L"cp: serialization refused: %s", why.c_str());
            return E_FAIL;
        }
        // consume before handing it over: whatever happens next, it is not used twice
        st[L"state"] = L"used";
        st[L"used_at"] = std::to_wstring(UnixNow());
        if (!WriteKV(PendingPath(), st)) { Log(L"cp: could not consume the pending logon"); return E_FAIL; }
        _key = st[L"key"];
        _thumb = st[L"thumb"];

        std::vector<BYTE> buf;
        // C:\ProgramData\MoaviLogon\cp-options.txt (SYSTEM / Administrators only): switches for the
        // serialization while it is proven on a new Windows / DC: mode=hash|csp, pkg=Negotiate|Kerberos,
        // names=on|off, struct=plain|unlock, pin=<a non-secret value>, store=MY
        KV opt;
        if (ReadKV(DataDir() + L"\\cp-options.txt", opt))
            for (auto& o : opt)
                if (o.first == L"mode" || o.first == L"pkg" || o.first == L"names" || o.first == L"struct" ||
                    o.first == L"pin" || o.first == L"store")
                    st[o.first] = o.second;
        bool unlock = _cpus == CPUS_UNLOCK_WORKSTATION || st[L"struct"] == L"unlock";
        if (!PackCertLogon(st, unlock, buf)) { Log(L"cp: bad pending logon"); return E_FAIL; }
        ULONG pkg = AuthPackage(st[L"pkg"]);
        if (pkg == (ULONG)-1) { Log(L"cp: no auth package"); return E_FAIL; }
        pcpcs->rgbSerialization = (BYTE*)CoTaskMemAlloc(buf.size());
        if (!pcpcs->rgbSerialization) return E_OUTOFMEMORY;
        memcpy(pcpcs->rgbSerialization, buf.data(), buf.size());
        pcpcs->cbSerialization = (ULONG)buf.size();
        pcpcs->ulAuthenticationPackage = pkg;
        pcpcs->clsidCredentialProvider = CLSID_MoaviLogonCP;
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        Log(L"cp: certificate logon %s\\%s (%lu bytes, mode %s, names %s, struct %s, pin %s, pkg %s, client says %s)",
            st[L"domain"].c_str(), st[L"user"].c_str(), (unsigned long)buf.size(),
            st[L"mode"].empty() ? L"hash" : st[L"mode"].c_str(), st[L"names"].empty() ? L"on" : st[L"names"].c_str(),
            unlock ? L"unlock" : L"plain", st[L"pin"].empty() ? L"empty" : L"set",
            st[L"pkg"].empty() ? L"Negotiate" : st[L"pkg"].c_str(), SessionClientAddress().c_str());
        return S_OK;
    }

    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* ppszStatus, CREDENTIAL_PROVIDER_STATUS_ICON* pIcon) override {
        if (ppszStatus) *ppszStatus = nullptr;
        if (pIcon) *pIcon = CPSI_NONE;
        Log(L"cp: logon result 0x%08lx / 0x%08lx", (unsigned long)status, (unsigned long)substatus);
        if (!_key.empty() || !_thumb.empty()) {
            RemoveKeyAndCert(_key, _thumb);
            KV st;
            if (ReadKV(PendingPath(), st) && st[L"key"] == _key) {
                st[L"state"] = status == 0 ? L"done" : L"failed";
                wchar_t r[32];
                swprintf_s(r, L"0x%08lx/0x%08lx", (unsigned long)status, (unsigned long)substatus);
                st[L"result"] = r;
                WriteKV(PendingPath(), st);
            }
            _key.clear();
            _thumb.clear();
        }
        return S_OK;
    }

private:
    ~Credential() {}
    LONG _refs;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    std::wstring _key, _thumb;
};

// --- provider ----------------------------------------------------------------------------------

class Provider : public ICredentialProvider {
public:
    Provider() : _refs(1), _cred(nullptr), _has(false), _cpus(CPUS_INVALID) { InterlockedIncrement(&g_refs); }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_refs); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&_refs);
        if (!r) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
            *ppv = static_cast<ICredentialProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) override {
        if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;
        _cpus = cpus;
        KV st;
        std::wstring why;
        _has = PendingForSession(st, why);
        if (_has) Log(L"cp: pending logon for %s\\%s in this session", st[L"domain"].c_str(), st[L"user"].c_str());
        else if (why != L"console session" && why != L"nothing armed") Log(L"cp: no automatic logon: %s", why.c_str());
        return S_OK;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR) override { return S_OK; }
    IFACEMETHODIMP UnAdvise() override { return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* n) override { *n = FI_COUNT; return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD i, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppd) override {
        if (i >= FI_COUNT || !ppd) return E_INVALIDARG;
        auto* d = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
        if (!d) return E_OUTOFMEMORY;
        ZeroMemory(d, sizeof(*d));
        d->dwFieldID = i;
        d->cpft = i == FI_LABEL ? CPFT_LARGE_TEXT : CPFT_SMALL_TEXT;
        d->guidFieldType = i == FI_LABEL ? CPFG_CREDENTIAL_PROVIDER_LABEL : GUID{};
        HRESULT hr = SHStrDupW(i == FI_LABEL ? L"MOAVI Desk" : L"", &d->pszLabel);
        if (FAILED(hr)) { CoTaskMemFree(d); return hr; }
        *ppd = d;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* def, BOOL* autoLogon) override {
        *count = _has ? 1 : 0;
        *def = _has ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogon = _has ? TRUE : FALSE;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD i, ICredentialProviderCredential** ppc) override {
        if (!_has || i != 0 || !ppc) return E_INVALIDARG;
        if (!_cred) _cred = new (std::nothrow) Credential(_cpus);
        if (!_cred) return E_OUTOFMEMORY;
        return _cred->QueryInterface(IID_ICredentialProviderCredential, (void**)ppc);
    }

private:
    ~Provider() {
        if (_cred) _cred->Release();
        InterlockedDecrement(&g_refs);
    }
    LONG _refs;
    Credential* _cred;
    bool _has;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
};

// --- COM plumbing ------------------------------------------------------------------------------

class Factory : public IClassFactory {
public:
    IFACEMETHODIMP_(ULONG) AddRef() override { return 2; }
    IFACEMETHODIMP_(ULONG) Release() override { return 1; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = static_cast<IClassFactory*>(this); return S_OK; }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        Provider* p = new (std::nothrow) Provider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_refs); else InterlockedDecrement(&g_refs);
        return S_OK;
    }
};

static Factory g_factory;

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
    if (clsid != CLSID_MoaviLogonCP) return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow() { return g_refs > 0 ? S_FALSE : S_OK; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_inst = h;
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}
