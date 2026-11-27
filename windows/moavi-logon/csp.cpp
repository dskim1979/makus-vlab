// MOAVI Desk Logon cryptographic provider (moavi-logon-csp.dll), "MOAVI Logon Cryptographic Provider".
//
// What LSA does with a smart card logon (Microsoft, "Smart card certificate requirements and
// enumeration"): it opens the CSP named in the logon's CSP data with CryptAcquireContext (container
// name, CRYPT_SILENT), gives it the PIN with CryptSetProvParam, gets the key with CryptGetUserKey and
// the certificate with CryptGetKeyParam(KP_CERTIFICATE), and has the CSP sign the PKINIT request.
// A smart card CSP reaches its card through WinSCard, and in an RDP session WinSCard goes to the RDP
// client's readers ("Smart Card and Remote Desktop Services": the redirection is decided per
// SCardEstablishContext). This CSP never calls WinSCard: it is the card. It opens only the pending
// logon key named in C:\ProgramData\MoaviLogon\pending.txt (armed or just used, not expired) - a
// non-exportable CAPI container in the Microsoft Enhanced RSA and AES CSP, SYSTEM's own - takes the PIN
// (there is none), answers the certificate, and passes hashing, signing and decryption to that
// container. Nothing is generated, imported or exported here. Calls are logged ("csp:"), never keys.
#include "common.h"
#include <wincrypt.h>
#include <new>
#include <vector>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

using namespace moavi;

// cspdk.h (Cryptographic Service Provider Developer's Kit)
struct VTableProvStruc {
    DWORD Version;
    FARPROC FuncVerifyImage;
    FARPROC FuncReturnhWnd;
    DWORD dwProvType;
    BYTE* pbContextInfo;
    DWORD cbContextInfo;
    LPSTR pszProvName;
};

static const char* CSP_NAME_A = "MOAVI Logon Cryptographic Provider";
static const wchar_t* CSP_NAME_W = L"MOAVI Logon Cryptographic Provider";
static const DWORD PROV_MAGIC = 0x4D4C4350, KEY_MAGIC = 0x4D4C434B, HASH_MAGIC = 0x4D4C4348;

struct Prov { DWORD magic; HCRYPTPROV sw; std::wstring name; std::wstring thumb; bool verify; };
struct Key { DWORD magic; HCRYPTKEY sw; DWORD spec; };
struct Hash { DWORD magic; HCRYPTHASH sw; };

static Prov* P(HCRYPTPROV h) { Prov* p = (Prov*)h; return p && p->magic == PROV_MAGIC ? p : nullptr; }
static Key* K(HCRYPTKEY h) { Key* k = (Key*)h; return k && k->magic == KEY_MAGIC ? k : nullptr; }
static Hash* H(HCRYPTHASH h) { Hash* x = (Hash*)h; return x && x->magic == HASH_MAGIC ? x : nullptr; }

static BOOL Fail(DWORD e) { SetLastError(e); return FALSE; }

static BOOL Put(const void* d, DWORD n, BYTE* out, DWORD* pcb) {
    if (!pcb) return Fail(ERROR_INVALID_PARAMETER);
    if (!out) { *pcb = n; return TRUE; }
    if (*pcb < n) { *pcb = n; return Fail(ERROR_MORE_DATA); }
    memcpy(out, d, n);
    *pcb = n;
    return TRUE;
}

static std::string A(const std::wstring& w) { return WToUtf8(w); }

static bool CertDer(const std::wstring& thumbHex, std::vector<BYTE>& der) {
    std::string thumb;
    if (!UnHex(thumbHex, thumb) || thumb.size() != 20) return false;
    for (DWORD loc : { (DWORD)CERT_SYSTEM_STORE_CURRENT_USER, (DWORD)CERT_SYSTEM_STORE_LOCAL_MACHINE }) {
        HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, loc | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY");
        if (!st) continue;
        CRYPT_HASH_BLOB blob = { 20, (BYTE*)thumb.data() };
        PCCERT_CONTEXT c = CertFindCertificateInStore(st, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
        if (c) {
            der.assign(c->pbCertEncoded, c->pbCertEncoded + c->cbCertEncoded);
            CertFreeCertificateContext(c);
            CertCloseStore(st, 0);
            return true;
        }
        CertCloseStore(st, 0);
    }
    return false;
}

// --- context -----------------------------------------------------------------------------------

extern "C" BOOL WINAPI CPAcquireContextW(HCRYPTPROV* ph, LPCWSTR container, DWORD flags, VTableProvStruc*);

extern "C" BOOL WINAPI CPAcquireContext(HCRYPTPROV* ph, LPCSTR container, DWORD flags, VTableProvStruc* vt) {
    std::wstring c = container ? Utf8ToW(container) : L"";
    return CPAcquireContextW(ph, container ? c.c_str() : nullptr, flags, vt);
}

extern "C" BOOL WINAPI CPAcquireContextW(HCRYPTPROV* ph, LPCWSTR container, DWORD flags, VTableProvStruc*) {
    if (!ph) return Fail(ERROR_INVALID_PARAMETER);
    Log(L"csp: AcquireContext %s flags 0x%lx (pid %lu)", container ? container : L"(null)", flags, GetCurrentProcessId());
    if (flags & (CRYPT_NEWKEYSET | CRYPT_DELETEKEYSET)) return Fail((DWORD)NTE_BAD_FLAGS);   // not a key maker
    Prov* p = new (std::nothrow) Prov();
    if (!p) return Fail(ERROR_NOT_ENOUGH_MEMORY);
    p->magic = PROV_MAGIC;
    if ((flags & CRYPT_VERIFYCONTEXT) || !container || !*container) {
        p->verify = true;
        if (!CryptAcquireContextW(&p->sw, nullptr, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            DWORD e = GetLastError(); delete p; return Fail(e);
        }
        *ph = (HCRYPTPROV)p;
        return TRUE;
    }
    // "\\.\<reader>\<container>" or just "<container>": the pending logon key only
    std::wstring r = container;
    size_t slash = r.find_last_of(L'\\');
    std::wstring name = slash == std::wstring::npos ? r : r.substr(slash + 1);
    KV st;
    bool ok = ReadKV(PendingPath(), st) && !st[L"key"].empty() && st[L"key"] == name &&
              (st[L"state"] == L"armed" || st[L"state"] == L"used") &&
              _wtoi64(st[L"not_after"].c_str()) + 120 >= UnixNow();
    if (!ok) { delete p; Log(L"csp: AcquireContext %s -> no such pending key", container); return Fail((DWORD)NTE_BAD_KEYSET); }
    if (!CryptAcquireContextW(&p->sw, name.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                              CRYPT_SILENT | (st[L"keyscope"] == L"machine" ? CRYPT_MACHINE_KEYSET : 0))) {
        DWORD e = GetLastError(); delete p;
        Log(L"csp: AcquireContext %s -> software container 0x%08lx", container, e);
        return Fail((DWORD)NTE_BAD_KEYSET);
    }
    p->name = name;
    p->thumb = st[L"thumb"];
    *ph = (HCRYPTPROV)p;
    Log(L"csp: AcquireContext %s -> ok", container);
    return TRUE;
}

extern "C" BOOL WINAPI CPReleaseContext(HCRYPTPROV h, DWORD) {
    Prov* p = P(h);
    if (!p) return Fail((DWORD)NTE_BAD_UID);
    if (p->sw) CryptReleaseContext(p->sw, 0);
    p->magic = 0;
    delete p;
    return TRUE;
}

extern "C" BOOL WINAPI CPGetProvParam(HCRYPTPROV h, DWORD param, BYTE* out, DWORD* pcb, DWORD flags) {
    Prov* p = P(h);
    if (!p) return Fail((DWORD)NTE_BAD_UID);
    BOOL r;
    std::string name = A(p->name);
    switch (param) {
    case PP_NAME: r = Put(CSP_NAME_A, (DWORD)strlen(CSP_NAME_A) + 1, out, pcb); break;
    case PP_CONTAINER: case PP_UNIQUE_CONTAINER: r = Put(name.c_str(), (DWORD)name.size() + 1, out, pcb); break;
    case PP_PROVTYPE: { DWORD t = PROV_RSA_AES; r = Put(&t, sizeof(t), out, pcb); break; }
    case PP_IMPTYPE: { DWORD t = CRYPT_IMPL_HARDWARE | CRYPT_IMPL_REMOVABLE; r = Put(&t, sizeof(t), out, pcb); break; }
    case PP_VERSION: { DWORD v = 0x00000100; r = Put(&v, sizeof(v), out, pcb); break; }
    case PP_KEYSPEC: { DWORD v = AT_KEYEXCHANGE; r = Put(&v, sizeof(v), out, pcb); break; }
    case PP_SMARTCARD_READER: { const char* rd = "MOAVI Logon"; r = Put(rd, (DWORD)strlen(rd) + 1, out, pcb); break; }
    case PP_ENUMCONTAINERS:
        if (flags & CRYPT_FIRST) r = Put(name.c_str(), (DWORD)name.size() + 1, out, pcb);
        else r = Fail(ERROR_NO_MORE_ITEMS);
        break;
    case PP_USER_CERTSTORE: {
        // a memory store holding the logon certificate, linked to this key
        std::vector<BYTE> der;
        HCERTSTORE ms = CertDer(p->thumb, der) ? CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr) : nullptr;
        PCCERT_CONTEXT c = nullptr;
        if (ms && CertAddEncodedCertificateToStore(ms, X509_ASN_ENCODING, der.data(), (DWORD)der.size(), CERT_STORE_ADD_ALWAYS, &c)) {
            CRYPT_KEY_PROV_INFO kpi = {};
            kpi.pwszContainerName = (LPWSTR)p->name.c_str();
            kpi.pwszProvName = (LPWSTR)CSP_NAME_W;
            kpi.dwProvType = PROV_RSA_AES;
            kpi.dwFlags = CRYPT_SILENT;
            kpi.dwKeySpec = AT_KEYEXCHANGE;
            CertSetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);
            CertFreeCertificateContext(c);
            r = Put(&ms, sizeof(ms), out, pcb);
            if (!out) CertCloseStore(ms, 0);
        } else {
            if (ms) CertCloseStore(ms, 0);
            r = Fail((DWORD)NTE_NOT_FOUND);
        }
        break;
    }
    default:
        r = p->sw ? CryptGetProvParam(p->sw, param, out, pcb, flags) : Fail((DWORD)NTE_BAD_TYPE);
    }
    Log(L"csp: GetProvParam %lu flags 0x%lx -> %s 0x%08lx", param, flags, r ? L"ok" : L"fail", r ? 0 : GetLastError());
    return r;
}

extern "C" BOOL WINAPI CPSetProvParam(HCRYPTPROV h, DWORD param, const BYTE*, DWORD flags) {
    Prov* p = P(h);
    if (!p) return Fail((DWORD)NTE_BAD_UID);
    // a PIN (there is none), a window handle, a context: taken, never logged by value
    Log(L"csp: SetProvParam %lu flags 0x%lx -> ok", param, flags);
    return TRUE;
}

// --- keys --------------------------------------------------------------------------------------

extern "C" BOOL WINAPI CPGetUserKey(HCRYPTPROV h, DWORD spec, HCRYPTKEY* phKey) {
    Prov* p = P(h);
    if (!p || !phKey) return Fail((DWORD)NTE_BAD_UID);
    if (p->verify) return Fail((DWORD)NTE_NO_KEY);
    Key* k = new (std::nothrow) Key{ KEY_MAGIC, 0, AT_KEYEXCHANGE };
    if (!k) return Fail(ERROR_NOT_ENOUGH_MEMORY);
    // the container has one key, made as AT_KEYEXCHANGE (it signs too)
    if (!CryptGetUserKey(p->sw, AT_KEYEXCHANGE, &k->sw)) {
        DWORD e = GetLastError(); delete k;
        Log(L"csp: GetUserKey %lu -> 0x%08lx", spec, e);
        return Fail(e);
    }
    *phKey = (HCRYPTKEY)k;
    Log(L"csp: GetUserKey %lu -> ok", spec);
    return TRUE;
}

extern "C" BOOL WINAPI CPDestroyKey(HCRYPTPROV, HCRYPTKEY hk) {
    Key* k = K(hk);
    if (!k) return Fail((DWORD)NTE_BAD_KEY);
    if (k->sw) CryptDestroyKey(k->sw);
    k->magic = 0;
    delete k;
    return TRUE;
}

extern "C" BOOL WINAPI CPGetKeyParam(HCRYPTPROV h, HCRYPTKEY hk, DWORD param, BYTE* out, DWORD* pcb, DWORD flags) {
    Prov* p = P(h);
    Key* k = K(hk);
    if (!p || !k) return Fail((DWORD)NTE_BAD_KEY);
    BOOL r;
    if (param == KP_CERTIFICATE) {
        std::vector<BYTE> der;
        r = CertDer(p->thumb, der) ? Put(der.data(), (DWORD)der.size(), out, pcb) : Fail((DWORD)NTE_NOT_FOUND);
    } else {
        r = CryptGetKeyParam(k->sw, param, out, pcb, flags);
    }
    Log(L"csp: GetKeyParam %lu -> %s 0x%08lx", param, r ? L"ok" : L"fail", r ? 0 : GetLastError());
    return r;
}

extern "C" BOOL WINAPI CPSetKeyParam(HCRYPTPROV, HCRYPTKEY hk, DWORD param, const BYTE* data, DWORD flags) {
    Key* k = K(hk);
    if (!k) return Fail((DWORD)NTE_BAD_KEY);
    if (param == KP_CERTIFICATE) return Fail((DWORD)NTE_PERM);
    BOOL r = CryptSetKeyParam(k->sw, param, data, flags);
    Log(L"csp: SetKeyParam %lu -> %s", param, r ? L"ok" : L"fail");
    return r;
}

extern "C" BOOL WINAPI CPExportKey(HCRYPTPROV, HCRYPTKEY hk, HCRYPTKEY, DWORD type, DWORD flags, BYTE* out, DWORD* pcb) {
    Key* k = K(hk);
    if (!k) return Fail((DWORD)NTE_BAD_KEY);
    if (type != PUBLICKEYBLOB) { Log(L"csp: ExportKey type %lu -> refused", type); return Fail((DWORD)NTE_BAD_TYPE); }   // public only
    BOOL r = CryptExportKey(k->sw, 0, PUBLICKEYBLOB, flags, out, pcb);
    Log(L"csp: ExportKey public -> %s", r ? L"ok" : L"fail");
    return r;
}

extern "C" BOOL WINAPI CPGenKey(HCRYPTPROV, ALG_ID alg, DWORD, HCRYPTKEY*) { Log(L"csp: GenKey 0x%x -> refused", alg); return Fail((DWORD)NTE_PERM); }
extern "C" BOOL WINAPI CPDeriveKey(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*) { return Fail((DWORD)NTE_PERM); }
extern "C" BOOL WINAPI CPImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*) { Log(L"csp: ImportKey -> refused"); return Fail((DWORD)NTE_PERM); }
extern "C" BOOL WINAPI CPDuplicateKey(HCRYPTPROV, HCRYPTKEY, DWORD*, DWORD, HCRYPTKEY*) { return Fail((DWORD)NTE_PERM); }

extern "C" BOOL WINAPI CPEncrypt(HCRYPTPROV, HCRYPTKEY hk, HCRYPTHASH hh, BOOL fin, DWORD flags, BYTE* data, DWORD* pcb, DWORD cbBuf) {
    Key* k = K(hk);
    if (!k) return Fail((DWORD)NTE_BAD_KEY);
    Hash* x = H(hh);
    return CryptEncrypt(k->sw, x ? x->sw : 0, fin, flags, data, pcb, cbBuf);
}

extern "C" BOOL WINAPI CPDecrypt(HCRYPTPROV, HCRYPTKEY hk, HCRYPTHASH hh, BOOL fin, DWORD flags, BYTE* data, DWORD* pcb) {
    Key* k = K(hk);
    if (!k) return Fail((DWORD)NTE_BAD_KEY);
    Hash* x = H(hh);
    BOOL r = CryptDecrypt(k->sw, x ? x->sw : 0, fin, flags, data, pcb);
    Log(L"csp: Decrypt -> %s 0x%08lx", r ? L"ok" : L"fail", r ? 0 : GetLastError());
    return r;
}

// --- hashes and signatures ---------------------------------------------------------------------

extern "C" BOOL WINAPI CPCreateHash(HCRYPTPROV h, ALG_ID alg, HCRYPTKEY hk, DWORD flags, HCRYPTHASH* phHash) {
    Prov* p = P(h);
    if (!p || !phHash) return Fail((DWORD)NTE_BAD_UID);
    Hash* x = new (std::nothrow) Hash{ HASH_MAGIC, 0 };
    if (!x) return Fail(ERROR_NOT_ENOUGH_MEMORY);
    Key* k = K(hk);
    if (!CryptCreateHash(p->sw, alg, k ? k->sw : 0, flags, &x->sw)) {
        DWORD e = GetLastError(); delete x;
        Log(L"csp: CreateHash 0x%x -> 0x%08lx", alg, e);
        return Fail(e);
    }
    *phHash = (HCRYPTHASH)x;
    return TRUE;
}

extern "C" BOOL WINAPI CPHashData(HCRYPTPROV, HCRYPTHASH hh, const BYTE* data, DWORD n, DWORD flags) {
    Hash* x = H(hh);
    if (!x) return Fail((DWORD)NTE_BAD_HASH);
    return CryptHashData(x->sw, data, n, flags);
}

extern "C" BOOL WINAPI CPHashSessionKey(HCRYPTPROV, HCRYPTHASH hh, HCRYPTKEY hk, DWORD flags) {
    Hash* x = H(hh);
    Key* k = K(hk);
    if (!x || !k) return Fail((DWORD)NTE_BAD_HASH);
    return CryptHashSessionKey(x->sw, k->sw, flags);
}

extern "C" BOOL WINAPI CPGetHashParam(HCRYPTPROV, HCRYPTHASH hh, DWORD param, BYTE* out, DWORD* pcb, DWORD flags) {
    Hash* x = H(hh);
    if (!x) return Fail((DWORD)NTE_BAD_HASH);
    return CryptGetHashParam(x->sw, param, out, pcb, flags);
}

extern "C" BOOL WINAPI CPSetHashParam(HCRYPTPROV, HCRYPTHASH hh, DWORD param, const BYTE* data, DWORD flags) {
    Hash* x = H(hh);
    if (!x) return Fail((DWORD)NTE_BAD_HASH);
    return CryptSetHashParam(x->sw, param, data, flags);
}

extern "C" BOOL WINAPI CPDestroyHash(HCRYPTPROV, HCRYPTHASH hh) {
    Hash* x = H(hh);
    if (!x) return Fail((DWORD)NTE_BAD_HASH);
    if (x->sw) CryptDestroyHash(x->sw);
    x->magic = 0;
    delete x;
    return TRUE;
}

extern "C" BOOL WINAPI CPDuplicateHash(HCRYPTPROV, HCRYPTHASH hh, DWORD* reserved, DWORD flags, HCRYPTHASH* phHash) {
    Hash* x = H(hh);
    if (!x || !phHash) return Fail((DWORD)NTE_BAD_HASH);
    Hash* y = new (std::nothrow) Hash{ HASH_MAGIC, 0 };
    if (!y) return Fail(ERROR_NOT_ENOUGH_MEMORY);
    if (!CryptDuplicateHash(x->sw, reserved, flags, &y->sw)) { DWORD e = GetLastError(); delete y; return Fail(e); }
    *phHash = (HCRYPTHASH)y;
    return TRUE;
}

extern "C" BOOL WINAPI CPSignHash(HCRYPTPROV h, HCRYPTHASH hh, DWORD spec, LPCWSTR, DWORD flags, BYTE* sig, DWORD* pcb) {
    Prov* p = P(h);
    Hash* x = H(hh);
    if (!p || !x) return Fail((DWORD)NTE_BAD_HASH);
    // the one key signs, whatever spec is asked for
    BOOL r = CryptSignHashW(x->sw, AT_KEYEXCHANGE, nullptr, flags, sig, pcb);
    Log(L"csp: SignHash spec %lu flags 0x%lx%s -> %s 0x%08lx", spec, flags, sig ? L"" : L" (size)", r ? L"ok" : L"fail", r ? 0 : GetLastError());
    return r;
}

extern "C" BOOL WINAPI CPVerifySignature(HCRYPTPROV, HCRYPTHASH hh, const BYTE* sig, DWORD n, HCRYPTKEY hk, LPCWSTR, DWORD flags) {
    Hash* x = H(hh);
    Key* k = K(hk);
    if (!x || !k) return Fail((DWORD)NTE_BAD_HASH);
    return CryptVerifySignatureW(x->sw, sig, n, k->sw, nullptr, flags);
}

extern "C" BOOL WINAPI CPGenRandom(HCRYPTPROV h, DWORD n, BYTE* out) {
    Prov* p = P(h);
    if (!p) return Fail((DWORD)NTE_BAD_UID);
    return CryptGenRandom(p->sw, n, out);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
