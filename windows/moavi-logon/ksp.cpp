// MOAVI Desk Logon key storage provider (moavi-logon-ksp.dll), "MOAVI Logon Key Storage Provider".
//
// Windows' smart card logon (LSASS, Kerberos PKINIT) only takes a key from a smart card provider: a
// software CSP / KSP key is refused (STATUS_SMARTCARD_NO_KEY_CONTAINER / _SUBSYSTEM_FAILURE). This
// provider presents the one pending logon key - made by moavi-logon.exe prepare in the Microsoft
// Software KSP, SYSTEM's own, not exportable - the way a card would: it takes a PIN (there is none,
// any value does), answers the certificate from the card, and passes the private key operations
// (sign, decrypt) to the software key. Nothing else: no key is made, imported or exported here, and
// only the key named in C:\ProgramData\MoaviLogon\pending.txt (armed or just used, not expired) opens.
// Every call is written to C:\ProgramData\MoaviLogon\logon.log ("ksp:"), never key material.
#include "common.h"
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <new>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

using namespace moavi;

#ifndef NTE_NOT_SUPPORTED
#define NTE_NOT_SUPPORTED ((SECURITY_STATUS)0x80090029L)
#endif

static const wchar_t* KSP_NAME = L"MOAVI Logon Key Storage Provider";

// --- the provider function table (ncrypt_provider.h of the CPDK, interface version 1) ------------

typedef SECURITY_STATUS (WINAPI* OpenProviderFn)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI* OpenKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* CreatePersistedKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* GetProviderPropertyFn)(NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* GetKeyPropertyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* SetProviderPropertyFn)(NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* SetKeyPropertyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* FinalizeKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
typedef SECURITY_STATUS (WINAPI* DeleteKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
typedef SECURITY_STATUS (WINAPI* FreeProviderFn)(NCRYPT_PROV_HANDLE);
typedef SECURITY_STATUS (WINAPI* FreeKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE);
typedef SECURITY_STATUS (WINAPI* FreeBufferFn)(PVOID);
typedef SECURITY_STATUS (WINAPI* CryptFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* IsAlgSupportedFn)(NCRYPT_PROV_HANDLE, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI* EnumAlgorithmsFn)(NCRYPT_PROV_HANDLE, DWORD, DWORD*, NCryptAlgorithmName**, DWORD);
typedef SECURITY_STATUS (WINAPI* EnumKeysFn)(NCRYPT_PROV_HANDLE, LPCWSTR, NCryptKeyName**, PVOID*, DWORD);
typedef SECURITY_STATUS (WINAPI* ImportKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* ExportKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* SignHashFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* VerifySignatureFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* PromptUserFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI* NotifyChangeKeyFn)(NCRYPT_PROV_HANDLE, HANDLE*, DWORD);
typedef SECURITY_STATUS (WINAPI* SecretAgreementFn)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_SECRET_HANDLE*, DWORD);
typedef SECURITY_STATUS (WINAPI* DeriveKeyFn)(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, ULONG);
typedef SECURITY_STATUS (WINAPI* FreeSecretFn)(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE);

struct KSP_TABLE {
    BCRYPT_INTERFACE_VERSION Version;
    OpenProviderFn OpenProvider;
    OpenKeyFn OpenKey;
    CreatePersistedKeyFn CreatePersistedKey;
    GetProviderPropertyFn GetProviderProperty;
    GetKeyPropertyFn GetKeyProperty;
    SetProviderPropertyFn SetProviderProperty;
    SetKeyPropertyFn SetKeyProperty;
    FinalizeKeyFn FinalizeKey;
    DeleteKeyFn DeleteKey;
    FreeProviderFn FreeProvider;
    FreeKeyFn FreeKey;
    FreeBufferFn FreeBuffer;
    CryptFn Encrypt;
    CryptFn Decrypt;
    IsAlgSupportedFn IsAlgSupported;
    EnumAlgorithmsFn EnumAlgorithms;
    EnumKeysFn EnumKeys;
    ImportKeyFn ImportKey;
    ExportKeyFn ExportKey;
    SignHashFn SignHash;
    VerifySignatureFn VerifySignature;
    PromptUserFn PromptUser;
    NotifyChangeKeyFn NotifyChangeKey;
    SecretAgreementFn SecretAgreement;
    DeriveKeyFn DeriveKey;
    FreeSecretFn FreeSecret;
};

// --- handles -----------------------------------------------------------------------------------

static const DWORD PROV_MAGIC = 0x4D4C5056;   // 'MLPV'
static const DWORD KEY_MAGIC = 0x4D4C4B59;    // 'MLKY'

struct Prov { DWORD magic; };
struct Key {
    DWORD magic;
    NCRYPT_PROV_HANDLE swProv;
    NCRYPT_KEY_HANDLE swKey;
    std::wstring name;
    std::wstring thumb;
};

static Prov* P(NCRYPT_PROV_HANDLE h) {
    Prov* p = (Prov*)h;
    return p && p->magic == PROV_MAGIC ? p : nullptr;
}
static Key* K(NCRYPT_KEY_HANDLE h) {
    Key* k = (Key*)h;
    return k && k->magic == KEY_MAGIC ? k : nullptr;
}

static const wchar_t* S(LPCWSTR s) { return s ? s : L"(null)"; }

// The pending logon key: its name (after any "\\.\reader\" prefix) must be the one in pending.txt,
// armed or just used, and not long expired.
static bool PendingKey(LPCWSTR requested, KV& st, std::wstring& name) {
    if (!requested) return false;
    std::wstring r = requested;
    size_t slash = r.find_last_of(L'\\');
    name = slash == std::wstring::npos ? r : r.substr(slash + 1);
    if (!ReadKV(PendingPath(), st)) return false;
    if (st[L"key"].empty() || st[L"key"] != name) return false;
    if (st[L"state"] != L"armed" && st[L"state"] != L"used") return false;
    if (_wtoi64(st[L"not_after"].c_str()) + 120 < UnixNow()) return false;
    return true;
}

static SECURITY_STATUS PutBytes(const void* data, DWORD len, PBYTE out, DWORD cbOut, DWORD* pcb) {
    if (!pcb) return NTE_INVALID_PARAMETER;
    *pcb = len;
    if (!out) return ERROR_SUCCESS;
    if (cbOut < len) return NTE_BUFFER_TOO_SMALL;
    memcpy(out, data, len);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS PutDword(DWORD v, PBYTE out, DWORD cbOut, DWORD* pcb) { return PutBytes(&v, sizeof(v), out, cbOut, pcb); }

static SECURITY_STATUS PutString(const wchar_t* s, PBYTE out, DWORD cbOut, DWORD* pcb) {
    return PutBytes(s, (DWORD)((wcslen(s) + 1) * sizeof(wchar_t)), out, cbOut, pcb);
}

// the logon certificate (DER), from SYSTEM's My or the machine's My
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

// --- the functions -----------------------------------------------------------------------------

static SECURITY_STATUS WINAPI OpenProvider(NCRYPT_PROV_HANDLE* ph, LPCWSTR name, DWORD flags) {
    Log(L"ksp: OpenProvider %s flags 0x%lx", S(name), flags);
    if (!ph) return NTE_INVALID_PARAMETER;
    Prov* p = new (std::nothrow) Prov{ PROV_MAGIC };
    if (!p) return NTE_NO_MEMORY;
    *ph = (NCRYPT_PROV_HANDLE)p;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI FreeProvider(NCRYPT_PROV_HANDLE h) {
    Prov* p = P(h);
    if (!p) return NTE_INVALID_HANDLE;
    p->magic = 0;
    delete p;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI OpenKey(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE* phKey, LPCWSTR keyName, DWORD spec, DWORD flags) {
    if (!P(hp) || !phKey) return NTE_INVALID_PARAMETER;
    KV st;
    std::wstring name;
    if (!PendingKey(keyName, st, name)) {
        Log(L"ksp: OpenKey %s spec %lu flags 0x%lx -> no such pending key", S(keyName), spec, flags);
        return NTE_BAD_KEYSET;
    }
    NCRYPT_PROV_HANDLE sw = 0;
    NCRYPT_KEY_HANDLE swKey = 0;
    SECURITY_STATUS ss = NCryptOpenStorageProvider(&sw, MS_KEY_STORAGE_PROVIDER, 0);
    if (ss == ERROR_SUCCESS)
        ss = NCryptOpenKey(sw, &swKey, name.c_str(), 0, KeyScopeFlags(st[L"keyscope"]) | NCRYPT_SILENT_FLAG);
    if (ss != ERROR_SUCCESS) {
        Log(L"ksp: OpenKey %s -> software key 0x%08lx", S(keyName), (unsigned long)ss);
        if (sw) NCryptFreeObject(sw);
        return NTE_BAD_KEYSET;
    }
    Key* k = new (std::nothrow) Key();
    if (!k) { NCryptFreeObject(swKey); NCryptFreeObject(sw); return NTE_NO_MEMORY; }
    k->magic = KEY_MAGIC;
    k->swProv = sw;
    k->swKey = swKey;
    k->name = name;
    k->thumb = st[L"thumb"];
    *phKey = (NCRYPT_KEY_HANDLE)k;
    Log(L"ksp: OpenKey %s spec %lu flags 0x%lx -> ok", S(keyName), spec, flags);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI FreeKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE hk) {
    Key* k = K(hk);
    if (!k) return NTE_INVALID_HANDLE;
    if (k->swKey) NCryptFreeObject(k->swKey);
    if (k->swProv) NCryptFreeObject(k->swProv);
    k->magic = 0;
    delete k;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI GetProviderProperty(NCRYPT_PROV_HANDLE hp, LPCWSTR prop, PBYTE out, DWORD cbOut, DWORD* pcb, DWORD flags) {
    if (!P(hp) || !prop) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = NTE_NOT_SUPPORTED;
    if (!wcscmp(prop, NCRYPT_IMPL_TYPE_PROPERTY)) r = PutDword(NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG, out, cbOut, pcb);
    else if (!wcscmp(prop, NCRYPT_NAME_PROPERTY)) r = PutString(KSP_NAME, out, cbOut, pcb);
    else if (!wcscmp(prop, NCRYPT_VERSION_PROPERTY)) r = PutDword(0x00010000, out, cbOut, pcb);
    else if (!wcscmp(prop, NCRYPT_MAX_NAME_LENGTH_PROPERTY)) r = PutDword(260, out, cbOut, pcb);
    else if (!wcscmp(prop, NCRYPT_READER_PROPERTY)) r = PutString(L"MOAVI Logon Reader", out, cbOut, pcb);
    else if (!wcscmp(prop, NCRYPT_SMARTCARD_GUID_PROPERTY)) {
        static const GUID g = { 0x6a1f2c3d, 0x7e8b, 0x4a90, { 0x9c, 0x1d, 0x2b, 0x3e, 0x4f, 0x5a, 0x6b, 0x71 } };
        r = PutBytes(&g, sizeof(g), out, cbOut, pcb);
    }
    Log(L"ksp: GetProviderProperty %s flags 0x%lx -> 0x%08lx", prop, flags, (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI SetProviderProperty(NCRYPT_PROV_HANDLE hp, LPCWSTR prop, PBYTE, DWORD cb, DWORD flags) {
    if (!P(hp) || !prop) return NTE_INVALID_PARAMETER;
    // a PIN, a window, a use context: taken, nothing to do with them (never logged by value)
    Log(L"ksp: SetProviderProperty %s (%lu bytes) flags 0x%lx -> ok", prop, cb, flags);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI GetKeyProperty(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, LPCWSTR prop, PBYTE out, DWORD cbOut, DWORD* pcb, DWORD flags) {
    Key* k = K(hk);
    if (!P(hp) || !k || !prop) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r;
    if (!wcscmp(prop, NCRYPT_CERTIFICATE_PROPERTY)) {
        std::vector<BYTE> der;
        r = CertDer(k->thumb, der) ? PutBytes(der.data(), (DWORD)der.size(), out, cbOut, pcb) : NTE_NOT_FOUND;
    } else if (!wcscmp(prop, NCRYPT_IMPL_TYPE_PROPERTY)) {
        r = PutDword(NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG, out, cbOut, pcb);
    } else if (!wcscmp(prop, NCRYPT_NAME_PROPERTY) || !wcscmp(prop, NCRYPT_UNIQUE_NAME_PROPERTY)) {
        r = PutString(k->name.c_str(), out, cbOut, pcb);
    } else if (!wcscmp(prop, NCRYPT_PROVIDER_HANDLE_PROPERTY)) {
        r = PutBytes(&hp, sizeof(hp), out, cbOut, pcb);
    } else {
        // algorithm, length, key usage, export policy, ...: the software key's own
        r = NCryptGetProperty(k->swKey, prop, out, cbOut, pcb, flags & ~NCRYPT_PERSIST_ONLY_FLAG);
    }
    Log(L"ksp: GetKeyProperty %s flags 0x%lx -> 0x%08lx", prop, flags, (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI SetKeyProperty(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, LPCWSTR prop, PBYTE, DWORD cb, DWORD flags) {
    if (!P(hp) || !K(hk) || !prop) return NTE_INVALID_PARAMETER;
    // the PIN (there is none), a window handle, a use context: taken; the key itself never changes
    Log(L"ksp: SetKeyProperty %s (%lu bytes) flags 0x%lx -> ok", prop, cb, flags);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI SignHash(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, VOID* pad, PBYTE hash, DWORD cbHash,
                                       PBYTE sig, DWORD cbSig, DWORD* pcb, DWORD flags) {
    Key* k = K(hk);
    if (!P(hp) || !k) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = NCryptSignHash(k->swKey, pad, hash, cbHash, sig, cbSig, pcb, flags | NCRYPT_SILENT_FLAG);
    Log(L"ksp: SignHash %lu bytes flags 0x%lx%s -> 0x%08lx", cbHash, flags, sig ? L"" : L" (size)", (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI Decrypt(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, PBYTE in, DWORD cbIn, VOID* pad,
                                      PBYTE out, DWORD cbOut, DWORD* pcb, DWORD flags) {
    Key* k = K(hk);
    if (!P(hp) || !k) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = NCryptDecrypt(k->swKey, in, cbIn, pad, out, cbOut, pcb, flags | NCRYPT_SILENT_FLAG);
    Log(L"ksp: Decrypt %lu bytes flags 0x%lx%s -> 0x%08lx", cbIn, flags, out ? L"" : L" (size)", (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI Encrypt(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, PBYTE in, DWORD cbIn, VOID* pad,
                                      PBYTE out, DWORD cbOut, DWORD* pcb, DWORD flags) {
    Key* k = K(hk);
    if (!P(hp) || !k) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = NCryptEncrypt(k->swKey, in, cbIn, pad, out, cbOut, pcb, flags | NCRYPT_SILENT_FLAG);
    Log(L"ksp: Encrypt %lu bytes -> 0x%08lx", cbIn, (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI VerifySignature(NCRYPT_PROV_HANDLE hp, NCRYPT_KEY_HANDLE hk, VOID* pad, PBYTE hash, DWORD cbHash,
                                              PBYTE sig, DWORD cbSig, DWORD flags) {
    Key* k = K(hk);
    if (!P(hp) || !k) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = NCryptVerifySignature(k->swKey, pad, hash, cbHash, sig, cbSig, flags | NCRYPT_SILENT_FLAG);
    Log(L"ksp: VerifySignature -> 0x%08lx", (unsigned long)r);
    return r;
}

static SECURITY_STATUS WINAPI IsAlgSupported(NCRYPT_PROV_HANDLE hp, LPCWSTR alg, DWORD flags) {
    if (!P(hp) || !alg) return NTE_INVALID_PARAMETER;
    SECURITY_STATUS r = !wcscmp(alg, BCRYPT_RSA_ALGORITHM) ? ERROR_SUCCESS : NTE_NOT_SUPPORTED;
    Log(L"ksp: IsAlgSupported %s flags 0x%lx -> 0x%08lx", alg, flags, (unsigned long)r);
    return r;
}

struct EnumState { DWORD magic; int done; };

static SECURITY_STATUS WINAPI EnumKeys(NCRYPT_PROV_HANDLE hp, LPCWSTR scope, NCryptKeyName** ppKey, PVOID* ppState, DWORD flags) {
    if (!P(hp) || !ppKey || !ppState) return NTE_INVALID_PARAMETER;
    KV st;
    if (*ppState || !ReadKV(PendingPath(), st) || st[L"key"].empty() ||
        (st[L"state"] != L"armed" && st[L"state"] != L"used")) {
        Log(L"ksp: EnumKeys %s flags 0x%lx -> no more", S(scope), flags);
        return NTE_NO_MORE_ITEMS;
    }
    std::wstring name = st[L"key"];
    size_t nameBytes = (name.size() + 1) * sizeof(wchar_t), algBytes = sizeof(L"RSA");
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptKeyName) + nameBytes + algBytes);
    EnumState* es = (EnumState*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EnumState));
    if (!buf || !es) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        if (es) HeapFree(GetProcessHeap(), 0, es);
        return NTE_NO_MEMORY;
    }
    NCryptKeyName* kn = (NCryptKeyName*)buf;
    kn->pszName = (LPWSTR)(buf + sizeof(NCryptKeyName));
    memcpy(kn->pszName, name.c_str(), nameBytes);
    kn->pszAlgid = (LPWSTR)(buf + sizeof(NCryptKeyName) + nameBytes);
    memcpy(kn->pszAlgid, L"RSA", algBytes);
    kn->dwLegacyKeySpec = AT_KEYEXCHANGE;
    kn->dwFlags = 0;
    es->magic = 0x4D4C454E;
    es->done = 1;
    *ppKey = kn;
    *ppState = es;
    Log(L"ksp: EnumKeys %s flags 0x%lx -> %s", S(scope), flags, name.c_str());
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI FreeBuffer(PVOID p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI CreatePersistedKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR alg, LPCWSTR name, DWORD, DWORD) {
    Log(L"ksp: CreatePersistedKey %s %s -> not supported", S(alg), S(name));
    return NTE_NOT_SUPPORTED;
}
static SECURITY_STATUS WINAPI FinalizeKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD) { return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI DeleteKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD) {
    Log(L"ksp: DeleteKey -> not supported");
    return NTE_NOT_SUPPORTED;
}
static SECURITY_STATUS WINAPI EnumAlgorithms(NCRYPT_PROV_HANDLE, DWORD ops, DWORD*, NCryptAlgorithmName**, DWORD) {
    Log(L"ksp: EnumAlgorithms 0x%lx -> not supported", ops);
    return NTE_NOT_SUPPORTED;
}
static SECURITY_STATUS WINAPI ImportKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR type, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD) {
    Log(L"ksp: ImportKey %s -> not supported", S(type));
    return NTE_NOT_SUPPORTED;
}
static SECURITY_STATUS WINAPI ExportKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR type, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD) {
    Log(L"ksp: ExportKey %s -> not supported", S(type));
    return NTE_NOT_SUPPORTED;   // public blobs too: the certificate carries the public key
}
static SECURITY_STATUS WINAPI PromptUser(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR op, DWORD) {
    Log(L"ksp: PromptUser %s -> ok (no UI)", S(op));
    return ERROR_SUCCESS;
}
static SECURITY_STATUS WINAPI NotifyChangeKey(NCRYPT_PROV_HANDLE, HANDLE*, DWORD) { return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI SecretAgreement(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_SECRET_HANDLE*, DWORD) {
    Log(L"ksp: SecretAgreement -> not supported");
    return NTE_NOT_SUPPORTED;
}
static SECURITY_STATUS WINAPI DeriveKey(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, ULONG) { return NTE_NOT_SUPPORTED; }
static SECURITY_STATUS WINAPI FreeSecret(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE) { return NTE_NOT_SUPPORTED; }

static KSP_TABLE g_table = {
    { 1, 0 },
    OpenProvider, OpenKey, CreatePersistedKey, GetProviderProperty, GetKeyProperty, SetProviderProperty,
    SetKeyProperty, FinalizeKey, DeleteKey, FreeProvider, FreeKey, FreeBuffer, Encrypt, Decrypt,
    IsAlgSupported, EnumAlgorithms, EnumKeys, ImportKey, ExportKey, SignHash, VerifySignature,
    PromptUser, NotifyChangeKey, SecretAgreement, DeriveKey, FreeSecret,
};

extern "C" NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR name, KSP_TABLE** table, DWORD flags) {
    Log(L"ksp: GetKeyStorageInterface %s flags 0x%lx (pid %lu)", S(name), flags, GetCurrentProcessId());
    if (!table) return (NTSTATUS)0xC000000DL;
    *table = &g_table;
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
