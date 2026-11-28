#include "common.h"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace moavi {

std::wstring DataDir() {
    wchar_t buf[MAX_PATH] = L"C:\\ProgramData";
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) wcscpy_s(buf, L"C:\\ProgramData");
    return std::wstring(buf) + L"\\MoaviLogon";
}

std::wstring PendingPath() { return DataDir() + L"\\pending.txt"; }

bool EnsureDataDir() {
    // SYSTEM and Administrators full control, protected (no inheritance from ProgramData, where
    // Users may create files).
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, nullptr))
        return false;
    std::wstring dir = DataDir();
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    BOOL ok = CreateDirectoryW(dir.c_str(), &sa);
    if (!ok && GetLastError() == ERROR_ALREADY_EXISTS) {
        BOOL present = FALSE, defaulted = FALSE;
        PACL dacl = nullptr;
        GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
        ok = SetNamedSecurityInfoW((LPWSTR)dir.c_str(), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
    }
    LocalFree(sd);
    return ok != FALSE;
}

std::wstring Utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::string WToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

KV ParseKV(const std::string& utf8) {
    KV kv;
    size_t i = 0;
    while (i < utf8.size()) {
        size_t e = utf8.find('\n', i);
        if (e == std::string::npos) e = utf8.size();
        std::string line = utf8.substr(i, e - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0)
            kv[Utf8ToW(line.substr(0, eq))] = Utf8ToW(line.substr(eq + 1));
        i = e + 1;
    }
    return kv;
}

bool ReadKV(const std::wstring& path, KV& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::string data;
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0 && data.size() < (1 << 20))
        data.append(buf, got);
    CloseHandle(h);
    out = ParseKV(data);
    return true;
}

bool WriteKV(const std::wstring& path, const KV& kv) {
    std::string data;
    for (auto& p : kv) data += WToUtf8(p.first) + "=" + WToUtf8(p.second) + "\n";
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &put, nullptr) && put == data.size();
    FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) { DeleteFileW(tmp.c_str()); return false; }
    return MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

void Log(const wchar_t* fmt, ...) {
    wchar_t msg[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(msg, _countof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    SYSTEMTIME st;
    GetSystemTime(&st);
    wchar_t line[1200];
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"%04d-%02d-%02dT%02d:%02d:%02dZ pid=%lu %s\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId(), msg);
    std::string u = WToUtf8(line);
    std::wstring path = DataDir() + L"\\logon.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size;
    if (GetFileSizeEx(h, &size) && size.QuadPart > 2 * 1024 * 1024) {
        CloseHandle(h);
        std::wstring old = path + L".1";
        MoveFileExW(path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING);
        h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
    }
    DWORD put = 0;
    WriteFile(h, u.data(), (DWORD)u.size(), &put, nullptr);
    CloseHandle(h);
}

long long UnixNow() { return (long long)time(nullptr); }

std::wstring Hex(const BYTE* p, DWORD n) {
    static const wchar_t* d = L"0123456789abcdef";
    std::wstring s;
    for (DWORD i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

static int HexVal(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

bool UnHex(const std::wstring& h, std::string& out) {
    out.clear();
    if (h.size() % 2) return false;
    for (size_t i = 0; i < h.size(); i += 2) {
        int a = HexVal(h[i]), b = HexVal(h[i + 1]);
        if (a < 0 || b < 0) return false;
        out += (char)((a << 4) | b);
    }
    return true;
}

static void RemoveCertFrom(DWORD location, const std::string& thumb) {
    HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, location | CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
    if (!st) return;
    CRYPT_HASH_BLOB blob = { (DWORD)thumb.size(), (BYTE*)thumb.data() };
    PCCERT_CONTEXT c;
    while ((c = CertFindCertificateInStore(st, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr)) != nullptr)
        CertDeleteCertificateFromStore(c);   // frees c
    CertCloseStore(st, 0);
}

bool ReadVsc(KV& vsc) {
    return ReadKV(DataDir() + L"\\vsc.txt", vsc) && !vsc[L"reader"].empty();
}

std::wstring VscContainer(const KV& vscc, const std::wstring& keyName) {
    KV vsc = vscc;
    return L"\\\\.\\" + vsc[L"reader"] + L"\\" + keyName;
}

static void RemoveVscKey(const std::wstring& keyName) {
    KV vsc;
    if (!ReadVsc(vsc)) return;
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return;
    NCRYPT_KEY_HANDLE key = 0;
    std::wstring full = VscContainer(vsc, keyName);
    if (NCryptOpenKey(prov, &key, full.c_str(), AT_KEYEXCHANGE, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        std::wstring pin = vsc[L"pin"];
        NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, (PBYTE)pin.c_str(), (DWORD)((pin.size() + 1) * sizeof(wchar_t)), NCRYPT_SILENT_FLAG);
        if (NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) NCryptFreeObject(key);
    }
    NCryptFreeObject(prov);
}

void RemoveKeyAndCert(const std::wstring& keyName, const std::wstring& thumbHex) {
    std::string thumb;
    if (!thumbHex.empty() && UnHex(thumbHex, thumb) && thumb.size() == 20) {
        RemoveCertFrom(CERT_SYSTEM_STORE_LOCAL_MACHINE, thumb);
        RemoveCertFrom(CERT_SYSTEM_STORE_CURRENT_USER, thumb);
    }
    if (keyName.empty() || keyName.compare(0, wcslen(MOAVI_KEY_PREFIX), MOAVI_KEY_PREFIX) != 0) return;
    RemoveVscKey(keyName);
    for (DWORD scope : { (DWORD)0, (DWORD)CRYPT_MACHINE_KEYSET }) {
        HCRYPTPROV hp = 0;
        CryptAcquireContextW(&hp, keyName.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET | CRYPT_SILENT | scope);
    }
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return;
    for (DWORD scope : { (DWORD)0, (DWORD)NCRYPT_MACHINE_KEY_FLAG }) {
        NCRYPT_KEY_HANDLE key = 0;
        if (NCryptOpenKey(prov, &key, keyName.c_str(), 0, scope | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
            NCryptDeleteKey(key, 0);   // frees key
    }
    NCryptFreeObject(prov);
}

}  // namespace moavi
