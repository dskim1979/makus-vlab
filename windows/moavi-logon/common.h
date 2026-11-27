// MOAVI Desk Logon - shared helpers for moavi-logon.exe and the credential provider.
// The pending logon lives in C:\ProgramData\MoaviLogon\pending.txt (folder ACL: SYSTEM and
// Administrators only). It holds no secret: the private key stays in the Microsoft Software KSP
// (machine key, SYSTEM-only ACL, not exportable); the file only names it.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <map>

#define MOAVI_LOGON_VERSION L"1.0.5"
#define MOAVI_KEY_PREFIX L"MOAVI-Logon-"

namespace moavi {

typedef std::map<std::wstring, std::wstring> KV;

std::wstring DataDir();                 // C:\ProgramData\MoaviLogon
std::wstring PendingPath();
bool EnsureDataDir();                   // creates it with the SYSTEM + Administrators ACL
bool ReadKV(const std::wstring& path, KV& out);
bool WriteKV(const std::wstring& path, const KV& kv);   // write to .tmp then rename
KV ParseKV(const std::string& utf8);
std::wstring Utf8ToW(const std::string& s);
std::string WToUtf8(const std::wstring& s);
void Log(const wchar_t* fmt, ...);      // appends to DataDir()\logon.log (never secrets)
long long UnixNow();
std::wstring Hex(const BYTE* p, DWORD n);
bool UnHex(const std::wstring& h, std::string& out);

// The pending logon's key and certificate are removed (key from the KSP, cert from LocalMachine\My
// and SYSTEM's own My). Safe to call when nothing is there.
void RemoveKeyAndCert(const std::wstring& keyName, const std::wstring& thumbHex);

// The key's scope: "user" (default) = SYSTEM's own key, the one LSASS (SYSTEM) opens for a certificate
// logon; "machine" = a machine key (LSA reports STATUS_SMARTCARD_NO_KEY_CONTAINER for it).
inline DWORD KeyScopeFlags(const std::wstring& scope) { return scope == L"machine" ? 0x20 /* NCRYPT_MACHINE_KEY_FLAG */ : 0; }

}  // namespace moavi
