# MOAVI Desk Logon - installer, run as SYSTEM by the engine through the guest agent
# (pegaprox/api/vlab_logon.py install). Also usable by hand in an elevated PowerShell:
#   install.ps1 -Setup <folder with the files> [-NoVerify]     install / update
#   install.ps1 -Uninstall                                     remove the module (the CA trust stays)
# stdin (from the engine): one line per file, "name|parts|sha256"; every file is checked against it.
# Prints key=value lines; install=ok at the end.
param(
    [string]$Setup = '',
    [switch]$Uninstall,
    [switch]$NoVerify
)
$ErrorActionPreference = 'Stop'
$clsid = '{6A1F2C3D-7E8B-4A90-9C1D-2B3E4F5A6B70}'
$dest = Join-Path $env:ProgramFiles 'MOAVI\Logon'
$data = Join-Path $env:ProgramData 'MoaviLogon'
$cpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$clsKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"

function Fail($m) { "error=$m"; exit 1 }

if ($Uninstall) {
    if (Test-Path $cpKey) { Remove-Item -Recurse -Force $cpKey }
    if (Test-Path $clsKey) { Remove-Item -Recurse -Force $clsKey }
    if (Test-Path (Join-Path $dest 'moavi-logon.exe')) {
        & (Join-Path $dest 'moavi-logon.exe') clear | Out-Null
        & (Join-Path $dest 'moavi-logon.exe') unregister-ksp | Out-Null
    }
    'uninstall=ok'
    exit 0
}

try {
    if (-not $Setup -or -not (Test-Path $Setup)) { Fail 'no setup folder' }
    # 1. the files are the engine's
    if (-not $NoVerify) {
        $manifest = [Console]::In.ReadToEnd() -split "`n" | Where-Object { $_ -match '\|' }
        if (-not $manifest) { Fail 'no manifest' }
        foreach ($line in $manifest) {
            $name, $parts, $sha = $line.Trim() -split '\|'
            $f = Join-Path $Setup $name
            if (-not (Test-Path $f)) { Fail "missing $name" }
            $got = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
            if ($got -ne $sha.ToLower()) { Fail "checksum $name" }
        }
    }
    foreach ($n in 'moavi-logon.exe', 'moavi-logon-cp.dll', 'moavi-logon-ksp.dll', 'moavi-logon-ca.cer') {
        if (-not (Test-Path (Join-Path $Setup $n))) { Fail "missing $n" }
    }

    # 2. the program folder: SYSTEM / Administrators write, Users read
    New-Item -ItemType Directory -Force $dest | Out-Null
    icacls $dest /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
    foreach ($n in 'moavi-logon.exe', 'moavi-logon-cp.dll') {
        $t = Join-Path $dest $n
        if (Test-Path $t) {
            # LogonUI may have the DLL loaded: move it aside (allowed while loaded), the next boot drops it
            $old = "$t.old-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
            try { Remove-Item -Force $t } catch { Move-Item -Force $t $old }
        }
        Copy-Item -Force (Join-Path $Setup $n) $t
    }
    Get-ChildItem $dest -Filter '*.old-*' -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item -Force $_.FullName } catch {} }

    # 2b. the key storage provider: in System32 (CNG loads registered images from there), then registered
    $ksp = Join-Path $env:SystemRoot 'System32\moavi-logon-ksp.dll'
    if (Test-Path $ksp) {
        $old = "$ksp.old-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
        try { Remove-Item -Force $ksp } catch { Move-Item -Force $ksp $old }   # LSASS may have it loaded
    }
    Copy-Item -Force (Join-Path $Setup 'moavi-logon-ksp.dll') $ksp
    Get-ChildItem (Split-Path $ksp) -Filter 'moavi-logon-ksp.dll.old-*' -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item -Force $_.FullName } catch {} }

    # 3. the data folder (pending logon, log): SYSTEM / Administrators only
    New-Item -ItemType Directory -Force $data | Out-Null
    icacls $data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

    # 4. the credential provider
    $dll = Join-Path $dest 'moavi-logon-cp.dll'
    New-Item -Force $clsKey | Out-Null
    Set-ItemProperty $clsKey '(default)' 'MOAVI Desk Logon'
    New-Item -Force "$clsKey\InprocServer32" | Out-Null
    Set-ItemProperty "$clsKey\InprocServer32" '(default)' $dll
    Set-ItemProperty "$clsKey\InprocServer32" 'ThreadingModel' 'Apartment'
    New-Item -Force $cpKey | Out-Null
    Set-ItemProperty $cpKey '(default)' 'MOAVI Desk Logon'

    $reg = & (Join-Path $dest 'moavi-logon.exe') register-ksp
    if ($LASTEXITCODE -ne 0) { Fail "ksp: $reg" }
    $reg
    # the smart card logon path wants the Smart Card service
    Set-Service SCardSvr -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service SCardSvr -ErrorAction SilentlyContinue

    # 4b. the VM's TPM virtual smart card: the logon key is made on it (Windows' smart card logon takes
    # no software key). Needs a (v)TPM; without one the module stays on the software key.
    $exe = Join-Path $dest 'moavi-logon.exe'
    $tpm = $null
    try { $tpm = Get-Tpm } catch {}
    if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
        $vi = & $exe vsc-info 2>&1
        if ($LASTEXITCODE -ne 0) {
            $mk = & tpmvscmgr.exe create /name 'MOAVI Logon' /pin default /adminkey random /generate 2>&1
            if ($LASTEXITCODE -ne 0) { "vsc=failed $($mk | Select-Object -Last 1)" }
            Start-Sleep -Seconds 3
            $vi = & $exe vsc-info 2>&1
        }
        $vi
    } else {
        'vsc=no-tpm'
    }

    # 4c. RDP sessions use the VM's own card readers: with smart card redirection on, Windows sends a
    # session's smart card calls to the RDP client (Warpgate has no readers) and the logon never sees
    # the VM's virtual smart card (Smart Card Logon event 5, STATUS_SMARTCARD_SUBSYSTEM_FAILURE).
    # Policy "Do not allow smart card device redirection".
    $ts = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    if (-not (Test-Path $ts)) { New-Item -Force $ts | Out-Null }
    Set-ItemProperty -Path $ts -Name 'fEnableSmartCard' -Value 0 -Type DWord
    'scard_redirect=off'

    # 5. trust the MOAVI Desk Logon CA: Root (chain) and NTAuth (smart card logon)
    $ca = Join-Path $Setup 'moavi-logon-ca.cer'
    $r1 = certutil -f -addstore Root $ca 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "Root store: $($r1 | Select-Object -Last 1)" }
    $r2 = certutil -f -enterprise -addstore NTAuth $ca 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "NTAuth store: $($r2 | Select-Object -Last 1)" }
    $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ca).Thumbprint

    # 6. what the module says now
    $st = & (Join-Path $dest 'moavi-logon.exe') status
    $st
    "ca=$thumb"
    Remove-Item -Recurse -Force $Setup -ErrorAction SilentlyContinue
    'install=ok'
    exit 0
} catch {
    Fail ($_.Exception.Message -replace "`r?`n", ' ')
}
