<#
MOAVI Desk protocol benchmark - the workloads, run inside the Windows 11 desktop.

  Invoke-BenchWorkload.ps1 -Video D:\bench\bbb_1080p.mp4 [-Document D:\bench\long.pdf]
                           [-Workload all|idle|scroll|video|3d] [-Seconds 60] [-Gap 10]
                           [-OutDir $env:USERPROFILE\bench-out] [-NoCounters]

  idle    the desktop does nothing (what the protocol costs with a still screen)
  scroll  a long document scrolled down: -Document (a PDF, PageDown every 0.4 s) or, without
          it, the bundled office-like page (text, tables, charts) scrolled at a steady 900 px/s
  video   -Video (a local 1080p file) played full screen, looped
  3d      the bundled WebGL viewer: a lit 200k-triangle model rotating full screen
  all     idle, scroll, video, 3d in that order, -Gap seconds of still screen between them

Every workload runs in a fresh full-screen Microsoft Edge window with its own throw-away
profile, so a run does not depend on the user's browser state. Start it right after
capture.sh on the emulator, from inside the remote session you are measuring.

Writes to -OutDir:
  markers.json  the UTC start/end of every workload (benchstat.py cuts the capture with it -
                keep the desktop's clock synced: w32tm /resync)
  counters.csv  RDP counters once a second (Sample-Counters.ps1): frames/s, RTT, ...
#>
param(
    [ValidateSet('all', 'idle', 'scroll', 'video', '3d')] [string] $Workload = 'all',
    [int] $Seconds = 60,
    [int] $Gap = 10,
    [string] $Video,
    [string] $Document,
    [string] $OutDir = (Join-Path $env:USERPROFILE 'bench-out'),
    [switch] $NoCounters
)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Assets = Join-Path $Here 'assets'

$order = @(if ($Workload -eq 'all') { 'idle', 'scroll', 'video', '3d' } else { $Workload })
if ($order -contains 'video') {
    if (-not $Video -or -not (Test-Path $Video)) { throw '-Video <a local 1080p video file> is needed for the video workload' }
    $Video = (Resolve-Path $Video).Path
}
if ($Document) { $Document = (Resolve-Path $Document).Path }

$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
          "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw 'Microsoft Edge not found' }
$profileDir = Join-Path $env:TEMP 'moavi-bench-edge'

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Now-Epoch { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 }
function File-Url([string] $p) { ([Uri] $p).AbsoluteUri }

function Stop-BenchEdge {
    Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe'" |
        Where-Object { $_.CommandLine -like "*moavi-bench-edge*" } |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
}

function Start-BenchEdge([string] $url, [string[]] $extra = @()) {
    Stop-BenchEdge
    $argv = @("--user-data-dir=`"$profileDir`"", '--no-first-run', '--no-default-browser-check',
              '--disable-features=Translate,msEdgeSidebarV2', '--hide-crash-restore-bubble',
              '--autoplay-policy=no-user-gesture-required', '--start-fullscreen', '--new-window') + $extra + @("`"$url`"")
    Start-Process -FilePath $edge -ArgumentList $argv | Out-Null
}

$shell = New-Object -ComObject WScript.Shell
function Run-Workload([string] $name) {
    switch ($name) {
        'idle' {
            # minimize everything: a still desktop
            (New-Object -ComObject Shell.Application).MinimizeAll()
            Start-Sleep -Seconds 2
            return { Start-Sleep -Seconds $Seconds }
        }
        'scroll' {
            if ($Document) {
                Start-BenchEdge (File-Url $Document)
                Start-Sleep -Seconds 5
                return {
                    $end = (Get-Date).AddSeconds($Seconds)
                    while ((Get-Date) -lt $end) {
                        [void] $shell.AppActivate('Microsoft Edge')
                        $shell.SendKeys('{PGDN}')
                        Start-Sleep -Milliseconds 400
                    }
                }
            }
            Start-BenchEdge ((File-Url (Join-Path $Assets 'scroll.html')) + '?pxs=900')
            Start-Sleep -Seconds 5
            return { Start-Sleep -Seconds $Seconds }
        }
        'video' {
            Start-BenchEdge ((File-Url (Join-Path $Assets 'video.html')) + '?src=' + [Uri]::EscapeDataString((File-Url $Video)))
            Start-Sleep -Seconds 5
            return { Start-Sleep -Seconds $Seconds }
        }
        '3d' {
            # no GPU in most desktops: let Edge render WebGL in software (SwiftShader / WARP),
            # which is what a GPU-less VDI desktop does anyway
            Start-BenchEdge (File-Url (Join-Path $Assets 'webgl.html')) @('--ignore-gpu-blocklist', '--enable-unsafe-swiftshader')
            Start-Sleep -Seconds 5
            return { Start-Sleep -Seconds $Seconds }
        }
    }
}

$total = $order.Count * ($Seconds + 7 + $Gap) + 30
$sampler = $null
if (-not $NoCounters) {
    $sampler = Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $Here 'Sample-Counters.ps1')`"",
        '-Out', "`"$(Join-Path $OutDir 'counters.csv')`"", '-Seconds', $total)
}

$clock = try { (w32tm /query /source 2>$null | Out-String).Trim() } catch { '' }
$meta = [ordered]@{
    host = $env:COMPUTERNAME; seconds = $Seconds; gap = $Gap; clock_source = $clock
    video = if ($Video) { Split-Path -Leaf $Video } else { $null }
    document = if ($Document) { Split-Path -Leaf $Document } else { 'scroll.html' }
    workloads = @()
}
function Save-Markers { $meta | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $OutDir 'markers.json') }

try {
    Start-Sleep -Seconds $Gap
    foreach ($w in $order) {
        Write-Host "[$w] preparing"
        $body = Run-Workload $w
        $start = Now-Epoch
        Write-Host "[$w] $Seconds s"
        & $body
        $meta.workloads += [ordered]@{ workload = $w; start = $start; end = (Now-Epoch) }
        Save-Markers
        Stop-BenchEdge
        Start-Sleep -Seconds $Gap
    }
} finally {
    Stop-BenchEdge
    Save-Markers
    if ($sampler) {
        # ask the sampler to write its last rows and stop
        Set-Content -Path (Join-Path $OutDir 'counters.csv.stop') -Value ''
        if (-not $sampler.WaitForExit(5000)) { Stop-Process -Id $sampler.Id -ErrorAction SilentlyContinue }
        Remove-Item (Join-Path $OutDir 'counters.csv.stop') -ErrorAction SilentlyContinue
    }
}
Write-Host "done: $OutDir (markers.json, counters.csv) - copy it into the run folder on the emulator"
