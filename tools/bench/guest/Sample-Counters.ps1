<#
MOAVI Desk protocol benchmark - sample the RDP (RemoteFX) performance counters in the desktop.

  Sample-Counters.ps1 -Out counters.csv -Seconds 400 [-Interval 1]

Writes one row per interval: utc_epoch, then one column per counter (the sum over its
instances; with one RDP session per desktop that is the session's value). It stops early when
<Out>.stop appears (Invoke-BenchWorkload.ps1 creates it at the end). A counter that does
not exist (no RDP session yet, SPICE/VNC session, older Windows) stays empty.

The counters are added by their English names through PdhAddEnglishCounter, so this works on a
Korean (or any) Windows, where Get-Counter / typeperf only accept the localized names.
#>
param(
    [Parameter(Mandatory)] [string] $Out,
    [int] $Seconds = 300,
    [int] $Interval = 1
)
$ErrorActionPreference = 'Stop'

$Counters = [ordered]@{
    fps_out          = '\RemoteFX Graphics(*)\Output Frames/Second'
    fps_in           = '\RemoteFX Graphics(*)\Input Frames/Second'
    skip_server      = '\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Server Resources'
    skip_network     = '\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Network Resources'
    skip_client      = '\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Client Resources'
    encode_ms        = '\RemoteFX Graphics(*)\Average Encoding Time'
    tcp_rtt_ms       = '\RemoteFX Network(*)\Current TCP RTT'
    udp_rtt_ms       = '\RemoteFX Network(*)\Current UDP RTT'
    tcp_bw_kbps      = '\RemoteFX Network(*)\Current TCP Bandwidth'
    udp_bw_kbps      = '\RemoteFX Network(*)\Current UDP Bandwidth'
    tx_kbps          = '\RemoteFX Network(*)\Total Sent Rate'
    loss_pct         = '\RemoteFX Network(*)\Loss Rate'
    cpu_pct          = '\Processor(_Total)\% Processor Time'
}

if (-not ('MoaviBench.Pdh' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace MoaviBench {
public static class Pdh {
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    static extern uint PdhOpenQueryW(string src, IntPtr user, out IntPtr query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    static extern uint PdhAddEnglishCounterW(IntPtr query, string path, IntPtr user, out IntPtr counter);
    [DllImport("pdh.dll")]
    static extern uint PdhCollectQueryData(IntPtr query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint fmt, ref uint size, out uint count, IntPtr items);
    const uint PDH_FMT_DOUBLE = 0x200, PDH_FMT_NOCAP100 = 0x8000, PDH_MORE_DATA = 0x800007D2;

    public static IntPtr Open() {
        IntPtr q; uint s = PdhOpenQueryW(null, IntPtr.Zero, out q);
        if (s != 0) throw new Exception("PdhOpenQuery 0x" + s.ToString("X"));
        return q;
    }
    // IntPtr.Zero when the counter does not exist on this machine
    public static IntPtr Add(IntPtr q, string path) {
        IntPtr c; return PdhAddEnglishCounterW(q, path, IntPtr.Zero, out c) == 0 ? c : IntPtr.Zero;
    }
    public static void Collect(IntPtr q) { PdhCollectQueryData(q); }
    // the sum over the instances, or NaN when there is none with a valid value
    public static double Sum(IntPtr c) {
        if (c == IntPtr.Zero) return double.NaN;
        uint size = 0, count;
        uint fmt = PDH_FMT_DOUBLE | PDH_FMT_NOCAP100;
        if (PdhGetFormattedCounterArrayW(c, fmt, ref size, out count, IntPtr.Zero) != PDH_MORE_DATA || size == 0) return double.NaN;
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try {
            if (PdhGetFormattedCounterArrayW(c, fmt, ref size, out count, buf) != 0) return double.NaN;
            // PDH_FMT_COUNTERVALUE_ITEM_W: name pointer, then {DWORD CStatus; double} aligned to 8
            int item = 8 + 16; double sum = 0; bool any = false;
            for (int i = 0; i < count; i++) {
                int at = i * item;
                uint status = (uint)Marshal.ReadInt32(buf, at + 8);
                if (status != 0 && status != 1) continue;   // PDH_CSTATUS_VALID_DATA / NEW_DATA
                sum += BitConverter.Int64BitsToDouble(Marshal.ReadInt64(buf, at + 16)); any = true;
            }
            return any ? sum : double.NaN;
        } finally { Marshal.FreeHGlobal(buf); }
    }
}
}
'@
}

$q = [MoaviBench.Pdh]::Open()
$handles = [ordered]@{}
foreach ($k in $Counters.Keys) { $handles[$k] = [MoaviBench.Pdh]::Add($q, $Counters[$k]) }
$missing = @($handles.Keys | Where-Object { $handles[$_] -eq [IntPtr]::Zero })
if ($missing) { Write-Warning ("counters not on this machine: " + ($missing -join ', ')) }

$inv = [Globalization.CultureInfo]::InvariantCulture
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('utc_epoch,' + ($Counters.Keys -join ','))
[MoaviBench.Pdh]::Collect($q)
$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
$stopFile = "$Out.stop"
Remove-Item $stopFile -ErrorAction SilentlyContinue
while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $stopFile)) {
    Start-Sleep -Seconds $Interval
    [MoaviBench.Pdh]::Collect($q)
    $now = ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0).ToString('F3', $inv)
    $vals = foreach ($k in $handles.Keys) {
        $v = [MoaviBench.Pdh]::Sum($handles[$k])
        if ([double]::IsNaN($v)) { '' } else { $v.ToString('0.###', $inv) }
    }
    $lines.Add($now + ',' + ($vals -join ','))
    # written every interval, so a run stopped early still leaves its rows
    if ($lines.Count % 10 -eq 0) { [IO.File]::WriteAllLines($Out, $lines) }
}
[IO.File]::WriteAllLines($Out, $lines)
