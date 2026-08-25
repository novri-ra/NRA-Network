#Requires -Version 5.1
<#
.SYNOPSIS
    Ultra-Fast DNS Benchmark & Auto-Optimizer (God-Mode Edition v2)
.DESCRIPTION
    Unified parallel pipeline, DoH/DoT/Hijack detection, ECS tagging,
    LLMNR/NetBIOS disable, backup/rollback, Markdown/JSON/CSV export,
    and full 9-option interactive menu.
#>

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# ── Setup Encoding & ANSI VT ────────────────────────────────────────────────────────────
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try {
    $VTType = Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int mode);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetConsoleMode(IntPtr handle, out int mode);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetStdHandle(int handle);
'@ -Name 'VTConsole' -Namespace 'Win32' -PassThru -ErrorAction SilentlyContinue
    if ($VTType) {
        $hOut = [Win32.VTConsole]::GetStdHandle(-11)
        $cMode = 0
        [Win32.VTConsole]::GetConsoleMode($hOut, [ref]$cMode) | Out-Null
        [Win32.VTConsole]::SetConsoleMode($hOut, $cMode -bor 0x0004) | Out-Null  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    }
} catch {}

# ── ANSI Helpers ──────────────────────────────────────────────────────────────
$ESC = [char]27
function C($color, $text) {
    $codes = @{ R="91"; G="92"; Y="93"; B="94"; M="95"; C="96"; W="97"; DG="90"; BOLD="1" }
    "$ESC[$($codes[$color])m$text$ESC[0m"
}

# ── Config ────────────────────────────────────────────────────────────────────
$TIMEOUT_MS = 800
$ICMP_COUNT = 4

# DNS Provider List (global for DoH template lookup)
$script:DnsProviders = @(
    # Fast / Anycast Tier 1
    @{Name="Cloudflare Primary";     IP="1.1.1.1";         IPv6="2606:4700:4700::1111"; Category="Fast";  DoH="https://cloudflare-dns.com/dns-query"; DoT="cloudflare-dns.com"; ECS=$false}
    @{Name="Cloudflare Secondary";   IP="1.0.0.1";         IPv6="2606:4700:4700::1001"; Category="Fast";  DoH="https://cloudflare-dns.com/dns-query"; DoT="cloudflare-dns.com"; ECS=$false}
    @{Name="Google Primary";         IP="8.8.8.8";         IPv6="2001:4860:4860::8888"; Category="Fast";  DoH="https://dns.google/dns-query";         DoT="dns.google";         ECS=$true}
    @{Name="Google Secondary";       IP="8.8.4.4";         IPv6="2001:4860:4860::8844"; Category="Fast";  DoH="https://dns.google/dns-query";         DoT="dns.google";         ECS=$true}
    @{Name="OpenDNS Primary";        IP="208.67.222.222";  IPv6="2620:119:35::35";      Category="Fast";  DoH="https://doh.opendns.com/dns-query";    DoT="";                   ECS=$true}
    @{Name="OpenDNS Secondary";      IP="208.67.220.220";  IPv6="2620:119:53::53";      Category="Fast";  DoH="https://doh.opendns.com/dns-query";    DoT="";                   ECS=$true}
    @{Name="Gcore Primary";          IP="2.56.220.2";      IPv6="2a03:90c0:9992::1";    Category="Fast";  DoH="https://doh.gcore.com/dns-query";      DoT="";                   ECS=$false}
    @{Name="Gcore Secondary";        IP="95.85.95.85";     IPv6="2a03:90c0:9992::2";    Category="Fast";  DoH="https://doh.gcore.com/dns-query";      DoT="";                   ECS=$false}
    @{Name="Hurricane Electric";     IP="74.82.42.42";     IPv6="2001:470:20::2";       Category="Fast";  DoH="";                                     DoT="";                   ECS=$false}
    @{Name="Level3/Lumen 1";         IP="4.2.2.1";         IPv6="2001:428::1";          Category="Fast";  DoH="";                                     DoT="";                   ECS=$false}
    @{Name="Level3/Lumen 2";         IP="4.2.2.2";         IPv6="2001:428::2";          Category="Fast";  DoH="";                                     DoT="";                   ECS=$false}
    @{Name="RethinkDNS Fast";        IP="104.28.1.1";      IPv6="2606:4700:300a::1";    Category="Fast";  DoH="https://max.rethinkdns.com/dns-query"; DoT="max.rethinkdns.com"; ECS=$true}
    @{Name="IIJ Public DNS";         IP="210.130.1.1";     IPv6="2001:240:bb5f::1";     Category="Fast";  DoH="";                                     DoT="";                   ECS=$true}
    @{Name="Comcast Business 1";     IP="75.75.75.75";     IPv6="2001:558:feed::1";     Category="Fast";  DoH="";                                     DoT="";                   ECS=$true}
    @{Name="Comcast Business 2";     IP="75.75.76.76";     IPv6="2001:558:feed::2";     Category="Fast";  DoH="";                                     DoT="";                   ECS=$true}

    # Privacy & Security
    @{Name="Quad9 Primary";          IP="9.9.9.9";         IPv6="2620:fe::fe";          Category="Privacy"; DoH="https://dns.quad9.net/dns-query";    DoT="dns.quad9.net";      ECS=$false}
    @{Name="Quad9 Secondary";        IP="149.112.112.112"; IPv6="2620:fe::9";           Category="Privacy"; DoH="https://dns.quad9.net/dns-query";    DoT="dns.quad9.net";      ECS=$false}
    @{Name="Quad9 ECS";              IP="9.9.9.11";        IPv6="2620:fe::11";          Category="Privacy"; DoH="https://dns11.quad9.net/dns-query";  DoT="dns11.quad9.net";    ECS=$true}
    @{Name="Mullvad DNS";            IP="194.242.2.2";     IPv6="2a07:e340::2";         Category="Privacy"; DoH="https://doh.mullvad.net/dns-query";  DoT="doh.mullvad.net";    ECS=$false}
    @{Name="CleanBrowsing Security"; IP="185.228.168.9";   IPv6="2a0d:2a00:1::2";       Category="Privacy"; DoH="https://doh.cleanbrowsing.org/doh/security-filter/"; DoT="security-filter-dns.cleanbrowsing.org"; ECS=$false}
    @{Name="Neustar/UltraDNS";      IP="64.6.64.6";       IPv6="2620:74:1b::1:1";      Category="Privacy"; DoH="";                                   DoT="";                   ECS=$false}
    @{Name="Digitale Gesellschaft"; IP="185.95.218.42";   IPv6="2a05:fc84::42";        Category="Privacy"; DoH="https://dns.digitale-gesellschaft.ch/dns-query"; DoT="dns.digitale-gesellschaft.ch"; ECS=$false}
    @{Name="Applied Privacy";       IP="146.255.56.98";   IPv6="2a02:418:6a04:500::1"; Category="Privacy"; DoH="https://doh.applied-privacy.net/query"; DoT="dot.applied-privacy.net"; ECS=$false}
    @{Name="LibreDNS";              IP="116.202.176.26";  IPv6="2a01:4f8:1c1c:6b4b::1"; Category="Privacy"; DoH="https://doh.libredns.gr/dns-query";  DoT="dot.libredns.gr";    ECS=$false}

    # AdBlock & Tracker Filtering
    @{Name="AdGuard Primary";        IP="94.140.14.14";    IPv6="2a10:50c0::ad1:ff";    Category="AdBlock"; DoH="https://dns.adguard-dns.com/dns-query"; DoT="dns.adguard-dns.com"; ECS=$false}
    @{Name="AdGuard Secondary";      IP="94.140.15.15";    IPv6="2a10:50c0::ad2:ff";    Category="AdBlock"; DoH="https://dns.adguard-dns.com/dns-query"; DoT="dns.adguard-dns.com"; ECS=$false}
    @{Name="AdGuard Non-Filtering";  IP="94.140.14.140";   IPv6="2a10:50c0::1:ff";      Category="AdBlock"; DoH="https://unfiltered.adguard-dns.com/dns-query"; DoT="unfiltered.adguard-dns.com"; ECS=$false}
    @{Name="NextDNS Primary";        IP="45.90.28.0";      IPv6="2a07:a8c0::";          Category="AdBlock"; DoH="https://dns.nextdns.io";               DoT="";                   ECS=$true}
    @{Name="NextDNS Secondary";      IP="45.90.30.0";      IPv6="2a07:a8c1::";          Category="AdBlock"; DoH="https://dns.nextdns.io";               DoT="";                   ECS=$true}
    @{Name="Control D Primary";      IP="76.76.2.0";       IPv6="2606:1a40::";          Category="AdBlock"; DoH="https://freedns.controld.com/p0";      DoT="";                   ECS=$false}
    @{Name="Control D Secondary";    IP="76.76.10.0";      IPv6="2606:1a40:1::";        Category="AdBlock"; DoH="https://freedns.controld.com/p0";      DoT="";                   ECS=$false}
    @{Name="AdGuard Family 1";      IP="94.140.14.15";    IPv6="2a10:50c0::bad1:ff";   Category="AdBlock"; DoH="https://family.adguard-dns.com/dns-query"; DoT="family.adguard-dns.com"; ECS=$false}
    @{Name="AdGuard Family 2";      IP="94.140.15.16";    IPv6="2a10:50c0::bad2:ff";   Category="AdBlock"; DoH="https://family.adguard-dns.com/dns-query"; DoT="family.adguard-dns.com"; ECS=$false}
    @{Name="AhaDNS India";          IP="144.24.111.139";  IPv6="2603:c020:6:5000::1";  Category="AdBlock"; DoH="https://doh.ahadns.net/in";                DoT="in.ahadns.net";     ECS=$false}
    @{Name="DNSForge";              IP="176.9.93.198";    IPv6="2a01:4f8:151:34aa::198"; Category="AdBlock"; DoH="https://dnsforge.de/dns-query";          DoT="dnsforge.de";       ECS=$false}

    # Regional & Global
    @{Name="AliDNS Primary";         IP="223.5.5.5";       IPv6="2400:3200::1";         Category="Global";  DoH="https://dns.alidns.com/dns-query";   DoT="dns.alidns.com";     ECS=$true}
    @{Name="AliDNS Secondary";       IP="223.6.6.6";       IPv6="2400:3200:baba::1";    Category="Global";  DoH="https://dns.alidns.com/dns-query";   DoT="dns.alidns.com";     ECS=$true}
    @{Name="Tencent DNSPod";         IP="119.29.29.29";    IPv6="2402:4e00::";          Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="Baidu DNS";              IP="180.76.76.76";    IPv6="2400:da00::6666";      Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="Alternate DNS Primary";  IP="76.76.19.19";     IPv6="2602:fcbc::ad";        Category="Global";  DoH="https://dns.alternate-dns.com/dns-query"; DoT="";              ECS=$false}
    @{Name="114DNS Primary";         IP="114.114.114.114"; IPv6="";                     Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="114DNS Secondary";       IP="114.114.115.115"; IPv6="";                     Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="360 Secure DNS";         IP="101.226.4.6";     IPv6="";                     Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="Chunghwa Telecom 1";     IP="168.95.1.1";      IPv6="2001:b000:168::1";     Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
    @{Name="Chunghwa Telecom 2";     IP="168.95.192.1";    IPv6="2001:b000:168::2";     Category="Global";  DoH="";                                   DoT="";                   ECS=$true}
)

# ── Banner ────────────────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Host "$(C 'C' '╔═════════════════════════════════════════════════════════════════════════════╗')"
    Write-Host "$(C 'C' '║') $(C 'BOLD' '   ⚡ DNS OPTIMIZER (GOD-MODE v2) - Ultra-Fast Network Benchmark Tool    ') $(C 'C' '║')"
    Write-Host "$(C 'C' '║') $(C 'DG' "   Engine: Async Runspace Pipeline | DoH/DoT | Hijack | ECS | Tuning     ") $(C 'C' '║')"
    Write-Host "$(C 'C' '╚═════════════════════════════════════════════════════════════════════════════╝')"
    Write-Host ""
}

# ── Unified Pipeline (Async Runspace) ────────────────────────────────────────
function Invoke-BenchmarkEngine {
    param([array]$Targets)

    $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($Targets.Count, 128))
    $pool.Open()

    $scriptBlock = {
        param($IP, $DoH, $DoT, $ECS, $TimeoutMs, $IcmpCount)
        $swTotal = [System.Diagnostics.Stopwatch]::StartNew()

        # 1. ICMP Ping
        $icmpTimes = @()
        $lost = 0
        try {
            $pinger = New-Object System.Net.NetworkInformation.Ping
            for ($i = 0; $i -lt $IcmpCount; $i++) {
                try {
                    $rep = $pinger.Send($IP, $TimeoutMs)
                    if ($rep.Status -eq 'Success') { $icmpTimes += $rep.RoundtripTime }
                    else { $lost++ }
                } catch { $lost++ }
            }
        } finally {
            if ($null -ne $pinger) { $pinger.Dispose() }
        }

        $pingAvg = if ($icmpTimes.Count -gt 0) { ($icmpTimes | Measure-Object -Average).Average } else { [double]::MaxValue }
        $pingJitter = if ($icmpTimes.Count -gt 0) { ($icmpTimes | Measure-Object -Maximum).Maximum - ($icmpTimes | Measure-Object -Minimum).Minimum } else { 999 }
        $lossPct = [math]::Round(($lost / $IcmpCount) * 100, 1)

        # 2. DNS Queries (2 valid + 1 nonexistent for hijack detection)
        $dnsTimes = @()
        $failures = 0
        $hijacked = $false

        function Test-UDP-DNS($domain) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $udp = New-Object System.Net.Sockets.UdpClient
                $udp.Client.ReceiveTimeout = $TimeoutMs
                $udp.Client.SendTimeout = $TimeoutMs

                try {
                    $ms = New-Object System.IO.MemoryStream
                    $ms.WriteByte([byte](Get-Random -Min 0 -Max 256))
                    $ms.WriteByte([byte](Get-Random -Min 0 -Max 256))
                    $flags = [byte[]](0x01,0x20, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00)
                    $ms.Write($flags, 0, $flags.Length)
                    foreach ($lbl in $domain.Split('.')) {
                        $ms.WriteByte([byte]$lbl.Length)
                        $b = [System.Text.Encoding]::ASCII.GetBytes($lbl)
                        $ms.Write($b, 0, $b.Length)
                    }
                    $ms.WriteByte(0x00)
                    $ms.Write([byte[]](0x00,0x01, 0x00,0x01), 0, 4)
                    $pkt = $ms.ToArray()
                } finally {
                    if ($null -ne $ms) { $ms.Dispose() }
                }

                $udp.Connect($IP, 53)
                [void]$udp.Send($pkt, $pkt.Length)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $res = $udp.Receive([ref]$ep)
                
                if ($null -eq $res -or $res.Length -lt 12) { return $null }
                
                # Check RCODE (byte 3, lower 4 bits)
                $rcode = $res[3] -band 0x0F
                
                # Check Answer Count (bytes 6 and 7)
                $ansCount = ($res[6] -shl 8) -bor $res[7]
                
                # Check AD bit (byte 3, bit 5 / mask 0x20)
                $dnssec = ($res[3] -band 0x20) -eq 0x20
                
                return @{ Time=$sw.Elapsed.TotalMilliseconds; RCode=$rcode; AnsCount=$ansCount; DNSSEC=$dnssec }
            } catch {
                return $null
            } finally {
                if ($null -ne $udp) { try { $udp.Close(); $udp.Dispose() } catch {} }
            }
        }

        # Valid domain queries
        $validRes = Test-UDP-DNS 'google.com'
        if ($validRes) { $dnsTimes += $validRes.Time } else { $failures++ }

        $validRes2 = Test-UDP-DNS 'cloudflare.com'
        if ($validRes2) { $dnsTimes += $validRes2.Time } else { $failures++ }

        # Optional: Test known DNSSEC signed domain (e.g. cloudflare.com or icann.org) for validation badge
        $secRes = Test-UDP-DNS 'cloudflare.com'
        if ($secRes -and $secRes.DNSSEC) {
            $dnssecOK = $true
        } else {
            $dnssecOK = $false
        }

        # NXDOMAIN Hijack Check
        $nxDomain = "nxdomain-test-$([guid]::NewGuid().ToString('N').Substring(0,12)).com"
        $nxRes = Test-UDP-DNS $nxDomain
        if ($nxRes) {
            $dnsTimes += $nxRes.Time
            if ($nxRes.RCode -eq 0 -and $nxRes.AnsCount -gt 0) { $hijacked = $true }
        } else { $failures++ }

        $dnsAvg = if ($dnsTimes.Count -gt 0) { ($dnsTimes | Measure-Object -Average).Average } else { [double]::MaxValue }

        @{
            IP = $IP
            DoH = $DoH -ne ""
            DoT = $DoT -ne ""
            ECS = $ECS
            PingAvg = $pingAvg
            PingJitter = $pingJitter
            Loss = $lossPct
            DnsAvg = $dnsAvg
            DnsFailed = $failures -ge 2
            Hijacked = $hijacked
            DNSSEC = $dnssecOK
        }
    }

    $jobs = @()
    foreach ($t in $Targets) {
        $ps = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($t.IP).AddArgument($t.DoH).AddArgument($t.DoT).AddArgument($t.ECS).AddArgument($TIMEOUT_MS).AddArgument($ICMP_COUNT)
        $ps.RunspacePool = $pool
        $jobs += @{ Pipe=$ps; Handle=$ps.BeginInvoke(); P=$t }
    }

    $total = $jobs.Count
    $done = 0
    $results = @()

    while ($jobs.Count -gt 0) {
        $incomplete = @()
        $completed = @()
        foreach ($j in $jobs) {
            if ($j.Handle.IsCompleted) { $completed += $j }
            else { $incomplete += $j }
        }
        $jobs = $incomplete
        
        foreach ($j in $completed) {
            $res = $null
            try {
                $rawRes = $j.Pipe.EndInvoke($j.Handle)
                if ($rawRes.Count -gt 0) { $res = $rawRes[0] }
            } catch {} finally {
                try { $j.Pipe.Dispose() } catch {}
            }
            
            $hasIP = $false
            try { $hasIP = $null -ne $res -and $null -ne $res.IP } catch {}
            if (-not $hasIP) {
                $res = @{ IP = $j.P.IP; DoH = ($j.P.DoH -ne ""); DoT = ($j.P.DoT -ne ""); ECS = $j.P.ECS; PingAvg = [double]::MaxValue; PingJitter = 999; Loss = 100.0; DnsAvg = [double]::MaxValue; DnsFailed = $true; Hijacked = $false; DNSSEC = $false }
            }
            $done++
            $pct = [math]::Floor(($done / $total) * 100)
            $bar = ([string][char]0x2588 * [math]::Floor($pct / 2.5)).PadRight(40)
            Write-Host -NoNewline "`r  $(C 'C' '[PIPELINE]') [$bar] $pct% ($done/$total)  "

            # Compute Score
            $score = [double]::MaxValue
            $status = 'OK'
            if ($res.DnsFailed -and $res.PingAvg -eq [double]::MaxValue) { $status = 'FAIL' }
            elseif ($res.Loss -gt 25) { $status = 'HIGH LOSS' }
            elseif ($res.DnsFailed) { $status = 'DNS FAIL' }
            elseif ($res.Hijacked) { $status = 'HIJACKED' }
            
            if ($status -eq 'OK' -or $status -eq 'HIJACKED' -or $status -eq 'HIGH LOSS') {
                $effPing = if ($res.PingAvg -eq [double]::MaxValue) { 999 } else { $res.PingAvg }
                $effDns = if ($res.DnsAvg -eq [double]::MaxValue) { 999 } else { $res.DnsAvg }
                $score = ($effPing * 0.4) + ($effDns * 0.4) + ($res.PingJitter * 0.15) + ($res.Loss * 5)
            }

            try {
                $results += [PSCustomObject]@{
                    Name     = $j.P.Name
                    IP       = $j.P.IP
                    IPv6     = $j.P.IPv6
                    Category = $j.P.Category
                    DoH      = $res.DoH
                    DoT      = $res.DoT
                    ECS      = $res.ECS
                    Hijacked = $res.Hijacked
                    PingAvg  = $res.PingAvg
                    Jitter   = $res.PingJitter
                    Loss     = $res.Loss
                    DnsTime  = $res.DnsAvg
                    Score    = $score
                    Status   = $status
                    DNSSEC   = $res.DNSSEC
                }
            } catch {}
        }
        if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 20 }
    }
    Write-Host ""
    try { $pool.Close() } finally { $pool.Dispose() }
    return $results | Sort-Object Score
}

# ── UI Rendering ─────────────────────────────────────────────────────────────
function Get-Badge($cat) {
    switch ($cat) {
        'Fast'    { return '[ANYCAST]' }
        'Privacy' { return '[PRIVACY]' }
        'AdBlock' { return '[ADBLCK]' }
        'Global'  { return '[GLOBAL]' }
        default   { return $cat }
    }
}

function Show-Table {
    param($Results)
    Write-Host ""
    Write-Host "  $(C 'BOLD' '════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════')"
    Write-Host "  $(C 'BOLD' ('{0,-4} {1,-24} {2,-11} {3,-15} {4,-4} {5,-4} {6,-4} {7,-6} {8,-8} {9,-7} {10,-6} {11,-9} {12,-8} {13}' -f 'Rank','Provider','Category','IP','DoH','DoT','ECS','SEC','Ping','Jitter','Loss','DNS','Score','Status'))"
    Write-Host "  $(C 'BOLD' '════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════')"

    $rank = 0
    foreach ($r in $Results) {
        $rank++
        $cat = Get-Badge $r.Category
        $doh = if ($r.DoH) { 'Yes' } else { 'No' }
        $dot = if ($r.DoT) { 'Yes' } else { 'No' }
        $ecs = if ($r.ECS) { 'Yes' } else { 'No' }
        $sec = if ($r.DNSSEC) { '[SEC]' } else { '---' }
        
        $pStr = if ($r.PingAvg -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.PingAvg,1))ms" }
        $jStr = if ($r.Jitter -eq 999) { 'N/A' } else { "$([math]::Round($r.Jitter,1))ms" }
        $lStr = "$($r.Loss)%"
        $dStr = if ($r.DnsTime -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.DnsTime,1))ms" }
        $sStr = if ($r.Score -eq [double]::MaxValue) { '99999' } else { [math]::Round($r.Score, 1) }

        $statColor = 'W'
        if ($r.Status -match 'FAIL') { $statColor = 'R' }
        elseif ($r.Status -eq 'HIJACKED') { $statColor = 'M' }
        elseif ($r.Status -eq 'HIGH LOSS') { $statColor = 'Y' }
        elseif ($rank -le 3) { $statColor = 'G' }

        $hj = if ($r.Hijacked) { ' HIJACK' } else { '' }
        $line = '{0,-4} {1,-24} {2,-11} {3,-15} {4,-4} {5,-4} {6,-4} {7,-6} {8,-8} {9,-7} {10,-6} {11,-9} {12,-8} {13}{14}' -f "#$rank", $r.Name, $cat, $r.IP, $doh, $dot, $ecs, $sec, $pStr, $jStr, $lStr, $dStr, $sStr, $r.Status, $hj
        Write-Host "  $(C $statColor $line)"
    }
    Write-Host "  $(C 'BOLD' '════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════')"
}

# ── Configuration Management ─────────────────────────────────────────────────
function Get-ActiveAdapter {
    # Exclude only loopback, allow Virtual/Hyper-V/PPPoE if they are the actual active WAN interfaces
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -notmatch 'Loopback') } | Sort-Object -Property @{Expression={if($_.Name -match 'Wi-Fi|Wireless'){0}elseif($_.Name -match 'Ethernet'){1}else{2}}}
    
    # Fallback to NetIPConfiguration default gateway check first since it's the most reliable for active internet connection
    try {
        $ipCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
        if ($ipCfg -and $ipCfg.NetAdapter) { return $ipCfg.NetAdapter }
    } catch {}
    
    if ($adapters) { return $adapters[0] }
    
    # Final fallback to WMI
    try {
        $wmi = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true -and $_.DefaultIPGateway -ne $null } | Select-Object -First 1
        if ($wmi) { 
            $wmiAdapter = Get-NetAdapter -InterfaceIndex $wmi.Index -ErrorAction SilentlyContinue
            if ($wmiAdapter) { return $wmiAdapter }
        }
    } catch {}
    
    return $null
}

function Backup-NetworkSettings {
    $adapter = Get-ActiveAdapter
    if (-not $adapter) { return $null }

    $dir = Join-Path $PSScriptRoot "backup"
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    
    $v4 = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4
    $v6 = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv6
    
    # Capture DHCP status
    $dhcp = $false
    try {
        $iface = Get-NetIPInterface -InterfaceAlias $adapter.Name -AddressFamily IPv4
        $dhcp = $iface.Dhcp -eq 'Enabled'
    } catch {}
    
    $backup = @{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        AdapterName = $adapter.Name
        AdapterGuid = $adapter.InterfaceGuid
        IPv4 = $v4.ServerAddresses
        IPv6 = $v6.ServerAddresses
        DHCP = $dhcp
    }
    
    $file = Join-Path $dir "dns_backup_$($adapter.Name -replace '[\\/:*?""<>|]','_').json"
    $backup | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
    return $file
}

function Restore-NetworkSettings {
    $adapter = Get-ActiveAdapter
    if (-not $adapter) { Write-Host "  $(C 'R' 'No adapter active.')"; return }
    $file = Join-Path $PSScriptRoot "backup\dns_backup_$($adapter.Name -replace '[\\/:*?""<>|]','_').json"
    
    if (-not (Test-Path $file)) { Write-Host "  $(C 'Y' 'No backup found for this adapter.')"; return }
    
    try {
        $backup = Get-Content $file | ConvertFrom-Json
        if ($backup.DHCP) {
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses
        } else {
            if ($backup.IPv4 -and $backup.IPv4.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $backup.IPv4 -AddressFamily IPv4 -ErrorAction Stop
            } else {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses -AddressFamily IPv4
            }
            
            if ($backup.IPv6 -and $backup.IPv6.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $backup.IPv6 -AddressFamily IPv6 -ErrorAction Stop
            } else {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses -AddressFamily IPv6
            }
        }
        
        Write-Host "  $(C 'G' "Restored $($adapter.Name) from backup: $($backup.Timestamp)")"
        ipconfig /flushdns | Out-Null
    } catch {
        Write-Host "  $(C 'R' "Restore failed: $_")"
    }
}

function Set-Dns {
    param($Primary, $Secondary, $Category)
    
    $adapter = Get-ActiveAdapter
    if (-not $adapter) { Write-Host "  $(C 'R' 'No active adapter found.')"; return }
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host "  $(C 'R' 'Administrator privileges required.')"; return }

    $backupOk = $false
    try { Backup-NetworkSettings | Out-Null; $backupOk = $true } catch {}
    if (-not $backupOk) {
        Write-Host "  $(C 'Y' 'Warning: Could not create rollback backup. Proceeding anyway.')"
    }

    try {
        $servers = @($Primary)
        if ($Secondary) { $servers += $Secondary }
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $servers -ErrorAction Stop

        $ipv6Binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
        $ipv6Servers = @()
        if ($ipv6Binding -and $ipv6Binding.Enabled) {
            $primProvider = $script:DnsProviders | Where-Object { $_.IP -eq $Primary } | Select-Object -First 1
            $secProvider  = $script:DnsProviders | Where-Object { $_.IP -eq $Secondary } | Select-Object -First 1

            if ($primProvider -and $primProvider.IPv6) { $ipv6Servers += $primProvider.IPv6 } else { $ipv6Servers += "2606:4700:4700::1111" }
            if ($Secondary) {
                if ($secProvider -and $secProvider.IPv6) { $ipv6Servers += $secProvider.IPv6 } else { $ipv6Servers += "2001:4860:4860::8888" }
            }

            if ($ipv6Servers.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $ipv6Servers -AddressFamily IPv6 -ErrorAction SilentlyContinue
            }
        }

        # Best-effort DoH template registration (Win 11 / modern Win 10)
        try {
            $primProvider = $script:DnsProviders | Where-Object { $_.IP -eq $Primary } | Select-Object -First 1
            if ($primProvider -and $primProvider.DoH) {
                Add-DnsClientDohServerAddress -ServerAddress $Primary -DohTemplate $primProvider.DoH -AllowFallbackToUdp $false -ErrorAction SilentlyContinue
            }
            if ($Secondary) {
                $secProvider = $script:DnsProviders | Where-Object { $_.IP -eq $Secondary } | Select-Object -First 1
                if ($secProvider -and $secProvider.DoH) {
                    Add-DnsClientDohServerAddress -ServerAddress $Secondary -DohTemplate $secProvider.DoH -AllowFallbackToUdp $false -ErrorAction SilentlyContinue
                }
            }
        } catch {}

        ipconfig /flushdns | Out-Null
        $v6msg = if ($ipv6Servers.Count -gt 0) { " & IPv6: $($ipv6Servers -join ', ')" } else { "" }
        Write-Host "  $(C 'G' "Applied [$Category] DNS to $($adapter.Name): $($servers -join ', ')$v6msg")"

        # Auto-Rollback Safety: verify DNS resolution works
        Write-Host "  $(C 'C' 'Verifying DNS resolution...')"
        $resolved = $false
        try {
            $check = Resolve-DnsName -Name 'google.com' -DnsOnly -ErrorAction Stop
            if ($check) { $resolved = $true }
        } catch {}
        if (-not $resolved) {
            try {
                $ping = Test-Connection -ComputerName 'google.com' -Count 1 -Quiet -ErrorAction Stop
                if ($ping) { $resolved = $true }
            } catch {}
        }

        if ($resolved) {
            Write-Host "  $(C 'G' 'DNS resolution verified OK.')"
        } else {
            Write-Host "  $(C 'R' 'DNS resolution FAILED after applying new DNS!')"
            Write-Host "  $(C 'Y' 'Auto-rolling back to previous settings...')"
            Restore-NetworkSettings
            Write-Host "  $(C 'Y' 'DNS reverted due to connectivity failure. Previous settings restored.')"
        }
    } catch {
        Write-Host "  $(C 'R' "Failed to apply DNS: $_")"
    }
}

function Optimize-NetworkRegistry {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host "  $(C 'R' 'Administrator privileges required.')"; return }

    try {
        # DNS Cache Tuning
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        Set-ItemProperty -Path $path -Name "MaxCacheTtl" -Value 86400 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "MaxNegativeCacheTtl" -Value 0 -Type DWord -Force

        # Disable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force

        # Disable NetBIOS over TCP/IP (WMI)
        $wmi = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($nic in $wmi) {
            $nic.SetTcpipNetbios(2) | Out-Null # 2 = Disable NetBIOS
        }
        
        # Advanced NIC Tuning
        $adapter = Get-ActiveAdapter
        if ($adapter) {
            $guid = $adapter.InterfaceGuid
            $tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
            if (-not (Test-Path $tcpPath)) { New-Item -Path $tcpPath -Force | Out-Null }
            Set-ItemProperty -Path $tcpPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $tcpPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force

            # Advanced NIC Hardware property tuning
            try {
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword '*EEE' -RegistryValue '0' -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword '*FlowControl' -RegistryValue '0' -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword '*InterruptModeration' -RegistryValue '0' -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword 'EnableGreenEthernet' -RegistryValue '0' -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword 'AdvancedEEE' -RegistryValue '0' -ErrorAction SilentlyContinue
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword 'PowerSavingMode' -RegistryValue '0' -ErrorAction SilentlyContinue
            } catch {}
        }

        # Multimedia SystemProfile
        $mmPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if (-not (Test-Path $mmPath)) { New-Item -Path $mmPath -Force | Out-Null }
        Set-ItemProperty -Path $mmPath -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
        Set-ItemProperty -Path $mmPath -Name "SystemResponsiveness" -Value 0 -Type DWord -Force

        # netsh TCP global settings
        netsh int tcp set global autotuninglevel=normal | Out-Null
        netsh int tcp set global rss=enabled | Out-Null
        
        Write-Host "  $(C 'G' 'Registry optimizations applied:')"
        Write-Host "    $(C 'G' '- DNS Cache: MaxCacheTtl=86400, MaxNegativeCacheTtl=0')"
        Write-Host "    $(C 'G' '- LLMNR disabled')"
        Write-Host "    $(C 'G' '- NetBIOS over TCP/IP disabled')"
        Write-Host "    $(C 'G' '- TCP/IP Latency & Multimedia settings optimized')"
        Write-Host "    $(C 'G' '- Advanced NIC Hardware Tuned (EEE, GreenEthernet, FlowControl)')"
        ipconfig /flushdns | Out-Null
        try { Get-Service -Name 'Dnscache' -ErrorAction Stop | Restart-Service -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "  $(C 'G' 'DNS cache flushed & Dnscache service restarted.')"
    } catch {
        Write-Host "  $(C 'Y' "Tuning completed with warnings: $_")"
    }
}

# ── Export ────────────────────────────────────────────────────────────────────
function Export-Telemetry {
    param($Results, $ElapsedSec)
    
    $dir = Join-Path $PSScriptRoot "telemetry"
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"

    # JSON
    $Results | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $dir "telemetry_$ts.json")
    
    # CSV
    $Results | Export-Csv -Path (Join-Path $dir "telemetry_$ts.csv") -NoTypeInformation

    # Markdown Report
    $md = @()
    $md += "# DNS Benchmark Report"
    $md += ""
    $md += "**Date:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $md += "**Providers Tested:** $($Results.Count)"
    $md += "**Total Benchmark Time:** $($ElapsedSec)s"
    $md += ""
    $adapter = Get-ActiveAdapter
    if ($adapter) { $md += "**Active Adapter:** $($adapter.Name)" }
    $md += ""
    $md += "## Rankings"
    $md += ""
    $md += "| Rank | Provider | Category | IP | DoH | DoT | ECS | Ping | Jitter | Loss | DNS | Score | Status |"
    $md += "|------|----------|----------|----|-----|-----|-----|------|--------|------|-----|-------|--------|"
    
    $rank = 0
    foreach ($r in $Results) {
        $rank++
        $pStr = if ($r.PingAvg -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.PingAvg,1))ms" }
        $jStr = if ($r.Jitter -eq 999) { 'N/A' } else { "$([math]::Round($r.Jitter,1))ms" }
        $dStr = if ($r.DnsTime -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.DnsTime,1))ms" }
        $sStr = if ($r.Score -eq [double]::MaxValue) { '99999' } else { [math]::Round($r.Score, 1) }
        $doh = if ($r.DoH) { 'Yes' } else { 'No' }
        $dot = if ($r.DoT) { 'Yes' } else { 'No' }
        $ecs = if ($r.ECS) { 'Yes' } else { 'No' }
        $hj = if ($r.Hijacked) { 'HIJACK' } else { '' }
        $statusFull = "$($r.Status) $hj".Trim()
        $md += "| #$rank | $($r.Name) | $($r.Category) | $($r.IP) | $doh | $dot | $ecs | $pStr | $jStr | $($r.Loss)% | $dStr | $sStr | $statusFull |"
    }
    
    $md += ""
    $md += "## Top 3 Summary"
    $md += ""
    $top3 = @($Results | Select-Object -First 3)
    foreach ($t in $top3) {
        $tPing = if ($t.PingAvg -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($t.PingAvg,1))ms" }
        $tDns = if ($t.DnsTime -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($t.DnsTime,1))ms" }
        $md += "- **$($t.Name)** ($($t.IP)) - Ping: $tPing, DNS: $tDns, Score: $([math]::Round($t.Score,1))"
    }
    
    $md += ""
    $md += "## Security Notes"
    $md += ""
    $hijacked = @($Results | Where-Object { $_.Hijacked })
    if ($hijacked.Count -gt 0) {
        $md += "**WARNING:** The following providers returned non-NXDOMAIN for nonexistent domains (possible hijacking):"
        foreach ($h in $hijacked) { $md += "- $($h.Name) ($($h.IP))" }
    } else {
        $md += "All tested providers correctly returned NXDOMAIN for nonexistent domains. No hijacking detected."
    }
    
    $md += ""
    $md += "---"
    $md += "*Generated by DNS Optimizer God-Mode v2*"
    
    $mdFile = Join-Path $dir "report_$ts.md"
    $md -join "`n" | Set-Content -Path $mdFile -Encoding UTF8

    Write-Host "  $(C 'G' "Telemetry exported to $dir :")"
    Write-Host "    $(C 'C' "- telemetry_$ts.json")"
    Write-Host "    $(C 'C' "- telemetry_$ts.csv")"
    Write-Host "    $(C 'C' "- report_$ts.md")"
}

function Optimize-MTU {
    $adapter = Get-ActiveAdapter
    if (-not $adapter) { Write-Host "  $(C 'R' 'No active adapter found.')"; return }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host "  $(C 'R' 'Administrator privileges required to set MTU.')"; return }

    $targetIp = '1.1.1.1'
    $chk = ping -n 1 -w 1000 1.1.1.1 2>&1
    if (($chk -join ' ') -match 'timed out|100% loss|unreachable') {
        $targetIp = '8.8.8.8'
        Write-Host "  $(C 'Y' '1.1.1.1 dropped ICMP. Falling back to 8.8.8.8...')"
    }
    Write-Host "`n  $(C 'C' "Starting Binary Search MTU Detection (Target: $targetIp)...")"
    
    $low = 1400
    $high = 1472
    $best = 1400
    
    while ($low -le $high) {
        $mid = [Math]::Floor(($low + $high) / 2)
        Write-Host -NoNewline "    Testing payload size $mid bytes... "
        $res = ping -f -l $mid -n 1 -w 1000 $targetIp 2>&1
        $resStr = $res -join " "
        
        if ($resStr -match 'needs to be fragmented|Packet needs to be fragmented|Request timed out|100% loss') {
            Write-Host "$(C 'Y' 'Fragmented or Lost')"
            $high = $mid - 1
        } else {
            Write-Host "$(C 'G' 'Success')"
            $best = $mid
            $low = $mid + 1
        }
    }
    
    $optMtu = $best + 28
    Write-Host "`n  $(C 'G' "Optimal Payload: $best bytes")"
    Write-Host "  $(C 'G' "Calculated MTU (Payload + 28): $optMtu bytes")"
    
    try {
        netsh int ipv4 set subinterface "$($adapter.Name)" mtu=$optMtu store=persistent | Out-Null
        Write-Host "  $(C 'G' "Successfully applied MTU $optMtu to adapter $($adapter.Name).")"
        return $optMtu
    } catch {
        Write-Host "  $(C 'R' "Failed to apply MTU: $_")"
        return $null
    }
}

# ── Game Server Latency Test ─────────────────────────────────────────────────
function Test-GameServerRouting {
    Write-Host ""
    Write-Host "  $(C 'BOLD' 'Game Server Routing Test (SEA Region)')"
    Write-Host "  $(C 'DG' 'Pinging game server gateways with current DNS config...')"
    Write-Host ""

    $targets = @(
        @{Name="Riot / Valorant SEA (SG)";    IP="104.160.131.3"}
        @{Name="Riot / Valorant SEA (SG 2)";  IP="151.106.248.1"}
        @{Name="Valve / Steam CS2 (SG Relay)";IP="103.10.124.1"}
        @{Name="Moonton / MLBB SEA";          IP="161.117.234.1"}
        @{Name="Cloudflare SEA (Anycast)";    IP="1.1.1.1"}
        @{Name="Google SEA (Anycast)";        IP="8.8.8.8"}
    )

    $pinger = New-Object System.Net.NetworkInformation.Ping
    $pingCount = 6

    Write-Host "  $(C 'BOLD' ('{0,-34} {1,-10} {2,-10} {3,-10} {4,-8} {5}' -f 'Server','Avg','Min','Max','Loss','Status'))"
    Write-Host "  $(C 'BOLD' ('-' * 90))"

    foreach ($t in $targets) {
        $times = @()
        $lost = 0
        $isTcp = $false
        for ($i = 0; $i -lt $pingCount; $i++) {
            try {
                $rep = $pinger.Send($t.IP, 800)
                if ($rep.Status -eq 'Success') { $times += $rep.RoundtripTime }
                else { $lost++ }
            } catch { $lost++ }
        }

        # Fallback to TCPing on standard game/web ports if ICMP fails completely
        if ($lost -eq $pingCount) {
            $times = @()
            $lost = 0
            $isTcp = $true
            for ($i = 0; $i -lt $pingCount; $i++) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $client = $null
                    try {
                        $client = New-Object System.Net.Sockets.TcpClient
                        $iar = $client.BeginConnect($t.IP, 443, $null, $null)
                        $wait = $iar.AsyncWaitHandle.WaitOne(800, $false)
                        if ($wait -and $client.Connected) {
                            $client.EndConnect($iar)
                            $times += $sw.Elapsed.TotalMilliseconds
                        } else {
                            try { $client.Close(); $client.Dispose() } catch {}
                            $client = New-Object System.Net.Sockets.TcpClient
                            $iar = $client.BeginConnect($t.IP, 80, $null, $null)
                            $wait = $iar.AsyncWaitHandle.WaitOne(800, $false)
                            if ($wait -and $client.Connected) {
                                $client.EndConnect($iar)
                                $times += $sw.Elapsed.TotalMilliseconds
                            } else {
                                $lost++
                            }
                        }
                    } finally {
                        if ($null -ne $client) { try { $client.Close(); $client.Dispose() } catch {} }
                    }
                } catch { $lost++ }
            }
        }

        $lossPct = [math]::Round(($lost / $pingCount) * 100, 0)
        $prot = if ($isTcp) { 'TCP' } else { 'ICMP' }

        if ($times.Count -gt 0) {
            $avg = [math]::Round(($times | Measure-Object -Average).Average, 1)
            $min = [math]::Round(($times | Measure-Object -Minimum).Minimum, 1)
            $max = [math]::Round(($times | Measure-Object -Maximum).Maximum, 1)
            $color = if ($avg -lt 30) { 'G' } elseif ($avg -lt 80) { 'Y' } else { 'R' }
            $status = if ($avg -lt 30) { 'Excellent' } elseif ($avg -lt 80) { 'Good' } elseif ($avg -lt 150) { 'Fair' } else { 'Poor' }
            $line = '{0,-34} {1,-10} {2,-10} {3,-10} {4,-8} {5,-11} {6}' -f $t.Name, "${avg}ms", "${min}ms", "${max}ms", "${lossPct}%", $status, $prot
            Write-Host "  $(C $color $line)"
        } else {
            $line = '{0,-34} {1,-10} {2,-10} {3,-10} {4,-8} {5,-11} {6}' -f $t.Name, 'N/A', 'N/A', 'N/A', '100%', 'UNREACHABLE', $prot
            Write-Host "  $(C 'R' $line)"
        }
    }
    $pinger.Dispose()

    Write-Host ""
    Write-Host "  $(C 'DG' 'Note: Results reflect routing with your current DNS. Re-test after changing DNS to compare.')"
}

# ── Interactive Menu ─────────────────────────────────────────────────────────
function Show-Menu {
    param($Results, $ElapsedSec)

    $adapter = Get-ActiveAdapter
    $aName = if ($adapter) { $adapter.Name } else { 'NONE DETECTED' }

    while ($true) {
        Write-Host ""
        Write-Host "  $(C 'C' '┌──────────────────────────────────────────────────────────────┐')"
        Write-Host "  $(C 'C' '│')  $(C 'BOLD' 'GOD-MODE ACTION MENU')          Adapter: $(C 'Y' $aName)"
        Write-Host "  $(C 'C' '├──────────────────────────────────────────────────────────────┤')"
        Write-Host "  $(C 'C' '│')  $(C 'DG' '[ DNS PROFILES ]')                                       $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'G' '1.') Apply #1 Fastest DNS Pair (IPv4+IPv6)               $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'G' '2.') Apply Best Gaming DNS (ECS + Low Jitter)            $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'G' '3.') Apply Best AdBlock DNS Pair                         $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'G' '4.') Apply Best Privacy DNS Pair                         $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'C' '5.') Select Custom Provider from Ranking                 $(C 'C' '│')"
        Write-Host "  $(C 'C' '├──────────────────────────────────────────────────────────────┤')"
        Write-Host "  $(C 'C' '│')  $(C 'DG' '[ NETWORK & LATENCY TUNING ]')                           $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'G' '6.') Auto-Detect & Apply Optimal MTU                     $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'M' '7.') Run Windows DNS Cache, TCP & NIC Hardware Tuning    $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'Y' '8.') Test Game Server Routing (SEA Latency)              $(C 'C' '│')"
        Write-Host "  $(C 'C' '├──────────────────────────────────────────────────────────────┤')"
        Write-Host "  $(C 'C' '│')  $(C 'DG' '[ MANAGEMENT & TELEMETRY ]')                             $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'M' '9.') Restore Previous DNS from Backup                    $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'Y' '10.') Reset to Default DHCP (ISP)                        $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'B' '11.') Export Full Telemetry (CSV, JSON, Markdown Report) $(C 'C' '│')"
        Write-Host "  $(C 'C' '├──────────────────────────────────────────────────────────────┤')"
        Write-Host "  $(C 'C' '│')  $(C 'DG' '[ EXIT ]')                                               $(C 'C' '│')"
        Write-Host "  $(C 'C' '│')  $(C 'DG' '0.') Exit                                                $(C 'C' '│')"
        Write-Host "  $(C 'C' '└──────────────────────────────────────────────────────────────┘')"
        $c = Read-Host "  Select option"

        switch ($c) {
            '1' {
                $best = $Results | Where-Object { $_.Status -eq 'OK' } | Select-Object -First 1
                if ($best) {
                    $baseName = $best.Name -replace ' (Primary|Secondary|1|2|3|4)',''
                    $pair = $Results | Where-Object { $_.Name -match [regex]::Escape($baseName) -and $_.IP -ne $best.IP -and $_.Status -eq 'OK' } | Select-Object -First 1
                    if (-not $pair) { $pair = $Results | Where-Object { $_.Status -eq 'OK' -and $_.IP -ne $best.IP } | Select-Object -First 1 }
                    Set-Dns -Primary $best.IP -Secondary ($pair.IP) -Category 'Fastest'
                } else { Write-Host "  $(C 'R' 'No viable DNS found.')" }
            }
            '2' {
                # Gaming DNS: ECS + 0% loss + weighted score (40% PingAvg, 30% DnsTime, 30% Jitter)
                $gamingPool = @($Results | Where-Object { $_.Status -eq 'OK' -and $_.Loss -eq 0 -and $_.ECS -eq $true })
                if ($gamingPool.Count -eq 0) {
                    # Relax: allow any OK+0%loss provider
                    $gamingPool = @($Results | Where-Object { $_.Status -eq 'OK' -and $_.Loss -eq 0 })
                    Write-Host "  $(C 'Y' 'No ECS providers with 0% loss. Relaxed filter (any 0% loss).')"
                }
                if ($gamingPool.Count -eq 0) {
                    Write-Host "  $(C 'R' 'No gaming-grade DNS candidates found.')"
                } else {
                    $gamingRanked = $gamingPool | ForEach-Object {
                        $ep = if ($_.PingAvg -eq [double]::MaxValue) { 999 } else { $_.PingAvg }
                        $ed = if ($_.DnsTime -eq [double]::MaxValue) { 999 } else { $_.DnsTime }
                        $ej = if ($_.Jitter -eq 999) { 999 } else { $_.Jitter }
                        $_ | Add-Member -NotePropertyName GamingScore -NotePropertyValue (($ep * 0.4) + ($ed * 0.3) + ($ej * 0.3)) -PassThru -Force
                    } | Sort-Object GamingScore

                    $best = $gamingRanked[0]
                    $baseName = $best.Name -replace ' (Primary|Secondary|1|2|3|4)',''
                    $pair = $gamingRanked | Where-Object { $_.Name -match [regex]::Escape($baseName) -and $_.IP -ne $best.IP } | Select-Object -First 1
                    if (-not $pair) { $pair = $gamingRanked | Where-Object { $_.IP -ne $best.IP } | Select-Object -First 1 }

                    $bestProv = $script:DnsProviders | Where-Object { $_.IP -eq $best.IP } | Select-Object -First 1
                    $pairProv = if ($pair) { $script:DnsProviders | Where-Object { $_.IP -eq $pair.IP } | Select-Object -First 1 } else { $null }

                    Write-Host ""
                    Write-Host "  $(C 'BOLD' '── Gaming DNS Selection ──')"
                    Write-Host "  $(C 'G' 'Primary: ')  $($best.Name) | IPv4: $($best.IP) | IPv6: $(if ($bestProv.IPv6) { $bestProv.IPv6 } else { 'fallback' }) | ECS: $($best.ECS) | Jitter: $([math]::Round($best.Jitter,1))ms | GScore: $([math]::Round($best.GamingScore,1))"
                    if ($pair) {
                        Write-Host "  $(C 'G' 'Secondary:')  $($pair.Name) | IPv4: $($pair.IP) | IPv6: $(if ($pairProv.IPv6) { $pairProv.IPv6 } else { 'fallback' }) | ECS: $($pair.ECS) | Jitter: $([math]::Round($pair.Jitter,1))ms | GScore: $([math]::Round($pair.GamingScore,1))"
                    }

                    Set-Dns -Primary $best.IP -Secondary $(if ($pair) { $pair.IP } else { $null }) -Category 'Gaming'
                    Write-Host "  $(C 'C' 'Running post-apply TCP/latency tuning...')"
                    Optimize-NetworkRegistry
                }
            }
            '3' {
                $best = $Results | Where-Object { $_.Status -eq 'OK' -and $_.Category -eq 'AdBlock' } | Select-Object -First 1
                if ($best) {
                    $baseName = $best.Name -replace ' (Primary|Secondary)',''
                    $pair = $Results | Where-Object { $_.Name -match [regex]::Escape($baseName) -and $_.IP -ne $best.IP -and $_.Status -eq 'OK' } | Select-Object -First 1
                    if (-not $pair) { $pair = $Results | Where-Object { $_.Status -eq 'OK' -and $_.Category -eq 'AdBlock' -and $_.IP -ne $best.IP } | Select-Object -First 1 }
                    if (-not $pair) { $pair = $Results | Where-Object { $_.Status -eq 'OK' -and $_.IP -ne $best.IP } | Select-Object -First 1 }
                    Set-Dns -Primary $best.IP -Secondary ($pair.IP) -Category 'AdBlock'
                } else { Write-Host "  $(C 'R' 'No viable AdBlock DNS found.')" }
            }
            '4' {
                $best = $Results | Where-Object { $_.Status -eq 'OK' -and $_.Category -eq 'Privacy' } | Select-Object -First 1
                if ($best) {
                    $baseName = $best.Name -replace ' (Primary|Secondary)',''
                    $pair = $Results | Where-Object { $_.Name -match [regex]::Escape($baseName) -and $_.IP -ne $best.IP -and $_.Status -eq 'OK' } | Select-Object -First 1
                    if (-not $pair) { $pair = $Results | Where-Object { $_.Status -eq 'OK' -and $_.Category -eq 'Privacy' -and $_.IP -ne $best.IP } | Select-Object -First 1 }
                    if (-not $pair) { $pair = $Results | Where-Object { $_.Status -eq 'OK' -and $_.IP -ne $best.IP } | Select-Object -First 1 }
                    Set-Dns -Primary $best.IP -Secondary ($pair.IP) -Category 'Privacy'
                } else { Write-Host "  $(C 'R' 'No viable Privacy DNS found.')" }
            }
            '5' {
                $viable = @($Results | Where-Object { $_.Status -eq 'OK' })
                Write-Host ""
                for ($i = 0; $i -lt [Math]::Min($viable.Count, 25); $i++) {
                    Write-Host "    $(C 'C' ($i+1)). $($viable[$i].Name) ($($viable[$i].IP))"
                }
                $sel = Read-Host "  Enter number"
                $idx = $sel -as [int]
                if ($null -eq $idx -or $idx -lt 1 -or $idx -gt $viable.Count) {
                    Write-Host "  $(C 'R' 'Invalid selection.')"
                } else {
                    $idx = $idx - 1
                    $best = $viable[$idx]
                    $baseName = $best.Name -replace ' (Primary|Secondary|1|2|3|4)',''
                    $pair = $viable | Where-Object { $_.Name -match [regex]::Escape($baseName) -and $_.IP -ne $best.IP } | Select-Object -First 1
                    if (-not $pair) { $pair = $viable | Where-Object { $_.IP -ne $best.IP } | Select-Object -First 1 }
                    Set-Dns -Primary $best.IP -Secondary ($pair.IP) -Category 'Custom'
                }
            }
            '6' { Optimize-MTU }
            '7' { Optimize-NetworkRegistry }
            '8' { Test-GameServerRouting }
            '9' { Restore-NetworkSettings }
            '10' {
                if ($aName -ne 'NONE DETECTED') {
                    Backup-NetworkSettings | Out-Null
                    Set-DnsClientServerAddress -InterfaceAlias $aName -ResetServerAddresses
                    ipconfig /flushdns | Out-Null
                    Write-Host "  $(C 'G' 'Reset to DHCP successfully.')"
                }
            }
            '11' { Export-Telemetry -Results $Results -ElapsedSec $ElapsedSec }
            '0' { Write-Host "  $(C 'DG' 'Goodbye.')"; return }
            default { Write-Host "  $(C 'Y' 'Invalid choice.')" }
        }
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────
function Main {
    Clear-Host
    Show-Banner

    Write-Host "  $(C 'C' 'Pre-flight check...')"
    $adapter = Get-ActiveAdapter
    if ($adapter) { Write-Host "  $(C 'G' "Active adapter: $($adapter.Name) ($($adapter.InterfaceDescription))")" }
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "  $(C $(if ($isAdmin) {'G'} else {'Y'}) "Admin: $isAdmin")"
    
    Write-Host "`n  $(C 'BOLD' "Executing Unified Pipeline Benchmark ($($script:DnsProviders.Count) Providers)...")"
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $results = Invoke-BenchmarkEngine -Targets $script:DnsProviders
    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)

    Write-Host "`n  $(C 'G' "Pipeline complete in ${elapsed}s")"

    # Security summary
    $hijacked = @($results | Where-Object { $_.Hijacked })
    if ($hijacked.Count -gt 0) {
        Write-Host "  $(C 'M' "WARNING: $($hijacked.Count) provider(s) detected as HIJACKED (non-NXDOMAIN response)")"
    } else {
        Write-Host "  $(C 'G' 'All providers passed NXDOMAIN hijack check.')"
    }

    Show-Table -Results $results
    Show-Menu -Results $results -ElapsedSec $elapsed
}

Main
