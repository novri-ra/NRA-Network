#Requires -Version 5.1

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

[xml]$XAML = Get-Content -Path (Join-Path $PSScriptRoot "MainWindow.xaml") -Raw

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Map XAML controls
$BtnRunBenchmark = $window.FindName("BtnRunBenchmark")
$AdapterBadge = $window.FindName("AdapterBadge")
$AdminBadge = $window.FindName("AdminBadge")
$StatTopDns = $window.FindName("StatTopDns")
$StatLowestPing = $window.FindName("StatLowestPing")
$StatDnsResolve = $window.FindName("StatDnsResolve")
$StatMtu = $window.FindName("StatMtu")
$DnsDataGrid = $window.FindName("DnsDataGrid")
$BtnApplyFastest = $window.FindName("BtnApplyFastest")
$BtnApplyAdblock = $window.FindName("BtnApplyAdblock")
$BtnApplyPrivacy = $window.FindName("BtnApplyPrivacy")
$BtnOptimizeTcp = $window.FindName("BtnOptimizeTcp")
$BtnAutoMtu = $window.FindName("BtnAutoMtu")
$BtnTestGames = $window.FindName("BtnTestGames")
$BtnResetDhcp = $window.FindName("BtnResetDhcp")
$BtnExport = $window.FindName("BtnExport")
$ProgBar = $window.FindName("ProgBar")
$ConsoleOutput = $window.FindName("ConsoleOutput")
$ConsoleScroll = $window.FindName("ConsoleScroll")

function Log-Message([string]$Msg) {
    $window.Dispatcher.Invoke([action]{
        $ConsoleOutput.Text += "[$(Get-Date -Format 'HH:mm:ss')] $Msg`n"
        $ConsoleScroll.ScrollToEnd()
    })
}

# --- Import logic from dns_benchmark.ps1 ---
$benchmarkScriptPath = Join-Path $PSScriptRoot "dns_benchmark.ps1"
$benchmarkScript = Get-Content -Path $benchmarkScriptPath -Raw
# Strip the Main function call at the bottom so it doesn't run the CLI
$benchmarkScript = $benchmarkScript -replace '(?m)^Main\s*$', ''

$AdminBadge.Text = if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "Admin: OK" } else { "Admin: No (Run as Admin)" }

# Pre-flight: load backend functions and detect active adapter
try {
    $ps = [PowerShell]::Create().AddScript($benchmarkScript)
    $ps.Invoke()
    $ps.Commands.Clear()
    $activeAdapter = $ps.AddScript("Get-ActiveAdapter").Invoke() | Select-Object -First 1
    if ($activeAdapter) {
        $AdapterBadge.Text = "Adapter: " + $activeAdapter.Name
        $ConsoleOutput.Text += "[$(Get-Date -Format 'HH:mm:ss')] Pre-flight OK: $($activeAdapter.Name)`n"
    } else {
        $AdapterBadge.Text = "Adapter: Not Detected"
        $ConsoleOutput.Text += "[$(Get-Date -Format 'HH:mm:ss')] Pre-flight: No active adapter found`n"
    }
    $ps.Dispose()
} catch {
    $AdapterBadge.Text = "Adapter: Error"
    $ConsoleOutput.Text += "[$(Get-Date -Format 'HH:mm:ss')] Pre-flight error: $_`n"
}

# ══════════════════════════════════════════════════════════════════════════════
# BtnRunBenchmark - Main benchmark with live progress
# ══════════════════════════════════════════════════════════════════════════════
$BtnRunBenchmark.Add_Click({
    Log-Message "Starting Benchmark..."
    $BtnRunBenchmark.IsEnabled = $false
    $ProgBar.Value = 0

    $script:bmSync = [hashtable]::Synchronized(@{ Progress = 0; IsDone = $false; Result = $null; Error = $null })
    $script:bmPs = [PowerShell]::Create()
    $script:bmPs.AddScript({
        param($bmScript, $sync)
        try {
            $psWorker = [PowerShell]::Create().AddScript($bmScript)
            $psWorker.Invoke()
            
            $psWorker.Commands.Clear()
            $targets = @($psWorker.AddScript('$script:DnsProviders').Invoke())

            if (-not $targets -or $targets.Count -eq 0) {
                $sync.Result = @()
                $sync.IsDone = $true
                $psWorker.Dispose()
                return
            }

            $timeout = 800
            $icmp = 4
            $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($targets.Count, 128))
            $pool.Open()

            $scriptBlock = {
                param($IP, $DoH, $DoT, $ECS, $TimeoutMs, $IcmpCount)
                $pinger = New-Object System.Net.NetworkInformation.Ping
                $icmpTimes = @()
                $lost = 0
                for ($i = 0; $i -lt $IcmpCount; $i++) {
                    try {
                        $rep = $pinger.Send($IP, $TimeoutMs)
                        if ($rep.Status -eq 'Success') { $icmpTimes += $rep.RoundtripTime }
                        else { $lost++ }
                    } catch { $lost++ }
                }
                $pinger.Dispose()

                $pingAvg = if ($icmpTimes.Count -gt 0) { ($icmpTimes | Measure-Object -Average).Average } else { [double]::MaxValue }
                $pingJitter = if ($icmpTimes.Count -gt 0) { ($icmpTimes | Measure-Object -Maximum).Maximum - ($icmpTimes | Measure-Object -Minimum).Minimum } else { 999 }
                $lossPct = [math]::Round(($lost / $IcmpCount) * 100, 1)

                function Test-UDP-DNS($domain) {
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        $udp = New-Object System.Net.Sockets.UdpClient
                        $udp.Client.ReceiveTimeout = $TimeoutMs
                        $udp.Client.SendTimeout = $TimeoutMs
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
                        $ms.Dispose()

                        $udp.Connect($IP, 53)
                        [void]$udp.Send($pkt, $pkt.Length)
                        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                        $res = $udp.Receive([ref]$ep)
                        $udp.Close()

                        $rcode = $res[3] -band 0x0F
                        $ansCount = ($res[6] -shl 8) -bor $res[7]
                        $dnssec = ($res[3] -band 0x20) -eq 0x20
                        return @{ Time=$sw.Elapsed.TotalMilliseconds; RCode=$rcode; AnsCount=$ansCount; DNSSEC=$dnssec }
                    } catch {
                        try { $udp.Close() } catch {}
                        return $null
                    }
                }

                $dnsTimes = @()
                $failures = 0
                $hijacked = $false
                $dnssecOK = $false

                $validRes = Test-UDP-DNS 'google.com'
                if ($validRes) { $dnsTimes += $validRes.Time } else { $failures++ }

                $validRes2 = Test-UDP-DNS 'cloudflare.com'
                if ($validRes2) { $dnsTimes += $validRes2.Time; if($validRes2.DNSSEC) { $dnssecOK = $true } } else { $failures++ }

                $nxDomain = "nxdomain-test-$([guid]::NewGuid().ToString('N').Substring(0,12)).com"
                $nxRes = Test-UDP-DNS $nxDomain
                if ($nxRes) {
                    $dnsTimes += $nxRes.Time
                    if ($nxRes.RCode -eq 0 -and $nxRes.AnsCount -gt 0) { $hijacked = $true }
                } else { $failures++ }

                $dnsAvg = if ($dnsTimes.Count -gt 0) { ($dnsTimes | Measure-Object -Average).Average } else { [double]::MaxValue }

                @{ IP = $IP; DoH = $DoH -ne ""; DoT = $DoT -ne ""; ECS = $ECS; PingAvg = $pingAvg; PingJitter = $pingJitter; Loss = $lossPct; DnsAvg = $dnsAvg; DnsFailed = $failures -ge 2; Hijacked = $hijacked; DNSSEC = $dnssecOK }
            }

            $jobs = @()
            foreach ($t in $targets) {
                $psJob = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($t.IP).AddArgument($t.DoH).AddArgument($t.DoT).AddArgument($t.ECS).AddArgument($timeout).AddArgument($icmp)
                $psJob.RunspacePool = $pool
                $jobs += @{ Pipe=$psJob; Handle=$psJob.BeginInvoke(); P=$t }
            }

            $total = $jobs.Count
            $done = 0
            $results = @()

            while ($jobs.Count -gt 0) {
                $incomplete = @()
                $completed = @()
                foreach ($j in $jobs) {
                    if ($j.Handle.IsCompleted) { $completed += $j } else { $incomplete += $j }
                }
                $jobs = $incomplete

                foreach ($j in $completed) {
                    $res = $null
                    try {
                        $rawRes = $j.Pipe.EndInvoke($j.Handle)
                        if ($rawRes.Count -gt 0) { $res = $rawRes[0] }
                    } catch {}

                    if (-not ($res -and $res.IP)) {
                        $res = @{ IP = $j.P.IP; DoH = ($j.P.DoH -ne ""); DoT = ($j.P.DoT -ne ""); ECS = $j.P.ECS; PingAvg = [double]::MaxValue; PingJitter = 999; Loss = 100.0; DnsAvg = [double]::MaxValue; DnsFailed = $true; Hijacked = $false; DNSSEC = $false }
                    }
                    $j.Pipe.Dispose()
                    $done++

                    $pct = [math]::Floor(($done / $total) * 100)
                    $sync.Progress = $pct

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
                }
                if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 20 }
            }
            $pool.Close()
            $pool.Dispose()
            $psWorker.Dispose()

            $sync.Result = $results | Sort-Object Score
        } catch {
            $sync.Error = $_
        }
        $sync.IsDone = $true
    }).AddArgument($benchmarkScript).AddArgument($script:bmSync)
    $script:bmHandle = $script:bmPs.BeginInvoke()

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({
        $ProgBar.Value = $script:bmSync.Progress
        if ($script:bmSync.IsDone -eq $true) {
            $timer.Stop()
            $BtnRunBenchmark.IsEnabled = $true
            try { $script:bmPs.EndInvoke($script:bmHandle) } catch {}
            $script:bmPs.Dispose()

            if ($script:bmSync.Error) {
                Log-Message "Error running benchmark: $($script:bmSync.Error)"
                return
            }

            $results = $script:bmSync.Result
            $uiList = New-Object System.Collections.ArrayList
            $rank = 1

            $bestPing = [double]::MaxValue
            $bestDns = [double]::MaxValue

            foreach ($r in $results) {
                if ($r.PingAvg -lt $bestPing -and $r.PingAvg -ne [double]::MaxValue) { $bestPing = $r.PingAvg }
                if ($r.DnsTime -lt $bestDns -and $r.DnsTime -ne [double]::MaxValue) { $bestDns = $r.DnsTime }

                $badges = @()
                if ($r.DoH) { $badges += "DoH" }
                if ($r.DoT) { $badges += "DoT" }
                if ($r.ECS) { $badges += "ECS" }
                if ($r.DNSSEC) { $badges += "SEC" }

                $pingTier = if ($r.PingAvg -eq [double]::MaxValue) { 'fail' } elseif ($r.PingAvg -lt 30) { 'good' } elseif ($r.PingAvg -lt 80) { 'mid' } else { 'high' }
                $dnsTier = if ($r.DnsTime -eq [double]::MaxValue) { 'fail' } elseif ($r.DnsTime -lt 30) { 'good' } elseif ($r.DnsTime -lt 80) { 'mid' } else { 'high' }

                [void]$uiList.Add([PSCustomObject]@{
                    Rank = $rank
                    Name = $r.Name
                    Category = $r.Category
                    IP = $r.IP
                    Badges = $badges -join " "
                    PingStr = if ($r.PingAvg -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.PingAvg,1))ms" }
                    PingTier = $pingTier
                    JitterStr = if ($r.Jitter -eq 999) { 'N/A' } else { "$([math]::Round($r.Jitter,1))ms" }
                    LossStr = "$($r.Loss)%"
                    DnsTimeStr = if ($r.DnsTime -eq [double]::MaxValue) { 'N/A' } else { "$([math]::Round($r.DnsTime,1))ms" }
                    DnsTier = $dnsTier
                    ScoreStr = if ($r.Score -eq [double]::MaxValue) { '99999' } else { [math]::Round($r.Score, 1) }
                    Status = $r.Status
                })
                $rank++
            }

            $DnsDataGrid.ItemsSource = $uiList

            if ($results.Count -gt 0) {
                $StatTopDns.Text = "$($results[0].Name) ($($results[0].IP))"
            }
            if ($bestPing -eq [double]::MaxValue) { $StatLowestPing.Text = "---" }
            else {
                $pv = [math]::Round($bestPing,1)
                $pi = if ($pv -lt 30) { [char]0x25BC } elseif ($pv -lt 80) { [char]0x25CF } else { [char]0x25B2 }
                $StatLowestPing.Text = "$pi $pv"
            }
            if ($bestDns -eq [double]::MaxValue) { $StatDnsResolve.Text = "---" }
            else {
                $dv = [math]::Round($bestDns,1)
                $di = if ($dv -lt 30) { [char]0x25BC } elseif ($dv -lt 80) { [char]0x25CF } else { [char]0x25B2 }
                $StatDnsResolve.Text = "$di $dv"
            }

            Log-Message "Benchmark Complete. Found $($results.Count) results."
        }
    })
    $timer.Start()
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnAutoMtu - MTU detection in background
# ══════════════════════════════════════════════════════════════════════════════
$BtnAutoMtu.Add_Click({
    Log-Message "Starting Auto MTU detection..."
    
    $script:mtuSync = [hashtable]::Synchronized(@{ IsDone = $false; Result = $null })
    $script:mtuPs = [PowerShell]::Create()
    $script:mtuPs.AddScript({
        param($bmScript, $sync)
        try {
            $psWorker = [PowerShell]::Create().AddScript($bmScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $mtuResult = $psWorker.AddScript("Optimize-MTU").Invoke()
            $mtuVal = $mtuResult | Where-Object { $_ -is [int] -or $_ -match '^\d+$' } | Select-Object -Last 1
            $sync.Result = if ($mtuVal) { [string]$mtuVal } else { "Done" }
            $psWorker.Dispose()
        } catch { $sync.Result = "Error" }
        $sync.IsDone = $true
    }).AddArgument($benchmarkScript).AddArgument($script:mtuSync)
    $script:mtuHandle = $script:mtuPs.BeginInvoke()
    
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({
        if ($script:mtuSync.IsDone -eq $true) {
            $timer.Stop()
            try { $script:mtuPs.EndInvoke($script:mtuHandle) } catch {}
            $script:mtuPs.Dispose()
            $StatMtu.Text = $script:mtuSync.Result
            Log-Message "MTU detection complete: $($script:mtuSync.Result)"
        }
    })
    $timer.Start()
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnResetDhcp
# ══════════════════════════════════════════════════════════════════════════════
$BtnResetDhcp.Add_Click({
    Log-Message "Resetting to DHCP..."
    try {
        $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
        $psWorker.Invoke()
        $psWorker.Commands.Clear()
        $adapter = $psWorker.AddScript("Get-ActiveAdapter").Invoke() | Select-Object -First 1
        if ($adapter) {
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Set-DnsClientServerAddress -InterfaceAlias `"$($adapter.Name)`" -ResetServerAddresses").Invoke()
            Log-Message "Reset complete."
        } else {
            Log-Message "No active adapter found."
        }
    } catch {
        Log-Message "Error: $_"
    } finally { if ($psWorker) { $psWorker.Dispose() } }
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnOptimizeTcp
# ══════════════════════════════════════════════════════════════════════════════
$BtnOptimizeTcp.Add_Click({
    Log-Message "Applying TCP/Registry Optimizations..."
    try {
        $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
        $psWorker.Invoke()
        $psWorker.Commands.Clear()
        $psWorker.AddScript("Optimize-NetworkRegistry").Invoke()
        Log-Message "TCP/Registry optimization complete."
    } catch {
        Log-Message "Error: $_"
    } finally { if ($psWorker) { $psWorker.Dispose() } }
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnTestGames - Game latency test in background
# ══════════════════════════════════════════════════════════════════════════════
$BtnTestGames.Add_Click({
    Log-Message "Testing Game Servers..."
    $script:gameSync = [hashtable]::Synchronized(@{ IsDone = $false })
    $script:gamePs = [PowerShell]::Create()
    $script:gamePs.AddScript({
        param($bmScript, $sync)
        try {
            $psWorker = [PowerShell]::Create().AddScript($bmScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Test-GameServerRouting").Invoke()
            $psWorker.Dispose()
        } catch {}
        $sync.IsDone = $true
    }).AddArgument($benchmarkScript).AddArgument($script:gameSync)
    $script:gameHandle = $script:gamePs.BeginInvoke()
    
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({
        if ($script:gameSync.IsDone -eq $true) {
            $timer.Stop()
            try { $script:gamePs.EndInvoke($script:gameHandle) } catch {}
            $script:gamePs.Dispose()
            Log-Message "Game server latency test finished."
        }
    })
    $timer.Start()
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnApplyFastest
# ══════════════════════════════════════════════════════════════════════════════
$BtnApplyFastest.Add_Click({
    if ($DnsDataGrid.Items.Count -gt 0) {
        $first = $DnsDataGrid.Items[0]
        Log-Message "Applying Fastest DNS: $($first.Name) ($($first.IP))"
        try {
            $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Set-Dns -Primary '$($first.IP)' -Secondary '' -Category '$($first.Category)'").Invoke()
            Log-Message "Applied."
        } catch { Log-Message "Error: $_" } finally { if ($psWorker) { $psWorker.Dispose() } }
    } else { Log-Message "Run benchmark first." }
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnApplyAdblock
# ══════════════════════════════════════════════════════════════════════════════
$BtnApplyAdblock.Add_Click({
    $adblock = $null
    foreach ($item in $DnsDataGrid.Items) {
        if ($item.Category -eq 'AdBlock') { $adblock = $item; break }
    }
    if ($adblock) {
        Log-Message "Applying Best Adblock DNS: $($adblock.Name) ($($adblock.IP))"
        try {
            $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Set-Dns -Primary '$($adblock.IP)' -Secondary '' -Category '$($adblock.Category)'").Invoke()
            Log-Message "Applied."
        } catch { Log-Message "Error: $_" } finally { if ($psWorker) { $psWorker.Dispose() } }
    } else { Log-Message "Run benchmark first." }
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnApplyPrivacy
# ══════════════════════════════════════════════════════════════════════════════
$BtnApplyPrivacy.Add_Click({
    $priv = $null
    foreach ($item in $DnsDataGrid.Items) {
        if ($item.Category -eq 'Privacy') { $priv = $item; break }
    }
    if ($priv) {
        Log-Message "Applying Best Privacy DNS: $($priv.Name) ($($priv.IP))"
        try {
            $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Set-Dns -Primary '$($priv.IP)' -Secondary '' -Category '$($priv.Category)'").Invoke()
            Log-Message "Applied."
        } catch { Log-Message "Error: $_" } finally { if ($psWorker) { $psWorker.Dispose() } }
    } else { Log-Message "Run benchmark first." }
})

# ══════════════════════════════════════════════════════════════════════════════
# BtnExport
# ══════════════════════════════════════════════════════════════════════════════
$BtnExport.Add_Click({
    Log-Message "Exporting telemetry..."
    try {
        $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
        $psWorker.Invoke()

        $results = $DnsDataGrid.ItemsSource
        if (-not $results) {
            Log-Message "No results to export. Run benchmark first."
            return
        }

        $psWorker.Runspace.SessionStateProxy.SetVariable("exportResults", $results)
        $psWorker.Commands.Clear()
        $psWorker.AddScript("Export-Telemetry -Results `$exportResults -ElapsedSec 0").Invoke()
        Log-Message "Export complete. Check script root directory."
    } catch { Log-Message "Error: $_" } finally { if ($psWorker) { $psWorker.Dispose() } }
})

# ══════════════════════════════════════════════════════════════════════════════
# DataGrid double-click to apply selected DNS
# ══════════════════════════════════════════════════════════════════════════════
$DnsDataGrid.Add_MouseDoubleClick({
    if ($DnsDataGrid.SelectedItem) {
        $item = $DnsDataGrid.SelectedItem
        Log-Message "Applying DNS: $($item.Name) ($($item.IP))"
        try {
            $psWorker = [PowerShell]::Create().AddScript($benchmarkScript)
            $psWorker.Invoke()
            $psWorker.Commands.Clear()
            $psWorker.AddScript("Set-Dns -Primary '$($item.IP)' -Secondary '' -Category '$($item.Category)'").Invoke()
            Log-Message "Applied $($item.IP)."
        } catch { Log-Message "Error: $_" } finally { if ($psWorker) { $psWorker.Dispose() } }
    }
})

$window.ShowDialog()
