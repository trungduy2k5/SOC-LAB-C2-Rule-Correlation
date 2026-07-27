#File này là file powershell để sinh ra log mô phỏng hành vi, phục vụ cho việc xây dựng và phát triển các quy tắc phát hiện. Trọng tâm của đề tài không nằm ở đây.Chạy file này để sinh log cho các quy tắc DOH,no DNS,Jitter.


$Config = @{
    VictimIP        = "172.25.0.10"
    SplunkIP        = "172.25.0.1"
    AttackerIP      = "172.25.0.20"
    C2_IP           = "45.33.32.156"
    DoHServer1      = "8.8.8.8"
    DoHServer2      = "1.1.1.1"
    SuricataLogDir  = "C:\SuricataLogs"
    SuricataLogFile = "C:\SuricataLogs\eve.json"
}

# ── HELPERS ──────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    $sep = "-" * 65
    Write-Host "`n$sep" -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host "$sep" -ForegroundColor $Color
}
function Write-Step { param([string]$T); Write-Host "[*] $T" -ForegroundColor Yellow }
function Write-OK   { param([string]$T); Write-Host "[+] $T" -ForegroundColor Green  }
function Write-Info { param([string]$T); Write-Host "    $T"  -ForegroundColor Gray   }
function Write-Warn { param([string]$T); Write-Host "[!] $T" -ForegroundColor Red    }

function Write-SuricataLog {
    param([hashtable]$Entry)
    if (-not (Test-Path $Config.SuricataLogDir)) {
        New-Item -ItemType Directory -Path $Config.SuricataLogDir -Force | Out-Null
    }
    $json = $Entry | ConvertTo-Json -Compress -Depth 6
    
    # Cơ chế Retry để né File Lock của Splunk
    $retryCount = 0
    $success = $false
    while (-not $success -and $retryCount -lt 10) {
        try {
            # Thêm ErrorAction Stop để ép try-catch bắt lỗi
            Add-Content -Path $Config.SuricataLogFile -Value $json -Encoding UTF8 -ErrorAction Stop
            $success = $true
        } catch {
            $retryCount++
            Start-Sleep -Milliseconds 150 # Đợi 150ms cho Splunk nhả file ra rồi thử lại
        }
    }
    
    if (-not $success) { 
        Write-Warn "Ghi file thất bại sau 10 lần thử do bị khóa (File Lock)." 
    }
}

# Wait for a Sysmon event to appear (poll Event Log)
function Wait-SysmonEvent {
    param([int]$EventId, [string]$MatchStr, [int]$TimeoutSec = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $ev = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
                           -MaxEvents 30 -ErrorAction SilentlyContinue |
              Where-Object { $_.Id -eq $EventId -and $_.Message -match $MatchStr }
        if ($ev) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# ================================================================
# RULE 1: C2 DNS-over-HTTPS Tunneling
#
# Needs:
#   [A] Suricata TLS log with tls.sni = dns.google / cloudflare-dns.com
#   [B] Sysmon EID 1 - process from abnormal path/parent
#   [C] Sysmon EID 3 - powershell.exe connects to 8.8.8.8:443
#   [D] Sysmon EID 22 - DNS query for dns.google (to correlate ProcessGuid)
#
# Sysmon config alignment:
#   EID1: powershell.exe NOT in exclude list -> will be logged
#   EID3: powershell.exe explicitly in include list -> will be logged
#   EID22: Resolve-DnsName creates real DNS query -> will be logged
#          dns.google NOT in EID22 exclude list -> will be logged
# ================================================================

function Invoke-Rule1 {
    Write-Banner "RULE 1: C2 DNS-over-HTTPS Tunneling" "Magenta"

    # ── [A] Write TLS JSON logs (Suricata) ──────────────────────
    Write-Step "[A] Writing 20 Suricata TLS logs (SNI=dns.google/cloudflare-dns.com)"

    $dohTargets = @(
        @{ sni = "dns.google";         ip = $Config.DoHServer1 },
        @{ sni = "cloudflare-dns.com"; ip = $Config.DoHServer2 }
    )
    $baseTs = Get-Date

    for ($i = 1; $i -le 20; $i++) {
        $t   = $dohTargets[$i % 2]
        $ts  = $baseTs.AddSeconds($i * 3).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $log = @{
            timestamp  = $ts
            flow_id    = [long](Get-Random -Min 100000000 -Max 999999999)
            event_type = "tls"
            src_ip     = $Config.VictimIP
            src_port   = Get-Random -Min 49152 -Max 65535
            dest_ip    = $t.ip
            dest_port  = 443
            proto      = "TCP"
            tls        = @{
                sni         = $t.sni
                version     = "TLS 1.3"
                subject     = "CN=$($t.sni)"
                issuerdn    = "CN=GTS CA 1C3,O=Google Trust Services LLC"
                fingerprint = [System.Guid]::NewGuid().ToString("N")
                ja3         = "769,47-53-5,0-10-11,23-24-25,0"
                ja3s        = "769,47,0"
            }
        }
        Write-SuricataLog -Entry $log
        Write-Info "TLS [$i/20] -> $($t.sni) ($($t.ip):443)"
        Start-Sleep -Milliseconds 80
    }
    Write-OK "20 TLS JSON logs written -> $($Config.SuricataLogFile)"

    # ── [B][C][D] Trigger Sysmon EID 1 + EID 3 + EID 22 via real powershell.exe ──
    # Strategy: Write a .ps1 to C:\Users\Public\ (suspicious location per EID1 analysis)
    # Then launch powershell.exe -File <that script>
    # Result:
    #   EID 1  -> Image=powershell.exe, ParentImage=powershell.exe (this script)
    #             CommandLine contains C:\Users\Public\ -> abnormal
    #   EID 22 -> Resolve-DnsName "dns.google" -> QueryName=dns.google
    #             dns.google is NOT in EID22 exclude list -> LOGGED
    #   EID 3  -> powershell.exe network connect to 8.8.8.8:443
    #             powershell.exe is in EID3 include list -> LOGGED

    Write-Step "[B][C][D] Triggering Sysmon EID 1 + EID 22 + EID 3 via real powershell.exe"

    # Write the child script that will be executed
    $childScript = "C:\Users\Public\doh_sim.ps1"
    $childContent = @'
# Simulate DoH behavior: DNS query then HTTPS connect
# EID 22: Sysmon logs these DNS queries (not in exclude list)
$targets = @("dns.google", "cloudflare-dns.com", "dns.google",
             "cloudflare-dns.com", "dns.google")
foreach ($h in $targets) {
    try { Resolve-DnsName $h -ErrorAction SilentlyContinue | Out-Null } catch {}
    Start-Sleep -Milliseconds 300
}
# EID 3: powershell.exe connects to DoH IPs -> in include list
$dohIPs = @("8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "8.8.8.8")
foreach ($ip in $dohIPs) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $r = $c.BeginConnect($ip, 443, $null, $null)
        $r.AsyncWaitHandle.WaitOne(2000) | Out-Null
        $c.Close()
    } catch {}
    Start-Sleep -Milliseconds 400
}
'@
    Set-Content -Path $childScript -Value $childContent -Encoding ASCII

    # Launch: Parent=powershell.exe (this script), Child=powershell.exe -File C:\Users\Public\...
    # This makes ParentImage=powershell.exe -> ABNORMAL (not explorer/browser)
    # Image path contains C:\Users\Public -> suspicious parent arg
    Write-Info "Launching: powershell.exe -File $childScript"
    $proc = Start-Process -FilePath "powershell.exe" `
                          -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$childScript`"" `
                          -PassThru

    Write-Info "Waiting for Sysmon EID 22 (DNS query for dns.google)..."
    $eid22ok = Wait-SysmonEvent -EventId 22 -MatchStr "dns\.google" -TimeoutSec 20
    if ($eid22ok) {
        Write-OK "Sysmon EID 22 confirmed in Event Log (dns.google)"
    } else {
        Write-Warn "EID 22 not detected in 20s - check Sysmon is running"
    }

    Write-Info "Waiting for Sysmon EID 3 (powershell.exe -> 8.8.8.8:443)..."
    $eid3ok = Wait-SysmonEvent -EventId 3 -MatchStr "8\.8\.8\.8" -TimeoutSec 20
    if ($eid3ok) {
        Write-OK "Sysmon EID 3 confirmed in Event Log (8.8.8.8:443)"
    } else {
        Write-Warn "EID 3 not detected in 20s - check network connectivity"
    }

    $proc | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
#    Remove-Item $childScript -Force -ErrorAction SilentlyContinue
    Write-OK "Rule 1 complete."
}

# ================================================================
# RULE 2: Direct IP Connection Without DNS
#
# Needs:
#   Sysmon EID 3 from process in \Users\, \AppData\Local\Temp\,
#   \Windows\Temp\, \ProgramData\  WITH NO EID 22 from same process
#
# Sysmon config alignment:
#   EID3 include: "begin with C:\Users" -> logged
#   EID3 include: "begin with C:\ProgramData" -> logged
#   EID3 include: "begin with C:\Windows\Temp" -> logged
#   EID3 exclude: dest 127.0.0.1 -> excluded (don't use loopback)
#
# Key insight: Script must be placed IN the suspicious path and
# executed by powershell.exe -File <suspicious_path\script.ps1>
# Then Sysmon logs Image=powershell.exe BUT the CommandLine and
# CurrentDirectory reveal the suspicious path.
# Actually for EID3: Image is the connecting process = powershell.exe
# BUT CurrentDirectory or the spawned script path triggers the alert.
#
# CORRECT approach per config line 273:
#   <Image condition="begin with">C:\Users</Image>
# This means the CONNECTING PROCESS IMAGE must begin with C:\Users.
# So we need a binary that lives in C:\Users\ making the connection.
# powershell.exe lives in C:\Windows\System32 -> does NOT match this.
#
# Solution: Write a small .NET exe via Add-Type, compile to C:\Users\Public\
# OR use mshta.exe / wscript.exe with a script in C:\Users\ path
# BEST: Use "powershell.exe" via WScript from C:\Users\ path so
# CurrentDirectory is in Users AND use port 4444/8080 (in include list)
#
# SIMPLEST that works: copy powershell.exe to C:\Users\Public\ps_sim.exe
# Sysmon sees Image="C:\Users\Public\ps_sim.exe" -> matches "begin with C:\Users"
# ================================================================

function Invoke-Rule2 {
    Write-Banner "RULE 2: Direct IP Connection Without DNS" "Yellow"
    Write-Step "Config insight: EID3 logs 'begin with C:\Users', 'C:\ProgramData', 'C:\Windows\Temp'"
    Write-Step "Strategy: Copy powershell.exe to suspicious paths -> Sysmon sees Image in those paths"

    $sessions = @(
        @{
            SrcDir   = "C:\Users\Public"
            BinName  = "svcupdate.exe"
            DestIP   = $Config.AttackerIP  # ĐÃ SỬA: Dùng IP Attacker thay vì IP Internet
            DestPort = 4444          
            Label    = "C2 Metasploit port"
        },
        @{
            SrcDir   = "C:\Windows\Temp"
            BinName  = "msupdater.exe"
            DestIP   = $Config.AttackerIP  # Giữ nguyên
            DestPort = 8080          
            Label    = "Proxy/C2 port"
        },
        @{
            SrcDir   = "C:\ProgramData"
            BinName  = "wuauclt_helper.exe"
            DestIP   = $Config.AttackerIP  # ĐÃ SỬA: Dùng IP Attacker thay vì IP Internet
            DestPort = 4444          
            Label    = "ProgramData binary - Metasploit port"
        }
    )

    # PowerShell binary path
    $psBin = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    foreach ($s in $sessions) {
        $fakeBin = Join-Path $s.SrcDir $s.BinName

        Write-Step "Session: $fakeBin -> $($s.DestIP):$($s.DestPort) [$($s.Label)]"

        # Copy powershell.exe to suspicious path
        # Sysmon will log Image = C:\Users\Public\svcupdate.exe (matches "begin with C:\Users")
        Copy-Item $psBin $fakeBin -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $fakeBin)) {
            Write-Warn "Cannot copy to $($s.SrcDir) - skipping"
            continue
        }

        # Build a connect command that uses DIRECT IP (no hostname = no DNS = no EID 22)
        # DO NOT use Resolve-DnsName here - that would create EID 22 and break Rule 2 logic
        $connectCmd = @"
try {
    `$c = New-Object System.Net.Sockets.TcpClient
    `$r = `$c.BeginConnect('$($s.DestIP)', $($s.DestPort), `$null, `$null)
    `$r.AsyncWaitHandle.WaitOne(3000) | Out-Null
    `$c.Close()
} catch {}
Start-Sleep -Seconds 1
"@
        # Write connect script to the same suspicious dir
        $connectScript = Join-Path $s.SrcDir "run_$($s.BinName).ps1"
        Set-Content -Path $connectScript -Value $connectCmd -Encoding ASCII

        # Run: Image will be C:\Users\Public\svcupdate.exe (the copied ps.exe)
        # This EXACTLY matches EID3 include rule: begin with C:\Users
        $proc = Start-Process -FilePath $fakeBin `
                      -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$connectCmd`"" `
                      -PassThru

	# 2. Ép script dừng lại chờ tiến trình này chạy xong hẳn (tối đa 5 giây)
	$proc | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue 

	# 3. Tiến trình đã tắt, bây giờ mới quét Event Viewer để tìm log Sysmon EID 3
	Write-Info "Waiting for EID 3 confirmation..."
	$found = Wait-SysmonEvent -EventId 3 -MatchStr $s.DestIP.Replace(".","\.") -TimeoutSec 15
        if ($found) {
            Write-OK "EID 3 confirmed: Image=$fakeBin -> $($s.DestIP):$($s.DestPort)"
            Write-OK "NO EID 22 generated (direct IP, no hostname) -> Rule 2 condition MET"
        } else {
            Write-Warn "EID 3 not confirmed for $($s.DestIP) - verify Sysmon/network"
        }

        $proc | Wait-Process -Timeout 8 -ErrorAction SilentlyContinue
#        Remove-Item $fakeBin      -Force -ErrorAction SilentlyContinue
#        Remove-Item $connectScript -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600
    }

    Write-OK "Rule 2 complete."
}

# ================================================================
# RULE 3: Automated C2 Beaconing - Low Jitter Flow Logs
#
# Needs: Suricata flow logs, >=30 flows, Jitter_Deviation < 10s
# This part is Suricata JSON only, no Sysmon involvement.
# Config is correct, rewritten for clarity.
#
# Jitter math: interval=30s, random jitter 0-400ms
#   stdev of 0..0.4 = ~0.12s  << threshold of 10s -> alert fires
# ================================================================

function Invoke-Rule3 {
    Write-Banner "RULE 3: Automated C2 Beaconing Low Jitter" "Red"
    Write-Step "Writing 35 Suricata flow logs per C2 (interval=30s, jitter<400ms)"
    Write-Info "Jitter stdev ~0.1s << threshold 10s -> Splunk alert will fire"

    $c2List = @(
        @{ ip = $Config.C2_IP;      port = 443;  proto = "TCP"; app = "tls"    },
        @{ ip = $Config.AttackerIP; port = 4444; proto = "TCP"; app = "failed" },
        @{ ip = "104.21.0.50";      port = 8080; proto = "TCP"; app = "http"   }
    )

    foreach ($c2 in $c2List) {
        Write-Step "Beacon: $($Config.VictimIP) -> $($c2.ip):$($c2.port) [$($c2.proto)/$($c2.app)]"

        $baseTime = (Get-Date).AddMinutes(-18)  # backdate so Splunk has history
        $prev     = $baseTime
        $flowBase = [long](Get-Random -Min 100000000000 -Max 999999999999)

        for ($i = 1; $i -le 35; $i++) {
            # Fixed 30s interval + tiny random jitter (0 to 400ms)
            $jitterMs = Get-Random -Min 0 -Max 400
            $t        = $prev.AddSeconds(30).AddMilliseconds($jitterMs)
            $prev     = $t
            $dur      = Get-Random -Min 80 -Max 600

            $log = @{
                timestamp  = $t.ToString("yyyy-MM-ddTHH:mm:ss.fff")
                flow_id    = $flowBase + $i
                event_type = "flow"
                src_ip     = $Config.VictimIP
                src_port   = Get-Random -Min 49152 -Max 65535
                dest_ip    = $c2.ip
                dest_port  = $c2.port
                proto      = $c2.proto
                app_proto  = $c2.app
                flow       = @{
                    pkts_toserver  = Get-Random -Min 3  -Max 8
                    pkts_toclient  = Get-Random -Min 4  -Max 12
                    bytes_toserver = Get-Random -Min 180 -Max 520
                    bytes_toclient = Get-Random -Min 900 -Max 3200
                    start          = $t.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    end            = $t.AddMilliseconds($dur).ToString("yyyy-MM-ddTHH:mm:ss.fff")
                    state          = "closed"
                    reason         = "timeout"
                    alerted        = $false
                }
            }
            Write-SuricataLog -Entry $log
	    Start-Sleep -Milliseconds 30
            if ($i % 7 -eq 0) {
                Write-Info "[$i/35] ts=$($t.ToString('HH:mm:ss')) jitter=${jitterMs}ms"
            }
        }
        Write-OK "35 flows written for $($c2.ip):$($c2.port)"
        Start-Sleep -Milliseconds 150
    }
    Write-OK "Rule 3 complete."
}

# ================================================================
# ENVIRONMENT CHECK
# ================================================================

function Test-Env {
    Write-Banner "ENVIRONMENT CHECK" "Cyan"
    $allOk = $true

    # Check Sysmon service
    $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service "Sysmon" -ErrorAction SilentlyContinue }
    if ($svc -and $svc.Status -eq "Running") {
        Write-OK "Sysmon service : Running ($($svc.Name))"
    } else {
        Write-Warn "Sysmon service : NOT RUNNING"
        $allOk = $false
    }

    # Check Sysmon event log accessible
    try {
        $last = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        Write-OK "Sysmon EventLog: Accessible (last event: EID $($last.Id))"
    } catch {
        Write-Warn "Sysmon EventLog: Cannot read - check permissions"
        $allOk = $false
    }

    # Check Splunk UF
    $uf = Get-Service "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($uf -and $uf.Status -eq "Running") {
        Write-OK "Splunk UF      : Running"
    } else {
        Write-Warn "Splunk UF      : NOT RUNNING - logs won't forward"
        $allOk = $false
    }

    # Create Suricata log dir
    if (-not (Test-Path $Config.SuricataLogDir)) {
        New-Item -ItemType Directory -Path $Config.SuricataLogDir -Force | Out-Null
        Write-OK "Created dir    : $($Config.SuricataLogDir)"
    } else {
        Write-OK "Log dir exists : $($Config.SuricataLogDir)"
    }

    # Check UF inputs.conf monitors the log dir
    $inputsPath = "C:\Program Files\SplunkUniversalForwarder\etc\apps\search\local\inputs.conf"
    if (Test-Path $inputsPath) {
        $inputsContent = Get-Content $inputsPath -Raw -ErrorAction SilentlyContinue
        if ($inputsContent -match "SuricataLogs") {
            Write-OK "UF inputs.conf : SuricataLogs monitored"
        } else {
            Write-Warn "UF inputs.conf : SuricataLogs NOT monitored!"
            Write-Host "" 
            Write-Host "  ADD THIS to $inputsPath :" -ForegroundColor Yellow
            Write-Host "  [monitor://C:\SuricataLogs\]" -ForegroundColor White
            Write-Host "  sourcetype = _json" -ForegroundColor White
            Write-Host "  index = main" -ForegroundColor White
            Write-Host ""
            Write-Host "  Then restart UF:" -ForegroundColor Yellow
            Write-Host '  & "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart' -ForegroundColor White
            Write-Host ""
            $allOk = $false
        }
    } else {
        Write-Warn "UF inputs.conf : Not found at default path"
    }

    # Ping Splunk
    if (Test-Connection $Config.SplunkIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-OK "Splunk reachable: $($Config.SplunkIP)"
    } else {
        Write-Warn "Splunk unreachable: $($Config.SplunkIP)"
    }

    return $allOk
}

function Show-SplunkQueries {
    Write-Banner "VERIFICATION QUERIES FOR SPLUNK" "Green"
    Write-Host ""
    Write-Host "  ---- RULE 1: DoH Tunneling ----" -ForegroundColor Cyan
    Write-Host '  index=* sourcetype=_json event_type="tls"' -ForegroundColor White
    Write-Host '  | stats count by tls.sni, dest_ip' -ForegroundColor White
    Write-Host '  Expect: tls.sni=dns.google and cloudflare-dns.com, count=10 each' -ForegroundColor Gray
    Write-Host ""
    Write-Host '  index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"' -ForegroundColor White
    Write-Host '  (EventCode=1 OR EventCode=3 OR EventCode=22)' -ForegroundColor White
    Write-Host '  | stats count by EventCode, Image' -ForegroundColor White
    Write-Host '  Expect: EID1 + EID3 for powershell.exe, EID22 for dns.google' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ---- RULE 2: Direct IP No DNS ----" -ForegroundColor Cyan
    Write-Host '  index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3' -ForegroundColor White
    Write-Host '  | search Image="C:\\Users\\*" OR Image="C:\\ProgramData\\*" OR Image="C:\\Windows\\Temp\\*"' -ForegroundColor White
    Write-Host '  Expect: svcupdate.exe, msupdater.exe, wuauclt_helper.exe' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ---- RULE 3: Beaconing ----" -ForegroundColor Cyan
    Write-Host '  index=* sourcetype=_json event_type="flow"' -ForegroundColor White
    Write-Host '  | stats count as Flow_Count, values(dest_port) as ports by src_ip, dest_ip' -ForegroundColor White
    Write-Host '  Expect: Flow_Count=35 per C2 destination' -ForegroundColor Gray
    Write-Host ""
}

# ================================================================
# MAIN
# ================================================================

Clear-Host
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "    LAB LOG GENERATOR v2 - Aligned with sysmonconfig.xml" -ForegroundColor Cyan
Write-Host "    Victim: $($Config.VictimIP)   Splunk: $($Config.SplunkIP)" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan

$envOk = Test-Env

if (-not $envOk) {
    Write-Host ""
    Write-Host "  Env issues detected. Continue anyway? (Y/N): " -ForegroundColor Red -NoNewline
    $ans = Read-Host
    if ($ans -notmatch "^[Yy]$") { exit 1 }
}

Write-Host ""
Write-Host "[*] Starting log generation for ALL 3 RULES..." -ForegroundColor Cyan
Write-Host "[*] Each rule will verify Sysmon events in real-time." -ForegroundColor Cyan
Start-Sleep -Seconds 1

Invoke-Rule1
Start-Sleep -Seconds 3

Invoke-Rule2
Start-Sleep -Seconds 3

Invoke-Rule3

# Final summary
Write-Banner "ALL DONE" "Green"
$lineCount = 0
if (Test-Path $Config.SuricataLogFile) {
    $lineCount = (Get-Content $Config.SuricataLogFile | Measure-Object -Line).Lines
}
Write-OK "Suricata JSON logs : $lineCount total lines in $($Config.SuricataLogFile)"
Write-OK "Sysmon events      : Written to Microsoft-Windows-Sysmon/Operational"
Write-OK "Wait 2-3 min then check Splunk for alerts."
Write-Host ""
Show-SplunkQueries


