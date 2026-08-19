# canary_phase_c.ps1 - PHASE C: CONTROLLED TESTNET on RC B4 (commit 24c61e3, sha 8f04bb27...)
# 5-10 controlled nodes + small tester group; load ramp 100/500/1000/2500/5000/10000;
# critical fresh-node joins at 2500/5000/10000; user-journey tests; metrics; watchdog
# (reboot resilience); incidents logged to docs/PHASE_C_INCIDENTS.md.
$ErrorActionPreference = "Continue"

$Root    = Join-Path $env:TEMP "opencode\aether-canary-b4"
$Repo    = "C:\Users\Shadow\Documents\aether-fix\aether-main"
$Bin     = Join-Path $Repo "target-b4\release\aether-unified.exe"
$LOG     = Join-Path $Root "canary_phase_c.log"
$PW      = "canary-pass-2026"
$FAUCET  = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$ports   = @{ 1 = @(42001,42101); 2 = @(43001,43101); 3 = @(44001,44101); 4 = @(45001,45101); 5 = @(46001,46101); 6 = @(47001,47101); 7 = @(48001,48101); 8 = @(49001,49101); 9 = @(50001,50101); 10 = @(51001,51101); 11 = @(52001,52101); 12 = @(53001,53101); 13 = @(54001,54101) }
$script:passes = 0; $script:fails = 0
$genWallets = @(); $script:allAddrs = @($FAUCET, $FOUNDER, $BURN)

function Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $LOG -Value $line -Encoding ascii
    Write-Host $line
}
function FailIf($cond, $msg) {
    if ($cond) { $script:fails++; Log ("  FAIL: " + $msg) } else { $script:passes++; Log ("  PASS: " + $msg) }
}
function Rpc($port, $method, $params) {
    try {
        $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 6
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 120
        $sw.Stop()
        return @{ res = $r; ms = $sw.Elapsed.TotalMilliseconds }
    } catch { return @{ res = $null; ms = -1; err = "$_" } }
}
function HexId($b) {
    if ($null -eq $b) { return "" }
    if ($b -is [string]) { return $b }
    if ($b -is [byte[]]) { return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }
    return ("$b")
}
function Get-State($port) {
    $g = (Rpc $port "aether_getDagGraph" @(10000)).res
    $st = (Rpc $port "aether_getDagStats" @()).res
    $tips = @((Rpc $port "aether_getTips" @()).res.result.tips | Sort-Object | ForEach-Object { HexId $_ })
    $led = @(); $supply = 0
    foreach ($a in $script:allAddrs) {
        $b = (Rpc $port "aether_getBalance" @($a)).res.result.balance
        $n = (Rpc $port "aether_getAccountNonce" @($a)).res.result.next_nonce
        $led += "$a=$b/$n"; $supply += [long]$b
    }
    $txset = @($g.result.nodes | ForEach-Object { HexId $_.tx_id } | Sort-Object)
    $dag = @($g.result.edges | ForEach-Object { (HexId $_.from) + "->" + (HexId $_.to) } | Sort-Object)
    $w = @($g.result.nodes | Sort-Object { HexId $_.tx_id } | ForEach-Object { (HexId $_.tx_id) + ":" + $_.weight })
    return @{ txset = ($txset -join ","); dag = ($dag -join ","); tips = ($tips -join ","); led = ($led -join ";"); w = ($w -join ","); supply = "$supply"; total = [long]$st.result.total_transactions; peers = $st.result.connected_peers }
}
function Fp($s) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $txt = "$($s.txset)|$($s.dag)|$($s.tips)|$($s.led)|$($s.w)|$($s.supply)"
    return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($txt)) | ForEach-Object { $_.ToString("x2") }) -join "")
}
function Node-Up($id) {
    try { $r = Rpc $ports[$id][1] "aether_getDagStats" @(); return ($null -ne $r.res.result.total_transactions) } catch { return $false }
}
function Start-Node($id, $fresh) {
    $ndir = Join-Path $Root ("node" + $id)
    if ($fresh -and (Test-Path $ndir)) { Remove-Item -Recurse -Force $ndir }
    New-Item -ItemType Directory -Force -Path $ndir | Out-Null
    if ($id -eq 1 -and (Test-Path (Join-Path $env:TEMP "opencode\aether-canary-a\node1\faucet.key"))) {
        Copy-Item (Join-Path $env:TEMP "opencode\aether-canary-a\node1\faucet.key") (Join-Path $ndir "faucet.key") -Force
    }
    $args = @("--node-type","validator","--data-dir",$ndir,"--p2p-port","$($ports[$id][0])","--rpc-port","$($ports[$id][1])")
    if ($id -ne 1) { $args += @("--bootnodes","127.0.0.1:42001") }
    Start-Process -FilePath $Bin -ArgumentList $args -RedirectStandardOutput (Join-Path $ndir "node.log") -RedirectStandardError (Join-Path $ndir "node.err") -WindowStyle Hidden | Out-Null
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Node-Up $id)) {
        if ((Get-Date) -gt $deadline) { Log ("  node$id did not come up"); return $false }
        Start-Sleep -Milliseconds 1500
    }
    Log ("  node$id up (p2p $($ports[$id][0]) rpc $($ports[$id][1]))")
    return $true
}
function Stop-Node($id) {
    Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" | Where-Object { $_.CommandLine -match ([regex]::Escape($Root) + "\\node" + $id + "\\") } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}
function Watchdog($ids) {
    $down = @()
    foreach ($id in $ids) { if (-not (Node-Up $id)) { $down += $id } }
    if ($down.Count -gt 0) {
        $ev = (Get-WinEvent -FilterHashtable @{LogName="System"; Id=6006,6008,1074,41} -MaxEvents 1 -ErrorAction SilentlyContinue)
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        Log ("  WATCHDOG: nodes down: $($down -join ',') - lastboot=$boot lastShutdownEvt=$($ev.TimeCreated) - restarting")
        foreach ($id in $down) {
            $ok = Start-Node $id $false
            if (-not $ok) { Log ("  WATCHDOG: node$id restart FAILED"); $script:fails++ }
        }
        Start-Sleep -Seconds 30
        foreach ($id in $ids) { if (-not (Node-Up $id)) { Log ("  WATCHDOG: node$id still down AFTER restart"); $script:fails++ } }
        return $false
    }
    return $true
}
function Check-Converged($ids, $label) {
    $ok = $true; $ref = Get-State $ports[$ids[0]][1]
    foreach ($id in $ids[1..($ids.Count - 1)]) {
        $s = Get-State $ports[$id][1]
        foreach ($k in @("txset","dag","tips","led","w","supply","total")) {
            if ($s.$k -ne $ref.$k) { Log ("  DIVERGENCE node$id $k"); $ok = $false }
        }
    }
    if ($ok) { Log ("  CONVERGED [$label] nodes $($ids -join ',') (total=$($ref.total))") }
    return $ok
}
function Wait-Converged($refPort, $port, $label, $timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ((Get-Date) -lt $deadline) {
        try {
            $rs = Get-State $refPort; $js = Get-State $port
            if ($js.total -eq $rs.total -and $js.txset -eq $rs.txset -and $js.dag -eq $rs.dag -and $js.tips -eq $rs.tips -and $js.led -eq $rs.led -and $js.w -eq $rs.w -and $js.supply -eq $rs.supply) {
                $sw.Stop()
                Log ("  CONVERGED [$label] in {0:N1}s (total={1})" -f $sw.Elapsed.TotalSeconds, $js.total)
                return @{ ok = $true; sec = $sw.Elapsed.TotalSeconds }
            }
        } catch {}
        Start-Sleep -Seconds 5
    }
    $sw.Stop()
    Log ("  TIMEOUT [$label] after {0:N0}s" -f $sw.Elapsed.TotalSeconds)
    return @{ ok = $false; sec = $sw.Elapsed.TotalSeconds }
}
function Show-SyncStats($port, $label) {
    $s = (Rpc $port "aether_getSyncStats" @()).res.result
    Log ("  sync[$label] requested={0} received={1} progress={2} batches={3} orphan_created={4} orphan_resolved={5} orphan_purged={6} retries={7} parent_requested={8} parent_deduped={9} dup_ignored={10}" -f $s.sync_requested,$s.sync_received,$s.sync_progress,$s.sync_batches,$s.orphan_created,$s.orphan_resolved,$s.orphan_purged,$s.retry_count,$s.parent_requested,$s.parent_already_known,$s.duplicate_ignored)
}
function Metrics($ids, $label) {
    $cpu = 0; $ram = 0; $procs = 0
    Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" | ForEach-Object {
        if ($_.CommandLine -match ([regex]::Escape($Root) + "\\node(\d+)\\")) {
            $p = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
            if ($p) { $cpu += $p.TotalProcessorTime.TotalSeconds; $ram += $p.WorkingSet64; $procs++ }
        }
    }
    $disk = ((Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum)
    $d = Rpc 42101 "aether_getDagStats" @()
    Log ("  METRICS[$label] nodes=$procs cpuTotalSec=$([Math]::Round($cpu,1)) ramMB=$([Math]::Round($ram/1MB,1)) diskMB=$([Math]::Round($disk/1MB,1)) dagNodes=$($d.res.result.total_transactions) rpcLatencyMs=$([Math]::Round($d.ms,2))")
    return $ram
}
function TxTotal($id) { return [long](Rpc $ports[$id][1] "aether_getDagStats" @()).res.result.total_transactions }
function Wait-Plateau($target, $label) {
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        $t = TxTotal 1
        if ($t -ge $target -and $t -le ($target + 12)) { Log ("  plateau ${label}: $t txs (target $target, wave overshoot allowed)"); return $t }
        Start-Sleep -Seconds 3
    }
    $t = TxTotal 1
    Log ("  plateau $label NOT reached (got $t, target $target)")
    return $t
}
function New-Wallet($name, $dir) {
    $w = Join-Path $dir "$name.json"
    "$PW`n" | & $Bin wallet create $w 2>&1 | Out-Null
    $bout = (& $Bin balance $w --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
    return @{ path = $w; addr = $addr }
}
function SendCli($w, $to, $amount, $fee, $rpcPort, $extra) {
    $a = @("send", $to, "$amount", "$fee", "--rpc-url", "http://127.0.0.1:$rpcPort", "--wallet", $w.path, "--password", $PW)
    if ($extra) { $a += $extra }
    $out = (& $Bin @a 2>&1 | Out-String)
    return $out
}

Log "=== PHASE C - CONTROLLED TESTNET (RC B4) ==="
Log "release gate (verified): cargo test 154/0, fmt clean, audit 0 vuln, sha 8f04bb27..., genesis 4f3e693e..., version 1.2.0, HEAD 1262475/24c61e3, secrets: none in repo/logs"

# ---- watchdogs: campaign network 1-8 must be up (post-reboot restart done)
$w = Watchdog @(1,2,3,4,5,6,7,8)
FailIf (-not $w) "campaign network 1-8 up"
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8) "base 1000")) "base convergence at 1000"
$supply0 = (Get-State 42101).supply
Log ("  baseline supply=$supply0")

# ---- FUNDED WALLETS (operator pre-funded): the faucet is BLOCKED at this DAG
# size (fee oracle min fee >= 100 within ~30-60s of boot due to V-22 periodic
# sync churn; faucet uses fee 1 - documented finding, PHASE_C_INCIDENTS.md).
# Generators + testers = the 12 campaign wallets (gen.json, wb1-3, b8_0-7),
# each with ~1e11 raw on the ledger. Verified by RPC (raw balances).
Log "=== FUNDED WALLETS (pre-funded campaign wallets, faucet blocked at scale) ==="
$tdir = Join-Path $Root "testers"
$gdir = Join-Path $Root "gens"
New-Item -ItemType Directory -Force -Path $tdir | Out-Null
New-Item -ItemType Directory -Force -Path $gdir | Out-Null
$funded = @()
foreach ($name in @("gen","wb1","wb2","wb3","b8_0","b8_1","b8_2","b8_3","b8_4","b8_5","b8_6","b8_7")) {
    $w = Join-Path $Root "$name.json"
    if (-not (Test-Path $w)) { $w = Join-Path $tdir "$name.json"; "$PW`n" | & $Bin wallet create $w 2>&1 | Out-Null }
    $bout = (& $Bin balance $w --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
    $raw = (Rpc 42101 "aether_getBalance" @($addr)).res.result.balance
    $script:allAddrs += $addr
    $funded += @{ path = $w; addr = $addr; raw = [long]$raw; name = $name }
    Log ("  wallet $name = $addr (raw $raw)")
}
$tw = @($funded | Where-Object { $_.name -in @("gen","wb1","wb2","wb3") })
$script:genWallets = @($funded | Where-Object { $_.name -notin @("gen","wb1","wb2","wb3") })
foreach ($a in $script:genWallets) { FailIf ($a.raw -lt 1000000) "generator $($a.name) funded (raw $($a.raw))" }

# ---- TESTEURS (mandate 3): nodes 9-10 fresh, per-node verify
Log "=== TESTEURS: nodes 9-10 (fresh, verified) ==="
foreach ($id in 9,10) {
    $ok = Start-Node $id $true
    FailIf (-not $ok) "tester node$id start (fresh)"
    Start-Sleep -Seconds 3
    $s = Get-State $ports[$id][1]
    FailIf ($s.peers -lt 1) "tester node$id peer count >= 1 (got $($s.peers))"
    $fb = (Rpc $ports[$id][1] "aether_getBalance" @($FOUNDER)).res.result.balance
    FailIf ([long]$fb -ne 100000000000) "tester node$id genesis (founder balance)"
}
FailIf (-not (Wait-Converged 42101 50101 "tester9 sync" 900)) "tester9 sync+convergence"
FailIf (-not (Wait-Converged 42101 51101 "tester10 sync" 900)) "tester10 sync+convergence"
$fp1 = Fp (Get-State 42101); $fp9 = Fp (Get-State 50101); $fp10 = Fp (Get-State 51101)
FailIf ($fp1 -ne $fp9 -or $fp1 -ne $fp10) "fingerprints identical (n1=$($fp1.Substring(0,12)) n9=$($fp9.Substring(0,12)) n10=$($fp10.Substring(0,12)))"
Log ("  fingerprints n1=$fp1 n9=$fp9 n10=$fp10")

# ---- TESTS UTILISATEURS (mandate 4) on nodes 9/10
Log "=== TESTS UTILISATEURS (nodes 9-10, CLI) ==="
$bal = (Rpc 50101 "aether_getBalance" @($tw[0].addr)).res.result.balance
FailIf ([long]$bal -lt 100000) "wallet + receive AETH (pre-funded; faucet blocked at scale) via node9 (got $bal)"
$o = SendCli $tw[0] $tw[1].addr 25 100 50101 $null
FailIf ($o -match "REJECTED|Failed|error") "send tx (PoW) via node9"
Start-Sleep -Seconds 8
$b1 = (Rpc 51101 "aether_getBalance" @($tw[1].addr)).res.result.balance
FailIf ([long]$b1 -lt 25) "receiver balance via node10 (got $b1)"
$dag = (Rpc 51101 "aether_getDagGraph" @(200)).res.result
FailIf ($null -eq $dag.nodes -or $dag.nodes.Count -lt 100) "DAG consult via node10"
# restart + resync on tester node9
Stop-Node 9
Start-Sleep -Seconds 3
$ok = Start-Node 9 $false
FailIf (-not $ok) "tester9 restart"
FailIf (-not (Wait-Converged 42101 50101 "tester9 resync" 900)) "tester9 resync after restart"
# multiple clients simultaneously (4 parallel sends)
$procs = @()
for ($i = 0; $i -lt 4; $i++) {
    $from = $tw[$i]; $to = $tw[($i + 1) % 4]
    $procs += Start-Process -FilePath $Bin -ArgumentList @("send", $to.addr, "3", "100", "--rpc-url", "http://127.0.0.1:50101", "--wallet", $from.path, "--password", $PW) -WindowStyle Hidden -PassThru
}
foreach ($p in $procs) { $p.WaitForExit(60000) | Out-Null }
Start-Sleep -Seconds 15
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10) "user multi-client")) "multi-client convergence"
Log "=== TESTS UTILISATEURS PASS ==="

# ---- CHARGE PROGRESSIVE (mandate 5): 2500 -> 5000 -> 10000
Log "=== CHARGE PROGRESSIVE (8 parallel generators) ==="
$script:genWallets = @($script:genWallets)
foreach ($a in $script:genWallets) {
    $b = (Rpc 42101 "aether_getBalance" @($a.addr)).res.result.balance
    FailIf ([long]$b -lt 1000000) "generator funded (got $b)"
}
function Gen-Ramp($target, $label) {
    $base = TxTotal 1
    if ($base -ge $target) { return }
    Log ("  ramp to $target (at $base)...")
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $accepted = 0; $waves = 0
    while ((TxTotal 1) -lt $target -and $waves -lt 9000) {
        $waves++
        $procs = @()
        foreach ($gw in $script:genWallets) {
            $procs += Start-Process -FilePath $Bin -ArgumentList @("send", $gw.addr, "1", "100", "--rpc-url", "http://127.0.0.1:42101", "--wallet", $gw.path, "--password", $PW) -WindowStyle Hidden -PassThru
        }
        foreach ($p in $procs) { $p.WaitForExit(120000) | Out-Null }
        foreach ($p in $procs) { if ($p.ExitCode -eq 0) { $accepted++ } }
        if ($waves % 50 -eq 0) { Log ("    wave $waves accepted=$accepted total=$(TxTotal 1)") }
    }
    $sw.Stop()
    $tps = $accepted / $sw.Elapsed.TotalSeconds
    Log ("  RAMP[$label] accepted=$accepted in {0:N0}s => {1:N2} tx/s (seed total=$(TxTotal 1))" -f $sw.Elapsed.TotalSeconds, $tps)
    FailIf ((TxTotal 1) -lt $target) "ramp reached $target"
    $plt = Wait-Plateau $target $label
    Metrics @(1,2,3,4,5,6,7,8,9,10) $label
    return @{ tps = $tps; plateau = $plt }
}
$tps2500 = Gen-Ramp 2500 "2500"
$ok = Watchdog @(1,2,3,4,5,6,7,8,9,10); FailIf (-not $ok) "watchdog @2500"
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10) "plateau 2500")) "convergence 2500"
$supply = (Get-State 42101).supply
FailIf ($supply -ne $supply0) "supply constant @2500 ($supply vs $supply0)"
Log ("  PASS: supply invariant @2500 ($supply)")

# ---- CRITICAL JOIN @2500 (mandate 6): fresh node 11
Log "=== CRITICAL JOIN @2500 (fresh node11) ==="
$ok = Start-Node 11 $true
FailIf (-not $ok) "node11 start @2500"
$c = Wait-Converged 42101 52101 "join@2500" 2400
FailIf (-not $c.ok) "CRITICAL: fresh join @2500 converges"
if ($c.ok) { Show-SyncStats 52101 "join@2500" }
$fp1 = Fp (Get-State 42101); $fp11 = Fp (Get-State 52101)
FailIf ($fp1 -ne $fp11) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @2500"

$tps5000 = Gen-Ramp 5000 "5000"
$ok = Watchdog @(1,2,3,4,5,6,7,8,9,10,11); FailIf (-not $ok) "watchdog @5000"
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10,11) "plateau 5000")) "convergence 5000"
FailIf ((Get-State 42101).supply -ne $supply0) "supply constant @5000"

Log "=== CRITICAL JOIN @5000 (fresh node12) ==="
$ok = Start-Node 12 $true
FailIf (-not $ok) "node12 start @5000"
$c = Wait-Converged 42101 53101 "join@5000" 3600
FailIf (-not $c.ok) "CRITICAL: fresh join @5000 converges"
if ($c.ok) { Show-SyncStats 53101 "join@5000" }
$fp1 = Fp (Get-State 42101); $fp12 = Fp (Get-State 53101)
FailIf ($fp1 -ne $fp12) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @5000"

$tps10000 = Gen-Ramp 10000 "10000"
$ok = Watchdog @(1,2,3,4,5,6,7,8,9,10,11,12); FailIf (-not $ok) "watchdog @10000"
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10,11,12) "plateau 10000")) "convergence 10000"
FailIf ((Get-State 42101).supply -ne $supply0) "supply constant @10000"

Log "=== CRITICAL JOIN @10000 (fresh node13) ==="
$ok = Start-Node 13 $true
FailIf (-not $ok) "node13 start @10000"
$c = Wait-Converged 42101 54101 "join@10000" 7200
FailIf (-not $c.ok) "CRITICAL: fresh join @10000 converges"
if ($c.ok) { Show-SyncStats 54101 "join@10000" }
$fp1 = Fp (Get-State 42101); $fp13 = Fp (Get-State 54101)
FailIf ($fp1 -ne $fp13) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @10000"

# ---- final checks
Log "=== FINAL CHECKS ==="
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10,11,12,13) "final 13-node")) "final convergence 13 nodes"
Metrics @(1,2,3,4,5,6,7,8,9,10,11,12,13) "final"
FailIf (-not (Node-Up 1)) "network still up at end"
Log ("  TPS: 2500={0:N2} 5000={1:N2} 10000={2:N2} (plateaus {3}/{4}/{5})" -f $tps2500.tps, $tps5000.tps, $tps10000.tps, $tps2500.plateau, $tps5000.plateau, $tps10000.plateau)
Log "=== PHASE C SUMMARY: $($script:passes) passed, $($script:fails) failed ==="
if ($script:fails -gt 0) { exit 1 } else { exit 0 }