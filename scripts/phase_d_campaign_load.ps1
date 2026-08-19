# phase_d_campaign_load.ps1 - PHASE D: load campaign on the new RC (commit d5051ed,
# sha 5cf6a204...). Stages:
#   A  ramp 1100 (CRITICAL Phase C non-regression) + plateau + convergence + mempool stats
#   B  critical fresh join @1100 (node9)
#   C  ramp 2500 + critical join @2500 (node10)
#   D  ramp 5000 + critical join @5000 (node11) + optional ramp 10000 + join (node12)
#   E  faucet under load + final convergence + summary
param([string]$Stage = "A")
$ErrorActionPreference = "Continue"

$Root    = Join-Path $env:TEMP "opencode\aether-canary-phase-d"
$Repo    = "C:\Users\Shadow\Documents\aether-fix\aether-main"
$Bin     = Join-Path $Repo "target\release\aether.exe"
$LOG     = Join-Path $Root "phase_d_campaign.log"
$PW      = "canary-pass-2026"
$FAUCET  = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$ports   = @{ 1 = @(42001,42101); 2 = @(43001,43101); 3 = @(44001,44101); 4 = @(45001,45101); 5 = @(46001,46101); 6 = @(47001,47101); 7 = @(48001,48101); 8 = @(49001,49101); 9 = @(49002,49102); 10 = @(49003,49103); 11 = @(49004,49104); 12 = @(49005,49105); 13 = @(49006,49106) }
$script:passes = 0; $script:fails = 0
$script:allAddrs = @($FAUCET, $FOUNDER, $BURN)

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
    $g = (Rpc $port "aether_getDagGraph" @(100000)).res
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
function Watchdog($ids) {
    $down = @()
    foreach ($id in $ids) { if (-not (Node-Up $id)) { $down += $id } }
    if ($down.Count -gt 0) {
        Log ("  WATCHDOG: nodes down: $($down -join ',') - restarting")
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
    Get-CimInstance Win32_Process -Filter "Name='aether.exe'" | ForEach-Object {
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
function Mempool-Stats($label) {
    $r = (Rpc 42101 "aether_getMempoolStats" @()).res.result
    Log ("  MEMPOOL[$label] size={0}/{1} min_fee={2} added={3} removed={4} included={5} rejected={6} expired={7} dup={8} orphan={9} resolved={10}" -f $r.size,$r.max_size,$r.min_fee,$r.added,$r.removed,$r.included,$r.rejected,$r.expired,$r.duplicate,$r.orphan_parked,$r.orphan_resolved)
    return $r
}
function Gen-Ramp($target, $label) {
    $base = TxTotal 1
    if ($base -ge $target) { return $null }
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
        if ($waves % 25 -eq 0) { Log ("    wave $waves accepted=$accepted total=$(TxTotal 1)") }
    }
    $sw.Stop()
    $tps = $accepted / $sw.Elapsed.TotalSeconds
    Log ("  RAMP[$label] accepted=$accepted in {0:N0}s => {1:N2} tx/s (seed total=$(TxTotal 1))" -f $sw.Elapsed.TotalSeconds, $tps)
    FailIf ((TxTotal 1) -lt $target) "ramp reached $target"
    $plt = Wait-Plateau $target $label
    return @{ tps = $tps; plateau = $plt }
}
function Zero-Emission {
    # No-minting / no-destruction invariant: the sum of balances over the
    # faucet, the founder, the 12 campaign wallets AND the burn address must
    # equal the genesis allocation EXACTLY (fees relocate to the burn address;
    # nothing is created or destroyed). DELTA 0 => PASS.
    $genesis = [decimal]1000000100000000000
    $all = [decimal]0
    foreach ($a in $script:funded) { $all += [decimal](Rpc 42101 "aether_getBalance" @($a.addr)).res.result.balance }
    foreach ($a in @($FAUCET, $FOUNDER, $BURN)) {
        $all += [decimal](Rpc 42101 "aether_getBalance" @($a)).res.result.balance
    }
    $delta = $all - $genesis
    FailIf ($delta -ne 0) "zero-emission invariant (all addrs sum=$all genesis=$genesis delta=$delta)"
    Log ("  supply(all addrs)=$all genesis=$genesis delta=$delta")
    return $delta
}
function Funded-Wallets {
    $tdir = Join-Path $Root "testers"
    New-Item -ItemType Directory -Force -Path $tdir | Out-Null
    $script:funded = @()
    foreach ($name in @("gen","wb1","wb2","wb3","b8_0","b8_1","b8_2","b8_3","b8_4","b8_5","b8_6","b8_7")) {
        $w = Join-Path (Join-Path $env:TEMP "opencode\aether-canary-b4") "$name.json"
        $bout = (& $Bin balance $w --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
        $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
        $raw = (Rpc 42101 "aether_getBalance" @($addr)).res.result.balance
        $script:funded += @{ path = $w; addr = $addr; raw = [long]$raw; name = $name }
    }
    $script:genWallets = @($script:funded | Where-Object { $_.name -notin @("gen","wb1","wb2","wb3") })
    foreach ($a in $script:genWallets) { FailIf ($a.raw -lt 1000000) "generator $($a.name) funded (raw $($a.raw))" }
}

# =====================================================================
Log "=== PHASE D CAMPAIGN - stage $Stage (new RC d5051ed, sha 5cf6a204...) ==="

if ($Stage -eq "A") {
    Log "=== STAGE A: ramp 1100 (CRITICAL Phase C non-regression) ==="
    $w = Watchdog @(1,2,3,4,5,6,7,8)
    FailIf (-not $w) "campaign network 1-8 up"
    FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8) "base 0")) "base convergence at 0"
    $supply0 = (Get-State 42101).supply
    Log ("  baseline supply=$supply0")
    Funded-Wallets
    $r1100 = Gen-Ramp 1100 "1100"
    $ok = Watchdog @(1,2,3,4,5,6,7,8); FailIf (-not $ok) "watchdog @1100"
    FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8) "plateau 1100")) "convergence 1100"
    Zero-Emission
    $ms = Mempool-Stats "after1100"
    FailIf ([long]$ms.size -gt 50) "mempool drained after 1100 (size=$($ms.size))"
    FailIf ([long]$ms.included -lt [long]$ms.added - 20) "drain conservation: included>=added-20 (included=$($ms.included) added=$($ms.added))"
    Metrics @(1,2,3,4,5,6,7,8) "after1100"
    Log "=== STAGE A DONE: $($script:passes) passed, $($script:fails) failed ==="
}

if ($Stage -eq "B") {
    Log "=== STAGE B: CRITICAL JOIN @1100 (fresh node9) ==="
    $ok = Start-Node 9 $true
    FailIf (-not $ok) "node9 start @1100"
    $c = Wait-Converged 42101 49102 "join@1100" 1200
    FailIf (-not $c.ok) "CRITICAL: fresh join @1100 converges"
    if ($c.ok) { Show-SyncStats 49102 "join@1100" }
    $fp1 = Fp (Get-State 42101); $fp9 = Fp (Get-State 49102)
    FailIf ($fp1 -ne $fp9) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @1100"
    Metrics @(1,2,3,4,5,6,7,8,9) "afterjoin1100"
    Log "=== STAGE B DONE: $($script:passes) passed, $($script:fails) failed ==="
}

if ($Stage -eq "C") {
    Log "=== STAGE C: ramp 2500 + CRITICAL JOIN @2500 (fresh node10) ==="
    $r2500 = Gen-Ramp 2500 "2500"
    $ok = Watchdog @(1,2,3,4,5,6,7,8,9); FailIf (-not $ok) "watchdog @2500"
    FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9) "plateau 2500")) "convergence 2500"
    $ms = Mempool-Stats "after2500"
    FailIf ([long]$ms.size -gt 50) "mempool drained after 2500 (size=$($ms.size))"
    $ok = Start-Node 10 $true
    FailIf (-not $ok) "node10 start @2500"
    $c = Wait-Converged 42101 49103 "join@2500" 2400
    FailIf (-not $c.ok) "CRITICAL: fresh join @2500 converges"
    if ($c.ok) { Show-SyncStats 49103 "join@2500" }
    $fp1 = Fp (Get-State 42101); $fp10 = Fp (Get-State 49103)
    FailIf ($fp1 -ne $fp10) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @2500"
    Metrics @(1,2,3,4,5,6,7,8,9,10) "afterjoin2500"
    Log "=== STAGE C DONE: $($script:passes) passed, $($script:fails) failed ==="
}

if ($Stage -eq "D") {
    Log "=== STAGE D: ramp 5000 + CRITICAL JOIN @5000 (fresh node11) ==="
    $r5000 = Gen-Ramp 5000 "5000"
    $ok = Watchdog @(1,2,3,4,5,6,7,8,9,10); FailIf (-not $ok) "watchdog @5000"
    FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10) "plateau 5000")) "convergence 5000"
    $ms = Mempool-Stats "after5000"
    FailIf ([long]$ms.size -gt 50) "mempool drained after 5000 (size=$($ms.size))"
    $ok = Start-Node 11 $true
    FailIf (-not $ok) "node11 start @5000"
    $c = Wait-Converged 42101 49104 "join@5000" 3600
    FailIf (-not $c.ok) "CRITICAL: fresh join @5000 converges"
    if ($c.ok) { Show-SyncStats 49104 "join@5000" }
    $fp1 = Fp (Get-State 42101); $fp11 = Fp (Get-State 49104)
    FailIf ($fp1 -ne $fp11) "h_txset/h_dag/h_tips/h_ledger/h_weights identical @5000"
    Metrics @(1,2,3,4,5,6,7,8,9,10,11) "afterjoin5000"
    Log "=== STAGE D DONE: $($script:passes) passed, $($script:fails) failed ==="
}

if ($Stage -eq "E") {
    Log "=== STAGE E: faucet under load + final checks ==="
    $faucetAddr = "1111111111111111111111111111111111111111111111111111111111111111"
    $f0 = (Rpc 42101 "aether_getBalance" @($faucetAddr)).res.result.balance
    $fr = (Rpc 42101 "aether_faucet" @($faucetAddr))
    FailIf ($null -eq $fr.res -or $null -ne $fr.res.error) "faucet tx accepted under load at 5000+"
    Start-Sleep -Seconds 5
    $f1 = (Rpc 42101 "aether_getBalance" @($faucetAddr)).res.result.balance
    FailIf ([long]$f1 - [long]$f0 -lt 100000000000) "faucet funds received under load (delta $([long]$f1-[long]$f0))"
    FailIf (-not (Watchdog @(1,2,3,4,5,6,7,8,9,10,11))) "final watchdog"
    FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8,9,10,11) "final 11-node")) "final convergence 11 nodes"
    $ms = Mempool-Stats "final"
    FailIf ([long]$ms.size -gt 50) "mempool drained at end (size=$($ms.size))"
    Metrics @(1,2,3,4,5,6,7,8,9,10,11) "final"
    Log "=== STAGE E DONE: $($script:passes) passed, $($script:fails) failed ==="
}

if ($script:fails -gt 0) { exit 1 } else { exit 0 }