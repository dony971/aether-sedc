# canary_b4_campaign.ps1 - CANARY CAMPAIGN Phase A -> B on RC B4 (commit 24c61e3)
# Priority: B4 fresh-node cold-start joins at 463 (MUST PASS), 500, 1000.
# New network on RC binary 8f04bb27..., fresh dirs, ports 42001-46101 (nodes
# 1-5) + 47001-49001 (joiners 6-8). Frozen network stopped beforehand.
# Consensus untouched (gates verify src diff = B4 fix files only).
$ErrorActionPreference = "Stop"

$Root    = Join-Path $env:TEMP "opencode\aether-canary-b4"
$Repo    = "C:\Users\Shadow\Documents\aether-fix\aether-main"
$Bin     = Join-Path $Repo "target-b4\release\aether-unified.exe"
$FROZEN  = "b1b8376d6adbbf3607e57b7ab1ab198c12e3902f"
$RC_SHA  = "8f04bb278aed4fd11fc76f839dcadc58df8b1af97ee13db0b9fb620d9c5587ff"
$LOG     = Join-Path $Root "canary_b4_campaign.log"
$PW      = "canary-pass-2026"
$FAUCET  = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$GENHASH = "4f3e693ee56a224dec556f1c05a7c2f4383b2ba8334368ae5d25ba48991d9f8f"
$ports   = @{ 1 = @(42001,42101); 2 = @(43001,43101); 3 = @(44001,44101); 4 = @(45001,45101); 5 = @(46001,46101); 6 = @(47001,47101); 7 = @(48001,48101); 8 = @(49001,49101) }
$script:passes = 0; $script:fails = 0

function Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $LOG -Value $line -Encoding ascii
    Write-Host $line
}
function FailIf($cond, $msg) {
    if ($cond) { $script:fails++; Log ("  FAIL: " + $msg) } else { $script:passes++; Log ("  PASS: " + $msg) }
}
function Rpc($port, $method, $params) {
    $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 6
    Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 90
}
function HexId($b) {
    if ($null -eq $b) { return "" }
    if ($b -is [string]) { return $b }
    if ($b -is [byte[]]) { return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }
    return ("$b")
}
function Get-State($port) {
    $g = (Rpc $port "aether_getDagGraph" @(10000)).result
    $st = (Rpc $port "aether_getDagStats" @()).result
    $tips = @((Rpc $port "aether_getTips" @()).result.tips | Sort-Object | ForEach-Object { HexId $_ })
    $led = @(); $supply = 0
    foreach ($a in @($FAUCET, $FOUNDER, $BURN)) {
        $b = (Rpc $port "aether_getBalance" @($a)).result.balance
        $n = (Rpc $port "aether_getAccountNonce" @($a)).result.next_nonce
        $led += "$a=$b/$n"; $supply += [long]$b
    }
    $txset = @($g.nodes | ForEach-Object { HexId $_.tx_id } | Sort-Object)
    $dag = @($g.edges | ForEach-Object { (HexId $_.from) + "->" + (HexId $_.to) } | Sort-Object)
    $w = @($g.nodes | Sort-Object { HexId $_.tx_id } | ForEach-Object { (HexId $_.tx_id) + ":" + $_.weight })
    return @{ txset = ($txset -join ","); dag = ($dag -join ","); tips = ($tips -join ","); led = ($led -join ";"); w = ($w -join ","); supply = "$supply"; total = [long]$st.total_transactions }
}
function Node-Rpc-Up($port) {
    try { $r = Rpc $port "aether_getDagStats" @(); if ($null -ne $r.result.total_transactions) { return $true } } catch {}
    return $false
}
function Start-Node($id, $fresh) {
    $ndir = Join-Path $Root ("node" + $id)
    if ($fresh -and (Test-Path $ndir)) { Remove-Item -Recurse -Force $ndir }
    New-Item -ItemType Directory -Force -Path $ndir | Out-Null
    if ($id -eq 1 -and (Test-Path (Join-Path $env:TEMP "opencode\aether-canary-a\node1\faucet.key"))) {
        Copy-Item (Join-Path $env:TEMP "opencode\aether-canary-a\node1\faucet.key") (Join-Path $ndir "faucet.key") -Force
        Log ("  faucet.key deployed to node1")
    }
    $p2p = $ports[$id][0]; $rpc = $ports[$id][1]
    $nargs = @("--node-type","validator","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc")
    if ($id -ne 1) { $nargs += @("--bootnodes","127.0.0.1:42001") }
    $p = Start-Process -FilePath $Bin -ArgumentList $nargs -RedirectStandardOutput (Join-Path $ndir "node.log") -RedirectStandardError (Join-Path $ndir "node.err") -WindowStyle Hidden -PassThru -ErrorAction Stop
    Log ("  started node$id (p2p $p2p rpc $rpc fresh=$fresh) pid=$($p.Id)")
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Node-Rpc-Up $rpc)) {
        if ((Get-Date) -gt $deadline) { return $false }
        if ($p.HasExited) { Log ("  node$id exited early: " + (Get-Content (Join-Path $ndir "node.err") -ErrorAction SilentlyContinue | Select-Object -Last 3)); return $false }
        Start-Sleep -Milliseconds 1500
    }
    Log ("  node$id RPC up")
    return $true
}
function Stop-Node($id) {
    $pp = Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" | Where-Object { $_.CommandLine -match ([regex]::Escape($Root) + "\\node" + $id + "\\") }
    foreach ($p in $pp) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}
function TxTotal($id) { return [long](Rpc $ports[$id][1] "aether_getDagStats" @()).result.total_transactions }
function Wait-Converged($refPort, $port, $label, $timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $js = $null; $rs = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $rs = Get-State $refPort; $js = Get-State $port
            if ($js.total -eq $rs.total -and $js.txset -eq $rs.txset -and $js.dag -eq $rs.dag -and $js.tips -eq $rs.tips -and $js.led -eq $rs.led -and $js.w -eq $rs.w -and $js.supply -eq $rs.supply) {
                $sw.Stop()
                Log ("  CONVERGED [$label] in {0:N1}s (total={1})" -f $sw.Elapsed.TotalSeconds, $js.total)
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 5
    }
    $sw.Stop()
    Log ("  TIMEOUT [$label] after {0:N0}s" -f $sw.Elapsed.TotalSeconds)
    return $false
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
function New-Wallet($name) {
    $w = Join-Path $Root "$name.json"
    "$PW`n" | & $Bin wallet create $w 2>&1 | Out-Null
    $bout = (& $Bin balance $w --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
    return @{ path = $w; addr = $addr }
}
function Send($w, $to, $amount, $fee, $rpcPort) {
    $out = (& $Bin send $to $amount $fee --rpc-url ("http://127.0.0.1:" + $rpcPort) --wallet $w.path --password $PW 2>&1 | Out-String)
    return $out
}
function Gen-To($target, $fee) {
    $base = (Rpc 42101 "aether_getDagStats" @()).result.total_transactions
    if ([long]$base -ge $target) { return }
    Log ("  generating to $target (at $base, fee $fee)...")
    $tries = 0; $sent = 0
    while ($sent -lt $target -and $tries -lt 5000) {
        $tries++
        try { if ((Rpc 42101 "aether_getDagStats" @()).result.total_transactions -ge $target) { break } } catch {}
        $o = (& $Bin send $genAddr 1 $fee --rpc-url "http://127.0.0.1:42101" --wallet $genWallet --password $PW 2>&1 | Out-String)
        if ($o -match "REJECTED|Failed|error") { Start-Sleep -Milliseconds 300; continue }
        $sent++
        if ($sent % 100 -eq 0) { Log ("    generated $sent ...") }
    }
    Log ("  generation done: seed total=" + (Rpc 42101 "aether_getDagStats" @()).result.total_transactions)
}
function Show-Stats($port, $label) {
    try {
        $s = (Rpc $port "aether_getSyncStats" @()).result
        Log ("  sync[$label] requested={0} received={1} progress={2} batches={3} orphan_created={4} orphan_resolved={5} orphan_purged={6} retries={7} parent_requested={8} parent_deduped={9} dup_ignored={10}" -f $s.sync_requested,$s.sync_received,$s.sync_progress,$s.sync_batches,$s.orphan_created,$s.orphan_resolved,$s.orphan_purged,$s.retry_count,$s.parent_requested,$s.parent_already_known,$s.duplicate_ignored)
    } catch { Log ("  sync[$label] stats unavailable") }
}

# ============ GATES ============
if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
New-Item -ItemType Directory -Force -Path $Root | Out-Null
Log "=== CANARY CAMPAIGN on RC B4 (binary 8f04bb27...) ==="

$sha = (Get-FileHash $Bin -Algorithm SHA256).Hash.ToLower()
FailIf ($sha -ne $RC_SHA) "binary sha256 = RC B4 ($($sha.Substring(0,8))...)"
$head = (git -C $Repo rev-parse HEAD).Trim()
FailIf ($head -notmatch "^24c61e3|^a3af1d6") "HEAD = campaign commit (got $head)"
$diff = (git -C $Repo diff --name-only $FROZEN -- src) -join ","
FailIf ($diff -ne "src/lib.rs,src/node.rs,src/p2p.rs,src/rpc.rs,src/sync_stats.rs,src/tests/security_tests.rs") "src diff vs frozen = B4 files only (got: $diff)"
$ver = ([regex]::Match((Get-Content (Join-Path $Repo "Cargo.toml") -Raw), 'version\s*=\s*"([^"]+)"')).Groups[1].Value
FailIf ($ver -ne "1.2.0") "version $ver"
$genHash = (Get-FileHash (Join-Path $Repo "docs\genesis.json") -Algorithm SHA256).Hash.ToLower()
FailIf ($genHash -ne $GENHASH) "genesis hash"

# ============ PHASE A : 3 seeds (node1 with faucet.key) ============
Log "=== PHASE A - deploy 3 seed nodes (RC B4) ==="
foreach ($id in 1,2,3) {
    $ok = Start-Node $id $true
    FailIf (-not $ok) "node$id start"
}
$hub = (Rpc 42101 "aether_getDagStats" @()).result.connected_peers
FailIf ($hub -lt 2) "hub peers >= 2 (got $hub)"
$fb = (Rpc 42101 "aether_getBalance" @($FOUNDER)).result.balance
FailIf ([long]$fb -ne 100000000000) "founder genesis balance"
FailIf (-not (Check-Converged @(1,2,3) "Phase A")) "Phase A convergence"
Start-Sleep -Seconds 120
FailIf (-not (Check-Converged @(1,2,3) "Phase A after 2min observe")) "Phase A observe convergence"
$beforeA = TxTotal 1
FailIf ($beforeA -ne 0) "Phase A: no txs yet (got $beforeA)"

# generator wallet (faucet fund once, cooldown 60s/address)
$genWallet = Join-Path $Root "gen.json"
"$PW`n" | & $Bin wallet create $genWallet 2>&1 | Out-Null
$bout = (& $Bin balance $genWallet --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
$genAddr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
FailIf ($genAddr -eq "") "generator wallet"
try { Rpc 42101 "aether_faucet" @($genAddr) | Out-Null } catch { Log "  faucet fund: $_" }
Start-Sleep -Seconds 5
$bal = (Rpc 42101 "aether_getBalance" @($genAddr)).result.balance
FailIf ([long]$bal -lt 100000) "generator funded (got $bal)"
Log "=== PHASE A PASS (3 seeds, converged, faucet on node1) ==="

# ============ PHASE B : nodes 4-5, battery, B4 joins ============
Log "=== PHASE B - nodes 4-5 join ==="
foreach ($id in 4,5) {
    $ok = Start-Node $id $true
    FailIf (-not $ok) "node$id start"
}
FailIf (-not (Check-Converged @(1,2,3,4,5) "Phase B deploy")) "Phase B deploy convergence"

# B1 : sync series 10/50/100
Log "-- B1 sync series --"
$w1 = New-Wallet "wb1"; $w2 = New-Wallet "wb2"; $w3 = New-Wallet "wb3"
foreach ($a in @($w1.addr, $w2.addr, $w3.addr)) { try { Rpc 42101 "aether_faucet" @($a) | Out-Null } catch {}; Start-Sleep -Milliseconds 700 }
foreach ($serie in @(10, 50, 100)) {
    $before = TxTotal 1
    $rej = 0
    for ($i = 0; $i -lt $serie; $i++) {
        $ep = @(42101, 45101, 46101)[$i % 3]
        $from = @($w1, $w2, $w3)[$i % 3]
        $to = @($w1.addr, $w2.addr, $w3.addr)[($i + 1) % 3]
        $o = Send $from $to 10 100 $ep
        if ($o -match "REJECTED|Failed|error") { $rej++ }
    }
    Start-Sleep -Seconds 15
    $after = TxTotal 1
    FailIf ($rej -gt 0) "B1 series ${serie}: $rej rejected"
    FailIf ($after -ne ($before + $serie)) "B1 series $serie delta $($after - $before) (expected $serie)"
    FailIf (-not (Check-Converged @(1,2,3,4,5) "B1-$serie")) "B1-$serie convergence"
    Log ("  PASS: B1 series $serie")
}

# B2 : restarts nodes 4,5 (same dirs)
Log "-- B2 restart --"
foreach ($id in 4,5) { Stop-Node $id }
$b2before = TxTotal 1
foreach ($id in 4,5) {
    $ok = Start-Node $id $false
    FailIf (-not $ok) "node$id restart"
}
Start-Sleep -Seconds 30
FailIf (TxTotal 1 -ne $b2before) "B2 no loss (before $b2before after $(TxTotal 1))"
FailIf (-not (Check-Converged @(1,2,3,4,5) "B2-restart")) "B2 convergence"
Log "  PASS: B2"

# B3 : node4 offline during 20 txs, then recovery
Log "-- B3 offline 20 txs --"
Stop-Node 4
$b3before = TxTotal 1
Gen-To ($b3before + 20) 100
Start-Sleep -Seconds 10
$ok = Start-Node 4 $false
FailIf (-not $ok) "node4 recovery start"
FailIf (-not (Wait-Converged 42101 45101 "B3-recovery" 600)) "B3 recovery convergence"
Log "  PASS: B3"

# B5 : 8 concurrent txs
Log "-- B5 concurrent 8 txs --"
$b5before = TxTotal 1
$procs = @()
for ($i = 0; $i -lt 8; $i++) {
    $from = @($w1, $w2, $w3)[$i % 3]
    $to = @($w1.addr, $w2.addr, $w3.addr)[($i + 1) % 3]
    $procs += Start-Process -FilePath $Bin -ArgumentList @("send", $to, "5", "100", "--rpc-url", "http://127.0.0.1:43101", "--wallet", $from.path, "--password", $PW) -WindowStyle Hidden -PassThru
}
foreach ($p in $procs) { $p.WaitForExit(30000) | Out-Null }
Start-Sleep -Seconds 20
$b5after = TxTotal 1
FailIf ($b5after -lt ($b5before + 8)) "B5 accepted >= 8 (delta $($b5after - $b5before))"
FailIf (-not (Check-Converged @(1,2,3,4,5) "B5")) "B5 convergence"
Log "  PASS: B5"

# B6 : double spend (2 parallel sends, same wallet)
Log "-- B6 double spend --"
$b6before = TxTotal 1
$p1 = Start-Process -FilePath $Bin -ArgumentList @("send", $w2.addr, "7", "100", "--rpc-url", "http://127.0.0.1:42101", "--wallet", $w1.path, "--password", $PW) -WindowStyle Hidden -PassThru
$p2 = Start-Process -FilePath $Bin -ArgumentList @("send", $w2.addr, "7", "100", "--rpc-url", "http://127.0.0.1:43101", "--wallet", $w1.path, "--password", $PW) -WindowStyle Hidden -PassThru
$p1.WaitForExit(30000) | Out-Null; $p2.WaitForExit(30000) | Out-Null
Start-Sleep -Seconds 15
$b6after = TxTotal 1
FailIf ($b6after -ne ($b6before + 1)) "B6 exactly 1 accepted (delta $($b6after - $b6before))"
FailIf (-not (Check-Converged @(1,2,3,4,5) "B6")) "B6 convergence"
Log "  PASS: B6"

# B7 : rate limit (250 rapid calls)
Log "-- B7 rate limit --"
$limited = 0; $okcalls = 0
for ($i = 0; $i -lt 250; $i++) {
    try { $r = Rpc 42101 "aether_getDagStats" @(); if ($null -ne $r.error) { $limited++ } else { $okcalls++ } } catch { $limited++ }
}
FailIf ($limited -eq 0) "B7 some calls rate-limited (limited=$limited ok=$okcalls)"
Start-Sleep -Seconds 12
FailIf (-not (Node-Rpc-Up 42101)) "B7 node still up"
Log ("  PASS: B7 (limited=$limited ok=$okcalls)")

# B8 : faucet burst 8
Log "-- B8 faucet burst --"
$b8before = TxTotal 1
$burst = @()
for ($i = 0; $i -lt 8; $i++) { $burst += New-Wallet ("b8_" + $i) }
foreach ($a in $burst) { try { Rpc 42101 "aether_faucet" @($a.addr) | Out-Null } catch {}; Start-Sleep -Milliseconds 200 }
Start-Sleep -Seconds 15
$b8after = TxTotal 1
$delta = $b8after - $b8before
FailIf ($delta -lt 8) "B8 faucet delta >= 8 (got $delta)"
FailIf (-not (Check-Converged @(1,2,3,4,5) "B8")) "B8 convergence"
Log "  PASS: B8"

# ============ B4 SERIES (priority) ============
Log "=== B4 SERIES - fresh cold-start joins (PRIORITY) ==="
function Wait-Exact($target, $label) {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $t = TxTotal 1
        if ($t -eq $target) { Log ("  seed at exactly $target txs [$label]"); return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}
$cur = TxTotal 1
Gen-To ($cur + (463 - $cur)) 100
FailIf (-not (Wait-Exact 463 "B4-1")) "seed at exactly 463 txs (got $(TxTotal 1))"
$ok = Start-Node 6 $true
FailIf (-not $ok) "node6 start @463"
$c6 = Wait-Converged 42101 47101 "B4-1 join@463" 1800
FailIf (-not $c6) "B4-1: FRESH JOIN @463 CONVERGES (MUST PASS)"
if ($c6) { Show-Stats 47101 "join@463" }

Gen-To (463 + 37) 100
FailIf (-not (Wait-Exact 500 "B4-2")) "seed at exactly 500 txs (got $(TxTotal 1))"
$ok = Start-Node 7 $true
FailIf (-not $ok) "node7 start @500"
$c7 = Wait-Converged 42101 48101 "B4-2 join@500" 1800
FailIf (-not $c7) "B4-2: FRESH JOIN @500 CONVERGES"
if ($c7) { Show-Stats 48101 "join@500" }

Gen-To (500 + 500) 100
FailIf (-not (Wait-Exact 1000 "B4-3")) "seed at exactly 1000 txs (got $(TxTotal 1))"
$ok = Start-Node 8 $true
FailIf (-not $ok) "node8 start @1000"
$c8 = Wait-Converged 42101 49101 "B4-3 join@1000" 2400
FailIf (-not $c8) "B4-3: FRESH JOIN @1000 CONVERGES"
if ($c8) { Show-Stats 49101 "join@1000" }

# final multi-node convergence
FailIf (-not (Check-Converged @(1,2,3,4,5,6,7,8) "final")) "final 8-node convergence"

# ============ SUMMARY ============
Log "=== CAMPAIGN SUMMARY: $($script:passes) passed, $($script:fails) failed ==="
if ($script:fails -gt 0) { exit 1 } else { exit 0 }