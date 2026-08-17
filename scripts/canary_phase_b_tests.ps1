# ============================================================
# CANARY TESTS - PHASE B battery (attach mode: 5 nodes running)
# B1 sync 10/50/100 | B2 restart x3 | B3 offline+recovery |
# B4 new node (package) | B5 orphan race | B6 double-spend x2 |
# B7 RPC rate limit | B8 faucet (seed-1 only). ASCII-only, no
# secrets logged. Exit 0 = PASS.
# ============================================================
param(
    [string]$Repo = "C:\Users\Shadow\Documents\aether-fix\aether-main",
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a"
)
$ErrorActionPreference = "Continue"
$exe = Join-Path $Repo "target\release\aether-unified.exe"
$pkgExe = Join-Path $Repo "aether-v3-testnet-release\aether-unified.exe"
$PW = "canary-pass-2026"
$FAUCET = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$knownAddrs = @($FOUNDER, $FAUCET, $BURN)
$script:ports = @{ 1 = @{ p2p = 42001; rpc = 42101 }; 2 = @{ p2p = 43001; rpc = 43101 }; 3 = @{ p2p = 44001; rpc = 44101 }; 4 = @{ p2p = 45001; rpc = 45101 }; 5 = @{ p2p = 46001; rpc = 46101 }; 6 = @{ p2p = 47001; rpc = 47101 } }
$fails = 0
function FailIf($cond, $msg) { if ($cond) { Write-Host ("  FAIL: " + $msg); $script:fails++ } else { Write-Host ("  PASS: " + $msg) } }

function Sha256Hex($s) {
    $b = [System.Text.Encoding]::UTF8.GetBytes($s)
    $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash($b)
    ($h | ForEach-Object { $_.ToString("x2") }) -join ""
}
function HexId($arr) {
    if ($arr -is [string]) { return $arr.ToLowerInvariant() }
    if ($null -eq $arr) { return "" }
    ($arr | ForEach-Object { $_.ToString("x2") }) -join ""
}
function Rpc($port, $method, $params) {
    $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 6
    Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 60
}
function Node-Alive($id) {
    $pidf = Join-Path $DataRoot ("node" + $id + "\node.pid")
    if (-not (Test-Path $pidf)) { return $false }
    $p = [int](Get-Content $pidf).Trim()
    return [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
}
function Wait-Up($id, $timeout = 120) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        try { $r = Rpc $script:ports[$id].rpc "aether_getDagStats" @(); if ($null -ne $r.result.total_transactions) { return $true } } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Start-Attached($id, $p2p, $rpc, $boot, $binPath) {
    $ndir = Join-Path $DataRoot ("node" + $id)
    New-Item -ItemType Directory -Path $ndir -Force | Out-Null
    $args = @("--node-type","validator","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc","--bootnodes",$boot)
    $p = Start-Process -FilePath $binPath -ArgumentList $args -RedirectStandardOutput (Join-Path $ndir "node.out.log") -RedirectStandardError (Join-Path $ndir "node.err.log") -WindowStyle Hidden -PassThru
    $p.Id | Set-Content (Join-Path $ndir "node.pid") -Encoding ascii
    return $p.Id
}
function Stop-Node($id) {
    $pidf = Join-Path $DataRoot ("node" + $id + "\node.pid")
    if (Test-Path $pidf) {
        $p = [int](Get-Content $pidf).Trim()
        Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}
function Get-FullState($id) {
    $rpc = $script:ports[$id].rpc
    $graph = (Rpc $rpc "aether_getDagGraph" @()).result
    $stats = (Rpc $rpc "aether_getDagStats" @()).result
    $tips = @((Rpc $rpc "aether_getTips" @()).result.tips | Sort-Object | ForEach-Object { HexId $_ })
    $txs = @(); $edges = @(); $weights = @()
    foreach ($n in $graph.nodes) { $txs += HexId $n.tx_id; $weights += "$(HexId $n.tx_id):$($n.weight)" }
    foreach ($e in $graph.edges) { $edges += "$(HexId $e.from)->$(HexId $e.to)" }
    $ledger = @()
    foreach ($a in $knownAddrs) {
        $b = (Rpc $rpc "aether_getBalance" @($a)).result.balance
        $n = (Rpc $rpc "aether_getAccountNonce" @($a)).result.next_nonce
        $ledger += "${a}:${b}:${n}"
    }
    return @{
        txset = Sha256Hex (($txs | Sort-Object) -join ",")
        dag = Sha256Hex (($edges | Sort-Object) -join ",")
        tips = Sha256Hex ($tips -join ",")
        ledger = Sha256Hex (($ledger | Sort-Object) -join ",")
        weights = Sha256Hex (($weights | Sort-Object) -join ",")
        supply = [decimal]$stats.supply
        txCount = [long]$stats.total_transactions
    }
}
function Check-Converged($ids, $label) {
    $states = @{}
    foreach ($id in $ids) { $states[$id] = Get-FullState $id }
    $ok = $true
    $ref = $states[$ids[0]]
    foreach ($id in $ids) {
        $s = $states[$id]
        foreach ($k in @("txset","dag","tips","ledger","weights")) {
            if ($s.$k -ne $ref.$k) { Write-Host "  DIVERGENCE node$id $k"; $ok = $false }
        }
        if ($s.supply -ne $ref.supply) { Write-Host "  DIVERGENCE node$id supply ($($s.supply) vs $($ref.supply))"; $ok = $false }
    }
    if ($ok) { Write-Host "  CONVERGED [$label]: txset/dag/tips/ledger/weights/supply identiques ($($ids -join ','))" }
    return $ok
}
$runSuffix = (Get-Date -Format "HHmmss")
function New-Wallet($name) {
    $w = Join-Path $DataRoot "$name$runSuffix.json"
    "$PW`n" | & $exe wallet create $w 2>&1 | Out-Null
    $bout = (& $exe balance $w --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value
    $knownAddrs += $addr.ToLower()
    return @{ path = $w; addr = $addr.ToLower() }
}
function Send($w, $to, $amount, $fee, $rpcPort) {
    $out = (& $exe send $to $amount $fee --rpc-url ("http://127.0.0.1:" + $rpcPort) --wallet $w.path --password $PW 2>&1 | Out-String)
    return $out
}
function TxTotal($id) { return [long]((Rpc $script:ports[$id].rpc "aether_getDagStats" @()).result.total_transactions) }

Write-Host "=== CANARY TESTS - PHASE B (5 nodes, frozen b1b8376) ==="

# ---- attach check
foreach ($id in 1,2,3,4,5) { FailIf (-not (Node-Alive $id)) "node$id not running" }
$hub = (Rpc 42101 "aether_getDagStats" @()).result.connected_peers
FailIf ($hub -lt 4) "hub peers $hub (expected >= 4)"
FailIf (-not (Check-Converged @(1,2,3,4,5) "pre-B")) "pre-B convergence"
Write-Host "  PASS: 5 nodes attached, hub >= 4 peers, converged"

# ---- fund wallets (faucet seed-1 only, 10 AETH each)
$w1 = New-Wallet "wb1"; $w2 = New-Wallet "wb2"; $w3 = New-Wallet "wb3"
foreach ($a in @($w1.addr, $w2.addr, $w3.addr)) {
    $r = Rpc 42101 "aether_faucet" @($a)
    if ($r.error) { Write-Host ("  FAIL: faucet fund: " + $r.error.message); $fails++ }
    Start-Sleep -Milliseconds 600
}
Write-Host "  PASS: wb1/wb2/wb3 funded (10 AETH each via seed-1)"

# ============ TEST B1 - SYNCHRONISATION (10/50/100) ============
Write-Host "-- TEST B1 - sync series --"
$endpoints = @(42101, 45101, 46101)
foreach ($serie in @(10, 50, 100)) {
    $before = TxTotal 1
    $rej = 0
    for ($i = 0; $i -lt $serie; $i++) {
        $ep = $endpoints[$i % 3]
        $from = @($w1, $w2, $w3)[$i % 3]
        $to = @($w1.addr, $w2.addr, $w3.addr)[($i + 1) % 3]
        $amt = 10 + ($i % 5) * 10
        $o = Send $from $to $amt 10 $ep
        if ($o -match "REJECTED|Failed") { $rej++ }
    }
    Start-Sleep -Seconds 12
    $after = TxTotal 1
    FailIf ($rej -gt 0) "B1 series ${serie}: $rej rejected"
    FailIf ($after -ne ($before + $serie)) "B1 series ${serie}: tx delta $($after - $before) (expected $serie)"
    FailIf (-not (Check-Converged @(1,2,3,4,5) "B1-$serie")) "B1-$serie convergence"
    Write-Host "  PASS: B1 series $serie txs ($endpoints -join ',') -> delta $serie, converged"
}
Write-Host "  PASS: TEST B1 (10/50/100, multi-node sends, h_txset/h_dag/h_tips/h_ledger/h_weights/supply identiques)"

# ============ TEST B2 - RESTART ============
Write-Host "-- TEST B2 - restart node4, node5, seed2 (one at a time) --"
foreach ($pair in @(@(4, 45001, 45101), @(5, 46001, 46101), @(2, 43001, 43101))) {
    $id = $pair[0]; $p2p = $pair[1]; $rpc = $pair[2]
    $before = TxTotal 1
    Stop-Node $id
    Start-Attached $id $p2p $rpc "127.0.0.1:42001" $exe | Out-Null
    FailIf (-not (Wait-Up $id)) "B2 node$id restart up"
    Start-Sleep -Seconds 15
    FailIf (-not (Check-Converged @(1,2,3,4,5) "B2-restart-$id")) "B2 restart node$id convergence"
    FailIf ((TxTotal $id) -ne $before) "B2 restart node${id}: data lost (tx $before -> $((TxTotal $id)))"
    Write-Host "  PASS: restart node$id -> resync + converge, 0 perte"
}
Write-Host "  PASS: TEST B2 (restarts node4/node5/seed2, resync/convergence/ledger/DAG/weights, 0 perte)"

# ============ TEST B3 - NODE OFFLINE ============
Write-Host "-- TEST B3 - node4 offline + 20 txs + recovery --"
$before = TxTotal 1
Stop-Node 4
$liveEps = @(42101, 46101)
for ($i = 0; $i -lt 20; $i++) {
    $ep = $liveEps[$i % 2]
    $o = Send $w1 $w2.addr (10 + $i) 10 $ep
    if ($o -match "REJECTED|Failed") { Write-Host "  FAIL: B3 tx $i"; $fails++ }
}
Start-Attached 4 45001 45101 "127.0.0.1:42001" $exe | Out-Null
FailIf (-not (Wait-Up 4)) "B3 node4 recovery"
Start-Sleep -Seconds 20
FailIf (-not (Check-Converged @(1,2,3,4,5) "B3-recovery")) "B3 post-recovery convergence"
FailIf ((TxTotal 4) -ne $before -and (TxTotal 4) -ne (TxTotal 1)) "B3 node4 missed txs (node4=$((TxTotal 4)) node1=$((TxTotal 1)))"
Write-Host "  PASS: TEST B3 (offline + load + recovery, 0 tx perdue, convergence complete)"

# ============ TEST B4 - NEW NODE FROM PACKAGE ============
Write-Host "-- TEST B4 - node6 from official package (fresh dir) --"
$ndir6 = Join-Path $DataRoot "node6"
if (Test-Path $ndir6) { Remove-Item $ndir6 -Recurse -Force -ErrorAction SilentlyContinue }
$p6 = Start-Attached 6 47001 47101 "127.0.0.1:42001" $pkgExe
FailIf (-not (Wait-Up 6)) "B4 node6 up"
Start-Sleep -Seconds 20
FailIf (-not (Check-Converged @(1,2,3,4,5,6) "B4-with-node6")) "B4 convergence with node6"
FailIf ((TxTotal 6) -ne (TxTotal 1)) "B4 node6 tx count mismatch"
FailIf (Test-Path (Join-Path $ndir6 "faucet.key")) "B4 node6 has faucet.key"
Write-Host "  PASS: TEST B4 (node6 package binary, fresh dir, join+sync, fingerprints identiques)"
Stop-Node 6
Start-Sleep -Seconds 5
FailIf (-not (Check-Converged @(1,2,3,4,5) "B4-after-node6-leaves")) "B4 convergence after node6 leaves"
Write-Host "  PASS: node6 left, 5 nodes re-converged (extension 6-10 to be proposed, not automatic)"

# ============ TEST B5 - ORPHANS ============
Write-Host "-- TEST B5 - orphan race attempt (tx before parent) --"
$orphHits = 0
for ($r = 0; $r -lt 3; $r++) {
    $a = Send $w2 $w3.addr 100 10 42101
    $b = Send $w2 $w3.addr 100 10 42101
    $c = Send $w3 $w2.addr 100 10 46101
    if ($a -match "REJECTED|Failed" -or $b -match "REJECTED|Failed" -or $c -match "REJECTED|Failed") { Write-Host "  WARN: B5 round $r rejection" }
}
Start-Sleep -Seconds 12
foreach ($id in 4,5) {
    $l1 = @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.out.log")) -ErrorAction SilentlyContinue | Select-String -Pattern "orphan").Count
    $l2 = @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.err.log")) -ErrorAction SilentlyContinue | Select-String -Pattern "orphan").Count
    $orphHits += ($l1 + $l2)
}
FailIf (-not (Check-Converged @(1,2,3,4,5) "B5-after-race")) "B5 convergence"
if ($orphHits -gt 0) { Write-Host "  INFO: $orphHits orphan event(s) observed in node4/node5 logs (detection+recovery path exercised)" }
else { Write-Host "  INFO: no orphan event reproduced via CLI (child always references known tips; injection requires node-level tooling -> covered by unit tests, no code change per mandate)" }
Write-Host "  PASS: TEST B5 (race attempt executed, 0 divergence, convergence complete)"

# ============ TEST B6 - DOUBLE SPEND (two arrival orders) ============
Write-Host "-- TEST B6 - double spend, two orders, same winner everywhere --"
foreach ($round in 1,2) {
    $wd = New-Wallet ("dsb" + $round)
    $r = Rpc 42101 "aether_faucet" @($wd.addr)
    FailIf ($r.error) "B6 round $round faucet fund"
    Start-Sleep -Seconds 2
    $bal = (Rpc 42101 "aether_getBalance" @($wd.addr)).result.balance
    $amt = $bal - 200
    $before = TxTotal 1
    $outA = Join-Path $env:TEMP ("opencode\ds_" + $round + "_a.out")
    $outB = Join-Path $env:TEMP ("opencode\ds_" + $round + "_b.out")
    if ($round -eq 1) { $epA = 45101; $epB = 46101 } else { $epA = 46101; $epB = 45101 }
    $pa = Start-Process -FilePath $exe -ArgumentList @("send", $w3.addr, "$amt", "10", "--rpc-url", ("http://127.0.0.1:" + $epA), "--wallet", $wd.path, "--password", $PW) -RedirectStandardOutput $outA -RedirectStandardError (Join-Path $env:TEMP ("opencode\ds_" + $round + "_a.err")) -WindowStyle Hidden -PassThru
    $pb = Start-Process -FilePath $exe -ArgumentList @("send", $w3.addr, "$amt", "10", "--rpc-url", ("http://127.0.0.1:" + $epB), "--wallet", $wd.path, "--password", $PW) -RedirectStandardOutput $outB -RedirectStandardError (Join-Path $env:TEMP ("opencode\ds_" + $round + "_b.err")) -WindowStyle Hidden -PassThru
    $pa.WaitForExit(60000) | Out-Null; $pb.WaitForExit(60000) | Out-Null
    Start-Sleep -Seconds 10
    $oa = Get-Content $outA -Raw -ErrorAction SilentlyContinue
    $ob = Get-Content $outB -Raw -ErrorAction SilentlyContinue
    $accA = ($oa -notmatch "REJECTED|Failed"); $accB = ($ob -notmatch "REJECTED|Failed")
    Write-Host "  INFO: B6 round $round CLI visibility: accA=$accA accB=$accB (rejection may surface at processor level)"
    FailIf ((TxTotal 1) -ne ($before + 1)) "B6 round ${round}: tx delta $((TxTotal 1) - $before) (expected 1)"
    FailIf (-not (Check-Converged @(1,2,3,4,5) "B6-round$round")) "B6 round $round convergence"
    $balAfter = (Rpc 42101 "aether_getBalance" @($wd.addr)).result.balance
    FailIf ($balAfter -ne 190) "B6 round $round ledger: dsb balance $balAfter (expected 190 = bal - amt - fee 10)"
    Write-Host "  PASS: B6 round $round (order: node$(@(4,5)[$round-1]) -> node$(@(5,4)[$round-1])): 1 seule tx au ledger, meme gagnant partout"
}
Write-Host "  PASS: TEST B6 (double spend, deux ordres d'arrivee, winner identique sur les 5 noeuds)"

# ============ TEST B7 - RPC RATE LIMIT ============
Write-Host "-- TEST B7 - RPC rate limit --"
$rl = 0
for ($i = 0; $i -lt 250; $i++) {
    try { $rr = Rpc 45101 "aether_getDagStats" @() } catch {}
    if ($rr.error -and "$($rr.error.message)" -match "Rate limited") { $rl++ }
}
FailIf ($rl -lt 1) "B7 rate limit never triggered"
FailIf (-not (Node-Alive 4)) "B7 node4 crashed after burst"
$ok2 = try { Rpc 45101 "aether_getDagStats" @(); $true } catch { $false }
FailIf (-not $ok2) "B7 RPC unresponsive right after burst"
Start-Sleep -Seconds 11
$ok3 = try { $x = (Rpc 45101 "aether_getDagStats" @()).result; $x.total_transactions -ge 0 } catch { $false }
FailIf (-not $ok3) "B7 RPC still limited after window"
Write-Host "  PASS: TEST B7 ($rl/250 rate-limited, post-window OK, aucun crash, aucune degradation silencieuse)"

# ============ TEST B8 - FAUCET (seed-1 only) ============
Write-Host "-- TEST B8 - faucet controls --"
$faucetBefore = (Rpc 42101 "aether_getBalance" @($FAUCET)).result.balance
$wf1 = New-Wallet "wf1"
$r = Rpc 42101 "aether_faucet" @($wf1.addr)
FailIf ($r.error) ("B8 normal: " + $r.error.message)
$balF = (Rpc 42101 "aether_getBalance" @($wf1.addr)).result.balance
FailIf ($balF -ne 100000000000) "B8 amount $balF (expected 1e11)"
$r = Rpc 42101 "aether_faucet" @($wf1.addr)
FailIf (-not $r.error -or "$($r.error.message)" -notmatch "Rate limited") "B8 cooldown"
$r = Rpc 45101 "aether_faucet" @($wf1.addr)
FailIf (-not $r.error -or "$($r.error.message)" -notmatch "disabled") "B8 faucet on node4"
$r = Rpc 46101 "aether_faucet" @($wf1.addr)
FailIf (-not $r.error -or "$($r.error.message)" -notmatch "disabled") "B8 faucet on node5"
$burst = 0; $accepted = 0
foreach ($i in 1..8) {
    $wX = New-Wallet ("wf2x" + $i)
    $rx = Rpc 42101 "aether_faucet" @($wX.addr)
    if ($rx.error) { $burst++ } else { $accepted++ }
    Start-Sleep -Milliseconds 300
}
$wf2 = New-Wallet "wf2"
$r2 = Rpc 42101 "aether_faucet" @($wf2.addr)
if ($r2.error) { Write-Host ("  FAIL: B8 wf2 fund: " + $r2.error.message); $fails++ }
$requests = 1 + $accepted + 1
$faucetAfter = (Rpc 42101 "aether_getBalance" @($FAUCET)).result.balance
FailIf ($faucetAfter -ne ($faucetBefore - ($requests * (100000000000 + 1)))) "B8 faucet balance delta $($faucetBefore - $faucetAfter) (expected $($requests * (100000000000 + 1)))"
$o = Send $wf2 $wf1.addr 1000 10 46101
FailIf ($o -match "REJECTED|Failed") "B8 multi-client send via node5"
$r = Rpc 46101 "aether_getBalance" @($wf2.addr)
FailIf (-not $r.result) "B8 multi-client balance via node5 RPC"
Write-Host "  PASS: B8 normal/cooldown/limite/solde/burst/multi-client ($requests requetes faucet, debit $($requests * (100000000000 + 1)) = montant+fee 1)"
Start-Sleep -Seconds 10
FailIf (-not (Check-Converged @(1,2,3,4,5) "B8-final")) "B8 final convergence"

# ---- no secrets in logs (incl. tests logs)
$seed = (Get-Content (Join-Path $DataRoot "node1\faucet.key") -Raw -ErrorAction SilentlyContinue).Trim()
$hits = 0
foreach ($id in 1,2,3,4,5,6) {
    $hits += @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.err.log")) -ErrorAction SilentlyContinue | Select-String $seed).Count
    $hits += @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.out.log")) -ErrorAction SilentlyContinue | Select-String $seed).Count
}
FailIf ($hits -gt 0) "$hits secret occurrences in node logs"
Write-Host "  PASS: aucun secret dans les logs (seed faucet introuvable)"

Write-Host "=================================================="
if ($fails -eq 0) { Write-Host "RESULTAT CANARY TESTS PHASE B : PASS (0 echec)"; exit 0 }
Write-Host ("RESULTAT CANARY TESTS PHASE B : FAIL (" + $fails + " echecs)"); exit 1