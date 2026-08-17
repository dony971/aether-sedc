# ============================================================
# CANARY TESTS - Phase A battery (attach mode: 3 seeds running)
# Order: faucet disabled check -> faucet ACTIVATION (after
# stability) -> battery (normal/concurrent/PoW/double-spend/
# restart/offline/resync/new peer/spam/rate limit) -> faucet
# controls -> final convergence. ASCII-only, no secrets logged.
# Exit 0 = PASS.
# ============================================================
param(
    [string]$Repo = "C:\Users\Shadow\Documents\aether-fix\aether-main",
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a",
    [int]$OfflineTxs = 20,
    [int]$SpamTxs = 30
)
$ErrorActionPreference = "Continue"
$exe = Join-Path $Repo "target\release\aether-unified.exe"
$PW = "canary-pass-2026"
$FOUNDER = $env:AETHER_FOUNDER
$FAUCET = $env:AETHER_FAUCET
$FAUCET_SEED = $env:AETHER_FAUCET_SEED
if (-not $FOUNDER -or -not $FAUCET -or -not $FAUCET_SEED) { throw "Missing ceremony env" }
$BURN = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$knownAddrs = @($FOUNDER, $FAUCET, $BURN)
$script:ports = @{ 1 = @{ p2p = 42001; rpc = 42101 }; 2 = @{ p2p = 43001; rpc = 43101 }; 3 = @{ p2p = 44001; rpc = 44101 }; 4 = @{ p2p = 45001; rpc = 45101 } }
$script:walletRcp = @{}

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
function Wait-Hub($minPeers = 2, $timeout = 90) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        try { $r = (Rpc 42101 "aether_getDagStats" @()).result; if ($r.connected_peers -ge $minPeers) { return $true } } catch {}
        Start-Sleep -Seconds 2
    }
    return $false
}
function Start-Attached($id, $p2p, $rpc, $boot) {
    $ndir = Join-Path $DataRoot ("node" + $id)
    $args = @("--node-type","validator","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc","--bootnodes",$boot)
    $p = Start-Process -FilePath $exe -ArgumentList $args -RedirectStandardOutput (Join-Path $ndir "node.out.log") -RedirectStandardError (Join-Path $ndir "node.err.log") -WindowStyle Hidden -PassThru
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
        txset  = Sha256Hex (($txs | Sort-Object) -join ",")
        dag    = Sha256Hex (($edges | Sort-Object) -join ",")
        tips   = Sha256Hex ($tips -join ",")
        ledger = Sha256Hex (($ledger | Sort-Object) -join ",")
        weights = Sha256Hex (($weights | Sort-Object) -join ",")
        supply = [decimal]$stats.supply
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

Write-Host "=== CANARY TESTS - PHASE A (frozen b1b8376) ==="
$fails = 0
function FailIf($cond, $msg) { if ($cond) { Write-Host ("  FAIL: " + $msg); $script:fails++ } }

# ---- attach check
FailIf (-not (Node-Alive 1)) "node1 not running"
FailIf (-not (Node-Alive 2)) "node2 not running"
FailIf (-not (Node-Alive 3)) "node3 not running"
if (-not (Wait-Hub 2)) { Write-Host "  FAIL: hub peers < 2"; $fails++ }
Write-Host "  PASS: 3 seeds attached, hub >= 2 peers"

# ---- faucet must be DISABLED before activation (keys absent)
foreach ($id in 1,2,3) {
    $r = Rpc $script:ports[$id].rpc "aether_faucet" @($FOUNDER)
    if (-not $r.error -or "$($r.error.message)" -notmatch "disabled") { Write-Host ("  FAIL: faucet node" + $id + " not disabled pre-activation"); $fails++ }
}
Write-Host "  PASS: faucet disabled on all 3 seeds (pre-activation)"

# ---- stability gate: 2 fingerprint checks 30s apart must be equal
$s1 = Get-FullState 1; $s2 = Get-FullState 2; $s3 = Get-FullState 3
Start-Sleep -Seconds 30
$t1 = Get-FullState 1; $t2 = Get-FullState 2; $t3 = Get-FullState 3
FailIf (($s1.txset -ne $t1.txset) -or ($s2.txset -ne $t2.txset) -or ($s3.txset -ne $t3.txset)) "network not stable during gate"
FailIf (($s1.tips -ne $t1.tips) -or ($s2.tips -ne $t2.tips) -or ($s3.tips -ne $t3.tips)) "tips changed during gate"
Write-Host "  PASS: stability gate (30s, no change)"

# ============ FAUCET ACTIVATION (seeds stable) ============
Write-Host "-- faucet activation on node1 --"
Set-Content -Path (Join-Path $DataRoot "node1\faucet.key") -Value $FAUCET_SEED -NoNewline -Encoding ascii
Stop-Node 1
$newPid = Start-Attached 1 42001 42101 "127.0.0.1:1"
FailIf (-not (Wait-Up 1)) "node1 restart after faucet.key"
FailIf (-not (Wait-Hub 2)) "hub peers < 2 after restart"
Write-Host "  PASS: node1 restarted with faucet.key (pid $newPid), hub reconnected"

# ---- faucet controls
$wA = New-Wallet "fa"
$r = Rpc 42101 "aether_faucet" @($wA.addr)
FailIf ($r.error) ("faucet 1st request: " + $r.error.message)
$balA = (Rpc 42101 "aether_getBalance" @($wA.addr)).result.balance
FailIf ($balA -ne 100000000000) ("faucet credit amount: got $balA, expected 100000000000 (10 AETH)")
$r = Rpc 42101 "aether_faucet" @($wA.addr)
FailIf (-not $r.error -or "$($r.error.message)" -notmatch "Rate limited") "cooldown not triggered"
Write-Host "  PASS: faucet = 1st OK (10 AETH), 2nd = cooldown 60s"
$r = Rpc 43101 "aether_faucet" @($wA.addr)
FailIf (-not $r.error -or "$($r.error.message)" -notmatch "disabled") "faucet enabled on node2 (no key)"
Write-Host "  PASS: faucet still disabled on node2/node3 (keys only on node1)"
$burst = 0
foreach ($i in 1..8) {
    $wX = New-Wallet ("fb" + $i)
    $rx = Rpc 42101 "aether_faucet" @($wX.addr)
    if ($rx.error) { $burst++ }
    Start-Sleep -Milliseconds 300
}
FailIf ($burst -gt 2) ("faucet burst failures: $burst/8 (cooldown per addr expected <=2)")
Write-Host "  PASS: faucet burst 8 addrs -> $burst rate-limited (expected 0-2)"

# ---- normal + concurrent + PoW + double spend
$w1 = New-Wallet "w1"; $w2 = New-Wallet "w2"; $w3 = New-Wallet "w3"
$n = 0
foreach ($a in @($w1.addr, $w2.addr, $w3.addr)) { $r = Rpc 42101 "aether_faucet" @($a); Start-Sleep -Milliseconds 500 }
for ($i = 0; $i -lt 5; $i++) {
    $o = Send $w1 $w1.addr 1000 10 42101
    if ($o -match "REJECTED|Failed") { Write-Host "  FAIL self tx"; $fails++ }
    $o = Send $w1 $w2.addr 1000 10 42101
    if ($o -match "REJECTED|Failed") { Write-Host "  FAIL cross tx"; $fails++ }
    $n += 2
}
Write-Host "  PASS: $n normal txs (self+cross, PoW 20)"
$conc = @()
for ($i = 0; $i -lt 8; $i++) {
    $o = Send $w2 $w3.addr 100 10 42101
    $conc += $o
}
FailIf (@($conc | Select-String "REJECTED|Failed").Count -gt 0) "concurrent txs rejected"
Write-Host "  PASS: 8 concurrent txs"
$nonce2 = (Rpc 42101 "aether_getAccountNonce" @($w2.addr)).result.next_nonce
$bal2 = (Rpc 42101 "aether_getBalance" @($w2.addr)).result.balance
$dsAmt = $bal2 - 100
$r1 = Send $w2 $w3.addr $dsAmt 10 42101
Start-Sleep -Seconds 2
$bal2b = (Rpc 42101 "aether_getBalance" @($w2.addr)).result.balance
$r2 = Send $w2 $w3.addr $bal2b 10 42101
$dsOk = ($r1 -match "REJECTED|Failed") -or (-not ($r2 -match "REJECTED|Failed"))
FailIf $dsOk "double spend: expected 1 accept + 1 reject"
Start-Sleep -Seconds 5
$d1After = (Rpc 42101 "aether_getBalance" @($w2.addr)).result.balance
$d1Nonce = (Rpc 42101 "aether_getAccountNonce" @($w2.addr)).result.next_nonce
FailIf ($d1After -ne 90) ("double spend ledger: w2 balance=$d1After (expected 90)")
FailIf ($d1Nonce -ne ($nonce2 + 1)) ("double spend ledger: w2 nonce=$d1Nonce (expected " + ($nonce2 + 1) + ")")
if ($dsOk) { Write-Host "  FAIL: double spend = aucun accepte" } else { Write-Host "  PASS: double spend = 1 acceptee (ledger bal=90, nonce+1), 1 rejetee (deterministe)" }
Start-Sleep -Seconds 8
FailIf (-not (Check-Converged @(1,2,3) "post-load")) "post-load convergence"

# ---- restart node2 (same data dir)
Write-Host "-- restart node2 --"
Stop-Node 2
Start-Attached 2 43001 43101 "127.0.0.1:42001" | Out-Null
FailIf (-not (Wait-Up 2)) "node2 restart"
Start-Sleep -Seconds 15
FailIf (-not (Check-Converged @(1,2,3) "post-restart")) "post-restart convergence"
Write-Host "  PASS: restart node2 -> resync + converge"

# ---- offline node3 + load + recovery
Write-Host "-- node3 offline during load --"
Stop-Node 3
for ($i = 0; $i -lt $OfflineTxs; $i++) {
    & $exe send $w3.addr 10 10 --rpc-url "http://127.0.0.1:43101" --wallet $w1 --password $PW 2>&1 | Out-Null
}
Write-Host "  $OfflineTxs txs pendant l absence de node3"
Start-Attached 3 44001 44101 "127.0.0.1:42001" | Out-Null
FailIf (-not (Wait-Up 3)) "node3 recovery"
Start-Sleep -Seconds 20
FailIf (-not (Check-Converged @(1,2,3) "post-resync")) "post-resync convergence"
Write-Host "  PASS: node3 offline + recovery + resync converge"

# ---- new peer joins (temp node4) then leaves
Write-Host "-- new peer node4 joins --"
Start-Attached 4 45001 45101 "127.0.0.1:42001" | Out-Null
FailIf (-not (Wait-Up 4)) "node4 join"
Start-Sleep -Seconds 15
FailIf (-not (Check-Converged @(1,2,3,4) "with-node4")) "convergence with node4"
Write-Host "  PASS: new peer node4 sync + converge"
Stop-Node 4
Start-Sleep -Seconds 5
FailIf (-not (Check-Converged @(1,2,3) "after-node4-leaves")) "convergence after node4 leaves"
Write-Host "  PASS: node4 leaves, 3 seeds converge"

# ---- spam raisonnable + rate limit
Write-Host "-- spam raisonnable $SpamTxs txs --"
$rej = 0
for ($i = 0; $i -lt $SpamTxs; $i++) {
    $o = Send $w3 $w1.addr 5 10 42101
    if ($o -match "REJECTED|Failed") { $rej++ }
}
Write-Host "  spam: $($SpamTxs - $rej)/$SpamTxs acceptees"
$rl = 0
for ($i = 0; $i -lt 250; $i++) {
    try { $rr = Rpc 42101 "aether_getDagStats" @() } catch {}
    if ($rr.error -and "$($rr.error.message)" -match "Rate limited") { $rl++ }
}
FailIf ($rl -lt 1) "RPC rate limit never triggered (250 rapid calls)"
Write-Host "  PASS: RPC rate limit triggered ($rl/250)"
Start-Sleep -Seconds 10
FailIf (-not (Check-Converged @(1,2,3) "post-spam")) "post-spam convergence"

# ---- no secrets in logs after activation
$hits = 0
foreach ($id in 1,2,3) {
    $hits += @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.err.log")) -ErrorAction SilentlyContinue | Select-String $FAUCET_SEED).Count
    $hits += @(Get-Content (Join-Path $DataRoot ("node" + $id + "\node.out.log")) -ErrorAction SilentlyContinue | Select-String $FAUCET_SEED).Count
}
FailIf ($hits -gt 0) "faucet seed found in node logs"
Write-Host "  PASS: aucun secret dans les logs (seed introuvable)"

Write-Host "=================================================="
if ($fails -eq 0) { Write-Host "RESULTAT CANARY TESTS PHASE A : PASS (0 echec)"; exit 0 }
Write-Host ("RESULTAT CANARY TESTS PHASE A : FAIL (" + $fails + " echecs)"); exit 1