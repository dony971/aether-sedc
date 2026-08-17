<#requires -Version 5.1
# 5-node V3 smoke (release candidate): fresh network, faucet controls,
# convergence fingerprints (txset/edges/tips/ledger/weights), restart,
# offline node + load + resync. Exit 0 = PASS.
#>
param(
    [int]$LoadTxs = 30
)

$ErrorActionPreference = 'Stop'
$exe = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe"
$dir = Join-Path $env:TEMP "opencode\aether-v3-net5"
$PW = "smoke-password-2026"
$FOUNDER = $env:AETHER_FOUNDER
$FAUCET = $env:AETHER_FAUCET
$FAUCET_SEED = $env:AETHER_FAUCET_SEED
if (-not $FOUNDER -or -not $FAUCET -or -not $FAUCET_SEED) { throw "Missing ceremony env" }
$BURN = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$knownAddrs = @($FOUNDER, $FAUCET, $BURN)

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
function Start-Node($id, $p2p, $rpc, $boot, $faucetSeed) {
    $ndir = Join-Path $dir "node$id"
    New-Item -ItemType Directory -Path $ndir -Force | Out-Null
    if ($faucetSeed) { Set-Content -Path (Join-Path $ndir "faucet.key") -Value $faucetSeed -NoNewline }
    $args = @("--node-type","observer","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc","--bootnodes",$boot)
    $script:procs[$id] = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $dir "node$id.out.log") -RedirectStandardError (Join-Path $dir "node$id.err.log")
    $script:ports[$id] = @{ p2p = $p2p; rpc = $rpc }
}
function Wait-Up($id, $timeout = 120) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        if ($script:procs[$id].HasExited) { return $false }
        try { $r = Rpc $script:ports[$id].rpc "aether_getDagStats" @(); if ($null -ne $r.result.total_transactions) { return $true } } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Wait-Peers($ids, $minPeers, $timeout = 90) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        $allOk = $true
        foreach ($id in $ids) {
            try {
                $r = (Rpc $script:ports[$id].rpc "aether_getDagStats" @()).result
                if ($r.connected_peers -lt $minPeers) { $allOk = $false }
            } catch { $allOk = $false }
        }
        if ($allOk) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}
function Stop-Node($id) { if ($script:procs[$id] -and -not $script:procs[$id].HasExited) { Stop-Process -Id $script:procs[$id].Id -Force -ErrorAction SilentlyContinue } }
function Stop-AllNodes { foreach ($id in $script:procs.Keys) { if (-not $script:procs[$id].HasExited) { Stop-Process -Id $script:procs[$id].Id -Force -ErrorAction SilentlyContinue } } }
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

$script:procs = @{}; $script:ports = @{}
Write-Host "=== 5-NODE V3 SMOKE (fresh network) ==="
try {
if (Test-Path $dir) { Get-ChildItem $dir -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue; Remove-Item $dir -Force -Recurse -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $dir -Force | Out-Null

Write-Host "-- start 5 nodes (faucet.key ONLY on node1) --"
Start-Node 1 42001 42101 "127.0.0.1:1" $FAUCET_SEED
Start-Node 2 43001 43101 "127.0.0.1:42001" $null
Start-Node 3 44001 44101 "127.0.0.1:42001" $null
Start-Node 4 45001 45101 "127.0.0.1:42001" $null
Start-Node 5 46001 46101 "127.0.0.1:42001" $null
foreach ($id in 1..5) { if (-not (Wait-Up $id)) { Write-Host "FAIL: node$id not up"; exit 1 } }
if (-not (Wait-Peers @(1) 4)) { Write-Host "FAIL: node1 hub < 4 peers apres 90s"; exit 1 }
Write-Host "  PASS: 5 nodes up, node1 hub connected to 4 peers"

Write-Host "-- genesis invariants --"
foreach ($id in 1..5) {
    $b = (Rpc $script:ports[$id].rpc "aether_getBalance" @($FOUNDER)).result.balance
    if ($b -ne 100000000000) { Write-Host "  FAIL: founder balance node$id = $b"; exit 1 }
}
Write-Host "  PASS: founder balance 1e11 sur les 5 nodes"

Write-Host "-- faucet controls --"
$w1 = Join-Path $dir "w1.json"; "$PW`n" | & $exe wallet create $w1 2>&1 | Out-Null
$b1out = (& $exe balance $w1 --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
$addr1 = ([regex]::Match($b1out, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value
$knownAddrs += $addr1.ToLower()
$r = Rpc 42101 "aether_faucet" @($addr1)
if ($r.error) { Write-Host "  FAIL: faucet node1 (key present) error: $($r.error.message)"; exit 1 }
$r = Rpc 42101 "aether_faucet" @($addr1)
if (-not $r.error -or "$($r.error.message)" -notmatch "Rate limited") { Write-Host "  FAIL: cooldown non declenche: $($r.error.message)"; exit 1 }
Write-Host "  PASS: faucet node1 = 1ere requete OK, 2e = cooldown 60s"
$r = Rpc 45101 "aether_faucet" @($addr1)
if (-not $r.error -or "$($r.error.message)" -notmatch "disabled") { Write-Host "  FAIL: faucet node4 (sans cle) non desactive"; exit 1 }
Write-Host "  PASS: faucet node4 (sans faucet.key) = disabled"

Write-Host "-- wallets + transactions --"
$w2 = Join-Path $dir "w2.json"; "$PW`n" | & $exe wallet create $w2 2>&1 | Out-Null
$w3 = Join-Path $dir "w3.json"; "$PW`n" | & $exe wallet create $w3 2>&1 | Out-Null
$b2out = (& $exe balance $w2 --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
$addr2 = ([regex]::Match($b2out, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value
$b3out = (& $exe balance $w3 --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
$addr3 = ([regex]::Match($b3out, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value
$knownAddrs += $addr2.ToLower(); $knownAddrs += $addr3.ToLower()
foreach ($a in @($addr2, $addr3)) { $r = Rpc 42101 "aether_faucet" @($a); if ($r.error) { Write-Host "  faucet fund $a : $($r.error.message)" } ; Start-Sleep -Seconds 2 }
$n = 0
foreach ($a in @($addr2, $addr3)) {
    for ($i = 0; $i -lt 5; $i++) {
        $out = & $exe send $a 1000 10 --rpc-url "http://127.0.0.1:42101" --wallet $w1 --password $PW 2>&1 | Out-String
        if ($out -match "REJECTED|Failed") { Write-Host "  send fail: $($out.Trim())"; }
        $n++
    }
}
Write-Host "  sent $n txs (self/faucet mix, mining PoW 20)"
Start-Sleep -Seconds 5
$txTotal = (Rpc 42101 "aether_getDagStats" @()).result.total_transactions
Write-Host "  total_transactions = $txTotal"

Write-Host "-- convergence 5 nodes --"
if (-not (Check-Converged @(1,2,3,4,5) "post-load")) { exit 1 }

Write-Host "-- restart node3 --"
Stop-Node 3; Start-Sleep -Seconds 2
Start-Node 3 44001 44101 "127.0.0.1:42001" $null
if (-not (Wait-Up 3)) { Write-Host "FAIL: node3 restart"; exit 1 }
Start-Sleep -Seconds 15
if (-not (Check-Converged @(1,2,3,4,5) "post-restart")) { exit 1 }

Write-Host "-- node5 offline pendant la charge --"
Stop-Node 5; Start-Sleep -Seconds 2
for ($i = 0; $i -lt $LoadTxs; $i++) {
    & $exe send $addr2 100 10 --rpc-url "http://127.0.0.1:42101" --wallet $w2 --password $PW 2>&1 | Out-Null
    & $exe send $addr3 100 10 --rpc-url "http://127.0.0.1:43101" --wallet $w3 --password $PW 2>&1 | Out-Null
}
Write-Host "  $LoadTxs txs envoyes pendant l absence de node5"
Start-Node 5 46001 46101 "127.0.0.1:42001" $null
if (-not (Wait-Up 5)) { Write-Host "FAIL: node5 restart"; exit 1 }
Start-Sleep -Seconds 20
if (-not (Check-Converged @(1,2,3,4,5) "post-resync")) { exit 1 }

Write-Host "=================================================="
Write-Host "RESULTAT 5-NODE SMOKE : PASS"
exit 0
} finally {
    Stop-AllNodes
}