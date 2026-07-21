param(
    [string]$AetherBin = "target/debug/aether.exe"
)

$ErrorActionPreference = "Stop"

# Colors
function Write-TestPass { Write-Host "[PASS]" -ForegroundColor Green -NoNewline; Write-Host " $args" }
function Write-TestFail { Write-Host "[FAIL]" -ForegroundColor Red -NoNewline; Write-Host " $args"; $script:failed = $true }
function Write-Info { Write-Host "[INFO]" -ForegroundColor Cyan -NoNewline; Write-Host " $args" }

$failed = $false
$nodes = @()
$logDir = "multi-node-logs"
Remove-Item $logDir -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# Clean data dirs
foreach ($d in "data-bootnode","data-miner-1","data-miner-2") {
    Remove-Item $d -Recurse -ErrorAction SilentlyContinue
}

function Start-Node($name, $p2pPort, $rpcPort, $bootnodes = "") {
    $log = "$logDir/$name"
    $args = @("--node-type","miner","--data-dir","data-$name","--p2p-port","$p2pPort","--rpc-port","$rpcPort")
    if ($bootnodes) { $args += @("--bootnodes", $bootnodes) }
    $env:RUST_LOG = "info"
    $proc = Start-Process -FilePath $AetherBin -ArgumentList $args -WindowStyle Hidden -PassThru -RedirectStandardOutput "$log.out" -RedirectStandardError "$log.err"
    return @{Name=$name; P2pPort=$p2pPort; RpcPort=$rpcPort; Proc=$proc; Log=$log}
}

function Wait-Rpc($node, $timeoutSeconds = 30) {
    $url = "http://127.0.0.1:$($node.RpcPort)"
    $body = '{"jsonrpc":"2.0","method":"aether_getDagStats","params":[],"id":1}'
    for ($i = 0; $i -lt $timeoutSeconds; $i++) {
        try {
            $r = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Body $body -ErrorAction SilentlyContinue
            if ($r.result) { return $true }
        } catch {}
        Start-Sleep 1
    }
    return $false
}

function Rpc-Call($node, $method, $params = @()) {
    $url = "http://127.0.0.1:$($node.RpcPort)"
    $body = @{jsonrpc="2.0"; method=$method; params=$params; id=1} | ConvertTo-Json -Compress
    try {
        $r = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Body $body
        return $r.result
    } catch {
        return $null
    }
}

# ──────────────────────────────────────────────
Write-Info "=== Aether Multi-Node Integration Test ==="
Write-Info "Binary: $AetherBin`n"

# ── Step 1: Start bootnode ──
Write-Info "Starting bootnode (P2P:25565 RPC:9933)..."
$boot = Start-Node "bootnode" 25565 9933
$nodes += $boot
if (-not (Wait-Rpc $boot)) { Write-TestFail "Bootnode RPC not ready"; exit 1 }
Write-TestPass "Bootnode ready"

# ── Step 2: Start miner 1 ──
Write-Info "Starting miner1 (P2P:25566 RPC:9934, bootnode=127.0.0.1:25565)..."
$m1 = Start-Node "miner-1" 25566 9934 "127.0.0.1:25565"
$nodes += $m1
if (-not (Wait-Rpc $m1)) { Write-TestFail "Miner1 RPC not ready"; exit 1 }
Write-TestPass "Miner1 ready"

# ── Step 3: Start miner 2 ──
Write-Info "Starting miner2 (P2P:25567 RPC:9935, bootnode=127.0.0.1:25565)..."
$m2 = Start-Node "miner-2" 25567 9935 "127.0.0.1:25565"
$nodes += $m2
if (-not (Wait-Rpc $m2)) { Write-TestFail "Miner2 RPC not ready"; exit 1 }
Write-TestPass "Miner2 ready"

# ── Step 4: Wait for P2P connections ──
Write-Info "Waiting 15s for P2P connections..."
Start-Sleep 15

# ── Step 5: Check peer counts ──
Write-Info "Checking peer counts..."
$minPeers = 1
foreach ($node in $nodes) {
    $stats = Rpc-Call $node "aether_getDagStats"
    if ($stats -and $stats.peer_count -ge $minPeers) {
        Write-TestPass "$($node.Name): $($stats.peer_count) peers"
    } else {
        Write-TestFail "$($node.Name): peer_count=$($stats.peer_count), expected >= $minPeers"
    }
}

# ── Step 6: Submit transaction via faucet on miner1 ──
Write-Info "Submitting faucet transaction on miner1..."
$faucetResult = Rpc-Call $m1 "aether_faucet" @("127.0.0.1:9934")
if ($faucetResult -and $faucetResult.status -eq "ok") {
    Write-TestPass "Faucet transaction submitted: tx_hash=$($faucetResult.tx_hash)"
    $txHash = $faucetResult.tx_hash
} else {
    Write-TestFail "Faucet failed: $($faucetResult | ConvertTo-Json)"
}

# ── Step 7: Wait for P2P propagation ──
Write-Info "Waiting 10s for P2P propagation..."
Start-Sleep 10

# ── Step 8: Verify transaction propagated ──
if ($txHash) {
    Write-Info "Checking transaction propagation..."
    foreach ($node in $nodes) {
        $stats = Rpc-Call $node "aether_getDagStats"
        if ($stats -and $stats.transaction_count -ge 1) {
            Write-TestPass "$($node.Name): transaction propagated (tx_count=$($stats.transaction_count))"
        } else {
            Write-TestFail "$($node.Name): transaction NOT found (tx_count=$($stats.transaction_count))"
        }
    }
}

# ── Step 9: Check all nodes still alive ──
Write-Info "Checking node health..."
foreach ($node in $nodes) {
    if ($node.Proc.HasExited) {
        Write-TestFail "$($node.Name): process exited unexpectedly (exit code $($node.Proc.ExitCode))"
    } else {
        Write-TestPass "$($node.Name): alive"
    }
}

# ── Cleanup ──
Write-Info "Stopping all nodes..."
foreach ($node in $nodes) {
    if (-not $node.Proc.HasExited) { $node.Proc.Kill() }
}

# ── Summary ──
Write-Host ""
if ($failed) {
    Write-Host "=== SOME TESTS FAILED ===" -ForegroundColor Red
    Write-Host "Check logs in $logDir/ for details"
    exit 1
} else {
    Write-Host "=== ALL TESTS PASSED ===" -ForegroundColor Green
    exit 0
}
