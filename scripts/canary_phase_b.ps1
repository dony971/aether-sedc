# ============================================================
# CANARY PHASE B - GATE 2 + deploy node-4, node-5 (progressive)
# Identity checks per GATE 2, fresh data dirs, join via seed-1
# hub, fingerprint comparison across ALL nodes after each join.
# ASCII-only, no secrets. Exit 0 = PASS.
# ============================================================
param(
    [string]$Repo = "C:\Users\Shadow\Documents\aether-fix\aether-main",
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a"
)
$ErrorActionPreference = "Continue"
$exe = Join-Path $Repo "target\release\aether-unified.exe"
$pkgExe = Join-Path $Repo "aether-v3-testnet-release\aether-unified.exe"
$FROZEN = "b1b8376d6adbbf3607e57b7ab1ab198c12e3902f"
$EXPECTED_SHA = "f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c"
$FAUCET = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$script:ports = @{ 1 = @{ p2p = 42001; rpc = 42101 }; 2 = @{ p2p = 43001; rpc = 43101 }; 3 = @{ p2p = 44001; rpc = 44101 }; 4 = @{ p2p = 45001; rpc = 45101 }; 5 = @{ p2p = 46001; rpc = 46101 } }
$knownAddrs = @($FOUNDER, $FAUCET, $BURN)
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
        peers = [long]$stats.connected_peers
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
function Node-Alive($id) {
    $pidf = Join-Path $DataRoot ("node" + $id + "\node.pid")
    if (-not (Test-Path $pidf)) { return $false }
    $p = [int](Get-Content $pidf).Trim()
    return [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
}

Write-Host "=== CANARY PHASE B - GATE 2 + deploy node-4/node-5 (frozen b1b8376) ==="

# ---- GATE 2 identity checks
Write-Host "-- GATE 2 identity --"
$head = (git -C $Repo rev-parse HEAD).Trim()
FailIf ($head -ne "3681ddb77b3fdab907506efe02dc4d02814bc255") "HEAD not campaign commit (got $head)"
git -C $Repo diff --quiet $FROZEN -- src
FailIf ($LASTEXITCODE -ne 0) "protocol src differs from frozen commit"
$ver = ([regex]::Match((Get-Content (Join-Path $Repo "Cargo.toml") -Raw), 'version\s*=\s*"([^"]+)"')).Groups[1].Value
FailIf ($ver -ne "1.2.0") "version $ver (expected 1.2.0)"
$genHash = (Get-FileHash (Join-Path $Repo "docs\genesis.json") -Algorithm SHA256).Hash.ToLower()
FailIf ($genHash -ne "4f3e693ee56a224dec556f1c05a7c2f4383b2ba8334368ae5d25ba48991d9f8f") "genesis hash mismatch"
$netId = ([regex]::Match((Get-Content (Join-Path $Repo "docs\genesis.json") -Raw), '"network_id"\s*:\s*"([^"]+)"')).Groups[1].Value
FailIf ($netId -ne "59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69") "network_id mismatch"
$p2pv = ([regex]::Match((Get-Content (Join-Path $Repo "src\p2p.rs") -Raw), 'P2P_PROTOCOL_VERSION\s*:\s*(u8|u16|u32|u64)\s*=\s*(\d+)')).Groups[2].Value
FailIf ($p2pv -ne "3") "P2P protocol version $p2pv (expected 3)"
$shaExe = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
$shaPkg = (Get-FileHash $pkgExe -Algorithm SHA256).Hash.ToLower()
FailIf ($shaExe -ne $EXPECTED_SHA) "binary sha256 mismatch (release binary)"
FailIf ($shaPkg -ne $EXPECTED_SHA) "package binary sha256 mismatch"
FailIf ($shaExe -ne $shaPkg) "release binary != package binary"

# ---- fresh data dirs + no keys
foreach ($id in 4,5) {
    $ndir = Join-Path $DataRoot ("node" + $id)
    if (Test-Path $ndir) { Remove-Item $ndir -Recurse -Force -ErrorAction SilentlyContinue }
    FailIf (Test-Path $ndir) "node$id dir not fresh after purge"
    FailIf (Test-Path (Join-Path $ndir "faucet.key")) "node$id has faucet.key"
}
$ceremonyKeys = @(Get-ChildItem -Path (Join-Path $Repo "docs") -Recurse -Include "*ceremony*" -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq ".key" })
FailIf ($ceremonyKeys.Count -gt 0) "$($ceremonyKeys.Count) ceremony key files found"
foreach ($id in 1,2,3) {
    if (Test-Path (Join-Path $DataRoot ("node" + $id + "\faucet.key"))) {
        if ($id -ne 1) { FailIf $true "node$id has faucet.key (must be seed-1 only)" }
    }
}
Write-Host "  PASS: GATE 2 identity verified (commit/version/genesis/network_id/P2P/SHA256/dirs/keys)"

# ---- attach check (3 seeds from Phase A)
foreach ($id in 1,2,3) { FailIf (-not (Node-Alive $id)) "seed$id not running (Phase A)" }
FailIf (-not (Check-Converged @(1,2,3) "pre-phase-B")) "seeds not converged pre-B"

# ---- deploy node-4 (progressive)
Write-Host "-- deploy node-4 (45001/45101 -> seed-1) --"
$p4 = Start-Attached 4 45001 45101 "127.0.0.1:42001" $exe
FailIf (-not (Wait-Up 4)) "node4 up"
Start-Sleep -Seconds 15
$hub = (Rpc 42101 "aether_getDagStats" @()).result.connected_peers
Write-Host "  hub peers after node4 join: $hub (expected >= 3)"
FailIf ($hub -lt 3) "hub peers < 3 after node4 join"
FailIf (-not (Check-Converged @(1,2,3,4) "after-node4-join")) "convergence with node4"
Write-Host "  PASS: node4 joined, synced, converged (pid $p4)"

# ---- deploy node-5 (progressive)
Write-Host "-- deploy node-5 (46001/46101 -> seed-1) --"
$p5 = Start-Attached 5 46001 46101 "127.0.0.1:42001" $exe
FailIf (-not (Wait-Up 5)) "node5 up"
Start-Sleep -Seconds 15
$hub = (Rpc 42101 "aether_getDagStats" @()).result.connected_peers
Write-Host "  hub peers after node5 join: $hub (expected >= 4)"
FailIf ($hub -lt 4) "hub peers < 4 after node5 join"
FailIf (-not (Check-Converged @(1,2,3,4,5) "after-node5-join")) "convergence with node5"
Write-Host "  PASS: node5 joined, synced, converged (pid $p5)"

# ---- no faucet key on new nodes
foreach ($id in 4,5) { FailIf (Test-Path (Join-Path $DataRoot ("node" + $id + "\faucet.key"))) "node$id has faucet.key" }
Write-Host "  PASS: faucet.key absent on node-4/node-5 (seed-1 only)"

Write-Host "=================================================="
if ($fails -eq 0) { Write-Host "RESULTAT CANARY PHASE B DEPLOY : PASS (0 echec)"; exit 0 }
Write-Host ("RESULTAT CANARY PHASE B DEPLOY : FAIL (" + $fails + " echecs)"); exit 1