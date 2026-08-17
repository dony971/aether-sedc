param([int]$Runs = 1, [string]$Only = "")
$ErrorActionPreference = "Continue"

$exe = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe"
$root = "C:\Users\Shadow\AppData\Local\Temp\opencode\aether-net2"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dir = Join-Path $root $stamp
New-Item -ItemType Directory -Path $dir | Out-Null

$script:addrs = @{}
$script:knownAddrs = @()
$script:procs = @{}
$script:nodePorts = @{}
$script:nodeDirs = @{}
$script:failed = @()
$script:assertions = 0
$PW = "pwtest123"

# Genesis addresses and faucet seed come from the ENVIRONMENT (ceremony step 2),
# never hardcoded. The harness FAILS if they are missing.
$FOUNDER = $env:AETHER_FOUNDER
$FAUCET  = $env:AETHER_FAUCET
$BURN    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$FAUCET_SEED = $env:AETHER_FAUCET_SEED
if (-not $FOUNDER -or -not $FAUCET -or -not $FAUCET_SEED) {
    throw "Missing ceremony environment: AETHER_FOUNDER, AETHER_FAUCET, AETHER_FAUCET_SEED must be set"
}

# genesis + burn accounts are part of the absolute invariant
$script:knownAddrs = @($FOUNDER, $FAUCET, $BURN)

function Sha256Hex($s) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ($h | ForEach-Object { $_.ToString("x2") }) -join ""
}

function HexId($arr) {
    ($arr | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Rpc($port, $method, $params) {
    $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 6
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 60
    return $resp
}

function Start-Node($id, $p2p, $rpc, $bootnode, $faucetSeed, $tag) {
    $ndir = Join-Path $dir "$tag\node$id"
    New-Item -ItemType Directory -Path $ndir -Force | Out-Null
    if ($faucetSeed) { Set-Content -Path (Join-Path $ndir "faucet.key") -Value $faucetSeed -NoNewline }
    $args = @("--node-type","observer","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc","--bootnodes",$bootnode)
    $p = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $dir "$tag\node$id.out.log") -RedirectStandardError (Join-Path $dir "$tag\node$id.err.log")
    $script:procs[$id] = $p
    $script:nodePorts[$id] = @{ p2p = $p2p; rpc = $rpc }
    $script:nodeDirs[$id] = $ndir
}

function Wait-NodeUp($id, $timeoutSec = 120) {
    $rpc = $script:nodePorts[$id].rpc
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not $script:procs[$id].HasExited) {
            try {
                $r = Rpc $rpc "aether_getDagStats" @()
                if ($null -ne $r.result.total_transactions) { return $true }
            } catch {}
        } else { return $false }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-Peers($id, $min, $timeoutSec = 90) {
    $rpc = $script:nodePorts[$id].rpc
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Rpc $rpc "aether_getDagStats" @()
            if ($r.result.connected_peers -ge $min) { return $r.result.connected_peers }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    return -1
}

function New-Wallet($name) {
    $wpath = Join-Path $dir "$name.json"
    $out = "$PW`n" | & $exe wallet create $wpath 2>&1 | Out-String
    $m = [regex]::Match($out, "Address: ([0-9a-fA-F]{64})")
    if (-not $m.Success) {
        $out2 = & $exe balance $wpath --rpc-url "http://127.0.0.1:$($script:nodePorts[1].rpc)" --password $PW 2>&1 | Out-String
        $m = [regex]::Match($out2, "Address: ([0-9a-fA-F]{64})")
        if (-not $m.Success) { throw "wallet create failed for $name : $out / $out2" }
    }
    $script:addrs[$name] = $m.Groups[1].Value.ToLower()
    $script:knownAddrs += $script:addrs[$name]
    Write-Output "  wallet $name = $($script:addrs[$name])"
}

function Faucet($id, $addr) {
    $rpc = $script:nodePorts[$id].rpc
    for ($try = 1; $try -le 6; $try++) {
        $r = Rpc $rpc "aether_faucet" @($addr)
        if (-not $r.error) { return }
        $msg = "$($r.error.message)"
        $transient = ($msg -match "Rate limited") -or ($msg -match "cooldown")
        if (-not $transient) { Write-Host "  faucet error: $msg"; return }
        if ($try -lt 6) { Start-Sleep -Seconds 5 }
    }
    Write-Host "  faucet gave up after retries: $($r.error.message)"
}

function Send-Tx($id, $walletName, $receiverName, $amount, $fee = 10) {
    # H3 hardening (2026-08): the node rate-limits RPC per (IP, method) at
    # 40 req / 10s window. The harness's own polling + assertions share the
    # 127.0.0.1 budget with the CLI, so a send may be transiently rejected.
    # Retry with a backoff that lets the window slide instead of failing.
    $rpc = $script:nodePorts[$id].rpc
    $wpath = Join-Path $dir "$walletName.json"
    $recv = $script:addrs[$receiverName]
    $lastOut = ""
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $out = & $exe send $recv $amount $fee --rpc-url "http://127.0.0.1:$rpc" --wallet $wpath --password $PW 2>&1 | Out-String
        $lastOut = $out
        if ($out -match "Transaction sent") {
            Set-Content -Path (Join-Path $dir "tx_${walletName}_${receiverName}_$amount.log") -Value $out -Encoding utf8
            return $true
        }
        $rateLimited = ($out -match "Rate limited") -or ($out -match "extract next_nonce")
        if (-not $rateLimited) { break }
        if ($attempt -lt 12) { Start-Sleep -Seconds 3 }
    }
    Set-Content -Path (Join-Path $dir "tx_${walletName}_${receiverName}_$amount.log") -Value $lastOut -Encoding utf8
    Write-Host "  SEND FAILED ${walletName}->${receiverName}: $($lastOut.Trim() -replace '\s+',' ')"
    return $false
}

function Send-Async($id, $walletName, $receiverName, $amount, $fee = 10, $tag = "") {
    $rpc = $script:nodePorts[$id].rpc
    $wpath = Join-Path $dir "$walletName.json"
    $recv = $script:addrs[$receiverName]
    $suffix = if ($tag) { "_$tag" } else { "" }
    $args = @("send", $recv, "$amount", "$fee", "--rpc-url", "http://127.0.0.1:$rpc", "--wallet", $wpath, "--password", $PW)
    $p = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $dir "send_${walletName}_${receiverName}$suffix.log") `
        -RedirectStandardError (Join-Path $dir "send_${walletName}_${receiverName}$suffix.err.log")
    return $p
}

function Wait-AllSends($procs, $timeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    foreach ($p in $procs) {
        while (-not $p.HasExited) {
            if ((Get-Date) -gt $deadline) { return $false }
            Start-Sleep -Milliseconds 200
        }
    }
    return $true
}

function Stop-Node($id) {
    if ($script:procs[$id] -and -not $script:procs[$id].HasExited) {
        Stop-Process -Id $script:procs[$id].Id -Force -ErrorAction SilentlyContinue
    }
}

function Stop-AllNodes {
    foreach ($id in $script:procs.Keys) {
        if (-not $script:procs[$id].HasExited) { Stop-Process -Id $script:procs[$id].Id -Force -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Seconds 2
}

function Wait-Converged($ids, $timeoutSec = 240) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $last = -1
    while ((Get-Date) -lt $deadline) {
        $counts = @(); $allUp = $true
        foreach ($id in $ids) {
            try {
                $r = Rpc $script:nodePorts[$id].rpc "aether_getDagStats" @()
                $counts += [int]$r.result.total_transactions
            } catch { $allUp = $false }
        }
        if ($allUp) {
            $unique = $counts | Sort-Object -Unique
            if ($unique.Count -eq 1) { $last = $unique[0]; Start-Sleep -Seconds 2; return $last }
        }
        Start-Sleep -Seconds 2
    }
    return $last
}

# ==================== ABSOLUTE INVARIANT ====================
function Get-FullState($id) {
    $rpc = $script:nodePorts[$id].rpc
    $graph = (Rpc $rpc "aether_getDagGraph" @()).result
    $stats = (Rpc $rpc "aether_getDagStats" @()).result
    $tips = @((Rpc $rpc "aether_getTips" @()).result.tips | Sort-Object)

$txs = @()
    foreach ($n in $graph.nodes) { $txs += HexId $n.tx_id }
    $edges = @()
    foreach ($e in $graph.edges) { $edges += "$(HexId $e.from)->$(HexId $e.to)" }
    $weights = @()
    foreach ($n in $graph.nodes) { $weights += "$(HexId $n.tx_id):$($n.weight)" }
    $weightsSorted = $weights | Sort-Object
    $h_weights = Sha256Hex ($weightsSorted -join ",")

    $ledgerEntries = @()
    $supply = [decimal]0
    $degraded = $false
    foreach ($addr in $script:knownAddrs) {
$b = $null; $n = $null
        for ($try = 1; $try -le 6 -and ($null -eq $b); $try++) {
            $resp = Rpc $rpc "aether_getBalance" @($addr)
            $b = $resp.result.balance
            if ($null -eq $b -and $try -lt 6) { Start-Sleep -Seconds 12 }
        }
        for ($try = 1; $try -le 6 -and ($null -eq $n); $try++) {
            $resp = Rpc $rpc "aether_getAccountNonce" @($addr)
            $n = $resp.result.next_nonce
            if ($null -eq $n -and $try -lt 6) { Start-Sleep -Seconds 12 }
        }
        if ($null -eq $b -or $null -eq $n) {
            $degraded = $true
            $b = 0; $n = 0
        }
        $supply += [decimal]$b
        $ledgerEntries += "${addr}:${b}:${n}"
    }

    $txSetSorted  = $txs   | Sort-Object
    $edgesSorted  = $edges | Sort-Object
    $ledgerSorted = $ledgerEntries | Sort-Object

$h_txset  = Sha256Hex ($txSetSorted  -join ",")
    $h_dag    = Sha256Hex (($txSetSorted -join ",") + "|" + ($edgesSorted -join ","))
    $h_tips   = Sha256Hex ($tips -join ",")
    $h_ledger = Sha256Hex ($ledgerSorted -join ",")
    $h_weights = Sha256Hex ($weightsSorted -join ",")

    return @{
        degraded     = $degraded
        total        = [int]$stats.total_transactions
        tip_count    = [int]$stats.tip_count
        epoch        = [int]$stats.epoch
        peers        = [int]$stats.connected_peers
        tx_count     = $txs.Count
        edge_count   = $edges.Count
        tips         = $tips
        h_txset      = $h_txset
        h_dag        = $h_dag
        h_tips       = $h_tips
        h_ledger     = $h_ledger
        h_weights    = $h_weights
        supply       = $supply
        balances     = @($ledgerSorted)
        fingerprint  = Sha256Hex ($h_txset + $h_dag + $h_tips + $h_ledger + $h_weights + $supply.ToString())
    }
}

function Assert-Invariant($ids, $name) {
    $states = @{}
    foreach ($id in $ids) { $states[$id] = Get-FullState $id }
    $ref = $states[$ids[0]]
    foreach ($id in $ids) {
        if ($states[$id].degraded) {
            Write-Output "  MISMATCH[$name] node$id ledger read degraded (rate limit) - not a clean state"
        }
    }
    if (($states.Values | Where-Object { $_.degraded }).Count -gt 0) {
        Write-Output "  FAIL $name (degraded reads)"
        $script:failed += "$name-degraded"
        return
    }
    $ok = $true
    foreach ($id in $ids[1..($ids.Count - 1)]) {
        $s = $states[$id]
        if ($s.total -ne $ref.total) { $ok = $false; Write-Output "  MISMATCH[$name] total node$id=$($s.total) ref=$($ref.total)" }
        if ($s.fingerprint -ne $ref.fingerprint) {
            $ok = $false
            Write-Output "  MISMATCH[$name] STATE HASH node$id=$($s.fingerprint) ref=$($ref.fingerprint)"
            if ($s.h_txset -ne $ref.h_txset) { Write-Output "    txset differs (node$id=$($s.tx_count) ref=$($ref.tx_count))" }
            if ($s.h_dag -ne $ref.h_dag) { Write-Output "    DAG structure differs (edges node$id=$($s.edge_count) ref=$($ref.edge_count))" }
            if ($s.h_weights -ne $ref.h_weights) { Write-Output "    WEIGHTS differ (node$id)" }
            if ($s.h_tips -ne $ref.h_tips) { Write-Output "    tips differ: [$($s.tips -join ',')] vs [$($ref.tips -join ',')]" }
            if ($s.h_ledger -ne $ref.h_ledger) {
                Write-Output "    ledger hash differs (supply node$id=$($s.supply) ref=$($ref.supply))"
                foreach ($entry in $s.balances) {
                    if ($entry -notin $ref.balances) { Write-Output "    ledger entry only on node${id}: $entry" }
                }
                foreach ($entry in $ref.balances) {
                    if ($entry -notin $s.balances) { Write-Output "    ledger entry missing on node${id}: $entry" }
                }
            }
        }
    }
    $script:assertions++
    if ($ok) {
        Write-Output "  PASS $name (tx=$($ref.total) tips=$($ref.tip_count) peers=$($ref.peers) epoch=$($ref.epoch) supply=$($ref.supply))"
    } else {
        Write-Output "  FAIL $name"
        $script:failed += $name
    }
}

# ==================== S1 : 2 noeuds, 20 txs ====================
function Scenario-S1 {
    Write-Output "=== S1: 2 nodes, 20 txs ==="
    Start-Node 1 42001 42101 "127.0.0.1:1" $FAUCET_SEED "s1"
    Start-Node 2 42002 42102 "127.0.0.1:42001" $null "s1"
    foreach ($id in 1,2) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S1-start"; Stop-AllNodes; return } }
    Wait-Peers 1 1 | Out-Null

    foreach ($w in "A","B","C","D","E") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 3
    Assert-Invariant @(1,2) "S1 faucet (5)"

    $seq = @(
        @(1,"A","B",100000000), @(2,"B","C",50000000), @(1,"C","D",20000000),
        @(2,"D","E",10000000), @(1,"E","A",80000000), @(2,"A","C",30000000),
        @(1,"B","D",40000000), @(2,"C","E",60000000), @(1,"D","A",15000000),
        @(2,"E","B",25000000), @(1,"A","D",70000000), @(2,"B","E",90000000),
        @(1,"C","A",12000000), @(2,"D","B",18000000), @(1,"E","C",22000000)
    )
    foreach ($s in $seq) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2)
    Write-Output "  converged tx=$t (expected 20)"
    Assert-Invariant @(1,2) "S1 20 txs"
    Stop-AllNodes
    Write-Output "=== S1 done ==="
}

# ==================== S2 : 3 noeuds, 30 txs, kill node3 puis restart ====================
function Scenario-S2 {
    Write-Output "=== S2: 3 nodes, 30 txs, kill node3 mid-load + restart (V-22) ==="
    Start-Node 1 43001 43101 "127.0.0.1:1" $FAUCET_SEED "s2"
    Start-Node 2 43002 43102 "127.0.0.1:43001" $null "s2"
    Start-Node 3 43003 43103 "127.0.0.1:43001" $null "s2"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S2-start"; Stop-AllNodes; return } }
    Wait-Peers 1 2 | Out-Null

    foreach ($w in "A","B","C","D","E","F") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E","F") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 4
    Assert-Invariant @(1,2,3) "S2 faucet (6)"

    $seq = @(
        @(1,"A","B",100000000), @(2,"B","C",50000000), @(3,"C","D",20000000),
        @(1,"D","E",10000000), @(2,"E","F",80000000), @(3,"F","A",30000000),
        @(1,"A","C",40000000), @(2,"B","D",60000000), @(3,"C","E",15000000),
        @(1,"D","F",25000000), @(2,"E","A",70000000), @(3,"F","B",90000000)
    )
    foreach ($s in $seq) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2,3)
    Write-Output "  phase1 tx=$t (expected 18)"
    Assert-Invariant @(1,2,3) "S2 phase1 (18 txs)"

    Write-Output "  KILL node3"
    Stop-Node 3
    Start-Sleep -Seconds 2

    $seq2 = @(
        @(1,"F","C",12000000), @(2,"A","D",18000000), @(1,"B","E",22000000),
        @(2,"C","F",35000000), @(1,"D","A",45000000), @(2,"E","B",55000000),
        @(1,"F","A",65000000), @(2,"A","B",75000000), @(1,"B","C",85000000),
        @(2,"C","D",95000000), @(1,"D","E",11000000), @(2,"E","F",21000000)
    )
    foreach ($s in $seq2) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2)
    Write-Output "  phase2 tx=$t (node3 down, expected 30)"
    Assert-Invariant @(1,2) "S2 phase2 (30 txs, node3 down)"

    Write-Output "  RESTART node3 (must full-sync)"
    Start-Node 3 43003 43103 "127.0.0.1:43001" $null "s2"
    if (-not (Wait-NodeUp 3)) { Write-Output "  FAIL: node3 restart never up"; $script:failed += "S2-restart"; Stop-AllNodes; return }
    $t = Wait-Converged @(1,2,3) 300
    Write-Output "  converged tx=$t"
    if ($t -lt 30) { Write-Output "  FAIL: node3 did not catch up (tx=$t)"; $script:failed += "S2-resync" }
    Assert-Invariant @(1,2,3) "S2 after restart"
    Stop-AllNodes
    Write-Output "=== S2 done ==="
}

# ==================== S3 : 3 noeuds, kill node2 apres quelques txs, restart ====================
function Scenario-S3 {
    Write-Output "=== S3: 3 nodes, kill node2 early, restart mid-stream ==="
    Start-Node 1 44001 44101 "127.0.0.1:1" $FAUCET_SEED "s3"
    Start-Node 2 44002 44102 "127.0.0.1:44001" $null "s3"
    Start-Node 3 44003 44103 "127.0.0.1:44001" $null "s3"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S3-start"; Stop-AllNodes; return } }
    Wait-Peers 1 2 | Out-Null

    foreach ($w in "A","B","C","D","E","F") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E","F") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 4
    Assert-Invariant @(1,2,3) "S3 faucet (6)"

    Send-Tx 1 "A" "B" 100000000; Send-Tx 3 "B" "C" 50000000; Send-Tx 2 "C" "D" 20000000
    $t = Wait-Converged @(1,2,3)
    Write-Output "  pre-kill tx=$t (expected 9)"
    Assert-Invariant @(1,2,3) "S3 pre-kill (9 txs)"

    Write-Output "  KILL node2"
    Stop-Node 2
    Start-Sleep -Seconds 2

    $seq = @(
        @(1,"D","E",10000000), @(3,"E","F",80000000), @(1,"F","A",30000000),
        @(3,"A","C",40000000), @(1,"B","D",60000000), @(3,"C","E",15000000),
        @(1,"D","F",25000000), @(3,"E","A",70000000), @(1,"F","B",90000000),
        @(3,"A","D",12000000), @(1,"B","E",18000000), @(3,"C","F",22000000)
    )
    foreach ($s in $seq) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,3)
    Write-Output "  mid tx=$t (node2 down, expected 21)"

    Write-Output "  RESTART node2"
    Start-Node 2 44002 44102 "127.0.0.1:44001" $null "s3"
    if (-not (Wait-NodeUp 2)) { Write-Output "  FAIL: node2 restart never up"; $script:failed += "S3-restart"; Stop-AllNodes; return }

    $seq2 = @(
        @(3,"C","A",65000000), @(1,"D","B",75000000), @(3,"E","C",85000000),
        @(1,"F","D",95000000), @(3,"A","E",11000000), @(1,"B","F",21000000),
        @(3,"C","D",31000000), @(1,"D","E",41000000), @(3,"E","F",51000000)
    )
    foreach ($s in $seq2) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2,3) 300
    Write-Output "  converged tx=$t (expected 30)"
    Assert-Invariant @(1,2,3) "S3 after restart (30 txs)"
    Stop-AllNodes
    Write-Output "=== S3 done ==="
}

# ==================== S4 : 4 noeuds, 50 txs, deconnecter/connecter node4 ====================
function Scenario-S4 {
    Write-Output "=== S4: 4 nodes, 50 txs, disconnect+reconnect node4 ==="
    Start-Node 1 45001 45101 "127.0.0.1:1" $FAUCET_SEED "s4"
    foreach ($id in 2,3,4) { Start-Node $id (45000 + $id) (45100 + $id) "127.0.0.1:45001" $null "s4" }
    foreach ($id in 1,2,3,4) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S4-start"; Stop-AllNodes; return } }
    Wait-Peers 1 3 | Out-Null

    foreach ($w in "A","B","C","D","E","F","G","H") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E","F","G","H") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 5
    Assert-Invariant @(1,2,3,4) "S4 faucet (8)"

    $seq = @(
        @(1,"A","B",100000000), @(2,"B","C",50000000), @(3,"C","D",20000000), @(4,"D","E",10000000),
        @(1,"E","F",80000000), @(2,"F","G",30000000), @(3,"G","H",40000000), @(4,"H","A",60000000),
        @(1,"A","C",15000000), @(2,"B","D",25000000), @(3,"C","E",70000000), @(4,"D","F",90000000),
        @(1,"E","G",12000000), @(2,"F","H",18000000), @(3,"G","A",22000000), @(4,"H","B",35000000)
    )
    foreach ($s in $seq) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2,3,4)
    Write-Output "  phase1 tx=$t (expected 24)"
    Assert-Invariant @(1,2,3,4) "S4 phase1 (24 txs)"

    Write-Output "  DISCONNECT node4 (kill)"
    Stop-Node 4
    Start-Sleep -Seconds 2

    $seq2 = @(
        @(1,"A","D",45000000), @(2,"B","E",55000000), @(3,"C","F",65000000),
        @(1,"D","G",75000000), @(2,"E","H",85000000), @(3,"F","A",95000000),
        @(1,"G","B",11000000), @(2,"H","C",21000000), @(3,"A","E",31000000),
        @(1,"B","F",41000000), @(2,"C","G",51000000), @(3,"D","H",61000000),
        @(1,"E","A",71000000), @(2,"F","B",81000000), @(3,"G","C",91000000),
        @(1,"H","D",13000000), @(2,"A","F",23000000), @(3,"B","G",33000000),
        @(1,"C","H",43000000), @(2,"D","A",53000000), @(3,"E","B",63000000),
        @(1,"F","C",73000000), @(2,"G","D",83000000), @(3,"H","E",93000000),
        @(1,"A","G",14000000), @(2,"B","H",24000000)
    )
    foreach ($s in $seq2) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2,3)
    Write-Output "  phase2 tx=$t (node4 down, expected 50)"
    Assert-Invariant @(1,2,3) "S4 phase2 (50 txs, node4 down)"

    Write-Output "  RECONNECT node4"
    Start-Node 4 45004 45104 "127.0.0.1:45001" $null "s4"
    if (-not (Wait-NodeUp 4)) { Write-Output "  FAIL: node4 restart never up"; $script:failed += "S4-restart"; Stop-AllNodes; return }
    $t = Wait-Converged @(1,2,3,4) 300
    Write-Output "  converged tx=$t"
    if ($t -lt 50) { Write-Output "  FAIL: node4 did not catch up (tx=$t)"; $script:failed += "S4-resync" }
    Assert-Invariant @(1,2,3,4) "S4 after reconnect"
    Stop-AllNodes
    Write-Output "=== S4 done ==="
}

# ==================== S5 : 5 noeuds, 100 txs, kill node5 puis restart ====================
function Scenario-S5 {
    Write-Output "=== S5: 5 nodes, 100 txs, kill node5 mid + restart (V-22) ==="
    Start-Node 1 46001 46101 "127.0.0.1:1" $FAUCET_SEED "s5"
    foreach ($id in 2,3,4,5) { Start-Node $id (46000 + $id) (46100 + $id) "127.0.0.1:46001" $null "s5" }
    foreach ($id in 1,2,3,4,5) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S5-start"; Stop-AllNodes; return } }
    Wait-Peers 1 4 | Out-Null

    $names = @("A","B","C","D","E","F","G","H","I","J")
    foreach ($n in $names) { New-Wallet $n }
    foreach ($w in $names) { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 6
    Assert-Invariant @(1,2,3,4,5) "S5 faucet (10)"

    $procs = @()
    for ($i = 0; $i -lt 40; $i++) {
        $from = $names[$i % 10]; $to = $names[($i * 3 + 1) % 10]
        if ($from -eq $to) { $to = $names[($i * 3 + 2) % 10] }
        $node = 1 + ($i % 5)
        if (-not (Send-Tx $node $from $to (10000000 + $i * 1000000) 10)) { $script:failed += "S5-send1-$i" }
    }
    $t = Wait-Converged @(1,2,3,4,5) 300
    Write-Output "  phase1 tx=$t (expected 50)"
    if ($t -ne 50) { Write-Output "  FAIL: expected 50 txs, got $t"; $script:failed += "S5-phase1-count" }
    Assert-Invariant @(1,2,3,4,5) "S5 phase1 (50 txs)"

    Write-Output "  KILL node5"
    Stop-Node 5
    Start-Sleep -Seconds 2

    $procs = @()
    for ($i = 0; $i -lt 50; $i++) {
        $from = $names[($i + 3) % 10]; $to = $names[($i * 5 + 2) % 10]
        if ($from -eq $to) { $to = $names[($i * 5 + 4) % 10] }
        $node = 1 + ($i % 4)
        if (-not (Send-Tx $node $from $to (10000000 + $i * 1500000) 10)) { $script:failed += "S5-send2-$i" }
    }
    $t = Wait-Converged @(1,2,3,4) 300
    Write-Output "  phase2 tx=$t (node5 down, expected 100)"
    if ($t -ne 100) { Write-Output "  FAIL: expected 100 txs, got $t"; $script:failed += "S5-phase2-count" }
    Assert-Invariant @(1,2,3,4) "S5 phase2 (100 txs, node5 down)"

    Write-Output "  RESTART node5 (full sync of 100 txs)"
    Start-Node 5 46005 46105 "127.0.0.1:46001" $null "s5"
    if (-not (Wait-NodeUp 5)) { Write-Output "  FAIL: node5 restart never up"; $script:failed += "S5-restart"; Stop-AllNodes; return }
    $t = Wait-Converged @(1,2,3,4,5) 420
    Write-Output "  converged tx=$t"
    if ($t -lt 100) { Write-Output "  FAIL: node5 did not catch up (tx=$t)"; $script:failed += "S5-resync" }
    Assert-Invariant @(1,2,3,4,5) "S5 after restart"
    Stop-AllNodes
    Write-Output "=== S5 done ==="
}

# ==================== S6 : redemarrage complet du cluster ====================
function Scenario-S6 {
    Write-Output "=== S6: full cluster restart (boot rebuild V-21) ==="
    Start-Node 1 47001 47101 "127.0.0.1:1" $FAUCET_SEED "s6"
    Start-Node 2 47002 47102 "127.0.0.1:47001" $null "s6"
    Start-Node 3 47003 47103 "127.0.0.1:47001" $null "s6"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S6-start"; Stop-AllNodes; return } }
    Wait-Peers 1 2 | Out-Null

    foreach ($w in "A","B","C","D","E","F") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E","F") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 4

    $seq = @(
        @(1,"A","B",100000000), @(2,"B","C",50000000), @(3,"C","D",20000000),
        @(1,"D","E",10000000), @(2,"E","F",80000000), @(3,"F","A",30000000),
        @(1,"A","C",40000000), @(2,"B","D",60000000), @(3,"C","E",15000000),
        @(1,"D","F",25000000), @(2,"E","A",70000000), @(3,"F","B",90000000),
        @(1,"A","D",12000000), @(2,"B","E",18000000), @(3,"C","F",22000000),
        @(1,"D","A",35000000), @(2,"E","B",45000000), @(3,"F","C",55000000),
        @(1,"A","E",65000000), @(2,"B","F",75000000), @(3,"C","D",85000000),
        @(1,"D","B",95000000), @(2,"E","C",11000000), @(3,"F","A",21000000)
    )
    foreach ($s in $seq) { Send-Tx $s[0] $s[1] $s[2] $s[3] }
    $t = Wait-Converged @(1,2,3)
    Write-Output "  pre-restart tx=$t (expected 30)"
    Assert-Invariant @(1,2,3) "S6 pre-restart (30 txs)"

    Write-Output "  KILL ALL nodes"
    Stop-AllNodes
    Start-Sleep -Seconds 3

    Write-Output "  RESTART all nodes (same data dirs)"
    Start-Node 1 47001 47101 "127.0.0.1:1" $FAUCET_SEED "s6"
    Start-Node 2 47002 47102 "127.0.0.1:47001" $null "s6"
    Start-Node 3 47003 47103 "127.0.0.1:47001" $null "s6"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id restart never up"; $script:failed += "S6-restart"; Stop-AllNodes; return } }
    $t = Wait-Converged @(1,2,3) 300
    Write-Output "  converged tx=$t"
    if ($t -lt 30) { Write-Output "  FAIL: cluster did not rebuild (tx=$t)"; $script:failed += "S6-rebuild" }
    Assert-Invariant @(1,2,3) "S6 after full restart"
    Stop-AllNodes
    Write-Output "=== S6 done ==="
}

# ==================== S7 : txs concurrentes simultanees ====================
function Scenario-S7 {
    Write-Output "=== S7: 4 nodes, 30 simultaneous txs ==="
    Start-Node 1 48001 48101 "127.0.0.1:1" $FAUCET_SEED "s7"
    foreach ($id in 2,3,4) { Start-Node $id (48000 + $id) (48100 + $id) "127.0.0.1:48001" $null "s7" }
    foreach ($id in 1,2,3,4) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S7-start"; Stop-AllNodes; return } }
    Wait-Peers 1 3 | Out-Null

    foreach ($w in "A","B","C","D","E","F","G","H") { New-Wallet $w }
    foreach ($w in "A","B","C","D","E","F","G","H") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 5
    Assert-Invariant @(1,2,3,4) "S7 faucet (8)"

    $procs = @()
    for ($i = 0; $i -lt 22; $i++) {
        $from = @("A","B","C","D","E","F","G","H")[$i % 8]
        $to   = @("H","G","F","E","D","C","B","A")[$i % 8]
        if ($from -eq $to) { $to = @("A","B","C","D","E","F","G","H")[($i + 3) % 8] }
        $node = 1 + ($i % 4)
        if (-not (Send-Tx $node $from $to (10000000 + $i * 1000000) 10)) { $script:failed += "S7-send-$i" }
    }
    $t = Wait-Converged @(1,2,3,4) 300
    Write-Output "  converged tx=$t (expected 30)"
    if ($t -ne 30) { Write-Output "  FAIL: expected 30 txs, got $t"; $script:failed += "S7-count" }
    Assert-Invariant @(1,2,3,4) "S7 simultaneous (30 txs)"
    Stop-AllNodes
    Write-Output "=== S7 done ==="
}

# ==================== S8 : double depense fonds insuffisants ====================
function Scenario-S8 {
    Write-Output "=== S8: double spend, insufficient funds ==="
    Start-Node 1 49001 49101 "127.0.0.1:1" $FAUCET_SEED "s8"
    Start-Node 2 49002 49102 "127.0.0.1:49001" $null "s8"
    Start-Node 3 49003 49103 "127.0.0.1:49001" $null "s8"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S8-start"; Stop-AllNodes; return } }
    Wait-Peers 1 2 | Out-Null

    foreach ($w in "A","B","C","D") { New-Wallet $w }
    foreach ($w in "A","B") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 3
    Assert-Invariant @(1,2,3) "S8 faucet (2)"

    # (a) plainly impossible send: amount >> balance -> must be rejected
    $rej = Send-Tx 1 "A" "B" 99999999999999
    if ($rej) { Write-Output "  WARN: impossible send was ACCEPTED (!)" } else { Write-Output "  OK: impossible send rejected" }
    $t = Wait-Converged @(1,2,3)
    Write-Output "  tx after rejected send=$t (must be 2)"
    Assert-Invariant @(1,2,3) "S8 rejected double spend"

    # (b) two parallel spends, each valid alone, BOTH impossible together
    Write-Output "  parallel double spend A->C 6e10 and A->D 6e10"
    $p1 = Send-Async 1 "A" "C" 60000000000
    $p2 = Send-Async 3 "A" "D" 60000000000
    Wait-AllSends @($p1, $p2) | Out-Null
    $t = Wait-Converged @(1,2,3)
    Write-Output "  converged tx=$t (only ONE of the two spends may survive)"
    if ($t -ne 3) { Write-Output "  FAIL: expected exactly 3 txs (2 faucet + 1 survivor), got $t"; $script:failed += "S8-double-spend-count" }
    Assert-Invariant @(1,2,3) "S8 parallel double spend"
    Stop-AllNodes
    Write-Output "=== S8 done ==="
}

# ==================== S9 : double depense concurrente meme nonce ====================
function Scenario-S9 {
    Write-Output "=== S9: concurrent double spend, same nonce ==="
    Start-Node 1 50001 50101 "127.0.0.1:1" $FAUCET_SEED "s9"
    Start-Node 2 50002 50102 "127.0.0.1:50001" $null "s9"
    Start-Node 3 50003 50103 "127.0.0.1:50001" $null "s9"
    foreach ($id in 1,2,3) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S9-start"; Stop-AllNodes; return } }
    Wait-Peers 1 2 | Out-Null

    foreach ($w in "A","B","C","D") { New-Wallet $w }
    foreach ($w in "A","B") { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 3
    Assert-Invariant @(1,2,3) "S9 faucet (2)"

    # 3 sends from SAME wallet fired at the same instant -> same-nonce race
    Write-Output "  3 simultaneous sends from wallet A (same-nonce race)"
    $p1 = Send-Async 1 "A" "B" 10000000
    $p2 = Send-Async 2 "A" "C" 10000000
    $p3 = Send-Async 3 "A" "D" 10000000
    Wait-AllSends @($p1, $p2, $p3) | Out-Null

    $t = Wait-Converged @(1,2,3)
    Write-Output "  converged tx=$t"

    $rpc = $script:nodePorts[1].rpc
    $snap = (Rpc $rpc "aether_getDagSnapshot" @()).result
    $aTxs = @($snap.transactions | Where-Object { $_.sender -eq $script:addrs["A"] })
    $nonces = @($aTxs | ForEach-Object { $_.nonce })
    $dups = @($nonces | Group-Object | Where-Object { $_.Count -gt 1 })
    Write-Output "  wallet A txs in DAG: $($aTxs.Count), nonces: $($nonces -join ',')"
    if ($dups.Count -gt 0) {
        Write-Output "  FAIL: duplicate (sender, nonce) still in the DAG: nonce $($dups[0].Name) used $($dups[0].Count) times"
        $script:failed += "S9-collision-unresolved"
    } else {
        Write-Output "  OK: no duplicate (sender, nonce) in the final DAG (canonical resolution verified)"
    }
    Assert-Invariant @(1,2,3) "S9 concurrent double spend"
    Stop-AllNodes
    Write-Output "=== S9 done ==="
}

# ==================== S10 : charge 200 txs ====================
function Scenario-S10 {
    Write-Output "=== S10: 4 nodes, load 200 txs ==="
    Start-Node 1 51001 51101 "127.0.0.1:1" $FAUCET_SEED "s10"
    foreach ($id in 2,3,4) { Start-Node $id (51000 + $id) (51100 + $id) "127.0.0.1:51001" $null "s10" }
    foreach ($id in 1,2,3,4) { if (-not (Wait-NodeUp $id)) { Write-Output "  FAIL: node$id never up"; $script:failed += "S10-start"; Stop-AllNodes; return } }
    Wait-Peers 1 3 | Out-Null

    $names = @("A","B","C","D","E","F","G","H")
    foreach ($n in $names) { New-Wallet $n }
    foreach ($w in $names) { Faucet 1 $script:addrs[$w] }
    Start-Sleep -Seconds 5
    Assert-Invariant @(1,2,3,4) "S10 faucet (8)"

    $sent = 0
    for ($i = 0; $i -lt 192; $i++) {
        $from = $names[$i % 8]; $to = $names[($i * 3 + 1) % 8]
        if ($from -eq $to) { $to = $names[($i * 3 + 2) % 8] }
        $node = 1 + ($i % 4)
        if (-not (Send-Tx $node $from $to (10000000 + $i * 500000) 10)) { $script:failed += "S10-send-$i" }
        $sent++
    }
    $t = Wait-Converged @(1,2,3,4) 420
    Write-Output "  converged tx=$t (expected 200)"
    if ($t -lt 200) { Write-Output "  FAIL: expected 200 txs, got $t"; $script:failed += "S10-count" }
    Assert-Invariant @(1,2,3,4) "S10 200 txs"
    Stop-AllNodes
    Write-Output "=== S10 done ==="
}

# ==================== RUNNER ====================
Get-Process -Name "aether-unified" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$scenarios = @(
    @{ name = "S1"; fn = { Scenario-S1 } },
    @{ name = "S2"; fn = { Scenario-S2 } },
    @{ name = "S3"; fn = { Scenario-S3 } },
    @{ name = "S4"; fn = { Scenario-S4 } },
    @{ name = "S5"; fn = { Scenario-S5 } },
    @{ name = "S6"; fn = { Scenario-S6 } },
    @{ name = "S7"; fn = { Scenario-S7 } },
    @{ name = "S8"; fn = { Scenario-S8 } },
    @{ name = "S9"; fn = { Scenario-S9 } },
    @{ name = "S10"; fn = { Scenario-S10 } }
)

foreach ($run in 1..$Runs) {
    Write-Output "############ RUN $run / $Runs ############"
    # Purge previous run's node data dirs and wallet files (fresh network state per run)
    Get-ChildItem -LiteralPath $dir | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    $script:knownAddrs = @($FOUNDER, $FAUCET, $BURN)
    foreach ($sc in $scenarios) {
        if ($Only -and $sc.name -ne $Only) { continue }
        Write-Output "############ $($sc.name) (run $run) ############"
        $sc.fn.Invoke()
        Stop-AllNodes
    }
}

Write-Output ""
Write-Output "############ SUMMARY ############"
Write-Output "assertions run: $($script:assertions)"
if ($script:failed.Count -eq 0) {
    Write-Output "ALL SCENARIOS PASSED"
} else {
    Write-Output "FAILED:"
    $script:failed | ForEach-Object { Write-Output "  $_" }
}
Write-Output "logs in: $dir"
exit $(if ($script:failed.Count -eq 0) { 0 } else { 1 })
