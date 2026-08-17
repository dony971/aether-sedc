# ============================================================
# CANARY OBSERVATION MONITOR - Phase B (N nodes, parameterized)
# Polls every IntervalSec for DurationMin; appends snapshots to
# %TEMP%\opencode\canary_monitor_b.log ; ASCII-only, no secrets.
# Node id -> p2p port 42000+(id-1)*1000+1, rpc p2p+100.
# Fingerprint = sha256(txset|edges|tips|ledger(faucet,founder,burn)|weights)
# NOTE: uses aether_getDagGraph (full DAG). aether_getDagSnapshot is truncated
# to MAX_PAGE_SIZE=100 txs in arbitrary per-node order -> false divergence.
# ============================================================
param(
    [string]$NodeList = "1,2,3,4,5",
    [int]$DurationMin = 90,
    [int]$IntervalSec = 60,
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a",
    [string]$LogName = "canary_monitor_b.log"
)
$ErrorActionPreference = "Continue"
$log = Join-Path $env:TEMP ("opencode\" + $LogName)
$FAUCET = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$FOUNDER = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$BURN = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
$script:nodes = @()
foreach ($id in ($NodeList -split "," | ForEach-Object { [int]$_ })) {
    $p2p = 42000 + ($id - 1) * 1000 + 1
    $script:nodes += @{ id = $id; rpc = $p2p + 100; p2p = $p2p }
}
$lastTx = @{}; $lastErr = @{}; $lastPid = @{}
foreach ($n in $script:nodes) { $lastTx[$n.id] = -1; $lastErr[$n.id] = -1; $lastPid[$n.id] = -1 }

function RpcCall($port, $method, $params) {
    try {
        $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Compress
        return (Invoke-RestMethod -Uri ("http://127.0.0.1:" + $port) -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5).result
    } catch { return $null }
}

function HexId($arr) {
    if ($arr -is [string]) { return $arr.ToLowerInvariant() }
    if ($null -eq $arr) { return "" }
    ($arr | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Fingerprint($port) {
    $stats = RpcCall $port "aether_getDagStats" @()
    if (-not $stats) { return "DOWN" }
    $tips = RpcCall $port "aether_getTips" @()
    $t = if ($tips) { ($tips.tips | Sort-Object | ForEach-Object { HexId $_ }) -join "," } else { "" }
    $led = @()
    foreach ($a in @($FAUCET, $FOUNDER, $BURN)) {
        $b = (RpcCall $port "aether_getBalance" @($a)).balance
        $n = (RpcCall $port "aether_getAccountNonce" @($a)).next_nonce
        $led += ($a + ":" + $b + ":" + $n)
    }
    $graph = RpcCall $port "aether_getDagGraph" @()
    $txs = @(); $w = @(); $eds = @()
    if ($graph) {
        foreach ($nd in $graph.nodes) { $txs += HexId $nd.tx_id; $w += "$(HexId $nd.tx_id):$($nd.weight)" }
        foreach ($ed in $graph.edges) { $eds += "$(HexId $ed.from)->$(HexId $ed.to)" }
    }
    $raw = ($stats.total_transactions.ToString()) + "|" + (($txs | Sort-Object) -join ",") + "|" + (($eds | Sort-Object) -join ",") + "|" + $t + "|" + (($led | Sort-Object) -join ",") + "|" + (($w | Sort-Object) -join ",")
    return [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace("-","").ToLower().Substring(0,16)
}

$start = Get-Date
"=== CANARY MONITOR START " + $start.ToString("yyyy-MM-dd HH:mm:ss") + " (nodes " + $NodeList + ", window " + $DurationMin + "min, interval " + $IntervalSec + "s) ===" | Add-Content $log -Encoding ascii

while ((Get-Date) -lt $start.AddMinutes($DurationMin)) {
    $snap = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = $snap
    $tpsSum = 0
    $maxH = 0; $minH = 999999999
    $fp = @{}
    foreach ($n in $script:nodes) {
        $dir = Join-Path $DataRoot ("node" + $n.id)
        $nproc = -1
        if (Test-Path (Join-Path $dir "node.pid")) { $nproc = [int](Get-Content (Join-Path $dir "node.pid")).Trim() }
        $proc = Get-Process -Id $nproc -ErrorAction SilentlyContinue
        $crash = if ($proc) { 0 } else { 1 }
        $restart = 0
        if ($lastPid[$n.id] -ne -1 -and $nproc -ne $lastPid[$n.id]) { $restart = 1 }
        $lastPid[$n.id] = $nproc
        $cpu = if ($proc) { [math]::Round($proc.CPU, 1) } else { -1 }
        $ram = if ($proc) { [math]::Round($proc.WorkingSet64 / 1MB, 0) } else { -1 }
        $stats = RpcCall $n.rpc "aether_getDagStats" @()
        $tx = if ($stats) { [long]$stats.total_transactions } else { -1 }
        $hgt = if ($stats) { [long]$stats.epoch } else { -1 }
        $peers = if ($stats) { [long]$stats.connected_peers } else { -1 }
        $nodeTps = if ($stats) { [math]::Round([double]$stats.current_tps, 2) } else { -1 }
        $orps = 0
        $orphLines = @(Get-Content (Join-Path $dir "node.out.log") -ErrorAction SilentlyContinue | Select-String -Pattern "Loaded (\d+) orphans")
        foreach ($ol in $orphLines) { if ($ol.Matches[0].Groups[1].Value -match '^\d+$') { $o = [int]$ol.Matches[0].Groups[1].Value; if ($o -gt $orps) { $orps = $o } } }
        $orphWarn = @(Get-Content (Join-Path $dir "node.out.log") -ErrorAction SilentlyContinue | Select-String -Pattern "orphan").Count
        $tps = 0
        if ($lastTx[$n.id] -ge 0 -and $tx -ge 0) { $tps = [math]::Round(($tx - $lastTx[$n.id]) / ($IntervalSec / 60.0), 2) }
        $lastTx[$n.id] = $tx
        if ($hgt -gt $maxH) { $maxH = $hgt }
        if ($hgt -ge 0 -and $hgt -lt $minH) { $minH = $hgt }
        $errCount = @(Get-Content (Join-Path $dir "node.err.log") -ErrorAction SilentlyContinue | Select-String "WARN|ERROR").Count
        $dErr = $errCount
        if ($lastErr[$n.id] -ge 0) { $dErr = $errCount - $lastErr[$n.id] }
        $lastErr[$n.id] = $errCount
        $fp[$n.id] = Fingerprint $n.rpc
        $tpsSum += [math]::Max(0, $tps)
        $line += ("|n" + $n.id + ":tx=" + $tx + " h=" + $hgt + " peers=" + $peers + " orph=" + $orps + " orphWarn=" + $orphWarn + " tps=" + $nodeTps + " cpu=" + $cpu + " ram=" + $ram + "MB err=" + $dErr + " crash=" + $crash + " restart=" + $restart)
    }
    $disk = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    $sync = if ($maxH -ge 0 -and $minH -lt 999999999) { $maxH - $minH } else { -1 }
    $upNodes = @($script:nodes | Where-Object { $fp[$_.id] -ne "DOWN" })
    $div = -1
    if ($upNodes.Count -ge 2) {
        $div = 0
        $refFp = $fp[$upNodes[0].id]
        foreach ($n in $upNodes) { if ($fp[$n.id] -ne $refFp) { $div = 1 } }
    }
    if ($upNodes.Count -lt 2 -and $upNodes.Count -gt 0) { $div = -1 }
    $fpStr = ($script:nodes | ForEach-Object { "fp" + $_.id + "=" + $fp[$_.id] }) -join " "
    $line += ("|sync=" + $sync + " diskFreeGB=" + $disk + " tpsSum=" + [math]::Round($tpsSum,2) + " " + $fpStr + " divergence=" + $div)
    $line | Add-Content $log -Encoding ascii
    if ($div -eq 1) { ("CRITICAL DIVERGENCE at " + $snap) | Add-Content $log -Encoding ascii }
    Start-Sleep -Seconds $IntervalSec
}
"=== CANARY MONITOR END " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " ===" | Add-Content $log -Encoding ascii
Write-Host "monitor done -> " + $log