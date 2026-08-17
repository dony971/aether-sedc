# ============================================================
# CANARY OBSERVATION MONITOR - Phase A (3 seed nodes)
# Polls every IntervalSec for DurationMin; appends snapshots to
# %TEMP%\opencode\canary_monitor_a.log ; ASCII-only, no secrets.
# ============================================================
param(
    [int]$DurationMin = 40,
    [int]$IntervalSec = 60,
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a"
)
$ErrorActionPreference = "Continue"
$log = "$env:TEMP\opencode\canary_monitor_a.log"
$nodes = @(
    @{ id = 1; rpc = 42101; p2p = 42001 },
    @{ id = 2; rpc = 43101; p2p = 43001 },
    @{ id = 3; rpc = 44101; p2p = 44001 }
)

function RpcCall($port, $method, $params) {
    try {
        $body = @{ jsonrpc = "2.0"; id = 1; method = $method; params = $params } | ConvertTo-Json -Compress
        return (Invoke-RestMethod -Uri ("http://127.0.0.1:" + $port) -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5).result
    } catch { return $null }
}

function Fingerprint($port) {
    $tips = RpcCall $port "aether_getTips" @()
    $stats = RpcCall $port "aether_getDagStats" @()
    if (-not $stats) { return "DOWN" }
    $t = if ($tips) { ($tips.tips | Sort-Object | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ForEach-Object { $_.ToString("x2") }) -join "" } }) -join "," } else { "" }
    $raw = ($stats.total_transactions.ToString()) + "|" + $t
    return [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace("-","").ToLower().Substring(0,16)
}

$start = Get-Date
"=== CANARY MONITOR START " + $start.ToString("yyyy-MM-dd HH:mm:ss") + " (window " + $DurationMin + "min, interval " + $IntervalSec + "s) ===" | Add-Content $log -Encoding ascii
$lastTx = @{ 1 = -1; 2 = -1; 3 = -1 }
$lastErr = @{ 1 = -1; 2 = -1; 3 = -1 }
$lastPid = @{ 1 = -1; 2 = -1; 3 = -1 }

while ((Get-Date) -lt $start.AddMinutes($DurationMin)) {
    $snap = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = $snap
    $tpsSum = 0
    $maxH = 0; $minH = 999999999
    $fp = @{}
    foreach ($n in $nodes) {
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
        $line += ("|n" + $n.id + ":tx=" + $tx + " h=" + $hgt + " peers=" + $peers + " orph=" + $orps + " tps=" + $nodeTps + " cpu=" + $cpu + " ram=" + $ram + "MB err=" + $dErr + " crash=" + $crash + " restart=" + $restart)
    }
    $disk = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    $sync = if ($maxH -ge 0 -and $minH -lt 999999999) { $maxH - $minH } else { -1 }
    $div = if (($fp[1] -eq $fp[2]) -and ($fp[2] -eq $fp[3]) -and $fp[1] -ne "DOWN") { 0 } else { 1 }
    $line += ("|sync=" + $sync + " diskFreeGB=" + $disk + " tpsSum=" + [math]::Round($tpsSum,2) + " fp1=" + $fp[1] + " fp2=" + $fp[2] + " fp3=" + $fp[3] + " divergence=" + $div)
    $line | Add-Content $log -Encoding ascii
    if ($div -eq 1) { ("CRITICAL DIVERGENCE at " + $snap) | Add-Content $log -Encoding ascii }
    Start-Sleep -Seconds $IntervalSec
}
"=== CANARY MONITOR END " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " ===" | Add-Content $log -Encoding ascii
Write-Host "monitor done -> " + $log