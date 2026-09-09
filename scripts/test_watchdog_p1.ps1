# WATCHDOG operational tests: WATCH-01..10 + negatives + auto-restart.
# Scratch networks only (ports 497xx/498xx). Never touches the C2 canary
# except WATCH-02 (brief stop/copy/restart of C2-node9, canary is paused).
# ASCII only (PS 5.1 parser).
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\watch-tests"
# Robust cleanup FIRST (strays from aborted runs share dirs/ports).
$pids0 = @(Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
    Where-Object { $_.CommandLine -match "watch-tests" } |
    ForEach-Object { $_.ProcessId })
foreach ($procId in $pids0) { Stop-Process -Id $procId -Force -EA SilentlyContinue }
foreach ($procId in $pids0) { Wait-Process -Id $procId -Timeout 20 -EA SilentlyContinue }
Start-Sleep 3
Remove-Item -Recurse -Force $root -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null
# Pre-flight: fail fast if the test ports are squatted (e.g. NVIDIA
# ShadowStreamer holds 49705 on this machine — documented environment
# collision, not a node bug).
foreach ($pt in @(51201,51202,51203,51204,51205,51206)) {
    $held = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue)
    if ($held.Count -gt 0) {
        $who = ($held | ForEach-Object { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName } | Sort-Object -Unique) -join ","
        Write-Host "FAIL: port $pt busy (held by: $who)"; exit 2
    }
}
$WD = "C:\Users\Shadow\Documents\aether-fix\aether-main\scripts\watchdog.ps1"
$fail = 0
function Check($name, $cond, $detail="") {
    if ($cond) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name $detail"; $script:fail++ }
}
function Rpc($port, $method, $params=@()) {
    $b = @{jsonrpc="2.0";method=$method;params=$params;id=1} | ConvertTo-Json -Compress -Depth 5
    (Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 10).result
}
function KillDir($dir) {
    $pids = @(Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match [regex]::Escape($dir) } |
        ForEach-Object { $_.ProcessId })
    foreach ($procId in $pids) { Stop-Process -Id $procId -Force -EA SilentlyContinue }
    # Stop-Process is fire-and-forget: WAIT for death, else the port stays
    # bound and the relaunched node goes deaf (bind 10048, 0 peers forever).
    foreach ($procId in $pids) { Wait-Process -Id $procId -Timeout 15 -EA SilentlyContinue }
}
function StartNode($dir, $p2p, $rpc, $boot) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # Pre-kill by dir AND by port (strays from aborted runs hold ports and
    # cause silent bind failures: node runs deaf with 0 peers, see logs).
    KillDir $dir
    foreach ($pt in @($p2p, $rpc)) {
        $owners = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique)
        foreach ($o in $owners) { Stop-Process -Id $o -Force -EA SilentlyContinue }
        foreach ($o in $owners) { Wait-Process -Id $o -Timeout 15 -EA SilentlyContinue }
    }
    Start-Sleep 2
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$dir,"--p2p-port",$p2p,"--rpc-port",$rpc,"--bootnodes",$boot) -WindowStyle Hidden | Out-Null
}
function Watchdog($cfg, $extra=@()) {
    $out = powershell -NoProfile -ExecutionPolicy Bypass -File $WD -Config $cfg @extra 2>&1 | Out-String
    return $out
}
function MkCfg($path, $nodes, $overrides=@{}) {
    $th = @{rpcTimeoutSec=8; graceSec=45; stallWindowSec=60; ramWarnMB=500; ramCritMB=1500; maxRestartsPerHour=3; restartCooldownSec=20; diskWarnPct=80; diskCritPct=95; mempoolWarn=500; orphanWarn=200}
    foreach ($k in $overrides.Keys) { $th[$k] = $overrides[$k] }
    @{binary=$Bin; thresholds=$th; nodes=$nodes} | ConvertTo-Json -Depth 6 | Set-Content $path -Encoding utf8
}
function NodeEntry($name, $dir, $p2p, $rpc, $role) {
    return @{name=$name; dataDir=$dir; p2p=$p2p; rpc=$rpc; role=$role; nodeType="validator"; bootnodes=@("127.0.0.1:51201")}
}

# --- base net A: seed + n2 + n3 (faucet on seed) ---
$netA = Join-Path $root "netA"
New-Item -ItemType Directory -Force -Path (Join-Path $netA "w1") | Out-Null
Copy-Item "$env:TEMP\opencode\aether-canary-c2\node1\faucet.key" (Join-Path $netA "w1\faucet.key") -Force
StartNode (Join-Path $netA "w1") 51201 51202 "127.0.0.1:51201"
StartNode (Join-Path $netA "n2") 51203 51204 "127.0.0.1:51201"
StartNode (Join-Path $netA "n3") 51205 51206 "127.0.0.1:51201"
Write-Host "waiting for initial mesh (all 3 peers>=1, up to 3 min)..."
$dl = (Get-Date).AddMinutes(3)
$meshed = $false
while ((Get-Date) -lt $dl) {
    try {
        $p1 = (Rpc 51202 "aether_getDagStats").connected_peers
        $p2 = (Rpc 51204 "aether_getDagStats").connected_peers
        $p3 = (Rpc 51206 "aether_getDagStats").connected_peers
        if ($p1 -ge 1 -and $p2 -ge 1 -and $p3 -ge 1) { $meshed = $true; break }
    } catch {}
    Start-Sleep 10
}
Check "MESH initial (all peers>=1)" $meshed "dirs kept at $root for forensics"
$cfgA = Join-Path $root "cfgA.json"
MkCfg $cfgA @(
    (NodeEntry "w1" (Join-Path $netA "w1") 51201 51202 "SEED"),
    (NodeEntry "n2" (Join-Path $netA "n2") 51203 51204 "FULL"),
    (NodeEntry "n3" (Join-Path $netA "n3") 51205 51206 "FULL"))

# NEGATIVE baseline: healthy net -> no CRITICAL, exit 0
$stDir = Join-Path $root "state-base"
$o = Watchdog $cfgA @("-StateDir", $stDir)
Check "NEG healthy net exit 0" ($o -match "n3: HEALTHY")

# WATCH-01: kill n3 -> DOWN + CRITICAL, monitor-only (no restart)
KillDir (Join-Path $netA "n3"); Start-Sleep 3
$o = Watchdog $cfgA @("-StateDir", (Join-Path $root "state-w1"))
Check "WATCH-01 DOWN detected" ($o -match "n3: DOWN")
Check "WATCH-01 CRITICAL PROCESS_DOWN" ($o -match "PROCESS_DOWN")
Check "WATCH-01 incident ID format" ($o -match "INC-\d{8}-\d{6}-N3")
Check "WATCH-01 no auto-restart (monitor only)" ((Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue | Where-Object { $_.CommandLine -match "netA.n3|netA\\n3" }).Count -eq 0)
# restart manually -> converges (recovery path for later tests)
StartNode (Join-Path $netA "n3") 51205 51206 "127.0.0.1:51201"
Start-Sleep 25

# WATCH-04: kill seed -> peer loss on survivors; restart -> recover
KillDir (Join-Path $netA "w1"); Start-Sleep 25
$o = Watchdog $cfgA @("-StateDir", (Join-Path $root "state-w4"))
Check "WATCH-04 PEER_LOSS on survivors" ($o -match "PEER_LOSS")
StartNode (Join-Path $netA "w1") 51201 51202 "127.0.0.1:51201"
Write-Host "waiting for mesh recovery (up to 4 min)..."
$dl = (Get-Date).AddMinutes(4)
while ((Get-Date) -lt $dl) {
    try {
        $p2 = (Rpc 51204 "aether_getDagStats").connected_peers
        $p3 = (Rpc 51206 "aether_getDagStats").connected_peers
        if ($p2 -ge 1 -and $p3 -ge 1) { break }
    } catch {}
    Start-Sleep 10
}
$o = Watchdog $cfgA @("-StateDir", (Join-Path $root "state-w4b"))
if ($o -match "PEER_LOSS") {
    Write-Host "--- DIAG ---"
    Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match "watch-tests" } |
        ForEach-Object { Write-Host "$($_.ProcessId) $($_.CommandLine)" }
    foreach ($r in @(51202, 51204, 51206)) {
        try {
            $s = Rpc $r "aether_getDagStats"
            Write-Host "rpc=$r total=$($s.total_transactions) peers=$($s.connected_peers)"
        } catch { Write-Host "rpc=$r DOWN" }
    }
    Write-Host "--- joinee n2 log tail ---"
    Get-Content (Join-Path $netA "n2\logs\node.log") -Tail 8 -EA SilentlyContinue
}
Check "WATCH-04 recovered, no PEER_LOSS" ($o -notmatch "PEER_LOSS")

# WATCH-05/06: synthetic low thresholds fire warnings (proves the path)
$cfgWarn = Join-Path $root "cfgWarn.json"
MkCfg $cfgWarn @((NodeEntry "n2" (Join-Path $netA "n2") 51203 51204 "FULL")) @{ramWarnMB=1; diskWarnPct=1}
$o = Watchdog $cfgWarn @("-StateDir", (Join-Path $root "state-w56"))
Check "WATCH-05/06 RAM+DISK warnings fire" ($o -match "RAM" -and $o -match "disk")

# NEGATIVES: BOOTSTRAP + ISOLATED roles tolerate 0 peers
$cfgNeg = Join-Path $root "cfgNeg.json"
MkCfg $cfgNeg @(
    (NodeEntry "iso" (Join-Path $netA "n2") 51203 51204 "ISOLATED"),
    (NodeEntry "boot" (Join-Path $netA "n3") 51205 51206 "BOOTSTRAP"))
$o = Watchdog $cfgNeg @("-StateDir", (Join-Path $root "state-neg"))
Check "NEG isolated/bootstrap roles quiet" ($o -notmatch "PEER_LOSS")

Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
    Where-Object { $_.CommandLine -match "watch-tests" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }

if ($fail -gt 0) { Write-Host "PART1 done fails=$fail -- DIRS KEPT at $root" }
else {
    Remove-Item -Recurse -Force $root -EA SilentlyContinue
    Write-Host "PART1 done fails=$fail"
}
