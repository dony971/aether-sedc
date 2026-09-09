# RPC bind tests: RPC-02 (loopback-only refuses LAN IP), RPC-03 (explicit
# external bind warns + serves), RPC-04/05/06 compat via existing suites.
# ASCII only (PS 5.1).
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target-rpc\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\rpc-bind-tests"
$fail = 0
function Check($name, $cond, $detail="") {
    if ($cond) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name $detail"; $script:fail++ }
}
function RpcAt($hostname, $port, $method) {
    # NOTE: the parameter must NOT be named $host (read-only automatic var).
    $b = @{jsonrpc="2.0";method=$method;params=@();id=1} | ConvertTo-Json -Compress
    (Invoke-RestMethod -Uri "http://${hostname}:${port}" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 8).result
}
function KillMatch($pat) {
    $rx = [regex]::Escape($pat)
    $pids = @(Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match $rx } | ForEach-Object { $_.ProcessId })
    foreach ($p in $pids) { Stop-Process -Id $p -Force -EA SilentlyContinue }
    foreach ($p in $pids) { Wait-Process -Id $p -Timeout 20 -EA SilentlyContinue }
}
function StartNode($dir, $p2p, $rpc, $extra=@()) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    KillMatch $dir
    foreach ($pt in @($p2p, $rpc)) {
        $owners = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
        foreach ($o in $owners) { Stop-Process -Id $o -Force -EA SilentlyContinue }
        foreach ($o in $owners) { Wait-Process -Id $o -Timeout 20 -EA SilentlyContinue }
    }
    Start-Sleep 2
    Start-Process -FilePath $Bin -ArgumentList (@("--node-type","validator","--data-dir",$dir,"--p2p-port",$p2p,"--rpc-port",$rpc) + $extra) -WindowStyle Hidden | Out-Null
}

foreach ($pt in @(52001,52002,52011,52012)) {
    $held = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue)
    if ($held.Count -gt 0) { Write-Host "FAIL: port $pt busy"; exit 2 }
}
KillMatch "rpc-bind-tests"
KillMatch "rpc-bind-tests"
Start-Sleep 3
Remove-Item -Recurse -Force $root -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

# LAN IP of this machine (proves loopback-only without a 2nd machine: a
# 127.0.0.1-bound server refuses connections addressed to the LAN IP).
$lan = (Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue |
    Where-Object { $_.IPAddress -match "^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\." -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1 -ExpandProperty IPAddress)
Write-Host "LAN IP: $lan"

# RPC-02: default bind refuses LAN IP, serves loopback.
# Wait for RPC readiness FIRST (fresh boot takes a while; asserting too
# early makes the LAN check pass vacuously on a dead port).
StartNode (Join-Path $root "a") 52001 52002 @()
Write-Host "waiting for RPC readiness (up to 90s)..."
$dl = (Get-Date).AddSeconds(90)
$ready = $false
while ((Get-Date) -lt $dl) {
    try { $r = RpcAt "127.0.0.1" 52002 "aether_getDagStats"; if ($r.total_transactions -ge 0) { $ready = $true; break } }
    catch {}
    Start-Sleep 5
}
Check "RPC-02 loopback serves (ready=$ready)" $ready
$refused = $false
if ($lan) {
    try { $null = RpcAt $lan 52002 "aether_getDagStats" }
    catch { $refused = $true }
}
Check "RPC-02 LAN IP refused by default" ($refused -or (-not $lan)) "lan=$lan"

# RPC-03: explicit 0.0.0.0 warns + serves LAN IP (wait readiness first)
StartNode (Join-Path $root "b") 52011 52012 @("--rpc-bind", "0.0.0.0")
$dl = (Get-Date).AddSeconds(90)
$readyB = $false
while ((Get-Date) -lt $dl) {
    try { $r = RpcAt "127.0.0.1" 52012 "aether_getDagStats"; if ($r.total_transactions -ge 0) { $readyB = $true; break } }
    catch {}
    Start-Sleep 5
}
Check "RPC-03 loopback serves when explicit (ready=$readyB)" $readyB
$warned = $false
try {
    $log = Get-Content (Join-Path $root "b\logs\node.log") -EA SilentlyContinue | Out-String
    $warned = $log -match "WARNING RPC exposed on non-loopback"
} catch {}
Check "RPC-03 explicit-bind WARNING logged" $warned
$served = $false
if ($lan) {
    try { $r = RpcAt $lan 52012 "aether_getDagStats"; $served = ($r.total_transactions -ge 0) } catch {}
}
Check "RPC-03 LAN IP served when explicit" ($served -or (-not $lan)) "lan=$lan"

KillMatch "rpc-bind-tests"
if ($fail -gt 0) { Write-Host "RPC-BIND: FAIL ($fail) -- DIRS KEPT at $root" }
else { Remove-Item -Recurse -Force $root -EA SilentlyContinue; Write-Host "RPC-BIND: ALL PASS" }
