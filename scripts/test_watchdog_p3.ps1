# WATCHDOG tests part 3 (S17): 9 fresh nodes. Single crash -> isolated
# NODE FAILURE (no network note). Double kill -> NETWORK EVENT note.
# Restart all -> converge, watchdog clean. ASCII only.
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\watch-tests3"
$WD = "C:\Users\Shadow\Documents\aether-fix\aether-main\scripts\watchdog.ps1"
$fail = 0
function Check($name, $cond, $detail="") {
    if ($cond) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name $detail"; $script:fail++ }
}
function Rpc($port, $method, $params=@()) {
    $b = @{jsonrpc="2.0";method=$method;params=$params;id=1} | ConvertTo-Json -Compress -Depth 5
    (Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 10).result
}
function KillMatch($pat) {
    $rx = [regex]::Escape($pat)
    $pids = @(Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match $rx } | ForEach-Object { $_.ProcessId })
    foreach ($p in $pids) { Stop-Process -Id $p -Force -EA SilentlyContinue }
    foreach ($p in $pids) { Wait-Process -Id $p -Timeout 20 -EA SilentlyContinue }
}
function StartNode($dir, $p2p, $rpc, $boot) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    KillMatch $dir
    foreach ($pt in @($p2p, $rpc)) {
        $owners = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
        foreach ($o in $owners) { Stop-Process -Id $o -Force -EA SilentlyContinue }
        foreach ($o in $owners) { Wait-Process -Id $o -Timeout 20 -EA SilentlyContinue }
    }
    Start-Sleep 2
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$dir,"--p2p-port",$p2p,"--rpc-port",$rpc,"--bootnodes",$boot) -WindowStyle Hidden | Out-Null
}
function Watchdog($cfg, $extra=@()) {
    powershell -NoProfile -ExecutionPolicy Bypass -File $WD -Config $cfg @extra 2>&1 | Out-String
}

$strays = @(Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
    Where-Object { $_.CommandLine -match "watch-tests3" } | ForEach-Object { $_.ProcessId })
foreach ($sp in $strays) { Stop-Process -Id $sp -Force -EA SilentlyContinue }
foreach ($sp in $strays) { Wait-Process -Id $sp -Timeout 20 -EA SilentlyContinue }
Start-Sleep 2
foreach ($pt in @(51701,51702,51703,51704,51705,51706,51707,51708,51709,51801,51802,51803,51804,51805,51806,51807,51808,51809)) {
    $held = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue)
    if ($held.Count -gt 0) { Write-Host "FAIL: port $pt busy"; exit 2 }
}
Remove-Item -Recurse -Force $root -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

$nodes = @()
for ($i = 1; $i -le 9; $i++) {
    $d = Join-Path $root "node$i"
    StartNode $d (51700 + $i) (51800 + $i) "127.0.0.1:51701"
    $nodes += @{name = "node$i"; dataDir = $d; p2p = (51700 + $i); rpc = (51800 + $i); role = "FULL"; nodeType = "validator"; bootnodes = @("127.0.0.1:51701") }
}
$nodes[0].role = "SEED"
$cfg = Join-Path $root "cfg9.json"
@{binary = $Bin; thresholds = @{rpcTimeoutSec = 8; graceSec = 20; stallWindowSec = 120; ramWarnMB = 500; ramCritMB = 1500; maxRestartsPerHour = 3; restartCooldownSec = 15; diskWarnPct = 80; diskCritPct = 95; mempoolWarn = 500; orphanWarn = 200}; nodes = $nodes } | ConvertTo-Json -Depth 6 | Set-Content $cfg -Encoding utf8

Write-Host "waiting for 9-mesh (up to 4 min)..."
$dl = (Get-Date).AddMinutes(4); $meshed = $false
while ((Get-Date) -lt $dl) {
    $ok = $true
    foreach ($r in @(51801,51802,51803,51804,51805,51806,51807,51808,51809)) {
        try { if ((Rpc $r "aether_getDagStats").connected_peers -lt 1) { $ok = $false; break } }
        catch { $ok = $false; break }
    }
    if ($ok) { $meshed = $true; break }
    Start-Sleep 10
}
Check "9-mesh initial" $meshed

# single crash -> isolated NODE FAILURE (others stay peered, no network note)
KillMatch (Join-Path $root "node4"); Start-Sleep 5
$o = Watchdog $cfg @("-StateDir", (Join-Path $root "st-c1"))
Check "single crash: node4 DOWN" ($o -match "node4: DOWN")
Check "single crash: no NETWORK EVENT note" ($o -notmatch "NETWORK EVENT")

# double kill -> NETWORK EVENT note
KillMatch (Join-Path $root "node5"); KillMatch (Join-Path $root "node6"); Start-Sleep 5
$o = Watchdog $cfg @("-StateDir", (Join-Path $root "st-c2"))
Check "double kill: both DOWN" (($o -match "node5: DOWN") -and ($o -match "node6: DOWN"))
Check "double kill: NETWORK EVENT note" ($o -match "NETWORK EVENT")

# restart all -> converge, watchdog clean
foreach ($i in @(4, 5, 6)) {
    $d = Join-Path $root "node$i"
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$d,"--p2p-port",(51700+$i),"--rpc-port",(51800+$i),"--bootnodes","127.0.0.1:51701") -WindowStyle Hidden | Out-Null
}
Start-Sleep 60
$o = Watchdog $cfg @("-StateDir", (Join-Path $root "st-c3"))
Check "recovered: no DOWN left" ($o -notmatch ": DOWN")
$ref = (Rpc 51801 "aether_getDagStats").total_transactions
$m = 1
foreach ($r in @(51802,51803,51804,51805,51806,51807,51808,51809)) {
    try { if ((Rpc $r "aether_getDagStats").total_transactions -eq $ref) { $m++ } } catch {}
}
Check "9/9 converged at $ref" ($m -eq 9)

Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
    Where-Object { $_.CommandLine -match "watch-tests3" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
if ($fail -gt 0) { Write-Host "PART3 done fails=$fail -- DIRS KEPT at $root" }
else { Remove-Item -Recurse -Force $root -EA SilentlyContinue; Write-Host "PART3 done fails=$fail" }
