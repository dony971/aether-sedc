# WATCHDOG tests part 2: WATCH-02/03/07/08 + auto-restart + perf.
# Scratch nets only. ASCII only (PS 5.1).
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\watch-tests2"
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
    KillMatch ([regex]::Escape($dir))
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
function MkCfg($path, $nodes, $overrides=@{}) {
    # NOTE: graceSec is deliberately short (15s): test nodes must be OLDER
    # than grace before fault injection, otherwise the watchdog correctly
    # reports boot-grace HEALTHY (a 25s-old silent node is indistinguishable
    # from a booting one — verified manually).
    $th = @{rpcTimeoutSec=8; graceSec=15; stallWindowSec=60; ramWarnMB=500; ramCritMB=1500; maxRestartsPerHour=3; restartCooldownSec=15; diskWarnPct=80; diskCritPct=95; mempoolWarn=500; orphanWarn=200}
    foreach ($k in $overrides.Keys) { $th[$k] = $overrides[$k] }
    @{binary=$Bin; thresholds=$th; nodes=$nodes} | ConvertTo-Json -Depth 6 | Set-Content $path -Encoding utf8
}
function NodeEntry($name, $dir, $p2p, $rpc, $role, $boot) {
    return @{name=$name; dataDir=$dir; p2p=$p2p; rpc=$rpc; role=$role; nodeType="validator"; bootnodes=@($boot)}
}
function Suspend-Proc($procId) {
    $sig = '[DllImport("ntdll.dll")] public static extern uint NtSuspendProcess(IntPtr h);'
    $t = Add-Type -MemberDefinition $sig -Name "NtCtl" -Namespace "W" -PassThru -EA SilentlyContinue
    if (-not $t) { $t = [W.NtCtl] }
    $h = (Get-Process -Id $procId).Handle
    [void]$t::NtSuspendProcess($h)
}
function Resume-Proc($procId) {
    $sig = '[DllImport("ntdll.dll")] public static extern uint NtResumeProcess(IntPtr h);'
    $t = Add-Type -MemberDefinition $sig -Name "NtCtl2" -Namespace "W" -PassThru -EA SilentlyContinue
    if (-not $t) { $t = [W.NtCtl2] }
    $h = (Get-Process -Id $procId).Handle
    [void]$t::NtResumeProcess($h)
}

# cleanup own strays FIRST (aborted runs share dirs/ports), then
# pre-flight ports (fail fast on foreign squatters, e.g. ShadowStreamer).
KillMatch "watch-tests2"
Start-Sleep 3
foreach ($pt in @(51401,51402,51403,51404,51405,51406,51407,51408,51501,51502)) {
    $held = @(Get-NetTCPConnection -LocalPort $pt -EA SilentlyContinue)
    if ($held.Count -gt 0) { Write-Host "FAIL: port $pt busy"; exit 2 }
}
Remove-Item -Recurse -Force $root -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null

# --- net A (seed s1 + a2 + a3, faucet on seed) ---
$netA = Join-Path $root "netA"
New-Item -ItemType Directory -Force -Path (Join-Path $netA "s1") | Out-Null
Copy-Item "$env:TEMP\opencode\aether-canary-c2\node1\faucet.key" (Join-Path $netA "s1\faucet.key") -Force
StartNode (Join-Path $netA "s1") 51401 51402 "127.0.0.1:51401"
StartNode (Join-Path $netA "a2") 51403 51404 "127.0.0.1:51401"
StartNode (Join-Path $netA "a3") 51405 51406 "127.0.0.1:51401"
$cfgA = Join-Path $root "cfgA.json"
MkCfg $cfgA @(
    (NodeEntry "s1" (Join-Path $netA "s1") 51401 51402 "SEED" "127.0.0.1:51401"),
    (NodeEntry "a2" (Join-Path $netA "a2") 51403 51404 "FULL" "127.0.0.1:51401"),
    (NodeEntry "a3" (Join-Path $netA "a3") 51405 51406 "FULL" "127.0.0.1:51401"))

# WATCH-02: suspend a2 (process alive, RPC dead) -> UNRESPONSIVE, no restart
# Nodes must be older than graceSec (see MkCfg note) before injecting.
Start-Sleep 25
$tgtPid = (Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
    Where-Object { $_.CommandLine -match "51404" } | Select-Object -First 1).ProcessId
Check "WATCH-02 target resolved (pid=$tgtPid)" ($tgtPid -gt 0)
Suspend-Proc $tgtPid
# Harness check: a suspended node must NOT answer RPC (distinguishes a
# broken suspend helper from a watchdog miss).
$suspOk = $false
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:51404" -Method Post -Body '{"jsonrpc":"2.0","method":"aether_getDagStats","params":[],"id":1}' -ContentType "application/json" -TimeoutSec 6 | Out-Null
} catch { $suspOk = $true }
Check "WATCH-02 harness: RPC silent while suspended" $suspOk
Start-Sleep 12
$o = Watchdog $cfgA @("-StateDir", (Join-Path $root "st-w2"))
Check "WATCH-02 UNRESPONSIVE (suspended proc)" ($o -match "a2: UNRESPONSIVE")
Check "WATCH-02 RPC_DOWN alert" ($o -match "RPC_DOWN")
Resume-Proc $tgtPid
Start-Sleep 10
$o = Watchdog $cfgA @("-StateDir", (Join-Path $root "st-w2b"))
Check "WATCH-02 recovered after resume" ($o -notmatch "a2: UNRESPONSIVE")

# fund + generate 120 txs on net A (for stall/divergence tests)
$gen = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\gen_optimized.exe"
$gp = Start-Process -FilePath $gen -ArgumentList @("--wallet-dir","$env:TEMP\opencode\aether-canary-c2w","--rpc-url","http://127.0.0.1:51402","--password","canary-pass-2026","--count","120","--workers","4") -RedirectStandardOutput (Join-Path $root "gen.txt") -PassThru
$gp.WaitForExit(300000) | Out-Null
Get-Content (Join-Path $root "gen.txt") -Tail 1
Start-Sleep 30
$tA = (Rpc 51402 "aether_getDagStats").total_transactions
Write-Host "netA total=$tA"

# WATCH-07: isolated net B (seed only, no txs) watched together -> DIVERGENCE
$netB = Join-Path $root "netB"
StartNode (Join-Path $netB "b1") 51501 51502 "127.0.0.1:51501"
Start-Sleep 25
$cfgAB = Join-Path $root "cfgAB.json"
MkCfg $cfgAB @(
    (NodeEntry "s1" (Join-Path $netA "s1") 51401 51402 "SEED" "127.0.0.1:51401"),
    (NodeEntry "b1" (Join-Path $netB "b1") 51501 51502 "ISOLATED" "127.0.0.1:51501"))
$o = Watchdog $cfgAB @("-StateDir", (Join-Path $root "st-w7"))
Check "WATCH-07 DIVERGENCE across groups" ($o -match "DIVERGENCE")
Check "WATCH-07 no auto-repair attempted" ($o -match "no auto-repair")

# WATCH-03: joiner J mid-sync, then kill seed -> STALL (stallWindow 60s).
# NOTE: stall needs TWO watchdog passes (baseline, then comparison).
StartNode (Join-Path $netA "jx") 51407 51408 "127.0.0.1:51401"
Start-Sleep 30
KillMatch (Join-Path $netA "s1")
Write-Host "seed killed mid-join; waiting out stall window..."
Start-Sleep 45
$cfgJ = Join-Path $root "cfgJ.json"
MkCfg $cfgJ @((NodeEntry "jx" (Join-Path $netA "jx") 51407 51408 "BOOTSTRAP" "127.0.0.1:51401"))
$o = Watchdog $cfgJ @("-StateDir", (Join-Path $root "st-w3"))
Start-Sleep 75
$o = Watchdog $cfgJ @("-StateDir", (Join-Path $root "st-w3"))
Check "WATCH-03 SYNC_STALL on orphaned joiner" ($o -match "SYNC_STALL")
StartNode (Join-Path $netA "s1") 51401 51402 "127.0.0.1:51401"
Start-Sleep 40

# WATCH-08 + S16: AUTO RESTART (max 2/h, cooldown 15s): kill a2 3x -> 2 restarts then breaker
$cfgR = Join-Path $root "cfgR.json"
MkCfg $cfgR @((NodeEntry "a2" (Join-Path $netA "a2") 51403 51404 "FULL" "127.0.0.1:51401")) @{maxRestartsPerHour=2; restartCooldownSec=15}
$stR = Join-Path $root "st-w8"
KillMatch (Join-Path $netA "a2"); Start-Sleep 3
$o = Watchdog $cfgR @("-StateDir", $stR, "-AutoRestart")
Check "WATCH-08 restart 1/2" ($o -match "AUTO_RESTART")
Start-Sleep 25
$pidA = (Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue | Where-Object { $_.CommandLine -match "51404" } | Select-Object -First 1).ProcessId
Check "WATCH-08 process back" ($pidA -gt 0)
KillMatch (Join-Path $netA "a2"); Start-Sleep 20
$o = Watchdog $cfgR @("-StateDir", $stR, "-AutoRestart")
KillMatch (Join-Path $netA "a2"); Start-Sleep 20
$o = Watchdog $cfgR @("-StateDir", $stR, "-AutoRestart")
Check "WATCH-08 CIRCUIT_BREAKER trips" ($o -match "CIRCUIT_BREAKER")
$stillDown = (Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue | Where-Object { $_.CommandLine -match "51404" } | Measure-Object).Count -eq 0
Check "WATCH-08 no restart after breaker" $stillDown
# manual recovery converges (restart policy does not strand the net)
StartNode (Join-Path $netA "a2") 51403 51404 "127.0.0.1:51401"
Start-Sleep 30
$tA2 = (Rpc 51404 "aether_getDagStats").total_transactions
Check "S16 manual recovery converges ($tA2 vs $tA)" ($tA2 -ge $tA)

# S18 perf of one watchdog sweep
$perf = Measure-Command { Watchdog $cfgA @("-StateDir", (Join-Path $root "st-perf")) | Out-Null }
$wproc = Get-Process powershell -EA SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
Write-Host ("PERF watchdog sweep: {0:N1}s" -f $perf.TotalSeconds)

KillMatch "watch-tests2"
Write-Host "PART2 done fails=$fail"
