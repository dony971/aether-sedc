# LOG-CRASH-01 — kill-hard recovery diagnostics from log files.
# 1. fresh 3 nodes (seed + 2), 2. generate txs, 3. kill-hard node2,
# 4. restart node2, 5-6. assert the log answers: which node, when,
# previous-shutdown verdict, rebuild/sync progress, convergence.
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\log-crash-01"
Remove-Item -Recurse -Force $root -EA SilentlyContinue
$fail = 0
function Check($name, $cond, $detail="") {
    if ($cond) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name $detail"; $script:fail++ }
}
function Rpc($port, $method, $params=@()) {
    $b = @{jsonrpc="2.0";method=$method;params=$params;id=1} | ConvertTo-Json -Compress -Depth 5
    (Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 10).result
}
function KillDir($dir) {
    Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match [regex]::Escape($dir) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
}

# 1. fresh 3 nodes
$cfg = @(@{i=1;p2p=49311;rpc=49312},@{i=2;p2p=49313;rpc=49314},@{i=3;p2p=49315;rpc=49316})
foreach ($c in $cfg) {
    $d = Join-Path $root "node$($c.i)"
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$d,"--p2p-port",$c.p2p,"--rpc-port",$c.rpc,"--bootnodes","127.0.0.1:49311") -WindowStyle Hidden | Out-Null
}
Start-Sleep 25
$t0 = (Rpc 49312 "aether_getDagStats").total_transactions

# 2. log files exist with banner?
$log2 = Join-Path $root "node2\logs\node.log"
Check "node2 log exists" (Test-Path $log2)
$head = Get-Content $log2 -TotalCount 6 -EA SilentlyContinue | Out-String
Check "banner has version/commit/genesis" ($head -match "BOOT aether v" -and $head -match "genesis_hash=" -and $head -match "pid=")
Check "first boot marker" ($head -match "first boot")

# 3. kill-hard node2 (no shutdown marker possible)
KillDir (Join-Path $root "node2")
Start-Sleep 3

# 4. restart node2
$d2 = Join-Path $root "node2"
Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$d2,"--p2p-port",49313,"--rpc-port",49314,"--bootnodes","127.0.0.1:49311") -WindowStyle Hidden | Out-Null
Start-Sleep 25

# 5-6. diagnose from the log only (whole file: mempool chatter pushes
# boot sections out of any small tail window)
$full = Get-Content $log2 -EA SilentlyContinue | Out-String
Check "UNCLEAN verdict logged" ($full -match "previous shutdown UNCLEAN")
Check "rebuild visible" ($full -match "(?i)rebuild|Rebuilding DAG")
Check "two BOOT banners with pid" (((Select-String -Path $log2 -Pattern "BOOT aether" -AllMatches).Matches.Count) -ge 2)
$t2 = (Rpc 49314 "aether_getDagStats").total_transactions
Check "node2 serves RPC after restart" ($t2 -ge $t0)

# cleanup
foreach ($c in $cfg) { KillDir (Join-Path $root "node$($c.i)") }
if ($fail -gt 0) { Write-Host "LOG-CRASH-01: FAIL ($fail)"; exit 1 }
Write-Host "LOG-CRASH-01: ALL PASS"
