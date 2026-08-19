# phase_d_campaign.ps1 - Phase D campaign network: 8 fresh validator nodes on the
# NEW mempool-correction binary (target\release\aether.exe), ports 42001-49001 p2p /
# 42101-49101 rpc, data dirs %TEMP%\opencode\aether-canary-phase-d\node1..8.
param(
    [int]$Nodes = 8
)
$ErrorActionPreference = "Stop"
$Root = Join-Path $env:TEMP "opencode\aether-canary-phase-d"
$Bin  = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether.exe"
if (-not (Test-Path $Bin)) { throw "binary not found: $Bin" }
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root | Out-Null }
Get-CimInstance Win32_Process -Filter "Name='aether.exe'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
for ($i = 1; $i -le $Nodes; $i++) {
    $p2p = 41000 + $i * 1000 + 1
    $rpc = 41100 + $i * 1000 + 1
    $d = Join-Path $Root ("node" + $i)
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    $na = @("--node-type", "validator", "--data-dir", $d, "--p2p-port", "$p2p", "--rpc-port", "$rpc")
    if ($i -gt 1) { $na += @("--bootnodes", "127.0.0.1:42001") }
    Start-Process -FilePath $Bin -ArgumentList $na -RedirectStandardOutput (Join-Path $d "node.log") -RedirectStandardError (Join-Path $d "node.err") -WindowStyle Hidden | Out-Null
    Write-Output ("launched node$i (p2p $p2p rpc $rpc)")
}
Start-Sleep -Seconds 20
$up = 0
foreach ($i in 1..$Nodes) {
    $p = 41100 + $i * 1000 + 1
    try {
        $b = @{jsonrpc="2.0";method="aether_getDagStats";params=@();id=1} | ConvertTo-Json -Compress
        $r = (Invoke-RestMethod -Uri "http://127.0.0.1:$p" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 5).result
        "port $p : total=$($r.total_transactions) tips=$($r.tip_count)"; $up++
    } catch { "port $p : DOWN" }
}
"nodes up: $up/$Nodes"