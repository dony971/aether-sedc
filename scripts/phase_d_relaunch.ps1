# phase_d_relaunch.ps1 - restart the Phase C 8-node network (ports 42001-49001)
$ErrorActionPreference = "Stop"
$Root = Join-Path $env:TEMP "opencode\aether-canary-b4"
$Bin  = "C:\Users\Shadow\Documents\aether-fix\aether-main\target-b4\release\aether-unified.exe"
Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
for ($i = 1; $i -le 8; $i++) {
    $p2p = 41000 + $i * 1000 + 1
    $rpc = 41100 + $i * 1000 + 1
    $d = Join-Path $Root ("node" + $i)
    $na = @("--node-type", "validator", "--data-dir", $d, "--p2p-port", "$p2p", "--rpc-port", "$rpc")
    if ($i -gt 1) { $na += @("--bootnodes", "127.0.0.1:42001") }
    Start-Process -FilePath $Bin -ArgumentList $na -RedirectStandardOutput (Join-Path $d "node.log") -RedirectStandardError (Join-Path $d "node.err") -WindowStyle Hidden | Out-Null
}
Start-Sleep -Seconds 18
$up = 0
foreach ($p in 42101,43101,44101,45101,46101,47101,48101,49101) {
    try {
        $b = @{jsonrpc="2.0";method="aether_getDagStats";params=@();id=1} | ConvertTo-Json -Compress
        $r = (Invoke-RestMethod -Uri "http://127.0.0.1:$p" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 5).result
        "port $p : total=$($r.total_transactions)"; $up++
    } catch { "port $p : DOWN" }
}
"nodes up: $up/8"