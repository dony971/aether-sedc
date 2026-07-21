$env:Path = "C:\Users\Shadow\AppData\Local\Temp\opencode\mingw\mingw64\bin;" + [Environment]::GetEnvironmentVariable("Path","User") + ";" + [Environment]::GetEnvironmentVariable("Path","Machine")
$env:CARGO_HOME = "$env:USERPROFILE\.cargo"
$env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
Set-Location "C:\Users\Shadow\Documents\aether-fix\aether-main"

# Kill existing aether processes
Get-Process -Name "aether" -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep 2

# Clean data
Remove-Item "data-bootnode" -Recurse -ErrorAction SilentlyContinue
Remove-Item "data-miner-1" -Recurse -ErrorAction SilentlyContinue
Remove-Item "data-miner-2" -Recurse -ErrorAction SilentlyContinue
Remove-Item "multi-node-logs" -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "multi-node-logs" -Force | Out-Null

Write-Host "=== Starting bootnode (P2P:25565 RPC:9933) ==="
$bootLog = "multi-node-logs/bootnode"
Start-Process -FilePath "target/debug/aether.exe" -ArgumentList "--node-type","miner","--data-dir","data-bootnode","--p2p-port","25565","--rpc-port","9933" -WindowStyle Hidden -RedirectStandardOutput "$bootLog.out" -RedirectStandardError "$bootLog.err"
Write-Host "Bootnode started"

# Wait for RPC
Write-Host "Waiting for bootnode RPC..."
Start-Sleep 5
for ($i = 0; $i -lt 25; $i++) {
    try {
        $body = '{"jsonrpc":"2.0","method":"aether_getDagStats","params":[],"id":1}'
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:9933" -Method Post -ContentType "application/json" -Body $body -ErrorAction SilentlyContinue
        if ($r.result) { Write-Host "Bootnode READY!" -ForegroundColor Green; break }
    } catch {}
    Start-Sleep 1
}

Write-Host "=== Starting miner1 (P2P:25566 RPC:9934) ==="
$m1Log = "multi-node-logs/miner1"
Start-Process -FilePath "target/debug/aether.exe" -ArgumentList "--node-type","miner","--data-dir","data-miner-1","--p2p-port","25566","--rpc-port","9934","--bootnodes","127.0.0.1:25565" -WindowStyle Hidden -RedirectStandardOutput "$m1Log.out" -RedirectStandardError "$m1Log.err"
Write-Host "Miner1 started"

Write-Host "=== Starting miner2 (P2P:25567 RPC:9935) ==="
$m2Log = "multi-node-logs/miner2"
Start-Process -FilePath "target/debug/aether.exe" -ArgumentList "--node-type","miner","--data-dir","data-miner-2","--p2p-port","25567","--rpc-port","9935","--bootnodes","127.0.0.1:25565" -WindowStyle Hidden -RedirectStandardOutput "$m2Log.out" -RedirectStandardError "$m2Log.err"
Write-Host "Miner2 started"

Write-Host "`n=== Network is running! ===" -ForegroundColor Cyan
Write-Host "Bootnode: http://127.0.0.1:9933" -ForegroundColor Cyan
Write-Host "Miner1:   http://127.0.0.1:9934" -ForegroundColor Cyan
Write-Host "Miner2:   http://127.0.0.1:9935" -ForegroundColor Cyan
Write-Host "Logs: multi-node-logs/"
Write-Host "Run the following to test P2P propagation:"
Write-Host '  curl -X POST http://127.0.0.1:9934 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"aether_faucet\",\"params\":[\"test\"],\"id\":1}"'
Write-Host "Then check stats on all nodes..."
