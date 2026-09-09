# LOG-SYNC-03 + LOG-P2P-04 — bootstrap progress + peer lifecycle in logs.
# Seed + fresh node; assert sync/handshake/connect lines; kill seed to
# force disconnect lines, restart seed, assert reconnect lines.
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\log-sync-p2p"
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
function StartNode($dir, $p2p, $rpc, $boot) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$dir,"--p2p-port",$p2p,"--rpc-port",$rpc,"--bootnodes",$boot) -WindowStyle Hidden | Out-Null
}

$seed = Join-Path $root "seed"; $joinee = Join-Path $root "joinee"
StartNode $seed 49411 49412 "127.0.0.1:49411"
Start-Sleep 20
StartNode $joinee 49413 49414 "127.0.0.1:49411"
Start-Sleep 30

$jl = Join-Path $joinee "logs\node.log"
$jf = Get-Content $jl -EA SilentlyContinue | Out-String
Check "SYNC: joinee log exists with boot" ($jf -match "BOOT aether")
Check "SYNC: peer connected line" ($jf -match "New peer connected|Connected to peer")
Check "SYNC: handshake line" ($jf -match "handshake complete")
Check "SYNC: inventory/sync lines" ($jf -match "inventory|Inventory|sync_requested|Sync")
$t = (Rpc 49414 "aether_getDagStats").total_transactions
Check "SYNC: joinee converged at 0/0 with seed" ($t -eq 0)

# P2P-04: kill seed -> disconnect lines; restart -> reconnect lines
KillDir $seed
Start-Sleep 20
$jf2 = Get-Content $jl -EA SilentlyContinue | Out-String
Check "P2P: disconnect line after seed kill" ($jf2 -match "disconnected|removed from peers map|Failed to connect|reconnect")
StartNode $seed 49411 49412 "127.0.0.1:49411"
Start-Sleep 30
$jf3 = Get-Content $jl -EA SilentlyContinue | Out-String
$peers = (Rpc 49414 "aether_getDagStats").connected_peers
Check "P2P: reconnected (peers=$peers)" ($peers -ge 1)
Check "P2P: reconnect/connect line present" ($jf3 -match "Connected to peer|New peer connected|Reconnecting")

KillDir $seed; KillDir $joinee
if ($fail -gt 0) { Write-Host "LOG-SYNC-P2P: FAIL ($fail)"; exit 1 }
Write-Host "LOG-SYNC-03 + LOG-P2P-04: ALL PASS"
