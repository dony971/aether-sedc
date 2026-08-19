# phase_d_fund.ps1 - fund the 12 campaign wallets via the faucet on the fresh
# Phase D network (node1 RPC 42101). The faucet works at genesis (cold oracle,
# fee 1). Cooldown is per-beneficiary address: 12 distinct wallets = 12 rapid
# requests. Each faucet tx is drained into the DAG within ~150ms by the drainer.
param(
    [string]$Rpc = "42101"
)
$ErrorActionPreference = "Stop"
$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether.exe"
$Root = Join-Path $env:TEMP "opencode\aether-canary-b4"
$PW = "canary-pass-2026"
$ok = 0; $fail = 0
foreach ($name in @("gen","wb1","wb2","wb3","b8_0","b8_1","b8_2","b8_3","b8_4","b8_5","b8_6","b8_7")) {
    $w = Join-Path $Root "$name.json"
    if (-not (Test-Path $w)) { Write-Output "$name : WALLET MISSING"; $fail++; continue }
    $bout = (& $Bin balance $w --rpc-url "http://127.0.0.1:$Rpc" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
    if (-not $addr) { Write-Output "$name : NO ADDRESS"; $fail++; continue }
    $bal0 = (Invoke-RestMethod -Uri "http://127.0.0.1:$Rpc" -Method Post -Body (@{jsonrpc="2.0";method="aether_getBalance";params=@($addr);id=1} | ConvertTo-Json -Compress) -ContentType "application/json" -TimeoutSec 5).result.balance
    try {
        $fr = Invoke-RestMethod -Uri "http://127.0.0.1:$Rpc" -Method Post -Body (@{jsonrpc="2.0";method="aether_faucet";params=@($addr);id=1} | ConvertTo-Json -Compress) -ContentType "application/json" -TimeoutSec 20
        if ($fr.error) { Write-Output "$name : FAUCET ERROR $($fr.error.message)"; $fail++; continue }
    } catch { Write-Output "$name : FAUCET EXCEPTION $_"; $fail++; continue }
    Start-Sleep -Milliseconds 1500
    $bal1 = (Invoke-RestMethod -Uri "http://127.0.0.1:$Rpc" -Method Post -Body (@{jsonrpc="2.0";method="aether_getBalance";params=@($addr);id=1} | ConvertTo-Json -Compress) -ContentType "application/json" -TimeoutSec 5).result.balance
    $delta = [long]$bal1 - [long]$bal0
    if ($delta -ge 100000000000) { Write-Output "$name : funded (+$delta raw)"; $ok++ } else { Write-Output "$name : FUNDING FAILED (delta $delta)"; $fail++ }
}
Write-Output ("funding done: $ok ok, $fail failed")