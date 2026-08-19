param(
    [Parameter(Mandatory=$true)][long]$Target,
    [string]$Label = "ramp"
)
$ErrorActionPreference = "Stop"
$Root = "$env:TEMP\opencode\aether-canary-phase-d"
$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether.exe"
$Wallets = "$env:TEMP\opencode\aether-canary-b4"
$PW = "canary-pass-2026"
$genWallets = @()
foreach ($i in 0..7) {
    $f = "$Wallets\b8_$i.json"
    $o = (& $Bin balance $f --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String)
    $addr = ([regex]::Match($o, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
    if (-not $addr) { throw "cannot resolve address for b8_$i" }
    $genWallets += @{ addr = $addr; path = $f }
}
function TxTotal { return [long](Invoke-RestMethod -Uri "http://127.0.0.1:42101" -Method Post -Body (@{jsonrpc="2.0";method="aether_getDagStats";params=@();id=1} | ConvertTo-Json -Compress) -ContentType "application/json" -TimeoutSec 10).result.total_transactions }
$log = "$Root\ramp.log"
"=== ramp to $Target (label $Label) started $(Get-Date) ===" | Out-File $log
$base = TxTotal
if ($base -ge $Target) { "already at $base >= $Target, nothing to do" | Out-File $log -Append; exit 0 }
"base=$base target=$Target" | Out-File $log -Append
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$accepted = 0; $waves = 0
while ((TxTotal) -lt $Target -and $waves -lt 9000) {
    $waves++
    $procs = @()
    foreach ($gw in $genWallets) {
        $procs += Start-Process -FilePath $Bin -ArgumentList @("send", $gw.addr, "1", "100", "--rpc-url", "http://127.0.0.1:42101", "--wallet", $gw.path, "--password", $PW) -WindowStyle Hidden -PassThru
    }
    foreach ($p in $procs) { $p.WaitForExit(120000) | Out-Null }
    foreach ($p in $procs) { if ($p.ExitCode -eq 0) { $accepted++ } }
    if ($waves % 25 -eq 0) { "  wave $waves accepted=$accepted total=$(TxTotal)" | Out-File $log -Append }
}
$sw.Stop()
$tps = $accepted / $sw.Elapsed.TotalSeconds
"RAMP[$Label] accepted=$accepted in {0:N0}s => {1:N2} tx/s (seed total=$(TxTotal))" -f $sw.Elapsed.TotalSeconds, $tps | Out-File $log -Append
exit 0