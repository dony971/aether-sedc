# LOG 9-node mini-canary (§8): fresh 9 nodes + txs + restart + crash +
# resync. Answers from LOGS (not RPC, except final convergence):
# which node / when / state / peers / ongoing op / tx count /
# sync progress / recovery.
param([string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe")
$ErrorActionPreference = "Stop"
$root = Join-Path $env:TEMP "opencode\log-mini9"
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

# faucet.key for the mini seed (local test infra only)
$d1 = Join-Path $root "node1"; New-Item -ItemType Directory -Force -Path $d1 | Out-Null
Copy-Item "$env:TEMP\opencode\aether-canary-c2\node1\faucet.key" (Join-Path $d1 "faucet.key")

# 9 fresh nodes
for ($i = 1; $i -le 9; $i++) {
    $d = Join-Path $root "node$i"
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$d,"--p2p-port",(49500+$i),"--rpc-port",(49600+$i),"--bootnodes","127.0.0.1:49501") -WindowStyle Hidden | Out-Null
}
Write-Host "waiting for mesh..."
Start-Sleep 40

# txs via gen_optimized (C2 test wallets, auto-funded by mini faucet)
$gen = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\gen_optimized.exe"
$gp = Start-Process -FilePath $gen -ArgumentList @("--wallet-dir","$env:TEMP\opencode\aether-canary-c2w","--rpc-url","http://127.0.0.1:49601","--password","canary-pass-2026","--count","60","--workers","4") -RedirectStandardOutput (Join-Path $root "gen.txt") -PassThru
$gp.WaitForExit(180000) | Out-Null
Get-Content (Join-Path $root "gen.txt") -Tail 1

# restart node3 (graceful attempt impossible headless -> hard restart, UNCLEAN expected)
KillDir (Join-Path $root "node3"); Start-Sleep 2
Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",(Join-Path $root "node3"),"--p2p-port",49503,"--rpc-port",49603,"--bootnodes","127.0.0.1:49501") -WindowStyle Hidden | Out-Null
# crash node5
Start-Sleep 5
KillDir (Join-Path $root "node5"); Start-Sleep 2
Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",(Join-Path $root "node5"),"--p2p-port",49505,"--rpc-port",49605,"--bootnodes","127.0.0.1:49501") -WindowStyle Hidden | Out-Null
Write-Host "waiting for resync..."
Start-Sleep 60

# --- answer from LOGS ---
function LogOf($i) { Get-Content (Join-Path $root "node$i\logs\node.log") -EA SilentlyContinue | Out-String }
$l3 = LogOf 3; $l5 = LogOf 5; $l1 = LogOf 1
Check "Q1 which node: tags node3/node5 present" ($l3 -match "\| node3 \|" -and $l5 -match "\| node5 \|")
Check "Q2 when: ISO8601 timestamps" ($l3 -match "20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ")
Check "Q3 state: UNCLEAN after kill on both" ($l3 -match "previous shutdown UNCLEAN" -and $l5 -match "previous shutdown UNCLEAN")
Check "Q4 peers: peer lines in logs" ($l1 -match "peer|Peer")
Check "Q5 ongoing op: sync/mempool/tx lines" ($l1 -match "Sync|sync|Mempool|mempool|Transaction|transaction")
Check "Q6 tx count: DAG total lines or RPC" ($l1 -match "total|DAG")
Check "Q7 sync progress: requested/received/resolved" ($l3 -match "received|resolved|progress|inventory" -or $l5 -match "received|resolved|progress|inventory")
Check "Q8 recovery: rebuild or recovery lines" ($l3 -match "(?i)rebuild|recovery|orphan" -or $l5 -match "(?i)rebuild|recovery|orphan")

# final convergence via RPC
$ref = (Rpc 49601 "aether_getDagStats").total_transactions
$m = 1
foreach ($r in @(49602,49603,49604,49605,49606,49607,49608,49609)) {
    try { if ((Rpc $r "aether_getDagStats").total_transactions -eq $ref) { $m++ } } catch {}
}
Write-Host "convergence: $m/9 at total=$ref"
Check "all 9 converged" ($m -eq 9)

for ($i = 1; $i -le 9; $i++) { KillDir (Join-Path $root "node$i") }
if ($fail -gt 0) { Write-Host "LOG-MINI9: FAIL ($fail)"; exit 1 }
Write-Host "LOG-MINI9: ALL PASS"
