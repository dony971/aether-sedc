# phase_c_escalation.ps1 - PHASE C evidence: mempool-capacity behavior.
# The mempool (max 1000, never drains) gates DAG growth: beyond ~1000 txs a
# new tx must STRICTLY exceed the pool's minimum fee (eviction bidding).
# This script: (1) ramps the network to ~1100 txs with escalating fees,
# (2) runs the CRITICAL fresh-node join at >1000 txs to test bootstrap.
$ErrorActionPreference = "Continue"
$Root = Join-Path $env:TEMP "opencode\aether-canary-b4"
$Bin  = "C:\Users\Shadow\Documents\aether-fix\aether-main\target-b4\release\aether-unified.exe"
$LOG  = Join-Path $Root "phase_c_escalation.log"
$PW   = "canary-pass-2026"
function Log($m) { $l = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m; Add-Content $LOG $l -Encoding ascii; Write-Host $l }
function Rpc($p, $m, $params) { try { $b = @{jsonrpc="2.0";method=$m;params=$params;id=1} | ConvertTo-Json -Compress -Depth 6; (Invoke-RestMethod -Uri "http://127.0.0.1:$p" -Method Post -Body $b -ContentType "application/json" -TimeoutSec 120).result } catch { $null } }
function HexId($b) { if ($null -eq $b) { return "" }; if ($b -is [string]) { return $b }; if ($b -is [byte[]]) { return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }; "$b" }
function Get-State($p) {
    $g = Rpc $p "aether_getDagGraph" @(10000); $st = Rpc $p "aether_getDagStats" @()
    $tips = @((Rpc $p "aether_getTips" @()).tips | Sort-Object | ForEach-Object { HexId $_ })
    $led = @(); $supply = 0
    foreach ($a in @("a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb","2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) {
        $b = (Rpc $p "aether_getBalance" @($a)).balance; $n = (Rpc $p "aether_getAccountNonce" @($a)).next_nonce
        $led += "$a=$b/$n"; $supply += [long]$b
    }
    $txset = @($g.nodes | ForEach-Object { HexId $_.tx_id } | Sort-Object)
    $dag = @($g.edges | ForEach-Object { (HexId $_.from) + "->" + (HexId $_.to) } | Sort-Object)
    $w = @($g.nodes | Sort-Object { HexId $_.tx_id } | ForEach-Object { (HexId $_.tx_id) + ":" + $_.weight })
    return @{ txset = ($txset -join ","); dag = ($dag -join ","); tips = ($tips -join ","); led = ($led -join ";"); w = ($w -join ","); supply = "$supply"; total = [long]$st.total_transactions }
}
function Converged($ref, $s) { foreach ($k in @("txset","dag","tips","led","w","supply","total")) { if ($s.$k -ne $ref.$k) { return $false } }; return $true }
Log "=== PHASE C ESCALATION (mempool capacity evidence) ==="
$wallets = @()
foreach ($i in 0..7) { $f = Join-Path $Root ("b8_" + $i + ".json"); $o = (& $Bin balance $f --rpc-url "http://127.0.0.1:42101" --password $PW 2>&1 | Out-String); $a = ([regex]::Match($o, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower(); $wallets += @{ path = $f; addr = $a } }
$base = (Rpc 42101 "aether_getDagStats" @()).total_transactions
Log ("  starting total=$base")
$target = 1100
$fee = 300; $wave = 0; $accepted = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ((Rpc 42101 "aether_getDagStats" @()).total_transactions -lt $target -and $wave -lt 400) {
    $wave++
    foreach ($w in $wallets) {
        $attempts = 0
        while ($attempts -lt 12) {
            $attempts++
            $p = Start-Process -FilePath $Bin -ArgumentList @("send", $w.addr, "1", "$fee", "--rpc-url", "http://127.0.0.1:42101", "--wallet", $w.path, "--password", $PW) -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            $p.WaitForExit(120000) | Out-Null
            if ($p.ExitCode -eq 0) { $accepted++; break }
            $fee += 200
            if ($attempts -ge 12) { break }
            Start-Sleep -Milliseconds 400
        }
        if ((Rpc 42101 "aether_getDagStats" @()).total_transactions -ge $target) { break }
    }
    if ($wave % 10 -eq 0) { Log ("  wave $wave fee=$fee accepted=$accepted total=$((Rpc 42101 'aether_getDagStats' @()).total_transactions)") }
}
$sw.Stop()
Log ("  RAMP done: accepted=$accepted waves=$wave fees up to $fee in {0:N0}s, total=$((Rpc 42101 'aether_getDagStats' @()).total_transactions)" -f $sw.Elapsed.TotalSeconds)
# ---- CRITICAL JOIN at >1000
$total = (Rpc 42101 "aether_getDagStats" @()).total_transactions
Log ("=== CRITICAL JOIN @ $total (fresh node14) ===")
$ndir = Join-Path $Root "node14"
if (Test-Path $ndir) { Remove-Item -Recurse -Force $ndir }
New-Item -ItemType Directory -Force -Path $ndir | Out-Null
Start-Process -FilePath $Bin -ArgumentList @("--node-type","validator","--data-dir",$ndir,"--p2p-port","55001","--rpc-port","55101","--bootnodes","127.0.0.1:42001") -RedirectStandardOutput (Join-Path $ndir "node.log") -RedirectStandardError (Join-Path $ndir "node.err") -WindowStyle Hidden | Out-Null
$up = $false
for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Seconds 2; if ($null -ne (Rpc 55101 "aether_getDagStats" @())) { $up = $true; break } }
Log ("  node14 up=$up")
$sw2 = [System.Diagnostics.Stopwatch]::StartNew()
$ok = $false
for ($i = 0; $i -lt 600; $i++) {
    Start-Sleep -Seconds 5
    $s = Get-State 55101; $r = Get-State 42101
    if ($null -ne $s.txset -and (Converged $r $s)) { $sw2.Stop(); $ok = $true; Log ("  CONVERGED in {0:N0}s at total=$($r.total)" -f $sw2.Elapsed.TotalSeconds); break }
    if ($i % 12 -eq 0) { Log ("    join progress: joiner=$($s.total) seed=$($r.total) txsetMatches=$($s.txset -eq $r.txset)") }
}
if (-not $ok) { $sw2.Stop(); Log ("  JOIN TIMEOUT after {0:N0}s - joiner=$((Get-State 55101).total) seed=$((Get-State 42101).total)" -f $sw2.Elapsed.TotalSeconds) }
$ss = Rpc 55101 "aether_getSyncStats" @()
Log ("  syncStats joiner: requested=$($ss.sync_requested) received=$($ss.sync_received) batches=$($ss.sync_batches) orphan_created=$($ss.orphan_created) orphan_resolved=$($ss.orphan_resolved) orphan_purged=$($ss.orphan_purged) retries=$($ss.retry_count)")
Log "=== ESCALATION SCRIPT END ==="