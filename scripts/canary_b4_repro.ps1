# canary_b4_repro.ps1 - Phase B4 reproduction/non-regression harness
# Fresh-node cold-start joins at increasing DAG sizes, with convergence
# checks (txset/dag/tips/ledger/weights/supply) and sync counters.
# Uses the FIXED binary (target-b4) on dedicated ports 51001+ so the
# running 5-node campaign (42001-46101) is untouched.
$ErrorActionPreference = "Stop"

$Root   = Join-Path $env:TEMP "opencode\canary-b4"
$Bin    = "C:\Users\Shadow\Documents\aether-fix\aether-main\target-b4\release\aether-unified.exe"
$Log    = Join-Path $Root "canary_b4_repro.log"
$PW     = "canary-pass-2026"
$Seed   = "51001"; $SeedRpc = "51101"; $SeedBoot = "127.0.0.1:51001"
$Relay  = "52001"; $RelayRpc = "52101"
$Sizes  = @{ 100 = "53001"; 224 = "54001"; 300 = "55001"; 463 = "56001"; 500 = "57001" }
$J6     = "58001"; $J6Rpc = "58101"
$JR     = "59001"; $JRpc = "59101"
$J7     = "60001"; $J7Rpc = "60101"

$script:passes = 0; $script:fails = 0; $script:pids = @()

function Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $Log -Value $line -Encoding ascii
    Write-Host $line
}
function FailIf($cond, $msg) {
    if ($cond) { $script:fails++; Log ("  FAIL: " + $msg) } else { $script:passes++; Log ("  PASS: " + $msg) }
}
function Rpc($port, $method, $params) {
    $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 6
    Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 90
}
function HexId($b) {
    if ($null -eq $b) { return "" }
    if ($b -is [string]) { return $b }
    if ($b -is [byte[]]) { return (($b | ForEach-Object { $_.ToString("x2") }) -join "") }
    return ("$b")
}
function Get-State($port) {
    # B4 note: getDagGraph defaults to a 500-node cap - pass an explicit
    # limit so joins above 500 txs compare the FULL DAG.
    $g = (Rpc $port "aether_getDagGraph" @(10000)).result
    $st = (Rpc $port "aether_getDagStats" @()).result
    $tips = @((Rpc $port "aether_getTips" @()).result.tips | Sort-Object | ForEach-Object { HexId $_ })
    $known = @("a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb","2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    $led = @()
    $supply = 0
    foreach ($a in $known) {
        $b = (Rpc $port "aether_getBalance" @($a)).result.balance
        $n = (Rpc $port "aether_getAccountNonce" @($a)).result.next_nonce
        $led += "$a=$b/$n"
        $supply += [long]$b
    }
    $txset = @($g.nodes | ForEach-Object { HexId $_.tx_id } | Sort-Object)
    $dag = @($g.edges | ForEach-Object { (HexId $_.from) + "->" + (HexId $_.to) } | Sort-Object)
    $w = @($g.nodes | Sort-Object { HexId $_.tx_id } | ForEach-Object { (HexId $_.tx_id) + ":" + $_.weight })
    return @{
        txset = ($txset -join ","); dag = ($dag -join ","); tips = ($tips -join ",")
        led = ($led -join ";"); w = ($w -join ","); supply = "$supply"
        total = [long]$st.total_transactions
    }
}
function Node-Rpc-Up($port) {
    try { $r = Rpc $port "aether_getDagStats" @(); if ($null -ne $r.result.total_transactions) { return $true } } catch {}
    return $false
}
function Start-Node($id, $p2p, $rpc, $boot, $fresh) {
    $ndir = Join-Path $Root "node$id"
    if ($fresh) { if (Test-Path $ndir) { Remove-Item -Recurse -Force $ndir } }
    New-Item -ItemType Directory -Force -Path $ndir | Out-Null
    $nargs = @("--node-type","validator","--data-dir",$ndir,"--p2p-port","$p2p","--rpc-port","$rpc")
    if ($boot -ne "") { $nargs += @("--bootnodes",$boot) }
    $p = Start-Process -FilePath $Bin -ArgumentList $nargs -RedirectStandardOutput (Join-Path $ndir "node.log") -RedirectStandardError (Join-Path $ndir "node.err") -WindowStyle Hidden -PassThru -ErrorAction Stop
    $script:pids += $p.Id
    Log ("  started node$id (p2p $p2p rpc $rpc boot '$boot' fresh=$fresh) pid=$($p.Id)")
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Node-Rpc-Up $rpc)) {
        if ((Get-Date) -gt $deadline) { return $false }
        if ($p.HasExited) { Log ("  node$id exited early: " + (Get-Content (Join-Path $ndir "node.err") -ErrorAction SilentlyContinue | Select-Object -Last 3)); return $false }
        Start-Sleep -Milliseconds 1500
    }
    Log ("  node$id RPC up")
    return $true
}
function Stop-Node($dirName) {
    $pp = Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" | Where-Object { $_.CommandLine -match ([regex]::Escape($Root) + "\\" + $dirName + "\\") }
    foreach ($p in $pp) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}
function Gen-To($target) {
    try { $base = (Rpc $SeedRpc "aether_getDagStats" @()).result.total_transactions } catch { $base = -1 }
    if ([long]$base -ge $target) { return }
    Log ("  generating to $target (at $base)...")
    $tries = 0; $sent = 0
    while ($sent -lt $target -and $tries -lt 5000) {
        $tries++
        try { if ((Rpc $SeedRpc "aether_getDagStats" @()).result.total_transactions -ge $target) { break } } catch {}
        $o = (& $Bin send $genAddr 1 100 --rpc-url "http://127.0.0.1:$SeedRpc" --wallet $genWallet --password $PW 2>&1 | Out-String)
        if ($o -match "REJECTED|Failed|error") { Start-Sleep -Milliseconds 300; continue }
        $sent++
        if ($sent % 100 -eq 0) { Log ("    generated $sent ...") }
    }
    try { $got = (Rpc $SeedRpc "aether_getDagStats" @()).result.total_transactions } catch { $got = -1 }
    Log ("  generation done: seed total=$got")
    return $got
}
function Wait-Converged($refPort, $port, $label, $timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $js = $null; $rs = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $rs = Get-State $refPort; $js = Get-State $port
            if ($js.total -eq $rs.total -and $js.txset -eq $rs.txset -and $js.dag -eq $rs.dag -and $js.tips -eq $rs.tips -and $js.led -eq $rs.led -and $js.w -eq $rs.w -and $js.supply -eq $rs.supply) {
                $sw.Stop()
                Log ("  CONVERGED [$label] in {0:N1}s (total={1})" -f $sw.Elapsed.TotalSeconds, $js.total)
                return @{ ok = $true; secs = $sw.Elapsed.TotalSeconds }
            }
        } catch {}
        Start-Sleep -Seconds 5
    }
    $sw.Stop()
    $jt = ""; $rt = ""
    if ($null -ne $js) { $jt = $js.total }; if ($null -ne $rs) { $rt = $rs.total }
    Log ("  TIMEOUT [$label] after {0:N0}s (joiner total {1} vs seed {2})" -f $sw.Elapsed.TotalSeconds, $jt, $rt)
    return @{ ok = $false; secs = $sw.Elapsed.TotalSeconds }
}
function Show-Stats($port, $label) {
    try {
        $s = (Rpc $port "aether_getSyncStats" @()).result
        Log ("  sync[$label] requested={0} received={1} progress={2} batches={3} orphan_created={4} orphan_resolved={5} orphan_purged={6} retries={7} parent_requested={8} parent_deduped={9} dup_ignored={10}" -f $s.sync_requested,$s.sync_received,$s.sync_progress,$s.sync_batches,$s.orphan_created,$s.orphan_resolved,$s.orphan_purged,$s.retry_count,$s.parent_requested,$s.parent_already_known,$s.duplicate_ignored)
        return $s
    } catch { Log ("  sync[$label] stats unavailable"); return $null }
}

# ============ RUN ============
if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
New-Item -ItemType Directory -Force -Path $Root | Out-Null
Log "=== CANARY PHASE B4 REPRO (fixed binary, ports 51001+) ==="
Log ("binary: " + $Bin)

# seed (faucet.key present from the first boot - no restart needed)
New-Item -ItemType Directory -Force -Path (Join-Path $Root "node1") | Out-Null
Copy-Item "C:\Users\Shadow\AppData\Local\Temp\opencode\aether-canary-a\node1\faucet.key" (Join-Path $Root "node1\faucet.key") -Force
$ok = Start-Node 1 $Seed $SeedRpc "" $false
FailIf (-not $ok) "seed-1 start with faucet.key"

# generator wallet
$genWallet = Join-Path $Root "gen.json"
"$PW`n" | & $Bin wallet create $genWallet 2>&1 | Out-Null
$bout = (& $Bin balance $genWallet --rpc-url "http://127.0.0.1:$SeedRpc" --password $PW 2>&1 | Out-String)
$genAddr = ([regex]::Match($bout, "Address: ([0-9a-fA-F]{64})")).Groups[1].Value.ToLower()
FailIf ($genAddr -eq "") "generator wallet address"
if ($genAddr -eq "") { Log "ABORT: no generator address"; exit 1 }
Log ("  generator wallet: $genAddr")
for ($i = 0; $i -lt 20; $i++) { try { Rpc $SeedRpc "aether_faucet" @($genAddr) | Out-Null } catch {}; Start-Sleep -Milliseconds 300 }
$bal = (Rpc $SeedRpc "aether_getBalance" @($genAddr)).result.balance
Log ("  generator balance: $bal")
FailIf ([long]$bal -lt 100000) "generator funded >= 100 AETH"

$total = (Rpc $SeedRpc "aether_getDagStats" @()).result.total_transactions
Log ("  seed initial total (incl faucet): $total")

# ---- sizes 100/224/300/463 (relay joins at 300)
$relayPid = $null
foreach ($size in @(100, 224, 300, 463)) {
    Gen-To ($total + $size)
    if ($size -eq 300) {
        $ok = Start-Node "R" $Relay $RelayRpc $SeedBoot $true
        FailIf (-not $ok) "relay start at 300"
        $c = Wait-Converged $SeedRpc $RelayRpc "relay@300" 900
        FailIf (-not $c.ok) "relay converges at 300"
        Show-Stats $RelayRpc "relay@300" | Out-Null
    }
    $p2p = $Sizes[$size]; $rpc = [string]([int]$p2p + 100); $id = "J" + $size
    $ok = Start-Node $id $p2p $rpc $SeedBoot $true
    FailIf (-not $ok) "joiner $id start at $size"
    $c = Wait-Converged $SeedRpc $rpc "joiner@$size" 1200
    FailIf (-not $c.ok) "joiner@$size converges ($size txs)"
    if ($c.ok) { Show-Stats $rpc "joiner@$size" | Out-Null }
}

# ---- simultaneous join at 500 (J5 + J6)
Gen-To ($total + 500)
$ok = Start-Node "J5" "57001" "57101" $SeedBoot $true; FailIf (-not $ok) "J5 start at 500"
$ok = Start-Node "J6" $J6 $J6Rpc $SeedBoot $true;   FailIf (-not $ok) "J6 start at 500"
$c5 = Wait-Converged $SeedRpc "57101" "J5@500-simultaneous" 1200
$c6 = Wait-Converged $SeedRpc $J6Rpc "J6@500-simultaneous" 1200
FailIf (-not ($c5.ok -and $c6.ok)) "simultaneous joiners converge at 500"
if ($c5.ok) { Show-Stats "57101" "J5@500" | Out-Null }
if ($c6.ok) { Show-Stats $J6Rpc "J6@500" | Out-Null }

# ---- restart during bootstrap at 800
Gen-To ($total + 800)
$ok = Start-Node "JR" $JR $JRpc $SeedBoot $true
FailIf (-not $ok) "JR start at 800"
$deadline = (Get-Date).AddSeconds(600); $killed = $false
while ((Get-Date) -lt $deadline -and -not $killed) {
    Start-Sleep -Seconds 5
    try {
        $t = (Rpc $JRpc "aether_getDagStats" @()).result.total_transactions
        if ($t -gt 150 -and $t -lt 700) { $killed = $true }
    } catch {}
}
FailIf (-not $killed) "JR reached mid-sync window before kill"
if ($killed) {
    Log ("  killing JR mid-bootstrap (total=" + (Rpc $JRpc "aether_getDagStats" @()).result.total_transactions + ")")
    Stop-Node "nodeJR"
    $ok = Start-Node "JR" $JR $JRpc $SeedBoot $false
    FailIf (-not $ok) "JR restart"
    $c = Wait-Converged $SeedRpc $JRpc "JR-restart@800" 1200
    FailIf (-not $c.ok) "JR converges after restart during bootstrap"
    if ($c.ok) { Show-Stats $JRpc "JR-restart@800" | Out-Null }
}

# ---- churn: relay stopped during J7 bootstrap at 1000
Gen-To ($total + 1000)
Stop-Node "nodeR"
Log ("  relay stopped before J7 join")
$ok = Start-Node "J7" $J7 $J7Rpc $SeedBoot $true
FailIf (-not $ok) "J7 start at 1000 (seed only)"
Start-Sleep -Seconds 30
$ok = Start-Node "R" $Relay $RelayRpc $SeedBoot $false
FailIf (-not $ok) "relay restart"
$c7 = Wait-Converged $SeedRpc $J7Rpc "J7@1000-churn" 1500
$cr = Wait-Converged $SeedRpc $RelayRpc "relay-resync@1000" 1500
FailIf (-not ($c7.ok -and $cr.ok)) "J7 and relay converge at 1000 (churn)"
if ($c7.ok) { Show-Stats $J7Rpc "J7@1000" | Out-Null }
if ($cr.ok) { Show-Stats $RelayRpc "relay@1000" | Out-Null }

# ---- summary
Log "=== B4 REPRO SUMMARY: $($script:passes) passed, $($script:fails) failed ==="
if ($script:fails -gt 0) { exit 1 } else { exit 0 }
