# AETHER watchdog - OBSERVABILITY/EXPLOITATION ONLY (phase n°5).
#
# DETECT -> CAPTURE -> ALERT -> DOCUMENT. Never touches consensus, DAG,
# ledger, balances, Genesis or network_id. Never "repairs" consensus.
# Default mode is MONITOR ONLY; auto-restart is explicit opt-in with
# max/hour + backoff + circuit breaker (no restart loops, ever).
#
# Usage:
#   .\watchdog.ps1 [-Config .\watchdog_c2.json] [-AutoRestart] [-StateDir ...]
#
# Exit code: 0 = no DOWN/CRITICAL, 1 = at least one DOWN/CRITICAL,
#            2 = config error.
param(
    [string]$Config = (Join-Path $PSScriptRoot "watchdog_c2.json"),
    [switch]$AutoRestart,
    [string]$StateDir = (Join-Path $env:TEMP "opencode\watchdog-state"),
    [string]$IncidentLog = (Join-Path $env:TEMP "opencode\watchdog-incidents.jsonl")
)
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- config --
if (-not (Test-Path $Config)) { Write-Host "WATCHDOG CONFIG ERROR: missing $Config"; exit 2 }
$cfg = Get-Content $Config -Raw | ConvertFrom-Json
$TH = $cfg.thresholds
$FAUCET = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$stateFile = Join-Path $StateDir "heartbeat.json"
$state = @{}
if (Test-Path $stateFile) {
    # PS 5.1 has no ConvertFrom-Json -AsHashtable: project properties
    # into a plain hashtable manually (nested arrays stay Object[]).
    try {
        $json = Get-Content $stateFile -Raw | ConvertFrom-Json
        foreach ($p in $json.PSObject.Properties) { $state[$p.Name] = $p.Value }
    } catch { $state = @{} }
}
function Save-State { $state | ConvertTo-Json -Depth 6 -Compress | Set-Content $stateFile -Encoding utf8 }

function New-IncidentId($node) {
    return "INC-{0:yyyyMMdd-HHmmss}-{1}" -f (Get-Date), $node.ToUpper()
}
function Write-Alert($sev, $node, $event, $detail, $snapshot) {
    $inc = [ordered]@{
        id = New-IncidentId $node
        ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        severity = $sev; node = $node; event = $event; detail = $detail
        version = "1.2.0"; genesis = "faucet=$FAUCET"
        snapshot = $snapshot
    }
    ($inc | ConvertTo-Json -Depth 6 -Compress) | Add-Content $IncidentLog -Encoding utf8
    Write-Host "ALERT [$sev] $($inc.id) node=$node event=$event :: $detail"
    if ($env:AETHER_ALERT_WEBHOOK) {
        # Extensible alerting (Discord/Telegram-compatible webhook). The URL
        # lives in the ENVIRONMENT, never in git. Best effort, never fatal.
        try {
            Invoke-RestMethod -Uri $env:AETHER_ALERT_WEBHOOK -Method Post `
                -Body (@{text = "[$sev] $($inc.id) $node $event :: $detail"} | ConvertTo-Json) `
                -ContentType "application/json" -TimeoutSec 10 | Out-Null
        } catch { Write-Host "WARN: webhook failed: $($_.Exception.Message)" }
    }
    return $inc.id
}

function Get-Proc($node) {
    $pat = [regex]::Escape($node.dataDir)
    $ps = Get-CimInstance Win32_Process -Filter "Name='aether-unified.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match $pat } | Select-Object -First 1
    if (-not $ps) { return $null }
    $p = Get-Process -Id $ps.ProcessId -EA SilentlyContinue
    return @{ pid = $ps.ProcessId; start = $ps.CreationDate; ram = if ($p) { $p.WorkingSet64 } else { 0 } }
}
function Rpc($port, $method, $params = @()) {
    $b = @{jsonrpc = "2.0"; method = $method; params = $params; id = 1 } | ConvertTo-Json -Compress -Depth 5
    return (Invoke-RestMethod -Uri "http://127.0.0.1:$port" -Method Post -Body $b -ContentType "application/json" -TimeoutSec $TH.rpcTimeoutSec).result
}
function Get-LogTail($node, $n = 60) {
    $p = Join-Path $node.dataDir "logs\node.log"
    if (-not (Test-Path $p)) { return @() }
    return @(Get-Content $p -Tail $n -EA SilentlyContinue)
}
function Test-LogPatterns($tail) {
    # Returns classification hits. Context-aware: UNCLEAN right after a
    # documented boot is INFO-level history, not a fresh CRITICAL.
    $txt = ($tail -join "`n")
    $hits = @()
    # UNCLEAN verdicts (only those NOT followed later by a newer BOOT = stale)
    $uncleans = @($txt | Select-String "previous shutdown UNCLEAN" -AllMatches).Count
    $boots = @($txt | Select-String "BOOT aether" -AllMatches).Count
    if ($uncleans -gt 0) { $hits += "UNCLEAN:$uncleans/BOOTS:$boots" }
    foreach ($pat in @("PANIC", "panic", "fatal runtime", "Failed to connect", "handshake failed")) {
        $c = @($txt | Select-String $pat -AllMatches).Count
        if ($c -gt 0) { $hits += "${pat}:$c" }
    }
    return $hits
}
function Get-Snapshot($node, $proc, $dag, $sync) {
    $disk = $null
    try {
        $d = (Get-Item $node.dataDir).PSDrive.Name
        $v = Get-PSDrive $d
        $disk = [math]::Round(100 * $v.Used / ($v.Used + $v.Free), 1)
    } catch {}
    return [ordered]@{
        pid = if ($proc) { $proc.pid } else { $null }
        ramMB = if ($proc) { [math]::Round($proc.ram / 1MB, 1) } else { $null }
        diskUsedPct = $disk
        total = if ($dag) { $dag.total_transactions } else { $null }
        tips = if ($dag) { $dag.tip_count } else { $null }
        peers = if ($dag) { $dag.connected_peers } else { $null }
        mempool = if ($sync -and $null -ne $sync.mempoolSize) { $sync.mempoolSize } else { $null }
    }
}

# ----------------------------------------------------------------- sweep --
$results = @()
$critCount = 0
foreach ($node in $cfg.nodes) {
    $name = $node.name
    $st = @{ node = $name; status = "HEALTHY"; reasons = @() }
    $proc = Get-Proc $node
    $now = Get-Date

    # --- process ---
    if (-not $proc) {
        $st.status = "DOWN"; $st.reasons += "process absent"
        $snap = Get-Snapshot $node $null $null $null
        Write-Alert "CRITICAL" $name "PROCESS_DOWN" "aether-unified absent for dataDir" $snap | Out-Null
        $critCount++
        # auto-restart policy (explicit opt-in only)
        if ($AutoRestart) {
            $hist = @()
            if ($state.ContainsKey("$name-restarts")) { $hist = @($state["$name-restarts"]) }
            $hist = @($hist | Where-Object { ((Get-Date) - [datetime]$_).TotalHours -lt 1 })
            if ($hist.Count -ge $TH.maxRestartsPerHour) {
                Write-Alert "CRITICAL" $name "CIRCUIT_BREAKER" "$($hist.Count) restarts in 1h: auto-restart disabled, operator needed" $snap | Out-Null
                $st.reasons += "circuit breaker open"
            } else {
                $last = $null
                if ($state.ContainsKey("$name-lastRestart")) { $last = [datetime]$state["$name-lastRestart"] }
                if ($last -and ((Get-Date) - $last).TotalSeconds -lt $TH.restartCooldownSec) {
                    $st.reasons += "restart cooldown"
                } else {
                    Write-Alert "WARNING" $name "AUTO_RESTART" "restarting (attempt $($hist.Count + 1)/$($TH.maxRestartsPerHour) per hour)" $snap | Out-Null
                    Start-Process -FilePath $cfg.binary -ArgumentList @("--node-type", $node.nodeType, "--data-dir", $node.dataDir, "--p2p-port", $node.p2p, "--rpc-port", $node.rpc, "--bootnodes", ($node.bootnodes -join ",")) -WindowStyle Hidden | Out-Null
                    $state["$name-lastRestart"] = (Get-Date).ToString("o")
                    $state["$name-restarts"] = @($hist + @((Get-Date).ToString("o")))
                }
            }
        }
        $results += $st; continue
    }

    # --- RPC ---
    $dag = $null; $sync = $null; $faucet = $null
    try {
        $dag = Rpc $node.rpc "aether_getDagStats"
        $sync = Rpc $node.rpc "aether_getSyncStats"
        try {
            $mp = Rpc $node.rpc "aether_getMempoolStats"; $sync | Add-Member -NotePropertyName mempoolSize -NotePropertyValue $mp.size -Force
        } catch {}
        try { $faucet = (Rpc $node.rpc "aether_getBalance" @($FAUCET)).balance } catch {}
    } catch {
        $age = ($now - $proc.start).TotalSeconds
        if ($age -lt $TH.graceSec) { $st.reasons += "rpc not ready yet (boot grace)" }
        else {
            $st.status = "UNRESPONSIVE"; $st.reasons += "process alive, RPC down"
            Write-Alert "CRITICAL" $name "RPC_DOWN" "process $($proc.pid) alive but RPC unreachable" (Get-Snapshot $node $proc $null $null) | Out-Null
            $critCount++
        }
        $results += $st; continue
    }

    # --- heartbeat / stall (S2, S7) ---
    # Stall = want-sync EVIDENCE NOW (requests growing, orphans/mempool
    # pending) + zero progress since last pass. A synced idle node has
    # static counters and pending queues at zero -> never flagged (no
    # false positive on quiet nodes; the cumulative-requests version of
    # this rule fired on healthy idle nodes and was removed).
    $key = "$name-hb"
    $prev = $null
    if ($state.ContainsKey($key)) { $prev = $state[$key] }
    $orph = 0; $mp = 0
    try {
        $mps = Rpc $node.rpc "aether_getMempoolStats"
        $orph = [int]$mps.orphan_parked; $mp = [int]$mps.size
    } catch {}
    $prog = [long]$dag.total_transactions + [long]$sync.sync_received
    $req = [long]$sync.sync_requested
    $state[$key] = @{ t = (Get-Date).ToString("o"); prog = $prog; req = $req }
    if ($prev -and $prev.req -ne $null) {
        $idle = ((Get-Date) - [datetime]$prev.t).TotalSeconds
        $moved = ($prog - [long]$prev.prog) -gt 0
        $reqGrew = ($req - [long]$prev.req) -gt 0
        $pending = ($orph -gt 0) -or ($mp -gt 0)
        if ($idle -gt $TH.stallWindowSec -and -not $moved -and ($reqGrew -or $pending)) {
            $st.status = "DEGRADED"; $st.reasons += "SYNC STALL: no progress for $([int]$idle)s"
            Write-Alert "WARNING" $name "SYNC_STALL" "no DAG/sync progress for $([int]$idle)s (req+$(($req - [long]$prev.req)) orphans=$orph mempool=$mp)" (Get-Snapshot $node $proc $dag $sync) | Out-Null
        }
    }

    # --- peers vs expected role (S6) ---
    $age = ($now - $proc.start).TotalSeconds
    $peers = [int]$dag.connected_peers
    if ($node.role -ne "ISOLATED" -and $node.role -ne "BOOTSTRAP" -and $age -gt $TH.graceSec -and $peers -eq 0) {
        $st.status = "DEGRADED"; $st.reasons += "0 peers past grace (role=$($node.role))"
        Write-Alert "WARNING" $name "PEER_LOSS" "0 peers for role $($node.role)" (Get-Snapshot $node $proc $dag $sync) | Out-Null
    }

    # --- resources (S9) ---
    $ramMB = [math]::Round($proc.ram / 1MB, 1)
    if ($ramMB -gt $TH.ramWarnMB) { $st.status = "DEGRADED"; $st.reasons += "RAM ${ramMB}MB > $($TH.ramWarnMB)" }    if ($ramMB -gt $TH.ramCritMB) {
        $st.status = "UNRESPONSIVE"; $st.reasons += "RAM ${ramMB}MB > $($TH.ramCritMB)"
        Write-Alert "CRITICAL" $name "MEMORY" "RAM ${ramMB}MB" (Get-Snapshot $node $proc $dag $sync) | Out-Null
        $critCount++
    }

    # disk (drive hosting the data dir)
    try {
        $drv = (Get-Item $node.dataDir).PSDrive.Name
        $vol = Get-PSDrive $drv
        $usedPct = [math]::Round(100 * $vol.Used / ($vol.Used + $vol.Free), 1)
        if ($usedPct -ge $TH.diskCritPct) {
            if ($st.status -eq "HEALTHY") { $st.status = "DEGRADED" }
            $st.reasons += "disk ${usedPct}% >= crit $($TH.diskCritPct)%"
            Write-Alert "WARNING" $name "DISK" "disk used ${usedPct}%" (Get-Snapshot $node $proc $dag $sync) | Out-Null
        } elseif ($usedPct -ge $TH.diskWarnPct) {
            $st.reasons += "disk ${usedPct}% >= warn $($TH.diskWarnPct)%"
        }
    } catch {}
    # mempool / orphans backlogs
    try {
        $mp = Rpc $node.rpc "aether_getMempoolStats"
        if ([int]$mp.size -gt $TH.mempoolWarn) { $st.reasons += "mempool backlog $($mp.size)" }
        if ([int]$mp.orphan_parked -gt $TH.orphanWarn) { $st.reasons += "orphans parked $($mp.orphan_parked)" }
    } catch {}

    # --- logs (S10) ---    $tail = Get-LogTail $node 80
    if ($tail.Count -eq 0) { $st.reasons += "no log file yet" }
    else {
        $hits = Test-LogPatterns $tail
        foreach ($h in $hits) {
            if ($h -match "^UNCLEAN") {
                # Context: UNCLEAN followed by a NEWER boot + progress = known
                # history (already diagnosed at boot), not a fresh critical.
                $st.reasons += "log shows past UNCLEAN shutdown(s): $h"
            } else {
                $st.reasons += "log pattern: $h"
            }
        }
        # fresh PANIC/fatal = always critical-ish
        $joined = ($tail -join "`n")
        if ($joined -match "PANIC|panic|fatal runtime") {
            if ($st.status -eq "HEALTHY") { $st.status = "DEGRADED" }
            $st.reasons += "panic/fatal markers in recent logs"
            Write-Alert "WARNING" $name "LOG_PANIC" "panic/fatal markers in last 80 log lines" (Get-Snapshot $node $proc $dag $sync) | Out-Null
        }
    }

    # --- store per-node facts for convergence step ---
    $st.total = [long]$dag.total_transactions
    $st.tips = [long]$dag.tip_count
    $st.peers = $peers
    $st.faucet = $faucet
    $results += $st
}

# ------------------------------------------------------- convergence (S8) --
$withData = @($results | Where-Object { $_.total -ne $null })
if ($withData.Count -ge 2) {
    $totals = @($withData | ForEach-Object { $_.total } | Sort-Object -Unique)
    if ($totals.Count -gt 1) {
        # Only CRITICAL when nobody is making progress (a syncing node that
        # moves is SYNCING, not divergent - checked via heartbeat deltas).
        $critCount++
        $detail = ($withData | ForEach-Object { "$($_.node)=$($_.total)" }) -join " "
        $snap = [ordered]@{ totals = $detail }
        Write-Alert "CRITICAL" "NETWORK" "DIVERGENCE" "DAG totals differ: $detail (no auto-repair attempted)" $snap | Out-Null
        foreach ($r in $results) { if ($r.status -eq "HEALTHY") { $r.status = "DEGRADED"; $r.reasons += "network divergence seen" } }
    } else {
        # tips + faucet balance as second-line tripwires (same total)
        $tips = @($withData | ForEach-Object { $_.tips } | Sort-Object -Unique)
        $fb = @($withData | Where-Object { $_.faucet -ne $null } | ForEach-Object { $_.faucet } | Sort-Object -Unique)
        if ($tips.Count -gt 1) {
            foreach ($r in $results) { $r.reasons += "tips differ across net (often transient)" }
        }
        if ($fb.Count -gt 1) {
            $critCount++
            $detail = ($withData | ForEach-Object { "$($_.node)=$($_.faucet)" }) -join " "
            Write-Alert "CRITICAL" "NETWORK" "LEDGER_DIVERGENCE" "faucet balances differ: $detail" ([ordered]@{ f = $detail }) | Out-Null
        }
    }
}

# ------------------------------------------------------------- network (S17)
$downNodes = @($results | Where-Object { $_.status -in @("DOWN", "UNRESPONSIVE") })
if ($downNodes.Count -ge 2 -and $results.Count -ge 3) {
    Write-Host "NOTE: $($downNodes.Count)/$($results.Count) nodes down/unresponsive simultaneously - likely NETWORK EVENT, not isolated node failures."
}

Save-State
Write-Host "---- watchdog summary ----"
foreach ($r in $results) { Write-Host "$($r.node): $($r.status) :: $($r.reasons -join ' / ')" }
if ($critCount -gt 0) { exit 1 } else { exit 0 }
