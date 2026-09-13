# Aether VPS Watchdog — Multi-Seed Monitor
# Runs as scheduled task every 5 minutes
# Detects: SEED DOWN, DEGRADED, RECOVERED, NETWORK DOWN

$Seed1 RPC = "http://127.0.0.1:9933"  # VPS via tunnel
$Seed2 RPC = "http://127.0.0.1:9934"  # Local seed
$LogDir = "$env:TEMP\opencode\aether-watchdog"
$LogFile = Join-Path $LogDir "watchdog.log"

if(-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

function Test-Seed($name, $rpc) {
    try {
        $d=(Invoke-RestMethod -Uri $rpc -Method Post -Body '{"jsonrpc":"2.0","method":"aether_getDagStats","params":[],"id":1}' -ContentType "application/json" -TimeoutSec 8).result
        return @{ status="HEALTHY"; total=$d.total_transactions; peers=$d.connected_peers; tips=$d.tip_count }
    } catch {
        return @{ status="DOWN"; total=0; peers=0; tips=0 }
    }
}

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$s1 = Test-Seed "Seed1" $Seed1 RPC
$s2 = Test-Seed "Seed2" $Seed2 RPC

# Determine overall status
if($s1.status -eq "HEALTHY" -and $s2.status -eq "HEALTHY") {
    $overall = "HEALTHY"
} elseif($s1.status -eq "DOWN" -and $s2.status -eq "DOWN") {
    $overall = "NETWORK DOWN"
} elseif($s1.status -eq "DOWN") {
    $overall = "SEED1 DOWN (failover to Seed2)"
} elseif($s2.status -eq "DOWN") {
    $overall = "SEED2 DOWN (failover to Seed1)"
} else {
    $overall = "DEGRADED"
}

$log = "$ts | $overall | Seed1=$($s1.status) t=$($s1.total) p=$($s1.peers) | Seed2=$($s2.status) t=$($s2.total) p=$($s2.peers)"
Add-Content -Path $LogFile -Value $log
Write-Host $log
