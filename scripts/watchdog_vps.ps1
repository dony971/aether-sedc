# AETHER VPS watchdog — OBSERVABILITY ONLY (phase VPS n°12).
#
# Same doctrine as scripts/watchdog.ps1 (DETECT/CAPTURE/ALERT/DOCUMENT,
# MONITOR ONLY, circuit breaker, no auto-repair of consensus), adapted
# to a remote seed reached over SSH. Authentication is NEVER embedded:
# set SSH_ASKPASS (+SSH_ASKPASS_REQUIRE=force) in the OPERATOR environment
# before running, e.g. a helper script echoing a password from a vault.
# Nothing secret is written here, in logs, or in incident files.
#
# Usage:
#   $env:SSH_ASKPASS="C:\secure\vps-ask.bat"; $env:SSH_ASKPASS_REQUIRE="force"
#   .\watchdog_vps.ps1 [-SshTarget "root@HOST:PORT"] [-StateDir ...]
param(
    [string]$SshTarget = "root@VPS-100333.ssh.vps1euro.fr:9221",
    [string]$StateDir = (Join-Path $env:TEMP "opencode\watchdog-vps-state"),
    [string]$IncidentLog = (Join-Path $env:TEMP "opencode\watchdog-vps-incidents.jsonl")
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
function Invoke-VpsSsh($remoteCmd) {
    $h, $p = $SshTarget.Split("@")[-1].Split(":")
    $u = ($SshTarget.Split("@")[0])
    if (-not $p) { $p = 22 }
    $out = ssh -p $p -o ConnectTimeout=25 "$u@$h" $remoteCmd 2>&1 | Out-String
    return $out
}
function Alert($sev, $event, $detail) {
    $inc = [ordered]@{
        id = "INC-{0:yyyyMMdd-HHmmss}-VPS" -f (Get-Date)
        ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        severity = $sev; node = "vps-seed"; event = $event; detail = $detail
    }
    ($inc | ConvertTo-Json -Compress) | Add-Content $IncidentLog -Encoding utf8
    Write-Host "ALERT [$sev] $($inc.id) VPS $event :: $detail"
}
$crit = 0
# process + service
$active = (Invoke-VpsSsh "systemctl is-active aether-seed.service") -match "active"
if (-not $active) { Alert "CRITICAL" "VPS_DOWN" "aether-seed.service not active"; $crit++ }
else { Write-Host "OK: service active" }
# RPC via localhost (never exposed publicly by design)
$dag = $null
try {
    $raw = Invoke-VpsSsh "curl -s -m 8 -X POST http://127.0.0.1:9933 -H 'Content-Type: application/json' -d @/tmp/q.json"
    $dag = ($raw | ConvertFrom-Json).result
    Write-Host ("OK: RPC total={0} tips={1} peers={2}" -f $dag.total_transactions, $dag.tip_count, $dag.connected_peers)
} catch { Alert "CRITICAL" "VPS_RPC_DOWN" "localhost RPC unreachable: $($_.Exception.Message)"; $crit++ }
# resources
$res = Invoke-VpsSsh "free -m | head -2 | tail -1; df -h / | tail -1; cat /proc/loadavg | cut -d' ' -f1"
Write-Host "RES: $res"
# logs: UNCLEAN since last check + fatals
$lg = Invoke-VpsSsh "grep -c 'previous shutdown UNCLEAN' /opt/aether/data/logs/node.log 2>/dev/null; grep -ciE 'panic|fatal runtime' /opt/aether/data/logs/node.log 2>/dev/null | head -1; ls -la /opt/aether/data/logs/ | head -8"
Write-Host "LOGS:"; Write-Host $lg
# sync progress vs stored state
$sf = Join-Path $StateDir "vps.json"
$prev = $null
if (Test-Path $sf) { try { $prev = Get-Content $sf -Raw | ConvertFrom-Json } catch {} }
if ($dag) {
    $now = @{ t = (Get-Date).ToString("o"); total = [long]$dag.total_transactions }
    $now | ConvertTo-Json -Compress | Set-Content $sf -Encoding utf8
    if ($prev -and ([long]$prev.total) -gt 0) {
        $idle = ((Get-Date) - [datetime]$prev.t).TotalMinutes
        if ([long]$dag.total_transactions -eq [long]$prev.total -and $idle -gt 60) {
            Write-Host "NOTE: VPS total static for $([int]$idle) min (network quiet or stalled - check peers/activity)"
        }
    }
}
if ($crit -gt 0) { exit 1 } else { Write-Host "VPS HEALTHY"; exit 0 }
