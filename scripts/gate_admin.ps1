$ErrorActionPreference = "Continue"
$log = Join-Path $env:TEMP "opencode\gate_admin.log"
function Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$m" | Out-File -FilePath $log -Append -Encoding ascii }

try { Remove-Item $log -Force -ErrorAction SilentlyContinue } catch {}

Log "=== GATE 0 + GATE 1 admin task start ==="

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "isAdmin=$isAdmin"

# ---- GATE 0 : firewall ----
$rpcPorts = @(42101, 43101, 44101, 45101, 46101, 47101)
$p2pPorts = @(42001, 43001, 44001, 45001, 46001, 47001)

foreach ($p in $rpcPorts) {
    $rn = "aether-canary-rpc-block-$p"
    try {
        Remove-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $rn -Direction Inbound -Protocol TCP -LocalPort $p -Action Block -Profile Any | Out-Null
        Log "RPC block rule OK: $p"
    } catch { Log "RPC block rule FAIL: $p : $($_.Exception.Message)" }
}
foreach ($p in $p2pPorts) {
    $rn = "aether-canary-p2p-blockpublic-$p"
    try {
        Remove-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $rn -Direction Inbound -Protocol TCP -LocalPort $p -Action Block -Profile Public | Out-Null
        Log "P2P public-block rule OK: $p"
    } catch { Log "P2P public-block rule FAIL: $p : $($_.Exception.Message)" }
}

# ---- GATE 1 : NTP / Windows Time ----
try {
    Set-Service -Name w32time -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name w32time -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $svc = Get-Service w32time -ErrorAction SilentlyContinue
    Log "w32time service: $($svc.Status) startup=$($svc.StartType)"
} catch { Log "w32time service FAIL: $($_.Exception.Message)" }

try {
    $r1 = & w32tm /config /manualpeerlist:"pool.ntp.org,0x8" /syncfromflags:manual /update 2>&1
    Log "w32tm config: $($r1 -join ' ')"
    Start-Sleep -Seconds 2
    $r2 = & w32tm /resync 2>&1
    Log "w32tm resync: $($r2 -join ' ')"
} catch { Log "w32tm FAIL: $($_.Exception.Message)" }

try {
    $st = & w32tm /query /status 2>&1
    Log "w32tm status:"
    foreach ($l in $st) { Log "  $l" }
} catch { Log "w32tm status FAIL: $($_.Exception.Message)" }

Log "=== GATE 0 + GATE 1 admin task end ==="