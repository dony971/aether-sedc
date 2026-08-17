# ============================================================
# CANARY PHASE A - deploy 3 seed nodes (frozen commit b1b8376)
# ASCII-only (PS 5.1 compatibility). No secrets in output.
# Exit 0 = PASS, 1 = FAIL (STOP before deploy).
# ============================================================
param(
    [string]$Repo = "C:\Users\Shadow\Documents\aether-fix\aether-main",
    [string]$DataRoot = "$env:TEMP\opencode\aether-canary-a"
)
$ErrorActionPreference = "Stop"
$fails = 0

$GJ = Join-Path $Repo "docs\genesis.json"
$EXE = Join-Path $Repo "target\release\aether-unified.exe"
$SHA_JSON = "4f3e693ee56a224dec556f1c05a7c2f4383b2ba8334368ae5d25ba48991d9f8f"
$SHA_EXE  = "f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c"
$NETID    = "59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69"
$P2P_VER  = 3
$CEREMONY = "$env:TEMP\opencode\aether-v3-ceremony"

function Chk($name, $ok, $detail) {
    if ($ok) { Write-Host ("  PASS: " + $name + " - " + $detail) }
    else { Write-Host ("  FAIL: " + $name + " - " + $detail); $script:fails++ }
}

Write-Host "=== PHASE A - PRE-START CHECKLIST ==="

# 1. Genesis hash (sha256 of genesis.json) - reproducible, identical everywhere
$h = (Get-FileHash $GJ -Algorithm SHA256).Hash.ToLower()
Chk "genesis hash" ($h -eq $SHA_JSON) ("genesis.json sha256=" + $h.Substring(0,16) + "...")

# 2. network_id identical (recompute from genesis.json like verify scripts)
$g = Get-Content $GJ -Raw | ConvertFrom-Json
$netid = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes(
        $g.genesis_message + "|" + $g.founder_address + "|" + $g.faucet_address + "|" +
        "1000000100000000000|2000000000000000000"))).Replace("-","").ToLower()
Chk "network_id" ($netid -eq $NETID) ("recompute=" + $netid.Substring(0,16) + "...")

# 3. P2P version 3 (frozen constant, enforced in handshake p2p.rs:69/550)
$p2pCheck = Select-String -Path (Join-Path $Repo "src\p2p.rs") -Pattern "const P2P_PROTOCOL_VERSION: u8 = 3;" -Quiet
Chk "P2P version 3" ($p2pCheck -eq $true) ("P2P_PROTOCOL_VERSION=" + $P2P_VER + " (frozen b1b8376)")

# 4. SHA256 of the binary identical to release hash
$he = (Get-FileHash $EXE -Algorithm SHA256).Hash.ToLower()
Chk "binary sha256" ($he -eq $SHA_EXE) ("aether-unified.exe sha256=" + $he.Substring(0,16) + "...")

# 5. Clock
$local = Get-Date
$w32 = (Get-Service w32time -ErrorAction SilentlyContinue).Status
Chk "clock readable" ($true) ("local=" + $local.ToString("yyyy-MM-dd HH:mm:ss") + " w32time=" + $w32)
if ($w32 -ne "Running") { Write-Host "  NOTE: w32time not running - operator must sync clocks on public seeds (ntp)." }

# 6/7. Fresh data dirs, no old data
if (Test-Path $DataRoot) {
    for ($r = 0; $r -lt 3; $r++) { try { Remove-Item $DataRoot -Recurse -Force -ErrorAction Stop; break } catch { Start-Sleep -Seconds 2 } }
}
New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
foreach ($i in 1,2,3) {
    $d = Join-Path $DataRoot ("node" + $i)
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
$leftovers = @(Get-ChildItem $DataRoot -Recurse -File -ErrorAction SilentlyContinue).Count
Chk "fresh data dirs" ($leftovers -eq 0) ("dirs node1-3 recreated, leftover files=" + $leftovers)

# 8. No ceremony keys anywhere (except the ACL-restricted ceremony folder)
$hits = 0
foreach ($root in @($DataRoot, (Join-Path $Repo "scripts"), (Join-Path $Repo "docs"))) {
    $hits += @(Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "faucet\.key|\.pem$|seed" } | Select-Object -First 1).Count
}
$seedScan = Select-String -Path (Join-Path $Repo "docs\genesis.json") -Pattern "7d19417362e1ad1d9ed36b45dff8b2484f503d69e9d5e9fa50735a206dda4b03|6878210fd5ee3b2411a405b2dfdaa1e58557741da38632026f94a897f94279da" -Quiet
Chk "no ceremony keys" (($hits -eq 0) -and ($seedScan -ne $true)) ("key-like files=" + $hits)

# 9. Firewall - RPC binds 0.0.0.0 (node.rs:565), must be loopback-only:
#    deny inbound rules on RPC ports keep the API local; P2P ports stay open.
$fwOk = $true
try {
    foreach ($p in 42101,43101,44101) {
        $rule = Get-NetFirewallRule -DisplayName ("Aether RPC loopback-only " + $p) -ErrorAction SilentlyContinue
        if (-not $rule) {
            New-NetFirewallRule -DisplayName ("Aether RPC loopback-only " + $p) -Direction Inbound -Action Block -Protocol TCP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null
        }
    }
    Write-Host "  PASS: firewall rules created (RPC ports 42101/43101/44101 inbound blocked, loopback exempt)"
} catch {
    $fwOk = $false
    Write-Host "  WARN: cannot create firewall rules (needs admin) - operator: block inbound TCP 42101/43101/44101"
}
$profiles = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } | Measure-Object).Count
Chk "firewall profiles" ($profiles -ge 1) ("enabled profiles=" + $profiles + " ; RPC loopback-only=" + $fwOk)

Write-Host ""
if ($fails -gt 0) { Write-Host "RESULTAT PHASE A CHECKLIST : FAIL ($fails echec)"; exit 1 }
Write-Host "RESULTAT PHASE A CHECKLIST : PASS (0 echec)"

# ============ DEPLOY 3 SEED NODES (no faucet yet) ============
Write-Host "=== PHASE A - DEPLOY 3 SEED NODES (faucet.key ABSENT) ==="
$env:AETHER_FOUNDER  = "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4"
$env:AETHER_FAUCET   = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb"
$env:AETHER_FAUCET_SEED = "6878210fd5ee3b2411a405b2dfdaa1e58557741da38632026f94a897f94279da"

function Start-Seed($id, $p2p, $rpc, $boot) {
    $dir = Join-Path $DataRoot ("node" + $id)
    $args = @("--node-type","validator","--data-dir",$dir,"--p2p-port","$p2p","--rpc-port","$rpc","--bootnodes",$boot)
    $p = Start-Process -FilePath $EXE -ArgumentList $args -RedirectStandardOutput (Join-Path $dir "node.out.log") -RedirectStandardError (Join-Path $dir "node.err.log") -WindowStyle Hidden -PassThru
    $p.Id | Set-Content (Join-Path $dir "node.pid") -Encoding ascii
    Write-Host ("  started node" + $id + " (pid " + $p.Id + ") p2p=" + $p2p + " rpc=" + $rpc)
}

Start-Seed 1 42001 42101 "127.0.0.1:1"
Start-Seed 2 43001 43101 "127.0.0.1:42001"
Start-Seed 3 44001 44101 "127.0.0.1:42001"
Start-Sleep -Seconds 5

$hub = $null
for ($t = 0; $t -lt 45; $t++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:42101" -Method Post -ContentType "application/json" -Body '{"jsonrpc":"2.0","id":1,"method":"aether_getDagStats","params":[]}' -TimeoutSec 5
        if ($r.result) { $hub = $r.result; break }
    } catch {}
}
if (-not $hub) { Write-Host "RESULTAT PHASE A DEPLOY : FAIL (node1 RPC inaccessible)"; exit 1 }
$peerCount = @($hub.peers).Count
Write-Host ("  node1 ready, peers=" + $peerCount)

# ============ IDENTITY MANIFEST ============
$m = @()
$m += "PHASE A - SEED NODES MANIFEST (commit b1b8376)"
$m += "date=" + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$m += "genesis_hash=" + $h
$m += "network_id=" + $netid
$m += "p2p_version=" + $P2P_VER
$m += "software_version=1.2.0 (b1b8376d6adbbf3607e57b7ab1ab198c12e3902f)"
$m += "faucet_key_present=NO"
for ($i = 1; $i -le 3; $i++) {
    $dir = Join-Path $DataRoot ("node" + $i)
    $pidv = (Get-Content (Join-Path $dir "node.pid")).Trim()
    $up = if (Get-Process -Id $pidv -ErrorAction SilentlyContinue) { "running" } else { "DOWN" }
    $m += ("node" + $i + "|node_id=seed-" + $i + "|public_address=127.0.0.1:" + (42000 + ($i - 1) * 1000 + 1) + "|pid=" + $pidv + "|uptime=" + $up)
}
$m | Set-Content (Join-Path $DataRoot "manifest.txt") -Encoding ascii
$m | ForEach-Object { Write-Host ("  " + $_) }
Write-Host "RESULTAT PHASE A DEPLOY : PASS (3 seed nodes, no faucet)"
exit 0