# TOOLCHAIN GATE — canary campaign pre-flight (step 2).
# Fails fast on ANY mismatch. Never launch with fallback to old versions.
param(
    [string]$Bin = "C:\Users\Shadow\Documents\aether-fix\aether-main\target\release\aether-unified.exe",
    [string]$SeedRpc = "http://127.0.0.1:42101"
)
$ErrorActionPreference = "Stop"
$fail = 0
function Check($name, $cond, $detail="") {
    if ($cond) { Write-Host "GATE PASS: $name" }
    else { Write-Host "GATE FAIL: $name $detail"; $script:fail++ }
}

# 1. CLI SHA == pinned build (canary-c2-fixes branch; updated per release)
$sha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$PinnedSHA = "8ADA9726EA09E2425DCE148289AC1E49EEE30C67F5127F07587E4478984B02CB"
Check "CLI SHA" ($sha -eq $PinnedSHA) "(got $sha)"

# 2. CLI surface: no --daemon, no keygen --import-file, has wallet/send/balance
$top = & $Bin --help 2>&1 | Out-String
Check "no --daemon" ($top -notmatch "--daemon")
Check "has wallet/send/balance" (($top -match "wallet") -and ($top -match "send") -and ($top -match "balance"))
$kg = & $Bin keygen --help 2>&1 | Out-String
Check "no keygen --import-file" ($kg -notmatch "import-file")

# 3. Wallet backend == RC + no dead RPC calls
$w = & python -c "from core.rc import verify_binary; verify_binary('C:/Users/Shadow/Documents/aether-wallet/aether.exe'); print('RC OK')" 2>&1 | Out-String
Check "wallet backend RC" ($w -match "RC OK") "($w)"
$dead = Select-String -Path "C:\Users\Shadow\Documents\aether-wallet\core\rpc_client.py" -Pattern 'self\._call\("aether_(startMining|stopMining|getNetworkHashrate|stakeTokens|unstakeTokens|getStakingInfo)"' -EA SilentlyContinue
Check "no dead RPC calls" ($null -eq $dead)

# 4. Config: local seed only
$cfg = & python -c "from core.config import config; print(config.validated_bootnodes())" 2>&1 | Out-String
Check "local bootnode" ($cfg -match "127.0.0.1:42001") "($cfg)"
Check "CANARY_MODE" ($env:CANARY_MODE -eq $null -or $env:CANARY_MODE -eq "LOCAL")

# 5. No legacy backend in resolution path
$leg = Test-Path "C:\Users\Shadow\Documents\aether-wallet\aether-legacy-v1.1.1.exe.bak"
Write-Host "GATE INFO: legacy quarantined (.bak): $leg"

if ($fail -gt 0) { Write-Host "TOOLCHAIN GATE: FAIL ($fail) - DO NOT LAUNCH"; exit 1 }
Write-Host "TOOLCHAIN GATE: ALL PASS - launch allowed"
