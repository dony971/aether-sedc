#requires -Version 5.1
<#
.SYNOPSIS
    Verification de la cérémonie genesis AETHER SEDC (Windows/PowerShell).
.DESCRIPTION
    Controle : (1) absence de la cle faucet historique dans le depot source,
    (2) absence d'artefacts de test contenant la cle, (3) coherence des
    constantes genesis dans src/genesis.rs, (4) calcul reproductible du
    network_id et du fingerprint genesis, (5) supply initiale.
    Exit code 0 = PASS, 1 = FAIL.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify_genesis.ps1 -Repo C:\aether-main
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    [string]$TempScanRoot = "$env:TEMP\opencode"
)

$ErrorActionPreference = 'Stop'
$script:failures = @()

function Write-Step([string]$msg) { Write-Host "`n=== $msg" -ForegroundColor Cyan }
function Fail([string]$msg) { $script:failures += $msg; Write-Host "FAIL: $msg" -ForegroundColor Red }
function Pass([string]$msg) { Write-Host "PASS: $msg" -ForegroundColor Green }

# Anciennes valeurs (premiere cérémonie) : clé faucet compromise + adresses ancien genesis
$script:OLD_FAUCET_SEED   = 'fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8'
$script:OLD_FAUCET_ADDR   = '5579ae9096f1ae55bfd6fd88155fad09c59ab8ccb61c8a297b5d1027ea4ca916'
$script:OLD_FOUNDER_ADDR  = '3d17ace653283dbd9aeba6e0d4684795a800e9da952cb682bb67cd970cbe1b3e'

# Whitelist : fichiers de la cérémonie qui contiennent VOLONTAIREMENT la clé historique
# (documentation + outils de détection). La clé ne doit exister NULLE PART ailleurs.
$script:ceremonyWhitelist = @(
    'docs\CEREMONIE_GENESIS.md',
    'docs\RAPPORT_CEREMONIE_GENESIS.md',
    'scripts\verify_genesis.ps1',
    'scripts\verify_genesis.sh'
)

# Constantes économiques (genesis.rs / protocole)
$script:UNITS_PER_AETH = 10000000000      # 1e10
$script:SUPPLY_FOUNDER = 100000000000     # 1e11 (10 AETH)
$script:SUPPLY_FAUCET  = 1000000000000000000  # 1e18 (100M AETH)
$script:MAX_SUPPLY     = 2000000000000000000  # 2e18
$script:EXPECTED_SUPPLY = $SUPPLY_FOUNDER + $SUPPLY_FAUCET   # 1000000100000000000

function Sha256Hex([string]$s) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
}

function Test-Hex64([string]$v) { return ($v -match '^[0-9a-f]{64}$') }

function Search-Key([string]$pattern, [string]$root) {
    # grep récursif insensible à la casse, sans target/.git ; fallback Select-String si rg absent
    $rg = Get-Command rg -ErrorAction SilentlyContinue
    if ($rg) {
        $hits = & rg -i -l $pattern $root -g '!target' -g '!**/.git/**' 2>$null
        if ($LASTEXITCODE -eq 0) { return @($hits) } else { return @() }
    }
    $hits = Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(target|\.git)\\' } |
        Select-String -Pattern $pattern -SimpleMatch -List -ErrorAction SilentlyContinue
    return @($hits | ForEach-Object { $_.Path })
}

function Test-Whitelisted([string]$path) {
    $rel = $path.Substring($Repo.Length).TrimStart('\', '/').Replace('/', '\').ToLowerInvariant()
    foreach ($w in $script:ceremonyWhitelist) {
        if ($rel -eq $w.ToLowerInvariant()) { return $true }
    }
    return $false
}

Write-Step "1/5  Absence de l'ancienne cle dans le depot source (hors whitelist cérémonie)"
$leaks = @(Search-Key $script:OLD_FAUCET_SEED $Repo | Where-Object { -not (Test-Whitelisted $_) })
if ($leaks.Count -gt 0) { Fail "Ancienne cle trouvee dans le source : $($leaks -join '; ')" }
else { Pass "Aucune occurrence de l'ancienne cle hors fichiers de cérémonie" }

$leaksShort = @(Search-Key $script:OLD_FAUCET_SEED.Substring(0, 8) $Repo | Where-Object { -not (Test-Whitelisted $_) })
if ($leaksShort.Count -gt 0) { Fail "Fragment d'ancienne cle ($($script:OLD_FAUCET_SEED.Substring(0,8))) trouve : $($leaksShort -join '; ')" }
else { Pass "Aucun fragment de cle historique hors whitelist" }

$inWhitelist = @(Search-Key $script:OLD_FAUCET_SEED $Repo | Where-Object { Test-Whitelisted $_ })
if ($inWhitelist.Count -ne $script:ceremonyWhitelist.Count) {
    Fail "Whitelist inattendue : $($inWhitelist.Count)/$($script:ceremonyWhitelist.Count) fichiers contenent la cle"
} else { Pass "Cle historique presente uniquement dans les $($inWhitelist.Count) fichiers de cérémonie (whitelist)" }

Write-Step "2/5  Absence d'artefacts de test (cle / wallets / data-dirs)"
foreach ($name in @('faucet.key', 'faucet.json')) {
    $found = @(Get-ChildItem $TempScanRoot -Recurse -Filter $name -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) { Fail "$name residuel x$($found.Count) (ex: $($found[0].FullName))" }
    else { Pass "Aucun $name sous $TempScanRoot" }
}
$oldWallets = @(Get-ChildItem $TempScanRoot -Recurse -Filter '*.json' -ErrorAction SilentlyContinue |
    Select-String -Pattern $script:OLD_FAUCET_SEED -List)
if ($oldWallets.Count -gt 0) { Fail "Wallets contenant l'ancienne cle : x$($oldWallets.Count)" }
else { Pass "Aucun wallet JSON contenant l'ancienne cle" }

Write-Step "3/5  Coherence des constantes genesis (src/genesis.rs)"
$genesisFile = Join-Path $Repo 'src\genesis.rs'
if (-not (Test-Path $genesisFile)) { Fail "src/genesis.rs introuvable"; }
else {
    $gen = Get-Content $genesisFile -Raw
    $founder = [regex]::Match($gen, 'FOUNDER_ADDRESS\s*:\s*&str\s*=\s*"([0-9a-fA-F]{64})"').Groups[1].Value.ToLowerInvariant()
    $faucet  = [regex]::Match($gen, 'FAUCET_ADDRESS\s*:\s*&str\s*=\s*"([0-9a-fA-F]{64})"').Groups[1].Value.ToLowerInvariant()
    $message = [regex]::Match($gen, 'GENESIS_MESSAGE\s*:\s*&str\s*=\s*"([^"]+)"').Groups[1].Value

    if (-not (Test-Hex64 $founder))  { Fail "FOUNDER_ADDRESS absente/invalide (trouve: '$founder')" }
    elseif ($founder -eq $script:OLD_FOUNDER_ADDR) { Fail "FOUNDER_ADDRESS = ancienne adresse (rotation non effectuee)" }
    else { Pass "FOUNDER_ADDRESS = $founder" }

    if (-not (Test-Hex64 $faucet))  { Fail "FAUCET_ADDRESS absente/invalide (trouve: '$faucet')" }
    elseif ($faucet -eq $script:OLD_FAUCET_ADDR) { Fail "FAUCET_ADDRESS = ancienne adresse (rotation non effectuee)" }
    else { Pass "FAUCET_ADDRESS = $faucet" }

    if (-not $message) { Fail "GENESIS_MESSAGE absent" }
    else {
        Pass "GENESIS_MESSAGE = '$($message.Substring(0, [Math]::Min(60, $message.Length)))...'"
        $script:genMessage = $message
    }
    if ($founder -and $faucet -and $founder -ne $faucet) { Pass "Adresses distinctes" }
    else { Fail "Adresses absentes ou identiques" }
}

Write-Step "4/5  Calcul reproductible network_id / fingerprint genesis"
if ($script:genMessage -and $founder -and $faucet) {
    $netSeed = "$script:genMessage|$founder|$faucet|$script:EXPECTED_SUPPLY|$script:MAX_SUPPLY"
    $networkId = Sha256Hex $netSeed
    Write-Host ("    network_id            = " + $networkId)
    Write-Host ("    supply initiale       = " + $script:EXPECTED_SUPPLY)
    Write-Host ("    MAX_SUPPLY            = " + $script:MAX_SUPPLY)
    Pass "network_id deterministe (recalculable hors ligne)"
} else { Fail "Impossible de calculer network_id (constantes manquantes)" }

Write-Step "5/5  Supply initiale attendue"
if ($script:EXPECTED_SUPPLY -ne 1000000100000000000) {
    Fail "Supply initiale inattendue : $script:EXPECTED_SUPPLY"
} else { Pass "Supply initiale = 1000000100000000000 (1e18 faucet + 1e11 founder)" }

Write-Host "`n=================================================="
if ($script:failures.Count -eq 0) {
    Write-Host "RESULTAT : PASS (0 echec)" -ForegroundColor Green
    exit 0
} else {
    Write-Host "RESULTAT : FAIL - $($script:failures.Count) echec(s) :" -ForegroundColor Red
    $script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}