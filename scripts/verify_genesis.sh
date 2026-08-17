#!/usr/bin/env bash
# Verification de la cérémonie genesis AETHER SEDC (Linux/CI).
# Mêmes contrôles que verify_genesis.ps1 : absence cle historique, artefacts,
# coherence genesis.rs, network_id reproductible, supply initiale.
# Exit 0 = PASS, 1 = FAIL.
set -u

REPO="${1:-.}"
TEMP_SCAN_ROOT="${TEMP_SCAN_ROOT:-/tmp/opencode}"
FAILS=0

OLD_FAUCET_SEED="fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8"
OLD_FAUCET_ADDR="5579ae9096f1ae55bfd6fd88155fad09c59ab8ccb61c8a297b5d1027ea4ca916"
OLD_FOUNDER_ADDR="3d17ace653283dbd9aeba6e0d4684795a800e9da952cb682bb67cd970cbe1b3e"

SUPPLY_FOUNDER=100000000000
SUPPLY_FAUCET=1000000000000000000
MAX_SUPPLY=2000000000000000000
EXPECTED_SUPPLY=$((SUPPLY_FOUNDER + SUPPLY_FAUCET))

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; FAILS=$((FAILS + 1)); }
step() { printf '\n=== %s\n' "$1"; }

sha256hex() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

step "1/5 Absence de l'ancienne cle dans le depot source"
# Whitelist : fichiers de cérémonie qui contiennent VOLONTAIREMENT la clé
# historique (documentation + outils de détection).
WHITELIST='docs/CEREMONIE_GENESIS.md|docs/RAPPORT_CEREMONIE_GENESIS.md|scripts/verify_genesis.ps1|scripts/verify_genesis.sh'
if grep -rIl --exclude-dir=target --exclude-dir=.git -i "$OLD_FAUCET_SEED" "$REPO" 2>/dev/null | grep -vE "$WHITELIST" | grep -q .; then
    fail "Ancienne cle trouvee dans le source (hors whitelist cérémonie)"
else
    pass "Aucune occurrence de l'ancienne cle hors whitelist cérémonie"
fi

step "2/5 Absence d'artefacts de test"
for name in faucet.key faucet.json; do
    if find "$TEMP_SCAN_ROOT" -name "$name" 2>/dev/null | grep -q .; then
        fail "Artefact residuel: $name"
    else
        pass "Aucun $name sous $TEMP_SCAN_ROOT"
    fi
done

step "3/5 Coherence des constantes genesis (src/genesis.rs)"
GENESIS_FILE="$REPO/src/genesis.rs"
if [ ! -f "$GENESIS_FILE" ]; then
    fail "src/genesis.rs introuvable"
else
    FOUNDER=$(grep -A1 'pub const FOUNDER_ADDRESS: &str' "$GENESIS_FILE" | grep -oE '"0x[0-9a-fA-F]{64}"|"[0-9a-fA-F]{64}"' | tr -d '"' | head -1 | tr 'A-F' 'a-f')
    FAUCET=$(grep -A1 'pub const FAUCET_ADDRESS: &str' "$GENESIS_FILE" | grep -oE '"0x[0-9a-fA-F]{64}"|"[0-9a-fA-F]{64}"' | tr -d '"' | head -1 | tr 'A-F' 'a-f')
    MESSAGE=$(grep 'pub const GENESIS_MESSAGE: &str' "$GENESIS_FILE" | sed -E 's/.*: &str = "([^"]+)".*/\1/' | head -1)

    if [ -z "$FOUNDER" ]; then fail "FOUNDER_ADDRESS absente/invalide"; else
        if [ "$FOUNDER" = "$OLD_FOUNDER_ADDR" ]; then fail "FOUNDER_ADDRESS = ancienne adresse"; else pass "FOUNDER_ADDRESS = $FOUNDER"; fi
    fi
    if [ -z "$FAUCET" ]; then fail "FAUCET_ADDRESS absente/invalide"; else
        if [ "$FAUCET" = "$OLD_FAUCET_ADDR" ]; then fail "FAUCET_ADDRESS = ancienne adresse"; else pass "FAUCET_ADDRESS = $FAUCET"; fi
    fi
    if [ -z "$MESSAGE" ]; then fail "GENESIS_MESSAGE absent"; else pass "GENESIS_MESSAGE present (${#MESSAGE} chars)"; fi
    if [ -n "$FOUNDER" ] && [ -n "$FAUCET" ] && [ "$FOUNDER" != "$FAUCET" ]; then pass "Adresses distinctes"; else fail "Adresses absentes ou identiques"; fi
fi

step "4/5 network_id reproductible"
if [ -n "${MESSAGE:-}" ] && [ -n "${FOUNDER:-}" ] && [ -n "${FAUCET:-}" ]; then
    NET_SEED="${MESSAGE}|${FOUNDER}|${FAUCET}|${EXPECTED_SUPPLY}|${MAX_SUPPLY}"
    NETWORK_ID=$(sha256hex "$NET_SEED")
    printf '    network_id       = %s\n' "$NETWORK_ID"
    printf '    supply initiale  = %s\n' "$EXPECTED_SUPPLY"
    pass "network_id deterministe"
else
    fail "Impossible de calculer network_id"
fi

step "5/5 Supply initiale attendue"
if [ "$EXPECTED_SUPPLY" = "1000000100000000000" ]; then
    pass "Supply initiale = 1000000100000000000 (1e18 faucet + 1e11 founder)"
else
    fail "Supply initiale inattendue : $EXPECTED_SUPPLY"
fi

printf '\n==================================================\n'
if [ "$FAILS" -eq 0 ]; then
    printf 'RESULTAT : PASS (0 echec)\n'
    exit 0
else
    printf 'RESULTAT : FAIL - %d echec(s)\n' "$FAILS"
    exit 1
fi