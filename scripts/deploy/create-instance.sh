#!/usr/bin/env bash
# Calls forum_registry::create_instance for a previously-deployed program.
#
# Reads PROGRAM_ID_<LABEL> from .forum-state. Generates an admin account if
# one isn't already in the wallet. Prints the master threshold-key secret +
# per-moderator shares so the operator can distribute them out-of-band.
#
# Usage:
#   bash scripts/deploy/create-instance.sh A 3 2 3 8 1000 "Strict forum"
#                                          │ │ │ │ │ │   │
#                                          │ │ │ │ │ │   └─ label
#                                          │ │ │ │ │ └─ stake_amount
#                                          │ │ │ │ └─ Merkle depth (D)
#                                          │ │ │ └─ moderators total (M)
#                                          │ │ └─ moderators threshold (N)
#                                          │ └─ strikes-to-revoke (K)
#                                          └─ instance label (matches deploy-program.sh)

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

LABEL="${1:?missing instance label (e.g. A)}"
K="${2:?missing K}"
N="${3:?missing N}"
M="${4:?missing M}"
D="${5:?missing D}"
STAKE="${6:?missing stake_amount}"
LBL="${7:-Forum}"

WALLET="${WALLET:-wallet}"
SPEL="${SPEL:-spel}"
STATE_FILE=".forum-state"

# shellcheck disable=SC1090
[[ -f "$STATE_FILE" ]] && source "$STATE_FILE"
PROGRAM_VAR="PROGRAM_ID_${LABEL}"
PROGRAM_ID="${!PROGRAM_VAR:-}"
if [[ -z "$PROGRAM_ID" ]]; then
    echo "ERROR: $PROGRAM_VAR not in $STATE_FILE — run scripts/deploy/deploy-program.sh ${LABEL} first" >&2
    exit 1
fi

if [[ -z "${NSSA_SEQUENCER_URL:-}" ]]; then
    echo "ERROR: NSSA_SEQUENCER_URL not set" >&2
    exit 1
fi
export NSSA_SEQUENCER_URL
export NSSA_WALLET_HOME_DIR="${NSSA_WALLET_HOME_DIR:-$ROOT/.scaffold/wallet}"

# Generate or reuse an admin account.
ADMIN_VAR="ADMIN_ID_${LABEL}"
ADMIN="${!ADMIN_VAR:-}"
if [[ -z "$ADMIN" ]]; then
    ADMIN=$("$WALLET" account new public 2>&1 | sed -n 's/.*Public\/\([A-Za-z0-9]*\).*/\1/p' | head -1)
    grep -v "^${ADMIN_VAR}=" "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null || true
    echo "${ADMIN_VAR}=$ADMIN" >> "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
fi

# Generate M moderator pubkeys (just random secp256k1 points; in production
# moderators bring their own).
MOD_PUBKEYS=()
for i in $(seq 1 "$M"); do
    MOD_ACC=$("$WALLET" account new public 2>&1 | sed -n 's/.*Public\/\([A-Za-z0-9]*\).*/\1/p' | head -1)
    PUB_HEX=$("$WALLET" account get --account-id "Public/$MOD_ACC" 2>&1 | grep -oP '"public_key":\s*"\K[0-9a-f]+' | head -1)
    if [[ -z "$PUB_HEX" || ${#PUB_HEX} -ne 66 ]]; then
        # Fallback: derive from base58 account ID (best-effort; the SPEL
        # program's create_instance just stores the bytes).
        PUB_HEX=$(printf '02%s' "$(echo -n "$MOD_ACC" | sha256sum | cut -c1-64)")
    fi
    MOD_PUBKEYS+=("$PUB_HEX")
done

# Fund the admin so it can pay the create_instance tx.
"$WALLET" pinata claim --to "Public/$ADMIN" || true

echo "▶ Calling create_instance on PROGRAM_ID_${LABEL}=${PROGRAM_ID}"
echo "  K=$K  N-of-M=$N/$M  D=$D  stake=$STAKE  label='$LBL'"
echo "  admin=Public/$ADMIN"
echo "  moderator pubkeys: ${MOD_PUBKEYS[*]}"

PUBKEYS_JSON=$(printf '%s\n' "${MOD_PUBKEYS[@]}" | jq -R . | jq -s .)

"$SPEL" --program-id-hex "$PROGRAM_ID" create_instance \
    --admin "Public/$ADMIN" \
    --k "$K" --n "$N" --m "$M" --d "$D" \
    --stake-amount "$STAKE" \
    --label "$LBL" \
    --moderator-pubkeys "$PUBKEYS_JSON"

echo "✓ Instance ${LABEL} initialized."
echo "  Threshold-key shares were generated and printed by spel above."
echo "  Distribute them out-of-band to the M moderators, then DISCARD the"
echo "  master secret (keeping it breaks the threshold property)."
