#!/usr/bin/env bash
# Deploys forum_registry.bin to a running LEZ sequencer (Railway or local)
# and appends the resulting program ID to .forum-state.
#
# Usage:
#   NSSA_SEQUENCER_URL=https://forum-seq.up.railway.app \
#   bash scripts/deploy/deploy-program.sh [INSTANCE_LABEL]
#
# INSTANCE_LABEL defaults to "A". Used only as a key in .forum-state, e.g.
# `PROGRAM_ID_A=...`.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

LABEL="${1:-A}"
GUEST_BIN="${GUEST_BIN:-methods/guest/target/riscv32im-risc0-zkvm-elf/docker/forum_registry.bin}"
WALLET="${WALLET:-wallet}"
STATE_FILE=".forum-state"

if [[ ! -f "$GUEST_BIN" ]]; then
    echo "ERROR: $GUEST_BIN not found." >&2
    echo "       Run 'make build-guest' first (requires docker buildx)." >&2
    exit 1
fi

if [[ -z "${NSSA_SEQUENCER_URL:-}" ]]; then
    echo "ERROR: NSSA_SEQUENCER_URL not set. Point at your sequencer, e.g.:" >&2
    echo "       export NSSA_SEQUENCER_URL=https://your-seq.up.railway.app" >&2
    exit 1
fi
export NSSA_SEQUENCER_URL
export NSSA_WALLET_HOME_DIR="${NSSA_WALLET_HOME_DIR:-$ROOT/.scaffold/wallet}"

echo "▶ Sequencer: $NSSA_SEQUENCER_URL"
echo "▶ Wallet home: $NSSA_WALLET_HOME_DIR"
echo "▶ Guest binary: $GUEST_BIN ($(stat -c%s "$GUEST_BIN") bytes)"

# Sanity: sequencer reachable?
"$WALLET" check-health || {
    echo "ERROR: wallet check-health failed against $NSSA_SEQUENCER_URL" >&2
    exit 1
}

# Capture program ID from the deploy output. wallet's exact output format:
#   Program deployed: <64-hex>
DEPLOY_OUT=$("$WALLET" deploy-program "$GUEST_BIN" 2>&1)
PROGRAM_ID=$(echo "$DEPLOY_OUT" | grep -oE '[0-9a-f]{64}' | head -1)

if [[ -z "$PROGRAM_ID" ]]; then
    echo "ERROR: couldn't extract program ID from deploy output:" >&2
    echo "$DEPLOY_OUT" >&2
    exit 1
fi

echo "✓ Deployed instance '$LABEL': $PROGRAM_ID"

# Persist to .forum-state (replace if PROGRAM_ID_$LABEL already there).
touch "$STATE_FILE"
grep -v "^PROGRAM_ID_${LABEL}=" "$STATE_FILE" > "${STATE_FILE}.tmp" || true
echo "PROGRAM_ID_${LABEL}=$PROGRAM_ID" >> "${STATE_FILE}.tmp"
mv "${STATE_FILE}.tmp" "$STATE_FILE"

echo "  → wrote PROGRAM_ID_${LABEL} to $STATE_FILE"
