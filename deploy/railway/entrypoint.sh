#!/usr/bin/env bash
# Entrypoint for the Railway-hosted LEZ sequencer.
#
# Railway sets $PORT dynamically per deploy; the sequencer reads its port
# from sequencer_config.json. We rewrite the config in-place at startup so
# the port matches Railway's expectation, then exec sequencer_service.
#
# Persistent data lives under /var/lib/sequencer_service (mounted as a
# Railway volume). On a cold deploy the dir is empty and the sequencer
# auto-bootstraps with a random genesis (the config sets is_genesis_random=true).

set -euo pipefail

CONFIG=/etc/sequencer_service/sequencer_config.json
DATA_DIR=/var/lib/sequencer_service
PORT="${PORT:-3040}"

# Patch only the data dir into the config — the listening port is a CLI arg
# (`--port`), NOT a config field. The `port` key in sequencer_config.json is
# unused by sequencer_service::main; passing it via --port is what binds.
TMP=$(mktemp)
jq --arg home "${DATA_DIR}" '. + {home: $home}' "${CONFIG}" > "${TMP}"
mv "${TMP}" "${CONFIG}"

echo "[entrypoint] starting sequencer_service on 0.0.0.0:${PORT}"
echo "[entrypoint] data dir: ${DATA_DIR}"
echo "[entrypoint] RISC0_DEV_MODE=${RISC0_DEV_MODE:-1}"

exec /usr/local/bin/sequencer_service --port "${PORT}" "${CONFIG}"
