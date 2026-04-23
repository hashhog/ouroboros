#!/bin/bash
# Launch ouroboros on mainnet as a detached daemon.
#
# Background: tools/start_mainnet.sh in the meta-repo invokes the ouroboros CLI
# without nohup/setsid/disown, so the process inherits the caller's
# controlling-terminal and session. When the caller's shell exits, SIGHUP kills
# ouroboros. This was the root cause of the wave-8 "silent exit at T+9min"
# incident (see wave9-2026-04-14/OUROBOROS-EXIT-REGRESSION.md).
#
# This script is the correct way to launch from a non-persistent shell. It:
#   - uses setsid to create a new session (immune to parent SIGHUP)
#   - redirects stdin from /dev/null (no tty coupling)
#   - appends stdout+stderr to the canonical mainnet log
#   - disowns the job
#
# Usage (from repo root or anywhere):
#   bash /home/work/hashhog/ouroboros/scripts/run_mainnet_daemon.sh [extra-args...]
#
# Environment overrides:
#   OURO_DATA_DIR    (default: /data/nvme1/hashhog-mainnet/ouroboros)
#   OURO_RPC_PORT    (default: 8359)
#   OURO_P2P_PORT    (default: 0)
#   OURO_LOG         (default: /data/nvme1/hashhog-mainnet/logs/ouroboros.log)

set -e

DATA_DIR="${OURO_DATA_DIR:-/data/nvme1/hashhog-mainnet/ouroboros}"
RPC_PORT="${OURO_RPC_PORT:-8359}"
P2P_PORT="${OURO_P2P_PORT:-0}"
LOG="${OURO_LOG:-/data/nvme1/hashhog-mainnet/logs/ouroboros.log}"

# OUROBOROS-CORE-ALIGNMENT-PLAN deploy (plan-w98 soak, 2026-04-23):
#   OUROBOROS_DISK_BUFFER=1    plan-W96 disk-on-receipt pending store
#   OUROBOROS_PER_PEER_SCHED=1 plan-W97 per-peer FindNextBlocksToDownload
# plan-W98 (on-demand Block.deserialize) is unconditional — no flag.
# Unset these (or edit this file) to revert to legacy round-robin + in-memory buffer.
export OUROBOROS_DISK_BUFFER="${OUROBOROS_DISK_BUFFER:-1}"
export OUROBOROS_PER_PEER_SCHED="${OUROBOROS_PER_PEER_SCHED:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

mkdir -p "$(dirname "$LOG")"

# Abort if already running on this RPC port.
if ss -tln 2>/dev/null | grep -q ":${RPC_PORT} "; then
  echo "ouroboros already listening on :${RPC_PORT}; refusing to double-launch" >&2
  exit 1
fi

cd "$REPO_ROOT"

echo "$(date -Iseconds) starting ouroboros mainnet daemon (rpc=${RPC_PORT} p2p=${P2P_PORT} data=${DATA_DIR})" >> "$LOG"

setsid nohup python3 -m ouroboros.cli \
    --network mainnet \
    --data-dir "$DATA_DIR" \
    start \
    --rpc-port "$RPC_PORT" \
    --p2p-port "$P2P_PORT" \
    --nolisten \
    --force \
    "$@" \
    </dev/null >> "$LOG" 2>&1 &

PID=$!
disown
echo "launched ouroboros pid=$PID"
echo "log: $LOG"
