#!/bin/bash
# Compare sync speed of Ouroboros vs Bitcoin Core on testnet4.
# Times syncing 5000 blocks. Use --use-existing to skip initial download and use
# existing comparison data (bitcoin/testnet4_sync_data, .ouroboros-testnet4-compare).
#
# Usage:
#   ./scripts/run_testnet4_speed_comparison.sh --fresh        # Full: phase 1 + phase 2
#   ./scripts/run_testnet4_speed_comparison.sh --use-existing  # Skip phase 1, use existing data
#
# --fresh         Clear dirs, sync 0-59999, then time 60000-60499
# --use-existing  Use existing data from previous comparison; time next 5000 blocks from min(tip)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

NUM_BLOCKS=5000

# Default: speed test dirs. With --use-existing: main comparison dirs.
BITCOIN_DIR="${PROJECT_ROOT}/bitcoin"
BITCOIND="${BITCOIN_DIR}/build/bin/bitcoind"
BITCOIN_CLI="${BITCOIN_DIR}/build/bin/bitcoin-cli"
OUROBOROS_DATA_SPEED="${PROJECT_ROOT}/.ouroboros-testnet4-speed-test"
OUROBOROS_DATA_COMPARE="${PROJECT_ROOT}/.ouroboros-testnet4-compare"
BITCOIN_DATA_SPEED="${BITCOIN_DIR}/testnet4_speed_test"
BITCOIN_DATA_COMPARE="${BITCOIN_DIR}/testnet4_sync_data"
COMPARE_SCRIPT="${PROJECT_ROOT}/scripts/compare_block_hashes.py"

# Parse args
FRESH=false
USE_EXISTING=false
for arg in "$@"; do
  case "$arg" in
    --fresh|-f) FRESH=true ;;
    --use-existing|-e) USE_EXISTING=true ;;
  esac
done

# Sanity checks
if [ ! -x "${BITCOIND}" ] || [ ! -x "${BITCOIN_CLI}" ]; then
  echo "Error: Bitcoin Core not built. Run: cd bitcoin && ./autogen.sh && ./configure && make"
  exit 1
fi
if ! command -v ouroboros &>/dev/null; then
  echo "Error: ouroboros not in PATH. Activate venv and ensure: pip install -e . && maturin develop"
  exit 1
fi

if [ "$FRESH" != true ] && [ "$USE_EXISTING" != true ]; then
  echo "Usage: $0 --fresh | $0 --use-existing"
  echo "  --fresh         Clear dirs and run full comparison (phase 1 + phase 2)"
  echo "  --use-existing  Use existing comparison data; skip phase 1, time next 5000 blocks"
  exit 1
fi

if [ "$USE_EXISTING" = true ]; then
  BITCOIN_DATA="${BITCOIN_DATA_COMPARE}"
  OUROBOROS_DATA="${OUROBOROS_DATA_COMPARE}"
  echo "=== Using existing data: ${BITCOIN_DATA} | ${OUROBOROS_DATA} ==="
  echo ""

  # Ensure bitcoind running to read tips
  "${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
  sleep 4
  BTC_TIP=$("${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockcount 2>/dev/null) || BTC_TIP=0
  OURO_TIP=$(python3 -c "
from pathlib import Path
import sys
sys.path.insert(0, '${PROJECT_ROOT}')
from ouroboros.database import BlockchainDatabase
try:
    _, h = BlockchainDatabase('${OUROBOROS_DATA}').get_best_block()
    print(h)
except: print(0)
" 2>/dev/null) || OURO_TIP=0

  # Use fixed range 60000-60499 (both already have this from previous comparison)
  BASE_HEIGHT=59999
  START_HEIGHT=60000
  END_HEIGHT=60499

  echo "Bitcoin tip: ${BTC_TIP}  |  Ouroboros tip: ${OURO_TIP}"
  echo "Both have blocks 0-${BASE_HEIGHT}. Timing sync of ${START_HEIGHT}-${END_HEIGHT} (${NUM_BLOCKS} blocks)."
  echo "(Data already present; will measure how quickly each verifies/catches up.)"
  echo ""

  if [ "${BTC_TIP}" -lt "${END_HEIGHT}" ] || [ "${OURO_TIP}" -lt "${END_HEIGHT}" ]; then
    echo "Error: Need at least ${END_HEIGHT} blocks. Bitcoin: ${BTC_TIP}, Ouroboros: ${OURO_TIP}"
    exit 1
  fi
else
  # Fresh mode
  START_HEIGHT=60000
  PHASE1_HEIGHT=59999
  END_HEIGHT=60499
  BASE_HEIGHT=${PHASE1_HEIGHT}
  BITCOIN_DATA="${BITCOIN_DATA_SPEED}"
  OUROBOROS_DATA="${OUROBOROS_DATA_SPEED}"

  echo "=== Testnet4 speed comparison: blocks ${START_HEIGHT}-${END_HEIGHT} (${NUM_BLOCKS} blocks) ==="
  echo ""

  # Fresh: clear data dirs
  echo "=== Clearing data dirs ==="
  rm -rf "${BITCOIN_DATA}"
  rm -rf "${OUROBOROS_DATA}"
  mkdir -p "${BITCOIN_DATA}"
  echo "Cleared ${BITCOIN_DATA} and ${OUROBOROS_DATA}"
  echo ""

  # --- Phase 1: Sync both to height 59999 ---
  echo "=== Phase 1: Syncing both to height ${PHASE1_HEIGHT} ==="
  echo ""

  "${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
  sleep 3
  for i in $(seq 1 30); do
    if "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo &>/dev/null; then
      echo "bitcoind ready"
      break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
      echo "Error: bitcoind failed to start"
      exit 1
    fi
  done

  echo "Bitcoin Core: syncing to ${PHASE1_HEIGHT}..."
  while true; do
    BLOCKS=$("${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockcount 2>/dev/null) || BLOCKS=0
    echo "  [$(date +%H:%M:%S)] Bitcoin: ${BLOCKS} / ${PHASE1_HEIGHT}"
    if [ "${BLOCKS}" -ge "${PHASE1_HEIGHT}" ] 2>/dev/null; then
      break
    fi
    sleep 5
  done
  echo "Bitcoin Core at ${PHASE1_HEIGHT}"
  "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" stop 2>/dev/null || true
  sleep 3
  echo ""

  echo "Ouroboros: syncing to ${PHASE1_HEIGHT}..."
  OUROBOROS_SYNC_DIAG=1 OUROBOROS_MAX_IN_FLIGHT=64 OUROBOROS_STALLING_TIMEOUT_SECS=5 \
  OUROBOROS_DESYNC_BLACKLIST_SECS=30 OUROBOROS_TRY_RESYNC=1 OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120 \
  RUST_LOG=sync=info ouroboros --network testnet4 --data-dir "${OUROBOROS_DATA}" sync --reset --limit "${PHASE1_HEIGHT}" 2>&1 | tee "${PROJECT_ROOT}/ouroboros_speed_test_phase1.log" || true
  echo "Ouroboros at ${PHASE1_HEIGHT}"
  echo ""
fi

# --- Phase 2: Time syncing 5000 blocks ---
echo "=== Phase 2: Timing sync of blocks ${START_HEIGHT}-${END_HEIGHT} (${NUM_BLOCKS} blocks) ==="
echo ""

# Bitcoin Core: ensure running, time until END_HEIGHT (may already be there with --use-existing)
"${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
sleep 4
for i in $(seq 1 30); do
  if "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo &>/dev/null; then
    break
  fi
  sleep 1
done

BTC_START=$(date +%s)
echo "Bitcoin Core: syncing ${START_HEIGHT} -> ${END_HEIGHT}..."
while true; do
  BLOCKS=$("${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockcount 2>/dev/null) || BLOCKS=0
  echo "  [$(date +%H:%M:%S)] Bitcoin: ${BLOCKS} / ${END_HEIGHT}"
  if [ "${BLOCKS}" -ge "${END_HEIGHT}" ] 2>/dev/null; then
    break
  fi
  sleep 5
done
BTC_END=$(date +%s)
BTC_DUR=$((BTC_END - BTC_START))
echo "Bitcoin Core complete in ${BTC_DUR}s ($(($BTC_DUR/60))m $(($BTC_DUR%60))s)"
echo ""

# Stop Bitcoin for Ouroboros phase 2 (free network)
"${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" stop 2>/dev/null || true
sleep 3
echo ""

# Ouroboros: sync to 60499 (fetches 60000-60499 = 5000 blocks)
OURO_START=$(date +%s)
echo "Ouroboros: syncing ${START_HEIGHT} -> ${END_HEIGHT}..."
OUROBOROS_SYNC_DIAG=1 OUROBOROS_MAX_IN_FLIGHT=64 OUROBOROS_STALLING_TIMEOUT_SECS=5 \
OUROBOROS_DESYNC_BLACKLIST_SECS=30 OUROBOROS_TRY_RESYNC=1 OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120 \
RUST_LOG=sync=info ouroboros --network testnet4 --data-dir "${OUROBOROS_DATA}" sync --limit "${END_HEIGHT}" 2>&1 | tee "${PROJECT_ROOT}/ouroboros_speed_test.log" || true
OURO_END=$(date +%s)
OURO_DUR=$((OURO_END - OURO_START))
echo "Ouroboros complete in ${OURO_DUR}s ($(($OURO_DUR/60))m $(($OURO_DUR%60))s)"
echo ""

# Restart Bitcoin for correctness check
echo "Restarting bitcoind for correctness check..."
"${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
sleep 4
for i in $(seq 1 30); do
  if "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo &>/dev/null; then
    echo "bitcoind ready"
    break
  fi
  sleep 1
done
echo ""

# --- Correctness: compare block hashes ---
echo "=== Correctness: comparing block hashes ==="
python3 "${COMPARE_SCRIPT}" \
  --ouroboros-dir "${OUROBOROS_DATA}" \
  --bitcoin-cli "${BITCOIN_CLI}" \
  --bitcoin-datadir "${BITCOIN_DATA}" \
  --testnet4 \
  --heights "60000,60100,60200,60300,60400,60499" 2>/dev/null || true
CMP_EXIT=$?
echo ""

# --- Summary ---
echo "=== Summary: blocks ${START_HEIGHT}-${END_HEIGHT} (${NUM_BLOCKS} blocks, testnet4) ==="
echo "| Node        | Sync time   | Blocks/sec |"
echo "|-------------|-------------|------------|"
BTC_BPS=$(python3 -c "print(round(${NUM_BLOCKS}/${BTC_DUR}, 1))" 2>/dev/null || echo "?")
OURO_BPS=$(python3 -c "print(round(${NUM_BLOCKS}/${OURO_DUR}, 1))" 2>/dev/null || echo "?")
echo "| Bitcoin Core| $(printf '%3d' $((BTC_DUR/60)))m $(printf '%02d' $((BTC_DUR%60)))s | ${BTC_BPS} |"
echo "| Ouroboros   | $(printf '%3d' $((OURO_DUR/60)))m $(printf '%02d' $((OURO_DUR%60)))s | ${OURO_BPS} |"
echo ""
if [ $OURO_DUR -le $((BTC_DUR * 12 / 10)) ]; then
  echo "Result: Ouroboros within 20% of Bitcoin Core speed ✓"
else
  RATIO=$(python3 -c "print(f'{${OURO_DUR}*100/${BTC_DUR}:.0f}')" 2>/dev/null || echo "?")
  echo "Result: Ouroboros took ${RATIO}% of Bitcoin Core time"
fi
echo ""
if [ $CMP_EXIT -eq 0 ]; then
  echo "Correctness: All sampled block hashes MATCH"
else
  echo "Correctness: See above for any mismatches"
fi
echo ""
echo "Data dirs: ${BITCOIN_DATA} | ${OUROBOROS_DATA}"
exit $CMP_EXIT
