#!/bin/bash
# Run Bitcoin Core and Ouroboros on testnet4, compare correctness and sync time.
# Usage: ./scripts/run_testnet4_comparison.sh [--fresh] [--compare-only]
#
# From project root: cd /home/max/hashhog/ouroboros && ./scripts/run_testnet4_comparison.sh
#
# --fresh        Clear both data dirs before syncing (fresh start)
# --compare-only Skip syncs; only compare block hashes (both must already be synced)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# Paths
BITCOIN_DIR="${PROJECT_ROOT}/bitcoin"
BITCOIND="${BITCOIN_DIR}/build/bin/bitcoind"
BITCOIN_CLI="${BITCOIN_DIR}/build/bin/bitcoin-cli"
BITCOIN_DATA="${BITCOIN_DIR}/testnet4_sync_data"
OUROBOROS_DATA="${PROJECT_ROOT}/.ouroboros-testnet4-compare"
COMPARE_SCRIPT="${PROJECT_ROOT}/scripts/compare_block_hashes.py"

# Parse args
FRESH=false
COMPARE_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --fresh|-f) FRESH=true ;;
    --compare-only) COMPARE_ONLY=true ;;
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

# Fresh: clear data dirs
if [ "$FRESH" = true ]; then
  echo "=== Fresh sync: clearing data dirs ==="
  rm -rf "${BITCOIN_DATA}"
  rm -rf "${OUROBOROS_DATA}"
  mkdir -p "${BITCOIN_DATA}"
  echo "Cleared ${BITCOIN_DATA} and ${OUROBOROS_DATA}"
fi

if [ "$COMPARE_ONLY" = true ]; then
  echo "=== Compare-only mode: skipping syncs ==="
  echo "Ensuring bitcoind is running..."
  "${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
  sleep 3
  if ! "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo &>/dev/null; then
    echo "Error: bitcoind not running. Start it first."
    exit 1
  fi
else

echo ""
echo "=== Bitcoin Core testnet4 sync ==="
echo "Data dir: ${BITCOIN_DATA}"
echo ""

# Stop any existing bitcoind
"${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" stop 2>/dev/null || true
sleep 2

# Start bitcoind
"${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon
echo "Waiting for bitcoind to start..."
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

# Sync Bitcoin Core (poll until verificationprogress >= 0.9999)
echo "Syncing Bitcoin Core (this may take 1-3 hours on testnet4)..."
BTC_START=$(date +%s)
while true; do
  PROG=$("${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    b = d.get('blocks', 0)
    h = d.get('headers', 0)
    p = d.get('verificationprogress', 0)
    print(f'{b} {h} {p}')
except: sys.exit(1)
" 2>/dev/null) || { sleep 10; continue; }
  BLOCKS=$(echo "$PROG" | cut -d' ' -f1)
  HEADERS=$(echo "$PROG" | cut -d' ' -f2)
  PROGRESS=$(echo "$PROG" | cut -d' ' -f3)
  PCT=$(python3 -c "print(f'{float(\"$PROGRESS\")*100:.1f}')" 2>/dev/null || echo "?")
  echo "  [$(date +%H:%M:%S)] Bitcoin: $BLOCKS / $HEADERS blocks ($PCT%)"
  if python3 -c "exit(0 if float('$PROGRESS') >= 0.9999 else 1)" 2>/dev/null; then
    break
  fi
  sleep 60
done
BTC_END=$(date +%s)
BTC_DUR=$((BTC_END - BTC_START))
echo "Bitcoin Core sync complete in ${BTC_DUR}s ($(($BTC_DUR/60))m $(($BTC_DUR%60))s)"
echo ""

# Ouroboros sync
echo "=== Ouroboros testnet4 sync ==="
echo "Data dir: ${OUROBOROS_DATA}"
echo ""

OURO_START=$(date +%s)
# Higher concurrency (64) + aggressive timeouts (reassign slow blocks sooner, Bitcoin Core-style)
OUROBOROS_SYNC_DIAG=1 OUROBOROS_MAX_IN_FLIGHT=64 OUROBOROS_STALLING_TIMEOUT_SECS=5 \
OUROBOROS_DESYNC_BLACKLIST_SECS=30 OUROBOROS_TRY_RESYNC=1 OUROBOROS_BLOCK_RECEIVE_TIMEOUT_SECS=120 \
RUST_LOG=sync=info ouroboros --network testnet4 --data-dir "${OUROBOROS_DATA}" sync 2>&1 | tee "${PROJECT_ROOT}/ouroboros_compare_sync.log" || true
OURO_END=$(date +%s)
OURO_DUR=$((OURO_END - OURO_START))
echo ""
echo "Ouroboros sync finished in ${OURO_DUR}s ($(($OURO_DUR/60))m $(($OURO_DUR%60))s)"
echo ""

fi  # end if not COMPARE_ONLY

# Ensure bitcoind is running before correctness check (it may have stopped during long Ouroboros sync)
echo "Ensuring bitcoind is running for block hash comparison..."
"${BITCOIND}" -testnet4 -datadir="${BITCOIN_DATA}" -daemon 2>/dev/null || true
sleep 3
for i in $(seq 1 30); do
  if "${BITCOIN_CLI}" -testnet4 -datadir="${BITCOIN_DATA}" getblockchaininfo &>/dev/null; then
    echo "bitcoind ready"
    break
  fi
  sleep 1
  if [ $i -eq 30 ]; then
    echo "Error: bitcoind not running. Start it with: ${BITCOIND} -testnet4 -datadir=${BITCOIN_DATA} -daemon"
    exit 1
  fi
done

# Correctness: compare block hashes
echo "=== Correctness: comparing block hashes ==="
if [ ! -f "${COMPARE_SCRIPT}" ]; then
  echo "Error: compare script not found: ${COMPARE_SCRIPT}"
  exit 1
fi
python3 "${COMPARE_SCRIPT}" \
  --ouroboros-dir "${OUROBOROS_DATA}" \
  --bitcoin-cli "${BITCOIN_CLI}" \
  --bitcoin-datadir "${BITCOIN_DATA}" \
  --testnet4 \
  --heights "0,1000,10000,50000,100000,tip"
CMP_EXIT=$?
echo ""

# Summary
echo "=== Summary ==="
if [ "$COMPARE_ONLY" != true ]; then
  echo "| Node        | Sync time   |"
  echo "|-------------|-------------|"
  echo "| Bitcoin Core| $(printf '%3d' $((BTC_DUR/60)))m $(printf '%02d' $((BTC_DUR%60)))s |"
  echo "| Ouroboros   | $(printf '%3d' $((OURO_DUR/60)))m $(printf '%02d' $((OURO_DUR%60)))s |"
else
  echo "(Compare-only: no sync times)"
fi
echo ""
if [ $CMP_EXIT -eq 0 ]; then
  echo "Correctness: All block hashes MATCH"
else
  echo "Correctness: MISMATCH (see above)"
fi
echo ""

# Leave bitcoind running so user can inspect; optionally stop
echo "Bitcoin Core is still running. To stop: ${BITCOIN_CLI} -testnet4 -datadir=${BITCOIN_DATA} stop"
exit $CMP_EXIT
