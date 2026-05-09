#!/usr/bin/env python3
"""
Populate HEADERS_CF for ouroboros from Bitcoin Core's getblockheader RPC.

This script fills the header-only store (HEADERS_CF) for blocks that are
absent from BLOCKS_CF — typically the gap between the genesis-sync range
(heights 0-107 for this deployment) and the post-snapshot range
(heights 944184+) after a loadtxoutset recovery.

It works in two phases:
  Phase 1: Extract headers from existing BLOCKS_CF entries (fast, local).
  Phase 2: For heights not in BLOCK_INDEX_CF, walk from h=0 upward via
           bitcoin-core's getblockhash + getblockheader RPCs and write
           the 80-byte header + nTx count into HEADERS_CF.

Usage:
  python3 tools/populate_headers_cf.py \
      --data-dir /data/nvme1/hashhog-mainnet/ouroboros \
      --core-rpc http://127.0.0.1:8332 \
      --core-cookie /data/nvme1/hashhog-mainnet/bitcoin-core/.cookie \
      [--start-height 0] [--end-height 948660] [--batch-size 500]
"""

import argparse
import struct
import sys
import time
import urllib.request
import urllib.error
import json
import base64
from pathlib import Path

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def load_cookie(cookie_path: str) -> str:
    """Read a Bitcoin Core cookie file and return 'user:password'."""
    text = Path(cookie_path).read_text().strip()
    return text  # format: __cookie__:<hex>


def rpc_call(url: str, auth: str, method: str, params: list) -> dict:
    """Make a JSON-RPC call and return the parsed response."""
    payload = json.dumps({"jsonrpc": "1.0", "id": "populate", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    # Basic auth
    cred = base64.b64encode(auth.encode()).decode()
    req.add_header("Authorization", f"Basic {cred}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# DB helpers (using the sync Rust extension)
# ---------------------------------------------------------------------------

def open_db(data_dir: str):
    """Open the ouroboros RocksDB and return the PyBlockchainDB instance."""
    try:
        from sync import sync as _sync
        db = _sync.PyBlockchainDB(data_dir)
        return db
    except Exception as e:
        print(f"ERROR: could not open DB at {data_dir}: {e}", file=sys.stderr)
        sys.exit(1)


def header_fields_to_bytes(version: int, prev_hash_hex: str, merkle_hex: str,
                            time_: int, bits_hex: str, nonce: int) -> bytes:
    """Serialize header fields into an 80-byte wire-format header."""
    # Display-order hashes need reversal to internal byte order
    prev_bytes = bytes.fromhex(prev_hash_hex)[::-1]
    merkle_bytes = bytes.fromhex(merkle_hex)[::-1]
    bits_int = int(bits_hex, 16)

    buf = struct.pack('<i', version)   # 4 bytes signed LE
    buf += prev_bytes                   # 32 bytes
    buf += merkle_bytes                 # 32 bytes
    buf += struct.pack('<I', time_)    # 4 bytes LE
    buf += struct.pack('<I', bits_int) # 4 bytes LE
    buf += struct.pack('<I', nonce)    # 4 bytes LE
    assert len(buf) == 80, f"Header must be 80 bytes, got {len(buf)}"
    return buf


def block_hash_display_to_internal(display_hex: str) -> bytes:
    """Convert display-order (big-endian) hex hash to internal byte order."""
    return bytes.fromhex(display_hex)[::-1]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Populate ouroboros HEADERS_CF from bitcoin-core")
    parser.add_argument("--data-dir", required=True, help="Path to ouroboros datadir (RocksDB)")
    parser.add_argument("--core-rpc", default="http://127.0.0.1:8332", help="Bitcoin Core RPC URL")
    parser.add_argument("--core-cookie", required=True, help="Path to bitcoin-core cookie file")
    parser.add_argument("--start-height", type=int, default=0, help="Start height (inclusive)")
    parser.add_argument("--end-height", type=int, default=None, help="End height (inclusive). Default: Core tip.")
    parser.add_argument("--batch-size", type=int, default=200, help="Heights to process per progress report")
    parser.add_argument("--skip-existing", action="store_true", default=True,
                        help="Skip heights already in HEADERS_CF (default: True)")
    args = parser.parse_args()

    auth = load_cookie(args.core_cookie)
    db = open_db(args.data_dir)

    # Determine end height from Core if not specified
    if args.end_height is None:
        resp = rpc_call(args.core_rpc, auth, "getblockcount", [])
        args.end_height = resp["result"]
    print(f"Populating HEADERS_CF for heights {args.start_height}..{args.end_height}")

    stored = 0
    skipped = 0
    errors = 0
    t0 = time.time()

    for height in range(args.start_height, args.end_height + 1):
        try:
            # Get block hash at this height from Core
            resp = rpc_call(args.core_rpc, auth, "getblockhash", [height])
            block_hash_display = resp["result"]
            block_hash_internal = block_hash_display_to_internal(block_hash_display)

            # Skip if already present
            if args.skip_existing:
                existing = db.get_raw_header(block_hash_internal)
                if existing is not None:
                    skipped += 1
                    if height % args.batch_size == 0:
                        elapsed = time.time() - t0
                        rate = (stored + skipped) / elapsed if elapsed > 0 else 0
                        print(f"  h={height}: stored={stored} skipped={skipped} errors={errors} rate={rate:.0f}/s")
                    continue

            # Get verbose header from Core
            resp = rpc_call(args.core_rpc, auth, "getblockheader", [block_hash_display, True])
            h = resp["result"]

            prev_hash_hex = h.get("previousblockhash", "00" * 32)
            header_bytes = header_fields_to_bytes(
                version=h["version"],
                prev_hash_hex=prev_hash_hex,
                merkle_hex=h["merkleroot"],
                time_=h["time"],
                bits_hex=h["bits"],
                nonce=h["nonce"],
            )
            n_tx = h.get("nTx", 0)

            db.store_raw_header(block_hash_internal, header_bytes, n_tx)
            stored += 1

        except Exception as e:
            errors += 1
            print(f"  ERROR at height {height}: {e}", file=sys.stderr)
            if errors > 100:
                print("Too many errors, aborting.", file=sys.stderr)
                sys.exit(1)
            continue

        if height % args.batch_size == 0:
            elapsed = time.time() - t0
            rate = (stored + skipped) / elapsed if elapsed > 0 else 0
            print(f"  h={height}: stored={stored} skipped={skipped} errors={errors} rate={rate:.0f}/s")

    elapsed = time.time() - t0
    print(f"Done: stored={stored} skipped={skipped} errors={errors} in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
