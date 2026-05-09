#!/usr/bin/env python3
"""
Populate HEADERS_CF for specific block hashes from Bitcoin Core.
Used to seed the 5 W57 corpus entries + any other specific blocks needed.
"""

import struct
import sys
import urllib.request
import json
import base64

CORPUS_HASHES = [
    # (display_hash, description)
    ("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048", "h=1 genesis+1"),
    ("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e", "h=210000 first-halving"),
    ("0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893", "h=481824 segwit-activation"),
    ("0000000000000000000687bca986194dc2c1f949318629b44bb54ec0a94d8244", "h=709632 taproot-activation"),
    ("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054", "h=800000 modern"),
]


def header_fields_to_bytes(version, prev_hash_hex, merkle_hex, time_, bits_hex, nonce):
    if not prev_hash_hex or prev_hash_hex == "0" * 64:
        prev_bytes = bytes(32)
    else:
        prev_bytes = bytes.fromhex(prev_hash_hex)[::-1]
    merkle_bytes = bytes.fromhex(merkle_hex)[::-1]
    bits_int = int(bits_hex, 16)
    buf = struct.pack('<i', version)
    buf += prev_bytes
    buf += merkle_bytes
    buf += struct.pack('<I', time_)
    buf += struct.pack('<I', bits_int)
    buf += struct.pack('<I', nonce)
    assert len(buf) == 80
    return buf


def rpc(url, auth_b64, method, params):
    payload = json.dumps({"jsonrpc": "1.0", "id": "x", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    req.add_header("Authorization", f"Basic {auth_b64}")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["result"]


def main():
    data_dir = sys.argv[1] if len(sys.argv) > 1 else "/data/nvme1/hashhog-mainnet/ouroboros"
    core_url = "http://127.0.0.1:8332"
    cookie_path = "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie"

    auth = open(cookie_path).read().strip()
    auth_b64 = base64.b64encode(auth.encode()).decode()

    from sync import sync as _sync
    db = _sync.PyBlockchainDB(data_dir)
    print(f"Opened DB at {data_dir}")

    for display_hash, desc in CORPUS_HASHES:
        block_hash_internal = bytes.fromhex(display_hash)[::-1]

        # Check if already present AND fully populated (has chainwork + mediantime + nexthash)
        # nexthash is stored at bytes 124..156 (format v3 = 156 bytes total)
        existing = db.get_raw_header_with_chainwork(block_hash_internal)
        if existing is not None:
            hdr_bytes, n_tx, cw_bytes, stored_height, stored_mt, stored_nh = existing
            cw_int = int.from_bytes(cw_bytes, 'big')
            # Only skip if we have the full 156-byte format (nexthash field is present and non-zero OR height is tip)
            # We check by looking at len(hdr_bytes) — actually hdr_bytes is always 80 bytes.
            # Instead check stored_mt > 0 (only written in 124+ byte format) and stored_nh is available.
            if cw_int > 0 and stored_height > 0 and stored_mt > 0 and any(b != 0 for b in stored_nh):
                print(f"  SKIP {desc}: already in HEADERS_CF v3 (nTx={n_tx}, h={stored_height})")
                continue
            # else: re-store with full format

        # Get header from Core
        try:
            h = rpc(core_url, auth_b64, "getblockheader", [display_hash, True])
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
            height = h.get("height", 0)
            mediantime = h.get("mediantime", h.get("time", 0))
            chainwork_hex = h.get("chainwork", "00" * 32)
            chainwork_bytes = bytes.fromhex(chainwork_hex)
            assert len(chainwork_bytes) == 32

            # nexthash: from Core display order → internal byte order (reversed)
            next_hash_display = h.get("nextblockhash", "")
            if next_hash_display:
                nexthash_bytes = bytes.fromhex(next_hash_display)[::-1]
            else:
                nexthash_bytes = bytes(32)  # all zeros = tip or unknown

            db.store_raw_header_with_chainwork(
                block_hash_internal, header_bytes, n_tx, chainwork_bytes,
                height, mediantime, nexthash_bytes
            )
            print(f"  STORED {desc}: nTx={n_tx} h={height} mt={mediantime} chainwork={chainwork_hex[:16]}...")
        except Exception as e:
            print(f"  ERROR {desc}: {e}", file=sys.stderr)

    print("Done.")


if __name__ == "__main__":
    main()
