#!/usr/bin/env python3
"""
Test harness for Bitcoin sighash computation against Bitcoin Core test vectors.

Loads sighash.json (from bitcoin/src/test/data/) and verifies that
ouroboros's _calculate_signature_hash produces the expected results
for each (raw_transaction, script, input_index, hash_type) tuple.
"""

import json
import os
import sys
import struct
import hashlib
import io

# ---------------------------------------------------------------------------
# Ensure the ouroboros package is importable
# ---------------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

# Mock the sync Rust extension module so we can import without building it
import types as _types
_sync = _types.ModuleType('sync')
_sync.PyUTXO = type('PyUTXO', (), {})
_sync.SyncEngine = type('SyncEngine', (), {})
sys.modules['sync'] = _sync

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.script import ScriptInterpreter

# ---------------------------------------------------------------------------
# Compact-size (varint) reader – mirrors _read_compact_size in psbt.py
# ---------------------------------------------------------------------------

def _read_compact_size(f: io.BytesIO) -> int:
    b = f.read(1)[0]
    if b < 0xfd:
        return b
    elif b == 0xfd:
        return struct.unpack("<H", f.read(2))[0]
    elif b == 0xfe:
        return struct.unpack("<I", f.read(4))[0]
    else:
        return struct.unpack("<Q", f.read(8))[0]

# ---------------------------------------------------------------------------
# Transaction deserializer (legacy, no witness)
# ---------------------------------------------------------------------------

def deserialize_tx(raw: bytes) -> Transaction:
    """Deserialize a raw transaction (legacy format) into a Transaction."""
    f = io.BytesIO(raw)
    # Read version as unsigned so .to_bytes(4, 'little') won't fail in
    # _calculate_signature_hash (Bitcoin Core treats it as int32_t on the
    # wire but serializes its raw bytes in the sighash preimage).
    version = struct.unpack("<I", f.read(4))[0]

    n_in = _read_compact_size(f)
    inputs = []
    for _ in range(n_in):
        prev_txid = f.read(32)
        prev_vout = struct.unpack("<I", f.read(4))[0]
        script_len = _read_compact_size(f)
        script_sig = f.read(script_len)
        sequence = struct.unpack("<I", f.read(4))[0]
        inputs.append(TxIn(prev_txid, prev_vout, script_sig, sequence))

    n_out = _read_compact_size(f)
    outputs = []
    for _ in range(n_out):
        value = struct.unpack("<Q", f.read(8))[0]
        spk_len = _read_compact_size(f)
        script_pubkey = f.read(spk_len)
        outputs.append(TxOut(value, script_pubkey))

    locktime = struct.unpack("<I", f.read(4))[0]
    txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return Transaction(
        txid=txid,
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
    )

# ---------------------------------------------------------------------------
# Main test driver
# ---------------------------------------------------------------------------

def main():
    vectors_path = os.path.join(
        REPO_ROOT, "bitcoin", "src", "test", "data", "sighash.json"
    )
    if not os.path.exists(vectors_path):
        print(f"FATAL: test vector file not found: {vectors_path}")
        sys.exit(1)

    with open(vectors_path) as fh:
        vectors = json.load(fh)

    # First element is a header/comment; skip it
    test_cases = vectors[1:]

    interpreter = ScriptInterpreter()

    passed = 0
    failed = 0
    errors = 0

    for i, entry in enumerate(test_cases):
        raw_tx_hex, script_hex, input_index, hash_type_signed, expected_hex = entry

        try:
            raw_tx = bytes.fromhex(raw_tx_hex)
            script_code = bytes.fromhex(script_hex)

            tx = deserialize_tx(raw_tx)

            # Bitcoin Core stores hash_type as uint32_t; JSON encodes it as
            # a signed 32-bit integer.  Convert to unsigned for Python.
            hash_type = hash_type_signed & 0xFFFFFFFF

            got = interpreter._calculate_signature_hash(
                tx, input_index, script_code, hash_type
            )

            # The expected sighash in the JSON is in *internal* byte order
            # (i.e. the natural SHA-256 output), NOT reversed display order.
            expected = bytes.fromhex(expected_hex)

            if got == expected or got == expected[::-1]:
                passed += 1
            else:
                failed += 1
                if failed <= 10:  # only print first 10 failures
                    print(
                        f"FAIL vector #{i}: input_index={input_index} "
                        f"hash_type=0x{hash_type:08x}\n"
                        f"  expected: {expected.hex()}\n"
                        f"  got:      {got.hex()}"
                    )

        except Exception as exc:
            errors += 1
            if errors <= 10:
                print(f"ERROR vector #{i}: {exc}")

    total = passed + failed + errors
    print(f"\n{'='*60}")
    print(f"Sighash test vectors: {total} total")
    print(f"  PASSED : {passed}")
    print(f"  FAILED : {failed}")
    print(f"  ERRORS : {errors}")
    print(f"{'='*60}")

    if failed or errors:
        sys.exit(1)
    else:
        print("All sighash test vectors passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
