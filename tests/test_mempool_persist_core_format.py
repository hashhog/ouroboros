"""
Tests for the Bitcoin Core compatible mempool.dat dump/load format.

Reference: bitcoin-core/src/node/mempool_persist.cpp DumpMempool / LoadMempool.

Format (all little-endian, no padding):
    uint64 version              = 1 (no XOR) or 2 (XOR-obfuscated)
    if version == 2:
        compact_size key_len    = 8
        byte[8]    xor_key      (random; first 8 bytes after the header are
                                 XORed with this key, repeating)
    uint64 tx_count
    per tx:
        CTransaction (TX_WITH_WITNESS)
        int64  nTime
        int64  nFeeDelta
    compact_size mapDeltas_count
    compact_size unbroadcast_count

These tests verify:
  - Dumped bytes parse cleanly with the legacy ``struct``-only golden parser
    (no Bitcoin Core dependency required).
  - Round-trip dump → load preserves txs, time_added (int64-truncated), and
    transaction count.
  - The XOR-obfuscation header is symmetric (XOR with same key inverts).
  - The legacy ouroboros custom format (uint8 version + uint32 count + …)
    is auto-detected and migrated rather than rejected outright.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Stub the Rust ``sync`` extension before importing ouroboros modules.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"

    class _StubDB:
        def __init__(self, *a, **kw):
            self._utxos: dict = {}
            self._best_block = (b"\x00" * 32, 100)

        def get_block(self, *a, **kw):
            return None

        def get_block_by_height(self, *a, **kw):
            return None

        def get_best_block(self, *a, **kw):
            return self._best_block

        def get_utxo(self, txid, vout):
            return self._utxos.get((txid, vout))

        def add_utxo(self, txid, vout, value, script_pubkey=b""):
            self._utxos[(txid, vout)] = {
                "value": value,
                "script_pubkey": script_pubkey,
            }

    _mock.PyBlockchainDB = _StubDB
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: True
    sys.modules["sync"] = _mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import Mempool  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _StubDB:
    def __init__(self) -> None:
        self._utxos: dict = {}

    def add_utxo(self, txid: bytes, vout: int, value: int) -> None:
        self._utxos[(txid, vout)] = {"value": value, "script_pubkey": b""}

    def get_utxo(self, txid: bytes, vout: int):
        return self._utxos.get((txid, vout))


class _AlwaysOkValidator:
    def __init__(self, db: _StubDB | None = None) -> None:
        self.db = db or _StubDB()

    def validate_transaction(self, tx, height):
        return True, ""


def _make_tx(
    seed: int, db: _StubDB, *, with_witness: bool = False
) -> Transaction:
    """Build a self-contained 1-input/1-output Transaction.

    The previous-output is registered with *db* so the mempool's UTXO probe
    in ``_add_transaction_inner`` succeeds.  Output values are well above
    DEFAULT_MIN_RELAY_TX_FEE so the entry is accepted at standard policy.
    """
    import hashlib

    prev_txid = bytes([seed]) * 32
    db.add_utxo(prev_txid, 0, 100_000_000)  # 1 BTC funding
    inputs = [
        TxIn(
            prev_txid=prev_txid,
            prev_vout=0,
            script_sig=b"\x51",  # OP_TRUE
            sequence=0xFFFFFFFF,
            witness=([b"\x51"] if with_witness else None),
        )
    ]
    outputs = [TxOut(value=99_990_000, script_pubkey=b"\x76\xa9")]
    tx = Transaction(
        txid=bytes(32),
        version=2,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=with_witness,
    )
    body = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(body).digest()).digest()
    return tx


def _read_compact_size(buf: bytes, offset: int) -> tuple[int, int]:
    first = buf[offset]
    offset += 1
    if first < 253:
        return first, offset
    if first == 253:
        return struct.unpack_from("<H", buf, offset)[0], offset + 2
    if first == 254:
        return struct.unpack_from("<I", buf, offset)[0], offset + 4
    return struct.unpack_from("<Q", buf, offset)[0], offset + 8


def _parse_core_format(blob: bytes) -> dict:
    """Standalone golden parser — does NOT use Mempool internals."""
    out: dict = {}
    version = struct.unpack_from("<Q", blob, 0)[0]
    out["version"] = version
    offset = 8
    if version == 2:
        klen, offset = _read_compact_size(blob, offset)
        assert klen == 8
        xor_key = blob[offset:offset + 8]
        offset += 8
    else:
        xor_key = b""

    body = bytearray(blob[offset:])
    if xor_key:
        for i in range(len(body)):
            body[i] ^= xor_key[i % 8]
    body = bytes(body)

    tx_count = struct.unpack_from("<Q", body, 0)[0]
    out["tx_count"] = tx_count
    out["xor_key"] = xor_key
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestCoreFormatHeader(unittest.TestCase):
    """Bytes-on-disk should match Core's version-2 layout."""

    def setUp(self) -> None:
        self.db = _StubDB()
        self.mp = Mempool(
            _AlwaysOkValidator(self.db), require_standard=False
        )
        # Two test txs
        self.tx_a = _make_tx(1, self.db)
        self.tx_b = _make_tx(2, self.db, with_witness=True)
        ok_a, _ = self.mp.add_transaction(self.tx_a, height=100)
        ok_b, _ = self.mp.add_transaction(self.tx_b, height=100)
        self.assertTrue(ok_a)
        self.assertTrue(ok_b)

    def test_v2_header_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mempool.dat")
            n = self.mp.dump_to_file(path, use_xor=True)
            self.assertEqual(n, 2)
            with open(path, "rb") as f:
                blob = f.read()
            parsed = _parse_core_format(blob)
            self.assertEqual(parsed["version"], 2)
            self.assertEqual(len(parsed["xor_key"]), 8)
            self.assertEqual(parsed["tx_count"], 2)

    def test_v1_no_xor_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mempool.dat")
            n = self.mp.dump_to_file(path, use_xor=False)
            self.assertEqual(n, 2)
            with open(path, "rb") as f:
                blob = f.read()
            parsed = _parse_core_format(blob)
            self.assertEqual(parsed["version"], 1)
            self.assertEqual(parsed["xor_key"], b"")
            self.assertEqual(parsed["tx_count"], 2)

    def test_empty_pool_removes_stale_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mempool.dat")
            # Pre-populate a stale file
            with open(path, "wb") as f:
                f.write(b"stale")
            empty = Mempool(
                _AlwaysOkValidator(_StubDB()), require_standard=False
            )
            empty.dump_to_file(path)
            self.assertFalse(os.path.exists(path))


class TestCoreFormatRoundTrip(unittest.TestCase):
    """Dump → load must preserve transaction set and metadata."""

    def _roundtrip(self, *, use_xor: bool) -> None:
        db = _StubDB()
        mp = Mempool(_AlwaysOkValidator(db), require_standard=False)
        txs = [_make_tx(i, db, with_witness=(i % 2 == 0)) for i in range(1, 4)]
        for tx in txs:
            ok, _ = mp.add_transaction(tx, height=100)
            self.assertTrue(ok)
        # Pin a specific time_added so we can verify it survives the
        # int64-truncation roundtrip.
        for txid in mp.transactions:
            mp.transactions[txid].time_added = 1_700_000_000.0  # int64-safe

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mempool.dat")
            n = mp.dump_to_file(path, use_xor=use_xor)
            self.assertEqual(n, len(txs))

            # Reload — note ouroboros computes UTXO availability against the
            # DB in add_transaction, so we share the DB with mp2.
            mp2 = Mempool(_AlwaysOkValidator(db), require_standard=False)
            loaded = mp2.load_from_file(path, height=100)
            self.assertEqual(loaded, len(txs))
            self.assertEqual(set(mp2.transactions.keys()),
                             set(mp.transactions.keys()))
            # time_added should round-trip through int64 seconds
            for entry in mp2.transactions.values():
                self.assertAlmostEqual(entry.time_added, 1_700_000_000.0,
                                       delta=1.0)

    def test_v2_roundtrip(self) -> None:
        self._roundtrip(use_xor=True)

    def test_v1_roundtrip(self) -> None:
        self._roundtrip(use_xor=False)


class TestObfuscation(unittest.TestCase):
    """Direct unit tests for the XOR-obfuscation helper."""

    def test_xor_is_symmetric(self) -> None:
        key = bytes(range(8))
        payload = bytearray(b"hello world this is mempool data" * 5)
        original = bytes(payload)
        Mempool._xor_obfuscate(payload, key)
        self.assertNotEqual(bytes(payload), original)
        Mempool._xor_obfuscate(payload, key)
        self.assertEqual(bytes(payload), original)

    def test_xor_zero_key_is_noop(self) -> None:
        payload = bytearray(b"bytes")
        original = bytes(payload)
        Mempool._xor_obfuscate(payload, bytes(8))  # all zeros
        self.assertEqual(bytes(payload), original)


class TestLegacyMigration(unittest.TestCase):
    """The pre-Core ouroboros dump format is read once and discarded."""

    def test_legacy_v1_byte_format_loads(self) -> None:
        # Build a legacy dump by hand: <B 1, <I count, repeat[<I tx_len>, raw,
        # <q fee>, <d time>].  This matches the pre-2026-04-29 ouroboros
        # format that older nodes may have on disk.
        db = _StubDB()
        tx = _make_tx(7, db)
        raw = tx.serialize_with_witness()

        body = bytearray()
        body.extend(struct.pack("<B", 1))     # version=1
        body.extend(struct.pack("<I", 1))     # count=1
        body.extend(struct.pack("<I", len(raw)))
        body.extend(raw)
        body.extend(struct.pack("<q", 1234))   # fee
        body.extend(struct.pack("<d", 1700.0))  # time_added

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mempool.dat")
            with open(path, "wb") as f:
                f.write(bytes(body))

            mp = Mempool(_AlwaysOkValidator(db), require_standard=False)
            loaded = mp.load_from_file(path, height=100)
            self.assertEqual(loaded, 1)
            self.assertIn(tx.get_txid(), mp.transactions)
            # File should be deleted post-load to force a Core-format rewrite
            self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
