"""Tests for three Core-parity fixes:

  4F — coinstatsindex BIP30 duplicate-coinbase skip
       (coinstatsindex.py::add_block, heights 91722 / 91812).
  5B — dumptxoutset uncompressed-P2PK script compression
       (snapshot.py::compress_script, tag 0x04/0x05).
  4G — txindex must NOT be deleted on reorg disconnect
       (ferrous-utils/sync/src/storage/db.rs, validate/block.rs).

Reference:
  bitcoin-core/src/index/coinstatsindex.cpp:128-131  (BIP30 skip)
  bitcoin-core/src/compressor.cpp:78-80              (P2PK uncompressed tag)
  bitcoin-core/src/index/base.h:136                  (CustomRemove no-op)
  bitcoin-core/src/index/txindex.cpp                 (no CustomRemove)
"""

from __future__ import annotations

import io
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup + mock Rust extension so ouroboros imports work without a build.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# ===========================================================================
# Finding 4F — coinstatsindex BIP30 duplicate-coinbase skip
# ===========================================================================

# Internal byte order (LE) for the two BIP30 exception blocks.
_BIP30_H91722_LE = bytes.fromhex(
    "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
)[::-1]
_BIP30_H91812_LE = bytes.fromhex(
    "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
)[::-1]


def _make_block(hash_: bytes, txs: list) -> SimpleNamespace:
    """Build a minimal Block-like object for CoinStatsIndex.add_block."""
    block = SimpleNamespace()
    block.hash = hash_
    block.transactions = txs
    return block


def _make_coinbase_tx(amount: int = 5_000_000_000) -> SimpleNamespace:
    """Build a minimal coinbase transaction."""
    out = SimpleNamespace(
        script_pubkey=b"\x76\xa9\x14" + b"\xaa" * 20 + b"\x88\xac",  # P2PKH
        value=amount,
    )
    tx = SimpleNamespace(
        is_coinbase=True,
        txid=b"\x01" * 32,
        inputs=[],
        outputs=[out],
    )
    return tx


def _make_noncoinbase_tx(txid: bytes, amount: int = 1_000_000) -> SimpleNamespace:
    """Build a minimal non-coinbase transaction with one output."""
    out = SimpleNamespace(
        script_pubkey=b"\x76\xa9\x14" + b"\xbb" * 20 + b"\x88\xac",
        value=amount,
    )
    inp = SimpleNamespace(prev_txid=b"\x00" * 32, prev_vout=0)
    tx = SimpleNamespace(
        is_coinbase=False,
        txid=txid,
        inputs=[inp],
        outputs=[out],
    )
    return tx


class TestBip30Skip:
    """4F: coinstatsindex MUST skip the duplicate coinbase for BIP30 exception
    blocks, mirroring Bitcoin Core coinstatsindex.cpp:128-131."""

    def setup_method(self) -> None:
        from ouroboros.coinstatsindex import CoinStatsIndex
        import tempfile
        import os
        self._tmp = tempfile.mkdtemp()
        self.index = CoinStatsIndex(self._tmp, enabled=True)

    def test_helper_identifies_bip30_blocks(self) -> None:
        """_is_bip30_unspendable returns True only for the two exception blocks."""
        from ouroboros.coinstatsindex import _is_bip30_unspendable

        # Exact matches
        assert _is_bip30_unspendable(91722, _BIP30_H91722_LE)
        assert _is_bip30_unspendable(91812, _BIP30_H91812_LE)

        # Wrong height
        assert not _is_bip30_unspendable(91723, _BIP30_H91722_LE)
        assert not _is_bip30_unspendable(91811, _BIP30_H91812_LE)

        # Right height, wrong hash
        assert not _is_bip30_unspendable(91722, b"\xff" * 32)
        assert not _is_bip30_unspendable(91812, b"\xff" * 32)

        # Normal blocks
        assert not _is_bip30_unspendable(100, b"\x00" * 32)
        assert not _is_bip30_unspendable(0, b"\x00" * 32)

    def _add_normal_block(self, height: int, block_hash: bytes,
                          coinbase_amount: int = 5_000_000_000) -> None:
        """Add a normal (non-BIP30) block and return the snapshot."""
        cb = _make_coinbase_tx(coinbase_amount)
        block = _make_block(block_hash, [cb])
        self.index.add_block(block, height=height)

    def test_bip30_coinbase_not_applied_to_muhash_h91722(self) -> None:
        """At height 91722 with the BIP30 block hash, the coinbase outputs must
        NOT be applied to the MuHash / txout count / total_amount.

        Without the fix, add_block applies the coinbase outputs and txouts
        becomes 1; with the fix it stays 0 (the coinbase is skipped)."""
        # Add a predecessor at height 91721 (normal block).
        normal_hash = b"\xaa" * 32
        self._add_normal_block(91721, normal_hash, coinbase_amount=5_000_000_000)

        # Now add the BIP30 exception block at 91722.
        cb = _make_coinbase_tx(amount=5_000_000_000)
        block = _make_block(_BIP30_H91722_LE, [cb])
        self.index.add_block(block, height=91722)

        snap_91722 = self.index.get_at_height(91722)
        snap_91721 = self.index.get_at_height(91721)
        assert snap_91722 is not None
        assert snap_91721 is not None

        # The coinbase was skipped, so txouts / total_amount MUST equal the
        # predecessor's values (no change from 91721 → 91722).
        assert snap_91722["txouts"] == snap_91721["txouts"], (
            f"BIP30 coinbase was applied: txouts changed from "
            f"{snap_91721['txouts']} to {snap_91722['txouts']} "
            f"(expected no change)"
        )
        assert snap_91722["total_amount"] == snap_91721["total_amount"], (
            f"BIP30 coinbase was applied: total_amount changed"
        )
        # MuHash must also be unchanged (same serialisation).
        assert snap_91722["muhash"] == snap_91721["muhash"], (
            "BIP30 coinbase was inserted into MuHash"
        )

    def test_bip30_coinbase_not_applied_to_muhash_h91812(self) -> None:
        """Same test for height 91812."""
        normal_hash = b"\xbb" * 32
        self._add_normal_block(91811, normal_hash, coinbase_amount=5_000_000_000)

        cb = _make_coinbase_tx(amount=5_000_000_000)
        block = _make_block(_BIP30_H91812_LE, [cb])
        self.index.add_block(block, height=91812)

        snap_91812 = self.index.get_at_height(91812)
        snap_91811 = self.index.get_at_height(91811)
        assert snap_91812 is not None
        assert snap_91811 is not None

        assert snap_91812["txouts"] == snap_91811["txouts"], (
            "BIP30 coinbase at 91812 was applied to txouts"
        )
        assert snap_91812["total_amount"] == snap_91811["total_amount"], (
            "BIP30 coinbase at 91812 was applied to total_amount"
        )
        assert snap_91812["muhash"] == snap_91811["muhash"], (
            "BIP30 coinbase at 91812 was inserted into MuHash"
        )

    def test_non_bip30_coinbase_is_applied(self) -> None:
        """Sanity: a normal coinbase (not a BIP30 exception) IS applied."""
        self._add_normal_block(1, b"\xcc" * 32, coinbase_amount=5_000_000_000)

        # Height 0 is always empty (genesis skipped).
        snap_0 = self.index.get_at_height(0)
        snap_1 = self.index.get_at_height(1)

        # Genesis block is skipped entirely; height 1 has one P2PKH output.
        assert snap_1 is not None
        assert snap_1["txouts"] == 1, (
            f"Normal coinbase at height 1 not applied; txouts={snap_1['txouts']}"
        )

    def test_wrong_hash_at_bip30_height_is_applied(self) -> None:
        """A block at height 91722 with the WRONG hash is NOT a BIP30 exception
        and its coinbase IS applied normally (fork block at same height)."""
        wrong_hash = b"\xdd" * 32  # not the BIP30 exception hash
        self._add_normal_block(91721, b"\xee" * 32, coinbase_amount=5_000_000_000)

        cb = _make_coinbase_tx(amount=5_000_000_000)
        block = _make_block(wrong_hash, [cb])
        self.index.add_block(block, height=91722)

        snap = self.index.get_at_height(91722)
        prev_snap = self.index.get_at_height(91721)
        assert snap is not None
        assert prev_snap is not None

        # Coinbase IS applied, so txouts increases.
        assert snap["txouts"] == prev_snap["txouts"] + 1, (
            "Fork-block coinbase at BIP30 height should be applied "
            f"(expected txouts={prev_snap['txouts'] + 1}, "
            f"got {snap['txouts']})"
        )


# ===========================================================================
# Finding 5B — compress_script for uncompressed P2PK (tag 0x04/0x05)
# ===========================================================================

# secp256k1 generator point (G) — standard test vector.
# Uncompressed pubkey: 0x04 || X32 || Y32
_Gx = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_Gy = bytes.fromhex(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
_G_UNCOMPRESSED = b"\x04" + _Gx + _Gy  # 65 bytes

# 67-byte P2PK script: 0x41 <65-byte pubkey> 0xac (OP_CHECKSIG)
_OP_CHECKSIG = 0xAC
_P2PK_UNCOMPRESSED_SCRIPT = bytes([65]) + _G_UNCOMPRESSED + bytes([_OP_CHECKSIG])


class TestCompressScriptUncompressedP2PK:
    """5B: compress_script must encode 67-byte uncompressed P2PK as tag
    0x04|(Y_lsb) || X[32], matching Bitcoin Core compressor.cpp:78-80."""

    def test_compress_uncompressed_p2pk_even_y(self) -> None:
        """Y has LSB 0 (even) → tag 0x04, body = X coordinate (32 bytes)."""
        from ouroboros.snapshot import compress_script

        result = compress_script(_P2PK_UNCOMPRESSED_SCRIPT)

        # _Gy ends in 0xb8 → LSB = 0 (even).
        y_lsb = _Gy[-1] & 0x01
        assert y_lsb == 0, "test pre-condition: G has even Y"

        assert result is not None, (
            "compress_script returned None for 67-byte uncompressed P2PK; "
            "expected tag 0x04 + X[32]"
        )
        assert len(result) == 33, f"Expected 33 bytes (tag+X), got {len(result)}"
        assert result[0] == 0x04, (
            f"Expected tag 0x04 (even Y), got {result[0]:#04x}"
        )
        assert result[1:] == _Gx, "Body must be the 32-byte X coordinate"

    def test_compress_uncompressed_p2pk_odd_y(self) -> None:
        """Y has LSB 1 (odd) → tag 0x05, body = X coordinate (32 bytes)."""
        from ouroboros.snapshot import compress_script

        # secp256k1 point with odd Y: negate G → (Gx, p - Gy).
        # p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        gy_int = int.from_bytes(_Gy, "big")
        neg_gy = (p - gy_int) % p
        neg_Gy_bytes = neg_gy.to_bytes(32, "big")
        assert neg_Gy_bytes[-1] & 1 == 1, "test pre-condition: negated G has odd Y"

        pubkey65_odd = b"\x04" + _Gx + neg_Gy_bytes
        script_odd = bytes([65]) + pubkey65_odd + bytes([_OP_CHECKSIG])
        result = compress_script(script_odd)

        assert result is not None, (
            "compress_script returned None for odd-Y uncompressed P2PK"
        )
        assert result[0] == 0x05, (
            f"Expected tag 0x05 (odd Y), got {result[0]:#04x}"
        )
        assert result[1:] == _Gx, "Body must be the 32-byte X coordinate"

    def test_compress_uncompressed_p2pk_roundtrip(self) -> None:
        """Compressed form must decompress back to the original 67-byte script."""
        from ouroboros.snapshot import compress_script, decompress_script

        compressed = compress_script(_P2PK_UNCOMPRESSED_SCRIPT)
        assert compressed is not None

        tag = compressed[0]
        body = compressed[1:]
        recovered = decompress_script(tag, body)

        assert recovered == _P2PK_UNCOMPRESSED_SCRIPT, (
            f"Round-trip failed:\n"
            f"  original:  {_P2PK_UNCOMPRESSED_SCRIPT.hex()}\n"
            f"  recovered: {recovered.hex()}"
        )

    def test_compress_p2pk_compressed_unchanged(self) -> None:
        """Sanity: compressed-key P2PK still uses tag 0x02/0x03 (no regression)."""
        from ouroboros.snapshot import compress_script

        # 35-byte P2PK with compressed key (0x02 prefix).
        compressed_pubkey = bytes([0x02]) + _Gx  # 33 bytes
        script = bytes([33]) + compressed_pubkey + bytes([_OP_CHECKSIG])
        result = compress_script(script)

        assert result is not None
        assert result[0] in (0x02, 0x03), (
            f"Compressed-key P2PK tag should be 0x02 or 0x03, got {result[0]:#04x}"
        )

    def test_compress_off_curve_pubkey_falls_through(self) -> None:
        """An off-curve uncompressed pubkey must NOT emit tag 0x04/0x05;
        it must fall through to None (raw fallback) to avoid a crash or
        invalid snapshot entry."""
        from ouroboros.snapshot import compress_script

        bad_x = b"\x00" * 32  # x=0 is not on the secp256k1 curve
        bad_y = b"\x00" * 32
        bad_pub = b"\x04" + bad_x + bad_y
        bad_script = bytes([65]) + bad_pub + bytes([_OP_CHECKSIG])

        result = compress_script(bad_script)
        # Off-curve → must fall through (None), matching Core's
        # pubkey.IsFullyValid() guard (compressor.cpp:50).
        assert result is None, (
            f"Off-curve pubkey should not be compressed (got {result!r})"
        )

    def test_write_compressed_script_encodes_uncompressed_p2pk(self) -> None:
        """write_compressed_script must emit a special (tag+body) encoding
        for uncompressed P2PK, not the raw (len+6) fallback."""
        from ouroboros.snapshot import write_compressed_script

        buf = io.BytesIO()
        write_compressed_script(buf, _P2PK_UNCOMPRESSED_SCRIPT)
        data = buf.getvalue()

        # Special encoding: VARINT(tag) where tag < 6, followed by 32-byte body.
        # Total = 1 (tag varint) + 32 (X) = 33 bytes.
        # Raw fallback would be VARINT(67+6=73) + 67 bytes = 68 bytes.
        assert len(data) == 33, (
            f"Expected 33-byte compressed encoding, got {len(data)} bytes "
            f"(raw fallback = 68 bytes)"
        )
        assert data[0] in (0x04, 0x05), (
            f"First byte (varint tag) expected 0x04 or 0x05, got {data[0]:#04x}"
        )


# ===========================================================================
# Finding 4G — txindex must NOT be deleted on reorg disconnect (Rust sources)
# ===========================================================================

class TestTxIndexNotDeletedOnDisconnect:
    """4G: Bitcoin Core's TxIndex has no CustomRemove (base.h:136 no-op).
    txindex entries must survive reorgs — getrawtransaction should still
    resolve txs from disconnected blocks."""

    def test_db_rs_disconnect_does_not_delete_txindex(self) -> None:
        """db.rs::disconnect_block_at_height_checked must NOT call
        delete_tx_index_batch for the per-block disconnect path."""
        db = _read_rust("sync/src/storage/db.rs")
        if not db:
            pytest.skip("ferrous-utils/sync/src/storage/db.rs not present")

        assert "self.delete_tx_index(txid.as_byte_array())" not in db, (
            "FAIL 4G: per-block disconnect path calls delete_tx_index — "
            "Core TxIndex keeps entries across reorgs (base.h:136 no-op)."
        )
        assert "batch.delete_cf(tx_index_cf, txid.as_byte_array())" not in db, (
            "FAIL 4G: atomic disconnect batch deletes txindex entries — "
            "Core TxIndex keeps entries across reorgs (base.h:136 no-op)."
        )

    def test_block_rs_disconnect_does_not_delete_txindex(self) -> None:
        """validate/block.rs::disconnect_block must NOT call delete_tx_index."""
        block_rs = _read_rust("sync/src/validate/block.rs")
        if not block_rs:
            pytest.skip("ferrous-utils/sync/src/validate/block.rs not present")

        assert "self.db.delete_tx_index(txid.as_byte_array())" not in block_rs, (
            "FAIL 4G: validate/block.rs::disconnect_block deletes txindex "
            "entries — Core TxIndex keeps entries across reorgs (base.h:136)."
        )

    def test_txindex_write_is_still_present_on_connect(self) -> None:
        """Sanity: the txindex WRITE path (block connect) must still be present.
        Removing deletes must not accidentally remove the write path."""
        db = _read_rust("sync/src/storage/db.rs")
        if not db:
            pytest.skip("ferrous-utils/sync/src/storage/db.rs not present")

        # store_tx_index_batch must still be called during block connect.
        assert "self.db.store_tx_index_batch" in db or "store_tx_index_batch" in db, (
            "REGRESSION: store_tx_index_batch missing from db.rs — "
            "txindex is no longer written on block connect."
        )
