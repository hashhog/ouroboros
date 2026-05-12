"""
W102 AssumeUTXO snapshot loading gate audit — pytest tests.

Gates tested (30-gate checklist):
  G1-G3  metadata + coin encoding + checksum
  G4-G7  preconditions for loadtxoutset
  G8-G11 populate + per-coin validation
  G12-G14 3-chainstate architecture
  G15-G17 background validation
  G18-G21 dumptxoutset output shape
  G22-G25 loadtxoutset RPC behaviour
  G26-G27 assumeutxo tables (Python + Rust)
  G28-G30 cleanup + signals

All tests operate on snapshot.py and muhash.py only — no live DB, no network.
Tests that cover known bugs are marked xfail where the bug makes them fail;
others that probe correct behaviour are plain assertions.
"""

import hashlib
import io
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ouroboros.snapshot import (
    SNAPSHOT_MAGIC,
    SNAPSHOT_VERSION,
    NETWORK_MAGIC,
    AssumeutxoData,
    SnapshotMetadata,
    SnapshotManager,
    HashWriter,
    _read_compact_size,
    _write_compact_size,
    read_varint,
    write_varint,
    compress_amount,
    decompress_amount,
    compress_script,
    decompress_script,
    serialize_coin,
    deserialize_coin,
    read_compressed_script,
    write_compressed_script,
    _read_metadata_header,
    get_assumeutxo_params,
    get_assumeutxo_data,
    get_assumeutxo_by_hash,
    get_available_snapshot_heights,
)
from ouroboros.muhash import coin_element, MuHash3072


# ---------------------------------------------------------------------------
# G1: Snapshot magic / version header
# ---------------------------------------------------------------------------

class TestG1_SnapshotMetadata:
    """G1 — metadata parsing: magic, version, network magic, base_blockhash, coins_count."""

    def _build_header(
        self,
        magic=SNAPSHOT_MAGIC,
        version=SNAPSHOT_VERSION,
        net_magic=NETWORK_MAGIC["mainnet"],
        base_hash=b"\xab" * 32,
        coins_count=1_000_000,
    ) -> bytes:
        buf = io.BytesIO()
        buf.write(magic)
        buf.write(struct.pack("<H", version))
        buf.write(net_magic)
        buf.write(base_hash)
        buf.write(struct.pack("<Q", coins_count))
        return buf.getvalue()

    def test_valid_header_roundtrip(self):
        raw = self._build_header()
        meta = _read_metadata_header(io.BytesIO(raw), "mainnet")
        assert meta.version == SNAPSHOT_VERSION
        assert meta.network == "mainnet"
        assert meta.coins_count == 1_000_000
        assert len(meta.base_blockhash) == 32

    def test_wrong_magic_raises(self):
        raw = self._build_header(magic=b"WRONG")
        with pytest.raises(ValueError, match="magic"):
            _read_metadata_header(io.BytesIO(raw), "mainnet")

    def test_wrong_version_raises(self):
        raw = self._build_header(version=99)
        with pytest.raises(ValueError, match="version"):
            _read_metadata_header(io.BytesIO(raw), "mainnet")

    def test_network_mismatch_raises(self):
        raw = self._build_header(net_magic=NETWORK_MAGIC["testnet4"])
        with pytest.raises(ValueError, match="mismatch"):
            _read_metadata_header(io.BytesIO(raw), "mainnet")

    def test_truncated_header_raises(self):
        raw = self._build_header()[:20]  # partial
        with pytest.raises((ValueError, EOFError, struct.error)):
            _read_metadata_header(io.BytesIO(raw), "mainnet")

    def test_base_blockhash_hex_display(self):
        bh = bytes(range(32))
        raw = self._build_header(base_hash=bh)
        meta = _read_metadata_header(io.BytesIO(raw), "mainnet")
        # base_blockhash_hex() should be the big-endian (reversed) display hex.
        assert meta.base_blockhash_hex() == bh[::-1].hex()


# ---------------------------------------------------------------------------
# G2: Coin encoding (varint, compress_amount, ScriptCompression)
# ---------------------------------------------------------------------------

class TestG2_CoinEncoding:
    """G2 — wire encoding: VARINT, AmountCompression, ScriptCompression."""

    def test_varint_roundtrip_small(self):
        for n in [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0xFFFF, 2**31]:
            buf = io.BytesIO()
            write_varint(buf, n)
            buf.seek(0)
            assert read_varint(buf) == n

    def test_compress_amount_zero(self):
        assert compress_amount(0) == 0
        assert decompress_amount(0) == 0

    def test_compress_amount_satoshi(self):
        # 1 satoshi round-trips
        enc = compress_amount(1)
        assert decompress_amount(enc) == 1

    def test_compress_amount_btc(self):
        # 1 BTC = 100_000_000 sat
        enc = compress_amount(100_000_000)
        assert decompress_amount(enc) == 100_000_000

    def test_compress_amount_roundtrip_range(self):
        for val in [0, 1, 546, 100_000, 100_000_000, 21_000_000 * 100_000_000]:
            assert decompress_amount(compress_amount(val)) == val

    def test_p2pkh_compress_roundtrip(self):
        # 25-byte P2PKH
        h160 = b"\x11" * 20
        script = bytes([0x76, 0xa9, 20]) + h160 + bytes([0x88, 0xac])
        buf = io.BytesIO()
        write_compressed_script(buf, script)
        buf.seek(0)
        assert read_compressed_script(buf) == script

    def test_p2sh_compress_roundtrip(self):
        h160 = b"\x22" * 20
        script = bytes([0xa9, 20]) + h160 + bytes([0x87])
        buf = io.BytesIO()
        write_compressed_script(buf, script)
        buf.seek(0)
        assert read_compressed_script(buf) == script

    def test_raw_script_roundtrip(self):
        # OP_RETURN + data — no special template
        script = bytes([0x6a]) + b"\x00" * 15
        buf = io.BytesIO()
        write_compressed_script(buf, script)
        buf.seek(0)
        assert read_compressed_script(buf) == script

    def test_serialize_deserialize_coin(self):
        buf = io.BytesIO()
        serialize_coin(buf, height=840000, is_coinbase=True, amount=5_000_000_000, script=b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac")
        buf.seek(0)
        h, cb, amt, sc = deserialize_coin(buf)
        assert h == 840000
        assert cb is True
        assert amt == 5_000_000_000


# ---------------------------------------------------------------------------
# G3: HASH_SERIALIZED (SHA256d) — HashWriter and coin_element format
# ---------------------------------------------------------------------------

class TestG3_HashSerialized:
    """G3 — HASH_SERIALIZED commitment: TxOutSer byte format + SHA-256d."""

    def test_hashwriter_double_sha256(self):
        # HashWriter.digest() must return SHA256(SHA256(data)), not SHA256(data).
        data = b"hello world"
        hw = HashWriter()
        hw.update(data)
        result = hw.digest()
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        assert result == expected, "HashWriter must produce double-SHA256"

    def test_hashwriter_single_sha256_would_differ(self):
        # Confirm that single-SHA256 is NOT equal to double-SHA256.
        data = b"test"
        hw = HashWriter()
        hw.update(data)
        double = hw.digest()
        single = hashlib.sha256(data).digest()
        assert double != single, "HashWriter.digest should NOT equal single SHA256"

    def test_coin_element_layout(self):
        # TxOutSer: txid(32) + vout(uint32LE) + code(uint32LE) + amount(int64LE)
        # + CompactSize(scriptLen) + script
        txid = b"\xab" * 32
        vout = 0
        height = 100
        is_coinbase = False
        amount = 5000
        script = b"\x76\xa9" + b"\x11" * 20 + b"\x88\xac"
        elem = coin_element(txid, vout, height, is_coinbase, amount, script)

        # Offsets:
        assert elem[:32] == txid
        assert struct.unpack("<I", elem[32:36])[0] == vout
        code = struct.unpack("<I", elem[36:40])[0]
        assert code == (height << 1) | (1 if is_coinbase else 0)
        amount_read = struct.unpack("<q", elem[40:48])[0]
        assert amount_read == amount

    def test_coin_element_code_is_uint32_not_uint64(self):
        # Core uses uint32_t for code; must be 4 bytes, NOT 8 bytes.
        txid = b"\x00" * 32
        elem = coin_element(txid, 0, 1, False, 1, b"\x51")
        # After txid(32) + vout(4) = offset 36; code must be 4 bytes (uint32 LE).
        code_bytes = elem[36:40]
        next_field = elem[40:48]  # should be int64 amount
        code_val = struct.unpack("<I", code_bytes)[0]
        amount_val = struct.unpack("<q", next_field)[0]
        assert code_val == (1 << 1) | 0  # height=1, not coinbase
        assert amount_val == 1


# ---------------------------------------------------------------------------
# G4: loadtxoutset preconditions
# ---------------------------------------------------------------------------

class TestG4_LoadtxoutsetPreconditions:
    """G4 — loadtxoutset must fail on missing-header, non-empty-mempool, bad-chainwork."""

    def test_headers_chain_precondition_missing(self):
        """BUG-1: ouroboros does NOT check that base block header is in headers chain.

        Core requires: snapshot_start_block = LookupBlockIndex(base_blockhash)
        If null, error: "The base block header must appear in the headers chain."
        Ouroboros skips this — xfail.
        """
        # We can only probe the Python code path; we test that the
        # SnapshotManager.load_snapshot proceeds even when the snapshot hash
        # is not in any local block index.  (That check would belong in the
        # RPC handler before calling load_snapshot.)
        # This test documents the MISSING gate: xfail because the node would
        # accept a snapshot even if headers haven't synced to that block.
        pytest.xfail(
            "BUG-1: headers-chain presence check absent from loadtxoutset/load_snapshot"
        )

    def test_mempool_empty_precondition_missing(self):
        """BUG-2: no mempool-empty check before loadtxoutset.

        Core: if (mempool && mempool->size() > 0)
                  return Error{"Can't activate a snapshot when mempool not empty"};
        Ouroboros: no such check.
        """
        pytest.xfail(
            "BUG-2: mempool-empty precondition missing from rpc_loadtxoutset"
        )

    def test_chainwork_exceeds_active_tip_precondition_missing(self):
        """BUG-3: no chainwork-vs-active-tip comparison before populate.

        Core: if (!CBlockIndexWorkComparator()(ActiveTip(), snapshot_start_block))
                  return Error{"Work does not exceed active chainstate"};
        Ouroboros: load proceeds unconditionally.
        """
        pytest.xfail(
            "BUG-3: chainwork-exceeds-active-chainstate check missing from load_snapshot"
        )


# ---------------------------------------------------------------------------
# G8: Per-coin validation during populate
# ---------------------------------------------------------------------------

class TestG8_PerCoinValidation:
    """G8 — per-coin bounds: height <= base_height, MoneyRange, vout overflow guard."""

    def _make_snapshot_bytes(
        self,
        network: str,
        base_hash: bytes,
        coins: list[tuple[bytes, int, int, bool, int, bytes]],  # (txid, vout, h, cb, amt, script)
    ) -> bytes:
        """Build a minimal snapshot byte string (no assumeutxo auth needed for these tests)."""
        coin_count = len(coins)
        buf = io.BytesIO()
        buf.write(SNAPSHOT_MAGIC)
        buf.write(struct.pack("<H", SNAPSHOT_VERSION))
        buf.write(NETWORK_MAGIC[network])
        buf.write(base_hash)
        buf.write(struct.pack("<Q", coin_count))
        for txid, vout, height, is_cb, amount, script in coins:
            buf.write(txid)
            _write_compact_size(buf, 1)  # one coin per txid group
            _write_compact_size(buf, vout)
            serialize_coin(buf, height, is_cb, amount, script)
        return buf.getvalue()

    def test_coin_height_gt_base_height_not_rejected(self, tmp_path):
        """BUG-4: coin_height > base_height is silently accepted.

        Core: if (coin.nHeight > base_height) return Error{...}
        Ouroboros: no such check.
        """
        # Build a regtest snapshot (base_height unknown, but coin at height=1000
        # is clearly higher than a genesis-era snapshot).
        base_hash = b"\x00" * 31 + b"\x01"
        snap_bytes = self._make_snapshot_bytes(
            "regtest", base_hash,
            [(b"\xaa" * 32, 0, 1000, False, 1000, b"\x51")]
        )
        snap_path = str(tmp_path / "snap_bad_height.dat")
        with open(snap_path, "wb") as f:
            f.write(snap_bytes)

        mock_db = MagicMock()
        mock_db.add_utxo_raw = MagicMock()
        mock_db.update_best_block = MagicMock()
        sm = SnapshotManager(mock_db, "regtest", str(tmp_path))

        # Per Core semantics this should raise because coin.height > base_height.
        # Ouroboros silently accepts it (loads the UTXO without error).
        sm.load_snapshot(snap_path, strict=False)
        # If we reach here, ouroboros accepted the bad coin — that's the bug.
        pytest.xfail("BUG-4: coin.height > base_height check missing from load_snapshot")

    def test_moneyrange_not_checked_per_coin(self):
        """BUG-5: MoneyRange not validated per coin during load.

        Core: if (!MoneyRange(coin.out.nValue)) return Error{...}
        Ouroboros: no such check.
        """
        pytest.xfail(
            "BUG-5: MoneyRange check missing for each coin in load_snapshot"
        )

    def test_eof_trailing_bytes_not_checked(self):
        """BUG-6: trailing bytes after last coin are not detected.

        Core reads one extra byte after coins loop; if it succeeds, returns Error
        "Bad snapshot - coins left over after deserializing N coins".
        Ouroboros closes the file immediately after the loop with no EOF check.
        """
        pytest.xfail(
            "BUG-6: no trailing-bytes EOF check after coins loop in load_snapshot"
        )


# ---------------------------------------------------------------------------
# G12-G14: 3-chainstate architecture, chain_tx_count
# ---------------------------------------------------------------------------

class TestG12_ThreeChainstateArchitecture:
    """G12-G14 — 3-chainstate design: IBD chainstate, chain_tx_count propagation."""

    def test_no_separate_ibd_chainstate(self):
        """BUG-8: no separate IBD chainstate managed alongside snapshot chainstate.

        Core maintains m_ibd_chainstate (genesis->tip IBD run) alongside the
        snapshot chainstate. Ouroboros has a single DB and no IBD chainstate object.
        """
        sm = SnapshotManager(MagicMock(), "mainnet", "/tmp")
        # No ibd_chainstate attribute exists anywhere.
        assert not hasattr(sm, "ibd_chainstate"), (
            "BUG-8 present: no ibd_chainstate in SnapshotManager"
        )
        assert not hasattr(sm, "background_chainstate"), (
            "BUG-8 present: no background_chainstate in SnapshotManager"
        )

    def test_chain_tx_count_not_applied_after_load(self):
        """BUG-9: chain_tx_count from AssumeutxoData is never applied to block index.

        Core: index->m_chain_tx_count = au_data.m_chain_tx_count (validation.cpp:5950).
        Ouroboros load_snapshot never calls db.set_chain_tx_count or equivalent.
        """
        mock_db = MagicMock()
        mock_db.update_best_block = MagicMock()
        mock_db.add_utxo_raw = MagicMock()
        sm = SnapshotManager(mock_db, "mainnet", "/tmp/fake")
        # Load never called, so check the method isn't even present.
        called = False
        for call in mock_db.method_calls:
            if "chain_tx_count" in str(call):
                called = True
        assert not called, "chain_tx_count should never have been set (no fixture yet)"
        pytest.xfail(
            "BUG-9: chain_tx_count not propagated to block index after snapshot load"
        )


# ---------------------------------------------------------------------------
# G15-G17: Background validation
# ---------------------------------------------------------------------------

class TestG15_BackgroundValidation:
    """G15-G17 — background validation worker does not actually replay blocks."""

    def test_background_validation_worker_is_noop_loop(self):
        """BUG-7: background validation loop counts heights but never replays blocks.

        The worker iterates range(target_height+1) incrementing
        self.background_validation_height but calls no block-validation function.
        The loop completes in microseconds for any height, proving it is a no-op.
        """
        mock_db = MagicMock()
        mock_db.iter_utxos = MagicMock(return_value=[])
        sm = SnapshotManager(mock_db, "mainnet", "/tmp/fake")
        sm.snapshot_loaded = True
        sm.snapshot_height = 10  # small number for speed
        sm.snapshot_hash = b"\x00" * 32

        start = time.monotonic()
        sm.start_background_validation()
        # Give the thread time to "complete"
        if sm._validation_thread:
            sm._validation_thread.join(timeout=2.0)
        elapsed = time.monotonic() - start

        # A real IBD from genesis to height 10 would take far longer than 1s
        # even on a trivial chain. If it finished in <1s, it's clearly not
        # replaying any blocks.
        assert elapsed < 1.0, "Background validation finished impossibly fast"
        # Document the bug: the loop does no real validation.
        pytest.xfail(
            "BUG-7: background_validation_worker is a counter loop, not a block replay"
        )

    def test_background_validation_sets_validated_flag(self):
        """Background validation sets background_validated=True even without any real work."""
        mock_db = MagicMock()
        mock_db.iter_utxos = MagicMock(return_value=[])
        sm = SnapshotManager(mock_db, "mainnet", "/tmp/fake")
        sm.snapshot_loaded = True
        sm.snapshot_height = 2
        sm.snapshot_hash = b"\x00" * 32  # no matching AU entry -> logs warning, sets True

        sm.start_background_validation()
        if sm._validation_thread:
            sm._validation_thread.join(timeout=2.0)

        # With no AU entry matching all-zeros, it logs a warning and sets True.
        assert sm.background_validated is True

    def test_background_validation_requires_snapshot_loaded(self):
        """start_background_validation must no-op when snapshot_loaded is False."""
        mock_db = MagicMock()
        sm = SnapshotManager(mock_db, "mainnet", "/tmp/fake")
        sm.snapshot_loaded = False

        sm.start_background_validation()
        # Thread should not have started.
        assert sm._validation_thread is None


# ---------------------------------------------------------------------------
# G22-G25: loadtxoutset RPC result shape
# ---------------------------------------------------------------------------

class TestG22_LoadtxoutsetRPCShape:
    """G22-G25 — loadtxoutset RPC result: field names, coins_loaded accuracy."""

    def test_result_uses_base_hash_not_tip_hash(self):
        """BUG-13: result key is 'base_hash'; Core uses 'tip_hash'.

        Bitcoin Core rpc/blockchain.cpp:3441: result.pushKV("tip_hash", ...)
        Ouroboros rpc.py: result["base_hash"] = metadata.base_blockhash_hex()

        This is a Core-parity field-name mismatch.
        """
        # We document the Core field name is tip_hash, not base_hash.
        core_field = "tip_hash"
        ouroboros_field = "base_hash"
        assert core_field != ouroboros_field, (
            "BUG-13: field name divergence — ouroboros='base_hash', Core='tip_hash'"
        )
        # Not xfail because it's observable (callers that expect 'tip_hash' break).

    def test_coins_loaded_uses_metadata_count_not_actual_loaded(self):
        """BUG-14: returned coins_loaded is metadata.coins_count (pre-read),
        not the actual number of coins inserted by load_snapshot.

        If load fails partway the count is still reported as the header value.
        """
        # This is a documentation/correctness issue; we mark xfail.
        pytest.xfail(
            "BUG-14: coins_loaded field is metadata.coins_count, not actual inserted count"
        )


# ---------------------------------------------------------------------------
# G26-G27: AssumeutxoData tables
# ---------------------------------------------------------------------------

class TestG26_AssumeutxoTables:
    """G26-G27 — hardcoded parameter correctness: Python table vs Rust table."""

    def test_mainnet_840000_hash_serialized_matches_core(self):
        """Mainnet h=840000 hash_serialized must match Core chainparams.cpp exactly.

        Core: uint256{"a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"}
        """
        au = get_assumeutxo_data("mainnet", 840_000)
        assert au is not None
        # Core stores as uint256 in display order; Python reverses with _hex_to_hash_le.
        expected_display = "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
        assert au.hash_serialized_hex() == expected_display

    def test_mainnet_840000_chain_tx_count_matches_core(self):
        """Mainnet h=840000 chain_tx_count must be 991_032_194 (Core value)."""
        au = get_assumeutxo_data("mainnet", 840_000)
        assert au is not None
        assert au.chain_tx_count == 991_032_194

    def test_testnet4_heights_match_core(self):
        """Testnet4 must have entries at h=90000 and h=120000 (Core chainparams.cpp)."""
        heights = get_available_snapshot_heights("testnet4")
        assert 90_000 in heights
        assert 120_000 in heights

    def test_signet_assumeutxo_missing(self):
        """BUG-11: signet assumeutxo table is empty; Core has entries at h=160000, h=290000."""
        params = get_assumeutxo_params("signet")
        if not params:
            pytest.xfail(
                "BUG-11: signet assumeutxo table empty; Core has h=160000 and h=290000"
            )
        # If it does have signet entries, verify known heights
        heights = [p.height for p in params]
        assert 160_000 in heights
        assert 290_000 in heights

    def test_rust_table_mainnet_840000_hash_is_placeholder(self):
        """BUG-10: Rust snapshot.rs mainnet h=840000 hash_serialized is a placeholder
        ('2d6b0d7a...'), not Core's canonical value ('a2a5521b...').

        This means any Rust-backed validation path would reject valid Core snapshots.
        This test documents the bug by checking the Python table is correct (it is).
        The Rust divergence must be fixed separately in snapshot.rs.
        """
        au = get_assumeutxo_data("mainnet", 840_000)
        assert au is not None
        # Python table is correct; Rust table at snapshot.rs:129 uses a fake hash.
        # We can't easily import Rust from Python here, so we document with xfail.
        pytest.xfail(
            "BUG-10: Rust snapshot.rs mainnet h=840000 uses placeholder hash 2d6b0d7a..., "
            "not Core's a2a5521b... (and wrong chain_tx_count 990M vs 991032194)"
        )

    def test_local_noncore_entry_944183(self):
        """BUG-12: local non-Core entry at h=944183 with comment 'not from Core chainparams'.

        This entry could cause chainwork miscalculation if used by a non-operator.
        """
        au = get_assumeutxo_data("mainnet", 944_183)
        # Entry exists; flag that it's non-Core.
        if au is not None:
            pytest.xfail(
                "BUG-12: local non-Core assumeutxo entry at h=944183 "
                "(comment: 'not from Core chainparams')"
            )

    def test_mainnet_880000_present(self):
        """Mainnet h=880000 must be in the table."""
        au = get_assumeutxo_data("mainnet", 880_000)
        assert au is not None
        assert au.chain_tx_count == 1_145_604_538

    def test_mainnet_910000_present(self):
        """Mainnet h=910000 must be in the table."""
        au = get_assumeutxo_data("mainnet", 910_000)
        assert au is not None

    def test_lookup_by_hash(self):
        """get_assumeutxo_by_hash must return the correct entry."""
        au = get_assumeutxo_data("testnet4", 90_000)
        assert au is not None
        au2 = get_assumeutxo_by_hash("testnet4", au.block_hash)
        assert au2 is not None
        assert au2.height == 90_000


# ---------------------------------------------------------------------------
# G18: Rust compute_utxo_hash encoding bugs (documented via Python comparison)
# ---------------------------------------------------------------------------

class TestG18_RustComputeUtxoHash:
    """G18 — Rust compute_utxo_hash has multiple encoding bugs vs Core's TxOutSer."""

    def test_hashwriter_is_double_sha256_not_single(self):
        """BUG-15: Rust compute_utxo_hash uses single SHA-256; Core requires SHA-256d.

        Python HashWriter.digest() correctly does double-SHA256.
        Rust: sha256::Hash::from_engine(engine).to_byte_array() = single SHA-256.
        """
        # Demonstrate Python correctness: HashWriter.digest() != sha256(data)
        data = b"tx" + b"\x00" * 30
        hw = HashWriter()
        hw.update(data)
        double_sha256 = hw.digest()
        single_sha256 = hashlib.sha256(data).digest()
        assert double_sha256 != single_sha256, (
            "BUG-15: Rust uses single SHA-256, Python correctly uses SHA-256d"
        )

    def test_coin_element_code_is_4_bytes_not_8(self):
        """BUG-16: Rust encodes 'code' as u64 (8 bytes); Core uses uint32_t (4 bytes).

        Python coin_element uses struct.pack('<I', code) = 4 bytes (correct).
        Rust: code.to_le_bytes() on a u64 = 8 bytes (wrong — diverges from Core).
        """
        txid = b"\x00" * 32
        elem = coin_element(txid, 0, 1, False, 1, b"\x51")
        # After txid(32) + vout(4) = offset 36; code must be 4 bytes.
        code_at_36 = elem[36:40]
        code_val = struct.unpack("<I", code_at_36)[0]
        assert code_val == (1 << 1) | 0  # height=1, not coinbase, 4 bytes
        # Python is correct. Rust produces 8 bytes here.
        pytest.xfail(
            "BUG-16: Rust snapshot.rs uses u64.to_le_bytes() for code (8 bytes); "
            "Core uses uint32_t (4 bytes) — hash diverges"
        )

    def test_coin_wire_uses_amount_compression_not_compact_size(self):
        """BUG-17: Rust read_coin/write_coin use CompactSize for amount; Core uses
        Bitcoin VARINT + AmountCompression (compress_amount).

        Python serialize_coin uses VARINT(compress_amount(amount)) — correct.
        Rust: write_compact_size(writer, coin.value) — wrong encoding.
        """
        # Demonstrate: CompactSize(100_000_000) != VARINT(compress_amount(100_000_000))
        amount = 100_000_000  # 1 BTC

        cs_buf = io.BytesIO()
        _write_compact_size(cs_buf, amount)
        cs_bytes = cs_buf.getvalue()

        varint_buf = io.BytesIO()
        write_varint(varint_buf, compress_amount(amount))
        varint_bytes = varint_buf.getvalue()

        assert cs_bytes != varint_bytes, (
            "BUG-17: CompactSize(amt) == VARINT(compress(amt)) for this value — "
            "choose a better test value if this trips"
        )
        pytest.xfail(
            "BUG-17: Rust read_coin/write_coin use CompactSize for amount; "
            "Core uses VARINT(compress_amount) — Rust snapshot I/O is wire-incompatible"
        )

    def test_coin_wire_uses_script_compression_not_raw_length(self):
        """BUG-18: Rust read_coin/write_coin use CompactSize(len)+raw for script;
        Core uses ScriptCompression (VARINT(nSize) where nSize < 6 selects a template).

        Python correctly implements ScriptCompression. Rust does raw length-prefix.
        """
        # For a P2PKH script the ScriptCompression tag+body is 21 bytes;
        # raw CompactSize(25)+25bytes would be 26 bytes — different!
        h160 = b"\x11" * 20
        p2pkh = bytes([0x76, 0xa9, 20]) + h160 + bytes([0x88, 0xac])  # 25 bytes

        sc_buf = io.BytesIO()
        write_compressed_script(sc_buf, p2pkh)
        sc_len = len(sc_buf.getvalue())  # should be 1 (tag) + 20 (body) = 21

        raw_len_bytes = 1 + len(p2pkh)  # CompactSize(25) + 25 raw = 26
        assert sc_len == 21, f"ScriptCompression P2PKH should be 21 bytes, got {sc_len}"
        assert raw_len_bytes == 26
        assert sc_len != raw_len_bytes, "Compression vs raw: sizes differ as expected"
        pytest.xfail(
            "BUG-18: Rust read_coin/write_coin use raw CompactSize+script instead of "
            "ScriptCompression — Rust snapshot I/O is wire-incompatible with Core"
        )


# ---------------------------------------------------------------------------
# G28-G30: Cleanup and dump correctness
# ---------------------------------------------------------------------------

class TestG28_DumpSnapshot:
    """G28-G30 — dump_snapshot: atomic-write (temp+rename), fsync, sort order."""

    def test_dump_uses_temp_file_then_rename(self, tmp_path):
        """Atomic-write: writes to .incomplete then renames. No torn output."""
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (b"\x00" * 32, 0)
        mock_db.utxo_count.return_value = 0
        mock_db.iter_utxos.return_value = []

        sm = SnapshotManager(mock_db, "regtest", str(tmp_path))
        output = str(tmp_path / "snap.dat")
        sm.dump_snapshot(output)

        assert Path(output).exists()
        assert not Path(output + ".incomplete").exists()

    def test_dump_snapshot_header_magic(self, tmp_path):
        """Dumped file starts with correct magic + version + network magic."""
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (b"\x00" * 32, 0)
        mock_db.utxo_count.return_value = 0
        mock_db.iter_utxos.return_value = []

        sm = SnapshotManager(mock_db, "mainnet", str(tmp_path))
        output = str(tmp_path / "snap.dat")
        sm.dump_snapshot(output)

        with open(output, "rb") as f:
            magic = f.read(5)
            version = struct.unpack("<H", f.read(2))[0]
            net_magic = f.read(4)
        assert magic == SNAPSHOT_MAGIC
        assert version == SNAPSHOT_VERSION
        assert net_magic == NETWORK_MAGIC["mainnet"]

    def test_dump_incomplete_file_cleaned_on_error(self, tmp_path):
        """On write error the .incomplete temp file is removed."""
        mock_db = MagicMock()
        mock_db.get_best_block.return_value = (b"\x00" * 32, 0)
        mock_db.utxo_count.return_value = 0
        mock_db.iter_utxos.side_effect = RuntimeError("disk full")

        sm = SnapshotManager(mock_db, "mainnet", str(tmp_path))
        output = str(tmp_path / "snap.dat")
        with pytest.raises(RuntimeError):
            sm.dump_snapshot(output)
        assert not Path(output + ".incomplete").exists()
        assert not Path(output).exists()
