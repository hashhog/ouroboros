"""
Unit tests for `ouroboros.snapshot` -- Bitcoin Core `dumptxoutset` /
`loadtxoutset` (v2) wire-format primitives + the SnapshotManager driver.

The goal of this file is byte-for-byte parity with Core's reference
encoding. Where we have published Core test vectors (CompressAmount round
trip, specific VARINT outputs from the comment block in serialize.h, the
ScriptCompression special-case templates) we exercise them directly.

These tests do not require the Rust `sync` extension -- the mock in
`conftest.py` is enough for the format-level checks. The SnapshotManager
end-to-end test uses a tiny in-memory DB stub instead.
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
from dataclasses import dataclass

import pytest

from ouroboros import snapshot
from ouroboros.snapshot import (
    NETWORK_MAGIC,
    SNAPSHOT_MAGIC,
    SNAPSHOT_VERSION,
    SnapshotManager,
    SnapshotMetadata,
    compress_amount,
    compress_script,
    decompress_amount,
    decompress_script,
    deserialize_coin,
    get_assumeutxo_data,
    get_assumeutxo_params,
    read_compressed_script,
    read_snapshot_metadata,
    read_varint,
    serialize_coin,
    write_compressed_script,
    write_varint,
    _read_compact_size,
    _write_compact_size,
)


# ---------------------------------------------------------------------------
# CompactSize round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "n, expected_bytes",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (252, b"\xfc"),
        (253, b"\xfd\xfd\x00"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0x10000, b"\xfe\x00\x00\x01\x00"),
        (0xFFFFFFFF, b"\xfe\xff\xff\xff\xff"),
        (0x1_0000_0000, b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"),
    ],
)
def test_compact_size_roundtrip(n: int, expected_bytes: bytes) -> None:
    buf = io.BytesIO()
    _write_compact_size(buf, n)
    assert buf.getvalue() == expected_bytes
    buf.seek(0)
    assert _read_compact_size(buf) == n


# ---------------------------------------------------------------------------
# VARINT round-trip -- vectors from comment block in
# bitcoin-core/src/serialize.h
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "n, expected_bytes",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (127, b"\x7f"),
        (128, b"\x80\x00"),
        (255, b"\x80\x7f"),
        (256, b"\x81\x00"),
        (16383, b"\xfe\x7f"),
        (16384, b"\xff\x00"),
        (16511, b"\xff\x7f"),
        (65535, b"\x82\xfe\x7f"),
        (1 << 32, b"\x8e\xfe\xfe\xff\x00"),
    ],
)
def test_varint_roundtrip_known_vectors(n: int, expected_bytes: bytes) -> None:
    buf = io.BytesIO()
    write_varint(buf, n)
    assert buf.getvalue() == expected_bytes, (
        f"VARINT({n}) -> {buf.getvalue().hex()}, expected {expected_bytes.hex()}"
    )
    buf.seek(0)
    assert read_varint(buf) == n


def test_varint_round_trip_random() -> None:
    import random

    rng = random.Random(0xC0FFEE)
    for _ in range(200):
        n = rng.randrange(0, 1 << 60)
        buf = io.BytesIO()
        write_varint(buf, n)
        buf.seek(0)
        assert read_varint(buf) == n


def test_varint_negative_rejected() -> None:
    buf = io.BytesIO()
    with pytest.raises(ValueError):
        write_varint(buf, -1)


# ---------------------------------------------------------------------------
# CompressAmount / DecompressAmount -- Core-defined cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, compressed",
    [
        (0, 0),
        # 1 sat -> e=0, d=1, n=0 -> 1 + (0*9 + 0)*10 + 0 = 1
        (1, 1),
        # 9 sat -> e=0, d=9, n=0 -> 1 + (0*9 + 8)*10 + 0 = 81
        (9, 81),
        # 10 sat -> e=1, d=1, n=0 -> 1 + (0*9 + 0)*10 + 1 = 2
        (10, 2),
        # 0.001 BTC = 100_000 sat -> e=5, d=1, n=0 -> 1 + 0 + 5 = 6
        (100_000, 6),
        # 1 BTC = 100_000_000 sat -> e=8, d=1, n=0 -> 1 + 0 + 8 = 9
        (100_000_000, 9),
        # 50 BTC = 5_000_000_000 sat -> e=9 (since /10^9 = 5, then loop stops at e=9), so n=5
        (5_000_000_000, 1 + (5 - 1) * 10 + 9),
    ],
)
def test_compress_amount_known_cases(raw: int, compressed: int) -> None:
    assert compress_amount(raw) == compressed
    assert decompress_amount(compressed) == raw


def test_compress_amount_round_trip_random() -> None:
    import random

    rng = random.Random(0xDEADBEEF)
    # 21M BTC in sats = 2.1e15
    for _ in range(2000):
        amount = rng.randrange(0, 21_000_000 * 100_000_000)
        assert decompress_amount(compress_amount(amount)) == amount


# ---------------------------------------------------------------------------
# ScriptCompression -- recognized templates + raw fallback
# ---------------------------------------------------------------------------


_OP_DUP = 0x76
_OP_HASH160 = 0xA9
_OP_EQUALVERIFY = 0x88
_OP_EQUAL = 0x87
_OP_CHECKSIG = 0xAC


def _p2pkh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return bytes([_OP_DUP, _OP_HASH160, 20]) + h160 + bytes([_OP_EQUALVERIFY, _OP_CHECKSIG])


def _p2sh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return bytes([_OP_HASH160, 20]) + h160 + bytes([_OP_EQUAL])


def _p2pk_compressed(pubkey33: bytes) -> bytes:
    assert len(pubkey33) == 33 and pubkey33[0] in (0x02, 0x03)
    return bytes([33]) + pubkey33 + bytes([_OP_CHECKSIG])


def test_compress_script_p2pkh() -> None:
    h160 = bytes(range(20))
    script = _p2pkh(h160)
    out = compress_script(script)
    assert out is not None
    assert out[0] == 0x00
    assert out[1:] == h160
    # Round-trip through write/read.
    buf = io.BytesIO()
    write_compressed_script(buf, script)
    buf.seek(0)
    assert read_compressed_script(buf) == script


def test_compress_script_p2sh() -> None:
    h160 = bytes(range(20, 40))
    script = _p2sh(h160)
    out = compress_script(script)
    assert out is not None
    assert out[0] == 0x01
    assert out[1:] == h160
    buf = io.BytesIO()
    write_compressed_script(buf, script)
    buf.seek(0)
    assert read_compressed_script(buf) == script


def test_compress_script_p2pk_compressed() -> None:
    pubkey = bytes([0x02]) + bytes(range(32))
    script = _p2pk_compressed(pubkey)
    out = compress_script(script)
    assert out is not None
    assert out[0] == 0x02
    assert out[1:] == pubkey[1:]
    buf = io.BytesIO()
    write_compressed_script(buf, script)
    buf.seek(0)
    assert read_compressed_script(buf) == script


def test_compress_script_raw_fallback_segwit_v0() -> None:
    # P2WPKH: 0x00 0x14 <20-byte witness program>
    script = bytes([0x00, 0x14]) + bytes(range(20))
    out = compress_script(script)
    assert out is None  # not a recognized template
    buf = io.BytesIO()
    write_compressed_script(buf, script)
    buf.seek(0)
    decoded = read_compressed_script(buf)
    assert decoded == script


def test_compress_script_raw_fallback_taproot() -> None:
    # P2TR: 0x51 0x20 <32-byte x-only pubkey>
    script = bytes([0x51, 0x20]) + bytes(range(32))
    buf = io.BytesIO()
    write_compressed_script(buf, script)
    buf.seek(0)
    assert read_compressed_script(buf) == script


def test_compress_script_overlong_rejected() -> None:
    script = b"\x6a" + b"\x00" * 12_000  # 12001-byte OP_RETURN
    buf = io.BytesIO()
    with pytest.raises(ValueError):
        write_compressed_script(buf, script)


def test_decompress_script_uncompressed_p2pk_generator_point() -> None:
    """
    Tag 0x04/0x05 must recover the full 65-byte uncompressed pubkey via
    secp256k1, matching `bitcoin-core/src/compressor.cpp::DecompressScript`.

    Vector: secp256k1 generator point G.
      Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
      Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
      Compressed (y even) -> 0x02 || Gx     -> wire tag 0x04
      Uncompressed        -> 0x04 || Gx || Gy
      Output script       -> 0x41 || pubkey65 || 0xac (67 bytes total)
    """
    gx = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    gy_even = bytes.fromhex(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
    # Tag 0x04 = compressed prefix 0x02 (y even)
    decoded = decompress_script(0x04, gx)
    assert len(decoded) == 67
    assert decoded[0] == 65
    assert decoded[1] == 0x04
    assert decoded[2:34] == gx
    assert decoded[34:66] == gy_even
    assert decoded[66] == _OP_CHECKSIG

    # Tag 0x05 = compressed prefix 0x03 (y odd) -> mirror y -> p - y
    # secp256k1 field prime p
    p = (1 << 256) - (1 << 32) - 0x3D1
    gy_odd_int = p - int.from_bytes(gy_even, "big")
    gy_odd = gy_odd_int.to_bytes(32, "big")
    decoded_odd = decompress_script(0x05, gx)
    assert len(decoded_odd) == 67
    assert decoded_odd[0] == 65
    assert decoded_odd[1] == 0x04
    assert decoded_odd[2:34] == gx
    assert decoded_odd[34:66] == gy_odd
    assert decoded_odd[66] == _OP_CHECKSIG


def test_decompress_script_uncompressed_p2pk_off_curve_fails_closed() -> None:
    """An x-coordinate that is not on the secp256k1 curve must fail closed."""
    # x = 5: y^2 = 132 mod p is a quadratic non-residue, no valid y exists.
    bad_x = (5).to_bytes(32, "big")
    with pytest.raises(ValueError):
        decompress_script(0x04, bad_x)
    with pytest.raises(ValueError):
        decompress_script(0x05, bad_x)


def test_decompress_script_uncompressed_p2pk_wrong_size() -> None:
    with pytest.raises(ValueError):
        decompress_script(0x04, bytes(31))
    with pytest.raises(ValueError):
        decompress_script(0x05, bytes(33))


def test_decompress_script_uncompressed_p2pk_round_trip_via_read() -> None:
    """
    Going through `write_varint(tag) + body` must produce the same 67-byte
    P2PK script as `decompress_script` directly. Exercises the wire-level
    `read_compressed_script` path that `loadtxoutset` actually hits.
    """
    gx = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    buf = io.BytesIO()
    write_varint(buf, 0x04)
    buf.write(gx)
    buf.seek(0)
    decoded = read_compressed_script(buf)
    assert decoded == decompress_script(0x04, gx)
    assert len(decoded) == 67


# ---------------------------------------------------------------------------
# Coin and metadata round-trip
# ---------------------------------------------------------------------------


def test_coin_round_trip_p2pkh() -> None:
    height = 800_000
    is_coinbase = False
    amount = 12_345_678
    script = _p2pkh(bytes(20))
    buf = io.BytesIO()
    serialize_coin(buf, height, is_coinbase, amount, script)
    buf.seek(0)
    h2, cb2, amt2, sc2 = deserialize_coin(buf)
    assert (h2, cb2, amt2, sc2) == (height, is_coinbase, amount, script)


def test_coin_round_trip_coinbase_zero_amount() -> None:
    """Coinbase outputs at height 0 with zero amount must round-trip."""
    buf = io.BytesIO()
    serialize_coin(buf, 0, True, 0, _p2sh(bytes(20)))
    buf.seek(0)
    h, cb, amt, sc = deserialize_coin(buf)
    assert (h, cb, amt) == (0, True, 0)


def test_coin_segwit_v0_round_trip() -> None:
    script = bytes([0x00, 0x14]) + os.urandom(20)
    buf = io.BytesIO()
    serialize_coin(buf, 750_000, False, 50_000, script)
    buf.seek(0)
    h, cb, amt, sc = deserialize_coin(buf)
    assert (h, cb, amt, sc) == (750_000, False, 50_000, script)


def test_metadata_header_round_trip(tmp_path) -> None:
    network = "mainnet"
    base = bytes(range(32))[::-1]
    coins = 1234567
    path = tmp_path / "snap.dat"
    with open(path, "wb") as f:
        snapshot._write_metadata_header(f, network, base, coins)
        # Pad the file with at least one byte so the read path doesn't EOF
        # on the per-coin section. We don't read into it here.
    md = read_snapshot_metadata(str(path), network)
    assert md.version == SNAPSHOT_VERSION
    assert md.network == network
    assert md.base_blockhash == base
    assert md.coins_count == coins


def test_metadata_rejects_wrong_magic(tmp_path) -> None:
    path = tmp_path / "bad.dat"
    with open(path, "wb") as f:
        f.write(b"HDOG\x01" + b"\x00" * 50)  # legacy HDOG magic must be rejected
    with pytest.raises(ValueError, match="Invalid snapshot magic"):
        read_snapshot_metadata(str(path), "mainnet")


def test_metadata_rejects_network_mismatch(tmp_path) -> None:
    path = tmp_path / "wrongnet.dat"
    with open(path, "wb") as f:
        f.write(SNAPSHOT_MAGIC)
        f.write(struct.pack("<H", SNAPSHOT_VERSION))
        f.write(NETWORK_MAGIC["testnet4"])  # file says testnet4 ...
        f.write(bytes(32))
        f.write(struct.pack("<Q", 0))
    with pytest.raises(ValueError, match="Network mismatch"):
        read_snapshot_metadata(str(path), "mainnet")  # ... but we're loading mainnet


# ---------------------------------------------------------------------------
# AssumeUTXO data: required heights + non-zero hashes
# ---------------------------------------------------------------------------


def test_mainnet_assumeutxo_has_all_five_heights() -> None:
    heights = [d.height for d in get_assumeutxo_params("mainnet")]
    assert heights == [840_000, 880_000, 910_000, 935_000, 944_183]


def test_mainnet_assumeutxo_944183_entry_present() -> None:
    """Local snapshot entry for h=944183 (recovery snapshot, not Core chainparams)."""
    data = get_assumeutxo_data("mainnet", 944_183)
    assert data is not None
    assert data.block_hash[::-1].hex() == (
        "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
    )
    assert data.hash_serialized[::-1].hex() == (
        "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
    )


def test_testnet4_assumeutxo_has_two_heights() -> None:
    heights = [d.height for d in get_assumeutxo_params("testnet4")]
    assert heights == [90_000, 120_000]


def test_testnet3_assumeutxo_has_two_heights() -> None:
    heights = [d.height for d in get_assumeutxo_params("testnet")]
    assert heights == [2_500_000, 4_840_000]


@pytest.mark.parametrize(
    "network, height, blockhash_be",
    [
        # Pulled directly from bitcoin-core/src/kernel/chainparams.cpp
        ("mainnet", 840_000,
         "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
        ("mainnet", 880_000,
         "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"),
        ("mainnet", 910_000,
         "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"),
        ("mainnet", 935_000,
         "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"),
        ("testnet4", 90_000,
         "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"),
        ("testnet4", 120_000,
         "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"),
    ],
)
def test_assumeutxo_blockhash_matches_core(network: str, height: int, blockhash_be: str) -> None:
    data = get_assumeutxo_data(network, height)
    assert data is not None
    # block_hash is internal byte order; reverse for the big-endian display form.
    assert data.block_hash[::-1].hex() == blockhash_be


def test_assumeutxo_chain_tx_count_nonzero() -> None:
    for d in get_assumeutxo_params("mainnet"):
        assert d.chain_tx_count > 0


# ---------------------------------------------------------------------------
# End-to-end SnapshotManager round-trip with an in-memory DB stub.
# ---------------------------------------------------------------------------


@dataclass
class _UTXOEntry:
    txid: bytes
    vout: int
    amount: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool


class _StubDB:
    """Minimal in-memory db for SnapshotManager round-trip tests."""

    def __init__(self) -> None:
        self.utxos: list[_UTXOEntry] = []
        self.best_hash: bytes = bytes(32)
        self.best_height: int = 0

    # write side (used during dump)
    def get_best_block(self) -> tuple[bytes, int]:
        return self.best_hash, self.best_height

    def utxo_count(self) -> int:
        return len(self.utxos)

    def iter_utxos(self):
        return iter(self.utxos)

    # read side (used during load)
    def add_utxo_raw(self, *, txid, vout, amount, script_pubkey, height, is_coinbase):
        self.utxos.append(
            _UTXOEntry(
                txid=txid,
                vout=vout,
                amount=amount,
                script_pubkey=bytes(script_pubkey),
                height=height,
                is_coinbase=is_coinbase,
            )
        )

    def update_best_block(self, block_hash: bytes, height: int) -> None:
        self.best_hash = block_hash
        self.best_height = height


def _make_fixture_db() -> _StubDB:
    db = _StubDB()
    # Pin to mainnet 840k so the loader path actually validates the
    # blockhash against the assumeutxo table.
    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None
    db.best_hash = au.block_hash
    db.best_height = au.height

    txid_a = b"\xaa" * 32
    txid_b = b"\xbb" * 32
    txid_c = b"\xcc" * 32

    db.utxos.append(_UTXOEntry(
        txid=txid_b, vout=0, amount=50_000_000, script_pubkey=_p2pkh(b"\x01" * 20),
        height=210_000, is_coinbase=True,
    ))
    db.utxos.append(_UTXOEntry(
        txid=txid_a, vout=1, amount=25_000_000, script_pubkey=_p2sh(b"\x02" * 20),
        height=300_000, is_coinbase=False,
    ))
    db.utxos.append(_UTXOEntry(
        txid=txid_a, vout=0, amount=12_345_678, script_pubkey=_p2pkh(b"\x03" * 20),
        height=300_000, is_coinbase=False,
    ))
    db.utxos.append(_UTXOEntry(
        txid=txid_c, vout=7, amount=1, script_pubkey=bytes([0x00, 0x14]) + b"\x04" * 20,
        height=700_000, is_coinbase=False,
    ))
    return db


def test_snapshot_manager_round_trip(tmp_path) -> None:
    src = _make_fixture_db()
    sm_dump = SnapshotManager(src, "mainnet", str(tmp_path / "src"))

    snap_path = tmp_path / "utxo.dat"
    n = sm_dump.dump_snapshot(str(snap_path))
    assert n == len(src.utxos)
    assert snap_path.stat().st_size > 0

    # Round-trip: read header back and confirm txid grouping order.
    md = read_snapshot_metadata(str(snap_path), "mainnet")
    assert md.coins_count == n
    au = get_assumeutxo_data("mainnet", 840_000)
    assert md.base_blockhash == au.block_hash

    # Now load into a fresh DB and verify byte-perfect parity per UTXO.
    # strict=False: this fixture is 3 synthetic UTXOs, so it cannot match
    # the published mainnet@840k HASH_SERIALIZED commitment. The strict
    # check is exercised in test_load_snapshot_strict_hash_serialized_check
    # below.
    dst = _StubDB()
    sm_load = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    md2 = sm_load.load_snapshot(str(snap_path), strict=False)
    assert md2.coins_count == md.coins_count

    src_sorted = sorted(src.utxos, key=lambda u: (u.txid, u.vout))
    dst_sorted = sorted(dst.utxos, key=lambda u: (u.txid, u.vout))
    assert len(src_sorted) == len(dst_sorted)
    for s, d in zip(src_sorted, dst_sorted, strict=True):
        assert s.txid == d.txid
        assert s.vout == d.vout
        assert s.amount == d.amount
        assert s.script_pubkey == d.script_pubkey
        assert s.height == d.height
        assert s.is_coinbase == d.is_coinbase

    # And confirm the snapshot manager updated the destination chain tip.
    assert dst.best_hash == au.block_hash
    assert dst.best_height == au.height


def test_dump_snapshot_atomic_write(tmp_path) -> None:
    """Mirrors Bitcoin Core's rpc/blockchain.cpp::dumptxoutset which writes
    to <path>.incomplete, fsyncs, and renames. After a successful write
    only <path> should exist; the .incomplete temp must be gone so that
    operators copying the snapshot mid-dump never see a torn file.
    """
    import os
    src = _make_fixture_db()
    sm = SnapshotManager(src, "mainnet", str(tmp_path / "src"))

    snap_path = tmp_path / "atomic.dat"
    temp_path = tmp_path / "atomic.dat.incomplete"

    sm.dump_snapshot(str(snap_path))

    assert snap_path.exists(), "final path missing after successful dump"
    assert not temp_path.exists(), \
        ".incomplete temp left on disk after successful dump"


def test_dump_snapshot_cleans_temp_on_error(tmp_path, monkeypatch) -> None:
    """If serialization raises mid-dump the .incomplete temp must be
    cleaned up best-effort so a crashed dump never leaves a torn
    artifact behind. No final-path snapshot should appear.
    """
    src = _make_fixture_db()
    sm = SnapshotManager(src, "mainnet", str(tmp_path / "src"))

    snap_path = tmp_path / "fail.dat"
    temp_path = tmp_path / "fail.dat.incomplete"

    # Patch serialize_coin to throw on the first call so the dump
    # exits before reaching the rename.
    from ouroboros import snapshot as _snapshot_mod

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated serialize_coin failure")

    monkeypatch.setattr(_snapshot_mod, "serialize_coin", _boom)

    with pytest.raises(RuntimeError, match="simulated"):
        sm.dump_snapshot(str(snap_path))

    assert not snap_path.exists(), "final path should not exist on failure"
    assert not temp_path.exists(), ".incomplete temp leaked after failure"


def test_snapshot_manager_rejects_unknown_blockhash(tmp_path) -> None:
    src = _make_fixture_db()
    src.best_hash = b"\xde" * 32  # not in the assumeutxo table
    sm = SnapshotManager(src, "mainnet", str(tmp_path / "src"))
    snap_path = tmp_path / "utxo.dat"
    sm.dump_snapshot(str(snap_path))

    # Loading on mainnet must reject this snapshot.
    dst = _StubDB()
    sm_load = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    with pytest.raises(ValueError, match="not recognized"):
        sm_load.load_snapshot(str(snap_path))


def test_load_snapshot_strict_hash_serialized_check(tmp_path, monkeypatch) -> None:
    """Strict load enforces the SHA256d (HASH_SERIALIZED) commitment per
    validation.cpp:5902-5915 + kernel/coinstats.cpp:161-163.

    Builds a 1-coin snapshot at the mainnet@840k whitelisted hash, swaps the
    chainparams entry to (a) the right SHA256d value -> load passes,
    (b) a different value -> load raises 'Bad snapshot content hash'.
    """
    from ouroboros import snapshot as _snapshot_mod
    from ouroboros.muhash import coin_element
    from ouroboros.snapshot import HashWriter

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    one_utxo = _UTXOEntry(
        txid=b"\xab" * 32, vout=0, amount=12345,
        script_pubkey=_p2pkh(b"\xcd" * 20),
        height=100_000, is_coinbase=False,
    )
    src.utxos.append(one_utxo)
    snap_path = tmp_path / "good.dat"
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(
        str(snap_path)
    )

    # Pre-compute the SHA256d commitment over the 1-coin set. Same path
    # the loader uses (HashWriter feeding TxOutSer bytes in (txid, vout)
    # order, finalize via double-SHA256).
    expected = HashWriter()
    expected.update(coin_element(
        txid=one_utxo.txid, vout=one_utxo.vout, height=one_utxo.height,
        is_coinbase=one_utxo.is_coinbase, amount=one_utxo.amount,
        script_pubkey=one_utxo.script_pubkey,
    ))
    expected_digest = expected.digest()

    # (a) Correct commitment -> load passes.
    patched_ok = _snapshot_mod.AssumeutxoData(
        height=au.height,
        block_hash=au.block_hash,
        hash_serialized=expected_digest,
        chain_tx_count=au.chain_tx_count,
    )
    monkeypatch.setattr(
        _snapshot_mod, "_MAINNET_ASSUMEUTXO",
        [patched_ok if d.height == au.height else d
         for d in _snapshot_mod._MAINNET_ASSUMEUTXO],
    )
    dst_ok = _StubDB()
    sm_ok = SnapshotManager(dst_ok, "mainnet", str(tmp_path / "dst-ok"))
    sm_ok.load_snapshot(str(snap_path))
    assert sm_ok.snapshot_loaded
    assert len(dst_ok.utxos) == 1

    # (b) Wrong commitment -> load raises with Core wording.
    bad_digest = bytes(b ^ 0xff for b in expected_digest)
    patched_bad = _snapshot_mod.AssumeutxoData(
        height=au.height,
        block_hash=au.block_hash,
        hash_serialized=bad_digest,
        chain_tx_count=au.chain_tx_count,
    )
    monkeypatch.setattr(
        _snapshot_mod, "_MAINNET_ASSUMEUTXO",
        [patched_bad if d.height == au.height else d
         for d in _snapshot_mod._MAINNET_ASSUMEUTXO],
    )
    dst_bad = _StubDB()
    sm_bad = SnapshotManager(dst_bad, "mainnet", str(tmp_path / "dst-bad"))
    with pytest.raises(ValueError, match="Bad snapshot content hash"):
        sm_bad.load_snapshot(str(snap_path))
    assert not sm_bad.snapshot_loaded


def test_hashwriter_matches_core_chash256() -> None:
    """HashWriter.digest() must equal SHA256d (CHash256), per Core's
    HashWriter::GetHash (hash.h:115-120). Fixed test vectors so any
    drift away from double-SHA256 (e.g. accidental single SHA-256)
    is caught immediately.
    """
    import hashlib

    from ouroboros.snapshot import HashWriter

    # Vector 1: empty input. SHA256d("") =
    #   SHA256(SHA256(""))
    #   = SHA256(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
    h = HashWriter()
    expected_empty = hashlib.sha256(hashlib.sha256(b"").digest()).digest()
    assert h.digest() == expected_empty
    # Confirm it's NOT a single SHA-256 -- guards against the bug we
    # just fixed (compute_utxo_hash used to do single-SHA256 in
    # hash_serialized mode).
    assert h.digest() != hashlib.sha256(b"").digest()

    # Vector 2: streaming update equivalence.
    h = HashWriter()
    h.update(b"hello").update(b" ").update(b"world")
    once = hashlib.sha256(b"hello world").digest()
    expected = hashlib.sha256(once).digest()
    assert h.digest() == expected

    # Vector 3: well-known SHA256d("abc"):
    #   SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #   SHA256(that)  = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
    h = HashWriter()
    h.update(b"abc")
    assert h.digest().hex() == (
        "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    )


def test_compute_utxo_hash_serialized_matches_streaming_load(tmp_path) -> None:
    """``compute_utxo_hash(hash_type='hash_serialized')`` and the
    streaming HashWriter inside ``load_snapshot`` must produce the same
    SHA256d digest for the same UTXO set. Pins both to a single
    canonical SHA256d-via-HashWriter implementation.
    """
    from ouroboros.muhash import coin_element
    from ouroboros.snapshot import HashWriter, compute_utxo_hash

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    # Build a fixture with a few UTXOs so order-sensitive hashing is
    # exercised non-trivially. Use unsorted insertion to make sure the
    # in-DB hasher does the (txid, vout) sort.
    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    utxos = [
        _UTXOEntry(txid=b"\x33" * 32, vout=2, amount=300,
                   script_pubkey=_p2pkh(b"\x03" * 20),
                   height=200_000, is_coinbase=False),
        _UTXOEntry(txid=b"\x11" * 32, vout=0, amount=100,
                   script_pubkey=_p2pkh(b"\x01" * 20),
                   height=100_000, is_coinbase=True),
        _UTXOEntry(txid=b"\x22" * 32, vout=1, amount=200,
                   script_pubkey=_p2pkh(b"\x02" * 20),
                   height=150_000, is_coinbase=False),
    ]
    src.utxos.extend(utxos)

    # Hash via the in-DB compute path (sorts internally).
    in_db_digest = compute_utxo_hash(src, hash_type="hash_serialized")

    # Hash via direct HashWriter over the canonically sorted list. Same
    # bytes Core would feed into HashWriter via TxOutSer + cursor walk.
    sorted_utxos = sorted(utxos, key=lambda u: (u.txid, u.vout))
    direct = HashWriter()
    for u in sorted_utxos:
        direct.update(coin_element(
            txid=u.txid, vout=u.vout, height=u.height,
            is_coinbase=u.is_coinbase, amount=u.amount,
            script_pubkey=u.script_pubkey,
        ))
    assert in_db_digest == direct.digest()

    # Now build a real snapshot file and compare to the streaming
    # digest from inside load_snapshot. We can't read the loader's
    # internal hasher state directly, but we can confirm the strict
    # gate matches the in-DB digest by injecting it into chainparams:
    snap_path = tmp_path / "fix.dat"
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(
        str(snap_path)
    )
    from ouroboros import snapshot as _snapshot_mod

    patched = _snapshot_mod.AssumeutxoData(
        height=au.height, block_hash=au.block_hash,
        hash_serialized=in_db_digest, chain_tx_count=au.chain_tx_count,
    )
    saved = list(_snapshot_mod._MAINNET_ASSUMEUTXO)
    try:
        _snapshot_mod._MAINNET_ASSUMEUTXO[:] = [
            patched if d.height == au.height else d for d in saved
        ]
        dst = _StubDB()
        sm = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
        # If the streaming hasher disagrees with compute_utxo_hash,
        # this raises "Bad snapshot content hash".
        sm.load_snapshot(str(snap_path))
        assert sm.snapshot_loaded
    finally:
        _snapshot_mod._MAINNET_ASSUMEUTXO[:] = saved


def test_compute_utxo_hash_default_is_hash_serialized() -> None:
    """The default ``hash_type`` for ``compute_utxo_hash`` must be
    ``"hash_serialized"`` (SHA256d), matching what the loadtxoutset
    strict gate uses. Catches accidental switches to MuHash3072 (the
    bug this commit reverts).
    """
    from ouroboros.snapshot import compute_utxo_hash

    src = _StubDB()
    src.utxos.append(_UTXOEntry(
        txid=b"\xaa" * 32, vout=0, amount=42,
        script_pubkey=_p2pkh(b"\xbb" * 20),
        height=1, is_coinbase=False,
    ))

    default = compute_utxo_hash(src)
    explicit = compute_utxo_hash(src, hash_type="hash_serialized")
    assert default == explicit

    # And it must NOT equal the MuHash3072 digest.
    muhash = compute_utxo_hash(src, hash_type="muhash")
    assert default != muhash


def test_strict_gate_rejects_muhash_value(tmp_path, monkeypatch) -> None:
    """If chainparams ever shipped a MuHash3072 digest where
    HASH_SERIALIZED is expected, the strict gate must reject the
    snapshot. This is the regression that motivated this commit:
    pre-fix, ouroboros computed MuHash and compared it to chainparams
    -- both wrong-type. Post-fix, chainparams holds SHA256d and the
    loader computes SHA256d, so a MuHash there must fail.
    """
    from ouroboros import snapshot as _snapshot_mod
    from ouroboros.muhash import MuHash3072, coin_element

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    one_utxo = _UTXOEntry(
        txid=b"\xab" * 32, vout=0, amount=12345,
        script_pubkey=_p2pkh(b"\xcd" * 20),
        height=100_000, is_coinbase=False,
    )
    src.utxos.append(one_utxo)
    snap_path = tmp_path / "muhash.dat"
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(
        str(snap_path)
    )

    # Compute the MuHash digest -- the value the buggy implementation
    # would have published in chainparams. Inject it as the supposed
    # HASH_SERIALIZED value; the strict gate (which now correctly
    # computes SHA256d) must reject it.
    muhash = MuHash3072()
    muhash.insert(coin_element(
        txid=one_utxo.txid, vout=one_utxo.vout, height=one_utxo.height,
        is_coinbase=one_utxo.is_coinbase, amount=one_utxo.amount,
        script_pubkey=one_utxo.script_pubkey,
    ))
    patched = _snapshot_mod.AssumeutxoData(
        height=au.height, block_hash=au.block_hash,
        hash_serialized=muhash.digest(),  # WRONG type for this gate
        chain_tx_count=au.chain_tx_count,
    )
    monkeypatch.setattr(
        _snapshot_mod, "_MAINNET_ASSUMEUTXO",
        [patched if d.height == au.height else d
         for d in _snapshot_mod._MAINNET_ASSUMEUTXO],
    )
    dst = _StubDB()
    sm = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    with pytest.raises(ValueError, match="Bad snapshot content hash"):
        sm.load_snapshot(str(snap_path))
    assert not sm.snapshot_loaded


# ---------------------------------------------------------------------------
# Byte-fixture: a hand-rolled minimal Core-format snapshot we can validate
# against a stable hex transcript. This guards against silent format drift.
# ---------------------------------------------------------------------------


def test_minimal_snapshot_matches_known_bytes(tmp_path) -> None:
    """
    Hand-build a 1-coin snapshot for mainnet 840k with a P2PKH script and
    a known amount, then verify the resulting bytes exactly. This pins
    the wire format down so any future encoder regression is loud.
    """
    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    txid = b"\xab" * 32
    h160 = b"\xcd" * 20
    script = _p2pkh(h160)
    height = 100_000
    is_coinbase = False
    amount = 1  # CompressAmount(1) == 1 -> VARINT encodes as single byte 0x01

    db = _StubDB()
    db.best_hash = au.block_hash
    db.best_height = au.height
    db.utxos.append(_UTXOEntry(
        txid=txid, vout=3, amount=amount, script_pubkey=script,
        height=height, is_coinbase=is_coinbase,
    ))
    sm = SnapshotManager(db, "mainnet", str(tmp_path / "src"))
    out = tmp_path / "utxo.dat"
    sm.dump_snapshot(str(out))

    actual = out.read_bytes()
    expected = bytearray()
    # Header
    expected += SNAPSHOT_MAGIC
    expected += struct.pack("<H", SNAPSHOT_VERSION)
    expected += NETWORK_MAGIC["mainnet"]
    expected += au.block_hash
    expected += struct.pack("<Q", 1)
    # Group: txid + 1 coin
    expected += txid
    expected += b"\x01"  # CompactSize(1)
    expected += b"\x03"  # CompactSize(vout=3)
    # code = (height<<1)|coinbase = 200_000. VARINT(200_000):
    #   200_000 = 0xC350. Encoding pulled from the recursive formula.
    code = (height << 1) | (1 if is_coinbase else 0)
    code_buf = io.BytesIO()
    write_varint(code_buf, code)
    expected += code_buf.getvalue()
    # value: VARINT(CompressAmount(1)) = VARINT(1) = 0x01
    expected += b"\x01"
    # script: P2PKH -> tag 0x00 then 20-byte h160
    expected += b"\x00" + h160

    assert actual == bytes(expected), (
        f"snapshot byte mismatch:\n  actual  : {actual.hex()}\n"
        f"  expected: {bytes(expected).hex()}"
    )


# ---------------------------------------------------------------------------
# dumptxoutset on an empty UTXO set: header-only, exactly 51 bytes
# ---------------------------------------------------------------------------
#
# Snapshot v2 header layout:
#   magic         5 B  ("utxo\xff")
#   version       2 B  uint16 LE     (= 2)
#   network_magic 4 B  pchMessageStart
#   base_blockhash 32 B internal byte order
#   coins_count   8 B  uint64 LE
#   ----------------
#   total        51 B
#
# A coins_count=0 dump must produce exactly the header and nothing else --
# no per-txid groups. This pins the no-UTXO branch of the dumper.


def test_dumptxoutset_empty_utxo_set_is_51_byte_header(tmp_path) -> None:
    db = _StubDB()
    # An empty regtest dump still needs *some* base hash so the header
    # encodes; pick the regtest genesis so the bytes are deterministic.
    regtest_genesis_le = bytes.fromhex(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )[::-1]
    db.best_hash = regtest_genesis_le
    db.best_height = 0
    assert db.utxo_count() == 0

    sm = SnapshotManager(db, "regtest", str(tmp_path / "src"))
    out = tmp_path / "empty.dat"
    n = sm.dump_snapshot(str(out))
    assert n == 0

    raw = out.read_bytes()
    assert len(raw) == 51, (
        f"empty snapshot must be exactly 51 bytes (header only), got {len(raw)}"
    )

    expected = (
        SNAPSHOT_MAGIC
        + struct.pack("<H", SNAPSHOT_VERSION)
        + NETWORK_MAGIC["regtest"]
        + regtest_genesis_le
        + struct.pack("<Q", 0)
    )
    assert raw == expected, (
        f"empty-snapshot bytes differ:\n  actual  : {raw.hex()}\n"
        f"  expected: {expected.hex()}"
    )

    # And the header must round-trip through read_snapshot_metadata.
    md = read_snapshot_metadata(str(out), "regtest")
    assert md.coins_count == 0
    assert md.base_blockhash == regtest_genesis_le
    assert md.version == SNAPSHOT_VERSION


# ---------------------------------------------------------------------------
# Core-strict assumeUTXO whitelist on the loadtxoutset RPC handler
# ---------------------------------------------------------------------------


def _build_minimal_snapshot(
    tmp_path, network: str, base_blockhash_le: bytes
) -> str:
    """Write a header-only snapshot file (coins_count=0) and return its path."""
    path = tmp_path / f"snap-{network}.dat"
    with open(path, "wb") as f:
        from ouroboros.snapshot import _write_metadata_header
        _write_metadata_header(f, network, base_blockhash_le, 0)
    return str(path)


class _RPCStubNode:
    """Minimal node surface needed by RPCServer.rpc_loadtxoutset."""

    def __init__(self, db, network: str, snapshot_manager) -> None:
        self.db = db
        self.network = network
        self.snapshot_manager = snapshot_manager


@pytest.fixture
def rpc_loader_factory(tmp_path):
    """Build an RPCServer wired to a stub node + snapshot manager."""
    from ouroboros.rpc import RPCServer

    def _factory(network: str, db: _StubDB | None = None):
        if db is None:
            db = _StubDB()
        sm = SnapshotManager(db, network, str(tmp_path / f"sm-{network}"))
        rpc = RPCServer.__new__(RPCServer)
        rpc.node = _RPCStubNode(db, network, sm)
        return rpc, sm, db

    return _factory


def test_rpc_loadtxoutset_rejects_regtest_genesis_blockhash(
    rpc_loader_factory, tmp_path
) -> None:
    """The loadtxoutset RPC must refuse a snapshot whose base_blockhash is
    not in the assumeUTXO whitelist. Reference: bitcoin-core
    validation.cpp:5775-5780. We exercise this with the regtest genesis,
    which has no entry in any AU table, and assert the Core error
    wording.
    """
    import asyncio

    from fastapi import HTTPException

    regtest_genesis_le = bytes.fromhex(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )[::-1]
    snap = _build_minimal_snapshot(tmp_path, "regtest", regtest_genesis_le)

    rpc, sm, _ = rpc_loader_factory("regtest")

    async def _call() -> None:
        await rpc.rpc_loadtxoutset(snap)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(_call())

    # Core's error: "Assumeutxo height in snapshot metadata not recognized
    # (<H>) - refusing to load snapshot". We don't have the height locally
    # so we report 'unknown' in its place; both the prefix and suffix must
    # match Core verbatim.
    assert excinfo.value.status_code == 400
    detail = excinfo.value.detail
    assert "Assumeutxo height in snapshot metadata not recognized" in detail
    assert "refusing to load snapshot" in detail
    # Snapshot loader must NOT have been activated.
    assert sm.snapshot_loaded is False


def test_rpc_loadtxoutset_accepts_whitelisted_blockhash_with_raw_insert(
    rpc_loader_factory, tmp_path, monkeypatch
) -> None:
    """A snapshot whose base_blockhash IS in the AU table must be accepted
    and its UTXOs inserted via add_utxo_raw. Uses mainnet height 840k.

    We override the published hash_serialized for the duration of the test
    with the SHA256d commitment over our 1-coin synthetic UTXO set, so
    the strict assumeUTXO check (mirrors validation.cpp:5902-5915) passes
    on this fixture.
    """
    import asyncio

    from ouroboros import snapshot as _snapshot_mod
    from ouroboros.muhash import coin_element
    from ouroboros.snapshot import HashWriter

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    # Build a real 1-coin snapshot at the whitelisted hash by going through
    # the dumper (so the wire bytes are guaranteed loader-compatible).
    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    one_utxo = _UTXOEntry(
        txid=b"\xab" * 32, vout=0, amount=12345,
        script_pubkey=_p2pkh(b"\xcd" * 20),
        height=100_000, is_coinbase=False,
    )
    src.utxos.append(one_utxo)
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(
        str(tmp_path / "good.dat")
    )

    # Pre-compute the SHA256d commitment over the 1-coin set and inject
    # it into the mainnet AU table for the duration of the test.
    expected = HashWriter()
    expected.update(coin_element(
        txid=one_utxo.txid, vout=one_utxo.vout, height=one_utxo.height,
        is_coinbase=one_utxo.is_coinbase, amount=one_utxo.amount,
        script_pubkey=one_utxo.script_pubkey,
    ))
    patched_au = _snapshot_mod.AssumeutxoData(
        height=au.height,
        block_hash=au.block_hash,
        hash_serialized=expected.digest(),
        chain_tx_count=au.chain_tx_count,
    )
    patched_table = [
        patched_au if d.height == au.height else d
        for d in _snapshot_mod._MAINNET_ASSUMEUTXO
    ]
    monkeypatch.setattr(_snapshot_mod, "_MAINNET_ASSUMEUTXO", patched_table)

    rpc, sm, dst = rpc_loader_factory("mainnet")

    async def _call() -> dict:
        return await rpc.rpc_loadtxoutset(str(tmp_path / "good.dat"))

    result = asyncio.run(_call())
    assert result["coins_loaded"] == 1
    assert result["base_height"] == au.height
    # Snapshot metadata exposes blockhash in big-endian display form.
    assert result["base_hash"] == au.block_hash[::-1].hex()

    # And the raw insertion must have populated the destination DB exactly
    # once with the correct fields.
    assert sm.snapshot_loaded is True
    assert len(dst.utxos) == 1
    inserted = dst.utxos[0]
    assert inserted.txid == b"\xab" * 32
    assert inserted.vout == 0
    assert inserted.amount == 12345
    assert inserted.height == 100_000
    assert inserted.is_coinbase is False


# ---------------------------------------------------------------------------
# Chainstate filter tests (require the Rust `sync` extension).
#
# These exercise the real `connect_block_from_bytes` / `dump_snapshot` path
# against a temporary RocksDB datadir, which is the same path the
# `dumptxoutset` RPC uses in production.
#
# Two correctness invariants live here:
#
#   1. Provably unspendable outputs (OP_RETURN / oversize scriptPubKey)
#      must NEVER enter the UTXO set, mirroring Core's `CScript::IsUnspendable`
#      filter inside `AddCoins` (coins.cpp:96-99).  Without this, every
#      witness-commitment OP_RETURN in a segwit-coinbase block ends up in
#      `dumptxoutset`, so ouroboros' snapshot diverges from Core's.
#   2. The genesis-block coinbase is unspendable per Core
#      (validation.cpp:2337-2343).  Adding it to the chainstate causes a
#      single-coin off-by-one in `coins_count` against Core's reference.
#
# Both bugs were caught by tools/snapshot-byte-identity.sh (regtest, 110
# Core-mined blocks): pre-fix ouroboros produced 12679B / 221 coins, where
# Core / rustoshi / hotbuns / lunarblock all produced 7908B / 110 coins.
# ---------------------------------------------------------------------------


def _try_import_sync() -> object | None:
    """Return the real Rust `sync` extension, bypassing conftest's stub.

    `tests/conftest.py` installs a pure-Python stub at `sys.modules["sync"]`
    so most of the test suite can import ouroboros without building the
    native extension.  The chainstate-filter tests below need the *real*
    extension to exercise `connect_block_from_bytes`.

    Caching the result so subsequent tests reuse the same module: the
    Rust extension's `PyInit_sync` symbol can only be loaded once per
    process (a pyo3 limitation — re-init fails with "module already
    initialized").
    """
    import importlib
    import sys
    from pathlib import Path

    if "_sync_real" in sys.modules:
        return sys.modules["_sync_real"]

    # Detect whether sys.modules["sync"] is the Python stub from conftest
    # or the real Rust .so.
    stub = sys.modules.get("sync")
    is_stub = stub is not None and getattr(stub, "__file__", "") == "<test-mock>"

    if not is_stub:
        # Already real (or absent) — try plain import.
        try:
            mod = importlib.import_module("sync")
        except ImportError:
            return None
        if not hasattr(mod, "PyBlockchainDB") or not hasattr(
            mod.PyBlockchainDB, "connect_block_from_bytes"
        ):
            return None
        sys.modules["_sync_real"] = mod
        return mod

    # Conftest installed a stub.  Confirm a real wheel exists in the venv
    # before we touch sys.modules.
    venv_root = Path(__file__).parent.parent / ".venv"
    candidates = sorted(venv_root.glob(
        "lib/python*/site-packages/sync/sync*.so"
    ))
    if not candidates:
        return None

    saved = sys.modules.pop("sync")
    try:
        mod = importlib.import_module("sync")
    except ImportError:
        sys.modules["sync"] = saved
        return None
    finally:
        # Re-install the stub so other tests that import via the stub
        # keep working.  The real module is cached under `_sync_real`.
        sys.modules["sync"] = saved
    if not hasattr(mod, "PyBlockchainDB") or not hasattr(
        mod.PyBlockchainDB, "connect_block_from_bytes"
    ):
        return None
    sys.modules["_sync_real"] = mod
    return mod


def _make_regtest_genesis_bytes() -> bytes:
    """Reconstruct the regtest genesis block (header + coinbase tx).

    Mirrors what `node._init_genesis_block` builds for the regtest network.
    """
    import struct as _struct

    prev_block = b"\x00" * 32
    merkle_root = bytes.fromhex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    )[::-1]
    ts, bits, nonce = 1296688602, 0x207FFFFF, 2
    coinbase_tx = bytes.fromhex(
        "01000000"
        "01"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff"
        "4d"
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
        "39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
        "ffffffff"
        "01"
        "00f2052a01000000"
        "43"
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
        "00000000"
    )
    header = _struct.pack("<i", 1) + prev_block + merkle_root
    header += _struct.pack("<III", ts, bits, nonce)
    return header + b"\x01" + coinbase_tx


def test_chainstate_skips_genesis_coinbase(tmp_path) -> None:
    """Genesis coinbase output must NOT enter the chainstate.

    Mirrors Core (validation.cpp:2337-2343, "Special case for the genesis
    block, skipping connection of its transactions (its coinbase is
    unspendable)").  Without this, `dumptxoutset` reports 1 extra coin.
    """
    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))
    block_bytes = _make_regtest_genesis_bytes()
    db.connect_block_from_bytes(block_bytes, 0)

    # Tip is at genesis but UTXO set is empty (genesis coinbase is unspendable).
    _, height = db.get_best_block()
    assert height == 0
    assert db.utxo_count() == 0


def test_chainstate_skips_op_return(tmp_path) -> None:
    """OP_RETURN outputs must NOT enter the chainstate.

    Mirrors Core's `CScript::IsUnspendable` filter inside `AddCoins`
    (script.h:563-566 + coins.cpp:96-99).  Without this, every
    witness-commitment OP_RETURN in a segwit-coinbase block ends up in
    `dumptxoutset`, doubling the coin count.

    We craft a synthetic non-genesis block whose coinbase has both a
    spendable P2WSH output AND an OP_RETURN witness-commitment output,
    matching the structure of Core's segwit regtest coinbase.  Only the
    P2WSH output should be present after `connect_block_from_bytes`.
    """
    import hashlib as _hashlib
    import struct as _struct

    sync = _try_import_sync()
    if sync is None or not hasattr(sync, "PyBlockchainDB"):
        pytest.skip("Rust `sync` extension not installed")

    db = sync.PyBlockchainDB(str(tmp_path / "db"))

    # We need a tip first; just plant the regtest genesis (UTXO-empty per
    # the test above) so the next block links cleanly.
    db.connect_block_from_bytes(_make_regtest_genesis_bytes(), 0)
    genesis_hash, _ = db.get_best_block()

    # Build a coinbase with two outputs: spendable P2WSH + OP_RETURN.
    # P2WSH output: 0x00 0x20 <32-byte program>  (always-anyone-can-spend
    # script-hash).
    p2wsh_script = bytes([0x00, 0x20]) + (b"\xab" * 32)
    p2wsh_value = 50 * 100_000_000  # 50 BTC subsidy (regtest)

    # OP_RETURN witness commitment: 0x6a 0x24 0xaa21a9ed <32-byte commit>
    op_return_script = bytes([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]) + (b"\x00" * 32)
    op_return_value = 0

    # Coinbase tx: 1 input with all-zero prevout, 2 outputs.
    coinbase_tx = (
        _struct.pack("<I", 1)                              # version
        + b"\x01"                                          # 1 input
        + b"\x00" * 32                                     # prev_txid
        + _struct.pack("<I", 0xFFFFFFFF)                   # prev_vout
        + b"\x02\x51\x01"                                  # scriptSig: BIP34 height push + OP_1
        + _struct.pack("<I", 0xFFFFFFFF)                   # sequence
        + b"\x02"                                          # 2 outputs
        + _struct.pack("<Q", p2wsh_value)                  # value 1
        + bytes([len(p2wsh_script)]) + p2wsh_script        # script 1
        + _struct.pack("<Q", op_return_value)              # value 2
        + bytes([len(op_return_script)]) + op_return_script  # script 2
        + _struct.pack("<I", 0)                            # locktime
    )
    txid = _hashlib.sha256(_hashlib.sha256(coinbase_tx).digest()).digest()
    merkle_root = txid

    # Solve the regtest header (target = 0x207fffff is permissive enough
    # that nonce=0 usually works).
    version = _struct.pack("<i", 1)
    bits = _struct.pack("<I", 0x207FFFFF)
    nonce = 0
    while True:
        header = (
            version
            + genesis_hash
            + merkle_root
            + _struct.pack("<I", 1296688700)               # time
            + bits
            + _struct.pack("<I", nonce)
        )
        block_hash = _hashlib.sha256(_hashlib.sha256(header).digest()).digest()
        # regtest target = 0x207fffff → 0x7fffff0000...000 LE.  Hash must
        # be <= target as a 256-bit LE int.  Trivially: top byte == 0x7f.
        if block_hash[31] < 0x7f or (block_hash[31] == 0x7f and block_hash[30] <= 0xff):
            break
        nonce += 1
        if nonce > 1_000_000:
            pytest.skip("could not solve regtest header (cosmic ray?)")

    block = header + b"\x01" + coinbase_tx
    db.connect_block_from_bytes(block, 1)

    # P2WSH output is in the UTXO set; OP_RETURN output is filtered out.
    assert db.utxo_count() == 1
    utxos = list(db.iter_utxos())
    assert len(utxos) == 1
    coin = utxos[0]
    assert bytes(coin.script_pubkey) == p2wsh_script
    assert int(coin.amount) == p2wsh_value
