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


def test_decompress_script_uncompressed_p2pk_unsupported() -> None:
    with pytest.raises(NotImplementedError):
        decompress_script(0x04, bytes(32))


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


def test_mainnet_assumeutxo_has_all_four_heights() -> None:
    heights = [d.height for d in get_assumeutxo_params("mainnet")]
    assert heights == [840_000, 880_000, 910_000, 935_000]


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
    dst = _StubDB()
    sm_load = SnapshotManager(dst, "mainnet", str(tmp_path / "dst"))
    md2 = sm_load.load_snapshot(str(snap_path))
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
    rpc_loader_factory, tmp_path
) -> None:
    """A snapshot whose base_blockhash IS in the AU table must be accepted
    and its UTXOs inserted via add_utxo_raw. Uses mainnet height 840k.
    """
    import asyncio

    au = get_assumeutxo_data("mainnet", 840_000)
    assert au is not None

    # Build a real 1-coin snapshot at the whitelisted hash by going through
    # the dumper (so the wire bytes are guaranteed loader-compatible).
    src = _StubDB()
    src.best_hash = au.block_hash
    src.best_height = au.height
    src.utxos.append(_UTXOEntry(
        txid=b"\xab" * 32, vout=0, amount=12345,
        script_pubkey=_p2pkh(b"\xcd" * 20),
        height=100_000, is_coinbase=False,
    ))
    SnapshotManager(src, "mainnet", str(tmp_path / "src")).dump_snapshot(
        str(tmp_path / "good.dat")
    )

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
