"""Behavioural tests for the Rust ``import_core_snapshot`` (import-utxo) path.

The importer parses + hashes the whole Core-format snapshot and stages sorted
SST files BEFORE it touches the chainstate, then ingests them in one step.
These tests pin what that must preserve:

* every coin lands byte-for-byte (read back through the ordinary get_utxo /
  Python HASH_SERIALIZED walk, which knows nothing about SST staging),
  including vouts >= 256 whose little-endian key bytes sort differently from
  their numeric order;
* the digest it returns is Core's HASH_SERIALIZED of the set;
* a wrong commitment, trailing bytes, an over-height coin or out-of-order
  txids are refused and leave the existing chainstate + tip untouched;
* a re-import over a populated chainstate replaces it (no stale coins).
"""

from __future__ import annotations

import io
import os
import struct

import pytest

sync = pytest.importorskip("sync")

from ouroboros.database import BlockchainDatabase  # noqa: E402
from ouroboros.muhash import coin_element  # noqa: E402
from ouroboros.snapshot import (  # noqa: E402
    NETWORK_MAGIC,
    HashWriter,
    _write_compact_size,
    _write_metadata_header,
    compute_utxo_hash,
    serialize_coin,
)

# Other test modules may swap ``sync`` for a stub in sys.modules; skip then.
_SIG = getattr(
    getattr(getattr(sync, "PyBlockchainDB", None), "import_core_snapshot", None),
    "__text_signature__",
    "",
) or ""
pytestmark = pytest.mark.skipif(
    "expected_hash_serialized" not in _SIG,
    reason="installed ferrous-utils extension predates the SST importer",
)

# Secp256k1 generator, uncompressed -- a valid point for the 0x04/0x05 tag.
_G_X = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
_G_Y = bytes.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

BASE_HASH = bytes(range(32))
BASE_HEIGHT = 1000


def _scripts():
    return [
        b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac",          # P2PKH
        b"\xa9\x14" + b"\x22" * 20 + b"\x87",                  # P2SH
        b"\x21\x02" + b"\x33" * 32 + b"\xac",                  # P2PK compressed
        b"\x41\x04" + _G_X + _G_Y + b"\xac",                   # P2PK uncompressed
        b"\x00\x14" + b"\x44" * 20,                            # P2WPKH (raw)
        b"\x51\x20" + b"\x55" * 32,                            # P2TR (raw)
        b"",                                                   # empty script
    ]


def _coins(seed: int):
    """Canonical-order coin list: [(txid, vout, height, cb, amount, script)]."""
    scripts = _scripts()
    out = []
    txids = sorted(bytes([seed, i]) + bytes(30) for i in range(12))
    for t, txid in enumerate(txids):
        vouts = [0, 1, 255, 256, 300, 70000] if t == 3 else [0, 2]
        for j, vout in enumerate(vouts):
            script = scripts[(t + j) % len(scripts)]
            out.append((txid, vout, 1 + t * 7 + j, (t + j) % 5 == 0, 1000 * (t + 1) + j, script))
    return out


def _snapshot_bytes(coins, *, trailing: bytes = b"", count: int | None = None) -> bytes:
    f = io.BytesIO()
    _write_metadata_header(f, "mainnet", BASE_HASH, len(coins) if count is None else count)
    groups: dict[bytes, list] = {}
    order: list[bytes] = []
    for c in coins:
        if c[0] not in groups:
            groups[c[0]] = []
            order.append(c[0])
        groups[c[0]].append(c)
    for txid in order:
        f.write(txid)
        _write_compact_size(f, len(groups[txid]))
        for (_t, vout, h, cb, amt, spk) in groups[txid]:
            _write_compact_size(f, vout)
            serialize_coin(f, h, cb, amt, spk)
    f.write(trailing)
    return f.getvalue()


def _expected_hash(coins) -> bytes:
    hw = HashWriter()
    for (txid, vout, h, cb, amt, spk) in sorted(coins, key=lambda c: (c[0], c[1])):
        hw.update(coin_element(txid=txid, vout=vout, height=h, is_coinbase=cb,
                               amount=amt, script_pubkey=spk))
    return hw.digest()


def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _import(db, path, expected=None, height=BASE_HEIGHT, per_file=5):
    return db._db.import_core_snapshot(
        path, height, list(NETWORK_MAGIC["mainnet"]), per_file, expected,
    )


@pytest.fixture
def db(tmp_path):
    d = tmp_path / "dd"
    d.mkdir()
    return BlockchainDatabase(str(d))


def _tip(db):
    # Bypass BlockchainDatabase's cached tip: read what is on disk.
    h, n = db._db.get_best_block()
    return bytes(h), int(n)


def _all_coins(db) -> set:
    return {
        (bytes(u.txid), int(u.vout), int(u.height), bool(u.is_coinbase),
         int(u.amount), bytes(u.script_pubkey))
        for u in db.iter_utxos()
    }


def test_core_stats_literals(tmp_path, db):
    """txouts / total_amount / bogosize are Core's counters, not aliases.

    kernel/coinstats.cpp ApplyStats: one txid group is one transaction,
    each coin is one txout, total_amount sums nValue, GetBogoSize is
    ``32+4+4+8+2+scriptPubKey.size()`` (50 + script length). One 25-byte
    P2PKH of 50_000 sats is therefore (txouts=1, transactions=1,
    total_amount=50000, bogosize=75).
    """
    spk = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
    assert len(spk) == 25
    coins = [(b"\x11" * 32, 0, 1, False, 50_000, spk)]
    path = _write(tmp_path, "one.dat", _snapshot_bytes(coins))
    _bh, _h, n, digest, ntx, total, bogo = _import(db, path, _expected_hash(coins))
    assert bytes(digest) == _expected_hash(coins)
    assert (n, ntx, total, bogo) == (1, 1, 50_000, 50 + 25)


def test_round_trip_hash_and_coins(tmp_path, db):
    coins = _coins(1)
    want = _expected_hash(coins)
    path = _write(tmp_path, "a.dat", _snapshot_bytes(coins))
    bh, h, n, digest, ntx, total, bogo = _import(db, path, want)

    assert (h, n) == (BASE_HEIGHT, len(coins))
    assert bytes(digest) == want
    assert ntx == len({c[0] for c in coins})
    assert total == sum(c[4] for c in coins)
    assert bogo == sum(50 + len(c[5]) for c in coins)
    assert bh == BASE_HASH[::-1].hex()
    assert _tip(db) == (BASE_HASH, BASE_HEIGHT)

    # Independent read-back: the ordinary Python walk over the DB.
    assert _all_coins(db) == set(coins)
    assert compute_utxo_hash(db, "hash_serialized") == want
    u = db.get_utxo(coins[0][0], coins[0][1])
    assert u is not None and u["value"] == coins[0][4]
    big = [c for c in coins if c[1] == 70000][0]
    u = db.get_utxo(big[0], 70000)
    assert u is not None and u["script_pubkey"] == big[5] and u["height"] == big[2]

    # Staging dir is gone; no in-progress marker survives.
    assert not os.path.exists(os.path.join(db._data_dir, "snapshot-import.tmp"))
    assert db._db.recover_from_crash() is False


def test_no_commitment_still_imports_and_reports_hash(tmp_path, db):
    coins = _coins(2)
    path = _write(tmp_path, "a.dat", _snapshot_bytes(coins))
    out = _import(db, path, None, height=0)  # regtest-style: height unknown
    assert bytes(out[3]) == _expected_hash(coins)
    assert _all_coins(db) == set(coins)


def _assert_untouched(db, coins_before):
    assert _tip(db) == (BASE_HASH, BASE_HEIGHT)
    assert _all_coins(db) == set(coins_before)
    assert not os.path.exists(os.path.join(db._data_dir, "snapshot-import.tmp"))


@pytest.fixture
def seeded(tmp_path, db):
    coins = _coins(3)
    _import(db, _write(tmp_path, "seed.dat", _snapshot_bytes(coins)), _expected_hash(coins))
    return db, coins


def test_wrong_commitment_refused_before_touching_chainstate(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    bad = bytearray(_expected_hash(coins))
    bad[0] ^= 1
    with pytest.raises(ValueError, match="Bad snapshot content hash"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(coins)), bytes(bad))
    _assert_untouched(db, before)


def test_trailing_bytes_refused(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    with pytest.raises(ValueError, match="coins left over"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(coins, trailing=b"\x00")),
                _expected_hash(coins))
    _assert_untouched(db, before)


def test_coin_above_base_height_refused(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    t, v, _h, cb, a, s = coins[5]
    coins[5] = (t, v, BASE_HEIGHT + 1, cb, a, s)
    with pytest.raises(ValueError, match="base_height"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(coins)), _expected_hash(coins))
    _assert_untouched(db, before)


def test_money_range_refused(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    t, v, h, cb, _a, s = coins[2]
    coins[2] = (t, v, h, cb, 21_000_000 * 100_000_000 + 1, s)
    with pytest.raises(ValueError, match="bad tx out value"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(coins)), _expected_hash(coins))
    _assert_untouched(db, before)


def test_out_of_order_txids_refused(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    first = [c for c in coins if c[0] == coins[0][0]]
    rest = [c for c in coins if c[0] != coins[0][0]]
    with pytest.raises(ValueError, match="canonical txid order"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(rest + first)), _expected_hash(coins))
    _assert_untouched(db, before)


def test_truncated_refused(tmp_path, seeded):
    db, before = seeded
    coins = _coins(4)
    with pytest.raises(ValueError, match="truncated"):
        _import(db, _write(tmp_path, "b.dat", _snapshot_bytes(coins, count=len(coins) + 1)),
                _expected_hash(coins))
    _assert_untouched(db, before)


def test_reimport_replaces_populated_chainstate(tmp_path, seeded):
    db, before = seeded
    coins = _coins(5)
    want = _expected_hash(coins)
    other_hash = bytes(reversed(range(32)))
    data = bytearray(_snapshot_bytes(coins))
    data[11:43] = other_hash
    _import(db, _write(tmp_path, "b.dat", bytes(data)), want, height=BASE_HEIGHT + 5)
    assert _tip(db) == (other_hash, BASE_HEIGHT + 5)
    assert _all_coins(db) == set(coins)
    assert compute_utxo_hash(db, "hash_serialized") == want


def test_metadata_header_layout_matches_offsets():
    # The re-import test patches the base hash at bytes [11:43]:
    # magic(5) + version(2) + network magic(4) = 11.
    f = io.BytesIO()
    _write_metadata_header(f, "mainnet", b"\xaa" * 32, 7)
    raw = f.getvalue()
    assert raw[11:43] == b"\xaa" * 32
    assert struct.unpack("<Q", raw[43:51])[0] == 7
