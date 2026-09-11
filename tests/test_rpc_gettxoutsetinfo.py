"""Tests for the ``gettxoutsetinfo`` RPC handler.

The handler walks the live chainstate, accumulating SHA256d
``HashWriter`` digests over Core's ``TxOutSer`` byte format
(kernel/coinstats.cpp:46-51). The on-the-wire shape mirrors Bitcoin
Core's ``rpc/blockchain.cpp::gettxoutsetinfo`` (post-#26553 ``_3``
naming, with a ``_2`` alias for older clients).

Coverage:
- digest matches the standalone ``compute_utxo_hash`` helper
  (so the snapshot dumper and the RPC handler stay byte-identical).
- ``hash_serialized_2`` and ``hash_serialized_3`` keys are aliases
  for the same digest (consumers pinned to either name see equal hex).
- ``muhash`` mode emits the multiplicative incremental digest;
  ``none`` emits no digest field; bogus types raise.
- ``bestblock`` is display-hex (uint256.GetHex byte order), matching
  what ``getbestblockhash`` returns.
- ``txouts``/``transactions``/``total_amount`` reflect the UTXO set.

The handler intentionally targets feature parity with
``gettxoutsetinfo []`` (the harness call shape from
tools/diff-test.sh:1294-1300) -- not the coinstatsindex / hash_or_height
branches, which ouroboros has no index for.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path

import pytest

from ouroboros.muhash import coin_element
from ouroboros.rpc import RPCServer
from ouroboros.snapshot import (
    HashWriter,
    _stream_utxo_txid_groups_from_iter,
    compute_utxo_hash,
    stream_utxo_txid_groups,
)

_REPO = Path(__file__).resolve().parents[1]


@dataclass
class _UTXOEntry:
    txid: bytes
    vout: int
    amount: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool


class _StubDB:
    def __init__(self) -> None:
        self.utxos: list[_UTXOEntry] = []
        # internal-order tip hash; mirror of Rust's get_best_block().
        self.best_hash: bytes = b"\x11" * 32
        self.best_height: int = 0

    def get_best_block(self) -> tuple[bytes, int]:
        return self.best_hash, self.best_height

    def iter_utxos(self):
        return iter(self.utxos)

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        if height == self.best_height:
            return self.best_hash
        return None


def _p2pkh(h160: bytes) -> bytes:
    assert len(h160) == 20
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def _make_rpc(db: _StubDB) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    node.network = "regtest"
    rpc.node = node
    rpc._current_wallet_name = None
    rpc.block_submission_paused = False
    return rpc


def _seed(db: _StubDB) -> None:
    """Three coins, two distinct txids -> 2 transactions / 3 txouts."""
    db.utxos.append(
        _UTXOEntry(
            txid=b"\xaa" * 32,
            vout=0,
            amount=50_000_000,
            script_pubkey=_p2pkh(b"\x01" * 20),
            height=1,
            is_coinbase=True,
        )
    )
    db.utxos.append(
        _UTXOEntry(
            txid=b"\xaa" * 32,
            vout=1,
            amount=25_000_000,
            script_pubkey=_p2pkh(b"\x02" * 20),
            height=1,
            is_coinbase=True,
        )
    )
    db.utxos.append(
        _UTXOEntry(
            txid=b"\xbb" * 32,
            vout=0,
            amount=12_345_678,
            script_pubkey=_p2pkh(b"\x03" * 20),
            height=2,
            is_coinbase=False,
        )
    )


@pytest.mark.asyncio
async def test_gettxoutsetinfo_basic_shape() -> None:
    db = _StubDB()
    db.best_height = 2
    db.best_hash = b"\xcc" * 32
    _seed(db)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo()

    # Field shape matches Core (rpc/blockchain.cpp:1115-1130).
    assert res["height"] == 2
    # uint256.GetHex() == reversed(internal). 0xcc..0xcc reverses to
    # itself, so check the broader principle by comparing to the
    # canonical reversal.
    assert res["bestblock"] == (b"\xcc" * 32)[::-1].hex()
    assert res["txouts"] == 3
    assert res["transactions"] == 2  # two distinct txids
    assert isinstance(res["bogosize"], int)
    assert res["bogosize"] > 0
    # 50M + 25M + 12.345678M sats = 0.87345678 BTC
    assert res["total_amount"].text == "0.87345678"  # BTCAmount, Core %d.%08d
    # Default hash_type is hash_serialized_3 (Core post-#26553).
    assert "hash_serialized_3" in res
    assert "hash_serialized_2" in res
    assert res["hash_serialized_2"] == res["hash_serialized_3"]
    assert "muhash" not in res


@pytest.mark.asyncio
async def test_gettxoutsetinfo_matches_compute_utxo_hash() -> None:
    """The RPC digest must equal the standalone snapshot helper.

    ``compute_utxo_hash`` is the same byte-walk that the snapshot
    dumper / loadtxoutset strict gate use (snapshot.py:1171), and is
    independently tested against fixed vectors in test_snapshot.py.
    Re-using its output as the oracle pins the RPC to the same
    SHA256d-over-TxOutSer construction.
    """
    from ouroboros.snapshot import compute_utxo_hash

    db = _StubDB()
    db.best_height = 7
    db.best_hash = b"\xab" * 32
    _seed(db)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo()
    expected = compute_utxo_hash(db, hash_type="hash_serialized")
    # uint256 display hex == reversed internal bytes.
    assert res["hash_serialized_3"] == expected[::-1].hex()


@pytest.mark.asyncio
async def test_gettxoutsetinfo_muhash_matches_compute_utxo_hash() -> None:
    from ouroboros.snapshot import compute_utxo_hash

    db = _StubDB()
    db.best_height = 9
    _seed(db)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo(hash_type="muhash")
    expected = compute_utxo_hash(db, hash_type="muhash")
    assert res["muhash"] == expected[::-1].hex()
    # Mutually exclusive with the SHA256d field set.
    assert "hash_serialized_3" not in res
    assert "hash_serialized_2" not in res


@pytest.mark.asyncio
async def test_gettxoutsetinfo_hash_type_aliases() -> None:
    """Old ``hash_serialized``, new ``hash_serialized_3``, and the
    legacy ``hash_serialized_2`` keyword must all return the same
    SHA256d digest. The harness probes the response keys in that
    fallback order (diff-test.sh:1300)."""
    db = _StubDB()
    _seed(db)
    rpc = _make_rpc(db)

    r3 = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_3")
    r2 = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized_2")
    rh = await rpc.rpc_gettxoutsetinfo(hash_type="hash_serialized")

    digest = r3["hash_serialized_3"]
    assert digest == r2["hash_serialized_3"] == rh["hash_serialized_3"]
    assert r3["hash_serialized_2"] == r2["hash_serialized_2"] == digest


@pytest.mark.asyncio
async def test_gettxoutsetinfo_hash_type_none_omits_digest() -> None:
    db = _StubDB()
    _seed(db)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo(hash_type="none")
    assert "hash_serialized_3" not in res
    assert "hash_serialized_2" not in res
    assert "muhash" not in res
    # Stats fields still present.
    assert res["txouts"] == 3
    assert res["transactions"] == 2


@pytest.mark.asyncio
async def test_gettxoutsetinfo_rejects_unknown_hash_type() -> None:
    # Core's ParseHashType throws RPC_INVALID_PARAMETER (-8) for an
    # unrecognized keyword; ouroboros mirrors that via RpcError so the
    # JSON-RPC envelope carries the same numeric code (rpc/blockchain.cpp).
    from ouroboros.rpc import RPC_INVALID_PARAMETER, RpcError

    db = _StubDB()
    rpc = _make_rpc(db)

    with pytest.raises(RpcError) as exc:
        await rpc.rpc_gettxoutsetinfo(hash_type="sha3-512")
    assert exc.value.code == RPC_INVALID_PARAMETER
    assert "not a valid hash_type" in exc.value.message


@pytest.mark.asyncio
async def test_gettxoutsetinfo_hash_serialized_specific_block_rejected() -> None:
    """``hash_serialized_3`` (the default) for a specific block/height must
    raise RPC_INVALID_PARAMETER (-8) -- it can only be computed for the tip
    (rpc/blockchain.cpp:1090-1092). Mirrors Core even without coinstatsindex,
    so clients see -8 rather than silently getting tip stats."""
    from ouroboros.rpc import RPC_INVALID_PARAMETER, RpcError

    db = _StubDB()
    rpc = _make_rpc(db)

    with pytest.raises(RpcError) as exc:
        await rpc.rpc_gettxoutsetinfo(
            hash_type="hash_serialized_3",
            hash_or_height=2,
        )
    assert exc.value.code == RPC_INVALID_PARAMETER
    assert "cannot be queried for a specific block" in exc.value.message

    # height 0 is a valid "specific block" too (truthiness must not gate it).
    with pytest.raises(RpcError) as exc0:
        await rpc.rpc_gettxoutsetinfo(
            hash_type="hash_serialized_3",
            hash_or_height=0,
        )
    assert exc0.value.code == RPC_INVALID_PARAMETER


@pytest.mark.asyncio
async def test_gettxoutsetinfo_specific_block_requires_index() -> None:
    """A specific block with a non-hash_serialized hash_type still needs
    coinstatsindex, which ouroboros lacks -> RPC_INVALID_PARAMETER (-8)
    (rpc/blockchain.cpp:1086-1088)."""
    from ouroboros.rpc import RPC_INVALID_PARAMETER, RpcError

    db = _StubDB()
    rpc = _make_rpc(db)

    with pytest.raises(RpcError) as exc:
        await rpc.rpc_gettxoutsetinfo(hash_type="muhash", hash_or_height=2)
    assert exc.value.code == RPC_INVALID_PARAMETER
    assert "coinstatsindex" in exc.value.message


@pytest.mark.asyncio
async def test_gettxoutsetinfo_empty_chainstate() -> None:
    db = _StubDB()
    db.best_height = 0
    db.best_hash = bytes(32)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo()
    assert res["height"] == 0
    assert res["txouts"] == 0
    assert res["transactions"] == 0
    assert res["total_amount"].text == "0.00000000"  # BTCAmount, Core %d.%08d
    # Empty SHA256d chain (HashWriter over no input) is still a
    # well-defined 32-byte digest, not absent.
    assert isinstance(res["hash_serialized_3"], str)
    assert len(res["hash_serialized_3"]) == 64


@pytest.mark.asyncio
async def test_gettxoutsetinfo_bestblock_is_display_hex() -> None:
    """``bestblock`` must be in display-hex (reversed internal),
    matching Core's ``uint256.GetHex()`` output and what
    ``getbestblockhash`` returns. This is what the diff-test
    harness compares against ``tip_after`` when checking reorg
    behaviour."""
    db = _StubDB()
    # Pick a non-palindromic tip hash so a missing reverse fails loudly.
    internal = bytes(range(32))
    db.best_hash = internal
    db.best_height = 1
    _seed(db)
    rpc = _make_rpc(db)

    res = await rpc.rpc_gettxoutsetinfo()
    expected_display = internal[::-1].hex()
    assert res["bestblock"] == expected_display
    assert res["bestblock"] != internal.hex()


def test_gettxoutsetinfo_streams_does_not_materialise_the_coin_set() -> None:
    """Revert control for QUEUES.md ouroboros item 0.

    Pre-fix ``rpc_gettxoutsetinfo`` / ``compute_utxo_hash`` collected every
    coin into a list and sorted it, and Rust ``iter_utxos`` had already
    built a Vec of the chainstate. Restoring those lines — or dropping
    STREAMING-HASH — must fail here. Pattern: haskoin
    ``dumpTxOutSetFromDB streams``.
    """
    rpc_src = inspect.getsource(RPCServer.rpc_gettxoutsetinfo)
    assert "list(self.node.db.iter_utxos())" not in rpc_src
    assert "self.node.db.iter_utxos" not in rpc_src
    assert "utxos.sort" not in rpc_src
    assert "stream_utxo_txid_groups" in rpc_src
    assert "STREAMING-HASH" in rpc_src

    rpc_file = (_REPO / "src/ouroboros/rpc.py").read_text(encoding="utf-8")
    assert "utxos = list(self.node.db.iter_utxos())" not in rpc_file

    hash_src = inspect.getsource(compute_utxo_hash)
    assert "list(db.iter_utxos())" not in hash_src
    assert "utxos.sort" not in hash_src
    assert "stream_utxo_txid_groups" in hash_src

    walk_src = inspect.getsource(stream_utxo_txid_groups)
    assert "visit_utxo_txid_groups" in walk_src
    assert "STREAMING-HASH" in walk_src
    assert "list(db.iter_utxos())" not in walk_src

    db_rs = (_REPO / "ferrous-utils/sync/src/storage/db.rs").read_text(
        encoding="utf-8",
    )
    assert "pub fn stream_utxo_txid_groups" in db_rs
    assert "BTreeMap<u32, UTXO>" in db_rs
    lib_rs = (_REPO / "ferrous-utils/sync/src/lib.rs").read_text(encoding="utf-8")
    assert "fn visit_utxo_txid_groups" in lib_rs


def test_stream_utxo_txid_groups_peak_is_the_widest_txid_not_the_set() -> None:
    """Runtime proof of the RAM bound: 50 singleton txids + one txid
    with 80 outputs + one txid with vouts {0,1,256} (LE-key order !=
    numeric). Peak live group must be 80, not 50+80+3. A walk that
    materialises the set and then reports length as "peak" fails this.
    """
    db = _StubDB()

    def coin(tid: bytes, vout: int) -> _UTXOEntry:
        return _UTXOEntry(
            txid=tid,
            vout=vout,
            amount=1,
            script_pubkey=_p2pkh(b"\x01" * 20),
            height=1,
            is_coinbase=False,
        )

    for b in range(1, 51):
        db.utxos.append(coin(bytes([b]) + b"\x00" * 31, 0))
    wide = b"\xaa" * 32
    for n in range(80):
        db.utxos.append(coin(wide, n))
    le = b"\xbb" * 32
    for n in (0, 1, 256):
        db.utxos.append(coin(le, n))

    n, peak = stream_utxo_txid_groups(db, lambda *_: None)
    assert n == 50 + 80 + 3
    assert peak == 80

    # LE32 key order visits vout 256 before vout 1; the grouper must
    # still flush numeric map order (Core std::map<uint32_t, Coin>).
    le_ordered = sorted(
        db.utxos,
        key=lambda u: (u.txid, int(u.vout).to_bytes(4, "little")),
    )
    groups: dict[bytes, list[int]] = {}

    def capture(tid, outputs) -> None:
        groups[tid] = list(outputs)

    n2, peak2 = _stream_utxo_txid_groups_from_iter(le_ordered, capture)
    assert n2 == n
    assert peak2 == 80
    assert groups[le] == [0, 1, 256]


def test_compute_utxo_hash_vout_256_is_numeric_map_order_not_le_key_order() -> None:
    """HASH_SERIALIZED must follow Core's numeric vout map, not RocksDB
    LE32 key order. vout 256 = 00 01 00 00 sorts before vout 1.
    """
    tid = b"\xcc" * 32
    coins = [
        _UTXOEntry(
            txid=tid,
            vout=0,
            amount=10,
            script_pubkey=_p2pkh(b"\x01" * 20),
            height=7,
            is_coinbase=False,
        ),
        _UTXOEntry(
            txid=tid,
            vout=256,
            amount=30,
            script_pubkey=_p2pkh(b"\x03" * 20),
            height=7,
            is_coinbase=False,
        ),
        _UTXOEntry(
            txid=tid,
            vout=1,
            amount=20,
            script_pubkey=_p2pkh(b"\x02" * 20),
            height=7,
            is_coinbase=False,
        ),
    ]
    db = _StubDB()
    db.utxos = list(coins)
    by_vout = {c.vout: c for c in coins}

    def feed(order: tuple[int, ...]) -> bytes:
        h = HashWriter()
        for v in order:
            u = by_vout[v]
            h.update(
                coin_element(
                    txid=u.txid,
                    vout=u.vout,
                    height=u.height,
                    is_coinbase=u.is_coinbase,
                    amount=u.amount,
                    script_pubkey=u.script_pubkey,
                )
            )
        return h.digest()

    numeric = feed((0, 1, 256))
    le_order = feed((0, 256, 1))
    assert numeric != le_order
    assert compute_utxo_hash(db, hash_type="hash_serialized") == numeric


@pytest.mark.asyncio
async def test_gettxoutsetinfo_hash_matches_numeric_vout_group() -> None:
    """RPC digest must match compute_utxo_hash on the LE-vs-numeric trap."""
    tid = b"\xdd" * 32
    db = _StubDB()
    db.best_height = 3
    db.utxos = [
        _UTXOEntry(
            txid=tid,
            vout=v,
            amount=100 + v,
            script_pubkey=_p2pkh(b"\x04" * 20),
            height=3,
            is_coinbase=True,
        )
        for v in (0, 256, 1)
    ]
    rpc = _make_rpc(db)
    res = await rpc.rpc_gettxoutsetinfo()
    expected = compute_utxo_hash(db, hash_type="hash_serialized")
    assert res["hash_serialized_3"] == expected[::-1].hex()
    assert res["transactions"] == 1
    assert res["txouts"] == 3
