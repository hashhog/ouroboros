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

from dataclasses import dataclass

import pytest

from ouroboros.rpc import RPCServer


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
    db.utxos.append(_UTXOEntry(
        txid=b"\xaa" * 32, vout=0, amount=50_000_000,
        script_pubkey=_p2pkh(b"\x01" * 20),
        height=1, is_coinbase=True,
    ))
    db.utxos.append(_UTXOEntry(
        txid=b"\xaa" * 32, vout=1, amount=25_000_000,
        script_pubkey=_p2pkh(b"\x02" * 20),
        height=1, is_coinbase=True,
    ))
    db.utxos.append(_UTXOEntry(
        txid=b"\xbb" * 32, vout=0, amount=12_345_678,
        script_pubkey=_p2pkh(b"\x03" * 20),
        height=2, is_coinbase=False,
    ))


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
    assert abs(res["total_amount"] - 0.87345678) < 1e-9
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
    from fastapi import HTTPException

    db = _StubDB()
    rpc = _make_rpc(db)

    with pytest.raises(HTTPException) as exc:
        await rpc.rpc_gettxoutsetinfo(hash_type="sha3-512")
    assert exc.value.status_code == 400


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
    assert res["total_amount"] == 0.0
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
