"""A disconnected block's segwit txs go back to the mempool WITH their witness.

Core (validation.cpp): DisconnectTip reads the block from disk with
ReadBlock (witnesses included) and puts its txs in
DisconnectedBlockTransactions; MaybeUpdateMempoolForReorg re-submits each
one to AcceptToMemoryPool.  A segwit spend therefore comes back exactly as
it was confirmed.

ouroboros built the disconnect pool from ``db.get_block_by_height`` /
``db.get_block``, which round-trip through the Rust ``PyTxIn`` -- it has no
witness field -- so every segwit input came back with an empty witness,
failed its script check in ATMP, and was dropped.  On the Core v31.1 regtest
harness that is the ``done-ouroboros-mempool-readd-after-invalidate`` rows:
after invalidateblock Core's mempool holds the disconnected txs, ouroboros's
is empty (warden_b/c/d/e, warden_invalidated_submit).

These tests drive the production RPC handlers against the real Rust DB, the
real Mempool and the real TransactionValidator (script checks included), on a
P2WSH(OP_TRUE) coin.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import (  # noqa: E402
    BASE_TIME,
    COIN,
    FUNDING,
    REGTEST_BITS,
    Chain,
    dsha,
    merkle_root,
    ser_tx,
    varint,
)

TIP = 10
WITNESS_SCRIPT = b"\x51"  # OP_TRUE
P2WSH = b"\x00\x20" + hashlib.sha256(WITNESS_SCRIPT).digest()
FEE = 1_000


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _segwit_spend(prev_txid: bytes, value: int, witness=(WITNESS_SCRIPT,)):
    """(legacy bytes, wire bytes) of a 1-in 1-out spend of a P2WSH(OP_TRUE)."""
    tx_in = prev_txid + struct.pack("<I", 0) + b"\x00" + struct.pack("<I", 0xFFFFFFFE)
    tx_out = struct.pack("<Q", value - FEE) + varint(len(P2WSH)) + P2WSH
    legacy = struct.pack("<I", 2) + b"\x01" + tx_in + b"\x01" + tx_out + struct.pack("<I", 0)
    wit = varint(len(witness)) + b"".join(varint(len(w)) + w for w in witness)
    wire = (struct.pack("<I", 2) + b"\x00\x01" + b"\x01" + tx_in + b"\x01" + tx_out
            + wit + struct.pack("<I", 0))
    return legacy, wire


def _segwit_block(prev: bytes, height: int, txs, tag: bytes = b"N"):
    """Block [coinbase with BIP141 commitment] + txs (each (legacy, wire))."""
    wroot = merkle_root([bytes(32)] + [dsha(w) for _l, w in txs])
    commit = b"\x6a\x24\xaa\x21\xa9\xed" + dsha(wroot + bytes(32))
    h_push = bytes([0x50 + height]) if 1 <= height <= 16 else (
        bytes([1]) + height.to_bytes(1, "little"))
    cb = ser_tx([(b"\x00" * 32, 0xFFFFFFFF, h_push + b"\x02" + tag, 0xFFFFFFFF)],
                [(50 * COIN, b"\x51"), (0, commit)])
    cb_wire = cb[:4] + b"\x00\x01" + cb[4:-4] + b"\x01\x20" + bytes(32) + cb[-4:]
    root = merkle_root([dsha(cb)] + [dsha(lg) for lg, _w in txs])
    for nonce in range(4_000_000):
        header = (struct.pack("<i", 0x20000000) + prev + root
                  + struct.pack("<III", BASE_TIME + height * 600 + 1, REGTEST_BITS, nonce))
        bh = dsha(header)
        if bh[31] < 0x7F:
            return header + varint(1 + len(txs)) + cb_wire + b"".join(w for _l, w in txs), bh
    raise RuntimeError("could not solve regtest header")  # pragma: no cover


def _setup(tmp_path):
    from ouroboros.block_sync import BlockSync
    from ouroboros.database import BlockchainDatabase
    from ouroboros.mempool import Mempool
    from ouroboros.rpc import RPCServer
    from ouroboros.validation import TransactionValidator

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    chain = Chain(bdb._db, tip=TIP)
    fund = dsha(b"witness-fund")
    bdb._db.add_utxo_raw(fund, 0, FUNDING, P2WSH, 1, False)
    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    if hasattr(bs, "load_rpc_invalidated"):
        bs.load_rpc_invalidated(str(tmp_path / "invalidated_blocks.json"))
    mempool = Mempool(TransactionValidator(bdb, network="regtest"), require_standard=False)
    node = SimpleNamespace(network="regtest", validator=None, mempool=mempool,
                           db=bdb, block_sync=bs, data_dir=str(tmp_path))
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    server._side_branch_max_entries = 1024
    return bdb, chain, bs, server, mempool, fund


def _tx(wire: bytes):
    from ouroboros.p2p_messages import TxMessage
    return TxMessage.from_payload(wire, 0).transaction


def _mine_segwit_spend(bdb, chain, fund):
    legacy, wire = _segwit_spend(fund, FUNDING)
    raw, bh = _segwit_block(chain.tip_hash, TIP + 1, [(legacy, wire)])
    bdb._db.connect_block_from_bytes(raw, TIP + 1, "regtest")
    assert bdb.get_best_block() == (bh, TIP + 1)
    return dsha(legacy), dsha(wire), bh


def test_controls_validator_needs_the_witness(tmp_path):
    """Instrument check: the real validator accepts the spend with its
    witness and refuses it without one, so the tests below measure the
    witness and not a stub that accepts anything."""
    bdb, _chain, _bs, _server, mempool, fund = _setup(tmp_path)
    stripped, wire = _segwit_spend(fund, FUNDING)  # stripped = no witness
    ok, err = mempool.add_transaction(_tx(stripped), height=TIP)
    assert not ok, "an empty witness on a P2WSH spend must fail the script check"
    ok, err = mempool.add_transaction(_tx(wire), height=TIP)
    assert ok, err


def test_invalidateblock_readds_segwit_tx_with_its_witness(tmp_path):
    bdb, chain, _bs, server, mempool, fund = _setup(tmp_path)
    txid, wtxid, bh = _mine_segwit_spend(bdb, chain, fund)
    asyncio.run(server.rpc_invalidateblock(bh[::-1].hex()))
    assert bdb.get_best_block()[1] == TIP
    assert txid in mempool.transactions, (
        "Core re-adds the disconnected segwit spend to the mempool")
    assert mempool.transactions[txid].tx.get_wtxid() == wtxid, "witness lost"


def test_submitblock_reorg_readds_segwit_tx_with_its_witness(tmp_path):
    bdb, chain, _bs, server, mempool, fund = _setup(tmp_path)
    txid, wtxid, _bh = _mine_segwit_spend(bdb, chain, fund)
    raw_a, ha = _segwit_block(chain.tip_hash, TIP + 1, [], tag=b"A")
    raw_b, hb = _segwit_block(ha, TIP + 2, [], tag=b"B")
    asyncio.run(server.rpc_submitblock(raw_a.hex()))
    asyncio.run(server.rpc_submitblock(raw_b.hex()))
    assert bdb.get_best_block() == (hb, TIP + 2), "side branch did not win"
    assert txid in mempool.transactions, (
        "Core re-adds the reorged-out segwit spend to the mempool")
    assert mempool.transactions[txid].tx.get_wtxid() == wtxid, "witness lost"


def test_get_block_with_witness_matches_the_stored_bytes(tmp_path):
    bdb, chain, _bs, _server, _mempool, fund = _setup(tmp_path)
    _txid, wtxid, bh = _mine_segwit_spend(bdb, chain, fund)
    assert bdb.get_block(bh).transactions[1].get_wtxid() != wtxid  # why it exists
    blk = bdb.get_block_with_witness(bh)
    assert blk.transactions[1].get_wtxid() == wtxid
    assert blk.hash == bh



def test_verbose_mempool_rpcs_report_the_readded_tx(tmp_path):
    """Once the refill puts a tx back, the verbose mempool RPCs must describe
    it.  ``_format_mempool_entry`` called helpers (``_display_hash`` /
    ``_display_txid``) that are local to other methods, so both RPCs raised
    NameError -> -32603 for any tx in the pool (Core v31.1 regtest rows
    warden_invalidated_submit/after-invalidate-tip/pool, warden_d/e entry-*).
    Core entryToJSON: ``wtxid`` is the display-order (reversed) wtxid."""
    bdb, chain, _bs, server, mempool, fund = _setup(tmp_path)
    txid, wtxid, bh = _mine_segwit_spend(bdb, chain, fund)
    asyncio.run(server.rpc_invalidateblock(bh[::-1].hex()))
    assert txid in mempool.transactions

    pool = asyncio.run(server.rpc_getrawmempool(True))
    assert list(pool) == [txid[::-1].hex()]
    assert pool[txid[::-1].hex()]["wtxid"] == wtxid[::-1].hex()

    entry = asyncio.run(server.rpc_getmempoolentry(txid[::-1].hex()))
    assert entry["wtxid"] == wtxid[::-1].hex()
    assert entry["wtxid"] != txid[::-1].hex(), "segwit wtxid must differ from txid"
    assert entry == pool[txid[::-1].hex()]
