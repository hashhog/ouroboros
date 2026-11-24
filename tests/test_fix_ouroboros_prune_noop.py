"""``-prune`` deletes block data, like Core's ``-prune=N`` (fix-ouroboros-prune-noop).

The node built ``BlockPruner(db=<BlockchainDatabase>)``, but the pruner only
knew the flat-file ``PyBlockStore`` API: every automatic pass called
``BlockchainDatabase.prune_to_target``, which does not exist, and the node
logged the AttributeError at DEBUG.  ``-prune`` deleted nothing, and
``pruneblockchain`` raised the same way.

These tests drive the pruner over the REAL compiled ``sync`` extension and a
real RocksDB chain (regtest blocks connected through
``connect_block_from_bytes``), and check what Core guarantees:

* block bodies (BLOCKS_CF) and undo records (UNDO_CF) more than 288 blocks
  below the tip are deleted until the stored data fits the target;
* the last 288 blocks below the tip are never deleted, whatever the target;
* headers stay (block index), so getheaders / the retarget ancestor answer;
* a pruned node still reorgs across the last 288 blocks (submitblock);
* a pruner failure is logged at ERROR, not swallowed.

Core: node/blockstorage.cpp FindFilesToPrune / PruneOneBlockFile,
validation.h MIN_BLOCKS_TO_KEEP, rpc/blockchain.cpp pruneblockchain.
"""

from __future__ import annotations

import asyncio
import logging
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import (  # noqa: E402
    BASE_TIME,
    COIN,
    FUNDING,
    OP_TRUE,
    Chain,
    build_block,
    coinbase_tx,
    spend,
)

KEEP = 288
TIP = 600
SPEND_H = TIP - 100  # a block inside the kept window that spends a coin
OLD_SPEND_H = 100  # a block that gets pruned, also with a spend (undo data)


def _subsidy(h: int) -> int:
    """Regtest block subsidy (nSubsidyHalvingInterval = 150)."""
    return (50 * COIN) >> (h // 150)


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _chain(tmp_path, tip: int = TIP):
    """A real DB holding regtest blocks 0..tip; block SPEND_H spends fund[0]
    and block OLD_SPEND_H spends fund[1], so both carry undo records."""
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    base = Chain(bdb._db, tip=2, n_fund=2)
    prev = base.tip_hash
    for h in range(3, tip + 1):
        txs = [coinbase_tx(h, value=_subsidy(h), tag=b"\x03P" + h.to_bytes(2, "little"))]
        if h == SPEND_H:
            txs.append(spend(base.fund[0], 0, [(FUNDING - 1000, OP_TRUE)]))
        if h == OLD_SPEND_H:
            txs.append(spend(base.fund[1], 0, [(FUNDING - 1000, OP_TRUE)]))
        raw, bh = build_block(prev, BASE_TIME + h * 600, txs)
        bdb._db.connect_block_from_bytes(raw, h, "regtest")
        prev = bh
    bdb.refresh_tip_cache()
    assert bdb.get_best_block() == (prev, tip)
    return bdb, base


def _body_len(bdb, h: int) -> int:
    raw = bdb.get_block_bytes(bytes(bdb.get_block_hash_by_height(h)))
    return 0 if raw is None else len(raw)


def _stored(bdb, tip: int) -> list[int]:
    return [h for h in range(tip + 1) if bdb.has_block_data(h)]


def _pruner(bdb, target_bytes: int):
    """The pruner exactly as Node.start builds it (prune=550), with the byte
    target lowered: regtest blocks are ~100 bytes, so Core's 550 MiB floor
    would never be reached in a test."""
    from ouroboros.pruning import BlockPruner

    p = BlockPruner(db=bdb, target_size_mb=550, keep_blocks=KEEP)
    p.target_size = target_bytes
    return p


# ---------------------------------------------------------------------------
# automatic pruning (Node._periodic_tasks -> BlockPruner.prune_blocks)
# ---------------------------------------------------------------------------


def test_auto_prune_deletes_block_and_undo_data_below_the_target_window(tmp_path):
    bdb, base = _chain(tmp_path)
    assert _stored(bdb, TIP) == list(range(TIP + 1))
    # connect_block_from_bytes keeps a block's undo data as the SPENT_CF row
    # of each coin it spent; both spent coins have one.
    assert bdb.get_utxo(base.fund[1], 0) is None
    assert bdb.get_utxo_or_spent(base.fund[1], 0) is not None
    assert bdb.get_utxo_or_spent(base.fund[0], 0) is not None
    target = sum(_body_len(bdb, h) for h in range(TIP - 349, TIP + 1))  # ~350 bodies

    pruned, retained = _pruner(bdb, target).prune_blocks(TIP)

    kept = _stored(bdb, TIP)
    assert pruned > 0
    assert len(kept) < TIP + 1, "nothing was pruned"
    low = kept[0]
    # One contiguous window up to the tip; everything below it is gone.
    assert kept == list(range(low, TIP + 1))
    assert pruned == low
    assert bdb.get_prune_height() == low
    # The kept window fits the target (bodies + undo) ...
    assert sum(_body_len(bdb, h) for h in kept) <= retained <= target
    # ... and is most of it: the cut is near the ~350-body target, not at
    # the 289-block keep floor and not at the genesis.
    assert 289 < len(kept) <= 350
    # Undo data goes with the body; the kept window keeps its undo.
    assert OLD_SPEND_H < low <= SPEND_H
    assert bdb.get_utxo_or_spent(base.fund[1], 0) is None
    assert bdb.get_utxo_or_spent(base.fund[0], 0) is not None
    # The block index (and the header) outlives the body, as CBlockIndex does.
    for h in (0, 1, low - 1):
        bh = bytes(bdb.get_block_hash_by_height(h))
        assert bdb.get_block_bytes(bh) is None
        hdr = bdb.get_index_header_bytes(bh)
        assert hdr is not None and len(hdr) == 80


def test_auto_prune_never_deletes_the_last_288_blocks(tmp_path):
    bdb, _ = _chain(tmp_path)
    pruned, _ = _pruner(bdb, 1).prune_blocks(TIP)  # target far below one block
    kept = _stored(bdb, TIP)
    # Blocks MORE than 288 below the tip go; tip-288 .. tip (289 blocks) stay:
    # tip-288 is the fork point of a 288-deep reorg.
    assert kept == list(range(TIP - KEEP, TIP + 1))
    assert pruned == TIP - KEEP


def test_auto_prune_under_target_deletes_nothing(tmp_path):
    bdb, _ = _chain(tmp_path)
    total = sum(_body_len(bdb, h) for h in range(TIP + 1))
    pruned, retained = _pruner(bdb, total * 4).prune_blocks(TIP)
    assert pruned == 0
    assert _stored(bdb, TIP) == list(range(TIP + 1))
    assert bdb.get_prune_height() == 0
    assert total <= retained <= total * 4


def test_auto_prune_is_incremental_as_the_tip_advances(tmp_path):
    """A second pass after more blocks prunes only the newly-old blocks."""
    bdb, base = _chain(tmp_path)
    p = _pruner(bdb, 1)
    p.prune_blocks(TIP)
    assert bdb.get_prune_height() == TIP - KEEP
    prev, tip = bdb.get_best_block()
    for h in range(tip + 1, tip + 11):
        raw, prev = build_block(prev, BASE_TIME + h * 600, [coinbase_tx(h, value=_subsidy(h), tag=b"\x04I")])
        bdb._db.connect_block_from_bytes(raw, h, "regtest")
    bdb.refresh_tip_cache()
    pruned, _ = p.prune_blocks(TIP + 10)
    assert pruned == 10
    assert _stored(bdb, TIP + 10) == list(range(TIP + 10 - KEEP, TIP + 11))


def test_auto_prune_first_pass_is_bounded_and_the_next_pass_finishes(tmp_path):
    """One step (it holds the chain lock) deletes at most 2000 bodies (and
    stops after ~1 s); a first prune of a long chain completes over the
    following steps, and ``pending`` says when another step is due."""
    tip = 2600
    bdb, _ = _chain(tmp_path, tip=tip)
    p = _pruner(bdb, 1)
    first = p.prune_blocks(tip)[0]
    assert 0 < first <= 2000
    assert p.pending is True
    assert _stored(bdb, tip)[0] == first
    total, steps = first, 1
    while p.pending:
        total += p.prune_blocks(tip)[0]
        steps += 1
        assert steps < 100
    assert total == tip - KEEP
    assert _stored(bdb, tip) == list(range(tip - KEEP, tip + 1))
    assert p.prune_blocks(tip)[0] == 0 and p.pending is False


def test_pruneblockchain_releases_the_chain_lock_between_steps(tmp_path):
    """A long manual prune must not wedge the chain: another chain-lock
    holder (a block connect) gets the lock while it is still pruning."""
    from ouroboros.chainlock import chain_lock

    tip = 4600  # 4311 bodies to prune: at least 3 bounded steps
    bdb, _ = _chain(tmp_path, tip=tip)
    server = _server(bdb, str(tmp_path), _pruner(bdb, 1))
    seen = []

    async def scenario():
        server._deployment_cache = {}
        server._deployment_cache_height = -1
        server._deployment_cache_network = ""
        server._current_wallet_name = None
        req = {"jsonrpc": "2.0", "method": "pruneblockchain", "params": [tip], "id": 1}
        rpc = asyncio.create_task(server._execute_single_rpc(req))
        # Wait until the first step is deleting (its marker is written every
        # 1000 heights), then queue behind it like a block connect would.
        for _ in range(10_000):
            if bdb.get_prune_height() > 0 or rpc.done():
                break
            await asyncio.sleep(0.001)

        async def other_writer():
            async with chain_lock(server.node):
                seen.append((rpc.done(), bdb.get_prune_height()))

        await other_writer()
        return await rpc

    resp = asyncio.run(scenario())
    assert resp.get("error") is None, resp
    assert resp.get("result") == tip - KEEP - 1
    assert seen and seen[0][0] is False, seen  # got the lock mid-prune
    assert 0 < seen[0][1] < tip - KEEP, seen


def test_auto_prune_waits_for_prune_after_height():
    """Core nPruneAfterHeight (regtest 1000): no pruning below it."""
    from ouroboros.pruning import BlockPruner

    store = MagicMock()
    p = BlockPruner(db=store, target_size_mb=550, network="regtest")
    assert p.prune_after_height == 1000
    assert p.prune_blocks(1000) == (0, 0)
    store.prune_block_data_to_target.assert_not_called()
    store.prune_block_data_to_target.return_value = (5, 123, False)
    assert p.prune_blocks(1001) == (5, 123)


def test_target_is_mebibytes_like_core():
    """Core: -prune=N is N * 1024 * 1024 bytes (blockmanager_args.cpp)."""
    from ouroboros.pruning import BlockPruner

    assert BlockPruner(db=MagicMock(), target_size_mb=550).target_size == 550 * 1024 * 1024
    assert BlockPruner(db=MagicMock(), target_size_mb=2000).target_size == 2000 * 1024 * 1024


# ---------------------------------------------------------------------------
# pruneblockchain (BlockPruner.prune_to_height)
# ---------------------------------------------------------------------------


def test_pruneblockchain_prunes_to_height_and_returns_highest_pruned(tmp_path):
    bdb, _ = _chain(tmp_path)
    p = _pruner(bdb, 1)
    assert p.prune_to_height(200, TIP) == 200
    assert _stored(bdb, TIP) == list(range(201, TIP + 1))
    # Asking past the keep window is capped, as Core caps to the window.
    assert p.prune_to_height(TIP, TIP) == TIP - KEEP - 1
    assert _stored(bdb, TIP) == list(range(TIP - KEEP, TIP + 1))
    # Asking below what is already pruned changes nothing.
    assert p.prune_to_height(10, TIP) == TIP - KEEP - 1


def test_pruneblockchain_rpc_reports_minus_one_when_nothing_pruned(tmp_path):
    bdb, _ = _chain(tmp_path, tip=KEEP)  # too short to prune anything
    assert _pruner(bdb, 1).prune_to_height(100, KEEP) == -1
    assert _stored(bdb, KEEP) == list(range(KEEP + 1))


def _rpc(server, method: str, params):
    """Through the JSON-RPC dispatcher, as a client call arrives."""
    server._deployment_cache = {}
    server._deployment_cache_height = -1
    server._deployment_cache_network = ""
    server._current_wallet_name = None
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    resp = asyncio.run(server._execute_single_rpc(req))
    err = resp.get("error")
    return (None, resp.get("result")) if not err else (err.get("code"), err.get("message"))


def test_pruneblockchain_rpc_prunes_and_answers_like_core(tmp_path):
    """rpc/blockchain.cpp pruneblockchain: errors, the timestamp form, and
    the returned height, through the dispatcher on a real pruned DB."""
    from ouroboros.pruning import BlockPruner

    bdb, _ = _chain(tmp_path)
    server = _server(bdb, str(tmp_path), _pruner(bdb, 1))
    assert _rpc(server, "pruneblockchain", [-1]) == (-8, "Negative block height.")
    assert _rpc(server, "pruneblockchain", [TIP + 1]) == (
        -8, "Blockchain is shorter than the attempted prune height.")
    # A value above 1e9 is a time: the earliest block at least (t - 2h).
    t = BASE_TIME + 150 * 600 + 7200
    assert _rpc(server, "pruneblockchain", [t]) == (None, 150)
    assert _stored(bdb, TIP)[0] == 151
    assert _rpc(server, "pruneblockchain", [250]) == (None, 250)
    assert _stored(bdb, TIP) == list(range(251, TIP + 1))
    # regtest nPruneAfterHeight is 1000: a 600-block chain is too short.
    server.node.pruner = BlockPruner(db=bdb, target_size_mb=550, network="regtest")
    assert _rpc(server, "pruneblockchain", [300]) == (-1, "Blockchain is too short for pruning.")
    # Not in prune mode at all.
    server.node.pruner = None
    assert _rpc(server, "pruneblockchain", [300]) == (
        -1, "Cannot prune blocks because node is not in prune mode.")


# ---------------------------------------------------------------------------
# getblockchaininfo on a pruned node
# ---------------------------------------------------------------------------


def test_getblockchaininfo_prune_fields_are_cores(tmp_path):
    """getblockchaininfo on a pruned node (rpc/blockchain.cpp): pruned is
    prune MODE, plus pruneheight / automatic_pruning / prune_target_size and
    none of the pruner's own diagnostics.  Before the fix this call raised:
    get_prune_info() called get_prune_stats(), which the chain DB lacks."""
    from ouroboros.pruning import BlockPruner

    bdb, _ = _chain(tmp_path)
    p = _pruner(bdb, 1)
    server = _server(bdb, str(tmp_path), p)
    code, info = _rpc(server, "getblockchaininfo", [])
    assert code is None, info
    assert info["pruned"] is True  # prune mode, before anything is pruned
    assert info["pruneheight"] == 0
    p.prune_blocks(TIP)
    code, info = _rpc(server, "getblockchaininfo", [])
    assert code is None, info
    assert info["pruned"] is True
    assert info["pruneheight"] == TIP - KEEP
    assert info["automatic_pruning"] is True
    assert info["prune_target_size"] == 1
    for k in ("prune_height", "pruned_files", "total_files", "target_size", "keep_blocks"):
        assert k not in info, k
    server.node.pruner = BlockPruner(db=bdb, target_size_mb=1)  # -prune=1
    code, info = _rpc(server, "getblockchaininfo", [])
    assert (info["automatic_pruning"], "prune_target_size" in info) == (False, False)
    server.node.pruner = None
    code, info = _rpc(server, "getblockchaininfo", [])
    assert info["pruned"] is False and "pruneheight" not in info


def test_pruned_node_does_not_advertise_node_network(tmp_path):
    """Core init.cpp: NODE_NETWORK only when !IsPruneMode(); a pruned node
    keeps NODE_NETWORK_LIMITED.  getnetworkinfo and the version message."""
    from ouroboros.peer import Peer

    bdb, _ = _chain(tmp_path, tip=10)
    server = _server(bdb, str(tmp_path), _pruner(bdb, 1))
    code, info = _rpc(server, "getnetworkinfo", [])
    assert code is None, info
    services = int(info["localservices"], 16)
    assert not services & 1 and services & 0x400 and services & 8
    assert "NETWORK" not in info["localservicesnames"]
    server.node.pruner = None
    services = int(_rpc(server, "getnetworkinfo", [])[1]["localservices"], 16)
    assert services & 1
    pruned_peer = Peer("10.0.0.1", 8333, "regtest", node_network_limited=True)
    assert not pruned_peer._assemble_our_services() & 1
    assert not pruned_peer._create_network_address("10.0.0.2", 8333).services & 1
    full_peer = Peer("10.0.0.1", 8333, "regtest")
    assert full_peer._assemble_our_services() & 1


# ---------------------------------------------------------------------------
# validation still has the headers it needs (Core reads them from CBlockIndex)
# ---------------------------------------------------------------------------


def test_retarget_ancestor_keeps_its_bits_after_pruning(tmp_path):
    """The retarget rule's period-first ancestor (pow.cpp GetNextWorkRequired)
    is far below the keep window.  Its body is gone after pruning, but its
    header (time AND bits; BIP94 needs the bits) must still resolve."""
    from ouroboros.validation import BlockValidator

    bdb, _ = _chain(tmp_path)
    _pruner(bdb, 1).prune_blocks(TIP)
    assert not bdb.has_block_data(5)
    v = BlockValidator.__new__(BlockValidator)
    v.db = bdb
    anc = v._active_ancestor_header(5)
    assert anc is not None
    assert anc.timestamp == BASE_TIME + 5 * 600
    assert anc.bits == 0x207FFFFF


def _p2p_header_verdict(bdb, network: str, tip: int):
    """The P2P header-admission diffbits verdict (block_sync
    ``_check_header_diffbits`` with its pointer-based ancestor provider) for
    a header at ``tip + 1`` on the active tip, under ``network``'s rules."""
    from types import SimpleNamespace

    from ouroboros.block_sync import BlockSync
    from ouroboros.validation import BlockValidator

    pm = MagicMock()
    pm.network = network
    bs = BlockSync(db=bdb, validator=BlockValidator(bdb, network=network), peer_manager=pm)
    tip_hash = bytes(bdb.get_block_hash_by_height(tip))
    provider = bs._header_ancestor_provider(tip_hash, tip, tip_hash, tip, {}, {})
    header = SimpleNamespace(bits=0x1D00FFFF, timestamp=BASE_TIME + (tip + 1) * 600,
                             prev_blockhash=tip_hash)
    return bs._check_header_diffbits(header, tip + 1, provider(tip), provider)


@pytest.mark.parametrize("network", ["mainnet", "testnet4"])
def test_p2p_retarget_header_verdict_is_unchanged_by_pruning(tmp_path, network):
    """A retarget header (height 2016) needs the period's first block, 2015
    below the tip: pruned on a pruned node.  The P2P admission path must reach
    the same verdict before and after pruning; it read the BODY and answered
    bad-diffbits-unresolved (reject + ban the peer) once the body was gone."""
    tip = 2015
    bdb, _ = _chain(tmp_path, tip=tip)
    before = _p2p_header_verdict(bdb, network, tip)
    assert not before[1].startswith("bad-diffbits-unresolved"), before
    _pruner(bdb, 1).prune_blocks(tip)
    assert not bdb.has_block_data(0) and not bdb.has_block_data(tip - KEEP - 1)
    after = _p2p_header_verdict(bdb, network, tip)
    assert after == before


# ---------------------------------------------------------------------------
# a pruned node still reorgs across the last 288 blocks (regtest, submitblock)
# ---------------------------------------------------------------------------


def _server(bdb, data_dir: str, pruner):
    """An RPCServer over ``bdb`` with the node in prune mode (``node.pruner``
    set, which also arms the 288-block reorg-depth cap)."""
    from ouroboros.block_sync import BlockSync
    from ouroboros.rpc import RPCServer

    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(os.path.join(data_dir, "invalidated_blocks.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=data_dir, pruner=pruner)
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_max_entries = 1024
    opener = getattr(server, "_open_side_branch_buffer", None)
    server._side_branch_blocks = opener() if opener is not None else {}
    return server


def _fork(bdb, server, fork_h: int, length: int, tag: bytes):
    """Submit a competing branch of ``length`` blocks on the active block at
    ``fork_h``; returns (results, branch hashes)."""
    prev = bytes(bdb.get_block_hash_by_height(fork_h))
    results, hashes = [], []
    for i in range(1, length + 1):
        h = fork_h + i
        cb = coinbase_tx(h, value=_subsidy(h), tag=tag + h.to_bytes(2, "little"))
        raw, prev = build_block(prev, BASE_TIME + h * 600 + 11, [cb])
        results.append(asyncio.run(server.rpc_submitblock(raw.hex())))
        hashes.append(prev)
    return results, hashes


def test_pruned_node_reorgs_288_blocks_deep(tmp_path):
    bdb, base = _chain(tmp_path)
    pruner = _pruner(bdb, 1)
    pruner.prune_blocks(TIP)
    assert _stored(bdb, TIP)[0] == TIP - KEEP  # pruned right up to the window
    spent = bdb.get_utxo(base.fund[0], 0)
    assert spent is None  # fund[0] was spent at SPEND_H

    server = _server(bdb, str(tmp_path), pruner)
    # The production pre-flight: the reorg engine runs the Python
    # BlockValidator on every block it connects (rpc.py, reorg pre-flight),
    # which reads the parent header, MTP window and retarget state.
    from ouroboros.validation import BlockValidator

    validator = BlockValidator(bdb, network="regtest")
    verdicts = []
    real_validate = validator.validate_block

    def _spy(block, height, *a, **k):
        out = real_validate(block, height, *a, **k)
        verdicts.append((height, out[0]))
        return out

    validator.validate_block = _spy
    server.node.validator = validator
    fork_h = TIP - KEEP  # disconnect 288 blocks, the deepest a pruned node allows
    results, branch = _fork(bdb, server, fork_h, KEEP + 1, b"\x05R")
    # The Python validator judged every block of the new branch, and passed it.
    assert sorted(h for h, _ in verdicts) == list(range(fork_h + 1, TIP + 2)), verdicts[:3]
    assert all(ok for _, ok in verdicts)

    assert results[-1] is None, results[-5:]
    assert bdb.refresh_tip_cache() == (branch[-1], TIP + 1)
    assert bytes(bdb.get_block_hash_by_height(fork_h + 1)) == branch[0]
    # The disconnect replayed SPEND_H's undo data: the coin it spent is back.
    coin = bdb.get_utxo(base.fund[0], 0)
    assert coin is not None and coin["value"] == FUNDING


def test_pruned_node_refuses_a_reorg_below_its_undo_window(tmp_path, caplog):
    """Negative control: a 289-deep reorg would need data the pruner deleted.
    The node keeps its tip (Core: missing undo is a fatal abort; ouroboros
    refuses up front) and is still consistent afterwards."""
    bdb, _ = _chain(tmp_path)
    pruner = _pruner(bdb, 1)
    pruner.prune_blocks(TIP)
    server = _server(bdb, str(tmp_path), pruner)
    tip_before = bdb.refresh_tip_cache()
    fork_h = TIP - KEEP - 1  # its body is pruned; the reorg is 289 deep
    with caplog.at_level(logging.WARNING, logger="ouroboros"):
        results, _ = _fork(bdb, server, fork_h, KEEP + 2, b"\x06D")
    assert results[-1] is not None
    # Refused by the undo-window cap (disconnect depth), not by anything else.
    assert any("depth cap exceeded" in r.getMessage() and "disconnect=289" in r.getMessage()
               for r in caplog.records), [r.getMessage() for r in caplog.records]
    assert bdb.refresh_tip_cache() == tip_before
    assert _stored(bdb, TIP) == list(range(TIP - KEEP, TIP + 1))


def test_invalidateblock_never_strands_the_tip_below_the_prune_height(tmp_path):
    """invalidateblock that would leave the tip on a pruned block (no body to
    build on, no undo to disconnect) is refused and changes nothing; one
    just above it succeeds, and the node then still connects a new block."""
    bdb, _ = _chain(tmp_path)
    pruner = _pruner(bdb, 1)
    pruner.prune_blocks(TIP)
    low = bdb.get_prune_height()
    assert low == TIP - KEEP
    server = _server(bdb, str(tmp_path), pruner)
    tip_before = bdb.refresh_tip_cache()

    deep = bytes(bdb.get_block_hash_by_height(low))[::-1].hex()
    code, msg = _rpc(server, "invalidateblock", [deep])
    assert code == -20 and "pruned" in msg, (code, msg)
    assert bdb.refresh_tip_cache() == tip_before

    ok = bytes(bdb.get_block_hash_by_height(low + 1))[::-1].hex()
    code, msg = _rpc(server, "invalidateblock", [ok])
    assert code is None, (code, msg)
    new_hash, new_h = bdb.refresh_tip_cache()
    assert new_h == low and bdb.has_block_data(low)
    # The kept tip can be built on.
    h = low + 1
    raw, bh = build_block(new_hash, BASE_TIME + h * 600 + 13,
                          [coinbase_tx(h, value=_subsidy(h), tag=b"\x07V")])
    assert asyncio.run(server.rpc_submitblock(raw.hex())) is None
    assert bdb.refresh_tip_cache() == (bh, h)


def _bridge_sync(active_height: int, ancestor_height: int, bridge_len: int):
    """A BlockSync on a pruned node holding a complete, heavier P2P fork
    bridge: ``bridge_len`` blocks on the active block at ``ancestor_height``.
    The reorg engine (``_attach_side_branch_block``) is a recording stub, so
    the test sees exactly whether the depth guard let the reorg through."""
    from unittest.mock import AsyncMock

    from ouroboros.block_sync import BlockSync

    bs = BlockSync.__new__(BlockSync)
    bridge = [i.to_bytes(2, "little") + b"\x00" * 30 for i in range(1, bridge_len + 1)]
    bs.pruning_enabled = True
    bs._attach_side_branch_block = AsyncMock(return_value=None)
    bs._reorg_db = MagicMock()
    bs._fork_bridge_chain = lambda tip: (bridge, b"\xaa" * 32, ancestor_height)
    bs._load_fork_body = lambda h: b"raw"
    bs._fork_tip_chainwork = lambda tip: 10**9
    bs.db = MagicMock()
    bs.db.get_best_block.return_value = (b"\xbb" * 32, active_height)
    bs.db.get_chainwork_by_height.return_value = 1
    bs._side_branch_buffer = None
    bs._fork_header_prev = {}
    bs._reorg_rpc_server = None
    return bs, bridge[-1]


def test_p2p_fork_bridge_288_deep_reorg_reaches_the_engine_on_a_pruned_node():
    """block_sync's P2P fork path caps the DISCONNECT depth, not the bridge
    length: a 288-deep reorg bridges 289 blocks and must go through."""
    bs, tip = _bridge_sync(TIP, TIP - KEEP, KEEP + 1)
    try:
        asyncio.run(bs._complete_fork_bridge(tip))
    except AttributeError as e:  # post-reorg bookkeeping this stub does not model
        assert "BlockSync" in str(e), e
    assert bs._attach_side_branch_block.await_count == 1


def test_p2p_fork_bridge_289_deep_reorg_is_refused_on_a_pruned_node():
    bs, tip = _bridge_sync(TIP, TIP - KEEP - 1, KEEP + 2)
    assert asyncio.run(bs._complete_fork_bridge(tip)) is None
    assert bs._attach_side_branch_block.await_count == 0


# ---------------------------------------------------------------------------
# a failing pass is logged loudly
# ---------------------------------------------------------------------------


class _BrokenPruner:
    target_size = 550 * 1024 * 1024
    keep_blocks = KEEP

    def prune_blocks(self, height):
        raise RuntimeError("prune store exploded")

    prune_to_target = prune_blocks


def test_pruner_failure_is_logged_at_error(caplog):
    from ouroboros.node import BitcoinNode

    node = BitcoinNode.__new__(BitcoinNode)
    node.synced = True
    node.db = MagicMock()
    node.db.get_best_block.return_value = (b"\x00" * 32, 5000)
    node.db.refresh_tip_cache.return_value = (b"\x00" * 32, 5000)
    node.peer_manager = None
    node.mempool = None
    node.get_current_difficulty = lambda: 1.0
    node.pruner = _BrokenPruner()
    with caplog.at_level(logging.DEBUG, logger="ouroboros"):
        asyncio.run(node._periodic_tasks())
    errors = [r for r in caplog.records
              if r.levelno >= logging.ERROR and "prune store exploded" in r.getMessage()]
    assert errors, [(r.levelname, r.getMessage()) for r in caplog.records]
    assert errors[0].exc_info is not None
