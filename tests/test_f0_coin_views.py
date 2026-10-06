"""F0 coin-view sweep (2026-10-05) — reproducers over the REAL Rust extension.

Each test states what the deployed ouroboros (60c3a87) ACCEPTED and what Core
does instead.  Core references (bitcoin-core/src):

* coins.cpp:84-91 ``CCoinsViewCache::AddCoin`` — ``if
  (coin.out.scriptPubKey.IsUnspendable()) return;``: an OP_RETURN or >10,000
  byte output never enters ANY view, including the per-block connect view, so a
  later tx in the same block that spends it fails ``HaveInputs`` ->
  ``bad-txns-inputs-missingorspent`` (validation.cpp ConnectBlock /
  consensus/tx_verify.cpp CheckTxInputs) — with or without script checks.
* validation.cpp ``UpdateCoins``: ``bool is_spent = inputs.SpendCoin(...);
  assert(is_spent);`` — connecting a block whose input is not in the coins view
  is impossible, never a silent no-op.
* validation.cpp: ``cs_main`` serialises validate+connect (ActivateBestChain /
  ConnectTip) against every other chainstate writer; a block is only connected
  on top of the CURRENT tip.
* txmempool.cpp ``CTxMemPool::removeForBlock`` -> ``removeConflicts``: a
  mempool tx that spends an outpoint a block tx spends is removed (with its
  descendants) when the block connects.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests._f0_chain import (  # noqa: E402
    COIN, OP_RETURN, OP_TRUE, Chain, dsha, spend,
)

UNSPENDABLE = {
    "op_return": OP_RETURN + b"\x01\x42",
    "oversize_10001": b"\x51" * 10_001,  # MAX_SCRIPT_SIZE + 1 (script.h:563)
}


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


@pytest.fixture
def chain(tmp_path):
    return Chain(sync.PyBlockchainDB(str(tmp_path / "db")))


def _drain_av_connect(db, raw: bytes, height: int) -> str:
    """Exactly what block_sync's drain does below the assumevalid cut:
    Rust ``validate_block_from_bytes(skip_scripts=True)`` then
    ``connect_block_from_bytes`` (block_sync.py:2784 / :3098)."""
    try:
        db.validate_block_from_bytes(raw, height - 1, True, "regtest")
    except ValueError as e:
        return f"reject(validate): {e}"
    try:
        db.connect_block_from_bytes(raw, height, "regtest")
    except ValueError as e:
        return f"reject(connect): {e}"
    return "ACCEPTED"


def _unspendable_inblock_block(chain: Chain, spk: bytes):
    """[coinbase, A, B]: A spends the funding coin fund[0] into (spk, 1 BTC) +
    change; B spends A:0 — the unspendable output created earlier in the SAME
    block."""
    tx_a = spend(chain.fund[0], 0, [(1 * COIN, spk), (48 * COIN, OP_TRUE)])
    tx_b = spend(dsha(tx_a), 0, [(COIN // 2, OP_TRUE)])
    raw, bh = chain.next_block([tx_a, tx_b])
    return raw, bh, dsha(tx_a), dsha(tx_b)


# ---------------------------------------------------------------------------
# 1. Unspendable outputs entered the intra-block views.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", sorted(UNSPENDABLE))
def test_av_drain_rejects_inblock_spend_of_unspendable_output(chain, kind):
    raw, bh, txa, _ = _unspendable_inblock_block(chain, UNSPENDABLE[kind])
    outcome = _drain_av_connect(chain.db, raw, chain.tip_height + 1)
    tip = chain.db.get_best_block()
    from ouroboros.rpc import bip22_result_string

    assert outcome.startswith("reject(validate)") and bip22_result_string(
        outcome.split(": ", 1)[1]) == "bad-txns-inputs-missingorspent", (
        f"{kind}: a block spending an unspendable output created earlier in the "
        f"same block was {outcome} (tip now h={tip[1]}); Core: rejected by "
        f"validation (CheckTxInputs), "
        f"bad-txns-inputs-missingorspent (coins.cpp:84-91 AddCoin skips it)")
    assert tip == (chain.tip_hash, chain.tip_height)
    # The unspendable output itself never became a coin either way.
    assert chain.db.get_utxo(txa, 0) is None


def test_av_drain_control_inblock_spend_of_spendable_output_accepted(chain):
    """CONTROL: the identical block shape with A:0 = OP_TRUE connects, so the
    reject above is the unspendable output and nothing else."""
    raw, bh, txa, txb = _unspendable_inblock_block(chain, OP_TRUE)
    assert _drain_av_connect(chain.db, raw, chain.tip_height + 1) == "ACCEPTED"
    assert chain.db.get_best_block() == (bh, chain.tip_height + 1)
    assert chain.db.get_utxo(txb, 0) is not None


class _SkipScriptsSync:
    """Proxy for the real extension whose checkpoint predicate says 'below
    the assumevalid cut' — the seam that puts the Python validator on its
    skip-scripts branch (mainnet: every block under 850000, e.g. the first
    block above an 840000 assumeUTXO snapshot, accept_block's
    _snapshot_base_parent route)."""

    def __init__(self, real):
        self._real = real

    def can_skip_scripts_for_block(self, *_a, **_k):
        return True

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.mark.parametrize("skip", [True, False], ids=["skip_scripts", "scripts_on"])
@pytest.mark.parametrize("kind", sorted(UNSPENDABLE))
def test_python_validator_rejects_inblock_spend_of_unspendable_output(
        tmp_path, monkeypatch, kind, skip):
    import ouroboros.validation as validation
    from ouroboros.database import Block, BlockchainDatabase

    bdb = BlockchainDatabase(str(tmp_path / "pydb"))
    chain = Chain(bdb._db)
    raw, bh, _, _ = _unspendable_inblock_block(chain, UNSPENDABLE[kind])
    if skip:
        monkeypatch.setattr(validation, "_sync_module",
                            _SkipScriptsSync(validation._sync_module))
    v = validation.BlockValidator(bdb, "regtest")
    ok, err = v.validate_block(Block.deserialize(raw), chain.tip_height + 1)
    assert not ok, (
        f"{kind} ({'skip' if skip else 'scripts on'}): Python validate_block "
        f"ACCEPTED a block spending an unspendable in-block output")
    from ouroboros.rpc import bip22_result_string

    assert bip22_result_string(err) == "bad-txns-inputs-missingorspent", (
        f"{kind}: rejected for the wrong reason {err!r}; Core reports "
        f"bad-txns-inputs-missingorspent before any script runs")


# ---------------------------------------------------------------------------
# 2. connect_block_from_bytes tolerated a missing input (lib.rs ~4401).
# ---------------------------------------------------------------------------
def test_connect_refuses_block_whose_input_is_not_a_coin(chain):
    ghost = b"\xee" * 32
    tx = spend(ghost, 0, [(50 * COIN, OP_TRUE)])
    raw, bh = chain.next_block([tx])
    try:
        chain.db.connect_block_from_bytes(raw, chain.tip_height + 1, "regtest")
        outcome = "ACCEPTED"
    except ValueError as e:
        outcome = f"reject: {e}"
    tip = chain.db.get_best_block()
    assert "missingorspent" in outcome, (
        f"connect of a block spending nonexistent {ghost.hex()[:8]}:0 was "
        f"{outcome}; tip h={tip[1]}, minted coin present="
        f"{chain.db.get_utxo(dsha(tx), 0) is not None}. Core UpdateCoins "
        f"asserts SpendCoin succeeded")
    assert tip == (chain.tip_hash, chain.tip_height)
    assert chain.db.get_utxo(dsha(tx), 0) is None


# ---------------------------------------------------------------------------
# 3. No chain lock: two writers validated against the same tip, both connected.
# ---------------------------------------------------------------------------
class _BarrierDB:
    """Real DB; ``connect_block_from_bytes`` waits until both writers have
    validated (or 3 s — a serialised writer never arrives)."""

    def __init__(self, real, parties=2):
        self._real = real
        self.barrier = threading.Barrier(parties, timeout=3)

    def connect_block_from_bytes(self, *a, **k):
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return self._real.connect_block_from_bytes(*a, **k)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _competing_pair(chain: Chain):
    """X1, X2 at tip+1 on the same parent, both spending fund[0]."""
    x1_tx = spend(chain.fund[0], 0, [(49 * COIN, OP_TRUE)])
    x2_tx = spend(chain.fund[0], 0, [(48 * COIN, OP_TRUE)])
    x1, h1 = chain.next_block([x1_tx], tag=b"\x02X1")
    x2, h2 = chain.next_block([x2_tx], tag=b"\x02X2")
    return (x1, h1, dsha(x1_tx)), (x2, h2, dsha(x2_tx))


def _coin_set_view(db, outs):
    return {name: db.get_utxo(txid, 0) is not None for name, txid in outs.items()}


def test_concurrent_accept_block_connects_one_block_per_height(chain):
    """NOT VULNERABLE on 60c3a87 (passes there too): two writers validated
    against the same tip, held at a barrier, then both connect.  The second
    connect is refused by connect_block_from_bytes' own prev == tip check
    (lib.rs ~4037-4060), which runs with the GIL held for the whole connect,
    so two connects cannot interleave.  Kept as the control that the
    same-height race stays closed."""
    from ouroboros.rpc import accept_block

    (x1, h1, t1), (x2, h2, t2) = _competing_pair(chain)
    bdb = _BarrierDB(chain.db)
    node = SimpleNamespace(network="regtest", validator=None, mempool=None)

    async def run():
        return await asyncio.gather(
            accept_block(bdb, node, x1, chain.tip_height + 1),
            accept_block(bdb, node, x2, chain.tip_height + 1),
            return_exceptions=True)

    r1, r2 = asyncio.run(run())
    accepted = [n for n, r in (("X1", r1), ("X2", r2)) if not isinstance(r, BaseException)]
    tip = chain.db.get_best_block()
    coins = _coin_set_view(chain.db, {"X1-out": t1, "X2-out": t2})
    assert len(accepted) == 1, (
        f"both competing tip+1 blocks ACCEPTED (results {r1!r} / {r2!r}); tip="
        f"{'X1' if tip[0] == h1 else 'X2' if tip[0] == h2 else tip[0].hex()[:8]}"
        f"; coins present {coins}. Core's cs_main connects only on the current tip")
    winner_out = "X1-out" if accepted == ["X1"] else "X2-out"
    loser_out = "X2-out" if accepted == ["X1"] else "X1-out"
    assert tip == ((h1 if accepted == ["X1"] else h2), chain.tip_height + 1)
    assert coins[winner_out] and not coins[loser_out], (
        f"UTXO set not the active chain's: {coins}")


def test_concurrent_submitblock_connects_one_block_per_height(chain):
    """Same race through the real rpc_submitblock (reads the tip, then
    accept_block).  NOT VULNERABLE on 60c3a87 either — same guard."""
    from ouroboros.rpc import RPCServer

    (x1, h1, t1), (x2, h2, t2) = _competing_pair(chain)
    bdb = _BarrierDB(chain.db)
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=bdb)
    server.block_submission_paused = False
    server._side_branch_blocks = {}
    server._side_branch_max_entries = 1024

    async def run():
        return await asyncio.gather(
            server.rpc_submitblock(x1.hex()), server.rpc_submitblock(x2.hex()),
            return_exceptions=True)

    r1, r2 = asyncio.run(run())
    tip = chain.db.get_best_block()
    coins = _coin_set_view(chain.db, {"X1-out": t1, "X2-out": t2})
    n_null = [r is None for r in (r1, r2)].count(True)
    assert n_null == 1, (
        f"submitblock answered {r1!r} / {r2!r} for two competing tip+1 blocks; "
        f"coins present {coins}")
    assert list(coins.values()).count(True) == 1, f"UTXO set mixes both: {coins}"
    assert tip[1] == chain.tip_height + 1


class _PauseAfterValidateDB:
    """Wrap the node's DB: after the real ``validate_block_from_bytes``
    returns, signal ``validated`` and hold the caller until ``release`` (3 s
    cap — a writer serialised behind the chain lock never gets here)."""

    def __init__(self, real):
        self._real = real
        self.validated = threading.Event()
        self.release = threading.Event()

    def validate_block_from_bytes(self, *a, **k):
        r = self._real.validate_block_from_bytes(*a, **k)
        self.validated.set()
        self.release.wait(timeout=3)
        return r

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_block_validated_inside_invalidate_reconsider_window_is_not_connected(tmp_path):
    """The drain/submitblock "validate, then connect" gap vs a chainstate
    writer's excursion (rpc_invalidateblock -> ... -> rpc_reconsiderblock;
    dumptxoutset's rollback is the same dance inside one RPC).

    h3 spends coin C.  invalidateblock(h3) rewinds the coins: C is unspent
    again, while h3 stays resolvable by height.  X (child of h3) re-spends C:
    validated in that window it passes; reconsiderblock(h3) restores the tip
    to h3 (C spent); X's connect then sees prev == tip and — tolerating the
    missing input — commits a second spend of C.  Core: X is connected only
    under cs_main on top of the CURRENT tip, against its coins."""
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer, accept_block

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    chain = Chain(bdb._db)
    C = chain.fund[0]
    t3 = spend(C, 0, [(49 * COIN, OP_TRUE)])
    b3, h3 = chain.next_block([t3])
    node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=bdb)
    asyncio.run(accept_block(bdb, node, b3, chain.tip_height + 1))
    chain.tip_hash, chain.tip_height = h3, chain.tip_height + 1
    x = spend(C, 0, [(48 * COIN, OP_TRUE)])  # re-spends C
    bx, hx = chain.next_block([x], tag=b"\x02XX")

    pdb = _PauseAfterValidateDB(bdb)
    server = RPCServer.__new__(RPCServer)
    server.node = node

    async def run():
        await server.rpc_invalidateblock(h3[::-1].hex())
        rewound = (chain.db.get_best_block()[1], chain.db.get_utxo(C, 0) is not None)
        task = asyncio.create_task(accept_block(pdb, node, bx, chain.tip_height + 1))
        for _ in range(300):  # until X validated (base) or X finished (fix)
            if pdb.validated.is_set() or task.done():
                break
            await asyncio.sleep(0.01)
        await server.rpc_reconsiderblock(h3[::-1].hex())
        pdb.release.set()
        res = await asyncio.gather(task, return_exceptions=True)
        return rewound, res[0]

    rewound, res = asyncio.run(run())
    tip = chain.db.get_best_block()
    x_out = chain.db.get_utxo(dsha(x), 0) is not None
    assert rewound == (chain.tip_height - 1, True), f"setup: rewind gave {rewound}"
    assert isinstance(res, BaseException) and not x_out and tip[0] != hx, (
        f"X — a second spend of C, which h3 already spent — was ACCEPTED "
        f"(accept_block -> {res!r}); tip h={tip[1]} is "
        f"{'X' if tip[0] == hx else tip[0][::-1].hex()[:8]}, X's output minted="
        f"{x_out}: it was validated against the rewound coins and connected "
        f"after the restore")
    assert tip == (h3, chain.tip_height), f"reconsiderblock did not restore h3: {tip}"
    assert chain.db.get_utxo(C, 0) is None


def test_valid_block_validated_inside_invalidate_window_is_not_marked_invalid(tmp_path):
    """The other face of the same race (fail-CLOSED): X spends an output
    CREATED by h3.  Validated while invalidateblock(h3) has rewound the coins,
    the output is absent and X — a VALID block on h3 — gets a consensus verdict
    (bad-txns-inputs-missingorspent), which the drain turns into a permanent
    BLOCK_FAILED mark.  Core never judges a block against a tip it does not
    extend: under cs_main X is either connected on h3 or not considered."""
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer, accept_block, bip22_result_string

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    chain = Chain(bdb._db)
    t3 = spend(chain.fund[0], 0, [(49 * COIN, OP_TRUE)])
    b3, h3 = chain.next_block([t3])
    node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=bdb)
    asyncio.run(accept_block(bdb, node, b3, chain.tip_height + 1))
    chain.tip_hash, chain.tip_height = h3, chain.tip_height + 1
    x = spend(dsha(t3), 0, [(48 * COIN, OP_TRUE)])  # spends h3's output: VALID on h3
    bx, hx = chain.next_block([x], tag=b"\x02XV")

    pdb = _PauseAfterValidateDB(bdb)
    server = RPCServer.__new__(RPCServer)
    server.node = node

    async def run():
        await server.rpc_invalidateblock(h3[::-1].hex())
        task = asyncio.create_task(accept_block(pdb, node, bx, chain.tip_height + 1))
        for _ in range(300):
            if pdb.validated.is_set() or task.done():
                break
            await asyncio.sleep(0.01)
        await server.rpc_reconsiderblock(h3[::-1].hex())
        pdb.release.set()
        return (await asyncio.gather(task, return_exceptions=True))[0]

    res = asyncio.run(run())
    verdict = bip22_result_string(str(res)) if isinstance(res, BaseException) else "accepted"
    assert verdict in ("accepted", "inconclusive"), (
        f"a VALID block on h3, judged while h3 was rewound, got the consensus "
        f"verdict {verdict!r} ({res!r}) — the drain would mark it BLOCK_FAILED")
    # Once the window is closed it connects normally.
    if verdict == "inconclusive":
        asyncio.run(accept_block(bdb, node, bx, chain.tip_height + 1))
    assert chain.db.get_best_block() == (hx, chain.tip_height + 1)


def test_sequential_competitor_is_not_connected_on_top(chain):
    """CONTROL (no concurrency): after X1 connects, X2 (same parent) must not
    be connected as the tip — passes on deployed too; proves the assertion
    shape above is about the race, not about accept_block per se."""
    from ouroboros.rpc import accept_block

    (x1, h1, t1), (x2, h2, t2) = _competing_pair(chain)
    node = SimpleNamespace(network="regtest", validator=None, mempool=None)
    asyncio.run(accept_block(chain.db, node, x1, chain.tip_height + 1))
    with pytest.raises(Exception):
        asyncio.run(accept_block(chain.db, node, x2, chain.tip_height + 1))
    assert chain.db.get_best_block() == (h1, chain.tip_height + 1)
    assert _coin_set_view(chain.db, {"a": t1, "b": t2}) == {"a": True, "b": False}
