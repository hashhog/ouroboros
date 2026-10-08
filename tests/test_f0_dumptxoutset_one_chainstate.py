"""F0 sweep — dumptxoutset must serialise ONE chainstate.

Core's PrepareUTXOSnapshot takes cs_main, flushes, and opens the coins cursor
(a LevelDB snapshot) and reads the base block from THAT cursor
(``pcursor->GetBestBlock()``, rpc/blockchain.cpp), so the file's base hash,
coin count and coins describe one tip even while blocks keep connecting.

ouroboros' SnapshotManager.dump_snapshot read the tip (``get_best_block``),
then the count (``utxo_count``), then the coins (``iter_utxos``) as three
separate reads of the live DB, with no chain lock against the drain/submitblock.
A block connected in between produced a file labelled with tip T whose coins
are those of T+1 (and whose coin count disagrees with the coins written), and
an RPC answer naming yet another read of the tip.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import COIN, OP_TRUE, Chain, dsha, spend  # noqa: E402


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


class _ConnectDuringDump:
    """Proxy for the node DB: when the dump starts reading coins, a block
    connect (through the production accept_block) is attempted from the event
    loop; the dump waits up to 2 s for it — a connect serialised behind the
    chain lock cannot happen until the dump is done."""

    def __init__(self, real, start_connect):
        self._real = real
        self._start_connect = start_connect
        self.fired = False

    def _fire(self):
        if not self.fired:
            self.fired = True
            fut = self._start_connect()
            try:
                fut.result(timeout=2)
            except Exception:
                pass

    def iter_utxos(self, *a, **k):
        self._fire()
        return self._real.iter_utxos(*a, **k)

    def visit_utxo_txid_groups(self, *a, **k):
        # the streaming dump walks the native cursor; same seam
        self._fire()
        return self._real.visit_utxo_txid_groups(*a, **k)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_latest_dump_describes_one_tip(tmp_path):
    from ouroboros.database import BlockchainDatabase
    from ouroboros.rpc import RPCServer, accept_block
    from ouroboros.snapshot import SnapshotManager, read_snapshot_metadata

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    chain = Chain(bdb._db)
    t3 = spend(chain.fund[0], 0, [(20 * COIN, OP_TRUE), (29 * COIN, OP_TRUE)])
    b3, h3 = chain.next_block([t3])
    h2 = chain.tip_hash
    count_h2 = bdb.utxo_count()
    node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=bdb)
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    out = str(tmp_path / "utxo.dat")

    async def run():
        loop = asyncio.get_running_loop()
        pending = []

        def start_connect():
            fut = asyncio.run_coroutine_threadsafe(
                accept_block(bdb, node, b3, chain.tip_height + 1), loop)
            pending.append(fut)
            return fut

        node.snapshot_manager = SnapshotManager(
            _ConnectDuringDump(bdb, start_connect), "regtest", str(tmp_path / "sm"))
        res = await server.rpc_dumptxoutset(out)
        for f in pending:
            await asyncio.wrap_future(f)
        return res

    res = asyncio.run(run())
    assert bdb.get_best_block() == (h3, chain.tip_height + 1), "block never connected"
    count_h3 = bdb.utxo_count()
    meta = read_snapshot_metadata(out, "regtest")
    base = "h2" if meta.base_blockhash == h2 else "h3" if meta.base_blockhash == h3 else "?"
    expect = {"h2": count_h2, "h3": count_h3}.get(base)
    assert meta.coins_count == res["coins_written"] == expect, (
        f"dump header says base={base} with {meta.coins_count} coins, "
        f"{res['coins_written']} coins were written (h2 has {count_h2}, h3 has "
        f"{count_h3}); RPC answered base_height={res['base_height']} — the file "
        f"mixes two chainstates")
    assert res["base_height"] == chain.tip_height + (0 if base == "h2" else 1)
