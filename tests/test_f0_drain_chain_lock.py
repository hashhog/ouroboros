"""F0 sweep — the P2P drain validates+connects under the SAME chain lock as
the RPC chainstate writers (Core cs_main), so it can never judge or connect a
block while invalidateblock / reconsiderblock / preciousblock / the reorg
engine / dumptxoutset's rollback holds the chainstate mid-excursion.

Before the lock (60c3a87) the drain was serialised only against itself
(``_drain_lock``).  The accept_block face of the race is reproduced against
the real DB in test_f0_coin_views.py; this pins that the drain takes part.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

from ouroboros.block_sync import BlockSync


def _coinbase_scriptsig(height: int) -> bytes:
    enc = height.to_bytes(4, "little").rstrip(b"\x00")
    if enc[-1] & 0x80:
        enc += b"\x00"
    return bytes([len(enc)]) + enc + b"\x00"


def _block(height: int, prev: bytes):
    cb = SimpleNamespace(inputs=[SimpleNamespace(script_sig=_coinbase_scriptsig(height))])
    return SimpleNamespace(
        transactions=[cb], prev_blockhash=prev, timestamp=int(time.time()),
        version=0x20000000, merkle_root=b"\x00" * 32, bits=0x17021EF0, nonce=0,
    )


class _ChainDB:
    def __init__(self, tip_hash, tip_height):
        self.tip = (tip_hash, tip_height)

    def get_best_block(self):
        return self.tip

    def get_block_bytes(self, h):
        return None


class _Validator:
    def __init__(self, db, hashes):
        self.db, self.hashes = db, hashes
        self.validated = 0

    def validate_block(self, block, **kw):
        self.validated += 1
        return True, ""

    def apply_block(self, block):
        h = self.hashes[id(block)]
        self.db.tip = (h, self.db.tip[1] + 1)


def test_drain_waits_for_a_chainstate_writer_holding_the_chain_lock():
    from ouroboros import chainlock  # absent on 60c3a87: no chain lock at all

    async def run():
        h0, h1 = b"\x10" * 32, b"\x11" * 32
        db = _ChainDB(h0, 969989)
        b1 = _block(969990, h0)
        validator = _Validator(db, {id(b1): h1})
        pm = SimpleNamespace(network="mainnet", get_all_ready_peers=lambda: [])
        bs = BlockSync(db=db, validator=validator, peer_manager=pm)
        bs._prebase_headers_complete = True
        node = SimpleNamespace()
        bs.set_reorg_handler(SimpleNamespace(
            node=node, _attach_side_branch_block=None,
            _reorg_to_side_branch_tip=None, _side_branch_blocks={}))
        bs._validated_headers = [(h1, SimpleNamespace(prev_blockhash=h0))]
        bs._buffer_put(h1, (b1, b"raw1"))

        writer_in = asyncio.Event()
        writer_out = asyncio.Event()

        async def writer():  # e.g. rpc_invalidateblock ... rpc_reconsiderblock
            async with chainlock.chain_lock(node):
                writer_in.set()
                await writer_out.wait()

        w = asyncio.create_task(writer())
        await writer_in.wait()
        drain = asyncio.create_task(bs._drain_block_buffer())
        await asyncio.sleep(0.3)
        assert validator.validated == 0 and db.tip == (h0, 969989), (
            "the drain validated/connected while a chainstate writer held the "
            "chain lock")
        writer_out.set()
        await w
        n = await asyncio.wait_for(drain, 5.0)
        assert n == 1 and db.tip == (h1, 969990)
        for t in list(bs._announce_tasks):
            t.cancel()

    asyncio.run(asyncio.wait_for(run(), 10.0))


def test_drain_hands_the_lock_to_a_waiting_writer_between_blocks():
    from ouroboros import chainlock

    async def run():
        hs = [bytes([0x20 + i]) * 32 for i in range(4)]
        db = _ChainDB(hs[0], 100)
        blocks = [_block(101 + i, hs[i]) for i in range(3)]
        validator = _Validator(db, {id(b): hs[i + 1] for i, b in enumerate(blocks)})
        pm = SimpleNamespace(network="mainnet", get_all_ready_peers=lambda: [])
        bs = BlockSync(db=db, validator=validator, peer_manager=pm)
        bs._prebase_headers_complete = True
        node = SimpleNamespace()
        bs.set_reorg_handler(SimpleNamespace(
            node=node, _attach_side_branch_block=None,
            _reorg_to_side_branch_tip=None, _side_branch_blocks={}))
        bs._validated_headers = [(hs[i + 1], SimpleNamespace(prev_blockhash=hs[i]))
                                 for i in range(3)]
        for i, b in enumerate(blocks):
            bs._buffer_put(hs[i + 1], (b, b"raw"))

        seen = []
        loop = asyncio.get_running_loop()
        orig_apply = validator.apply_block

        def apply(block):
            orig_apply(block)
            if db.tip[1] == 101:  # after the first block, a writer queues up
                loop.call_soon_threadsafe(
                    lambda: seen.append(asyncio.create_task(writer())))
        validator.apply_block = apply

        async def writer():
            async with chainlock.chain_lock(node):
                return db.tip[1]

        n = await asyncio.wait_for(bs._drain_block_buffer(), 5.0)
        assert n == 3
        got = await seen[0]
        assert got < 103, f"writer waited for the whole drain (ran at h={got})"
        for t in list(bs._announce_tasks):
            t.cancel()

    asyncio.run(asyncio.wait_for(run(), 10.0))
