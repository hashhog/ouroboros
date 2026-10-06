"""The chain lock — ouroboros' ``cs_main`` for chainstate writers.

Bitcoin Core validates and connects a block under ``cs_main``
(``ActivateBestChain`` -> ``ConnectTip`` -> ``ConnectBlock``), and every other
chainstate writer (submitblock's ``ProcessNewBlock``, ``invalidateblock``,
``reconsiderblock``, ``preciousblock``, ``dumptxoutset``'s rollback,
``loadtxoutset``) takes the same lock, so a block is always validated against
the coins of the tip it is connected on.

ouroboros validates a block (``validate_block_from_bytes`` / the Python
validator) and connects it (``connect_block_from_bytes``) in separate
``asyncio.to_thread`` steps.  Before this lock only the P2P drain was
serialised (``BlockSync._drain_lock``, drain against drain); submitblock, the
reorg engine, invalidate/reconsider/precious and the dumptxoutset rollback
yielded between "validate" and "connect" and ran concurrently with the drain
and with each other.  Two writers could validate against the same tip and both
connect: two blocks at one height committed, the UTXO set holding the outputs
of the block that lost the tip, the second block's spend of a coin the first
had already consumed "connected" with no coin behind it.

``ChainLock`` is re-entrant per asyncio task: submitblock holds it and calls
``accept_block`` / the side-branch reorg engine, which take it again.  It is
fair (``asyncio.Lock`` is FIFO), and a long holder (the IBD drain) hands it
over between blocks with :meth:`ChainLock.yield_if_contended`.

Readers (gettxout, mempool ATMP, getblocktemplate) do NOT take it: every
connect is one atomic RocksDB batch, so a reader sees one tip's coins or the
next one's, and the mempool's own lock plus ``removeForBlock`` handle the
interleaving with a connect.
"""

from __future__ import annotations

import asyncio
import functools


class ChainLock:
    """Re-entrant (per asyncio task), FIFO-fair async lock."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task | None = None
        self._depth = 0
        self._waiting = 0

    def held(self) -> bool:
        """True when the CURRENT task holds the lock."""
        task = asyncio.current_task()
        return task is not None and self._owner is task

    def locked(self) -> bool:
        return self._lock.locked()

    async def acquire(self) -> None:
        task = asyncio.current_task()
        if task is not None and self._owner is task:
            self._depth += 1
            return
        self._waiting += 1
        try:
            await self._lock.acquire()
        finally:
            self._waiting -= 1
        self._owner = task
        self._depth = 1

    def release(self) -> None:
        if self._owner is not asyncio.current_task():
            raise RuntimeError("chain lock released by a task that does not hold it")
        self._depth -= 1
        if self._depth == 0:
            self._owner = None
            self._lock.release()

    async def __aenter__(self) -> "ChainLock":
        await self.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        self.release()

    async def yield_if_contended(self) -> None:
        """Between blocks: if another writer is waiting, let it run first.

        Only at the outermost level — a nested holder is mid-operation.
        """
        if self._waiting and self._depth == 1 and self.held():
            self.release()
            await asyncio.sleep(0)
            await self.acquire()


def chain_lock(holder) -> ChainLock:
    """The chain lock of *holder* (the ``Node``; one per process).

    Created on first use and stored on the holder so the P2P drain, the RPC
    server and ``accept_block`` all share it.
    """
    lock = getattr(holder, "_ouroboros_chain_lock", None)
    if lock is None:
        lock = ChainLock()
        try:
            setattr(holder, "_ouroboros_chain_lock", lock)
        except (AttributeError, TypeError):
            pass  # unsettable holder: a private lock still serialises the caller
    return lock


def holds_chain_lock(method):
    """Decorator for ``RPCServer`` chainstate-writer methods."""

    @functools.wraps(method)
    async def wrapper(self, *args, **kwargs):
        node = getattr(self, "node", None)
        async with chain_lock(node if node is not None else self):
            return await method(self, *args, **kwargs)

    return wrapper
