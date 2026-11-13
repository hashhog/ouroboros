"""sm-fix-ouroboros-sigterm-stop-cancelled: BitcoinNode.stop() is one shared
shutdown that every caller waits for.

The headline regression (signal-scheduled stop + ``run()``'s finally) is
``tests/test_sm_sweep_shutdown.py::test_sm_sweep_signal_scheduled_stop_dumps_mempool``.
These pin the properties the fix relies on:

* a second concurrent ``stop()`` waits for the first one to finish instead of
  returning while teardown is still in flight;
* cancelling one waiter (the signal-scheduled task) does not abort the
  shutdown for the others;
* the shutdown body runs exactly once;
* ``stop()`` on a node that never started, and a repeat ``stop()`` from a new
  event loop after shutdown finished (cli.py's KeyboardInterrupt path), are
  no-ops.

Core: init.cpp ``Shutdown()`` runs DumpMempool / fee estimates synchronously
and the process does not exit until it returns.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest


def _node(tmp_path, block_sync=None):
    from ouroboros.node import BitcoinNode

    node = BitcoinNode.__new__(BitcoinNode)
    node.running = True
    node.data_dir = str(tmp_path)
    node.peer_manager = None
    node._rpc_task = None
    node.zmq_notifier = None
    node.fee_estimator = MagicMock()
    node.mempool = MagicMock()
    node.block_sync = block_sync
    return node


class _SlowBlockSync:
    def __init__(self):
        self.calls = 0

    async def stop(self):
        self.calls += 1
        await asyncio.sleep(0.3)

    def save_header_index(self):
        pass


def test_second_stop_waits_for_first_to_finish(tmp_path):
    bs = _SlowBlockSync()
    node = _node(tmp_path, bs)

    async def main():
        first = asyncio.create_task(node.stop())
        await asyncio.sleep(0.05)  # first stop() is now inside teardown
        assert node.running is False
        assert not node.mempool.dump_to_file.called
        await node.stop()  # must not return before the saves
        assert node.mempool.dump_to_file.called
        assert node.fee_estimator.save_to_file.called
        await first

    asyncio.run(main())
    assert bs.calls == 1, "shutdown body ran more than once"
    assert node.mempool.dump_to_file.call_count == 1


def test_cancelling_one_waiter_does_not_abort_shutdown(tmp_path):
    bs = _SlowBlockSync()
    node = _node(tmp_path, bs)

    async def main():
        first = asyncio.create_task(node.stop())
        await asyncio.sleep(0.05)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        # The shared shutdown keeps going; a later waiter sees it complete.
        await node.stop()

    asyncio.run(main())
    assert node.mempool.dump_to_file.call_count == 1
    assert node.fee_estimator.save_to_file.call_count == 1


def test_stop_on_never_started_node_is_noop(tmp_path):
    node = _node(tmp_path)
    node.running = False
    asyncio.run(node.stop())
    assert not node.mempool.dump_to_file.called


def test_repeat_stop_from_new_loop_after_shutdown_is_noop(tmp_path):
    node = _node(tmp_path)
    asyncio.run(node.stop())
    assert node.mempool.dump_to_file.call_count == 1
    # cli.py calls asyncio.run(_node.stop()) again after run() on Ctrl+C.
    asyncio.run(node.stop())
    assert node.mempool.dump_to_file.call_count == 1
