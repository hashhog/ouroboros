"""sm-sweep-ouroboros E1: a SIGTERM shutdown can skip the shutdown saves.

E1a  ``PeerManager.stop`` (p2p.py) closes the listening servers and then
     ``await server.wait_closed()`` BEFORE it disconnects any peer.  On
     Python >= 3.12.1 ``Server.wait_closed()`` waits for every accepted
     connection to close, so one live inbound peer blocks ``stop()`` there,
     and ``_save_anchors()`` / ``addrman.save()`` (peers.json) never run.

E1b  The SIGTERM handler (node.py ``start``) schedules ``self.stop()`` as a
     task; ``stop()`` sets ``running = False`` before its first await, the
     main loop exits within 1 s, ``start()`` returns and ``run()``'s
     ``finally: await self.stop()`` is a no-op (running already False).
     ``asyncio.run`` then cancels the still-running first ``stop()`` task;
     ``CancelledError`` is not an ``Exception``, so the fee-estimate save
     and ``mempool.dump_to_file`` (mempool.dat) are skipped.

Core: init.cpp ``Shutdown()`` stops the connman (closing every socket)
and then runs DumpMempool / fee estimates / peers.dat / anchors
synchronously, and the process does not exit until it returns.

E1b's test copies the current SIGTERM handler (schedule ``stop()`` as a
task) and the real ``run()`` / ``stop()``.  A fix that instead makes the
handler only set the event and lets ``run()``'s finally do the stop must
update ``fake_start`` to match the new handler.

xfail(strict=True) until sm-fix-ouroboros-pm-stop-inbound-hang (E1a) and
sm-fix-ouroboros-sigterm-stop-cancelled (E1b) land.
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import MagicMock

import pytest

from tests.test_inbound_p2p import (
    _handshake_as_dialer,
    _listen_port,
    _start_listening_pm,
)

_XFAIL_A = pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros E1a: PeerManager.stop awaits server.wait_closed() "
    "before disconnecting inbound peers",
)
_XFAIL_B = pytest.mark.xfail(
    strict=True,
    reason="sm-sweep-ouroboros E1b: run()'s finally-stop is a no-op and "
    "asyncio.run cancels the signal-scheduled stop() mid-way",
)


@pytest.mark.skipif(
    sys.version_info < (3, 12, 1),
    reason="Server.wait_closed() waits for accepted connections only on "
    "Python >= 3.12.1 (the deployed venv is 3.13)",
)
@_XFAIL_A
@pytest.mark.asyncio
async def test_sm_sweep_peer_manager_stop_with_live_inbound_peer_saves_peers(tmp_path):
    pm = await _start_listening_pm(tmp_path)
    port = _listen_port(pm)
    reader, writer = await _handshake_as_dialer("127.0.0.1", port)
    for _ in range(50):
        if pm.inbound_peers:
            break
        await asyncio.sleep(0.05)
    assert pm.inbound_peers, "precondition: inbound peer registered"
    try:
        # The inbound peer stays connected, as it does on a listening node.
        await asyncio.wait_for(pm.stop(), timeout=5)
    except TimeoutError:
        pytest.fail("PeerManager.stop() hung with one live inbound peer")
    finally:
        writer.close()
    assert os.path.exists(tmp_path / "peers.json"), "addrman.save() did not run"


@_XFAIL_B
def test_sm_sweep_signal_scheduled_stop_dumps_mempool(tmp_path):
    from ouroboros.node import BitcoinNode

    node = BitcoinNode.__new__(BitcoinNode)
    node.running = True
    node.data_dir = str(tmp_path)
    node.peer_manager = None
    node._rpc_task = None
    node.zmq_notifier = None
    node.fee_estimator = None
    node.mempool = MagicMock()

    class _SlowBlockSync:
        async def stop(self):
            # Any shutdown step that takes longer than the main loop's
            # 1 s poll (block_sync / peer_manager / RPC teardown).
            await asyncio.sleep(1.5)

    node.block_sync = _SlowBlockSync()

    async def fake_start():
        # Exactly what start()'s SIGTERM handler + _main_loop do.
        node._shutdown_event = asyncio.Event()
        asyncio.get_running_loop().call_soon(lambda: asyncio.create_task(node.stop()))
        node._shutdown_event.set()
        await asyncio.sleep(0.1)  # main loop notices the event and returns

    node.start = fake_start
    asyncio.run(node.run())
    assert node.mempool.dump_to_file.called, "mempool.dat was not written on SIGTERM"


# --------------------------------------------------------------------------- #
# Controls (pass on master): the same instruments see a successful save.
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_sm_sweep_control_peer_manager_stop_after_peer_closed_saves_peers(tmp_path):
    pm = await _start_listening_pm(tmp_path)
    port = _listen_port(pm)
    reader, writer = await _handshake_as_dialer("127.0.0.1", port)
    for _ in range(50):
        if pm.inbound_peers:
            break
        await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()
    await asyncio.wait_for(pm.stop(), timeout=5)
    assert os.path.exists(tmp_path / "peers.json")


def test_sm_sweep_control_fast_stop_dumps_mempool(tmp_path):
    from ouroboros.node import BitcoinNode

    node = BitcoinNode.__new__(BitcoinNode)
    node.running = True
    node.data_dir = str(tmp_path)
    node.peer_manager = None
    node._rpc_task = None
    node.zmq_notifier = None
    node.fee_estimator = None
    node.mempool = MagicMock()
    node.block_sync = None

    async def fake_start():
        node._shutdown_event = asyncio.Event()
        asyncio.get_running_loop().call_soon(lambda: asyncio.create_task(node.stop()))
        node._shutdown_event.set()
        await asyncio.sleep(0.1)

    node.start = fake_start
    asyncio.run(node.run())
    assert node.mempool.dump_to_file.called
