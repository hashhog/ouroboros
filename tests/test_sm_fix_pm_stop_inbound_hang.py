"""sm-fix-ouroboros-pm-stop-inbound-hang: PeerManager.stop() must save
peers.json / anchors and return even while an inbound socket is open.

The live-registered-peer case is pinned in
tests/test_sm_sweep_shutdown.py::test_sm_sweep_peer_manager_stop_with_live_inbound_peer_saves_peers.
This file covers the case the bounded wait exists for: an accepted TCP
connection that never completed version/verack, so it is in no peer map
and the peer-disconnect loop cannot close it.  On Python >= 3.12.1
``Server.wait_closed()`` waits for it, so stop() must neither block on it
before the saves nor hang on it after them.

Core: init.cpp Shutdown() -> CConnman::Stop/StopNodes closes every socket
(handshaken or not) and dumps peers.dat / anchors.dat.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

from tests.test_inbound_p2p import _listen_port, _start_listening_pm


@pytest.mark.skipif(
    sys.version_info < (3, 12, 1),
    reason="Server.wait_closed() waits for accepted connections only on "
    "Python >= 3.12.1 (the deployed venv is 3.13)",
)
@pytest.mark.asyncio
async def test_pm_stop_with_unhandshaken_inbound_socket_saves_and_returns(tmp_path):
    pm = await _start_listening_pm(tmp_path)
    port = _listen_port(pm)
    # Connect but send nothing: accepted by the server, never registered.
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.2)
    assert not pm.inbound_peers, "precondition: socket is not a registered peer"
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    try:
        await asyncio.wait_for(pm.stop(), timeout=10)
    except TimeoutError:
        pytest.fail("PeerManager.stop() hung on an un-handshaken inbound socket")
    finally:
        writer.close()
    elapsed = loop.time() - t0
    assert os.path.exists(tmp_path / "peers.json"), "addrman.save() did not run"
    assert os.path.exists(tmp_path / "anchors.dat"), "_save_anchors() did not run"
    if sys.version_info >= (3, 13):
        # Server.close_clients() closes the stray socket, so stop() does not
        # sit out the whole SERVER_CLOSE_TIMEOUT bound.
        assert elapsed < 2.0, f"stop() took {elapsed:.2f}s; stray socket not force-closed"
