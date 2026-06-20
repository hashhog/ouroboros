"""Regression test for the 2026-06-20 ouroboros OOM-spike fix.

PeerManager._relay_addr used `asyncio.ensure_future(p.send_message(msg))`
(fire-and-forget). When a relay target stopped draining its socket,
send_message parked forever on writer.drain() and each Task held the inbound
addr NetworkMessage alive — the only un-bounded message-capturing Task in the
node. Under load that piled up millions of Tasks (live capture: ~2.5M retained
messages, RSS 1.4G->16G). The fix awaits the relay send with a timeout and
disconnects a target that won't drain, so no Task is left holding the message.

This test asserts the awaited+bounded+disconnect behavior.
"""

import asyncio
import time
import types

from ouroboros import p2p
from ouroboros.p2p import PeerManager


class _StubPeer:
    def __init__(self, host: str, wedged: bool):
        self.host = host
        self.port = 8333
        self.relay_txs = True
        self._wedged = wedged
        self.disconnected = False
        self.sent = 0

    def is_connected(self) -> bool:
        return True

    async def send_message(self, msg):
        if self._wedged:
            await asyncio.sleep(3600)  # never drains (simulates a wedged peer)
        self.sent += 1

    async def disconnect(self):
        self.disconnected = True


def test_relay_addr_awaits_bounds_and_disconnects_wedged_target():
    async def _run():
        orig = p2p.ADDR_RELAY_SEND_TIMEOUT
        p2p.ADDR_RELAY_SEND_TIMEOUT = 0.05  # fast for the test
        try:
            wedged = _StubPeer("1.1.1.1", wedged=True)
            healthy = _StubPeer("2.2.2.2", wedged=False)
            fake = types.SimpleNamespace(
                peers={"1.1.1.1:8333": wedged},
                inbound_peers={"2.2.2.2:8333": healthy},
            )
            msg = object()  # _relay_addr only forwards it to send_message

            t0 = time.monotonic()
            # Unbound-method call with a minimal stub self.
            await PeerManager._relay_addr(fake, msg, exclude="")
            elapsed = time.monotonic() - t0

            # 1) It must RETURN promptly (bounded by ~2*timeout), not hang or
            #    fire-and-forget — the regression was an unbounded parked Task.
            assert elapsed < 2.0, f"_relay_addr blocked {elapsed:.2f}s (fire-and-forget regressed?)"
            # 2) A healthy target actually received the relay.
            assert healthy.sent == 1
            # 3) The wedged target was scheduled for disconnect (Core: drop a
            #    peer whose send buffer won't drain). Let the ensure_future run.
            await asyncio.sleep(0)
            assert wedged.disconnected, "wedged relay target was not disconnected"
        finally:
            p2p.ADDR_RELAY_SEND_TIMEOUT = orig

    asyncio.run(_run())


if __name__ == "__main__":
    test_relay_addr_awaits_bounds_and_disconnects_wedged_target()
    print("PASS: _relay_addr awaits + bounds + disconnects wedged target (no Task pile-up)")
