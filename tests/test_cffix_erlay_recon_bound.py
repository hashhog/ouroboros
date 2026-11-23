"""cffix-ouroboros-erlay-recon-set-bound: bound the per-peer Erlay
reconciliation set and time out an unanswered ``reqtxrcncl``.

Only reachable with ``OUROBOROS_ERLAY=1`` (Erlay is off by default, matching
Core, which never constructs a TxReconciliationTracker without the debug-only
-txreconciliation arg).

The bug on master:

* every relayed txid was added to each Erlay peer's ``local_set`` with no
  cap (``ReconciliationSet.add_tx``), and
* once we sent ``reqtxrcncl`` the peer was skipped by the reconciliation loop
  until it answered with a ``sketch`` -- with no timeout.

So an Erlay peer that negotiates and then never answers pins an
ever-growing set: 10,000 queued txids -> 10,000 entries, forever.

BIP-330 reconciliation sets are bounded and fall back to flooding
(the upstream Erlay work in Core uses MAX_RECONSET_SIZE = 3000 and fans a
transaction out instead of adding it to a full set).  These tests pin:

1. ``set_size`` stays at the cap after 10,000 queued txids while a
   reconciliation is pending, and the overflow is flooded (it goes to the
   peer's trickle queue, so it is still announced);
2. a pending reconciliation the peer never answers times out: the loop
   floods the pending set via INV and clears the in-flight flag.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from ouroboros import minisketch
from ouroboros.minisketch import ReconciliationSet
from ouroboros.p2p import PeerManager

ADDR = "10.0.0.1:8333"


def _txid(n: int) -> bytes:
    return struct.pack("<I", n) + b"\x11" * 28


class _FakeErlayPeer:
    """Minimal stand-in for ``Peer``: connected, full-relay, records sends."""

    def __init__(self) -> None:
        self.inbound = False
        self.relay_txs = True
        self.wtxid_relay = False
        self.sent: list = []

    def is_connected(self) -> bool:
        return True

    async def send_message(self, msg) -> None:
        self.sent.append(msg)


def _manager_with_erlay_peer(monkeypatch) -> tuple[PeerManager, _FakeErlayPeer]:
    monkeypatch.setenv("OUROBOROS_ERLAY", "1")
    pm = PeerManager(network="regtest", max_peers=4)
    assert pm.erlay_enabled
    peer = _FakeErlayPeer()
    pm.peers[ADDR] = peer
    pm._erlay_peers[ADDR] = ReconciliationSet(local_salt=1, remote_salt=2)
    pm._erlay_pending_recon[ADDR] = False
    return pm, peer


async def _run_rounds(pm: PeerManager, seconds: float) -> None:
    """Run the real reconciliation loop for *seconds*, then stop it."""
    pm._reconciliation_interval = 0.01
    pm.running = True
    task = asyncio.ensure_future(pm._reconciliation_loop())
    await asyncio.sleep(seconds)
    pm.running = False
    await asyncio.wait_for(task, timeout=2)


def test_recon_set_capped_while_reconciliation_pending(monkeypatch):
    pm, peer = _manager_with_erlay_peer(monkeypatch)
    rs = pm._erlay_peers[ADDR]

    # One reconciliation round: the loop sends reqtxrcncl and marks the
    # peer in flight.  The fake peer never answers.
    rs.add_tx(_txid(0))
    asyncio.run(_run_rounds(pm, 0.05))
    assert pm._erlay_pending_recon[ADDR] is True
    assert any(m.command == "reqtxrcncl" for m in peer.sent)

    # Queue 10,000 relayed txids while the peer sits on the request.
    n = 10_000
    for i in range(1, n + 1):
        pm.queue_tx_for_relay(_txid(i), _txid(i), fee=1000, vsize=100)

    # Master has no cap constant; 3000 is the bound the fix introduces.
    cap = getattr(minisketch, "MAX_RECONSET_SIZE", 3000)
    assert cap == 3000
    assert rs.set_size <= cap, f"local_set holds {rs.set_size} txids (cap {cap})"

    # The overflow is not dropped: it falls back to flooding via the
    # peer's trickle queue, so every txid is still announced somewhere.
    queue = pm._trickle_queues.get(ADDR)
    flooded = len(queue.pending_wtxids) if queue is not None else 0
    assert rs.set_size + flooded >= n


def test_unanswered_reconciliation_times_out_and_floods(monkeypatch):
    pm, peer = _manager_with_erlay_peer(monkeypatch)
    rs = pm._erlay_peers[ADDR]
    pm._reconciliation_timeout = 0.05

    for i in range(5):
        rs.add_tx(_txid(i))

    # Long enough for: round 1 sends reqtxrcncl, then the timeout elapses
    # and a later round gives up on the peer.
    asyncio.run(_run_rounds(pm, 0.3))

    invs = [m for m in peer.sent if m.command == "inv"]
    assert invs, "pending reconciliation never timed out into an INV flood"
    assert rs.set_size == 0
    for i in range(5):
        assert _txid(i) in rs.announced_txids
