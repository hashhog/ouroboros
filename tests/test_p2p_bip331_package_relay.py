"""
Tests for BIP-331 package-relay dispatch in :mod:`ouroboros.p2p`.

Reference: Bitcoin Core net_processing.cpp ProcessMessage handlers for
``sendpackages`` / ``getpkgtxns`` / ``pkgtxns``.

These tests verify:
  - ``_register_package_relay_handlers`` wires the four BIP 331 commands
    (sendpackages / getpkgtxns / pkgtxns / ancpkginfo) onto the peer.
  - ``_negotiate_package_relay`` sends a sendpackages with the manager's
    advertised version + max_count + max_weight.
  - Receiving a sendpackages flips ``peer.package_relay_version`` /
    ``peer.package_max_count`` / ``peer.package_max_weight`` and — once both
    sides have spoken — registers the addr in ``_package_peers``.
  - ``getpkgtxns`` for a known mempool wtxid produces a ``pkgtxns`` reply.
  - ``getpkgtxns`` for an unknown wtxid is silently ignored.
  - ``pkgtxns`` from a peer that hasn't completed handshake is rejected.
"""

from __future__ import annotations

import asyncio
import sys
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Stub the Rust ``sync`` extension before importing ouroboros modules.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: True
    sys.modules["sync"] = _mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ouroboros.p2p import PeerManager  # noqa: E402
from ouroboros.p2p_messages import (  # noqa: E402
    GetPkgTxnsMessage,
    NetworkMessage,
    PkgTxnsMessage,
    SendPackagesMessage,
)
from ouroboros.peer import Peer  # noqa: E402


@dataclass
class _FakeMempool:
    """Minimal Mempool stand-in used by the package handlers."""
    transactions: dict[bytes, Any] = field(default_factory=dict)
    wtxid_to_txid: dict[bytes, bytes] = field(default_factory=dict)

    def get_transaction_by_wtxid(self, wtxid: bytes):
        txid = self.wtxid_to_txid.get(wtxid)
        if txid is None:
            return None
        entry = self.transactions.get(txid)
        return entry.tx if entry is not None else None


@dataclass
class _Entry:
    tx: Any
    parents: set[bytes] = field(default_factory=set)


@dataclass
class _FakeTx:
    """Stand-in for ouroboros.database.Transaction sufficient for the test."""
    _txid: bytes
    _wtxid: bytes
    _bytes: bytes

    def get_txid(self) -> bytes:
        return self._txid

    def get_wtxid(self) -> bytes:
        return self._wtxid

    def serialize_with_witness(self) -> bytes:
        return self._bytes


def _make_peer(addr: str = "10.0.0.1:18333") -> Peer:
    """Construct a Peer suitable for the package-relay handlers.

    The peer is marked relay_txs=True so the negotiation path runs.  Any
    socket I/O is bypassed via send_message stub in the tests below.
    """
    p = Peer("10.0.0.1", 18333, "regtest", relay_txs=True)
    return p


def _capture_handlers(pm: PeerManager, peer: Peer, addr: str):
    """Register BIP 331 handlers; return (sent_messages, handlers dict)."""
    sent: list[NetworkMessage] = []

    async def fake_send(msg: NetworkMessage) -> None:
        sent.append(msg)

    peer.send_message = fake_send  # type: ignore[assignment]
    pm._register_package_relay_handlers(peer, addr)
    handlers = {
        cmd: peer.message_handlers[cmd]
        for cmd in ("sendpackages", "getpkgtxns", "pkgtxns", "ancpkginfo")
    }
    return sent, handlers


class TestRegistration(unittest.TestCase):
    def setUp(self) -> None:
        self.pm = PeerManager(network="regtest", listen=False)

    def test_handlers_registered(self) -> None:
        peer = _make_peer()
        self.pm._register_package_relay_handlers(peer, "10.0.0.1:18333")
        for cmd in ("sendpackages", "getpkgtxns", "pkgtxns", "ancpkginfo"):
            self.assertIn(cmd, peer.message_handlers,
                          f"handler missing for {cmd}")


class TestNegotiation(unittest.TestCase):
    def setUp(self) -> None:
        self.pm = PeerManager(network="regtest", listen=False)
        self.pm.package_relay_version = 1
        self.pm.package_max_count = 25
        self.pm.package_max_weight = 404_000

    def test_negotiate_sends_sendpackages(self) -> None:
        peer = _make_peer()
        sent: list[NetworkMessage] = []

        async def fake_send(msg: NetworkMessage) -> None:
            sent.append(msg)

        peer.send_message = fake_send  # type: ignore[assignment]
        asyncio.run(self.pm._negotiate_package_relay(peer))
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].command, "sendpackages")
        sp = SendPackagesMessage.from_payload(sent[0].payload)
        self.assertEqual(sp.version, 1)
        self.assertEqual(sp.max_count, 25)
        self.assertEqual(sp.max_weight, 404_000)
        self.assertTrue(peer._sendpackages_sent)

    def test_negotiate_skips_block_relay_only_peer(self) -> None:
        peer = _make_peer()
        peer.relay_txs = False
        sent: list[NetworkMessage] = []

        async def fake_send(msg: NetworkMessage) -> None:
            sent.append(msg)

        peer.send_message = fake_send  # type: ignore[assignment]
        asyncio.run(self.pm._negotiate_package_relay(peer))
        self.assertEqual(sent, [])
        self.assertFalse(peer._sendpackages_sent)

    def test_inbound_sendpackages_sets_peer_flags(self) -> None:
        peer = _make_peer()
        addr = "10.0.0.1:18333"
        self.pm._register_package_relay_handlers(peer, addr)
        msg = SendPackagesMessage(
            version=1, max_count=20, max_weight=300_000
        ).to_network_message("regtest")
        asyncio.run(peer.message_handlers["sendpackages"](msg))
        self.assertEqual(peer.package_relay_version, 1)
        self.assertEqual(peer.package_max_count, 20)
        self.assertEqual(peer.package_max_weight, 300_000)
        self.assertTrue(peer._sendpackages_received)
        # Until *we* also sent sendpackages, the peer should NOT be in
        # _package_peers.
        self.assertNotIn(addr, self.pm._package_peers)

    def test_handshake_complete_after_both_sides(self) -> None:
        peer = _make_peer()
        addr = "10.0.0.1:18333"
        self.pm._register_package_relay_handlers(peer, addr)
        # Simulate having sent ours first.
        peer._sendpackages_sent = True
        msg = SendPackagesMessage().to_network_message("regtest")
        asyncio.run(peer.message_handlers["sendpackages"](msg))
        self.assertIn(addr, self.pm._package_peers)


class TestGetPkgTxns(unittest.TestCase):
    """getpkgtxns lookup uses Mempool.get_transaction_by_wtxid."""

    def setUp(self) -> None:
        self.pm = PeerManager(network="regtest", listen=False)
        # Plant a fake parent + child in the mempool stub
        self.parent_tx = _FakeTx(
            _txid=b"\x10" * 32,
            _wtxid=b"\x20" * 32,
            _bytes=b"PARENT-RAW",
        )
        self.child_tx = _FakeTx(
            _txid=b"\x11" * 32,
            _wtxid=b"\x21" * 32,
            _bytes=b"CHILD-RAW",
        )
        mp = _FakeMempool()
        mp.transactions[self.parent_tx.get_txid()] = _Entry(
            tx=self.parent_tx, parents=set()
        )
        mp.transactions[self.child_tx.get_txid()] = _Entry(
            tx=self.child_tx, parents={self.parent_tx.get_txid()}
        )
        mp.wtxid_to_txid[self.parent_tx.get_wtxid()] = self.parent_tx.get_txid()
        mp.wtxid_to_txid[self.child_tx.get_wtxid()] = self.child_tx.get_txid()
        self.pm._mempool = mp

    def test_known_wtxid_replies_with_pkgtxns(self) -> None:
        peer = _make_peer()
        sent, handlers = _capture_handlers(self.pm, peer, "10.0.0.1:18333")
        req = GetPkgTxnsMessage(
            child_wtxid=self.child_tx.get_wtxid()
        ).to_network_message("regtest")
        asyncio.run(handlers["getpkgtxns"](req))
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].command, "pkgtxns")
        pkg = PkgTxnsMessage.from_payload(sent[0].payload)
        # Expect parent first, child last (topological order).
        self.assertEqual(len(pkg.transactions), 2)
        self.assertEqual(pkg.transactions[0], b"PARENT-RAW")
        self.assertEqual(pkg.transactions[-1], b"CHILD-RAW")

    def test_unknown_wtxid_silent(self) -> None:
        peer = _make_peer()
        sent, handlers = _capture_handlers(self.pm, peer, "10.0.0.1:18333")
        req = GetPkgTxnsMessage(
            child_wtxid=b"\xff" * 32
        ).to_network_message("regtest")
        asyncio.run(handlers["getpkgtxns"](req))
        self.assertEqual(sent, [])


class TestPkgTxnsGate(unittest.TestCase):
    """Inbound pkgtxns is only honoured for negotiated peers."""

    def setUp(self) -> None:
        self.pm = PeerManager(network="regtest", listen=False)
        self.pm._mempool = _FakeMempool()

    def test_pkgtxns_from_unnegotiated_peer_ignored(self) -> None:
        peer = _make_peer()
        addr = "10.0.0.1:18333"
        sent, handlers = _capture_handlers(self.pm, peer, addr)
        # Peer never negotiated → addr not in _package_peers.
        self.assertNotIn(addr, self.pm._package_peers)
        msg = PkgTxnsMessage(transactions=[]).to_network_message("regtest")
        # Should not raise and must NOT mutate the mempool.
        asyncio.run(handlers["pkgtxns"](msg))
        self.assertEqual(self.pm._mempool.transactions, {})


if __name__ == "__main__":
    unittest.main()
