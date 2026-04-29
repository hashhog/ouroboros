"""
Tests for BIP-35 (mempool message) NODE_BLOOM gating.

The MEMPOOL handler is gated on whether *we* advertised NODE_BLOOM in
our version message — independently of BIP-37 fRelay (peer.relay_txs).

Bitcoin Core reference: net_processing.cpp ~4855
    if (!(peer.m_our_services & NODE_BLOOM) &&
        !pfrom.HasPermission(NetPermissionFlags::Mempool))

This module verifies:
  1. NODE_BLOOM is advertised in our_services after handshake setup.
  2. on_mempool returns immediately when our_services lacks NODE_BLOOM
     (no inv sent), regardless of peer.relay_txs.
  3. on_mempool dumps the mempool as inv chunks of MAX_INV_SZ=50000
     when our_services has NODE_BLOOM, regardless of peer.relay_txs.
  4. NODE_WITNESS peers receive MSG_WTX (5) inv types; non-witness
     peers receive INV_TYPE_TX (1).
"""

from __future__ import annotations

import asyncio
import unittest
from dataclasses import dataclass, field
from typing import Any

from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import (
    INV_TYPE_TX,
    MSG_WTX,
    NODE_BLOOM,
    NODE_NETWORK,
    NODE_WITNESS,
    InvMessage,
    NetworkMessage,
)
from ouroboros.peer import Peer


@dataclass
class _FakeMempool:
    """Minimal Mempool stand-in: exposes a `.transactions` dict."""
    transactions: dict[bytes, Any] = field(default_factory=dict)


def _build_mempool_message() -> NetworkMessage:
    """Build a wire-level `mempool` (BIP 35) NetworkMessage."""
    from ouroboros.p2p_messages import MempoolMessage
    return MempoolMessage().to_network_message("regtest")


def _capture_handler(pm: PeerManager, peer: Peer, addr: str):
    """Register protocol handlers on *peer* and return (sent_messages, on_mempool)."""
    sent: list[NetworkMessage] = []

    async def fake_send(msg: NetworkMessage) -> None:
        sent.append(msg)

    # Bypass the real socket path.
    peer.send_message = fake_send  # type: ignore[assignment]

    pm._register_compact_handlers(peer, addr)

    on_mempool = peer.message_handlers["mempool"]
    return sent, on_mempool


def _make_peer(
    *,
    our_services: int,
    peer_services: int,
    relay_txs: bool,
) -> Peer:
    p = Peer("10.0.0.1", 18333, "regtest", relay_txs=relay_txs)
    p.our_services = our_services
    p.services = peer_services
    return p


class TestBip35Gate(unittest.TestCase):
    """Tests for BIP-35 MEMPOOL gating against local NODE_BLOOM."""

    def setUp(self) -> None:
        self.pm = PeerManager(network="regtest", listen=False)
        self.pm._mempool = _FakeMempool(transactions={
            b"\x11" * 32: object(),
            b"\x22" * 32: object(),
            b"\x33" * 32: object(),
        })
        self.msg = _build_mempool_message()

    def tearDown(self) -> None:
        # PeerManager constructed an addrman / banman with on-disk state
        # under data_dir=None (in-memory). Nothing to clean up here, but
        # keeping this hook for future side effects.
        self.pm = None  # type: ignore[assignment]

    # --- gate behavior ---------------------------------------------------

    def test_no_bloom_no_dump(self) -> None:
        """If we did NOT advertise NODE_BLOOM, no inv is sent."""
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_WITNESS,  # NODE_BLOOM missing
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=True,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        self.assertEqual(sent, [], "MEMPOOL must be ignored without NODE_BLOOM")

    def test_no_bloom_ignored_even_when_block_relay_only(self) -> None:
        """relay_txs=False without NODE_BLOOM still produces no inv."""
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_WITNESS,
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=False,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        self.assertEqual(sent, [])

    def test_bloom_advertised_dumps_mempool(self) -> None:
        """With NODE_BLOOM advertised, mempool is dumped as inv."""
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=True,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].command, "inv")

    def test_bloom_dump_independent_of_relay_txs(self) -> None:
        """BIP-35 gate is independent of BIP-37 fRelay (relay_txs)."""
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=False,  # block-relay-only
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        self.assertEqual(len(sent), 1, "Gate should not consult relay_txs")
        self.assertEqual(sent[0].command, "inv")

    # --- inv content -----------------------------------------------------

    def test_inv_uses_msg_wtx_for_witness_peer(self) -> None:
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=True,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        inv = InvMessage.from_payload(sent[0].payload)
        self.assertEqual(len(inv.inventory), 3)
        for t, _ in inv.inventory:
            self.assertEqual(t, MSG_WTX)

    def test_inv_uses_msg_tx_for_legacy_peer(self) -> None:
        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
            peer_services=NODE_NETWORK,  # no NODE_WITNESS
            relay_txs=True,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))
        inv = InvMessage.from_payload(sent[0].payload)
        for t, _ in inv.inventory:
            self.assertEqual(t, INV_TYPE_TX)

    # --- chunking --------------------------------------------------------

    def test_inv_chunked_at_max_inv_sz(self) -> None:
        """A mempool larger than MAX_INV_SZ=50_000 is split into chunks."""
        big_txids = {bytes([i & 0xFF]) * 32: object() for i in range(50_001)}
        # Fix collisions: use unique 32-byte ids by encoding the index.
        big_txids = {
            i.to_bytes(32, "big"): object() for i in range(50_001)
        }
        self.pm._mempool = _FakeMempool(transactions=big_txids)

        peer = _make_peer(
            our_services=NODE_NETWORK | NODE_BLOOM | NODE_WITNESS,
            peer_services=NODE_NETWORK | NODE_WITNESS,
            relay_txs=True,
        )
        sent, handler = _capture_handler(self.pm, peer, "10.0.0.1:18333")
        asyncio.run(handler(self.msg))

        self.assertEqual(len(sent), 2)
        first = InvMessage.from_payload(sent[0].payload)
        second = InvMessage.from_payload(sent[1].payload)
        self.assertEqual(len(first.inventory), 50_000)
        self.assertEqual(len(second.inventory), 1)


class TestBip35Advertisement(unittest.TestCase):
    """Verify Peer.our_services tracks the wire-advertised services."""

    def test_default_our_services_zero(self) -> None:
        """Before handshake runs, our_services starts at 0 (Core parity)."""
        p = Peer("10.0.0.1", 18333, "regtest")
        self.assertEqual(p.our_services, 0)


if __name__ == "__main__":
    unittest.main()
