"""
getaddr / addr anti-DoS guards — functional (Core net_processing.cpp parity)

Reference: bitcoin-core/src/net_processing.cpp
  - getaddr handler  : 4822 (ignore non-inbound), 4833 (m_getaddr_recvd once),
                       4842/4844 (MAX_ADDR_TO_SEND=1000, MAX_PCT_ADDR_TO_SEND=23)
  - ProcessAddrs     : 5644-5671 (m_addr_token_bucket init 1.0, refill
                       elapsed*MAX_ADDR_RATE_PER_SECOND[0.1] capped
                       MAX_ADDR_PROCESSING_TOKEN_BUCKET[1000], spend 1/addr,
                       drop excess)
  - constants        : net_processing.cpp:188-197

These drive the ACTUAL handlers registered by
``PeerManager._register_addr_handlers`` (and the addrman 23%-cap path), so they
prove the live behaviour, not just the presence of a field.
"""

import asyncio
import time
import unittest

from ouroboros.p2p import (
    PeerManager,
    MAX_ADDR_RATE_PER_SECOND,
    MAX_ADDR_PROCESSING_TOKEN_BUCKET,
)
from ouroboros.peer import Peer
from ouroboros.p2p_messages import (
    AddrMessage,
    GetAddrMessage,
    NetworkAddress,
)


def _make_pm_and_peer(inbound=True):
    """A PeerManager (no socket) + a registered Peer with addr handlers wired."""
    pm = PeerManager(network="mainnet", listen=False)
    peer = Peer(host="9.9.9.9", port=8333, network="mainnet", inbound=inbound)
    peer.handshake_complete = True
    addr_key = "9.9.9.9:8333"
    pm._register_addr_handlers(peer, addr_key)
    return pm, peer, addr_key


def _capture_sends(peer):
    """Patch peer.send_message to record outgoing NetworkMessages."""
    sent = []

    async def _fake_send(msg):
        sent.append(msg)

    peer.send_message = _fake_send  # type: ignore[assignment]
    return sent


def _addr_message(n, ts=None):
    """Build an AddrMessage carrying ``n`` distinct routable IPv4 addresses."""
    if ts is None:
        ts = int(time.time())
    addrs = []
    for i in range(n):
        na = NetworkAddress.from_ipv4(
            f"{20 + i // 65536}.{(i // 256) % 256}.{i % 256}.5",
            8333,
            services=1,  # NODE_NETWORK
        )
        addrs.append((ts, na))
    return AddrMessage(addresses=addrs)


# ---------------------------------------------------------------------------
# (a) getaddr-once + ignore-outbound
# ---------------------------------------------------------------------------
class TestGetaddrOnceAndOutbound(unittest.TestCase):
    def test_first_getaddr_answered_repeat_ignored(self):
        """Core net_processing.cpp:4833 — only the FIRST getaddr is answered."""
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        # Seed addrman so there is something to share.
        now = time.time()
        for i in range(50):
            pm.addrman.add(f"3.4.{i // 256}.{i % 256}", 8333, timestamp=now)
        # Mark a success so a non-empty set exists even after capping.
        sent = _capture_sends(peer)
        handler = peer.message_handlers["getaddr"]
        gmsg = GetAddrMessage().to_network_message("mainnet")

        self.assertFalse(peer.getaddr_recvd)
        asyncio.run(handler(gmsg))
        self.assertTrue(peer.getaddr_recvd, "first getaddr sets getaddr_recvd")
        first_responses = len(sent)

        # Repeat: must be ignored — no new addr message sent.
        asyncio.run(handler(gmsg))
        self.assertEqual(
            len(sent), first_responses,
            "repeated getaddr must NOT produce another response (Core once-guard)",
        )

    def test_outbound_getaddr_ignored(self):
        """Core net_processing.cpp:4822 — getaddr from a non-inbound peer is ignored."""
        pm, peer, _ = _make_pm_and_peer(inbound=False)
        now = time.time()
        for i in range(50):
            pm.addrman.add(f"5.6.{i // 256}.{i % 256}", 8333, timestamp=now)
        sent = _capture_sends(peer)
        handler = peer.message_handlers["getaddr"]
        asyncio.run(handler(GetAddrMessage().to_network_message("mainnet")))
        self.assertEqual(
            len(sent), 0,
            "getaddr from an OUTBOUND peer must be ignored (Core 4822)",
        )
        # And the once-guard must NOT be tripped (we never answered).
        self.assertFalse(peer.getaddr_recvd)


# ---------------------------------------------------------------------------
# (b) 23%-cap in the live getaddr response
# ---------------------------------------------------------------------------
class TestGetaddr23PctCap(unittest.TestCase):
    def test_response_capped_to_23pct(self):
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        now = time.time()
        for i in range(400):
            pm.addrman.add(f"7.8.{i // 256}.{i % 256}", 8333, timestamp=now)
        stored = len(pm.addrman.get_addresses(count=10000))
        expected_cap = (23 * stored) // 100  # Core FLOOR(23*size/100)

        sent = _capture_sends(peer)
        handler = peer.message_handlers["getaddr"]
        asyncio.run(handler(GetAddrMessage().to_network_message("mainnet")))

        # Exactly one addr response, capped at FLOOR(23%).
        self.assertEqual(len(sent), 1, "one addr response to a single getaddr")
        resp = AddrMessage.from_payload(sent[0].payload)
        self.assertLessEqual(
            len(resp.addresses), expected_cap,
            f"response must be <= FLOOR(23%)={expected_cap} of {stored} stored",
        )
        self.assertLessEqual(len(resp.addresses), 1000, "hard 1000 cap")
        self.assertLess(
            len(resp.addresses), stored,
            "23%-cap must return a strict subset of the addrman",
        )


# ---------------------------------------------------------------------------
# (c) inbound-addr token bucket (shared across addr + addrv2)
# ---------------------------------------------------------------------------
class TestInboundAddrTokenBucket(unittest.TestCase):
    def test_bucket_initial_and_drain(self):
        """init 1.0 -> a burst of N addresses admits ~1, drops the rest (no refill)."""
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        self.assertEqual(peer.addr_token_bucket, 1.0, "Core init bucket = 1.0")

        # Freeze the clock so no tokens refill mid-test (deterministic).
        peer.addr_token_timestamp = time.monotonic()
        sent_before = peer.addr_processed
        msg = _addr_message(100).to_network_message("mainnet")
        asyncio.run(peer.message_handlers["addr"](msg))
        # With bucket=1.0 and ~0 refill, exactly 1 address is admitted.
        admitted = peer.addr_processed - sent_before
        self.assertEqual(
            admitted, 1,
            "bucket=1.0 admits exactly one address from a 100-addr burst",
        )
        self.assertEqual(
            peer.addr_rate_limited, 99,
            "remaining 99 addresses are rate-limited (dropped)",
        )
        # Bucket is now drained below 1.0.
        self.assertLess(peer.addr_token_bucket, 1.0)

    def test_refill_rate_is_core_value(self):
        """Refill admits floor(elapsed * 0.1) extra tokens (Core 0.1/sec)."""
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        # Drain the initial token.
        peer.addr_token_bucket = 0.0
        # Pretend 100s elapsed -> 100 * 0.1 = 10 tokens refilled.
        peer.addr_token_timestamp = time.monotonic() - 100.0
        admitted = pm._admit_addrs_token_bucket(peer, 50)
        self.assertEqual(
            admitted, 10,
            "100s * MAX_ADDR_RATE_PER_SECOND(0.1) = 10 tokens admitted",
        )
        self.assertEqual(MAX_ADDR_RATE_PER_SECOND, 0.1)

    def test_bucket_soft_capped_at_1000(self):
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        peer.addr_token_bucket = 0.0
        # Huge elapsed time would overflow the bucket; it must clamp at 1000.
        peer.addr_token_timestamp = time.monotonic() - 1_000_000.0
        pm._refill_addr_token_bucket(peer)
        self.assertEqual(
            peer.addr_token_bucket, MAX_ADDR_PROCESSING_TOKEN_BUCKET,
            "bucket soft-capped at MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000",
        )

    def test_addr_and_addrv2_share_one_bucket(self):
        """addr and addrv2 spend from the SAME per-peer bucket (Core: one Peer field)."""
        pm, peer, _ = _make_pm_and_peer(inbound=True)
        # Give the bucket exactly 3 tokens, frozen (no refill).
        peer.addr_token_bucket = 3.0
        peer.addr_token_timestamp = time.monotonic()
        # Spend 2 via addr.  (A real monotonic-clock refill of a few
        # micro-tokens may occur between calls — Core ProcessAddrs always
        # refills first — so we assert ~1.0 within one token, then prove the
        # behaviour: only ONE more address can be admitted from the shared bucket.)
        msg = _addr_message(2).to_network_message("mainnet")
        asyncio.run(peer.message_handlers["addr"](msg))
        self.assertGreaterEqual(peer.addr_token_bucket, 1.0)
        self.assertLess(peer.addr_token_bucket, 2.0)
        # Now a 5-addr addr burst sees only ~1 token left -> admits 1.
        before = peer.addr_processed
        msg2 = _addr_message(5).to_network_message("mainnet")
        asyncio.run(peer.message_handlers["addr"](msg2))
        self.assertEqual(
            peer.addr_processed - before, 1,
            "the shared bucket (now ~1.0) admits exactly one more address",
        )


# ---------------------------------------------------------------------------
# (d) addr/addrv2 timestamp clamping (Core net_processing.cpp:5678-5680)
# ---------------------------------------------------------------------------
class TestAddrTimestampClamping(unittest.TestCase):
    """Core net_processing.cpp:5678-5680:
      if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min)
          addr.nTime = current_time - 5 * 24h;

    Pre-fix: ouroboros stored the raw peer-supplied timestamp.
    Post-fix: timestamps <= 100_000_000 or > now+600 are clamped to now-5days.
    """

    def _make_pm_peer_with_full_bucket(self):
        pm, peer, addr_key = _make_pm_and_peer(inbound=True)
        # Give enough tokens to admit all addresses without rate-limiting.
        peer.addr_token_bucket = 1000.0
        peer.addr_token_timestamp = time.monotonic()
        return pm, peer, addr_key

    def test_ancient_timestamp_clamped_addr(self):
        """An addr entry with ts=1 (pre-2001) must be stored with a clamped timestamp.

        Non-vacuous: without the fix, addrman._addrs[key].last_seen == 1;
        with the fix, last_seen is approximately now - 5*24*3600.
        """
        pm, peer, _ = self._make_pm_peer_with_full_bucket()
        ancient_ts = 1  # far before the 100_000_000 threshold (~1973)
        msg = _addr_message(1, ts=ancient_ts).to_network_message("mainnet")
        t_before = time.time()
        asyncio.run(peer.message_handlers["addr"](msg))
        t_after = time.time()

        # Lookup the entry that should have been stored.
        key = "20.0.0.5:8333"
        self.assertIn(key, pm.addrman._addrs,
                      "addr entry must be stored despite ancient timestamp")
        stored_ts = pm.addrman._addrs[key].last_seen

        # The stored timestamp must NOT be the raw ancient value.
        self.assertGreater(
            stored_ts, ancient_ts + 100,
            f"stored timestamp ({stored_ts}) must not be the raw ancient value ({ancient_ts})"
        )
        # Must be in the range: now - 5days ± 10s.
        expected_lo = t_before - 5 * 24 * 3600 - 10
        expected_hi = t_after - 5 * 24 * 3600 + 10
        self.assertGreaterEqual(stored_ts, expected_lo,
                                f"clamped ts {stored_ts} below expected floor {expected_lo}")
        self.assertLessEqual(stored_ts, expected_hi,
                             f"clamped ts {stored_ts} above expected ceiling {expected_hi}")

    def test_future_timestamp_clamped_addr(self):
        """An addr entry with ts 1 hour in the future must be clamped."""
        pm, peer, _ = self._make_pm_peer_with_full_bucket()
        future_ts = int(time.time()) + 3600  # 1h in the future (> now + 10 min)
        msg = _addr_message(1, ts=future_ts).to_network_message("mainnet")
        t_before = time.time()
        asyncio.run(peer.message_handlers["addr"](msg))

        key = "20.0.0.5:8333"
        self.assertIn(key, pm.addrman._addrs,
                      "addr entry must be stored despite future timestamp")
        stored_ts = pm.addrman._addrs[key].last_seen

        self.assertLess(stored_ts, time.time(),
                        "clamped ts must be in the past, not the supplied future value")
        # Must be approximately now - 5days.
        expected_lo = t_before - 5 * 24 * 3600 - 10
        self.assertGreaterEqual(stored_ts, expected_lo,
                                f"clamped ts {stored_ts} below expected floor {expected_lo}")

    def test_valid_recent_timestamp_not_clamped_addr(self):
        """A recent valid timestamp (now - 1h) must NOT be clamped."""
        pm, peer, _ = self._make_pm_peer_with_full_bucket()
        valid_ts = int(time.time()) - 3600  # 1 hour ago — well within the valid window
        msg = _addr_message(1, ts=valid_ts).to_network_message("mainnet")
        asyncio.run(peer.message_handlers["addr"](msg))

        key = "20.0.0.5:8333"
        self.assertIn(key, pm.addrman._addrs)
        stored_ts = pm.addrman._addrs[key].last_seen
        # Must be preserved (within 1s of the original).
        self.assertAlmostEqual(stored_ts, float(valid_ts), delta=1.0,
                               msg="valid recent timestamp must be stored as-is")


if __name__ == "__main__":
    unittest.main()
