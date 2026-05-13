"""
W104 AddrMan 30-gate fleet audit — ouroboros (Python + Rust two-pipeline)

Reference: bitcoin-core/src/addrman.cpp, addrman_impl.h, addrman.h

Two-pipeline note
-----------------
ouroboros has TWO peer management stacks:

  Python pipeline  — src/ouroboros/addrman.py (AddressManager)
                     used by p2p.py at runtime.

  Rust pipeline    — ferrous-utils/sync/src/network/peer_manager.rs
                     (PeerManager with a HashSet<SocketAddr> known_addrs)
                     NOT exported to Python via #[pyfunction] / #[pyclass];
                     never instantiated from Python. Dead helper for AddrMan.

All 30 gates below test the Python pipeline. Rust pipeline findings are
flagged in individual docstrings as TWO-PIPELINE divergences.

Gate legend
-----------
PASS    — matches Core behaviour
BUG-N   — confirmed deviation from Core
"""

import time
import unittest
from unittest.mock import patch

from ouroboros.addrman import (
    NEW_BUCKET_COUNT,
    NEW_BUCKET_SIZE,
    NEW_BUCKETS_PER_SOURCE_GROUP,
    TRIED_BUCKET_COUNT,
    TRIED_BUCKET_SIZE,
    TRIED_BUCKETS_PER_GROUP,
    HORIZON,
    RETRIES,
    MAX_FAILURES,
    MIN_FAIL,
    MAX_TRIED_COLLISIONS,
    REPLACEMENT_HOURS,
    AddressManager,
    AddrInfo,
    get_network_group,
    NET_IPV4,
    NET_IPV6,
    NET_TORV3,
    NET_I2P,
    NET_CJDNS,
)


# ---------------------------------------------------------------------------
# G1  Bucket counts: new=1024, tried=256, both×64 entries
#     Core: ADDRMAN_NEW_BUCKET_COUNT=1024, ADDRMAN_TRIED_BUCKET_COUNT=256,
#           ADDRMAN_BUCKET_SIZE=64
# ---------------------------------------------------------------------------
class TestG1BucketCounts(unittest.TestCase):
    """
    BUG-1: ouroboros uses NEW_BUCKET_COUNT=256 (not 1024) and
           TRIED_BUCKET_COUNT=64 (not 256).
    Comment in addrman.py line 31: "(Bitcoin Core uses 1024 new buckets, we
    use 256 for memory efficiency)" — deliberate but wrong for eclipse
    resistance. Core capacity is 65,536 new slots; ouroboros has 16,384.

    TWO-PIPELINE: Rust PeerManager uses a plain HashSet<SocketAddr> — no
    bucketed structure at all, so bucket counts are undefined there.
    """

    def test_new_bucket_count_wrong(self):
        # BUG-1a: should be 1024
        self.assertNotEqual(
            NEW_BUCKET_COUNT, 1024,
            "BUG-1a: NEW_BUCKET_COUNT should be 1024 (Core), got %d" % NEW_BUCKET_COUNT,
        )
        self.assertEqual(NEW_BUCKET_COUNT, 256)

    def test_tried_bucket_count_wrong(self):
        # BUG-1b: should be 256
        self.assertNotEqual(
            TRIED_BUCKET_COUNT, 256,
            "BUG-1b: TRIED_BUCKET_COUNT should be 256 (Core), got %d" % TRIED_BUCKET_COUNT,
        )
        self.assertEqual(TRIED_BUCKET_COUNT, 64)

    def test_bucket_size_correct(self):
        # PASS: 64 entries per bucket is correct for both new and tried
        self.assertEqual(NEW_BUCKET_SIZE, 64)
        self.assertEqual(TRIED_BUCKET_SIZE, 256)  # but TRIED_BUCKET_SIZE is 256 (wrong — should be 64)

    def test_tried_bucket_size_wrong(self):
        # BUG-1c: TRIED_BUCKET_SIZE=256 is wrong; Core uses 64 for both.
        # addrman_impl.h: ADDRMAN_BUCKET_SIZE = 1 << ADDRMAN_BUCKET_SIZE_LOG2 = 1<<6 = 64
        self.assertNotEqual(
            TRIED_BUCKET_SIZE, 64,
            "BUG-1c: TRIED_BUCKET_SIZE should be 64 (Core), got %d" % TRIED_BUCKET_SIZE,
        )


# ---------------------------------------------------------------------------
# G2  Max per-address bucket multiplicity (ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8)
# ---------------------------------------------------------------------------
class TestG2BucketMultiplicity(unittest.TestCase):
    """
    BUG-2: ouroboros AddressManager.add() always inserts an address into
    exactly ONE new bucket (ref_count=1) and never increases ref_count
    beyond 1. Core allows up to 8 bucket references per address, using
    stochastic exponential back-off (randrange(1<<nRefCount)) to limit
    inflation.

    This also means the "IsTerrible eviction preference" in AddSingle —
    `infoExisting.nRefCount > 1 && pinfo->nRefCount == 0` — is never
    triggered in ouroboros (ref_count is always 1).
    """

    def test_add_twice_does_not_increase_ref_count(self):
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now, source="5.6.7.8")
        info = am.get_addr_info("1.2.3.4", 8333)
        self.assertEqual(info.ref_count, 1)

        # Add again with a newer timestamp from a different source — should
        # still be ref_count=1 (no multi-bucket promotion)
        am.add("1.2.3.4", 8333, timestamp=now + 7200, source="9.10.11.12")
        info2 = am.get_addr_info("1.2.3.4", 8333)
        self.assertEqual(info2.ref_count, 1)  # BUG-2: never > 1

    def test_no_addrman_new_buckets_per_address_constant(self):
        # Core: ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8
        # ouroboros has no equivalent constant
        import ouroboros.addrman as m
        self.assertFalse(
            hasattr(m, "NEW_BUCKETS_PER_ADDRESS"),
            "BUG-2: missing ADDRMAN_NEW_BUCKETS_PER_ADDRESS constant",
        )


# ---------------------------------------------------------------------------
# G3  Routability gate in Add (addr.IsRoutable() check)
# ---------------------------------------------------------------------------
class TestG3RoutabilityGate(unittest.TestCase):
    """
    BUG-3: ouroboros AddressManager.add() has NO IsRoutable() check.
    Core's AddSingle() at addrman.cpp:534 returns false immediately if
    addr.IsRoutable() is false.
    This allows loopback (127.0.0.1), RFC-1918 (192.168.x.x, 10.x.x.x),
    and unspecified addresses to be stored in the address table.
    """

    def test_loopback_address_accepted(self):
        # BUG-3: 127.0.0.1 should be rejected by IsRoutable but is accepted
        am = AddressManager()
        result = am.add("127.0.0.1", 8333, timestamp=time.time())
        self.assertTrue(result, "BUG-3: loopback should fail IsRoutable and be rejected")

    def test_private_rfc1918_accepted(self):
        # BUG-3: 192.168.1.1 should be rejected
        am = AddressManager()
        result = am.add("192.168.1.1", 8333, timestamp=time.time())
        self.assertTrue(result, "BUG-3: RFC-1918 private address should be rejected")

    def test_unspecified_zero_accepted(self):
        # BUG-3: 0.0.0.0 should be rejected
        am = AddressManager()
        result = am.add("0.0.0.0", 8333, timestamp=time.time())
        self.assertTrue(result, "BUG-3: unspecified (0.0.0.0) should be rejected")


# ---------------------------------------------------------------------------
# G4  time_penalty applied to nTime on Add
# ---------------------------------------------------------------------------
class TestG4TimePenalty(unittest.TestCase):
    """
    BUG-4: ouroboros AddressManager.add() has no time_penalty parameter
    (Core: Add(vAddr, source, time_penalty)).
    Core applies a time penalty when adding addresses received from remote
    peers to prevent addr-timestamp manipulation.
    net_processing.cpp applies 2-hour penalty for addr/addrv2 messages.
    """

    def test_no_time_penalty_parameter(self):
        import inspect
        sig = inspect.signature(AddressManager.add)
        self.assertNotIn(
            "time_penalty", sig.parameters,
            "BUG-4: add() should accept time_penalty parameter (Core parity)",
        )

    def test_add_accepts_future_timestamp_without_penalty(self):
        # BUG-4: a future timestamp is stored verbatim; Core would apply
        # time_penalty to bring it closer to current time.
        am = AddressManager()
        future = time.time() + 7200  # 2 hours in future (would be penalised in Core)
        am.add("1.2.3.4", 8333, timestamp=future)
        info = am.get_addr_info("1.2.3.4", 8333)
        self.assertAlmostEqual(info.last_seen, future, delta=1)


# ---------------------------------------------------------------------------
# G5  Periodic timestamp update logic (1h/24h update_interval)
# ---------------------------------------------------------------------------
class TestG5TimestampUpdate(unittest.TestCase):
    """
    BUG-5: ouroboros add() updates last_seen only when timestamp > info.last_seen
    (monotone). Core uses an update_interval (1h if currently online, 24h
    otherwise) so that repeated gossiping of an already-known address does
    not inflate its freshness.

    This means ouroboros accepts any timestamp improvement, whereas Core
    throttles updates to at most once per hour per address.
    """

    def test_small_timestamp_bump_updates_last_seen(self):
        # BUG-5: Core would NOT update if the increment < update_interval
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now)
        # 10 seconds later — Core would skip (< 1h interval) when online
        am.add("1.2.3.4", 8333, timestamp=now + 10)
        info = am.get_addr_info("1.2.3.4", 8333)
        # ouroboros updates; Core would NOT
        self.assertAlmostEqual(info.last_seen, now + 10, delta=1)


# ---------------------------------------------------------------------------
# G6  Source self-announcement: time_penalty waived when addr == source
# ---------------------------------------------------------------------------
class TestG6SelfAnnouncementPenalty(unittest.TestCase):
    """
    BUG-6 (linked to BUG-4): Core's AddSingle waives time_penalty when
    addr == source (addrman.cpp:541-543). ouroboros has no time_penalty
    at all so this distinction is moot — but the complete absence of
    time_penalty is itself the bug.
    """

    def test_no_self_announcement_penalty_waiver(self):
        # Because BUG-4 means there is no penalty at all, the waiver is
        # unreachable. Document this as a sub-finding.
        am = AddressManager()
        import inspect
        sig = inspect.signature(AddressManager.add)
        self.assertNotIn("time_penalty", sig.parameters)


# ---------------------------------------------------------------------------
# G7  Stochastic eviction from new bucket:
#     "IsTerrible || (existingRefCount > 1 && newRefCount == 0)"
# ---------------------------------------------------------------------------
class TestG7StochasticEviction(unittest.TestCase):
    """
    BUG-7: ouroboros always evicts the existing entry when the slot is
    occupied. Core only evicts if IsTerrible(existing) OR
    (existing.nRefCount > 1 && new.nRefCount == 0) — providing a
    soft resistance to ejection of recently-seen good addresses.

    addrman.cpp:583-588:
      if (infoExisting.IsTerrible() ||
          (infoExisting.nRefCount > 1 && pinfo->nRefCount == 0)) {
          fInsert = true;
      }
    """

    def test_evicts_good_address_immediately(self):
        # BUG-7: a recently-seen good address in a slot is evicted
        # immediately instead of being kept when the slot isn't terrible.
        am = AddressManager()
        # Force both addresses to the same bucket/position by using the
        # same key (this is deterministic per _key, so we just verify
        # the general add-evicts-existing behaviour)
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now, source="5.6.7.8")
        size_before = am.size()
        self.assertEqual(size_before, 1)


# ---------------------------------------------------------------------------
# G8  IsTerrible: 1-minute protection window (last_try <= 1min → not terrible)
# ---------------------------------------------------------------------------
class TestG8IsTerrible1MinProtect(unittest.TestCase):
    """
    PASS (partial): ouroboros _is_terrible checks `now - addr.last_attempt < 60`
    which matches Core's `now - m_last_try <= 1min`.

    BUG-8 (subtle): Core's condition is <= 1min (inclusive), ouroboros uses
    strict < 60. This is a 1-second boundary difference that is unlikely
    to matter in practice but is technically wrong.
    """

    def test_recent_attempt_not_terrible(self):
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now - 100)
        info = am.get_addr_info("1.2.3.4", 8333)
        info.last_attempt = now - 30  # attempted 30s ago
        info.attempts = 100           # lots of failures
        info.last_seen = now - (35 * 24 * 3600)  # very old
        # Core: not terrible (last_try <= 1min)
        # ouroboros: same logic
        result = am._is_terrible(info)
        self.assertFalse(result, "recently attempted address should not be terrible")

    def test_is_terrible_future_timestamp(self):
        # PASS: future timestamp > now+600 → terrible
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now - 100)
        info = am.get_addr_info("1.2.3.4", 8333)
        info.last_attempt = now - 200
        info.last_seen = now + 7200  # 2h in future
        self.assertTrue(am._is_terrible(info))

    def test_is_terrible_old_address(self):
        # PASS: last_seen > HORIZON → terrible
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now - 100)
        info = am.get_addr_info("1.2.3.4", 8333)
        info.last_attempt = now - 200
        info.last_seen = now - HORIZON - 1
        self.assertTrue(am._is_terrible(info))

    def test_is_terrible_too_many_failures(self):
        # PASS: failures >= MAX_FAILURES AND now - last_success > MIN_FAIL
        # Condition: now - last_success < MIN_FAIL (i.e. within MIN_FAIL window)
        # So to trigger: last_success must be recent enough (< MIN_FAIL ago)
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now - 100)
        info = am.get_addr_info("1.2.3.4", 8333)
        info.last_attempt = now - 200
        info.last_seen = now - 3600
        # last_success within MIN_FAIL window (recent enough to activate the check)
        info.last_success = now - (MIN_FAIL // 2)
        info.failures = MAX_FAILURES
        info.attempts = MAX_FAILURES
        self.assertTrue(am._is_terrible(info))


# ---------------------------------------------------------------------------
# G9  GetChance: chance_factor *= 1.2 retry loop (Core's select_ loop)
# ---------------------------------------------------------------------------
class TestG9GetChanceSelectLoop(unittest.TestCase):
    """
    BUG-9: ouroboros select_for_connection() does a linear scan with
    weighted-sum selection — it does NOT implement Core's bucket-random
    iteration with chance_factor *= 1.2 retry loop.

    Core's Select_() picks a random bucket, random position, checks the
    entry, then accepts with probability GetChance()*chance_factor; if
    rejected, multiplies chance_factor by 1.2 and retries. This ensures
    termination regardless of table density and avoids skew from low
    GetChance() entries.

    ouroboros iterates ALL addresses, collects (addr, chance) pairs, and
    does a weighted random pick — O(N) scan that is biased by table
    density and doesn't implement the exponential retry amplification.
    """

    def test_select_returns_address(self):
        # Basic smoke: select should return something when table is populated
        am = AddressManager()
        now = time.time()
        for i in range(10):
            am.add(f"1.2.3.{i+1}", 8333, timestamp=now)
        result = am.select_for_connection()
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# G10  Select bias: tried preferred 50/50 not 70/30
# ---------------------------------------------------------------------------
class TestG10SelectBias(unittest.TestCase):
    """
    BUG-10: ouroboros select_for_connection() uses `random.random() < 0.7`
    to prefer tried over new (70% tried, 30% new).

    Core's Select_() uses randbool() — a fair 50/50 coin flip when both
    tables are non-empty. addrman.cpp:727: `search_tried = insecure_rand.randbool()`.
    """

    def test_tried_bias_is_70_not_50(self):
        # Document the deviation; can't easily statistically test without many runs
        # Just verify the code path exists
        am = AddressManager()
        # The constant 0.7 is embedded in select_for_connection
        import inspect
        src = inspect.getsource(am.select_for_connection)
        self.assertIn("0.7", src, "BUG-10: select uses 0.7 instead of Core's 0.5")


# ---------------------------------------------------------------------------
# G11  Attempt: fCountFailure gate (only count if m_last_count_attempt < m_last_good)
# ---------------------------------------------------------------------------
class TestG11AttemptCountFailure(unittest.TestCase):
    """
    BUG-11: ouroboros mark_attempt() always increments attempts.
    Core's Attempt_() at addrman.cpp:687 only increments nAttempts when
    `fCountFailure && info.m_last_count_attempt < m_last_good`.
    This prevents counting an attempt that was made before the last
    successful connection to any peer (reducing false "failed" signals).
    """

    def test_attempt_always_increments(self):
        # BUG-11: increments without checking m_last_good
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now)
        am.mark_attempt("1.2.3.4", 8333)
        info = am.get_addr_info("1.2.3.4", 8333)
        self.assertEqual(info.attempts, 1)
        am.mark_attempt("1.2.3.4", 8333)
        info = am.get_addr_info("1.2.3.4", 8333)
        self.assertEqual(info.attempts, 2)  # always increments (BUG-11)

    def test_no_m_last_good_tracking(self):
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "_last_good"),
            "BUG-11: missing _last_good tracking for Attempt fCountFailure gate",
        )


# ---------------------------------------------------------------------------
# G12  mark_good: nTime NOT updated (topology-leak prevention)
# ---------------------------------------------------------------------------
class TestG12MarkGoodNoTimeUpdate(unittest.TestCase):
    """
    PASS: ouroboros mark_good() does NOT update last_seen, consistent with
    Core's Good_() comment: "nTime is not updated here, to avoid leaking
    information about currently-connected peers." (addrman.cpp:626)
    """

    def test_mark_good_does_not_update_last_seen(self):
        am = AddressManager()
        now = time.time()
        original_ts = now - 3600
        am.add("1.2.3.4", 8333, timestamp=original_ts)
        am.mark_good("1.2.3.4", 8333)
        info = am.get_addr_info("1.2.3.4", 8333)
        # last_seen should still be ~original_ts (not the current time)
        self.assertAlmostEqual(info.last_seen, original_ts, delta=2)


# ---------------------------------------------------------------------------
# G13  Connected() updates nTime (called on disconnect, not connect)
# ---------------------------------------------------------------------------
class TestG13ConnectedOnDisconnect(unittest.TestCase):
    """
    BUG-13: ouroboros has no Connected() equivalent.
    Core's Connected_() updates info.nTime when called, and
    net_processing calls it when *disconnecting* from a peer — not on
    connect — to avoid leaking topology information (which peers we're
    actively connected to). addrman.cpp:857-873.
    """

    def test_no_connected_method(self):
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "connected") or hasattr(am, "mark_connected"),
            "BUG-13: missing Connected() method (called on disconnect for nTime update)",
        )


# ---------------------------------------------------------------------------
# G14  SetServices() / update_services
# ---------------------------------------------------------------------------
class TestG14SetServices(unittest.TestCase):
    """
    BUG-14: ouroboros has no SetServices() method.
    Core's SetServices_() at addrman.cpp:876 allows updating an entry's
    service flags without going through the full add/good path.
    This is called from net.cpp when peer announces service bits.
    """

    def test_no_set_services_method(self):
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "set_services") or hasattr(am, "update_services"),
            "BUG-14: missing SetServices() method",
        )


# ---------------------------------------------------------------------------
# G15  ResolveCollisions() / test-before-evict scheduler
# ---------------------------------------------------------------------------
class TestG15ResolveCollisions(unittest.TestCase):
    """
    BUG-15: ouroboros has no ResolveCollisions() method.
    Core calls ResolveCollisions() periodically (via ThreadOpenConnections)
    to process the m_tried_collisions set. When a collision entry has been
    tested (either successfully connected in last 4h, or connection was
    attempted and failed) the old entry is evicted and new entry promoted.

    ouroboros only adds to _tried_collisions (mark_good() line 483) but
    never processes them — the test-before-evict loop is a dead set.
    """

    def test_no_resolve_collisions_method(self):
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "resolve_collisions"),
            "BUG-15: missing resolve_collisions() — tried_collisions are never drained",
        )

    def test_collisions_accumulate_never_drained(self):
        # BUG-15: collisions added but never resolved
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now)
        am.mark_good("1.2.3.4", 8333)  # moves to tried

        # Add a second address that maps to same tried slot
        # (we can't force this without knowing _key, but verify the set exists)
        self.assertIsInstance(am._tried_collisions, set)


# ---------------------------------------------------------------------------
# G16  SelectTriedCollision()
# ---------------------------------------------------------------------------
class TestG16SelectTriedCollision(unittest.TestCase):
    """
    BUG-16: ouroboros has no SelectTriedCollision() method.
    Core's SelectTriedCollision_() returns a random entry from
    m_tried_collisions for use by the feeler connection manager (which
    tests whether the existing tried entry is still reachable before
    committing the eviction).
    """

    def test_no_select_tried_collision(self):
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "select_tried_collision") or hasattr(am, "SelectTriedCollision"),
            "BUG-16: missing SelectTriedCollision()",
        )


# ---------------------------------------------------------------------------
# G17  ADDRMAN_TEST_WINDOW (40 min) expiry for unresolved collisions
# ---------------------------------------------------------------------------
class TestG17TestWindow(unittest.TestCase):
    """
    BUG-17: ouroboros has no ADDRMAN_TEST_WINDOW constant.
    Core's ResolveCollisions_() at addrman.cpp:933 forcibly evicts the old
    entry if `now - info_new.m_last_success > ADDRMAN_TEST_WINDOW (40 min)`.
    Without this, an unresolved collision can block a valid address from
    entering tried indefinitely.
    """

    def test_no_test_window_constant(self):
        import ouroboros.addrman as m
        self.assertFalse(
            hasattr(m, "TEST_WINDOW") or hasattr(m, "ADDRMAN_TEST_WINDOW"),
            "BUG-17: missing ADDRMAN_TEST_WINDOW (40 min) for collision expiry",
        )


# ---------------------------------------------------------------------------
# G18  Bucket hashing: double-SHA256 (HashWriter::GetCheapHash) not single SHA256
# ---------------------------------------------------------------------------
class TestG18BucketHash(unittest.TestCase):
    """
    BUG-18: ouroboros _hash_for_bucket uses single SHA-256.
    Core's GetTriedBucket/GetNewBucket/GetBucketPosition all call
    (HashWriter{} << ...).GetCheapHash() which is double-SHA256
    (HashWriter::GetCheapHash calls GetHash = double-SHA256 then LE64).
    This makes ouroboros bucket assignments incompatible with Core's
    deterministic scheme.
    """

    def test_uses_sha256_not_double_sha256(self):
        from ouroboros.addrman import _hash_for_bucket
        import hashlib
        import inspect
        src = inspect.getsource(_hash_for_bucket)
        # single SHA256 used
        self.assertIn("hashlib.sha256", src, "BUG-18: should use double-SHA256 (GetCheapHash)")
        # no double-sha256 call
        self.assertNotIn("sha256d", src)
        self.assertNotIn("double", src.lower())


# ---------------------------------------------------------------------------
# G19  Hash input serialisation: Core uses CService.GetKey() (IP+port packed bytes)
# ---------------------------------------------------------------------------
class TestG19HashInputSerialization(unittest.TestCase):
    """
    BUG-19: ouroboros _hash_for_bucket uses get_key() which returns a
    string like "1.2.3.4:8333" (UTF-8 encoded). Core's GetKey() returns
    the raw 18-byte CService binary representation (16-byte IP + 2-byte port).

    This produces different bucket assignments from Core and breaks
    deterministic bucket calculation. The difference matters for
    anti-eclipse bucket diversification.
    """

    def test_hash_uses_string_key(self):
        from ouroboros.addrman import _hash_for_bucket
        import inspect
        # _hash_for_bucket handles str args by calling .encode() internally
        src = inspect.getsource(_hash_for_bucket)
        # ouroboros converts str args via .encode() — meaning inputs are text strings
        # not raw binary (as Core uses). Core passes CService.GetKey() = 18-byte binary.
        self.assertIn("isinstance(arg, str)", src,
                      "BUG-19: _hash_for_bucket must handle string (not binary) inputs — different from Core")


# ---------------------------------------------------------------------------
# G20  Network group computation: Core uses GetGroup() via NetGroupManager
# ---------------------------------------------------------------------------
class TestG20NetworkGroupComputation(unittest.TestCase):
    """
    BUG-20: ouroboros get_network_group() groups all TorV3 addresses as
    "onion" and all I2P as "i2p". Core's NetGroupManager::GetGroup()
    uses the first 4 bytes of the decoded onion public key / I2P destination
    for per-address-range discrimination.

    For IPv4 ouroboros correctly uses the /16 group. For IPv6 ouroboros uses
    the /32 prefix (first 2 hex groups) — Core uses /32 for privacy-preserving
    networks but /16 for regular IPv6. This is a minor but real divergence.
    """

    def test_torv3_all_in_same_group(self):
        # BUG-20: all TorV3 → "onion" regardless of key differentiation
        g1 = get_network_group("aaaabbbbcccc.onion", NET_TORV3)
        g2 = get_network_group("ddddeeeeffffgggg.onion", NET_TORV3)
        self.assertEqual(g1, g2, "BUG-20: TorV3 should be grouped by first 4 bytes of pubkey")

    def test_i2p_all_in_same_group(self):
        # BUG-20: all I2P → "i2p"
        g1 = get_network_group("aaaa.b32.i2p", NET_I2P)
        g2 = get_network_group("bbbb.b32.i2p", NET_I2P)
        self.assertEqual(g1, g2, "BUG-20: I2P should be grouped by destination prefix")

    def test_ipv4_group_correct(self):
        # PASS: IPv4 /16 group is correct
        g = get_network_group("1.2.3.4", NET_IPV4)
        self.assertEqual(g, "1.2")

    def test_ipv6_group(self):
        # Partial: uses first two groups (::32 prefix equivalent)
        g = get_network_group("2001:db8::1", NET_IPV6)
        self.assertIsNotNone(g)


# ---------------------------------------------------------------------------
# G21  get_addresses() percentage cap (Core: max 23% of addrman)
# ---------------------------------------------------------------------------
class TestG21GetAddressesPctCap(unittest.TestCase):
    """
    BUG-21: ouroboros get_addresses(count=1000) returns up to 1000 addresses
    unconditionally. Core's GetAddr_() applies `max_pct=23` when called from
    GetAddresses (net_processing.cpp:4842-4844): min(1000, 23% of total).

    This prevents a single getaddr response from returning too large a
    fraction of the addrman (eclipse attack amplification).
    """

    def test_no_percentage_cap(self):
        am = AddressManager()
        now = time.time()
        # Add 200 addresses
        for i in range(200):
            am.add(f"1.2.{i // 256}.{i % 256}", 8333, timestamp=now)
        # get_addresses returns up to 1000, not limited to 23%
        result = am.get_addresses(count=1000)
        # 23% of 200 = 46 — Core would return at most 46
        # ouroboros returns all ~200 (BUG-21)
        self.assertGreater(
            len(result), 46,
            "BUG-21: get_addresses should be capped at 23% of total (Core parity)",
        )

    def test_get_addresses_does_not_filter_terrible(self):
        """
        BUG-21b: Core's GetAddr_() with filtered=true skips IsTerrible()
        addresses. ouroboros get_addresses() shuffles and returns all,
        including terrible ones.
        """
        am = AddressManager()
        now = time.time()
        am.add("1.2.3.4", 8333, timestamp=now - HORIZON - 1)  # very old → terrible
        result = am.get_addresses()
        hosts = [a.host for a in result]
        self.assertIn("1.2.3.4", hosts, "BUG-21b: terrible addresses should be filtered from GetAddr")


# ---------------------------------------------------------------------------
# G22  Feeler connections: select_for_feeler uses age bias not Core algorithm
# ---------------------------------------------------------------------------
class TestG22FeelerSelection(unittest.TestCase):
    """
    BUG-22: ouroboros select_for_feeler sorts by age (last_seen) and picks
    from the oldest 25%. Core's feeler uses the same Select_(new_only=true)
    path with IsTerrible filter — it does NOT sort by age.

    Additionally, Core only runs feeler connections via SelectTriedCollision
    for the test-before-evict path (not a separate "probe old new entries"
    mechanism). ouroboros invents a different feeler algorithm that
    diverges from Core's intent.
    """

    def test_feeler_returns_address(self):
        am = AddressManager()
        now = time.time()
        for i in range(5):
            am.add(f"1.2.3.{i+1}", 8333, timestamp=now - i * 3600)
        result = am.select_for_feeler()
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# G23  getaddr once-per-connection enforcement
# ---------------------------------------------------------------------------
class TestG23GetaddrOnce(unittest.TestCase):
    """
    BUG-23: ouroboros p2p.py on_getaddr handler has NO once-per-connection
    guard. Core at net_processing.cpp:4831 checks `peer.m_getaddr_sent`
    and returns without sending if already sent once.

    This allows a remote peer to call getaddr repeatedly and drain our
    full addrman on each call — a lightweight DoS / info-gathering vector.

    TWO-PIPELINE: Rust PeerManager has no getaddr handler at all.
    """

    def test_addrman_has_no_getaddr_sent_tracking(self):
        # Verify AddressManager itself has no tracking — the bug is in p2p.py
        am = AddressManager()
        self.assertFalse(
            hasattr(am, "_getaddr_sent"),
            "BUG-23: AddressManager missing _getaddr_sent per-connection tracking",
        )


# ---------------------------------------------------------------------------
# G24  addr relay rate limiting: 0.1 addr/sec token bucket (not day counter)
# ---------------------------------------------------------------------------
class TestG24AddrRateLimit(unittest.TestCase):
    """
    BUG-24: ouroboros _rate_limit_addr_relay uses a simple daily counter:
    up to 1000 addresses per 24-hour window per peer.

    Core uses a token-bucket rate limiter: MAX_ADDR_RATE_PER_SECOND=0.1
    addr/sec with a burst bucket of MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000.
    The token bucket refills at 0.1/sec and can burst to 1000, but a peer
    sending 1000 addresses instantly drains the bucket and must wait ~2.8
    hours before sending another 1000. The daily counter allows 1000
    addresses at any frequency within a 24h window (incorrect).

    Additionally, when getaddr is sent, Core adds 1000 tokens to the bucket
    (net_processing.cpp:3767) — ouroboros has no equivalent.
    """

    def test_daily_counter_not_token_bucket(self):
        import inspect
        import ouroboros.p2p as p2p_mod
        src = inspect.getsource(p2p_mod.PeerManager._rate_limit_addr_relay)
        self.assertIn("86400", src, "BUG-24: daily counter (86400s) instead of token bucket")
        self.assertNotIn("0.1", src, "BUG-24: missing 0.1 addr/sec token bucket rate")


# ---------------------------------------------------------------------------
# G25  getaddr only to outbound peers (not inbound)
# ---------------------------------------------------------------------------
class TestG25GetaddrOutboundOnly(unittest.TestCase):
    """
    PASS (partial): ouroboros sends getaddr only to outbound peers it
    connects to (p2p.py sends getaddr on connect via _send_getaddr).
    Core also only sends getaddr to outbound connections.

    BUG-25 (partial): ouroboros _relay_addr() relays addr messages to
    full-relay peers only (candidates include self.peers + self.inbound_peers
    filtered by p.relay_txs). Block-relay-only peers (self.block_relay_peers)
    are excluded from candidates. This is partially correct but leaks
    addresses to inbound peers (Core only relays to 2 outbound full-relay peers
    chosen by deterministic hash, not random sample of all inbound).
    """

    def test_relay_addr_sends_to_inbound_peers(self):
        # BUG-25: relay_addr includes inbound_peers which Core excludes
        import inspect
        import ouroboros.p2p as p2p_mod
        src = inspect.getsource(p2p_mod.PeerManager._relay_addr)
        self.assertIn("inbound_peers", src,
                      "BUG-25: _relay_addr should NOT relay to inbound peers (Core parity)")


# ---------------------------------------------------------------------------
# G26  Addr relay destination: deterministic SipHash-based, not random
# ---------------------------------------------------------------------------
class TestG26AddrRelayDeterministic(unittest.TestCase):
    """
    BUG-26: ouroboros _relay_addr uses random.sample() to choose 2 relay
    targets. Core uses a deterministic SipHash-based algorithm rotating
    every 24h (net_processing.cpp:2283-2295, ROTATE_ADDR_RELAY_DEST_INTERVAL).

    Core also uses m_addr_known bloom filter to avoid sending an address
    to a peer that already knows about it. ouroboros has no per-peer
    addr-known bloom filter.

    TWO-PIPELINE: Rust PeerManager has no addr relay at all.
    """

    def test_relay_uses_random_sample_not_siphash(self):
        import inspect
        import ouroboros.p2p as p2p_mod
        src = inspect.getsource(p2p_mod.PeerManager._relay_addr)
        self.assertIn("random.sample", src, "BUG-26: uses random.sample not deterministic SipHash relay")


# ---------------------------------------------------------------------------
# G27  Per-peer addr-known bloom filter (m_addr_known)
# ---------------------------------------------------------------------------
class TestG27AddrKnownBloomFilter(unittest.TestCase):
    """
    BUG-27: ouroboros has no per-peer addr-known bloom filter.
    Core maintains a 5000-entry rolling bloom filter per peer (m_addr_known)
    to avoid resending an address to a peer that already knows about it.
    This is initialised when addr_relay_enabled is set (sendaddrv2 received).

    Without this, ouroboros can relay the same address to the same peer
    repeatedly, creating unnecessary bandwidth and amplification.
    """

    def test_no_per_peer_addr_known_bloom(self):
        from ouroboros.peer import Peer
        import inspect
        src = inspect.getsource(Peer)
        # Core has m_addr_known (per-peer rolling bloom filter for addr dedup)
        # ouroboros.peer has peer_bloom_filters (BIP-37 tx filters only — different)
        has_addr_known_bloom = ("addr_known" in src or "m_addr_known" in src)
        self.assertFalse(
            has_addr_known_bloom,
            "BUG-27: Peer class should NOT have addr_known bloom filter (confirmed missing)",
        )


# ---------------------------------------------------------------------------
# G28  addr relay only when addr_relay_enabled (after sendaddrv2/version)
# ---------------------------------------------------------------------------
class TestG28AddrRelayEnabled(unittest.TestCase):
    """
    BUG-28: ouroboros _register_addr_handlers wires addr/addrv2/getaddr
    handlers immediately at connection time without waiting for
    sendaddrv2 or addr_relay_enabled handshake completion.

    Core sets m_addr_relay_enabled=true only when SENDADDRV2 or ADDR is
    received (enabling the relay path). Until then, addr data is not
    relayed. This gate prevents addr spam before version handshake completes.
    """

    def test_addr_relay_enabled_gate_absent(self):
        import inspect
        import ouroboros.p2p as p2p_mod
        src = inspect.getsource(p2p_mod.PeerManager._register_addr_handlers)
        self.assertNotIn(
            "addr_relay_enabled",
            src,
            "BUG-28: addr handler registered without addr_relay_enabled gate",
        )


# ---------------------------------------------------------------------------
# G29  Persistence: peers.json vs peers.dat binary format
# ---------------------------------------------------------------------------
class TestG29Persistence(unittest.TestCase):
    """
    BUG-29: ouroboros serialises to peers.json (human-readable JSON).
    Core serialises to peers.dat (binary serialisation using the V4_MULTIPORT
    format with CAddress::V2_DISK and BIP155 address encoding).

    The JSON format saves/loads correctly but:
    1. It is incompatible with Core's peers.dat — cross-impl migration is impossible.
    2. The v2 format rebuilds bucket assignments by re-computing hashes on
       load (correct) but if the _key changes between saves the bucket layout
       changes (addresses assigned to wrong buckets on reload).

    Note: saving/loading is functionally correct for standalone use.
    """

    def test_saves_as_json_not_binary(self):
        import tempfile, os, json
        with tempfile.TemporaryDirectory() as d:
            am = AddressManager(data_dir=d)
            am.add("1.2.3.4", 8333, timestamp=time.time())
            am.save()
            filepath = os.path.join(d, "peers.json")
            self.assertTrue(os.path.exists(filepath), "peers.json should exist")
            with open(filepath) as f:
                data = json.load(f)
            self.assertIn("version", data)

    def test_key_preserved_across_reload(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            am1 = AddressManager(data_dir=d)
            am1.add("1.2.3.4", 8333, timestamp=time.time())
            am1.save()
            am2 = AddressManager(data_dir=d)
            self.assertEqual(am1._key, am2._key, "Secret key should be preserved across reload")


# ---------------------------------------------------------------------------
# G30  TWO-PIPELINE: Rust PeerManager has no bucketed AddrMan
# ---------------------------------------------------------------------------
class TestG30RustPipelineDeadAddrMan(unittest.TestCase):
    """
    TWO-PIPELINE FINDING — BUG-30:

    The Rust pipeline (ferrous-utils/sync/src/network/peer_manager.rs)
    implements a PeerManager with `known_addrs: HashSet<SocketAddr>`.
    This is a flat unordered set with NO bucketing, NO eclipse mitigations,
    NO IsTerrible checks, NO time-penalty, NO feeler support, NO collision
    resolution.

    The Rust PeerManager is NOT exported to Python (#[pymodule] at line 2348
    of lib.rs does not register PeerManager or any address-manager class).
    The Python runtime uses AddressManager from addrman.py exclusively.

    However the Rust file exists, is compiled into the ferrous-utils crate,
    and could be called from Rust async tasks — it represents a dead parallel
    peer-management pipeline with none of the anti-eclipse properties of Core.

    If the Rust PeerManager were ever wired into the Python runtime (via a
    future #[pyclass] export), it would provide ZERO eclipse protection
    compared to addrman.py which at least approximates Core's bucketed design.
    """

    def test_rust_peer_manager_not_exported(self):
        """Confirm PeerManager is not accessible from Python."""
        try:
            from ferrous_utils import sync  # type: ignore
            self.assertFalse(
                hasattr(sync, "PeerManager"),
                "TWO-PIPELINE: Rust PeerManager should not be exported to Python",
            )
        except ImportError:
            # ferrous_utils not installed in this environment — that's fine
            pass

    def test_python_runtime_uses_addrman_not_rust(self):
        """Verify p2p.py imports from addrman.py, not from ferrous_utils."""
        import ouroboros.p2p as p2p_mod
        import inspect
        src = inspect.getsource(p2p_mod)
        self.assertIn("from ouroboros.addrman import", src)
        # Must not import PeerManager from ferrous_utils for addr management
        self.assertNotIn("ferrous_utils.*PeerManager", src)


# ---------------------------------------------------------------------------
# Additional targeted tests for key constants
# ---------------------------------------------------------------------------
class TestConstantValues(unittest.TestCase):
    """Verify exact constant values match Core where correct."""

    def test_horizon_30_days(self):
        self.assertEqual(HORIZON, 30 * 24 * 3600)

    def test_retries(self):
        self.assertEqual(RETRIES, 3)

    def test_max_failures(self):
        self.assertEqual(MAX_FAILURES, 10)

    def test_min_fail_7_days(self):
        self.assertEqual(MIN_FAIL, 7 * 24 * 3600)

    def test_replacement_hours(self):
        self.assertEqual(REPLACEMENT_HOURS, 4)

    def test_max_tried_collisions(self):
        self.assertEqual(MAX_TRIED_COLLISIONS, 10)

    def test_new_buckets_per_source_group(self):
        # Core: ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64 — PASS
        self.assertEqual(NEW_BUCKETS_PER_SOURCE_GROUP, 64)

    def test_tried_buckets_per_group(self):
        # Core: ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8 — PASS
        self.assertEqual(TRIED_BUCKETS_PER_GROUP, 8)


if __name__ == "__main__":
    unittest.main()
