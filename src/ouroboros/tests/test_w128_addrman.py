"""W128 — AddrMan + connman + peer selection audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/addrman.cpp, addrman_impl.h, addrman.h,
  bitcoin-core/src/net.cpp, node/eviction.cpp,
  bitcoin-core/src/banman.cpp + banman.h.

This file contains an xfail test per Core-divergent gate; the
xfails flip to XPASS the moment a fix lands. PRESENT gates are
plain asserts that pin the current Core-parity wiring against
regression.

W128 is complementary to W104 (bucketing/hash math). W128 audits
the remaining surfaces: select probability search, multi-bucket
new-table refcount, time penalties, mark_attempt count-failure
gating, full inbound-eviction protect pipeline, banman ban-vs-
discourage separation, persistence quirks, connman extras (extra
BRO rotation + extra network peer + anchors.dat format), and the
two-pipeline Rust-connman absence guard.

Reference: ouroboros/audit/w128_addrman.md for the bug catalogue.

NO production code changes. NO behavior changes. Only audit + xfail
tests.
"""

from __future__ import annotations

import inspect
import re
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import ouroboros.addrman as addrman_mod
import ouroboros.banman as banman_mod
import ouroboros.p2p as p2p_mod
import ouroboros.peer as peer_mod
from ouroboros.addrman import (
    AddressManager,
    AddrInfo,
    HORIZON,
    MAX_FAILURES,
    MAX_TRIED_COLLISIONS,
    MIN_FAIL,
    NEW_BUCKET_COUNT,
    NEW_BUCKET_SIZE,
    NET_IPV4,
    RETRIES,
    TRIED_BUCKET_COUNT,
    TRIED_BUCKET_SIZE,
)
from ouroboros.banman import BanManager

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"


# ===========================================================================
# Select_ probability gates — G1-G4
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-1 (P0): ouroboros uses weight-sum-once sampling; "
           "Core uses chance_factor *= 1.2 rejection loop "
           "(addrman.cpp:733-771). Look for 'chance_factor' in addrman.py.",
    strict=True,
)
def test_w128_g1_select_chance_factor_rejection_loop() -> None:
    """G1: Select_ implements chance_factor multiplicative rejection loop.

    Core's selection algorithm picks a random bucket, accepts with
    `chance_factor * info.GetChance()`, and on rejection retries with
    `chance_factor *= 1.2`. The 1.2 multiplier guarantees the loop
    terminates while preferring high-chance addresses.

    ouroboros builds a flat weighted list and samples once — no
    rejection loop, no chance_factor.
    """
    src = (SRC_OUROBOROS / "addrman.py").read_text(encoding="utf-8")
    assert "chance_factor" in src, (
        "G1: addrman.py must implement Core's chance_factor "
        "*= 1.2 rejection loop in Select_"
    )


@pytest.mark.xfail(
    reason="W128 BUG-2 (P1): ouroboros uses 70/30 tried-vs-new bias; "
           "Core uses 50/50 (addrman.cpp:721-728).",
    strict=True,
)
def test_w128_g2_select_5050_tried_vs_new() -> None:
    """G2: Select_ uses 50/50 randbool() for tried-vs-new choice.

    Core picks `insecure_rand.randbool()` (50/50) when both tables are
    non-empty. ouroboros uses `random.random() < 0.7`, biasing
    selection toward the tried table.
    """
    src = (SRC_OUROBOROS / "addrman.py").read_text(encoding="utf-8")
    # The Core-parity literal would be `< 0.5` (or `randbool()`); the
    # current incorrect literal is `< 0.7`. Assert the bias is 0.5.
    m = re.search(
        r"use_tried\s*=\s*random\.random\(\)\s*<\s*0\.5",
        src,
    )
    assert m, (
        "G2: addrman.py select_for_connection must use 50/50 "
        "random.random() < 0.5 bias; currently 0.7"
    )


@pytest.mark.xfail(
    reason="W128 BUG-3 (P1): ouroboros uses float weighted sum sampling; "
           "Core uses randbits<30>() < chance*(1<<30) — robust to "
           "underflow (addrman.cpp:765).",
    strict=True,
)
def test_w128_g3_select_randbits_30_threshold() -> None:
    """G3: Select_ accept-probability uses 30-bit integer test.

    Core's accept test is `randbits<30>() < chance_factor *
    info.GetChance() * (1<<30)`. This is robust to float underflow.
    ouroboros uses `random.random() * total` walking cumulative sum;
    when GetChance gets very small (~3.6e-4), float underflow can
    silently bias the selection.
    """
    src = (SRC_OUROBOROS / "addrman.py").read_text(encoding="utf-8")
    # Look for either a 30-bit-mask randint pattern or `(1 << 30)` scaling.
    found = bool(re.search(r"randbits\(?\s*30|1\s*<<\s*30", src))
    assert found, (
        "G3: Select_ must use 30-bit integer probability test "
        "(randbits<30>() < ... * (1<<30))"
    )


@pytest.mark.xfail(
    reason="W128 BUG-4 (P2): ouroboros lacks include_networks filter; "
           "Core's Select_ takes unordered_set<Network> networks "
           "(addrman.cpp:702-714).",
    strict=True,
)
def test_w128_g4_select_for_connection_networks_filter() -> None:
    """G4: select_for_connection accepts include-networks filter.

    Core's `Select_(new_only, networks)` returns only entries whose
    `GetNetwork()` is in the networks set when non-empty. ouroboros
    has `exclude_groups` and `exclude_asns` but no
    `include_networks` filter — callers cannot ask for "tor only".
    """
    sig = inspect.signature(AddressManager.select_for_connection)
    assert "networks" in sig.parameters or "include_networks" in sig.parameters, (
        "G4: select_for_connection must accept a 'networks' or "
        "'include_networks' filter parameter"
    )


# ===========================================================================
# Add() gates — G5-G7
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-5 (P2): ouroboros add() lacks time_penalty parameter; "
           "Core's AddSingle(addr, source, time_penalty) ages "
           "gossiped addresses; source==addr exempts self-announces "
           "(addrman.cpp:540-543).",
    strict=True,
)
def test_w128_g5_add_time_penalty_with_self_announce_exempt() -> None:
    """G5: add() takes a time_penalty argument and zeros it for self-announce.

    Core's `AddSingle(addr, source, time_penalty)`:

      if (addr == source) time_penalty = 0s;

    ouroboros' `add()` has no time_penalty parameter at all.
    """
    sig = inspect.signature(AddressManager.add)
    assert "time_penalty" in sig.parameters, (
        "G5: add() must accept a time_penalty parameter "
        "(Core: AddSingle aged-by-penalty for gossiped addrs)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-6 (P1): ouroboros add() never increments ref_count "
           "beyond 1; Core lets one addr occupy up to 8 buckets with "
           "stochastic 2^n gate (addrman.cpp:566-572).",
    strict=True,
)
def test_w128_g6_add_multi_bucket_refcount() -> None:
    """G6: add() supports multi-bucket ref_count up to 8.

    Core: same address from N source-groups gets N new-bucket slots,
    gated stochastically by `1 << pinfo->nRefCount`. ouroboros adds
    to exactly one bucket and returns False on every subsequent
    re-add, so ref_count is always 1.
    """
    am = AddressManager()
    # Add the same address from two different source IPs.
    am.add("8.8.8.8", 8333, source="1.2.3.4:8333", network_id=NET_IPV4)
    info = am.get_addr_info("8.8.8.8", 8333)
    assert info is not None
    first_ref = info.ref_count
    am.add("8.8.8.8", 8333, source="5.6.7.8:8333", network_id=NET_IPV4)
    info = am.get_addr_info("8.8.8.8", 8333)
    assert info is not None
    # Core would have stochastically maybe-bumped ref_count to 2;
    # ouroboros never bumps it. We assert the Core invariant: at
    # least once across many trials we expect ref_count > 1 when
    # different source groups re-announce.
    assert info.ref_count > first_ref or info.ref_count >= 2, (
        "G6: add() from a second source group should be able to "
        "increase ref_count (Core: stochastic 2^n gate, "
        "ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-7 (P2): ouroboros add() updates last_seen on every "
           "re-announce; Core gates updates to 1h (online) / 24h "
           "(offline) intervals (addrman.cpp:546-551).",
    strict=True,
)
def test_w128_g7_add_periodic_ntime_update_interval() -> None:
    """G7: add() rate-limits last_seen update per Core's 1h/24h intervals.

    Core: nTime updated only if `pinfo->nTime < addr.nTime -
    update_interval - time_penalty`, where update_interval is
    1h if the addr was online <24h ago, else 24h.
    """
    am = AddressManager()
    am.add("8.8.8.8", 8333, timestamp=1000.0, source="", network_id=NET_IPV4)
    info = am.get_addr_info("8.8.8.8", 8333)
    assert info is not None
    initial = info.last_seen
    # Re-add 30 minutes later (1800s) — below Core's 1h interval.
    am.add("8.8.8.8", 8333, timestamp=initial + 1800,
           source="", network_id=NET_IPV4)
    info2 = am.get_addr_info("8.8.8.8", 8333)
    assert info2 is not None
    # Core would NOT update last_seen at 30min; ouroboros updates
    # on any newer timestamp. We expect Core-parity: no update.
    assert info2.last_seen == initial, (
        "G7: add() within 1h must not update last_seen (Core "
        "online-update interval)"
    )


# ===========================================================================
# Attempt / Good / Tried gates — G8-G11
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-8 (P0): mark_attempt unconditionally increments "
           "attempts; Core gates increment on fCountFailure AND "
           "m_last_count_attempt < m_last_good (addrman.cpp:687-689).",
    strict=True,
)
def test_w128_g8_mark_attempt_count_failure_gate() -> None:
    """G8: mark_attempt gates `attempts++` on fCountFailure and m_last_good.

    Core's Attempt_:

      info.m_last_try = time;
      if (fCountFailure && info.m_last_count_attempt < m_last_good) {
          info.m_last_count_attempt = time;
          info.nAttempts++;
      }

    The gate prevents one outage from poisoning the address with 30
    attempts and marking it terrible after 3.

    ouroboros' mark_attempt always does `info.attempts += 1`.
    """
    sig = inspect.signature(AddressManager.mark_attempt)
    # Core takes fCountFailure parameter; ouroboros must too for parity.
    assert "count_failure" in sig.parameters or "fCountFailure" in sig.parameters, (
        "G8: mark_attempt must accept fCountFailure parameter "
        "(Core: Attempt_(addr, fCountFailure, time))"
    )


@pytest.mark.xfail(
    reason="W128 BUG-9 (P1): mark_good adds to _tried_collisions but no "
           "periodic resolver drains it; collisions silently dropped "
           "past MAX_TRIED_COLLISIONS=10 (addrman.cpp:892, 1183).",
    strict=True,
)
def test_w128_g9_resolve_collisions_method_exists() -> None:
    """G9: AddressManager has a resolve_collisions() method.

    Core: `ResolveCollisions` is called periodically from PeerManager
    to drain m_tried_collisions, re-probing each pending entry and
    moving it to tried only if the existing tried entry fails the
    4-day window.

    ouroboros: _tried_collisions is populated by mark_good but no
    method drains it. Past MAX_TRIED_COLLISIONS=10 new collisions
    are silently dropped.
    """
    assert hasattr(AddressManager, "resolve_collisions"), (
        "G9: AddressManager must expose resolve_collisions() "
        "(Core: ResolveCollisions called periodically)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-10 (P2): _remove_from_tried sometimes deletes the "
           "address when the new-table slot is occupied; Core's "
           "MakeTried always ClearNew()-s the slot first "
           "(addrman.cpp:511-520).",
    strict=True,
)
def test_w128_g10_remove_from_tried_always_demotes() -> None:
    """G10: _remove_from_tried always demotes (never deletes outright).

    Core's MakeTried clears the target new-table slot via ClearNew()
    before placing the demoted entry, never deletes the addr from
    mapInfo. ouroboros falls through to `del self._addrs[addr_key]`
    when the new-table slot is occupied.
    """
    src = (SRC_OUROBOROS / "addrman.py").read_text(encoding="utf-8")
    # Look for the "del self._addrs[addr_key]" pattern inside
    # _remove_from_tried — its presence is the bug.
    # Grab the body of _remove_from_tried.
    func_match = re.search(
        r"def _remove_from_tried\b.*?(?=\n    def |\Z)",
        src, re.DOTALL,
    )
    assert func_match, "G10: _remove_from_tried must exist"
    body = func_match.group(0)
    assert "del self._addrs[" not in body, (
        "G10: _remove_from_tried must never delete addrs; Core's "
        "MakeTried demotes via ClearNew()"
    )


@pytest.mark.xfail(
    reason="W128 BUG-11 (P1): no periodic call site for "
           "resolve_collisions; Core calls ResolveCollisions from "
           "PeerManager housekeeping (net_processing.cpp).",
    strict=True,
)
def test_w128_g11_resolve_collisions_called_periodically() -> None:
    """G11: p2p.py calls AddressManager.resolve_collisions() periodically.

    Even if the method existed (G9), there must be a periodic call
    site — otherwise the collision set never drains.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    assert "resolve_collisions" in src, (
        "G11: p2p.py must call addrman.resolve_collisions() "
        "periodically"
    )


# ===========================================================================
# IsTerrible + GetChance baseline gates — G12-G13 (PRESENT)
# ===========================================================================


def test_w128_g12_isterrible_protects_recent_attempt_window() -> None:
    """G12 (PRESENT): _is_terrible exempts addrs tried in the last minute.

    Core (addrman.cpp:51-53):

        if (now - m_last_try <= 1min) return false;

    ouroboros (addrman.py:511-513):

        if now - addr.last_attempt < 60: return False
    """
    am = AddressManager()
    addr = AddrInfo(host="8.8.8.8", port=8333, network_id=NET_IPV4,
                    last_attempt=time.time(), last_seen=0.0)
    # last_seen=0 would normally make it terrible (30-day horizon),
    # but the 1-min protection should shield it.
    assert not am._is_terrible(addr), (
        "G12: _is_terrible must return False within 60s of "
        "last_attempt (Core: 1-min protection)"
    )


def test_w128_g13_getchance_recent_attempt_damper() -> None:
    """G13 (PRESENT): _get_chance multiplies by 0.01 for <10min attempts.

    Core (addrman.cpp:78-81):

        if (now - m_last_try < 10min) fChance *= 0.01;

    ouroboros (addrman.py:541-543):

        if now - addr.last_attempt < 600: chance *= 0.01
    """
    am = AddressManager()
    addr = AddrInfo(host="8.8.8.8", port=8333, network_id=NET_IPV4,
                    last_attempt=time.time(), attempts=0)
    chance = am._get_chance(addr)
    assert chance == pytest.approx(0.01, rel=0.01), (
        "G13: _get_chance must multiply by 0.01 within 10min of "
        "last_attempt (Core: 10-min damper)"
    )


# ===========================================================================
# Inbound eviction protect-pass gates — G14-G24
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-12 (P0): _select_eviction_candidate never checks "
           "peer.noban; Core's ProtectNoBanConnections removes all "
           "NoBan peers before any comparison (eviction.cpp:87-94).",
    strict=True,
)
def test_w128_g14_eviction_protect_noban() -> None:
    """G14: _select_eviction_candidate excludes noban peers."""
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    # Locate _select_eviction_candidate body.
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m, "G14: _select_eviction_candidate must exist"
    body = m.group(0)
    assert ".noban" in body, (
        "G14: _select_eviction_candidate must filter noban peers "
        "(Core: ProtectNoBanConnections)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-13 (P0): no outbound eviction path; Core's eviction "
           "operates on inbound only (ProtectOutboundConnections), and "
           "outbound rotation is handled separately in net.cpp:2723.",
    strict=True,
)
def test_w128_g15_outbound_eviction_path_exists() -> None:
    """G15: PeerManager has an outbound-eviction method.

    Core: outbound peer rotation happens in ThreadOpenConnections
    via tightening the eligibility filter when at max. ouroboros
    has no outbound-eviction code at all — at max_peers we simply
    stop dialing.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    # Look for any outbound-eviction-like method or rotation timer.
    found = bool(re.search(
        r"def .*?(outbound_eviction|evict_outbound|rotate_outbound)\b",
        src,
    ))
    assert found, (
        "G15: p2p.py must implement outbound eviction / rotation "
        "(Core: net.cpp:2723 nOutboundFullRelay tightening)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-14 (P1): eviction protects only 4 unique-/16 peers, "
           "not 8 nKeyedNetGroup peers; predictable to attackers "
           "(eviction.cpp:188).",
    strict=True,
)
def test_w128_g16_eviction_protect_8_keyed_netgroup() -> None:
    """G16: eviction protects 8 peers by deterministic-keyed netgroup hash.

    Core: EraseLastKElements(CompareNetGroupKeyed, 8) — the keyed
    netgroup hash is unpredictable to attackers. ouroboros protects
    a greedy first-4-unique-/16-prefixes, which is predictable
    (attacker just maps their botnet across 4+ /16s).
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    # We expect literal `8` somewhere in the eviction code near
    # "netgroup" or "KeyedNetGroup".
    m = re.search(
        r"_select_eviction_candidate\b.*?KeyedNetGroup",
        src, re.DOTALL,
    )
    assert m, (
        "G16: _select_eviction_candidate must protect 8 KeyedNetGroup "
        "peers (Core: CompareNetGroupKeyed, 8)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-15 (P2): eviction protects only 4 lowest-latency "
           "peers using latest RTT; Core protects 8 by m_min_ping_time "
           "(eviction.cpp:191).",
    strict=True,
)
def test_w128_g17_eviction_protect_8_min_ping_time() -> None:
    """G17: eviction protects 8 peers with lowest min_ping_time (not 4).

    Core: EraseLastKElements(ReverseCompareNodeMinPingTime, 8). The
    "min" is robust to a high-ping attacker simulating one fast PONG.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    # Look for `[8:]` slicing (protect 8) AND a min_ping reference.
    assert "min_ping" in body and "[8:]" in body, (
        "G17: must protect 8 peers by min_ping_time (Core uses 8 "
        "and min not current ping)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-16 (P1): eviction has no CompareNodeTXTime protect "
           "(Peer.last_tx_time field missing); Core protects 4 most "
           "recent tx-relayers (eviction.cpp:193-194).",
    strict=True,
)
def test_w128_g18_eviction_protect_4_tx_time() -> None:
    """G18: eviction protects 4 peers by most-recent novel-tx-relayed."""
    peer_src = (SRC_OUROBOROS / "peer.py").read_text(encoding="utf-8")
    assert "last_tx_time" in peer_src, (
        "G18: Peer must have last_tx_time field; eviction uses it "
        "to protect 4 best tx-relayers (Core: CompareNodeTXTime)"
    )


def test_w128_g19_eviction_protect_4_block_time_present() -> None:
    """G19 (PRESENT): eviction protects 4 peers by recent block-relay time.

    ouroboros' Step 4 protects 4 peers with highest last_block_time
    (`p2p.py:805-807`), matching Core's CompareNodeBlockTime (4)
    pass at eviction.cpp:201.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert "last_block_time" in body, (
        "G19: eviction must protect by last_block_time"
    )


@pytest.mark.xfail(
    reason="W128 BUG-17 (P1): no CompareNodeBlockRelayOnlyTime protect "
           "for non-tx-relay peers (eviction.cpp:196-197).",
    strict=True,
)
def test_w128_g20_eviction_protect_8_block_relay_only_time() -> None:
    """G20: eviction protects 8 non-tx-relay peers with relevant services.

    Core: EraseLastKElements(CompareNodeBlockRelayOnlyTime, 8,
                              !m_relays_txs && fRelevantServices).
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert "block_relay" in body.lower() and "relay_txs" in body, (
        "G20: eviction must have a non-tx-relay protect pass "
        "(Core: CompareNodeBlockRelayOnlyTime)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-18 (P2): Peer has no prefer_evict field; Core's "
           "eviction collapses candidates to prefer_evict-only when "
           "any present (eviction.cpp:212-215).",
    strict=True,
)
def test_w128_g21_eviction_prefer_evict_reduce() -> None:
    """G21: Peer has prefer_evict field and eviction collapses to it.

    Core: after all protects, if any candidate has prefer_evict, the
    candidate list is reduced to only those.
    """
    peer_src = (SRC_OUROBOROS / "peer.py").read_text(encoding="utf-8")
    assert "prefer_evict" in peer_src, (
        "G21: Peer must have prefer_evict field"
    )


@pytest.mark.xfail(
    reason="W128 BUG-19 (P1): eviction Step 6 protects 4 most-RECENT "
           "instead of Core's 50% LONGEST-connected ratio protect "
           "(eviction.cpp:174-175).",
    strict=True,
)
def test_w128_g22_eviction_protect_by_ratio_50pct_longest() -> None:
    """G22: eviction protects half by longest-connected uptime.

    Core: ProtectEvictionCandidatesByRatio protects 50% by reverse
    connect-time (longest-connected). ouroboros' Step 6 protects 4
    MOST-RECENTLY-connected then Step 7 evicts longest-connected —
    the opposite direction.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    # Heuristic: a parity fix would either name "ratio" or "reverse"
    # protect for connected_at, and the SLICE direction must be
    # "protect first half" not "evict longest".
    assert (
        "ratio" in body.lower()
        or re.search(r"connected_at.*reverse=True.*\[:len.*//\s*2\]", body)
    ), (
        "G22: eviction must protect 50% longest-connected via "
        "ratio pass (Core: ProtectEvictionCandidatesByRatio)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-20 (P2): no disadvantaged-network protect pass "
           "(Tor/I2P/CJDNS/local); Core reserves up to 25% of the 50% "
           "ratio for these (eviction.cpp:117-169).",
    strict=True,
)
def test_w128_g23_eviction_protect_disadvantaged_networks() -> None:
    """G23: eviction reserves 25% of ratio-slots for Tor/I2P/CJDNS/local."""
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    # Look for disadvantaged-network signal.
    assert any(net in body.lower() for net in ("disadvantaged", "i2p", "cjdns")), (
        "G23: eviction must reserve slots for Tor/I2P/CJDNS/local "
        "(Core: disadvantaged-network round-robin)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-21 (P1): final selector evicts longest-connected; "
           "Core picks largest-netgroup youngest member "
           "(eviction.cpp:217-239).",
    strict=True,
)
def test_w128_g24_eviction_final_selector_largest_netgroup() -> None:
    """G24: final eviction selector picks largest-netgroup youngest member.

    Core: group by nKeyedNetGroup, pick the group with the most
    candidates (tiebreak: youngest member), evict that group's
    longest-connected member.

    ouroboros: simply `candidates.sort(key=connected_at); return
    candidates[0][0]` — evict any longest-connected peer regardless
    of netgroup clustering.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _select_eviction_candidate\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    # Heuristic: parity fix names "most_connections" or "largest_group"
    # somewhere in the final selection logic.
    assert (
        "largest" in body.lower()
        or "most_connections" in body
        or "nMostConnections" in body
    ), (
        "G24: final eviction must pick largest-netgroup youngest "
        "member (Core: net.cpp:217-239)"
    )


# ===========================================================================
# Connman extras — G25-G27
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-22 (P1): no EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL "
           "rotation; Core spawns extra BRO every 5min and disconnects "
           "the oldest (net.cpp:63,2729-2755).",
    strict=True,
)
def test_w128_g25_extra_block_relay_only_rotation() -> None:
    """G25: connman periodically rotates an extra BRO peer.

    Core: every 5 min, open a third block-relay-only outbound, then
    disconnect the oldest of the three. This is a key eclipse defense
    — a passive attacker who occupied our 2 BRO slots gets one
    rotated out every 5 min.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    assert "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL" in src, (
        "G25: p2p.py must implement BRO peer rotation interval "
        "(Core: EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5 min)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-23 (P1): no EXTRA_NETWORK_PEER_INTERVAL outbound; "
           "Core opens extra peers to underrepresented networks every "
           "5min (net.cpp:91,2758-2767).",
    strict=True,
)
def test_w128_g26_extra_network_peer_interval() -> None:
    """G26: connman opens an extra outbound to underrepresented networks.

    Core: when many full-relay peers are NODE_NETWORK_LIMITED, every
    5 min Core opens an extra peer prioritising the underrepresented
    network classes.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    assert "EXTRA_NETWORK_PEER_INTERVAL" in src, (
        "G26: p2p.py must implement extra-network-peer interval "
        "(Core: EXTRA_NETWORK_PEER_INTERVAL = 5 min)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-24 (P1): anchors persisted as JSON (filename is "
           "anchors.dat but content is json.dump); Core uses binary "
           "CDataStream serialisation of std::vector<CAddress> "
           "(net.cpp:60,3495,3650).",
    strict=True,
)
def test_w128_g27_anchors_dat_binary_format() -> None:
    """G27: anchor file content is binary CDataStream (Core format).

    Core: serialises std::vector<CAddress> with nVersion to a binary
    `anchors.dat` (see net.cpp ReadAnchors / DumpAnchors at lines
    3495 / 3650).

    ouroboros: filename is `anchors.dat` but the writer is
    `json.dump(data, f)` (p2p.py:999) and the reader is `json.load(f)`
    — the file is JSON, not interchangeable with Core, breaks
    anchor-file backup portability.
    """
    src = (SRC_OUROBOROS / "p2p.py").read_text(encoding="utf-8")
    # Locate the _save_anchors body and confirm Core-style binary
    # serialisation rather than json.dump.
    m = re.search(
        r"def _save_anchors\b.*?(?=\n    def |\n    async def |\Z)",
        src, re.DOTALL,
    )
    assert m, "G27: _save_anchors must exist"
    body = m.group(0)
    # Bug signature: json.dump used to persist anchors.
    assert "json.dump" not in body, (
        "G27: _save_anchors must use Core's CDataStream binary "
        "serialisation, not json.dump"
    )


# ===========================================================================
# Banman gates — G28-G29
# ===========================================================================


@pytest.mark.xfail(
    reason="W128 BUG-25 (P0): BanManager conflates ban and discouragement; "
           "Core has m_banned (persistent CSubNet map) and m_discouraged "
           "(CRollingBloomFilter[50000, 1e-6]) — separate APIs and "
           "different accept-time semantics (banman.h:96-98, "
           "net.cpp:1804-1818).",
    strict=True,
)
def test_w128_g28_banman_discouragement_filter_separate() -> None:
    """G28: BanManager has separate ban + discourage paths.

    Core: `Discourage()` adds to a 50000-entry rolling bloom filter
    in-memory; `Ban()` adds to a persistent disk-backed map. The
    accept-flow rejects banned peers unconditionally but only
    rejects discouraged peers when inbound is (almost) full.

    ouroboros: ONE `banned: dict[str, float]`. Every discouragement
    event calls the same `ban()` that writes to disk.
    """
    # Core-parity APIs that should exist on BanManager.
    expected = ["discourage", "is_discouraged"]
    missing = [m for m in expected if not hasattr(BanManager, m)]
    assert not missing, (
        f"G28: BanManager must expose {expected} as separate "
        "discouragement API (Core: m_discouraged rolling bloom)"
    )


@pytest.mark.xfail(
    reason="W128 BUG-26 (P1): ban() unconditionally overwrites; Core "
           "only extends (banman.cpp:144-148). A shorter setban can "
           "silently shrink an existing auto-ban.",
    strict=True,
)
def test_w128_g29_ban_only_extend_semantics() -> None:
    """G29: ban() only extends existing bans, never shortens.

    Core (banman.cpp:144-148):

        if (m_banned[sub_net].nBanUntil < ban_entry.nBanUntil) {
            m_banned[sub_net] = ban_entry;
        } else
            return;
    """
    bm = BanManager(ban_threshold=100, ban_duration=86400)
    bm.ban("1.2.3.4", duration=86400)   # 24-hour auto-ban
    long_ban = bm.banned["1.2.3.4"]
    bm.ban("1.2.3.4", duration=60)      # operator setban add 60
    short_ban = bm.banned["1.2.3.4"]
    # Core semantics: short_ban must equal long_ban (no shortening).
    assert short_ban >= long_ban, (
        "G29: ban() must not shorten an existing ban; Core only-"
        "extends. Current behaviour silently overwrites."
    )


# ===========================================================================
# Two-pipeline guard — G30 (PRESENT, extends W104 G30)
# ===========================================================================


def test_w128_g30_rust_pipeline_no_connman_or_banman_export() -> None:
    """G30 (PRESENT): ferrous_utils Rust crate must not export any
    Connman / BanMan / Eviction class.

    Extends W104's G30 (which asserted no PeerManager export) with
    coverage for connman, banman, and eviction surfaces. A future
    Rust-side AddrMan reintroduction would surface here.
    """
    try:
        from ferrous_utils import sync  # type: ignore
    except ImportError:
        # Crate not built into this environment; the source-level
        # check below covers the equivalent invariant.
        sync = None
    if sync is not None:
        for forbidden in ("Connman", "BanMan", "BanManager",
                          "Eviction", "AddrMan", "AddrManager",
                          "PeerEviction"):
            assert not hasattr(sync, forbidden), (
                f"G30: ferrous_utils.sync must not export {forbidden!r} "
                "(addrman/connman/banman is Python-only)"
            )


def test_w128_g30_no_rust_addrman_surface_grep() -> None:
    """G30 (PRESENT): source-level grep — Rust crate has no addrman
    surface beyond the asmap parser (W115).

    The asmap.rs file legitimately contains "addrman" in comments
    describing its purpose; production identifiers like `tried_tbl`,
    `new_tbl`, `select_addr`, `peer_select`, `connman`, `banman`
    must NOT appear under ferrous-utils/.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present in this environment")

    forbidden_identifiers = [
        "AddrMan",
        "BanMan",
        "Connman",
        "tried_tbl",
        "new_tbl",
        "select_addr",
        "peer_select",
        "evict_inbound",
        "PeerEviction",
    ]
    found: list[tuple[str, str]] = []
    for rs_path in FERROUS_UTILS.rglob("*.rs"):
        text = rs_path.read_text(encoding="utf-8", errors="replace")
        # Strip comments at line level so the W115 asmap.rs comment
        # mentions of "addrman" don't trigger this guard.
        lines = []
        for line in text.splitlines():
            stripped = line.split("//", 1)[0]
            lines.append(stripped)
        code_only = "\n".join(lines)
        for ident in forbidden_identifiers:
            if ident in code_only:
                found.append((str(rs_path), ident))
    assert not found, (
        "G30: forbidden addrman/connman/banman identifiers found "
        f"in Rust crate (not in comments): {found}"
    )


# ===========================================================================
# Anchor + connman constant pinning (defensive)
# ===========================================================================


def test_w128_anchor_count_matches_core() -> None:
    """MAX_BLOCK_RELAY_ONLY_ANCHORS == Core's MAX_BLOCK_RELAY_ONLY_ANCHORS=2.

    Pin against accidental drift; Core net.cpp:57.
    """
    assert p2p_mod.MAX_BLOCK_RELAY_ONLY_ANCHORS == 2


def test_w128_max_feeler_matches_core() -> None:
    """MAX_FEELER_CONNECTIONS == Core's MAX_FEELER_CONNECTIONS=1.

    Pin against accidental drift; Core net.h:75.
    """
    assert p2p_mod.MAX_FEELER_CONNECTIONS == 1


def test_w128_feeler_interval_matches_core() -> None:
    """FEELER_INTERVAL == Core's 2min Poisson interval.

    Pin against accidental drift; Core net.cpp:88 FEELER_SLEEP_WINDOW=1s
    and Poisson rate 1/120s.
    """
    assert p2p_mod.FEELER_INTERVAL == 120.0


def test_w128_max_inbound_matches_core_default() -> None:
    """MAX_INBOUND == Core's default 125 - 8 outbound = 117."""
    assert p2p_mod.MAX_INBOUND == 117


def test_w128_max_block_relay_only_matches_core() -> None:
    """MAX_BLOCK_RELAY_ONLY_CONNECTIONS == 2.

    Pin against accidental drift; Core net.h:73.
    """
    assert p2p_mod.MAX_BLOCK_RELAY_ONLY_CONNECTIONS == 2


def test_w128_max_tried_collisions_matches_core() -> None:
    """MAX_TRIED_COLLISIONS == 10 (Core's ADDRMAN_SET_TRIED_COLLISION_SIZE).

    Pin against accidental drift; Core addrman_impl.h.
    """
    assert MAX_TRIED_COLLISIONS == 10


# ===========================================================================
# Banman defaults pinning (defensive)
# ===========================================================================


def test_w128_banman_default_ban_time_matches_core() -> None:
    """BanManager default ban_duration == 86400 (Core DEFAULT_MISBEHAVING_BANTIME).

    Pin against accidental drift; Core banman.h:19.
    """
    bm = BanManager()
    assert bm.ban_duration == 86400


def test_w128_banman_default_threshold_present() -> None:
    """BanManager default ban_threshold == 100 (single-event 100 = instant ban).

    Pin against drift; Core net_processing.cpp Misbehaving sets
    m_should_discourage on any score ≥ DISCOURAGEMENT_THRESHOLD.
    """
    bm = BanManager()
    assert bm.ban_threshold == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
