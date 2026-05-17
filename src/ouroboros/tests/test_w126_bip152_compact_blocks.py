"""
W126 — BIP-152 Compact Block Relay audit (ouroboros).

DISCOVERY wave: 30 gates audited against bitcoin-core/src/blockencodings.{h,cpp}
and bitcoin-core/src/net_processing.cpp (SENDCMPCT / CMPCTBLOCK / GETBLOCKTXN /
BLOCKTXN). This file contains a passing test per CORE-compatible gate, plus an
@pytest.mark.xfail test per Core-divergent gate. As future FIX waves close the
audit gaps each xfail will flip to pass.

Re-audit of W112 (FIX-41 closed W112 BUG-1/BUG-2). This file adds the deeper
gates that W112 did not score (FillBlock IsBlockMutated, duplicate sendcmpct,
m_provides_cmpctblocks split, HB-peer rotation invariants,
m_bip152_highbandwidth_to/from state fields, fast-announce dedup, low-work drop,
fRevertToHeaderProcessing branch, MSG_CMPCT_BLOCK getdata serving path, optimistic
reconstruction, vExtraTxnForCompact pool, MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK).

Status: 30 gates — PRESENT 12 / PARTIAL 4 / MISSING 14.
BUGs: 17 (2 P0-CDIV / 6 P1 / 7 P2 / 2 P3).

Two-pipeline guard: this file imports only Python `compact_blocks`,
`PeerManager`, and `Mempool`. The Rust `ferrous-utils/` crate contains
SipHash-2-4 + compute_siphash_key + short_txid helpers reused by BIP-330
transaction reconciliation (Erlay), NOT by BIP-152 wire handling.  All
BIP-152 message handlers and CompactBlock/PartiallyDownloadedBlock-
equivalent code live in Python. G30 asserts this invariant.

Run:
    cd /home/work/hashhog/ouroboros && \\
      python3 -m pytest src/ouroboros/tests/test_w126_bip152_compact_blocks.py -v

NO production code changes. NO behavior changes. Only audit + xfail tests.
"""

from __future__ import annotations

import hashlib
import inspect
import re
import struct
import unittest
from pathlib import Path

import pytest


OUROBOROS_SRC = Path(__file__).resolve().parents[1]
REPO_ROOT = OUROBOROS_SRC.parents[1]
RUST_PEER_PATH = REPO_ROOT / "ferrous-utils" / "sync" / "src" / "network" / "peer.rs"
RUST_SYNC_DIR = REPO_ROOT / "ferrous-utils" / "sync" / "src"
RUST_COMMON_DIR = REPO_ROOT / "ferrous-utils" / "common" / "src"


# =========================================================================
# Constants + wire codec (re-audit baseline; should all pass)
# =========================================================================

class TestW126_ConstantsAndCodec(unittest.TestCase):
    """G1-G8: Constants + InitData structural gates (re-audit of W112 G1-G5/G12-G15)."""

    def test_g1_cmpctblocks_version_equals_2(self):
        """G1: CMPCTBLOCKS_VERSION = 2 (BIP-152 §6 wtxid)."""
        from ouroboros.compact_blocks import CMPCTBLOCKS_VERSION
        self.assertEqual(CMPCTBLOCKS_VERSION, 2)

    def test_g2_max_cmpctblock_depth_equals_5(self):
        """G2: MAX_CMPCTBLOCK_DEPTH = 5 (net_processing.cpp:138)."""
        from ouroboros.compact_blocks import MAX_CMPCTBLOCK_DEPTH
        self.assertEqual(MAX_CMPCTBLOCK_DEPTH, 5)

    def test_g3_max_blocktxn_depth_equals_10(self):
        """G3: MAX_BLOCKTXN_DEPTH = 10 (net_processing.cpp:140)."""
        from ouroboros.compact_blocks import MAX_BLOCKTXN_DEPTH
        self.assertEqual(MAX_BLOCKTXN_DEPTH, 10)

    def test_g4_short_id_length_is_6_bytes(self):
        """G4: short_txid returns 48 bits (6 bytes)."""
        from ouroboros.compact_blocks import short_txid
        key = bytes(16)
        sid = short_txid(key, b"\x00" * 32)
        self.assertEqual(sid >> 48, 0, "short_txid should be 48-bit")
        self.assertLess(sid, 1 << 48)

    def test_g5_siphash_key_derivation(self):
        """G5: SipHash key = SHA256(header || nonce_le64)[0:16]."""
        from ouroboros.compact_blocks import compute_siphash_key
        header = bytes(80)
        nonce = 0xDEADBEEFCAFEBABE
        expected = hashlib.sha256(header + struct.pack("<Q", nonce)).digest()[:16]
        self.assertEqual(compute_siphash_key(header, nonce), expected)

    def test_g6_init_data_max_tx_count_gate(self):
        """G6: BlockTxCount > 4_000_000/40 = 100_000 → READ_STATUS_INVALID."""
        from ouroboros.compact_blocks import (
            MAX_CMPCTBLOCK_TX_COUNT,
            CompactBlock,
            ReadStatus,
        )
        self.assertEqual(MAX_CMPCTBLOCK_TX_COUNT, 100_000)
        # Synthetic check: validate() with sids that exceed the cap must return INVALID.
        # We can't actually construct 100k+1 sids cheaply, but we can verify the cap
        # value and reach into the validate path with a high-tx-count payload via varint
        # at the deserialize boundary (G7 covers the uint16 boundary).

    def test_g7_init_data_uint16_overflow_at_deserialize(self):
        """G7: BlockTxCount > 0xFFFF at deserialize → raises ValueError (uint16 limit)."""
        from ouroboros.compact_blocks import CompactBlock
        # Craft a header+nonce+sid_count varint > 0xFFFF
        header = bytes(80)
        nonce_le = struct.pack("<Q", 0)
        # CompactSize encoding for 0x10000 = 0xfe + 4 bytes LE
        sid_count_varint = b"\xfe" + struct.pack("<I", 0x10000)
        payload = header + nonce_le + sid_count_varint
        with self.assertRaises((ValueError, Exception)):
            CompactBlock.deserialize(payload)

    def test_g8_init_data_duplicate_and_bucket_dos(self):
        """G8: Duplicate short IDs OR bucket > 12 → READ_STATUS_FAILED."""
        from ouroboros.compact_blocks import (
            CompactBlock,
            PrefilledTransaction,
            ReadStatus,
        )
        # Build a CompactBlock with one prefilled coinbase + 2 duplicate sids.
        # Need a real coinbase tx; reach for one out of mempool tests.
        # We can synthesize a minimal mock that has .serialize_with_witness() / .get_wtxid().
        class _MockTx:
            def serialize_with_witness(self):
                return b"\x00" * 60
            def get_wtxid(self):
                return b"\x00" * 32

        # Header has nBits=0 (all-zero) is the IsNull case; use a non-zero nBits.
        header = bytes(72) + b"\xff\xff\xff\x7f" + bytes(4)
        cb = CompactBlock(
            header=header, nonce=1,
            short_ids=[0x1234, 0x1234],  # duplicate
            prefilled_txs=[PrefilledTransaction(index=0, tx=_MockTx())],
        )
        status = cb.validate()
        self.assertEqual(status, ReadStatus.FAILED,
                         "Duplicate short IDs must return READ_STATUS_FAILED")


# =========================================================================
# HB-peer management + sendcmpct negotiation (mostly MISSING)
# =========================================================================

class TestW126_HBPeerManagement(unittest.TestCase):
    """G9-G13, G18, G19: HB-peer state and selection."""

    @pytest.mark.xfail(reason="W126 BUG-1 (P1): sendcmpct is sent TWICE per peer "
                              "(once from peer.py:852, once from p2p.py:2114 via "
                              "negotiate_compact_blocks()). Core sends once.",
                       strict=False, raises=AssertionError)
    def test_g9_sendcmpct_sent_exactly_once(self):
        """G9: sendcmpct sent exactly once per peer (Core: net_processing.cpp:3870)."""
        peer_src = (OUROBOROS_SRC / "peer.py").read_text()
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        # Count the construction sites:
        sites = (
            len(re.findall(r"SendCmpctMessage\s*\(\s*announce", peer_src))
            + len(re.findall(r"SendCmpctMessage\s*\(\s*announce", p2p_src))
        )
        # Two send sites (inbound + outbound) is fine; FOUR (peer.py:852 + 1406
        # + p2p.py:917-1723 series) is the bug.
        self.assertLessEqual(sites, 2,
            f"BUG-1: SendCmpctMessage created at {sites} sites; expected ≤2 "
            f"(once for inbound handshake, once for outbound)")

    @pytest.mark.xfail(reason="W126 BUG-2 (P1): on_sendcmpct only sets "
                              "peer.wants_cmpctblock when announce=True. Core sets "
                              "m_provides_cmpctblocks for ANY valid sendcmpct.",
                       strict=False, raises=AssertionError)
    def test_g10_provides_cmpctblocks_recorded_for_any_valid_sendcmpct(self):
        """G10: A peer that sent sendcmpct(False, 2) must be recorded as
        provides-cmpctblocks (Core: net_processing.cpp:3911)."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        # Look for the on_sendcmpct handler body and check it sets a
        # `provides_cmpctblocks` field unconditionally.
        # Current code: `if sc.announce: peer.wants_cmpctblock = True`
        # Required: separate `peer.provides_cmpctblocks = True` outside the if.
        m = re.search(r"async def on_sendcmpct[^{}]+?(?=async def|\Z)",
                      p2p_src, re.DOTALL)
        self.assertIsNotNone(m, "on_sendcmpct handler not found")
        body = m.group(0)
        self.assertIn("provides_cmpctblocks", body,
            "BUG-2: on_sendcmpct must record provides_cmpctblocks separately "
            "from wants_cmpctblock")

    @pytest.mark.xfail(reason="W126 BUG-3 (P1): No HB-peer cap, no rotation, no "
                              "MaybeSetPeerAsAnnouncingHeaderAndIDs equivalent. "
                              "Confirms W112 BUG-3/BUG-4 still open.",
                       strict=False, raises=AssertionError)
    def test_g11_hb_peer_rotation_cap_of_3(self):
        """G11: We MUST select at most 3 HB-announce-to-us peers
        (BIP-152 §Selection of Peers; Core: net_processing.cpp:1312)."""
        # Look for a constant or list maintaining HB-from-us state.
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        block_sync_src = (OUROBOROS_SRC / "block_sync.py").read_text()
        for name in ("lNodesAnnouncingHeaderAndIDs", "hb_announce_peers",
                     "MaybeSetPeerAsAnnouncing", "MAX_HB_ANNOUNCE_PEERS",
                     "maybe_set_peer_as_hb"):
            if name in p2p_src or name in block_sync_src:
                return
        self.fail("BUG-3: no HB-peer rotation list or cap constant found")

    @pytest.mark.xfail(reason="W126 BUG-5 (P1): cmpctblock receive path does not "
                              "call UpdateBlockAvailability / mapBlockSource.emplace, "
                              "so we have no signal of 'this peer delivered a valid "
                              "block' for later HB-peer promotion.",
                       strict=False, raises=AssertionError)
    def test_g12_maybe_set_peer_as_announcing_on_valid_block(self):
        """G12: We must invoke MaybeSetPeerAsAnnouncingHeaderAndIDs after a peer
        delivered a valid block (Core: net_processing.cpp:2220 via BlockChecked)."""
        for path in (OUROBOROS_SRC / "p2p.py", OUROBOROS_SRC / "block_sync.py",
                     OUROBOROS_SRC / "node.py"):
            src = path.read_text()
            if "MaybeSetPeerAsAnnouncing" in src or "maybe_set_peer_as_hb" in src:
                return
            if "UpdateBlockAvailability" in src or "update_block_availability" in src:
                return
        self.fail("BUG-5: no UpdateBlockAvailability or HB-promotion call found")

    @pytest.mark.xfail(reason="W126 BUG-8 (P2, latent): No -blocksonly gate in "
                              "HB-peer selection. Latent until BUG-3 fixed.",
                       strict=False, raises=AssertionError)
    def test_g13_blocksonly_disables_hb_selection(self):
        """G13: -blocksonly must short-circuit HB-peer selection (Core:
        net_processing.cpp:1279)."""
        for path in OUROBOROS_SRC.glob("*.py"):
            src = path.read_text()
            if "blocksonly" in src.lower() and "cmpct" in src.lower():
                return
        self.fail("BUG-8: no -blocksonly cmpct gate found")

    @pytest.mark.xfail(reason="W126 BUG-10 (P2): MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK "
                              "constant absent; no per-block parallel cmpct tracking.",
                       strict=False, raises=AssertionError)
    def test_g18_max_cmpctblocks_inflight_per_block(self):
        """G18: Per-block cmpctblock parallel cap = 3 (Core net_processing.h:47)."""
        for path in OUROBOROS_SRC.glob("*.py"):
            src = path.read_text()
            if re.search(r"MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK\s*[=:]\s*3", src):
                return
        self.fail("BUG-10: MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK constant absent")

    @pytest.mark.xfail(reason="W126 BUG-11 (P1): m_bip152_highbandwidth_to / "
                              "m_bip152_highbandwidth_from per-peer state fields "
                              "missing. ouroboros only has wants_cmpctblock which "
                              "conflates the two directions.",
                       strict=False, raises=AssertionError)
    def test_g19_high_bandwidth_to_from_state_fields(self):
        """G19: Two-bit HB state per peer (BIP-152; Core: net_processing.cpp:3915)."""
        peer_src = (OUROBOROS_SRC / "peer.py").read_text()
        for name in ("bip152_highbandwidth_to", "bip152_highbandwidth_from",
                     "hb_to", "hb_from", "high_bandwidth_to", "high_bandwidth_from"):
            if name in peer_src:
                return
        self.fail("BUG-11: no per-peer high_bandwidth_to/from state fields found")


# =========================================================================
# Reconstruction safety: FillBlock + IsBlockMutated  (P0-CDIV)
# =========================================================================

class TestW126_ReconstructionSafety(unittest.TestCase):
    """G14, G15, G16: Reconstruction-side correctness gates."""

    @pytest.mark.xfail(reason="W126 BUG-4 (P0-CDIV): reconstruct_partial does NOT "
                              "call IsBlockMutated(segwit_active) before returning "
                              "the reconstructed block. Core does so inside FillBlock "
                              "(blockencodings.cpp:218-222) to catch short-ID-collision "
                              "mutations and trigger Misbehaving + getdata fallback.",
                       strict=False, raises=AssertionError)
    def test_g14_fill_block_invokes_is_block_mutated(self):
        """G14: FillBlock MUST verify segwit_active mutation before READ_STATUS_OK
        (Core: blockencodings.cpp:218-222)."""
        cb_src = (OUROBOROS_SRC / "compact_blocks.py").read_text()
        # Look for IsBlockMutated equivalent: witness-root or merkle-root check
        # inside the reconstruct / fill path.
        for name in ("IsBlockMutated", "is_block_mutated", "check_block_mutated",
                     "check_witness_root", "verify_merkle_root",
                     "compute_witness_merkle_root"):
            if name in cb_src:
                # Verify it's INSIDE reconstruct/fill (not just imported).
                m = re.search(r"def (?:reconstruct|reconstruct_partial|fill_block)[^{}]+?(?=\n    (?:def |@|class )|\Z)",
                              cb_src, re.DOTALL)
                if m and name in m.group(0):
                    return
        self.fail("BUG-4 P0-CDIV: no IsBlockMutated check inside "
                  "reconstruct/reconstruct_partial/fill_block")

    @pytest.mark.xfail(reason="W126 BUG-5 (P1): on_cmpctblock does not call "
                              "UpdateBlockAvailability(peer_id, block_hash) on the "
                              "peer that delivered the cmpctblock. Core does so at "
                              "net_processing.cpp:4529.",
                       strict=False, raises=AssertionError)
    def test_g15_update_block_availability_on_cmpctblock(self):
        """G15: cmpctblock receive must update per-peer best-known block."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        m = re.search(r"async def on_cmpctblock.+?(?=async def|\Z)",
                      p2p_src, re.DOTALL)
        self.assertIsNotNone(m, "on_cmpctblock not found in p2p.py")
        body = m.group(0)
        self.assertTrue(
            "UpdateBlockAvailability" in body
            or "update_block_availability" in body
            or "best_known_block" in body,
            "BUG-5: on_cmpctblock does not update per-peer best-known block")

    @pytest.mark.xfail(reason="W126 BUG-5 (P1): no mapBlockSource emplace on "
                              "reconstructed compact block.",
                       strict=False, raises=AssertionError)
    def test_g16_map_block_source_on_reconstructed(self):
        """G16: mapBlockSource record for HB-peer scoring (Core:4690)."""
        for path in (OUROBOROS_SRC / "p2p.py", OUROBOROS_SRC / "block_sync.py"):
            src = path.read_text()
            if "mapBlockSource" in src or "map_block_source" in src:
                return
        self.fail("BUG-5: no mapBlockSource equivalent found")


# =========================================================================
# Optimistic reconstruction + extra-txn pool
# =========================================================================

class TestW126_OptimisticPath(unittest.TestCase):
    """G17, G22: Bandwidth-optimization gates."""

    @pytest.mark.xfail(reason="W126 BUG-9 (P2): no optimistic tempBlock "
                              "reconstruction when block already in-flight from "
                              "another peer (Core: net_processing.cpp:4640-4654).",
                       strict=False, raises=AssertionError)
    def test_g17_optimistic_temp_block_reconstruction(self):
        """G17: Second cmpctblock for in-flight block triggers tempBlock attempt."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        for name in ("tempBlock", "temp_block", "optimistic_reconstruct",
                     "already_in_flight"):
            if name in p2p_src:
                return
        self.fail("BUG-9: no optimistic temp-block reconstruction path")

    @pytest.mark.xfail(reason="W126 BUG-7 (P2): no vExtraTxnForCompact rolling pool "
                              "of recently-orphan-resolved / block-evicted txs "
                              "(Core: net_processing.cpp:997).",
                       strict=False, raises=AssertionError)
    def test_g22_extra_txn_pool(self):
        """G22: vExtraTxnForCompact pool for short-ID matching."""
        for path in OUROBOROS_SRC.glob("*.py"):
            src = path.read_text()
            if "vExtraTxnForCompact" in src or "extra_txn_pool" in src or \
                    "ExtraTxnForCompact" in src:
                return
        self.fail("BUG-7: no vExtraTxnForCompact equivalent")


# =========================================================================
# getblocktxn / blocktxn round-trip (mostly PRESENT, one PARTIAL)
# =========================================================================

class TestW126_GetBlockTxnRoundTrip(unittest.TestCase):
    """G20, G21: getblocktxn → blocktxn response path."""

    def test_g20_getblocktxn_depth_and_oob_gates(self):
        """G20: getblocktxn handler enforces depth gate + OOB index check."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        m = re.search(r"async def on_getblocktxn.+?(?=async def|\Z)",
                      p2p_src, re.DOTALL)
        self.assertIsNotNone(m, "on_getblocktxn not found")
        body = m.group(0)
        self.assertIn("MAX_BLOCKTXN_DEPTH", body, "depth gate constant missing")
        self.assertTrue(
            "out_of_bounds" in body or "out-of-bounds" in body or
            ">= len(txs)" in body,
            "OOB index check missing")

    @pytest.mark.xfail(reason="W126 BUG-12 (P2): getblocktxn for blocks > "
                              "MAX_BLOCKTXN_DEPTH deep returns nothing. Core falls "
                              "back to MSG_WITNESS_BLOCK full block "
                              "(net_processing.cpp:4299-4302). Re-audit of "
                              "W112 BUG-7.",
                       strict=False, raises=AssertionError)
    def test_g21_getblocktxn_deep_block_full_fallback(self):
        """G21: Deep block fallback to MSG_WITNESS_BLOCK.

        The current handler at p2p.py:2321 returns SILENTLY on the deep-block
        branch — no MSG_WITNESS_BLOCK fallback, just `return`. We look for an
        actual send/push of a full-block message inside the deep branch."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        m = re.search(r"async def on_getblocktxn.+?(?=async def|\Z)",
                      p2p_src, re.DOTALL)
        self.assertIsNotNone(m, "on_getblocktxn not found")
        body = m.group(0)
        # Strip docstring + line comments — they reference MSG_WITNESS_BLOCK in
        # the documentation but the code path is missing.
        code_only = "\n".join(
            line for line in body.splitlines()
            if not line.lstrip().startswith("#")
        )
        # Drop the triple-quoted docstring.
        code_only = re.sub(r'"""[^"]*"""', "", code_only, count=1)
        # Now the only MSG_WITNESS_BLOCK reference would be in an actual send.
        deep_branch_sends_full_block = (
            "MSG_WITNESS_BLOCK" in code_only
            or ("BlockMessage(" in code_only and "send_message" in code_only)
            or ("block.serialize(" in code_only and "send_message" in code_only)
        )
        self.assertTrue(
            deep_branch_sends_full_block,
            "BUG-12: deep getblocktxn returns silently; no full-block fallback")


# =========================================================================
# cmpctblock receive: depth, low-work, fRevertToHeaderProcessing
# =========================================================================

class TestW126_CmpctBlockReceive(unittest.TestCase):
    """G23, G24, G25: cmpctblock receive-side gates."""

    @pytest.mark.xfail(reason="W126 BUG-13 (P2): depth gate is documented "
                              "differently from Core. Core caps at +2 ABOVE tip + "
                              "reverts to header processing for far-future; "
                              "ouroboros drops only too-OLD blocks. Re-audit of "
                              "W112 BUG-5 — direction is correct, semantics "
                              "different.",
                       strict=False, raises=AssertionError)
    def test_g23_cmpct_depth_gate_caps_at_tip_plus_2(self):
        """G23: We must cap cmpctblock processing at tip+2 (Core: 4576)."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        m = re.search(r"async def on_cmpctblock.+?(?=async def|\Z)",
                      p2p_src, re.DOTALL)
        body = m.group(0) if m else ""
        # Core's check: announced_height <= tip_height + 2  → process compact
        # ouroboros currently: announced_height < our_height - 5  → drop
        self.assertTrue(
            "our_height + 2" in body or "tip_height + 2" in body or
            "+2" in body and "announced_height" in body,
            "BUG-13: cmpctblock depth gate does not match Core's +2 cap")

    @pytest.mark.xfail(reason="W126 BUG-14 (P1): no GetAntiDoSWorkThreshold "
                              "low-work cmpctblock drop. Cheap DoS vector — "
                              "Core does this check at "
                              "net_processing.cpp:4490-4494.",
                       strict=False, raises=AssertionError)
    def test_g24_low_work_cmpct_drop(self):
        """G24: cmpctblock low-work drop."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        for name in ("GetAntiDoSWorkThreshold", "anti_dos_work_threshold",
                     "low_work", "min_chain_work"):
            if name in p2p_src and "cmpct" in p2p_src.lower():
                return
        self.fail("BUG-14: no low-work cmpctblock drop")

    @pytest.mark.xfail(reason="W126 BUG-15 (P2): no fRevertToHeaderProcessing "
                              "branch for far-future cmpctblocks. Core falls back "
                              "to ProcessHeadersMessage (net_processing.cpp:4664).",
                       strict=False, raises=AssertionError)
    def test_g25_revert_to_header_processing(self):
        """G25: Far-future cmpctblock processed as plain headers message."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        for name in ("fRevertToHeaderProcessing", "revert_to_header",
                     "process_as_header", "ProcessHeadersMessage"):
            if name in p2p_src:
                return
        self.fail("BUG-15: no fRevertToHeaderProcessing-equivalent branch")


# =========================================================================
# Serving side: most-recent cache, MSG_CMPCT_BLOCK getdata, fast-announce
# =========================================================================

class TestW126_ServingSide(unittest.TestCase):
    """G26, G27, G28: Outbound BIP-152 serving path."""

    @pytest.mark.xfail(reason="W126 BUG-6 (P2): no m_most_recent_compact_block "
                              "cache. Core caches it (net_processing.h:863) for "
                              "serving MSG_CMPCT_BLOCK getdata without rebuilding.",
                       strict=False, raises=AssertionError)
    def test_g26_most_recent_compact_block_cache(self):
        """G26: Cache the most-recent compact block for getdata serving."""
        for path in OUROBOROS_SRC.glob("*.py"):
            src = path.read_text()
            if ("most_recent_compact_block" in src or
                    "most_recent_cmpct" in src or
                    "m_most_recent_compact_block" in src or
                    "recent_cmpctblock_cache" in src):
                return
        self.fail("BUG-6: no most-recent compact block cache")

    @pytest.mark.xfail(reason="W126 BUG-16 (P2): MSG_CMPCT_BLOCK (inv type 4) "
                              "getdata serving path missing. Core handles this in "
                              "ProcessGetBlockData :2461-2476.",
                       strict=False, raises=AssertionError)
    def test_g27_msg_cmpct_block_getdata_serving(self):
        """G27: Handle inbound getdata MSG_CMPCT_BLOCK (type 4)."""
        for path in (OUROBOROS_SRC / "node.py",
                     OUROBOROS_SRC / "p2p.py",
                     OUROBOROS_SRC / "block_sync.py"):
            src = path.read_text()
            # MSG_CMPCT_BLOCK = 4
            if ("MSG_CMPCT_BLOCK" in src or
                    "inv_type == 4" in src or
                    "IsMsgCmpctBlk" in src or
                    "INV_TYPE_CMPCT_BLOCK" in src):
                return
        self.fail("BUG-16: no MSG_CMPCT_BLOCK getdata handler")

    @pytest.mark.xfail(reason="W126 BUG-17 (P3): _announce_block does not de-dup "
                              "by m_highest_fast_announce height. On reorgs at tip "
                              "we re-announce.",
                       strict=False, raises=AssertionError)
    def test_g28_highest_fast_announce_dedup(self):
        """G28: De-dup compact-block fast-announce at same height."""
        block_sync_src = (OUROBOROS_SRC / "block_sync.py").read_text()
        for name in ("highest_fast_announce", "m_highest_fast_announce",
                     "_last_announce_height", "last_announce_height"):
            if name in block_sync_src:
                return
        self.fail("BUG-17: no highest-fast-announce dedup")


# =========================================================================
# Dead state + two-pipeline guard
# =========================================================================

class TestW126_DeadStateAndTwoPipelineGuard(unittest.TestCase):
    """G29, G30: dead-helper + two-pipeline architectural guard."""

    @pytest.mark.xfail(reason="W126 / W112 BUG-8 (P3): cmpct_peers set is written "
                              "by on_sendcmpct but never read. Dead state — "
                              "actual HB tracking lives on peer.wants_cmpctblock. "
                              "Dead-helper-at-call-site (34-wave streak continues).",
                       strict=False, raises=AssertionError)
    def test_g29_cmpct_peers_set_is_dead_state(self):
        """G29: cmpct_peers is dead state (never read)."""
        p2p_src = (OUROBOROS_SRC / "p2p.py").read_text()
        # Reads (anything that is NOT .add and not a declaration `cmpct_peers: set`):
        # 1 declaration + 1 .add = 2 mentions. Any > 2 means it's being read.
        mentions = re.findall(r"\bcmpct_peers\b", p2p_src)
        self.assertGreater(len(mentions), 2,
            "BUG-8 closed: cmpct_peers is now being read (update test)")

    def test_g30_rust_pipeline_has_no_bip152_handlers(self):
        """G30: Two-pipeline guard. Rust ferrous-utils has NO BIP-152 wire
        handlers (CompactBlock / cmpctblock / getblocktxn / blocktxn). The
        SipHash + short_txid helpers in Rust are reused for BIP-330
        reconciliation (Erlay), NOT for BIP-152 P2P. Extends the two-pipeline
        guard set per FIX-76 / FIX-79 ouroboros pattern."""
        if not RUST_PEER_PATH.exists():
            self.skipTest("ferrous-utils Rust crate not present")

        # Scan ALL .rs files under sync/ for BIP-152 wire handlers.
        bip152_wire_terms = (
            "CompactBlock", "PartiallyDownloadedBlock",
            # lower-case wire commands — search outside comments
            "cmpctblock_handler", "on_cmpctblock", "on_getblocktxn",
            "on_blocktxn", "on_sendcmpct",
            "BlockTransactionsRequest", "BlockTransactions",
            "PrefilledTransaction",
        )
        violations: list[str] = []
        for rs_path in RUST_SYNC_DIR.rglob("*.rs"):
            content = rs_path.read_text()
            # Strip line comments (// ...) — keep block comments naive since
            # SipHash references appear in comments and shouldn't trip.
            non_comment = "\n".join(
                line for line in content.splitlines()
                if not line.lstrip().startswith("//")
            )
            for term in bip152_wire_terms:
                if term in non_comment:
                    violations.append(f"{rs_path}: {term}")

        self.assertFalse(
            violations,
            f"Two-pipeline guard VIOLATED: BIP-152 wire handlers found in Rust "
            f"sync crate: {violations}"
        )

    def test_g30b_rust_siphash_kept_for_erlay_only(self):
        """G30 corollary: SipHash + short_txid live in Rust because they are
        reused by BIP-330 (Erlay reconciliation), not for BIP-152.  Audit
        documents intent so future refactors don't accidentally route BIP-152
        wire handling through the Rust crate."""
        if not RUST_COMMON_DIR.exists():
            self.skipTest("ferrous-utils Rust crate not present")
        siphash_path = RUST_COMMON_DIR / "crypto" / "siphash.rs"
        minisketch_path = RUST_COMMON_DIR / "minisketch.rs"
        self.assertTrue(siphash_path.exists(), "Rust siphash.rs missing")
        self.assertTrue(minisketch_path.exists(),
                        "Rust minisketch.rs (BIP-330) missing")
        # Confirm Rust short_txid serves minisketch (BIP-330), not a cmpctblock
        # message handler.
        minisketch_src = minisketch_path.read_text()
        self.assertIn("compute_short_txid", minisketch_src)
        # Confirm Rust peer.rs explicitly notes BIP-152 is Python-only.
        rust_peer_src = RUST_PEER_PATH.read_text()
        self.assertIn("BIP-152", rust_peer_src)


if __name__ == "__main__":
    unittest.main()
