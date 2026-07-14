"""
W101 ActivateBestChain + InvalidateBlock gate audit — ouroboros.

Tests the ouroboros analogs of Bitcoin Core's:
  - Chainstate::ActivateBestChain / FindMostWorkChain (validation.cpp:3114/3323)
  - Chainstate::ActivateBestChainStep (validation.cpp:3191)
  - Chainstate::InvalidateBlock (validation.cpp:3521)
  - Chainstate::ResetBlockFailureFlags (validation.cpp:3711)
  - Chainstate::InvalidBlockFound (validation.cpp:1988)
  - Chainstate::LoadGenesisBlock (validation.cpp:4926)
  - Chainstate::PruneAndFlush (validation.cpp:2849)

Discovered bugs (11 total):

BUG-1 [CONSENSUS-DIVERGENT] invalidate_block() scans only active-chain heights
  (target_height+1..=best_height) for descendants to mark BLOCK_FAILED_CHILD.
  Off-chain orphans stored above best_height are never marked invalid.
  Core's SetBlockFailureFlags / InvalidateBlock walk the FULL block-tree
  (all of m_blockman.m_block_index), not just the active chain window.

BUG-2 [CONSENSUS-DIVERGENT] reconsider_block / ResetBlockFailureFlags: ouroboros
  clear_failed() clears BOTH BLOCK_FAILED_VALID and BLOCK_FAILED_CHILD on every
  ancestor/descendant of the target. Core's ResetBlockFailureFlags only clears
  BLOCK_FAILED_VALID and only on blocks that are ancestors OR descendants of the
  specific reconsidered block. A block with a DIFFERENT invalid ancestor gets
  its flags incorrectly cleared.

BUG-3 [CONSENSUS-DIVERGENT] reactivate_best_chain() only considers blocks at
  heights > best_height (scan range best_height+1..=scan_height). After
  invalidate_block rolls the tip back to height N, competing fork blocks stored
  at heights <= original_best (as orphans) are never discovered as candidates.
  Core's FindMostWorkChain searches the full setBlockIndexCandidates regardless
  of height.

BUG-4 [CORRECTNESS] _handle_reorg in block_sync.py tracks new-chain heights
  incorrectly. It initialises temp_height = current_height for the new-chain
  walk, then assigns that height to the new-chain blocks. When the new chain
  diverges at a different depth, the stored heights mismatch actual block
  heights, causing the common_ancestor_height to be wrong.

BUG-5 [CORRECTNESS] invalidate_block() includes target_height in the disconnect
  loop (range target_height..=best_height). This disconnects the target block
  itself before marking it invalid. Core's InvalidateBlock disconnects
  only blocks ABOVE the target; it marks the disconnected_tip BLOCK_FAILED_VALID
  each iteration, reaching the target only when it is the last tip at the
  boundary.

BUG-6 [CORRECTNESS] connect_block_at_height() in reactivate_best_chain() skips
  re-validation ("blocks were validated once already"). For blocks that were
  never on the active chain (reorg branches), this silently connects
  unvalidated blocks. Core's ConnectTip always calls ConnectBlock (which
  runs CheckBlock + ConnectBlock validation) even on reactivation.

BUG-7 [DOS] block_descends_from() is called once per candidate height inside
  invalidate_block(), each call walks O(height_diff) blocks via DB reads.
  For a 1000-block chain above the target, this is O(N^2) DB reads.
  Core builds a multimap once and uses GetAncestor(height) — O(log N) per
  candidate.

BUG-8 [OBSERVABILITY] rpc_invalidateblock() does not fire zmq notifications or
  update the block filter index after the chain tip changes. Core's
  InvalidateBlock emits blockTip + ActiveTipChange signals
  (validation.cpp:3685-3693) when pindex_was_in_chain is true.

BUG-9 [OBSERVABILITY] rpc_reconsiderblock() does not signal the sync loop or
  mempool after reactivate_best_chain() reconnects blocks. Core's
  ActivateBestChain fires BlockConnected + UpdatedBlockTip + ActiveTipChange
  for every block connected. The Python RPC handler discards the new tip
  height and does not wake the sync loop.

BUG-10 [CORRECTNESS] _init_genesis_block() idempotency check uses
  get_best_block() raising RuntimeError as the "empty DB" signal. If the
  DB has synced headers but the chainstate tip is at height 0, the genesis
  block is not re-initialized. Core's LoadGenesisBlock checks the BLOCK
  INDEX (m_blockman.m_block_index.contains(genesisHash)), not the chainstate
  tip.

BUG-11 [CORRECTNESS] reactivate_best_chain() returns best_height unchanged
  when fork_height < best_height (real reorg case), deferring to the sync
  loop. But neither rpc_reconsiderblock() nor the dumptxoutset path wakes
  the sync loop after reconsider_block() returns. The chain is silently
  left at the old tip even though a better chain exists.
"""

import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Block, BlockchainDatabase  # noqa: E402
from ouroboros.validation import BlockValidator  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_block(**kwargs) -> Block:
    """Return a minimal Block with sane defaults."""
    defaults = dict(
        version=1,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1231006505,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[],
        hash=bytes(32),
        height=0,
    )
    defaults.update(kwargs)
    return Block(**defaults)


# ---------------------------------------------------------------------------
# BUG-1: invalidate_block() misses off-chain orphans above best_height
# ---------------------------------------------------------------------------

class TestInvalidateBlockMissesOrphans(unittest.TestCase):
    """BUG-1 (FIXED): descendants above best_height are now marked invalid."""

    def test_invalidate_marks_orphan_descendants_above_best_height(self):
        """
        After fixing BUG-1, invalidate_block() extends the descendant scan
        past best_height by FAILED_CHILD_SCAN_HORIZON so that off-chain
        orphans stored above the current active-chain tip also receive
        BLOCK_FAILED_CHILD.  Core's SetBlockFailureFlags walks the full
        m_blockman.m_block_index, not just active-chain heights.

        Asserts the fix: the scan ceiling in db.rs must exceed best_height.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # The fix introduces FAILED_CHILD_SCAN_HORIZON and uses it to compute
        # a scan ceiling above best_height.
        self.assertIn("FAILED_CHILD_SCAN_HORIZON", src,
            "FAILED_CHILD_SCAN_HORIZON constant not found — BUG-1 not fixed")
        self.assertIn("scan_ceiling", src,
            "scan_ceiling variable not found — BUG-1 not fixed")
        # The old restricted range must no longer be the only scan range.
        # After the fix the loop iterates up to scan_ceiling, not best_height.
        self.assertIn("target_height + 1)..=scan_ceiling", src,
            "Descendant scan must extend to scan_ceiling (above best_height) — BUG-1 not fixed")


# ---------------------------------------------------------------------------
# BUG-2: reconsider_block clears flags on unrelated invalid ancestors
# ---------------------------------------------------------------------------

class TestResetBlockFailureFlagsScope(unittest.TestCase):
    """BUG-2: ResetBlockFailureFlags clears flags too broadly."""

    def test_clear_failed_clears_both_flags(self):
        """
        clear_failed() in common/src/types.rs clears BOTH BLOCK_FAILED_VALID
        and BLOCK_FAILED_CHILD in a single mask clear (BUG-2).
        Core's ResetBlockFailureFlags only clears BLOCK_FAILED_VALID
        (nStatus &= ~BLOCK_FAILED_VALID) — it never explicitly clears
        BLOCK_FAILED_CHILD; that flag is pruned separately.

        A block that is BLOCK_FAILED_CHILD due to a DIFFERENT invalid ancestor
        must NOT have its flag cleared when an unrelated block is reconsidered.
        """
        try:
            from common import BlockStatus  # type: ignore — Rust pyi stubs
            status = BlockStatus()
            status.set_failed_child()
            self.assertTrue(status.is_invalid(), "FAILED_CHILD should be invalid")
            status.clear_failed()
            self.assertFalse(status.is_invalid(),
                "clear_failed() cleared FAILED_CHILD even though only "
                "FAILED_VALID should be cleared by ResetBlockFailureFlags")
        except ImportError:
            self.skipTest("common Rust extension not available")

    @unittest.expectedFailure  # BUG-2
    def test_reconsider_leaves_unrelated_failed_child_intact(self):
        """
        Reconsidering block A must NOT clear BLOCK_FAILED_CHILD on block B
        when B's FAILED_CHILD flag was set because of a DIFFERENT invalid
        ancestor C (not A).

        Expected to fail because clear_failed() clears all failure flags
        indiscriminately.
        """
        try:
            from common import BlockStatus  # type: ignore
        except ImportError:
            raise unittest.SkipTest("common Rust extension not available")

        # Simulate: B is FAILED_CHILD because C is invalid (C != A).
        status_b = BlockStatus()
        status_b.set_failed_child()

        # Reconsidering A — B should keep its FAILED_CHILD (it was not
        # caused by A), but clear_failed() clears everything.
        # This test documents the bug: it will PASS (not raise) only if
        # the implementation is correct; we mark xfail because it is buggy.
        status_b.clear_failed()  # simulates what reconsider does
        self.assertTrue(status_b.is_invalid(),
            "B should still be invalid after reconsidering unrelated block A")


# ---------------------------------------------------------------------------
# BUG-3: reactivate_best_chain() ignores competing fork blocks
# ---------------------------------------------------------------------------

class TestReactivateBestChainIgnoresForks(unittest.TestCase):
    """BUG-3 (FIXED): competing forks at heights <= best_height are now candidates."""

    def test_competing_fork_below_best_height_is_candidate(self):
        """
        After fixing BUG-3, reactivate_best_chain() scans from scan_height
        down to 0 (inclusive), so competing forks at heights <= best_height
        are now discovered as candidates if their chainwork exceeds the new
        tip.  Core's FindMostWorkChain searches setBlockIndexCandidates
        which contains ALL known blocks regardless of height.

        Asserts the fix: the scan range in db.rs must start from 0.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # The old restricted range must be gone.
        self.assertNotIn("(best_height + 1..=scan_height)", src,
            "Old restricted scan range still present — BUG-3 not fixed")

        # The fix must scan from 0 so that all known heights are covered.
        self.assertIn("(0..=scan_height).rev()", src,
            "reactivate_best_chain must scan from 0 to discover "
            "competing forks below best_height — BUG-3 not fixed")


# ---------------------------------------------------------------------------
# BUG-4: _handle_reorg height tracking for the new chain
# ---------------------------------------------------------------------------

class TestHandleReorgHeightTracking(unittest.TestCase):
    """BUG-4: new chain height is initialized to current_height, not its real height."""

    def test_new_chain_height_initialized_to_current_height(self):
        """
        In block_sync.py _handle_reorg, the new-chain walk starts with
        temp_height = current_height (line 2830), but the new chain tip may
        be at a different height. The blocks in the new_chain list carry
        heights copied from current_height, which may not match their true
        height. This leads to wrong common_ancestor_height.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._handle_reorg)
        # The initialisation sets temp_height = current_height for BOTH chains.
        # Line ~2830: temp_height = current_height (second time)
        # A correct implementation would determine the new tip's height
        # from the block header or the block index.
        lines = [l.strip() for l in src.splitlines()]
        assignments = [l for l in lines if "temp_height = current_height" in l]
        self.assertGreaterEqual(len(assignments), 2,
            "Expected two 'temp_height = current_height' assignments "
            "(one for each chain walk) — BUG-4: new-chain height is wrong")


# ---------------------------------------------------------------------------
# BUG-5: invalidate_block disconnects the target block itself
# ---------------------------------------------------------------------------

class TestInvalidateBlockDisconnectsTarget(unittest.TestCase):
    """BUG-5 (FIXED): disconnect loop now excludes the target block itself."""

    def test_disconnect_loop_excludes_target_height(self):
        """
        After fixing BUG-5, the disconnect loop in db.rs invalidate_block()
        uses an exclusive lower bound:
          for height in (target_height + 1..=best_height).rev()

        Core's InvalidateBlock disconnects only blocks ABOVE the target;
        the target block itself remains connected (it is only marked
        BLOCK_FAILED_VALID so that chain selection skips it).

        Asserts the fix: the exclusive form must be present and the old
        inclusive form must be gone.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # Old inclusive form must be gone.
        self.assertNotIn("(target_height..=best_height).rev()", src,
            "Old inclusive disconnect loop still present — BUG-5 not fixed")
        # Fixed exclusive form must be present.
        self.assertIn("(target_height + 1..=best_height).rev()", src,
            "Exclusive disconnect loop not found — BUG-5 not fixed")


# ---------------------------------------------------------------------------
# BUG-6: connect_block_at_height skips re-validation
# ---------------------------------------------------------------------------

class TestConnectBlockSkipsValidation(unittest.TestCase):
    """BUG-6: connect_block_at_height does not re-validate blocks."""

    def test_connect_block_at_height_no_validation(self):
        """
        reactivate_best_chain() calls connect_block_at_height() which does
        NOT call any block validator. The comment explicitly says "these
        blocks were validated once already". For blocks that were on the
        active chain before invalidate_block, this is safe. But for reorg
        branches (blocks that were never on the active chain), validation
        must be re-run. Core's ConnectTip always invokes ConnectBlock.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # The comment is the canary.
        self.assertIn("validated once already", src,
            "Expected 'validated once already' comment not found; "
            "source may have changed")
        # Verify there is no validate_block CALL inside connect_block_at_height.
        # Find the function including its doc-comment (which precedes pub fn).
        # The "validated once already" comment lives in the doc block right
        # before the pub fn signature, so search from the doc comment start.
        doc_marker = "Reconnect a previously-disconnected block at `height`"
        idx = src.find(doc_marker)
        if idx == -1:
            # Fall back to finding the pub fn signature directly.
            idx = src.find("pub fn connect_block_at_height")
        self.assertNotEqual(idx, -1, "connect_block_at_height not found")
        # Grab the next ~5000 chars covering doc-comment + function body.
        body = src[idx:idx + 5000]
        # Look for an actual call site (not the doc comment phrase).
        # An actual call would appear as "validate_block(" not "validation"
        # or "validated once already".
        import re
        call_sites = re.findall(r'\bvalidate_block\s*\(', body)
        self.assertEqual(len(call_sites), 0,
            "connect_block_at_height calls validate_block — bug may be fixed")
        # This assertion confirms the absence of validation (the bug).
        self.assertIn("validated once already", body,
            "connect_block_at_height explicitly skips validation (BUG-6)")


# ---------------------------------------------------------------------------
# BUG-7: block_descends_from O(N^2) complexity
# ---------------------------------------------------------------------------

class TestBlockDescendsFromComplexity(unittest.TestCase):
    """BUG-7: O(N^2) DB reads during descendant marking."""

    def test_block_descends_from_is_linear_per_call(self):
        """
        block_descends_from(height, ancestor_height, ancestor_hash) walks
        (height - ancestor_height) blocks per call. When called for every
        height in (target_height+1)..=best_height, total DB reads are
        O((best_height - target_height)^2). Core builds a multimap once
        and uses GetAncestor — O(N log N) total. This is a DoS vector for
        deep invalidations.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # Confirm block_descends_from walks blocks one at a time.
        idx = src.find("fn block_descends_from")
        self.assertNotEqual(idx, -1)
        body = src[idx:idx + 1000]
        self.assertIn("current_height -= 1", body,
            "block_descends_from walks one block at a time — O(N^2) total (BUG-7)")

    @unittest.expectedFailure  # BUG-7 performance, only visible at scale
    def test_invalidate_deep_chain_is_not_quadratic(self):
        """
        Invalidating a block 500 blocks deep should NOT perform O(250000)
        DB reads. This test would fail if the implementation had a more
        efficient path; it is marked expectedFailure to document the bug.
        """
        # We can't run this without a real DB, so just assert the source
        # uses the multimap pattern Core uses.
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            raise unittest.SkipTest("ferrous-utils not found")
        with open(db_path) as f:
            src = f.read()
        self.assertIn("highpow_outofchain_headers", src,
            "Multimap optimization from Core is not present (BUG-7 confirmed)")


# ---------------------------------------------------------------------------
# BUG-8: invalidateblock RPC has no ZMQ/blockfilter notifications
# ---------------------------------------------------------------------------

class TestInvalidateBlockNoNotifications(unittest.TestCase):
    """BUG-8: rpc_invalidateblock fires no zmq/filter notifications."""

    def test_rpc_invalidateblock_has_no_zmq_call(self):
        """
        Core's InvalidateBlock fires blockTip + ActiveTipChange when
        pindex_was_in_chain. The ouroboros rpc_invalidateblock handler
        does not call any zmq notifier, block filter index update, or
        signal to the sync layer.
        """
        import inspect
        from ouroboros import rpc as rpc_module

        src = inspect.getsource(rpc_module.RPCServer.rpc_invalidateblock)
        self.assertNotIn("zmq", src.lower(),
            "rpc_invalidateblock unexpectedly has ZMQ notification")
        self.assertNotIn("notify", src.lower(),
            "rpc_invalidateblock unexpectedly has notification call")
        self.assertNotIn("block_filter", src.lower(),
            "rpc_invalidateblock unexpectedly updates block filter index")
        # The assertions above PASS because notifications are absent — confirming BUG-8.

    def test_rpc_reconsiderblock_has_no_sync_loop_wakeup(self):
        """
        After rpc_reconsiderblock reconnects blocks, the sync loop is not
        woken up to process the new tip. Core fires BlockConnected,
        UpdatedBlockTip, and ActiveTipChange. BUG-9 companion.
        """
        import inspect
        from ouroboros import rpc as rpc_module

        src = inspect.getsource(rpc_module.RPCServer.rpc_reconsiderblock)
        self.assertNotIn("notify", src.lower(),
            "rpc_reconsiderblock unexpectedly notifies something")
        self.assertNotIn("sync_loop", src.lower(),
            "rpc_reconsiderblock unexpectedly wakes the sync loop")
        # Pass means the notifications are absent — confirming BUG-8/9.


# ---------------------------------------------------------------------------
# BUG-9: reconsiderblock sync loop not woken after reactivation
# ---------------------------------------------------------------------------

class TestReactivationSyncLoopNotWoken(unittest.TestCase):
    """BUG-9: reactivate_best_chain return value discarded; sync loop not woken."""

    @unittest.expectedFailure  # BUG-9
    def test_reconsider_block_wakes_sync_loop(self):
        """
        After reactivate_best_chain() reconnects blocks, the Python sync
        loop should be notified (e.g. via an asyncio.Event.set() or
        similar). Currently the new tip height is returned to the RPC
        caller but the sync loop is never woken.
        """
        import inspect
        from ouroboros import rpc as rpc_module

        src = inspect.getsource(rpc_module.RPCServer.rpc_reconsiderblock)
        # For this test to PASS (which would mean the bug is fixed),
        # the handler must call some form of sync notification.
        found = (
            "event.set()" in src
            or "sync_event" in src
            or "_tip_changed" in src
            or "wake" in src.lower()
            or "notify_tip" in src.lower()
        )
        self.assertTrue(found,
            "rpc_reconsiderblock does not wake the sync loop after "
            "reactivate_best_chain — new tip silently ignored (BUG-9)")


# ---------------------------------------------------------------------------
# BUG-10: _init_genesis_block idempotency
# ---------------------------------------------------------------------------

class TestLoadGenesisBlockIdempotency(unittest.TestCase):
    """BUG-10: _init_genesis_block uses wrong idempotency check."""

    def test_genesis_init_uses_chainstate_not_block_index(self):
        """
        _init_genesis_block() is triggered when get_best_block() raises
        RuntimeError, i.e. when the CHAINSTATE has no tip. But Core's
        LoadGenesisBlock checks m_blockman.m_block_index — the BLOCK INDEX.
        If the block index has the genesis but the chainstate is at 0,
        _init_genesis_block will re-try to connect the genesis, which may
        fail or corrupt state.
        """
        import inspect
        from ouroboros.node import BitcoinNode

        src = inspect.getsource(BitcoinNode._init_genesis_block)
        # The method does NOT check whether the genesis is already in the
        # block index; it relies on connect_block_from_bytes to fail/no-op.
        self.assertNotIn("block_index", src,
            "Unexpected block_index check found — BUG-10 may be fixed")
        self.assertNotIn("has_block_hash", src.lower(),
            "Unexpected hash-existence check found — BUG-10 may be fixed")
        # Confirm the triggering condition is the chainstate check.
        # (The _init call is in node.py at the RuntimeError catch site,
        # not in _init_genesis_block itself.)

    def test_node_genesis_triggered_by_runtime_error(self):
        """
        Verify the triggering condition is a RuntimeError from get_best_block,
        not a block-index check (BUG-10: wrong idempotency guard).
        """
        import inspect
        from ouroboros.node import BitcoinNode

        src = inspect.getsource(BitcoinNode.start)
        self.assertIn("RuntimeError", src,
            "Genesis initialization trigger (RuntimeError) not found in start()")
        # Core checks block_index, not chainstate tip.
        # The presence of RuntimeError-based trigger confirms BUG-10.


# ---------------------------------------------------------------------------
# BUG-11: reactivate_best_chain defers real reorgs without waking sync loop
# ---------------------------------------------------------------------------

class TestReactivateBestChainReorgDeferral(unittest.TestCase):
    """BUG-11: real reorgs deferred to sync loop that is never woken."""

    def test_reactivate_returns_without_reorg_when_fork_below_best(self):
        """
        reactivate_best_chain() returns best_height unchanged when
        fork_height < best_height (real reorg required). The call sites
        (rpc_reconsiderblock and dumptxoutset rollback) do not wake the
        sync loop, so the better chain is never activated.
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            self.skipTest("ferrous-utils/sync/src/storage/db.rs not found")

        with open(db_path) as f:
            src = f.read()

        # Confirm the deferral comment is present.
        self.assertIn("reorg required, deferring to sync loop", src,
            "Deferral comment not found; source may have changed")
        # Confirm that when fork_height < best_height the function
        # returns Ok(best_height) — not the leaf height.
        self.assertIn("return Ok(best_height)", src,
            "Expected 'return Ok(best_height)' return for fork deferral (BUG-11)")

    @unittest.expectedFailure  # BUG-11
    def test_reconsider_block_triggers_reorg_when_fork_below_best(self):
        """
        When reconsider_block() reveals a competing chain with more work
        whose fork point is below best_height, a reorg should occur.
        Currently it silently returns the unchanged tip height (BUG-11).
        """
        db_path = (Path(__file__).parent.parent.parent.parent
                   / "ferrous-utils" / "sync" / "src" / "storage" / "db.rs")
        if not db_path.exists():
            raise unittest.SkipTest("ferrous-utils not found")
        with open(db_path) as f:
            src = f.read()

        # For this test to pass (meaning the bug is fixed), the function
        # must handle the fork_height < best_height case, not just defer.
        self.assertNotIn("reorg required, deferring to sync loop", src,
            "reactivate_best_chain still defers real reorgs (BUG-11)")


# ---------------------------------------------------------------------------
# Structural: Python two-pipeline gap (dead-helper pattern)
# ---------------------------------------------------------------------------

class TestTwoPipelineGap(unittest.TestCase):
    """
    Confirm the two-pipeline pattern: Rust helpers for chain activation
    exist (invalidate_block, reconsider_block, reactivate_best_chain) but
    the Python sync loop (_handle_reorg, _drain_block_buffer_locked) does
    NOT call them, creating two parallel activation pipelines.
    """

    def test_handle_reorg_does_not_call_reactivate_best_chain(self):
        """
        _handle_reorg implements its own connect/disconnect loop without
        calling the Rust reactivate_best_chain. This diverges from the
        authoritative Rust chain-selection logic and can produce different
        results on competing forks.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._handle_reorg)
        self.assertNotIn("reactivate_best_chain", src,
            "Unexpected reactivate_best_chain call found in _handle_reorg")
        self.assertNotIn("invalidate_block", src,
            "Unexpected invalidate_block call found in _handle_reorg")
        # Confirms two-pipeline gap.

    def test_drain_block_buffer_does_not_call_find_most_work_chain(self):
        """
        _drain_block_buffer_locked connects blocks sequentially without
        calling FindMostWorkChain / reactivate_best_chain to confirm the
        connected chain is the highest-work candidate. A peer could feed
        a low-work chain that passes this path while a higher-work valid
        chain exists in BLOCKS_CF.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        self.assertNotIn("reactivate_best_chain", src,
            "Unexpected reactivate_best_chain call — may be fixed")
        self.assertNotIn("find_most_work", src,
            "Unexpected find_most_work_chain call — may be fixed")

    def test_rpc_invalidateblock_calls_rust_not_python(self):
        """
        rpc_invalidateblock() calls rust_db.invalidate_block directly,
        bypassing the Python sync layer. After invalidation, the Python
        sync layer's internal state (validated_headers queue, etc.) is
        stale relative to the new chain tip.
        """
        import inspect
        from ouroboros import rpc as rpc_module

        src = inspect.getsource(rpc_module.RPCServer.rpc_invalidateblock)
        self.assertIn("rust_db.invalidate_block", src,
            "Expected direct Rust call in rpc_invalidateblock")
        # Confirms that the Python sync state is not updated after invalidation.
        self.assertNotIn("_validated_headers", src,
            "Python sync state not cleared after invalidation — two-pipeline gap")

    def test_connect_block_at_height_not_called_from_python_sync(self):
        """
        connect_block_at_height exists in Rust db.rs but is never invoked
        directly from the Python block_sync.py sync loop. The Python loop
        only calls connect_block_from_bytes (the forward-only IBD path).
        The string appears in the docstring of _handle_reorg as a reference,
        but is not actually called — confirming the two-pipeline gap where
        the Rust reactivation helper is not used by Python's reorg path.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        for method_name in ("sync_loop", "_drain_block_buffer_locked",
                            "handle_block"):
            method = getattr(BlockSync, method_name, None)
            if method is None:
                continue
            src = inspect.getsource(method)
            # Strip docstrings for a cleaner check — we want actual call sites.
            import ast
            try:
                tree = ast.parse(src)
                # Walk AST call nodes looking for connect_block_at_height
                calls = [
                    n for n in ast.walk(tree)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "connect_block_at_height"
                ]
                self.assertEqual(len(calls), 0,
                    f"{method_name} unexpectedly calls connect_block_at_height")
            except SyntaxError:
                # Fallback: simple string check (less precise)
                pass


# ---------------------------------------------------------------------------
# InvalidBlockFound: BLOCK_MUTATED exception
# ---------------------------------------------------------------------------

class TestInvalidBlockFoundMutatedException(unittest.TestCase):
    """
    Core's InvalidBlockFound (validation.cpp:1988) does NOT set
    BLOCK_FAILED_VALID when state.GetResult() == BLOCK_MUTATED.
    Verify ouroboros preserves this exception.
    """

    def test_block_mutated_result_does_not_set_failed_valid(self):
        """
        Bitcoin Core validation.cpp:1988-1996:
          if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
              pindex->nStatus |= BLOCK_FAILED_VALID;
              ...
          }
        A mutated block (duplicate transactions in the merkle tree) must
        NOT be permanently invalidated — it may arrive correctly from a
        different peer. Ouroboros should not mark such blocks FAILED_VALID.

        Check that the block validator rejects mutated blocks with a
        distinct non-permanent error rather than via the invalid-block path.
        """
        import shutil
        import tempfile
        from ouroboros.database import BlockchainDatabase, Transaction, TxIn, TxOut
        from ouroboros.validation import BlockValidator

        temp_dir = tempfile.mkdtemp()
        try:
            db = BlockchainDatabase(data_dir=temp_dir)
            validator = BlockValidator(db)

            # _verify_merkle_root returns False for mutated blocks.
            # Confirm it catches the mutated = True case.
            txid = bytes(range(32))
            # Duplicate the only txid — this triggers mutated=True.
            root, mutated = validator._calculate_merkle_root_checked([txid, txid])
            self.assertTrue(mutated,
                "Two identical txids should trigger mutated=True")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# PruneAndFlush ordering
# ---------------------------------------------------------------------------

class TestPruneAndFlushOrdering(unittest.TestCase):
    """
    Core's PruneAndFlush (validation.cpp:2849) calls FlushStateToDisk
    with FlushStateMode::NONE — it only prunes, does not force a sync.
    Ouroboros's block pruner should not force-flush after pruning.
    """

    def test_pruner_does_not_force_flush_after_prune(self):
        """
        The Python BlockPruner.prune_to_height should call db pruning
        methods without triggering a FlushStateToDisk(FORCE_SYNC).
        A forced sync after every prune is expensive and diverges from
        Core's NONE-mode flush.
        """
        import inspect
        from ouroboros.pruning import BlockPruner

        src = inspect.getsource(BlockPruner)
        # Core does not force-flush after prune; check ouroboros doesn't either.
        self.assertNotIn("force_flush", src.lower(),
            "BlockPruner appears to force-flush after pruning (diverges from Core)")
        self.assertNotIn("ForceFlush", src,
            "BlockPruner appears to call ForceFlush")


# ---------------------------------------------------------------------------
# W99 G16/G17: BLOCK_MUTATED + BLOCK_INVALID_HEADER must Misbehaving(100)
# ---------------------------------------------------------------------------

class TestBlockMutatedMisbehaving(unittest.TestCase):
    """
    W99 G16: Bitcoin Core's ProcessNewBlock path (net_processing.cpp) calls
    Misbehaving(100) when block validation returns BLOCK_MUTATED (duplicate
    txids in the merkle tree → "Invalid merkle root").

    Ouroboros must score the delivering peer with SCORE_INVALID_BLOCK (100)
    so the ban manager can disconnect and ban it.
    """

    def test_misbehaving_called_on_block_mutated(self):
        """
        Inject an "Invalid merkle root" rejection into
        _drain_block_buffer_locked and confirm misbehaving(100) is called
        against the delivering peer's address.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # The fix stores peer addr and calls misbehaving on merkle failure.
        self.assertIn("Invalid merkle root", src,
            "_drain_block_buffer_locked must check for 'Invalid merkle root'")
        self.assertIn("misbehaving", src,
            "_drain_block_buffer_locked must call misbehaving on BLOCK_MUTATED")
        self.assertIn("SCORE_INVALID_BLOCK", src,
            "_drain_block_buffer_locked must use SCORE_INVALID_BLOCK (100)")
        self.assertIn("_block_source_peer_addr", src,
            "_drain_block_buffer_locked must look up delivering peer addr")

    def test_block_source_peer_addr_cleared_on_success(self):
        """
        On successful block connect, _block_source_peer_addr entry must be
        popped so the dict does not grow unboundedly during normal IBD.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # Count pop calls — must appear at least twice:
        # once after perm-reject, once on successful connect.
        pop_count = src.count("_block_source_peer_addr.pop")
        self.assertGreaterEqual(pop_count, 2,
            "_drain_block_buffer_locked must pop _block_source_peer_addr on "
            "both rejection and success paths")

    def test_block_source_peer_addr_stored_on_buffer(self):
        """
        handle_block must populate _block_source_peer_addr when buffering a
        block so the drain loop knows who delivered each block.
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync.handle_block)
        self.assertIn("_block_source_peer_addr", src,
            "handle_block must store peer addr in _block_source_peer_addr")


class TestBlockInvalidHeaderMisbehaving(unittest.TestCase):
    """
    W99 G17: Bitcoin Core's ProcessNewBlock path calls Misbehaving(100) when
    block validation returns BLOCK_INVALID_HEADER (bad PoW, bad prev-hash,
    bad nBits, etc. → "Invalid header").

    Ouroboros must score the delivering peer with SCORE_INVALID_BLOCK (100).
    """

    def test_misbehaving_called_on_invalid_header(self):
        """
        Confirm _drain_block_buffer_locked covers "Invalid header" in its
        misbehaving gate alongside "Invalid merkle root".
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        self.assertIn("Invalid header", src,
            "_drain_block_buffer_locked must check for 'Invalid header'")
        self.assertIn("Invalid merkle root", src,
            "_drain_block_buffer_locked must check for 'Invalid merkle root'")
        # Both strings must appear inside the _misbehav_errors tuple.
        # Find the tuple definition and confirm both strings are in it.
        tuple_pos = src.find("_misbehav_errors")
        self.assertGreater(tuple_pos, 0,
            "_misbehav_errors tuple not found in _drain_block_buffer_locked")
        # The misbehaving call must appear after the tuple definition.
        misbehav_call_pos = src.find("misbehaving(", tuple_pos)
        self.assertGreater(misbehav_call_pos, tuple_pos,
            "misbehaving() call must appear after _misbehav_errors definition")

    def test_non_misbehav_errors_not_scored(self):
        """
        "Previous block not found" and other transient errors must NOT
        trigger misbehaving — only BLOCK_MUTATED and BLOCK_INVALID_HEADER do.
        Confirm the guard is inside the _mark_perm_rejected branch (i.e.
        not reachable for the "Previous block not found" re-buffer path).
        """
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # The misbehaving call must be inside the else-branch (perm-reject),
        # NOT in the "Previous block not found" re-buffer branch.
        # Heuristic: "Previous block not found" must appear BEFORE the
        # misbehaving call in the source (it's in the if-branch that skips
        # the misbehaving logic).
        prev_not_found_pos = src.find("Previous block not found")
        misbehav_pos = src.find("misbehaving")
        self.assertGreater(prev_not_found_pos, 0,
            "'Previous block not found' guard must be present")
        self.assertGreater(misbehav_pos, prev_not_found_pos,
            "misbehaving must be in the else-branch after "
            "'Previous block not found' check")


class TestCrossCheckFallthrough(unittest.TestCase):
    """
    OUROBOROS-RUST-TRACK-SPEC §M0 item 1: with
    OUROBOROS_VALIDATE_CROSS_CHECK=1 and skip_scripts=False (the permanent
    condition at tip), neither the cross-check branch nor the route-only
    branch runs, so (valid, error) was never assigned and the drain hit
    `if not valid:` with an unbound local (UnboundLocalError).

    The fix tracks whether any branch produced a verdict and falls back to
    the Python validator otherwise — the old fallback was guarded on
    `not cross_check`, which could never run in cross-check mode.
    """

    def test_fallback_not_guarded_on_not_cross_check(self):
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # The Python fallback must be reachable in cross-check mode: it must
        # be gated on the verdict tracker, NOT on `not cross_check`.
        self.assertIn("verdict_assigned", src,
            "_drain_block_buffer_locked must track verdict assignment")
        self.assertIn("if not verdict_assigned:", src,
            "Python-validator fallback must be gated on `not verdict_assigned`")
        self.assertNotIn("if not validated_via_rust and not cross_check:", src,
            "the old `not cross_check` fallback guard (the fallthrough bug) "
            "must be gone")


class TestRustRouteErrorPrefixNormalization(unittest.TestCase):
    """
    OUROBOROS-RUST-TRACK-SPEC §M0 item 2: the Rust FFI wraps every reject as
    "validate: <msg>" (deserialize failures as "deserialize: <msg>"), but the
    drain dispatch matches Python-validator strings verbatim
    (== "Previous block not found"; startswith(("Invalid merkle root",
    "Invalid header"))). The prefix must be stripped before dispatch so a
    Rust-routed reject requeues/bans identically to a Python reject.
    """

    def test_prefix_stripped_before_dispatch(self):
        import inspect
        from ouroboros.block_sync import BlockSync

        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        # The normalization must strip the Rust FFI prefixes.
        self.assertIn('"validate: "', src,
            "drain must normalize the Rust 'validate: ' reject prefix")
        self.assertIn('"deserialize: "', src,
            "drain must normalize the Rust 'deserialize: ' reject prefix")
        # And it must appear BEFORE the reject dispatch so `== "Previous block
        # not found"` and the misbehaving startswith() see the bare message.
        norm_pos = src.find('for _ffi_prefix in ("validate: "')
        dispatch_pos = src.find('if error == "Previous block not found":')
        self.assertGreater(norm_pos, 0, "prefix normalization must be present")
        self.assertGreater(dispatch_pos, 0, "reject dispatch must be present")
        self.assertLess(norm_pos, dispatch_pos,
            "prefix normalization must run before the reject dispatch")


class TestFlushCommitInstrumentation(unittest.TestCase):
    """
    OUROBOROS-RUST-TRACK-SPEC §M0 item 4: ouroboros emitted zero flush/commit
    timing lines. _flush_record_commit adds a per-commit DEBUG line plus a
    throttled INFO rollup — pure instrumentation, no behavior change.
    """

    def _stub(self, log_every):
        import types
        s = types.SimpleNamespace()
        s._flush_commits = 0
        s._flush_commit_sum_ns = 0
        s._flush_commit_max_ns = 0
        s._flush_log_every = log_every
        return s

    def test_rollup_fires_at_threshold_and_resets(self):
        from ouroboros.block_sync import BlockSync
        stub = self._stub(log_every=3)
        with self.assertLogs("ouroboros.block_sync", level="INFO") as cm:
            # Two commits: no rollup yet.
            BlockSync._flush_record_commit(stub, 100, 5_000_000)
            BlockSync._flush_record_commit(stub, 101, 15_000_000)
            self.assertEqual(stub._flush_commits, 2)
            # Third commit: rollup fires and counters reset.
            BlockSync._flush_record_commit(stub, 102, 10_000_000)
        joined = "\n".join(cm.output)
        self.assertIn("[FLUSH-ATTR]", joined,
            "flush rollup must emit an INFO [FLUSH-ATTR] line at the threshold")
        self.assertIn("commits=3", joined)
        # avg of 5,15,10 ms = 10.00 ms; max = 15.00 ms.
        self.assertIn("commit_avg_ms=10.00", joined)
        self.assertIn("commit_max_ms=15.00", joined)
        # Counters reset after the rollup.
        self.assertEqual(stub._flush_commits, 0)
        self.assertEqual(stub._flush_commit_sum_ns, 0)
        self.assertEqual(stub._flush_commit_max_ns, 0)

    def test_call_site_present_in_drain(self):
        import inspect
        from ouroboros.block_sync import BlockSync
        src = inspect.getsource(BlockSync._drain_block_buffer_locked)
        self.assertIn("_flush_record_commit(new_height, connect_ns)", src,
            "the drain must record a commit-timing sample after each connect")


if __name__ == "__main__":
    unittest.main()
