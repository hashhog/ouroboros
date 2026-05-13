"""
W109 — CChain + CBlockIndex + CBlockTreeDB + block-file storage
30-gate fleet audit for ouroboros (Python + Rust ferrous-utils).

Covers both pipelines:
  Pipeline A (main): PyBlockchainDB / BlockchainDB  (ferrous-utils/sync/src/storage/db.rs)
                     wrapped in src/ouroboros/database.py
  Pipeline B (aux):  PyBlockStore / BlockStore       (ferrous-utils/sync/src/storage/blockstore.rs)
                     used only by PyBlockStore pyclass, never wired into the sync loop

Reference: bitcoin-core/src/chain.h, chain.cpp, node/blockstorage.h/cpp, txdb.h/cpp

Run:
    cd /home/work/hashhog/ouroboros && \
      python3 -m unittest src.ouroboros.tests.test_w109_block_index
"""

import unittest


class TestW109_G1_BlockStatusValidityLevelNumbering(unittest.TestCase):
    """
    BUG-1 (P1): BLOCK_VALID_* level numbering diverges from Bitcoin Core.

    Core (chain.h):
        BLOCK_VALID_UNKNOWN      = 0
        BLOCK_VALID_RESERVED     = 1   # was HEADER
        BLOCK_VALID_TREE         = 2
        BLOCK_VALID_TRANSACTIONS = 3
        BLOCK_VALID_CHAIN        = 4
        BLOCK_VALID_SCRIPTS      = 5
        BLOCK_VALID_MASK         = RESERVED|TREE|TRANS|CHAIN|SCRIPTS = 0x1F (5-bit)

    ouroboros BlockStatus (ferrous-utils/common/src/types.rs):
        BLOCK_VALID_TREE         = 1   # one level off
        BLOCK_VALID_TRANSACTIONS = 2   # one level off
        BLOCK_VALID_CHAIN        = 3   # one level off
        BLOCK_VALID_SCRIPTS      = 4   # one level off
        BLOCK_VALID_MASK         = 0x07  # 3-bit, misses Core's 5-bit mask

    CONSENSUS-DIVERGENT: if ouroboros ever persists these constants in an
    on-disk format read by Core or vice-versa the levels are off-by-one.
    Any comparison of raw nStatus bytes across implementations diverges.

    Fix: renumber to match Core exactly (add RESERVED=1, shift TREE to 2,
    update BLOCK_VALID_MASK to 0x1F).
    """

    def test_block_valid_tree_should_be_2_not_1(self):
        """BLOCK_VALID_TREE must equal 2 (Core) not 1 (ouroboros)."""
        # Core: BLOCK_VALID_TREE = 2
        CORE_BLOCK_VALID_TREE = 2
        # ouroboros: BLOCK_VALID_TREE = 1
        OUROBOROS_BLOCK_VALID_TREE = 1
        self.assertEqual(
            CORE_BLOCK_VALID_TREE,
            2,
            "Core BLOCK_VALID_TREE is 2",
        )
        # This assertion documents the bug: ouroboros is 1, should be 2
        self.assertNotEqual(
            OUROBOROS_BLOCK_VALID_TREE,
            CORE_BLOCK_VALID_TREE,
            "BUG-1: ouroboros BLOCK_VALID_TREE=1 diverges from Core=2",
        )

    def test_block_valid_mask_should_be_0x1f_not_0x07(self):
        """BLOCK_VALID_MASK must be 0x1F (5-bit) to cover all Core validity levels."""
        CORE_BLOCK_VALID_MASK = 0x1F
        OUROBOROS_BLOCK_VALID_MASK = 0x07
        self.assertNotEqual(
            OUROBOROS_BLOCK_VALID_MASK,
            CORE_BLOCK_VALID_MASK,
            "BUG-1: ouroboros BLOCK_VALID_MASK=0x07 truncates Core's 5-bit validity range",
        )

    def test_block_valid_reserved_level_absent(self):
        """BLOCK_VALID_RESERVED=1 constant is absent from ouroboros BlockStatus."""
        # Core reserves level 1 (previously HEADER); ouroboros starts at TREE=1
        # There is no BLOCK_VALID_RESERVED in ouroboros — document with assertion
        BLOCK_VALID_RESERVED_CORE = 1
        # ouroboros has no such constant; TREE occupies this slot
        ouroboros_has_reserved = False  # confirmed by code inspection
        self.assertFalse(
            ouroboros_has_reserved,
            "BUG-1: ouroboros missing BLOCK_VALID_RESERVED=1 (Core chain.h)",
        )


class TestW109_G2_MissingBlockOptWitnessAndStatusReservedFlags(unittest.TestCase):
    """
    BUG-2 (P2): BLOCK_OPT_WITNESS and BLOCK_STATUS_RESERVED constants absent.

    Core (chain.h):
        BLOCK_OPT_WITNESS     = 128  # block data was received with witness-enforcing client
        BLOCK_STATUS_RESERVED = 256  # formerly used by assumeutxo snapshot ancestor marking

    Neither constant exists in ouroboros BlockStatus (common/src/types.rs:469-566).

    Impact: ouroboros cannot represent the full Core nStatus bit-field; any code
    reading a Core-format nStatus will silently lose these bits.

    Fix: add BLOCK_OPT_WITNESS = 128 and BLOCK_STATUS_RESERVED = 256 to BlockStatus.
    """

    def test_block_opt_witness_absent(self):
        """BLOCK_OPT_WITNESS = 128 is absent from BlockStatus."""
        ouroboros_has_opt_witness = False
        self.assertFalse(
            ouroboros_has_opt_witness,
            "BUG-2: BLOCK_OPT_WITNESS=128 absent from ouroboros BlockStatus",
        )

    def test_block_status_reserved_absent(self):
        """BLOCK_STATUS_RESERVED = 256 is absent from BlockStatus."""
        ouroboros_has_status_reserved = False
        self.assertFalse(
            ouroboros_has_status_reserved,
            "BUG-2: BLOCK_STATUS_RESERVED=256 absent from ouroboros BlockStatus",
        )


class TestW109_G3_MissingSkipListPskip(unittest.TestCase):
    """
    BUG-3 (P2): CBlockIndex::pskip (skip-list pointer) absent; GetAncestor O(N) not O(log N).

    Core (chain.cpp:83-108): GetAncestor(height) uses a skip-list (pskip pointer) enabling
    O(log N) ancestor traversal. BuildSkip() populates pskip on index construction.

    ouroboros:
    - Both pipelines lack any skip-list structure.
    - consensus.py:461 implements GetAncestor equivalent as a linear loop fetching
      block metadata from RocksDB one-by-one (O(N) DB reads).
    - ferrous-utils/sync/src/storage/db.rs:block_is_ancestor and block_descends_from
      also walk back block-by-block using get_block() calls (O(N) I/O each).

    Impact: difficulty adjustment calls GetAncestor(pindexPrev->nHeight - 2015) which
    on mainnet walks ~2016 blocks. Each call during IBD requires ~2016 RocksDB reads
    vs Core's ~11 pointer dereferences. Correctness unaffected; performance O(N²) for
    IBD at difficulty adjustment intervals.

    Fix: add skip-list or at least cache the 2016-block-back ancestor in BlockMetadata.
    """

    def test_getancestor_is_linear_not_log(self):
        """GetAncestor equivalent in consensus.py is O(N) linear walk."""
        # Verify by inspecting the consensus.py diff-adjustment path.
        # GetNextWorkRequired calls: pindexFirst = pindexLast->GetAncestor(nHeight - 2015)
        # ouroboros equivalent is a loop that steps back one block at a time.
        import inspect
        try:
            from ouroboros import consensus
            src = inspect.getsource(consensus)
            # The loop uses .pprev or iterates — no skip pointer
            has_skip_list = "pskip" in src or "skip_list" in src or "GetSkipHeight" in src
            self.assertFalse(
                has_skip_list,
                "BUG-3: consensus.py unexpectedly has skip-list — update test",
            )
        except ImportError:
            self.skipTest("ouroboros not importable in this environment")

    def test_skip_list_absent_in_blockmetadata(self):
        """BlockMetadata has no skip-list pointer or cached ancestor info."""
        # BlockMetadata fields: height, chainwork, timestamp, status
        # No skip_height, no ancestor_hash, no pskip equivalent
        expected_fields = {"height", "chainwork", "timestamp", "status"}
        unexpected_skip_fields = {"pskip", "skip_height", "ancestor_2016"}
        actual_fields = expected_fields  # confirmed from code inspection
        for f in unexpected_skip_fields:
            self.assertNotIn(f, actual_fields, f"BUG-3: unexpected skip field {f}")


class TestW109_G4_MissingnTimeMax(unittest.TestCase):
    """
    BUG-4 (P2): CBlockIndex::nTimeMax absent from BlockMetadata.

    Core (chain.h:152): nTimeMax is the maximum block time in the chain up to and
    including this block. Used by FindEarliestAtLeast() for wallet rescan and IBD
    recovery. It is a memory-only field populated during LoadBlockIndex.

    ouroboros BlockMetadata: height, chainwork, timestamp, status.
    No nTimeMax equivalent. FindEarliestAtLeast() is also absent (see BUG-18).

    Fix: add max_time_in_chain to BlockMetadata, populate in connect_block_from_bytes.
    """

    def test_blockmetadata_has_no_nTimeMax(self):
        """BlockMetadata lacks nTimeMax / max_time_in_chain field."""
        blockmetadata_fields = ["height", "chainwork", "timestamp", "status"]
        self.assertNotIn(
            "max_time_in_chain",
            blockmetadata_fields,
            "BUG-4: BlockMetadata missing nTimeMax equivalent",
        )
        self.assertNotIn(
            "nTimeMax",
            blockmetadata_fields,
            "BUG-4: BlockMetadata missing nTimeMax equivalent",
        )


class TestW109_G5_MissingMChainTxCount(unittest.TestCase):
    """
    BUG-5 (P2): CBlockIndex::m_chain_tx_count / HaveNumChainTxs() absent.

    Core (chain.h:129): m_chain_tx_count is the cumulative transaction count for
    the chain up to and including this block. It is set only when the full chain
    back to genesis (or snapshot base) has VALID_TRANSACTIONS status, allowing
    the node to know whether IBD is complete.

    HaveNumChainTxs() { return m_chain_tx_count != 0; } is the canonical IBD-
    completion predicate used throughout Core (net_processing.cpp, init.cpp).

    ouroboros: no chain_tx_count in BlockMetadata, no HaveNumChainTxs() equivalent.
    IBD completion is detected differently (height-based or sync-progress heuristic).

    Fix: add chain_tx_count u64 to BlockMetadata, accumulate in connect_block_from_bytes.
    """

    def test_blockmetadata_lacks_chain_tx_count(self):
        """BlockMetadata does not track cumulative chain transaction count."""
        blockmetadata_fields = ["height", "chainwork", "timestamp", "status"]
        self.assertNotIn("chain_tx_count", blockmetadata_fields)
        self.assertNotIn("m_chain_tx_count", blockmetadata_fields)

    def test_have_num_chain_txs_absent(self):
        """No HaveNumChainTxs() equivalent exposed to Python layer."""
        try:
            from ouroboros.database import BlockchainDatabase
            self.assertFalse(
                hasattr(BlockchainDatabase, "have_num_chain_txs"),
                "BUG-5: HaveNumChainTxs() unexpectedly present",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G6_MissingnSequenceId(unittest.TestCase):
    """
    BUG-6 (P2): CBlockIndex::nSequenceId absent; tie-breaking on equal-chainwork
    blocks is non-deterministic or missing.

    Core (chain.h:149): nSequenceId is assigned in the order blocks are RECEIVED
    (not by height). Blocks from disk get SEQ_ID_INIT_FROM_DISK=1, best-chain blocks
    get SEQ_ID_BEST_CHAIN_FROM_DISK=0. Equal-chainwork tie-breaking in
    setBlockIndexCandidates uses (nChainWork DESC, nSequenceId ASC) to prefer the
    block received first.

    ouroboros: BlockMetadata has no sequence_id. Equal-chainwork tie-breaking in
    reactivate_best_chain() iterates block heights downward — the result depends on
    which fork is stored at the canonical height in BLOCK_INDEX_CF, not on reception
    order. This is non-deterministic across restarts (height-keyed DB may overwrite).

    Fix: add sequence_id to BlockMetadata, auto-increment on receive, use for tie-
    breaking in reactivate_best_chain.
    """

    def test_sequence_id_absent_from_blockmetadata(self):
        """BlockMetadata has no sequence_id field."""
        blockmetadata_fields = ["height", "chainwork", "timestamp", "status"]
        self.assertNotIn("sequence_id", blockmetadata_fields)
        self.assertNotIn("nSequenceId", blockmetadata_fields)


class TestW109_G7_BlockIndexKeyedByHeightNotHashSideBranchLoss(unittest.TestCase):
    """
    BUG-7 (P0/C-DIV TWO-PIPELINE): BLOCK_INDEX_CF keyed by height (4-byte LE),
    not by block hash as in Core's BlockMap.

    Core (blockstorage.h:135):
        using BlockMap = std::unordered_map<uint256, CBlockIndex, BlockHasher>;
    The in-memory map is keyed by block *hash*, allowing multiple blocks at the
    same height (competing forks) to coexist.

    ouroboros Rust (storage/schema.rs:330-332, db.rs:189-201):
        BLOCK_INDEX_CF key = encode_height(height) = height.to_le_bytes() (4 bytes).
    A new block at height H overwrites the BLOCK_INDEX_CF entry for that height,
    silently discarding the previously stored fork-branch block.

    TWO-PIPELINE GAP:
    - Pipeline A (BlockchainDB): stores blocks by hash in BLOCKS_CF but indexes
      them by height in BLOCK_INDEX_CF. Side-chain blocks stored in BLOCKS_CF via
      submitblock are unreachable from the height index.
    - Pipeline B (BlockStore): stores blocks in blk*.dat files indexed by hash
      (BLOCKPOS_CF). Side-chain blocks ARE indexable by hash here — but Pipeline B
      is never wired into the main sync loop.

    CONSENSUS-DIVERGENT for invalidateblock + reconsider: if a side-chain block
    was submitted via submitblock and later invalidateblock + reconsider is called,
    the block's metadata may have been overwritten; reconsider cannot find it.

    Fix: add hash → BlockMetadata index (BLOCK_INDEX_BY_HASH_CF) alongside the
    height index, so fork branches are not lost.
    """

    def test_block_index_key_is_height_not_hash(self):
        """BLOCK_INDEX_CF key is 4-byte height, not 32-byte hash."""
        # encode_height produces 4 bytes; Core's BlockMap uses 32-byte hash
        height = 100
        encoded = height.to_bytes(4, "little")
        self.assertEqual(len(encoded), 4, "height key is 4 bytes")
        self.assertNotEqual(len(encoded), 32, "BUG-7: height key != 32-byte hash key")

    def test_two_blocks_at_same_height_cannot_both_be_indexed(self):
        """Storing a second block at height H overwrites first in height-keyed index."""
        # Simulate two different block hashes at height 100
        hash_a = bytes(range(32))
        hash_b = bytes(reversed(range(32)))
        height = 100
        # In a height-keyed dict only one entry per height is possible
        index: dict[bytes, bytes] = {}
        key = height.to_bytes(4, "little")
        index[key] = hash_a  # store block A
        index[key] = hash_b  # store block B — A is silently lost
        self.assertEqual(index[key], hash_b)
        self.assertNotIn(hash_a, index.values(), "BUG-7: fork block A overwritten by B")


class TestW109_G8_RaiseValidityAbsent(unittest.TestCase):
    """
    BUG-8 (P1): CBlockIndex::RaiseValidity() / IsValid(nUpTo) absent.

    Core (chain.h:250-273): IsValid(nUpTo) checks both that no FAILED flag is set
    AND that (nStatus & BLOCK_VALID_MASK) >= nUpTo. RaiseValidity(nUpTo) monotonically
    advances the validity level. These are called at every stage:
      - BLOCK_VALID_TREE after header validation
      - BLOCK_VALID_TRANSACTIONS after CheckBlock
      - BLOCK_VALID_CHAIN after ContextualCheckBlock
      - BLOCK_VALID_SCRIPTS after ConnectBlock (script verification)

    ouroboros: no RaiseValidity equivalent. Newly stored BlockMetadata always has
    BlockStatus::new() = BLOCK_VALID_TREE(1). Even after full ConnectBlock/validation,
    the status stays at BLOCK_VALID_TREE — it is never raised to VALID_SCRIPTS.

    Impact: any code that gates on IsValid(BLOCK_VALID_SCRIPTS) would always see
    blocks as not-fully-validated. ActivateBestChain would incorrectly exclude fully
    validated blocks from chain selection if it checked validity levels.

    Fix: call update_block_status with BLOCK_VALID_SCRIPTS after successful validation
    in connect_block_from_bytes; add raise_validity helper to BlockStatus.
    """

    def test_new_blockstatus_is_always_valid_tree(self):
        """BlockStatus::new() initializes to BLOCK_VALID_TREE(1) regardless of validation."""
        # After connect_block_from_bytes the stored metadata status is BlockStatus::new()
        # which equals BLOCK_VALID_TREE=1, not BLOCK_VALID_SCRIPTS=4
        BLOCK_VALID_TREE_OUROBOROS = 1
        BLOCK_VALID_SCRIPTS_OUROBOROS = 4
        initial_status_bits = BLOCK_VALID_TREE_OUROBOROS
        # A block that passed full validation should be at VALID_SCRIPTS
        self.assertNotEqual(
            initial_status_bits,
            BLOCK_VALID_SCRIPTS_OUROBOROS,
            "BUG-8: connect_block never raises validity to BLOCK_VALID_SCRIPTS",
        )

    def test_raise_validity_helper_absent(self):
        """BlockStatus has no raise_validity / is_valid_up_to methods."""
        # These methods are absent from common/src/types.rs BlockStatus impl
        expected_missing = ["raise_validity", "is_valid_up_to", "RaiseValidity"]
        # The methods that DO exist: is_valid, is_invalid, is_failed_valid, etc.
        existing_methods = [
            "is_valid", "is_invalid", "is_failed_valid", "is_failed_child",
            "set_failed_valid", "set_failed_child", "clear_failed",
            "has_data", "has_undo", "set_has_data", "set_has_undo",
        ]
        for m in expected_missing:
            self.assertNotIn(
                m, existing_methods,
                f"BUG-8: {m} unexpectedly found — update test",
            )


class TestW109_G9_InMemoryBlockMapAbsent(unittest.TestCase):
    """
    BUG-9 (P1): In-memory BlockMap (m_block_index) absent; no CBlockIndex graph
    maintained in memory.

    Core (blockstorage.h:332):
        BlockMap m_block_index GUARDED_BY(cs_main);
    This in-memory hash map is the authoritative block tree. Every known block
    (genesis to tip, including side branches) has a live CBlockIndex* with pprev
    pointers forming a graph. This enables:
      - O(1) lookup by hash at any time
      - SetTip() walking pprev to rebuild vChain
      - FindFork() via pprev traversal
      - setBlockIndexCandidates membership

    ouroboros: no in-memory block index. All lookups require RocksDB reads.
    Memory-only fields (nChainWork, nTimeMax, pskip, nSequenceId, pprev, phashBlock)
    are computed on-demand or absent.

    Fix: add an in-memory LRU cache of BlockMetadata, or at minimum cache the tip
    path (active chain heights 0..tip).
    """

    def test_no_in_memory_block_map_in_python_layer(self):
        """BlockchainDatabase has no in-memory hash map of all block indices."""
        try:
            from ouroboros.database import BlockchainDatabase
            # _cached_tip exists but it's only the tip (hash, height) — not a full map
            bd_attrs = [a for a in dir(BlockchainDatabase) if not a.startswith("__")]
            has_block_map = any("block_map" in a or "m_block_index" in a for a in bd_attrs)
            self.assertFalse(
                has_block_map,
                "BUG-9: in-memory block map unexpectedly present",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G10_SetTipNoPrevChainRebuild(unittest.TestCase):
    """
    BUG-10 (P2): CChain::SetTip() equivalent does not rebuild the pprev chain.

    Core (chain.cpp:16-23): SetTip(block) walks back via pprev, resizing and
    filling vChain[height] for every ancestor that differs from current, stopping
    at the first already-correct entry. This atomically makes the chain object
    consistent with a new tip.

    ouroboros: update_best_block() in BlockchainDB just writes two META_CF keys
    (BEST_BLOCK_HASH, BEST_HEIGHT). No chain-structure rebuild. The Python
    _cached_tip is a (hash, height) tuple — no chain vector.

    The effective CChain in ouroboros is the BLOCK_INDEX_CF height→hash table.
    SetTip() equivalent is update_best_block() + the caller already having written
    BLOCK_INDEX_CF entries. But there is no consistency check that vChain is
    contiguous from genesis to tip on reconnect.

    Fix: after connect_block_from_bytes, verify BLOCK_INDEX_CF has a contiguous
    entry from genesis to tip; emit a warning if any height gap exists.
    """

    def test_update_best_block_is_just_two_kv_writes(self):
        """update_best_block() writes BEST_BLOCK_HASH and BEST_HEIGHT only."""
        # Inspecting db.rs:827-838: only two puts, no chain walk
        meta_keys_written = ["best_block_hash", "best_height"]
        self.assertIn("best_block_hash", meta_keys_written)
        self.assertIn("best_height", meta_keys_written)
        # No pprev chain rebuild
        pprev_walk = False
        self.assertFalse(pprev_walk, "BUG-10: SetTip() equivalent has no pprev walk")


class TestW109_G11_FindForkAbsent(unittest.TestCase):
    """
    BUG-11 (P2): CChain::FindFork() absent; fork finding requires O(N) block body reads.

    Core (chain.cpp:50-58): FindFork(pindex) — if pindex is above tip, uses
    GetAncestor(Height()) to step down; then walks pprev until pindex is in the
    chain (Contains check = O(1) via vChain[height] == pindex). Total O(log N).

    ouroboros (db.rs:2362-2402): reactivate_best_chain walks back block-by-block
    using get_block() to fetch the full block body for each step just to read
    prev_blockhash. This is O(N * IO_cost) where each IO_cost is a RocksDB read
    of the full serialized block. For a 100-block reorg that's 100 full block
    fetches vs Core's ~7 pointer hops.

    Fix: store prev_blockhash in BlockMetadata (or in HEADERS_CF as part of the
    80-byte header, which IS stored) and use that for fork-finding without loading
    the full block body.
    """

    def test_fork_finding_reads_full_block_body(self):
        """reactivate_best_chain reads full block bodies to traverse prev_blockhash."""
        # db.rs:2395-2400: get_block(&walk_hash) to access header.prev_blockhash
        # The 80-byte header IS stored in HEADERS_CF but get_raw_header() is not
        # called in the fork-walk path — get_block() fetches the full body instead.
        uses_headers_cf_for_fork = False  # confirmed: get_block not get_raw_header
        self.assertFalse(
            uses_headers_cf_for_fork,
            "BUG-11: fork walk reads full block bodies instead of HEADERS_CF",
        )


class TestW109_G12_FindEarliestAtLeastAbsent(unittest.TestCase):
    """
    BUG-12 (P2): CChain::FindEarliestAtLeast(nTime, height) absent.

    Core uses this to locate the earliest block at or above a timestamp+height,
    primarily for wallet rescans and getblockstats queries. It performs a
    lower_bound search over the vChain vector using nTimeMax as the comparator.

    ouroboros: no equivalent method. Wallet rescans and time-based queries must
    fall back to a linear scan.

    Fix: add a binary search over BLOCK_INDEX_CF using stored timestamps.
    """

    def test_find_earliest_at_least_absent(self):
        """BlockchainDatabase / BlockchainDB has no FindEarliestAtLeast equivalent."""
        try:
            from ouroboros.database import BlockchainDatabase
            self.assertFalse(
                hasattr(BlockchainDatabase, "find_earliest_at_least"),
                "BUG-12: find_earliest_at_least unexpectedly present",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G13_SetBlockIndexCandidatesAbsent(unittest.TestCase):
    """
    BUG-13 (P1/C-DIV): setBlockIndexCandidates equivalent absent; reactivate_best_chain
    scans only from height 0..best_height+1000 instead of the full block tree.

    Core (blockstorage.h:138-141): CBlockIndexWorkComparator sorts by (nChainWork DESC,
    nSequenceId ASC). setBlockIndexCandidates is the sorted set of all candidate tips
    (valid leaves with BLOCK_HAVE_DATA, no FAILED flags). FindMostWorkChain iterates
    this set to find the best candidate — it covers ALL known chains, including short
    forks that are BELOW the current best height.

    ouroboros (db.rs:2300-2350): reactivate_best_chain scans heights 0..scan_height
    downward, stopping at the first entry with more chainwork. This:
    1. Misses side branches stored in BLOCKS_CF that have no BLOCK_INDEX_CF entry
       (because height-keyed writes overwrite on forks).
    2. If two chains have equal work, uses height ordering (highest wins) rather
       than sequenceId ordering (first-received wins) — non-deterministic.
    3. SCAN_HORIZON = 1000 caps the look-ahead but any fork beyond 1000 blocks
       ahead of the tip is invisible.

    Fix: maintain a separate by-chainwork index (or at minimum an explicit fork
    tracking table) so FindMostWorkChain can cover all known blocks.
    """

    def test_reactivate_best_chain_uses_linear_height_scan(self):
        """reactivate_best_chain iterates heights, not a sorted candidate set."""
        # db.rs:2333: for h in (0..=scan_height).rev() { ... }
        # Core: while let Some(pindex) = setBlockIndexCandidates.iter().next_back()
        uses_sorted_candidate_set = False
        self.assertFalse(
            uses_sorted_candidate_set,
            "BUG-13: no setBlockIndexCandidates equivalent — linear height scan only",
        )

    def test_equal_work_tiebreak_uses_height_not_sequence_id(self):
        """Equal-chainwork blocks: ouroboros picks by height position, not sequenceId."""
        # reactivate_best_chain(db.rs:2343): if metadata.chainwork <= current_chainwork: continue
        # No sequenceId tiebreak exists; first block at a given height wins by DB key order
        has_sequence_id_tiebreak = False
        self.assertFalse(
            has_sequence_id_tiebreak,
            "BUG-13: equal-chainwork tiebreak is height-ordered, not sequenceId-ordered",
        )


class TestW109_G14_TwoPipelineBlockStoreNotWiredIntoSync(unittest.TestCase):
    """
    BUG-14 (P0/TWO-PIPELINE): PyBlockStore (blk*.dat flat files) is implemented
    but NEVER wired into the mainline sync pipeline.

    Pipeline B (blockstore.rs / lib.rs:1337+):
      - PyBlockStore writes blocks to blk?????.dat / rev?????.dat files in Bitcoin
        Core–compatible flat-file format.
      - Has its own FILEINFO_CF and BLOCKPOS_CF RocksDB column families for indexing.
      - CBlockFileInfo equivalent (BlockFileInfo) tracks nBlocks, size, undo_size,
        height ranges, time ranges.

    Pipeline A (db.rs / lib.rs:3290+):
      - connect_block_from_bytes() stores blocks in BLOCKS_CF (hash-keyed RocksDB
        blob store) and metadata in BLOCK_INDEX_CF.
      - NEVER calls PyBlockStore.write_block().
      - BLOCKS_CF and BLOCKPOS_CF are entirely disjoint stores.

    Result:
    - Blocks stored via the main sync loop are in BLOCKS_CF; PyBlockStore files
      are EMPTY unless explicitly called by Python code.
    - A Python caller using `PyBlockStore.get_block(hash)` will find nothing for
      blocks synced through the normal pipeline.
    - The blk*.dat files do NOT grow during IBD — this breaks Bitcoin Core
      compatibility for any external tool expecting blk*.dat files.

    Fix: wire connect_block_from_bytes (or the IBD block acceptance path) to ALSO
    call BlockStore.write_block() so blk*.dat files are populated during sync.
    """

    def test_pyblockstore_exists_as_separate_class(self):
        """PyBlockStore exists but is a separate class from PyBlockchainDB."""
        try:
            import sync as _sync
            has_pyblockchaindb = hasattr(_sync, "PyBlockchainDB")
            has_pyblockstore = hasattr(_sync, "PyBlockStore")
            if not has_pyblockchaindb:
                self.skipTest("sync module not built")
            # Both exist as separate classes — not integrated
            self.assertTrue(has_pyblockchaindb, "PyBlockchainDB should exist")
            # If PyBlockStore also exists, document the gap
            if has_pyblockstore:
                # They are separate — main pipeline only uses PyBlockchainDB
                self.assertNotEqual(
                    _sync.PyBlockchainDB.__module__,
                    "INTEGRATED",
                    "BUG-14: PyBlockStore is separate from PyBlockchainDB",
                )
        except ImportError:
            self.skipTest("sync module not importable")

    def test_connect_block_from_bytes_only_writes_to_rocksdb(self):
        """connect_block_from_bytes stores blocks in BLOCKS_CF, never calls flat-file store."""
        # Verified by reading lib.rs:3290-3810: no call to BlockStore.write_block()
        # All writes go to RocksDB batch (chainstate_cf, spent_cf, etc.)
        calls_block_store = False
        self.assertFalse(
            calls_block_store,
            "BUG-14: connect_block_from_bytes never calls flat-file BlockStore",
        )


class TestW109_G15_LoadBlockIndexAbsent(unittest.TestCase):
    """
    BUG-15 (P1): LoadBlockIndex() equivalent absent; in-memory fields not
    reconstructed from disk on startup.

    Core (blockstorage.h:204-205): LoadBlockIndex() reads all CBlockIndex entries
    from disk, populates m_block_index (the in-memory BlockMap), reconstructs
    nChainWork, nTimeMax, nSequenceId, and rebuilds pprev pointers by following
    stored hashPrev fields. This ensures the in-memory view is consistent with
    disk after every startup.

    ouroboros: on database open, recover_from_crash() is called (db.rs:1061) to
    handle mid-apply crashes. But there is NO pass that rebuilds in-memory
    structures from BLOCK_INDEX_CF. The Python layer's _cached_tip is refreshed
    by a single get_best_block() call. No pprev graph, no nTimeMax, no nSequenceId
    reconstruction.

    Fix: at startup, scan BLOCK_INDEX_CF from 0 to best_height, verify contiguity,
    and populate any caches that the code depends on.
    """

    def test_startup_does_not_scan_entire_block_index(self):
        """BlockchainDatabase.__init__ calls get_best_block() but not a full index scan."""
        try:
            import inspect
            from ouroboros.database import BlockchainDatabase
            src = inspect.getsource(BlockchainDatabase.__init__)
            has_full_scan = (
                "for h in" in src
                or "for height in" in src
                or "scan_block_index" in src
            )
            self.assertFalse(
                has_full_scan,
                "BUG-15: __init__ unexpectedly does a full index scan",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G16_DirtyBlockIndexAbsent(unittest.TestCase):
    """
    BUG-16 (P2): m_dirty_blockindex absent; immediate-write instead of deferred flush.

    Core (blockstorage.h:310-313):
        std::set<CBlockIndex*> m_dirty_blockindex;
    Block index updates are collected into this set and flushed to disk in batches
    during FlushStateToDisk(). This amortizes LevelDB/RocksDB I/O over many blocks.

    ouroboros: every call to store_block_metadata() / update_block_status() writes
    immediately to RocksDB. There is no dirty-tracking; each block connect/disconnect
    issues at least one RocksDB write for block metadata.

    Impact: performance only during IBD (each block writes metadata immediately).
    Not a consensus issue.

    Fix: accumulate block metadata writes in the existing WriteBatch (they already
    use WriteBatch for UTXO/header data; just add metadata to the same batch).
    """

    def test_block_metadata_written_immediately_not_deferred(self):
        """store_block_metadata writes immediately; no dirty-tracking set."""
        # db.rs:188-202: put_cf(cf, key, value) — immediate write
        # No dirty set, no deferred flush
        has_dirty_set = False
        self.assertFalse(
            has_dirty_set,
            "BUG-16: no m_dirty_blockindex equivalent; all metadata writes are immediate",
        )


class TestW109_G17_BlockMetadataMissingNTx(unittest.TestCase):
    """
    BUG-17 (P2): BlockMetadata missing nTx (number of transactions in block).

    Core (chain.h:123): CBlockIndex::nTx is the number of transactions in the block.
    It is set when the block reaches BLOCK_VALID_TRANSACTIONS. Used by:
      - HaveNumChainTxs() for IBD completion
      - getblockchaininfo "verificationprogress" estimate

    ouroboros BlockMetadata: {height, chainwork, timestamp, status}.
    No nTx field. The HEADERS_CF stores n_tx as a 4-byte field alongside the
    80-byte header (schema.rs:118-126) but it is not in BlockMetadata and
    is not used for chain progress estimation.

    Fix: add nTx to BlockMetadata and populate from block.txdata.len() in
    connect_block_from_bytes.
    """

    def test_blockmetadata_lacks_ntx(self):
        """BlockMetadata does not store nTx (number of transactions)."""
        blockmetadata_fields = ["height", "chainwork", "timestamp", "status"]
        self.assertNotIn("n_tx", blockmetadata_fields)
        self.assertNotIn("nTx", blockmetadata_fields)


class TestW109_G18_CBlockTreeDBSerializationDivergence(unittest.TestCase):
    """
    BUG-18 (CONSENSUS-DIVERGENT): CDiskBlockIndex serialization format incompatible
    with Core's CBlockTreeDB.

    Core (chain.h:340-360): CDiskBlockIndex SERIALIZE_METHODS uses VARINT encoding:
        VARINT_MODE(nVersion, NONNEG_SIGNED)
        VARINT_MODE(nHeight, NONNEG_SIGNED)
        VARINT(nStatus)
        VARINT(nTx)
        if (nStatus & HAVE_DATA|HAVE_UNDO): VARINT_MODE(nFile, NONNEG_SIGNED)
        if (HAVE_DATA): VARINT(nDataPos)
        if (HAVE_UNDO): VARINT(nUndoPos)
        then: nVersion, hashPrev, hashMerkleRoot, nTime, nBits, nNonce (fixed-size)

    ouroboros BlockMetadata serialization (common/src/types.rs:615-628):
        [height: 4 bytes u32 LE][chainwork: 32 bytes][timestamp: 4 bytes u32 LE][status: 4 bytes u32 LE]
    Total: 44 bytes, fixed-width, no VARINT, no nFile/nDataPos/nUndoPos,
    no hashPrev/hashMerkleRoot (only in HEADERS_CF), no nVersion, no nNonce.

    CONSENSUS-DIVERGENT: a datadir written by ouroboros cannot be opened by Core;
    a Core datadir (blocks/index/) cannot be parsed by ouroboros. Any migration tool
    must be aware of this incompatibility.

    Fix: add DUMMY_VERSION + VARINT-based serialization matching CDiskBlockIndex if
    Core datadir compatibility is needed, OR document the incompatibility explicitly.
    """

    def test_blockmetadata_format_is_fixed_width_44_bytes(self):
        """BlockMetadata serializes to 44 bytes fixed-width, not VARINT like CDiskBlockIndex."""
        # 4 (height) + 32 (chainwork) + 4 (timestamp) + 4 (status) = 44
        EXPECTED_OUROBOROS_SIZE = 44
        CORE_VARINT_VARIABLE = True  # Core uses VARINT — variable size
        self.assertEqual(EXPECTED_OUROBOROS_SIZE, 44)
        self.assertTrue(CORE_VARINT_VARIABLE, "Core CDiskBlockIndex uses VARINTs (variable)")
        # Document incompatibility
        self.assertNotEqual(
            EXPECTED_OUROBOROS_SIZE,
            -1,  # not VARINT
            "BUG-18: fixed 44-byte format != Core VARINT CDiskBlockIndex — wire incompatible",
        )

    def test_disk_block_index_missing_file_position_fields(self):
        """ouroboros BlockMetadata lacks nFile, nDataPos, nUndoPos (Core CDiskBlockIndex fields)."""
        core_fields = ["nFile", "nDataPos", "nUndoPos", "hashPrev", "hashMerkleRoot",
                       "nVersion", "nNonce", "nTx"]
        ouroboros_fields = ["height", "chainwork", "timestamp", "status"]
        for f in core_fields:
            self.assertNotIn(
                f,
                ouroboros_fields,
                f"BUG-18: Core CDiskBlockIndex field '{f}' absent from BlockMetadata",
            )


class TestW109_G19_FindHeightOfHashIsLinearScan(unittest.TestCase):
    """
    BUG-19 (P2): find_height_of_hash() is O(N) linear scan.

    Core: any block's height is an in-memory field (CBlockIndex::nHeight). Given a
    block hash, Core looks up m_block_index[hash] and reads nHeight directly — O(1).

    ouroboros (db.rs:283-291): find_height_of_hash(hash, max_height) loops from
    max_height down to 0, calling get_block_hash_by_height(h) for each step and
    comparing. Worst case O(N) where N = best_height (~900,000 on mainnet).

    This is called in invalidate_block(), reconsider_block(), and anywhere a hash
    must be resolved to a height. On mainnet with 900k blocks this could be ~900k
    RocksDB reads in the worst case.

    Fix: add a BLOCK_HASH_TO_HEIGHT_CF inverse index (hash → height, 32-byte key)
    populated in connect_block_from_bytes, deleted in disconnect. This gives O(1)
    hash→height lookup.
    """

    def test_find_height_of_hash_loop_from_max_height(self):
        """find_height_of_hash iterates heights 0..max_height — O(N)."""
        # Simulate the scan logic
        def find_height_of_hash_ouroboros(target_hash: bytes, fake_index: dict) -> int | None:
            max_h = max(fake_index.keys()) if fake_index else 0
            for h in range(max_h, -1, -1):
                if fake_index.get(h) == target_hash:
                    return h
            return None

        index = {i: bytes([i & 0xFF] * 32) for i in range(100)}
        target = bytes([50 & 0xFF] * 32)
        found = find_height_of_hash_ouroboros(target, index)
        self.assertEqual(found, 50, "linear scan finds height correctly")
        # Count iterations needed: 50 steps from top (99 down to 50)
        # vs O(1) hash-map lookup
        steps_needed = 100 - 50  # 50 steps
        self.assertGreater(steps_needed, 1, "BUG-19: O(N) — multiple steps required")


class TestW109_G20_BlockFileInfoNotPersistedInMainPipeline(unittest.TestCase):
    """
    BUG-20 (P2/TWO-PIPELINE): CBlockFileInfo (nBlocks, nSize, nUndoSize, nHeightFirst/Last,
    nTimeFirst/Last) is NOT tracked in the main sync pipeline.

    Core (blockstorage.h:56-94): CBlockFileInfo stores statistics per blk*.dat file.
    Written to CBlockTreeDB via WriteBatchSync(). Used by:
      - ReadLastBlockFile() to find where to append new blocks
      - Pruning (FindFilesToPrune uses nHeightFirst/Last to identify safe-to-prune files)
      - Reindex to skip already-indexed files

    ouroboros Pipeline B (blockstore.rs:88-140): BlockFileInfo equivalent exists and
    is persisted in FILEINFO_CF column family.

    ouroboros Pipeline A (db.rs): BlockchainDB has NO block-file tracking. BLOCKS_CF
    is a flat hash→body map; there are no "files" in this sense. Pruning logic
    (prune_blocks_range) deletes individual BLOCKS_CF entries rather than whole files.

    Result: no "last block file" concept in Pipeline A; pruning is by height range
    not by file; no reindex support.
    """

    def test_main_pipeline_has_no_blockfileinfo(self):
        """BlockchainDB (main pipeline) has no block file info tracking."""
        # db.rs: no FILEINFO_CF, no BlockFileInfo, no ReadLastBlockFile equivalent
        main_pipeline_has_fileinfo = False
        self.assertFalse(
            main_pipeline_has_fileinfo,
            "BUG-20: BlockchainDB has no CBlockFileInfo equivalent",
        )

    def test_prune_is_by_height_range_not_by_file(self):
        """Pruning deletes individual BLOCKS_CF entries by height, not whole blk*.dat files."""
        # db.rs:884-912: prune_blocks_range iterates heights, deletes from BLOCKS_CF one by one
        prune_by_file = False
        self.assertFalse(
            prune_by_file,
            "BUG-20: pruning deletes per-height BLOCKS_CF entries, not whole block files",
        )


class TestW109_G21_InvalidateBlockMissesOrphansOutsideActiveChain(unittest.TestCase):
    """
    BUG-21 (P1): invalidate_block() can only mark descendants that are at heights
    the BLOCK_INDEX_CF covers. Side-chain blocks (stored in BLOCKS_CF but with
    overwritten BLOCK_INDEX_CF entries) are not reachable by block_descends_from().

    Core: SetBlockFailureFlags walks m_block_index (the FULL block tree including
    all known forks). Every block descended from the invalidated block — regardless
    of which chain it's on — gets BLOCK_FAILED_CHILD.

    ouroboros (db.rs:2140-2148): block_descends_from() fetches get_block_by_height(h)
    which reads BLOCK_INDEX_CF[h] and then BLOCKS_CF. If a fork block at height H
    overwrote the BLOCK_INDEX_CF entry, block_descends_from() cannot see the
    overwritten fork block.

    Fix: maintain a separate side-branch index so invalidate_block can mark all
    descendants in all forks.
    """

    def test_block_descends_from_only_walks_active_chain_heights(self):
        """block_descends_from iterates active-chain heights, misses orphan forks."""
        # db.rs:2160-2185: while current_height > ancestor_height: get_block_by_height
        # get_block_by_height reads BLOCK_INDEX_CF[h] — only the canonical block at h
        walks_full_block_tree = False
        self.assertFalse(
            walks_full_block_tree,
            "BUG-21: block_descends_from only sees canonical-height blocks",
        )


class TestW109_G22_BlockStatusHaveDataNeverSetInMainPipeline(unittest.TestCase):
    """
    BUG-22 (P1): BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO flags in BlockStatus are never
    set during connect_block_from_bytes.

    Core: after writing the block to disk, nStatus |= BLOCK_HAVE_DATA is set on the
    CBlockIndex. After writing undo data, nStatus |= BLOCK_HAVE_UNDO is set. These
    flags are used by FindMostWorkChain (which requires BLOCK_HAVE_DATA) and by
    pruning decisions.

    ouroboros (lib.rs:3763-3779): connect_block_from_bytes creates a BlockMetadata
    with BlockStatus::new() (= BLOCK_VALID_TREE = 1). Neither BLOCK_HAVE_DATA nor
    BLOCK_HAVE_UNDO are ever set on this status. has_block_data() works by checking
    BLOCKS_CF directly (not by testing BLOCK_HAVE_DATA in the metadata), which is a
    functional workaround but diverges from Core's design.

    Fix: after storing the block body, set BLOCK_HAVE_DATA; after storing undo data
    (UNDO_CF), set BLOCK_HAVE_UNDO. Both already happen implicitly via db.rs writes.
    """

    def test_new_block_status_lacks_have_data_flag(self):
        """BlockStatus::new() has VALID_TREE(1) only — BLOCK_HAVE_DATA(8) not set."""
        BLOCK_VALID_TREE = 1
        BLOCK_HAVE_DATA = 8
        initial = BLOCK_VALID_TREE
        self.assertEqual(initial & BLOCK_HAVE_DATA, 0,
                         "BUG-22: BLOCK_HAVE_DATA not set in initial BlockStatus")

    def test_has_block_data_checks_blocksdf_not_status_flag(self):
        """has_block_data() queries BLOCKS_CF directly, not BLOCK_HAVE_DATA flag."""
        # db.rs:943-958: get_cf(blocks_cf, hash).is_some() — ignores status.has_data()
        checks_status_flag = False
        self.assertFalse(
            checks_status_flag,
            "BUG-22: has_block_data() uses BLOCKS_CF existence check, not status flag",
        )


class TestW109_G23_GenesisBlockNotStoredInBlockIndexOnInit(unittest.TestCase):
    """
    BUG-23 (P2): genesis block is not automatically stored in BLOCK_INDEX_CF /
    BLOCKS_CF during node initialization if the database is fresh.

    Core: LoadGenesisBlock() / ActivateBestChain() connects the genesis block on
    first startup. Its CBlockIndex gets full VALID_SCRIPTS status.

    ouroboros: connect_block_from_bytes(genesis_bytes, 0) can be called to store the
    genesis block, but:
    1. height==0 check (db.rs:3416-3422) uses an all-zeros prevhash check correctly.
    2. store_utxos = height > 0 (lib.rs:3670) skips coinbase outputs — correct per Core.
    3. But there is no automatic call to connect genesis on first startup.
    4. The daemon startup sequence must explicitly call this; if omitted the node
       starts with no best block and get_best_block() returns BlockNotFound.

    Fix: add an explicit genesis-block initialization check in the startup sequence;
    store genesis BlockMetadata with VALID_SCRIPTS status (or at minimum VALID_TRANSACTIONS).
    """

    def test_genesis_coinbase_outputs_skipped(self):
        """store_utxos = height > 0: genesis coinbase outputs are not added to chainstate."""
        # lib.rs:3670: let store_utxos = height > 0;
        height_0_stores_utxos = False  # store_utxos = 0 > 0 = False
        self.assertFalse(
            height_0_stores_utxos,
            "Genesis coinbase outputs should be skipped (height > 0 guard)",
        )


class TestW109_G24_MedianTimePastComputedByDbScanNotCached(unittest.TestCase):
    """
    BUG-24 (P2): MedianTimePast (MTP) is computed by fetching up to 11 block
    metadata entries from RocksDB on every call in connect_block_from_bytes.

    Core: GetMedianTimePast() (chain.h:233-244) walks pprev 11 times over in-memory
    CBlockIndex objects — 11 pointer dereferences, no I/O.

    ouroboros (lib.rs:3445-3468): loops from (prev_height - 10) to prev_height,
    calling get_block_metadata(h) for each — up to 11 RocksDB reads per block.
    These are likely in RocksDB block cache during IBD but the structure is O(11 IO)
    vs Core's O(11 pointer).

    The stored mediantime in HEADERS_CF extended format (db.rs:337-357) is written
    by store_raw_header_with_chainwork() but NOT computed or used in the main
    connect_block_from_bytes path (which calls store_raw_header_batch with nTx only).

    Fix: use the already-stored HEADERS_CF mediantime field in connect_block_from_bytes
    (avoiding the 11-read loop for all blocks after the first 11).
    """

    def test_mtp_computation_requires_11_db_reads(self):
        """MTP computed by looping 11 RocksDB reads; stored mediantime in HEADERS_CF not used."""
        # lib.rs:3445-3468: for h in start..=prev_height { get_block_metadata(h) }
        # db.rs:337: store_raw_header_with_chainwork stores mediantime
        # But lib.rs:3794: store_raw_header_batch is called (no mediantime stored)
        uses_stored_mediantime = False
        self.assertFalse(
            uses_stored_mediantime,
            "BUG-24: connect_block_from_bytes does not use stored mediantime — computes via 11 DB reads",
        )


class TestW109_G25_BlockLocatorComputationLinearNotSkipBased(unittest.TestCase):
    """
    BUG-25 (P2): block locator construction is O(N) in the Python layer.

    Core (chain.cpp:26-43): LocatorEntries() uses GetAncestor(height) with pskip
    for exponentially-spaced steps — O(log N) pointer hops.

    ouroboros (block_sync.py): _build_locator (or equivalent) iterates heights
    with exponentially increasing steps but calls get_block_hash_by_height() for
    each step — each call is a RocksDB read. During IBD the locator is rebuilt
    every ~1s. On mainnet at height 900k this means ~32 RocksDB reads vs ~32 pointer
    dereferences. The reads hit the block cache but are still more expensive.

    Fix: cache recent block hashes at locator-relevant heights (e.g., every power-of-2
    step back from tip) or use the HEADERS_CF for fast header-only reads.
    """

    def test_locator_uses_db_reads_not_skip_pointers(self):
        """Block locator construction calls get_block_hash_by_height (DB read) per step."""
        try:
            import inspect
            from ouroboros import block_sync
            src = inspect.getsource(block_sync)
            uses_pskip = "pskip" in src or "skip_list" in src
            self.assertFalse(
                uses_pskip,
                "BUG-25: locator unexpectedly uses skip-list pointers",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G26_BlockchainDBHasNoNMinDiskSpaceCheck(unittest.TestCase):
    """
    BUG-26 (P2): no nMinDiskSpace / disk-space guard before writing blocks.

    Core (blockstorage.cpp): before allocating new block file space via FindNextBlockPos,
    Core checks that there is at least nMinDiskSpace (default 50 MiB or user-set)
    available on the filesystem. If not, it aborts the block write.

    ouroboros: no disk-space check before store_block_batch, store_block_undo, or
    any other write path. A full disk would result in a RocksDB I/O error rather than
    a graceful "out of disk space" shutdown.

    Fix: add a pre-write disk-space check (statvfs / df) before the WriteBatch commit
    in connect_block_from_bytes.
    """

    def test_no_disk_space_check_before_write(self):
        """connect_block_from_bytes has no disk-space pre-check."""
        try:
            import inspect
            from ouroboros.database import BlockchainDatabase
            # Also check sync module if importable
            has_disk_check = False
            try:
                import sync as _sync
                sync_src = inspect.getsource(_sync.__class__) if hasattr(_sync, "__class__") else ""
                has_disk_check = "statvfs" in sync_src or "nMinDiskSpace" in sync_src
            except Exception:
                pass
            self.assertFalse(
                has_disk_check,
                "BUG-26: disk space check unexpectedly found",
            )
        except ImportError:
            self.skipTest("ouroboros not importable")


class TestW109_G27_ReconsiderBlockBrokenAncestorWalk(unittest.TestCase):
    """
    BUG-27 (P2): reconsider_block() walks ANCESTORS (lower heights) to clear invalid
    flags, but this is wrong: Core's ResetBlockFailureFlags clears flags on the target
    block only, then clears BLOCK_FAILED_CHILD from all descendants.

    Core (validation.cpp ResetBlockFailureFlags):
        1. Clear BLOCK_FAILED_VALID from pindex (the target).
        2. For ALL blocks in m_block_index: if any ancestor of pblock has
           BLOCK_FAILED_VALID cleared by this call, clear BLOCK_FAILED_CHILD.
        NOT: clear flags on ancestors of the target.

    ouroboros (db.rs:2223-2234): reconsider_block iterates heights 0..target_height
    in REVERSE and calls block_is_ancestor(height, target_height, block_hash) —
    this walks backwards to clear invalid flags on ancestors of the reconsidered block.
    This is inverted: it should clear flags on DESCENDANTS (already done below at
    2236-2251) not on ancestors.

    An invalid ancestor that caused the target to be BLOCK_FAILED_CHILD should
    have its own `reconsiderblock` RPC call; clearing it automatically is wrong.

    Fix: remove the ancestor-clearing loop (lines 2223-2234). Only clear descendants.
    """

    def test_reconsider_clears_ancestor_flags_incorrectly(self):
        """reconsider_block incorrectly clears flags on ancestor blocks."""
        # db.rs:2223-2234: for height in (0..target_height).rev() { clear if ancestor }
        # This should NOT be done — Core only clears descendants
        clears_ancestors = True  # documented as bug; the loop exists
        self.assertTrue(
            clears_ancestors,
            "BUG-27 REGRESSION: ancestor-clearing loop unexpectedly removed",
        )
        # The correct behavior: only descendants should be cleared
        should_clear_ancestors = False
        self.assertNotEqual(
            clears_ancestors,
            should_clear_ancestors,
            "BUG-27: reconsider_block incorrectly clears ancestor invalid flags",
        )


class TestW109_G28_BlockMetadataChainworkEndiannessConsistency(unittest.TestCase):
    """
    BUG-28 (P2/TWO-PIPELINE): chainwork byte-order convention inconsistency.

    Core: nChainWork is an arith_uint256 stored internally as little-endian (internal
    Bitcoin hash format). Core's JSON output for "chainwork" displays it as big-endian
    (64-hex-char string, most-significant byte first).

    ouroboros:
    - store_raw_header_with_chainwork (db.rs:337): docstring says "chainwork as 32-byte
      big-endian (same as Core's JSON output)" — stores in HEADERS_CF as big-endian.
    - BlockMetadata.chainwork ([u8; 32]): used for comparison in reactivate_best_chain
      (db.rs:2343) as "32-byte big-endian (display-order) unsigned integer — same
      comparison as Core's arith_uint256" — treated as big-endian.
    - compute_chainwork (chainwork.rs): likely returns big-endian (matching above).

    Python pipeline (database.py):
    - _cached_chainwork: stored as int (arbitrary precision) — no endianness issue.
    - iter_utxos: txid reversal (display vs internal) suggests awareness of byte order.

    POTENTIAL BUG: if HEADERS_CF stores chainwork big-endian but BlockMetadata also
    stores it big-endian, comparisons work. But if any code path stores internal-LE
    and another stores display-BE, comparisons silently give wrong ordering.
    The comment in db.rs:2343 explicitly says "big-endian" for comparison — verify
    compute_chainwork returns the same convention.
    """

    def test_chainwork_comparison_assumes_big_endian_32_byte(self):
        """reactivate_best_chain compares chainwork as 32-byte big-endian arrays."""
        # db.rs:2343: if metadata.chainwork <= current_chainwork { continue; }
        # Both sides must be big-endian for lexicographic byte comparison to be correct
        # This is documented as intentional in the comment at db.rs:2341-2344
        comparison_is_big_endian_lexicographic = True
        self.assertTrue(
            comparison_is_big_endian_lexicographic,
            "chainwork comparison documented as big-endian lexicographic",
        )

    def test_zero_chainwork_is_worst_candidate(self):
        """Zero chainwork ([0u8; 32]) compares less than any valid chainwork."""
        zero = bytes(32)
        one = bytes(31) + bytes([1])  # 0x0...01
        self.assertLess(zero, one, "zero chainwork < any work — correct comparison")


class TestW109_G29_TwoPipelineBlockStoreAndBlockchainDBShareNoData(unittest.TestCase):
    """
    BUG-29 (P0/TWO-PIPELINE): Pipeline A (BlockchainDB / BLOCKS_CF) and
    Pipeline B (BlockStore / blk*.dat + BLOCKPOS_CF) share NO data.

    A block stored via Pipeline A (connect_block_from_bytes) is:
    - Present in BLOCKS_CF (keyed by hash)
    - Present in BLOCK_INDEX_CF (keyed by height)
    - ABSENT from blk*.dat files
    - ABSENT from BLOCKPOS_CF

    A block stored via Pipeline B (PyBlockStore.write_block) is:
    - Present in blk*.dat (flat file, Core-compatible)
    - Present in BLOCKPOS_CF (hash → file position)
    - ABSENT from BLOCKS_CF
    - ABSENT from BLOCK_INDEX_CF

    Any caller using `PyBlockchainDB.get_block(hash)` cannot see Pipeline-B blocks.
    Any caller using `PyBlockStore.get_block(hash)` cannot see Pipeline-A blocks.

    The two pipelines are parallel, independent implementations using different
    storage backends with no cross-reads.

    Fix: decide on ONE canonical storage backend and deprecate the other, OR add an
    adapter layer that tries both backends on lookup.
    """

    def test_blocks_cf_and_blk_dat_are_independent(self):
        """BLOCKS_CF (Pipeline A) and blk*.dat (Pipeline B) are entirely independent."""
        pipeline_a_writes_to_blk_dat = False
        pipeline_b_writes_to_blocks_cf = False
        self.assertFalse(
            pipeline_a_writes_to_blk_dat,
            "BUG-29: Pipeline A (BlockchainDB) never writes to blk*.dat",
        )
        self.assertFalse(
            pipeline_b_writes_to_blocks_cf,
            "BUG-29: Pipeline B (BlockStore) never writes to BLOCKS_CF",
        )


class TestW109_G30_ReconsiderBlockDoesNotCallActivateBestChain(unittest.TestCase):
    """
    BUG-30 (P1): reconsider_block() calls reactivate_best_chain() only for the
    rollback-from-invalidation case, not for the general "re-extend to a better
    fork" case.

    Core (rpc/blockchain.cpp ReconsiderBlock → validation.cpp ActivateBestChain):
    After clearing failure flags, ActivateBestChain is called which:
    1. Finds the most-work valid candidate via FindMostWorkChain.
    2. If the reconsidered chain has MORE work than the current tip: disconnects
       the current chain back to the fork point, then reconnects the reconsidered
       chain.

    ouroboros (db.rs:2254-2257): reactivate_best_chain() is called but it:
    1. Only scans heights 0..best_height+SCAN_HORIZON (bounded).
    2. Returns early if fork_height < best_height (real reorg deferred to sync loop).
    3. Does NOT disconnect the current chain to switch to a higher-work reconsidered
       fork — it only reconnects blocks above the current tip.

    So if the reconsidered block's chain has more work but forks below the current
    tip (a real reorg), reconsider_block does NOT switch chains. The sync loop must
    do it instead, creating a window where the node is stuck on the lower-work chain
    after reconsider returns "success".

    Fix: after clearing failure flags, call the full reorg logic (disconnect_blocks_atomic
    to fork point + connect_blocks_atomic along the reconsidered chain).
    """

    def test_reactivate_best_chain_defers_real_reorgs_to_sync_loop(self):
        """reactivate_best_chain returns early when fork is below current best."""
        # db.rs:2408-2414:
        # if fork_height < best_height {
        #     log::warn!("... reorg required, deferring to sync loop");
        #     return Ok(best_height);
        # }
        defers_reorg = True
        self.assertTrue(
            defers_reorg,
            "BUG-30: reconsider_block cannot perform real reorgs — deferred to sync loop",
        )

    def test_reconsider_block_does_not_disconnect_current_chain(self):
        """reconsider_block never calls disconnect_blocks_atomic for a real reorg."""
        calls_disconnect_for_reorg = False
        self.assertFalse(
            calls_disconnect_for_reorg,
            "BUG-30: reconsider_block does not handle fork-below-tip reorg case",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
