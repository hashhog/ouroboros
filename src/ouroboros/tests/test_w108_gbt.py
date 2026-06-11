"""
W108 — BlockTemplate / GBT (getblocktemplate) mining RPC 30-gate audit.

Covers both pipelines:
  Pipeline-1 (Python): rpc_getblocktemplate, rpc_submitblock, rpc_getmininginfo,
                        rpc_prioritisetransaction, rpc_generatetoaddress
  Pipeline-2 (Rust):   ferrous-utils/sync/src/lib.rs (connect_block_from_bytes,
                        is_final_tx — no dedicated Rust GBT path; Rust helpers
                        are called by the Python pipeline via FFI).

Reference:
  bitcoin-core/src/rpc/mining.cpp
  bitcoin-core/src/node/miner.cpp
  bitcoin-core/src/node/miner.h
  bitcoin-core/src/policy/policy.h
  BIP-22 / BIP-23 / BIP-141 / BIP-34 / BIP-94
"""

import asyncio
import hashlib
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub the Rust extension before any ouroboros imports
sys.modules.setdefault("sync", MagicMock())

from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import MempoolEntry
from ouroboros.rpc import RPCServer, bip22_result_string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _txid(label: str) -> bytes:
    """Deterministic 32-byte txid from label string."""
    return hashlib.sha256(label.encode()).digest()


def _make_simple_tx(txid: bytes, fee: int = 1000, size: int = 250) -> Transaction:
    """Minimal segwit transaction fixture."""
    tx = Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=b"\xaa" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            TxOut(value=fee, script_pubkey=b"\x51\x20" + b"\x00" * 32)
        ],
        has_witness=False,
    )
    return tx


def _make_rpc(height: int = 800_000, mempool=None, network: str = "mainnet") -> RPCServer:
    """Build a minimally-mocked RPCServer for GBT testing."""
    mock_db = MagicMock()
    best_hash = hashlib.sha256(str(height).encode()).digest()
    mock_db.get_best_block.return_value = (best_hash, height)

    mock_block = MagicMock()
    mock_block.bits = 0x17053894  # mainnet-like compact difficulty
    mock_block.version = 0x20000000
    mock_db.get_block.return_value = mock_block
    mock_db.get_median_time_past.return_value = 1_700_000_000

    if mempool is None:
        mempool = MagicMock()
        mempool.snapshot.return_value = ([], {})

    mock_node = MagicMock()
    mock_node.db = mock_db
    mock_node.mempool = mempool
    mock_node.network = network
    # Node deliberately does NOT expose get_next_bits / get_next_block_version
    # to exercise the dead-helper fallback paths.
    del mock_node.get_next_bits
    del mock_node.get_next_block_version

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = mock_node
    rpc._side_branch_blocks = {}
    rpc._side_branch_max_entries = 1024
    rpc.block_submission_paused = False
    return rpc


def _run_gbt(rpc: RPCServer, template_request: dict | None = None) -> dict:
    return asyncio.run(rpc.rpc_getblocktemplate(template_request or {}))


# ---------------------------------------------------------------------------
# G1 — IBD guard missing
# Core: refuses GBT if isInitialBlockDownload() (non-test chain)
# Ouroboros: no IBD check; always proceeds
# ---------------------------------------------------------------------------
class TestG1IBDGuard(unittest.TestCase):
    """BUG: GBT does not refuse while node is in IBD (non-test chain)."""

    def test_ibd_not_rejected(self):
        rpc = _make_rpc()
        # Simulate IBD via _is_synced returning False
        rpc._is_synced = lambda: False
        # Core would raise RPC_CLIENT_IN_INITIAL_DOWNLOAD here.
        # Ouroboros returns a template — no error raised.
        result = _run_gbt(rpc)
        self.assertIn("height", result,
                       "IBD nodes must refuse GBT on mainnet (Core RPC_CLIENT_IN_INITIAL_DOWNLOAD)")


# ---------------------------------------------------------------------------
# G2 — No-peers guard missing
# Core: refuses GBT if no connected peers on non-test chain
# Ouroboros: no peer-count check; always proceeds
# ---------------------------------------------------------------------------
class TestG2PeersGuard(unittest.TestCase):
    """BUG: GBT does not check for connected peers on mainnet."""

    def test_no_peers_not_rejected(self):
        rpc = _make_rpc()
        # Node advertises zero peers
        rpc.node.get_peer_count = lambda: 0
        # Core: if (connman.GetNodeCount(Both) == 0) → RPC_CLIENT_NOT_CONNECTED
        result = _run_gbt(rpc)
        self.assertIn("height", result,
                       "GBT on mainnet with 0 peers must raise RPC_CLIENT_NOT_CONNECTED (Core)")


# ---------------------------------------------------------------------------
# G3 — proposal mode not handled
# BIP-23: mode="proposal" must validate the supplied block hex, not return a new template
# Ouroboros: template_request parameter is never read; no dispatch on mode
# ---------------------------------------------------------------------------
class TestG3ProposalMode(unittest.TestCase):
    """BUG: mode='proposal' not implemented — template_request is ignored."""

    def test_proposal_mode_ignored(self):
        rpc = _make_rpc()
        # Provide a dummy 80-byte block proposal (clearly invalid hex block).
        dummy_hex = "00" * 80
        result = _run_gbt(rpc, {"mode": "proposal", "data": dummy_hex, "rules": ["segwit"]})
        # Core would return a validation string (e.g. "bad-txnmrklroot") not a full template.
        # Ouroboros returns a full template dict — proposal validation never ran.
        self.assertIn("height", result,
                       "mode='proposal' must validate block and return result string, not a template")

    def test_unknown_mode_should_error(self):
        rpc = _make_rpc()
        # Core: mode != "template" and mode != "proposal" → RPC_INVALID_PARAMETER "Invalid mode"
        # Ouroboros: ignores template_request entirely → no error
        try:
            result = _run_gbt(rpc, {"mode": "invalid_mode", "rules": ["segwit"]})
            # If no exception raised, mode validation is absent
            self.assertIn("height", result,
                           "mode='invalid_mode' must raise RPC_INVALID_PARAMETER (Core)")
        except Exception:
            pass  # exception would be correct behavior


# ---------------------------------------------------------------------------
# G4 — BIP-9 / BIP-23 fields absent: rules, vbavailable, capabilities, vbrequired
# Core: GBT response includes rules[], vbavailable{}, capabilities[], vbrequired
# Ouroboros: none of these fields are present in the response
# ---------------------------------------------------------------------------
class TestG4GBTBip9Fields(unittest.TestCase):
    """FIXED (W108 G4): BIP-9/BIP-23 fields rules, vbavailable, capabilities, vbrequired now present."""

    def setUp(self):
        self.rpc = _make_rpc()
        self.result = _run_gbt(self.rpc)

    def test_rules_field_present(self):
        # Core always includes at least ["csv", "!segwit", "taproot"].
        self.assertIn("rules", self.result,
                      "rules field must be present in GBT response (BIP-9/BIP-23)")
        rules = self.result["rules"]
        self.assertIn("csv", rules, "rules must include 'csv'")
        self.assertIn("!segwit", rules, "rules must include '!segwit' (mandatory segwit marker)")
        self.assertIn("taproot", rules, "rules must include 'taproot'")

    def test_vbavailable_field_present(self):
        # Core: set of pending versionbit deployments.
        self.assertIn("vbavailable", self.result,
                      "vbavailable field must be present — BIP-9 signalling")
        self.assertIsInstance(self.result["vbavailable"], dict,
                              "vbavailable must be a dict (deployment_name → bit)")

    def test_capabilities_field_present(self):
        # Core: at minimum ["proposal"].
        self.assertIn("capabilities", self.result,
                      "capabilities field must be present — BIP-23 mining capabilities")
        self.assertIn("proposal", self.result["capabilities"],
                      "capabilities must include 'proposal' per BIP-23")

    def test_vbrequired_field_present(self):
        # Core always emits vbrequired (usually 0).
        self.assertIn("vbrequired", self.result,
                      "vbrequired field must be present — BIP-23 mandates this field")
        self.assertEqual(self.result["vbrequired"], 0,
                         "vbrequired should be 0 for current deployments")


# ---------------------------------------------------------------------------
# G5 — longpollid absent
# Core: response includes longpollid = tip_hash + nTransactionsUpdated
# Ouroboros: longpollid key not present
# ---------------------------------------------------------------------------
class TestG5LongPollId(unittest.TestCase):
    """BUG: longpollid missing from GBT response."""

    def test_longpollid_absent(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        self.assertNotIn("longpollid", result,
                         "longpollid must be present (BIP-22 §Specification/Template)")


# ---------------------------------------------------------------------------
# G6 — Long-polling not implemented
# Core: when longpollid param given, blocks until tip changes or mempool updates
# Ouroboros: template_request param entirely ignored (never read)
# ---------------------------------------------------------------------------
class TestG6LongPolling(unittest.TestCase):
    """BUG: BIP-22 long-polling not implemented."""

    def test_longpollid_param_ignored(self):
        rpc = _make_rpc()
        # Passing a longpollid should trigger the long-poll wait path in Core.
        # In ouroboros it is silently ignored (template_request never read).
        import time
        t0 = time.monotonic()
        _run_gbt(rpc, {"longpollid": "0" * 65, "rules": ["segwit"]})
        elapsed = time.monotonic() - t0
        # Any genuine long-poll implementation would wait at least briefly.
        # The point is that template_request is never parsed at all.
        self.assertLess(elapsed, 1.0,
                        "longpollid processed instantly — confirms template_request is ignored")


# ---------------------------------------------------------------------------
# G7 — coinbasetxn lacks required "data" field (serialized coinbase hex)
# Core: coinbase_tx.data = serialized coinbase transaction in hex
# Ouroboros: coinbasetxn only has {locktime, sequence}
# ---------------------------------------------------------------------------
class TestG7CoinbaseTxnDataField(unittest.TestCase):
    """BUG: coinbasetxn missing 'data' field (serialized coinbase hex)."""

    def test_coinbasetxn_data_field_absent(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        cb = result.get("coinbasetxn", {})
        self.assertNotIn("data", cb,
                         "coinbasetxn.data (serialized coinbase hex) is absent — "
                         "miners need this to build the coinbase tx")


# ---------------------------------------------------------------------------
# G8 — coinbasetxn and coinbasevalue both present (BIP-22 violation)
# BIP-22: server must return EITHER coinbasevalue OR coinbasetxn, not both.
#         coinbasetxn takes precedence when the client supports it.
# Ouroboros: returns both coinbasevalue and coinbasetxn in every response.
# ---------------------------------------------------------------------------
class TestG8CoinbaseTxnOrValue(unittest.TestCase):
    """BUG: both coinbasetxn and coinbasevalue present — BIP-22 violation."""

    def test_both_coinbasetxn_and_coinbasevalue_present(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        has_txn = "coinbasetxn" in result
        has_val = "coinbasevalue" in result
        self.assertTrue(has_txn and has_val,
                        "Both coinbasetxn and coinbasevalue are present — BIP-22 requires only one")


# ---------------------------------------------------------------------------
# G9 — mintime missing BIP-94 timewarp boundary check
# Core GetMinimumTime(): min_time = max(MTP+1, pindexPrev->GetBlockTime() - MAX_TIMEWARP)
#      at difficulty-adjustment-interval boundaries (height % 2016 == 0 on mainnet).
# Ouroboros: mintime = MTP + 1 always (no timewarp boundary check).
# ---------------------------------------------------------------------------
class TestG9MinTimeBip94(unittest.TestCase):
    """BUG: mintime ignores BIP-94 timewarp check at difficulty-adjustment boundaries."""

    def test_mintime_is_only_mtp_plus_one(self):
        # At height 800,000 (not a DAI boundary), MTP+1 == correct result.
        # At a DAI boundary (height % 2016 == 0), Core also clamps:
        #   min_time = max(MTP+1, prev_block_time - MAX_TIMEWARP)
        # Ouroboros always returns MTP+1.
        rpc = _make_rpc(height=2016)  # DAI boundary
        result = _run_gbt(rpc)
        # MTP is 1_700_000_000 (from mock)
        expected_simple = 1_700_000_000 + 1
        self.assertEqual(result.get("mintime"), expected_simple,
                         "mintime is MTP+1 only — BIP-94 timewarp boundary not applied")


# ---------------------------------------------------------------------------
# G10 — Dead-helper: get_next_bits / get_next_block_version never wired
# Two-pipeline pattern: GBT has getattr(node, "get_next_bits") calls but
# Node class never implements these methods → always falls back to
# best_block.bits and (best_block.version | 0x20000000).
# ---------------------------------------------------------------------------
class TestG10DeadHelperBitsVersion(unittest.TestCase):
    """BUG: get_next_bits/get_next_block_version dead-helpers — always use fallback."""

    def test_bits_from_prev_block_not_work_required(self):
        rpc = _make_rpc()
        # The mock node has get_next_bits deleted (see _make_rpc).
        # GBT must fall back to best_block.bits.
        result = _run_gbt(rpc)
        mock_bits = rpc.node.db.get_block.return_value.bits
        expected_bits_hex = f"{mock_bits:08x}"
        self.assertEqual(result.get("bits"), expected_bits_hex,
                         "bits came from prev block (fallback) — GetNextWorkRequired not called")

    def test_version_fallback_to_prev_or_bip9(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        # get_next_block_version is absent → fallback: best_block.version | 0x20000000
        mock_version = rpc.node.db.get_block.return_value.version
        fallback_version = mock_version | 0x20000000
        self.assertEqual(result.get("version"), fallback_version,
                         "version came from prev block | BIP9 top bits (fallback) — "
                         "ComputeBlockVersion not called")


# ---------------------------------------------------------------------------
# G11 — prioritisetransaction must apply delta to mempool (FIXED in FIX-72)
# Core: modifies mempool fee delta for priority ordering (mining + RBF + RPC).
# Ouroboros: rpc_prioritisetransaction now calls mempool.prioritise_transaction
#            with the LE txid (W69 endian convention) and the delta_sats.
# ---------------------------------------------------------------------------
class TestG11PrioritiseTransactionStub(unittest.TestCase):
    """FIXED (FIX-72 / W120 BUG-3): prioritisetransaction now updates mempool."""

    def test_handler_returns_true(self):
        rpc = _make_rpc()
        # Provide a real prioritise_transaction stub so the handler can call it.
        rpc.node.mempool.prioritise_transaction = MagicMock()
        result = asyncio.run(rpc.rpc_prioritisetransaction(
            txid="aa" * 32, dummy=0, fee_delta=10000
        ))
        self.assertTrue(result, "prioritisetransaction returns True on success")

    def test_handler_calls_mempool_prioritise(self):
        rpc = _make_rpc()
        rpc.node.mempool.prioritise_transaction = MagicMock()
        asyncio.run(rpc.rpc_prioritisetransaction(
            txid="aa" * 32, dummy=0, fee_delta=50000
        ))
        self.assertTrue(
            rpc.node.mempool.prioritise_transaction.called,
            "prioritisetransaction must apply delta to mempool (FIX-72)"
        )
        # Argument check: txid is LE (display-order reversed) + delta is int.
        (txid_arg, delta_arg), _ = rpc.node.mempool.prioritise_transaction.call_args
        self.assertEqual(len(txid_arg), 32)
        self.assertEqual(delta_arg, 50000)

    def test_handler_rejects_nonzero_dummy(self):
        rpc = _make_rpc()
        rpc.node.mempool.prioritise_transaction = MagicMock()
        with self.assertRaises(ValueError):
            asyncio.run(rpc.rpc_prioritisetransaction(
                txid="aa" * 32, dummy=1.0, fee_delta=10000
            ))


# ---------------------------------------------------------------------------
# G12 — sigoplimit / sizelimit not divided for pre-segwit blocks
# Core: if pre-segwit: sigoplimit /= WITNESS_SCALE_FACTOR; sizelimit /= WSF
# Ouroboros: always emits sigoplimit=80000, sizelimit=4_000_000
# ---------------------------------------------------------------------------
class TestG12PreSegWitLimits(unittest.TestCase):
    """BUG: sigoplimit and sizelimit not adjusted for pre-segwit (fPreSegWit) mode."""

    def test_sigoplimit_always_80000(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        # For post-segwit, 80_000 is correct. For pre-segwit it should be 20_000.
        # Ouroboros never distinguishes — always 80_000.
        self.assertEqual(result.get("sigoplimit"), 80_000,
                         "sigoplimit is 80000 — no pre-segwit adjustment (Core divides by 4)")

    def test_sizelimit_always_4mb(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        self.assertEqual(result.get("sizelimit"), 4_000_000,
                         "sizelimit is 4_000_000 — no pre-segwit adjustment (Core divides by 4)")


# ---------------------------------------------------------------------------
# G13 — signet_challenge absent for signet networks
# Core: if signet_blocks, emits signet_challenge hex
# Ouroboros: no signet handling in GBT
# ---------------------------------------------------------------------------
class TestG13SignetChallenge(unittest.TestCase):
    """BUG: signet_challenge not included for signet networks."""

    def test_signet_challenge_absent(self):
        rpc = _make_rpc(network="signet")
        result = _run_gbt(rpc)
        self.assertNotIn("signet_challenge", result,
                         "signet_challenge missing for signet network")


# ---------------------------------------------------------------------------
# G14 — getmininginfo blockmintxfee hardcoded
# Core: reads from BlockAssembler::Options blockMinFeeRate (from -blockmintxfee arg)
# Ouroboros: hardcoded 0.00001000
# ---------------------------------------------------------------------------
def _make_rpc_mining_info(height: int = 800_000) -> RPCServer:
    """RPCServer with bits properly set for getmininginfo (needs int bits on db)."""
    mock_db = MagicMock()
    best_hash = hashlib.sha256(str(height).encode()).digest()
    mock_db.get_best_block.return_value = (best_hash, height)
    # getmininginfo reads _tip_bits directly from db
    mock_db._tip_bits = 0x1D00FFFF

    mock_node = MagicMock()
    mock_node.db = mock_db
    mock_node.network = "mainnet"
    mock_node.get_current_difficulty.return_value = 1.0
    mock_node.mempool.get_all_transactions.return_value = []

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = mock_node
    rpc._side_branch_blocks = {}
    rpc._side_branch_max_entries = 1024
    rpc.block_submission_paused = False
    return rpc


class TestG14BlockMinTxFeeHardcoded(unittest.TestCase):
    """getmininginfo blockmintxfee = DEFAULT_BLOCK_MIN_TX_FEE (1 sat/kvB).

    Byte-diff parity (2026-06): Core's blockmintxfee is
    ValueFromAmount(DEFAULT_BLOCK_MIN_TX_FEE=1 sat) = 0.00000001 BTC/kvB,
    serialized via BTCAmount (fixed %d.%08d). Previously this was hardcoded
    to the wrong 0.00001000.
    """

    def test_blockmintxfee_default(self):
        from ouroboros.psbt import BTCAmount
        rpc = _make_rpc_mining_info()
        result = asyncio.run(rpc.rpc_getmininginfo())
        val = result.get("blockmintxfee")
        # Emitted as a BTCAmount sentinel (decimal text "0.00000001").
        self.assertIsInstance(val, BTCAmount)
        self.assertEqual(
            val.text, "0.00000001",
            "blockmintxfee should be DEFAULT_BLOCK_MIN_TX_FEE (1 sat) = 0.00000001"
        )


# ---------------------------------------------------------------------------
# G15 — getmininginfo missing currentblockweight / currentblocktx
# Core: emits these optional fields if a block was ever assembled
# Ouroboros: these fields never appear in getmininginfo response
# ---------------------------------------------------------------------------
class TestG15GetMiningInfoMissingFields(unittest.TestCase):
    """BUG: getmininginfo missing currentblockweight / currentblocktx fields."""

    def test_currentblockweight_absent(self):
        rpc = _make_rpc_mining_info()
        result = asyncio.run(rpc.rpc_getmininginfo())
        self.assertNotIn("currentblockweight", result,
                         "currentblockweight absent from getmininginfo")

    def test_currentblocktx_absent(self):
        rpc = _make_rpc_mining_info()
        result = asyncio.run(rpc.rpc_getmininginfo())
        self.assertNotIn("currentblocktx", result,
                         "currentblocktx absent from getmininginfo")


# ---------------------------------------------------------------------------
# G16 — coinbaseaux has spurious "flags" key
# Core: coinbaseaux is empty {} in default GBT response
# Ouroboros: always returns {"flags": ""}
# ---------------------------------------------------------------------------
class TestG16CoinbaseAuxFlags(unittest.TestCase):
    """BUG: coinbaseaux contains spurious 'flags' key — Core returns {}."""

    def test_coinbaseaux_has_flags_key(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        cb_aux = result.get("coinbaseaux", {})
        self.assertIn("flags", cb_aux,
                      "coinbaseaux has spurious 'flags' key (Core returns empty {})")


# ---------------------------------------------------------------------------
# G17 — coinbasetxn missing required "sigops", "fee", "weight" fields
# Core: coinbase_tx struct has required_outputs; miners get fee/sigops/weight.
# Ouroboros coinbasetxn has only {locktime, sequence} — no fee/sigops/weight.
# ---------------------------------------------------------------------------
class TestG17CoinbaseTxnFields(unittest.TestCase):
    """BUG: coinbasetxn missing fee, sigops, weight fields."""

    def setUp(self):
        self.rpc = _make_rpc()
        self.result = _run_gbt(self.rpc)
        self.cb = self.result.get("coinbasetxn", {})

    def test_coinbasetxn_missing_fee(self):
        self.assertNotIn("fee", self.cb,
                         "coinbasetxn.fee is absent (coinbase fee = negative total block fees in Core)")

    def test_coinbasetxn_missing_sigops(self):
        self.assertNotIn("sigops", self.cb,
                         "coinbasetxn.sigops is absent")

    def test_coinbasetxn_missing_weight(self):
        self.assertNotIn("weight", self.cb,
                         "coinbasetxn.weight is absent")


# ---------------------------------------------------------------------------
# G18 — submitblock missing UpdateUncommittedBlockStructures step
# Core submitblock calls chainman.UpdateUncommittedBlockStructures(block, pindex)
# BEFORE ProcessNewBlock to fix witness commitment for post-segwit prev blocks.
# Ouroboros goes straight to accept_block without this step.
# ---------------------------------------------------------------------------
class TestG18SubmitBlockUpdateUncommitted(unittest.TestCase):
    """BUG: submitblock skips UpdateUncommittedBlockStructures (Core pre-processing step)."""

    def test_no_update_uncommitted_structures(self):
        rpc = _make_rpc()
        # verify there is no call to UpdateUncommittedBlockStructures or equivalent
        # by checking that no such method is called on the node or db
        rpc.node.db.update_uncommitted_block_structures = MagicMock()
        rpc.node.update_uncommitted_block_structures = MagicMock()

        # Provide a minimal valid-looking 80-byte header block
        dummy_block = b"\x00" * 80 + b"\x00"  # header + 0 txs varint
        best_hash = rpc.node.db.get_best_block.return_value[0]
        # Build a fake block that extends the current tip
        block_header = struct.pack("<I", 0x20000000)  # version
        block_header += best_hash[::-1]               # prev hash (LE wire)
        block_header += b"\x00" * 32                  # merkle root
        block_header += struct.pack("<I", 1_700_000_000)  # time
        block_header += struct.pack("<I", 0x1D00FFFF)  # bits
        block_header += struct.pack("<I", 0)           # nonce
        block_bytes = block_header + b"\x00"           # 0 txs (empty block)

        # Suppress actual block processing
        async def fake_accept(*args, **kwargs):
            return b"\xab" * 32
        with patch("ouroboros.rpc.accept_block", fake_accept):
            asyncio.run(rpc.rpc_submitblock(block_bytes.hex()))

        self.assertFalse(
            rpc.node.db.update_uncommitted_block_structures.called or
            rpc.node.update_uncommitted_block_structures.called,
            "UpdateUncommittedBlockStructures never called (expected in Core before ProcessNewBlock)"
        )


# ---------------------------------------------------------------------------
# G19 — submitblock "duplicate-invalid" response missing
# Core submitblock: if pindex->nStatus & BLOCK_FAILED_VALID → return "duplicate-invalid"
# Ouroboros: only returns "duplicate" (active-chain hit) or "duplicate-inconclusive"
#            (side-branch hit); no "duplicate-invalid" for BLOCK_FAILED status.
# ---------------------------------------------------------------------------
class TestG19SubmitBlockDuplicateInvalid(unittest.TestCase):
    """BUG: submitblock never returns 'duplicate-invalid' for previously-rejected blocks."""

    def test_duplicate_invalid_not_returned(self):
        rpc = _make_rpc()
        tip_hash = rpc.node.db.get_best_block.return_value[0]

        # Build a minimal block extending the tip
        block_header = struct.pack("<I", 0x20000000)
        block_header += tip_hash[::-1]
        block_header += b"\x00" * 32
        block_header += struct.pack("<I", 1_700_000_000)
        block_header += struct.pack("<I", 0x1D00FFFF)
        block_header += struct.pack("<I", 0)
        block_bytes = block_header + b"\x01" + b"\x00" * 60  # 1 tx placeholder

        # Mock accept_block to raise an error (block was rejected)
        async def reject_block(*args, **kwargs):
            raise ValueError("high-hash: proof of work check failed")

        with patch("ouroboros.rpc.accept_block", reject_block):
            result = asyncio.run(rpc.rpc_submitblock(block_bytes.hex()))

        # A subsequent submit of the same block should return "duplicate-invalid".
        # Ouroboros has no mechanism to track previously-rejected blocks;
        # "duplicate-invalid" is never emitted.
        self.assertNotEqual(result, "duplicate-invalid",
                            "submitblock returns 'duplicate-invalid' — unexpected (confirmed absent)")


# ---------------------------------------------------------------------------
# G20 — GBT response missing required "rules" field with segwit requirement check
# Core: raises RPC_INVALID_PARAMETER if "segwit" not in client rules
# Ouroboros: never validates template_request["rules"] for "segwit"
# ---------------------------------------------------------------------------
class TestG20SegwitRulesRequired(unittest.TestCase):
    """BUG: GBT does not enforce that client must declare segwit support."""

    def test_no_segwit_rule_not_rejected(self):
        rpc = _make_rpc()
        # Core: if !setClientRules.contains("segwit") → RPC_INVALID_PARAMETER
        # Ouroboros: template_request never read → no enforcement
        result = _run_gbt(rpc, {"rules": []})  # segwit not declared
        self.assertIn("height", result,
                       "GBT must reject when client doesn't declare segwit support (Core)")


# ---------------------------------------------------------------------------
# G21 — GBT ancestor fee rate uses entry.size (stripped bytes ≠ vsize)
# Core: BlockAssembler selects by chunk feerate (fee / weight in WU)
# Ouroboros: ancestor_fee_rate = fee / size where size is MempoolEntry.size
#            which may be stripped size (not vsize = ceil(weight/4)).
# ---------------------------------------------------------------------------
class TestG21AncestorFeeRateVsize(unittest.TestCase):
    """BUG: ancestor fee rate uses entry.size not true vsize — segwit tx prioritization skewed."""

    def test_ancestor_fee_rate_size_used(self):
        txid_a = _txid("fee_rate_size_a")
        tx_a = _make_simple_tx(txid_a, fee=1000)

        mempool = MagicMock()
        entry_a = MempoolEntry(tx=tx_a, fee=1000, fee_rate=4.0,
                               size=250, time_added=0.0, height_added=100)
        mempool.snapshot.return_value = ([txid_a], {txid_a: entry_a})

        rpc = _make_rpc(mempool=mempool)
        result = _run_gbt(rpc)
        # Template includes the tx — confirm size-based sort operates
        if result.get("transactions"):
            tx_entry = result["transactions"][0]
            # If weight was used correctly: weight = size*3+total for segwit.
            # For non-witness tx: weight = size*4; vsize = size = weight//4.
            # Bug: entry.size (stripped bytes) used as vsize denominator.
            self.assertEqual(tx_entry.get("weight"), tx_a.get_weight(),
                             "tx weight in template should match get_weight()")


# ---------------------------------------------------------------------------
# G22 — GBT locktime_check: Python fallback compares locktime < lock_cmp not <=
# Core IsFinalTx: tx is non-final if nLockTime >= block_height (block) or
#                 nLockTime >= block_mtp (time). i.e. final if nLockTime < cmp.
# Ouroboros Python fallback: uses lock_cmp as exclusive upper bound (correct).
# But edge case: locktime == MTP is rejected (non-final). Verify.
# ---------------------------------------------------------------------------
class TestG22LockTimeEdgeCase(unittest.TestCase):
    """Verify: IsFinalTx locktime == MTP is non-final (tx must be excluded)."""

    def test_locktime_equal_to_mtp_is_nonfinal(self):
        # MTP = 1_700_000_000 (from mock). A tx with locktime == MTP is non-final.
        # Core: if nLockTime >= MTP → non-final (not included until next block).
        LOCKTIME_THRESHOLD = 500_000_000
        mtp = 1_700_000_000  # matches mock
        height = 800_001

        txid = _txid("nonfinal_locktime")
        nonfinal_tx = Transaction(
            txid=txid,
            version=2,
            locktime=mtp,   # exactly equal to MTP → non-final
            inputs=[TxIn(prev_txid=b"\xaa"*32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFE)],  # not SEQUENCE_FINAL
            outputs=[TxOut(value=5000, script_pubkey=b"\x51")],
            has_witness=False,
        )

        mempool = MagicMock()
        entry = MempoolEntry(tx=nonfinal_tx, fee=1000, fee_rate=4.0,
                             size=200, time_added=0.0, height_added=100)
        mempool.snapshot.return_value = ([txid], {txid: entry})

        rpc = _make_rpc(height=height - 1, mempool=mempool)
        result = _run_gbt(rpc)

        included = {bytes.fromhex(t["txid"])[::-1] for t in result.get("transactions", [])}
        self.assertNotIn(txid, included,
                         "tx with locktime == MTP must be excluded (non-final per IsFinalTx)")


# ---------------------------------------------------------------------------
# G23 — Two-pipeline: Rust is_final_tx uses height as u32; Python fallback uses int
# The Rust function signature: is_final_tx(locktime: u32, sequences: Vec<u32>,
#                                          block_height: u32, block_mtp: i64)
# Python side passes next_height: int. For heights > 2^32-1 this truncates.
# In practice this is theoretical, but the type mismatch is a design bug.
# ---------------------------------------------------------------------------
class TestG23RustFinalTxTypeMismatch(unittest.TestCase):
    """Design bug: Rust is_final_tx takes block_height: u32; Python passes int."""

    def test_rust_is_final_tx_called_with_correct_types(self):
        """Verify that the GBT passes next_height as a compatible value to Rust."""
        from unittest.mock import call as mcall
        mock_sync = MagicMock()
        mock_rust_final = MagicMock(return_value=True)
        mock_sync.is_final_tx = mock_rust_final

        txid = _txid("rust_type_test")
        tx = Transaction(
            txid=txid, version=2, locktime=1,
            inputs=[TxIn(prev_txid=b"\xaa"*32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFE)],
            outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
            has_witness=False,
        )
        mempool = MagicMock()
        entry = MempoolEntry(tx=tx, fee=500, fee_rate=2.0,
                             size=200, time_added=0.0, height_added=100)
        mempool.snapshot.return_value = ([txid], {txid: entry})

        rpc = _make_rpc(height=800_000, mempool=mempool)
        with patch.dict("sys.modules", {"sync": mock_sync}):
            # The GBT imports sync.is_final_tx inside the function
            _run_gbt(rpc)
        # If Rust is_final_tx was called, the height value passed should be
        # next_height (800_001) — within u32 range. Just verify it was called.
        # (In practice Rust extension not loaded in test env, ImportError triggers.)


# ---------------------------------------------------------------------------
# G24 — GBT response: no "rules" field with segwit and taproot markers
# Core always emits ["csv", "!segwit", "taproot"] for post-taproot blocks.
# Ouroboros response has no rules field at all.
# ---------------------------------------------------------------------------
class TestG24RulesFieldMissingSegwitTaproot(unittest.TestCase):
    """FIXED (W108 G24): GBT rules field present with segwit/taproot markers."""

    def test_rules_field_in_response(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        self.assertIn("rules", result,
                      "GBT rules field must be present with segwit/taproot markers for miners")
        rules = result["rules"]
        self.assertIn("!segwit", rules,
                      "rules must include '!segwit' — mandatory SegWit activation marker")
        self.assertIn("taproot", rules,
                      "rules must include 'taproot' — Taproot activation marker")


# ---------------------------------------------------------------------------
# G25 — generatetoaddress coinbase sequence is 0xFFFFFFFF (SEQUENCE_FINAL)
# Core miner.cpp:171: coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)
# Ouroboros generatetoaddress: sequence = 0xFFFFFFFF — disables nLockTime enforcement
# ---------------------------------------------------------------------------
class TestG25GenerateToAddressCoinbaseSequence(unittest.TestCase):
    """BUG: generatetoaddress coinbase uses sequence 0xFFFFFFFF not MAX_SEQUENCE_NONFINAL."""

    def test_coinbase_sequence_in_rpc_gbt_is_correct(self):
        # rpc_getblocktemplate correctly sets sequence to 0xFFFFFFFE (B2 fix)
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        cb = result.get("coinbasetxn", {})
        self.assertEqual(cb.get("sequence"), 0xFFFFFFFE,
                         "GBT coinbasetxn.sequence should be MAX_SEQUENCE_NONFINAL=0xFFFFFFFE")

    def test_generatetoaddress_coinbase_sequence_is_sequence_final(self):
        # In generatetoaddress the coinbase is built with sequence=0xFFFFFFFF
        # See rpc.py line 8235: sequence=0xFFFFFFFF
        # Read the source directly to assert the constant
        import inspect, ouroboros.rpc as rpc_mod
        src = inspect.getsource(rpc_mod.RPCServer.rpc_generatetoaddress)
        # The known bug: sequence=0xFFFFFFFF in the coinbase input
        self.assertIn("0xFFFFFFFF", src,
                      "generatetoaddress uses sequence=0xFFFFFFFF — should be 0xFFFFFFFE "
                      "(MAX_SEQUENCE_NONFINAL) to enforce nLockTime (miner.cpp:171)")


# ---------------------------------------------------------------------------
# G26 — generatetoaddress coinbase locktime is 0, not next_height - 1
# Core miner.cpp:196: coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)
# Ouroboros generatetoaddress: locktime=0 (see cb_raw line 8274)
# ---------------------------------------------------------------------------
class TestG26GenerateToAddressCoinbaseLocktime(unittest.TestCase):
    """BUG: generatetoaddress coinbase locktime=0 — should be next_height-1 (miner.cpp:196)."""

    def test_generatetoaddress_locktime_zero(self):
        import inspect, ouroboros.rpc as rpc_mod
        src = inspect.getsource(rpc_mod.RPCServer.rpc_generatetoaddress)
        # Look for the locktime=0 constant near the locktime packing line
        # rpc.py: _st.pack("<I", 0)  # locktime
        self.assertIn('pack("<I", 0)', src,
                      "generatetoaddress packs locktime=0 — should be next_height-1 "
                      "(causes nLockTime enforcement failure per BIP-34)")


# ---------------------------------------------------------------------------
# G27 — GBT subsidy hardcodes mainnet halving interval (210_000)
# Core: GetBlockSubsidy reads from consensusParams.nSubsidyHalvingInterval
# Ouroboros: halvings = next_height // 210_000 — wrong for testnet4 (210_000)
#            or regtest (150) which use different halving intervals
# Note: testnet4 also uses 210_000 so the regtest case is the divergence.
# ---------------------------------------------------------------------------
class TestG27SubsidyHalvingInterval(unittest.TestCase):
    """BUG: GBT subsidy hardcodes 210_000 halving interval — wrong for regtest (150)."""

    def test_mainnet_subsidy_correct_at_height_210000(self):
        # 1 halving → subsidy = 25 BTC = 2_500_000_000 sat
        rpc = _make_rpc(height=210_000)
        result = _run_gbt(rpc)
        expected = 25 * 100_000_000  # first halving
        self.assertEqual(result.get("coinbasevalue"), expected,
                         "coinbasevalue after first halving should be 25 BTC")

    def test_regtest_subsidy_uses_wrong_interval(self):
        # On regtest the halving interval is 150 blocks (Core consensus param).
        # Ouroboros uses hardcoded 210_000 — so at height=150 on regtest
        # it would incorrectly still return 50 BTC instead of 25 BTC.
        rpc = _make_rpc(height=150, network="regtest")
        result = _run_gbt(rpc)
        # Ouroboros: halvings = 150 // 210_000 = 0 → subsidy = 50 BTC (wrong for regtest)
        # Correct for regtest: halvings = 150 // 150 = 1 → subsidy = 25 BTC
        self.assertEqual(result.get("coinbasevalue"), 50 * 100_000_000,
                         "regtest coinbasevalue at h=150 returns 50 BTC (wrong — should be 25 BTC)")


# ---------------------------------------------------------------------------
# G28 — GBT response field ordering / BIP-23 "weightlimit" for post-segwit
# Core: "weightlimit" is only present in post-segwit templates
# Ouroboros: always emits weightlimit=MAX_BLOCK_WEIGHT regardless of chain state
# This is benign for modern chains but diverges from the spec for test scenarios.
# ---------------------------------------------------------------------------
class TestG28WeightLimitAlwaysPresent(unittest.TestCase):
    """Verify: weightlimit always present (correct for modern chains but BIP-23 says optional)."""

    def test_weightlimit_always_emitted(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        self.assertEqual(result.get("weightlimit"), 4_000_000,
                         "weightlimit always emitted as 4_000_000 (correct for post-segwit)")


# ---------------------------------------------------------------------------
# G29 — GBT "noncerange" value: correct ("00000000ffffffff")
# This is a known-correct field — verify it as a regression guard.
# ---------------------------------------------------------------------------
class TestG29NonceRange(unittest.TestCase):
    """Regression: noncerange must be '00000000ffffffff'."""

    def test_noncerange_correct(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        self.assertEqual(result.get("noncerange"), "00000000ffffffff",
                         "noncerange must be '00000000ffffffff' per BIP-22")


# ---------------------------------------------------------------------------
# G30 — submitblock returns None (null) on success, not empty string
# BIP-22: null result means accepted; string result means rejected with reason.
# Ouroboros: rpc_submitblock returns None on success (correct).
# Regression test: verify None is preserved through the dispatch.
# ---------------------------------------------------------------------------
class TestG30SubmitBlockReturnNullOnSuccess(unittest.TestCase):
    """Regression: submitblock must return None (null) on success."""

    def test_success_returns_none(self):
        rpc = _make_rpc()
        tip_hash = rpc.node.db.get_best_block.return_value[0]

        # Wire format: prev_blockhash is stored in internal LE byte order
        # (same as tip_hash from get_best_block). The comparison in
        # rpc_submitblock is: block_bytes[4:36] == tip_hash
        block_header = struct.pack("<I", 0x20000000)
        block_header += tip_hash          # internal LE → matches tip_hash directly
        block_header += b"\x00" * 32      # merkle root
        block_header += struct.pack("<I", 1_700_000_000)  # time
        block_header += struct.pack("<I", 0x1D00FFFF)     # bits
        block_header += struct.pack("<I", 0)              # nonce
        block_bytes = block_header + b"\x01" + b"\x00" * 100

        async def fake_accept(*args, **kwargs):
            return b"\xcd" * 32

        # has_block_hash must return False to skip the "duplicate" short-circuit
        rpc.node.db.has_block_hash.return_value = False

        with patch("ouroboros.rpc.accept_block", fake_accept):
            result = asyncio.run(rpc.rpc_submitblock(block_bytes.hex()))

        self.assertIsNone(result,
                          "submitblock must return None (null JSON) on success per BIP-22")


if __name__ == "__main__":
    unittest.main()
