"""
W123 — Mining / GBT (getblocktemplate) parity audit — 30 fresh gates.

Distinct from W108 (which already exercised IBD guard, BIP-9 fields,
longpollid, mintime, dead-helper next_bits/next_version, sigops, locktime
edge cases, sequence/locktime in generatetoaddress, etc.). W123 layers on
30 additional gates that probe areas W108 left untouched:

  - Coinbase output script / extranonce / scriptSig prefix policy
  - Block-template caching / pindexPrev pinning
  - mode=proposal TestBlockValidity
  - GetTransactionsUpdated long-poll counter wiring
  - Argument-driven knobs (-blockmaxweight, -blockmintxfee, -blockreservedweight, -printpriority)
  - Signet block-signing (BIP-325)
  - BIP-94 mintime / UpdateTime min-difficulty recompute
  - CooldownIfHeadersAhead / WaitTipChanged interface
  - submitblock dummy arg / duplicate-invalid / ZMQ notify hook
  - GBT side-branch propagation
  - Cluster-mempool chunked block builder API (GetBlockBuilderChunk)
  - getmininginfo current-block telemetry persistence
  - Missing RPCs: generateblock, generatetodescriptor, submitheader
  - GBT coinbasetxn data field policy / sigops budget reserve
  - Two-pipeline guard: Rust ferrous-utils remains mining-free

Reference:
  bitcoin-core/src/node/miner.cpp
  bitcoin-core/src/rpc/mining.cpp
  bitcoin-core/src/node/miner.h
  bitcoin-core/src/policy/policy.h
  BIP-22 / BIP-23 / BIP-141 / BIP-152 / BIP-325 / BIP-94

All tests are xfail-shaped: they ASSERT the current (incorrect) state so
the suite stays green and any subsequent fix that flips the underlying
behaviour will RED-flip a single specific test. Fixes for W123 gates
must convert the corresponding ``assertEqual``/``assertIn`` from current-
state assertion to Core-spec assertion.
"""

import asyncio
import hashlib
import inspect
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Stub Rust extension before any ouroboros imports.
sys.modules.setdefault("sync", MagicMock())

src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.mempool import MempoolEntry  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402
import ouroboros.rpc as _rpc_mod  # noqa: E402


def _txid(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def _make_rpc(height: int = 800_000, mempool=None, network: str = "mainnet") -> RPCServer:
    mock_db = MagicMock()
    best_hash = hashlib.sha256(str(height).encode()).digest()
    mock_db.get_best_block.return_value = (best_hash, height)
    mock_block = MagicMock()
    mock_block.bits = 0x17053894
    mock_block.version = 0x20000000
    mock_db.get_block.return_value = mock_block
    mock_db.get_median_time_past.return_value = 1_700_000_000

    if mempool is None:
        mempool = MagicMock()
        mempool.snapshot.return_value = ([], {})
        mempool.map_deltas = {}

    mock_node = MagicMock()
    mock_node.db = mock_db
    mock_node.mempool = mempool
    mock_node.network = network
    # Strip the dead-helper attrs so the fallback branch runs.
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
# G1 — coinbase_output_script is not a configurable option
# Core: BlockAssembler::Options has coinbase_output_script (CScript); used in
#       generateblock + IPC mining interface. miner.cpp:176.
# Ouroboros: GBT response leaves coinbase to caller; there is no coinbase
#       output template at all, so the miner cannot know where rewards go.
# ---------------------------------------------------------------------------
class TestG1CoinbaseOutputScriptOption(unittest.TestCase):
    """BUG: GBT response has no coinbase_output_script field; miners must build their own."""

    def test_template_lacks_coinbase_output_template(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        # Core's GBT does not emit the actual coinbase script either,
        # but in IPC/generateblock paths Core EXPOSES it via createNewBlock
        # options.  Ouroboros never threads coinbase_output_script through
        # to its GBT/generatetoaddress flows as a configurable option.
        cbtxn = result.get("coinbasetxn", {})
        # current state: no scriptPubKey field; coinbase_output_script not wired
        self.assertNotIn("scriptPubKey", cbtxn,
                         "current state: coinbasetxn lacks scriptPubKey (Core IPC has it)")
        # Audit gate: hint Core/spec gap — once a coinbase_output_script
        # option is wired, change this to assertIn.


# ---------------------------------------------------------------------------
# G2 — Coinbase scriptSig BIP-34 height prefix vs include_dummy_extranonce
# Core: scriptSig = CScript() << nHeight, optionally appended with OP_0
#       (`include_dummy_extranonce`) — miner.cpp:186-193. Required because
#       BIP-34 height at heights <= 16 encodes as a single byte; consensus
#       requires coinbase scriptSig >= 2 bytes (bad-cb-length).
# Ouroboros: generatetoaddress does build the height prefix but does NOT
#       enforce the >= 2-byte rule — for height 1..16 the script is a
#       single push of one byte; only the length prefix saves it.
# ---------------------------------------------------------------------------
class TestG2CoinbaseScriptSigMinLen(unittest.TestCase):
    """BUG: include_dummy_extranonce policy missing — coinbase scriptSig
    can collapse below 2 bytes at small heights."""

    def test_height_one_scriptsig_extranonce_absent(self):
        # generatetoaddress builds: bytes([len(height_bytes)]) + height_bytes
        # For height = 1: height_bytes = b"\x01", scriptsig = b"\x01\x01" (2 bytes).
        # OK by accident.  But the dummy-extranonce policy is structurally absent
        # — there is no `include_dummy_extranonce` option to opt in/out.
        src = inspect.getsource(RPCServer.rpc_generatetoaddress)
        self.assertNotIn("include_dummy_extranonce", src,
                         "current state: no include_dummy_extranonce policy")
        self.assertNotIn("OP_0", src,
                         "current state: no OP_0 extranonce padding in coinbase scriptSig")


# ---------------------------------------------------------------------------
# G3 — Block-template caching / pindexPrev pinning
# Core: caches CBlockTemplate; only rebuilds on tip change OR (mempool tx
#       count delta AND > 5 seconds elapsed) — mining.cpp:863-884.
# Ouroboros: rebuilds the whole template on every GBT call — no caching.
# ---------------------------------------------------------------------------
class TestG3TemplateCaching(unittest.TestCase):
    """BUG: GBT rebuilds template on every call — no pindexPrev pin / 5s cache."""

    def test_no_template_cache_attribute(self):
        rpc = _make_rpc()
        # Core RPC tracks `static pindexPrev`, `static block_template`,
        # `static time_start` to avoid rebuilding.  Ouroboros has no such
        # state on the RPCServer.
        self.assertFalse(hasattr(rpc, "_gbt_template_cache"),
                         "current state: no template cache (every call rebuilds)")
        self.assertFalse(hasattr(rpc, "_gbt_pindex_prev"),
                         "current state: no pindexPrev pin")


# ---------------------------------------------------------------------------
# G4 — mode='proposal' does NOT call TestBlockValidity
# Core: mode=proposal returns BIP22ValidationResult(TestBlockValidity(...))
#       — mining.cpp:751.  Validates the proposed block via the real engine.
# Ouroboros: ignores template_request entirely (W108 G3 already flagged
#       the dispatch gap; W123 G4 narrows in on the validation engine call).
# ---------------------------------------------------------------------------
class TestG4ProposalValidationEngine(unittest.TestCase):
    """BUG: mode=proposal does not invoke TestBlockValidity — never validates the block."""

    def test_proposal_mode_no_validate_call(self):
        rpc = _make_rpc()
        # validate_block is supposed to fire on proposal mode in Core's analog.
        validate_calls = []
        rpc.node.validator = MagicMock()
        rpc.node.validator.validate_block.side_effect = lambda *a, **k: validate_calls.append(a) or (True, "")

        # Use 80 bytes of arbitrary data — Core would dispatch on mode=='proposal'.
        result = _run_gbt(rpc, {"mode": "proposal", "data": "00" * 80, "rules": ["segwit"]})
        # Current state: returns full template (no validation occurred).
        self.assertIsInstance(result, dict, "current state: returns template dict")
        self.assertEqual(len(validate_calls), 0,
                         "current state: validator.validate_block was NEVER invoked")


# ---------------------------------------------------------------------------
# G5 — mempool.GetTransactionsUpdated counter for long-poll wiring
# Core: CTxMemPool::GetTransactionsUpdated() returns a monotone counter
#       incremented on every accept/remove; mining.cpp:864 uses it as a
#       cheap "mempool changed?" signal for long-poll wake-ups.
# Ouroboros: no such counter on Mempool.
# ---------------------------------------------------------------------------
class TestG5MempoolTransactionsUpdatedCounter(unittest.TestCase):
    """BUG: Mempool exposes no GetTransactionsUpdated counter for long-polling."""

    def test_no_transactions_updated_counter(self):
        from ouroboros.mempool import Mempool
        attrs = dir(Mempool)
        candidates = [a for a in attrs if "transactions_updated" in a.lower()
                      or a == "GetTransactionsUpdated"]
        self.assertEqual(candidates, [],
                         "current state: no transactions-updated counter")


# ---------------------------------------------------------------------------
# G6 — -blockmaxweight CLI / config arg ignored
# Core: ApplyArgsManOptions reads -blockmaxweight into Options.nBlockMaxWeight
#       — miner.cpp:101.
# Ouroboros: WEIGHT_BUDGET = MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT hardcoded.
# ---------------------------------------------------------------------------
class TestG6BlockMaxWeightArgIgnored(unittest.TestCase):
    """BUG: -blockmaxweight argument is structurally absent."""

    def test_no_blockmaxweight_arg_in_gbt(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        self.assertNotIn("blockmaxweight", src,
                         "current state: no -blockmaxweight knob in GBT")
        self.assertIn("WEIGHT_BUDGET", src,
                      "current state: hardcoded WEIGHT_BUDGET constant in source")


# ---------------------------------------------------------------------------
# G7 — -blockmintxfee CLI / config arg ignored
# Core: ApplyArgsManOptions reads -blockmintxfee; tip used by addChunks
#       to early-return when the chunk feerate falls below the floor.
# Ouroboros: getmininginfo returns blockmintxfee = 0.00001 hardcoded
#       (rpc.py:4828) and GBT has no fee-floor gate at all.
# ---------------------------------------------------------------------------
class TestG7BlockMinTxFeeArgIgnored(unittest.TestCase):
    """BUG: -blockmintxfee argument is structurally absent in GBT (W108 G14 was
    about the value being hardcoded; W123 G7 is about the chunk-fee-floor gate)."""

    def test_no_chunk_fee_floor_gate_in_gbt(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        # Core: `if (chunk_feerate_vsize << blockMinFeeRate.GetFeePerVSize()) return;`
        self.assertNotIn("blockMinFeeRate", src,
                         "current state: no chunk fee-floor gate in GBT loop")
        self.assertNotIn("min_fee_rate", src,
                         "current state: no min_fee_rate floor check")


# ---------------------------------------------------------------------------
# G8 — -blockreservedweight CLI / config arg ignored
# Core: -blockreservedweight controls BLOCK_RESERVED_WEIGHT — miner.cpp:107.
# Ouroboros: hardcoded BLOCK_RESERVED_WEIGHT = 8000.
# ---------------------------------------------------------------------------
class TestG8BlockReservedWeightArgIgnored(unittest.TestCase):
    """BUG: -blockreservedweight argument is structurally absent."""

    def test_no_blockreservedweight_arg(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        self.assertNotIn("blockreservedweight", src,
                         "current state: no -blockreservedweight knob")
        self.assertIn("BLOCK_RESERVED_WEIGHT", src,
                      "current state: hardcoded BLOCK_RESERVED_WEIGHT")


# ---------------------------------------------------------------------------
# G9 — -printpriority logging knob missing
# Core: print_modified_fee option; logs each tx's fee rate + txid during
#       block building when -printpriority=1 — miner.cpp:272-275.
# Ouroboros: no equivalent log path.
# ---------------------------------------------------------------------------
class TestG9PrintPriorityLoggingMissing(unittest.TestCase):
    """BUG: -printpriority debug knob not implemented."""

    def test_no_print_priority(self):
        src = inspect.getsource(_rpc_mod)
        self.assertNotIn("print_modified_fee", src,
                         "current state: no print_modified_fee option")
        self.assertNotIn("printpriority", src.lower().replace("_", ""),
                         "current state: no -printpriority logging")


# ---------------------------------------------------------------------------
# G10 — Signet block-signing (BIP-325) not implemented in mining helpers
# Core: signet ActivateBestChain validates signet challenge; for mining,
#       the signet_solve_block (Signer interface) injects the signature
#       into the coinbase scriptSig before submission. signet.cpp.
# Ouroboros: generatetoaddress / GBT do not attempt to sign signet blocks.
# ---------------------------------------------------------------------------
class TestG10SignetBlockSigning(unittest.TestCase):
    """BUG: signet block-signing not wired into mining helpers."""

    def test_generatetoaddress_does_not_sign_signet(self):
        src = inspect.getsource(RPCServer.rpc_generatetoaddress)
        self.assertNotIn("signet", src.lower(),
                         "current state: generatetoaddress unaware of signet")
        self.assertNotIn("SignetSolution", src,
                         "current state: no signet-block signer")

    def test_gbt_does_not_signal_signet_challenge_field(self):
        rpc = _make_rpc(network="signet")
        result = _run_gbt(rpc, {"rules": ["segwit", "signet"]})
        # Core: GBT response on signet emits "signet_challenge".  Ouroboros
        # currently does not.  W108 G13 had the same observation; W123 G10
        # confirms the BIP-325 sign-and-publish flow is absent too.
        self.assertNotIn("signet_challenge", result,
                         "current state: signet_challenge not in GBT response")


# ---------------------------------------------------------------------------
# G11 — BIP-94 mintime corner case (retarget-boundary cap by tip time)
# Core: GetMinimumTime accounts for BIP-94 timewarp at retarget boundary:
#       min_time = max(MTP+1, tip.GetBlockTime() - MAX_TIMEWARP) — miner.cpp:36-46.
# Ouroboros: mintime = block_mtp + 1 — no MAX_TIMEWARP arm.
# ---------------------------------------------------------------------------
class TestG11Bip94MintimeMaxTimewarpArm(unittest.TestCase):
    """BUG: BIP-94 MAX_TIMEWARP arm of GetMinimumTime not honoured at retarget boundary."""

    def test_no_max_timewarp_reference_in_gbt(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        self.assertNotIn("MAX_TIMEWARP", src,
                         "current state: BIP-94 max-timewarp arm not wired")
        self.assertNotIn("difficulty_adjustment_interval", src.lower(),
                         "current state: no retarget-boundary branch in mintime calc")


# ---------------------------------------------------------------------------
# G12 — UpdateTime does not recompute bits on fPowAllowMinDifficultyBlocks
# Core: UpdateTime calls GetNextWorkRequired() when timestamp advances on
#       testnet/testnet4/regtest (fPowAllowMinDifficultyBlocks) — miner.cpp:60-62.
# Ouroboros: GBT computes bits once and never recomputes after curtime
#       updates. (Long-poll missing makes this less acute, but the gap is real
#       for testnet/regtest miners that bump curtime manually.)
# ---------------------------------------------------------------------------
class TestG12UpdateTimeBitsRecompute(unittest.TestCase):
    """BUG: UpdateTime equivalent does not recompute bits on min-difficulty chains."""

    def test_no_bits_recompute_on_curtime_advance(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        # Core: pblock->nBits = GetNextWorkRequired(...) inside UpdateTime
        # when fPowAllowMinDifficultyBlocks.  Ouroboros computes bits once.
        bits_lines = [l for l in src.splitlines() if "bits =" in l]
        # Expect 1-2 occurrences (initial calc); not a recompute loop.
        self.assertLessEqual(len(bits_lines), 4,
                             "current state: bits set in 1-2 places, no recompute")
        self.assertNotIn("fPowAllowMinDifficultyBlocks", src,
                         "current state: no min-difficulty bits recompute branch")


# ---------------------------------------------------------------------------
# G13 — CooldownIfHeadersAhead not implemented
# Core: miner.cpp:458 — refuses to mine if BlocksAheadOfTip indicates we
#       haven't validated up to the headers chain.
# Ouroboros: GBT proceeds even if headers are ahead of validated tip.
# ---------------------------------------------------------------------------
class TestG13CooldownIfHeadersAhead(unittest.TestCase):
    """BUG: CooldownIfHeadersAhead not implemented; GBT proceeds with stale tip."""

    def test_no_cooldown_branch(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        self.assertNotIn("CooldownIfHeadersAhead", src,
                         "current state: cooldown branch absent")
        self.assertNotIn("BlocksAheadOfTip", src,
                         "current state: BlocksAheadOfTip not consulted")


# ---------------------------------------------------------------------------
# G14 — WaitTipChanged interface absent (BIP-23 mining interface long-poll)
# Core: Mining::waitTipChanged is the kernel-side primitive that long-poll
#       relies on — miner.cpp:492.
# Ouroboros: no such interface; long-poll cannot be implemented without it.
# ---------------------------------------------------------------------------
class TestG14WaitTipChangedInterface(unittest.TestCase):
    """BUG: WaitTipChanged primitive missing — blocks long-poll implementation."""

    def test_no_wait_tip_changed_in_node(self):
        from ouroboros.node import BitcoinNode
        attrs = dir(BitcoinNode)
        lower = [a.lower() for a in attrs]
        self.assertNotIn("wait_tip_changed", lower,
                         "current state: no wait_tip_changed primitive")
        self.assertNotIn("waittipchanged", lower,
                         "current state: no WaitTipChanged primitive")


# ---------------------------------------------------------------------------
# G15 — submitblock ignores the BIP-22 "dummy" 2nd argument
# Core: submitblock accepts (hexdata, dummy=ignored) — mining.cpp:1064.
#       Some pool stacks pass a workid in dummy; Core ignores it but accepts.
# Ouroboros: rpc_submitblock signature is (hexdata: str) — second arg breaks
#       the dispatch.
# ---------------------------------------------------------------------------
class TestG15SubmitBlockDummyArg(unittest.TestCase):
    """BUG: rpc_submitblock signature lacks the BIP-22 dummy 2nd arg."""

    def test_signature_one_arg_only(self):
        sig = inspect.signature(RPCServer.rpc_submitblock)
        # current state: (self, hexdata: str)
        param_names = [p for p in sig.parameters if p != "self"]
        self.assertEqual(param_names, ["hexdata"],
                         "current state: signature is (self, hexdata) only")
        # Core: would expect (hexdata, dummy=ignored).


# ---------------------------------------------------------------------------
# G16 — submitblock does not distinguish "duplicate-invalid" from "duplicate-inconclusive"
# Core: returns "duplicate-invalid" when block.nStatus & BLOCK_FAILED_VALID
#       — mining.cpp:746-747.
# Ouroboros: returns "duplicate" for active-chain blocks, "duplicate-inconclusive"
#       for side-branch, but "duplicate-invalid" is never emitted (no invalid-block
#       index lookup).
# ---------------------------------------------------------------------------
class TestG16SubmitBlockDuplicateInvalid(unittest.TestCase):
    """BUG: submitblock cannot emit 'duplicate-invalid' (no invalid-block index)."""

    def test_no_duplicate_invalid_emit_path(self):
        src = inspect.getsource(RPCServer.rpc_submitblock)
        self.assertNotIn("duplicate-invalid", src,
                         "current state: 'duplicate-invalid' string not emitted")


# ---------------------------------------------------------------------------
# G17 — submitblock + accept_block do NOT notify ZMQ subscribers
# Core: ProcessNewBlock fires CMainSignals::BlockChecked which the ZMQ
#       publisher subscribes to.  Subscribers get hashblock/rawblock on
#       every accepted block including ones from submitblock.
# Ouroboros: accept_block in rpc.py:288 does NOT call zmq_publisher.notify_block.
#       Only block_sync.py:1381 notifies — i.e. P2P-arrived blocks notify ZMQ
#       but RPC-submitted blocks do NOT.
# ---------------------------------------------------------------------------
class TestG17SubmitBlockZmqNotifyMissing(unittest.TestCase):
    """BUG: submitblock / accept_block path does not call zmq_publisher.notify_block."""

    def test_accept_block_does_not_notify_zmq(self):
        # accept_block is a module-level function in rpc.py.
        accept_block = getattr(_rpc_mod, "accept_block", None)
        self.assertIsNotNone(accept_block)
        src = inspect.getsource(accept_block)
        self.assertNotIn("zmq", src.lower(),
                         "current state: accept_block does not notify ZMQ")
        self.assertNotIn("notify_block", src,
                         "current state: accept_block does not call notify_block")


# ---------------------------------------------------------------------------
# G18 — Side-branch buffer is in-memory only (lost on restart)
# Core: BlockManager persists side-branch blocks to disk; reorgs survive restart.
# Ouroboros: _side_branch_blocks is a dict on RPCServer instance.  Restart
#       loses all accumulated forks until they re-arrive via P2P.
# ---------------------------------------------------------------------------
class TestG18SideBranchBufferEphemeral(unittest.TestCase):
    """BUG: side-branch buffer is in-memory only — restart discards forks."""

    def test_side_branch_dict_not_persisted(self):
        rpc = _make_rpc()
        self.assertIsInstance(rpc._side_branch_blocks, dict)
        # No load/save method exists.
        self.assertFalse(hasattr(rpc, "_load_side_branch_buffer"))
        self.assertFalse(hasattr(rpc, "_save_side_branch_buffer"))


# ---------------------------------------------------------------------------
# G19 — Cluster-mempool chunked block-builder API not implemented
# Core (post-cluster-mempool): GetBlockBuilderChunk / IncludeBuilderChunk /
#       SkipBuilderChunk on CTxMemPool — miner.cpp:293-332.
# Ouroboros: snapshot()-based greedy ancestor-fee-rate sort.  Functionally
#       similar for simple mempools but does not implement chunked DAG cuts.
# ---------------------------------------------------------------------------
class TestG19ClusterMempoolChunkApiMissing(unittest.TestCase):
    """BUG: GetBlockBuilderChunk / IncludeBuilderChunk / SkipBuilderChunk absent."""

    def test_mempool_lacks_chunk_api(self):
        from ouroboros.mempool import Mempool
        attrs = {a.lower() for a in dir(Mempool)}
        for name in ("getblockbuilderchunk", "includebuilderchunk", "skipbuilderchunk",
                     "start_block_building", "stop_block_building"):
            self.assertNotIn(name, attrs, f"current state: {name} absent on Mempool")


# ---------------------------------------------------------------------------
# G20 — getmininginfo lacks BlockAssembler::m_last_block_weight persistence
# W108 G15 noted currentblockweight/currentblocktx missing from response.
# W123 G20 narrows: even after a successful GBT call, no state is stashed
# anywhere on the RPCServer/Node to feed a later getmininginfo.
# ---------------------------------------------------------------------------
class TestG20LastBlockTelemetryNotStored(unittest.TestCase):
    """BUG: no last-block telemetry stored after GBT for later getmininginfo."""

    def test_gbt_does_not_persist_telemetry(self):
        rpc = _make_rpc()
        before = sorted(rpc.__dict__.keys())
        _run_gbt(rpc)
        after = sorted(rpc.__dict__.keys())
        # Confirm no new "last_block_*" attribute appeared after a GBT call.
        new_keys = set(after) - set(before)
        for k in new_keys:
            self.assertFalse(k.startswith("_last_block") or k.startswith("last_block"),
                             f"current state: GBT did not persist {k}")


# ---------------------------------------------------------------------------
# G21 — generateblock RPC missing entirely
# Core: rpc_generateblock — mining.cpp:305.  Mines a set of pre-supplied
#       transactions in deterministic order, no mempool selection.
# Ouroboros: not implemented.
# ---------------------------------------------------------------------------
class TestG21GenerateBlockRpcMissing(unittest.TestCase):
    """BUG: generateblock RPC not implemented."""

    def test_no_rpc_generateblock_method(self):
        self.assertFalse(hasattr(RPCServer, "rpc_generateblock"),
                         "current state: rpc_generateblock method missing")


# ---------------------------------------------------------------------------
# G22 — generatetodescriptor RPC missing entirely
# Core: rpc_generatetodescriptor — mining.cpp:219.  Same as generatetoaddress
#       but takes a descriptor instead of a parsed address.
# Ouroboros: not implemented.
# ---------------------------------------------------------------------------
class TestG22GenerateToDescriptorMissing(unittest.TestCase):
    """BUG: generatetodescriptor RPC not implemented."""

    def test_no_rpc_generatetodescriptor_method(self):
        self.assertFalse(hasattr(RPCServer, "rpc_generatetodescriptor"),
                         "current state: rpc_generatetodescriptor method missing")


# ---------------------------------------------------------------------------
# G23 — submitheader RPC missing entirely
# Core: rpc_submitheader — mining.cpp:1108.  Submits a header (80 bytes)
#       without requiring the full block, used by light-client / SPV bridge.
# Ouroboros: not implemented.
# ---------------------------------------------------------------------------
class TestG23SubmitHeaderRpcMissing(unittest.TestCase):
    """BUG: submitheader RPC not implemented."""

    def test_no_rpc_submitheader_method(self):
        self.assertFalse(hasattr(RPCServer, "rpc_submitheader"),
                         "current state: rpc_submitheader method missing")


# ---------------------------------------------------------------------------
# G24 — GBT coinbasetxn lacks "data" (serialized raw hex) field
# Core: BIP-22 coinbasetxn alternative includes a `data` key with the
#       full hex-encoded raw coinbase tx — mining.cpp:911-913.
# Ouroboros: coinbasetxn dict only carries `locktime` and `sequence`; the
#       miner cannot reconstruct the txid without rebuilding the cb tx.
# ---------------------------------------------------------------------------
class TestG24CoinbaseTxnDataField(unittest.TestCase):
    """BUG: GBT coinbasetxn lacks serialized 'data' hex field (BIP-22)."""

    def test_coinbasetxn_lacks_data_field(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        cbtxn = result.get("coinbasetxn", {})
        self.assertNotIn("data", cbtxn,
                         "current state: coinbasetxn has no serialized 'data' hex")


# ---------------------------------------------------------------------------
# G25 — GBT does not reserve sigops budget for coinbase
# Core: coinbase_output_max_additional_sigops in Options;
#       nBlockSigOpsCost starts at that value — miner.cpp:115.
# Ouroboros: starts at 0; the budget gate (sum + new) >= MAX_BLOCK_SIGOPS_COST
#       allows a marginal block to overshoot by the coinbase's sigops.
# ---------------------------------------------------------------------------
class TestG25CoinbaseSigopsReserveMissing(unittest.TestCase):
    """BUG: coinbase_output_max_additional_sigops reserve missing — total_sigops starts at 0."""

    def test_total_sigops_starts_at_zero(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        # The local var initial value:
        self.assertIn("total_sigops = 0", src,
                      "current state: total_sigops starts at zero (no coinbase reserve)")
        self.assertNotIn("coinbase_output_max_additional_sigops", src,
                         "current state: no coinbase sigops reserve constant")


# ---------------------------------------------------------------------------
# G26 — Two-pipeline guard: Rust ferrous-utils mining surface remains empty
# This is a POSITIVE/invariant gate — W123 must NOT change.  Mining lives
# in the Python pipeline only.  Asserting this prevents drive-by additions.
# ---------------------------------------------------------------------------
class TestG26TwoPipelineMiningFreeRust(unittest.TestCase):
    """PRESERVE: ferrous-utils Rust pipeline contains no mining code."""

    def test_rust_pipeline_has_no_mining(self):
        rust_root = Path(__file__).parent.parent.parent.parent / "ferrous-utils"
        if not rust_root.is_dir():
            self.skipTest(f"ferrous-utils not present at {rust_root}")
        forbidden_terms = (
            "getblocktemplate", "block_assembler", "BlockAssembler",
            "createNewBlock", "prioritise_transaction", "prioritisetransaction",
            "BlockTemplate", "block_template", "addChunks",
            "GetBlockBuilderChunk",
        )
        rs_files = list(rust_root.rglob("*.rs"))
        # Filter out target/ build artefacts.
        rs_files = [p for p in rs_files if "/target/" not in str(p)]
        hits = {}
        for p in rs_files:
            try:
                src = p.read_text(errors="ignore")
            except Exception:
                continue
            for t in forbidden_terms:
                if t in src:
                    hits.setdefault(str(p.relative_to(rust_root)), []).append(t)
        self.assertEqual(hits, {},
                         f"INVARIANT BREACH: Rust pipeline gained mining code: {hits}")


# ---------------------------------------------------------------------------
# G27 — GBT "default_witness_commitment" not in mutable
# Core: "mutable" array includes "prevblock" / "time" / "transactions" but
#       MAY also expose "version/force" / "submit/coinbase" — mining.cpp:942-945.
# Ouroboros: emits the standard 3-element list (already W108 G28 passes
#       weightlimit always-present); W123 G27 narrows to mutable contents.
# ---------------------------------------------------------------------------
class TestG27MutableArrayMissingCapability(unittest.TestCase):
    """BUG: GBT mutable[] omits 'version/force' and 'submit/coinbase' BIP-23 caps."""

    def test_mutable_array_contains_only_three(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        mutable = result.get("mutable", [])
        self.assertEqual(set(mutable), {"time", "transactions", "prevblock"},
                         "current state: mutable[] has exactly the 3 BIP-22 basics")


# ---------------------------------------------------------------------------
# G28 — GBT response does NOT emit "default_witness_commitment" when there is no SegWit
# Core: only emits default_witness_commitment when SegWit is active and
#       block_template's coinbase has a witness commitment — mining.cpp:1028-1031.
# Ouroboros: emits unconditionally — pre-SegWit miners see a witness commit
#       hex they cannot use.
# ---------------------------------------------------------------------------
class TestG28DefaultWitnessCommitmentUnconditional(unittest.TestCase):
    """BUG: default_witness_commitment emitted even when not applicable."""

    def test_default_witness_commitment_always_present(self):
        rpc = _make_rpc()
        result = _run_gbt(rpc)
        # Current state: present unconditionally regardless of fPreSegWit.
        self.assertIn("default_witness_commitment", result,
                      "current state: default_witness_commitment emitted unconditionally")
        # Bytes should always start with 6a24aa21a9ed (OP_RETURN OP_PUSH36 magic).
        self.assertTrue(result["default_witness_commitment"].startswith("6a24aa21a9ed"))


# ---------------------------------------------------------------------------
# G29 — GBT response missing "signet_challenge" pass-through for signet (W108 G13)
# W108 G13 already covered presence-of-the-key.  W123 G29 narrows in: even
# if the key were present, ouroboros has no consensus.signet_challenge
# wiring on the Node object — the value would have to come from
# validation.DEFAULT_SIGNET_CHALLENGE not from Node config.
# ---------------------------------------------------------------------------
class TestG29NodeSignetChallengeWiring(unittest.TestCase):
    """BUG: Node lacks a signet_challenge attribute / config plumbing."""

    def test_node_has_no_signet_challenge_attribute(self):
        from ouroboros.node import BitcoinNode
        # Check class-level (instance might exist later, but Mining RPC code
        # has no way to read it — searching the RPC source confirms).
        rpc_src = inspect.getsource(_rpc_mod)
        self.assertNotIn("signet_challenge", rpc_src,
                         "current state: rpc.py never reads signet_challenge")
        self.assertNotIn("signet_challenge", dir(BitcoinNode),
                         "current state: BitcoinNode has no signet_challenge attribute")


# ---------------------------------------------------------------------------
# G30 — GBT "longpollid" omitted ALSO means stateless mode (no nTransactionsUpdated)
# Even ignoring long-poll itself, Core puts `tip + nTransactionsUpdated`
# in longpollid so polling clients can detect mempool changes.  Ouroboros
# would need both a counter AND a longpollid format string.
# Two parts: the counter (G5) + the longpollid format string.
# G30 explicitly asserts the format-string codepath is absent.
# ---------------------------------------------------------------------------
class TestG30LongpollidFormatMissing(unittest.TestCase):
    """BUG: no 'tip.hex + counter' longpollid format code path exists."""

    def test_no_longpollid_format_code(self):
        src = inspect.getsource(RPCServer.rpc_getblocktemplate)
        # The Core format is `tip.GetHex() + ToString(nTransactionsUpdatedLast)`.
        # Neither the field nor any concatenation helper exists.
        self.assertNotIn("longpollid", src,
                         "current state: longpollid not emitted")
        self.assertNotIn("nTransactionsUpdated", src,
                         "current state: nTransactionsUpdated not referenced")


if __name__ == "__main__":
    unittest.main()
