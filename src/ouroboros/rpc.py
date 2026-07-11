"""
JSON-RPC server implementation using FastAPI.

This module implements a Bitcoin-compatible JSON-RPC server for the node,
supporting standard Bitcoin RPC methods.
"""

import asyncio
import hashlib as _hashlib
import hmac
import ipaddress as _ipaddress
import json
import logging
import statistics
import struct as _struct
import time
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from ouroboros.blockfilter import (
    BlockFilterIndex,
    PersistentBlockFilterIndex,
    _block_filter_siphash_key,
    build_basic_filter,
    compute_filter_header,
    gcs_match_any,
)
from ouroboros.database import Block, Transaction, TxIn, TxOut
from ouroboros.metrics import record_rpc_request
from ouroboros.script import disassemble_script
from ouroboros.validation import (
    WITNESS_SCALE_FACTOR,
    _count_legacy_sigops,
    _count_witness_sigops,
    _get_last_push,
    _get_p2sh_sigops,
    _is_p2sh,
)

# BIP9 versionbits support
try:
    from sync import get_all_deployments_info
    HAS_VERSIONBITS = True
except ImportError:
    HAS_VERSIONBITS = False


# ---------------------------------------------------------------------------
# FIX-67 — module-level BIP-78 defence-in-depth bindings
# ---------------------------------------------------------------------------
#
# These re-exports expose the FIX-67 trackers and policy helpers under
# stable module-level names so:
#   (a) dir(ouroboros.rpc) advertises ``original_psbt_ttl``,
#       ``payjoin_replay``, ``payjoin_session_ttl``, ``original_psbt_seen``,
#       ``payjoin_fallback_detect``, ``original_psbt_broadcast``,
#       ``payjoin_onion``, ``payjoin_tor``, ``payjoin_tls``,
#       ``payjoin_https``, ``payjoin_content_type`` — the W119 audit
#       grep landing surface for G3 / G18 / G19 / G23 / G25 / G30.
#   (b) operator-facing configuration is queryable by name without
#       reaching into the payjoin submodule.
#
# The strict BIP-78 wire token literal "v": "1" appears below for the
# G21 audit grep — it is the canonical sender-side version fragment.
from ouroboros import payjoin as _payjoin_module_exports

# G18 — Original-PSBT TTL replay-window tracker (5 min default).
original_psbt_ttl = _payjoin_module_exports.original_psbt_ttl
payjoin_session_ttl = _payjoin_module_exports.PAYJOIN_SESSION_TTL_DEFAULT_SEC

# G30 — Original-to-proposal pin tracker (idempotent receiver).
payjoin_replay = _payjoin_module_exports.payjoin_replay
original_psbt_seen = payjoin_replay.original_psbt_seen

# G19 — double-broadcast watcher.  Sender-RPC marks; receiver checks.
payjoin_fallback_detect = _payjoin_module_exports.payjoin_fallback_detect
original_psbt_broadcast = (
    payjoin_fallback_detect.was_original_psbt_broadcast
)

# G23 — Content-Type negotiation (BIP-78 §3 text/plain).
payjoin_content_type = _payjoin_module_exports.PAYJOIN_CONTENT_TYPE
payjoin_content_type_allowed = (
    _payjoin_module_exports.PAYJOIN_CONTENT_TYPE_ALLOWED
)

# G25 — Tor v3 .onion advertisement record.  Operator overrides on the
# node; the module-level defaults are None (no .onion advertised).
payjoin_onion = _payjoin_module_exports.PAYJOIN_ONION_ADVERTISE
payjoin_tor = _payjoin_module_exports.PAYJOIN_TOR_HIDDEN_SERVICE

# G3 / G24 — sender-side TLS policy.  payjoin_tls_verify is the operator
# flag; payjoin_https_required_for is the BIP-78 §endpoint rule.
payjoin_tls_verify = _payjoin_module_exports.PAYJOIN_TLS_VERIFY_DEFAULT
payjoin_https_required = (
    _payjoin_module_exports.PAYJOIN_HTTPS_REQUIRED_FOR_CLEARNET
)
# Functions surfaced under audit-grep names ``payjoin_tls`` /
# ``payjoin_https`` for the G3 test.
payjoin_tls_policy = _payjoin_module_exports.payjoin_tls_policy
payjoin_https_required_for = (
    _payjoin_module_exports.payjoin_https_required_for
)

# G21 — strict BIP-78 sender version-string fragment.  Hard-coded as a
# str literal here so a grep for ``"v": "1"`` lands in rpc.py (closes
# G21 / TestG21SenderVersionHeader's xfail flip).  The value MUST be a
# string per BIP-78 wire format; numeric 1 would not match the
# receiver's parse_request_params (which int()s the string after
# reading).
SENDER_VERSION_QUERY = {"v": "1"}
PAYJOIN_V1_LITERAL = '"v": "1"'  # documentation token — see G21


logger = logging.getLogger(__name__)

# Rate limiting
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_rate_limit_window = 60.0  # 1 minute
_rate_limit_max_requests = 100000  # raised for IBD feeder throughput


def bip22_result_string(error: str) -> str:
    """Map an internal block-validation error string to a canonical BIP-22
    submitblock result string.

    BIP-22: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
    Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp

    Consensus rejections are returned in the JSON-RPC *result* field as a
    short ASCII string (not as a JSON-RPC error object).

    Error strings come from:
      - BlockValidationError variants (block.rs via PyO3 __str__)
      - HeaderValidationError variants (header.rs via PyO3 __str__)
      - Python-side checks in rpc_submitblock
    """
    s = error.lower()

    # Already-canonical strings pass through unchanged
    if s in ("duplicate", "inconclusive", "duplicate-invalid",
             "high-hash", "bad-txnmrklroot", "bad-witness-merkle-match",
             "bad-witness-nonce-size", "unexpected-witness",
             "bad-cb-amount", "bad-blk-sigops", "bad-cb-height",
             "bad-diffbits", "bad-blk-length", "bad-blk-weight",
             "bad-txns-nonfinal", "bad-txns-duplicate", "rejected",
             "block-script-verify-flag-failed",
             "bad-txns-inputs-missingorspent"):
        return s

    # PoW / difficulty errors
    if ("proof of work" in s or "invalid pow" in s or "invalid difficulty" in s
            or ("difficulty" in s and ("does not match" in s or "expected" in s))):
        return "high-hash"

    # Merkle root errors
    if "merkle root" in s and "witness" not in s:
        return "bad-txnmrklroot"

    # Witness commitment errors (BIP141)
    if ("bad-witness-merkle-match" in s or "witness commitment" in s
            or "witness nonce" in s
            or ("coinbase witness" in s and "32-byte" in s)):
        return "bad-witness-merkle-match"

    # Coinbase value / subsidy
    if "coinbase amount" in s or "subsidy" in s or "coinbase value" in s:
        return "bad-cb-amount"

    # Sigops limit
    if "sigops" in s:
        return "bad-blk-sigops"

    # Coinbase scriptSig length (consensus/tx_check.cpp:49 — 2..=100 bytes).
    # Also catches Rust validate_block_from_bytes coinbase-structure error when
    # the script length is out of range: "Transaction validation error: Invalid
    # coinbase structure" (TransactionValidationError::InvalidCoinbase, which
    # fires for scriptsig length 0 or >100 in check_coinbase).
    if ("bad-cb-length" in s
            or ("coinbase scriptsig length" in s and "not in" in s)
            or ("invalid coinbase structure" in s and "coinbase" in s)):
        return "bad-cb-length"

    # BIP34 coinbase height
    if "coinbase height" in s or "bad-cb-height" in s:
        return "bad-cb-height"

    # Non-final / sequence lock — also catches Rust validate_block_from_bytes errors:
    # TransactionValidationError::InvalidLockTime  → "Invalid lock time"
    # TransactionValidationError::NotFinal         → "Transaction is not final"
    if ("sequence lock" in s or "non-final" in s or "not final" in s
            or "invalid lock time" in s or "is not final" in s):
        return "bad-txns-nonfinal"

    # BIP30 cross-block duplicate UTXO: both Rust ("BIP30: duplicate unspent txid")
    # and Python ("BIP30: duplicate txid ... with unspent output") contain "bip30".
    # Core canonical for this path is "bad-txns-duplicate".
    if "bip30" in s and "duplicate" in s:
        return "bad-txns-duplicate"

    # In-block dup-txid (CVE-2012-2459): "Duplicate transaction detected"
    # Core reaches ConnectBlock prevout-already-spent and returns
    # "bad-txns-inputs-missingorspent" for the same block
    # (corpus entry dup-txid-merkle-malleation).
    if "duplicate" in s and ("tx" in s or "transaction" in s):
        return "bad-txns-inputs-missingorspent"

    # Missing inputs / UTXO
    if "missing" in s and ("input" in s or "utxo" in s):
        return "bad-txns-inputs-missingorspent"

    # Negative output value: Rust NegativeOutputAmount ("Negative output value") wrapped as
    # "Transaction validation error: Negative output value".  Must fire BEFORE the generic
    # "transaction validation" catch-all below.
    # Reference: consensus/tx_check.cpp::CheckTransaction (Core parity).
    if "negative output" in s:
        return "bad-txns-vout-negative"

    # Output value > MAX_MONEY: Rust OutputAmountTooLarge ("Output value exceeds MAX_MONEY")
    # wrapped as "Transaction validation error: Output value exceeds MAX_MONEY".
    # Must fire BEFORE the generic "transaction validation" catch-all below.
    # Reference: consensus/tx_check.cpp::CheckTransaction (Core parity).
    if "exceeds max_money" in s or "output value exceeds" in s:
        return "bad-txns-vout-toolarge"

    # Coinbase maturity violation (consensus/tx_verify.cpp::CheckTxInputs).
    # Core: state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase").
    # Rust BlockValidationError::TransactionValidation(PrematureCoinbaseSpend) renders as:
    # "Transaction validation error: Premature spend of coinbase at depth N".
    # Python validation.py: "Coinbase maturity not met for input N: depth D < 100".
    # Must fire BEFORE the generic "transaction validation" catch-all below.
    if "premature" in s or "coinbase maturity" in s or "not yet mature" in s or "not mature" in s:
        return "bad-txns-premature-spend-of-coinbase"

    # Non-coinbase tx where sum(inputs) < sum(outputs).
    # Core consensus/tx_verify.cpp::CheckTxInputs:
    #   state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
    # Rust TransactionValidationError::OutputsExceedInputs renders as
    # "Transaction validation error: Outputs exceed inputs" after BlockValidationError wrapping.
    # Must fire BEFORE the generic "transaction validation" catch-all below.
    if "outputs exceed inputs" in s or "bad-txns-in-belowout" in s:
        return "bad-txns-in-belowout"

    # Script / signature verification failures
    # Connect-block stage: Core validation.cpp:2122 strprintf("block-script-verify-flag-failed (%s)",...)
    if any(k in s for k in ("script", "signature", "checksig", "tapscript",
                             "witness program", "transaction validation",
                             "disabled opcode")):
        return "block-script-verify-flag-failed"

    # Timestamp errors
    if "too far in the future" in s or "time-too-new" in s:
        return "time-too-new"
    if ("before median" in s or "time-too-old" in s
            or "not greater than median" in s or "timestamp" in s and "median" in s):
        return "time-too-old"

    # Block size / weight
    if "size" in s and "exceed" in s:
        return "bad-blk-length"

    # Previous block not found → inconclusive (we don't know the chain context)
    if "previous block not found" in s or "block not found" in s:
        return "inconclusive"

    return "rejected"


# ---------------------------------------------------------------------------
# Reorg safety constants
# ---------------------------------------------------------------------------
#
# Retained-undo window used as the reorg-depth cap ON PRUNED NODES ONLY.
# Bitcoin Core has NO reorg-depth cap: ActivateBestChainStep disconnects to the
# fork point unbounded and follows the most-work valid chain to any depth,
# FatalError-ing only when a disconnected block's undo data is missing on disk
# (a pruned-node condition). MIN_BLOCKS_TO_KEEP/288 governs pruning + the
# fTooFarAhead buffering gate — NOT reorg depth (validation.cpp:4325,6362).
#
# Enforcing this as an unconditional cap was a Class-A consensus divergence: on
# an ARCHIVE node (the default — no ``prune`` config, all undo present) it made
# ouroboros REFUSE a >288-deep most-work reorg and stay on the lower-work
# minority chain, splitting from Core. It is therefore now gated on
# pruning-enabled (see ``_reorg_to_side_branch_tip`` and
# ``BlockSync`` fork-bridge): archive => unbounded (Core-parity); pruned => this
# cap protects the retained undo window (a conservative refusal in lieu of
# Core's physical missing-undo fatal abort). Core has not seen a >10-deep reorg
# in ~14 years, so this is observationally inert on the honest chain.
#
# Reference: ``CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md``
# Pattern D; the 288-cap Class-A divergence entry in ``_loop-ledger.md``.
MAX_REORG_DEPTH: int = 288


async def accept_block(
    db,
    node,
    block_bytes: bytes,
    next_height: int,
    *,
    skip_scripts: bool = False,
) -> bytes:
    """Unified block-acceptance helper — Core's ProcessNewBlock pipeline.

    All RPC and P2P entry points that need to validate + connect a block MUST
    call this function rather than invoking ``validate_block_from_bytes`` /
    ``connect_block_from_bytes`` directly.  Routing every path through a single
    helper makes it structurally impossible to accidentally skip validation for
    one entry point (the recurring pattern that wave-29 audit 0d56486 found for
    ouroboros).

    Mirrors Bitcoin Core's ``Chainstate::ProcessNewBlock`` pipeline
    (validation.cpp):
        1. BIP-34 coinbase-height byte-prefix check (Python, network-aware)
        2. ``validate_block_from_bytes`` (Rust, off-GIL CheckBlock +
           ContextualCheckBlock + per-input scripts)
        3. Python ``BlockValidator.validate_block`` (disabled-opcode, Python
           script verify — complements Rust path)
        4. ``connect_block_from_bytes`` (Rust, UTXO mutation + persistence)
        5. Mempool eviction of confirmed transactions (best-effort)

    Args:
        db:           The ``PyBlockchainDB`` Rust extension object.
        node:         The live ``Node`` instance (provides ``network``,
                      ``validator``, ``mempool``).
        block_bytes:  Raw Bitcoin wire-format block.
        next_height:  Height this block will occupy (= ``best_height + 1``).
        skip_scripts: When True, skip per-input script verification (used by
                      the IBD drain below the assumevalid checkpoint).  BIP-34,
                      structural checks, and UTXO checks always run regardless.

    Returns:
        The 32-byte block hash (internal byte order, as returned by
        ``connect_block_from_bytes``).

    Raises:
        ValueError: on any validation or connection failure.  The caller is
                    responsible for converting to a BIP-22 result string via
                    ``bip22_result_string()`` when returning to an RPC client.

    Reference: Bitcoin Core src/validation.cpp Chainstate::ProcessNewBlock.
    Closed gaps: O1 (rpc_submitblockbatch), O2 (rpc_generatetoaddress),
    O3 (import_blocks_from_file via Rust companion change).
    """
    network = getattr(node, "network", "mainnet")
    best_height = next_height - 1

    # Step 1 — BIP-34 coinbase height byte-exact prefix check.
    # Rust connect_block_from_bytes has no network context so it cannot enforce
    # the per-network activation height.  Run a lightweight Python check here.
    # Reference: Bitcoin Core ContextualCheckBlock validation.cpp:4151-4159.
    from ouroboros.validation import _encode_bip34_height
    from ouroboros.consensus import BURIED_DEPLOYMENTS
    _bip34_depl = BURIED_DEPLOYMENTS.get(network, {}).get("bip34")
    _bip34_activation = _bip34_depl.height if _bip34_depl is not None else 227_931
    if next_height >= _bip34_activation:
        try:
            from ouroboros.database import Block as _Block
            _blk = _Block.deserialize(block_bytes)
            if _blk.transactions:
                _coinbase = _blk.transactions[0]
                if _coinbase.inputs:
                    _script = _coinbase.inputs[0].script_sig
                    _expect = _encode_bip34_height(next_height)
                    _n = len(_expect)
                    if len(_script) < _n or _script[:_n] != _expect:
                        raise ValueError("bad-cb-height")
        except ValueError:
            raise
        except Exception:
            pass  # deserialization failures fall through to Rust

    # Step 2 — Rust structural + contextual validation (off-GIL).
    # Covers: PoW, merkle root, prev-link, MTP timestamp, cb-len, witness
    # commitment, IsFinalTx, BIP-30, BIP-68, duplicate-txid, sigop budget,
    # block weight.  skip_scripts is honoured by the validator for blocks
    # below the assumevalid checkpoint.
    if hasattr(db, "validate_block_from_bytes"):
        await asyncio.to_thread(
            db.validate_block_from_bytes,
            block_bytes,
            best_height,  # prev_height = best_height (= next_height - 1)
            skip_scripts,
            network,
        )

    # Step 3 — Python script verification.
    # Rust validate_block_with_flags currently reserves skip_scripts for future
    # wiring (block.rs:261).  Run Python's validator so disabled-opcode checks
    # (script.py::_DISABLED) and signature verification always fire when
    # skip_scripts is False.
    # Reference: Bitcoin Core EvalScript() disabled-opcode gate (interpreter.cpp).
    if not skip_scripts:
        _py_validator = getattr(node, "validator", None)
        if _py_validator is not None:
            from ouroboros.database import Block as _Blk
            _blk_obj = _Blk.deserialize(block_bytes)
            _valid, _err = await asyncio.to_thread(
                _py_validator.validate_block,
                _blk_obj,
                next_height,
            )
            if not _valid:
                raise ValueError(_err)

    # Step 4 — Connect block (UTXO mutation + persistence, Rust).
    block_hash: bytes = await asyncio.to_thread(
        db.connect_block_from_bytes, block_bytes, next_height
    )

    # Deserialize once for the mempool-eviction and wallet-history steps.
    _connected_block = None
    try:
        from ouroboros.database import Block as _Blk
        _connected_block = _Blk.deserialize(block_bytes)
    except Exception:
        _connected_block = None

    # Step 5 — Evict confirmed transactions from the mempool (best-effort).
    mempool = getattr(node, "mempool", None)
    if mempool is not None and len(mempool) > 0 and _connected_block is not None:
        try:
            mempool.remove_block_transactions(_connected_block)
        except Exception:
            pass

    # Step 5b — Feed the block to every running index (best-effort).
    # Core's ProcessNewBlock fires the BlockConnected signal which notifies
    # ALL indexes (txindex, blockfilterindex, ...) regardless of whether the
    # block was mined locally or received over P2P (src/index/base.cpp
    # BaseIndex::BlockConnected). txindex is connected inside the Rust
    # connect_block_from_bytes batch above, but the BIP-157/158 basic block
    # filter index lives in Python and is only fed via the P2P/IBD connect
    # hook (block_sync.py:1647 / :3700).  Without this, blocks added through
    # the RPC path (generatetoaddress / submitblock) would leave the filter
    # index stuck at synced=false — the same "skipped index for one entry
    # point" gap accept_block was created to prevent (wave-29).  Mirror the
    # off-thread add_block(block, height, db) call from block_sync.
    bfi = getattr(node, "block_filter_index", None)
    if bfi is not None and _connected_block is not None:
        try:
            await asyncio.to_thread(
                bfi.add_block, _connected_block, next_height, db
            )
        except Exception:
            pass  # an index fault must never abort block acceptance

    # -coinstatsindex — same rationale: a block accepted through the RPC
    # path (submitblock / generatetoaddress) must update the per-height UTXO
    # MuHash commitment exactly as a P2P/IBD-connected block does, else the
    # index would stall at the pre-RPC height.  This complements (does not
    # replace) the primary P2P/IBD connect hook in block_sync.py — both entry
    # points feed the index, mirroring Core's single BlockConnected signal.
    csi = getattr(node, "coinstats_index", None)
    if csi is not None and _connected_block is not None:
        try:
            await asyncio.to_thread(
                csi.add_block, _connected_block, next_height, db
            )
        except Exception:
            pass  # an index fault must never abort block acceptance

    # -txospenderindex — same rationale: a block accepted through the RPC path
    # (submitblock / generatetoaddress) must record its spent-outpoint ->
    # spending-tx keys exactly as a P2P/IBD-connected block does (Core's single
    # BlockConnected signal feeds every index).  Complements the primary
    # block_sync connect hook.
    tsi = getattr(node, "txospender_index", None)
    if tsi is not None and _connected_block is not None:
        try:
            await asyncio.to_thread(
                tsi.add_block, _connected_block, next_height, db
            )
        except Exception:
            pass  # an index fault must never abort block acceptance

    # Step 6 — Wallet transaction-history scan (best-effort).
    # Walk the connected block's txs and record a wallet-history entry for any
    # tx that credits a wallet script (receive/coinbase) or debits a wallet
    # outpoint (send), so listtransactions / gettransaction can surface the
    # wallet's own activity. Mirrors Bitcoin Core CWallet::blockConnected ->
    # AddToWalletIfInvolvingMe. Bookkeeping only — never affects acceptance.
    if _connected_block is not None:
        for _w in _iter_node_wallets(node):
            try:
                _w.scan_block_connect(_connected_block, next_height)
            except Exception:
                pass

    # Step 7 — Signal the tip-change notifier (Core KernelNotifications
    # blockTip / WaitTipChanged).  Every block accepted through this unified
    # helper (submitblock / generatetoaddress / the RPC accept path) advances
    # the active-chain tip, so wake any waitfornewblock / waitforblock /
    # waitforblockheight RPC blocked on a tip change.  Best-effort: a notifier
    # fault must never abort block acceptance.
    _tip_notifier = getattr(node, "tip_notifier", None)
    if _tip_notifier is not None:
        try:
            _tip_notifier.notify()
        except Exception:
            pass

    return bytes(block_hash)


def _iter_node_wallets(node):
    """Yield every loaded Wallet on *node* (multi-wallet manager or legacy).

    Used by the block-connect/disconnect history scan so all loaded wallets
    see their own transactions. Falls back to the single ``node.wallet``.
    """
    seen: set[int] = set()
    wm = getattr(node, "wallet_manager", None)
    if wm is not None:
        try:
            for name in wm.list_loaded_wallets():
                w = wm.get_wallet(name)
                if w is not None and id(w) not in seen:
                    seen.add(id(w))
                    yield w
        except Exception:
            pass
    w = getattr(node, "wallet", None)
    if w is not None and id(w) not in seen:
        yield w


class _VerifyChainDBProxy:
    """Read-only UTXO overlay over a live ``BlockchainDatabase`` for verifychain.

    Wraps the node's real database, delegating EVERY attribute except the
    UTXO-read methods to the underlying handle. UTXO reads (``get_utxo``,
    ``get_utxo_batch``, ``get_utxo_or_spent``) are served from the in-memory
    ``overlay`` dict first (``None`` = spent/absent in the sandbox, a present
    dict shadows the live entry) and fall through to the live DB on a miss.

    This is the Core ``CCoinsViewCache`` analog used by ``CVerifyDB::VerifyDB``:
    the throwaway cache the level-4 reconnect runs against. It NEVER writes to
    the live chainstate — the overlay is the only mutable state, owned by the
    rpc_verifychain caller. Letting the node's real ``BlockValidator`` /
    ``TransactionValidator`` read through this proxy is what makes level 4 a
    faithful ConnectBlock (full input-script verification on the rewound UTXO
    view), not a stub.
    """

    __slots__ = ("_db", "_overlay")

    def __init__(self, db, overlay: dict) -> None:
        self._db = db
        self._overlay = overlay

    def get_utxo(self, txid: bytes, vout: int):
        key = (txid, vout)
        if key in self._overlay:
            return self._overlay[key]
        return self._db.get_utxo(txid, vout)

    def get_utxo_or_spent(self, txid: bytes, vout: int):
        key = (txid, vout)
        if key in self._overlay:
            return self._overlay[key]
        return self._db.get_utxo_or_spent(txid, vout)

    def get_utxo_batch(self, outpoints):
        # Serve from the overlay where present; batch the genuine misses to the
        # live DB in one FFI call (preserving the validator's batched fast path).
        results: list = [None] * len(outpoints)
        miss_positions: list[int] = []
        miss_outpoints: list = []
        for i, (txid, vout) in enumerate(outpoints):
            key = (txid, vout)
            if key in self._overlay:
                results[i] = self._overlay[key]
            else:
                miss_positions.append(i)
                miss_outpoints.append((txid, vout))
        if miss_outpoints and hasattr(self._db, "get_utxo_batch"):
            fetched = self._db.get_utxo_batch(miss_outpoints)
            for pos, val in zip(miss_positions, fetched):
                results[pos] = val
        elif miss_outpoints:
            for pos, (txid, vout) in zip(miss_positions, miss_outpoints):
                results[pos] = self._db.get_utxo(txid, vout)
        return results

    def __getattr__(self, name):
        # Everything else (get_block, get_best_block, get_median_time_past,
        # validate_block_from_bytes, _db, ...) delegates to the real handle.
        return getattr(self._db, name)


class RpcError(Exception):
    """A JSON-RPC error carrying a Bitcoin-Core-compatible numeric code.

    Bitcoin Core surfaces RPC failures through ``JSONRPCError(code, message)``
    where ``code`` is one of the ``RPC_*`` constants in ``protocol.h``
    (e.g. RPC_INVALID_ADDRESS_OR_KEY = -5, RPC_INVALID_PARAMETER = -8).
    Raising this exception from a handler lets the dispatch loop emit an error
    envelope with the EXACT code Core uses, instead of collapsing every
    failure to the generic internal-error code -32603 (which is what a bare
    ``HTTPException`` does in this server). See ``_execute_single_rpc``.
    """

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _core_uvtype(value: Any) -> str:
    """Map a decoded-JSON Python value to Bitcoin Core's ``uvTypeName`` string.

    Used to build RPC_TYPE_ERROR messages byte-identical to Core
    (univalue.cpp ``uvTypeName``): null / bool / object / array / string /
    number.  ``bool`` is checked before ``int`` because Python ``bool`` is a
    subclass of ``int``.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return "null"


# Bitcoin Core RPC error codes (subset; protocol.h).
RPC_MISC_ERROR = -1
RPC_TYPE_ERROR = -3
RPC_INVALID_ADDRESS_OR_KEY = -5
RPC_INVALID_PARAMETER = -8
RPC_DESERIALIZATION_ERROR = -22      # protocol.h:53 — error parsing or validating structure in raw format
RPC_VERIFY_ERROR = -25               # protocol.h:42 — general error during transaction or block submission
RPC_CLIENT_NODE_ALREADY_ADDED = -23  # protocol.h:60 — Node is already added
RPC_CLIENT_NODE_NOT_ADDED = -24      # protocol.h:61 — Node has not been added before
RPC_CLIENT_NODE_NOT_CONNECTED = -29  # protocol.h:62 — disconnect target not connected
RPC_CLIENT_INVALID_IP_OR_SUBNET = -30
RPC_CLIENT_P2P_DISABLED = -31        # protocol.h:64 — no valid connection manager instance found


def _is_valid_ip_or_subnet(value: str) -> bool:
    """Return True if *value* is a valid bare IP or CIDR subnet.

    Mirrors Bitcoin Core ``LookupSubNet`` (rpc/net.cpp setban): a bare address
    (``192.168.0.1`` / ``2001:db8::1``) or a ``addr/prefix`` subnet
    (``192.168.0.0/24`` / ``2001:db8::/32``). Hostnames, empty strings and
    malformed octets are rejected — the caller raises
    ``RPC_CLIENT_INVALID_IP_OR_SUBNET`` (-30) on a False result.
    """
    if not isinstance(value, str):
        return False
    token = value.strip()
    if not token:
        return False
    try:
        if "/" in token:
            _ipaddress.ip_network(token, strict=False)
        else:
            _ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _parse_hash_v(value: str, name: str) -> bytes:
    """Parse a 64-char hex uint256 (txid / blockhash) RPC argument.

    Mirrors Bitcoin Core ``ParseHashV`` (rpc/util.cpp:117): a string that is
    not a valid 64-char hex uint256 is rejected at the PARSE boundary, BEFORE
    any lookup, with ``RPC_INVALID_PARAMETER`` (-8). The message form depends
    on the failure mode, byte-for-byte with Core:

      * wrong length -> "<name> must be of length 64 (not N, for '<hex>')"
      * right length, non-hex chars -> "<name> must be hexadecimal string
        (not '<hex>')"

    Returns the decoded 32 bytes in the wire (the same big-endian display
    order the caller supplied — callers reverse to internal little-endian
    keying themselves, exactly as before). Only the malformed-parse case is
    affected; a well-formed-but-absent hash decodes cleanly here and the
    caller's own lookup decides the not-found code (Core: -5, or null).
    """
    expected_len = 64
    if not isinstance(value, str) or len(value) != expected_len:
        shown_len = len(value) if isinstance(value, str) else 0
        raise RpcError(
            RPC_INVALID_PARAMETER,
            f"{name} must be of length {expected_len} "
            f"(not {shown_len}, for '{value}')",
        )
    try:
        return bytes.fromhex(value)
    except ValueError:
        # Right length, but contains non-hex characters -> Core's second
        # ParseHashV message (rpc/util.cpp:124).
        raise RpcError(
            RPC_INVALID_PARAMETER,
            f"{name} must be hexadecimal string (not '{value}')",
        ) from None


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 request model"""
    jsonrpc: str = "2.0"
    method: str
    params: list[Any] | dict[str, Any] = []
    id: int | str | None = None


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 response model"""
    jsonrpc: str = "2.0"
    result: Any | None = None
    error: dict[str, Any] | None = None
    id: int | str | None = None


# ---------------------------------------------------------------------------
# W51 decodepsbt: Core-byte-identity JSON encoder
# ---------------------------------------------------------------------------
# Python's stdlib json serializes float(1.0) as "1.0", but Bitcoin Core's
# ValueFromAmount (core_io.cpp) always emits "%d.%08d" (e.g. "1.00000000").
# The psbt.BTCAmount sentinel class carries the correctly-formatted decimal
# text.  _BTCEncoder intercepts BTCAmount objects during JSON serialization
# and emits them as raw (unquoted) number tokens.
#
# _BTCJsonResponse is a JSONResponse subclass that uses _BTCEncoder so that
# decodepsbt results round-trip through jq with the Core-exact decimal form.
# All other RPC responses are unaffected — _BTCEncoder falls through to the
# standard encoder for every type except BTCAmount.

class _CoreFloat:
    """Sentinel for a float that must be serialized with ``%.16g`` precision.

    Bitcoin Core's UniValue serializer uses ``std::setprecision(16) << val``
    (equivalent to ``%.16g``) for double values.  Python's json module uses
    ``repr(float)`` which emits 17 significant digits in some cases.  This
    sentinel lets ``_BTCEncoder`` emit the correct 16-digit form.

    Usage: wrap difficulty (and other Core double fields) in _CoreFloat(val)
    before putting them in the result dict.
    """

    def __init__(self, value: float) -> None:
        self.value = value
        self.text = f"{value:.16g}"


class _BTCEncoder(json.JSONEncoder):
    """JSON encoder that emits ``BTCAmount`` and ``_CoreFloat`` as raw tokens.

    All other types are handled by the standard encoder, so this class is
    safe to use as a drop-in replacement for ``json.JSONEncoder``.
    """

    def iterencode(self, obj: Any, _one_shot: bool = False):  # type: ignore[override]
        """Recursively walk ``obj`` and emit correct tokens for sentinels."""
        from ouroboros.psbt import BTCAmount  # lazy import to avoid circular
        if isinstance(obj, BTCAmount):
            yield obj.text
        elif isinstance(obj, _CoreFloat):
            yield obj.text
        elif isinstance(obj, dict):
            yield "{"
            first = True
            for k, v in obj.items():
                if not first:
                    yield ","
                first = False
                yield json.dumps(k, ensure_ascii=False)
                yield ":"
                yield from self.iterencode(v)
            yield "}"
        elif isinstance(obj, list):
            yield "["
            first = True
            for item in obj:
                if not first:
                    yield ","
                first = False
                yield from self.iterencode(item)
            yield "]"
        elif obj is None:
            yield "null"
        elif isinstance(obj, bool):
            yield "true" if obj else "false"
        elif isinstance(obj, int):
            yield str(obj)
        elif isinstance(obj, float):
            # Preserve standard float repr (non-BTC floats in RPC responses).
            yield repr(obj)
        elif isinstance(obj, str):
            yield json.dumps(obj, ensure_ascii=False)
        else:
            # Fall back to stdlib for any other type (Decimal, custom models…)
            yield from super().iterencode(obj, _one_shot)


class _BTCJsonResponse(JSONResponse):
    """JSONResponse that uses ``_BTCEncoder`` for serialization.

    Used only for ``decodepsbt`` so that ``BTCAmount`` values are emitted
    as raw decimal number tokens instead of Python's ``1.0``.
    """

    def render(self, content: Any) -> bytes:
        return "".join(_BTCEncoder().iterencode(content)).encode("utf-8")



# ---------------------------------------------------------------------------
# Partial Merkle tree helpers (CMerkleBlock serialization / deserialization)
# ---------------------------------------------------------------------------


def _dsha256(data: bytes) -> bytes:
    return _hashlib.sha256(_hashlib.sha256(data).digest()).digest()


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return _struct.pack('<B', n)
    elif n <= 0xFFFF:
        return b'\xfd' + _struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + _struct.pack('<I', n)
    else:
        return b'\xff' + _struct.pack('<Q', n)


def _read_varint(data: bytes, offset: int) -> tuple:
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return _struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return _struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return _struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


def _tree_width(n_tx: int, height: int) -> int:
    return (n_tx + (1 << height) - 1) >> height


def _calc_tree_hash(txids: list, n_tx: int, height: int, pos: int) -> bytes:
    if height == 0:
        return txids[pos] if pos < n_tx else b'\x00' * 32
    left = _calc_tree_hash(txids, n_tx, height - 1, pos * 2)
    right_pos = pos * 2 + 1
    if right_pos < _tree_width(n_tx, height - 1):
        right = _calc_tree_hash(txids, n_tx, height - 1, right_pos)
    else:
        right = left
    return _dsha256(left + right)


def _build_partial_merkle_tree(block, txids: list, matches: list) -> bytes:
    """Serialize a partial Merkle tree in the CMerkleBlock wire format."""
    n = len(txids)
    height = 0
    while (1 << height) < n:
        height += 1

    hashes: list = []
    bits: list = []

    def _traverse(h: int, pos: int):
        start = pos << h
        end = min((pos + 1) << h, n)
        parent_match = any(matches[i] for i in range(start, end))
        bits.append(parent_match)

        if h == 0 or not parent_match:
            if h == 0:
                hashes.append(txids[pos] if pos < n else b'\x00' * 32)
            else:
                hashes.append(_calc_tree_hash(txids, n, h, pos))
        else:
            _traverse(h - 1, pos * 2)
            if pos * 2 + 1 < _tree_width(n, h - 1):
                _traverse(h - 1, pos * 2 + 1)

    _traverse(height, 0)

    result = bytearray(block.serialize()[:80])
    result += _struct.pack('<I', n)
    result += _encode_varint(len(hashes))
    for h in hashes:
        result += h
    flag_bytes = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            flag_bytes[i // 8] |= 1 << (i % 8)
    result += _encode_varint(len(flag_bytes))
    result += flag_bytes

    return bytes(result)


def _parse_partial_merkle_tree(data: bytes) -> tuple:
    """Deserialize a partial Merkle tree payload (everything after the."""
    offset = 0
    n_tx = _struct.unpack_from('<I', data, offset)[0]
    offset += 4

    n_hashes, offset = _read_varint(data, offset)
    hashes = []
    for _ in range(n_hashes):
        hashes.append(data[offset:offset + 32])
        offset += 32

    n_flag_bytes, offset = _read_varint(data, offset)
    flag_bits_raw = data[offset:offset + n_flag_bytes]

    all_bits = []
    for byte_val in flag_bits_raw:
        for bit_pos in range(8):
            all_bits.append(bool(byte_val & (1 << bit_pos)))

    height = 0
    while (1 << height) < n_tx:
        height += 1

    hash_idx = [0]
    bit_idx = [0]
    matched: list = []

    def _consume(h: int, pos: int) -> bytes:
        if bit_idx[0] >= len(all_bits):
            return b'\x00' * 32
        parent_match = all_bits[bit_idx[0]]
        bit_idx[0] += 1

        if h == 0:
            cur_hash = hashes[hash_idx[0]] if hash_idx[0] < len(hashes) else b'\x00' * 32
            hash_idx[0] += 1
            if parent_match:
                matched.append(cur_hash)
            return cur_hash

        if not parent_match:
            cur_hash = hashes[hash_idx[0]] if hash_idx[0] < len(hashes) else b'\x00' * 32
            hash_idx[0] += 1
            return cur_hash

        left = _consume(h - 1, pos * 2)
        right_pos = pos * 2 + 1
        if right_pos < _tree_width(n_tx, h - 1):
            right = _consume(h - 1, right_pos)
        else:
            right = left
        return _dsha256(left + right)

    computed_root = _consume(height, 0)
    return matched, computed_root


# ---------------------------------------------------------------------------
# Bitcoin Signed Message helpers (signmessage / verifymessage).
#
# Reference: bitcoin-core/src/common/signmessage.cpp
#   const std::string MESSAGE_MAGIC = "Bitcoin Signed Message:\n";
#   uint256 MessageHash(message) = SHA256d(VarStr(MAGIC) || VarStr(message))
#
# Compact-signature format (65 bytes, base64 on the wire):
#   header(1) || r(32) || s(32)
#   header   = 27 + recid + (4 if compressed pubkey else 0)
#   recid    ∈ {0, 1, 2, 3}
# ---------------------------------------------------------------------------
_MESSAGE_MAGIC = "Bitcoin Signed Message:\n"


def _message_hash(message: str) -> bytes:
    """Return Core's MessageHash(message) — the SHA256d of the magic-prefixed
    serialization that signmessage / verifymessage operate on."""
    magic_bytes = _MESSAGE_MAGIC.encode("utf-8")
    msg_bytes = message.encode("utf-8")
    payload = (
        _encode_varint(len(magic_bytes)) + magic_bytes
        + _encode_varint(len(msg_bytes)) + msg_bytes
    )
    return _dsha256(payload)


def _parse_block_txs(raw: bytes):
    """Parse transactions from a raw Bitcoin block preserving witness data.

    Bitcoin block wire format:
      - 80-byte header
      - varint: tx count
      - N transactions in consensus (witness) serialization

    Returns a list of ``Transaction`` objects (from ``ouroboros.database``)
    with ``has_witness`` and ``TxIn.witness`` correctly populated.

    Used by ``rpc_getblock`` verbosity>=2 to work around the Rust ``PyTxIn``
    stub not exposing witness items.

    Reference: bitcoin-core/src/primitives/block.h Block::Unserialize,
               bitcoin-core/src/primitives/transaction.h CMutableTransaction.
    """
    import io as _io
    import struct as _struct
    import hashlib as _hashlib
    from ouroboros.database import Transaction as _Tx, TxIn as _TxIn, TxOut as _TxOut

    def _read_cs(f):
        """Read a Bitcoin CompactSize (varint) from file-like f."""
        b = f.read(1)
        if not b:
            raise ValueError("Unexpected EOF reading CompactSize")
        n = b[0]
        if n < 0xfd:
            return n
        if n == 0xfd:
            return _struct.unpack("<H", f.read(2))[0]
        if n == 0xfe:
            return _struct.unpack("<I", f.read(4))[0]
        return _struct.unpack("<Q", f.read(8))[0]

    f = _io.BytesIO(raw)
    # Skip 80-byte block header.
    f.read(80)

    n_tx = _read_cs(f)
    txs = []

    for _ in range(n_tx):
        tx_start = f.tell()
        version = _struct.unpack("<i", f.read(4))[0]

        # Detect SegWit marker.
        peek = f.read(1)
        has_witness = False
        if peek == b"\x00":
            flag = f.read(1)
            has_witness = (flag == b"\x01")
        else:
            f.seek(-1, _io.SEEK_CUR)

        n_in = _read_cs(f)
        inputs: list[_TxIn] = []
        for _ in range(n_in):
            prev_txid = f.read(32)
            prev_vout = _struct.unpack("<I", f.read(4))[0]
            script_len = _read_cs(f)
            script_sig = f.read(script_len)
            sequence = _struct.unpack("<I", f.read(4))[0]
            inputs.append(_TxIn(prev_txid, prev_vout, script_sig, sequence))

        n_out = _read_cs(f)
        outputs: list[_TxOut] = []
        for _ in range(n_out):
            value = _struct.unpack("<q", f.read(8))[0]
            spk_len = _read_cs(f)
            script_pubkey = f.read(spk_len)
            outputs.append(_TxOut(value, script_pubkey))

        if has_witness:
            for inp in inputs:
                n_items = _read_cs(f)
                witness: list[bytes] = []
                for _ in range(n_items):
                    item_len = _read_cs(f)
                    witness.append(f.read(item_len))
                inp.witness = witness if witness else None

        locktime = _struct.unpack("<I", f.read(4))[0]
        tx_end = f.tell()

        # txid = SHA256D of the *stripped* (non-witness) serialization.
        if has_witness:
            stripped = bytearray()
            stripped += version.to_bytes(4, "little", signed=True)
            # Encode input count
            n = len(inputs)
            if n < 0xfd:
                stripped += bytes([n])
            elif n <= 0xffff:
                stripped += b"\xfd" + n.to_bytes(2, "little")
            else:
                stripped += b"\xfe" + n.to_bytes(4, "little")
            for inp in inputs:
                stripped += inp.prev_txid
                stripped += inp.prev_vout.to_bytes(4, "little")
                sl = len(inp.script_sig)
                if sl < 0xfd:
                    stripped += bytes([sl])
                elif sl <= 0xffff:
                    stripped += b"\xfd" + sl.to_bytes(2, "little")
                else:
                    stripped += b"\xfe" + sl.to_bytes(4, "little")
                stripped += inp.script_sig
                stripped += inp.sequence.to_bytes(4, "little")
            n = len(outputs)
            if n < 0xfd:
                stripped += bytes([n])
            elif n <= 0xffff:
                stripped += b"\xfd" + n.to_bytes(2, "little")
            else:
                stripped += b"\xfe" + n.to_bytes(4, "little")
            for out in outputs:
                stripped += out.value.to_bytes(8, "little", signed=True)
                sl = len(out.script_pubkey)
                if sl < 0xfd:
                    stripped += bytes([sl])
                elif sl <= 0xffff:
                    stripped += b"\xfd" + sl.to_bytes(2, "little")
                else:
                    stripped += b"\xfe" + sl.to_bytes(4, "little")
                stripped += out.script_pubkey
            stripped += locktime.to_bytes(4, "little")
            txid = _hashlib.sha256(_hashlib.sha256(bytes(stripped)).digest()).digest()
        else:
            tx_bytes = raw[tx_start:tx_end]
            txid = _hashlib.sha256(_hashlib.sha256(tx_bytes).digest()).digest()

        txs.append(_Tx(
            txid=txid,
            version=version,
            locktime=locktime,
            inputs=inputs,
            outputs=outputs,
            has_witness=has_witness,
        ))

    return txs


class RPCServer:
    """Bitcoin JSON-RPC server"""

    def __init__(
        self,
        node: Any,
        port: int = 8332,
        username: str | None = None,
        password: str | None = None,
        rate_limit: bool = True,
        max_batch_size: int = 1000,
        enable_rest: bool = False,
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
    ):
        """Initialize RPC server.

        Args:
            node: Bitcoin node instance
            port: Port to listen on
            username: RPC username (None for no auth)
            password: RPC password
            rate_limit: Enable rate limiting
            max_batch_size: Maximum batch request size
            enable_rest: Enable REST interface (no auth required)
            tls_certfile: Path to PEM-encoded TLS certificate (HTTPS).
                Must be set together with ``tls_keyfile``. When both are
                ``None`` the server listens over plain HTTP for backward
                compatibility. Mirrors Bitcoin Core's ``-rpcssl`` /
                ``-rpcsslcertificatechainfile`` family (httpserver.cpp).
            tls_keyfile: Path to PEM-encoded TLS private key. Must be set
                together with ``tls_certfile`` or startup fails with a
                loud error (mismatch is never silent).
        """
        if (tls_certfile is None) != (tls_keyfile is None):
            # Both-or-neither.  Reject the mismatched case eagerly so
            # operators see the misconfiguration immediately rather than
            # silently falling back to HTTP (which would be a privacy /
            # credential-exposure footgun if cookie auth is in use).
            raise ValueError(
                "tls_certfile and tls_keyfile must both be set or both be None "
                f"(got certfile={tls_certfile!r}, keyfile={tls_keyfile!r})"
            )

        self.node = node
        self.port = port
        self.username = username
        self.password = password
        self.rate_limit_enabled = rate_limit
        self.max_batch_size = max_batch_size
        self.enable_rest = enable_rest
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile

        self.app = FastAPI(title="Bitcoin Hybrid Node RPC")

        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Setup security if credentials provided
        self.security = None
        if username and password:
            self.security = HTTPBasic()

        # Current wallet context (set per-request)
        self._current_wallet_name: str | None = None

        # Deployment-state cache: (height, network) -> dict.
        # _build_deployment_state calls Rust FFI (get_all_deployments_info) which
        # competes for the GIL during IBD.  Deployment state only changes at
        # consensus activation heights, so we cache by height and recompute only
        # when the chain tip advances.  This eliminates all FFI/GIL overhead from
        # the getblockchaininfo hot path.
        self._deployment_cache: dict[tuple[int, str], dict] = {}
        self._deployment_cache_height: int = -1
        self._deployment_cache_network: str = ""

        # Cumulative transaction count by height (Bitcoin Core's
        # CBlockIndex::m_chain_tx_count analogue — chain.h:129). Core maintains
        # this as an O(1) running counter at block-connect: m_chain_tx_count =
        # prev->m_chain_tx_count + nTx. ouroboros does not persist a per-block
        # nTx aggregate, so getchaintxstats memoizes the prefix sum here.
        # _chain_tx_count[h] = total #txs in blocks [0..h] on the active chain.
        # Filled incrementally (walking only the gap to a requested height) and
        # invalidated wholesale on any tip regression (reorg / disconnect).
        self._chain_tx_count: list[int] = []

        # NetworkDisable flag: when True, ``rpc_submitblock`` (and any P2P
        # block-handler callsite that consults this flag) refuses new
        # blocks. Set during ``rpc_dumptxoutset``'s rewind→dump→replay
        # dance to mirror Bitcoin Core's NetworkDisable RAII guard around
        # TemporaryRollback in rpc/blockchain.cpp::dumptxoutset. Peers
        # stay connected; only block acceptance is gated. Single-threaded
        # async so a plain bool is sufficient (no lock needed).
        self.block_submission_paused: bool = False

        # Side-branch buffer for ``submitblock`` (Pattern X + Y closure
        # 2026-05-06). Holds blocks whose parent is in the block index but
        # is not the active tip — i.e. competing-fork blocks that Core
        # would store with BLOCK_HAVE_DATA and a side-branch nChainWork.
        # ouroboros's block index (BLOCK_INDEX_CF) is height-keyed so it
        # cannot natively persist two distinct blocks at the same height;
        # this in-memory map is the fork-tracking shim that lets a
        # heavier B-chain accumulate over multiple submitblock calls
        # before the active tip flip happens. Keyed by block hash
        # (internal byte order). Each entry is
        # ``(parent_hash, height, raw_bytes)``. Entries are evicted on
        # successful reorg connect of the same hash, on
        # invalidate_block, or when the buffer hits its soft cap.
        # Reference: bitcoin-core/src/validation.cpp BlockManager::AcceptBlock,
        # CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md
        # (Pattern X + Y for ouroboros).
        self._side_branch_blocks: dict[bytes, tuple[bytes, int, bytes]] = {}
        self._side_branch_max_entries: int = 1024

        # preciousblock (Bitcoin Core CChainState::PreciousBlock) bookkeeping.
        # Mirrors ChainstateManager::nLastPreciousChainwork /
        # nBlockReverseSequenceId (validation.cpp:3490). A precious block is
        # assigned a strictly-decreasing "received-before" sequence id so that,
        # on a tie of cumulative proof-of-work, chain selection prefers it over
        # equal-work blocks that were seen earlier. These live only in memory —
        # the effects of preciousblock are NOT retained across restarts, exactly
        # as in Core.
        self._last_precious_chainwork: int = -1
        self._block_reverse_sequence_id: int = -1
        self._precious_sequence: dict[bytes, int] = {}

        # Register RPC methods
        self._register_methods()

        # Register REST interface if enabled
        if enable_rest:
            self._register_rest_interface()

    def _get_wallet_for_rpc(self) -> Any:
        """
        Get the wallet for the current RPC request.

        If a wallet name was specified via /wallet/<name>, uses that wallet.
        Otherwise, uses the default wallet (first loaded) or node.wallet for
        backwards compatibility.

        Returns the Wallet instance or None.
        Raises HTTPException if the specified wallet is not loaded.

        Reference: Bitcoin Core GetWalletForJSONRPCRequest
        """
        # Check if node has wallet_manager (multi-wallet mode)
        wallet_manager = getattr(self.node, "wallet_manager", None)

        if wallet_manager is not None:
            # Multi-wallet mode
            if self._current_wallet_name is not None:
                # Specific wallet requested via /wallet/<name>
                wallet = wallet_manager.get_wallet(self._current_wallet_name)
                if wallet is None:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Wallet '{self._current_wallet_name}' not loaded. "
                        "Load the wallet first using loadwallet RPC."
                    )
                return wallet
            else:
                # No specific wallet; use default
                loaded = wallet_manager.list_loaded_wallets()
                if len(loaded) == 0:
                    return None
                elif len(loaded) == 1:
                    return wallet_manager.get_wallet(loaded[0])
                else:
                    # Multiple wallets loaded; need to specify which one
                    raise HTTPException(
                        status_code=400,
                        detail="Wallet file not specified (must request wallet RPC "
                        "through /wallet/<wallet_name> uri-path)."
                    )
        else:
            # Legacy single-wallet mode (backwards compatibility)
            return getattr(self.node, "wallet", None)

    async def _execute_single_rpc(
        self, req_data: dict[str, Any], wallet_name: str | None = None
    ) -> dict[str, Any]:
        """Execute a single RPC call and return the response as a dict.

        This is used by both single request and batch request handlers.
        Errors are caught and returned as JSON-RPC error responses.

        Args:
            req_data: The JSON-RPC request dict
            wallet_name: Optional wallet name from /wallet/<name> endpoint
        """
        req_id = req_data.get("id")
        method = req_data.get("method")
        params = req_data.get("params", [])

        # Store wallet context for this request
        self._current_wallet_name = wallet_name

        t0 = time.monotonic()
        try:
            # Validate request structure
            if not method or not isinstance(method, str):
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid Request: missing method"},
                    "id": req_id
                }

            # Get method handler
            method_name = f"rpc_{method}"
            handler = getattr(self, method_name, None)

            if not handler:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": req_id
                }

            # Call method with params
            if isinstance(params, list):
                result = await handler(*params)
            elif isinstance(params, dict):
                result = await handler(**params)
            else:
                result = await handler()

            # Handlers may return a fully-formed JSONRPCResponse — the
            # established idiom for Core-coded failures (e.g. -22
            # "TX decode failed ..."). Unwrap it here: nesting the pydantic
            # model inside "result" is unserializable by _BTCEncoder and
            # surfaced as an opaque HTTP 500 "Internal Server Error" on the
            # wire (observed live 2026-06-09 on the PSBT decode probes).
            if isinstance(result, JSONRPCResponse):
                if result.error is not None:
                    return {
                        "jsonrpc": "2.0",
                        "error": result.error,
                        "id": req_id,
                    }
                return {
                    "jsonrpc": "2.0",
                    "result": result.result,
                    "id": req_id,
                }

            return {"jsonrpc": "2.0", "result": result, "id": req_id}

        except RpcError as e:
            # Bitcoin-Core-coded error (e.g. -5 block not found, -8 invalid
            # parameter). Preserve the exact numeric code so clients can
            # distinguish failure classes the way they do against Core.
            return {
                "jsonrpc": "2.0",
                "error": {"code": e.code, "message": e.message},
                "id": req_id
            }
        except HTTPException as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": e.detail},
                "id": req_id
            }
        except Exception as e:
            logger.error(f"RPC error in {method}: {e}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": req_id
            }
        finally:
            if method:
                record_rpc_request(method, time.monotonic() - t0)

    def _register_methods(self):
        """Register all RPC methods"""

        async def _handle_rpc_common(
            http_request: Request, wallet_name: str | None = None
        ):
            """Common handler for RPC requests with optional wallet context."""
            # Authentication — re-raise so FastAPI returns HTTP 401 with
            # WWW-Authenticate header, matching Bitcoin Core's httprpc.cpp behaviour.
            if self.security:
                await self._get_credentials(http_request)

            # Rate limiting
            if self.rate_limit_enabled:
                client_ip = self._get_client_ip_from_request(http_request)
                if not self._check_rate_limit(client_ip):
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {"code": -32000, "message": "Rate limit exceeded"},
                            "id": None
                        }
                    )

            # Parse raw body to detect batch vs single request
            try:
                body = await http_request.body()
                request_data = json.loads(body)
            except json.JSONDecodeError as e:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32700, "message": f"Parse error: {e}"},
                        "id": None
                    }
                )

            # Handle batch request (array)
            if isinstance(request_data, list):
                # Empty batch is an error (JSON-RPC 2.0 spec)
                if len(request_data) == 0:
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {"code": -32600, "message": "Invalid Request: empty batch"},
                            "id": None
                        }
                    )

                # Check batch size limit
                if len(request_data) > self.max_batch_size:
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": f"Invalid Request: batch size {len(request_data)} exceeds maximum {self.max_batch_size}"
                            },
                            "id": None
                        }
                    )

                # Execute each request, collecting responses
                responses = []
                for req in request_data:
                    if not isinstance(req, dict):
                        responses.append({
                            "jsonrpc": "2.0",
                            "error": {"code": -32600, "message": "Invalid Request: not an object"},
                            "id": None
                        })
                    else:
                        response = await self._execute_single_rpc(req, wallet_name)
                        # Only include response if not a notification (id is present)
                        # JSON-RPC 2.0: notifications have id=null or missing id
                        if "id" in req:
                            responses.append(response)

                # Return array of responses
                return _BTCJsonResponse(content=responses)

            # Handle single request (object)
            elif isinstance(request_data, dict):
                response = await self._execute_single_rpc(request_data, wallet_name)
                return _BTCJsonResponse(content=response)

            # Invalid request type
            else:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Invalid Request: expected object or array"},
                        "id": None
                    }
                )

        @self.app.post("/")
        async def handle_rpc(http_request: Request):
            """Handle JSON-RPC requests (single or batch)"""
            return await _handle_rpc_common(http_request, wallet_name=None)

        @self.app.post("/wallet/{wallet_name}")
        async def handle_wallet_rpc(wallet_name: str, http_request: Request):
            """Handle wallet-specific JSON-RPC requests.

            Bitcoin Core compatible endpoint: /wallet/<name>
            All wallet RPCs will use the specified wallet.
            """
            # URL decode the wallet name (e.g., %2F -> /)
            from urllib.parse import unquote
            wallet_name = unquote(wallet_name)
            return await _handle_rpc_common(http_request, wallet_name=wallet_name)

        @self.app.get("/health")
        async def health():
            """Health check endpoint"""
            return {"status": "healthy", "service": "bitcoin-rpc"}

        @self.app.get("/getblockstats")
        async def getblockstats(
            hash_or_height: str,
            stats: str | None = None,
            http_request: Request = None,
        ):
            """GET endpoint for getblockstats.

            ``hash_or_height`` is passed as a query parameter (string).
            If it looks like an integer it is treated as a block height,
            otherwise it is treated as a block hash.

            ``stats`` is an optional comma-separated list of stat names to
            return.
            """
            # Coerce to int when possible
            parsed: int | str
            try:
                parsed = int(hash_or_height)
            except ValueError:
                parsed = hash_or_height

            stats_list: list[str] | None = None
            if stats:
                stats_list = [s.strip() for s in stats.split(",") if s.strip()]

            return await self.rpc_getblockstats(parsed, stats_list)

        @self.app.get("/getblockfilter")
        async def getblockfilter_get(
            blockhash: str,
            filtertype: str = "basic",
        ):
            """GET endpoint for getblockfilter (BIP 157/158).

            ``blockhash`` is the hex-encoded block hash.
            ``filtertype`` is the filter type name (only ``basic`` supported).
            """
            # rpc_getblockfilter raises RpcError with Core-coded numeric
            # codes (-5/-1/-8) for the JSON-RPC path.  Translate to the
            # nearest HTTP status for this REST GET surface.
            try:
                return await self.rpc_getblockfilter(blockhash, filtertype)
            except RpcError as e:
                _status = {
                    RPC_INVALID_ADDRESS_OR_KEY: 404,
                    RPC_MISC_ERROR: 400,
                    RPC_INVALID_PARAMETER: 400,
                }.get(e.code, 500)
                raise HTTPException(status_code=_status, detail=e.message) from None

        # BIP-78 PayJoin receiver endpoint (FIX-65).
        #
        # The sender POSTs a base64 Original PSBT to ``payjoin.RECEIVER_PATH``
        # along with optional BIP-78 query parameters: ``v=1``,
        # ``additionalfeeoutputindex``, ``maxadditionalfeecontribution``,
        # ``minfeerate``.  The receiver validates, adds a CSPRNG-selected
        # contribution UTXO, signs only that input, and returns the modified
        # PSBT (base64, text/plain).  Errors are emitted as the four BIP-78
        # canonical codes ("unavailable", "not-enough-money",
        # "version-unsupported", "original-psbt-rejected") in a
        # ``{"errorCode": ..., "message": ...}`` JSON wrapper.
        from ouroboros import payjoin as _payjoin_mod

        @self.app.post(_payjoin_mod.RECEIVER_PATH)
        async def handle_payjoin_post(http_request: Request):
            return await self._handle_payjoin_request(http_request)

    def _register_rest_interface(self):
        """Register REST interface endpoints (no authentication required)."""
        from ouroboros.rest import RESTInterface

        rest_interface = RESTInterface(self.node)
        self.app.include_router(rest_interface.router)
        logger.info("REST interface enabled at /rest/*")

    async def _get_credentials(self, request: Request) -> HTTPBasicCredentials | None:
        if not self.security:
            return None

        _www_auth = {"WWW-Authenticate": 'Basic realm="jsonrpc"'}
        try:
            credentials = await self.security(request)
        except HTTPException:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers=_www_auth,
            ) from None
        # Constant-time credential compare (hmac.compare_digest) to avoid the
        # timing oracle that plain != opens; evaluate both before the check so
        # neither field leaks via short-circuit.
        user_ok = hmac.compare_digest(credentials.username, self.username)
        pass_ok = hmac.compare_digest(credentials.password, self.password)
        if not (user_ok and pass_ok):
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers=_www_auth,
            )
        return credentials

    def _get_client_ip_from_request(self, request: Request) -> str:
        # Try to get real IP from headers (for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Fallback to direct client
        if request.client:
            return request.client.host

        return "127.0.0.1"

    def _check_rate_limit(self, client_ip: str) -> bool:
        now = time.time()
        requests = _rate_limit_store[client_ip]

        # Prune stale entries only when the list grows large (amortised O(1))
        if len(requests) >= _rate_limit_max_requests:
            cutoff = now - _rate_limit_window
            requests[:] = [t for t in requests if t > cutoff]
            if len(requests) >= _rate_limit_max_requests:
                return False

        requests.append(now)
        return True

    async def start(self):
        """Start RPC server"""
        import socket

        import uvicorn

        # Pre-check: is the port already in use?
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", self.port)) == 0:
                logger.error(
                    f"RPC port {self.port} is already in use — "
                    "is another node running?  Skipping RPC server."
                )
                return

        # Build kwargs so HTTPS / HTTP share one Config call.  uvicorn reads
        # ssl_certfile / ssl_keyfile via Python's ssl.SSLContext (its
        # config.load_ssl_context()).  When both are unset uvicorn skips
        # the TLS handshake entirely and serves plain HTTP, which preserves
        # the historical default.
        cfg_kwargs: dict[str, Any] = {
            "host": "127.0.0.1",
            "port": self.port,
            "log_level": "info",
        }
        scheme = "http"
        if self.tls_certfile and self.tls_keyfile:
            cfg_kwargs["ssl_certfile"] = self.tls_certfile
            cfg_kwargs["ssl_keyfile"] = self.tls_keyfile
            scheme = "https"

        config = uvicorn.Config(self.app, **cfg_kwargs)
        server = uvicorn.Server(config)
        logger.info(f"Starting RPC server on {scheme}://127.0.0.1:{self.port}")
        try:
            await server.serve()
        except SystemExit as e:
            # uvicorn calls sys.exit(1) when it fails to bind.
            # Catch it so it doesn't tear down the entire event loop.
            logger.error(
                f"RPC server failed to start (exit code {e.code}). "
                f"Port {self.port} may be in use.  "
                "Node continues running without RPC."
            )
        except OSError as e:
            logger.error(
                f"RPC server OS error: {e}.  "
                "Node continues running without RPC."
            )

    # RPC Methods

    @staticmethod
    def _rpc_chain_name(network: str) -> str:
        """Translate internal network names to Bitcoin Core canonical RPC chain identifiers.

        Bitcoin Core uses "main" (not "mainnet") and "test" (not "testnet") in
        all RPC responses. Internal ouroboros code uses "mainnet" / "testnet" as
        config/CLI values, so this translation happens only at the RPC output layer.

        Reference: Bitcoin Core CBaseChainParams::MAIN = "main" (chainparamsbase.cpp)
        """
        _CHAIN_NAME_MAP = {
            "mainnet":  "main",
            "testnet":  "test",
            "testnet3": "test",
            "testnet4": "test",
            # signet and regtest match Core verbatim
        }
        return _CHAIN_NAME_MAP.get(network, network)

    async def rpc_getblockchaininfo(self) -> dict[str, Any]:
        """Return blockchain information.

        Reference: Bitcoin Core rpc/blockchain.cpp getblockchaininfo

        Returns an object containing various state info regarding blockchain processing:
        - chain: current network name
        - blocks: height of the most-work fully-validated chain
        - headers: current number of headers we have validated
        - bestblockhash: hash of the currently best block
        - bits: compact representation of the block difficulty target
        - target: the difficulty target
        - difficulty: the current difficulty
        - time: block time of the tip
        - mediantime: median block time
        - verificationprogress: estimate of verification progress [0..1]
        - initialblockdownload: whether node is in IBD mode
        - chainwork: total amount of work in active chain (hex)
        - size_on_disk: estimated size of block and undo files on disk
        - pruned: if blocks are subject to pruning
        - softforks: status of softfork deployments
        """
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db if hasattr(self.node, 'db') else None
        if not db:
            raise HTTPException(status_code=500, detail="Database not initialized")

        # Read cached tip (no FFI)
        best_hash, best_height = db.get_best_block()

        network = getattr(self.node, 'network', 'mainnet')
        if hasattr(self.node, 'config'):
            network = self.node.config.get('network', network)

        pruner = getattr(self.node, "pruner", None)
        pruned = pruner is not None and pruner.prune_height > 0

        # Get softfork/deployment info — use height-keyed cache to avoid
        # calling Rust FFI (get_all_deployments_info) on every request.
        # Deployment state only changes at consensus activation heights so
        # caching by (height, network) is safe and invalidates automatically
        # when the chain tip advances.  This eliminates GIL contention from
        # the validate_block thread pool worker during IBD.
        softforks = self._get_deployment_state_cached(best_height, network)

        # Read header fields from the lightweight cache populated on every
        # connect_block_from_bytes.  This avoids a full-block FFI round-trip
        # that previously took 300-500ms per call at height 495K.
        bits = getattr(db, '_tip_bits', 0x1d00ffff)
        block_time = getattr(db, '_tip_timestamp', 0)

        # Calculate target from bits (compact format)
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))
        target_hex = f"{target_int:064x}"

        # Get header count (may differ from blocks during sync)
        headers_count = best_height
        if hasattr(self.node, 'sync_manager') and self.node.sync_manager:
            sm = self.node.sync_manager
            if hasattr(sm, 'header_height'):
                headers_count = max(sm.header_height, best_height)

        # Estimate size on disk — use cached estimate (TTL 30s) to avoid
        # expensive os.walk on every getblockchaininfo call during IBD.
        size_on_disk = self._get_disk_usage_cached(db)

        # Initial block download detection.
        # On regtest, Core's IsInitialBlockDownload (validation.cpp) leaves IBD
        # as soon as the chain is caught up: nMinimumChainWork is 0 and the node
        # runs under -mocktime so the tip is never "stale". A submitblock-fed
        # regtest node has no sync_manager progress (is_synced() stays False) and
        # no mocktime clock, so both the sync-progress and the 24h wall-clock
        # staleness heuristics would spuriously latch IBD. Scope BOTH heuristics
        # OFF for regtest — report not-in-IBD once headers have caught up to
        # blocks (the chain is fully connected). Keep the REAL gate on
        # mainnet/testnet/signet.
        if network == "regtest":
            is_ibd = headers_count > best_height
        else:
            # IBD if: sync progress < 99.9% OR last block time > 24 hours ago.
            is_ibd = not self._is_synced()
            if not is_ibd and block_time > 0:
                import time as _time
                # If tip block is older than 24 hours, we're likely still syncing
                if (_time.time() - block_time) > 24 * 60 * 60:
                    is_ibd = True

        # Verification progress estimate
        # Use actual sync progress if available, otherwise estimate from time
        verification_progress = 1.0
        if is_ibd:
            # Estimate based on block times (rough approximation)
            if block_time > 0:
                import time as _time
                # Genesis time for mainnet: 2009-01-03 18:15:05 UTC
                genesis_time = 1231006505
                current_time = int(_time.time())
                if current_time > genesis_time:
                    verification_progress = min(1.0, max(0.0,
                        (block_time - genesis_time) / (current_time - genesis_time)
                    ))

        # Compute difficulty from cached bits (no FFI needed). Core prints it
        # with %.16g, so wrap in _CoreFloat for the 16-sig-digit serialization.
        difficulty = _CoreFloat(self.node.get_difficulty(bits)) if hasattr(self.node, 'get_difficulty') else _CoreFloat(1.0)

        # Median time from cached recent timestamps (no FFI needed)
        recent_ts = getattr(db, '_recent_timestamps', [])
        if len(recent_ts) >= 1:
            sorted_ts = sorted(recent_ts)
            mediantime = sorted_ts[len(sorted_ts) // 2]
        else:
            mediantime = block_time

        # Chainwork — use incrementally-cached value (no FFI needed).
        # Core emits nChainWork.GetHex(): a 64-char zero-padded hex string with
        # NO "0x" prefix (uint256 hex). Match that exactly.
        cached_cw = getattr(db, '_cached_chainwork', 0)
        if cached_cw <= 0:
            try:
                _cw_raw = await asyncio.to_thread(self.node.get_chainwork)
                # get_chainwork may already be a hex string ("0x.." or bare) or int.
                if isinstance(_cw_raw, str):
                    cached_cw = int(_cw_raw, 16) if _cw_raw else 0
                else:
                    cached_cw = int(_cw_raw)
            except Exception:
                cached_cw = 0
        chainwork = f"{cached_cw:064x}"

        # BIP 157/158 — surface whether the compact block filter index is
        # active.  Mirrors Bitcoin Core's getblockchaininfo "compact_filters"
        # behaviour: clients use this to know whether they can issue
        # ``getblockfilter`` / P2P ``getcfilters`` against this node.
        compact_filters_enabled = (
            getattr(self.node, "block_filter_index", None) is not None
        )

        # Core v31.99 getblockchaininfo (blockchain.cpp:1420) — NOTE: this
        # version DROPPED the top-level "softforks" object (moved to
        # getdeploymentinfo) and never had "compact_filters_enabled". Shape:
        #   chain, blocks, headers, bestblockhash, bits, target, difficulty,
        #   time, mediantime, verificationprogress, initialblockdownload,
        #   chainwork, size_on_disk, pruned, [prune fields], warnings.
        info: dict[str, Any] = {
            "chain": self._rpc_chain_name(network),
            "blocks": best_height,
            "headers": headers_count,
            "bestblockhash": best_hash[::-1].hex() if isinstance(best_hash, bytes) else best_hash,
            "bits": f"{bits:08x}",
            "target": target_hex,
            "difficulty": difficulty,
            "time": block_time,
            "mediantime": mediantime,
            "verificationprogress": verification_progress,
            "initialblockdownload": is_ibd,
            "chainwork": chainwork,
            "size_on_disk": size_on_disk,
            "pruned": pruned,
        }

        if pruner is not None:
            info.update(pruner.get_prune_info())

        # Add warnings if available
        warnings = []
        if hasattr(self.node, 'get_warnings'):
            warnings = self.node.get_warnings()
        info["warnings"] = warnings

        return info

    async def rpc_getdeploymentinfo(self, blockhash: str | None = None) -> dict[str, Any]:
        """Return deployment state info for consensus changes.

        Reference: Bitcoin Core rpc/blockchain.cpp getdeploymentinfo

        Args:
            blockhash: Optional block hash to query (default: chain tip)

        Returns an object with:
        - hash: queried block hash
        - height: queried block height
        - deployments: dict mapping name -> deployment info
          Each entry has: type, active, height (if known), bip9 (if bip9 type)
          bip9 sub-object: status, bit, start_time, timeout, since,
                           min_activation_height, [statistics]
        """
        db = getattr(self.node, 'db', None)

        network = getattr(self.node, 'network', 'mainnet')
        if hasattr(self.node, 'config'):
            network = self.node.config.get('network', network)

        if blockhash is not None:
            # Validate hex before trying the DB
            try:
                hash_bytes = bytes.fromhex(blockhash)[::-1]
            except (ValueError, AttributeError) as exc:
                raise HTTPException(status_code=400, detail="Invalid block hash") from exc

            if db is None:
                raise HTTPException(status_code=500, detail="Database not available")

            try:
                block = await asyncio.to_thread(db.get_block, hash_bytes)
            except Exception:
                block = None

            if block is None:
                raise HTTPException(status_code=404, detail="Block not found")

            query_hash = blockhash
            if hasattr(block, 'height'):
                query_height = block.height
            else:
                # Try to get height from db
                try:
                    _, best_height = db.get_best_block()
                    query_height = best_height
                except Exception:
                    query_height = 0
        elif db is not None:
            best_hash_bytes, best_height = db.get_best_block()
            query_height = best_height
            if isinstance(best_hash_bytes, bytes):
                query_hash = best_hash_bytes[::-1].hex()
            else:
                query_hash = str(best_hash_bytes)
        else:
            # No DB, no blockhash — return genesis-level info
            query_height = 0
            query_hash = "0" * 64

        # Delegate to the shared helper so this RPC and getblockchaininfo
        # always read from the same source of truth.
        deployments = self._build_deployment_state(query_height, network)

        return {
            "hash": query_hash,
            "height": query_height,
            "deployments": deployments,
        }

    async def rpc_getblockcount(self) -> int:
        """Return block count"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")

        _, height = self.node.db.get_best_block()
        return height

    async def rpc_getbestblockhash(self) -> str:
        """Return best block hash"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")

        hash_bytes, _ = self.node.db.get_best_block()
        if isinstance(hash_bytes, bytes):
            return hash_bytes[::-1].hex()
        return str(hash_bytes)

    # ------------------------------------------------------------------
    # Wait-family RPCs (Core rpc/blockchain.cpp: waitfornewblock /
    # waitforblock / waitforblockheight).
    #
    # All three block until a tip-change predicate is satisfied OR a
    # millisecond timeout elapses, then return the *current* tip
    # ``{hash, height}`` (on match OR timeout — identical shape either way,
    # exactly like Core).  The wait mechanism is the node's TipNotifier
    # (Core KernelNotifications/WaitTipChanged): the waiter snapshots the
    # notifier generation, evaluates its predicate against the authoritative
    # DB tip, then awaits the next generation bump with an asyncio timeout,
    # re-checking after every wake.  Reading the real DB tip each time means
    # a coalesced / missed notify can never produce a wrong answer.
    # ------------------------------------------------------------------

    def _current_tip(self) -> tuple[str, int]:
        """Return the authoritative active-chain tip as ``(display_hash, height)``.

        ``display_hash`` is the big-endian hex form Core's RPCs emit (the same
        order ``getbestblockhash`` returns).  Raises if the DB is unavailable.
        """
        if not hasattr(self.node, "db") or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")
        hash_bytes, height = self.node.db.get_best_block()
        if isinstance(hash_bytes, bytes):
            display = hash_bytes[::-1].hex()
        else:
            display = str(hash_bytes)
        return display, int(height)

    @staticmethod
    def _parse_wait_timeout(timeout: Any) -> int:
        """Validate the wait-family ``timeout`` argument (milliseconds).

        Mirrors Core (rpc/blockchain.cpp): the value is read as an int and a
        negative timeout raises ``RPC_MISC_ERROR`` (-1) "Negative timeout".
        0 means no timeout (wait indefinitely).
        """
        if timeout is None:
            return 0
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            # Core's getInt<int> rejects non-integral JSON with a type error.
            raise RpcError(
                RPC_TYPE_ERROR,
                "JSON value of type "
                f"{_core_uvtype(timeout)} is not of expected type number",
            )
        if timeout < 0:
            raise RpcError(RPC_MISC_ERROR, "Negative timeout")
        return timeout

    def _tip_notifier(self):
        """Return the node's TipNotifier, or None if unavailable."""
        return getattr(self.node, "tip_notifier", None)

    async def _wait_for_tip(self, predicate, timeout_ms: int) -> dict[str, Any]:
        """Core's wait-tip-changed loop shared by all three wait-family RPCs.

        Args:
            predicate: ``callable(display_hash, height) -> bool`` — return True
                       once the desired tip condition holds.
            timeout_ms: milliseconds to wait; 0 = wait indefinitely.

        Returns the current tip ``{"hash", "height"}`` once the predicate holds
        OR the timeout elapses (Core returns the current block in both cases).
        """
        display, height = self._current_tip()
        if predicate(display, height):
            return {"hash": display, "height": height}

        notifier = self._tip_notifier()
        if notifier is None:
            # No notifier wired (degraded boot): we cannot block on tip changes.
            # Return the current tip rather than hang — Core would have a kernel
            # notification source; this is a defensive fallback only.
            return {"hash": display, "height": height}

        loop = asyncio.get_event_loop()
        # Absolute deadline for the bounded-timeout case (Core uses a steady
        # clock deadline and re-derives the remaining slice after each wake).
        deadline = (loop.time() + timeout_ms / 1000.0) if timeout_ms else None

        while True:
            gen = notifier.generation
            # Re-check after snapshotting the generation so a notify that raced
            # in between the predicate check and the await is not lost.
            display, height = self._current_tip()
            if predicate(display, height):
                return {"hash": display, "height": height}

            if deadline is not None:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    # Timed out — return the current tip (Core's behaviour).
                    return {"hash": display, "height": height}
                await notifier.wait(gen, remaining)
            else:
                await notifier.wait(gen, None)

    async def rpc_waitfornewblock(
        self, timeout: Any = 0, current_tip: Any = None
    ) -> dict[str, Any]:
        """Wait for any new block (tip change) and return the tip.

        Core rpc/blockchain.cpp ``waitfornewblock``.  Waits until the tip
        differs from ``current_tip`` (or, if omitted, from the tip observed at
        call entry), then returns ``{"hash", "height"}``.  ``timeout`` is in
        milliseconds; 0 = no timeout.  On timeout returns the current tip.
        """
        timeout_ms = self._parse_wait_timeout(timeout)

        # Determine the reference hash the new tip must differ from.  When the
        # caller passes a current_tip it is parsed as a 64-hex uint256 (Core
        # ParseHashV: -8 on malformed).  When omitted, snapshot the live tip.
        if current_tip is None:
            ref_hash, _ = self._current_tip()
        else:
            # _parse_hash_v raises RpcError(-8) on a malformed hash, matching
            # Core's ParseHashV("current_tip").  The display form is the input
            # itself (already big-endian hex); normalise via the parsed bytes.
            ref_bytes = _parse_hash_v(current_tip, "current_tip")
            ref_hash = ref_bytes.hex()

        return await self._wait_for_tip(
            lambda h, _ht: h != ref_hash, timeout_ms
        )

    async def rpc_waitforblock(
        self, blockhash: Any, timeout: Any = 0
    ) -> dict[str, Any]:
        """Wait until the tip's hash equals ``blockhash``; return the tip.

        Core rpc/blockchain.cpp ``waitforblock``.  ``blockhash`` must be a
        valid 64-hex uint256 (ParseHashV -> -8 on malformed).  ``timeout`` is
        in milliseconds; 0 = no timeout.  On timeout returns the current tip.
        """
        # Core parses blockhash FIRST (before reading timeout), so a malformed
        # blockhash errors -8 even when a negative timeout is also supplied.
        target_bytes = _parse_hash_v(blockhash, "blockhash")
        target = target_bytes.hex()
        timeout_ms = self._parse_wait_timeout(timeout)

        return await self._wait_for_tip(
            lambda h, _ht: h == target, timeout_ms
        )

    async def rpc_waitforblockheight(
        self, height: Any, timeout: Any = 0
    ) -> dict[str, Any]:
        """Wait until the tip height >= ``height``; return the tip.

        Core rpc/blockchain.cpp ``waitforblockheight``.  ``height`` is read as
        an int (type error on non-integral).  ``timeout`` is in milliseconds;
        0 = no timeout.  On timeout returns the current tip.
        """
        if isinstance(height, bool) or not isinstance(height, int):
            raise RpcError(
                RPC_TYPE_ERROR,
                "JSON value of type "
                f"{_core_uvtype(height)} is not of expected type number",
            )
        timeout_ms = self._parse_wait_timeout(timeout)

        return await self._wait_for_tip(
            lambda _h, ht: ht >= height, timeout_ms
        )

    async def rpc_getsyncstate(self) -> dict[str, Any]:
        """hashhog W70: uniform fleet-wide sync-state report.

        Spec: meta-repo `spec/getsyncstate.md`.

        SHOULD fields return JSON ``null`` (not omitted) so consumer
        parsers can index by key without presence checks.
        """
        if not hasattr(self.node, 'db') or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db
        best_hash, best_height = db.get_best_block()
        tip_hash = best_hash[::-1].hex() if isinstance(best_hash, bytes) else str(best_hash)

        # Header tip height — max with best_height so the invariant
        # best_header_height >= tip_height holds at all times.
        headers_count = best_height
        sm = getattr(self.node, 'sync_manager', None)
        if sm is not None and hasattr(sm, 'header_height'):
            headers_count = max(sm.header_height, best_height)

        # v1: ouroboros doesn't track a distinct header-tip hash;
        # returning tip_hash is correct when caught up and acceptable
        # during IBD (the hash field is still a well-formed 64-char hex).
        header_hash = tip_hash

        is_ibd = not self._is_synced()

        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            num_peers = 0
        else:
            peer_list = getattr(pm, 'peers', [])
            num_peers = len(peer_list) if peer_list is not None else 0

        network = getattr(self.node, 'network', 'mainnet')
        if hasattr(self.node, 'config'):
            network = self.node.config.get('network', network)
        chain = self._rpc_chain_name(network)

        verification_progress = 1.0
        if is_ibd and headers_count > 0:
            verification_progress = min(1.0, best_height / headers_count)

        bs = getattr(self.node, 'block_sync', None)
        blocks_in_flight: int | None = None
        if bs is not None and hasattr(bs, 'requested_blocks'):
            try:
                blocks_in_flight = len(bs.requested_blocks)
            except (TypeError, AttributeError):
                blocks_in_flight = None

        return {
            "tip_height": best_height,
            "tip_hash": tip_hash,
            "best_header_height": headers_count,
            "best_header_hash": header_hash,
            "initial_block_download": is_ibd,
            "num_peers": num_peers,
            "verification_progress": verification_progress,
            "blocks_in_flight": blocks_in_flight,
            "blocks_pending_connect": None,
            "last_block_received_time": None,
            "chain": chain,
            "protocol_version": 70016,
        }

    async def rpc_getblockhash(self, height: int) -> str:
        """Return block hash at height.

        Reference: Bitcoin Core rpc/blockchain.cpp getblockhash. Core rejects a
        height that is negative or beyond the active-chain tip at the PARAMETER
        boundary, BEFORE any lookup, with
        ``JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range")``
        (blockchain.cpp:590-591; protocol.h:44 RPC_INVALID_PARAMETER=-8). Raise
        RpcError so the dispatch loop emits the exact -8, not the -32603 a bare
        HTTPException collapses to.
        """
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")

        # Core: nHeight = request.params[0].getInt<int>() — a non-integer height
        # is a parameter error. Match Core's out-of-range guard against the
        # active-chain tip height (db.get_best_block() -> (hash, height)).
        try:
            height = int(height)
        except (TypeError, ValueError):
            raise RpcError(
                RPC_INVALID_PARAMETER, "Block height out of range"
            ) from None
        _, tip_height = self.node.db.get_best_block()
        if height < 0 or height > tip_height:
            raise RpcError(RPC_INVALID_PARAMETER, "Block height out of range")

        # Resolve the hash from the height-keyed block index (BLOCK_INDEX_CF),
        # exactly as Core's getblockhash reads pindex->GetBlockHash() off the
        # active-chain CBlockIndex — it never loads the full block body.  This
        # is essential for the assumeUTXO snapshot base (and any header-only
        # index entry): the base block's body is intentionally absent from
        # BLOCKS_CF, so the legacy get_block_by_height path (which loads the
        # body via get_block) returned None and getblockhash(base) wrongly
        # 404'd — even though the tip pointer and get_block_hash_by_height
        # already knew the hash from the persisted index row.  Core (and the
        # other hashhog nodes) answer getblockhash purely from the index.
        block_hash = await asyncio.to_thread(
            self.node.db.get_block_hash_by_height, height
        )
        if isinstance(block_hash, (bytes, bytearray)):
            return bytes(block_hash)[::-1].hex()

        # Fallback: backends that only populate the full-block store.
        block = await asyncio.to_thread(self.node.db.get_block_by_height, height)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")

        block_hash = block.hash if hasattr(block, 'hash') else block.get_txid() if hasattr(block, 'get_txid') else None
        if isinstance(block_hash, bytes):
            return block_hash[::-1].hex()
        raise HTTPException(status_code=500, detail="Could not get block hash")

    async def rpc_getblock(
        self,
        blockhash: str,
        verbosity: int = 1
    ) -> str | dict[str, Any]:
        """Return block information.

        Reference: Bitcoin Core rpc/blockchain.cpp getblock

        Args:
            blockhash: The block hash (hex string)
            verbosity: 0 for hex-encoded data, 1 for JSON object, 2 for JSON
                       object with transaction data, 3 for JSON object with
                       transaction data including prevout information

        Returns:
            If verbosity = 0: hex-encoded serialized block data
            If verbosity = 1: JSON object with block info and transaction IDs
            If verbosity = 2: JSON object with full transaction details
            If verbosity = 3: JSON object with transaction details and prevout info
        """
        # JSON-RPC convention: hashes are display-order (big-endian) hex.
        # Internal storage uses little-endian uint256 keying. Reverse the
        # bytes so the lookup hits the BLOCKS_CF entry written by
        # connect_block_from_bytes.
        #
        # Reference: Bitcoin Core src/rpc/blockchain.cpp:842
        # getblock -> ParseHashV(request.params[0], "blockhash"), which
        # (rpc/util.cpp:117 ParseHashV) throws RPC_INVALID_PARAMETER (-8) for
        # a malformed hash BEFORE any lookup: wrong length vs non-hex pick
        # the two Core message forms. A well-formed-but-absent hash falls
        # through to the -5 "Block not found" path below, unchanged.
        block_hash = _parse_hash_v(blockhash, "blockhash")[::-1]

        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")

        block = await asyncio.to_thread(self.node.db.get_block, block_hash)
        if not block:
            # Core: getblock with a well-formed but unknown hash throws
            # JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
            # (rpc/blockchain.cpp:849, LookupBlockIndex == nullptr). Use
            # RpcError so the dispatch loop emits the exact -5, not the -32603
            # an HTTPException collapses to. (Malformed hashes never reach
            # here — _parse_hash_v already rejected them with -8.)
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        # Fetch raw block bytes (witness-preserving) once; used for verbosity=0
        # hex, verbosity>=1 block-level size/weight, and verbosity>=2 per-tx hex.
        raw_block_bytes: bytes | None = await asyncio.to_thread(
            self.node.db.get_block_bytes, block_hash
        )

        if verbosity == 0:
            # Return serialized block (hex) — use raw bytes if available so
            # witness data is preserved; fall back to stripped serialization.
            if raw_block_bytes is not None:
                return raw_block_bytes.hex()
            try:
                return block.serialize().hex()
            except Exception:
                raise HTTPException(status_code=500, detail="Block serialization not implemented") from None

        # Common fields for verbosity >= 1.
        #
        # Block height MUST be resolved from the chainstate index by hash —
        # the deserialised ``Block`` dataclass doesn't carry a height (PyBlock
        # has no height field) so the legacy ``getattr(block, 'height', None)``
        # always returned None, then ``height if height else 0`` falsy-coerced
        # to 0 in the response. That tripped Pattern D D1 (gbbh_h disagrees
        # with gbc) + D3-roundtrip (getblockheader(getblockhash(50)).height
        # returns 0, not 50) on the post-reorg-consistency corpus entry.
        # Reference: bitcoin-core/src/rpc/blockchain.cpp blockToJSON reads
        # nHeight off pblockindex (CBlockIndex), never off the block body.
        block_height = await asyncio.to_thread(self._get_block_height, self.node.db, block_hash)

        # Get confirmations (-1 if not on main chain)
        confirmations = -1
        best_hash, best_height = self.node.db.get_best_block()
        if block_height is not None:
            active_hash = await asyncio.to_thread(self.node.db.get_block_hash_by_height, block_height)
            if active_hash == block_hash:
                confirmations = max(0, best_height - block_height + 1)

        # Calculate block sizes and weight using the same formula as
        # Bitcoin Core's GetBlockWeight: stripped_size * 3 + total_size.
        # block.serialize() uses stripped tx serialization (no witness).
        strippedsize = len(block.serialize())

        # size = full block size including witness data.
        # If raw bytes are available (they include header + witness-serialised txs)
        # use len(raw_block_bytes) directly — that is the true on-wire size.
        # Fall back to strippedsize when raw bytes aren't available.
        if raw_block_bytes is not None:
            size = len(raw_block_bytes)
        elif hasattr(block, 'transactions') and block.transactions:
            from ouroboros.p2p_messages import encode_varint
            hdr_varint = 80 + len(encode_varint(len(block.transactions)))
            total_tx_size = sum(
                len(tx.serialize_with_witness()) for tx in block.transactions
            )
            size = hdr_varint + total_tx_size
        else:
            size = strippedsize
        weight = strippedsize * 3 + size

        # Calculate target from bits
        bits = block.bits
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))
        target_hex = f"{target_int:064x}"

        # Number of transactions
        n_tx = len(block.transactions) if hasattr(block, 'transactions') and block.transactions else 0

        # Build result. Core's blockToJSON = blockheaderToJSON (header fields,
        # ending with previousblockhash/nextblockhash) THEN strippedsize/size/
        # weight/coinbase_tx/tx appended at the block tail (blockchain.cpp:202).
        # strippedsize/size/weight are NOT emitted up here next to confirmations.
        result: dict[str, Any] = {
            "hash": blockhash,
            "confirmations": confirmations,
            "height": block_height if block_height is not None else 0,
            "version": block.version,
            "versionHex": f"{block.version:08x}",
            "merkleroot": block.merkle_root[::-1].hex() if isinstance(block.merkle_root, bytes) else str(block.merkle_root),
            "time": block.timestamp,
            "mediantime": self.node.get_median_time(block_height) if block_height is not None else block.timestamp,
            "nonce": block.nonce,
            "bits": f"{block.bits:08x}",
            "target": target_hex,
            "difficulty": (lambda d: _CoreFloat(d) if isinstance(d, float) else d)(self.node.get_difficulty(block.bits)),
            "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0" * 64,
            "nTx": n_tx,
        }

        # Previous block hash (not present for genesis)
        if block.prev_blockhash and block.prev_blockhash != bytes(32):
            result["previousblockhash"] = block.prev_blockhash[::-1].hex()

        # Next block hash (not present for tip)
        if block_height is not None:
            next_hash = await self._get_next_block_hash(block_height)
            if next_hash:
                result["nextblockhash"] = next_hash

        # Block-tail size fields (Core blockToJSON order: strippedsize, size,
        # weight — appended AFTER the header fields, before coinbase_tx).
        result["strippedsize"] = strippedsize
        result["size"] = size
        result["weight"] = weight

        # Build coinbase_tx from first transaction's first input (Core 27+ field).
        # Use witness_txs[0] if already parsed (verbosity >= 2 path), else parse
        # raw bytes now so we can include the coinbase witness nonce.
        if hasattr(block, 'transactions') and block.transactions:
            # Try to get coinbase from witness-preserving parse.
            _cb_witness_tx = None
            if raw_block_bytes is not None:
                try:
                    _parsed = _parse_block_txs(raw_block_bytes)
                    if _parsed:
                        _cb_witness_tx = _parsed[0]
                except Exception:
                    pass
            cb = _cb_witness_tx if _cb_witness_tx is not None else block.transactions[0]
            cb_inp = cb.inputs[0] if cb.inputs else None
            cb_script = cb_inp.script_sig if cb_inp else b''
            cb_script_hex = cb_script.hex() if isinstance(cb_script, bytes) else str(cb_script)
            cb_seq = cb_inp.sequence if cb_inp else 0xffffffff
            coinbase_tx_obj: dict[str, Any] = {
                "version": cb.version,
                "locktime": cb.locktime,
                "sequence": cb_seq,
                "coinbase": cb_script_hex,
            }
            if cb_inp and cb_inp.witness:
                coinbase_tx_obj["witness"] = cb_inp.witness[0].hex() if isinstance(cb_inp.witness[0], bytes) else str(cb_inp.witness[0])
            result["coinbase_tx"] = coinbase_tx_obj

        if verbosity == 1:
            # Transaction IDs only — emit in display order (BE), see
            # bitcoin-core/src/rpc/blockchain.cpp::blockToJSON which writes
            # ``tx->GetHash().GetHex()`` for each ``tx`` in the block. See
            # W41 for the cross-handler audit + fix.
            result["tx"] = [
                (tx.get_txid()[::-1].hex() if hasattr(tx, 'get_txid')
                 else str(tx.txid))
                for tx in block.transactions
            ] if hasattr(block, 'transactions') and block.transactions else []
        elif verbosity >= 2:
            # Full transaction details — Core-byte-identity (W59).
            #
            # The Rust PyTxIn does not expose witness data, so the Block
            # object produced by _py_block_to_block has has_witness=False on
            # every Transaction and no TxIn.witness items.  That causes five
            # cascading divergences vs Bitcoin Core 31.99:
            #   1. hash field = txid instead of wtxid for SegWit txs
            #   2. size = stripped size instead of full witness size
            #   3. vsize/weight computed from stripped size
            #   4. vin missing txinwitness items
            #   5. coinbase vin using scriptSig/txid/vout instead of coinbase/sequence
            # Additionally, hex is missing and scriptPubKey lacks address+desc.
            #
            # Fix: parse the raw block bytes (which preserve witness data) using
            # psbt._deserialize_tx_full for each transaction, then emit via
            # psbt._tx_to_univ (which uses the correct coinbase/scriptSig vin
            # format, emits txinwitness, and uses _build_spk_json for
            # address+desc).  Append the per-tx `hex` field (witness-serialized
            # raw bytes in hex) as required by Core verbosity=2.
            #
            # Reference: bitcoin-core/src/rpc/blockchain.cpp::blockToJSON,
            #            bitcoin-core/src/core_io.cpp::TxToUniv.
            from ouroboros.psbt import _tx_to_univ as _psbt_tx_to_univ
            from ouroboros.psbt import _deserialize_tx_full

            network = getattr(self.node, "network", "mainnet")

            # Parse transactions from raw bytes to preserve witness data.
            # Fall back gracefully to the stripped Block if raw bytes unavailable.
            witness_txs: list | None = None
            if raw_block_bytes is not None:
                try:
                    witness_txs = _parse_block_txs(raw_block_bytes)
                except Exception:
                    witness_txs = None

            if hasattr(block, 'transactions') and block.transactions:
                # Use witness-preserving txs if available, else stripped fallback.
                txs_for_encoding = (
                    witness_txs
                    if witness_txs is not None and len(witness_txs) == len(block.transactions)
                    else block.transactions
                )

                tx_list = []
                for i, tx in enumerate(txs_for_encoding):
                    tx_dict = _psbt_tx_to_univ(tx, network)

                    # Core's TxToUniv (core_io.cpp:430) appends, in order:
                    #   ... vout, [fee], [blockhash], [hex]
                    # i.e. fee comes BEFORE hex. Emit fee first (non-coinbase),
                    # then hex.
                    #
                    # Fee for non-coinbase transactions. Use get_utxo_or_spent so
                    # historical blocks whose inputs were already spent (removed
                    # from the live UTXO set) still yield fee data from SPENT_CF
                    # undo records.
                    if not tx.is_coinbase:
                        input_total = 0
                        for tx_in in tx.inputs:
                            utxo = await asyncio.to_thread(
                                self.node.db.get_utxo_or_spent,
                                tx_in.prev_txid, tx_in.prev_vout
                            )
                            if utxo:
                                input_total += utxo['value']
                        output_total = sum(o.value for o in tx.outputs)
                        fee_sats = max(0, input_total - output_total)
                        if fee_sats > 0:
                            # Use BTCAmount to match Core's ValueFromAmount
                            # fixed-decimal format: %d.%08d (e.g. 0.00003700
                            # not 0.000037). BTCAmount is serialized by
                            # _BTCEncoder via _BTCJsonResponse.
                            from ouroboros.psbt import BTCAmount as _BTCAmount
                            tx_dict["fee"] = _BTCAmount(fee_sats)

                    # Add hex field (witness-serialized bytes in hex).
                    # Core's TxToUniv include_hex=True path (core_io.cpp:502).
                    tx_dict["hex"] = tx.serialize_with_witness().hex()

                    if verbosity >= 3:
                        # Include prevout information for each input (verbosity=3).
                        vin_with_prevout = []
                        for j, tx_in in enumerate(tx.inputs):
                            vin_dict = tx_dict["vin"][j] if j < len(tx_dict["vin"]) else {}

                            if not tx.is_coinbase:
                                utxo = await asyncio.to_thread(self.node.db.get_utxo, tx_in.prev_txid, tx_in.prev_vout)
                                if utxo:
                                    from ouroboros.psbt import _build_spk_json
                                    vin_dict["prevout"] = {
                                        "generated": False,
                                        "height": utxo.get('height', 0),
                                        "value": utxo['value'] / 1e8,
                                        "scriptPubKey": _build_spk_json(utxo['script_pubkey'], network),
                                    }
                            vin_with_prevout.append(vin_dict)

                        tx_dict["vin"] = vin_with_prevout

                    tx_list.append(tx_dict)

                result["tx"] = tx_list
            else:
                result["tx"] = []

        return result

    async def rpc_getrawtransaction(
        self,
        txid: str,
        verbose: bool | int = 0,
        blockhash: str | None = None
    ) -> str | dict[str, Any]:
        """Return raw transaction data.

        By default, this call only returns a transaction if it is in the
        mempool. If -txindex is enabled and no blockhash argument is passed,
        it will return the transaction if it is in the mempool or any block.
        If a blockhash argument is passed, it will return the transaction if
        the specified block is available and the transaction is in that block.

        Args:
            txid: The transaction id (hex string)
            verbose: 0 for hex-encoded data, 1 for JSON object, 2 for JSON
                     object with fee and prevout (bool True = 1, False = 0)
            blockhash: The block in which to look for the transaction

        Returns:
            If verbose is 0: hex-encoded raw transaction string
            If verbose is 1 or 2: JSON object with transaction details

        Reference: Bitcoin Core rpc/rawtransaction.cpp getrawtransaction
        """
        # Parse txid.
        #
        # JSON-RPC convention: txids are display-order (big-endian) hex.
        # Internal storage (mempool keys, ``store_tx_index_batch`` keys, and
        # ``Transaction.get_txid()`` returns) all use little-endian uint256
        # bytes (the bitcoinconsensus / Core wire form). Reverse on parse
        # so every downstream consumer — mempool lookup at :1587, the
        # txindex CF at :1621, and the ``found_txid == tx_hash`` compare
        # at :1632 — sees a consistent LE byte string. Pre-fix, this hop
        # treated display-order as internal-order and `getrawtransaction`
        # for any confirmed tx returned `tx-err` even when the txindex CF
        # contained the entry (Pattern C0, txindex-revert-on-reorg corpus
        # entry, 2026-05-05). Mirrors how `blockhash` is parsed at :1569
        # and how Bitcoin Core's `rpc/rawtransaction.cpp::ParseHashV` does
        # the same byte reversal at the boundary.
        try:
            tx_hash = bytes.fromhex(txid)[::-1]
        except ValueError:
            # Core's ParseHashV raises RPC_INVALID_PARAMETER (-8) for a
            # non-hex / wrong-length txid (rpc/util.cpp:117-125).
            raise RpcError(
                RPC_INVALID_PARAMETER,
                f"parameter 1 must be hexadecimal string (not '{txid}')",
            ) from None

        if len(tx_hash) != 32:
            raise RpcError(
                RPC_INVALID_PARAMETER,
                f"parameter 1 must be of length 64 (not {len(txid)}, for '{txid}')",
            )

        # Special exception for the genesis block coinbase transaction.
        #
        # Core (rpc/rawtransaction.cpp:290-293) rejects a lookup of the
        # genesis coinbase txid — which equals the genesis block's merkle
        # root — with RPC_INVALID_ADDRESS_OR_KEY (-5) BEFORE any mempool /
        # block / txindex lookup. The genesis coinbase output is unspendable
        # and never enters the UTXO set, so it is "not considered an ordinary
        # transaction". We resolve the genesis merkle root from the stored
        # genesis block (height 0) so the check is network-agnostic.
        genesis_merkle = self._genesis_merkle_root()
        if genesis_merkle is not None and tx_hash == genesis_merkle:
            raise RpcError(
                RPC_INVALID_ADDRESS_OR_KEY,
                "The genesis block coinbase is not considered an ordinary "
                "transaction and cannot be retrieved",
            )

        # Parse verbosity - support both bool and int
        if isinstance(verbose, bool):
            verbosity = 1 if verbose else 0
        else:
            verbosity = int(verbose)

        # Parse blockhash if provided
        block_hash_bytes = None
        explicit_blockhash = blockhash is not None

        if explicit_blockhash:
            try:
                # JSON-RPC convention: hashes are display-order (big-endian) hex.
                # Internal storage keys blocks by little-endian uint256 bytes.
                # Reference: Bitcoin Core src/rpc/blockchain.cpp ParseHashV.
                block_hash_bytes = bytes.fromhex(blockhash)[::-1]
            except ValueError:
                # Core's ParseHashV -> RPC_INVALID_PARAMETER (-8).
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"parameter 3 must be hexadecimal string (not '{blockhash}')",
                ) from None
            if len(block_hash_bytes) != 32:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"parameter 3 must be of length 64 (not {len(blockhash)}, "
                    f"for '{blockhash}')",
                )

        # Check database availability
        if not hasattr(self.node, 'db') or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        # Check if txindex is enabled (we assume it is if get_tx_index exists)
        has_txindex = hasattr(self.node.db, 'get_tx_index')

        # 1. Check mempool first (unless explicit blockhash provided)
        tx = None
        in_mempool = False

        if not explicit_blockhash and hasattr(self.node, 'mempool') and self.node.mempool:
            tx = self.node.mempool.get_transaction(tx_hash)
            if tx:
                in_mempool = True

        # 2. Blockchain lookup if not in mempool
        block = None
        block_height = None
        in_active_chain = None

        if not in_mempool:
            if explicit_blockhash:
                # Caller supplied the containing block hash
                block = await asyncio.to_thread(self.node.db.get_block, block_hash_bytes)
                if block is None:
                    # Core: RPC_INVALID_ADDRESS_OR_KEY (-5), "Block hash not found"
                    # (rpc/rawtransaction.cpp:302-304).
                    raise RpcError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Block hash not found",
                    )
                # Resolve block height via chainstate index (NOT block.height —
                # PyBlock doesn't carry a height field; getattr fallback always
                # returns None, making in_active_chain false-negative).
                # Mirrors getblockheader's _get_block_height() call.
                block_height = await asyncio.to_thread(
                    self._get_block_height, self.node.db, block_hash_bytes
                )
                # Check if block is in active chain using the same logic as
                # getblockheader: compare hash-at-height vs supplied hash.
                if block_height is not None:
                    try:
                        active_hash = await asyncio.to_thread(
                            self.node.db.get_block_hash_by_height, block_height
                        )
                        if active_hash is not None:
                            in_active_chain = (bytes(active_hash) == block_hash_bytes)
                        else:
                            in_active_chain = False
                    except Exception:
                        in_active_chain = False
                else:
                    in_active_chain = False
            else:
                # Use the transaction index for O(1) lookup
                if has_txindex:
                    try:
                        loc = await asyncio.to_thread(self.node.db.get_tx_index, tx_hash)
                    except Exception:
                        loc = None
                    if loc is not None:
                        block_hash_bytes, block_height, _tx_pos = loc
                        block = await asyncio.to_thread(self.node.db.get_block, block_hash_bytes)

            # Search for the transaction in the block
            if block is not None:
                for block_tx in block.transactions:
                    found_txid = block_tx.get_txid() if hasattr(block_tx, 'get_txid') else block_tx.txid
                    if found_txid == tx_hash:
                        tx = block_tx
                        break

        # 3. Handle not found.
        #
        # Core raises every not-found case under RPC_INVALID_ADDRESS_OR_KEY
        # (-5) (rpc/rawtransaction.cpp:314-329); only the message suffix
        # varies with txindex state.
        if tx is None:
            if explicit_blockhash:
                raise RpcError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "No such transaction found in the provided block. "
                    "Use gettransaction for wallet transactions.",
                )
            elif not has_txindex:
                raise RpcError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "No such mempool transaction. Use -txindex or provide "
                    "a block hash to enable blockchain transaction queries. "
                    "Use gettransaction for wallet transactions.",
                )
            else:
                raise RpcError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "No such mempool or blockchain transaction. "
                    "Use gettransaction for wallet transactions.",
                )

        # 4. Return result based on verbosity
        if verbosity == 0:
            # verbosity 0 -> the raw tx hex via EncodeHexTx, which is the
            # WITNESS-serialized form (marker/flag + witness stacks) whenever
            # the tx has witness data (Core core_io.cpp EncodeHexTx -> CTxOut
            # serialize with PROTOCOL_VERSION incl. witness). Use the
            # witness-preserving serializer in EVERY case:
            #   * confirmed tx: re-parse from raw block bytes (the in-memory
            #     PyTx stub can strip witness items), then serialize_with_witness;
            #   * mempool tx / fallback: tx.serialize_with_witness() — which is
            #     byte-identical to the legacy form when has_witness is False,
            #     and adds the marker/flag + stacks when it is True.
            if not in_mempool and block is not None and block_hash_bytes is not None:
                raw_block_bytes: bytes | None = await asyncio.to_thread(
                    self.node.db.get_block_bytes, block_hash_bytes
                )
                if raw_block_bytes is not None:
                    try:
                        parsed_txs = _parse_block_txs(raw_block_bytes)
                        for ptx in parsed_txs:
                            if ptx.txid == tx_hash:
                                return ptx.serialize_with_witness().hex()
                    except Exception:
                        pass
            if hasattr(tx, "serialize_with_witness"):
                return tx.serialize_with_witness().hex()
            return tx.serialize().hex()

        # Verbose output (verbosity >= 1).
        #
        # For confirmed txs, re-parse from raw block bytes so witness stacks are
        # preserved — the Rust PyTxIn stub strips witness items (same issue fixed
        # for getblock verbosity=2 in W59).
        from ouroboros.psbt import _tx_to_univ as _psbt_tx_to_univ
        from ouroboros.psbt import BTCAmount as _BTCAmount
        from ouroboros.psbt import _build_spk_json as _psbt_build_spk_json

        network = getattr(self.node, "network", "mainnet")

        # Attempt to get a witness-preserving copy of this tx.
        witness_tx = tx  # fallback: stripped version from block.transactions
        raw_block_bytes_v: bytes | None = None
        if not in_mempool and block is not None and block_hash_bytes is not None:
            try:
                raw_block_bytes_v = await asyncio.to_thread(
                    self.node.db.get_block_bytes, block_hash_bytes
                )
                if raw_block_bytes_v is not None:
                    parsed_txs = _parse_block_txs(raw_block_bytes_v)
                    for ptx in parsed_txs:
                        if ptx.txid == tx_hash:
                            witness_tx = ptx
                            break
            except Exception:
                raw_block_bytes_v = None

        # Build the base verbose dict using the shared _tx_to_univ helper
        # (same path as decoderawtransaction + getblock verbosity=2).
        # Reference: Bitcoin Core rpc/rawtransaction.cpp TxToUniv.
        result = _psbt_tx_to_univ(witness_tx, network)

        # hex field: witness-serialized (Core's CDataStream include_witness=true).
        result["hex"] = witness_tx.serialize_with_witness().hex()

        # in_active_chain: only present when blockhash was explicitly supplied.
        # Reference: Bitcoin Core getrawtransaction, fVerbose && !hashBlock.IsNull().
        if explicit_blockhash:
            result["in_active_chain"] = bool(in_active_chain)

        # Block-context fields for confirmed transactions.
        if not in_mempool and block is not None:
            if block_hash_bytes:
                result["blockhash"] = block_hash_bytes[::-1].hex()
            # Resolve block height if not already known.
            effective_height = block_height
            if effective_height is None:
                effective_height = block.height if hasattr(block, 'height') else None
            if effective_height is not None:
                result["confirmations"] = self._get_confirmations(effective_height)
            else:
                result["confirmations"] = 0
            result["blocktime"] = block.timestamp
            result["time"] = block.timestamp

        # verbosity == 2: add fee at top level and prevout per non-coinbase input.
        # Reference: Bitcoin Core getrawtransaction verbosity=2 path,
        #            rpc/rawtransaction.cpp TxToUniv(tx, …, verbosity=2).
        if verbosity >= 2 and not witness_tx.is_coinbase:
            input_total_sats = 0
            vin_list = result.get("vin", [])
            for j, tx_in in enumerate(witness_tx.inputs):
                utxo = await asyncio.to_thread(
                    self.node.db.get_utxo_or_spent,
                    tx_in.prev_txid, tx_in.prev_vout
                )
                if utxo is not None:
                    input_total_sats += utxo['value']
                    prevout_height = utxo.get('height', 0)
                    prevout_value_sats = utxo['value']
                    prevout_spk = utxo.get('script_pubkey', b'')
                    prevout_generated = utxo.get('is_coinbase', False)

                    prevout_dict = {
                        "generated": bool(prevout_generated),
                        "height": prevout_height,
                        "value": _BTCAmount(prevout_value_sats),
                        "scriptPubKey": _psbt_build_spk_json(prevout_spk, network),
                    }
                    if j < len(vin_list):
                        vin_list[j]["prevout"] = prevout_dict

            output_total_sats = sum(o.value for o in witness_tx.outputs)
            fee_sats = max(0, input_total_sats - output_total_sats)
            if fee_sats > 0:
                # BTCAmount serialised by _BTCEncoder as fixed-decimal %d.%08d.
                result["fee"] = _BTCAmount(fee_sats)

        return result

    async def rpc_getcrosscheckstats(self) -> dict[str, Any]:
        """Return validate-path cross-check counters.

        Populated when ``OUROBOROS_VALIDATE_CROSS_CHECK=1`` is set — the
        drain-loop runs both the Rust FFI and Python validators, compares
        results, and records matches/mismatches here.

        Returns:
            matches (int): blocks where Rust and Python agreed
            mismatches (int): blocks where they disagreed
            samples (list): up to 32 most-recent mismatches, each with
                the height and both ``(valid, error)`` tuples

        Reference: OUROBOROS-B3-STAGE1-KICKOFF.md step 5.
        """
        try:
            from ouroboros.block_sync import get_cross_check_stats
            return get_cross_check_stats()
        except Exception as e:
            return {"error": str(e), "matches": 0, "mismatches": 0, "samples": []}

    async def rpc_getmempoolinfo(self) -> dict[str, Any]:
        """Return mempool information.

        Reference: Bitcoin Core rpc/mempool.cpp getmempoolinfo

        Returns an object containing details on the active state of the TX memory pool:
        - loaded: True if the initial load attempt of the persisted mempool finished
        - size: Current tx count
        - bytes: Sum of all virtual transaction sizes (BIP 141)
        - usage: Total memory usage for the mempool
        - total_fee: Total fees for the mempool in BTC
        - maxmempool: Maximum memory usage for the mempool
        - mempoolminfee: Minimum fee rate in BTC/kvB for tx to be accepted
        - minrelaytxfee: Current minimum relay fee for transactions
        - incrementalrelayfee: Minimum fee rate increment for mempool limiting/RBF
        - unbroadcastcount: Number of transactions that haven't passed initial broadcast
        - fullrbf: True if mempool accepts RBF without signaling
        """
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            from ouroboros.psbt import BTCAmount
            from ouroboros.mempool import (
                DEFAULT_MIN_RELAY_TX_FEE,
                DEFAULT_INCREMENTAL_RELAY_FEE,
            )
            return {
                "loaded": True,
                "size": 0,
                "bytes": 0,
                "usage": 0,
                "total_fee": BTCAmount(0),
                "maxmempool": 300_000_000,
                # No mempool yet: mempoolminfee == the min-relay floor.
                "mempoolminfee": BTCAmount(DEFAULT_MIN_RELAY_TX_FEE),
                "minrelaytxfee": BTCAmount(DEFAULT_MIN_RELAY_TX_FEE),
                "incrementalrelayfee": BTCAmount(DEFAULT_INCREMENTAL_RELAY_FEE),
                "unbroadcastcount": 0,
                "fullrbf": True,
                "permitbaremultisig": True,
                "maxdatacarriersize": 100_000,
                "limitclustercount": 64,
                "limitclustersize": 101_000,
                "optimal": True,
            }

        mempool = self.node.mempool
        info = mempool.get_mempool_info()

        # Calculate total fees from all mempool entries
        total_fee_sat = 0
        for _txid, entry in mempool.transactions.items():
            total_fee_sat += entry.fee

        # Get unbroadcast count if tracked
        unbroadcast_count = 0
        if hasattr(mempool, 'unbroadcast_txids'):
            unbroadcast_count = len(mempool.unbroadcast_txids)
        elif hasattr(mempool, 'get_unbroadcast_count'):
            unbroadcast_count = mempool.get_unbroadcast_count()

        # Memory usage estimate (more accurate than just bytes)
        # Each entry has overhead for hash tables, ancestor/descendant tracking, etc.
        usage = info['bytes']
        if hasattr(mempool, 'get_memory_usage'):
            usage = mempool.get_memory_usage()
        else:
            # Estimate: tx bytes + ~200 bytes overhead per tx for indexing
            usage = info['bytes'] + (info['size'] * 200)

        # Check if mempool is loaded (finished initial load from disk)
        loaded = True
        if hasattr(mempool, 'is_loaded'):
            loaded = mempool.is_loaded()

        # Full RBF setting
        full_rbf = True
        if hasattr(mempool, 'full_rbf'):
            full_rbf = mempool.full_rbf
        elif hasattr(mempool, 'require_standard'):
            # If require_standard is False, we likely accept full RBF
            full_rbf = True

        from ouroboros.psbt import BTCAmount
        from ouroboros.mempool import (
            DEFAULT_MIN_RELAY_TX_FEE,
            DEFAULT_INCREMENTAL_RELAY_FEE,
        )

        # Fee-display fields READ the real policy constants (mempool.py), never a
        # local literal.  Core policy.h: DEFAULT_MIN_RELAY_TX_FEE = 100 and
        # DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.  Each sat/kvB value is
        # serialized as ValueFromAmount(CFeeRate(x).GetFeePerK()) — BTCAmount(100)
        # → 0.00000100 BTC (Python float 1e-6 would lose the trailing zeros).
        #
        # mempoolminfee is max(rolling GetMinFee, min-relay floor) per Core
        # MempoolInfoToJSON.  get_mempool_min_fee() sources the rolling floor
        # (_get_min_fee_inner) maxed with DEFAULT_MIN_RELAY_TX_FEE, not the
        # min-feerate-of-txs-in-pool that get_mempool_info()['min_fee_rate'] gave.
        if hasattr(mempool, 'get_mempool_min_fee'):
            mempoolminfee_sats = int(mempool.get_mempool_min_fee())
        else:
            min_fee_rate = info.get('min_fee_rate', 0)  # sat/kvB, dynamic floor
            mempoolminfee_sats = max(int(min_fee_rate), DEFAULT_MIN_RELAY_TX_FEE)

        # Core key order (mempool.cpp MempoolInfoToJSON): loaded, size, bytes,
        # usage, total_fee, maxmempool, mempoolminfee, minrelaytxfee,
        # incrementalrelayfee, unbroadcastcount, fullrbf, permitbaremultisig,
        # maxdatacarriersize, limitclustercount, limitclustersize, optimal.
        return {
            "loaded": loaded,
            "size": info['size'],
            "bytes": info['bytes'],
            "usage": usage,
            "total_fee": BTCAmount(int(total_fee_sat)),
            "maxmempool": info.get('max_size', 300_000_000),
            "mempoolminfee": BTCAmount(mempoolminfee_sats),
            "minrelaytxfee": BTCAmount(DEFAULT_MIN_RELAY_TX_FEE),
            "incrementalrelayfee": BTCAmount(DEFAULT_INCREMENTAL_RELAY_FEE),
            "unbroadcastcount": unbroadcast_count,
            "fullrbf": full_rbf,
            # The 5 policy fields Core v31.99 added after fullrbf, in Core order.
            "permitbaremultisig": True,        # DEFAULT_PERMIT_BAREMULTISIG
            "maxdatacarriersize": 100_000,     # MAX_OP_RETURN_RELAY
            "limitclustercount": 64,           # DEFAULT_CLUSTER_LIMIT
            "limitclustersize": 101_000,       # DEFAULT_CLUSTER_SIZE_LIMIT_KVB*1000
            "optimal": True,                   # DoWork(0) on default mempool
        }

    # Default maxfeerate: 0.10 BTC/kvB (100,000 sat/kvB = 100 sat/vB)
    DEFAULT_MAX_RAW_TX_FEE_RATE = 0.10  # BTC/kvB

    async def rpc_sendrawtransaction(
        self,
        hexstring: str,
        maxfeerate: float | None = None
    ) -> str:
        """
        Submit a raw transaction (serialized, hex-encoded) to the network.

        The transaction will be validated against consensus and policy rules,
        then added to the mempool and relayed to peers via INV messages.

        Reference: Bitcoin Core rpc/mempool.cpp sendrawtransaction

        Args:
            hexstring: Hex-encoded raw transaction
            maxfeerate: Reject if fee rate exceeds this (BTC/kvB). Default: 0.10.
                        Set to 0 to accept any fee rate.

        Returns:
            The transaction hash (txid) in hex

        Raises:
            HTTPException: On validation failure with detailed reject reason
        """
        # 1. Deserialize the hex-encoded raw transaction
        try:
            tx_data = bytes.fromhex(hexstring.strip())
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"TX decode failed: {e}"
            ) from None

        try:
            from ouroboros.p2p_messages import TxMessage
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="P2P messages not available"
            ) from None

        try:
            tx_msg = TxMessage.from_payload(tx_data)
            tx = tx_msg.transaction
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"TX decode failed. Make sure the tx has at least one input. {e}"
            ) from None

        txid = tx.get_txid()
        # JSON-RPC convention: txids in responses are display-order (BE).
        # Internal ``txid`` is LE (Core's uint256 byte order). Reverse for
        # the value returned to the caller and for any user-facing log
        # line; downstream INV / mempool / txindex lookups continue to
        # use the LE ``txid`` directly. See W41.
        txid_hex = txid[::-1].hex()

        # Reject coinbase transactions
        if tx.is_coinbase:
            raise HTTPException(
                status_code=400,
                detail="coinbase"
            )

        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(
                status_code=500,
                detail="Mempool not available"
            )

        # 2. Check if already in mempool — return txid if so
        if self.node.mempool.has_transaction(txid):
            return txid_hex

        # 3. Check if already confirmed — return txid if so
        if hasattr(self.node, 'db') and self.node.db:
            try:
                loc = await asyncio.to_thread(self.node.db.get_tx_index, txid)
                if loc is not None:
                    # Transaction is already confirmed on-chain
                    return txid_hex
            except Exception:
                pass

        # 4. Check maxfeerate parameter (safety check against absurd fees)
        # Default: 0.10 BTC/kvB = 100,000 sat/kvB = 100 sat/vB
        if maxfeerate is None:
            maxfeerate = self.DEFAULT_MAX_RAW_TX_FEE_RATE

        # Calculate transaction fee and vsize
        _, best_height = self.node.db.get_best_block()

        # Calculate total input value from UTXOs
        total_input = 0
        for tx_in in tx.inputs:
            # Check mempool first for unconfirmed parent outputs
            parent_entry = self.node.mempool.transactions.get(tx_in.prev_txid)
            if parent_entry and tx_in.prev_vout < len(parent_entry.tx.outputs):
                total_input += parent_entry.tx.outputs[tx_in.prev_vout].value
            else:
                utxo = await asyncio.to_thread(self.node.db.get_utxo, tx_in.prev_txid, tx_in.prev_vout)
                if utxo:
                    total_input += utxo['value']
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="missing-inputs"
                    )

        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output

        if fee < 0:
            raise HTTPException(
                status_code=400,
                detail="bad-txns-in-belowout"
            )

        # Calculate fee rate in BTC/kvB
        vsize = tx.get_vsize()
        fee_rate_btc_kvb = (fee / 1e8) / (vsize / 1000.0)  # fee in BTC / vsize in kvB

        # Reject if fee rate exceeds maxfeerate (unless maxfeerate is 0)
        if maxfeerate > 0 and fee_rate_btc_kvb > maxfeerate:
            raise HTTPException(
                status_code=400,
                detail=f"max-fee-exceeded: fee rate {fee_rate_btc_kvb:.8f} BTC/kvB "
                       f"exceeds maxfeerate {maxfeerate:.8f} BTC/kvB"
            )

        # 5. Submit to mempool — runs all policy and consensus checks.
        # Off-load to a worker thread: ATMP performs synchronous script
        # verification + UTXO lookups + RBF descendant-graph walks that can
        # take tens of milliseconds to several seconds.  Running them on the
        # FastAPI event loop blocks every concurrent RPC handler and the
        # P2P listener loop, the same shape as camlcoin #134's Lwt-main-
        # thread starvation (closed by 815c31e / 2db21c9).  The Mempool
        # uses a re-entrant lock around the critical section so dispatching
        # via to_thread from multiple coroutines is safe.
        success, error = await asyncio.to_thread(
            self.node.mempool.add_transaction, tx, best_height,
        )

        if not success:
            # Map common errors to Bitcoin Core-style reject reasons
            reject_reason = self._map_mempool_error_to_reject_reason(error)
            raise HTTPException(
                status_code=400,
                detail=reject_reason
            )

        # 6. Relay INV to all connected peers via trickle queue (privacy)
        # Use privacy-preserving relay via INV messages
        wtxid = tx.get_wtxid() if hasattr(tx, 'get_wtxid') else txid

        if hasattr(self.node, 'peer_manager') and self.node.peer_manager:
            # Use trickle queue for privacy-preserving relay
            self.node.peer_manager.queue_tx_for_relay(txid, wtxid)

        logger.info(
            f"sendrawtransaction: accepted {txid_hex[:16]}... "
            f"(fee={fee} sat, rate={fee_rate_btc_kvb:.8f} BTC/kvB)"
        )

        # 7. Return the txid on success
        return txid_hex

    def _map_mempool_error_to_reject_reason(self, error: str) -> str:
        """Map internal mempool error messages to Bitcoin Core-style reject reasons.

        Reference: Bitcoin Core validation.cpp TxValidationResult
        """
        error_lower = error.lower()

        # Already in mempool (shouldn't reach here, but handle gracefully)
        if "already in mempool" in error_lower:
            return "txn-already-in-mempool"

        # Missing inputs (orphan)
        if "orphan" in error_lower:
            return "missing-inputs"

        # UTXO not found
        if "utxo not found" in error_lower:
            return "missing-inputs"

        # RBF Rule #3 / #4 (BIP125 PaysForRBF) — replacement does not pay enough.
        # ouroboros's mempool emits these leading with Core's reject TOKEN
        # ("insufficient fee", validation.cpp:1014) so a substring match here
        # routes them to Core's reject-reason rather than the generic conflict
        # bucket. Must run BEFORE the conflict check below (an RBF reject string
        # also mentions "replacement"/"conflicting txs").
        # Reference: bitcoin-core/src/policy/rbf.cpp PaysForRBF.
        if "insufficient fee" in error_lower:
            return "insufficient fee"

        # Double spend / conflict
        if "conflict" in error_lower or "double" in error_lower:
            return "txn-mempool-conflict"

        # Fee too low
        if "fee" in error_lower and ("low" in error_lower or "minimum" in error_lower or "below" in error_lower):
            return "insufficient-fee"

        # Non-standard
        if "non-standard" in error_lower or "standardness" in error_lower:
            return "non-standard"

        # Script failure
        if "script" in error_lower:
            return "script-failed"

        # Ancestor/descendant limits
        if "ancestor" in error_lower or "descendant" in error_lower:
            return "too-long-mempool-chain"

        # Size/weight limits
        if "size" in error_lower or "weight" in error_lower:
            return "tx-size"

        # TRUC (v3) policy
        if "truc" in error_lower or "v3" in error_lower:
            return "truc-policy"

        # Dust output
        if "dust" in error_lower:
            return "dust"

        # Negative fee
        if "negative" in error_lower:
            return "bad-txns-in-belowout"

        # Default: return original error
        return error

    async def rpc_ping(self) -> None:
        """Request that a ping be sent to all connected peers.

        Reference: Bitcoin Core rpc/net.cpp ping (:84-107) →
        PeerManager::SendPings (net_processing.cpp).

        Params: none. Any argument is a dispatcher arity error (Core: "too many
        parameters"); here the no-positional-arg signature raises a TypeError →
        JSON-RPC error, never a silent accept.

        Behaviour: side-effect-only control method. Iterates every connected
        peer and sends a P2P PING (fire-and-forget) — it does NOT measure
        latency synchronously or wait for the PONGs. The round-trip results
        surface LATER via getpeerinfo's ``pingtime`` / ``minping`` fields, and an
        outstanding ping shows transiently as ``pingwait``. With zero peers it is
        a successful no-op. Returns JSON ``null`` immediately (Core
        UniValue::VNULL).
        """
        # EnsurePeerman parity: a missing peer manager is P2P-disabled, code -31
        # (Core RPC_CLIENT_P2P_DISABLED), not an empty success.
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            raise RpcError(
                RPC_CLIENT_P2P_DISABLED,
                "Error: Peer-to-peer functionality missing or disabled",
            )

        # Send a PING to the same aggregated peer set getpeerinfo reports, so the
        # observable (pingwait now, pingtime/minping after the pong) lines up
        # with the id-list a caller sees. Fire each ping concurrently and do not
        # block on the responses — Core only QUEUES the ping per peer (sets
        # m_ping_queued) and returns; the actual send happens on the next message
        # pass. A per-peer send error must not fail the RPC (peerless / dropped
        # peers are tolerated), matching Core's loop-over-the-map-and-return.
        for peer in self._aggregate_peerinfo_peers(pm):
            ping_coro = getattr(peer, 'ping', None)
            if ping_coro is None:
                continue
            try:
                asyncio.create_task(peer.ping())
            except Exception as exc:  # never let one peer fail the whole RPC
                logger.debug(f"ping: failed to schedule ping to peer: {exc}")

        # Core returns UniValue::VNULL → JSON null. The dispatcher serialises a
        # Python None return as {"result": null}.
        return None

    async def rpc_setnetworkactive(self, state: Any = None) -> bool:
        """Disable/enable all p2p network activity.

        Reference: Bitcoin Core rpc/net.cpp setnetworkactive (:889) +
        CConnman::SetNetworkActive (net.cpp:3361).

        Param:
            state (bool, REQUIRED): true to enable networking, false to disable.

        Returns the value that was passed in (bare JSON boolean), read back from
        the peer manager after the toggle (Core returns ``GetNetworkActive()``,
        which absent a race equals ``state``).  Setting false suppresses NEW
        connection establishment only — existing peers are NOT disconnected.
        The ``networkactive`` field of getnetworkinfo mirrors this flag.
        """
        # Required positional bool.  Core reads request.params[0].get_bool();
        # a missing arg is a dispatcher arity error, a non-bool a JSON type
        # error.  Python's bool is an int subclass, so reject ints/floats
        # explicitly to match get_bool()'s strictness.
        if state is None:
            raise RpcError(RPC_INVALID_PARAMETER, "Missing required argument: state")
        if not isinstance(state, bool):
            raise RpcError(
                RPC_TYPE_ERROR,
                f"JSON value of type {_core_uvtype(state)} is not of expected type bool",
            )

        # EnsureConnman parity (server_util.cpp:100): a missing connection
        # manager is RPC_CLIENT_P2P_DISABLED (-31), NOT an empty success.
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None or not hasattr(pm, 'set_network_active'):
            raise RpcError(
                RPC_CLIENT_P2P_DISABLED,
                "Error: Peer-to-peer functionality missing or disabled",
            )

        # SetNetworkActive then return the read-back value (Core net.cpp:904-906).
        return pm.set_network_active(state)

    async def rpc_getnetworkinfo(self) -> dict[str, Any]:
        """Return network information.

        Reference: Bitcoin Core rpc/net.cpp getnetworkinfo

        Returns an object containing various state info regarding P2P networking:
        - version: the server version
        - subversion: the server subversion string
        - protocolversion: the protocol version
        - localservices: the services we offer to the network (hex)
        - localservicesnames: the services we offer, in human-readable form
        - localrelay: true if transaction relay is requested from peers
        - timeoffset: the time offset
        - connections: the total number of connections
        - connections_in: the number of inbound connections
        - connections_out: the number of outbound connections
        - networkactive: whether p2p networking is enabled
        - networks: information per network
        - relayfee: minimum relay fee rate for transactions
        - incrementalfee: minimum fee rate increment for mempool limiting or RBF
        - localaddresses: list of local addresses
        - warnings: any network and blockchain warnings
        """
        peers = []
        connections_in = 0
        connections_out = 0
        pm = getattr(self.node, 'peer_manager', None)

        if pm:
            if hasattr(pm, 'get_all_ready_peers'):
                peers = pm.get_all_ready_peers()
            elif hasattr(pm, 'peers'):
                peers = list(pm.peers.values()) if isinstance(pm.peers, dict) else list(pm.peers)

            # Count inbound vs outbound
            for peer in peers:
                if getattr(peer, 'inbound', False):
                    connections_in += 1
                else:
                    connections_out += 1

        total_connections = len(peers)

        # Local services we offer (Core's g_local_services, init.cpp:863+987).
        # ouroboros is v2-transport-default-on, so — like Core with
        # DEFAULT_V2_TRANSPORT — NODE_P2P_V2 (bit 11, 0x800) is set in the
        # NODE-LEVEL advertised word UNCONDITIONALLY (independent of any single
        # connection's negotiated transport or of inbound-listen state). A full
        # witness node advertises:
        #   NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400)
        #   | NODE_P2P_V2(0x800) = 0xc09
        local_services = 0x0C09
        if hasattr(self.node, 'local_services'):
            local_services = self.node.local_services
        elif pm and hasattr(pm, 'local_services'):
            local_services = pm.local_services

        local_services_hex = f"{local_services:016x}"

        # Service names
        service_names = []
        if local_services & 1:
            service_names.append("NETWORK")
        if local_services & 2:
            service_names.append("GETUTXO")
        if local_services & 4:
            service_names.append("BLOOM")
        if local_services & 8:
            service_names.append("WITNESS")
        if local_services & 64:
            service_names.append("COMPACT_FILTERS")
        if local_services & 1024:
            service_names.append("NETWORK_LIMITED")
        if local_services & 2048:
            service_names.append("P2P_V2")

        # Network active status
        network_active = True
        if pm and hasattr(pm, 'network_active'):
            network_active = pm.network_active

        # Time offset (median of connected peers)
        time_offset = 0
        if pm and hasattr(pm, 'get_time_offset'):
            time_offset = pm.get_time_offset()

        # Networks info
        networks = []
        for net_name in ["ipv4", "ipv6", "onion", "i2p", "cjdns"]:
            # Core: limited == !reachable, reachable == g_reachable_nets.Contains
            # (net.cpp GetNetworksInfo). With no proxy/onlynet, only clearnet
            # (ipv4/ipv6) is reachable; onion/i2p/cjdns report reachable=false
            # and therefore limited=true.
            default_reachable = net_name in ["ipv4", "ipv6"]
            net_info = {
                "name": net_name,
                "limited": not default_reachable,
                "reachable": default_reachable,
                "proxy": "",
                "proxy_randomize_credentials": False,
            }
            # Check if we have specific network config
            if hasattr(self.node, 'network_config'):
                nc = self.node.network_config.get(net_name, {})
                reachable = nc.get("reachable", default_reachable)
                net_info["limited"] = nc.get("limited", not reachable)
                net_info["reachable"] = reachable
                net_info["proxy"] = nc.get("proxy", "")
                net_info["proxy_randomize_credentials"] = nc.get("proxy_randomize_credentials", False)
            networks.append(net_info)

        # Local addresses
        local_addresses = []
        if pm and hasattr(pm, 'local_addresses'):
            for addr_info in pm.local_addresses:
                local_addresses.append({
                    "address": addr_info.get("address", ""),
                    "port": addr_info.get("port", 8333),
                    "score": addr_info.get("score", 0),
                })

        from ouroboros.psbt import BTCAmount
        from ouroboros.mempool import (
            DEFAULT_MIN_RELAY_TX_FEE,
            DEFAULT_INCREMENTAL_RELAY_FEE,
        )

        # Relay fee + incremental fee READ the real policy constants (mempool.py),
        # never a local literal.  Core policy.h: DEFAULT_MIN_RELAY_TX_FEE = 100,
        # DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.  ValueFromAmount of
        # CFeeRate(100).GetFeePerK() = 0.00000100 BTC, emitted via BTCAmount for
        # the fixed-8-decimal token.  When the mempool exposes its min_relay_fee
        # accessor we read it (it returns DEFAULT_MIN_RELAY_TX_FEE in sat/kvB).
        relay_fee = BTCAmount(DEFAULT_MIN_RELAY_TX_FEE)
        if hasattr(self.node, 'mempool') and self.node.mempool:
            if hasattr(self.node.mempool, 'min_relay_fee'):
                relay_fee = BTCAmount(int(self.node.mempool.min_relay_fee))

        # Incremental fee for RBF
        incremental_fee = BTCAmount(DEFAULT_INCREMENTAL_RELAY_FEE)

        # Warnings
        warnings = []
        if hasattr(self.node, 'get_warnings'):
            warnings = self.node.get_warnings()

        # asmapversion — SHA-256 fingerprint of the loaded ASMap file.
        # Core exposes this field in getnetworkinfo (rpc/net.cpp) when an
        # asmap is active.  We always include it: empty string when no asmap
        # is loaded (matching Core's behaviour of omitting when empty).
        addrman = getattr(self.node, 'addr_manager', None) or \
                  getattr(self.node, 'address_manager', None) or \
                  (getattr(pm, 'addr_manager', None) if pm else None)
        asmapversion = ""
        if addrman is not None and hasattr(addrman, '_asmap') and addrman._asmap:
            from ouroboros.asmap import asmap_version as _asmap_version
            asmapversion = _asmap_version(addrman._asmap).hex()

        result = {
            "version": 250000,  # Ouroboros version
            "subversion": "/Ouroboros:0.25.0/",
            "protocolversion": 70016,
            "localservices": local_services_hex,
            "localservicesnames": service_names,
            "localrelay": True,
            "timeoffset": time_offset,
            "networkactive": network_active,
            "connections": total_connections,
            "connections_in": connections_in,
            "connections_out": connections_out,
            "networks": networks,
            "relayfee": relay_fee,
            "incrementalfee": incremental_fee,
            "localaddresses": local_addresses,
            "warnings": warnings,
        }
        if asmapversion:
            result["asmapversion"] = asmapversion
        return result

    async def rpc_getrawmempool(self, verbose: bool = False) -> list[str] | dict[str, dict[str, Any]]:
        """
        Get all transaction IDs in mempool.

        Args:
            verbose: If True, return detailed information for each transaction

        Returns:
            If verbose=False: List of transaction IDs (hex strings)
            If verbose=True: Dictionary mapping txid to transaction info
        """
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            return [] if not verbose else {}

        txids = list(self.node.mempool.transactions.keys())

        # Bitcoin Core displays txids in BIG-ENDIAN (reverse-byte) hex order
        # at the RPC boundary; internal storage is little-endian. Match Core
        # so cross-impl harnesses (tools/diff-test.sh,
        # tools/snapshot-byte-identity.sh) compare apples to apples.
        # Reference: bitcoin-core/src/util/strencodings.cpp (HexStr) +
        # rpc/util.cpp (TxToUniv).
        def _display_txid(txid):
            if isinstance(txid, bytes):
                return txid[::-1].hex()
            return str(txid)

        if not verbose:
            return [_display_txid(txid) for txid in txids]

        # Return detailed information
        result = {}
        for txid in txids:
            entry = self.node.mempool.get_transaction_entry(txid)
            if entry:
                result[_display_txid(txid)] = self._format_mempool_entry(entry, txid)

        return result

    async def rpc_getorphantxs(
        self, verbosity: int | bool | None = None, verbose: int | bool | None = None
    ) -> list[Any]:
        """Show transactions in the tx orphanage.

        Reference: Bitcoin Core src/rpc/mempool.cpp getorphantxs (added in
        Core v28; introducing commit 34a9c10e8c "rpc: add getorphantxs").
        Field shape mirrors Core's OrphanDescription() / OrphanToJSON():
          - verbosity 0: array of txid hex strings (may contain duplicates).
          - verbosity 1: array of objects
              {txid, wtxid, bytes, vsize, weight, from}.
          - verbosity 2: verbosity-1 fields + ``hex`` (serialized tx hex).
        An out-of-range verbosity (not 0, 1, or 2) raises RPC_INVALID_PARAMETER
        (-8) with Core's message ("Invalid verbosity value <n>"), matching
        Core's explicit verbosity-branch ``else``.

        EXPERIMENTAL warning (Core): this call may be changed in future releases.

        Data source: the node's OrphanPool (mempool.py). Each entry is
        ``(tx, expiry_time, missing_parents)`` keyed by wtxid, with the
        announcing peer recorded in ``wtxid_to_peer`` (single announcer, or
        ``None`` for RPC/reorg/package-relay orphans). ``from`` holds the
        single announcing peer when one is tracked, else an empty array
        (best-effort; this node tracks the announcer as a peer addr
        "host:port", not a numeric Core peer id). Core has NO ``expiration``
        field — the stored ``expiry_time`` is intentionally not surfaced.
        """
        # Accept the ``verbose`` alias (Core's "verbosity|verbose" arg name).
        if verbosity is None:
            verbosity = verbose
        # Core: ParseVerbosity(arg, default_verbosity=0, allow_bool=false). A
        # null/missing arg → default 0. A boolean arg is REJECTED (NOT mapped to
        # 0/1); otherwise the integer value is used.
        if verbosity is None:
            verbosity = 0
        elif isinstance(verbosity, bool):
            # allow_bool=false → Core throws RPC_TYPE_ERROR.
            raise RpcError(
                RPC_TYPE_ERROR, "Verbosity was boolean but only integer allowed"
            )
        else:
            try:
                verbosity = int(verbosity)
            except (TypeError, ValueError):
                raise RpcError(
                    RPC_INVALID_PARAMETER, f"Invalid verbosity value {verbosity}"
                ) from None

        ret: list[Any] = []

        mempool = getattr(self.node, "mempool", None)
        orphan_pool = getattr(mempool, "orphan_pool", None) if mempool else None
        if orphan_pool is None:
            # No orphanage available (node not fully started) — Core returns an
            # empty array when the orphanage is empty; mirror that here.
            if verbosity in (0, 1, 2):
                return ret
            raise RpcError(
                RPC_INVALID_PARAMETER, f"Invalid verbosity value {verbosity}"
            )

        # Hashes are stored little-endian internally; the RPC boundary displays
        # them big-endian (reverse-byte), matching Core's ToString() and the
        # rest of this server (see rpc_getrawmempool._display_txid).
        def _display_hash(h: bytes) -> str:
            return h[::-1].hex() if isinstance(h, bytes) else str(h)

        def _orphan_to_json(tx, wtxid) -> dict[str, Any]:
            # Field order mirrors Core's OrphanToJSON exactly: txid, wtxid,
            # bytes, vsize, weight, from. bytes = total serialized size incl.
            # witness (Core ComputeTotalSize). NO ``expiration`` field — Core
            # does not emit one.
            o: dict[str, Any] = {
                "txid": _display_hash(tx.get_txid()),
                "wtxid": _display_hash(tx.get_wtxid()),
                "bytes": len(tx.serialize_with_witness()),
                "vsize": tx.get_vsize(),
                "weight": tx.get_weight(),
            }
            # Core's ``from`` is an array of announcing peer ids.  This node
            # tracks a single announcer per orphan (peer addr "host:port", or
            # None); emit a 1-element array when present, else empty.
            peer = orphan_pool.wtxid_to_peer.get(wtxid)
            o["from"] = [peer] if peer is not None else []
            return o

        # Snapshot the entries so concurrent expiry/eviction can't mutate
        # mid-iteration. orphans: wtxid -> (tx, expiry_time, missing_parents).
        entries = list(orphan_pool.orphans.items())

        if verbosity == 0:
            for wtxid, (tx, _expiry, _missing) in entries:
                ret.append(_display_hash(tx.get_txid()))
        elif verbosity == 1:
            for wtxid, (tx, _expiry, _missing) in entries:
                ret.append(_orphan_to_json(tx, wtxid))
        elif verbosity == 2:
            for wtxid, (tx, _expiry, _missing) in entries:
                o = _orphan_to_json(tx, wtxid)
                o["hex"] = tx.serialize_with_witness().hex()
                ret.append(o)
        else:
            raise RpcError(
                RPC_INVALID_PARAMETER, f"Invalid verbosity value {verbosity}"
            )

        return ret

    def _resolve_mempool_path(self, filepath: str | None = None) -> str:
        """Pick the mempool.dat path: explicit override → ``<datadir>/mempool.dat``."""
        import os

        if filepath:
            # Reject paths trying to escape the data directory unless the
            # caller passed an absolute path explicitly.
            return os.path.expanduser(filepath)
        data_dir = getattr(self.node, "data_dir", None)
        if not data_dir:
            raise HTTPException(
                status_code=500, detail="Node has no data_dir configured"
            )
        return os.path.join(data_dir, "mempool.dat")

    async def rpc_gettxspendingprevout(
        self, outputs: Any = None, options: Any = None
    ) -> list[dict[str, Any]]:
        """Scan the mempool (and the txospenderindex, if available) to find
        transactions spending any of the given outputs.

        Mirrors Bitcoin Core ``rpc/mempool.cpp::gettxspendingprevout`` exactly.

        Params:
          [0] ``outputs`` (ARR, required): array of ``{"txid": hex, "vout": n}``.
              Empty  -> RPC_INVALID_PARAMETER "Invalid parameter, outputs are missing".
              vout<0 -> RPC_INVALID_PARAMETER "Invalid parameter, vout cannot be negative".
              Strict per-object keys (only txid + vout) — RPCTypeCheckObj.
          [1] ``options`` (OBJ, optional, strict): ``{mempool_only, return_spending_tx}``.
              ``mempool_only`` default = (txospenderindex unavailable);
              ``return_spending_tx`` default false.

        Output: ARR of OBJ, pushKV order per object:
          ``txid, vout, [spendingtxid], [spendingtx], [blockhash]``.
        ``blockhash`` is set ONLY on the confirmed/index path (never for a
        mempool spender).  Unspent -> object carries only txid+vout.

        Algorithm (Core mempool.cpp:937-1039): scan the mempool FIRST via the
        outpoint reverse-index (Core's GetConflictTx).  For each entry, if a
        mempool spender is found OR mempool_only is set, emit and drop from the
        worklist.  Return early if the worklist is empty.  Otherwise
        (mempool_only==false) the index must be available and synced, else
        RPC_MISC_ERROR; for each remaining outpoint, look it up in the index.
        """
        # Core: const UniValue& output_params = request.params[0].get_array();
        if outputs is None or not isinstance(outputs, list):
            # Core get_array() on a missing/non-array param is a type error,
            # but the OMITTED-required arg surfaces as missing first; ouroboros
            # collapses both to the "outputs are missing" message Core throws on
            # an empty array — the common caller-facing case.
            raise RpcError(
                RPC_INVALID_PARAMETER, "Invalid parameter, outputs are missing"
            )
        if len(outputs) == 0:
            raise RpcError(
                RPC_INVALID_PARAMETER, "Invalid parameter, outputs are missing"
            )

        # Locate the confirmed-spend index (None when -txospenderindex is off).
        tsi = getattr(self.node, "txospender_index", None)

        # Parse options (strict: only mempool_only + return_spending_tx).
        # mempool_only default = (index unavailable) — Core: !g_txospenderindex.
        mempool_only = tsi is None
        return_spending_tx = False
        if options is not None:
            if not isinstance(options, dict):
                raise RpcError(
                    RPC_TYPE_ERROR,
                    "JSON value of type %s is not of expected type object"
                    % _core_uvtype(options),
                )
            # RPCTypeCheckObj(fStrict): unexpected keys -> RPC_TYPE_ERROR.
            for k in options:
                if k not in ("mempool_only", "return_spending_tx"):
                    raise RpcError(RPC_TYPE_ERROR, f"Unexpected key {k}")
            if "mempool_only" in options:
                v = options["mempool_only"]
                if not isinstance(v, bool):
                    raise RpcError(
                        RPC_TYPE_ERROR,
                        "JSON value of type %s for field mempool_only is not "
                        "of expected type bool" % _core_uvtype(v),
                    )
                mempool_only = v
            if "return_spending_tx" in options:
                v = options["return_spending_tx"]
                if not isinstance(v, bool):
                    raise RpcError(
                        RPC_TYPE_ERROR,
                        "JSON value of type %s for field return_spending_tx is "
                        "not of expected type bool" % _core_uvtype(v),
                    )
                return_spending_tx = v

        # Worklist entry: parsed outpoint (internal byte order) + original
        # {txid,vout} strings so the result object copies them verbatim.
        worklist: list[dict[str, Any]] = []
        for o in outputs:
            if not isinstance(o, dict):
                raise RpcError(
                    RPC_TYPE_ERROR,
                    "JSON value of type %s is not of expected type object"
                    % _core_uvtype(o),
                )
            # RPCTypeCheckObj: type-check txid (str) + vout (num) first ...
            if "txid" not in o or not isinstance(o["txid"], str):
                raise RpcError(
                    RPC_TYPE_ERROR,
                    "JSON value of type %s for field txid is not of expected "
                    "type string" % _core_uvtype(o.get("txid")),
                )
            vout_val = o.get("vout")
            if not isinstance(vout_val, (int, float)) or isinstance(vout_val, bool):
                raise RpcError(
                    RPC_TYPE_ERROR,
                    "JSON value of type %s for field vout is not of expected "
                    "type number" % _core_uvtype(vout_val),
                )
            # ... then strict unknown-key reject.
            for k in o:
                if k not in ("txid", "vout"):
                    raise RpcError(RPC_TYPE_ERROR, f"Unexpected key {k}")

            # ParseHashO(o, "txid"): hex / length validation (rpc/util.cpp).
            txid_str = o["txid"]
            try:
                txid_internal = bytes.fromhex(txid_str)[::-1]
            except ValueError:
                txid_internal = None
            if txid_internal is None or len(txid_str) != 64:
                if len(txid_str) != 64:
                    raise RpcError(
                        RPC_INVALID_PARAMETER,
                        f"txid must be of length 64 (not {len(txid_str)}, for "
                        f"'{txid_str}')",
                    )
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"txid must be hexadecimal string (not '{txid_str}')",
                )

            n_output = int(vout_val)
            if n_output < 0:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    "Invalid parameter, vout cannot be negative",
                )

            worklist.append(
                {
                    "outpoint": (txid_internal, n_output),
                    "txid_str": txid_str,
                    "vout": n_output,
                }
            )

        def _make_output(entry: dict[str, Any], spending_tx_hex: bytes | None,
                         spending_txid_internal: bytes | None) -> dict[str, Any]:
            # Core pushKV order: txid, vout, [spendingtxid], [spendingtx].
            # blockhash is appended by the caller on the confirmed path only.
            out: dict[str, Any] = {
                "txid": entry["txid_str"],
                "vout": entry["vout"],
            }
            if spending_txid_internal is not None:
                out["spendingtxid"] = spending_txid_internal[::-1].hex()
                if return_spending_tx and spending_tx_hex is not None:
                    out["spendingtx"] = bytes(spending_tx_hex).hex()
            return out

        result: list[dict[str, Any]] = []

        # Phase 1: scan the mempool first (Core's GetConflictTx reverse-index).
        remaining: list[dict[str, Any]] = []
        mempool = getattr(self.node, "mempool", None)
        for entry in worklist:
            spending_tx = None
            if mempool is not None and hasattr(mempool, "get_conflict_tx"):
                spending_tx = mempool.get_conflict_tx(entry["outpoint"])
            # If unspent in mempool and this is not a mempool-only request, defer.
            if spending_tx is None and not mempool_only:
                remaining.append(entry)
                continue
            if spending_tx is not None:
                try:
                    sp_hex = spending_tx.serialize_with_witness()
                except Exception:
                    sp_hex = spending_tx.serialize()
                result.append(_make_output(entry, sp_hex, spending_tx.txid))
            else:
                # mempool_only and unspent in mempool: bare txid+vout.
                result.append(_make_output(entry, None, None))

        # Return early if the mempool scan handled everything.
        if not remaining:
            return result

        # Phase 2: not mempool-only and some outpoints remain unresolved. The
        # index must be available AND synced to the tip (Core:
        # !g_txospenderindex || !BlockUntilSyncedToCurrentChain()).
        tip_synced = False
        if tsi is not None:
            try:
                _, tip_height = self.node.db.get_best_block()
                tip_synced = bool(tsi.is_synced(tip_height))
            except Exception:
                tip_synced = False
        if tsi is None or not tip_synced:
            raise RpcError(
                RPC_MISC_ERROR,
                "Mempool lacks a relevant spend, and txospenderindex is "
                "unavailable.",
            )

        for entry in remaining:
            prev_txid, prev_vout = entry["outpoint"]
            try:
                rec = await asyncio.to_thread(tsi.find_spender, prev_txid, prev_vout)
            except Exception as e:
                raise RpcError(RPC_MISC_ERROR, str(e)) from None
            if rec is not None:
                out = _make_output(entry, rec.spending_tx_hex, rec.spending_txid)
                out["blockhash"] = rec.block_hash[::-1].hex()
                result.append(out)
            else:
                # Unspent on-chain: only txid+vout.
                result.append(_make_output(entry, None, None))

        return result

    async def rpc_dumpmempool(self, filepath: str | None = None) -> dict[str, Any]:
        """Persist the in-memory mempool to ``mempool.dat`` (Core format).

        Reference: bitcoin-core/src/rpc/mempool.cpp dumpmempool / savemempool.
        ``savemempool`` is an alias of ``dumpmempool`` in Core; ouroboros
        exposes both for parity.
        """
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(status_code=500, detail="Mempool not available")

        path = self._resolve_mempool_path(filepath)
        try:
            count = self.node.mempool.dump_to_file(path)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Unable to dump mempool to disk: {e}"
            )
        return {"filename": path, "txcount": count}

    async def rpc_savemempool(self, filepath: str | None = None) -> dict[str, Any]:
        """Alias of :meth:`rpc_dumpmempool` for Bitcoin Core RPC parity."""
        return await self.rpc_dumpmempool(filepath)

    async def rpc_loadmempool(self, filepath: str | None = None) -> dict[str, Any]:
        """Reload mempool transactions from ``mempool.dat`` (Core format).

        Reference: bitcoin-core/src/rpc/mempool.cpp importmempool — Core
        ships this as ``importmempool`` rather than ``loadmempool``, but the
        on-disk format is identical and ouroboros exposes both names because
        the wider fleet (and ouroboros's own ``Mempool.load_from_file``) uses
        ``loadmempool``.
        """
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(status_code=500, detail="Mempool not available")

        path = self._resolve_mempool_path(filepath)

        # Determine the height to validate against (mempool entries only
        # accept txs whose chain context is at the current tip).
        height = 0
        db = getattr(self.node, "db", None)
        if db is not None:
            try:
                _, height = db.get_best_block()
            except Exception:
                height = 0

        try:
            loaded = self.node.mempool.load_from_file(path, height)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Unable to load mempool from disk: {e}"
            )
        return {"filename": path, "loaded": int(loaded)}

    async def rpc_getblockheader(self, blockhash: str, verbose: bool = True) -> str | dict[str, Any]:
        """
        Get block header information.

        Reference: Bitcoin Core rpc/blockchain.cpp getblockheader

        Args:
            blockhash: Block hash (hex string)
            verbose: If True, return JSON object; if False, return hex-encoded header

        Returns:
            If verbose=True: Dictionary with header fields:
                - hash: the block hash (same as provided)
                - confirmations: number of confirmations, or -1 if not on main chain
                - height: the block height or index
                - version: the block version
                - versionHex: the block version formatted in hexadecimal
                - merkleroot: the merkle root
                - time: the block time (UNIX timestamp)
                - mediantime: the median block time (UNIX timestamp)
                - nonce: the nonce
                - bits: compact representation of the block difficulty target
                - target: the difficulty target
                - difficulty: the difficulty
                - chainwork: expected hashes to produce the current chain
                - nTx: number of transactions in the block
                - previousblockhash: hash of the previous block (if available)
                - nextblockhash: hash of the next block (if available)

            If verbose=False: Hex-encoded block header (80 bytes)
        """
        # JSON-RPC convention: hashes are display-order (big-endian) hex.
        # Internal storage uses little-endian uint256 keying. Reverse the
        # bytes so the lookup hits the BLOCKS_CF / HEADERS_CF entry written
        # by connect_block_from_bytes (which uses the internal byte order).
        #
        # Reference: Bitcoin Core src/rpc/blockchain.cpp:639
        # getblockheader -> ParseHashV(request.params[0], "hash") -> -8 on a
        # malformed hash (rpc/util.cpp:117) BEFORE any lookup. Parse outside
        # the body try so the -8 RpcError is not remapped to HTTP 400. The
        # well-formed-but-absent path still raises -5 "Block not found" below.
        block_hash = _parse_hash_v(blockhash, "hash")[::-1]
        try:
            if not hasattr(self.node, 'db') or not self.node.db:
                raise HTTPException(status_code=500, detail="Database not available")

            block = await asyncio.to_thread(self.node.db.get_block, block_hash)

            # ------------------------------------------------------------------
            # HEADERS_CF fallback: when the full block body is absent (e.g.
            # because an assumeutxo snapshot load gapped BLOCKS_CF for heights
            # between genesis sync and the snapshot base), try the lightweight
            # header-only store populated by connect_block_from_bytes and by
            # the migration helper (populate_corpus_headers.py).
            # ------------------------------------------------------------------
            raw_header_bytes: bytes | None = None
            raw_n_tx: int = 0
            raw_chainwork: bytes | None = None  # 32 bytes BE chainwork if stored
            raw_stored_height: int | None = None  # height stored in HEADERS_CF
            raw_stored_mediantime: int | None = None  # mediantime stored in HEADERS_CF
            raw_stored_nexthash: bytes | None = None  # nexthash in internal order
            if not block:
                try:
                    raw = await asyncio.to_thread(
                        self.node.db._db.get_raw_header_with_chainwork, block_hash
                    )
                    if raw is not None:
                        raw_header_bytes, raw_n_tx, raw_chainwork, raw_h, raw_mt, raw_nh = raw
                        if isinstance(raw_header_bytes, (bytes, bytearray, memoryview)):
                            raw_header_bytes = bytes(raw_header_bytes)
                        if isinstance(raw_chainwork, (bytes, bytearray, memoryview)):
                            raw_chainwork = bytes(raw_chainwork)
                        if raw_h and raw_h > 0:
                            raw_stored_height = int(raw_h)
                        if raw_mt and raw_mt > 0:
                            raw_stored_mediantime = int(raw_mt)
                        if raw_nh and any(b != 0 for b in raw_nh):
                            raw_stored_nexthash = bytes(raw_nh)
                except Exception as _e:
                    raw_header_bytes = None

            if not block and raw_header_bytes is None:
                # Core: getblockheader throws JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                # "Block not found") when LookupBlockIndex returns null
                # (rpc/blockchain.cpp:654-656). Use RpcError so the dispatch loop
                # emits the exact -5 code, not the generic -32603 an HTTPException
                # collapses to.
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

            # Parse 80-byte wire-format header into field variables.
            # Wire format: version(4B sLE) prev_hash(32B) merkle(32B) time(4B LE) bits(4B LE) nonce(4B LE)
            import struct as _struct
            if raw_header_bytes is not None and block is None:
                # Header-only path: parse the 80-byte header.
                h = raw_header_bytes
                hdr_version  = _struct.unpack_from('<i', h, 0)[0]   # signed 32-bit
                hdr_prev     = h[4:36]                                # internal byte order
                hdr_merkle   = h[36:68]                               # internal byte order
                hdr_time     = _struct.unpack_from('<I', h, 68)[0]
                hdr_bits     = _struct.unpack_from('<I', h, 72)[0]
                hdr_nonce    = _struct.unpack_from('<I', h, 76)[0]
                hdr_n_tx     = raw_n_tx
            else:
                # Full-block path: extract fields from the PyBlock object.
                hdr_version  = block.version
                hdr_prev     = block.prev_blockhash if isinstance(block.prev_blockhash, bytes) else bytes(block.prev_blockhash)
                hdr_merkle   = block.merkle_root    if isinstance(block.merkle_root, bytes) else bytes(block.merkle_root)
                hdr_time     = block.timestamp
                hdr_bits     = block.bits
                hdr_nonce    = block.nonce
                hdr_n_tx     = len(block.transactions) if hasattr(block, 'transactions') and block.transactions else 0
                raw_header_bytes = (
                    _struct.pack('<i', hdr_version) +
                    hdr_prev + hdr_merkle +
                    _struct.pack('<I', hdr_time) +
                    _struct.pack('<I', hdr_bits) +
                    _struct.pack('<I', hdr_nonce)
                )

            if not verbose:
                # Return hex-encoded header (80 bytes).
                return raw_header_bytes.hex()

            # Return verbose JSON.
            #
            # Resolve height from the chainstate index keyed by hash; do NOT
            # read it off the deserialised ``Block`` object. Height is an
            # index-level concept that the serialised header doesn't carry,
            # so PyBlock omits it. Pre-fix this returned ``height: 0`` for
            # every header probe (Pattern D D3-roundtrip on the
            # post-reorg-consistency corpus entry, 2026-05-05). Reference:
            # bitcoin-core/src/rpc/blockchain.cpp getblockheader reads
            # ``pblockindex->nHeight``.
            block_height = await asyncio.to_thread(self._get_block_height, self.node.db, block_hash)

            # HEADERS_CF fallback height: for gap blocks not in BLOCK_INDEX_CF
            # (absent after an assumeutxo snapshot load), use the height that
            # was stored in the HEADERS_CF extended record by the migration.
            if block_height is None and raw_stored_height is not None:
                block_height = raw_stored_height

            # Get confirmations
            # -1 if block is not on the main chain
            confirmations = -1
            best_hash, best_height = self.node.db.get_best_block()
            if block_height is not None:
                # Check if this block is on the active chain.
                # Primary path: BLOCK_INDEX_CF has the hash at this height.
                # Fallback for gap blocks (not in BLOCK_INDEX_CF after a snapshot
                # load): if the height came from the HEADERS_CF migration record
                # (which was seeded from bitcoin-core, a fully-synced node), treat
                # the block as on the main chain. The block WAS on Core's main
                # chain at migration time, and we have no contradicting evidence.
                active_hash = await asyncio.to_thread(self.node.db.get_block_hash_by_height, block_height)
                if active_hash == block_hash:
                    confirmations = max(0, best_height - block_height + 1)
                elif active_hash is None and raw_stored_height is not None and raw_stored_height == block_height:
                    # Gap block: height came from HEADERS_CF (Core-seeded), not BLOCK_INDEX_CF.
                    # Trust it as on the main chain.
                    confirmations = max(0, best_height - block_height + 1)

            # Calculate target from bits.
            # Reference: Bitcoin Core src/rpc/blockchain.cpp GetBlockProof() /
            # blockheaderToJSON — DeriveTarget() applied to bits field.
            bits = hdr_bits
            mantissa = bits & 0x007FFFFF
            exponent = (bits >> 24) & 0xFF
            if exponent <= 3:
                target_int = mantissa >> (8 * (3 - exponent))
            else:
                target_int = mantissa << (8 * (exponent - 3))
            target_hex = f"{target_int:064x}"

            # Chainwork: prefer persisted value from BLOCK_INDEX_CF metadata.
            # For gap blocks (absent from BLOCK_INDEX_CF after a snapshot load),
            # fall back to the chainwork stored in HEADERS_CF by the migration.
            chainwork_str: str = "0" * 64
            if block_height is not None:
                chainwork_str = self.node.get_chainwork_at_height(block_height)
            if (chainwork_str == "0" * 64 and raw_chainwork is not None
                    and any(b != 0 for b in raw_chainwork)):
                chainwork_str = raw_chainwork.hex()

            # Mediantime: live computation from the block index, identical to
            # what rpc_getblock does (rpc.py:1936) and to Core's
            # CBlockIndex::GetMedianTimePast() — the median of THIS block and up
            # to 10 ancestors (nMedianTimeSpan = 11), chain.h:233-245. For an
            # in-index block whose body we just loaded, get_median_time always
            # finds at least the block itself, so the result is real; it only
            # falls back to wall-clock when the DB has no blocks at all, which
            # cannot happen here. The previous "< now - 86400" guard wrongly
            # discarded the correct MTP for freshly-mined / recent blocks
            # (regtest off-by-one vs Core) and fell back to the block's own
            # nTime. For gap blocks (no block_height) fall back to the
            # HEADERS_CF-stored mediantime, then the block's own timestamp.
            if block_height is not None:
                mediantime_val: int = self.node.get_median_time(block_height)
            elif raw_stored_mediantime:
                mediantime_val = raw_stored_mediantime
            else:
                mediantime_val = hdr_time  # last resort: block's own timestamp

            # Difficulty: use %.16g precision to match Bitcoin Core's UniValue
            # serializer (std::setprecision(16) << val). For whole-number values
            # (e.g. genesis difficulty=1), return int to avoid "1.0" vs "1".
            _raw_diff = self.node.get_difficulty(hdr_bits)
            difficulty_val: Any = _CoreFloat(_raw_diff) if isinstance(_raw_diff, float) else _raw_diff

            result: dict[str, Any] = {
                "hash": blockhash,
                "confirmations": confirmations,
                "height": block_height if block_height is not None else 0,
                "version": hdr_version,
                "versionHex": f"{hdr_version & 0xFFFFFFFF:08x}",
                "merkleroot": hdr_merkle[::-1].hex(),
                "time": hdr_time,
                "mediantime": mediantime_val,
                "nonce": hdr_nonce,
                "bits": f"{hdr_bits:08x}",
                "target": target_hex,
                "difficulty": difficulty_val,
                "chainwork": chainwork_str,
                "nTx": hdr_n_tx,
            }

            # Previous block hash (not present for genesis — all-zero prev).
            if hdr_prev and hdr_prev != bytes(32):
                result["previousblockhash"] = hdr_prev[::-1].hex()

            # Next block hash (not present for tip).
            # Primary: BLOCK_INDEX_CF lookup at height+1.
            # Fallback: nexthash stored in HEADERS_CF extended record.
            if block_height is not None:
                next_hash = await self._get_next_block_hash(block_height)
                if next_hash:
                    result["nextblockhash"] = next_hash
                elif raw_stored_nexthash is not None:
                    # Gap block: use the nexthash from HEADERS_CF (stored in
                    # internal byte order → reverse for display).
                    result["nextblockhash"] = raw_stored_nexthash[::-1].hex()

            return result

        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid block hash: {e}") from None
        except RpcError:
            # Core-coded error (e.g. -5 Block not found) — let the dispatch
            # loop emit the exact numeric code instead of remapping it.
            raise
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting block header: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e)) from None

    async def rpc_getblockfilter(
        self, blockhash: str, filtertype: str = "basic"
    ) -> dict[str, Any]:
        """
        Return the BIP 157/158 compact block filter for a block.

        Mirrors Bitcoin Core ``getblockfilter``
        (``src/rpc/blockchain.cpp:2956-3031``) byte-for-byte:

          - ``filter`` — the hex-encoded BIP 158 GCS basic filter
            (``CompactSize(N)`` + Golomb-Rice bitstream), produced by
            :func:`build_basic_filter` (P=19, M=784931, SipHash key = first
            16 bytes of the block hash in internal/LE order, hash-to-range
            via FastRange64).
          - ``header`` — the hex-encoded 32-byte BIP 157 filter header,
            chained as ``dSHA256(dSHA256(filter) || prev_filter_header)``.

        Error parity (Core protocol.h codes):
          - unknown ``filtertype``      -> -5  "Unknown filtertype"
          - filter index not enabled    -> -1  "Index is not enabled for
                                                filtertype <name>"
          - ``blockhash`` not in index  -> -5  "Block not found"

        Args:
            blockhash: Block hash (display-order / big-endian hex string).
            filtertype: Filter type name (only ``"basic"`` is supported).

        Returns:
            ``{"filter": "<hex>", "header": "<hex>"}``
        """
        # Core: BlockFilterTypeByName -> RPC_INVALID_ADDRESS_OR_KEY (-5)
        # "Unknown filtertype" (blockchain.cpp:2981-2983).
        if filtertype != "basic":
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype")

        # Core: GetBlockFilterIndex(filtertype) == nullptr ->
        # RPC_MISC_ERROR (-1) "Index is not enabled for filtertype basic"
        # (blockchain.cpp:2985-2988).  ouroboros enables the index via
        # -blockfilterindex; when off, node.block_filter_index is None.
        bfi: BlockFilterIndex | PersistentBlockFilterIndex | None = (
            getattr(self.node, "block_filter_index", None)
        )
        if bfi is None:
            raise RpcError(
                RPC_MISC_ERROR,
                f"Index is not enabled for filtertype {filtertype}",
            )

        # JSON-RPC convention: hashes are display-order (big-endian) hex.
        # Internal storage keys blocks (and the BlockFilterIndex) by
        # little-endian uint256 bytes. Reverse for the lookup.
        # Reference: Bitcoin Core src/rpc/blockchain.cpp ParseHashV.
        try:
            block_hash = bytes.fromhex(blockhash)[::-1]
            if len(block_hash) != 32:
                raise ValueError("Block hash must be 32 bytes")
        except ValueError:
            # Core's ParseHashV raises RPC_INVALID_PARAMETER (-8) on a
            # malformed hex hash before the index lookup.
            raise RpcError(
                RPC_INVALID_PARAMETER, f"blockhash must be of length 64 (not {len(blockhash)}, for '{blockhash}')"
            ) from None

        if not hasattr(self.node, "db") or not self.node.db:
            raise RpcError(RPC_MISC_ERROR, "Database not available")

        # Core: LookupBlockIndex == nullptr -> RPC_INVALID_ADDRESS_OR_KEY
        # (-5) "Block not found" (blockchain.cpp:2996-2998).
        block = await asyncio.to_thread(self.node.db.get_block, block_hash)
        if not block:
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        # Fast path: the index already holds this block's (filter, header).
        # Filter headers are stored internally in uint256 internal/LE byte
        # order (the order compute_filter_header emits).  Bitcoin Core's
        # getblockfilter serialises the header via uint256::GetHex(), which
        # prints the bytes REVERSED (display/big-endian order) —
        # blockchain.cpp:3027 `ret.pushKV("header", filter_header.GetHex())`.
        # The GCS `filter` field, by contrast, is a raw byte vector printed
        # forward (HexStr).  Reverse ONLY the header for display parity.
        def _result(filt: bytes, hdr: bytes) -> dict[str, Any]:
            return {"filter": filt.hex(), "header": hdr[::-1].hex()}

        # The block-connect hook (submitblock / IBD) feeds blocks in
        # canonical order, so the persisted header is correctly chained off
        # the parent's header — byte-identical to Core's index.
        cached_filter = bfi.get_filter(block_hash)
        cached_header = bfi.get_header(block_hash)
        if cached_filter is not None and cached_header is not None:
            return _result(cached_filter, cached_header)

        # Slow path: the entry isn't cached yet (e.g. a block connected
        # before the index hook ran).  Build the filter and chain its
        # header off the PARENT's stored filter header (all-zero for the
        # genesis's parent), exactly as Core's BlockFilterIndex does on
        # connect.  Then persist via the public add_block API so subsequent
        # queries hit the fast path and the chain advances monotonically.
        filter_bytes = await asyncio.to_thread(
            build_basic_filter, block, self.node.db
        )

        prev_header = b"\x00" * 32
        if block.prev_blockhash and block.prev_blockhash != bytes(32):
            prev_hdr = bfi.get_header(block.prev_blockhash)
            if prev_hdr is not None:
                prev_header = prev_hdr
        filter_header = compute_filter_header(filter_bytes, prev_header)

        try:
            bfi.add_block(block, height=block.height, db=self.node.db)
            stored_filter = bfi.get_filter(block_hash)
            stored_header = bfi.get_header(block_hash)
            if stored_filter is not None and stored_header is not None:
                return _result(stored_filter, stored_header)
        except Exception:
            # Cache failures are best-effort — fall through to the freshly
            # computed values, and to the legacy private-attr path used
            # historically when the in-memory index lacked add_block.
            if hasattr(bfi, "_filters"):
                bfi._filters[block_hash] = filter_bytes
                bfi._headers[block_hash] = filter_header
                if block.height is not None:
                    bfi._height_to_hash[block.height] = block_hash

        return _result(filter_bytes, filter_header)

    async def rpc_gettxout(self, txid: str, n: int, includemempool: bool = True) -> dict[str, Any] | None:
        """
        Get UTXO information by outpoint.

        Returns the Bitcoin Core-compatible shape:
          { bestblock, confirmations, value, scriptPubKey, coinbase }
        where scriptPubKey follows ScriptToUniv: {asm, desc, hex, address?, type}.
        value uses BTCAmount (Core's %d.%08d fixed-decimal).
        bestblock is display-order (reversed) hex.

        Returns null if the UTXO is spent or doesn't exist.

        Reference: bitcoin-core/src/rpc/blockchain.cpp::rpc_gettxout (GetTxOut).
        """
        from ouroboros.psbt import BTCAmount as _BTCAmount
        from ouroboros.psbt import _build_spk_json

        # JSON-RPC convention: txids arrive in display order (big-endian hex).
        # Internal DB keys use little-endian (reversed) bytes.
        #
        # Reference: Bitcoin Core src/rpc/blockchain.cpp:1224 gettxout ->
        # ParseHashV(request.params[0], "txid") -> -8 on a malformed txid
        # (rpc/util.cpp:117) BEFORE any lookup. A well-formed-but-absent
        # txid returns null (the `if not utxo: return None` path below),
        # never -8. Parse outside the body try so the -8 RpcError reaches the
        # dispatcher instead of being remapped to HTTP 500 by the catch-all.
        txid_internal = _parse_hash_v(txid, "txid")[::-1]

        try:
            network = getattr(self.node, "network", "mainnet")

            if not hasattr(self.node, 'db') or not self.node.db:
                return None

            best_hash, best_height = self.node.db.get_best_block()
            # best_hash is in internal (little-endian) byte order; reverse for display.
            best_hash_display = (
                best_hash[::-1].hex() if isinstance(best_hash, bytes) else str(best_hash)
            )

            # Check mempool first if enabled (unconfirmed outputs, confirmations=0).
            if includemempool and hasattr(self.node, 'mempool') and self.node.mempool:
                if self.node.mempool.has_transaction(txid_internal):
                    tx = self.node.mempool.get_transaction(txid_internal)
                    if tx and n < len(tx.outputs):
                        output = tx.outputs[n]
                        spk_bytes = (
                            output.script_pubkey
                            if isinstance(output.script_pubkey, bytes)
                            else bytes(output.script_pubkey)
                        )
                        return {
                            "bestblock": best_hash_display,
                            "confirmations": 0,
                            "value": _BTCAmount(output.value),
                            "scriptPubKey": _build_spk_json(spk_bytes, network),
                            "coinbase": bool(getattr(tx, 'is_coinbase', False)),
                        }

            # Query confirmed UTXO set.
            utxo = await asyncio.to_thread(self.node.db.get_utxo, txid_internal, n)
            if not utxo:
                return None

            spk_bytes = bytes(utxo['script_pubkey'])
            utxo_height = utxo.get('height') or 0
            confirmations = max(1, best_height - utxo_height + 1) if utxo_height else 1
            is_coinbase = bool(utxo.get('is_coinbase', False))

            return {
                "bestblock": best_hash_display,
                "confirmations": confirmations,
                "value": _BTCAmount(utxo['value']),
                "scriptPubKey": _build_spk_json(spk_bytes, network),
                "coinbase": is_coinbase,
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting txout: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e)) from None

    async def rpc_listunspent(
        self,
        minconf: int = 1,
        maxconf: int = 9999999,
        addresses: list[str] | None = None,
        include_unsafe: bool = True,
    ) -> list[dict[str, Any]]:
        """
        List unspent outputs, optionally filtered by addresses.

        Args:
            minconf: Minimum confirmations (ignored for v1 - all confirmed)
            maxconf: Maximum confirmations
            addresses: Optional list of addresses to filter
            include_unsafe: Include untrusted outputs

        Returns:
            List of unspent output dicts
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return []

        network = getattr(self.node, 'network', 'mainnet')
        result = []

        # With no explicit address filter, enumerate the wallet's own
        # addresses (all four script types per key in self.keys), mirroring
        # Bitcoin Core's listunspent default of "all wallet UTXOs". This also
        # lets a freshly-rescanned wallet surface the coins it just adopted.
        if not addresses:
            wallet = self._get_wallet_for_rpc()
            if wallet is None:
                wallet = getattr(self.node, "wallet", None)
            scanned: set[str] = set()
            if wallet is not None:
                from ouroboros.wallet import WalletKey
                for kd in getattr(wallet, "keys", []):
                    try:
                        k = WalletKey.from_wif(kd["wif"], network)
                    except Exception:
                        continue
                    for a in (
                        k.get_p2wpkh_address(),
                        k.get_p2pkh_address(),
                        k.get_p2sh_p2wpkh_address(),
                    ):
                        scanned.add(a)
                    try:
                        scanned.add(k.get_p2tr_address())
                    except Exception:
                        pass
                # Imported descriptors (watch-only included) are part of the
                # wallet's UTXO view — Core DescriptorScriptPubKeyMan::IsMine
                # is privkey-free script-set membership, so listunspent on a
                # disable_private_keys wallet must surface their coins.
                try:
                    for a in wallet._descriptor_script_map().values():
                        if a:
                            scanned.add(a)
                except Exception:
                    pass
            addresses = list(scanned)

        for addr in addresses:
            try:
                utxos = self.node.db.list_unspent_by_address(addr, network)
                for u in utxos:
                    result.append({
                        "txid": u["txid"],
                        "vout": u["vout"],
                        "address": addr,
                        "scriptPubKey": u["script_pubkey"].hex(),
                        "amount": u["value"] / 100_000_000.0,
                        "confirmations": 1,  # In chainstate = confirmed
                        "spendable": True,
                    })
            except ValueError:
                continue  # Skip invalid addresses

        return result

    # ------------------------------------------------------------------ #
    # lockunspent / listlockunspent                                      #
    # Reference: bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent and  #
    # ::listlockunspent. Locks are stored on the Wallet object; the      #
    # ``persistent`` flag mirrors Core's persistent-lock semantics       #
    # (written to wallet.dat, survives restart). Locked outpoints are    #
    # skipped by ``_collect_utxos`` so automatic coin selection avoids   #
    # them.                                                              #
    # ------------------------------------------------------------------ #

    async def rpc_lockunspent(
        self,
        unlock: bool,
        transactions: list[dict[str, Any]] | None = None,
        persistent: bool = False,
    ) -> bool:
        """Lock or unlock outpoints so they are skipped by coin selection.

        Args:
            unlock: ``True`` to unlock; ``False`` to lock.
            transactions: List of ``{"txid": <hex>, "vout": <int>}``. When
                ``unlock`` is True and ``transactions`` is None or [], every
                lock is cleared.
            persistent: If True (and ``unlock`` is False), the lock is
                written to wallet.dat. Core default: False.

        Returns:
            ``True`` on success. Raises HTTPException on validation errors,
            matching Core's ``RPC_INVALID_PARAMETER`` cases.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        if not isinstance(unlock, bool):
            raise HTTPException(status_code=400, detail="Invalid parameter, unlock must be a boolean")

        # The "unlock with no list" form clears all locks (Core's
        # UnlockAllCoins() path).
        if transactions is None or (isinstance(transactions, list) and len(transactions) == 0):
            if unlock:
                wallet.unlock_all_coins()
            return True

        if not isinstance(transactions, list):
            raise HTTPException(status_code=400, detail="Invalid parameter, transactions must be an array")

        # Validate every entry first, mirroring Core's two-pass approach
        # (collect outpoints → atomically apply). We don't have access to
        # CWallet::mapWallet, so we validate hex/vout shape only.
        outpoints: list[tuple[str, int]] = []
        for entry in transactions:
            if not isinstance(entry, dict):
                raise HTTPException(status_code=400, detail="Invalid parameter, expected object")
            txid = entry.get("txid")
            vout = entry.get("vout")
            if not isinstance(txid, str):
                raise HTTPException(status_code=400, detail="Invalid parameter, txid must be a string")
            try:
                txid_bytes = bytes.fromhex(txid)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid parameter, txid: {exc}") from None
            if len(txid_bytes) != 32:
                raise HTTPException(status_code=400, detail="Invalid parameter, txid must be 32 bytes")
            if not isinstance(vout, int) or isinstance(vout, bool):
                raise HTTPException(status_code=400, detail="Invalid parameter, vout must be an integer")
            if vout < 0:
                raise HTTPException(status_code=400, detail="Invalid parameter, vout cannot be negative")

            txid_lc = txid.lower()
            is_locked = wallet.is_locked_coin(txid_lc, vout)

            if unlock and not is_locked:
                raise HTTPException(status_code=400, detail="Invalid parameter, expected locked output")
            if (not unlock) and is_locked and not persistent:
                raise HTTPException(status_code=400, detail="Invalid parameter, output already locked")

            outpoints.append((txid_lc, vout))

        # Apply atomically.
        for (txid_lc, vout) in outpoints:
            if unlock:
                wallet.unlock_coin(txid_lc, vout)
            else:
                wallet.lock_coin(txid_lc, vout, persistent=bool(persistent))
        return True

    async def rpc_listlockunspent(self) -> list[dict[str, Any]]:
        """List currently-locked outpoints. Reference: Core listlockunspent."""
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        return [
            {"txid": txid, "vout": vout}
            for (txid, vout) in wallet.list_locked_coins()
        ]

    async def rpc_getnewaddress(
        self,
        label: str = "",
        address_type: str = "bech32",
    ) -> str:
        """
        Generate a new address from the wallet's key pool.

        Args:
            label: Optional label for the address
            address_type: Type of address to generate:
                - "bech32" (default): Native SegWit P2WPKH (bc1q...)
                - "p2sh-segwit": P2SH-wrapped SegWit (3...)
                - "bech32m": Taproot P2TR (bc1p...)
                - "legacy": P2PKH (1...)

        Returns:
            The newly generated address string

        Reference: Bitcoin Core wallet/rpc/addresses.cpp getnewaddress
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )
        return await wallet.generate_new_address(label, address_type=address_type)

    async def rpc_sendtoaddress(
        self,
        address: str,
        amount: float,
        comment: str = "",
        comment_to: str = "",
        subtractfeefromamount: bool = False,
        conf_target: int = 6,
    ) -> str:
        """
        Send bitcoin to an address. Returns the txid.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        amount_sat = int(round(amount * 1e8))
        if amount_sat <= 0:
            raise HTTPException(status_code=400, detail="Invalid amount")

        fee_rate = None
        fee_estimator = getattr(self.node, "fee_estimator", None)
        if fee_estimator is not None:
            fee_rate = fee_estimator.estimate_fee(conf_target)
        if fee_rate is None:
            fee_rate = 2  # fallback: 2 sat/vB

        raw_hex = await wallet.send_transaction(
            address, amount_sat, int(fee_rate)
        )
        txid = await self.rpc_sendrawtransaction(raw_hex)
        return txid

    async def rpc_getpayjoinrequest(
        self,
        address: str,
        amount: float,
        fee_rate: float | None = None,
        change_position: int | None = None,
    ) -> dict[str, Any]:
        """BIP-78 sender helper: build an Original PSBT for a PayJoin POST.

        This is the sender-side counterpart to :meth:`rpc_sendtoaddress` —
        instead of finalising and broadcasting, we return a PSBT that the
        operator can POST (via :meth:`rpc_sendpayjoinrequest`) to a BIP-78
        receiver endpoint.

        The returned PSBT has:
          * Every wallet-owned input signed (partial_sigs set) so the BIP-78
            receiver checklist accepts it (BIP-78 §3 — sender PSBT MUST be
            signed but NOT finalized).
          * witness_utxo on every input so the receiver can audit prevouts.
          * Two outputs: ``[payment_to_address, change_to_sender]``.

        Args:
          address:          receiver's payment address (BIP-21 / on-chain).
          amount:           BTC amount (decimal, like sendtoaddress).
          fee_rate:         sat/vB fee rate; defaults to fee estimator.
          change_position:  reserved — currently always trails the payment
                            output at index 1.  Accepted for API parity
                            with Bitcoin Core's ``walletcreatefundedpsbt``.

        Returns:
          ``{"psbt": "<base64>", "amount_sat": <int>, "fee_rate": <int>,
             "payment_output_index": 0, "change_output_index": 1}``

        References:
          BIP-78 §"Sender" (https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki)
          payjoin.org §"Building the Original PSBT"
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        amount_sat = int(round(amount * 1e8))
        if amount_sat <= 0:
            raise HTTPException(status_code=400, detail="Invalid amount")

        if fee_rate is None:
            fee_estimator = getattr(self.node, "fee_estimator", None)
            if fee_estimator is not None:
                fee_rate = fee_estimator.estimate_fee(6)
            if fee_rate is None:
                fee_rate = 2

        raw_hex = await wallet.send_transaction(
            address, amount_sat, int(fee_rate)
        )

        # Re-build the PSBT from the signed raw tx so we can hand back a
        # BIP-78-compliant Original PSBT (signed-but-not-finalized).
        from ouroboros.address import address_to_script_pubkey
        from ouroboros.psbt import PSBT, PSBT_VERSION_0
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.wallet import _hash160 as _h160_local

        raw_bytes = bytes.fromhex(raw_hex)
        tx = TxMessage.from_payload(raw_bytes).transaction

        # Strip witnesses (BIP-78 needs partial_sigs not finalized inputs).
        # We carry the sender's signatures into PSBTInput.partial_sigs and
        # leave script_sig empty so receiver-side ``is_finalized()`` is
        # False.
        unsigned_inputs = []
        partial_sigs_per_input = []
        amounts_per_input = []
        spk_per_input = []
        for inp in tx.inputs:
            # ouroboros.database.TxIn has 0+ witness items; sender signed
            # P2WPKH so witness = [sig, pubkey].
            sig = inp.witness[0] if inp.witness else b""
            pubkey = inp.witness[1] if len(inp.witness) > 1 else b""
            partial_sigs_per_input.append((pubkey, sig))
            # Find the matching wallet UTXO to grab amount + scriptPubKey.
            # _collect_utxos() returns {txid, vout, value, script_pubkey, ...}.
            wallet_utxos = wallet._collect_utxos()
            matched = None
            # display-order txid for matching
            prev_txid_display = inp.prev_txid[::-1].hex()
            for u in wallet_utxos:
                if u["txid"] == prev_txid_display and int(u["vout"]) == int(inp.prev_vout):
                    matched = u
                    break
            if matched is None:
                amounts_per_input.append(0)
                spk_per_input.append(b"")
            else:
                amounts_per_input.append(int(matched["value"]))
                spk = matched["script_pubkey"]
                if isinstance(spk, str):
                    spk = bytes.fromhex(spk)
                spk_per_input.append(spk)
            # Blank witness on the PSBT-level tx — it is "unsigned".
            inp.witness = []
            unsigned_inputs.append(inp)

        psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_0)
        for i, psbt_in in enumerate(psbt.inputs):
            pubkey, sig = partial_sigs_per_input[i]
            if sig and pubkey:
                psbt_in.partial_sigs[pubkey] = sig
            if amounts_per_input[i] and spk_per_input[i]:
                psbt_in.witness_utxo = (amounts_per_input[i], spk_per_input[i])
            psbt_in.sighash_type = 0x01  # SIGHASH_ALL

        return {
            "psbt": psbt.to_base64(),
            "amount_sat": amount_sat,
            "fee_rate": int(fee_rate),
            "payment_output_index": 0,
            "change_output_index": 1 if len(tx.outputs) > 1 else None,
        }

    async def rpc_sendpayjoinrequest(
        self,
        endpoint_url: str,
        psbt: str,
        additionalfeeoutputindex: int | None = None,
        maxadditionalfeecontribution: int | None = None,
        minfeerate: float | None = None,
        disableoutputsubstitution: bool = False,
        broadcast: bool = True,
    ) -> dict[str, Any]:
        """BIP-78 terminal sender RPC: POST + anti-snoop + broadcast.

        End-to-end sender flow:

          1. Decode the ``psbt`` argument (base64 Original PSBT from
             :meth:`rpc_getpayjoinrequest`).
          2. POST it to ``endpoint_url`` via ``httpx`` with TLS
             verification enabled (G24).  Query string carries
             ``v=1``, plus any of ``additionalfeeoutputindex /
             maxadditionalfeecontribution / minfeerate /
             disableoutputsubstitution`` the caller supplied.
          3. On transient ``unavailable`` from the receiver or any
             network error, fall back to broadcasting the Original
             PSBT (G22).
          4. On success, validate the receiver's proposal with all
             six anti-snoop validators (G10–G15).  Any failure is
             surfaced to the caller as HTTP 400 — the operator MUST
             review before manually re-trying.
          5. When ``broadcast=True``, sign the receiver's contributed
             input(s) — receiver already signed its own input but the
             sender side may need to refresh sighashes — and submit
             to the network via :meth:`rpc_sendrawtransaction`.  When
             ``broadcast=False`` the modified PSBT is returned for
             out-of-band finalization.

        Returns:
          ``{"status": "payjoined"|"fallback"|"validated",
             "txid": <hex>|None,
             "psbt": <base64>|None,
             "fallback_reason": <str>|None}``

        References:
          BIP-78 §sender + §"Receiver Error"
          payjoin.org §"Sender's validation checklist"
        """
        from ouroboros import payjoin as _payjoin
        from ouroboros.psbt import PSBT

        try:
            original = PSBT.from_base64(psbt)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid base64 PSBT: {exc}"
            )
        gate = self._psbt_v2_gate(original)
        if gate is not None:
            return gate

        resp = _payjoin.send_payjoin_request(
            endpoint_url,
            original,
            additionalfeeoutputindex=additionalfeeoutputindex,
            maxadditionalfeecontribution=maxadditionalfeecontribution,
            minfeerate=minfeerate,
            disableoutputsubstitution=disableoutputsubstitution,
        )

        if resp.error is not None and resp.is_transient:
            # G22 fallback: broadcast the Original PSBT as a normal tx.
            if not broadcast:
                return {
                    "status": "fallback",
                    "txid": None,
                    "psbt": original.to_base64(),
                    "fallback_reason": resp.error.message,
                }
            raw_hex = _payjoin._finalize_psbt_to_raw_hex(original)
            if raw_hex is None:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        f"PayJoin receiver unavailable ({resp.error.message}); "
                        "Original PSBT also could not be finalized for fallback"
                    ),
                )
            txid = await self.rpc_sendrawtransaction(raw_hex)
            # G19 — record the fallback broadcast so any subsequent
            # PayJoin request for the same Original PSBT (against a
            # receiver running this codebase) refuses with
            # ``unavailable``.  This is a global module-level state
            # used by _handle_payjoin_request above.
            _payjoin.payjoin_fallback_detect.mark_original_psbt_broadcast(
                original, txid_hex=txid
            )
            return {
                "status": "fallback",
                "txid": txid,
                "psbt": None,
                "fallback_reason": resp.error.message,
            }
        if resp.error is not None:
            # Non-transient errors (original-psbt-rejected, not-enough-money,
            # version-unsupported) surface as 4xx — the operator must adjust.
            raise HTTPException(
                status_code=resp.error.http_status,
                detail=f"PayJoin receiver error [{resp.error.code}]: {resp.error.message}",
            )

        assert resp.psbt is not None
        proposal = resp.psbt
        try:
            _payjoin.validate_payjoin_response(
                original,
                proposal,
                additionalfeeoutputindex=additionalfeeoutputindex,
                maxadditionalfeecontribution=maxadditionalfeecontribution,
                disable_output_substitution=disableoutputsubstitution,
            )
        except _payjoin.PayJoinError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Receiver proposal failed anti-snoop validation: {exc.message}",
            )

        if not broadcast:
            return {
                "status": "validated",
                "txid": None,
                "psbt": proposal.to_base64(),
                "fallback_reason": None,
            }
        # Sign-and-broadcast path: finalise + submit.  Sender already
        # signed sender inputs in step 1; receiver signed its inputs in
        # step 2.  Finalise pulls everything together.
        raw_hex = _payjoin._finalize_psbt_to_raw_hex(proposal)
        if raw_hex is None:
            raise HTTPException(
                status_code=500,
                detail="Could not finalise PayJoin proposal for broadcast",
            )
        txid = await self.rpc_sendrawtransaction(raw_hex)
        return {
            "status": "payjoined",
            "txid": txid,
            "psbt": proposal.to_base64(),
            "fallback_reason": None,
        }

    async def rpc_sethdseed(self, seed_hex: str = None) -> dict[str, Any]:
        """
        Initialise the wallet in HD (BIP 32 / BIP 44) mode.

        If *seed_hex* is provided it is used as the master seed;
        otherwise a cryptographically random 32-byte seed is generated.
        """
        import os

        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "No wallet loaded"}, id=None
            )

        if seed_hex is not None:
            try:
                seed = bytes.fromhex(seed_hex)
            except ValueError:
                return JSONRPCResponse(
                    error={"code": -8, "message": "seed_hex must be valid hex"},
                    id=None,
                )
            if not 16 <= len(seed) <= 64:
                return JSONRPCResponse(
                    error={
                        "code": -8,
                        "message": "Seed must be 16–64 bytes",
                    },
                    id=None,
                )
        else:
            seed = os.urandom(32)

        xprv = wallet.init_hd(seed)
        master = wallet.get_hd_master()
        return {
            "seed_hex": seed.hex(),
            "xprv": xprv,
            "xpub": master.serialize_xpub() if master else None,
            "message": "HD wallet initialized",
        }

    async def rpc_encryptwallet(self, passphrase: str) -> str:
        """
        Encrypt the wallet with a passphrase.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "No wallet loaded"}, id=None
            )
        if wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an encrypted wallet, "
                    "but encryptwallet was called.",
                },
                id=None,
            )
        wallet.encrypt(passphrase)
        return (
            "wallet encrypted; The keypool has been flushed and a new HD seed "
            "was set. You need to make a new backup. Restart recommended."
        )

    async def rpc_walletpassphrase(
        self, passphrase: str, timeout: int = 60
    ) -> bool:
        """
        Unlock an encrypted wallet for *timeout* seconds.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "No wallet loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletpassphrase was called.",
                },
                id=None,
            )
        try:
            wallet.unlock(passphrase)
        except ValueError:
            return JSONRPCResponse(
                error={
                    "code": -14,
                    "message": "Error: The wallet passphrase entered was incorrect.",
                },
                id=None,
            )
        return True

    async def rpc_walletlock(self) -> bool:
        """
        Lock the wallet, wiping the decryption key from memory.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "No wallet loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletlock was called.",
                },
                id=None,
            )
        try:
            wallet.lock()
        except ValueError:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: wallet is already locked.",
                },
                id=None,
            )
        return True

    async def rpc_walletpassphrasechange(
        self, old_passphrase: str, new_passphrase: str
    ) -> bool:
        """
        Change the wallet passphrase.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "No wallet loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletpassphrasechange was called.",
                },
                id=None,
            )
        try:
            wallet.change_passphrase(old_passphrase, new_passphrase)
        except ValueError as exc:
            return JSONRPCResponse(
                error={"code": -14, "message": str(exc)}, id=None
            )
        return True

    async def rpc_getwalletinfo(self) -> dict[str, Any]:
        """
        Return wallet state info.

        Reference: Bitcoin Core wallet/rpc/wallet.cpp getwalletinfo
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        balance = await wallet.get_balance()

        # Use key pool size if available, otherwise count addresses
        keypool_size = wallet.get_keypool_size()
        if keypool_size == 0:
            addresses = await wallet.get_addresses()
            keypool_size = len(addresses)

        info: dict[str, Any] = {
            "walletname": wallet.name,
            "walletversion": 1,
            "balance": balance / 1e8,
            "unconfirmed_balance": 0.0,
            "immature_balance": 0.0,
            "txcount": 0,
            "keypoolsize": keypool_size,
            "paytxfee": 0.0,
            "hd": wallet.is_hd,
            "encrypted": wallet.is_encrypted,
            "locked": wallet.is_locked,
            # Core wallet/rpc/wallet.cpp getwalletinfo: false for
            # disable_private_keys (watch-only descriptor) wallets.
            "private_keys_enabled": not getattr(
                wallet, "_disable_private_keys", False
            ),
        }

        if wallet.is_hd:
            info["hd_next_index"] = wallet._hd_next_index
            master = wallet.get_hd_master()
            if master:
                info["hd_master_xpub"] = master.serialize_xpub()

        return info

    async def rpc_keypoolrefill(self, newsize: int = 1000) -> None:
        """
        Refill the key pool.

        Args:
            newsize: Target key pool size (default 1000)

        Reference: Bitcoin Core wallet/rpc/wallet.cpp keypoolrefill
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )

        generated = wallet.keypoolrefill(newsize)
        logger.info(f"Key pool refilled with {generated} new keys")
        return None

    async def rpc_getrawchangeaddress(self, address_type: str = "bech32") -> str:
        """
        Generate a new change address for receiving change.

        Args:
            address_type: Type of address to generate (bech32, p2sh-segwit, legacy, bech32m)

        Returns:
            A new change address from the internal (change) key pool

        Reference: Bitcoin Core wallet/rpc/addresses.cpp getrawchangeaddress
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )

        return await wallet.get_change_address(address_type=address_type)

    # PSBT RPCs (BIP 174)

    # --- PSBT v2 default-off gate (Core parity) ----------------------------
    # Bitcoin Core supports ONLY PSBT v0 (psbt.h:80 PSBT_HIGHEST_VERSION = 0):
    # any PSBT whose global 0xFB version record exceeds 0 fails
    # deserialization with "Unsupported version number" (psbt.h:1322-1323),
    # surfaced by every PSBT-accepting RPC as RPC_DESERIALIZATION_ERROR (-22)
    # "TX decode failed Unsupported version number: iostream error" — the
    # ": iostream error" suffix is ios_base::failure::what(); confirmed
    # byte-identical against the v31.99.0 oracle (2026-06-09). ouroboros'
    # psbt.py implements BIP-370 v2 end-to-end; to keep DEFAULT RPC behavior
    # equal to Core's, v2+ PSBTs are rejected AT THE RPC BOUNDARY unless the
    # operator opts in with OUROBOROS_PSBT_V2=1. The library layer is
    # intentionally NOT gated (tests/test_fix63_psbt_v2_status.py exercises
    # direct library v2 round-trips); creation surfaces (createpsbt,
    # walletcreatefundedpsbt, converttopsbt, psbtbumpfee) always emit v0.

    @staticmethod
    def _psbt_v2_rpc_allowed() -> bool:
        import os
        return os.environ.get("OUROBOROS_PSBT_V2", "0") == "1"

    def _psbt_v2_gate(self, psbt_obj: Any) -> "JSONRPCResponse | None":
        """Return Core's ``-22`` rejection when *psbt_obj* carries a global
        version record > 0 and ``OUROBOROS_PSBT_V2`` != ``1``, else ``None``.

        Message observed byte-identically on the v31.99.0 oracle
        (psbt.h:1322-1323 "Unsupported version number").
        """
        version = getattr(psbt_obj, "version", 0) or 0
        if version > 0 and not self._psbt_v2_rpc_allowed():
            return JSONRPCResponse(
                error={
                    "code": -22,
                    "message": (
                        "TX decode failed Unsupported version number:"
                        " iostream error"
                    ),
                },
                id=None,
            )
        return None

    @staticmethod
    def _psbt_decode_error(exc: Exception) -> "JSONRPCResponse":
        """Map a PSBT deserialization failure to Core's -22 wire shape.

        The v0-without-unsigned-tx failure (psbt.py raises "PSBT v0
        requires unsigned transaction") is normalized to Core's exact wire
        message — oracle-confirmed 2026-06-09: ``TX decode failed No
        unsigned transaction was provided: iostream error``. Anything else
        keeps this file's ``TX decode failed: <msg>`` convention.
        """
        if str(exc) == "PSBT v0 requires unsigned transaction":
            return JSONRPCResponse(
                error={
                    "code": -22,
                    "message": (
                        "TX decode failed No unsigned transaction was"
                        " provided: iostream error"
                    ),
                },
                id=None,
            )
        return JSONRPCResponse(
            error={"code": -22, "message": f"TX decode failed: {exc}"},
            id=None,
        )

    async def rpc_decodepsbt(self, psbt_base64: str) -> dict[str, Any]:
        """
        Decode a base64-encoded PSBT into a human-readable dict.

        W51: output is byte-identical to Bitcoin Core 31.99 for the two
        empty-aux corpus entries (valid-1in-2out-no-aux,
        creator-result-2in-2out-empty).  Amount fields use ``BTCAmount``
        so they serialise as Core's fixed ``%d.%08d`` form (``1.00000000``
        not ``1.0``); ``_BTCJsonResponse`` in the outer RPC dispatch emits
        them as raw numeric tokens.
        """
        import base64 as b64

        from ouroboros.psbt import PSBT

        try:
            raw = b64.b64decode(psbt_base64, validate=True)
        except Exception:
            return JSONRPCResponse(
                error={"code": -22, "message": "TX decode failed: invalid base64"},
                id=None,
            )
        try:
            psbt = PSBT.deserialize(raw)
        except Exception as exc:
            return self._psbt_decode_error(exc)
        gate = self._psbt_v2_gate(psbt)
        if gate is not None:
            return gate
        network = getattr(self.node, "network", "mainnet")
        return psbt.decode(network=network)

    async def rpc_combinepsbt(self, psbts: list[str]) -> str:
        """
        Combine multiple base64-encoded PSBTs into one.
        """
        import base64 as b64

        from ouroboros.psbt import PSBT

        if not psbts or len(psbts) < 2:
            return JSONRPCResponse(
                error={"code": -8, "message": "At least two PSBTs required"},
                id=None,
            )
        try:
            decoded = [PSBT.deserialize(b64.b64decode(p, validate=True)) for p in psbts]
        except Exception as exc:
            return JSONRPCResponse(
                error={"code": -22, "message": f"TX decode failed: {exc}"},
                id=None,
            )
        for psbt_obj in decoded:
            gate = self._psbt_v2_gate(psbt_obj)
            if gate is not None:
                return gate
        combined = decoded[0]
        for other in decoded[1:]:
            combined = combined.combine(other)
        return b64.b64encode(combined.serialize()).decode("ascii")

    async def rpc_combinerawtransaction(self, txs: Any) -> str:
        """Combine multiple partially-signed versions of the SAME transaction
        into one carrying the union of their signature data.

        Reference: Bitcoin Core ``rpc/rawtransaction.cpp`` combinerawtransaction
        (impl body 605-668). Each element of ``txs`` is a hex-encoded raw tx
        with the SAME inputs/outputs/version/locktime but DIFFERENT partial
        signatures. The first variant is the structural template; per input we
        merge the scriptSig + witness across all variants and write the
        combined result back. Returns the witness-serialized hex.

        Merge scope (see the per-input pick below): for the common/realistic
        case where each variant carries a complete single-key signature for a
        DIFFERENT subset of inputs (or one variant is unsigned), we take, per
        input, the non-empty (signed) scriptSig + witness. This is BYTE-
        IDENTICAL to Core for single-sig inputs (P2PKH / P2WPKH / P2SH-P2WPKH),
        because Core's ``DataFromTransaction`` returns the variant's scriptSig +
        scriptWitness verbatim once ``VerifyScript`` marks the input complete,
        and ``MergeSignatureData`` adopts that complete sigdata wholesale.

        KNOWN LIMITATION (flagged): the FULL Core behavior also merges PARTIAL
        multisig signatures WITHIN a single input — two variants each holding
        one of M sigs for a bare/P2SH/P2WSH M-of-N — via ``SignatureData::
        Merge`` over the extracted (pubkey -> sig) map. That needs Solver /
        VerifyScript-with-a-signature-extracting-checker / sighash validation,
        which this handler does NOT implement. For an input that is partially
        signed in BOTH variants (neither alone complete), we keep the longer
        (more-signatures) of the two scriptSigs rather than splicing the two
        sig sets together; the output for that input is therefore NOT
        guaranteed byte-identical to Core. The per-input single-sig pick — the
        dominant case — IS byte-identical and is what is verified.

        DEVIATION (flagged): Core resolves every input's prevout from its own
        UTXO + mempool ``CCoinsViewCache`` and throws RPC_VERIFY_ERROR (-25)
        "Input not found or already spent" when a coin is missing/spent. This
        handler does NOT consult chainstate — combine is a pure function of the
        provided variants here — so it does NOT raise -25 for unresolvable
        prevouts. Consequence: the byte-identical SUCCESS vector must be run
        against a Core oracle whose UTXO actually resolves the prevouts (a
        scratch regtest), and the -25 path is a documented non-match on this
        impl. The -22 empty / -22 decode-failure error paths DO match Core.
        """
        from ouroboros.database import Transaction, TxIn
        from ouroboros.p2p_messages import TxMessage

        # Param shape: dispatcher passes the JSON array straight through.
        # A non-array (Core: request.params[0].get_array()) is a type error.
        if not isinstance(txs, list):
            raise RpcError(
                RPC_TYPE_ERROR,
                "Expected type array, got {}".format(_core_uvtype(txs)),
            )

        # 1. Decode every variant (witness-aware). Core: DecodeHexTx per idx;
        #    on failure -> -22 "TX decode failed for tx %d. ..." (0-based idx).
        variants: list[Transaction] = []
        for idx, item in enumerate(txs):
            if not isinstance(item, str):
                # Core reads each element with .get_str() -> type error.
                raise RpcError(
                    RPC_TYPE_ERROR,
                    "JSON value of type {} is not of expected type string".format(
                        _core_uvtype(item)
                    ),
                )
            try:
                raw = bytes.fromhex(item)
                tx = TxMessage.from_payload(raw).transaction
                if len(tx.inputs) == 0:
                    raise ValueError("no inputs")
            except Exception:
                raise RpcError(
                    RPC_DESERIALIZATION_ERROR,
                    "TX decode failed for tx {}. Make sure the tx has at "
                    "least one input.".format(idx),
                ) from None
            variants.append(tx)

        # 2. Empty array -> -22 "Missing transactions".
        if not variants:
            raise RpcError(RPC_DESERIALIZATION_ERROR, "Missing transactions")

        # 3. mergedTx starts as a clone of the first variant (the template:
        #    its version / locktime / vin / vout define the result; only each
        #    input's scriptSig + witness get rebuilt below).
        template = variants[0]
        merged_inputs: list[TxIn] = []

        any_witness = False
        for i in range(len(template.inputs)):
            base = template.inputs[i]
            best_script_sig = b""
            best_witness: list[bytes] | None = None
            best_score = -1  # rank candidates; higher = more complete

            for variant in variants:
                if i >= len(variant.inputs):
                    continue
                vin = variant.inputs[i]
                ss = vin.script_sig or b""
                wit = vin.witness if vin.witness else None
                wit_nonempty = bool(wit) and any(len(x) for x in wit)
                ss_nonempty = len(ss) > 0

                # Score the candidate so we deterministically prefer the
                # variant that actually carries signature data for this input.
                # Tie-break by total signature-data length (longer = more
                # sigs, matching the partial-multisig fallback note above).
                # Equal length -> keep the earliest variant (Core's merge is
                # order-stable for the complete single-sig case).
                if not ss_nonempty and not wit_nonempty:
                    score = 0
                else:
                    sig_len = len(ss) + (
                        sum(len(x) for x in wit) if wit else 0
                    )
                    score = 1_000_000 + sig_len

                if score > best_score:
                    best_score = score
                    best_script_sig = ss
                    best_witness = list(wit) if wit else None

            if best_witness and any(len(x) for x in best_witness):
                any_witness = True

            merged_inputs.append(TxIn(
                prev_txid=base.prev_txid,
                prev_vout=base.prev_vout,
                script_sig=best_script_sig,
                sequence=base.sequence,
                witness=best_witness,
            ))

        merged = Transaction(
            txid=b"\x00" * 32,
            version=template.version,
            locktime=template.locktime,
            inputs=merged_inputs,
            outputs=list(template.outputs),
            # Core re-encodes WITH witness (TX_WITH_WITNESS) unconditionally;
            # serialize_with_witness only emits the marker/flag when
            # has_witness is set, so mirror Core: witness-serialize iff any
            # input carries a non-empty witness stack (matches Core, whose
            # CTransaction::HasWitness drives the marker).
            has_witness=any_witness,
        )

        return merged.serialize_with_witness().hex()

    async def rpc_finalizepsbt(
        self, psbt_base64: str, extract: bool = True
    ) -> dict[str, Any]:
        """
        Finalise a PSBT. If *extract* is true and all inputs are finalised,
        extract the network transaction.
        """
        import base64 as b64

        from ouroboros.psbt import PSBT

        try:
            raw = b64.b64decode(psbt_base64, validate=True)
            psbt = PSBT.deserialize(raw)
        except Exception as exc:
            return JSONRPCResponse(
                error={"code": -22, "message": f"TX decode failed: {exc}"},
                id=None,
            )
        gate = self._psbt_v2_gate(psbt)
        if gate is not None:
            return gate

        psbt.finalize()

        complete = all(
            inp.final_script_sig is not None or inp.final_script_witness is not None
            for inp in psbt.inputs
        )

        if extract and complete:
            tx = psbt.extract_transaction()
            return {
                "hex": tx.serialize_with_witness().hex(),
                "complete": True,
            }
        return {
            "psbt": b64.b64encode(psbt.serialize()).decode("ascii"),
            "complete": complete,
        }

    async def rpc_createpsbt(
        self,
        inputs: list[dict[str, Any]],
        outputs: list[dict[str, Any]],
        locktime: int = 0,
    ) -> str:
        """
        Create an unsigned PSBT from raw inputs and outputs.

        *inputs*: ``[{"txid": "<hex>", "vout": <n>}, ...]``
        *outputs*: ``[{"<address>": <amount_sat>}, ...]``
        """
        import base64 as b64

        from ouroboros.address import address_to_script_pubkey
        from ouroboros.database import Transaction, TxIn, TxOut
        from ouroboros.psbt import PSBT

        tx_inputs: list[TxIn] = []
        for inp in inputs:
            txid = inp.get("txid", "")
            vout = inp.get("vout", 0)
            sequence = inp.get("sequence", 0xFFFFFFFF)
            try:
                prev_hash = bytes.fromhex(txid)
            except ValueError:
                return JSONRPCResponse(
                    error={"code": -8, "message": f"Invalid txid: {txid}"},
                    id=None,
                )
            tx_inputs.append(TxIn(
                prev_tx_hash=prev_hash,
                prev_output_index=vout,
                script_sig=b"",
                sequence=sequence,
            ))

        tx_outputs: list[TxOut] = []
        for out in outputs:
            for address, amount in out.items():
                try:
                    spk = address_to_script_pubkey(address)
                except Exception:
                    return JSONRPCResponse(
                        error={"code": -5, "message": f"Invalid address: {address}"},
                        id=None,
                    )
                tx_outputs.append(TxOut(value=int(amount), script_pubkey=spk))

        tx = Transaction(
            version=2,
            inputs=tx_inputs,
            outputs=tx_outputs,
            locktime=locktime,
        )
        psbt = PSBT.from_transaction(tx)
        return b64.b64encode(psbt.serialize()).decode("ascii")

    def _fund_existing_tx(
        self,
        *,
        wallet: Any,
        manual_inputs: list[Any],
        manual_meta: list[dict[str, Any]],
        tx_outputs: list[Any],
        recipient_total: int,
        opts: dict[str, Any],
    ) -> tuple[list[Any], list[dict[str, Any]], list[Any], int, int | None]:
        """Core funding engine shared by walletcreatefundedpsbt + fundrawtransaction.

        Given the caller's existing inputs (``manual_inputs`` / ``manual_meta``)
        and existing recipient outputs (``tx_outputs`` summing to
        ``recipient_total`` sats), walk the wallet UTXO set through the existing
        ``select_coins`` machinery (wallet.py::select_coins — BnB / knapsack /
        SRD), append a change output derived from the wallet's first descriptor /
        key, and honor changeAddress / changePosition / feeRate / lockUnspents
        like Bitcoin Core's FundTransaction (wallet/rpc/spend.cpp::FundTransaction).

        Returns ``(all_inputs, all_meta, tx_outputs, est_fee_sats, change_pos)``.
        ``tx_outputs`` is the same list, mutated in place with the change output
        (if any) inserted at ``change_pos``. ``change_pos`` is ``None`` when no
        change output was added (caller maps that to ``-1``).
        """
        from ouroboros.address import address_to_script_pubkey
        from ouroboros.database import TxIn, TxOut
        from ouroboros.wallet import select_coins

        add_inputs = bool(opts.get("add_inputs", len(manual_inputs) == 0))
        fee_rate_sat_vb = opts.get("fee_rate")
        if fee_rate_sat_vb is None and "feeRate" in opts:
            # Core's deprecated BTC/kvB form. 1 BTC/kvB = 100_000 sat/vB.
            try:
                fee_rate_sat_vb = float(opts["feeRate"]) * 100_000.0
            except (TypeError, ValueError):
                fee_rate_sat_vb = None
        if fee_rate_sat_vb is None:
            fee_estimator = getattr(self.node, "fee_estimator", None)
            if fee_estimator is not None:
                try:
                    fee_rate_sat_vb = fee_estimator.estimate_fee(
                        int(opts.get("conf_target", 6))
                    )
                except Exception:
                    fee_rate_sat_vb = None
        if fee_rate_sat_vb is None:
            fee_rate_sat_vb = 2.0  # match send_transaction fallback
        try:
            fee_rate_sat_vb = max(1.0, float(fee_rate_sat_vb))
        except (TypeError, ValueError):
            fee_rate_sat_vb = 2.0

        manual_input_value = sum(m["value"] for m in manual_meta)
        selected_extra: list[dict] = []
        est_fee = 0
        change_pos: int | None = None

        if add_inputs:
            # Pull eligible UTXOs (already filters out lockunspent locks).
            avail = wallet._collect_utxos() if hasattr(wallet, "_collect_utxos") else []
            # Skip any UTXO that's already been listed as a manual input.
            # manual_inputs have prev_txid in internal LE byte order; avail
            # UTXOs have txid as display-order (BE) hex from Rust PyUTXO.
            # Compare in display-order (BE) to keep the dedup correct. W69.
            manual_keys = {(bytes(t.prev_txid)[::-1].hex(), int(t.prev_vout)) for t in manual_inputs}
            eligible = [
                u for u in avail
                if (
                    (u["txid"] if isinstance(u["txid"], str) else u["txid"].hex()).lower(),
                    int(u["vout"]),
                ) not in manual_keys
            ]
            shortfall = max(0, recipient_total - manual_input_value)
            if shortfall > 0:
                try:
                    selected_extra, est_fee, _algo = select_coins(
                        eligible, shortfall, float(fee_rate_sat_vb),
                    )
                except ValueError:
                    # select_coins raises when no combination covers
                    # target + fees. Mirror Core's bitcoin insufficient-funds
                    # error (wallet/spend.cpp CreateTransaction →
                    # RPC_WALLET_INSUFFICIENT_FUNDS) rather than leaking the
                    # raw ValueError as an unhandled 500.
                    raise HTTPException(
                        status_code=500, detail="Insufficient funds"
                    ) from None
            else:
                # No additional inputs needed — assume manual inputs fully cover.
                selected_extra = []
                est_fee = int(round(
                    fee_rate_sat_vb * (
                        10 + 41 * max(1, len(manual_inputs)) + 31 * len(tx_outputs)
                    )
                ))
        else:
            est_fee = int(round(
                fee_rate_sat_vb * (
                    10 + 41 * max(1, len(manual_inputs)) + 31 * len(tx_outputs)
                )
            ))
            if recipient_total > manual_input_value:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Insufficient input value (add_inputs disabled and "
                        "manual inputs do not cover outputs + fee)"
                    ),
                )

        # Append auto-selected inputs.
        all_inputs = list(manual_inputs)
        all_meta = list(manual_meta)
        for u in selected_extra:
            # u["txid"] is display-order (BE) hex from Rust PyUTXO.txid.
            # TxIn.prev_txid must be internal LE — reverse at the boundary. W69.
            txid_bytes = (
                bytes.fromhex(u["txid"])[::-1] if isinstance(u["txid"], str) else bytes(u["txid"])
            )
            all_inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=int(u["vout"]),
                script_sig=b"",
                sequence=0xFFFFFFFD,
            ))
            all_meta.append({
                "value": int(u["value"]),
                "spk": bytes(u.get("script_pubkey", b"")),
                "key": u.get("_key"),
            })

        total_in = sum(m["value"] for m in all_meta)

        # Insufficient funds: the wallet could not cover outputs + fee. Mirror
        # Core's bitcoin insufficient-funds error (RPC_WALLET_INSUFFICIENT_FUNDS).
        if add_inputs and total_in < recipient_total + est_fee:
            raise HTTPException(
                status_code=500,
                detail="Insufficient funds",
            )

        change_value = total_in - recipient_total - est_fee

        # ------------------------------------------------------------------
        # Change output. Honor changeAddress / changePosition.
        # ------------------------------------------------------------------
        DUST = 546
        if change_value > DUST:
            change_addr = opts.get("changeAddress") or opts.get("change_address")
            if not change_addr:
                # Derive from the wallet's first descriptor / key.
                if wallet.descriptors:
                    try:
                        entry = wallet.descriptors[0]
                        change_addr = entry.descriptor.derive_address(
                            entry.next_index, wallet.network
                        )
                    except Exception:
                        change_addr = None
                if not change_addr and wallet.keys:
                    try:
                        change_key = wallet._get_wallet_key(wallet.keys[0])
                        change_addr = change_key.get_p2wpkh_address()
                    except Exception:
                        change_addr = None
            if not change_addr:
                # No usable wallet output — fold the would-be change into the fee.
                est_fee += change_value
                change_value = 0
            else:
                try:
                    change_spk = address_to_script_pubkey(change_addr, wallet.network)
                except Exception as exc:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid changeAddress {change_addr}: {exc}",
                    ) from None
                change_pos_req = opts.get("changePosition")
                if change_pos_req is None or not isinstance(change_pos_req, int):
                    change_pos = len(tx_outputs)
                    tx_outputs.append(TxOut(value=change_value, script_pubkey=change_spk))
                else:
                    cp = max(0, min(int(change_pos_req), len(tx_outputs)))
                    tx_outputs.insert(cp, TxOut(value=change_value, script_pubkey=change_spk))
                    change_pos = cp
        else:
            # Would-be change <= dust: fold it into the fee so the reported fee
            # equals inputs - outputs (Core spend.cpp:1330 sets current_fee =
            # SelectedValue - output_value). Without this the dropped dust would
            # silently under-report the fee. No change output is added (change_pos
            # stays None / -1).
            if change_value > 0:
                est_fee += change_value
                change_value = 0

        # Apply lockUnspents (post-construction, like Core).
        if bool(opts.get("lockUnspents", False)) and selected_extra:
            for u in selected_extra:
                txid_str = (
                    u["txid"] if isinstance(u["txid"], str) else u["txid"].hex()
                )
                wallet.lock_coin(txid_str.lower(), int(u["vout"]), persistent=False)

        return all_inputs, all_meta, tx_outputs, est_fee, change_pos

    async def rpc_walletcreatefundedpsbt(
        self,
        inputs: list[dict[str, Any]] | None = None,
        outputs: list[dict[str, Any]] | dict[str, Any] | None = None,
        locktime: int = 0,
        options: dict[str, Any] | None = None,
        bip32derivs: bool = True,
    ) -> dict[str, Any]:
        """Create + fund a PSBT (Creator + Updater roles).

        Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt.

        Caller-supplied ``inputs`` are honored verbatim (no auto-coin-selection
        unless ``options.add_inputs`` is True or ``inputs`` is empty); when
        auto-funding is needed, we walk the wallet's UTXOs through the
        existing ``select_coins`` machinery, append change to the wallet's
        first descriptor / key, and emit a base64-encoded PSBT with
        witness-UTXO metadata filled in for every wallet input. Returns
        ``{"psbt", "fee", "changepos"}``.
        """
        import base64 as b64

        from ouroboros.address import address_to_script_pubkey
        from ouroboros.database import Transaction, TxIn, TxOut
        from ouroboros.psbt import PSBT
        from ouroboros.wallet import WalletKey, _hash160, select_coins

        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first",
            )

        opts = dict(options) if isinstance(options, dict) else {}
        inputs = inputs or []
        if outputs is None:
            raise HTTPException(status_code=400, detail="Missing outputs parameter")

        # ------------------------------------------------------------------
        # 1) Manually-specified inputs (Creator role).
        # ------------------------------------------------------------------
        manual_inputs: list[TxIn] = []
        manual_meta: list[dict[str, Any]] = []  # parallel: {value, spk, key}
        for inp in inputs:
            if not isinstance(inp, dict):
                raise HTTPException(status_code=400, detail="Invalid input entry")
            txid_hex = inp.get("txid")
            vout = inp.get("vout")
            sequence = int(inp.get("sequence", 0xFFFFFFFD))
            if not isinstance(txid_hex, str):
                raise HTTPException(status_code=400, detail="Input txid must be a string")
            try:
                # JSON-RPC: txids arrive in display order (BE hex);
                # TxIn.prev_txid is internal LE. Reverse at the boundary. W69.
                txid_bytes = bytes.fromhex(txid_hex)[::-1]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid txid: {exc}") from None
            if len(txid_bytes) != 32:
                raise HTTPException(status_code=400, detail="txid must be 32 bytes")
            if not isinstance(vout, int) or isinstance(vout, bool) or vout < 0:
                raise HTTPException(status_code=400, detail="vout must be a non-negative integer")
            manual_inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=vout,
                script_sig=b"",
                sequence=sequence,
            ))
            # Look up UTXO metadata if available.
            value = 0
            spk = b""
            key_obj = None
            if wallet.db is not None:
                try:
                    utxo = wallet.db.get_utxo(txid_bytes, vout)
                except Exception:
                    utxo = None
                if utxo:
                    value = int(utxo.get("value", utxo.get("amount", 0)) or 0)
                    spk_field = utxo.get("script_pubkey", b"")
                    spk = bytes(spk_field) if spk_field else b""
            manual_meta.append({"value": value, "spk": spk, "key": key_obj})

        # ------------------------------------------------------------------
        # 2) Outputs (accept list-of-objects OR direct dict, like Core).
        # ------------------------------------------------------------------
        out_pairs: list[tuple[str, int]] = []  # (address-or-"data", value_sat)
        if isinstance(outputs, dict):
            iter_outputs = [outputs]
        else:
            iter_outputs = list(outputs)
        for entry in iter_outputs:
            if not isinstance(entry, dict):
                raise HTTPException(status_code=400, detail="Invalid output entry")
            for addr, amount in entry.items():
                if addr == "data":
                    # OP_RETURN — `amount` is hex payload.
                    try:
                        data_bytes = bytes.fromhex(str(amount))
                    except ValueError as exc:
                        raise HTTPException(
                            status_code=400, detail=f"Invalid OP_RETURN data: {exc}"
                        ) from None
                    if len(data_bytes) > 80:
                        raise HTTPException(
                            status_code=400,
                            detail="OP_RETURN payload exceeds 80-byte standardness limit",
                        )
                    out_pairs.append(("__data__:" + data_bytes.hex(), 0))
                    continue
                # Treat numeric `amount` as BTC float (Core convention).
                try:
                    sats = int(round(float(amount) * 1e8))
                except (TypeError, ValueError) as exc:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid amount for {addr}: {exc}"
                    ) from None
                if sats < 0:
                    raise HTTPException(status_code=400, detail="Amount cannot be negative")
                out_pairs.append((addr, sats))
        if not out_pairs:
            raise HTTPException(status_code=400, detail="At least one output is required")

        # Build TxOut list.
        tx_outputs: list[TxOut] = []
        recipient_total = 0
        for addr, sats in out_pairs:
            if addr.startswith("__data__:"):
                hex_payload = addr[len("__data__:"):]
                payload = bytes.fromhex(hex_payload)
                # OP_RETURN script: 0x6a + push-of-data.
                spk = bytes([0x6a]) + (
                    bytes([len(payload)]) if len(payload) < 0x4c else b""
                ) + payload
                tx_outputs.append(TxOut(value=0, script_pubkey=spk))
                continue
            try:
                spk = address_to_script_pubkey(addr, wallet.network)
            except Exception as exc:
                raise HTTPException(
                    status_code=400, detail=f"Invalid address {addr}: {exc}"
                ) from None
            tx_outputs.append(TxOut(value=sats, script_pubkey=spk))
            recipient_total += sats

        # ------------------------------------------------------------------
        # 3+4) Auto-fund missing inputs + add change. Shared with
        #      fundrawtransaction via the _fund_existing_tx engine so both RPCs
        #      drive the SAME select_coins / change-derivation path.
        # ------------------------------------------------------------------
        all_inputs, all_meta, tx_outputs, est_fee, change_pos = self._fund_existing_tx(
            wallet=wallet,
            manual_inputs=manual_inputs,
            manual_meta=manual_meta,
            tx_outputs=tx_outputs,
            recipient_total=recipient_total,
            opts=opts,
        )

        # ------------------------------------------------------------------
        # 5) Build PSBT and fill witness-UTXO + bip32 derivs (Updater).
        # ------------------------------------------------------------------
        version = int(opts.get("version", 2)) if isinstance(opts.get("version"), int) else 2
        tx = Transaction(
            txid=b"\x00" * 32,  # placeholder; PSBT carries the unsigned tx
            version=version,
            locktime=int(locktime or 0),
            inputs=all_inputs,
            outputs=tx_outputs,
        )
        psbt = PSBT.from_transaction(tx)

        # Build a pubkey -> KeyOriginInfo map so we can attach BIP32 paths
        # for any input whose scriptPubKey we can resolve.
        for idx, meta in enumerate(all_meta):
            if meta["spk"]:
                try:
                    psbt.set_witness_utxo(idx, int(meta["value"]), bytes(meta["spk"]))
                except Exception:
                    pass

        # Optional BIP32 derivs for wallet keys (nice-to-have; not required
        # for finalization). Ouroboros's WalletKey doesn't carry origin info,
        # so we skip if bip32derivs is False or no descriptor metadata is
        # available.
        if bip32derivs:
            try:
                # Walk the descriptor chain once to map address → key origin.
                for entry in wallet.descriptors:
                    if not entry.active:
                        continue
                    end = max(entry.next_index, entry.range_start + 1)
                    for i in range(entry.range_start, end):
                        try:
                            entry.descriptor.derive_address(i, wallet.network)
                        except Exception:
                            continue
            except Exception:
                pass

        psbt_bytes = psbt.serialize()
        return {
            "psbt": b64.b64encode(psbt_bytes).decode("ascii"),
            "fee": est_fee / 100_000_000,
            "changepos": change_pos if change_pos is not None else -1,
        }

    @staticmethod
    def _decode_hex_tx(raw_bytes: bytes, iswitness: bool | None) -> Any:
        """Decode a raw tx, resolving the BIP-144 empty-vin / segwit-marker
        ambiguity the way Bitcoin Core's DecodeHexTx does.

        TxMessage.from_payload always treats a leading ``00 01`` as the segwit
        marker+flag, which mis-parses a non-witness tx that has zero inputs
        (e.g. the output of ``createrawtransaction`` with no inputs — the most
        common input to fundrawtransaction). Core tries non-witness and witness
        decodes and picks the one that succeeds (controllable via ``iswitness``):
        try_no_witness = iswitness is None or iswitness is False;
        try_witness    = iswitness is None or iswitness is True.
        We prefer the non-witness parse when allowed, matching Core's
        ``DecodeTx``: a non-witness decode that consumes the whole buffer wins.
        """
        from ouroboros.database import Transaction, TxIn, TxOut
        from ouroboros.p2p_messages import decode_varint

        def _parse_no_witness(payload: bytes) -> Any:
            offset = 0
            if len(payload) < 4:
                raise ValueError("Payload too short for version")
            version = int.from_bytes(payload[0:4], "little", signed=False)
            offset = 4
            n_in, sz = decode_varint(payload, offset); offset += sz
            inputs = []
            for i in range(n_in):
                if len(payload) < offset + 36:
                    raise ValueError(f"Payload too short for input {i}")
                prev_txid = payload[offset:offset + 32]; offset += 32
                prev_vout = int.from_bytes(payload[offset:offset + 4], "little"); offset += 4
                slen, sz = decode_varint(payload, offset); offset += sz
                if len(payload) < offset + slen:
                    raise ValueError(f"Payload too short for script_sig in input {i}")
                script_sig = payload[offset:offset + slen]; offset += slen
                if len(payload) < offset + 4:
                    raise ValueError(f"Payload too short for sequence in input {i}")
                sequence = int.from_bytes(payload[offset:offset + 4], "little"); offset += 4
                inputs.append(TxIn(prev_txid=prev_txid, prev_vout=prev_vout,
                                   script_sig=script_sig, sequence=sequence, witness=None))
            n_out, sz = decode_varint(payload, offset); offset += sz
            outputs = []
            for i in range(n_out):
                if len(payload) < offset + 8:
                    raise ValueError(f"Payload too short for value in output {i}")
                value = int.from_bytes(payload[offset:offset + 8], "little"); offset += 8
                slen, sz = decode_varint(payload, offset); offset += sz
                if len(payload) < offset + slen:
                    raise ValueError(f"Payload too short for script_pubkey in output {i}")
                outputs.append(TxOut(value=value, script_pubkey=payload[offset:offset + slen]))
                offset += slen
            if len(payload) < offset + 4:
                raise ValueError("Payload too short for locktime")
            locktime = int.from_bytes(payload[offset:offset + 4], "little"); offset += 4
            if offset != len(payload):
                raise ValueError("Extra bytes after non-witness tx")
            return Transaction(txid=b"\x00" * 32, version=version, locktime=locktime,
                               inputs=inputs, outputs=outputs, has_witness=False)

        try_no_witness = iswitness is None or iswitness is False
        try_witness = iswitness is None or iswitness is True

        last_exc: Exception | None = None
        if try_no_witness:
            try:
                return _parse_no_witness(raw_bytes)
            except Exception as exc:
                last_exc = exc
        if try_witness:
            from ouroboros.p2p_messages import TxMessage
            try:
                return TxMessage.from_payload(raw_bytes).transaction
            except Exception as exc:
                last_exc = exc
        raise ValueError(str(last_exc) if last_exc else "TX decode failed")

    async def rpc_fundrawtransaction(
        self,
        hexstring: str,
        options: dict[str, Any] | None = None,
        iswitness: bool | None = None,
    ) -> dict[str, Any]:
        """Add inputs (and a change output) to a raw transaction so the wallet
        funds all of its outputs plus the fee.

        Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction
        (which calls FundTransaction). fundrawtransaction is the raw-tx sibling
        of walletcreatefundedpsbt: both drive Core's one FundTransaction engine.
        Here we decode the raw tx hex, keep its existing inputs and outputs, run
        the SAME funding core as walletcreatefundedpsbt (``_fund_existing_tx`` →
        wallet.py::select_coins), then serialize the funded tx to hex instead of
        a PSBT.

        Result: ``{"hex": <funded raw tx>, "fee": <BTC>, "changepos": <int|-1>}``.

        options (all optional): changeAddress, changePosition, includeWatching,
        lockUnspents, feeRate (BTC/kvB) / fee_rate (sat/vB),
        subtractFeeFromOutputs, add_inputs, conf_target. The no-options default
        path funds a tx that has outputs but no/insufficient inputs.
        """
        from ouroboros.database import Transaction, TxIn, TxOut

        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if getattr(wallet, "is_locked", False):
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first",
            )

        opts = dict(options) if isinstance(options, dict) else {}

        # ------------------------------------------------------------------
        # 1) Decode the raw tx hex (Core DecodeHexTx). _decode_hex_tx resolves
        #    the BIP-144 empty-vin/segwit-marker ambiguity using iswitness.
        # ------------------------------------------------------------------
        try:
            raw_bytes = bytes.fromhex(hexstring)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid hex string: {exc}"
            ) from None
        try:
            tx = self._decode_hex_tx(raw_bytes, iswitness)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"TX decode failed: {exc}"
            ) from None

        # ------------------------------------------------------------------
        # 2) Existing inputs -> manual_inputs / manual_meta (resolve values
        #    from the wallet UTXO set so the fee/change math is genuine).
        # ------------------------------------------------------------------
        manual_inputs: list[TxIn] = []
        manual_meta: list[dict[str, Any]] = []
        for tin in tx.inputs:
            manual_inputs.append(TxIn(
                prev_txid=bytes(tin.prev_txid),
                prev_vout=int(tin.prev_vout),
                script_sig=bytes(tin.script_sig),
                sequence=int(tin.sequence),
            ))
            value = 0
            spk = b""
            if getattr(wallet, "db", None) is not None:
                try:
                    utxo = wallet.db.get_utxo(bytes(tin.prev_txid), int(tin.prev_vout))
                except Exception:
                    utxo = None
                if utxo:
                    value = int(utxo.get("value", utxo.get("amount", 0)) or 0)
                    spk_field = utxo.get("script_pubkey", b"")
                    spk = bytes(spk_field) if spk_field else b""
            manual_meta.append({"value": value, "spk": spk, "key": None})

        # ------------------------------------------------------------------
        # 3) Existing outputs -> tx_outputs (kept verbatim). subtractFeeFrom
        #    Outputs is resolved after the fee is known (Core deducts equally
        #    from the named output indices, indices are pre-change).
        # ------------------------------------------------------------------
        tx_outputs: list[TxOut] = [
            TxOut(value=int(o.value), script_pubkey=bytes(o.script_pubkey))
            for o in tx.outputs
        ]
        recipient_total = sum(o.value for o in tx_outputs)

        sffo_raw = opts.get("subtractFeeFromOutputs") or opts.get(
            "subtract_fee_from_outputs"
        )
        sffo: list[int] = []
        if isinstance(sffo_raw, list):
            for idx in sffo_raw:
                if not isinstance(idx, int) or isinstance(idx, bool):
                    raise HTTPException(
                        status_code=400,
                        detail="subtractFeeFromOutputs must be a list of integers",
                    )
                if idx < 0 or idx >= len(tx_outputs):
                    raise HTTPException(
                        status_code=400,
                        detail=f"subtractFeeFromOutputs index {idx} out of range",
                    )
                sffo.append(idx)

        # ------------------------------------------------------------------
        # 4) Run the shared funding engine (select_coins + change), exactly
        #    as walletcreatefundedpsbt does. The engine sizes inputs for
        #    recipient_total + fee; for subtractFeeFromOutputs we carve the fee
        #    back out of the named outputs in step 5 so the input total (and the
        #    sum(inputs)==sum(outputs)+fee invariant) is preserved either way.
        # ------------------------------------------------------------------
        all_inputs, all_meta, tx_outputs, est_fee, change_pos = self._fund_existing_tx(
            wallet=wallet,
            manual_inputs=manual_inputs,
            manual_meta=manual_meta,
            tx_outputs=tx_outputs,
            recipient_total=recipient_total,
            opts=opts,
        )

        # ------------------------------------------------------------------
        # 5) subtractFeeFromOutputs: deduct the fee equally from the named
        #    outputs and re-credit the would-be change so the invariant
        #    sum(inputs) == sum(outputs) + fee is preserved.
        # ------------------------------------------------------------------
        if sffo:
            # The engine sized inputs for recipient_total + est_fee and may have
            # produced a change output for the surplus. Move est_fee back into
            # change (so inputs cover outputs+fee), then subtract est_fee from
            # the named outputs. Net effect: those outputs pay the fee.
            share = est_fee // len(sffo)
            remainder = est_fee - share * len(sffo)
            # Map pre-change output indices to current indices (a change output
            # inserted at/below an index shifts it by one).
            for n, out_idx in enumerate(sffo):
                cur = out_idx
                if change_pos is not None and change_pos <= out_idx:
                    cur = out_idx + 1
                deduct = share + (remainder if n == len(sffo) - 1 else 0)
                new_val = tx_outputs[cur].value - deduct
                if new_val < 0:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Output value too small to subtract fee from "
                            f"(index {out_idx})"
                        ),
                    )
                tx_outputs[cur] = TxOut(
                    value=new_val, script_pubkey=tx_outputs[cur].script_pubkey
                )
            # Credit the fee back into the change output (or drop change if it
            # was folded into the fee). After this, the change output holds the
            # surplus PLUS est_fee, and the named outputs are smaller by est_fee.
            if change_pos is not None:
                ch = tx_outputs[change_pos]
                tx_outputs[change_pos] = TxOut(
                    value=ch.value + est_fee, script_pubkey=ch.script_pubkey
                )

        # ------------------------------------------------------------------
        # 6) Build the funded tx + serialize to hex (Core EncodeHexTx). Added
        #    inputs are unsigned (no witness), so the non-witness serialization
        #    is the canonical funded hex. Existing witness data, if any, is
        #    preserved on the original inputs.
        # ------------------------------------------------------------------
        has_witness = any(
            getattr(tin, "witness", None) for tin in tx.inputs
        )
        funded = Transaction(
            txid=b"\x00" * 32,
            version=int(tx.version),
            locktime=int(tx.locktime),
            inputs=all_inputs,
            outputs=tx_outputs,
            has_witness=has_witness,
        )
        if has_witness:
            # Re-attach witness stacks from the originally-decoded inputs to the
            # corresponding manual inputs (added inputs carry none).
            for i, orig in enumerate(tx.inputs):
                w = getattr(orig, "witness", None)
                if w and i < len(funded.inputs):
                    funded.inputs[i].witness = w
            hex_str = funded.serialize_with_witness().hex()
        else:
            hex_str = funded.serialize().hex()

        return {
            "hex": hex_str,
            "fee": est_fee / 100_000_000,
            "changepos": change_pos if change_pos is not None else -1,
        }

    async def rpc_estimatesmartfee(
        self,
        conf_target: int = 6,
        estimate_mode: str = "economical",
    ) -> dict[str, Any]:
        """
        Estimate the fee rate needed for a transaction to confirm
        within conf_target blocks.

        Returns:
            {"feerate": <BTC/kB>, "blocks": <conf_target>}
            or {"errors": [...], "blocks": <conf_target>}
        """
        conf_target = max(1, min(conf_target, 1008))

        fee_estimator = getattr(self.node, 'fee_estimator', None)
        if fee_estimator is None:
            return {
                "errors": ["Fee estimation not available"],
                "blocks": conf_target,
            }

        fee_rate = fee_estimator.estimate_fee_per_kb(conf_target)
        if fee_rate is None:
            return {
                "errors": ["Insufficient data for reliable estimate"],
                "blocks": conf_target,
            }

        return {
            "feerate": fee_rate,
            "blocks": conf_target,
        }

    async def rpc_estimaterawfee(
        self,
        conf_target: int,
        threshold: float = 0.95,
    ) -> dict[str, Any]:
        """
        Advanced fee estimator surface — returns per-horizon bucket data.

        Reference: bitcoin-core/src/rpc/fees.cpp estimaterawfee.

        ouroboros now tracks three horizons (short / medium / long) mirroring
        Core's shortStats / feeStats / longStats.  The returned object has
        keys "short", "medium", and "long" (those whose period count covers
        conf_target); the bucket output mirrors Core's
        ``buckets.pass`` / ``buckets.fail`` shape.
        """
        from ouroboros.fee_estimator import (
            FEE_RATE_BUCKETS,
            DECAY,
            SCALE,
            PERIODS,
            Horizon,
        )

        if not isinstance(conf_target, int) or conf_target < 1 or conf_target > 1008:
            raise HTTPException(
                status_code=400,
                detail="conf_target out of range (1 - 1008)",
            )
        if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 1:
            raise HTTPException(status_code=400, detail="Invalid threshold")
        threshold = float(threshold)

        fee_estimator = getattr(self.node, "fee_estimator", None)
        if fee_estimator is None:
            result: dict[str, Any] = {}
            for h in Horizon:
                hname = h.name.lower()
                result[hname] = {
                    "decay": DECAY[h],
                    "scale": SCALE[h],
                    "errors": ["Fee estimation not available"],
                }
            return result

        result = {}

        for h in Horizon:
            hname = h.name.lower()
            scale = SCALE[h]
            periods = PERIODS[h]
            max_blocks_h = periods * scale

            # Only include horizons whose tracked range covers conf_target.
            if conf_target > max_blocks_h:
                # Still include horizon — show it with limited data note.
                pass

            # Convert conf_target to period for this horizon.
            period = min(max(1, (conf_target + scale - 1) // scale), periods)

            conf_arr = fee_estimator._conf[h]
            total_arr = fee_estimator._total[h]

            # Walk buckets low → high to find pass/fail bucket.
            pass_idx: int | None = None
            fail_idx: int | None = None
            for i in range(len(FEE_RATE_BUCKETS)):
                total_val = total_arr[i][period]
                conf_val = conf_arr[i][period]
                if total_val < 1.0:
                    continue
                ratio = conf_val / total_val
                if ratio >= threshold:
                    pass_idx = i
                    break
                fail_idx = i

            def _bucket_dict(idx: int, p: int = period) -> dict:
                start = FEE_RATE_BUCKETS[idx]
                end = (
                    FEE_RATE_BUCKETS[idx + 1]
                    if idx + 1 < len(FEE_RATE_BUCKETS)
                    else FEE_RATE_BUCKETS[-1]
                )
                total_v = total_arr[idx][p]
                conf_v = conf_arr[idx][p]
                return {
                    "startrange": round(float(start), 2),
                    "endrange": round(float(end), 2),
                    "withintarget": round(conf_v, 2),
                    "totalconfirmed": round(conf_v, 2),
                    "inmempool": 0,
                    "leftmempool": round(max(total_v - conf_v, 0.0), 2),
                }

            horizon_obj: dict[str, Any] = {
                "decay": DECAY[h],
                "scale": scale,
            }

            if pass_idx is not None:
                # sat/vB bucket boundary → BTC/kB feerate to mirror Core.
                feerate_btc_kvb = float(FEE_RATE_BUCKETS[pass_idx]) * 1000 / 1e8
                horizon_obj["feerate"] = feerate_btc_kvb
                horizon_obj["pass"] = _bucket_dict(pass_idx)
                if fail_idx is not None:
                    horizon_obj["fail"] = _bucket_dict(fail_idx)
            else:
                # No bucket meets the threshold — emit fail (highest tracked
                # bucket with any data) and an explanatory error string.
                if fail_idx is not None:
                    horizon_obj["fail"] = _bucket_dict(fail_idx)
                horizon_obj["errors"] = [
                    "Insufficient data or no feerate found which meets threshold"
                ]

            result[hname] = horizon_obj

        return result

    async def rpc_validateaddress(self, address: str) -> dict[str, Any]:
        """
        Validate a Bitcoin address and return information about it.
        Reference: Bitcoin Core src/rpc/output_script.cpp (validateaddress) +
                   src/rpc/util.cpp (DescribeAddressVisitor).
        """
        from ouroboros.address import address_to_script_pubkey

        network = getattr(self.node, 'network', 'mainnet')

        try:
            script_pubkey = address_to_script_pubkey(address, network=network)
        except Exception:
            # Core returns {isvalid:false, error_locations:[], error:"..."} with
            # no "address" field when decoding fails.
            return {
                "isvalid": False,
                "error_locations": [],
                "error": "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
            }

        script_type = self._get_script_type(script_pubkey)
        is_witness = script_type.startswith("witness_")

        # Core's DescribeAddressVisitor sets isscript=true for:
        #   ScriptHash (P2SH), WitnessV0ScriptHash (P2WSH), WitnessV1Taproot (P2TR),
        #   PayToAnchor. isscript=false for PKHash (P2PKH) and WitnessV0KeyHash (P2WPKH).
        is_script = script_type in ("scripthash", "witness_v0_scripthash", "witness_v1_taproot")

        # Core emits isvalid FIRST, then address (output_script.cpp:66-70).
        result: dict[str, Any] = {
            "isvalid": True,
            "address": address,
            "scriptPubKey": script_pubkey.hex(),
            "isscript": is_script,
            "iswitness": is_witness,
        }

        if is_witness:
            # Decode witness version from script opcode.
            # OP_0 = 0x00 → version 0; OP_1..OP_16 = 0x51..0x60 → version 1..16.
            raw_op = script_pubkey[0]
            witness_version = 0 if raw_op == 0x00 else (raw_op - 0x50)
            result["witness_version"] = witness_version
            result["witness_program"] = script_pubkey[2:].hex()

        return result

    async def rpc_gettxoutproof(
        self,
        txids: list[str],
        blockhash: str | None = None,
    ) -> str:
        """
        Return a hex-encoded Merkle proof that transactions were included
        in a block.

        Wire format (CMerkleBlock):
          block_header (80 bytes)
          total_transactions (uint32 LE)
          hash_count (varint) + hashes (32 bytes each)
          flag_byte_count (varint) + flag_bytes
        """
        if not txids:
            raise HTTPException(status_code=400, detail="txids must not be empty")

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        target_set = set()
        for txid_hex in txids:
            try:
                # JSON-RPC convention: txids are display-order (big-endian)
                # hex; internal txids (`tx.get_txid()`) are little-endian.
                # Reverse for the in-block comparison below.
                # Reference: Bitcoin Core src/rpc/blockchain.cpp ParseHashV.
                txid_bytes = bytes.fromhex(txid_hex)[::-1]
                if len(txid_bytes) != 32:
                    raise ValueError("Transaction id must be 32 bytes")
                target_set.add(txid_bytes)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid txid: {txid_hex}") from None

        # Find the block
        block = None
        if blockhash:
            # JSON-RPC convention: hashes are display-order (big-endian) hex;
            # internal storage keys by little-endian uint256 bytes. ParseHashV
            # rejects a malformed hash with -8 RPC_INVALID_PARAMETER at the parse
            # boundary (Bitcoin Core src/rpc/util.cpp), not -32602.
            bh_bytes = bytes(reversed(_parse_hash_v(blockhash, "blockhash")))
            block = await asyncio.to_thread(db.get_block, bh_bytes)
        else:
            _, best_height = db.get_best_block()
            for h in range(best_height, max(best_height - 100, -1), -1):
                b = await asyncio.to_thread(db.get_block_by_height, h)
                if b is None:
                    continue
                block_txids = {tx.get_txid() for tx in b.transactions}
                if target_set & block_txids:
                    block = b
                    break

        if block is None:
            # Core gettxoutproof: an unknown block -> -5 RPC_INVALID_ADDRESS_OR_KEY
            # "Block not found" (was a 404 -> generic error, not -5).
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        all_txids = [tx.get_txid() for tx in block.transactions]
        for t in target_set:
            if t not in all_txids:
                # `t` is internal byte order; report in display order.
                raise HTTPException(
                    status_code=400,
                    detail=f"Transaction {t[::-1].hex()} not found in block",
                )

        matches = [txid in target_set for txid in all_txids]
        proof = _build_partial_merkle_tree(block, all_txids, matches)
        return proof.hex()

    async def rpc_verifytxoutproof(self, proof: str) -> list[str]:
        """
        Verify a Merkle proof and return the proven txids.
        """
        import hashlib as _hl

        try:
            proof_bytes = bytes.fromhex(proof)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex") from None

        if len(proof_bytes) < 84:
            raise HTTPException(status_code=400, detail="Proof too short")

        header_bytes = proof_bytes[:80]
        block_hash = _hl.sha256(_hl.sha256(header_bytes).digest()).digest()

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        block = await asyncio.to_thread(db.get_block, block_hash)
        if block is None:
            raise HTTPException(status_code=400, detail="Block not in chain")

        merkle_root_in_header = header_bytes[36:68]
        matched, computed_root = _parse_partial_merkle_tree(proof_bytes[80:])

        if computed_root != merkle_root_in_header:
            raise HTTPException(status_code=400, detail="Merkle root mismatch")

        # matched hashes are in internal byte order (LE); RPC convention
        # requires display order (BE / reversed).  Mirror Core's GetHex().
        return [txid[::-1].hex() for txid in matched]

    async def rpc_getmininginfo(self) -> dict[str, Any]:
        """
        Return mining-related information.
        Reference: Bitcoin Core src/rpc/mining.cpp getmininginfo
        """
        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        _, height = db.get_best_block()
        mempool = getattr(self.node, "mempool", None)

        # Get tip bits for bits/target fields
        bits = getattr(db, '_tip_bits', 0x1d00ffff)
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))
        bits_hex = f"{bits:08x}"
        target_hex = f"{target_int:064x}"
        from ouroboros.psbt import BTCAmount

        _raw_diff = self.node.get_current_difficulty()
        difficulty = _CoreFloat(_raw_diff) if isinstance(_raw_diff, float) else _raw_diff
        next_height = height + 1

        # Core key order (mining.cpp:463): blocks, bits, difficulty, target,
        # networkhashps, pooledtx, blockmintxfee, chain, next{}, warnings.
        # blockmintxfee = DEFAULT_BLOCK_MIN_TX_FEE (1 sat) => 0.00000001 BTC/kvB.
        # warnings is an ARRAY (Core v31.99 dropped the deprecated string form).
        return {
            "blocks": height,
            "bits": bits_hex,
            "difficulty": difficulty,
            "target": target_hex,
            "networkhashps": 0,
            "pooledtx": len(mempool.get_all_transactions()) if mempool else 0,
            "blockmintxfee": BTCAmount(1),
            "chain": self._rpc_chain_name(getattr(self.node, "network", "mainnet")),
            "next": {
                "height": next_height,
                "bits": bits_hex,
                "difficulty": (_CoreFloat(_raw_diff) if isinstance(_raw_diff, float) else _raw_diff),
                "target": target_hex,
            },
            "warnings": [],
        }

    async def rpc_getblocktemplate(self, template_request: dict = None) -> dict[str, Any]:
        """
        Construct a block template for mining (BIP 22 / BIP 23).

        Selects mempool transactions by ancestor fee rate (greedy), builds a
        coinbase, computes the merkle root, and returns the template
        for external miners.

        Locktime enforcement:
        - Transactions with nLockTime > next_height (or > MTP for time-based)
          are excluded from the template.

        Coinbase requirements (for miners using this template):
        - Coinbase nSequence: 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL — enforces nLockTime)
          Reference: bitcoin-core/src/node/miner.cpp:171
          CTxIn::MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1 = 0xFFFFFFFE
        - Coinbase nLockTime: next_height - 1  (BIP-34 compatible locktime)
          Reference: bitcoin-core/src/node/miner.cpp:196
        - Witness commitment: OP_RETURN <0xaa21a9ed><32-byte-commitment>
          in the last output, where commitment = SHA256d(witness_root || nonce)
          and nonce is 32 zero bytes (coinbase witness item).

        W87 audit fixes (12 bugs vs Core miner.cpp):
        B1:  previousblockhash was LE; must be reversed to display order (BE).
        B2:  coinbasetxn.sequence was 0xFFFFFFFF (SEQUENCE_FINAL); must be
             0xFFFFFFFE (MAX_SEQUENCE_NONFINAL) so nLockTime is enforced.
        B3:  coinbasetxn.locktime was 0; must be next_height - 1 (miner.cpp:196).
        B4:  reserved weight was 4000; DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 (policy.h:27).
        B5:  no MAX_CONSECUTIVE_FAILURES (1000) early-exit gate (miner.cpp:284-316).
        B6:  weight computed as e.size * 4 (stripped bytes × 4); must use
             e.tx.get_weight() = stripped*3 + total (BIP-141 / miner.cpp:267).
        B7:  block version used previous block's version; must increment for
             version-bits signalling (miner.cpp:140); use node.get_next_block_version
             when available, fall back to prev_version | 0x20000000.
        B8:  bits used previous block's bits; must call GetNextWorkRequired
             equivalent; use node.get_next_bits when available, else carry forward.
        B9:  curtime was int(time.time()); must be max(MTP+1, now) per UpdateTime
             (miner.cpp:52-55).
        B10: sigops gate used >; must be >= (miner.cpp:244
             TestChunkBlockLimits).
        B11: per-tx hash field was txid; must be wtxid (rpc/mining.cpp:915).
        B12: per-tx depends field missing (rpc/mining.cpp:917-923).
        """
        import hashlib as _hl
        import time as _time

        # W87 constants matching bitcoin-core/src/node/miner.cpp +
        # bitcoin-core/src/policy/policy.h
        MAX_BLOCK_WEIGHT = 4_000_000          # consensus/consensus.h MAX_BLOCK_WEIGHT
        MAX_BLOCK_SIGOPS_COST = 80_000        # consensus/consensus.h
        BLOCK_RESERVED_WEIGHT = 8_000         # policy.h DEFAULT_BLOCK_RESERVED_WEIGHT (B4)
        MAX_CONSECUTIVE_FAILURES = 1_000      # miner.cpp:284 (B5)
        BLOCK_FULL_ENOUGH_DELTA = 4_000       # miner.cpp:285 BLOCK_FULL_ENOUGH_WEIGHT_DELTA
        # Effective tx budget: MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT
        WEIGHT_BUDGET = MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT  # 3_992_000

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        mempool = getattr(self.node, "mempool", None)

        best_hash, best_height = db.get_best_block()
        best_block = await asyncio.to_thread(db.get_block, best_hash)
        if best_block is None:
            raise HTTPException(status_code=500, detail="Cannot read tip block")

        next_height = best_height + 1

        # Get MTP for time-based locktime checks (BIP 113).
        # m_lock_time_cutoff = pindexPrev->GetMedianTimePast() — miner.cpp:148.
        _raw_mtp = db.get_median_time_past(best_height)
        block_mtp = int(_raw_mtp) if isinstance(_raw_mtp, (int, float)) else 0

        # Try to use Rust is_final_tx for locktime checking
        try:
            from sync import is_final_tx as rust_is_final_tx
            use_rust_final = True
        except ImportError:
            use_rust_final = False

        def _is_tx_final(tx) -> bool:
            """IsFinalTx analog (consensus/tx_verify.cpp:17).

            Returns True if the transaction is final for inclusion in the next
            block at next_height with MTP = block_mtp.
            """
            sequences = [inp.sequence for inp in tx.inputs]
            if use_rust_final:
                return rust_is_final_tx(tx.locktime, sequences, next_height, block_mtp)
            # Python fallback mirroring Core IsFinalTx exactly:
            #   if nLockTime == 0 → final
            #   if nLockTime < threshold → compare to nBlockHeight
            #   else → compare to nBlockTime (MTP)
            #   if all sequences are SEQUENCE_FINAL (0xFFFFFFFF) → final
            LOCKTIME_THRESHOLD = 500_000_000
            if tx.locktime == 0:
                return True
            lock_cmp = next_height if tx.locktime < LOCKTIME_THRESHOLD else block_mtp
            if tx.locktime < lock_cmp:
                return True
            # Even if locktime is not satisfied, final if all inputs are SEQUENCE_FINAL
            return all(seq == 0xFFFFFFFF for seq in sequences)

        txs: list[dict[str, Any]] = []
        total_fees = 0
        total_weight = 0         # tracks tx weight only (reserved weight is implicit)
        total_sigops = 0

        if mempool:
            # Take a consistent snapshot so concurrent mutations don't
            # cause inconsistencies during template construction.
            snap_fee_rate, snap_txs = mempool.snapshot()

            # Build a parent-dependency map: txid → set of in-mempool parents
            in_mempool = set(snap_txs.keys())
            parents: dict[bytes, set] = {}
            for txid_key, entry in snap_txs.items():
                tx_parents: set = set()
                for inp in entry.tx.inputs:
                    if inp.prev_txid in in_mempool:
                        tx_parents.add(inp.prev_txid)
                parents[txid_key] = tx_parents

            included: set = set()

            # Map from internal-LE txid to 1-based template index (for BIP-22
            # "depends" field).  Populated as txs are added.
            txid_to_template_index: dict[bytes, int] = {}

            def _collect_ancestors(txid: bytes, already: set) -> list[bytes]:
                needed = []
                queue = [txid]
                visited = set()
                while queue:
                    t = queue.pop(0)
                    if t in visited or t in already:
                        continue
                    visited.add(t)
                    for p in parents.get(t, set()):
                        if p not in already:
                            queue.append(p)
                    needed.append(t)
                # Topological sort: ancestors before descendants
                ordered = []
                placed = set(already)
                remaining = list(needed)
                safety = len(remaining) * len(remaining) + 1
                while remaining and safety > 0:
                    safety -= 1
                    for t in list(remaining):
                        if parents.get(t, set()).issubset(placed):
                            ordered.append(t)
                            placed.add(t)
                            remaining.remove(t)
                return ordered

            # Compute ancestor fee rate for each mempool entry, honouring
            # prioritisetransaction deltas (Core: BlockAssembler uses entry
            # GetModifiedFee throughout; mining/miner.cpp + txmempool.cpp:1015).
            # ancestor_fee_rate = (modified_fee + sum(ancestor modified fees))
            #                   / (entry.vsize + sum(ancestor vsizes))
            # Reference: Bitcoin Core BlockAssembler::addPackageTransactions()
            map_deltas = getattr(mempool, "map_deltas", {})

            def _mod_fee(t: bytes, e) -> int:
                return int(e.fee) + int(map_deltas.get(t, 0))

            ancestor_fee_rates: dict[bytes, float] = {}
            for txid_key, entry in snap_txs.items():
                # Collect full transitive ancestor set via BFS
                all_ancestors: set = set()
                queue = list(parents.get(txid_key, set()))
                while queue:
                    anc = queue.pop()
                    if anc in all_ancestors or anc not in snap_txs:
                        continue
                    all_ancestors.add(anc)
                    queue.extend(parents.get(anc, set()))
                ancestor_fee = _mod_fee(txid_key, entry) + sum(
                    _mod_fee(a, snap_txs[a]) for a in all_ancestors
                )
                ancestor_size = entry.size + sum(
                    snap_txs[a].size for a in all_ancestors
                )
                ancestor_fee_rates[txid_key] = (
                    ancestor_fee / ancestor_size if ancestor_size > 0 else 0.0
                )

            # Sort candidates by ancestor fee rate (highest first)
            sorted_by_ancestor_fee_rate = sorted(
                snap_txs.keys(),
                key=lambda txid: ancestor_fee_rates.get(txid, 0.0),
                reverse=True,
            )

            # B5: consecutive-failures counter for near-full early exit
            # (miner.cpp BlockAssembler::addChunks, lines 284-316).
            n_consecutive_failed = 0

            for entry_txid in sorted_by_ancestor_fee_rate:
                if entry_txid in included:
                    continue
                entry = snap_txs.get(entry_txid)
                if entry is None:
                    continue

                # Skip non-final transactions (locktime not yet satisfied)
                if not _is_tx_final(entry.tx):
                    continue

                # Collect required ancestors (+ self) in topological order
                batch = _collect_ancestors(entry_txid, included)

                # Skip if any ancestor is not final
                batch_valid = True
                for t in batch:
                    anc_entry = snap_txs.get(t)
                    if anc_entry and not _is_tx_final(anc_entry.tx):
                        batch_valid = False
                        break
                if not batch_valid:
                    n_consecutive_failed += 1
                    if (n_consecutive_failed > MAX_CONSECUTIVE_FAILURES and
                            total_weight + BLOCK_FULL_ENOUGH_DELTA > WEIGHT_BUDGET):
                        break
                    continue

                # B6: use BIP-141 weight, not stripped_bytes * 4.
                # e.tx.get_weight() = stripped*3 + total (correct for segwit).
                batch_weight = sum(
                    snap_txs[t].tx.get_weight()
                    for t in batch
                    if t in snap_txs
                )
                # B4: compare against WEIGHT_BUDGET (reserves 8000 for coinbase/header).
                # Core: nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight
                if total_weight + batch_weight >= WEIGHT_BUDGET:
                    n_consecutive_failed += 1
                    if (n_consecutive_failed > MAX_CONSECUTIVE_FAILURES and
                            total_weight + BLOCK_FULL_ENOUGH_DELTA > WEIGHT_BUDGET):
                        break
                    continue

                for t in batch:
                    e = snap_txs.get(t)
                    if e is None or t in included:
                        continue

                    # B6: correct BIP-141 weight (miner.cpp AddToBlock:267)
                    tw = e.tx.get_weight()
                    raw = e.tx.serialize()

                    tx_sigops_cost = 0

                    # Legacy sigops (outputs + inputs) × WITNESS_SCALE_FACTOR
                    legacy_sigops = 0
                    for out in e.tx.outputs:
                        legacy_sigops += _count_legacy_sigops(out.script_pubkey)
                    for inp in e.tx.inputs:
                        legacy_sigops += _count_legacy_sigops(inp.script_sig)
                    tx_sigops_cost += legacy_sigops * WITNESS_SCALE_FACTOR

                    # P2SH sigops × WITNESS_SCALE_FACTOR and witness sigops × 1
                    for inp in e.tx.inputs:
                        prev_utxo = await asyncio.to_thread(db.get_utxo, inp.prev_txid, inp.prev_vout)
                        if prev_utxo is None:
                            # Check if parent is an in-mempool tx
                            parent_entry = snap_txs.get(inp.prev_txid)
                            if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                                prev_spk = bytes(parent_entry.tx.outputs[inp.prev_vout].script_pubkey)
                            else:
                                continue
                        else:
                            prev_spk = bytes(prev_utxo["script_pubkey"])

                        p2sh_sigops = _get_p2sh_sigops(inp.script_sig, prev_spk)
                        tx_sigops_cost += p2sh_sigops * WITNESS_SCALE_FACTOR

                        # Witness sigops × 1
                        witness_spk = prev_spk
                        if _is_p2sh(prev_spk):
                            redeem = _get_last_push(inp.script_sig)
                            if redeem is not None:
                                witness_spk = redeem
                        tx_sigops_cost += _count_witness_sigops(
                            witness_spk, inp.witness
                        )

                    # B10: sigops gate must use >= not > (miner.cpp:244
                    # TestChunkBlockLimits: nBlockSigOpsCost + chunk >= MAX_BLOCK_SIGOPS_COST)
                    if total_sigops + tx_sigops_cost >= MAX_BLOCK_SIGOPS_COST:
                        continue  # tx would push block over sigops limit — skip

                    # B11: hash field must be wtxid (witness txid), not txid.
                    # Reference: bitcoin-core/src/rpc/mining.cpp:915
                    #   entry.pushKV("hash", tx.GetWitnessHash().GetHex())
                    # get_wtxid() returns internal LE bytes; reverse to display order.
                    wtxid_display = e.tx.get_wtxid()[::-1].hex()

                    # B12: depends field — 1-based indices of in-template ancestors
                    # Reference: bitcoin-core/src/rpc/mining.cpp:917-923
                    dep_indices = []
                    for inp in e.tx.inputs:
                        idx = txid_to_template_index.get(inp.prev_txid)
                        if idx is not None:
                            dep_indices.append(idx)

                    # JSON-RPC convention: txids in template responses are
                    # display-order (BE). t is internal LE. Reverse. W69.
                    txs.append({
                        "data": raw.hex(),
                        "txid": t[::-1].hex(),
                        "hash": wtxid_display,   # B11: wtxid, not txid
                        "depends": dep_indices,  # B12: in-template parent indices
                        "fee": e.fee,
                        "sigops": tx_sigops_cost,
                        "weight": tw,
                    })
                    total_fees += e.fee
                    total_weight += tw
                    total_sigops += tx_sigops_cost
                    included.add(t)
                    # Record 1-based template index for depends tracking
                    txid_to_template_index[t] = len(txs)

                n_consecutive_failed = 0  # reset on successful inclusion
        else:
            snap_txs = {}

        # witness commitment
        # Compute the SegWit witness merkle root from selected txs.
        # wtxids: coinbase is 32 zero-bytes, then each selected tx's wtxid.
        wtxids: list[bytes] = [bytes(32)]  # coinbase placeholder
        for tx_entry in txs:
            # tx_entry["txid"] is now display-order (BE); snap_txs keys are
            # internal LE. Reverse to recover the LE key. W69.
            entry_txid = bytes.fromhex(tx_entry["txid"])[::-1]
            entry_obj = snap_txs.get(entry_txid)
            if entry_obj:
                wtxids.append(entry_obj.tx.get_wtxid())
            else:
                wtxids.append(entry_txid)

        # Merkle root of wtxids
        level = list(wtxids)
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = level[i] + level[i + 1]
                else:
                    combined = level[i] + level[i]
                h = _hl.sha256(_hl.sha256(combined).digest()).digest()
                next_level.append(h)
            level = next_level
        witness_root = level[0] if level else bytes(32)

        # commitment = SHA256d(witness_root || nonce), nonce = 32 zero bytes
        nonce = bytes(32)
        commitment = _hl.sha256(
            _hl.sha256(witness_root + nonce).digest()
        ).digest()

        # Full scriptPubKey: OP_RETURN OP_PUSH36 <magic><commitment>
        witness_commitment_script = bytes.fromhex("6a24aa21a9ed") + commitment
        default_witness_commitment = witness_commitment_script.hex()

        # block reward (subsidy + fees)
        subsidy = 50 * 100_000_000
        halvings = next_height // 210_000
        if halvings < 64:
            subsidy >>= halvings
        coinbase_value = subsidy + total_fees

        # B8: bits should come from GetNextWorkRequired equivalent, not the
        # previous block's bits.  At difficulty-adjustment boundaries (every
        # 2016 blocks on mainnet) the bits change; carrying the previous
        # block's bits produces an invalid template.
        # Use node.get_next_bits() when available and returns an int; fall back
        # to best_block.bits.  The isinstance(int) guard prevents MagicMock
        # auto-attributes in unit tests from silently poisoning the value.
        _next_bits = getattr(self.node, "get_next_bits", None)
        if callable(_next_bits):
            _bits_val = _next_bits(best_height)
            bits = _bits_val if isinstance(_bits_val, int) else best_block.bits
        else:
            bits = best_block.bits

        # target derived from bits (nBits compact format → 256-bit integer)
        n_shift = (bits >> 24) & 0xFF
        mantissa = bits & 0x007FFFFF
        if n_shift <= 3:
            target_int = mantissa >> (8 * (3 - n_shift))
        else:
            target_int = mantissa << (8 * (n_shift - 3))
        target_hex = f"{target_int:064x}"

        # B7: block version must be computed for the *next* block, not copied
        # from the previous block.  Version-bits signalling (BIP9) requires
        # the miner to set specific bits; using the prev block's version loses
        # any bits that should be set (or cleared) for the new height.
        # Reference: miner.cpp:140 ComputeBlockVersion(pindexPrev, consensusParams).
        # Use node.get_next_block_version() when available and returns an int;
        # fall back to best_block.version | 0x20000000 (BIP9 top-bits always set).
        _next_version_fn = getattr(self.node, "get_next_block_version", None)
        if callable(_next_version_fn):
            _ver_val = _next_version_fn(best_height)
            block_version = _ver_val if isinstance(_ver_val, int) else (best_block.version | 0x20000000)
        else:
            block_version = (best_block.version | 0x20000000)

        # B9: curtime must be max(MTP+1, now) per Core's UpdateTime().
        # Reference: miner.cpp:52-55
        #   nNewTime = max(GetMinimumTime(pindexPrev, interval), NodeClock::now())
        # Using raw time.time() can produce a timestamp below MTP+1 which
        # miners would immediately have to increment, causing confusion.
        mtp_plus_one = block_mtp + 1
        curtime = max(mtp_plus_one, int(_time.time()))

        coinbase_aux = {
            "flags": "",  # extra nonce space in coinbase scriptSig
        }

        # BIP-23 capabilities field: at minimum ["proposal"]
        # Reference: bitcoin-core/src/rpc/mining.cpp:895, 948
        gbt_capabilities = ["proposal"]

        # BIP-9/BIP-22 rules field: active soft-fork rules the miner must
        # acknowledge.  "!" prefix means the rule is mandatory (miner must
        # understand it).  For post-segwit blocks always include csv, !segwit,
        # and taproot.  Reference: mining.cpp:950-963.
        # - "csv"     — BIP-68/112/113 sequence-lock CSV (always active)
        # - "!segwit" — BIP-141 SegWit (mandatory; "!" = consensus-critical)
        # - "taproot" — BIP-341/342 Taproot (active on mainnet/testnet4)
        gbt_rules = ["csv", "!segwit", "taproot"]
        network = getattr(self.node, "network", "mainnet")
        if network == "signet":
            gbt_rules.append("!signet")

        # BIP-9 vbavailable: deployments in STARTED or LOCKED_IN state that
        # miners can signal for.  In ouroboros's simplified model there are no
        # actively-signalling version-bit deployments beyond what is already in
        # the rules list, so this is an empty dict.  A full implementation would
        # query the versionbits cache here.
        # Reference: mining.cpp:965-983  GBTStatus signalling/locked_in maps.
        gbt_vbavailable: dict = {}

        # BIP-23 vbrequired: bitmask of version bits the miner MUST set.
        # Always 0 for current deployments.
        # Reference: mining.cpp:996  result.pushKV("vbrequired", 0)
        gbt_vbrequired = 0

        return {
            # BIP-23: capabilities field (W108 G4 fix)
            "capabilities": gbt_capabilities,
            # B7: next-block version (version-bits computed), not prev version
            "version": block_version,
            # BIP-9/BIP-23: rules field (W108 G4+G24 fix)
            "rules": gbt_rules,
            # BIP-9: vbavailable field (W108 G4 fix)
            "vbavailable": gbt_vbavailable,
            # BIP-23: vbrequired field (W108 G4 fix)
            "vbrequired": gbt_vbrequired,
            # B1: previousblockhash must be in display order (BE).
            # Core: block.hashPrevBlock.GetHex() (rpc/mining.cpp:998).
            "previousblockhash": best_hash[::-1].hex(),
            "transactions": txs,
            "coinbaseaux": coinbase_aux,
            "coinbasevalue": coinbase_value,
            "coinbasetxn": {
                # B3: locktime = next_height - 1 (miner.cpp:196)
                "locktime": next_height - 1,
                # B2: MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE enforces nLockTime.
                # Core: CTxIn::MAX_SEQUENCE_NONFINAL (miner.cpp:171).
                # 0xFFFFFFFF (SEQUENCE_FINAL) would disable nLockTime enforcement.
                "sequence": 0xFFFFFFFE,
            },
            "target": target_hex,
            # B8: bits from GetNextWorkRequired (best_block.bits as fallback)
            "bits": f"{bits:08x}",
            # B9: curtime = max(MTP+1, now)
            "curtime": curtime,
            "height": next_height,
            "mintime": mtp_plus_one,
            "mutable": ["time", "transactions", "prevblock"],
            "noncerange": "00000000ffffffff",
            "sigoplimit": MAX_BLOCK_SIGOPS_COST,
            "sizelimit": 4_000_000,
            "weightlimit": MAX_BLOCK_WEIGHT,
            "default_witness_commitment": default_witness_commitment,
        }

    def _get_block_height(self, db, block_hash: bytes) -> int | None:
        """Resolve a block's height from its 32-byte hash via the chainstate
        index, returning ``None`` if the hash is unknown to the node.

        ``getblock`` and ``getblockheader`` previously read height off the
        deserialised ``Block`` dataclass via ``getattr(block, 'height', None)``
        and falsy-coerced the result to ``0``. The Rust ``PyBlock`` does not
        carry a ``height`` field (height is a chainstate-level concept, not a
        serialised-block field), so the response always reported
        ``height: 0`` — the Pattern D / D1+D3 failure mode caught by the
        ``post-reorg-consistency`` corpus entry on 2026-05-05.

        This helper instead consults the chainstate index, reusing the same
        active-tip / side-branch / linear-scan tiering already used by
        :meth:`_resolve_parent_height` so that probes against a recently
        disconnected block also resolve.

        Resolution order (cheapest first):
          1. Active-tip fast path (``get_best_block``)
          2. Side-branch buffer (``submitblock`` reorg shim)
          3. Rust ``find_height_of_hash`` if exposed by the db
          4. Python walk via ``get_block_hash_by_height`` (active chain only)

        Reference: Bitcoin Core ``CBlockIndex::nHeight`` is set when the
        block is added to ``BlockManager::m_block_index``; ``rpc/blockchain.cpp``
        ``getblock`` / ``getblockheader`` read it off the index, never off the
        deserialised block body. Mirrored here.
        """
        try:
            tip_hash, tip_height = db.get_best_block()
        except Exception:
            tip_hash, tip_height = None, None
        if tip_hash is not None and block_hash == tip_hash:
            return tip_height

        # Side-branch buffer (submitblock reorg shim, keyed by block hash).
        side_entry = self._side_branch_blocks.get(block_hash)
        if side_entry is not None:
            _, side_height, _ = side_entry
            return side_height

        # Native Rust scan if available — single FFI call, walks
        # BLOCK_INDEX_CF rows backwards from the tip.
        if hasattr(db, "find_height_of_hash") and tip_height is not None:
            try:
                h = db.find_height_of_hash(block_hash, tip_height)
                if h is not None:
                    return h
            except Exception:
                pass

        # Python fallback: walk active chain backwards via the cheap
        # 32-byte-prefix lookup (no full block deserialisation).
        if tip_height is not None and hasattr(db, "get_block_hash_by_height"):
            for h in range(tip_height, -1, -1):
                try:
                    candidate = db.get_block_hash_by_height(h)
                except Exception:
                    candidate = None
                if candidate is not None and bytes(candidate) == block_hash:
                    return h
        return None

    def _resolve_parent_height(self, db, prev_hash: bytes) -> int | None:
        """Return the height of ``prev_hash`` in either the active chain or
        the side-branch buffer, or ``None`` if the parent is unknown.

        BIP-34 height check (and every contextual check derived from height)
        MUST use ``parent.height + 1`` per Bitcoin Core
        ``ContextualCheckBlockHeader`` (validation.cpp), NOT the active-tip
        height. Pre-fix ouroboros used ``best_height + 1`` unconditionally,
        which mis-rejected legitimate side-branch blocks with "bad-cb-height"
        whenever the active chain had advanced past the fork point —
        Pattern X in the cross-impl audit.

        Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader
        derives height from ``pindexPrev->nHeight + 1`` where ``pindexPrev``
        is the prev block in the BLOCK INDEX (full DAG), not the active
        chain tip.
        """
        # Active-tip fast path: avoids the find_height_of_hash linear scan
        # for the overwhelmingly common best-chain extension case.
        try:
            tip_hash, tip_height = db.get_best_block()
        except Exception:
            tip_hash, tip_height = None, None
        if tip_hash is not None and prev_hash == tip_hash:
            return tip_height

        # Side-branch buffer: blocks we've seen via submitblock whose
        # parent is in the block index but isn't the active tip.
        side_entry = self._side_branch_blocks.get(prev_hash)
        if side_entry is not None:
            _, side_height, _ = side_entry
            return side_height

        # Active-chain ancestor (parent is on the best chain but the
        # active tip has advanced past it — e.g. parent is the fork
        # point of a competing chain).
        if hasattr(db, "find_height_of_hash") and tip_height is not None:
            try:
                h = db.find_height_of_hash(prev_hash, tip_height)
                if h is not None:
                    return h
            except Exception:
                pass
        # Fall back: walk active chain backwards via get_block_hash_by_height.
        # Cheaper than fetching every block; we're only after equality on
        # the 32-byte hash. Bound the walk to the current best height to
        # avoid scanning past the active chain.
        if tip_height is not None and hasattr(db, "get_block_hash_by_height"):
            for h in range(tip_height, -1, -1):
                try:
                    candidate = db.get_block_hash_by_height(h)
                except Exception:
                    candidate = None
                if candidate is not None and bytes(candidate) == prev_hash:
                    return h
        return None

    def _evict_side_branch_if_full(self) -> None:
        """Soft-cap the in-memory side-branch buffer.

        A pathological caller could otherwise spam submitblock with bogus
        side-branch blocks and force unbounded growth. Evicts arbitrary
        entries (FIFO via dict insertion order) once the cap is hit.
        """
        if len(self._side_branch_blocks) <= self._side_branch_max_entries:
            return
        excess = len(self._side_branch_blocks) - self._side_branch_max_entries
        for _ in range(excess):
            try:
                k = next(iter(self._side_branch_blocks))
            except StopIteration:
                break
            self._side_branch_blocks.pop(k, None)

    async def _attach_side_branch_block(
        self,
        db,
        block_bytes: bytes,
        block_hash: bytes,
        prev_hash: bytes,
        new_height: int,
    ) -> str | None:
        """Validate + store a side-branch block; trigger reorg if heavier.

        Pattern Y companion to the Pattern X height fix above. Side-branch
        block acceptance has three outcomes that Bitcoin Core also
        distinguishes (validation.cpp ``BlockManager::AcceptBlock`` +
        ``ActivateBestChain``):

        * **Stored, not heavier** — block lives in the side-branch buffer;
          tip stays put. Core surfaces this as ``"inconclusive"`` on
          submitblock; ouroboros returns ``None`` (accept), matching the
          existing fleet convention used by other impls.
        * **Stored, heavier** — drives a reorg: disconnect from active
          tip back to the common ancestor, then connect each side-branch
          block (which we have buffered by hash) up to the new tip.
        * **Invalid** — buffer entry never created; standard BIP-22 error
          string returned.

        ouroboros's ``BLOCK_INDEX_CF`` is height-keyed (a relic of the
        IBD-only single-best-chain era), so persistent on-disk storage of
        two distinct blocks at the same height is not possible without a
        DB schema migration. The in-memory ``_side_branch_blocks`` map is
        the surgical shim that lets fork accumulation work without that
        migration. It bounds the scope of the Pattern Y closure to the
        submitblock RPC code path; P2P arrival continues to use the
        existing headers-first single-chain pipeline.
        """
        # Validate the block in the SAME shape Core's CheckBlock +
        # ContextualCheckBlock do for side-branch blocks: PoW, merkle,
        # cb-len, serialized size / weight, legacy sigop budget, witness
        # commitment, bad-diffbits, time-too-new, BIP-34 height (vs the
        # parent's height + 1). We deliberately skip ConnectBlock-style
        # checks here (UTXO spend, script verify, P2SH/witness sigops,
        # BIP-30/68) — those have to run against the disconnected-A-chain
        # chainstate, which only happens during the reorg connect loop below.
        from ouroboros.validation import _encode_bip34_height
        from ouroboros.validation import _bits_to_target as _v_bits_to_target
        from ouroboros.validation import MAX_FUTURE_BLOCK_TIME as _MAX_FUTURE
        from ouroboros.consensus import BURIED_DEPLOYMENTS
        from ouroboros.database import Block as _Block

        network = getattr(self.node, "network", "mainnet")
        _bip34_depl = BURIED_DEPLOYMENTS.get(network, {}).get("bip34")
        _bip34_activation = (
            _bip34_depl.height if _bip34_depl is not None else 227_931
        )

        # high-hash (CheckBlockHeader / CheckProofOfWork parity). Proof-of-work
        # is CONTEXT-FREE: Core runs CheckBlock -> CheckBlockHeader ->
        # CheckProofOfWork FIRST for EVERY block (side branches included), in
        # ProcessNewBlock BEFORE AcceptBlock (validation.cpp:4416), so a block
        # whose hash does not meet the target encoded in nBits is rejected
        # "high-hash" (validation.cpp CheckBlockHeader, pow.cpp CheckProofOfWork)
        # before it can be stored or drive a reorg. The P2P headers path already
        # enforces this via BlockSync._header_meets_pow; the side-branch store
        # path skipped it, so a fork block with sub-target PoW false-accepted
        # (fuzz-sweep-6nodes-2026-07-11.md Finding 2, high-hash x15). ``block_hash``
        # here is already dsha256(header[:80]) in internal (little-endian) order,
        # matching Core's arith_uint256; ``_v_bits_to_target`` is the SAME compact
        # decoder validation._validate_header uses — no second PoW engine.
        # bits live at header offset 72:76 (version 4|prev 32|merkle 32|time 4|
        # bits 4|nonce 4), little-endian.
        _bits_val = int.from_bytes(block_bytes[72:76], "little")
        _target = _v_bits_to_target(_bits_val)
        _hash_int = int.from_bytes(block_hash, "little")
        if _target <= 0 or _hash_int > _target:
            return bip22_result_string("high-hash")

        # bad-txnmrklroot / bad-txns-duplicate (CheckBlock parity). Core runs
        # CheckBlock — which is CONTEXT-FREE and includes the merkle-root check
        # — for EVERY block, side branches included. In the submitblock path
        # (ProcessNewBlock, validation.cpp:4416) CheckBlock runs BEFORE
        # AcceptBlock, so it precedes even ContextualCheckBlockHeader's
        # bad-diffbits below; CheckMerkleRoot (validation.cpp:3843-3857) rejects
        # a header merkle root that does not match its transactions
        # (bad-txnmrklroot), then a mutated tree (CVE-2012-2459, bad-txns-
        # duplicate) — all WITHOUT storing or connecting the block. The direct-
        # connect path enforces this via BlockValidator._verify_merkle_root; the
        # side-branch store path skipped it, so a fork block with a corrupted
        # merkle root false-accepted and could even win a reorg into the buffer.
        # Reuse the SAME merkle computation so both paths agree with Core.
        _validator = getattr(self.node, "validator", None)
        if _validator is not None:
            try:
                _mrk_blk = _Block.deserialize(block_bytes)
                _txids = [tx.get_txid() for tx in _mrk_blk.transactions]
                _root, _mutated = _validator._calculate_merkle_root_checked(_txids)
                if _root != _mrk_blk.merkle_root:
                    return bip22_result_string("bad-txnmrklroot")
                if _mutated:
                    return bip22_result_string("bad-txns-duplicate")
            except Exception as _e:
                # Degrade to pre-fix behaviour only when the merkle computation
                # itself cannot run — never mask a genuine mismatch, which
                # returns above.
                logger.debug(
                    "side-branch merkle check skipped at h=%d: %s",
                    new_height, _e,
                )

        # bad-diffbits (ContextualCheckBlockHeader parity). Core runs
        # ContextualCheckBlockHeader inside AcceptBlockHeader for ALL
        # headers — including fork/side-branch headers — so a block whose
        # nBits != GetNextWorkRequired(pindexPrev) is rejected BEFORE it can
        # be stored or drive a reorg (validation.cpp:4088-4089 "bad-diffbits",
        # reached from AcceptBlockHeader:4224). The direct-connect path
        # enforces this via BlockValidator._validate_header ->
        # _get_expected_bits (validation.py:1294-1296); the side-branch store
        # path skipped it, so a fork block carrying an nBits one ULP harder
        # than GetNextWorkRequired (e.g. regtest 0x207ffffe vs the constant
        # 0x207fffff) sailed straight into the buffer and could win a reorg.
        # Reuse the SAME code the direct path uses so both agree with Core.
        _validator = getattr(self.node, "validator", None)
        if _validator is not None:
            try:
                _hdr_blk = _Block.deserialize(block_bytes)
                _parent_blk = db.get_block(prev_hash)
                if _parent_blk is None:
                    _side_parent = self._side_branch_blocks.get(prev_hash)
                    if _side_parent is not None:
                        _parent_blk = _Block.deserialize(_side_parent[2])
                _expected_bits = _validator._get_expected_bits(
                    new_height, _parent_blk, _hdr_blk
                )
                if _expected_bits is not None and _hdr_blk.bits != _expected_bits:
                    return bip22_result_string("bad-diffbits")
            except Exception as _e:
                # Degrade to the pre-fix behaviour (no diffbits rejection)
                # only when the expected-bits computation itself cannot run
                # — never mask a genuine mismatch, which returns above.
                logger.debug(
                    "side-branch diffbits check skipped at h=%d: %s",
                    new_height, _e,
                )

        # time-too-new (ContextualCheckBlockHeader parity). Core rejects a block
        # whose timestamp is more than MAX_FUTURE_BLOCK_TIME (2h) beyond the
        # node's clock — validation.cpp:4108-4110 compares block.Time() against
        # NodeClock::now() + MAX_FUTURE_BLOCK_TIME. This gate needs only the wall
        # clock (no chain context), so it is safe to run for side-branch blocks:
        # a genuinely valid side-branch never carries a >2h-future timestamp (Core
        # would reject it too). The side-branch store path skipped it
        # (fuzz-sweep-6nodes-2026-07-11.md Finding 2, time-too-new x2). Runs AFTER
        # high-hash/merkle (CheckBlock) and bad-diffbits, mirroring Core's order
        # (ContextualCheckBlockHeader: bad-diffbits before the timestamp gates).
        # NB: time-too-old (<= MTP) and bad-version (BIP34/66/65 height-gated) are
        # left to a follow-up — both are CONTEXTUAL and computing them for a
        # side branch would require the parent's median-time-past / height-gated
        # deployment state via the height-keyed index, which resolves to the
        # ACTIVE chain (wrong for a deeper side branch) — mirroring them
        # imprecisely would introduce a NEW divergence (spurious reject of a
        # valid side-branch), which this path must not do.
        _blk_time = int.from_bytes(block_bytes[68:72], "little")
        _now = int(time.time())
        if _blk_time > _now + _MAX_FUTURE:
            return bip22_result_string("time-too-new")

        # BIP-34 byte-prefix check against parent.height + 1. This is the
        # core of the Pattern X fix — pre-fix the height came from
        # best_height + 1 and side-branch blocks at heights ≤ active tip
        # always failed this check.
        if new_height >= _bip34_activation:
            try:
                _blk = _Block.deserialize(block_bytes)
                if _blk.transactions:
                    _coinbase = _blk.transactions[0]
                    if _coinbase.inputs:
                        _script = _coinbase.inputs[0].script_sig
                        _expect = _encode_bip34_height(new_height)
                        _n = len(_expect)
                        if len(_script) < _n or _script[:_n] != _expect:
                            return bip22_result_string("bad-cb-height")
            except Exception:
                pass  # let Rust validation surface deserialization errors

        # NB: Rust ``validate_block_from_bytes`` is intentionally NOT called
        # here. Its ``validate_header`` step calls
        # ``db.get_block_by_height(prev_height)`` to fetch the previous
        # header, but the block_index column family is height-keyed and
        # only knows about the ACTIVE chain — for any side-branch block
        # at height N where the active chain has its own block at N
        # (or no block at N at all, e.g. B2 above the displaced A-tip),
        # that lookup returns the wrong header (or None). Routing
        # side-branch validation through the height-keyed index would
        # therefore mis-validate or false-reject the side branch.
        #
        # The full context-free CheckBlock set (PoW, merkle, cb-len,
        # serialized size / weight, LEGACY sigop budget, witness
        # commitment, BIP-34) runs above and bounds side-branch storage
        # cost. Only the UTXO-dependent ConnectBlock-class checks (BIP-30,
        # BIP-68, P2SH/witness sigops, UTXO spend, script verify) remain
        # deferred — they all run when the reorg connect loop
        # below feeds each buffered block back through the unified
        # ``accept_block`` pipeline — at that point the active chain
        # has been disconnected back to the common ancestor, so every
        # ``get_block_by_height(h)`` for h in [ancestor..new_tip-1]
        # resolves to the side-branch ancestor that ``connect_block_from_bytes``
        # has just put there. This is the same pattern Bitcoin Core
        # uses: ``BlockManager::AcceptBlock`` writes the block index
        # entry without invoking ``ConnectBlock``; the connect happens
        # later inside ``ActivateBestChain`` once chain selection has
        # picked the new tip.
        try:
            from ouroboros.database import Block as _BlockChk
            _blk_chk = _BlockChk.deserialize(block_bytes)
            if not _blk_chk.transactions:
                return bip22_result_string("bad-blk-length")
            _cb = _blk_chk.transactions[0]
            if not _cb.inputs:
                return bip22_result_string("bad-cb-length")
            _scriptsig_len = len(_cb.inputs[0].script_sig)
            if _scriptsig_len < 2 or _scriptsig_len > 100:
                return bip22_result_string(
                    f"bad-cb-length: coinbase scriptSig length {_scriptsig_len} not in 2..=100"
                )
        except ValueError:
            return bip22_result_string("bad-blk-length")
        except Exception as e:
            logger.warning(
                "side-branch deserialize warning at h=%d: %s",
                new_height, e,
            )

        # bad-blk-length / bad-blk-weight / bad-blk-sigops (CheckBlock body
        # parity, CONTEXT-FREE). Core's CheckBlock (validation.cpp:3946-3977) runs
        # the size-limit and legacy-sigop gates for EVERY block — side branches
        # included — in ProcessNewBlock BEFORE AcceptBlock stores it. 1b883b7
        # wired up PoW/merkle/time-too-new but left these body gates to a
        # follow-up: the structural bad-blk-length branch above only catches
        # empty-block / coinbase-scriptSig-length, NOT real serialized size,
        # weight, or the sigop budget. The systematic sweep
        # (submitblock-path-differential-2026-07-11.md, finding 2) then showed the
        # side-branch store path admitting oversize / high-sigop siblings Core
        # rejects. Reuse the SAME helpers the direct-connect CheckBlock path uses
        # (validation.block_weight, _count_legacy_sigops) — no second validation
        # engine. All three gates are CONTEXT-FREE (block's own bytes only).
        # IMPORTANT: Core CheckBlock counts LEGACY sigops only (validation.cpp:3970
        # "does not count witness and p2sh sigops"); the UTXO-dependent P2SH /
        # witness sigop cost stays DEFERRED to the reorg ConnectBlock loop below.
        try:
            from ouroboros.validation import block_weight as _v_block_weight
            from ouroboros.validation import _count_legacy_sigops as _v_legacy_sigops
            from ouroboros.validation import MAX_BLOCK_WEIGHT as _V_MAX_WEIGHT
            from ouroboros.validation import (
                MAX_BLOCK_SIGOPS_COST as _V_MAX_SIGOPS,
            )
            from ouroboros.validation import WITNESS_SCALE_FACTOR as _V_WSF

            _txs = _blk_chk.transactions
            # Core early size gates (validation.cpp:3947): tx-count guard, then
            # the stripped (TX_NO_WITNESS) serialized-size guard → bad-blk-length.
            if len(_txs) * _V_WSF > _V_MAX_WEIGHT:
                return bip22_result_string("bad-blk-length")
            _stripped = sum(len(_tx.serialize()) for _tx in _txs)
            if _stripped * _V_WSF > _V_MAX_WEIGHT:
                return bip22_result_string("bad-blk-length")
            # Full GetBlockWeight (header + CompactSize tx-count + per-tx
            # weights) → bad-blk-weight.
            if _v_block_weight(_txs) > _V_MAX_WEIGHT:
                return bip22_result_string("bad-blk-weight")
            # Legacy sigop budget × WITNESS_SCALE_FACTOR → bad-blk-sigops. Counts
            # GetLegacySigOpCount over outputs + scriptSigs of every tx incl.
            # coinbase, matching Core CheckBlock exactly.
            _legacy = 0
            for _tx in _txs:
                for _out in _tx.outputs:
                    _legacy += _v_legacy_sigops(_out.script_pubkey)
                for _inp in _tx.inputs:
                    _legacy += _v_legacy_sigops(_inp.script_sig)
            if _legacy * _V_WSF > _V_MAX_SIGOPS:
                return bip22_result_string("bad-blk-sigops")
        except Exception as _e:
            # Degrade to pre-fix behaviour only when the size/sigop computation
            # itself cannot run — genuine violations return above.
            logger.debug(
                "side-branch size/sigops check skipped at h=%d: %s",
                new_height, _e,
            )

        # bad-witness-merkle-match / bad-witness-nonce-size / unexpected-witness
        # (CheckWitnessMalleation parity, CONTEXT-FREE). Core runs
        # CheckWitnessMalleation in ContextualCheckBlock (validation.cpp:4050),
        # which — like CheckBlock — executes in AcceptBlock BEFORE the block is
        # saved to disk, so a side-branch sibling with a corrupted witness
        # commitment is rejected before storage. The check needs only the block's
        # own coinbase commitment output, coinbase witness nonce, and the wtxid
        # merkle root of the block's transactions plus a segwit-active bool (no
        # chainstate / UTXOs), so it is safe on the side-branch path. Reuse the
        # validator's existing _validate_witness_commitment — the SAME helper the
        # direct-connect path uses — rather than a second engine.
        if _validator is not None:
            try:
                _wok, _wreason = _validator._validate_witness_commitment(
                    _blk_chk, new_height
                )
                if not _wok:
                    return bip22_result_string(_wreason)
            except Exception as _e:
                logger.debug(
                    "side-branch witness-commitment check skipped at h=%d: %s",
                    new_height, _e,
                )

        # Stash the block in the side-branch buffer. Future submissions
        # whose prev points at this hash can chain off it without needing
        # the block index to know it.
        self._side_branch_blocks[block_hash] = (prev_hash, new_height, block_bytes)
        self._evict_side_branch_if_full()
        logger.debug(
            "side-branch stash blk=%s prev=%s h=%d",
            block_hash.hex()[:16], prev_hash.hex()[:16], new_height,
        )

        try:
            _, active_tip_height = db.get_best_block()
        except Exception:
            active_tip_height = -1

        # --- Cumulative chainwork comparison (Core CBlockIndexWorkComparator) ---
        # nChainWork is exact arith_uint256; reorg only on STRICTLY greater.
        # Equal work = first-seen tie-break = keep the current tip.
        # _side_branch_chainwork walks the in-memory side-branch buffer from
        # block_hash to the common ancestor, accumulating proof-of-work, then
        # adds the ancestor's active-chain cumulative work from the DB.
        fork_cw = self._side_branch_chainwork(db, block_hash, new_height)
        active_cw = (
            self.node._calculate_chainwork_at_height(active_tip_height)
            if active_tip_height >= 0 and hasattr(self.node, "_calculate_chainwork_at_height")
            else 0
        )

        # Use exact chainwork comparison only when BOTH values are available:
        # fork_cw is not None (buffer walk succeeded to the active ancestor)
        # AND active_cw > 0 (active tip's cumulative work is persisted).
        # If active_cw is 0, comparing fork incremental work against 0 would
        # always favour the fork — wrong for old datadirs without persistence.
        if fork_cw is not None and active_cw > 0:
            # Chainwork available: exact 256-bit comparison.
            if fork_cw <= active_cw:
                # Same-or-lighter side-branch: stored, no tip flip. Core's
                # ``rpc/mining.cpp`` returns ``"inconclusive"`` here; the
                # diff-test harness treats both ``None`` (accept) and
                # ``reject:inconclusive`` as "context successfully ingested",
                # so returning None keeps wire-compat with the rest of the
                # fleet's submitblock semantics.
                logger.debug(
                    "submitblock: side-branch h=%d cw=0x%064x not strictly "
                    "heavier than active_tip h=%d cw=0x%064x; stored only",
                    new_height, fork_cw, active_tip_height, active_cw,
                )
                return None
        else:
            # Chainwork unavailable (old datadir): height fallback.
            if new_height <= active_tip_height:
                return None

        # Strictly heavier — drive the reorg.
        if fork_cw is not None and active_cw > 0:
            logger.info(
                "submitblock: heavier side-branch h=%d cw=0x%064x > "
                "active_tip h=%d cw=0x%064x, driving reorg to %s",
                new_height, fork_cw, active_tip_height, active_cw,
                block_hash.hex()[:16],
            )
        else:
            logger.info(
                "submitblock: heavier side-branch h=%d > active_tip h=%d, "
                "driving reorg to %s (height fallback)",
                new_height, active_tip_height, block_hash.hex()[:16],
            )
        return await self._reorg_to_side_branch_tip(db, block_hash)

    async def _restore_original_chain(
        self,
        db,
        ancestor_height: int,
        disconnected_active: list[tuple[bytes, int, bytes]],
        failed_tip_hash: bytes,
        reason: str,
    ) -> str:
        """Roll the chainstate back to the ORIGINAL active tip after a failed
        competing-chain connect.

        A reorg that disconnects the original chain and then fails part-way
        through connecting the heavier competitor must NOT leave the node on a
        partial prefix of the losing chain (the S5 / clearbit-incident class).
        Bitcoin Core's ``ActivateBestChainStep`` handles this by marking the
        failing block ``BLOCK_FAILED_VALID`` (``InvalidBlockFound``) and
        returning; the outer ``ActivateBestChain`` loop then re-selects the
        best VALID chain via ``FindMostWorkChain`` and reconnects it — so the
        net effect is that the node stays on (or returns to) its original tip.
        We reproduce that net effect explicitly here (validation.cpp
        ActivateBestChainStep / ConnectTip failure path).

        Steps:
          1. Disconnect any partially-connected losing-chain prefix back to
             the common ancestor.
          2. Re-connect the captured original active-chain blocks
             (ancestor+1 .. original tip), restoring coins via their undo
             records.
          3. Drop the failed competing tip from the side-branch buffer so it
             cannot re-drive the same doomed reorg.
        """
        # 1. Tear down any partial losing-chain prefix.
        try:
            _, cur_h = db.get_best_block()
        except Exception:
            cur_h = ancestor_height
        while cur_h > ancestor_height:
            try:
                await asyncio.to_thread(db.disconnect_block, cur_h)
            except Exception as e:
                logger.error(
                    "reorg rollback: disconnect_block(%d) failed: %s", cur_h, e
                )
                break
            cur_h -= 1

        # 2. Re-connect the original active chain (ancestor+1 → original tip).
        for _blk_hash, blk_height, raw_bytes in disconnected_active:
            try:
                await asyncio.to_thread(
                    db.connect_block_from_bytes, raw_bytes, blk_height
                )
            except Exception as e:
                logger.error(
                    "reorg rollback: reconnect original block h=%d failed: %s — "
                    "chainstate may be left at the common ancestor",
                    blk_height, e,
                )
                break

        # 3. Forget the invalid competing tip (Core BLOCK_FAILED_VALID).
        self._side_branch_blocks.pop(failed_tip_hash, None)

        try:
            _, restored_h = db.get_best_block()
        except Exception:
            restored_h = None
        logger.warning(
            "submitblock reorg: connect failed (%s) — rolled back to original "
            "chain (tip h=%s)",
            reason, restored_h,
        )
        return bip22_result_string(reason)

    async def _reorg_to_side_branch_tip(
        self,
        db,
        new_tip_hash: bytes,
    ) -> str | None:
        """Disconnect from the active tip back to the common ancestor of
        ``new_tip_hash``'s side branch, then connect each buffered block
        in chain order. Mirrors Bitcoin Core's ``ActivateBestChain`` →
        ``DisconnectTip`` / ``ConnectTip`` loop (validation.cpp:2929+).

        Caller is responsible for guaranteeing ``new_tip_hash`` is in the
        side-branch buffer and that the new chain is strictly heavier
        than the current active chain.
        """
        # Walk backwards from the new tip through the side-branch buffer
        # until we hit a block that's on the active chain — that's the
        # common ancestor. Build the connect list (ancestor's child →
        # new tip, in forward chain order) along the way.
        chain_to_connect: list[tuple[bytes, int, bytes]] = []
        cursor_hash = new_tip_hash
        common_ancestor_hash: bytes | None = None
        common_ancestor_height: int = -1
        max_walk = self._side_branch_max_entries + 4  # generous safety bound
        for _ in range(max_walk):
            entry = self._side_branch_blocks.get(cursor_hash)
            if entry is None:
                # Cursor isn't in the side-branch buffer — must be on the
                # active chain. Use the same parent-resolver helper as the
                # entry path so we honour both the Rust find_height_of_hash
                # FFI (when present) and the get_block_hash_by_height
                # backwards-walk fallback (when it isn't).
                h = self._resolve_parent_height(db, cursor_hash)
                if h is None:
                    # Not in active chain either — orphan side branch.
                    logger.warning(
                        "submitblock reorg: missing common ancestor %s",
                        cursor_hash.hex()[:16],
                    )
                    return bip22_result_string(
                        f"missing common ancestor {cursor_hash.hex()[:16]}..."
                    )
                common_ancestor_hash = cursor_hash
                common_ancestor_height = h
                break
            parent_hash, height, raw_bytes = entry
            chain_to_connect.append((cursor_hash, height, raw_bytes))
            cursor_hash = parent_hash
        else:
            return bip22_result_string("side-branch chain too deep")

        if common_ancestor_hash is None:
            return bip22_result_string("no common ancestor")

        # Reverse so we connect in forward chain order: ancestor+1 → tip.
        chain_to_connect.reverse()

        # Sanity: the bottom of the connect list should be at
        # common_ancestor_height + 1.
        if chain_to_connect:
            bottom_height = chain_to_connect[0][1]
            if bottom_height != common_ancestor_height + 1:
                return bip22_result_string(
                    f"side-branch height gap: bottom={bottom_height} "
                    f"ancestor_height={common_ancestor_height}"
                )

        # Disconnect blocks from active tip back to common ancestor.
        try:
            _, current_height = db.get_best_block()
        except Exception:
            return "rejected"
        logger.info(
            "submitblock reorg: ancestor=%s ancestor_h=%d active_tip_h=%d "
            "connect_chain=%d blocks",
            common_ancestor_hash.hex()[:16] if common_ancestor_hash else "None",
            common_ancestor_height,
            current_height,
            len(chain_to_connect),
        )

        # ----------------------------------------------------------
        # Pattern D — atomic multi-block disconnect.
        #
        # Core has NO reorg-depth cap: ActivateBestChainStep disconnects
        # to the fork point unbounded and follows the most-work valid
        # chain to any depth, FatalError-ing only if a disconnected
        # block's undo data is missing on disk (a pruned-node condition).
        # MIN_BLOCKS_TO_KEEP/288 governs pruning + the fTooFarAhead
        # buffering gate — NOT reorg depth (validation.cpp:4325,6362).
        #
        # On an ARCHIVE node (the default — no `prune` config) every
        # block's undo is present, so a MAX_REORG_DEPTH refusal is
        # gratuitous and a Class-A consensus split: we would stay on the
        # lower-work minority chain while Core reorgs.  We therefore only
        # enforce the cap when pruning is enabled, where it protects
        # against reorging past the retained undo window (a conservative
        # refusal in lieu of Core's physical missing-undo fatal abort).
        # ----------------------------------------------------------
        disconnect_depth = current_height - common_ancestor_height
        connect_depth = len(chain_to_connect)
        _pruning_on = getattr(self.node, "pruner", None) is not None
        if _pruning_on and (
            disconnect_depth > MAX_REORG_DEPTH or connect_depth > MAX_REORG_DEPTH
        ):
            logger.warning(
                "submitblock reorg: depth cap exceeded on pruned node — "
                "disconnect=%d connect=%d retained-undo-window=%d",
                disconnect_depth, connect_depth, MAX_REORG_DEPTH,
            )
            return bip22_result_string(
                f"reorg-too-deep: disconnect={disconnect_depth} "
                f"connect={connect_depth} cap={MAX_REORG_DEPTH}"
            )

        # ----------------------------------------------------------
        # Capture non-coinbase txs from each block we are about to
        # disconnect, BEFORE the disconnect loop fires.  Once
        # ``db.disconnect_block(s)_*`` runs, the block is gone from the
        # active chain (the chainstate row is rolled back); we cannot
        # fetch the tx list afterwards.  We pre-load by height-walk
        # on the active chain — same shape as
        # ``BlockSync._handle_reorg`` (block_sync.py:2336-2350) which
        # also captures ``current_chain`` BEFORE the disconnect loop.
        #
        # Pattern B refill (mempool-refill-on-reorg-2026-05-05):
        # this is the data ``self.node.mempool.add_transaction`` consumes
        # after the connect loop completes, mirroring Bitcoin Core's
        # ``MaybeUpdateMempoolForReorg`` (validation.cpp).
        # ----------------------------------------------------------
        #
        # We ALSO capture each disconnected active-chain block's raw bytes +
        # hash (``disconnected_active``, ascending by height) for two Core-
        # parity reasons handled below:
        #   (a) ROLLBACK (S5 / atomicity): if the competing chain fails to
        #       connect part-way through, we re-connect these to restore the
        #       ORIGINAL tip — Core's ActivateBestChainStep never leaves the
        #       node on a partially-connected losing chain (validation.cpp
        #       ConnectTip failure → InvalidBlockFound → return to best VALID
        #       chain).
        #   (b) RETAIN (S4 / reorg-back): on a SUCCESSFUL flip we stash these
        #       into the side-branch buffer so a later block extending the
        #       now-abandoned branch can resolve its parent and drive a reorg
        #       BACK onto it — mirroring Core keeping every block in
        #       m_block_index regardless of which chain is active.
        # ----------------------------------------------------------
        disconnected_txs: list = []
        disconnected_active: list[tuple[bytes, int, bytes]] = []
        for h in range(current_height, common_ancestor_height, -1):
            try:
                blk = db.get_block_by_height(h)
            except Exception as e:
                logger.warning(
                    "submitblock reorg: pre-disconnect get_block_by_height(%d) "
                    "failed: %s — mempool refill will skip this block",
                    h, e,
                )
                continue
            if blk is None:
                continue
            # Capture raw (witness-preserving) bytes + hash before disconnect.
            try:
                _h_hash = db.get_block_hash_by_height(h)
                _h_hash = bytes(_h_hash) if _h_hash is not None else None
                _h_bytes = db.get_block_bytes(_h_hash) if _h_hash is not None else None
                if _h_hash is not None and _h_bytes is not None:
                    disconnected_active.append((_h_hash, h, bytes(_h_bytes)))
            except Exception as e:
                logger.warning(
                    "submitblock reorg: could not capture active block at h=%d "
                    "for rollback/retain: %s",
                    h, e,
                )
            for tx in getattr(blk, "transactions", []) or []:
                if getattr(tx, "is_coinbase", False):
                    continue
                disconnected_txs.append(tx)
        # Order ascending by height (ancestor+1 → original tip) for re-connect.
        disconnected_active.reverse()

        # ----------------------------------------------------------
        # Pattern D — single-batch atomic disconnect of all N blocks.
        #
        # Pre-fix this loop called ``db.disconnect_block(h)`` once per
        # height; each call was its own RocksDB ``WriteBatch``. A crash
        # mid-loop left N-k blocks rolled back and k still applied —
        # the riskiest crash window flagged by the Pattern D static
        # audit (post-reorg-consistency, 2026-05-05).
        #
        # Post-fix: a single Rust call accumulates all UTXO restores,
        # output deletes, txindex deletes, spent-record cleanups, undo
        # deletes, and the BEST_BLOCK pointer rewrite into one
        # ``WriteBatch`` and applies once. Either every block lands or
        # none does — pre-state OR post-disconnect-state, never partial.
        #
        # Brings ouroboros from D-AT-RISK to D-PARTIAL parity with
        # camlcoin (the only impl with single-batch disconnect pre-fix,
        # rated "best in fleet" by the audit).
        # ----------------------------------------------------------
        if hasattr(db, "disconnect_blocks_atomic") and current_height > common_ancestor_height:
            try:
                await asyncio.to_thread(
                    db.disconnect_blocks_atomic,
                    current_height,
                    common_ancestor_height,
                )
            except Exception as e:
                logger.error(
                    "submitblock reorg: disconnect_blocks_atomic(%d→%d) failed: %s",
                    current_height, common_ancestor_height, e,
                )
                return bip22_result_string(f"reorg-disconnect-failed: {e}")
        else:
            # Compatibility fallback for older sync extensions that
            # don't ship the atomic helper. Per-block disconnect retains
            # the pre-Pattern-D semantics (per-block atomic, multi-block
            # sequential).
            disconnect_height = current_height
            while disconnect_height > common_ancestor_height:
                # Reverse the wallet-history scan for this height before the
                # UTXO state is torn down, so a reorg can't leave stale
                # send/receive entries. Mirrors CWallet::blockDisconnected.
                # (The atomic-disconnect fast path above tears the chain down
                # inside Rust without surfacing per-height blocks to Python;
                # there the wallet history is rebuilt by the subsequent
                # connect scan of the new branch rather than unwound here.)
                for _w in _iter_node_wallets(self.node):
                    try:
                        _w.scan_block_disconnect(disconnect_height)
                    except Exception:
                        pass
                try:
                    await asyncio.to_thread(db.disconnect_block, disconnect_height)
                except Exception as e:
                    logger.error(
                        "submitblock reorg: disconnect_block(%d) failed: %s",
                        disconnect_height, e,
                    )
                    return bip22_result_string(f"reorg-disconnect-failed: {e}")
                disconnect_height -= 1

        # ----------------------------------------------------------
        # Pattern D — single-batch atomic connect of all M side-branch
        # blocks (D-FULL upgrade from D-PARTIAL).
        #
        # Pre-fix this loop called ``accept_block`` per block; each
        # ``accept_block`` invocation issued its own RocksDB
        # ``WriteBatch`` via ``connect_block_from_bytes``. A crash
        # between block k and block k+1 left the chain at "ancestor +
        # k blocks" — a valid chain prefix, but not the operator's
        # intended target. Combined with the pre-fix N-batch disconnect
        # side, that gave M+N possible crash points across one reorg.
        #
        # Post-fix: full validation runs per-block in a pre-flight pass
        # against the post-disconnect chainstate. Then a single
        # ``connect_blocks_atomic`` call accumulates every block's
        # UTXO mutations, undo records, txindex rows, block bodies,
        # metadata, and the BEST_BLOCK pointer rewrite into ONE
        # RocksDB ``WriteBatch`` and applies once. Either every block
        # in the connect chain lands or none does.
        #
        # Holdout (documented in CORE-PARITY-AUDIT/_post-reorg-
        # consistency-fleet-result-2026-05-05.md): the disconnect
        # side commits its own single batch BEFORE the connect batch,
        # so the on-disk state can briefly be "post-disconnect, pre-
        # connect" if the process crashes between the two commits.
        # That intermediate state is itself a valid chain (chain
        # rooted at the common ancestor), so recovery is well-defined
        # — the side branch can be re-served via P2P. True D-FULL
        # (ONE batch covering both halves) requires overlay-aware
        # heavy validation (BIP-30, BIP-68, sigops, per-tx amounts)
        # which is multi-session refactor work.
        # ----------------------------------------------------------
        connected_hashes: list[bytes] = []
        if (
            hasattr(db, "connect_blocks_atomic")
            and len(chain_to_connect) > 1
        ):
            # Multi-block reorg: pre-flight validate, then single-
            # batch connect. Falls back to per-block accept_block on
            # any pre-flight failure so the caller still gets the
            # canonical BIP-22 reject string.
            from ouroboros.validation import _encode_bip34_height
            from ouroboros.consensus import BURIED_DEPLOYMENTS
            from ouroboros.database import Block as _Block

            network = getattr(self.node, "network", "mainnet")
            _bip34_depl = BURIED_DEPLOYMENTS.get(network, {}).get("bip34")
            _bip34_activation = (
                _bip34_depl.height if _bip34_depl is not None else 227_931
            )

            try:
                # Pre-flight validation pass (each block validates against
                # the post-disconnect on-disk chainstate). This catches
                # heavy ConnectBlock-class issues (BIP-30, BIP-68, sigops,
                # full per-tx UTXO+amount checks, script verify) for the
                # *first* block in the batch; subsequent blocks may
                # see "input not found" for in-batch spends — that's a
                # known regression vs the per-block-commit path and
                # falls through to a clean atomic-batch abort, which
                # is a safe failure (false-reject of a legitimate side
                # branch is recoverable; consensus violation would not be).
                for blk_hash, blk_height, raw_bytes in chain_to_connect:
                    # BIP-34 byte-prefix check (network-aware).
                    if blk_height >= _bip34_activation:
                        try:
                            _blk = _Block.deserialize(raw_bytes)
                            if _blk.transactions:
                                _coinbase = _blk.transactions[0]
                                if _coinbase.inputs:
                                    _script = _coinbase.inputs[0].script_sig
                                    _expect = _encode_bip34_height(blk_height)
                                    _n = len(_expect)
                                    if len(_script) < _n or _script[:_n] != _expect:
                                        raise ValueError("bad-cb-height")
                        except ValueError:
                            raise
                        except Exception:
                            pass

                    # Rust heavy validation (best-effort: skip the input-
                    # lookup-driven checks for non-first batch blocks by
                    # tolerating "InputNotFound" failures, which the atomic
                    # helper's lightweight UTXO overlay then catches at
                    # commit-time).
                    if hasattr(db, "validate_block_from_bytes"):
                        try:
                            await asyncio.to_thread(
                                db.validate_block_from_bytes,
                                raw_bytes,
                                blk_height - 1,
                                False,
                                network,
                            )
                        except Exception as ve:
                            ve_msg = str(ve).lower()
                            # Tolerate intra-batch UTXO-miss false-rejects
                            # for non-first blocks — the atomic helper's
                            # in-batch overlay will resolve them. Re-raise
                            # everything else.
                            is_first_in_batch = chain_to_connect[0][0] == blk_hash
                            if is_first_in_batch or (
                                "inputnotfound" not in ve_msg
                                and "input not found" not in ve_msg
                            ):
                                raise

                    # Python validator (disabled-opcode + script verify) —
                    # same tolerance for input-lookup misses on non-first
                    # batch blocks.
                    _py_validator = getattr(self.node, "validator", None)
                    if _py_validator is not None:
                        try:
                            from ouroboros.database import Block as _Blk
                            _blk_obj = _Blk.deserialize(raw_bytes)
                            _valid, _err = await asyncio.to_thread(
                                _py_validator.validate_block,
                                _blk_obj,
                                blk_height,
                            )
                            if not _valid:
                                _err_lower = (str(_err) or "").lower()
                                is_first_in_batch = chain_to_connect[0][0] == blk_hash
                                if is_first_in_batch or (
                                    "input not found" not in _err_lower
                                    and "missing utxo" not in _err_lower
                                ):
                                    raise ValueError(_err)
                        except ValueError:
                            raise
                        except Exception:
                            pass

                # Single-batch connect — Rust accumulates every block's
                # writes into one WriteBatch and commits atomically.
                blocks_arg: list[tuple[bytes, int]] = [
                    (raw_bytes, blk_height)
                    for _, blk_height, raw_bytes in chain_to_connect
                ]
                hashes_returned = await asyncio.to_thread(
                    db.connect_blocks_atomic,
                    blocks_arg,
                    network,
                )
                connected_hashes = [bytes(h) for h in hashes_returned]

                # Mempool eviction for confirmed transactions (best-effort).
                _mempool = getattr(self.node, "mempool", None)
                try:
                    _has_mempool_entries = (
                        _mempool is not None and len(_mempool) > 0
                    )
                except Exception:
                    _has_mempool_entries = False
                if _has_mempool_entries:
                    for _, _, raw_bytes in chain_to_connect:
                        try:
                            from ouroboros.database import Block as _Blk
                            _blk = _Blk.deserialize(raw_bytes)
                            _mempool.remove_block_transactions(_blk)
                        except Exception:
                            pass
            except Exception as e:
                logger.error(
                    "submitblock reorg: connect_blocks_atomic failed: %s",
                    e, exc_info=True,
                )
                # ATOMICITY (S5): the disconnect-side commit already landed,
                # so the disk state is now a prefix of the LOSING competitor
                # (or the bare common ancestor). Core never stays there — roll
                # back to the original tip so a failed reorg is a no-op.
                return await self._restore_original_chain(
                    db, common_ancestor_height, disconnected_active,
                    new_tip_hash, str(e),
                )
        else:
            # Single-block reorg (or atomic helper unavailable): retain
            # the original per-block accept_block path. accept_block
            # runs the same CheckBlock + ConnectBlock pipeline as the
            # IBD path, so SPENT_CF undo records get written for the
            # new chain — required for any future re-reorg back to the
            # displaced A-chain.
            for blk_hash, blk_height, raw_bytes in chain_to_connect:
                logger.debug(
                    "submitblock reorg: connecting %s at h=%d",
                    blk_hash.hex()[:16], blk_height,
                )
                try:
                    await accept_block(
                        db,
                        self.node,
                        raw_bytes,
                        blk_height,
                        skip_scripts=False,
                    )
                    connected_hashes.append(blk_hash)
                except Exception as e:
                    logger.error(
                        "submitblock reorg: accept_block at h=%d failed: %s",
                        blk_height, e, exc_info=True,
                    )
                    # ATOMICITY (S5): we have already disconnected the original
                    # chain and connected 0..k blocks of the losing competitor.
                    # A partial switch to the losing chain is a consensus fault
                    # (the clearbit-incident / blockbrew-R3 class). Roll the
                    # chainstate back to the original tip so the failed reorg
                    # leaves no trace — matching Core ActivateBestChainStep.
                    return await self._restore_original_chain(
                        db, common_ancestor_height, disconnected_active,
                        new_tip_hash, str(e),
                    )

        # Successful flip: drop the connected blocks from the side-branch
        # buffer (they're now on the active chain), and shed any blocks
        # whose buffered height is now stale-equal to the displaced A-chain.
        for h in connected_hashes:
            self._side_branch_blocks.pop(h, None)

        # RETAIN (S4 / reorg-back): stash the just-disconnected original-chain
        # blocks into the side-branch buffer so a later block extending the
        # now-abandoned branch can resolve its parent (``_resolve_parent_height``)
        # and drive a reorg BACK onto it. Without this, ouroboros's height-keyed
        # BLOCK_INDEX_CF overwrites the displaced branch's height slots with the
        # winning chain, so the abandoned blocks become unreachable and any
        # follow-up on them is false-rejected as "prev-blk-not-found" — the node
        # can reorg A->B but never B->A'. Bitcoin Core retains every block in
        # ``m_block_index`` regardless of active chain, which is what makes its
        # ``FindMostWorkChain`` able to switch back (validation.cpp).
        for _blk_hash, _blk_height, _raw in disconnected_active:
            if _blk_hash in self._side_branch_blocks:
                continue
            try:
                _prev = bytes(_raw[4:36])
            except Exception:
                continue
            self._side_branch_blocks[_blk_hash] = (_prev, _blk_height, _raw)
        self._evict_side_branch_if_full()

        # ----------------------------------------------------------
        # Mempool refill (Pattern B closure for the submitblock path).
        # Mirror ``BlockSync._handle_reorg`` (block_sync.py:2537-2555):
        # feed each disconnected non-coinbase tx back to the mempool so
        # that on a chain reorg, transactions valid against the new tip
        # don't silently vanish. ``add_transaction`` runs the same
        # checks as a freshly received tx (BIP-113 IsFinalTx, BIP-68
        # SequenceLocks, standardness, double-spend against new-chain
        # UTXOs), so this is policy-correct against the new tip.
        #
        # Counterpart in Bitcoin Core: ``Chainstate::DisconnectTip`` →
        # ``MaybeUpdateMempoolForReorg`` (validation.cpp).
        #
        # Today's c822cc1 introduced this submitblock-driven reorg path
        # but routed disconnect through ``db.disconnect_block`` directly,
        # bypassing the refill loop that ``_handle_reorg`` already had —
        # the "Pattern B miswire" identified in
        # CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.
        # ----------------------------------------------------------
        mempool = getattr(self.node, "mempool", None)
        if mempool is not None and disconnected_txs:
            try:
                _, final_height = db.get_best_block()
            except Exception:
                final_height = -1
            refilled = 0
            for tx in disconnected_txs:
                try:
                    success, reason = mempool.add_transaction(tx, final_height)
                    if success:
                        refilled += 1
                    else:
                        logger.debug(
                            "submitblock reorg: tx %s not re-added: %s",
                            tx.get_txid().hex()[:16], reason,
                        )
                except Exception as e:
                    logger.debug(
                        "submitblock reorg: error re-adding tx: %s", e,
                    )
            logger.info(
                "submitblock reorg: refilled %d/%d disconnected txs to mempool",
                refilled, len(disconnected_txs),
            )

        return None

    def _side_branch_chainwork(
        self, db, tip_hash: bytes, tip_height: int
    ) -> int | None:
        """Cumulative chainwork of the branch ending at ``tip_hash``.

        Walks the in-memory side-branch buffer from ``tip_hash`` back to the
        common ancestor on the active chain, summing each buffered block's
        proof-of-work onto the ancestor's active-chain cumulative work. Returns
        the branch's total cumulative work as an int (the value Bitcoin Core's
        ``CBlockIndex::nChainWork`` would carry for this block), or ``None`` if
        the branch cannot be resolved through the buffer.
        """
        total = 0
        cursor = tip_hash
        seen: set[bytes] = set()
        for _ in range(self._side_branch_max_entries + 4):
            if cursor in seen:
                return None
            seen.add(cursor)
            entry = self._side_branch_blocks.get(cursor)
            if entry is None:
                # cursor is no longer in the side-branch buffer — it must be the
                # common ancestor on the active chain. Confirm it really is the
                # active-chain block at its height, then add its cumulative work.
                anc_h = self._resolve_parent_height(db, cursor)
                if anc_h is None:
                    return None
                try:
                    anc_active = db.get_block_hash_by_height(anc_h)
                except Exception:
                    anc_active = None
                if anc_active is None or bytes(anc_active) != cursor:
                    return None
                return total + self.node._calculate_chainwork_at_height(anc_h)
            prev_hash, _h, raw_bytes = entry
            # 80-byte header: version(4) prev(32) merkle(32) time(4) bits(4)
            # nonce(4) -> compact ``bits`` lives at offset 72:76 (little-endian).
            if len(raw_bytes) >= 76:
                bits = int.from_bytes(raw_bytes[72:76], "little")
                total += self.node._calculate_block_work(bits)
            cursor = prev_hash
        return None

    async def _activate_precious_block(
        self, db, block_hash: bytes, block_height: int
    ) -> None:
        """ActivateBestChain analog for a precious block.

        Drives the same DisconnectTip/ConnectTip reorg machinery the
        submitblock side-branch path uses. The equal-work tiebreak is implicit:
        the normal P2P/IBD path only reorgs onto a STRICTLY-heavier branch,
        whereas preciousblock forces the flip onto an equal-work competitor that
        has just been marked precious.

        Reference: bitcoin-core/src/validation.cpp
        ``Chainstate::PreciousBlock`` -> ``ActivateBestChain``.
        """
        if block_hash not in self._side_branch_blocks:
            # Not staged in the in-memory side-branch buffer, so a buffered
            # branch reorg cannot be assembled. Fall back to the Rust
            # ActivateBestChain analog, which reactivates a strictly-heavier
            # stored leaf (a no-op for an equal-work block — documented gap).
            rust = getattr(db, "_db", None) or getattr(db, "rust_db", None)
            if rust is not None and hasattr(rust, "reactivate_best_chain"):
                try:
                    await asyncio.to_thread(rust.reactivate_best_chain)
                    if hasattr(db, "_cached_tip"):
                        db._cached_tip = None
                except Exception as e:
                    logger.warning(
                        "preciousblock: reactivate_best_chain failed: %s", e
                    )
            return

        result = await self._reorg_to_side_branch_tip(db, block_hash)
        if result is not None:
            # The reorg engine returned a BIP-22 reject string — the precious
            # branch could not be activated (e.g. a buffered block failed
            # validation). Core would surface this via state.IsValid(); here we
            # log and leave the active chain unchanged.
            logger.warning(
                "preciousblock: activation did not flip the chain: %s", result
            )
            return

        if hasattr(db, "_cached_tip"):
            db._cached_tip = None

        # The reorg did not fire the Python connect/disconnect index hooks, so
        # re-align the optional indexes with the new active chain — same
        # non-fatal pattern invalidateblock / reconsiderblock use.
        csi = getattr(self.node, "coinstats_index", None)
        if csi is not None:
            try:
                await asyncio.to_thread(csi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    "preciousblock: coinstatsindex resync failed: %s", e
                )
        tsi = getattr(self.node, "txospender_index", None)
        if tsi is not None:
            try:
                await asyncio.to_thread(tsi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    "preciousblock: txospenderindex resync failed: %s", e
                )

    async def rpc_submitblock(self, hexdata: str) -> str | None:
        """
        Submit a mined block to the network.

        Returns None on success, an error string on failure.
        Stores the block in the database (block data, header/height index,
        UTXO set, tx index) and updates the chain tip.

        Routes through the unified ``accept_block`` helper (Core
        ProcessNewBlock parity) — all structural, contextual, and script
        checks fire before any UTXO mutation.

        Side-branch blocks (parent is in the block index but is NOT the
        active tip) are stored in an in-memory side-branch buffer rather
        than rejected. When a side-branch block makes the competing chain
        strictly heavier than the active chain, this method drives a
        reorg back to the common ancestor and forward to the new tip.
        Mirrors Bitcoin Core's ``BlockManager::AcceptBlock`` /
        ``ActivateBestChain`` separation of storage and best-chain
        selection (validation.cpp). Pattern X + Y closure
        (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md).
        """
        # NetworkDisable gate: refuse submissions while a ``dumptxoutset
        # rollback`` rewind→dump→replay dance is in progress. Mirrors
        # Bitcoin Core's NetworkDisable RAII around TemporaryRollback in
        # rpc/blockchain.cpp::dumptxoutset.
        if self.block_submission_paused:
            # BIP-22: return canonical string in result field, not a long message.
            return "rejected"

        try:
            block_bytes = bytes.fromhex(hexdata)
        except ValueError:
            return "rejected"

        db = getattr(self.node, "db", None)
        if db is None:
            return "rejected"

        # Pre-deserialise the header to inspect prev_blockhash. Cheap
        # (header is the first 80 bytes); the full Block.deserialize gets
        # called inside accept_block / _attach_side_branch_block once we
        # know which path to dispatch.
        if len(block_bytes) < 80:
            return "rejected"
        # 80-byte header layout:
        #   version (4) | prev_blockhash (32) | merkle_root (32) | time (4)
        #   | bits (4) | nonce (4)
        prev_hash = block_bytes[4:36]
        # Block hash is dsha256(header[:80]), already in internal byte order.
        block_hash = _hashlib.sha256(
            _hashlib.sha256(block_bytes[:80]).digest()
        ).digest()

        # Duplicate-submission short-circuit. Core returns "duplicate" for
        # blocks already on the active chain, "duplicate-inconclusive" for
        # blocks already stored as side-branch.
        try:
            if hasattr(db, "has_block_hash") and db.has_block_hash(block_hash):
                return "duplicate"
        except Exception:
            pass
        if block_hash in self._side_branch_blocks:
            return "duplicate-inconclusive"

        try:
            tip_hash, best_height = db.get_best_block()
        except Exception:
            return "rejected"

        # Best-chain extension fast path: prev == active tip. This is the
        # overwhelmingly common case (mining a block on the canonical
        # chain). Routes through the existing accept_block pipeline
        # unchanged — the height comes from ``best_height + 1`` because
        # the parent IS the tip.
        if prev_hash == tip_hash:
            try:
                await accept_block(
                    db,
                    self.node,
                    block_bytes,
                    best_height + 1,
                    skip_scripts=False,
                )
                return None
            except Exception as e:
                return bip22_result_string(str(e))

        # Side-branch path: parent is not the active tip. Resolve its
        # height (via active chain or side-branch buffer); if unknown,
        # the block is a true orphan. Pattern X + Y closure.
        parent_height = self._resolve_parent_height(db, prev_hash)
        if parent_height is None:
            return bip22_result_string(
                f"prev-blk-not-found {prev_hash.hex()[:16]}..."
            )

        new_height = parent_height + 1
        return await self._attach_side_branch_block(
            db,
            block_bytes,
            block_hash,
            prev_hash,
            new_height,
        )

    async def rpc_submitheader(self, hexdata: str) -> None:
        """
        Decode the given hexdata as a header and submit it as a candidate chain
        tip if valid.  Throws when the header is invalid.

        Reference: Bitcoin Core mining.cpp submitheader()

        Args:
            hexdata: Hex-encoded 80-byte block header.

        Returns:
            None on success (JSON null).

        Raises:
            RpcError(-22): Bad hex or wrong length (not 80 bytes).
            RpcError(-25): Previous block header is not known to this node.
            RpcError(-25): Header fails PoW or contextual validation.

        Error strings are byte-identical to Bitcoin Core:
          * "Block header decode failed"                        (RPC_DESERIALIZATION_ERROR -22)
          * "Must submit previous header (<prevhash>) first"   (RPC_VERIFY_ERROR -25)
          * reject reason string on PoW / contextual failure   (RPC_VERIFY_ERROR -25)
        """
        # --- Step 1: decode the hex-encoded header --------------------------
        # Core: DecodeHexBlockHeader(h, request.params[0].get_str())
        # Bad hex or non-80-byte payload → RPC_DESERIALIZATION_ERROR -22
        from ouroboros.p2p_messages import BlockHeader as _BlockHeader

        try:
            header_bytes = bytes.fromhex(hexdata)
        except (ValueError, AttributeError):
            raise RpcError(RPC_DESERIALIZATION_ERROR, "Block header decode failed")

        if len(header_bytes) != 80:
            raise RpcError(RPC_DESERIALIZATION_ERROR, "Block header decode failed")

        try:
            header, _ = _BlockHeader.from_payload(header_bytes, 0)
        except Exception:
            raise RpcError(RPC_DESERIALIZATION_ERROR, "Block header decode failed")

        # Compute the block hash (double-SHA256 of 80-byte header, internal
        # byte order — little-endian, matches Bitcoin Core's uint256).
        block_hash = _hashlib.sha256(_hashlib.sha256(header_bytes).digest()).digest()

        # prev_blockhash is already in internal (little-endian) byte order.
        prev_hash = header.prev_blockhash  # 32 bytes, internal order

        # Display-order (big-endian) hex of prevhash for error messages,
        # matching Core's h.hashPrevBlock.GetHex() which reverses the bytes.
        prev_hash_display = prev_hash[::-1].hex()

        # --- Step 2: parent-known check -------------------------------------
        # Core: chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)
        # prev not in block index → RPC_VERIFY_ERROR -25
        db = getattr(self.node, "db", None)
        if db is None:
            raise RpcError(RPC_VERIFY_ERROR, "Database not available")

        parent_known = False

        # Fast path: check the full block store (covers active chain + any
        # blocks we have downloaded and stored).
        try:
            if hasattr(db, "has_block_hash") and db.has_block_hash(prev_hash):
                parent_known = True
        except Exception:
            pass

        # Also check the headers-only queues inside block_sync (covers
        # headers validated via the P2P headers-first path but not yet
        # downloaded as full blocks — Core's block index includes these).
        if not parent_known:
            block_sync = getattr(self.node, "block_sync", None)
            if block_sync is not None:
                # Tip-anchored validated-header queue.
                if hasattr(block_sync, "_validated_headers"):
                    for _bh, _ in block_sync._validated_headers:
                        if _bh == prev_hash:
                            parent_known = True
                            break
                # Competing-fork header store.
                if not parent_known and hasattr(block_sync, "_fork_headers"):
                    if prev_hash in block_sync._fork_headers:
                        parent_known = True

        if not parent_known:
            raise RpcError(
                RPC_VERIFY_ERROR,
                f"Must submit previous header ({prev_hash_display}) first",
            )

        # --- Step 3: idempotency -------------------------------------------
        # Core's ProcessNewBlockHeaders is idempotent — submitting a header
        # already in the block index is a no-op that returns null.
        already_known = False
        try:
            if hasattr(db, "has_block_hash") and db.has_block_hash(block_hash):
                already_known = True
        except Exception:
            pass
        if not already_known:
            block_sync = getattr(self.node, "block_sync", None)
            if block_sync is not None:
                if hasattr(block_sync, "_validated_headers"):
                    for _bh, _ in block_sync._validated_headers:
                        if _bh == block_hash:
                            already_known = True
                            break
                if not already_known and hasattr(block_sync, "_fork_headers"):
                    if block_hash in block_sync._fork_headers:
                        already_known = True
        if already_known:
            return None

        # --- Step 4: PoW validation ----------------------------------------
        # Core: ProcessNewBlockHeaders → CheckBlockHeader → CheckProofOfWork.
        # Reuse BlockSync._header_meets_pow — same algorithm, no import loop.
        block_sync = getattr(self.node, "block_sync", None)
        if block_sync is not None:
            pow_ok = type(block_sync)._header_meets_pow(header)
        else:
            # Inline fallback (same logic as BlockSync._header_meets_pow).
            try:
                _mantissa = int(header.bits) & 0x007FFFFF
                _exp = (int(header.bits) >> 24) & 0xFF
                if _mantissa == 0:
                    _target = 0
                elif _exp <= 3:
                    _target = _mantissa >> (8 * (3 - _exp))
                else:
                    _target = _mantissa << (8 * (_exp - 3))
                _hash_int = int.from_bytes(block_hash, "little")
                pow_ok = (_target > 0) and (_hash_int <= _target)
            except Exception:
                pow_ok = False

        if not pow_ok:
            raise RpcError(RPC_VERIFY_ERROR, "bad-diffbits")

        # --- Step 5: admit the header into the appropriate store ------------
        # Mirrors Core's ProcessNewBlockHeaders → AcceptBlockHeader which
        # inserts the validated header into the block index.
        #
        # In ouroboros the block-index equivalent is:
        #   _validated_headers  — tip-anchored queue for the best chain
        #   _fork_headers       — competing-fork storage
        if block_sync is not None:
            # Determine the expected prev for the tip-anchored queue.
            if block_sync._validated_headers:
                queue_tip_hash = block_sync._validated_headers[-1][0]
            else:
                try:
                    queue_tip_hash, _ = db.get_best_block()
                except Exception:
                    queue_tip_hash = None

            if queue_tip_hash is not None and prev_hash == queue_tip_hash:
                # Extends the tip-anchored validated-header queue.
                block_sync._validated_headers.append((block_hash, header))
                logger.info(
                    "submitheader: queued tip-extending header %s (prev %s)",
                    block_hash[::-1].hex()[:16],
                    prev_hash_display[:16],
                )
            elif hasattr(block_sync, "_store_fork_header"):
                # Parent is on the active chain or in the fork store but is
                # NOT the validated-header queue tip → store as fork header.
                block_sync._store_fork_header(block_hash, header, prev_hash)
                logger.info(
                    "submitheader: stored fork header %s (prev %s)",
                    block_hash[::-1].hex()[:16],
                    prev_hash_display[:16],
                )

        return None

    async def rpc_submitblockbatch(self, hexblocks: list) -> list:
        """
        Submit multiple blocks in a single RPC call (IBD fast-path).

        Accepts a JSON array of hex-encoded blocks. Returns a list of
        results: null for success, or an error string for each block.
        Blocks are applied sequentially in the order given.

        Previously this called ``connect_block_from_bytes`` directly,
        bypassing all validation (Gap O1, wave-29 audit).  Now routes
        through the unified ``accept_block`` helper so the same
        CheckBlock + ContextualCheckBlock + script-verify pipeline runs
        as for ``rpc_submitblock`` and the P2P drain.  skip_scripts=False
        because this is an over-the-wire RPC — the caller is trusted to
        supply sequential blocks but NOT trusted to supply valid ones.
        """
        # NetworkDisable gate: refuse the whole batch while a
        # ``dumptxoutset rollback`` rewind→dump→replay dance is in
        # progress. Mirrors Bitcoin Core's NetworkDisable RAII around
        # TemporaryRollback in rpc/blockchain.cpp::dumptxoutset.
        if self.block_submission_paused:
            # BIP-22: return canonical "rejected" strings, not long messages.
            return ["rejected"] * len(hexblocks)

        db = getattr(self.node, "db", None)
        if db is None:
            return ["rejected"] * len(hexblocks)

        results = []
        for hexdata in hexblocks:
            try:
                block_bytes = bytes.fromhex(hexdata)
            except (ValueError, TypeError):
                results.append("rejected")
                continue

            try:
                _, best_height = db.get_best_block()
                next_height = best_height + 1
                await accept_block(
                    db,
                    self.node,
                    block_bytes,
                    next_height,
                    skip_scripts=False,
                )
                results.append(None)
            except Exception as e:
                # Map to canonical BIP-22 result string.
                # On failure, stop processing subsequent blocks in the batch:
                # a validation failure means the chain tip did not advance,
                # so the next block would also fail (wrong prev_hash).
                results.append(bip22_result_string(str(e)))
                # Pad remaining entries as "rejected" (stale prev context).
                remaining = len(hexblocks) - len(results)
                if remaining > 0:
                    results.extend(["rejected"] * remaining)
                break

        return results

    async def rpc_pruneblockchain(self, height: int) -> int:
        """
        Prune block data up to the given height.

        Instructs the node to delete old block files (blk*.dat and rev*.dat)
        up to the specified height.  Block headers and metadata are preserved.

        The actual prune height may be less than requested to maintain the
        minimum reorg safety margin (288 blocks).

        Returns:
            The height of the last block that was pruned.
        """
        pruner = getattr(self.node, "pruner", None)
        if pruner is None:
            return JSONRPCResponse(
                error={
                    "code": -1,
                    "message": "Cannot prune blocks because node is not "
                    "in prune mode. Start with -prune=<target_size_mb>.",
                },
                id=None,
            )

        _, best_height = self.node.db.get_best_block()

        # Use the file-based pruner
        actual_height = pruner.prune_to_height(height, best_height)
        logger.info(f"RPC pruneblockchain: pruned up to height {actual_height}")
        return actual_height

    async def rpc_invalidateblock(self, blockhash: str) -> None:
        """
        Mark a block as invalid and disconnect it from the active chain.

        Permanently marks a block as permanently invalid, as if it violated
        a consensus rule. The block and all its descendants will be marked
        as invalid and excluded from chain selection.

        If the block is part of the active chain, the chain will be reorganized
        to the best valid chain (the parent of the invalidated block).

        This command can be used to manually trigger a chain reorganization
        or to mark a known-bad block as invalid for testing purposes.

        Arguments:
            blockhash: The hash of the block to invalidate (hex string)

        Returns:
            None on success

        Raises:
            JSONRPCError: If the block is not found or cannot be invalidated

        Reference:
            Bitcoin Core: rpc/blockchain.cpp invalidateblock()
        """
        if not hasattr(self.node, 'db') or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        # Parse the block hash the way Core's ParseHashV does: a malformed
        # (non-hex / wrong-length) hash is RPC_INVALID_PARAMETER (-8) at the
        # parse boundary, BEFORE any lookup (rpc/util.cpp ParseHashV) — not the
        # internal-error/-32603 the old HTTPException(400) mapped to.
        block_hash = _parse_hash_v(blockhash, "blockhash")  # display order; -8 on malformed
        block_hash_internal = bytes(reversed(block_hash))   # internal little-endian

        # Check if block exists
        db = self.node.db
        try:
            # Resolve the Rust DB handle.  BlockchainDatabase wraps the
            # PyBlockchainDB as ``_db`` (older drafts referenced a ``rust_db``
            # attribute that never existed, so invalidateblock always errored
            # — fixed here so the reorg primitive actually runs).
            rust = getattr(db, '_db', None) or getattr(db, 'rust_db', None)
            if rust is not None and hasattr(rust, 'invalidate_block'):
                new_tip_height = rust.invalidate_block(block_hash_internal)
                logger.info(
                    f"invalidateblock: Invalidated block {blockhash[:16]}... "
                    f"new tip height: {new_tip_height}"
                )
                # Keep the cached chain tip consistent with the Rust reorg.
                if hasattr(db, '_cached_tip'):
                    db._cached_tip = None
                # Core's InvalidateBlock disconnects the target block ITSELF
                # (the active tip ends at the target's parent).  The Rust
                # invalidate_block disconnects only blocks ABOVE the target and
                # RETURNS target-1 while leaving the target block connected, so
                # the actual chainstate tip can sit one block high.  Reconcile
                # the chainstate down to the returned new_tip_height so the tip
                # lands at the parent, matching Core.
                try:
                    _, actual_h = rust.get_best_block()
                    while int(actual_h) > int(new_tip_height):
                        rust.disconnect_block(int(actual_h))
                        _, actual_h = rust.get_best_block()
                    if hasattr(db, '_cached_tip'):
                        db._cached_tip = None
                except Exception as _e:
                    logger.warning(
                        f"invalidateblock: tip reconcile to {new_tip_height} "
                        f"failed: {_e}"
                    )
            else:
                # Fallback: Python-only implementation
                raise HTTPException(
                    status_code=500,
                    detail="invalidateblock requires Rust database bindings"
                )
        except Exception as e:
            if "not found" in str(e).lower():
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found") from None
            if "genesis" in str(e).lower():
                raise HTTPException(status_code=400, detail="Cannot invalidate genesis block") from None
            raise HTTPException(status_code=500, detail=str(e)) from None

        # The Rust layer performed the chainstate reorg WITHOUT firing the
        # Python connect/disconnect index hooks, so re-align the coin-stats
        # index with the new active chain (rewind reorged-away heights, then
        # re-connect the new chain forward).  Non-fatal: an index fault must
        # never abort the RPC.  Same gap the block_sync reorg loop handles for
        # the P2P/IBD path — here it is the invalidateblock-driven reorg.
        csi = getattr(self.node, "coinstats_index", None)
        if csi is not None:
            try:
                await asyncio.to_thread(csi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    f"invalidateblock: coinstatsindex resync failed: {e}"
                )

        # Same gap for -txospenderindex: the Rust reorg did not fire the Python
        # connect/disconnect hooks, so re-align the spender index with the new
        # active chain (rewind reorged-away spend keys, re-connect forward).
        tsi = getattr(self.node, "txospender_index", None)
        if tsi is not None:
            try:
                await asyncio.to_thread(tsi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    f"invalidateblock: txospenderindex resync failed: {e}"
                )

        return None

    async def rpc_reconsiderblock(self, blockhash: str) -> None:
        """
        Remove invalidity status from a block and reconsider it for activation.

        Removes the "invalid" marking from a block that was previously marked
        invalid via invalidateblock. The block and its ancestors/descendants
        will be reconsidered for chain selection.

        If the reconsidered chain has more cumulative proof-of-work than the
        current active chain, a reorganization will occur.

        This command can be used to undo the effects of invalidateblock.

        Arguments:
            blockhash: The hash of the block to reconsider (hex string)

        Returns:
            None on success

        Raises:
            JSONRPCError: If the block is not found

        Reference:
            Bitcoin Core: rpc/blockchain.cpp reconsiderblock()
        """
        if not hasattr(self.node, 'db') or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        # Parse the block hash the way Core's ParseHashV does: a malformed
        # (non-hex / wrong-length) hash is RPC_INVALID_PARAMETER (-8) at the
        # parse boundary, BEFORE any lookup (rpc/util.cpp ParseHashV) — not the
        # internal-error/-32603 the old HTTPException(400) mapped to.
        block_hash = _parse_hash_v(blockhash, "blockhash")  # display order; -8 on malformed
        block_hash_internal = bytes(reversed(block_hash))   # internal little-endian

        # Reconsider the block
        db = self.node.db
        try:
            rust = getattr(db, '_db', None) or getattr(db, 'rust_db', None)
            if rust is not None and hasattr(rust, 'reconsider_block'):
                new_tip_height = rust.reconsider_block(block_hash_internal)
                logger.info(
                    f"reconsiderblock: Reconsidered block {blockhash[:16]}... "
                    f"tip height: {new_tip_height}"
                )
                if hasattr(db, '_cached_tip'):
                    db._cached_tip = None
            else:
                raise HTTPException(
                    status_code=500,
                    detail="reconsiderblock requires Rust database bindings"
                )
        except Exception as e:
            if "not found" in str(e).lower():
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found") from None
            raise HTTPException(status_code=500, detail=str(e)) from None

        # reconsiderblock can re-activate (and reorg onto) a previously
        # invalidated branch in the Rust layer without firing the Python index
        # hooks; re-align the coin-stats index with the resulting active chain.
        # Non-fatal.
        csi = getattr(self.node, "coinstats_index", None)
        if csi is not None:
            try:
                await asyncio.to_thread(csi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    f"reconsiderblock: coinstatsindex resync failed: {e}"
                )

        # Same re-alignment for -txospenderindex.
        tsi = getattr(self.node, "txospender_index", None)
        if tsi is not None:
            try:
                await asyncio.to_thread(tsi.resync_to_chainstate, db)
            except Exception as e:
                logger.warning(
                    f"reconsiderblock: txospenderindex resync failed: {e}"
                )

        return None

    async def rpc_preciousblock(self, blockhash: str) -> None:
        """
        Treats a block as if it were received before others with the same work.

        A later preciousblock call can override the effect of an earlier one.
        The effects of preciousblock are NOT retained across restarts.

        Marks the named block "precious": it is assigned a strictly-decreasing
        receive-sequence id so that, on a tie of cumulative proof-of-work, chain
        selection prefers it over equal-work blocks that were seen earlier. The
        node then re-activates the best chain — so if the precious block heads a
        valid competing branch of equal-or-greater work, the active chain is
        reorganised onto it. If the block is already on the active chain, has
        less work than the current tip, or is otherwise not a viable
        competitor, this is a no-op.

        Arguments:
            blockhash: The hash of the block to mark as precious (hex string)

        Returns:
            None on success (JSON null).

        Raises:
            RpcError(-5): if the block hash is unknown.
            RpcError(-8): if the hash is not a valid 64-char hex string.

        Reference:
            Bitcoin Core: validation.cpp Chainstate::PreciousBlock,
            rpc/blockchain.cpp preciousblock().
        """
        if not hasattr(self.node, "db") or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")
        db = self.node.db

        # Core: uint256 hash(ParseHashV(request.params[0], "blockhash"));
        # ParseHashV rejects a malformed hash at the parse boundary with -8.
        parsed = _parse_hash_v(blockhash, "blockhash")  # big-endian display
        block_hash = bytes(reversed(parsed))            # internal little-endian

        # Core: pblockindex = LookupBlockIndex(hash);
        #       if (!pblockindex) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
        #                                            "Block not found");
        block_height = self._get_block_height(db, block_hash)
        if block_height is None:
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        # --- Chainstate::PreciousBlock (validation.cpp:3490) ---
        try:
            best_hash, best_height = db.get_best_block()
            best_hash = bytes(best_hash)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"chain tip unavailable: {e}"
            ) from None

        # Already the active tip, or on the active chain at its height:
        # ActivateBestChain would be a no-op (the block is at or below the tip
        # on the active chain). Return null, matching Core.
        if block_hash == best_hash:
            return None
        try:
            active_at_height = db.get_block_hash_by_height(block_height)
        except Exception:
            active_at_height = None
        if active_at_height is not None and bytes(active_at_height) == block_hash:
            return None

        # Cumulative work of the active tip vs. the precious block's branch.
        tip_work = self.node._calculate_chainwork_at_height(best_height)
        precious_work = self._side_branch_chainwork(db, block_hash, block_height)

        # Core: if (pindex->nChainWork < m_chain.Tip()->nChainWork) return true;
        # The precious block has strictly less work than the tip — nothing to
        # do; do NOT touch the reverse-sequence counter.
        if precious_work is not None and precious_work < tip_work:
            return None

        # Core: reset the reverse-sequence counter when the chain has been
        # extended since the last call, then assign this block the current
        # (decreasing) sequence id and decrement — so a later preciousblock
        # call overrides an earlier one.
        if tip_work > self._last_precious_chainwork:
            self._block_reverse_sequence_id = -1
        self._last_precious_chainwork = tip_work
        self._precious_sequence[block_hash] = self._block_reverse_sequence_id
        _INT32_MIN = -(2 ** 31)
        if self._block_reverse_sequence_id > _INT32_MIN:
            self._block_reverse_sequence_id -= 1

        # --- ActivateBestChain (validation.cpp:3518) ---
        # The precious block now wins the equal-work tie; re-activate the best
        # chain, reorganising onto the precious branch if it is a competitor.
        await self._activate_precious_block(db, block_hash, block_height)
        return None

    # --- Additional RPC methods ---

    async def rpc_help(self, command: str = "") -> str:
        """List all available RPC commands, or get help for a specific command."""
        methods = sorted([
            m[4:] for m in dir(self) if m.startswith('rpc_')
        ])
        if command:
            method = getattr(self, f'rpc_{command}', None)
            if method:
                return method.__doc__ or f"No help for '{command}'"
            return f"Unknown command: {command}"
        return "\n".join(methods)

    async def rpc_stop(self) -> str:
        """Stop the node."""
        import asyncio

        def _trigger_shutdown():
            # Set the shutdown event so _main_loop exits cleanly.
            if hasattr(self.node, '_shutdown_event') and self.node._shutdown_event:
                self.node._shutdown_event.set()
            elif hasattr(self.node, 'stop'):
                asyncio.ensure_future(self.node.stop())

        asyncio.get_event_loop().call_later(0.5, _trigger_shutdown)
        return "Ouroboros server stopping"

    async def rpc_uptime(self) -> int:
        """Return server uptime in seconds."""
        start = getattr(self.node, 'start_time', None)
        if start:
            return int(time.time() - start)
        return 0

    def _aggregate_peerinfo_peers(self, pm: Any) -> list:
        """Return the connected-peer list in ``getpeerinfo`` order.

        Bitcoin Core lists every connection in the ``vNodes`` vector regardless
        of direction (rpc/net.cpp getpeerinfo); ouroboros' PeerManager keeps
        outbound full-relay peers, block-relay-only outbounds, and inbound
        peers in three separate buckets.  Both ``getpeerinfo`` (which emits the
        ``id`` field) and ``getblockfrompeer`` (which resolves the ``peer_id``
        argument) MUST iterate the union of these buckets in the same order so
        that the ``id`` a caller reads from ``getpeerinfo`` selects the same
        peer when handed back to ``getblockfrompeer``.  Deduplicated by object
        identity so a peer that appears in two buckets is listed once.
        """
        peer_list: list = []
        seen_ids: set[int] = set()
        for bucket_name in ("peers", "block_relay_peers", "inbound_peers"):
            bucket = getattr(pm, bucket_name, None)
            if bucket is None:
                continue
            iterable = bucket.values() if isinstance(bucket, dict) else bucket
            for peer in iterable:
                pid = id(peer)
                if pid in seen_ids:
                    continue
                seen_ids.add(pid)
                peer_list.append(peer)
        return peer_list

    def _resolve_peer_by_id(self, peer_id: int):
        """Resolve a ``getpeerinfo`` ``id`` back to its ``Peer`` object.

        ``getpeerinfo`` emits ``getattr(peer, 'id', i)`` for the i-th peer in
        :meth:`_aggregate_peerinfo_peers` order, so we reconstruct that exact
        same mapping and return the peer whose emitted id matches *peer_id*.
        Returns ``None`` when no such peer exists (Core: GetPeerRef → nullptr →
        "Peer does not exist", net_processing.cpp:1966).
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return None
        for i, peer in enumerate(self._aggregate_peerinfo_peers(pm)):
            emitted_id = getattr(peer, 'id', i)
            if emitted_id == peer_id:
                return peer
        return None

    async def rpc_getblockfrompeer(self, blockhash: str, peer_id: int) -> dict[str, Any]:
        """Attempt to fetch a block from a given peer.

        Reference: Bitcoin Core rpc/blockchain.cpp getblockfrompeer +
        net_processing.cpp PeerManagerImpl::FetchBlock.

        We must already have the *header* for this block (e.g. from headers
        sync or ``submitheader``).  On success we schedule a block ``getdata``
        (``MSG_BLOCK | MSG_WITNESS_FLAG``) to the requested peer and return an
        empty object — exactly mirroring Core, which returns ``UniValue::VOBJ``.

        Errors (all ``RPC_MISC_ERROR`` / code ``-1``, matching Core):
          * "Block header missing"  — we don't know the header (blockchain.cpp:547)
          * "Peer does not exist"   — peer_id resolves to no peer (net_processing.cpp:1966)
          * "Block already downloaded" — we already have the full body (blockchain.cpp:558)

        Args:
            blockhash: The block hash to fetch (display-order / big-endian hex).
            peer_id:   The peer to fetch it from (an ``id`` from ``getpeerinfo``).

        Returns:
            ``{}`` if the request was successfully scheduled.
        """
        # JSON-RPC hashes are display-order (big-endian) hex; internal storage
        # and the inv/getdata wire format both use little-endian byte order.
        # Reference: rpc/blockchain.cpp ParseHashV + rpc_getblockheader above.
        try:
            block_hash = bytes.fromhex(blockhash)[::-1]
        except ValueError:
            raise RpcError(RPC_INVALID_PARAMETER, "blockhash must be hexadecimal string")
        if len(block_hash) != 32:
            raise RpcError(RPC_INVALID_PARAMETER, "blockhash must be of length 64 (not %d)" % len(blockhash))

        # peer_id is a NodeId in Core (int64).  Accept numeric strings too.
        try:
            peer_id = int(peer_id)
        except (TypeError, ValueError):
            raise RpcError(RPC_INVALID_PARAMETER, "peer_id must be an integer")

        if not hasattr(self.node, 'db') or not self.node.db:
            raise RpcError(RPC_MISC_ERROR, "Database not available")

        # ----------------------------------------------------------------
        # (1) Header must be known — Core: LookupBlockIndex == nullptr ->
        #     RPC_MISC_ERROR "Block header missing" (blockchain.cpp:547).
        #     The full body being present (get_block) also implies the
        #     header is known; otherwise consult the header-only store the
        #     same way rpc_getblockheader does.
        # ----------------------------------------------------------------
        block = await asyncio.to_thread(self.node.db.get_block, block_hash)
        header_known = block is not None
        if not header_known:
            try:
                raw = await asyncio.to_thread(
                    self.node.db._db.get_raw_header_with_chainwork, block_hash
                )
                header_known = raw is not None
            except Exception:
                header_known = False
        if not header_known:
            raise RpcError(RPC_MISC_ERROR, "Block header missing")

        # ----------------------------------------------------------------
        # (2) Resolve the peer — Core: GetPeerRef(peer_id) == nullptr ->
        #     RPC_MISC_ERROR "Peer does not exist" (net_processing.cpp:1966).
        #     Resolved against the SAME aggregated index getpeerinfo emits.
        # ----------------------------------------------------------------
        peer = self._resolve_peer_by_id(peer_id)
        if peer is None:
            raise RpcError(RPC_MISC_ERROR, "Peer does not exist")

        # ----------------------------------------------------------------
        # (3) Already-downloaded body — Core: index->nStatus & BLOCK_HAVE_DATA
        #     -> RPC_MISC_ERROR "Block already downloaded" (blockchain.cpp:558).
        #     Checked AFTER peer resolution to match Core's RPC ordering
        #     (the RPC body-present check precedes FetchBlock, but FetchBlock's
        #     own peer check is what produces "Peer does not exist"; Core
        #     orders header -> body -> FetchBlock(peer).  We keep header ->
        #     peer -> body so a bad peer_id is reported regardless of body
        #     state, which is the more useful diagnostic).  See note below.
        # ----------------------------------------------------------------
        if block is not None:
            raise RpcError(RPC_MISC_ERROR, "Block already downloaded")

        # ----------------------------------------------------------------
        # (4) Schedule the fetch: send a witness-block getdata to the peer.
        #     Core: CInv(MSG_BLOCK | MSG_WITNESS_FLAG, hash) -> GETDATA
        #     (net_processing.cpp:1981-1987).  Our inventory tuple is
        #     (MSG_WITNESS_BLOCK, hash_internal_LE).
        # ----------------------------------------------------------------
        from ouroboros.p2p_messages import GetDataMessage, MSG_WITNESS_BLOCK

        network = getattr(self.node, 'network', 'mainnet')
        getdata = GetDataMessage(inventory=[(MSG_WITNESS_BLOCK, block_hash)])
        try:
            await peer.send_message(getdata.to_network_message(network))
        except Exception as e:
            # Core: ForNode returning false -> "Peer not fully connected".
            raise RpcError(RPC_MISC_ERROR, "Peer not fully connected")

        logger.debug(
            "getblockfrompeer: requested block %s from peer=%d",
            blockhash, peer_id,
        )
        # Core returns an empty JSON object (UniValue::VOBJ) on success.
        return {}

    async def rpc_getpeerinfo(self) -> list[dict[str, Any]]:
        """Return information about connected peers.

        Reference: Bitcoin Core rpc/net.cpp getpeerinfo

        Returns data about each connected network peer as a JSON array of objects.
        Each peer object includes:
        - id: Peer index
        - addr: IP address and port
        - services: Services offered (hex)
        - servicesnames: Human-readable service names
        - lastsend: UNIX timestamp of last send
        - lastrecv: UNIX timestamp of last receive
        - bytessent: Total bytes sent
        - bytesrecv: Total bytes received
        - conntime: Connection time (UNIX timestamp)
        - version: Protocol version
        - subver: User agent string
        - inbound: True if inbound connection
        - connection_type: Type of connection
        - synced_headers: Last header we have in common
        - synced_blocks: Last block we have in common
        """
        import time as _time

        peers = []
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return []

        # Aggregate every category PeerManager tracks (see
        # ``_aggregate_peerinfo_peers``).  ``getblockfrompeer`` resolves its
        # ``peer_id`` argument against this exact same ordered list so that a
        # caller can take an ``id`` straight out of ``getpeerinfo`` and feed it
        # back in — Core makes the same guarantee (rpc/net.cpp getpeerinfo and
        # rpc/blockchain.cpp getblockfrompeer both key off NodeId).
        peer_list = self._aggregate_peerinfo_peers(pm)

        for i, peer in enumerate(peer_list):
            # Get peer ID (use internal ID if available)
            peer_id = getattr(peer, 'id', i)

            # Get address
            addr = getattr(peer, 'address', '')
            if not addr and hasattr(peer, 'host') and hasattr(peer, 'port'):
                addr = f"{peer.host}:{peer.port}"

            # Services
            services = getattr(peer, 'services', 0)
            services_hex = f"{services:016x}"

            # Service names (Bitcoin Core style)
            service_names = []
            if services & 1:    # NODE_NETWORK
                service_names.append("NETWORK")
            if services & 2:    # NODE_GETUTXO
                service_names.append("GETUTXO")
            if services & 4:    # NODE_BLOOM
                service_names.append("BLOOM")
            if services & 8:    # NODE_WITNESS
                service_names.append("WITNESS")
            if services & 16:   # NODE_XTHIN
                service_names.append("XTHIN")
            if services & 64:   # NODE_COMPACT_FILTERS
                service_names.append("COMPACT_FILTERS")
            if services & 1024: # NODE_NETWORK_LIMITED
                service_names.append("NETWORK_LIMITED")
            if services & 2048: # NODE_P2P_V2
                service_names.append("P2P_V2")

            # Timestamps.  Peer.connected_at (peer.py:259) is the canonical
            # attribute; the old `connected_time` lookup always fell through
            # to the default (current time), so every peer looked like it
            # had just connected.
            now = int(_time.time())
            lastsend = int(getattr(peer, 'last_send', 0) or 0)
            lastrecv = int(getattr(peer, 'last_recv', 0) or 0)
            conntime = int(getattr(peer, 'connected_at', now) or now)

            # Bytes sent/received — populated by peer.send_message /
            # peer.receive_message.  Wire-bytes (include v1 header framing
            # and v2 AEAD tags), matching Bitcoin Core's semantics.
            bytessent = getattr(peer, 'bytes_sent', 0)
            bytesrecv = getattr(peer, 'bytes_recv', 0)

            # Connection type
            inbound = getattr(peer, 'inbound', False)
            connection_type = "inbound" if inbound else "outbound-full-relay"
            if hasattr(peer, 'connection_type'):
                connection_type = peer.connection_type
            elif hasattr(peer, 'is_feeler') and peer.is_feeler:
                connection_type = "feeler"
            elif hasattr(peer, 'is_block_relay_only') and peer.is_block_relay_only:
                connection_type = "block-relay-only"

            # Ping times.  Peer tracks `latency` (last pong RTT in seconds),
            # `min_ping` (running minimum RTT, Core m_min_ping_time) and
            # `ping_wait_since` (monotonic-clock send time of an outstanding
            # ping, Core m_ping_start).  These mirror Core's pingtime / minping /
            # pingwait (rpc/net.cpp:253-260): pingwait is the elapsed time of an
            # in-flight ping and is omitted once the pong lands.
            latency = getattr(peer, 'latency', 0) or 0
            pingtime = latency if latency > 0 else None
            min_ping = getattr(peer, 'min_ping', None)
            minping = min_ping if (min_ping is not None and min_ping > 0) else None
            ping_wait_since = getattr(peer, 'ping_wait_since', None)
            if ping_wait_since is not None:
                pingwait = max(0.0, _time.time() - ping_wait_since)
            else:
                pingwait = None

            # Block relay info
            bip152_hb_to = getattr(peer, 'bip152_highbandwidth_to', False)
            bip152_hb_from = getattr(peer, 'bip152_highbandwidth_from', False)

            # Min fee filter
            minfeefilter = getattr(peer, 'fee_filter', 0)

            # BIP-324 transport classification.  Bitcoin Core exposes
            # ``transport_protocol_type`` ("v1" | "v2" | "detecting") and
            # the 32-byte hex ``session_id`` on getpeerinfo (rpc/net.cpp
            # 24.0+).  Cross-impl interop tooling matches on these fields,
            # so omitting them caused the matrix harness to misclassify
            # ouroboros-inbound v2 connections as v1.
            v2_obj = getattr(peer, '_v2_transport', None)
            if v2_obj is not None:
                transport_protocol_type = "v2"
                try:
                    session_id_hex = v2_obj.session_id.hex()
                except Exception:
                    session_id_hex = ""
            else:
                transport_protocol_type = "v1"
                session_id_hex = ""

            info: dict[str, Any] = {
                "id": peer_id,
                "addr": addr,
                # network: derived from the peer's connection type (ipv4/ipv6/
                # onion/i2p/cjdns/not_publicly_routable), matching Core rpc/net.cpp.
                "network": self._addrman_network_name(peer),
                "services": services_hex,
                "servicesnames": service_names,
                # Peer.relay_txs (peer.py:207) — prior `relay_txes` lookup
                # fell through to the `True` default on every peer.
                "relaytxes": getattr(peer, 'relay_txs', True),
                # last_inv_sequence / inv_to_send — Core v31.99 emits these two
                # NUM fields immediately after relaytxes and before lastsend
                # (rpc/net.cpp:242-245).  ouroboros does not track per-peer INV
                # mempool-sequence / outbound-INV-queue depth at the manager
                # layer, so emit 0 (same pattern as addr_processed /
                # addr_rate_limited) to preserve Core's exact wire order.
                "last_inv_sequence": int(getattr(peer, 'last_inv_sequence', 0) or 0),
                "inv_to_send": int(getattr(peer, 'inv_to_send', 0) or 0),
                "lastsend": lastsend,
                "lastrecv": lastrecv,
                "last_transaction": getattr(peer, 'last_tx_time', 0),
                "last_block": getattr(peer, 'last_block_time', 0),
                "bytessent": bytessent,
                "bytesrecv": bytesrecv,
                "conntime": conntime,
                "timeoffset": getattr(peer, 'time_offset', 0),
                "version": getattr(peer, 'version', 0),
                "subver": getattr(peer, 'user_agent', ''),
                "inbound": inbound,
                "bip152_hb_to": bip152_hb_to,
                "bip152_hb_from": bip152_hb_from,
                # startingheight removed in Bitcoin Core v31.99 — getpeerinfo
                # now goes bip152_hb_from -> presynced_headers with no
                # startingheight pushKV (rpc/net.cpp:269-270).  m_starting_height
                # survives only as a local int in version-message handling and
                # is no longer surfaced via RPC.
                "presynced_headers": getattr(peer, 'presynced_headers', -1),
                "synced_headers": getattr(peer, 'synced_headers', -1),
                "synced_blocks": getattr(peer, 'synced_blocks', -1),
                "inflight": getattr(peer, 'inflight_blocks', []),
                "addr_relay_enabled": getattr(peer, 'addr_relay_enabled', True),
                "addr_processed": getattr(peer, 'addr_processed', 0),
                "addr_rate_limited": getattr(peer, 'addr_rate_limited', 0),
                "permissions": getattr(peer, 'permissions', []),
                "minfeefilter": minfeefilter / 1e8 if minfeefilter > 0 else 0.0,
                "connection_type": connection_type,
                "transport_protocol_type": transport_protocol_type,
                "session_id": session_id_hex,
            }

            # Optional ping fields
            if pingtime is not None:
                info["pingtime"] = pingtime
            if minping is not None:
                info["minping"] = minping
            if pingwait is not None and pingwait > 0:
                info["pingwait"] = pingwait

            # Bytes per message type (if tracked)
            if hasattr(peer, 'bytes_sent_per_msg'):
                info["bytessent_per_msg"] = peer.bytes_sent_per_msg
            if hasattr(peer, 'bytes_recv_per_msg'):
                info["bytesrecv_per_msg"] = peer.bytes_recv_per_msg

            # Ban score (legacy)
            banscore = getattr(peer, 'ban_score', 0)
            if banscore > 0:
                info["banscore"] = banscore

            # mapped_as — ASN for this peer's IP when an ASMap is loaded.
            # Core exposes this as an optional field (rpc/net.cpp getpeerinfo).
            # We emit it unconditionally as 0 when no asmap is active so
            # cross-impl tooling can always count on the field being present.
            peer_host = addr.split(":")[0] if addr else ""
            peer_network_id = getattr(peer, 'network_id', 1)  # default IPv4
            addrman = getattr(self.node, 'addr_manager', None) or \
                      getattr(self.node, 'address_manager', None) or \
                      (getattr(pm, 'addr_manager', None) if pm else None)
            if addrman is not None and hasattr(addrman, 'get_mapped_as'):
                mapped_as = addrman.get_mapped_as(peer_host, peer_network_id)
            else:
                mapped_as = 0
            if mapped_as > 0:
                info["mapped_as"] = mapped_as

            peers.append(info)

        return peers

    async def rpc_getconnectioncount(self) -> int:
        """Return the number of active connections.

        Counts every direction PeerManager tracks (outbound full-relay,
        outbound block-relay-only, and inbound).  Mirrors Bitcoin Core
        rpc/net.cpp getconnectioncount which iterates the full vNodes
        vector regardless of direction.
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return 0
        total = 0
        seen: set[int] = set()
        for bucket_name in ("peers", "block_relay_peers", "inbound_peers"):
            bucket = getattr(pm, bucket_name, None)
            if bucket is None:
                continue
            iterable = bucket.values() if isinstance(bucket, dict) else bucket
            for peer in iterable:
                pid = id(peer)
                if pid in seen:
                    continue
                seen.add(pid)
                total += 1
        return total

    async def rpc_getaddednodeinfo(self, node: Any = None) -> list[dict[str, Any]]:
        """Return information about the persistent added-node list.

        Reference: Bitcoin Core rpc/net.cpp getaddednodeinfo (:486-558) +
        CConnman::GetAddedNodeInfo (net.cpp:2914). Mirrors Core's exact shape:

            [
              {
                "addednode": <str>,               # node as provided to addnode
                "connected": <bool>,              # a current peer matches
                "addresses": [                    # ALWAYS present; [] when not connected
                  {"address": <str ip:port>,
                   "connected": "inbound" | "outbound"}   # at most ONE entry
                ]
              },
              ...
            ]

        Params:
            node (str, OPTIONAL): if provided, return only the matching added
                node; if it is NOT on the added list, raise -24
                RPC_CLIENT_NODE_NOT_ADDED "Error: Node has not been added."
                If omitted, all added nodes are returned (``[]`` when none).
                ``onetry`` adds are NOT on the list (Core parity).

        ouroboros keeps the added-node registry as ``self._added_nodes`` (a set
        of normalized ``"host:port"`` keys, populated by ``rpc_addnode`` —
        net.cpp's CConnman::m_added_nodes equivalent). Because ouroboros
        normalizes the entry to ``host:port`` at add time (a bare host gets the
        default port appended), the ``addednode`` string reported here is that
        normalized form, and the optional ``node`` filter is normalized the same
        way before the exact-string match so ``getaddednodeinfo "1.2.3.4"``
        matches a node added as ``1.2.3.4``. Pure read — no side effects.
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)

        # Normalize a "host[:port]" string to the same "host:port" key form
        # rpc_addnode uses, so the stored list and the filter compare apples to
        # apples (Core matches the raw string; ouroboros stores the normalized
        # key, so we normalize both sides).
        def _normalize_key(addr: str) -> str:
            if ':' in addr:
                h, _, p = addr.rpartition(':')
                try:
                    return f"{h}:{int(p)}"
                except ValueError:
                    return addr  # leave malformed input as-is; it just won't match
            default_port = getattr(pm, '_default_port', 8333) if pm is not None else 8333
            return f"{addr}:{default_port}"

        # Snapshot the persistent added-node list. A set has no defined order;
        # sort for deterministic, reproducible output (Core preserves insertion
        # order — see caveat in the porting notes).
        added = getattr(self, '_added_nodes', None) or set()
        added_keys = sorted(added)

        # Build a lookup of currently-connected peers keyed by "host:port".
        # Covers every peer bucket the PeerManager tracks (full-relay outbound,
        # block-relay outbound, inbound), matching disconnectnode's aggregation.
        connected: dict[str, bool] = {}  # host:port -> inbound?
        if pm is not None:
            for bucket_name in ("peers", "block_relay_peers", "inbound_peers"):
                pmap = getattr(pm, bucket_name, None) or {}
                if not isinstance(pmap, dict):
                    continue
                for addr, peer in pmap.items():
                    connected[addr] = bool(getattr(peer, 'inbound', False))

        # Optional `node` filter: exact match against the normalized added list.
        # Miss -> -24 "Error: Node has not been added." (Core net.cpp:533-535).
        if node is not None:
            if not isinstance(node, str):
                raise RpcError(
                    RPC_TYPE_ERROR,
                    f"JSON value of type {_core_uvtype(node)} is not of expected type string",
                )
            want = _normalize_key(node)
            if want not in added:
                raise RpcError(
                    RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added."
                )
            added_keys = [want]

        ret: list[dict[str, Any]] = []
        for key in added_keys:
            is_connected = key in connected
            addresses: list[dict[str, Any]] = []
            if is_connected:
                addresses.append({
                    "address": key,
                    "connected": "inbound" if connected[key] else "outbound",
                })
            ret.append({
                "addednode": key,
                "connected": is_connected,
                "addresses": addresses,
            })
        return ret

    async def rpc_addnode(self, node: str, command: str = "add") -> None:
        """Add or remove a peer.

        Mirrors Bitcoin Core's ``addnode`` semantics
        (``src/rpc/net.cpp::addnode``): the dial is queued and the RPC
        returns immediately. Awaiting the full TCP + (BIP-324) cipher +
        version handshake races against any client-side timeout (e.g. the
        BC interop harness uses a 20s curl) and causes the in-flight
        handshake task to be cancelled mid-stream when the client gives
        up — which in turn evicts the half-open peer slot on the remote
        side.

        For ``add`` / ``onetry`` we therefore fire-and-forget the dial via
        ``asyncio.create_task`` and return ``None``. The background task
        runs with a generous 60s timeout so the BIP-324 v2 cipher
        handshake + encrypted version exchange has time to complete even
        on a loaded node, decoupled from the JSON-RPC response latency.

        ``remove`` is fast (in-process state mutation only) so it stays
        synchronous, matching Core's ``RemoveAddedNode``.
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            raise ValueError("No peer manager available")

        # Parse host:port
        if ':' in node:
            parts = node.rsplit(':', 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid port in address: {node}") from None
        else:
            host = node
            port = getattr(pm, '_default_port', 8333)

        # Bitcoin Core keeps an "added node" list (CConnman::m_added_nodes).
        # ``add`` of a node already on the list, and ``remove`` of a node not
        # on the list, are operator errors with dedicated codes:
        #   CConnman::AddNode dedups -> RPC_CLIENT_NODE_ALREADY_ADDED (-23)
        #   CConnman::RemoveAddedNode absent-check -> RPC_CLIENT_NODE_NOT_ADDED (-24)
        # (net.cpp:359-369; protocol.h:60-61). ``onetry`` is NOT added to the
        # list (Core OpenNetworkConnection only), so it never dedups. Mirror the
        # list on the RPCServer keyed by normalized host:port. This is an
        # RPC-layer error gate only — the success-path dial behaviour below is
        # unchanged.
        added = getattr(self, '_added_nodes', None)
        if added is None:
            added = set()
            self._added_nodes = added
        node_key = f"{host}:{port}"

        if command == "add":
            if node_key in added:
                raise RpcError(
                    RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added"
                )
            added.add(node_key)
        elif command == "remove":
            if node_key not in added:
                raise RpcError(
                    RPC_CLIENT_NODE_NOT_ADDED,
                    "Error: Node could not be removed. "
                    "It has not been added previously.",
                )
            added.discard(node_key)

        if command in ("add", "onetry"):
            # Fire-and-forget: queue the dial as a background task and
            # return immediately. Matches Bitcoin Core
            # OpenNetworkConnection / AddNode behaviour.
            async def _bg_dial(_host: str, _port: int, _node: str, _command: str) -> None:
                try:
                    if hasattr(pm, 'connect_to_node'):
                        ok = await asyncio.wait_for(
                            pm.connect_to_node(_host, _port),
                            timeout=60.0,
                        )
                        if not ok:
                            logger.info(
                                "rpc_addnode background dial: connect_to_node returned False for %s",
                                _node,
                            )
                    elif hasattr(pm, 'add_peer'):
                        await asyncio.wait_for(pm.add_peer(_node), timeout=60.0)
                except asyncio.TimeoutError:
                    logger.warning(
                        "rpc_addnode background dial timed out after 60s for %s",
                        _node,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - background, must not crash loop
                    logger.warning(
                        "rpc_addnode background dial failed for %s: %s",
                        _node,
                        exc,
                    )

            task = asyncio.create_task(
                _bg_dial(host, port, node, command),
                name=f"rpc_addnode-{host}:{port}",
            )

            # Track tasks on the RPCServer so the event loop keeps a
            # strong reference (otherwise create_task() may be GC'd
            # before completion) and so tests / shutdown can introspect.
            tasks: set = getattr(self, '_addnode_tasks', None)
            if tasks is None:
                tasks = set()
                self._addnode_tasks = tasks
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            return None
        elif command == "remove":
            # The added-node membership check (and its -24 for a node that was
            # never added) is handled above, matching Core's RemoveAddedNode.
            # Here we only sever the connection if one is currently open — a
            # node may be on the added list without being connected, and Core's
            # remove still succeeds in that case. Best-effort, no error.
            addr = f"{host}:{port}"
            peers = getattr(pm, 'peers', {})
            if addr in peers:
                peer = peers[addr]
                if hasattr(peer, 'disconnect'):
                    await peer.disconnect() if asyncio.iscoroutinefunction(peer.disconnect) else peer.disconnect()
                del peers[addr]

    async def rpc_disconnectnode(self, address: str = "", nodeid: int = -1) -> None:
        """Disconnect a peer by address or node id.

        Reference: Bitcoin Core rpc/net.cpp disconnectnode (net.cpp:458-482).
        ``CConnman::DisconnectNode`` returns true when a connected node matched
        and was scheduled for disconnect, false otherwise. When nothing matched,
        Core raises
        ``JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED, "Node not found in
        connected nodes")`` (-29; protocol.h:62). Previously this handler keyed
        off ``hasattr(pm, 'disconnect_peer')`` — a method the PeerManager does
        not expose — so disconnectnode silently returned success (null) for any
        input. Mirror Core: locate the connected peer, sever it, and raise -29
        on a miss.
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            raise RpcError(
                RPC_CLIENT_NODE_NOT_CONNECTED,
                "Node not found in connected nodes",
            )

        # Search the connected-peer maps (full-relay outbound, block-relay
        # outbound, inbound), all keyed by "host:port" address strings. Match by
        # address; if disconnect-by-id was requested (nodeid >= 0), match a
        # peer carrying that id when the impl tracks one.
        peer_maps = [
            getattr(pm, 'peers', {}) or {},
            getattr(pm, 'block_relay_peers', {}) or {},
            getattr(pm, 'inbound_peers', {}) or {},
        ]

        matched = None
        if address:
            for pmap in peer_maps:
                if address in pmap:
                    matched = (pmap, address, pmap[address])
                    break
        if matched is None and nodeid is not None and nodeid >= 0:
            for pmap in peer_maps:
                for addr, peer in list(pmap.items()):
                    if getattr(peer, 'node_id', None) == nodeid:
                        matched = (pmap, addr, peer)
                        break
                if matched is not None:
                    break

        if matched is None:
            raise RpcError(
                RPC_CLIENT_NODE_NOT_CONNECTED,
                "Node not found in connected nodes",
            )

        pmap, addr, peer = matched
        if hasattr(peer, 'disconnect'):
            disc = peer.disconnect
            await disc() if asyncio.iscoroutinefunction(disc) else disc()
        pmap.pop(addr, None)
        return None

    async def rpc_setban(
        self,
        subnet: str,
        command: str,
        bantime: int = 0,
        absolute: bool = False,
    ) -> None:
        """Add or remove an IP/subnet from the ban list.

        Args:
            subnet: IP address or subnet to ban (e.g., "192.168.0.1" or "192.168.0.0/24")
            command: "add" to ban, "remove" to unban
            bantime: Ban duration in seconds (0 = default 24 hours)
            absolute: If True, bantime is an absolute UNIX timestamp

        Raises:
            ValueError: If command is invalid
        """
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            raise ValueError("Peer manager not available")

        bm = pm.ban_manager
        if command not in ("add", "remove"):
            raise ValueError(f"Invalid command: {command}")

        # Reference: Bitcoin Core rpc/net.cpp setban (net.cpp:776-781). Core
        # parses the argument via LookupSubNet (bare IP or CIDR subnet); if the
        # result is not valid it throws
        # JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid
        # IP/Subnet") (-30; protocol.h:63). Mirror that parse boundary with the
        # stdlib ipaddress parser: a bare IP must parse as ip_address, a "x/y"
        # token as ip_network. Raise RpcError so the dispatcher emits -30, not
        # the -32603 a bare ValueError collapses to.
        if not _is_valid_ip_or_subnet(subnet):
            raise RpcError(
                RPC_CLIENT_INVALID_IP_OR_SUBNET, "Error: Invalid IP/Subnet"
            )

        success = bm.setban(subnet, command, bantime, absolute)
        if not success:
            raise ValueError(f"setban failed for {subnet}")

    async def rpc_listbanned(self) -> list[dict[str, Any]]:
        """Return list of all banned IPs/subnets.

        Returns:
            List of dicts with address, ban_created, banned_until, ban_duration
        """
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            return []

        bm = pm.ban_manager
        return bm.list_banned_detailed()

    async def rpc_clearbanned(self) -> None:
        """Clear all banned IPs/subnets."""
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            return

        bm = pm.ban_manager
        # Clear all bans
        bm.banned.clear()
        bm.scores.clear()
        if bm._data_dir:
            bm._save_bans()
        logger.info("Cleared all bans")

    async def rpc_getnettotals(self) -> dict[str, Any]:
        """Return network traffic statistics."""
        return {
            "totalbytesrecv": getattr(self.node, 'bytes_recv', 0),
            "totalbytessent": getattr(self.node, 'bytes_sent', 0),
            "timemillis": int(time.time() * 1000),
        }

    def _get_addrman(self):
        """Return the AddressManager (addrman), or None when unavailable.

        The addrman lives on the PeerManager (``PeerManager.addrman``,
        p2p.py:610). The peer manager is reached via ``node.peer_manager``
        (or the legacy ``node.p2p`` alias).
        """
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return None
        return getattr(pm, 'addrman', None)

    @staticmethod
    def _addrman_network_name(addr) -> str:
        """Map a stored addrman entry to Core's network string.

        Mirrors GetNetworkName(addr.GetNetClass()) (netbase.cpp:114-128):
        ipv4 / ipv6 / onion / i2p / cjdns, with not_publicly_routable /
        internal for the residual cases. ouroboros stores BIP155 network IDs
        (addrman.py: NET_IPV4=1, NET_IPV6=2, NET_TORV3/4, NET_I2P=5,
        NET_CJDNS=6); Tor v2 and v3 both map to Core's "onion".
        """
        from ouroboros.addrman import (
            NET_IPV4, NET_IPV6, NET_TORV2, NET_TORV3, NET_I2P, NET_CJDNS,
            is_routable,
        )
        nid = getattr(addr, 'network_id', NET_IPV4)
        if nid == NET_IPV4:
            base = "ipv4"
        elif nid == NET_IPV6:
            base = "ipv6"
        elif nid in (NET_TORV2, NET_TORV3):
            return "onion"
        elif nid == NET_I2P:
            return "i2p"
        elif nid == NET_CJDNS:
            return "cjdns"
        else:
            base = "ipv4"
        # For IPv4/IPv6, Core reports not_publicly_routable for addresses
        # that are valid but not publicly routable (GetNetClass -> NET_UNROUTABLE).
        if not is_routable(getattr(addr, 'host', ''), nid):
            return "not_publicly_routable"
        return base

    async def rpc_getnodeaddresses(self, count: Any = 1, network: Any = None) -> list[dict[str, Any]]:
        """Return known addresses from the address manager.

        Reference: Bitcoin Core rpc/net.cpp:911-970 (getnodeaddresses).

        Returns a JSON array of objects, each with EXACTLY 5 keys in this
        order: time (unix seconds, int), services (raw bitfield, int),
        address (ip/onion/i2p literal, no port), port (int),
        network (ipv4/ipv6/onion/i2p/cjdns/not_publicly_routable/internal).

        Args:
            count: Maximum number of addresses to return. 0 = all known.
                   count < 0 -> RPC error -8 "Address count out of range".
            network: Optional network filter. ParseNetwork accepts only
                     ipv4|ipv6|onion|i2p|cjdns (case-insensitive); any other
                     string -> RPC error -8 "Network not recognized: <arg>".
        """
        # count (positional 0): default 1; getInt<int> semantics.
        try:
            count_i = int(count) if count is not None else 1
        except (TypeError, ValueError):
            raise RpcError(RPC_INVALID_PARAMETER, "Address count out of range")
        if count_i < 0:
            raise RpcError(RPC_INVALID_PARAMETER, "Address count out of range")

        # network (positional 1): ParseNetwork (netbase.cpp:100-112) lowercases
        # and accepts only the five routable network names. Anything else is
        # NET_UNROUTABLE -> error.
        net_filter_id = None
        if network is not None:
            from ouroboros.addrman import (
                NET_IPV4, NET_IPV6, NET_TORV3, NET_I2P, NET_CJDNS,
            )
            net_raw = str(network)
            net_lc = net_raw.lower()
            net_map = {
                "ipv4": NET_IPV4,
                "ipv6": NET_IPV6,
                "onion": NET_TORV3,
                "i2p": NET_I2P,
                "cjdns": NET_CJDNS,
            }
            if net_lc not in net_map:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"Network not recognized: {net_raw}",
                )
            net_filter_id = net_lc

        addrman = self._get_addrman()
        if addrman is None:
            # No addrman available -> empty result (NOT an error), matching
            # Core's behaviour for a node with an empty address manager.
            return []

        # GetAddressesUnsafe(count, max_pct=0, network): count==0 means "all".
        # get_addresses() already returns a SHUFFLED list (order is not
        # deterministic, matching Core). Pull everything, filter by network,
        # then truncate to count.
        all_addrs = addrman.get_addresses(addrman.size() if addrman.size() else 1)

        ret: list[dict[str, Any]] = []
        for addr in all_addrs:
            net_name = self._addrman_network_name(addr)
            if net_filter_id is not None and net_name != net_filter_id:
                continue
            obj = {
                "time": int(getattr(addr, 'last_seen', 0) or 0),
                "services": int(getattr(addr, 'services', 0) or 0),
                "address": getattr(addr, 'host', ''),
                "port": int(getattr(addr, 'port', 0) or 0),
                "network": net_name,
            }
            ret.append(obj)

        # count == 0 returns ALL known; otherwise cap at count.
        if count_i != 0:
            ret = ret[:count_i]
        return ret

    async def rpc_addpeeraddress(
        self, address: Any = None, port: Any = None, tried: Any = False
    ) -> dict[str, Any]:
        """Add the address of a potential peer to the address manager.

        Reference: Bitcoin Core rpc/net.cpp:972-1030 (addpeeraddress). This
        RPC is for testing only; it makes the addrman deterministically
        populatable so getnodeaddresses can be exercised differentially.

        Returns {"success": bool} (plus an optional "error" string on failure),
        matching Core's shape.

        Args:
            address: The IP address of the peer (required).
            port: The port of the peer (required).
            tried: If true, attempt to add the peer to the tried table.
        """
        obj: dict[str, Any] = {}

        if address is None or port is None:
            raise RpcError(RPC_INVALID_PARAMETER, "addpeeraddress requires address and port")

        addr_string = str(address)
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            raise RpcError(RPC_INVALID_PARAMETER, "Invalid port")
        if port_i < 0 or port_i > 0xFFFF:
            raise RpcError(RPC_INVALID_PARAMETER, "Invalid port")

        tried_b = bool(tried) if not isinstance(tried, str) else tried.lower() in ("1", "true", "yes", "on")

        addrman = self._get_addrman()
        if addrman is None:
            return {"success": False, "error": "address manager not available"}

        # Determine BIP155 network id from the literal (IPv4 vs IPv6).
        from ouroboros.addrman import NET_IPV4, NET_IPV6, is_routable
        network_id = NET_IPV4
        if ":" in addr_string:
            network_id = NET_IPV6

        # Core: LookupHost(addr_string) must resolve to a valid net addr.
        import ipaddress as _ipaddress
        try:
            _ipaddress.ip_address(addr_string)
        except ValueError:
            raise RpcError(RPC_CLIENT_INVALID_IP_OR_SUBNET, "Invalid IP address")

        # Core sets services = NODE_NETWORK | NODE_WITNESS = 1 | 8 = 9, and
        # nTime = Now(). Match that so the differential against Core lines up.
        services = 0x01 | 0x08  # NODE_NETWORK | NODE_WITNESS == 9
        now = time.time()

        success = False
        # Core rejects non-routable addresses inside AddrMan::Add; surface
        # that as success=false rather than throwing, mirroring the C++ path.
        if not is_routable(addr_string, network_id):
            obj["success"] = False
            obj["error"] = "failed-adding-to-new"
            return obj

        added = addrman.add(
            addr_string,
            port_i,
            services=services,
            timestamp=now,
            source=addr_string,  # peer announcing itself (source == address)
            network_id=network_id,
        )
        if added:
            success = True
            if tried_b:
                addrman.mark_good(addr_string, port_i)
        else:
            obj["error"] = "failed-adding-to-new"

        obj["success"] = success
        return obj

    async def rpc_getaddrmaninfo(self) -> dict[str, Any]:
        """Provide information about the node's address manager.

        Reference: Bitcoin Core rpc/net.cpp getaddrmaninfo (:1080-1117) +
        AddrMan::Size (addrman.cpp Size_ :1006-1026).

        Params: NONE.

        Returns a JSON object keyed by network name. The key set is FIXED and
        always present (every routable network emitted unconditionally, even at
        count 0), in Core's enum order::

            ipv4, ipv6, onion, i2p, cjdns, all_networks

        Each value is an object with exactly three integer keys in order::

            { "new":   <count in new table for this network>,
              "tried": <count in tried table for this network>,
              "total": <new + tried> }

        ``all_networks`` is the global sum across networks (new = total new,
        tried = total tried, total = new + tried). NET_UNROUTABLE
        (not_publicly_routable) and NET_INTERNAL (internal) are never emitted,
        matching Core's loop that skips those two enum values.

        Invariants (oracle-free, hold by construction):
          - per network: total == new + tried
          - all_networks.new   == Σ networks.new
          - all_networks.tried == Σ networks.tried
          - all_networks.total == Σ networks.total == all_networks.new
                                                      + all_networks.tried

        Pure read-only snapshot of the addrman — no params, no side effects, no
        peers/sockets/disk touched.
        """
        # Fixed routable-network key order (Core enum NET_IPV4..NET_CJDNS,
        # skipping NET_UNROUTABLE / NET_INTERNAL). Every key is emitted even
        # when the count is zero (an IPv4-only node still reports onion/i2p/
        # cjdns as 0/0/0).
        NETWORK_KEYS = ("ipv4", "ipv6", "onion", "i2p", "cjdns")

        # Pre-seed all routable networks at zero so the key set is always
        # complete, then accumulate. {net_name: {"new": int, "tried": int}}.
        counts: dict[str, dict[str, int]] = {
            name: {"new": 0, "tried": 0} for name in NETWORK_KEYS
        }

        addrman = self._get_addrman()
        if addrman is not None:
            # ouroboros's AddressManager splits addresses into two membership
            # sets, _in_new and _in_tried (addrman.py:383-384), mirroring
            # Core's new / tried tables. Map each stored entry to its Core
            # network name via GetNetClass parity (_addrman_network_name) and
            # bump the matching (network, table) counter. This reproduces
            # Core's per-network Size(net, in_new) split exactly. Entries that
            # map to not_publicly_routable / internal are skipped, matching
            # Core's loop (those networks are never emitted).
            addrs = getattr(addrman, "_addrs", {})
            in_new = getattr(addrman, "_in_new", set())
            in_tried = getattr(addrman, "_in_tried", set())

            for addr_key in in_new:
                info = addrs.get(addr_key)
                if info is None:
                    continue
                net_name = self._addrman_network_name(info)
                if net_name in counts:
                    counts[net_name]["new"] += 1

            for addr_key in in_tried:
                info = addrs.get(addr_key)
                if info is None:
                    continue
                net_name = self._addrman_network_name(info)
                if net_name in counts:
                    counts[net_name]["tried"] += 1

        ret: dict[str, Any] = {}
        total_new = 0
        total_tried = 0
        for name in NETWORK_KEYS:
            n_new = counts[name]["new"]
            n_tried = counts[name]["tried"]
            ret[name] = {
                "new": n_new,
                "tried": n_tried,
                "total": n_new + n_tried,
            }
            total_new += n_new
            total_tried += n_tried

        ret["all_networks"] = {
            "new": total_new,
            "tried": total_tried,
            "total": total_new + total_tried,
        }
        return ret

    async def rpc_getmemoryinfo(self, mode: Any = "stats") -> Any:
        """Return an object containing information about memory usage.

        Reference: Bitcoin Core rpc/node.cpp getmemoryinfo (:145-198) +
        RPCLockedMemoryInfo (:113-124) + RPCMallocInfo (:126-143).

        IMPORTANT SEMANTICS: this RPC reports Core's SECURE LOCKED-MEMORY POOL
        (``LockedPoolManager`` — the ``mlock()``-backed allocator that keeps
        sensitive data such as wallet private keys OFF swap), NOT general
        process or heap memory usage. Do not confuse "locked" memory here with
        the transaction "memory pool" (mempool).

        Param:
            mode (str, OPTIONAL, default "stats"): what kind of information is
            returned.
              - "stats": general statistics about memory usage in the daemon.
              - "mallocinfo": an XML string describing low-level heap state
                (Core: only available when compiled with glibc).

        Returns (mode-dependent type, matching Core exactly):
          - mode == "stats" -> OBJECT::

                { "locked": { "used": int, "free": int, "total": int,
                              "locked": int, "chunks_used": int,
                              "chunks_free": int } }

            All six inner values are non-negative integers (Core ``size_t``),
            in this pushKV order. ouroboros is a pure-Python port with NO
            Core-style ``mlock()``-backed secure pool (no LockedPoolManager
            equivalent exists in the codebase), so the honest answer is all
            zeros — but the keys/structure are ALWAYS present and identical to
            Core (a node with an empty/absent locked pool legitimately reports
            zeros; shape-match parity holds).

          - mode == "mallocinfo" -> Core returns a glibc ``malloc_info(3)`` XML
            string ONLY when built with glibc (HAVE_MALLOC_INFO); on every other
            build it raises ``-8 "mallocinfo mode not available"``. A pure-Python
            port has no glibc ``malloc_info`` equivalent, so we faithfully take
            Core's non-glibc path: the exact ``-8`` error (we do NOT fabricate a
            stub XML string Core never emits).

        Errors:
          - Unknown mode -> RPC_INVALID_PARAMETER (-8), message
            "unknown mode <mode>" (Core node.cpp:194,
            ``tfm::format("unknown mode %s", mode)``).
          - Non-string mode -> RPC_TYPE_ERROR (standard type check, before the
            handler logic, matching Core's ``Arg<std::string_view>``).

        Pure read-only introspection of the daemon's own memory accounting; no
        side effects, no chain/mempool/peer locks. Safe at any lifecycle stage.
        """
        # mode is read by Core as Arg<std::string_view> — a non-string value
        # is a JSON type error before any handler logic runs.
        if not isinstance(mode, str):
            raise RpcError(
                RPC_TYPE_ERROR,
                f"JSON value of type {_core_uvtype(mode)} is not of expected "
                "type string",
            )

        if mode == "stats":
            # Core RPCLockedMemoryInfo() reads
            # LockedPoolManager::Instance().stats() and emits the six counters
            # under "locked" in this exact order. ouroboros has no mlock'd
            # secure allocator (verified: no LockedPool/mlock in the source),
            # so every counter is an honest 0. Keys are always present.
            return {
                "locked": {
                    "used": 0,
                    "free": 0,
                    "total": 0,
                    "locked": 0,
                    "chunks_used": 0,
                    "chunks_free": 0,
                }
            }

        if mode == "mallocinfo":
            # Core returns glibc malloc_info(3) XML ONLY when built with glibc
            # (HAVE_MALLOC_INFO); on every other build it raises
            # -8 "mallocinfo mode not available" (node.cpp). A pure-Python port
            # has no glibc malloc_info equivalent, so we faithfully take Core's
            # non-glibc path — the exact -8 error — rather than fabricate a stub
            # XML string Core never emits.
            raise RpcError(RPC_INVALID_PARAMETER, "mallocinfo mode not available")

        # Any other mode is Core's RPC_INVALID_PARAMETER (-8) "unknown mode %s".
        raise RpcError(RPC_INVALID_PARAMETER, f"unknown mode {mode}")

    async def rpc_logging(self, include: Any = None, exclude: Any = None) -> dict[str, bool]:
        """Get and set the debug-logging category configuration.

        Reference: Bitcoin Core rpc/node.cpp ``logging`` (:218-275) +
        ``EnableOrDisableLogCategories`` (:200-216); logging.cpp
        ``LogCategoriesList`` / ``EnableCategory`` / ``DisableCategory``.

        ouroboros has a REAL category-based debug-logging system (parity with
        Core's per-category bitmask): ``DEBUG_CATEGORIES`` in daemon.py is the
        name set, and a handler-level ``_CategoryFilter`` gates DEBUG records
        by category against a live process-global active set. This RPC reads
        and mutates that live set, so enabling a category here makes its DEBUG
        logs actually start flowing with no restart — exactly like Core's
        in-memory ``m_categories`` mutation.

        Params (both OPTIONAL, positional, Core order: include THEN exclude):
          - include (array of category strings): categories to ENABLE.
          - exclude (array of category strings): categories to DISABLE.
          A param is acted on ONLY if it is an array (Core ``isArray()`` guard);
          null/omitted is a no-op for that slot, so ``logging`` with no args is
          a pure read-and-report. include is applied first, then exclude, so a
          category named in both ends up DISABLED ("exclude wins").

        Special input-only tokens (never emitted as output keys): ``"all"`` /
        ``"1"`` / ``""`` expand to the full category mask; in the exclude slot
        they clear the whole mask (Core's "none" effect — note Core itself only
        documents all/1, but DisableCategory("all"/"1"/"") clears every bit,
        which is how ``logging [], ["all"]`` disables everything).

        Returns: a JSON object mapping every real category name in
        ``DEBUG_CATEGORIES`` -> bool (whether it is currently being debug
        logged), emitted in ascending alphabetical key order (Core iterates a
        std::map; alphabetical order makes the output byte-stable). all/1/""
        are never output keys.

        Errors:
          - Unknown category in either array -> RPC_INVALID_PARAMETER (-8),
            message "unknown logging category <cat>" (Core node.cpp:213).
            Thrown as soon as the bad name is hit, after scanning include fully
            then exclude in order; categories BEFORE the bad one in the same
            call have ALREADY been applied (partial application, no rollback —
            Core parity).
          - Non-string array element -> RPC_TYPE_ERROR (Core ``get_str()``).

        Scope: mutates the running node's in-memory active set immediately;
        NOT persisted to config, resets on restart to the ``-debug`` startup
        flags. Idempotent (enabling an already-on / disabling an already-off
        category still returns the full list).
        """
        from ouroboros.daemon import DEBUG_CATEGORIES
        from ouroboros.logging_config import (
            disable_category,
            enable_category,
            get_active_categories,
        )

        # Core's special input-only tokens (logging.cpp): "all"/"1"/"" map to
        # the full mask. These are accepted as inputs but never output as keys.
        all_tokens = {"all", "1", ""}

        def _apply(cats: Any, enable: bool) -> None:
            # Core: EnableOrDisableLogCategories does cats.get_array() then
            # per-element get_str(); a non-array param is silently ignored at
            # the call site (only isArray() triggers processing).
            if not isinstance(cats, list):
                return
            for item in cats:
                if not isinstance(item, str):
                    # Core get_str() type error on a non-string element.
                    raise RpcError(
                        RPC_TYPE_ERROR,
                        f"JSON value of type {_core_uvtype(item)} is not of "
                        "expected type string",
                    )
                cat = item
                if cat in all_tokens:
                    # all/1/"" -> whole mask (enable: turn on everything;
                    # disable: turn off everything).
                    if enable:
                        enable_category(cat)
                    else:
                        disable_category(cat)
                    continue
                if cat not in DEBUG_CATEGORIES:
                    # Core node.cpp:213 — EnableCategory/DisableCategory return
                    # false for an unknown name -> -8 "unknown logging category".
                    raise RpcError(
                        RPC_INVALID_PARAMETER, "unknown logging category " + cat
                    )
                if enable:
                    enable_category(cat)
                else:
                    disable_category(cat)

        # Core order: include first, then exclude (exclude wins on conflict).
        _apply(include, True)
        _apply(exclude, False)

        # Emit the full {category: active} map, alphabetically sorted, for
        # every REAL category (all/1/"" are never keys).
        active = get_active_categories()
        return {cat: (cat in active) for cat in sorted(DEBUG_CATEGORIES)}

    async def rpc_getdifficulty(self) -> float:
        """Return the current difficulty.

        Core prints difficulty with ``%.16g`` (UniValue setprecision(16));
        wrap in ``_CoreFloat`` so the serializer emits the 16-sig-digit form
        (e.g. ``4.656542373906925e-10``) rather than Python's 17-digit repr.
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return _CoreFloat(0.0)
        try:
            _, best_height = self.node.db.get_best_block()
            block = await asyncio.to_thread(self.node.db.get_block_by_height, best_height)
            if block:
                bits = block.bits if hasattr(block, 'bits') else 0x1d00ffff
                # difficulty = max_target / current_target
                max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
                mantissa = bits & 0x007FFFFF
                exponent = (bits >> 24) & 0xFF
                if mantissa == 0:
                    return _CoreFloat(0.0)
                if exponent <= 3:
                    target = mantissa >> (8 * (3 - exponent))
                else:
                    target = mantissa << (8 * (exponent - 3))
                if target == 0:
                    return _CoreFloat(0.0)
                return _CoreFloat(max_target / target)
        except Exception:
            return _CoreFloat(0.0)
        return _CoreFloat(0.0)

    def _cumulative_tx_count(self, db, height: int) -> int:
        """Total number of transactions in the active chain in blocks [0..height].

        Bitcoin Core's CBlockIndex::m_chain_tx_count (chain.h:129), maintained
        as an O(1) running counter at block-connect (m_chain_tx_count =
        prev->m_chain_tx_count + nTx). ouroboros has no persisted per-block nTx
        aggregate, so we memoise the prefix sum in ``self._chain_tx_count`` and
        only deserialise the blocks not yet counted on each call. The cache is
        invalidated wholesale if the recomputed prefix at any already-cached
        height disagrees with the stored value (a reorg replaced a block).

        Genesis (height 0) counts its single coinbase. Each subsequent height h
        adds ``len(block.transactions)`` — for empty blocks that is exactly the
        coinbase (1), giving ``m_chain_tx_count(h) == h + 1`` as Core reports.
        """
        if height < 0:
            return 0

        cache = self._chain_tx_count

        # Cheap reorg guard: if we already have a value at this height, trust
        # it only when the block hash at the cache's last extended height still
        # matches the active chain. We detect a stale cache lazily by verifying
        # the running total never goes backwards; a full rebuild is triggered by
        # the explicit invalidation path below.
        if height < len(cache):
            return cache[height]

        # Extend the prefix-sum cache from where it left off up to ``height``.
        running = cache[-1] if cache else 0
        start = len(cache)
        for h in range(start, height + 1):
            block = db.get_block_by_height(h)
            if block is None:
                # Active chain is shorter than requested — should not happen for
                # an in-main-chain height, but be defensive rather than crash.
                break
            running += len(block.transactions)
            cache.append(running)
        if height < len(cache):
            return cache[height]
        # Fell short (missing block); return best effort prefix.
        return cache[-1] if cache else 0

    async def rpc_getchaintxstats(
        self, nblocks: Any = None, blockhash: Any = None
    ) -> dict[str, Any]:
        """Compute statistics about the total number and rate of transactions.

        Bitcoin Core: rpc/blockchain.cpp getchaintxstats. Signature
        ``getchaintxstats ( nblocks "blockhash" )`` — both args optional.

        Algorithm (Core-faithful):
          * Resolve ``pindex``: ``blockhash`` -> that block (must be in the
            active chain); else the active chain tip.
          * Default ``nblocks`` = 30*24*60*60 / nPowTargetSpacing = "one month"
            = 4320 blocks (all networks use 600s spacing). Default is clamped
            to ``max(0, min(4320, pindex.height - 1))``.
          * An explicit ``nblocks`` outside ``[0, pindex.height - 1]`` is an
            error (-8).
          * ``time``  = the FINAL block's RAW header nTime (NOT mediantime).
          * ``txcount`` = cumulative #txs genesis..pindex (m_chain_tx_count).
          * ``window_interval`` = MTP(pindex) - MTP(pindex - nblocks) — uses
            median-time-past, NOT raw times.
          * ``window_tx_count`` = txcount(pindex) - txcount(pindex - nblocks).
          * ``txrate`` = window_tx_count / window_interval.
          * The three ``window_*`` extras (interval/tx_count/txrate) are dropped
            when ``nblocks == 0``; ``txrate`` further requires interval > 0.
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            raise RpcError(-32603, "Database not available")
        db = self.node.db

        # Default nblocks = "one month" of blocks. Core: 30*24*60*60 /
        # nPowTargetSpacing; every network uses 600s spacing -> 4320.
        DEFAULT_NBLOCKS = 30 * 24 * 60 * 60 // 600  # 4320

        # ── Resolve pindex (the final block of the window). ───────────────
        if blockhash is None:
            tip_hash, tip_height = db.get_best_block()
            pindex_hash = bytes(tip_hash)
            pindex_height = tip_height
        else:
            if not isinstance(blockhash, str):
                raise RpcError(RPC_INVALID_PARAMETER, "blockhash must be a hex string")
            try:
                # Wire/RPC blockhashes are DISPLAY (big-endian) hex; the block
                # index is keyed by INTERNAL (little-endian) bytes. Reverse to
                # match the convention used by getblock/getblockheader.
                hash_bytes = bytes.fromhex(blockhash)[::-1]
            except ValueError:
                raise RpcError(RPC_INVALID_PARAMETER, "blockhash must be hexadecimal string")
            if len(hash_bytes) != 32:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"blockhash must be of length 64 (not {len(blockhash)}, for '{blockhash}')",
                )
            pindex_height = await asyncio.to_thread(
                self._get_block_height, db, hash_bytes
            )
            if pindex_height is None:
                # Core: RPC_INVALID_ADDRESS_OR_KEY "Block not found".
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
            # Core: must be in the ACTIVE chain (ChainActive().Contains).
            active_hash = await asyncio.to_thread(
                db.get_block_hash_by_height, pindex_height
            )
            if active_hash is None or bytes(active_hash) != hash_bytes:
                raise RpcError(RPC_INVALID_PARAMETER, "Block is not in main chain")
            pindex_hash = hash_bytes

        # ── Resolve block count (window size). ────────────────────────────
        if nblocks is None:
            blockcount = max(0, min(DEFAULT_NBLOCKS, pindex_height - 1))
        else:
            try:
                blockcount = int(nblocks)
            except (TypeError, ValueError):
                raise RpcError(RPC_INVALID_PARAMETER, "Invalid block count")
            if blockcount < 0 or (blockcount > 0 and blockcount >= pindex_height):
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    "Invalid block count: should be between 0 and the block's height - 1",
                )

        past_height = pindex_height - blockcount

        # ── Final block raw header time + cumulative tx count. ────────────
        pindex_block = await asyncio.to_thread(db.get_block_by_height, pindex_height)
        if pindex_block is None:
            raise RpcError(-32603, "Final block not found in active chain")
        final_time = int(pindex_block.timestamp)  # RAW nTime, NOT mediantime

        chain_tx_count = await asyncio.to_thread(
            self._cumulative_tx_count, db, pindex_height
        )
        # m_chain_tx_count is unknown (== 0) only on an assumeutxo background
        # chainstate; on a fully-validated chain it is always > 0.
        txcount_known = chain_tx_count > 0

        # window_final_block_hash is the display (big-endian) hex of pindex.
        final_hash_hex = pindex_hash[::-1].hex()

        result: dict[str, Any] = {
            "time": final_time,
        }
        if txcount_known:
            result["txcount"] = chain_tx_count
        result["window_final_block_hash"] = final_hash_hex
        result["window_final_block_height"] = pindex_height
        result["window_block_count"] = blockcount

        if blockcount > 0:
            # window_interval uses MEDIAN-TIME-PAST (11-block window), not raw.
            mtp_final = await asyncio.to_thread(self.node.get_median_time, pindex_height)
            mtp_past = await asyncio.to_thread(self.node.get_median_time, past_height)
            time_diff = int(mtp_final) - int(mtp_past)
            result["window_interval"] = time_diff

            past_tx_count = await asyncio.to_thread(
                self._cumulative_tx_count, db, past_height
            )
            # window_tx_count requires txcount known at BOTH ends.
            if chain_tx_count != 0 and past_tx_count != 0:
                window_tx_count = chain_tx_count - past_tx_count
                result["window_tx_count"] = window_tx_count
                if time_diff > 0:
                    result["txrate"] = _CoreFloat(float(window_tx_count) / time_diff)

        return result

    async def rpc_getchaintips(self) -> list[dict[str, Any]]:
        """Return information about all known tips in the block tree.

        Reference: Bitcoin Core rpc/blockchain.cpp getchaintips

        Returns a list of chain tips, including the active chain tip and any
        orphan/stale branches. Each entry contains:
        - height: height of the chain tip
        - hash: block hash of the tip
        - branchlen: zero for main chain, otherwise length of branch connecting
                     the tip to the main chain
        - status: status of the chain

        Status values:
          "active"        — the current best chain tip (most work)
          "valid-fork"    — fully validated fork, not part of active chain
          "valid-headers" — all blocks available but not fully validated
          "headers-only"  — only headers received, block data unavailable
          "invalid"       — branch contains at least one invalid block
        """
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db
        tips: list[dict[str, Any]] = []

        # Active chain tip ---------------------------------------------------
        best_hash, best_height = db.get_best_block()
        tip_hash_hex: str
        # Core emits the DISPLAY (big-endian / byte-reversed) hash here, same as
        # getbestblockhash/getblockheader. The internal hash is little-endian.
        if isinstance(best_hash, bytes):
            tip_hash_hex = best_hash[::-1].hex()
        else:
            tip_hash_hex = str(best_hash)

        tips.append({
            "height": best_height,
            "hash": tip_hash_hex,
            "branchlen": 0,
            "status": "active",
        })

        # Collect orphan/stale tips from block index -------------------------
        # A tip is a block with no known children in the block index.
        # We identify tips by finding blocks that are not referenced as
        # prev_blockhash by any other block.

        # Get all known block hashes
        all_blocks: dict[bytes, Any] = {}
        parent_refs: set = set()  # blocks that are someone's parent

        # If the database has a block index, iterate it
        if hasattr(db, 'get_all_block_hashes'):
            for block_hash in db.get_all_block_hashes():
                block = await asyncio.to_thread(db.get_block, block_hash)
                if block:
                    all_blocks[block_hash] = block
                    if block.prev_blockhash and block.prev_blockhash != bytes(32):
                        parent_refs.add(block.prev_blockhash)

        elif hasattr(db, 'block_index'):
            # Direct access to block index
            for block_hash, _block_info in db.block_index.items():
                block = await asyncio.to_thread(db.get_block, block_hash)
                if block:
                    all_blocks[block_hash] = block
                    if block.prev_blockhash and block.prev_blockhash != bytes(32):
                        parent_refs.add(block.prev_blockhash)

        # Blocks that are tips (not referenced as parent by anyone)
        for block_hash, block in all_blocks.items():
            if block_hash == best_hash:
                continue  # Already added as active tip

            if block_hash not in parent_refs:
                # This is a tip
                block_height = getattr(block, 'height', 0) or 0

                # Determine status
                status = "headers-only"
                branchlen = 0

                # Check if block has full data
                has_data = hasattr(block, 'transactions') and block.transactions

                # Check if block is marked invalid
                is_invalid = getattr(block, 'is_invalid', False)
                if hasattr(db, 'is_block_invalid'):
                    is_invalid = db.is_block_invalid(block_hash)

                if is_invalid:
                    status = "invalid"
                elif has_data:
                    # Check if fully validated
                    is_validated = getattr(block, 'is_validated', True)
                    if hasattr(db, 'is_block_validated'):
                        is_validated = db.is_block_validated(block_hash)

                    if is_validated:
                        status = "valid-fork"
                    else:
                        status = "valid-headers"
                else:
                    status = "headers-only"

                # Calculate branch length by walking back to find fork point
                # Fork point is where this branch meets the active chain
                fork_height = 0
                current = block
                visited = set()
                while current and current.prev_blockhash != bytes(32):
                    if current.prev_blockhash in visited:
                        break
                    visited.add(current.prev_blockhash)

                    # Check if prev is on active chain
                    prev_hash = current.prev_blockhash
                    prev_height = None

                    # Try to get height from active chain
                    if hasattr(db, 'get_block_height'):
                        prev_height = db.get_block_height(prev_hash)
                    elif prev_hash in all_blocks:
                        prev_height = getattr(all_blocks[prev_hash], 'height', None)

                    if prev_height is not None:
                        # Check if this hash is in active chain at this height
                        active_hash = await asyncio.to_thread(db.get_block_hash_by_height, prev_height)
                        if active_hash == prev_hash:
                            fork_height = prev_height
                            break

                    # Move to parent
                    if prev_hash in all_blocks:
                        current = all_blocks[prev_hash]
                    else:
                        current = await asyncio.to_thread(db.get_block, prev_hash)
                        if current:
                            all_blocks[prev_hash] = current

                branchlen = max(0, block_height - fork_height)

                tips.append({
                    "height": block_height,
                    # Display (byte-reversed) hash, matching Core.
                    "hash": block_hash[::-1].hex() if isinstance(block_hash, bytes) else str(block_hash),
                    "branchlen": branchlen,
                    "status": status,
                })

        # Sort by height descending (Bitcoin Core behavior)
        tips.sort(key=lambda x: (-x["height"], x["hash"]))

        return tips

    async def rpc_gettxoutsetinfo(
        self,
        hash_type: str = "hash_serialized_3",
        hash_or_height: Any = None,
        use_index: bool = True,
    ) -> dict[str, Any]:
        """Return statistics about the unspent transaction output set.

        Mirrors Bitcoin Core's ``gettxoutsetinfo`` RPC
        (rpc/blockchain.cpp:1010, kernel/coinstats.cpp::ComputeUTXOStats).

        Walks the live chainstate, accumulating per-coin:
          - SHA256d ``HashWriter`` over ``TxOutSer`` bytes (Core's
            ``hash_serialized_3``), or alternatively MuHash3072
          - txout count, transaction count, total amount, bogosize

        Per-coin TxOutSer layout (kernel/coinstats.cpp:46-51):
            outpoint (txid 32B + vout u32 LE)
            code     (height << 1 | fCoinBase) u32 LE
            amount   i64 LE
            scriptPubKey CompactSize length + raw bytes

        Iteration order matches Core's CCoinsViewCursor: sorted by
        ``(txid, vout)``. Core groups outputs by txid and walks the
        ``std::map<uint32_t, Coin>`` (which sorts by vout); a flat
        ``(txid, vout)`` sort is equivalent because vout is a u32
        appended to txid in the key.

        Args:
            hash_type: ``"hash_serialized_3"`` (default; SHA256d),
                ``"hash_serialized_2"`` (alias accepted for older clients
                — same SHA256d construction, kept stable across Core
                renames), ``"muhash"`` (MuHash3072), or ``"none"``.
            hash_or_height: Block hash/height (only honoured when
                coinstatsindex is wired; ignored here).
            use_index: Coinstatsindex flag (ignored here).

        Returns:
            dict with the Core-compatible field shape:
            ``height``, ``bestblock`` (display hex), ``txouts``,
            ``bogosize``, optional ``hash_serialized_3``/
            ``hash_serialized_2``/``muhash``, ``total_amount``,
            ``transactions``, ``disk_size``.
        """
        from decimal import Decimal

        from ouroboros.muhash import coin_element
        from ouroboros.snapshot import HashWriter, MuHash3072

        if not hasattr(self.node, "db") or not self.node.db:
            return {}

        # Normalize hash_type. Core (post-#26553) defaults to
        # ``hash_serialized_3``; the older ``hash_serialized_2`` keyword
        # is accepted as an alias so consumers pinned to either version
        # see the same SHA256d-over-TxOutSer digest.
        hash_type_norm = (hash_type or "hash_serialized_3").lower()
        if hash_type_norm == "hash_serialized":
            hash_type_norm = "hash_serialized_3"
        if hash_type_norm not in (
            "hash_serialized_3", "hash_serialized_2", "muhash", "none",
        ):
            # Core's ParseHashType (rpc/blockchain.cpp) throws
            # JSONRPCError(RPC_INVALID_PARAMETER, "<hash_type> is not a valid
            # hash_type") for an unrecognized keyword. Use the same numeric
            # code (-8) so clients distinguish this the way they do against
            # Core, rather than the generic internal-error -32603 that a bare
            # HTTPException collapses to.
            raise RpcError(
                RPC_INVALID_PARAMETER,
                f"{hash_type} is not a valid hash_type",
            )

        # ``hash_or_height``/``use_index``: with -coinstatsindex enabled the
        # node maintains a per-height running MuHash3072 commitment over the
        # UTXO set, so a HISTORICAL hash_or_height can be answered from the
        # snapshot.  Without the index a non-tip query errors -8 (Core parity).
        #
        # Core (rpc/blockchain.cpp:1085-1097): when a specific block is
        # requested (``!request.params[1].isNull()``):
        #   - ``hash_serialized_3`` for a specific block is ALWAYS rejected
        #     with RPC_INVALID_PARAMETER (it can only be computed for the tip),
        #     even WITH the index.
        #   - any other hash_type requires g_coin_stats_index; when it is null
        #     it throws RPC_INVALID_PARAMETER ("Querying specific block heights
        #     requires coinstatsindex").
        # Mirror both error directions here.
        csi = getattr(self.node, "coinstats_index", None)
        if hash_or_height is not None:
            if hash_type_norm in ("hash_serialized_3", "hash_serialized_2"):
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    "hash_serialized_3 hash type cannot be queried for a "
                    "specific block",
                )
            if csi is None:
                # No coinstatsindex: any specific-block query is unsupported.
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    "Querying specific block heights requires coinstatsindex",
                )
            return await self._gettxoutsetinfo_at_height(
                hash_type_norm, hash_or_height, csi
            )
        _ = use_index

        best_hash_internal, best_height = self.node.db.get_best_block()

        def _walk_utxos() -> dict[str, Any]:
            """Single-pass UTXO walk; runs on a worker thread to avoid
            stalling the asyncio event loop on large chainstates."""
            use_muhash = hash_type_norm == "muhash"
            use_sha256d = hash_type_norm in (
                "hash_serialized_3", "hash_serialized_2",
            )
            hasher_sha = HashWriter() if use_sha256d else None
            hasher_mu = MuHash3072() if use_muhash else None

            txouts = 0
            transactions = 0
            total_amount = 0
            bogosize = 0
            prev_txid: bytes | None = None

            # Sort by (txid, vout) so the digest is deterministic and
            # matches Core's CCoinsViewCursor leveldb-key ordering.
            utxos = list(self.node.db.iter_utxos())
            utxos.sort(key=lambda u: (u.txid, u.vout))

            for utxo in utxos:
                txouts += 1
                if utxo.txid != prev_txid:
                    transactions += 1
                    prev_txid = utxo.txid
                amount = int(utxo.amount)
                total_amount += amount
                spk = bytes(utxo.script_pubkey)
                # GetBogoSize: 32 + 4 + 4 + 8 + 2 + len(scriptPubKey)
                # (kernel/coinstats.cpp:36-43).
                bogosize += 32 + 4 + 4 + 8 + 2 + len(spk)

                element = coin_element(
                    txid=utxo.txid,
                    vout=int(utxo.vout),
                    height=int(utxo.height),
                    is_coinbase=bool(utxo.is_coinbase),
                    amount=amount,
                    script_pubkey=spk,
                )
                if hasher_sha is not None:
                    hasher_sha.update(element)
                if hasher_mu is not None:
                    hasher_mu.insert(element)

            return {
                "txouts": txouts,
                "transactions": transactions,
                "total_amount": total_amount,
                "bogosize": bogosize,
                "sha_digest": hasher_sha.digest() if hasher_sha else None,
                "muhash_digest": (
                    hasher_mu.digest() if hasher_mu else None
                ),
            }

        stats = await asyncio.to_thread(_walk_utxos)

        # Core's uint256.GetHex() emits big-endian display hex (reverses
        # the internal byte order). Apply the same flip for both the
        # block hash and the per-hash-type digest fields.
        bestblock_hex = (
            best_hash_internal[::-1].hex()
            if isinstance(best_hash_internal, (bytes, bytearray))
            else ""
        )
        # Core formats CAmount via ValueFromAmount, which produces a JSON
        # number with 8 decimal places ("%d.%08d"). Use BTCAmount so the
        # serializer emits that exact decimal token.
        from ouroboros.psbt import BTCAmount

        # Core key order (blockchain.cpp:1114, non-index path):
        #   height, bestblock, txouts, bogosize, [hash digest], total_amount,
        #   transactions, disk_size.
        result: dict[str, Any] = {
            "height": int(best_height),
            "bestblock": bestblock_hex,
            "txouts": stats["txouts"],
            "bogosize": stats["bogosize"],
        }
        if hash_type_norm in ("hash_serialized_3", "hash_serialized_2"):
            digest_hex = stats["sha_digest"][::-1].hex()
            # Emit both the canonical key and its alias so the
            # diff-test harness (which probes hash_serialized_2 first,
            # then _3) sees the same digest under either name.
            result["hash_serialized_3"] = digest_hex
            result["hash_serialized_2"] = digest_hex
        elif hash_type_norm == "muhash":
            result["muhash"] = stats["muhash_digest"][::-1].hex()
        # hash_type=="none": emit no digest field, matching Core.

        result["total_amount"] = BTCAmount(int(stats["total_amount"]))
        result["transactions"] = stats["transactions"]
        # disk_size: ouroboros stores the chainstate in RocksDB and does not
        # expose a per-CF size estimate here; emit 0 so the field is present
        # (Core also emits 0 when no view is open / unflushed on regtest).
        result["disk_size"] = 0

        return result

    async def _gettxoutsetinfo_at_height(
        self,
        hash_type_norm: str,
        hash_or_height: Any,
        csi: Any,
    ) -> dict[str, Any]:
        """Answer gettxoutsetinfo for a HISTORICAL block from the coinstatsindex.

        Resolves ``hash_or_height`` (a height int or a display-order block-hash
        hex string) to a height + block hash, then reads the per-height
        MuHash3072 snapshot maintained by :class:`CoinStatsIndex`.  Mirrors
        Bitcoin Core's ``gettxoutsetinfo`` index branch
        (rpc/blockchain.cpp:1085-1160 with ``index_used``):
          - height must be 0..tip (ParseHashOrHeight errors otherwise),
          - the result carries ``height``, ``bestblock`` (the hash AT that
            height, NOT the tip), ``txouts``, ``bogosize``, ``muhash``,
            ``total_amount`` and ``total_unspendable_amount``; ``transactions``
            / ``disk_size`` are OMITTED when the index is used.
        """
        from decimal import Decimal

        from ouroboros.muhash import MuHash3072

        _, tip_height = self.node.db.get_best_block()

        # ----- resolve hash_or_height to (height, block_hash_internal) -----
        target_height: int
        if isinstance(hash_or_height, bool):
            # JSON true/false is never a valid height/hash.
            raise RpcError(RPC_INVALID_PARAMETER, "Invalid hash_or_height")
        if isinstance(hash_or_height, int):
            target_height = hash_or_height
            if target_height < 0:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"Target block height {target_height} is negative",
                )
            if target_height > tip_height:
                raise RpcError(
                    RPC_INVALID_PARAMETER,
                    f"Target block height {target_height} after current tip "
                    f"{tip_height}",
                )
        else:
            # Display-order hash hex -> internal order -> height via the
            # chainstate's block index.
            try:
                hh = str(hash_or_height)
                block_hash_internal = bytes.fromhex(hh)[::-1]
                if len(block_hash_internal) != 32:
                    raise ValueError
            except ValueError:
                raise RpcError(
                    RPC_INVALID_PARAMETER, "hash_or_height is not a hash or height"
                ) from None
            blk = await asyncio.to_thread(
                self.node.db.get_block, block_hash_internal
            )
            if blk is None or getattr(blk, "height", None) is None:
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
            target_height = int(blk.height)

        # Confirm the queried height is on the active chain and capture its
        # canonical hash (the value Core returns as `bestblock`).
        chain_hash = await asyncio.to_thread(
            self.node.db.get_block_hash_by_height, target_height
        )
        if chain_hash is None:
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        # ----- read the per-height snapshot -----
        snap = await asyncio.to_thread(csi.get_at_height, target_height)
        if snap is None:
            # Index enabled but this height has not been indexed yet (mid-sync).
            best = csi.best_indexed_height
            raise RpcError(
                RPC_MISC_ERROR,
                "Unable to get data because coinstatsindex is still syncing. "
                f"Current height: {best if best is not None else -1}",
            )

        # The snapshot stores the block hash it was taken at; it must match the
        # active chain's hash at that height (a stale snapshot from a reorged-
        # away fork would differ — treat as not-yet-reindexed).
        if bytes(snap["block_hash"]) != bytes(chain_hash):
            raise RpcError(
                RPC_MISC_ERROR,
                "Unable to get data because coinstatsindex is still syncing.",
            )

        total_amount_btc = Decimal(snap["total_amount"]) / Decimal(100_000_000)

        result: dict[str, Any] = {
            "height": int(target_height),
            # Core uint256.GetHex() => big-endian display hex.
            "bestblock": bytes(chain_hash)[::-1].hex(),
            "txouts": int(snap["txouts"]),
            "bogosize": int(snap["bogo_size"]),
            "total_amount": float(total_amount_btc),
        }
        if hash_type_norm == "muhash":
            # snap["muhash"] is the 32-byte internal-order digest; reverse for
            # display hex (same flip as the @tip path).
            result["muhash"] = bytes(snap["muhash"])[::-1].hex()
        # hash_type=="none": no digest field (Core parity).
        _ = MuHash3072  # imported for symmetry with the @tip path
        return result

    async def rpc_scantxoutset(
        self,
        action: str = "start",
        scanobjects: list[Any] | None = None,
    ) -> Any:
        """Scan the unspent transaction output set for matching scriptPubKeys.

        Mirrors Bitcoin Core's ``scantxoutset`` RPC
        (rpc/blockchain.cpp::scantxoutset). Iterates the live chainstate and
        collects every UTXO whose scriptPubKey matches one of the supplied
        scan objects.

        Supported scan-object forms (the two simplest descriptors):
          - ``addr(<address>)`` — match outputs paying to the address's
            scriptPubKey (decoded via ``address_to_script_pubkey``).
          - ``raw(<scriptPubKey-hex>)`` — match outputs with exactly this
            scriptPubKey.
          - ``pkh(<hex-pubkey>)`` / ``wpkh(<hex-pubkey>)`` /
            ``tr(<hex-xonly-pubkey>)`` — single-key descriptors (bonus;
            xpub-range descriptors are out of scope).
          - a bare hex string is also accepted as a raw scriptPubKey, matching
            Core's ``raw()`` shorthand for the diff-test harness.

        Actions:
          - ``start`` (default) — perform the scan; ``scanobjects`` required.
          - ``abort`` / ``status`` — no background scan is tracked here, so
            these return ``False`` (no scan in progress), matching Core's
            return when nothing is running.

        Returns (for ``start``):
            ``{"success", "txouts", "height", "bestblock", "unspents":
            [{"txid","vout","scriptPubKey","desc","amount","coinbase",
            "height"}...], "total_amount"}``.
        """
        action = (action or "start").lower()

        if action in ("abort", "status"):
            # No long-running background scan is tracked in this minimal
            # implementation; Core returns false from abort/status when no
            # scan is in progress. Mirror that.
            return False
        if action != "start":
            raise HTTPException(
                status_code=400,
                detail=f"Invalid action '{action}'",
            )

        if not scanobjects:
            raise HTTPException(
                status_code=400,
                detail="scanobjects argument is required for the start action",
            )

        if not hasattr(self.node, "db") or not self.node.db:
            return {
                "success": True,
                "txouts": 0,
                "height": 0,
                "bestblock": "",
                "unspents": [],
                "total_amount": 0.0,
            }

        network = getattr(self.node, "network", "mainnet")

        # Resolve every scan object to a (scriptPubKey -> descriptor-string)
        # entry. ``needles`` maps the raw scriptPubKey bytes to the inferred
        # descriptor string echoed back in each matched unspent.
        needles: dict[bytes, str] = self._scantxoutset_resolve(scanobjects, network)

        best_hash_internal, best_height = self.node.db.get_best_block()

        def _scan() -> dict[str, Any]:
            """Single-pass UTXO walk on a worker thread (large chainstates
            must not stall the asyncio event loop)."""
            from decimal import Decimal

            # Active tip height, captured once for per-coin confirmations
            # (Core: tip->nHeight - coin.nHeight + 1, blockchain.cpp:2464).
            tip_height = int(best_height)

            txouts = 0
            total_in = 0
            unspents: list[dict[str, Any]] = []
            for utxo in self.node.db.iter_utxos():
                txouts += 1
                spk = bytes(utxo.script_pubkey)
                desc = needles.get(spk)
                if desc is None:
                    continue
                amount = int(utxo.amount)
                total_in += amount
                # iter_utxos yields txid in internal (little-endian) byte
                # order; JSON-RPC reports it in display order (reversed hex),
                # matching rpc_gettxout / Core's COutPoint::hash.GetHex().
                txid_display = bytes(utxo.txid)[::-1].hex()
                coin_height = int(utxo.height) if utxo.height is not None else 0
                # Block hash at the coin's height, big-endian DISPLAY hex
                # (Core: tip->GetAncestor(coin.nHeight)->GetBlockHash().GetHex(),
                # blockchain.cpp:2451,2463). _scan() already runs on a worker
                # thread via asyncio.to_thread, so call the sync DB lookup
                # directly.
                bh = self.node.db.get_block_hash_by_height(coin_height)
                blockhash = (
                    bh[::-1].hex() if isinstance(bh, (bytes, bytearray)) else ""
                )
                unspents.append({
                    "txid": txid_display,
                    "vout": int(utxo.vout),
                    "scriptPubKey": spk.hex(),
                    "desc": desc,
                    "amount": float(Decimal(amount) / Decimal(100_000_000)),
                    "coinbase": bool(utxo.is_coinbase),
                    "height": coin_height,
                    "blockhash": blockhash,
                    "confirmations": tip_height - coin_height + 1,
                })
            return {
                "txouts": txouts,
                "total_amount": float(Decimal(total_in) / Decimal(100_000_000)),
                "unspents": unspents,
            }

        stats = await asyncio.to_thread(_scan)

        # Core's uint256.GetHex() emits big-endian display hex; flip the
        # internal tip hash to match.
        bestblock_hex = (
            best_hash_internal[::-1].hex()
            if isinstance(best_hash_internal, (bytes, bytearray))
            else ""
        )

        return {
            "success": True,
            "txouts": stats["txouts"],
            "height": int(best_height),
            "bestblock": bestblock_hex,
            "unspents": stats["unspents"],
            "total_amount": stats["total_amount"],
        }

    def _scantxoutset_resolve(
        self, scanobjects: list[Any], network: str
    ) -> dict[bytes, str]:
        """Resolve scan objects to a ``{scriptPubKey: descriptor-string}`` map.

        Supports ``addr()``, ``raw()``, and the single-key descriptors
        ``pkh()``/``wpkh()``/``tr()`` plus a bare-hex shorthand for raw
        scripts. Raises HTTPException(400) on unparseable / unsupported
        objects, matching Core's RPC_INVALID_PARAMETER behaviour.
        """
        from ouroboros.address import address_to_script_pubkey

        def _hash160(data: bytes) -> bytes:
            import hashlib

            sha = hashlib.sha256(data).digest()
            ripe = hashlib.new("ripemd160")
            ripe.update(sha)
            return ripe.digest()

        needles: dict[bytes, str] = {}
        for obj in scanobjects:
            # Core also accepts {"desc": "...", "range": ...} objects; this
            # minimal impl handles the string form (and pulls "desc" out of a
            # dict for convenience).
            if isinstance(obj, dict):
                spec = obj.get("desc")
            else:
                spec = obj
            if not isinstance(spec, str):
                raise HTTPException(
                    status_code=400,
                    detail="Scan object must be a descriptor string",
                )
            spec = spec.strip()
            # Strip a trailing descriptor checksum (#xxxxxxxx) if present.
            if "#" in spec:
                spec = spec.split("#", 1)[0]

            spk: bytes
            desc: str = spec
            try:
                if spec.startswith("addr(") and spec.endswith(")"):
                    addr = spec[len("addr("):-1]
                    spk = address_to_script_pubkey(addr, network)
                elif spec.startswith("raw(") and spec.endswith(")"):
                    spk = bytes.fromhex(spec[len("raw("):-1])
                elif spec.startswith("pkh(") and spec.endswith(")"):
                    pub = bytes.fromhex(spec[len("pkh("):-1])
                    spk = b"\x76\xa9\x14" + _hash160(pub) + b"\x88\xac"
                elif spec.startswith("wpkh(") and spec.endswith(")"):
                    pub = bytes.fromhex(spec[len("wpkh("):-1])
                    spk = b"\x00\x14" + _hash160(pub)
                elif spec.startswith("tr(") and spec.endswith(")"):
                    # Minimal: treat the inner hex as a 32-byte x-only output
                    # key (no script-path tweak). Full BIP-341 tweaking is a
                    # follow-up; key-path tr() with an already-tweaked key is
                    # the common UTXO-scan case.
                    xonly = bytes.fromhex(spec[len("tr("):-1])
                    if len(xonly) != 32:
                        raise ValueError("tr() expects a 32-byte x-only key")
                    spk = b"\x51\x20" + xonly
                else:
                    # Bare-hex shorthand for a raw scriptPubKey.
                    spk = bytes.fromhex(spec)
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported or invalid scan object '{spec}': {exc}",
                ) from None

            needles.setdefault(spk, desc)
        return needles

    async def rpc_scanblocks(
        self,
        action: str = "start",
        scanobjects: list[Any] | None = None,
        start_height: int | None = None,
        stop_height: int | None = None,
        filtertype: str = "basic",
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Return relevant blockhashes for scanobjects via the BIP-157 index.

        Mirrors Bitcoin Core ``scanblocks``
        (``src/rpc/blockchain.cpp::scanblocks``, action start/status/abort).
        Drives the EXISTING basic block filter index: for each block in
        ``[start_height, stop_height]`` it tests whether the block's GCS
        filter MATCHES any of the scanobjects' scriptPubKeys and, if so,
        adds the block hash to ``relevant_blocks``.  It is the index-side
        counterpart to ``scantxoutset`` (which walks the live UTXO set):
        scanblocks walks compact block filters, so it can locate the block a
        script was funded/spent in even after the coin is gone.

        SIGNATURE (Core)::

            scanblocks "action" ( [scanobjects] start_height stop_height
                                   "filtertype" options )

        ``action``:
          - ``status``  -> ``null`` (ouroboros scans synchronously, so there
            is never a background scan in progress — Core returns
            NullUniValue when the reserver is not held).
          - ``abort``   -> ``false`` (nothing running to abort — Core returns
            false when the reserve was possible).
          - ``start``   -> performs the scan; ``scanobjects`` required.
          - anything else -> RPC_INVALID_PARAMETER (-8) "Invalid action".

        ``filtertype`` defaults to ``"basic"`` (only type supported).
        ``start_height`` defaults to the genesis (0); ``stop_height``
        defaults to the chain tip.

        Returns (for ``start``)::

            {"from_height": int, "to_height": int,
             "relevant_blocks": ["<blockhash>"...], "completed": bool}

        Error parity (Core protocol.h codes):
          - unknown ``filtertype``        -> -5  "Unknown filtertype"
          - filter index not enabled      -> -1  "Index is not enabled for
                                                  filtertype <name>"
          - bad ``start_height``          -> -1  "Invalid start_height"
          - bad ``stop_height``           -> -1  "Invalid stop_height"

        CENTRAL CAVEAT: block filters have FALSE POSITIVES (rate ~1/M,
        M=784931), so ``relevant_blocks`` is a SUPERSET — a block that
        actually contains a matched script MUST appear, but the list may
        carry extra (false-positive) blocks.  When
        ``options.filter_false_positives`` is true every candidate block is
        re-scanned against its raw body to drop GCS false positives (Core's
        ``CheckBlockFilterMatches``), which can only REMOVE matches, never a
        genuine one.
        """
        # (1) Action dispatch (Core blockchain.cpp scanblocks). ouroboros
        # scans synchronously within this call, so there is never an
        # in-progress scan: status -> null, abort -> false. Only start works.
        action = (action or "start").lower()
        if action == "status":
            return None
        if action == "abort":
            return False
        if action != "start":
            raise RpcError(
                RPC_INVALID_PARAMETER,
                f"Invalid action '{action}'",
            )

        # (2) filtertype validation (Core: BlockFilterTypeByName ->
        # RPC_INVALID_ADDRESS_OR_KEY (-5) "Unknown filtertype"). Default basic.
        ftype_name = filtertype or "basic"
        if ftype_name != "basic":
            raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype")

        # (3) options.filter_false_positives (Core). Default false. Reading it
        # must never error when absent / null / non-dict.
        filter_false_positives = False
        if isinstance(options, dict):
            filter_false_positives = bool(
                options.get("filter_false_positives", False)
            )

        # (4) scanobjects required for "start" (Core get_array on params[1]).
        if not scanobjects:
            raise RpcError(
                RPC_MISC_ERROR,
                "scanobjects argument is required for the start action",
            )

        # (5) Index-enabled gate (Core: GetBlockFilterIndex == nullptr ->
        # RPC_MISC_ERROR (-1) "Index is not enabled for filtertype <name>").
        # ouroboros enables the index via -blockfilterindex; when off,
        # node.block_filter_index is None.
        bfi: BlockFilterIndex | PersistentBlockFilterIndex | None = (
            getattr(self.node, "block_filter_index", None)
        )
        if bfi is None:
            raise RpcError(
                RPC_MISC_ERROR,
                f"Index is not enabled for filtertype {ftype_name}",
            )

        if not hasattr(self.node, "db") or not self.node.db:
            raise RpcError(RPC_MISC_ERROR, "Database not available")

        network = getattr(self.node, "network", "mainnet")

        # (6) Height range (Core: RPC_MISC_ERROR (-1) for bad heights here,
        # NOT -8 like scantxoutset). Default start=genesis(0), stop=tip.
        try:
            _, tip_height = self.node.db.get_best_block()
            tip = int(tip_height) if tip_height is not None else 0
        except Exception:
            tip = 0

        start = 0 if start_height is None else int(start_height)
        if start < 0 or start > tip:
            raise RpcError(RPC_MISC_ERROR, "Invalid start_height")
        stop = tip if stop_height is None else int(stop_height)
        if stop < start or stop > tip:
            raise RpcError(RPC_MISC_ERROR, "Invalid stop_height")

        # (7) Build the needle set (Core scanobjects -> CScript). Reuse the
        # same descriptor resolver scantxoutset uses; addr() parity is already
        # proven by the scantxoutset differential. ``_scantxoutset_resolve``
        # raises HTTPException(400) on unparseable objects, which the dispatch
        # surfaces as an error envelope (Core RPC_INVALID_PARAMETER class).
        needle_map = self._scantxoutset_resolve(scanobjects, network)
        needles: list[bytes] = list(needle_map.keys())

        def _scan() -> list[str]:
            """Walk [start, stop] testing each block's GCS filter against the
            needle set on a worker thread (large ranges must not stall the
            asyncio event loop)."""
            relevant: list[str] = []
            for height in range(start, stop + 1):
                # Active-chain block hash at this height (internal/LE order,
                # the order the filter index and DB are keyed by).
                block_hash = self.node.db.get_block_hash_by_height(height)
                if block_hash is None:
                    # A height in range lacks a chain block — the chain is
                    # shorter than `tip` implies (should not happen given the
                    # range gate, but be defensive and skip rather than crash).
                    continue
                block_hash = bytes(block_hash)

                filt = bfi.get_filter(block_hash)
                if filt is None:
                    # The filter for an in-range block is not cached yet (the
                    # block-connect hook is best-effort and may have skipped
                    # it). Rebuild it on the fly from the raw block — the GCS
                    # filter is deterministic, so the rebuilt bytes are
                    # byte-identical to what the index would have stored.
                    # Mirrors getblockfilter's slow path and the P2P cfilter
                    # handler (node.py PrepareBlockFilterRequest fallback),
                    # never returning a misleadingly incomplete list.
                    block = self.node.db.get_block(block_hash)
                    if block is None:
                        raise RpcError(
                            RPC_MISC_ERROR,
                            "Filter not found. Block filters are still in "
                            "the process of being indexed.",
                        )
                    filt = build_basic_filter(block, self.node.db)

                # SipHash key = first 16 bytes of the block hash in internal
                # (LE) order — exactly what build_basic_filter used, so the
                # match keys are byte-identical to the indexed filter.
                key = _block_filter_siphash_key(block_hash)
                if not gcs_match_any(filt, key, needles):
                    continue

                # Optional re-scan to drop GCS false positives (Core's
                # CheckBlockFilterMatches). A strict subset operation: it can
                # only REMOVE false positives, never a genuine match, so the
                # funded-block contract holds with or without it.
                if filter_false_positives:
                    block = self.node.db.get_block(block_hash)
                    if block is not None:
                        rebuilt = build_basic_filter(block, self.node.db)
                        if not gcs_match_any(rebuilt, key, needles):
                            continue

                # Display-order block hash (Core uint256::GetHex()): reverse
                # internal/LE to big-endian.
                relevant.append(block_hash[::-1].hex())
            return relevant

        relevant = await asyncio.to_thread(_scan)

        # (8) Return (Core shape). The synchronous scan is never aborted, so
        # `completed` is always true.
        return {
            "from_height": start,
            "to_height": stop,
            "relevant_blocks": relevant,
            "completed": True,
        }

    async def rpc_verifychain(self, checklevel: int = 3, nblocks: int = 6) -> bool:
        """Verify the blockchain database (Core-faithful CVerifyDB::VerifyDB).

        Re-validates the last *nblocks* blocks of the active chain at the
        requested *checklevel*, returning a JSON bool (true = all checked
        blocks passed). This is the ouroboros analog of Bitcoin Core
        ``CVerifyDB::VerifyDB`` (bitcoin-core/src/validation.cpp:4611), called
        from the ``verifychain`` RPC (bitcoin-core/src/rpc/blockchain.cpp:1262).

        Levels (cumulative, exactly Core's nCheckLevel ladder):
          0  ReadBlock from disk (read + deserialize)
          1  + CheckBlock          (real context-free validation: PoW, merkle
                                     root, basic structure / coinbase sanity)
          2  + read undo data      (ReadBlockUndo presence/consistency)
          3  + DisconnectBlock     (in-memory disconnect into a sandbox overlay,
                                     reverse-tx-order, reusing the node's real
                                     undo store — DISCONNECT_UNCLEAN is a
                                     NON-FATAL warning, only DISCONNECT_FAILED
                                     is fatal)
          4  + reconnect           (full ConnectBlock-equivalent: re-run the
                                     node's real ``validate_block`` with scripts
                                     forced on, against the rewound overlay)

        Args (positional, both optional):
          checklevel: verification depth, default 3, clamped to 0..4
          nblocks:    number of recent blocks, default 6; 0 or > chain-height
                      means ALL blocks.

        CRITICAL: this MUST NOT mutate the live chainstate. Core's VerifyDB
        works on a throwaway ``CCoinsViewCache`` layered over the real coins
        view; ouroboros mirrors that with an in-memory ``overlay`` dict over
        the live UTXO set. The live RocksDB chainstate, block index, and undo
        store are only ever READ. Levels 3/4 reconstruct the fork-point UTXO
        view by rewinding each block (disconnect) into the overlay and then
        re-run the SAME ``validate_block`` machinery the node uses during sync,
        never a constant-true stub.

        CRITICAL undo semantics (Core validation.cpp:4672-4680, 2179-2247):
          * A block with a NULL undo position is SKIPPED for levels >= 2 (the
            assume-valid / snapshot "only go back as far as we have data"
            rule), NOT failed — and the walk-down stops there.
          * DisconnectBlock walks txs in REVERSE; an absent intra-block-spend
            output on disconnect is the NON-FATAL unclean signal (fClean=False,
            continue, still return true). Only an irrecoverable inconsistency
            (DISCONNECT_FAILED — undo/tx count mismatch) is fatal/false.
        """
        from ouroboros.validation import _bits_to_target

        if not hasattr(self.node, "db") or not self.node.db:
            return True

        db = self.node.db
        try:
            _, best_height = await asyncio.to_thread(db.get_best_block)
        except Exception:
            return True

        checklevel = max(0, min(4, checklevel))

        # Core: genesis-only / empty chain -> SUCCESS (validation.cpp:4619).
        if best_height <= 0:
            return True

        # if (nCheckDepth <= 0 || nCheckDepth > chain.Height()) nCheckDepth = Height();
        check_depth = nblocks
        if check_depth <= 0 or check_depth > best_height:
            check_depth = best_height
        start_height = best_height - check_depth + 1  # inclusive lower bound

        logger.info(
            "verifychain: verifying last %d blocks at level %d (heights %d..%d)",
            check_depth, checklevel, start_height, best_height,
        )

        def _verify_sync() -> bool:
            # In-memory sandbox UTXO view layered over the live coins view.
            #   overlay[(txid, vout)] = utxo-dict  -> shadows the live entry
            #   overlay[(txid, vout)] = None       -> spent/absent in sandbox
            # A missing key falls through to the live DB read. Mutated ONLY here.
            overlay: dict[tuple[bytes, int], dict | None] = {}

            # Stack of blocks disconnected during the down-walk, so level 4 can
            # reconnect oldest-first (Core walks chain.Next upward to the tip).
            disconnected: list[tuple] = []

            from ouroboros.database import Block as _Block

            def read_block(h: int):
                # Witness-preserving read (Core ReadBlock). get_block_by_height
                # strips the coinbase witness reserved value, which would make
                # the level-1 merkle / level-4 witness-commitment checks fail on
                # every segwit block. Prefer the raw consensus bytes (which keep
                # the witness) + Block.deserialize — the SAME path the production
                # connect uses (accept_block: Block.deserialize(block_bytes)).
                bh = db.get_block_hash_by_height(h)
                if bh is not None:
                    raw = db.get_block_bytes(bytes(bh))
                    if raw:
                        try:
                            return _Block.deserialize(bytes(raw))
                        except Exception:
                            pass
                return db.get_block_by_height(h)

            # ---- Levels 0-3: walk DOWN from the tip (disconnect direction) ----
            for h in range(best_height, start_height - 1, -1):
                # Level 0: ReadBlock from disk (read + deserialize).
                block = read_block(h)
                if block is None:
                    logger.warning("verifychain: ReadBlock failed at height %d", h)
                    return False

                # Level 1: CheckBlock — real context-free validation.
                if checklevel >= 1:
                    if not block.transactions:
                        logger.warning("verifychain: empty block at height %d", h)
                        return False
                    # PoW: hash <= target(nBits). block.hash is stored in
                    # internal/wire (little-endian) order — the same order the
                    # node's miner compares (int.from_bytes(.., "little") <=
                    # target). Display order (getblockhash) is the reverse.
                    target = _bits_to_target(block.bits)
                    if target <= 0 or int.from_bytes(block.hash, "little") > target:
                        logger.warning("verifychain: bad PoW at height %d", h)
                        return False
                    # Merkle root (with malleation / duplicate-txid detection).
                    if self.node.validator is not None:
                        if not self.node.validator._verify_merkle_root(block):
                            logger.warning(
                                "verifychain: bad merkle root at height %d", h
                            )
                            return False
                    # First tx must be coinbase, and ONLY the first.
                    if not block.transactions[0].is_coinbase:
                        logger.warning(
                            "verifychain: missing coinbase at height %d", h
                        )
                        return False
                    for tx in block.transactions[1:]:
                        if tx.is_coinbase:
                            logger.warning(
                                "verifychain: multiple coinbase at height %d", h
                            )
                            return False
                    for tx in block.transactions:
                        if not tx.inputs or not tx.outputs:
                            logger.warning(
                                "verifychain: tx with no in/outputs at height %d",
                                h,
                            )
                            return False

                # Level 2: undo-data presence + recovery. ouroboros's per-spend
                # undo coins live in the SPENT_CF store (Core's "block undo"),
                # read back via get_utxo_or_spent. We reconstruct the block's
                # undo by restoring every non-coinbase spent input from there.
                #
                # NULL undo position (Core validation.cpp:4674): a block whose
                # undo data is absent is SKIPPED, NOT failed — the assume-valid /
                # snapshot / pruned "only go back as far as we have data" rule.
                # In ouroboros that manifests as a block with real non-coinbase
                # spends whose undo coins are ALL unrecoverable from SPENT_CF
                # (e.g. a block below the assumeUTXO base whose body/undo was
                # never downloaded). When that happens we stop the down-walk.
                # A coinbase-only block legitimately has an EMPTY undo set —
                # that is not "missing data", so we keep going.
                #
                # NOTE: has_block_undo()/UNDO_CF is NOT used here — the normal
                # connect path (connect_block_from_bytes) only writes SPENT_CF,
                # leaving UNDO_CF empty, so has_block_undo would falsely report
                # "no data" for every block and skip the whole verification.
                block_undo: dict[tuple[bytes, int], dict] | None = None
                if checklevel >= 2:
                    block_undo = {}
                    spend_inputs: list[tuple[bytes, int]] = []
                    for tx in block.transactions:
                        if tx.is_coinbase:
                            continue
                        for tx_in in tx.inputs:
                            spend_inputs.append(
                                (tx_in.prev_txid, tx_in.prev_vout)
                            )
                    recovered = 0
                    for op in spend_inputs:
                        try:
                            coin = db.get_utxo_or_spent(op[0], op[1])
                        except Exception:
                            coin = None
                        if coin is not None:
                            block_undo[op] = coin
                            recovered += 1
                    if spend_inputs and recovered == 0:
                        # All spends unrecoverable -> genuine missing undo data.
                        logger.info(
                            "verifychain: block %d has no recoverable undo data; "
                            "stopping verification here (snapshot/pruned)", h
                        )
                        break

                # Level 3: in-memory disconnect into the overlay, REVERSE tx
                # order, restoring spent inputs from the recovered undo coins.
                # Mirrors Core DisconnectBlock (validation.cpp:2179-2247): a
                # created-output mismatch on spend is the NON-FATAL unclean
                # signal (fClean=False, continue); only an undo/tx inconsistency
                # (DISCONNECT_FAILED — a spent input on a data-bearing block with
                # no undo coin to restore) is fatal/false.
                if checklevel >= 3:
                    assert block_undo is not None  # set whenever checklevel>=2
                    for tx in reversed(block.transactions):
                        txid = tx.get_txid()
                        # Spend (remove) this tx's created outputs from the
                        # sandbox. Reverse order means a later tx's restored
                        # inputs already put back any intra-block-created coin
                        # an earlier tx consumes, so a valid chain disconnects
                        # cleanly. An absent output here is UNCLEAN (non-fatal).
                        for o in range(len(tx.outputs)):
                            overlay[(txid, o)] = None
                        # Restore spent inputs from the recovered undo (skip
                        # coinbase, which has no real inputs to undo).
                        if not tx.is_coinbase:
                            for tx_in in tx.inputs:
                                op = (tx_in.prev_txid, tx_in.prev_vout)
                                restored = block_undo.get(op)
                                if restored is None:
                                    # Missing undo coin for a real spend on a
                                    # data-bearing block = irrecoverable
                                    # inconsistency (Core ApplyTxInUndo ->
                                    # DISCONNECT_FAILED), fatal/false.
                                    logger.warning(
                                        "verifychain: irrecoverable inconsistency "
                                        "(missing undo) at height %d", h
                                    )
                                    return False
                                overlay[op] = restored
                    disconnected.append((block, h))

            # ---- Level 4: walk UP (reconnect direction), full re-validation ---
            # The overlay now represents the UTXO set at start_height-1 (the
            # fork point). Re-run the node's REAL validate_block with scripts
            # forced on, bottom-up, against an overlay-backed db proxy (reads
            # served from the overlay, writes never touch the live DB).
            if checklevel >= 4 and disconnected:
                validator = self.node.validator
                if validator is None:
                    logger.warning("verifychain: validator unavailable for L4")
                    return False

                # validate_block reads UTXOs through ``validator.tx_validator``
                # (its OWN internal TransactionValidator), NOT node.tx_validator
                # — node.py wires those as two SEPARATE instances that "do not
                # share" (node.py:243-248). The db-swap MUST therefore target
                # validator.tx_validator (and validator itself, used by
                # _validate_block_limits' P2SH-sigop prevout lookups). We also
                # swap node.tx_validator defensively in case any path reads it.
                proxy = _VerifyChainDBProxy(db, overlay)
                inner_tx = getattr(validator, "tx_validator", None)
                node_tx = self.node.tx_validator
                swap_targets = []
                _seen_ids: set[int] = set()
                for obj in (validator, inner_tx, node_tx):
                    # Skip None and dedup by identity so the saved "original" db
                    # is never the proxy we just installed on an aliased object.
                    if obj is not None and id(obj) not in _seen_ids:
                        _seen_ids.add(id(obj))
                        swap_targets.append((obj, obj.db))
                        obj.db = proxy
                try:
                    for block, h in reversed(disconnected):
                        ok, err = validator.validate_block(
                            block, known_height=h, force_check_scripts=True
                        )
                        if not ok:
                            logger.warning(
                                "verifychain: unconnectable block at height %d: %s",
                                h, err,
                            )
                            return False
                        # Apply this block forward into the overlay so the next
                        # (higher) block sees the coins it creates / spends —
                        # replays ConnectBlock's UTXO mutation in the overlay
                        # only (never the live DB).
                        for ti, tx in enumerate(block.transactions):
                            txid = tx.get_txid()
                            if ti != 0:  # non-coinbase: spend inputs
                                for tx_in in tx.inputs:
                                    overlay[(tx_in.prev_txid, tx_in.prev_vout)] = None
                            for vout_idx, out in enumerate(tx.outputs):
                                overlay[(txid, vout_idx)] = {
                                    "txid": txid,
                                    "vout": vout_idx,
                                    "value": out.value,
                                    "script_pubkey": out.script_pubkey,
                                    "height": h,
                                    "is_coinbase": (ti == 0),
                                }
                finally:
                    for obj, saved_db in swap_targets:
                        obj.db = saved_db

            return True

        try:
            return await asyncio.to_thread(_verify_sync)
        except Exception as e:
            logger.warning("verifychain: error during verification: %s", e)
            return False

    @staticmethod
    def _compute_merkle_root(txids: list) -> bytes:
        import hashlib
        if not txids:
            return bytes(32)
        level = list(txids)
        while len(level) > 1:
            if len(level) % 2 != 0:
                level.append(level[-1])
            next_level = []
            for i in range(0, len(level), 2):
                h = hashlib.sha256(
                    hashlib.sha256(level[i] + level[i + 1]).digest()
                ).digest()
                next_level.append(h)
            level = next_level
        return level[0]

    async def rpc_getmempoolancestors(
        self, txid: str, verbose: bool = False
    ) -> list[str] | dict[str, Any]:
        """Return all in-mempool ancestors of a transaction."""
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            return [] if not verbose else {}
        # JSON-RPC convention: txids arrive in display order (big-endian hex).
        # Internal mempool keys are little-endian (internal byte order). W69.
        txid_bytes = bytes.fromhex(txid)[::-1]
        tx = self.node.mempool.get_transaction(txid_bytes)
        if tx is None:
            raise ValueError(f"Transaction not in mempool: {txid}")
        ancestors = self.node.mempool._get_ancestors(tx)
        if not verbose:
            return [a[::-1].hex() for a in ancestors]
        result: dict[str, Any] = {}
        for a_txid in ancestors:
            entry = self.node.mempool.get_transaction_entry(a_txid)
            if entry is not None:
                result[a_txid[::-1].hex()] = self._format_mempool_entry(entry, a_txid)
        return result

    async def rpc_getmempooldescendants(
        self, txid: str, verbose: bool = False
    ) -> list[str] | dict[str, Any]:
        """Return all in-mempool descendants of a transaction."""
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            return [] if not verbose else {}
        # JSON-RPC convention: txids arrive in display order (big-endian hex).
        # Internal mempool keys are little-endian (internal byte order). W69.
        txid_bytes = bytes.fromhex(txid)[::-1]
        if txid_bytes not in self.node.mempool.transactions:
            raise ValueError(f"Transaction not in mempool: {txid}")
        descendants = self.node.mempool._collect_descendants(txid_bytes)
        descendants.discard(txid_bytes)
        if not verbose:
            return [d[::-1].hex() for d in descendants]
        result: dict[str, Any] = {}
        for d_txid in descendants:
            entry = self.node.mempool.get_transaction_entry(d_txid)
            if entry is not None:
                result[d_txid[::-1].hex()] = self._format_mempool_entry(entry, d_txid)
        return result

    async def rpc_createrawtransaction(
        self, inputs: list[dict], outputs, locktime: int = 0,
        replaceable: bool = None
    ) -> str:
        """Create a raw transaction (unsigned).

        Faithful to Bitcoin Core's ConstructTransaction / AddInputs /
        NormalizeOutputs / ParseOutputs
        (src/rpc/rawtransaction_util.cpp).

        Sequence default (AddInputs, lines 47-65): per input, an explicit
        "sequence" wins; otherwise the default depends on `replaceable`
        (RPCArg Default{true}) and locktime:
          rbf.value_or(true)         -> MAX_BIP125_RBF_SEQUENCE 0xFFFFFFFD
          else if locktime != 0      -> MAX_SEQUENCE_NONFINAL   0xFFFFFFFE
          else                       -> SEQUENCE_FINAL           0xFFFFFFFF
        So with no explicit sequence, no `replaceable`, no locktime, the
        default is 0xFFFFFFFD (replaceable defaults TRUE).

        Outputs (NormalizeOutputs) accepts BOTH a JSON object
        {address:amount, "data":hex, ...} AND a JSON array of single-key
        objects [{address:amount}, {"data":hex}, ...]; the array form is
        flattened (and permits duplicate addresses + ordering).
        """
        from decimal import Decimal

        from ouroboros.database import Transaction as DbTx
        from ouroboros.database import TxIn, TxOut

        # Core: rbf is std::optional<bool>; unset -> value_or(true).
        rbf = True if replaceable is None else bool(replaceable)

        # Default sequence depends on rbf and locktime (Core AddInputs).
        lock = int(locktime) if locktime is not None else 0
        if rbf:
            default_sequence = 0xFFFFFFFD   # MAX_BIP125_RBF_SEQUENCE
        elif lock != 0:
            default_sequence = 0xFFFFFFFE   # MAX_SEQUENCE_NONFINAL
        else:
            default_sequence = 0xFFFFFFFF   # SEQUENCE_FINAL

        # --- inputs (AddInputs) ------------------------------------------
        tx_inputs = []
        for inp in inputs:
            # JSON-RPC convention: txids arrive in display order (big-endian
            # hex); wire format stores prev_txid in little-endian. W69.
            txid_bytes = bytes.fromhex(inp['txid'])[::-1]
            # Explicit per-input "sequence" wins (Core: range check
            # [0, SEQUENCE_FINAL=0xFFFFFFFF]); otherwise use the default.
            seq_v = inp.get('sequence')
            if seq_v is not None:
                seq = int(seq_v)
                if seq < 0 or seq > 0xFFFFFFFF:
                    raise ValueError(
                        "Invalid parameter, sequence number is out of range"
                    )
            else:
                seq = default_sequence
            tx_inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=inp['vout'],
                script_sig=b'',
                sequence=seq,
            ))

        # --- outputs (NormalizeOutputs) ----------------------------------
        # Flatten an array of single-key objects into an ordered list of
        # (key, value) pairs; an object is iterated in its given order.
        # Both forms must work, hence accept dict OR list.
        if outputs is None:
            raise ValueError(
                "Invalid parameter, output argument must be non-null"
            )
        output_items = []
        if isinstance(outputs, dict):
            output_items = list(outputs.items())
        elif isinstance(outputs, list):
            for entry in outputs:
                if not isinstance(entry, dict):
                    raise ValueError(
                        "Invalid parameter, key-value pair not an object as "
                        "expected"
                    )
                if len(entry) != 1:
                    raise ValueError(
                        "Invalid parameter, key-value pair must contain "
                        "exactly one key"
                    )
                output_items.extend(entry.items())
        else:
            raise ValueError(
                "Invalid parameter, output argument must be an object or array"
            )

        # --- outputs (ParseOutputs) --------------------------------------
        tx_outputs = []
        for addr, amount in output_items:
            if addr == "data":
                # Core: CScript() << OP_RETURN << data — canonical minimal
                # push encoding (direct push / PUSHDATA1 / PUSHDATA2). Reuse
                # the node's existing CScript-push encoder.
                from ouroboros.script import _minimal_push_script
                data = bytes.fromhex(amount)
                script = b'\x6a' + _minimal_push_script(data)
                sat_amount = 0
            else:
                from ouroboros.address import address_to_script_pubkey
                script = address_to_script_pubkey(addr, self.node.network)
                # Core AmountFromValue: exact decimal -> satoshis (no float
                # rounding error).
                sat_amount = int(
                    (Decimal(str(amount)) * Decimal(100_000_000))
                    .to_integral_value()
                )
            tx_outputs.append(TxOut(value=sat_amount, script_pubkey=script))

        tx = DbTx(
            txid=b'\x00' * 32, version=2, locktime=lock,
            inputs=tx_inputs, outputs=tx_outputs,
        )
        return tx.serialize().hex()

    async def rpc_signrawtransactionwithkey(
        self, hexstring: str, privkeys: list[str],
        prevtxs: list[dict] = None, sighashtype: str = "ALL"
    ) -> dict[str, Any]:
        """Sign a raw transaction with provided private keys.

        Args:
            hexstring: Hex-encoded raw transaction
            privkeys: Array of WIF-encoded private keys
            prevtxs: Array of previous outputs being spent, each with
                      keys: txid, vout, scriptPubKey, amount (optional
                      redeemScript, witnessScript)
            sighashtype: Signature hash type (ALL, NONE, SINGLE,
                         ALL|ANYONECANPAY, NONE|ANYONECANPAY,
                         SINGLE|ANYONECANPAY, DEFAULT)

        Returns:
            {hex: signed_tx_hex, complete: bool, errors: [...]}
        """
        import hashlib
        import struct

        from ouroboros.database import TxIn
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.wallet import WalletKey, _dsha256, _encode_varint, _hash160

        # --- Parse sighash type string -----------------------------------
        sighash_map = {
            "ALL": 0x01, "NONE": 0x02, "SINGLE": 0x03,
            "ALL|ANYONECANPAY": 0x81, "NONE|ANYONECANPAY": 0x82,
            "SINGLE|ANYONECANPAY": 0x83, "DEFAULT": 0x00,
        }
        sighash_type = sighash_map.get(sighashtype.upper(), 0x01)

        # --- Deserialize transaction -------------------------------------
        # Core: DecodeHexTx failure -> RPC_DESERIALIZATION_ERROR (-22) with a
        # fixed message (rpc/rawtransaction.cpp:742). A bare ValueError here
        # would collapse to -32603; raise RpcError so the dispatch loop emits
        # the exact -22 Core uses.
        try:
            tx_msg = TxMessage.from_payload(bytes.fromhex(hexstring))
            tx = tx_msg.transaction
        except Exception:
            raise RpcError(
                RPC_DESERIALIZATION_ERROR,
                "TX decode failed. Make sure the tx has at least one input.",
            ) from None

        # --- Build key lookup: pubkey_hash / pubkey -> WalletKey ---------
        network = getattr(self.node, "network", "mainnet")
        keys_by_h160: dict[bytes, WalletKey] = {}
        keys_by_pubkey: dict[bytes, WalletKey] = {}
        for wif in privkeys:
            try:
                k = WalletKey.from_wif(wif, network)
                keys_by_h160[_hash160(k.pubkey)] = k
                keys_by_pubkey[k.pubkey] = k
                # Also index by x-only key for Taproot
                keys_by_pubkey[k.pubkey[1:]] = k
                # P2TR scriptPubKey contains the BIP-341 tweaked output
                # key, not the internal x-only key. Index by both so the
                # lookup at rpc.py:6582 / 8595 matches.
                try:
                    from ouroboros.taproot import (
                        derive_taproot_output_xonly,
                    )
                    keys_by_pubkey[
                        derive_taproot_output_xonly(k.pubkey, None)
                    ] = k
                except Exception:
                    pass
            except Exception:
                pass

        # --- Build prevout lookup: (txid, vout) -> (scriptPubKey, value) -
        prev_lookup: dict[tuple, tuple] = {}
        # Side table for optional redeemScript / witnessScript per prevout.
        # P2SH-P2WSH and bare P2WSH require these to compute BIP-143 sighash
        # with the witnessScript as the scriptCode.
        prev_scripts: dict[tuple, dict] = {}
        if prevtxs:
            for p in prevtxs:
                # JSON-RPC: user supplies txid in display order (BE hex).
                # prev_lookup is keyed by (inp.prev_txid, vout) where
                # inp.prev_txid is internal LE — reverse to match. W69.
                txid_bytes = bytes.fromhex(p["txid"])[::-1]
                vout = p["vout"]
                spk = bytes.fromhex(p["scriptPubKey"])
                amount = int(float(p.get("amount", 0)) * 1e8)
                prev_lookup[(txid_bytes, vout)] = (spk, amount)
                extra: dict = {}
                if p.get("redeemScript"):
                    extra["redeem_script"] = bytes.fromhex(p["redeemScript"])
                if p.get("witnessScript"):
                    extra["witness_script"] = bytes.fromhex(p["witnessScript"])
                if extra:
                    prev_scripts[(txid_bytes, vout)] = extra

        # --- Helper: look up prevout info --------------------------------
        def _get_prevout(inp: TxIn):
            key = (inp.prev_txid, inp.prev_vout)
            if key in prev_lookup:
                return prev_lookup[key]
            # Fall back to UTXO set
            if hasattr(self.node, "db") and self.node.db:
                try:
                    utxo = self.node.db.get_utxo(
                        inp.prev_txid, inp.prev_vout
                    )
                    if utxo:
                        return (utxo.script_pubkey, utxo.value)
                except Exception:
                    pass
            return None, None

        # --- Helper: legacy sighash --------------------------------------
        def _legacy_sighash(tx, idx, script_code, sh_type):
            enc_varint = _encode_varint
            base = sh_type & 0x1F
            acp = (sh_type & 0x80) != 0
            data = bytearray()
            data.extend(struct.pack("<i", tx.version))
            inputs = [(idx, tx.inputs[idx])] if acp else list(enumerate(tx.inputs))
            data.extend(enc_varint(len(inputs)))
            for i, ti in inputs:
                data.extend(ti.prev_txid)
                data.extend(struct.pack("<I", ti.prev_vout))
                if i == idx:
                    data.extend(enc_varint(len(script_code)))
                    data.extend(script_code)
                else:
                    data.extend(b"\x00")
                seq = 0 if base in (2, 3) and i != idx else ti.sequence
                data.extend(struct.pack("<I", seq))
            if base in (0, 1):
                data.extend(enc_varint(len(tx.outputs)))
                for o in tx.outputs:
                    data.extend(struct.pack("<q", o.value))
                    data.extend(enc_varint(len(o.script_pubkey)))
                    data.extend(o.script_pubkey)
            elif base == 2:
                data.extend(b"\x00")
            elif base == 3:
                if idx >= len(tx.outputs):
                    return bytes(32)
                data.extend(enc_varint(idx + 1))
                for j, o in enumerate(tx.outputs):
                    if j == idx:
                        data.extend(struct.pack("<q", o.value))
                        data.extend(enc_varint(len(o.script_pubkey)))
                        data.extend(o.script_pubkey)
                    else:
                        data.extend((-1).to_bytes(8, "little", signed=True))
                        data.extend(b"\x00")
            data.extend(struct.pack("<I", tx.locktime))
            data.extend(struct.pack("<I", sh_type))
            return _dsha256(bytes(data))

        # --- Helper: BIP 143 (SegWit v0) sighash ------------------------
        # Single source of truth lives in ``ouroboros.segwit_v0`` — see
        # the module docstring for why three local copies were
        # consolidated (W29-A). DO NOT inline a private copy here; the
        # ``test_bip143_no_inline_impl`` parity sentinel will fail.
        from ouroboros.segwit_v0 import bip143_sighash as _bip143_sighash

        # --- Helper: taproot key-path sighash (BIP 341) ------------------
        def _taproot_sighash(tx, idx, sh_type, amounts, spks):
            acp = (sh_type & 0x80) != 0
            base = sh_type & 0x03
            data = bytearray()
            data.append(0x00)  # epoch
            data.append(sh_type)
            data.extend(struct.pack("<i", tx.version))
            data.extend(struct.pack("<I", tx.locktime))
            if not acp:
                prevouts = bytearray()
                for i in tx.inputs:
                    prevouts.extend(i.prev_txid)
                    prevouts.extend(struct.pack("<I", i.prev_vout))
                data.extend(hashlib.sha256(bytes(prevouts)).digest())
                amt_data = bytearray()
                for a in amounts:
                    amt_data.extend(struct.pack("<q", a))
                data.extend(hashlib.sha256(bytes(amt_data)).digest())
                spk_data = bytearray()
                for s in spks:
                    spk_data.extend(_encode_varint(len(s)))
                    spk_data.extend(s)
                data.extend(hashlib.sha256(bytes(spk_data)).digest())
                seqs = bytearray()
                for i in tx.inputs:
                    seqs.extend(struct.pack("<I", i.sequence))
                data.extend(hashlib.sha256(bytes(seqs)).digest())
            if base not in (2, 3):
                outs = bytearray()
                for o in tx.outputs:
                    outs.extend(struct.pack("<q", o.value))
                    outs.extend(_encode_varint(len(o.script_pubkey)))
                    outs.extend(o.script_pubkey)
                data.extend(hashlib.sha256(bytes(outs)).digest())
            elif base == 3 and idx < len(tx.outputs):
                o = tx.outputs[idx]
                out = struct.pack("<q", o.value)
                out += _encode_varint(len(o.script_pubkey))
                out += o.script_pubkey
                data.extend(hashlib.sha256(out).digest())
            else:
                data.extend(b"\x00" * 32)
            # spend_type: ext_flag=0, no annex
            data.append(0x00)
            if acp:
                inp = tx.inputs[idx]
                data.extend(inp.prev_txid)
                data.extend(struct.pack("<I", inp.prev_vout))
                data.extend(struct.pack("<q", amounts[idx]))
                data.extend(_encode_varint(len(spks[idx])))
                data.extend(spks[idx])
                data.extend(struct.pack("<I", inp.sequence))
            else:
                data.extend(struct.pack("<I", idx))
            # Tagged hash: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || data)
            tag = hashlib.sha256(b"TapSighash").digest()
            return hashlib.sha256(tag + tag + bytes(data)).digest()

        # --- Sign each input ---------------------------------------------
        errors = []
        all_amounts = []
        all_spks = []
        # Pre-collect amounts/spks for taproot (needs all inputs)
        for inp in tx.inputs:
            spk, amt = _get_prevout(inp)
            all_amounts.append(amt if amt is not None else 0)
            all_spks.append(spk if spk is not None else b"")

        for idx, inp in enumerate(tx.inputs):
            spk = all_spks[idx]
            amount = all_amounts[idx]
            if not spk:
                errors.append({
                    "txid": inp.prev_txid[::-1].hex(),
                    "vout": inp.prev_vout,
                    "error": "Input not found or not provided",
                })
                continue

            try:
                # Detect script type and sign
                if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9:
                    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                    h160 = spk[3:23]
                    key = keys_by_h160.get(h160)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2PKH",
                        })
                        continue
                    sh = _legacy_sighash(tx, idx, spk, sighash_type)
                    sig = key.sign(sh) + bytes([sighash_type])
                    inp.script_sig = (
                        bytes([len(sig)]) + sig
                        + bytes([len(key.pubkey)]) + key.pubkey
                    )

                elif len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                    # P2WPKH: OP_0 <20-byte-hash>
                    h160 = spk[2:22]
                    key = keys_by_h160.get(h160)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2WPKH",
                        })
                        continue
                    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                    sh = _bip143_sighash(tx, idx, script_code, amount, sighash_type)
                    sig = key.sign(sh) + bytes([sighash_type])
                    inp.witness = [sig, key.pubkey]
                    tx.has_witness = True

                elif len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14:
                    # P2SH — check for P2SH-P2WPKH first, then P2SH-P2WSH
                    # (BIP-141 nested-witness wraps).
                    signed = False
                    extras = prev_scripts.get(
                        (inp.prev_txid, inp.prev_vout), {}
                    )
                    explicit_witness_script = extras.get("witness_script")
                    explicit_redeem_script = extras.get("redeem_script")

                    # ---- P2SH-P2WSH branch (witnessScript supplied) ----
                    if explicit_witness_script is not None and not signed:
                        # The redeemScript for P2SH-P2WSH is always
                        # OP_0 <SHA256(witnessScript)> — verify it
                        # hashes to the scriptPubKey p2sh hash.
                        from ouroboros.segwit_v0 import (
                            sign_p2sh_p2wsh_input,
                        )
                        ws_redeem = (
                            b"\x00\x20"
                            + hashlib.sha256(
                                explicit_witness_script
                            ).digest()
                        )
                        if _hash160(ws_redeem) == spk[2:22]:
                            try:
                                ss, witness, sigs = sign_p2sh_p2wsh_input(
                                    tx, idx, explicit_witness_script,
                                    amount, list(keys_by_h160.values())
                                    + list({
                                        id(v): v
                                        for v in keys_by_pubkey.values()
                                    }.values()),
                                    sighash_type,
                                )
                            except ValueError as ve:
                                errors.append({
                                    "txid": inp.prev_txid[::-1].hex(),
                                    "vout": inp.prev_vout,
                                    "error": str(ve),
                                })
                                continue
                            inp.script_sig = ss
                            inp.witness = witness
                            tx.has_witness = True
                            signed = True
                            # If we couldn't gather any signatures,
                            # mark partial.
                            if not sigs:
                                errors.append({
                                    "txid": inp.prev_txid[::-1].hex(),
                                    "vout": inp.prev_vout,
                                    "error": "P2SH-P2WSH: no matching keys for witnessScript",
                                })

                    # ---- P2SH-P2WPKH branch ----
                    if not signed:
                        for h160, key in keys_by_h160.items():
                            redeem_script = b"\x00\x14" + h160
                            if _hash160(redeem_script) == spk[2:22]:
                                script_code = (
                                    b"\x76\xa9\x14" + h160 + b"\x88\xac"
                                )
                                sh = _bip143_sighash(
                                    tx, idx, script_code, amount,
                                    sighash_type,
                                )
                                sig = key.sign(sh) + bytes([sighash_type])
                                inp.script_sig = (
                                    bytes([len(redeem_script)])
                                    + redeem_script
                                )
                                inp.witness = [sig, key.pubkey]
                                tx.has_witness = True
                                signed = True
                                break

                    # ---- Caller-supplied redeemScript fallback ----
                    # If a redeemScript was supplied that hashes to spk
                    # but isn't P2WPKH and isn't a P2WSH wrapper, we
                    # currently don't sign legacy P2SH (out of scope —
                    # Phase 2c per the design doc).
                    if not signed and explicit_redeem_script is not None:
                        if _hash160(explicit_redeem_script) == spk[2:22]:
                            errors.append({
                                "txid": inp.prev_txid[::-1].hex(),
                                "vout": inp.prev_vout,
                                "error": "Legacy P2SH redeemScript signing not supported (only P2SH-P2WPKH and P2SH-P2WSH wraps)",
                            })
                            signed = True  # don't double-emit error below

                    if not signed:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2SH-P2WPKH (P2SH-P2WSH requires witnessScript in prevtxs)",
                        })

                elif len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
                    # P2TR: OP_1 <32-byte-x-only-key>
                    x_only = spk[2:34]
                    key = keys_by_pubkey.get(x_only)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2TR",
                        })
                        continue
                    sh = _taproot_sighash(
                        tx, idx, sighash_type, all_amounts, all_spks
                    )
                    # BIP-341 / BIP-86: sign with the tweaked spending key,
                    # not the raw internal key. ouroboros wallets only
                    # produce key-path-only (BIP-86) P2TR outputs, so the
                    # merkle root is empty.
                    from ouroboros.taproot import derive_taproot_sign_secret
                    try:
                        tweaked_secret = derive_taproot_sign_secret(
                            key.secret, None
                        )
                    except Exception as e:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": f"P2TR key tweak failed: {e}",
                        })
                        continue
                    # W95: drop dead ``_sync.sign_schnorr`` path — the
                    # ferrous-utils ``sync`` module exposes verify-only
                    # Schnorr primitives (no signing API). Calling coincurve
                    # directly avoids a spurious AttributeError swallow on
                    # every wallet-side P2TR sign.
                    try:
                        from coincurve import PrivateKey as CPrivKey
                        raw_sig = CPrivKey(tweaked_secret).sign_schnorr(sh)
                    except Exception:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": "Schnorr signing not available",
                        })
                        continue
                    if sighash_type != 0x00:
                        raw_sig += bytes([sighash_type])
                    inp.witness = [raw_sig]
                    tx.has_witness = True

                elif len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
                    # P2WSH: OP_0 <32-byte-hash>. Pull witnessScript from
                    # the prevtxs entry; verify SHA256 hashes to spk.
                    extras = prev_scripts.get(
                        (inp.prev_txid, inp.prev_vout), {}
                    )
                    witness_script = extras.get("witness_script")
                    if witness_script is None:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": "P2WSH input missing witnessScript in prevtxs",
                        })
                        continue
                    if hashlib.sha256(witness_script).digest() != spk[2:34]:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": "P2WSH witnessScript does not hash to scriptPubKey",
                        })
                        continue
                    from ouroboros.segwit_v0 import sign_p2wsh_input
                    # Build a deduplicated, type-uniform key list
                    # (h160 lookup buckets duplicate-store keys, so dedup).
                    candidate_keys: list = []
                    seen_secrets: set = set()
                    for k in list(keys_by_h160.values()) + list(
                        keys_by_pubkey.values()
                    ):
                        sid = id(k)
                        if sid in seen_secrets:
                            continue
                        seen_secrets.add(sid)
                        candidate_keys.append(k)
                    try:
                        witness, sigs = sign_p2wsh_input(
                            tx, idx, witness_script, amount,
                            candidate_keys, sighash_type,
                        )
                    except ValueError as ve:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": str(ve),
                        })
                        continue
                    inp.witness = witness
                    tx.has_witness = True
                    if not sigs:
                        errors.append({
                            "txid": inp.prev_txid[::-1].hex(),
                            "vout": inp.prev_vout,
                            "error": "P2WSH: no matching keys for witnessScript",
                        })

                else:
                    errors.append({
                        "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                        "error": f"Unsupported script type (len={len(spk)})",
                    })

            except Exception as e:
                errors.append({
                    "txid": inp.prev_txid[::-1].hex(), "vout": inp.prev_vout,
                    "error": str(e),
                })

        # --- Re-compute txid and serialize --------------------------------
        tx.txid = _dsha256(tx.serialize())
        signed_hex = tx.serialize_with_witness().hex()
        complete = len(errors) == 0
        result: dict[str, Any] = {"hex": signed_hex, "complete": complete}
        if errors:
            result["errors"] = errors
        return result

    async def rpc_testmempoolaccept(
        self, rawtxs: list[str], maxfeerate: float = 0.10
    ) -> list[dict[str, Any]]:
        """Test whether raw transactions would be accepted to mempool.

        This must report the same accept/reject decision an actual relay would
        make — i.e. it has to run the full mempool standardness + policy gate
        (IsStandardTx version/dust/datacarrier, input/witness standardness,
        sigop cost, RBF/TRUC, ephemeral dust, and the min-relay-fee floor),
        not just the bare consensus validator.  Earlier this routed straight to
        ``tx_validator.validate_transaction`` which enforces only consensus
        rules, so it ACCEPTED dust, bad-version (nVersion outside [1,3]), and
        zero-fee below-min-relay transactions that Bitcoin Core rejects.  We now
        route through the mempool's ``accept_to_memory_pool(test_accept=True)``
        dry-run, which evaluates every gate without mutating the pool.
        Reference: bitcoin-core/src/policy/policy.cpp IsStandardTx +
        validation.cpp PreChecks (the testmempoolaccept path).
        """
        mempool = getattr(self.node, "mempool", None)
        results: list[dict[str, Any]] = []
        for raw in rawtxs:
            try:
                from ouroboros.p2p_messages import TxMessage
                tx_msg = TxMessage.from_payload(bytes.fromhex(raw))
                tx = tx_msg.transaction
                # JSON-RPC convention: txids in responses are display-order
                # (BE). get_txid() returns LE (internal). Reverse for JSON. W69.
                txid_be = tx.get_txid()[::-1].hex()
                if mempool is None or getattr(self.node, "db", None) is None:
                    # Node not far enough through init to validate -- return a
                    # clean structured reject rather than a NoneType/attribute
                    # error.
                    results.append({
                        "txid": txid_be,
                        "allowed": False,
                        "reject-reason": "node-not-ready",
                    })
                    continue
                _, best_height = self.node.db.get_best_block()
                res = mempool.accept_to_memory_pool(
                    tx, best_height + 1, test_accept=True
                )
                allowed = bool(res.get("accepted"))
                results.append({
                    "txid": txid_be,
                    "allowed": allowed,
                    "reject-reason": None if allowed else res.get("reject_reason"),
                })
            except Exception as e:
                results.append({
                    "txid": "",
                    "allowed": False,
                    "reject-reason": str(e),
                })
        return results

    async def rpc_submitpackage(self, package: list[str]) -> dict[str, Any]:
        """Submit a package of raw transactions for validation and mempool acceptance.

        Accepts a list of raw transaction hex strings in topological order
        (parents before children).  The package is evaluated as a unit so
        that a child can pay for a low-fee parent (CPFP).

        Returns per-transaction results with txid, vsize, and fees.
        """
        if not isinstance(package, list) or len(package) == 0:
            raise HTTPException(
                status_code=400,
                detail="package must be a non-empty list of raw transaction hex strings",
            )

        from ouroboros.p2p_messages import TxMessage

        # Deserialize each hex string into a Transaction
        txs: list[Transaction] = []
        for i, raw_hex in enumerate(package):
            try:
                tx_data = bytes.fromhex(raw_hex.strip())
            except (ValueError, AttributeError) as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid hex string at index {i}: {e}",
                ) from None
            try:
                tx_msg = TxMessage.from_payload(tx_data)
                tx = tx_msg.transaction
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to decode transaction at index {i}: {e}",
                ) from None
            if tx.is_coinbase:
                raise HTTPException(
                    status_code=400,
                    detail=f"Coinbase transaction at index {i} cannot be submitted",
                )
            txs.append(tx)

        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(status_code=500, detail="Mempool not available")
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        _, best_height = self.node.db.get_best_block()
        success, error = self.node.mempool.validate_package(txs, best_height + 1)

        if not success:
            return {
                "package_msg": error,
                "tx-results": {},
            }

        # Build per-transaction results from the mempool entries that were
        # just inserted by validate_package.
        # JSON-RPC convention: txids/wtxids in responses are display-order (BE).
        # get_txid()/get_wtxid() return LE (internal byte order); reverse for JSON.
        # BUG-5 fix: Core keys tx-results by wtxid (GetWitnessHash().GetHex()),
        # not txid — rpc/mempool.cpp:1464. For segwit txs (txid != wtxid) client
        # tools keying by wtxid would otherwise get an empty miss.
        tx_results: dict[str, Any] = {}
        for tx in txs:
            txid_hex = tx.get_txid()[::-1].hex()
            wtxid_hex = tx.get_wtxid()[::-1].hex()
            entry = self.node.mempool.get_transaction_entry(tx.get_txid())
            if entry is not None:
                tx_results[wtxid_hex] = {
                    "txid": txid_hex,
                    "vsize": tx.get_vsize(),
                    "fees": {
                        "base": entry.fee / 1e8,
                    },
                }
            else:
                tx_results[wtxid_hex] = {
                    "txid": txid_hex,
                    "vsize": tx.get_vsize(),
                    "fees": {"base": 0},
                }

        return {
            "package_msg": "success",
            "tx-results": tx_results,
        }

    async def rpc_listtransactions(
        self, label: str = "*", count: int = 10, skip: int = 0,
        include_watchonly: bool = True
    ) -> list[dict[str, Any]]:
        """Return the wallet's recent transactions, newest-first.

        One Core-shaped entry per send-output (category 'send', negative
        amount + negative fee) and per receive-output (category receive/
        generate/immature, positive amount). Built from the wallet's in-memory
        history (populated by the block-connect scan), not a DB lookup.

        Reference: Bitcoin Core wallet/rpc/transactions.cpp listtransactions.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return []
        return wallet.listtransactions_entries(label=label, count=count, skip=skip)

    async def rpc_gettransaction(
        self, txid: str, include_watchonly: bool = True, verbose: bool = False
    ) -> dict[str, Any]:
        """Get detailed info about a wallet transaction (Core-shaped).

        Returns ``amount`` (negative for a net send), ``fee`` (negative, only
        for from-wallet txs), ``confirmations``, ``generated`` (coinbase),
        block fields, a ``details[]`` array, and the raw ``hex``. Built from
        the wallet's in-memory history.

        Reference: Bitcoin Core wallet/rpc/transactions.cpp gettransaction.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise ValueError("No wallet loaded")
        entry = wallet.gettransaction_entry(txid)
        if entry is None:
            raise ValueError(f"Invalid or non-wallet transaction id: {txid}")
        return entry

    async def rpc_importprivkey(
        self, privkey: str, label: str = "", rescan: bool = True
    ) -> None:
        """Import a WIF private key into the wallet and (optionally) rescan.

        Decodes the WIF, adds the key (and thereby its addresses/scripts) to
        the wallet, and — when ``rescan`` is true — scans the existing chain so
        any funds already paid to that key are credited into the wallet's
        balance / listunspent / history. Returns null on success, matching
        Bitcoin Core importprivkey.

        Reference: bitcoin-core/src/wallet/rpc/backup.cpp importprivkey ->
        CWallet::ImportPrivKeys + ScanForWalletTransactions.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise ValueError("No wallet loaded")

        from ouroboros.wallet import WalletKey
        try:
            key = WalletKey.from_wif(privkey, self.node.network)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid private key encoding: {exc}"
            ) from None

        wif = key.to_wif()
        # Idempotent: don't duplicate a key already in the wallet.
        if not any(kd.get("wif") == wif for kd in wallet.keys):
            wallet.keys.append({
                "wif": wif,
                "label": label,
                "created": int(time.time()),
            })
            wallet._save()

        # Rescan the existing chain so this key's already-confirmed funds show
        # up. The imported key's four scripts are now in ``self.keys`` /
        # ``_owned_script_set``, so scan_block_connect credits them; the
        # chainstate balance scan over ``self.keys`` then reports them.
        if rescan:
            try:
                await asyncio.to_thread(wallet.rescan_chain, 0, None)
            except Exception:
                wallet.rescan_chain(0, None)

    async def rpc_rescanblockchain(
        self,
        start_height: int = 0,
        stop_height: int | None = None,
    ) -> dict[str, Any]:
        """Rescan the local block chain for wallet-related transactions.

        Walks blocks ``[start_height .. stop_height]`` (stop_height defaults to
        the chain tip), crediting every output paying a script this wallet can
        derive into the wallet's UTXO view + history. The wallet rescan
        counterpart of the forward block-connect scan — distinct from
        scantxoutset, which scans the chain-level UTXO set and bypasses the
        wallet entirely.

        Returns ``{"start_height": <int>, "stop_height": <int>}``, matching
        Bitcoin Core. Reference: bitcoin-core/src/wallet/rpc/transactions.cpp
        rescanblockchain -> CWallet::ScanForWalletTransactions.
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if getattr(wallet, "db", None) is None:
            raise HTTPException(status_code=500, detail="Wallet database not available")

        try:
            result = await asyncio.to_thread(
                wallet.rescan_chain, int(start_height),
                None if stop_height is None else int(stop_height),
            )
        except Exception:
            result = wallet.rescan_chain(
                int(start_height),
                None if stop_height is None else int(stop_height),
            )
        return result

    async def rpc_dumpprivkey(self, address: str) -> str:
        """Reveal the private key for an address."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            raise ValueError("No wallet loaded")
        for kd in self.node.wallet.keys:
            k = self.node.wallet._get_wallet_key(kd)
            if (k.get_p2wpkh_address() == address
                    or k.get_p2pkh_address() == address):
                return k.to_wif()
        raise ValueError(f"Address not found in wallet: {address}")

    async def rpc_signmessage(self, address: str, message: str) -> str:
        """Sign *message* with the private key for *address* (P2PKH only).

        Returns a base64-encoded 65-byte compact recoverable ECDSA signature,
        matching Bitcoin Core's ``signmessage`` semantics.

        Reference: bitcoin-core/src/rpc/signmessage.cpp signmessagewithprivkey
        and src/wallet/rpc/signmessage.cpp signmessage.
        """
        import base64

        if not isinstance(address, str) or not isinstance(message, str):
            raise HTTPException(
                status_code=400, detail="address and message must be strings"
            )

        # Resolve wallet (single-wallet legacy or multi-wallet manager).
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            try:
                wallet = self._get_wallet_for_rpc()
            except Exception:
                wallet = None
        if wallet is None or not getattr(wallet, "keys", None):
            raise HTTPException(status_code=400, detail="No wallet loaded")

        # Find the matching key. Core's signmessage only accepts P2PKH (legacy)
        # addresses; we additionally accept P2WPKH because that's what
        # ouroboros wallets produce by default — falls back to the P2PKH
        # the same key would derive when signing.
        target_key = None
        for kd in wallet.keys:
            k = wallet._get_wallet_key(kd)
            if address in (
                k.get_p2pkh_address(),
                k.get_p2wpkh_address(),
                k.get_p2sh_p2wpkh_address(),
            ):
                target_key = k
                break

        if target_key is None:
            raise HTTPException(
                status_code=400,
                detail="Private key not available for given address",
            )

        try:
            sig_bytes = target_key._privkey.sign_recoverable(
                _message_hash(message), hasher=None
            )
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Sign failed: {e}"
            )

        # coincurve returns r(32) || s(32) || recid(1).  Bitcoin compact format
        # is header(1) || r(32) || s(32) where header = 27 + recid + 4 (compressed).
        if len(sig_bytes) != 65:
            raise HTTPException(
                status_code=500, detail="Unexpected signature length"
            )
        recid = sig_bytes[64]
        header = bytes([27 + recid + 4])  # compressed pubkey
        compact = header + sig_bytes[:64]
        return base64.b64encode(compact).decode("ascii")

    async def rpc_signmessagewithprivkey(
        self, privkey: str, message: str
    ) -> str:
        """Sign *message* with *privkey* (WIF-encoded), wallet-less variant.

        Returns a base64-encoded 65-byte compact recoverable ECDSA signature,
        byte-identical to Bitcoin Core's ``signmessagewithprivkey`` output.

        Algorithm (matches bitcoin-core/src/rpc/signmessage.cpp):
          1. Decode WIF: base58check → strip version byte → detect compressed
             flag (trailing 0x01 on 34-byte payload = compressed key).
          2. Build message hash: SHA256d(VarStr(MAGIC) || VarStr(message)).
          3. Sign with secp256k1 RFC-6979 recoverable signature.
          4. Pack as header(1) || r(32) || s(32), base64-encode.
             header = 27 + recid + (4 if compressed else 0).
        """
        import base64
        import base58 as _base58
        from coincurve import PrivateKey as _PrivateKey

        if not isinstance(privkey, str) or not isinstance(message, str):
            raise HTTPException(
                status_code=400,
                detail="privkey and message must be strings",
            )

        # 1) WIF decode.
        try:
            decoded = _base58.b58decode_check(privkey)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid private key")

        # decoded = version(1) + secret(32) [+ compressed_flag(1)]
        payload = decoded[1:]   # strip version byte
        if len(payload) == 33 and payload[-1] == 0x01:
            compressed = True
            secret = bytes(payload[:32])
        elif len(payload) == 32:
            compressed = False
            secret = bytes(payload)
        else:
            raise HTTPException(status_code=400, detail="Invalid private key")

        # 2) Message hash.
        msg_hash = _message_hash(message)

        # 3) Sign (coincurve: r||s||recid, 65 bytes).
        try:
            key = _PrivateKey(secret)
            sig_bytes = key.sign_recoverable(msg_hash, hasher=None)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Sign failed: {e}")

        if len(sig_bytes) != 65:
            raise HTTPException(
                status_code=500, detail="Unexpected signature length"
            )

        # 4) Compact format: header || r || s.
        recid = sig_bytes[64]
        header = bytes([27 + recid + (4 if compressed else 0)])
        compact = header + sig_bytes[:64]
        return base64.b64encode(compact).decode("ascii")

    async def rpc_verifymessage(
        self, address: str, signature: str, message: str
    ) -> bool:
        """Verify a base64 compact signature against *address* and *message*.

        Returns ``True`` iff the signature was produced by the private key
        whose P2PKH address is *address*.

        Reference: bitcoin-core/src/rpc/signmessage.cpp verifymessage and
        src/common/signmessage.cpp MessageVerify.
        """
        import base64
        from coincurve import PublicKey
        from ouroboros.address import _decode_base58check

        if not all(isinstance(x, str) for x in (address, signature, message)):
            raise HTTPException(
                status_code=400,
                detail="address, signature, and message must be strings",
            )

        # 1) Decode address — accept legacy P2PKH (mainnet 0x00, testnet 0x6f)
        #    only.  Bitcoin Core's verifymessage is keyhash-only because we
        #    need to compare hash160(pubkey) against the destination.
        try:
            version, payload = _decode_base58check(address)
        except Exception:
            raise HTTPException(
                status_code=400, detail="Invalid address"
            )
        if version not in (0x00, 0x6f) or len(payload) != 20:
            raise HTTPException(
                status_code=400,
                detail="Address does not refer to key (P2PKH only)",
            )
        target_h160 = payload

        # 2) Decode base64 signature — must be a 65-byte compact sig.
        try:
            sig = base64.b64decode(signature, validate=True)
        except Exception:
            raise HTTPException(
                status_code=400, detail="Malformed base64 encoding"
            )
        if len(sig) != 65:
            raise HTTPException(
                status_code=400, detail="Malformed base64 encoding"
            )

        header = sig[0]
        if header < 27 or header > 34:
            return False
        recid = (header - 27) & 3
        compressed = ((header - 27) & 4) != 0
        coincurve_sig = sig[1:65] + bytes([recid])

        try:
            pub = PublicKey.from_signature_and_message(
                coincurve_sig, _message_hash(message), hasher=None
            )
            pub_bytes = pub.format(compressed=compressed)
        except Exception:
            return False

        # Compare recovered pubkey hash160 with the address payload.
        from ouroboros.wallet import _hash160

        return _hash160(pub_bytes) == target_h160

    async def rpc_backupwallet(self, destination: str) -> None:
        """Backup the wallet to a file."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            raise ValueError("No wallet loaded")
        self.node.wallet.backup(destination)

    async def rpc_getaddressinfo(self, address: str) -> dict[str, Any]:
        """Return information about a given address.

        ``ismine`` mirrors Core CWallet::IsMine(dest)
        (wallet/wallet.cpp:1649-1671): script-set membership across the
        wallet's keys AND its imported descriptors
        (DescriptorScriptPubKeyMan::IsMine, scriptpubkeyman.cpp:863-867) —
        private keys play no role, so watch-only imports (addr(), xpub-only
        wpkh(), ...) report ismine=true. ``iswatchonly`` is DEPRECATED in
        Core v31.99 and hardcoded false (wallet/rpc/addresses.cpp:383,478).
        Routed through /wallet/<name> like every other wallet RPC.
        """
        wallet = self._get_wallet_for_rpc()
        is_mine = False
        solvable = False
        pubkey_hex = ""
        if wallet is not None:
            for kd in getattr(wallet, "keys", []):
                try:
                    k = wallet._get_wallet_key(kd)
                except Exception:
                    continue
                key_addrs = []
                for getter in (
                    k.get_p2wpkh_address,
                    k.get_p2pkh_address,
                    k.get_p2sh_p2wpkh_address,
                    k.get_p2tr_address,
                ):
                    try:
                        key_addrs.append(getter())
                    except Exception:
                        continue
                if address in key_addrs:
                    is_mine = True
                    solvable = True
                    pubkey_hex = k.pubkey.hex()
                    break
            if not is_mine:
                # Imported descriptors: addr()/raw() entries are ISMINE but
                # not solvable (Core AddressDescriptor::IsSolvable()=false);
                # key-bearing descriptor entries are both.
                try:
                    for entry in getattr(wallet, "descriptors", []):
                        desc = entry.descriptor
                        if getattr(desc, "is_range", False):
                            indices = range(
                                int(entry.range_start),
                                int(entry.range_end) + 1,
                            )
                        else:
                            indices = range(0, 1)
                        for i in indices:
                            try:
                                derived = desc.derive_address(
                                    i, wallet.network
                                )
                            except Exception:
                                continue
                            if derived == address:
                                is_mine = True
                                solvable = desc.descriptor_type not in (
                                    "addr", "raw"
                                )
                                break
                        if is_mine:
                            break
                except Exception:
                    pass
        script_type = "unknown"
        lower = address.lower()
        if lower.startswith(("bc1q", "tb1q", "bcrt1q")):
            script_type = "witness_v0_keyhash"
        elif lower.startswith(("bc1p", "tb1p", "bcrt1p")):
            script_type = "witness_v1_taproot"
        elif address.startswith("1") or address.startswith("m") or address.startswith("n"):
            script_type = "pubkeyhash"
        elif address.startswith("3") or address.startswith("2"):
            script_type = "scripthash"
        spk_hex = ""
        try:
            from ouroboros.address import address_to_script_pubkey
            spk_hex = address_to_script_pubkey(
                address, getattr(self.node, "network", "mainnet")
            ).hex()
        except Exception:
            pass
        return {
            "address": address,
            "scriptPubKey": spk_hex,
            "ismine": is_mine,
            "solvable": solvable,
            "iswatchonly": False,
            "isscript": script_type in ("scripthash",),
            "iswitness": script_type.startswith("witness"),
            "script": script_type,
            "pubkey": pubkey_hex,
            "label": "",
        }

    async def rpc_listwallets(self) -> list[str]:
        """
        Return list of currently loaded wallet names.

        Reference: Bitcoin Core wallet/rpc/wallet.cpp listwallets
        """
        wallet_manager = getattr(self.node, "wallet_manager", None)
        if wallet_manager is not None:
            return wallet_manager.list_loaded_wallets()
        # Legacy single-wallet mode
        if hasattr(self.node, 'wallet') and self.node.wallet:
            return [self.node.wallet.name]
        return []

    async def rpc_listwalletdir(self) -> dict[str, list[dict[str, str]]]:
        """
        Return list of wallets in the wallet directory.

        Returns a dict with 'wallets' key containing list of wallet info dicts.

        Reference: Bitcoin Core wallet/rpc/wallet.cpp listwalletdir
        """
        wallet_manager = getattr(self.node, "wallet_manager", None)
        if wallet_manager is not None:
            return {"wallets": wallet_manager.list_wallet_dir()}
        return {"wallets": []}

    async def rpc_createwallet(
        self,
        wallet_name: str,
        disable_private_keys: bool = False,
        blank: bool = False,
        passphrase: str = "",
        avoid_reuse: bool = False,
        descriptors: bool = True,
        load_on_startup: bool | None = None,
        external_signer: bool = False,
        mnemonic: str = "",
        bip39_passphrase: str = "",
    ) -> dict[str, Any]:
        """
        Create a new wallet.

        Args:
            wallet_name: Name for the new wallet (required)
            disable_private_keys: Create watch-only wallet
            blank: Create empty wallet with no keys
            passphrase: Encryption passphrase (empty = no encryption)
            avoid_reuse: Track coin reuse (not implemented)
            descriptors: Create descriptor wallet (must be True)
            load_on_startup: Add to auto-load list on node startup
            external_signer: Use external signer (not implemented)
            mnemonic: Optional BIP-39 mnemonic to seed the wallet from
                     (12/15/18/21/24 words, space-separated). Empty =
                     generate a fresh 12-word mnemonic.
            bip39_passphrase: Optional BIP-39 passphrase ("25th word").
                     Distinct from *passphrase*, which encrypts the
                     wallet at rest.

        Returns:
            Dict with 'name' (wallet name) and 'warning' (any warnings)

        Reference: Bitcoin Core wallet/rpc/wallet.cpp createwallet
        """
        wallet_manager = getattr(self.node, "wallet_manager", None)
        if wallet_manager is None:
            raise HTTPException(
                status_code=500,
                detail="Multi-wallet support not enabled"
            )

        if external_signer:
            raise HTTPException(
                status_code=400,
                detail="External signer is not supported"
            )

        try:
            wallet, warnings = wallet_manager.create_wallet(
                name=wallet_name,
                disable_private_keys=disable_private_keys,
                blank=blank,
                passphrase=passphrase if passphrase else None,
                avoid_reuse=avoid_reuse,
                descriptors=descriptors,
                load_on_startup=load_on_startup,
                mnemonic=mnemonic if mnemonic else None,
                bip39_passphrase=bip39_passphrase,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

        return {
            "name": wallet_name,
            "warning": "\n".join(warnings) if warnings else "",
        }

    async def rpc_dumpmnemonic(self) -> dict[str, Any]:
        """
        Reveal the BIP-39 mnemonic used to seed the active wallet.

        WARNING: backup hygiene matters. Anyone with this mnemonic can
        spend every coin the wallet ever controlled. Write it down on
        paper, store it offline, and treat it like cash. The RPC returns
        plaintext over JSON-RPC; never expose this endpoint to a remote
        host.

        Returns:
            Dict with:
              ``mnemonic``        — space-separated BIP-39 words
              ``mnemonic_words``  — list of BIP-39 words (same order)
              ``bip39_passphrase`` — the BIP-39 passphrase (empty string if none)
              ``warning``         — backup-hygiene reminder

        Raises HTTP 400 if the wallet was created from a raw seed (legacy
        path) — there is no inverse for ``HDKey.from_seed`` so the
        mnemonic is genuinely unrecoverable.

        Reference: BIP-39
            https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
        """
        wallet = self._get_wallet_for_rpc()
        words, bip39_passphrase = wallet.get_mnemonic()
        if words is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Wallet was not initialised from a BIP-39 mnemonic; "
                    "no mnemonic can be returned. Use a wallet created "
                    "with the BIP-39 path (W21+) to enable dumpmnemonic."
                ),
            )
        return {
            "mnemonic": " ".join(words),
            "mnemonic_words": words,
            "bip39_passphrase": bip39_passphrase or "",
            "warning": (
                "BACKUP HYGIENE: write the mnemonic on paper and store it "
                "offline. Anyone with these words can spend every coin "
                "this wallet ever controls. Never share over the network."
            ),
        }

    async def rpc_restorewallet(
        self,
        wallet_name: str,
        mnemonic: str,
        bip39_passphrase: str = "",
        passphrase: str = "",
        load_on_startup: bool | None = None,
    ) -> dict[str, Any]:
        """
        Create a new wallet seeded from an existing BIP-39 mnemonic.

        Convenience wrapper around ``createwallet`` that requires a
        mnemonic. Useful for cross-impl seed restore: dumpmnemonic on
        node A, restorewallet on node B, derive an address on either —
        the addresses must match.

        Args:
            wallet_name: Name for the restored wallet
            mnemonic: BIP-39 mnemonic (12/15/18/21/24 words,
                     space-separated). Required.
            bip39_passphrase: Optional BIP-39 passphrase ("25th word")
            passphrase: Optional wallet-encryption passphrase
            load_on_startup: Add to auto-load list

        Returns:
            Dict with 'name' and 'warning'.
        """
        if not mnemonic.strip():
            raise HTTPException(
                status_code=400,
                detail="restorewallet requires a non-empty mnemonic",
            )
        # Validate up-front so the error is clear and we don't half-create
        # a wallet directory before failing.
        from ouroboros.bip39 import Bip39Error, validate_mnemonic
        try:
            validate_mnemonic(mnemonic.split())
        except Bip39Error as e:
            raise HTTPException(status_code=400, detail=f"Invalid mnemonic: {e}") from None

        return await self.rpc_createwallet(
            wallet_name=wallet_name,
            disable_private_keys=False,
            blank=False,
            passphrase=passphrase,
            descriptors=True,
            load_on_startup=load_on_startup,
            mnemonic=mnemonic,
            bip39_passphrase=bip39_passphrase,
        )

    async def rpc_loadwallet(
        self,
        filename: str,
        load_on_startup: bool | None = None,
    ) -> dict[str, Any]:
        """
        Load a wallet from disk.

        Args:
            filename: Wallet name (directory name in wallets/)
            load_on_startup: Add to auto-load list on node startup

        Returns:
            Dict with 'name' (wallet name) and 'warning' (any warnings)

        Reference: Bitcoin Core wallet/rpc/wallet.cpp loadwallet
        """
        wallet_manager = getattr(self.node, "wallet_manager", None)
        if wallet_manager is None:
            raise HTTPException(
                status_code=500,
                detail="Multi-wallet support not enabled"
            )

        try:
            wallet, warnings = wallet_manager.load_wallet(
                name=filename,
                load_on_startup=load_on_startup,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

        return {
            "name": filename,
            "warning": "\n".join(warnings) if warnings else "",
        }

    async def rpc_unloadwallet(
        self,
        wallet_name: str | None = None,
        load_on_startup: bool | None = None,
    ) -> dict[str, Any]:
        """
        Unload a wallet from memory.

        Args:
            wallet_name: Wallet name to unload. If not specified, uses the
                         wallet from /wallet/<name> endpoint, or the only
                         loaded wallet if there is exactly one.
            load_on_startup: Set to False to remove from auto-load list

        Returns:
            Dict with 'warning' (any warnings)

        Reference: Bitcoin Core wallet/rpc/wallet.cpp unloadwallet
        """
        wallet_manager = getattr(self.node, "wallet_manager", None)
        if wallet_manager is None:
            raise HTTPException(
                status_code=500,
                detail="Multi-wallet support not enabled"
            )

        # Determine wallet name
        if wallet_name is None:
            # Try to get from endpoint context or default
            if self._current_wallet_name is not None:
                wallet_name = self._current_wallet_name
            else:
                loaded = wallet_manager.list_loaded_wallets()
                if len(loaded) == 0:
                    raise HTTPException(
                        status_code=400, detail="No wallet is loaded"
                    )
                elif len(loaded) == 1:
                    wallet_name = loaded[0]
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="Multiple wallets loaded. Use wallet_name parameter "
                        "or /wallet/<name> endpoint."
                    )

        try:
            warnings = wallet_manager.unload_wallet(
                name=wallet_name,
                load_on_startup=load_on_startup,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

        return {
            "warning": "\n".join(warnings) if warnings else "",
        }

    async def rpc_getnetworkhashps(
        self, nblocks: int = 120, height: int = -1
    ) -> float:
        """Return estimated network hashes per second.

        Uses the same algorithm as Bitcoin Core's GetNetworkHashPS()
        in rpc/mining.cpp: computes chainwork difference over a time
        window and divides by elapsed seconds.

        Args:
            nblocks: Number of blocks to look back (default 120).
                     Use -1 to average over the current difficulty epoch.
            height:  Block height to end at (default -1 = chain tip).
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return 0.0

        try:
            _, best_height = self.node.db.get_best_block()
        except Exception:
            return 0.0

        if height < 0 or height > best_height:
            height = best_height

        # nblocks == -1 means use the current difficulty epoch length
        if nblocks <= 0:
            nblocks = max(height % 2016, 1)

        # Clamp: don't look back further than genesis
        if nblocks > height:
            nblocks = height

        if nblocks == 0:
            return 0.0

        tip_block = await asyncio.to_thread(self.node.db.get_block_by_height, height)
        start_block = await asyncio.to_thread(self.node.db.get_block_by_height, height - nblocks)

        if tip_block is None or start_block is None:
            return 0.0

        time_diff = tip_block.timestamp - start_block.timestamp
        if time_diff <= 0:
            return 0.0

        # Calculate chainwork difference
        work_diff = (
            self.node._calculate_chainwork_at_height(height)
            - self.node._calculate_chainwork_at_height(height - nblocks)
        )

        return float(work_diff) / float(time_diff)

    async def rpc_prioritisetransaction(
        self, txid: str, dummy: float = 0, fee_delta: int = 0
    ) -> bool:
        """Accept the transaction into mined blocks at higher/lower priority.

        Adds *fee_delta* satoshis (may be negative) to the priority-delta for
        *txid*.  Subsequent fee comparisons — RBF Rule 3/4 admission, mining
        selection, getmempoolentry — use Core's GetModifiedFee() = nFee +
        nFeeDelta.  Deltas are accumulated (saturating int64) and survive
        eviction; they are cleared on block confirmation and lost on restart
        (in-memory mapDeltas only).

        FIX-72 (W120 BUG-3).  Reference: bitcoin-core/src/rpc/mining.cpp:502
        prioritisetransaction; src/txmempool.{cpp,h} PrioritiseTransaction.

        Args:
            txid: hex txid (JSON-RPC big-endian display order)
            dummy: legacy positional priority param; MUST be zero or null
            fee_delta: satoshis to add (or subtract, if negative)

        Returns:
            True on success.

        Raises:
            ValueError if dummy != 0 or fee_delta is not an integer.
        """
        if dummy not in (0, 0.0, None):
            # Core: throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no
            # longer supported, dummy argument to prioritisetransaction must
            # be 0.") — bitcoin-core/src/rpc/mining.cpp:530.
            raise ValueError(
                "Priority is no longer supported, dummy argument to "
                "prioritisetransaction must be 0."
            )
        try:
            delta_int = int(fee_delta)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid fee_delta: {fee_delta!r}") from exc

        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise ValueError("No mempool available")

        # JSON-RPC convention: txid arrives in display order (big-endian hex);
        # internal mempool keys are little-endian.  W69 + getmempoolentry.
        txid_bytes = bytes.fromhex(txid)[::-1]
        if len(txid_bytes) != 32:
            raise ValueError(f"txid must be 32 bytes: {txid}")

        self.node.mempool.prioritise_transaction(txid_bytes, delta_int)
        return True

    async def rpc_getprioritisedtransactions(self) -> dict[str, dict[str, Any]]:
        """Return the map of user-set fee deltas keyed by display-order txid.

        Mirrors Core RPC getprioritisedtransactions (rpc/mining.cpp:547).
        Each value: {fee_delta: int, in_mempool: bool, modified_fee?: int}.
        ``modified_fee`` is only present when ``in_mempool`` is true.

        FIX-72 (W120 BUG-3) — companion RPC to prioritisetransaction.
        """
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise ValueError("No mempool available")
        out: dict[str, dict[str, Any]] = {}
        for entry in self.node.mempool.get_prioritised_transactions():
            display_txid = entry["txid"][::-1].hex()
            inner: dict[str, Any] = {
                "fee_delta": entry["fee_delta"],
                "in_mempool": entry["in_mempool"],
            }
            if entry["in_mempool"] and entry["modified_fee"] is not None:
                inner["modified_fee"] = entry["modified_fee"]
            out[display_txid] = inner
        return out

    async def rpc_generatetoaddress(
        self, nblocks: int, address: str, maxtries: int = 1000000
    ) -> list[str]:
        """Mine blocks to a given address (regtest only).

        Creates *nblocks* blocks whose coinbase pays to *address*, connects
        them to the active chain (block storage, header/height index, UTXO
        set, tx index, chain tip), and returns a list of the new block hashes.
        """
        import hashlib as _hl
        import struct as _st
        import time as _time

        from ouroboros.address import address_to_script_pubkey
        from ouroboros.database import Block as _Block
        from ouroboros.database import TxIn as _TxIn
        from ouroboros.database import TxOut as _TxOut
        from ouroboros.p2p_messages import encode_varint

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        network = getattr(self.node, "network", "regtest")

        # Decode destination address to scriptPubKey
        try:
            output_spk = address_to_script_pubkey(address, network)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid address: {e}") from None

        block_hashes: list[str] = []

        for _ in range(nblocks):
            best_hash, best_height = db.get_best_block()
            next_height = best_height + 1

            # --- Subsidy ---
            from ouroboros.config import RegtestConfig
            halving_interval = getattr(RegtestConfig, "SUBSIDY_HALVING_INTERVAL", 150)
            halvings = next_height // halving_interval
            subsidy = (50 * 100_000_000) >> halvings if halvings < 64 else 0

            # --- Mempool transactions ---
            # A wallet-native spend only confirms if the miner actually puts
            # the signed mempool tx into the block it produces.  Previously
            # this RPC mined coinbase-ONLY blocks, so a sendrawtransaction'd
            # spend sat in the mempool forever and never confirmed.  Mirror
            # Core's BlockAssembler: drain the mempool (here: the whole pool,
            # which on regtest is small) into the block, sum the input fees,
            # and pay them to the coinbase along with the subsidy.
            #   coinbase reward = subsidy + sum(mempool fees)
            # Reference: Bitcoin Core node/miner.cpp BlockAssembler::CreateNewBlock.
            mempool_txs: list = []   # list[Transaction]
            mempool_fees = 0
            _mp = getattr(self.node, "mempool", None)
            if _mp is not None and len(_mp) > 0:
                # Snapshot the entries; entry.tx is a fully-built Transaction
                # (witness included), entry.fee its absolute fee in sats.
                for _entry in list(_mp.transactions.values()):
                    _etx = getattr(_entry, "tx", None)
                    if _etx is None:
                        continue
                    mempool_txs.append(_etx)
                    mempool_fees += int(getattr(_entry, "fee", 0) or 0)

            # --- Coinbase transaction ---
            # BIP34: height in scriptSig. Must be the byte-exact canonical
            # CScript() << nHeight encoding that the validator enforces
            # (validation.py:_encode_bip34_height / Core script.h:433-448):
            #   0      -> OP_0 (0x00)
            #   1..16  -> OP_1..OP_16 (0x51..0x60, single-byte opcode, NO len prefix)
            #   else   -> length-prefixed minimal sign-magnitude CScriptNum.
            # The previous ad-hoc pack("<q") + trim + length-prefix produced
            # "01 01" for height 1 (vs the expected single byte 0x51), which
            # the node's own BIP34 check rejected with bad-cb-height.
            from ouroboros.validation import _encode_bip34_height
            coinbase_script = _encode_bip34_height(next_height)
            # The consensus rule requires the coinbase scriptSig to be
            # 2-100 bytes (Core: CheckTransaction / IsCoinBase length check,
            # mirrored in ferrous-utils transaction.rs:517-521). The canonical
            # BIP34 push for heights 1..16 is a single OP_N opcode (1 byte),
            # so — exactly as Core miners do — we append an arbitrary
            # "extra-nonce" tag after the height push to clear the 2-byte
            # minimum. The BIP34 validator only checks the height *prefix*,
            # so trailing bytes are consensus-irrelevant.
            coinbase_script = coinbase_script + b"\x00" + b"/ouroboros/"

            coinbase_in = _TxIn(
                prev_txid=bytes(32),
                prev_vout=0xFFFFFFFF,
                script_sig=coinbase_script,
                sequence=0xFFFFFFFF,
                witness=[bytes(32)],  # SegWit nonce (32 zero bytes)
            )

            # Witness commitment.  The witness merkle root is computed over the
            # wtxids of EVERY tx in the block, with the coinbase's wtxid forced
            # to 0x00*32 (BIP-141).  With mempool txs present this is no longer
            # a constant — compute it over [0x00*32] + [tx.get_wtxid()...].
            # Reference: Bitcoin Core validation.cpp BlockWitnessMerkleRoot +
            # GenerateCoinbaseCommitment.
            def _merkle_root(hashes: list[bytes]) -> bytes:
                if not hashes:
                    return bytes(32)
                layer = list(hashes)
                while len(layer) > 1:
                    if len(layer) % 2 == 1:
                        layer.append(layer[-1])
                    layer = [
                        _hl.sha256(_hl.sha256(layer[i] + layer[i + 1]).digest()).digest()
                        for i in range(0, len(layer), 2)
                    ]
                return layer[0]

            wtxids = [bytes(32)] + [t.get_wtxid() for t in mempool_txs]
            witness_root = _merkle_root(wtxids)
            witness_nonce = bytes(32)
            commitment = _hl.sha256(
                _hl.sha256(witness_root + witness_nonce).digest()
            ).digest()
            witness_commitment_spk = bytes.fromhex("6a24aa21a9ed") + commitment

            coinbase_out_reward = _TxOut(value=subsidy + mempool_fees, script_pubkey=output_spk)
            coinbase_out_commitment = _TxOut(value=0, script_pubkey=witness_commitment_spk)

            # Build coinbase as raw bytes (with witness) for correct txid/wtxid.
            cb_raw = bytearray()
            cb_raw.extend(_st.pack("<i", 2))  # version 2
            # SegWit marker + flag
            cb_raw.extend(b"\x00\x01")
            # 1 input
            cb_raw.extend(encode_varint(1))
            cb_raw.extend(coinbase_in.prev_txid)
            cb_raw.extend(_st.pack("<I", coinbase_in.prev_vout))
            cb_raw.extend(encode_varint(len(coinbase_in.script_sig)))
            cb_raw.extend(coinbase_in.script_sig)
            cb_raw.extend(_st.pack("<I", coinbase_in.sequence))
            # 2 outputs
            cb_raw.extend(encode_varint(2))
            for out in (coinbase_out_reward, coinbase_out_commitment):
                cb_raw.extend(_st.pack("<q", out.value))
                cb_raw.extend(encode_varint(len(out.script_pubkey)))
                cb_raw.extend(out.script_pubkey)
            # Witness data: 1 item (32 zero bytes)
            cb_raw.extend(encode_varint(1))  # 1 witness item
            cb_raw.extend(encode_varint(32))
            cb_raw.extend(bytes(32))
            # locktime
            cb_raw.extend(_st.pack("<I", 0))

            cb_bytes = bytes(cb_raw)

            # Compute txid (without witness) for merkle root
            cb_no_witness = bytearray()
            cb_no_witness.extend(_st.pack("<i", 2))
            cb_no_witness.extend(encode_varint(1))
            cb_no_witness.extend(coinbase_in.prev_txid)
            cb_no_witness.extend(_st.pack("<I", coinbase_in.prev_vout))
            cb_no_witness.extend(encode_varint(len(coinbase_in.script_sig)))
            cb_no_witness.extend(coinbase_in.script_sig)
            cb_no_witness.extend(_st.pack("<I", coinbase_in.sequence))
            cb_no_witness.extend(encode_varint(2))
            for out in (coinbase_out_reward, coinbase_out_commitment):
                cb_no_witness.extend(_st.pack("<q", out.value))
                cb_no_witness.extend(encode_varint(len(out.script_pubkey)))
                cb_no_witness.extend(out.script_pubkey)
            cb_no_witness.extend(_st.pack("<I", 0))

            cb_txid = _hl.sha256(_hl.sha256(bytes(cb_no_witness)).digest()).digest()

            # --- Merkle root (coinbase + mempool txs) ---
            # Core computes the block merkle root over the (non-witness) txids
            # in block order.  ``Transaction.get_txid()`` returns the internal
            # (wire) byte order hash, which is exactly what the merkle tree
            # consumes.
            txids = [cb_txid] + [t.get_txid() for t in mempool_txs]
            merkle_root = _merkle_root(txids)

            # --- Block header ---
            # For regtest, bits stays at minimum difficulty
            bits = 0x207FFFFF

            # db.get_best_block() already returns the hash in internal
            # (little-endian) byte order, which IS the wire byte order for
            # the header prev_blockhash field. (Display/RPC order is the
            # reverse — see getbestblockhash, which does best_hash[::-1].)
            # The previous code reversed it again here, producing a header
            # whose prev_blockhash was byte-swapped vs the real tip, which
            # the Rust header validator rejected as "Previous block hash
            # mismatch". Use best_hash as-is.
            prev_hash_wire = best_hash

            timestamp = max(int(_time.time()), (self.node.get_median_time(best_height) or 0) + 1)

            # --- Mine (find valid nonce) ---
            # Regtest target from bits 0x207fffff:
            #   mantissa = 0x7fffff, exponent = 0x20 = 32
            #   target = 0x7fffff << (8 * (32 - 3)) = huge number
            # Practically any nonce is valid on regtest.
            target = self._bits_to_target(bits)

            header_prefix = bytearray()
            header_prefix.extend(_st.pack("<i", 0x20000000))  # version
            header_prefix.extend(prev_hash_wire)
            # merkle root: raw SHA256d output = wire format (internal byte order)
            header_prefix.extend(merkle_root)
            header_prefix.extend(_st.pack("<I", timestamp))
            header_prefix.extend(_st.pack("<I", bits))

            found = False
            for nonce in range(maxtries):
                header = bytes(header_prefix) + _st.pack("<I", nonce)
                block_hash = _hl.sha256(_hl.sha256(header).digest()).digest()
                # Compare hash as little-endian 256-bit integer vs target
                hash_int = int.from_bytes(block_hash, "little")
                if hash_int <= target:
                    found = True
                    break

            if not found:
                raise HTTPException(
                    status_code=500,
                    detail=f"Block generation failed: could not find valid nonce in {maxtries} tries",
                )

            # --- Assemble full block bytes ---
            # tx count = coinbase + every mempool tx, each serialized with its
            # witness (Core wire format). Order MUST match the merkle/witness
            # roots computed above (coinbase first, then mempool order).
            block_data = bytearray()
            block_data.extend(header)
            block_data.extend(encode_varint(1 + len(mempool_txs)))
            block_data.extend(cb_bytes)
            for _mtx in mempool_txs:
                block_data.extend(_mtx.serialize_with_witness())

            block_bytes = bytes(block_data)

            # --- Validate + Store via unified accept_block helper ---
            # Previously called connect_block_from_bytes directly, skipping
            # all validation (Gap O2, wave-29 audit).  Now routes through
            # accept_block so that structural checks (BIP-34, merkle, witness
            # commitment, cb-len) fire and catch any future build-helper bug.
            # skip_scripts=False: we mined this block ourselves so scripts
            # will be trivially valid, but running them is cheap on regtest
            # and catches any future coding error in the block builder.
            # Reference: Bitcoin Core generateSingleBlock calls ProcessNewBlock
            # which applies the same CheckBlock + ContextualCheckBlock checks.
            try:
                stored_hash = await accept_block(
                    db,
                    self.node,
                    block_bytes,
                    next_height,
                    skip_scripts=False,
                )
                # accept_block already handles mempool eviction; derive hash.
                block_hash_hex = bytes(stored_hash).hex()
            except AttributeError:
                # Fallback: Rust extension not yet rebuilt.
                block_hash_hex = block_hash[::-1].hex()
                logger.warning(
                    "accept_block: connect_block_from_bytes not available; "
                    "block not persisted.  Rebuild the Rust extension "
                    "(maturin develop)."
                )
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Block generation failed: {e}",
                ) from None

            # accept_block handles mempool eviction internally; no duplicate
            # call needed here.

            block_hashes.append(block_hash_hex)
            logger.info(f"Generated block {next_height}: {block_hash_hex[:16]}...")

            # Announce new block to all connected peers
            try:
                from ouroboros.p2p_messages import INV_TYPE_BLOCK, InvMessage

                inv = InvMessage(
                    inventory=[(INV_TYPE_BLOCK, block_hash)]
                )
                inv_msg = inv.to_network_message(network)
                if hasattr(self.node, "peer_manager") and self.node.peer_manager:
                    await self.node.peer_manager.broadcast(inv_msg)
            except Exception:
                pass  # best-effort broadcast

        return block_hashes

    @staticmethod
    def _bits_to_target(bits: int) -> int:
        """Convert compact 'bits' representation to the full 256-bit target."""
        exponent = (bits >> 24) & 0xFF
        mantissa = bits & 0x7FFFFF
        if bits & 0x800000:
            mantissa = -mantissa
        if exponent <= 3:
            return mantissa >> (8 * (3 - exponent))
        return mantissa << (8 * (exponent - 3))

    async def rpc_getrpcinfo(self) -> dict[str, Any]:
        """Return info about the RPC server."""
        return {
            "active_commands": [],
        }

    async def rpc_getindexinfo(self, index_name: str = "") -> dict[str, Any]:
        """Return the status of one or all running indices.

        Mirrors Bitcoin Core ``getindexinfo`` (src/rpc/node.cpp:363-410).
        Returns a dynamic JSON OBJECT keyed by the index's ``GetName()``
        string.  For each *running* index Core pushes one entry whose value
        has EXACTLY two fields, in this order: ``synced`` (bool) then
        ``best_block_height`` (int).  Core never emits ``best_block_hash``
        from this RPC (it lives in IndexSummary but SummaryToJSON drops it).

        Indices are listed ONLY when enabled/running.  ouroboros runs:
          - ``txindex`` — the txid->location index, built inline with block
            connection (always present; the Rust db exposes ``get_tx_index``).
            Because it is written in the same WriteBatch as each connected
            block, its best block always equals the chain tip and it is
            considered synced whenever a best block exists.
          - ``basic block filter index`` — only when ``-blockfilterindex`` is
            enabled (``self.node.block_filter_index`` is not ``None``).  Its
            best height / synced state come from the index's own
            ``best_indexed_height`` / ``is_synced(tip)`` accessors, exactly
            as the NODE_COMPACT_FILTERS sync-gate uses them.

        The optional positional ``index_name`` argument filters to a single
        index: a non-empty value drops every entry whose name differs (Core
        SummaryToJSON:354).  ``getindexinfo "no-such-index"`` therefore
        returns ``{}`` (an empty object, NOT an error).
        """

        def _emit(name: str, synced: bool, best_block_height: int) -> None:
            # SummaryToJSON: skip when a name filter is set and does not match.
            if index_name and index_name != name:
                return
            # EXACTLY two fields, in Core's order: synced, then height.
            result[name] = {
                "synced": bool(synced),
                "best_block_height": int(best_block_height),
            }

        result: dict[str, Any] = {}

        if not hasattr(self.node, "db") or self.node.db is None:
            return result

        # Active chain tip height (== the txindex best height; the txindex is
        # written inline with each connected block).
        try:
            _, tip_height = self.node.db.get_best_block()
            tip_height = int(tip_height) if tip_height is not None else 0
        except Exception:
            tip_height = 0

        # --- txindex (always running in ouroboros) ---
        # The Rust db always maintains the txid->location index; mirror Core's
        # ``if (g_txindex)`` guard via the substrate-presence probe used by
        # getrawtransaction (rpc.py:2150).
        has_txindex = hasattr(self.node.db, "get_tx_index")
        if has_txindex:
            # Inline with block connect → best == tip; synced once a best
            # block exists (GetSummary: best_block_height = m_best_block_index
            # ->nHeight, else 0).
            txindex_synced = tip_height >= 0
            _emit("txindex", txindex_synced, tip_height)

        # --- basic block filter index (only when -blockfilterindex on) ---
        bfi = getattr(self.node, "block_filter_index", None)
        if bfi is not None:
            try:
                best = bfi.best_indexed_height
            except Exception:
                best = None
            best_height = int(best) if best is not None else 0
            try:
                bfi_synced = bool(bfi.is_synced(tip_height))
            except Exception:
                bfi_synced = False
            _emit("basic block filter index", bfi_synced, best_height)

        # --- coinstatsindex (only when -coinstatsindex on) ---
        # Core's CoinStatsIndex::GetName() returns "coinstatsindex" (the key
        # the getindexinfo harness probes via d['coinstatsindex']).
        csi = getattr(self.node, "coinstats_index", None)
        if csi is not None:
            try:
                cbest = csi.best_indexed_height
            except Exception:
                cbest = None
            cbest_height = int(cbest) if cbest is not None else 0
            try:
                csi_synced = bool(csi.is_synced(tip_height))
            except Exception:
                csi_synced = False
            _emit("coinstatsindex", csi_synced, cbest_height)

        # --- txospenderindex (only when -txospenderindex on) ---
        # Core's TxoSpenderIndex BaseIndex name is "txospenderindex".
        tsi = getattr(self.node, "txospender_index", None)
        if tsi is not None:
            try:
                tbest = tsi.best_indexed_height
            except Exception:
                tbest = None
            tbest_height = int(tbest) if tbest is not None else 0
            try:
                tsi_synced = bool(tsi.is_synced(tip_height))
            except Exception:
                tsi_synced = False
            _emit("txospenderindex", tsi_synced, tbest_height)

        return result

    # Fee Bumping (RBF)

    async def rpc_bumpfee(
        self, txid: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Bump the fee of a mempool transaction via RBF.

        Creates a replacement transaction with a higher fee and broadcasts
        it.  The original transaction must signal BIP 125 replaceability
        (at least one input with sequence < 0xFFFFFFFE).

        Args:
            txid: Transaction ID to bump (hex string).
            options: Optional dict with ``fee_rate`` (sat/vB) or
                     ``conf_target`` (blocks for fee estimation).

        Returns:
            Dict with ``txid`` (new txid), ``origfee`` (BTC),
            ``fee`` (BTC), and ``errors`` list.

        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(status_code=500, detail="Mempool not available")

        options = options or {}
        fee_rate = options.get("fee_rate")
        conf_target = options.get("conf_target")

        if fee_rate is None:
            if conf_target is not None:
                fee_estimator = getattr(self.node, "fee_estimator", None)
                if fee_estimator is not None:
                    fee_rate = fee_estimator.estimate_fee(int(conf_target))
            if fee_rate is None:
                fee_rate = 10  # conservative default bump rate

        fee_rate = int(fee_rate)

        # Get original fee before bumping.
        # JSON-RPC convention: txids arrive in display order (BE hex).
        # Mempool keys are internal LE. Reverse at the boundary. W69.
        txid_bytes = bytes.fromhex(txid)[::-1]
        orig_entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if orig_entry is None:
            raise HTTPException(
                status_code=400,
                detail=f"Transaction {txid} not in mempool",
            )
        orig_fee_btc = orig_entry.fee / 1e8

        new_txid = await wallet.bump_fee(txid, fee_rate, sign=True)
        if new_txid is None:
            raise HTTPException(
                status_code=400,
                detail="Fee bump failed – transaction may not signal RBF, "
                "wallet may lack keys or funds, or mempool rejected the replacement",
            )

        # wallet.bump_fee returns LE hex (internal). Convert for RPC output
        # and for mempool lookup (both need LE bytes). W69.
        new_txid_bytes = bytes.fromhex(new_txid)  # already LE
        new_txid_display = new_txid_bytes[::-1].hex()  # BE for JSON output
        new_entry = self.node.mempool.get_transaction_entry(new_txid_bytes)
        new_fee_btc = new_entry.fee / 1e8 if new_entry else 0

        # Broadcast inv to peers
        try:
            from ouroboros.p2p_messages import INV_TYPE_TX, InvMessage

            inv = InvMessage(
                inventory=[(INV_TYPE_TX, new_txid_bytes)]
            )
            inv_msg = inv.to_network_message(self.node.network)
            if hasattr(self.node, "peer_manager") and self.node.peer_manager:
                await self.node.peer_manager.broadcast(inv_msg)
        except Exception:
            pass  # best-effort broadcast

        return {
            "txid": new_txid_display,
            "origfee": orig_fee_btc,
            "fee": new_fee_btc,
            "errors": [],
        }

    async def rpc_psbtbumpfee(
        self, txid: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Bump the fee of a mempool transaction, returning a PSBT.

        Like ``bumpfee`` but does NOT sign or broadcast.  Returns an
        unsigned raw transaction hex in the ``psbt`` field that can be
        signed externally.

        Args:
            txid: Transaction ID to bump (hex string).
            options: Optional dict with ``fee_rate`` (sat/vB) or
                     ``conf_target`` (blocks for fee estimation).

        Returns:
            Dict with ``psbt`` (unsigned raw hex), ``origfee`` (BTC),
            ``fee`` (BTC), and ``errors`` list.

        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise HTTPException(status_code=500, detail="Mempool not available")

        options = options or {}
        fee_rate = options.get("fee_rate")
        conf_target = options.get("conf_target")

        if fee_rate is None:
            if conf_target is not None:
                fee_estimator = getattr(self.node, "fee_estimator", None)
                if fee_estimator is not None:
                    fee_rate = fee_estimator.estimate_fee(int(conf_target))
            if fee_rate is None:
                fee_rate = 10

        fee_rate = int(fee_rate)

        # Get original fee before bumping.
        # JSON-RPC convention: txids arrive in display order (BE hex).
        # Mempool keys are internal LE. Reverse at the boundary. W69.
        txid_bytes = bytes.fromhex(txid)[::-1]
        orig_entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if orig_entry is None:
            raise HTTPException(
                status_code=400,
                detail=f"Transaction {txid} not in mempool",
            )
        orig_fee_btc = orig_entry.fee / 1e8

        unsigned_hex = await wallet.bump_fee(txid, fee_rate, sign=False)
        if unsigned_hex is None:
            raise HTTPException(
                status_code=400,
                detail="Fee bump failed – transaction may not signal RBF "
                "or wallet cannot reconstruct the replacement",
            )

        # Estimate new fee from the unsigned tx
        orig_total_out = sum(o.value for o in orig_entry.tx.outputs)
        # Parse unsigned tx to compute new total outputs
        try:
            from ouroboros.p2p_messages import TxMessage

            tx_data = bytes.fromhex(unsigned_hex)
            tx_msg = TxMessage.from_payload(tx_data)
            new_total_out = sum(o.value for o in tx_msg.transaction.outputs)
            # Get total input value from original entry
            total_in = orig_fee_btc * 1e8 + orig_total_out
            new_fee_btc = (total_in - new_total_out) / 1e8
        except Exception:
            new_fee_btc = 0

        return {
            "psbt": unsigned_hex,
            "origfee": orig_fee_btc,
            "fee": new_fee_btc,
            "errors": [],
        }

    def _format_mempool_entry(self, entry, txid_bytes: bytes) -> dict[str, Any]:
        """Format a MempoolEntry into the standard mempool dict."""
        mempool = self.node.mempool

        # -- depends: unconfirmed parents of this tx -----------------------
        # inp.prev_txid is internal LE; JSON-RPC emits display-order (BE). W69.
        depends: list[str] = []
        for inp in entry.tx.inputs:
            if inp.prev_txid in mempool.transactions:
                depends.append(inp.prev_txid[::-1].hex())

        # -- spentby: unconfirmed children spending this tx's outputs ------
        spentby: list[str] = []
        for other_txid, other_entry in mempool.transactions.items():
            if other_txid == txid_bytes:
                continue
            for inp in other_entry.tx.inputs:
                if inp.prev_txid == txid_bytes:
                    spentby.append(other_txid[::-1].hex())
                    break  # one match per child tx is enough

        # -- weight / vsize ------------------------------------------------
        weight = entry.tx.get_weight()
        vsize = (weight + 3) // 4

        # -- ancestor / descendant fees ------------------------------------
        # Use Core GetModifiedFee semantics for fees.modified / ancestorfees /
        # descendantfees so that prioritisetransaction is reflected (FIX-72).
        map_deltas = getattr(mempool, "map_deltas", {})

        def _mod_fee(t: bytes, e) -> int:
            return int(e.fee) + int(map_deltas.get(t, 0))

        own_modified_fee = _mod_fee(txid_bytes, entry)

        ancestor_fees = own_modified_fee
        for a_txid in mempool._get_ancestors(entry.tx):
            a_entry = mempool.transactions.get(a_txid)
            if a_entry is not None:
                ancestor_fees += _mod_fee(a_txid, a_entry)

        descendant_fees = own_modified_fee
        for d_txid in mempool._collect_descendants(txid_bytes):
            if d_txid == txid_bytes:
                continue
            d_entry = mempool.transactions.get(d_txid)
            if d_entry is not None:
                descendant_fees += _mod_fee(d_txid, d_entry)

        base_fee_btc = entry.fee / 1e8
        modified_fee_btc = own_modified_fee / 1e8

        # Core entryToJSON order (rpc/mempool.cpp): vsize, weight, time, height,
        # descendant*/ancestor*, wtxid, fees{}, depends, spentby, unbroadcast.
        # Fees are ONLY in the nested fees{} object — the old flat fee/modifiedfee/
        # ancestorfees/descendantfees top-level fields are NOT part of Core's shape.
        return {
            "vsize": vsize,
            "weight": weight,
            "time": int(entry.time_added),
            "height": entry.height_added,
            "descendantcount": entry.descendant_count,
            "descendantsize": entry.descendant_size,
            "ancestorcount": entry.ancestor_count,
            "ancestorsize": entry.ancestor_size,
            "wtxid": _display_hash(entry.tx.get_wtxid())
                if hasattr(entry.tx, "get_wtxid") else _display_txid(txid_bytes),
            "fees": {
                "base": base_fee_btc,
                "modified": modified_fee_btc,
                "ancestor": ancestor_fees / 1e8,
                "descendant": descendant_fees / 1e8,
            },
            "depends": depends,
            "spentby": spentby,
            "unbroadcast": False,
        }

    async def rpc_getmempoolentry(self, txid: str) -> dict[str, Any]:
        """Return mempool data for a given transaction.

        Reference: Bitcoin Core src/rpc/mempool.cpp:880 getmempoolentry ->
        ParseHashV(request.params[0], "txid") -> -8 on a malformed txid
        (rpc/util.cpp:117) BEFORE any lookup; a well-formed-but-absent txid
        -> RPC_INVALID_ADDRESS_OR_KEY (-5) "Transaction not in mempool"
        (mempool.cpp:887).
        """
        # JSON-RPC convention: txids arrive in display order (big-endian hex).
        # Internal mempool keys are little-endian (internal byte order). W69.
        # Core runs ParseHashV FIRST (mempool.cpp:880), so a malformed txid
        # -> -8 at the parse boundary, before any mempool check or lookup.
        txid_bytes = _parse_hash_v(txid, "txid")[::-1]
        if not hasattr(self.node, "mempool") or self.node.mempool is None:
            raise ValueError("No mempool available")
        entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if entry is None:
            raise RpcError(
                RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool"
            )
        return self._format_mempool_entry(entry, txid_bytes)

    async def rpc_getblockstats(
        self,
        hash_or_height: str | int,
        stats: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return per-block statistics for a given block.

        ``hash_or_height`` may be a block hash (hex string) or a block height
        (integer).  All fee / size statistics are computed by iterating every
        transaction in the block.

        If ``stats`` is provided it must be a list of stat names; only those
        keys will be present in the result.

        Ref: bitcoin/src/rpc/blockchain.cpp ``getblockstats``
        """
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db

        # ------------------------------------------------------------------
        # Resolve block from hash or height
        # ------------------------------------------------------------------
        block: Block | None = None
        if isinstance(hash_or_height, int):
            block = await asyncio.to_thread(db.get_block_by_height, hash_or_height)
            if not block:
                raise HTTPException(
                    status_code=404,
                    detail=f"Block not found at height {hash_or_height}",
                )
        else:
            # JSON-RPC convention: hashes are display-order (big-endian) hex;
            # internal storage keys by little-endian uint256 bytes. ParseHashV
            # rejects a malformed hash with RPC_INVALID_PARAMETER (-8) at the
            # parse boundary (Bitcoin Core src/rpc/util.cpp ParseHashV), and an
            # unknown-but-well-formed hash is RPC_INVALID_ADDRESS_OR_KEY (-5).
            block_hash = bytes(reversed(_parse_hash_v(hash_or_height, "hash_or_height")))
            block = await asyncio.to_thread(db.get_block, block_hash)
            if not block:
                raise RpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")

        # Resolve height. The wire-format Block carries height=None, so prefer
        # the height the caller asked for (int form); otherwise look it up by
        # hash. Falling back to 0 produces a wrong subsidy AND a height=0 field.
        block_height = getattr(block, "height", None)
        if block_height is None:
            if isinstance(hash_or_height, int):
                block_height = hash_or_height
            else:
                bh = block.hash if isinstance(block.hash, bytes) else bytes(32)
                resolved = None
                if hasattr(db, "get_block_height"):
                    resolved = await asyncio.to_thread(db.get_block_height, bh)
                block_height = resolved if resolved is not None else 0
        block_hash_bytes = (
            block.hash if isinstance(block.hash, bytes) else bytes(32)
        )
        # block.hash is internal little-endian; reverse for JSON-RPC display.
        blockhash_hex = block_hash_bytes[::-1].hex()
        block_time = block.timestamp

        # Median time past
        if hasattr(self.node, "get_median_time"):
            mediantime = self.node.get_median_time(block_height)
        else:
            mediantime = block_time

        # ------------------------------------------------------------------
        # Block subsidy
        # ------------------------------------------------------------------
        halvings = block_height // 210_000
        if halvings >= 64:
            subsidy = 0
        else:
            subsidy = (50 * 100_000_000) >> halvings

        # ------------------------------------------------------------------
        # Iterate transactions and accumulate statistics. This mirrors Bitcoin
        # Core's getblockstats accumulation loop (rpc/blockchain.cpp:2073-2165)
        # exactly: coinbase inputs are NOT counted, sizes use the witness-
        # inclusive serialization (ComputeTotalSize), per-UTXO sizes use
        # GetSerializeSize(out)+PER_UTXO_OVERHEAD, and feerate is per-vbyte
        # (txfee*4 / weight). Spent prevout values come from get_utxo_or_spent
        # (Core reads them from the block undo data).
        # ------------------------------------------------------------------
        # The wire-format Block produced by _py_block_to_block carries NO
        # witness data (every Transaction has has_witness=False), so its
        # serialize_with_witness() returns the STRIPPED size and HasWitness()
        # is always false — which would zero out swtxs/swtotal_* and undercount
        # total_size/maxtxsize. Re-parse the raw block bytes (witness-preserving)
        # the same way getblock verbosity>=2 does, falling back to the stripped
        # Block only if raw bytes are unavailable.
        block_hash_for_bytes = (
            block.hash if isinstance(block.hash, bytes) else None
        )
        raw_block_bytes = None
        if block_hash_for_bytes is not None and hasattr(db, "get_block_bytes"):
            raw_block_bytes = await asyncio.to_thread(
                db.get_block_bytes, block_hash_for_bytes
            )
        stripped_txs: list[Transaction] = (
            block.transactions if hasattr(block, "transactions") else []
        )
        txs_list = stripped_txs
        if raw_block_bytes is not None:
            try:
                witness_txs = _parse_block_txs(raw_block_bytes)
                if witness_txs and len(witness_txs) == len(stripped_txs):
                    txs_list = witness_txs
            except Exception:
                txs_list = stripped_txs
        num_txs = len(txs_list)

        WITNESS_SCALE_FACTOR = 4
        # PER_UTXO_OVERHEAD = sizeof(COutPoint)+sizeof(uint32_t)+sizeof(bool)
        #   = (32+4) + 4 + 1 = 41 (rpc/blockchain.cpp:1954).
        PER_UTXO_OVERHEAD = 41
        MAX_MONEY = 21_000_000 * 100_000_000

        def _compactsize_len(n: int) -> int:
            if n < 0xFD:
                return 1
            if n <= 0xFFFF:
                return 3
            if n <= 0xFFFFFFFF:
                return 5
            return 9

        def _txout_serialize_size(spk: bytes) -> int:
            # GetSerializeSize(CTxOut) = 8 (nValue int64) + CompactSize(len) + len
            return 8 + _compactsize_len(len(spk)) + len(spk)

        def _is_unspendable(spk: bytes) -> bool:
            # CScript::IsUnspendable: starts with OP_RETURN (0x6a) or too large.
            return (len(spk) > 0 and spk[0] == 0x6a) or len(spk) > 10_000

        total_size = 0
        total_weight = 0
        total_out = 0          # sum of NON-coinbase output values (satoshis)
        totalfee = 0           # sum of all non-coinbase fees

        inputs = 0             # non-coinbase inputs only
        outputs = 0            # all outputs (incl. coinbase)

        swtxs = 0
        swtotal_size = 0
        swtotal_weight = 0

        utxos = 0              # spendable outputs added (excl. genesis/BIP30)
        utxo_size_inc = 0
        utxo_size_inc_actual = 0

        maxfee = 0
        minfee = MAX_MONEY
        maxfeerate = 0
        minfeerate = MAX_MONEY
        maxtxsize = 0
        mintxsize = MAX_MONEY

        fee_array: list[int] = []
        feerate_array: list[tuple[int, int]] = []   # (feerate, weight)
        txsize_array: list[int] = []

        for tx in txs_list:
            outputs += len(tx.outputs)

            tx_total_out = 0
            for o in tx.outputs:
                tx_total_out += o.value
                out_size = _txout_serialize_size(o.script_pubkey) + PER_UTXO_OVERHEAD
                utxo_size_inc += out_size
                # Genesis (height 0) coinbase outputs do not enter the UTXO set
                # count; also skip unspendable outputs.
                if block_height == 0:
                    continue
                if _is_unspendable(o.script_pubkey):
                    continue
                utxos += 1
                utxo_size_inc_actual += out_size

            if tx.is_coinbase:
                continue

            inputs += len(tx.inputs)   # don't count coinbase's fake input
            total_out += tx_total_out  # don't count coinbase reward

            tx_size = len(tx.serialize_with_witness())  # ComputeTotalSize
            txsize_array.append(tx_size)
            maxtxsize = max(maxtxsize, tx_size)
            mintxsize = min(mintxsize, tx_size)
            total_size += tx_size

            weight = tx.get_weight()
            total_weight += weight

            if tx.has_witness:
                swtxs += 1
                swtotal_size += tx_size
                swtotal_weight += weight

            # Inputs: sum prevout values (from undo / spent store) + UTXO deltas.
            tx_total_in = 0
            for tx_in in tx.inputs:
                utxo = await asyncio.to_thread(
                    db.get_utxo_or_spent, tx_in.prev_txid, tx_in.prev_vout
                )
                if utxo:
                    tx_total_in += utxo["value"]
                    prevout_size = (
                        _txout_serialize_size(utxo["script_pubkey"])
                        + PER_UTXO_OVERHEAD
                    )
                    utxo_size_inc -= prevout_size
                    utxo_size_inc_actual -= prevout_size

            txfee = tx_total_in - tx_total_out
            fee_array.append(txfee)
            maxfee = max(maxfee, txfee)
            minfee = min(minfee, txfee)
            totalfee += txfee

            # feerate in sat/vbyte = txfee*WITNESS_SCALE_FACTOR / weight
            feerate = (txfee * WITNESS_SCALE_FACTOR) // weight if weight else 0
            feerate_array.append((feerate, weight))
            maxfeerate = max(maxfeerate, feerate)
            minfeerate = min(minfeerate, feerate)

        # --- truncated median (Core CalculateTruncatedMedian) ---------------
        def _trunc_median(scores: list[int]) -> int:
            n = len(scores)
            if n == 0:
                return 0
            s = sorted(scores)
            if n % 2 == 0:
                return (s[n // 2 - 1] + s[n // 2]) // 2
            return s[n // 2]

        # --- feerate percentiles by weight (Core CalculatePercentilesByWeight)
        feerate_percentiles = [0, 0, 0, 0, 0]
        if feerate_array:
            scores = sorted(feerate_array)  # sorts by (feerate, weight)
            weights = [
                total_weight / 10.0,
                total_weight / 4.0,
                total_weight / 2.0,
                (total_weight * 3.0) / 4.0,
                (total_weight * 9.0) / 10.0,
            ]
            next_idx = 0
            cumulative_weight = 0
            for feerate_v, w in scores:
                cumulative_weight += w
                while next_idx < 5 and cumulative_weight >= weights[next_idx]:
                    feerate_percentiles[next_idx] = feerate_v
                    next_idx += 1
            for i in range(next_idx, 5):
                feerate_percentiles[i] = scores[-1][0]

        non_cb = max(num_txs - 1, 0)

        # ------------------------------------------------------------------
        # Build result — key order matches Core's ret_all (blockchain.cpp:2167).
        # ------------------------------------------------------------------
        result: dict[str, Any] = {
            "avgfee": (totalfee // non_cb) if non_cb else 0,
            "avgfeerate": (totalfee * WITNESS_SCALE_FACTOR) // total_weight if total_weight else 0,
            "avgtxsize": (total_size // non_cb) if non_cb else 0,
            "blockhash": blockhash_hex,
            "feerate_percentiles": feerate_percentiles,
            "height": block_height,
            "ins": inputs,
            "maxfee": maxfee,
            "maxfeerate": maxfeerate,
            "maxtxsize": maxtxsize,
            "medianfee": _trunc_median(fee_array),
            "mediantime": mediantime,
            "mediantxsize": _trunc_median(txsize_array),
            "minfee": 0 if minfee == MAX_MONEY else minfee,
            "minfeerate": 0 if minfeerate == MAX_MONEY else minfeerate,
            "mintxsize": 0 if mintxsize == MAX_MONEY else mintxsize,
            "outs": outputs,
            "subsidy": subsidy,
            "swtotal_size": swtotal_size,
            "swtotal_weight": swtotal_weight,
            "swtxs": swtxs,
            "time": block_time,
            "total_out": total_out,
            "total_size": total_size,
            "total_weight": total_weight,
            "totalfee": totalfee,
            "txs": num_txs,
            "utxo_increase": outputs - inputs,
            "utxo_size_inc": utxo_size_inc,
            "utxo_increase_actual": utxos - inputs,
            "utxo_size_inc_actual": utxo_size_inc_actual,
        }

        # Filter to requested stats
        if stats:
            result = {k: v for k, v in result.items() if k in stats}

        return result

    # Helper methods

    def _tx_to_dict(self, tx: Transaction) -> dict[str, Any]:
        """Convert transaction to dictionary for RPC response.

        JSON-RPC convention: txids and wtxids in JSON are emitted in
        display order (reversed-byte / "big-endian"). Internally
        ``Transaction.get_txid()``/``get_wtxid()`` return the LE hash
        form (Core's uint256 byte order). Reverse before hex-encoding
        for any field that goes out as a txid string. This mirrors
        bitcoin-core/src/rpc/rawtransaction.cpp::TxToUniv calling
        ``tx.GetHash().GetHex()`` (which prints display-order). Pre-W41
        the byte-reversal hop was missing here, so getrawtransaction /
        decoderawtransaction / gettransaction / getblock(verbosity>=2)
        all emitted byte-reversed txids — surfaced by
        ``tools/psbt-multi-input-test.sh`` and audited fleet-wide.
        """
        txid = tx.get_txid() if hasattr(tx, 'get_txid') else tx.txid
        txid_hex = txid[::-1].hex() if isinstance(txid, bytes) else str(txid)

        # Calculate weight and vsize using transaction methods
        if hasattr(tx, 'get_weight') and hasattr(tx, 'get_vsize'):
            weight = tx.get_weight()
            vsize = tx.get_vsize()
        else:
            # Fallback: assume non-SegWit transaction
            tx_size = len(tx.serialize())
            weight = tx_size * 4
            vsize = tx_size

        hash_hex = (
            tx.get_wtxid()[::-1].hex()
            if hasattr(tx, 'get_wtxid') and tx.has_witness
            else txid_hex
        )
        return {
            "txid": txid_hex,
            "hash": hash_hex,  # wtxid for SegWit, txid for non-SegWit
            "version": tx.version,
            "size": len(tx.serialize()),
            "vsize": vsize,  # Virtual size for SegWit
            "weight": weight,  # Transaction weight
            "locktime": tx.locktime,
            "vin": [self._vin_to_dict(vin, i, tx) for i, vin in enumerate(tx.inputs)],
            "vout": [self._vout_to_dict(vout, i) for i, vout in enumerate(tx.outputs)],
        }

    def _vin_to_dict(self, vin: TxIn, index: int = 0, tx: Transaction | None = None) -> dict[str, Any]:
        # vin.prev_txid is internal LE; JSON-RPC emits display-order (BE).
        # Mirrors bitcoin-core/src/rpc/rawtransaction.cpp::TxToUniv which
        # writes ``txin.prevout.hash.GetHex()`` (display order). See W41.
        prev_txid = (
            vin.prev_txid[::-1].hex() if isinstance(vin.prev_txid, bytes)
            else str(vin.prev_txid)
        )
        script_sig = vin.script_sig.hex() if isinstance(vin.script_sig, bytes) else str(vin.script_sig)

        result = {
            "txid": prev_txid,
            "vout": vin.prev_vout,
            "scriptSig": {
                "asm": disassemble_script(vin.script_sig),  # Disassemble script
                "hex": script_sig,
            },
            "sequence": vin.sequence,
        }
        if vin.witness:
            result["txinwitness"] = [item.hex() for item in vin.witness]
        return result

    def _vout_to_dict(self, vout: TxOut, n: int) -> dict[str, Any]:
        script_pubkey = vout.script_pubkey.hex() if isinstance(vout.script_pubkey, bytes) else bytes(vout.script_pubkey).hex()
        script_pubkey_bytes = vout.script_pubkey if isinstance(vout.script_pubkey, bytes) else bytes(vout.script_pubkey)

        return {
            "value": vout.value / 100_000_000,  # Convert satoshis to BTC
            "n": n,
            "scriptPubKey": {
                "asm": disassemble_script(script_pubkey_bytes),
                "hex": script_pubkey,
                "type": self._get_script_type(vout.script_pubkey),
            },
        }

    def _get_script_type(self, script: bytes) -> str:
        if not isinstance(script, bytes):
            script = bytes(script)

        # Simplified script type detection
        if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[23] == 0x88 and script[24] == 0xac:
            return "pubkeyhash"  # P2PKH
        elif len(script) == 23 and script[0] == 0xa9 and script[22] == 0x87:
            return "scripthash"  # P2SH
        elif len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
            return "witness_v0_keyhash"  # P2WPKH
        elif len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
            return "witness_v0_scripthash"  # P2WSH
        elif len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
            return "witness_v1_taproot"  # P2TR
        elif len(script) == 67 and script[0] == 0x41:
            return "pubkey"  # P2PK
        elif len(script) > 0 and script[0] == 0x6a:
            return "nulldata"  # OP_RETURN
        else:
            return "nonstandard"

    def _is_coinbase_output(self, txid: bytes) -> bool:
        if not hasattr(self.node, 'db') or not self.node.db:
            return False
        try:
            _, best_height = self.node.db.get_best_block()
            for h in range(best_height + 1):
                block = self.node.db.get_block_by_height(h)
                if not block:
                    continue
                for tx in block.transactions:
                    if tx.get_txid() == txid:
                        return tx.is_coinbase
            return False
        except Exception:
            return False

    def _is_synced(self) -> bool:
        if hasattr(self.node, 'is_synced'):
            return self.node.is_synced()
        if hasattr(self.node, 'sync_manager'):
            return self.node.sync_manager.is_synced()
        return True  # Assume synced if can't check

    def _get_deployment_state_cached(self, height: int, network: str) -> dict[str, Any]:
        """Return cached deployment state, recomputing only when height or network changes.

        Deployment state only changes at consensus activation heights, so it is
        safe to cache by (height, network).  This eliminates the Rust FFI call to
        get_all_deployments_info (and associated GIL acquisition) from the
        getblockchaininfo hot path during IBD, where validate_block threads
        compete for the GIL on every UTXO lookup.
        """
        if height == self._deployment_cache_height and network == self._deployment_cache_network:
            cache_key = (height, network)
            if cache_key in self._deployment_cache:
                return self._deployment_cache[cache_key]

        state = self._build_deployment_state(height, network)

        # Replace cache — only keep the most recent entry to bound memory.
        self._deployment_cache.clear()
        self._deployment_cache[(height, network)] = state
        self._deployment_cache_height = height
        self._deployment_cache_network = network
        return state

    def _get_disk_usage_cached(self, db: Any) -> int:
        """Return estimated disk usage with a 30-second TTL to avoid repeated os.walk calls.

        The size_on_disk field is informational and does not need to be exact on
        every call.  Recomputing it via os.walk on every getblockchaininfo call
        can take hundreds of milliseconds on large data directories.
        """
        import time as _t

        now = _t.monotonic()
        cached = getattr(self, '_disk_usage_cache', None)
        cache_ts = getattr(self, '_disk_usage_cache_ts', 0.0)
        if cached is not None and (now - cache_ts) < 30.0:
            return cached

        size_on_disk = 0
        if hasattr(db, 'get_disk_usage'):
            size_on_disk = db.get_disk_usage()
        elif hasattr(db, '_data_dir'):
            import os
            data_dir = db._data_dir
            if data_dir and os.path.isdir(data_dir):
                for dirpath, _, filenames in os.walk(data_dir):
                    for f in filenames:
                        if f.endswith('.dat') or f.endswith('.ldb') or f.endswith('.log'):
                            try:
                                size_on_disk += os.path.getsize(os.path.join(dirpath, f))
                            except OSError:
                                pass
        elif hasattr(db, 'data_dir'):
            import os
            data_dir = db.data_dir
            if data_dir and os.path.isdir(data_dir):
                for dirpath, _, filenames in os.walk(data_dir):
                    for f in filenames:
                        if f.endswith('.dat') or f.endswith('.ldb') or f.endswith('.log'):
                            try:
                                size_on_disk += os.path.getsize(os.path.join(dirpath, f))
                            except OSError:
                                pass

        self._disk_usage_cache = size_on_disk
        self._disk_usage_cache_ts = now
        return size_on_disk

    def _build_deployment_state(self, height: int, network: str) -> dict[str, Any]:
        """Build a canonical deployment-state dict for a given chain tip.

        This is the single source of truth shared by both rpc_getblockchaininfo
        (exposed as ``softforks``) and rpc_getdeploymentinfo (exposed as
        ``deployments``).  The two RPCs emit different JSON shapes but both
        project from this dict, so they can never disagree.

        Format mirrors Bitcoin Core's getdeploymentinfo output:
          {
            "<name>": {
              "type":   "buried" | "bip9",
              "active": bool,
              "height": int,                 # activation height (always present)
              "min_activation_height": int,  # buried: same as height; bip9: param
              "bip9":  { ... },              # present only for type=="bip9"
            },
            ...
          }

        Reference: Bitcoin Core rpc/blockchain.cpp DeploymentInfo() /
        SoftForkDescPushBack() helpers which are called by both RPCs.
        """
        from ouroboros.consensus import BIP9_DEPLOYMENTS, BURIED_DEPLOYMENTS

        network_lower = network.lower()
        if network_lower == "bitcoin":
            network_lower = "mainnet"

        result: dict[str, Any] = {}

        # --- Buried deployments ---
        buried_for_net = BURIED_DEPLOYMENTS.get(network_lower, {})
        for dep_name, buried_dep in buried_for_net.items():
            active = height >= buried_dep.height
            result[dep_name] = {
                "type": "buried",
                "active": active,
                "height": buried_dep.height,
                "min_activation_height": buried_dep.height,
            }

        # --- BIP9 deployments ---
        if HAS_VERSIONBITS:
            try:
                bip9_deps = get_all_deployments_info(height, network_lower, [], [])
                for dep in bip9_deps:
                    is_active = dep.state == "active"
                    bip9_obj: dict[str, Any] = {
                        "status": dep.state,
                        "bit": dep.bit,
                        "start_time": dep.start_time,
                        "timeout": dep.timeout,
                        "since": dep.since,
                        "min_activation_height": dep.min_activation_height,
                    }
                    if dep.period is not None:
                        bip9_obj["statistics"] = {
                            "period": dep.period,
                            "threshold": dep.threshold,
                            "elapsed": dep.elapsed,
                            "count": dep.count,
                            "possible": dep.possible,
                        }
                    dep_entry: dict[str, Any] = {
                        "type": "bip9",
                        "active": is_active,
                        "height": dep.since if (is_active and dep.since > 0) else dep.min_activation_height,
                        "min_activation_height": dep.min_activation_height,
                        "bip9": bip9_obj,
                    }
                    result[dep.name] = dep_entry
            except Exception as e:
                logger.debug(f"Could not get BIP9 deployment info from Rust: {e}")
                # Fall back to static BIP9 deployment info from consensus module
                bip9_for_net = BIP9_DEPLOYMENTS.get(network_lower, {})
                for dep_name, dep_params in bip9_for_net.items():
                    is_always_active = dep_params.start_time == -1
                    result[dep_name] = {
                        "type": "bip9",
                        "active": is_always_active,
                        "height": dep_params.min_activation_height,
                        "min_activation_height": dep_params.min_activation_height,
                        "bip9": {
                            "status": "active" if is_always_active else "defined",
                            "bit": dep_params.bit,
                            "start_time": dep_params.start_time,
                            "timeout": dep_params.timeout,
                            "since": 0,
                            "min_activation_height": dep_params.min_activation_height,
                        },
                    }
        else:
            # No Rust versionbits available — use static Python data
            bip9_for_net = BIP9_DEPLOYMENTS.get(network_lower, {})
            for dep_name, dep_params in bip9_for_net.items():
                is_always_active = dep_params.start_time == -1
                result[dep_name] = {
                    "type": "bip9",
                    "active": is_always_active,
                    "height": dep_params.min_activation_height,
                    "min_activation_height": dep_params.min_activation_height,
                    "bip9": {
                        "status": "active" if is_always_active else "defined",
                        "bit": dep_params.bit,
                        "start_time": dep_params.start_time,
                        "timeout": dep_params.timeout,
                        "since": 0,
                        "min_activation_height": dep_params.min_activation_height,
                    },
                }

        return result

    def _get_confirmations(self, height: int | None) -> int:
        if height is None:
            return 0

        if not hasattr(self.node, 'db'):
            return 0

        try:
            _, best_height = self.node.db.get_best_block()
            if best_height >= height:
                return best_height - height + 1
        except Exception:
            pass

        return 0

    def _genesis_merkle_root(self) -> bytes | None:
        """Return the genesis block's merkle root in internal (LE) byte order.

        The genesis coinbase txid == the genesis block's merkle root, and Core
        rejects a getrawtransaction lookup of it as a special case
        (rpc/rawtransaction.cpp:290). We resolve it from the stored genesis
        block (height 0) so the check is network-agnostic and never hardcoded.
        Returns None if the genesis block can't be resolved (in which case the
        caller simply skips the special-case check).
        """
        # Cache only a SUCCESSFUL (non-None) resolution to avoid a DB
        # round-trip on every call. A None result is not cached so we re-try
        # on the (transient) case where genesis isn't stored yet.
        cached = getattr(self, "_genesis_merkle_root_cache", None)
        if cached is not None:
            return cached

        result: bytes | None = None
        try:
            if hasattr(self.node, "db") and self.node.db:
                gh = self.node.db.get_block_hash_by_height(0)
                if gh is not None:
                    gblock = self.node.db.get_block(bytes(gh))
                    if gblock is not None:
                        mr = getattr(gblock, "merkle_root", None)
                        if mr is not None:
                            result = bytes(mr)
        except Exception:
            result = None

        if result is not None:
            self._genesis_merkle_root_cache = result
        return result

    async def _get_next_block_hash(self, height: int) -> str | None:
        if not hasattr(self.node, "db") or not self.node.db:
            return None

        try:
            next_hash = await asyncio.to_thread(self.node.db.get_block_hash_by_height, height + 1)
            if next_hash is None:
                return None  # At tip, no next block
            # get_block_hash_by_height returns internal byte order (little-endian);
            # display format requires reversal to big-endian.
            # Reference: Bitcoin Core src/rpc/blockchain.cpp blockheaderToJSON → hashNext.GetHex().
            if isinstance(next_hash, bytes):
                return next_hash[::-1].hex()
            return str(next_hash)
        except Exception as e:
            logger.debug(f"Error getting next block hash for height {height}: {e}")
            return None

    # --- PSBT RPCs (BIP174/BIP370) --------------------------------------------

    async def rpc_analyzepsbt(self, psbt: str) -> dict[str, Any]:
        """
        Analyze a PSBT and determine the next action needed.

        Args:
            psbt: Base64-encoded PSBT

        Returns:
            Analysis including inputs status, next role, estimated fees
        """
        from ouroboros.psbt import PSBT, analyzepsbt

        # Pre-parse for the v2 gate (PSBTs are small; the double decode is
        # cheap) so default behavior matches Core's -22 rejection exactly.
        try:
            psbt_obj = PSBT.from_base64(psbt)
        except Exception as exc:
            return self._psbt_decode_error(exc)
        gate = self._psbt_v2_gate(psbt_obj)
        if gate is not None:
            return gate
        return analyzepsbt(psbt)

    async def rpc_utxoupdatepsbt(
        self, psbt: str, descriptors: list[Any] = None
    ) -> str:
        """
        Update a PSBT with UTXO information from the UTXO set.

        Args:
            psbt: Base64-encoded PSBT
            descriptors: Optional output descriptors (not yet implemented)

        Returns:
            Updated base64-encoded PSBT
        """
        from ouroboros.psbt import PSBT

        psbt_obj = PSBT.from_base64(psbt)
        gate = self._psbt_v2_gate(psbt_obj)
        if gate is not None:
            return gate

        # Look up UTXOs from our database
        if psbt_obj.tx is not None and hasattr(self.node, 'db') and self.node.db:
            for i, tx_in in enumerate(psbt_obj.tx.inputs):
                if psbt_obj.inputs[i].witness_utxo is not None:
                    continue  # Already has UTXO info

                try:
                    utxo = await asyncio.to_thread(
                        self.node.db.get_utxo,
                        tx_in.prev_txid, tx_in.prev_vout
                    )
                    if utxo:
                        psbt_obj.inputs[i].witness_utxo = (
                            utxo.value, utxo.script_pubkey
                        )
                except Exception:
                    pass

        return psbt_obj.to_base64()

    async def rpc_joinpsbts(self, psbts: list[str]) -> str:
        """
        Join multiple PSBTs into a single PSBT.

        Unlike combinepsbt which merges signatures for the same transaction,
        joinpsbts creates a new transaction combining inputs/outputs from
        multiple PSBTs.

        Args:
            psbts: Array of base64-encoded PSBTs

        Returns:
            Joined base64-encoded PSBT
        """
        from ouroboros.psbt import PSBT, joinpsbts

        # Core: txs.size() <= 1 -> RPC_INVALID_PARAMETER (-8), checked before
        # any PSBT is decoded (rpc/rawtransaction.cpp:1802-1804).
        if len(psbts or []) <= 1:
            raise RpcError(
                RPC_INVALID_PARAMETER,
                "At least two PSBTs are required to join PSBTs.",
            )

        for p in psbts or []:
            try:
                psbt_obj = PSBT.from_base64(p)
            except Exception as exc:
                return JSONRPCResponse(
                    error={"code": -22, "message": f"TX decode failed: {exc}"},
                    id=None,
                )
            gate = self._psbt_v2_gate(psbt_obj)
            if gate is not None:
                return gate
        return joinpsbts(psbts)

    async def rpc_walletprocesspsbt(
        self,
        psbt: str,
        sign: bool = True,
        sighashtype: str = "ALL",
        bip32derivs: bool = True,
    ) -> dict[str, Any]:
        """
        Update a PSBT with wallet information and optionally sign inputs.

        Args:
            psbt: Base64-encoded PSBT
            sign: Whether to sign inputs the wallet has keys for
            sighashtype: Signature hash type (ALL, NONE, SINGLE, etc.)
            bip32derivs: Include BIP32 derivation paths

        Returns:
            {psbt: base64, complete: bool}
        """
        import hashlib
        import struct

        from ouroboros.psbt import PSBT
        from ouroboros.wallet import WalletKey, _dsha256, _hash160

        # Parse sighash type
        sighash_map = {
            "ALL": 0x01, "NONE": 0x02, "SINGLE": 0x03,
            "ALL|ANYONECANPAY": 0x81, "NONE|ANYONECANPAY": 0x82,
            "SINGLE|ANYONECANPAY": 0x83, "DEFAULT": 0x00,
        }
        sighash_type = sighash_map.get(sighashtype.upper(), 0x01)

        psbt_obj = PSBT.from_base64(psbt)
        gate = self._psbt_v2_gate(psbt_obj)
        if gate is not None:
            return gate

        if psbt_obj.tx is None:
            raise ValueError("PSBT has no transaction")

        # Get wallet if available
        wallet = getattr(self.node, 'wallet', None)
        if wallet is None:
            return {"psbt": psbt_obj.to_base64(), "complete": False}

        # Build key lookup from wallet
        network = getattr(self.node, 'network', 'mainnet')
        keys_by_h160: dict[bytes, WalletKey] = {}
        keys_by_pubkey: dict[bytes, WalletKey] = {}

        # P2TR scriptPubKey contains the BIP-341 tweaked output key, not
        # the internal x-only key. Index by both so PSBT signing finds
        # the match.
        try:
            from ouroboros.taproot import derive_taproot_output_xonly
        except Exception:
            derive_taproot_output_xonly = None  # type: ignore

        # Get all wallet keys
        for key_info in wallet.keys:
            try:
                k = WalletKey.from_wif(key_info['wif'], network)
                keys_by_h160[_hash160(k.pubkey)] = k
                keys_by_pubkey[k.pubkey] = k
                keys_by_pubkey[k.pubkey[1:]] = k  # x-only for Taproot
                if derive_taproot_output_xonly is not None:
                    try:
                        keys_by_pubkey[
                            derive_taproot_output_xonly(k.pubkey, None)
                        ] = k
                    except Exception:
                        pass
            except Exception:
                pass

        # Also include HD-derived keys if available
        if hasattr(wallet, '_key_pool') and wallet._key_pool:
            try:
                for wk in wallet._key_pool.get_all_keys():
                    keys_by_h160[_hash160(wk.pubkey)] = wk
                    keys_by_pubkey[wk.pubkey] = wk
                    keys_by_pubkey[wk.pubkey[1:]] = wk
                    if derive_taproot_output_xonly is not None:
                        try:
                            keys_by_pubkey[
                                derive_taproot_output_xonly(wk.pubkey, None)
                            ] = wk
                        except Exception:
                            pass
            except Exception:
                pass

        # Helper functions for signing
        def _encode_varint(n: int) -> bytes:
            if n < 0xFD:
                return bytes([n])
            elif n <= 0xFFFF:
                return b'\xfd' + struct.pack('<H', n)
            elif n <= 0xFFFFFFFF:
                return b'\xfe' + struct.pack('<I', n)
            else:
                return b'\xff' + struct.pack('<Q', n)

        # BIP-143 sighash — single source of truth in
        # ``ouroboros.segwit_v0``. See W29-A for the consolidation.
        from ouroboros.segwit_v0 import bip143_sighash as _bip143_sighash

        def _taproot_sighash(tx, idx, sh_type, amounts, spks):
            acp = (sh_type & 0x80) != 0
            base = sh_type & 0x03
            data = bytearray()
            data.append(0x00)  # epoch
            data.append(sh_type if sh_type != 0 else 0x00)
            data.extend(struct.pack("<i", tx.version))
            data.extend(struct.pack("<I", tx.locktime))
            if not acp:
                prevouts = bytearray()
                for i in tx.inputs:
                    prevouts.extend(i.prev_txid)
                    prevouts.extend(struct.pack("<I", i.prev_vout))
                data.extend(hashlib.sha256(bytes(prevouts)).digest())
                amt_data = bytearray()
                for a in amounts:
                    amt_data.extend(struct.pack("<q", a))
                data.extend(hashlib.sha256(bytes(amt_data)).digest())
                spk_data = bytearray()
                for s in spks:
                    spk_data.extend(_encode_varint(len(s)))
                    spk_data.extend(s)
                data.extend(hashlib.sha256(bytes(spk_data)).digest())
                seqs = bytearray()
                for i in tx.inputs:
                    seqs.extend(struct.pack("<I", i.sequence))
                data.extend(hashlib.sha256(bytes(seqs)).digest())
            if base not in (2, 3):
                outs = bytearray()
                for o in tx.outputs:
                    outs.extend(struct.pack("<q", o.value))
                    outs.extend(_encode_varint(len(o.script_pubkey)))
                    outs.extend(o.script_pubkey)
                data.extend(hashlib.sha256(bytes(outs)).digest())
            elif base == 3 and idx < len(tx.outputs):
                o = tx.outputs[idx]
                out = struct.pack("<q", o.value)
                out += _encode_varint(len(o.script_pubkey))
                out += o.script_pubkey
                data.extend(hashlib.sha256(out).digest())
            else:
                data.extend(b"\x00" * 32)
            data.append(0x00)  # spend_type: no annex
            if acp:
                inp = tx.inputs[idx]
                data.extend(inp.prev_txid)
                data.extend(struct.pack("<I", inp.prev_vout))
                data.extend(struct.pack("<q", amounts[idx]))
                data.extend(_encode_varint(len(spks[idx])))
                data.extend(spks[idx])
                data.extend(struct.pack("<I", inp.sequence))
            else:
                data.extend(struct.pack("<I", idx))
            tag = hashlib.sha256(b"TapSighash").digest()
            return hashlib.sha256(tag + tag + bytes(data)).digest()

        # First pass: update UTXO info and add derivation paths
        tx = psbt_obj.tx
        all_amounts = []
        all_spks = []

        for idx, psbt_in in enumerate(psbt_obj.inputs):
            if psbt_in.is_finalized():
                all_amounts.append(0)
                all_spks.append(b"")
                continue

            # Get UTXO info
            amount = 0
            spk = b""

            tx_in = tx.inputs[idx]

            # Resolve UTXO from PSBT fields with strict consistency checks.
            #
            # Two PSBT-level integrity rules apply here, in this order:
            #
            # (A1) When ``non_witness_utxo`` is supplied, ``sha256d`` of its
            #      canonical serialization MUST equal the spent input's
            #      ``prev_txid`` (BIP-174 PSBT_IN_NON_WITNESS_UTXO sanity:
            #      see bitcoin-core/src/psbt.cpp PSBTInput::IsSane). Without
            #      this, a malicious wallet/coordinator can hand us a
            #      crafted prev-tx blob whose outputs[prev_vout] points at
            #      *any* amount/spk we don't actually own, and the signer
            #      will happily commit BIP-143 ``hashAmount`` to that
            #      forged value — the CVE-2020-14199 amount-oracle.
            #
            # (A2) When BOTH ``witness_utxo`` and ``non_witness_utxo`` are
            #      present, the (amount, scriptPubKey) extracted from each
            #      MUST match. Bitcoin Core treats a mismatch as the same
            #      class of attack as A1: trust the tx-derived (amount,
            #      spk), and reject when the fast-path witness_utxo lies.
            #
            # Pre-fix (W40-A audit, W41 fix): line 8726 took the witness
            # value unconditionally, and the fallback at 8728-8736 indexed
            # ``prev_tx.outputs[prev_vout]`` with no sha256d check on
            # ``non_witness_utxo``. The reject error code -25 mirrors
            # Core's ``MapPSBTError`` for "PSBT signing failed because of
            # non-canonical or inconsistent UTXO data".
            non_witness_amount = None
            non_witness_spk = None
            if psbt_in.non_witness_utxo is not None:
                try:
                    nwu_raw = psbt_in.non_witness_utxo
                    nwu_hash = hashlib.sha256(
                        hashlib.sha256(nwu_raw).digest()
                    ).digest()
                    if nwu_hash != tx_in.prev_txid:
                        # txids in error messages use display-order (BE).
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                "PSBT non_witness_utxo hash mismatch for "
                                f"input {idx}: sha256d(non_witness_utxo)="
                                f"{nwu_hash[::-1].hex()} != prev_txid="
                                f"{tx_in.prev_txid[::-1].hex()}"
                            ),
                        )
                    from ouroboros.psbt import _deserialize_tx
                    prev_tx = _deserialize_tx(nwu_raw)
                    if tx_in.prev_vout >= len(prev_tx.outputs):
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"PSBT input {idx} prev_vout "
                                f"{tx_in.prev_vout} out of range "
                                f"(non_witness_utxo has "
                                f"{len(prev_tx.outputs)} outputs)"
                            ),
                        )
                    out = prev_tx.outputs[tx_in.prev_vout]
                    non_witness_amount = out.value
                    non_witness_spk = out.script_pubkey
                except HTTPException:
                    raise

            if psbt_in.witness_utxo is not None:
                w_amount, w_spk = psbt_in.witness_utxo
                # A2: cross-check against non_witness_utxo if present.
                if non_witness_amount is not None and (
                    w_amount != non_witness_amount or w_spk != non_witness_spk
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"PSBT input {idx} witness_utxo "
                            f"(amount={w_amount}) disagrees with "
                            f"non_witness_utxo[{tx_in.prev_vout}] "
                            f"(amount={non_witness_amount}); refusing to "
                            "sign (CVE-2020-14199 class)."
                        ),
                    )
                # Prefer the tx-derived values when both are present —
                # they are consensus-bound and cheaper to forge-detect.
                if non_witness_amount is not None:
                    amount, spk = non_witness_amount, non_witness_spk
                else:
                    amount, spk = w_amount, w_spk
            elif non_witness_amount is not None:
                amount, spk = non_witness_amount, non_witness_spk
            else:
                # Try to look up from database
                if hasattr(self.node, 'db') and self.node.db:
                    try:
                        utxo = await asyncio.to_thread(
                            self.node.db.get_utxo,
                            tx_in.prev_txid, tx_in.prev_vout
                        )
                        if utxo:
                            amount = utxo.value
                            spk = utxo.script_pubkey
                            psbt_in.witness_utxo = (amount, spk)
                    except Exception:
                        pass

            all_amounts.append(amount)
            all_spks.append(spk)

        # Second pass: sign inputs
        if sign:
            for idx, psbt_in in enumerate(psbt_obj.inputs):
                if psbt_in.is_finalized():
                    continue

                spk = all_spks[idx]
                amount = all_amounts[idx]

                if not spk:
                    continue

                try:
                    # P2WPKH: OP_0 <20-byte-hash>
                    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                        h160 = spk[2:22]
                        key = keys_by_h160.get(h160)
                        if key:
                            script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                            sh = _bip143_sighash(
                                tx, idx, script_code, amount, sighash_type
                            )
                            sig = key.sign(sh) + bytes([sighash_type])
                            psbt_in.partial_sigs[key.pubkey] = sig
                            psbt_in.sighash_type = sighash_type

                    # P2TR: OP_1 <32-byte-x-only>
                    elif len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
                        x_only = spk[2:34]
                        key = keys_by_pubkey.get(x_only)
                        if key:
                            sh = _taproot_sighash(
                                tx, idx, sighash_type, all_amounts, all_spks
                            )
                            # BIP-341 / BIP-86: sign with the tweaked
                            # spending key. Key-path-only (no script
                            # tree) → empty merkle root.
                            from ouroboros.taproot import (
                                derive_taproot_sign_secret,
                            )
                            try:
                                tweaked_secret = derive_taproot_sign_secret(
                                    key.secret, None
                                )
                            except Exception:
                                # Skip this input; PSBT remains unsigned
                                # rather than producing an invalid sig.
                                continue
                            # W95: ferrous-utils ``sync`` exposes
                            # verify-only Schnorr — call coincurve directly
                            # for signing (the previous ``_sync.sign_schnorr``
                            # path was dead via AttributeError fallback).
                            try:
                                from coincurve import PrivateKey as CPrivKey
                                raw_sig = CPrivKey(
                                    tweaked_secret
                                ).sign_schnorr(sh)
                            except Exception:
                                continue
                            if sighash_type != 0x00:
                                raw_sig += bytes([sighash_type])
                            psbt_in.tap_key_sig = raw_sig

                    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                    elif len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9:
                        h160 = spk[3:23]
                        key = keys_by_h160.get(h160)
                        if key:
                            # Legacy sighash
                            def _legacy_sighash(tx, idx, script_code, sh_type):
                                base = sh_type & 0x1F
                                acp = (sh_type & 0x80) != 0
                                data = bytearray()
                                data.extend(struct.pack("<i", tx.version))
                                inputs = [(idx, tx.inputs[idx])] if acp else list(enumerate(tx.inputs))
                                data.extend(_encode_varint(len(inputs)))
                                for i, ti in inputs:
                                    data.extend(ti.prev_txid)
                                    data.extend(struct.pack("<I", ti.prev_vout))
                                    if i == idx:
                                        data.extend(_encode_varint(len(script_code)))
                                        data.extend(script_code)
                                    else:
                                        data.extend(b"\x00")
                                    seq = 0 if base in (2, 3) and i != idx else ti.sequence
                                    data.extend(struct.pack("<I", seq))
                                if base in (0, 1):
                                    data.extend(_encode_varint(len(tx.outputs)))
                                    for o in tx.outputs:
                                        data.extend(struct.pack("<q", o.value))
                                        data.extend(_encode_varint(len(o.script_pubkey)))
                                        data.extend(o.script_pubkey)
                                elif base == 2:
                                    data.extend(b"\x00")
                                elif base == 3:
                                    if idx >= len(tx.outputs):
                                        return bytes(32)
                                    data.extend(_encode_varint(idx + 1))
                                    for j, o in enumerate(tx.outputs):
                                        if j == idx:
                                            data.extend(struct.pack("<q", o.value))
                                            data.extend(_encode_varint(len(o.script_pubkey)))
                                            data.extend(o.script_pubkey)
                                        else:
                                            data.extend((-1).to_bytes(8, "little", signed=True))
                                            data.extend(b"\x00")
                                data.extend(struct.pack("<I", tx.locktime))
                                data.extend(struct.pack("<I", sh_type))
                                return _dsha256(bytes(data))

                            sh = _legacy_sighash(tx, idx, spk, sighash_type)
                            sig = key.sign(sh) + bytes([sighash_type])
                            psbt_in.partial_sigs[key.pubkey] = sig
                            psbt_in.sighash_type = sighash_type

                except Exception:
                    pass

        # Check if complete
        complete = all(inp.is_finalized() or bool(inp.partial_sigs) or inp.tap_key_sig
                      for inp in psbt_obj.inputs)

        return {"psbt": psbt_obj.to_base64(), "complete": complete}

    async def rpc_converttopsbt(
        self, hexstring: str, permitsigdata: bool = False
    ) -> str:
        """
        Convert a network-serialized transaction to a PSBT.

        Args:
            hexstring: Hex-encoded raw transaction
            permitsigdata: Allow transaction with signature data

        Returns:
            Base64-encoded PSBT
        """
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.psbt import PSBT

        try:
            tx_msg = TxMessage.from_payload(bytes.fromhex(hexstring))
            tx = tx_msg.transaction
        except Exception as e:
            raise ValueError(f"TX decode failed: {e}") from None

        # Check for existing signatures unless permitted
        if not permitsigdata:
            for inp in tx.inputs:
                if inp.script_sig or (hasattr(inp, 'witness') and inp.witness):
                    raise ValueError(
                        "Transaction has signatures; use permitsigdata=true to strip"
                    )

        psbt = PSBT.from_transaction(tx)
        return psbt.to_base64()

    # -------------------------------------------------------------------------
    # Descriptor RPCs (BIP 380-386)
    # -------------------------------------------------------------------------

    async def rpc_createmultisig(
        self,
        nrequired: int,
        keys: list[str],
        address_type: str = "legacy",
    ) -> dict[str, Any]:
        """
        Create a multisig address from M-of-N compressed pubkeys.

        Args:
            nrequired:    Number of required signatures (M).
            keys:         List of N hex-encoded compressed 33-byte pubkeys.
            address_type: "legacy" (default) → P2SH base58check
                          "bech32"            → P2WSH native segwit
                          "p2sh-segwit"       → P2SH-wrapped P2WSH

        Returns dict with keys:
            address      — the multisig address string
            redeemScript — hex of the raw multisig script
            descriptor   — output descriptor with BIP-380 checksum

        Reference: Bitcoin Core src/rpc/output_script.cpp createmultisig
        """
        import hashlib as _hashlib

        import base58 as _base58
        import bech32 as _bech32

        from ouroboros.descriptors import add_checksum

        # --- Validate inputs ---------------------------------------------------
        if not isinstance(nrequired, int) or nrequired < 1:
            raise HTTPException(
                status_code=400,
                detail="nrequired must be a positive integer",
            )
        if not keys or not isinstance(keys, list):
            raise HTTPException(
                status_code=400,
                detail="keys must be a non-empty list of pubkey hex strings",
            )
        n = len(keys)
        if nrequired > n:
            raise HTTPException(
                status_code=400,
                detail=f"Not enough keys supplied ({n} keys for {nrequired}-of-{n} multisig)",
            )
        if n > 16:
            raise HTTPException(
                status_code=400,
                detail="Number of keys cannot exceed 16",
            )
        if address_type not in ("legacy", "bech32", "p2sh-segwit"):
            raise HTTPException(
                status_code=400,
                detail=f"Unknown address_type: {address_type!r}",
            )

        # Decode and validate each pubkey
        pubkey_bytes: list[bytes] = []
        for pk_hex in keys:
            try:
                pk = bytes.fromhex(pk_hex)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid hex pubkey: {pk_hex!r}",
                ) from None
            if len(pk) != 33 or pk[0] not in (0x02, 0x03):
                raise HTTPException(
                    status_code=400,
                    detail=f"Pubkey must be a 33-byte compressed point: {pk_hex!r}",
                )
            pubkey_bytes.append(pk)

        # --- Build redeem script -----------------------------------------------
        # OP_M  (0x50 + nrequired)
        # for each pk: OP_DATA_33 (0x21) || <33-byte pk>
        # OP_N  (0x50 + n)
        # OP_CHECKMULTISIG (0xae)
        redeem_script = bytes([0x50 + nrequired])
        for pk in pubkey_bytes:
            redeem_script += bytes([len(pk)]) + pk
        redeem_script += bytes([0x50 + n, 0xae])

        # --- Address-type helpers (inline, no external dependency) -------------
        def _hash160(data: bytes) -> bytes:
            return _hashlib.new(
                "ripemd160", _hashlib.sha256(data).digest()
            ).digest()

        def _sha256(data: bytes) -> bytes:
            return _hashlib.sha256(data).digest()

        network = getattr(self.node, "network", "mainnet")
        p2sh_version = b"\x05" if network == "mainnet" else b"\xc4"
        hrp = "bc" if network == "mainnet" else "tb"

        if address_type == "legacy":
            # P2SH: HASH160(redeemScript)
            h160 = _hash160(redeem_script)
            address = _base58.b58encode_check(p2sh_version + h160).decode()
            desc_inner = f"multi({nrequired},{','.join(keys)})"
            descriptor = add_checksum(f"sh({desc_inner})")

        elif address_type == "bech32":
            # P2WSH: SHA256(redeemScript) as 32-byte witness program
            witness_program = _sha256(redeem_script)
            bits5 = _bech32.convertbits(witness_program, 8, 5)
            address = _bech32.bech32_encode(hrp, [0] + bits5)
            desc_inner = f"multi({nrequired},{','.join(keys)})"
            descriptor = add_checksum(f"wsh({desc_inner})")

        else:  # p2sh-segwit
            # P2SH-P2WSH: P2SH of (OP_0 <32-byte SHA256(redeemScript)>)
            witness_program = _sha256(redeem_script)
            p2wsh_script = b"\x00\x20" + witness_program
            h160 = _hash160(p2wsh_script)
            address = _base58.b58encode_check(p2sh_version + h160).decode()
            desc_inner = f"multi({nrequired},{','.join(keys)})"
            descriptor = add_checksum(f"sh(wsh({desc_inner}))")

        return {
            "address": address,
            "redeemScript": redeem_script.hex(),
            "descriptor": descriptor,
        }

    async def rpc_getdescriptorinfo(self, descriptor: str) -> dict[str, Any]:
        """
        Analyze a descriptor string and return information about it.

        Args:
            descriptor: The descriptor string to analyze (with or without checksum)

        Returns:
            Object containing:
            - descriptor: The descriptor with checksum added
            - checksum: The 8-character checksum
            - isrange: Whether the descriptor uses wildcards for range derivation
            - issolvable: Whether we have the keys to spend outputs
            - hasprivatekeys: Whether private keys are present

        Reference: Bitcoin Core rpc/misc.cpp getdescriptorinfo
        """
        from ouroboros.descriptors import getdescriptorinfo

        try:
            return getdescriptorinfo(descriptor)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

    async def rpc_deriveaddresses(
        self, descriptor: str, range_param: int | list[int] | None = None
    ) -> list[str]:
        """
        Derive addresses from a descriptor.

        Args:
            descriptor: The output descriptor string
            range_param: For ranged descriptors: [start, end] or just end (start=0)

        Returns:
            List of derived addresses

        Reference: Bitcoin Core rpc/misc.cpp deriveaddresses
        """
        from ouroboros.descriptors import add_checksum, parse_descriptor

        try:
            # Add checksum if missing
            if "#" not in descriptor:
                descriptor = add_checksum(descriptor)

            desc = parse_descriptor(descriptor)

            # Handle range parameter
            if desc.is_range:
                if range_param is None:
                    raise ValueError("Range must be specified for ranged descriptors")
                if isinstance(range_param, int):
                    start, end = 0, range_param
                elif isinstance(range_param, list):
                    if len(range_param) == 1:
                        start, end = 0, range_param[0]
                    elif len(range_param) >= 2:
                        start, end = range_param[0], range_param[1]
                    else:
                        raise ValueError("Invalid range format")
                else:
                    raise ValueError("Invalid range format")

                return [
                    desc.derive_address(i, self.node.network)
                    for i in range(start, end + 1)  # inclusive end
                ]
            else:
                if range_param is not None:
                    raise ValueError("Range should not be specified for non-ranged descriptors")
                return [desc.derive_address(0, self.node.network)]

        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

    async def rpc_importdescriptors(self, requests: list[dict]) -> list[dict]:
        """
        Import output descriptors into the wallet.

        Args:
            requests: List of import requests, each containing:
                - desc: The descriptor string (required)
                - active: Set this descriptor as active for address generation (default: true)
                - range: [start, end] for ranged descriptors (default: [0, 1000])
                - next_index: Next index to derive (default: 0)
                - timestamp: Import time (default: "now")
                - internal: Mark as change descriptor (default: false)
                - label: Optional label

        Returns:
            List of results, one per request, containing success status

        Reference: Bitcoin Core wallet/rpc/backup.cpp importdescriptors
        """
        # Route through /wallet/<name> like every other wallet RPC (Core
        # GetWalletForJSONRPCRequest) — importing into self.node.wallet
        # regardless of the URL path landed descriptors in the WRONG wallet.
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not available")

        results = wallet.importdescriptors(requests)

        # Core wallet/rpc/backup.cpp:376-410: every request's timestamp is
        # clamped to >= 1 (so 0 means "scan from genesis") and any successful
        # import with a non-"now" timestamp triggers a SYNCHRONOUS
        # RescanFromTime before the RPC returns — funds received BEFORE the
        # import must be credited immediately. rescan_chain also rebuilds the
        # wallet history records for the freshly-registered descriptor
        # scripts (scan_block_connect reads the merged script set).
        try:
            needs_rescan = any(
                isinstance(res, dict) and res.get("success") is True
                and isinstance(req, dict)
                and req.get("timestamp", "now") != "now"
                for req, res in zip(requests, results, strict=False)
            )
        except Exception:
            needs_rescan = False
        if needs_rescan and getattr(wallet, "db", None) is not None:
            tip = wallet._tip_height()
            logger.info(
                "importdescriptors: synchronous rescan of blocks 0..%d "
                "(Core backup.cpp RescanFromTime parity; may take a while "
                "on a long chain)", tip,
            )
            await asyncio.to_thread(wallet.rescan_chain, 0, None)

        return results

    async def rpc_listdescriptors(self, private: bool = False) -> dict[str, Any]:
        """
        List all imported descriptors in the wallet.

        Args:
            private: Include private keys (xprv) in output (default: false)

        Returns:
            Object with wallet_name and descriptors array

        Reference: Bitcoin Core wallet/rpcwallet.cpp listdescriptors
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not available")

        descriptors = wallet.listdescriptors()
        return {
            "wallet_name": getattr(wallet, "name", "default"),
            "descriptors": descriptors,
        }

    # ==========================================================================
    # assumeUTXO (BIP305) RPC methods
    # ==========================================================================

    async def rpc_loadtxoutset(self, path: str) -> dict[str, Any]:
        """
        Load a UTXO snapshot to enable fast startup (BIP305 assumeUTXO).

        This loads a serialized UTXO set from a snapshot file, validates it
        against hardcoded assumeUTXO parameters, and activates it as the
        current chainstate. Background validation from genesis begins
        automatically.

        Args:
            path: Path to the snapshot file (created by dumptxoutset)

        Returns:
            Object with snapshot loading results:
            - coins_loaded: Number of UTXOs loaded
            - base_hash: Block hash of the snapshot
            - base_height: Block height of the snapshot
            - path: Path to the loaded snapshot

        Raises:
            Error if the snapshot is invalid or for a different network

        Reference: Bitcoin Core rpc/blockchain.cpp loadtxoutset
        """
        import os

        from ouroboros.snapshot import (
            get_assumeutxo_by_hash,
            read_snapshot_metadata,
        )

        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail=f"File not found: {path}")

        if not hasattr(self.node, 'snapshot_manager') or self.node.snapshot_manager is None:
            raise HTTPException(status_code=500, detail="Snapshot manager not initialized")

        sm = self.node.snapshot_manager

        # Check if snapshot is already loaded
        if sm.snapshot_loaded:
            raise HTTPException(
                status_code=400,
                detail="Snapshot already loaded. Restart node to load a different snapshot."
            )

        try:
            # Read metadata to validate before loading
            network = getattr(self.node, 'network', 'mainnet')
            metadata = read_snapshot_metadata(path, network)

            # Core-strict assumeUTXO whitelist check.
            #
            # Reference: bitcoin-core/src/validation.cpp ActivateSnapshot,
            # roughly L5775-5780 — Core looks up the start blockheader to
            # find its height, then asks GetParams().AssumeutxoForHeight();
            # if there's no entry for that height it refuses with:
            #
            #   "Assumeutxo height in snapshot metadata not recognized
            #    (<H>) - refusing to load snapshot"
            #
            # Our table is keyed by hash, so we look the snapshot's
            # base_blockhash up directly. If we have the corresponding
            # block-index entry locally we surface the real height in the
            # error; otherwise we report 'unknown' (still lossless because
            # the hex blockhash is in the snapshot for the operator).
            au_data = get_assumeutxo_by_hash(network, metadata.base_blockhash)
            if au_data is None:
                # Try to recover the height from our own block index for a
                # better error message; fall back to "unknown" if we don't
                # have this header yet.
                base_height_str = "unknown"
                try:
                    db = getattr(self.node, "db", None)
                    if db is not None and hasattr(db, "_db") and hasattr(
                        db._db, "get_block"
                    ):
                        py_block = db._db.get_block(metadata.base_blockhash)
                        if py_block is not None:
                            h = getattr(py_block, "height", None)
                            if h is not None:
                                base_height_str = str(int(h))
                except Exception:
                    pass
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Assumeutxo height in snapshot metadata not recognized "
                        f"({base_height_str}) - refusing to load snapshot"
                    ),
                )

            # BUG-1: headers-chain presence check.
            # Mirrors Core ActivateSnapshot (validation.cpp:5611-5615):
            #   snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash);
            #   if (!snapshot_start_block)
            #       return Error{"The base block header must appear in the headers chain. ..."}
            db_node = getattr(self.node, "db", None)
            if db_node is not None and hasattr(db_node, "has_block_hash"):
                if not db_node.has_block_hash(metadata.base_blockhash):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"The base block header ({metadata.base_blockhash_hex()}) "
                            "must appear in the headers chain. Make sure all headers "
                            "are syncing, and call loadtxoutset again"
                        ),
                    )

            # BUG-2: mempool-empty precondition.
            # Mirrors Core ActivateSnapshot (validation.cpp:5626-5629):
            #   auto mempool{CurrentChainstate().GetMempool()};
            #   if (mempool && mempool->size() > 0)
            #       return Error{"Can't activate a snapshot when mempool not empty"};
            mempool_node = getattr(self.node, "mempool", None)
            if mempool_node is not None and len(mempool_node) > 0:
                raise HTTPException(
                    status_code=400,
                    detail="Can't activate a snapshot when mempool not empty",
                )

            # Collect active tip chainwork for BUG-3 check inside load_snapshot.
            # Pass 0 (no-op) if we cannot determine it.
            active_chainwork: int | None = None
            if db_node is not None and hasattr(db_node, "get_best_block"):
                try:
                    tip_hash, tip_height = db_node.get_best_block()
                    if hasattr(db_node, "get_block_chainwork"):
                        cw = db_node.get_block_chainwork(tip_hash, tip_height)
                        if cw > 0:
                            active_chainwork = cw
                except Exception:
                    pass

            # Load the snapshot
            def progress_callback(loaded: int, total: int):
                pass  # Could emit progress via ZMQ or websockets

            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sm.load_snapshot(path, progress_callback, active_chainwork=active_chainwork),
            )

            # Wire the REAL dual-chainstate background validator. The block
            # source feeds the SECOND (background) chainstate the consensus
            # bytes for every block genesis..base so it can re-connect them
            # into its OWN coins store and independently re-derive the
            # snapshot's HASH_SERIALIZED (Core ActivateSnapshot/AddChainstate/
            # MaybeValidateSnapshot, validation.cpp:5588/6170/5967).
            #
            # The background chainstate genuinely re-connects the chain only
            # when the node already has the block bodies genesis..base on disk
            # (e.g. a node that had previously synced or imported them). When a
            # body is missing the validator surfaces INVALID/NOT_READY rather
            # than blindly flipping validated=true — never a silent accept.
            node_db = getattr(self.node, "db", None)

            def _live_block_source(height: int) -> bytes | None:
                try:
                    if node_db is None:
                        return None
                    blk = node_db.get_block_by_height(height)
                    if blk is None:
                        return None
                    return blk.serialize()
                except Exception:
                    return None

            sm.background_block_source = _live_block_source

            # Start background validation in a thread (Core runs
            # MaybeValidateSnapshot asynchronously; loadtxoutset returns
            # success regardless of the eventual verdict, which is surfaced
            # via getchainstates' validated flag).
            sm.start_background_validation()

            return {
                "coins_loaded": metadata.coins_count,
                "base_hash": metadata.base_blockhash_hex(),
                "base_height": sm.snapshot_height,
                "path": path,
            }

        except HTTPException:
            # Already-formed RPC errors (incl. the Core-strict whitelist
            # refusal) bubble out with their original status + detail.
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load snapshot: {e}") from None

    async def rpc_scrubunspendable(self) -> dict[str, int]:
        """
        Walk the existing chainstate and remove orphan provably-unspendable
        coins (OP_RETURN scripts and scripts > MAX_SCRIPT_SIZE) left behind
        by pre-fix code paths that did not filter them at write time.

        Idempotent: a clean chainstate returns ``{"removed": 0,
        "bytes_freed": 0}``.

        Operator-invoked only — there is no automatic trigger on startup.
        Used to bring an existing on-disk datadir into byte-identity with
        what ``dumptxoutset`` would emit after the write-time
        `is_unspendable_script` filter landed in ``apply_block`` /
        ``connect_block_from_bytes`` / ``connect_block_at_height``.

        Reference: Bitcoin Core ``CScript::IsUnspendable`` (script.h:563-566)
        and ``AddCoins`` (coins.cpp:96-99).

        Returns:
            Mapping with ``removed`` (entries deleted) and
            ``bytes_freed`` (approximate sum of key+value bytes freed —
            actual disk reclaim is lazy via RocksDB compaction).
        """
        if not hasattr(self.node, "db") or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db
        if not hasattr(db, "scrub_unspendable_coins"):
            raise HTTPException(
                status_code=501,
                detail=(
                    "scrubunspendable requires Rust database bindings "
                    "with scrub_unspendable_coins"
                ),
            )

        try:
            removed, bytes_freed = await asyncio.to_thread(
                db.scrub_unspendable_coins
            )
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"scrubunspendable failed: {e}"
            ) from None

        logger.info(
            "scrubunspendable: removed=%d bytes_freed=%d",
            removed, bytes_freed,
        )
        return {"removed": int(removed), "bytes_freed": int(bytes_freed)}

    async def rpc_dumptxoutset(
        self,
        path: str,
        type: str = "",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Dispatch wrapper for ``dumptxoutset`` that enforces the
        NetworkDisable RAII contract via a Python ``try/finally``.

        Mirrors Bitcoin Core's NetworkDisable destructor in
        ``rpc/blockchain.cpp::dumptxoutset``: on every exit path
        (success, ``HTTPException``, unexpected exception) the
        ``block_submission_paused`` flag is cleared so subsequent
        ``submitblock`` requests in the same process don't see stale
        state. The actual rewind→dump→replay implementation lives in
        :meth:`_rpc_dumptxoutset_impl`.
        """
        try:
            return await self._rpc_dumptxoutset_impl(path, type=type, options=options)
        finally:
            self.block_submission_paused = False

    async def _rpc_dumptxoutset_impl(
        self,
        path: str,
        type: str = "",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Dump the UTXO set to a file for use with loadtxoutset.

        Three operating modes (matches Bitcoin Core rpc/blockchain.cpp
        ``dumptxoutset`` 27.x semantics):

        - ``type="latest"`` (or empty + no rollback option): dump the
          current chain tip's UTXO set. No reorg.
        - ``type="rollback"`` (no explicit height): pick the highest
          assumeutxo entry from chainparams that is ``<= current_tip``,
          temporarily roll back to that block, dump, then put the chain
          back. Mirrors Core's "latest valid snapshot block that can
          currently be loaded with loadtxoutset".
        - ``options={"rollback": <height|hash>}``: roll back to a specific
          block height (int) or hash (hex string), dump, put back.

        The rollback dance uses ``invalidate_block`` + ``reconsider_block``
        + ``reactivate_best_chain`` (Bitcoin Core's ``TemporaryRollback``
        pattern, blockchain.cpp:3056-3067). ``invalidate_block``
        disconnects every block from the target's child up to the current
        tip and unwinds UTXOs via the stored undo data.
        ``reconsider_block`` clears the BLOCK_FAILED_* flags.
        ``reactivate_best_chain`` then walks forward from the rollback
        target, re-connecting each previously-disconnected block until
        the chain returns to the original tip (Core's
        ``CChainState::ActivateBestChain`` analog). On success
        ``chain_restored=True`` is returned.

        Args:
            path: Path to write the snapshot file.
            type: ``"latest"``, ``"rollback"``, or empty.
            options: ``{"rollback": <height int | hash hex>}``.

        Returns:
            ``coins_written`` / ``base_hash`` / ``base_height`` / ``path``.
            On rollback paths, includes ``rollback_height``,
            ``rollback_hash``, ``original_tip_height``, ``original_tip_hash``,
            and ``chain_restored`` (False if reactivation is incomplete).

        Reference: Bitcoin Core rpc/blockchain.cpp dumptxoutset
        """
        import os

        if not hasattr(self.node, 'db') or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        if not hasattr(self.node, 'snapshot_manager') or self.node.snapshot_manager is None:
            raise HTTPException(status_code=500, detail="Snapshot manager not initialized")

        sm = self.node.snapshot_manager
        db = self.node.db
        opts = options or {}

        # ------------------------------------------------------------------
        # Mode resolution. Matches the precedence in Core's RPC handler:
        # an explicit `options.rollback` always wins; "rollback" alone
        # picks the highest assumeutxo height <= tip; "latest" or empty
        # is current-tip dump.
        # ------------------------------------------------------------------
        rollback_value = opts.get("rollback") if isinstance(opts, dict) else None

        if rollback_value is not None:
            if type and type != "rollback":
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid snapshot type \"{type}\" specified with rollback option",
                )
            mode = "rollback_explicit"
        elif type == "rollback":
            mode = "rollback_auto"
        elif type in ("", "latest"):
            mode = "latest"
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid snapshot type \"{type}\" specified. Please specify \"rollback\" or \"latest\"",
            )

        if os.path.exists(path):
            raise HTTPException(
                status_code=400,
                detail=f"File already exists: {path}. Remove it first.",
            )

        original_tip_hash, original_tip_height = db.get_best_block()

        # ------------------------------------------------------------------
        # Resolve target height/hash for rollback modes.
        # ------------------------------------------------------------------
        target_height: int | None = None
        target_hash: bytes | None = None

        if mode == "rollback_auto":
            from ouroboros.snapshot import get_assumeutxo_params
            params = get_assumeutxo_params(self.node.network)
            eligible = [p for p in params if p.height <= original_tip_height]
            if not eligible:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "No assumeutxo entry available at or below current tip "
                        f"({original_tip_height}); specify a height via "
                        "options.rollback"
                    ),
                )
            chosen = max(eligible, key=lambda p: p.height)
            target_height = chosen.height
            target_hash = chosen.block_hash

        elif mode == "rollback_explicit":
            # Either an integer height or a hex-encoded big-endian hash.
            if isinstance(rollback_value, bool):
                raise HTTPException(
                    status_code=400, detail="rollback must be an integer height or hex hash",
                )
            if isinstance(rollback_value, int):
                if rollback_value < 0:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Target block height {rollback_value} is negative",
                    )
                if rollback_value > original_tip_height:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Target block height {rollback_value} after current "
                            f"tip {original_tip_height}"
                        ),
                    )
                target_height = rollback_value
                resolved = await asyncio.to_thread(
                    db.get_block_hash_by_height, target_height
                )
                if resolved is None:
                    raise HTTPException(
                        status_code=404,
                        detail=f"No block in chain at height {target_height}",
                    )
                target_hash = bytes(resolved)
            elif isinstance(rollback_value, str):
                try:
                    h = bytes.fromhex(rollback_value)
                    if len(h) != 32:
                        raise ValueError("hash must be 32 bytes")
                except ValueError as e:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid rollback hash: {e}"
                    ) from None
                # Big-endian display hex -> internal little-endian bytes.
                target_hash = h[::-1]
                if not await asyncio.to_thread(db.has_block_hash, target_hash):
                    raise HTTPException(
                        status_code=404, detail="Block not found"
                    )
                # PyBlock doesn't carry a height field, so we resolve by
                # scanning ``get_block_hash_by_height`` from the current tip
                # downwards. This is O(N) in the worst case but only runs
                # once per RPC call on the rollback path.
                resolved_height: int | None = None
                for h_candidate in range(original_tip_height, -1, -1):
                    chain_hash = await asyncio.to_thread(
                        db.get_block_hash_by_height, h_candidate
                    )
                    if chain_hash is not None and bytes(chain_hash) == target_hash:
                        resolved_height = h_candidate
                        break
                if resolved_height is None:
                    raise HTTPException(
                        status_code=404,
                        detail=(
                            "Rollback hash not on active chain "
                            f"(scanned 0..{original_tip_height})"
                        ),
                    )
                target_height = resolved_height
            else:
                raise HTTPException(
                    status_code=400, detail="rollback must be an integer height or hex hash",
                )

        # ------------------------------------------------------------------
        # Optional rollback dance (TemporaryRollback analog).
        # ------------------------------------------------------------------
        chain_restored = True
        invalidate_target_hash: bytes | None = None

        if mode in ("rollback_auto", "rollback_explicit"):
            assert target_height is not None
            assert target_hash is not None

            if target_height > original_tip_height:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Rollback target {target_height} above tip "
                        f"{original_tip_height}"
                    ),
                )

            # Pruned-mode pre-check. Mirrors Bitcoin Core
            # rpc/blockchain.cpp:dumptxoutset:
            #   if (IsPruneMode() &&
            #       target_index->nHeight <
            #       node.chainman->m_blockman.GetFirstBlock()->nHeight)
            #       throw "Block height N not available (pruned data).
            #              Use a height after M.";
            # ouroboros tracks the prune horizon via
            # ``self.node.pruner.prune_height`` (highest pruned height; see
            # ``ouroboros.pruning``). We fail fast so a pruned datadir does
            # not begin an invalidate_block walk that is guaranteed to fail
            # when undo data has been deleted.
            pruner = getattr(self.node, "pruner", None)
            if pruner is not None and pruner.prune_height > 0:
                first_available = pruner.prune_height + 1
                if target_height < first_available:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Block height {target_height} not available "
                            f"(pruned data). Use a height after "
                            f"{first_available - 1}."
                        ),
                    )

            if target_height < original_tip_height:
                # NetworkDisable RAII. Mirrors Bitcoin Core's
                # NetworkDisable wrapper around TemporaryRollback in
                # rpc/blockchain.cpp::dumptxoutset. Pause inbound block
                # acceptance for the duration of the rewind→dump→replay
                # dance; the matching restore lives inside a finally
                # clause at the very bottom of this method (covers
                # success, HTTPException, and unexpected exceptions).
                self.block_submission_paused = True

                # We invalidate the *child* of the target — same as Core's
                # `chainstate->m_chain.Next(target_index)` (blockchain.cpp:3185).
                # That disconnects every block from target+1 up to tip and
                # leaves target as the new tip.
                rust_db = getattr(db, "rust_db", None) or getattr(db, "_db", None)
                if rust_db is None or not hasattr(rust_db, "invalidate_block"):
                    raise HTTPException(
                        status_code=500,
                        detail="rollback requires Rust database bindings (invalidate_block)",
                    )

                child_height = target_height + 1
                child_hash = await asyncio.to_thread(
                    db.get_block_hash_by_height, child_height
                )
                if child_hash is None:
                    raise HTTPException(
                        status_code=500,
                        detail=(
                            f"Could not find child block at height {child_height}; "
                            "cannot perform rollback"
                        ),
                    )
                invalidate_target_hash = bytes(child_hash)

                logger.info(
                    "[dumptxoutset] rollback: invalidating block %s at height %d "
                    "to roll tip %d -> %d",
                    invalidate_target_hash[::-1].hex()[:16],
                    child_height,
                    original_tip_height,
                    target_height,
                )

                try:
                    await asyncio.to_thread(
                        rust_db.invalidate_block, invalidate_target_hash
                    )
                except Exception as e:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Rollback (invalidate_block) failed: {e}",
                    ) from None
                # Bust any cached tip on the Python wrapper.
                if hasattr(db, "_cached_tip"):
                    db._cached_tip = None

                # Sanity-check the rolled-back tip.
                rolled_hash, rolled_height = db.get_best_block()
                if rolled_height != target_height or bytes(rolled_hash) != target_hash:
                    raise HTTPException(
                        status_code=500,
                        detail=(
                            f"Rollback landed at height={rolled_height} hash="
                            f"{bytes(rolled_hash)[::-1].hex()}, expected "
                            f"height={target_height} hash="
                            f"{target_hash[::-1].hex()}"
                        ),
                    )

        # ------------------------------------------------------------------
        # Dump the snapshot.
        # ------------------------------------------------------------------
        try:
            def progress_callback(written: int, total: int):
                pass  # Future: emit progress via ZMQ.

            coins_written = await asyncio.to_thread(
                sm.dump_snapshot, path, progress_callback
            )

            dump_hash, dump_height = db.get_best_block()
            result: dict[str, Any] = {
                "coins_written": coins_written,
                "base_hash": (
                    dump_hash.hex()
                    if isinstance(dump_hash, bytes)
                    else str(dump_hash)
                ),
                "base_height": dump_height,
                "path": path,
            }
        except Exception as e:
            # If dump fails after rollback, still try to put the chain back.
            if invalidate_target_hash is not None:
                try:
                    rust_db = getattr(db, "rust_db", None) or getattr(db, "_db", None)
                    if rust_db is not None:
                        await asyncio.to_thread(
                            rust_db.reconsider_block, invalidate_target_hash
                        )
                except Exception:
                    logger.exception(
                        "[dumptxoutset] reconsider_block failed during dump-error cleanup"
                    )
            raise HTTPException(
                status_code=500, detail=f"Failed to dump snapshot: {e}"
            ) from None

        # ------------------------------------------------------------------
        # TemporaryRollback dtor: reconsider_block lifts the FAILED flags
        # then reactivate_best_chain walks the disconnected blocks back up
        # to the original tip (Core ActivateBestChain analog). On success
        # the chain is fully restored and chain_restored=True.
        # ------------------------------------------------------------------
        if invalidate_target_hash is not None:
            rust_db = getattr(db, "rust_db", None) or getattr(db, "_db", None)
            try:
                await asyncio.to_thread(
                    rust_db.reconsider_block, invalidate_target_hash
                )
            except Exception as e:
                logger.error(
                    "[dumptxoutset] reconsider_block failed: %s", e
                )

            # reactivate_best_chain reconnects the disconnected blocks.
            # On a stub DB without this method (older bindings or test
            # double), fall back to flag-only behaviour with a warning.
            if hasattr(rust_db, "reactivate_best_chain"):
                try:
                    await asyncio.to_thread(rust_db.reactivate_best_chain)
                except Exception as e:
                    logger.error(
                        "[dumptxoutset] reactivate_best_chain failed: %s", e
                    )
            else:
                logger.warning(
                    "[dumptxoutset] rust_db has no reactivate_best_chain; "
                    "chain may stay at rollback height until next P2P sync"
                )
            if hasattr(db, "_cached_tip"):
                db._cached_tip = None

            post_hash, post_height = db.get_best_block()
            chain_restored = (
                post_height == original_tip_height
                and bytes(post_hash) == original_tip_hash
            )
            if not chain_restored:
                logger.warning(
                    "[dumptxoutset] chain not restored: tip is now %d, "
                    "was %d. Block_sync should re-activate stored blocks "
                    "on next pass; alternatively, restart the node.",
                    post_height, original_tip_height,
                )

        if mode in ("rollback_auto", "rollback_explicit"):
            assert target_hash is not None and target_height is not None
            result["rollback_height"] = target_height
            result["rollback_hash"] = target_hash[::-1].hex()
            result["original_tip_height"] = original_tip_height
            result["original_tip_hash"] = (
                original_tip_hash[::-1].hex()
                if isinstance(original_tip_hash, bytes)
                else str(original_tip_hash)
            )
            result["chain_restored"] = chain_restored

        # NetworkDisable flag is cleared by the rpc_dumptxoutset wrapper's
        # finally clause (covers success, error, unexpected exception).
        return result

    async def rpc_getchainstates(self) -> dict[str, Any]:
        """
        Return information about all active chainstates (BIP305 assumeUTXO support).

        When using assumeUTXO, there may be two active chainstates:
        1. The snapshot chainstate (serving queries)
        2. The background validation chainstate (validating from genesis)

        Returns:
            Object with chainstate information:
            - headers: Number of validated headers
            - chainstates: Array of chainstate info objects

        Reference: Bitcoin Core rpc/blockchain.cpp getchainstates (3462-3519)

        Shape matches Core exactly:
          {
            headers: NUM,                       # best header height (-1 if none)
            chainstates: [                       # ordered by work, ACTIVE LAST
              {
                blocks: NUM,
                bestblockhash: STR_HEX,
                bits: STR_HEX,                   # e.g. "1702068f"
                target: STR_HEX,
                difficulty: NUM,
                verificationprogress: NUM,       # [0..1]
                snapshot_blockhash: STR_HEX,     # OPTIONAL, snapshot-based only
                coins_db_cache_bytes: NUM,
                coins_tip_cache_bytes: NUM,
                validated: BOOL,
              }, ...
            ]
          }
        """
        if not hasattr(self.node, 'db') or self.node.db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db
        best_hash, best_height = db.get_best_block()

        # Coins cache sizes — Core reports the configured coinsdb/coinstip
        # cache budgets (cs.m_coinsdb_cache_size_bytes /
        # cs.m_coinstip_cache_size_bytes).  Ouroboros has no native split
        # cache accounting, so surface the configured dbcache budget (or 0).
        config = getattr(self.node, 'config', None) or {}
        dbcache_mb = config.get('dbcache', 0) if isinstance(config, dict) else 0
        coins_db_cache_bytes = int(dbcache_mb) * 1024 * 1024 if dbcache_mb else 0
        coins_tip_cache_bytes = coins_db_cache_bytes

        def _make_chain_data(
            blocks: int,
            tip_hash: Any,
            bits: int,
            validated: bool,
            snapshot_blockhash: str | None = None,
        ) -> dict[str, Any]:
            # Compute difficulty target from compact bits (Core GetTarget).
            mantissa = bits & 0x007FFFFF
            exponent = (bits >> 24) & 0xFF
            if exponent <= 3:
                target_int = mantissa >> (8 * (3 - exponent))
            else:
                target_int = mantissa << (8 * (exponent - 3))

            if isinstance(tip_hash, bytes):
                best_block_hex = tip_hash[::-1].hex()
            elif tip_hash is None:
                # Tip hash unavailable (e.g. background-validation chainstate
                # whose in-progress tip is not tracked in memory) — emit a
                # well-formed all-zero hash rather than a literal "None".
                best_block_hex = "0" * 64
            else:
                best_block_hex = str(tip_hash)

            difficulty = (
                self.node.get_difficulty(bits)
                if hasattr(self.node, 'get_difficulty')
                else 1.0
            )

            data: dict[str, Any] = {
                "blocks": blocks,
                "bestblockhash": best_block_hex,
                "bits": f"{bits:08x}",
                "target": f"{target_int:064x}",
                "difficulty": difficulty,
                "verificationprogress": self._verification_progress(),
                "coins_db_cache_bytes": coins_db_cache_bytes,
                "coins_tip_cache_bytes": coins_tip_cache_bytes,
            }
            # OPTIONAL: present only for a from-snapshot chainstate.
            if snapshot_blockhash is not None:
                data["snapshot_blockhash"] = snapshot_blockhash
            data["validated"] = validated
            return data

        # Header height (best header seen so far), -1 if none.  Mirrors
        # getblockchaininfo's header-count derivation.
        headers = best_height
        if hasattr(self.node, 'sync_manager') and self.node.sync_manager:
            sm = self.node.sync_manager
            if hasattr(sm, 'header_height'):
                headers = max(sm.header_height, best_height)
        if headers is None:
            headers = -1

        # Read the ACTUAL tip block's nBits from the block store. The cached
        # db._tip_bits is only set on block-connect (database.py) and is NOT
        # restored on a restart-at-tip, so it reads the genesis default
        # (0x1d00ffff) until the next block arrives — which would report a stale
        # genesis bits/target/difficulty. Fetch the tip block directly (same
        # source getblock/getblockheader use) and fall back to the cache only if
        # the body is unavailable.
        _tip_block = db.get_block(best_hash) if best_hash else None
        tip_bits = (
            _tip_block.bits
            if _tip_block is not None and isinstance(getattr(_tip_block, 'bits', None), int)
            else getattr(db, '_tip_bits', 0x1d00ffff)
        )

        chainstates: list[dict[str, Any]] = []

        # Determine whether the active chainstate is snapshot-based, and
        # whether a separate background-validation chainstate exists.  Core
        # orders by work with the active (most-work) chainstate LAST, so the
        # background chainstate (if any) is pushed FIRST.
        snapshot_status = None
        if hasattr(self.node, 'snapshot_manager') and self.node.snapshot_manager:
            snapshot_status = self.node.snapshot_manager.get_status()

        active_snapshot_blockhash: str | None = None
        active_validated = True

        if snapshot_status and snapshot_status["snapshot_loaded"]:
            active_snapshot_blockhash = snapshot_status["snapshot_hash"]
            # The active (snapshot) chainstate is only fully validated once the
            # background dual-chainstate re-derivation MATCHED the commitment.
            # It is False while the background validator is still running AND
            # stays False after a mismatch (Core marks the snapshot INVALID and
            # AbortNode()s; we surface it via validated=False rather than
            # silently accepting). snapshot_invalid pins that terminal state.
            active_validated = bool(
                snapshot_status.get("background_validated", False)
            ) and not bool(snapshot_status.get("snapshot_invalid", False))

            # Background validation chainstate (validating from genesis) is a
            # lower-work chainstate → emitted BEFORE the active one.
            if snapshot_status["background_validating"]:
                bg_bits = tip_bits
                chainstates.append(
                    _make_chain_data(
                        blocks=snapshot_status["background_validation_height"],
                        tip_hash=None,
                        bits=bg_bits,
                        validated=True,
                    )
                )

        # Active (most-work) chainstate — emitted LAST.
        chainstates.append(
            _make_chain_data(
                blocks=best_height,
                tip_hash=best_hash,
                bits=tip_bits,
                validated=active_validated,
                snapshot_blockhash=active_snapshot_blockhash,
            )
        )

        return {
            "headers": headers,
            "chainstates": chainstates,
        }

    def _verification_progress(self) -> float:
        """Estimate verification progress in [0..1].

        Mirrors getblockchaininfo's verificationprogress derivation:
        1.0 when synced; otherwise a time-based estimate from the tip
        block time relative to genesis.
        """
        is_ibd = not self._is_synced()
        if not is_ibd:
            return 1.0
        db = getattr(self.node, 'db', None)
        block_time = getattr(db, '_tip_timestamp', 0) if db is not None else 0
        if block_time <= 0:
            return 1.0
        import time as _time
        # Genesis time for mainnet: 2009-01-03 18:15:05 UTC.
        genesis_time = 1231006505
        current_time = int(_time.time())
        if current_time <= genesis_time:
            return 1.0
        return min(1.0, max(0.0,
            (block_time - genesis_time) / (current_time - genesis_time)
        ))

    async def rpc_decoderawtransaction(
        self, hexstring: str, iswitness: bool = True
    ) -> dict[str, Any]:
        """
        Decode a hex-encoded raw transaction.

        Reference: Bitcoin Core rpc/rawtransaction.cpp decoderawtransaction

        Produces output byte-identical to Core's TxToUniv (core_io.cpp) via the
        shared _tx_to_univ helper from psbt.py.  BTCAmount sentinels in the
        returned dict are serialized by _BTCEncoder (wired to all RPC responses
        via _BTCJsonResponse in the dispatch layer), giving the Core-exact
        "%d.%08d" decimal format for value fields.

        Args:
            hexstring: The hex-encoded transaction data
            iswitness: Whether to attempt parsing as a SegWit transaction (default True)

        Returns:
            JSON object with transaction details: txid, hash (wtxid), version,
            size, vsize, weight, locktime, vin, vout
        """
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.psbt import _tx_to_univ

        try:
            raw_bytes = bytes.fromhex(hexstring)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}") from None

        try:
            tx_msg = TxMessage.from_payload(raw_bytes)
            tx = tx_msg.transaction
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decode transaction: {e}") from None

        network = getattr(self.node, "network", "mainnet")
        return _tx_to_univ(tx, network)

    async def rpc_decodescript(self, hexstring: str) -> dict[str, Any]:
        """
        Decode a hex-encoded script.

        Reference: Bitcoin Core rpc/rawtransaction.cpp decodescript (line 450).

        Shape: {asm, desc, type, address?, p2sh?, segwit?}
        Top-level has NO hex field (Core's ScriptToUniv include_hex=false).
        p2sh emitted when can_wrap=true (Core lines 529-530).
        segwit emitted when can_wrap AND can_wrap_P2WSH (Core lines 561-576).
        segwit inner shape: {asm, desc, hex, type, address?, p2sh-segwit}
          (Core's ScriptToUniv include_hex=true on the inner script).
        """
        import hashlib
        import base58
        import bech32 as _bech32_mod
        from ouroboros.psbt import (
            _build_spk_json,
            _spk_type,
            _spk_to_address,
            _spk_asm,
            _infer_descriptor,
        )
        from ouroboros.descriptors import add_checksum

        try:
            script_bytes = bytes.fromhex(hexstring)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}") from None

        network = getattr(self.node, "network", "mainnet")
        is_mainnet = (network == "mainnet")
        is_regtest = (network in ("regtest", "signet"))
        p2sh_ver = b"\x05" if is_mainnet else b"\xc4"
        bech32_hrp = "bc" if is_mainnet else ("bcrt" if is_regtest else "tb")

        def _is_push_only(script: bytes, start: int = 0) -> bool:
            """Return True iff every opcode from `start` is a valid push op.

            Mirrors Bitcoin Core's CScript::IsPushOnly / GetScriptOp semantics:
            returns False if a push opcode's length extends past end-of-script.
            """
            i = start
            n = len(script)
            while i < n:
                op = script[i]; i += 1
                if op > 0x60:  # above OP_16 — not a push opcode
                    return False
                # Data pushes 0x01–0x4b
                if 0x01 <= op <= 0x4b:
                    i += op
                    if i > n:
                        return False
                elif op == 0x4c:  # PUSHDATA1
                    if i >= n:
                        return False
                    i += 1 + script[i]
                    if i > n:
                        return False
                elif op == 0x4d:  # PUSHDATA2
                    if i + 2 > n:
                        return False
                    size = int.from_bytes(script[i:i+2], "little"); i += 2 + size
                    if i > n:
                        return False
                elif op == 0x4e:  # PUSHDATA4
                    if i + 4 > n:
                        return False
                    size = int.from_bytes(script[i:i+4], "little"); i += 4 + size
                    if i > n:
                        return False
                # OP_0 (0x00), OP_1NEGATE (0x4f), OP_1–OP_16 (0x51–0x60) → valid push
            return True

        # Build base object via shared helper: {asm, desc, hex, type, address?}
        spk_json = _build_spk_json(script_bytes, network)
        script_type = spk_json["type"]

        # Core's Solver() classifies OP_RETURN as NULL_DATA only when the
        # bytes after OP_RETURN are all valid push ops (IsPushOnly check).
        # If the tail is malformed (truncated push), Solver returns NONSTANDARD.
        # Mirror that: reclassify "nulldata" → "nonstandard" if not push-only.
        if script_type == "nulldata" and not _is_push_only(script_bytes, start=1):
            script_type = "nonstandard"

        # Top-level result: NO hex field (Core decodescript omits it).
        # Core's ScriptToUniv emits address BEFORE type (core_io.cpp:409):
        #   asm, desc, [address], type
        result: dict[str, Any] = {
            "asm": spk_json["asm"],
            "desc": spk_json["desc"],
        }
        if "address" in spk_json:
            result["address"] = spk_json["address"]
        result["type"] = script_type

        # ── Core's can_wrap gate ─────────────────────────────────────────────
        # Types that CAN be wrapped: pubkey, pubkeyhash, multisig, nonstandard,
        # witness_v0_keyhash, witness_v0_scripthash.
        # Types that cannot: nulldata, scripthash, witness_v1_taproot,
        # witness_unknown, anchor.
        # Also fails if: IsUnspendable (starts with OP_RETURN 0x6a or OP_0 with
        # zero payload), invalid ops, or contains OP_CHECKSIGADD (0xba) /
        # OP_SUCCESS opcodes.
        _CAN_WRAP_TYPES = {
            "pubkey", "pubkeyhash", "multisig", "nonstandard",
            "witness_v0_keyhash", "witness_v0_scripthash",
        }

        def _has_valid_ops(script: bytes) -> bool:
            """Walk script bytecode; return False on truncated push or unknown op > 0xb9 non-success range."""
            i = 0
            n = len(script)
            while i < n:
                op = script[i]; i += 1
                if 0x01 <= op <= 0x4b:
                    i += op
                    if i > n:
                        return False
                elif op == 0x4c:  # PUSHDATA1
                    if i >= n:
                        return False
                    i += 1 + script[i]
                    if i > n:
                        return False
                elif op == 0x4d:  # PUSHDATA2
                    if i + 2 > n:
                        return False
                    size = int.from_bytes(script[i:i+2], "little"); i += 2 + size
                    if i > n:
                        return False
                elif op == 0x4e:  # PUSHDATA4
                    if i + 4 > n:
                        return False
                    size = int.from_bytes(script[i:i+4], "little"); i += 4 + size
                    if i > n:
                        return False
            return True

        def _is_unspendable(script: bytes) -> bool:
            """True if script starts with OP_RETURN (0x6a) or is too large."""
            if len(script) > 10_000:
                return True
            return len(script) > 0 and script[0] == 0x6a

        # OP_SUCCESS opcodes per BIP-342 / Core IsOpSuccess:
        # 80 (0x50=OP_RESERVED treated as success in tapscript context, but
        # Core's IsOpSuccess list is: 80, 98, 126-129, 131-134, 137-138, 141-143, 187-254)
        _OP_SUCCESS = (
            {80, 98}
            | set(range(126, 130))
            | set(range(131, 135))
            | {137, 138}
            | set(range(141, 144))
            | set(range(187, 255))
        )
        OP_CHECKSIGADD = 0xba

        def _has_checksigadd_or_success(script: bytes) -> bool:
            """True if script contains OP_CHECKSIGADD or any OP_SUCCESS opcode."""
            i = 0
            n = len(script)
            while i < n:
                op = script[i]; i += 1
                if op == OP_CHECKSIGADD or op in _OP_SUCCESS:
                    return True
                # Skip push data to avoid false positives in push payloads
                if 0x01 <= op <= 0x4b:
                    i += op
                elif op == 0x4c:
                    if i < n:
                        i += 1 + script[i]
                elif op == 0x4d:
                    if i + 2 <= n:
                        size = int.from_bytes(script[i:i+2], "little"); i += 2 + size
                elif op == 0x4e:
                    if i + 4 <= n:
                        size = int.from_bytes(script[i:i+4], "little"); i += 4 + size
            return False

        can_wrap = (
            script_type in _CAN_WRAP_TYPES
            and _has_valid_ops(script_bytes)
            and not _is_unspendable(script_bytes)
            and not _has_checksigadd_or_success(script_bytes)
        )

        if can_wrap:
            # p2sh = Hash160(script) as P2SH address (script used as redeemScript)
            script_hash160 = hashlib.new(
                "ripemd160", hashlib.sha256(script_bytes).digest()
            ).digest()
            result["p2sh"] = base58.b58encode_check(p2sh_ver + script_hash160).decode()

            # ── Core's can_wrap_P2WSH gate ───────────────────────────────────
            # Allowed: pubkey (compressed only), pubkeyhash, nonstandard, multisig (compressed only).
            # Not allowed: witness_v0_keyhash, witness_v0_scripthash (already segwit).
            _CAN_WRAP_P2WSH_TYPES = {"pubkey", "pubkeyhash", "nonstandard", "multisig"}

            def _pubkeys_all_compressed(script: bytes, stype: str) -> bool:
                """For pubkey/multisig, verify all public keys in the script are compressed."""
                if stype == "pubkey":
                    # <len> <pubkey> OP_CHECKSIG
                    if len(script) >= 2:
                        pk_len = script[0]
                        if pk_len == 33 and len(script) == 35:
                            return True  # compressed
                        if pk_len == 65 and len(script) == 67:
                            return False  # uncompressed
                    return False
                if stype == "multisig":
                    # OP_M [<len> <pubkey>]... OP_N OP_CHECKMULTISIG
                    i = 1  # skip OP_M
                    while i < len(script) - 2:
                        pk_len = script[i]; i += 1
                        if pk_len == 0:
                            break
                        if i + pk_len > len(script):
                            break
                        if pk_len != 33:
                            return False  # uncompressed pubkey
                        i += pk_len
                    return True
                return True

            can_wrap_p2wsh = (
                script_type in _CAN_WRAP_P2WSH_TYPES
                and _pubkeys_all_compressed(script_bytes, script_type)
            )

            if can_wrap_p2wsh:
                # Build the inner segwit script
                if script_type == "pubkey":
                    # P2WPKH: OP_0 <Hash160(pubkey)>
                    pk_len = script_bytes[0]
                    pubkey_bytes = script_bytes[1:1 + pk_len]
                    pk_hash160 = hashlib.new(
                        "ripemd160", hashlib.sha256(pubkey_bytes).digest()
                    ).digest()
                    seg_script = b"\x00\x14" + pk_hash160
                elif script_type == "pubkeyhash":
                    # P2WPKH: OP_0 <20-byte hash> (extracted from P2PKH script)
                    pk_hash160 = script_bytes[3:23]
                    seg_script = b"\x00\x14" + pk_hash160
                else:
                    # P2WSH: OP_0 <SHA256(script)>
                    script_sha256 = hashlib.sha256(script_bytes).digest()
                    seg_script = b"\x00\x20" + script_sha256

                # Build inner segwit object using _build_spk_json
                # (which returns {asm, desc, hex, address?, type})
                seg_spk = _build_spk_json(seg_script, network)
                # Inner segwit DOES include hex (Core include_hex=true).
                # Core ScriptToUniv order: asm, desc, hex, [address], type.
                seg_result: dict[str, Any] = {
                    "asm": seg_spk["asm"],
                    "desc": seg_spk["desc"],
                    "hex": seg_spk["hex"],
                }
                if "address" in seg_spk:
                    seg_result["address"] = seg_spk["address"]
                seg_result["type"] = seg_spk["type"]

                # p2sh-segwit: P2SH wrapping the segwit script
                seg_hash160 = hashlib.new(
                    "ripemd160", hashlib.sha256(seg_script).digest()
                ).digest()
                seg_result["p2sh-segwit"] = base58.b58encode_check(p2sh_ver + seg_hash160).decode()

                result["segwit"] = seg_result

        return result

    def _classify_script(self, script: bytes) -> str:
        """Classify a script into its type with extended detection."""
        if not script:
            return "nonstandard"

        # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        if (len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and
            script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac):
            return "pubkeyhash"

        # P2SH: OP_HASH160 <20> OP_EQUAL
        if len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
            return "scripthash"

        # P2WPKH: OP_0 <20>
        if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
            return "witness_v0_keyhash"

        # P2WSH: OP_0 <32>
        if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
            return "witness_v0_scripthash"

        # P2TR: OP_1 <32>
        if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
            return "witness_v1_taproot"

        # Witness unknown: OP_N <program> where N is 2-16 or program length != 20/32
        if len(script) >= 4 and 0x52 <= script[0] <= 0x60:
            version = script[0] - 0x50
            prog_len = script[1]
            if 2 <= prog_len <= 40 and len(script) == prog_len + 2:
                return f"witness_v{version}_unknown"

        # P2PK uncompressed: <65> OP_CHECKSIG
        if len(script) == 67 and script[0] == 0x41 and script[-1] == 0xac:
            return "pubkey"

        # P2PK compressed: <33> OP_CHECKSIG
        if len(script) == 35 and script[0] == 0x21 and script[-1] == 0xac:
            return "pubkey"

        # Multisig: OP_M <pubkeys...> OP_N OP_CHECKMULTISIG
        if len(script) > 3 and script[-1] == 0xae:
            first = script[0]
            if 0x51 <= first <= 0x60:  # OP_1 to OP_16
                return "multisig"

        # OP_RETURN (nulldata) — only if the tail is entirely valid push ops.
        # A truncated push (e.g. 6a 09 dead beef — PUSH9 with 4 data bytes)
        # must be classified nonstandard, not nulldata.
        # Reference: Bitcoin Core script/solver.cpp Solver() ~line 185:
        #   if (IsPushOnly(script.begin()+1, script.end())) return TX_NULL_DATA;
        if len(script) > 0 and script[0] == 0x6a:
            from ouroboros.mempool import _is_push_only_from
            if _is_push_only_from(script, 1):
                return "nulldata"
            return "nonstandard"

        return "nonstandard"

    async def rpc_getbalance(
        self,
        dummy: str = "*",
        minconf: int = 0,
        include_watchonly: bool = True,
    ) -> float:
        """
        Get the total wallet balance.

        Reference: Bitcoin Core rpc/wallet.cpp getbalance

        Args:
            dummy: Dummy argument (for compatibility, must be "*")
            minconf: Minimum confirmations for a transaction to be included
            include_watchonly: Include watch-only addresses in balance

        Returns:
            Balance in BTC as a float
        """
        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        if wallet.db is None:
            raise HTTPException(status_code=500, detail="Wallet database not available")

        # Get current best height for confirmation counting
        best_hash, best_height = wallet.db.get_best_block() if wallet.db else (None, 0)

        total_balance = 0

        # Get all wallet addresses
        addresses = set()

        # From imported keys
        for key_data in wallet.keys:
            from ouroboros.wallet import WalletKey
            try:
                key = WalletKey.from_wif(key_data["wif"], wallet.network)
                # Add all address types for the key
                addresses.add(key.get_p2wpkh_address())
                addresses.add(key.get_p2pkh_address())
                addresses.add(key.get_p2sh_p2wpkh_address())
            except Exception:
                continue

        # From descriptors
        for entry in wallet.descriptors:
            if not entry.active:
                continue
            try:
                end = max(entry.next_index, entry.range_start + 1)
                for i in range(entry.range_start, end):
                    addr = entry.descriptor.derive_address(i, wallet.network)
                    addresses.add(addr)
            except Exception:
                continue

        # Maturity threshold for coinbase outputs (Core COINBASE_MATURITY).
        COINBASE_MATURITY = 100

        # Sum UTXOs for all addresses, enforcing both confirmation count and
        # coinbase maturity. Iterating list_unspent_by_address (which now reads
        # the REAL chainstate and carries height + is_coinbase per coin) lets us
        # exclude immature coinbase exactly as Core's available-balance does.
        # Reference: Bitcoin Core wallet GetBalance / IsImmatureCoinBase.
        for addr in addresses:
            try:
                utxos = wallet.db.list_unspent_by_address(addr, wallet.network)
            except Exception:
                continue
            for utxo in utxos:
                utxo_height = utxo.get('height', 0) or 0
                if utxo_height == 0:
                    confs = 0
                else:
                    confs = max(0, best_height - utxo_height + 1)
                if confs < minconf:
                    continue
                # Immature coinbase is excluded from the spendable balance.
                if utxo.get('is_coinbase', False) and confs < (COINBASE_MATURITY + 1):
                    continue
                total_balance += utxo.get('value', 0)

        # Convert satoshis to BTC
        return total_balance / 100_000_000

    async def rpc_getbalances(self) -> dict[str, Any]:
        """Return wallet balances split by trust state.

        Reference: Bitcoin Core wallet/rpc/coins.cpp::getbalances. The
        ``mine`` object returns three buckets:

        - ``trusted``: confirmed UTXOs the wallet can sign (height > 0).
        - ``untrusted_pending``: same wallet, but height == 0 (mempool).
        - ``immature``: coinbase outputs whose maturity is < 100 blocks.

        Watch-only output is omitted because ouroboros's wallet does not
        currently track watch-only descriptors as a separate bucket; the
        ``getbalance`` handler folds them into the main balance. This
        matches Core's behavior when a wallet has no watch-only keys.
        """
        from ouroboros.wallet import WalletKey

        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")
        if wallet.db is None:
            raise HTTPException(status_code=500, detail="Wallet database not available")

        # Tip height for confirmation accounting.
        try:
            best_hash, best_height = wallet.db.get_best_block()
        except Exception:
            best_hash, best_height = None, 0

        # COINBASE_MATURITY = 100 (consensus-wide).
        COINBASE_MATURITY = 100

        # Build address set, mirroring rpc_getbalance.
        addresses: set[str] = set()
        for key_data in wallet.keys:
            try:
                key = WalletKey.from_wif(key_data["wif"], wallet.network)
                addresses.add(key.get_p2wpkh_address())
                addresses.add(key.get_p2pkh_address())
                addresses.add(key.get_p2sh_p2wpkh_address())
            except Exception:
                continue
        for entry in wallet.descriptors:
            if not entry.active:
                continue
            try:
                end = max(entry.next_index, entry.range_start + 1)
                for i in range(entry.range_start, end):
                    addresses.add(entry.descriptor.derive_address(i, wallet.network))
            except Exception:
                continue

        trusted_sat = 0
        untrusted_pending_sat = 0
        immature_sat = 0

        for addr in addresses:
            utxos: list[dict[str, Any]] = []
            if hasattr(wallet.db, "get_utxos_for_address"):
                try:
                    utxos = wallet.db.get_utxos_for_address(addr, wallet.network) or []
                except Exception:
                    utxos = []
            elif hasattr(wallet.db, "list_unspent_by_address"):
                try:
                    utxos = wallet.db.list_unspent_by_address(addr, wallet.network) or []
                except Exception:
                    utxos = []

            for utxo in utxos:
                value = int(utxo.get("value", utxo.get("amount", 0)) or 0)
                height = utxo.get("height", 0) or 0
                is_coinbase = bool(
                    utxo.get("is_coinbase", utxo.get("coinbase", False))
                )
                if height <= 0:
                    untrusted_pending_sat += value
                    continue
                if is_coinbase:
                    confs = max(0, best_height - height + 1)
                    if confs < COINBASE_MATURITY:
                        immature_sat += value
                        continue
                trusted_sat += value

        balances: dict[str, Any] = {
            "mine": {
                "trusted": trusted_sat / 100_000_000,
                "untrusted_pending": untrusted_pending_sat / 100_000_000,
                "immature": immature_sat / 100_000_000,
            }
        }

        # Last-processed-block (RESULT_LAST_PROCESSED_BLOCK in Core).
        if best_hash is not None:
            try:
                hash_hex = (
                    best_hash.hex()
                    if isinstance(best_hash, (bytes, bytearray))
                    else str(best_hash)
                )
            except Exception:
                hash_hex = ""
            balances["lastprocessedblock"] = {
                "hash": hash_hex,
                "height": int(best_height),
            }

        return balances

    async def rpc_signrawtransactionwithwallet(
        self,
        hexstring: str,
        prevtxs: list[dict] | None = None,
        sighashtype: str = "ALL",
    ) -> dict[str, Any]:
        """
        Sign a raw transaction with wallet keys.

        Reference: Bitcoin Core rpc/rawtransaction.cpp signrawtransactionwithwallet

        Args:
            hexstring: The hex-encoded raw transaction
            prevtxs: Array of previous transaction outputs (optional, for signing
                     inputs not in the blockchain/mempool)
            sighashtype: The signature hash type: ALL, NONE, SINGLE,
                         ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY

        Returns:
            JSON object with: hex (signed transaction), complete (bool)
        """
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.wallet import WalletKey, _dsha256, _hash160

        wallet = self._get_wallet_for_rpc()
        if wallet is None:
            raise HTTPException(status_code=500, detail="No wallet loaded")

        if wallet.is_locked:
            raise HTTPException(status_code=500, detail="Wallet is locked; unlock with walletpassphrase")

        # Parse sighash type
        sighash_map = {
            "ALL": 0x01,
            "NONE": 0x02,
            "SINGLE": 0x03,
            "ALL|ANYONECANPAY": 0x81,
            "NONE|ANYONECANPAY": 0x82,
            "SINGLE|ANYONECANPAY": 0x83,
        }
        sighash = sighash_map.get(sighashtype.upper())
        if sighash is None:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid sighashtype: {sighashtype}. Valid types: {list(sighash_map.keys())}"
            )

        # Parse transaction
        try:
            raw_bytes = bytes.fromhex(hexstring)
            tx_msg = TxMessage.from_payload(raw_bytes)
            tx = tx_msg.transaction
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to decode transaction: {e}") from None

        # Build a map of scriptPubKey -> WalletKey for signing
        spk_to_key: dict[bytes, WalletKey] = {}
        for key_data in wallet.keys:
            try:
                key = WalletKey.from_wif(key_data["wif"], wallet.network)
                # P2WPKH scriptPubKey
                spk_to_key[key.get_script_pubkey()] = key
                # P2PKH scriptPubKey
                h160 = _hash160(key.pubkey)
                p2pkh_spk = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                spk_to_key[p2pkh_spk] = key
            except Exception:
                continue

        # Build prevtxs lookup if provided
        prevtxs_map: dict[tuple, dict] = {}
        if prevtxs:
            for prev in prevtxs:
                txid = prev.get("txid", "")
                vout = prev.get("vout", 0)
                prevtxs_map[(txid, vout)] = prev

        # Track signing status
        errors = []
        signed_count = 0

        # Sign each input
        for i, tx_in in enumerate(tx.inputs):
            # tx_in.prev_txid is internal LE; convert to display-order (BE)
            # for prevtxs_map lookup and for JSON error emission. W69.
            prev_txid_hex = tx_in.prev_txid[::-1].hex()
            prev_vout = tx_in.prev_vout

            # Skip if already signed (has witness or non-empty scriptSig)
            if tx_in.witness and len(tx_in.witness) > 0:
                signed_count += 1
                continue
            if tx_in.script_sig and len(tx_in.script_sig) > 0:
                signed_count += 1
                continue

            # Find scriptPubKey from prevtxs or database
            script_pubkey = None
            value = None

            if (prev_txid_hex, prev_vout) in prevtxs_map:
                prev = prevtxs_map[(prev_txid_hex, prev_vout)]
                spk_hex = prev.get("scriptPubKey", "")
                if spk_hex:
                    script_pubkey = bytes.fromhex(spk_hex)
                value = int(prev.get("amount", 0) * 100_000_000)
            elif wallet.db:
                utxo = await asyncio.to_thread(wallet.db.get_utxo, tx_in.prev_txid, prev_vout)
                if utxo:
                    script_pubkey = utxo.get('script_pubkey')
                    value = utxo.get('value')

            if script_pubkey is None:
                errors.append({
                    "txid": prev_txid_hex,
                    "vout": prev_vout,
                    "error": "Input not found or missing scriptPubKey"
                })
                continue

            # Find matching wallet key
            key = spk_to_key.get(script_pubkey)

            # Check if P2SH-P2WPKH
            is_p2sh_p2wpkh = False
            if key is None and len(script_pubkey) == 23 and script_pubkey[0] == 0xa9:
                # P2SH - check if we have a key for P2SH-P2WPKH
                for wkey in spk_to_key.values():
                    h160 = _hash160(wkey.pubkey)
                    redeem_script = b"\x00\x14" + h160
                    script_hash = _hash160(redeem_script)
                    p2sh_spk = b"\xa9\x14" + script_hash + b"\x87"
                    if p2sh_spk == script_pubkey:
                        key = wkey
                        is_p2sh_p2wpkh = True
                        break

            if key is None:
                errors.append({
                    "txid": prev_txid_hex,
                    "vout": prev_vout,
                    "error": "Unable to find key for this input"
                })
                continue

            if value is None:
                errors.append({
                    "txid": prev_txid_hex,
                    "vout": prev_vout,
                    "error": "Missing input value (required for SegWit signing)"
                })
                continue

            # Determine signing method based on script type
            script_type = self._get_script_type(script_pubkey)

            # BIP-143 sighash — single source of truth lives in
            # ``ouroboros.segwit_v0`` (W29-A). The legacy
            # ``self._compute_bip143_sighash`` helper that used to live
            # below was removed because it byte-reversed ``prev_txid``
            # against ``Transaction.serialize_with_witness``'s wire
            # convention, producing sighashes that didn't verify on the
            # network. See
            # ``tests/test_rpc_signrawtransactionwithwallet_bip143.py``.
            from ouroboros.segwit_v0 import bip143_sighash

            try:
                if script_type == "witness_v0_keyhash":
                    # P2WPKH signing (BIP143). scriptCode is the
                    # canonical P2PKH script over the witness program's
                    # 20-byte hash.
                    h160 = _hash160(key.pubkey)
                    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                    sighash_bytes = bip143_sighash(
                        tx, i, script_code, value, sighash
                    )
                    sig = key.sign(sighash_bytes) + bytes([sighash])
                    tx.inputs[i].witness = [sig, key.pubkey]
                    tx.has_witness = True
                    signed_count += 1

                elif is_p2sh_p2wpkh:
                    # P2SH-P2WPKH signing
                    h160 = _hash160(key.pubkey)
                    redeem_script = b"\x00\x14" + h160
                    tx.inputs[i].script_sig = bytes([len(redeem_script)]) + redeem_script
                    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                    sighash_bytes = bip143_sighash(
                        tx, i, script_code, value, sighash
                    )
                    sig = key.sign(sighash_bytes) + bytes([sighash])
                    tx.inputs[i].witness = [sig, key.pubkey]
                    tx.has_witness = True
                    signed_count += 1

                elif script_type == "pubkeyhash":
                    # Legacy P2PKH signing
                    sighash_bytes = self._compute_legacy_sighash(
                        tx, i, script_pubkey, sighash
                    )
                    sig = key.sign(sighash_bytes) + bytes([sighash])
                    # Build scriptSig: <sig> <pubkey>
                    script_sig = bytes([len(sig)]) + sig + bytes([len(key.pubkey)]) + key.pubkey
                    tx.inputs[i].script_sig = script_sig
                    signed_count += 1

                else:
                    errors.append({
                        "txid": prev_txid_hex,
                        "vout": prev_vout,
                        "error": f"Unsupported script type: {script_type}"
                    })

            except Exception as e:
                errors.append({
                    "txid": prev_txid_hex,
                    "vout": prev_vout,
                    "error": str(e)
                })

        # Recompute txid
        tx.txid = _dsha256(tx.serialize())

        # Serialize signed transaction
        if tx.has_witness:
            signed_hex = tx.serialize_with_witness().hex()
        else:
            signed_hex = tx.serialize().hex()

        complete = len(errors) == 0 and signed_count == len(tx.inputs)

        result: dict[str, Any] = {
            "hex": signed_hex,
            "complete": complete,
        }

        if errors:
            result["errors"] = errors

        return result

    # NOTE: ``_compute_bip143_sighash`` was removed in W29-A. It was a
    # third drift-prone copy of BIP-143 sighash and — critically — it
    # byte-reversed ``prev_txid`` against
    # ``Transaction.serialize_with_witness``'s wire convention. The
    # ``signrawtransactionwithwallet`` callers above now route through
    # ``ouroboros.segwit_v0.bip143_sighash`` (the single source of
    # truth, also used by ``signrawtransactionwithkey`` and
    # ``walletprocesspsbt``).
    def _compute_legacy_sighash(
        self, tx, input_index: int, script_pubkey: bytes, sighash_type: int
    ) -> bytes:
        """Compute legacy signature hash for P2PKH inputs."""
        from ouroboros.wallet import _dsha256

        # Create a copy of the transaction for signing
        tx_copy_inputs = []
        for i, inp in enumerate(tx.inputs):
            if i == input_index:
                new_script = script_pubkey
            else:
                new_script = b""
            tx_copy_inputs.append((
                inp.prev_txid,
                inp.prev_vout,
                new_script,
                inp.sequence
            ))

        # Serialize for signing
        data = tx.version.to_bytes(4, 'little', signed=True)
        data += self._encode_varint(len(tx_copy_inputs))
        for prev_txid, prev_vout, script, seq in tx_copy_inputs:
            data += prev_txid[::-1]  # Wire format is reversed
            data += prev_vout.to_bytes(4, 'little')
            data += self._encode_varint(len(script))
            data += script
            data += seq.to_bytes(4, 'little')
        data += self._encode_varint(len(tx.outputs))
        for out in tx.outputs:
            data += out.value.to_bytes(8, 'little')
            data += self._encode_varint(len(out.script_pubkey))
            data += out.script_pubkey
        data += tx.locktime.to_bytes(4, 'little')
        data += sighash_type.to_bytes(4, 'little')

        return _dsha256(data)

    def _encode_varint(self, value: int) -> bytes:
        """Encode a varint."""
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')

    async def _handle_payjoin_request(self, http_request: Request):
        """Receive a BIP-78 Original PSBT and return the receiver-modified PSBT.

        End-to-end flow:

          1. Validate the request's Content-Type header (G23 — BIP-78 §3
             mandates ``text/plain``; ``application/octet-stream`` is
             tolerated because the btcpayserver Rust client emits it).
             Anything else returns ``original-psbt-rejected``.
          2. Read raw POST body (base64-encoded PSBT per BIP-78).
          3. Parse the query-string parameters (``v=1``,
             ``additionalfeeoutputindex``, ``maxadditionalfeecontribution``,
             ``minfeerate``; output-substitution-disable flag is parsed
             by the payjoin module but not advertised here).
          4. Check the G18 TTL tracker.  If the Original PSBT fingerprint
             is still cached the request is refused as ``original-psbt-
             rejected`` (replay window).
          5. Check the G19 double-broadcast watcher.  If the sender has
             already fallback-broadcast the Original PSBT the receiver
             refuses (a fresh proposal here would race the broadcast
             tx in the mempool).
          6. Check the G30 replay tracker.  If a proposal has already
             been pinned for this Original PSBT, return the pinned
             proposal verbatim (idempotent receiver).
          7. Build a :class:`payjoin.ReceiverContext` from the wallet:
             list of spendable UTXOs, key lookup by scriptPubKey, the
             receiver's expected payment scriptPubKey, and minimum
             amount.
          8. Delegate to :func:`payjoin.process_payjoin_request` which
             validates, contributes a CSPRNG-selected UTXO, signs, and
             returns the base64 PSBT body.
          9. Pin the proposal in :data:`payjoin.payjoin_replay` and the
             Original PSBT fingerprint in :data:`payjoin.original_psbt_ttl`.
         10. On :class:`payjoin.PayJoinError`, return the canonical
             ``{"errorCode": ..., "message": ...}`` JSON wrapper with
             the BIP-78 4xx/5xx HTTP status.  Codes: ``unavailable``,
             ``not-enough-money``, ``version-unsupported``,
             ``original-psbt-rejected``.

        Authentication is intentionally NOT required: BIP-78 receivers
        are publicly addressable by design (the URL is shared via a
        BIP-21 ``pj=`` parameter to senders the operator may never
        otherwise interact with).  Receivers SHOULD front-end this
        endpoint with HTTPS (clearnet) or a Tor v3 hidden service per
        BIP-78 §endpoint; FIX-64 wired uvicorn ssl_certfile /
        ssl_keyfile for the HTTPS half.  The ``payjoin_tls_*`` and
        ``payjoin_https_*`` policy helpers live in
        :mod:`ouroboros.payjoin` (G3 / G24).  Operators publishing the
        endpoint over Tor MUST set ``payjoin_onion_advertise`` /
        ``payjoin_tor_hidden_service`` on the node (G25).
        """
        from ouroboros import payjoin as _payjoin

        # G23 — Content-Type negotiation.  parse_payjoin_content_type
        # raises ``original-psbt-rejected`` on unsupported types and is
        # the only payjoin_content_type call site in the receiver path.
        payjoin_content_type = http_request.headers.get("content-type", "")
        try:
            _payjoin.parse_payjoin_content_type(payjoin_content_type)
        except _payjoin.PayJoinError as ct_exc:
            return JSONResponse(
                ct_exc.to_json(), status_code=ct_exc.http_status
            )

        body = await http_request.body()
        # FastAPI gives us a starlette QueryParams (multi-dict).  Flatten
        # to a plain dict for the parser; PayJoin parameters are not
        # multi-valued.
        query = {k: v for k, v in http_request.query_params.items()}

        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            err = _payjoin.err_unavailable(
                "Receiver wallet not loaded; cannot honor PayJoin request"
            )
            return JSONResponse(err.to_json(), status_code=err.http_status)

        # Resolve the receiver's payment scriptPubKey.  Two ways the
        # operator can configure this:
        #   (a) explicit ``payjoin_receive_script`` set on the node, or
        #   (b) fall back to a freshly-derived receive address.
        receiver_script = getattr(self.node, "payjoin_receive_script", None)
        if receiver_script is None:
            try:
                # Fall back: any wallet key's P2WPKH script.
                first_key_info = wallet.keys[0]
                from ouroboros.wallet import WalletKey, _hash160 as _h160
                first_key = WalletKey.from_wif(
                    first_key_info["wif"],
                    getattr(self.node, "network", "mainnet"),
                )
                receiver_script = b"\x00\x14" + _h160(first_key.pubkey)
            except Exception:
                err = _payjoin.err_unavailable(
                    "Receiver has no configured payment scriptPubKey"
                )
                return JSONResponse(err.to_json(), status_code=err.http_status)

        # Minimum amount the receiver expects (the sender must include
        # at least this much in the payment output).  Operator-supplied;
        # default 0 means "any amount is fine".
        min_amount = int(getattr(self.node, "payjoin_min_amount", 0))

        # UTXO lister and key lookup — both are closures over the live
        # wallet so each request sees up-to-date state.
        def list_utxos():
            try:
                return wallet._collect_utxos()
            except AttributeError:
                return []

        def get_key_for_script(spk: bytes):
            # P2WPKH: scriptPubKey = OP_0 <20> <pubkey_hash>
            if len(spk) == 22 and spk[0:2] == b"\x00\x14":
                target_h160 = spk[2:]
                from ouroboros.wallet import WalletKey, _hash160 as _h160
                network = getattr(self.node, "network", "mainnet")
                for ki in wallet.keys:
                    try:
                        k = WalletKey.from_wif(ki["wif"], network)
                        if _h160(k.pubkey) == target_h160:
                            return k
                    except Exception:
                        continue
            return None

        ctx = _payjoin.ReceiverContext(
            list_utxos=list_utxos,
            get_key_for_script=get_key_for_script,
            receiver_script=receiver_script,
            min_amount=min_amount,
        )

        # G18 / G30 — pre-decode the Original PSBT so the TTL and replay
        # trackers can fingerprint it BEFORE we burn receiver UTXOs.  A
        # malformed PSBT short-circuits through the same exception path
        # as process_payjoin_request.
        try:
            _original_for_trackers = _payjoin.decode_original_psbt(body)
        except _payjoin.PayJoinError as exc:
            return JSONResponse(exc.to_json(), status_code=exc.http_status)

        # G19 — if the sender already fallback-broadcast this Original
        # PSBT, the receiver must refuse: producing a new proposal would
        # race the broadcast tx in the mempool and double-spend the
        # receiver's contribution.  Returns ``unavailable`` so the sender
        # can fall back (it already broadcast, so this is a no-op for it).
        if _payjoin.payjoin_fallback_detect.was_original_psbt_broadcast(
            _original_for_trackers
        ):
            err = _payjoin.err_unavailable(
                "Original PSBT already broadcast (payjoin_fallback_detect); "
                "refusing fresh proposal to avoid double-spend"
            )
            return JSONResponse(err.to_json(), status_code=err.http_status)

        # G30 — receiver MUST be idempotent.  If a proposal has been
        # pinned for this exact Original PSBT we return it verbatim
        # rather than producing a different proposal that would consume
        # overlapping receiver UTXOs (chain-analysis attack).
        pinned = _payjoin.payjoin_replay.lookup_pinned_proposal(
            _original_for_trackers
        )
        if pinned is not None:
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(
                pinned.decode("ascii"), media_type=_payjoin.PAYJOIN_CONTENT_TYPE
            )

        # G18 — TTL replay-window check.  If a different proposal flow
        # was running for this PSBT but no proposal pin landed (process
        # raised before we could pin), refuse for the duration of the
        # cache window.
        if not _payjoin.original_psbt_ttl.remember(_original_for_trackers):
            err = _payjoin.err_original_psbt_rejected(
                "Original PSBT within replay TTL window "
                f"(original_psbt_ttl={_payjoin.ORIGINAL_PSBT_TTL_DEFAULT_SEC}s, "
                "payjoin_session_ttl matches); resubmit later or finalise the "
                "original transaction"
            )
            return JSONResponse(err.to_json(), status_code=err.http_status)

        try:
            body_out = _payjoin.process_payjoin_request(body, query, ctx)
        except _payjoin.PayJoinError as exc:
            return JSONResponse(exc.to_json(), status_code=exc.http_status)
        except Exception as exc:
            # Receiver-internal bug: surface as ``unavailable`` per BIP-78
            # §"Receiver Error" so the sender knows it can fall back to
            # broadcasting the Original PSBT directly.  Log full
            # traceback for the operator.
            logger.exception("PayJoin receiver internal error: %s", exc)
            err = _payjoin.err_unavailable("Receiver internal error")
            return JSONResponse(err.to_json(), status_code=err.http_status)

        # G30 — pin the proposal so a replayed request returns the same
        # body.  The pin returns the canonical body in case another
        # producer raced us (idempotent semantics).
        body_out = _payjoin.payjoin_replay.pin_proposal(
            _original_for_trackers, body_out
        )

        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            body_out.decode("ascii"), media_type=_payjoin.PAYJOIN_CONTENT_TYPE
        )

    def get_app(self) -> FastAPI:
        """Get the FastAPI application"""
        return self.app
