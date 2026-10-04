"""Gate 6: a resource / system failure is never a consensus decision.

docs/RELEASE-CHECKLIST.md gate 6: *OOM, heap caps and timeouts lead to retry
or halt, never to a reject or accept.*  Audit:
receipts/gate6-resource-limit-audit-2026-10-04.md (ouroboros F1, F4, F9, F10,
F12, tier-3 mempool).

Bitcoin Core's model (bitcoin-core/src):
  * script checks report only ScriptError values (CScriptCheck /
    CCheckQueue); ``bad_alloc`` terminates the process;
  * a coins-DB read error goes through CCoinsViewErrorCatcher
    (coins.cpp:415-427) whose callback aborts the node;
  * a failed block read / write is FatalError -> AbortNode
    (validation.cpp:2136): the block is never marked invalid and its sender
    is never punished (MaybePunishNodeForBlock acts only on a
    BlockValidationResult).

Every test here is a FAULT INJECTION (the fault is made to happen) with a
CONTROL showing that a genuinely invalid block / script still gets its
verdict.  Each injected test fails on 852961d and passes after the fix.
"""

from __future__ import annotations

import gc
import glob
import os
import shutil
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ouroboros.database import Transaction, TxIn, TxOut

DB_ERR = (
    "Database error: get_utxo_batch: RocksDB error: Corruption: block "
    "checksum mismatch (missing input utxo)"
)


def _fatal():
    """``ouroboros.fatal`` (absent before the fix: tests must still FAIL, on
    behaviour, not on an import error)."""
    try:
        from ouroboros import fatal
    except ImportError:
        return None
    return fatal


def _is_fatal() -> bool:
    f = _fatal()
    return bool(f and f.is_fatal())


# ---------------------------------------------------------------------------
# F4 — sig-check exception returned ``false``: <sig> <pk> CHECKSIG NOT passed
# ---------------------------------------------------------------------------


def _push(data: bytes) -> bytes:
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


def _spend_tx() -> Transaction:
    return Transaction(
        txid=b"\x00" * 32,
        version=1,
        locktime=0,
        inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=1000, script_pubkey=b"\x51")],
    )


# A DER-shaped signature + SIGHASH_ALL and a compressed-format pubkey.  With
# flags=0 no encoding rule fires, so the interpreter reaches the actual
# signature check — which is where the fault is injected.
_SIG = bytes.fromhex(
    "3044022012345678901234567890123456789012345678901234567890123456789012"
    "3402201234567890123456789012345678901234567890123456789012345678901234"
) + b"\x01"
_PK = b"\x02" + b"\x55" * 32
_SCRIPT_SIG = _push(_SIG)
_CHECKSIG_NOT = _push(_PK) + b"\xac\x91"   # <pk> OP_CHECKSIG OP_NOT
_CHECKSIG = _push(_PK) + b"\xac"           # <pk> OP_CHECKSIG


def test_checksig_not_with_sigcheck_memoryerror_is_not_accepted(monkeypatch):
    """FAULT: the ECDSA verify raises MemoryError while checking the sig.

    Pre-fix the CHECKSIG catch-all pushed ``false``, OP_NOT made it true and
    the script PASSED — an invalid spend accepted (and the result cached).
    Post-fix the system error propagates: neither pass nor fail."""
    from ouroboros.script import ScriptInterpreter

    def _oom(*_a, **_k):
        raise MemoryError("injected: allocation failed in secp verify")

    monkeypatch.setattr(ScriptInterpreter, "_verify_ecdsa_signature", _oom)
    interp = ScriptInterpreter()
    with pytest.raises(MemoryError):
        interp.verify_python(_SCRIPT_SIG, _CHECKSIG_NOT, _spend_tx(), 0, flags=0)
    # The plain form must not turn the fault into "invalid" either.
    with pytest.raises(MemoryError):
        interp.verify_python(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0)


def test_checksig_with_db_runtimeerror_in_sighash_propagates(monkeypatch):
    """FAULT: the sighash computation hits a RuntimeError (thread / FFI)."""
    from ouroboros.script import ScriptInterpreter

    def _boom(*_a, **_k):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(ScriptInterpreter, "_calculate_signature_hash", _boom)
    interp = ScriptInterpreter()
    with pytest.raises(RuntimeError):
        interp.verify_python(_SCRIPT_SIG, _CHECKSIG_NOT, _spend_tx(), 0, flags=0)


def test_checksig_control_genuinely_invalid_signature(monkeypatch):
    """CONTROL: a signature that verifies FALSE keeps Core semantics —
    CHECKSIG pushes false, so CHECKSIG fails and CHECKSIG NOT succeeds
    (that is consensus-valid; NULLFAIL is a policy flag, off here)."""
    from ouroboros.script import ScriptInterpreter

    monkeypatch.setattr(
        ScriptInterpreter, "_verify_ecdsa_signature", lambda *a, **k: False
    )
    interp = ScriptInterpreter()
    assert interp.verify_python(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0) is False
    assert interp.verify_python(_SCRIPT_SIG, _CHECKSIG_NOT, _spend_tx(), 0, flags=0) is True


def test_checksig_control_interpreter_error_is_still_a_reject(monkeypatch):
    """CONTROL: a non-system interpreter exception (here IndexError) is still
    a script failure, never a pass — the three-outcome split only reroutes
    SYSTEM faults."""
    from ouroboros.script import ScriptInterpreter

    def _idx(*_a, **_k):
        raise IndexError("bad sighash input index")

    monkeypatch.setattr(ScriptInterpreter, "_calculate_signature_hash", _idx)
    interp = ScriptInterpreter()
    assert interp.verify_python(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0) is False


class _FakeNative:
    def __init__(self, exc=None, result=None):
        self._exc, self._result = exc, result

    def script_verify(self, *_a, **_k):
        if self._exc is not None:
            raise self._exc
        return self._result


def test_native_interpreter_system_error_is_not_a_reject(monkeypatch):
    """FAULT (OUROBOROS_NATIVE_SCRIPT=1 path): the native call raises
    MemoryError.  Pre-fix verify_native returned False -> a script verdict
    on a valid block (mark + ban).  Post-fix it propagates."""
    import ouroboros.script as smod

    monkeypatch.setattr(smod, "native_script_context", lambda *a, **k: object())
    monkeypatch.setattr(
        smod, "_native_sync_module",
        lambda: _FakeNative(exc=MemoryError("injected")),
    )
    interp = smod.ScriptInterpreter()
    with pytest.raises(MemoryError):
        interp.verify_native(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0)


def test_native_interpreter_control_script_error_is_reject(monkeypatch):
    """CONTROL (native): a real ScriptError still rejects."""
    import ouroboros.script as smod

    monkeypatch.setattr(smod, "native_script_context", lambda *a, **k: object())
    monkeypatch.setattr(
        smod, "_native_sync_module",
        lambda: _FakeNative(result=(False, 2, "SCRIPT_ERR_EVAL_FALSE")),
    )
    interp = smod.ScriptInterpreter()
    assert interp.verify_native(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0) is False
    # A non-system native exception keeps the old reject contract too.
    monkeypatch.setattr(
        smod, "_native_sync_module",
        lambda: _FakeNative(exc=ValueError("malformed")),
    )
    assert interp.verify_native(_SCRIPT_SIG, _CHECKSIG, _spend_tx(), 0, flags=0) is False


# ---------------------------------------------------------------------------
# F10 — serial script-check queue: "a crash is a reject"
# ---------------------------------------------------------------------------


def _queue_validator(behaviour):
    from ouroboros.validation import TransactionValidator

    tv = TransactionValidator.__new__(TransactionValidator)
    tv._verify_input_signature = behaviour
    return tv


def _one_item_queue():
    tx = _spend_tx()
    utxo = {"value": 1000, "script_pubkey": b"\x51"}
    return [(1, tx, tx.inputs[0], utxo, 0, 0, [1000], [b"\x51"])]


@pytest.fixture
def python_interpreter(monkeypatch):
    import ouroboros.validation as vmod

    monkeypatch.setattr(vmod, "NATIVE_SCRIPT_ENABLED", False)


def test_check_queue_recurring_system_error_is_internal_not_reject(python_interpreter):
    """FAULT: every attempt of a script check raises MemoryError.  Pre-fix:
    "Transaction 1 invalid: Invalid signature for input 0" (a verdict ->
    InvalidBlockFound + ban).  Post-fix: retried once, then
    InternalValidationError."""
    calls = []

    def _oom(*a):
        calls.append(a)
        raise MemoryError("injected")

    tv = _queue_validator(_oom)
    f = _fatal()
    expected = f.InternalValidationError if f else Exception
    with pytest.raises(expected):
        tv.run_script_check_queue(_one_item_queue(), 1)
    assert len(calls) == 2  # one retry in the caller (beamchain 30fdcfb pattern)


def test_check_queue_transient_system_error_retries_and_passes(python_interpreter):
    """FAULT (transient): the first attempt raises, the re-run succeeds ->
    the block's scripts PASS (pre-fix: rejected as an invalid signature)."""
    state = {"n": 0}

    def _flaky(*a):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError(24, "Too many open files")
        return True

    tv = _queue_validator(_flaky)
    assert tv.run_script_check_queue(_one_item_queue(), 1) is None


def test_check_queue_control_invalid_signature_is_reject(python_interpreter):
    """CONTROL: a genuinely failing script is still the first-failure verdict."""
    tv = _queue_validator(lambda *a: False)
    err = tv.run_script_check_queue(_one_item_queue(), 1)
    assert err == "Transaction 1 invalid: Invalid signature for input 0"


# ---------------------------------------------------------------------------
# Classifier — a wrapped system error must never map to a verdict token
# ---------------------------------------------------------------------------


def test_classifier_wrapped_db_errors_are_nonverdict():
    from ouroboros.block_sync import classify_block_reject as v

    # Pre-fix these mapped through the "transaction validation" / "missing
    # input" keywords to block-script-verify-flag-failed /
    # bad-txns-inputs-missingorspent: verdicts.
    assert v("validate: Transaction validation error: Database error: "
             "RocksDB error: IO error: No space left on device") == "nonverdict"
    assert v(DB_ERR) == "nonverdict"
    assert v("reorg-disconnect-failed: Database error: missing undo for input") == "nonverdict"
    f = _fatal()
    if f is not None:
        assert v(f"{f.INTERNAL_ERROR_MARKER}: script check: MemoryError") == "nonverdict"
    # CONTROLS — real consensus failures are still verdicts.
    assert v("Transaction 1 invalid: Input not found: ab:0") == "verdict"
    assert v("Transaction 2 invalid: Invalid signature for input 0") == "verdict"
    assert v("validate: Transaction validation error: Outputs exceed inputs") == "verdict"


def test_bip22_db_error_is_not_a_consensus_token():
    from ouroboros.rpc import bip22_result_string

    tok = bip22_result_string(
        "Transaction validation error: Database error: IO error (input 3)"
    )
    assert tok not in ("block-script-verify-flag-failed",
                       "bad-txns-inputs-missingorspent")
    # CONTROL
    assert bip22_result_string("Input not found: ab:0") == "bad-txns-inputs-missingorspent"


# ---------------------------------------------------------------------------
# F9 / F12 — P2P drain: a DB read error is not a verdict and not a ban
# ---------------------------------------------------------------------------


def _drain_bs():
    from ouroboros.block_sync import BlockSync

    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 0)
    pm = MagicMock()
    pm.misbehaving = MagicMock(return_value=True)
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    bs._prebase_headers_complete = True
    return bs


def _stage(bs, block_hash: bytes, child_hash: bytes, src: str = "127.0.0.2:5555"):
    tip_hash, _ = bs.db.get_best_block.return_value
    h1 = MagicMock()
    h1.prev_blockhash = tip_hash
    h2 = MagicMock()
    h2.prev_blockhash = block_hash
    bs._validated_headers = [(block_hash, h1), (child_hash, h2)]
    cb_in = MagicMock()
    cb_in.script_sig = bytes([0x00, 0x00])
    cb = MagicMock()
    cb.inputs = [cb_in]
    blk = MagicMock()
    blk.transactions = [cb]
    blk.timestamp = 0
    bs._ibd_block_buffer[block_hash] = (blk, b"\x00" * 80)
    bs.requested_blocks[block_hash] = 1.0
    bs._block_source_peer_addr[block_hash] = src


def _not_marked_not_punished(bs, b1):
    assert b1 not in bs._perm_rejected_blocks
    assert b1 not in getattr(bs, "_failed_blocks", set())
    bs.peer_manager.misbehaving.assert_not_called()


@pytest.mark.asyncio
async def test_drain_utxo_read_error_is_not_marked_or_punished(monkeypatch):
    """FAULT: the coins read raises (Rust PyRuntimeError "Database error")
    on every attempt.  Pre-fix the exception escaped the drain (and, through
    get_utxo_batch's Err->None, became "Input not found" -> verdict + ban).
    Post-fix: retried once, then AbortNode; block kept, nobody punished."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x41" * 32, b"\x42" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(side_effect=RuntimeError(DB_ERR))

    await bs._drain_block_buffer_locked()

    _not_marked_not_punished(bs, b1)
    assert b1 in bs._ibd_block_buffer          # held, not dropped
    assert [h for h, _ in bs._validated_headers] == [b1, b2]
    assert bs.validator.validate_block.call_count == 2   # one retry
    bs.db.connect_block_from_bytes.assert_not_called()  # never connected
    assert _is_fatal()                                  # AbortNode


@pytest.mark.asyncio
async def test_drain_transient_utxo_read_error_retries_and_connects(monkeypatch):
    """FAULT (transient): the first validate raises, the retry succeeds ->
    the block connects; the node is not halted."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x43" * 32, b"\x44" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(
        side_effect=[RuntimeError(DB_ERR), (True, "")]
    )

    await bs._drain_block_buffer_locked()

    _not_marked_not_punished(bs, b1)
    bs.db.connect_block_from_bytes.assert_called_once()
    assert not _is_fatal()


@pytest.mark.asyncio
async def test_drain_connect_write_failure_halts_without_verdict(monkeypatch):
    """FAULT: the connect WriteBatch fails twice (ENOSPC).  Pre-fix: re-buffer
    and retry forever (no halt).  Post-fix: retried once, then AbortNode."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x45" * 32, b"\x46" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(return_value=(True, ""))
    bs.db.connect_block_from_bytes = MagicMock(
        side_effect=RuntimeError("Database error: IO error: No space left on device")
    )

    await bs._drain_block_buffer_locked()

    _not_marked_not_punished(bs, b1)
    assert bs.db.connect_block_from_bytes.call_count == 2
    assert b1 in bs._ibd_block_buffer
    assert _is_fatal()


@pytest.mark.asyncio
async def test_drain_control_missing_coin_is_still_a_verdict(monkeypatch):
    """CONTROL: a genuinely missing coin (validator answers, no exception)
    is bad-txns-inputs-missingorspent: marked failed, sender punished,
    node NOT halted."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs = _drain_bs()
    b1, b2 = b"\x47" * 32, b"\x48" * 32
    _stage(bs, b1, b2)
    bs.validator.validate_block = MagicMock(
        return_value=(False, "Transaction 1 invalid: Input not found: " + "ab" * 32 + ":0")
    )

    await bs._drain_block_buffer_locked()

    assert b1 in bs._perm_rejected_blocks
    assert b1 in getattr(bs, "_failed_blocks", set())
    bs.peer_manager.misbehaving.assert_called_once()
    assert not _is_fatal()


@pytest.mark.asyncio
async def test_handle_block_catch_all_does_not_score_peer_for_system_error():
    """FAULT (F12): an unexpected system error inside handle_block used to
    cost the delivering peer -5."""
    bs = _drain_bs()

    async def _boom():
        raise MemoryError("injected")

    bs._drain_block_buffer = _boom
    bs._request_next_blocks = MagicMock()
    msg = MagicMock()
    # a minimal well-formed-length payload; drain is where the fault fires
    import hashlib
    header = b"\x01" + b"\x00" * 79
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    bs._validated_headers = [(block_hash, MagicMock())]
    bs.requested_blocks[block_hash] = 1.0
    msg.payload = header + b"\x00"
    peer = MagicMock()
    peer.host, peer.port = "127.0.0.3", 8333
    await bs.handle_block(msg, peer)
    for c in peer.adjust_score.call_args_list:
        assert c.args[0] >= 0, f"peer penalised for our own fault: {c}"


# ---------------------------------------------------------------------------
# F1 — multi-block reorg pre-flight swallowed exceptions => no script check
# ---------------------------------------------------------------------------

A0 = b"\xa0" * 32   # common ancestor (height 1, active chain)
A1 = b"\xa1" * 32   # active tip (height 2) — disconnected by the reorg
B1 = b"\xb1" * 32   # side branch height 2
B2 = b"\xb2" * 32   # side branch height 3 (heavier tip)


def _reorg_server(validate_block):
    from ouroboros.rpc import RPCServer

    srv = RPCServer.__new__(RPCServer)
    srv._side_branch_blocks = {
        B1: (A0, 2, b"\x00" * 81),
        B2: (B1, 3, b"\x00" * 82),
    }
    srv._side_branch_max_entries = 16
    srv._last_reorg_failure = None
    srv._resolve_parent_height = lambda db, h: 1 if h == A0 else None
    validator = MagicMock()
    validator.validate_block = MagicMock(side_effect=validate_block)
    srv.node = SimpleNamespace(
        network="regtest", validator=validator, mempool=None, pruner=None,
        wallet=None, wallet_manager=None, tip_notifier=None,
    )
    db = MagicMock()
    db.get_best_block.return_value = (A1, 2)
    db.get_block_by_height.return_value = None   # nothing to refill/retain
    db.validate_block_from_bytes = MagicMock(return_value=None)
    db.connect_blocks_atomic = MagicMock(return_value=[B1, B2])
    return srv, db, validator


@pytest.fixture
def _decodable_blocks(monkeypatch):
    """The side-branch bodies are placeholders; make Block.deserialize hand
    back an empty block so the BIP-34 pre-check and the validator call are
    reached exactly as for a real body."""
    from ouroboros import database

    monkeypatch.setattr(
        database.Block, "deserialize",
        staticmethod(lambda raw: SimpleNamespace(transactions=[])),
    )


@pytest.mark.asyncio
async def test_reorg_preflight_system_error_does_not_connect_unvalidated(_decodable_blocks):
    """FAULT: the pre-flight validator (the ONLY script check this batch gets)
    raises MemoryError on every attempt during a 2-block reorg.

    Pre-fix: ``except Exception: pass`` -> ``connect_blocks_atomic`` ran and
    the batch was connected WITHOUT script verification (fail-open).
    Post-fix: retried once, no connect, no verdict on any block, AbortNode."""
    from ouroboros.block_sync import classify_block_reject

    def _oom(*_a, **_k):
        raise MemoryError("injected: validate_block OOM")

    srv, db, validator = _reorg_server(_oom)
    result = await srv._reorg_to_side_branch_tip(db, B2)

    db.connect_blocks_atomic.assert_not_called()
    assert validator.validate_block.call_count == 2          # retry once
    assert srv._last_reorg_failure is None                   # no verdict
    assert result is not None and classify_block_reject(result) == "nonverdict"
    assert _is_fatal()


@pytest.mark.asyncio
async def test_reorg_preflight_db_read_error_does_not_connect(_decodable_blocks):
    """FAULT: a coins read error (Rust PyRuntimeError) in the pre-flight."""
    def _db(*_a, **_k):
        raise RuntimeError(DB_ERR)

    srv, db, _v = _reorg_server(_db)
    await srv._reorg_to_side_branch_tip(db, B2)
    db.connect_blocks_atomic.assert_not_called()
    assert srv._last_reorg_failure is None


@pytest.mark.asyncio
async def test_reorg_preflight_unexpected_bug_does_not_connect(_decodable_blocks):
    """FAULT: a non-system exception (a validator bug, TypeError).  Never a
    skip: the batch is refused, not connected unvalidated."""
    def _bug(*_a, **_k):
        raise TypeError("validator bug")

    srv, db, _v = _reorg_server(_bug)
    await srv._reorg_to_side_branch_tip(db, B2)
    db.connect_blocks_atomic.assert_not_called()
    assert srv._last_reorg_failure is None


@pytest.mark.asyncio
async def test_reorg_preflight_transient_error_retries_then_connects(_decodable_blocks):
    """FAULT (transient): first attempt raises, retry validates -> connect."""
    state = {"n": 0}

    def _flaky(*_a, **_k):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError(5, "Input/output error")
        return True, ""

    srv, db, _v = _reorg_server(_flaky)
    await srv._reorg_to_side_branch_tip(db, B2)
    db.connect_blocks_atomic.assert_called_once()
    assert not _is_fatal()


@pytest.mark.asyncio
async def test_reorg_preflight_control_invalid_first_block_is_verdict(_decodable_blocks):
    """CONTROL: an invalid FIRST block is still a verdict on that block and
    the batch is not connected; the node is not halted."""
    from ouroboros.block_sync import classify_block_reject

    srv, db, _v = _reorg_server(
        lambda *a, **k: (False, "Transaction 1 invalid: Invalid signature for input 0")
    )
    await srv._reorg_to_side_branch_tip(db, B2)
    db.connect_blocks_atomic.assert_not_called()
    assert srv._last_reorg_failure is not None
    failed_hash, err = srv._last_reorg_failure
    assert failed_hash == B1
    assert classify_block_reject(err) == "verdict"
    assert not _is_fatal()


# ---------------------------------------------------------------------------
# accept_block / submitblock — a storage error is never a BIP-22 reject
# ---------------------------------------------------------------------------


def _accept_node():
    return SimpleNamespace(network="regtest", validator=None, mempool=None)


def _decoded():
    """A structurally plausible decoded block so accept_block's Python
    CheckBlock pre-gates pass and the Rust validator is reached."""
    cb = SimpleNamespace(
        is_coinbase=True,
        inputs=[SimpleNamespace(script_sig=b"\x51\x00")],
    )
    return SimpleNamespace(transactions=[cb])


@pytest.mark.asyncio
async def test_accept_block_rust_db_error_is_not_a_reject():
    """FAULT: the Rust validator's storage read fails (PyRuntimeError) twice.
    Pre-fix accept_block re-raised it as ValueError(<refined reason>) — a
    BIP-22 reject token.  Post-fix: InternalValidationError + AbortNode."""
    from ouroboros.rpc import accept_block

    db = MagicMock()
    db.validate_block_from_bytes = MagicMock(
        side_effect=RuntimeError("validate: Database error: IO error")
    )
    with pytest.raises(Exception) as ei:
        await accept_block(db, _accept_node(), b"\x00" * 81, 1,
                           decoded_block=_decoded())
    assert not isinstance(ei.value, ValueError), (
        f"storage error surfaced as a consensus reject: {ei.value!r}"
    )
    assert db.validate_block_from_bytes.call_count == 2
    db.connect_block_from_bytes.assert_not_called()
    assert _is_fatal()


@pytest.mark.asyncio
async def test_accept_block_control_consensus_reject_is_valueerror():
    """CONTROL: a consensus failure from the Rust validator is a ValueError
    (BIP-22 token), not a halt."""
    from ouroboros.rpc import accept_block

    db = MagicMock()
    db.validate_block_from_bytes = MagicMock(
        side_effect=ValueError("validate: Coinbase amount exceeds subsidy + fees")
    )
    with pytest.raises(ValueError):
        await accept_block(db, _accept_node(), b"\x00" * 81, 1,
                           decoded_block=_decoded())
    assert not _is_fatal()


# ---------------------------------------------------------------------------
# Tier 3 — mempool: an MTP read error is not MTP 0
# ---------------------------------------------------------------------------


def test_mempool_mtp_read_error_is_not_mtp_zero():
    """FAULT: get_median_time_past raises.  Pre-fix MTP became 0 (every
    time-locked tx "non-final" -> a reject the relay path scored at 10).
    Post-fix: refused without a verdict, validate_transaction not reached."""
    from ouroboros.mempool import Mempool

    class _DB:
        def get_utxo(self, txid, vout):
            return {"value": 10_000, "script_pubkey": b"\x51", "height": 1,
                    "is_coinbase": False}

        def get_median_time_past(self, h):
            raise RuntimeError("Database error: get_median_time_past(5): IO error")

    validator = MagicMock()
    validator.db = _DB()
    validator.network = "regtest"
    validator.validate_transaction = MagicMock(return_value=(True, ""))
    pool = Mempool(validator=validator, require_standard=False, full_rbf=True)
    tx = Transaction(
        txid=b"\x07" * 32, version=2, locktime=0,
        inputs=[TxIn(prev_txid=b"\x09" * 32, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=5_000, script_pubkey=b"\x51")],
    )
    ok, reason = pool.add_transaction(tx, 10)
    assert not ok
    validator.validate_transaction.assert_not_called()
    f = _fatal()
    assert f is not None and f.is_internal_error_text(reason)


# ---------------------------------------------------------------------------
# F9 (Rust) — a REAL RocksDB read error: get_utxo_batch reported "absent"
# ---------------------------------------------------------------------------


def _corrupt_chainstate_with_one_coin(sync, d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    txid = bytes(range(32))
    db = sync.PyBlockchainDB(d)
    for v in range(200):
        db.add_utxo_raw(txid, v, 5000 + v, b"\x51" * 30, 10, False)
    del db
    gc.collect()
    db = sync.PyBlockchainDB(d)   # WAL replay flushes the coins to an SST
    assert db.get_utxo_batch([(txid, 3)])[0] is not None
    del db
    gc.collect()
    ssts = glob.glob(os.path.join(d, "**", "*.sst"), recursive=True)
    assert ssts, "expected the coins to be in an SST"
    for p in ssts:  # flip bytes inside the first data block -> checksum error
        with open(p, "r+b") as f:
            f.seek(40)
            b = f.read(64)
            f.seek(40)
            f.write(bytes(x ^ 0xFF for x in b))
    return sync.PyBlockchainDB(d), txid


def test_rust_get_utxo_batch_read_error_is_raised_not_absent(tmp_path):
    """FAULT (real, no mock): a corrupted SST data block makes RocksDB return
    ``Corruption: block checksum mismatch`` for the coin.  Pre-fix
    ``get_utxo_batch`` mapped ``Err(_) => None`` (lib.rs:3639): the validator
    saw "Input not found" -> bad-txns-inputs-missingorspent -> mark + ban.
    Post-fix it raises RuntimeError("Database error: ...").  CONTROL: the
    single-key ``get_utxo`` already raised for the same fault."""
    from tests._real_sync import load_real_sync

    sync = load_real_sync()
    if sync is None:
        pytest.skip("compiled sync extension not available")
    db, txid = _corrupt_chainstate_with_one_coin(sync, str(tmp_path / "db"))
    with pytest.raises(RuntimeError, match="(?i)database error"):
        db.get_utxo(txid, 3)            # control: already correct
    with pytest.raises(RuntimeError, match="(?i)database error"):
        db.get_utxo_batch([(txid, 3)])  # the fixed site
    # CONTROL: a coin that is genuinely absent is still None, not an error.
    fresh = sync.PyBlockchainDB(str(tmp_path / "fresh"))
    assert fresh.get_utxo_batch([(b"\x77" * 32, 0)]) == [None]
