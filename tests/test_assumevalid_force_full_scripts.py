"""
-assumevalid=0 / --noassumevalid: force full script verification on the
sync/drain path (Core parity with the other 9 hashhog nodes' AV=0 flag).

Bug closed (pre-flag):
  ouroboros script-SKIPPED every block at or below the last hardcoded
  checkpoint (mainnet 850000) on the live P2P drain/sync path
  (block_sync.py: can_skip_scripts_for_block -> True), and there was NO CLI
  override.  A block carrying a tx with an INVALID script/signature below the
  checkpoint was silently ACCEPTED — zero replay-coverage of the entire
  genesis..850000 range.

Fix (post-flag):
  BlockSync gains ``force_full_scripts`` (wired from the ``--assumevalid 0`` /
  ``--noassumevalid`` CLI flag via node.py).  When set, the drain path never
  routes to the Rust fast path (whose interpreter is decorative) and instead
  calls ``validator.validate_block(..., force_check_scripts=True)``, which sets
  ``skip_scripts=False`` and runs the REAL per-input script interpreter.

EFFECTIVE criterion (this test):
  A block at mainnet height 1000 (well below the 850000 checkpoint, so the
  assume-valid heuristic would normally skip scripts) contains a non-coinbase
  tx that spends a UTXO whose scriptPubKey is ``OP_0`` (evaluates FALSE) with
  an empty scriptSig — i.e. an unspendable/invalid-script spend.

    * force_check_scripts=False  (assume-valid, pre-flag behaviour)
        -> can_skip_scripts_for_block(mainnet, 1000) == True
        -> script interpreter is NOT invoked
        -> block ACCEPTED            (the silent-accept bug)

    * force_check_scripts=True   (post-flag, --assumevalid 0)
        -> skip_scripts forced False
        -> script interpreter IS invoked per-input
        -> OP_0 spk evaluates false
        -> block REJECTED with "Invalid signature for input 0"

This proves the flag is NOT a dead flag: the interpreter demonstrably runs
and rejects an invalid script at a height it would otherwise skip.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

# We REQUIRE the real, compiled module: the test relies on the real
# can_skip_scripts_for_block(mainnet, 1000) returning True (below the 850000
# checkpoint).  The comment this replaced claimed "conftest only installs a
# stub when sync is genuinely absent" — it does not; it installs the stub
# whenever nothing has already claimed the name, so `pytest.importorskip`
# found the mock, never skipped, and this test exercised conftest's stubbed
# checkpoint table instead of the Rust one.
sync = real_sync_or_skip()

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.validation import BlockValidator  # noqa: E402


BELOW_CHECKPOINT_HEIGHT = 1000  # << mainnet last checkpoint (850000)

# Sanity: the assume-valid heuristic really does skip scripts at this height.
assert sync.can_skip_scripts_for_block("mainnet", BELOW_CHECKPOINT_HEIGHT, b"\x00" * 32) is True
# ... and does NOT skip above the checkpoint (control).
assert sync.can_skip_scripts_for_block("mainnet", 900000, b"\x00" * 32) is False


@pytest.fixture(autouse=True)
def _use_real_sync():
    """Make the code under test reach the real extension too.

    ``ouroboros.validation`` binds ``import sync as _sync_module`` at import
    time and ``ouroboros.script`` re-imports ``sync`` on every signature check,
    so without this the validator would consult conftest's stub even though
    this module holds the real one.  Scoped and restored, so the rest of the
    suite keeps the stub.
    """
    with real_sync_installed(sync):
        yield



def _make_prev_block() -> MagicMock:
    prev = MagicMock()
    prev.hash = bytes(32)
    prev.timestamp = 1_600_000_000
    prev.bits = 0x1D00FFFF
    prev.height = BELOW_CHECKPOINT_HEIGHT - 1
    prev.version = 4
    return prev


def _make_coinbase() -> Transaction:
    return Transaction(
        txid=b"\xcc" * 32,
        version=1,
        locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF, script_sig=b"\x00" * 4, sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=50_00000000, script_pubkey=b"\x51")],
    )


def _make_invalid_script_spend() -> Transaction:
    """Non-coinbase tx spending the OP_0 (false) UTXO with an empty scriptSig."""
    return Transaction(
        txid=b"\xbb" * 32,
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=b"\xAA" * 32, prev_vout=0, script_sig=b"", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=900_000, script_pubkey=b"\x51")],
    )


def _funding_utxo() -> dict:
    # scriptPubKey = OP_0 -> pushes empty/false -> script evaluates FALSE.
    return {
        "txid": b"\xAA" * 32,
        "vout": 0,
        "value": 1_000_000,
        "script_pubkey": b"\x00",
        "height": 500,
        "is_coinbase": False,
    }


def _build_block() -> Block:
    return Block(
        version=4,
        prev_blockhash=bytes(32),
        merkle_root=bytes(32),
        timestamp=1_600_001_000,
        bits=0x1D00FFFF,
        nonce=0,
        transactions=[_make_coinbase(), _make_invalid_script_spend()],
        hash=b"\x22" * 32,
        height=BELOW_CHECKPOINT_HEIGHT,
    )


def _make_validator():
    db = MagicMock()
    # BIP30 output-existence probe must miss (block txids not in UTXO set).
    db.get_utxo.return_value = None
    # Input resolution goes through the batch path.
    db.get_utxo_batch.return_value = [_funding_utxo()]
    return BlockValidator(db, network="mainnet"), db


def _run(force_check_scripts: bool):
    v, db = _make_validator()
    block = _build_block()
    with \
            patch.object(v, "_validate_header", return_value=True), \
            patch.object(v, "_verify_merkle_root", return_value=True), \
            patch.object(v, "_validate_block_limits", return_value=(True, "")), \
            patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
            patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
            patch.object(v, "_validate_coinbase", return_value=True), \
            patch.object(v, "_verify_coinbase_amount", return_value=True), \
            patch.object(v.tx_validator, "_is_final_tx", return_value=True):
        return v.validate_block(
            block,
            known_height=BELOW_CHECKPOINT_HEIGHT,
            force_check_scripts=force_check_scripts,
        )


def test_pre_flag_assume_valid_accepts_invalid_script_below_checkpoint():
    """Without the flag, the invalid-script spend is silently ACCEPTED (the bug)."""
    ok, err = _run(force_check_scripts=False)
    assert ok, (
        "pre-flag (assume-valid) MUST accept below-checkpoint block without "
        f"running scripts; got reject: {err!r}"
    )
    assert err == ""


def test_post_flag_full_scripts_rejects_invalid_script_below_checkpoint():
    """With the flag, the interpreter runs and REJECTS the invalid script."""
    ok, err = _run(force_check_scripts=True)
    assert not ok, "post-flag (--assumevalid 0) MUST reject the invalid-script block"
    assert "Invalid signature for input 0" in err, (
        f"expected a script/sig rejection from the interpreter, got: {err!r}"
    )


def test_interpreter_actually_invoked_only_with_flag():
    """Direct proof the script interpreter is invoked ONLY when the flag is set."""
    # Pre-flag: _verify_input_signature must NOT be called (scripts skipped).
    v, db = _make_validator()
    block = _build_block()
    common = dict(
        known_height=BELOW_CHECKPOINT_HEIGHT,
    )
    with \
            patch.object(v, "_validate_header", return_value=True), \
            patch.object(v, "_verify_merkle_root", return_value=True), \
            patch.object(v, "_validate_block_limits", return_value=(True, "")), \
            patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
            patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
            patch.object(v, "_validate_coinbase", return_value=True), \
            patch.object(v, "_verify_coinbase_amount", return_value=True), \
            patch.object(v.tx_validator, "_is_final_tx", return_value=True), \
            patch.object(
                v.tx_validator, "_verify_input_signature", wraps=v.tx_validator._verify_input_signature
            ) as spy:
        v.validate_block(block, force_check_scripts=False, **common)
        assert spy.call_count == 0, "assume-valid must NOT invoke the script interpreter"

        v.validate_block(block, force_check_scripts=True, **common)
        assert spy.call_count >= 1, "flag must invoke the script interpreter per-input"


def test_blocksync_threads_force_full_scripts_flag():
    """Wiring: BlockSync stores force_full_scripts and the drain closure would
    pass it into validate_block as force_check_scripts."""
    import inspect
    from ouroboros.block_sync import BlockSync

    bs = BlockSync.__new__(BlockSync)  # avoid full __init__ deps
    bs.force_full_scripts = True
    assert bs.force_full_scripts is True

    # The drain path's Python runner forwards the attribute verbatim.
    src = inspect.getsource(BlockSync._drain_block_buffer_locked)
    assert "force_check_scripts=self.force_full_scripts" in src, (
        "drain path must forward force_full_scripts into validate_block"
    )
    # And it must suppress the Rust fast-path skip when the flag is set.
    assert "and not self.force_full_scripts" in src
