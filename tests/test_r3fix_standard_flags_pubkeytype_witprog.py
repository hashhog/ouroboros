"""Mempool script flags include Core's DISCOURAGE_UPGRADABLE_PUBKEYTYPE and
DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.

R3 generating differential fuzzer, night 1 (seed 739943, Core v31.1), triage
group G3 for ouroboros: ``get_standard_script_flags`` (the mempool's
``standard & ~consensus`` policy delta) never added
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE or
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.

* Row R52: a tapscript ``<0x30> OP_13 OP_CHECKSIG`` (non-empty signature, a
  1-byte pubkey) passes under consensus, so ouroboros ACCEPTED it to the
  mempool; Core refuses it as policy (SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
* Row R29: ``<0x30> OP_1NEGATE OP_CHECKSIGVERIFY`` was refused only because
  the final stack is empty (CLEANSTACK-style); Core stops earlier, on the
  pubkey type.
* Latent: a P2SH-wrapped v2+ witness program passes under consensus; Core
  refuses it in the mempool (SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM).

Core v31.1:

* ``policy/policy.h`` STANDARD_SCRIPT_VERIFY_FLAGS includes
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM and DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
* ``script/interpreter.cpp`` EvalChecksigTapscript: a pubkey that is neither
  empty nor 32 bytes fails with DISCOURAGE_UPGRADABLE_PUBKEYTYPE when the
  flag is set, whatever the signature; without the flag it succeeds.
* ``script/interpreter.cpp`` VerifyWitnessProgram: an unknown witness
  version (not bare P2A) fails with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
  when the flag is set, and succeeds otherwise.

The flags come from one Python function, but both interpreters consume them,
so every mempool case runs on the Python interpreter and, when the compiled
``sync`` extension is built, on the native (Rust) one, which is the node's
default.  The mempool cases run the REAL ``Mempool`` (``require_standard``)
over the REAL ``TransactionValidator``; only the UTXO database is a stub.
The expected decisions come from Core's rules above, not from ouroboros.
"""
from __future__ import annotations

import copy
import hashlib
import sys

import pytest
from coincurve import PrivateKey, PublicKey

import tests.conftest  # noqa: F401  (installs the sync stub first)
import ouroboros.script as S
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import Mempool
from ouroboros.script import (
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE as PUBKEYTYPE,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM as WITPROG,
    ScriptInterpreter,
    get_flags_for_height,
    get_standard_script_flags,
)
from ouroboros.validation import SIG_CACHE, TransactionValidator
from tests._real_sync import load_real_sync, real_sync_installed

# The night-1 minimised case for R52, as the fuzzer submitted it.
R52_HEX = (
    "0200000000010106a59a32fc0e95ae89b2a58e72611dcab4abb8d4e0f82ee5cd493fcd"
    "92a6d6890000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5c"
    "ed7a1a000945432e83e1551e6f721ee9c00b8cc33260020401305dac21c179be667ef9"
    "dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
)
PREV_TXID = bytes.fromhex(
    "06a59a32fc0e95ae89b2a58e72611dcab4abb8d4e0f82ee5cd493fcd92a6d689")
P2WSH_OUT = bytes.fromhex(
    "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260")
FUND_VALUE = 100_000
OUT_VALUE = 0x017ED0  # 98,000 sat, as in R52
HEIGHT = 1_000  # regtest: every buried deployment is active
NETWORK = "regtest"
# The BIP-341 internal key in R52's control block: the secp256k1 generator's x.
INTERNAL_X = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

OP_0, OP_1, OP_1NEGATE, OP_2, OP_13 = 0x00, 0x51, 0x4F, 0x52, 0x5D
OP_NOT, OP_CHECKSIG, OP_CHECKSIGVERIFY = 0x91, 0xAC, 0xAD


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _tagged(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _p2tr_single_leaf(leaf: bytes) -> tuple[bytes, bytes]:
    """(scriptPubKey, control block) for a one-leaf tree, leaf version 0xc0,
    internal key INTERNAL_X -- computed from BIP-341 here, independent of
    ouroboros' own taproot code."""
    assert len(leaf) < 0xFD
    leaf_hash = _tagged("TapLeaf", b"\xc0" + bytes([len(leaf)]) + leaf)
    tweak = _tagged("TapTweak", INTERNAL_X + leaf_hash)
    q = PublicKey.combine_keys([
        PublicKey(b"\x02" + INTERNAL_X), PrivateKey(tweak).public_key,
    ]).format(compressed=True)
    parity = q[0] & 1
    return b"\x51\x20" + q[1:], bytes([0xC0 | parity]) + INTERNAL_X


class _StubDB:
    def __init__(self, utxos):
        self._utxos = utxos

    def get_utxo(self, txid, vout):
        return self._utxos.get((txid, vout))

    def get_utxo_batch(self, outpoints):
        return [self._utxos.get(op) for op in outpoints]

    def get_median_time_past(self, height):
        return 1_700_000_000


def _tapscript_spend(leaf: bytes) -> tuple[Transaction, bytes]:
    spk, control = _p2tr_single_leaf(leaf)
    tx = Transaction(
        txid=b"", version=2, locktime=0,
        inputs=[TxIn(prev_txid=PREV_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFE, witness=[leaf, control])],
        outputs=[TxOut(value=OUT_VALUE, script_pubkey=P2WSH_OUT)],
        has_witness=True,
    )
    tx.txid = _dsha(tx.serialize())
    return tx, spk


def _p2sh_witprog_spend(redeem: bytes) -> tuple[Transaction, bytes]:
    spk = b"\xa9\x14" + _hash160(redeem) + b"\x87"
    tx = Transaction(
        txid=b"", version=2, locktime=0,
        inputs=[TxIn(prev_txid=PREV_TXID, prev_vout=0,
                     script_sig=bytes([len(redeem)]) + redeem,
                     sequence=0xFFFFFFFE, witness=[])],
        outputs=[TxOut(value=OUT_VALUE, script_pubkey=P2WSH_OUT)],
    )
    tx.txid = _dsha(tx.serialize())
    return tx, spk


# Tapscript leaves.  name -> leaf
R52_LEAF = bytes([0x01, 0x30, OP_13, OP_CHECKSIG])
R29_LEAF = bytes([0x01, 0x30, OP_1NEGATE, OP_CHECKSIGVERIFY])
# Empty signature, unknown pubkey type: Core checks the pubkey type before it
# looks at `success`, so this too is PUBKEYTYPE under policy; under
# consensus CHECKSIG pushes false and OP_NOT makes the stack [1].
EMPTYSIG_LEAF = bytes([OP_0, OP_13, OP_CHECKSIG, OP_NOT])
OPTRUE_LEAF = bytes([OP_1])
# P2SH-wrapped v2 witness program (20 non-zero bytes, so the redeemScript
# itself evaluates true and the witness-version rule decides).
P2SH_V2_REDEEM = bytes([OP_2, 20]) + b"\x01" * 20


# --------------------------------------------------------------------------
# Interpreter selection
# --------------------------------------------------------------------------

@pytest.fixture(params=["python", "native"])
def interp(request, monkeypatch):
    """Run the test on the Python interpreter, then on the native one.

    The process-wide SIG_CACHE is cleared first: it caches successful
    verifications, so without this the native run of a control would be
    answered from the Python run's cache entry and never reach Rust."""
    SIG_CACHE.clear()
    request.addfinalizer(SIG_CACHE.clear)
    if request.param == "python":
        monkeypatch.setattr(S, "NATIVE_SCRIPT_ENABLED", False)
        yield "python"
        return
    real = load_real_sync()
    if real is None or not hasattr(real, "script_verify"):
        pytest.skip("compiled sync extension with the native script API not built")
    with real_sync_installed(real):
        monkeypatch.setattr(S, "NATIVE_SCRIPT_ENABLED", True)
        monkeypatch.setattr(S, "_native_sync", real)
        yield "native"


def _pool(spk: bytes) -> Mempool:
    db = _StubDB({
        (PREV_TXID, 0): {"value": FUND_VALUE, "script_pubkey": spk,
                         "height": HEIGHT - 100, "is_coinbase": False},
    })
    v = TransactionValidator(db=db, network=NETWORK)
    return Mempool(validator=v, max_size=300_000_000, require_standard=True,
                   full_rbf=True)


def _admit(tx: Transaction, spk: bytes, monkeypatch) -> tuple[bool, str, object, list]:
    """Submit *tx* to a fresh pool.  Returns (ok, reason, the interpreter's
    recorded SCRIPT_ERR_* name, the flags of every script check the pool
    ran).  The flag spy wraps the real dispatcher; it changes nothing."""
    seen: list[int] = []
    real_verify = ScriptInterpreter.verify

    def spy(self, *args, **kwargs):
        seen.append(int(kwargs.get("flags", 0)))
        return real_verify(self, *args, **kwargs)

    monkeypatch.setattr(ScriptInterpreter, "verify", spy)
    pool = _pool(spk)
    ok, err = pool.add_transaction(copy.deepcopy(tx), HEIGHT)
    monkeypatch.setattr(ScriptInterpreter, "verify", real_verify)
    return (ok, err,
            getattr(pool.validator.script_interpreter, "last_error", None), seen)


def _verify(tx: Transaction, spk: bytes, flags: int) -> bool:
    return ScriptInterpreter().verify(
        tx.inputs[0].script_sig, spk, tx, 0, flags=flags, amount=FUND_VALUE,
        input_amounts=[FUND_VALUE], input_script_pubkeys=[spk])


def _consensus_flags() -> int:
    return get_flags_for_height(HEIGHT, None, NETWORK)


def _mempool_flags() -> int:
    # What Mempool passes to the validator: consensus | (standard & ~consensus).
    c = _consensus_flags()
    return c | (get_standard_script_flags(HEIGHT, None, NETWORK) & ~c)


# --------------------------------------------------------------------------
# Instrument checks
# --------------------------------------------------------------------------

def test_instrument_r52_fixture_is_the_fuzzer_case() -> None:
    """The R52 spend built here is byte-for-byte the night-1 minimised case,
    and the computed output key's parity matches its control byte (0xc1),
    so the prevout is the one Core saw."""
    tx, _spk = _tapscript_spend(R52_LEAF)
    assert tx.serialize_with_witness().hex() == R52_HEX
    assert _p2tr_single_leaf(R52_LEAF)[1][0] == 0xC1


def test_instrument_wrong_output_key_is_refused(interp) -> None:
    """Negative control: the spend reaches the taproot script path (a wrong
    output key fails the commitment), so acceptances below are decided by
    the leaf script, not by a check that never ran."""
    tx, spk = _tapscript_spend(OPTRUE_LEAF)
    bad_spk = spk[:-1] + bytes([spk[-1] ^ 0x01])
    assert _verify(tx, bad_spk, _consensus_flags()) is False


def test_instrument_each_param_runs_its_interpreter(interp, monkeypatch) -> None:
    """Negative control: with the other interpreter booby-trapped, the spend
    still verifies, so the [python] and [native] runs measure different
    code."""
    def trap(*_a, **_k):
        raise AssertionError("the wrong interpreter ran")

    other = "verify_native" if interp == "python" else "verify_python"
    monkeypatch.setattr(ScriptInterpreter, other, trap)
    tx, spk = _tapscript_spend(OPTRUE_LEAF)
    assert _verify(tx, spk, _consensus_flags()) is True


# --------------------------------------------------------------------------
# The flag sets
# --------------------------------------------------------------------------

@pytest.mark.parametrize("network,height", [
    ("mainnet", 900_000), ("testnet4", 100_000), ("regtest", 1_000),
])
@pytest.mark.parametrize("bit,name", [
    (PUBKEYTYPE, "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"),
    (WITPROG, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"),
])
def test_standard_flags_include_policy_bit(network, height, bit, name) -> None:
    """Core STANDARD_SCRIPT_VERIFY_FLAGS has the bit; it is policy only, so
    it is in the mempool's standard-minus-consensus delta and not in the
    block flags."""
    standard = get_standard_script_flags(height, None, network)
    consensus = get_flags_for_height(height, None, network)
    assert standard & bit, name
    assert (standard & ~consensus) & bit, name
    assert not (consensus & bit), name


@pytest.mark.parametrize("bit,name", [
    (PUBKEYTYPE, "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"),
    (WITPROG, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"),
])
def test_standard_flags_fallback_include_policy_bit(monkeypatch, bit, name) -> None:
    """The height-constant fallback (no ouroboros.consensus) adds the bit too."""
    monkeypatch.setitem(sys.modules, "ouroboros.consensus", None)
    assert get_standard_script_flags(900_000, None, "mainnet") & bit, name


def test_standard_flags_cover_core_standard_set() -> None:
    """At a post-taproot mainnet height every bit of Core v31.1's
    STANDARD_SCRIPT_VERIFY_FLAGS (policy.h) is set."""
    core_standard = (
        # MANDATORY_SCRIPT_VERIFY_FLAGS
        S.SCRIPT_VERIFY_P2SH | S.SCRIPT_VERIFY_DERSIG | S.SCRIPT_VERIFY_NULLDUMMY
        | S.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | S.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
        | S.SCRIPT_VERIFY_WITNESS | S.SCRIPT_VERIFY_TAPROOT
        # the standard-only additions, in policy.h order
        | S.SCRIPT_VERIFY_STRICTENC | S.SCRIPT_VERIFY_MINIMALDATA
        | S.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | S.SCRIPT_VERIFY_CLEANSTACK
        | S.SCRIPT_VERIFY_MINIMALIF | S.SCRIPT_VERIFY_NULLFAIL | S.SCRIPT_VERIFY_LOW_S
        | WITPROG | S.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
        | S.SCRIPT_VERIFY_CONST_SCRIPTCODE
        | S.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
        | S.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS | PUBKEYTYPE
    )
    standard = get_standard_script_flags(900_000, None, "mainnet")
    assert core_standard & ~standard == 0, hex(core_standard & ~standard)


# --------------------------------------------------------------------------
# Mempool admission (both interpreters)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("leaf", [
    pytest.param(R52_LEAF, id="R52_sig_onebyte_pubkey_checksig"),
    pytest.param(R29_LEAF, id="R29_sig_1negate_checksigverify"),
    pytest.param(EMPTYSIG_LEAF, id="emptysig_op13_pubkey_checksig_not"),
])
def test_unknown_tapscript_pubkey_type_refused_as_pubkeytype(
        interp, leaf, monkeypatch) -> None:
    """Core refuses each spend with SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
    the pubkey-type check fails the script at the CHECKSIG, before the final
    stack is looked at.  The pool's script check must carry the flag; the
    native interpreter records the exact error name.  (The Python
    interpreter records no name for this error, and mapping the name into
    the reject reason is triage group G1, a separate item, so the reason
    string is not asserted here.)"""
    tx, spk = _tapscript_spend(leaf)
    ok, err, script_error, flags_seen = _admit(tx, spk, monkeypatch)
    assert flags_seen, "the pool never ran the script check"
    assert all(f & PUBKEYTYPE for f in flags_seen), [hex(f) for f in flags_seen]
    assert ok is False, "accepted; Core refuses DISCOURAGE_UPGRADABLE_PUBKEYTYPE"
    if interp == "native":
        assert script_error == "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE", (
            err, script_error)


def test_p2sh_wrapped_v2_witness_program_refused(interp, monkeypatch) -> None:
    """Latent half of G3: Core refuses a P2SH-wrapped v2 witness program in
    the mempool with SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM."""
    tx, spk = _p2sh_witprog_spend(P2SH_V2_REDEEM)
    ok, err, script_error, flags_seen = _admit(tx, spk, monkeypatch)
    assert flags_seen, "the pool never ran the script check"
    assert all(f & WITPROG for f in flags_seen), [hex(f) for f in flags_seen]
    assert ok is False, "accepted; Core refuses DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
    if interp == "native":
        assert script_error == (
            "SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"), (err, script_error)


def test_control_optrue_tapscript_accepted(interp, monkeypatch) -> None:
    """Control: the same harness admits a standard tapscript spend, so the
    refusals above are the policy flag and not a harness defect."""
    tx, spk = _tapscript_spend(OPTRUE_LEAF)
    ok, err, _, flags_seen = _admit(tx, spk, monkeypatch)
    assert flags_seen, "the pool never ran the script check"
    assert (ok, err) == (True, ""), err


def test_control_p2sh_v0_witness_program_accepted(interp, monkeypatch) -> None:
    """Control: a P2SH-P2WSH spend (v0, known version) of an OP_TRUE witness
    script is still admitted, so the v2 refusal is the version rule."""
    witness_script = bytes([OP_1])
    redeem = b"\x00\x20" + hashlib.sha256(witness_script).digest()
    tx, spk = _p2sh_witprog_spend(redeem)
    tx.inputs[0].witness = [witness_script]
    tx.has_witness = True
    tx.txid = _dsha(tx.serialize())
    ok, err, _, flags_seen = _admit(tx, spk, monkeypatch)
    assert flags_seen, "the pool never ran the script check"
    assert (ok, err) == (True, ""), err


def test_control_bare_p2a_spend_accepted(interp, monkeypatch) -> None:
    """Control: a bare pay-to-anchor output (``OP_1 <0x4e73>``, a v1 2-byte
    witness program) is spendable under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    Core's VerifyWitnessProgram returns true for it before the discourage
    check (``!is_p2sh && IsPayToAnchor``).  With the flag now in the mempool
    set, an empty-witness P2A spend must still be admitted."""
    spk = b"\x51\x02\x4e\x73"
    tx = Transaction(
        txid=b"", version=2, locktime=0,
        inputs=[TxIn(prev_txid=PREV_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFE, witness=[])],
        outputs=[TxOut(value=OUT_VALUE, script_pubkey=P2WSH_OUT)],
    )
    tx.txid = _dsha(tx.serialize())
    ok, err, _, flags_seen = _admit(tx, spk, monkeypatch)
    assert flags_seen, "the pool never ran the script check"
    assert (ok, err) == (True, ""), err
    # And directly, with the discourage bit forced on whatever the flag set.
    assert _verify(tx, spk, _mempool_flags() | WITPROG) is True


# --------------------------------------------------------------------------
# Consensus is unchanged (both interpreters)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("leaf", [
    pytest.param(R52_LEAF, id="R52"),
    pytest.param(EMPTYSIG_LEAF, id="emptysig_not"),
])
def test_unknown_pubkey_type_spend_valid_under_block_flags(interp, leaf) -> None:
    """Block validity must not change: under the block flags an unknown
    tapscript pubkey type is success (Core treats it as an upgrade hook)."""
    tx, spk = _tapscript_spend(leaf)
    assert _verify(tx, spk, _consensus_flags()) is True
    assert _verify(tx, spk, _mempool_flags()) is False


def test_p2sh_v2_witness_program_valid_under_block_flags(interp) -> None:
    """Block validity must not change: an unknown witness version succeeds
    under the block flags and fails only under the mempool flags."""
    tx, spk = _p2sh_witprog_spend(P2SH_V2_REDEEM)
    assert _verify(tx, spk, _consensus_flags()) is True
    assert _verify(tx, spk, _mempool_flags()) is False


def test_r29_fails_under_block_flags_too(interp) -> None:
    """R29 leaves an empty stack, so it is invalid under the block flags as
    well; the fix changes only which rule refuses it in the mempool."""
    tx, spk = _tapscript_spend(R29_LEAF)
    assert _verify(tx, spk, _consensus_flags()) is False
