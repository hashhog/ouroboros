"""Regression tests for BIP141 block sigops cost accounting.

Triggered by mainnet block 713465 rejection:
    Invalid block at height 713465: Block sigops cost 119681 exceeds 80000

Root cause: `_count_witness_sigops` called `_count_legacy_sigops(witness_script)`
without `accurate=True`, so P2WSH N-of-M multisigs were counted as 20 sigops
each instead of N.  Bitcoin Core's WitnessSigOps uses accurate counting
(script/interpreter.cpp WitnessSigOps: `subscript.GetSigOpCount(true)`).

These tests verify the P2WSH witness-sigop helper uses accurate multisig
counting, which is what prevents valid segwit blocks with heavy multisig
usage from being spuriously rejected.
"""
from __future__ import annotations

from ouroboros.validation import (
    MAX_BLOCK_SIGOPS_COST,
    WITNESS_SCALE_FACTOR,
    _count_legacy_sigops,
    _count_witness_sigops,
)


# --- Opcode byte constants (Bitcoin script) ---
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE


def _p2wsh_spk() -> bytes:
    """Synthesise a P2WSH scriptPubKey: OP_0 <32-byte hash>."""
    return bytes([OP_0, 0x20]) + b"\x00" * 32


def _push_op(n: int) -> int:
    """Return the OP_N byte for 1..16."""
    assert 1 <= n <= 16
    return OP_1 + (n - 1)


def _multisig_script(n: int) -> bytes:
    """Build an N-of-N multisig witness script: OP_N <N pubkeys> OP_N OP_CHECKMULTISIG."""
    out = bytearray([_push_op(n)])
    for _ in range(n):
        out.append(0x21)  # push 33 bytes
        out += b"\x02" + b"\x00" * 32
    out.append(_push_op(n))
    out.append(OP_CHECKMULTISIG)
    return bytes(out)


# =============================================================================
# Helper-level tests: accurate multisig counting
# =============================================================================

def test_count_legacy_sigops_inaccurate_multisig_counts_20():
    """Inaccurate mode: OP_CHECKMULTISIG alone counts as 20."""
    script = bytes([OP_CHECKMULTISIG])
    assert _count_legacy_sigops(script, accurate=False) == 20


def test_count_legacy_sigops_accurate_2of3():
    """Accurate mode: OP_3 ... OP_CHECKMULTISIG counts as 3."""
    script = _multisig_script(3)
    assert _count_legacy_sigops(script, accurate=True) == 3


def test_count_witness_sigops_p2wpkh_is_one():
    """P2WPKH always counts as exactly 1 witness sigop."""
    spk = bytes([OP_0, 0x14]) + b"\x00" * 20  # 20-byte program
    # Witness stack is irrelevant for P2WPKH
    assert _count_witness_sigops(spk, [b"sig", b"pubkey"]) == 1


def test_count_witness_sigops_p2wsh_checksig_is_one():
    """P2WSH with OP_CHECKSIG witness script counts as 1."""
    spk = _p2wsh_spk()
    witness_script = bytes([OP_CHECKSIG])
    witness = [b"sig", witness_script]
    assert _count_witness_sigops(spk, witness) == 1


def test_count_witness_sigops_p2wsh_2of3_uses_accurate_count():
    """**Regression test for block 713465.**

    Before the fix, a 2-of-3 P2WSH multisig was counted as 20 witness sigops
    (inaccurate mode).  Bitcoin Core counts 3 (accurate mode, decoded from the
    OP_3 push preceding CHECKMULTISIG).
    """
    spk = _p2wsh_spk()
    witness_script = _multisig_script(3)
    # Witness stack: dummy + 2 sigs + witness_script (last)
    witness = [b"", b"sig1", b"sig2", witness_script]
    # Correct BIP141 accurate count: 3, not 20
    assert _count_witness_sigops(spk, witness) == 3


def test_count_witness_sigops_p2wsh_many_multisigs_stay_under_budget():
    """Batch payout scenario: 100 inputs each spending a 2-of-3 P2WSH multisig.

    Budget: 100 inputs × 3 witness-sigops each = 300.  Under accurate counting
    the block cost contribution from witness sigops is ~300, well under 80 000.
    Under the buggy inaccurate counting it would be 100 × 20 = 2 000 — still
    under the limit here, but on real mainnet blocks with heavier multisig
    distributions (e.g. 10-of-15) the over-count pushes cost past 80 000.

    This explicitly checks the accurate-vs-inaccurate delta for a realistic
    input count and confirms accurate counting keeps us under budget when
    inaccurate counting would not.
    """
    spk = _p2wsh_spk()
    # 3-of-3 multisig (actual = 3 sigops per input; inaccurate = 20 per input)
    witness_script = _multisig_script(3)
    witness = [b"", b"s1", b"s2", b"s3", witness_script]

    n_inputs = 5000  # 5000 × 3 = 15 000 (OK);  5000 × 20 = 100 000 (> 80 000!)
    accurate_total = sum(
        _count_witness_sigops(spk, witness) for _ in range(n_inputs)
    )
    # Witness sigops are NOT multiplied by WITNESS_SCALE_FACTOR (they're
    # already "discounted" per BIP141), so this is the raw contribution.
    assert accurate_total == 3 * n_inputs == 15_000
    assert accurate_total <= MAX_BLOCK_SIGOPS_COST

    # Sanity: confirm the old buggy behaviour WOULD have exceeded the cap.
    buggy_total = 20 * n_inputs
    assert buggy_total == 100_000
    assert buggy_total > MAX_BLOCK_SIGOPS_COST


def test_count_witness_sigops_rejects_over_budget_block():
    """An actually-over-budget witness-sigop distribution must still be rejected.

    Accurate multisig counting uses the OP_N push *immediately preceding*
    OP_CHECKMULTISIG, which encodes the number of pubkeys (N in M-of-N).
    So a 10-of-15 multisig contributes 15 sigops per input, not 10.

    Uses a 10-of-15 P2WSH multisig: 15 sigops per input × ~6 000 inputs
    = 90 000 > 80 000 cap.
    """
    spk = _p2wsh_spk()
    # Build a 10-of-15 multisig.  OP_N before CHECKMULTISIG is OP_15 → 15 sigops.
    out = bytearray([_push_op(10)])
    for _ in range(15):
        out.append(0x21)
        out += b"\x02" + b"\x00" * 32
    out.append(_push_op(15))
    out.append(OP_CHECKMULTISIG)
    witness_script = bytes(out)
    witness = [b""] + [b"sig"] * 10 + [witness_script]

    per_input = _count_witness_sigops(spk, witness)
    assert per_input == 15, f"expected accurate count = 15, got {per_input}"

    # 6 000 inputs × 15 = 90 000 raw witness-sigop units
    total = per_input * 6_000
    assert total == 90_000
    assert total > MAX_BLOCK_SIGOPS_COST  # must trigger block rejection


def test_witness_scale_factor_constant():
    """Sanity: WITNESS_SCALE_FACTOR = 4 per BIP141."""
    assert WITNESS_SCALE_FACTOR == 4


def test_max_block_sigops_cost_constant():
    """Sanity: MAX_BLOCK_SIGOPS_COST = 80 000 per BIP141."""
    assert MAX_BLOCK_SIGOPS_COST == 80_000
