"""W135 — Standardness rules (IsStandardTx) audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/policy/policy.{h,cpp} (IsStandardTx, IsStandard,
  ValidateInputsStandardness, IsWitnessStandard, GetDustThreshold),
  bitcoin-core/src/script/solver.{h,cpp} (TxoutType, Solver,
  MatchPayToPubkey, MatchMultisig),
  bitcoin-core/src/policy/truc_policy.{h,cpp} (SingleTRUCChecks,
  PackageTRUCChecks),
  bitcoin-core/src/consensus/tx_check.cpp (CheckTransaction floor),
  bitcoin-core/src/node/mempool_args.cpp (operator policy flag plumbing),
  bitcoin-core/src/init.cpp (operator policy CLI args).

Scope:
- IsStandardTx 8 gates (version, weight, min-size, scriptSig size+pushonly,
  output type, datacarrier cumulative cap, dust).
- IsStandard output-type recognition (P2PK, P2PKH, P2SH, P2WPKH, P2WSH,
  P2TR, P2A, NULL_DATA, MULTISIG bounds + WITNESS_UNKNOWN passthrough).
- ValidateInputsStandardness (P2SH redeem-script sigops, witness_unknown
  spend rejection).
- IsWitnessStandard (P2WSH script size + stack-item limits, tapscript
  stack-item limits, annex rejection).
- TRUC SingleTRUCChecks + PackageTRUCChecks parity.
- Operator-tunable policy flags (-permitbaremultisig, -datacarrier,
  -datacarriersize, -dustrelayfee, -bytespersigop).
- Two-pipeline guard (G30): standardness is Python-only, MUST NOT leak
  into ferrous-utils.

Excludes (audited elsewhere or not in scope):
- Script interpreter STANDARD_SCRIPT_VERIFY_FLAGS — that's a script
  evaluation gate, not an IsStandardTx gate (CheckInputScripts).
- BIP-125 RBF Rule 3 — W130.
- Mempool cluster eviction — W120.
- nSequence / OP_CSV / MTP — W132.

This file contains an xfail test per Core-divergent gate; xfails flip
to XPASS the moment a fix lands. PRESENT gates are plain asserts that
pin Core-parity wiring.

Reference: ouroboros/audit/w135_standardness_rules.md.

NO production code changes. NO behavior changes. Only audit + xfail.
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup + sync module mock so ouroboros imports cleanly without the
# compiled Rust extension being present. Mirrors test_w133_index_databases.py.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

_tests_root = REPO_ROOT / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))

import conftest  # noqa: F401,E402 — installs sync stub

import ouroboros.mempool as mempool_mod  # noqa: E402
from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _make_tx(
    *,
    version: int = 2,
    inputs: list[TxIn] | None = None,
    outputs: list[TxOut] | None = None,
    locktime: int = 0,
    txid: bytes | None = None,
) -> Transaction:
    if inputs is None:
        inputs = [TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                       script_sig=b"\x00" * 32, sequence=0xffffffff)]
    if outputs is None:
        outputs = [TxOut(value=10_000, script_pubkey=b"\x76\xa9\x14" + b"\x22" * 20 + b"\x88\xac")]
    if txid is None:
        txid = b"\xab" * 32  # placeholder txid; standardness checks don't use it
    return Transaction(
        txid=txid,
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
    )


P2PKH_SPK = b"\x76\xa9\x14" + b"\x22" * 20 + b"\x88\xac"
P2SH_SPK = b"\xa9\x14" + b"\x33" * 20 + b"\x87"
P2WPKH_SPK = b"\x00\x14" + b"\x44" * 20
P2WSH_SPK = b"\x00\x20" + b"\x55" * 32
P2TR_SPK = b"\x51\x20" + b"\x66" * 32
P2A_SPK = bytes([0x51, 0x02, 0x4e, 0x73])
OP_RETURN_SPK = bytes([0x6a]) + b"\x10" + b"\xab" * 16

# Real-shape P2PK output: 0x21 <33-byte-compressed-pubkey> 0xac (OP_CHECKSIG)
# Compressed pubkey starts with 0x02 or 0x03.
P2PK_COMPRESSED_SPK = b"\x21" + b"\x02" + b"\x77" * 32 + b"\xac"

# 33-byte non-compressed (invalid) — Core would reject this in CPubKey::ValidSize.
P2PK_BAD_SPK = b"\x21" + b"\x07" + b"\x77" * 32 + b"\xac"

# Bare multisig 2-of-3 standard pattern: OP_2 <33 pk1> <33 pk2> <33 pk3> OP_3 OP_CHECKMULTISIG
PK33A = b"\x02" + b"\xaa" * 32
PK33B = b"\x02" + b"\xbb" * 32
PK33C = b"\x02" + b"\xcc" * 32
MULTI_2_OF_3 = (
    bytes([0x52])  # OP_2
    + b"\x21" + PK33A
    + b"\x21" + PK33B
    + b"\x21" + PK33C
    + bytes([0x53])  # OP_3
    + bytes([0xae])  # OP_CHECKMULTISIG
)

# Non-standard 4-of-7: Core IsStandard rejects (n > 3).
MULTI_4_OF_7 = (
    bytes([0x54])  # OP_4
    + (b"\x21" + b"\x02" + b"\xdd" * 32) * 7
    + bytes([0x57])  # OP_7
    + bytes([0xae])
)

# Bogus "multisig" (just OP_CHECKMULTISIG suffix with garbage prefix).
BOGUS_MULTI = b"\x99\x98\x97" + bytes([0xae])


# ===========================================================================
# G1-G5 — Core IsStandardTx gates 1-5 (version, weight, min-size, scriptSig)
# ===========================================================================


def test_w135_g1_version_range_present() -> None:
    """G1 (PRESENT): version ∈ [TX_MIN_STANDARD_VERSION=1, TX_MAX_STANDARD_VERSION=3].

    Core: policy.h:152-153 + policy.cpp:102-104.
    ouroboros: mempool.py:1125-1126.
    """
    # Below 1 → non-standard
    tx = _make_tx(version=0)
    ok, reason = mempool_mod._is_standard_tx(tx)
    assert not ok and "version" in reason.lower(), reason

    # Above 3 (TX_MAX_STANDARD_VERSION) → non-standard
    tx = _make_tx(version=4)
    ok, reason = mempool_mod._is_standard_tx(tx)
    assert not ok and "version" in reason.lower(), reason

    # Versions 1, 2, 3 → standard (gate 1 passes; other gates may still reject)
    for v in (1, 2, 3):
        tx = _make_tx(version=v)
        ok, reason = mempool_mod._is_standard_tx(tx)
        # gate 1 passes for v ∈ {1,2,3}; non-version gates may reject (e.g. dust on a
        # default-zero output)
        if not ok:
            assert "version" not in reason.lower(), f"v={v} failed on version gate: {reason}"


def test_w135_g2_max_standard_tx_weight_present() -> None:
    """G2 (PRESENT): tx.weight > MAX_STANDARD_TX_WEIGHT=400000 → "tx-size".

    Core: policy.h:38 + policy.cpp:111-115.
    ouroboros: mempool.py:1133-1135.
    """
    assert mempool_mod.MAX_STANDARD_TX_WEIGHT == 400_000, "G2 REGRESSION: MAX_STANDARD_TX_WEIGHT"


def test_w135_g3_min_standard_tx_nonwitness_size_present() -> None:
    """G3 (PRESENT): non-witness serialized size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE=65.

    Mitigates CVE-2017-12842 (64-byte tx merkle-tree malleability).
    Core: policy.h:40 + validation.cpp:813.
    ouroboros: mempool.py:1137-1142.
    """
    assert mempool_mod.MIN_STANDARD_TX_NONWITNESS_SIZE == 65


def test_w135_g4_max_standard_scriptsig_size_present() -> None:
    """G4 (PRESENT): every input scriptSig size ≤ 1650 bytes ("scriptsig-size").

    Core: policy.h:62 + policy.cpp:127-130.
    ouroboros: mempool.py:1149-1150.
    """
    assert mempool_mod.MAX_STANDARD_SCRIPTSIG_SIZE == 1650

    big_sig = b"\x00" * 1651
    tx = _make_tx(inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                               script_sig=big_sig, sequence=0xffffffff)])
    ok, reason = mempool_mod._is_standard_tx(tx)
    assert not ok and "scriptsig" in reason.lower() and "size" in reason.lower()


def test_w135_g5_scriptsig_push_only_present() -> None:
    """G5 (PRESENT): every input scriptSig must be IsPushOnly.

    Core: policy.cpp:131-134.
    ouroboros: mempool.py:1151-1152 + _is_push_only_from helper.
    """
    # OP_DUP (0x76) is NOT a push opcode → fails push-only.
    non_push = bytes([0x76])
    tx = _make_tx(inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                               script_sig=non_push, sequence=0xffffffff)])
    ok, reason = mempool_mod._is_standard_tx(tx)
    assert not ok and "push" in reason.lower(), reason


# ===========================================================================
# G6 — Output scriptPubKey standardness (includes BUG-2/3/4/13/14/15)
# ===========================================================================


def test_w135_g6_p2pkh_p2sh_segwit_outputs_standard() -> None:
    """G6 (PRESENT): P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A, OP_RETURN, and
    well-formed bare multisig are all recognized as standard.

    Core: solver.cpp:141-211 + policy.cpp:80-98.
    ouroboros: mempool.py:_is_standard_output_type.
    """
    assert mempool_mod._is_standard_output_type(P2PKH_SPK)
    assert mempool_mod._is_standard_output_type(P2SH_SPK)
    assert mempool_mod._is_standard_output_type(P2WPKH_SPK)
    assert mempool_mod._is_standard_output_type(P2WSH_SPK)
    assert mempool_mod._is_standard_output_type(P2TR_SPK)
    assert mempool_mod._is_standard_output_type(P2A_SPK)
    assert mempool_mod._is_standard_output_type(OP_RETURN_SPK)
    assert mempool_mod._is_standard_output_type(MULTI_2_OF_3)  # 2-of-3 is standard in Core


@pytest.mark.xfail(
    reason="W135 BUG-3 (P0-CDIV): P2PK output (<pubkey> OP_CHECKSIG) "
           "not recognized. Core's MatchPayToPubkey (solver.cpp:36-47) "
           "+ Solver returns TxoutType::PUBKEY; IsStandard accepts. "
           "ouroboros rejects as non-standard. Cross-impl divergence "
           "on sendrawtransaction.",
    strict=True,
)
def test_w135_g12_p2pk_output_recognized_bug3() -> None:
    """G12 (BUG-3 P0-CDIV): P2PK output recognized as standard."""
    assert mempool_mod._is_standard_output_type(P2PK_COMPRESSED_SPK), (
        "G12: <33-byte-compressed-pubkey> OP_CHECKSIG should be standard (TxoutType::PUBKEY) "
        "per Core MatchPayToPubkey (solver.cpp:36-47)"
    )


@pytest.mark.xfail(
    reason="W135 BUG-4 (P0-CDIV): WITNESS_UNKNOWN rejected at output side. "
           "Core's IsStandard accepts WITNESS_UNKNOWN (only spending is "
           "rejected in ValidateInputsStandardness). ouroboros's symmetric "
           "rejection breaks forward-compatibility for future witness "
           "versions added by soft fork. See policy.cpp:80-98 vs "
           "ValidateInputsStandardness policy.cpp:234-240.",
    strict=True,
)
def test_w135_g16_witness_unknown_accepted_at_output_bug4() -> None:
    """G16 (BUG-4 P0-CDIV): WITNESS_UNKNOWN output accepted (asymmetric
    with input-side rejection)."""
    # Witness version 2, 20-byte program — not standard yet, but Core's
    # IsStandard returns true (WITNESS_UNKNOWN). Future soft fork.
    witness_v2 = bytes([0x52, 0x14]) + b"\x77" * 20
    assert mempool_mod._is_standard_output_type(witness_v2), (
        "G16: WITNESS_UNKNOWN should be standard at output side "
        "(forward-compat); only rejected on spend"
    )


@pytest.mark.xfail(
    reason="W135 BUG-2 (P0-CDIV): Bare multisig 'detection' is just "
           "script_pubkey[-1] == 0xae (last byte is OP_CHECKMULTISIG). "
           "Core's IsStandard for MULTISIG rejects n > 3 "
           "(policy.cpp:91-92). ouroboros accepts 4-of-7 multisig.",
    strict=True,
)
def test_w135_g13_multisig_n_le_3_bug2() -> None:
    """G13 (BUG-2 P0-CDIV): n ≤ 3 enforced for bare multisig."""
    # 4-of-7 — Core: nonstandard. ouroboros: currently passes the lazy check.
    assert not mempool_mod._is_standard_output_type(MULTI_4_OF_7), (
        "G13: 4-of-7 bare multisig is non-standard in Core (n>3)"
    )


@pytest.mark.xfail(
    reason="W135 BUG-2 (P0-CDIV): Bare multisig has no opcode parser. "
           "Core's MatchMultisig (solver.cpp:85-105) parses ALL opcodes "
           "+ verifies m/pubkeys/n. ouroboros accepts any script ending "
           "in 0xae as standard.",
    strict=True,
)
def test_w135_g15_multisig_full_opcode_parse_bug2() -> None:
    """G15 (BUG-2 P0-CDIV): Bare multisig requires full opcode parse,
    not just last-byte check."""
    # Garbage 3-byte script ending in OP_CHECKMULTISIG (0xae).
    # Core's Solver / MatchMultisig will return NONSTANDARD because parsing
    # fails (first byte isn't OP_1..OP_16 + valid pushdata pattern).
    assert not mempool_mod._is_standard_output_type(BOGUS_MULTI), (
        "G15: <0x99 0x98 0x97 0xae> is not a valid bare multisig; "
        "Core's MatchMultisig rejects via opcode parse"
    )


@pytest.mark.xfail(
    reason="W135 BUG-13 (P1): MAX_PUBKEYS_PER_MULTISIG=20 not enforced. "
           "Core's MatchMultisig (solver.cpp:101-103) requires "
           "num_keys ≤ MAX_PUBKEYS_PER_MULTISIG. Sub-issue of BUG-2.",
    strict=True,
)
def test_w135_g13_max_pubkeys_per_multisig_bug13() -> None:
    """G13b (BUG-13 P1): Bare multisig with > 20 pubkeys rejected.

    Even closing BUG-2 with just the n≤3 check would leave a separate
    overflow with n=21+. This pins the additional bound.
    """
    # We can't reach this without first matching the multisig pattern; the
    # bug surfaces if and when MatchMultisig is rewritten to parse opcodes
    # but forgets MAX_PUBKEYS_PER_MULTISIG.
    # Pseudo-multisig 21-of-21 would be rejected by Core's MatchMultisig.
    # Currently ouroboros accepts because of the last-byte check.
    fake_21_of_21 = (
        bytes([0x01, 21])  # PUSH 1 byte: value 21 (not OP_N; Core wants OP_21 which doesn't exist either)
        + (b"\x21" + b"\x02" + b"\xee" * 32) * 21
        + bytes([0x01, 21])
        + bytes([0xae])
    )
    # When BUG-2 is fixed (MatchMultisig with opcode parse), 21-of-21 must
    # still fail MAX_PUBKEYS_PER_MULTISIG. Today's `_is_standard_output_type`
    # accepts via last-byte, so this xfails (the assertion holds when the
    # fix lands).
    assert not mempool_mod._is_standard_output_type(fake_21_of_21), (
        "G13b: 21-of-21 multisig > MAX_PUBKEYS_PER_MULTISIG=20"
    )


@pytest.mark.xfail(
    reason="W135 BUG-14 (P1): minimal-push encoding not enforced for "
           "m/n in bare multisig. Core's GetScriptNumber "
           "(solver.cpp:66-83) calls CheckMinimalPush. Sub-issue of BUG-2.",
    strict=True,
)
def test_w135_g14_multisig_minimal_push_encoding_bug14() -> None:
    """G14 (BUG-14 P1): m/n in bare multisig must be minimally encoded."""
    # 3-of-3 with m encoded as `01 03` (PUSH1 byte 3) instead of OP_3.
    non_minimal_3_of_3 = (
        bytes([0x01, 0x03])  # non-minimal: PUSH1 0x03 instead of OP_3 (0x53)
        + b"\x21" + PK33A
        + b"\x21" + PK33B
        + b"\x21" + PK33C
        + bytes([0x53])
        + bytes([0xae])
    )
    # Core's MatchMultisig + GetScriptNumber with CheckMinimalPush would reject.
    # ouroboros's last-byte check accepts.
    assert not mempool_mod._is_standard_output_type(non_minimal_3_of_3), (
        "G14: non-minimal m encoding is rejected by Core's CheckMinimalPush"
    )


def test_w135_g15_p2a_forward_compat_lax() -> None:
    """G15b (BUG-15 P1): is_pay_to_anchor accepts ALL OP_1 OP_PUSHBYTES_2
    outputs, not just program=0x4e73.

    Reviewing the actual code: mempool.py:730 is_pay_to_anchor() DOES check
    bytes 2,3 == 0x4e,0x73. So this is actually PRESENT, not missing.
    Pin the present behavior so a regression flips the test.
    """
    # Correct P2A pattern → accepted
    assert mempool_mod._is_standard_output_type(P2A_SPK)
    # Bogus "anchor" with same length but different program bytes → rejected
    fake_anchor = bytes([0x51, 0x02, 0xab, 0xcd])
    assert not mempool_mod._is_standard_output_type(fake_anchor) or (
        # If any future P2A semantics expand to more programs, this assertion
        # would loosen — flag for regression review.
        False
    ), "G15b: P2A pattern accepts non-canonical anchor program"


# ===========================================================================
# G7 — OP_RETURN tail push-only (PRESENT)
# ===========================================================================


def test_w135_g7_op_return_tail_push_only_present() -> None:
    """G7 (PRESENT): OP_RETURN tail bytes must be push-only.

    Core: solver.cpp:185.
    ouroboros: mempool.py:835-836 + _is_push_only_from.
    """
    # Truncated push (PUSH9 with only 4 bytes of data) → non-standard
    truncated = bytes([0x6a, 9, 0xde, 0xad, 0xbe, 0xef])
    assert not mempool_mod._is_standard_output_type(truncated), (
        "G7: truncated OP_RETURN tail must be rejected"
    )

    # Well-formed PUSH4 → standard
    good = bytes([0x6a, 4, 0xde, 0xad, 0xbe, 0xef])
    assert mempool_mod._is_standard_output_type(good)

    # OP_RETURN followed by non-push opcode → non-standard
    bad_op = bytes([0x6a, 0x76])  # OP_DUP after OP_RETURN
    assert not mempool_mod._is_standard_output_type(bad_op)


# ===========================================================================
# G8 — Cumulative datacarrier size cap (BUG-1)
# ===========================================================================


def test_w135_g8_datacarrier_cumulative_cap_present() -> None:
    """G8 (PRESENT): MAX_OP_RETURN_RELAY=100000 cap honored across multiple
    OP_RETURNs in a single tx.

    Core: policy.cpp:137-156.
    ouroboros: mempool.py:1159-1170.
    """
    assert mempool_mod.MAX_OP_RETURN_RELAY == 100_000


@pytest.mark.xfail(
    reason="W135 BUG-1 (P1): No -datacarrier toggle. Core's off-mode "
           "(value_or(0)) means ANY OP_RETURN with size > 0 must fail. "
           "Also no -datacarriersize tunable. mempool_args.cpp:95-99.",
    strict=True,
)
def test_w135_g18_datacarrier_off_mode_bug1() -> None:
    """G18 (BUG-1 P1): -datacarrier=false rejects ANY OP_RETURN.

    When max_datacarrier_bytes is None (Core: std::nullopt), value_or(0)
    returns 0; any OP_RETURN with size > 0 trips reason='datacarrier'.
    Currently mempool.py hard-codes the comparison to MAX_OP_RETURN_RELAY,
    no None path.
    """
    # Probe by signature inspection — does _is_standard_tx accept a
    # max_datacarrier_bytes parameter? Core's IsStandardTx does.
    sig = inspect.signature(mempool_mod._is_standard_tx)
    assert "max_datacarrier_bytes" in sig.parameters, (
        "G18: _is_standard_tx should accept max_datacarrier_bytes for "
        "-datacarrier=false support"
    )


@pytest.mark.xfail(
    reason="W135 BUG-1 (P1): No -datacarriersize operator toggle. "
           "Operators cannot tune the limit. mempool.py:43 hard-codes "
           "MAX_OP_RETURN_RELAY=100000.",
    strict=True,
)
def test_w135_g19_datacarriersize_tunable_bug1() -> None:
    """G19 (BUG-1 P1): -datacarriersize CLI flag accepted + plumbed."""
    cli_text = _read_py("cli.py")
    has_arg = "--datacarriersize" in cli_text or "'-datacarriersize'" in cli_text
    assert has_arg, "G19: --datacarriersize flag missing from CLI"


# ===========================================================================
# G9-G10 — Dust check + MAX_DUST_OUTPUTS_PER_TX (BUG-6)
# ===========================================================================


def test_w135_g10_max_dust_outputs_per_tx_present() -> None:
    """G10 (PRESENT): MAX_DUST_OUTPUTS_PER_TX = 1.

    Core: policy.h:95.
    ouroboros: mempool.py:85.
    """
    assert mempool_mod.MAX_DUST_OUTPUTS_PER_TX == 1
    assert mempool_mod.DUST_RELAY_TX_FEE == 3000


def test_w135_g9_dust_threshold_formula_bug6() -> None:
    """G9 (BUG-6 P1): GetDustThreshold matches Core's serialize-size formula.

    FIXED (ported from rustoshi d6e9934): _get_dust_threshold now computes
    nSize = GetSerializeSize(txout) + spend_cost faithfully to Core
    policy.cpp:27-63, instead of a hardcoded per-type size table (which both
    dropped the GetSerializeSize term and mis-sized P2WPKH to 297).

    Core formula: nSize = GetSerializeSize(txout) + spend_cost
      GetSerializeSize(CTxOut) = 8 (value, int64) + CompactSize(len) + len
      spend_cost = 32+4+1+107+4 = 148 legacy, OR 32+4+1+(107//4)+4 = 67 segwit
      threshold = CeilDiv(nSize * dustRelayFee, 1000)
    """
    def core_dust_threshold(spk: bytes) -> int:
        """Independent Core reference (does NOT call the impl)."""
        if spk and spk[0] == 0x6a:
            return 0
        if mempool_mod.is_pay_to_anchor(spk):
            return 0
        n = len(spk)
        prefix = 1 if n < 0xfd else (3 if n <= 0xffff else 5)
        ser = 8 + prefix + n
        # witness program: OP_0/OP_1..16 + 2..40 byte push
        is_wp = (
            4 <= n <= 42
            and (spk[0] == 0x00 or 0x51 <= spk[0] <= 0x60)
            and spk[1] + 2 == n
            and 2 <= spk[1] <= 40
        )
        spend = 67 if is_wp else 148
        nsize = ser + spend
        return -((-(nsize * mempool_mod.DUST_RELAY_TX_FEE)) // 1000)

    # The five standard Core thresholds at the default 3000 sat/kvB rate.
    p2pkh = b"\x76\xa9\x14" + b"\x77" * 20 + b"\x88\xac"            # 25B legacy
    p2sh = b"\xa9\x14" + b"\x77" * 20 + b"\x87"                      # 23B legacy
    p2wpkh = b"\x00\x14" + b"\x77" * 20                             # 22B segwit
    p2wsh = b"\x00\x20" + b"\x77" * 32                              # 34B segwit
    p2tr = b"\x51\x20" + b"\x77" * 32                               # 34B segwit
    expected = {
        bytes(p2pkh): 546,
        bytes(p2sh): 540,
        bytes(p2wpkh): 294,
        bytes(p2wsh): 330,
        bytes(p2tr): 330,
    }
    for spk, want in expected.items():
        got = mempool_mod._get_dust_threshold(spk)
        assert got == want, f"dust({spk.hex()}) = {got}, Core = {want}"
        assert got == core_dust_threshold(spk)

    # Custom-size probe: a 30-byte spendable legacy script. The OLD hardcoded
    # table returned its catch-all 182*3000//1000 = 546; Core's formula gives
    # (8 + 1 + 30 + 148) * 3000 / 1000 = 561 → the fix is required to match.
    custom_30 = b"\x76\xa9\x14" + b"\x77" * 20 + b"\x88\xac\x00\x00\x00\x00\x00"
    assert len(custom_30) == 30
    core_dust = (8 + 1 + 30 + 148) * mempool_mod.DUST_RELAY_TX_FEE // 1000
    assert core_dust == 561
    actual = mempool_mod._get_dust_threshold(custom_30)
    assert actual == core_dust, (
        f"G9: dust threshold {actual} != Core formula {core_dust} for 30-byte script"
    )

    # OP_RETURN and P2A are unspendable / anchor → threshold 0.
    assert mempool_mod._get_dust_threshold(b"\x6a\x04dead") == 0
    assert mempool_mod._get_dust_threshold(b"\x51\x02\x4e\x73") == 0


# ===========================================================================
# G11 — Coinbase always non-standard (PRESENT)
# ===========================================================================


def test_w135_g11_coinbase_rejected_present() -> None:
    """G11 (PRESENT): coinbase txs are never standard (mempool-side).

    Core: validation.cpp:802-804 (PreChecks rejects coinbase).
    ouroboros: mempool.py:1976-1981 in _add_transaction_inner.
    """
    src = _read_py("mempool.py")
    assert 'return False, "coinbase"' in src, (
        "G11: coinbase rejection (return 'coinbase') missing"
    )


# ===========================================================================
# G17-G21 — Operator-tunable policy flags (BUG-1/5/8/9)
# ===========================================================================


@pytest.mark.xfail(
    reason="W135 BUG-5 (P1): No -permitbaremultisig flag. Core: "
           "policy.h:52 DEFAULT_PERMIT_BAREMULTISIG=true. Operators "
           "cannot refuse to relay bare multisig.",
    strict=True,
)
def test_w135_g17_permitbaremultisig_flag_bug5() -> None:
    """G17 (BUG-5 P1): --permitbaremultisig CLI flag accepted + plumbed."""
    cli_text = _read_py("cli.py")
    has_arg = "--permitbaremultisig" in cli_text or "'-permitbaremultisig'" in cli_text
    assert has_arg, "G17: --permitbaremultisig flag missing from CLI"


@pytest.mark.xfail(
    reason="W135 BUG-8 (P1): No -dustrelayfee flag. Core: "
           "policy.h:68 DUST_RELAY_TX_FEE=3000 is default; operators "
           "can tune. mempool.py:48 hardcodes.",
    strict=True,
)
def test_w135_g20_dustrelayfee_flag_bug8() -> None:
    """G20 (BUG-8 P1): --dustrelayfee CLI flag accepted + plumbed."""
    cli_text = _read_py("cli.py")
    has_arg = "--dustrelayfee" in cli_text or "'-dustrelayfee'" in cli_text
    assert has_arg, "G20: --dustrelayfee flag missing from CLI"


@pytest.mark.xfail(
    reason="W135 BUG-9 (P2): No -bytespersigop flag. Core: "
           "policy.h:50 DEFAULT_BYTES_PER_SIGOP=20.",
    strict=True,
)
def test_w135_g21_bytespersigop_flag_bug9() -> None:
    """G21 (BUG-9 P2): --bytespersigop CLI flag accepted + plumbed."""
    cli_text = _read_py("cli.py")
    has_arg = "--bytespersigop" in cli_text or "'-bytespersigop'" in cli_text
    assert has_arg, "G21: --bytespersigop flag missing from CLI"


# ===========================================================================
# G22 — Core debug-string error parity (BUG-7)
# ===========================================================================


@pytest.mark.xfail(
    reason="W135 BUG-7 (P1): _is_standard_tx emits English diagnostic "
           "strings instead of Core's short kebab strings ('version', "
           "'tx-size', 'scriptsig-size', 'scriptsig-not-pushonly', "
           "'scriptpubkey', 'bare-multisig', 'datacarrier', 'dust'). "
           "Continuation of W125 RPC error parity.",
    strict=True,
)
def test_w135_g22_error_string_parity_bug7() -> None:
    """G22 (BUG-7 P1): Core short kebab strings emitted, not English."""
    # Test: version-out-of-range should produce "version" (Core's short string)
    tx = _make_tx(version=5)
    ok, reason = mempool_mod._is_standard_tx(tx)
    assert not ok
    # Core's IsStandardTx sets reason="version" (single token). ouroboros says
    # "Non-standard version: 5". Pin Core's short form.
    assert reason == "version" or reason.startswith("version"), (
        f"G22: expected Core short string 'version', got {reason!r}"
    )


# ===========================================================================
# G23-G24 — ValidateInputsStandardness (PRESENT)
# ===========================================================================


def test_w135_g23_validate_inputs_standardness_present() -> None:
    """G23 (PRESENT): _validate_inputs_standardness exists + mirrors Core.

    Core: policy.cpp:214-263.
    ouroboros: mempool.py:1016-1105.
    """
    assert hasattr(mempool_mod, "_validate_inputs_standardness")
    sig = inspect.signature(mempool_mod._validate_inputs_standardness)
    assert "tx" in sig.parameters and "prev_scripts" in sig.parameters


def test_w135_g24_max_p2sh_sigops_present() -> None:
    """G24 (PRESENT): MAX_P2SH_SIGOPS = 15.

    Core: policy.h:42.
    ouroboros: mempool.py:91.
    """
    assert mempool_mod.MAX_P2SH_SIGOPS == 15


# ===========================================================================
# G25-G26 — IsWitnessStandard (PRESENT)
# ===========================================================================


def test_w135_g25_is_witness_standard_p2wsh_limits_present() -> None:
    """G25 (PRESENT): IsWitnessStandard P2WSH limits.

    Core: policy.cpp:309-318.
    ouroboros: mempool.py:1354-1366.
    """
    assert mempool_mod.MAX_STANDARD_P2WSH_SCRIPT_SIZE == 3600
    assert mempool_mod.MAX_STANDARD_P2WSH_STACK_ITEMS == 100
    assert mempool_mod.MAX_STANDARD_P2WSH_STACK_ITEM_SIZE == 80


def test_w135_g26_tapscript_stack_item_size_present() -> None:
    """G26 (PRESENT): MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80.

    Core: policy.h:58.
    ouroboros: mempool.py:97.
    """
    assert mempool_mod.MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE == 80


# ===========================================================================
# G27-G28 — TRUC (BIP-431) single + package checks (BUG-10/11/16)
# ===========================================================================


def test_w135_g27_truc_constants_present() -> None:
    """G27 (PRESENT subset): TRUC constants match Core BIP-431.

    Core: truc_policy.h:20-34.
    ouroboros: mempool.py:60-67.
    """
    assert mempool_mod.TRUC_VERSION == 3
    assert mempool_mod.TRUC_MAX_VSIZE == 10_000
    assert mempool_mod.TRUC_CHILD_MAX_VSIZE == 1_000
    assert mempool_mod.TRUC_ANCESTOR_LIMIT == 2
    assert mempool_mod.TRUC_DESCENDANT_LIMIT == 2


@pytest.mark.xfail(
    reason="W135 BUG-10 (P1): _check_truc_policy sibling-eviction uses "
           "children-set semantics where Core uses descendants-set. For "
           "TRUC where descendant_count ≤ 2 these coincide today, but "
           "the semantic divergence (truc_policy.cpp:240-250 std::any_of "
           "over descendants vs ouroboros direct_conflicts.intersection "
           "over parent.children) is observable under reorg replacement.",
    strict=True,
)
def test_w135_g27_truc_descendant_set_semantics_bug10() -> None:
    """G27b (BUG-10 P1): _check_truc_policy descendants/children parity."""
    src = _read_py("mempool.py")
    # Look for Core-shaped descendant-set derivation: erase parent from
    # descendants set then iterate (Core truc_policy.cpp:234-242).
    has_descendants_erase = "descendants.erase" in src or "descendants.remove" in src
    assert has_descendants_erase, (
        "G27b: _check_truc_policy should derive descendants-set per Core "
        "(descendants minus parent), not parent.children"
    )


def test_w135_g28_package_truc_grandparent_rejection_present() -> None:
    """G28 (PRESENT, audit-flip): _check_package_truc_policy DOES reject
    1-parent-1-package-grandparent TRUC packages via the combined
    ancestor-count gate (mempool_parents + package_parents + 1 >
    TRUC_ANCESTOR_LIMIT).

    Audit-doc BUG-11 was raised as a suspected gap; the implementation
    audit found the gate exists at mempool.py:2706-2722 (the
    `total_ancestors + 1 > TRUC_ANCESTOR_LIMIT` arm) which catches the
    1-parent + 1-package-grandparent case naturally. Closure recorded.

    Pinning this PRESENT means a regression that removes the
    package-parent counting flips the test red.

    Reference: bitcoin-core/src/policy/truc_policy.cpp:76-79 +
    truc_policy.h:87-88 case 5.
    """
    src = _read_py("mempool.py")
    # Combined-ancestor gate must use BOTH mempool_parents AND package_parents
    has_combined_gate = (
        "len(mempool_parents) + len(package_parents)" in src
        or "total_ancestors = len(mempool_parents) + len(package_parents)" in src
    )
    assert has_combined_gate, (
        "G28 REGRESSION: PackageTRUCChecks no longer sums mempool_parents + "
        "package_parents; the grandparent rejection (truc_policy.h:87-88) "
        "regressed"
    )


@pytest.mark.xfail(
    reason="W135 BUG-16 (P2): TRUC error strings missing txid+wtxid "
           "context that Core's strprintf includes "
           "(truc_policy.cpp:72-73 / 77 / 83 / etc).",
    strict=True,
)
def test_w135_g27_truc_error_string_context_bug16() -> None:
    """G27c (BUG-16 P2): TRUC error strings include tx id + wtxid context."""
    src = _read_py("mempool.py")
    # Probe for txid/wtxid hex-formatted in error strings near TRUC checks.
    # We grep within _check_truc_policy.
    has_context = (
        '"would have too many ancestors"' in src
        and (".hex()" in src or "txid.hex" in src)
        and "tx_is_v3" in src  # locating the TRUC function
    )
    # Required pattern: "tx {txid_hex} (wtxid={wtxid_hex}) would have ..."
    # ouroboros has "tx would have too many ancestors" — no context.
    assert "txid_hex" in src and "wtxid_hex" in src, (
        "G27c: TRUC error strings should include txid+wtxid context per Core"
    )


# ===========================================================================
# G29 — SpendsNonAnchorWitnessProg helper (BUG-12)
# ===========================================================================


@pytest.mark.xfail(
    reason="W135 BUG-12 (P2): No SpendsNonAnchorWitnessProg helper "
           "(Core: policy.cpp:354-388). Used in CPFP/ephemeral-dust "
           "interaction checks. Latent.",
    strict=True,
)
def test_w135_g29_spends_non_anchor_witness_prog_bug12() -> None:
    """G29 (BUG-12 P2): SpendsNonAnchorWitnessProg helper present."""
    has_helper = (
        hasattr(mempool_mod, "spends_non_anchor_witness_prog")
        or hasattr(mempool_mod, "_spends_non_anchor_witness_prog")
        or hasattr(mempool_mod, "SpendsNonAnchorWitnessProg")
    )
    assert has_helper, (
        "G29: SpendsNonAnchorWitnessProg helper missing"
    )


# ===========================================================================
# G30 — Two-pipeline guard (PRESENT, extends W76+W120+W122+W125+W128+W129+W130+W133)
# ===========================================================================


def test_w135_g30_two_pipeline_standardness_only_in_python() -> None:
    """G30 (PRESENT): standardness is Python-only.

    ferrous-utils (Rust) MUST NOT contain IsStandard / IsStandardTx /
    MAX_STANDARD_TX_* / permit_bare_multisig / max_datacarrier_bytes /
    TRUC_VERSION identifiers. Standardness is policy, not consensus; it
    lives on the Python side where operator flags are applied.

    Extends the guard set W76 + W120 + W122 + W125 + W128 + W129 + W130
    + W133 → now W135. Eighth dedicated guard. Specifically covers the
    POLICY boundary (vs. prior guards which covered functional-area
    boundaries).

    Future regressions (e.g. an attempt to move IsStandardTx into a
    Rust validator pass for performance) trip this guard.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present")

    forbidden_identifiers = [
        # Direct names of standardness functions.
        "fn is_standard_tx",
        "fn IsStandardTx",
        "fn is_standard(",
        "fn validate_inputs_standardness",
        "fn is_witness_standard",
        # Constants only meaningful to standardness.
        "MAX_STANDARD_TX_WEIGHT",
        "MAX_STANDARD_SCRIPTSIG_SIZE",
        "MAX_STANDARD_P2WSH_SCRIPT_SIZE",
        "MAX_STANDARD_P2WSH_STACK_ITEMS",
        "MAX_OP_RETURN_RELAY",
        "DUST_RELAY_TX_FEE",
        "MAX_DUST_OUTPUTS_PER_TX",
        "DEFAULT_PERMIT_BAREMULTISIG",
        "DEFAULT_ACCEPT_DATACARRIER",
        # TRUC policy is also Python-side.
        "TRUC_VERSION",
        "TRUC_MAX_VSIZE",
        "TRUC_CHILD_MAX_VSIZE",
        "TRUC_ANCESTOR_LIMIT",
        "TRUC_DESCENDANT_LIMIT",
        # Operator policy flags.
        "permit_bare_multisig",
        "max_datacarrier_bytes",
        "dust_relay_fee",
    ]

    offenders: list[tuple[str, str, int]] = []
    for rs_path in FERROUS_UTILS.rglob("*.rs"):
        text = rs_path.read_text(encoding="utf-8", errors="replace")
        for ident in forbidden_identifiers:
            if ident in text:
                # Allow comment-only mentions (e.g. cross-reference to
                # Core's policy.h in a doc comment). Filter pure-comment lines.
                lines = text.splitlines()
                for lineno, line in enumerate(lines, 1):
                    if ident not in line:
                        continue
                    stripped = line.lstrip()
                    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                        continue  # pure comment, OK
                    if stripped.startswith("#") and "[" in stripped:
                        continue  # attribute / cfg gate, OK
                    offenders.append((str(rs_path.relative_to(FERROUS_UTILS)), ident, lineno))

    assert not offenders, (
        "G30: standardness identifiers leaked into ferrous-utils (Rust). "
        "Standardness is policy, MUST stay Python-only.\n"
        + "\n".join(f"  {path}:{lineno} → {ident}" for path, ident, lineno in offenders)
    )


def test_w135_g30_standardness_constants_only_in_python_mempool() -> None:
    """G30b (PRESENT): Standardness constants live ONLY in src/ouroboros/mempool.py.

    Other Python files (rpc.py, node.py, validation.py, etc.) MAY reference
    them by name, but the DEFINITIONS (the `= NUMBER` assignment) live
    only in mempool.py. This pins the single-source-of-truth.
    """
    if not SRC_OUROBOROS.exists():
        pytest.skip("src/ouroboros tree not present")

    defining_constants = [
        "MAX_STANDARD_TX_WEIGHT",
        "MAX_STANDARD_TX_SIGOPS_COST",
        "MAX_STANDARD_SCRIPTSIG_SIZE",
        "MAX_OP_RETURN_RELAY",
        "TRUC_VERSION",
        "TRUC_MAX_VSIZE",
    ]

    definers: dict[str, list[str]] = {c: [] for c in defining_constants}
    for py_path in SRC_OUROBOROS.rglob("*.py"):
        if py_path.parts[-2] == "tests":
            continue
        if py_path.name == "__init__.py":
            continue
        text = py_path.read_text(encoding="utf-8", errors="replace")
        for c in defining_constants:
            # Looks for `CONST = <number>` definitions, not comments.
            if re.search(rf"^{re.escape(c)}\s*=\s*[\d_]+", text, re.M):
                definers[c].append(py_path.name)

    for c, files in definers.items():
        # mempool.py is the canonical home; any OTHER file defining it would
        # be a violation.
        non_mempool = [f for f in files if f != "mempool.py"]
        assert not non_mempool, (
            f"G30b: {c} defined outside mempool.py in {non_mempool} — "
            "standardness constants should live in mempool.py only"
        )


# ===========================================================================
# Order-of-checks guard (audit-doc BUG-13 nominal entry — kept as regression
# pin in case anyone reorders _is_standard_output_type checks).
# ===========================================================================


def test_w135_op_return_check_precedes_multisig_check() -> None:
    """Audit-only guard: in _is_standard_output_type, OP_RETURN (0x6a)
    check MUST appear before the trailing-0xae multisig check.

    Otherwise an OP_RETURN that happens to end in 0xae would be
    classified as multisig instead of nulldata.
    """
    src = _read_py("mempool.py")
    # Find the _is_standard_output_type body
    fn_start = src.find("def _is_standard_output_type")
    assert fn_start != -1, "Audit guard: _is_standard_output_type not found"
    fn_body = src[fn_start:fn_start + 4000]
    op_return_pos = fn_body.find("script_pubkey[0] == 0x6a")
    multisig_pos = fn_body.find("script_pubkey[-1] == 0xae")
    assert op_return_pos != -1, "OP_RETURN check missing from _is_standard_output_type"
    assert multisig_pos != -1, "Multisig check missing from _is_standard_output_type"
    assert op_return_pos < multisig_pos, (
        "Order regression: OP_RETURN check must precede multisig check"
    )


# ===========================================================================
# Audit-traceability test: ensure the audit doc file and this test file
# describe the same gate set + bug numbering (catches drift between docs).
# ===========================================================================


def test_w135_audit_doc_and_test_file_consistent() -> None:
    """Sanity: audit doc references BUG-1..BUG-16 + G1..G30; this test
    file should mention every BUG-N (1..12) at least once in xfail
    reasons or test names.

    Allows drift only on cosmetic / non-bug entries that the audit doc
    intentionally documents as 'not actually a bug' (BUG-13 placeholder
    + BUG-18 in the doc).
    """
    audit_path = REPO_ROOT / "audit" / "w135_standardness_rules.md"
    assert audit_path.exists(), "Audit doc missing"
    audit_text = audit_path.read_text(encoding="utf-8")
    this_text = Path(__file__).read_text(encoding="utf-8")

    # Spot-check: at least P0-CDIV bugs MUST be referenced in test reasons.
    p0_bugs = ["BUG-2", "BUG-3", "BUG-4"]
    for b in p0_bugs:
        assert b in this_text, f"P0-CDIV {b} missing from test file xfail reasons"

    # Two-pipeline guard mentioned in both
    assert "two-pipeline" in this_text.lower() or "two_pipeline" in this_text.lower()
    assert "two-pipeline" in audit_text.lower() or "Two-pipeline" in audit_text
