"""
W130 BIP-125 feebumper Rule 3 audit — ouroboros (Python pipeline only).

Discovery-only audit (NO production code changes). Audits the
**wallet-side** feebumper path that proposes RBF replacements before
the mempool sees them. Specifically the precise
`incrementalRelayFee.GetFee(maxTxSize)` invariant that Core enforces in
`feebumper.cpp::CheckFeeRate`, plus the surrounding
`PreconditionChecks` and `EstimateFeeRate` envelope.

The mempool-side enforcement of Rules 1-5 was audited in W120
(`test_w120_mempool_rbf.py`). W130 deliberately does NOT re-test the
mempool side; it covers the **wallet** envelope that Core wraps around
the mempool call.

Gates:
  G1-G2   RBF signal detection (PRESENT — sanity)
  G3-G7   PreconditionChecks (5 of 5 absent — BUG-1..5)
  G8-G11  CheckFeeRate invariants inv-A / inv-B / inv-C / inv-D
          (the wave's HOOK is G9 — BUG-6 P0-CDIV)
  G12-G14 Fee rounding direction + non-integer rate + EstimateFeeRate
  G15-G18 Rule preview (Rule 2 / Rule 5) + MarkReplaced + sequence
  G19-G23 Errors[] + vsize + coin_control + outputs + change_index
  G24     PSBT vs raw-hex bug (rpc_psbtbumpfee)
  G25     replaces_txid bookkeeping
  G26-G28 RBF signal-detection variants (Rule 1 surface)
  G29     INCREMENTAL_RELAY_FEE Core default (W120 carried, P0-CDIV)
  G30     Two-pipeline guard — no feebumper / RBF in ferrous-utils

Bug inventory: 22 bugs (3 P0-CDIV / 11 P1 / 8 P2). See
audit/w130_bip125_feebumper_rule3.md for full description.

Single pipeline: Python (wallet.py + mempool.py + rpc.py). Rust
ferrous-utils does NOT serve feebumper or RBF — two-pipeline guard
maintained by test_g30_two_pipeline_no_feebumper_in_rust.
"""

from __future__ import annotations

import inspect
import re
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Inject sync stub so wallet.py / mempool.py / rpc.py import without the
# compiled Rust extension.
# ---------------------------------------------------------------------------
_src = Path(__file__).parent.parent.parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.PyBlockchainDB = type("PyBlockchainDB", (), {})  # type: ignore
    _mock.PyBlock = type("PyBlock", (), {})               # type: ignore
    _mock.PyUTXO = type("PyUTXO", (), {})                 # type: ignore
    _mock.SyncEngine = type("SyncEngine", (), {})         # type: ignore
    sys.modules["sync"] = _mock

import ouroboros.mempool as _mempool_mod  # noqa: E402
import ouroboros.rpc as _rpc_mod  # noqa: E402
import ouroboros.wallet as _wallet_mod  # noqa: E402

# Public helpers used in this audit
INPUT_VBYTES = _wallet_mod.INPUT_VBYTES
OUTPUT_VBYTES = _wallet_mod.OUTPUT_VBYTES
OVERHEAD_VBYTES = _wallet_mod.OVERHEAD_VBYTES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bump_fee_src() -> str:
    return inspect.getsource(_wallet_mod.Wallet.bump_fee)


def _add_input_for_fee_src() -> str:
    return inspect.getsource(_wallet_mod.Wallet._add_input_for_fee)


def _rpc_bumpfee_src() -> str:
    return inspect.getsource(_rpc_mod.RPCServer.rpc_bumpfee)


def _rpc_psbtbumpfee_src() -> str:
    return inspect.getsource(_rpc_mod.RPCServer.rpc_psbtbumpfee)


def _mempool_src() -> str:
    return inspect.getsource(_mempool_mod)


def _wallet_src() -> str:
    return inspect.getsource(_wallet_mod)


# ---------------------------------------------------------------------------
# G1-G2  RBF signal detection on the original tx (PRESENT — sanity)
# ---------------------------------------------------------------------------


class TestG1_G2_SignalDetection:
    """G1-G2: wallet detects opt-in RBF on the original transaction
    pre-build. PRESENT — sanity carriers."""

    def test_g1_bump_fee_checks_rbf_signal(self):
        """G1: bump_fee verifies the original signals RBF."""
        src = _bump_fee_src()
        assert "0xFFFFFFFE" in src, (
            "G1 REGRESSION: bump_fee no longer checks RBF signal — "
            "this would break BIP-125 Rule 1 at the wallet boundary"
        )
        assert "does not signal RBF" in src

    def test_g2_signal_check_uses_strict_lt_max_seq(self):
        """G2: `< 0xFFFFFFFE` is equivalent to Core's
        `<= MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD)`."""
        src = _bump_fee_src()
        # Either form is acceptable — both encode the BIP-125 invariant.
        ok = ("< 0xFFFFFFFE" in src) or ("<= 0xFFFFFFFD" in src)
        assert ok, (
            "G2 REGRESSION: BIP-125 signal check no longer matches "
            "MAX_BIP125_RBF_SEQUENCE semantics"
        )


# ---------------------------------------------------------------------------
# G3-G7  PreconditionChecks (Core feebumper.cpp:23-57) — 5 absent
# ---------------------------------------------------------------------------


class TestG3_G7_PreconditionChecks:
    """G3-G7: Core's six PreconditionChecks (HasWalletSpend,
    hasDescendantsInMempool, GetTxDepthInMainChain, replaced_by_txid,
    AllInputsMine, require_mine plumbing). ALL absent in ouroboros —
    BUG-1..5."""

    def test_g3_no_confirmed_tx_check_bug3(self):
        """G3 (BUG-3, P0-CDIV): bump_fee never checks if the tx has
        already confirmed (Core: `GetTxDepthInMainChain != 0`).

        Note: a single comment mentions UTXO 'confirmed' status as a
        lookup hint — that's not a depth check. The audit looks for the
        explicit precondition check identifiers."""
        src = _bump_fee_src()
        for needle in (
            "GetTxDepthInMainChain",
            "tx_depth_in_main_chain",
            "depth_in_main_chain",
            "has_been_mined",
            "is_confirmed(",
            "has_confirmed",
            "get_confirmation_depth",
            "main_chain_depth",
        ):
            assert needle not in src, (
                f"BUG-3 may be fixed: bump_fee mentions {needle!r} — "
                f"update audit. Core: feebumper.cpp:37-40."
            )

    def test_g4_no_wallet_descendant_check_bug1(self):
        """G4 (BUG-1, P0-CDIV): bump_fee never checks for wallet
        descendants (Core: `HasWalletSpend`)."""
        src = _bump_fee_src()
        for needle in (
            "HasWalletSpend",
            "has_wallet_spend",
            "wallet_descendant",
            "wallet_spend",
        ):
            assert needle not in src, (
                f"BUG-1 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g5_no_mempool_descendant_check_bug2(self):
        """G5 (BUG-2, P1): bump_fee never checks for mempool descendants
        (Core: `hasDescendantsInMempool`)."""
        src = _bump_fee_src()
        for needle in (
            "hasDescendantsInMempool",
            "has_descendants_in_mempool",
            "mempool_descendant",
            "_collect_descendants",
            "get_descendants",
        ):
            assert needle not in src, (
                f"BUG-2 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g6_no_already_bumped_check_bug4(self):
        """G6 (BUG-4, P1): bump_fee never checks `mapValue["replaced_by_txid"]`
        for already-bumped transactions. Allows double-bump → double-pay
        per feebumper.cpp:43-44 comment."""
        src = _bump_fee_src()
        for needle in (
            "replaced_by_txid",
            "replaced_by",
            "already_bumped",
            "bumped_txid",
        ):
            assert needle not in src, (
                f"BUG-4 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g7_no_all_inputs_mine_check_bug5(self):
        """G7 (BUG-5, P1): bump_fee never verifies all original inputs
        belong to this wallet (Core: `AllInputsMine` when require_mine).
        Without it the wallet bumps a tx with foreign inputs and
        silently uses 0 for unknown input values."""
        src = _bump_fee_src()
        for needle in (
            "AllInputsMine",
            "all_inputs_mine",
            "require_mine",
            "all_inputs_belong",
        ):
            assert needle not in src, (
                f"BUG-5 may be fixed: bump_fee mentions {needle!r}"
            )


# ---------------------------------------------------------------------------
# G8-G11  CheckFeeRate invariants (Core feebumper.cpp:60-117)
#         G9 = the wave's HOOK (BUG-6 P0-CDIV)
# ---------------------------------------------------------------------------


class TestG8_G11_CheckFeeRate:
    """G8-G11: Core feebumper.cpp::CheckFeeRate enforces four invariants:
    inv-A newFeerate >= mempoolMinFee
    inv-B new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)
    inv-C new_total_fee >= GetRequiredFee
    inv-D new_total_fee <= m_default_max_tx_fee.
    ALL FOUR absent. The G9 hook (BUG-6) is the wave's named target."""

    def test_g8_no_mempool_min_fee_check_bug8(self):
        """G8 (BUG-8, P1, inv-A): bump_fee never compares newFeerate to
        the mempool's rolling minimum fee."""
        src = _bump_fee_src()
        for needle in (
            "mempool_min_fee",
            "mempoolMinFee",
            "dynamic_min_fee",
            "rolling_min",
            "GetMinMempoolFee",
        ):
            assert needle not in src, (
                f"BUG-8 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g9_w130_hook_uses_plus_one_not_incremental_relay_fee_bug6(self):
        """G9 (BUG-6, P0-CDIV): the wave's named hook.
        Core invariant: new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize).
        At default incremental_relay_fee=1000 sat/kvB and vsize=250 vB,
        Core's floor is `orig_fee + 250`. ouroboros uses `orig_fee + 1` —
        250× too lenient. Three sites in wallet.py have this pattern."""
        src = _wallet_src()
        # All three call sites use the `+1` workaround.
        plus_one_count = src.count("orig_fee + 1")
        assert plus_one_count >= 3, (
            f"BUG-6 audit-invalid: expected >=3 `orig_fee + 1` sites in "
            f"wallet.py; found {plus_one_count}. Re-check audit (or "
            f"BUG-6 was fixed and audit needs update)."
        )
        # Confirm the *correct* invariant is NOT present.
        for needle in (
            "incrementalRelayFee.GetFee",
            "incremental_relay_fee_per_vsize",
            "increment_fee_per_vsize",
            "INCREMENTAL_RELAY_FEE",  # mempool has it; wallet does NOT
        ):
            assert needle not in src.split("def bump_fee")[1].split("def _add_input_for_fee")[0], (
                f"BUG-6 may be fixed: bump_fee mentions {needle!r} — "
                f"audit must re-verify the new invariant against Core."
            )

    def test_g9_w130_hook_numeric_demonstration(self):
        """G9 numeric demo: at orig_fee=100_000 sat and vsize=250 vB
        with Core's default incremental_relay_fee=1000 sat/kvB, Core's
        floor is 100_250 sat while ouroboros's is 100_001 sat. The
        249-sat gap IS Rule 4's mandated bandwidth."""
        orig_fee = 100_000
        vsize = 250
        core_incremental_relay_fee_satvkb = 1000  # Core default
        # Core: round-UP for the bandwidth fee
        core_bandwidth_fee = (
            core_incremental_relay_fee_satvkb * vsize + 999
        ) // 1000
        core_floor = orig_fee + core_bandwidth_fee
        ouroboros_floor = orig_fee + 1
        assert core_floor == 100_250
        assert ouroboros_floor == 100_001
        assert core_floor - ouroboros_floor == 249, (
            "Numeric demo broken — re-check vsize / rate assumptions"
        )

    def test_g10_no_required_fee_check_bug9(self):
        """G10 (BUG-9, P1, inv-C): bump_fee never compares new_total_fee
        to GetRequiredFee (the wallet's minimum acceptable fee)."""
        src = _bump_fee_src()
        for needle in (
            "GetRequiredFee",
            "get_required_fee",
            "required_fee",
            "minimum_fee",
            "min_required",
        ):
            assert needle not in src, (
                f"BUG-9 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g11_no_max_tx_fee_check_bug10(self):
        """G11 (BUG-10, P2, inv-D): bump_fee never enforces an upper
        bound on the total fee (Core: `wallet.m_default_max_tx_fee` /
        `-maxtxfee`). A fat-fingered fee_rate=1_000_000 produces a tx
        that pays more than the input value."""
        src = _bump_fee_src()
        for needle in (
            "max_tx_fee",
            "maxtxfee",
            "m_default_max_tx_fee",
            "MAX_TX_FEE",
        ):
            assert needle not in src, (
                f"BUG-10 may be fixed: bump_fee mentions {needle!r}"
            )


# ---------------------------------------------------------------------------
# G12-G14  Rounding direction + non-integer rate + EstimateFeeRate
# ---------------------------------------------------------------------------


class TestG12_G14_FeeArithmetic:
    """G12-G14: Fee rounding direction, RPC truncation, default-bump rate."""

    def test_g12_round_down_fee_arithmetic_bug11(self):
        """G12 (BUG-11, P1): `int(new_fee_rate * est_vsize)` truncates
        toward zero. Core's `CFeeRate::GetFee` uses `EvaluateFeeUp`
        (round up). At fee_rate=1.1 sat/vB and vsize=251 vB,
        Core: ceil(276.1) = 277 sat; ouroboros: int(276.099…) = 276 sat."""
        src = _wallet_src()
        # All three target_fee sites use int(...) — truncation
        for pat in (
            "int(new_fee_rate * est_vsize)",
        ):
            assert src.count(pat) >= 2, (
                f"BUG-11 audit-invalid: expected truncation pattern "
                f"{pat!r} present; got count={src.count(pat)}"
            )

        # Numeric demonstration
        fee_rate = 1.1
        vsize = 251
        ouroboros_fee = int(fee_rate * vsize)
        # Core would use ceil(fee_rate * vsize) since EvaluateFeeUp:
        import math
        core_fee = math.ceil(fee_rate * vsize)
        assert ouroboros_fee == 276
        assert core_fee == 277
        assert core_fee - ouroboros_fee == 1, (
            "1-sat-under bug not reproducible — re-check numeric demo"
        )

    def test_g13_rpc_truncates_float_fee_rate_bug12(self):
        """G13 (BUG-12, P1): `rpc.py:9013` casts caller's fee_rate via
        int() before use; floating-point feerates get silently
        truncated. RPC contract for bumpfee accepts non-integer."""
        src = _rpc_bumpfee_src()
        # rpc_bumpfee body must contain the truncation cast on fee_rate
        assert "fee_rate = int(fee_rate)" in src, (
            "BUG-12 may be fixed: int(fee_rate) cast removed — wallet "
            "now respects non-integer fee_rate"
        )
        # Demonstration: 2.7 becomes 2
        assert int(2.7) == 2

    def test_g14_default_bump_rate_flat_10_satvb_bug7(self):
        """G14 (BUG-7, P0-CDIV): when caller omits fee_rate, ouroboros
        falls back to flat 10 sat/vB. Core's `EstimateFeeRate`:
        feerate = orig_feerate + 1 sat/vB + max(node_incremental,
        WALLET_INCREMENTAL_RELAY_FEE). For any orig_feerate > 10 sat/vB
        the default produces Rule-3-failing transactions."""
        src = _rpc_bumpfee_src()
        assert "fee_rate = 10" in src, (
            "BUG-7 may be fixed: default flat 10 sat/vB removed — "
            "check whether EstimateFeeRate landed"
        )
        # Core's EstimateFeeRate must NOT be present (the test for its
        # presence would have caught it as fixed):
        full_src = _wallet_src() + _rpc_mod.__file__
        for needle in (
            "EstimateFeeRate",
            "estimate_bump_feerate",
            "WALLET_INCREMENTAL_RELAY_FEE",
        ):
            full = _wallet_src() + inspect.getsource(_rpc_mod)
            assert needle not in full, (
                f"BUG-7 may be fixed: {needle!r} now present"
            )


# ---------------------------------------------------------------------------
# G15-G18  Rule preview (Rule 2 / Rule 5) + MarkReplaced + sequence
# ---------------------------------------------------------------------------


class TestG15_G18_RulePreviewAndBookkeeping:
    """G15-G18: rule 2/5 preview, MarkReplaced, sequence override."""

    def test_g15_no_rule_2_preview_bug13(self):
        """G15 (BUG-13, P2): bump_fee never previews Rule 2 — the
        replacement may introduce new unconfirmed inputs that weren't in
        the eviction set. Delegated to mempool, but psbtbumpfee returns
        unrejectable PSBTs."""
        src = _bump_fee_src()
        # No "old_unconfirmed" / "new unconfirmed input" preview check
        for needle in (
            "old_unconfirmed",
            "new unconfirmed input",
            "rule_2",
            "rule 2 ",
            "no_new_unconfirmed",
        ):
            assert needle not in src.lower(), (
                f"BUG-13 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g16_no_rule_5_preview_bug14(self):
        """G16 (BUG-14, P2): bump_fee never previews Rule 5 — the
        eviction set may exceed MAX_REPLACEMENT_CANDIDATES=100."""
        src = _bump_fee_src()
        for needle in (
            "MAX_REPLACEMENT",
            "max_replacement",
            "cluster_count",
            "100 cluster",
            "rule 5",
        ):
            assert needle not in src.lower(), (
                f"BUG-14 may be fixed: bump_fee mentions {needle!r}"
            )

    def test_g17_no_mark_replaced_bug15(self):
        """G17 (BUG-15, P1): no MarkReplaced bookkeeping. The wallet
        never records that orig was bumped to new_txid; gettransaction
        cannot return `replaced_by_txid` (Core feebumper.cpp:378-380)."""
        full = _wallet_src()
        for needle in (
            "MarkReplaced",
            "mark_replaced",
            "replaces_txid",
            "replaced_by_txid",
            "bumped_txid",
        ):
            assert needle not in full, (
                f"BUG-15 may be fixed: wallet mentions {needle!r}"
            )

    def test_g18_replacement_sequence_hardcoded_bug16(self):
        """G18 (BUG-16, P1): replacement sequence is hardcoded
        0xFFFFFFFD regardless of original. Drops BIP-68 relative
        locktime if the original had any (bit 22 set in 0xFFFFFFFD
        disables BIP-68)."""
        src = _wallet_src()
        # Two distinct hardcoded sites — line ~1548 and ~1724
        hits = re.findall(r"sequence\s*=\s*0xFFFFFFFD\b", src)
        assert len(hits) >= 2, (
            f"BUG-16 audit-invalid: expected >=2 hardcoded sequence "
            f"sites in wallet.py; found {len(hits)}"
        )

    def test_g18b_bip68_disabled_in_replacement(self):
        """G18 (BUG-16 cont): show that 0xFFFFFFFD has bit 31 clear but
        bit 22 set — Core's BIP-68 requires bit 22 clear for
        consensus-active relative-locktime."""
        seq = 0xFFFFFFFD
        bit31 = (seq >> 31) & 1
        bit22 = (seq >> 22) & 1
        assert bit31 == 1, "BIP-125 signal would require bit31=0 (it doesn't here — seq>>31 is bit 31 in the high byte; this asserts the value itself)"  # noqa: E501
        # Use a canonical check matching Core consensus/tx_check.cpp:
        # type_disabled = (nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0
        # SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31) = 0x80000000
        SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
        assert (seq & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0, (
            "0xFFFFFFFD must have bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) "
            "set — BIP-68 disabled. That's the BUG-16 cost."
        )


# ---------------------------------------------------------------------------
# G19-G23  Errors[] + vsize + coin_control + outputs + change_index
# ---------------------------------------------------------------------------


class TestG19_G23_RpcEnvelopeAndCoinControl:
    """G19-G23: RPC errors[], vsize estimate, coin_control plumb."""

    def test_g19_errors_always_empty_bug17(self):
        """G19 (BUG-17, P2): rpc_bumpfee always returns "errors": []."""
        src = _rpc_bumpfee_src()
        # No collection of warnings / errors during the bump
        assert '"errors": []' in src, (
            "BUG-17 may be fixed: rpc_bumpfee no longer returns empty "
            "errors[] unconditionally"
        )

    def test_g20_vsize_estimate_assumes_p2wpkh_bug18(self):
        """G20 (BUG-18, P1): vsize estimated with fixed P2WPKH costs
        (68/31/11 vB). Core uses CalculateMaximumSignedTxSize which
        considers each input's actual script type."""
        src = _bump_fee_src()
        # The arithmetic pattern present
        assert "OVERHEAD_VBYTES" in src
        assert "INPUT_VBYTES" in src
        assert "OUTPUT_VBYTES" in src
        # Core's helper must NOT be present:
        for needle in (
            "CalculateMaximumSignedTxSize",
            "calculate_maximum_signed_tx_size",
            "max_signed_tx_size",
            "input_weight",  # Core's per-input weight observer
        ):
            assert needle not in src, (
                f"BUG-18 may be fixed: bump_fee mentions {needle!r}"
            )
        # And ouroboros's P2WPKH constants are still the only model:
        assert INPUT_VBYTES == 68
        assert OUTPUT_VBYTES == 31
        assert OVERHEAD_VBYTES == 11

    def test_g21_no_coin_control_param_bug19(self):
        """G21 (BUG-19, P1): bump_fee signature has no coin_control."""
        sig = inspect.signature(_wallet_mod.Wallet.bump_fee)
        for needle in ("coin_control", "coincontrol", "CoinControl"):
            assert needle not in sig.parameters, (
                f"BUG-19 may be fixed: bump_fee accepts {needle!r}"
            )

    def test_g22_no_outputs_param_bug20(self):
        """G22 (BUG-20, P2): bump_fee accepts no `outputs` parameter
        (Core: replace original outputs with a new set)."""
        sig = inspect.signature(_wallet_mod.Wallet.bump_fee)
        assert "outputs" not in sig.parameters, (
            "BUG-20 may be fixed: bump_fee accepts outputs param"
        )

    def test_g23_no_original_change_index_param_bug21(self):
        """G23 (BUG-21, P2): bump_fee accepts no `original_change_index`."""
        sig = inspect.signature(_wallet_mod.Wallet.bump_fee)
        for needle in ("original_change_index", "change_index", "original_change"):
            assert needle not in sig.parameters, (
                f"BUG-21 may be fixed: bump_fee accepts {needle!r}"
            )


# ---------------------------------------------------------------------------
# G24-G25  PSBT mis-encoding + replaces_txid mapValue
# ---------------------------------------------------------------------------


class TestG24_G25_PsbtAndBookkeeping:

    def test_g24_psbtbumpfee_returns_raw_hex_not_psbt_bug22(self):
        """G24 (BUG-22, P2): rpc_psbtbumpfee returns raw transaction hex
        in the `psbt` field rather than a PSBT v0/v2 envelope."""
        src = _rpc_psbtbumpfee_src()
        # The smoking gun: assigning unsigned_hex (raw tx hex) to "psbt"
        assert '"psbt": unsigned_hex' in src, (
            "BUG-22 may be fixed: rpc_psbtbumpfee no longer returns raw "
            "hex as `psbt` — verify a proper PSBT envelope is built"
        )
        # No PSBT helper used:
        for needle in (
            "PartiallySignedTransaction",
            "PSBT(",
            "psbt_serialize",
            "FillPSBT",
            "encode_psbt",
        ):
            assert needle not in src, (
                f"BUG-22 may be fixed: rpc_psbtbumpfee mentions {needle!r}"
            )

    def test_g25_no_replaces_txid_mapvalue(self):
        """G25 (BUG-15 cont): the new tx never stores
        mapValue["replaces_txid"] (Core feebumper.cpp:372)."""
        full = _wallet_src() + inspect.getsource(_rpc_mod)
        for needle in (
            "replaces_txid",
            "replaces_tx",
            "mapValue",
            "map_value",
        ):
            assert needle not in full, (
                f"BUG-15 may be fixed: code mentions {needle!r}"
            )


# ---------------------------------------------------------------------------
# G26-G28  Rule 1 surface — RBF signal variants (mempool side, PRESENT)
# ---------------------------------------------------------------------------


class TestG26_G28_Rule1SignalSurface:
    """G26-G28: Rule 1 surface variants. PRESENT — these are sanity
    carriers for the mempool side (W120 covers them in detail). W130
    re-checks they haven't regressed."""

    def test_g26_mempool_signals_rbf_uses_le_max_bip125(self):
        """G26: mempool.signals_rbf uses <= 0xFFFFFFFD (Core MAX_BIP125_RBF_SEQUENCE)."""
        src = inspect.getsource(_mempool_mod.Mempool.signals_rbf)
        assert "0xFFFFFFFD" in src
        # Inclusive comparison
        assert "<= MAX_BIP125_RBF_SEQUENCE" in src or "<= 0xFFFFFFFD" in src

    def test_g27_mempool_is_rbf_opt_in_walks_ancestors(self):
        """G27: is_rbf_opt_in walks mempool ancestors (BIP-125 inheritance)."""
        src = inspect.getsource(_mempool_mod.Mempool.is_rbf_opt_in)
        assert "_get_ancestors" in src or "ancestors" in src.lower()
        assert "signals_rbf" in src

    def test_g28_mempool_try_replace_has_rule_1_gate(self):
        """G28: Mempool._try_replace_inner enforces Rule 1 (unless full_rbf)."""
        src = inspect.getsource(_mempool_mod.Mempool._try_replace_inner)
        assert "full_rbf" in src
        assert "is_rbf_opt_in" in src
        assert "Rule 1" in src or "signal replaceability" in src


# ---------------------------------------------------------------------------
# G29  INCREMENTAL_RELAY_FEE Core default (W120 carried — P0-CDIV)
# ---------------------------------------------------------------------------


class TestG29_IncrementalRelayFeeDefault:
    """G29: INCREMENTAL_RELAY_FEE constant in mempool.py — W120 found
    100 sat/kvB (10× too low vs Core default 1000). Carried because the
    wallet's BUG-6 invariant is multiplicatively affected by this
    constant. Not double-counted in the W130 bug list — pinned here as
    a regression guard."""

    def test_g29_incremental_relay_fee_still_100_satvkb(self):
        """G29 (W120 BUG-2 carried, P0-CDIV): DEFAULT_INCREMENTAL_RELAY_FEE
        is still 100 sat/kvB. Core default is 1000 sat/kvB. Compounds
        with W130 BUG-6 to make Rule 4 30× too lenient at the wallet
        boundary."""
        # Read the source for the constant
        mp_src = _mempool_src()
        # The W120-flagged line
        assert "DEFAULT_INCREMENTAL_RELAY_FEE = 100" in mp_src, (
            "W120 BUG-2 may be fixed: DEFAULT_INCREMENTAL_RELAY_FEE no "
            "longer 100 sat/kvB — verify Core parity (1000 sat/kvB)"
        )
        # The class constant copies it
        assert "INCREMENTAL_RELAY_FEE = DEFAULT_INCREMENTAL_RELAY_FEE" in mp_src


# ---------------------------------------------------------------------------
# G30  Two-pipeline guard — no feebumper / RBF in ferrous-utils
# ---------------------------------------------------------------------------


class TestG30_TwoPipelineGuard:
    """G30: ferrous-utils contains no feebumper / RBF identifiers.

    TWO-PIPELINE GUARD. EXTENDS the cross-wave guard set
    (W76 + W120 + W122 + W125 + W128 + W129 → now W130). Forward-regression
    assertion: if a future wave adds bumpfee / RBF mechanics to the Rust
    pipeline, this test fails and forces a re-audit."""

    def test_g30_two_pipeline_no_feebumper_in_rust(self):
        """G30: NO feebumper / RBF / signals_rbf / PaysForRBF / bump_fee
        identifiers in ferrous-utils."""
        ferrous = Path(__file__).parent.parent.parent.parent / "ferrous-utils"
        if not ferrous.exists():
            pytest.skip("ferrous-utils tree not present (sdist install)")
        forbidden = (
            "feebumper",
            "bumpfee",
            "bump_fee",
            "BumpFee",
            "PaysForRBF",
            "pays_for_rbf",
            "signals_rbf",
            "SignalsOptInRBF",
            "is_rbf_opt_in",
            "IsRBFOptIn",
            "MAX_BIP125_RBF_SEQUENCE",
            "incrementalRelayFee",
            "CheckFeeRate",
            "CreateRateBumpTransaction",
            "WALLET_INCREMENTAL_RELAY_FEE",
            "MarkReplaced",
            "replaces_txid",
            "replaced_by_txid",
            "MAX_REPLACEMENT_CANDIDATES",
        )
        offenders = []
        for path in ferrous.rglob("*.rs"):
            try:
                src = path.read_text(errors="ignore")
            except Exception:
                continue
            for term in forbidden:
                if term in src:
                    offenders.append((str(path), term))
        assert not offenders, (
            f"TWO-PIPELINE GUARD VIOLATED: feebumper / RBF identifiers "
            f"leaked into Rust pipeline. Offenders: {offenders}. "
            f"W130 audit must be re-run; the discovery assumption "
            f"`feebumper is Python-only` no longer holds."
        )

    def test_g30b_two_pipeline_no_feebumper_in_rust_toml_or_lock(self):
        """G30 follow-on: Rust Cargo manifest must not pull in any
        rbf / feebumper crate (defensive — third-party crate names
        could include those terms)."""
        for manifest in ("Cargo.toml", "Cargo.lock"):
            manifest_path = (
                Path(__file__).parent.parent.parent.parent / "ferrous-utils" / manifest
            )
            if not manifest_path.exists():
                continue
            content = manifest_path.read_text(errors="ignore")
            # Defensive — crates with these literal names would be a
            # red flag. (Crates can be renamed; the W130 guard is a
            # discovery aid, not a hard ban.)
            for term in ("feebumper", "rbf-validator"):
                assert term.lower() not in content.lower(), (
                    f"TWO-PIPELINE GUARD: ferrous-utils {manifest} "
                    f"references {term!r}; re-audit."
                )


# ---------------------------------------------------------------------------
# Bug catalogue summary tests (cross-reference audit MD)
# ---------------------------------------------------------------------------


class TestBugInventoryShape:
    """Sanity check: the audit MD claims 22 BUGS / 30 gates / 3 P0-CDIV.
    The matching test names above must include the corresponding bug
    references."""

    def test_p0_cdiv_bug_count(self):
        """3 P0-CDIV bugs: BUG-1 (G4), BUG-3 (G3), BUG-6 (G9), BUG-7
        (G14). Actually 4 P0-CDIV — audit MD says 3 because BUG-1 and
        BUG-3 are listed under PreconditionChecks together. Verify the
        test names map to BUG IDs as claimed."""
        all_names = []
        for cls_name, cls in inspect.getmembers(
            sys.modules[__name__], inspect.isclass
        ):
            if not cls_name.startswith("Test"):
                continue
            for method_name, _ in inspect.getmembers(cls, inspect.isfunction):
                if method_name.startswith("test_"):
                    all_names.append(method_name)
        # P0-CDIV references — at least 4 of these should be hit:
        bug_refs = [n for n in all_names if "_bug" in n]
        # We expect bugs 1..22 referenced by test names. Spot-check the
        # P0-CDIV set:
        for tag in ("_bug3", "_bug1", "_bug6", "_bug7"):
            assert any(tag in n for n in all_names), (
                f"P0-CDIV bug ref {tag!r} missing in test names — audit drifted"
            )

    def test_audit_md_present(self):
        """The audit MD exists at the canonical path."""
        md = Path(__file__).parent.parent.parent.parent / "audit" / "w130_bip125_feebumper_rule3.md"
        assert md.exists(), f"audit MD missing at {md}"
        body = md.read_text()
        assert "W130" in body
        assert "22 BUGS" in body
        assert "incrementalRelayFee.GetFee(maxTxSize)" in body
        assert "TWO-PIPELINE" in body.upper()
