"""
W129 Coin Selection re-audit — ouroboros (Python pipeline only; no Rust pipeline).

Discovery-only audit (NO production code changes). Re-audits the W113
subsystem with three new dimensions: CoinGrinder + SFFO, cost-of-change
formula precision, and CoinControl / TRUC plumbing.

Gates: G1-G5  Algorithm presence + CoinGrinder + auto-activation
       G6-G8  OutputGroup + MAX_ENTRIES + avoid_partial_spends
       G9-G11 CoinEligibilityFilter cascade + long_chain guard
       G12-G14 BnB parity (waste / tries counter / clone+is_feerate_high)
       G15-G17 Knapsack parity (two-pass / lowest_larger / SFFO)
       G18-G20 SRD parity (change_fee headroom / max-weight / pos group)
       G21-G23 Change output (P0 privacy: address + position; dust)
       G24-G26 Waste metric (change_cost decompose / SFFO / min_viable_change)
       G27-G28 CoinControl + SelectionResult comparator
       G29-G30 Two-pipeline guard + W118 BUG-3 CSPRNG fix

Bug inventory: 20 bugs (2 P0-PRIVACY / 8 P1 / 10 P2). See
audit/w129_coin_selection.md for full description.

Single pipeline: Python wallet.py. Rust ferrous-utils does NOT serve
coin selection — two-pipeline guard maintained by
test_two_pipeline_no_coin_selection_in_rust.
"""

from __future__ import annotations

import inspect
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Inject sync stub so wallet.py imports without the compiled Rust extension.
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

from ouroboros.wallet import (  # noqa: E402
    BNB_MAX_TRIES,
    COST_OF_CHANGE_VBYTES,
    DEFAULT_LONG_TERM_FEE_RATE,
    INPUT_VBYTES,
    OUTPUT_VBYTES,
    _CSPRNG,
    _selection_waste,
    select_coins,
    select_coins_bnb,
    select_coins_knapsack,
    select_coins_srd,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_utxo(value: int, txid: str = "aa" * 32, vout: int = 0) -> dict:
    return {"txid": txid, "vout": vout, "value": value}


def _make_utxos(values: list[int]) -> list[dict]:
    return [
        {"txid": f"{i:064x}", "vout": 0, "value": v}
        for i, v in enumerate(values)
    ]


def _wallet_src() -> str:
    import ouroboros.wallet as w
    return inspect.getsource(w)


# ---------------------------------------------------------------------------
# G1-G5  Algorithm presence + CoinGrinder + auto-activation
# ---------------------------------------------------------------------------


class TestG1_G5_AlgorithmPresence:
    """G1-G5: Verify BnB/Knapsack/SRD callable; CG absent (BUG-1); no
    auto-activation rule (BUG-2)."""

    def test_g1_bnb_callable(self):
        """G1: BnB present."""
        utxos = _make_utxos([100_000])
        result = select_coins_bnb(utxos, 50_000, 1.0)
        assert result is None or isinstance(result, list)

    def test_g2_knapsack_callable(self):
        """G2: Knapsack present."""
        utxos = _make_utxos([100_000])
        result = select_coins_knapsack(utxos, 50_000, 1.0)
        assert result is None or isinstance(result, list)

    def test_g3_srd_callable(self):
        """G3: SRD present."""
        utxos = _make_utxos([100_000])
        result = select_coins_srd(utxos, 50_000, 1.0)
        assert result is None or isinstance(result, list)

    def test_g4_coingrinder_absent_bug1(self):
        """G4 (BUG-1): CoinGrinder absent — no select_coins_coingrinder."""
        import ouroboros.wallet as w
        assert not hasattr(w, "select_coins_coingrinder"), (
            "BUG-1 may be fixed: CoinGrinder found — update audit"
        )
        assert not hasattr(w, "coin_grinder"), (
            "BUG-1 may be fixed: coin_grinder found — update audit"
        )
        assert not hasattr(w, "CoinGrinder"), (
            "BUG-1 may be fixed: CoinGrinder class found — update audit"
        )

    def test_g5_cg_autoactivation_rule_absent_bug2(self):
        """G5 (BUG-2): No auto-activation rule
        (effective_feerate > 3*long_term_feerate)."""
        src = _wallet_src()
        # Core: if (coin_selection_params.m_effective_feerate >
        #         CFeeRate{3 * coin_selection_params.m_long_term_feerate})
        # Search for any '3 *' bucketing rule on fee_rate
        assert "3 * long_term_fee_rate" not in src, (
            "BUG-2 appears fixed: 3* gating rule found — update audit"
        )
        assert "3 * fee_rate" not in src, (
            "BUG-2 appears fixed: 3* gating rule found — update audit"
        )
        # Confirm select_coins doesn't branch on fee_rate vs long_term ratio
        sig = inspect.signature(select_coins)
        # No 'force_cg' or 'use_cg' kwarg either
        assert "force_cg" not in sig.parameters
        assert "use_cg" not in sig.parameters


# ---------------------------------------------------------------------------
# G6-G8  OutputGroup + MAX_ENTRIES + avoid_partial_spends
# ---------------------------------------------------------------------------


class TestG6_G8_OutputGroup:
    """G6-G8: OutputGroup abstraction. BUG-3/4/5 split out of W113 BUG-1."""

    def test_g6_output_group_class_absent_bug3(self):
        """G6 (BUG-3): No OutputGroup class."""
        import ouroboros.wallet as w
        assert not hasattr(w, "OutputGroup"), (
            "BUG-3 may be fixed: OutputGroup class found — update audit"
        )

    def test_g7_max_entries_cap_absent_bug4(self):
        """G7 (BUG-4): OUTPUT_GROUP_MAX_ENTRIES=100 constant absent."""
        import ouroboros.wallet as w
        assert not hasattr(w, "OUTPUT_GROUP_MAX_ENTRIES"), (
            "BUG-4 may be fixed: OUTPUT_GROUP_MAX_ENTRIES found — update audit"
        )
        # Magic 100 should not appear with grouping comment either
        src = _wallet_src()
        assert "OUTPUT_GROUP_MAX_ENTRIES" not in src

    def test_g8_avoid_partial_spends_absent_bug5(self):
        """G8 (BUG-5): avoid_partial_spends not in select_coins signature."""
        sig = inspect.signature(select_coins)
        assert "avoid_partial_spends" not in sig.parameters, (
            "BUG-5 may be fixed: avoid_partial_spends param found — update audit"
        )
        assert "m_avoid_partial_spends" not in sig.parameters
        import ouroboros.wallet as w
        assert not hasattr(w, "avoid_partial_spend"), (
            "BUG-5 may be fixed: helper found — update audit"
        )


# ---------------------------------------------------------------------------
# G9-G11  CoinEligibilityFilter cascade + long-chain guard
# ---------------------------------------------------------------------------


class TestG9_G11_EligibilityFilter:
    """G9-G11: Outer confirmation-tier cascade. BUG-6/7 new in W129."""

    def test_g9_eligibility_filter_cascade_absent_bug6(self):
        """G9 (BUG-6): No CoinEligibilityFilter outer loop."""
        import ouroboros.wallet as w
        assert not hasattr(w, "CoinEligibilityFilter"), (
            "BUG-6 may be fixed: CoinEligibilityFilter found — update audit"
        )
        # No (conf_mine, conf_theirs, max_ancestors) tuples in select_coins
        src = inspect.getsource(select_coins)
        assert "conf_mine" not in src
        assert "conf_theirs" not in src
        assert "max_ancestors" not in src

    def test_g10_walletrejectlongchains_guard_absent_bug7(self):
        """G10 (BUG-7): No walletrejectlongchains / long-mempool-cluster guard."""
        import ouroboros.wallet as w
        src = _wallet_src()
        assert "walletrejectlongchains" not in src.lower(), (
            "BUG-7 may be fixed: long-chain guard found — update audit"
        )
        assert "long_mempool_cluster" not in src.lower(), (
            "BUG-7 may be fixed: long-chain guard found — update audit"
        )

    def test_g11_long_term_feerate_constant_default_only(self):
        """G11: DEFAULT_LONG_TERM_FEE_RATE=10 exists but is not read from
        wallet config (m_consolidate_feerate equivalent)."""
        # Constant exists
        assert DEFAULT_LONG_TERM_FEE_RATE == 10.0
        # But there's no consolidate_feerate / m_consolidate equivalent
        import ouroboros.wallet as w
        assert not hasattr(w, "m_consolidate_feerate")
        assert not hasattr(w, "consolidate_feerate")
        # Wallet class shouldn't expose a configurable long-term fee rate
        wallet_class = w.Wallet
        assert not hasattr(wallet_class, "m_consolidate_feerate")


# ---------------------------------------------------------------------------
# G12-G14  BnB parity (waste / tries counter / pruning shortcuts)
# ---------------------------------------------------------------------------


class TestG12_G14_BnB:
    """G12-G14: BnB parity. BUG-8 (excess), BUG-9 (tries), BUG-10+11 (pruning)."""

    def test_g12_bnb_excess_term_missing_bug8(self):
        """G12 (BUG-8): no-change waste omits excess term."""
        fee_rate = 5.0
        long_term = DEFAULT_LONG_TERM_FEE_RATE
        selected = [{"value": 200_000}, {"value": 100_000}]
        waste = _selection_waste(selected, fee_rate, long_term, has_change=False)
        timing_cost = len(selected) * INPUT_VBYTES * (fee_rate - long_term)
        # ouroboros: waste == timing_cost (no excess added)
        assert abs(waste - timing_cost) < 1.0, (
            "BUG-8 may be fixed: waste includes excess term — update audit"
        )

    def test_g13_bnb_tries_counter_semantic_bug9(self):
        """G13 (BUG-9): BnB tries counter increments per backtrack call, not
        per loop iteration. Demonstrate by inspecting source."""
        src = inspect.getsource(select_coins_bnb)
        # Core: for (size_t curr_try=0, ...; curr_try < TOTAL_TRIES; ++curr_try)
        # — one increment per loop iteration.
        # ouroboros: `tries += 1` inside `backtrack(idx)`, before include+exclude
        # — one increment per recursive call (= one per decision node).
        # Verify the recursive shape (semantic differs from Core's iterative DFS).
        assert "def backtrack" in src, (
            "BUG-9 may be fixed: BnB became iterative — update audit"
        )
        assert "tries += 1" in src, (
            "BUG-9 may be fixed: tries counter semantic changed — update audit"
        )

    def test_g13_bnb_max_tries_constant_value(self):
        """G13: BNB_MAX_TRIES=100000 matches Core's TOTAL_TRIES."""
        assert BNB_MAX_TRIES == 100_000

    def test_g14_bnb_clone_pruning_absent_bug10(self):
        """G14 (BUG-10): BnB does not skip excluding a clone of a previously
        excluded UTXO with equal effective value AND equal fee."""
        src = inspect.getsource(select_coins_bnb)
        # Core: `utxo.GetSelectionAmount() != utxo_pool.at(utxo_pool_index-1)
        # .GetSelectionAmount() || utxo.fee != utxo_pool.at(...).fee`
        # ouroboros has no such equality-skip check.
        assert "fee !=" not in src
        assert "clone" not in src.lower(), (
            "BUG-10 may be fixed: clone-pruning found — update audit"
        )

    def test_g14_bnb_is_feerate_high_pruning_absent_bug11(self):
        """G14 (BUG-11): BnB does not perform is_feerate_high waste-
        monotonicity pruning."""
        src = inspect.getsource(select_coins_bnb)
        assert "is_feerate_high" not in src, (
            "BUG-11 may be fixed: is_feerate_high pruning found — update audit"
        )
        # Core also tracks curr_waste vs best_waste during DFS; ouroboros
        # only tracks best_waste in the leaf check.
        assert "curr_waste" not in src


# ---------------------------------------------------------------------------
# G15-G17  Knapsack parity (two-pass / lowest_larger / SFFO)
# ---------------------------------------------------------------------------


class TestG15_G17_Knapsack:
    """G15-G17: Knapsack two-pass + lowest_larger fallback + SFFO short-circuit."""

    def test_g15_knapsack_missing_two_pass_bug12(self):
        """G15 (BUG-12): Knapsack does not implement Core's two-pass-per-rep
        (pass-0 random 50%, pass-1 sweep remaining)."""
        src = inspect.getsource(select_coins_knapsack)
        # Core: `for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)`
        # ouroboros: single pass per iteration; no nested pass loop.
        assert "for nPass" not in src
        assert "nPass" not in src, (
            "BUG-12 may be fixed: two-pass loop found — update audit"
        )
        # The `for _ in range(iterations)` body is single-pass
        assert "for _ in range(iterations):" in src

    def test_g16_knapsack_lowest_larger_fallback_partial_bug13(self):
        """G16 (BUG-13): The `lowest_larger` initial scan exists but the
        Core fallback when stochastic-approx fails is incomplete."""
        src = inspect.getsource(select_coins_knapsack)
        # The initial scan exists ("Check if any single UTXO covers ...")
        assert "ev >= target" in src
        # But there's no Core-style "if no better stochastic match, use
        # lowest_larger" fallback path
        # Core: `if (lowest_larger && ((nBest != nTargetValue && nBest <
        # nTargetValue + change_target) || lowest_larger->GetSelectionAmount()
        # <= nBest)) { result.AddInput(*lowest_larger); }`
        assert "lowest_larger" not in src, (
            "BUG-13 may be fixed: lowest_larger fallback found — update audit"
        )

    def test_g17_knapsack_sffo_short_circuit_absent_bug14(self):
        """G17 (BUG-14): Knapsack does not branch on subtract_fee_outputs;
        always uses effective value (value - input_fee)."""
        sig = inspect.signature(select_coins_knapsack)
        assert "subtract_fee_outputs" not in sig.parameters, (
            "BUG-14 may be fixed: SFFO param found — update audit"
        )
        assert "sffo" not in sig.parameters
        src = inspect.getsource(select_coins_knapsack)
        # Core uses GetSelectionAmount() which returns m_value for SFFO
        assert "GetSelectionAmount" not in src
        # ouroboros always computes effective value:
        assert "u[\"value\"] - input_fee" in src


# ---------------------------------------------------------------------------
# G18-G20  SRD parity (change_fee headroom / max-weight / positive group)
# ---------------------------------------------------------------------------


class TestG18_G20_SRD:
    """G18-G20: SRD parity. BUG-15 (change_fee headroom), BUG-16 (max-weight)."""

    def test_g18_srd_missing_change_fee_headroom_bug15(self):
        """G18 (BUG-15): SRD does not add CHANGE_LOWER + change_fee to
        target. Core line 546: `target_value += CHANGE_LOWER + change_fee`."""
        src = inspect.getsource(select_coins_srd)
        # CHANGE_LOWER = 50000 sat in Core
        assert "CHANGE_LOWER" not in src, (
            "BUG-15 may be fixed: CHANGE_LOWER referenced — update audit"
        )
        assert "50000" not in src and "50_000" not in src, (
            "BUG-15 may be fixed: CHANGE_LOWER value found — update audit"
        )
        # Caller passes change_target already-adjusted, but SRD has no
        # change_fee parameter at all
        sig = inspect.signature(select_coins_srd)
        assert "change_fee" not in sig.parameters

    def test_g19_srd_max_weight_eviction_absent_bug16(self):
        """G19 (BUG-16): SRD does not implement max-weight eviction via
        min-priority queue."""
        src = inspect.getsource(select_coins_srd)
        # Core uses std::priority_queue<MinOutputGroupComparator>
        # ouroboros: plain list + early-return; no eviction loop
        assert "priority_queue" not in src
        assert "max_selection_weight" not in src
        assert "max_weight" not in src
        sig = inspect.signature(select_coins_srd)
        assert "max_selection_weight" not in sig.parameters, (
            "BUG-16 may be fixed: max weight param found — update audit"
        )

    def test_g20_srd_excludes_non_positive_effective_value(self):
        """G20: SRD approximates Core's positive_group by filtering
        value > input_fee."""
        fee_rate = 10.0
        input_fee = int(INPUT_VBYTES * fee_rate)
        dust = {"txid": "dd" * 32, "vout": 0, "value": input_fee - 1}
        good = {"txid": "aa" * 32, "vout": 0, "value": 500_000}
        # SRD on a pool where one is sub-input-fee
        result = select_coins_srd([dust, good], 100_000, fee_rate)
        if result is not None:
            assert dust not in result


# ---------------------------------------------------------------------------
# G21-G23  Change output (P0 PRIVACY: address reuse + position + dust)
# ---------------------------------------------------------------------------


class TestG21_G23_ChangePrivacy:
    """G21-G23: P0-PRIVACY change output handling. BUG-17/18/19."""

    def test_g21_change_address_always_keys_zero_bug17(self):
        """G21 (BUG-17 P0-PRIVACY): send_transaction always uses self.keys[0]
        for change output (massive address-reuse leak)."""
        import ouroboros.wallet as w
        src = inspect.getsource(w.Wallet.send_transaction)
        assert "self.keys[0]" in src, (
            "BUG-17 may be fixed: keys[0] removed from send_transaction"
        )
        # The KeyPool's change pool is NOT consulted
        assert "is_change=True" not in src, (
            "BUG-17 may be fixed: KeyPool change consulted — update audit"
        )
        assert "_change_pool" not in src
        # And get_new_address with the change flag isn't called
        # (it might be called for receive addresses elsewhere)
        change_consultation = ("get_new_address(is_change=True"
                              in src or "get_new_address(True" in src)
        assert not change_consultation, (
            "BUG-17 may be fixed: change KeyPool used — update audit"
        )

    def test_g22_change_position_always_last_bug18(self):
        """G22 (BUG-18 P0-PRIVACY): change is always appended last, not
        randomly positioned."""
        import ouroboros.wallet as w
        src = inspect.getsource(w.Wallet.send_transaction)
        # Core: `change_pos = rng_fast.randrange(txNew.vout.size() + 1)`
        # then `txNew.vout.insert(begin() + change_pos, ...)`
        assert "outputs.append(TxOut(value=change" in src, (
            "BUG-18 may be fixed: change appended differently — update audit"
        )
        assert "outputs.insert(" not in src or "change" not in src, (
            "BUG-18 may be fixed: change inserted at random — update audit"
        )
        assert "randrange" not in src, (
            "BUG-18 may be fixed: randrange found in send_transaction"
        )
        assert "randbelow" not in src

    def test_g23_dust_threshold_hardcoded_bug19(self):
        """G23 (BUG-19): dust threshold hardcoded 546 sat instead of
        GetDustThreshold(spk, discard_feerate)."""
        import ouroboros.wallet as w
        src = inspect.getsource(w.Wallet.send_transaction)
        assert "546" in src, (
            "BUG-19 may be fixed: 546 not in send_transaction — update audit"
        )
        # No GetDustThreshold equivalent
        assert "get_dust_threshold" not in src.lower(), (
            "BUG-19 may be fixed: dust threshold computed dynamically"
        )
        assert "discard_feerate" not in src, (
            "BUG-19 may be fixed: discard_feerate plumbed — update audit"
        )
        # Same for bump_fee:
        bump_src = inspect.getsource(w.Wallet.bump_fee)
        assert "546" in bump_src, (
            "BUG-19 may be fixed in bump_fee — update audit"
        )


# ---------------------------------------------------------------------------
# G24-G26  Waste metric (change_cost decompose / SFFO / min_viable_change)
# ---------------------------------------------------------------------------


class TestG24_G26_WasteMetric:
    """G24-G26: Waste metric. BUG-20 (change_cost formula)."""

    def test_g24_change_cost_formula_collapses_to_single_rate_bug20(self):
        """G24 (BUG-20): change_cost = COST_OF_CHANGE_VBYTES * fee_rate
        (single rate). Core decomposes into:
        change_cost = effective_feerate * change_output_size
                    + discard_feerate * change_spend_size."""
        src = inspect.getsource(_selection_waste)
        # ouroboros: COST_OF_CHANGE_VBYTES * fee_rate (single rate; bug)
        assert "COST_OF_CHANGE_VBYTES * fee_rate" in src, (
            "BUG-20 may be fixed: COST_OF_CHANGE_VBYTES * fee_rate removed"
        )
        # No discard_feerate split:
        assert "discard_feerate" not in src, (
            "BUG-20 may be fixed: discard_feerate plumbed — update audit"
        )
        # Verify numeric impact: at fee_rate=20, long_term=2, the formula
        # over-penalizes change vs Core's mixed-rate formula.
        fee_rate = 20.0
        long_term = 2.0
        selected = [{"value": 100_000}]
        w_change = _selection_waste(selected, fee_rate, long_term, has_change=True)
        w_no_change = _selection_waste(selected, fee_rate, long_term, has_change=False)
        ouroboros_change_cost = w_change - w_no_change
        # ouroboros: 99 * 20 = 1980
        assert abs(ouroboros_change_cost - 99 * fee_rate) < 2.0
        # Core w/ effective=20, discard=3 (Core default):
        # = 20*31 + 3*68 = 620 + 204 = 824 sat
        # ouroboros is 2.4× larger — over-penalty
        core_change_cost_approx = 20 * 31 + 3 * 68  # 824
        assert ouroboros_change_cost > core_change_cost_approx * 2.0

    def test_g25_no_sffo_branch_in_waste(self):
        """G25: _selection_waste has no subtract_fee_outputs branch.
        Core's GetSelectionAmount returns m_value when SFFO is on; ouroboros
        always uses effective."""
        sig = inspect.signature(_selection_waste)
        assert "subtract_fee_outputs" not in sig.parameters
        assert "sffo" not in sig.parameters
        assert "m_use_effective" not in sig.parameters

    def test_g26_min_viable_change_absent(self):
        """G26: No min_viable_change concept. Core defines:
        min_viable_change = max(discard_feerate*change_spend_size + 1,
        GetDustThreshold(change_spk, discard_feerate)). ouroboros uses
        flat 546 dust check."""
        import ouroboros.wallet as w
        assert not hasattr(w, "min_viable_change"), (
            "min_viable_change unexpectedly present — update audit"
        )
        assert not hasattr(w, "MIN_VIABLE_CHANGE")


# ---------------------------------------------------------------------------
# G27-G28  CoinControl + SelectionResult comparator
# ---------------------------------------------------------------------------


class TestG27_G28_ControlAndComparator:
    """G27-G28: CoinControl plumbing + waste-comparator tie-breaker."""

    def test_g27_coin_control_absent(self):
        """G27 (architectural): CoinControl class entirely absent.
        W113 BUG-11 carried; subsumed in audit notes (not in W129 bug list
        because it's a roll-up of every other gap)."""
        import ouroboros.wallet as w
        assert not hasattr(w, "CoinControl"), (
            "CoinControl class unexpectedly found — update audit"
        )
        sig = inspect.signature(select_coins)
        assert "coin_control" not in sig.parameters
        # send_transaction also has no coin_control param
        send_sig = inspect.signature(w.Wallet.send_transaction)
        assert "coin_control" not in send_sig.parameters

    def test_g28_selection_comparator_tie_break_absent(self):
        """G28 (PARTIAL): waste-tie-break on `more inputs` absent.
        Core SelectionResult::operator<: ties on waste prefer the result
        with MORE inputs (= less change attribution). ouroboros uses
        a flat min() over waste only."""
        src = inspect.getsource(select_coins)
        # Look for the comparator
        # Core: `return *m_waste < *other.m_waste || (*m_waste == *other.m_waste
        #         && m_selected_inputs.size() > other.m_selected_inputs.size())`
        # ouroboros: `min(candidates, key=lambda c: _selection_waste(...))` —
        # no tie-break on input count.
        assert "min(\n        candidates" in src or "min(candidates" in src
        # Confirm no tie-break helper exists
        import ouroboros.wallet as w
        assert not hasattr(w, "_selection_result_lt")
        assert not hasattr(w, "selection_comparator")


# ---------------------------------------------------------------------------
# G29-G30  Two-pipeline guard + W118 BUG-3 CSPRNG fix
# ---------------------------------------------------------------------------


class TestG29_G30_PipelineGuard:
    """G29-G30: Two-pipeline guard (no coin selection in Rust) and W118
    BUG-3 fix verification."""

    def test_g29_two_pipeline_no_coin_selection_in_rust(self):
        """G29: ferrous-utils contains no coin-selection identifiers.

        TWO-PIPELINE GUARD. Forward-regression assertion: if a future wave
        adds coin selection to the Rust pipeline, this test fails and forces
        re-audit. Codifies W129 + W113 + W125 + W122 + W120 + W76 guard set.
        """
        # Walk ferrous-utils tree, grep for coin-selection terms.
        ferrous = Path(__file__).parent.parent.parent.parent / "ferrous-utils"
        if not ferrous.exists():
            pytest.skip("ferrous-utils tree not present (sdist install)")
        forbidden = (
            "select_coins",
            "coin_select",
            "coinselect",
            "select_coins_bnb",
            "select_coins_knapsack",
            "select_coins_srd",
            "effective_value",
            "cost_of_change",
            "long_term_fee",
            "change_target",
            "min_viable_change",
            "OutputGroup",
            "CoinSelectionParams",
            "CoinControl",
            "SelectionResult",
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
            f"BUG: coin-selection identifiers leaked into Rust pipeline. "
            f"This breaks the two-pipeline guard. Offenders: {offenders}"
        )

    def test_g30_w118_bug3_csprng_fix_verified(self):
        """G30: W118 BUG-3 fix (`703cf69`) confirmed — coin selection uses
        secrets.SystemRandom, not random.Random."""
        import ouroboros.wallet as w
        # _CSPRNG should be a SystemRandom subclass instance
        import secrets as _secrets
        assert isinstance(_CSPRNG, _secrets.SystemRandom)
        # Knapsack and SRD use _CSPRNG:
        src_knap = inspect.getsource(select_coins_knapsack)
        src_srd = inspect.getsource(select_coins_srd)
        assert "_CSPRNG.shuffle" in src_knap, (
            "W118 BUG-3 regression: Knapsack no longer uses _CSPRNG"
        )
        assert "_CSPRNG.random()" in src_knap, (
            "W118 BUG-3 regression: Knapsack no longer uses _CSPRNG.random"
        )
        assert "_CSPRNG.shuffle" in src_srd, (
            "W118 BUG-3 regression: SRD no longer uses _CSPRNG"
        )
        # No plain `random.` usage in those functions
        assert "random.shuffle" not in src_knap
        assert "random.random()" not in src_knap
        assert "random.shuffle" not in src_srd


# ---------------------------------------------------------------------------
# Carried W113 sanity checks (functional, not bug-detect)
# ---------------------------------------------------------------------------


class TestBnBFunctional:
    """BnB end-to-end correctness (carried from W113 with abridgement)."""

    def test_bnb_exact_match_single_utxo(self):
        """BnB finds an exact-match single-UTXO selection."""
        fee_rate = 1.0
        input_fee = int(INPUT_VBYTES * fee_rate)
        target = 50_000
        value = target + input_fee
        utxo = {"txid": "aa" * 32, "vout": 0, "value": value}
        result = select_coins_bnb([utxo], target, fee_rate)
        assert result is not None
        assert len(result) == 1

    def test_bnb_returns_none_on_empty(self):
        """BnB returns None for empty pool."""
        assert select_coins_bnb([], 10_000, 1.0) is None

    def test_bnb_skips_dust_utxos(self):
        """BnB does not select UTXOs with value <= input_fee."""
        fee_rate = 10.0
        input_fee = int(INPUT_VBYTES * fee_rate)
        dust = {"txid": "ff" * 32, "vout": 0, "value": input_fee}
        good = {"txid": "aa" * 32, "vout": 0, "value": 500_000}
        result = select_coins_bnb([dust, good], 100_000, fee_rate)
        if result is not None:
            assert dust not in result


class TestKnapsackFunctional:
    """Knapsack end-to-end correctness."""

    def test_knapsack_returns_valid_selection(self):
        """Knapsack produces a selection meeting target effective value."""
        fee_rate = 1.0
        input_fee = int(INPUT_VBYTES * fee_rate)
        target = 100_000
        utxos = _make_utxos([50_000, 80_000, 150_000])
        result = select_coins_knapsack(utxos, target, fee_rate)
        assert result is not None
        total_eff = sum(u["value"] - input_fee for u in result)
        assert total_eff >= target

    def test_knapsack_insufficient_funds(self):
        """Knapsack returns None when funds inadequate."""
        utxos = _make_utxos([1_000, 1_000, 1_000])
        result = select_coins_knapsack(utxos, 1_000_000, 1.0)
        assert result is None


class TestSRDFunctional:
    """SRD end-to-end correctness."""

    def test_srd_returns_valid_selection(self):
        """SRD finds a selection meeting target."""
        fee_rate = 1.0
        input_fee = int(INPUT_VBYTES * fee_rate)
        target = 50_000
        utxos = _make_utxos([30_000, 40_000, 50_000])
        result = select_coins_srd(utxos, target, fee_rate)
        assert result is not None
        total_eff = sum(u["value"] - input_fee for u in result)
        assert total_eff >= target

    def test_srd_insufficient_funds(self):
        """SRD returns None on insufficient funds."""
        utxos = _make_utxos([200, 200])
        result = select_coins_srd(utxos, 1_000_000, 100.0)
        assert result is None


class TestSelectCoinsTopLevel:
    """select_coins() three-tier dispatch."""

    def test_select_coins_returns_tuple(self):
        """select_coins returns (utxos, fee, algorithm)."""
        utxos = _make_utxos([200_000])
        selected, fee, algo = select_coins(utxos, 50_000, 1.0)
        assert isinstance(selected, list)
        assert isinstance(fee, int)
        assert algo in {"bnb", "knapsack", "srd"}

    def test_select_coins_insufficient_funds_raises(self):
        """select_coins raises ValueError when all three algos fail."""
        utxos = _make_utxos([1_000])
        with pytest.raises(ValueError, match="Insufficient funds"):
            select_coins(utxos, 10_000_000, 1.0)
