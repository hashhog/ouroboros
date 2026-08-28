"""Core v31 cluster mempool limits — boundary and UNITS pins (ouroboros).

Bitcoin Core v31 replaced the generic ancestor/descendant admission gates with
two cluster limits.  The exact form Core enforces, all in WEIGHT units:

    per-tx  := GetSigOpsAdjustedWeight(GetTransactionWeight(tx), sigops, 20)
             = max(tx_weight, tx_sigops_cost * 20)          policy.cpp:390
    cluster := Σ per-tx                                     txmempool.cpp:1017
    reject if cluster_count > 64        (DEFAULT_CLUSTER_LIMIT, policy.h:72)
    reject if cluster_weight > 404_000  (101 kvB × 4, txmempool.cpp:181)
    both comparisons strict >                               txgraph.cpp:2059
    reject token "too-large-cluster", empty debug string
                              validation.cpp:1024, :1116, :1343, :1521

The single most likely wrong implementation is swapping the constant 101_000 for
404_000 while still summing per-transaction ceil(weight/4) vbytes.  Because
Σ⌈wᵢ/4⌉ ≥ (Σwᵢ)/4, that predicate is systematically STRICTER than Core, always
in the reject direction.  ``TestClusterSizeUnits`` below is built specifically to
fail such an implementation: its cluster weighs exactly 404_000 (Core: ACCEPT)
while Σ⌈wᵢ/4⌉ = 101_048 (per-tx-rounding form: REJECT).

The second wrong implementation is summing ``entry.size``, which in ouroboros is
the STRIPPED, witness-less byte count driving the mempool RAM budget.  For
segwit members stripped ≪ vsize, so that form UNDER-counts and is looser than
Core.  ``TestClusterSizeIgnoresStrippedSize`` pins that.

These tests drive ``Mempool._check_cluster_limit`` — the LIVE gate, called from
``Mempool.add_transaction``.  ``ClusterManager.check_cluster_limit`` is an
unreferenced duplicate and is deliberately NOT exercised here: a test that
passed against it would prove nothing about admission.
"""

from __future__ import annotations

import time

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    Mempool,
    MempoolEntry,
    CLUSTER_REJECT_TOKEN,
    MAX_CLUSTER_COUNT,
    MAX_CLUSTER_SIZE_VBYTES,
    MAX_CLUSTER_SIZE_WEIGHT,
    MAX_PACKAGE_COUNT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _txid(tag: int) -> bytes:
    return tag.to_bytes(4, "little") + b"\x00" * 28


class _StubDB:
    def __init__(self, mapping: dict):
        self._m = mapping

    def get_utxo(self, txid: bytes, vout: int):
        return self._m.get((txid, vout))

    def get_block_height(self):
        return 100

    def get_median_time_past(self, height: int | None = None) -> int:
        return 1_600_000_000


class _StubValidator:
    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, *a, **kw):
        return True, ""


def _pool(utxos: dict | None = None) -> Mempool:
    return Mempool(
        validator=_StubValidator(utxos or {}),
        require_standard=False,
        full_rbf=True,
    )


def _mk(txid: bytes, inputs: list[tuple[bytes, int]], wit_lens: list[int]) -> Transaction:
    """Build a segwit transaction with a witness stack of the given item sizes.

    Segwit is required to reach weights that are NOT multiples of 4: for a
    witness-less transaction weight == stripped_size * 4 always, which would
    make Σ⌈wᵢ/4⌉ and (Σwᵢ)/4 agree and hide exactly the bug under test.
    """
    return Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=[
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=b"", sequence=0xFFFFFFFD,
                 witness=[b"\x00" * n for n in wit_lens])
            for pt, pv in inputs
        ],
        outputs=[TxOut(value=50_000, script_pubkey=b"\x51")],
        has_witness=True,
    )


def _tx_of_weight(txid: bytes, inputs: list[tuple[bytes, int]], target: int) -> Transaction:
    """Build a transaction whose BIP-141 weight is EXACTLY `target`.

    Weight is monotonic in the witness item length, so a few Newton-style steps
    converge; the nested fallback covers the 2-weight discontinuity where the
    witness-item length varint grows from 1 byte to 3.
    """
    length = 0
    for _ in range(10):
        tx = _mk(txid, inputs, [length])
        weight = tx.get_weight()
        if weight == target:
            return tx
        length += target - weight
        if length < 0:
            raise ValueError(f"target weight {target} is below the minimum")
    for back in range(6):
        for extra in range(6):
            tx = _mk(txid, inputs, [max(length - back, 0), extra])
            if tx.get_weight() == target:
                return tx
    raise ValueError(f"could not build a transaction of weight {target}")


def _inject(pool: Mempool, tx: Transaction, sigop_cost: int = 0) -> bytes:
    """Insert a MempoolEntry directly and register it with the cluster manager."""
    txid = tx.get_txid()
    size = len(tx.serialize())

    parents = {i.prev_txid for i in tx.inputs if i.prev_txid in pool.transactions}

    pool.transactions[txid] = MempoolEntry(
        tx=tx,
        fee=1000,
        fee_rate=1.0,
        size=size,
        time_added=time.time(),
        height_added=100,
        sigop_cost=sigop_cost,
        parents=parents,
        children=set(),
    )
    pool.current_size += size
    for inp in tx.inputs:
        pool.spent_outputs.add((inp.prev_txid, inp.prev_vout))
    for parent in parents:
        pool.transactions[parent].children.add(txid)
    pool._cluster_manager.add_transaction(txid)
    return txid


def _chain(pool: Mempool, weights: list[int], start_id: int = 1000) -> bytes:
    """Inject a linear chain with the given per-tx weights; return the tip txid."""
    prev = _txid(start_id - 1)  # confirmed, not in the pool
    for i, weight in enumerate(weights):
        tx = _tx_of_weight(_txid(start_id + i), [(prev, 0)], weight)
        prev = _inject(pool, tx)
    return prev


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_cluster_count_is_64(self):
        """DEFAULT_CLUSTER_LIMIT (bitcoin-core policy/policy.h:72)."""
        assert MAX_CLUSTER_COUNT == 64

    def test_declared_size_limit_is_101_000_vbytes(self):
        """kernel/mempool_limits.h:22 — the number Core reports over RPC."""
        assert MAX_CLUSTER_SIZE_VBYTES == 101_000

    def test_enforced_size_limit_is_404_000_weight(self):
        """txmempool.cpp:181 — cluster_size_vbytes * WITNESS_SCALE_FACTOR."""
        assert MAX_CLUSTER_SIZE_WEIGHT == 404_000
        assert MAX_CLUSTER_SIZE_WEIGHT == MAX_CLUSTER_SIZE_VBYTES * 4

    def test_reject_token_is_bare_and_has_no_debug_prose(self):
        """validation.cpp:1024 — Invalid(TX_MEMPOOL_POLICY, "too-large-cluster", "")."""
        assert CLUSTER_REJECT_TOKEN == "too-large-cluster"

    def test_package_count_limit_is_untouched(self):
        """MAX_PACKAGE_COUNT is a DIFFERENT limit and must remain 25."""
        assert MAX_PACKAGE_COUNT == 25


# ---------------------------------------------------------------------------
# Gate 1 — cluster COUNT boundary: 64 accepts, 65 rejects
# ---------------------------------------------------------------------------

class TestClusterCountBoundary:
    """txgraph.cpp:2059 — `total_count > m_max_cluster_count` (strict >)."""

    def _probe(self, existing: int):
        pool = _pool()
        # Keep every member tiny so the size gate cannot fire first.
        tip = _chain(pool, [400] * existing)
        incoming = _tx_of_weight(_txid(9999), [(tip, 0)], 400)
        return pool._check_cluster_limit(incoming)

    def test_63_existing_plus_incoming_is_64_and_accepts(self):
        ok, err = self._probe(63)
        assert ok, f"a 64-transaction cluster is exactly at the limit: {err}"
        assert err == ""

    def test_64_existing_plus_incoming_is_65_and_rejects(self):
        ok, err = self._probe(64)
        assert not ok, "a 65-transaction cluster exceeds DEFAULT_CLUSTER_LIMIT"
        assert err == CLUSTER_REJECT_TOKEN

    def test_26_long_chain_accepts_since_ancestor_limit_is_gone(self):
        """Core v31 has no 25-ancestor gate; only the cluster limits bound this.

        Mirrors the `cluster-linear-26` corpus entry.
        """
        ok, err = self._probe(25)  # 25 existing + incoming = 26
        assert ok, f"26-transaction chain must accept under cluster limits: {err}"


# ---------------------------------------------------------------------------
# Gate 2 — cluster SIZE boundary, in weight units
# ---------------------------------------------------------------------------

class TestClusterSizeBoundary:
    """404_000 accepts, 404_001 rejects (strict >, txgraph.cpp:2059)."""

    def _probe(self, total_weight: int):
        # 3 members + 1 incoming: far below the count limit, so any rejection
        # here is unambiguously the size gate.
        member = total_weight // 4
        weights = [member, member, member]
        pool = _pool()
        tip = _chain(pool, weights)
        incoming = _tx_of_weight(_txid(9999), [(tip, 0)], total_weight - 3 * member)
        assert (sum(weights) + incoming.get_weight()) == total_weight
        return pool._check_cluster_limit(incoming)

    def test_exactly_404_000_accepts(self):
        ok, err = self._probe(404_000)
        assert ok, f"a cluster weighing exactly 404_000 is at the limit: {err}"
        assert err == ""

    def test_404_001_rejects(self):
        ok, err = self._probe(404_001)
        assert not ok, "404_001 weight units exceeds the cluster size limit"
        assert err == CLUSTER_REJECT_TOKEN


# ---------------------------------------------------------------------------
# THE UNITS TEST — catches a constant swap that keeps per-tx rounding
# ---------------------------------------------------------------------------

class TestClusterSizeUnits:
    """Σweight == 404_000 exactly, but Σ⌈wᵢ/4⌉ == 101_048 > 101_000.

    Core sums the UNROUNDED sigop-adjusted weight of each member and divides
    never (txmempool.cpp:181 converts the LIMIT once, up front).  An
    implementation that instead sums per-transaction vbytes rejects this
    cluster, because rounding 64 members up individually loses up to 3 weight
    units each.  This test therefore fails for:

      * the pre-fix form (101_000 vbyte limit, per-tx ceil), and
      * the classic half-fix (404_000 limit but still per-tx ceil, then
        compared in the wrong unit), and
      * any form that divides before summing.

    64 members × ~1.5 weight units of rounding loss ≈ 48 vB — small, but
    structural and always in the reject direction.
    """

    MEMBER_WEIGHT = 6_313      # ⌈6313/4⌉ = 1579
    N_MEMBERS = 63
    INCOMING_WEIGHT = 6_281    # ⌈6281/4⌉ = 1571

    def test_arithmetic_premise_holds(self):
        """Guard the test's own construction, so it cannot silently go vacuous."""
        total_weight = self.N_MEMBERS * self.MEMBER_WEIGHT + self.INCOMING_WEIGHT
        total_ceiled_vbytes = (
            self.N_MEMBERS * ((self.MEMBER_WEIGHT + 3) // 4)
            + (self.INCOMING_WEIGHT + 3) // 4
        )
        assert total_weight == 404_000, total_weight
        assert total_weight // 4 == 101_000
        assert total_ceiled_vbytes == 101_048, total_ceiled_vbytes
        # The premise: the two forms DISAGREE at this point.
        assert total_ceiled_vbytes > MAX_CLUSTER_SIZE_VBYTES
        assert total_weight <= MAX_CLUSTER_SIZE_WEIGHT

    def test_cluster_of_exactly_404_000_weight_accepts(self):
        pool = _pool()
        tip = _chain(pool, [self.MEMBER_WEIGHT] * self.N_MEMBERS)
        incoming = _tx_of_weight(_txid(9999), [(tip, 0)], self.INCOMING_WEIGHT)

        ok, err = pool._check_cluster_limit(incoming)
        assert ok, (
            "Σweight is exactly 404_000 so Core ACCEPTS; a rejection here means "
            "the sum is being taken in per-transaction ceil-vbytes "
            f"(Σ⌈wᵢ/4⌉ = 101_048 > 101_000). err={err!r}"
        )

    def test_one_more_weight_unit_rejects(self):
        """The same cluster at 404_001 must reject — proves the gate is live."""
        pool = _pool()
        tip = _chain(pool, [self.MEMBER_WEIGHT] * self.N_MEMBERS)
        incoming = _tx_of_weight(_txid(9999), [(tip, 0)], self.INCOMING_WEIGHT + 1)

        ok, err = pool._check_cluster_limit(incoming)
        assert not ok
        assert err == CLUSTER_REJECT_TOKEN


# ---------------------------------------------------------------------------
# Sigop-dominated cluster: max(weight, sigops * 20) is what trips
# ---------------------------------------------------------------------------

class TestSigopAdjustedWeight:
    """policy.cpp:390 — GetSigOpsAdjustedWeight = max(weight, sigops * 20).

    Every transaction here is tiny by raw weight; only the sigop term can
    exceed 404_000.  An implementation that sums raw weight (or raw vsize)
    accepts all of these.
    """

    def _probe(self, member_sigops: int):
        pool = _pool()
        member = _tx_of_weight(_txid(1000), [(_txid(999), 0)], 1_000)
        _inject(pool, member, sigop_cost=member_sigops)
        incoming = _tx_of_weight(_txid(9999), [(member.get_txid(), 0)], 1_004)
        # Raw weight alone is nowhere near the limit.
        assert member.get_weight() + incoming.get_weight() == 2_004
        return pool._check_cluster_limit(incoming, sigop_cost=0)

    def test_sigop_term_below_limit_accepts(self):
        # 20_149 * 20 = 402_980; + 1_004 = 403_984 <= 404_000
        ok, err = self._probe(20_149)
        assert ok, f"403_984 weight units is under the limit: {err}"

    def test_sigop_term_over_limit_rejects(self):
        # 20_150 * 20 = 403_000; + 1_004 = 404_004 > 404_000
        ok, err = self._probe(20_150)
        assert not ok, (
            "the sigop term (403_000) dominates the 1_000-unit raw weight and "
            "pushes the cluster over 404_000"
        )
        assert err == CLUSTER_REJECT_TOKEN

    def test_incoming_transaction_sigops_also_count(self):
        """The incoming tx contributes max(weight, sigops*20) too, not raw weight."""
        pool = _pool()
        member = _tx_of_weight(_txid(1000), [(_txid(999), 0)], 1_000)
        _inject(pool, member, sigop_cost=0)
        incoming = _tx_of_weight(_txid(9999), [(member.get_txid(), 0)], 1_000)

        ok, _ = pool._check_cluster_limit(incoming, sigop_cost=0)
        assert ok, "2_000 raw weight units is far under the limit"

        # 20_200 * 20 = 404_000; + 1_000 member = 405_000 > 404_000
        ok, err = pool._check_cluster_limit(incoming, sigop_cost=20_200)
        assert not ok, "the incoming transaction's own sigop cost must be counted"
        assert err == CLUSTER_REJECT_TOKEN


# ---------------------------------------------------------------------------
# The stripped-size regression: entry.size must NOT be the summand
# ---------------------------------------------------------------------------

class TestClusterSizeIgnoresStrippedSize:
    """`entry.size` is the witness-less byte count; using it under-counts.

    Each member below serialises to 61 stripped bytes but weighs 6_313 units
    (vsize 1_579) — a 26x gap.  Summing `entry.size` would put this cluster at
    ~3.9 kB, nowhere near any limit, and it would be admitted.
    """

    def test_witness_heavy_cluster_is_counted_by_weight_not_stripped_bytes(self):
        pool = _pool()
        weights = [6_313] * 63
        tip = _chain(pool, weights)

        stripped_total = sum(pool.transactions[t].size for t in pool.transactions)
        assert stripped_total < 5_000, (
            "premise: the stripped byte total is trivially small for these "
            f"witness-heavy transactions (got {stripped_total})"
        )

        # Σ member weight = 397_719; a 6_500-unit newcomer takes it to 404_219.
        incoming = _tx_of_weight(_txid(9999), [(tip, 0)], 6_500)
        ok, err = pool._check_cluster_limit(incoming)
        assert not ok, (
            "404_219 weight units exceeds the limit; accepting it means the "
            "gate is summing stripped `entry.size` bytes instead of weight"
        )
        assert err == CLUSTER_REJECT_TOKEN

    def test_entry_exposes_sigop_adjusted_weight_not_vsize(self):
        pool = _pool()
        tx = _tx_of_weight(_txid(1000), [(_txid(999), 0)], 6_313)
        txid = _inject(pool, tx, sigop_cost=0)
        entry = pool.transactions[txid]

        assert entry.sigop_adjusted_weight == 6_313      # unrounded weight
        assert entry.vsize == 1_579                      # ceil(6313/4)
        assert entry.size == 61                          # stripped bytes
        # All three differ — a gate summing the wrong one is detectable.
        assert len({entry.sigop_adjusted_weight, entry.vsize, entry.size}) == 3

    def test_sigop_adjusted_weight_takes_the_max(self):
        pool = _pool()
        tx = _tx_of_weight(_txid(1000), [(_txid(999), 0)], 1_000)
        txid = _inject(pool, tx, sigop_cost=100)  # 100 * 20 = 2_000 > 1_000
        assert pool.transactions[txid].sigop_adjusted_weight == 2_000


# ---------------------------------------------------------------------------
# Reject token — DECISIONS keyed on the token, never on prose
# ---------------------------------------------------------------------------

class TestRejectToken:
    def test_count_and_size_gates_emit_the_identical_bare_token(self):
        """Core does not distinguish them: both are ("too-large-cluster", "")."""
        pool_count = _pool()
        tip = _chain(pool_count, [400] * 64)
        _, count_err = pool_count._check_cluster_limit(
            _tx_of_weight(_txid(9999), [(tip, 0)], 400))

        pool_size = _pool()
        tip = _chain(pool_size, [100_000] * 4)
        _, size_err = pool_size._check_cluster_limit(
            _tx_of_weight(_txid(9998), [(tip, 0)], 4_001))

        assert count_err == "too-large-cluster"
        assert size_err == "too-large-cluster"
        assert count_err == size_err

    def test_token_carries_no_debug_string(self):
        """No limit values, no English prose — the debug string is empty."""
        pool = _pool()
        tip = _chain(pool, [400] * 64)
        _, err = pool._check_cluster_limit(_tx_of_weight(_txid(9999), [(tip, 0)], 400))
        assert err == CLUSTER_REJECT_TOKEN
        assert "101" not in err and "404" not in err and "64" not in err

    def test_rpc_maps_the_token_to_itself_not_to_tx_size(self):
        """rpc.py must not route a cluster rejection into the size/weight bucket."""
        from ouroboros.rpc import RPCServer

        mapped = RPCServer._map_mempool_error_to_reject_reason(None, CLUSTER_REJECT_TOKEN)
        assert mapped == "too-large-cluster"
        assert mapped != "tx-size"
        assert mapped != "too-long-mempool-chain"


# ---------------------------------------------------------------------------
# Invariants that this wave must NOT disturb
# ---------------------------------------------------------------------------

class TestUnchangedInvariants:
    def test_rpc_reports_cluster_size_in_vbytes(self):
        """rpc/mempool.cpp:1062 reports cluster_size_vbytes — 101_000, NOT 404_000."""
        import re
        from pathlib import Path

        source = Path(__file__).resolve().parents[1] / "src" / "ouroboros" / "rpc.py"
        reported = re.findall(r'"limitclustersize":\s*([0-9_]+)', source.read_text())
        assert reported, "getmempoolinfo must still report limitclustersize"
        for value in reported:
            assert int(value.replace("_", "")) == 101_000, (
                "limitclustersize is a VBYTE figure; reporting 404_000 would be "
                "a wire-visible divergence from Core"
            )

    def test_truc_ancestor_and_descendant_limits_survive(self):
        """TRUC 2/2 is the only remaining ancestor/descendant enforcement."""
        from ouroboros.mempool import TRUC_ANCESTOR_LIMIT, TRUC_DESCENDANT_LIMIT

        assert TRUC_ANCESTOR_LIMIT == 2
        assert TRUC_DESCENDANT_LIMIT == 2
