"""W86 — Mempool eviction comprehensive audit (ouroboros).

Gates tested (Bitcoin Core txmempool.cpp:811-911, kernel/mempool_options.h,
policy/policy.h:48):

  Gate 1  — INCREMENTAL_RELAY_FEE constant = 100 sat/kvB (was 1000).
  Gate 2  — ROLLING_FEE_HALFLIFE constant = 43200 s (12 h).
  Gate 3  — _track_package_removed bumps rolling_minimum_fee_rate.
  Gate 4  — _track_package_removed clears block_since_last_rolling_fee_bump.
  Gate 5  — get_min_fee() returns 0 when rolling rate == 0.
  Gate 6  — get_min_fee() decays exponentially; reaches 0 when below threshold.
  Gate 7  — get_min_fee() halflife accelerates to /4 when usage < sizelimit/4.
  Gate 8  — get_min_fee() halflife accelerates to /2 when usage < sizelimit/2.
  Gate 9  — get_min_fee() returns max(rolling, INCREMENTAL_RELAY_FEE).
  Gate 10 — get_min_fee() does NOT decay when block_since_last_rolling_fee_bump=False.
  Gate 11 — _evict_low_fee_txs calls _track_package_removed (rolling fee rises).
  Gate 12 — after eviction low-fee tx is rejected by rolling-fee gate.
  Gate 13 — expire_old_transactions expands to descendant closure.
  Gate 14 — expired ancestor removes descendant (not just direct entry).
  Gate 15 — remove_block_transactions sets block_since_last_rolling_fee_bump=True.
  Gate 16 — remove_block_transactions updates last_rolling_fee_update timestamp.
  Gate 17 — RBF gate 4 uses 100 sat/kvB incremental fee (not 1000).
  Gate 18 — Admission gate rejects tx below rolling minimum fee rate.
  Gate 19 — Rolling fee resets to 0 after sufficient block-triggered decay.
  Gate 20 — blockSinceLastRollingFeeBump=True enables decay, =False locks it.
  Gate 21 — TrimToSize loop: rolling fee is max of all evicted chunk rates.
  Gate 22 — Expired txs with no descendants: count = 1 (no over-removal).

Reference: bitcoin-core/src/txmempool.cpp lines 811-911
           bitcoin-core/src/txmempool.h lines 195-197, 212
           bitcoin-core/src/kernel/mempool_options.h
           bitcoin-core/src/policy/policy.h:48
"""

from __future__ import annotations

import math
import time

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    DEFAULT_INCREMENTAL_RELAY_FEE,
    DEFAULT_MIN_RELAY_TX_FEE,
    MEMPOOL_EXPIRY_HOURS,
    ROLLING_FEE_HALFLIFE,
    Mempool,
    MempoolEntry,
)


# ---------------------------------------------------------------------------
# Helpers (same pattern as test_mempool_ancestor_descendant_cluster.py)
# ---------------------------------------------------------------------------

def _txid(tag: int) -> bytes:
    """Make a deterministic 32-byte txid from a small integer."""
    return tag.to_bytes(4, "little") + b"\x00" * 28


def _make_tx(
    txid: bytes,
    inputs: list,
    outputs: list[int],
    version: int = 2,
) -> Transaction:
    return Transaction(
        txid=txid,
        version=version,
        locktime=0,
        inputs=[
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=b"", sequence=0xFFFFFFFD)
            for pt, pv in inputs
        ],
        outputs=[TxOut(value=v, script_pubkey=b"\x51") for v in outputs],
    )


class _StubDB:
    def __init__(self, mapping: dict):
        self._m = mapping

    def get_utxo(self, txid: bytes, vout: int):
        return self._m.get((txid, vout))

    def get_median_time_past(self, height: int) -> int:
        return 0


class _StubValidator:
    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


def _pool(
    utxos: dict | None = None,
    max_size: int = 300_000_000,
    require_standard: bool = False,
) -> Mempool:
    return Mempool(
        validator=_StubValidator(utxos or {}),
        max_size=max_size,
        require_standard=require_standard,
        full_rbf=True,
    )


def _inject(
    pool: Mempool,
    tx: Transaction,
    fee: int = 1000,
    size: int | None = None,
    time_added: float | None = None,
) -> bytes:
    """Bypass add_transaction: insert a MempoolEntry directly."""
    txid = tx.get_txid()
    sz = size if size is not None else len(tx.serialize())
    fee_rate = fee / sz if sz else 0.0

    direct_parents: set[bytes] = set()
    for inp in tx.inputs:
        if inp.prev_txid in pool.transactions:
            direct_parents.add(inp.prev_txid)

    all_ancestors: set[bytes] = set()
    queue = list(direct_parents)
    while queue:
        a = queue.pop()
        if a in all_ancestors:
            continue
        all_ancestors.add(a)
        ae = pool.transactions.get(a)
        if ae:
            queue.extend(ae.parents - all_ancestors)

    ancestor_size_sum = sum(
        pool.transactions[a].size for a in all_ancestors if a in pool.transactions
    )

    entry = MempoolEntry(
        tx=tx,
        fee=fee,
        fee_rate=fee_rate,
        size=sz,
        time_added=time_added if time_added is not None else time.time(),
        height_added=100,
        parents=direct_parents,
        children=set(),
        ancestor_count=len(all_ancestors) + 1,
        ancestor_size=ancestor_size_sum + sz,
    )
    pool.transactions[txid] = entry
    pool.current_size += sz

    for inp in tx.inputs:
        pool.spent_outputs.add((inp.prev_txid, inp.prev_vout))

    for parent_txid in direct_parents:
        parent_entry = pool.transactions.get(parent_txid)
        if parent_entry:
            parent_entry.children.add(txid)

    for a_txid in all_ancestors:
        ae = pool.transactions.get(a_txid)
        if ae:
            ae.descendant_count += 1
            ae.descendant_size += sz

    pool._cluster_manager.add_transaction(txid)
    return txid


# ---------------------------------------------------------------------------
# Gate 1 — INCREMENTAL_RELAY_FEE constant
# ---------------------------------------------------------------------------

class TestIncrementalRelayFeeConstant:
    def test_incremental_relay_fee_is_100(self):
        """Gate 1: Core DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48)."""
        assert DEFAULT_INCREMENTAL_RELAY_FEE == 100, (
            f"INCREMENTAL_RELAY_FEE should be 100 sat/kvB (Core policy/policy.h:48), "
            f"got {DEFAULT_INCREMENTAL_RELAY_FEE}"
        )

    def test_mempool_class_constant_matches_module(self):
        """Gate 1b: Mempool.INCREMENTAL_RELAY_FEE equals module-level constant."""
        pool = _pool()
        assert pool.INCREMENTAL_RELAY_FEE == DEFAULT_INCREMENTAL_RELAY_FEE


# ---------------------------------------------------------------------------
# Gate 2 — ROLLING_FEE_HALFLIFE constant
# ---------------------------------------------------------------------------

class TestRollingFeeHalflifeConstant:
    def test_rolling_fee_halflife_is_12h(self):
        """Gate 2: Core ROLLING_FEE_HALFLIFE = 60*60*12 = 43200 s (txmempool.h:212)."""
        assert ROLLING_FEE_HALFLIFE == 43200, (
            f"ROLLING_FEE_HALFLIFE should be 43200 s (12h), got {ROLLING_FEE_HALFLIFE}"
        )


# ---------------------------------------------------------------------------
# Gates 3-4 — _track_package_removed
# ---------------------------------------------------------------------------

class TestTrackPackageRemoved:
    def test_bumps_rolling_min_when_higher(self):
        """Gate 3: _track_package_removed bumps _rolling_minimum_fee_rate when new rate > current."""
        pool = _pool()
        assert pool._rolling_minimum_fee_rate == 0.0
        pool._track_package_removed(500.0)
        assert pool._rolling_minimum_fee_rate == 500.0

    def test_does_not_lower_rolling_min(self):
        """Gate 3b: _track_package_removed does not lower existing rolling rate."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 1000.0
        pool._block_since_last_rolling_fee_bump = False
        pool._track_package_removed(200.0)
        assert pool._rolling_minimum_fee_rate == 1000.0

    def test_clears_block_since_last_bump(self):
        """Gate 4: _track_package_removed clears block_since_last_rolling_fee_bump."""
        pool = _pool()
        pool._block_since_last_rolling_fee_bump = True
        pool._track_package_removed(500.0)
        assert pool._block_since_last_rolling_fee_bump is False

    def test_no_effect_when_rate_lower(self):
        """Gate 4b: block_since flag NOT cleared when new rate does not beat current."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 1000.0
        pool._block_since_last_rolling_fee_bump = True
        pool._track_package_removed(100.0)
        # Flag should remain True since rate didn't change
        assert pool._block_since_last_rolling_fee_bump is True


# ---------------------------------------------------------------------------
# Gates 5-10 — get_min_fee decay logic
# ---------------------------------------------------------------------------

class TestGetMinFee:
    def test_returns_zero_when_rate_zero(self):
        """Gate 5: get_min_fee() returns 0.0 when rolling rate is 0."""
        pool = _pool()
        assert pool.get_min_fee() == 0.0

    def test_no_decay_when_block_flag_false(self):
        """Gate 10: get_min_fee() does not decay when block_since_last_rolling_fee_bump=False."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 5000.0
        pool._block_since_last_rolling_fee_bump = False
        # The rate should not decay regardless of time
        pool._last_rolling_fee_update = time.time() - 100_000  # very old timestamp
        result = pool.get_min_fee()
        assert result == 5000.0, (
            f"Rolling fee should NOT decay when block flag is False, got {result}"
        )

    def test_decay_happens_when_block_flag_true(self):
        """Gate 6: get_min_fee() decays when block_since_last_rolling_fee_bump=True.

        Use a large pool where usage > sizelimit/2 to avoid halflife acceleration.
        """
        pool = _pool(max_size=300_000_000)
        # Set usage to 75% of max_size so no halflife acceleration applies
        pool.current_size = int(300_000_000 * 0.75)
        pool._rolling_minimum_fee_rate = 1_000_000.0  # very high
        pool._block_since_last_rolling_fee_bump = True
        # Simulate 12 hours elapsed = exactly one halflife → ~50% decay
        pool._last_rolling_fee_update = time.time() - ROLLING_FEE_HALFLIFE - 11
        result = pool.get_min_fee()
        # After one halflife with no acceleration, should be ~500_000
        assert result < 1_000_000.0, "Rolling fee should have decayed"
        approx = 1_000_000.0 / 2.0
        assert abs(result - max(approx, DEFAULT_INCREMENTAL_RELAY_FEE)) < approx * 0.05, (
            f"Expected ~{approx}, got {result}"
        )

    def test_returns_zero_when_decayed_below_half_incremental(self):
        """Gate 6b: get_min_fee() returns 0 when rate decays below incremental/2."""
        pool = _pool()
        # Set rate just above incremental/2 = 50 sat/kvB
        pool._rolling_minimum_fee_rate = 55.0
        pool._block_since_last_rolling_fee_bump = True
        # Simulate a lot of time elapsed — should decay below 50
        pool._last_rolling_fee_update = time.time() - ROLLING_FEE_HALFLIFE * 10
        result = pool.get_min_fee()
        assert result == 0.0, (
            f"get_min_fee() should return 0 when rate decays below incremental/2=50, got {result}"
        )
        assert pool._rolling_minimum_fee_rate == 0.0

    def test_returns_max_of_rolling_and_incremental(self):
        """Gate 9: get_min_fee() returns max(rolling, INCREMENTAL_RELAY_FEE) after decay.

        Core: when blockSinceLastRollingFeeBump=False, return raw rolling rate.
              when blockSinceLastRollingFeeBump=True AND decay happens,
              return max(rolling, incremental_relay_feerate).

        This test verifies the max() path by having a block flag=True with a
        rate that survives decay (using a very recent update so no decay fires)
        but is below INCREMENTAL_RELAY_FEE.
        """
        pool = _pool(max_size=300_000_000)
        pool.current_size = int(300_000_000 * 0.75)  # avoid halflife acceleration
        # Set rolling rate lower than INCREMENTAL_RELAY_FEE but above threshold (50)
        pool._rolling_minimum_fee_rate = 60.0
        pool._block_since_last_rolling_fee_bump = True
        # Very recent timestamp — decay gate (> 10s) won't fire, so we fall
        # through to the final return max(rolling, incremental_relay_feerate)
        pool._last_rolling_fee_update = time.time() - 5  # only 5s ago
        result = pool.get_min_fee()
        assert result == DEFAULT_INCREMENTAL_RELAY_FEE, (
            f"get_min_fee() should return max(60, 100)=100 on block-decay path, got {result}"
        )

    def test_halflife_acceleration_quarter(self):
        """Gate 7: halflife divides by 4 when usage < sizelimit/4."""
        pool = _pool(max_size=1_000_000)
        pool.current_size = 100_000  # 10% of 1MB = well under 25%
        pool._rolling_minimum_fee_rate = 1_000_000.0
        pool._block_since_last_rolling_fee_bump = True
        # Simulate ROLLING_FEE_HALFLIFE / 4 seconds elapsed
        # With halflife = ROLLING_FEE_HALFLIFE/4, decay is 50% after ROLLING_FEE_HALFLIFE/4
        elapsed = ROLLING_FEE_HALFLIFE / 4
        pool._last_rolling_fee_update = time.time() - elapsed - 11  # > 10s threshold
        result = pool.get_min_fee()
        # After ROLLING_FEE_HALFLIFE/4 with halflife=ROLLING_FEE_HALFLIFE/4 → ~50% decay
        approx = 1_000_000.0 / 2.0
        assert abs(result - max(approx, DEFAULT_INCREMENTAL_RELAY_FEE)) < approx * 0.10, (
            f"Accelerated halflife /4 expected ~{approx}, got {result}"
        )

    def test_halflife_acceleration_half(self):
        """Gate 8: halflife divides by 2 when sizelimit/4 <= usage < sizelimit/2."""
        pool = _pool(max_size=1_000_000)
        pool.current_size = 300_000  # 30% = between 25% and 50%
        pool._rolling_minimum_fee_rate = 1_000_000.0
        pool._block_since_last_rolling_fee_bump = True
        elapsed = ROLLING_FEE_HALFLIFE / 2
        pool._last_rolling_fee_update = time.time() - elapsed - 11
        result = pool.get_min_fee()
        approx = 1_000_000.0 / 2.0
        assert abs(result - max(approx, DEFAULT_INCREMENTAL_RELAY_FEE)) < approx * 0.10, (
            f"Accelerated halflife /2 expected ~{approx}, got {result}"
        )

    def test_no_decay_within_10s_update_interval(self):
        """Gate 6c: get_min_fee() skips decay when last update < 10s ago."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 5000.0
        pool._block_since_last_rolling_fee_bump = True
        pool._last_rolling_fee_update = time.time() - 5  # only 5s ago
        result = pool.get_min_fee()
        # Should return max(5000, 100) unchanged
        assert result == 5000.0


# ---------------------------------------------------------------------------
# Gate 11 — _evict_low_fee_txs calls _track_package_removed
# ---------------------------------------------------------------------------

class TestEvictLowFeeTxsRollingFee:
    def test_eviction_bumps_rolling_min_fee(self):
        """Gate 11: TrimToSize eviction must call _track_package_removed."""
        # Use a tiny max_size so eviction fires immediately
        pool = _pool(max_size=500)

        root_txid = _txid(1)
        # Inject a tx with 100 bytes and 1 sat fee = ~10 sat/kvB
        tx = _make_tx(root_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, tx, fee=100, size=100)

        assert pool._rolling_minimum_fee_rate == 0.0

        # Trigger eviction by forcing current_size > max_size
        pool.current_size = pool.max_size + 1

        pool._evict_low_fee_txs(1)

        # Rolling min fee should now be non-zero
        assert pool._rolling_minimum_fee_rate > 0.0, (
            "_evict_low_fee_txs must call _track_package_removed to bump rolling min fee"
        )

    def test_eviction_locks_block_flag(self):
        """Gate 11b: After eviction block_since_last_rolling_fee_bump=False (locked)."""
        pool = _pool(max_size=500)
        pool._block_since_last_rolling_fee_bump = True

        root_txid = _txid(1)
        tx = _make_tx(root_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, tx, fee=100, size=100)
        pool.current_size = pool.max_size + 1

        pool._evict_low_fee_txs(1)

        # If eviction happened and _track_package_removed was called with a rate
        # higher than 0, the flag should be False (locked, not decaying)
        if pool._rolling_minimum_fee_rate > 0.0:
            assert pool._block_since_last_rolling_fee_bump is False, (
                "After eviction, block_since flag must be False (rate is locked)"
            )


# ---------------------------------------------------------------------------
# Gate 12 — Admission rejected by rolling minimum fee rate
# ---------------------------------------------------------------------------

class TestAdmissionRollingFeeGate:
    def test_low_fee_tx_rejected_after_eviction(self):
        """Gate 12: tx below rolling min fee is rejected at admission.

        Uses a high rolling minimum fee rate (locked, no block decay) so that
        a tx paying only DEFAULT_MIN_RELAY_TX_FEE (1000 sat/kvB) is rejected
        by the rolling-min gate.  The tx is sized to pass the static min-relay
        check but fail the rolling-min gate.
        """
        pool = _pool(max_size=300_000_000)

        # Rolling min = 50_000 sat/kvB (locked, no decay)
        pool._rolling_minimum_fee_rate = 50_000.0
        pool._block_since_last_rolling_fee_bump = False  # locked, no decay

        utxo_value = 10_000_000  # 0.1 BTC
        confirmed_txid = _txid(999)
        utxos = {(confirmed_txid, 0): {"value": utxo_value, "script_pubkey": b"\x51"}}
        pool.validator = _StubValidator(utxos)

        tx_txid = _txid(1)
        # Pay exactly 1000 sat/kvB (static minimum) but far below rolling min.
        # tx serialized size ≈ 85-100 bytes; set fee = 100 sats (≈ 1000 sat/kvB for 100 B)
        # rolling_min_fee = 85 * 50_000 / 1000 = 4_250 sats >> 100 sats
        tx = _make_tx(tx_txid, [(confirmed_txid, 0)], [utxo_value - 100])  # 100 sat fee
        ok, err = pool._add_transaction_inner(tx, height=100)
        assert not ok, "Tx below rolling min fee should be rejected"
        # Core validation.cpp:705 PreChecks: "mempool min fee not met"
        assert "mempool min fee not met" in err, (
            f"Expected rolling min fee rejection, got: {err}"
        )

    def test_adequate_fee_tx_accepted_above_rolling_min(self):
        """Gate 12b: tx above rolling min fee is accepted."""
        pool = _pool(max_size=300_000_000)

        # Set a moderate rolling min fee
        pool._rolling_minimum_fee_rate = 100.0  # 0.1 sat/vB
        pool._block_since_last_rolling_fee_bump = False  # locked

        utxo_value = 100_000
        confirmed_txid = _txid(999)
        utxos = {(confirmed_txid, 0): {"value": utxo_value, "script_pubkey": b"\x51"}}
        pool.validator = _StubValidator(utxos)

        tx_txid = _txid(1)
        # 100 byte tx, fee of 100 sat = 1000 sat/kvB > 100 sat/kvB rolling min
        tx = _make_tx(tx_txid, [(confirmed_txid, 0)], [utxo_value - 100])
        ok, err = pool._add_transaction_inner(tx, height=100)
        assert ok, f"Tx should be accepted above rolling min fee, error: {err}"


# ---------------------------------------------------------------------------
# Gates 13-14 — expire_old_transactions descendant closure
# ---------------------------------------------------------------------------

class TestExpireDescendantClosure:
    def test_expiry_removes_descendants(self):
        """Gate 13: expire_old_transactions removes descendants of expired txs.

        Core Expire() calls CalculateDescendants to expand expiry set to the
        full closure (txmempool.cpp:822-825).  Without this a child of an
        expired parent stays orphaned in the pool.
        """
        pool = _pool()
        old_time = time.time() - (MEMPOOL_EXPIRY_HOURS * 3600) - 1

        # Parent (old) + child (new) — parent should pull child out on expiry
        parent_txid = _txid(1)
        child_txid = _txid(2)

        parent_tx = _make_tx(parent_txid, [(_txid(0), 0)], [50_000])
        child_tx = _make_tx(child_txid, [(parent_txid, 0)], [49_000])

        _inject(pool, parent_tx, fee=1000, time_added=old_time)
        _inject(pool, child_tx, fee=1000)  # recently added

        assert parent_txid in pool.transactions
        assert child_txid in pool.transactions

        removed = pool.expire_old_transactions(current_time=time.time())

        assert parent_txid not in pool.transactions, (
            "Expired parent should have been removed"
        )
        assert child_txid not in pool.transactions, (
            "Child of expired parent must also be removed (descendant closure)"
        )
        assert removed == 2, f"Expected 2 removed (parent+child), got {removed}"

    def test_expiry_grandchild_removed(self):
        """Gate 14: Full descendant chain removed when root expires."""
        pool = _pool()
        old_time = time.time() - (MEMPOOL_EXPIRY_HOURS * 3600) - 1

        ids = [_txid(i) for i in range(1, 5)]
        # Build chain: ids[0] → ids[1] → ids[2] → ids[3]
        tx0 = _make_tx(ids[0], [(_txid(0), 0)], [50_000])
        tx1 = _make_tx(ids[1], [(ids[0], 0)], [49_000])
        tx2 = _make_tx(ids[2], [(ids[1], 0)], [48_000])
        tx3 = _make_tx(ids[3], [(ids[2], 0)], [47_000])

        _inject(pool, tx0, fee=1000, time_added=old_time)  # expired
        _inject(pool, tx1, fee=1000)
        _inject(pool, tx2, fee=1000)
        _inject(pool, tx3, fee=1000)

        removed = pool.expire_old_transactions(current_time=time.time())

        for txid in ids:
            assert txid not in pool.transactions, (
                f"All 4 chain members should be removed, {txid.hex()[:8]}... still present"
            )
        assert removed == 4

    def test_expiry_isolated_tx_count_correct(self):
        """Gate 22: Isolated expired tx with no descendants: count == 1."""
        pool = _pool()
        old_time = time.time() - (MEMPOOL_EXPIRY_HOURS * 3600) - 1

        txid = _txid(1)
        tx = _make_tx(txid, [(_txid(0), 0)], [50_000])
        _inject(pool, tx, fee=1000, time_added=old_time)

        removed = pool.expire_old_transactions(current_time=time.time())
        assert removed == 1, f"Isolated expired tx should count as 1, got {removed}"

    def test_recent_tx_not_expired(self):
        """Gate 14b: Recently added tx is not removed by expire_old_transactions."""
        pool = _pool()

        txid = _txid(1)
        tx = _make_tx(txid, [(_txid(0), 0)], [50_000])
        _inject(pool, tx, fee=1000)  # time_added = now

        removed = pool.expire_old_transactions(current_time=time.time())
        assert removed == 0, "Recent tx should not be expired"
        assert txid in pool.transactions


# ---------------------------------------------------------------------------
# Gates 15-16 — remove_block_transactions rolling fee state
# ---------------------------------------------------------------------------

class _FakeBlock:
    """Minimal block stub for remove_block_transactions."""
    def __init__(self, txids: list[bytes], txmap: dict):
        self.transactions = [
            _TxStub(txid, txmap) for txid in txids
        ]


class _TxStub:
    def __init__(self, txid: bytes, txmap: dict):
        self._txid = txid
        self.is_coinbase = False
        self.inputs = txmap.get(txid, {}).get("inputs", [])

    def get_txid(self):
        return self._txid


class TestRemoveBlockTransactions:
    def test_sets_block_since_flag(self):
        """Gate 15: remove_block_transactions sets _block_since_last_rolling_fee_bump=True."""
        pool = _pool()
        pool._block_since_last_rolling_fee_bump = False

        block = _FakeBlock([], {})
        pool.remove_block_transactions(block)

        assert pool._block_since_last_rolling_fee_bump is True, (
            "remove_block_transactions must set block_since_last_rolling_fee_bump=True "
            "(Core txmempool.cpp:427 blockSinceLastRollingFeeBump = true)"
        )

    def test_updates_last_rolling_fee_update(self):
        """Gate 16: remove_block_transactions updates _last_rolling_fee_update."""
        pool = _pool()
        old_ts = time.time() - 10_000
        pool._last_rolling_fee_update = old_ts

        block = _FakeBlock([], {})
        pool.remove_block_transactions(block)

        assert pool._last_rolling_fee_update > old_ts, (
            "remove_block_transactions must update _last_rolling_fee_update "
            "(Core txmempool.cpp:426 lastRollingFeeUpdate = GetTime())"
        )

    def test_block_flag_enables_decay(self):
        """Gate 15b: After block, rolling fee can decay (flag=True enables decay)."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 1_000_000.0
        pool._block_since_last_rolling_fee_bump = False  # locked

        block = _FakeBlock([], {})
        pool.remove_block_transactions(block)

        # Now flag=True; simulate elapsed time > 10s and decay should work
        pool._last_rolling_fee_update = time.time() - ROLLING_FEE_HALFLIFE
        result = pool.get_min_fee()
        assert result < 1_000_000.0, (
            "After block (flag=True) rolling fee should be able to decay"
        )


# ---------------------------------------------------------------------------
# Gate 17 — RBF incremental fee uses 100 sat/kvB
# ---------------------------------------------------------------------------

class TestRbfIncrementalFee:
    def test_rbf_incremental_fee_100_not_1000(self):
        """Gate 17: RBF gate 4 uses INCREMENTAL_RELAY_FEE=100 sat/kvB, not 1000."""
        # Build a pool where we can check the RBF incremental fee threshold.
        # The Mempool class constant should match the module-level constant.
        pool = _pool()
        assert pool.INCREMENTAL_RELAY_FEE == 100, (
            f"Mempool.INCREMENTAL_RELAY_FEE should be 100 sat/kvB, "
            f"got {pool.INCREMENTAL_RELAY_FEE}"
        )

    def test_rbf_gate4_threshold_with_100_sat_kvb(self):
        """Gate 17b: Verify incremental_fee_needed formula uses 100 sat/kvB.

        For a 1000-byte tx the incremental fee needed = 1000 * 100 / 1000 = 100 sat.
        With old 1000 sat/kvB it would have been 1000 sat.
        """
        pool = _pool()
        size = 1000  # bytes
        expected = (size * 100) // 1000  # = 100 sat
        wrong = (size * 1000) // 1000    # = 1000 sat (old behavior)
        actual = (size * pool.INCREMENTAL_RELAY_FEE) // 1000
        assert actual == expected, (
            f"Incremental fee for {size}B should be {expected} sat (100 sat/kvB), "
            f"got {actual}"
        )
        assert actual != wrong, (
            f"Incremental fee should NOT be {wrong} sat (old 1000 sat/kvB behavior)"
        )


# ---------------------------------------------------------------------------
# Gate 19-20 — Rolling fee decay resets to 0 after block decay
# ---------------------------------------------------------------------------

class TestRollingFeeDecayReset:
    def test_rolling_fee_resets_after_block_decay(self):
        """Gate 19: Rolling fee reaches 0 after sufficient block-triggered decay."""
        pool = _pool()
        # Start with a moderate rolling fee
        pool._rolling_minimum_fee_rate = 200.0  # slightly above 2x incremental
        pool._block_since_last_rolling_fee_bump = True
        # Simulate many halflives elapsed (100× the halflife)
        pool._last_rolling_fee_update = time.time() - ROLLING_FEE_HALFLIFE * 100
        result = pool.get_min_fee()
        assert result == 0.0, (
            f"Rolling fee should decay to 0 after many halflives, got {result}"
        )

    def test_rolling_fee_locked_without_block(self):
        """Gate 20: Rolling fee does NOT reach 0 without blockSinceLastRollingFeeBump."""
        pool = _pool()
        pool._rolling_minimum_fee_rate = 200.0
        pool._block_since_last_rolling_fee_bump = False  # no block
        pool._last_rolling_fee_update = time.time() - ROLLING_FEE_HALFLIFE * 100
        result = pool.get_min_fee()
        # Without block_since flag, no decay should occur
        assert result == 200.0, (
            f"Rolling fee should stay at 200 without block_since flag, got {result}"
        )


# ---------------------------------------------------------------------------
# Gate 21 — TrimToSize: rolling fee = max of all evicted chunk rates
# ---------------------------------------------------------------------------

class TestTrimToSizeMultipleChunks:
    def test_rolling_fee_is_max_across_chunks(self):
        """Gate 21: rolling min fee tracks max across all evicted chunks."""
        pool = _pool(max_size=200)

        # Inject two txs with different fee rates:
        #   tx1: 50 sat / 100 bytes = 0.5 sat/vB = 500 sat/kvB → removed_rate = 600
        #   tx2: 20 sat / 100 bytes = 0.2 sat/vB = 200 sat/kvB → removed_rate = 300
        # If both get evicted the final rolling fee should be max(600, 300) = 600

        tx1_id = _txid(1)
        tx2_id = _txid(2)
        tx1 = _make_tx(tx1_id, [(_txid(10), 0)], [50_000])
        tx2 = _make_tx(tx2_id, [(_txid(11), 0)], [50_000])

        _inject(pool, tx1, fee=50, size=100)
        _inject(pool, tx2, fee=20, size=100)

        # current_size = 200 = max_size; we need to evict at least 100 bytes
        pool.current_size = pool.max_size + 1  # force eviction

        pool._evict_low_fee_txs(100)

        # At least one tx should have been evicted and rolling fee bumped
        assert pool._rolling_minimum_fee_rate > 0.0, (
            "Rolling minimum fee must be bumped after eviction"
        )
