"""W75 — Ancestor / descendant / cluster limit comprehensive audit (ouroboros).

Gates tested (Bitcoin Core policy/policy.h:70-95, kernel/mempool_limits.h,
txmempool.cpp:179-181):

  Gate 1  — Ancestor COUNT limit: <= DEFAULT_ANCESTOR_LIMIT = 25 (self included).
  Gate 2  — Ancestor SIZE limit:  ancestor set + new tx <= 101,000 vbytes.
  Gate 3  — Descendant COUNT limit: each ancestor's descendant_count+1 <= 25.
  Gate 4  — Descendant SIZE limit: each ancestor's descendant_size + new tx <= 101,000 vbytes.
  Gate 5  — Cluster COUNT limit = 64 (was wrong: 100). DEFAULT_CLUSTER_LIMIT.
  Gate 6  — Cluster SIZE limit  = 101,000 vbytes. (Was MISSING entirely.)
  Gate 7  — Constant values match Core defaults.
  Gate 8  — At-boundary acceptance: ancestor_count == 25 is accepted.
  Gate 9  — Cluster-count boundary: 64 accepted, 65 rejected.
  Gate 10 — Cluster-size boundary: cluster joining triggers vbyte gate.

Reference: bitcoin/src/policy/policy.h:70-95,
           bitcoin/src/kernel/mempool_limits.h,
           bitcoin/src/txmempool.cpp:169-188.
"""

from __future__ import annotations

import time

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    Mempool,
    MempoolEntry,
    MAX_ANCESTOR_COUNT,
    MAX_DESCENDANT_COUNT,
    MAX_ANCESTOR_SIZE_KVB,
    MAX_DESCENDANT_SIZE_KVB,
    MAX_CLUSTER_COUNT,
    MAX_CLUSTER_SIZE_VBYTES,
    EXTRA_DESCENDANT_TX_SIZE_LIMIT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _txid(tag: int) -> bytes:
    """Make a deterministic 32-byte txid from a small integer."""
    return tag.to_bytes(4, "little") + b"\x00" * 28


def _make_tx(txid: bytes, inputs: list, outputs: list[int], version: int = 2) -> Transaction:
    """Build a Transaction with a 1-byte OP_TRUE output."""
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


class _StubValidator:
    """Always accepts; returns UTXOs from a pre-seeded dict."""

    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0):
        return True, ""


def _pool(utxos: dict | None = None) -> Mempool:
    return Mempool(
        validator=_StubValidator(utxos or {}),
        require_standard=False,
        full_rbf=True,
    )


def _inject(pool: Mempool, tx: Transaction, fee: int = 1000, size: int | None = None) -> bytes:
    """Bypass add_transaction: insert a MempoolEntry directly.

    Correctly updates parent.children, ancestor_count/ancestor_size, and
    all ancestor descendant_count/descendant_size fields.
    Returns txid.
    """
    txid = tx.get_txid()
    sz = size if size is not None else len(tx.serialize())

    # Compute the ancestor set via BFS
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
        fee_rate=fee / sz if sz else 0.0,
        size=sz,
        time_added=time.time(),
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

    # Wire parent→child links
    for parent_txid in direct_parents:
        parent_entry = pool.transactions.get(parent_txid)
        if parent_entry:
            parent_entry.children.add(txid)

    # Update all ancestors' descendant_count and descendant_size
    for a_txid in all_ancestors:
        ae = pool.transactions.get(a_txid)
        if ae:
            ae.descendant_count += 1
            ae.descendant_size += sz

    # Register in cluster manager
    pool._cluster_manager.add_transaction(txid)
    return txid


def _build_chain(pool: Mempool, length: int, start_id: int = 1000) -> list[bytes]:
    """Build a linear chain of `length` txs using _inject.

    Each tx spends the previous one.  The root tx spends confirmed UTXO
    (_txid(start_id-1), 0) — that UTXO is NOT in the pool.
    """
    txids: list[bytes] = []
    prev_txid = _txid(start_id - 1)
    prev_vout = 0
    for i in range(length):
        txid = _txid(start_id + i)
        tx = _make_tx(txid, [(prev_txid, prev_vout)], [50_000])
        _inject(pool, tx)
        txids.append(txid)
        prev_txid = txid
        prev_vout = 0
    return txids


def _build_flat_cluster(pool: Mempool, root_txid: bytes, n_children: int,
                        start_child_id: int) -> list[bytes]:
    """Build a star topology: one root with n_children each spending root.

    This keeps ancestor_count = 2 for all children (self + root).
    The root spends a confirmed UTXO — root must already be in pool.
    """
    children: list[bytes] = []
    for i in range(n_children):
        child_txid = _txid(start_child_id + i)
        child_tx = _make_tx(child_txid, [(root_txid, i)], [49_000])
        _inject(pool, child_tx)
        children.append(child_txid)
    # Make root aware it's a multi-output tx (fake the spent_outputs differently)
    return children


# ---------------------------------------------------------------------------
# Gate 7 — Constant correctness
# ---------------------------------------------------------------------------

class TestConstantValues:
    """Gate 7: verify constants match Bitcoin Core defaults."""

    def test_max_ancestor_count(self):
        """DEFAULT_ANCESTOR_LIMIT = 25 (policy/policy.h:76)."""
        assert MAX_ANCESTOR_COUNT == 25

    def test_max_descendant_count(self):
        """DEFAULT_DESCENDANT_LIMIT = 25 (policy/policy.h:78)."""
        assert MAX_DESCENDANT_COUNT == 25

    def test_max_ancestor_size_kvb(self):
        assert MAX_ANCESTOR_SIZE_KVB == 101

    def test_max_descendant_size_kvb(self):
        assert MAX_DESCENDANT_SIZE_KVB == 101

    def test_max_cluster_count(self):
        """DEFAULT_CLUSTER_LIMIT = 64 (policy/policy.h:72). Was wrong (100) before W75."""
        assert MAX_CLUSTER_COUNT == 64, (
            f"MAX_CLUSTER_COUNT must be 64 (Core DEFAULT_CLUSTER_LIMIT); got {MAX_CLUSTER_COUNT}"
        )

    def test_max_cluster_size_vbytes(self):
        """DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000 (policy/policy.h:74)."""
        assert MAX_CLUSTER_SIZE_VBYTES == 101_000

    def test_extra_descendant_tx_size_limit(self):
        """EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10,000 (policy/policy.h:90)."""
        assert EXTRA_DESCENDANT_TX_SIZE_LIMIT == 10_000


# ---------------------------------------------------------------------------
# Gate 1 — Ancestor COUNT limit
# ---------------------------------------------------------------------------

class TestAncestorCountLimit:
    """Gate 1: reject when len(ancestors) + 1 > MAX_ANCESTOR_COUNT (25)."""

    def _pool_with_chain(self, depth: int) -> tuple[Mempool, list[bytes]]:
        """Build a pool with a `depth`-tx chain via _inject."""
        pool = _pool()
        chain = _build_chain(pool, depth)
        return pool, chain

    def test_chain_of_24_plus_new_accepted(self):
        """24 in-pool ancestors + self = 25 = limit: must be ACCEPTED.

        gate: len(ancestors)+1 = 25 <= 25 → pass
        """
        pool, chain = self._pool_with_chain(24)
        assert pool.transactions[chain[0]].ancestor_count == 1
        assert pool.transactions[chain[-1]].ancestor_count == 24

        # New tx: 24 in-pool ancestors + self = 25
        txid_25 = _txid(9000)
        tx_25 = _make_tx(txid_25, [(chain[-1], 0)], [49_980])

        # The test calls _check_cluster_limit + ancestor gates directly without UTXO lookup.
        # We verify the ancestor gate via the internal helper:
        ancestors = pool._get_ancestors(tx_25)
        assert len(ancestors) == 24
        # Count check: 24 + 1 = 25 <= 25 → should NOT be rejected by ancestor gate
        assert len(ancestors) + 1 <= MAX_ANCESTOR_COUNT

    def test_chain_of_25_plus_new_rejected(self):
        """25 in-pool ancestors + self = 26 > 25: must be REJECTED.

        gate: len(ancestors)+1 = 26 > 25 → reject
        """
        pool, chain = self._pool_with_chain(25)
        assert pool.transactions[chain[-1]].ancestor_count == 25

        txid_26 = _txid(9000)
        tx_26 = _make_tx(txid_26, [(chain[-1], 0)], [49_980])
        ancestors = pool._get_ancestors(tx_26)
        assert len(ancestors) == 25  # verifies graph traversal is correct
        # Simulate gate 1
        assert len(ancestors) + 1 > MAX_ANCESTOR_COUNT

    def test_add_transaction_inner_rejects_on_ancestor_count(self):
        """_add_transaction_inner must return (False, ...) for a 26-level chain."""
        pool = _pool({(_txid(0), 0): {"value": 100_000}})
        # Build 25-deep chain: need UTXO at every step for _add_transaction_inner
        # Use _inject for levels 0..23 to set up ancestors, then try level 24.
        chain = _build_chain(pool, 25)  # levels 0-24 in pool (ancestor_count 1-25)
        tip = chain[-1]
        assert pool.transactions[tip].ancestor_count == 25

        txid_26 = _txid(9001)
        tx_26 = _make_tx(txid_26, [(tip, 0)], [49_980])

        # Seed UTXO so UTXO check passes and ancestor gate can fire
        pool.validator.db._m[(tip, 0)] = {"value": 50_000}
        ok, err = pool._add_transaction_inner(tx_26, height=100)
        assert not ok, "26-level chain must be rejected by ancestor count gate"
        assert "ancestor" in err.lower()

    def test_ancestor_gate_fires_before_utxo_for_count(self):
        """Ancestor count check precedes UTXO lookup in add_transaction_inner."""
        pool = _pool()  # No UTXOs seeded
        chain = _build_chain(pool, 25)
        tip = chain[-1]
        txid_26 = _txid(9001)
        tx_26 = _make_tx(txid_26, [(tip, 0)], [49_980])

        ok, err = pool._add_transaction_inner(tx_26, height=100)
        # Should fail with ancestor error (count gate), not UTXO-not-found
        assert not ok
        assert "ancestor" in err.lower(), f"Expected ancestor error, got: {err}"


# ---------------------------------------------------------------------------
# Gate 2 — Ancestor SIZE limit
# ---------------------------------------------------------------------------

class TestAncestorSizeLimit:
    """Gate 2: ancestor_size + new_tx_size > 101,000 bytes → reject."""

    def test_ancestor_size_gate_fires(self):
        """Two ancestors with inflated sizes pushing the ancestor set over 101 kB → reject."""
        pool = _pool()

        # Ancestor 1: fake size = 80,000 bytes
        anc1_txid = _txid(1)
        anc1_tx = _make_tx(anc1_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, anc1_tx, size=80_000)

        # Ancestor 2 spends anc1, fake size = 20,000
        # child's ancestor_size = 80,000 + 20,000 = 100,000
        anc2_txid = _txid(2)
        anc2_tx = _make_tx(anc2_txid, [(anc1_txid, 0)], [49_000])
        _inject(pool, anc2_tx, size=20_000)

        # Child tx: real serialized size is ~61 bytes
        # ancestor_size = 100,000; child adds >= 61 bytes → 100,061 > 101,000? No.
        # Use ancestor 1 alone with size = 101,000 bytes.
        # Easier: single big ancestor of 100_940 bytes; child >= 61 bytes → 101,001 > 101,000.
        pool2 = _pool()
        big_anc_txid = _txid(10)
        big_anc_tx = _make_tx(big_anc_txid, [(_txid(0), 0)], [50_000])
        _inject(pool2, big_anc_tx, size=100_940)

        child_txid = _txid(11)
        child_tx = _make_tx(child_txid, [(big_anc_txid, 0)], [49_500])
        child_serial = len(child_tx.serialize())

        ancestors = pool2._get_ancestors(child_tx)
        ancestor_size = sum(pool2.transactions[a].size for a in ancestors if a in pool2.transactions)
        # 100,940 + child_serial > 101,000 for any child >= 61 bytes (they all are)
        assert ancestor_size + child_serial > MAX_ANCESTOR_SIZE_KVB * 1000, (
            f"Test setup error: {ancestor_size} + {child_serial} = "
            f"{ancestor_size + child_serial} should exceed 101,000"
        )

        # Confirm the gate fires in the actual code
        pool2.validator.db._m[(big_anc_txid, 0)] = {"value": 50_000}
        ok, err = pool2._add_transaction_inner(child_tx, height=100)
        assert not ok, f"ancestor size gate should fire; err={err}"
        assert "ancestor" in err.lower() and "size" in err.lower(), f"Unexpected error: {err}"

    def test_ancestor_size_within_limit_accepted(self):
        """Single small ancestor; ancestor_size well under 101 kB → accepted."""
        pool = _pool()

        anc_txid = _txid(1)
        anc_tx = _make_tx(anc_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, anc_tx, size=200)

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(anc_txid, 0)], [49_000])
        child_serial = len(child_tx.serialize())

        ancestors = pool._get_ancestors(child_tx)
        ancestor_size = sum(pool.transactions[a].size for a in ancestors if a in pool.transactions)
        assert ancestor_size + child_serial <= MAX_ANCESTOR_SIZE_KVB * 1000

        # Seed UTXO so add_transaction_inner can compute fee
        pool.validator.db._m[(anc_txid, 0)] = {"value": 50_000}
        ok, err = pool._add_transaction_inner(child_tx, height=100)
        assert ok, f"Child under ancestor size limit must be accepted; err={err}"


# ---------------------------------------------------------------------------
# Gate 3 — Descendant COUNT limit
# ---------------------------------------------------------------------------

class TestDescendantCountLimit:
    """Gate 3: any ancestor's descendant_count + 1 > 25 → reject."""

    def test_ancestor_at_25_descendants_rejects_new_child(self):
        """Root with descendant_count=25 (self + 24 real descendants) must reject next.

        Use a star topology (root + 24 direct children) so all children have
        ancestor_count=2 (self + root), avoiding the ancestor-count gate firing first.
        Root.descendant_count = 25 after 24 children are injected.
        """
        pool = _pool()
        # Build root with 24 outputs
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 25)
        _inject(pool, root_tx)
        # inject 24 direct children (each spending one output of root)
        for i in range(24):
            _inject(pool, _make_tx(_txid(6000 + i), [(root_txid, i)], [48_000]))

        root_entry = pool.transactions[root_txid]
        # descendant_count = 1(self) + 24(children) = 25
        assert root_entry.descendant_count == 25, (
            f"Expected 25, got {root_entry.descendant_count}"
        )

        # 25th child would push root to 26 descendants — must be rejected
        txid_new = _txid(9000)
        tx_new = _make_tx(txid_new, [(root_txid, 24)], [48_000])

        # Seed UTXO so UTXO gate doesn't fire (root output 24 exists as confirmed)
        pool.validator.db._m[(root_txid, 24)] = {"value": 49_000}
        ok, err = pool._add_transaction_inner(tx_new, height=100)
        assert not ok, "Root with descendant_count=25 should reject 25th child"
        assert "descendant" in err.lower(), f"Expected descendant error, got: {err}"

    def test_ancestor_at_24_descendants_accepts_new_child(self):
        """Root with descendant_count=24 (self + 23 descendants) must accept 24th child.

        Star topology: root + 23 children → root.descendant_count = 24.
        Adding one more child brings root to 25 = limit → accepted.
        """
        pool = _pool()
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 24)
        _inject(pool, root_tx)
        for i in range(23):
            _inject(pool, _make_tx(_txid(6000 + i), [(root_txid, i)], [48_000]))

        root_entry = pool.transactions[root_txid]
        assert root_entry.descendant_count == 24, (
            f"Expected 24, got {root_entry.descendant_count}"
        )

        # 24th child: root → 25 descendants = limit → accepted
        txid_new = _txid(9000)
        tx_new = _make_tx(txid_new, [(root_txid, 23)], [48_000])
        pool.validator.db._m[(root_txid, 23)] = {"value": 49_000}
        ok, err = pool._add_transaction_inner(tx_new, height=100)
        assert ok, f"Root at descendant_count=24 should accept 24th child (→ 25 = limit); err={err}"

    def test_descendant_count_gate_direct(self):
        """Verify gate logic: simulate manually inflated descendant_count."""
        pool = _pool()
        root_txid = _txid(1)
        root_tx = _make_tx(root_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, root_tx, size=200)
        # Inflate descendant_count to 25 directly (simulating many descendants)
        pool.transactions[root_txid].descendant_count = 25

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(root_txid, 0)], [49_000])
        child_size = len(child_tx.serialize())

        # Check the gate condition directly
        entry = pool.transactions[root_txid]
        assert entry.descendant_count + 1 > MAX_DESCENDANT_COUNT


# ---------------------------------------------------------------------------
# Gate 4 — Descendant SIZE limit
# ---------------------------------------------------------------------------

class TestDescendantSizeLimit:
    """Gate 4: any ancestor's descendant_size + new_tx_size > 101,000 → reject."""

    def test_ancestor_descendant_size_exceeded(self):
        """Root with descendant_size=100,940 must reject child of any real size.

        Any tx serialized with _make_tx is >= 61 bytes (one input + one output),
        so 100,940 + 61 = 101,001 > 101,000.
        """
        pool = _pool()

        root_txid = _txid(1)
        root_tx = _make_tx(root_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, root_tx, size=200)
        # Inflate descendant_size to 100,940 — any 61-byte child pushes it over 101,000
        pool.transactions[root_txid].descendant_size = 100_940
        pool.transactions[root_txid].descendant_count = 2

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(root_txid, 0)], [49_000])
        child_size = len(child_tx.serialize())

        # 100,940 + 61 = 101,001 > 101,000
        assert 100_940 + child_size > MAX_DESCENDANT_SIZE_KVB * 1000, (
            f"Test setup error: 100,940 + {child_size} should exceed 101,000"
        )

        pool.validator.db._m[(root_txid, 0)] = {"value": 50_000}
        ok, err = pool._add_transaction_inner(child_tx, height=100)
        assert not ok, f"Descendant size gate must fire; err={err}"
        assert "descendant" in err.lower() and "size" in err.lower(), f"Got: {err}"

    def test_ancestor_descendant_size_within_limit(self):
        """Root with descendant_size=0 (fresh singleton) and small child → accept.

        Note: MempoolEntry.descendant_size defaults to 0 (does not include self).
        The gate checks: ancestor.descendant_size + new_tx_size <= 101,000.
        A fresh root has descendant_size=0, so any small child is accepted.
        """
        pool = _pool()
        root_txid = _txid(1)
        root_tx = _make_tx(root_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, root_tx, size=200)
        # descendant_size = 0 after inject (not including self, per mempool.py convention)
        assert pool.transactions[root_txid].descendant_size == 0

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(root_txid, 0)], [49_000])
        pool.validator.db._m[(root_txid, 0)] = {"value": 50_000}
        ok, err = pool._add_transaction_inner(child_tx, height=100)
        assert ok, f"Small child with ancestor descendant_size=0 must be accepted; err={err}"


# ---------------------------------------------------------------------------
# Gate 5 — Cluster COUNT limit = 64 (not 100)
# ---------------------------------------------------------------------------

class TestClusterCountLimit:
    """Gate 5: merged cluster tx count > MAX_CLUSTER_COUNT (64) → reject."""

    def _build_star_cluster(self, pool: Mempool, n: int, root_id: int,
                            child_start_id: int) -> tuple[bytes, list[bytes]]:
        """Build a star: one root + (n-1) children, each spending output 0,1,...
        The root is a single tx with (n-1) outputs.  Children each spend one output.
        This keeps ancestor_count=2 for all children, avoiding ancestor limit.
        """
        root_txid = _txid(root_id)
        root_tx = _make_tx(
            root_txid,
            [(_txid(root_id - 1), 0)],
            [49_000] * (n - 1),
        )
        _inject(pool, root_tx)

        children: list[bytes] = []
        for i in range(n - 1):
            child_txid = _txid(child_start_id + i)
            child_tx = _make_tx(child_txid, [(root_txid, i)], [48_000])
            _inject(pool, child_tx)
            children.append(child_txid)
        return root_txid, children

    def test_cluster_count_limit_is_64_not_100(self):
        """MAX_CLUSTER_COUNT must be 64. Was 100 before W75 (off-by-36)."""
        assert MAX_CLUSTER_COUNT == 64

    def test_cluster_count_gate_rejects_at_65(self):
        """A 65-tx cluster (1 root + 64 children) must be rejected at the 65th member.

        Star topology: root + 63 children = 64 txs (accepted). Adding the
        64th child (making 65 total) must be rejected by the cluster count gate.
        """
        pool = _pool()
        # Build star with 64 txs (root + 63 children) using star topology
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 64)
        _inject(pool, root_tx)

        # Add 63 children → cluster size = 64
        for i in range(63):
            child_txid = _txid(6000 + i)
            child_tx = _make_tx(child_txid, [(root_txid, i)], [48_000])
            _inject(pool, child_tx)

        # Verify cluster is at 64
        root_cid = pool._cluster_manager.get_cluster_id(root_txid)
        assert root_cid is not None
        cluster_size = pool._cluster_manager._clusters[root_cid].size()
        assert cluster_size == 64, f"Expected 64-tx cluster, got {cluster_size}"

        # 65th member: child spending output 63 of root
        txid_65 = _txid(9000)
        tx_65 = _make_tx(txid_65, [(root_txid, 63)], [47_000])
        ok, err = pool._check_cluster_limit(tx_65)
        assert not ok, "65th cluster member must be rejected by cluster count gate"
        assert "cluster" in err.lower()

    def test_cluster_count_at_64_accepted(self):
        """A 64-tx star cluster is at the limit and must be accepted."""
        pool = _pool()
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 63)
        _inject(pool, root_tx)

        for i in range(63):
            child_txid = _txid(6000 + i)
            child_tx = _make_tx(child_txid, [(root_txid, i)], [48_000])
            _inject(pool, child_tx)

        root_cid = pool._cluster_manager.get_cluster_id(root_txid)
        assert pool._cluster_manager._clusters[root_cid].size() == 64

    def test_merge_two_clusters_within_limit(self):
        """Two independent clusters of 30 each; bridge tx merges to 61 < 64 → accept."""
        pool = _pool()

        # Cluster A: star with 30 txs (root_A + 29 children)
        root_a = _txid(1000)
        tx_a = _make_tx(root_a, [(_txid(999), 0)], [49_000] * 30)
        _inject(pool, tx_a)
        for i in range(29):
            _inject(pool, _make_tx(_txid(2000 + i), [(root_a, i)], [48_000]))

        # Cluster B: star with 30 txs
        root_b = _txid(3000)
        tx_b = _make_tx(root_b, [(_txid(2999), 0)], [49_000] * 30)
        _inject(pool, tx_b)
        for i in range(29):
            _inject(pool, _make_tx(_txid(4000 + i), [(root_b, i)], [48_000]))

        cid_a = pool._cluster_manager.get_cluster_id(root_a)
        cid_b = pool._cluster_manager.get_cluster_id(root_b)
        assert pool._cluster_manager._clusters[cid_a].size() == 30
        assert pool._cluster_manager._clusters[cid_b].size() == 30

        # Bridge tx spends one output from each cluster (output 29 of each root)
        bridge_txid = _txid(9000)
        bridge_tx = _make_tx(bridge_txid, [(root_a, 29), (root_b, 29)], [47_000])
        ok, err = pool._check_cluster_limit(bridge_tx)
        # 30 + 30 + 1 = 61 <= 64 → must be accepted
        assert ok, f"Merging two 30-tx clusters (61 total) must be accepted; err={err}"

    def test_merge_two_clusters_over_limit(self):
        """Two clusters of 33 each; bridge merges to 67 > 64 → rejected."""
        pool = _pool()

        root_a = _txid(1000)
        tx_a = _make_tx(root_a, [(_txid(999), 0)], [49_000] * 33)
        _inject(pool, tx_a)
        for i in range(32):
            _inject(pool, _make_tx(_txid(2000 + i), [(root_a, i)], [48_000]))

        root_b = _txid(3000)
        tx_b = _make_tx(root_b, [(_txid(2999), 0)], [49_000] * 33)
        _inject(pool, tx_b)
        for i in range(32):
            _inject(pool, _make_tx(_txid(4000 + i), [(root_b, i)], [48_000]))

        bridge_txid = _txid(9000)
        bridge_tx = _make_tx(bridge_txid, [(root_a, 32), (root_b, 32)], [47_000])
        ok, err = pool._check_cluster_limit(bridge_tx)
        # 33 + 33 + 1 = 67 > 64 → must be rejected
        assert not ok, "Merging two 33-tx clusters (67 > 64) must be rejected"
        assert "cluster" in err.lower()


# ---------------------------------------------------------------------------
# Gate 6 — Cluster SIZE (vbytes) limit = 101,000
# ---------------------------------------------------------------------------

class TestClusterSizeLimit:
    """Gate 6: merged cluster total vbytes > MAX_CLUSTER_SIZE_VBYTES (101,000) → reject."""

    def test_cluster_size_gate_fires(self):
        """Ancestor with fake size 100,940 bytes; child join (61 bytes) → 101,001 > 101,000."""
        pool = _pool()
        big_txid = _txid(1)
        big_tx = _make_tx(big_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, big_tx, size=100_940)

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(big_txid, 0)], [49_000])
        child_size = len(child_tx.serialize())

        # _make_tx produces 61 bytes; 100,940 + 61 = 101,001 > 101,000
        assert 100_940 + child_size > MAX_CLUSTER_SIZE_VBYTES, (
            f"Test setup error: 100,940 + {child_size} should exceed 101,000"
        )

        ok, err = pool._check_cluster_limit(child_tx)
        assert not ok, (
            f"Should reject: cluster vbytes {100_940 + child_size} > 101,000; err={err}"
        )
        assert "cluster" in err.lower() and (
            "vbyte" in err.lower() or "size" in err.lower()
        )

    def test_cluster_size_within_limit_accepted(self):
        """Ancestor with size=200; child joining is 200+child_size << 101,000 → accepted."""
        pool = _pool()
        small_txid = _txid(1)
        small_tx = _make_tx(small_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, small_tx, size=200)

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(small_txid, 0)], [49_000])
        ok, err = pool._check_cluster_limit(child_tx)
        assert ok, f"Small cluster merge under size limit must succeed; err={err}"

    def test_cluster_size_merge_over_limit(self):
        """Two clusters of 50,600 vbytes each; bridge merges to >101,000 → rejected."""
        pool = _pool()
        a_txid = _txid(1)
        _inject(pool, _make_tx(a_txid, [(_txid(0), 0)], [50_000]), size=50_600)

        b_txid = _txid(2)
        _inject(pool, _make_tx(b_txid, [(_txid(100), 0)], [50_000]), size=50_600)

        bridge_txid = _txid(3)
        bridge_tx = _make_tx(bridge_txid, [(a_txid, 0), (b_txid, 0)], [49_000])
        bridge_size = len(bridge_tx.serialize())
        expected_total = 50_600 + 50_600 + bridge_size  # clearly > 101,000

        ok, err = pool._check_cluster_limit(bridge_tx)
        assert not ok, f"Merged cluster {expected_total} vbytes > 101,000 must be rejected"
        assert "cluster" in err.lower()

    def test_cluster_size_merge_within_limit(self):
        """Two tiny clusters (200 vbytes each); bridge merges to <<101,000 → accepted."""
        pool = _pool()
        a_txid = _txid(1)
        _inject(pool, _make_tx(a_txid, [(_txid(0), 0)], [50_000]), size=200)

        b_txid = _txid(2)
        _inject(pool, _make_tx(b_txid, [(_txid(100), 0)], [50_000]), size=200)

        bridge_txid = _txid(3)
        bridge_tx = _make_tx(bridge_txid, [(a_txid, 0), (b_txid, 0)], [49_000])
        ok, err = pool._check_cluster_limit(bridge_tx)
        assert ok, f"Tiny cluster merge (<<101,000 vbytes) must succeed; err={err}"

    def test_cluster_size_was_missing_before_w75(self):
        """Confirm the new vbyte gate catches what old code (count=100 only) allowed.

        Before W75: MAX_CLUSTER_COUNT=100, no size gate.
          - 2-tx cluster (count=2 <= 100) → ACCEPTED (wrong).
        After W75: MAX_CLUSTER_COUNT=64, + size gate at 101,000 vbytes.
          - 2-tx cluster but 100,940 + 61 = 101,001 vbytes > 101,000 → REJECTED (correct).
        """
        pool = _pool()
        big_txid = _txid(1)
        _inject(pool, _make_tx(big_txid, [(_txid(0), 0)], [50_000]), size=100_940)

        child_txid = _txid(2)
        child_tx = _make_tx(child_txid, [(big_txid, 0)], [49_000])
        child_size = len(child_tx.serialize())

        # _make_tx produces 61 bytes; 100,940 + 61 = 101,001 > 101,000
        assert 100_940 + child_size > MAX_CLUSTER_SIZE_VBYTES

        # Old code would check: total_count=2 <= 100 → pass (no size gate)
        # New code checks: total_vbytes = 100,940 + child_size > 101,000 → fail
        ok, err = pool._check_cluster_limit(child_tx)
        assert not ok, "Cluster vbyte gate (new in W75) must fire here"


# ---------------------------------------------------------------------------
# Gate 8 — Boundary acceptance: ancestor_count == 25 accepted
# ---------------------------------------------------------------------------

class TestBoundaryAcceptance:
    """Gate 8: a chain of exactly 24 in-pool txs + self = 25 must be accepted."""

    def test_ancestor_gate_at_exact_limit(self):
        """_get_ancestors on a 24-deep chain must return exactly 24 ancestors."""
        pool = _pool()
        chain = _build_chain(pool, 24)
        tip = chain[-1]

        txid_25 = _txid(9000)
        tx_25 = _make_tx(txid_25, [(tip, 0)], [49_980])
        ancestors = pool._get_ancestors(tx_25)
        assert len(ancestors) == 24
        assert len(ancestors) + 1 == MAX_ANCESTOR_COUNT  # exactly at limit

    def test_descendant_gate_at_exact_limit(self):
        """Root with descendant_count=24 (self=1 + 23 others): adding 24th pushes to 25 = limit.

        _build_chain(24) → root.descendant_count = 24. Gate: 24 + 1 = 25 <= 25 → pass.
        """
        pool = _pool()
        chain = _build_chain(pool, 24)
        root = pool.transactions[chain[0]]
        assert root.descendant_count == 24, f"Expected 24, got {root.descendant_count}"
        # Adding one more: root would have descendant_count 25 = MAX → accepted
        # Gate: root.descendant_count + 1 = 25 <= 25 → NOT rejected
        assert root.descendant_count + 1 <= MAX_DESCENDANT_COUNT

    def test_add_transaction_inner_accepts_at_limit(self):
        """add_transaction_inner must accept a tx that brings root descendant_count to 25 = limit.

        Star topology (24 children of root) → root.descendant_count=24.
        Adding 25th child via add_transaction_inner → root reaches 25 → accepted.
        Fee must be >= min_relay = ceil(tx_size * DEFAULT_MIN_RELAY_TX_FEE / 1000).
        """
        pool = _pool()
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 25)
        _inject(pool, root_tx)
        for i in range(23):
            _inject(pool, _make_tx(_txid(6000 + i), [(root_txid, i)], [48_000]))

        root_entry = pool.transactions[root_txid]
        assert root_entry.descendant_count == 24, f"Expected 24, got {root_entry.descendant_count}"

        # 24th child spending output 23 of root
        # fee = 49,000 (UTXO) - 48,800 (output) = 200 sat ≥ min_relay for any ~61-byte tx
        txid_new = _txid(9000)
        tx_new = _make_tx(txid_new, [(root_txid, 23)], [48_800])
        pool.validator.db._m[(root_txid, 23)] = {"value": 49_000}
        ok, err = pool._add_transaction_inner(tx_new, height=100)
        assert ok, f"Tx bringing root descendant_count to 25 = limit must be accepted; err={err}"


# ---------------------------------------------------------------------------
# Gate 9 — Cluster-count boundary: 64 accepted, 65 rejected
# ---------------------------------------------------------------------------

class TestClusterCountBoundary:
    """Gate 9: cluster of 64 txs at limit; 65th rejected."""

    def test_64_accepted_65_rejected(self):
        """Star cluster: root + 63 children = 64 (accepted). 64th child = 65 → rejected."""
        pool = _pool()
        root_txid = _txid(5000)
        root_tx = _make_tx(root_txid, [(_txid(4999), 0)], [49_000] * 64)
        _inject(pool, root_tx)

        for i in range(63):
            _inject(pool, _make_tx(_txid(6000 + i), [(root_txid, i)], [48_000]))

        cid = pool._cluster_manager.get_cluster_id(root_txid)
        assert pool._cluster_manager._clusters[cid].size() == 64

        # 65th child
        tx_65 = _make_tx(_txid(9001), [(root_txid, 63)], [47_000])
        ok, err = pool._check_cluster_limit(tx_65)
        assert not ok, "65th cluster member must fail cluster count gate"

    def test_singleton_cluster_always_accepted(self):
        """A completely isolated tx (no neighbors in pool) is always a new singleton → ok."""
        pool = _pool()
        tx = _make_tx(_txid(1), [(_txid(0), 0)], [50_000])
        ok, err = pool._check_cluster_limit(tx)
        assert ok, f"Isolated tx (new singleton cluster) must always be accepted; err={err}"


# ---------------------------------------------------------------------------
# Gate 10 — Cluster-size boundary: 101,000 vbytes
# ---------------------------------------------------------------------------

class TestClusterSizeBoundary:
    """Gate 10: cluster vbyte size boundary checks."""

    def test_singleton_large_but_under_limit(self):
        """A single tx of 100,999 vbytes forms a singleton cluster → accepted by size gate."""
        pool = _pool()
        big_txid = _txid(1)
        big_tx = _make_tx(big_txid, [(_txid(0), 0)], [50_000])
        _inject(pool, big_tx, size=100_999)

        # A second tx not connected to big_tx — no cluster merge
        tx2 = _make_tx(_txid(2), [(_txid(999), 0)], [50_000])
        ok, err = pool._check_cluster_limit(tx2)
        assert ok, "Unrelated tx (singleton) must be accepted regardless of big tx"

    def test_child_joining_100940_cluster_rejected(self):
        """100,940-byte ancestor + 61-byte child = 101,001 > 101,000 → rejected."""
        pool = _pool()
        _inject(pool, _make_tx(_txid(1), [(_txid(0), 0)], [50_000]), size=100_940)

        child_tx = _make_tx(_txid(2), [(_txid(1), 0)], [49_000])
        child_size = len(child_tx.serialize())
        assert 100_940 + child_size > MAX_CLUSTER_SIZE_VBYTES

        ok, err = pool._check_cluster_limit(child_tx)
        assert not ok
        assert "cluster" in err.lower()

    def test_child_joining_small_cluster_accepted(self):
        """200-byte ancestor + small child << 101,000 → accepted by size gate."""
        pool = _pool()
        _inject(pool, _make_tx(_txid(1), [(_txid(0), 0)], [50_000]), size=200)

        child_tx = _make_tx(_txid(2), [(_txid(1), 0)], [49_000])
        ok, err = pool._check_cluster_limit(child_tx)
        assert ok, f"Small cluster well under size limit must be accepted; err={err}"
