"""W78 — BIP-431 TRUC (v3 transaction) policy comprehensive audit.

6+3 gates from Bitcoin Core policy/truc_policy.cpp SingleTRUCChecks() and
PackageTRUCChecks():

SingleTRUCChecks (single-tx path):
  Gate 1  — Non-TRUC tx must not spend from TRUC (v3) mempool parent.
  Gate 2  — TRUC tx must not spend from non-TRUC mempool parent.
  Gate 3  — TRUC tx must be <= TRUC_MAX_VSIZE (10,000 vbytes, sigop-adjusted).
  Gate 4  — TRUC ancestor count including self must be <= TRUC_ANCESTOR_LIMIT (2).
  Gate 4b — In-mempool parent's own ancestor_count must leave room for the child.
  Gate 5  — TRUC child of unconfirmed parent must be <= TRUC_CHILD_MAX_VSIZE
             (1,000 vbytes, sigop-adjusted).
  Gate 6  — TRUC parent may have at most 1 unconfirmed child (TRUC_DESCENDANT_LIMIT=2).
  Gate 6a — Sibling eviction: single-child parent returns sibling txid for RBF
             consideration when topology is simple 1-parent-1-child.
  Gate 6b — direct_conflicts: if sibling is already conflicted (RBF in flight),
             descendant limit is not violated.

PackageTRUCChecks (package path — _check_package_truc_policy):
  Gate P1 — TRUC tx in package: vsize <= TRUC_MAX_VSIZE (sigop-adjusted).
  Gate P2 — TRUC tx in package: ancestor count (mempool+package+self) <= 2.
  Gate P3 — TRUC child in package: vsize <= TRUC_CHILD_MAX_VSIZE (sigop-adjusted).
  Gate P4 — TRUC parent in package or mempool must be v3.
  Gate P5 — No sibling allowed: only 1 child per TRUC parent across mempool+package.
  Gate P6 — No in-package grandchild: TRUC child cannot itself be a parent in-package.
  Gate P7 — Mempool TRUC parent must have no existing descendant.
  Gate P8 — Non-TRUC tx cannot spend TRUC mempool parent.
  Gate P9 — Non-TRUC tx cannot spend TRUC package parent.

Sigop-adjustment regression:
  Gate S1 — TRUC_MAX_VSIZE uses sigop-adjusted vsize (tx with many sigops).
  Gate S2 — TRUC_CHILD_MAX_VSIZE uses sigop-adjusted vsize.

Reference: bitcoin-core/src/policy/truc_policy.cpp, bitcoin/src/policy/truc_policy.h
BIP 431 — https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki
"""

from __future__ import annotations

import time

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    Mempool,
    MempoolEntry,
    TRUC_VERSION,
    TRUC_MAX_VSIZE,
    TRUC_CHILD_MAX_VSIZE,
    TRUC_ANCESTOR_LIMIT,
    TRUC_DESCENDANT_LIMIT,
    _compute_tx_sigop_cost,
)
from ouroboros.validation import (
    get_virtual_transaction_size,
    DEFAULT_BYTES_PER_SIGOP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _txid(tag: int) -> bytes:
    """Deterministic 32-byte txid from a small integer."""
    return tag.to_bytes(4, "little") + b"\x00" * 28


def _make_tx(
    txid: bytes,
    inputs: list[tuple[bytes, int]],
    outputs: list[int],
    version: int = 2,
    extra_script: bytes = b"",
) -> Transaction:
    """Build a Transaction with simple OP_TRUE outputs.

    extra_script is appended to the first input's script_sig to inflate size.
    """
    inputs_built = []
    for i, (pt, pv) in enumerate(inputs):
        sig = extra_script if i == 0 else b""
        inputs_built.append(
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=sig, sequence=0xFFFFFFFD)
        )
    return Transaction(
        txid=txid,
        version=version,
        locktime=0,
        inputs=inputs_built,
        outputs=[TxOut(value=v, script_pubkey=b"\x51") for v in outputs],
    )


def _make_v3(txid: bytes, inputs: list[tuple[bytes, int]], outputs: list[int], **kw) -> Transaction:
    """Shortcut for version=3 (TRUC) transaction."""
    return _make_tx(txid, inputs, outputs, version=3, **kw)


class _StubDB:
    def __init__(self, mapping: dict):
        self._m = mapping  # (txid, vout) -> {"value": int, "script_pubkey": bytes}

    def get_utxo(self, txid: bytes, vout: int):
        return self._m.get((txid, vout))


class _StubValidator:
    """Always-accept validator with a configurable UTXO set."""

    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0):
        return True, ""


def _pool(utxos: dict | None = None) -> Mempool:
    """Create a bare Mempool (require_standard=False, full_rbf=True)."""
    return Mempool(
        validator=_StubValidator(utxos or {}),
        require_standard=False,
        full_rbf=True,
    )


def _utxo(value: int, script_pubkey: bytes = b"\x51") -> dict:
    return {"value": value, "script_pubkey": script_pubkey}


def _inject(
    pool: Mempool,
    tx: Transaction,
    fee: int = 10_000,
    size: int | None = None,
) -> bytes:
    """Insert a MempoolEntry directly, correctly wiring parent/child links
    and ancestor/descendant counts.  Returns txid."""
    txid = tx.get_txid()
    sz = size if size is not None else len(tx.serialize())

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
        descendant_count=1,
        descendant_size=sz,
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
# Constant sanity checks
# ---------------------------------------------------------------------------

class TestConstants:
    """Verify constants match Core's truc_policy.h values."""

    def test_truc_version(self):
        assert TRUC_VERSION == 3

    def test_truc_ancestor_limit(self):
        assert TRUC_ANCESTOR_LIMIT == 2

    def test_truc_descendant_limit(self):
        assert TRUC_DESCENDANT_LIMIT == 2

    def test_truc_max_vsize(self):
        assert TRUC_MAX_VSIZE == 10_000

    def test_truc_child_max_vsize(self):
        assert TRUC_CHILD_MAX_VSIZE == 1_000


# ---------------------------------------------------------------------------
# Gate 1 — Non-TRUC tx must not spend from TRUC mempool parent
# ---------------------------------------------------------------------------

class TestGate1NonTRUCCannotSpendTRUCParent:
    """Core: truc_policy.cpp:180-184 (non-v3 spending v3 parent)."""

    def test_non_v3_spending_v3_parent_rejected(self):
        """A v2 tx spending a v3 mempool output is rejected."""
        parent_txid = _txid(1)
        pool = _pool({(_txid(0), 0): _utxo(100_000)})

        parent = _make_v3(parent_txid, [(_txid(0), 0)], [90_000])
        _inject(pool, parent)

        child = _make_tx(_txid(2), [(parent_txid, 0)], [80_000], version=2)
        ok, err, sibling = pool._check_truc_policy(child)
        assert not ok
        assert "non-version=3" in err
        assert sibling is None

    def test_non_v3_spending_confirmed_parent_ok(self):
        """A v2 tx spending a *confirmed* output is fine even if the UTXO
        was once a v3 transaction output (TRUC rule only cares about
        *unconfirmed* parents)."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        child = _make_tx(_txid(1), [(_txid(0), 0)], [90_000], version=2)
        ok, err, sibling = pool._check_truc_policy(child)
        assert ok

    def test_non_v3_multi_input_one_v3_parent_rejected(self):
        """Non-v3 tx with 2 inputs where only one is a v3 parent — rejected."""
        pool = _pool({(_txid(10), 0): _utxo(50_000), (_txid(10), 1): _utxo(50_000)})
        parent = _make_v3(_txid(10), [(_txid(0), 0)], [90_000])
        # Inject parent manually (doesn't need a real UTXO since we bypass)
        pool.transactions[_txid(10)] = MempoolEntry(
            tx=parent, fee=1000, fee_rate=10.0, size=100,
            time_added=time.time(), height_added=100,
        )

        # Child has two inputs: one from the v3 parent, one from chain UTXO
        child = _make_tx(
            _txid(2),
            [(_txid(10), 0), (_txid(99), 0)],
            [80_000],
            version=2,
        )
        ok, err, _ = pool._check_truc_policy(child)
        assert not ok
        assert "non-version=3" in err


# ---------------------------------------------------------------------------
# Gate 2 — TRUC tx must not spend from non-TRUC mempool parent
# ---------------------------------------------------------------------------

class TestGate2TRUCCannotSpendNonTRUCParent:
    """Core: truc_policy.cpp:185-190 (v3 spending non-v3 parent)."""

    def test_v3_spending_v2_parent_rejected(self):
        """A v3 tx spending a v2 mempool output is rejected."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_tx(_txid(1), [(_txid(0), 0)], [90_000], version=2)
        _inject(pool, parent)

        child = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        ok, err, _ = pool._check_truc_policy(child)
        assert not ok
        assert "non-version=3" in err

    def test_v3_spending_confirmed_output_ok(self):
        """A v3 tx spending only confirmed outputs has no inheritance violation."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        ok, err, _ = pool._check_truc_policy(tx)
        assert ok, err


# ---------------------------------------------------------------------------
# Gate 3 — TRUC tx must be <= TRUC_MAX_VSIZE (10,000 vbytes)
# ---------------------------------------------------------------------------

class TestGate3TRUCMaxVsize:
    """Core: truc_policy.cpp:200-204."""

    def test_v3_exactly_at_max_vsize_accepted(self):
        """A v3 tx at exactly TRUC_MAX_VSIZE vbytes is accepted."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        # Search for padding size that yields exactly TRUC_MAX_VSIZE vbytes.
        # The compact-size encoding of script_sig length adds overhead so we
        # can't compute this analytically; scan a wide window instead.
        target = TRUC_MAX_VSIZE
        for pad_size in range(target - 100, target + 100):
            tx = _make_v3(_txid(1), [(_txid(0), 0)], [1], extra_script=bytes(pad_size))
            tx_vsize = (tx.get_weight() + 3) // 4
            if tx_vsize == target:
                break
        else:
            pytest.skip(f"Could not craft tx of exactly {target} vbytes")
        ok, err, _ = pool._check_truc_policy(tx)
        assert ok, err

    def test_v3_one_byte_over_max_vsize_rejected(self):
        """A v3 tx one vbyte over TRUC_MAX_VSIZE is rejected."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        base_tx = _make_v3(_txid(1), [(_txid(0), 0)], [1])
        base_size = len(base_tx.serialize())
        pad = bytes(TRUC_MAX_VSIZE - base_size + 1)
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [1], extra_script=pad)
        ok, err, _ = pool._check_truc_policy(tx)
        assert not ok
        assert "too big" in err

    def test_non_v3_large_tx_not_gated(self):
        """A non-v3 tx over TRUC_MAX_VSIZE is not rejected by TRUC policy
        (only general standardness checks apply, which are disabled here)."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        pad = bytes(TRUC_MAX_VSIZE + 100)
        tx = _make_tx(_txid(1), [(_txid(0), 0)], [1], version=2, extra_script=pad)
        ok, err, _ = pool._check_truc_policy(tx)
        assert ok, f"TRUC policy must not reject non-v3 tx for size: {err}"


# ---------------------------------------------------------------------------
# Gate 4 — Ancestor count limit
# ---------------------------------------------------------------------------

class TestGate4AncestorLimit:
    """TRUC tx can have at most 1 unconfirmed ancestor (TRUC_ANCESTOR_LIMIT=2).
    Core: truc_policy.cpp:207-211."""

    def test_v3_no_ancestor_accepted(self):
        """v3 tx with only confirmed inputs: no ancestor limit issue."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        ok, err, _ = pool._check_truc_policy(tx)
        assert ok, err

    def test_v3_one_v3_ancestor_accepted(self):
        """v3 tx spending one v3 mempool parent: ancestor_count=2, accepted."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        _inject(pool, parent)

        child = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        ok, err, _ = pool._check_truc_policy(child)
        assert ok, err

    def test_v3_two_v3_ancestors_rejected(self):
        """v3 tx with 2 mempool parents: ancestor_count would be 3, rejected."""
        pool = _pool({(_txid(0), 0): _utxo(100_000), (_txid(10), 0): _utxo(50_000)})
        parent_a = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        parent_b = _make_v3(_txid(2), [(_txid(10), 0)], [40_000])
        _inject(pool, parent_a)
        _inject(pool, parent_b)

        grandchild = _make_v3(_txid(3), [(_txid(1), 0), (_txid(2), 0)], [100_000])
        ok, err, _ = pool._check_truc_policy(grandchild)
        assert not ok
        assert "too many ancestors" in err


# ---------------------------------------------------------------------------
# Gate 4b — In-mempool parent's ancestor count
# ---------------------------------------------------------------------------

class TestGate4bParentAncestorDepth:
    """If the in-mempool parent already has an unconfirmed ancestor of its own,
    adding a child would push the depth to 3.
    Core: truc_policy.cpp:217-220."""

    def test_grandparent_already_in_mempool_rejected(self):
        """Chain: grandparent(v3) → parent(v3) → child(v3) must be rejected
        because child would be at depth 3."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})

        grandparent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        parent = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, grandparent)
        _inject(pool, parent)

        child = _make_v3(_txid(3), [(_txid(2), 0)], [70_000])
        ok, err, _ = pool._check_truc_policy(child)
        assert not ok
        assert "too many ancestors" in err

    def test_parent_confirmed_grandparent_mempool_accepted(self):
        """Grandparent in mempool but parent is confirmed: child is at depth 1,
        accepted."""
        pool = _pool({(_txid(100), 0): _utxo(80_000)})
        # Only confirmed output → parent is _txid(100) which is NOT in mempool.
        child = _make_v3(_txid(3), [(_txid(100), 0)], [70_000])
        ok, err, _ = pool._check_truc_policy(child)
        assert ok, err


# ---------------------------------------------------------------------------
# Gate 5 — TRUC child max vsize (1,000 vbytes)
# ---------------------------------------------------------------------------

class TestGate5ChildMaxVsize:
    """TRUC child of an unconfirmed parent must be <= 1,000 vbytes.
    Core: truc_policy.cpp:223-227."""

    def test_child_exactly_1000_vbytes_accepted(self):
        """Child tx at exactly TRUC_CHILD_MAX_VSIZE is accepted."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        _inject(pool, parent)

        target = TRUC_CHILD_MAX_VSIZE
        for pad_size in range(max(0, target - 100), target + 100):
            child = _make_v3(_txid(2), [(_txid(1), 0)], [1], extra_script=bytes(pad_size))
            child_vsize = (child.get_weight() + 3) // 4
            if child_vsize == target:
                break
        else:
            pytest.skip(f"Could not craft child tx of exactly {target} vbytes")

        ok, err, _ = pool._check_truc_policy(child)
        assert ok, err

    def test_child_1001_vbytes_rejected(self):
        """Child tx one vbyte over TRUC_CHILD_MAX_VSIZE is rejected."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        _inject(pool, parent)

        base_child = _make_v3(_txid(2), [(_txid(1), 0)], [1])
        base_size = len(base_child.serialize())
        pad = bytes(TRUC_CHILD_MAX_VSIZE - base_size + 1)
        child = _make_v3(_txid(2), [(_txid(1), 0)], [1], extra_script=pad)

        ok, err, _ = pool._check_truc_policy(child)
        assert not ok
        assert "child" in err and "too big" in err

    def test_rootlevel_v3_tx_not_gated_by_child_limit(self):
        """A v3 tx with no unconfirmed parents is not subject to child limit
        (only TRUC_MAX_VSIZE applies)."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        # 5,000 vbytes — over child limit but under max vsize
        base_tx = _make_v3(_txid(1), [(_txid(0), 0)], [1])
        base_size = len(base_tx.serialize())
        pad = bytes(5_000 - base_size)
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [1], extra_script=pad)
        ok, err, _ = pool._check_truc_policy(tx)
        assert ok, err


# ---------------------------------------------------------------------------
# Gate 6 — Descendant count limit (one child only)
# ---------------------------------------------------------------------------

class TestGate6DescendantLimit:
    """TRUC parent may have at most 1 unconfirmed child.
    Core: truc_policy.cpp:243-258."""

    def test_second_child_rejected(self):
        """Adding a second child to a TRUC parent is rejected."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child1 = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, parent)
        _inject(pool, child1)

        child2 = _make_v3(_txid(3), [(_txid(1), 0)], [75_000])
        ok, err, _ = pool._check_truc_policy(child2)
        assert not ok
        assert "descendant count limit" in err


# ---------------------------------------------------------------------------
# Gate 6a — Sibling eviction topology
# ---------------------------------------------------------------------------

class TestGate6aSiblingEviction:
    """When the TRUC parent has exactly 1 child with no descendants of its own,
    the new child may evict the sibling via RBF.
    Core: truc_policy.cpp:249-257."""

    def test_sibling_txid_returned_for_simple_1p1c(self):
        """Simple 1-parent-1-child: sibling txid is returned for eviction."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child1 = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, parent)
        _inject(pool, child1)

        # Attempt to add a second child
        child2 = _make_v3(_txid(3), [(_txid(1), 0)], [75_000])
        ok, err, sibling = pool._check_truc_policy(child2)
        assert not ok
        assert "descendant count limit" in err
        assert sibling == _txid(2), "must return existing child txid for eviction"

    def test_no_sibling_eviction_when_sibling_has_child(self):
        """If the existing child itself has a child (shouldn't happen under TRUC
        but could happen due to reorg), sibling eviction is not offered."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child1 = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, parent)
        _inject(pool, child1)

        # Artificially give child1 a descendant (simulate post-reorg state)
        pool.transactions[_txid(2)].ancestor_count = 3  # makes it look deep
        # Reset to normal depth but push descendant_count of parent to 3
        pool.transactions[_txid(1)].descendant_count = 3  # 3 means: self+child+grandchild

        child2 = _make_v3(_txid(3), [(_txid(1), 0)], [75_000])
        ok, err, sibling = pool._check_truc_policy(child2)
        assert not ok
        # sibling should be None because parent.descendant_count != 2
        assert sibling is None, "no sibling eviction when topology is complex"


# ---------------------------------------------------------------------------
# Gate 6b — direct_conflicts avoids double-counting sibling
# ---------------------------------------------------------------------------

class TestGate6bDirectConflicts:
    """If the sibling is already in direct_conflicts (will be RBF'd), the
    descendant limit is not violated.
    Core: truc_policy.cpp:240-242."""

    def test_sibling_in_direct_conflicts_passes(self):
        """Child2 conflicts with child1 (RBF path): descendant limit waived."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child1 = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, parent)
        _inject(pool, child1)

        child2 = _make_v3(_txid(3), [(_txid(1), 0)], [75_000])
        # direct_conflicts contains child1 → sibling will be replaced by RBF
        ok, err, sibling = pool._check_truc_policy(
            child2, direct_conflicts={_txid(2)}
        )
        assert ok, f"should pass when sibling is a direct conflict: {err}"
        assert sibling is None

    def test_sibling_not_in_direct_conflicts_fails(self):
        """If the sibling is NOT in direct_conflicts, the limit is enforced."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child1 = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        _inject(pool, parent)
        _inject(pool, child1)

        child2 = _make_v3(_txid(3), [(_txid(1), 0)], [75_000])
        # direct_conflicts is empty — no RBF planned
        ok, err, _ = pool._check_truc_policy(child2, direct_conflicts=set())
        assert not ok
        assert "descendant count limit" in err


# ---------------------------------------------------------------------------
# Gate S1/S2 — Sigop-adjusted vsize used for TRUC limits
# ---------------------------------------------------------------------------

class TestSigopAdjustedVsize:
    """TRUC size gates must use sigop-adjusted vsize, not raw vsize.
    Core: truc_policy.cpp receives pre-computed sigop-adjusted int64_t vsize.
    Bug: previous code called tx.get_vsize() which ignores sigop adjustment."""

    def test_sigop_cost_inflates_vsize_for_max_check(self):
        """A v3 tx whose raw vsize is under TRUC_MAX_VSIZE but whose
        sigop-adjusted vsize is over must be rejected (Gate 3, sigop path)."""
        # DEFAULT_BYTES_PER_SIGOP = 20 means each sigop adds 20 vbytes of
        # virtual cost.  We need enough sigops to push a tx that is
        # (TRUC_MAX_VSIZE - N) bytes raw over the limit.
        #
        # We use OP_CHECKSIG in an output's script_pubkey for legacy sigop
        # counting.  WITNESS_SCALE_FACTOR=4 so each legacy sigop contributes
        # sigop_cost=4 and thus adds 4/20 * (sigop_adjusted_weight - raw_weight).
        #
        # Concretely: craft a tx with raw vsize = TRUC_MAX_VSIZE - 100,
        # then add 501 OP_CHECKSIG outputs (each adds 4 sigop_cost,
        # total sigop_cost = 2004, additional_vbytes = 2004*20//4 = 10020/4
        # -- actually the formula is get_virtual_transaction_size(weight, sigop_cost).
        #
        # get_virtual_transaction_size(weight, sigop_cost) =
        #   ceil(max(weight, sigop_cost * bytes_per_sigop) / 4)
        # So if sigop_cost * 20 > weight → sigop_cost drives the vsize.
        # We want sigop_cost * 20 > TRUC_MAX_VSIZE * 4.
        # => sigop_cost > TRUC_MAX_VSIZE * 4 / 20 = 2000.
        # Each OP_CHECKSIG in an output contributes 4 sigop_cost (legacy * 4).
        # => we need ceil(2001 / 4) = 501 OP_CHECKSIG outputs.

        pool = _pool({(_txid(0), 0): _utxo(1_000_000)})

        # Build tx with 501 OP_CHECKSIG outputs — sigop_cost = 501*4 = 2004
        # => adjusted vsize = ceil(2004 * 20 / 4) = ceil(10020) = 10020 > 10000
        outputs = [TxOut(value=1, script_pubkey=b"\xac") for _ in range(501)]  # OP_CHECKSIG
        tx = Transaction(
            txid=_txid(50),
            version=3,
            locktime=0,
            inputs=[TxIn(prev_txid=_txid(0), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=outputs,
        )

        raw_vsize = (tx.get_weight() + 3) // 4
        # Compute expected sigop-adjusted vsize
        sigop_cost = _compute_tx_sigop_cost(tx, lambda pt, pv: {"script_pubkey": b"\x51"})
        adj_vsize = get_virtual_transaction_size(tx.get_weight(), sigop_cost, DEFAULT_BYTES_PER_SIGOP)

        # Verify our setup: raw vsize should be under 10000, adj vsize over
        assert raw_vsize < TRUC_MAX_VSIZE, f"raw_vsize={raw_vsize} should be < {TRUC_MAX_VSIZE}"
        assert adj_vsize > TRUC_MAX_VSIZE, f"adj_vsize={adj_vsize} should be > {TRUC_MAX_VSIZE}"

        # _check_truc_policy with sigop_cost should reject
        ok, err, _ = pool._check_truc_policy(tx, sigop_cost=sigop_cost)
        assert not ok, (
            f"TRUC must reject tx with adj_vsize={adj_vsize} > TRUC_MAX_VSIZE={TRUC_MAX_VSIZE}; "
            f"raw_vsize={raw_vsize}"
        )
        assert "too big" in err

    def test_sigop_cost_zero_uses_raw_vsize(self):
        """With sigop_cost=0, vsize falls back to raw vsize (baseline check)."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        raw_vsize = (tx.get_weight() + 3) // 4
        assert raw_vsize < TRUC_MAX_VSIZE
        ok, err, _ = pool._check_truc_policy(tx, sigop_cost=0)
        assert ok, err

    def test_child_sigop_adjusted_vsize_gate(self):
        """Child of unconfirmed v3 parent: sigop-adjusted vsize above
        TRUC_CHILD_MAX_VSIZE must be rejected even if raw vsize is under it."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        _inject(pool, parent)

        # Build a child with enough OP_CHECKSIG outputs so that
        # sigop_cost * 20 > TRUC_CHILD_MAX_VSIZE * 4 = 4000.
        # => sigop_cost > 200; 51 OP_CHECKSIG outputs → sigop_cost = 204
        # adj_vsize = ceil(max(weight, 204*20) / 4) = ceil(max(weight,4080)/4)
        # For a small tx, weight < 4080, so adj_vsize = ceil(4080/4) = 1020 > 1000.
        outputs = [TxOut(value=1, script_pubkey=b"\xac") for _ in range(51)]
        child = Transaction(
            txid=_txid(2),
            version=3,
            locktime=0,
            inputs=[TxIn(prev_txid=_txid(1), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=outputs,
        )

        raw_vsize = (child.get_weight() + 3) // 4
        sigop_cost = _compute_tx_sigop_cost(child, lambda pt, pv: {"script_pubkey": b"\x51"})
        adj_vsize = get_virtual_transaction_size(child.get_weight(), sigop_cost, DEFAULT_BYTES_PER_SIGOP)

        assert raw_vsize < TRUC_CHILD_MAX_VSIZE, f"raw_vsize={raw_vsize}"
        assert adj_vsize > TRUC_CHILD_MAX_VSIZE, f"adj_vsize={adj_vsize}"

        ok, err, _ = pool._check_truc_policy(child, sigop_cost=sigop_cost)
        assert not ok, (
            f"child with adj_vsize={adj_vsize} > {TRUC_CHILD_MAX_VSIZE} must be rejected"
        )
        assert "child" in err and "too big" in err


# ---------------------------------------------------------------------------
# PackageTRUCChecks — _check_package_truc_policy
# ---------------------------------------------------------------------------

class TestPackageTRUCChecks:
    """Gate P1–P9: Bitcoin Core PackageTRUCChecks (truc_policy.cpp:57-169)."""

    # --- Gate P1: package TRUC tx max vsize ---

    def test_p1_v3_package_tx_too_large(self):
        """A v3 tx in a package over TRUC_MAX_VSIZE is rejected."""
        pool = _pool()
        base_tx = _make_v3(_txid(1), [(_txid(0), 0)], [1])
        base_size = len(base_tx.serialize())
        pad = bytes(TRUC_MAX_VSIZE - base_size + 1)
        big_tx = _make_v3(_txid(1), [(_txid(0), 0)], [1], extra_script=pad)
        ok, err = pool._check_package_truc_policy([big_tx])
        assert not ok
        assert "too big" in err

    def test_p1_v3_package_tx_at_limit_accepted(self):
        """A v3 tx in a package exactly at TRUC_MAX_VSIZE is accepted."""
        pool = _pool()
        target = TRUC_MAX_VSIZE
        for pad_size in range(target - 100, target + 100):
            tx = _make_v3(_txid(1), [(_txid(0), 0)], [1], extra_script=bytes(pad_size))
            if (tx.get_weight() + 3) // 4 == target:
                break
        else:
            pytest.skip(f"Could not craft tx of exactly {target} vbytes")
        ok, err = pool._check_package_truc_policy([tx])
        assert ok, err

    # --- Gate P2: ancestor count in package ---

    def test_p2_v3_child_in_package_with_two_parents_rejected(self):
        """v3 child with 2 parents in package: ancestor_count=3, rejected."""
        pool = _pool()
        pa = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        pb = _make_v3(_txid(2), [(_txid(10), 0)], [90_000])
        child = _make_v3(_txid(3), [(_txid(1), 0), (_txid(2), 0)], [100_000])
        ok, err = pool._check_package_truc_policy([pa, pb, child])
        assert not ok
        assert "too many ancestors" in err

    def test_p2_v3_child_with_one_package_parent_accepted(self):
        """v3 child with exactly 1 package parent is fine."""
        pool = _pool()
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        ok, err = pool._check_package_truc_policy([parent, child])
        assert ok, err

    # --- Gate P3: child max vsize ---

    def test_p3_v3_child_in_package_too_large(self):
        """v3 child of a package parent over 1,000 vbytes is rejected."""
        pool = _pool()
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        base = _make_v3(_txid(2), [(_txid(1), 0)], [1])
        pad = bytes(TRUC_CHILD_MAX_VSIZE - len(base.serialize()) + 1)
        big_child = _make_v3(_txid(2), [(_txid(1), 0)], [1], extra_script=pad)
        ok, err = pool._check_package_truc_policy([parent, big_child])
        assert not ok
        assert "child" in err and "too big" in err

    # --- Gate P4: parent must be TRUC ---

    def test_p4_v3_child_non_v3_package_parent_rejected(self):
        """v3 child of a non-v3 package parent is rejected."""
        pool = _pool()
        parent = _make_tx(_txid(1), [(_txid(0), 0)], [90_000], version=2)
        child = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        ok, err = pool._check_package_truc_policy([parent, child])
        assert not ok
        assert "non-version=3" in err

    def test_p4_v3_child_non_v3_mempool_parent_rejected(self):
        """v3 child of a non-v3 *mempool* parent is rejected."""
        pool = _pool()
        # Inject non-v3 parent into mempool
        mp_parent = _make_tx(_txid(1), [(_txid(0), 0)], [90_000], version=2)
        _inject(pool, mp_parent)

        child = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        ok, err = pool._check_package_truc_policy([child])
        assert not ok
        assert "non-version=3" in err

    # --- Gate P5: no sibling in package ---

    def test_p5_two_v3_children_same_parent_rejected(self):
        """Two v3 children of the same parent in the same package: rejected."""
        pool = _pool()
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        child_a = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        child_b = _make_v3(_txid(3), [(_txid(1), 0)], [79_000])
        ok, err = pool._check_package_truc_policy([parent, child_a, child_b])
        assert not ok
        assert "descendant count limit" in err

    # --- Gate P6: no in-package grandchild ---

    def test_p6_v3_grandchild_in_package_rejected(self):
        """A v3 tx can't be both a child of a package parent and have its own
        package child (3-level chain within one package)."""
        pool = _pool()
        gp = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        parent = _make_v3(_txid(2), [(_txid(1), 0)], [80_000])
        grandchild = _make_v3(_txid(3), [(_txid(2), 0)], [70_000])
        ok, err = pool._check_package_truc_policy([gp, parent, grandchild])
        assert not ok
        assert "too many ancestors" in err

    # --- Gate P7: mempool parent must have no existing descendant ---

    def test_p7_mempool_parent_already_has_child_rejected(self):
        """A package child of a mempool v3 parent that already has a descendant
        is rejected."""
        pool = _pool()
        mp_parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        existing_child = _make_v3(_txid(99), [(_txid(1), 0)], [80_000])
        _inject(pool, mp_parent)
        _inject(pool, existing_child)

        new_child = _make_v3(_txid(2), [(_txid(1), 0)], [75_000])
        ok, err = pool._check_package_truc_policy([new_child])
        assert not ok
        assert "descendant count limit" in err

    # --- Gate P8: non-TRUC tx cannot spend TRUC mempool parent ---

    def test_p8_non_v3_spending_v3_mempool_parent_rejected(self):
        """Non-v3 tx in package cannot spend a v3 mempool parent."""
        pool = _pool()
        mp_parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        _inject(pool, mp_parent)

        child = _make_tx(_txid(2), [(_txid(1), 0)], [80_000], version=2)
        ok, err = pool._check_package_truc_policy([child])
        assert not ok
        assert "non-version=3" in err

    # --- Gate P9: non-TRUC tx cannot spend TRUC package parent ---

    def test_p9_non_v3_spending_v3_package_parent_rejected(self):
        """Non-v3 tx in package cannot spend a v3 parent from the same package."""
        pool = _pool()
        v3_parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])
        non_v3_child = _make_tx(_txid(2), [(_txid(1), 0)], [80_000], version=2)
        ok, err = pool._check_package_truc_policy([v3_parent, non_v3_child])
        assert not ok
        assert "non-version=3" in err

    # --- Package sigop-adjusted vsize ---

    def test_package_sigop_adjusted_vsize_child_gate(self):
        """Package child whose sigop-adjusted vsize exceeds TRUC_CHILD_MAX_VSIZE
        must be rejected even if raw vsize is under the limit."""
        pool = _pool()
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [90_000])

        # 51 OP_CHECKSIG outputs: sigop_cost=204 → adj_vsize>1000
        outputs = [TxOut(value=1, script_pubkey=b"\xac") for _ in range(51)]
        child = Transaction(
            txid=_txid(2),
            version=3,
            locktime=0,
            inputs=[TxIn(prev_txid=_txid(1), prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=outputs,
        )
        raw_vsize = (child.get_weight() + 3) // 4
        assert raw_vsize < TRUC_CHILD_MAX_VSIZE

        ok, err = pool._check_package_truc_policy([parent, child])
        assert not ok, (
            f"package child with high sigop cost must be rejected; raw_vsize={raw_vsize}"
        )
        assert "child" in err and "too big" in err


# ---------------------------------------------------------------------------
# Integration: add_transaction with real UTXO set
# ---------------------------------------------------------------------------

class TestAddTransactionIntegration:
    """End-to-end tests using the full add_transaction path."""

    def test_v3_solo_tx_accepted(self):
        """A standalone v3 tx with confirmed inputs is accepted."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        tx = _make_v3(_txid(1), [(_txid(0), 0)], [99_000])
        ok, err = pool.add_transaction(tx, height=100)
        assert ok, err

    def test_v3_parent_child_pair_accepted(self):
        """A v3 parent followed by a v3 child is accepted (depth=2, OK)."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [99_000])
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, err

        pool.validator.db._m[(_txid(1), 0)] = _utxo(99_000)
        child = _make_v3(_txid(2), [(_txid(1), 0)], [98_000])
        ok, err = pool.add_transaction(child, height=100)
        assert ok, err

    def test_non_v3_cannot_spend_v3_mempool_parent_integration(self):
        """add_transaction rejects a v2 tx spending a v3 mempool parent."""
        pool = _pool({(_txid(0), 0): _utxo(100_000)})
        parent = _make_v3(_txid(1), [(_txid(0), 0)], [99_000])
        ok, _ = pool.add_transaction(parent, height=100)
        assert ok

        pool.validator.db._m[(_txid(1), 0)] = _utxo(99_000)
        child = _make_tx(_txid(2), [(_txid(1), 0)], [98_000], version=2)
        ok, err = pool.add_transaction(child, height=100)
        assert not ok
        assert "non-version=3" in err

    def test_v3_third_generation_rejected_integration(self):
        """Three-level v3 chain: grandchild is rejected."""
        pool = _pool({(_txid(0), 0): _utxo(200_000)})
        gp = _make_v3(_txid(1), [(_txid(0), 0)], [199_000])
        ok, err = pool.add_transaction(gp, height=100)
        assert ok, err

        pool.validator.db._m[(_txid(1), 0)] = _utxo(199_000)
        parent = _make_v3(_txid(2), [(_txid(1), 0)], [198_000])
        ok, err = pool.add_transaction(parent, height=100)
        assert ok, err

        pool.validator.db._m[(_txid(2), 0)] = _utxo(198_000)
        grandchild = _make_v3(_txid(3), [(_txid(2), 0)], [197_000])
        ok, err = pool.add_transaction(grandchild, height=100)
        assert not ok
        assert "ancestors" in err
