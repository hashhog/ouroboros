"""prefetch_utxos is a cache-warming hint: it must never change what a lookup returns.

Pins the three properties the perf change relies on:
  * values read after a parallel prefetch are identical to those of a DB that
    was never prefetched (same coins, same misses);
  * a prefetched MISS does not survive a later chainstate write (the read
    cache is invalidated by every commit, so a cached None cannot hide a coin);
  * BlockValidator._prefetch_block_inputs asks only for coins that can be in
    the chainstate (no coinbase input, no outpoint created in the same block)
    and is a no-op when disabled or when the backend lacks the method.
"""

import types

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

_real = real_sync_or_skip()
if not hasattr(_real.PyBlockchainDB, "prefetch_utxos"):
    pytest.skip("sync extension predates prefetch_utxos", allow_module_level=True)

from ouroboros.database import BlockchainDatabase  # noqa: E402
from ouroboros.validation import BlockValidator  # noqa: E402


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(_real):
        yield


def _txid(i: int) -> bytes:
    return i.to_bytes(4, "little") + bytes([0xA5]) * 28


def _fill(db: BlockchainDatabase, n: int) -> None:
    for i in range(n):
        db.add_utxo_raw(
            txid=_txid(i), vout=i % 3, amount=1000 + i,
            script_pubkey=bytes([0x51]) + i.to_bytes(2, "little"),
            height=100 + i, is_coinbase=(i % 7 == 0),
        )


def test_prefetch_returns_identical_values(tmp_path):
    n = 300
    a = BlockchainDatabase(str(tmp_path / "a"))
    b = BlockchainDatabase(str(tmp_path / "b"))
    _fill(a, n)
    _fill(b, n)
    present = [(_txid(i), i % 3) for i in range(n)]
    absent = [(_txid(i), 7) for i in range(50)] + [(bytes(32), 0xFFFFFFFF)]
    ops = present + absent

    found = a.prefetch_utxos(ops, 8)
    assert found == n

    got_a = [a.get_utxo(t, v) for t, v in ops]
    got_b = [b.get_utxo(t, v) for t, v in ops]  # never prefetched
    assert got_a == got_b
    assert sum(u is not None for u in got_a) == n
    assert a.get_utxo_batch(ops) == b.get_utxo_batch(ops)


def test_prefetched_miss_does_not_hide_later_write(tmp_path):
    db = BlockchainDatabase(str(tmp_path / "c"))
    op = (_txid(9999), 0)
    assert db.prefetch_utxos([op], 4) == 0
    assert db.get_utxo(*op) is None  # served from the cached miss
    db.add_utxo_raw(txid=op[0], vout=0, amount=5, script_pubkey=b"\x51",
                    height=1, is_coinbase=False)
    u = db.get_utxo(*op)
    assert u is not None and u["value"] == 5


def test_prefetch_disabled_or_unsupported_is_noop(tmp_path):
    db = BlockchainDatabase(str(tmp_path / "d"))
    assert db.prefetch_utxos([(_txid(1), 0)], 0) == 0
    assert db.prefetch_utxos([], 8) == 0


def _block(txs):
    return types.SimpleNamespace(transactions=txs)


def _tx(txid, inputs):
    return types.SimpleNamespace(
        get_txid=lambda: txid,
        inputs=[types.SimpleNamespace(prev_txid=t, prev_vout=v) for t, v in inputs],
    )


def test_block_prefetch_selects_only_chainstate_coins(monkeypatch):
    calls = []
    fake_db = types.SimpleNamespace(prefetch_utxos=lambda ops, th: calls.append((list(ops), th)) or 0)
    v = BlockValidator.__new__(BlockValidator)
    v.db = fake_db
    cb = _tx(b"\x01" * 32, [(bytes(32), 0xFFFFFFFF)])
    t1 = _tx(b"\x02" * 32, [(b"\xaa" * 32, 0), (b"\xab" * 32, 3)])
    t2 = _tx(b"\x03" * 32, [(b"\x02" * 32, 0), (b"\xac" * 32, 1)])  # spends t1 in-block
    blk = _block([cb, t1, t2])

    monkeypatch.setenv("OUROBOROS_UTXO_PREFETCH_THREADS", "5")
    v._prefetch_block_inputs(blk)
    assert calls == [([(b"\xaa" * 32, 0), (b"\xab" * 32, 3), (b"\xac" * 32, 1)], 5)]

    calls.clear()
    monkeypatch.setenv("OUROBOROS_UTXO_PREFETCH_THREADS", "0")
    v._prefetch_block_inputs(blk)
    assert calls == []

    v.db = types.SimpleNamespace()  # backend without the method
    monkeypatch.delenv("OUROBOROS_UTXO_PREFETCH_THREADS")
    v._prefetch_block_inputs(blk)  # must not raise
