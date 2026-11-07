"""getmempoolinfo ``bytes`` is the sum of sigop-adjusted vsizes, like Core
(fleet item refill-20261106-ouroboros-consensus).

Core rpc/mempool.cpp MempoolInfoToJSON: ``bytes`` = ``pool.GetTotalTxSize()``.
txmempool.cpp adds ``entry.GetTxSize()`` per entry, and
kernel/mempool_entry.h ``GetTxSize()`` is
``GetVirtualTransactionSize(nTxWeight, sigOpCost, nBytesPerSigOp)``: the
BIP-141 vsize, raised to ``sigop_cost * 20 / 4`` for sigop-heavy txs.

Before the fix ouroboros reported ``current_size``, the stripped
(witness-less) byte count it budgets RAM with: smaller than vsize for a
segwit spend and blind to the sigop adjustment (tools/core-regtest rows
``warden_b/b-invalidate/info:bytes`` Core 220 vs 164,
``warden_e/e-invalidate/info:bytes`` 8992 vs 7201, and the
``warden_invalidated_submit`` ``tip100`` / ``usage-*`` / ``pressure``
``info:bytes`` rows).

``usage`` is a separate number (Core's DynamicMemoryUsage) and not changed
here: it stays the existing stripped-bytes estimate.
"""

from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.mempool import (
    DEFAULT_BYTES_PER_SIGOP,
    Mempool,
    get_virtual_transaction_size,
)

FUNDING = b"\xab" * 32
P2WSH_TRUE = b"\x00\x20" + bytes.fromhex(
    # sha256(OP_TRUE)
    "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"
)


def _Utxo(value: int, script: bytes) -> dict:
    """The dict shape BlockchainDatabase.get_utxo returns."""
    return {"value": value, "script_pubkey": script, "height": 1, "is_coinbase": False}


class _StubDB:
    def __init__(self, utxos: dict):
        self._m = utxos

    def get_utxo(self, txid: bytes, vout: int):
        u = self._m.get((txid, vout))
        return None if u is None else dict(u, txid=txid, vout=vout)

    def get_median_time_past(self, height: int) -> int:
        return 0


class _StubValidator:
    def __init__(self, utxos: dict):
        self.db = _StubDB(utxos)

    def validate_transaction(self, tx, height, block_mtp=0, **kwargs):
        return True, ""


def _pool(utxos: dict) -> Mempool:
    # require_standard=True is the regtest/mainnet default, and the only
    # admission mode in which the mempool computes a tx's sigop cost
    # (mempool.py, ahead of PolicyScriptChecks).
    return Mempool(validator=_StubValidator(utxos), require_standard=True, full_rbf=True)


def _with_txid(tx: Transaction) -> Transaction:
    tx.txid = hashlib.sha256(hashlib.sha256(tx.serialize()).digest()).digest()
    return tx


def _segwit_spend(vout: int) -> Transaction:
    """Spend a P2WSH(OP_TRUE) output: empty scriptSig, witness [OP_TRUE]."""
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=FUNDING, prev_vout=vout, script_sig=b"",
                     sequence=0xFFFFFFFD, witness=[b"\x51"])],
        outputs=[TxOut(value=99_000, script_pubkey=P2WSH_TRUE)],
        has_witness=True,
    )
    return _with_txid(tx)


PUBKEY = b"\x02" + b"\x11" * 32
# Bare 1-of-3 multisig: standard (permitbaremultisig) and, under Core's
# inaccurate legacy count, 20 sigops for the OP_CHECKMULTISIG.
BARE_MULTISIG = b"\x51" + (b"\x21" + PUBKEY) * 3 + b"\x53\xae"


def _sigop_heavy_spend(vout: int) -> Transaction:
    """Two bare-multisig outputs: 2 * 20 legacy sigops * 4 = 160 sigop cost,
    so 160 * 20 = 3200 weight units dominate its real weight (~1121)."""
    tx = Transaction(
        txid=b"",
        version=2,
        locktime=0,
        inputs=[TxIn(prev_txid=FUNDING, prev_vout=vout, script_sig=b"",
                     sequence=0xFFFFFFFD, witness=[b"\x51"])],
        outputs=[TxOut(value=40_000, script_pubkey=BARE_MULTISIG),
                 TxOut(value=40_000, script_pubkey=BARE_MULTISIG)],
        has_witness=True,
    )
    return _with_txid(tx)


def _admit(pool: Mempool, tx: Transaction) -> None:
    ok, err = pool.add_transaction(tx, 200)
    assert ok, err


def _core_vsize(pool: Mempool, tx: Transaction) -> int:
    entry = pool.transactions[tx.get_txid()]
    return get_virtual_transaction_size(tx.get_weight(), entry.sigop_cost, DEFAULT_BYTES_PER_SIGOP)


def test_segwit_spend_bytes_is_vsize_not_stripped_size():
    utxos = {(FUNDING, 0): _Utxo(100_000, P2WSH_TRUE)}
    pool = _pool(utxos)
    tx = _segwit_spend(0)
    _admit(pool, tx)
    vsize = _core_vsize(pool, tx)
    stripped = len(tx.serialize())
    assert vsize > stripped  # the witness counts, a quarter weight per byte
    assert pool.get_mempool_info()["bytes"] == vsize


def test_sigop_heavy_bytes_is_sigop_adjusted():
    utxos = {(FUNDING, 1): _Utxo(100_000, P2WSH_TRUE)}
    pool = _pool(utxos)
    tx = _sigop_heavy_spend(1)
    _admit(pool, tx)
    entry = pool.transactions[tx.get_txid()]
    assert entry.sigop_cost == 160  # computed by admission, not set here
    assert _core_vsize(pool, tx) == 800  # 160 * 20 / 4
    assert len(tx.serialize()) < 800
    assert pool.get_mempool_info()["bytes"] == 800


def test_bytes_is_the_sum_and_drops_with_removal():
    utxos = {(FUNDING, 0): _Utxo(100_000, P2WSH_TRUE),
             (FUNDING, 1): _Utxo(100_000, P2WSH_TRUE)}
    pool = _pool(utxos)
    a, b = _segwit_spend(0), _sigop_heavy_spend(1)
    _admit(pool, a)
    _admit(pool, b)
    total = _core_vsize(pool, a) + _core_vsize(pool, b)
    assert pool.get_mempool_info()["bytes"] == total
    pool.remove_transaction(a.get_txid())
    assert pool.get_mempool_info()["bytes"] == 800


def test_getmempoolinfo_rpc_bytes_and_unchanged_usage():
    """The RPC reports Core's bytes; usage keeps its old estimate
    (stripped bytes + 200 per entry), which this change does not touch."""
    from ouroboros.rpc import RPCServer

    utxos = {(FUNDING, 0): _Utxo(100_000, P2WSH_TRUE)}
    pool = _pool(utxos)
    tx = _segwit_spend(0)
    _admit(pool, tx)
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(mempool=pool)
    info = asyncio.run(server.rpc_getmempoolinfo())
    assert info["size"] == 1
    assert info["bytes"] == _core_vsize(pool, tx)
    assert info["usage"] == len(tx.serialize()) + 200


def test_empty_pool_is_zero():
    """Control: the empty-pool branch is unchanged."""
    pool = _pool({})
    assert pool.get_mempool_info()["bytes"] == 0
