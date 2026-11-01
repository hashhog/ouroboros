"""getblocktemplate transactions[].data is the witness serialization.

Core rpc/mining.cpp getblocktemplate: ``entry.pushKV("data",
EncodeHexTx(tx))``, and EncodeHexTx (core_io.cpp) writes
``TX_WITH_WITNESS(tx)``.  A miner that builds the block from ``data`` with
the witnesses stripped produces a block whose witness commitment does not
match (bad-witness-merkle-match).  ouroboros emitted ``tx.serialize()``,
the non-witness form; the ``hash`` field next to it was already the wtxid,
so the two disagreed for every segwit tx.
"""

from __future__ import annotations

import hashlib

from ouroboros.database import TxIn, TxOut
from tests.test_w87_gbt_assembly import _build_rpc, _make_entry, _txid


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _segwit_entry(label: str):
    entry = _make_entry(_txid(label), fee=2000, size=110)
    tx = entry.tx
    tx.inputs = [TxIn(prev_txid=b"\xaa" * 32, prev_vout=0, script_sig=b"",
                      sequence=0xFFFFFFFD, witness=[b"\x30" * 71, b"\x02" * 33])]
    tx.outputs = [TxOut(value=9000, script_pubkey=b"\x00\x14" + b"\xbb" * 20)]
    tx.has_witness = True
    return entry


def test_segwit_tx_data_carries_the_witness():
    entry = _segwit_entry("gbt-segwit")
    t = entry.tx.txid
    result = _build_rpc({t: entry}, [t])
    (item,) = result["transactions"]
    assert item["data"] == entry.tx.serialize_with_witness().hex()
    # data and hash describe the same tx: hash is the wtxid of data.
    assert _dsha(bytes.fromhex(item["data"]))[::-1].hex() == item["hash"]


def test_legacy_tx_data_unchanged():
    entry = _make_entry(_txid("gbt-legacy"), fee=2000, size=85)
    t = entry.tx.txid
    result = _build_rpc({t: entry}, [t])
    (item,) = result["transactions"]
    assert item["data"] == entry.tx.serialize().hex()
