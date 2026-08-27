"""#53f — coin metadata must never be silently fabricated (loud-guard pin).

The Rust PyUtxo has carried ``height`` / ``is_coinbase`` since the metadata
backfill; the only way they can be absent is a stale ferrous-utils wheel
(build skew).  The old ``getattr(py_utxo, 'is_coinbase', False)`` default
silently answered "ordinary coin" in that state — a fabrication consumed by
consensus paths (coinbase maturity, BIP-68).  The dict builders must instead
fail loudly, naming the missing field.

The negative tests FAIL at the parent commit (the getattr defaults swallow
the missing attributes and return a fabricated dict).
"""

import pytest

from ouroboros.database import BlockchainDatabase


class _BareUtxo:
    """Simulates a PyUtxo from a stale build: no height / is_coinbase."""

    def __init__(self):
        self.txid = b"\x00" * 32
        self.vout = 0
        self.value = 50_000
        self.script_pubkey = b"\x51"


class _FullUtxo(_BareUtxo):
    def __init__(self):
        super().__init__()
        self.height = 123
        self.is_coinbase = True


class _FakeDb:
    def __init__(self, utxo):
        self._utxo = utxo

    def get_utxo(self, txid, vout):
        return self._utxo

    def get_utxo_or_spent(self, txid, vout):
        return self._utxo


def _db_with(utxo):
    db = BlockchainDatabase.__new__(BlockchainDatabase)
    db._db = _FakeDb(utxo)
    return db


def test_get_utxo_refuses_metadata_less_coin():
    db = _db_with(_BareUtxo())
    with pytest.raises(AttributeError):
        db.get_utxo(b"\x00" * 32, 0)


def test_get_utxo_or_spent_refuses_metadata_less_coin():
    db = _db_with(_BareUtxo())
    with pytest.raises(AttributeError):
        db.get_utxo_or_spent(b"\x00" * 32, 0)


def test_get_utxo_passes_real_metadata_through():
    db = _db_with(_FullUtxo())
    coin = db.get_utxo(b"\x00" * 32, 0)
    assert coin["height"] == 123
    assert coin["is_coinbase"] is True
