"""getblocktemplate coinbaseaux / coinbasetxn match Core v31.1.

Core rpc/mining.cpp (getblocktemplate) builds ``aux`` as an empty
UniValue::VOBJ and pushes ``coinbaseaux`` and ``coinbasevalue``; it never
emits ``coinbasetxn``. ouroboros emitted ``coinbaseaux: {"flags": ""}`` and a
``coinbasetxn: {locktime, sequence}`` stub, which made 18 rows of the Core
regtest baseline mismatch (``coinbaseaux.flags`` and ``coinbasetxn``, 9 each).
"""

from __future__ import annotations

from tests.test_w87_gbt_assembly import _build_rpc


def test_coinbaseaux_is_an_empty_object():
    result = _build_rpc({}, [])
    assert result["coinbaseaux"] == {}


def test_coinbasetxn_is_not_emitted():
    result = _build_rpc({}, [])
    assert "coinbasetxn" not in result
    assert "coinbasevalue" in result
