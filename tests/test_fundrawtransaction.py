"""Focused functional tests for the fundrawtransaction RPC handler.

fundrawtransaction is the raw-tx sibling of walletcreatefundedpsbt: both drive
the SAME funding / coin-selection engine (ouroboros wallet.py::select_coins,
shared via RPCServer._fund_existing_tx). Here we build a raw tx with outputs but
no inputs, fund it, and assert the funded tx is genuinely valid:
inputs were added, a change output exists, fee > 0, changepos is consistent with
the returned hex, and sum(selected inputs) == sum(outputs) + fee.

Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction
(-> FundTransaction). Result shape: {hex, fee, changepos}.

Reuses the regtest-style funded-wallet fixtures from
tests/test_wallet_lockunspent_getbalances.py exactly as the
walletcreatefundedpsbt tests there do.
"""

from __future__ import annotations

import hashlib

import pytest

try:
    # When collected as part of the ``tests`` package (tests/__init__.py).
    from tests.test_wallet_lockunspent_getbalances import (
        _StubKey,
        _make_wallet,
        _StubNode,
    )
except ImportError:  # pragma: no cover - direct-file invocation fallback
    from test_wallet_lockunspent_getbalances import (
        _StubKey,
        _make_wallet,
        _StubNode,
    )


@pytest.fixture
def rpc_with_wallet():
    from ouroboros.rpc import RPCServer

    wallet, key, db, tmpdir = _make_wallet(b"fundrawtransaction-tests-2026-06")
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = _StubNode(wallet)
    rpc._current_wallet_name = None
    rpc._key = key
    rpc._db = db
    rpc._tmpdir = tmpdir
    yield rpc


def _sum_input_value(db, tx) -> int:
    """Sum the value of the funded tx's inputs by resolving each outpoint
    against the wallet UTXO set (proves the selected inputs are real coins)."""
    total = 0
    for tin in tx.inputs:
        u = db.get_utxo(bytes(tin.prev_txid), int(tin.prev_vout))
        assert u is not None, "funded input does not resolve to a wallet UTXO"
        total += int(u["value"])
    return total


@pytest.mark.asyncio
async def test_fundrawtransaction_default_path(rpc_with_wallet):
    """Default (no-options) path: a raw tx with 1 output and no inputs must
    get inputs + a change output added, and the math must be genuine."""
    rpc = rpc_with_wallet
    key = rpc._key
    db = rpc._db
    addr = key.get_p2wpkh_address()

    # Wallet has 1 BTC available (one mature UTXO).
    db.add_utxo(addr, b"\xee" * 32, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    recipient = _StubKey(hashlib.sha256(b"recip").digest()).get_p2wpkh_address()
    recipient_sats = 10_000_000  # 0.1 BTC

    # createrawtransaction: 1 output (0.1 BTC), no inputs.
    raw = await rpc.rpc_createrawtransaction(
        inputs=[], outputs=[{recipient: 0.1}],
    )
    pre = rpc._decode_hex_tx(bytes.fromhex(raw), False)
    assert len(pre.inputs) == 0
    assert len(pre.outputs) == 1

    res = await rpc.rpc_fundrawtransaction(hexstring=raw, options={"fee_rate": 5})

    # Result shape: {hex, fee, changepos}.
    assert set(res.keys()) == {"hex", "fee", "changepos"}
    assert isinstance(res["hex"], str) and res["hex"]
    assert res["fee"] > 0
    assert isinstance(res["changepos"], int)

    # The returned hex MUST decode to the funded tx.
    funded = rpc._decode_hex_tx(bytes.fromhex(res["hex"]), None)

    # Inputs were added (vin non-empty).
    assert len(funded.inputs) >= 1

    # A change output exists (recipient + change == 2 outputs) and changepos
    # points at it.
    assert res["changepos"] != -1
    assert len(funded.outputs) == 2
    cp = res["changepos"]
    assert 0 <= cp < len(funded.outputs)

    # Genuine fee/change math:
    #   sum(inputs) == sum(outputs) + fee
    in_val = _sum_input_value(db, funded)
    out_val = sum(int(o.value) for o in funded.outputs)
    fee_sats = round(res["fee"] * 1e8)
    assert fee_sats > 0
    assert in_val == out_val + fee_sats, (in_val, out_val, fee_sats)

    # change == inputs - recipient_outputs - fee, and the change output value
    # at changepos matches.
    expected_change = in_val - recipient_sats - fee_sats
    assert funded.outputs[cp].value == expected_change

    # The recipient output is preserved verbatim (the non-change output).
    non_change = [o for i, o in enumerate(funded.outputs) if i != cp]
    assert len(non_change) == 1
    assert non_change[0].value == recipient_sats

    # Input value covers outputs + fee.
    assert in_val >= out_val + fee_sats


@pytest.mark.asyncio
async def test_fundrawtransaction_changepos_consistent_with_hex(rpc_with_wallet):
    """options.changePosition pins where the change output lands, and the
    returned hex must reflect that exact position."""
    rpc = rpc_with_wallet
    key = rpc._key
    db = rpc._db
    addr = key.get_p2wpkh_address()

    db.add_utxo(addr, b"\x33" * 32, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    recipient = _StubKey(hashlib.sha256(b"recip2").digest()).get_p2wpkh_address()
    raw = await rpc.rpc_createrawtransaction(inputs=[], outputs=[{recipient: 0.1}])

    res = await rpc.rpc_fundrawtransaction(
        hexstring=raw, options={"fee_rate": 5, "changePosition": 0},
    )
    assert res["changepos"] == 0
    funded = rpc._decode_hex_tx(bytes.fromhex(res["hex"]), None)
    # Output 0 is change; output 1 is the 0.1 BTC recipient.
    assert funded.outputs[1].value == 10_000_000
    # Invariant still holds with the pinned change position.
    in_val = _sum_input_value(db, funded)
    out_val = sum(int(o.value) for o in funded.outputs)
    fee_sats = round(res["fee"] * 1e8)
    assert in_val == out_val + fee_sats


@pytest.mark.asyncio
async def test_fundrawtransaction_insufficient_funds(rpc_with_wallet):
    """When the wallet cannot cover the outputs + fee, mirror Core's
    insufficient-funds error."""
    from fastapi import HTTPException

    rpc = rpc_with_wallet
    key = rpc._key
    db = rpc._db
    addr = key.get_p2wpkh_address()

    # Only 0.001 BTC available, asking to fund 5 BTC.
    db.add_utxo(addr, b"\x44" * 32, 0, 100_000, height=50,
                script_pubkey=key.get_script_pubkey())

    recipient = _StubKey(hashlib.sha256(b"recip3").digest()).get_p2wpkh_address()
    raw = await rpc.rpc_createrawtransaction(inputs=[], outputs=[{recipient: 5.0}])

    with pytest.raises(HTTPException):
        await rpc.rpc_fundrawtransaction(hexstring=raw, options={"fee_rate": 5})


@pytest.mark.asyncio
async def test_fundrawtransaction_subtract_fee_from_outputs(rpc_with_wallet):
    """subtractFeeFromOutputs: the fee is carved out of the named output, and
    the sum(inputs)==sum(outputs)+fee invariant still holds."""
    rpc = rpc_with_wallet
    key = rpc._key
    db = rpc._db
    addr = key.get_p2wpkh_address()

    db.add_utxo(addr, b"\x55" * 32, 0, 100_000_000, height=50,
                script_pubkey=key.get_script_pubkey())

    recipient = _StubKey(hashlib.sha256(b"recip4").digest()).get_p2wpkh_address()
    raw = await rpc.rpc_createrawtransaction(inputs=[], outputs=[{recipient: 0.1}])

    res = await rpc.rpc_fundrawtransaction(
        hexstring=raw,
        options={"fee_rate": 5, "subtractFeeFromOutputs": [0]},
    )
    funded = rpc._decode_hex_tx(bytes.fromhex(res["hex"]), None)
    fee_sats = round(res["fee"] * 1e8)
    assert fee_sats > 0

    in_val = _sum_input_value(db, funded)
    out_val = sum(int(o.value) for o in funded.outputs)
    assert in_val == out_val + fee_sats

    # The recipient output paid the fee: its value is 0.1 BTC minus the fee.
    cp = res["changepos"]
    recipient_idx = 0 if cp != 0 else 1
    assert funded.outputs[recipient_idx].value == 10_000_000 - fee_sats
