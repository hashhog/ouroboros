"""
Regression test: CHECKMULTISIG must treat an invalid (non-curve-point) pubkey
as a non-match, not as a fatal script-execution error.

Bitcoin Core (interpreter.cpp, CheckECDSASignature): CPubKey::IsValid() returns
false for malformed pubkeys, and CHECKMULTISIG simply moves on to the next
pubkey in the loop.  Ouroboros previously let coincurve's PublicKey(bytes)
ValueError propagate out of _verify_ecdsa_signature — that killed the whole
multisig loop and rejected the entire transaction.

Real-world trigger: mainnet block 851204 tx 26 (txid in display order:
d547078f745d844fc34ab70c4770d5c82a6af77ef6e9e89d4c49ae14421381a9) spends a
bare 2-of-3 multisig whose third pubkey is a Counterparty-style fake (valid
length 33 bytes, prefix 0x02, but trailing bytes zeroed — not on the curve).
The two real pubkeys verify the two provided signatures; the fake pubkey is
skipped.  Ouroboros wedged mainnet sync at h=851203 on 2026-04-23 by rejecting
this tx.
"""

import sys
import types

if "sync" not in sys.modules:
    sync = types.ModuleType("sync")
    sync.PyUTXO = type("PyUTXO", (), {})
    sync.SyncEngine = type("SyncEngine", (), {})
    sync.PyBlockchainDB = type("PyBlockchainDB", (), {})
    sys.modules["sync"] = sync

import struct  # noqa: E402

from ouroboros.database import Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.script import (  # noqa: E402
    SCRIPT_VERIFY_ALL_DEPLOYED,
    ScriptInterpreter,
)

# Flag bundle used by the live BlockValidator on mainnet at h=851204 —
# captured via a one-shot diagnostic dump of the wedged process.
LIVE_FLAGS = 0x1EFFD

# Raw tx hex fetched from blockstream for txid
# d547078f745d844fc34ab70c4770d5c82a6af77ef6e9e89d4c49ae14421381a9.
TX_HEX = (
    "0100000001c2221dd7a62234cb060a137ba9cf0bff7a9bf79450a3973f49b4e6eedb9eae6d"
    "00000000"
    "91"
    "00"
    "47"
    "3044022021f73d8ed089f90ae85e54ae128ca505bc8138ee5e026aa2e01849c1ebda17e9022004ec4d3f4ba3c607bcb398c27a55c69e3008369c3c1ca32af6f3566f7f06dd6901"
    "47"
    "3044022042ff46c90955123959cb217097bacb60399686bb3fd709e5da91a8b9dc1b027102207ddc2fc50f0f6dd8ab5323e38e6e7a0c483657ad9d62e4bf7ab0777a09ece82001"
    "ffffffff"
    "0110270000000000001976a914c8c1db9378df722a4f21abbd2c3ffa13e7bf653688ac"
    "00000000"
)

# Spent output (vout 0 of c2221dd7...): bare 2-of-3 multisig,
# pk1 + pk2 valid, pk3 is Counterparty-style (trailing zeros, not on curve).
INPUT0_VALUE_SATS = 20_000
INPUT0_SCRIPT_PUBKEY = bytes.fromhex(
    "52"
    "21032f546a6787b417b42b0d1cfb508a3277ffc65b9b6d166557395fc291558cded6"
    "21021499a0ca6ca03c32448aea57bb339b8c90b39479845bb38bef37c436f9f66ac1"
    "2102c8c1db9378df722a4f21abbd2c3ffa13e7bf653600000000000000000000000"  # fake pk3
    "0"
    "53"
    "ae"
)


def _deserialize(raw: bytes) -> Transaction:
    p = 0
    version = struct.unpack_from('<i', raw, p)[0]
    p += 4
    has_witness = raw[p] == 0x00 and raw[p + 1] == 0x01
    if has_witness:
        p += 2

    def varint() -> int:
        nonlocal p
        b = raw[p]
        p += 1
        if b < 0xFD:
            return b
        if b == 0xFD:
            v = struct.unpack_from('<H', raw, p)[0]
            p += 2
            return v
        if b == 0xFE:
            v = struct.unpack_from('<I', raw, p)[0]
            p += 4
            return v
        v = struct.unpack_from('<Q', raw, p)[0]
        p += 8
        return v

    n_in = varint()
    inputs: list[TxIn] = []
    for _ in range(n_in):
        prev_txid = raw[p:p + 32]
        p += 32
        prev_vout = struct.unpack_from('<I', raw, p)[0]
        p += 4
        sl = varint()
        script_sig = raw[p:p + sl]
        p += sl
        seq = struct.unpack_from('<I', raw, p)[0]
        p += 4
        inputs.append(TxIn(
            prev_txid=prev_txid, prev_vout=prev_vout,
            script_sig=script_sig, sequence=seq, witness=None,
        ))
    n_out = varint()
    outputs: list[TxOut] = []
    for _ in range(n_out):
        val = struct.unpack_from('<q', raw, p)[0]
        p += 8
        sl = varint()
        spk = raw[p:p + sl]
        p += sl
        outputs.append(TxOut(value=val, script_pubkey=spk))
    if has_witness:
        for inp in inputs:
            n_w = varint()
            ws = []
            for _ in range(n_w):
                wl = varint()
                ws.append(raw[p:p + wl])
                p += wl
            inp.witness = ws
    locktime = struct.unpack_from('<I', raw, p)[0]
    return Transaction(
        txid=b'\x00' * 32,
        version=version,
        locktime=locktime,
        inputs=inputs,
        outputs=outputs,
        has_witness=has_witness,
    )


def test_block_851204_tx_26_input_0_verifies_with_fake_pubkey():
    """Mainnet tx that wedged ouroboros on 2026-04-23 — must verify True."""
    tx = _deserialize(bytes.fromhex(TX_HEX))
    interp = ScriptInterpreter()
    for flags in (SCRIPT_VERIFY_ALL_DEPLOYED, LIVE_FLAGS):
        assert interp.verify(
            script_sig=tx.inputs[0].script_sig,
            script_pubkey=INPUT0_SCRIPT_PUBKEY,
            tx=tx,
            input_index=0,
            flags=flags,
            amount=INPUT0_VALUE_SATS,
            input_amounts=[INPUT0_VALUE_SATS],
            input_script_pubkeys=[INPUT0_SCRIPT_PUBKEY],
        ) is True, f"verify() must be True under flags=0x{flags:x}"


def test_verify_ecdsa_signature_returns_false_on_malformed_pubkey():
    """Direct unit test: invalid pubkey bytes must yield False, never raise."""
    interp = ScriptInterpreter()
    malformed = bytes.fromhex(
        "02c8c1db9378df722a4f21abbd2c3ffa13e7bf6536000000000000000000000000"
    )
    msg = b"\x00" * 32
    der_sig = b"\x30\x06\x02\x01\x01\x02\x01\x01"  # nonsense DER
    # Must not raise; must return False.
    assert interp._verify_ecdsa_signature(msg, der_sig, malformed) is False
