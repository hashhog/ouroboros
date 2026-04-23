"""
Regression test: CHECKSIG/CHECKMULTISIG must push canonical empty-bytes false
so subsequent MINIMALIF doesn't reject the script.

Mainnet block 850000, tx 2261 (txid 55605554c5a17ad0d2769abf81c53b637e74f361
e3185235aa82da035018e3b2) input 0 spends a P2SH-P2WSH output whose witness
script is:

    <keyA> CHECKSIGVERIFY <keyB> CHECKSIG IFDUP NOTIF <51840> CSV ENDIF

The witness only carries one signature.  The witness script verifies it
against keyA (CHECKSIGVERIFY), then deliberately runs CHECKSIG against
keyB with an empty signature so that NULLFAIL allows the failure and the
NOTIF branch falls through into a CSV check.

For this to be valid under MINIMALIF, the false produced by the failing
CHECKSIG must be encoded as zero-length bytes (Bitcoin Core's
``vchFalse``).  Pushing ``b'\\x00'`` instead trips MINIMALIF and the whole
block is rejected — the symptom that wedged ouroboros at h=849999 on
2026-04-22.
"""

# Mock the sync FFI before any ouroboros imports
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


# ---------------------------------------------------------------------------
# Real mainnet tx 2261 of block 850000 (BIP141 P2SH-wrapped P2WSH).
# Hex extracted from bitcoin-core via getrawtransaction (verbosity 0).
# ---------------------------------------------------------------------------
TX_HEX = (
    "02000000000102"
    "ea25fc3a491475b3242ef19d5d64af5af1ac8fa90708ee08901bdec617a0e527"
    "5f000000"
    "23"
    "22002070d49a636258fa9aec97b24f731dc80ce31a456d33ad6a42f1c5bdba75083963"
    "80ca0000"
    "e7d8cace8ebc6f69ad8a7306b29e48a48fb02486045bab35dae961a50eb1e886"
    "28000000"
    "23"
    "220020154c1f6915d4a64a62100f74c66930b384267791e9af30784372b00e0ff4564c"
    "80ca0000"
    "01"
    "3527100000000000"
    "16"
    "0014fd70784c6292da4c7c75b8785e82d57f709ddac3"
    "03"
    "00"
    "47"
    "304402207d44551fecb28356e9a19cb74d8fa32236b5e62a19fe8f6131e1caabcb4b9beb"
    "022005cca8e4783dd68b36266c64e4f86ed4c16b3b0764d6b6c4ed877e9e4bcb4b1901"
    "4e"
    "2103b917dc46261857684b058acf08ac2290d9305fdaf9f694ab5e51b1ce7534e28f"
    "ad21030b55ed39d6e594e96a74e55fd2dc736a0b839789f172352c8743ef8e82a50b0b"
    "ac73640380ca00b268"
    "03"
    "00"
    "47"
    "304402204733efa27b5d7ab85fe8a4f8238db074325fe10157e48d48f2731f1e6f49cf79"
    "022003ff9eccc0a80c00d4be111d44fc80130bd621ddbee30b44ffbf1e862c3a621d01"
    "4e"
    "21033da812186105d4e88fa83e6e74c09dcda2031a0f298243485ae1a2b3f2af9b2d"
    "ad21031721d032d02049ef85629ffb278fb33167d6c42a82c0e30a6fc4c4a3cdcf11be"
    "ac73640380ca00b268"
    "4ff80c00"
)

# Ground-truth UTXO data (bitcoin-core, getrawtransaction verbosity 2).
INPUT0_VALUE_SATS = 757_602
INPUT0_SCRIPT_PUBKEY = bytes.fromhex(
    "a914a5bf35e3176d339955019cc32ee41662f028192a87"
)


def _deserialize(raw: bytes) -> Transaction:
    """Minimal SegWit-aware tx deserializer (test-local; production uses Rust)."""
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


def test_block_850000_tx_2261_input_0_verifies():
    """Mainnet tx that wedged ouroboros — must verify True, not False."""
    tx = _deserialize(bytes.fromhex(TX_HEX))
    interp = ScriptInterpreter()
    assert interp.verify(
        script_sig=tx.inputs[0].script_sig,
        script_pubkey=INPUT0_SCRIPT_PUBKEY,
        tx=tx,
        input_index=0,
        flags=SCRIPT_VERIFY_ALL_DEPLOYED,
        amount=INPUT0_VALUE_SATS,
        input_amounts=[INPUT0_VALUE_SATS, 0],
        input_script_pubkeys=[INPUT0_SCRIPT_PUBKEY, b''],
    ) is True


def test_checksig_false_pushes_empty_bytes_not_zero_byte():
    """Direct unit test: CHECKSIG with empty sig must push b'', not b'\\x00'.

    The bug pushed b'\\x00' which trips MINIMALIF on the next OP_IF/OP_NOTIF.
    """
    interp = ScriptInterpreter()
    # Witness script: <pk> CHECKSIG NOTIF OP_1 ENDIF
    # Stack before script: [empty]   (one witness item, empty)
    # Execution:
    #   push <pk>            stack: [empty, pk]
    #   CHECKSIG             stack: [false]   <-- empty sig means push false
    #   NOTIF (with MINIMALIF) — must accept the false as canonical empty bytes
    #   OP_1                 stack: [1]
    #   ENDIF
    pubkey = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    witness_script = bytes([0x21]) + pubkey + bytes([0xac, 0x64, 0x51, 0x68])
    # Build a synthetic tx with one P2WSH input that uses this script.
    import hashlib
    program = hashlib.sha256(witness_script).digest()
    spk = bytes([0x00, 0x20]) + program
    tx = Transaction(
        txid=b'\x00' * 32,
        version=2,
        locktime=0,
        inputs=[TxIn(
            prev_txid=b'\x11' * 32, prev_vout=0,
            script_sig=b'',
            sequence=0xffffffff,
            witness=[b'', witness_script],
        )],
        outputs=[TxOut(value=0, script_pubkey=b'')],
        has_witness=True,
    )
    assert interp.verify(
        script_sig=b'',
        script_pubkey=spk,
        tx=tx,
        input_index=0,
        flags=SCRIPT_VERIFY_ALL_DEPLOYED,
        amount=0,
        input_amounts=[0],
        input_script_pubkeys=[spk],
    ) is True
