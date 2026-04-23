"""
Regression test: CHECKSIG/CHECKSIGVERIFY/CHECKMULTISIG sighash must use the
scriptCode truncated at the last executed OP_CODESEPARATOR (BIP143).

Mainnet block 850846, tx 811 (txid 5d83aad79133fad5040166c2d5ca5ab4cdb57881
0628b35095661d8f031a4678) input 0 spends a P2WSH output whose witness script
is:

    <pk_A> DEPTH 2 EQUAL
    IF
        CHECKSIGVERIFY <510140> CSV
    ELSE
        CODESEPARATOR
        CHECKSIGVERIFY
        SIZE <40> EQUALVERIFY
        SHA256 <hash> EQUALVERIFY
        <pk_B> CHECKSIG
    ENDIF

The witness supplies 3 stack items (sig_1, 64-byte preimage, sig_2) so DEPTH=4
and the IF branch is NOT taken.  The ELSE branch runs OP_CODESEPARATOR, then
CHECKSIGVERIFY — whose sighash per BIP143 must be computed over the witness
script *starting after the CODESEPARATOR*, not over the full witness script.

Ouroboros was passing the full script_pubkey as scriptCode, producing the
wrong sighash and always failing signature verification — the symptom that
wedged mainnet sync at h=850845 on 2026-04-23.
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

# Exact flag set used by the live BlockValidator at mainnet h=850846 — captured
# from the wedged process via diagnostic dump.  Differs from
# SCRIPT_VERIFY_ALL_DEPLOYED (no TAPROOT, no STRICTENC; has CONST_SCRIPTCODE,
# CLEANSTACK, MINIMALDATA, SIGPUSHONLY, DISCOURAGE_UPGRADABLE_NOPS).  The first
# cut of the CODESEPARATOR fix passed under ALL_DEPLOYED but still rejected the
# block live, because ALL_DEPLOYED does not set CONST_SCRIPTCODE — the check
# mis-fired on witness-v0 scripts where sig_version was left at the BASE
# default even though is_witness_v0=True.  Pin the live value here so the
# regression test actually exercises that path.
LIVE_FLAGS = 0x1EFFD


TX_HEX = (
    "0200000000010134cfe21ad49968fee8000a71fa0aa7039c13a8092546d82433ed0de63d56440b"
    "01000000000100000001691f000000000000"
    "22"
    "0020ba8d2124d1cb55d9b3035855d4310adf4c00847ef15397284704157d0fa9acc9"
    "04"
    "47"
    "3044022079e0752c58a33ed5743cb0c691e4fa7e0b04f70344cc18a6176c9b0975c7d39f02204ba3f214406c3afe353012446724c0021d8e73c040dd98b5d00c4ffcbbdd96ee01"
    "40"
    "f8f8567f884749ebc1c1def9dceacf199f1e51c40d511a077aa7bef1d17cfe6e86a78c28b1614d8b902cc583394939e89857a5a4e3d5bf5644f803d9e97deff7"
    "47"
    "30440220024ce16a8a31f296e4bbaac9242435959e3cd9a7cf586506fbf1c62e7519d387022078b3f9f37de9df6c1da320a82dd59a4663030b8f6cdf8fb5be8d4c8b838dd30f01"
    "7a"
    "2102427408a7ec3e38365532e41778f1a0332c84833f2553c5e5fe4c21a930f49b2474528763ad03510140b267abad82014088a820501cd5c22475f7327a737ec63c4b636b75fd1e78eeb9ed5c422ba91d0025d48f88210207c373de927872546c9cf655c9b11482da9b6f1d585282b231856480d1000b87ac68"
    "00000000"
)

INPUT0_VALUE_SATS = 10_799
INPUT0_SCRIPT_PUBKEY = bytes.fromhex(
    "0020c4ad32feb27d8937587a9fc9370731ce40a3677f2705db4c7bfa984d550d9bdf"
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


def test_block_850846_tx_811_input_0_verifies():
    """Mainnet tx that wedged ouroboros on 2026-04-23 — must verify True.

    Exercises both the in-tree ALL_DEPLOYED flag bundle and the exact LIVE_FLAGS
    used by the BlockValidator, because the initial CODESEPARATOR fix passed
    under ALL_DEPLOYED while still rejecting live (CONST_SCRIPTCODE mis-fire
    on SegWit v0 witness scripts).
    """
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
