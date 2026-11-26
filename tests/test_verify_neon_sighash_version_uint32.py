"""Signing-side sighash preimages serialize nVersion as uint32.

verify-neon-ouroboros-findings #5.  Core's CTransaction::version is a
uint32_t (primitives/transaction.h), and SignatureHash writes it as four
unsigned little-endian bytes on every path (script/interpreter.cpp: the
legacy CTransactionSignatureSerializer, the BIP143 branch and
SignatureHashSchnorr).  The RPC tx decoder reads the version unsigned
(p2p_messages.py), but the wallet/RPC signing helpers packed it with
struct.pack("<i", ...), so a transaction with nVersion >= 0x80000000 could
not be signed: struct.error.  Core signs it.

PR #175 fixed the verifier (script.py).  This covers the signers:
segwit_v0.bip143_sighash, Wallet._bip143_sighash, and the sighash closures
of signrawtransactionwithkey / walletprocesspsbt /
signrawtransactionwithwallet in rpc.py.  The RPC tests (legacy, BIP143 and
BIP341 key-path closures of signrawtransactionwithkey) check that the
signature ouroboros produces is valid under the (already uint32) verifier,
so a signature over a wrongly-serialized preimage fails too.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import struct
import types
from pathlib import Path

import pytest

from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.p2p_messages import TxMessage
from ouroboros.script import ScriptInterpreter, get_flags_for_height
from ouroboros.segwit_v0 import bip143_sighash
from ouroboros.wallet import Wallet

VERSIONS = [2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
IDS = [f"{v:#010x}" for v in VERSIONS]
SRC = Path(__file__).resolve().parent.parent / "src" / "ouroboros"


def _d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _u32(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _ser_outs(tx) -> bytes:
    return b"".join(struct.pack("<q", o.value) + bytes([len(o.script_pubkey)])
                    + o.script_pubkey for o in tx.outputs)


def _ref_bip143_all(tx, script_code: bytes, amount: int) -> bytes:
    """Independent BIP143 SIGHASH_ALL for input 0 (Core SignatureHash)."""
    i = tx.inputs[0]
    pre = (_u32(tx.version) + _d(i.prev_txid + _u32(i.prev_vout)) + _d(_u32(i.sequence))
           + i.prev_txid + _u32(i.prev_vout) + bytes([len(script_code)]) + script_code
           + struct.pack("<q", amount) + _u32(i.sequence) + _d(_ser_outs(tx))
           + _u32(tx.locktime) + _u32(1))
    return _d(pre)


def _tx(version: int) -> Transaction:
    return Transaction(
        txid=b"", version=version, locktime=0,
        inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFD)],
        outputs=[TxOut(value=100_000, script_pubkey=b"\x00\x14" + b"\x33" * 20)],
    )


PUB = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
H160 = hashlib.new("ripemd160", hashlib.sha256(PUB).digest()).digest()
SCRIPT_CODE = b"\x76\xa9\x14" + H160 + b"\x88\xac"


@pytest.mark.parametrize("version", VERSIONS, ids=IDS)
def test_segwit_v0_bip143_sighash_version_uint32(version):
    tx = _tx(version)
    assert bip143_sighash(tx, 0, SCRIPT_CODE, 200_000, 0x01) == _ref_bip143_all(
        tx, SCRIPT_CODE, 200_000)


@pytest.mark.parametrize("version", VERSIONS, ids=IDS)
def test_wallet_bip143_sighash_version_uint32(version):
    tx = _tx(version)
    assert Wallet._bip143_sighash(tx, 0, PUB, 200_000) == _ref_bip143_all(
        tx, SCRIPT_CODE, 200_000)


# --- signrawtransactionwithkey, end to end ------------------------------------
# Private key 1 (WIF below); PUB is its compressed public key.
WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
P2WPKH_SPK = b"\x00\x14" + H160
P2PKH_SPK = SCRIPT_CODE


def _p2tr_keypath_spk() -> bytes:
    """BIP86-style output key for PUB (no script tree): Q = P + H_TapTweak(P)G."""
    from coincurve import PublicKey

    assert PUB[0] == 0x02  # even y, so P is the x-only lift of PUB[1:]
    tag = hashlib.sha256(b"TapTweak").digest()
    tweak = hashlib.sha256(tag + tag + PUB[1:]).digest()
    q = PublicKey(PUB).add(tweak).format(compressed=True)
    return b"\x51\x20" + q[1:]


P2TR_SPK = _p2tr_keypath_spk()
AMOUNT_BTC = 0.002
AMOUNT_SAT = 200_000
UNSIGNED_TAIL = (  # 1 input (aa..aa:0, empty scriptSig), 1 output, locktime 0
    "01" + "aa" * 32 + "00000000" + "00" + "fdffffff"
    + "01" + "a086010000000000" + "16" + "0014" + "33" * 20 + "00000000"
)


class _AbsentDB:
    def get_block(self, _h): return None
    def get_block_bytes(self, _h): return None
    def get_best_block(self): return (b"\x00" * 32, 0)
    def get_utxo(self, _t, _n): return None
    def get_block_hash_by_height(self, _h): return None
    def get_tx_index(self, *_a, **_k): return None


class _EmptyMempool:
    transactions: dict = {}
    def get_transaction(self, _t): return None
    def get_transaction_entry(self, _t): return None


def _rpc():
    from ouroboros.rpc import RPCServer

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = types.SimpleNamespace(
        network="mainnet", config={"network": "mainnet"}, db=_AbsentDB(),
        mempool=_EmptyMempool(), pruner=None, block_filter_index=None)
    rpc._side_branch_blocks = {}
    rpc._deployment_cache = {}
    rpc._current_wallet_name = None
    return rpc


def _sign_with_key(version: int, spk: bytes) -> dict:
    raw = _u32(version).hex() + UNSIGNED_TAIL
    prev = [{"txid": "aa" * 32, "vout": 0, "scriptPubKey": spk.hex(),
             "amount": AMOUNT_BTC}]
    req = {"jsonrpc": "2.0", "method": "signrawtransactionwithkey",
           "params": [raw, [WIF], prev], "id": 1}
    return asyncio.run(_rpc()._execute_single_rpc(req))


def _verifies(signed_hex: str, spk: bytes) -> bool:
    tx = TxMessage.from_payload(bytes.fromhex(signed_hex)).transaction
    flags = get_flags_for_height(900_001, None, "mainnet")
    inp = tx.inputs[0]
    return ScriptInterpreter().verify_python(
        inp.script_sig, spk, tx, 0, flags=flags, amount=AMOUNT_SAT,
        input_amounts=[AMOUNT_SAT], input_script_pubkeys=[spk])


@pytest.mark.parametrize("version", VERSIONS, ids=IDS)
@pytest.mark.parametrize("kind,spk",
                         [("p2wpkh", P2WPKH_SPK), ("p2pkh", P2PKH_SPK), ("p2tr", P2TR_SPK)],
                         ids=["p2wpkh", "p2pkh", "p2tr"])
def test_signrawtransactionwithkey_signs_any_version(kind, spk, version):
    resp = _sign_with_key(version, spk)
    assert resp.get("error") is None, resp
    res = resp["result"]
    assert res["complete"] is True, res
    assert res["hex"][:8] == _u32(version).hex()
    assert _verifies(res["hex"], spk), f"{kind} signature invalid at {version:#x}"


# --- the closures the RPC tests above cannot reach without a wallet -----------
_SIGNED_PACK = re.compile(r"""struct\.pack\(\s*["']<i["']\s*,\s*tx\.version\s*\)""")


@pytest.mark.parametrize("module", ["rpc.py", "wallet.py", "segwit_v0.py"])
def test_no_signed_tx_version_pack_in_signers(module):
    """walletprocesspsbt and signrawtransactionwithwallet build their legacy
    and taproot preimages in local closures that need a loaded wallet; pin
    that none of the signers packs a transaction version as signed int32."""
    text = (SRC / module).read_text()
    hits = [text.count("\n", 0, m.start()) + 1 for m in _SIGNED_PACK.finditer(text)]
    assert hits == [], f"{module}: signed nVersion pack at lines {hits}"
