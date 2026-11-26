"""BIP30 repeat / BIP34 hash byte order, on a DB shaped like the real one.

verify-neon-ouroboros-findings #7.  Core (validation.cpp ConnectBlock):

    bool fEnforceBIP30 = !IsBIP30Repeat(*pindex);
    CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(BIP34Height);
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height ||
        !(pindexBIP34height->GetBlockHash() == BIP34Hash));
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) { ... }

The Python validator's BIP34 arm asked the DB for ``get_block_hash_at_height``
(``BlockchainDatabase`` has only ``get_block_hash_by_height``) and compared the
answer with the DISPLAY-order hash, so it could never suppress BIP30.  The
older tests in test_bip30_bip34_coinbase.py used a MagicMock db, which answers
every attribute name, and fed it the same display-order constant, so they
passed against a path production never takes.

Here the DB stub has only the methods ``BlockchainDatabase`` has, and the
BIP34 hash is computed by double-SHA256 of the real mainnet 227931 header
(fetched from Core v31.1 with ``getblockheader <hash> false``), not copied
from the constant under test.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

from ouroboros.validation import BlockValidator

HEADER_227931 = bytes.fromhex(
    "02000000d629b6d62e07d09960f1c093dbfea0fa1b049c5b8d4c83b35102000000000000"
    "bad87c7cd313c982787729637b1ff4651df74ee34803fe84af74b667f010a2b501fd4f51"
    "6e81021a160a0594"
)


def _internal_hash(header: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


BIP34_INTERNAL = _internal_hash(HEADER_227931)
assert BIP34_INTERNAL[::-1].hex() == (
    "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
)


class _RealShapedDB:
    """Only methods BlockchainDatabase really has (no get_block_hash_at_height)."""

    def __init__(self, hash_at_bip34: bytes | None):
        self._h = hash_at_bip34

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        return self._h if height == 227_931 else None

    def get_utxo(self, txid, vout):
        return {"value": 5000}  # every output collides: BIP30 would reject

    def get_best_block(self):
        return (bytes(32), 0)

    def get_median_time_past(self, *_a, **_k):
        return 0

    def get_block(self, *_a, **_k):
        blk = MagicMock()
        blk.transactions = []
        return blk


def _coinbase(height_push: bytes):
    tx = MagicMock()
    tx.get_txid.return_value = b"\xdd" * 32
    tx.outputs = [MagicMock()]
    tx.is_coinbase = True
    tx.locktime = 0
    inp = MagicMock()
    inp.prev_txid = bytes(32)
    inp.prev_vout = 0xFFFFFFFF
    inp.script_sig = height_push + b"\x00" * 6
    inp.sequence = 0xFFFFFFFF
    tx.inputs = [inp]
    return tx


def _block(cb):
    blk = MagicMock()
    blk.hash = b"\xab" * 32
    blk.transactions = [cb]
    blk.prev_blockhash = bytes(32)
    blk.height = None
    blk.version = 4
    blk.bits = 0x1D00FFFF
    blk.nonce = 0
    blk.timestamp = 1_600_000_000
    blk.merkle_root = bytes(32)
    return blk


def _run(db, height: int, height_push: bytes):
    v = BlockValidator(db, network="mainnet")
    with patch.object(v, "_validate_header", return_value=True), \
         patch.object(v, "_verify_merkle_root", return_value=True), \
         patch.object(v, "_validate_block_limits", return_value=(True, "")), \
         patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
         patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
         patch.object(v, "_validate_coinbase", return_value=True), \
         patch.object(v, "_verify_coinbase_amount", return_value=True):
        return v.validate_block(_block(_coinbase(height_push)), known_height=height)


H250000 = b"\x03\x90\xd0\x03"   # BIP34 push of 250000
H227931 = b"\x03\x5b\x7a\x03"   # BIP34 push of 227931


def test_canonical_bip34_block_suppresses_bip30_above_it():
    ok, err = _run(_RealShapedDB(BIP34_INTERNAL), 250_000, H250000)
    assert ok, f"Core skips BIP30 above a canonical BIP34 block, got {err}"


def test_bip30_still_enforced_at_bip34_height():
    # pprev->GetAncestor(227931) is null for the block at 227931.
    ok, err = _run(_RealShapedDB(BIP34_INTERNAL), 227_931, H227931)
    assert not ok and "bad-txns-BIP30" in err


def test_non_canonical_bip34_block_keeps_bip30():
    other = bytearray(BIP34_INTERNAL)
    other[0] ^= 1
    ok, err = _run(_RealShapedDB(bytes(other)), 250_000, H250000)
    assert not ok and "bad-txns-BIP30" in err


def test_display_order_hash_is_not_the_canonical_block():
    # The display-order bytes are not a block hash the DB can return.
    ok, err = _run(_RealShapedDB(BIP34_INTERNAL[::-1]), 250_000, H250000)
    assert not ok and "bad-txns-BIP30" in err
