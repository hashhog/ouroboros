"""Block sigop cost must count inputs that spend an output created EARLIER IN
THE SAME BLOCK.

Bitcoin Core ConnectBlock (validation.cpp:2568) adds
``GetTransactionSigOpCost(tx, view, flags)`` (consensus/tx_verify.cpp:143) for
each tx against a coins view that ``UpdateCoins`` (validation.cpp:2600) has
already filled with every earlier tx's outputs, so the P2SH redeemScript
sigops (BIP16, x WITNESS_SCALE_FACTOR) and witness sigops (BIP141, x1) of an
in-block spend are counted toward MAX_BLOCK_SIGOPS_COST (80,000).

``_validate_block_limits`` used to resolve every prevout against the chainstate
only; an in-block coin is not there yet, so the input was skipped and a block
Core rejects ``bad-blk-sigops`` was accepted on the P2P path.

The blocks here mirror the regtest discriminators (P2SH: 11 x 8,000 = 88,000;
P2WSH: 41 x 2,000 = 82,000) and their at-limit controls (80,000 accept).
"""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.modules.setdefault("sync", MagicMock())
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.validation import (  # noqa: E402
    MAX_BLOCK_SIGOPS_COST,
    BlockValidator,
)

# 100 x (OP_0 OP_0 OP_0 OP_CHECKMULTISIG OP_DROP) + OP_1: executes, and
# GetSigOpCount(true) counts 20 per CHECKMULTISIG (preceded by OP_0) = 2,000.
UNIT_SCRIPT = (b"\x00\x00\x00\xae\x75" * 100) + b"\x51"
SIGOPS_PER_INPUT = 2_000


def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def _push(b: bytes) -> bytes:
    n = len(b)
    if n < 0x4C:
        return bytes([n]) + b
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


P2SH_SPK = b"\xa9\x14" + _hash160(UNIT_SCRIPT) + b"\x87"
P2WSH_SPK = b"\x00\x20" + hashlib.sha256(UNIT_SCRIPT).digest()

CB_TXID = b"\xc0" * 32
FUND_TXID = b"\xf0" * 32  # a chainstate coin (OP_TRUE) T1 spends
T1_TXID = b"\x11" * 32
T2_TXID = b"\x22" * 32


def _coinbase() -> Transaction:
    return Transaction(
        txid=CB_TXID, version=2, locktime=0,
        inputs=[TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                     script_sig=b"\x01\x6f\x00", sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=0, script_pubkey=b"\x51")],
    )


def _block(n_inputs: int, kind: str) -> Block:
    spk = P2SH_SPK if kind == "p2sh" else P2WSH_SPK
    t1 = Transaction(
        txid=T1_TXID, version=2, locktime=0,
        inputs=[TxIn(prev_txid=FUND_TXID, prev_vout=0, script_sig=b"",
                     sequence=0xFFFFFFFF)],
        outputs=[TxOut(value=1000, script_pubkey=spk) for _ in range(n_inputs)],
    )
    if kind == "p2sh":
        ins = [TxIn(prev_txid=T1_TXID, prev_vout=i, script_sig=_push(UNIT_SCRIPT),
                    sequence=0xFFFFFFFF) for i in range(n_inputs)]
        has_witness = False
    else:
        ins = [TxIn(prev_txid=T1_TXID, prev_vout=i, script_sig=b"",
                    sequence=0xFFFFFFFF, witness=[UNIT_SCRIPT])
               for i in range(n_inputs)]
        has_witness = True
    t2 = Transaction(txid=T2_TXID, version=2, locktime=0, inputs=ins,
                     outputs=[TxOut(value=1, script_pubkey=b"\x51")],
                     has_witness=has_witness)
    return Block(version=0x20000000, prev_blockhash=bytes(32),
                 merkle_root=bytes(32), timestamp=0, bits=0x207FFFFF, nonce=0,
                 transactions=[_coinbase(), t1, t2], hash=b"\xab" * 32)


class _ChainstateDB:
    """Chainstate holding only ``coins``; an in-block coin is absent, exactly
    as it is in the live RocksDB chainstate while the block is validated."""

    def __init__(self, coins=None):
        self.coins = dict(coins or {})
        self.lookups = []

    def get_utxo(self, txid, vout):
        self.lookups.append((txid, vout))
        spk = self.coins.get((txid, vout))
        return None if spk is None else {"script_pubkey": spk, "value": 1000}


def _validator(db) -> BlockValidator:
    v = BlockValidator.__new__(BlockValidator)
    v.db = db
    v.network = "regtest"
    return v


class TestInBlockSpendSigops(unittest.TestCase):
    def _check(self, n, kind, expect_ok, expect_cost):
        db = _ChainstateDB({(FUND_TXID, 0): b"\x51"})
        v = _validator(db)
        for height in (None, 111):  # flags default-on / regtest height 111
            ok, err = v._validate_block_limits(_block(n, kind), height, b"\xab" * 32)
            self.assertEqual(ok, expect_ok, f"{kind} n={n} height={height}: {err}")
            if not expect_ok:
                self.assertIn(f"Block sigops cost {expect_cost} exceeds", err)

    def test_p2sh_inblock_over_limit_rejected(self):
        # 11 x 2,000 x 4 = 88,000 > 80,000 (Core: bad-blk-sigops)
        self._check(11, "p2sh", False, 11 * SIGOPS_PER_INPUT * 4)

    def test_p2sh_inblock_at_limit_accepted(self):
        # 10 x 2,000 x 4 = 80,000 == MAX; the test is `>`
        self.assertEqual(10 * SIGOPS_PER_INPUT * 4, MAX_BLOCK_SIGOPS_COST)
        self._check(10, "p2sh", True, None)

    def test_p2wsh_inblock_over_limit_rejected(self):
        # 41 x 2,000 x 1 = 82,000 > 80,000 (Core: bad-blk-sigops)
        self._check(41, "p2wsh", False, 41 * SIGOPS_PER_INPUT)

    def test_p2wsh_inblock_at_limit_accepted(self):
        self.assertEqual(40 * SIGOPS_PER_INPUT, MAX_BLOCK_SIGOPS_COST)
        self._check(40, "p2wsh", True, None)

    def test_inblock_and_chainstate_spend_count_identically(self):
        # Control: the same T2 spending coins that are ALREADY in the
        # chainstate must give the same verdict/cost as the in-block spend.
        blk = _block(11, "p2sh")
        coins = {(T1_TXID, i): P2SH_SPK for i in range(11)}
        coins[(FUND_TXID, 0)] = b"\x51"
        blk.transactions = [blk.transactions[0], blk.transactions[2]]  # drop T1
        ok, err = _validator(_ChainstateDB(coins))._validate_block_limits(blk)
        self.assertFalse(ok)
        self.assertIn(f"Block sigops cost {11 * SIGOPS_PER_INPUT * 4} exceeds", err)

    def test_tx_does_not_see_its_own_or_later_outputs(self):
        # Core's view only holds EARLIER txs' outputs.  A tx whose input names
        # a LATER tx's output resolves nothing here (tx validation rejects it
        # as missing); it must not be counted from the not-yet-created coin.
        blk = _block(11, "p2sh")
        cb, t1, t2 = blk.transactions
        blk.transactions = [cb, t2, t1]  # spender BEFORE the creator
        ok, err = _validator(_ChainstateDB({(FUND_TXID, 0): b"\x51"}))._validate_block_limits(blk)
        self.assertTrue(ok, err)

    def test_p2sh_flag_off_skips_inblock_p2sh_sigops(self):
        # Exception-block gating still applies to in-block coins: with
        # SCRIPT_VERIFY_P2SH clear (mainnet 170060's flags), P2SH sigops are
        # not counted (tx_verify.cpp:150).
        import ouroboros.validation as val
        orig = val.get_flags_for_height
        val.get_flags_for_height = lambda h, bh, net: 0
        try:
            ok, err = _validator(_ChainstateDB({(FUND_TXID, 0): b"\x51"}))._validate_block_limits(
                _block(11, "p2sh"), 111, b"\xab" * 32)
        finally:
            val.get_flags_for_height = orig
        self.assertTrue(ok, err)


if __name__ == "__main__":
    unittest.main()
