"""
Unit tests for fee bumping (bumpfee / psbtbumpfee RPC).

Tests the wallet.bump_fee() method and the RPC wrappers by building
mock mempool / database / wallet objects and verifying the full
bump-fee flow.
"""

import asyncio
import hashlib
import os
import struct
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure the src directory is on the path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

# Mock the Rust extension module before any ouroboros import
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

# We import only the pure-Python modules we need, avoiding the Rust
# extension (`sync`) required by the real BlockchainDatabase.
from ouroboros.wallet import (
    Wallet,
    WalletKey,
    _dsha256,
    _hash160,
    INPUT_VBYTES,
    OUTPUT_VBYTES,
    OVERHEAD_VBYTES,
)


# ── Lightweight stand-ins for database.py dataclasses ────────────────
# We redefine them here so we don't trigger the `import sync` error.

@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class TxIn:
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: Optional[List[bytes]] = None


@dataclass
class Transaction:
    txid: bytes
    version: int
    locktime: int
    inputs: List[TxIn]
    outputs: List[TxOut]
    has_witness: bool = False

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == bytes(32)

    def _encode_varint(self, value: int) -> bytes:
        if value < 0xFD:
            return bytes([value])
        elif value <= 0xFFFF:
            return b"\xfd" + value.to_bytes(2, "little")
        elif value <= 0xFFFFFFFF:
            return b"\xfe" + value.to_bytes(4, "little")
        return b"\xff" + value.to_bytes(8, "little")

    def serialize(self) -> bytes:
        data = self.version.to_bytes(4, "little")
        data += self._encode_varint(len(self.inputs))
        for tx_in in self.inputs:
            data += tx_in.prev_txid
            data += tx_in.prev_vout.to_bytes(4, "little")
            data += self._encode_varint(len(tx_in.script_sig))
            data += tx_in.script_sig
            data += tx_in.sequence.to_bytes(4, "little")
        data += self._encode_varint(len(self.outputs))
        for tx_out in self.outputs:
            data += tx_out.value.to_bytes(8, "little")
            data += self._encode_varint(len(tx_out.script_pubkey))
            data += tx_out.script_pubkey
        data += self.locktime.to_bytes(4, "little")
        return data

    def serialize_with_witness(self) -> bytes:
        data = bytearray()
        data.extend(self.version.to_bytes(4, "little", signed=True))
        if self.has_witness:
            data.extend(b"\x00\x01")
        data.extend(self._encode_varint(len(self.inputs)))
        for tx_in in self.inputs:
            data.extend(tx_in.prev_txid)
            data.extend(tx_in.prev_vout.to_bytes(4, "little"))
            data.extend(self._encode_varint(len(tx_in.script_sig)))
            data.extend(tx_in.script_sig)
            data.extend(tx_in.sequence.to_bytes(4, "little"))
        data.extend(self._encode_varint(len(self.outputs)))
        for tx_out in self.outputs:
            data.extend(tx_out.value.to_bytes(8, "little"))
            data.extend(self._encode_varint(len(tx_out.script_pubkey)))
            data.extend(tx_out.script_pubkey)
        if self.has_witness:
            for tx_in in self.inputs:
                witness = tx_in.witness or []
                data.extend(self._encode_varint(len(witness)))
                for item in witness:
                    data.extend(self._encode_varint(len(item)))
                    data.extend(item)
        data.extend(self.locktime.to_bytes(4, "little"))
        return bytes(data)

    def get_txid(self) -> bytes:
        return self.txid

    def get_witness_bytes(self) -> int:
        if not self.has_witness:
            return 0
        total = 0
        for tx_in in self.inputs:
            if tx_in.witness is None:
                continue
            total += len(self._encode_varint(len(tx_in.witness)))
            for item in tx_in.witness:
                total += len(self._encode_varint(len(item))) + len(item)
        return total

    def get_weight(self) -> int:
        non_witness_bytes = len(self.serialize())
        if self.has_witness:
            non_witness_bytes += 2
        witness_bytes = self.get_witness_bytes()
        return (non_witness_bytes * 4) + witness_bytes

    def get_vsize(self) -> int:
        weight = self.get_weight()
        return (weight + 3) // 4


@dataclass
class MempoolEntry:
    tx: Transaction
    fee: int
    fee_rate: float
    size: int
    time_added: float
    height_added: int
    ancestor_count: int = 1
    ancestor_size: int = 0
    descendant_count: int = 1
    descendant_size: int = 0


# ── Mock objects ─────────────────────────────────────────────────────


class MockMempool:
    """Minimal mempool mock that supports the operations needed by bump_fee."""

    def __init__(self):
        self.transactions: Dict[bytes, MempoolEntry] = {}

    def add_transaction(self, tx: Transaction, height: int) -> Tuple[bool, str]:
        fee = 0  # will be set in tests
        vsize = tx.get_vsize()
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee / max(vsize, 1),
            size=vsize,
            time_added=0,
            height_added=height,
        )
        self.transactions[tx.txid] = entry
        return True, ""

    def add_entry(self, tx: Transaction, fee: int, height: int = 100):
        """Helper: add a transaction with a known fee."""
        vsize = tx.get_vsize()
        entry = MempoolEntry(
            tx=tx,
            fee=fee,
            fee_rate=fee / max(vsize, 1),
            size=vsize,
            time_added=0,
            height_added=height,
        )
        self.transactions[tx.txid] = entry

    def get_transaction(self, txid: bytes) -> Optional[Transaction]:
        entry = self.transactions.get(txid)
        return entry.tx if entry else None

    def get_transaction_entry(self, txid: bytes) -> Optional[MempoolEntry]:
        return self.transactions.get(txid)

    def has_transaction(self, txid: bytes) -> bool:
        return txid in self.transactions

    def try_replace(self, new_tx: Transaction, height: int) -> Tuple[bool, str]:
        """Accept replacement if new tx conflicts with an existing one and has higher fee."""
        # Find conflicts
        conflicts = set()
        for inp in new_tx.inputs:
            for txid, entry in self.transactions.items():
                for existing_inp in entry.tx.inputs:
                    if (
                        inp.prev_txid == existing_inp.prev_txid
                        and inp.prev_vout == existing_inp.prev_vout
                    ):
                        conflicts.add(txid)

        if not conflicts:
            return False, "No conflicts to replace"

        # Check that conflicting txs signal RBF
        for c_txid in conflicts:
            c_entry = self.transactions[c_txid]
            if not any(i.sequence < 0xFFFFFFFE for i in c_entry.tx.inputs):
                return False, "Conflicting tx does not signal replaceability"

        # Calculate new tx fee (total_in - total_out)
        total_in = 0
        for inp in new_tx.inputs:
            for txid, entry in self.transactions.items():
                if txid in conflicts:
                    continue
                if inp.prev_txid == entry.tx.txid:
                    if inp.prev_vout < len(entry.tx.outputs):
                        total_in += entry.tx.outputs[inp.prev_vout].value
            # Also check the mock UTXO source (handled by test setup)

        # Remove conflicts and add new tx
        evicted_fee = sum(self.transactions[c].fee for c in conflicts)
        for c_txid in conflicts:
            del self.transactions[c_txid]

        new_vsize = new_tx.get_vsize()
        new_total_out = sum(o.value for o in new_tx.outputs)
        # We'll compute fee from context in the test; for now trust it
        new_fee = evicted_fee + 1000  # mock: just make it higher
        entry = MempoolEntry(
            tx=new_tx,
            fee=new_fee,
            fee_rate=new_fee / max(new_vsize, 1),
            size=new_vsize,
            time_added=0,
            height_added=height,
        )
        self.transactions[new_tx.txid] = entry
        return True, ""


class MockDB:
    """Minimal database mock."""

    def __init__(self):
        self.utxos: Dict[Tuple[bytes, int], dict] = {}
        self.best_height = 100

    def get_utxo(self, txid: bytes, vout: int) -> Optional[dict]:
        return self.utxos.get((txid, vout))

    def get_best_block(self) -> Tuple[bytes, int]:
        return (b"\x00" * 32, self.best_height)

    def get_balance(self, address: str, network: str) -> int:
        return 0

    def list_unspent_by_address(self, address: str, network: str) -> List[dict]:
        result = []
        for (txid, vout), utxo in self.utxos.items():
            if utxo.get("_address") == address:
                result.append(utxo)
        return result

    def get_transactions_for_address(self, address: str, network: str) -> list:
        return []


# ── Helpers ──────────────────────────────────────────────────────────


def make_key() -> WalletKey:
    """Generate a random wallet key on testnet."""
    return WalletKey.generate(network="testnet")


def make_txid() -> bytes:
    """Generate a random 32-byte txid."""
    return os.urandom(32)


def make_funding_tx(
    wallet_key: WalletKey, amount: int = 100_000
) -> Tuple[Transaction, bytes]:
    """Create a simple funding transaction that pays to the wallet key."""
    txid = make_txid()
    tx = Transaction(
        txid=txid,
        version=2,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=bytes(32),
                prev_vout=0xFFFFFFFF,
                script_sig=b"\x01\x01",
                sequence=0xFFFFFFFF,
            )
        ],
        outputs=[
            TxOut(value=amount, script_pubkey=wallet_key.get_script_pubkey())
        ],
    )
    return tx, txid


# ── Test Cases ───────────────────────────────────────────────────────


class TestBumpFee(unittest.TestCase):
    """Test wallet.bump_fee() logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Patch the database import so Wallet doesn't pull in Rust
        self.wallet = Wallet.__new__(Wallet)
        self.wallet.data_dir = Path(self.tmpdir)
        self.wallet.network = "testnet"
        self.wallet.name = "test"
        self.wallet.wallet_path = Path(self.tmpdir) / "wallets" / "test.json"
        self.wallet.wallet_path.parent.mkdir(parents=True, exist_ok=True)
        self.wallet._hd_seed = None
        self.wallet._hd_next_index = 0
        self.wallet._hd_base_path = "m/84'/0'/0'/0"
        self.wallet._passphrase = None
        self.wallet._encrypted_blob = None

        self.key = make_key()
        self.wallet.keys = [{"wif": self.key.to_wif(), "label": "", "created": 0}]

        self.db = MockDB()
        self.mempool = MockMempool()
        self.wallet.db = self.db
        self.wallet.mempool = self.mempool

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_original_tx(
        self, *, rbf: bool = True, fee: int = 500, amount: int = 50_000
    ) -> Tuple[Transaction, bytes]:
        """Create an original transaction in the mock mempool.

        Returns (original_tx, funding_txid).
        """
        funding_txid = make_txid()
        funding_value = amount + fee + 10_000  # generous for change

        # Register the funding UTXO
        self.db.utxos[(funding_txid, 0)] = {
            "txid": funding_txid,
            "vout": 0,
            "value": funding_value,
            "script_pubkey": self.key.get_script_pubkey(),
            "_address": self.key.get_p2wpkh_address(),
        }

        dest_spk = b"\x00\x14" + os.urandom(20)  # random P2WPKH
        change_value = funding_value - amount - fee

        orig_tx = Transaction(
            txid=b"\x00" * 32,  # placeholder
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=funding_txid,
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFD if rbf else 0xFFFFFFFF,
                    witness=[b"\x00" * 72, self.key.pubkey],
                )
            ],
            outputs=[
                TxOut(value=amount, script_pubkey=dest_spk),
                TxOut(
                    value=change_value,
                    script_pubkey=self.key.get_script_pubkey(),
                ),
            ],
            has_witness=True,
        )
        orig_tx.txid = _dsha256(orig_tx.serialize())

        self.mempool.add_entry(orig_tx, fee=fee, height=100)
        return orig_tx, funding_txid

    # ── Core bump_fee tests ──────────────────────────────────────────

    def test_bump_fee_basic(self):
        """bump_fee succeeds and returns a new txid."""
        orig_tx, _ = self._create_original_tx(rbf=True, fee=500)

        async def run():
            # Patch the database module import inside bump_fee
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                result = await self.wallet.bump_fee(
                    orig_tx.txid.hex(), new_fee_rate=20
                )
            return result

        new_txid = asyncio.run(run())
        self.assertIsNotNone(new_txid, "bump_fee should return a new txid")
        self.assertNotEqual(new_txid, orig_tx.txid.hex())
        # Original should no longer be in mempool
        self.assertFalse(
            self.mempool.has_transaction(orig_tx.txid),
            "Original tx should be replaced",
        )
        # New tx should be in mempool
        self.assertTrue(
            self.mempool.has_transaction(bytes.fromhex(new_txid)),
            "New tx should be in mempool",
        )

    def test_bump_fee_rejects_non_rbf(self):
        """bump_fee returns None for a tx that does not signal RBF."""
        orig_tx, _ = self._create_original_tx(rbf=False, fee=500)

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                return await self.wallet.bump_fee(
                    orig_tx.txid.hex(), new_fee_rate=20
                )

        result = asyncio.run(run())
        self.assertIsNone(result, "bump_fee should reject non-RBF tx")

    def test_bump_fee_missing_tx(self):
        """bump_fee returns None for a txid not in mempool."""

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                return await self.wallet.bump_fee("aa" * 32, new_fee_rate=20)

        result = asyncio.run(run())
        self.assertIsNone(result, "bump_fee should return None for missing tx")

    def test_bump_fee_no_mempool(self):
        """bump_fee returns None when mempool is not set."""
        self.wallet.mempool = None

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                return await self.wallet.bump_fee("aa" * 32, new_fee_rate=20)

        result = asyncio.run(run())
        self.assertIsNone(result)

    def test_bump_fee_unsigned(self):
        """bump_fee with sign=False returns unsigned hex."""
        orig_tx, _ = self._create_original_tx(rbf=True, fee=500)

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                return await self.wallet.bump_fee(
                    orig_tx.txid.hex(), new_fee_rate=20, sign=False
                )

        result = asyncio.run(run())
        self.assertIsNotNone(result, "unsigned bump_fee should return hex")
        # Should be valid hex
        bytes.fromhex(result)
        # Original should still be in mempool (unsigned doesn't submit)
        self.assertTrue(
            self.mempool.has_transaction(orig_tx.txid),
            "Original tx should still be in mempool for unsigned bump",
        )

    def test_bump_fee_reduces_change(self):
        """The change output should be smaller after fee bump."""
        orig_tx, _ = self._create_original_tx(rbf=True, fee=200, amount=50_000)
        orig_change = orig_tx.outputs[1].value  # change output

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                new_txid = await self.wallet.bump_fee(
                    orig_tx.txid.hex(), new_fee_rate=50
                )
            return new_txid

        new_txid = asyncio.run(run())
        self.assertIsNotNone(new_txid)

        # Check new tx in mempool has lower change
        new_entry = self.mempool.get_transaction_entry(bytes.fromhex(new_txid))
        self.assertIsNotNone(new_entry)
        new_tx = new_entry.tx

        # Destination output (index 0) should be unchanged
        self.assertEqual(
            new_tx.outputs[0].value,
            orig_tx.outputs[0].value,
            "Destination output should remain unchanged",
        )

        # If there's a change output, it should be smaller
        if len(new_tx.outputs) > 1:
            new_change = new_tx.outputs[1].value
            self.assertLess(
                new_change,
                orig_change,
                "Change output should be reduced to cover higher fee",
            )

    def test_bump_fee_preserves_rbf_sequence(self):
        """New transaction inputs should signal RBF."""
        orig_tx, _ = self._create_original_tx(rbf=True, fee=500)

        async def run():
            with patch.dict("sys.modules", {
                "ouroboros.database": MagicMock(
                    Transaction=Transaction, TxIn=TxIn, TxOut=TxOut
                ),
            }):
                return await self.wallet.bump_fee(
                    orig_tx.txid.hex(), new_fee_rate=20
                )

        new_txid = asyncio.run(run())
        self.assertIsNotNone(new_txid)

        new_entry = self.mempool.get_transaction_entry(bytes.fromhex(new_txid))
        for inp in new_entry.tx.inputs:
            self.assertLess(
                inp.sequence,
                0xFFFFFFFE,
                "All replacement inputs should signal RBF",
            )


class TestBumpFeeRPC(unittest.TestCase):
    """Verify the RPC endpoint stubs are properly defined."""

    def test_rpc_bumpfee_method_exists(self):
        """The RPCServer class should have rpc_bumpfee method."""
        from ouroboros.rpc import RPCServer

        self.assertTrue(hasattr(RPCServer, "rpc_bumpfee"))
        self.assertTrue(callable(getattr(RPCServer, "rpc_bumpfee")))

    def test_rpc_psbtbumpfee_method_exists(self):
        """The RPCServer class should have rpc_psbtbumpfee method."""
        from ouroboros.rpc import RPCServer

        self.assertTrue(hasattr(RPCServer, "rpc_psbtbumpfee"))
        self.assertTrue(callable(getattr(RPCServer, "rpc_psbtbumpfee")))


if __name__ == "__main__":
    unittest.main()
