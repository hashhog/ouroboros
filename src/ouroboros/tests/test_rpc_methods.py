"""
Test new RPC methods.

This test verifies that the new RPC methods (getrawmempool, getblockheader, gettxout)
are implemented and work correctly.
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.node import BitcoinNode
from ouroboros.rpc import RPCServer


class TestRPCMethods(unittest.TestCase):
    """Test new RPC methods"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc_server = RPCServer(self.node, port=18332)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_getrawmempool_method_exists(self):
        """Test that getrawmempool method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_getrawmempool'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_getrawmempool', None)))
    
    def test_getrawmempool_returns_list(self):
        """Test that getrawmempool returns a list when verbose=False"""
        import asyncio
        
        async def test():
            result = await self.rpc_server.rpc_getrawmempool(verbose=False)
            self.assertIsInstance(result, list)
        
        asyncio.run(test())
    
    def test_getrawmempool_verbose_returns_dict(self):
        """Test that getrawmempool returns a dict when verbose=True"""
        import asyncio
        
        async def test():
            result = await self.rpc_server.rpc_getrawmempool(verbose=True)
            self.assertIsInstance(result, dict)
        
        asyncio.run(test())
    
    def test_getblockheader_method_exists(self):
        """Test that getblockheader method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_getblockheader'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_getblockheader', None)))
    
    def test_getblockheader_handles_invalid_hash(self):
        """Test that getblockheader handles invalid hash"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_getblockheader("invalid_hash", verbose=True)
        
        asyncio.run(test())
    
    def test_getblockheader_handles_not_found(self):
        """Test that getblockheader handles block not found"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            # Use a valid hex string but non-existent block
            fake_hash = "0" * 64
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_getblockheader(fake_hash, verbose=True)
        
        asyncio.run(test())
    
    def test_gettxout_method_exists(self):
        """Test that gettxout method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_gettxout'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_gettxout', None)))
    
    def test_gettxout_handles_invalid_txid(self):
        """Test that gettxout handles invalid transaction ID"""
        import asyncio
        from fastapi import HTTPException
        
        async def test():
            with self.assertRaises(HTTPException):
                await self.rpc_server.rpc_gettxout("invalid_txid", 0, includemempool=True)
        
        asyncio.run(test())
    
    def test_gettxout_returns_none_for_nonexistent(self):
        """Test that gettxout returns None for non-existent UTXO"""
        import asyncio
        
        async def test():
            # Use a valid hex string but non-existent transaction
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=True)
            # Should return None, not raise an exception
            self.assertIsNone(result)
        
        asyncio.run(test())
    
    def test_gettxout_with_mempool(self):
        """Test that gettxout checks mempool when includemempool=True"""
        import asyncio
        
        async def test():
            # Even if mempool is empty, should not raise exception
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=True)
            self.assertIsNone(result)
        
        asyncio.run(test())
    
    def test_gettxout_without_mempool(self):
        """Test that gettxout skips mempool when includemempool=False"""
        import asyncio

        async def test():
            fake_txid = "0" * 64
            result = await self.rpc_server.rpc_gettxout(fake_txid, 0, includemempool=False)
            self.assertIsNone(result)

        asyncio.run(test())

    def test_sendrawtransaction_method_exists(self):
        """Test that sendrawtransaction method exists"""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_sendrawtransaction'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_sendrawtransaction', None)))

    def test_sendrawtransaction_invalid_hex(self):
        """Test sendrawtransaction rejects invalid hex"""
        import asyncio
        from fastapi import HTTPException

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction("nothex")
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Invalid hex", ctx.exception.detail)

        asyncio.run(test())

    def test_sendrawtransaction_coinbase_rejected(self):
        """Test sendrawtransaction rejects coinbase transactions"""
        import asyncio
        from fastapi import HTTPException

        # Genesis block coinbase tx hex
        coinbase_hex = (
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff1d030f8d13049faa805a063538706f6f6c0c00010000fe22030000000000ffffff"
            "ff015341cb04000000001976a914f11298ce777cb5db5c09250cad4eb856b1e366ef88ac"
            "00000000"
        )

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction(coinbase_hex)
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Coinbase", ctx.exception.detail)

        asyncio.run(test())

    def test_sendrawtransaction_mempool_unavailable(self):
        """Test sendrawtransaction when mempool is not available"""
        import asyncio
        from fastapi import HTTPException

        # Valid non-coinbase tx (P2PKH from Bitcoin Core test)
        tx_hex = (
            "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d"
            "000000008a4730440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d5027"
            "8380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a218"
            "8e96e01410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
            "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8fffffff"
            "f01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00"
            "000000"
        )

        async def test():
            # Node has no mempool (not started) -> 500
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_sendrawtransaction(tx_hex)
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("Mempool", ctx.exception.detail)

        asyncio.run(test())


class TestSubmitPackage(unittest.TestCase):
    """Tests for the submitpackage RPC endpoint."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc_server = RPCServer(self.node, port=18332)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_submitpackage_method_exists(self):
        """Test that submitpackage method exists and is callable."""
        self.assertTrue(hasattr(self.rpc_server, 'rpc_submitpackage'))
        self.assertTrue(callable(getattr(self.rpc_server, 'rpc_submitpackage', None)))

    def test_submitpackage_rejects_empty_package(self):
        """Test that submitpackage rejects an empty package list."""
        import asyncio
        from fastapi import HTTPException

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_submitpackage([])
            self.assertEqual(ctx.exception.status_code, 400)

        asyncio.run(test())

    def test_submitpackage_rejects_invalid_hex(self):
        """Test that submitpackage rejects invalid hex strings."""
        import asyncio
        from fastapi import HTTPException

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_submitpackage(["nothex"])
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Invalid hex", ctx.exception.detail)

        asyncio.run(test())

    def test_submitpackage_rejects_coinbase(self):
        """Test that submitpackage rejects coinbase transactions."""
        import asyncio
        from fastapi import HTTPException

        # Genesis block coinbase tx hex
        coinbase_hex = (
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff1d030f8d13049faa805a063538706f6f6c0c00010000fe22030000000000ffffff"
            "ff015341cb04000000001976a914f11298ce777cb5db5c09250cad4eb856b1e366ef88ac"
            "00000000"
        )

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_submitpackage([coinbase_hex])
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Coinbase", ctx.exception.detail)

        asyncio.run(test())

    def test_submitpackage_mempool_unavailable(self):
        """Test that submitpackage returns error when mempool is not available."""
        import asyncio
        from fastapi import HTTPException

        # Valid non-coinbase tx hex
        tx_hex = (
            "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d"
            "000000008a4730440220131432090a6af42da3e8335ff110831b41a44f4e9d18d88f5d5027"
            "8380696c7202200fc2e48938f323ad13625890c0ea926c8a189c08b8efc38376b20c8a218"
            "8e96e01410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
            "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8fffffff"
            "f01a0860100000000001976a9145834479edbbe0539b31ffd3a8f8ebadc2165ed0188ac00"
            "000000"
        )

        async def test():
            with self.assertRaises(HTTPException) as ctx:
                await self.rpc_server.rpc_submitpackage([tx_hex])
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("Mempool", ctx.exception.detail)

        asyncio.run(test())

    def test_submitpackage_cpfp_success(self):
        """Test submitting a 2-tx CPFP package where child pays for parent.

        This creates a parent tx with a very low fee and a child tx that
        spends the parent's output with a high enough fee to bring the
        package fee rate above the minimum relay fee threshold.
        """
        import asyncio
        from ouroboros.mempool import Mempool
        from ouroboros.database import Transaction, TxIn, TxOut

        # -- stub validator / UTXO DB -----------------------------------------

        class _StubUTXODB:
            def __init__(self, mapping):
                self._m = dict(mapping)

            def get_utxo(self, txid, vout):
                return self._m.get((txid, vout))

        class _StubValidator:
            def __init__(self, utxo_values):
                self.db = _StubUTXODB(utxo_values)

            def validate_transaction(self, tx, height, block_mtp=0):
                return True, ""

        class _StubDB:
            def get_best_block(self):
                return (b"\x00" * 32, 100)

        # -- build parent & child txs -----------------------------------------
        # Confirmed UTXO: 100,000 sats
        confirmed_txid = b"\x01" * 32
        utxos = {(confirmed_txid, 0): {"value": 100_000}}

        parent = Transaction(
            txid=b"\xAA" * 32,
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=confirmed_txid,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                )
            ],
            # Parent pays near-zero fee: 100,000 - 99,999 = 1 sat
            outputs=[TxOut(value=99_999, script_pubkey=b"\x00\x14" + b"\x00" * 20)],
        )

        child = Transaction(
            txid=b"\xBB" * 32,
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\xAA" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                )
            ],
            # Child pays high fee: 99,999 - 90,000 = 9,999 sats
            # Total package fee: 1 + 9,999 = 10,000 sats for ~250 bytes
            outputs=[TxOut(value=90_000, script_pubkey=b"\x00\x14" + b"\x00" * 20)],
        )

        # -- wire up node stubs -----------------------------------------------
        validator = _StubValidator(utxos)
        mempool = Mempool(validator=validator, require_standard=False)

        self.node.mempool = mempool
        self.node.db = _StubDB()

        # -- serialize txs to hex for the RPC call ----------------------------
        parent_hex = parent.serialize().hex()
        child_hex = child.serialize().hex()

        async def test():
            result = await self.rpc_server.rpc_submitpackage([parent_hex, child_hex])

            # The package should be accepted
            self.assertEqual(result["package_msg"], "success")
            self.assertIn("tx-results", result)

            tx_results = result["tx-results"]
            # Should have results for both transactions
            self.assertEqual(len(tx_results), 2)

            parent_txid = parent.get_txid().hex()
            child_txid = child.get_txid().hex()

            self.assertIn(parent_txid, tx_results)
            self.assertIn(child_txid, tx_results)

            # Verify parent result
            parent_result = tx_results[parent_txid]
            self.assertEqual(parent_result["txid"], parent_txid)
            self.assertIn("vsize", parent_result)
            self.assertGreater(parent_result["vsize"], 0)
            self.assertIn("fees", parent_result)
            self.assertIn("base", parent_result["fees"])
            # Parent fee: 1 sat = 0.00000001 BTC
            self.assertAlmostEqual(parent_result["fees"]["base"], 1 / 1e8)

            # Verify child result
            child_result = tx_results[child_txid]
            self.assertEqual(child_result["txid"], child_txid)
            self.assertIn("vsize", child_result)
            self.assertGreater(child_result["vsize"], 0)
            self.assertIn("fees", child_result)
            self.assertIn("base", child_result["fees"])
            # Child fee: 9,999 sats = 0.00009999 BTC
            self.assertAlmostEqual(child_result["fees"]["base"], 9_999 / 1e8)

        asyncio.run(test())

    def test_submitpackage_validation_failure(self):
        """Test that submitpackage returns error for invalid package."""
        import asyncio
        from ouroboros.mempool import Mempool
        from ouroboros.database import Transaction, TxIn, TxOut

        class _StubUTXODB:
            def __init__(self):
                self._m = {}

            def get_utxo(self, txid, vout):
                return self._m.get((txid, vout))

        class _StubValidator:
            def __init__(self):
                self.db = _StubUTXODB()

            def validate_transaction(self, tx, height, block_mtp=0):
                return True, ""

        class _StubDB:
            def get_best_block(self):
                return (b"\x00" * 32, 100)

        # Build a tx that spends a non-existent UTXO -> package will fail
        tx = Transaction(
            txid=b"\xCC" * 32,
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\xFF" * 32,
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFD,
                )
            ],
            outputs=[TxOut(value=50_000, script_pubkey=b"\x00\x14" + b"\x00" * 20)],
        )

        self.node.mempool = Mempool(validator=_StubValidator(), require_standard=False)
        self.node.db = _StubDB()

        tx_hex = tx.serialize().hex()

        async def test():
            result = await self.rpc_server.rpc_submitpackage([tx_hex])
            # Should fail with error message
            self.assertNotEqual(result["package_msg"], "success")
            self.assertEqual(result["tx-results"], {})

        asyncio.run(test())


class TestMempoolEntryRPCs(unittest.TestCase):
    """Tests for getmempoolentry, getmempoolancestors, getmempooldescendants."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.node = BitcoinNode(data_dir=self.temp_dir, network="regtest")
        self.rpc_server = RPCServer(self.node, port=18332)

        from ouroboros.mempool import Mempool, MempoolEntry
        from ouroboros.database import Transaction, TxIn, TxOut

        class _StubValidator:
            class db:
                @staticmethod
                def get_utxo(txid, vout):
                    return None
            @staticmethod
            def validate_transaction(tx, height, block_mtp=0):
                return True, ""

        self.mempool = Mempool(validator=_StubValidator(), require_standard=False)
        self.node.mempool = self.mempool

        # --- Build parent tx (spends a confirmed UTXO) ---
        self.parent_txid = b"\xAA" * 32
        self.parent_tx = Transaction(
            txid=self.parent_txid,
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=b"\x01" * 32,  # confirmed, not in mempool
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[
                TxOut(value=100_000, script_pubkey=b"\x00\x14" + b"\x00" * 20),
                TxOut(value=50_000, script_pubkey=b"\x00\x14" + b"\x11" * 20),
            ],
        )
        parent_entry = MempoolEntry(
            tx=self.parent_tx,
            fee=1000,
            fee_rate=5.0,
            size=len(self.parent_tx.serialize()),
            time_added=1700000000.0,
            height_added=800_000,
            ancestor_count=1,
            ancestor_size=len(self.parent_tx.serialize()),
            descendant_count=1,
            descendant_size=len(self.parent_tx.serialize()),
        )
        self.mempool.transactions[self.parent_txid] = parent_entry

        # --- Build child tx (spends parent's output 0) ---
        self.child_txid = b"\xBB" * 32
        self.child_tx = Transaction(
            txid=self.child_txid,
            version=2,
            locktime=0,
            inputs=[
                TxIn(
                    prev_txid=self.parent_txid,  # unconfirmed parent
                    prev_vout=0,
                    script_sig=b"\x00" * 72,
                    sequence=0xFFFFFFFF,
                )
            ],
            outputs=[
                TxOut(value=90_000, script_pubkey=b"\x00\x14" + b"\x22" * 20),
            ],
        )
        child_entry = MempoolEntry(
            tx=self.child_tx,
            fee=500,
            fee_rate=3.0,
            size=len(self.child_tx.serialize()),
            time_added=1700000001.0,
            height_added=800_000,
            ancestor_count=2,
            ancestor_size=len(self.parent_tx.serialize()) + len(self.child_tx.serialize()),
            descendant_count=1,
            descendant_size=len(self.child_tx.serialize()),
        )
        self.mempool.transactions[self.child_txid] = child_entry

        # Update parent's descendant count
        parent_entry.descendant_count = 2
        parent_entry.descendant_size = (
            len(self.parent_tx.serialize()) + len(self.child_tx.serialize())
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # getmempoolentry

    def test_getmempoolentry_all_fields(self):
        """getmempoolentry returns all required fields."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolentry(
                self.parent_txid.hex()
            )
            # Top-level required keys
            for key in (
                "fees", "vsize", "weight", "fee", "time", "height",
                "descendantcount", "descendantsize", "descendantfees",
                "ancestorcount", "ancestorsize", "ancestorfees",
                "depends", "spentby",
            ):
                self.assertIn(key, result, f"Missing key: {key}")

            # fees sub-keys
            for sub in ("base", "modified", "ancestor", "descendant"):
                self.assertIn(sub, result["fees"], f"Missing fees.{sub}")

        asyncio.run(test())

    def test_getmempoolentry_depends(self):
        """Child tx should list parent in depends."""
        import asyncio

        async def test():
            child = await self.rpc_server.rpc_getmempoolentry(
                self.child_txid.hex()
            )
            self.assertEqual(child["depends"], [self.parent_txid.hex()])

        asyncio.run(test())

    def test_getmempoolentry_spentby(self):
        """Parent tx should list child in spentby."""
        import asyncio

        async def test():
            parent = await self.rpc_server.rpc_getmempoolentry(
                self.parent_txid.hex()
            )
            self.assertEqual(parent["spentby"], [self.child_txid.hex()])

        asyncio.run(test())

    def test_getmempoolentry_parent_no_depends(self):
        """Parent tx has no unconfirmed parents -> depends is empty."""
        import asyncio

        async def test():
            parent = await self.rpc_server.rpc_getmempoolentry(
                self.parent_txid.hex()
            )
            self.assertEqual(parent["depends"], [])

        asyncio.run(test())

    def test_getmempoolentry_child_no_spentby(self):
        """Child tx has no unconfirmed children -> spentby is empty."""
        import asyncio

        async def test():
            child = await self.rpc_server.rpc_getmempoolentry(
                self.child_txid.hex()
            )
            self.assertEqual(child["spentby"], [])

        asyncio.run(test())

    def test_getmempoolentry_fees(self):
        """Fee fields should be in BTC."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolentry(
                self.parent_txid.hex()
            )
            self.assertAlmostEqual(result["fees"]["base"], 1000 / 1e8)
            self.assertAlmostEqual(result["fees"]["modified"], 1000 / 1e8)
            # ancestor fees = parent fee only (no ancestors)
            self.assertAlmostEqual(result["fees"]["ancestor"], 1000 / 1e8)
            # descendant fees = parent + child
            self.assertAlmostEqual(result["fees"]["descendant"], 1500 / 1e8)
            self.assertAlmostEqual(result["fee"], 1000 / 1e8)

        asyncio.run(test())

    def test_getmempoolentry_weight_vsize(self):
        """weight and vsize should be consistent."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolentry(
                self.parent_txid.hex()
            )
            self.assertIsInstance(result["weight"], int)
            self.assertIsInstance(result["vsize"], int)
            self.assertEqual(result["vsize"], (result["weight"] + 3) // 4)

        asyncio.run(test())

    def test_getmempoolentry_not_found(self):
        """getmempoolentry raises on unknown txid."""
        import asyncio

        async def test():
            with self.assertRaises(ValueError):
                await self.rpc_server.rpc_getmempoolentry("ff" * 32)

        asyncio.run(test())

    # getmempoolancestors

    def test_getmempoolancestors_non_verbose(self):
        """Non-verbose returns list of ancestor txid hex strings."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolancestors(
                self.child_txid.hex()
            )
            self.assertIsInstance(result, list)
            self.assertIn(self.parent_txid.hex(), result)

        asyncio.run(test())

    def test_getmempoolancestors_verbose(self):
        """Verbose returns dict keyed by ancestor txid with full entry."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolancestors(
                self.child_txid.hex(), verbose=True
            )
            self.assertIsInstance(result, dict)
            self.assertIn(self.parent_txid.hex(), result)
            entry = result[self.parent_txid.hex()]
            self.assertIn("fees", entry)
            self.assertIn("depends", entry)
            self.assertIn("spentby", entry)

        asyncio.run(test())

    def test_getmempoolancestors_parent_has_none(self):
        """Parent tx has no ancestors in mempool."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempoolancestors(
                self.parent_txid.hex()
            )
            self.assertEqual(result, [])

        asyncio.run(test())

    # getmempooldescendants

    def test_getmempooldescendants_non_verbose(self):
        """Non-verbose returns list of descendant txid hex strings."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempooldescendants(
                self.parent_txid.hex()
            )
            self.assertIsInstance(result, list)
            self.assertIn(self.child_txid.hex(), result)

        asyncio.run(test())

    def test_getmempooldescendants_verbose(self):
        """Verbose returns dict keyed by descendant txid with full entry."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempooldescendants(
                self.parent_txid.hex(), verbose=True
            )
            self.assertIsInstance(result, dict)
            self.assertIn(self.child_txid.hex(), result)
            entry = result[self.child_txid.hex()]
            self.assertIn("fees", entry)
            self.assertIn("depends", entry)
            self.assertIn("spentby", entry)

        asyncio.run(test())

    def test_getmempooldescendants_child_has_none(self):
        """Child tx has no descendants in mempool."""
        import asyncio

        async def test():
            result = await self.rpc_server.rpc_getmempooldescendants(
                self.child_txid.hex()
            )
            self.assertEqual(result, [])

        asyncio.run(test())

    def test_getmempooldescendants_not_found(self):
        """getmempooldescendants raises on unknown txid."""
        import asyncio

        async def test():
            with self.assertRaises(ValueError):
                await self.rpc_server.rpc_getmempooldescendants("ff" * 32)

        asyncio.run(test())


if __name__ == '__main__':
    unittest.main()
