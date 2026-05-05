"""
Test UTXO restoration during chain reorganization.

This module verifies the *structural* contract of the reorg path:

* ``BlockSync._handle_reorg`` exists and is async-callable.
* The dead helpers ``_restore_utxos_from_block`` /
  ``_find_transaction_in_blocks`` (which dropped ``height`` +
  ``is_coinbase`` from restored UTXOs and were never wired to a real
  ``db.restore_utxo`` method) are gone.
* The Python ``BlockchainDatabase`` exposes ``disconnect_block`` (the
  Rust-routed correct disconnect path) and ``get_block_bytes`` (used by
  the new reorg connect side to feed witness-preserving block bytes back
  into the Rust connect path).

End-to-end correctness — that the disconnect path actually preserves
``height`` and ``is_coinbase`` post-reorg — is exercised by
``tests/test_reorg_handle_rust_path.py`` against the real Rust
extension.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.database import BlockchainDatabase  # noqa: E402
from ouroboros.validation import BlockValidator  # noqa: E402


class TestReorgUTXORestoration(unittest.TestCase):
    """Test reorg UTXO restoration plumbing"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.db = BlockchainDatabase(self.temp_dir)
        self.validator = BlockValidator(self.db)

        # Create a mock peer manager (minimal implementation)
        class MockPeerManager:
            def get_all_ready_peers(self):
                return []
            def get_best_peer(self):
                return None
            def broadcast(self, msg):
                pass

        self.peer_manager = MockPeerManager()
        self.block_sync = BlockSync(self.db, self.validator, self.peer_manager)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_handle_reorg_exists(self):
        """The reorg entry point must still be there for the sync loop."""
        self.assertTrue(hasattr(self.block_sync, '_handle_reorg'))
        self.assertTrue(callable(self.block_sync._handle_reorg))

    def test_dead_helpers_removed(self):
        """The previous (broken) Python disconnect path is gone.

        ``_restore_utxos_from_block`` searched only the prior 100 blocks
        and dropped ``height`` + ``is_coinbase`` from the restored UTXO,
        breaking the matured-coinbase rule on any reorg that crossed a
        coinbase spend.  ``_find_transaction_in_blocks`` was its only
        caller.  Both should be gone — the Rust path
        (``db.disconnect_block``) is the live one now.
        """
        self.assertFalse(hasattr(self.block_sync, '_restore_utxos_from_block'))
        self.assertFalse(hasattr(self.block_sync, '_find_transaction_in_blocks'))

    def test_database_disconnect_block_method(self):
        """db.disconnect_block (Rust-routed) must be present and callable."""
        self.assertTrue(hasattr(self.db, 'disconnect_block'))
        self.assertTrue(callable(getattr(self.db, 'disconnect_block', None)))

    def test_database_get_block_bytes_method(self):
        """db.get_block_bytes (witness-preserving raw bytes) must exist."""
        self.assertTrue(hasattr(self.db, 'get_block_bytes'))
        self.assertTrue(callable(getattr(self.db, 'get_block_bytes', None)))


if __name__ == '__main__':
    unittest.main()
