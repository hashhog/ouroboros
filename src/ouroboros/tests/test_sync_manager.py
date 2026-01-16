"""
Tests for SyncManager module.
"""

import unittest
import tempfile
import shutil
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add src to path if not already there
try:
    test_dir = Path(__file__).parent
except NameError:
    # __file__ not available, use current working directory
    test_dir = Path.cwd() / "src" / "ouroboros" / "tests"

src_dir = test_dir.parent.parent / "src"
if not src_dir.exists():
    # Try alternative path structure
    src_dir = Path.cwd() / "src"
    
if str(src_dir) not in sys.path and src_dir.exists():
    sys.path.insert(0, str(src_dir))

try:
    from ouroboros.sync_manager import SyncManager, SyncProgress
    SYNC_MANAGER_AVAILABLE = True
except ImportError:
    SYNC_MANAGER_AVAILABLE = False
    # Import SyncProgress directly if sync_manager import fails
    try:
        import importlib.util
        sync_manager_path = src_dir / "ouroboros" / "sync_manager.py"
        spec = importlib.util.spec_from_file_location(
            "sync_manager", 
            str(sync_manager_path)
        )
        sync_manager_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync_manager_module)
        SyncProgress = sync_manager_module.SyncProgress
    except Exception:
        SyncProgress = None


class TestSyncProgress(unittest.TestCase):
    """Test SyncProgress dataclass (doesn't require Rust module)"""
    
    def test_sync_progress(self):
        """Test SyncProgress dataclass"""
        if SyncProgress is None:
            self.skipTest("SyncProgress not available")
            
        progress = SyncProgress(
            current_height=1000,
            total_height=800000,
            progress_percent=0.125,
            blocks_per_second=5.0,
            eta_seconds=159800
        )
        
        self.assertEqual(progress.current_height, 1000)
        self.assertEqual(progress.total_height, 800000)
        self.assertEqual(progress.progress_percent, 0.125)
        self.assertEqual(progress.blocks_per_second, 5.0)
        self.assertEqual(progress.eta_seconds, 159800)
        
        # Test string representation
        str_repr = str(progress)
        self.assertIn("0.12", str_repr)  # Should contain percentage
        self.assertIn("1,000", str_repr)  # Should contain current height
        self.assertIn("800,000", str_repr)  # Should contain total height
    
    def test_sync_progress_eta_formatting(self):
        """Test ETA formatting in SyncProgress"""
        if SyncProgress is None:
            self.skipTest("SyncProgress not available")
            
        # Test seconds
        progress = SyncProgress(0, 100, 0.0, 1.0, 45)
        self.assertIn("45s", str(progress))
        
        # Test minutes
        progress = SyncProgress(0, 100, 0.0, 1.0, 125)
        self.assertIn("2m", str(progress))
        
        # Test hours
        progress = SyncProgress(0, 100, 0.0, 1.0, 3665)
        self.assertIn("1h", str(progress))


@unittest.skipIf(not SYNC_MANAGER_AVAILABLE, "SyncManager not available (Rust sync module required)")
class TestSyncManager(unittest.TestCase):
    """Test SyncManager functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_sync_manager_init(self):
        """Test SyncManager initialization"""
        try:
            manager = SyncManager(self.temp_dir, "regtest")
            self.assertEqual(manager.data_dir, self.temp_dir)
            self.assertEqual(manager.network, "regtest")
            self.assertFalse(manager.is_running)
        except ImportError:
            self.skipTest("Rust sync module not available")
    
    def test_sync_progress(self):
        """Test SyncProgress dataclass"""
        progress = SyncProgress(
            current_height=1000,
            total_height=800000,
            progress_percent=0.125,
            blocks_per_second=5.0,
            eta_seconds=159800
        )
        
        self.assertEqual(progress.current_height, 1000)
        self.assertEqual(progress.total_height, 800000)
        self.assertEqual(progress.progress_percent, 0.125)
        self.assertEqual(progress.blocks_per_second, 5.0)
        self.assertEqual(progress.eta_seconds, 159800)
        
        # Test string representation
        str_repr = str(progress)
        self.assertIn("0.12", str_repr)  # Should contain percentage
        self.assertIn("1,000", str_repr)  # Should contain current height
        self.assertIn("800,000", str_repr)  # Should contain total height
    
    def test_sync_progress_eta_formatting(self):
        """Test ETA formatting in SyncProgress"""
        # Test seconds
        progress = SyncProgress(0, 100, 0.0, 1.0, 45)
        self.assertIn("45s", str(progress))
        
        # Test minutes
        progress = SyncProgress(0, 100, 0.0, 1.0, 125)
        self.assertIn("2m", str(progress))
        
        # Test hours
        progress = SyncProgress(0, 100, 0.0, 1.0, 3665)
        self.assertIn("1h", str(progress))
    
    def test_get_progress(self):
        """Test getting sync progress"""
        try:
            manager = SyncManager(self.temp_dir, "regtest")
            progress = manager.get_progress()
            # Progress might be None if not syncing, or a SyncProgress object
            self.assertTrue(progress is None or isinstance(progress, SyncProgress))
        except ImportError:
            self.skipTest("Rust sync module not available")
    
    def test_is_synced(self):
        """Test checking sync status"""
        try:
            manager = SyncManager(self.temp_dir, "regtest")
            # Should return a boolean
            result = manager.is_synced()
            self.assertIsInstance(result, bool)
        except ImportError:
            self.skipTest("Rust sync module not available")
    
    def test_cancel_sync(self):
        """Test cancelling sync"""
        try:
            manager = SyncManager(self.temp_dir, "regtest")
            # Should not raise an exception
            manager.cancel_sync()
        except ImportError:
            self.skipTest("Rust sync module not available")


if __name__ == "__main__":
    unittest.main()

