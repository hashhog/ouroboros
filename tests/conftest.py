"""Shared test fixtures for Ouroboros integration tests."""

import sys
import types
from pathlib import Path

# ---------------------------------------------------------------------------
# Mock the Rust `sync` extension module so pure-Python components can be
# imported without building the native library.  This MUST happen before
# any ouroboros submodule is imported.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"

    class _StubDB:
        def __init__(self, *a, **kw): pass
        def get_block(self, *a, **kw): return None
        def get_block_by_height(self, *a, **kw): return None
        def get_best_block(self, *a, **kw): return (b"\x00" * 32, 0)
        def get_utxo(self, *a, **kw): return None

    _mock.PyBlockchainDB = _StubDB
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.verify_ecdsa = lambda *a, **kw: False
    sys.modules["sync"] = _mock

# Now it's safe to add src/ and import ouroboros submodules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import asyncio
import pytest


@pytest.fixture
def temp_data_dir(tmp_path):
    """Provide a temporary data directory that is cleaned up after the test."""
    d = tmp_path / "ouroboros_test"
    d.mkdir()
    yield str(d)


@pytest.fixture
def event_loop():
    """Create a fresh event loop for each async test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
