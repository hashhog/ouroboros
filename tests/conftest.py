"""Shared test fixtures for Ouroboros integration tests."""

import sys
from pathlib import Path

# Ensure src/ is on the import path so submodules can be imported directly
# without going through ouroboros/__init__.py (which pulls in the Rust extension).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import asyncio
import shutil
import tempfile

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
