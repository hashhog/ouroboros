"""Differential bug-hunt (2026-06-14): the BIP-68 connect-block version gates
compared tx.version signed, while Core stores version as uint32_t and computes
fEnforceBIP68 = version >= 2 UNSIGNED (tx_verify.cpp:51). ouroboros decodes the
version as a signed i32, so a high-bit version (0x80000002, decoded as -2147483646)
read as < 2 would SKIP BIP-68 -> false-accept a tx whose relative timelock is unmet
(a chain split). bip68_version_active masks to the unsigned 32-bit value.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Mock the Rust extension module before any ouroboros imports.
sys.modules.setdefault("sync", MagicMock())
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ouroboros.validation import bip68_version_active  # noqa: E402


def test_bip68_version_active_compares_unsigned():
    assert bip68_version_active(-2147483646) is True  # 0x80000002 (high bit set)
    assert bip68_version_active(-1) is True            # 0xFFFFFFFF
    assert bip68_version_active(2) is True
    assert bip68_version_active(3) is True
    assert bip68_version_active(1) is False
    assert bip68_version_active(0) is False
