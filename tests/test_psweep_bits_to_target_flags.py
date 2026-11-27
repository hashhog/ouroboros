"""Headers presync, through the `sync` extension, counts Core's work for nBits.

Item psweep-ouroboros-rust-bits-to-target-flags.  The Python P2P header sync
runs Core's PRESYNC/REDOWNLOAD anti-DoS through `sync.PyHeadersSyncState`
(ferrous-utils/sync/src/validate/headers_presync.rs).  Core adds
GetBlockProof (src/chain.cpp GetBitsProof) per header, which is 0 for a
negative, overflowing or zero target.  The Rust code decoded nBits without
the sign and overflow flags, so a header with nBits 0x2080ffff (a negative
target) counted 0x100 work on regtest, where Core counts 0.

The Rust unit tests live in ferrous-utils/sync/tests/; this file checks the
built extension that the node actually imports.
"""

from __future__ import annotations

import struct

import pytest

from tests._real_sync import real_sync_or_skip

# tests/conftest.py stubs `sync`; a bare importorskip would run against it.
sync = real_sync_or_skip()

REGTEST_BITS = 0x207FFFFF


def _presync_work_after_one_header(bits: int) -> int:
    state = sync.PyHeadersSyncState("regtest", bytes(32), 0, 0, REGTEST_BITS)
    # version, prev (genesis-start hash = 32 zero bytes), merkle, time, bits, nonce
    header = struct.pack("<i32s32sIII", 0x20000000, bytes(32), bytes(32), 1000, bits, 0)
    result = state.process_headers([header], False)
    assert result.success, result.error
    assert state.presync_height() == 1
    return int(state.presync_work(), 16)


@pytest.mark.parametrize(
    "bits",
    [0x2080FFFF, 0x22010000, 0x23000001, 0x04000000, 0x00000000],
    ids=["negative-0x2080ffff", "overflow-0x22010000", "overflow-0x23000001",
         "zero-mantissa-0x04000000", "zero-0x00000000"],
)
def test_presync_counts_no_work_for_invalid_nbits(bits: int) -> None:
    assert _presync_work_after_one_header(bits) == 0


def test_presync_counts_core_work_for_regtest_powlimit() -> None:
    # Core GetBlockProof for 0x207fffff is 2.
    assert _presync_work_after_one_header(REGTEST_BITS) == 2
