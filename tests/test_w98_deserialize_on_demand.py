"""plan-W98 — on-demand `Block.deserialize` in the drain loop.

Before W98, `_drain_block_buffer_locked` unconditionally parsed every
received block into a Python `Block` object, paying ~1 MB allocation +
~1 ms CPU on every iteration.  The Rust validator (`sync.validate_block_
from_bytes`) and raw-bytes connect (`db.connect_block_from_bytes`) never
touch that structured view — the deserialize is pure overhead on the
steady-state mainnet IBD fast path.

After W98, `Block.deserialize` runs only on paths that actually need
the structured view:
  - Python validator fallback (`OUROBOROS_DISABLE_RUST_VALIDATE=1` or
    above the assumevalid checkpoint).
  - Cross-check diagnostic (`OUROBOROS_VALIDATE_CROSS_CHECK=1`).
  - Python `apply_block` connect (only when `connect_block_from_bytes`
    is unavailable, which is never in current production).

These tests pin the gate so a well-meaning refactor can't accidentally
re-introduce the unconditional deserialize.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ouroboros import block_sync as block_sync_mod
from ouroboros.block_sync import BlockSync
from ouroboros.database import Block
from ouroboros.p2p_messages import BlockHeader

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "b3_blocks"


def _load_fixture(height: int) -> tuple[bytes, bytes, BlockHeader]:
    """Return (raw_payload, block_hash_internal, header_obj) for a fixture."""
    raw = (FIXTURE_DIR / f"block_{height}.bin").read_bytes()
    hash_hex = (FIXTURE_DIR / f"block_{height}.hash").read_text().strip()
    # .hash files are stored in display (big-endian) order — reverse for
    # internal byte order used by the drain loop's hash lookups.
    block_hash = bytes.fromhex(hash_hex)[::-1]
    header, _ = BlockHeader.from_payload(raw[:80])
    return raw, block_hash, header


def _make_block_sync(rust_succeeds: bool = True) -> tuple[BlockSync, MagicMock]:
    """Construct a BlockSync wired to mock backends.

    The mock db supports the two raw-bytes paths (validate / connect) so
    the drain loop never needs to construct a Python Block.  Counter
    lets each test assert on validate/connect call counts.
    """
    db = MagicMock()
    db.get_best_block.return_value = (b"\x00" * 32, 699999)
    db.has_block_hash.return_value = False

    def _validate(raw, height_minus_one, strict, network):
        if not rust_succeeds:
            raise ValueError("mock rust validate rejected")
        return None  # Rust returns None on accept

    db.validate_block_from_bytes.side_effect = _validate
    db.connect_block_from_bytes.return_value = None

    validator = MagicMock()
    peer_manager = MagicMock()
    peer_manager.network = "mainnet"

    bs = BlockSync(db=db, validator=validator, peer_manager=peer_manager)
    return bs, db


@pytest.fixture
def rust_sync_patched(monkeypatch):
    """Force the drain's `rust_available` guard to be True and declare
    every block as script-skippable (simulates being below the
    assumevalid checkpoint, which is all of mainnet IBD)."""
    monkeypatch.setattr(block_sync_mod, "_has_sync_module", True)
    fake_sync = MagicMock()
    fake_sync.can_skip_scripts_for_block.return_value = True
    monkeypatch.setattr(block_sync_mod, "_sync_module", fake_sync)
    yield


@pytest.fixture
def deserialize_counter(monkeypatch):
    """Replace `Block.deserialize` with a counter that delegates to the
    real impl.  Returns a list so the test can inspect
    `counter[0]`."""
    counter = [0]
    real = Block.deserialize

    def counting(raw):
        counter[0] += 1
        return real(raw)

    monkeypatch.setattr(block_sync_mod.Block, "deserialize", staticmethod(counting))
    return counter


@pytest.mark.asyncio
async def test_rust_fast_path_does_not_deserialize(
    rust_sync_patched, deserialize_counter
):
    """Steady-state mainnet IBD: Rust validate + raw connect.  Python
    `Block.deserialize` must NOT be called.  This is the whole point
    of plan-W98 — ~1 ms/block saved at mainnet tip."""
    raw, block_hash, header = _load_fixture(770000)

    bs, _db = _make_block_sync(rust_succeeds=True)
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 1, "fast path should connect the block"
    assert deserialize_counter[0] == 0, (
        f"Rust fast path should skip Block.deserialize entirely; "
        f"got {deserialize_counter[0]} call(s)"
    )


@pytest.mark.asyncio
async def test_python_forced_path_does_deserialize(
    rust_sync_patched, deserialize_counter, monkeypatch
):
    """`OUROBOROS_DISABLE_RUST_VALIDATE=1` → Python validator runs →
    Python needs a Block object → `_ensure_block()` materialises it."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")

    raw, block_hash, header = _load_fixture(770000)

    bs, _db = _make_block_sync()
    # Python `validate_block` returns (True, "") on success.
    bs.validator.validate_block.return_value = (True, "")
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 1
    assert deserialize_counter[0] == 1, (
        f"Python-forced path must deserialize exactly once "
        f"(got {deserialize_counter[0]})"
    )
    bs.validator.validate_block.assert_called_once()


@pytest.mark.asyncio
async def test_cross_check_path_deserializes_once(
    rust_sync_patched, deserialize_counter, monkeypatch
):
    """`OUROBOROS_VALIDATE_CROSS_CHECK=1` runs both Rust and Python —
    Python needs the Block.  `_ensure_block()` caches after first
    call, so even though Rust ran first, only one deserialize fires."""
    monkeypatch.setenv("OUROBOROS_VALIDATE_CROSS_CHECK", "1")

    raw, block_hash, header = _load_fixture(770000)

    bs, _db = _make_block_sync()
    bs.validator.validate_block.return_value = (True, "")
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 1
    assert deserialize_counter[0] == 1, (
        "cross-check should deserialize exactly once, not zero "
        "(Python side needs it) and not twice (memoised)"
    )


@pytest.mark.asyncio
async def test_rust_reject_breaks_without_deserialize(
    rust_sync_patched, deserialize_counter
):
    """Rust rejects → drain breaks out of the loop without materialising
    a Block.  The reject-path doesn't need the Python view; only the
    cross-check/python paths do."""
    raw, block_hash, header = _load_fixture(770000)

    bs, _db = _make_block_sync(rust_succeeds=False)
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 0, "Rust rejected — no block should connect"
    assert deserialize_counter[0] == 0, (
        "reject path must not deserialize; the Rust error is authoritative"
    )


@pytest.mark.asyncio
async def test_fast_path_never_calls_apply_block(
    rust_sync_patched, deserialize_counter
):
    """Sanity: confirm `connect_block_from_bytes` is used, not
    `validator.apply_block` (which would need a Block)."""
    raw, block_hash, header = _load_fixture(770000)

    bs, db = _make_block_sync()
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 1
    db.connect_block_from_bytes.assert_called_once()
    bs.validator.apply_block.assert_not_called()
    assert deserialize_counter[0] == 0


@pytest.mark.asyncio
async def test_fast_path_with_mempool_materialises_block_for_removal(
    rust_sync_patched, deserialize_counter
):
    """Regression: 2026-04-23 mainnet crash.  Once `can_skip_scripts_for_block`
    returned True above the last hard checkpoint (via the assumevalid branch),
    the Rust fast path started running for all of IBD.  But W98 left `block`
    as None on the fast path, and `_drain_block_buffer_locked` unconditionally
    called `self.mempool.remove_block_transactions(block)` — a hot-loop
    `AttributeError: 'NoneType' object has no attribute 'transactions'`.

    With a mempool attached, the fast path must now materialise the Block
    before handing off to consumers (one deserialise, memoised).  Without a
    mempool/fee/zmq consumer, the old zero-deserialize behaviour still holds
    (pinned by test_rust_fast_path_does_not_deserialize)."""
    raw, block_hash, header = _load_fixture(770000)

    bs, _db = _make_block_sync(rust_succeeds=True)
    bs.mempool = MagicMock()
    bs._validated_headers = [(block_hash, header)]
    bs._ibd_block_buffer[block_hash] = (None, raw)

    connected = await bs._drain_block_buffer_locked()

    assert connected == 1
    assert deserialize_counter[0] == 1, (
        "fast path must materialise Block exactly once when a mempool "
        "consumer is attached (so remove_block_transactions can walk "
        f"block.transactions); got {deserialize_counter[0]} call(s)"
    )
    bs.mempool.remove_block_transactions.assert_called_once()
    (called_block,) = bs.mempool.remove_block_transactions.call_args.args
    assert called_block is not None, (
        "remove_block_transactions received a None block — the crash "
        "observed on mainnet 2026-04-23 post-assumevalid-fix"
    )
