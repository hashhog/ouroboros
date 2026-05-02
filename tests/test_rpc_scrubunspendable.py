"""Tests for the ``scrubunspendable`` RPC handler.

The handler walks ``CHAINSTATE_CF`` and deletes orphan unspendable
coins (OP_RETURN scripts and scripts > MAX_SCRIPT_SIZE) left behind by
pre-fix code paths.  The fix landed at write time in
``apply_block`` / ``connect_block_from_bytes`` /
``connect_block_at_height`` (see ``ferrous-utils/sync/src/validate/block.rs::is_unspendable_script``);
``scrubunspendable`` exists to bring an existing on-disk datadir into
line with the new write filter.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
from fastapi import HTTPException

from ouroboros.rpc import RPCServer


# ---------------------------------------------------------------------------
# Stub DB.  Mirrors the surface ``rpc_scrubunspendable`` uses.
# ---------------------------------------------------------------------------


@dataclass
class _ScrubResult:
    removed: int
    bytes_freed: int


class _StubDB:
    """In-memory mimic of the Rust BlockchainDB scrub surface."""

    def __init__(self) -> None:
        self.scrub_calls: int = 0
        self.scrub_returns: list[tuple[int, int]] = []

    def scrub_unspendable_coins(self) -> tuple[int, int]:
        self.scrub_calls += 1
        if self.scrub_returns:
            return self.scrub_returns.pop(0)
        return (0, 0)


class _DBWithoutMethod:
    """Stand-in for a Python-only DB; lacks scrub_unspendable_coins."""


def _make_rpc(db) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = db
    rpc.node = node
    rpc._current_wallet_name = None
    return rpc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scrubunspendable_returns_counts_and_calls_rust_once() -> None:
    db = _StubDB()
    db.scrub_returns = [(7, 12_345)]
    rpc = _make_rpc(db)

    result = asyncio.run(rpc.rpc_scrubunspendable())

    assert result == {"removed": 7, "bytes_freed": 12_345}
    assert db.scrub_calls == 1


def test_scrubunspendable_is_idempotent_clean_db() -> None:
    """A clean chainstate must yield (0, 0) on the first call and on
    every subsequent call.  rpc_scrubunspendable is operator-invoked,
    so the contract is: re-running on a chainstate the previous call
    already cleaned must be a safe no-op."""
    db = _StubDB()
    db.scrub_returns = [(0, 0), (0, 0)]
    rpc = _make_rpc(db)

    first = asyncio.run(rpc.rpc_scrubunspendable())
    second = asyncio.run(rpc.rpc_scrubunspendable())

    assert first == {"removed": 0, "bytes_freed": 0}
    assert second == {"removed": 0, "bytes_freed": 0}
    assert db.scrub_calls == 2


def test_scrubunspendable_idempotency_across_two_runs() -> None:
    """First scrub finds orphans; second scrub finds nothing because
    the write-time filter prevents new orphans."""
    db = _StubDB()
    db.scrub_returns = [(42, 8_400), (0, 0)]
    rpc = _make_rpc(db)

    first = asyncio.run(rpc.rpc_scrubunspendable())
    second = asyncio.run(rpc.rpc_scrubunspendable())

    assert first == {"removed": 42, "bytes_freed": 8_400}
    assert second == {"removed": 0, "bytes_freed": 0}
    assert db.scrub_calls == 2


def test_scrubunspendable_db_missing_method_raises_501() -> None:
    rpc = _make_rpc(_DBWithoutMethod())
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(rpc.rpc_scrubunspendable())
    assert excinfo.value.status_code == 501
    assert "scrub_unspendable_coins" in excinfo.value.detail


def test_scrubunspendable_no_db_raises_500() -> None:
    rpc = RPCServer.__new__(RPCServer)

    class _Node:
        pass

    node = _Node()
    node.db = None
    rpc.node = node
    rpc._current_wallet_name = None

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(rpc.rpc_scrubunspendable())
    assert excinfo.value.status_code == 500


def test_scrubunspendable_rust_failure_raises_500() -> None:
    class _BoomDB:
        def scrub_unspendable_coins(self):
            raise RuntimeError("rocksdb explosion")

    rpc = _make_rpc(_BoomDB())
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(rpc.rpc_scrubunspendable())
    assert excinfo.value.status_code == 500
    assert "rocksdb explosion" in excinfo.value.detail
