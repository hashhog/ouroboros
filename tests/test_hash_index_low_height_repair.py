"""Heights below the #52 backfill gap get their hash-index rows back on open.

Item fix-ouroboros-hash-index-rows-below-backfill-gap.  The mainnet datadir
holds a height row and a body for heights 0..107 (written by the IBD stub that
predates 5f78633) but no ``BLOCK_INDEX_BY_HASH_CF`` row: the #52 header
backfill only fills the gap above them.  RPC answers by height and matches
Core, but everything keyed by hash is blind there:
``get_block_height_by_hash(h)`` is None, so ``getheaders`` with a locator at
1..107 falls back to Core's "no fork found" and restarts from height 1 instead
of serving h+1.

The fixture is the chain Bitcoin Core v31.1 mined for
``tests/fixtures/index_header_fill`` (heights 0..125, every height with a
body), connected block by block, then the hash-index rows of heights 0..107
deleted (``delete_hash_index_row_for_test``, test support) and the database
closed.  Opening it again is what the repair runs on.
"""

from __future__ import annotations

import gc
import json
from pathlib import Path

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests.test_getheaders_header_only import (  # noqa: E402
    _headers_payload,
    _request,
    _StubPeer,
    _StubPeerManager,
)

FIXTURE = Path(__file__).parent / "fixtures" / "index_header_fill" / "core31_chain.json"
CHAIN = json.loads(FIXTURE.read_text())["chain"]
TIP = len(CHAIN) - 1
GAP = 108  # heights 0..107, as on the mainnet datadir
HASHES = [bytes.fromhex(c["hash"])[::-1] for c in CHAIN]
HEADERS = [bytes.fromhex(c["header_hex"]) for c in CHAIN]


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _close(bdb) -> None:
    del bdb
    gc.collect()


def _gapped_datadir(path: str):
    """Connect the chain, record the hash-index entries, delete 0..107's.
    Returns the entries as they were, keyed by height; the db is closed."""
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(path)
    for c in CHAIN:
        bdb._db.connect_block_from_bytes(bytes.fromhex(c["block"]), c["height"], "regtest")
    before = {h: tuple(bdb._db.get_block_index_entry(HASHES[h])) for h in range(TIP + 1)}
    for h in range(GAP):
        bdb._db.delete_hash_index_row_for_test(HASHES[h])
    # Instrument check: the gap exists, the rows above it are untouched.
    assert all(bdb.get_block_height_by_hash(HASHES[h]) is None for h in range(GAP))
    assert bdb.get_block_height_by_hash(HASHES[GAP]) == GAP
    assert bdb.get_block_hash_by_height(50) == HASHES[50]
    _close(bdb)
    return before


@pytest.fixture
def reopened(tmp_path):
    from ouroboros.database import BlockchainDatabase

    path = str(tmp_path / "db")
    before = _gapped_datadir(path)
    return BlockchainDatabase(path), before, path


def test_every_low_height_is_found_by_hash_after_open(reopened):
    bdb, _before, _ = reopened
    for h in range(GAP):
        assert bdb.get_block_height_by_hash(HASHES[h]) == h, f"height {h}"


def test_repaired_rows_equal_the_rows_a_connect_wrote(reopened):
    """Chainwork, time, status, header and nTx come back byte-for-byte what
    ``connect_block_from_bytes`` wrote: chainwork/time from the height row,
    header and nTx from the body, status data-present."""
    bdb, before, _ = reopened
    for h in range(TIP + 1):
        now = tuple(bdb._db.get_block_index_entry(HASHES[h]))
        want = before[h]
        assert now[:4] == want[:4], f"height {h}: metadata {now[:4]} != {want[:4]}"
        assert bytes(now[4]) == HEADERS[h], f"height {h}: header"
        assert now[5] == want[5], f"height {h}: nTx"


def test_getheaders_locator_at_50_starts_at_51(reopened):
    from ouroboros.node import BitcoinNode

    bdb, _, _ = reopened
    peer = _StubPeer()
    node = BitcoinNode.__new__(BitcoinNode)
    node.db = bdb
    node.block_filter_index = None
    node.peer_manager = _StubPeerManager([peer])
    node.mempool = None
    node._register_handlers()
    payload = _request(peer.handlers["getheaders"], peer, [HASHES[50]])
    assert payload == _headers_payload(HEADERS[51:]), (
        "a locator at height 50 must be answered from 51, not restarted at 1"
    )


def test_second_open_changes_nothing(reopened):
    """Idempotent: a repaired datadir opens to the same rows."""
    from ouroboros.database import BlockchainDatabase

    bdb, _before, path = reopened
    rows = {h: tuple(bdb._db.get_block_index_entry(HASHES[h])) for h in range(TIP + 1)}
    _close(bdb)
    again = BlockchainDatabase(path)
    for h in range(TIP + 1):
        assert tuple(again._db.get_block_index_entry(HASHES[h])) == rows[h], f"height {h}"
