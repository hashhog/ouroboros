"""getheaders serves the body-less (assumeUTXO) range from the block index.

Item fix-ouroboros-getheaders-serve-bodyless-headers.  ``_make_getheaders_handler``
(node.py) read every header through ``db.get_block_header``, which returns None
exactly when the block has no body in BLOCKS_CF, and the loop stopped at the
first None.  A snapshot-loaded mainnet node holds bodies only for 0..107 and
from the snapshot base up, so every locator in 108..944183 got an empty
``headers`` reply and a genesis locator got 107 headers (measured 2026-11-20;
Core answered 2000 for both).  A peer header-syncing from ouroboros stalls.

Core copies the header out of ``CBlockIndex`` (net_processing.cpp
ProcessGetHeaders: ``vHeaders.emplace_back(pindex->GetBlockHeader())``) and
never needs the block data.  ouroboros keeps the same header in the v2
hash-index entry (BLOCK_INDEX_BY_HASH_CF, written by the v2 migration and the
online index header fill) and in HEADERS_CF, the stores ``getblockheader``
already reads (#196).

The datadir here is the mainnet shape: the chain Bitcoin Core v31.1 mined for
``tests/fixtures/index_header_fill`` (heights 0..125), extended past 2000 with
regtest-PoW headers mined below, written by the real #52 metadata backfill (no
header, no body) and then given its headers by the real online index header
fill, answered the way a peer answers.  No height has a body.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from tests.test_getheaders_header_only import (  # noqa: E402
    _headers_payload,
    _request,
    _SpyDB,
    _StubPeer,
    _StubPeerManager,
)

FIXTURE = Path(__file__).parent / "fixtures" / "index_header_fill" / "core31_chain.json"
CORE = json.loads(FIXTURE.read_text())
TIP = 2150  # > 2000 past a mid-range locator, so a full 2000-header reply fits
MAX_HEADERS = 2000
ZERO = b"\x00" * 32


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _mine_on(prev_header: bytes, height: int) -> bytes:
    """One regtest header on top of ``prev_header`` (bits 0x207fffff)."""
    prev_hash = dsha(prev_header)
    prev_time = int.from_bytes(prev_header[68:72], "little")
    target = 0x7FFFFF << (8 * (0x20 - 3))
    merkle = dsha(b"bodyless-range" + height.to_bytes(4, "little"))
    for nonce in range(1 << 20):
        hdr = (
            (0x20000000).to_bytes(4, "little") + prev_hash + merkle
            + (prev_time + 600).to_bytes(4, "little")
            + (0x207FFFFF).to_bytes(4, "little") + nonce.to_bytes(4, "little")
        )
        if int.from_bytes(dsha(hdr), "little") <= target:
            return hdr
    raise AssertionError("no regtest nonce found")


def _build_headers() -> list[bytes]:
    headers = [bytes.fromhex(c["header_hex"]) for c in CORE["chain"]]
    while len(headers) <= TIP:
        headers.append(_mine_on(headers[-1], len(headers)))
    return headers


HEADERS = _build_headers()
HASHES = [dsha(h) for h in HEADERS]


def _backfilled(path: str):
    """#52 shape: height/hash/chainwork/time per height, no header, no body."""
    from ouroboros.database import BlockchainDatabase
    from ouroboros.header_backfill import backfill_metadata

    bdb = BlockchainDatabase(path)
    written = backfill_metadata(bdb, HEADERS, start_height=0, anchor_hash=HASHES[TIP],
                                network="regtest", base_chainwork=0)
    assert written == TIP + 1
    bdb._db.update_best_block(HASHES[TIP], TIP)
    return bdb


def _fill_like_a_peer(bdb) -> None:
    """Give every entry its header through the online index header fill."""
    from ouroboros import index_header_fill as ihf

    fill = ihf.IndexHeaderFill(bdb._db)
    for _ in range(10_000):
        if fill.is_complete():
            return
        fill.step()
        if fill.waiting_on_peer():
            loc = fill.locator()
            if not loc:
                reply = [HEADERS[HASHES.index(fill.hash_stop())]]
            else:
                start = HASHES.index(loc[0]) + 1
                reply = HEADERS[start:start + MAX_HEADERS]
            fill.accept(reply)
    raise AssertionError("index header fill did not complete")


def _handler_for(db):
    from ouroboros.node import BitcoinNode

    peer = _StubPeer()
    node = BitcoinNode.__new__(BitcoinNode)
    node.db = db
    node.block_filter_index = None
    node.peer_manager = _StubPeerManager([peer])
    node.mempool = None
    node._register_handlers()
    return peer.handlers["getheaders"], peer


@pytest.fixture(scope="module")
def filled(tmp_path_factory):
    """(spy db, real db, handler, peer) over a fully body-less, index-filled chain."""
    # Module scope runs before the function-scoped autouse swap, so install
    # the real extension here too (the stub has no metadata writers).
    with real_sync_installed(sync):
        real = _backfilled(str(tmp_path_factory.mktemp("bodyless") / "db"))
        _fill_like_a_peer(real)
    spy = _SpyDB(real)
    handler, peer = _handler_for(spy)
    return spy, real, handler, peer


def _expected(heights) -> bytes:
    return _headers_payload([HEADERS[h] for h in heights])


def test_bodyless_fixture_shape(filled):
    """Precondition: no body anywhere, a v2 header at every height."""
    _, real, _, _ = filled
    for h in (0, 1, 107, 108, 1000, TIP):
        assert real.get_block_hash_by_height(h) == HASHES[h]
        assert real.get_block_bytes(HASHES[h]) is None, f"height {h} holds a body"
        assert real.get_block_header(HASHES[h]) is None
        entry = real._db.get_block_index_entry(HASHES[h])
        assert entry is not None and bytes(entry[4]) == HEADERS[h], f"height {h}: no v2 header"


def test_bodyless_mid_locator_serves_2000_headers_after_it(filled):
    """getheaders(locator = h) answers 2000 headers h+1..h+2000, like Core."""
    _, _, handler, peer = filled
    for h in (108, 150):
        payload = _request(handler, peer, [HASHES[h]])
        assert payload == _expected(range(h + 1, h + 1 + MAX_HEADERS)), (
            f"locator at body-less height {h}: expected {MAX_HEADERS} headers from {h + 1}"
        )


def test_bodyless_genesis_locator_serves_2000_headers(filled):
    _, _, handler, peer = filled
    payload = _request(handler, peer, [HASHES[0]])
    assert payload == _expected(range(1, 1 + MAX_HEADERS))


def test_bodyless_unknown_locator_serves_from_height_1(filled):
    """No locator matches -> Core's genesis fork point -> 1..2000."""
    _, _, handler, peer = filled
    payload = _request(handler, peer, [b"\x11" * 32])
    assert payload == _expected(range(1, 1 + MAX_HEADERS))


def test_bodyless_hash_stop_ends_the_reply(filled):
    """hashStop inside the body-less range ends the reply there, inclusive."""
    _, _, handler, peer = filled
    payload = _request(handler, peer, [HASHES[200]], HASHES[640])
    assert payload == _expected(range(201, 641))


def test_bodyless_reply_reaches_the_tip(filled):
    """A locator within 2000 of the tip gets every header up to it."""
    _, _, handler, peer = filled
    payload = _request(handler, peer, [HASHES[TIP - 30]])
    assert payload == _expected(range(TIP - 29, TIP + 1))


def test_bodyless_getheaders_never_reads_full_blocks(filled):
    """Guard, not a fail-before test (it passes on master too): the handler
    itself makes no full-block read on the body-less range.  Reads inside
    ``get_index_header_bytes`` do not pass through the spy; that helper's
    body fallback is the header-only ``get_block_header``."""
    spy, _, handler, peer = filled
    spy.calls.clear()
    _request(handler, peer, [HASHES[108]])
    hits = [c for c in spy.calls if c in ("get_block", "get_block_by_height")]
    assert not hits, f"getheaders read full blocks: {sorted(set(hits))}"


def test_headers_cf_row_without_body_or_v2_header_is_served(tmp_path):
    """Second source: a HEADERS_CF row (no body, no v2 header) is served."""
    real = _backfilled(str(tmp_path / "db"))
    for h in range(0, 60):
        real._db.store_raw_header(HASHES[h], HEADERS[h], 0)
    assert real._db.get_block_index_entry(HASHES[10])[4] is None, "fixture: v2 header present"
    handler, peer = _handler_for(real)
    payload = _request(handler, peer, [HASHES[10]])
    assert payload == _expected(range(11, 60)), (
        "HEADERS_CF rows 11..59 must be served; the reply ends where no store holds a header"
    )


def test_no_header_anywhere_serves_empty_not_wrong(tmp_path):
    """Control: the bare #52 rows hold no header, so nothing can be served;
    the reply is empty rather than made up."""
    real = _backfilled(str(tmp_path / "db"))
    handler, peer = _handler_for(real)
    assert _request(handler, peer, [HASHES[10]]) == _expected([])


def test_header_that_does_not_hash_to_the_index_hash_is_not_served(tmp_path):
    """A HEADERS_CF row whose bytes do not hash to the active-chain hash at
    that height is never served: the reply stops before it."""
    real = _backfilled(str(tmp_path / "db"))
    for h in range(0, 40):
        hdr = HEADERS[h]
        if h == 25:
            hdr = HEADERS[h][:76] + b"\xff\xff\xff\xff"  # wrong nonce
        real._db.store_raw_header(HASHES[h], hdr, 0)
    handler, peer = _handler_for(real)
    assert _request(handler, peer, [HASHES[10]]) == _expected(range(11, 25))


def test_store_read_error_skips_to_the_next_store(tmp_path):
    """A store whose read raises is skipped (as getblockheader does), so one
    bad v2 row does not lose the HEADERS_CF header or the whole reply."""
    real = _backfilled(str(tmp_path / "db"))
    for h in range(0, 30):
        real._db.store_raw_header(HASHES[h], HEADERS[h], 0)

    class _RaisingIndex:
        def __init__(self, inner):
            self._inner = inner

        def get_block_index_entry(self, block_hash):
            raise RuntimeError("Database error: corrupt row")

        def __getattr__(self, name):
            return getattr(self._inner, name)

    real._db = _RaisingIndex(real._db)
    handler, peer = _handler_for(real)
    assert _request(handler, peer, [HASHES[10]]) == _expected(range(11, 30))
