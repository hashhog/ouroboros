"""getblockheader answers every block-index entry, like Core, once the online
index header fill has run (item fix-ouroboros-getblockheader-headerless-backfill).

Core keeps the header fields in every ``CBlockIndex`` (chain.h; a block enters
the index only through ``AcceptBlockHeader`` -> ``AddToBlockIndex``), so
``getblockheader`` (rpc/blockchain.cpp) answers any hash ``LookupBlockIndex``
finds.  An assumeUTXO-booted ouroboros wrote its pre-snapshot rows with the #52
header backfill (``header_backfill.backfill_metadata``): height, chainwork and
time only, no header, no body.  On mainnet 711,249 such entries answered
``getblockhash`` with Core's hash but ``getblockheader`` with -5 "Block not
found".

The datadir here is that shape, built with the real #52 writer from a chain
Bitcoin Core v31.1 mined (``fixtures/index_header_fill/core31_chain.json``,
recorded by ``make_fixture.py`` next to it).  The fill gets the headers the way
a peer serves them: a ``getheaders`` from the locator it asks for, answered
with Core's own headers in chain order, at most 2000 per reply.

Reference values are Core's own ``getblockheader`` answers for the same chain.
``nTx`` is the one field that depends on whether the node holds the block's
transactions: Core sets ``pindex->nTx`` only in ``ReceivedBlockTransactions``
(validation.cpp:3768) and asserts ``VALID_TRANSACTIONS == (nTx > 0)``
(``CheckBlockIndex``, :5257), so a Core node without the data (a snapshot node
before background validation) answers 0.  These rows have no data, so 0 is the
Core answer; the fully-connected control below shows the harness reproduces
Core's nTx where the data is held.

The tests reach the new API through getattr, so this file imports and fails
on its assertions against a build without it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

from ouroboros.rpc import RpcError  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "index_header_fill" / "core31_chain.json"
CORE = json.loads(FIXTURE.read_text())
CHAIN = CORE["chain"]
TIP = CORE["tip"]
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def internal(display_hex: str) -> bytes:
    return bytes.fromhex(display_hex)[::-1]


HEADERS = [bytes.fromhex(c["header_hex"]) for c in CHAIN]
HASHES = [internal(c["hash"]) for c in CHAIN]


def backfilled_datadir(path: str):
    """The mainnet shape: every height written by the #52 header backfill
    (metadata only: no header, no body), tip = the chain's tip."""
    from ouroboros.database import BlockchainDatabase
    from ouroboros.header_backfill import backfill_metadata

    bdb = BlockchainDatabase(path)
    written = backfill_metadata(bdb, HEADERS, start_height=0, anchor_hash=HASHES[TIP],
                                network="regtest", base_chainwork=0)
    assert written == TIP + 1
    bdb._db.update_best_block(HASHES[TIP], TIP)
    return bdb


def connected_datadir(path: str):
    """Control: the same chain connected block by block (bodies held)."""
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(path)
    for c in CHAIN:
        bdb._db.connect_block_from_bytes(bytes.fromhex(c["block"]), c["height"], "regtest")
    assert bdb.get_best_block()[1] == TIP
    return bdb


def server_for(bdb, data_dir: str):
    from ouroboros.node import BitcoinNode
    from ouroboros.rpc import RPCServer

    node = SimpleNamespace(network="regtest", validator=None, mempool=None, db=bdb,
                           data_dir=data_dir, config={"network": "regtest"},
                           block_sync=MagicMock(_validated_headers=[], _fork_headers={}))
    node._chainwork_offset_cache = None
    for name in ("get_median_time", "_calculate_chainwork_at_height", "get_chainwork_at_height",
                 "get_difficulty", "_bits_to_difficulty", "_calculate_block_work"):
        fn = getattr(BitcoinNode, name, None)
        if fn is not None:
            setattr(node, name, fn.__get__(node))
    if isinstance(getattr(BitcoinNode, "_chainwork_snapshot_offset", None), property):
        node._chainwork_snapshot_offset = 0
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_max_entries = 1024
    server._side_branch_blocks = {}
    server._deployment_cache = {}
    server._deployment_cache_height = None
    server._deployment_cache_network = None
    server._headers_only_index_entry = lambda _h: None
    return server


def getblockheader(server, h: int, verbose: bool = True):
    return asyncio.run(server.rpc_getblockheader(CHAIN[h]["hash"], verbose))


def as_core_json(obj) -> dict:
    """Round-trip through the RPC server's own JSON encoder (the wire), so
    number forms compare as Core's."""
    from ouroboros.rpc import _BTCEncoder

    return json.loads(json.dumps(obj, cls=_BTCEncoder))


def fill_module():
    """``ouroboros.index_header_fill``, asserted present (so a tree without
    the fill fails here on the assertion, by name, not on an import)."""
    import importlib.util

    spec = importlib.util.find_spec("ouroboros.index_header_fill")
    assert spec is not None, "ouroboros.index_header_fill is missing: no online index header fill"
    return importlib.import_module("ouroboros.index_header_fill")


def new_fill(bdb, **kw):
    ihf = fill_module()
    assert ihf.supported(bdb._db), (
        "PyBlockchainDB has no index header fill API (fill_index_headers_by_height)"
    )
    return ihf.IndexHeaderFill(bdb._db, **kw)


def serve_like_a_peer(fill, max_reply: int = 2000) -> int:
    """Answer the fill's getheaders the way a peer does: the headers after the
    locator hash, in chain order, at most ``max_reply``.  Returns replies sent."""
    replies = 0
    while not fill.is_complete():
        fill.step()
        if fill.waiting_on_peer():
            loc = fill.locator()
            assert loc is not None, "a run needs a locator"
            if not loc:  # Core: empty locator -> the hashStop header alone
                reply = [HEADERS[HASHES.index(fill.hash_stop())]]
            else:
                start = HASHES.index(loc[0]) + 1
                reply = HEADERS[start:start + max_reply]
            assert fill.wants(reply)
            fill.accept(reply)
            replies += 1
        assert replies < 10_000
    return replies


def test_master_shape_answers_block_not_found(tmp_path):
    """Precondition (the bug): getblockhash answers, getblockheader -5."""
    bdb = backfilled_datadir(str(tmp_path / "db"))
    server = server_for(bdb, str(tmp_path))
    assert bytes(bdb.get_block_hash_by_height(500 % (TIP + 1))) == HASHES[500 % (TIP + 1)]
    e = bdb._db.get_block_index_entry(HASHES[50])
    assert e is not None and e[4] is None, "the #52 row has no header"
    with pytest.raises(RpcError) as err:
        getblockheader(server, 50)
    assert (err.value.code, err.value.message) == (-5, "Block not found")


def test_fill_makes_every_height_answer_exactly_like_core(tmp_path):
    """After the fill, getblockheader at every height 0..tip equals Core's
    answer for the same chain, field by field (nTx: 0, see the module
    docstring), and verbose=false is Core's 80-byte header hex."""
    bdb = backfilled_datadir(str(tmp_path / "db"))
    server = server_for(bdb, str(tmp_path))
    fill = new_fill(bdb, max_peer_run=50)  # several replies: exercise the run logic
    replies = serve_like_a_peer(fill, max_reply=50)
    assert replies >= 3
    assert fill.counts["attached"] == TIP + 1  # genesis included (hashStop)
    for c in CHAIN:
        h = c["height"]
        got = as_core_json(getblockheader(server, h))
        want = dict(c["header"])
        assert got.get("nTx") == 0, f"height {h}: nTx without the block's data is 0"
        want["nTx"] = 0
        assert got == want, f"height {h}: {got} != Core {want}"
        assert getblockheader(server, h, False) == c["header_hex"]


def test_connected_control_matches_core_including_ntx(tmp_path):
    """Instrument check: a datadir that holds the bodies answers Core's
    getblockheader byte for byte, nTx included, through the same harness."""
    bdb = connected_datadir(str(tmp_path / "db"))
    server = server_for(bdb, str(tmp_path))
    for c in CHAIN:
        assert as_core_json(getblockheader(server, c["height"])) == c["header"], c["height"]


def test_fill_never_changes_metadata_and_resumes_from_its_cursor(tmp_path):
    """The 44 metadata bytes of every entry are unchanged, and a fresh driver
    (a restart) resumes at the persisted height instead of rescanning."""
    bdb = backfilled_datadir(str(tmp_path / "db"))
    before = {h: tuple(bdb._db.get_block_index_entry(HASHES[h])[:4]) for h in range(TIP + 1)}
    fill = new_fill(bdb, max_peer_run=40)
    serve_one = lambda: fill.accept(
        [HEADERS[0]] if not fill.locator() else
        HEADERS[HASHES.index(fill.locator()[0]) + 1:][:40])
    fill.step()
    assert fill.waiting_on_peer()
    serve_one()  # genesis (hashStop form)
    fill.step()
    serve_one()  # heights 1..40
    fill.step()  # next run requested
    resumed = new_fill(bdb, max_peer_run=40)
    assert resumed.next_height == fill.peer_run[0][0] == 40
    serve_like_a_peer(resumed, max_reply=40)
    for h in range(TIP + 1):
        e = bdb._db.get_block_index_entry(HASHES[h])
        assert tuple(e[:4]) == before[h], f"height {h}: metadata changed"
        assert e[4] is not None and dsha(bytes(e[4])) == HASHES[h]


def test_peer_headers_that_do_not_verify_are_counted_not_written(tmp_path):
    """A reply with a tampered header (hash no longer an index key) and a
    header for a block we do not know write nothing; the run stays open and
    a correct reply then completes it."""
    bdb = backfilled_datadir(str(tmp_path / "db"))
    fill = new_fill(bdb, max_peer_run=2000)
    fill.step()
    assert fill.waiting_on_peer() and fill.locator() == []
    fill.accept([HEADERS[0]])  # genesis, served by hashStop
    fill.step()
    loc = fill.locator()
    start = HASHES.index(loc[0]) + 1
    reply = [bytearray(h) for h in HEADERS[start:]]
    reply[3][76] ^= 1  # nonce of the 4th header
    fill.accept([bytes(h) for h in reply])
    tampered = HASHES[start + 3]
    assert bdb._db.get_block_index_entry(tampered)[4] is None
    assert any(k == tampered for _h, k in fill.peer_run)
    raw = bdb._db.attach_index_headers([bytes(reply[3])], None, True)
    assert raw["unknown"] == 1 and raw["attached"] == 0
    serve_like_a_peer(fill)
    assert bdb._db.get_block_index_entry(tampered)[4] is not None


def test_dry_run_counts_without_writing(tmp_path):
    """The dry run counts the peer backlog exactly and writes nothing: the
    datadir's files are unchanged (negative control: the real fill changes
    them)."""
    dry_run = fill_module().dry_run

    path = tmp_path / "db"
    bdb = backfilled_datadir(str(path))
    del bdb
    import gc

    gc.collect()
    sec = sync.PyBlockchainDB.open_secondary(str(path), str(tmp_path / "secondary"))
    snap = {p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in path.iterdir() if p.is_file()}
    r = dry_run(sec)
    assert r["need_peer"] == TIP + 1
    assert (r["hash_mismatch"], r["corrupt_body"], r["unlinked"], r["fillable_local"]) == (0, 0, 0, 0)
    assert r["index_legacy"] == TIP + 1
    del sec
    gc.collect()
    after = {p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
             for p in path.iterdir() if p.is_file()}
    assert after == snap
    # negative control: the real fill does write.
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(str(path))
    fill = new_fill(bdb)
    serve_like_a_peer(fill)
    del fill, bdb
    gc.collect()
    changed = {p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
               for p in path.iterdir() if p.is_file()}
    assert changed != snap


def test_dry_run_tool_prints_the_counts(tmp_path):
    path = tmp_path / "db"
    bdb = backfilled_datadir(str(path))
    del bdb
    import gc

    gc.collect()
    out = subprocess.run(
        [sys.executable, str(REPO / "tools" / "index_header_fill_dryrun.py"),
         "--datadir", str(path), "--secondary-dir", str(tmp_path / "sec"), "--json"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["tip_height"] == TIP and r["index_legacy"] == TIP + 1
    bad = subprocess.run(
        [sys.executable, str(REPO / "tools" / "index_header_fill_dryrun.py"),
         "--datadir", str(path), "--secondary-dir", str(path / "inside")],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    assert bad.returncode == 2 and "REFUSED" in bad.stderr


KILL_CHILD = textwrap.dedent("""
    import os, sys, signal
    sys.path[:0] = sys.argv[3].split(os.pathsep)
    import sync
    from ouroboros import index_header_fill as ihf
    import json
    chain = json.load(open(sys.argv[2]))["chain"]
    headers = [bytes.fromhex(c["header_hex"]) for c in chain]
    hashes = [bytes.fromhex(c["hash"])[::-1] for c in chain]
    db = sync.PyBlockchainDB(sys.argv[1])
    fill = ihf.IndexHeaderFill(db, max_peer_run=10, max_scan=10)
    served = 0
    while not fill.is_complete():
        fill.step()
        if fill.waiting_on_peer():
            loc = fill.locator()
            start = hashes.index(loc[0]) + 1 if loc else 0
            fill.accept(headers[start:start + (10 if loc else 1)])
            served += 1
            if served == 4:
                print("KILLING", flush=True)
                os.kill(os.getpid(), signal.SIGKILL)
""")


def test_sigkill_mid_fill_resumes_and_completes(tmp_path):
    """SIGKILL the process mid-fill: the next open resumes at the persisted
    height and finishes; every entry ends v2 with unchanged metadata."""
    path = tmp_path / "db"
    bdb = backfilled_datadir(str(path))
    before = {h: tuple(bdb._db.get_block_index_entry(HASHES[h])[:4]) for h in range(TIP + 1)}
    del bdb
    import gc

    gc.collect()
    child = subprocess.run(
        [sys.executable, "-c", KILL_CHILD, str(path), str(FIXTURE), os.pathsep.join(sys.path)],
        capture_output=True, text=True,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr
    assert "KILLING" in child.stdout
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(str(path))
    v2 = sum(1 for h in range(TIP + 1) if bdb._db.get_block_index_entry(HASHES[h])[4] is not None)
    assert 0 < v2 < TIP + 1, f"the kill should land mid-fill (v2={v2})"
    fill = new_fill(bdb, max_peer_run=10)
    assert fill.next_height > 1, "a restart resumes from the persisted height"
    serve_like_a_peer(fill, max_reply=10)
    for h in range(TIP + 1):
        e = bdb._db.get_block_index_entry(HASHES[h])
        assert tuple(e[:4]) == before[h]
        assert e[4] is not None and dsha(bytes(e[4])) == HASHES[h]


def test_block_sync_tick_asks_peers_and_fills_through_handle_headers(tmp_path):
    """The online path: BlockSync's sync_loop tick runs a step under the chain
    lock and sends getheaders; the peer's reply arrives through the ordinary
    ``handle_headers`` and is attached.  Ends with every entry filled and
    getblockheader answering."""
    from ouroboros.block_sync import BlockSync
    from ouroboros.p2p_messages import BlockHeader, GetHeadersMessage, HeadersMessage, NetworkMessage

    bdb = backfilled_datadir(str(tmp_path / "db"))
    sent: list[bytes] = []

    class Peer:
        host, port = "127.0.0.1", 18444

        def is_connected(self):
            return True

        async def send_message(self, msg):
            sent.append(msg)

    peer = Peer()
    pm = MagicMock()
    pm.network = "regtest"
    pm.get_all_ready_peers.return_value = [peer]
    bs = BlockSync(db=bdb, validator=MagicMock(), peer_manager=pm)
    bs._backfill_done = True
    bs._prebase_headers_complete = True
    tick = getattr(bs, "_index_header_fill_tick", None)
    assert tick is not None, "BlockSync has no online index header fill"

    async def drive():
        for _ in range(200):
            sent.clear()
            await tick()
            if bs._index_fill_off:
                return
            for m in sent:
                assert m.command == "getheaders"
                gh = GetHeadersMessage.from_payload(m.payload)
                loc = list(gh.locator_hashes)
                if not loc:
                    reply = [HEADERS[HASHES.index(bytes(gh.hash_stop))]]
                else:
                    start = HASHES.index(bytes(loc[0])) + 1
                    reply = HEADERS[start:start + 2000]
                hdrs = [BlockHeader.from_payload(r)[0] for r in reply]
                msg = NetworkMessage(command="headers",
                                     payload=HeadersMessage(headers=hdrs).serialize_payload(), magic=0)
                await bs.handle_headers(msg, peer)
        raise AssertionError("fill did not complete")

    asyncio.run(drive())
    assert bs._index_fill.counts["attached"] == TIP + 1
    for h in range(TIP + 1):
        e = bdb._db.get_block_index_entry(HASHES[h])
        assert e[4] is not None and bytes(e[4]) == HEADERS[h], h
    server = server_for(bdb, str(tmp_path))
    assert getblockheader(server, 77, False) == CHAIN[77]["header_hex"]
