"""Headers-only block-index entries: counted in ``headers``, kept on restart.

Core keeps every accepted header in its block index
(validation.cpp ChainstateManager::AcceptBlockHeader -> AddToBlockIndex,
which also moves ``m_best_header``), writes the index to disk and reloads it
at startup (LoadBlockIndex).  So after ``submitheader`` of two headers on top
of the tip, Core's getblockchaininfo reports ``headers`` = tip + 2
(rpc/blockchain.cpp: ``m_best_header->nHeight``) and getchaintips lists the
``headers-only`` tip, before AND after a restart.

ouroboros read ``sync_manager.header_height``, an attribute nothing defines,
so ``headers`` always equalled ``blocks``; and its header stores
(``BlockSync._validated_headers`` / ``_fork_headers``) were memory-only, so a
restart dropped the headers-only tip.  tools/core-regtest rows this pins:
``warden_invalidated_submit/{headers-only,restart,p2p-header}/info:headers``
and ``warden_invalidated_submit/{restart,p2p-header}/tips`` (15b45ee2...).

The restarted server is built the way ``BitcoinNode.start`` builds it: a
fresh BlockSync over the same database, ``load_rpc_invalidated`` then
``load_header_index`` (guarded, so this file runs on a tree without it and
fails on the assertion).
"""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from tests._f0_chain import BASE_TIME, Chain, build_block, coinbase_tx  # noqa: E402

TIP = 6


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _server(bdb, data_dir: str):
    from ouroboros.block_sync import BlockSync
    from ouroboros.rpc import RPCServer

    pm = MagicMock()
    pm.network = "regtest"
    validator = MagicMock()
    validator.validate_block.return_value = (True, "")
    bs = BlockSync(db=bdb, validator=validator, peer_manager=pm)
    bs.load_rpc_invalidated(os.path.join(data_dir, "invalidated_blocks.json"))
    loader = getattr(bs, "load_header_index", None)
    if loader is not None:
        loader(os.path.join(data_dir, "headers_only.json"))
    node = SimpleNamespace(network="regtest", validator=None, mempool=None,
                           db=bdb, block_sync=bs, data_dir=data_dir,
                           config={"network": "regtest"})
    node._calculate_chainwork_at_height = lambda h: (h + 1) * 2
    node._calculate_block_work = lambda bits: 2
    server = RPCServer.__new__(RPCServer)
    server.node = node
    server.block_submission_paused = False
    server._side_branch_max_entries = 1024
    server._deployment_cache = {}
    server._deployment_cache_height = None
    server._deployment_cache_network = None
    opener = getattr(server, "_open_side_branch_buffer", None)
    server._side_branch_blocks = opener() if opener is not None else {}
    return server


def _setup(tmp_path):
    from ouroboros.database import BlockchainDatabase

    bdb = BlockchainDatabase(str(tmp_path / "db"))
    Chain(bdb._db, tip=TIP)
    hashes = {h: bytes(bdb.get_block_hash_by_height(h)) for h in range(TIP + 1)}
    return bdb, _server(bdb, str(tmp_path)), hashes


def _disp(h: bytes) -> str:
    return h[::-1].hex()


def _block(prev: bytes, height: int, tag: bytes):
    cb = coinbase_tx(height, tag=tag)
    return build_block(prev, BASE_TIME + height * 600 + 7, [cb])


def _submitheader(server, raw: bytes):
    """None on acceptance, else the RPC error message (so a refusal fails
    the caller's assertion instead of raising)."""
    from ouroboros.rpc import RpcError

    try:
        return asyncio.run(server.rpc_submitheader(raw[:80].hex()))
    except RpcError as e:
        return getattr(e, "message", str(e))


def _headers(server) -> int:
    return asyncio.run(server.rpc_getblockchaininfo())["headers"]


def _tips(server) -> dict[str, dict]:
    return {t["hash"]: t for t in asyncio.run(server.rpc_getchaintips())}


def _two_headers_on_tip(server, hashes):
    raw1, h1 = _block(hashes[TIP], TIP + 1, b"\x91\xc5")
    raw2, h2 = _block(h1, TIP + 2, b"\x92\xc5")
    assert _submitheader(server, raw1) is None
    assert _submitheader(server, raw2) is None
    return (raw1, h1), (raw2, h2)


def test_headers_counts_submitted_headers_only_entries(tmp_path):
    """warden_invalidated_submit/headers-only/info:headers: Core 210 = tip+2."""
    _bdb, server, hashes = _setup(tmp_path)
    assert _headers(server) == TIP
    _two_headers_on_tip(server, hashes)
    assert _headers(server) == TIP + 2


def test_headers_counts_a_fork_header_above_the_tip(tmp_path):
    """m_best_header is the most-work entry wherever it sits: a fork header
    one above the tip (parent = tip's parent's sibling chain) counts too."""
    _bdb, server, hashes = _setup(tmp_path)
    raw1, f1 = _block(hashes[TIP - 1], TIP, b"\xa1\xc5")
    raw2, _f2 = _block(f1, TIP + 1, b"\xa2\xc5")
    assert _submitheader(server, raw1) is None
    assert _submitheader(server, raw2) is None
    assert _headers(server) == TIP + 1


def test_headers_only_tip_survives_restart(tmp_path):
    """warden_invalidated_submit/restart/tips:15b45ee2... and
    restart/info:headers: the headers-only tip and the header count are the
    same after a restart."""
    bdb, server, hashes = _setup(tmp_path)
    _first, (_raw2, h2) = _two_headers_on_tip(server, hashes)
    fresh = _server(bdb, str(tmp_path))
    tips = _tips(fresh)
    assert tips.get(_disp(h2)) == {
        "height": TIP + 2, "hash": _disp(h2), "branchlen": 2,
        "status": "headers-only"}
    assert tips[_disp(hashes[TIP])]["status"] == "active"
    assert _headers(fresh) == TIP + 2


def test_restored_header_still_accepts_a_child_header(tmp_path):
    """The restored entry is a real index entry: a child header of it is
    admitted after the restart (Core: parent found by LookupBlockIndex)."""
    bdb, server, hashes = _setup(tmp_path)
    _first, (_raw2, h2) = _two_headers_on_tip(server, hashes)
    fresh = _server(bdb, str(tmp_path))
    raw3, h3 = _block(h2, TIP + 3, b"\x93\xc5")
    assert _submitheader(fresh, raw3) is None
    assert _headers(fresh) == TIP + 3
    assert _tips(fresh)[_disp(h3)]["status"] == "headers-only"


def test_header_under_an_invalidated_block_is_not_restored(tmp_path):
    """Invalid stays invalid: a stored header whose parent was invalidated
    before the restart is not reloaded and is not counted (Core marks it
    failed, and RecalculateBestHeader skips failed entries)."""
    bdb, server, hashes = _setup(tmp_path)
    raw1, f1 = _block(hashes[TIP - 1], TIP, b"\xb1\xc5")
    raw2, f2 = _block(f1, TIP + 1, b"\xb2\xc5")
    _submitheader(server, raw1)
    _submitheader(server, raw2)
    bs = server.node.block_sync
    bs._rpc_invalidated.add(f1)
    bs.save_rpc_invalidated(os.path.join(str(tmp_path), "invalidated_blocks.json"))
    fresh = _server(bdb, str(tmp_path))
    assert f2 not in fresh.node.block_sync._fork_headers
    assert _headers(fresh) == TIP


def test_tampered_header_file_entries_are_dropped(tmp_path):
    """Negative control for the reload: an entry that fails proof of work,
    or whose parent is unknown, is not restored, so a damaged datadir cannot
    plant a header the node never accepted."""
    bdb, server, hashes = _setup(tmp_path)
    (raw1, h1), _second = _two_headers_on_tip(server, hashes)
    path = os.path.join(str(tmp_path), "headers_only.json")
    rows = {"queue": [], "fork": []}
    bad_pow = bytearray(raw1[:80])
    bad_pow[72:76] = (0x03000001).to_bytes(4, "little")  # target 1: no hash meets it
    orphan = bytearray(raw1[:80])
    orphan[4:36] = b"\x07" * 32
    rows["queue"] = [bytes(bad_pow).hex()] + rows["queue"]
    rows["fork"] = [bytes(orphan).hex()]
    with open(path, "w") as f:
        json.dump(rows, f)
    fresh = _server(bdb, str(tmp_path))
    bs = fresh.node.block_sync
    assert bs._validated_headers == []
    assert bs._fork_headers == {}
    assert _headers(fresh) == TIP
    assert _disp(h1) not in _tips(fresh)


def test_block_of_first_header_arrives_rest_stay_headers_only(tmp_path):
    """Headers h1, h2 on the tip, then submitblock(h1) (which does not pop
    the header queue).  Core: h1 now has data and is the tip; h2 is still a
    headers-only entry and ``m_best_header``.  So ``headers`` stays tip+1,
    getchaintips lists h2 as headers-only, the sync loop's drain and queue
    prune keep h2, and all of that holds after a restart; h1 is not restored as a
    headers-only entry because its block is connected."""
    bdb, server, hashes = _setup(tmp_path)
    (raw1, h1), (_raw2, h2) = _two_headers_on_tip(server, hashes)
    assert asyncio.run(server.rpc_submitblock(raw1.hex())) is None
    assert bdb.get_best_block() == (h1, TIP + 1)
    want = {"height": TIP + 2, "hash": _disp(h2), "branchlen": 1,
            "status": "headers-only"}
    assert _headers(server) == TIP + 2
    assert _tips(server).get(_disp(h2)) == want
    bs = server.node.block_sync
    # The sync loop's order on a running node: drain, then prune.  The
    # header sync has completed (as on a live node), so the drain runs its
    # queue-anchor check instead of returning early.
    bs._prebase_headers_complete = True
    asyncio.run(bs._drain_block_buffer())
    assert [h for h, _ in bs._validated_headers] == [h2]
    bs._prune_validated_headers()
    assert [h for h, _ in bs._validated_headers] == [h2]
    saver = getattr(bs, "save_header_index", None)
    if saver is not None:
        saver()
    fresh = _server(bdb, str(tmp_path))
    assert [h for h, _ in fresh.node.block_sync._validated_headers] == [h2]
    assert _headers(fresh) == TIP + 2
    assert _tips(fresh).get(_disp(h2)) == want


def test_header_on_an_invalidated_stored_block_is_not_restored(tmp_path):
    """Invalid stays invalid, parent still known: a tip-extending header h1
    (queue) and a sibling g1 of it (fork store, same parent: the tip), then
    invalidateblock(tip) and a crash before the header file is rewritten.
    After the restart the invalidated block is still in the block store, so
    g1's parent is known, but it is failed: Core's AcceptBlockHeader refuses
    a header on a failed parent (bad-prevblk), so neither header may come
    back or be counted."""
    bdb, server, hashes = _setup(tmp_path)
    raw1, h1 = _block(hashes[TIP], TIP + 1, b"\xc1\xc5")
    rawg, g1 = _block(hashes[TIP], TIP + 1, b"\xc2\xc5")
    assert _submitheader(server, raw1) is None
    assert _submitheader(server, rawg) is None
    assert g1 in server.node.block_sync._fork_headers
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    assert bdb.get_best_block() == (hashes[TIP - 1], TIP - 1)
    # No save after the invalidation: the file still holds both headers, as
    # the eager submitheader write left it.
    fresh = _server(bdb, str(tmp_path))
    bs = fresh.node.block_sync
    assert g1 not in bs._fork_headers and h1 not in bs._fork_headers
    assert all(h not in (h1, g1) for h, _ in bs._validated_headers)
    assert _headers(fresh) == TIP - 1


def test_p2p_header_after_a_connected_prefix_extends_the_queue(tmp_path):
    """Headers h1, h2 on the tip, submitblock(h1), then a peer announces h3
    (child of h2).  Core: h3 extends the best header chain, so it is
    accepted and ``headers`` becomes tip+2 (tip h1).  The headers-receive
    path must not treat the queue [h1, h2] as stale and clear it, which
    would leave h3 unconnecting."""
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage, NetworkMessage

    bdb, server, hashes = _setup(tmp_path)
    (raw1, h1), (_raw2, h2) = _two_headers_on_tip(server, hashes)
    assert asyncio.run(server.rpc_submitblock(raw1.hex())) is None
    raw3, h3 = _block(h2, TIP + 3, b"\x94\xc5")
    hdr3, _ = BlockHeader.from_payload(raw3[:80])
    msg = NetworkMessage(command="headers",
                         payload=HeadersMessage(headers=[hdr3]).serialize_payload(),
                         magic=0)
    peer = MagicMock()
    peer.host, peer.port = "127.0.0.1", 18444
    bs = server.node.block_sync
    asyncio.run(bs.handle_headers(msg, peer))
    assert [h for h, _ in bs._validated_headers] == [h2, h3]
    assert _headers(server) == TIP + 3
