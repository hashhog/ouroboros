"""getblockheader answers for a headers-only block-index entry, like Core
(fleet item refill-20261114-ouroboros-consensus).

Core keeps every accepted header in its block index
(validation.cpp ChainstateManager::AcceptBlockHeader -> AddToBlockIndex), and
rpc/blockchain.cpp ``getblockheader`` answers for any entry
``BlockManager::LookupBlockIndex`` finds.  A header that arrived over P2P (or
by ``submitheader``) without its block is such an entry: Core returns it with
``confirmations: -1`` (not on the active chain), its own height, its own
``nChainWork`` (parent's work + GetBlockProof), its own median time past,
``nTx: 0`` (blockheaderToJSON reads ``nTx``, zero until the block arrives)
and no ``nextblockhash``.

ouroboros keeps those entries in BlockSync's header stores
(``_validated_headers``, the tip-anchored queue, and ``_fork_headers``).
getblockchaininfo ``headers`` and getchaintips already read them, but
getblockheader looked only in the block store and HEADERS_CF, so it answered
-5 "Block not found".  tools/core-regtest row this pins:
``warden_invalidated_submit/p2p-header/valid:$``.

The negative controls keep what Core still refuses: a header on a failed
parent never enters the index (``failed-child`` row, -5 on both), and an
unknown hash is -5.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from tests._real_sync import real_sync_installed, real_sync_or_skip

sync = real_sync_or_skip()

import pytest  # noqa: E402

from ouroboros.rpc import RpcError  # noqa: E402
from tests.test_headers_only_index_restart import (  # noqa: E402
    TIP,
    _block,
    _disp,
    _setup,
    _submitheader,
)

REGTEST_PROOF = 2  # GetBlockProof(0x207fffff) = 2**256 // (target + 1)


@pytest.fixture(autouse=True)
def _use_real_sync():
    with real_sync_installed(sync):
        yield


def _server(tmp_path):
    bdb, server, hashes = _setup(tmp_path)
    node = server.node
    # BitcoinNode's contract: the ACTIVE chain's work at a height (fixture
    # model (h + 1) * 2, the same values the Rust index holds), zero above
    # the tip.
    def _active_work(h: int) -> str:
        tip = bdb.get_best_block()[1]
        return f"{node._calculate_chainwork_at_height(h) if h <= tip else 0:064x}"

    node.get_chainwork_at_height = _active_work
    node.get_median_time = lambda h: 0
    node.get_difficulty = lambda bits: 1.0
    return bdb, server, hashes


def _header(server, h: bytes, verbose: bool = True):
    return asyncio.run(server.rpc_getblockheader(_disp(h), verbose))


def _mtp(bdb, extra: list[bytes], parent: bytes) -> int:
    """Median of the last 11 timestamps along the header's own chain:
    *extra* (headers-only, newest first) then stored ancestors from *parent*."""
    times = [int.from_bytes(raw[68:72], "little") for raw in extra]
    cur = parent
    while len(times) < 11:
        raw = bdb.get_block_bytes(cur)
        times.append(int.from_bytes(raw[68:72], "little"))
        cur = bytes(raw[4:36])
        if cur == bytes(32):
            break
    times.sort()
    return times[len(times) // 2]


def _push_p2p(server, raw: bytes) -> None:
    from ouroboros.p2p_messages import BlockHeader, HeadersMessage, NetworkMessage

    hdr, _ = BlockHeader.from_payload(raw[:80])
    msg = NetworkMessage(command="headers",
                         payload=HeadersMessage(headers=[hdr]).serialize_payload(),
                         magic=0)
    peer = MagicMock()
    peer.host, peer.port = "127.0.0.1", 18444
    asyncio.run(server.node.block_sync.handle_headers(msg, peer))


def test_p2p_header_on_the_tip_is_served_headers_only(tmp_path):
    """warden_invalidated_submit/p2p-header/valid: a header pushed over P2P
    that extends the active tip.  Core answers it with confirmations -1,
    height tip+1, nTx 0, its own chainwork and MTP, no nextblockhash."""
    bdb, server, hashes = _server(tmp_path)
    raw, h = _block(hashes[TIP], TIP + 1, b"\xa2\xc5")
    _push_p2p(server, raw)
    assert any(q == h for q, _ in server.node.block_sync._validated_headers)
    hdr = _header(server, h)
    assert hdr["hash"] == _disp(h)
    assert hdr["confirmations"] == -1
    assert hdr["height"] == TIP + 1
    assert hdr["nTx"] == 0
    assert hdr["previousblockhash"] == _disp(hashes[TIP])
    assert "nextblockhash" not in hdr
    assert hdr["time"] == int.from_bytes(raw[68:72], "little")
    assert hdr["bits"] == raw[72:76][::-1].hex()
    assert hdr["merkleroot"] == raw[36:68][::-1].hex()
    assert hdr["chainwork"] == f"{(TIP + 1) * 2 + REGTEST_PROOF:064x}"
    assert hdr["mediantime"] == _mtp(bdb, [raw], hashes[TIP])
    # verbose=false: the 80-byte header itself.
    assert _header(server, h, False) == raw[:80].hex()


def test_second_headers_only_header_chains_its_parents_work(tmp_path):
    """Two headers on the tip (submitheader, the same store): the second's
    parent is itself headers-only, so height, work and MTP come from walking
    the header chain down to the stored tip."""
    bdb, server, hashes = _server(tmp_path)
    raw1, h1 = _block(hashes[TIP], TIP + 1, b"\x91\xc5")
    raw2, h2 = _block(h1, TIP + 2, b"\x92\xc5")
    assert _submitheader(server, raw1) is None
    assert _submitheader(server, raw2) is None
    hdr = _header(server, h2)
    assert (hdr["height"], hdr["confirmations"], hdr["nTx"]) == (TIP + 2, -1, 0)
    assert hdr["previousblockhash"] == _disp(h1)
    assert hdr["chainwork"] == f"{(TIP + 1) * 2 + 2 * REGTEST_PROOF:064x}"
    assert hdr["mediantime"] == _mtp(bdb, [raw2, raw1], hashes[TIP])
    assert "nextblockhash" not in _header(server, h1)


def test_fork_header_below_the_tip_is_served_off_chain(tmp_path):
    """A competing header at the tip's height (parent tip-1) sits in the
    fork store.  Its height slot belongs to the active tip, so it must be
    confirmations -1 with its OWN work, not the active block's."""
    bdb, server, hashes = _server(tmp_path)
    raw, f = _block(hashes[TIP - 1], TIP, b"\xa1\xc5")
    assert _submitheader(server, raw) is None
    assert f in server.node.block_sync._fork_headers
    hdr = _header(server, f)
    assert (hdr["height"], hdr["confirmations"], hdr["nTx"]) == (TIP, -1, 0)
    assert hdr["previousblockhash"] == _disp(hashes[TIP - 1])
    assert hdr["chainwork"] == f"{TIP * 2 + REGTEST_PROOF:064x}"
    assert hdr["mediantime"] == _mtp(bdb, [raw], hashes[TIP - 1])
    assert "nextblockhash" not in hdr


def test_header_on_a_failed_parent_is_still_not_found(tmp_path):
    """Negative control, warden_invalidated_submit/p2p-header/failed-child:
    Core's AcceptBlockHeader refuses a header whose parent is failed
    (bad-prevblk), so it is not in the index and getblockheader is -5."""
    _bdb, server, hashes = _server(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    raw, h = _block(hashes[TIP], TIP + 1, b"\xa3\xc5")
    _push_p2p(server, raw)
    with pytest.raises(RpcError) as e:
        _header(server, h)
    assert (e.value.code, e.value.message) == (-5, "Block not found")


def test_unknown_hash_is_still_not_found(tmp_path):
    _bdb, server, _hashes = _server(tmp_path)
    with pytest.raises(RpcError) as e:
        _header(server, b"\x42" * 32)
    assert (e.value.code, e.value.message) == (-5, "Block not found")
