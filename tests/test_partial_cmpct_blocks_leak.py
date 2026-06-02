"""Regression tests for the 2026-06-02 ouroboros RSS-leak fix.

Background — ``PeerManager._partial_cmpct_blocks`` is the in-flight BIP-152
partial-compact-block store: ``on_cmpctblock`` inserts a full block's worth of
deserialized ``Transaction`` objects whenever a compact block has missing txs
(awaiting the getblocktxn→blocktxn round-trip), and ``on_blocktxn`` pops the
matching entry once the round-trip completes.

The original port made it a GLOBAL hash-keyed dict with no per-peer ownership,
no in-flight cap and no TTL.  Bitcoin Core's analogous ``PartiallyDownloadedBlock``
is PER-PEER state torn down by ``FinalizeNode`` on disconnect and bounded by
``MAX_BLOCKS_IN_TRANSIT_PER_PEER``.  The missing bounds let the dict accrete a
1–2 MB block of Transaction objects per orphaned round-trip forever — the
93.8 GB OOM driver (root-cause:
``CORE-PARITY-AUDIT/_ouroboros-rss-leak-rootcause-2026-06-02.md``).

The fix restores all three Core bounds (delivery-layer only; no consensus path):
  1. per-peer attribution + drop-on-disconnect (``_cleanup_peer_state``),
  2. a per-peer in-flight cap (``MAX_CMPCT_IN_FLIGHT_PER_PEER`` = 16) on insert,
  3. a TTL sweep (``_sweep_partial_cmpct_blocks``, driven from the maintenance
     loop) reclaiming entries older than ``PARTIAL_CMPCT_TTL``.

These tests pin: (a) the dict empties after a mid-round-trip peer disconnect,
(b) the dict empties after TTL expiry, (c) it stays bounded under repeated
orphaned-cmpctblock insertion from one peer, and (d) the happy-path
blocktxn-pop + the getblocktxn / getdata fallback all still work with the new
``(addr, cb, partial_txs, ts)`` tuple shape.

Pure unit tests: a real ``PeerManager`` with ``_database``/``_mempool`` left
unset (height gate skipped, all txs treated missing) and MagicMock peers that
record the messages they are asked to send.  No node / no sync.
"""

from __future__ import annotations

import hashlib
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from ouroboros.compact_blocks import (
    BlockTransactions,
    CompactBlock,
    PrefilledTransaction,
    compute_siphash_key,
    short_txid,
)
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.p2p import (
    MAX_CMPCT_IN_FLIGHT_PER_PEER,
    PARTIAL_CMPCT_TTL,
    PeerManager,
)
from ouroboros.p2p_messages import (
    BlockTxnMessage,
    CmpctBlockMessage,
)


# ---------------------------------------------------------------------------
# Helpers (mirror test_compact_blocks.py)
# ---------------------------------------------------------------------------


def _make_header(nonce_tag: int, nBits: int = 0x1D00FFFF) -> bytes:
    """An 80-byte header with a non-null nBits (so validate() passes) and a
    distinct nNonce per tag so each compact block hashes to a unique block."""
    header = bytearray(80)
    struct.pack_into("<I", header, 72, nBits)        # nBits (must be non-zero)
    struct.pack_into("<I", header, 76, nonce_tag)    # nNonce — makes block hash unique
    return bytes(header)


def _make_tx(value: int, *, is_coinbase: bool = False) -> Transaction:
    if is_coinbase:
        # script_sig encodes a (bounded) height-like value, NOT the output
        # amount — keep it within uint32 so struct.pack('<I', ...) is valid.
        inputs = [TxIn(prev_txid=bytes(32), prev_vout=0xFFFFFFFF,
                       script_sig=b"\x04" + struct.pack("<I", value & 0xFFFFFFFF),
                       sequence=0xFFFFFFFF, witness=None)]
    else:
        inputs = [TxIn(prev_txid=hashlib.sha256(struct.pack("<Q", value)).digest(),
                       prev_vout=0, script_sig=b"", sequence=0xFFFFFFFF,
                       witness=[b"\x30" * 72, b"\x02" * 33])]
    outputs = [TxOut(value=value, script_pubkey=b"\x76\xa9" + bytes(20) + b"\x88\xac")]
    tx = Transaction(txid=bytes(32), version=1, locktime=0,
                     inputs=inputs, outputs=outputs, has_witness=not is_coinbase)
    raw = tx.serialize()
    tx.txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return tx


def _make_partial_cmpctblock(nonce_tag: int) -> tuple[CompactBlock, Transaction]:
    """A structurally-valid compact block with a coinbase prefilled at index 0
    and one short-id slot.  With the PeerManager's mempool unset, the short-id
    slot is unresolvable, so ``on_cmpctblock`` stores partial state + sends a
    getblocktxn.  Returns (cb, missing_tx) — missing_tx is the tx the matching
    blocktxn must supply to complete the happy path."""
    header = _make_header(nonce_tag)
    nonce = nonce_tag
    key = compute_siphash_key(header, nonce)
    coinbase = _make_tx(5_000_000_000 + nonce_tag, is_coinbase=True)
    missing_tx = _make_tx(1000 + nonce_tag)
    cb = CompactBlock(
        header=header,
        nonce=nonce,
        short_ids=[short_txid(key, missing_tx.get_wtxid())],
        prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
    )
    return cb, missing_tx


def _make_peer(host: str, port: int = 8333) -> MagicMock:
    """A MagicMock peer with a real per-instance ``message_handlers`` dict so
    ``register_handler`` actually stores the closures, an async
    ``send_message`` that records its calls, and connected status."""
    peer = MagicMock()
    peer.host = host
    peer.port = port
    peer.message_handlers = {}
    peer.register_handler = lambda cmd, fn: peer.message_handlers.__setitem__(cmd, fn)
    peer.send_message = AsyncMock()
    peer.is_connected.return_value = True
    return peer


def _make_manager() -> PeerManager:
    """A bare PeerManager wired for offline unit testing (no listen socket, no
    DNS seed).  ``_database``/``_mempool`` deliberately left None so the
    cmpctblock height gate is skipped and every short-id slot is 'missing'."""
    return PeerManager(network="regtest", listen=False, dns_seed=False)


def _register(pm: PeerManager, peer: MagicMock, addr: str) -> None:
    """Wire the real compact-block handler closures onto ``peer`` for ``addr``."""
    pm._register_compact_handlers(peer, addr)


def _cmpct_msg(pm: PeerManager, cb: CompactBlock):
    return CmpctBlockMessage(payload_bytes=cb.serialize()).to_network_message(pm.network)


def _blocktxn_msg(pm: PeerManager, block_hash: bytes, txs):
    bt = BlockTransactions(block_hash=block_hash, transactions=txs)
    return BlockTxnMessage(payload_bytes=bt.serialize()).to_network_message(pm.network)


# ---------------------------------------------------------------------------
# Sanity: an orphaned cmpctblock actually populates the store
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orphaned_cmpctblock_is_stored_with_new_tuple_shape():
    """A cmpctblock with a missing tx stores a 4-tuple keyed by block hash and
    sends a getblocktxn — the precondition for every leak scenario below."""
    pm = _make_manager()
    addr = "10.0.0.1:8333"
    peer = _make_peer("10.0.0.1")
    _register(pm, peer, addr)

    cb, _ = _make_partial_cmpctblock(nonce_tag=1)
    await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))

    assert cb.block_hash in pm._partial_cmpct_blocks
    entry = pm._partial_cmpct_blocks[cb.block_hash]
    # New tuple shape: (announcing addr, CompactBlock, partial_txs, monotonic_ts).
    # The stored CompactBlock is deserialized from the wire payload, so it is an
    # equal-but-distinct object — compare by block hash, not identity.
    assert len(entry) == 4
    assert entry[0] == addr
    assert entry[1].block_hash == cb.block_hash
    assert isinstance(entry[2], list)
    assert isinstance(entry[3], float)
    # getblocktxn was sent to request the missing slot.
    assert peer.send_message.await_count == 1


# ---------------------------------------------------------------------------
# (a) Mid-round-trip disconnect empties the store
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_cleans_partial_cmpct_blocks():
    """A peer that announces a cmpctblock and then disconnects (before sending
    blocktxn) must have its in-flight partial blocks dropped — Core's
    FinalizeNode teardown.  This is the dominant leak path."""
    pm = _make_manager()
    addr = "10.0.0.2:8333"
    peer = _make_peer("10.0.0.2")
    _register(pm, peer, addr)

    # Two orphaned cmpctblocks from this peer.
    for tag in (10, 11):
        cb, _ = _make_partial_cmpctblock(nonce_tag=tag)
        await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))
    assert len(pm._partial_cmpct_blocks) == 2

    # Peer disconnects → cleanup must drop ALL of its entries.
    pm._cleanup_peer_state(addr)
    assert pm._partial_cmpct_blocks == {}


@pytest.mark.asyncio
async def test_disconnect_only_drops_the_disconnecting_peers_entries():
    """Cleanup is per-peer: a disconnect must NOT drop another live peer's
    in-flight entry (it can still answer its own getblocktxn)."""
    pm = _make_manager()
    addr_a, addr_b = "10.0.0.3:8333", "10.0.0.4:8333"
    peer_a, peer_b = _make_peer("10.0.0.3"), _make_peer("10.0.0.4")
    _register(pm, peer_a, addr_a)
    _register(pm, peer_b, addr_b)

    cb_a, _ = _make_partial_cmpctblock(nonce_tag=20)
    cb_b, _ = _make_partial_cmpctblock(nonce_tag=21)
    await peer_a.message_handlers["cmpctblock"](_cmpct_msg(pm, cb_a))
    await peer_b.message_handlers["cmpctblock"](_cmpct_msg(pm, cb_b))
    assert len(pm._partial_cmpct_blocks) == 2

    pm._cleanup_peer_state(addr_a)
    assert cb_a.block_hash not in pm._partial_cmpct_blocks
    assert cb_b.block_hash in pm._partial_cmpct_blocks
    assert pm._partial_cmpct_blocks[cb_b.block_hash][0] == addr_b


# ---------------------------------------------------------------------------
# (b) TTL expiry empties the store
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_sweep_drops_expired_entries():
    """A peer that announces and silently never sends blocktxn (without
    disconnecting) is reclaimed by the TTL sweep once its entry is older than
    PARTIAL_CMPCT_TTL.  The sweep re-requests the block via getdata for
    liveness."""
    pm = _make_manager()
    addr = "10.0.0.5:8333"
    peer = _make_peer("10.0.0.5")
    pm.inbound_peers[addr] = peer  # so the getdata fallback has a ready peer
    _register(pm, peer, addr)

    cb, _ = _make_partial_cmpctblock(nonce_tag=30)
    await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))
    assert cb.block_hash in pm._partial_cmpct_blocks

    # A fresh entry is NOT swept.
    swept = await pm._sweep_partial_cmpct_blocks()
    assert swept == 0
    assert cb.block_hash in pm._partial_cmpct_blocks

    # Age the entry past the TTL by rewriting its timestamp.
    a, c, p, _ts = pm._partial_cmpct_blocks[cb.block_hash]
    import time as _t
    pm._partial_cmpct_blocks[cb.block_hash] = (a, c, p, _t.monotonic() - PARTIAL_CMPCT_TTL - 1)

    swept = await pm._sweep_partial_cmpct_blocks()
    assert swept == 1
    assert pm._partial_cmpct_blocks == {}
    # Liveness: a full-block getdata was sent for the swept hash (1 getblocktxn
    # at store time + 1 getdata at sweep time == 2 sends total).
    assert peer.send_message.await_count == 2


@pytest.mark.asyncio
async def test_ttl_sweep_empty_store_is_noop():
    """Sweeping an empty store returns 0 and does not raise."""
    pm = _make_manager()
    assert await pm._sweep_partial_cmpct_blocks() == 0


# ---------------------------------------------------------------------------
# (c) Per-peer in-flight cap keeps the store bounded under repeated insertion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_peer_in_flight_cap_bounds_the_store():
    """A single peer flooding orphaned cmpctblocks cannot retain more than
    MAX_CMPCT_IN_FLIGHT_PER_PEER entries: each insert past the cap evicts that
    peer's oldest entry (re-requested as a full block via getdata)."""
    pm = _make_manager()
    addr = "10.0.0.6:8333"
    peer = _make_peer("10.0.0.6")
    _register(pm, peer, addr)

    n = MAX_CMPCT_IN_FLIGHT_PER_PEER * 3  # 48 orphaned announcements
    for tag in range(100, 100 + n):
        cb, _ = _make_partial_cmpctblock(nonce_tag=tag)
        await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))

    # The store never exceeds the per-peer cap for this single peer.
    assert len(pm._partial_cmpct_blocks) <= MAX_CMPCT_IN_FLIGHT_PER_PEER
    # All surviving entries are attributed to the peer.
    assert all(e[0] == addr for e in pm._partial_cmpct_blocks.values())


@pytest.mark.asyncio
async def test_cap_is_per_peer_not_global():
    """The cap is PER-PEER: two peers can each hold up to the cap; one peer's
    fill does not evict another peer's entries."""
    pm = _make_manager()
    addr_a, addr_b = "10.0.0.7:8333", "10.0.0.8:8333"
    peer_a, peer_b = _make_peer("10.0.0.7"), _make_peer("10.0.0.8")
    _register(pm, peer_a, addr_a)
    _register(pm, peer_b, addr_b)

    # Peer B stores one entry first.
    cb_b, _ = _make_partial_cmpctblock(nonce_tag=900)
    await peer_b.message_handlers["cmpctblock"](_cmpct_msg(pm, cb_b))

    # Peer A floods well past the cap.
    for tag in range(200, 200 + MAX_CMPCT_IN_FLIGHT_PER_PEER * 2):
        cb, _ = _make_partial_cmpctblock(nonce_tag=tag)
        await peer_a.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))

    # Peer B's entry survives Peer A's flood.
    assert cb_b.block_hash in pm._partial_cmpct_blocks
    # Peer A is still bounded by its own cap.
    a_count = sum(1 for e in pm._partial_cmpct_blocks.values() if e[0] == addr_a)
    assert a_count <= MAX_CMPCT_IN_FLIGHT_PER_PEER


# ---------------------------------------------------------------------------
# (d) Correctness preserved: happy-path pop + fallbacks still work
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_blocktxn_pops_and_fires_handler():
    """The happy path is unchanged: a matching blocktxn pops the entry, fills
    the missing slot, and fires the registered compact-block handler with the
    completed tx list.  This is the path that decides which block CONNECTS."""
    pm = _make_manager()
    addr = "10.0.0.9:8333"
    peer = _make_peer("10.0.0.9")
    _register(pm, peer, addr)

    fired: list = []
    pm.set_compact_block_handler(lambda h, hdr, txs: fired.append((h, hdr, txs)))

    cb, missing_tx = _make_partial_cmpctblock(nonce_tag=40)
    await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))
    assert cb.block_hash in pm._partial_cmpct_blocks

    # Matching blocktxn supplies the one missing tx.
    await peer.message_handlers["blocktxn"](_blocktxn_msg(pm, cb.block_hash, [missing_tx]))

    # Entry popped, handler fired with a fully-assembled tx list (no None slots).
    assert cb.block_hash not in pm._partial_cmpct_blocks
    assert len(fired) == 1
    h, hdr, txs = fired[0]
    assert h == cb.block_hash
    assert hdr == cb.header
    assert all(tx is not None for tx in txs)
    assert len(txs) == 2  # coinbase + the filled missing tx


@pytest.mark.asyncio
async def test_blocktxn_with_no_matching_entry_is_ignored():
    """A blocktxn for a hash we never stored (or already cleaned/swept) is a
    no-op — it must not raise and must not fabricate an entry."""
    pm = _make_manager()
    addr = "10.0.0.10:8333"
    peer = _make_peer("10.0.0.10")
    _register(pm, peer, addr)

    fired: list = []
    pm.set_compact_block_handler(lambda *a: fired.append(a))

    unknown_hash = hashlib.sha256(b"never-stored").digest()
    await peer.message_handlers["blocktxn"](_blocktxn_msg(pm, unknown_hash, []))

    assert pm._partial_cmpct_blocks == {}
    assert fired == []


@pytest.mark.asyncio
async def test_blocktxn_too_few_txs_falls_back_to_getdata():
    """The existing getdata fallback still works with the new tuple shape:
    a blocktxn with fewer txs than missing slots pops the entry and re-requests
    the full block via getdata (entry NOT re-leaked)."""
    pm = _make_manager()
    addr = "10.0.0.11:8333"
    peer = _make_peer("10.0.0.11")
    _register(pm, peer, addr)

    cb, _missing_tx = _make_partial_cmpctblock(nonce_tag=50)
    await peer.message_handlers["cmpctblock"](_cmpct_msg(pm, cb))
    send_count_after_store = peer.send_message.await_count  # 1 (getblocktxn)

    # blocktxn with ZERO txs but the entry needs one → StopIteration fallback.
    await peer.message_handlers["blocktxn"](_blocktxn_msg(pm, cb.block_hash, []))

    # Entry consumed (popped), not re-leaked, and a getdata was sent.
    assert cb.block_hash not in pm._partial_cmpct_blocks
    assert peer.send_message.await_count == send_count_after_store + 1
