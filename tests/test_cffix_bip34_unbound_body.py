"""An unbound body must not trigger the BIP34 slot-misalign wipe.

``handle_block`` keys a delivered body by the hash of its first 80 bytes and
does no merkle binding before buffering it.  The drain's first check on the
deserialized body is the BIP34 coinbase-height-vs-slot guard; on a mismatch
``_handle_misaligned_block`` clears the validated-header queue, the IBD
buffer and all in-flight state.  So any peer could send a queued header
followed by a ~200-byte one-tx body whose coinbase encodes some other height
and wipe the whole download window, unpunished, as often as it liked.

Core runs ``CheckMerkleRoot`` (validation.cpp ``CheckBlock``) before a body
is stored (``ChainstateManager::AcceptBlock``): a body that does not hash to
its header's merkle root is ``BLOCK_MUTATED``, the sender is punished
(``MaybePunishNodeForBlock``) and nothing else is touched.

These tests drive the real ``handle_block`` -> ``_drain_block_buffer_locked``
path with real serialized bytes.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

from ouroboros.block_sync import BlockSync
from ouroboros.p2p_messages import encode_varint

H = 900_000  # active tip height, well above BIP34 activation (227,931)
PEER_HOST, PEER_PORT = "203.0.113.7", 8333
PEER_ADDR = f"{PEER_HOST}:{PEER_PORT}"


def _dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _bip34_script(height: int) -> bytes:
    enc = height.to_bytes(4, "little").rstrip(b"\x00")
    if enc[-1] & 0x80:
        enc += b"\x00"
    return bytes([len(enc)]) + enc + b"\x00"


def _coinbase_tx(height: int) -> bytes:
    script = _bip34_script(height)
    return (
        (1).to_bytes(4, "little")
        + b"\x01"
        + b"\x00" * 32 + b"\xff\xff\xff\xff"
        + encode_varint(len(script)) + script
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + (50_0000_0000).to_bytes(8, "little")
        + b"\x01\x51"  # OP_TRUE
        + (0).to_bytes(4, "little")
    )


def _header(prev: bytes, merkle_root: bytes, nonce: int) -> bytes:
    return (
        (0x20000000).to_bytes(4, "little")
        + prev
        + merkle_root
        + (1_700_000_000).to_bytes(4, "little")
        + (0x1703_0ECD).to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


def _block(header: bytes, txs: list[bytes]) -> bytes:
    return header + encode_varint(len(txs)) + b"".join(txs)


class _HdrRec:
    def __init__(self, prev: bytes):
        self.prev_blockhash = prev


def _setup():
    """Tip at H; queued headers H+1..H+4; honest body for H+2 buffered;
    H+3 in flight from another peer."""
    tip = b"\x7a" * 32
    db = MagicMock()
    db.get_best_block.return_value = (tip, H)
    db.has_block_hash.return_value = False
    db.get_block_bytes.return_value = None
    pm = MagicMock()
    pm.network = "mainnet"
    bs = BlockSync(db=db, validator=MagicMock(), peer_manager=pm)
    bs._prebase_headers_complete = True

    headers = []
    blocks = []
    prev = tip
    for i in range(1, 5):
        cb = _coinbase_tx(H + i)
        hdr = _header(prev, _dsha(cb), nonce=i)
        bh = _dsha(hdr)
        headers.append((bh, hdr, prev))
        blocks.append(_block(hdr, [cb]))
        prev = bh
    bs._validated_headers = [(bh, _HdrRec(p)) for bh, _, p in headers]

    h2_hash = headers[1][0]
    bs._buffer_put(h2_hash, (None, blocks[1]))
    bs._block_source_peer_addr[h2_hash] = "198.51.100.2:8333"
    other_peer = MagicMock()
    bs.requested_blocks[headers[2][0]] = 123.0
    bs._block_request_peer[headers[2][0]] = other_peer

    async def _noop():
        return None

    bs._request_next_blocks = _noop
    return bs, headers, blocks


def _attacker():
    peer = MagicMock()
    peer.host = PEER_HOST
    peer.port = PEER_PORT
    return peer


def _snapshot(bs):
    return (
        [bh for bh, _ in bs._validated_headers],
        {k: v[1] for k, v in bs._ibd_block_buffer.items()},
        dict(bs.requested_blocks),
        dict(bs._block_request_peer),
    )


@pytest.mark.asyncio
async def test_unbound_body_with_misaligned_bip34_does_not_wipe_state():
    """The finding: header_{H+1} + a one-tx body whose coinbase says H+5,
    from a peer we never asked.  The queue, the buffered honest H+2 body and
    the in-flight H+3 request must survive, and the sender is punished."""
    bs, headers, _ = _setup()
    before = _snapshot(bs)

    junk = _block(headers[0][1], [_coinbase_tx(H + 5)])
    assert len(junk) < 200
    msg = MagicMock()
    msg.payload = junk
    await bs.handle_block(msg, _attacker())

    after = _snapshot(bs)
    assert after[0] == before[0], "validated-header queue was wiped"
    assert after[1] == before[1], "IBD buffer was wiped"
    assert after[2] == before[2], "in-flight requests were wiped"
    assert after[3] == before[3], "in-flight peer map was wiped"
    calls = [
        c for c in bs.peer_manager.misbehaving.call_args_list
        if c.args and c.args[0] == PEER_ADDR
    ]
    assert calls, "sender of the unbound body was not punished"
    assert "bad-txnmrklroot" in calls[0].args[2]
    # BLOCK_MUTATED: the header may still name a valid block, so it is
    # neither marked failed nor perm-rejected, and is re-fetchable.
    h1 = headers[0][0]
    assert h1 not in bs._perm_rejected_blocks
    assert not bs.is_block_failed(h1)
    assert h1 not in bs._ibd_block_buffer


@pytest.mark.asyncio
async def test_repeated_unbound_bodies_never_wipe_state():
    """'Repeats the wipe at will': ten junk bodies leave the state intact."""
    bs, headers, _ = _setup()
    before = _snapshot(bs)
    for k in range(10):
        msg = MagicMock()
        msg.payload = _block(headers[0][1], [_coinbase_tx(H + 5 + k)])
        await bs.handle_block(msg, _attacker())
    assert _snapshot(bs) == before
    assert bs.peer_manager.misbehaving.call_count >= 10


@pytest.mark.asyncio
async def test_duplicated_tx_mutation_is_also_unbound():
    """CVE-2012-2459: [cb, x, y, y] hashes to the same root as [cb, x, y]
    (the odd level is padded by repeating its last hash).  Even with the
    header committing to that root, the body is mutated (bad-txns-duplicate,
    Core ComputeMerkleRoot) and must not wipe state either."""
    bs, headers, _ = _setup()
    cb = _coinbase_tx(H + 5)
    x = _coinbase_tx(H + 6)  # any distinct txs
    y = _coinbase_tx(H + 7)
    l1 = [_dsha(cb), _dsha(x), _dsha(y)]
    root = _dsha(_dsha(l1[0] + l1[1]) + _dsha(l1[2] + l1[2]))
    hdr = _header(headers[0][2], root, nonce=1)
    bh = _dsha(hdr)
    bs._validated_headers[0] = (bh, _HdrRec(headers[0][2]))
    before = _snapshot(bs)
    msg = MagicMock()
    msg.payload = _block(hdr, [cb, x, y, y])
    await bs.handle_block(msg, _attacker())
    assert _snapshot(bs) == before
    calls = [c for c in bs.peer_manager.misbehaving.call_args_list
             if c.args and c.args[0] == PEER_ADDR]
    assert calls and "bad-txns-duplicate" in calls[0].args[2]


@pytest.mark.asyncio
async def test_bound_misaligned_body_still_realigns_queue():
    """Control (the 938231 recovery is kept): a body that IS bound to its
    header yet carries another height means the queue itself is misaligned;
    the realignment wipe still runs and the canonical block is not punished
    or poisoned."""
    bs, headers, _ = _setup()
    cb = _coinbase_tx(H + 5)
    hdr = _header(headers[0][2], _dsha(cb), nonce=99)
    bh = _dsha(hdr)
    bs._validated_headers[0] = (bh, _HdrRec(headers[0][2]))
    msg = MagicMock()
    msg.payload = _block(hdr, [cb])
    await bs.handle_block(msg, _attacker())
    assert bs._validated_headers == []
    assert bs._ibd_block_buffer == {}
    assert bs.requested_blocks == {}
    assert not bs.peer_manager.misbehaving.called
    assert bh not in bs._perm_rejected_blocks


@pytest.mark.asyncio
async def test_bound_aligned_body_reaches_validation(monkeypatch):
    """Control (a valid block stays valid): the honest H+1 body passes the
    guard and is handed to the validator; nothing is dropped or punished."""
    monkeypatch.setenv("OUROBOROS_DISABLE_RUST_VALIDATE", "1")
    bs, headers, blocks = _setup()
    seen = []

    def _validate(block, **kw):
        seen.append(kw.get("known_height"))
        return False, "Previous block not found"  # hold: stop the drain here

    bs.validator.validate_block = _validate
    msg = MagicMock()
    msg.payload = blocks[0]
    await bs.handle_block(msg, _attacker())
    assert seen == [H + 1]
    assert not bs.peer_manager.misbehaving.called
    assert [bh for bh, _ in bs._validated_headers] == [h[0] for h in headers]


def test_merkle_token_helper_matches_core_classes():
    """Unit check of the binding helper on deserialized blocks."""
    from ouroboros.database import Block

    cb = _coinbase_tx(H + 1)
    good = Block.deserialize(_block(_header(b"\x00" * 32, _dsha(cb), 0), [cb]))
    bad = Block.deserialize(_block(_header(b"\x00" * 32, b"\x01" * 32, 0), [cb]))
    tok = getattr(BlockSync, "_body_merkle_reject_token", None)
    assert tok is not None, "BlockSync has no merkle-binding check"
    assert tok(good) is None
    assert tok(bad) == "bad-txnmrklroot"
