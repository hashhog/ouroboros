"""submitheader on a header whose parent is invalid answers ``bad-prevblk``.

Core rpc/mining.cpp submitheader -> ProcessNewBlockHeaders -> AcceptBlockHeader
(validation.cpp): a header whose parent has BLOCK_FAILED_MASK set is rejected
with ``bad-prevblk`` (BLOCK_INVALID_PREV).  Core-regtest rows warden_invalidated_submit/header/
failed-parent:message and seed_invalidated_submit/header/failed-parent:message.
"""
import asyncio

import pytest

from tests.test_getchaintips_fleet_regtest import (  # noqa: F401
    TIP, _block, _disp, _setup, _use_real_sync,
)
from ouroboros.rpc import RpcError


def test_header_on_invalidated_tip_is_bad_prevblk(tmp_path):
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP])))
    raw, _h = _block(hashes[TIP], TIP + 1, b"\x31\xc5")
    with pytest.raises(RpcError) as ei:
        asyncio.run(server.rpc_submitheader(raw[:80].hex()))
    assert ei.value.code == -25
    assert ei.value.message == "bad-prevblk"


def test_header_on_invalidated_mid_chain_block_is_bad_prevblk(tmp_path):
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    asyncio.run(server.rpc_invalidateblock(_disp(hashes[TIP - 2])))
    # parent TIP-1 is a descendant of the invalidated block (BLOCK_FAILED_CHILD)
    raw, _h = _block(hashes[TIP - 1], TIP, b"\x32\xc5")
    with pytest.raises(RpcError) as ei:
        asyncio.run(server.rpc_submitheader(raw[:80].hex()))
    assert ei.value.message == "bad-prevblk"


def test_header_on_valid_parent_still_accepted(tmp_path):
    """Control: the new gate must not touch a header on a healthy parent."""
    _bdb, _chain, _bs, server, hashes = _setup(tmp_path)
    raw, _h = _block(hashes[TIP], TIP + 1, b"\x33\xc5")
    assert asyncio.run(server.rpc_submitheader(raw[:80].hex())) is None
