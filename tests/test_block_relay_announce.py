"""Block relay: a block connected via P2P must be announced to peers.

Regtest relay test 2026-09-26: two Bitcoin Core nodes connected ONLY to
ouroboros never converged -- ouroboros downloaded and connected Core A's
blocks but never announced them to Core B, because ``_announce_block`` was
only reached from the orphan-resolution path. Core relays every new tip from
PeerManagerImpl::UpdatedBlockTip (net_processing.cpp:2158) unless in IBD.
"""
import inspect

from ouroboros import block_sync
from ouroboros.block_sync import should_announce_tip


def test_should_announce_tip_follows_core_max_tip_age():
    now = 1_800_000_000
    assert should_announce_tip(now, now)
    assert should_announce_tip(now - 24 * 3600, now)  # boundary
    assert not should_announce_tip(now - 24 * 3600 - 1, now)
    assert should_announce_tip(now + 600, now)  # header slightly in the future


def test_primary_connect_path_announces():
    src = inspect.getsource(block_sync)
    notify = src.index("self._tip_notifier.notify()")
    progress = src.index('f"✓ Block {new_height} connected "')
    call = src.find("await self._announce_block(block, next_hash)", notify)
    assert notify < call < progress, "drain connect loop must announce the new tip"


def test_getdata_serves_msg_cmpct_block():
    """getdata(MSG_CMPCT_BLOCK) must be answered (full witness block).

    Core fetches a single directly-announced tip with MSG_CMPCT_BLOCK from a
    peer that sent sendcmpct; ouroboros used to drop it without a reply.
    """
    from ouroboros import node

    src = inspect.getsource(node)
    assert (
        "elif inv_type in (INV_TYPE_BLOCK, MSG_WITNESS_BLOCK, INV_TYPE_COMPACT_BLOCK):"
        in src
    )
    assert "if inv_type in (MSG_WITNESS_BLOCK, INV_TYPE_COMPACT_BLOCK):" in src
