"""Regression: request wtxid-announced txs via a MSG_WTX getdata (BIP-339).

Bug (found via tools/regtest-harness.sh --tx-relay, ouroboros Ingested=NO):
ouroboros negotiates BIP-339 wtxidrelay, so a wtxid-relay peer (Bitcoin Core)
announces a tx via an ``inv`` of type MSG_WTX(5) carrying the WTXID.  The old
``handle_inv`` matched MSG_WTX but then requested it via
``(MSG_WITNESS_TX, inv_hash)`` — downgrading the request to a TXID lookup while
keeping the hash = the WTXID.  For a segwit tx (wtxid != txid) the peer looks up
by txid, misses, and replies notfound → ouroboros never ingests the tx.

Fix mirrors Core's GetRequestsToSend
(``gtxid.IsWtxid() ? MSG_WTX : MSG_TX|fetch_flags``): a wtxid-announced inv is
requested via MSG_WTX (peer resolves by wtxid), a txid-announced inv via
MSG_WITNESS_TX.

Same bug class as the already-fixed rustoshi (d8936f3) and nimrod (4701dce).
"""

import sys
import unittest
from pathlib import Path

src_dir = Path(__file__).parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ouroboros.block_sync import BlockSync  # noqa: E402
from ouroboros.p2p_messages import (  # noqa: E402
    GetDataMessage,
    InvMessage,
    INV_TYPE_TX,
    MSG_WITNESS_TX,
    MSG_WTX,
)
from ouroboros.peer import Peer, PeerState  # noqa: E402


def _b32(n: int) -> bytes:
    return n.to_bytes(32, "little")


class _StubDB:
    def get_best_block(self):
        return _b32(0), 0

    def has_block_hash(self, h):
        return False


class _StubMempool:
    """Empty mempool: every inv item is an unknown tx that must be fetched.

    Distinct txid / wtxid namespaces so a namespace mix-up would surface.

    Defines __len__ (like the real ``Mempool``) so an EMPTY instance is
    *falsy* — this guards the regression where ``if self.mempool`` (a bare
    truthiness check) skips the very first tx request into a fresh mempool.
    The handler must use ``self.mempool is not None``.
    """

    def __len__(self):
        return 0

    def get_transaction(self, txid):
        return None

    def get_transaction_by_wtxid(self, wtxid):
        return None


class _StubPeerManager:
    network = "regtest"

    def __init__(self, peers):
        self._peers = peers

    def get_all_ready_peers(self):
        return self._peers


def _make_peer() -> Peer:
    p = Peer("10.0.0.1", 18444, network="regtest")
    p.state = PeerState.READY
    p.adjust_score = lambda d: None
    p.note_block_height = lambda h: None
    p.sent = []

    async def _send(msg):
        p.sent.append(msg)
        return None

    p.send_message = _send
    return p


def _fresh():
    peer = _make_peer()
    pm = _StubPeerManager([peer])
    bs = BlockSync.__new__(BlockSync)
    BlockSync.__init__(
        bs, db=_StubDB(), validator=None, peer_manager=pm, mempool=_StubMempool()
    )
    return bs, peer


def _getdata_items(peer):
    """Collect all (type, hash) tuples from every getdata the peer sent."""
    items = []
    for m in peer.sent:
        if m.command == "getdata":
            items.extend(GetDataMessage.from_payload(m.payload).inventory)
    return items


class TestWtxGetdataRequest(unittest.IsolatedAsyncioTestCase):
    async def test_wtx_inv_requested_via_msg_wtx(self):
        """A MSG_WTX inv for an unknown tx must yield a getdata of type MSG_WTX
        (NOT MSG_WITNESS_TX), keying the peer's lookup on the wtxid."""
        bs, peer = _fresh()
        wtxid = _b32(0xA1)
        inv = InvMessage([(MSG_WTX, wtxid)]).to_network_message("regtest")
        await bs.handle_inv(inv, peer)

        items = _getdata_items(peer)
        self.assertIn(
            (MSG_WTX, wtxid),
            items,
            "wtxid-announced tx must be requested via MSG_WTX(5) + wtxid",
        )
        self.assertNotIn(
            (MSG_WITNESS_TX, wtxid),
            items,
            "must NOT downgrade a MSG_WTX inv to a MSG_WITNESS_TX (txid) request",
        )

    async def test_txid_inv_requested_via_msg_witness_tx(self):
        """A plain INV_TYPE_TX inv for an unknown tx is still requested via
        MSG_WITNESS_TX (a witness TXID request) — legacy path unchanged."""
        bs, peer = _fresh()
        txid = _b32(0xB2)
        inv = InvMessage([(INV_TYPE_TX, txid)]).to_network_message("regtest")
        await bs.handle_inv(inv, peer)

        items = _getdata_items(peer)
        self.assertIn(
            (MSG_WITNESS_TX, txid),
            items,
            "txid-announced tx must be requested via MSG_WITNESS_TX + txid",
        )
        self.assertNotIn(
            (MSG_WTX, txid),
            items,
            "a txid inv must not be promoted to a MSG_WTX request",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
