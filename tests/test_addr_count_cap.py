"""addr / addrv2 per-message entry cap and re-serialized relay (audit H2).

Core ``ProcessAddrs`` (net_processing.cpp:5635-5638): an addr or addrv2
message with more than MAX_ADDR_TO_SEND (1000) entries is ``Misbehaving``
(discourage + disconnect) and none of it is processed or relayed.

Before this fix ouroboros' ``AddrMessage.from_payload`` looped over the
attacker-chosen count with no cap (a 4 MB frame parsed ~133k entries on the
event loop), and ``_relay_addr`` forwarded the RAW inbound message to two
peers, so an oversize message was amplified.  addrv2 was capped in the parser
but the peer was never scored.

Pins:
* the v1 parser refuses count > 1000 before reading a single entry;
* addr and addrv2 with 1001 entries score (ban) the sender, add nothing to
  addrman and relay nothing;
* what is relayed is a fresh message holding only the token-bucket-admitted
  entries, never the raw inbound bytes.
"""

import asyncio
import struct
import time

import pytest

from ouroboros.p2p import PeerManager
from ouroboros.p2p_messages import (
    AddrMessage,
    AddrV2Entry,
    AddrV2Message,
    NetworkAddress,
    NetworkMessage,
    NODE_NETWORK,
    encode_varint,
    get_magic,
)
from ouroboros.peer import Peer

SENDER_HOST = "93.184.216.34"


def _v1_entry(i: int, ts: int) -> tuple[int, NetworkAddress]:
    # 11.x.y.z — routable, distinct per i.
    ip = f"11.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
    return ts, NetworkAddress.from_ipv4(ip, 8333, services=NODE_NETWORK)


def _v1_msg(n: int) -> NetworkMessage:
    now = int(time.time())
    return AddrMessage(
        addresses=[_v1_entry(i + 1, now) for i in range(n)]
    ).to_network_message("regtest")


def _v1_payload(n: int) -> bytes:
    """Raw payload with count=n (AddrMessage.to_network_message is uncapped)."""
    now = int(time.time())
    data = encode_varint(n)
    for i in range(n):
        ts, na = _v1_entry(i + 1, now)
        data += struct.pack("<I", ts) + na.serialize()
    return data


def _v2_payload(n: int) -> bytes:
    """Raw addrv2 payload with count=n, built by hand so the
    serializer's own 1000-cap cannot hide the oversize count."""
    now = int(time.time())
    data = encode_varint(n)
    for i in range(n):
        i += 1
        data += struct.pack("<I", now)
        data += encode_varint(NODE_NETWORK)
        data += bytes([1])  # BIP155 IPv4
        data += encode_varint(4)
        data += bytes([12, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF])
        data += struct.pack(">H", 8333)
    return data


class _RelayTarget:
    """Connected full-relay peer that records what it is sent."""

    def __init__(self, host):
        self.host = host
        self.port = 8333
        self.relay_txs = True
        self.sent: list[NetworkMessage] = []

    def is_connected(self):
        return True

    async def send_message(self, msg):
        self.sent.append(msg)

    async def disconnect(self):
        pass


def _setup(tokens: float = 1000.0):
    pm = PeerManager(network="regtest", listen=False)
    sender = Peer(SENDER_HOST, 8333, "regtest", inbound=True)
    sender.addr_token_bucket = tokens
    sender.addr_token_timestamp = time.monotonic()
    key = f"{SENDER_HOST}:8333"
    pm.inbound_peers[key] = sender
    targets = [_RelayTarget("1.1.1.1"), _RelayTarget("2.2.2.2")]
    for t in targets:
        pm.peers[f"{t.host}:8333"] = t
    pm._register_addr_handlers(sender, key)
    return pm, sender, targets


def _run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------ parser


def test_addr_from_payload_1001_entries_raises():
    with pytest.raises(ValueError, match="1001"):
        AddrMessage.from_payload(_v1_payload(1001))


def test_addr_from_payload_refuses_huge_count_before_reading_entries():
    # Count claims 133,000 entries but no entry bytes follow.  Uncapped, the
    # parser starts reading and dies with struct.error; capped, it refuses on
    # the count (a ValueError naming the count) without touching an entry.
    payload = encode_varint(133_000)
    with pytest.raises(ValueError, match="133000"):
        AddrMessage.from_payload(payload)


def test_addr_from_payload_1000_entries_ok():
    am = AddrMessage.from_payload(_v1_payload(1000))
    assert len(am.addresses) == 1000


# ------------------------------------------------------------------ handler


def test_on_addr_1001_entries_scores_peer_and_relays_nothing():
    pm, sender, targets = _setup()
    before = pm.addrman.size()
    msg = NetworkMessage(command="addr", payload=_v1_payload(1001),
                         magic=get_magic("regtest"))
    _run(sender.message_handlers["addr"](msg))
    assert pm.ban_manager.is_banned(SENDER_HOST), \
        "oversize addr must Misbehave the sender (Core net_processing.cpp:5637)"
    assert pm.addrman.size() == before, "nothing from an oversize addr is stored"
    assert all(t.sent == [] for t in targets), "nothing is relayed"


def test_on_addrv2_1001_entries_scores_peer_and_relays_nothing():
    pm, sender, targets = _setup()
    before = pm.addrman.size()
    msg = NetworkMessage(command="addrv2", payload=_v2_payload(1001),
                         magic=get_magic("regtest"))
    _run(sender.message_handlers["addrv2"](msg))
    assert pm.ban_manager.is_banned(SENDER_HOST), \
        "oversize addrv2 must Misbehave the sender (Core net_processing.cpp:5637)"
    assert pm.addrman.size() == before
    assert all(t.sent == [] for t in targets)


def test_on_addr_1000_entries_does_not_score_peer():
    pm, sender, _ = _setup()
    _run(sender.message_handlers["addr"](_v1_msg(1000)))
    assert not pm.ban_manager.is_banned(SENDER_HOST)


def _relayed(targets):
    sent = [m for t in targets for m in t.sent]
    assert sent, "an addr that taught us new addresses is relayed"
    return sent


def test_on_addr_relays_only_token_bucket_admitted_entries_reserialized():
    pm, sender, targets = _setup(tokens=3.0)
    msg = _v1_msg(5)
    _run(sender.message_handlers["addr"](msg))
    for out in _relayed(targets):
        assert out.command == "addr"
        assert out.payload != msg.payload, "the raw inbound message is never relayed"
        relayed = AddrMessage.from_payload(out.payload).addresses
        assert len(relayed) == 3, "only the 3 token-bucket-admitted entries are relayed"
        inbound = AddrMessage.from_payload(msg.payload).addresses[:3]
        assert [(ts, a.serialize()) for ts, a in relayed] == \
            [(ts, a.serialize()) for ts, a in inbound]


def test_on_addr_relay_drops_trailing_garbage():
    # Bytes after the last entry are ignored by the parser; relaying the raw
    # message would forward them to two peers.
    pm, sender, targets = _setup()
    msg = _v1_msg(2)
    raw = NetworkMessage(command="addr", payload=msg.payload + b"\x00" * 4096,
                         magic=msg.magic)
    _run(sender.message_handlers["addr"](raw))
    for out in _relayed(targets):
        assert out.payload == msg.payload


def test_on_addrv2_relays_only_token_bucket_admitted_entries_reserialized():
    pm, sender, targets = _setup(tokens=3.0)
    payload = _v2_payload(5)
    msg = NetworkMessage(command="addrv2", payload=payload,
                         magic=get_magic("regtest"))
    _run(sender.message_handlers["addrv2"](msg))
    for out in _relayed(targets):
        assert out.command == "addrv2"
        assert out.payload != payload
        relayed = AddrV2Message.from_payload(out.payload).addresses
        assert [e.addr for e in relayed] == \
            [e.addr for e in AddrV2Message.from_payload(payload).addresses[:3]]
