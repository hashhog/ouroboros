"""Tests for the ``getnodeaddresses`` RPC handler.

Mirrors Bitcoin Core ``rpc/net.cpp:911-970`` (getnodeaddresses) +
``netbase.cpp:100-128`` (ParseNetwork / GetNetworkName). The handler returns a
JSON array of objects, each with EXACTLY five keys in this order:
``time`` (unix seconds int), ``services`` (raw bitfield int), ``address``
(literal, no port), ``port`` (int), ``network`` (ipv4/ipv6/onion/i2p/cjdns/
not_publicly_routable).

Coverage:
- shape: keys + order + types for a routable ipv4 entry.
- count: default 1, ``0`` = all, ``count`` caps the result.
- network filter: only matching entries; an empty match returns ``[]``.
- error paths: ``count < 0`` -> -8 "Address count out of range";
  an unknown network -> -8 "Network not recognized: <raw>".
- empty addrman (no peer manager) -> ``[]`` (not an error).
"""
from __future__ import annotations

import pytest

from ouroboros.addrman import (
    AddrInfo,
    NET_IPV4,
    NET_TORV3,
)
from ouroboros.rpc import RPCServer, RpcError, RPC_INVALID_PARAMETER


class _StubAddrman:
    """Minimal addrman exposing the surface getnodeaddresses uses."""

    def __init__(self, addrs: list[AddrInfo]) -> None:
        self._addrs = list(addrs)

    def size(self) -> int:
        return len(self._addrs)

    def get_addresses(self, count: int = 1000) -> list[AddrInfo]:
        # Real addrman shuffles; the handler is order-insensitive, so a
        # deterministic slice keeps the test stable.
        return self._addrs[:count]


def _make_rpc(addrs: list[AddrInfo] | None) -> RPCServer:
    rpc = RPCServer.__new__(RPCServer)

    class _PeerManager:
        pass

    class _Node:
        pass

    node = _Node()
    if addrs is not None:
        pm = _PeerManager()
        pm.addrman = _StubAddrman(addrs)
        node.peer_manager = pm
    node.network = "regtest"
    rpc.node = node
    return rpc


def _ipv4(host: str, port: int, services: int, last_seen: int) -> AddrInfo:
    return AddrInfo(
        host=host, port=port, services=services,
        network_id=NET_IPV4, last_seen=float(last_seen),
    )


@pytest.mark.asyncio
async def test_shape_keys_order_and_types() -> None:
    rpc = _make_rpc([_ipv4("8.8.8.8", 8333, 1033, 1_700_000_000)])
    res = await rpc.rpc_getnodeaddresses(0)
    assert len(res) == 1
    obj = res[0]
    # EXACTLY these five keys, in this order.
    assert list(obj.keys()) == ["time", "services", "address", "port", "network"]
    assert obj["address"] == "8.8.8.8"
    assert obj["port"] == 8333
    assert obj["network"] == "ipv4"
    assert obj["services"] == 1033
    assert obj["time"] == 1_700_000_000
    # services/time/port are plain ints (NOT hex strings, unlike getpeerinfo).
    assert isinstance(obj["services"], int)
    assert isinstance(obj["time"], int)
    assert isinstance(obj["port"], int)


@pytest.mark.asyncio
async def test_count_caps_and_zero_is_all() -> None:
    addrs = [_ipv4(f"8.8.8.{i}", 8333, 1, 1_700_000_000 + i) for i in range(5)]
    rpc = _make_rpc(addrs)
    assert len(await rpc.rpc_getnodeaddresses(0)) == 5       # 0 = all
    assert len(await rpc.rpc_getnodeaddresses(2)) == 2       # capped
    assert len(await rpc.rpc_getnodeaddresses()) == 1        # default 1


@pytest.mark.asyncio
async def test_network_filter() -> None:
    onion = AddrInfo(
        host="explorernuoc63nb.onion", port=8333, services=1,
        network_id=NET_TORV3, last_seen=1_700_000_000.0,
    )
    rpc = _make_rpc([_ipv4("8.8.8.8", 8333, 1, 1_700_000_000), onion])
    ipv4_only = await rpc.rpc_getnodeaddresses(0, "ipv4")
    assert [o["network"] for o in ipv4_only] == ["ipv4"]
    onion_only = await rpc.rpc_getnodeaddresses(0, "onion")
    assert [o["network"] for o in onion_only] == ["onion"]
    # A valid network with no matching entry -> empty array, not an error.
    assert await rpc.rpc_getnodeaddresses(0, "i2p") == []
    # ParseNetwork is case-insensitive.
    assert len(await rpc.rpc_getnodeaddresses(0, "IPv4")) == 1


@pytest.mark.asyncio
async def test_negative_count_raises() -> None:
    rpc = _make_rpc([_ipv4("8.8.8.8", 8333, 1, 1_700_000_000)])
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getnodeaddresses(-1)
    assert ei.value.code == RPC_INVALID_PARAMETER
    assert ei.value.message == "Address count out of range"


@pytest.mark.asyncio
async def test_unknown_network_raises_with_raw_arg() -> None:
    rpc = _make_rpc([_ipv4("8.8.8.8", 8333, 1, 1_700_000_000)])
    with pytest.raises(RpcError) as ei:
        await rpc.rpc_getnodeaddresses(1, "bogus")
    assert ei.value.code == RPC_INVALID_PARAMETER
    assert ei.value.message == "Network not recognized: bogus"


@pytest.mark.asyncio
async def test_empty_addrman_returns_empty_list() -> None:
    rpc = _make_rpc(None)  # no peer_manager -> _get_addrman() is None
    assert await rpc.rpc_getnodeaddresses(0) == []
