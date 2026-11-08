"""operator/stop/result:$ -- Core's ``stop`` answers a fixed string.

Core rpc/server.cpp ``stop`` returns ``tfm::format("%s stopping", CLIENT_NAME)``
and CLIENT_NAME is "Bitcoin Core"; the core-regtest operator group compares the
string, so ouroboros must answer "Bitcoin Core stopping".
"""
import asyncio
from types import SimpleNamespace

from ouroboros.rpc import RPCServer


def test_stop_result_matches_core():
    server = RPCServer.__new__(RPCServer)
    server.node = SimpleNamespace(_shutdown_event=None)  # no event, no stop(): nothing scheduled to fire

    async def run():
        return await server.rpc_stop()

    assert asyncio.run(run()) == "Bitcoin Core stopping"
