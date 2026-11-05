"""The `rest` setting must reach the node's config dict.

NodeConfig knows `rest` (default "0", settable through ouroboros.conf or
OUROBOROS_REST) but to_dict() did not emit it, so BitcoinNode always read the
default and never mounted /rest/*, whatever the operator set.
"""

import pytest

from ouroboros.config import NodeConfig


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.delenv("OUROBOROS_REST", raising=False)
    monkeypatch.setenv("OUROBOROS_DATADIR", str(tmp_path))
    return lambda: NodeConfig(data_dir=str(tmp_path)).to_dict()


def test_rest_defaults_off(cfg):
    assert cfg()["rest"] is False


def test_rest_env_reaches_node_config(cfg, monkeypatch):
    monkeypatch.setenv("OUROBOROS_REST", "1")
    assert cfg()["rest"] is True


def test_rest_conf_file_reaches_node_config(tmp_path, monkeypatch):
    monkeypatch.delenv("OUROBOROS_REST", raising=False)
    conf = tmp_path / "ouroboros.conf"
    conf.write_text("[network]\nrest = 1\n")
    d = NodeConfig(config_path=str(conf), data_dir=str(tmp_path)).to_dict()
    assert d["rest"] is True


# --- /rest/mempool/* must answer, including for an EMPTY mempool ----------

import asyncio  # noqa: E402

from fastapi import HTTPException  # noqa: E402

from ouroboros.rest import RESTInterface  # noqa: E402


class _EmptyPool:
    """Falsy like the real Mempool (defines __len__ == 0)."""

    def __len__(self):
        return 0

    @property
    def mempool_sequence(self):
        return 7


class _FakeRPC:
    async def rpc_getmempoolinfo(self):
        return {"loaded": True, "size": 0}

    async def rpc_getrawmempool(self, verbose=False):
        return {} if verbose else []


class _Node:
    mempool = _EmptyPool()


def _rest(node=None):
    return RESTInterface(node or _Node(), rpc=_FakeRPC())


def test_rest_mempool_info_answers_for_empty_pool():
    resp = asyncio.run(_rest().rest_mempool_info())
    assert resp.status_code == 200
    assert b'"loaded":true' in resp.body.replace(b" ", b"")


def test_rest_mempool_contents_verbose_and_plain_for_empty_pool():
    r = _rest()
    assert asyncio.run(r.rest_mempool_contents(verbose=True, mempool_sequence=False)).body == b"{}"
    assert asyncio.run(r.rest_mempool_contents(verbose=False, mempool_sequence=False)).body == b"[]"
    seq = asyncio.run(r.rest_mempool_contents(verbose=False, mempool_sequence=True))
    assert b'"mempool_sequence":7' in seq.body.replace(b" ", b"")


def test_rest_mempool_absent_is_404():
    class NoPool:
        mempool = None

    with pytest.raises(HTTPException) as e:
        asyncio.run(_rest(NoPool()).rest_mempool_info())
    assert e.value.status_code == 404
