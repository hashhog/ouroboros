"""-maxmempool (MB) must size the mempool, as in Core's mempool_args.cpp.

Core: max_size_bytes = -maxmempool * 1'000'000, default 300.  ouroboros
hard-coded Mempool(max_size=300_000_000) and had no such option.
"""
from ouroboros import mempool as mp
from ouroboros.cli import start
from ouroboros.config import NodeConfig


def _helper():
    fn = getattr(mp, "max_mempool_bytes", None)
    assert fn is not None, "mempool.max_mempool_bytes missing: no -maxmempool support"
    return fn


def test_maxmempool_megabytes_to_bytes():
    assert _helper()({"maxmempool": 5}) == 5_000_000


def test_maxmempool_default_is_300mb():
    assert _helper()({}) == 300_000_000


def test_cli_start_has_maxmempool_option():
    assert "maxmempool" in {p.name for p in start.params}


def test_conf_file_maxmempool(tmp_path):
    conf = tmp_path / "ouroboros.conf"
    conf.write_text("[network]\nmaxmempool=7\n")
    cfg = NodeConfig(config_path=str(conf), data_dir=str(tmp_path)).to_dict()
    assert cfg.get("maxmempool") == 7
