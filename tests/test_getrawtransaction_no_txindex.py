"""getrawtransaction without a blockhash honours --no-txindex, like Core.

Core's default is -txindex=0: a confirmed transaction asked for without a
blockhash is not found, and the error is -5 "No such mempool transaction.
Use -txindex or provide a block hash ..." (rpc/rawtransaction.cpp).
ouroboros keeps the index on by default; --no-txindex turns the lookup off.
"""
import pytest

from tests.test_getrawtx import MockNode
from tests.test_getrawtx import sample_block, sample_tx  # noqa: F401  (fixtures)


def _rpc(node):
    from ouroboros.rpc import RPCServer
    rpc = RPCServer.__new__(RPCServer)
    rpc._side_branch_blocks = {}
    rpc.node = node
    return rpc


def _confirmed(node, tx, block):
    node.db.blocks[block.block_hash] = block
    node.db.tx_index[tx.get_txid()] = (block.block_hash, 50, 0)
    node.db.height_to_hash[50] = block.block_hash


@pytest.mark.asyncio
async def test_no_txindex_confirmed_tx_needs_blockhash(sample_tx, sample_block):
    from ouroboros.rpc import RPC_INVALID_ADDRESS_OR_KEY, RpcError
    node = MockNode()
    node.config = {"txindex": False}
    _confirmed(node, sample_tx, sample_block)
    with pytest.raises(RpcError) as exc:
        await _rpc(node).rpc_getrawtransaction(sample_tx.get_txid().hex(), verbose=True)
    assert exc.value.code == RPC_INVALID_ADDRESS_OR_KEY
    assert exc.value.message.startswith("No such mempool transaction. Use -txindex")


@pytest.mark.asyncio
async def test_no_txindex_blockhash_still_works(sample_tx, sample_block):
    node = MockNode()
    node.config = {"txindex": False}
    _confirmed(node, sample_tx, sample_block)
    result = await _rpc(node).rpc_getrawtransaction(
        sample_tx.get_txid().hex(), verbose=True, blockhash=sample_block.block_hash.hex())
    assert result["blockhash"] == sample_block.block_hash.hex()


@pytest.mark.asyncio
async def test_default_keeps_txindex_lookup(sample_tx, sample_block):
    node = MockNode()
    node.config = {}
    _confirmed(node, sample_tx, sample_block)
    result = await _rpc(node).rpc_getrawtransaction(sample_tx.get_txid().hex(), verbose=True)
    assert result["blockhash"] == sample_block.block_hash.hex()


def test_cli_exposes_no_txindex_flag():
    from ouroboros.cli import start
    names = {o for p in start.params for o in p.opts + p.secondary_opts}
    assert "--no-txindex" in names and "--txindex" in names
