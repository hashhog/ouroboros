"""Persistent wallet tx/output store (Core ``CWallet::mapWallet``).

Before the store, balance, listunspent and coin selection asked the
chainstate for each wallet address (``Database.list_unspent_by_address``,
one full UTXO-set walk per address per call), the coinbase-maturity rule was
copied with different thresholds (getbalances counted a 100-confirmation
coinbase as trusted, listunspent listed every immature coinbase), the tx
history was in-memory only, and the mempool never told the wallet anything.

Core v31.1 regtest rows this targets (``wallet`` group):
``wallet/receive/listunspent:{count,min_confirmations,spendable[1],
spendable[2],spendable_count}`` and
``wallet/receive/getbalances:mine.{trusted,immature}``.

Core references: wallet/wallet.h mapWallet; wallet/wallet.cpp
AddToWalletIfInvolvingMe, blockConnected, blockDisconnected,
transactionAddedToMempool, transactionRemovedFromMempool, IsSpent,
IsTxImmatureCoinBase; wallet/receive.cpp GetBalance; wallet/spend.cpp
AvailableCoins.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from types import SimpleNamespace

COIN = 100_000_000
FOREIGN_SPK = b"\x00\x14" + b"\xee" * 20


def _h(*parts) -> bytes:
    return hashlib.sha256(repr(parts).encode()).digest()


class _Tx(SimpleNamespace):
    def get_txid(self):
        return self.txid

    def serialize_with_witness(self):
        return b"\x00"


def _coinbase(height, spk, value=50 * COIN):
    return _Tx(
        txid=_h("cb", height, spk), is_coinbase=True, inputs=[],
        outputs=[SimpleNamespace(value=value, script_pubkey=spk)],
    )


def _spend(prev_txid, prev_vout, outputs, tag="spend"):
    return _Tx(
        txid=_h(tag, prev_txid, prev_vout, tuple(outputs)), is_coinbase=False,
        inputs=[SimpleNamespace(prev_txid=prev_txid, prev_vout=prev_vout)],
        outputs=[SimpleNamespace(value=v, script_pubkey=s) for s, v in outputs],
    )


class FakeChain:
    """Active chain + chainstate UTXO set, fed block by block.

    It answers the chainstate queries the wallet used before the store
    (``list_unspent_by_address``, ``get_balance``), counting each one, and
    the ones the store needs (``iter_unspent_for_scripts``, ``get_utxo``,
    ``get_block_hash_by_height``).
    """

    def __init__(self, network="regtest"):
        self.network = network
        self.blocks: dict[int, SimpleNamespace] = {}
        self.utxos: dict[tuple[bytes, int], dict] = {}
        self.tip = 0
        self.utxo_walks = 0

    def connect(self, wallet, height, txs, tag=""):
        block = SimpleNamespace(
            hash=_h("blk", height, tag), timestamp=1_700_000_000 + height,
            transactions=txs,
        )
        for tx in txs:
            for inp in tx.inputs:
                self.utxos.pop((bytes(inp.prev_txid), int(inp.prev_vout)), None)
            for i, out in enumerate(tx.outputs):
                self.utxos[(tx.txid, i)] = {
                    "value": out.value, "script_pubkey": out.script_pubkey,
                    "height": height, "is_coinbase": tx.is_coinbase,
                }
        self.blocks[height] = block
        self.tip = height
        wallet.scan_block_connect(block, height)
        return block

    # --- chain queries ------------------------------------------------------
    def get_best_block(self):
        return self.blocks[self.tip].hash if self.tip in self.blocks else b"\x00" * 32, self.tip

    def get_block_hash_by_height(self, h):
        b = self.blocks.get(h)
        return None if b is None else b.hash

    def get_block_by_height(self, h):
        return self.blocks.get(h)

    def get_utxo(self, txid, vout):
        return self.utxos.get((bytes(txid), int(vout)))

    # --- chainstate walks ---------------------------------------------------
    def _rows(self, match):
        for (txid, vout), u in self.utxos.items():
            if match(bytes(u["script_pubkey"])):
                yield {"txid": txid[::-1].hex(), "vout": vout, **u}

    def list_unspent_by_address(self, address, network="regtest"):
        from ouroboros.address import address_to_script_pubkey

        self.utxo_walks += 1
        spk = address_to_script_pubkey(address, network)
        return list(self._rows(lambda s: s == spk))

    def get_balance(self, address, network="regtest"):
        return sum(u["value"] for u in self.list_unspent_by_address(address, network))

    def iter_unspent_for_scripts(self, scripts):
        self.utxo_walks += 1
        yield from self._rows(lambda s: s in scripts)


def _wallet(tmp_path, name="w"):
    from ouroboros.wallet import Wallet

    wdir = tmp_path / "wallets" / name
    wdir.mkdir(parents=True, exist_ok=True)
    return Wallet(
        data_dir=str(tmp_path), network="regtest", name=name, wallet_dir=str(wdir)
    )


def _funded_wallet(tmp_path, blocks=101):
    """Wallet whose address A received the coinbase of blocks 1..*blocks*
    (the Core regtest wallet group's setup)."""
    from ouroboros.address import address_to_script_pubkey

    w = _wallet(tmp_path)
    w.init_hd(seed=bytes(range(32)))
    addr = asyncio.run(w.generate_new_address(address_type="bech32"))
    spk = address_to_script_pubkey(addr, "regtest")
    chain = FakeChain()
    w.set_database(chain)
    for h in range(1, blocks + 1):
        chain.connect(w, h, [_coinbase(h, spk)])
    return w, chain, addr, spk


def _rpc(wallet, chain):
    from ouroboros.rpc import RPCServer

    rpc = RPCServer.__new__(RPCServer)
    rpc.node = SimpleNamespace(
        wallet=wallet, db=chain, network="regtest", fee_estimator=None,
    )
    rpc._current_wallet_name = None
    return rpc


def test_listunspent_and_balances_apply_one_coinbase_maturity_rule(tmp_path):
    """Core at tip 101 with 101 coinbases of 50: listunspent lists only the
    mature height-1 coin (101 confirmations); getbalances is trusted 50,
    immature 5000; getbalance 50.  ouroboros listed all 101 coins and
    counted the 100-confirmation coinbase as trusted (100 / 4950)."""
    w, chain, _addr, _spk = _funded_wallet(tmp_path)
    rpc = _rpc(w, chain)

    unspent = asyncio.run(rpc.rpc_listunspent())
    assert [(u["amount"], u["confirmations"]) for u in unspent] == [(50.0, 101)]

    bal = asyncio.run(rpc.rpc_getbalances())
    assert bal["mine"]["trusted"] == 50.0
    assert bal["mine"]["immature"] == 5000.0
    assert bal["mine"]["untrusted_pending"] == 0.0
    assert asyncio.run(rpc.rpc_getbalance()) == 50.0
    assert asyncio.run(w.get_balance()) == 50 * COIN
    assert [u["height"] for u in w._collect_utxos()] == [1]


def test_wallet_reads_never_walk_the_utxo_set(tmp_path):
    """Balance, listunspent, getbalance(s), getwalletinfo-style address
    balances and coin selection read the wallet's own store; none of them
    walks the chainstate UTXO set (one walk per address per call before)."""
    w, chain, _addr, _spk = _funded_wallet(tmp_path)
    rpc = _rpc(w, chain)
    chain.utxo_walks = 0

    asyncio.run(rpc.rpc_listunspent())
    asyncio.run(rpc.rpc_getbalances())
    asyncio.run(rpc.rpc_getbalance())
    asyncio.run(w.get_balance())
    asyncio.run(w.get_addresses())
    w._collect_utxos()
    w._select_coins(1 * COIN, 1.0)

    assert chain.utxo_walks == 0


def test_wallet_coins_and_history_survive_restart(tmp_path):
    """The store is on disk: a restarted wallet still has its coins and its
    transaction history without a rescan.  The history was in-memory only,
    and the startup reconcile rescans only above the scan marker, so
    gettransaction lost every tx at or below it on restart."""
    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=5)
    txid3 = _coinbase(3, spk).txid[::-1].hex()
    assert w.gettransaction_entry(txid3) is not None
    w._save()
    getattr(w, "close_store", lambda: None)()

    w2 = _wallet(tmp_path)
    w2.set_database(chain)
    entry = w2.gettransaction_entry(txid3)
    assert entry is not None and entry["blockheight"] == 3
    coins = w2.wallet_coins()
    assert sorted(c["height"] for c in coins) == [1, 2, 3, 4, 5]


def test_mempool_add_and_remove_update_the_store(tmp_path):
    """Core transactionAddedToMempool / transactionRemovedFromMempool: a
    mempool tx spending a wallet coin hides that coin from listunspent and
    coin selection, its change is a trusted unconfirmed coin; when the tx
    leaves the pool unconfirmed (replaced) both are undone.  ouroboros's
    wallet never heard from the mempool."""
    from ouroboros.wallet import WalletManager

    w, chain, _addr, spk = _funded_wallet(tmp_path)
    mgr = WalletManager(str(tmp_path), "regtest")
    mgr._wallets["w"] = w
    pool = SimpleNamespace(_on_tx_added=None, _on_tx_removed=None)
    mgr.set_mempool(pool)
    rpc = _rpc(w, chain)

    mature = _coinbase(1, spk)
    send = _spend(mature.txid, 0, [(FOREIGN_SPK, 10 * COIN), (spk, 39 * COIN)])
    pool._on_tx_added(send.txid, send, 1)

    unspent = asyncio.run(rpc.rpc_listunspent(0))
    assert (50.0, 101) not in [(u["amount"], u["confirmations"]) for u in unspent]
    assert [(u["amount"], u["confirmations"], u["safe"])
            for u in unspent if u["confirmations"] == 0] == [(39.0, 0, True)]
    assert asyncio.run(rpc.rpc_listunspent()) == []          # minconf=1 default
    assert w._collect_utxos() == []
    bal = asyncio.run(rpc.rpc_getbalances())
    assert bal["mine"]["trusted"] == 39.0
    assert bal["mine"]["immature"] == 5000.0

    pool._on_tx_removed(send.txid, "replaced", 2)
    unspent = asyncio.run(rpc.rpc_listunspent(0))
    assert [(u["amount"], u["confirmations"]) for u in unspent] == [(50.0, 101)]
    assert (asyncio.run(rpc.rpc_getbalances()))["mine"]["trusted"] == 50.0


def test_mempool_tx_then_block_then_pool_removal_keeps_confirmed_rows(tmp_path):
    """The mempool removes a tx after its block connected; that removal must
    not undo what the block confirmed."""
    from ouroboros.wallet import WalletManager

    w, chain, _addr, spk = _funded_wallet(tmp_path)
    mgr = WalletManager(str(tmp_path), "regtest")
    mgr._wallets["w"] = w
    pool = SimpleNamespace(_on_tx_added=None, _on_tx_removed=None)
    mgr.set_mempool(pool)

    mature = _coinbase(1, spk)
    send = _spend(mature.txid, 0, [(FOREIGN_SPK, 10 * COIN), (spk, 39 * COIN)])
    pool._on_tx_added(send.txid, send, 1)
    chain.connect(w, 102, [_coinbase(102, FOREIGN_SPK), send])
    pool._on_tx_removed(send.txid, "unknown", 2)

    coins = {(c["value"], c["depth"]) for c in w.wallet_coins()}
    assert (39 * COIN, 1) in coins
    assert (50 * COIN, 102) not in coins
    # tip 102: the height-2 coinbase is now mature as well.
    assert asyncio.run(w.get_balance()) == 39 * COIN + 50 * COIN


def test_block_at_held_height_unwinds_the_old_branch(tmp_path):
    """A block arriving at a height the store holds under another hash
    (the atomic Rust disconnect path never reports per-height disconnects)
    unwinds the stale block first: its coins and history go."""
    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=101)
    mature = _coinbase(1, spk)
    pay = _spend(mature.txid, 0, [(spk, 49 * COIN)], tag="stale")
    chain.connect(w, 102, [_coinbase(102, FOREIGN_SPK), pay], tag="A")
    assert w.gettransaction_entry(pay.txid[::-1].hex()) is not None

    chain.connect(w, 102, [_coinbase(102, FOREIGN_SPK)], tag="B")
    assert w.gettransaction_entry(pay.txid[::-1].hex()) is None
    coins = {(c["height"], c["value"]) for c in w.wallet_coins()}
    assert (102, 49 * COIN) not in coins
    assert (1, 50 * COIN) in coins            # its spend was undone


def test_reconcile_unwinds_blocks_the_chain_lost_while_down(tmp_path):
    """Restart after a reorg the wallet never saw: the store's top block is
    not the chain's any more, so it is unwound (Core AttachChain locator)."""
    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=101)
    chain.connect(w, 102, [_coinbase(102, spk)], tag="A")
    getattr(w, "close_store", lambda: None)()

    chain.blocks[102] = SimpleNamespace(
        hash=_h("blk", 102, "B"), timestamp=0, transactions=[]
    )
    w2 = _wallet(tmp_path)
    w2.set_database(chain)
    assert w2.reconcile_store_with_chain() == 102
    assert 102 not in {c["height"] for c in w2.wallet_coins()}


def test_migration_builds_the_store_from_the_chain(tmp_path):
    """A wallet file from before the store gets one built from the existing
    chain: every chainstate coin paying a wallet script, with its height
    and coinbase flag, in ONE walk.  A coin spent while the walk ran is
    dropped by the re-check against the chainstate."""
    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import WalletManager

    w = _wallet(tmp_path)
    w.init_hd(seed=bytes(range(32)))
    addr = asyncio.run(w.generate_new_address(address_type="bech32"))
    w._save()
    getattr(w, "close_store", lambda: None)()
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / "wallets" / "w" / f"txstore.sqlite{suffix}"
        if p.exists():
            p.unlink()

    spk = address_to_script_pubkey(addr, "regtest")
    chain = FakeChain()
    for h in range(1, 102):
        tx = _coinbase(h, spk)
        chain.utxos[(tx.txid, 0)] = {
            "value": 50 * COIN, "script_pubkey": spk, "height": h, "is_coinbase": True,
        }
        chain.blocks[h] = SimpleNamespace(hash=_h("blk", h), timestamp=0, transactions=[tx])
    chain.tip = 101
    ghost = _h("ghost")
    real_iter = chain.iter_unspent_for_scripts

    def _iter_then_spend(scripts):
        yield {"txid": ghost[::-1].hex(), "vout": 0, "value": 7 * COIN,
               "script_pubkey": spk, "height": 50, "is_coinbase": False}
        yield from real_iter(scripts)

    chain.iter_unspent_for_scripts = _iter_then_spend

    mgr = WalletManager(str(tmp_path), "regtest")
    mgr.set_database(chain)
    wallet, _warn = mgr.load_wallet("w")
    assert not wallet.store_migration_pending
    bal = wallet.get_balances_sat()
    assert bal == {"trusted": 50 * COIN, "untrusted_pending": 0, "immature": 100 * 50 * COIN}
    assert 7 * COIN not in {c["value"] for c in wallet.wallet_coins()}
    assert wallet.migrate_store_if_needed() is None      # done once


def test_migration_waits_for_background_reconcile_at_startup(tmp_path):
    """Startup loading never runs the UTXO walk inline (a boot repair must not
    hold up boot); the background reconcile_on_load does it."""
    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import WalletManager

    w = _wallet(tmp_path)
    w.init_hd(seed=bytes(range(32)))
    addr = asyncio.run(w.generate_new_address(address_type="bech32"))
    w._best_scanned_height = 3
    w._save()
    getattr(w, "close_store", lambda: None)()
    (tmp_path / "wallets" / "w" / "txstore.sqlite").unlink()

    spk = address_to_script_pubkey(addr, "regtest")
    chain = FakeChain()
    tx = _coinbase(1, spk, value=5 * COIN)
    chain.utxos[(tx.txid, 0)] = {"value": 5 * COIN, "script_pubkey": spk,
                                 "height": 1, "is_coinbase": False}
    for h in range(1, 4):
        chain.blocks[h] = SimpleNamespace(hash=_h("blk", h), timestamp=0, transactions=[])
    chain.tip = 3

    mgr = WalletManager(str(tmp_path), "regtest")
    mgr.set_database(chain)
    mgr._update_load_on_startup("w", True)
    mgr.load_startup_wallets()
    wallet = mgr.get_wallet("w")
    assert wallet.store_migration_pending
    assert chain.utxo_walks == 0
    mgr.reconcile_on_load()
    assert not wallet.store_migration_pending
    assert asyncio.run(wallet.get_balance()) == 5 * COIN


def test_store_file_is_owner_only(tmp_path):
    _wallet(tmp_path)
    path = tmp_path / "wallets" / "w" / "txstore.sqlite"
    assert path.exists(), "no persistent wallet store"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_unlock_catches_up_blocks_connected_and_lost_while_locked(tmp_path):
    """A locked wallet has no scripts in memory, so block notifications skip
    it.  Before the store its coins still showed up after unlock, because
    every read walked the chainstate with the unlocked keys; the store has
    to catch up on unlock instead: drop coins from blocks the chain lost
    while locked, and add coins from blocks connected while locked."""
    from ouroboros.wallet import WalletManager

    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=101)
    mgr = WalletManager(str(tmp_path), "regtest")
    mgr._wallets["w"] = w
    via_mgr = SimpleNamespace(scan_block_connect=mgr.notify_block_connected)

    stale = _spend(_h("foreign"), 0, [(spk, 3 * COIN)], tag="stale")
    chain.connect(via_mgr, 102, [_coinbase(102, FOREIGN_SPK), stale], tag="A")
    assert 3 * COIN in {c["value"] for c in w.wallet_coins()}

    w.encrypt("pw")
    w.lock()
    # Reorg while locked: 102A is replaced by 102B, then 103 pays the wallet.
    chain.utxos.pop((stale.txid, 0), None)
    chain.connect(via_mgr, 102, [_coinbase(102, FOREIGN_SPK)], tag="B")
    pay = _spend(_h("foreign2"), 0, [(spk, 7 * COIN)], tag="pay")
    chain.connect(via_mgr, 103, [_coinbase(103, FOREIGN_SPK), pay])

    w.unlock("pw")
    values = [c["value"] for c in w.wallet_coins()]
    assert 3 * COIN not in values
    assert 7 * COIN in values
    # tip 103: coinbases 1..3 are mature (150) plus the 7 BTC payment.
    assert asyncio.run(w.get_balance()) == 3 * 50 * COIN + 7 * COIN


def test_failed_migration_walk_stays_pending(tmp_path):
    """A chainstate walk that cannot run must not be recorded as a finished
    migration with no coins: the balance would read 0 for good.  The store
    stays pending and the next attempt migrates."""
    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import WalletManager

    w = _wallet(tmp_path)
    w.init_hd(seed=bytes(range(32)))
    addr = asyncio.run(w.generate_new_address(address_type="bech32"))
    w._save()
    getattr(w, "close_store", lambda: None)()
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / "wallets" / "w" / f"txstore.sqlite{suffix}"
        if p.exists():
            p.unlink()

    spk = address_to_script_pubkey(addr, "regtest")
    chain = FakeChain()
    tx = _coinbase(1, spk, value=5 * COIN)
    chain.utxos[(tx.txid, 0)] = {"value": 5 * COIN, "script_pubkey": spk,
                                 "height": 1, "is_coinbase": False}
    chain.blocks[1] = SimpleNamespace(hash=_h("blk", 1), timestamp=0, transactions=[tx])
    chain.tip = 1
    real_iter = chain.iter_unspent_for_scripts

    # The real database walk over an extension whose UTXO iterator fails
    # to open (a stale wheel, a RocksDB error).
    from ouroboros.database import BlockchainDatabase

    def _fail():
        raise OSError("iterator open")

    real_db = BlockchainDatabase.__new__(BlockchainDatabase)
    real_db._db = SimpleNamespace(iter_utxos=_fail)
    chain.iter_unspent_for_scripts = real_db.iter_unspent_for_scripts
    mgr = WalletManager(str(tmp_path), "regtest")
    mgr.set_database(chain)
    wallet, _warn = mgr.load_wallet("w")
    assert wallet.store_migration_pending

    chain.iter_unspent_for_scripts = real_iter
    assert wallet.migrate_store_if_needed() == 1
    assert not wallet.store_migration_pending
    assert asyncio.run(wallet.get_balance()) == 5 * COIN


def test_database_script_walk_raises_when_the_walk_cannot_run():
    """``BlockchainDatabase.iter_unspent_for_scripts`` (the migration's walk) raises
    instead of yielding nothing when the extension has no ``iter_utxos`` or
    the iterator fails to open; the per-address walks keep their old
    yield-nothing fallback."""
    import pytest

    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase.__new__(BlockchainDatabase)
    db._db = SimpleNamespace()
    with pytest.raises(RuntimeError):
        list(db.iter_unspent_for_scripts({b"\x51"}))

    def _fail():
        raise OSError("iterator open")

    db._db = SimpleNamespace(iter_utxos=_fail)
    with pytest.raises(RuntimeError):
        list(db.iter_unspent_for_scripts({b"\x51"}))
    assert list(db._iter_matching_utxos(b"\x51")) == []


def test_block_connected_through_the_rpc_path_while_locked_is_found_on_unlock(tmp_path):
    """submitblock / generatetoaddress call ``scan_block_connect`` on every
    wallet directly, locked or not.  A locked wallet (no scripts in memory)
    must not record that block as processed, or unlock would skip it."""
    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=101)
    w.encrypt("pw")
    w.lock()
    pay = _spend(_h("foreign"), 0, [(spk, 7 * COIN)], tag="pay")
    chain.connect(w, 102, [_coinbase(102, FOREIGN_SPK), pay])   # RPC path

    w.unlock("pw")
    assert 7 * COIN in [c["value"] for c in w.wallet_coins()]


class _Pool(SimpleNamespace):
    """Mempool stand-in: holds txs, fires the hooks the wallet installs."""

    def __init__(self):
        super().__init__(_on_tx_added=None, _on_tx_removed=None, txs={})

    def add(self, tx):
        self.txs[bytes(tx.txid)] = tx
        if self._on_tx_added is not None:
            self._on_tx_added(tx.txid, tx, 1)

    def get_transaction(self, txid):
        return self.txs.get(bytes(txid))

    def get_all_transactions(self):
        return list(self.txs.values())


def test_invalidate_and_reconsider_resync_the_store(tmp_path):
    """invalidateblock / reconsiderblock / the atomic Rust reorg change the
    chain without per-block wallet notifications.  The RPC's mempool refill
    resyncs every wallet first: an invalidated block's coins go and its txs
    come back as unconfirmed through the mempool re-add; a reconsidered
    branch's coins come back."""
    from ouroboros.rpc import RPCServer

    w, chain, _addr, spk = _funded_wallet(tmp_path, blocks=101)
    pay = _spend(_h("foreign"), 0, [(spk, 3 * COIN)], tag="pay")
    block102 = chain.connect(w, 102, [_coinbase(102, spk), pay])
    pool = _Pool()
    w.set_mempool(pool)
    rpc = RPCServer.__new__(RPCServer)
    rpc.node = SimpleNamespace(wallet=w, mempool=None, wallet_manager=None)

    # invalidateblock 102: the chain drops it, then the mempool refill runs.
    del chain.blocks[102]
    chain.tip = 101
    asyncio.run(rpc._update_mempool_after_disconnect(chain, []))
    assert 102 not in {c["height"] for c in w.wallet_coins()}
    assert 3 * COIN not in {c["value"] for c in w.wallet_coins()}
    pool.txs[bytes(pay.txid)] = pay          # re-accepted by the mempool
    w.on_mempool_tx_added(pay)
    assert (3 * COIN, 0) in {(c["value"], c["depth"]) for c in w.wallet_coins()}

    # reconsiderblock 102: the chain has it again.
    chain.blocks[102] = block102
    chain.tip = 102
    rpc._reorg_mempool_refill(chain, [], "test")
    coins = {(c["height"], c["value"]) for c in w.wallet_coins()}
    assert (102, 3 * COIN) in coins and (102, 50 * COIN) in coins
    assert 0 not in {c["height"] for c in w.wallet_coins()}   # no unconfirmed copy


def test_mempool_replay_on_attach_and_trust_needs_the_mempool(tmp_path):
    """Core requestMempoolTransactions: txs already in the mempool when the
    wallet is hooked up (mempool.dat at startup, loadwallet) reach the store.
    Core CachedTxIsTrusted: an unconfirmed tx counts as trusted only while it
    is in the mempool; once gone its change is untrusted_pending."""
    from ouroboros.wallet import WalletManager

    w, chain, _addr, spk = _funded_wallet(tmp_path)
    mature = _coinbase(1, spk)
    send = _spend(mature.txid, 0, [(FOREIGN_SPK, 10 * COIN), (spk, 39 * COIN)])
    pool = _Pool()
    pool.add(send)                     # in the pool before the wallet hooks up

    mgr = WalletManager(str(tmp_path), "regtest")
    mgr._wallets["w"] = w
    mgr.set_mempool(pool)
    bal = w.get_balances_sat()
    assert bal["trusted"] == 39 * COIN

    del pool.txs[bytes(send.txid)]     # gone without a removal event
    bal = w.get_balances_sat()
    assert bal["trusted"] == 0
    assert bal["untrusted_pending"] == 39 * COIN


def test_rpc_accept_block_scans_the_wallet_before_evicting_block_txs(tmp_path):
    """submitblock / generate* go through ``rpc.accept_block``.  The mempool
    eviction of the block's txs fires the wallet's removal hook, which drops
    a tx's unconfirmed rows (and a mempool child's spend of its outputs)
    unless the block has already confirmed them; so the wallet must see the
    block first, as on the P2P path.  Drives the REAL accept_block."""
    from ouroboros.rpc import accept_block
    from tests import test_assumevalid_submitblock_path as sb

    order: list[str] = []

    class _RecPool:
        def __len__(self):
            return 1

        def remove_block_transactions(self, block):
            order.append("mempool-evict")

    class _RecWallet:
        name = "rec"

        def scan_block_connect(self, block, height):
            order.append("wallet-scan")

    db = sb._make_db()
    node = sb._make_node(db, assumevalid_zero=False)
    node.mempool = _RecPool()
    node.wallet = _RecWallet()
    raw = sb._build_block_bytes(flip_signature_byte=False)
    patches = sb._patched_gates(node.validator)
    for p in patches:
        p.start()
    try:
        asyncio.run(accept_block(db, node, raw, sb.BELOW_CHECKPOINT_HEIGHT))
    finally:
        for p in patches:
            p.stop()
    assert order == ["wallet-scan", "mempool-evict"]


def test_reads_raise_warmup_while_migration_is_pending(tmp_path):
    """A pre-store wallet whose store is still being built (startup
    background walk, failed walk awaiting retry, locked wallet) must not read
    as an empty wallet: balance and listunspent answer RPC_IN_WARMUP (-28)."""
    import pytest

    from ouroboros.address import address_to_script_pubkey
    from ouroboros.wallet import WalletManager

    w = _wallet(tmp_path)
    w.init_hd(seed=bytes(range(32)))
    addr = asyncio.run(w.generate_new_address(address_type="bech32"))
    w._best_scanned_height = 1
    w._save()
    getattr(w, "close_store", lambda: None)()
    p = tmp_path / "wallets" / "w" / "txstore.sqlite"
    if p.exists():
        p.unlink()

    spk = address_to_script_pubkey(addr, "regtest")
    chain = FakeChain()
    tx = _coinbase(1, spk, value=5 * COIN)
    chain.utxos[(tx.txid, 0)] = {"value": 5 * COIN, "script_pubkey": spk,
                                 "height": 1, "is_coinbase": False}
    chain.blocks[1] = SimpleNamespace(hash=_h("blk", 1), timestamp=0, transactions=[tx])
    chain.tip = 1
    mgr = WalletManager(str(tmp_path), "regtest")
    mgr.set_database(chain)
    mgr._update_load_on_startup("w", True)
    mgr.load_startup_wallets()
    wallet = mgr.get_wallet("w")
    rpc = _rpc(wallet, chain)

    with pytest.raises(Exception) as ei:
        asyncio.run(rpc.rpc_getbalance())
    assert getattr(ei.value, "code", None) == -28
    with pytest.raises(Exception) as ei:
        asyncio.run(rpc.rpc_listunspent())
    assert getattr(ei.value, "code", None) == -28

    mgr.reconcile_on_load()
    assert asyncio.run(rpc.rpc_getbalance()) == 5.0
