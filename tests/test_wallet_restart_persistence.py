"""Regression tests for ouroboros wallet restart-persistence.

These pin the four restart-persistence fixes (audit 2026-06-06):

  1. Durable atomic save: ``Wallet._save`` writes via temp + fsync +
     ``os.replace`` and never leaves a ``.tmp`` sidecar behind.
  2. Fault-tolerant load: a missing / empty / partial / corrupt wallet file
     never crashes startup — it is quarantined and a fresh wallet is created.
  3. Save-on-mutation survives a simulated restart (reopen from disk).
  4. The live block-connect path feeds the wallet: ``BlockSync`` calls
     ``wallet_notifier.notify_block_connected`` and ``WalletManager`` fans the
     notification out to loaded wallets + reconciles on load.

Each test is written to FAIL against the pre-fix code (proven teeth) — the
fault-tolerant-load tests raise ``json.JSONDecodeError`` before the fix; the
wiring tests assert on a hook that did not exist before the fix.

Reference: Bitcoin Core wallet/wallet.cpp (durable DB flush, AttachChain,
CWallet::blockConnected / blockDisconnected). Mirrors ouroboros's own correct
durable-write pattern in snapshot.py:1574-1584.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ouroboros.wallet import Wallet, WalletManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_wallet(tmp: Path, name: str = "w") -> Wallet:
    """Create an HD wallet in its own directory under *tmp*."""
    wdir = tmp / "wallets" / name
    wdir.mkdir(parents=True, exist_ok=True)
    w = Wallet(
        data_dir=str(tmp), network="regtest", name=name, wallet_dir=str(wdir)
    )
    w.init_hd(seed=os.urandom(32))
    return w


# ---------------------------------------------------------------------------
# 1. Durable atomic save
# ---------------------------------------------------------------------------


def test_save_uses_fsync_and_atomic_replace(monkeypatch):
    """_save must flush + fsync the fd before the atomic rename.

    Teeth: pre-fix _save did ``json.dump`` then ``tmp.rename`` with no fsync.
    We monkeypatch os.fsync to record invocation and assert it ran.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        w = _make_wallet(tmp)

        fsync_calls = []
        real_fsync = os.fsync
        monkeypatch.setattr(
            os, "fsync", lambda fd: (fsync_calls.append(fd), real_fsync(fd))[1]
        )

        w._save()

        assert fsync_calls, "_save did not fsync the wallet fd before rename"
        # The live wallet exists and parses; no temp sidecar left behind.
        assert w.wallet_path.exists()
        json.loads(w.wallet_path.read_text())
        leftover = list(w.wallet_path.parent.glob("*.tmp"))
        assert not leftover, f"stale temp file(s) left: {leftover}"


def test_failed_save_leaves_original_intact_and_no_temp(monkeypatch):
    """A crash mid-save must not corrupt the live wallet nor leak a temp."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        w = _make_wallet(tmp)
        original = w.wallet_path.read_text()

        # Force the rename to blow up after the temp is written + fsynced.
        def boom(src, dst):
            raise OSError("simulated power loss during rename")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            w._save()

        # Live wallet untouched; no stale temp.
        assert w.wallet_path.read_text() == original
        assert not list(w.wallet_path.parent.glob("*.tmp"))


# ---------------------------------------------------------------------------
# 2. Fault-tolerant load (never crash startup)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_content",
    [
        "",  # zero-length (classic torn-write after crash)
        "{",  # truncated / partial JSON
        '{"version": 1, "network": "regtest", "keys": [],',  # partial
        "not json at all",  # garbage
        "[]",  # valid JSON but not an object
        '{"version":1,"hd":{"seed_hex":"zz"}}',  # parses, bad hex field
    ],
)
def test_corrupt_wallet_does_not_crash_startup(bad_content):
    """Loading a damaged wallet.dat must recover, not raise.

    Teeth: pre-fix _load_or_create called ``json.load`` (and bytes.fromhex)
    unguarded — every one of these inputs raised and crashed node startup.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        wdir = tmp / "wallets" / "w"
        wdir.mkdir(parents=True, exist_ok=True)
        wallet_file = wdir / "wallet.dat"
        wallet_file.write_text(bad_content)

        # Must not raise.
        w = Wallet(
            data_dir=str(tmp), network="regtest", name="w",
            wallet_dir=str(wdir),
        )

        # A fresh, valid wallet now exists on disk.
        assert wallet_file.exists()
        reparsed = json.loads(wallet_file.read_text())
        assert isinstance(reparsed, dict)
        # The corrupt bytes were quarantined, not destroyed.
        sidecars = list(wdir.glob("wallet.dat.corrupt-*"))
        assert sidecars, "corrupt wallet was not quarantined to a sidecar"
        assert sidecars[0].read_text() == bad_content
        # The recovered wallet is usable.
        assert w.keys == []


def test_missing_wallet_file_creates_fresh():
    """A nonexistent wallet file is created fresh (baseline, must not regress)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        wdir = tmp / "wallets" / "w"
        w = Wallet(
            data_dir=str(tmp), network="regtest", name="w",
            wallet_dir=str(wdir),
        )
        assert w.wallet_path.exists()
        json.loads(w.wallet_path.read_text())


# ---------------------------------------------------------------------------
# 3. Save-on-mutation survives restart
# ---------------------------------------------------------------------------


def test_keypool_advance_survives_restart():
    """A keypool refill is durably persisted and reloaded on 'restart'."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        w = _make_wallet(tmp)
        before = w._key_pool.to_dict()
        # Mutate + persist (keypoolrefill calls _save).
        w.keypoolrefill(w.get_keypool_size() + 50)
        after = w._key_pool.to_dict()
        assert after != before

        # Simulate restart: brand-new Wallet over the same on-disk file.
        w2 = Wallet(
            data_dir=str(tmp), network="regtest", name="w",
            wallet_dir=str(w.wallet_dir),
        )
        assert w2._key_pool is not None
        assert w2._key_pool.to_dict() == after
        # HD seed survived too.
        assert w2._hd_seed == w._hd_seed


def test_hd_seed_and_locks_round_trip():
    """HD seed + persistent lockunspent entries survive a restart."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        w = _make_wallet(tmp)
        w._locked_coins[("ab" * 32, 0)] = True  # persistent lock
        w._save()

        w2 = Wallet(
            data_dir=str(tmp), network="regtest", name="w",
            wallet_dir=str(w.wallet_dir),
        )
        assert w2._hd_seed == w._hd_seed
        assert ("ab" * 32, 0) in w2._locked_coins


# ---------------------------------------------------------------------------
# 4. Live block-connect path feeds the wallet
# ---------------------------------------------------------------------------


def test_block_sync_accepts_wallet_notifier():
    """BlockSync must accept and store a wallet_notifier (the new wire).

    Teeth: pre-fix BlockSync.__init__ had no wallet_notifier param.
    """
    from ouroboros.block_sync import BlockSync

    notifier = object()
    bs = BlockSync(
        db=SimpleNamespace(),
        validator=SimpleNamespace(),
        peer_manager=SimpleNamespace(),
        wallet_notifier=notifier,
    )
    assert bs.wallet_notifier is notifier


def test_manager_notify_block_connected_fans_out():
    """WalletManager.notify_block_connected calls each loaded wallet's scan."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        mgr.create_wallet("a")
        mgr.create_wallet("b")

        seen = {}

        for name, w in mgr._wallets.items():
            calls = []
            seen[name] = calls
            w.scan_block_connect = (
                lambda block, height, _c=calls: _c.append((block, height))
            )

        block = object()
        mgr.notify_block_connected(block, 7)

        for name, calls in seen.items():
            assert calls == [(block, 7)], f"wallet '{name}' not notified"


def test_manager_notify_block_disconnected_fans_out():
    """WalletManager.notify_block_disconnected calls each wallet's disconnect."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        mgr.create_wallet("a")

        calls = []
        w = mgr.get_default_wallet()
        w.scan_block_disconnect = lambda height: calls.append(height)

        mgr.notify_block_disconnected(99)
        assert calls == [99]


def test_manager_notify_swallows_per_wallet_errors():
    """A faulting wallet must not stall the connect loop for others."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        mgr.create_wallet("good")
        mgr.create_wallet("bad")

        good_calls = []
        for name, w in mgr._wallets.items():
            if name == "bad":
                w.scan_block_connect = (
                    lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
                )
            else:
                w.scan_block_connect = (
                    lambda block, height: good_calls.append(height)
                )

        # Must not raise despite the bad wallet.
        mgr.notify_block_connected(object(), 3)
        assert good_calls == [3]


def test_reconcile_on_load_rescans_loaded_wallets():
    """reconcile_on_load rescans each loaded wallet above its scan marker.

    Teeth: pre-fix there was no startup reconcile at all, so the in-memory tx
    history started empty after every restart. Post GEN-OURO boot-starvation
    fix the rescan covers only the gap above the persisted scan marker —
    never the whole chain (Core CWallet::AttachChain locator parity).
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        # Attach a stub db so reconcile_on_load does not early-return.
        mgr.set_database(SimpleNamespace(get_best_block=lambda: (b"\x00" * 32, 0)))
        mgr.create_wallet("a")

        rescans = []
        w = mgr.get_default_wallet()
        w._best_scanned_height = 5
        w.rescan_chain = (
            lambda start=0, stop=None: rescans.append((start, stop)) or
            {"start_height": 0, "stop_height": 0}
        )

        mgr.reconcile_on_load()
        assert rescans == [(6, None)]


def test_reconcile_on_load_no_marker_adopts_birthday():
    """A wallet with no scan marker adopts the tip as its birthday.

    Core AttachChain parity: a fresh wallet's birthday is its creation tip,
    so it never auto-rescans history (an explicit rescanblockchain is needed
    for restored wallets). Pinning this guards the GEN-OURO boot-starvation
    fix — an unconditional rescan_chain(0, None) at every boot.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        mgr.set_database(SimpleNamespace(get_best_block=lambda: (b"\x00" * 32, 7)))
        mgr.create_wallet("a")

        rescans = []
        w = mgr.get_default_wallet()
        w.rescan_chain = (
            lambda start=0, stop=None: rescans.append((start, stop)) or
            {"start_height": 0, "stop_height": 0}
        )

        mgr.reconcile_on_load()
        assert rescans == []
        assert w._best_scanned_height == 7


def test_reconcile_on_load_noop_without_db():
    """reconcile_on_load is a safe no-op when no database is attached."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        mgr = WalletManager(str(tmp), network="regtest")
        mgr.create_wallet("a")
        # Should not raise and should not touch the wallet.
        mgr.reconcile_on_load()


def test_end_to_end_scan_then_disconnect_round_trip():
    """A connected block credits the wallet; disconnect rolls it back.

    Exercises the real scan_block_connect / scan_block_disconnect path that the
    new live wiring drives, using stub tx/block objects matching the duck-typed
    shape scan_block_connect reads.
    """
    import asyncio

    from ouroboros.address import address_to_script_pubkey

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        w = _make_wallet(tmp)

        # Register an owned receiving address (also appends to self.keys, which
        # is what _owned_script_set iterates over).
        addr = asyncio.run(w.generate_new_address(address_type="bech32"))
        assert w.keys, "generate_new_address did not register a key"
        spk = address_to_script_pubkey(addr, w.network)

        out = SimpleNamespace(value=500_000, script_pubkey=spk)
        tx = SimpleNamespace(
            inputs=[],
            outputs=[out],
            is_coinbase=False,
            get_txid=lambda: b"\x11" * 32,
            serialize_with_witness=lambda: b"\xde\xad\xbe\xef",
        )
        block = SimpleNamespace(
            hash=b"\x22" * 32, timestamp=1_700_000_000, transactions=[tx]
        )

        w.scan_block_connect(block, height=10)
        assert ("11" * 32) in w._tx_history
        rec = w._tx_history["11" * 32]
        assert rec["credit"] == 500_000

        w.scan_block_disconnect(10)
        assert ("11" * 32) not in w._tx_history
