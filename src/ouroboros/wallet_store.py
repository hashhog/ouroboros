"""Persistent wallet transaction / output store (Core ``CWallet::mapWallet``).

Before this store the wallet had no record of its own coins.  Balance,
listunspent and coin selection asked the chainstate for every coin paying
each wallet address (``Database.list_unspent_by_address``), which walks the
whole UTXO set once per address per call, and the per-transaction history
lived only in memory, so it was gone after a restart.

This module keeps, per wallet, in one SQLite file next to ``wallet.dat``:

``coins``
    Every output paying a wallet script: value, script, address, the height
    of the block that created it (``-1`` while its transaction is only in the
    mempool), whether it is a coinbase output, and who spent it
    (``spent_txid`` / ``spent_height``, ``-1`` for a mempool spend).  Core's
    equivalent is the ``CWalletTx`` set plus the spent-ness test of
    ``CWallet::IsSpent`` (wallet/wallet.cpp).
``txs``
    One record per wallet transaction, keyed by display txid, with the
    history record the RPC layer formats (credit/debit/fee/details).
``blocks``
    The hash of every block the wallet has processed, by height.  The store
    is a block locator: when a block arrives at a height that already holds a
    different hash, the old branch is unwound first, so a reorg that never
    surfaced per-height disconnects (the atomic Rust disconnect path) cannot
    leave stale coins behind.
``meta``
    Schema version and migration state.

The store is updated on block connect and disconnect
(``Wallet.scan_block_connect`` / ``scan_block_disconnect``) and on mempool add
and remove (``WalletManager`` registers the mempool callbacks).  All writes
of one event are a single SQLite transaction.

Reference: bitcoin-core/src/wallet/wallet.h ``mapWallet``;
wallet/wallet.cpp ``AddToWalletIfInvolvingMe``, ``blockConnected``,
``blockDisconnected``, ``transactionAddedToMempool``,
``transactionRemovedFromMempool``; wallet/receive.cpp ``GetBalance``;
wallet/spend.cpp ``AvailableCoins``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# Core consensus/consensus.h COINBASE_MATURITY.
COINBASE_MATURITY = 100

# Height marker for an output (or a spend) that is only in the mempool.
UNCONFIRMED = -1

SCHEMA_VERSION = 1


def coin_depth(height: int, tip_height: int) -> int:
    """Confirmations of a coin created at *height* (0 when unconfirmed)."""
    if height is None or int(height) <= 0:
        return 0
    return max(0, int(tip_height) - int(height) + 1)


def is_immature_coinbase(is_coinbase: bool, height: int, tip_height: int) -> bool:
    """Core ``CWallet::IsTxImmatureCoinBase`` / ``GetTxBlocksToMaturity``.

    A coinbase output is spendable once ``GetBlocksToMaturity`` is 0, i.e.
    ``max(0, COINBASE_MATURITY + 1 - depth) == 0`` (wallet/wallet.cpp).
    The one maturity rule for every wallet read path: balances,
    listunspent and coin selection.
    """
    if not is_coinbase:
        return False
    return coin_depth(height, tip_height) < COINBASE_MATURITY + 1


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash   TEXT
);
CREATE TABLE IF NOT EXISTS txs (
    txid    TEXT PRIMARY KEY,
    height  INTEGER NOT NULL,
    record  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS txs_height ON txs(height);
CREATE TABLE IF NOT EXISTS coins (
    txid         TEXT NOT NULL,
    vout         INTEGER NOT NULL,
    value        INTEGER NOT NULL,
    script       BLOB NOT NULL,
    address      TEXT NOT NULL,
    height       INTEGER NOT NULL,
    is_coinbase  INTEGER NOT NULL,
    trusted      INTEGER NOT NULL DEFAULT 0,
    spent_txid   TEXT,
    spent_height INTEGER,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX IF NOT EXISTS coins_height ON coins(height);
CREATE INDEX IF NOT EXISTS coins_spent ON coins(spent_txid);
"""


class WalletTxStore:
    """SQLite-backed wallet coin and transaction store (one per wallet)."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.created = not self.path.exists()
        if self.created:
            # Owner-only, like wallet.dat (audit H6): create the file 0600
            # before SQLite opens it.
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            if self.get_meta("schema_version") is None:
                self.set_meta("schema_version", str(SCHEMA_VERSION))

    # --- plumbing ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def _tx(self):
        """Context manager: one BEGIN IMMEDIATE ... COMMIT transaction."""
        store = self

        class _Txn:
            def __enter__(self_inner):
                store._lock.acquire()
                store._conn.execute("BEGIN IMMEDIATE")
                return store._conn

            def __exit__(self_inner, exc_type, exc, tb):
                try:
                    if exc_type is None:
                        store._conn.execute("COMMIT")
                    else:
                        store._conn.execute("ROLLBACK")
                finally:
                    store._lock.release()
                return False

        return _Txn()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else row[0]

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # --- writes -----------------------------------------------------------

    @staticmethod
    def _upsert_coin(conn, txid: str, coin: dict, height: int, trusted: bool) -> None:
        # Re-processing a block (rescan replay, mempool tx then its block)
        # refreshes the creation fields only; who spent the coin is kept.
        conn.execute(
            "INSERT INTO coins(txid, vout, value, script, address, height, "
            "is_coinbase, trusted) VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(txid, vout) DO UPDATE SET value = excluded.value, "
            "script = excluded.script, address = excluded.address, "
            "height = excluded.height, is_coinbase = excluded.is_coinbase, "
            "trusted = excluded.trusted",
            (
                txid, int(coin["vout"]), int(coin["value"]),
                bytes(coin["script_pubkey"]), coin.get("address") or "",
                int(height), 1 if coin.get("is_coinbase") else 0,
                1 if trusted else 0,
            ),
        )

    def connect_block(
        self,
        height: int,
        block_hash: str | None,
        records: Iterable[dict],
        coins: Iterable[tuple[str, dict]],
        spends: Iterable[tuple[str, int, str]],
    ) -> None:
        """Record one connected block.

        *records*: wallet tx history records (``record["txid"]`` keyed).
        *coins*: ``(txid, coin)`` for each output paying a wallet script.
        *spends*: ``(prev_txid, prev_vout, spender_txid)`` for each input of
        the block that spends a wallet coin.
        """
        height = int(height)
        with self._tx() as conn:
            for rec in records:
                conn.execute(
                    "INSERT INTO txs(txid, height, record) VALUES(?, ?, ?) "
                    "ON CONFLICT(txid) DO UPDATE SET height = excluded.height, "
                    "record = excluded.record",
                    (rec["txid"], height, json.dumps(rec)),
                )
            for txid, coin in coins:
                self._upsert_coin(conn, txid, coin, height, True)
            for prev_txid, prev_vout, spender in spends:
                conn.execute(
                    "UPDATE coins SET spent_txid = ?, spent_height = ? "
                    "WHERE txid = ? AND vout = ?",
                    (spender, height, prev_txid, int(prev_vout)),
                )
            conn.execute(
                "INSERT INTO blocks(height, hash) VALUES(?, ?) "
                "ON CONFLICT(height) DO UPDATE SET hash = excluded.hash",
                (height, block_hash),
            )

    def disconnect_block(self, height: int) -> None:
        """Undo :meth:`connect_block` for *height* (Core blockDisconnected).

        Outputs created at that height are removed and spends made at that
        height are undone.  A transaction the mempool takes back is
        re-recorded through :meth:`add_unconfirmed`; rows it already rewrote
        to ``UNCONFIRMED`` are left alone.
        """
        height = int(height)
        with self._tx() as conn:
            conn.execute("DELETE FROM coins WHERE height = ?", (height,))
            conn.execute(
                "UPDATE coins SET spent_txid = NULL, spent_height = NULL "
                "WHERE spent_height = ?",
                (height,),
            )
            conn.execute("DELETE FROM txs WHERE height = ?", (height,))
            conn.execute("DELETE FROM blocks WHERE height = ?", (height,))

    def add_unconfirmed(
        self,
        txid: str,
        record: dict | None,
        coins: Iterable[tuple[str, dict]],
        spends: Iterable[tuple[str, int, str]],
        trusted: bool,
    ) -> None:
        """Record a wallet transaction that entered the mempool."""
        with self._tx() as conn:
            row = conn.execute(
                "SELECT height FROM txs WHERE txid = ?", (txid,)
            ).fetchone()
            if row is not None and int(row[0]) != UNCONFIRMED:
                return  # already confirmed; the block is authoritative
            if record is not None:
                conn.execute(
                    "INSERT INTO txs(txid, height, record) VALUES(?, ?, ?) "
                    "ON CONFLICT(txid) DO UPDATE SET record = excluded.record",
                    (txid, UNCONFIRMED, json.dumps(record)),
                )
            for ctxid, coin in coins:
                existing = conn.execute(
                    "SELECT height FROM coins WHERE txid = ? AND vout = ?",
                    (ctxid, int(coin["vout"])),
                ).fetchone()
                if existing is not None and int(existing[0]) != UNCONFIRMED:
                    continue
                self._upsert_coin(conn, ctxid, coin, UNCONFIRMED, trusted)
            for prev_txid, prev_vout, spender in spends:
                conn.execute(
                    "UPDATE coins SET spent_txid = ?, spent_height = ? "
                    "WHERE txid = ? AND vout = ? AND spent_txid IS NULL",
                    (spender, UNCONFIRMED, prev_txid, int(prev_vout)),
                )

    def remove_unconfirmed(self, txid: str) -> None:
        """Forget a mempool transaction that left the pool unconfirmed.

        Rows a block already confirmed (height != UNCONFIRMED) stay, so the
        mempool's own block-inclusion removal is a no-op here.
        """
        with self._tx() as conn:
            conn.execute(
                "DELETE FROM coins WHERE txid = ? AND height = ?",
                (txid, UNCONFIRMED),
            )
            conn.execute(
                "UPDATE coins SET spent_txid = NULL, spent_height = NULL "
                "WHERE spent_txid = ? AND spent_height = ?",
                (txid, UNCONFIRMED),
            )
            conn.execute(
                "DELETE FROM txs WHERE txid = ? AND height = ?",
                (txid, UNCONFIRMED),
            )

    def seed_coins(self, coins: Iterable[tuple[str, dict, int]]) -> int:
        """Bulk-insert confirmed, unspent coins (migration from the UTXO set).

        *coins*: ``(txid, coin, height)``.  Returns the number inserted.
        """
        n = 0
        with self._tx() as conn:
            for txid, coin, height in coins:
                self._upsert_coin(conn, txid, coin, int(height), True)
                n += 1
        return n

    # --- reads ------------------------------------------------------------

    def block_hash_at(self, height: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT hash FROM blocks WHERE height = ?", (int(height),)
            ).fetchone()
        return None if row is None else row[0]

    def has_block(self, height: int) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM blocks WHERE height = ?", (int(height),)
            ).fetchone()
        return row is not None

    def block_heights_from(self, height: int) -> list[int]:
        """Processed block heights >= *height*, highest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT height FROM blocks WHERE height >= ? ORDER BY height DESC",
                (int(height),),
            ).fetchall()
        return [int(r[0]) for r in rows]

    def best_height(self) -> int | None:
        with self._lock:
            row = self._conn.execute("SELECT MAX(height) FROM blocks").fetchone()
        return None if row is None or row[0] is None else int(row[0])

    @staticmethod
    def _coin_row(row) -> dict[str, Any]:
        (txid, vout, value, script, address, height, is_coinbase, trusted,
         spent_txid, spent_height) = row
        return {
            "txid": txid,
            "vout": int(vout),
            "value": int(value),
            "script_pubkey": bytes(script),
            "address": address,
            "height": int(height),
            "is_coinbase": bool(is_coinbase),
            "trusted": bool(trusted),
            "spent_txid": spent_txid,
            "spent_height": None if spent_height is None else int(spent_height),
        }

    _COIN_COLS = (
        "txid, vout, value, script, address, height, is_coinbase, trusted, "
        "spent_txid, spent_height"
    )

    def unspent_coins(self) -> list[dict[str, Any]]:
        """Wallet coins not spent by a block or by a mempool transaction."""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {self._COIN_COLS} FROM coins WHERE spent_txid IS NULL "
                "ORDER BY height, txid, vout"
            ).fetchall()
        return [self._coin_row(r) for r in rows]

    def all_coins(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {self._COIN_COLS} FROM coins ORDER BY height, txid, vout"
            ).fetchall()
        return [self._coin_row(r) for r in rows]

    def get_coin(self, txid: str, vout: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._COIN_COLS} FROM coins WHERE txid = ? AND vout = ?",
                (txid, int(vout)),
            ).fetchone()
        return None if row is None else self._coin_row(row)

    def tx_records(self, *, confirmed_only: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT record FROM txs"
        if confirmed_only:
            sql += f" WHERE height != {UNCONFIRMED}"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [json.loads(r[0]) for r in rows]
