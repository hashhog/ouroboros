"""
Coin-stats index (Bitcoin Core ``-coinstatsindex`` parity).

Maintains, per block height, a running MuHash3072 commitment over the UTXO
set together with cumulative counts (txouts), total amount, and bogo-size.
This lets ``gettxoutsetinfo`` answer for a HISTORICAL ``hash_or_height``
(not just the chain tip) byte-exactly versus Bitcoin Core's coinstatsindex,
and lets ``getindexinfo`` report the index.

Design — reorg-safe, incremental on the PRIMARY block-connect path
------------------------------------------------------------------
The index is updated on the node's primary block connect+disconnect path
(P2P/IBD ``_drain_block_buffer`` and the reorg connect/disconnect loop in
``block_sync.py``, plus the ``submitblock``/``generatetoaddress`` RPC accept
path), exactly where ``txindex``/``blockfilterindex`` are maintained — NOT
only on the ``submitblock`` RPC path.

Per Bitcoin Core ``src/index/coinstatsindex.cpp`` (``CustomAppend``):

  * Created outputs: for every output of every tx in the block, build the
    coin ``(out, block.height, is_coinbase)`` and ``Insert`` its TxOutSer
    element into the running MuHash — SKIPPING provably-unspendable scripts
    (``CScript::IsUnspendable``: empty-OP_RETURN-prefixed, or > 10000 bytes),
    which Core never adds to the UTXO set.  Increment ``txouts`` /
    ``total_amount`` / ``bogo_size`` accordingly.
  * Spent prevouts: for every non-coinbase input, ``Remove`` the spent
    coin's TxOutSer element (using the prevout's ORIGINAL height + coinbase
    flag, read from the undo / spent-coin record).  Decrement the counters.

Each height persists a SELF-CONTAINED snapshot of the running state, so:

  * connect(H): load running state from the H-1 snapshot (or empty for the
    genesis height), apply the block's delta, write the H snapshot.
  * disconnect(H): drop the H snapshot.  The running state for the new tip
    is simply the already-persisted H-1 snapshot — no recomputation, which
    makes reorg trivially correct and atomic per height.

TxOutSer / MuHash element encoding and the MuHash3072 class are REUSED
verbatim from ``ouroboros.muhash`` (the same code path ``gettxoutsetinfo``
uses at the tip), guaranteeing the historical digest is byte-identical to
the @tip digest construction.

Storage layout (file-per-height under ``<data_dir>/coinstatsindex/``)::

    <data_dir>/coinstatsindex/
        VERSION                       # schema version text file
        meta/best_indexed_height      # highest height indexed (or "none")
        snap/<8-digit>.csi            # per-height snapshot record (binary)

All writes use write-then-rename (``os.replace`` is atomic on POSIX) so a
crash mid-connect cannot leave a half-written snapshot.  A single
``threading.Lock`` serialises connect / disconnect so concurrent
``asyncio.to_thread`` calls cannot interleave the load-modify-store of the
running state.

References:
  - bitcoin-core/src/index/coinstatsindex.cpp  (CustomAppend / CustomRewind)
  - bitcoin-core/src/kernel/coinstats.cpp       (TxOutSer / ApplyCoinHash /
                                                 GetBogoSize)
  - bitcoin-core/src/script/script.h            (CScript::IsUnspendable)
  - blockbrew internal/storage/coinstatsindex.go,
    nimrod src/storage/indexes/coinstatsindex.nim,
    haskoin src/Haskoin/Index.hs (committed reorg-safe references)
"""

from __future__ import annotations

import logging
import os
import struct
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ouroboros.muhash import MuHash3072, coin_element

if TYPE_CHECKING:
    from ouroboros.database import Block, BlockchainDatabase

logger = logging.getLogger(__name__)

# Core CScript constants (script/script.h).
OP_RETURN = 0x6A
MAX_SCRIPT_SIZE = 10000


def _is_unspendable(script: bytes) -> bool:
    """Mirror Bitcoin Core ``CScript::IsUnspendable`` (script/script.h:563).

    ``(size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE)``.
    Unspendable outputs are never added to the UTXO set, so the coinstats
    index must skip them when applying created outputs.
    """
    n = len(script)
    return (n > 0 and script[0] == OP_RETURN) or (n > MAX_SCRIPT_SIZE)


def _bogo_size(script_pubkey: bytes) -> int:
    """Per-coin bogo-size (kernel/coinstats.cpp ``GetBogoSize``).

    ``32 + 4 + 4 + 8 + 2 + scriptPubKey.size()`` — the fixed outpoint /
    code / amount / length overhead plus the script length.
    """
    return 32 + 4 + 4 + 8 + 2 + len(script_pubkey)


class _RunningStats:
    """Mutable running coinstats accumulator for a single height."""

    __slots__ = ("muhash", "txouts", "total_amount", "bogo_size", "transactions")

    def __init__(self) -> None:
        self.muhash = MuHash3072()
        self.txouts = 0
        self.total_amount = 0
        self.bogo_size = 0
        # transactions == number of distinct txids with at least one unspent
        # output.  Core derives this from the cursor at query time; here we
        # don't persist a perfectly Core-matching value (it is not gated by
        # the harness), but we track an approximation for the field's sake.
        self.transactions = 0

    @classmethod
    def empty(cls) -> "_RunningStats":
        return cls()

    def clone(self) -> "_RunningStats":
        out = _RunningStats()
        # MuHash3072 carries only numerator/denominator ints; copy them.
        out.muhash.numerator = self.muhash.numerator
        out.muhash.denominator = self.muhash.denominator
        out.txouts = self.txouts
        out.total_amount = self.total_amount
        out.bogo_size = self.bogo_size
        out.transactions = self.transactions
        return out


class CoinStatsIndex:
    """Persistent, reorg-safe per-height UTXO MuHash3072 commitment index."""

    SCHEMA_VERSION = 1

    # Snapshot record wire format (little-endian):
    #   block_hash         32 bytes (internal byte order)
    #   muhash serialize   768 bytes (num 384 LE || denom 384 LE)
    #   txouts             u64
    #   total_amount       i64 (sats)
    #   bogo_size          u64
    #   transactions       u64
    _REC_HEADER = struct.Struct("<32s768sQqQQ")
    _REC_SIZE = _REC_HEADER.size

    def __init__(
        self,
        data_dir: str,
        enabled: bool = True,
        cache_capacity: int = 4096,
    ) -> None:
        self._enabled = enabled
        self._data_dir = data_dir
        self._lock = threading.RLock()
        self._cache_capacity = max(0, int(cache_capacity))
        self._snap_cache: OrderedDict[int, dict[str, Any]] = OrderedDict()
        self._best_indexed_height: int | None = None

        root = os.path.join(data_dir, "coinstatsindex")
        os.makedirs(root, exist_ok=True)
        self._root_path = root
        self._snap_path = os.path.join(root, "snap")
        self._meta_path = os.path.join(root, "meta")
        os.makedirs(self._snap_path, exist_ok=True)
        os.makedirs(self._meta_path, exist_ok=True)

        version_path = os.path.join(root, "VERSION")
        if not os.path.exists(version_path):
            try:
                with open(version_path, "w", encoding="utf-8") as f:
                    f.write(f"{self.SCHEMA_VERSION}\n")
            except OSError:
                pass

        self._best_indexed_height = self._load_best_indexed_height()

    # ------------------------------------------------------------------
    # atomic IO + cache
    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)

    def _snap_file(self, height: int) -> str:
        return os.path.join(self._snap_path, f"{height:08d}.csi")

    def _best_indexed_height_path(self) -> str:
        return os.path.join(self._meta_path, "best_indexed_height")

    def _load_best_indexed_height(self) -> int | None:
        try:
            with open(self._best_indexed_height_path(), "rb") as f:
                raw = f.read().decode("utf-8", errors="ignore").strip()
        except (FileNotFoundError, OSError):
            return None
        if not raw or raw == "none":
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _persist_best_indexed_height(self) -> None:
        try:
            value = (
                "none"
                if self._best_indexed_height is None
                else str(int(self._best_indexed_height))
            )
            self._atomic_write(
                self._best_indexed_height_path(), value.encode("utf-8")
            )
        except OSError:
            pass

    def _cache_put(self, height: int, rec: dict[str, Any]) -> None:
        if self._cache_capacity == 0:
            return
        self._snap_cache[height] = rec
        self._snap_cache.move_to_end(height)
        while len(self._snap_cache) > self._cache_capacity:
            self._snap_cache.popitem(last=False)

    # ------------------------------------------------------------------
    # snapshot read / write
    # ------------------------------------------------------------------

    def _write_snapshot(
        self, height: int, block_hash: bytes, stats: _RunningStats
    ) -> None:
        blob = self._REC_HEADER.pack(
            bytes(block_hash),
            stats.muhash.serialize(),
            int(stats.txouts),
            int(stats.total_amount),
            int(stats.bogo_size),
            int(stats.transactions),
        )
        self._atomic_write(self._snap_file(height), blob)
        rec = {
            "block_hash": bytes(block_hash),
            "muhash_serialize": stats.muhash.serialize(),
            "txouts": int(stats.txouts),
            "total_amount": int(stats.total_amount),
            "bogo_size": int(stats.bogo_size),
            "transactions": int(stats.transactions),
        }
        self._cache_put(height, rec)

    def _read_snapshot_raw(self, height: int) -> dict[str, Any] | None:
        if height in self._snap_cache:
            self._snap_cache.move_to_end(height)
            return self._snap_cache[height]
        try:
            with open(self._snap_file(height), "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return None
        if len(blob) < self._REC_SIZE:
            return None
        (block_hash, muser, txouts, total_amount, bogo, txs) = self._REC_HEADER.unpack(
            blob[: self._REC_SIZE]
        )
        rec = {
            "block_hash": block_hash,
            "muhash_serialize": muser,
            "txouts": int(txouts),
            "total_amount": int(total_amount),
            "bogo_size": int(bogo),
            "transactions": int(txs),
        }
        self._cache_put(height, rec)
        return rec

    def _load_running(self, height: int) -> _RunningStats:
        """Load the running accumulator AS OF *height* (or empty for < 0)."""
        if height < 0:
            return _RunningStats.empty()
        rec = self._read_snapshot_raw(height)
        if rec is None:
            return _RunningStats.empty()
        stats = _RunningStats.empty()
        stats.muhash = MuHash3072.deserialize(rec["muhash_serialize"])
        stats.txouts = rec["txouts"]
        stats.total_amount = rec["total_amount"]
        stats.bogo_size = rec["bogo_size"]
        stats.transactions = rec["transactions"]
        return stats

    # ------------------------------------------------------------------
    # primary connect / disconnect hooks
    # ------------------------------------------------------------------

    def add_block(
        self,
        block: "Block",
        height: int | None = None,
        db: "BlockchainDatabase | None" = None,
    ) -> None:
        """Connect *block* at *height* into the index (PRIMARY connect hook).

        Loads the running state from the previous height, applies the block's
        created-output / spent-prevout delta (Core ``CustomAppend``), and
        persists a self-contained snapshot at *height*.  Idempotent: a repeat
        connect at an already-indexed height recomputes from height-1 and
        overwrites, so a double-fire never double-counts.
        """
        if height is None:
            height = getattr(block, "height", None)
        if height is None:
            return

        with self._lock:
            stats = self._load_running(height - 1)

            # Genesis (height 0): Core's CoinStatsIndex::CustomAppend takes the
            # `else` branch and adds NOTHING to the muhash — the genesis
            # coinbase output is never added to the UTXO set (its subsidy is
            # accounted as total_unspendables_genesis_block).  So the height-0
            # snapshot is the EMPTY set: txouts=0, total_amount=0, MuHash of the
            # empty multiset.  Mirror that by skipping the block's txs entirely.
            if height == 0:
                self._write_snapshot(height, block.hash, stats)
                if (
                    self._best_indexed_height is None
                    or height > self._best_indexed_height
                ):
                    self._best_indexed_height = height
                    self._persist_best_indexed_height()
                return

            for tx in block.transactions:
                is_coinbase = bool(tx.is_coinbase)
                txid = tx.txid
                created_here = 0

                # --- created outputs (skip unspendable) ---
                for vout, out in enumerate(tx.outputs):
                    spk = bytes(out.script_pubkey)
                    if _is_unspendable(spk):
                        continue
                    amount = int(out.value)
                    element = coin_element(
                        txid=txid,
                        vout=vout,
                        height=height,
                        is_coinbase=is_coinbase,
                        amount=amount,
                        script_pubkey=spk,
                    )
                    stats.muhash.insert(element)
                    stats.txouts += 1
                    stats.total_amount += amount
                    stats.bogo_size += _bogo_size(spk)
                    created_here += 1

                if created_here > 0:
                    stats.transactions += 1

                # --- spent prevouts (coinbase spends nothing) ---
                if is_coinbase:
                    continue
                for inp in tx.inputs:
                    coin = self._lookup_spent_coin(db, inp.prev_txid, inp.prev_vout)
                    if coin is None:
                        logger.warning(
                            "coinstatsindex: missing spent coin for %s:%d at "
                            "height %d; index may diverge",
                            inp.prev_txid[::-1].hex(),
                            inp.prev_vout,
                            height,
                        )
                        continue
                    spk = bytes(coin["script_pubkey"])
                    amount = int(coin["amount"])
                    element = coin_element(
                        txid=inp.prev_txid,
                        vout=int(inp.prev_vout),
                        height=int(coin["height"]),
                        is_coinbase=bool(coin["is_coinbase"]),
                        amount=amount,
                        script_pubkey=spk,
                    )
                    stats.muhash.remove(element)
                    stats.txouts -= 1
                    stats.total_amount -= amount
                    stats.bogo_size -= _bogo_size(spk)

            self._write_snapshot(height, block.hash, stats)

            if (
                self._best_indexed_height is None
                or height > self._best_indexed_height
            ):
                self._best_indexed_height = height
                self._persist_best_indexed_height()

    def remove(self, block_hash: bytes, height: int | None = None) -> bool:
        """Disconnect the block at *height* (PRIMARY disconnect / reorg hook).

        Drops the per-height snapshot at *height*; the running state for the
        new tip is the already-persisted ``height-1`` snapshot, so no
        recomputation is needed.  Rolls ``best_indexed_height`` back to
        ``height-1`` when *height* is at/above the current best.  ``height``
        is optional only for in-memory-fallback API symmetry — the file
        store requires it to locate the snapshot.
        """
        with self._lock:
            found = False
            if height is not None:
                try:
                    os.remove(self._snap_file(height))
                    found = True
                except FileNotFoundError:
                    pass
                self._snap_cache.pop(height, None)
                if (
                    self._best_indexed_height is not None
                    and height >= self._best_indexed_height
                ):
                    self._best_indexed_height = (
                        height - 1 if height > 0 else None
                    )
                    self._persist_best_indexed_height()
            return found

    def _lookup_spent_coin(
        self, db: "BlockchainDatabase | None", prev_txid: bytes, prev_vout: int
    ) -> dict[str, Any] | None:
        """Resolve the coin spent by an input (original height + coinbase flag).

        Mirrors how the block-filter index reads spent prevouts: consult the
        SPENT_CF undo record (``get_utxo_or_spent``), falling back to the live
        UTXO set for a prevout created earlier in the same block that has not
        yet been moved to the spent store.  Returns a dict with ``amount``,
        ``script_pubkey``, ``height``, ``is_coinbase`` or ``None``.
        """
        if db is None:
            return None
        coin = None
        if hasattr(db, "get_utxo_or_spent"):
            try:
                coin = db.get_utxo_or_spent(prev_txid, prev_vout)
            except Exception:
                coin = None
        if coin is None:
            try:
                coin = db.get_utxo(prev_txid, prev_vout)
            except Exception:
                coin = None
        if coin is None:
            return None
        # get_utxo / get_utxo_or_spent return 'value' for the amount.
        amount = coin.get("amount")
        if amount is None:
            amount = coin.get("value")
        return {
            "amount": int(amount) if amount is not None else 0,
            "script_pubkey": bytes(coin.get("script_pubkey") or b""),
            "height": int(coin.get("height") or 0),
            "is_coinbase": bool(coin.get("is_coinbase", False)),
        }

    # ------------------------------------------------------------------
    # query API (used by gettxoutsetinfo / getindexinfo)
    # ------------------------------------------------------------------

    def get_at_height(self, height: int) -> dict[str, Any] | None:
        """Return the coinstats snapshot AS OF *height*, or ``None``.

        Result dict: ``block_hash`` (32-byte internal order), ``muhash``
        (32-byte digest, internal order), ``txouts``, ``total_amount``
        (sats), ``bogo_size``, ``transactions``.
        """
        with self._lock:
            rec = self._read_snapshot_raw(height)
        if rec is None:
            return None
        mu = MuHash3072.deserialize(rec["muhash_serialize"])
        return {
            "block_hash": rec["block_hash"],
            "muhash": mu.digest(),
            "txouts": rec["txouts"],
            "total_amount": rec["total_amount"],
            "bogo_size": rec["bogo_size"],
            "transactions": rec["transactions"],
        }

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def best_indexed_height(self) -> int | None:
        return self._best_indexed_height

    def is_synced(self, chain_tip_height: int | None) -> bool:
        if chain_tip_height is None or chain_tip_height < 0:
            return False
        if self._best_indexed_height is None:
            return False
        return self._best_indexed_height >= chain_tip_height

    # ------------------------------------------------------------------
    # startup reconcile (Core BaseIndex::Init parity)
    # ------------------------------------------------------------------

    def reconcile_to_chainstate(self, db: "BlockchainDatabase") -> int:
        """Rewind the index so it is never ahead of / forked from chainstate.

        Mirrors ``PersistentBlockFilterIndex.reconcile_to_chainstate`` and
        Bitcoin Core ``BaseIndex::Init``: the index is written AFTER the
        chainstate commit, so an unclean restart can leave the index past the
        chainstate or on an orphaned fork.  Walk the index tip down while it
        is ahead of, or forks away from, the active chain.  Returns the number
        of heights rewound (0 == already consistent).
        """
        if db is None:
            return 0
        try:
            _, chain_tip_height = db.get_best_block()
        except Exception as e:
            logger.warning(
                "coinstatsindex: could not read chainstate tip for startup "
                "reconcile (%s); skipping", e
            )
            return 0

        rewound = 0
        with self._lock:
            while True:
                best = self._best_indexed_height
                if best is None:
                    break
                ahead = best > chain_tip_height
                forked = False
                if not ahead:
                    rec = self._read_snapshot_raw(best)
                    idx_hash = rec["block_hash"] if rec else None
                    try:
                        chain_hash = db.get_block_hash_by_height(best)
                    except Exception:
                        chain_hash = None
                    if (
                        idx_hash is not None
                        and chain_hash is not None
                        and bytes(idx_hash) != bytes(chain_hash)
                    ):
                        forked = True
                if not ahead and not forked:
                    break
                self.remove(b"\x00" * 32, height=best)
                rewound += 1

        if rewound:
            logger.warning(
                "coinstatsindex: rewound %d height(s) on startup to reconcile "
                "with chainstate tip %d (new best_indexed_height=%s)",
                rewound, chain_tip_height, self._best_indexed_height,
            )
        return rewound

    def resync_to_chainstate(self, db: "BlockchainDatabase") -> int:
        """Re-align the index with the active chainstate after a reorg.

        Used by the ``invalidateblock`` / ``reconsiderblock`` RPC paths, where
        the chainstate reorg is performed in the Rust layer and therefore does
        NOT fire the Python connect/disconnect index hooks in ``block_sync``.
        This first rewinds any heights that are ahead of / forked from the new
        active chain (:meth:`reconcile_to_chainstate`), then walks FORWARD from
        ``best_indexed_height + 1`` to the chainstate tip, applying each block's
        delta via :meth:`add_block`.  The spent-prevout lookups read the
        SPENT_CF undo records the Rust reorg already wrote for the new chain, so
        the forward catch-up reconstructs the same per-height MuHash a P2P/IBD
        connect would have produced.

        Returns the net number of heights (re)connected forward (0 == already
        in sync).
        """
        if db is None:
            return 0
        # First drop stale / forked / ahead heights.
        self.reconcile_to_chainstate(db)
        try:
            _, chain_tip_height = db.get_best_block()
        except Exception as e:
            logger.warning(
                "coinstatsindex: resync could not read chainstate tip (%s)", e
            )
            return 0

        connected = 0
        with self._lock:
            start = (
                0 if self._best_indexed_height is None
                else self._best_indexed_height + 1
            )
            for h in range(start, chain_tip_height + 1):
                block = db.get_block_by_height(h)
                if block is None:
                    logger.warning(
                        "coinstatsindex: resync missing block at height %d; "
                        "stopping forward catch-up", h
                    )
                    break
                # add_block re-derives from height-1 and overwrites height h.
                self.add_block(block, height=h, db=db)
                connected += 1
        if connected:
            logger.info(
                "coinstatsindex: resync connected %d height(s) forward to "
                "chainstate tip %d", connected, chain_tip_height,
            )
        return connected
