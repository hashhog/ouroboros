"""
Transaction-output spender index (Bitcoin Core ``-txospenderindex`` parity).

For every input of every NON-coinbase transaction in a connected block this
index records a single key mapping the SPENT outpoint -> the SPENDING
transaction (txid, the hash of the block that confirmed it, and the full
spending-tx hex so ``return_spending_tx`` can be answered without a second DB
trip).  It is the data source for the CONFIRMED-spend path of the
``gettxspendingprevout`` RPC.

This mirrors Bitcoin Core's ``TxoSpenderIndex``
(bitcoin-core/src/index/txospenderindex.{h,cpp}).  Core stores the spending
tx's on-disk LOCATION (``CDiskTxPos``) keyed by a per-DB-salted
``siphash(outpoint)`` and reads the tx back from the block files on lookup (a
flat-file optimisation that also disambiguates siphash collisions and serves
the full spending tx).  The ``txospenderindex.cpp`` header comment notes that a
from-scratch implementation may legitimately store ``outpoint -> spending-txid``
directly; that is the simpler, faithful equivalent and is what this index does.
NO salt and NO separate undo data are needed: the disconnect path
(:meth:`remove_block`) RE-DERIVES the exact same keys from the disconnected
block's OWN inputs and erases them, exactly like Core's
``CustomRemove(BuildSpenderPositions(block))``.

Default-off, gated by ``-txospenderindex``, matching Core's
``DEFAULT_TXOSPENDERINDEX{false}``.

Design — reorg-safe, incremental on the PRIMARY block-connect path
------------------------------------------------------------------
The index is updated on the node's primary block connect+disconnect path
(P2P/IBD linear connect, the reorg connect/disconnect loop in
``block_sync.py``, and the ``submitblock``/``generatetoaddress`` RPC accept
path), exactly where ``coinstatsindex``/``blockfilterindex`` are maintained.

Per Bitcoin Core ``CustomAppend`` / ``CustomRemove``:

  * connect(H): for every non-coinbase input of every tx, write
    ``spent_outpoint -> (spending_txid, block_hash, spending_tx_hex)``.
  * disconnect(H): re-derive those same keys from the block's inputs and
    delete them (no undo data).  Persist a ``best_indexed_height`` rollback.

Storage layout (file-per-spend, sharded by outpoint-hash prefix, under
``<data_dir>/txospenderindex/``)::

    <data_dir>/txospenderindex/
        VERSION                       # schema version text file
        meta/best_indexed_height      # highest height indexed (or "none")
        meta/best_indexed_hash        # 32-byte hash of that height's block
        spend/<aa>/<keyhex>.s         # per-spend record (binary)

The per-spend key is ``sha256(outpoint.hash || outpoint.n)`` so two distinct
outpoints never share a file and a lookup is a single O(1) ``open``.  An
outpoint can be spent only once on a single chain, so each key file holds at
most one record.  All writes use write-then-rename (``os.replace`` is atomic
on POSIX) so a crash mid-connect cannot leave a half-written record.  A single
``threading.RLock`` serialises connect / disconnect so concurrent
``asyncio.to_thread`` calls cannot interleave.

References:
  - bitcoin-core/src/index/txospenderindex.{h,cpp}  (CustomAppend / CustomRemove)
  - bitcoin-core/src/rpc/mempool.cpp::gettxspendingprevout
  - blockbrew internal/storage/txospenderindex.go (committed reorg-safe template)
  - ouroboros coinstatsindex.py / blockfilter.py (this impl's index plumbing)
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ouroboros.database import Block, BlockchainDatabase, Transaction

logger = logging.getLogger(__name__)


def _outpoint_key(prev_txid: bytes, prev_vout: int) -> bytes:
    """Stable per-outpoint key: ``sha256(txid(32) || vout(4 LE))``.

    The key collapses the 36-byte outpoint to a fixed 32-byte digest that is
    safe to use as a sharded filename (hex), mirroring how blockfilter.py
    shards by block-hash prefix.  An outpoint is spent at most once on a chain,
    so the key space is collision-free in practice (and a sha256 pre-image is
    irrelevant here — this is an internal index key, not a commitment).
    """
    return hashlib.sha256(bytes(prev_txid) + struct.pack("<I", int(prev_vout) & 0xFFFFFFFF)).digest()


class TxoSpenderRecord:
    """Decoded value of a spender-index entry."""

    __slots__ = ("spending_txid", "block_hash", "spending_tx_hex")

    def __init__(self, spending_txid: bytes, block_hash: bytes, spending_tx_hex: bytes) -> None:
        self.spending_txid = spending_txid  # 32-byte internal byte order
        self.block_hash = block_hash        # 32-byte internal byte order
        self.spending_tx_hex = spending_tx_hex  # full wire-serialized spending tx


class TxoSpenderIndex:
    """Persistent, reorg-safe ``spent outpoint -> spending tx`` index."""

    SCHEMA_VERSION = 1

    # Record wire format (little-endian):
    #   spending_txid   32 bytes (internal byte order)
    #   block_hash      32 bytes (internal byte order)
    #   tx_len          u32
    #   tx_bytes        tx_len bytes (wire-serialized spending tx, with witness)
    _REC_HEADER = struct.Struct("<32s32sI")

    def __init__(
        self,
        data_dir: str,
        enabled: bool = True,
        cache_capacity: int = 8192,
    ) -> None:
        self._enabled = enabled
        self._data_dir = data_dir
        self._lock = threading.RLock()
        self._cache_capacity = max(0, int(cache_capacity))
        self._cache: OrderedDict[bytes, TxoSpenderRecord] = OrderedDict()
        self._best_indexed_height: int | None = None
        self._best_indexed_hash: bytes | None = None

        root = os.path.join(data_dir, "txospenderindex")
        os.makedirs(root, exist_ok=True)
        self._root_path = root
        self._spend_path = os.path.join(root, "spend")
        self._meta_path = os.path.join(root, "meta")
        os.makedirs(self._spend_path, exist_ok=True)
        os.makedirs(self._meta_path, exist_ok=True)

        version_path = os.path.join(root, "VERSION")
        if not os.path.exists(version_path):
            try:
                with open(version_path, "w", encoding="utf-8") as f:
                    f.write(f"{self.SCHEMA_VERSION}\n")
            except OSError:
                pass

        self._best_indexed_height = self._load_best_indexed_height()
        self._best_indexed_hash = self._load_best_indexed_hash()

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

    def _spend_file(self, key: bytes) -> str:
        khex = key.hex()
        shard = os.path.join(self._spend_path, khex[:2])
        return os.path.join(shard, f"{khex}.s")

    def _best_indexed_height_path(self) -> str:
        return os.path.join(self._meta_path, "best_indexed_height")

    def _best_indexed_hash_path(self) -> str:
        return os.path.join(self._meta_path, "best_indexed_hash")

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

    def _load_best_indexed_hash(self) -> bytes | None:
        try:
            with open(self._best_indexed_hash_path(), "rb") as f:
                raw = f.read()
        except (FileNotFoundError, OSError):
            return None
        return raw if len(raw) == 32 else None

    def _persist_best(self) -> None:
        try:
            value = (
                "none"
                if self._best_indexed_height is None
                else str(int(self._best_indexed_height))
            )
            self._atomic_write(self._best_indexed_height_path(), value.encode("utf-8"))
            self._atomic_write(
                self._best_indexed_hash_path(),
                bytes(self._best_indexed_hash) if self._best_indexed_hash else b"\x00" * 32,
            )
        except OSError:
            pass

    def _cache_put(self, key: bytes, rec: TxoSpenderRecord) -> None:
        if self._cache_capacity == 0:
            return
        self._cache[key] = rec
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_capacity:
            self._cache.popitem(last=False)

    # ------------------------------------------------------------------
    # record read / write
    # ------------------------------------------------------------------

    def _write_record(self, key: bytes, rec: TxoSpenderRecord) -> None:
        blob = (
            self._REC_HEADER.pack(
                bytes(rec.spending_txid),
                bytes(rec.block_hash),
                len(rec.spending_tx_hex),
            )
            + bytes(rec.spending_tx_hex)
        )
        path = self._spend_file(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._atomic_write(path, blob)
        self._cache_put(key, rec)

    def _erase_record(self, key: bytes) -> None:
        try:
            os.remove(self._spend_file(key))
        except FileNotFoundError:
            pass
        self._cache.pop(key, None)

    def _read_record(self, key: bytes) -> TxoSpenderRecord | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        try:
            with open(self._spend_file(key), "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return None
        hsz = self._REC_HEADER.size
        if len(blob) < hsz:
            return None
        spending_txid, block_hash, tx_len = self._REC_HEADER.unpack(blob[:hsz])
        tx_bytes = blob[hsz : hsz + tx_len]
        rec = TxoSpenderRecord(spending_txid, block_hash, tx_bytes)
        self._cache_put(key, rec)
        return rec

    # ------------------------------------------------------------------
    # primary connect / disconnect hooks
    # ------------------------------------------------------------------

    @staticmethod
    def _spend_keys_for_block(block: "Block") -> list[tuple[bytes, "Transaction"]]:
        """Re-derive every (outpoint-key, spending-tx) pair from a block.

        Mirrors Core ``BuildSpenderPositions``: for each non-coinbase tx, one
        entry per input.  Both the connect (write) and disconnect (erase)
        paths call this so the keys are a pure function of the block's own
        inputs (no undo data required).
        """
        out: list[tuple[bytes, "Transaction"]] = []
        for tx in block.transactions:
            if getattr(tx, "is_coinbase", False):
                continue
            for inp in tx.inputs:
                out.append((_outpoint_key(inp.prev_txid, inp.prev_vout), tx))
        return out

    def add_block(
        self,
        block: "Block",
        height: int | None = None,
        db: "BlockchainDatabase | None" = None,
    ) -> None:
        """Connect *block* at *height* into the index (PRIMARY connect hook).

        Writes ``spent_outpoint -> spending tx`` for every non-coinbase input.
        Idempotent: a repeat connect at the same height overwrites the same
        keys with the same values, so a double-fire never corrupts the index.
        """
        if not self._enabled:
            return
        if height is None:
            height = getattr(block, "height", None)
        if height is None:
            return

        with self._lock:
            # Genesis (height 0): the single coinbase has a null prevout, so
            # there is nothing to index — just record the best pointer (Core's
            # CustomAppend writes nothing for a coinbase-only block).
            if height > 0:
                block_hash = block.hash
                for key, tx in self._spend_keys_for_block(block):
                    try:
                        tx_hex = tx.serialize_with_witness()
                    except Exception:
                        tx_hex = tx.serialize()
                    rec = TxoSpenderRecord(tx.txid, block_hash, tx_hex)
                    self._write_record(key, rec)

            if (
                self._best_indexed_height is None
                or height > self._best_indexed_height
            ):
                self._best_indexed_height = height
                self._best_indexed_hash = bytes(block.hash)
                self._persist_best()
            elif height == self._best_indexed_height:
                self._best_indexed_hash = bytes(block.hash)
                self._persist_best()

    def remove_block(
        self,
        block: "Block",
        height: int | None = None,
        db: "BlockchainDatabase | None" = None,
    ) -> bool:
        """Disconnect *block* at *height* (PRIMARY disconnect / reorg hook).

        RE-DERIVES the block's spend keys and erases them, mirroring Core's
        ``CustomRemove(BuildSpenderPositions(block))``.  Rolls
        ``best_indexed_height`` back to ``height-1``.  No undo data needed —
        the keys are a pure function of the disconnected block's inputs.
        """
        if not self._enabled:
            return False
        if height is None:
            height = getattr(block, "height", None)

        with self._lock:
            for key, _tx in self._spend_keys_for_block(block):
                self._erase_record(key)

            if height is not None and (
                self._best_indexed_height is not None
                and height <= self._best_indexed_height
            ):
                prev_height = height - 1
                prev_hash: bytes | None = None
                if prev_height < 0:
                    prev_height = None  # type: ignore[assignment]
                else:
                    prev_hash = (
                        bytes(block.prev_blockhash)
                        if getattr(block, "prev_blockhash", None)
                        else None
                    )
                self._best_indexed_height = prev_height
                self._best_indexed_hash = prev_hash
                self._persist_best()
            return True

    # ------------------------------------------------------------------
    # query API (used by gettxspendingprevout / getindexinfo)
    # ------------------------------------------------------------------

    def find_spender(self, prev_txid: bytes, prev_vout: int) -> TxoSpenderRecord | None:
        """Return the on-chain tx that spends ``(prev_txid, prev_vout)``.

        ``None`` when the outpoint is unspent on-chain.  Mirrors Core's
        ``TxoSpenderIndex::FindSpender`` (``std::nullopt`` when unspent).
        """
        with self._lock:
            return self._read_record(_outpoint_key(prev_txid, prev_vout))

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

        Mirrors ``CoinStatsIndex.reconcile_to_chainstate`` and Bitcoin Core
        ``BaseIndex::Init``: the index is written AFTER the chainstate commit,
        so an unclean restart can leave the index past the chainstate or on an
        orphaned fork.  Walk the index tip down while it is ahead of, or forks
        away from, the active chain, erasing each rewound block's spend keys.
        Returns the number of heights rewound (0 == already consistent).
        """
        if db is None:
            return 0
        try:
            _, chain_tip_height = db.get_best_block()
        except Exception as e:
            logger.warning(
                "txospenderindex: could not read chainstate tip for startup "
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
                    try:
                        chain_hash = db.get_block_hash_by_height(best)
                    except Exception:
                        chain_hash = None
                    if (
                        self._best_indexed_hash is not None
                        and chain_hash is not None
                        and bytes(self._best_indexed_hash) != bytes(chain_hash)
                    ):
                        forked = True
                if not ahead and not forked:
                    break
                block = None
                try:
                    block = db.get_block_by_height(best)
                except Exception:
                    block = None
                if block is None:
                    # Cannot re-derive the keys to erase; just roll the pointer
                    # back so we never serve a tip ahead of chainstate.
                    self._best_indexed_height = best - 1 if best > 0 else None
                    self._best_indexed_hash = None
                    self._persist_best()
                else:
                    self.remove_block(block, height=best, db=db)
                rewound += 1

        if rewound:
            logger.warning(
                "txospenderindex: rewound %d height(s) on startup to reconcile "
                "with chainstate tip %d (new best_indexed_height=%s)",
                rewound, chain_tip_height, self._best_indexed_height,
            )
        return rewound

    def resync_to_chainstate(self, db: "BlockchainDatabase") -> int:
        """Re-align the index with the active chainstate after a reorg.

        Used by the ``invalidateblock`` / ``reconsiderblock`` RPC paths, where
        the chainstate reorg is performed in the Rust layer and therefore does
        NOT fire the Python connect/disconnect index hooks in ``block_sync``.
        First rewinds heights that are ahead of / forked from the new active
        chain (:meth:`reconcile_to_chainstate`), then walks FORWARD from
        ``best_indexed_height + 1`` to the chainstate tip, applying each
        block's spend keys via :meth:`add_block`.

        Returns the net number of heights (re)connected forward.
        """
        if db is None:
            return 0
        self.reconcile_to_chainstate(db)
        try:
            _, chain_tip_height = db.get_best_block()
        except Exception as e:
            logger.warning(
                "txospenderindex: resync could not read chainstate tip (%s)", e
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
                        "txospenderindex: resync missing block at height %d; "
                        "stopping forward catch-up", h
                    )
                    break
                self.add_block(block, height=h, db=db)
                connected += 1
        if connected:
            logger.info(
                "txospenderindex: resync connected %d height(s) forward to "
                "chainstate tip %d", connected, chain_tip_height,
            )
        return connected
