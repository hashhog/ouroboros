"""
Python wrapper for blockchain database operations.

This module provides a high-level Python interface to the Rust blockchain database
implementation, allowing Python code to interact with the blockchain storage layer.
"""

import hashlib
from dataclasses import dataclass
from typing import Any

import sync  # Rust extension module (required)


@dataclass
class Block:
    """Bitcoin block representation"""
    version: int
    prev_blockhash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    transactions: list['Transaction']
    hash: bytes
    height: int | None = None  # Block height (if known)

    def hash(self) -> bytes:
        """Compute block hash"""
        return self.hash

    def serialize(self) -> bytes:
        """Serialize block to Bitcoin wire format (80-byte header + tx list)."""
        from ouroboros.p2p_messages import encode_varint

        data = bytearray()

        # Serialize header (80 bytes)
        # Version (4 bytes)
        data.extend(self.version.to_bytes(4, 'little', signed=True))

        # Previous block hash (32 bytes, already in internal/wire byte order)
        data.extend(self.prev_blockhash)

        # Merkle root (32 bytes, already in internal/wire byte order)
        data.extend(self.merkle_root)

        # Timestamp (4 bytes)
        data.extend(self.timestamp.to_bytes(4, 'little'))

        # Bits (4 bytes)
        data.extend(self.bits.to_bytes(4, 'little'))

        # Nonce (4 bytes)
        data.extend(self.nonce.to_bytes(4, 'little'))

        # Transaction count (varint)
        data.extend(encode_varint(len(self.transactions)))

        # Serialize each transaction
        for tx in self.transactions:
            tx_bytes = tx.serialize()
            data.extend(tx_bytes)

        return bytes(data)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Block':
        """Deserialize a block from Bitcoin wire format.

        Raises ValueError if data is invalid or too short.
        """
        from ouroboros.p2p_messages import TxMessage, decode_varint

        offset = 0

        if len(data) < 80:  # Minimum header size
            raise ValueError("Block data too short for header")

        # Parse header (80 bytes)
        version = int.from_bytes(data[offset:offset+4], byteorder='little', signed=True)
        offset += 4

        prev_blockhash = data[offset:offset+32]  # Internal (little-endian) byte order — matches DB
        offset += 32

        merkle_root = data[offset:offset+32]  # Internal (little-endian) byte order
        offset += 32

        timestamp = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4

        bits = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4

        nonce = int.from_bytes(data[offset:offset+4], byteorder='little')
        offset += 4

        # Parse transaction count (varint)
        if len(data) <= offset:
            raise ValueError("Block data too short for transaction count")
        tx_count, varint_size = decode_varint(data, offset)
        offset += varint_size

        # Parse transactions
        # We need to track transaction sizes accurately
        # Since transactions can have variable sizes and we need to know where each ends,
        # we'll parse each transaction and use its serialized size to track bytes consumed
        transactions = []
        for i in range(tx_count):
            if offset >= len(data):
                raise ValueError(f"Block data too short for transaction {i}")

            # Store offset before parsing this transaction
            tx_start_offset = offset

            # Parse transaction using TxMessage.from_payload
            tx_data = data[offset:]
            try:
                tx_msg = TxMessage.from_payload(tx_data)
                tx = tx_msg.transaction

                # Use the exact byte count consumed by the parser (including
                # segwit marker, flag, and witness data) so that we advance
                # past the full wire-format transaction.
                tx_size = getattr(tx_msg, 'bytes_consumed', None)
                if tx_size is None:
                    # Fallback: non-witness serialization (may be wrong for segwit)
                    tx_size = len(tx.serialize())

                offset = tx_start_offset + tx_size
                transactions.append(tx)

            except ValueError as e:
                # If parsing fails, try to recover by finding next transaction
                # This is a fallback - ideally we should parse correctly
                raise ValueError(f"Error parsing transaction {i} at offset {tx_start_offset}: {e}") from None
            except Exception as e:
                raise ValueError(f"Unexpected error parsing transaction {i}: {e}") from None

        # Calculate block hash
        import hashlib
        block_header = data[0:80]
        block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()  # Internal byte order — matches DB

        return cls(
            version=version,
            prev_blockhash=prev_blockhash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
            transactions=transactions,
            hash=block_hash,
            height=None  # Height not in wire format
        )


@dataclass
class Transaction:
    """Bitcoin transaction representation"""
    txid: bytes
    version: int
    locktime: int
    inputs: list['TxIn']
    outputs: list['TxOut']
    has_witness: bool = False  # True if SegWit (marker 0x00, flag 0x01)

    @property
    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction"""
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == bytes(32)

    def get_txid(self) -> bytes:
        """Get transaction ID"""
        return self.txid

    def serialize(self) -> bytes:
        """
        Serialize transaction to bytes for fee calculation.

        This is a simplified serialization for size estimation.
        For full Bitcoin protocol serialization, use the Rust layer.
        """
        # Version (4 bytes)
        data = self.version.to_bytes(4, 'little')

        # Input count (varint)
        data += self._encode_varint(len(self.inputs))

        # Inputs
        for tx_in in self.inputs:
            data += tx_in.prev_txid  # 32 bytes
            data += tx_in.prev_vout.to_bytes(4, 'little')
            data += self._encode_varint(len(tx_in.script_sig))
            data += tx_in.script_sig
            data += tx_in.sequence.to_bytes(4, 'little')

        # Output count (varint)
        data += self._encode_varint(len(self.outputs))

        # Outputs
        for tx_out in self.outputs:
            data += tx_out.value.to_bytes(8, 'little')
            data += self._encode_varint(len(tx_out.script_pubkey))
            data += tx_out.script_pubkey

        # Locktime (4 bytes)
        data += self.locktime.to_bytes(4, 'little')

        return data

    def serialize_with_witness(self) -> bytes:
        """
        Serialize transaction including witness (SegWit wire format).
        Used for wtxid: SHA256D of this equals witness txid for SegWit txs.
        """
        data = bytearray()
        # Tx version is uint32 on the wire (Core CTransaction::version);
        # write UNSIGNED to match serialize() so a negative-looking version
        # (e.g. 0xFFFFFFFF) round-trips byte-identically here and there.
        data.extend(self.version.to_bytes(4, 'little'))
        if self.has_witness:
            data.extend(b'\x00\x01')  # marker, flag
        data.extend(self._encode_varint(len(self.inputs)))
        for tx_in in self.inputs:
            data.extend(tx_in.prev_txid)
            data.extend(tx_in.prev_vout.to_bytes(4, 'little'))
            data.extend(self._encode_varint(len(tx_in.script_sig)))
            data.extend(tx_in.script_sig)
            data.extend(tx_in.sequence.to_bytes(4, 'little'))
        data.extend(self._encode_varint(len(self.outputs)))
        for tx_out in self.outputs:
            data.extend(tx_out.value.to_bytes(8, 'little'))
            data.extend(self._encode_varint(len(tx_out.script_pubkey)))
            data.extend(tx_out.script_pubkey)
        if self.has_witness:
            for tx_in in self.inputs:
                witness = tx_in.witness or []
                data.extend(self._encode_varint(len(witness)))
                for item in witness:
                    data.extend(self._encode_varint(len(item)))
                    data.extend(item)
        data.extend(self.locktime.to_bytes(4, 'little'))
        return bytes(data)

    def get_wtxid(self) -> bytes:
        """Witness transaction ID: double SHA256 of full serialization including witness."""
        if not self.has_witness:
            return self.get_txid()
        return hashlib.sha256(hashlib.sha256(self.serialize_with_witness()).digest()).digest()

    def _encode_varint(self, value: int) -> bytes:
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')

    def get_witness_bytes(self) -> int:
        """Total encoded witness size in bytes (0 for non-SegWit)."""
        if not self.has_witness:
            return 0
        total = 0
        for tx_in in self.inputs:
            if tx_in.witness is None:
                continue
            total += len(self._encode_varint(len(tx_in.witness)))
            for item in tx_in.witness:
                total += len(self._encode_varint(len(item))) + len(item)
        return total

    def get_weight(self) -> int:
        """Transaction weight per BIP 141: stripped_size * 3 + total_size.

        This matches Bitcoin Core's GetTransactionWeight exactly:
          GetSerializeSize(TX_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1)
          + GetSerializeSize(TX_WITH_WITNESS)
        For non-SegWit txs, stripped == total so weight == size * 4.
        """
        stripped_size = len(self.serialize())
        total_size = len(self.serialize_with_witness())
        return stripped_size * 3 + total_size

    def get_vsize(self) -> int:
        """Virtual size in bytes: ceil(weight / 4)."""
        weight = self.get_weight()
        # vsize = ceil(weight / 4) = (weight + 3) // 4
        return (weight + 3) // 4


@dataclass
class TxIn:
    """Bitcoin transaction input"""
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: list[bytes] | None = None  # SegWit witness stack; None = non-SegWit


@dataclass
class TxOut:
    """Bitcoin transaction output"""
    value: int
    script_pubkey: bytes


@dataclass
class _SnapshotUTXOView:
    """Lightweight UTXO view yielded by ``BlockchainDatabase.iter_utxos``.

    Mirrors the fields the snapshot dumper expects (raw 32-byte ``txid``
    in internal order, ``vout``, ``amount``, ``script_pubkey``, ``height``,
    ``is_coinbase``).  Kept private so callers depend on field names, not
    the concrete type.
    """
    txid: bytes
    vout: int
    amount: int
    script_pubkey: bytes
    height: int
    is_coinbase: bool


class BlockchainDatabase:
    """Read/write access to blockchain data using Rust backend"""

    def __init__(self, data_dir: str):
        self._db = sync.PyBlockchainDB(data_dir)
        self._data_dir = data_dir
        # Cached chain tip — updated after every block connect/disconnect.
        # RPC reads this instead of calling into Rust FFI, avoiding lock
        # contention during IBD.
        self._cached_tip: tuple[bytes, int] | None = None
        # Lightweight header-field cache for RPC — avoids full-block
        # deserialisation in getblockchaininfo.  Updated on connect.
        self._tip_bits: int = 0x1d00ffff
        self._tip_timestamp: int = 0
        self._recent_timestamps: list = []  # last 11 block timestamps
        self._cached_chainwork: int = 0  # cumulative chain work, updated on connect
        try:
            self._cached_tip = self.get_best_block()
        except Exception:
            pass

    def get_block(self, block_hash: bytes) -> Block | None:
        """Look up a block by its 32-byte hash; returns None if not found."""
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        py_block = self._db.get_block(block_hash)
        if py_block is None:
            return None

        return self._py_block_to_block(py_block)

    def has_block_hash(self, block_hash: bytes) -> bool:
        """Return True if *block_hash* is present in the block store.

        Cheap existence probe — avoids full block deserialisation. Used by
        ``block_sync`` to filter already-known headers from inv/headers
        batches without paying the cost of ``get_block``.
        """
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        return self._db.has_block_hash(block_hash)

    def get_block_bytes(self, block_hash: bytes) -> bytes | None:
        """Fetch the raw consensus-serialised bytes of a stored block.

        Unlike :meth:`get_block`, the returned bytes preserve segwit
        witness data — the Python ``Block`` dataclass strips witnesses on
        the round-trip. The reorg path uses this to re-feed side-chain
        blocks into ``connect_block_from_bytes`` so that SPENT_CF undo
        records are re-written and the block can be cleanly disconnected
        if the chain re-reorgs.
        """
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        if not hasattr(self._db, "get_block_bytes"):
            return None
        result = self._db.get_block_bytes(block_hash)
        if result is None:
            return None
        return bytes(result)

    def get_block_by_height(self, height: int) -> Block | None:
        """Look up a block by height; returns None if not found."""
        py_block = self._db.get_block_by_height(height)
        if py_block is None:
            return None

        return self._py_block_to_block(py_block)

    def get_utxo(self, txid: bytes, vout: int) -> dict[str, Any] | None:
        """Fetch a UTXO by outpoint; returns a dict (txid, vout, value, script_pubkey) or None."""
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")

        py_utxo = self._db.get_utxo(txid, vout)
        if py_utxo is None:
            return None

        return {
            'txid': py_utxo.txid,
            'vout': py_utxo.vout,
            'value': py_utxo.value,
            'script_pubkey': bytes(py_utxo.script_pubkey),
            'height': getattr(py_utxo, 'height', None),
            'is_coinbase': getattr(py_utxo, 'is_coinbase', False),
        }

    def get_utxo_or_spent(self, txid: bytes, vout: int) -> dict[str, Any] | None:
        """Fetch a UTXO by outpoint from either the live chainstate or the spent-record
        store (SPENT_CF). Used by rpc_getblock verbosity>=2 to compute transaction fees
        for historical blocks whose inputs have already been spent.

        Returns None if the outpoint is not found in either location.
        Falls back to ``get_utxo`` if the Rust layer does not yet expose
        ``get_utxo_or_spent`` (older builds).
        """
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")

        if hasattr(self._db, 'get_utxo_or_spent'):
            py_utxo = self._db.get_utxo_or_spent(txid, vout)
        else:
            py_utxo = self._db.get_utxo(txid, vout)

        if py_utxo is None:
            return None

        return {
            'txid': py_utxo.txid,
            'vout': py_utxo.vout,
            'value': py_utxo.value,
            'script_pubkey': bytes(py_utxo.script_pubkey),
            'height': getattr(py_utxo, 'height', None),
            'is_coinbase': getattr(py_utxo, 'is_coinbase', False),
        }

    def utxo_count(self) -> int:
        """Return the number of UTXOs currently in the chainstate.

        Used by ``dumptxoutset`` (BIP305 snapshot creation) to write
        the per-snapshot ``coins_count`` header field. Returns 0 if
        the underlying Rust extension does not yet expose
        ``utxo_count`` (older builds), so that an empty-set dump
        still succeeds rather than raising.
        """
        if hasattr(self._db, "utxo_count"):
            return int(self._db.utxo_count())
        # Fallback: count via iteration if the count method isn't available.
        if hasattr(self._db, "iter_utxos"):
            return sum(1 for _ in self._db.iter_utxos())
        return 0

    def iter_utxos(self):
        """Yield every UTXO in the chainstate as PyUTXO-shaped objects.

        Used by ``dumptxoutset`` to assemble per-txid groups for the
        snapshot wire format. The yielded items expose ``txid`` (raw
        32-byte hash), ``vout``, ``amount``, ``script_pubkey``, ``height``,
        and ``is_coinbase`` — matching the fields the snapshot dumper
        reads.
        """
        if not hasattr(self._db, "iter_utxos"):
            return
        for py_utxo in self._db.iter_utxos():
            # Rust returns txid as a hex string; the snapshot format wants
            # raw 32 bytes, internal byte order. The Rust ``Txid::to_string``
            # produces the *display* (reversed) hex, so we reverse here to
            # recover the wire/internal byte order.
            raw_txid = py_utxo.txid
            if isinstance(raw_txid, str):
                raw_txid = bytes.fromhex(raw_txid)[::-1]
            else:
                raw_txid = bytes(raw_txid)
            yield _SnapshotUTXOView(
                txid=raw_txid,
                vout=int(py_utxo.vout),
                amount=int(getattr(py_utxo, "amount", py_utxo.value)),
                script_pubkey=bytes(py_utxo.script_pubkey),
                height=int(py_utxo.height) if py_utxo.height is not None else 0,
                is_coinbase=bool(getattr(py_utxo, "is_coinbase", False)),
            )

    def add_utxo_raw(
        self,
        *,
        txid: bytes,
        vout: int,
        amount: int,
        script_pubkey: bytes,
        height: int,
        is_coinbase: bool,
    ) -> None:
        """Insert a UTXO into the chainstate from already-decoded scalar fields.

        Used by the ``loadtxoutset`` snapshot loader: the snapshot wire
        format produces (txid, vout, amount, scriptPubKey, height,
        is_coinbase) per coin, so this skips the PyUTXO round-trip and
        feeds the values straight to Rust ``add_utxo``.

        Raises ValueError if ``txid`` is not 32 bytes.
        """
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        if not hasattr(self._db, "add_utxo_raw"):
            raise NotImplementedError(
                "Rust extension does not expose add_utxo_raw; rebuild the "
                "ferrous-utils/sync extension"
            )
        self._db.add_utxo_raw(
            bytes(txid),
            int(vout),
            int(amount),
            bytes(script_pubkey),
            int(height),
            bool(is_coinbase),
        )

    # ------------------------------------------------------------------
    # Atomic snapshot-load primitives (FIX-D, chainstate atomicity family
    # 2026-05-26).  See snapshot.py::load_snapshot for the call protocol.
    #
    # All three methods passthrough to PyBlockchainDB; the cached tip
    # ``self._cached_tip`` is invalidated where appropriate so subsequent
    # ``get_best_block()`` calls re-read from Rust.
    # ------------------------------------------------------------------

    def snapshot_load_begin(self, base_blockhash: bytes, base_height: int) -> None:
        """Phase 1 of an atomic snapshot load.

        Clears the chainstate (the snapshot is the authoritative new UTXO
        set) and writes the ``SNAPSHOT_LOAD_IN_PROGRESS`` marker to META_CF.
        After this returns, a crash leaves the chainstate empty + marker
        set; the next-boot ``recover_from_crash`` clears any partial state
        and instructs the operator to re-run ``loadtxoutset``.

        Raises ``NotImplementedError`` if the Rust extension is older than
        FIX-D (no ``snapshot_load_begin`` symbol).
        """
        if len(base_blockhash) != 32:
            raise ValueError("base_blockhash must be 32 bytes")
        if not hasattr(self._db, "snapshot_load_begin"):
            raise NotImplementedError(
                "Rust extension does not expose snapshot_load_begin; "
                "rebuild the ferrous-utils/sync extension (FIX-D)"
            )
        self._db.snapshot_load_begin(bytes(base_blockhash), int(base_height))
        # Tip will be reset to all-zeros / 0 during recovery; invalidate cache.
        self._cached_tip = None

    def snapshot_load_chunk(
        self,
        coins: list[tuple[bytes, int, int, bytes, int, bool]],
    ) -> None:
        """Phase 2 of an atomic snapshot load — apply N coins in one batch.

        ``coins`` is a list of ``(txid, vout, amount, script_pubkey, height,
        is_coinbase)`` tuples.  All N puts land together or none of them do;
        on RocksDB failure the entire chunk is rejected and the caller can
        retry.  Pre-FIX-D the loader did N individual ``add_utxo_raw`` calls,
        so partial chunks were the norm on any error.

        Raises ``ValueError`` if any txid is not 32 bytes (the entire chunk
        is rejected — no partial commit).
        Raises ``NotImplementedError`` if the Rust extension is older than
        FIX-D.
        """
        if not hasattr(self._db, "snapshot_load_chunk"):
            raise NotImplementedError(
                "Rust extension does not expose snapshot_load_chunk; "
                "rebuild the ferrous-utils/sync extension (FIX-D)"
            )
        # Normalise to the exact tuple shape pyo3 expects; this also raises
        # cleanly if any field is wrong before crossing the FFI boundary.
        normalised: list[tuple[bytes, int, int, bytes, int, bool]] = []
        for i, c in enumerate(coins):
            txid, vout, amount, script_pubkey, height, is_coinbase = c
            if len(txid) != 32:
                raise ValueError(
                    f"snapshot_load_chunk: coin {i} txid is {len(txid)} bytes "
                    "(expected 32)"
                )
            normalised.append((
                bytes(txid),
                int(vout),
                int(amount),
                bytes(script_pubkey),
                int(height),
                bool(is_coinbase),
            ))
        self._db.snapshot_load_chunk(normalised)

    def snapshot_load_commit(
        self,
        base_blockhash: bytes,
        base_height: int,
        chainwork_be: bytes | None = None,
        timestamp: int | None = None,
    ) -> None:
        """Phase 3 of an atomic snapshot load — final commit batch.

        Single atomic ``WriteBatch`` containing:
          - ``update_best_block_batch(base_blockhash, base_height)``
            (tip pointer, atomic pair via FIX-C)
          - ``store_block_metadata_batch`` for the snapshot block, when
            ``chainwork_be`` (32-byte big-endian) AND ``timestamp`` are
            provided (assumeUTXO entries in chainparams ship these;
            testnet-only entries may not)
          - delete of the ``SNAPSHOT_LOAD_IN_PROGRESS`` marker

        After this commits, the tip + chainwork metadata + cleared marker
        are all consistent and durable.  ``recover_from_crash`` on a
        subsequent boot takes the no-op fast path.

        Raises ``ValueError`` if ``base_blockhash`` is not 32 bytes or
        ``chainwork_be`` (when provided) is not 32 bytes.
        Raises ``NotImplementedError`` if the Rust extension is older than
        FIX-D.
        """
        if len(base_blockhash) != 32:
            raise ValueError("base_blockhash must be 32 bytes")
        if chainwork_be is not None and len(chainwork_be) != 32:
            raise ValueError(
                f"chainwork_be must be 32 bytes (got {len(chainwork_be)})"
            )
        if not hasattr(self._db, "snapshot_load_commit"):
            raise NotImplementedError(
                "Rust extension does not expose snapshot_load_commit; "
                "rebuild the ferrous-utils/sync extension (FIX-D)"
            )
        cw = bytes(chainwork_be) if chainwork_be is not None else None
        ts = int(timestamp) if timestamp is not None else None
        self._db.snapshot_load_commit(
            bytes(base_blockhash), int(base_height), cw, ts,
        )
        # Tip just moved; refresh the cache.
        self._cached_tip = (bytes(base_blockhash), int(base_height))

    def has_snapshot_load_marker(self) -> bool:
        """True iff a SNAPSHOT_LOAD_IN_PROGRESS marker is set in META_CF.

        Useful for tests and operator diagnostics.  Production callers rely
        on ``recover_from_crash`` instead.  Falls back to ``False`` when
        the Rust extension is older than FIX-D so callers that pre-flight
        this don't need to special-case absent attributes.
        """
        if not hasattr(self._db, "has_snapshot_load_marker"):
            return False
        return bool(self._db.has_snapshot_load_marker())

    def get_utxo_batch(self, outpoints: list[tuple[bytes, int]]) -> list[dict[str, Any] | None]:
        """Batch-fetch UTXOs for a list of (txid, vout) pairs in one FFI call.

        Returns a list of UTXO dicts (same shape as get_utxo) in the same order
        as ``outpoints``.  None is returned for any outpoint not found in the
        UTXO set.

        Using this instead of N individual get_utxo() calls reduces Python→Rust
        boundary crossings and GIL re-acquisition overhead during transaction
        validation, which is particularly important during IBD.
        """
        if not hasattr(self._db, 'get_utxo_batch'):
            # Fallback for older Rust builds without batch support
            return [self.get_utxo(txid, vout) for txid, vout in outpoints]

        raw_outpoints = [(bytes(txid), int(vout)) for txid, vout in outpoints]
        py_utxos = self._db.get_utxo_batch(raw_outpoints)
        results: list[dict[str, Any] | None] = []
        for py_utxo in py_utxos:
            if py_utxo is None:
                results.append(None)
            else:
                results.append({
                    'txid': py_utxo.txid,
                    'vout': py_utxo.vout,
                    'value': py_utxo.value,
                    'script_pubkey': bytes(py_utxo.script_pubkey),
                    'height': getattr(py_utxo, 'height', None),
                    'is_coinbase': getattr(py_utxo, 'is_coinbase', False),
                })
        return results

    def store_block(self, block: Block) -> None:
        """Not implemented — use the Rust API via FastSync or BlockSync instead."""
        raise NotImplementedError(
            "store_block requires BlockWrapper reconstruction. "
            "Use Rust API directly via FastSync.store_block() or BlockSync"
        )

    def disconnect_block(self, height: int) -> bytes:
        """
        Disconnect the block at the given height — reverse all UTXO changes.

        For each transaction (processed in reverse order):
          - Outputs created by this block are removed from the UTXO set.
          - Inputs spent by this block are restored from undo data stored
            during ``apply_block()`` (full UTXO serialization in SPENT_CF).
        The chain tip (BEST_BLOCK_HASH / BEST_HEIGHT) is rolled back to the
        previous block.

        Args:
            height: Block height to disconnect.

        Returns:
            The 32-byte hash of the disconnected block.

        Raises:
            RuntimeError: If the block is not found or the Rust API fails.

        NOTE (wave-33b dead-symbol audit, TIER-3): This Python-layer wrapper
        has ZERO live callers from ouroboros Python code. The reorg path uses
        the Rust FFI directly via self._db (ferrous_utils.RocksDB). Any future
        Python-level reorg logic should call this method (not the Rust object
        directly) so cache invalidation stays consistent. Do not add consensus
        logic here — fixes belong in the Rust crate.
        """
        result = bytes(self._db.disconnect_block(height))
        # Invalidate cache — next get_best_block() will re-fetch from Rust
        self._cached_tip = None
        return result

    def recover_from_crash(self) -> bool:
        """
        Check for and recover from a mid-apply crash (two-phase commit).

        If a HEAD_BLOCKS marker exists, the previous process crashed during
        ``apply_block()``.  This method rolls back the partial apply by
        disconnecting the incomplete block and restoring the UTXO set.

        Should be called once at startup before any new blocks are applied.
        The Rust ``PyBlockchainDB`` constructor calls this automatically, so
        explicit calls are only needed when using a long-lived database handle
        that was opened before a crash occurred.

        Returns:
            True if a recovery was performed, False if the database was clean.
        """
        return self._db.recover_from_crash()

    def get_tx_index(self, txid: bytes) -> tuple[bytes, int, int] | None:
        """Look up a confirmed transaction; returns ``(block_hash, height, tx_position)`` or None."""
        if len(txid) != 32:
            raise ValueError("Transaction ID must be 32 bytes")
        result = self._db.get_tx_index(txid)
        if result is None:
            return None
        block_hash, height, tx_pos = result
        return (bytes(block_hash), height, tx_pos)

    def get_best_block(self) -> tuple[bytes, int]:
        """Return the current chain tip as ``(block_hash, height)``."""
        if self._cached_tip is not None:
            return self._cached_tip
        hash_bytes, height = self._db.get_best_block()
        self._cached_tip = (bytes(hash_bytes), height)
        return self._cached_tip

    def update_best_block(self, block_hash: bytes, height: int) -> None:
        """Update the chain tip pointer (used during reorg / snapshot load).

        Atomic: BEST_BLOCK_HASH and BEST_HEIGHT land together via a single
        WriteBatch on the Rust side (see ``storage/db.rs::update_best_block``).
        Pre-fix the two puts were independent and could tear under SIGKILL,
        leaving META_CF in a (hash=new, height=old) or (hash=old, height=new)
        intermediate state. Callers that already hold a batch (the connect /
        disconnect / loadSnapshot Rust paths) keep using
        ``update_best_block_batch`` so the tip update fuses with the rest of
        their write set. See CORE-PARITY-AUDIT/_chainstate-atomicity-family-2026-05-26.md.
        """
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        self._db.update_best_block(block_hash, height)
        self._cached_tip = (bytes(block_hash), height)

    def get_median_time_past(self, height: int) -> int | None:
        """Median timestamp of the 11 blocks up to *height* (BIP 68 / BIP 113 MTP).

        Uses the Rust backend's lightweight metadata lookup when available,
        falling back to full block deserialization otherwise.

        Returns ``None`` when the 11-block window ``[height-10 .. height]``
        is incomplete — i.e. at least one of those blocks is not in the
        index.  Bitcoin Core always has every header from genesis, so its
        MTP is ALWAYS the median of exactly ``min(11, height+1)`` blocks;
        a partial-window median is not the MTP and must not be returned.

        After an assumeUTXO snapshot load ouroboros only persists the
        snapshot block's own header — the 10 headers below the snapshot tip
        are absent.  For a height whose window reaches below the snapshot
        tip the pre-fix code (both here and in the Rust fast path) silently
        dropped the missing blocks and took the median of whatever remained.
        A truncated window is right-shifted toward the larger recent
        timestamps, so the computed "MTP" came out far too LARGE (by up to
        ~2200s near the boundary).  That over-large value fed BIP-68
        time-based relative-locktime evaluation and rejected valid blocks
        with "BIP 68 sequence lock not satisfied", permanently wedging IBD
        one block above the snapshot range (mainnet stall at h=948464,
        block 948465, 2026-05-20).

        Returning ``None`` here makes ``check_sequence_locks`` treat the
        coin time as 0, which lets the relative time-lock pass — the same
        outcome as the BIP-68 snapshot stopgap and consistent with the
        assumeUTXO trust model.  This wrapper enforces window-completeness
        itself rather than trusting the Rust return value, so the fix is
        effective even before the Rust extension is rebuilt.
        """
        start = max(0, height - 10)
        expected = height - start + 1

        # Fast path: Rust computes MTP from block metadata (no full block
        # deser).  Only trust the Rust value when the window is provably
        # complete — an older Rust build computes a partial-window median.
        window_complete = self._mtp_window_complete(start, height)
        if hasattr(self._db, 'get_median_time_past'):
            result = self._db.get_median_time_past(height)
            if result is not None and window_complete:
                return result

        # Window incomplete — refuse to fabricate an MTP from a partial set,
        # and DO NOT fall through to the deserializing slow path.  After an
        # assumeUTXO snapshot the 10 blocks below the snapshot base are not
        # in the index, so a window that dips below the base can never be
        # completed; deserializing the 1-2 present multi-MB blocks here once
        # per input of every v2+ tx (5767 txs in block 944186) is what
        # wedged forward-sync at the snapshot boundary — handle_block's
        # validation worker spun in get_block_by_height -> _py_block_to_block
        # and never finished a single block (the "block downloads timeout"
        # Known Issue surfaced by --connect to a single fast loopback peer).
        # The cheap height->hash probe in _mtp_window_complete already tells
        # us the window can't be completed, so bail here with None (coin
        # time 0 -> relative time-locks pass, consistent with the assumeUTXO
        # trust model and the BIP-68 snapshot stopgap) without touching a
        # single block body.
        if not window_complete:
            return None

        # Slow fallback (window provably complete but Rust fast path absent
        # or returned None): deserialize full blocks.  Reached only on a
        # genesis-IBD node lacking the Rust metadata MTP, never across the
        # snapshot boundary.
        timestamps = []
        for h in range(start, height + 1):
            block = self.get_block_by_height(h)
            if block is not None:
                timestamps.append(block.timestamp)
        # Incomplete window — refuse to fabricate an MTP from a partial set.
        if len(timestamps) < expected:
            return None
        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def _mtp_window_complete(self, start: int, height: int) -> bool:
        """True iff every block in ``[start .. height]`` is in the index.

        Used to decide whether the Rust ``get_median_time_past`` fast-path
        result can be trusted: an older Rust build silently medians a
        partial window.  Probes the cheap height->hash index rather than
        deserializing blocks.
        """
        for h in range(start, height + 1):
            try:
                if self.get_block_hash_by_height(h) is None:
                    return False
            except Exception:
                return False
        return True

    def get_balance(self, address: str, network: str = "mainnet") -> int:
        """Return total balance in satoshis for *address* (sum of matching UTXOs)."""
        from ouroboros.address import address_to_script_pubkey

        script_pubkey = address_to_script_pubkey(address, network)
        return self._balance_for_script_pubkey(script_pubkey)

    def list_unspent_by_address(
        self, address: str, network: str = "mainnet"
    ) -> list[dict[str, Any]]:
        """Return UTXOs for *address* as a list of dicts (txid, vout, value, script_pubkey)."""
        from ouroboros.address import address_to_script_pubkey

        script_pubkey = address_to_script_pubkey(address, network)
        return self._list_unspent_for_script_pubkey(script_pubkey)

    def _balance_for_script_pubkey(self, script_pubkey: bytes) -> int:
        total = 0
        for utxo in self._iter_matching_utxos(script_pubkey):
            total += utxo["value"]
        return total

    def _list_unspent_for_script_pubkey(self, script_pubkey: bytes) -> list[dict[str, Any]]:
        return list(self._iter_matching_utxos(script_pubkey))

    def _iter_matching_utxos(self, script_pubkey: bytes):
        try:
            py_utxos = self._db.get_utxos()
        except AttributeError:
            return
        for py_utxo in py_utxos:
            spk = bytes(py_utxo.script_pubkey)
            if spk == script_pubkey:
                txid_hex = py_utxo.txid if isinstance(py_utxo.txid, str) else py_utxo.txid.hex()
                yield {
                    "txid": txid_hex,
                    "vout": py_utxo.vout,
                    "value": py_utxo.value,
                    "script_pubkey": spk,
                }

    def get_block_hash_by_height(self, height: int) -> bytes | None:
        """Return the 32-byte block hash at *height*, or None if not found."""
        try:
            block_hash = self._db.get_block_hash_by_height(height)
            if block_hash is None:
                return None
            return bytes(block_hash)
        except Exception:
            # Fallback: get block by height and extract hash
            block = self.get_block_by_height(height)
            if block:
                h = getattr(block, "hash", None)
            if h is None:
                return None
            return bytes(h() if callable(h) else h)
            return None

    def get_chainwork_by_height(self, height: int) -> int:
        """Return cumulative chainwork at *height* (from Rust metadata), or 0 if missing."""
        try:
            cw_bytes = bytes(self._db.get_chainwork_by_height(height))
        except AttributeError:
            # Rust module not yet rebuilt with get_chainwork_by_height
            return 0
        if len(cw_bytes) != 32:
            return 0
        return int.from_bytes(cw_bytes, "big")

    def store_block_metadata_persistent(
        self, height: int, block_hash: bytes, chainwork: int, timestamp: int
    ) -> None:
        """Persist BlockMetadata (height, chainwork, timestamp) for *block_hash*.

        Writes through to the Rust ``store_block_metadata_raw``, which lands
        the row in BOTH the height-keyed ``BLOCK_INDEX_CF`` and the
        hash-keyed ``BLOCK_INDEX_BY_HASH_CF``.  Unlike ``store_block_chainwork``
        (in-memory cache only) this survives a restart and is what
        ``get_chainwork_by_height`` reads back.

        Used by the assumeUTXO snapshot loader so the snapshot block carries
        its true cumulative chainwork — without it, the first block connected
        above the snapshot reads a missing ``prev_chainwork`` and the whole
        post-snapshot chain accumulates work from 0 (see snapshot.py).

        ``chainwork`` is a non-negative integer; it is stored as 32-byte
        big-endian (Bitcoin Core display order), matching the encoding
        ``connect_block_from_bytes`` uses.
        """
        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")
        if chainwork < 0:
            raise ValueError("chainwork must be non-negative")
        cw_bytes = int(chainwork).to_bytes(32, "big")
        self._db.store_block_metadata_raw(
            height, block_hash, height, cw_bytes, timestamp
        )

    def store_block_chainwork(self, block_hash: bytes, chainwork: int) -> None:
        """Cache chainwork for *block_hash* in memory (fallback when Rust metadata is unavailable)."""
        if not hasattr(self, "_chainwork_cache"):
            self._chainwork_cache: dict[bytes, int] = {}

        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        self._chainwork_cache[block_hash] = chainwork

    def get_block_chainwork(self, block_hash: bytes, height: int | None = None) -> int:
        """Return chainwork for a block; prefers Rust metadata, falls back to in-memory cache."""
        if height is not None:
            persisted = self.get_chainwork_by_height(height)
            if persisted > 0:
                return persisted

        if not hasattr(self, "_chainwork_cache"):
            self._chainwork_cache = {}

        if len(block_hash) != 32:
            raise ValueError("Block hash must be 32 bytes")

        return self._chainwork_cache.get(block_hash, 0)

    def connect_block_from_bytes(self, block_bytes: bytes, height: int) -> bytes:
        """Connect a block via Rust FFI and update the cached chain tip.

        Wraps ``_db.connect_block_from_bytes`` so that every call site that
        connects a block through this method automatically keeps the
        in-memory tip cache consistent.

        Returns the block hash (bytes) as returned by the Rust layer.
        """
        result = self._db.connect_block_from_bytes(block_bytes, height)
        # Invalidate cache so next get_best_block() re-reads from Rust.
        # We don't know the hash here without parsing, so just invalidate.
        self._cached_tip = None

        # Extract header-level fields from the raw block bytes so that
        # RPC handlers can serve them without a full-block FFI round-trip.
        # Bitcoin block header: version(4) + prevhash(32) + merkle(32) +
        #                       timestamp(4) + bits(4) + nonce(4) = 80 bytes
        if len(block_bytes) >= 80:
            import struct
            ts = struct.unpack_from("<I", block_bytes, 68)[0]
            bits = struct.unpack_from("<I", block_bytes, 72)[0]
            self._tip_bits = bits
            self._tip_timestamp = ts
            self._recent_timestamps.append(ts)
            # Keep only the last 11 timestamps for median-time calculation
            if len(self._recent_timestamps) > 11:
                self._recent_timestamps = self._recent_timestamps[-11:]
            # Accumulate chain work from bits (compact target)
            # work = 2^256 / (target + 1)
            mantissa = bits & 0x007FFFFF
            exponent = (bits >> 24) & 0xFF
            if mantissa > 0:
                if exponent <= 3:
                    target = mantissa >> (8 * (3 - exponent))
                else:
                    target = mantissa << (8 * (exponent - 3))
                if target > 0:
                    self._cached_chainwork += (2**256) // (target + 1)

        return result

    def validate_block_from_bytes(
        self,
        block_bytes: bytes,
        prev_height: int,
        skip_scripts: bool,
        network: str,
    ) -> None:
        """Validate a block via the off-GIL Rust fast path (B3 Stage 1).

        Thin passthrough to ``_db.validate_block_from_bytes``.  The Rust
        side deserialises, validates, and releases the GIL for the duration
        of the call.  No DB writes; caller still must apply/connect the
        block separately on success.

        Raises ``ValueError`` on any validation failure.
        """
        self._db.validate_block_from_bytes(
            block_bytes, prev_height, skip_scripts, network
        )

    def refresh_tip_cache(self) -> tuple[bytes, int]:
        """Force-refresh the cached tip from Rust and return it."""
        hash_bytes, height = self._db.get_best_block()
        self._cached_tip = (bytes(hash_bytes), height)
        return self._cached_tip

    # Pruning (delegated to Rust)

    def prune_blocks_range(self, from_height: int, to_height: int) -> int:
        """Delete raw block data for heights [from_height, to_height].
        Block index (headers/metadata) is preserved. Returns count removed."""
        return self._db.prune_blocks_range(from_height, to_height)

    def prune_block_at_height(self, height: int) -> bool:
        """Delete raw block data at *height*. Returns True if removed."""
        return self._db.prune_block_at_height(height)

    def get_prune_height(self) -> int:
        """Lowest height whose block body is still available (0 = never pruned)."""
        return self._db.get_prune_height()

    def has_block_data(self, height: int) -> bool:
        """True when the full block body exists for *height*."""
        return self._db.has_block_data(height)

    def estimate_blocks_size(self) -> int:
        """Approximate total bytes of all block bodies in RocksDB."""
        return self._db.estimate_blocks_size()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Database operations are already atomic via RocksDB
        return False

    def _py_block_to_block(self, py_block) -> Block:
        # Type hint: py_block should be sync.PyBlock if available
        """Convert PyBlock to Block"""
        transactions = []
        for py_tx in py_block.transactions:
            inputs = [
                TxIn(
                    prev_txid=bytes(py_in.prev_txid),
                    prev_vout=py_in.prev_vout,
                    script_sig=bytes(py_in.script_sig),
                    sequence=py_in.sequence,
                )
                for py_in in py_tx.inputs
            ]
            outputs = [
                TxOut(
                    value=py_out.value,
                    script_pubkey=bytes(py_out.script_pubkey),
                )
                for py_out in py_tx.outputs
            ]
            transactions.append(Transaction(
                txid=bytes(py_tx.txid),
                version=py_tx.version,
                locktime=py_tx.locktime,
                inputs=inputs,
                outputs=outputs,
            ))

        return Block(
            version=py_block.version,
            prev_blockhash=bytes(py_block.prev_blockhash),
            merkle_root=bytes(py_block.merkle_root),
            timestamp=py_block.timestamp,
            bits=py_block.bits,
            nonce=py_block.nonce,
            transactions=transactions,
            hash=bytes(py_block.hash() if callable(getattr(py_block, "hash", None)) else py_block.hash),
            height=getattr(py_block, 'height', None),
        )
