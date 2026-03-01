"""
ZeroMQ notification publisher.

Publishes real-time events over ZMQ PUB sockets for external
consumers (block explorers, wallets, monitoring, etc.).

Topics:
  - ``hashblock``  — 32-byte block hash (on new tip)
  - ``hashtx``     — 32-byte txid (on mempool acceptance)
  - ``rawblock``   — full serialised block
  - ``rawtx``      — full serialised transaction

Usage::

    pub = ZMQPublisher("tcp://127.0.0.1:28332")
    await pub.start()
    pub.notify_block(block)
    pub.notify_transaction(tx)
    await pub.stop()

Reference: bitcoin/src/zmq/
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy-import zmq so the rest of the codebase works without pyzmq
_zmq = None


def _ensure_zmq():
    global _zmq
    if _zmq is None:
        try:
            import zmq
            import zmq.asyncio
            _zmq = zmq
        except ImportError:
            raise ImportError(
                "pyzmq is required for ZMQ notifications. "
                "Install it with: pip install pyzmq"
            )
    return _zmq


class ZMQPublisher:
    """
    Publishes blockchain events over ZeroMQ PUB sockets.

    Each notification is a multi-part ZMQ message::

        [topic, body, sequence_le32]

    where *sequence* is a per-topic counter (uint32 little-endian).
    """

    TOPIC_HASH_BLOCK = b"hashblock"
    TOPIC_HASH_TX = b"hashtx"
    TOPIC_RAW_BLOCK = b"rawblock"
    TOPIC_RAW_TX = b"rawtx"

    def __init__(self, endpoint: str = "tcp://127.0.0.1:28332"):
        self.endpoint = endpoint
        self._socket: Optional[object] = None
        self._context: Optional[object] = None
        self._sequences: dict[bytes, int] = {
            self.TOPIC_HASH_BLOCK: 0,
            self.TOPIC_HASH_TX: 0,
            self.TOPIC_RAW_BLOCK: 0,
            self.TOPIC_RAW_TX: 0,
        }
        self._started = False

    async def start(self) -> None:
        zmq = _ensure_zmq()
        self._context = zmq.asyncio.Context()
        self._socket = self._context.socket(zmq.PUB)
        self._socket.bind(self.endpoint)
        self._started = True
        logger.info(f"ZMQ publisher bound to {self.endpoint}")

    async def stop(self) -> None:
        if self._socket is not None:
            self._socket.close()
        if self._context is not None:
            self._context.term()
        self._started = False
        logger.info("ZMQ publisher stopped")

    def _publish(self, topic: bytes, data: bytes) -> None:
        if not self._started or self._socket is None:
            return
        seq = self._sequences.get(topic, 0)
        self._socket.send_multipart([topic, data, struct.pack("<I", seq)])
        self._sequences[topic] = (seq + 1) & 0xFFFFFFFF

    # public notification API

    def notify_block(self, block) -> None:
        """Publish hashblock and rawblock for a new block."""
        block_hash = block.hash if hasattr(block, "hash") else b"\x00" * 32
        if isinstance(block_hash, str):
            block_hash = bytes.fromhex(block_hash)
        self._publish(self.TOPIC_HASH_BLOCK, block_hash)
        try:
            raw = block.serialize()
            self._publish(self.TOPIC_RAW_BLOCK, raw)
        except Exception:
            pass

    def notify_transaction(self, tx) -> None:
        """Publish hashtx and rawtx for a new mempool transaction."""
        txid = tx.get_txid() if hasattr(tx, "get_txid") else tx.txid
        if isinstance(txid, str):
            txid = bytes.fromhex(txid)
        self._publish(self.TOPIC_HASH_TX, txid)
        try:
            raw = tx.serialize()
            self._publish(self.TOPIC_RAW_TX, raw)
        except Exception:
            pass

    @property
    def is_running(self) -> bool:
        return self._started
