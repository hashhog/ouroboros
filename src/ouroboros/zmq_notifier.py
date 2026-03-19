"""
ZeroMQ notification publisher.

Publishes real-time events over ZMQ PUB sockets for external
consumers (block explorers, wallets, monitoring, etc.).

Topics:
  - ``hashblock``  -- 32-byte block hash (on new tip)
  - ``hashtx``     -- 32-byte txid (on mempool acceptance)
  - ``rawblock``   -- full serialised block
  - ``rawtx``      -- full serialised transaction
  - ``sequence``   -- mempool add/remove and block connect/disconnect events

The ``sequence`` topic provides fine-grained notifications for mempool and
chain changes. Each message body is: 32-byte hash + 1-byte label + optional
8-byte mempool sequence number (little-endian).

Labels:
  - 'A' = mempool Acceptance (tx added)
  - 'R' = mempool Removal (tx evicted/mined)
  - 'C' = block Connected (new tip)
  - 'D' = block Disconnected (reorg)

Usage::

    notifier = ZMQNotifier()
    notifier.configure_endpoint("hashblock", "tcp://127.0.0.1:28332")
    notifier.configure_endpoint("hashtx", "tcp://127.0.0.1:28332")
    notifier.configure_endpoint("sequence", "tcp://127.0.0.1:28333")
    await notifier.start()

    # Block notifications
    notifier.notify_block(block)
    notifier.notify_block_disconnect(block_hash)

    # Transaction notifications
    notifier.notify_transaction(tx, mempool_sequence=123)
    notifier.notify_transaction_removed(txid, mempool_sequence=124)

    await notifier.stop()

Reference: bitcoin/src/zmq/zmqpublishnotifier.cpp
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Optional, Dict

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


class ZMQNotifier:
    """
    Publishes blockchain events over ZeroMQ PUB sockets.

    Each notification is a multi-part ZMQ message::

        [topic, body, sequence_le32]

    where *sequence* is a per-topic counter (uint32 little-endian).

    Unlike the simpler ZMQPublisher, this class supports:
    - Per-topic endpoint configuration
    - Shared sockets when multiple topics use the same endpoint
    - The ``sequence`` topic with mempool and block events
    """

    TOPIC_HASH_BLOCK = b"hashblock"
    TOPIC_HASH_TX = b"hashtx"
    TOPIC_RAW_BLOCK = b"rawblock"
    TOPIC_RAW_TX = b"rawtx"
    TOPIC_SEQUENCE = b"sequence"

    # Sequence topic labels (Bitcoin Core convention)
    LABEL_MEMPOOL_ACCEPT = ord('A')
    LABEL_MEMPOOL_REMOVE = ord('R')
    LABEL_BLOCK_CONNECT = ord('C')
    LABEL_BLOCK_DISCONNECT = ord('D')

    def __init__(self):
        # topic -> endpoint URL
        self._topic_endpoints: Dict[bytes, str] = {}
        # endpoint URL -> socket
        self._sockets: Dict[str, object] = {}
        self._context: Optional[object] = None
        # per-topic sequence numbers (uint32)
        self._sequences: Dict[bytes, int] = {
            self.TOPIC_HASH_BLOCK: 0,
            self.TOPIC_HASH_TX: 0,
            self.TOPIC_RAW_BLOCK: 0,
            self.TOPIC_RAW_TX: 0,
            self.TOPIC_SEQUENCE: 0,
        }
        self._started = False

    def configure_endpoint(self, topic: str, endpoint: str) -> None:
        """
        Configure the ZMQ endpoint for a topic.

        Args:
            topic: One of "hashblock", "hashtx", "rawblock", "rawtx", "sequence"
            endpoint: ZMQ endpoint URL, e.g. "tcp://127.0.0.1:28332"
        """
        topic_bytes = topic.encode() if isinstance(topic, str) else topic
        self._topic_endpoints[topic_bytes] = endpoint

    def has_topic(self, topic: bytes) -> bool:
        """Check if a topic is configured."""
        return topic in self._topic_endpoints

    async def start(self) -> None:
        """Start the ZMQ publisher, binding sockets for all configured topics."""
        if not self._topic_endpoints:
            logger.debug("No ZMQ topics configured, skipping start")
            return

        zmq = _ensure_zmq()
        self._context = zmq.asyncio.Context()

        # Group topics by endpoint to share sockets
        endpoint_topics: Dict[str, list] = {}
        for topic, endpoint in self._topic_endpoints.items():
            endpoint_topics.setdefault(endpoint, []).append(topic)

        # Create one socket per unique endpoint
        for endpoint, topics in endpoint_topics.items():
            socket = self._context.socket(zmq.PUB)
            # Set high water mark (matches Bitcoin Core default)
            socket.setsockopt(zmq.SNDHWM, 1000)
            # Enable TCP keepalive
            socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
            socket.bind(endpoint)
            self._sockets[endpoint] = socket
            logger.info(
                f"ZMQ publisher bound to {endpoint} for topics: "
                f"{[t.decode() for t in topics]}"
            )

        self._started = True
        logger.info(f"ZMQ notifier started with {len(self._sockets)} socket(s)")

    async def stop(self) -> None:
        """Stop the ZMQ publisher and close all sockets."""
        if not self._started:
            return

        for endpoint, socket in self._sockets.items():
            try:
                socket.setsockopt(_zmq.LINGER, 0)
                socket.close()
            except Exception as e:
                logger.warning(f"Error closing ZMQ socket {endpoint}: {e}")

        if self._context is not None:
            try:
                self._context.term()
            except Exception as e:
                logger.warning(f"Error terminating ZMQ context: {e}")

        self._sockets.clear()
        self._context = None
        self._started = False
        logger.info("ZMQ notifier stopped")

    def _get_socket(self, topic: bytes) -> Optional[object]:
        """Get the socket for a topic, or None if not configured."""
        endpoint = self._topic_endpoints.get(topic)
        if endpoint is None:
            return None
        return self._sockets.get(endpoint)

    def _publish(self, topic: bytes, data: bytes) -> None:
        """Publish a multi-part message: [topic, body, sequence_le32]."""
        if not self._started:
            return

        socket = self._get_socket(topic)
        if socket is None:
            return

        seq = self._sequences.get(topic, 0)
        try:
            socket.send_multipart([topic, data, struct.pack("<I", seq)])
            self._sequences[topic] = (seq + 1) & 0xFFFFFFFF
        except Exception as e:
            logger.warning(f"Failed to publish ZMQ message on {topic.decode()}: {e}")

    # --------------------------------------------------------------------------
    # Block notifications
    # --------------------------------------------------------------------------

    def notify_block(self, block) -> None:
        """
        Publish hashblock, rawblock, and sequence (connect) for a new block.

        Args:
            block: Block object with .hash (bytes) and .serialize() method
        """
        block_hash = self._get_block_hash(block)

        # hashblock: 32-byte hash in internal byte order
        if self.has_topic(self.TOPIC_HASH_BLOCK):
            self._publish(self.TOPIC_HASH_BLOCK, block_hash)

        # rawblock: full serialized block
        if self.has_topic(self.TOPIC_RAW_BLOCK):
            try:
                raw = block.serialize()
                self._publish(self.TOPIC_RAW_BLOCK, raw)
            except Exception as e:
                logger.debug(f"Could not serialize block for rawblock: {e}")

        # sequence: block connect event
        if self.has_topic(self.TOPIC_SEQUENCE):
            self._publish_sequence(block_hash, self.LABEL_BLOCK_CONNECT)

    def notify_block_disconnect(self, block_hash: bytes) -> None:
        """
        Publish sequence (disconnect) event for a block being disconnected (reorg).

        Args:
            block_hash: 32-byte block hash in internal byte order
        """
        if isinstance(block_hash, str):
            block_hash = bytes.fromhex(block_hash)

        # Only sequence topic gets disconnect events
        if self.has_topic(self.TOPIC_SEQUENCE):
            self._publish_sequence(block_hash, self.LABEL_BLOCK_DISCONNECT)

    # --------------------------------------------------------------------------
    # Transaction notifications
    # --------------------------------------------------------------------------

    def notify_transaction(
        self,
        tx,
        mempool_sequence: Optional[int] = None,
    ) -> None:
        """
        Publish hashtx, rawtx, and sequence (accept) for a new mempool transaction.

        Args:
            tx: Transaction object with .get_txid() and .serialize() methods
            mempool_sequence: Optional mempool sequence number for the sequence topic
        """
        txid = self._get_txid(tx)

        # hashtx: 32-byte txid
        if self.has_topic(self.TOPIC_HASH_TX):
            self._publish(self.TOPIC_HASH_TX, txid)

        # rawtx: full serialized transaction
        if self.has_topic(self.TOPIC_RAW_TX):
            try:
                raw = tx.serialize()
                self._publish(self.TOPIC_RAW_TX, raw)
            except Exception as e:
                logger.debug(f"Could not serialize tx for rawtx: {e}")

        # sequence: mempool acceptance event
        if self.has_topic(self.TOPIC_SEQUENCE):
            self._publish_sequence(
                txid,
                self.LABEL_MEMPOOL_ACCEPT,
                mempool_sequence=mempool_sequence,
            )

    def notify_transaction_removed(
        self,
        txid: bytes,
        mempool_sequence: Optional[int] = None,
    ) -> None:
        """
        Publish sequence (remove) event for a transaction removed from mempool.

        Args:
            txid: 32-byte transaction ID
            mempool_sequence: Optional mempool sequence number
        """
        if isinstance(txid, str):
            txid = bytes.fromhex(txid)

        # Only sequence topic gets removal events
        if self.has_topic(self.TOPIC_SEQUENCE):
            self._publish_sequence(
                txid,
                self.LABEL_MEMPOOL_REMOVE,
                mempool_sequence=mempool_sequence,
            )

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    def _publish_sequence(
        self,
        hash_bytes: bytes,
        label: int,
        mempool_sequence: Optional[int] = None,
    ) -> None:
        """
        Publish a sequence topic message.

        Message format:
            - 32 bytes: hash (block hash or txid)
            - 1 byte: label ('A', 'R', 'C', 'D')
            - [optional] 8 bytes: mempool sequence number (LE uint64)

        Args:
            hash_bytes: 32-byte hash
            label: Single byte label
            mempool_sequence: Optional 8-byte mempool sequence number
        """
        if mempool_sequence is not None:
            # 32 + 1 + 8 = 41 bytes
            data = hash_bytes + bytes([label]) + struct.pack("<Q", mempool_sequence)
        else:
            # 32 + 1 = 33 bytes
            data = hash_bytes + bytes([label])

        self._publish(self.TOPIC_SEQUENCE, data)

    def _get_block_hash(self, block) -> bytes:
        """Extract block hash from a block object."""
        if hasattr(block, "hash"):
            h = block.hash
        elif hasattr(block, "get_hash"):
            h = block.get_hash()
        else:
            return b"\x00" * 32

        if isinstance(h, str):
            return bytes.fromhex(h)
        return h

    def _get_txid(self, tx) -> bytes:
        """Extract txid from a transaction object."""
        if hasattr(tx, "get_txid"):
            txid = tx.get_txid()
        elif hasattr(tx, "txid"):
            txid = tx.txid
        else:
            return b"\x00" * 32

        if isinstance(txid, str):
            return bytes.fromhex(txid)
        return txid

    @property
    def is_running(self) -> bool:
        """Check if the notifier is running."""
        return self._started


# Backward compatibility alias
ZMQPublisher = ZMQNotifier
