"""
JSON-RPC server implementation using FastAPI.

This module implements a Bitcoin-compatible JSON-RPC server for the node,
supporting standard Bitcoin RPC methods.
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from typing import Dict, Any, List, Optional, Union
import json
import logging
import statistics
import time
from collections import defaultdict
from pydantic import BaseModel

from ouroboros.database import Transaction, TxIn, TxOut, Block
from ouroboros.script import disassemble_script
from ouroboros.metrics import record_rpc_request
from ouroboros.blockfilter import (
    build_basic_filter,
    compute_filter_header,
    compute_filter_hash,
    BlockFilterIndex,
)
from ouroboros.validation import (
    _count_legacy_sigops,
    _get_p2sh_sigops,
    _count_witness_sigops,
    _is_p2sh,
    _get_last_push,
    WITNESS_SCALE_FACTOR,
)

logger = logging.getLogger(__name__)

# Rate limiting
_rate_limit_store: Dict[str, List[float]] = defaultdict(list)
_rate_limit_window = 60.0  # 1 minute
_rate_limit_max_requests = 100


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 request model"""
    jsonrpc: str = "2.0"
    method: str
    params: Union[List[Any], Dict[str, Any]] = []
    id: Optional[Union[int, str]] = None


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 response model"""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[Union[int, str]] = None



# ---------------------------------------------------------------------------
# Partial Merkle tree helpers (CMerkleBlock serialization / deserialization)
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import math as _math
import struct as _struct


def _dsha256(data: bytes) -> bytes:
    return _hashlib.sha256(_hashlib.sha256(data).digest()).digest()


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return _struct.pack('<B', n)
    elif n <= 0xFFFF:
        return b'\xfd' + _struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + _struct.pack('<I', n)
    else:
        return b'\xff' + _struct.pack('<Q', n)


def _read_varint(data: bytes, offset: int) -> tuple:
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return _struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return _struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return _struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


def _tree_width(n_tx: int, height: int) -> int:
    return (n_tx + (1 << height) - 1) >> height


def _calc_tree_hash(txids: list, n_tx: int, height: int, pos: int) -> bytes:
    if height == 0:
        return txids[pos] if pos < n_tx else b'\x00' * 32
    left = _calc_tree_hash(txids, n_tx, height - 1, pos * 2)
    right_pos = pos * 2 + 1
    if right_pos < _tree_width(n_tx, height - 1):
        right = _calc_tree_hash(txids, n_tx, height - 1, right_pos)
    else:
        right = left
    return _dsha256(left + right)


def _build_partial_merkle_tree(block, txids: list, matches: list) -> bytes:
    """Serialize a partial Merkle tree in the CMerkleBlock wire format."""
    n = len(txids)
    height = 0
    while (1 << height) < n:
        height += 1

    hashes: list = []
    bits: list = []

    def _traverse(h: int, pos: int):
        start = pos << h
        end = min((pos + 1) << h, n)
        parent_match = any(matches[i] for i in range(start, end))
        bits.append(parent_match)

        if h == 0 or not parent_match:
            if h == 0:
                hashes.append(txids[pos] if pos < n else b'\x00' * 32)
            else:
                hashes.append(_calc_tree_hash(txids, n, h, pos))
        else:
            _traverse(h - 1, pos * 2)
            if pos * 2 + 1 < _tree_width(n, h - 1):
                _traverse(h - 1, pos * 2 + 1)

    _traverse(height, 0)

    result = bytearray(block.serialize()[:80])
    result += _struct.pack('<I', n)
    result += _encode_varint(len(hashes))
    for h in hashes:
        result += h
    flag_bytes = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            flag_bytes[i // 8] |= 1 << (i % 8)
    result += _encode_varint(len(flag_bytes))
    result += flag_bytes

    return bytes(result)


def _parse_partial_merkle_tree(data: bytes) -> tuple:
    """Deserialize a partial Merkle tree payload (everything after the."""
    offset = 0
    n_tx = _struct.unpack_from('<I', data, offset)[0]
    offset += 4

    n_hashes, offset = _read_varint(data, offset)
    hashes = []
    for _ in range(n_hashes):
        hashes.append(data[offset:offset + 32])
        offset += 32

    n_flag_bytes, offset = _read_varint(data, offset)
    flag_bits_raw = data[offset:offset + n_flag_bytes]

    all_bits = []
    for byte_val in flag_bits_raw:
        for bit_pos in range(8):
            all_bits.append(bool(byte_val & (1 << bit_pos)))

    height = 0
    while (1 << height) < n_tx:
        height += 1

    hash_idx = [0]
    bit_idx = [0]
    matched: list = []

    def _consume(h: int, pos: int) -> bytes:
        if bit_idx[0] >= len(all_bits):
            return b'\x00' * 32
        parent_match = all_bits[bit_idx[0]]
        bit_idx[0] += 1

        if h == 0:
            cur_hash = hashes[hash_idx[0]] if hash_idx[0] < len(hashes) else b'\x00' * 32
            hash_idx[0] += 1
            if parent_match:
                matched.append(cur_hash)
            return cur_hash

        if not parent_match:
            cur_hash = hashes[hash_idx[0]] if hash_idx[0] < len(hashes) else b'\x00' * 32
            hash_idx[0] += 1
            return cur_hash

        left = _consume(h - 1, pos * 2)
        right_pos = pos * 2 + 1
        if right_pos < _tree_width(n_tx, h - 1):
            right = _consume(h - 1, right_pos)
        else:
            right = left
        return _dsha256(left + right)

    computed_root = _consume(height, 0)
    return matched, computed_root


class RPCServer:
    """Bitcoin JSON-RPC server"""
    
    def __init__(
        self,
        node: Any,
        port: int = 8332,
        username: Optional[str] = None,
        password: Optional[str] = None,
        rate_limit: bool = True
    ):
        """Initialize RPC server."""
        self.node = node
        self.port = port
        self.username = username
        self.password = password
        self.rate_limit_enabled = rate_limit
        
        self.app = FastAPI(title="Bitcoin Hybrid Node RPC")
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup security if credentials provided
        self.security = None
        if username and password:
            self.security = HTTPBasic()
        
        # Register RPC methods
        self._register_methods()
    
    def _register_methods(self):
        """Register all RPC methods"""
        @self.app.post("/")
        async def handle_rpc(
            request: JSONRPCRequest,
            http_request: Request
        ) -> JSONRPCResponse:
            """Handle JSON-RPC requests"""
            # Authentication
            if self.security:
                try:
                    credentials = await self._get_credentials(http_request)
                except HTTPException:
                    return JSONRPCResponse(
                        error={
                            "code": -32000,
                            "message": "Authentication required"
                        },
                        id=request.id
                    )
            
            # Rate limiting
            if self.rate_limit_enabled:
                client_ip = self._get_client_ip_from_request(http_request)
                if not self._check_rate_limit(client_ip):
                    return JSONRPCResponse(
                        error={
                            "code": -32000,
                            "message": "Rate limit exceeded"
                        },
                        id=request.id
                    )
            
            t0 = time.monotonic()
            try:
                # Get method handler
                method_name = f"rpc_{request.method}"
                method = getattr(self, method_name, None)
                
                if not method:
                    return JSONRPCResponse(
                        error={
                            "code": -32601,
                            "message": f"Method not found: {request.method}"
                        },
                        id=request.id
                    )
                
                # Call method with params
                if isinstance(request.params, list):
                    result = await method(*request.params)
                else:
                    result = await method(**request.params)
                
                return JSONRPCResponse(result=result, id=request.id)
                
            except HTTPException as e:
                return JSONRPCResponse(
                    error={
                        "code": -32603,
                        "message": e.detail
                    },
                    id=request.id
                )
            except Exception as e:
                logger.error(f"RPC error in {request.method}: {e}", exc_info=True)
                return JSONRPCResponse(
                    error={
                        "code": -32603,
                        "message": str(e)
                    },
                    id=request.id
                )
            finally:
                record_rpc_request(request.method, time.monotonic() - t0)
        
        @self.app.get("/health")
        async def health():
            """Health check endpoint"""
            return {"status": "healthy", "service": "bitcoin-rpc"}

        @self.app.get("/getblockstats")
        async def getblockstats(
            hash_or_height: str,
            stats: Optional[str] = None,
            http_request: Request = None,
        ):
            """GET endpoint for getblockstats.

            ``hash_or_height`` is passed as a query parameter (string).
            If it looks like an integer it is treated as a block height,
            otherwise it is treated as a block hash.

            ``stats`` is an optional comma-separated list of stat names to
            return.
            """
            # Coerce to int when possible
            parsed: Union[int, str]
            try:
                parsed = int(hash_or_height)
            except ValueError:
                parsed = hash_or_height

            stats_list: Optional[List[str]] = None
            if stats:
                stats_list = [s.strip() for s in stats.split(",") if s.strip()]

            return await self.rpc_getblockstats(parsed, stats_list)

        @self.app.get("/getblockfilter")
        async def getblockfilter_get(
            blockhash: str,
            filtertype: str = "basic",
        ):
            """GET endpoint for getblockfilter (BIP 157/158).

            ``blockhash`` is the hex-encoded block hash.
            ``filtertype`` is the filter type name (only ``basic`` supported).
            """
            return await self.rpc_getblockfilter(blockhash, filtertype)

    async def _get_credentials(self, request: Request) -> Optional[HTTPBasicCredentials]:
        if not self.security:
            return None
        
        try:
            credentials = await self.security(request)
            if credentials.username != self.username or credentials.password != self.password:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return credentials
        except Exception:
            raise HTTPException(status_code=401, detail="Authentication required")
    
    def _get_client_ip_from_request(self, request: Request) -> str:
        # Try to get real IP from headers (for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Fallback to direct client
        if request.client:
            return request.client.host
        
        return "127.0.0.1"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        now = time.time()
        requests = _rate_limit_store[client_ip]
        
        # Remove old requests outside window
        requests[:] = [req_time for req_time in requests if now - req_time < _rate_limit_window]
        
        # Check limit
        if len(requests) >= _rate_limit_max_requests:
            return False
        
        # Add current request
        requests.append(now)
        return True
    
    async def start(self):
        """Start RPC server"""
        import uvicorn
        config = uvicorn.Config(
            self.app,
            host="127.0.0.1",
            port=self.port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        logger.info(f"Starting RPC server on 127.0.0.1:{self.port}")
        await server.serve()
    
    # RPC Methods
    
    async def rpc_getblockchaininfo(self) -> Dict[str, Any]:
        """Return blockchain information"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")
        
        db = self.node.db if hasattr(self.node, 'db') else None
        if not db:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        best_hash, best_height = db.get_best_block()
        
        network = getattr(self.node, 'network', 'mainnet')
        if hasattr(self.node, 'config'):
            network = self.node.config.get('network', network)
        
        pruner = getattr(self.node, "pruner", None)
        pruned = pruner is not None and pruner.prune_height > 0

        info: Dict[str, Any] = {
            "chain": network,
            "blocks": best_height,
            "headers": best_height,
            "bestblockhash": best_hash.hex() if isinstance(best_hash, bytes) else best_hash,
            "difficulty": self.node.get_current_difficulty(),
            "mediantime": self.node.get_median_time(),
            "verificationprogress": 1.0 if self._is_synced() else 0.0,
            "chainwork": self.node.get_chainwork(),
            "pruned": pruned,
            "softforks": {},
        }

        if pruner is not None:
            info.update(pruner.get_prune_info())

        return info
    
    async def rpc_getblockcount(self) -> int:
        """Return block count"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")
        
        _, height = self.node.db.get_best_block()
        return height
    
    async def rpc_getbestblockhash(self) -> str:
        """Return best block hash"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")
        
        hash_bytes, _ = self.node.db.get_best_block()
        if isinstance(hash_bytes, bytes):
            return hash_bytes.hex()
        return str(hash_bytes)
    
    async def rpc_getblockhash(self, height: int) -> str:
        """Return block hash at height"""
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")
        
        block = self.node.db.get_block_by_height(height)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")
        
        block_hash = block.hash if hasattr(block, 'hash') else block.get_txid() if hasattr(block, 'get_txid') else None
        if isinstance(block_hash, bytes):
            return block_hash.hex()
        raise HTTPException(status_code=500, detail="Could not get block hash")
    
    async def rpc_getblock(
        self,
        blockhash: str,
        verbosity: int = 1
    ) -> Union[str, Dict[str, Any]]:
        """Return block information"""
        try:
            block_hash = bytes.fromhex(blockhash)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid block hash")
        
        if not hasattr(self.node, 'db'):
            raise HTTPException(status_code=500, detail="Database not available")
        
        block = self.node.db.get_block(block_hash)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")
        
        if verbosity == 0:
            # Return serialized block (hex)
            try:
                return block.serialize().hex()
            except:
                raise HTTPException(status_code=500, detail="Block serialization not implemented")
        
        elif verbosity == 1:
            block_height = getattr(block, 'height', None)
            return {
                "hash": blockhash,
                "confirmations": self._get_confirmations(block_height) if block_height else 0,
                "height": block_height if block_height else 0,
                "version": block.version,
                "merkleroot": block.merkle_root.hex() if isinstance(block.merkle_root, bytes) else str(block.merkle_root),
                "time": block.timestamp,
                "mediantime": self.node.get_median_time(block_height) if block_height is not None else block.timestamp,
                "nonce": block.nonce,
                "bits": hex(block.bits),
                "difficulty": self.node.get_difficulty(block.bits),
                "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0x0",
                "nTx": len(block.transactions) if hasattr(block, 'transactions') else 0,
                "previousblockhash": block.prev_blockhash.hex() if isinstance(block.prev_blockhash, bytes) else str(block.prev_blockhash),
                "nextblockhash": self._get_next_block_hash(block_height) if block_height is not None else None,
                "tx": [
                    tx.get_txid().hex() if hasattr(tx, 'get_txid') else str(tx.txid)
                    for tx in block.transactions
                ] if hasattr(block, 'transactions') else [],
            }
        else:  # verbosity == 2
            # Include full transaction data
            block_data = await self.rpc_getblock(blockhash, 1)
            if hasattr(block, 'transactions'):
                block_data["tx"] = [
                    self._tx_to_dict(tx) for tx in block.transactions
                ]
            return block_data
    
    async def rpc_getrawtransaction(
        self,
        txid: str,
        verbose: bool = False,
        blockhash: Optional[str] = None
    ) -> Union[str, Dict[str, Any]]:
        """Return raw transaction data.

        Searches the mempool first, then falls back to the on-disk
        transaction index.  If *blockhash* is provided the transaction
        is looked up directly inside that block.
        """
        try:
            tx_hash = bytes.fromhex(txid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid transaction ID")

        # 1. Mempool lookup (fast)
        if hasattr(self.node, 'mempool') and self.node.mempool:
            tx = self.node.mempool.get_transaction(tx_hash)
            if tx:
                if verbose:
                    return self._tx_to_dict(tx)
                return tx.serialize().hex()

        # 2. Blockchain lookup
        block = None
        block_hash_bytes = None
        block_height = None

        if blockhash is not None:
            # Caller supplied the containing block hash
            try:
                block_hash_bytes = bytes.fromhex(blockhash)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid block hash")
            block = self.node.db.get_block(block_hash_bytes)
            if block is None:
                raise HTTPException(status_code=404, detail="Block not found")
        else:
            # Use the transaction index for O(1) lookup
            try:
                loc = self.node.db.get_tx_index(tx_hash)
            except Exception:
                loc = None
            if loc is not None:
                block_hash_bytes, block_height, _tx_pos = loc
                block = self.node.db.get_block(block_hash_bytes)

        if block is not None:
            for tx in block.transactions:
                found_txid = tx.get_txid() if hasattr(tx, 'get_txid') else tx.txid
                if found_txid == tx_hash:
                    if verbose:
                        result = self._tx_to_dict(tx)
                        # Add block context fields for confirmed txs
                        if block_hash_bytes:
                            result["blockhash"] = block_hash_bytes.hex()
                        if block_height is not None:
                            result["confirmations"] = self._get_confirmations(block_height)
                            result["blocktime"] = block.timestamp
                            result["time"] = block.timestamp
                        elif block is not None:
                            result["blocktime"] = block.timestamp
                            result["time"] = block.timestamp
                        return result
                    return tx.serialize().hex()

        raise HTTPException(status_code=404, detail="Transaction not found")
    
    async def rpc_getmempoolinfo(self) -> Dict[str, Any]:
        """Return mempool information"""
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            return {
                "size": 0,
                "bytes": 0,
                "usage": 0,
                "maxmempool": 300_000_000,
                "mempoolminfee": 0.0,
                "minrelaytxfee": 0.00001,
            }
        
        info = self.node.mempool.get_mempool_info()
        return {
            "size": info['size'],
            "bytes": info['bytes'],
            "usage": info['bytes'],
            "maxmempool": info['max_size'],
            "mempoolminfee": info['min_fee_rate'] / 1e8 if info['min_fee_rate'] > 0 else 0.0,
            "minrelaytxfee": 0.00001,  # 1 sat/vbyte
        }
    
    async def rpc_sendrawtransaction(
        self,
        hexstring: str,
        maxfeerate: Optional[float] = None
    ) -> str:
        """
        Broadcast a raw transaction to the network.

        Accepts hex-encoded raw transaction, deserializes, adds to mempool,
        and broadcasts inv to peers. Peers that want the tx will send getdata;
        we respond with the full tx via the getdata handler.
        """
        try:
            tx_data = bytes.fromhex(hexstring.strip())
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")

        try:
            from ouroboros.p2p_messages import TxMessage, InvMessage, INV_TYPE_TX
        except ImportError:
            raise HTTPException(status_code=500, detail="P2P messages not available")

        try:
            tx_msg = TxMessage.from_payload(tx_data)
            tx = tx_msg.transaction
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid transaction: {e}")

        # Reject coinbase
        if tx.is_coinbase:
            raise HTTPException(status_code=400, detail="Coinbase transactions cannot be broadcast")

        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            raise HTTPException(status_code=500, detail="Mempool not available")

        _, best_height = self.node.db.get_best_block()
        success, error = self.node.mempool.add_transaction(tx, best_height)

        if not success:
            if error == "Already in mempool":
                return tx.txid.hex()
            raise HTTPException(status_code=400, detail=error)

        # Broadcast inv to peers
        txid = tx.txid
        inv = InvMessage(inventory=[(INV_TYPE_TX, txid)])
        inv_msg = inv.to_network_message(self.node.network)
        if hasattr(self.node, 'peer_manager') and self.node.peer_manager:
            await self.node.peer_manager.broadcast(inv_msg)

        return txid.hex()
    
    async def rpc_getnetworkinfo(self) -> Dict[str, Any]:
        """Return network information"""
        peers = []
        if hasattr(self.node, 'peer_manager'):
            if hasattr(self.node.peer_manager, 'get_all_ready_peers'):
                peers = self.node.peer_manager.get_all_ready_peers()
            elif hasattr(self.node.peer_manager, 'peers'):
                peers = list(self.node.peer_manager.peers.values()) if isinstance(self.node.peer_manager.peers, dict) else []
        
        return {
            "version": 240000,
            "subversion": "/bitcoin-hybrid:0.1.0/",
            "protocolversion": 70015,
            "connections": len(peers),
            "networkactive": True,
            "relayfee": 0.00001,
        }
    
    async def rpc_getrawmempool(self, verbose: bool = False) -> Union[List[str], Dict[str, Dict[str, Any]]]:
        """
        Get all transaction IDs in mempool.
        
        Args:
            verbose: If True, return detailed information for each transaction
            
        Returns:
            If verbose=False: List of transaction IDs (hex strings)
            If verbose=True: Dictionary mapping txid to transaction info
        """
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            return [] if not verbose else {}
        
        txids = list(self.node.mempool.transactions.keys())
        
        if not verbose:
            return [txid.hex() if isinstance(txid, bytes) else str(txid) for txid in txids]
        
        # Return detailed information
        result = {}
        for txid in txids:
            entry = self.node.mempool.get_transaction_entry(txid)
            if entry:
                txid_hex = txid.hex() if isinstance(txid, bytes) else str(txid)
                result[txid_hex] = self._format_mempool_entry(entry, txid)

        return result
    
    async def rpc_getblockheader(self, blockhash: str, verbose: bool = True) -> Union[str, Dict[str, Any]]:
        """
        Get block header information.
        
        Args:
            blockhash: Block hash (hex string)
            verbose: If True, return JSON object; if False, return hex-encoded header
            
        Returns:
            If verbose=True: Dictionary with header fields
            If verbose=False: Hex-encoded block header (80 bytes)
        """
        try:
            block_hash = bytes.fromhex(blockhash)
            if not hasattr(self.node, 'db') or not self.node.db:
                raise HTTPException(status_code=500, detail="Database not available")
            
            block = self.node.db.get_block(block_hash)
            
            if not block:
                raise HTTPException(status_code=404, detail="Block not found")
            
            if not verbose:
                # Return hex-encoded header (80 bytes)
                # Serialize block header
                header_data = bytearray()
                header_data.extend(block.version.to_bytes(4, 'little', signed=True))
                header_data.extend(block.prev_blockhash[::-1])  # Reverse for wire format
                header_data.extend(block.merkle_root[::-1])
                header_data.extend(block.timestamp.to_bytes(4, 'little'))
                header_data.extend(block.bits.to_bytes(4, 'little'))
                header_data.extend(block.nonce.to_bytes(4, 'little'))
                return header_data.hex()
            
            # Return verbose JSON
            block_height = block.height if hasattr(block, 'height') and block.height is not None else None
            
            # Get confirmations
            confirmations = 0
            if block_height is not None:
                best_hash, best_height = self.node.db.get_best_block()
                confirmations = max(0, best_height - block_height + 1) if best_height >= block_height else 0
            
            return {
                "hash": blockhash,
                "confirmations": confirmations,
                "height": block_height if block_height is not None else 0,
                "version": block.version,
                "versionHex": f"{block.version:08x}",
                "merkleroot": block.merkle_root.hex() if isinstance(block.merkle_root, bytes) else str(block.merkle_root),
                "time": block.timestamp,
                "mediantime": self.node.get_median_time(block_height) if block_height is not None else block.timestamp,
                "nonce": block.nonce,
                "bits": f"{block.bits:08x}",
                "difficulty": self.node.get_difficulty(block.bits),
                "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0x0",
                "previousblockhash": block.prev_blockhash.hex() if block.prev_blockhash != bytes(32) else None,
                "nextblockhash": self._get_next_block_hash(block_height) if block_height is not None else None
            }
        
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid block hash: {e}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting block header: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    async def rpc_getblockfilter(
        self, blockhash: str, filtertype: str = "basic"
    ) -> Dict[str, Any]:
        """
        Return the BIP 158 compact block filter for a block.

        Args:
            blockhash: Block hash (hex string).
            filtertype: Filter type name (only ``"basic"`` is supported).

        Returns:
            ``{"filter": "<hex>", "header": "<hex>"}``
        """
        if filtertype != "basic":
            raise HTTPException(
                status_code=400,
                detail=f"Unknown filtertype: {filtertype}. Only 'basic' is supported.",
            )

        try:
            block_hash = bytes.fromhex(blockhash)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid block hash: {e}")

        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        block = self.node.db.get_block(block_hash)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")

        # Build the basic filter (includes prevout lookups when db is available)
        filter_bytes = build_basic_filter(block, self.node.db)

        # Compute filter header.  For a full index the previous filter header
        # would come from the stored chain; here we use a zero prev-header as
        # a sane default when no persistent filter index is available.
        prev_header = b"\x00" * 32

        # If the node keeps a BlockFilterIndex, try to use it.
        bfi: Optional[BlockFilterIndex] = getattr(self.node, "block_filter_index", None)
        if bfi is not None:
            cached_filter = bfi.get_filter(block_hash)
            cached_header = bfi.get_header(block_hash)
            if cached_filter is not None and cached_header is not None:
                return {
                    "filter": cached_filter.hex(),
                    "header": cached_header.hex(),
                }
            # Look up previous filter header for chaining
            if block.prev_blockhash and block.prev_blockhash != bytes(32):
                prev_hdr = bfi.get_header(block.prev_blockhash)
                if prev_hdr is not None:
                    prev_header = prev_hdr

        filter_header = compute_filter_header(filter_bytes, prev_header)

        # Cache if index is available
        if bfi is not None:
            bfi._filters[block_hash] = filter_bytes
            bfi._headers[block_hash] = filter_header
            if block.height is not None:
                bfi._height_to_hash[block.height] = block_hash

        return {
            "filter": filter_bytes.hex(),
            "header": filter_header.hex(),
        }

    async def rpc_gettxout(self, txid: str, n: int, includemempool: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get UTXO information by outpoint.

        Args:
            txid: Transaction ID (hex string)
            n: Output index (vout)
            includemempool: If True, also check mempool

        Returns:
            Dictionary with UTXO information, or None if spent/not found
        """
        try:
            txid_bytes = bytes.fromhex(txid)
            
            # First check mempool if enabled
            if includemempool and hasattr(self.node, 'mempool') and self.node.mempool:
                # Check if transaction is in mempool
                if self.node.mempool.has_transaction(txid_bytes):
                    tx = self.node.mempool.get_transaction(txid_bytes)
                    if tx and n < len(tx.outputs):
                        output = tx.outputs[n]
                        script_pubkey_bytes = output.script_pubkey if isinstance(output.script_pubkey, bytes) else bytes(output.script_pubkey)
                        best_hash = None
                        if hasattr(self.node, 'db') and self.node.db:
                            try:
                                best_hash, _ = self.node.db.get_best_block()
                                best_hash = best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash)
                            except Exception:
                                pass
                        return {
                            "bestblock": best_hash,
                            "confirmations": 0,
                            "value": output.value / 100000000.0,  # Convert to BTC
                            "scriptPubKey": {
                                "asm": disassemble_script(script_pubkey_bytes),
                                "hex": output.script_pubkey.hex() if isinstance(output.script_pubkey, bytes) else str(output.script_pubkey),
                                "type": self._get_script_type(output.script_pubkey)
                            },
                            "coinbase": tx.is_coinbase,
                        }
            
            # Check database (confirmed UTXOs)
            if not hasattr(self.node, 'db') or not self.node.db:
                return None
            
            utxo = self.node.db.get_utxo(txid_bytes, n)
            if not utxo:
                return None
            
            # Get block height for confirmations
            # Try to find which block contains this transaction
            block_height = 0  # Placeholder - would need transaction index
            best_hash, best_height = self.node.db.get_best_block()
            confirmations = max(0, best_height - block_height + 1) if block_height else 0
            
            script_pubkey = utxo['script_pubkey']
            if isinstance(script_pubkey, bytes):
                script_hex = script_pubkey.hex()
                script_pubkey_bytes = script_pubkey
            else:
                script_hex = str(script_pubkey)
                script_pubkey_bytes = bytes(script_pubkey)
            
            coinbase = self._is_coinbase_output(txid_bytes)
            return {
                "bestblock": best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash),
                "confirmations": confirmations,
                "value": utxo['value'] / 100000000.0,  # Convert to BTC
                "scriptPubKey": {
                    "asm": disassemble_script(script_pubkey_bytes),
                    "hex": script_hex,
                    "type": self._get_script_type(script_pubkey)
                },
                "coinbase": coinbase,
            }
        
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid transaction ID: {e}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting txout: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    async def rpc_listunspent(
        self,
        minconf: int = 1,
        maxconf: int = 9999999,
        addresses: Optional[List[str]] = None,
        include_unsafe: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        List unspent outputs, optionally filtered by addresses.

        Args:
            minconf: Minimum confirmations (ignored for v1 - all confirmed)
            maxconf: Maximum confirmations
            addresses: Optional list of addresses to filter
            include_unsafe: Include untrusted outputs

        Returns:
            List of unspent output dicts
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return []

        network = getattr(self.node, 'network', 'mainnet')
        result = []

        if addresses:
            for addr in addresses:
                try:
                    utxos = self.node.db.list_unspent_by_address(addr, network)
                    for u in utxos:
                        result.append({
                            "txid": u["txid"],
                            "vout": u["vout"],
                            "scriptPubKey": u["script_pubkey"].hex(),
                            "amount": u["value"] / 100_000_000.0,
                            "confirmations": 1,  # In chainstate = confirmed
                            "spendable": True,
                        })
                except ValueError:
                    continue  # Skip invalid addresses
        else:
            # No address filter: would need to iterate all (expensive). Return empty for now.
            pass

        return result

    async def rpc_getnewaddress(
        self,
        label: str = "",
        address_type: str = "bech32",
    ) -> str:
        """
        Generate a new address.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")
        return await wallet.generate_new_address(label)

    async def rpc_sendtoaddress(
        self,
        address: str,
        amount: float,
        comment: str = "",
        comment_to: str = "",
        subtractfeefromamount: bool = False,
        conf_target: int = 6,
    ) -> str:
        """
        Send bitcoin to an address. Returns the txid.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")

        amount_sat = int(round(amount * 1e8))
        if amount_sat <= 0:
            raise HTTPException(status_code=400, detail="Invalid amount")

        fee_rate = None
        fee_estimator = getattr(self.node, "fee_estimator", None)
        if fee_estimator is not None:
            fee_rate = fee_estimator.estimate_fee(conf_target)
        if fee_rate is None:
            fee_rate = 2  # fallback: 2 sat/vB

        raw_hex = await wallet.send_transaction(
            address, amount_sat, int(fee_rate)
        )
        txid = await self.rpc_sendrawtransaction(raw_hex)
        return txid

    async def rpc_sethdseed(self, seed_hex: str = None) -> Dict[str, Any]:
        """
        Initialise the wallet in HD (BIP 32 / BIP 44) mode.

        If *seed_hex* is provided it is used as the master seed;
        otherwise a cryptographically random 32-byte seed is generated.
        """
        import os

        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "Wallet not loaded"}, id=None
            )

        if seed_hex is not None:
            try:
                seed = bytes.fromhex(seed_hex)
            except ValueError:
                return JSONRPCResponse(
                    error={"code": -8, "message": "seed_hex must be valid hex"},
                    id=None,
                )
            if not 16 <= len(seed) <= 64:
                return JSONRPCResponse(
                    error={
                        "code": -8,
                        "message": "Seed must be 16–64 bytes",
                    },
                    id=None,
                )
        else:
            seed = os.urandom(32)

        xprv = wallet.init_hd(seed)
        master = wallet.get_hd_master()
        return {
            "seed_hex": seed.hex(),
            "xprv": xprv,
            "xpub": master.serialize_xpub() if master else None,
            "message": "HD wallet initialized",
        }

    async def rpc_encryptwallet(self, passphrase: str) -> str:
        """
        Encrypt the wallet with a passphrase.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "Wallet not loaded"}, id=None
            )
        if wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an encrypted wallet, "
                    "but encryptwallet was called.",
                },
                id=None,
            )
        wallet.encrypt(passphrase)
        return (
            "wallet encrypted; The keypool has been flushed and a new HD seed "
            "was set. You need to make a new backup. Restart recommended."
        )

    async def rpc_walletpassphrase(
        self, passphrase: str, timeout: int = 60
    ) -> bool:
        """
        Unlock an encrypted wallet for *timeout* seconds.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "Wallet not loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletpassphrase was called.",
                },
                id=None,
            )
        try:
            wallet.unlock(passphrase)
        except ValueError:
            return JSONRPCResponse(
                error={
                    "code": -14,
                    "message": "Error: The wallet passphrase entered was incorrect.",
                },
                id=None,
            )
        return True

    async def rpc_walletlock(self) -> bool:
        """
        Lock the wallet, wiping the decryption key from memory.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "Wallet not loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletlock was called.",
                },
                id=None,
            )
        try:
            wallet.lock()
        except ValueError:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: wallet is already locked.",
                },
                id=None,
            )
        return True

    async def rpc_walletpassphrasechange(
        self, old_passphrase: str, new_passphrase: str
    ) -> bool:
        """
        Change the wallet passphrase.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            return JSONRPCResponse(
                error={"code": -18, "message": "Wallet not loaded"}, id=None
            )
        if not wallet.is_encrypted:
            return JSONRPCResponse(
                error={
                    "code": -15,
                    "message": "Error: running with an unencrypted wallet, "
                    "but walletpassphrasechange was called.",
                },
                id=None,
            )
        try:
            wallet.change_passphrase(old_passphrase, new_passphrase)
        except ValueError as exc:
            return JSONRPCResponse(
                error={"code": -14, "message": str(exc)}, id=None
            )
        return True

    async def rpc_getwalletinfo(self) -> Dict[str, Any]:
        """
        Return wallet state info.
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")

        balance = await wallet.get_balance()
        addresses = await wallet.get_addresses()

        info: Dict[str, Any] = {
            "walletname": wallet.name,
            "walletversion": 1,
            "balance": balance / 1e8,
            "unconfirmed_balance": 0.0,
            "immature_balance": 0.0,
            "txcount": 0,
            "keypoolsize": len(addresses),
            "paytxfee": 0.0,
            "hd": wallet.is_hd,
            "encrypted": wallet.is_encrypted,
            "locked": wallet.is_locked,
        }

        if wallet.is_hd:
            info["hd_next_index"] = wallet._hd_next_index
            master = wallet.get_hd_master()
            if master:
                info["hd_master_xpub"] = master.serialize_xpub()

        return info

    # PSBT RPCs (BIP 174)

    async def rpc_decodepsbt(self, psbt_base64: str) -> Dict[str, Any]:
        """
        Decode a base64-encoded PSBT into a human-readable dict.
        """
        import base64 as b64
        from ouroboros.psbt import PSBT

        try:
            raw = b64.b64decode(psbt_base64, validate=True)
        except Exception:
            return JSONRPCResponse(
                error={"code": -22, "message": "TX decode failed: invalid base64"},
                id=None,
            )
        try:
            psbt = PSBT.deserialize(raw)
        except Exception as exc:
            return JSONRPCResponse(
                error={"code": -22, "message": f"TX decode failed: {exc}"},
                id=None,
            )
        return psbt.decode()

    async def rpc_combinepsbt(self, psbts: List[str]) -> str:
        """
        Combine multiple base64-encoded PSBTs into one.
        """
        import base64 as b64
        from ouroboros.psbt import PSBT

        if not psbts or len(psbts) < 2:
            return JSONRPCResponse(
                error={"code": -8, "message": "At least two PSBTs required"},
                id=None,
            )
        try:
            decoded = [PSBT.deserialize(b64.b64decode(p, validate=True)) for p in psbts]
        except Exception as exc:
            return JSONRPCResponse(
                error={"code": -22, "message": f"TX decode failed: {exc}"},
                id=None,
            )
        combined = decoded[0]
        for other in decoded[1:]:
            combined = combined.combine(other)
        return b64.b64encode(combined.serialize()).decode("ascii")

    async def rpc_finalizepsbt(
        self, psbt_base64: str, extract: bool = True
    ) -> Dict[str, Any]:
        """
        Finalise a PSBT. If *extract* is true and all inputs are finalised,
        extract the network transaction.
        """
        import base64 as b64
        from ouroboros.psbt import PSBT

        try:
            raw = b64.b64decode(psbt_base64, validate=True)
            psbt = PSBT.deserialize(raw)
        except Exception as exc:
            return JSONRPCResponse(
                error={"code": -22, "message": f"TX decode failed: {exc}"},
                id=None,
            )

        psbt.finalize()

        complete = all(
            inp.final_script_sig is not None or inp.final_script_witness is not None
            for inp in psbt.inputs
        )

        if extract and complete:
            tx = psbt.extract_transaction()
            return {
                "hex": tx.serialize_with_witness().hex(),
                "complete": True,
            }
        return {
            "psbt": b64.b64encode(psbt.serialize()).decode("ascii"),
            "complete": complete,
        }

    async def rpc_createpsbt(
        self,
        inputs: List[Dict[str, Any]],
        outputs: List[Dict[str, Any]],
        locktime: int = 0,
    ) -> str:
        """
        Create an unsigned PSBT from raw inputs and outputs.

        *inputs*: ``[{"txid": "<hex>", "vout": <n>}, ...]``
        *outputs*: ``[{"<address>": <amount_sat>}, ...]``
        """
        import base64 as b64
        from ouroboros.psbt import PSBT
        from ouroboros.database import Transaction, TxIn, TxOut
        from ouroboros.address import address_to_script_pubkey

        tx_inputs: List[TxIn] = []
        for inp in inputs:
            txid = inp.get("txid", "")
            vout = inp.get("vout", 0)
            sequence = inp.get("sequence", 0xFFFFFFFF)
            try:
                prev_hash = bytes.fromhex(txid)
            except ValueError:
                return JSONRPCResponse(
                    error={"code": -8, "message": f"Invalid txid: {txid}"},
                    id=None,
                )
            tx_inputs.append(TxIn(
                prev_tx_hash=prev_hash,
                prev_output_index=vout,
                script_sig=b"",
                sequence=sequence,
            ))

        tx_outputs: List[TxOut] = []
        for out in outputs:
            for address, amount in out.items():
                try:
                    spk = address_to_script_pubkey(address)
                except Exception:
                    return JSONRPCResponse(
                        error={"code": -5, "message": f"Invalid address: {address}"},
                        id=None,
                    )
                tx_outputs.append(TxOut(value=int(amount), script_pubkey=spk))

        tx = Transaction(
            version=2,
            inputs=tx_inputs,
            outputs=tx_outputs,
            locktime=locktime,
        )
        psbt = PSBT.from_transaction(tx)
        return b64.b64encode(psbt.serialize()).decode("ascii")

    async def rpc_estimatesmartfee(
        self,
        conf_target: int = 6,
        estimate_mode: str = "economical",
    ) -> Dict[str, Any]:
        """
        Estimate the fee rate needed for a transaction to confirm
        within conf_target blocks.

        Returns:
            {"feerate": <BTC/kB>, "blocks": <conf_target>}
            or {"errors": [...], "blocks": <conf_target>}
        """
        conf_target = max(1, min(conf_target, 1008))

        fee_estimator = getattr(self.node, 'fee_estimator', None)
        if fee_estimator is None:
            return {
                "errors": ["Fee estimation not available"],
                "blocks": conf_target,
            }

        fee_rate = fee_estimator.estimate_fee_per_kb(conf_target)
        if fee_rate is None:
            return {
                "errors": ["Insufficient data for reliable estimate"],
                "blocks": conf_target,
            }

        return {
            "feerate": fee_rate,
            "blocks": conf_target,
        }

    async def rpc_validateaddress(self, address: str) -> Dict[str, Any]:
        """
        Validate a Bitcoin address and return information about it.
        """
        from ouroboros.address import address_to_script_pubkey

        result: Dict[str, Any] = {
            "isvalid": False,
            "address": address,
        }

        network = getattr(self.node, 'network', 'mainnet')

        try:
            script_pubkey = address_to_script_pubkey(address, network=network)
        except Exception:
            return result

        result["isvalid"] = True
        result["scriptPubKey"] = script_pubkey.hex()

        script_type = self._get_script_type(script_pubkey)
        result["isscript"] = script_type in ("scripthash", "witness_v0_scripthash")
        result["iswitness"] = script_type.startswith("witness_")

        if result["iswitness"]:
            result["witness_version"] = script_pubkey[0] if script_pubkey[0] != 0 else 0
            result["witness_program"] = script_pubkey[2:].hex()

        return result

    async def rpc_gettxoutproof(
        self,
        txids: List[str],
        blockhash: Optional[str] = None,
    ) -> str:
        """
        Return a hex-encoded Merkle proof that transactions were included
        in a block.

        Wire format (CMerkleBlock):
          block_header (80 bytes)
          total_transactions (uint32 LE)
          hash_count (varint) + hashes (32 bytes each)
          flag_byte_count (varint) + flag_bytes
        """
        if not txids:
            raise HTTPException(status_code=400, detail="txids must not be empty")

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        target_set = set()
        for txid_hex in txids:
            try:
                target_set.add(bytes.fromhex(txid_hex))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid txid: {txid_hex}")

        # Find the block
        block = None
        if blockhash:
            try:
                block = db.get_block(bytes.fromhex(blockhash))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid blockhash")
        else:
            _, best_height = db.get_best_block()
            for h in range(best_height, max(best_height - 100, -1), -1):
                b = db.get_block_by_height(h)
                if b is None:
                    continue
                block_txids = {tx.get_txid() for tx in b.transactions}
                if target_set & block_txids:
                    block = b
                    break

        if block is None:
            raise HTTPException(status_code=404, detail="Block not found")

        all_txids = [tx.get_txid() for tx in block.transactions]
        for t in target_set:
            if t not in all_txids:
                raise HTTPException(
                    status_code=400,
                    detail=f"Transaction {t.hex()} not found in block",
                )

        matches = [txid in target_set for txid in all_txids]
        proof = _build_partial_merkle_tree(block, all_txids, matches)
        return proof.hex()

    async def rpc_verifytxoutproof(self, proof: str) -> List[str]:
        """
        Verify a Merkle proof and return the proven txids.
        """
        import hashlib as _hl

        try:
            proof_bytes = bytes.fromhex(proof)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex")

        if len(proof_bytes) < 84:
            raise HTTPException(status_code=400, detail="Proof too short")

        header_bytes = proof_bytes[:80]
        block_hash = _hl.sha256(_hl.sha256(header_bytes).digest()).digest()

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        block = db.get_block(block_hash)
        if block is None:
            raise HTTPException(status_code=400, detail="Block not in chain")

        merkle_root_in_header = header_bytes[36:68]
        matched, computed_root = _parse_partial_merkle_tree(proof_bytes[80:])

        if computed_root != merkle_root_in_header:
            raise HTTPException(status_code=400, detail="Merkle root mismatch")

        return [txid.hex() for txid in matched]

    async def rpc_getmininginfo(self) -> Dict[str, Any]:
        """
        Return mining-related information.
        """
        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        _, height = db.get_best_block()
        mempool = getattr(self.node, "mempool", None)

        return {
            "blocks": height,
            "difficulty": self.node.get_current_difficulty(),
            "networkhashps": 0,
            "pooledtx": len(mempool.get_all_transactions()) if mempool else 0,
            "chain": getattr(self.node, "network", "mainnet"),
            "warnings": "",
        }

    async def rpc_getblocktemplate(self, template_request: Dict = None) -> Dict[str, Any]:
        """
        Construct a block template for mining (BIP 22 / BIP 23).

        Selects mempool transactions by fee rate (greedy), builds a
        coinbase, computes the merkle root, and returns the template
        for external miners.
        """
        import time as _time
        import hashlib as _hl

        db = getattr(self.node, "db", None)
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")

        mempool = getattr(self.node, "mempool", None)

        best_hash, best_height = db.get_best_block()
        best_block = db.get_block(best_hash)
        if best_block is None:
            raise HTTPException(status_code=500, detail="Cannot read tip block")

        next_height = best_height + 1

        # gather transactions from mempool (dependency-aware)
        MAX_BLOCK_WEIGHT = 4_000_000
        txs: List[Dict[str, Any]] = []
        total_fees = 0
        total_weight = 0

        if mempool:
            # Take a consistent snapshot so concurrent mutations don't
            # cause inconsistencies during template construction.
            snap_fee_rate, snap_txs = mempool.snapshot()

            # Build a parent-dependency map: txid → set of in-mempool parents
            in_mempool = set(snap_txs.keys())
            parents: Dict[bytes, set] = {}
            for txid_key, entry in snap_txs.items():
                tx_parents: set = set()
                for inp in entry.tx.inputs:
                    if inp.prev_txid in in_mempool:
                        tx_parents.add(inp.prev_txid)
                parents[txid_key] = tx_parents

            included: set = set()

            def _collect_ancestors(txid: bytes, already: set) -> List[bytes]:
                needed = []
                queue = [txid]
                visited = set()
                while queue:
                    t = queue.pop(0)
                    if t in visited or t in already:
                        continue
                    visited.add(t)
                    for p in parents.get(t, set()):
                        if p not in already:
                            queue.append(p)
                    needed.append(t)
                # Topological sort: ancestors before descendants
                ordered = []
                placed = set(already)
                remaining = list(needed)
                safety = len(remaining) * len(remaining) + 1
                while remaining and safety > 0:
                    safety -= 1
                    for t in list(remaining):
                        if parents.get(t, set()).issubset(placed):
                            ordered.append(t)
                            placed.add(t)
                            remaining.remove(t)
                return ordered

            # Compute ancestor fee rate for each mempool entry
            # ancestor_fee_rate = (entry.fee + sum(ancestor fees))
            #                   / (entry.size + sum(ancestor sizes))
            # Reference: Bitcoin Core BlockAssembler::addPackageTransactions()
            ancestor_fee_rates: Dict[bytes, float] = {}
            for txid_key, entry in snap_txs.items():
                # Collect full transitive ancestor set via BFS
                all_ancestors: set = set()
                queue = list(parents.get(txid_key, set()))
                while queue:
                    anc = queue.pop()
                    if anc in all_ancestors or anc not in snap_txs:
                        continue
                    all_ancestors.add(anc)
                    queue.extend(parents.get(anc, set()))
                ancestor_fee = entry.fee + sum(
                    snap_txs[a].fee for a in all_ancestors
                )
                ancestor_size = entry.size + sum(
                    snap_txs[a].size for a in all_ancestors
                )
                ancestor_fee_rates[txid_key] = (
                    ancestor_fee / ancestor_size if ancestor_size > 0 else 0.0
                )

            # Sort candidates by ancestor fee rate (highest first)
            sorted_by_ancestor_fee_rate = sorted(
                snap_txs.keys(),
                key=lambda txid: ancestor_fee_rates.get(txid, 0.0),
                reverse=True,
            )

            for entry_txid in sorted_by_ancestor_fee_rate:
                if entry_txid in included:
                    continue
                entry = snap_txs.get(entry_txid)
                if entry is None:
                    continue

                # Collect required ancestors (+ self) in topological order
                batch = _collect_ancestors(entry_txid, included)
                batch_weight = sum(
                    snap_txs[t].size * 4
                    for t in batch
                    if t in snap_txs
                )
                if total_weight + batch_weight > MAX_BLOCK_WEIGHT - 4000:
                    continue  # skip — batch doesn't fit

                for t in batch:
                    e = snap_txs.get(t)
                    if e is None or t in included:
                        continue
                    tw = e.size * 4
                    raw = e.tx.serialize()

                    tx_sigops_cost = 0

                    # Legacy sigops (outputs + inputs) × WITNESS_SCALE_FACTOR
                    legacy_sigops = 0
                    for out in e.tx.outputs:
                        legacy_sigops += _count_legacy_sigops(out.script_pubkey)
                    for inp in e.tx.inputs:
                        legacy_sigops += _count_legacy_sigops(inp.script_sig)
                    tx_sigops_cost += legacy_sigops * WITNESS_SCALE_FACTOR

                    # P2SH sigops × WITNESS_SCALE_FACTOR and witness sigops × 1
                    for inp in e.tx.inputs:
                        prev_utxo = db.get_utxo(inp.prev_txid, inp.prev_vout)
                        if prev_utxo is None:
                            # Check if parent is an in-mempool tx
                            parent_entry = snap_txs.get(inp.prev_txid)
                            if parent_entry and inp.prev_vout < len(parent_entry.tx.outputs):
                                prev_spk = bytes(parent_entry.tx.outputs[inp.prev_vout].script_pubkey)
                            else:
                                continue
                        else:
                            prev_spk = bytes(prev_utxo["script_pubkey"])

                        p2sh_sigops = _get_p2sh_sigops(inp.script_sig, prev_spk)
                        tx_sigops_cost += p2sh_sigops * WITNESS_SCALE_FACTOR

                        # Witness sigops × 1
                        witness_spk = prev_spk
                        if _is_p2sh(prev_spk):
                            redeem = _get_last_push(inp.script_sig)
                            if redeem is not None:
                                witness_spk = redeem
                        tx_sigops_cost += _count_witness_sigops(
                            witness_spk, inp.witness
                        )

                    txs.append({
                        "data": raw.hex(),
                        "txid": t.hex(),
                        "hash": t.hex(),
                        "fee": e.fee,
                        "sigops": tx_sigops_cost,
                        "weight": tw,
                    })
                    total_fees += e.fee
                    total_weight += tw
                    included.add(t)
        else:
            snap_txs = {}

        # witness commitment
        # Compute the SegWit witness merkle root from selected txs.
        # wtxids: coinbase is 32 zero-bytes, then each selected tx's wtxid.
        wtxids: List[bytes] = [bytes(32)]  # coinbase placeholder
        for tx_entry in txs:
            entry_txid = bytes.fromhex(tx_entry["txid"])
            entry_obj = snap_txs.get(entry_txid)
            if entry_obj:
                wtxids.append(entry_obj.tx.get_wtxid())
            else:
                wtxids.append(entry_txid)

        # Merkle root of wtxids
        level = list(wtxids)
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = level[i] + level[i + 1]
                else:
                    combined = level[i] + level[i]
                h = _hl.sha256(_hl.sha256(combined).digest()).digest()
                next_level.append(h)
            level = next_level
        witness_root = level[0] if level else bytes(32)

        # commitment = SHA256d(witness_root || nonce), nonce = 32 zero bytes
        nonce = bytes(32)
        commitment = _hl.sha256(
            _hl.sha256(witness_root + nonce).digest()
        ).digest()

        # Full scriptPubKey: OP_RETURN OP_PUSH36 <magic><commitment>
        witness_commitment_script = bytes.fromhex("6a24aa21a9ed") + commitment
        default_witness_commitment = witness_commitment_script.hex()

        # block reward (subsidy + fees)
        subsidy = 50 * 100_000_000
        halvings = next_height // 210_000
        if halvings < 64:
            subsidy >>= halvings
        coinbase_value = subsidy + total_fees

        # target / bits
        bits = best_block.bits
        n_shift = (bits >> 24) & 0xFF
        mantissa = bits & 0x007FFFFF
        if n_shift <= 3:
            target_int = mantissa >> (8 * (3 - n_shift))
        else:
            target_int = mantissa << (8 * (n_shift - 3))
        target_hex = f"{target_int:064x}"

        return {
            "version": best_block.version,
            "previousblockhash": best_hash.hex(),
            "transactions": txs,
            "coinbasevalue": coinbase_value,
            "target": target_hex,
            "bits": f"{bits:08x}",
            "curtime": int(_time.time()),
            "height": next_height,
            "mintime": self.node.get_median_time(best_height) + 1,
            "mutable": ["time", "transactions", "prevblock"],
            "noncerange": "00000000ffffffff",
            "sigoplimit": 80000,
            "sizelimit": 4000000,
            "weightlimit": MAX_BLOCK_WEIGHT,
            "default_witness_commitment": default_witness_commitment,
        }

    async def rpc_submitblock(self, hexdata: str) -> Optional[str]:
        """
        Submit a mined block to the network.

        Returns None on success, an error string on failure.
        """
        from ouroboros.database import Block as _Block

        try:
            block_bytes = bytes.fromhex(hexdata)
        except ValueError:
            return "Invalid hex"

        try:
            block = _Block.deserialize(block_bytes)
        except Exception as e:
            return f"Block deserialization failed: {e}"

        block_sync = getattr(self.node, "block_sync", None)
        if block_sync is None:
            return "Block sync not available"

        try:
            valid, error = block_sync.validator.validate_block(block)
            if not valid:
                return error or "Block validation failed"

            block_sync.validator.apply_block(block)

            if block_sync.mempool is not None:
                block_sync.mempool.remove_block_transactions(block)

            return None
        except Exception as e:
            return str(e)

    async def rpc_pruneblockchain(self, height: int) -> int:
        """
        Prune block data up to the given height.

        Returns the height of the last block pruned.
        """
        pruner = getattr(self.node, "pruner", None)
        if pruner is None:
            return JSONRPCResponse(
                error={
                    "code": -1,
                    "message": "Cannot prune blocks because node is not "
                    "in prune mode. Start with -prune=<target_size_mb>.",
                },
                id=None,
            )

        _, best_height = self.node.db.get_best_block()
        max_height = best_height - pruner.keep_blocks
        target = min(height, max_height)
        if target < 0:
            target = 0

        from_height = pruner.prune_height
        if from_height > target:
            return from_height

        removed = self.node.db.prune_blocks_range(from_height, target)
        logger.info(f"RPC pruneblockchain: pruned {removed} blocks up to height {target}")
        return target

    # --- Additional RPC methods ---

    async def rpc_help(self, command: str = "") -> str:
        """List all available RPC commands, or get help for a specific command."""
        methods = sorted([
            m[4:] for m in dir(self) if m.startswith('rpc_')
        ])
        if command:
            method = getattr(self, f'rpc_{command}', None)
            if method:
                return method.__doc__ or f"No help for '{command}'"
            return f"Unknown command: {command}"
        return "\n".join(methods)

    async def rpc_stop(self) -> str:
        """Stop the node."""
        import asyncio
        asyncio.get_event_loop().call_later(0.5, self.node.stop
                                            if hasattr(self.node, 'stop') else lambda: None)
        return "Ouroboros server stopping"

    async def rpc_uptime(self) -> int:
        """Return server uptime in seconds."""
        start = getattr(self.node, 'start_time', None)
        if start:
            return int(time.time() - start)
        return 0

    async def rpc_getpeerinfo(self) -> List[Dict[str, Any]]:
        """Return information about connected peers."""
        peers = []
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return []
        peer_list = getattr(pm, 'peers', [])
        if isinstance(peer_list, dict):
            peer_list = list(peer_list.values())
        for i, peer in enumerate(peer_list):
            info = {
                "id": i,
                "addr": getattr(peer, 'address', ''),
                "services": hex(getattr(peer, 'services', 0)),
                "version": getattr(peer, 'version', 0),
                "subver": getattr(peer, 'user_agent', ''),
                "startingheight": getattr(peer, 'start_height', 0),
                "synced_headers": getattr(peer, 'synced_headers', -1),
                "synced_blocks": getattr(peer, 'synced_blocks', -1),
                "inbound": getattr(peer, 'inbound', False),
                "banscore": getattr(peer, 'ban_score', 0),
            }
            peers.append(info)
        return peers

    async def rpc_getconnectioncount(self) -> int:
        """Return the number of active connections."""
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return 0
        peers = getattr(pm, 'peers', [])
        return len(peers) if isinstance(peers, list) else len(list(peers))

    async def rpc_addnode(self, node: str, command: str = "add") -> None:
        """Add or remove a peer."""
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            raise ValueError("No peer manager available")
        if command == "add":
            if hasattr(pm, 'add_peer'):
                await pm.add_peer(node)
        elif command == "remove":
            if hasattr(pm, 'remove_peer'):
                await pm.remove_peer(node)
        elif command == "onetry":
            if hasattr(pm, 'connect'):
                await pm.connect(node)

    async def rpc_disconnectnode(self, address: str = "", nodeid: int = -1) -> None:
        """Disconnect a peer by address or node id."""
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm and hasattr(pm, 'disconnect_peer'):
            await pm.disconnect_peer(address or nodeid)

    async def rpc_getnettotals(self) -> Dict[str, Any]:
        """Return network traffic statistics."""
        return {
            "totalbytesrecv": getattr(self.node, 'bytes_recv', 0),
            "totalbytessent": getattr(self.node, 'bytes_sent', 0),
            "timemillis": int(time.time() * 1000),
        }

    async def rpc_getdifficulty(self) -> float:
        """Return the current difficulty."""
        if not hasattr(self.node, 'db') or not self.node.db:
            return 0.0
        try:
            _, best_height = self.node.db.get_best_block()
            block = self.node.db.get_block_by_height(best_height)
            if block:
                bits = block.bits if hasattr(block, 'bits') else 0x1d00ffff
                # difficulty = max_target / current_target
                max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
                mantissa = bits & 0x007FFFFF
                exponent = (bits >> 24) & 0xFF
                if mantissa == 0:
                    return 0.0
                if exponent <= 3:
                    target = mantissa >> (8 * (3 - exponent))
                else:
                    target = mantissa << (8 * (exponent - 3))
                if target == 0:
                    return 0.0
                return max_target / target
        except Exception:
            return 0.0
        return 0.0

    async def rpc_getchaintxstats(self, nblocks: int = 30) -> Dict[str, Any]:
        """Return chain transaction statistics."""
        if not hasattr(self.node, 'db') or not self.node.db:
            return {}
        _, best_height = self.node.db.get_best_block()
        return {
            "time": int(time.time()),
            "txcount": best_height,  # approximate
            "window_final_block_height": best_height,
            "window_block_count": min(nblocks, best_height),
        }

    async def rpc_getchaintips(self) -> List[Dict[str, Any]]:
        """Return information about all known tips in the block tree.

        Returns a list of chain tips, including the active chain tip and any
        orphan/stale branches.  Each entry contains the tip height, block hash,
        branch length (distance to the main chain fork point) and a status
        string.

        Status values:
          "active"        — the current best chain tip
          "valid-fork"    — fully validated fork (not best chain)
          "valid-headers" — headers are valid but block data not fully validated
          "headers-only"  — only headers received
        """
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        tips: List[Dict[str, Any]] = []

        # Active chain tip ---------------------------------------------------
        hash_bytes, height = self.node.db.get_best_block()
        tip_hash_hex: str
        if isinstance(hash_bytes, bytes):
            tip_hash_hex = hash_bytes.hex()
        else:
            tip_hash_hex = str(hash_bytes)

        tips.append({
            "height": height,
            "hash": tip_hash_hex,
            "branchlen": 0,
            "status": "active",
        })

        # Future enhancement: iterate over orphan / stale block headers
        # stored in the block index and report them as additional tips with
        # status "valid-fork", "valid-headers", or "headers-only".

        return tips

    async def rpc_gettxoutsetinfo(self) -> Dict[str, Any]:
        """Return UTXO set statistics."""
        if not hasattr(self.node, 'db') or not self.node.db:
            return {}
        _, best_height = self.node.db.get_best_block()
        return {
            "height": best_height,
            "bestblock": self.node.db.get_block_hash_by_height(best_height).hex()
                if self.node.db.get_block_hash_by_height(best_height) else "",
            "txouts": 0,  # would need UTXO count
            "disk_size": 0,
        }

    async def rpc_verifychain(self, checklevel: int = 3, nblocks: int = 6) -> bool:
        """Verify the blockchain database.

        Checks the most recent *nblocks* blocks at the given level:
          0 — Block data reads and deserializes correctly
          1 — Block hash matches the stored hash
          2 — Merkle root matches computed merkle root
          3 — Proof-of-work meets difficulty target (default)
          4 — Full transaction structure validation (expensive)

        Args:
            checklevel: Verification depth 0-4 (default 3)
            nblocks: Number of recent blocks to check (default 6)

        Returns:
            True if all checks pass, False otherwise
        """
        import hashlib
        from ouroboros.validation import _bits_to_target

        if not hasattr(self.node, "db") or not self.node.db:
            return True

        try:
            _, best_height = self.node.db.get_best_block()
        except Exception:
            return True

        start_height = max(0, best_height - nblocks + 1)
        checklevel = max(0, min(4, checklevel))

        for h in range(best_height, start_height - 1, -1):
            try:
                block = self.node.db.get_block_by_height(h)
                if block is None:
                    logger.warning(f"verifychain: block at height {h} not found")
                    return False

                # Level 0: block deserialized successfully (implied)

                if checklevel >= 1:
                    # Recompute block hash from header and compare
                    header = bytearray()
                    header.extend(block.version.to_bytes(4, "little", signed=True))
                    header.extend(block.prev_blockhash[::-1])
                    header.extend(block.merkle_root[::-1])
                    header.extend(block.timestamp.to_bytes(4, "little"))
                    header.extend(block.bits.to_bytes(4, "little"))
                    header.extend(block.nonce.to_bytes(4, "little"))
                    computed = hashlib.sha256(
                        hashlib.sha256(bytes(header)).digest()
                    ).digest()[::-1]
                    if computed != block.hash:
                        logger.warning(
                            f"verifychain: hash mismatch at height {h}"
                        )
                        return False

                if checklevel >= 2:
                    # Verify merkle root
                    txids = [tx.get_txid() for tx in block.transactions]
                    if not txids:
                        logger.warning(
                            f"verifychain: no transactions at height {h}"
                        )
                        return False
                    computed_root = self._compute_merkle_root(txids)
                    if computed_root != block.merkle_root:
                        logger.warning(
                            f"verifychain: merkle root mismatch at height {h}"
                        )
                        return False

                if checklevel >= 3:
                    # Verify proof-of-work meets difficulty target
                    target = _bits_to_target(block.bits)
                    if target <= 0:
                        logger.warning(
                            f"verifychain: invalid target at height {h}"
                        )
                        return False
                    # block.hash is display format (big-endian)
                    block_hash_int = int.from_bytes(block.hash, "big")
                    if block_hash_int > target:
                        logger.warning(
                            f"verifychain: PoW failed at height {h}"
                        )
                        return False

                if checklevel >= 4:
                    # Full transaction structure validation
                    for tx in block.transactions:
                        if tx.is_coinbase:
                            continue
                        if len(tx.inputs) == 0:
                            logger.warning(
                                f"verifychain: tx with no inputs "
                                f"at height {h}"
                            )
                            return False
                        if len(tx.outputs) == 0:
                            logger.warning(
                                f"verifychain: tx with no outputs "
                                f"at height {h}"
                            )
                            return False

            except Exception as e:
                logger.warning(f"verifychain: error at height {h}: {e}")
                return False

        return True

    @staticmethod
    def _compute_merkle_root(txids: list) -> bytes:
        import hashlib
        if not txids:
            return bytes(32)
        level = list(txids)
        while len(level) > 1:
            if len(level) % 2 != 0:
                level.append(level[-1])
            next_level = []
            for i in range(0, len(level), 2):
                h = hashlib.sha256(
                    hashlib.sha256(level[i] + level[i + 1]).digest()
                ).digest()
                next_level.append(h)
            level = next_level
        return level[0]

    async def rpc_getmempoolancestors(
        self, txid: str, verbose: bool = False
    ) -> Union[List[str], Dict[str, Any]]:
        """Return all in-mempool ancestors of a transaction."""
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            return [] if not verbose else {}
        txid_bytes = bytes.fromhex(txid)
        tx = self.node.mempool.get_transaction(txid_bytes)
        if tx is None:
            raise ValueError(f"Transaction not in mempool: {txid}")
        ancestors = self.node.mempool._get_ancestors(tx)
        if not verbose:
            return [a.hex() for a in ancestors]
        result: Dict[str, Any] = {}
        for a_txid in ancestors:
            entry = self.node.mempool.get_transaction_entry(a_txid)
            if entry is not None:
                result[a_txid.hex()] = self._format_mempool_entry(entry, a_txid)
        return result

    async def rpc_getmempooldescendants(
        self, txid: str, verbose: bool = False
    ) -> Union[List[str], Dict[str, Any]]:
        """Return all in-mempool descendants of a transaction."""
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            return [] if not verbose else {}
        txid_bytes = bytes.fromhex(txid)
        if txid_bytes not in self.node.mempool.transactions:
            raise ValueError(f"Transaction not in mempool: {txid}")
        descendants = self.node.mempool._collect_descendants(txid_bytes)
        descendants.discard(txid_bytes)
        if not verbose:
            return [d.hex() for d in descendants]
        result: Dict[str, Any] = {}
        for d_txid in descendants:
            entry = self.node.mempool.get_transaction_entry(d_txid)
            if entry is not None:
                result[d_txid.hex()] = self._format_mempool_entry(entry, d_txid)
        return result

    async def rpc_createrawtransaction(
        self, inputs: List[Dict], outputs: List[Dict],
        locktime: int = 0, replaceable: bool = False
    ) -> str:
        """Create a raw transaction (unsigned)."""
        from ouroboros.database import Transaction as DbTx, TxIn, TxOut
        tx_inputs = []
        for inp in inputs:
            txid_bytes = bytes.fromhex(inp['txid'])
            tx_inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=inp['vout'],
                script_sig=b'',
                sequence=0xFFFFFFFD if replaceable else 0xFFFFFFFF,
            ))
        tx_outputs = []
        for out_dict in outputs:
            for addr, amount in out_dict.items():
                if addr == "data":
                    script = b'\x6a' + bytes.fromhex(amount)
                else:
                    from ouroboros.address import address_to_script_pubkey
                    script = address_to_script_pubkey(addr, self.node.network)
                sat_amount = int(float(amount) * 1e8) if addr != "data" else 0
                tx_outputs.append(TxOut(value=sat_amount, script_pubkey=script))
        tx = DbTx(
            txid=b'\x00' * 32, version=2, locktime=locktime,
            inputs=tx_inputs, outputs=tx_outputs,
        )
        return tx.serialize().hex()

    async def rpc_signrawtransactionwithkey(
        self, hexstring: str, privkeys: List[str],
        prevtxs: List[Dict] = None, sighashtype: str = "ALL"
    ) -> Dict[str, Any]:
        """Sign a raw transaction with provided private keys.

        Args:
            hexstring: Hex-encoded raw transaction
            privkeys: Array of WIF-encoded private keys
            prevtxs: Array of previous outputs being spent, each with
                      keys: txid, vout, scriptPubKey, amount (optional
                      redeemScript, witnessScript)
            sighashtype: Signature hash type (ALL, NONE, SINGLE,
                         ALL|ANYONECANPAY, NONE|ANYONECANPAY,
                         SINGLE|ANYONECANPAY, DEFAULT)

        Returns:
            {hex: signed_tx_hex, complete: bool, errors: [...]}
        """
        import hashlib
        import struct
        from ouroboros.p2p_messages import TxMessage
        from ouroboros.database import Transaction as DbTx, TxIn, TxOut
        from ouroboros.wallet import WalletKey, _hash160, _dsha256, _encode_varint

        # --- Parse sighash type string -----------------------------------
        sighash_map = {
            "ALL": 0x01, "NONE": 0x02, "SINGLE": 0x03,
            "ALL|ANYONECANPAY": 0x81, "NONE|ANYONECANPAY": 0x82,
            "SINGLE|ANYONECANPAY": 0x83, "DEFAULT": 0x00,
        }
        sighash_type = sighash_map.get(sighashtype.upper(), 0x01)

        # --- Deserialize transaction -------------------------------------
        try:
            tx_msg = TxMessage.from_payload(bytes.fromhex(hexstring))
            tx = tx_msg.transaction
        except Exception as e:
            raise ValueError(f"TX decode failed: {e}")

        # --- Build key lookup: pubkey_hash / pubkey -> WalletKey ---------
        network = getattr(self.node, "network", "mainnet")
        keys_by_h160: Dict[bytes, WalletKey] = {}
        keys_by_pubkey: Dict[bytes, WalletKey] = {}
        for wif in privkeys:
            try:
                k = WalletKey.from_wif(wif, network)
                keys_by_h160[_hash160(k.pubkey)] = k
                keys_by_pubkey[k.pubkey] = k
                # Also index by x-only key for Taproot
                keys_by_pubkey[k.pubkey[1:]] = k
            except Exception:
                pass

        # --- Build prevout lookup: (txid, vout) -> (scriptPubKey, value) -
        prev_lookup: Dict[tuple, tuple] = {}
        if prevtxs:
            for p in prevtxs:
                txid_bytes = bytes.fromhex(p["txid"])
                vout = p["vout"]
                spk = bytes.fromhex(p["scriptPubKey"])
                amount = int(float(p.get("amount", 0)) * 1e8)
                prev_lookup[(txid_bytes, vout)] = (spk, amount)

        # --- Helper: look up prevout info --------------------------------
        def _get_prevout(inp: TxIn):
            key = (inp.prev_txid, inp.prev_vout)
            if key in prev_lookup:
                return prev_lookup[key]
            # Fall back to UTXO set
            if hasattr(self.node, "db") and self.node.db:
                try:
                    utxo = self.node.db.get_utxo(
                        inp.prev_txid, inp.prev_vout
                    )
                    if utxo:
                        return (utxo.script_pubkey, utxo.value)
                except Exception:
                    pass
            return None, None

        # --- Helper: legacy sighash --------------------------------------
        def _legacy_sighash(tx, idx, script_code, sh_type):
            enc_varint = _encode_varint
            base = sh_type & 0x1F
            acp = (sh_type & 0x80) != 0
            data = bytearray()
            data.extend(struct.pack("<i", tx.version))
            inputs = [(idx, tx.inputs[idx])] if acp else list(enumerate(tx.inputs))
            data.extend(enc_varint(len(inputs)))
            for i, ti in inputs:
                data.extend(ti.prev_txid)
                data.extend(struct.pack("<I", ti.prev_vout))
                if i == idx:
                    data.extend(enc_varint(len(script_code)))
                    data.extend(script_code)
                else:
                    data.extend(b"\x00")
                seq = 0 if base in (2, 3) and i != idx else ti.sequence
                data.extend(struct.pack("<I", seq))
            if base in (0, 1):
                data.extend(enc_varint(len(tx.outputs)))
                for o in tx.outputs:
                    data.extend(struct.pack("<q", o.value))
                    data.extend(enc_varint(len(o.script_pubkey)))
                    data.extend(o.script_pubkey)
            elif base == 2:
                data.extend(b"\x00")
            elif base == 3:
                if idx >= len(tx.outputs):
                    return bytes(32)
                data.extend(enc_varint(idx + 1))
                for j, o in enumerate(tx.outputs):
                    if j == idx:
                        data.extend(struct.pack("<q", o.value))
                        data.extend(enc_varint(len(o.script_pubkey)))
                        data.extend(o.script_pubkey)
                    else:
                        data.extend((-1).to_bytes(8, "little", signed=True))
                        data.extend(b"\x00")
            data.extend(struct.pack("<I", tx.locktime))
            data.extend(struct.pack("<I", sh_type))
            return _dsha256(bytes(data))

        # --- Helper: BIP 143 (SegWit v0) sighash ------------------------
        def _bip143_sighash(tx, idx, script_code, value, sh_type):
            base = sh_type & 0x1F
            acp = (sh_type & 0x80) != 0
            if not acp:
                prevouts = b""
                for i in tx.inputs:
                    prevouts += i.prev_txid + struct.pack("<I", i.prev_vout)
                hp = _dsha256(prevouts)
            else:
                hp = b"\x00" * 32
            if not acp and base not in (2, 3):
                seqs = b""
                for i in tx.inputs:
                    seqs += struct.pack("<I", i.sequence)
                hs = _dsha256(seqs)
            else:
                hs = b"\x00" * 32
            if base not in (2, 3):
                outs = b""
                for o in tx.outputs:
                    outs += struct.pack("<q", o.value)
                    outs += _encode_varint(len(o.script_pubkey))
                    outs += o.script_pubkey
                ho = _dsha256(outs)
            elif base == 3 and idx < len(tx.outputs):
                o = tx.outputs[idx]
                single = struct.pack("<q", o.value)
                single += _encode_varint(len(o.script_pubkey))
                single += o.script_pubkey
                ho = _dsha256(single)
            else:
                ho = b"\x00" * 32
            inp = tx.inputs[idx]
            sc_with_len = bytes([len(script_code)]) + script_code
            pre = struct.pack("<i", tx.version)
            pre += hp + hs
            pre += inp.prev_txid + struct.pack("<I", inp.prev_vout)
            pre += sc_with_len
            pre += struct.pack("<q", value)
            pre += struct.pack("<I", inp.sequence)
            pre += ho
            pre += struct.pack("<I", tx.locktime)
            pre += struct.pack("<I", sh_type)
            return _dsha256(pre)

        # --- Helper: taproot key-path sighash (BIP 341) ------------------
        def _taproot_sighash(tx, idx, sh_type, amounts, spks):
            acp = (sh_type & 0x80) != 0
            base = sh_type & 0x03
            data = bytearray()
            data.append(0x00)  # epoch
            data.append(sh_type)
            data.extend(struct.pack("<i", tx.version))
            data.extend(struct.pack("<I", tx.locktime))
            if not acp:
                prevouts = bytearray()
                for i in tx.inputs:
                    prevouts.extend(i.prev_txid)
                    prevouts.extend(struct.pack("<I", i.prev_vout))
                data.extend(hashlib.sha256(bytes(prevouts)).digest())
                amt_data = bytearray()
                for a in amounts:
                    amt_data.extend(struct.pack("<q", a))
                data.extend(hashlib.sha256(bytes(amt_data)).digest())
                spk_data = bytearray()
                for s in spks:
                    spk_data.extend(_encode_varint(len(s)))
                    spk_data.extend(s)
                data.extend(hashlib.sha256(bytes(spk_data)).digest())
                seqs = bytearray()
                for i in tx.inputs:
                    seqs.extend(struct.pack("<I", i.sequence))
                data.extend(hashlib.sha256(bytes(seqs)).digest())
            if base not in (2, 3):
                outs = bytearray()
                for o in tx.outputs:
                    outs.extend(struct.pack("<q", o.value))
                    outs.extend(_encode_varint(len(o.script_pubkey)))
                    outs.extend(o.script_pubkey)
                data.extend(hashlib.sha256(bytes(outs)).digest())
            elif base == 3 and idx < len(tx.outputs):
                o = tx.outputs[idx]
                out = struct.pack("<q", o.value)
                out += _encode_varint(len(o.script_pubkey))
                out += o.script_pubkey
                data.extend(hashlib.sha256(out).digest())
            else:
                data.extend(b"\x00" * 32)
            # spend_type: ext_flag=0, no annex
            data.append(0x00)
            if acp:
                inp = tx.inputs[idx]
                data.extend(inp.prev_txid)
                data.extend(struct.pack("<I", inp.prev_vout))
                data.extend(struct.pack("<q", amounts[idx]))
                data.extend(_encode_varint(len(spks[idx])))
                data.extend(spks[idx])
                data.extend(struct.pack("<I", inp.sequence))
            else:
                data.extend(struct.pack("<I", idx))
            # Tagged hash: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || data)
            tag = hashlib.sha256(b"TapSighash").digest()
            return hashlib.sha256(tag + tag + bytes(data)).digest()

        # --- Sign each input ---------------------------------------------
        errors = []
        all_amounts = []
        all_spks = []
        # Pre-collect amounts/spks for taproot (needs all inputs)
        for inp in tx.inputs:
            spk, amt = _get_prevout(inp)
            all_amounts.append(amt if amt is not None else 0)
            all_spks.append(spk if spk is not None else b"")

        for idx, inp in enumerate(tx.inputs):
            spk = all_spks[idx]
            amount = all_amounts[idx]
            if not spk:
                errors.append({
                    "txid": inp.prev_txid.hex(),
                    "vout": inp.prev_vout,
                    "error": "Input not found or not provided",
                })
                continue

            try:
                # Detect script type and sign
                if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9:
                    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                    h160 = spk[3:23]
                    key = keys_by_h160.get(h160)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2PKH",
                        })
                        continue
                    sh = _legacy_sighash(tx, idx, spk, sighash_type)
                    sig = key.sign(sh) + bytes([sighash_type])
                    inp.script_sig = (
                        bytes([len(sig)]) + sig
                        + bytes([len(key.pubkey)]) + key.pubkey
                    )

                elif len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                    # P2WPKH: OP_0 <20-byte-hash>
                    h160 = spk[2:22]
                    key = keys_by_h160.get(h160)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2WPKH",
                        })
                        continue
                    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                    sh = _bip143_sighash(tx, idx, script_code, amount, sighash_type)
                    sig = key.sign(sh) + bytes([sighash_type])
                    inp.witness = [sig, key.pubkey]
                    tx.has_witness = True

                elif len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14:
                    # P2SH — check for P2SH-P2WPKH
                    signed = False
                    for h160, key in keys_by_h160.items():
                        redeem_script = b"\x00\x14" + h160
                        if _hash160(redeem_script) == spk[2:22]:
                            script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                            sh = _bip143_sighash(
                                tx, idx, script_code, amount, sighash_type
                            )
                            sig = key.sign(sh) + bytes([sighash_type])
                            inp.script_sig = (
                                bytes([len(redeem_script)]) + redeem_script
                            )
                            inp.witness = [sig, key.pubkey]
                            tx.has_witness = True
                            signed = True
                            break
                    if not signed:
                        errors.append({
                            "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2SH-P2WPKH",
                        })

                elif len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
                    # P2TR: OP_1 <32-byte-x-only-key>
                    x_only = spk[2:34]
                    key = keys_by_pubkey.get(x_only)
                    if not key:
                        errors.append({
                            "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                            "error": "No matching key for P2TR",
                        })
                        continue
                    sh = _taproot_sighash(
                        tx, idx, sighash_type, all_amounts, all_spks
                    )
                    try:
                        import sync as _sync
                        raw_sig = _sync.sign_schnorr(sh, key.secret)
                    except (ImportError, AttributeError):
                        try:
                            from coincurve import PrivateKey as CPrivKey
                            raw_sig = CPrivKey(key.secret).sign_schnorr(sh)
                        except Exception:
                            errors.append({
                                "txid": inp.prev_txid.hex(),
                                "vout": inp.prev_vout,
                                "error": "Schnorr signing not available",
                            })
                            continue
                    if sighash_type != 0x00:
                        raw_sig += bytes([sighash_type])
                    inp.witness = [raw_sig]
                    tx.has_witness = True

                elif len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
                    # P2WSH: OP_0 <32-byte-hash> — need witnessScript
                    errors.append({
                        "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                        "error": "P2WSH signing requires witnessScript "
                                 "(not yet supported)",
                    })

                else:
                    errors.append({
                        "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                        "error": f"Unsupported script type (len={len(spk)})",
                    })

            except Exception as e:
                errors.append({
                    "txid": inp.prev_txid.hex(), "vout": inp.prev_vout,
                    "error": str(e),
                })

        # --- Re-compute txid and serialize --------------------------------
        tx.txid = _dsha256(tx.serialize())
        signed_hex = tx.serialize_with_witness().hex()
        complete = len(errors) == 0
        result: Dict[str, Any] = {"hex": signed_hex, "complete": complete}
        if errors:
            result["errors"] = errors
        return result

    async def rpc_testmempoolaccept(
        self, rawtxs: List[str], maxfeerate: float = 0.10
    ) -> List[Dict[str, Any]]:
        """Test whether raw transactions would be accepted to mempool."""
        results = []
        for raw in rawtxs:
            try:
                from ouroboros.p2p_messages import TxMessage
                tx_msg = TxMessage.from_payload(bytes.fromhex(raw))
                tx = tx_msg.transaction
                _, best_height = self.node.db.get_best_block()
                valid, error = self.node.validator.validate_transaction(
                    tx, best_height + 1)
                results.append({
                    "txid": tx.get_txid().hex(),
                    "allowed": valid,
                    "reject-reason": error if not valid else None,
                })
            except Exception as e:
                results.append({
                    "txid": "",
                    "allowed": False,
                    "reject-reason": str(e),
                })
        return results

    async def rpc_submitpackage(self, package: List[str]) -> Dict[str, Any]:
        """Submit a package of raw transactions for validation and mempool acceptance.

        Accepts a list of raw transaction hex strings in topological order
        (parents before children).  The package is evaluated as a unit so
        that a child can pay for a low-fee parent (CPFP).

        Returns per-transaction results with txid, vsize, and fees.
        """
        if not isinstance(package, list) or len(package) == 0:
            raise HTTPException(
                status_code=400,
                detail="package must be a non-empty list of raw transaction hex strings",
            )

        from ouroboros.p2p_messages import TxMessage

        # Deserialize each hex string into a Transaction
        txs: List[Transaction] = []
        for i, raw_hex in enumerate(package):
            try:
                tx_data = bytes.fromhex(raw_hex.strip())
            except (ValueError, AttributeError) as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid hex string at index {i}: {e}",
                )
            try:
                tx_msg = TxMessage.from_payload(tx_data)
                tx = tx_msg.transaction
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to decode transaction at index {i}: {e}",
                )
            if tx.is_coinbase:
                raise HTTPException(
                    status_code=400,
                    detail=f"Coinbase transaction at index {i} cannot be submitted",
                )
            txs.append(tx)

        if not hasattr(self.node, "mempool") or not self.node.mempool:
            raise HTTPException(status_code=500, detail="Mempool not available")
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        _, best_height = self.node.db.get_best_block()
        success, error = self.node.mempool.validate_package(txs, best_height + 1)

        if not success:
            return {
                "package_msg": error,
                "tx-results": {},
            }

        # Build per-transaction results from the mempool entries that were
        # just inserted by validate_package.
        tx_results: Dict[str, Any] = {}
        for tx in txs:
            txid_hex = tx.get_txid().hex()
            entry = self.node.mempool.get_transaction_entry(tx.get_txid())
            if entry is not None:
                tx_results[txid_hex] = {
                    "txid": txid_hex,
                    "vsize": tx.get_vsize(),
                    "fees": {
                        "base": entry.fee / 1e8,
                    },
                }
            else:
                tx_results[txid_hex] = {
                    "txid": txid_hex,
                    "vsize": tx.get_vsize(),
                    "fees": {"base": 0},
                }

        return {
            "package_msg": "success",
            "tx-results": tx_results,
        }

    async def rpc_listtransactions(
        self, label: str = "*", count: int = 10, skip: int = 0,
        include_watchonly: bool = True
    ) -> List[Dict[str, Any]]:
        """Return recent transactions for the wallet."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            return []
        txs = await self.node.wallet.get_transactions()
        return [
            {"txid": t.txid, "amount": t.amount / 1e8,
             "confirmations": t.confirmations, "time": t.timestamp}
            for t in txs[skip:skip + count]
        ]

    async def rpc_gettransaction(self, txid: str) -> Dict[str, Any]:
        """Get detailed information about a wallet transaction."""
        if not hasattr(self.node, 'db') or not self.node.db:
            raise ValueError("No database available")
        txid_bytes = bytes.fromhex(txid)
        tx = self.node.db.get_transaction(txid_bytes)
        if tx is None:
            raise ValueError(f"Transaction not found: {txid}")
        return self._tx_to_dict(tx)

    async def rpc_importprivkey(self, privkey: str, label: str = "", rescan: bool = True) -> None:
        """Import a private key into the wallet."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            raise ValueError("No wallet loaded")
        from ouroboros.wallet import WalletKey
        key = WalletKey.from_wif(privkey, self.node.network)
        self.node.wallet.keys.append({
            "wif": key.to_wif(),
            "label": label,
            "created": int(time.time()),
        })
        self.node.wallet._save()

    async def rpc_dumpprivkey(self, address: str) -> str:
        """Reveal the private key for an address."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            raise ValueError("No wallet loaded")
        for kd in self.node.wallet.keys:
            k = self.node.wallet._get_wallet_key(kd)
            if (k.get_p2wpkh_address() == address
                    or k.get_p2pkh_address() == address):
                return k.to_wif()
        raise ValueError(f"Address not found in wallet: {address}")

    async def rpc_backupwallet(self, destination: str) -> None:
        """Backup the wallet to a file."""
        if not hasattr(self.node, 'wallet') or not self.node.wallet:
            raise ValueError("No wallet loaded")
        self.node.wallet.backup(destination)

    async def rpc_getaddressinfo(self, address: str) -> Dict[str, Any]:
        """Return information about a given address."""
        is_mine = False
        pubkey_hex = ""
        if hasattr(self.node, 'wallet') and self.node.wallet:
            for kd in self.node.wallet.keys:
                k = self.node.wallet._get_wallet_key(kd)
                if (k.get_p2wpkh_address() == address
                        or k.get_p2pkh_address() == address
                        or k.get_p2sh_p2wpkh_address() == address):
                    is_mine = True
                    pubkey_hex = k.pubkey.hex()
                    break
        script_type = "unknown"
        if address.startswith("bc1q") or address.startswith("tb1q"):
            script_type = "witness_v0_keyhash"
        elif address.startswith("bc1p") or address.startswith("tb1p"):
            script_type = "witness_v1_taproot"
        elif address.startswith("1") or address.startswith("m") or address.startswith("n"):
            script_type = "pubkeyhash"
        elif address.startswith("3") or address.startswith("2"):
            script_type = "scripthash"
        return {
            "address": address,
            "scriptPubKey": "",
            "ismine": is_mine,
            "iswatchonly": False,
            "isscript": script_type in ("scripthash",),
            "iswitness": script_type.startswith("witness"),
            "script": script_type,
            "pubkey": pubkey_hex,
            "label": "",
        }

    async def rpc_listwallets(self) -> List[str]:
        """Return list of loaded wallets."""
        if hasattr(self.node, 'wallet') and self.node.wallet:
            return [self.node.wallet.name]
        return []

    async def rpc_getnetworkhashps(
        self, nblocks: int = 120, height: int = -1
    ) -> float:
        """Return estimated network hashes per second.

        Uses the same algorithm as Bitcoin Core's GetNetworkHashPS()
        in rpc/mining.cpp: computes chainwork difference over a time
        window and divides by elapsed seconds.

        Args:
            nblocks: Number of blocks to look back (default 120).
                     Use -1 to average over the current difficulty epoch.
            height:  Block height to end at (default -1 = chain tip).
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return 0.0

        try:
            _, best_height = self.node.db.get_best_block()
        except Exception:
            return 0.0

        if height < 0 or height > best_height:
            height = best_height

        # nblocks == -1 means use the current difficulty epoch length
        if nblocks <= 0:
            nblocks = max(height % 2016, 1)

        # Clamp: don't look back further than genesis
        if nblocks > height:
            nblocks = height

        if nblocks == 0:
            return 0.0

        tip_block = self.node.db.get_block_by_height(height)
        start_block = self.node.db.get_block_by_height(height - nblocks)

        if tip_block is None or start_block is None:
            return 0.0

        time_diff = tip_block.timestamp - start_block.timestamp
        if time_diff <= 0:
            return 0.0

        # Calculate chainwork difference
        work_diff = (
            self.node._calculate_chainwork_at_height(height)
            - self.node._calculate_chainwork_at_height(height - nblocks)
        )

        return float(work_diff) / float(time_diff)

    async def rpc_prioritisetransaction(
        self, txid: str, dummy: float = 0, fee_delta: int = 0
    ) -> bool:
        """Accept the transaction into mined blocks at higher/lower priority."""
        return True

    async def rpc_generatetoaddress(
        self, nblocks: int, address: str, maxtries: int = 1000000
    ) -> List[str]:
        """Mine blocks to a given address (regtest only)."""
        return []

    async def rpc_getrpcinfo(self) -> Dict[str, Any]:
        """Return info about the RPC server."""
        return {
            "active_commands": [],
        }

    async def rpc_getindexinfo(self) -> Dict[str, Any]:
        """Return the status of indices."""
        return {}

    # Fee Bumping (RBF)

    async def rpc_bumpfee(
        self, txid: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Bump the fee of a mempool transaction via RBF.

        Creates a replacement transaction with a higher fee and broadcasts
        it.  The original transaction must signal BIP 125 replaceability
        (at least one input with sequence < 0xFFFFFFFE).

        Args:
            txid: Transaction ID to bump (hex string).
            options: Optional dict with ``fee_rate`` (sat/vB) or
                     ``conf_target`` (blocks for fee estimation).

        Returns:
            Dict with ``txid`` (new txid), ``origfee`` (BTC),
            ``fee`` (BTC), and ``errors`` list.

        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")

        if not hasattr(self.node, "mempool") or not self.node.mempool:
            raise HTTPException(status_code=500, detail="Mempool not available")

        options = options or {}
        fee_rate = options.get("fee_rate")
        conf_target = options.get("conf_target")

        if fee_rate is None:
            if conf_target is not None:
                fee_estimator = getattr(self.node, "fee_estimator", None)
                if fee_estimator is not None:
                    fee_rate = fee_estimator.estimate_fee(int(conf_target))
            if fee_rate is None:
                fee_rate = 10  # conservative default bump rate

        fee_rate = int(fee_rate)

        # Get original fee before bumping
        txid_bytes = bytes.fromhex(txid)
        orig_entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if orig_entry is None:
            raise HTTPException(
                status_code=400,
                detail=f"Transaction {txid} not in mempool",
            )
        orig_fee_btc = orig_entry.fee / 1e8

        new_txid = await wallet.bump_fee(txid, fee_rate, sign=True)
        if new_txid is None:
            raise HTTPException(
                status_code=400,
                detail="Fee bump failed – transaction may not signal RBF, "
                "wallet may lack keys or funds, or mempool rejected the replacement",
            )

        # Get the new entry fee
        new_entry = self.node.mempool.get_transaction_entry(
            bytes.fromhex(new_txid)
        )
        new_fee_btc = new_entry.fee / 1e8 if new_entry else 0

        # Broadcast inv to peers
        try:
            from ouroboros.p2p_messages import InvMessage, INV_TYPE_TX

            inv = InvMessage(
                inventory=[(INV_TYPE_TX, bytes.fromhex(new_txid))]
            )
            inv_msg = inv.to_network_message(self.node.network)
            if hasattr(self.node, "peer_manager") and self.node.peer_manager:
                await self.node.peer_manager.broadcast(inv_msg)
        except Exception:
            pass  # best-effort broadcast

        return {
            "txid": new_txid,
            "origfee": orig_fee_btc,
            "fee": new_fee_btc,
            "errors": [],
        }

    async def rpc_psbtbumpfee(
        self, txid: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Bump the fee of a mempool transaction, returning a PSBT.

        Like ``bumpfee`` but does NOT sign or broadcast.  Returns an
        unsigned raw transaction hex in the ``psbt`` field that can be
        signed externally.

        Args:
            txid: Transaction ID to bump (hex string).
            options: Optional dict with ``fee_rate`` (sat/vB) or
                     ``conf_target`` (blocks for fee estimation).

        Returns:
            Dict with ``psbt`` (unsigned raw hex), ``origfee`` (BTC),
            ``fee`` (BTC), and ``errors`` list.

        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")

        if not hasattr(self.node, "mempool") or not self.node.mempool:
            raise HTTPException(status_code=500, detail="Mempool not available")

        options = options or {}
        fee_rate = options.get("fee_rate")
        conf_target = options.get("conf_target")

        if fee_rate is None:
            if conf_target is not None:
                fee_estimator = getattr(self.node, "fee_estimator", None)
                if fee_estimator is not None:
                    fee_rate = fee_estimator.estimate_fee(int(conf_target))
            if fee_rate is None:
                fee_rate = 10

        fee_rate = int(fee_rate)

        # Get original fee before bumping
        txid_bytes = bytes.fromhex(txid)
        orig_entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if orig_entry is None:
            raise HTTPException(
                status_code=400,
                detail=f"Transaction {txid} not in mempool",
            )
        orig_fee_btc = orig_entry.fee / 1e8

        unsigned_hex = await wallet.bump_fee(txid, fee_rate, sign=False)
        if unsigned_hex is None:
            raise HTTPException(
                status_code=400,
                detail="Fee bump failed – transaction may not signal RBF "
                "or wallet cannot reconstruct the replacement",
            )

        # Estimate new fee from the unsigned tx
        orig_total_out = sum(o.value for o in orig_entry.tx.outputs)
        # Parse unsigned tx to compute new total outputs
        try:
            from ouroboros.p2p_messages import TxMessage

            tx_data = bytes.fromhex(unsigned_hex)
            tx_msg = TxMessage.from_payload(tx_data)
            new_total_out = sum(o.value for o in tx_msg.transaction.outputs)
            # Get total input value from original entry
            total_in = orig_fee_btc * 1e8 + orig_total_out
            new_fee_btc = (total_in - new_total_out) / 1e8
        except Exception:
            new_fee_btc = 0

        return {
            "psbt": unsigned_hex,
            "origfee": orig_fee_btc,
            "fee": new_fee_btc,
            "errors": [],
        }

    def _format_mempool_entry(self, entry, txid_bytes: bytes) -> Dict[str, Any]:
        """Format a MempoolEntry into the standard mempool dict."""
        mempool = self.node.mempool

        # -- depends: unconfirmed parents of this tx -----------------------
        depends: List[str] = []
        for inp in entry.tx.inputs:
            if inp.prev_txid in mempool.transactions:
                depends.append(inp.prev_txid.hex())

        # -- spentby: unconfirmed children spending this tx's outputs ------
        spentby: List[str] = []
        for other_txid, other_entry in mempool.transactions.items():
            if other_txid == txid_bytes:
                continue
            for inp in other_entry.tx.inputs:
                if inp.prev_txid == txid_bytes:
                    spentby.append(other_txid.hex())
                    break  # one match per child tx is enough

        # -- weight / vsize ------------------------------------------------
        weight = entry.tx.get_weight()
        vsize = (weight + 3) // 4

        # -- ancestor / descendant fees ------------------------------------
        ancestor_fees = entry.fee
        for a_txid in mempool._get_ancestors(entry.tx):
            a_entry = mempool.transactions.get(a_txid)
            if a_entry is not None:
                ancestor_fees += a_entry.fee

        descendant_fees = entry.fee
        for d_txid in mempool._collect_descendants(txid_bytes):
            if d_txid == txid_bytes:
                continue
            d_entry = mempool.transactions.get(d_txid)
            if d_entry is not None:
                descendant_fees += d_entry.fee

        base_fee_btc = entry.fee / 1e8

        return {
            "fees": {
                "base": base_fee_btc,
                "modified": base_fee_btc,
                "ancestor": ancestor_fees / 1e8,
                "descendant": descendant_fees / 1e8,
            },
            "vsize": vsize,
            "weight": weight,
            "fee": base_fee_btc,
            "time": int(entry.time_added),
            "height": entry.height_added,
            "descendantcount": entry.descendant_count,
            "descendantsize": entry.descendant_size,
            "descendantfees": descendant_fees,
            "ancestorcount": entry.ancestor_count,
            "ancestorsize": entry.ancestor_size,
            "ancestorfees": ancestor_fees,
            "depends": depends,
            "spentby": spentby,
        }

    async def rpc_getmempoolentry(self, txid: str) -> Dict[str, Any]:
        """Return mempool data for a given transaction."""
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            raise ValueError("No mempool available")
        txid_bytes = bytes.fromhex(txid)
        entry = self.node.mempool.get_transaction_entry(txid_bytes)
        if entry is None:
            raise ValueError(f"Transaction not in mempool: {txid}")
        return self._format_mempool_entry(entry, txid_bytes)

    async def rpc_getblockstats(
        self,
        hash_or_height: Union[str, int],
        stats: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return per-block statistics for a given block.

        ``hash_or_height`` may be a block hash (hex string) or a block height
        (integer).  All fee / size statistics are computed by iterating every
        transaction in the block.

        If ``stats`` is provided it must be a list of stat names; only those
        keys will be present in the result.

        Ref: bitcoin/src/rpc/blockchain.cpp ``getblockstats``
        """
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db

        # ------------------------------------------------------------------
        # Resolve block from hash or height
        # ------------------------------------------------------------------
        block: Optional[Block] = None
        if isinstance(hash_or_height, int):
            block = db.get_block_by_height(hash_or_height)
            if not block:
                raise HTTPException(
                    status_code=404,
                    detail=f"Block not found at height {hash_or_height}",
                )
        else:
            try:
                block_hash = bytes.fromhex(hash_or_height)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail="Invalid block hash"
                )
            block = db.get_block(block_hash)
            if not block:
                raise HTTPException(
                    status_code=404, detail="Block not found"
                )

        block_height = getattr(block, "height", None) or 0
        block_hash_bytes = (
            block.hash if isinstance(block.hash, bytes) else bytes(32)
        )
        blockhash_hex = block_hash_bytes.hex()
        block_time = block.timestamp

        # Median time past
        if hasattr(self.node, "get_median_time"):
            mediantime = self.node.get_median_time(block_height)
        else:
            mediantime = block_time

        # ------------------------------------------------------------------
        # Block subsidy
        # ------------------------------------------------------------------
        halvings = block_height // 210_000
        if halvings >= 64:
            subsidy = 0
        else:
            subsidy = (50 * 100_000_000) >> halvings

        # ------------------------------------------------------------------
        # Iterate transactions and accumulate statistics
        # ------------------------------------------------------------------
        txs_list: List[Transaction] = (
            block.transactions if hasattr(block, "transactions") else []
        )
        num_txs = len(txs_list)

        total_size = 0
        total_weight = 0
        total_out = 0          # sum of all output values (satoshis)
        totalfee = 0           # sum of all non-coinbase fees

        ins = 0
        outs = 0

        swtxs = 0
        swtotal_size = 0
        swtotal_weight = 0

        utxo_increase = 0      # outputs created minus inputs spent

        # Per-tx collections (exclude coinbase for fee stats)
        tx_fees: List[int] = []
        tx_feerates: List[int] = []   # sat / vbyte (integer)
        tx_sizes: List[int] = []

        for tx in txs_list:
            tx_size = len(tx.serialize())
            tx_weight = tx.get_weight()
            tx_vsize = tx.get_vsize()

            total_size += tx_size
            total_weight += tx_weight

            n_in = len(tx.inputs)
            n_out = len(tx.outputs)
            ins += n_in
            outs += n_out
            utxo_increase += n_out  # each output creates a UTXO

            out_value = sum(o.value for o in tx.outputs)
            total_out += out_value

            if tx.has_witness:
                swtxs += 1
                swtotal_size += tx_size
                swtotal_weight += tx_weight

            if tx.is_coinbase:
                # Coinbase has no real inputs to spend
                # utxo_increase is not reduced by coinbase inputs
                continue

            # Non-coinbase: each input spends a UTXO
            utxo_increase -= n_in

            # Fee = sum(input values) - sum(output values)
            input_total = 0
            for tx_in in tx.inputs:
                utxo = db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                if utxo:
                    input_total += utxo["value"]

            fee = input_total - out_value
            if fee < 0:
                fee = 0

            totalfee += fee
            tx_fees.append(fee)
            tx_sizes.append(tx_size)

            if tx_vsize > 0:
                tx_feerates.append(fee // tx_vsize)
            else:
                tx_feerates.append(0)

        # ------------------------------------------------------------------
        # Aggregates (guard against empty lists)
        # ------------------------------------------------------------------
        if tx_fees:
            avgfee = totalfee // len(tx_fees)
            minfee = min(tx_fees)
            maxfee = max(tx_fees)
            medianfee = int(statistics.median(tx_fees))
        else:
            avgfee = minfee = maxfee = medianfee = 0

        if tx_feerates:
            avgfeerate = sum(tx_feerates) // len(tx_feerates)
            minfeerate = min(tx_feerates)
            maxfeerate = max(tx_feerates)
        else:
            avgfeerate = minfeerate = maxfeerate = 0

        if tx_sizes:
            avgtxsize = sum(tx_sizes) // len(tx_sizes)
            mintxsize = min(tx_sizes)
            maxtxsize = max(tx_sizes)
            mediantxsize = int(statistics.median(tx_sizes))
        else:
            avgtxsize = mintxsize = maxtxsize = mediantxsize = 0

        # utxo_size_inc: approximate serialized size change of the UTXO set
        # Each UTXO ≈ 32 (txid) + 4 (vout) + 8 (value) + scriptPubKey bytes
        # Simplified: count * 50 bytes as a rough estimate, matching Bitcoin
        # Core's approach of tracking the actual serialized UTXO set delta.
        # A positive utxo_increase means the set grew.
        utxo_size_inc = 0
        for tx in txs_list:
            if tx.is_coinbase:
                for o in tx.outputs:
                    utxo_size_inc += 50 + len(o.script_pubkey)
                continue
            for o in tx.outputs:
                utxo_size_inc += 50 + len(o.script_pubkey)
            for _ in tx.inputs:
                utxo_size_inc -= 50

        # ------------------------------------------------------------------
        # Build result
        # ------------------------------------------------------------------
        result: Dict[str, Any] = {
            "avgfee": avgfee,
            "avgfeerate": avgfeerate,
            "avgtxsize": avgtxsize,
            "blockhash": blockhash_hex,
            "height": block_height,
            "ins": ins,
            "maxfee": maxfee,
            "maxfeerate": maxfeerate,
            "maxtxsize": maxtxsize,
            "medianfee": medianfee,
            "mediantime": mediantime,
            "mediantxsize": mediantxsize,
            "minfee": minfee,
            "minfeerate": minfeerate,
            "mintxsize": mintxsize,
            "outs": outs,
            "subsidy": subsidy,
            "swtotal_size": swtotal_size,
            "swtotal_weight": swtotal_weight,
            "swtxs": swtxs,
            "time": block_time,
            "total_out": total_out,
            "total_size": total_size,
            "total_weight": total_weight,
            "totalfee": totalfee,
            "txs": num_txs,
            "utxo_increase": utxo_increase,
            "utxo_size_inc": utxo_size_inc,
        }

        # Filter to requested stats
        if stats:
            result = {k: v for k, v in result.items() if k in stats}

        return result

    # Helper methods

    def _tx_to_dict(self, tx: Transaction) -> Dict[str, Any]:
        """Convert transaction to dictionary for RPC response."""
        txid = tx.get_txid() if hasattr(tx, 'get_txid') else tx.txid
        txid_hex = txid.hex() if isinstance(txid, bytes) else str(txid)
        
        # Calculate weight and vsize using transaction methods
        if hasattr(tx, 'get_weight') and hasattr(tx, 'get_vsize'):
            weight = tx.get_weight()
            vsize = tx.get_vsize()
        else:
            # Fallback: assume non-SegWit transaction
            tx_size = len(tx.serialize())
            weight = tx_size * 4
            vsize = tx_size
        
        hash_hex = (
            tx.get_wtxid().hex() if hasattr(tx, 'get_wtxid') and tx.has_witness
            else txid_hex
        )
        return {
            "txid": txid_hex,
            "hash": hash_hex,  # wtxid for SegWit, txid for non-SegWit
            "version": tx.version,
            "size": len(tx.serialize()),
            "vsize": vsize,  # Virtual size for SegWit
            "weight": weight,  # Transaction weight
            "locktime": tx.locktime,
            "vin": [self._vin_to_dict(vin, i, tx) for i, vin in enumerate(tx.inputs)],
            "vout": [self._vout_to_dict(vout, i) for i, vout in enumerate(tx.outputs)],
        }
    
    def _vin_to_dict(self, vin: TxIn, index: int = 0, tx: Optional[Transaction] = None) -> Dict[str, Any]:
        prev_txid = vin.prev_txid.hex() if isinstance(vin.prev_txid, bytes) else str(vin.prev_txid)
        script_sig = vin.script_sig.hex() if isinstance(vin.script_sig, bytes) else str(vin.script_sig)
        
        result = {
            "txid": prev_txid,
            "vout": vin.prev_vout,
            "scriptSig": {
                "asm": disassemble_script(vin.script_sig),  # Disassemble script
                "hex": script_sig,
            },
            "sequence": vin.sequence,
        }
        if vin.witness:
            result["txinwitness"] = [item.hex() for item in vin.witness]
        return result
    
    def _vout_to_dict(self, vout: TxOut, n: int) -> Dict[str, Any]:
        script_pubkey = vout.script_pubkey.hex() if isinstance(vout.script_pubkey, bytes) else bytes(vout.script_pubkey).hex()
        script_pubkey_bytes = vout.script_pubkey if isinstance(vout.script_pubkey, bytes) else bytes(vout.script_pubkey)
        
        return {
            "value": vout.value / 100_000_000,  # Convert satoshis to BTC
            "n": n,
            "scriptPubKey": {
                "asm": disassemble_script(script_pubkey_bytes),
                "hex": script_pubkey,
                "type": self._get_script_type(vout.script_pubkey),
            },
        }
    
    def _get_script_type(self, script: bytes) -> str:
        if not isinstance(script, bytes):
            script = bytes(script)
        
        # Simplified script type detection
        if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[23] == 0x88 and script[24] == 0xac:
            return "pubkeyhash"  # P2PKH
        elif len(script) == 23 and script[0] == 0xa9 and script[22] == 0x87:
            return "scripthash"  # P2SH
        elif len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
            return "witness_v0_keyhash"  # P2WPKH
        elif len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
            return "witness_v0_scripthash"  # P2WSH
        elif len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
            return "witness_v1_taproot"  # P2TR
        elif len(script) == 67 and script[0] == 0x41:
            return "pubkey"  # P2PK
        elif len(script) > 0 and script[0] == 0x6a:
            return "nulldata"  # OP_RETURN
        else:
            return "nonstandard"

    def _is_coinbase_output(self, txid: bytes) -> bool:
        if not hasattr(self.node, 'db') or not self.node.db:
            return False
        try:
            _, best_height = self.node.db.get_best_block()
            for h in range(best_height + 1):
                block = self.node.db.get_block_by_height(h)
                if not block:
                    continue
                for tx in block.transactions:
                    if tx.get_txid() == txid:
                        return tx.is_coinbase
            return False
        except Exception:
            return False
    
    def _is_synced(self) -> bool:
        if hasattr(self.node, 'is_synced'):
            return self.node.is_synced()
        if hasattr(self.node, 'sync_manager'):
            return self.node.sync_manager.is_synced()
        return True  # Assume synced if can't check
    
    def _get_confirmations(self, height: Optional[int]) -> int:
        if height is None:
            return 0
        
        if not hasattr(self.node, 'db'):
            return 0
        
        try:
            _, best_height = self.node.db.get_best_block()
            if best_height >= height:
                return best_height - height + 1
        except:
            pass
        
        return 0
    
    def _get_next_block_hash(self, height: int) -> Optional[str]:
        if not hasattr(self.node, "db") or not self.node.db:
            return None

        try:
            next_hash = self.node.db.get_block_hash_by_height(height + 1)
            if next_hash is None:
                return None  # At tip, no next block
            if isinstance(next_hash, bytes):
                return next_hash.hex()
            return str(next_hash)
        except Exception as e:
            logger.debug(f"Error getting next block hash for height {height}: {e}")
            return None
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI application"""
        return self.app
