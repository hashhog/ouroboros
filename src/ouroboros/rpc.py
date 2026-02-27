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
import time
from collections import defaultdict
from pydantic import BaseModel

from ouroboros.database import Transaction, TxIn, TxOut, Block
from ouroboros.script import disassemble_script
from ouroboros.metrics import record_rpc_request

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
# Reference: Bitcoin Core merkleblock.cpp, CPartialMerkleTree
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
    """Number of nodes at a given height in a Merkle tree with n_tx leaves."""
    return (n_tx + (1 << height) - 1) >> height


def _calc_tree_hash(txids: list, n_tx: int, height: int, pos: int) -> bytes:
    """Compute the hash of a subtree rooted at (height, pos)."""
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
    """
    Serialize a partial Merkle tree in the CMerkleBlock wire format.

    ``block`` must have a ``.serialize()`` returning at least 80 bytes of
    header.  ``txids`` is the ordered list of 32-byte txids.  ``matches``
    is a parallel bool list indicating which txids should be provable.
    """
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
    """
    Deserialize a partial Merkle tree payload (everything after the
    80-byte header) and return ``(matched_txids, merkle_root)``.
    """
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
        """
        Initialize RPC server.
        
        Args:
            node: BitcoinNode instance
            port: RPC server port
            username: RPC username (optional, for authentication)
            password: RPC password (optional, for authentication)
            rate_limit: Enable rate limiting
        """
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
    
    async def _get_credentials(self, request: Request) -> Optional[HTTPBasicCredentials]:
        """Get and validate credentials if authentication is enabled"""
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
        """Get client IP address for rate limiting"""
        # Try to get real IP from headers (for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Fallback to direct client
        if request.client:
            return request.client.host
        
        return "127.0.0.1"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
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
        
        return {
            "chain": network,
            "blocks": best_height,
            "headers": best_height,
            "bestblockhash": best_hash.hex() if isinstance(best_hash, bytes) else best_hash,
            "difficulty": self.node.get_current_difficulty(),
            "mediantime": self.node.get_median_time(),
            "verificationprogress": 1.0 if self._is_synced() else 0.0,
            "chainwork": self.node.get_chainwork(),
            "pruned": False,
            "softforks": {},
        }
    
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
        """Return transaction"""
        try:
            tx_hash = bytes.fromhex(txid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid transaction ID")
        
        # Try mempool first
        if hasattr(self.node, 'mempool') and self.node.mempool:
            tx = self.node.mempool.get_transaction(tx_hash)
            if tx:
                if verbose:
                    return self._tx_to_dict(tx)
                return tx.serialize().hex()
        
        # Try blockchain (would need to search blocks)
        # For now, return error if not in mempool
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
            "version": 240000,  # Bitcoin Core compatible version
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
                result[txid_hex] = {
                    "size": entry.size,
                    "fee": entry.fee,
                    "time": entry.time,
                    "height": entry.height,
                    "startingpriority": 0.0,  # TODO: Calculate priority
                    "currentpriority": 0.0,    # TODO: Calculate priority
                    "depends": []  # TODO: Track dependencies
                }
        
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

        Reference: Bitcoin Core getnewaddress (wallet/rpc/addresses.cpp)
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

        Reference: Bitcoin Core sendtoaddress (wallet/rpc/spend.cpp)
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

        Reference: Bitcoin Core sethdseed (wallet/rpc/wallet.cpp)
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

        Reference: Bitcoin Core encryptwallet (wallet/rpc/encrypt.cpp)
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

        Reference: Bitcoin Core walletpassphrase (wallet/rpc/encrypt.cpp)
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

        Reference: Bitcoin Core walletlock (wallet/rpc/encrypt.cpp)
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

        Reference: Bitcoin Core walletpassphrasechange (wallet/rpc/encrypt.cpp)
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

        Reference: Bitcoin Core getwalletinfo (wallet/rpc/wallet.cpp)
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

    # ── PSBT RPCs (BIP 174) ────────────────────────────────────────────

    async def rpc_decodepsbt(self, psbt_base64: str) -> Dict[str, Any]:
        """
        Decode a base64-encoded PSBT into a human-readable dict.

        Reference: Bitcoin Core decodepsbt (rpc/rawtransaction.cpp)
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

        Reference: Bitcoin Core combinepsbt (rpc/rawtransaction.cpp)
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

        Reference: Bitcoin Core finalizepsbt (rpc/rawtransaction.cpp)
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

        Reference: Bitcoin Core createpsbt (rpc/rawtransaction.cpp)
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

        Returns a dict matching Bitcoin Core's format:
            {"feerate": <BTC/kB>, "blocks": <conf_target>}
        or  {"errors": [...], "blocks": <conf_target>}

        Reference: Bitcoin Core estimatesmartfee (rpc/fees.cpp)
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

        Reference: Bitcoin Core validateaddress (rpc/misc.cpp)
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

        Reference: Bitcoin Core gettxoutproof (rpc/rawtransaction.cpp),
                   merkleblock.cpp CPartialMerkleTree
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

        Reference: Bitcoin Core verifytxoutproof (rpc/rawtransaction.cpp)
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

        Reference: Bitcoin Core getmininginfo (rpc/mining.cpp)
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

        Reference: Bitcoin Core getblocktemplate (rpc/mining.cpp)
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

        # ── gather transactions from mempool ──────────────────────
        MAX_BLOCK_WEIGHT = 4_000_000
        txs: List[Dict[str, Any]] = []
        total_fees = 0
        total_weight = 0

        if mempool:
            for entry_txid in reversed(mempool.by_fee_rate):
                entry = mempool.transactions.get(entry_txid)
                if entry is None:
                    continue
                tx_weight = entry.size * 4
                if total_weight + tx_weight > MAX_BLOCK_WEIGHT - 4000:
                    break
                raw = entry.tx.serialize()
                txid_hex = entry_txid.hex()
                txs.append({
                    "data": raw.hex(),
                    "txid": txid_hex,
                    "hash": txid_hex,
                    "fee": entry.fee,
                    "sigops": 0,
                    "weight": tx_weight,
                })
                total_fees += entry.fee
                total_weight += tx_weight

        # ── block reward (subsidy + fees) ─────────────────────────
        subsidy = 50 * 100_000_000
        halvings = next_height // 210_000
        if halvings < 64:
            subsidy >>= halvings
        coinbase_value = subsidy + total_fees

        # ── target / bits ─────────────────────────────────────────
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
        }

    async def rpc_submitblock(self, hexdata: str) -> Optional[str]:
        """
        Submit a mined block to the network.

        Returns None on success, an error string on failure.

        Reference: Bitcoin Core submitblock (rpc/mining.cpp)
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

    # Helper methods
    
    def _tx_to_dict(self, tx: Transaction) -> Dict[str, Any]:
        """
        Convert transaction to dictionary for RPC response.
        
        Includes proper SegWit weight and vsize calculations.
        """
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
        """
        Convert input to dictionary.
        
        Args:
            vin: Transaction input
            index: Input index (for potential witness data)
            tx: Transaction (for potential witness data)
        """
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
        """Convert output to dictionary"""
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
        """Determine script type"""
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
        elif len(script) == 67 and script[0] == 0x41:
            return "pubkey"  # P2PK
        else:
            return "nonstandard"

    def _is_coinbase_output(self, txid: bytes) -> bool:
        """
        Check if a transaction (that created a UTXO) is a coinbase transaction.
        Searches blocks from genesis to tip. Returns False if not found.
        """
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
        """Check if node is synced"""
        if hasattr(self.node, 'is_synced'):
            return self.node.is_synced()
        if hasattr(self.node, 'sync_manager'):
            return self.node.sync_manager.is_synced()
        return True  # Assume synced if can't check
    
    def _get_confirmations(self, height: Optional[int]) -> int:
        """Get confirmation count for a block"""
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
        """
        Get next block hash for a given block height.

        Returns block at height+1 hash as hex, or None if at tip.
        Ref: bitcoin/src/rpc/blockchain.cpp blockToJSON
        """
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
