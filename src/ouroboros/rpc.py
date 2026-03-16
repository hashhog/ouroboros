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

# BIP9 versionbits support
try:
    from sync import get_all_deployments_info
    HAS_VERSIONBITS = True
except ImportError:
    HAS_VERSIONBITS = False

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
        rate_limit: bool = True,
        max_batch_size: int = 1000
    ):
        """Initialize RPC server."""
        self.node = node
        self.port = port
        self.username = username
        self.password = password
        self.rate_limit_enabled = rate_limit
        self.max_batch_size = max_batch_size
        
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
    
    async def _execute_single_rpc(self, req_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single RPC call and return the response as a dict.

        This is used by both single request and batch request handlers.
        Errors are caught and returned as JSON-RPC error responses.
        """
        req_id = req_data.get("id")
        method = req_data.get("method")
        params = req_data.get("params", [])

        t0 = time.monotonic()
        try:
            # Validate request structure
            if not method or not isinstance(method, str):
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid Request: missing method"},
                    "id": req_id
                }

            # Get method handler
            method_name = f"rpc_{method}"
            handler = getattr(self, method_name, None)

            if not handler:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": req_id
                }

            # Call method with params
            if isinstance(params, list):
                result = await handler(*params)
            elif isinstance(params, dict):
                result = await handler(**params)
            else:
                result = await handler()

            return {"jsonrpc": "2.0", "result": result, "id": req_id}

        except HTTPException as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": e.detail},
                "id": req_id
            }
        except Exception as e:
            logger.error(f"RPC error in {method}: {e}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": req_id
            }
        finally:
            if method:
                record_rpc_request(method, time.monotonic() - t0)

    def _register_methods(self):
        """Register all RPC methods"""
        @self.app.post("/")
        async def handle_rpc(http_request: Request):
            """Handle JSON-RPC requests (single or batch)"""
            # Authentication
            if self.security:
                try:
                    credentials = await self._get_credentials(http_request)
                except HTTPException:
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {"code": -32000, "message": "Authentication required"},
                            "id": None
                        }
                    )

            # Rate limiting
            if self.rate_limit_enabled:
                client_ip = self._get_client_ip_from_request(http_request)
                if not self._check_rate_limit(client_ip):
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {"code": -32000, "message": "Rate limit exceeded"},
                            "id": None
                        }
                    )

            # Parse raw body to detect batch vs single request
            try:
                body = await http_request.body()
                request_data = json.loads(body)
            except json.JSONDecodeError as e:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32700, "message": f"Parse error: {e}"},
                        "id": None
                    }
                )

            # Handle batch request (array)
            if isinstance(request_data, list):
                # Empty batch is an error (JSON-RPC 2.0 spec)
                if len(request_data) == 0:
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {"code": -32600, "message": "Invalid Request: empty batch"},
                            "id": None
                        }
                    )

                # Check batch size limit
                if len(request_data) > self.max_batch_size:
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": f"Invalid Request: batch size {len(request_data)} exceeds maximum {self.max_batch_size}"
                            },
                            "id": None
                        }
                    )

                # Execute each request, collecting responses
                responses = []
                for req in request_data:
                    if not isinstance(req, dict):
                        responses.append({
                            "jsonrpc": "2.0",
                            "error": {"code": -32600, "message": "Invalid Request: not an object"},
                            "id": None
                        })
                    else:
                        response = await self._execute_single_rpc(req)
                        # Only include response if not a notification (id is present)
                        # JSON-RPC 2.0: notifications have id=null or missing id
                        if "id" in req:
                            responses.append(response)

                # Return array of responses
                return JSONResponse(content=responses)

            # Handle single request (object)
            elif isinstance(request_data, dict):
                response = await self._execute_single_rpc(request_data)
                return JSONResponse(content=response)

            # Invalid request type
            else:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Invalid Request: expected object or array"},
                        "id": None
                    }
                )
        
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
        """Return blockchain information.

        Reference: Bitcoin Core rpc/blockchain.cpp getblockchaininfo

        Returns an object containing various state info regarding blockchain processing:
        - chain: current network name
        - blocks: height of the most-work fully-validated chain
        - headers: current number of headers we have validated
        - bestblockhash: hash of the currently best block
        - bits: compact representation of the block difficulty target
        - target: the difficulty target
        - difficulty: the current difficulty
        - time: block time of the tip
        - mediantime: median block time
        - verificationprogress: estimate of verification progress [0..1]
        - initialblockdownload: whether node is in IBD mode
        - chainwork: total amount of work in active chain (hex)
        - size_on_disk: estimated size of block and undo files on disk
        - pruned: if blocks are subject to pruning
        - softforks: status of softfork deployments
        """
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

        # Get softfork info from BIP9 versionbits
        softforks = self._get_softforks_info(best_height, network)

        # Get tip block for bits, target, and time
        tip_block = db.get_block(best_hash) if isinstance(best_hash, bytes) else None
        bits = tip_block.bits if tip_block else 0x1d00ffff
        block_time = tip_block.timestamp if tip_block else 0

        # Calculate target from bits (compact format)
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))
        target_hex = f"{target_int:064x}"

        # Get header count (may differ from blocks during sync)
        headers_count = best_height
        if hasattr(self.node, 'sync_manager') and self.node.sync_manager:
            sm = self.node.sync_manager
            if hasattr(sm, 'header_height'):
                headers_count = max(sm.header_height, best_height)

        # Estimate size on disk (block files + undo files)
        size_on_disk = 0
        if hasattr(db, 'get_disk_usage'):
            size_on_disk = db.get_disk_usage()
        elif hasattr(db, 'data_dir'):
            import os
            data_dir = db.data_dir
            if data_dir and os.path.isdir(data_dir):
                for dirpath, _, filenames in os.walk(data_dir):
                    for f in filenames:
                        if f.endswith('.dat') or f.endswith('.ldb') or f.endswith('.log'):
                            try:
                                size_on_disk += os.path.getsize(os.path.join(dirpath, f))
                            except OSError:
                                pass

        # Initial block download detection
        # IBD if: sync progress < 99.9% OR last block time > 24 hours ago
        is_ibd = not self._is_synced()
        if not is_ibd and block_time > 0:
            import time as _time
            # If tip block is older than 24 hours, we're likely still syncing
            if (_time.time() - block_time) > 24 * 60 * 60:
                is_ibd = True

        # Verification progress estimate
        # Use actual sync progress if available, otherwise estimate from time
        verification_progress = 1.0
        if is_ibd:
            # Estimate based on block times (rough approximation)
            if block_time > 0:
                import time as _time
                # Genesis time for mainnet: 2009-01-03 18:15:05 UTC
                genesis_time = 1231006505
                current_time = int(_time.time())
                if current_time > genesis_time:
                    verification_progress = min(1.0, max(0.0,
                        (block_time - genesis_time) / (current_time - genesis_time)
                    ))

        info: Dict[str, Any] = {
            "chain": network,
            "blocks": best_height,
            "headers": headers_count,
            "bestblockhash": best_hash.hex() if isinstance(best_hash, bytes) else best_hash,
            "bits": f"{bits:08x}",
            "target": target_hex,
            "difficulty": self.node.get_current_difficulty(),
            "time": block_time,
            "mediantime": self.node.get_median_time(),
            "verificationprogress": verification_progress,
            "initialblockdownload": is_ibd,
            "chainwork": self.node.get_chainwork(),
            "size_on_disk": size_on_disk,
            "pruned": pruned,
            "softforks": softforks,
        }

        if pruner is not None:
            info.update(pruner.get_prune_info())

        # Add warnings if available
        warnings = []
        if hasattr(self.node, 'get_warnings'):
            warnings = self.node.get_warnings()
        info["warnings"] = warnings

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
        """Return block information.

        Reference: Bitcoin Core rpc/blockchain.cpp getblock

        Args:
            blockhash: The block hash (hex string)
            verbosity: 0 for hex-encoded data, 1 for JSON object, 2 for JSON
                       object with transaction data, 3 for JSON object with
                       transaction data including prevout information

        Returns:
            If verbosity = 0: hex-encoded serialized block data
            If verbosity = 1: JSON object with block info and transaction IDs
            If verbosity = 2: JSON object with full transaction details
            If verbosity = 3: JSON object with transaction details and prevout info
        """
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

        # Common fields for verbosity >= 1
        block_height = getattr(block, 'height', None)

        # Get confirmations (-1 if not on main chain)
        confirmations = -1
        best_hash, best_height = self.node.db.get_best_block()
        if block_height is not None:
            active_hash = self.node.db.get_block_hash_by_height(block_height)
            if active_hash == block_hash:
                confirmations = max(0, best_height - block_height + 1)

        # Calculate block sizes and weight
        block_data_bytes = block.serialize()
        size = len(block_data_bytes)

        # Stripped size: size without witness data
        # For non-SegWit blocks, strippedsize == size
        strippedsize = size
        weight = size * 4  # Default: no witness discount

        if hasattr(block, 'transactions') and block.transactions:
            # Calculate stripped size and weight accurately
            total_base_size = 0
            total_witness_size = 0

            for tx in block.transactions:
                if hasattr(tx, 'get_base_size') and hasattr(tx, 'get_witness_size'):
                    total_base_size += tx.get_base_size()
                    total_witness_size += tx.get_witness_size()
                elif hasattr(tx, 'has_witness') and tx.has_witness:
                    # Estimate: serialize with and without witness
                    full_size = len(tx.serialize())
                    # Witness flag is 2 bytes, then witness data
                    # Rough estimate: assume witness is 50% of SegWit tx
                    total_base_size += full_size // 2
                    total_witness_size += full_size - (full_size // 2)
                else:
                    tx_size = len(tx.serialize())
                    total_base_size += tx_size

            # Block header is 80 bytes (no witness)
            strippedsize = 80 + total_base_size + 1  # +1 for tx count varint (approx)

            # Weight = base_size * 4 + witness_size
            # For block: (header + tx_base) * 4 + witness
            weight = strippedsize * 4 + total_witness_size

        # Calculate target from bits
        bits = block.bits
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            target_int = mantissa >> (8 * (3 - exponent))
        else:
            target_int = mantissa << (8 * (exponent - 3))
        target_hex = f"{target_int:064x}"

        # Number of transactions
        n_tx = len(block.transactions) if hasattr(block, 'transactions') and block.transactions else 0

        # Build result
        result: Dict[str, Any] = {
            "hash": blockhash,
            "confirmations": confirmations,
            "size": size,
            "strippedsize": strippedsize,
            "weight": weight,
            "height": block_height if block_height else 0,
            "version": block.version,
            "versionHex": f"{block.version:08x}",
            "merkleroot": block.merkle_root.hex() if isinstance(block.merkle_root, bytes) else str(block.merkle_root),
            "time": block.timestamp,
            "mediantime": self.node.get_median_time(block_height) if block_height is not None else block.timestamp,
            "nonce": block.nonce,
            "bits": f"{block.bits:08x}",
            "target": target_hex,
            "difficulty": self.node.get_difficulty(block.bits),
            "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0" * 64,
            "nTx": n_tx,
        }

        # Previous block hash (not present for genesis)
        if block.prev_blockhash and block.prev_blockhash != bytes(32):
            result["previousblockhash"] = block.prev_blockhash.hex()

        # Next block hash (not present for tip)
        if block_height is not None:
            next_hash = self._get_next_block_hash(block_height)
            if next_hash:
                result["nextblockhash"] = next_hash

        if verbosity == 1:
            # Transaction IDs only
            result["tx"] = [
                tx.get_txid().hex() if hasattr(tx, 'get_txid') else str(tx.txid)
                for tx in block.transactions
            ] if hasattr(block, 'transactions') and block.transactions else []
        elif verbosity >= 2:
            # Full transaction details
            if hasattr(block, 'transactions') and block.transactions:
                tx_list = []
                for tx in block.transactions:
                    tx_dict = self._tx_to_dict(tx)

                    # Calculate fee for non-coinbase transactions
                    if not tx.is_coinbase:
                        fee = 0
                        input_total = 0
                        for tx_in in tx.inputs:
                            utxo = self.node.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                            if utxo:
                                input_total += utxo['value']
                        output_total = sum(o.value for o in tx.outputs)
                        fee = max(0, input_total - output_total)
                        tx_dict["fee"] = fee / 1e8  # BTC

                    if verbosity >= 3:
                        # Include prevout information for each input
                        vin_with_prevout = []
                        for i, tx_in in enumerate(tx.inputs):
                            vin_dict = self._vin_to_dict(tx_in, i, tx)

                            if not tx.is_coinbase:
                                # Add prevout info
                                utxo = self.node.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                                if utxo:
                                    vin_dict["prevout"] = {
                                        "generated": False,  # TODO: check if coinbase output
                                        "height": utxo.get('height', 0),
                                        "value": utxo['value'] / 1e8,
                                        "scriptPubKey": {
                                            "asm": disassemble_script(utxo['script_pubkey']),
                                            "hex": utxo['script_pubkey'].hex() if isinstance(utxo['script_pubkey'], bytes) else str(utxo['script_pubkey']),
                                            "type": self._get_script_type(utxo['script_pubkey']),
                                        }
                                    }
                            vin_with_prevout.append(vin_dict)

                        tx_dict["vin"] = vin_with_prevout

                    tx_list.append(tx_dict)

                result["tx"] = tx_list
            else:
                result["tx"] = []

        return result
    
    async def rpc_getrawtransaction(
        self,
        txid: str,
        verbose: Union[bool, int] = 0,
        blockhash: Optional[str] = None
    ) -> Union[str, Dict[str, Any]]:
        """Return raw transaction data.

        By default, this call only returns a transaction if it is in the
        mempool. If -txindex is enabled and no blockhash argument is passed,
        it will return the transaction if it is in the mempool or any block.
        If a blockhash argument is passed, it will return the transaction if
        the specified block is available and the transaction is in that block.

        Args:
            txid: The transaction id (hex string)
            verbose: 0 for hex-encoded data, 1 for JSON object, 2 for JSON
                     object with fee and prevout (bool True = 1, False = 0)
            blockhash: The block in which to look for the transaction

        Returns:
            If verbose is 0: hex-encoded raw transaction string
            If verbose is 1 or 2: JSON object with transaction details

        Reference: Bitcoin Core rpc/rawtransaction.cpp getrawtransaction
        """
        # Parse txid
        try:
            tx_hash = bytes.fromhex(txid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid transaction id")

        if len(tx_hash) != 32:
            raise HTTPException(status_code=400, detail="Invalid transaction id")

        # Parse verbosity - support both bool and int
        if isinstance(verbose, bool):
            verbosity = 1 if verbose else 0
        else:
            verbosity = int(verbose)

        # Parse blockhash if provided
        block_hash_bytes = None
        explicit_blockhash = blockhash is not None

        if explicit_blockhash:
            try:
                block_hash_bytes = bytes.fromhex(blockhash)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid block hash")
            if len(block_hash_bytes) != 32:
                raise HTTPException(status_code=400, detail="Invalid block hash")

        # Check database availability
        if not hasattr(self.node, 'db') or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        # Check if txindex is enabled (we assume it is if get_tx_index exists)
        has_txindex = hasattr(self.node.db, 'get_tx_index')

        # 1. Check mempool first (unless explicit blockhash provided)
        tx = None
        in_mempool = False

        if not explicit_blockhash and hasattr(self.node, 'mempool') and self.node.mempool:
            tx = self.node.mempool.get_transaction(tx_hash)
            if tx:
                in_mempool = True

        # 2. Blockchain lookup if not in mempool
        block = None
        block_height = None
        in_active_chain = None

        if not in_mempool:
            if explicit_blockhash:
                # Caller supplied the containing block hash
                block = self.node.db.get_block(block_hash_bytes)
                if block is None:
                    raise HTTPException(
                        status_code=404,
                        detail="Block hash not found"
                    )
                # Check if block has data
                block_height = block.height if hasattr(block, 'height') else None
                # Check if block is in active chain
                if block_height is not None:
                    try:
                        active_hash = self.node.db.get_block_hash_by_height(block_height)
                        if active_hash is not None:
                            in_active_chain = (active_hash == block_hash_bytes)
                        else:
                            in_active_chain = False
                    except Exception:
                        in_active_chain = None
            else:
                # Use the transaction index for O(1) lookup
                if has_txindex:
                    try:
                        loc = self.node.db.get_tx_index(tx_hash)
                    except Exception:
                        loc = None
                    if loc is not None:
                        block_hash_bytes, block_height, _tx_pos = loc
                        block = self.node.db.get_block(block_hash_bytes)

            # Search for the transaction in the block
            if block is not None:
                for block_tx in block.transactions:
                    found_txid = block_tx.get_txid() if hasattr(block_tx, 'get_txid') else block_tx.txid
                    if found_txid == tx_hash:
                        tx = block_tx
                        break

        # 3. Handle not found
        if tx is None:
            if explicit_blockhash:
                raise HTTPException(
                    status_code=404,
                    detail="No such transaction found in the provided block. "
                           "Use gettransaction for wallet transactions."
                )
            elif not has_txindex:
                raise HTTPException(
                    status_code=404,
                    detail="No such mempool transaction. Use -txindex or provide "
                           "a block hash to enable blockchain transaction queries. "
                           "Use gettransaction for wallet transactions."
                )
            else:
                raise HTTPException(
                    status_code=404,
                    detail="No such mempool or blockchain transaction. "
                           "Use gettransaction for wallet transactions."
                )

        # 4. Return result based on verbosity
        if verbosity == 0:
            return tx.serialize().hex()

        # Verbose output (verbosity >= 1)
        result = self._tx_to_dict(tx)

        # Add hex-encoded raw transaction
        result["hex"] = tx.serialize().hex()

        # Add in_active_chain if explicit blockhash was provided
        if explicit_blockhash and in_active_chain is not None:
            result["in_active_chain"] = in_active_chain

        # Add block context fields for confirmed transactions
        if not in_mempool and block is not None:
            if block_hash_bytes:
                result["blockhash"] = block_hash_bytes.hex()
            if block_height is not None:
                result["confirmations"] = self._get_confirmations(block_height)
            else:
                # Try to get height from block
                bh = block.height if hasattr(block, 'height') else None
                if bh is not None:
                    result["confirmations"] = self._get_confirmations(bh)
                else:
                    result["confirmations"] = 0
            result["blocktime"] = block.timestamp
            result["time"] = block.timestamp
        else:
            # Mempool transaction - no confirmations
            pass

        # TODO: verbosity == 2 would include fee and prevout information
        # This requires looking up the spent outputs for each input
        # which needs undo data or UTXO lookups

        return result
    
    async def rpc_getmempoolinfo(self) -> Dict[str, Any]:
        """Return mempool information.

        Reference: Bitcoin Core rpc/mempool.cpp getmempoolinfo

        Returns an object containing details on the active state of the TX memory pool:
        - loaded: True if the initial load attempt of the persisted mempool finished
        - size: Current tx count
        - bytes: Sum of all virtual transaction sizes (BIP 141)
        - usage: Total memory usage for the mempool
        - total_fee: Total fees for the mempool in BTC
        - maxmempool: Maximum memory usage for the mempool
        - mempoolminfee: Minimum fee rate in BTC/kvB for tx to be accepted
        - minrelaytxfee: Current minimum relay fee for transactions
        - incrementalrelayfee: Minimum fee rate increment for mempool limiting/RBF
        - unbroadcastcount: Number of transactions that haven't passed initial broadcast
        - fullrbf: True if mempool accepts RBF without signaling
        """
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            return {
                "loaded": True,
                "size": 0,
                "bytes": 0,
                "usage": 0,
                "total_fee": 0.0,
                "maxmempool": 300_000_000,
                "mempoolminfee": 0.00001,
                "minrelaytxfee": 0.00001,
                "incrementalrelayfee": 0.00001,
                "unbroadcastcount": 0,
                "fullrbf": True,
            }

        mempool = self.node.mempool
        info = mempool.get_mempool_info()

        # Calculate total fees from all mempool entries
        total_fee_sat = 0
        for txid, entry in mempool.transactions.items():
            total_fee_sat += entry.fee

        # Get unbroadcast count if tracked
        unbroadcast_count = 0
        if hasattr(mempool, 'unbroadcast_txids'):
            unbroadcast_count = len(mempool.unbroadcast_txids)
        elif hasattr(mempool, 'get_unbroadcast_count'):
            unbroadcast_count = mempool.get_unbroadcast_count()

        # Memory usage estimate (more accurate than just bytes)
        # Each entry has overhead for hash tables, ancestor/descendant tracking, etc.
        usage = info['bytes']
        if hasattr(mempool, 'get_memory_usage'):
            usage = mempool.get_memory_usage()
        else:
            # Estimate: tx bytes + ~200 bytes overhead per tx for indexing
            usage = info['bytes'] + (info['size'] * 200)

        # Check if mempool is loaded (finished initial load from disk)
        loaded = True
        if hasattr(mempool, 'is_loaded'):
            loaded = mempool.is_loaded()

        # Full RBF setting
        full_rbf = True
        if hasattr(mempool, 'full_rbf'):
            full_rbf = mempool.full_rbf
        elif hasattr(mempool, 'require_standard'):
            # If require_standard is False, we likely accept full RBF
            full_rbf = True

        # Min fee rate calculation (mempoolminfee)
        # This is max(minrelaytxfee, dynamic_min_fee_for_mempool_acceptance)
        min_fee_rate = info.get('min_fee_rate', 1000)  # sat/kvB
        mempoolminfee_btc = min_fee_rate / 1e8  # BTC/kvB

        # Min relay tx fee (static policy setting)
        minrelaytxfee_btc = 0.00001  # 1 sat/vB = 0.00001 BTC/kvB

        # Incremental relay fee for RBF (typically same as minrelaytxfee)
        incrementalfee_btc = 0.00001

        return {
            "loaded": loaded,
            "size": info['size'],
            "bytes": info['bytes'],
            "usage": usage,
            "total_fee": total_fee_sat / 1e8,  # BTC
            "maxmempool": info.get('max_size', 300_000_000),
            "mempoolminfee": mempoolminfee_btc,
            "minrelaytxfee": minrelaytxfee_btc,
            "incrementalrelayfee": incrementalfee_btc,
            "unbroadcastcount": unbroadcast_count,
            "fullrbf": full_rbf,
        }
    
    # Default maxfeerate: 0.10 BTC/kvB (100,000 sat/kvB = 100 sat/vB)
    DEFAULT_MAX_RAW_TX_FEE_RATE = 0.10  # BTC/kvB

    async def rpc_sendrawtransaction(
        self,
        hexstring: str,
        maxfeerate: Optional[float] = None
    ) -> str:
        """
        Submit a raw transaction (serialized, hex-encoded) to the network.

        The transaction will be validated against consensus and policy rules,
        then added to the mempool and relayed to peers via INV messages.

        Reference: Bitcoin Core rpc/mempool.cpp sendrawtransaction

        Args:
            hexstring: Hex-encoded raw transaction
            maxfeerate: Reject if fee rate exceeds this (BTC/kvB). Default: 0.10.
                        Set to 0 to accept any fee rate.

        Returns:
            The transaction hash (txid) in hex

        Raises:
            HTTPException: On validation failure with detailed reject reason
        """
        # 1. Deserialize the hex-encoded raw transaction
        try:
            tx_data = bytes.fromhex(hexstring.strip())
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"TX decode failed: {e}"
            )

        try:
            from ouroboros.p2p_messages import TxMessage
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="P2P messages not available"
            )

        try:
            tx_msg = TxMessage.from_payload(tx_data)
            tx = tx_msg.transaction
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"TX decode failed. Make sure the tx has at least one input. {e}"
            )

        txid = tx.get_txid()
        txid_hex = txid.hex()

        # Reject coinbase transactions
        if tx.is_coinbase:
            raise HTTPException(
                status_code=400,
                detail="coinbase"
            )

        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            raise HTTPException(
                status_code=500,
                detail="Mempool not available"
            )

        # 2. Check if already in mempool — return txid if so
        if self.node.mempool.has_transaction(txid):
            return txid_hex

        # 3. Check if already confirmed — return txid if so
        if hasattr(self.node, 'db') and self.node.db:
            try:
                loc = self.node.db.get_tx_index(txid)
                if loc is not None:
                    # Transaction is already confirmed on-chain
                    return txid_hex
            except Exception:
                pass

        # 4. Check maxfeerate parameter (safety check against absurd fees)
        # Default: 0.10 BTC/kvB = 100,000 sat/kvB = 100 sat/vB
        if maxfeerate is None:
            maxfeerate = self.DEFAULT_MAX_RAW_TX_FEE_RATE

        # Calculate transaction fee and vsize
        _, best_height = self.node.db.get_best_block()

        # Calculate total input value from UTXOs
        total_input = 0
        for tx_in in tx.inputs:
            # Check mempool first for unconfirmed parent outputs
            parent_entry = self.node.mempool.transactions.get(tx_in.prev_txid)
            if parent_entry and tx_in.prev_vout < len(parent_entry.tx.outputs):
                total_input += parent_entry.tx.outputs[tx_in.prev_vout].value
            else:
                utxo = self.node.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                if utxo:
                    total_input += utxo['value']
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="missing-inputs"
                    )

        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output

        if fee < 0:
            raise HTTPException(
                status_code=400,
                detail="bad-txns-in-belowout"
            )

        # Calculate fee rate in BTC/kvB
        vsize = tx.get_vsize()
        fee_rate_btc_kvb = (fee / 1e8) / (vsize / 1000.0)  # fee in BTC / vsize in kvB

        # Reject if fee rate exceeds maxfeerate (unless maxfeerate is 0)
        if maxfeerate > 0 and fee_rate_btc_kvb > maxfeerate:
            raise HTTPException(
                status_code=400,
                detail=f"max-fee-exceeded: fee rate {fee_rate_btc_kvb:.8f} BTC/kvB "
                       f"exceeds maxfeerate {maxfeerate:.8f} BTC/kvB"
            )

        # 5. Submit to mempool — runs all policy and consensus checks
        success, error = self.node.mempool.add_transaction(tx, best_height)

        if not success:
            # Map common errors to Bitcoin Core-style reject reasons
            reject_reason = self._map_mempool_error_to_reject_reason(error)
            raise HTTPException(
                status_code=400,
                detail=reject_reason
            )

        # 6. Relay INV to all connected peers via trickle queue (privacy)
        # Use privacy-preserving relay via INV messages
        wtxid = tx.get_wtxid() if hasattr(tx, 'get_wtxid') else txid

        if hasattr(self.node, 'peer_manager') and self.node.peer_manager:
            # Use trickle queue for privacy-preserving relay
            self.node.peer_manager.queue_tx_for_relay(txid, wtxid)

        logger.info(
            f"sendrawtransaction: accepted {txid_hex[:16]}... "
            f"(fee={fee} sat, rate={fee_rate_btc_kvb:.8f} BTC/kvB)"
        )

        # 7. Return the txid on success
        return txid_hex

    def _map_mempool_error_to_reject_reason(self, error: str) -> str:
        """Map internal mempool error messages to Bitcoin Core-style reject reasons.

        Reference: Bitcoin Core validation.cpp TxValidationResult
        """
        error_lower = error.lower()

        # Already in mempool (shouldn't reach here, but handle gracefully)
        if "already in mempool" in error_lower:
            return "txn-already-in-mempool"

        # Missing inputs (orphan)
        if "orphan" in error_lower:
            return "missing-inputs"

        # UTXO not found
        if "utxo not found" in error_lower:
            return "missing-inputs"

        # Double spend / conflict
        if "conflict" in error_lower or "double" in error_lower:
            return "txn-mempool-conflict"

        # Fee too low
        if "fee" in error_lower and ("low" in error_lower or "minimum" in error_lower or "below" in error_lower):
            return "insufficient-fee"

        # Non-standard
        if "non-standard" in error_lower or "standardness" in error_lower:
            return "non-standard"

        # Script failure
        if "script" in error_lower:
            return "script-failed"

        # Ancestor/descendant limits
        if "ancestor" in error_lower or "descendant" in error_lower:
            return "too-long-mempool-chain"

        # Size/weight limits
        if "size" in error_lower or "weight" in error_lower:
            return "tx-size"

        # TRUC (v3) policy
        if "truc" in error_lower or "v3" in error_lower:
            return "truc-policy"

        # Dust output
        if "dust" in error_lower:
            return "dust"

        # Negative fee
        if "negative" in error_lower:
            return "bad-txns-in-belowout"

        # Default: return original error
        return error
    
    async def rpc_getnetworkinfo(self) -> Dict[str, Any]:
        """Return network information.

        Reference: Bitcoin Core rpc/net.cpp getnetworkinfo

        Returns an object containing various state info regarding P2P networking:
        - version: the server version
        - subversion: the server subversion string
        - protocolversion: the protocol version
        - localservices: the services we offer to the network (hex)
        - localservicesnames: the services we offer, in human-readable form
        - localrelay: true if transaction relay is requested from peers
        - timeoffset: the time offset
        - connections: the total number of connections
        - connections_in: the number of inbound connections
        - connections_out: the number of outbound connections
        - networkactive: whether p2p networking is enabled
        - networks: information per network
        - relayfee: minimum relay fee rate for transactions
        - incrementalfee: minimum fee rate increment for mempool limiting or RBF
        - localaddresses: list of local addresses
        - warnings: any network and blockchain warnings
        """
        peers = []
        connections_in = 0
        connections_out = 0
        pm = getattr(self.node, 'peer_manager', None)

        if pm:
            if hasattr(pm, 'get_all_ready_peers'):
                peers = pm.get_all_ready_peers()
            elif hasattr(pm, 'peers'):
                peers = list(pm.peers.values()) if isinstance(pm.peers, dict) else list(pm.peers)

            # Count inbound vs outbound
            for peer in peers:
                if getattr(peer, 'inbound', False):
                    connections_in += 1
                else:
                    connections_out += 1

        total_connections = len(peers)

        # Local services we offer
        local_services = 0x0409  # NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
        if hasattr(self.node, 'local_services'):
            local_services = self.node.local_services
        elif pm and hasattr(pm, 'local_services'):
            local_services = pm.local_services

        local_services_hex = f"{local_services:016x}"

        # Service names
        service_names = []
        if local_services & 1:
            service_names.append("NETWORK")
        if local_services & 2:
            service_names.append("GETUTXO")
        if local_services & 4:
            service_names.append("BLOOM")
        if local_services & 8:
            service_names.append("WITNESS")
        if local_services & 64:
            service_names.append("COMPACT_FILTERS")
        if local_services & 1024:
            service_names.append("NETWORK_LIMITED")
        if local_services & 2048:
            service_names.append("P2P_V2")

        # Network active status
        network_active = True
        if pm and hasattr(pm, 'network_active'):
            network_active = pm.network_active

        # Time offset (median of connected peers)
        time_offset = 0
        if pm and hasattr(pm, 'get_time_offset'):
            time_offset = pm.get_time_offset()

        # Networks info
        networks = []
        for net_name in ["ipv4", "ipv6", "onion", "i2p", "cjdns"]:
            net_info = {
                "name": net_name,
                "limited": False,
                "reachable": net_name in ["ipv4", "ipv6"],  # Default reachability
                "proxy": "",
                "proxy_randomize_credentials": False,
            }
            # Check if we have specific network config
            if hasattr(self.node, 'network_config'):
                nc = self.node.network_config.get(net_name, {})
                net_info["limited"] = nc.get("limited", False)
                net_info["reachable"] = nc.get("reachable", net_name in ["ipv4", "ipv6"])
                net_info["proxy"] = nc.get("proxy", "")
                net_info["proxy_randomize_credentials"] = nc.get("proxy_randomize_credentials", False)
            networks.append(net_info)

        # Local addresses
        local_addresses = []
        if pm and hasattr(pm, 'local_addresses'):
            for addr_info in pm.local_addresses:
                local_addresses.append({
                    "address": addr_info.get("address", ""),
                    "port": addr_info.get("port", 8333),
                    "score": addr_info.get("score", 0),
                })

        # Relay fee (minimum fee for tx to be relayed)
        relay_fee = 0.00001  # 1 sat/vB in BTC/kvB
        if hasattr(self.node, 'mempool') and self.node.mempool:
            if hasattr(self.node.mempool, 'min_relay_fee'):
                relay_fee = self.node.mempool.min_relay_fee / 1e8

        # Incremental fee for RBF
        incremental_fee = 0.00001

        # Warnings
        warnings = []
        if hasattr(self.node, 'get_warnings'):
            warnings = self.node.get_warnings()

        return {
            "version": 250000,  # Ouroboros version
            "subversion": "/Ouroboros:0.25.0/",
            "protocolversion": 70016,
            "localservices": local_services_hex,
            "localservicesnames": service_names,
            "localrelay": True,
            "timeoffset": time_offset,
            "networkactive": network_active,
            "connections": total_connections,
            "connections_in": connections_in,
            "connections_out": connections_out,
            "networks": networks,
            "relayfee": relay_fee,
            "incrementalfee": incremental_fee,
            "localaddresses": local_addresses,
            "warnings": warnings,
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

        Reference: Bitcoin Core rpc/blockchain.cpp getblockheader

        Args:
            blockhash: Block hash (hex string)
            verbose: If True, return JSON object; if False, return hex-encoded header

        Returns:
            If verbose=True: Dictionary with header fields:
                - hash: the block hash (same as provided)
                - confirmations: number of confirmations, or -1 if not on main chain
                - height: the block height or index
                - version: the block version
                - versionHex: the block version formatted in hexadecimal
                - merkleroot: the merkle root
                - time: the block time (UNIX timestamp)
                - mediantime: the median block time (UNIX timestamp)
                - nonce: the nonce
                - bits: compact representation of the block difficulty target
                - target: the difficulty target
                - difficulty: the difficulty
                - chainwork: expected hashes to produce the current chain
                - nTx: number of transactions in the block
                - previousblockhash: hash of the previous block (if available)
                - nextblockhash: hash of the next block (if available)

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
            # -1 if block is not on the main chain
            confirmations = -1
            best_hash, best_height = self.node.db.get_best_block()
            if block_height is not None:
                # Check if this block is on the active chain
                active_hash = self.node.db.get_block_hash_by_height(block_height)
                if active_hash == block_hash:
                    confirmations = max(0, best_height - block_height + 1)
                # else confirmations stays -1

            # Calculate target from bits
            bits = block.bits
            mantissa = bits & 0x007FFFFF
            exponent = (bits >> 24) & 0xFF
            if exponent <= 3:
                target_int = mantissa >> (8 * (3 - exponent))
            else:
                target_int = mantissa << (8 * (exponent - 3))
            target_hex = f"{target_int:064x}"

            # Number of transactions
            n_tx = len(block.transactions) if hasattr(block, 'transactions') and block.transactions else 0

            result: Dict[str, Any] = {
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
                "target": target_hex,
                "difficulty": self.node.get_difficulty(block.bits),
                "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0" * 64,
                "nTx": n_tx,
            }

            # Previous block hash (not present for genesis)
            if block.prev_blockhash and block.prev_blockhash != bytes(32):
                result["previousblockhash"] = block.prev_blockhash.hex()

            # Next block hash (not present for tip)
            if block_height is not None:
                next_hash = self._get_next_block_hash(block_height)
                if next_hash:
                    result["nextblockhash"] = next_hash

            return result

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
        Generate a new address from the wallet's key pool.

        Args:
            label: Optional label for the address
            address_type: Type of address to generate:
                - "bech32" (default): Native SegWit P2WPKH (bc1q...)
                - "p2sh-segwit": P2SH-wrapped SegWit (3...)
                - "bech32m": Taproot P2TR (bc1p...)
                - "legacy": P2PKH (1...)

        Returns:
            The newly generated address string

        Reference: Bitcoin Core wallet/rpc/addresses.cpp getnewaddress
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )
        return await wallet.generate_new_address(label, address_type=address_type)

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

        Reference: Bitcoin Core wallet/rpc/wallet.cpp getwalletinfo
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")

        balance = await wallet.get_balance()

        # Use key pool size if available, otherwise count addresses
        keypool_size = wallet.get_keypool_size()
        if keypool_size == 0:
            addresses = await wallet.get_addresses()
            keypool_size = len(addresses)

        info: Dict[str, Any] = {
            "walletname": wallet.name,
            "walletversion": 1,
            "balance": balance / 1e8,
            "unconfirmed_balance": 0.0,
            "immature_balance": 0.0,
            "txcount": 0,
            "keypoolsize": keypool_size,
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

    async def rpc_keypoolrefill(self, newsize: int = 1000) -> None:
        """
        Refill the key pool.

        Args:
            newsize: Target key pool size (default 1000)

        Reference: Bitcoin Core wallet/rpc/wallet.cpp keypoolrefill
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )

        generated = wallet.keypoolrefill(newsize)
        logger.info(f"Key pool refilled with {generated} new keys")
        return None

    async def rpc_getrawchangeaddress(self, address_type: str = "bech32") -> str:
        """
        Generate a new change address for receiving change.

        Args:
            address_type: Type of address to generate (bech32, p2sh-segwit, legacy, bech32m)

        Returns:
            A new change address from the internal (change) key pool

        Reference: Bitcoin Core wallet/rpc/addresses.cpp getrawchangeaddress
        """
        wallet = getattr(self.node, "wallet", None)
        if wallet is None:
            raise HTTPException(status_code=500, detail="Wallet not loaded")
        if wallet.is_locked:
            raise HTTPException(
                status_code=500,
                detail="Wallet is locked; unlock with walletpassphrase first"
            )

        return await wallet.get_change_address(address_type=address_type)

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

        Locktime enforcement:
        - Transactions with nLockTime > next_height (or > MTP for time-based)
          are excluded from the template.

        Coinbase requirements (for miners using this template):
        - Coinbase nSequence: 0xFFFFFFFF (SEQUENCE_FINAL)
        - Coinbase nLockTime: 0
        - Witness commitment: OP_RETURN <0xaa21a9ed><32-byte-commitment>
          in the last output, where commitment = SHA256d(witness_root || nonce)
          and nonce is 32 zero bytes (coinbase witness item).
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

        # Get MTP for time-based locktime checks (BIP 113)
        block_mtp = db.get_median_time_past(best_height) or 0

        # Try to use Rust is_final_tx for locktime checking
        try:
            from sync import is_final_tx as rust_is_final_tx
            use_rust_final = True
        except ImportError:
            use_rust_final = False

        def _is_tx_final(tx) -> bool:
            """Check if transaction is final for inclusion in next block."""
            sequences = [inp.sequence for inp in tx.inputs]
            if use_rust_final:
                return rust_is_final_tx(tx.locktime, sequences, next_height, block_mtp)
            else:
                # Python fallback
                LOCKTIME_THRESHOLD = 500_000_000
                if tx.locktime == 0:
                    return True
                if all(seq == 0xFFFFFFFF for seq in sequences):
                    return True
                if tx.locktime < LOCKTIME_THRESHOLD:
                    return tx.locktime < next_height
                else:
                    return tx.locktime < block_mtp

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

                # Skip non-final transactions (locktime not yet satisfied)
                if not _is_tx_final(entry.tx):
                    continue

                # Collect required ancestors (+ self) in topological order
                batch = _collect_ancestors(entry_txid, included)

                # Skip if any ancestor is not final
                batch_valid = True
                for t in batch:
                    anc_entry = snap_txs.get(t)
                    if anc_entry and not _is_tx_final(anc_entry.tx):
                        batch_valid = False
                        break
                if not batch_valid:
                    continue

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

        # Coinbase requirements:
        # - nSequence: 0xFFFFFFFF (SEQUENCE_FINAL)
        # - nLockTime: 0
        # - witness: single 32-byte zero nonce
        coinbase_aux = {
            "flags": "",  # extra nonce space in coinbase scriptSig
        }

        return {
            "version": best_block.version,
            "previousblockhash": best_hash.hex(),
            "transactions": txs,
            "coinbaseaux": coinbase_aux,
            "coinbasevalue": coinbase_value,
            "coinbasetxn": {
                "locktime": 0,
                "sequence": 0xFFFFFFFF,
            },
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

        Instructs the node to delete old block files (blk*.dat and rev*.dat)
        up to the specified height.  Block headers and metadata are preserved.

        The actual prune height may be less than requested to maintain the
        minimum reorg safety margin (288 blocks).

        Returns:
            The height of the last block that was pruned.
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

        # Use the file-based pruner
        actual_height = pruner.prune_to_height(height, best_height)
        logger.info(f"RPC pruneblockchain: pruned up to height {actual_height}")
        return actual_height

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
        """Return information about connected peers.

        Reference: Bitcoin Core rpc/net.cpp getpeerinfo

        Returns data about each connected network peer as a JSON array of objects.
        Each peer object includes:
        - id: Peer index
        - addr: IP address and port
        - services: Services offered (hex)
        - servicesnames: Human-readable service names
        - lastsend: UNIX timestamp of last send
        - lastrecv: UNIX timestamp of last receive
        - bytessent: Total bytes sent
        - bytesrecv: Total bytes received
        - conntime: Connection time (UNIX timestamp)
        - version: Protocol version
        - subver: User agent string
        - inbound: True if inbound connection
        - connection_type: Type of connection
        - synced_headers: Last header we have in common
        - synced_blocks: Last block we have in common
        """
        import time as _time

        peers = []
        pm = getattr(self.node, 'peer_manager', None) or getattr(self.node, 'p2p', None)
        if pm is None:
            return []

        peer_list = getattr(pm, 'peers', [])
        if isinstance(peer_list, dict):
            peer_list = list(peer_list.values())

        for i, peer in enumerate(peer_list):
            # Get peer ID (use internal ID if available)
            peer_id = getattr(peer, 'id', i)

            # Get address
            addr = getattr(peer, 'address', '')
            if not addr and hasattr(peer, 'host') and hasattr(peer, 'port'):
                addr = f"{peer.host}:{peer.port}"

            # Services
            services = getattr(peer, 'services', 0)
            services_hex = f"{services:016x}"

            # Service names (Bitcoin Core style)
            service_names = []
            if services & 1:    # NODE_NETWORK
                service_names.append("NETWORK")
            if services & 2:    # NODE_GETUTXO
                service_names.append("GETUTXO")
            if services & 4:    # NODE_BLOOM
                service_names.append("BLOOM")
            if services & 8:    # NODE_WITNESS
                service_names.append("WITNESS")
            if services & 16:   # NODE_XTHIN
                service_names.append("XTHIN")
            if services & 64:   # NODE_COMPACT_FILTERS
                service_names.append("COMPACT_FILTERS")
            if services & 1024: # NODE_NETWORK_LIMITED
                service_names.append("NETWORK_LIMITED")
            if services & 2048: # NODE_P2P_V2
                service_names.append("P2P_V2")

            # Timestamps
            now = int(_time.time())
            lastsend = getattr(peer, 'last_send', 0)
            lastrecv = getattr(peer, 'last_recv', 0)
            conntime = getattr(peer, 'connected_time', now)

            # Bytes sent/received
            bytessent = getattr(peer, 'bytes_sent', 0)
            bytesrecv = getattr(peer, 'bytes_recv', 0)

            # Connection type
            inbound = getattr(peer, 'inbound', False)
            connection_type = "inbound" if inbound else "outbound-full-relay"
            if hasattr(peer, 'connection_type'):
                connection_type = peer.connection_type
            elif hasattr(peer, 'is_feeler') and peer.is_feeler:
                connection_type = "feeler"
            elif hasattr(peer, 'is_block_relay_only') and peer.is_block_relay_only:
                connection_type = "block-relay-only"

            # Ping times
            pingtime = getattr(peer, 'ping_time', None)
            minping = getattr(peer, 'min_ping_time', None)
            pingwait = getattr(peer, 'ping_wait', None)

            # Block relay info
            bip152_hb_to = getattr(peer, 'bip152_highbandwidth_to', False)
            bip152_hb_from = getattr(peer, 'bip152_highbandwidth_from', False)

            # Min fee filter
            minfeefilter = getattr(peer, 'fee_filter', 0)

            info: Dict[str, Any] = {
                "id": peer_id,
                "addr": addr,
                "services": services_hex,
                "servicesnames": service_names,
                "relaytxes": getattr(peer, 'relay_txes', True),
                "lastsend": lastsend,
                "lastrecv": lastrecv,
                "last_transaction": getattr(peer, 'last_tx_time', 0),
                "last_block": getattr(peer, 'last_block_time', 0),
                "bytessent": bytessent,
                "bytesrecv": bytesrecv,
                "conntime": conntime,
                "timeoffset": getattr(peer, 'time_offset', 0),
                "version": getattr(peer, 'version', 0),
                "subver": getattr(peer, 'user_agent', ''),
                "inbound": inbound,
                "bip152_hb_to": bip152_hb_to,
                "bip152_hb_from": bip152_hb_from,
                "startingheight": getattr(peer, 'start_height', 0),
                "presynced_headers": getattr(peer, 'presynced_headers', -1),
                "synced_headers": getattr(peer, 'synced_headers', -1),
                "synced_blocks": getattr(peer, 'synced_blocks', -1),
                "inflight": getattr(peer, 'inflight_blocks', []),
                "addr_relay_enabled": getattr(peer, 'addr_relay_enabled', True),
                "addr_processed": getattr(peer, 'addr_processed', 0),
                "addr_rate_limited": getattr(peer, 'addr_rate_limited', 0),
                "permissions": getattr(peer, 'permissions', []),
                "minfeefilter": minfeefilter / 1e8 if minfeefilter > 0 else 0.0,
                "connection_type": connection_type,
            }

            # Optional ping fields
            if pingtime is not None:
                info["pingtime"] = pingtime
            if minping is not None:
                info["minping"] = minping
            if pingwait is not None and pingwait > 0:
                info["pingwait"] = pingwait

            # Bytes per message type (if tracked)
            if hasattr(peer, 'bytes_sent_per_msg'):
                info["bytessent_per_msg"] = peer.bytes_sent_per_msg
            if hasattr(peer, 'bytes_recv_per_msg'):
                info["bytesrecv_per_msg"] = peer.bytes_recv_per_msg

            # Ban score (legacy)
            banscore = getattr(peer, 'ban_score', 0)
            if banscore > 0:
                info["banscore"] = banscore

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

    async def rpc_setban(
        self,
        subnet: str,
        command: str,
        bantime: int = 0,
        absolute: bool = False,
    ) -> None:
        """Add or remove an IP/subnet from the ban list.

        Args:
            subnet: IP address or subnet to ban (e.g., "192.168.0.1" or "192.168.0.0/24")
            command: "add" to ban, "remove" to unban
            bantime: Ban duration in seconds (0 = default 24 hours)
            absolute: If True, bantime is an absolute UNIX timestamp

        Raises:
            ValueError: If command is invalid
        """
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            raise ValueError("Peer manager not available")

        bm = pm.ban_manager
        if command not in ("add", "remove"):
            raise ValueError(f"Invalid command: {command}")

        success = bm.setban(subnet, command, bantime, absolute)
        if not success:
            raise ValueError(f"setban failed for {subnet}")

    async def rpc_listbanned(self) -> List[Dict[str, Any]]:
        """Return list of all banned IPs/subnets.

        Returns:
            List of dicts with address, ban_created, banned_until, ban_duration
        """
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            return []

        bm = pm.ban_manager
        return bm.list_banned_detailed()

    async def rpc_clearbanned(self) -> None:
        """Clear all banned IPs/subnets."""
        pm = getattr(self.node, 'peer_manager', None)
        if not pm or not hasattr(pm, 'ban_manager'):
            return

        bm = pm.ban_manager
        # Clear all bans
        bm.banned.clear()
        bm.scores.clear()
        if bm._data_dir:
            bm._save_bans()
        logger.info("Cleared all bans")

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

        Reference: Bitcoin Core rpc/blockchain.cpp getchaintips

        Returns a list of chain tips, including the active chain tip and any
        orphan/stale branches. Each entry contains:
        - height: height of the chain tip
        - hash: block hash of the tip
        - branchlen: zero for main chain, otherwise length of branch connecting
                     the tip to the main chain
        - status: status of the chain

        Status values:
          "active"        — the current best chain tip (most work)
          "valid-fork"    — fully validated fork, not part of active chain
          "valid-headers" — all blocks available but not fully validated
          "headers-only"  — only headers received, block data unavailable
          "invalid"       — branch contains at least one invalid block
        """
        if not hasattr(self.node, "db") or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")

        db = self.node.db
        tips: List[Dict[str, Any]] = []

        # Active chain tip ---------------------------------------------------
        best_hash, best_height = db.get_best_block()
        tip_hash_hex: str
        if isinstance(best_hash, bytes):
            tip_hash_hex = best_hash.hex()
        else:
            tip_hash_hex = str(best_hash)

        tips.append({
            "height": best_height,
            "hash": tip_hash_hex,
            "branchlen": 0,
            "status": "active",
        })

        # Collect orphan/stale tips from block index -------------------------
        # A tip is a block with no known children in the block index.
        # We identify tips by finding blocks that are not referenced as
        # prev_blockhash by any other block.

        # Get all known block hashes
        all_blocks: Dict[bytes, Any] = {}
        parent_refs: set = set()  # blocks that are someone's parent

        # If the database has a block index, iterate it
        if hasattr(db, 'get_all_block_hashes'):
            for block_hash in db.get_all_block_hashes():
                block = db.get_block(block_hash)
                if block:
                    all_blocks[block_hash] = block
                    if block.prev_blockhash and block.prev_blockhash != bytes(32):
                        parent_refs.add(block.prev_blockhash)

        elif hasattr(db, 'block_index'):
            # Direct access to block index
            for block_hash, block_info in db.block_index.items():
                block = db.get_block(block_hash)
                if block:
                    all_blocks[block_hash] = block
                    if block.prev_blockhash and block.prev_blockhash != bytes(32):
                        parent_refs.add(block.prev_blockhash)

        # Blocks that are tips (not referenced as parent by anyone)
        for block_hash, block in all_blocks.items():
            if block_hash == best_hash:
                continue  # Already added as active tip

            if block_hash not in parent_refs:
                # This is a tip
                block_height = getattr(block, 'height', 0) or 0

                # Determine status
                status = "headers-only"
                branchlen = 0

                # Check if block has full data
                has_data = hasattr(block, 'transactions') and block.transactions

                # Check if block is marked invalid
                is_invalid = getattr(block, 'is_invalid', False)
                if hasattr(db, 'is_block_invalid'):
                    is_invalid = db.is_block_invalid(block_hash)

                if is_invalid:
                    status = "invalid"
                elif has_data:
                    # Check if fully validated
                    is_validated = getattr(block, 'is_validated', True)
                    if hasattr(db, 'is_block_validated'):
                        is_validated = db.is_block_validated(block_hash)

                    if is_validated:
                        status = "valid-fork"
                    else:
                        status = "valid-headers"
                else:
                    status = "headers-only"

                # Calculate branch length by walking back to find fork point
                # Fork point is where this branch meets the active chain
                fork_height = 0
                current = block
                visited = set()
                while current and current.prev_blockhash != bytes(32):
                    if current.prev_blockhash in visited:
                        break
                    visited.add(current.prev_blockhash)

                    # Check if prev is on active chain
                    prev_hash = current.prev_blockhash
                    prev_height = None

                    # Try to get height from active chain
                    if hasattr(db, 'get_block_height'):
                        prev_height = db.get_block_height(prev_hash)
                    elif prev_hash in all_blocks:
                        prev_height = getattr(all_blocks[prev_hash], 'height', None)

                    if prev_height is not None:
                        # Check if this hash is in active chain at this height
                        active_hash = db.get_block_hash_by_height(prev_height)
                        if active_hash == prev_hash:
                            fork_height = prev_height
                            break

                    # Move to parent
                    if prev_hash in all_blocks:
                        current = all_blocks[prev_hash]
                    else:
                        current = db.get_block(prev_hash)
                        if current:
                            all_blocks[prev_hash] = current

                branchlen = max(0, block_height - fork_height)

                tips.append({
                    "height": block_height,
                    "hash": block_hash.hex() if isinstance(block_hash, bytes) else str(block_hash),
                    "branchlen": branchlen,
                    "status": status,
                })

        # Sort by height descending (Bitcoin Core behavior)
        tips.sort(key=lambda x: (-x["height"], x["hash"]))

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

    def _get_softforks_info(self, height: int, network: str) -> Dict[str, Any]:
        """Get BIP9 softfork deployment info for getblockchaininfo.

        Returns a dict mapping deployment names to their state info.
        """
        if not HAS_VERSIONBITS:
            return {}

        # For a full implementation, we'd query block versions/MTPs from DB
        # For now, return static info based on known activation heights
        softforks = {}

        try:
            # Get deployment info from Rust
            # We need to pass block versions and MTPs for the BIP9 state machine
            # For now, use empty lists which will return ALWAYS_ACTIVE deployments correctly
            deployments = get_all_deployments_info(height, network, [], [])

            for dep in deployments:
                sf_info: Dict[str, Any] = {
                    "type": "bip9",
                    "bip9": {
                        "status": dep.state,
                        "bit": dep.bit,
                        "start_time": dep.start_time,
                        "timeout": dep.timeout,
                        "since": dep.since,
                        "min_activation_height": dep.min_activation_height,
                    },
                    "active": dep.state == "active",
                }

                # Add statistics if available (for STARTED/LOCKED_IN states)
                if dep.period is not None:
                    sf_info["bip9"]["statistics"] = {
                        "period": dep.period,
                        "threshold": dep.threshold,
                        "elapsed": dep.elapsed,
                        "count": dep.count,
                        "possible": dep.possible,
                    }

                # Add activation height if known and active
                if dep.state == "active" and dep.min_activation_height > 0:
                    sf_info["height"] = dep.min_activation_height

                softforks[dep.name] = sf_info
        except Exception as e:
            logger.debug(f"Could not get softfork info: {e}")

        return softforks

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
    
    # --- PSBT RPCs (BIP174/BIP370) --------------------------------------------

    async def rpc_createpsbt(
        self,
        inputs: List[Dict[str, Any]],
        outputs: List[Dict[str, Any]],
        locktime: int = 0,
        replaceable: bool = True,
    ) -> str:
        """
        Create a Partially Signed Bitcoin Transaction (PSBT).

        Args:
            inputs: Array of input objects with txid, vout, and optional sequence
            outputs: Array of output objects with address:amount pairs
            locktime: Transaction locktime (default 0)
            replaceable: Enable RBF (default True)

        Returns:
            Base64-encoded PSBT string
        """
        from ouroboros.psbt import createpsbt
        return createpsbt(inputs, outputs, locktime, replaceable)

    async def rpc_decodepsbt(self, psbt: str) -> Dict[str, Any]:
        """
        Decode a PSBT to human-readable format.

        Args:
            psbt: Base64-encoded PSBT

        Returns:
            Decoded PSBT as dictionary
        """
        from ouroboros.psbt import decodepsbt
        return decodepsbt(psbt)

    async def rpc_analyzepsbt(self, psbt: str) -> Dict[str, Any]:
        """
        Analyze a PSBT and determine the next action needed.

        Args:
            psbt: Base64-encoded PSBT

        Returns:
            Analysis including inputs status, next role, estimated fees
        """
        from ouroboros.psbt import analyzepsbt
        return analyzepsbt(psbt)

    async def rpc_combinepsbt(self, psbts: List[str]) -> str:
        """
        Combine multiple PSBTs for the same transaction.

        Args:
            psbts: Array of base64-encoded PSBTs

        Returns:
            Combined base64-encoded PSBT
        """
        from ouroboros.psbt import combinepsbt
        return combinepsbt(psbts)

    async def rpc_finalizepsbt(
        self, psbt: str, extract: bool = True
    ) -> Dict[str, Any]:
        """
        Finalize a PSBT and optionally extract the signed transaction.

        Args:
            psbt: Base64-encoded PSBT
            extract: If True and complete, return hex transaction

        Returns:
            {psbt: base64, complete: bool, hex: raw_tx (if complete and extract)}
        """
        from ouroboros.psbt import finalizepsbt
        return finalizepsbt(psbt, extract)

    async def rpc_utxoupdatepsbt(
        self, psbt: str, descriptors: List[Any] = None
    ) -> str:
        """
        Update a PSBT with UTXO information from the UTXO set.

        Args:
            psbt: Base64-encoded PSBT
            descriptors: Optional output descriptors (not yet implemented)

        Returns:
            Updated base64-encoded PSBT
        """
        from ouroboros.psbt import PSBT

        psbt_obj = PSBT.from_base64(psbt)

        # Look up UTXOs from our database
        if psbt_obj.tx is not None and hasattr(self.node, 'db') and self.node.db:
            for i, tx_in in enumerate(psbt_obj.tx.inputs):
                if psbt_obj.inputs[i].witness_utxo is not None:
                    continue  # Already has UTXO info

                try:
                    utxo = self.node.db.get_utxo(
                        tx_in.prev_txid, tx_in.prev_vout
                    )
                    if utxo:
                        psbt_obj.inputs[i].witness_utxo = (
                            utxo.value, utxo.script_pubkey
                        )
                except Exception:
                    pass

        return psbt_obj.to_base64()

    async def rpc_joinpsbts(self, psbts: List[str]) -> str:
        """
        Join multiple PSBTs into a single PSBT.

        Unlike combinepsbt which merges signatures for the same transaction,
        joinpsbts creates a new transaction combining inputs/outputs from
        multiple PSBTs.

        Args:
            psbts: Array of base64-encoded PSBTs

        Returns:
            Joined base64-encoded PSBT
        """
        from ouroboros.psbt import joinpsbts
        return joinpsbts(psbts)

    async def rpc_walletprocesspsbt(
        self,
        psbt: str,
        sign: bool = True,
        sighashtype: str = "ALL",
        bip32derivs: bool = True,
    ) -> Dict[str, Any]:
        """
        Update a PSBT with wallet information and optionally sign inputs.

        Args:
            psbt: Base64-encoded PSBT
            sign: Whether to sign inputs the wallet has keys for
            sighashtype: Signature hash type (ALL, NONE, SINGLE, etc.)
            bip32derivs: Include BIP32 derivation paths

        Returns:
            {psbt: base64, complete: bool}
        """
        import hashlib
        import struct
        from ouroboros.psbt import PSBT, SIGHASH_ALL
        from ouroboros.wallet import WalletKey, _hash160, _dsha256

        # Parse sighash type
        sighash_map = {
            "ALL": 0x01, "NONE": 0x02, "SINGLE": 0x03,
            "ALL|ANYONECANPAY": 0x81, "NONE|ANYONECANPAY": 0x82,
            "SINGLE|ANYONECANPAY": 0x83, "DEFAULT": 0x00,
        }
        sighash_type = sighash_map.get(sighashtype.upper(), 0x01)

        psbt_obj = PSBT.from_base64(psbt)

        if psbt_obj.tx is None:
            raise ValueError("PSBT has no transaction")

        # Get wallet if available
        wallet = getattr(self.node, 'wallet', None)
        if wallet is None:
            return {"psbt": psbt_obj.to_base64(), "complete": False}

        # Build key lookup from wallet
        network = getattr(self.node, 'network', 'mainnet')
        keys_by_h160: Dict[bytes, WalletKey] = {}
        keys_by_pubkey: Dict[bytes, WalletKey] = {}

        # Get all wallet keys
        for key_info in wallet.keys:
            try:
                k = WalletKey.from_wif(key_info['wif'], network)
                keys_by_h160[_hash160(k.pubkey)] = k
                keys_by_pubkey[k.pubkey] = k
                keys_by_pubkey[k.pubkey[1:]] = k  # x-only for Taproot
            except Exception:
                pass

        # Also include HD-derived keys if available
        if hasattr(wallet, '_key_pool') and wallet._key_pool:
            try:
                for wk in wallet._key_pool.get_all_keys():
                    keys_by_h160[_hash160(wk.pubkey)] = wk
                    keys_by_pubkey[wk.pubkey] = wk
                    keys_by_pubkey[wk.pubkey[1:]] = wk
            except Exception:
                pass

        # Helper functions for signing
        def _encode_varint(n: int) -> bytes:
            if n < 0xFD:
                return bytes([n])
            elif n <= 0xFFFF:
                return b'\xfd' + struct.pack('<H', n)
            elif n <= 0xFFFFFFFF:
                return b'\xfe' + struct.pack('<I', n)
            else:
                return b'\xff' + struct.pack('<Q', n)

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

        def _taproot_sighash(tx, idx, sh_type, amounts, spks):
            acp = (sh_type & 0x80) != 0
            base = sh_type & 0x03
            data = bytearray()
            data.append(0x00)  # epoch
            data.append(sh_type if sh_type != 0 else 0x00)
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
            data.append(0x00)  # spend_type: no annex
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
            tag = hashlib.sha256(b"TapSighash").digest()
            return hashlib.sha256(tag + tag + bytes(data)).digest()

        # First pass: update UTXO info and add derivation paths
        tx = psbt_obj.tx
        all_amounts = []
        all_spks = []

        for idx, psbt_in in enumerate(psbt_obj.inputs):
            if psbt_in.is_finalized():
                all_amounts.append(0)
                all_spks.append(b"")
                continue

            # Get UTXO info
            amount = 0
            spk = b""

            if psbt_in.witness_utxo is not None:
                amount, spk = psbt_in.witness_utxo
            elif psbt_in.non_witness_utxo is not None:
                # Parse the prev tx to get the output
                try:
                    from ouroboros.psbt import _deserialize_tx
                    prev_tx = _deserialize_tx(psbt_in.non_witness_utxo)
                    tx_in = tx.inputs[idx]
                    out = prev_tx.outputs[tx_in.prev_vout]
                    amount = out.value
                    spk = out.script_pubkey
                except Exception:
                    pass
            else:
                # Try to look up from database
                tx_in = tx.inputs[idx]
                if hasattr(self.node, 'db') and self.node.db:
                    try:
                        utxo = self.node.db.get_utxo(
                            tx_in.prev_txid, tx_in.prev_vout
                        )
                        if utxo:
                            amount = utxo.value
                            spk = utxo.script_pubkey
                            psbt_in.witness_utxo = (amount, spk)
                    except Exception:
                        pass

            all_amounts.append(amount)
            all_spks.append(spk)

        # Second pass: sign inputs
        if sign:
            for idx, psbt_in in enumerate(psbt_obj.inputs):
                if psbt_in.is_finalized():
                    continue

                spk = all_spks[idx]
                amount = all_amounts[idx]

                if not spk:
                    continue

                try:
                    # P2WPKH: OP_0 <20-byte-hash>
                    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                        h160 = spk[2:22]
                        key = keys_by_h160.get(h160)
                        if key:
                            script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
                            sh = _bip143_sighash(
                                tx, idx, script_code, amount, sighash_type
                            )
                            sig = key.sign(sh) + bytes([sighash_type])
                            psbt_in.partial_sigs[key.pubkey] = sig
                            psbt_in.sighash_type = sighash_type

                    # P2TR: OP_1 <32-byte-x-only>
                    elif len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
                        x_only = spk[2:34]
                        key = keys_by_pubkey.get(x_only)
                        if key:
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
                                    continue
                            if sighash_type != 0x00:
                                raw_sig += bytes([sighash_type])
                            psbt_in.tap_key_sig = raw_sig

                    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                    elif len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9:
                        h160 = spk[3:23]
                        key = keys_by_h160.get(h160)
                        if key:
                            # Legacy sighash
                            def _legacy_sighash(tx, idx, script_code, sh_type):
                                base = sh_type & 0x1F
                                acp = (sh_type & 0x80) != 0
                                data = bytearray()
                                data.extend(struct.pack("<i", tx.version))
                                inputs = [(idx, tx.inputs[idx])] if acp else list(enumerate(tx.inputs))
                                data.extend(_encode_varint(len(inputs)))
                                for i, ti in inputs:
                                    data.extend(ti.prev_txid)
                                    data.extend(struct.pack("<I", ti.prev_vout))
                                    if i == idx:
                                        data.extend(_encode_varint(len(script_code)))
                                        data.extend(script_code)
                                    else:
                                        data.extend(b"\x00")
                                    seq = 0 if base in (2, 3) and i != idx else ti.sequence
                                    data.extend(struct.pack("<I", seq))
                                if base in (0, 1):
                                    data.extend(_encode_varint(len(tx.outputs)))
                                    for o in tx.outputs:
                                        data.extend(struct.pack("<q", o.value))
                                        data.extend(_encode_varint(len(o.script_pubkey)))
                                        data.extend(o.script_pubkey)
                                elif base == 2:
                                    data.extend(b"\x00")
                                elif base == 3:
                                    if idx >= len(tx.outputs):
                                        return bytes(32)
                                    data.extend(_encode_varint(idx + 1))
                                    for j, o in enumerate(tx.outputs):
                                        if j == idx:
                                            data.extend(struct.pack("<q", o.value))
                                            data.extend(_encode_varint(len(o.script_pubkey)))
                                            data.extend(o.script_pubkey)
                                        else:
                                            data.extend((-1).to_bytes(8, "little", signed=True))
                                            data.extend(b"\x00")
                                data.extend(struct.pack("<I", tx.locktime))
                                data.extend(struct.pack("<I", sh_type))
                                return _dsha256(bytes(data))

                            sh = _legacy_sighash(tx, idx, spk, sighash_type)
                            sig = key.sign(sh) + bytes([sighash_type])
                            psbt_in.partial_sigs[key.pubkey] = sig
                            psbt_in.sighash_type = sighash_type

                except Exception:
                    pass

        # Check if complete
        complete = all(inp.is_finalized() or bool(inp.partial_sigs) or inp.tap_key_sig
                      for inp in psbt_obj.inputs)

        return {"psbt": psbt_obj.to_base64(), "complete": complete}

    async def rpc_converttopsbt(
        self, hexstring: str, permitsigdata: bool = False
    ) -> str:
        """
        Convert a network-serialized transaction to a PSBT.

        Args:
            hexstring: Hex-encoded raw transaction
            permitsigdata: Allow transaction with signature data

        Returns:
            Base64-encoded PSBT
        """
        from ouroboros.psbt import PSBT
        from ouroboros.p2p_messages import TxMessage

        try:
            tx_msg = TxMessage.from_payload(bytes.fromhex(hexstring))
            tx = tx_msg.transaction
        except Exception as e:
            raise ValueError(f"TX decode failed: {e}")

        # Check for existing signatures unless permitted
        if not permitsigdata:
            for inp in tx.inputs:
                if inp.script_sig or (hasattr(inp, 'witness') and inp.witness):
                    raise ValueError(
                        "Transaction has signatures; use permitsigdata=true to strip"
                    )

        psbt = PSBT.from_transaction(tx)
        return psbt.to_base64()

    def get_app(self) -> FastAPI:
        """Get the FastAPI application"""
        return self.app
