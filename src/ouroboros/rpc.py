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
        """Broadcast transaction"""
        try:
            tx_data = bytes.fromhex(hexstring)
            # TODO: Deserialize transaction
            # For now, this is a placeholder
            raise HTTPException(status_code=500, detail="Transaction deserialization not fully implemented")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid hex string: {e}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid transaction: {e}")
    
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
    
    # Helper methods
    
    def _tx_to_dict(self, tx: Transaction) -> Dict[str, Any]:
        """Convert transaction to dictionary"""
        txid = tx.get_txid() if hasattr(tx, 'get_txid') else tx.txid
        txid_hex = txid.hex() if isinstance(txid, bytes) else str(txid)
        
        return {
            "txid": txid_hex,
            "hash": txid_hex,  # TODO: Add wtxid for segwit
            "version": tx.version,
            "size": len(tx.serialize()),
            "vsize": len(tx.serialize()),  # TODO: Calculate vsize for segwit
            "weight": len(tx.serialize()) * 4,  # TODO: Calculate weight
            "locktime": tx.locktime,
            "vin": [self._vin_to_dict(vin) for vin in tx.inputs],
            "vout": [self._vout_to_dict(vout, i) for i, vout in enumerate(tx.outputs)],
        }
    
    def _vin_to_dict(self, vin: TxIn) -> Dict[str, Any]:
        """Convert input to dictionary"""
        prev_txid = vin.prev_txid.hex() if isinstance(vin.prev_txid, bytes) else str(vin.prev_txid)
        script_sig = vin.script_sig.hex() if isinstance(vin.script_sig, bytes) else str(vin.script_sig)
        
        return {
            "txid": prev_txid,
            "vout": vin.prev_vout,
            "scriptSig": {
                "asm": "",  # TODO: disassemble script
                "hex": script_sig,
            },
            "sequence": vin.sequence,
        }
    
    def _vout_to_dict(self, vout: TxOut, n: int) -> Dict[str, Any]:
        """Convert output to dictionary"""
        script_pubkey = vout.script_pubkey.hex() if isinstance(vout.script_pubkey, bytes) else bytes(vout.script_pubkey).hex()
        
        return {
            "value": vout.value / 100_000_000,  # Convert satoshis to BTC
            "n": n,
            "scriptPubKey": {
                "asm": "",  # TODO: disassemble script
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
        
        Args:
            height: Block height
            
        Returns:
            Next block hash as hex string, or None if no next block
        """
        if not hasattr(self.node, 'db') or not self.node.db:
            return None
        
        try:
            # Get next block at height + 1
            next_block = self.node.db.get_block_by_height(height + 1)
            if next_block:
                # Try to get hash from block object
                if hasattr(next_block, 'hash') and next_block.hash:
                    next_hash = next_block.hash
                    if isinstance(next_hash, bytes):
                        return next_hash.hex()
                    return str(next_hash)
                
                # Fallback: get hash by height
                next_hash = self.node.db.get_block_hash_by_height(height + 1)
                if next_hash:
                    if isinstance(next_hash, bytes):
                        return next_hash.hex()
                    return str(next_hash)
            
            return None
        
        except Exception as e:
            logger.debug(f"Error getting next block hash for height {height}: {e}")
            return None
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI application"""
        return self.app
