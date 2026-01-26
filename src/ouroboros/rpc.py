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
                        return {
                            "bestblock": None,  # TODO: Get best block hash
                            "confirmations": 0,
                            "value": output.value / 100000000.0,  # Convert to BTC
                            "scriptPubKey": {
                                "asm": disassemble_script(script_pubkey_bytes),
                                "hex": output.script_pubkey.hex() if isinstance(output.script_pubkey, bytes) else str(output.script_pubkey),
                                "type": self._get_script_type(output.script_pubkey)
                            },
                            "coinbase": False
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
            
            return {
                "bestblock": best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash),
                "confirmations": confirmations,
                "value": utxo['value'] / 100000000.0,  # Convert to BTC
                "scriptPubKey": {
                    "asm": disassemble_script(script_pubkey_bytes),
                    "hex": script_hex,
                    "type": self._get_script_type(script_pubkey)
                },
                "coinbase": False  # TODO: Check if coinbase
            }
        
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid transaction ID: {e}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting txout: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
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
        
        return {
            "txid": txid_hex,
            "hash": txid_hex,  # TODO: Add wtxid for segwit (witness transaction ID)
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
        
        # TODO: Add witness data when it's stored in Transaction
        # if tx and hasattr(tx, 'witness') and tx.witness and index < len(tx.witness):
        #     result["txinwitness"] = [item.hex() for item in tx.witness[index]]
        
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
