"""
HTTP REST interface for blockchain data.

This module implements Bitcoin Core-compatible REST endpoints for accessing
blockchain data without JSON-RPC authentication. These are read-only endpoints
suitable for public-facing block explorers and lightweight clients.

Reference: Bitcoin Core rest.cpp
"""

import logging
from enum import Enum
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response

if TYPE_CHECKING:
    from ouroboros.node import BitcoinNode

logger = logging.getLogger(__name__)

# Maximum number of headers that can be requested at once
MAX_REST_HEADERS_RESULTS = 2000

# Maximum number of outpoints that can be queried at once
MAX_GETUTXOS_OUTPOINTS = 15


class RESTResponseFormat(Enum):
    """REST response format types."""
    BINARY = "bin"
    HEX = "hex"
    JSON = "json"


def parse_format(path: str) -> tuple[str, RESTResponseFormat | None]:
    """
    Parse format suffix from path (e.g., 'blockhash.json' -> ('blockhash', JSON)).

    Returns (param, format) tuple. Format is None if no valid suffix found.
    """
    # Remove query string
    path = path.split('?')[0]

    # Find last dot
    dot_pos = path.rfind('.')
    if dot_pos == -1:
        return path, None

    suffix = path[dot_pos + 1:].lower()
    param = path[:dot_pos]

    format_map = {
        'bin': RESTResponseFormat.BINARY,
        'hex': RESTResponseFormat.HEX,
        'json': RESTResponseFormat.JSON,
    }

    return param, format_map.get(suffix)


def available_formats_string() -> str:
    """Return string listing available format suffixes."""
    return ".bin, .hex, .json"


class RESTInterface:
    """
    Bitcoin REST interface handler.

    Provides read-only HTTP endpoints for accessing blockchain data without
    JSON-RPC authentication. Implements Bitcoin Core-compatible REST API.
    """

    def __init__(self, node: "BitcoinNode"):
        """
        Initialize REST interface.

        Args:
            node: Bitcoin node instance providing access to blockchain data
        """
        self.node = node
        self.router = APIRouter(prefix="/rest", tags=["rest"])
        self._register_routes()

    def _register_routes(self):
        """Register all REST endpoints."""
        # Block endpoints (notxdetails must be registered BEFORE block to match first)
        self.router.add_api_route(
            "/block/notxdetails/{blockhash:path}",
            self.rest_block_notxdetails,
            methods=["GET"],
            name="rest_block_notxdetails",
        )
        self.router.add_api_route(
            "/block/{blockhash:path}",
            self.rest_block,
            methods=["GET"],
            name="rest_block",
        )

        # Headers endpoint
        self.router.add_api_route(
            "/headers/{path:path}",
            self.rest_headers,
            methods=["GET"],
            name="rest_headers",
        )

        # Transaction endpoint
        self.router.add_api_route(
            "/tx/{txid:path}",
            self.rest_tx,
            methods=["GET"],
            name="rest_tx",
        )

        # UTXO endpoint
        self.router.add_api_route(
            "/getutxos/{path:path}",
            self.rest_getutxos,
            methods=["GET"],
            name="rest_getutxos",
        )

        # Block hash by height endpoint
        self.router.add_api_route(
            "/blockhashbyheight/{height:path}",
            self.rest_blockhash_by_height,
            methods=["GET"],
            name="rest_blockhash_by_height",
        )

        # Chain info endpoint
        self.router.add_api_route(
            "/chaininfo.json",
            self.rest_chaininfo,
            methods=["GET"],
            name="rest_chaininfo",
        )

        # Mempool endpoints
        self.router.add_api_route(
            "/mempool/info.json",
            self.rest_mempool_info,
            methods=["GET"],
            name="rest_mempool_info",
        )
        self.router.add_api_route(
            "/mempool/contents.json",
            self.rest_mempool_contents,
            methods=["GET"],
            name="rest_mempool_contents",
        )

    def _get_db(self):
        """Get database, raise HTTP 500 if not available."""
        if not hasattr(self.node, 'db') or not self.node.db:
            raise HTTPException(status_code=500, detail="Database not available")
        return self.node.db

    def _get_mempool(self):
        """Get mempool, raise HTTP 404 if not available."""
        if not hasattr(self.node, 'mempool') or not self.node.mempool:
            raise HTTPException(status_code=404, detail="Mempool disabled or instance not found")
        return self.node.mempool

    def _format_response(
        self,
        data: bytes,
        rf: RESTResponseFormat,
        json_data: Any = None,
    ) -> Response:
        """
        Format response based on requested format.

        Args:
            data: Binary data for bin/hex formats
            rf: Requested response format
            json_data: JSON-serializable data for JSON format

        Returns:
            Appropriate Response object
        """
        if rf == RESTResponseFormat.BINARY:
            return Response(
                content=data,
                media_type="application/octet-stream",
            )
        elif rf == RESTResponseFormat.HEX:
            return PlainTextResponse(
                content=data.hex() + "\n",
                media_type="text/plain",
            )
        elif rf == RESTResponseFormat.JSON:
            if json_data is None:
                raise HTTPException(
                    status_code=404,
                    detail="output format not found (available: json)"
                )
            return JSONResponse(content=json_data)
        else:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

    async def rest_block(self, blockhash: str) -> Response:
        """
        Get block by hash with full transaction details.

        Path: /rest/block/<hash>.<format>

        Formats:
        - .json: JSON object with transaction details and prevout info
        - .hex: Hex-encoded serialized block
        - .bin: Raw binary serialized block
        """
        param, rf = parse_format(blockhash)
        if rf is None:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

        return await self._get_block_response(param, rf, include_tx_details=True)

    async def rest_block_notxdetails(self, blockhash: str) -> Response:
        """
        Get block by hash with transaction IDs only (no details).

        Path: /rest/block/notxdetails/<hash>.<format>
        """
        param, rf = parse_format(blockhash)
        if rf is None:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

        return await self._get_block_response(param, rf, include_tx_details=False)

    async def _get_block_response(
        self,
        hash_str: str,
        rf: RESTResponseFormat,
        include_tx_details: bool,
    ) -> Response:
        """Get block data in requested format."""
        # Validate hash
        try:
            block_hash = bytes.fromhex(hash_str)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {hash_str}") from None

        if len(block_hash) != 32:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {hash_str}")

        db = self._get_db()
        block = db.get_block(block_hash)

        if not block:
            raise HTTPException(status_code=404, detail=f"{hash_str} not found")

        # Get serialized block data
        try:
            block_data = block.serialize()
        except Exception:
            raise HTTPException(status_code=500, detail=f"I/O error reading {hash_str}") from None

        if rf == RESTResponseFormat.BINARY:
            return Response(content=block_data, media_type="application/octet-stream")

        elif rf == RESTResponseFormat.HEX:
            return PlainTextResponse(content=block_data.hex() + "\n", media_type="text/plain")

        elif rf == RESTResponseFormat.JSON:
            # Build JSON response
            json_data = self._block_to_json(block, include_tx_details)
            return JSONResponse(content=json_data)

        raise HTTPException(
            status_code=404,
            detail=f"output format not found (available: {available_formats_string()})"
        )

    def _block_to_json(self, block: Any, include_tx_details: bool) -> dict[str, Any]:
        """Convert block to JSON representation."""
        db = self._get_db()

        block_hash = block.hash if hasattr(block, 'hash') else block.get_hash()
        block_height = getattr(block, 'height', None)

        # Get confirmations
        confirmations = -1
        best_hash, best_height = db.get_best_block()
        if block_height is not None:
            active_hash = db.get_block_hash_by_height(block_height)
            if active_hash == block_hash:
                confirmations = max(0, best_height - block_height + 1)

        # Calculate sizes and weight (BIP 141)
        block_data = block.serialize()  # stripped (no witness)
        strippedsize = len(block_data)

        txs_list = block.transactions if hasattr(block, 'transactions') else []
        if txs_list:
            from ouroboros.p2p_messages import encode_varint
            hdr_varint = 80 + len(encode_varint(len(txs_list)))
            total_tx = sum(len(tx.serialize_with_witness()) for tx in txs_list)
            size = hdr_varint + total_tx
            weight = strippedsize * 3 + size
        else:
            size = strippedsize
            weight = size * 4

        # Get transactions
        txs = block.transactions if hasattr(block, 'transactions') else []
        n_tx = len(txs)

        # Calculate target from bits
        bits = block.bits
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            mantissa >> (8 * (3 - exponent))
        else:
            mantissa << (8 * (exponent - 3))

        result: dict[str, Any] = {
            "hash": block_hash[::-1].hex() if isinstance(block_hash, bytes) else str(block_hash),
            "confirmations": confirmations,
            "size": size,
            "strippedsize": strippedsize,
            "weight": weight,
            "height": block_height if block_height is not None else 0,
            "version": block.version,
            "versionHex": f"{block.version:08x}",
            "merkleroot": block.merkle_root[::-1].hex() if isinstance(block.merkle_root, bytes) else str(block.merkle_root),
            "time": block.timestamp,
            "mediantime": self.node.get_median_time(block_height) if block_height is not None else block.timestamp,
            "nonce": block.nonce,
            "bits": f"{block.bits:08x}",
            "difficulty": self.node.get_difficulty(block.bits),
            "chainwork": self.node.get_chainwork_at_height(block_height) if block_height is not None else "0" * 64,
            "nTx": n_tx,
        }

        # Previous block hash
        if block.prev_blockhash and block.prev_blockhash != bytes(32):
            result["previousblockhash"] = block.prev_blockhash[::-1].hex()

        # Next block hash
        if block_height is not None:
            next_block = db.get_block_by_height(block_height + 1)
            if next_block:
                next_hash = next_block.hash if hasattr(next_block, 'hash') else next_block.get_hash()
                result["nextblockhash"] = next_hash[::-1].hex() if isinstance(next_hash, bytes) else str(next_hash)

        # Transactions
        if include_tx_details:
            # Full transaction details with prevout
            tx_list = []
            for tx in txs:
                tx_dict = self._tx_to_json(tx)
                tx_list.append(tx_dict)
            result["tx"] = tx_list
        else:
            # Transaction IDs only
            result["tx"] = [
                tx.get_txid().hex() if hasattr(tx, 'get_txid') else str(tx.txid)
                for tx in txs
            ]

        return result

    def _tx_to_json(self, tx: Any) -> dict[str, Any]:
        """Convert transaction to JSON representation."""
        from ouroboros.script import disassemble_script

        txid = tx.get_txid() if hasattr(tx, 'get_txid') else tx.txid
        wtxid = tx.get_wtxid() if hasattr(tx, 'get_wtxid') else txid

        # Serialize
        tx_data = tx.serialize()
        size = len(tx_data)
        vsize = tx.get_vsize() if hasattr(tx, 'get_vsize') else size
        weight = tx.get_weight() if hasattr(tx, 'get_weight') else size * 4

        result: dict[str, Any] = {
            "txid": txid.hex() if isinstance(txid, bytes) else str(txid),
            "hash": wtxid.hex() if isinstance(wtxid, bytes) else str(wtxid),
            "version": tx.version,
            "size": size,
            "vsize": vsize,
            "weight": weight,
            "locktime": tx.locktime,
        }

        # Inputs
        vin = []
        for i, tx_in in enumerate(tx.inputs):
            if tx.is_coinbase:
                vin.append({
                    "coinbase": tx_in.script_sig.hex() if isinstance(tx_in.script_sig, bytes) else str(tx_in.script_sig),
                    "sequence": tx_in.sequence,
                })
            else:
                vin_entry: dict[str, Any] = {
                    "txid": tx_in.prev_txid.hex() if isinstance(tx_in.prev_txid, bytes) else str(tx_in.prev_txid),
                    "vout": tx_in.prev_vout,
                    "scriptSig": {
                        "asm": disassemble_script(tx_in.script_sig) if tx_in.script_sig else "",
                        "hex": tx_in.script_sig.hex() if isinstance(tx_in.script_sig, bytes) else str(tx_in.script_sig or ""),
                    },
                    "sequence": tx_in.sequence,
                }

                # Add witness data if present
                if hasattr(tx, 'witnesses') and tx.witnesses and i < len(tx.witnesses):
                    witness = tx.witnesses[i]
                    if witness:
                        vin_entry["txinwitness"] = [
                            item.hex() if isinstance(item, bytes) else str(item)
                            for item in witness
                        ]

                vin.append(vin_entry)

        result["vin"] = vin

        # Outputs
        vout = []
        for n, tx_out in enumerate(tx.outputs):
            script_pubkey = tx_out.script_pubkey if hasattr(tx_out, 'script_pubkey') else tx_out.script
            vout.append({
                "value": tx_out.value / 1e8,
                "n": n,
                "scriptPubKey": {
                    "asm": disassemble_script(script_pubkey) if script_pubkey else "",
                    "hex": script_pubkey.hex() if isinstance(script_pubkey, bytes) else str(script_pubkey or ""),
                    "type": self._get_script_type(script_pubkey),
                }
            })

        result["vout"] = vout

        return result

    def _get_script_type(self, script: bytes) -> str:
        """Determine script type."""
        if not script:
            return "nonstandard"

        length = len(script)

        # P2PKH: OP_DUP OP_HASH160 <20> <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        if length == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac:
            return "pubkeyhash"

        # P2SH: OP_HASH160 <20> <scripthash> OP_EQUAL
        if length == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
            return "scripthash"

        # P2WPKH: OP_0 <20> <pubkeyhash>
        if length == 22 and script[0] == 0x00 and script[1] == 0x14:
            return "witness_v0_keyhash"

        # P2WSH: OP_0 <32> <scripthash>
        if length == 34 and script[0] == 0x00 and script[1] == 0x20:
            return "witness_v0_scripthash"

        # P2TR: OP_1 <32> <pubkey>
        if length == 34 and script[0] == 0x51 and script[1] == 0x20:
            return "witness_v1_taproot"

        # P2PK: <33/65> <pubkey> OP_CHECKSIG
        if (length == 35 and script[0] == 0x21 and script[34] == 0xac) or \
           (length == 67 and script[0] == 0x41 and script[66] == 0xac):
            return "pubkey"

        # OP_RETURN (nulldata)
        if length > 0 and script[0] == 0x6a:
            return "nulldata"

        # Multisig: OP_<n> <pubkeys> OP_<m> OP_CHECKMULTISIG
        if length > 0 and script[-1] == 0xae:
            return "multisig"

        return "nonstandard"

    async def rest_headers(
        self,
        path: str,
        count: int | None = Query(default=None),
    ) -> Response:
        """
        Get block headers.

        Path: /rest/headers/<count>/<hash>.<format>  (deprecated)
        Path: /rest/headers/<hash>.<format>?count=<count>  (preferred)

        Args:
            path: Either "<count>/<hash>.<format>" or "<hash>.<format>"
            count: Number of headers (query param, default 5)
        """
        # Parse path to extract format
        parts = path.split('/')

        if len(parts) == 2:
            # Deprecated format: /rest/headers/<count>/<hash>.<format>
            raw_count = parts[0]
            hash_with_format = parts[1]
        elif len(parts) == 1:
            # New format: /rest/headers/<hash>.<format>?count=<count>
            raw_count = str(count) if count is not None else "5"
            hash_with_format = parts[0]
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid URI format. Expected /rest/headers/<hash>.<ext>?count=<count>"
            )

        hash_str, rf = parse_format(hash_with_format)
        if rf is None:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

        # Parse count
        try:
            num_headers = int(raw_count)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Header count is invalid or out of acceptable range (1-{MAX_REST_HEADERS_RESULTS}): {raw_count}"
            ) from None

        if num_headers < 1 or num_headers > MAX_REST_HEADERS_RESULTS:
            raise HTTPException(
                status_code=400,
                detail=f"Header count is invalid or out of acceptable range (1-{MAX_REST_HEADERS_RESULTS}): {raw_count}"
            )

        # Parse hash
        try:
            block_hash = bytes.fromhex(hash_str)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {hash_str}") from None

        if len(block_hash) != 32:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {hash_str}")

        db = self._get_db()

        # Find starting block and collect headers
        block = db.get_block(block_hash)
        if not block:
            raise HTTPException(status_code=404, detail=f"{hash_str} not found")

        headers: list[Any] = []
        current_height = getattr(block, 'height', None)

        if current_height is not None:
            # Collect headers from this block forward
            for i in range(num_headers):
                blk = db.get_block_by_height(current_height + i)
                if blk is None:
                    break
                headers.append(blk)
        else:
            # No height info, just return this one header
            headers.append(block)

        if rf == RESTResponseFormat.BINARY:
            # Serialize all headers (80 bytes each)
            data = b''.join(h.serialize()[:80] for h in headers)
            return Response(content=data, media_type="application/octet-stream")

        elif rf == RESTResponseFormat.HEX:
            data = b''.join(h.serialize()[:80] for h in headers)
            return PlainTextResponse(content=data.hex() + "\n", media_type="text/plain")

        elif rf == RESTResponseFormat.JSON:
            best_hash, best_height = db.get_best_block()
            json_headers = []
            for h in headers:
                h_height = getattr(h, 'height', 0)
                confirmations = best_height - h_height + 1 if h_height is not None else 0
                h_hash = h.hash if hasattr(h, 'hash') else h.get_hash()

                json_headers.append({
                    "hash": h_hash.hex() if isinstance(h_hash, bytes) else str(h_hash),
                    "confirmations": confirmations,
                    "height": h_height,
                    "version": h.version,
                    "versionHex": f"{h.version:08x}",
                    "merkleroot": h.merkle_root[::-1].hex() if isinstance(h.merkle_root, bytes) else str(h.merkle_root),
                    "time": h.timestamp,
                    "mediantime": self.node.get_median_time(h_height) if h_height is not None else h.timestamp,
                    "nonce": h.nonce,
                    "bits": f"{h.bits:08x}",
                    "difficulty": self.node.get_difficulty(h.bits),
                    "chainwork": self.node.get_chainwork_at_height(h_height) if h_height is not None else "0" * 64,
                    "nTx": len(h.transactions) if hasattr(h, 'transactions') and h.transactions else 0,
                    "previousblockhash": h.prev_blockhash[::-1].hex() if h.prev_blockhash and h.prev_blockhash != bytes(32) else None,
                })

            return JSONResponse(content=json_headers)

        raise HTTPException(
            status_code=404,
            detail=f"output format not found (available: {available_formats_string()})"
        )

    async def rest_tx(self, txid: str) -> Response:
        """
        Get transaction by txid.

        Path: /rest/tx/<txid>.<format>

        Looks up transaction in both mempool and blockchain (if txindex enabled).
        """
        param, rf = parse_format(txid)
        if rf is None:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

        # Parse txid.  REST convention mirrors JSON-RPC: txids in URLs are
        # display-order (big-endian) hex; internal storage (mempool keys
        # and the ``tx_index`` column family written by
        # ``store_tx_index_batch``) is little-endian. Reverse on parse so
        # the mempool lookup at :649 and the txindex hit at :654 both see
        # consistent LE bytes — and so the ``found_txid == tx_hash``
        # compare at :661 succeeds when the block contains the tx.
        # Pattern C0 (txindex-revert-on-reorg corpus, 2026-05-05).
        try:
            tx_hash = bytes.fromhex(param)[::-1]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {param}") from None

        if len(tx_hash) != 32:
            raise HTTPException(status_code=400, detail=f"Invalid hash: {param}")

        db = self._get_db()

        # Check mempool first
        tx = None
        block_hash = None

        if hasattr(self.node, 'mempool') and self.node.mempool:
            tx = self.node.mempool.get_transaction(tx_hash)

        # Check blockchain via txindex
        if tx is None and hasattr(db, 'get_tx_index'):
            try:
                loc = db.get_tx_index(tx_hash)
                if loc is not None:
                    block_hash_bytes, block_height, tx_pos = loc
                    block = db.get_block(block_hash_bytes)
                    if block and hasattr(block, 'transactions'):
                        for block_tx in block.transactions:
                            found_txid = block_tx.get_txid() if hasattr(block_tx, 'get_txid') else block_tx.txid
                            if found_txid == tx_hash:
                                tx = block_tx
                                block_hash = block_hash_bytes
                                break
            except Exception:
                pass

        if tx is None:
            raise HTTPException(status_code=404, detail=f"{param} not found")

        # Serialize transaction
        tx_data = tx.serialize()

        if rf == RESTResponseFormat.BINARY:
            return Response(content=tx_data, media_type="application/octet-stream")

        elif rf == RESTResponseFormat.HEX:
            return PlainTextResponse(content=tx_data.hex() + "\n", media_type="text/plain")

        elif rf == RESTResponseFormat.JSON:
            tx_json = self._tx_to_json(tx)
            if block_hash:
                tx_json["blockhash"] = block_hash.hex() if isinstance(block_hash, bytes) else str(block_hash)
            return JSONResponse(content=tx_json)

        raise HTTPException(
            status_code=404,
            detail=f"output format not found (available: {available_formats_string()})"
        )

    async def rest_getutxos(self, path: str) -> Response:
        """
        Query UTXO set for specific outpoints.

        Path: /rest/getutxos/<checkmempool>/<txid>-<n>/....<format>

        The first path component can be "checkmempool" to also check mempool.
        Outpoints are specified as <txid>-<vout>.
        """
        # Parse format from last component
        parts = path.split('/')
        if not parts:
            raise HTTPException(status_code=400, detail="Error: empty request")

        # Extract format from last part
        last_part = parts[-1]
        param, rf = parse_format(last_part)
        if rf is None:
            rf = RESTResponseFormat.JSON
            param = last_part

        # Reconstruct parts with parsed last component
        parts = parts[:-1] + [param] if param else parts[:-1]

        # Check for checkmempool flag
        check_mempool = False
        start_idx = 0

        if parts and parts[0] == "checkmempool":
            check_mempool = True
            start_idx = 1

        # Parse outpoints
        outpoints: list[tuple[bytes, int]] = []
        for i in range(start_idx, len(parts)):
            part = parts[i]
            if not part:
                continue

            try:
                txid_out = part.split('-')
                if len(txid_out) != 2:
                    raise HTTPException(status_code=400, detail="Parse error")

                txid_bytes = bytes.fromhex(txid_out[0])
                if len(txid_bytes) != 32:
                    raise HTTPException(status_code=400, detail="Parse error")

                vout = int(txid_out[1])
                outpoints.append((txid_bytes, vout))
            except ValueError:
                raise HTTPException(status_code=400, detail="Parse error") from None

        if not outpoints:
            raise HTTPException(status_code=400, detail="Error: empty request")

        if len(outpoints) > MAX_GETUTXOS_OUTPOINTS:
            raise HTTPException(
                status_code=400,
                detail=f"Error: max outpoints exceeded (max: {MAX_GETUTXOS_OUTPOINTS}, tried: {len(outpoints)})"
            )

        db = self._get_db()
        best_hash, best_height = db.get_best_block()

        # Query UTXOs
        bitmap = []
        utxos = []

        for txid_bytes, vout in outpoints:
            # Check mempool spent status
            if check_mempool and hasattr(self.node, 'mempool') and self.node.mempool:
                if self.node.mempool.is_spent(txid_bytes, vout):
                    bitmap.append(False)
                    continue

            # Check UTXO set
            utxo = db.get_utxo(txid_bytes, vout)
            if utxo:
                bitmap.append(True)
                utxos.append({
                    "height": utxo.get('height', 0),
                    "value": utxo['value'],
                    "script_pubkey": utxo['script_pubkey'],
                })
            else:
                bitmap.append(False)

        # Build bitmap string
        bitmap_str = ''.join('1' if b else '0' for b in bitmap)

        # Binary bitmap for serialization
        bitmap_bytes = bytearray((len(bitmap) + 7) // 8)
        for i, b in enumerate(bitmap):
            if b:
                bitmap_bytes[i // 8] |= 1 << (i % 8)

        if rf == RESTResponseFormat.JSON:
            utxos_json = []
            for u in utxos:
                script = u['script_pubkey']
                utxos_json.append({
                    "height": u['height'],
                    "value": u['value'] / 1e8,
                    "scriptPubKey": {
                        "asm": "",  # Would need disassemble
                        "hex": script.hex() if isinstance(script, bytes) else str(script),
                        "type": self._get_script_type(script),
                    }
                })

            return JSONResponse(content={
                "chainHeight": best_height,
                "chaintipHash": best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash),
                "bitmap": bitmap_str,
                "utxos": utxos_json,
            })

        elif rf == RESTResponseFormat.BINARY or rf == RESTResponseFormat.HEX:
            # Serialize in BIP64 format
            import struct
            data = bytearray()
            data.extend(struct.pack('<I', best_height))
            data.extend(best_hash if isinstance(best_hash, bytes) else bytes.fromhex(best_hash))
            data.extend(self._encode_varint(len(bitmap_bytes)))
            data.extend(bitmap_bytes)
            data.extend(self._encode_varint(len(utxos)))

            for u in utxos:
                data.extend(struct.pack('<I', 0))  # nTxVerDummy
                data.extend(struct.pack('<I', u['height']))
                data.extend(struct.pack('<q', u['value']))
                script = u['script_pubkey']
                if isinstance(script, bytes):
                    data.extend(self._encode_varint(len(script)))
                    data.extend(script)
                else:
                    script_bytes = bytes.fromhex(script)
                    data.extend(self._encode_varint(len(script_bytes)))
                    data.extend(script_bytes)

            if rf == RESTResponseFormat.BINARY:
                return Response(content=bytes(data), media_type="application/octet-stream")
            else:
                return PlainTextResponse(content=bytes(data).hex() + "\n", media_type="text/plain")

        raise HTTPException(
            status_code=404,
            detail=f"output format not found (available: {available_formats_string()})"
        )

    def _encode_varint(self, n: int) -> bytes:
        """Encode integer as Bitcoin varint."""
        import struct
        if n < 0xFD:
            return struct.pack('<B', n)
        elif n <= 0xFFFF:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xFFFFFFFF:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)

    async def rest_blockhash_by_height(self, height: str) -> Response:
        """
        Get block hash at given height.

        Path: /rest/blockhashbyheight/<height>.<format>
        """
        param, rf = parse_format(height)
        if rf is None:
            raise HTTPException(
                status_code=404,
                detail=f"output format not found (available: {available_formats_string()})"
            )

        # Parse height
        try:
            block_height = int(param)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid height: {param}") from None

        if block_height < 0:
            raise HTTPException(status_code=400, detail=f"Invalid height: {param}")

        db = self._get_db()
        best_hash, best_height = db.get_best_block()

        if block_height > best_height:
            raise HTTPException(status_code=404, detail="Block height out of range")

        block = db.get_block_by_height(block_height)
        if not block:
            raise HTTPException(status_code=404, detail="Block not found")

        block_hash = block.hash if hasattr(block, 'hash') else block.get_hash()

        if rf == RESTResponseFormat.BINARY:
            # 32 bytes little-endian
            return Response(content=block_hash, media_type="application/octet-stream")

        elif rf == RESTResponseFormat.HEX:
            return PlainTextResponse(
                content=block_hash.hex() + "\n" if isinstance(block_hash, bytes) else str(block_hash) + "\n",
                media_type="text/plain"
            )

        elif rf == RESTResponseFormat.JSON:
            return JSONResponse(content={
                "blockhash": block_hash.hex() if isinstance(block_hash, bytes) else str(block_hash)
            })

        raise HTTPException(
            status_code=404,
            detail=f"output format not found (available: {available_formats_string()})"
        )

    async def rest_chaininfo(self) -> JSONResponse:
        """
        Get blockchain state information.

        Path: /rest/chaininfo.json

        Only JSON format is supported for this endpoint.
        """
        db = self._get_db()
        best_hash, best_height = db.get_best_block()

        network = getattr(self.node, 'network', 'mainnet')
        if hasattr(self.node, 'config'):
            network = self.node.config.get('network', network)

        # Translate internal network name to Core-canonical RPC chain ID.
        # Bitcoin Core returns "main" / "test" in chain info responses (not
        # "mainnet" / "testnet"); ouroboros uses the *-net form internally.
        # Mirrors rpc.py:_rpc_chain_name — keep the two maps in sync.
        _REST_CHAIN_NAME_MAP = {
            "mainnet":  "main",
            "testnet":  "test",
            "testnet3": "test",
            "testnet4": "test",
            # signet and regtest match Core verbatim
        }
        chain_name = _REST_CHAIN_NAME_MAP.get(network, network)

        # Get tip block for bits and time
        tip_block = db.get_block(best_hash) if isinstance(best_hash, bytes) else None
        bits = tip_block.bits if tip_block else 0x1d00ffff
        block_time = tip_block.timestamp if tip_block else 0

        # Calculate target
        mantissa = bits & 0x007FFFFF
        exponent = (bits >> 24) & 0xFF
        if exponent <= 3:
            mantissa >> (8 * (3 - exponent))
        else:
            mantissa << (8 * (exponent - 3))

        return JSONResponse(content={
            "chain": chain_name,
            "blocks": best_height,
            "headers": best_height,
            "bestblockhash": best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash),
            "difficulty": self.node.get_current_difficulty() if hasattr(self.node, 'get_current_difficulty') else 1.0,
            "time": block_time,
            "mediantime": self.node.get_median_time() if hasattr(self.node, 'get_median_time') else block_time,
            "verificationprogress": 1.0,
            "initialblockdownload": False,
            "chainwork": self.node.get_chainwork() if hasattr(self.node, 'get_chainwork') else "0" * 64,
            "size_on_disk": 0,
            "pruned": False,
        })

    async def rest_mempool_info(self) -> JSONResponse:
        """
        Get mempool state information.

        Path: /rest/mempool/info.json

        Only JSON format is supported.
        """
        mempool = self._get_mempool()

        return JSONResponse(content={
            "loaded": True,
            "size": mempool.size(),
            "bytes": mempool.get_total_bytes() if hasattr(mempool, 'get_total_bytes') else 0,
            "usage": mempool.get_memory_usage() if hasattr(mempool, 'get_memory_usage') else 0,
            "total_fee": mempool.get_total_fee() / 1e8 if hasattr(mempool, 'get_total_fee') else 0.0,
            "maxmempool": mempool.max_size if hasattr(mempool, 'max_size') else 300000000,
            "mempoolminfee": mempool.get_min_fee() if hasattr(mempool, 'get_min_fee') else 0.00001,
            "minrelaytxfee": 0.00001,
            "incrementalrelayfee": 0.00001,
            "unbroadcastcount": 0,
            "fullrbf": getattr(mempool, 'full_rbf', False),
        })

    async def rest_mempool_contents(
        self,
        verbose: bool = Query(default=True),
        mempool_sequence: bool = Query(default=False),
    ) -> JSONResponse:
        """
        Get mempool contents.

        Path: /rest/mempool/contents.json?verbose=<true|false>&mempool_sequence=<true|false>

        Only JSON format is supported.
        """
        if verbose and mempool_sequence:
            raise HTTPException(
                status_code=400,
                detail='Verbose results cannot contain mempool sequence values. (hint: set "verbose=false")'
            )

        mempool = self._get_mempool()

        if verbose:
            # Detailed mempool entries
            result = {}
            for tx_hash, entry in mempool.get_all_entries():
                txid = tx_hash.hex() if isinstance(tx_hash, bytes) else str(tx_hash)
                result[txid] = {
                    "vsize": entry.get('vsize', 0),
                    "weight": entry.get('weight', 0),
                    "fee": entry.get('fee', 0) / 1e8,
                    "modifiedfee": entry.get('fee', 0) / 1e8,
                    "time": entry.get('time', 0),
                    "height": entry.get('height', 0),
                    "descendantcount": entry.get('descendant_count', 1),
                    "descendantsize": entry.get('descendant_size', entry.get('vsize', 0)),
                    "descendantfees": entry.get('descendant_fees', entry.get('fee', 0)),
                    "ancestorcount": entry.get('ancestor_count', 1),
                    "ancestorsize": entry.get('ancestor_size', entry.get('vsize', 0)),
                    "ancestorfees": entry.get('ancestor_fees', entry.get('fee', 0)),
                    "wtxid": entry.get('wtxid', txid),
                    "fees": {
                        "base": entry.get('fee', 0) / 1e8,
                        "modified": entry.get('fee', 0) / 1e8,
                        "ancestor": entry.get('ancestor_fees', entry.get('fee', 0)) / 1e8,
                        "descendant": entry.get('descendant_fees', entry.get('fee', 0)) / 1e8,
                    },
                    "depends": entry.get('depends', []),
                    "spentby": entry.get('spentby', []),
                    "bip125-replaceable": entry.get('bip125_replaceable', True),
                    "unbroadcast": entry.get('unbroadcast', False),
                }
            return JSONResponse(content=result)
        else:
            # Just txids
            txids = []
            sequence = 0
            for tx_hash, entry in mempool.get_all_entries():
                txid = tx_hash.hex() if isinstance(tx_hash, bytes) else str(tx_hash)
                txids.append(txid)
                sequence = max(sequence, entry.get('sequence', 0))

            if mempool_sequence:
                return JSONResponse(content={
                    "txids": txids,
                    "mempool_sequence": sequence,
                })
            else:
                return JSONResponse(content=txids)
