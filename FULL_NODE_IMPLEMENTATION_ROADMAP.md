# Full Node Implementation Roadmap

This document provides step-by-step instructions and prompts to complete the remaining Ouroboros Bitcoin full node implementation. Each task includes specific implementation steps, code locations, and testing instructions.

See `FULL_NODE_CHECKLIST.md` for the full status of completed vs remaining work.

---

## Completed Work (no longer tracked here)

The following are fully implemented and working:

- **Difficulty calculation** — `node.py:_bits_to_difficulty()`
- **Chainwork calculation** — `node.py:_calculate_chainwork_at_height()` + Rust `compute_chainwork()`
- **Median time** — `node.py:get_median_time()` (last 11 blocks)
- **Transaction deserialization** — `p2p_messages.py:TxMessage.from_payload()` (SegWit + legacy)
- **Block serialization/deserialization** — `database.py:Block.serialize()`, `Block.deserialize()`
- **ECDSA signature verification** — `script.py:ScriptInterpreter` (OP_CHECKSIG, OP_CHECKMULTISIG)
- **Reorg handling** — `block_sync.py:_handle_reorg()`
- **Orphan block management** — `block_sync.py` (max 100 orphans, recursive processing)
- **Configuration file** — `config.py:NodeConfig`, `share/ouroboros.conf.example`
- **Script disassembly** — `script.py:disassemble_script()`
- **UTXO querying** — `database.py:get_balance()`, `list_unspent_by_address()`
- **vsize/weight** — `database.py:Transaction.get_weight()`, `get_vsize()`
- **Next block hash** — `rpc.py:_get_next_block_hash()`
- **`assumevalid`** — `ferrous-utils/sync/src/validate/block.rs:BlockValidator`
- **13 RPC methods** — getblockchaininfo, getblockcount, getbestblockhash, getblockhash, getblock, getblockheader, getrawtransaction, sendrawtransaction, getrawmempool, gettxout, listunspent, getpeerinfo, getmempoolinfo

---

## Phase 1: Fee Estimation (1-2 weeks)

### Task 1.1: Implement Fee Rate Tracker

**Priority:** Medium  
**Estimated Time:** 3-4 days  
**Files to Modify:** `src/ouroboros/fee_estimator.py` (new), `src/ouroboros/node.py`, `src/ouroboros/block_sync.py`

The node currently has no fee estimation. Bitcoin Core tracks how many blocks it takes for transactions at various fee rates to confirm, then uses that history to predict required fee rates. A simpler approach (suitable for an initial implementation) is to track recent block fee rate percentiles.

#### Step 1: Create fee estimator module

**File:** `src/ouroboros/fee_estimator.py` (new)

```python
"""
Fee estimation based on recent block fee rate statistics.

Tracks fee rates from the most recent N confirmed blocks and returns
percentile-based estimates for target confirmation windows.

Reference: Bitcoin Core's CBlockPolicyEstimator (policy/fees.cpp)
uses exponential decay buckets. This is a simpler percentile approach
that is sufficient for basic fee estimation.
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# How many recent blocks to keep for fee statistics
MAX_BLOCK_HISTORY = 144  # ~1 day of blocks


@dataclass
class BlockFeeData:
    """Fee rate statistics for a single confirmed block."""
    height: int
    fee_rates: List[float]  # sat/vB for each transaction in the block
    median_fee_rate: float
    min_fee_rate: float


class FeeEstimator:
    """
    Estimates fee rates required for confirmation within a target number
    of blocks, based on observed fee rates in recent confirmed blocks.
    """

    def __init__(self, max_history: int = MAX_BLOCK_HISTORY):
        self.max_history = max_history
        # Ring buffer of recent block fee data, newest last
        self.block_history: deque[BlockFeeData] = deque(maxlen=max_history)

    def process_block(self, block, height: int) -> None:
        """
        Record fee rate data from a newly confirmed block.

        Called by block_sync after a block is connected. For each
        non-coinbase transaction, calculate fee_rate = fee / vsize.

        Args:
            block: Block object with .transactions list
            height: Block height
        """
        fee_rates = []

        for tx in block.transactions:
            if tx.is_coinbase:
                continue

            # fee = sum(input_values) - sum(output_values)
            # If fee data is available from UTXO lookups during validation,
            # pass it here. Otherwise estimate from mempool or skip.
            # For now, use the fee stored in MempoolEntry if the tx was
            # in our mempool, or skip if unknown.
            fee = getattr(tx, '_confirmed_fee', None)
            if fee is None:
                continue

            vsize = tx.get_vsize()
            if vsize > 0:
                fee_rates.append(fee / vsize)

        if not fee_rates:
            return

        fee_rates.sort()
        median = fee_rates[len(fee_rates) // 2]
        self.block_history.append(BlockFeeData(
            height=height,
            fee_rates=fee_rates,
            median_fee_rate=median,
            min_fee_rate=fee_rates[0],
        ))

    def estimate_fee(self, conf_target: int = 6) -> Optional[float]:
        """
        Estimate fee rate (sat/vB) for confirmation within conf_target blocks.

        Strategy:
        - conf_target 1-2:  use 90th percentile of recent blocks
        - conf_target 3-6:  use 50th percentile (median)
        - conf_target 7-25: use 25th percentile
        - conf_target 25+:  use 10th percentile (economy)

        Returns None if insufficient data.
        """
        if len(self.block_history) < 3:
            return None

        # How many recent blocks to sample depends on conf_target
        sample_depth = min(len(self.block_history), max(conf_target * 2, 6))

        all_rates = []
        for block_data in list(self.block_history)[-sample_depth:]:
            all_rates.extend(block_data.fee_rates)

        if not all_rates:
            return None

        all_rates.sort()

        if conf_target <= 2:
            percentile = 0.90
        elif conf_target <= 6:
            percentile = 0.50
        elif conf_target <= 25:
            percentile = 0.25
        else:
            percentile = 0.10

        idx = int(len(all_rates) * percentile)
        idx = min(idx, len(all_rates) - 1)
        rate = all_rates[idx]

        # Floor at 1 sat/vB (minimum relay fee)
        return max(rate, 1.0)

    def estimate_fee_per_kb(self, conf_target: int = 6) -> Optional[float]:
        """Return fee estimate in BTC/kB (Bitcoin Core RPC format)."""
        rate = self.estimate_fee(conf_target)
        if rate is None:
            return None
        # sat/vB -> BTC/kB: rate * 1000 / 1e8
        return rate * 1000 / 1e8

    def get_fee_summary(self) -> Dict:
        """Return summary statistics for debugging / getmempoolinfo."""
        if not self.block_history:
            return {"blocks_tracked": 0}

        medians = [b.median_fee_rate for b in self.block_history]
        return {
            "blocks_tracked": len(self.block_history),
            "oldest_height": self.block_history[0].height,
            "newest_height": self.block_history[-1].height,
            "median_fee_rate": sorted(medians)[len(medians) // 2],
            "min_fee_rate": min(b.min_fee_rate for b in self.block_history),
        }
```

#### Step 2: Integrate fee estimator into the node

**File:** `src/ouroboros/node.py`

Add to `BitcoinNode.__init__()`:
```python
from ouroboros.fee_estimator import FeeEstimator
self.fee_estimator = FeeEstimator()
```

**File:** `src/ouroboros/block_sync.py`

After a block is connected (in `handle_block()` or the block processing callback), call:
```python
self.node.fee_estimator.process_block(block, height)
```

Before removing confirmed transactions from the mempool, tag them with their fee so the estimator can use it:
```python
for tx in block.transactions:
    if not tx.is_coinbase:
        entry = self.node.mempool.get_transaction_entry(tx.get_txid())
        if entry:
            tx._confirmed_fee = entry.fee
```

#### Step 3: Add `estimatesmartfee` RPC method

**File:** `src/ouroboros/rpc.py`

```python
async def rpc_estimatesmartfee(self, conf_target: int = 6, estimate_mode: str = "economical") -> Dict[str, Any]:
    """
    Estimate fee rate for confirmation within conf_target blocks.
    
    Returns dict matching Bitcoin Core format:
    {
        "feerate": <BTC/kB>,
        "errors": [...],
        "blocks": <conf_target>
    }
    """
    if conf_target < 1:
        conf_target = 1
    if conf_target > 1008:
        conf_target = 1008

    fee_rate = self.node.fee_estimator.estimate_fee_per_kb(conf_target)

    if fee_rate is None:
        return {
            "errors": ["Insufficient data for reliable estimate"],
            "blocks": conf_target,
        }

    return {
        "feerate": fee_rate,
        "blocks": conf_target,
    }
```

#### Testing

```bash
# After syncing some blocks:
curl -s -X POST http://localhost:48332/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"estimatesmartfee","params":[6],"id":1}'

# Expected: {"feerate": 0.00001, "blocks": 6} or similar
# Or: {"errors": ["Insufficient data..."], "blocks": 6} if just started
```

---

### Task 1.2: Add `validateaddress` RPC Method

**Priority:** Low  
**Estimated Time:** 1-2 hours  
**Files to Modify:** `src/ouroboros/rpc.py`

```python
async def rpc_validateaddress(self, address: str) -> Dict[str, Any]:
    """
    Validate a Bitcoin address and return information about it.
    
    Reference: Bitcoin Core validateaddress (rpc/misc.cpp)
    """
    from ouroboros.address import address_to_script_pubkey

    result = {
        "isvalid": False,
        "address": address,
    }

    try:
        script_pubkey = address_to_script_pubkey(address, network=self.node.network)
        result["isvalid"] = True
        result["scriptPubKey"] = script_pubkey.hex()

        # Determine address type from script_pubkey
        if len(script_pubkey) == 25 and script_pubkey[0] == 0x76:
            result["isscript"] = False
            result["iswitness"] = False
        elif len(script_pubkey) == 23 and script_pubkey[0] == 0xa9:
            result["isscript"] = True
            result["iswitness"] = False
        elif script_pubkey[0] == 0x00 and len(script_pubkey) == 22:
            result["isscript"] = False
            result["iswitness"] = True
            result["witness_version"] = 0
            result["witness_program"] = script_pubkey[2:].hex()
        elif script_pubkey[0] == 0x00 and len(script_pubkey) == 34:
            result["isscript"] = True
            result["iswitness"] = True
            result["witness_version"] = 0
            result["witness_program"] = script_pubkey[2:].hex()
        elif script_pubkey[0] == 0x51 and len(script_pubkey) == 34:
            result["isscript"] = False
            result["iswitness"] = True
            result["witness_version"] = 1
            result["witness_program"] = script_pubkey[2:].hex()
    except Exception:
        pass

    return result
```

---

## Phase 2: Wallet Implementation (3-4 weeks)

### Task 2.1: Key Management

**Priority:** Medium  
**Estimated Time:** 1 week  
**Files to Modify:** `src/ouroboros/wallet.py`  
**Dependencies:** `pip install coincurve` (already a dependency for ECDSA)

The current `Wallet` class in `wallet.py` has async stub methods and pydantic models `AddressInfo` and `TransactionInfo`. All methods need real implementations.

#### Step 1: Add key generation and storage

Replace the entire `Wallet` class. The constructor currently takes `name: str | None = None` and the class uses pydantic models `AddressInfo(address, balance, label)` and `TransactionInfo(txid, amount, confirmations, timestamp)`.

```python
import os
import json
import hashlib
import hmac
from pathlib import Path
from typing import Optional, List, Dict, Tuple

# coincurve is already installed for ECDSA verification
from coincurve import PrivateKey, PublicKey

from ouroboros.address import script_pubkey_to_address  # needs to be added


class WalletKey:
    """A single private/public key pair with derived address."""

    def __init__(self, private_key_bytes: bytes, network: str = "mainnet"):
        self.private_key = PrivateKey(private_key_bytes)
        self.public_key = self.private_key.public_key
        self.network = network
        # Compressed public key (33 bytes)
        self.pubkey_bytes = self.public_key.format(compressed=True)

    @classmethod
    def generate(cls, network: str = "mainnet") -> 'WalletKey':
        """Generate a new random private key."""
        return cls(os.urandom(32), network)

    def get_p2wpkh_address(self) -> str:
        """Derive native SegWit (bech32) P2WPKH address."""
        # witness program = HASH160(compressed_pubkey)
        sha256 = hashlib.sha256(self.pubkey_bytes).digest()
        hash160 = hashlib.new('ripemd160', sha256).digest()

        import bech32
        hrp = "bc" if self.network == "mainnet" else "tb"
        witness_version = 0
        converted = bech32.convertbits(hash160, 8, 5)
        return bech32.bech32_encode(hrp, [witness_version] + converted)

    def get_p2pkh_address(self) -> str:
        """Derive legacy P2PKH address."""
        sha256 = hashlib.sha256(self.pubkey_bytes).digest()
        hash160 = hashlib.new('ripemd160', sha256).digest()

        version = b'\x00' if self.network == "mainnet" else b'\x6f'
        payload = version + hash160
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        import base58
        return base58.b58encode(payload + checksum).decode()

    def to_wif(self) -> str:
        """Export private key as WIF (Wallet Import Format)."""
        version = b'\x80' if self.network == "mainnet" else b'\xef'
        # Compressed key flag
        payload = version + self.private_key.secret + b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        import base58
        return base58.b58encode(payload + checksum).decode()

    @classmethod
    def from_wif(cls, wif: str, network: str = "mainnet") -> 'WalletKey':
        """Import private key from WIF."""
        import base58
        decoded = base58.b58decode(wif)
        # Remove version byte and checksum (last 4 bytes)
        # If compressed (ends with 0x01 before checksum), strip that too
        key_bytes = decoded[1:-4]
        if len(key_bytes) == 33 and key_bytes[-1] == 0x01:
            key_bytes = key_bytes[:-1]
        return cls(key_bytes, network)
```

#### Step 2: Implement wallet storage

The wallet file should be stored as encrypted JSON at `{data_dir}/wallet.dat` or `{data_dir}/wallets/{name}.json`.

```python
class Wallet:
    """
    Bitcoin wallet with key management, address derivation, and transaction signing.

    Wallet file format (JSON, optionally encrypted):
    {
        "version": 1,
        "network": "mainnet",
        "keys": [
            {"privkey_wif": "...", "label": "...", "created": 1234567890}
        ]
    }
    """

    def __init__(self, data_dir: str, network: str = "mainnet", name: str = "default"):
        self.data_dir = Path(data_dir)
        self.network = network
        self.name = name
        self.wallet_path = self.data_dir / "wallets" / f"{name}.json"
        self.keys: List[Dict] = []
        self._load_or_create()

    def _load_or_create(self) -> None:
        """Load existing wallet or create a new one."""
        if self.wallet_path.exists():
            with open(self.wallet_path, 'r') as f:
                data = json.load(f)
            self.keys = data.get("keys", [])
        else:
            self.wallet_path.parent.mkdir(parents=True, exist_ok=True)
            self._save()

    def _save(self) -> None:
        """Persist wallet to disk."""
        data = {
            "version": 1,
            "network": self.network,
            "keys": self.keys,
        }
        with open(self.wallet_path, 'w') as f:
            json.dump(data, f, indent=2)

    async def generate_new_address(self, label: str | None = None) -> str:
        """Generate a new P2WPKH address and persist the key."""
        import time
        key = WalletKey.generate(self.network)
        self.keys.append({
            "privkey_wif": key.to_wif(),
            "label": label or "",
            "created": int(time.time()),
        })
        self._save()
        return key.get_p2wpkh_address()

    async def get_balance(self, address: str | None = None) -> int:
        """
        Get wallet balance in satoshis.
        Requires a database reference (set via set_database).
        """
        total = 0
        if address:
            total = self.db.get_balance(address, self.network) if self.db else 0
        else:
            for addr in await self.get_addresses():
                total += self.db.get_balance(addr.address, self.network) if self.db else 0
        return total

    async def get_addresses(self) -> list:
        """Return all wallet addresses with balances."""
        result = []
        for key_data in self.keys:
            key = WalletKey.from_wif(key_data["privkey_wif"], self.network)
            addr = key.get_p2wpkh_address()
            balance = self.db.get_balance(addr, self.network) if self.db else 0
            result.append(AddressInfo(
                address=addr,
                balance=balance,
                label=key_data.get("label"),
            ))
        return result

    def set_database(self, db) -> None:
        """Set database reference for UTXO lookups."""
        self.db = db
```

#### Step 3: Integrate wallet into the node

**File:** `src/ouroboros/node.py`

In `BitcoinNode.__init__()`:
```python
from ouroboros.wallet import Wallet
self.wallet = Wallet(self.data_dir, self.network)
self.wallet.set_database(self.db)
```

#### Testing

```python
# Test key generation
from ouroboros.wallet import WalletKey
key = WalletKey.generate("testnet4")
print(f"Address: {key.get_p2wpkh_address()}")
print(f"WIF: {key.to_wif()}")

# Round-trip
key2 = WalletKey.from_wif(key.to_wif(), "testnet4")
assert key2.get_p2wpkh_address() == key.get_p2wpkh_address()
```

---

### Task 2.2: Transaction Signing and Coin Selection

**Priority:** Medium  
**Estimated Time:** 1 week  
**Files to Modify:** `src/ouroboros/wallet.py`

#### Step 1: Implement coin selection

```python
def _select_coins(
    self, amount: int, fee_rate: float, db
) -> Tuple[List[Dict], int]:
    """
    Select UTXOs to fund a transaction.

    Uses a simple largest-first strategy. A production implementation
    would use branch-and-bound (BIP 325) or knapsack.

    Args:
        amount: Target amount in satoshis (excluding fee)
        fee_rate: Fee rate in sat/vB
        db: Database instance for UTXO lookups

    Returns:
        (selected_utxos, estimated_fee) tuple

    Raises:
        ValueError: Insufficient funds
    """
    all_utxos = []
    for key_data in self.keys:
        key = WalletKey.from_wif(key_data["privkey_wif"], self.network)
        addr = key.get_p2wpkh_address()
        utxos = db.list_unspent_by_address(addr, self.network)
        for utxo in utxos:
            utxo["_key"] = key
        all_utxos.extend(utxos)

    # Sort by value descending (largest first)
    all_utxos.sort(key=lambda u: u["value"], reverse=True)

    selected = []
    total_in = 0

    for utxo in all_utxos:
        selected.append(utxo)
        total_in += utxo["value"]

        # Estimate tx size: ~10 (overhead) + 68 per input + 31 per output * 2
        est_vsize = 10 + len(selected) * 68 + 2 * 31
        est_fee = int(est_vsize * fee_rate)

        if total_in >= amount + est_fee:
            return selected, est_fee

    raise ValueError(
        f"Insufficient funds: have {total_in}, need {amount} + fee"
    )
```

#### Step 2: Implement transaction building and signing

```python
async def send_transaction(
    self,
    to_address: str,
    amount: int,
    fee_rate: int | None = None,
) -> str:
    """
    Build, sign, and broadcast a transaction.

    Args:
        to_address: Destination address
        amount: Amount in satoshis
        fee_rate: Fee rate in sat/vB (default: estimate or 2)

    Returns:
        Transaction ID (hex)
    """
    if fee_rate is None:
        fee_rate = 2  # fallback: 2 sat/vB

    selected, est_fee = self._select_coins(amount, fee_rate, self.db)
    total_in = sum(u["value"] for u in selected)
    change = total_in - amount - est_fee

    from ouroboros.address import address_to_script_pubkey
    from ouroboros.database import Transaction, TxIn, TxOut
    import struct, hashlib

    # Build outputs
    outputs = [TxOut(
        value=amount,
        script_pubkey=address_to_script_pubkey(to_address, self.network),
    )]

    if change > 546:  # dust threshold
        # Change goes to first wallet address
        change_key = WalletKey.from_wif(self.keys[0]["privkey_wif"], self.network)
        change_spk = address_to_script_pubkey(
            change_key.get_p2wpkh_address(), self.network
        )
        outputs.append(TxOut(value=change, script_pubkey=change_spk))

    # Build inputs (unsigned)
    inputs = []
    for utxo in selected:
        inputs.append(TxIn(
            prev_txid=bytes.fromhex(utxo["txid"]),
            prev_vout=utxo["vout"],
            script_sig=b'',
            sequence=0xFFFFFFFD,
        ))

    tx = Transaction(
        txid=b'\x00' * 32,  # placeholder, computed after signing
        version=2,
        locktime=0,
        inputs=inputs,
        outputs=outputs,
        has_witness=True,
    )

    # Sign each input (BIP 143 / SegWit P2WPKH)
    for i, utxo in enumerate(selected):
        key = utxo["_key"]
        value = utxo["value"]

        # Compute BIP143 sighash
        sighash = self._bip143_sighash(tx, i, key.pubkey_bytes, value)

        # Sign
        sig = key.private_key.sign(sighash, hasher=None)
        # Append SIGHASH_ALL
        sig_with_hashtype = sig + b'\x01'

        # P2WPKH witness: [sig, pubkey]
        tx.inputs[i].witness = [sig_with_hashtype, key.pubkey_bytes]

    # Compute txid
    tx.txid = tx.get_txid()

    # Broadcast via mempool + P2P
    raw_hex = tx.serialize_with_witness().hex()
    # Use the node's sendrawtransaction pathway
    return raw_hex

def _bip143_sighash(
    self, tx, input_index: int, pubkey: bytes, value: int
) -> bytes:
    """
    Compute BIP 143 signature hash for P2WPKH.

    Reference: BIP 143 (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
    """
    import hashlib, struct

    def dsha256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    # hashPrevouts
    prevouts = b''
    for inp in tx.inputs:
        prevouts += inp.prev_txid[::-1] + struct.pack('<I', inp.prev_vout)
    hash_prevouts = dsha256(prevouts)

    # hashSequence
    sequences = b''
    for inp in tx.inputs:
        sequences += struct.pack('<I', inp.sequence)
    hash_sequence = dsha256(sequences)

    # hashOutputs
    outputs = b''
    for out in tx.outputs:
        outputs += struct.pack('<q', out.value)
        outputs += len(out.script_pubkey).to_bytes(1, 'little')
        outputs += out.script_pubkey
    hash_outputs = dsha256(outputs)

    # scriptCode for P2WPKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    sha256 = hashlib.sha256(pubkey).digest()
    pubkey_hash = hashlib.new('ripemd160', sha256).digest()
    script_code = b'\x19\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

    inp = tx.inputs[input_index]

    preimage = struct.pack('<i', tx.version)
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += inp.prev_txid[::-1] + struct.pack('<I', inp.prev_vout)
    preimage += script_code
    preimage += struct.pack('<q', value)
    preimage += struct.pack('<I', inp.sequence)
    preimage += hash_outputs
    preimage += struct.pack('<I', tx.locktime)
    preimage += struct.pack('<I', 1)  # SIGHASH_ALL

    return dsha256(preimage)
```

#### Testing

```bash
# Unit test: build and sign a transaction (regtest / testnet4)
python3 -c "
from ouroboros.wallet import Wallet
w = Wallet('/tmp/test_wallet', 'testnet4')
import asyncio
addr = asyncio.run(w.generate_new_address('test'))
print(f'Generated address: {addr}')
"
```

---

### Task 2.3: Wallet RPC Methods

**Priority:** Medium  
**Estimated Time:** 2-3 days  
**Files to Modify:** `src/ouroboros/rpc.py`

#### Step 1: Add `getnewaddress`

```python
async def rpc_getnewaddress(self, label: str = "", address_type: str = "bech32") -> str:
    """
    Generate a new address.
    
    Reference: Bitcoin Core getnewaddress (wallet/rpc/addresses.cpp)
    """
    if not hasattr(self.node, 'wallet') or self.node.wallet is None:
        raise ValueError("Wallet not loaded")
    return await self.node.wallet.generate_new_address(label)
```

#### Step 2: Add `sendtoaddress`

```python
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
    Send bitcoin to an address.
    
    Args:
        address: Destination address
        amount: Amount in BTC
    
    Returns:
        Transaction ID (hex)
        
    Reference: Bitcoin Core sendtoaddress (wallet/rpc/spend.cpp)
    """
    if not hasattr(self.node, 'wallet') or self.node.wallet is None:
        raise ValueError("Wallet not loaded")

    amount_sat = int(amount * 1e8)
    if amount_sat <= 0:
        raise ValueError("Invalid amount")

    # Get fee rate estimate
    fee_rate = None
    if hasattr(self.node, 'fee_estimator'):
        fee_rate = self.node.fee_estimator.estimate_fee(conf_target)
    if fee_rate is None:
        fee_rate = 2  # fallback: 2 sat/vB

    raw_hex = await self.node.wallet.send_transaction(address, amount_sat, int(fee_rate))

    # Broadcast via existing sendrawtransaction path
    txid = await self.rpc_sendrawtransaction(raw_hex)
    return txid
```

#### Step 3: Add `getwalletinfo`

```python
async def rpc_getwalletinfo(self) -> Dict[str, Any]:
    """
    Return wallet state info.
    
    Reference: Bitcoin Core getwalletinfo (wallet/rpc/wallet.cpp)
    """
    if not hasattr(self.node, 'wallet') or self.node.wallet is None:
        raise ValueError("Wallet not loaded")

    balance = await self.node.wallet.get_balance()
    addresses = await self.node.wallet.get_addresses()

    return {
        "walletname": self.node.wallet.name,
        "walletversion": 1,
        "balance": balance / 1e8,
        "txcount": 0,  # TODO: track transaction count
        "keypoolsize": len(addresses),
    }
```

---

## Phase 3: Missing RPC Methods (1 week) — ✅ COMPLETED

### Task 3.1: Merkle Proof RPCs — ✅ DONE

**Priority:** Low  
**Estimated Time:** 1-2 days  
**Files Modified:** `src/ouroboros/rpc.py`

#### `gettxoutproof`

```python
async def rpc_gettxoutproof(
    self, txids: List[str], blockhash: Optional[str] = None
) -> str:
    """
    Return a hex-encoded Merkle proof that one or more transactions
    were included in a block.

    Format: block_header (80 bytes) + merkle_proof
    
    Reference: Bitcoin Core gettxoutproof (rpc/rawtransaction.cpp)
    Uses CMerkleBlock which serializes as:
      - CBlockHeader (80 bytes)
      - CPartialMerkleTree:
        - total_transactions (uint32)
        - vHash count (varint) + hashes (32 bytes each)
        - vBits count (varint) + flag bits

    Implementation:
    1. Find the block containing the transaction(s)
    2. Build a partial Merkle tree containing only the target txids
    3. Serialize as hex
    """
    if not txids:
        raise ValueError("txids must not be empty")

    target_txids = set()
    for txid_hex in txids:
        target_txids.add(bytes.fromhex(txid_hex))

    # Find block
    if blockhash:
        block = self.node.db.get_block(bytes.fromhex(blockhash))
    else:
        # Search recent blocks for the transaction
        block = None
        for txid_bytes in target_txids:
            tx_info = self.node.db.get_transaction(txid_bytes)
            if tx_info and tx_info.get("blockhash"):
                block = self.node.db.get_block(tx_info["blockhash"])
                break
        if block is None:
            raise ValueError("Transaction not found in any block")

    # Build partial Merkle tree
    all_txids = [tx.get_txid() for tx in block.transactions]
    matches = [txid in target_txids for txid in all_txids]

    proof = _build_merkle_proof(block, all_txids, matches)
    return proof.hex()


def _build_merkle_proof(block, txids: list, matches: list) -> bytes:
    """
    Build a serialized partial Merkle tree (CMerkleBlock format).

    See Bitcoin Core: merkleblock.cpp CPartialMerkleTree
    """
    import struct, hashlib, math

    def dsha256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    n = len(txids)
    # Tree height
    height = 0
    while (1 << height) < n:
        height += 1

    hashes = []
    bits = []

    def traverse(h, pos):
        parent_match = False
        # Check if any leaf under this node matches
        start = pos << h
        end = min((pos + 1) << h, n)
        for i in range(start, end):
            if matches[i]:
                parent_match = True
                break

        bits.append(parent_match)

        if h == 0 or not parent_match:
            # Leaf or no match below — emit hash
            if h == 0:
                hashes.append(txids[pos] if pos < n else b'\x00' * 32)
            else:
                # Compute subtree hash
                left = _calc_hash(txids, n, h - 1, pos * 2)
                right = _calc_hash(txids, n, h - 1, pos * 2 + 1)
                hashes.append(dsha256(left + right))
        else:
            traverse(h - 1, pos * 2)
            if pos * 2 + 1 < _calc_tree_width(n, h - 1):
                traverse(h - 1, pos * 2 + 1)

    traverse(height, 0)

    # Serialize
    result = block.serialize()[:80]  # block header
    result += struct.pack('<I', n)
    # hashes
    result += _encode_varint(len(hashes))
    for h in hashes:
        result += h
    # bits as bytes
    bit_bytes = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            bit_bytes[i // 8] |= 1 << (i % 8)
    result += _encode_varint(len(bit_bytes))
    result += bytes(bit_bytes)

    return result
```

**Note:** The Merkle proof functions (`_calc_hash`, `_calc_tree_width`, `_encode_varint`) need helper implementations matching Bitcoin Core's `CPartialMerkleTree`. This is the most complex RPC to implement correctly. Reference Bitcoin Core `src/merkleblock.cpp`.

#### `verifytxoutproof`

```python
async def rpc_verifytxoutproof(self, proof: str) -> List[str]:
    """
    Verify a Merkle proof and return the txids it proves.
    
    Reference: Bitcoin Core verifytxoutproof (rpc/rawtransaction.cpp)

    Implementation:
    1. Deserialize the proof (block header + partial Merkle tree)
    2. Verify the Merkle root matches the block header
    3. Look up the block by header hash to confirm it's in our chain
    4. Return the list of proven txids
    """
    proof_bytes = bytes.fromhex(proof)

    # Parse block header (first 80 bytes)
    header_bytes = proof_bytes[:80]
    import hashlib
    block_hash = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()

    # Verify block is in our chain
    block = self.node.db.get_block(block_hash)
    if block is None:
        raise ValueError("Block not found in chain")

    # Parse partial Merkle tree and extract matched txids
    matched_txids = _parse_merkle_proof(proof_bytes[80:])

    return [txid.hex() for txid in matched_txids]
```

---

### Task 3.2: Mining-Related RPCs — ✅ DONE

**Priority:** Low  
**Estimated Time:** 2-3 hours  
**Files Modified:** `src/ouroboros/rpc.py`

```python
async def rpc_getmininginfo(self) -> Dict[str, Any]:
    """
    Return mining-related information.
    
    Reference: Bitcoin Core getmininginfo (rpc/mining.cpp)
    """
    _, height = self.node.db.get_best_block()

    return {
        "blocks": height,
        "difficulty": self.node.get_current_difficulty(),
        "networkhashps": 0,  # TODO: estimate from recent blocks
        "pooledtx": len(self.node.mempool.get_all_transactions()) if self.node.mempool else 0,
        "chain": self.node.network,
        "warnings": "",
    }


async def rpc_submitblock(self, hexdata: str) -> Optional[str]:
    """
    Submit a mined block to the network.
    
    Reference: Bitcoin Core submitblock (rpc/mining.cpp)

    Implementation:
    1. Deserialize the block from hex
    2. Validate the block
    3. If valid, add to chain and relay to peers
    4. Return None on success, error string on failure
    """
    from ouroboros.database import Block

    try:
        block_bytes = bytes.fromhex(hexdata)
        block = Block.deserialize(block_bytes)

        # Process through normal block handling
        await self.node.block_sync.handle_block(block)
        return None

    except Exception as e:
        return str(e)
```

---

## Phase 4: Testing Infrastructure (1-2 weeks) — ✅ COMPLETED

### Task 4.1: Python Integration Tests — ✅ DONE

**Priority:** Medium  
**Estimated Time:** 3-4 days  
**Files Created:** `tests/test_integration.py`, `tests/conftest.py`

#### Step 1: Create test fixtures

**File:** `tests/conftest.py`

```python
"""Shared test fixtures for integration tests."""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path

from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool
from ouroboros.node import BitcoinNode


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory for tests."""
    d = tempfile.mkdtemp(prefix="ouroboros_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def test_db(temp_data_dir):
    """Create a test database."""
    db = BlockchainDatabase(temp_data_dir)
    yield db


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
```

#### Step 2: Write integration tests

**File:** `tests/test_integration.py`

```python
"""Integration tests for the Ouroboros full node."""

import pytest
import asyncio
from ouroboros.wallet import Wallet, WalletKey
from ouroboros.fee_estimator import FeeEstimator
from ouroboros.address import address_to_script_pubkey


class TestWallet:
    """Test wallet key generation and address derivation."""

    def test_key_generation(self):
        key = WalletKey.generate("testnet4")
        addr = key.get_p2wpkh_address()
        assert addr.startswith("tb1q")
        assert len(addr) == 42  # bech32 P2WPKH

    def test_wif_roundtrip(self):
        key = WalletKey.generate("mainnet")
        wif = key.to_wif()
        key2 = WalletKey.from_wif(wif, "mainnet")
        assert key.get_p2wpkh_address() == key2.get_p2wpkh_address()

    def test_p2pkh_address(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2pkh_address()
        assert addr.startswith("1")

    @pytest.mark.asyncio
    async def test_wallet_generate_address(self, temp_data_dir):
        w = Wallet(temp_data_dir, "testnet4")
        addr = await w.generate_new_address("test")
        assert addr.startswith("tb1q")
        # Should persist
        w2 = Wallet(temp_data_dir, "testnet4")
        addrs = await w2.get_addresses()
        assert len(addrs) == 1


class TestFeeEstimator:
    """Test fee estimation."""

    def test_insufficient_data(self):
        fe = FeeEstimator()
        assert fe.estimate_fee(6) is None

    def test_estimate_with_data(self):
        from ouroboros.fee_estimator import BlockFeeData
        fe = FeeEstimator()
        # Add some synthetic block data
        for i in range(10):
            fe.block_history.append(BlockFeeData(
                height=i,
                fee_rates=[1.0, 2.0, 5.0, 10.0, 20.0],
                median_fee_rate=5.0,
                min_fee_rate=1.0,
            ))
        rate = fe.estimate_fee(6)
        assert rate is not None
        assert rate >= 1.0


class TestAddressValidation:
    """Test address encoding/decoding."""

    def test_p2wpkh_script(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2wpkh_address()
        spk = address_to_script_pubkey(addr, "mainnet")
        assert len(spk) == 22
        assert spk[0] == 0x00  # witness v0
        assert spk[1] == 0x14  # 20 bytes

    def test_p2pkh_script(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2pkh_address()
        spk = address_to_script_pubkey(addr, "mainnet")
        assert len(spk) == 25
        assert spk[0] == 0x76  # OP_DUP
```

#### Step 3: Run tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest tests/ -v

# Run specific test class
pytest tests/test_integration.py::TestWallet -v
```

---

### Task 4.2: CI/CD Pipeline — ✅ DONE

**Priority:** Medium  
**Estimated Time:** 1 day  
**Files Created:** `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build Rust library
        run: cargo check --manifest-path ferrous-utils/sync/Cargo.toml --lib
      - name: Run Rust tests
        run: cargo test --manifest-path ferrous-utils/sync/Cargo.toml --lib

  test-python:
    runs-on: ubuntu-latest
    needs: test-rust
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - uses: dtolnay/rust-toolchain@stable
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
          pip install maturin
          maturin develop --manifest-path ferrous-utils/sync/Cargo.toml
      - name: Run Python tests
        run: pytest tests/ -v

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Lint
        run: |
          pip install ruff
          ruff check src/ouroboros/
```

---

## Phase 5: Taproot / Schnorr Support (2-3 weeks) — ✅ COMPLETED

### Task 5.1: Schnorr Signature Verification (BIP 340) — ✅ DONE

**Priority:** Low  
**Estimated Time:** 1 week  
**Files Modified:** `src/ouroboros/script.py`

Schnorr signatures use a different algorithm than ECDSA but still operate on the secp256k1 curve. The `coincurve` library has some Schnorr support, or the Rust `secp256k1` crate can be used via PyO3.

#### Step 1: Add Schnorr verification to script interpreter

```python
def _verify_schnorr_signature(
    self, message_hash: bytes, signature: bytes, pubkey_x: bytes
) -> bool:
    """
    Verify a BIP 340 Schnorr signature.

    Args:
        message_hash: 32-byte sighash
        signature: 64-byte Schnorr signature
        pubkey_x: 32-byte x-only public key

    Reference: BIP 340 (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
    """
    if len(signature) != 64 or len(pubkey_x) != 32:
        return False

    try:
        # Option A: Use Rust extension if available
        import sync
        return sync.verify_schnorr(message_hash, signature, pubkey_x)
    except (ImportError, AttributeError):
        pass

    try:
        # Option B: Use coincurve (if version supports Schnorr)
        from coincurve import PublicKeyXOnly
        pk = PublicKeyXOnly(pubkey_x)
        return pk.verify(signature, message_hash)
    except Exception:
        return False
```

#### Step 2: Add OP_CHECKSIGADD support

BIP 342 replaces OP_CHECKMULTISIG with OP_CHECKSIGADD in tapscript:

```python
# In _execute_script(), add handling for opcode 0xba (OP_CHECKSIGADD):
elif opcode == 0xba:  # OP_CHECKSIGADD (BIP 342)
    if len(stack) < 3:
        return False
    pubkey = stack.pop()
    n = _decode_script_num(stack.pop())
    sig = stack.pop()

    if sig:  # non-empty signature
        # Verify Schnorr signature
        if self._verify_schnorr_signature(sighash, sig, pubkey):
            stack.append(_encode_script_num(n + 1))
        else:
            return False  # invalid sig is script failure in tapscript
    else:
        stack.append(_encode_script_num(n))
```

### Task 5.2: Taproot Output Validation (BIP 341) — ✅ DONE

**Priority:** Low  
**Estimated Time:** 1 week  
**Files Modified:** `src/ouroboros/script.py`, `src/ouroboros/address.py`

Taproot outputs use witness version 1 with a 32-byte program (the tweaked public key).

#### Step 1: Add P2TR address support

**File:** `src/ouroboros/address.py`

In `address_to_script_pubkey()`, bech32m addresses with witness version 1 already fall through to the existing SegWit handling. Verify that bech32m decoding works (it should, since the `bech32` library handles both bech32 and bech32m).

#### Step 2: Taproot key-path spending

```python
def _verify_taproot_keypath(
    self, tx, input_index: int, witness: list, output_pubkey: bytes
) -> bool:
    """
    Verify a taproot key-path spend.

    The witness is [signature] (64 or 65 bytes).
    The output_pubkey is the 32-byte x-only key from the scriptPubKey.

    Reference: BIP 341 key path spending
    """
    if len(witness) != 1:
        return False  # key path = exactly one witness element

    sig = witness[0]
    sighash_type = 0x00  # default
    if len(sig) == 65:
        sighash_type = sig[-1]
        sig = sig[:-1]
    elif len(sig) != 64:
        return False

    # Compute taproot sighash (BIP 341 §4)
    sighash = self._compute_taproot_sighash(tx, input_index, sighash_type)

    return self._verify_schnorr_signature(sighash, sig, output_pubkey)
```

**Note:** The taproot sighash algorithm (BIP 341 §4) is significantly different from BIP 143. It uses a tagged hash (`TapSighash`) and commits to all input amounts and scriptPubKeys. This is the most complex part of Taproot implementation.

---

## Phase 6: Production Hardening (2-3 weeks) — ✅ COMPLETED

### Task 6.1: Structured Logging — ✅ DONE

**Priority:** Low  
**Estimated Time:** 1-2 days  
**Files Created/Modified:** `src/ouroboros/logging_config.py` (new), `src/ouroboros/cli.py`

```python
import logging
import json
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def configure_logging(debug: bool = False, json_format: bool = False):
    """Configure logging for the node."""
    level = logging.DEBUG if debug else logging.INFO

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]
```

### Task 6.2: Prometheus Metrics — ✅ DONE

**Priority:** Low  
**Estimated Time:** 2-3 days  
**Files Created:** `src/ouroboros/metrics.py`  
**Dependencies:** `prometheus-client` (added to pyproject.toml)

```python
"""Prometheus metrics for node monitoring."""

from prometheus_client import (
    Counter, Gauge, Histogram, Info,
    start_http_server, REGISTRY,
)

# Chain metrics
BLOCK_HEIGHT = Gauge('ouroboros_block_height', 'Current block height')
CHAIN_DIFFICULTY = Gauge('ouroboros_chain_difficulty', 'Current chain difficulty')
PEERS_CONNECTED = Gauge('ouroboros_peers_connected', 'Number of connected peers')

# Mempool metrics
MEMPOOL_SIZE = Gauge('ouroboros_mempool_size', 'Mempool size in bytes')
MEMPOOL_TX_COUNT = Gauge('ouroboros_mempool_tx_count', 'Number of mempool transactions')

# P2P metrics
BLOCKS_RECEIVED = Counter('ouroboros_blocks_received_total', 'Total blocks received')
TX_RECEIVED = Counter('ouroboros_tx_received_total', 'Total transactions received')
PEER_DISCONNECTS = Counter('ouroboros_peer_disconnects_total', 'Total peer disconnections')

# RPC metrics
RPC_REQUESTS = Counter(
    'ouroboros_rpc_requests_total',
    'Total RPC requests',
    ['method'],
)
RPC_DURATION = Histogram(
    'ouroboros_rpc_duration_seconds',
    'RPC request duration',
    ['method'],
)

# Node info
NODE_INFO = Info('ouroboros_node', 'Node information')


def start_metrics_server(port: int = 9332):
    """Start Prometheus metrics HTTP server."""
    start_http_server(port)


def update_chain_metrics(height: int, difficulty: float, peers: int):
    """Update chain-related gauges."""
    BLOCK_HEIGHT.set(height)
    CHAIN_DIFFICULTY.set(difficulty)
    PEERS_CONNECTED.set(peers)


def update_mempool_metrics(size: int, tx_count: int):
    """Update mempool gauges."""
    MEMPOOL_SIZE.set(size)
    MEMPOOL_TX_COUNT.set(tx_count)
```

Integration into `node.py`:
```python
# In BitcoinNode.__init__():
from ouroboros.metrics import start_metrics_server, NODE_INFO
start_metrics_server(port=9332)
NODE_INFO.info({"version": "0.1.0", "network": self.network})

# In _periodic_tasks():
from ouroboros.metrics import update_chain_metrics, update_mempool_metrics
update_chain_metrics(height, self.get_current_difficulty(), len(self.peers))
update_mempool_metrics(self.mempool.total_size, len(self.mempool.txids))
```

### Task 6.3: Cookie-Based RPC Authentication — ✅ DONE

**Priority:** Low  
**Estimated Time:** 1 day  
**Files Created/Modified:** `src/ouroboros/cookie_auth.py` (new), `src/ouroboros/node.py`, `src/ouroboros/rpc.py`

Bitcoin Core generates a `.cookie` file at startup with a random password. Clients read this file to authenticate.

```python
import os
import secrets
from pathlib import Path


def generate_rpc_cookie(data_dir: str) -> Tuple[str, str]:
    """
    Generate an RPC auth cookie file.

    Creates {data_dir}/.cookie with content: __cookie__:{random_password}

    Returns (username, password).
    """
    cookie_path = Path(data_dir) / ".cookie"
    password = secrets.token_hex(32)
    username = "__cookie__"

    cookie_path.write_text(f"{username}:{password}")
    cookie_path.chmod(0o600)

    return username, password


def read_rpc_cookie(data_dir: str) -> Tuple[str, str]:
    """Read RPC credentials from cookie file."""
    cookie_path = Path(data_dir) / ".cookie"
    if not cookie_path.exists():
        raise FileNotFoundError(f"Cookie file not found: {cookie_path}")

    content = cookie_path.read_text().strip()
    username, password = content.split(":", 1)
    return username, password
```

---

## Quick Reference: Implementation Order

| Phase | Tasks | Priority | Effort |
|-------|-------|----------|--------|
| 1 | Fee estimation, `estimatesmartfee` RPC, `validateaddress` RPC | Medium | 1-2 weeks |
| 2 | Wallet: keys, signing, coin selection, wallet RPCs | Medium | 3-4 weeks |
| 3 | Merkle proof RPCs, mining RPCs | Low | 1 week |
| 4 | Integration tests, CI/CD | Medium | 1-2 weeks |
| 5 | Taproot / Schnorr | Low | 2-3 weeks |
| 6 | Logging, metrics, auth hardening | Low | 2-3 weeks | ✅ |

**Total estimated time: ~10-14 weeks**

---

## Notes

- Phases 1-4 can be worked on somewhat independently
- Phase 5 (Taproot) is optional — the node functions without it for pre-Taproot transactions
- Phase 6 (Production) is polish — implement as needed for deployment
- Reference Bitcoin Core source for edge cases: `bitcoin/src/`
- Prefer using the Rust extension (`ferrous-utils/sync/`) for performance-critical crypto operations
- Test with testnet4 before mainnet

---

## Key Source File Reference

| File | Purpose |
|------|---------|
| `src/ouroboros/node.py` | Main node orchestrator, `BitcoinNode` class |
| `src/ouroboros/rpc.py` | RPC server, `RPCServer` class, dispatch via `rpc_*` methods |
| `src/ouroboros/wallet.py` | Wallet (currently stubs) |
| `src/ouroboros/mempool.py` | Mempool with fee rate sorting |
| `src/ouroboros/database.py` | `BlockchainDatabase`, `Transaction`, `Block` classes |
| `src/ouroboros/script.py` | `ScriptInterpreter`, `disassemble_script()` |
| `src/ouroboros/address.py` | `address_to_script_pubkey()` |
| `src/ouroboros/config.py` | `NodeConfig` — `ouroboros.conf` parsing |
| `src/ouroboros/p2p_messages.py` | P2P message types, `TxMessage.from_payload()` |
| `src/ouroboros/block_sync.py` | Block sync, reorg handling, orphan management |
| `src/ouroboros/fee_estimator.py` | Fee estimation (to be created) |
| `ferrous-utils/sync/src/validate/block.rs` | Block validation (Rust), `assumevalid` |
| `ferrous-utils/sync/src/validate/transaction.rs` | Transaction validation (Rust) |
| `ferrous-utils/sync/src/network/block_sync.rs` | Parallel block download (Rust) |
