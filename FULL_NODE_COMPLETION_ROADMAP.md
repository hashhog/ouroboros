# Ouroboros — Full Node Completion Roadmap

What remains to bring Ouroboros to parity with Bitcoin Core as a consensus-valid full node. Items are ordered by severity: consensus-critical first, then protocol, then polish.

---

## Phase A: Consensus-Critical (must-fix before chain tip validation)

These gaps mean Ouroboros will reject valid blocks or accept invalid ones once `assumevalid` is disabled for new blocks.

### A.1 — OP_CHECKLOCKTIMEVERIFY (BIP 65) — ✅ DONE

**Opcode:** `0xb1` (redefines `OP_NOP2`)
**Active since:** Block 388,381 (December 2015)
**File:** `src/ouroboros/script.py`

The opcode reads the top stack element as a 5-byte integer and compares it against `tx.locktime`. If the lock condition is not met, the script fails. The stack is **not** popped (the value stays).

**Implementation:**

```python
# In _execute_script(), after the OP_CHECKMULTISIG block:

# OP_CHECKLOCKTIMEVERIFY (0xb1) — BIP 65
if opcode == 0xb1:
    if not stack:
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: stack empty")

    # Read as 5-byte CScriptNum (allows values up to 2^39-1)
    raw = stack[-1]  # peek, do NOT pop
    if len(raw) > 5:
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: operand too large")
    lock_value = self._read_signed_num(raw)

    if lock_value < 0:
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: negative locktime")

    # Both must be same type: either both < 500_000_000 (block height)
    # or both >= 500_000_000 (unix timestamp)
    LOCKTIME_THRESHOLD = 500_000_000
    if not (
        (tx.locktime < LOCKTIME_THRESHOLD and lock_value < LOCKTIME_THRESHOLD) or
        (tx.locktime >= LOCKTIME_THRESHOLD and lock_value >= LOCKTIME_THRESHOLD)
    ):
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: locktime type mismatch")

    if lock_value > tx.locktime:
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: unsatisfied")

    # Must not be finalized (sequence != 0xffffffff)
    if tx.inputs[input_index].sequence == 0xffffffff:
        raise ValueError("OP_CHECKLOCKTIMEVERIFY: input is finalized")

    continue
```

**Also needed:** A `_read_signed_num` helper that handles the sign bit correctly for CScriptNum encoding (the existing `_read_num` does unsigned-only):

```python
def _read_signed_num(self, data: bytes) -> int:
    """Read a signed CScriptNum (little-endian, MSB of last byte is sign)."""
    if not data:
        return 0
    # Check minimal encoding
    if len(data) > 1 and data[-1] == 0 and not (data[-2] & 0x80):
        raise ValueError("Non-minimal CScriptNum encoding")
    value = int.from_bytes(data, 'little')
    if data[-1] & 0x80:
        # Negative: clear sign bit
        value -= (1 << (len(data) * 8))
        value += (data[-1] & 0x80) << ((len(data) - 1) * 8)
        # Simpler approach:
        neg = True
        value = int.from_bytes(data, 'little')
        value &= ~(0x80 << ((len(data) - 1) * 8))
        return -value
    return value
```

**Reference:** `bitcoin/src/script/interpreter.cpp:522-558`, `CheckLockTime()` at line 1748.

**Tests to add:**
- Script with `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP` where `tx.locktime >= height` → pass
- Same where `tx.locktime < height` → fail
- Locktime type mismatch (block height vs unix timestamp) → fail
- Input with `sequence = 0xffffffff` → fail
- Negative locktime value → fail

---

### A.2 — OP_CHECKSEQUENCEVERIFY (BIP 112) — ✅ DONE

**Opcode:** `0xb2` (redefines `OP_NOP3`)
**Active since:** Block 419,328 (July 2016)
**File:** `src/ouroboros/script.py`

Compares the top stack element against the input's `nSequence` field for relative timelocks. Like CLTV, the stack value is peeked, not popped.

**Implementation:**

```python
# OP_CHECKSEQUENCEVERIFY (0xb2) — BIP 112
if opcode == 0xb2:
    if not stack:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: stack empty")

    raw = stack[-1]  # peek
    if len(raw) > 5:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: operand too large")
    lock_value = self._read_signed_num(raw)

    if lock_value < 0:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: negative sequence")

    SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31  # 0x80000000
    SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22     # 0x00400000
    SEQUENCE_LOCKTIME_MASK = 0x0000ffff

    # If disable flag set in the operand, behave as NOP
    if lock_value & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        continue

    # Transaction version must be >= 2 for BIP 68
    if tx.version < 2:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: tx version < 2")

    tx_sequence = tx.inputs[input_index].sequence

    # Input's sequence must not have disable flag set
    if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: input disable flag set")

    # Mask to consensus-meaningful bits
    nLockTimeMask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
    tx_sequence_masked = tx_sequence & nLockTimeMask
    lock_value_masked = lock_value & nLockTimeMask

    # Type must match (both block-based or both time-based)
    if not (
        (tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG and
         lock_value_masked < SEQUENCE_LOCKTIME_TYPE_FLAG) or
        (tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG and
         lock_value_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)
    ):
        raise ValueError("OP_CHECKSEQUENCEVERIFY: type mismatch")

    if lock_value_masked > tx_sequence_masked:
        raise ValueError("OP_CHECKSEQUENCEVERIFY: unsatisfied")

    continue
```

**Reference:** `bitcoin/src/script/interpreter.cpp:561-593`, `CheckSequence()` at line 1786.

**Tests to add:**
- Relative lock of 10 blocks with sequence encoding 15 → pass
- Relative lock of 10 blocks with sequence encoding 5 → fail
- Time-based vs height-based mismatch → fail
- Disable flag set in operand → NOP (pass through)
- Transaction version 1 → fail

---

### A.3 — BIP 68: nSequence Relative Locktime Enforcement ✅ DONE

**Active since:** Block 419,328 (same deployment as BIP 112)
**Files:** `src/ouroboros/validation.py`

BIP 68 is enforced **at the transaction level**, not inside the script interpreter. Before a transaction is accepted into a block, the node must check that each input's `nSequence` relative locktime is satisfied based on the height/time of the UTXO being spent.

**Implementation in `TransactionValidator`:**

```python
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000ffff

def check_sequence_locks(self, tx: Transaction, block_height: int,
                         block_median_time: int) -> bool:
    """
    BIP 68: Verify relative lock-time constraints on all inputs.

    For each input where the disable flag is NOT set:
      - If type flag is clear: sequence & MASK = required confirmations
        (input's UTXO must be at least that many blocks deep)
      - If type flag is set: sequence & MASK * 512 = required seconds
        (median-time-past must exceed UTXO's MTP by that amount)
    """
    if tx.version < 2:
        return True  # BIP 68 only applies to version >= 2

    for inp in tx.inputs:
        if inp.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            continue

        # Look up the UTXO being spent to find its confirmation height/time
        utxo_info = self.db.get_utxo_info(inp.prev_txid, inp.prev_vout)
        if utxo_info is None:
            return False

        if inp.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            # Time-based: units of 512 seconds
            required_time = (inp.sequence & SEQUENCE_LOCKTIME_MASK) * 512
            elapsed = block_median_time - utxo_info.median_time_past
            if elapsed < required_time:
                return False
        else:
            # Height-based
            required_height = inp.sequence & SEQUENCE_LOCKTIME_MASK
            depth = block_height - utxo_info.confirmed_height
            if depth < required_height:
                return False

    return True
```

**Database requirement:** The UTXO set or a coin metadata store needs to record the **block height** and **median-time-past** at which each UTXO was confirmed. If this data is not currently stored, add two fields to the UTXO record in RocksDB:
- `confirmed_height: u32`
- `median_time_past: u32`

**Reference:** `bitcoin/src/consensus/tx_verify.cpp` — `SequenceLocks()`, `CalculateSequenceLocks()`.

**Tests to add:**
- Spend a UTXO confirmed 10 blocks ago with sequence requiring 5 → pass
- Spend a UTXO confirmed 3 blocks ago with sequence requiring 5 → fail
- Time-based relative lock with sufficient MTP elapsed → pass
- Version 1 transaction ignores sequence locks → pass
- Disable flag set → skip check

---

### A.4 — Additional Missing Script Opcodes ✅ DONE

**File:** `src/ouroboros/script.py`

The interpreter currently falls through to a no-op for unrecognized opcodes. These must be implemented or explicitly handled:

| Opcode | Hex | What it does |
|--------|-----|-------------|
| `OP_EQUAL` | `0x87` | Pop two, push 1 if equal, 0 otherwise |
| `OP_VERIFY` | `0x69` | Pop top, fail if false |
| `OP_RETURN` | `0x6a` | Mark output as provably unspendable |
| `OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF` | `0x63-0x68` | Conditional execution |
| `OP_DROP / OP_2DROP` | `0x75 / 0x6d` | Remove stack items |
| `OP_SWAP / OP_ROT / OP_OVER / OP_PICK / OP_ROLL` | Various | Stack manipulation |
| `OP_SIZE` | `0x82` | Push length of top element |
| `OP_ADD / OP_SUB` | `0x93 / 0x94` | Arithmetic |
| `OP_WITHIN` | `0xa5` | Range check |
| `OP_RIPEMD160 / OP_SHA256 / OP_HASH256` | `0xa6-0xaa` | Hash functions |
| `OP_CODESEPARATOR` | `0xab` | Update subscript position |
| `OP_CHECKSIGVERIFY` | `0xad` | CHECKSIG + VERIFY |
| `OP_CHECKMULTISIGVERIFY` | `0xaf` | CHECKMULTISIG + VERIFY |
| `OP_NOP1, OP_NOP4-OP_NOP10` | `0xb0, 0xb3-0xb9` | Reserved NOPs (must be actual no-ops) |

Bitcoin Core reference: `bitcoin/src/script/interpreter.cpp` — the full `EvalScript()` switch block. The most commonly used in real transactions are `OP_IF/OP_ELSE/OP_ENDIF`, `OP_DROP`, `OP_EQUAL`, `OP_VERIFY`, and the hash opcodes.

---

## Phase B: Protocol Gaps (required for chain-tip operation)

These don't break consensus but are needed for a node to function properly at the chain tip rather than just during IBD.

### B.1 — Compact Blocks (BIP 152) ✅ DONE

**Priority:** High for chain-tip operation
**Files to create:** `src/ouroboros/compact_blocks.py`
**Files to modify:** `src/ouroboros/p2p_messages.py`, `src/ouroboros/p2p.py`

Without compact blocks, the node must download full blocks for every new block at the chain tip. Bitcoin Core nodes prefer compact block relay and may not send full blocks promptly.

**New P2P messages to implement:**
- `sendcmpct` — negotiate compact block support with peers
- `cmpctblock` — compact block announcement (header + short txids)
- `getblocktxn` — request missing transactions
- `blocktxn` — response with missing transactions

**Implementation outline:**

```python
class CompactBlock:
    """BIP 152 compact block representation."""

    def __init__(self, header: bytes, nonce: int, short_ids: List[int],
                 prefilled_txs: List[Tuple[int, Transaction]]):
        self.header = header
        self.nonce = nonce
        self.short_ids = short_ids
        self.prefilled_txs = prefilled_txs

    def reconstruct(self, mempool: Mempool) -> Optional[Block]:
        """
        Attempt to reconstruct the full block using mempool transactions.

        For each short_id, compute SipHash(mempool_tx) with the block's
        nonce and match. If all transactions are found, return the full
        block. Otherwise, return None (caller should send getblocktxn).
        """
        ...
```

**SipHash key derivation:**
```python
import struct, hashlib
# key = SHA256(header || nonce)[0:16]
# short_id = SipHash-2-4(key, tx_hash) & 0xffffffffffff
```

**Reference:** `bitcoin/src/blockencodings.cpp`, `bitcoin/src/blockencodings.h`.

---

### B.2 — Peer Misbehavior Tracking and Banning ✅ DONE

**Priority:** High (DoS protection)
**Files to create:** `src/ouroboros/banman.py`
**Files to modify:** `src/ouroboros/p2p.py`

**Implementation outline:**

```python
class BanManager:
    """Track peer misbehavior and enforce bans."""

    def __init__(self, ban_threshold: int = 100,
                 ban_duration: int = 86400):
        self.scores: Dict[str, int] = {}        # ip -> score
        self.banned: Dict[str, float] = {}       # ip -> ban_until timestamp
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration

    def record_misbehavior(self, ip: str, score: int, reason: str):
        self.scores[ip] = self.scores.get(ip, 0) + score
        if self.scores[ip] >= self.ban_threshold:
            self.ban(ip)

    def ban(self, ip: str):
        self.banned[ip] = time.time() + self.ban_duration

    def is_banned(self, ip: str) -> bool:
        if ip not in self.banned:
            return False
        if time.time() > self.banned[ip]:
            del self.banned[ip]
            return False
        return True
```

**Misbehavior events to score (following Bitcoin Core):**
| Event | Score | Reference |
|-------|-------|-----------|
| Invalid block header | 100 (instant ban) | `net_processing.cpp` |
| Invalid block | 100 | `net_processing.cpp` |
| Invalid transaction | 1-10 | `net_processing.cpp` |
| Too many orphan txs | 1 | `net_processing.cpp` |
| Unsolicited block data | 20 | `net_processing.cpp` |
| Headers that don't connect | 10 | `net_processing.cpp` |

**Reference:** `bitcoin/src/banman.cpp`, `bitcoin/src/net_processing.cpp` (`Misbehaving()`).

---

### B.3 — Replace-By-Fee (BIP 125) ✅

**Priority:** Medium
**File:** `src/ouroboros/mempool.py`

**Implementation outline:**

```python
def try_replace(self, new_tx: Transaction) -> bool:
    """
    BIP 125: Allow replacement if:
    1. The replaced tx signals replaceability (sequence < 0xfffffffe)
    2. New tx pays strictly higher fee rate
    3. New tx's fee covers the bandwidth cost of relay (incremental relay fee)
    4. New tx doesn't evict more than 100 transactions
    5. New tx doesn't introduce new unconfirmed inputs
    """
    conflicts = self._find_conflicts(new_tx)
    if not conflicts:
        return False

    for conflict_txid in conflicts:
        conflict = self.transactions[conflict_txid]
        # Check signal
        if not any(inp.sequence < 0xfffffffe for inp in conflict.inputs):
            return False

    new_fee = self._calculate_fee(new_tx)
    old_fees = sum(self._calculate_fee(self.transactions[c]) for c in conflicts)
    if new_fee <= old_fees:
        return False

    # Remove conflicts and add new tx
    for txid in conflicts:
        self._remove_transaction(txid)
    self._add_transaction(new_tx)
    return True
```

**Reference:** `bitcoin/src/policy/rbf.cpp`.

---

## Phase C: Wallet Hardening

### C.1 — HD Key Derivation (BIP 32 / BIP 44) ✅

**Priority:** Medium
**File:** `src/ouroboros/wallet.py`

```python
import hmac, hashlib

def derive_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """BIP 32: Derive master private key and chain code from seed."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = I[:32]      # private key
    chain_code = I[32:]      # chain code
    return master_key, chain_code

def derive_child(parent_key: bytes, chain_code: bytes,
                 index: int, hardened: bool = False) -> Tuple[bytes, bytes]:
    """BIP 32: Derive child key at index."""
    if hardened:
        index |= 0x80000000
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:
        pubkey = private_to_public(parent_key)
        data = pubkey + index.to_bytes(4, 'big')

    I = hmac.new(chain_code, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(I[:32], 'big') +
                 int.from_bytes(parent_key, 'big')) % SECP256K1_ORDER
    return child_key.to_bytes(32, 'big'), I[32:]
```

**BIP 44 derivation path:** `m/84'/0'/0'/0/i` for native SegWit (P2WPKH).

**Reference:** `bitcoin/src/wallet/scriptpubkeyman.cpp`.

---

### C.2 — Encrypted Wallet ✅

**Priority:** Medium
**File:** `src/ouroboros/wallet.py`

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def encrypt_wallet(wallet_data: bytes, passphrase: str) -> bytes:
    """Encrypt wallet data with passphrase using AES-256-GCM."""
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**18, r=8, p=1)
    key = kdf.derive(passphrase.encode())
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, wallet_data, None)
    return salt + nonce + ciphertext
```

**Reference:** `bitcoin/src/wallet/crypter.cpp`.

---

### C.3 — PSBT Support (BIP 174) ✅

**Priority:** Low
**File to create:** `src/ouroboros/psbt.py`

Required for hardware wallet integration and multi-party signing workflows. Implement the PSBT binary format (key-value maps for global, per-input, per-output data) and `combinepsbt`, `finalizepsbt`, `decodepsbt` RPCs.

**Reference:** `bitcoin/src/psbt.cpp`, `bitcoin/src/psbt.h`.

---

## Phase D: Advanced Features

### D.1 — BIP 324 v2 P2P Transport ✅

**Priority:** Low
**Files to create:** `src/ouroboros/transport_v2.py`

Encrypted and authenticated P2P connections using the ElligatorSwift key exchange and ChaCha20-Poly1305 AEAD. Prevents passive eavesdropping and connection manipulation.

**Reference:** `bitcoin/src/bip324.cpp`, `bitcoin/src/bip324.h`.

---

### D.2 — Block Pruning ✅

**Priority:** Low
**Files to modify:** `src/ouroboros/database.py`, Rust storage layer

Allow the node to discard old block data after validation, keeping only the UTXO set and recent blocks. Requires a `prune=<target_size_mb>` config option.

**Reference:** `bitcoin/src/node/blockstorage.cpp` — `PruneOneBlockFile()`.

---

### D.3 — `getblocktemplate` RPC (Mining Support) ✅

**Priority:** Low
**File:** `src/ouroboros/rpc.py`

Assemble a candidate block from mempool transactions, optimizing for fee revenue while respecting weight limits. Return the template for external miners.

```python
async def rpc_getblocktemplate(self, template_request: Dict = None) -> Dict:
    """Construct a block template for mining."""
    # 1. Select transactions from mempool by fee rate (knapsack, greedy)
    # 2. Build coinbase transaction with block reward + fees
    # 3. Compute merkle root
    # 4. Return: version, previousblockhash, transactions, coinbasevalue,
    #    target, bits, curtime, height, etc.
```

**Reference:** `bitcoin/src/rpc/mining.cpp` — `getblocktemplate`.

---

### D.4 — ZMQ Notifications ✅

**Priority:** Low
**Files to create:** `src/ouroboros/zmq_publisher.py`
**Dependency:** `pyzmq`

Publish `hashblock`, `hashtx`, `rawblock`, `rawtx` events over ZeroMQ PUB sockets for external consumers.

**Reference:** `bitcoin/src/zmq/`.

---

## Phase E: Improved Coin Selection

### E.1 — Branch-and-Bound Coin Selection (BIP ???) ✅

**Priority:** Low
**File:** `src/ouroboros/wallet.py`

Replace the current largest-first strategy with Bitcoin Core's algorithms:
1. **Branch and Bound** — find exact-match combinations to avoid change outputs
2. **Knapsack** — randomized approximation when B&B fails
3. **Single Random Draw** — fallback

**Reference:** `bitcoin/src/wallet/coinselection.cpp`.

---

## Quick Reference

| Phase | Tasks | Impact | Effort |
|-------|-------|--------|--------|
| **A** (consensus) | CLTV, CSV, BIP 68, missing opcodes | **Breaks consensus** if missing | 1-2 weeks |
| **B** (protocol) | Compact blocks, ban manager, RBF | Needed at chain tip | 2-3 weeks |
| **C** (wallet) | HD keys, encryption, PSBT | Wallet usability | 2-3 weeks |
| **D** (advanced) | v2 transport, pruning, mining, ZMQ | Feature parity | 3-4 weeks |
| **E** (optimization) | Coin selection algorithms | Wallet efficiency | 1 week |

**Total estimated effort: ~9-13 weeks**

**Recommended order:** A.1 → A.2 → A.3 → A.4 → B.2 → B.1 → B.3 → C.1 → rest as needed.

Phase A is the only blocker for calling Ouroboros a full-validating node.
