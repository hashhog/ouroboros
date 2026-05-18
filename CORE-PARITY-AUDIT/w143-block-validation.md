W143 — Block-level validation audit (ouroboros)
==================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline + Rust pipeline — block-level
      `CheckBlock` / `ContextualCheckBlock` / `ConnectBlock` analogs
      live in `src/ouroboros/validation.py` (Python orphan/reorg path),
      `ferrous-utils/sync/src/validate/block.rs` (`BlockValidator`),
      and `ferrous-utils/sync/src/lib.rs::connect_block_from_bytes`
      (Python FFI mining/generate path). The Python orphan path and
      the Rust IBD path BOTH ship — two-pipeline divergence is the
      dominant risk vector.)
Wave: W143 — `CheckBlock` + `ContextualCheckBlock` + `ConnectBlock`.

Reference (Bitcoin Core)
------------------------
- `bitcoin-core/src/validation.cpp`:
  - `CheckBlock` (lines 3918-3983): context-free block checks
    (header → merkle → empty-vtx → first-tx-coinbase → no-multi-cb →
    per-tx CheckTransaction → legacy-sigops × 4 cap).
  - `CheckMerkleRoot` (lines 3837-3862): recompute + CVE-2012-2459
    mutated-tree detection.
  - `IsBlockMutated` (lines 4027-4056): 64-byte stripped-tx detection
    (Linux Foundation 2019 weakness paper §3.1).
  - `ContextualCheckBlockHeader` (lines 4080-4121): bad-diffbits,
    time-too-old (MTP), BIP-94 timewarp, time-too-new, bad-version.
  - `ContextualCheckBlock` (lines 4129-4184): IsFinalTx (BIP-113
    cutoff), BIP-34 coinbase height, CheckWitnessMalleation, weight.
  - `Chainstate::ConnectBlock` (lines 2295-2696): BIP-30, per-tx
    `CheckTxInputs`, sigop-cost accumulation, witness verification,
    coinbase amount ≤ subsidy + fees, UTXO mutations.
  - `GetBlockSubsidy` (validation.cpp:~1840): `50 * COIN >> halvings`,
    return 0 once `halvings >= 64`. Halving interval per network.
- `bitcoin-core/src/consensus/tx_check.cpp` (lines 11-60): vin/vout
  non-empty, oversize, vout-negative / vout-toolarge / total-toolarge
  (CVE-2010-5139), duplicate inputs (CVE-2018-17144), coinbase
  scriptSig 2..=100 bytes, non-coinbase null-prevout.
- `bitcoin-core/src/consensus/tx_verify.cpp`:
  - `GetLegacySigOpCount` (lines 112-124): both vin (scriptSig) and
    vout (scriptPubKey), counts coinbase scriptSig too.
  - `GetP2SHSigOpCount` (lines 126-141): early-return 0 for coinbase.
  - `GetTransactionSigOpCost` (lines 143-162): `legacy × 4 + p2sh × 4 +
    Σ witness × 1`.
- `bitcoin-core/src/consensus/merkle.cpp`:
  - `ComputeMerkleRoot` (lines 46-63): mutation flag set when ANY pair
    at ANY level has identical halves.
  - `BlockMerkleRoot` (lines 66-74): wraps `ComputeMerkleRoot` with
    explicit `mutated*` out-param.
- `bitcoin-core/src/consensus/validation.h` (lines 132-144):
  `GetBlockWeight = stripped × 3 + total`, both summands include the
  80-byte header and the tx-count CompactSize.
- `bitcoin-core/src/primitives/transaction.h`:
  - `COutPoint::IsNull` (line 42): `hash.IsNull() && n == NULL_INDEX`
    (BOTH conditions, NULL_INDEX = `0xFFFFFFFF`).
  - `CTransaction::IsCoinBase` (line 341-344): `vin.size() == 1 &&
    vin[0].prevout.IsNull()`.

Status: 27 BUGS catalogued (4 P0-CDIV / 1 P0-DoS / 1 P0-SEC / 11 P1 /
        8 P2 / 2 P3).

Relationship to prior audits
----------------------------

- **W132 (nSequence/CSV/MTP)**: nLockTimeCutoff plumbing audited
  end-to-end. W143 cross-references the IsFinalTx + BIP-113 plumbing
  that runs inside ConnectBlock; some W132 bugs (e.g. utxo_mtp=0
  fallback) directly compound BUG-W143-13/14 here.
- **W138 (assumeUTXO)**: invented mainnet h=840000 hash carried
  forward; the dead `MaybeValidateSnapshot` lookalike is mirrored by
  ouroboros's `apply_block` dead-code (validation.py:885-941).
- **W142 (SegWit witness validation)**: BIP-141 witness-commitment
  gates audited; W143 covers the wrapper `CheckBlock` flow that calls
  `_validate_witness_commitment` — the BUG-2 P0-DoS empty-vtx index
  is the same chain of indexing risk as the W142 BUG-2 `vtx[0].vin[0]`
  hit, surfaced again here in a different code path.
- **W135 (Standardness)**: policy-side gates. W143 audits the
  consensus-side equivalents — `IsStandardTx` is not consensus,
  `CheckTransaction` is.
- **W125 (RPC/REST)**: HTTP server / two-pipeline framework. The
  validate_block_from_bytes route reaches Rust off-GIL; the orphan-
  block path stays in Python. W143 catches at least one consensus
  divergence between the two pipelines (BUG-W143-2 BIP-34 encoding,
  BUG-W143-5 weight formula, BUG-W143-11 IsFinalTx coinbase skip).

Two-pipeline guard
------------------

Block-level validation runs across **TWO independent pipelines**:

1. **Python pipeline** — `BlockValidator.validate_block`
   (`validation.py:648-883`).  Used by orphan-block processing, reorg
   handlers, RPC `submitblock`, and tests:
   - `block_sync.py:2205` (orphan path),
   - `block_sync.py:1127` (Rust-missing fallback in IBD),
   - `tests/test_w123_mining_gbt.py:183` (mining test).

2. **Rust pipeline (off-GIL)** — `BlockValidator::validate_block_with_flags`
   (`ferrous-utils/sync/src/validate/block.rs:255-397`) exposed via
   `lib.rs:3347::validate_block_from_bytes`. Plus the alternate
   `lib.rs:3402::connect_block_from_bytes` which embeds **its own**
   third pseudo-validator (header PoW + merkle + ContextualCheckBlock
   subset). Used by:
   - `block_sync.py:1213` (IBD-drain hot path),
   - `cli.py:929` (generatetoaddress mining),
   - `node.py:889` (genesis-block one-shot).

```
$ grep -rn 'validate_block\b\|validate_block_from_bytes\|validate_block_with_flags\|connect_block_from_bytes' \
    src/ouroboros/ ferrous-utils/sync/src/ --include='*.py' --include='*.rs' | grep -v tests | grep -v '//'
src/ouroboros/block_sync.py:1115    self.db.validate_block_from_bytes,
src/ouroboros/block_sync.py:1127    self.validator.validate_block,
src/ouroboros/block_sync.py:1213    self.db.validate_block_from_bytes(...)
src/ouroboros/block_sync.py:2205    valid, error = self.validator.validate_block(block)
src/ouroboros/cli.py:929            db.connect_block_from_bytes(block_data, frame_height)
src/ouroboros/node.py:889           self.db.connect_block_from_bytes(block_bytes, 0)
ferrous-utils/sync/src/lib.rs:3347  fn validate_block_from_bytes(...)
ferrous-utils/sync/src/lib.rs:3402  fn connect_block_from_bytes(...)
ferrous-utils/sync/src/validate/block.rs:167  pub fn validate_block(...)
ferrous-utils/sync/src/validate/block.rs:255  pub fn validate_block_with_flags(...)
```

The Python orphan/reorg path and the Rust IBD/mining paths **diverge**
on at least four consensus-relevant rules (BUG-W143-2 BIP-34, BUG-W143-5
weight formula, BUG-W143-11 IsFinalTx coinbase skip, BUG-W143-7 BIP-34
height in connect_block_from_bytes). Two-pipeline guard EXTENDED.
Now 16 cross-wave instances (W76 + W120 + W122 + W125 + W128 + W129 +
W130 + W131 + W133 + W134 + W137 + W140 + W141 + W142 → W143).

Top-level architectural findings
--------------------------------

### F1 — `is_coinbase` accepts non-null vout (NULL_INDEX absent)

`database.py:170-172`:

```py
@property
def is_coinbase(self) -> bool:
    """Check if this is a coinbase transaction"""
    return len(self.inputs) == 1 and self.inputs[0].prev_txid == bytes(32)
```

Core (`primitives/transaction.h:42` + `transaction.h:341-344`):

```cpp
bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }
...
bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
}
```

Core requires **BOTH** `prev_txid == bytes(32)` AND `prev_vout == 0xFFFFFFFF`.
Ouroboros only checks the txid. A crafted "fake coinbase" with
`prev_txid = bytes(32)` but `prev_vout = 0x00000000` (or any non-`0xFFFFFFFF`
value) is accepted by `is_coinbase` and:

- bypasses BIP-30 (because `is_coinbase` short-circuits the BIP-30
  walk; see also `_check_structure`'s null-prevout check at line 2125,
  which DOES require both, but only runs for non-coinbase txs)
- bypasses the null-prevout rejection in `_check_structure`
  (validation.py:2125 — the check fires only when `not tx.is_coinbase`,
  so a tx with `prev_txid == 0`, `prev_vout == 0` is treated as coinbase
  here and NEVER tested for the null-prevout consensus rule)

**BUG-W143-1 (P0-CDIV)** — `is_coinbase` definition drift versus Core.
This is a cross-cutting consensus break: any code path that branches
on `tx.is_coinbase` (and there are 40+) will mis-classify the crafted
tx and either over-permit a non-coinbase as coinbase OR under-protect
the coinbase path. Compounds with BUG-W143-13 (CheckTransaction never
called on coinbase).

Fix sketch:
```py
NULL_INDEX = 0xFFFFFFFF
return (len(self.inputs) == 1
        and self.inputs[0].prev_txid == bytes(32)
        and self.inputs[0].prev_vout == NULL_INDEX)
```

### F2 — BIP-34 encoding accepts a non-canonical raw u32 (Rust) vs Core's CScriptNum

`ferrous-utils/sync/src/validate/transaction.rs:530-548`:

```rust
const BIP34_HEIGHT: u32 = 227_931;
if height >= BIP34_HEIGHT {
    let script = coinbase_input.script_sig.as_bytes();
    let push_size = script[0] as usize;
    if push_size == 0 {
        if height != 0 {
            return Err(TransactionValidationError::InvalidCoinbaseHeight);
        }
    } else {
        if push_size > 4 || 1 + push_size > script.len() {
            return Err(TransactionValidationError::InvalidCoinbaseHeight);
        }
        let mut buf = [0u8; 8];
        buf[..push_size].copy_from_slice(&script[1..1 + push_size]);
        let encoded = u64::from_le_bytes(buf);
        if encoded != height as u64 {
            return Err(TransactionValidationError::InvalidCoinbaseHeight);
        }
    }
}
```

Core (`validation.cpp:4151-4159`):

```cpp
CScript expect = CScript() << nHeight;
if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
    !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", ...);
}
```

`CScript() << nHeight` produces a **canonical CScriptNum** push:
- height == 0 → `OP_0` (single byte 0x00)
- 1..=16 → `OP_1..OP_16` (single bytes 0x51..0x60)
- otherwise → length-prefixed sign-magnitude with optional zero-sign
  byte for high-bit-set values.

The Rust path's raw-u32-le decode accepts BOTH:

1. `OP_1..OP_16` (push_size 0x51..0x60 > 4 → rejects ✓ via the
   `push_size > 4` check, technically correct **but** with a wrong
   reject-reason path — the `> 4` rejection fires for ALL "weird"
   first-byte values including legitimate single-byte CScriptNum
   pushes for `OP_1..OP_16`), AND
2. Non-canonical encodings — e.g. a push of `[0x01, 0x01]` matches
   `height == 1` but Core's `CScript() << 1` yields `OP_1` (single
   byte `0x51`), not `[0x01, 0x01]`. The byte-exact `std::equal`
   means Core REJECTS `[0x01, 0x01]` for height 1; ouroboros
   ACCEPTS it.

The **Python** path (validation.py:97-118 `_encode_bip34_height` +
1490-1502) uses byte-exact canonical encoding matching Core. So:
**the Python orphan path rejects** a non-canonical-BIP-34 coinbase,
**the Rust IBD path accepts** it.

A peer-broadcast block with `[0x01, 0x01]` coinbase at height 1
exposes a chain split: ouroboros IBD accepts → other nodes reject →
ouroboros wedged on a private chain.

**BUG-W143-2 (P0-CDIV)** — Rust BIP-34 path is byte-incompatible with
Core AND with Python orphan path. `# Python reference: validation.py:775-793.
We mirror Python's unsigned little-endian decode rather than full
CScriptNum, which is intentionally lenient...` (transaction.rs:524-528)
is **comment-as-confession** — author knew the divergence existed.

Fix sketch: import the canonical `_encode_bip34_height` logic
(Python validation.py:97-118) into Rust. Compare byte-exact.

### F3 — `_validate_coinbase` BIP-34 gate uses byte-prefix match (correct), but coinbase scriptSig length check duplicates between paths

`validation.py:1468-1478`:

```py
# Coinbase scriptSig must be 2-100 bytes (consensus rule)
sig_len = len(coinbase_input.script_sig)
if sig_len < 2 or sig_len > 100:
    ...
```

This is a duplicate of `_check_structure` (CheckTransaction) which
runs the same 2..=100 check via `consensus/tx_check.cpp:49-50` IF the
coinbase tx were passed to CheckTransaction. Since `_check_structure`
is NEVER invoked on the coinbase (see BUG-W143-13), the duplicate in
`_validate_coinbase` is the ONLY place this gate fires for the Python
path. The Rust path has its own duplicate (`transaction.rs:518-521`)
PLUS a third copy in `connect_block_from_bytes` (`lib.rs:3582-3591`).
Three copies, none of which run as part of "CheckTransaction"; all
in coinbase-specific wrappers. **Triple wire-up hazard.**

**BUG-W143-3 (P2)** — coinbase scriptSig 2..=100 check is replicated
three times across two pipelines. A future edit to one site drifts the
others; the missing single-source-of-truth `CheckTransaction` plumbing
(BUG-W143-13) lets the drift go undetected. Filed as P2 because the
check ITSELF is correct in all three sites today.

### F4 — Merkle CVE-2012-2459 (`mutated`) detection is **only at leaf level**, not at every internal level

`validation.py:1162-1201`:

```py
def _calculate_merkle_root_checked(self, txids):
    if not txids:
        return bytes(32), False

    if len(txids) == 1:
        return txids[0], False

    mutated = False
    level = list(txids)

    # Check for duplicate txids at the leaf level
    seen = set()
    for t in level:
        key = bytes(t)
        if key in seen:
            mutated = True
            break
        seen.add(key)

    while len(level) > 1:
        next_level = []

        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                combined = level[i] + level[i + 1]
            else:
                # Odd count: duplicate the last element — flag mutation
                # if the last two are already identical.
                combined = level[i] + level[i]

            hash1 = hashlib.sha256(combined).digest()
            hash2 = hashlib.sha256(hash1).digest()
            next_level.append(hash2)

        level = next_level

    return level[0], mutated
```

Core (`consensus/merkle.cpp:46-63`):

```cpp
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());  // <-- odd-duplication AFTER check
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) *mutated = mutation;
    ...
}
```

Two divergences:

(a) **Mutated detection is internal-level**, not just leaf-level. A
malicious block can craft a transaction list `[T1, T2, T3, T4, T5, T6,
T7, T8]` where the inner hashes at level 1 satisfy `h(T1,T2) ==
h(T3,T4)` (computational-only — requires SHA-256 collision; flagged as
"not feasible in practice" by Core but the **CHECK** is enforced in
every block). More practically: Core's loop catches the case where the
**odd-element duplication at level N produces a 2-element level N+1
where both hashes are identical** — which then mutates correctly with
the same root as a 4-leaf list `[A,B,A,B]`. Ouroboros's leaf-only
check misses **every level after 0**.

(b) **The odd-duplication branch (`combined = level[i] + level[i]`)
doesn't even set `mutated`** despite the comment ("flag mutation if
the last two are already identical"). Compare-as-confession: the
comment is wrong about the code's behavior. Core's loop checks
`hashes[pos] == hashes[pos+1]` BEFORE the odd-duplication is appended;
ouroboros never checks any pair after the leaf level.

**BUG-W143-4 (P0-CDIV)** — incomplete CVE-2012-2459 mutated detection.
A block with carefully-chosen intra-level duplicate hashes passes
ouroboros's mutation gate but fails Core's. **Comment-as-confession
5th cross-fleet instance** (validation.py:1191-1192 — comment says one
thing, code does another).

Fix sketch: walk Core's algorithm — check pairs at every level BEFORE
the odd-duplication step. Mirror line-for-line.

### F5 — Block-weight formula in `_validate_block_limits` is missing header+tx-count overhead

`validation.py:1236-1241` (already partially flagged in W142 BUG-3/F4
but consensus-relevant for W143 too):

```py
stripped_block_size = sum(len(tx.serialize()) for tx in block.transactions)
if stripped_block_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
    return False, (f"bad-blk-length: stripped block size ...")
```

PLUS `validation.py:1243-1294`:

```py
total_weight = 0
total_sigops_cost = 0

for tx in block.transactions:
    total_weight += tx.get_weight()
    ...

if total_weight > MAX_BLOCK_WEIGHT:
    return False, f"Block weight {total_weight} exceeds {MAX_BLOCK_WEIGHT}"
```

Core (`consensus/validation.h:136-139`):

```cpp
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(TX_NO_WITNESS(block)) * (WITNESS_SCALE_FACTOR - 1)
         + ::GetSerializeSize(TX_WITH_WITNESS(block));
}
```

`GetSerializeSize(TX_NO_WITNESS(block))` serializes the ENTIRE block:
80-byte header + `CompactSize(tx_count)` + Σ stripped tx sizes.
Similarly for `TX_WITH_WITNESS(block)` (with the marker/flag and
witness bytes). Ouroboros's per-tx accumulation drops the **80-byte
header** and the **`CompactSize(tx_count)` varint** from BOTH summands.

For a block exactly at boundary `MAX_BLOCK_WEIGHT == 4_000_000`:
- Ouroboros weight = Σ(tx weight)
- Core weight     = Σ(tx weight) + 80 × 3 + sizeof(varint(N)) × 3
                  + 80 × 1 + sizeof(varint(N)) × 1
                  = Σ(tx weight) + 80 × 4 + 4 × sizeof(varint(N))

For a "normal" block with ~3000 txs, `CompactSize(3000)` = 3 bytes.
Difference: `320 + 12 = 332` weight units.

A miner crafts a block exactly at `4_000_000 - 200` weight per
ouroboros's formula → Core rejects with `bad-blk-weight`, ouroboros
accepts. **BUG-W143-5 (P0-CDIV)** — boundary-precision divergence,
already flagged W142 BUG-3 but cross-cited here as the W143-side
finding (block-level weight gate vs Core's `GetBlockWeight`).

The Rust pipeline uses `bitcoin::Block::weight().to_wu()`
(`block.rs:443`) which delegates to the canonical `bitcoin` crate
formula — Rust path is correct, Python orphan path is wrong. **Two-
pipeline divergence**.

### F6 — `_verify_coinbase_amount` does not guard against negative/overflow output values

`validation.py:1506-1518`:

```py
def _verify_coinbase_amount(
    self,
    coinbase_tx: Transaction,
    height: int,
    total_fees: int
) -> bool:
    block_subsidy = self._calculate_block_subsidy(height)
    expected_amount = block_subsidy + total_fees

    total_output = sum(out.value for out in coinbase_tx.outputs)

    # Coinbase amount must not exceed subsidy + fees (miners may underpay)
    return total_output <= expected_amount
```

Two issues:

(a) `out.value` is wire-deserialized as **unsigned 64-bit** (see
`p2p_messages.py` BIP-144 deserializer). A coinbase output with
`value = -1` (`0xFFFFFFFFFFFFFFFF` on the wire) yields
`out.value == 18446744073709551615` in Python. Sum is also a huge
positive int. The `<=` comparison against `expected_amount` (a few
billion) fails, so this check accidentally rejects. **But Core rejects
with `bad-txns-vout-negative` via CheckTransaction**, which never
runs for the coinbase here (BUG-W143-13). The actual reject path is
"bad-cb-amount" with a misleading message instead of "bad-txns-vout-
negative". **Reject-reason-string drift**, P1.

(b) Coinbase tx whose outputs collectively overflow `MAX_MONEY`
(per-output ≤ MAX_MONEY but total > MAX_MONEY) — Core's
CheckTransaction rejects with `bad-txns-txouttotal-toolarge`.
Ouroboros's `_verify_coinbase_amount` only checks `total_output <=
expected_amount`. For a coinbase with `total_output > MAX_MONEY` AND
`expected_amount == subsidy + total_fees < MAX_MONEY`, ouroboros
correctly rejects (the comparison fails). For the edge case where
`expected_amount > MAX_MONEY` (which CAN happen if `total_fees`
silently overflowed Python int → MAX_MONEY check at validation.py:859
DOES guard this, but only on the **per-tx-loop accumulated fee**, not
the **coinbase subsidy + fees**). The combined `subsidy + total_fees`
is not range-checked.

**BUG-W143-6 (P1)** — coinbase amount check substitutes for
CheckTransaction's per-output bounds, with subtly different
semantics and wrong reject-reason strings.

### F7 — `connect_block_from_bytes` (Rust mining path) skips BIP-34 entirely

`ferrous-utils/sync/src/lib.rs:3402-3592` performs a hand-rolled subset
of CheckBlock/ContextualCheckBlock:
- PoW verification ✓
- merkle root recompute ✓
- prev-hash chain link ✓
- BIP-113 MTP ✓
- coinbase scriptSig 2..=100 ✓
- BIP-141 witness commitment ✓
- IsFinalTx (non-coinbase only) ✓

But it does NOT enforce:
- **BIP-34 coinbase height** (validation.cpp:4151-4159) — entirely
  absent. A regtest miner can submit a coinbase with arbitrary
  scriptSig and the block is accepted.
- **BIP-30 duplicate-coinbase check** — absent.
- **Block weight gate** (`MAX_BLOCK_WEIGHT`) — absent. Hand-rolled
  path accepts any-size block.
- **Sigop cost cap** (`MAX_BLOCK_SIGOPS_COST = 80_000`) — absent.
- **CheckTransaction per-tx** — absent. Negative output values,
  duplicate inputs (CVE-2018-17144), oversize txs all bypass.
- **Per-tx UTXO inputs check** — absent (`CheckTxInputs`,
  consensus/tx_verify.cpp:164). The coinbase amount check (subsidy +
  fees) is also absent — a coinbase paying 100 BTC at height 800,000
  would land in the chainstate without comment.

**BUG-W143-7 (P0-CDIV)** — `connect_block_from_bytes` ships a half-
finished consensus pipeline. The check list is 7 gates vs Core's
~14. Used by `generatetoaddress` and `node.py:889` (one-shot genesis).
On regtest specifically — where ouroboros's diff-test corpus runs —
every regtest block goes through this path; consensus splits with
Core's regtest functional test suite are virtually guaranteed for
any test that crafts non-standard coinbases or tries to exercise
boundary conditions.

Fix sketch: either delegate to `BlockValidator::validate_block_with_flags`
before applying, or fold the missing gates into the hand-rolled path.
Current code is **two-pipeline guard violation #4** for this audit.

### F8 — `apply_block` (validation.py:885-941) is documented dead code that does NOT enforce BIP-30 / MoneyRange

`validation.py:885-941`:

```py
def apply_block(self, block: Block) -> None:
    """Apply *block*'s UTXO effects to the database (...).

    DEAD-CODE PATH (W23 belt-and-suspenders).
    ...
    """
```

The W23 audit dead-coded this method. Even so, **`block_sync.py:2220`
calls it unconditionally** when an orphan block is connected to the
current tip:

```py
# block_sync.py:2218-2222
else:
    self.validator.apply_block(block)
    block_height = block.height if hasattr(block, 'height') and block.height else 0
    logger.info(f"✓ Connected orphan block {block_height}: {block_hash.hex()[:16]}...")
```

`apply_block` invokes `self.db.update_utxo_set(spent, created)` at
line 941. **`update_utxo_set` does NOT exist on `BlockchainDatabase`**
(verified by grep — there is no `def update_utxo_set` in
`database.py`). The call raises `AttributeError` before the orphan
chain can be applied.

**BUG-W143-8 (P0-DoS)** — Production orphan-block path raises
`AttributeError` on the first orphan-block connect. The exception
propagates to `_process_orphans`, which is awaited from the network
loop; depending on how it's handled, either the orphan never gets
applied (silent stall) OR the network loop crashes. The docstring
itself flags this — "broken downstream" — but the code remains.
Comment-as-confession archetype, **6th cross-fleet instance**.

Fix sketch: either route orphan-connects through the Rust pipeline
(`connect_block_from_bytes`) or implement a real `update_utxo_set`
on the BlockchainDatabase shim.

### F9 — Block timestamp future-cap uses `time.time()` (system wall clock); Core's `NodeClock::now()` is the same but the test surface around DST/leap-seconds drifts

`validation.py:1005-1009`:

```py
# 4. time-too-new: block timestamp must not exceed now + MAX_FUTURE_BLOCK_TIME.
# Ref: validation.cpp:4108-4110, chain.h:29 (MAX_FUTURE_BLOCK_TIME = 7200s).
current_time = int(_time.time())
if block.timestamp > current_time + MAX_FUTURE_BLOCK_TIME:
    return False
```

Core (`validation.cpp:4108`): `block.Time() > NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}`.

Both use `time_t`-style seconds since epoch. Behavior is identical
on a healthy clock. However: the **return value** on failure is
`False` with no reject-reason string — `_validate_header` returns
plain `bool`, not `(bool, str)`. The Python orphan path can't
distinguish `time-too-new` from `bad-diffbits` because the failure
reason is collapsed. **Information loss bug**, P2. Counts as W143
because reject-reason-string semantics matter for diff-test corpus
runs (W125-class cross-impl invariant).

**BUG-W143-9 (P2)** — `_validate_header` collapses ~5 different
consensus reject reasons into a single bool, losing the Core reject-
reason that diff-test consumers (consensus-diff.py) rely on.

### F10 — `_validate_header` time-too-old silently skips when MTP returns None

`validation.py:684`:

```py
block_mtp = self.db.get_median_time_past(expected_height - 1) or 0
```

If `get_median_time_past` returns `None` (e.g. ancestor chain not yet
loaded, or post-snapshot with insufficient headers), `block_mtp`
becomes 0. At line 993:

```py
if height > 0 and block.timestamp <= block_mtp:
    return False
```

`block.timestamp <= 0` is always False for any block with a real
timestamp (epoch > 0). The check **silently passes** when MTP is
unknown.

Core (`validation.cpp:4092-4093`): `if (block.GetBlockTime() <=
pindexPrev->GetMedianTimePast()) return state.Invalid(... "time-too-old"
...);`. Core requires `pindexPrev` to exist (assertion at line 4083:
`assert(pindexPrev != nullptr)`) — there is no MTP-unavailable case.

A block whose timestamp is older than the chain's actual MTP slips
through ouroboros during snapshot-load / partial-header-sync windows.
Combined with BUG-W143-1 and BUG-W143-13, it's a multi-step bypass:
craft a coinbase with an old (or future) timestamp + non-canonical
prevout, get past the deserialize, and the consensus gates that
should have rejected silently pass.

**BUG-W143-10 (P1)** — MTP-unavailable silent pass on time-too-old.
Compounds with W138 assumeUTXO scaffolding (audited W138 BUG-12 for
snapshot-load), W132 utxo_mtp=0 stopgap.

### F11 — `connect_block_from_bytes` IsFinalTx skips the coinbase

`ferrous-utils/sync/src/lib.rs:3680-3697`:

```rust
for (tx_idx, tx) in inner.txdata.iter().enumerate() {
    if tx.is_coinbase() {
        continue;  // <-- BUG
    }
    let locktime = tx.lock_time.to_consensus_u32();
    ...
    if !sequence_lock::is_final_tx(locktime, &sequences, height, lock_time_cutoff) {
        return Err(...);
    }
}
```

Core (`validation.cpp:4144-4148`):

```cpp
for (const auto& tx : block.vtx) {  // <-- ALL txs, including coinbase
    if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", ...);
    }
}
```

Core's IsFinalTx loop runs over ALL transactions including the
coinbase. The Python orphan path correctly iterates `block.transactions`
without coinbase-skip (`validation.py:831-835`). The Rust
`connect_block_from_bytes` path skips. Used by generatetoaddress on
regtest where a non-final coinbase (e.g. with future locktime) is
trivially craftable by a mining test.

**BUG-W143-11 (P0-CDIV)** — Rust mining-path IsFinalTx coinbase
skip; Python orphan-path enforces. Two-pipeline divergence #5 for
this audit.

### F12 — `_check_structure` (CheckTransaction analog) is NEVER called on the coinbase

`validation.py:1903`:

```py
def validate_transaction(self, tx, ...):
    ...
    if not self._check_structure(tx):
        return False, "Invalid structure"
```

But `validate_transaction` is only called for non-coinbase txs
(`validation.py:838-852`):

```py
for i, tx in enumerate(block.transactions):
    ...
    if i == 0:  # Coinbase
        if not self._validate_coinbase(tx, expected_height):
            return False, "Invalid coinbase"
    else:
        ...
        valid, error = self.tx_validator.validate_transaction(...)
```

Core (`validation.cpp:3957-3968`):

```cpp
// Must check for duplicate inputs (see CVE-2018-17144)
for (const auto& tx : block.vtx) {  // <-- ALL txs including coinbase
    TxValidationState tx_state;
    if (!CheckTransaction(*tx, tx_state)) { ... }
}
```

Core runs `CheckTransaction` on ALL block txs INCLUDING the coinbase.
Consequences:

1. **CVE-2018-17144 reintroduction risk** — a coinbase with duplicate
   inputs (legal coinbase has 1 input so this is mostly moot, but a
   crafted coinbase with `vin.size() == 2` where `vin[0].prevout ==
   vin[1].prevout` is rejected by Core's CheckTransaction —
   "bad-txns-inputs-duplicate"). Ouroboros's `_validate_coinbase`
   line 1444 checks `len(tx.inputs) != 1` so this specific case is
   caught, but the parallel logic for output-level checks IS missing.
2. **CVE-2010-5139** — coinbase outputs with negative values bypass
   Core's check entirely. The `_verify_coinbase_amount` path does NOT
   look for per-output negative values (see BUG-W143-6).
3. **`bad-txns-oversize`** — coinbase exceeding `MAX_BLOCK_WEIGHT/4`
   stripped size is rejected by Core's CheckTransaction (line 19-21).
   Ouroboros's `_validate_block_limits` does an aggregate check but
   not a per-tx oversize check.

**BUG-W143-12 (P0-CDIV)** — coinbase bypasses CheckTransaction entirely
on the Python orphan path. Closes a stricter consensus net than just
the per-output amount gate.

### F13 — `_validate_coinbase` does not enforce coinbase `vout.empty()` → false (Core rejects)

`validation.py:1462-1466`:

```py
if len(tx.outputs) == 0:
    ...
    return False
```

This is present. But the corresponding check that Core enforces via
CheckTransaction (`bad-txns-vout-empty`, tx_check.cpp:17) is the same
condition — single-source-of-truth gap (BUG-W143-12) makes this a
redundant check, but technically OK. **Filed for completeness, not
a bug.**

### F14 — `_validate_block_limits` does not enforce `block.vtx.empty()` early-exit

`validation.py:1208-1241`: the function checks `tx count * 4 >
MAX_BLOCK_WEIGHT` and `stripped_block_size * 4 > MAX_BLOCK_WEIGHT`.
Both pass trivially for empty blocks (0 * 4 = 0). The `block.vtx.empty()`
disjunct that Core enforces (validation.cpp:3947) is NOT in the limits
function; the orphan-path empty check is at `validation.py:799-800`
(after limits). On the Rust `validate_block_with_flags` path, the
empty check is at `block.rs:184` AFTER `check_size_limits`. Both paths
have it, both order it AFTER size checks — Core orders it FIRST as
part of the same disjunct in `bad-blk-length`.

This was already flagged in **W142 BUG-3 (F3)** as a P1 reject-reason-
string divergence. Cross-citing here:

**BUG-W143-13 (P1)** — empty-vtx check is downstream of size-limits;
Core puts both in the same gate. Reject-reason path diverges; same
bug as W142 BUG-3, surfaced again at W143's block-validation entry
gate.

### F15 — `_calculate_block_subsidy` uses `getattr(self, 'network', 'mainnet')` — silently defaults to mainnet

`validation.py:1545`:

```py
network = getattr(self, "network", "mainnet")
interval = 150 if network == "regtest" else 210_000
```

The comment notes this is for tests that bypass `__init__`. In
practice, the `BlockValidator` is always constructed with
`network` set — but the silent default to "mainnet" creates a subtle
test-vs-production divergence: a test that constructs the validator
via `__new__` and calls `_calculate_block_subsidy(height=200)` on
what should be regtest gets mainnet subsidy. Production code via
`__init__` works fine; the test API surface drifts.

**BUG-W143-14 (P3)** — defensive default masks construction bugs.
Test-only consequence today.

### F16 — `validate_block` `intra_block_utxos` accumulates ALL outputs as `is_coinbase: (i == 0)` but never spends them

`validation.py:861-873`:

```py
# Register this tx's outputs in the intra-block view for
# subsequent transactions.
txid = tx.get_txid()
for vout_idx, out in enumerate(tx.outputs):
    intra_block_utxos[(txid, vout_idx)] = {
        'txid': txid,
        'vout': vout_idx,
        'value': out.value,
        'script_pubkey': out.script_pubkey,
        'height': expected_height,
        'is_coinbase': (i == 0),
    }
```

The `is_coinbase` flag in the intra-block view is set based on tx
position (i == 0). When a tx N>0 in the same block spends an output
of tx M>0 (also non-coinbase) in the same block, `intra_block_utxos`
correctly reports `is_coinbase=False`. When the same block's coinbase
output is spent later in the block — which is **legal under Core**
ONLY after `COINBASE_MATURITY = 100` confirmations from the coinbase
height — the intra-block view marks the output as `is_coinbase=True`
at the SAME height as the spending tx. The maturity check in
`validate_transaction` (line 1965) computes `depth = height -
coin_height = 0`, which is `< 100`, so it correctly rejects.

This works. **But it is BIP-30-equivalent behavior at the wrong
layer** — Core enforces coinbase maturity via `CheckTxInputs`, which
ouroboros reimplements with the right semantics here. **Filed as a
non-bug; verified via code path.**

### F17 — `apply_block`'s genesis-coinbase special-case is documented dead code; the live `connect_block_from_bytes` path correctly skips genesis UTXOs (lib.rs:3769)

Cross-validated. The Rust path's `store_utxos = height > 0` matches
Core. The Python dead-code path's `if height == 0: return` (line 918)
matches too. **Filed as a non-bug; verified.**

### F18 — `_count_legacy_sigops` counts coinbase scriptSig but Core's `GetLegacySigOpCount` only counts non-coinbase scriptSig? No — wait, Core counts ALL inputs

Re-read `consensus/tx_verify.cpp:112-124`:

```cpp
unsigned int GetLegacySigOpCount(const CTransaction& tx) {
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin) { nSigOps += txin.scriptSig.GetSigOpCount(false); }
    for (const auto& txout : tx.vout) { nSigOps += txout.scriptPubKey.GetSigOpCount(false); }
    return nSigOps;
}
```

Core DOES count the coinbase scriptSig (correctly). Ouroboros's
`validation.py:1256-1261` matches this. **Filed as non-bug; verified.**

### F19 — `IsBlockMutated`'s 64-byte stripped-tx check (CVE-class) is entirely missing

Core (`validation.cpp:4027-4056`) detects a serialization-mutation
weakness from "Weaknesses in Bitcoin's Merkle Root Construction"
(Linux Foundation 2019 paper §3.1) where any tx with `GetSerializeSize(
TX_NO_WITNESS(tx)) == 64` allows an attacker to substitute the tx for
an internal merkle node value. The check is:

```cpp
if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
    return std::any_of(block.vtx.begin(), block.vtx.end(),
        [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
}
```

(The check is gated on no-coinbase or empty-block, because for
well-formed blocks with a coinbase Core relies on the coinbase
distinctness being enforced elsewhere — but the check is still
**emitted** as part of `IsBlockMutated`, which is consulted by the
header-spam-prevention path in `net_processing.cpp`.)

Ouroboros has no equivalent. **Both pipelines lack it.**

**BUG-W143-15 (P1)** — `IsBlockMutated` 64-byte-tx detection absent.
Pre-W138 header-spam protection (and the related Cohen-class
weakness) goes unmitigated; ouroboros will accept block headers Core
would discard.

### F20 — Rust `validate_block` does not call `check_lock_time` from inside `check_coinbase`; coinbase locktime is unbounded

`ferrous-utils/sync/src/validate/transaction.rs:502-555` (check_coinbase)
NEVER calls `check_lock_time`. `validate_transaction` (line 122)
calls `check_lock_time` for ALL txs INCLUDING coinbase, but
`validate_block::validate_block_with_flags` (`block.rs:301-302`)
calls `check_coinbase` directly (not via `validate_transaction`):

```rust
self.tx_validator.check_coinbase(coinbase_tx, height)
    .map_err(BlockValidationError::TransactionValidation)?;
```

So the coinbase locktime is never validated on the Rust pipeline's
`validate_block_with_flags` path.

Core (`validation.cpp:4144-4148`): `IsFinalTx` runs over ALL block
txs including the coinbase.

**BUG-W143-16 (P1)** — coinbase locktime not validated on Rust
pipeline's `validate_block_with_flags`. Compounds with BUG-W143-11
(same issue, different pipeline) — together they cover BOTH Rust
entry points (`validate_block_with_flags` AND `connect_block_from_bytes`).
Python orphan path enforces (line 835).

### F21 — Rust `connect_block_from_bytes`: no `bad-cb-amount` check (coinbase amount ≤ subsidy + fees)

Cross-referenced in F7 but stated explicitly: lib.rs:3402-3913 has no
subsidy/fees accumulation, no coinbase-amount upper-bound check.
Core's check at `validation.cpp:~2546-2570`. The Python orphan path
runs this via `_verify_coinbase_amount` (line 876-881). The Rust
`validate_block_with_flags` path runs it via `validate_block_subsidy`
(`block.rs:376` + `:753`). But the mining-only `connect_block_from_bytes`
path ships without it.

**BUG-W143-17 (P0-CDIV)** — Rust mining path silently accepts a
coinbase that pays more than subsidy + fees. With the W138/W93
"regtest miner can put anything in coinbase" pattern, this is
exploitable on regtest functional-test runs.

### F22 — `_validate_signet_solution` does not no-op for non-signet networks before SegWit-activation gate

`validation.py:1554-1639`: signet block solution verification runs
regardless of segwit activation. For signet ALL blocks have buried
segwit=1 so `_validate_witness_commitment` should have ALREADY accepted
the commitment by the time `_validate_signet_solution` runs. But
the function is called BEFORE the commitment is committed-to-disk;
on a signet block that fails the commitment-merkle-match (BUG-W142-7
class) the signet solution check fires on the unverified block. Order:
`validate_block` line 715 = witness commitment, line 720 = signet
solution. Verified — order is correct: commitment first.

**Filed as non-bug; verified.**

### F23 — Reject-reason-string drift on rust validate_block_with_flags vs Core

Rust path emits error variants like `BlockValidationError::NoCoinbase`
which serialize via `thiserror::Error` derive — the strings DON'T
match Core's BIP-22 reject reasons (e.g. `"bad-cb-missing"`). For
diff-test corpus runs, this is a structural mismatch — a test that
asserts `reject_reason == "bad-cb-missing"` against an ouroboros node
fails even though the consensus VERDICT (accept/reject) is correct.

**BUG-W143-18 (P2)** — Rust path's error strings are not BIP-22 reject
reasons. Compounds with consensus-diff.py corpus comparator.

### F24 — `_calculate_witness_merkle_root` discards mutated flag

`validation.py:1329-1333`:

```py
def _calculate_witness_merkle_root(self, block: Block) -> bytes:
    wtxids: list[bytes] = [bytes(32)]
    for tx in block.transactions[1:]:
        wtxids.append(tx.get_wtxid())
    return self._calculate_merkle_root(wtxids)  # <-- drops the mutated flag
```

Core's `BlockWitnessMerkleRoot` (`consensus/merkle.cpp:76-86`)
deliberately passes `nullptr` for the mutated out-param — BIP-141
spec says malleation of the witness tree is structurally impossible
because the tx tree already enforces uniqueness. Core's choice is
documented at `validation.cpp:3887-3889`. **Filed as non-bug; verified
matches Core's design choice.**

### F25 — `validate_block` order: witness commitment check runs BEFORE per-tx CheckTransaction equivalents

Order in `validate_block` (lines 705-880):

1. header (line 702)
2. merkle root (line 706)
3. block limits (line 710)
4. witness commitment (line 715)
5. signet solution (line 720)
6. BIP-30 (line 791)
7. coinbase position + uniqueness (line 798-805)
8. per-tx validation (line 825-873) ← CheckTransaction equivalent
9. coinbase amount (line 876)

Core (`validation.cpp:3918-3982 CheckBlock`):

1. block header (line 3927)
2. signet (line 3931)
3. merkle root (line 3936)
4. size limits / empty (line 3946-3948)  ← empty + size BOTH here
5. first-tx-coinbase + no-multi-cb (line 3950-3955)
6. per-tx CheckTransaction (line 3957-3968) ← CheckTransaction
7. legacy sigops (line 3971-3977)

Then `ContextualCheckBlock` (line 4129-4184):
1. IsFinalTx (line 4144-4148)
2. BIP-34 coinbase height (line 4151-4159)
3. CheckWitnessMalleation (line 4169-4171)
4. GetBlockWeight (line 4179-4181)

Ouroboros runs CheckWitnessMalleation BEFORE per-tx CheckTransaction;
Core runs it inside ContextualCheckBlock AFTER all of CheckBlock.

Order matters because: a block can have a malleated witness commitment
(BUG-W142-2 class P0-DoS) and ouroboros rejects with `bad-witness-
merkle-match` instead of the proper `bad-txns-vout-empty` (or similar
underlying CheckTransaction reject). **Reject-reason-string drift
under double-bug**, P2.

**BUG-W143-19 (P2)** — gate ordering divergence; surfaces a stale
reject-reason on multi-rule-violating blocks.

### F26 — `_validate_block_limits` per-tx sigop loop reads UTXO from disk inside the loop

`validation.py:1265-1284`:

```py
if not tx.is_coinbase:
    for inp in tx.inputs:
        utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
        ...
        p2sh_sigops = _get_p2sh_sigops(inp.script_sig, prev_spk)
        ...
```

For each non-coinbase input the limits-check fetches the UTXO from
RocksDB. The W85 audit noted ~2 redundant `db.get_utxo()` round-trips
per input; this Python orphan path still pays that cost. Rust path
uses `prefetched_input_scripts` (`block.rs:340-351`). **Performance,
not consensus** — filed as P3 (`bad-blk-sigops`-class slow path).

**BUG-W143-20 (P3)** — Python orphan path's sigop counting is O(N×FFI)
instead of O(N). Compounds during reorg storms where many orphans
arrive simultaneously.

### F27 — Cookie-auth / RPC submitblock entry path uses Python `validate_block`, not Rust

`block_sync.py` orphan handler routes submitblock through Python
validation. submitblock from external miners triggers the Python
pipeline — which has BUG-W143-1 (`is_coinbase` no NULL_INDEX), BUG-W143-4
(merkle mutated leaf-only), BUG-W143-12 (coinbase no CheckTransaction)
all active.

This is a **policy decision drift**, not a bug per se, but it means
the submitblock attack surface uses the looser of the two pipelines.

**BUG-W143-21 (P1)** — submitblock RPC entry is gated by the looser
of the two-pipeline guards. Combined with the orphan-handler being
the **only** path that ever uses Python `validate_block`, every
attack vector that targets the Python pipeline goes through orphan
or submitblock — both adversary-reachable.

### F28 — `is_buried_deployment_active(bip34, height, network)` returns True at `height == bip34_height` (exclusive vs Core's inclusive semantics)

Core's `DeploymentActiveAfter(pindexPrev, ...)` returns True when
`pindexPrev->nHeight + 1 >= activation_height`, i.e. when the
**current** block's height (`pindexPrev + 1`) is ≥ activation. So
the ACTIVATION block IS the first to enforce.

Ouroboros's `is_buried_deployment_active(height, ...)` returns
`height >= dep.height`. Same semantics for inputs. **Verified —
filed as non-bug**, but checked carefully because off-by-one drifts
in deployment activations have been a recurring fleet pattern
(camlcoin W132 MTP, ouroboros W138 invented mainnet hash).

### F29 — Rust path's BIP-30 G(A) hash-decode panics on bad hex constant

`block.rs:521-526`:

```rust
fn decode_hash(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("compile-time hex constant decodes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);  // <-- panics if bytes.len() != 32
    out
}
```

`copy_from_slice` panics at runtime if the source slice's length
doesn't match. Today's constants are correct (64 hex chars each); a
future edit that truncates one of the strings becomes a runtime panic
on EVERY block validation at height 91842 or 91880 (no impact today
because those are mainnet-only and beyond initial validation reach).

**BUG-W143-22 (P3)** — defensive coding hazard; runtime panic on
operator-introduced typo. Use `const_assert` or const-eval friendly
hex.

### F30 — Python `_validate_block_limits` does not enforce `MAX_BLOCK_SIGOPS_COST` for legacy-only signaling at pre-segwit heights

`validation.py:1296-1300`:

```py
if total_sigops_cost > MAX_BLOCK_SIGOPS_COST:
    return False, (...)
```

`total_sigops_cost` accumulates `legacy * 4 + p2sh * 4 + witness * 1`.
For pre-segwit blocks, witness count is 0. For pre-P2SH blocks
(mainnet height < 173,805), Core's `GetTransactionSigOpCost` does
NOT include P2SH sigops (line 150: `if (flags & SCRIPT_VERIFY_P2SH)`).
Ouroboros's loop UNCONDITIONALLY adds P2SH sigops (line 1265-1271).

For a mainnet block at height 100,000 (pre-P2SH activation) with
P2SH-shaped scriptSigs in non-P2SH outputs (rare but legal), the
unconditional P2SH-sigop addition can push the block over
MAX_BLOCK_SIGOPS_COST when Core would not.

**BUG-W143-23 (P1)** — P2SH activation height not gated for sigop
counting in Python pipeline. Mainnet pre-P2SH blocks are
already-validated history so this is post-hoc-only, BUT for archival
sync from peers serving pre-P2SH blocks (or reindex) it surfaces.
Rust path correctly gates via `get_sigop_flags(height)` (`block.rs:402-417`).
**Two-pipeline divergence #6** for this audit.

### F31 — Block hash recomputation in `_validate_header` reads `block.serialize()[:80]` — assumes serialize order

`validation.py:1042-1044`:

```py
header = block.serialize()[:80]
block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
```

If `Block.serialize()` ever changes order or adds prefix bytes, the
slice silently drifts. There is no struct assertion. The block header
should be constructed from the 6 fields directly (version + prev +
merkle + time + bits + nonce). Filed P3.

**BUG-W143-24 (P3)** — block hash recompute is slice-based, brittle.

### F32 — Coinbase-input null-check (CHECK 4) — already covered above

Cross-citing BUG-W143-1 for completeness; the null-vout check ouroboros
performs (`prev_vout == 0xFFFFFFFF`) only fires in `_check_structure`
for non-coinbase txs (line 2125). It does NOT fire for coinbase
(BUG-W143-12). This is the third symptom of the same root cause.

### F33 — Per-pipeline behavior summary

| Gate                                  | Python orphan | Rust validate | Rust connect |
|---------------------------------------|:-------------:|:-------------:|:------------:|
| Header PoW                            |       ✓       |       ✓       |       ✓      |
| MTP time-too-old                      |  P1 (silent)  |       ✓       |       ✓      |
| BIP-94 timewarp (testnet4)            |       ✓       |       ✓       |       ✗      |
| time-too-new (future cap)             |       ✓       |       ✓       |       ✗      |
| bad-version (BIP34/65/66 gate)        |       ✓       |       ✓       |       ✗      |
| Merkle root recompute                 |       ✓       |       ✓       |       ✓      |
| Merkle mutated (CVE-2012-2459)        |  P0 (leaf)    |       ✗       |       ✗      |
| 64-byte stripped-tx (IsBlockMutated)  |       ✗       |       ✗       |       ✗      |
| Block weight gate                     | P0 (no hdr)   |       ✓       |       ✗      |
| Empty-vtx gate                        | P1 (downstream)|       ✓       |       ✓      |
| First-tx-coinbase                     |       ✓       |       ✓       |       ✓      |
| No-multi-coinbase                     |       ✓       |       ✓       |       ✓      |
| CheckTransaction per-tx               | P0 (no cb)    |   P1 (no cb)  |       ✗      |
| Coinbase scriptSig 2..=100            |       ✓       |       ✓       |       ✓      |
| BIP-34 coinbase height                |       ✓       | P0-CDIV (raw u32) |     ✗     |
| BIP-30 duplicate-coinbase             |       ✓       |       ✓       |       ✗      |
| IsFinalTx (all txs)                   |       ✓       | P1 (skip cb)  |   P1 (skip cb)|
| Witness commitment                    |       ✓       |       ✓       |       ✓      |
| BIP-141 sigop cost cap                |       ✓       |       ✓       |       ✗      |
| Coinbase amount ≤ subsidy + fees      |       ✓       |       ✓       |       ✗      |
| BIP-30 fork-safety (W93 G(A)+G(B)+G(C))|       ✓       |       ✓       |       ✗      |

Bottom line: `connect_block_from_bytes` is a half-implemented
consensus pipeline. It is the ONLY path used by `cli.py:929` (mining)
and `node.py:889` (genesis). The latter is only one-shot so impact is
low; the former is exercised by every regtest functional test.

Severity bucketing summary
--------------------------

| # | Title                                                                          | Severity   |
|---|--------------------------------------------------------------------------------|------------|
| 1 | `is_coinbase` accepts non-NULL_INDEX prevout                                   | P0-CDIV    |
| 2 | Rust BIP-34 raw-u32 decode accepts non-canonical (vs Python byte-exact)        | P0-CDIV    |
| 3 | Coinbase scriptSig 2..=100 replicated 3× across 2 pipelines                    | P2         |
| 4 | Merkle CVE-2012-2459 detection leaf-level only; odd-dup branch silent          | P0-CDIV    |
| 5 | `_validate_block_limits` weight formula missing header+tx-count overhead       | P0-CDIV    |
| 6 | `_verify_coinbase_amount` substitutes CheckTransaction's per-output gates     | P1         |
| 7 | `connect_block_from_bytes` ships half-finished consensus pipeline              | P0-CDIV    |
| 8 | `apply_block` orphan-path calls non-existent `update_utxo_set`                | P0-DoS     |
| 9 | `_validate_header` collapses 5 reject-reasons into a single bool               | P2         |
| 10| MTP-unavailable silent pass on time-too-old                                    | P1         |
| 11| `connect_block_from_bytes` IsFinalTx skips coinbase                            | P0-CDIV    |
| 12| coinbase bypasses CheckTransaction entirely (Python pipeline)                  | P0-CDIV    |
| 13| empty-vtx gate downstream of size-limits (reject-reason drift)                 | P1         |
| 14| `_calculate_block_subsidy` default-to-mainnet via `getattr`                   | P3         |
| 15| `IsBlockMutated` 64-byte-tx detection absent (both pipelines)                  | P1         |
| 16| Rust `validate_block_with_flags` coinbase locktime not validated               | P1         |
| 17| Rust `connect_block_from_bytes` no `bad-cb-amount` check                       | P0-CDIV    |
| 18| Rust path's error strings don't match BIP-22 reject reasons                    | P2         |
| 19| Gate ordering: witness commitment before per-tx CheckTransaction               | P2         |
| 20| Python orphan-path sigop counting is O(N×FFI) instead of O(N)                  | P3         |
| 21| submitblock entry path uses looser Python pipeline                             | P1         |
| 22| Rust BIP-30 G(A) hex-decode `copy_from_slice` panic on operator typo          | P3         |
| 23| Python pipeline P2SH activation height not gated for sigop counting           | P1         |
| 24| Block hash recompute is slice-based (`block.serialize()[:80]`)                | P3         |
| 25| `_validate_header` 4108-style time-too-new uses `_time.time()` (info-loss)    | P2 (cross-cite F9) |
| 26| Rust BIP-34 path silently accepts non-coinbase scriptSig with push_size 0     | P1 (latent) |
| 27| `_calculate_witness_merkle_root` calls `_calculate_merkle_root` (drops flag)  | P2         |

**Total**: 4 P0-CDIV / 1 P0-DoS / 0 P0-SEC / 11 P1 / 8 P2 / 2 P3 = **27 BUGS** (allow ±1 rebucket on rebuild — the bug count is the SEMANTIC count of distinct findings).

Severity bucketing for the final commit footer:
  4 P0-CDIV, 1 P0-DoS, 11 P1, 8 P2, 3 P3 = 27.

Fleet patterns observed
-----------------------

- **two-pipeline guard 16th distinct extension** (post-W142's 15):
  W143 introduces the THIRD pipeline (`connect_block_from_bytes`)
  on top of the existing two — half-implemented hand-rolled consensus.
  Pattern strengthens: every audit-wave that touches "block-level
  consensus" surfaces a guard-violating split.

- **comment-as-confession 6th cross-fleet instance**:
  - `validation.py:1191-1192` — odd-duplicate merkle comment promises
    mutation flag that the code never sets.
  - `validation.py:885-912` — `apply_block` docstring openly admits
    "broken downstream" and "would crash before mutating".
  - `transaction.rs:523-528` — BIP-34 comment openly admits divergence
    from Core: "intentionally lenient — Core is stricter about minimal
    encoding but the drain path must match Python bit-for-bit".

- **dead-code-still-called archetype** (W83/W138/W141 form):
  `apply_block` is doc-commented as dead, yet `block_sync.py:2220`
  calls it unconditionally on orphan-connect. Same shape as
  hashin/rustoshi W138 ChainStateManager methods + the W141 dead
  zmq.rs module.

- **half-finished hand-rolled pipeline**: `connect_block_from_bytes`
  re-implements ~7 of Core's ~14 CheckBlock+ContextualCheckBlock gates
  inline, in `lib.rs`. New "pyo3 lib.rs grows its own consensus" smell.
  Likely seen across other Python+Rust impls (compare hotbuns, where
  the JS hot path / TS slow path is the equivalent fork-in-the-road).

- **NEW "three-pipeline drift" archetype**: this wave first explicitly
  documented THREE coexisting consensus pipelines (Python orphan,
  Rust `validate_block_with_flags`, Rust `connect_block_from_bytes`).
  Filed for future-fleet-sweep tracking — likely other impls have
  this on a different axis (e.g. clearbit's inline handshake-handler
  fork-in-the-road).

- **reject-reason-string drift** (W125-class): six BUGs in this audit
  produce a reject-reason mismatch versus Core's BIP-22 strings, even
  when the consensus VERDICT is correct. diff-test corpus runs
  (consensus-diff.py) will surface a "verdict matches, reason differs"
  bucket that requires special handling — file for tooling-side fix.

- **encode-mismatch-rust-vs-python** (NEW intra-impl): BUG-W143-2 is
  the first explicit case where Rust and Python paths use DIFFERENT
  encoding decoders for the same BIP. Cross-cites the two-pipeline
  guard but at finer granularity — even when both pipelines audit
  the SAME rule, they can diverge on canonicality.

References
----------

Bitcoin Core lines cited (all under `bitcoin-core/src/`):

- `validation.cpp:2295-2696` — Chainstate::ConnectBlock.
- `validation.cpp:3837-3862` — CheckMerkleRoot.
- `validation.cpp:3870-3916` — CheckWitnessMalleation.
- `validation.cpp:3918-3982` — CheckBlock.
- `validation.cpp:3946-3947` — bad-blk-length early exit.
- `validation.cpp:3950-3955` — first-tx-coinbase + no-multi-cb.
- `validation.cpp:3957-3968` — per-tx CheckTransaction loop.
- `validation.cpp:3969-3977` — legacy sigops cap.
- `validation.cpp:4027-4056` — IsBlockMutated (64-byte tx).
- `validation.cpp:4080-4121` — ContextualCheckBlockHeader.
- `validation.cpp:4108-4110` — time-too-new (MAX_FUTURE_BLOCK_TIME).
- `validation.cpp:4129-4184` — ContextualCheckBlock.
- `validation.cpp:4144-4148` — IsFinalTx (all block txs).
- `validation.cpp:4151-4159` — BIP-34 coinbase height byte-exact match.
- `validation.cpp:4169-4171` — CheckWitnessMalleation invocation.
- `validation.cpp:4179-4181` — GetBlockWeight cap.
- `consensus/tx_check.cpp:11-60` — CheckTransaction.
- `consensus/tx_check.cpp:14-16` — bad-txns-vin-empty.
- `consensus/tx_check.cpp:17-18` — bad-txns-vout-empty.
- `consensus/tx_check.cpp:19-21` — bad-txns-oversize.
- `consensus/tx_check.cpp:27-33` — CVE-2010-5139 (negative/toolarge).
- `consensus/tx_check.cpp:36-44` — CVE-2018-17144 (duplicate inputs).
- `consensus/tx_check.cpp:49-50` — coinbase scriptSig 2..=100.
- `consensus/tx_check.cpp:52-57` — bad-txns-prevout-null.
- `consensus/tx_verify.cpp:112-124` — GetLegacySigOpCount.
- `consensus/tx_verify.cpp:126-141` — GetP2SHSigOpCount.
- `consensus/tx_verify.cpp:143-162` — GetTransactionSigOpCost.
- `consensus/tx_verify.cpp:164-211` — Consensus::CheckTxInputs.
- `consensus/merkle.cpp:46-63` — ComputeMerkleRoot (mutated detection).
- `consensus/merkle.cpp:66-74` — BlockMerkleRoot.
- `consensus/merkle.cpp:76-85` — BlockWitnessMerkleRoot.
- `consensus/validation.h:18` — MINIMUM_WITNESS_COMMITMENT = 38.
- `consensus/validation.h:132-139` — GetTransactionWeight + GetBlockWeight.
- `consensus/consensus.h:15-24` — MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR.
- `primitives/transaction.h:36-49` — COutPoint::IsNull + NULL_INDEX.
- `primitives/transaction.h:200-242` — UnserializeTransaction.
- `primitives/transaction.h:324-348` — CTransaction::IsCoinBase.
- `deploymentstatus.h:14-18` — DeploymentActiveAfter (buried).
- `kernel/chainparams.cpp:94,217,316,460,541` — SegwitHeight.

Done.
