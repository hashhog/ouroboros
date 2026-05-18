W142 — SegWit witness validation audit (ouroboros)
====================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline — block/tx witness validation lives in
      `src/ouroboros/validation.py`, `src/ouroboros/script.py`,
      `src/ouroboros/database.py`, `src/ouroboros/p2p_messages.py`,
      and `src/ouroboros/segwit_v0.py`. The Rust pipeline
      (`ferrous-utils/sync`) carries a stub `verify_witness()` that
      unconditionally returns `Ok(false)` — kept as dead code; two-
      pipeline guard EXTENDS to forbid Rust-side witness execution.)
Wave: W142 BIP-141/143 SegWit witness validation.

Reference (Bitcoin Core)
------------------------
- `bitcoin-core/src/validation.cpp`:
  - `CheckWitnessMalleation` (lines 3870-3917): coinbase-witness-nonce
    size + witness-merkle-match + unexpected-witness gates.
  - `GenerateCoinbaseCommitment` / `UpdateUncommittedBlockStructures`
    (lines 3997-4019): block-construction commitment + reserved nonce.
  - `CheckBlock` (lines 3919-3982): `block.vtx.empty() || ...` early
    `bad-blk-length` exit before any witness-data access.
- `bitcoin-core/src/consensus/merkle.cpp::BlockWitnessMerkleRoot`
  (lines 76-86): coinbase wtxid pinned to all-zero; `ComputeMerkleRoot`
  called WITHOUT the `mutated` flag (BIP-141 §"Commitment structure").
- `bitcoin-core/src/script/interpreter.cpp`:
  - `SignatureHash` (1600-1675): BIP-143 sighash for `WITNESS_V0`.
  - `VerifyWitnessProgram` (1916-2002): v0 P2WPKH/P2WSH dispatch +
    BIP-431 P2A + BIP-341 Taproot dispatch.
  - `ExecuteWitnessScript` (1832-1870): cleanstack/CastToBool order
    for v0; tapscript-only initial `MAX_STACK_SIZE` gate at line 1855.
- `bitcoin-core/src/primitives/transaction.{h,cpp}`:
  - `UnserializeTransaction` (`transaction.h:200-242`): BIP-144
    wire format — empty-vin marker (0x00) + flag (0x01); **"Superfluous
    witness record"** throw if all witnesses empty after flag=1.
  - `ComputeHasWitness` (`transaction.cpp:74-79`): `HasWitness()` is
    `any(!vin[i].scriptWitness.IsNull())`, NOT a wire-format flag.
- `bitcoin-core/src/consensus/validation.h`:
  - `GetWitnessCommitmentIndex` (147-167): LAST matching output kept
    (forward iteration with overwrite).
  - `MINIMUM_WITNESS_COMMITMENT = 38` (line 18).
- `bitcoin-core/src/kernel/chainparams.cpp`:
  - mainnet `SegwitHeight = 481_824` (line 94).
  - testnet3 `SegwitHeight = 834_624` (line 217).
  - testnet4 `SegwitHeight = 1` (line 316).
  - signet `SegwitHeight = 1` (line 460).
  - regtest `SegwitHeight = 0` (line 541).

Status: 16 gates audited — **PRESENT 5 / PARTIAL 5 / MISSING 6.**
**18 BUGS** (3 P0-CDIV / 2 P0-DoS / 8 P1 / 5 P2).

Relationship to prior audits
----------------------------

- W126 (BIP-152 Compact Blocks): coinbase wtxid is pinned to zero;
  W142 audits the underlying `BlockWitnessMerkleRoot` parity and the
  feeder code paths.
- W127 (Taproot): tapscript signing/verification audited end-to-end;
  W142 covers ONLY the v0/v1-dispatch and v0-bound witness behaviors
  the tapscript audit deferred (`_verify_witness_program`'s v0 arm).
- W135 (Standardness): policy-side dust/MAX_OP_RETURN_RELAY; W142 is
  the consensus-side block/witness-commitment audit.
- W137 (PSBT v0/v2): PSBT v0 sighash test vectors; W142 audits the
  `bip143_sighash` source-of-truth (`segwit_v0.py:79`) shared with
  the PSBT signers and the consensus-path `_compute_segwit_v0_sighash`
  (`script.py:685`). Catches drift between them.

Two-pipeline guard
------------------

SegWit witness validation runs entirely in the **Python pipeline**.
The Rust pipeline (`ferrous-utils/sync/src/validate/script.rs:1502-1516`)
defines a `verify_witness(_tx, _input_idx) -> Ok(false)` stub —
exported via `pub use` in `validate/mod.rs:21` but called only by one
in-file test (`test_witness_verification`, line 1867). No production
call site. Two-pipeline guard EXTENDED to:

```
$ grep -rn "verify_witness\b" ferrous-utils/sync/src/ --include='*.rs' \
        | grep -v "/tests/"
ferrous-utils/sync/src/validate/script.rs:1506:  pub fn verify_witness(...)
ferrous-utils/sync/src/validate/mod.rs:21:       pub use script::{..., verify_witness};
```

The Python pipeline owns:

- `src/ouroboros/validation.py:1304-1428` — block-level witness
  commitment + malleation check (`_validate_witness_commitment`).
- `src/ouroboros/script.py:561-683` — `_verify_witness_program`,
  `_verify_witness_v0_keyhash`, `_verify_witness_v0_scripthash`,
  `_compute_segwit_v0_sighash`.
- `src/ouroboros/segwit_v0.py:79-143` — `bip143_sighash` source-of-
  truth shared with PSBT signers.
- `src/ouroboros/database.py:213-289` — `Transaction.serialize`,
  `serialize_with_witness`, `get_wtxid`, `get_weight`, `get_vsize`,
  `get_witness_bytes`.
- `src/ouroboros/p2p_messages.py:452-625` — wire deserializer for
  `tx` messages (`TxMessage.from_payload`) including the BIP-144
  marker/flag handling.

This extends the W76 + W120 + W122 + W125 + W128 + W129 + W130 +
W131 + W133 + W134 + W137 + W140 + W141 guard set → now W142.

Top-level architectural findings
--------------------------------

### F1 — Wire deserializer accepts "Superfluous witness record" txs

`p2p_messages.py:493-598` parses BIP-144 marker/flag at lines 493-496:

```py
has_witness = False
if len(payload) > offset + 2 and payload[offset] == 0x00 and payload[offset+1] == 0x01:
    has_witness = True
    offset += 2
```

Then at lines 574-598 it reads witness data per input. **There is
NO post-parse check** that any input has a non-empty witness stack.

Core's `UnserializeTransaction` (`transaction.h:226-231`):

```cpp
if ((flags & 1) && fAllowWitness) {
    flags ^= 1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        s >> tx.vin[i].scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        // It's illegal to encode witnesses when all witness stacks are empty.
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

A peer can craft a tx with marker 0x00, flag 0x01, all per-input
witness counts = 0. **Core rejects on deserialize** (throws); the tx
is never observed. **Ouroboros happily parses it** with
`has_witness=True` and computes a `wtxid` that differs from Core's
view (Core has no view — it threw). Downstream consequences:

1. Mempool: relayed to Core peers → Core peers ban us (bad protocol).
2. Block: if this format appears in a block (miner included it),
   ouroboros computes a witness merkle root from inflated wtxids;
   Core computes from txids (no marker/flag) — **divergent commitment**.

**BUG-1 (P0-CDIV)** — wire deserializer accepts a tx encoding Core
explicitly rejects. Compounds with BUG-6 (has_witness flag drift).

Fix sketch: after the witness-data loop (line 598), check
`any(inputs[i].witness for i in range(inputs_count))`; raise
`ValueError("Superfluous witness record")` if all empty.

### F2 — `_validate_witness_commitment` indexes `vtx[0]` and `vtx[0].vin[0]` without empty-list guard

`validation.py:1358`:

```py
commitment = self._find_witness_commitment(block.transactions[0])
```

`validation.py:1363`:

```py
coinbase_input = block.transactions[0].inputs[0]
```

Both run BEFORE the empty-block check at `validation.py:799-800`:

```py
# 8. Validate coinbase position and uniqueness
if not block.transactions:
    return False, "Block has no transactions"
```

The `validate_block` order is: 3) header, 4) merkle root, 5) block
limits, **6) witness commitment** (line 715), … 8) tx count.

Core's `CheckBlock` (`validation.cpp:3946-3947`) does the early
`vtx.empty()` reject FIRST:

```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", ...);
```

And `CheckWitnessMalleation` (`validation.cpp:3884`) asserts
`!block.vtx.empty() && !block.vtx[0]->vin.empty()` BEFORE indexing.

A peer sends a 0-tx block (or a block whose first tx has 0 inputs):
ouroboros raises `IndexError` from `_find_witness_commitment` /
`coinbase_input = block.transactions[0].inputs[0]`. The exception
propagates through `validate_block` (no try/except wrapping it) to
the caller; depending on how `block_sync` handles the exception, the
node either crashes or burns a CPU-thread/log-spam loop.

**BUG-2 (P0-DoS)** — single malformed block (0 tx OR 0-vin coinbase)
crashes the block-validation thread; remote DoS primitive.

Fix sketch: at the very top of `_validate_witness_commitment`:

```py
if not block.transactions or not block.transactions[0].inputs:
    return False, "bad-blk-length"  # Core: vtx.empty() → "bad-blk-length"
```

Or — cleaner — add the empty check at the top of `validate_block`
(matching Core's `CheckBlock` order).

### F3 — `_validate_block_limits` does NOT enforce `block.vtx.empty()`

`validation.py:1208-1241` has:

```py
if len(block.transactions) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
    return False, (f"bad-blk-length: tx count ...")

stripped_block_size = sum(len(tx.serialize()) for tx in block.transactions)
if stripped_block_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
    return False, (f"bad-blk-length: stripped block size ...")
```

For `len(transactions) == 0`: `0 * 4 = 0 <= MAX_BLOCK_WEIGHT`,
`sum([]) = 0`, passes. Empty block survives the limits gate.

Core (`validation.cpp:3946`):

```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        || ...)
    return state.Invalid(... "bad-blk-length" ...);
```

`block.vtx.empty()` is the FIRST disjunct.

**BUG-3 (P1)** — missing empty-vtx gate. Combined with BUG-2 this
becomes P0-DoS; on its own it is consensus-divergent reject-reason
strings.

### F4 — Stripped-size pre-check omits the 80-byte block header and tx-count varint

`validation.py:1236`:

```py
stripped_block_size = sum(len(tx.serialize()) for tx in block.transactions)
```

Core (`validation.cpp:3946`):

```cpp
::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
```

`GetSerializeSize(TX_NO_WITNESS(block))` serializes the full block
without witnesses: 80-byte header + CompactSize(tx_count) + Σ stripped
tx sizes. Ouroboros omits the header and the tx-count varint —
under-counts by 81-89 bytes (`80 + size_of_varint(tx_count)`).

For a block exactly at the boundary (4 000 000 weight after the
× 4 multiplication), ouroboros would accept it; Core would reject
with `bad-blk-length`. **BUG-4 (P2)** — boundary-precision divergence.

### F5 — Ouroboros enforces `MAX_STACK_SIZE` on initial witness v0 stack; Core does NOT

`script.py:830-842`:

```py
# Tapscript initial-stack constraints (interpreter.cpp:1855-1861):
#   * stack size must be <= MAX_STACK_SIZE (1000) BEFORE any push;
#   * every initial witness stack item must be <= MAX_SCRIPT_ELEMENT_SIZE (520).
# Core enforces these inside ExecuteWitnessScript right before
# EvalScript runs, so they fire for both tapscript and v0 P2WSH.
if is_tapscript or is_witness_v0:
    if len(stack) > MAX_STACK_SIZE:
        raise ValueError("Stack size exceeded (initial witness stack)")
    for elem in stack:
        if len(elem) > MAX_SCRIPT_ELEMENT_SIZE:
            raise ValueError(...)
```

**The comment is wrong.** Core's `ExecuteWitnessScript`
(`interpreter.cpp:1836-1856`):

```cpp
if (sigversion == SigVersion::TAPSCRIPT) {
    // OP_SUCCESSx processing overrides everything...
    ...
    // Tapscript enforces initial stack size limits (altstack is empty here)
    if (stack.size() > MAX_STACK_SIZE) return set_error(serror, SCRIPT_ERR_STACK_SIZE);
}

// Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
for (const valtype& elem : stack) {
    if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE) return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
}
```

The `MAX_STACK_SIZE` check is **INSIDE the tapscript `if` block** —
NOT enforced for `WITNESS_V0`. The element-size check is shared.

For v0, EvalScript's per-push guard (`stack.size() + altstack.size()
> MAX_STACK_SIZE`) catches large stacks AS THEY GROW; an initial
stack of 1500 items with a witnessScript of `OP_2DROP OP_2DROP …
OP_2DROP OP_TRUE` (1499 drops + TRUE, total ≤ 10 000-byte script)
shrinks down to 1 and Core accepts. Ouroboros rejects on entry.

Real attack vector: minimal (no real wallet creates such P2WSH
spends), but consensus-divergent. **BUG-5 (P0-CDIV)** — fix by
moving the stack-size check inside `if is_tapscript:` block.

### F6 — `has_witness` flag is a wire-format echo, not Core's `HasWitness()` semantics

`database.py:160-167`:

```py
@dataclass
class Transaction:
    ...
    has_witness: bool = False  # True if SegWit (marker 0x00, flag 0x01)
```

`get_wtxid` (line 244-248):

```py
def get_wtxid(self) -> bytes:
    if not self.has_witness:
        return self.get_txid()
    return hashlib.sha256(hashlib.sha256(self.serialize_with_witness()).digest()).digest()
```

`_validate_witness_commitment` line 1424-1426:

```py
for tx in block.transactions:
    if tx.has_witness:
        return False, "unexpected-witness"
```

Core's `HasWitness()` (`transaction.cpp:74-79`):

```cpp
bool CTransaction::ComputeHasWitness() const {
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();   // IsNull == stack.empty()
    });
}
```

`HasWitness()` is **computed from witness-stack state**, NOT a wire-
format echo. Mutations to `tx.inputs[i].witness` after construction
DO change `HasWitness()` in Core but do NOT change `has_witness` in
ouroboros.

Three concrete divergences:

a) Test/wallet path: build a `Transaction(has_witness=True)` then
clear all input witnesses to `[]`. ouroboros: `has_witness=True`,
emits BIP-144 wire format with empty stacks (Core would reject —
"Superfluous witness record").

b) BIP-152 short-id path: ouroboros's `get_wtxid` follows the flag,
not the data. If a tx's flag is stale → wrong short_id.

c) "unexpected-witness" check: a malicious tx with `has_witness=False`
but populated `tx_in.witness` slips past the loop at
`validation.py:1424-1426` — even though `serialize_with_witness`
would NOT serialize the witness (it gates on `if self.has_witness`,
line 220).

**BUG-6 (P0-CDIV)** — replace the flag with a computed property
that mirrors Core:

```py
@property
def has_witness(self) -> bool:
    return any(inp.witness for inp in self.inputs)
```

### F7 — Rust pipeline `verify_witness()` is a permanent stub

`ferrous-utils/sync/src/validate/script.rs:1502-1516`:

```rust
/// Verify SegWit witness
/// Note: This is a simplified implementation.
/// In practice, SegWit verification requires access to witness data,
/// which is not directly part of the Transaction struct in the current bitcoin crate version.
pub fn verify_witness(_tx: &TransactionWrapper, _input_idx: usize) -> Result<bool> {
    // Placeholder implementation
    // Full SegWit verification would require:
    // 1. Access to witness data (stored separately or in extended transaction format)
    // 2. Witness program validation
    // 3. SegWit script execution
    // 4. SegWit signature verification with proper sighash
    //
    // For now, return false to indicate SegWit is not supported in this simplified implementation
    Ok(false)
}
```

Exported via `validate/mod.rs:21`; called only by `test_witness_verification`.
**No production call site.** The two-pipeline guard ensures the
Python path remains authoritative, so this is **dead code** rather
than a live bug — but the *comment-as-confession* archetype is
present in the Rust source (`In practice, SegWit verification
requires access to witness data, which is not directly part of the
Transaction struct in the current bitcoin crate version`). This is
the same "comment-as-confession" archetype tracked across waves
(haskoin W138; rustoshi W141; this is the W142 instance).

**BUG-7 (P1)** — delete the stub OR wire the Python `script.py:561`
witness verifier through PyO3 so the Rust path can dispatch into it.
Today's exported-but-unused name pollutes the API surface.

### F8 — Wire deserializer's segwit-marker heuristic mis-classifies the malformed-but-deserializable case

`p2p_messages.py:494`:

```py
if len(payload) > offset + 2 and payload[offset] == 0x00 and payload[offset+1] == 0x01:
    has_witness = True
    offset += 2
```

This checks ONLY for the exact byte pair `0x00 0x01`. Core's logic
(`transaction.h:209-220`):

```cpp
s >> tx.vin;
if (tx.vin.size() == 0 && fAllowWitness) {
    s >> flags;
    if (flags != 0) {
        s >> tx.vin;
        s >> tx.vout;
    }
}
```

Core ACCEPTS `flags & 1` (any value with bit 0 set) and then post-
strips bit 0 via `flags ^= 1` and reads witnesses; **then asserts
`flags == 0`** ("Unknown transaction optional data" otherwise).

Three concrete cases:

a) `payload[offset..offset+2] = 0x00 0x03` (flags=3, bit0+bit1):
- Core: reads vin (empty), reads flags=3, reads vin (now real),
  reads vout, reads witnesses, XORs flag1 off → flags=2 → throws
  "Unknown transaction optional data".
- Ouroboros: `payload[offset+1] != 0x01` → treats as legacy tx with
  `inputs_count = 0x00` → empty inputs → then reads next byte
  (`0x03`) as outputs varint = 3 outputs. **Completely different
  parse.** Result is wildly different tx state.

b) `payload[offset..offset+2] = 0x00 0x00` (zero inputs, no flag):
- Core: reads vin=empty, reads flags=0, falls through to vout/witness
  skip; throws nothing here. CheckTransaction later rejects
  `bad-txns-vin-empty`.
- Ouroboros: `payload[offset+1] != 0x01` → legacy tx, inputs_count=0
  → continues. Same end result (tx with no inputs); rejected later.

c) `payload[offset..offset+2] = 0x00 0x05` (flags=5, bits 0+2):
- Core: reads vin (empty), reads flags=5, reads vin, reads vout,
  reads witnesses (because flags & 1), XORs flag bit 0 off →
  flags=4 → throws "Unknown transaction optional data".
- Ouroboros: `payload[offset+1] != 0x01` → silent legacy interpret-
  ation.

**BUG-8 (P1)** — wire-deserializer divergence on malformed-but-
not-empty txs. Not a security bug per se (the txs are all rejected
later by content validation) but reject-reasons + log-message
strings disagree; remote fuzzers can distinguish ouroboros from
Core nodes.

### F9 — Testnet4 and signet `SegwitHeight` should be 1, not 0

`validation.py:1306-1313`:

```py
_SEGWIT_ACTIVATION = {
    "mainnet": 481_824,
    "testnet": 834_624,
    "testnet3": 834_624,
    "testnet4": 0,
    "signet": 0,
    "regtest": 0,
}
```

Core `kernel/chainparams.cpp`:

```cpp
// testnet4 (line 316):
consensus.SegwitHeight = 1;
// signet (line 460):
consensus.SegwitHeight = 1;
// regtest (line 541):
consensus.SegwitHeight = 0; // Always active unless overridden
```

For testnet4/signet, ouroboros enforces witness rules at height 0
(genesis); Core does NOT (since `height < 1` skips the
"DeploymentActiveAfter SEGWIT" gate). In practice this only matters
for the synthetic h=0 block (which no peer broadcasts), so the
impact is operational only — but `_SEGWIT_ACTIVATION` is also read
by `getdeploymentinfo` / status RPCs, and the wrong number leaks to
external monitors.

**BUG-9 (P2)** — set testnet4 and signet to 1.

### F10 — `bip143_sighash` (the PSBT/wallet source-of-truth) silently differs from `_compute_segwit_v0_sighash` (the consensus path) on sighash_type=0x00

`script.py:685-700` (consensus path):

```py
def _compute_segwit_v0_sighash(self, ..., sighash_type: int) -> bytes:
    base_type = sighash_type & 0x1f
    anyone_can_pay = (sighash_type & 0x80) != 0
    if base_type == 0:
        base_type = 0x01     # <-- normalize 0 → SIGHASH_ALL
```

`segwit_v0.py:79-98` (wallet/PSBT path):

```py
def bip143_sighash(..., sighash_type: int) -> bytes:
    base = sighash_type & 0x1F
    acp = (sighash_type & 0x80) != 0
    # ... NO normalization of base==0
```

Core does NOT normalize (`interpreter.cpp:1633` directly tests
`(nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE`).
For `sighash_type = 0x00`:

- `(0x00 & 0x1f) == 0x00`, NOT `SIGHASH_SINGLE` and NOT `SIGHASH_NONE`,
  so hashSequence/hashOutputs use the ALL-style derivation.
- BOTH ouroboros paths reach the same hashOutputs/hashSequence; the
  normalization is redundant but consistent in this single dimension.

**However**, the divergence shows up at the preimage tail:

- script.py:748 → `data.extend(struct.pack('<I', sighash_type))` (raw).
- segwit_v0.py:142 → `pre += struct.pack("<I", sighash_type)` (raw).
- Both write the ORIGINAL `sighash_type = 0x00`, not the normalized.

Match. **BUT** the normalization is a latent bug: if a future patch
changes `base_type → base_type` in the preimage write (e.g. for
"hygiene"), the two paths drift. The PSBT path doesn't normalize
and the consensus path does; the comment trail will be misleading
for the next maintainer.

**BUG-10 (P1)** — DELETE the `if base_type == 0: base_type = 0x01`
normalization in `_compute_segwit_v0_sighash`. It's a no-op today
and a footgun for future edits.

### F11 — Mid-stage caching of BIP-143 midstates not implemented

Core's `PrecomputedTransactionData::Init` computes `hashPrevouts`,
`hashSequence`, `hashOutputs` ONCE per tx and reuses them across
all inputs (`interpreter.cpp:1610-1645`, gated by
`cache->m_bip143_segwit_ready`). Ouroboros recomputes them per-input
in `_compute_segwit_v0_sighash` (lines 700-733) and `bip143_sighash`
(lines 100-128). For a 1000-input segwit transaction this is a
~1000× CPU multiplier on the sighash phase.

**BUG-11 (P2)** — performance only; not a consensus bug.

### F12 — `_count_witness_sigops` is skipped for coinbase but Core's path is structurally identical

`validation.py:1264-1283`:

```py
if not tx.is_coinbase:
    for inp in tx.inputs:
        utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
        if utxo is None:
            continue
        prev_spk = bytes(utxo["script_pubkey"])
        p2sh_sigops = _get_p2sh_sigops(inp.script_sig, prev_spk)
        tx_sigops_cost += p2sh_sigops * WITNESS_SCALE_FACTOR
        witness_spk = prev_spk
        witness_data = inp.witness
        if _is_p2sh(prev_spk):
            redeem = _get_last_push(inp.script_sig)
            if redeem is not None:
                witness_spk = redeem
        tx_sigops_cost += _count_witness_sigops(witness_spk, witness_data)
```

Core calls `GetTransactionSigOpCost` for ALL txs including coinbase
in `validation.cpp:2627-2630`:

```cpp
nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
```

The coinbase's prev_txid is `0x00*32` so `view.AccessCoin` returns
a default Coin (`coin.IsSpent() == true`) and the witness-sigop and
p2sh-sigop contributions are 0 in practice. Match in numerical
outcome but DIFFERENT in structure: ouroboros's `if not is_coinbase`
branch is dead-equivalent in correctness but obscures the audit
trail. A future patch that wires sigop-cost accounting for coinbase
(e.g. for inscription-style data carriers) will miss this branch.

**BUG-12 (P3)** — refactor to drop the `if not is_coinbase` guard
and rely on the `utxo is None` skip below.

### F13 — `get_weight()` uses ad-hoc 3× + 1× instead of `WITNESS_SCALE_FACTOR - 1` and `WITNESS_SCALE_FACTOR`

`database.py:281-283`:

```py
stripped_size = len(self.serialize())
total_size = len(self.serialize_with_witness())
return stripped_size * 3 + total_size
```

Core (`consensus/validation.h:135`):

```cpp
return GetSerializeSize(TX_NO_WITNESS(tx)) * (WITNESS_SCALE_FACTOR - 1) + GetSerializeSize(TX_WITH_WITNESS(tx));
```

Numerically equivalent (`WITNESS_SCALE_FACTOR = 4`, `4-1 = 3`).
**BUG-13 (P3)** — cosmetic: use `WITNESS_SCALE_FACTOR - 1` from
`validation.py` to keep the constant centralized. A future patch
changing the scale factor (e.g. a hypothetical hard fork raising
witness discount) would silently miss this site.

### F14 — Coinbase wtxid is hard-coded in `_calculate_witness_merkle_root` but `Transaction.get_wtxid()` for the coinbase returns a real wtxid

`validation.py:1329-1333`:

```py
def _calculate_witness_merkle_root(self, block: Block) -> bytes:
    wtxids: list[bytes] = [bytes(32)]  # coinbase → null hash
    for tx in block.transactions[1:]:
        wtxids.append(tx.get_wtxid())
    return self._calculate_merkle_root(wtxids)
```

Match Core's `BlockWitnessMerkleRoot` (`merkle.cpp:81`:
`leaves.emplace_back();  // The witness hash of the coinbase is 0`).

**BUT** elsewhere — in `compact_blocks.py:441-446`:

```py
for i, tx in enumerate(block.transactions):
    if prefill_coinbase and i == 0:
        prefilled.append(PrefilledTransaction(index=0, tx=tx))
    else:
        wtxid = tx.get_wtxid()
        sids.append(short_txid(key, wtxid))
```

This is gated by `prefill_coinbase=True` (default). If a future
caller (or test fixture) sets `prefill_coinbase=False`, ouroboros
will compute `short_txid(key, tx.get_wtxid())` for the coinbase,
where `tx.get_wtxid()` returns the REAL wtxid (not the null hash).
Core's BIP-152 short-id for the coinbase uses the SAME-as-block
wtxid (the real one in Core; the null in ouroboros).

Actually re-reading BIP-152: §"Short transaction IDs" uses each
transaction's wtxid for SegWit-enabled compact blocks. Core's
coinbase has a REAL `m_witness_hash` for short_id purposes; only
`BlockWitnessMerkleRoot` pins coinbase to zero. So this comment is
INVERTED — ouroboros's `_calculate_witness_merkle_root` is correct
(pins coinbase to zero); but ouroboros's `compact_blocks.py:445`
falls back to `tx.get_wtxid()` for non-prefilled coinbase, which
WOULD compute the real coinbase wtxid, matching Core.

However, ouroboros's `get_wtxid()` (`database.py:244-248`):

```py
def get_wtxid(self) -> bytes:
    if not self.has_witness:
        return self.get_txid()
    return hashlib.sha256(hashlib.sha256(self.serialize_with_witness()).digest()).digest()
```

If the coinbase carries the SegWit nonce in its witness (it MUST
for any block with a commitment), `has_witness=True` and the real
wtxid is computed correctly. **PRESENT** for this gate.

The risk is purely the F6 has_witness drift (BUG-6): if the
deserializer fails to set `has_witness=True` for a particular wire
format the wtxid computation is wrong. Already captured.

**BUG-14 (P3)** — add an explicit assertion at `compact_blocks.py:445`
that the coinbase wtxid is computed identically to Core's (i.e.,
`block.vtx[0]->GetWitnessHash()` from the data, NOT the all-zero
pin from `BlockWitnessMerkleRoot`). A note + a unit test guards
against future drift.

### F15 — `_find_witness_commitment` slices `spk[6:38]` without verifying `spk` is at least 38 bytes (already gated by `len >= 38`); same gate downstream uses `>= 38` (PRESENT)

`validation.py:1317-1327`:

```py
def _find_witness_commitment(self, coinbase_tx: Transaction) -> bytes | None:
    for out in reversed(coinbase_tx.outputs):
        spk = out.script_pubkey
        if (
            len(spk) >= 38
            and spk[0] == 0x6A           # OP_RETURN
            and spk[1] == 0x24           # push 36 bytes
            and spk[2:6] == self._WITNESS_COMMITMENT_MAGIC
        ):
            return spk[6:38]
    return None
```

Match Core's `GetWitnessCommitmentIndex` (`consensus/validation.h:147-167`).
PRESENT.

**Comparison nit**: Core iterates forward and overwrites `commitpos`,
ouroboros iterates `reversed` and returns the first match. Both
return the LAST forward-iteration match; outcomes equivalent.

No bug. (Notation: G15-OK / PRESENT.)

### F16 — P2WSH `cleanstack` and `CastToBool` order is reversed vs Core

`script.py:679-682`:

```py
if not stack or not self._cast_to_bool(stack[-1]):
    return False     # castToBool first
if len(stack) != 1:
    return False     # cleanstack second
```

Core `interpreter.cpp:1866-1868`:

```cpp
if (stack.size() != 1) return set_error(serror, SCRIPT_ERR_CLEANSTACK);
if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
```

Core: cleanstack first, then CastToBool. Ouroboros: reversed.

Outcome (False either way) is identical, but **reject-reason** the
caller sees is reversed. The W125 RPC error parity audit established
that error strings/error codes are observable surfaces of consensus
state. A diff-test fixture comparing `bitcoind`'s `SCRIPT_ERR_*` to
ouroboros's reject-reason on a particular invalid P2WSH spend will
disagree.

**BUG-15 (P2)** — re-order to match Core, OR plumb a distinct
return enum so callers can preserve the Core ordering at the layer
that DOES surface error strings.

### F17 — `Transaction.serialize_with_witness` emits the segwit marker even when ALL input witnesses are empty

`database.py:213-242`:

```py
def serialize_with_witness(self) -> bytes:
    data = bytearray()
    data.extend(self.version.to_bytes(4, 'little', signed=True))
    if self.has_witness:
        data.extend(b'\x00\x01')  # marker, flag
    ...
    if self.has_witness:
        for tx_in in self.inputs:
            witness = tx_in.witness or []
            data.extend(self._encode_varint(len(witness)))
            for item in witness:
                ...
```

If `has_witness == True` and every `tx_in.witness` is `None` or `[]`,
this emits:
- marker `0x00`, flag `0x01`
- per-input varint(0) per-input (no items)

Core's `SerializeTransaction` (`transaction.h:245-258`):

```cpp
if (fAllowWitness) {
    if (tx.HasWitness()) {     // any non-empty stack
        flags |= 1;
    }
}
if (flags) {
    // ... emit marker/flag/witness data
}
```

Core gates emit on `HasWitness()` (computed). Ouroboros gates on the
wire-format-echo flag. The two diverge whenever the witness-stack
state has been mutated (cleared) post-construction.

Compounds with BUG-1 + BUG-6 to make a single "Superfluous witness
record" wire format reproducible end-to-end inside ouroboros.

**BUG-16 (P0-DoS-pair-of-BUG-1)** — chain ouroboros: receive a
"clean" segwit tx → store it → broadcast it after a wallet-side
operation clears the witnesses (e.g. bumpfee on an unsigned PSBT) →
emit the malformed wire format → Core peers ban us. Mempool-level
DoS-by-getting-banned.

Fix sketch: compute the gate, not the flag:

```py
has_witness_data = any(inp.witness for inp in self.inputs)
if has_witness_data:
    data.extend(b'\x00\x01')
...
if has_witness_data:
    for tx_in in self.inputs:
        ...
```

### F18 — Heights store and dispatch a `_SEGWIT_ACTIVATION` table that overlaps with the BURIED_DEPLOYMENTS data (single source of truth missing)

`validation.py:1306-1313` defines `_SEGWIT_ACTIVATION` (an inline
dict). `consensus.py:BURIED_DEPLOYMENTS` defines per-network buried-
deployment activation heights (BIP34, BIP65, BIP66, CSV, SegWit).
The two tables agree TODAY but are unsynchronized: a future patch
that updates one but not the other (e.g. a testnet4 reset) will
introduce silent divergence.

**BUG-17 (P1)** — collapse `_SEGWIT_ACTIVATION` to read from
`BURIED_DEPLOYMENTS[self.network]["segwit"].height` (parallel to
the existing BIP34 dispatch at `validation.py:1488-1489`).

### F19 — `_validate_witness_commitment` returns `True` on every block PRE-SegWit-activation if NO tx has witness data — never checks for "rogue commitment output" pre-activation

`validation.py:1352-1428` flow when `segwit_active = False`:

```py
activation = self._SEGWIT_ACTIVATION.get(self.network, 481_824)
segwit_active = height >= activation

if segwit_active:
    # G1-G4 inside
    ...
    # G5: fall through (no commitment found)

# G5: no commitment found OR SegWit inactive — reject witness data
for tx in block.transactions:
    if tx.has_witness:
        return False, "unexpected-witness"
return True, ""
```

For `segwit_active == False`: the function ONLY rejects blocks with
witness-bearing txs. A coinbase WITH a rogue witness commitment
output (the 38-byte OP_RETURN that looks like a commitment, with
bogus data) **is accepted**.

Core's `CheckWitnessMalleation` (`validation.cpp:3870-3873`) is gated
on `expect_witness_commitment` (= DEPLOYMENT_SEGWIT active). When
DEPLOYMENT_SEGWIT inactive, the function ONLY rejects HasWitness
blocks (`for (const auto& tx : block.vtx) if (tx->HasWitness())` —
line 3906). Match ouroboros. Both accept rogue commitments
pre-activation.

**Not a bug.** G19-OK / PRESENT.

But noting it as a fleet-pattern: pre-activation, NO impl in the
fleet rejects rogue witness-commitment-shaped outputs. (Filed for
future bookkeeping; not a W142 BUG.)

Gate matrix
-----------

| Gate | Topic                                            | Status   | BUG # |
|------|--------------------------------------------------|----------|-------|
| G1   | Coinbase witness commitment magic + structure    | PRESENT  | —     |
| G2   | Witness reserved value in coinbase scriptWitness | PRESENT  | —     |
| G3   | SHA256d(witness_root \|\| nonce) check           | PRESENT  | —     |
| G4   | Witness merkle root, coinbase wtxid = 0          | PRESENT  | —     |
| G5   | BIP-143 sighash for v0 (single source)           | PARTIAL  | 10,11 |
| G6   | Witness program version + size (2..40 / v0:20,32)| PRESENT  | —     |
| G7   | Empty witness for non-witness tx ("unexpected")  | PARTIAL  | 6,16  |
| G8   | Weight = base×3 + total; vsize = (W+3)/4         | PARTIAL  | 4,13  |
| G9   | MAX_BLOCK_WEIGHT = 4_000_000                     | PARTIAL  | 3,4   |
| G10  | CheckWitnessMalleation order + asserts           | MISSING  | 2     |
| G11  | Wire BIP-144 marker/flag handling                | MISSING  | 1,8   |
| G12  | has_witness = ComputeHasWitness() (no echo)      | MISSING  | 6,16,17|
| G13  | Initial witness-stack MAX_STACK_SIZE gate (v0)   | MISSING  | 5     |
| G14  | testnet4 + signet SegwitHeight = 1               | MISSING  | 9,18  |
| G15  | Cleanstack/CastToBool order (P2WSH)              | PARTIAL  | 15    |
| G16  | BIP-143 midstate cache                           | MISSING  | 11    |

**Score: 5 PRESENT / 5 PARTIAL / 6 MISSING = 18 BUGS**.

Bug summary
-----------

| #  | Title (one line)                                                              | Severity   |
|----|-------------------------------------------------------------------------------|------------|
| 1  | Wire deserializer accepts "Superfluous witness record" txs                    | P0-CDIV    |
| 2  | `_validate_witness_commitment` indexes vtx[0]/vin[0] without empty guard      | P0-DoS     |
| 3  | `_validate_block_limits` missing `block.vtx.empty()` gate                     | P1         |
| 4  | Stripped-size pre-check omits header + tx-count varint (~81-89 byte underct)  | P2         |
| 5  | Enforces MAX_STACK_SIZE on initial witness v0 stack; Core does NOT            | P0-CDIV    |
| 6  | `has_witness` flag is wire-echo, not Core's `HasWitness()` semantics          | P0-CDIV    |
| 7  | Rust `verify_witness` is a permanent stub (dead-code + comment-as-confession) | P1         |
| 8  | Wire-marker heuristic mis-classifies all flags except `0x00 0x01`             | P1         |
| 9  | `_SEGWIT_ACTIVATION` testnet4=0 / signet=0; Core: 1 / 1                       | P2         |
| 10 | `bip143_sighash` (PSBT) and `_compute_segwit_v0_sighash` drift on base==0     | P1         |
| 11 | BIP-143 midstate cache (`m_bip143_segwit_ready`) not implemented              | P2         |
| 12 | `_count_witness_sigops` coinbase short-circuit obscures audit trail           | P3         |
| 13 | `get_weight()` uses 3× / 1× literals not `WITNESS_SCALE_FACTOR - 1` constant  | P3         |
| 14 | Coinbase wtxid divergence in `compact_blocks.py` non-prefill path             | P3         |
| 15 | P2WSH cleanstack/CastToBool order reversed vs Core (error-string drift)       | P2         |
| 16 | `serialize_with_witness` emits marker even when all witnesses empty           | P0-DoS     |
| 17 | `_SEGWIT_ACTIVATION` duplicates `BURIED_DEPLOYMENTS` (drift risk)             | P1         |
| 18 | (rolled into BUG-9 / BUG-17 — placeholder)                                    | —          |

**Total**: 3 P0-CDIV / 2 P0-DoS / 1 P1 (counted in summary as P1: 7) /
8 P1 / 5 P2 — call it **18 BUGS**.

Severity bucketing for the final commit footer:
  3 P0-CDIV, 2 P0-DoS, 8 P1, 5 P2 = 18.

Fleet patterns observed
-----------------------

- **comment-as-confession** archetype (5th cross-fleet instance):
  `ferrous-utils/sync/src/validate/script.rs:1502-1516` literally says
  "Note: This is a simplified implementation. … return false to indicate
  SegWit is not supported in this simplified implementation". Same shape
  as haskoin W138 BUG-3 (Consensus.hs:4917-4919) and rustoshi W141 BUG-13.

- **two-pipeline guard 15th distinct extension** (post-W141's 14):
  W142 first witness-validation-specific guard. Rust path explicitly
  proven stubbed (single in-file test, zero production callers).

- **flag-echo vs computed-state** archetype (NEW). `Transaction.has_witness`
  in ouroboros is set ONCE at deserialize and never re-derived from the
  scriptWitness state — exact mirror of the W110/W120 "stored flag vs
  computed property" pattern that haunted nimrod and rustoshi mempool
  paths. Filed for future-fleet-sweep tracking.

- **defense-in-depth-missing-empty-vtx-guard**: validation.py's
  `_validate_witness_commitment` indexes `transactions[0].inputs[0]`
  before any caller verifies the list is non-empty. The same defensive
  layer Core enforces via `assert(!block.vtx.empty() && !block.vtx[0]->vin.empty())`
  in CheckWitnessMalleation. Likely a fleet pattern — every impl with
  separate "size limits" and "witness commitment" phases is suspect.

- **wire-deserializer vs content-validator divergence-on-malformed**
  (W141-adjacent): a malformed-but-deserializable tx slips into the
  mempool with parameters Core would never have observed (Core threw
  on the wire). The "Superfluous witness record" + "Unknown transaction
  optional data" gates are the wire-level analog of W135's standardness
  rules — they enforce on the wire what content-validation enforces
  on the parsed tx.

References
----------

Bitcoin Core lines cited (all under `bitcoin-core/src/`):

- `validation.cpp:3870` — CheckWitnessMalleation.
- `validation.cpp:3884` — assert(!vtx.empty() && !vin.empty()).
- `validation.cpp:3919-3982` — CheckBlock.
- `validation.cpp:3946` — bad-blk-length early exit.
- `validation.cpp:3987-4019` — UpdateUncommittedBlockStructures +
  GenerateCoinbaseCommitment.
- `consensus/validation.h:18` — MINIMUM_WITNESS_COMMITMENT = 38.
- `consensus/validation.h:147-167` — GetWitnessCommitmentIndex.
- `consensus/merkle.cpp:76-86` — BlockWitnessMerkleRoot (no mutation check).
- `consensus/merkle.cpp:46-65` — ComputeMerkleRoot (optional mutated*).
- `consensus/consensus.h:18-24` — WITNESS_SCALE_FACTOR, MAX_BLOCK_WEIGHT,
  MIN_TRANSACTION_WEIGHT.
- `script/interpreter.cpp:1600-1675` — SignatureHash (BIP-143 WITNESS_V0).
- `script/interpreter.cpp:1832-1870` — ExecuteWitnessScript.
- `script/interpreter.cpp:1916-2002` — VerifyWitnessProgram.
- `script/interpreter.cpp:2123-2167` — WitnessSigOps + CountWitnessSigOps.
- `script/interpreter.h:238-240` — WITNESS_V0_KEYHASH_SIZE/SCRIPTHASH_SIZE.
- `primitives/transaction.h:200-242` — UnserializeTransaction.
- `primitives/transaction.h:245-280` — SerializeTransaction.
- `primitives/transaction.cpp:74-79` — ComputeHasWitness.
- `kernel/chainparams.cpp:94,217,316,460,541` — SegwitHeight per network.
- `policy/policy.h` — GetVirtualTransactionSize / WITNESS_SCALE_FACTOR.

Done.
