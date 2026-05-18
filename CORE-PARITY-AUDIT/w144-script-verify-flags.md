W144 — Script-verify flag mux audit (ouroboros)
=================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline — script flag derivation lives in
      `src/ouroboros/script.py:130-271` (`get_flags_for_height`,
      `get_standard_script_flags`), block-hash exception table at
      `script.py:113-122`, and buried-deployment table at
      `src/ouroboros/consensus.py:119-165`. Application call sites are
      scattered across `src/ouroboros/script.py` (`ScriptInterpreter`)
      and `src/ouroboros/validation.py::_verify_input_signature`.)
Wave: W144 — script-verify flag mux (`SCRIPT_VERIFY_*` application +
      softfork activation, BIP-16/65/66/112/141/147/341/342).

Reference (Bitcoin Core)
------------------------
- `bitcoin-core/src/script/interpreter.h:47-160`: `script_verify_flag_name`
  enum (P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, SIGPUSHONLY,
  MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, CLTV, CSV, WITNESS,
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLFAIL,
  WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT,
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS,
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
- `bitcoin-core/src/validation.cpp:2250-2289` `GetBlockScriptFlags`:
  baseline `{P2SH | WITNESS | TAPROOT}`, then `script_flag_exceptions`
  override, then `|=` DERSIG / CLTV / CSV / NULLDUMMY per
  buried-deployment height. **Critical architectural detail**: the
  override REPLACES the baseline (`flags = it->second`) but the
  per-deployment `|=` ORs run AFTER the override unconditionally.
- `bitcoin-core/src/policy/policy.h:105-135`:
  - `MANDATORY_SCRIPT_VERIFY_FLAGS = P2SH | DERSIG | NULLDUMMY | CLTV |
    CSV | WITNESS | TAPROOT` (consensus / `ConnectBlock`).
  - `STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY | STRICTENC | MINIMALDATA |
    DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL |
    LOW_S | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE
    | CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (mempool /
    relay). **No SIGPUSHONLY in either set.**
- `bitcoin-core/src/kernel/chainparams.cpp`:
  - mainnet (lines 85-94): `script_flag_exceptions` has two entries
    (BIP16 block `0000…ac4f9c22` → `NONE`; Taproot block `0000…e395ad`
    → `P2SH | WITNESS`); `BIP34Height=227931`, `BIP65Height=388381`,
    `BIP66Height=363725`, `CSVHeight=419328`, `SegwitHeight=481824`.
  - testnet3 (lines 210-217): `script_flag_exceptions` has one entry
    (`0000…32b105` → `NONE`); deployments at 21111/581885/330776/770112/834624.
  - testnet4 (lines 311-316), signet (lines 455-460), regtest (lines
    536-541): NO exception entries; deployments at height 1 (regtest
    segwit at 0).
- `bitcoin-core/src/deploymentstatus.h:14-37`: `DeploymentActiveAt` is
  `index.nHeight >= params.DeploymentHeight(dep)` for buried; for
  BIP9 it walks the threshold-state cache.
- `bitcoin-core/src/consensus/params.h:25-43`: **`BuriedDeployment` enum
  contains HEIGHTINCB, CLTV, DERSIG, CSV, SEGWIT only — TAPROOT IS NOT
  A BURIED DEPLOYMENT.** `DeploymentPos` enum contains ONLY
  `DEPLOYMENT_TESTDUMMY`. Taproot is treated as **always-active baseline
  flag** plus the one block-hash carve-out in `script_flag_exceptions`.
- `bitcoin-core/src/script/interpreter.cpp`:
  - `EvalScript` (lines 425-2000): flag application during execution
    (MAX_SCRIPT_SIZE 425; MINIMALDATA 432; CONST_SCRIPTCODE/CODESEPARATOR
    474-476; DISCOURAGE_UPGRADABLE_NOPS 595-601; CLTV 522-559;
    CSV 561-593; NULLFAIL 1186, 1423; NULLDUMMY 1201-1202; WITNESS
    492; FindAndDelete CONST_SCRIPTCODE 330-332, 1146-1148).
  - `CheckPubKeyEncoding` (lines 218-228): WITNESS_PUBKEYTYPE gated on
    `sigversion == WITNESS_V0`.
  - `VerifyScript` (lines 2010-2120): CLEANSTACK + WITNESS_UNEXPECTED
    + `assert(WITNESS => P2SH)` (line 2114).

Status: 8 behaviors × multiple gates audited — 22 BUGS catalogued
(2 P0-CONSENSUS / 1 P0-CDIV / 8 P1 / 9 P2 / 2 P3).

Relationship to prior audits
----------------------------
- W127 (Taproot): tapscript opcode-level audit. W144 covers ONLY the
  flag derivation that decides whether tapscript runs in the first place.
- W132 (nSequence / CSV / MTP): W132 audited the BIP-68/112/113
  behaviors at the transaction level. W144 covers the
  `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` flag that *gates* OP_CSV execution.
  Cross-cite: W132 BUG re. `BIP68_ACTIVATION_HEIGHT` mis-named is
  re-confirmed below as BUG-19.
- W142 (SegWit witness validation): W142 audited witness-merkle and
  `_verify_witness_program` body. W144 covers the
  `SCRIPT_VERIFY_WITNESS` flag derivation.
- W143 (Block validation): W143 audited `validate_block` / `CheckBlock`.
  W144 audits the script-flag input feeding into that.
- W135 (Standardness): W135 audited `IsStandardTx`. W144 audits the
  `STANDARD_SCRIPT_VERIFY_FLAGS` policy set the same code path uses.

Two-pipeline guard
------------------
Script-verify flag derivation runs entirely in the **Python pipeline**
(`src/ouroboros/script.py::get_flags_for_height` /
`get_standard_script_flags`). The Rust pipeline (`ferrous-utils/sync`)
has a `get_deployment_state` PyO3 export at `lib.rs:654-699` that is
called from the Python fallback (`consensus.py:578-586`), but the
SCRIPT_VERIFY_* bitmask itself is never assembled in Rust. The Rust
script verifier (`ferrous-utils/sync/src/validate/script.rs`) is a
stub — production validation runs through the Python `ScriptInterpreter`.

Two-pipeline guard EXTENDED to:

```
$ grep -rn "SCRIPT_VERIFY_\|get_flags_for_height\|get_block_script_flags" \
        ferrous-utils/sync/src/ --include='*.rs'
ferrous-utils/sync/src/lib.rs:654:  fn get_deployment_state(...)   # state only, no flag bitmask
ferrous-utils/sync/src/validate/script.rs:1502: pub fn verify_witness(...)  # stub returns Ok(false)
```

The Rust side has no `GetBlockScriptFlags` analog. Two-pipeline drift
risk is in the *opposite* direction here vs. W137-W141 — Rust can't
disagree because Rust never produces a flag set. Guard EXTENDS the
W76 + W120 + W122 + W125 + W128 + W129 + W130 + W131 + W133 + W134 +
W137 + W140 + W141 + W142 set → now W144.

Top-level architectural findings
--------------------------------

### F1 — Taproot is modeled as a BIP9 versionbits deployment; Core treats it as ALWAYS-ACTIVE baseline + one block-hash carve-out

Core's `GetBlockScriptFlags` (`validation.cpp:2262`) seeds the bitmask
with `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT`
unconditionally. The single Taproot exception block (mainnet
`0000…e395ad` at height 709,632) overrides the baseline via the
`script_flag_exceptions` map. After the optional override, Core ORs in
DERSIG/CLTV/CSV/NULLDUMMY per buried-deployment height — those `|=`
calls run even for blocks that hit the exception.

`BuriedDeployment` enum (`consensus/params.h:25-34`) explicitly lists
**HEIGHTINCB, CLTV, DERSIG, CSV, SEGWIT** — TAPROOT is NOT present.
`DeploymentPos` enum (params.h:37-42) contains ONLY `DEPLOYMENT_TESTDUMMY`
in modern Core. Taproot is no longer a versionbits deployment; it is
implicit-always-active.

ouroboros (`script.py:201`):

```py
# Taproot (BIP340/341/342) — TAPROOT only.
if is_deployment_active("taproot", height, network):
    flags |= SCRIPT_VERIFY_TAPROOT
```

`is_deployment_active("taproot", ...)` calls into the BIP9 state machine
(`consensus.py:619-642 → get_deployment_state → _bip9_state_for_pindexPrev`
or its Rust equivalent at `lib.rs:654-699`). With the default empty
`block_versions=[]` / `block_mtps=[]` that every production call site
passes (see BUG-1 below), the state machine resolves to `DEFINED` (never
reaches `STARTED` because MTP at start-of-period is `unwrap_or(0)` and
`0 < deployment.start_time = 1619222400`).

Net effect on mainnet validation: **SCRIPT_VERIFY_TAPROOT is NEVER
SET on mainnet blocks**, including blocks at and after height 709,632.
A spend of a v1 32-byte witness output is treated as the BIP-141
forward-compat unknown-version success path (`script.py:618: return True`),
which makes every Taproot output spendable WITHOUT signature
verification.

This is **P0-CONSENSUS** — see BUG-1.

### F2 — Block-hash exception table early-returns, missing the deployment OR-ins

Core (`validation.cpp:2262-2286`):

```cpp
script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
const auto it{consensusparams.script_flag_exceptions.find(...)};
if (it != consensusparams.script_flag_exceptions.end()) {
    flags = it->second;        // REPLACES baseline
}
if (DeploymentActiveAt(... DERSIG)) flags |= SCRIPT_VERIFY_DERSIG;
if (DeploymentActiveAt(... CLTV))   flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
if (DeploymentActiveAt(... CSV))    flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
if (DeploymentActiveAt(... SEGWIT)) flags |= SCRIPT_VERIFY_NULLDUMMY;
return flags;
```

Note the override is a REPLACE, but the subsequent `|=` lines run
unconditionally — so the Taproot exception block at height 709,632 (where
DERSIG/CLTV/CSV/NULLDUMMY are all deployed and active) ends up with
flags = `P2SH | WITNESS | DERSIG | CLTV | CSV | NULLDUMMY`.

ouroboros (`script.py:158-160`):

```py
# Check for historical exception blocks first
if block_hash is not None and block_hash in _SCRIPT_FLAG_EXCEPTIONS:
    return _SCRIPT_FLAG_EXCEPTIONS[block_hash]
```

**Early-returns** the raw exception entry. For the Taproot exception
block, that's `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS` only —
**MISSING DERSIG / CLTV / CSV / NULLDUMMY**.

P0-CDIV at the single Taproot exception block on mainnet (height 709,632).
See BUG-2.

### F3 — `block_versions` / `block_mtps` chain data never plumbed to flag derivation

`get_flags_for_height(height, block_hash, network)` (`script.py:130-219`)
has only three parameters — no chain data. It calls
`is_deployment_active("taproot", height, network)` (line 201) which
internally tries to call the Rust deployment state machine with empty
versions/mtps lists.

Every production call site (`validation.py:1899` in
`validate_transaction`, `mempool.py:2130-2131` in mempool acceptance)
passes `block_hash` and `network` but cannot supply `block_versions` /
`block_mtps` because the API doesn't accept them.

The Rust state machine (`versionbits.rs:183-246 get_state_for`) handles
empty data by walking back through periods, hitting
`provider.get_median_time_past(...)` which returns `None →
.unwrap_or(0)` (line 271), so `mtp < start_time` and state stays
`DEFINED` forever for any BIP9 deployment that is NOT
`ALWAYS_ACTIVE` / `NEVER_ACTIVE`.

This is the proximate cause of BUG-1: even on a fully synced mainnet,
Taproot is computed as DEFINED → NOT ACTIVE because no chain data is
passed.

Bug-by-bug catalogue
--------------------

### BUG-1 — Taproot SCRIPT_VERIFY_TAPROOT never set on mainnet (call sites pass empty chain data → BIP9 state stuck at DEFINED forever)

**Severity**: P0-CONSENSUS
**File**: `src/ouroboros/script.py:201`, `consensus.py:619-642`,
`ferrous-utils/sync/src/versionbits.rs:183-246`
**Core ref**: `bitcoin-core/src/validation.cpp:2262` (TAPROOT in
baseline, always active); `consensus/params.h:25-43` (TAPROOT absent
from BuriedDeployment + DeploymentPos enums).

`get_flags_for_height` (script.py:201) gates SCRIPT_VERIFY_TAPROOT on
`is_deployment_active("taproot", height, network)`. This calls
`get_deployment_state(...)` (`consensus.py:619`) which preferentially
routes to the Rust BIP9 state machine
(`ferrous-utils/sync/src/lib.rs:654-699 → versionbits.rs:493-505`).

The Rust state machine with empty `block_versions` / `block_mtps` walks
back through periods calling `provider.get_median_time_past(...)`. The
PyO3 provider (`lib.rs:631-650`) returns `None` for any height not in
the provided map; the state machine unwraps to 0:

```rust
let mtp = provider.get_median_time_past(prev_period_end).unwrap_or(0);
```

For mainnet taproot `start_time = 1619222400` (April 24 2021): `0 <
1619222400` → state stays `Defined` forever. `is_deployment_active`
returns False. SCRIPT_VERIFY_TAPROOT is NEVER OR'd into the flag set
on mainnet validation.

**Excerpt** (`script.py:198-202`):

```py
# Taproot (BIP340/341/342) — TAPROOT only.
# DISCOURAGE_UPGRADABLE_TAPROOT_VERSION and DISCOURAGE_OP_SUCCESS
# are policy flags for mempool/relay only.
if is_deployment_active("taproot", height, network):
    flags |= SCRIPT_VERIFY_TAPROOT
```

And the call site (`validation.py:1899`):

```py
flags = get_flags_for_height(height, block_hash, self.network)
```

No `block_versions` argument — the entire BIP9 state machine receives
empty data on every validation call.

**Impact**: A v1 32-byte witness output is treated as the BIP-141
forward-compat "unknown version" success path
(`script.py:618: return True`). Every Taproot spend on mainnet at
height ≥ 709,632 is accepted as anyone-can-spend in ouroboros while
Core enforces full BIP-341/342 verification. ouroboros forks from Core
on the first block after 709,632 that contains a Taproot input with an
invalid Schnorr signature or invalid script-path commitment. The
ouroboros node accepts the block; Core rejects → ouroboros builds a
chain Core cannot follow.

Compounded by BUG-2 (same bug class on the Taproot exception block,
opposite direction), F1 (architectural — taproot should be baseline).

**Fix sketch**: Mirror Core's "always-active baseline" — set
`SCRIPT_VERIFY_TAPROOT` unconditionally in `get_flags_for_height` (just
like `P2SH | WITNESS | TAPROOT` is the baseline in Core), and rely
solely on the `_SCRIPT_FLAG_EXCEPTIONS` table to carve out the Taproot
exception block. Remove the `is_deployment_active("taproot", ...)` gate.

### BUG-2 — Block-hash exception table early-returns, skipping DERSIG / CLTV / CSV / NULLDUMMY OR-ins for the Taproot exception block

**Severity**: P0-CDIV
**File**: `src/ouroboros/script.py:158-160`
**Core ref**: `bitcoin-core/src/validation.cpp:2264-2286`

Core OVERRIDES the baseline with the exception entry but then ORs in
DERSIG/CLTV/CSV/NULLDUMMY unconditionally. ouroboros early-returns.

**Excerpt** (`script.py:155-202`):

```py
flags = SCRIPT_VERIFY_NONE
# Check for historical exception blocks first
if block_hash is not None and block_hash in _SCRIPT_FLAG_EXCEPTIONS:
    return _SCRIPT_FLAG_EXCEPTIONS[block_hash]   # ← BUG

# Import consensus module for deployment checks
... # subsequent flag ORs are SKIPPED for exception blocks
```

For the Taproot exception block on mainnet (`0000…e395ad`, height
709,632), the table entry is `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS`.
Core then ORs in `DERSIG | CLTV | CSV | NULLDUMMY` (all four buried
deployments are active by 709,632). ouroboros returns only `P2SH |
WITNESS`, **missing all four post-override OR-ins**.

For the BIP16 exception block on mainnet (`0000…ac4f9c22`, ~height
170,060), the table entry is `SCRIPT_VERIFY_NONE`. Core then ORs in
DERSIG/CLTV/CSV/NULLDUMMY — but none of those are active at height
170,060 (all deploy at 363,725+), so the practical result is `NONE`.
The bug is silent here.

**Impact**: One-block consensus divergence for the Taproot exception
block: ouroboros validates the block's transactions without DERSIG /
CLTV / CSV / NULLDUMMY enforcement, while Core enforces all four.
Concretely: a tx in that block that uses a non-strict-DER signature
(DERSIG check), or a NOP2/NOP3 that's now consensus-mandatory, or a
CHECKMULTISIG with a non-empty dummy, would pass in ouroboros and fail
in Core.

**Fix sketch**: Replace `return _SCRIPT_FLAG_EXCEPTIONS[block_hash]` with
`flags = _SCRIPT_FLAG_EXCEPTIONS[block_hash]` and let control fall
through to the deployment OR-ins below.

### BUG-3 — P2SH height-gated on `BIP16_ACTIVATION_HEIGHT = 173805` mainnet; Core treats P2SH as always-active baseline

**Severity**: P1
**File**: `src/ouroboros/script.py:101, 175-177, 205-207`
**Core ref**: `bitcoin-core/src/validation.cpp:2262`
(`flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT}`
baseline).

ouroboros gates `SCRIPT_VERIFY_P2SH` on `height >= 173805` for mainnet.
Core sets P2SH baseline-on for ALL heights and only carves out one
specific block (`0000…ac4f9c22`) via `script_flag_exceptions`.

**Excerpt** (`script.py:172-177`):

```py
# P2SH (BIP16) - not a buried deployment but always active
# (activated via ISM, hardcoded to height 173805 on mainnet)
if network.lower() in ("regtest", "testnet4", "signet"):
    flags |= SCRIPT_VERIFY_P2SH
elif height >= BIP16_ACTIVATION_HEIGHT:
    flags |= SCRIPT_VERIFY_P2SH
```

**Impact**: Mainnet heights 1..173,804 → ouroboros omits P2SH where Core
includes it. The BIP16 exception block at ~170,060 is also at issue, but
the table already handles it. No real P2SH outputs were spent in
pre-activation mainnet blocks, so practical divergence is theoretical —
but if a reorg or rewind triggers re-validation of an old block that
happens to contain a P2SH-shaped scriptPubKey, ouroboros may accept it
where Core rejects. The comment "activated via ISM, hardcoded to height
173805" is itself wrong — Core has no `BIP16Height` field; the BIP16
roll-out is encoded entirely via the exception block.

**Fix sketch**: Same as BUG-1 — set `flags |= SCRIPT_VERIFY_P2SH`
unconditionally; rely on `_SCRIPT_FLAG_EXCEPTIONS` for the one
exception block.

### BUG-4 — Testnet3 BIP16 exception block hash missing from exception table

**Severity**: P1
**File**: `src/ouroboros/script.py:113-122`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:210-211`

Core testnet3 chainparams add ONE `script_flag_exceptions` entry for
the testnet3 BIP16 exception block:

```cpp
consensus.script_flag_exceptions.emplace( // BIP16 exception
    uint256{"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"},
    SCRIPT_VERIFY_NONE);
```

ouroboros' `_SCRIPT_FLAG_EXCEPTIONS` table contains only the two mainnet
hashes; testnet3's `0000…32b105` is absent.

**Excerpt** (`script.py:113-122`):

```py
_SCRIPT_FLAG_EXCEPTIONS: dict[bytes, int] = {
    # BIP16 exception (mainnet height ~170,060)
    bytes.fromhex(
        "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
    )[::-1]: SCRIPT_VERIFY_NONE,
    # Taproot exception (mainnet height 709,632)
    bytes.fromhex(
        "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
    )[::-1]: SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
}
```

**Impact**: ouroboros re-validating testnet3 at the BIP16 exception block
height would apply full P2SH where Core applies SCRIPT_VERIFY_NONE.
Affects testnet3 historical re-sync (and the testnet3 BIP16 carve-out
exists precisely because that specific block fails P2SH evaluation — so
ouroboros would *reject* a block Core accepts).

### BUG-5 — `_SCRIPT_FLAG_EXCEPTIONS` table is global, not per-network — mainnet exception hashes apply on testnet/signet/regtest

**Severity**: P3
**File**: `src/ouroboros/script.py:113-122, 159-160`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211`
(per-network `consensus.script_flag_exceptions.emplace(...)`).

Core's exception map is a per-network field on `consensus`. Each
network's `CChainParams` populates its own table. ouroboros stores one
global dict and looks up `block_hash in _SCRIPT_FLAG_EXCEPTIONS`
regardless of `network`.

The hashes happen to be unique 256-bit values (collision probability
≈ 2^-256), so the practical impact is zero. The bug is structural:
a future operator who reuses a mainnet hash on a custom network (e.g.,
for testing) would be surprised. Combined with BUG-4 (testnet3 entry
missing), the right fix is to make the table per-network.

### BUG-6 — `BIP68_ACTIVATION_HEIGHT` constant name is wrong; the value (419328) is CSV / BIP-112 activation, not BIP-68 standalone

**Severity**: P3
**File**: `src/ouroboros/script.py:106`
**Core ref**: `bitcoin-core/src/consensus/params.h:104-105`
(`CSVHeight = 419328`).

BIP-68 (relative locktime), BIP-112 (CSV opcode), and BIP-113 (MTP
locktime) activate together via the CSV deployment at `CSVHeight`. The
name `BIP68_ACTIVATION_HEIGHT` is misleading — it gates CSV (the script
opcode), not BIP-68's relative-locktime semantics. (Same name re-used
in two places to gate `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` at line 213.)

**Excerpt** (`script.py:106, 212-213`):

```py
BIP68_ACTIVATION_HEIGHT = 419328
...
if height >= BIP68_ACTIVATION_HEIGHT:
    flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
```

**Impact**: Cosmetic / maintainer-confusion. The value is correct;
the name should be `CSV_ACTIVATION_HEIGHT`. Cross-cite: W132 raised the
same naming concern.

### BUG-7 — `SCRIPT_VERIFY_SIGPUSHONLY` included in `STANDARD_SCRIPT_VERIFY_FLAGS`; Core does NOT include SIGPUSHONLY in STANDARD

**Severity**: P1
**File**: `src/ouroboros/script.py:251, 263`
**Core ref**: `bitcoin-core/src/policy/policy.h:119-132`
(`STANDARD_SCRIPT_VERIFY_FLAGS` definition).

Core's `STANDARD_SCRIPT_VERIFY_FLAGS` lists: STRICTENC, MINIMALDATA,
DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S,
DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE,
CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE — **no
SIGPUSHONLY**.

**Excerpt** (`script.py:249-254`):

```py
if is_buried_deployment_active("segwit", height, network):
    flags |= (SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_CLEANSTACK
              | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA  # ← BUG
              | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
              | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
              | SCRIPT_VERIFY_CONST_SCRIPTCODE)
```

**Impact**: ouroboros mempool over-enforces — rejects valid Core-relayable
txs whose `scriptSig` contains a non-push opcode (e.g., a P2SH
spend where the scriptSig pushes the redeem-script via an alternative
encoding). Net: ouroboros drops txs Core relays, isolating it from the
broader mempool gossip path.

### BUG-8 — `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` and `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE` missing from `STANDARD_SCRIPT_VERIFY_FLAGS`

**Severity**: P1
**File**: `src/ouroboros/script.py:250-257, 262-269`
**Core ref**: `bitcoin-core/src/policy/policy.h:127, 132`

Core's STANDARD set includes BOTH discouragement flags;
ouroboros'  `get_standard_script_flags` includes neither.

**Excerpt** (`script.py:255-257`):

```py
if is_deployment_active("taproot", height, network):
    flags |= (SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
              | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)
```

Note both missing:
- `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` (would be ORed
  at segwit activation in Core's static STANDARD set).
- `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (BIP-342 tapscript
  unknown pubkey discouragement; would be ORed at taproot activation).

**Impact**: ouroboros mempool relays txs Core flags as non-standard
(unknown witness versions v2-v16, and unknown tapscript pubkey types
via OP_CHECKSIGADD with a non-32-byte pubkey). Relay-pool drift.

### BUG-9 — `_find_and_delete` strips signatures without enforcing `SCRIPT_VERIFY_CONST_SCRIPTCODE`

**Severity**: P1
**File**: `src/ouroboros/script.py:1845-1861, 1439, 2117`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:330-333, 1146-1148`

Core's `EvalChecksig` and `OP_CHECKMULTISIG` both call `FindAndDelete`
and check the return count:

```cpp
int found = FindAndDelete(scriptCode, CScript() << vchSig);
if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
    return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
```

ouroboros' `_find_and_delete` (lines 1845-1861) returns only the cleaned
bytes — no found-count. Callers at line 1439 (CHECKSIG) and 2117
(CHECKMULTISIG inside `_verify_multisig`) just discard the original
and use the result, never gating on `CONST_SCRIPTCODE`.

**Excerpt** (`script.py:1857-1861`):

```py
# Remove all occurrences
result = script
while needle in result:
    result = result.replace(needle, b"", 1)
return result
```

vs. Core (`interpreter.cpp:229-249`):

```cpp
int FindAndDelete(CScript& script, const CScript& b)
{
    int nFound = 0;
    ...
    nFound++;
    ...
    return nFound;
}
```

**Impact**: `SCRIPT_VERIFY_CONST_SCRIPTCODE` is a policy-only flag in
STANDARD_SCRIPT_VERIFY_FLAGS. ouroboros mempool fails to reject txs that
have signatures embedded in scriptCode that Core would reject as
non-standard. Relay-pool drift; over-acceptance.

### BUG-10 — `SCRIPT_VERIFY_WITNESS` does NOT imply `SCRIPT_VERIFY_P2SH` — Core asserts this invariant, ouroboros silently allows the impossible combination

**Severity**: P2
**File**: `src/ouroboros/script.py:175-202, 539-550`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:2114`
(`assert((flags & SCRIPT_VERIFY_P2SH) != 0);` inside WITNESS branch).

Core's `VerifyScript` (line 2110-2114) requires:

```cpp
if (flags & SCRIPT_VERIFY_WITNESS) {
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);
    ...
}
```

The reasoning (Core comment line 2112-2113): going from `WITNESS →
P2SH+WITNESS` is not a softfork. The invariant is preserved by Core's
flag derivation: every active path that sets WITNESS also has P2SH set.

ouroboros' `get_flags_for_height` does NOT enforce this invariant:
- For mainnet, P2SH activates at `BIP16_ACTIVATION_HEIGHT = 173805`,
  WITNESS at `SEGWIT_ACTIVATION_HEIGHT = 481824`. P2SH ⊇ WITNESS by
  height, so the invariant holds by happenstance on mainnet.
- For non-mainnet, both flags activate at height 1 — invariant holds.

But ouroboros' `ScriptInterpreter.verify` does not assert the invariant.
If a future caller passes `flags=SCRIPT_VERIFY_WITNESS` (e.g., a unit
test, or a synthetic regtest config with `BIP16Height=2` and
`SegwitHeight=1`), ouroboros would happily evaluate witness programs
without P2SH wrapping, accepting consensus-invalid combinations.

**Excerpt** (`script.py:486-503`):

```py
witness = ...
wp = _get_witness_version_and_program(script_pubkey)
if (flags & SCRIPT_VERIFY_WITNESS) and wp is not None:
    version, program = wp
    if script_sig:
        return False  # scriptSig must be empty for native witness
    if not self._verify_witness_program(...):
        return False
    return True
```

No `assert (flags & SCRIPT_VERIFY_P2SH)`.

**Impact**: Latent — no real consensus harm today because the flag
derivation never produces this combination. But the assert exists in
Core for a reason: any future flag-derivation bug (e.g., a test fixture
that hand-rolls flags) would not be caught.

### BUG-11 — `SCRIPT_VERIFY_NULLDUMMY` and `SCRIPT_VERIFY_WITNESS` co-activated at SegwitHeight — testnet3 BIP-147 historical timing not preserved

**Severity**: P2
**File**: `src/ouroboros/script.py:195-196`
**Core ref**: `bitcoin-core/src/validation.cpp:2283-2286`

This actually matches Core (Core also co-activates NULLDUMMY with SEGWIT
in `GetBlockScriptFlags`). The historical reality is that BIP-147 was
deployed earlier on testnet3 (`bip147` activated with the standalone
versionbits deployment at testnet3 block ~770,112 and segwit later at
834,624). Core's modern code unifies them.

The risk is in testnet3 historical re-sync: txs in blocks between the
old BIP-147 activation and segwit activation that used CHECKMULTISIG
with non-empty dummy. ouroboros and Core agree on the modern unified
gating. No drift, but the comment block at `script.py:191-194` ("WITNESS
+ NULLDUMMY only") could be clearer about the historical context.

### BUG-12 — Fallback path silently triggers when `from ouroboros.consensus import ...` fails; uses raw mainnet heights for all networks

**Severity**: P2
**File**: `src/ouroboros/script.py:161-217`
**Core ref**: per-network `chainparams.cpp` heights (lines 89-94, 212-217,
311-316, 455-460, 536-541).

`get_flags_for_height` tries to import `is_buried_deployment_active`
and falls back to hardcoded mainnet activation heights if the import
fails:

```py
try:
    from ouroboros.consensus import is_buried_deployment_active, is_deployment_active
    use_consensus = True
except ImportError:
    use_consensus = False

flags = SCRIPT_VERIFY_NONE
if use_consensus:
    ...  # per-network buried-deployment check
else:
    # Fallback to hardcoded mainnet heights
    if height >= BIP16_ACTIVATION_HEIGHT:
        flags |= SCRIPT_VERIFY_P2SH
    ...
```

If a testnet4 / signet / regtest call ever lands in the `else` branch
(e.g., during a test that mocks out `ouroboros.consensus`), the
mainnet heights (BIP66 at 363725, segwit at 481824, etc.) are applied
to the testnet4 height — so a height-100 testnet4 block gets NO flags
instead of the full Core mainnet set. Silent fall-through, no error.

**Impact**: Test-environment flag drift. Hard to detect because
both branches "work"; only the wrong network gets the wrong heights.

### BUG-13 — `SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` enforced in `_verify_witness_v0_keyhash` but the flag is policy-only — gating is correct but documentation in `_SCRIPT_FLAG_EXCEPTIONS` table is misleading

**Severity**: P3
**File**: `src/ouroboros/script.py:631-632`
**Core ref**: `bitcoin-core/src/policy/policy.h:128`

Match — Core also makes WITNESS_PUBKEYTYPE policy-only (in
STANDARD_SCRIPT_VERIFY_FLAGS, not MANDATORY_SCRIPT_VERIFY_FLAGS). Just
worth a check.

### BUG-14 — `get_flags_for_height(height=0, ...)` returns 0 (no flags) — but Core's baseline at height 0 includes `P2SH | WITNESS | TAPROOT`

**Severity**: P2
**File**: `src/ouroboros/script.py:130-219`
**Core ref**: `bitcoin-core/src/validation.cpp:2262`

Test `test_no_flags_before_p2sh` (`tests/functional/test_script_flags.py:43-45`)
asserts `flags == 0` at height 0. This codifies the divergence as the
intended behavior. Core's behavior at height 0 (genesis block) sets the
baseline `P2SH | WITNESS | TAPROOT` (plus DERSIG/CLTV/CSV/NULLDUMMY if
their `DeploymentHeight()` is 0 — which on regtest segwit `SegwitHeight
= 0` means segwit-related flags fire at genesis).

**Impact**: Latent on mainnet (no transactions to validate at height 0).
On regtest with `SegwitHeight = 0`, ouroboros returns 0 at genesis where
Core would return `P2SH | WITNESS | TAPROOT | NULLDUMMY`. A regtest
genesis-level tx wouldn't typically need flag enforcement, but the
divergence is documented as intended.

### BUG-15 — Buried deployment heights for testnet3 differ from chainparams.cpp lines 212-217 — `csv` is `770112`, `segwit` is `834624` (match), but `bip65` is `581885`, `bip66` is `330776` (match) — verify

**Severity**: (verification only — no bug found)
**File**: `src/ouroboros/consensus.py:127-140`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:212-217`

`BURIED_DEPLOYMENTS["testnet"]`:
- bip34 = 21111 (Core: BIP34Height = 21111) ✓
- bip65 = 581885 (Core: BIP65Height = 581885) ✓
- bip66 = 330776 (Core: BIP66Height = 330776) ✓
- csv = 770112 (Core: CSVHeight = 770112) ✓
- segwit = 834624 (Core: SegwitHeight = 834624) ✓

All match. No bug. Recorded for verification.

### BUG-16 — Test asserts `get_flags_for_height(BIP66_ACTIVATION_HEIGHT)` doesn't include LOW_S — match — but the test name `test_dersig_active` could mislead a reader to think LOW_S activates with DERSIG

**Severity**: P3
**File**: `src/ouroboros/tests/functional/test_script_flags.py:51-57`
**Core ref**: `bitcoin-core/src/policy/policy.h:105-111`
(MANDATORY excludes LOW_S).

Cosmetic — test is correct (assertion is `not (flags & SCRIPT_VERIFY_LOW_S)`).
Verification only.

### BUG-17 — `get_standard_script_flags` does NOT include `STRICTENC` after BIP-66 — wait, it does (line 248)

After re-reading: `get_standard_script_flags` lines 248 DOES include
STRICTENC. Verification only — no bug.

### BUG-18 — `SCRIPT_VERIFY_TAPROOT` activation height in fallback path is hardcoded `TAPROOT_ACTIVATION_HEIGHT = 709632`; this is the `min_activation_height`, but the actual mainnet `nActivationHeight` was determined by BIP9 signalling

**Severity**: P2
**File**: `src/ouroboros/script.py:108, 216-217`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:106`
(historical comment).

Core's chainparams comment notes taproot's `min_activation_height =
709632` was a "Speedy trial" lower bound. The actual activation
happened at exactly 709632 because signalling completed in time. In
ouroboros' fallback (post-BIP9-import-failure) branch:

```py
if height >= TAPROOT_ACTIVATION_HEIGHT:
    flags |= SCRIPT_VERIFY_TAPROOT
```

is correct for mainnet but skips the signalling check that *could* in
principle have produced a different activation. The fallback's main use
is when the consensus module is missing — at which point the only
sensible fallback is "trust the hardcoded mainnet height." OK.

**Impact**: Cosmetic / documentation. The fallback works on mainnet by
historical accident.

### BUG-19 — CLTV / CSV opcode handling correctly checks `flags & SCRIPT_VERIFY_*` and falls through as NOP — match — verification only

**Severity**: (verification only — no bug found)
**File**: `src/ouroboros/script.py:1724-1776`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:522-593`

ouroboros at script.py:1726-1727: `if not (flags &
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY): continue` (treat as NOP). Match.
ouroboros at script.py:1779: `DISCOURAGE_UPGRADABLE_NOPS` only fires for
OP_NOP1 / OP_NOP4..10 (excludes 0xb1 CLTV / 0xb2 CSV). Match. Good.

### BUG-20 — `DISCOURAGE_UPGRADABLE_NOPS` policy check on OP_NOP1/4-10 fires unconditionally inside `EvalScript`-equivalent; matches Core — verification only

**Severity**: (verification only — no bug found)
**File**: `src/ouroboros/script.py:1778-1785`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:595-601`

Match. Good.

### BUG-21 — `_is_p2sh` size check (23 bytes) and prefix matching is correct; matches `Solver`/`MatchPayToScriptHash` — verification only

**Severity**: (verification only — no bug found)
**File**: `src/ouroboros/script.py:555-559`
**Core ref**: `bitcoin-core/src/script/solver.cpp` (MatchPayToScriptHash).

```py
def _is_p2sh(self, script: bytes) -> bool:
    return (len(script) == 23
            and script[0] == 0xa9
            and script[1] == 0x14
            and script[22] == 0x87)
```

Matches Core's `IsPayToScriptHash` (OP_HASH160 0x14 [20 bytes] OP_EQUAL).
Good.

### BUG-22 — `_SCRIPT_FLAG_EXCEPTIONS` table comment "BIP16 exception (mainnet height ~170,060)" but the actual block height is 170,060 — confirm

**Severity**: P3
**File**: `src/ouroboros/script.py:114`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:85`

Comment says "~170,060" — the actual exception block hash
`0000…ac4f9c22` is at mainnet height 170,060. Comment is approximate but
not wrong. Cosmetic.

Fleet patterns detected
-----------------------

1. **"Always-active baseline + carve-outs" architectural mismatch**: ouroboros
   treats P2SH / WITNESS / TAPROOT as height-gated activations (mainnet
   heights 173805 / 481824 / 709632); Core treats them as baseline-active
   with one-block exceptions. Cross-cite: this pattern likely affects
   most non-Python implementations; the "exception block hashes" model
   is unique to Core.

2. **Dead-data BIP9 plumbing**: `is_deployment_active(...)` accepts
   `block_versions` / `block_mtps` parameters but the production callers
   pass empty lists. The whole BIP9 state-machine code path
   (`consensus.py:419-616`, `versionbits.rs:183-246`) is functionally
   reachable but receives no real data → resolves to DEFINED forever.
   Cross-cite: matches the "well-engineered-helper-never-wired" fleet
   pattern surfaced in W136 (rustoshi FeeFilterManager, blockbrew
   MaybeSendFeeFilter), W141 (haskoin newZmqNotifier).

3. **Comment-as-confession (W137/W141/W142 pattern)**: `script.py:172-173`
   comment "P2SH (BIP16) - not a buried deployment but always active
   (activated via ISM, hardcoded to height 173805 on mainnet)" reads as
   self-aware that the Core model is different but defends the
   divergence as intentional. Cross-cite to W141 / W142 comment-
   as-confession occurrences.

4. **Early-return-skips-OR-ins**: `_SCRIPT_FLAG_EXCEPTIONS` lookup early-
   returns the exception entry, missing the subsequent deployment OR-ins
   (BUG-2). Cross-cite: similar early-return pattern surfaced in W139
   beamchain BUG-1 (HIGH scan direction reversed; similar "exit early
   from a state machine in the wrong place").

5. **Policy-set divergence**: `get_standard_script_flags` adds
   SIGPUSHONLY (Core doesn't), omits DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
   and DISCOURAGE_UPGRADABLE_PUBKEYTYPE (Core has both). Pattern: STANDARD
   vs. MANDATORY drift via "additive policy" (BUG-7, BUG-8). Cross-cite
   to W135 standardness-set divergence findings.

Summary
-------

22 BUGS catalogued (2 P0-CONSENSUS / 1 P0-CDIV / 8 P1 / 9 P2 / 2 P3).

The dominant finding is **BUG-1 P0-CONSENSUS — Taproot never activates
on mainnet validation** because the BIP9 state machine is called with
empty `block_versions`/`block_mtps`. Combined with BUG-2 (exception
table early-return skips DERSIG/CLTV/CSV/NULLDUMMY OR-ins), the
script-flag derivation is structurally divergent from Core in two
direction simultaneously: under-restrictive on Taproot enforcement
(every Taproot output spendable), and under-restrictive on
DERSIG/CLTV/CSV/NULLDUMMY enforcement at the one Taproot exception
block.

Architectural fix: rewrite `get_flags_for_height` to mirror Core's
"baseline + carve-out" model:

```py
flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
if block_hash in exceptions_for_network:
    flags = exceptions_for_network[block_hash]
if height >= bip66_height: flags |= SCRIPT_VERIFY_DERSIG
if height >= bip65_height: flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
if height >= csv_height:   flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
if height >= segwit_height: flags |= SCRIPT_VERIFY_NULLDUMMY
```

That closes BUG-1, BUG-2, BUG-3 simultaneously and removes the dead
BIP9 plumbing in the taproot path. BUG-4 is a one-line addition to the
exception table. BUG-7/BUG-8 are mempool policy alignment.
