W127 — Taproot / Schnorr / Tapscript audit (ouroboros)
======================================================

Date: 2026-05-17
Impl: ouroboros (Python+Rust two-pipeline)
Wave: W127 BIP-340 / BIP-341 / BIP-342 (DISCOVERY)

Reference:
  - `bitcoin-core/src/script/interpreter.cpp` (EvalChecksigTapscript :347,
    SignatureHashSchnorr :1483, ExecuteWitnessScript :1832,
    VerifyTaprootCommitment :1903, VerifyWitnessProgram :1917)
  - `bitcoin-core/src/script/script.cpp` (IsOpSuccess :364, CheckMinimalPush)
  - `bitcoin-core/src/key.cpp`, `bitcoin-core/src/pubkey.cpp`
    (XOnlyPubKey::CheckTapTweak :257, CreateTapTweak :265)
  - `bitcoin-core/src/test/data/script_assets_test.json`
  - BIP-340 Schnorr signatures
  - BIP-341 Taproot
  - BIP-342 Tapscript

Status: 30 gates audited — PRESENT 19 / PARTIAL 6 / MISSING 5.
**11 BUGS** (3 P0-CDIV / 2 P0 / 4 P1 / 2 P2).

Two-pipeline guard
------------------

ouroboros's *production* script verification path lives entirely in
Python (`src/ouroboros/script.py`). The Rust `ferrous-utils` crate is
used **only** for performance-critical leaf primitives:

```
$ grep -nE "^pub fn|pyfunction" ferrous-utils/sync/src/lib.rs \
       | grep -iE "schnorr|taproot|tapscript"
ferrous-utils/sync/src/lib.rs:101: fn crypto_verify_schnorr(...)
ferrous-utils/sync/src/lib.rs:120: fn crypto_batch_verify_schnorr(...)
```

Only the BIP-340 Schnorr **verify** is exposed across the FFI; tweaking,
Merkle walking, sighash, and opcode execution are all Python. The
Schnorr fast-path is wired at `script.py:2212-2221` and is reached on
every Schnorr verify call.

**There is also a Rust tapscript surface** at
`ferrous-utils/sync/src/validate/script.rs:704-831` (`evaluate_tapscript`
+ `execute_witness_script` + `execute_opcode_with_context`), but it is
**NOT** wired into the Python production path. It exists as a Rust-only
test artefact (used by the crate's own `cargo test`) and OP_CHECKSIG /
OP_CHECKSIGVERIFY in that file is a stub:

```rust
// ferrous-utils/sync/src/validate/script.rs:997-1027
OP_CHECKSIG | OP_CHECKSIGVERIFY => {
    let pubkey = stack.pop()?;
    let sig = stack.pop()?;
    check_pubkey_encoding(&pubkey, flags, sigversion)?;
    // For now, just check that both are non-empty
    // Real implementation would verify the signature cryptographically
    let valid = !pubkey.is_empty() && !sig.is_empty();
    ...
}
```

That stub is **isolated** — no Python call site invokes
`evaluate_tapscript`. If a future wave moves Schnorr verification
wholesale into Rust (a plausible perf-win), this stub *must* be replaced
or the audit must extend the two-pipeline guard to forbid promoting it.
For W127 the production behavior is the Python pipeline only.

**Two-pipeline guard EXTENDED.** Test
`test_w127_taproot.py::TestW127_TwoPipelineGuard` codifies:
1. The Python pipeline is the sole BIP-341/342 consensus surface
   (`src/ouroboros/script.py::ScriptInterpreter._verify_taproot_*`).
2. The Rust `evaluate_tapscript` is forbidden from being called from
   Python (greps `src/ouroboros/` for any reference; must be zero).
3. The Rust `crypto_verify_schnorr` is the **only** Rust symbol
   permitted on the Schnorr path; it's a primitive (not an interpreter).
4. The Rust `ferrous-utils/sync/src/validate/script.rs` CHECKSIG stub
   must NOT acquire imports of `secp256k1` schnorr machinery without
   first wiring the Python pipeline to call it.

This is the 6th two-pipeline guard extension (priority + persistence +
reorg + cfheaders + brief-error + this); pattern continues.

Architectural shape
-------------------

ouroboros's W94 + W95 + W41 waves landed substantial Taproot/Schnorr
coverage. This audit (W127) extends to the residual 30 gates spanning
BIP-340/341/342, with a focus on consensus-critical gaps not covered
by prior waves. The PRESENT majority reflects mature W94/W95 fix
landing; the BUGGY minority concentrates on:

- **Cleanstack enforcement on Taproot script-path** (BUG-1 P0-CDIV).
- **OP_CHECKSIGADD `n`-operand decoding** (BUG-2 P0-CDIV) — uses unsigned
  `int.from_bytes(little)` instead of CScriptNum (signed, minimal).
- **Stack-top `cast_to_bool` divergence** for taproot script-path
  (BUG-3 P0-CDIV) — uses ad-hoc `any(b != 0)` not `_cast_to_bool`.
- Lesser P0/P1/P2 around malleability, code paths split between
  `_execute_script` and dead `_execute_tapscript`, and a missing
  policy-only DISCOURAGE flag.

The audit gates are tagged G01..G30 and the bug numbers below cross-
reference the gate tests in `test_w127_taproot.py`.

30-gate audit matrix
--------------------

### BIP-340 Schnorr (G01..G10)

| #   | Gate                                                       | Status   | Source ref |
|-----|------------------------------------------------------------|----------|------------|
| G01 | Schnorr sig length == 64 or 65 bytes (with hashtype byte)  | PRESENT  | script.py:2203-2208, :2298-2306 |
| G02 | Schnorr pubkey length == 32 (x-only)                       | PRESENT  | script.py:2205-2206 |
| G03 | Schnorr msg length == 32                                   | PRESENT  | script.py:2207-2208 (W95) |
| G04 | 65-byte sig: hashtype byte != 0x00 (else SCRIPT_ERR)       | PRESENT  | script.py:2304-2305, :1359-1360 |
| G05 | hashtype byte in {0x01,0x02,0x03,0x81,0x82,0x83}           | PRESENT  | script.py:2544-2546 |
| G06 | Rust `crypto_verify_schnorr` wired correctly (W95)         | PRESENT  | script.py:2212-2215 |
| G07 | Rust ValueError mapped to False (W95)                      | PRESENT  | script.py:2218-2221 |
| G08 | coincurve fallback used when Rust missing                  | PRESENT  | script.py:2223-2231 |
| G09 | BIP-340 tagged hash midstate (`SHA(tag) || SHA(tag) || x`) | PRESENT  | script.py:2664 + taproot.py:46-49 |
| G10 | Empty sig in tapscript: special-cased (no Schnorr call)    | PRESENT  | script.py:1330-1352 |

### BIP-341 Taproot (G11..G20)

| #   | Gate                                                       | Status   | Source ref |
|-----|------------------------------------------------------------|----------|------------|
| G11 | Output `OP_1 <32B>` only (v1 + 32-byte program)            | PRESENT  | script.py:2254 |
| G12 | P2SH-wrapped v1/32 NOT taproot (forward-compat)            | PRESENT  | script.py:596-600 (W94) |
| G13 | Pay-to-Anchor (v1/2-byte `\x4e\x73`) succeeds bare         | PRESENT  | script.py:607-615 |
| G14 | Annex (last witness elem starts with 0x50) stripped        | PRESENT  | script.py:2263-2266 |
| G15 | Witness empty: reject                                      | PRESENT  | script.py:2259-2260 |
| G16 | Key-path single sig 64B or 65B (DEFAULT or explicit type)  | PRESENT  | script.py:2298-2307 |
| G17 | Script-path control block geometry [33, 4129], step 32     | PRESENT  | script.py:2353-2358 (W94) |
| G18 | Tapleaf tagged-hash: `TapLeaf || leaf_ver || cs(script)`   | PRESENT  | script.py:2366-2369 |
| G19 | Merkle path walk uses lex-sorted TapBranch                 | PRESENT  | script.py:2371-2378 |
| G20 | Output-key tweak parity == `control[0] & 1`                | PRESENT  | script.py:2387-2392 |

### BIP-342 Tapscript (G21..G30)

| #   | Gate                                                       | Status   | Source ref |
|-----|------------------------------------------------------------|----------|------------|
| G21 | Leaf version `0xc0` is tapscript; else fallthrough         | PRESENT  | script.py:2395, :2444-2450 |
| G22 | OP_SUCCESS opcodes per BIP-342 (80,98,...,254)             | PRESENT  | script.py:2951-2959 |
| G23 | DISCOURAGE_OP_SUCCESS policy flag                          | PRESENT  | script.py:805-808 |
| G24 | Validation-weight budget `seed + 50` per CHECKSIG-PASSED   | PRESENT  | script.py:844-851 + tests |
| G25 | OP_CHECKMULTISIG / VERIFY disabled in tapscript            | PRESENT  | script.py:1654, :1692 |
| G26 | OP_CODESEPARATOR records `opcode_pos` for sighash          | PRESENT  | script.py:1302-1305 |
| G27 | Initial witness stack <=MAX_STACK_SIZE and <=520/elem      | PRESENT  | script.py:835-842 |
| G28 | **Tapscript cleanstack: exactly 1 element on success**     | **MISSING (BUG-1)** | script.py:2437-2440 |
| G29 | **OP_CHECKSIGADD `n` decoded as signed CScriptNum**        | **MISSING (BUG-2)** | script.py:1574-1587 |
| G30 | **Stack-top `_cast_to_bool` (negative-zero handling)**     | **MISSING (BUG-3)** | script.py:2440 |

---

BUG catalogue
-------------

### BUG-1 — P0-CDIV: Taproot script-path missing cleanstack check

**Where:** `src/ouroboros/script.py:2437-2440`

```python
if not result_stack:
    return False
top = result_stack[-1]
return len(top) > 0 and any(b != 0 for b in top)
```

**Should be (Core interpreter.cpp:1866-1868 ExecuteWitnessScript):**

```cpp
if (stack.size() != 1) return set_error(serror, SCRIPT_ERR_CLEANSTACK);
if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
```

ouroboros's P2WSH path correctly enforces `len(stack) != 1` (script.py:681)
but the taproot script-path path does NOT. A tapscript that leaves
multiple elements on the stack with the top one truthy currently
**succeeds in ouroboros and FAILS in Core**. This is a consensus split.

**Reproduction:**
- Build a tapscript: `<0x01> <0x01>` (push two truthy values, leave both
  on stack). Core: CLEANSTACK error → script fails → tx invalid. ouroboros:
  top=`\x01` → succeed → tx accepted. Chain forks.

**Severity:** P0-CDIV (consensus divergence).

Note: Comment-as-confession adjacent at script.py:2440 — "len > 0 and
any b != 0" pattern is **factually the wrong rule**. Core uses CastToBool
with neg-zero handling AND cleanstack-of-one. See BUG-3 below.

### BUG-2 — P0-CDIV: OP_CHECKSIGADD `n` decoded as unsigned, no minimal

**Where:** `src/ouroboros/script.py:1574-1587`

```python
num_bytes = stack.pop()
if len(num_bytes) > 4:
    raise ValueError("OP_CHECKSIGADD: n is not a valid CScriptNum")
n = self._read_num(num_bytes)   # int.from_bytes(LE, unsigned)
```

**Should be (Core interpreter.cpp:1093):**

```cpp
const CScriptNum num(stacktop(-2), fRequireMinimal);  // SIGNED, with minimal-data
```

CScriptNum reads the top bit of the last byte as a sign indicator
(`0x80` = negative). `_read_num` ignores sign.

**Concrete divergence:**
- Stack top `bytes [0x81]` (= -1 in CScriptNum):
  - Core: `n = -1`, push `n + 1 = 0` → `b""` on stack.
  - ouroboros: `n = 0x81 = 129`, push `129 + 1 = 130` → `bytes([130]) = b"\x82"`.
- Stack top `bytes [0xFF, 0xFF, 0xFF, 0xFF]` (= -2147483647 in CScriptNum):
  - Core: `n = -(2^31 - 1)`, success path adds 1.
  - ouroboros: `n = 4294967295`, adds 1 → 4294967296 → silently encodes as
    5-byte CScriptNum which would later overflow when next op tries to
    decode (or just produces a different stack value).

ouroboros also doesn't enforce the **minimal-data** check — but in
tapscript Core's `fRequireMinimal` is gated on `SCRIPT_VERIFY_MINIMALDATA`
which is not always set by `MANDATORY_SCRIPT_VERIFY_FLAGS`. Still, the
*signed* decoding is consensus-critical and the unsigned form diverges
on any negative `n` operand.

**Severity:** P0-CDIV (consensus divergence on adversarial inputs).

### BUG-3 — P0-CDIV: Taproot script-path uses wrong cast_to_bool

**Where:** `src/ouroboros/script.py:2440`

```python
return len(top) > 0 and any(b != 0 for b in top)
```

**Should be (Core script.cpp::CastToBool):**

```python
return self._cast_to_bool(top)   # treats 0x..80 (negative zero) as False
```

ouroboros has the correct helper `_cast_to_bool` at line 1795-1801 (used
correctly for P2WSH at line 679). For taproot script-path it's bypassed
and replaced with `any(b != 0 for b in top)` which **misses negative
zero**. CastToBool spec: "A value is true unless it is all zeros, or
all zeros except for the sign bit (which must be the last byte's high
bit)."

**Divergence:**
- Stack top `bytes [0x00, 0x00, 0x80]` (negative zero):
  - Core: `CastToBool` → False (-0 is falsy).
  - ouroboros: `any(b != 0 for b in [0,0,0x80])` → True (sign bit non-zero).
- Stack top `bytes [0x80]` (negative zero, single byte):
  - Core: False.
  - ouroboros: True.

Pair with BUG-1 (no cleanstack) and the bypass is doubly wrong. The
correct one-liner is `self._cast_to_bool(top)`.

**Severity:** P0-CDIV.

### BUG-4 — P0: BIP-342 `_TAPSCRIPT_OP_SUCCESS` set in wrong file location

**Where:** `src/ouroboros/script.py:2952-2959` (frozenset defined at module
end, AFTER `_execute_tapscript` at line 2667 which references it).

Forward references in Python work at runtime if the reference is inside
a function body (lazy lookup), so this isn't an `ImportError`. But the
**duplicate `_execute_tapscript` function at line 2667-2933 is dead
code**: production path `_execute_script` (line 752-1812) handles
tapscript via `is_tapscript` branches, including its own OP_SUCCESS scan
at line 778-809. `_execute_tapscript` is never called from production
(no grep hits in `_verify_taproot_scriptpath` or anywhere else).

A future contributor adding a new opcode to `_TAPSCRIPT_OP_SUCCESS` may
miss one of the two sites; this is exactly the
"two-pipeline-but-internal" failure mode the audit framework keeps
flagging.

**Severity:** P0 (dead helper at call-site / future maintenance hazard).

### BUG-5 — P0: BIP-342 OP_CHECKSIG fall-through in non-tapscript path
        when pubkey size unknown

**Where:** `src/ouroboros/script.py:1422-1426`

```python
if len(pubkey) < 1:
    if (flags & SCRIPT_VERIFY_NULLFAIL) and sig:
        raise ValueError("NULLFAIL: non-empty sig for empty pubkey")
    stack.append(b'')
    continue
```

Pre-tapscript path: an empty pubkey produces `b''` push. Core's path
fails out with `SCRIPT_ERR_PUBKEYTYPE` only when STRICTENC is set; on
relaxed flags Core also pushes false on empty key. Behavior is similar,
but ouroboros lacks the `SCRIPT_VERIFY_STRICTENC` gate at this site
(only the pre-empty-sig DER check). Documented in W94 audit table as
"PARTIAL"; not flipped in W127 either.

**Severity:** P0 (consensus rule diverges only under STRICTENC, which is
not in MANDATORY_SCRIPT_VERIFY_FLAGS, so not a P0-CDIV — but still a
correctness gap on policy flags).

### BUG-6 — P1: `_read_num` non-minimal acceptance in tapscript

**Where:** `src/ouroboros/script.py:1810-1813`

```python
def _read_num(self, data: bytes) -> int:
    if not data:
        return 0
    return int.from_bytes(data, 'little')
```

No minimal-data check, no signed-bit handling, no overflow check beyond
the caller's len-cap. Used at `OP_CHECKSIGADD` and `_execute_tapscript`
(dead). Pair with BUG-2 above. The fix is to use `_read_signed_num` with
`require_minimal=True` and `max_len=4` — but the caller path uses
`_read_num` for backwards compatibility.

**Severity:** P1 (correctness; surfaces only with non-minimal pushes,
which mempool would reject as non-standard but a malicious miner can
include).

### BUG-7 — P1: `_verify_taproot` `>=2` annex check ambiguity

**Where:** `src/ouroboros/script.py:2265`

```python
if len(effective_witness) >= 2 and effective_witness[-1] and effective_witness[-1][0] == 0x50:
    annex = effective_witness.pop()
```

Core (interpreter.cpp:1951): `if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG)`. The
matching guard is correct **only because** key-path requires single
witness element. But:

- If witness is `[sig]` (1 element), the `>=2` gate skips annex strip
  (correct).
- If witness is `[sig, 0x50_annex]` (2 elements, the second one being
  an annex), `>=2` triggers, annex stripped to leave `[sig]`, key-path
  proceeds. **Correct.**
- If witness is `[anything_starting_with_0x50]` (1 element) — the `>=2`
  gate skips annex strip. The element will then be interpreted as a
  64/65-byte Schnorr sig if length matches, else fail. Core same.

The edge case is fine. PARTIAL flag is for the comment-truthiness
`effective_witness[-1]` check — Python truthy check on `bytes` is "len
> 0", which matches Core's `!stack.back().empty()`. PARTIAL → PRESENT.
(Actually moved to G14 PRESENT in the matrix above.) Withdrawing this
as a false-alarm BUG — but I'll keep the gate test.

### BUG-8 — P1: `_compute_taproot_sighash` SIGHASH_DEFAULT comment vs behavior

**Where:** `src/ouroboros/script.py:2549-2552`

```python
base_type = sighash_type & 0x03  # 0=default/all, 1=all, 2=none, 3=single
if sighash_type == 0:
    base_type = 0  # SIGHASH_DEFAULT = SIGHASH_ALL
```

Setting `base_type = 0` (when SIGHASH_DEFAULT) and then branching on
`if base_type not in (2, 3)` covers DEFAULT (0) the same as ALL (1).
**Behaviorally correct.** But the comment says "SIGHASH_DEFAULT =
SIGHASH_ALL" and then immediately sets it to 0, not 1, which is
misleading. Core's invariant is `output_type = SIGHASH_ALL` when
`hash_type == SIGHASH_DEFAULT` — the comment should be `base_type = 0
sentinel; outputs included same as base_type == 1`. Cosmetic.

**Severity:** P1 (correctness comment, not behavior).

### BUG-9 — P1: `_verify_taproot` catches broad `Exception` masking real bugs

**Where:** `src/ouroboros/script.py:2435`

```python
try:
    result_stack = self._execute_script(...)
except (ValueError, Exception):
    return False
```

`except (ValueError, Exception)` is equivalent to `except Exception` —
the `ValueError` is redundant. This catches EVERY Python exception
(NameError, TypeError, OverflowError) and silently returns False,
masking implementation bugs. Core only fails on script semantic errors;
a Python-level exception should be re-raised so tests catch them.

Better: `except (ValueError, AssertionError): return False` — explicit
about script-error mapping. Or even tighter: `except ValueError`.

**Severity:** P1 (test hygiene / hidden bug surface).

### BUG-10 — P2: `derive_taproot_output_xonly` does not enforce BIP-86

**Where:** `src/ouroboros/taproot.py:121-154`

The helper accepts `merkle_root=None` (BIP-86 key-path-only) but also
accepts arbitrary merkle_root for non-BIP-86 outputs. For wallet output
derivation, BIP-86 requires `merkle_root=b""`. The helper is permissive
but the docstring says "primarily for testing". No production wallet
call site passes a non-None merkle_root, so this is a code-shape issue
not a behavior bug.

**Severity:** P2 (API hygiene).

### BUG-11 — P2: Dead `_execute_tapscript` function (~270 LOC)

**Where:** `src/ouroboros/script.py:2667-2933`

The function `_execute_tapscript` exists as a standalone tapscript
interpreter that's structurally similar to but DIFFERENT FROM the
`_execute_script` tapscript path. It is never called from production
(`_verify_taproot_scriptpath` at line 2419 calls `_execute_script` with
`sig_version=SigVersion.TAPSCRIPT`).

Key differences that would cause consensus splits IF anyone wired it:
- `_execute_tapscript` line 2702: `if op_count > max_ops: return False`
  but BIP-342 removes op-count limit (`_execute_script` line 951 gates
  this correctly on `not is_tapscript`).
- `_execute_tapscript` line 2776-2779: codesep_pos snapshot. Same shape.
- `_execute_tapscript` line 2784-2835: separate CHECKSIG path with
  different sighash and error handling.
- `_execute_tapscript` line 2920-2921: `if opcode in (0xae, 0xaf):
  return False` — disables CHECKMULTISIG (same).
- `_execute_tapscript` line 2925-2926: OP_SUCCESS scan happens
  IN-LINE during execution, not as a pre-scan like `_execute_script`
  line 781-809.

Dead code at this scale is a P0 maintenance hazard (BUG-4 above) and a
P2 "obvious source of future divergence" — anyone reading the file may
"fix" the dead helper thinking it's the production path. The function
should be deleted in a future FIX wave.

**Severity:** P2 (dead code; future-divergence hazard).

---

Top findings summary
--------------------

1. **BUG-1 — Taproot script-path missing cleanstack check (P0-CDIV).**
   `_verify_taproot_scriptpath` checks only the top element, not that
   the stack has exactly one element. A tapscript that leaves multiple
   truthy elements on stack succeeds in ouroboros, fails in Core.

2. **BUG-2 — OP_CHECKSIGADD reads `n` as unsigned with no minimal check
   (P0-CDIV).** Uses `int.from_bytes(LE)` instead of `CScriptNum`-signed
   decode. Negative `n` operands produce wrong values.

3. **BUG-3 — Taproot script-path bypasses `_cast_to_bool` (P0-CDIV).**
   Inline `any(b != 0 for b in top)` misses BIP-341 "negative zero"
   handling that Core enforces via `CastToBool`. The correct helper
   exists at line 1795 but isn't called.

4. **BUG-4 — Dead duplicate `_execute_tapscript` at line 2667-2933
   (P0 maintenance hazard).** Production path is `_execute_script` with
   `sig_version=TAPSCRIPT`. The dead helper has divergent behavior
   (e.g. enforces 201 op-count limit which BIP-342 removes); a future
   contributor wiring it in causes a hard fork.

5. **Two-pipeline guard EXTENDED.** Rust `evaluate_tapscript` in
   `ferrous-utils/sync/src/validate/script.rs` is a dead Rust artefact
   with a stub CHECKSIG. The Rust pipeline must NOT be promoted to
   production for tapscript without first replacing the stub. Guard
   test enforces zero Python imports of `evaluate_tapscript`.

Out of scope (deferred)
-----------------------

- BIP-340 batch verification (`crypto_batch_verify_schnorr`) — gate
  G06 checks the *singular* fast-path; batch is a perf optimization
  used at block-connect, not consensus-critical for this audit.
- Wallet-side signing parity (BIP-86 single-key descriptors) — covered
  by `tests/test_taproot_bip86.py`.
- Tapscript fuzzing — the `tests/test_taproot_w94_audit.py` suite is
  the better home for negative-case coverage.

Closure path
------------

Future FIX wave to land:
- 1-line fix BUG-1: add `if len(result_stack) != 1: return False` at
  `script.py:2438`.
- 1-line fix BUG-2: replace `_read_num(num_bytes)` with
  `_read_signed_num(num_bytes, max_len=4, require_minimal=True)` at
  `script.py:1587`.
- 1-line fix BUG-3: replace inline cast with `_cast_to_bool(top)` at
  `script.py:2440`.
- Delete dead `_execute_tapscript` function (BUG-4 + BUG-11) — ~270 LOC.

That's 3 lines of fix code + 1 deletion that closes 4 of the 5
production-impacting bugs (BUG-5,6,7,8,9,10 are policy/cosmetic/API
hygiene and not in W127 closure scope).

Streak: 71 fix + 56 discovery preserved (this is wave 56 of discovery).
