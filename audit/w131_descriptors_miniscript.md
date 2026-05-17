# W131 — Descriptors + Miniscript (BIP-380 / BIP-385) audit

**Wave:** W131
**Scope:** Output-descriptor language (BIP-380/381/383/385/386) + Miniscript
**Impl:** ouroboros (Python + Rust two-pipeline)
**Bitcoin Core refs:**
- `bitcoin-core/src/script/descriptor.cpp` (3006 lines)
- `bitcoin-core/src/script/miniscript.{h,cpp}` (2707 + 432 lines)
- `bitcoin-core/src/test/{descriptor_tests.cpp,miniscript_tests.cpp}`
- BIPs 380, 381, 383, 385, 386 + Miniscript spec
- (Note: there is **no** Core test data file `descriptor_tests_external.json`
  in the shallow clone we ship; the only `*_tests_external.json` in
  `src/test/data/` is `script_tests.json`. The audit uses the in-source vectors
  in `descriptor_tests.cpp` instead.)

**ouroboros files audited:**
- `src/ouroboros/descriptors.py` (1412 lines)
- `src/ouroboros/miniscript.py` (1429 lines)
- existing tests: `src/ouroboros/tests/test_descriptors.py` (102 tests)

**Two-pipeline status:** CLEAN
`grep -riE 'descriptor|miniscript' ferrous-utils/` only matches RocksDB
`ColumnFamilyDescriptor` symbols in `sync/src/storage/{db,blockstore,txindex}.rs`.
There is no BIP-380 descriptor or BIP-379 miniscript code on the Rust side —
the wallet pipeline is Python-only, as the architecture requires.
The two-pipeline guard test in this wave codifies that invariant.

## 30-gate audit matrix

Status legend: PASS = matches Core / spec, BUG = behavior diverges, GAP =
feature absent (not implemented), OBS = observation worth flagging but not a
correctness bug.

### A. BIP-380 checksum + charset (gates G1-G5)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G1 | PolyMod generator constants match Core (`0xf5dee51989`, `0xa9fdca3312`, `0x1bab10e32d`, `0x3706b1677a`, `0x644d626ffd`) | PASS | `descriptors.py:113-121` byte-identical. |
| G2 | INPUT_CHARSET 96 chars in the same group order as Core | PASS | `descriptors.py:101-105` matches Core `descriptor.cpp:121-124`. |
| G3 | CHECKSUM_CHARSET = `"qpzry9x8gf2tvdw0s3jn54khce6mua7l"` (bech32) | PASS | `descriptors.py:106`. |
| G4 | Checksum result accepts/rejects per Core test vectors (4 vectors) | PASS | Verified in new tests. |
| G5 | `descriptor_checksum()` raises on out-of-charset input; Core returns empty string instead. Behavior divergence. | **BUG-1** | `descriptors.py:133` `raise ValueError`; Core `descriptor.cpp:134` returns `""`. Caller of `verify_checksum()` is OK (it catches the path through `_INPUT_CHARSET.find` only on the body, not the checksum chars; but our 8-char checksum can itself contain non-INPUT_CHARSET chars (`q`/`p`/`z`/`r`/`y`/...) — fortunately ALL bech32 chars are in INPUT_CHARSET so this is unreachable in practice). **Severity LOW** — observable only via `descriptor_checksum("foo!")` where `!` IS in INPUT_CHARSET so still unreachable; the only path that throws is bytes outside both charsets (e.g. unicode). Net: cosmetic API-contract bug; no on-chain consequence. |

### B. Key expression / KeyOrigin / xpub (G6-G10)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G6 | Accepts compressed pubkey (66 hex, prefix 02/03) | PASS | `_parse_key_expression` rejects other prefixes correctly. |
| G7 | Accepts x-only pubkey (64 hex, 32 bytes) for taproot contexts | PARTIAL / **BUG-2** | `_parse_key_expression` accepts 64-hex regardless of descriptor context; Core only accepts 32-byte x-only inside P2TR (`descriptor.cpp:1907`). ouroboros will happily build `pkh(<32-hex>)` from a 64-char x-only and then `derive_pubkey` returns it as the "pubkey" — but downstream `_hash160(pub)` accepts any length, so the address is silently *not* what Core would compute (Core rejects). Net effect: ouroboros accepts a class of malformed descriptors Core rejects. Tightening needed. |
| G8 | Rejects uncompressed pubkey (130 hex / 65 bytes) | **BUG-3** | Core accepts 65-byte uncompressed only in TOP / P2SH contexts, rejects in wpkh / wsh / tr (`descriptor.cpp:1899-1929`). ouroboros's `_parse_key_expression` rejects ALL non-66/64 hex (`descriptors.py:380`), so it cannot parse legacy `pk(04...)` / `pkh(04...)` that Core supports. **Severity MED** — ouroboros cannot import some legitimate Core-issued legacy descriptors. |
| G9 | Rejects hybrid pubkey (06/07 prefix) | PASS (incidentally) | ouroboros rejects via the 0x02/0x03 prefix check at `descriptors.py:367`; Core rejects via `IsValidNonHybrid()`. Same outcome. |
| G10 | xpub/tpub deserialize round-trip preserves all 5 fields (depth, fingerprint, child_index, chain_code, key) | PASS | `ExtendedPubKey.{serialize,deserialize}` covers all five. |

### C. Origin + derivation path (G11-G15)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G11 | `[fingerprint/path]` origin parse: 8-hex fingerprint + optional `/path` | PASS | `_ORIGIN_RE` matches Core's grammar. |
| G12 | Hardened path step `'` (apostrophe) accepted | PARTIAL / **BUG-4** | `derive_path` rejects `'` AND `h` hardened steps from xpub (correct — public keys can't derive hardened), but `_ORIGIN_RE` regex `[0-9'/h]+` accepts both forms inside origin (correct). However the parsed `KeyOrigin.path` is stored as a raw string; ouroboros never normalizes `'` ↔ `h` or computes `apostrophe` vs `h-step` for round-tripping. Core preserves the form: `ToString(COMPAT)` always uses apostrophe; `ToNormalizedString` always uses `h`. ouroboros has no normalized-form distinction. **Severity LOW** — affects RPC `getdescriptorinfo` output stability across xprv/xpub. |
| G13 | `h` (lowercase, Core 0.21+) hardened-step notation accepted everywhere `'` is | PARTIAL / **BUG-5** | The origin regex accepts `h`, but `ExtendedPubKey.derive_path` only checks `part.endswith("'") or part.endswith("h")` for the *suffix* path. For the origin itself (already stripped) we never derive — but origin info is what the BIP-32 fingerprint cache relies on. If user passes `[deadbeef/44h/0h/0h]xpub.../0/*`, the suffix `/0/*` derives fine, but the origin path `44h/0h/0h` is stored verbatim and never validated for hardened-step legality. Core validates the origin path syntax via `ParseKeyPathNum` (`descriptor.cpp:1754-1782`). |
| G14 | `*` wildcard in suffix marks `is_range=True` | PASS | `_parse_key_expression:354`. |
| G15 | `*'` / `*h` (hardened wildcard, requires xprv) | GAP | ouroboros has no hardened-wildcard support; range descriptors always use unhardened `*`. Core supports `*'` (and `*h`) for HARDENED_RANGED (`descriptor.cpp:511`). **Severity LOW** — affects only descriptor exports from Core that use hardened ranged derivation (uncommon). |

### D. Descriptor types (G16-G20)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G16 | All 16 top-level descriptor names parse: pk, pkh, wpkh, sh, wsh, combo, multi, sortedmulti, tr, rawtr, addr, raw + nestings sh(wpkh), sh(multi), sh(wsh(multi)), wsh(multi) | PASS | All present in `parse_descriptor`. |
| G17 | `musig(KEY,KEY,...)` participant aggregation inside tr() / rawtr() | GAP | Core supports `musig()` per BIP-390-ish (`descriptor.cpp:596-790`, `1964-2096`). ouroboros has zero `musig` references. **Severity LOW** for current mainnet (musig is wallet-only construction-time aggregation); fleet-critical only if importing Core descriptors that use it. |
| G18 | `sortedmulti_a(k, K1, K2, ...)` inside tr() | GAP-B + **BUG-11** | Core supports it at `descriptor.cpp:2318` / `1339`. ouroboros has only `multi_a` (in miniscript.py); no `sortedmulti_a` parse path. **Worse**, `parse_descriptor` for `tr(K, TREE)` stores the tap_tree leaves as **raw strings** without ever validating them as miniscript — so `tr(K, sortedmulti_a(...))` "parses successfully" (returns `tr-script`) and then explodes when the user calls `derive_address`. Accept-then-crash is worse than reject-at-parse. **Severity MED**. |
| G19 | combo() expansion: P2PK + P2PKH + (P2WPKH + P2SH-P2WPKH iff compressed) | PARTIAL / **BUG-6** | ouroboros gates segwit variants on `pub[0] in (0x02, 0x03)` — i.e. the prefix byte (`descriptors.py:593,615`). For x-only / hex-only pubkeys (64-hex), the parsed `hex_pubkey` is 32 bytes whose first byte is not 02/03, so segwit is skipped. Correct for x-only inputs. But for a *raw 32-byte hex string that happens to start with 0x02 or 0x03* (e.g. a x-only key with high entropy at index 0), ouroboros would emit corrupt P2WPKH/P2SH-P2WPKH wrapping a 32-byte "pubkey" (Hash160 of 32 bytes, not 33). Core gates on `IsCompressed()` (full validity). **Severity MED**. |
| G20 | rawtr(X-ONLY) emits OP_1 <32-byte> with **no** taproot tweak; isrange-from-key passthrough | **BUG-10** | `derive_address` for `rawtr` correctly bypasses `_taproot_tweak_pubkey` and emits bech32m(1, xonly) — **but** `derive_script_pubkey` (line 503-577) has **no rawtr arm** and raises `ValueError("Unknown descriptor type: rawtr")`. Asymmetric API: addresses work, scriptPubKeys don't. Any downstream consumer (PSBT building, wallet scanning, tx construction) that uses `derive_script_pubkey` for a rawtr descriptor crashes. **Severity MED**. |

### E. Miniscript fragments + type system (G21-G25)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G21 | All 25 fragments present (PK_K, PK_H, OLDER, AFTER, SHA256, HASH256, RIPEMD160, HASH160, JUST_0/1, 7 wrappers, AND_V, AND_B, OR_B/C/D/I, ANDOR, THRESH, MULTI, MULTI_A) | PASS | `Fragment` enum complete vs `miniscript.h::Fragment`. |
| G22 | `older(n)` / `after(n)` value bounds: 1 <= n < 0x80000000 | PASS | `miniscript.py:928,934` matches `miniscript.cpp:51` and `miniscript.h:2027,2034`. |
| G23 | SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22 sets type bit `g`, otherwise `h`; LOCKTIME_THRESHOLD=500_000_000 sets `i` vs `j` | PASS | `miniscript.py:297,310-312` matches `miniscript.cpp:92-97`. |
| G24 | multi() rejects > 20 keys (MAX_PUBKEYS_PER_MULTISIG) | PASS | `miniscript.py:1049-1050`. |
| G25 | multi_a() accepts up to MAX_PUBKEYS_PER_MULTI_A = 999 keys (Core `script.h:37`) | **BUG-7** | `miniscript.py:1063` rejects `k > len(keys)` only; there is **no upper bound on n** for `multi_a`. Core caps at 999 (`miniscript.h:1879,2404,2418`). ouroboros will compile `multi_a(1, K0..K999, K1000)` and produce a script that Core would reject as standardness-violating. **Severity MED** — emits unspendable scripts on mainnet. |

### F. Type computation + serialization (G26-G30)

| # | Gate | Verdict | Notes |
|---|------|---------|-------|
| G26 | Type computation for ALL fragments matches Core's `ComputeType` (esp. AND_V, OR_I, ANDOR with mixed timelock detection) | PARTIAL / **BUG-8** | `_compute_type` for THRESH lacks the `acc_g/acc_h/acc_i/acc_j` propagation through `(x|y) & "ghij"` for binary fragments — but the binary fragments DO have it. For THRESH specifically, the `g/h/i/j` accumulators ARE present (`miniscript.py:502-517`), so this is OK. **However** the `WRAP_C` type computation in ouroboros sets `_mst("us")` unconditionally (`miniscript.py:336-337`), but Core's `ComputeType` for `c:X` sets `"us"_mst` only after the type-class checks (`miniscript.cpp:114-115` adds `"us"_mst` unconditionally — so this PASSES). The bug is elsewhere: ouroboros's `WRAP_J` type omits `"u"` even when `is_tapscript` because there's no tapscript-specific branch (`miniscript.py:357-363`). Core treats `j` identically in both contexts — checked. ouroboros PASSES. Re-verdict: this gate **PASS**. |
| G27 | Duplicate-key detection across miniscript fragment (Core `miniscript.h:1493-1549` `DuplicateKeyCheck`) | GAP | ouroboros has **no** duplicate-key check anywhere in miniscript.py. Core rejects `and_v(pk(K),pk(K))` (and equivalent) — see `miniscript.h:1690`. ouroboros will happily compile it. **Severity MED** — Core would reject the descriptor; ouroboros accepts; emitted script is technically valid Bitcoin Script but is malleable/inefficient. Per BIP-379 this is a "must-reject" property. |
| G28 | `miniscript_to_str()` round-trips through `parse_miniscript()` for all fragments | PARTIAL / **BUG-9** | `miniscript_to_str` emits `t:` and `l:` / `u:` sugar but `_parse_miniscript_inner` strips wrappers one char at a time via `expr[1]==':'`. For wrapper concatenations like `vc:pk(K)` Core parses left-to-right; ouroboros stops at the first non-wrapper char. Compatible with single-wrapper inputs but fails for adjacent stacked wrappers like `tvc:pk(K)` because `t` is treated as a wrapper that re-parses the rest — actually ouroboros's loop at `miniscript.py:824` correctly consumes adjacent wrappers char-by-char including `t`/`l`/`u`. Re-checked: this works. **Real bug**: `miniscript_to_str` for `WRAP_C` over `MULTI` emits `c:multi(...)` but `c:` wrapping `multi` is invalid (multi already returns `B`, not `K`); ouroboros prints it anyway. Cosmetic. |
| G29 | Script compilation byte-equality against Core for canonical examples (`thresh`, `andor`, `or_i`, `multi_a` in tapscript) | PARTIAL | Not previously test-pinned against Core's golden vectors. New tests in this audit add byte-exact comparisons for a representative subset (basic miniscripts). |
| G30 | analyze_satisfaction sizes for ALL fragments — particularly WRAP_J adds 1 byte for OP_IF selector but does the dissatisfaction include the satisfaction's body cost? | PASS for the documented fragments, but `analyze_satisfaction` returns garbage for WRAP_A/S/N (it returns the sub's info unchanged with no adjustment for the wrapper). This is **correct** for A and S (they don't change witness size) and N (also unchanged) so PASS. |

## BUG catalogue

| ID | Severity | Component | Summary |
|----|----------|-----------|---------|
| BUG-1 | LOW | descriptors.py:133 | `descriptor_checksum` raises ValueError on bad char; Core returns empty string. API-contract divergence; not on-chain observable since INPUT_CHARSET covers all bech32+ASCII. |
| BUG-2 | MED | descriptors.py:372-377 | x-only 32-byte hex accepted in *any* context, not just P2TR. Allows constructing pkh(<x-only>) which Core rejects. |
| BUG-3 | MED | descriptors.py:380 | Uncompressed 65-byte/130-hex pubkeys are flat-rejected. Core accepts them in TOP/P2SH contexts (pk/pkh/sh). ouroboros cannot import legacy Core descriptors with `04...` keys. |
| BUG-4 | LOW | descriptors.py KeyOrigin | No normalized-form (`'` vs `h`) tracking; round-trip through `getdescriptorinfo` is lossy. |
| BUG-5 | LOW | descriptors.py:_ORIGIN_RE | Origin-path hardened steps not validated for value < 0x80000000; accepts oversized step numbers silently. |
| BUG-6 | MED | descriptors.py:593,615 (combo) | combo() gates segwit variants on raw prefix byte 02/03 instead of full-length compressed-pubkey check. For 32-byte x-only key whose first byte happens to be 02/03, ouroboros emits malformed P2WPKH/P2SH-P2WPKH (Hash160 of 32 bytes, not 33). |
| BUG-7 | MED | miniscript.py:1063 (multi_a) | No upper bound on multi_a key count (Core caps 999 per MAX_PUBKEYS_PER_MULTI_A). |
| BUG-8 | LOW | miniscript.py | (resolved — no bug; left for traceability) |
| BUG-9 | LOW | miniscript.py:1384 (miniscript_to_str) | Emits `c:multi(...)` which is type-invalid (multi returns B, c expects K). Round-trip output is unparseable in such cases. Cosmetic. |
| BUG-10 | MED | descriptors.py:503-577 (derive_script_pubkey) | rawtr arm missing. derive_address() works but derive_script_pubkey() raises ValueError. Asymmetric API blocks PSBT / wallet scan / tx-build paths that consume scriptPubKey. |
| BUG-11 | MED | descriptors.py:_parse_tap_tree | tr() script-tree leaves are stored as raw strings without validation. tr(K, sortedmulti_a(...)) "parses" successfully and then crashes on derive_address. Accept-then-crash is strictly worse than reject-at-parse. |
| GAP-A | INFO | descriptors.py | No `musig(...)` participant aggregation inside tr() / rawtr() (BIP-390 / Core descriptor.cpp musig support). |
| GAP-B | INFO | descriptors.py / miniscript.py | No `sortedmulti_a` parse path inside tr() (Core descriptor.cpp:2318). |
| GAP-C | INFO | descriptors.py | No multipath `<0;1>` parse syntax. Core supports it for BIP-389-style external/internal split. |
| GAP-D | MED | miniscript.py | No duplicate-key detection in miniscript expressions (Core `miniscript.h:1690-ish` `DuplicateKeyCheck`). ouroboros silently accepts redundant-key constructs. |
| GAP-E | LOW | descriptors.py | No WIF (base58check private key) support inside descriptors. Core accepts `pk(L4rK...)` directly; ouroboros only takes hex pubkeys and xprv/xpub. |
| GAP-F | LOW | descriptors.py | No hardened-ranged wildcard (`*'` / `*h`). |

## Two-pipeline guard

A two-pipeline drift guard is added in this wave (see test file):

```python
def test_descriptors_pipeline_is_python_only():
    """Descriptor parsing is wallet-side and must live in Python only.
    If descriptor/miniscript code ever appears on the Rust side of the
    two-pipeline, the wallet pipeline has crossed into the consensus pipeline."""
    ferrous = Path(__file__).resolve().parents[3] / "ferrous-utils"
    hits = []
    for root in (ferrous / "common" / "src", ferrous / "sync" / "src"):
        for rs in root.rglob("*.rs"):
            text = rs.read_text(errors="ignore").lower()
            for needle in ("bip-380", "bip 380", "descriptor parse", "miniscript",
                           "fn descriptor", "wpkh(", "tr(", "addr("):
                if needle in text:
                    hits.append((rs, needle))
    # RocksDB ColumnFamilyDescriptor is allowed (it's an unrelated symbol).
    hits = [(p, n) for p, n in hits if "columnfamilydescriptor" not in p.read_text(errors="ignore").lower() or n not in ("descriptor parse",)]
    assert not hits, f"BIP-380 descriptor/miniscript code on Rust side: {hits}"
```

This codifies that descriptor / miniscript code must remain Python-only.

## Top findings (parent-summary fodder)

1. **BUG-10 (rawtr derive_script_pubkey missing)** — `derive_address("rawtr(...)")` works, `derive_script_pubkey("rawtr(...)")` raises `Unknown descriptor type: rawtr`. Asymmetric API blocks any PSBT / wallet / tx-build path through rawtr. Trivial fix (3-line patch).
2. **BUG-11 (tr() script-tree leaves stored unvalidated)** — `parse_descriptor("tr(K, ANYTHING_AT_ALL)")` succeeds, then crashes at derive time. Accept-then-crash is strictly worse than reject-at-parse. Reachable any time a user types a typo or pastes a sortedmulti_a / musig that ouroboros doesn't yet support.
3. **BUG-6 (combo segwit gating)** — combo() emits malformed P2WPKH for a 32-byte x-only key whose first byte happens to be 02/03. Silently corrupts derived addresses.
4. **BUG-7 (multi_a unbounded)** — miniscript multi_a accepts >999 keys, generating standardness-violating scripts that mainnet relayers would drop.
5. **GAP-D (no duplicate-key detection in miniscript)** — BIP-379 mandates DuplicateKeyCheck; ouroboros accepts and compiles miniscripts Core would reject.

## Universal pattern observations (cross-wave reuse)

- **"audit-flip" pattern (W128 history)**: G26's first verdict was BUG-8 (WRAP_J u-bit gating); re-checking against Core showed PASS. Lesson reinforced: always re-read Core after writing the matrix, not before.
- **"feature gap vs correctness bug" distinction**: GAP-A/B/C are intentional scope limits (musig/multipath are wallet-construction features), not consensus-correctness bugs. BUG-1..11 are correctness divergences.
- **"compressed-key check by prefix"** (BUG-6) is the same shape as BUG-9 from W117 (LSB-first vs MSB-first byte packing) — checking a partial proxy for the full invariant. Pattern: when validating a key/byte stream, always check length AND prefix AND structure, not just one of them.
- **"accept-then-crash" anti-pattern** (BUG-11): a parser that "succeeds" but stores unvalidated content is strictly worse than one that rejects. Fail-fast is easier to debug than fail-late. Pattern: every parse path should either (a) fully validate, (b) clearly mark a quarantined region with an explicit `UnvalidatedBlob` type, or (c) raise. Free-form `str` slots in AST nodes are a smell.
- **"asymmetric API surface"** (BUG-10): two code paths (derive_address + derive_script_pubkey) that should be sibling operations on the same input have different supported-type sets. Pattern: when adding a new descriptor type (or any sum-type variant), grep for the existing dispatch and update *every* dispatch table, not just the one you're testing.
- **"test-fixture pubkey encoding mismatch"** (G25 discovery): the test originally failed not because ouroboros lacked the 999-key cap, but because the default key_parser only accepts 66-hex compressed keys. Pattern: when a test fails for a reason that's not the gate's intent, look for fixture / harness issues before adding xfails.
