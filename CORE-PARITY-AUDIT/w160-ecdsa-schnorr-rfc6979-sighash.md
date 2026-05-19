# W160 — ECDSA + Schnorr + RFC 6979 + sighash construction (ouroboros)

**Wave:** W160 — `secp256k1_ecdsa_sign` (RFC 6979 deterministic nonce),
`secp256k1_ecdsa_sign_recoverable`, `secp256k1_ecdsa_signature_normalize`
(low-S enforcement), `secp256k1_schnorrsig_sign32` / `_sign_custom`
(`aux_rand32`), `SignatureHash` (legacy), `SignatureHash` (BIP-143
SegWit-v0), `SignatureHashSchnorr` (BIP-341 + BIP-342), `PrecomputedTransactionData`
(hash_prevouts / hash_sequence / hash_outputs / sha_amounts /
sha_scriptpubkeys midstate caching), `SIGHASH_DEFAULT = 0x00` (64-byte
sig), `SIGHASH_SINGLE` legacy-uint256(1) bug preserved, Taproot
SIGHASH_SINGLE-out-of-range = consensus reject (BIP-341 §"Common
signature message"), Taproot epoch byte = 0x00, `ext_flag` /
`spend_type` byte composition, annex commitment, tap_leaf_hash +
key_version + codesep_pos extension block, `SignatureCache::ComputeEntryECDSA`
/ `ComputeEntrySchnorr` (per-sig cache key on full sighash material),
BIP-32 private-key scalar tweak (`secp256k1_ec_seckey_tweak_add`),
`CKey::Sign` post-sign verify paranoia, `CKey::SignCompact` recovery
round-trip belt-and-suspenders, BIP-340 `lift_x` even-Y normalization
on Taproot keypair, BIP-62 / BIP-66 strict DER (`IsValidSignatureEncoding`),
LOW_S policy gate (`CheckLowS`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/secp256k1/include/secp256k1.h` — `secp256k1_ecdsa_sign`
  doc: "By default, the created signature will be uniformly random and
  conformant to RFC 6979." Default `noncefp = secp256k1_nonce_function_rfc6979`,
  default `ndata = NULL`. ALWAYS returns a low-S signature.
- `bitcoin-core/src/secp256k1/src/ecdsa_impl.h:284-300` —
  `secp256k1_ecdsa_sig_sign` enforces low-S internally:
  `high = secp256k1_scalar_is_high(sigs); secp256k1_scalar_cond_negate(sigs, high)`.
- `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h` —
  `secp256k1_ecdsa_sign_recoverable` produces a 65-byte (r || s ||
  recid) form. recid ∈ [0, 3]. Low-S enforced same as sign.
- `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h:108-125` —
  `secp256k1_schnorrsig_sign32`: `aux_rand32` strongly recommended
  per BIP-340 §3.3 "Default Signing". `NULL == all-zero`. The Core
  wallet ALWAYS passes a freshly-generated 32-byte `auxiliary_rand`.
- `bitcoin-core/src/key.cpp:225-234` — `CKey::Sign` calls
  `secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash, &pk);
  assert(ret)` post-sign. Hardware-bitflip / fault-injection defense.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact` recovery
  round-trip: signs, recovers, `secp256k1_ec_pubkey_cmp` against the
  expected pubkey. Same paranoia.
- `bitcoin-core/src/key.cpp:293-314` — `CKey::Derive` (BIP-32 private
  child) calls `secp256k1_ec_seckey_tweak_add(secp256k1_context_static,
  keyChild.begin(), vout.data())` — constant-time scalar tweak inside
  libsecp256k1.
- `bitcoin-core/src/key.cpp:540-560` — `CKey::SignSchnorr` calls
  `secp256k1_keypair_create` then `secp256k1_schnorrsig_sign32` with
  a freshly-generated `aux_rand`. Internal-key seckey-flip on odd-y
  handled inside libsecp256k1's keypair API.
- `bitcoin-core/src/script/interpreter.h:163-200` —
  `PrecomputedTransactionData` cache: `hashPrevouts`, `hashSequence`,
  `hashOutputs`, `m_prevouts_single_hash`, `m_sequences_single_hash`,
  `m_outputs_single_hash`, `m_spent_amounts_single_hash`,
  `m_spent_scripts_single_hash`. Computed ONCE per tx; reused for
  every (input, sighash_type) combination.
- `bitcoin-core/src/script/interpreter.cpp:1483-1570` —
  `SignatureHashSchnorr` (BIP-341 §4 sighash). Epoch = 0x00,
  `hash_type` validation against `{0x00, 0x01..0x03, 0x81..0x83}`,
  output_type = `(hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type
  & SIGHASH_OUTPUT_MASK)`, spend_type byte = `(ext_flag << 1) |
  annex_present`, annex SHA256, extension block (`tap_leaf_hash`,
  `key_version = 0x00`, `codesep_pos uint32 LE`).
- `bitcoin-core/src/script/interpreter.cpp:1538-1550` — BIP-341
  SIGHASH_SINGLE: if `in_pos >= tx_to.vout.size()` ⇒ `return false`
  (NOT the legacy uint256(1) bug). Caller maps to
  `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`.
- `bitcoin-core/src/script/interpreter.cpp:1605-1612` — legacy
  `SignatureHash` SIGHASH_SINGLE bug: `if ((nHashType & 0x1f) ==
  SIGHASH_SINGLE && nIn >= txTo.vout.size())` ⇒ return `uint256{1}`
  (a hash literally equal to integer 1; first byte 0x01). Bug
  preserved as consensus.
- `bitcoin-core/src/script/interpreter.cpp:1600-1675` — BIP-143
  SegWit-v0 sighash: re-uses cached `hashPrevouts` / `hashSequence`
  / `hashOutputs` from `PrecomputedTransactionData`. For
  SIGHASH_SINGLE with `nIn >= vout.size()`, `hashOutputs = uint256::ZERO`.
- `bitcoin-core/src/script/interpreter.cpp:182-200` —
  `IsValidSignatureEncoding` (BIP-66 strict DER): size ∈ [9, 73],
  prefix 0x30, length byte = `size - 3`, no extraneous leading zeros
  in R / S, marker bytes 0x02, etc.
- `bitcoin-core/src/script/interpreter.cpp:204-220` —
  `IsLowDERSignature` / `CheckLowS`: `secp256k1_ecdsa_signature_normalize`
  semantics — `s <= n/2`. Hardcoded `vchMaxModOrderHalf` boundary.
- `bitcoin-core/src/script/sigcache.cpp:22-32` — `SignatureCache`
  ctor calls `GetRandHash()` for a per-process 32-byte salt.
- `bitcoin-core/src/script/sigcache.cpp:55-90` — `ComputeEntryECDSA(entry,
  hash, vchSig, pubkey)` and `ComputeEntrySchnorr` hash the **sighash
  bytes (32 B)**, the **signature bytes**, the **pubkey bytes**, and
  the **salt** into a 256-bit cache key. The sighash is the REAL
  sighash output (post-`SignatureHash` / `SignatureHashSchnorr`), not
  a placeholder.
- BIP-66 — strict DER signatures.
- BIP-62 — low-S policy (later promoted to MANDATORY in `mempool` /
  consensus-via-SegWit).
- BIP-143 — BIP-143 SegWit-v0 sighash (six precomputed digests,
  amount commitment, scriptCode commitment, sighash type LE32).
- BIP-340 — Schnorr signatures + tagged hash + `lift_x` even-Y.
- BIP-341 — Taproot key tweak, epoch byte, spend_type byte,
  SIGHASH_DEFAULT semantics, ext_flag commitment, annex commitment.
- BIP-342 — Tapscript: tap_leaf_hash + key_version + codesep_pos
  extension block, opcode-position counter.

**Files audited**

- `src/ouroboros/script.py:124-127` — `SECP256K1_ORDER_HALF`
  (literal hex, `(N-1)//2` form which equals `N//2` since N is odd —
  cross-validated).
- `src/ouroboros/script.py:339-371` — `_check_der_signature`
  (BIP-66 strict DER parser).
- `src/ouroboros/script.py:378-388` — `_is_defined_hashtype`
  (Core IsDefinedHashtypeSignature parity).
- `src/ouroboros/script.py:391-403` — `_check_low_s` (BIP-62
  low-S check; **defensive-true-on-error** below).
- `src/ouroboros/script.py:685-750` — `_compute_segwit_v0_sighash`
  (BIP-143 SegWit-v0). Inline `for inp in tx.inputs:` loop **three
  times** per call; NO `PrecomputedTransactionData` midstate cache.
- `src/ouroboros/script.py:1354-1397` — Tapscript OP_CHECKSIG sig
  parsing, sighash dispatch, Schnorr verify.
- `src/ouroboros/script.py:1496-1533` — same path for
  OP_CHECKSIGVERIFY.
- `src/ouroboros/script.py:1615-1648` — same path for
  OP_CHECKSIGADD.
- `src/ouroboros/script.py:1867-1967` — `_calculate_signature_hash`
  (legacy SignatureHash). Line **1946** correctly emits
  `b'\x01' + b'\x00' * 31` for SIGHASH_SINGLE-out-of-range bug.
- `src/ouroboros/script.py:1970-2026` — `_lax_der_to_compact`
  (always-low-S normalize-on-fallback path).
- `src/ouroboros/script.py:2028-2090` — `_verify_ecdsa_signature`
  (strict-DER fast path → lax fallback). No `flags` parameter; LOW_S
  enforcement is caller-side.
- `src/ouroboros/script.py:2172-2233` — `_verify_schnorr_signature`
  (BIP-340 verify; Rust fast path → coincurve fallback).
- `src/ouroboros/script.py:2288-2321` — `_verify_taproot_keypath`.
- `src/ouroboros/script.py:2323-2450` — `_verify_taproot_scriptpath`.
- `src/ouroboros/script.py:2452-2473` — `_taproot_tweak_pubkey`
  (coincurve `PublicKeyXOnly.tweak_add`).
- `src/ouroboros/script.py:2518-2665` — `_compute_taproot_sighash`
  (BIP-341 §4 + BIP-342 extension block).
- `src/ouroboros/sig_cache.py` — `SigCache` (OrderedDict LRU,
  `nonce = os.urandom(32)`, key = `SHA256(nonce||sighash||
  pubkey||sig||flags_le32)[:8]`, 50 000 entries).
- `src/ouroboros/validation.py:2130-2176` — `_verify_input_signature`
  builds **fake** sighash material at line 2152:
  `sighash_material = tx.get_txid() + struct.pack("<I", input_index)`.
- `src/ouroboros/wallet.py:52-53` — `SECP256K1_ORDER` (1 of 3 copies).
- `src/ouroboros/wallet.py:617-654` — `HDKey.from_seed`,
  `HDKey.derive_child` (BIP-32 master + child). **Pure-Python int
  scalar addition** at line 643; not `secp256k1_ec_seckey_tweak_add`.
- `src/ouroboros/wallet.py:756-811` — `WalletKey.get_p2tr_address`
  (BIP-86 Taproot tweak, even-Y normalization).
- `src/ouroboros/wallet.py:846-850` — `WalletKey.sign` —
  one-liner: `self._privkey.sign(message_hash, hasher=None)`. NO
  post-sign verify paranoia.
- `src/ouroboros/wallet.py:1213-1227` — `Wallet.lock` — clears
  `self.keys = []` etc. via Python GC; no `memory_cleanse`.
- `src/ouroboros/wallet.py:2031-2078` — `_bip143_sighash` (4th
  copy of the SegWit-v0 sighash — see N-pipeline drift below).
- `src/ouroboros/segwit_v0.py:79-143` — `bip143_sighash` (5th
  copy, named as "single source of truth" in the docstring).
- `src/ouroboros/segwit_v0.py:307-389` — `sign_p2wsh_input`
  (multisig branch recomputes `bip143_sighash` PER SIGNING KEY).
- `src/ouroboros/segwit_v0.py:392-417` — `sign_p2sh_p2wpkh_input`.
- `src/ouroboros/segwit_v0.py:493-512` — `sign_p2sh_p2wsh_input`.
- `src/ouroboros/taproot.py:36-118` — `derive_taproot_sign_secret`
  (BIP-86 / BIP-341 internal-key tweak), `_tagged_hash` (1 of 4).
- `src/ouroboros/taproot.py:121-154` — `derive_taproot_output_xonly`
  (verifier-side counterpart).
- `src/ouroboros/descriptors.py:65-67` — `SECP256K1_ORDER` (2 of 3).
- `src/ouroboros/descriptors.py:188-207` — `ExtendedPubKey.derive_child`
  (BIP-32 normal-only public derivation; `coincurve.PublicKey.add`
  with NO identity-check exception handler).
- `src/ouroboros/rpc.py:7519-7559` — `_legacy_sighash` (6th sighash
  copy). **SIGHASH_SINGLE-out-of-range bug WRONG** (line 7547 returns
  `bytes(32)` instead of `b'\x01' + b'\x00'*31`).
- `src/ouroboros/rpc.py:7561-7625` — `_taproot_sighash` (3rd
  TapSighash copy). SIGHASH_SINGLE-out-of-range silently writes
  32 zero-bytes (line 7610) where Core returns false.
- `src/ouroboros/rpc.py:7790-7826` — P2TR wallet signing via
  `derive_taproot_sign_secret` + `coincurve.PrivateKey(...).sign_schnorr(sh)`.
- `src/ouroboros/rpc.py:8118-8136` — `signmessage` (wallet-side)
  via `target_key._privkey.sign_recoverable(...)`. No post-sign
  recovery round-trip.
- `src/ouroboros/rpc.py:8138-8200` — `signmessagewithprivkey`
  (wallet-less). No post-sign recovery round-trip.
- `src/ouroboros/rpc.py:8202-8269` — `verifymessage`.
- `src/ouroboros/rpc.py:9984-10042` — `_taproot_sighash` (4th
  TapSighash copy; same shape as 7569).
- `src/ouroboros/rpc.py:10180-10275` — `walletprocesspsbt`
  signing branch (P2WPKH / P2TR / P2PKH). Defines a 4th
  `_legacy_sighash` (line 10231) with the SAME bug as 7519.
- `ferrous-utils/sync/src/validate/sighash.rs:143-226` —
  `signature_hash_legacy` (Rust legacy sighash). Line 157-161
  CORRECTLY emits `result[0] = 1` for SIGHASH_SINGLE-out-of-range.
- `ferrous-utils/sync/src/validate/script.rs:1373-1500` —
  `verify_signature_in_script`, `verify_p2pkh_signature` (line
  1460 `Ok(true)` — **dead-but-public-returns-true**, W159 BUG-6
  carry-forward).
- `ferrous-utils/common/src/crypto/secp.rs:14-23` —
  `SECP_CTX: OnceLock<Secp256k1<All>>` (global verify context).
- `ferrous-utils/common/src/crypto/secp.rs:36-79` —
  `verify_ecdsa_compact`, `verify_ecdsa_der` (use global ctx).
- `ferrous-utils/common/src/crypto/secp.rs:92-116` —
  `verify_schnorr` (uses global ctx).
- `ferrous-utils/common/src/crypto/secp.rs:146-162` —
  `batch_verify_schnorr` (sequential fallback; comment-as-confession).
- `ferrous-utils/common/src/crypto/mod.rs:23-80` —
  `verify_ecdsa_signature`, `verify_ecdsa_signature_der` —
  per-call `Secp256k1::verification_only()` context (W159 BUG-1).
- `ferrous-utils/sync/src/lib.rs:54-64` — `verify_ecdsa` Python
  FFI wires the per-call slow path (W159 BUG-1 carry-forward).
- `Cargo.lock` — `secp256k1 0.29.1` + `0.31.1` (2 versions),
  `secp256k1-sys 0.10.1` + `0.11.0` (2 versions) — W159 BUG-2.

---

## Gate matrix (28 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RFC 6979 deterministic nonce (ECDSA sign) | G1: default nonce = RFC 6979 in sign path | PASS via coincurve — `keys.py:43-70` calls `secp256k1_ecdsa_sign` with `DEFAULT_NONCE = (NULL, NULL)` ⇒ RFC 6979 |
| 1 | … | G2: deterministic across multiple invocations on same `(d, msg)` | PASS (libsecp256k1 guarantee) |
| 2 | Low-S enforcement at sign time | G3: signature output `s <= n/2` | PASS (libsecp256k1 always emits low-S internally) |
| 2 | … | G4: high-S accepted in verify when LOW_S flag NOT set | PASS — `_verify_ecdsa_signature` (`script.py:2028`) defers LOW_S to caller |
| 3 | Strict DER (BIP-66) at sign | G5: signer never emits non-canonical DER | PASS — libsecp256k1 always emits canonical DER |
| 3 | … | G6: verifier `_check_der_signature` rejects non-canonical | PASS (`script.py:339-371`); cross-cite **BUG-1** below for `_check_low_s` defensive return |
| 4 | BIP-340 Schnorr signing | G7: `aux_rand32` provided (not all-zero) | PARTIAL — coincurve `sign_schnorr(message, aux_randomness=b"")` auto-generates `os.urandom(32)` per `keys.py:97-98`. Carries forward W159 **BUG-11** (no test asserts this stays non-zero across coincurve releases) |
| 4 | … | G8: Taproot internal-key seckey-flip on odd-y | PASS — `taproot.py:91-92` `d = (SECP256K1_ORDER - d) % SECP256K1_ORDER` on parity 0x03 |
| 5 | Post-sign verify paranoia | G9: `secp256k1_ecdsa_verify` post-sign in `CKey::Sign` analog | **BUG-2 (P1)** (W159 BUG-4 carry-forward) — `WalletKey.sign` (`wallet.py:848-850`) is a thin coincurve passthrough; no post-sign verify |
| 5 | … | G10: `SignCompact` recovery-roundtrip vs source pubkey | **BUG-3 (P1)** (W159 BUG-5 carry-forward) — `signmessage` / `signmessagewithprivkey` (`rpc.py:8119-8200`) skip the recovery round-trip |
| 6 | Sighash construction — legacy | G11: SIGHASH_SINGLE-out-of-range = `0x01||0x00*31` | PARTIAL — **BUG-4 (P0-CONS)** below. `script.py:1946` ✔, `sighash.rs:159` ✔, but `rpc.py:7547` AND `rpc.py:10258` BOTH return `bytes(32)` (all-zero, NOT the historic uint256{1} value) |
| 6 | … | G12: FindAndDelete + OP_CODESEPARATOR strip | PASS — `script.py:1873-1915` opcode-aware; `sighash.rs:32-71` byte-naive (acceptable for serialised sig push patterns; documented divergence) |
| 7 | Sighash construction — BIP-143 (SegWit-v0) | G13: cached hash_prevouts / hash_sequence / hash_outputs | **BUG-5 (P1-PERF)** — no `PrecomputedTransactionData` cache. `_compute_segwit_v0_sighash` (`script.py:685-750`) iterates over all inputs THREE times per call (lines 702-705, 711-713, plus 4th sighash type's outputs loop) |
| 7 | … | G14: amount commitment | PASS (`script.py:744`) |
| 7 | … | G15: scriptCode commitment | PASS (`script.py:742-743`) |
| 7 | … | G16: sighash_type undefined-byte handling | **BUG-6 (P1)** — `script.py:696-697` silently maps `base_type == 0` ⇒ `base_type = 0x01` (SIGHASH_ALL). Core does NOT do this remap for BIP-143; observationally equivalent for the canonical-hash output but masks divergent intent |
| 8 | Sighash construction — BIP-341 / BIP-342 | G17: epoch byte = 0x00 | PASS (`script.py:2557`) |
| 8 | … | G18: SIGHASH_SINGLE-out-of-range = consensus reject (NOT uint256{1}) | PASS at verify-path (`script.py:2645-2646` `return None`). **BUG-7 (P1)** — wallet-side `_taproot_sighash` helpers (`rpc.py:7603-7610` + `rpc.py:9984+`) silently write 32 zero-bytes instead of returning None / raising, producing a Schnorr signature over a hash Core's verifier would NEVER compute |
| 8 | … | G19: hash_type valid set `{0x00, 0x01..0x03, 0x81..0x83}` | PASS at verify (`script.py:2544-2546`); cross-cite **BUG-7** for wallet path |
| 8 | … | G20: spend_type = `(ext_flag << 1) | annex_present` | PASS (`script.py:2610-2611`) |
| 8 | … | G21: annex SHA256 prefixed by compact-size | PASS (`script.py:2631-2634`) |
| 8 | … | G22: extension block tap_leaf_hash + key_version=0x00 + codesep_pos LE32 | PASS (`script.py:2655-2663`) |
| 9 | Tagged-hash | G23: single source of truth | **BUG-8 (P1)** (W159 BUG-12 carry-forward + **EXPANDED**) — `_tagged_hash` defined 4× (`script.py:274`, `taproot.py:46`, `descriptors.py:92`, `transport_v2.py:383`); `_taproot_sighash` defined 4× (`script.py:2518`, `rpc.py:7569`, `rpc.py:9984`, plus the verifier path); `bip143_sighash` defined 4× (`script.py:685`, `segwit_v0.py:79`, `wallet.py:2034`, `rpc.py:7561-7626` via local closure pattern); `_legacy_sighash` defined 2× (`rpc.py:7519`, `rpc.py:10231`). Five distinct sighash N-pipelines all reachable in production |
| 10 | SigCache key | G24: includes real sighash bytes | **BUG-9 (P0-SEC) "fake-sighash SigCache key"** (W159 BUG-13 carry-forward — STILL OPEN AT HEAD) — `validation.py:2152` builds `sighash_material = tx.get_txid() + struct.pack("<I", input_index)`. NOT the sighash |
| 10 | … | G25: salted with per-process random | PASS (`sig_cache.py:56`) |
| 10 | … | G26: failures NOT cached | PASS (`validation.py:2173-2174`) |
| 11 | BIP-32 private-key derive | G27: scalar tweak via libsecp256k1 | **BUG-10 (P1-SEC) "BIP-32-priv-pure-python-int"** — `wallet.py:643` `child_int = (il + int.from_bytes(...)) % SECP256K1_ORDER` is **Python int** modular addition. Not constant-time, leaks timing channel on each `derive_child` call. Core uses `secp256k1_ec_seckey_tweak_add` (`key.cpp:307`) |
| 12 | secp256k1 context | G28: process-singleton + randomized | **BUG-11 (P0-SEC) "side-channel-blinding-disabled"** (W159 BUG-3 carry-forward — STILL OPEN AT HEAD); **BUG-12 (P1) "4-context co-existence"** (W159 BUG-2 + Cargo.lock dual-version carry-forward — STILL OPEN AT HEAD) |

---

## BUG-1 (P1) — `_check_low_s` returns True ("OK") on malformed input — defense-in-depth gap

**Severity:** P1 (defensive-true-on-error). `script.py:391-403`
`_check_low_s` returns **True** for any of: signature shorter than 6
bytes (line 392-393), wrong prefix byte (394-395), or out-of-bounds
length declaration (399-400). In all three cases, "low-S OK" means
"this signature satisfies the LOW_S consensus / policy check".

```python
def _check_low_s(sig_without_hashtype: bytes) -> bool:
    if len(sig_without_hashtype) < 6:
        return True               # <-- malformed = "low-S OK"
    if sig_without_hashtype[0] != 0x30:
        return True               # <-- wrong DER prefix = "low-S OK"
    len_r = sig_without_hashtype[3]
    s_start = 6 + len_r
    len_s = sig_without_hashtype[5 + len_r]
    if s_start + len_s > len(sig_without_hashtype):
        return True               # <-- buffer overrun = "low-S OK"
    ...
```

In normal use, the caller has already run `_check_der_signature`
first (the actual sites at `script.py:643, 1408, 1411, 1542, 2133`
gate on `SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC`
before calling `_check_low_s` on `sig[:-1]`). So in production these
defensive branches are unreachable. But:

  1. The semantic of "returns True on malformed input" is the
     OPPOSITE of what a defensive helper should do.
  2. A future caller who pulls `_check_low_s` out of the
     DER-gated branch (e.g. a new BIP-32 or PSBT validator) inherits
     the silent malleability acceptance.

Core's `IsLowDERSignature` (`interpreter.cpp:204-220`) calls
`IsValidSignatureEncoding` first and returns false on parse failure,
not true.

**File:** `src/ouroboros/script.py:391-403`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:204-220`
`IsLowDERSignature`.

**Impact:**
- Currently latent: every production caller pre-gates with
  `_check_der_signature`.
- Future-proofing: silent malleability admission if the gate ordering
  changes. New PSBT / BIP-322 validators that want to verify low-S
  on a sig they fetched from a PSBT input may forget the pre-check.
- Cross-cite the **defensive-true-on-error** pattern at
  `script.py:2019-2023` (`_lax_der_to_compact` normalize_s default
  swallows S-malleability silently for the LAX fallback).

---

## BUG-2 (P1) — `WalletKey.sign` has no post-sign verify (W159 BUG-4 carry-forward, STILL OPEN AT HEAD)

**Severity:** P1 (fault-injection / hardware-bitflip defense
absent). `wallet.py:846-850`:

```python
def sign(self, message_hash: bytes) -> bytes:
    """Sign a 32-byte hash, return DER-encoded signature."""
    return self._privkey.sign(message_hash, hasher=None)
```

A 1-line passthrough to coincurve. coincurve's `PrivateKey.sign`
(see `.venv/lib/python3.13/site-packages/coincurve/keys.py:43-70`)
calls `secp256k1_ecdsa_sign` and returns the DER. **No post-sign
verify round-trip.**

Bitcoin Core's `CKey::Sign` (`key.cpp:225-234`) calls
`secp256k1_ecdsa_verify` with the just-produced signature and
asserts the result. This catches:
  1. Hardware bitflips between sign and broadcast (cosmic rays,
     unstable CPU, memory bit-rot under power supply noise).
  2. Fault-injection attacks (deliberate glitches on the signing
     CPU to leak partial secret bits via differential analysis of
     produced sigs).
  3. Library version skew (cargo update bumps `secp256k1` to a
     buggy point release).

The defense costs ~50 µs per signature; the wallet signing path is
not on a hot loop. coincurve does NOT do this internally.

**File:** `src/ouroboros/wallet.py:846-850`.

**Core ref:** `bitcoin-core/src/key.cpp:225-234`.

**Impact:**
- Every wallet-side signature emitted by ouroboros is subject to
  fault-injection / hardware-bitflip corruption with zero detection.
- For `signrawtransactionwithwallet`, `walletprocesspsbt`, P2WPKH /
  P2TR / P2PKH / P2WSH / P2SH-* — every sign-out is single-sourced
  with no integrity check.
- Carry-forward from W159 BUG-4 (audited 2026-05-18); still present
  at head 0dd8eea.

---

## BUG-3 (P1) — `signmessage` / `signmessagewithprivkey` skip the recovery round-trip (W159 BUG-5 carry-forward)

**Severity:** P1 — Core's `CKey::SignCompact` (`key.cpp:250-271`)
unconditionally recovers the pubkey from the just-produced compact
signature and compares it against the expected source pubkey via
`secp256k1_ec_pubkey_cmp`. This catches:
  1. Wrong recid bit (a bug in coincurve / libsecp256k1's
     `secp256k1_ecdsa_sign_recoverable` recid encoding would produce
     a sig that recovers the WRONG pubkey).
  2. Same hardware-bitflip / fault-injection class as BUG-2.

`signmessage` (`rpc.py:8118-8136`) and `signmessagewithprivkey`
(`rpc.py:8186-8200`) both call `key.sign_recoverable(msg_hash,
hasher=None)`, format the 65-byte compact result, and emit. Neither
runs `PublicKey.from_signature_and_message` against the source
pubkey to verify the round-trip.

**File:** `src/ouroboros/rpc.py:8118-8136, 8186-8200`.

**Core ref:** `bitcoin-core/src/key.cpp:250-271`.

**Impact:** Same as BUG-2, on the recoverable-sig path; in addition,
a sig that doesn't round-trip is broadcast to the user who copies
the base64 string, paste into another wallet for verifymessage,
and gets "invalid". User-visible breakage with no recovery channel
(the original message can never be re-signed by the same key with
the same nonce, since coincurve uses RFC 6979 — so a "good" sig
becomes irretrievable from the compromised signing event).

Carry-forward from W159 BUG-5.

---

## BUG-4 (P0-CONS) — `_legacy_sighash` SIGHASH_SINGLE-out-of-range returns `bytes(32)` instead of historic `uint256{1}` ⇒ wrong signatures

**Severity:** P0-CONS (wallet signs over a sighash that does NOT
match what Core's verifier computes; the produced signatures fail
script verification at the network).

The historic SIGHASH_SINGLE bug (BIP-66 pre-SegWit) is that when
`(nHashType & 0x1f) == SIGHASH_SINGLE` AND `input_index >=
tx.vout.size()`, `SignatureHash` returns the uint256 value `1`
(i.e. a 32-byte little-endian hash whose first byte is `0x01` and
the rest are `0x00`). This is preserved as consensus.

`script.py:1945-1946` does this correctly:

```python
elif base_type == 0x03:  # SIGHASH_SINGLE
    if input_index >= len(transaction.outputs):
        return b'\x01' + b'\x00' * 31    # historic uint256{1} bug — CORRECT
```

`ferrous-utils/sync/src/validate/sighash.rs:157-161` also CORRECT
(`result[0] = 1`).

But the **wallet-side** `_legacy_sighash` closures defined in two
places in `rpc.py` are WRONG:

```python
# src/ouroboros/rpc.py:7519-7547 — signrawtransactionwithkey
def _legacy_sighash(tx, idx, script_code, sh_type):
    ...
    elif base == 3:
        if idx >= len(tx.outputs):
            return bytes(32)   # <-- WRONG: all zeros, not 0x01||0x00*31
```

Identical bug at `src/ouroboros/rpc.py:10257-10258` inside
`walletprocesspsbt`'s P2PKH branch.

Result: when a user calls `signrawtransactionwithkey` or
`walletprocesspsbt` on a P2PKH legacy input with SIGHASH_SINGLE
and `input_index >= num_outputs`, ouroboros signs the all-zero hash
(`SHA256(secret || 0^32)`-ish via libsecp256k1's RFC-6979 nonce
generation). Bitcoin Core's verifier — and ouroboros's OWN
verifier — compute the `0x01||0x00*31` hash, get a different
sigmsg, and the signature fails.

**Files:**
- `src/ouroboros/rpc.py:7519-7547` (signrawtransactionwithkey)
- `src/ouroboros/rpc.py:10231-10258` (walletprocesspsbt P2PKH branch)

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1605-1612`:

```cpp
if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
    if (nIn >= txTo.vout.size()) {
        //  nOut out of range
        return uint256::ONE;     // 32-byte LE: 0x01 0x00 ... 0x00
    }
}
```

**Impact:**
- Wallet emits structurally-invalid signatures whenever a legacy
  P2PKH input is signed with SIGHASH_SINGLE and `idx >= num_outputs`.
- Network rejects the resulting tx with bad-txns-input-script-mismatch.
- Two-pipeline drift between `script.py` verifier (correct), Rust
  `sighash.rs` verifier (correct), AND two `rpc.py` wallet-side
  closures (wrong) — pattern **"single source of truth proliferated
  to closures that drifted"**.
- Cross-cite the N-pipeline drift in BUG-8 — same root cause: each
  RPC handler defined a private inline sighash helper instead of
  importing the shared verifier-side `_calculate_signature_hash`.

---

## BUG-5 (P1-PERF) — `_compute_segwit_v0_sighash` has no `PrecomputedTransactionData` cache; O(N²) per-block sighashing

**Severity:** P1-PERF. `_compute_segwit_v0_sighash`
(`script.py:685-750`) iterates over `tx.inputs` **three times per
call**:
  - lines 702-705 (hash_prevouts)
  - lines 711-713 (hash_sequence)
  - implicit output loop at 720-724

For a transaction with M inputs and K signatures to verify (in
multisig, K can be up to M*N where N is the witnessScript M-of-N),
the sighash is computed K times. Each computation re-iterates
all M inputs. Total work: `O(K * M)`. Core's
`PrecomputedTransactionData` (`script/interpreter.h:163-200`) does
the three "all inputs" digests ONCE per transaction. Total work for
Core: `O(M + K)`.

For a tx with 100 inputs each signed by 1 key, ouroboros: 100 × 3 ×
100 = 30 000 outpoint serializations. Core: 100 + 100 = 200.
**150× wasted work on the sigmsg construction alone.**

`_compute_taproot_sighash` (`script.py:2518-2665`) has the same
problem — every call recomputes sha_prevouts / sha_amounts /
sha_scriptpubkeys / sha_sequences / sha_outputs from scratch
(lines 2566-2606).

**File:** `src/ouroboros/script.py:685-750` (BIP-143);
`src/ouroboros/script.py:2518-2665` (BIP-341).

**Core ref:** `bitcoin-core/src/script/interpreter.h:163-200`,
`bitcoin-core/src/script/interpreter.cpp:1600-1675` (BIP-143
cache reuse), `bitcoin-core/src/script/interpreter.cpp:1483-1570`
(BIP-341 cache reuse via `cache` parameter).

**Impact:**
- IBD: Python is already slow; this is multiplied by 150× on
  N-input txs. Practical effect: rare on real mainnet (median
  tx has ~2 inputs) but pathological for high-fanout multisig
  txs or batch-spends.
- Mempool ATMP: every relay-time policy check re-runs sighash.
- Block validation: every connect-block re-runs sighash.
- Cross-cite the **"caching primitive absent"** fleet pattern.

---

## BUG-6 (P1) — `_compute_segwit_v0_sighash` silently remaps `base_type == 0` ⇒ `SIGHASH_ALL`; Core does not

**Severity:** P1. `script.py:696-697`:

```python
base_type = sighash_type & 0x1f
anyone_can_pay = (sighash_type & 0x80) != 0
if base_type == 0:
    base_type = 0x01     # <-- silent remap of undefined hashtype
```

BIP-143 defines `hashType` values 1, 2, 3 (with optional
ANYONECANPAY OR-in). Value 0 is **undefined** in BIP-143
(`SIGHASH_DEFAULT = 0x00` is a BIP-341 concept). Bitcoin Core's
BIP-143 path does NOT have this remap — it uses the raw `nHashType`
in all branch conditions.

Observationally, the remap **does** produce the same final hash for
hashtype 0 as for hashtype 1 (the if-branches at lines 710, 719
make decisions based on `base_type not in (0x02, 0x03)`, which is
true for both 0 and 1). The `sighash_type` (raw) is committed at
line 748 — so the final 4-byte BE / LE serialization differs (Core
commits 0x00000000, ouroboros also commits 0x00000000 since `sighash_type`
is unchanged).

So: **same final hash for valid inputs**, BUT:
  - The intent is masked: the code looks like it's gracefully
    handling SIGHASH_DEFAULT for SegWit-v0, but BIP-143 does NOT
    have SIGHASH_DEFAULT (only BIP-341 / Taproot does).
  - If a future caller emits a sig with raw hashtype 0 expecting
    "Core would reject this", ouroboros's verifier silently accepts
    it.
  - Cross-cite the **comment-as-confession** pattern below (the
    code comment "if base_type == 0: base_type = 0x01" has NO
    explanation of why — pure cargo-cult).

**File:** `src/ouroboros/script.py:696-697`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1600-1675`
(no remap; raw nHashType used).

**Impact:**
- Latent: same hash produced, no consensus split via THIS path.
- Defensive failure mode: a maliciously crafted sig with hashtype
  0 on a SegWit-v0 P2WPKH input is accepted by ouroboros but
  Core's `IsDefinedHashtypeSignature` returns false → Core
  rejects with `SCRIPT_ERR_SIG_HASHTYPE`, ouroboros accepts. **Soft
  consensus divergence**: ouroboros accepts a non-standard sig
  Core rejects. The remap is **lax** (over-acceptance).
- Cross-cite **"silent-remap-vs-strict-reject"** fleet pattern.

---

## BUG-7 (P1) — `_taproot_sighash` wallet helpers silently produce wrong sighash on SIGHASH_SINGLE-out-of-range; not None / not error

**Severity:** P1 (wallet-emits-bogus-Schnorr-sig). The wallet-side
helpers `_taproot_sighash` at `rpc.py:7569-7625` and
`rpc.py:9984-10042` (a 4-pipeline duplicate) handle SIGHASH_SINGLE
as follows:

```python
# rpc.py:7596-7610 (and identical at 9984+)
if base not in (2, 3):
    outs = bytearray()
    for o in tx.outputs:
        ...
    data.extend(hashlib.sha256(bytes(outs)).digest())
elif base == 3 and idx < len(tx.outputs):
    o = tx.outputs[idx]
    out = struct.pack("<q", o.value)
    ...
    data.extend(hashlib.sha256(out).digest())
else:
    data.extend(b"\x00" * 32)   # <-- WRONG: silently zeros
```

The `else` branch fires when `base == 3 AND idx >= len(tx.outputs)`.
BIP-341 §"Common signature message" explicitly says this case is
**invalid** and the verifier MUST return false
(`SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`). The verifier-side
`_compute_taproot_sighash` (`script.py:2638-2646`) correctly returns
`None` in this case and the caller maps to error.

But the wallet helper **silently writes 32 zero bytes** and produces
a tagged-hash over the resulting buffer. The wallet then signs that
hash and emits a Schnorr signature that:
  1. Does not match any sighash Core's verifier would ever compute.
  2. Is structurally valid (64 bytes, on-curve R, valid S).
  3. Fails verify at the next mempool / block validation hop with
     `SCRIPT_ERR_SCHNORR_SIG` (the sig verifies against a different
     message than the one Core computes).

**File:** `src/ouroboros/rpc.py:7609-7610`,
`src/ouroboros/rpc.py:10027-10028` (4-pipeline duplicate).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1538-1550`
returns false for `in_pos >= tx_to.vout.size()` under SIGHASH_SINGLE.

**Impact:**
- Wallet emits an unspendable transaction whenever the user issues
  `signrawtransactionwithwallet` (signs via the 7569 path) or
  `walletprocesspsbt` (signs via the 9984 path) with SIGHASH_SINGLE
  and idx-out-of-range.
- The transaction broadcasts then bounces (mempool rejects).
- Cross-cite the N-pipeline drift in BUG-8 — both wallet helpers
  share the same bug because they were copy-pasted from each other.

---

## BUG-8 (P1) — N-pipeline drift: 5 sighash implementations, 4 tagged-hash copies, 2 `_legacy_sighash` closures

**Severity:** P1 (architectural rot, root cause for BUG-4 and BUG-7).
ouroboros's sighash computation lives in:

| Function | File | LOC | Notes |
|----------|------|-----|-------|
| `_calculate_signature_hash` (legacy) | `script.py:1867` | ~100 | Verifier path. SIGHASH_SINGLE bug **correct** |
| `_compute_segwit_v0_sighash` (BIP-143) | `script.py:685` | ~66 | Verifier path. **BUG-6** remap |
| `_compute_taproot_sighash` (BIP-341) | `script.py:2518` | ~148 | Verifier path. Correct return-None on SIGHASH_SINGLE-OOR |
| `signature_hash_legacy` (Rust) | `sync/src/validate/sighash.rs:143` | ~85 | **Wired into nothing** (`verify_signature_in_script` etc. don't call it — W159 BUG-6) |
| `bip143_sighash` | `segwit_v0.py:79` | ~65 | Wallet signing path; documented "single source of truth" |
| `_bip143_sighash` (method) | `wallet.py:2034` | ~48 | Used by `bump_fee` + `send_transaction`. Inline copy |
| `_legacy_sighash` (closure) | `rpc.py:7519` | ~41 | **BUG-4** SIGHASH_SINGLE-OOR `bytes(32)` |
| `_taproot_sighash` (closure) | `rpc.py:7569` | ~57 | **BUG-7** SIGHASH_SINGLE-OOR |
| `_legacy_sighash` (closure) | `rpc.py:10231` | ~41 | **BUG-4 dup** SIGHASH_SINGLE-OOR `bytes(32)` |
| `_taproot_sighash` (closure) | `rpc.py:9984` | ~57 | **BUG-7 dup** SIGHASH_SINGLE-OOR |

**5 distinct sighash code paths** for the same protocol. Each was
written from scratch when the calling RPC was added; the closures
in `rpc.py` exist because `signrawtransactionwithwallet` and
`walletprocesspsbt` could not import from each other without a
refactor.

`_tagged_hash` is defined **4×** (`script.py:274`, `taproot.py:46`,
`descriptors.py:92`, `transport_v2.py:383`). `SECP256K1_ORDER` is
defined **3×** (`wallet.py:53`, `descriptors.py:67`, `taproot.py:42`)
— the `script.py` copy at line 126 is the half-order
`SECP256K1_ORDER_HALF`.

**Impact:**
- BUG-4 and BUG-7 (P0-CONS-class wallet signing bugs) are direct
  consequences of N-pipeline drift.
- Any future BIP-341-V2 / BIP-119 / BIP-118 / BIP-431 / BIP-345 /
  BIP-Hai-an-extension change must be applied in 5 places. Probability
  of all 5 staying consistent decreases geometrically.
- Pattern is fleet-recurring: **W155 ouroboros 7-pipeline drift**
  on `getblocktemplate` already documented; W156 ouroboros
  `_partial_cmpct_blocks` 8-pipeline. W160 reveals the same shape
  in the sighash family.

---

## BUG-9 (P0-SEC) — `_verify_input_signature` cache key uses fake sighash material; not the actual sighash (W159 BUG-13 carry-forward, STILL OPEN)

**Severity:** P0-SEC (cache-key collision can mark INVALID sigs as
cached-valid).

`validation.py:2152`:

```python
sighash_material = tx.get_txid() + _struct.pack("<I", input_index)
```

This is NOT the sighash. It's a 36-byte string of (txid || input_index).
For a given (txid, input_index) tuple:
  - The "real" sighash varies with `sighash_type` (ALL vs NONE vs
    SINGLE vs +ANYONECANPAY = 6 distinct sighashes per input).
  - For Taproot key-path with implicit SIGHASH_DEFAULT (0x00), the
    sighash also varies with `ext_flag`, `annex`, `tap_leaf_hash`,
    and `codesep_pos`.

ouroboros's cache key uses ONLY (txid, input_index). All sighashes
for the same `(txid, input_index)` tuple collide on the same cache
key. The cache *also* includes `pubkey_bytes` and `sig_bytes`
(line 2153-2154) — `pubkey_bytes` is `utxo['script_pubkey']` and
`sig_bytes` is `tx_in.script_sig`. **For SegWit inputs, `script_sig`
is empty**; the actual signature lives in `tx_in.witness`. So for
EVERY SegWit input, the cache key contains:

  - "fake" 36-byte (txid + idx)
  - 22 / 34 / 25 bytes of `script_pubkey`
  - **empty** `script_sig`
  - `flags` (uint32)

For 2 SegWit inputs from the same tx with the same UTXO
scriptPubKey (e.g. spending two outputs of the same parent), the
cache keys collide. If input #0 verifies successfully and is
cached, input #1's lookup returns True regardless of whether the
witness sigs are valid. **Cross-input cached false-positive**.

**Worse for Taproot**: `script_pubkey` for two distinct P2TR outputs
with the same `derive_taproot_output_xonly` tweak (e.g. same internal
key, both BIP-86 key-path-only) is identical. Witness lives outside
`script_sig`. Two inputs collide on the cache key. Insert one valid;
the other LOOKS valid.

**File:** `src/ouroboros/validation.py:2152`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp:55-90`
`ComputeEntryECDSA(entry, hash, vchSig, pubkey)` — `hash` is the
ACTUAL 32-byte sighash output, `vchSig` is the actual signature.

**Impact:**
- Cached-false-positive for any tx with two inputs sharing a
  `(txid, input_index)` collision class.
- For SegWit and Taproot transactions, this is REGULARLY hit
  (e.g. spending multiple UTXOs from the same wallet, same address
  reuse pattern).
- **PRE-CONS class**: cached-false-positive can let an invalid sig
  pass `accept_to_mempool` if its sibling input's sig was previously
  verified. Block validation re-runs the full sigcheck (sigcache is
  invoked but real verifier still runs on miss) — so consensus is
  saved by the cache-miss path. But a mempool-only relay vector
  exists.
- Test that PINS this bug as a feature: `test_w105_checkqueue.py:437-451`
  uses literal `b"sighash_material" + bytes(16)` strings as the
  cache key — TESTS THE SHAPE OF THE KEY, NOT THE CORRECTNESS OF
  THE KEY. Classic **test-pins-bug** pattern; the test passes, but
  it pins the divergence as if it were correct.
- Carry-forward from W159 BUG-13 (audited 2026-05-18); still
  present at head `0dd8eea`. **9-day-open at head**, increasing.

---

## BUG-10 (P1-SEC) — `HDKey.derive_child` does BIP-32 scalar add in pure-Python int (not constant-time, leaks timing channel)

**Severity:** P1-SEC. `wallet.py:643`:

```python
child_int = (il + int.from_bytes(self.private_key, "big")) % SECP256K1_ORDER
if child_int == 0:
    raise ValueError("Derived key is zero")
child_key = child_int.to_bytes(32, "big")
```

This is **CPython int** modular arithmetic. CPython's `int` type:
  - Uses a variable-length big-int representation (PyLong).
  - Multi-limb operations branch on per-limb carries.
  - `int.to_bytes` allocates fresh memory whose layout depends on
    the bit-length of the underlying int.
  - `%` operation is not constant-time in either operand.

**Result**: the time taken by `derive_child` measurably correlates
with the leading bits of the parent's private key. An attacker who
can measure derivation latency (cloud-VM cohabitant, shared-cache
side channel, network-RTT-based remote timing on RPC) can recover
seckey bits over many `derive_child` calls.

Bitcoin Core uses `secp256k1_ec_seckey_tweak_add` (`key.cpp:307`):

```cpp
bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_static,
    (unsigned char*)keyChild.begin(), vout.data());
```

`secp256k1_ec_seckey_tweak_add` is constant-time (libsecp256k1
guarantee). No timing leak.

**File:** `src/ouroboros/wallet.py:630-654` (`HDKey.derive_child`).

**Core ref:** `bitcoin-core/src/key.cpp:293-314` (`CKey::Derive`).

**Impact:**
- Every wallet using `derive_path("m/84'/0'/0'/0/N")` for N children
  exposes O(N) timing samples. Over a few hours of `getnewaddress`
  RPC calls, the attacker recovers the master xprv.
- Combined with **BUG-11 (side-channel-blinding-disabled)**, the
  timing channel is unprotected end-to-end.
- Fleet pattern: **"BIP-32-priv-pure-python"** (also confirmed in
  earlier W118 wallet audit; now formally numbered).
- The PUBKEY-side `derive_child` in `descriptors.py:188-207` uses
  `coincurve.PublicKey.add` which IS constant-time (libsecp256k1
  internal). So the **asymmetry** between priv-side (pure-Python)
  and pub-side (libsecp256k1) is a "two-pipeline drift" where one
  half got the security treatment and the other did not.

---

## BUG-11 (P0-SEC) — `secp256k1_context_randomize` never called (W159 BUG-3 carry-forward, STILL OPEN AT HEAD)

**Severity:** P0-SEC ("side-channel-blinding-disabled" — fleet-wide
saturating pattern). Cross-confirmed at W160 with `grep -rn
"context_randomize\|seeded_randomize" src/ ferrous-utils/` returning
zero production hits — same gap as W159.

The relevant context objects:
  - `ferrous-utils/common/src/crypto/secp.rs:22` `SECP_CTX.get_or_init(Secp256k1::new)`
  - `ferrous-utils/common/src/crypto/mod.rs:28, 66` per-call
    `Secp256k1::verification_only()`
  - `ferrous-utils/common/src/crypto/bip324.rs:165` per-call `Secp256k1::new()`
  - coincurve's `GLOBAL_CONTEXT` reached via cffi in `src/ouroboros/transport_v2.py:56`

All four NEVER call `randomize` / `seeded_randomize`. Cumulative
process state: zero side-channel blinding on any of: ECDSA verify,
ECDSA sign (via coincurve), Schnorr verify, Schnorr sign (via
coincurve), BIP-324 ellswift / ECDH, BIP-340 tagged-hash.

Bitcoin Core mandates blinding at `key.cpp:579-583`:

```cpp
std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
GetRandBytes(vseed);
bool ret = secp256k1_context_randomize(ctx, vseed.data());
assert(ret);
```

**File / Core ref:** see W159 BUG-3 for full citation chain.

**Impact:**
- Power-analysis / cache-timing side-channel against every signing
  and verification path (sign-message, sign-raw-tx, taproot
  derivations, BIP-32 priv path which is ALREADY leaky per BUG-10).
- Confirmed unchanged at head `0dd8eea`. ouroboros is the 4-of-4
  hashhog fleet impl with this gap (lunarblock + rustoshi + nimrod
  + clearbit per W158/W159).

---

## BUG-12 (P1) — 4 parallel secp256k1 contexts; dual-version `secp256k1 0.29.1` + `0.31.1` (W159 BUG-2 carry-forward)

**Severity:** P1 (architectural). Same as W159 BUG-2 — still present
at head `0dd8eea`.

`Cargo.lock` confirms:
```
name = "secp256k1"   version = "0.29.1"
name = "secp256k1"   version = "0.31.1"
name = "secp256k1-sys"  version = "0.10.1"
name = "secp256k1-sys"  version = "0.11.0"
```

Two distinct copies of libsecp256k1 are statically linked into the
rustoshi sync `.so`. Combined with coincurve's bundled libsecp256k1
(reached via Python cffi in `transport_v2.py:56`), three copies of
the C library coexist in the same address space.

**File / Core ref:** see W159 BUG-2.

**Impact:**
- BUG-11 has to be done N times to cover all N contexts.
- ~1 MB pre-computed table per context = ~3 MB resident wasted.
- Differential-analysis risk if the two Rust crate versions
  diverge on a future bugfix.

---

## BUG-13 (P1-PERF) — Multisig `sign_p2wsh_input` recomputes `bip143_sighash` per signing key

**Severity:** P1-PERF (correctness-adjacent). `segwit_v0.py:307-389`,
multisig branch:

```python
for pk in script_pubkeys:
    if len(sigs_in_order) >= m:
        break
    key = keys_by_pubkey.get(pk)
    if key is None:
        continue
    sh = bip143_sighash(
        tx, input_index, witness_script, value, sighash_type
    )                                            # <-- inside the loop
    sig = key.sign(sh) + bytes([sighash_type])
```

The sighash doesn't depend on the signing key. For an M-of-N P2WSH
multisig, this computes the same sighash up to N times — O(N) extra
BIP-143 sighash digests per multisig input signed.

Combined with BUG-5 (BIP-143 has no `PrecomputedTransactionData`
cache), an M-of-N multisig input on a transaction with K inputs
triggers `O(N * K)` outpoint serializations where `O(K)` suffices.

**File:** `src/ouroboros/segwit_v0.py:357-359`.

**Core ref:** `bitcoin-core/src/script/sign.cpp::ProduceSignature`
computes sigmsg once per (input, sighash_type) and reuses across
all keys in a multisig.

**Impact:**
- Inefficient signing for high-N multisig wallets.
- Cross-cite the `_legacy_sighash` closures (BUG-4): they ALSO
  recompute per key in the multisig branch upstream.

---

## BUG-14 (P1) — `verify_p2pkh_signature` Rust returns `Ok(true)` after only checking pubkey hash; dead-but-public-returns-true (W159 BUG-6 carry-forward)

**Severity:** P1 (W159 BUG-6 carry-forward; STILL OPEN AT HEAD).
`ferrous-utils/sync/src/validate/script.rs:1413-1461`:

```rust
fn verify_p2pkh_signature(...) -> Result<bool> {
    // ... extract sig/pubkey from script_sig ...
    let pubkey_hash = crypto::hash160(pubkey_bytes);
    if &pubkey_hash[..] != expected_hash {
        return Ok(false);
    }
    // For now, skip actual signature verification
    // In production, this would create the sighash and verify the signature
    // using secp256k1
    Ok(true)
}
```

Identical shape at `verify_p2pk_signature` (`script.rs:1499`),
`verify_witness` (`script.rs:1506-1516`) returns `Ok(false)`
unconditionally.

These are **`pub fn`**, exported via `validate/mod.rs:21`:

```rust
pub use script::{ScriptInterpreter, ScriptError, ScriptType, Stack,
    identify_script_type, verify_signature_in_script, verify_witness};
```

Not wired into PyO3 — `lib.rs` does not register a `#[pyfunction]`
for them. So Python callers can't reach them. But:
  1. The functions are public Rust API.
  2. If anyone (a future native-Rust block validator, the
     `validate/block.rs` path, a fuzz harness) calls
     `verify_signature_in_script(tx, idx, p2pkh_spk)`, it returns
     `Ok(true)` for any (sig, pubkey) whose hash matches the spk's
     hash. **No actual sig check.**

`bitcoin-core/src/script/interpreter.cpp::EvalScript` calls
`CheckECDSASignature` for OP_CHECKSIG — never returns true without
a full ECDSA verify.

**File:** `ferrous-utils/sync/src/validate/script.rs:1413-1500`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1828-1841`.

**Impact:**
- Pattern: **"dead-but-public-returns-true"** (W159 origin, now
  cross-cited at W160 again).
- Latent today (no production caller). Cocked-and-ready for a
  future Rust path that imports the helper and trusts the
  return.
- Cross-cite `comment-as-confession` saturation: "For now, skip
  actual signature verification" — admits incompleteness in the
  one-line comment above the wrong return.

---

## BUG-15 (P1) — `_taproot_tweak_pubkey` swallows all exceptions; identity-point on derive silently returns None

**Severity:** P1. `script.py:2452-2473`:

```python
def _taproot_tweak_pubkey(
    self, internal_key: bytes, tweak: bytes
) -> tuple[bytes, int] | None:
    try:
        from coincurve import PublicKeyXOnly
        pk = PublicKeyXOnly(internal_key)
        pk.tweak_add(tweak)
        return pk.format(), int(pk.parity)
    except ImportError:
        return None
    except Exception:
        return None
```

`except Exception:` is too broad. Possible exceptions:
  - `ImportError` (coincurve missing) — caller can't recover.
  - `coincurve.Error: tweak_add: arithmetic exception` (BIP-341
    edge case where `internal_key + tweak * G == identity`,
    probability ~1/n).
  - `ValueError` (malformed `internal_key`).
  - `MemoryError` / `KeyboardInterrupt` / `SystemExit` (caught
    by `except Exception`).

All map to `return None`. The caller (`_verify_taproot_scriptpath`
at `script.py:2384-2385`) treats None as "verify fails" — same
script-side outcome. But:
  1. **The identity-point case is observable consensus behavior**:
     BIP-341 says if the tweaked key is identity, the tx is invalid.
     ouroboros gets this right (returns False).
  2. **The malformed-internal-key case is undefined**: a 32-byte
     value with x-coord >= field-prime or no-square-root-y is "not
     on curve". BIP-341 specifies this is `lift_x` failure ⇒
     "invalid". ouroboros returns False. OK.
  3. **The infrastructure-error case (MemoryError, etc.)**: these
     are caught silently. Production crashes look like "signature
     failed" to the caller. Diagnostic loss.

**File:** `src/ouroboros/script.py:2452-2473`.

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h`
`secp256k1_xonly_pubkey_tweak_add_check` — distinguishes
"signature failed" from "library error" via separate return codes.

**Impact:** Diagnostic loss; no consensus impact.

---

## BUG-16 (P1) — `_compute_taproot_sighash` allows sighash_type encoding ambiguity at boundaries

**Severity:** P1. `script.py:2544-2546`:

```python
if not (sighash_type <= 0x03
        or (0x81 <= sighash_type <= 0x83)):
    return None
```

This rejects sighash_type values outside `{0x00, 0x01, 0x02, 0x03,
0x81, 0x82, 0x83}`. Good. But:
  - `sighash_type <= 0x03` includes `sighash_type < 0` (signed int
    in Python). Python `int` is unbounded, so a negative
    `sighash_type` (passed as the result of `sig[-1]` which is `int`
    in Python — always >=0) is irrelevant here since the source is
    always an unsigned byte. Acceptable.
  - The comment at `script.py:2540-2542` says "Any other byte is
    invalid and Core rejects via SCRIPT_ERR_SCHNORR_SIG_HASHTYPE
    (interpreter.cpp:1516)". Check Core: line 1516 in current
    Core `interpreter.cpp` is at `bitcoin-core/src/script/interpreter.cpp:1516`
    `const uint8_t output_type = (hash_type == SIGHASH_DEFAULT) ?
    SIGHASH_ALL : (hash_type & SIGHASH_OUTPUT_MASK);`. The actual
    rejection is earlier at line 1492+ — comment line-number drift.

**Lower-severity than the others but worth noting for documentation
fidelity.**

**File:** `src/ouroboros/script.py:2540-2546`.

---

## BUG-17 (P1) — Test-pins-bug at `test_w105_checkqueue.py:434-460` pins the fake-sighash SigCache key as correct

**Severity:** P1 ("test-pins-bug" — a regression test that pins a
known bug as a feature, preventing fixers from seeing the failure).

```python
# src/ouroboros/tests/test_w105_checkqueue.py:434-460
def test_no_false_cache_hit_with_different_sigs(self):
    """FIXED: a different sig on same outpoint does NOT produce a cache hit."""
    cache = SigCache(max_entries=100)
    sighash = b"sighash_material" + bytes(16)        # <-- literal placeholder
    pubkey  = b"pubkey_material_" + bytes(17)
    sig_a   = b"sig_a_material__" + bytes(48)
    sig_b   = b"sig_b_material__" + bytes(48)
    cache.insert(sighash, pubkey, sig_a, 0)
    self.assertTrue(cache.lookup(sighash, pubkey, sig_a, 0))
    self.assertFalse(cache.lookup(sighash, pubkey, sig_b, 0),
        "G9 FIXED: malleated sig must not produce a false cache hit")
```

The test claims "G9 FIXED" but uses literal byte strings as the
`sighash` parameter, exercising the cache's `_make_key` shape only.
**It does NOT verify that `sighash` is the actual sighash bytes
emitted by `_calculate_signature_hash` / `_compute_segwit_v0_sighash`
/ `_compute_taproot_sighash`.** So when `validation.py:2152` builds
a FAKE sighash material out of (txid, input_index), the test still
passes — the cache mechanism IS correct, but the wiring is wrong,
and the test only exercises the mechanism.

Pattern: **test-pins-bug** with **mechanism-vs-wiring split**.
The cache primitive works; the call site is wrong; the test
exercises the primitive in isolation.

**File:** `src/ouroboros/tests/test_w105_checkqueue.py:434-460`.

**Impact:**
- Closes the visibility loop on BUG-9 (W159 BUG-13 carry-forward):
  if a fixer runs the test suite, BUG-9 looks "tested" and they
  pass over it.
- Anti-pattern is documented at the wave-15-test-suite-shape level.

---

## BUG-18 (P1) — `derive_taproot_sign_secret` reconstructs the `coincurve.PrivateKey` solely to read pubkey parity (secret leak into 5th context)

**Severity:** P1. `taproot.py:84-86`:

```python
pub_compressed = PrivateKey(bytes(secret_d_bytes)).public_key.format(
    compressed=True
)
```

The function's purpose is BIP-341 even-Y normalization of the
internal private key `d`. Step:
  1. Compute `P = d * G` (the pubkey).
  2. If `P.y` is odd, flip `d` to `n - d`.

The implementation constructs a brand-new `coincurve.PrivateKey`
just to call `.public_key.format(compressed=True)`. This:
  - Allocates a fresh libsecp256k1 keypair (coincurve does
    `secp256k1_ec_pubkey_create` internally).
  - Stores the secret in coincurve's `GLOBAL_CONTEXT` cffi-side
    memory (a **fifth** secp256k1 instance in the process per
    BUG-12).
  - Does not call `memory_cleanse` after.

The secret bytes pass through coincurve's `PrivateKey.__init__`
which stores them in `self.secret` (a `bytes` object). When the
local `PrivateKey` object goes out of scope, Python's GC may or may
not promptly free the underlying buffer, and the `bytes` object's
storage layout (PEP 393 + Python's small-object allocator) means the
secret bytes may sit in heap memory long after the function returns.

Core's `CKey` uses `secure_allocator` + `memory_cleanse` for exactly
this reason.

**File:** `src/ouroboros/taproot.py:84-86`.

**Core ref:** `bitcoin-core/src/key.cpp:530-560` (`CKey::SignSchnorr`)
uses `secp256k1_keypair_create` which keeps the secret in
locked-memory, then explicitly `memory_cleanse(keypair)` on exit.

**Impact:**
- Every P2TR signing operation leaks the (tweaked) internal-key
  secret into coincurve's GLOBAL_CONTEXT for an indeterminate
  window.
- Combined with BUG-11 (no side-channel blinding) and BUG-10
  (BIP-32 priv path uses pure-Python int), the wallet's
  TAPROOT signing path has the weakest end-to-end security
  posture in the entire ouroboros codebase.

---

## BUG-19 (P1) — `parse_multisig_script` accepts uncompressed pubkey in P2WSH (BIP-141 violation)

**Severity:** P1. `segwit_v0.py:235`:

```python
if 1 <= op <= 0x4B and len(payload) in (33, 65):
    pubkeys.append(bytes(payload))
```

Accepts both 33-byte compressed AND 65-byte uncompressed pubkeys
in P2WSH witness scripts. BIP-141 §"Restrictions on public key type"
says SegWit-v0 scripts (P2WPKH and P2WSH) MUST use compressed
pubkeys (33 bytes). Bitcoin Core enforces this via
`SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` policy flag (mandatory for
SegWit-v0 outputs accepted into mempool / non-standard).

Calling `sign_p2wsh_input` (`segwit_v0.py:307`) on a witnessScript
containing a 65-byte pubkey will:
  1. Parse it via `parse_multisig_script` → returns (M, [65B-key, ...]).
  2. Match against `keys_by_pubkey` (line 343 builds dict from
     `WalletKey.pubkey` which is the 33-byte compressed form).
  3. **No match** → returns empty signature stack.

So the bug is **silently no-op** for ouroboros wallets (which only
generate compressed keys). But:
  - A future code path that supplies uncompressed keys (e.g. PSBT
    finalizer with `key_origin_info` pointing to a legacy hardware
    wallet) gets confusing "no matching key" errors.
  - The parser **accepts** scripts that Core would reject as
    non-standard. ouroboros wallet could be tricked into "signing"
    a P2WSH whose witnessScript Core would never accept.

**File:** `src/ouroboros/segwit_v0.py:215, 235`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::CheckPubKey`
(`SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` gate).

**Impact:** Defense-in-depth gap; wallet over-accepts witnessScript
shapes Core rejects.

---

## BUG-20 (P1) — `_lax_der_to_compact` default `normalize_s=True` admits S-malleated sigs through the fallback path

**Severity:** P1 (defense-in-depth). `script.py:1970-2026`:

```python
@staticmethod
def _lax_der_to_compact(der_sig: bytes, normalize_s: bool = True):
    ...
    s_int = int.from_bytes(s_bytes, 'big') if s_bytes else 0
    # Only normalize to low-S when requested (i.e. LOW_S flag is set)
    if normalize_s:                         # <-- default True
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if s_int > order // 2:
            s_int = order - s_int
    return r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big')
```

The doc comment claims "Only normalize to low-S when requested
(i.e. LOW_S flag is set)" — but the default is `normalize_s=True`,
and the call at `script.py:2080` always passes `True` after the
`normalize_s=False` attempt at line 2069.

So the verifier's **fallback path** silently normalizes S, accepting
a sig that:
  - Has non-canonical DER encoding (extra leading zero, etc).
  - Has high-S (BIP-62 violation).

In production, the strict path at `script.py:2063` (`pk.verify(der_sig,
...)`) runs first. coincurve's `verify` does NOT enforce low-S. So
a high-S, well-formed-DER sig passes the strict path. The lax
fallback is only entered when strict fails. So this is observationally
only a problem for sigs that:
  1. Failed strict DER parse (non-canonical encoding).
  2. AND have high-S.

For such a sig, ouroboros accepts it (via lax fallback +
normalize_s=True), Core rejects it (strict DER + LOW_S both
enforced post-SegWit consensus).

**Soft-consensus divergence**.

**File:** `src/ouroboros/script.py:1970-2026, 2080-2087`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:204-220`
`IsLowDERSignature` requires `IsValidSignatureEncoding` first.

**Impact:**
- Latent: requires a sig that's both non-canonical-DER AND high-S
  to trigger. Such sigs are rare and would be rejected at the
  STRICTENC gate upstream (DERSIG | LOW_S | STRICTENC fires at
  `script.py:643, 1408, 1411, 1542, 2133` before
  `_verify_ecdsa_signature` is called). So gated in normal use.
- Defense-in-depth gap: a path that calls `_verify_ecdsa_signature`
  without the pre-gates (e.g. a future BIP-322 verifier) silently
  admits the malleation.

---

## Cross-fleet patterns

**13 NEW patterns identified or re-confirmed in W160:**

1. **"non-deterministic-where-Core-is-deterministic"** (W160 origin
   per task pre-cite, but ouroboros ECDSA sign IS deterministic via
   coincurve's RFC-6979 default — so the pattern does NOT fire on
   ouroboros ECDSA. The pattern DOES fire on Schnorr aux_rand:
   coincurve auto-generates `os.urandom(32)` per call, which is
   correct BIP-340 §3.3 behavior. **No-fire at ouroboros.** Cross-cite
   for rustoshi.)

2. **"drift-converged-on-wrong-default"** (W160 origin per task pre-cite,
   camlcoin context. Pattern: multiple impls land on a non-Core value
   that mutually agree but disagree with Core. **No-fire at ouroboros
   directly**; but cross-cite the `SECP256K1_ORDER` constant 3-copy
   pattern as a structural risk for future drift.)

3. **"defensive-true-on-error"** (BUG-1 — `_check_low_s` returns True
   on parse failure; W160 NEW formal name for the pattern, also seen
   in `_taproot_tweak_pubkey` swallowing all Exception → None at
   BUG-15. Two distinct instances within ouroboros in one wave.)

4. **"silent-remap-vs-strict-reject"** (BUG-6 — SegWit-v0 sighash
   accepts hashtype 0 by remapping to 1; Core rejects. W160 NEW name
   for a pattern that fleet-recurs in `descriptors` / `psbt` /
   `script` validation.)

5. **"N-pipeline drift in sighash family"** (BUG-8 — 5 distinct
   sighash implementations across ouroboros codebase. Extends
   ouroboros's already-documented 6-pipeline ATMP drift (W150) and
   7-pipeline GBT drift (W155) and 8-pipeline `_partial_cmpct_blocks`
   drift (W156) into the SIGHASH FAMILY for the first time. This is
   the **9th distinct N-pipeline pattern** documented in ouroboros.)

6. **"test-pins-bug with mechanism-vs-wiring split"** (BUG-17 — the
   test exercises the SigCache mechanism in isolation with literal
   placeholder bytes, masking the wiring divergence at
   `validation.py:2152`. W160 NEW formal sub-variant of test-pins-bug.)

7. **"asymmetric-security-treatment between priv-side and pub-side"**
   (BUG-10 — `HDKey.derive_child` (priv) is pure-Python int;
   `ExtendedPubKey.derive_child` (pub) uses coincurve. Security
   treatment given to the LESS sensitive of the two derivations.
   W160 NEW pattern.)

8. **"secret-leak into Nth secp256k1 context"** (BUG-18 — wallet
   leaks the (tweaked) Taproot internal key into coincurve's
   GLOBAL_CONTEXT solely to read pubkey parity. W160 NEW pattern,
   cross-cite W159 BUG-2 (4-context coexistence).)

9. **"BIP-141 WITNESS_PUBKEYTYPE accepted in parser, rejected in
   verifier"** (BUG-19 — `parse_multisig_script` accepts 65-byte
   uncompressed in P2WSH; Core's policy rejects. W160 NEW name.)

10. **"comment-says-low-S, code-says-always-normalize"** (BUG-20 —
    docstring claims "Only normalize when requested" but default is
    True; classic **comment-as-confession** subvariant — the comment
    DOCUMENTS the bug-fix-intent that was never wired through.)

11. **"side-channel-blinding-disabled"** (BUG-11 — W159 BUG-3
    carry-forward; ouroboros remains 1 of 5 hashhog impls (lunarblock
    + rustoshi + nimrod + clearbit + ouroboros) confirmed missing
    the blinding step. Wave-level fleet pattern at saturation.)

12. **"fake-sighash SigCache key"** (BUG-9 — W159 BUG-13 carry-forward;
    STILL OPEN AT HEAD `0dd8eea` 1+ days after W159 audit. Pattern
    origin ouroboros; not yet observed elsewhere — but the underlying
    cause (using (txid, idx) as a stand-in for sighash) could appear
    anywhere a "real sighash is expensive, let me use a quick proxy"
    optimization is made.)

13. **"dead-but-public-returns-true"** (BUG-14 — W159 BUG-6
    carry-forward; STILL OPEN AT HEAD. Pattern origin ouroboros at W159.)

**Pattern saturation observation (cumulative through W160):**

- **comment-as-confession**: 19+ distinct subvariant fleet-wide; now
  recurring **MULTIPLE TIMES PER WAVE** in single-impl audits.
- **N-pipeline drift**: 9 distinct subsystem instances in ouroboros
  alone (ATMP, GBT, cmpctblock, sighash, plus earlier waves).
- **test-pins-bug**: BUG-17 is the 5th+ distinct ouroboros
  instance (test_sig_cache + test_w127_taproot + test_w105_checkqueue
  + others).
- **two-pipeline guard**: now 22+ distinct extensions fleet-wide.

**W160 cumulative meta-tally:**

- **Carry-forward bugs from W158-W159 still present at head**:
  BUG-2 (W159 BUG-4), BUG-3 (W159 BUG-5), BUG-9 (W159 BUG-13),
  BUG-11 (W159 BUG-3), BUG-12 (W159 BUG-2), BUG-14 (W159 BUG-6) — **6
  carry-forward bugs** in one wave. Audit drumbeat outpacing fix
  drumbeat by 9 days for the ouroboros sub-corpus.

---

## Priority fix list (ordered by P-class, then by leverage)

1. **🚨 BUG-4 (P0-CONS) `_legacy_sighash` SIGHASH_SINGLE-OOR ⇒ `b'\x01' + b'\x00'*31`** in 2 sites (`rpc.py:7547` + `rpc.py:10258`). ~2 LOC each, closes "wallet emits unspendable sigs on legacy SIGHASH_SINGLE-OOR".

2. **🚨 BUG-9 (P0-SEC) Wire `_verify_input_signature` to use the actual sighash bytes** (`validation.py:2152`). Refactor `ScriptInterpreter.verify` to return the sighash it computed (or thread the sighash through the call). ~30 LOC, closes "cached-false-positive across SegWit inputs with shared scriptPubKey". W159 BUG-13 5-day-open carry-forward.

3. **🚨 BUG-11 (P0-SEC) Call `seeded_randomize` on `SECP_CTX` post-init** (`ferrous-utils/common/src/crypto/secp.rs:22`). ~5 LOC. Also coincurve's GLOBAL_CONTEXT — that one needs a feature request upstream OR a one-time call via cffi at process start. W159 BUG-3 carry-forward; fleet-wide pattern.

4. **🚨 BUG-7 (P1) `_taproot_sighash` wallet helpers should raise on SIGHASH_SINGLE-OOR**, not silently zero-pad. 2 sites (`rpc.py:7609-7610` + `rpc.py:10027-10028`). ~3 LOC each.

5. **🚨 BUG-10 (P1-SEC) `HDKey.derive_child` switch to `coincurve.PrivateKey(parent).add(...)`** — coincurve exposes a method that uses libsecp256k1's `secp256k1_ec_seckey_tweak_add`. ~5 LOC + test. Closes the BIP-32 priv pure-Python timing channel.

6. **🚨 BUG-8 (P1) Collapse the 5 sighash code paths to ONE**: re-export `ScriptInterpreter._calculate_signature_hash`, `_compute_segwit_v0_sighash`, `_compute_taproot_sighash` as module-level functions and import from `rpc.py` + `wallet.py` + `segwit_v0.py`. ~50 LOC delete + ~10 LOC re-import. Eliminates BUG-4 + BUG-7 at their root.

7. **🚨 BUG-2 (P1) `WalletKey.sign` post-sign verify paranoia**: `_privkey.public_key.verify(sig, message_hash, hasher=None)` after `sign`. ~3 LOC. Closes the hardware-bitflip / fault-injection class fleet-wide for ouroboros.

8. **🚨 BUG-3 (P1) `signmessage` recovery round-trip vs source pubkey**: after `sign_recoverable`, call `PublicKey.from_signature_and_message` and compare via `bytes(pub)`. ~5 LOC per RPC, 2 RPCs.

9. **🚨 BUG-5 (P1-PERF) Port `PrecomputedTransactionData`**: cache the 3 (BIP-143) + 5 (BIP-341) digests once per tx. ~80 LOC + plumbing through the `ScriptInterpreter.verify` API.

10. **🚨 BUG-13 (P1-PERF) Hoist `bip143_sighash` out of the multisig per-key loop** (`segwit_v0.py:357-359`). ~3 LOC.

11. **🚨 BUG-12 (P1) Drop one of the two `secp256k1` Rust-crate versions** by patching `bitcoin = "0.32"` to use the same `secp256k1` version as direct deps. May require waiting for an upstream `bitcoin` crate bump. ~Cargo.toml edit + verify.

12. **🚨 BUG-14 (P1) Remove or implement `verify_p2pkh_signature` / `verify_p2pk_signature` / `verify_witness` Rust functions** — either delete (and remove the `pub use` re-export) or wire them to the actual sighash + ECDSA / Schnorr verify. ~20-50 LOC.

13. **🚨 BUG-17 (P1) Fix the test at `test_w105_checkqueue.py:434-460`** to exercise REAL sighash material via `_compute_segwit_v0_sighash` or similar, not literal `b"sighash_material"` placeholders. Test would then catch BUG-9 immediately.

14. **🚨 BUG-1 (P1) `_check_low_s` returns False on malformed input**, not True. ~3 LOC edits at lines 393, 395, 400.

15. **🚨 BUG-6 (P1) Remove the silent `base_type == 0 ⇒ 0x01` remap** in `_compute_segwit_v0_sighash` (`script.py:696-697`). Reject undefined hashtype 0 in SegWit-v0 with the same diagnostic as STRICTENC failures.

16. **🚨 BUG-15 (P1) Tighten the `except Exception:` in `_taproot_tweak_pubkey`** to specifically `except (ImportError, coincurve.Error, ValueError):`.

17. **🚨 BUG-18 (P1) Use `coincurve.PublicKey.from_secret(secret_d_bytes)`** — exposes only the pubkey without committing the secret to GLOBAL_CONTEXT. Or compute parity directly via `derive_taproot_output_xonly` semantics (avoid coincurve allocation entirely).

18. **🚨 BUG-19 (P1) `parse_multisig_script` reject 65-byte uncompressed in P2WSH** — add an `if pubkey_len == 65: continue` for SegWit-v0 scripts.

19. **🚨 BUG-20 (P1) `_lax_der_to_compact` default `normalize_s=False`** — match the docstring's claim. Caller-side LOW_S enforcement must be explicit, not silent normalization.

20. **🚨 BUG-16 (P1) Update the comment-line-number in `_compute_taproot_sighash`** to match current Core interpreter.cpp.

---

## Summary

20 bugs catalogued. **3 P0-class** (BUG-4 P0-CONS wallet-emits-unspendable-sigs, BUG-9 P0-SEC SigCache fake-sighash key, BUG-11 P0-SEC side-channel-blinding-disabled), **17 P1**. Estimated single-engineer fix burden: 2-3 PRs covering all 20 (~400 LOC + ~150 LOC tests).

6 carry-forward bugs from W159 STILL OPEN AT HEAD (BUG-2, BUG-3, BUG-9, BUG-11, BUG-12, BUG-14) — audit drumbeat outpacing fix drumbeat by 9 days.

13 distinct cross-fleet patterns identified or re-confirmed; 3 W160 NEW patterns (defensive-true-on-error, silent-remap-vs-strict-reject, asymmetric-security-treatment between priv/pub derivation paths).
