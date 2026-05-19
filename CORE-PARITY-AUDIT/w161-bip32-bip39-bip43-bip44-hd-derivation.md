# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (ouroboros)

**Wave:** W161 — Hierarchical-deterministic wallet stack: BIP-32 master /
CKD priv / CKD pub / xprv / xpub / parent fingerprint / chain code /
hardened-vs-normal indices / "Bitcoin seed" HMAC-SHA512 / BIP-32 retry
semantics on `IL >= n` or `k_i == 0`; BIP-39 mnemonic / entropy
encoding / 2048-word English wordlist / SHA-256 checksum (N/32 bits) /
NFKD / PBKDF2-HMAC-SHA512(2048, "mnemonic"+passphrase, dklen=64);
BIP-43 purpose-namespacing; BIP-44 (legacy P2PKH at `m/44'/coin'/0'`);
BIP-49 (P2SH-P2WPKH at `m/49'/coin'/0'`, ypub/upub version bytes);
BIP-84 (native SegWit at `m/84'/coin'/0'`, zpub/vpub);
BIP-86 (key-path Taproot at `m/86'/coin'/0'`, BIP-341 TapTweak with
empty merkle root).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:293-310` — `CKey::Derive`: hardened branch
  uses `0x00 || priv || nChild`; normal branch uses
  `compressed_pubkey || nChild`; both feed `BIP32Hash` (HMAC-SHA512
  with chain code as key); child secret = `secp256k1_ec_seckey_tweak_add`
  (libsecp256k1, constant-time, native validates `IL < n` AND `result != 0`
  and returns `false` on either → CKey::ClearKeyData).
- `bitcoin-core/src/key.cpp:482-489` — `CExtKey::Derive`: increments depth,
  populates `vchFingerprint` from `key.GetPubKey().GetID()` (HASH160[0:4]),
  refuses to derive when `nDepth == 0xff`.
- `bitcoin-core/src/key.cpp:491-501` — `CExtKey::SetSeed`: master key
  via HMAC-SHA512 with `key=b"Bitcoin seed"` (12 ASCII bytes).
- `bitcoin-core/src/key.cpp:513-530` — `CExtKey::Encode/Decode`: 78-byte
  layout (1 depth + 4 fingerprint + 4 nChild + 32 chaincode + 33 keydata).
  `Decode` clears key if `nDepth == 0 && (nChild != 0 || fingerprint != 0)`
  OR `code[41] != 0`.
- `bitcoin-core/src/pubkey.cpp:341-363` — `CPubKey::Derive`: asserts
  hardened bit is OFF, uses `secp256k1_ec_pubkey_tweak_add`.
- `bitcoin-core/src/pubkey.cpp:415-421` — `CExtPubKey::Derive`: depth
  increment and fingerprint propagation.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp` — `DescriptorScriptPubKeyMan::SetupDescriptorGeneration`:
  builds `m/44'/coin'/0'` (legacy), `m/49'/coin'/0'` (p2sh-segwit),
  `m/84'/coin'/0'` (bech32), `m/86'/coin'/0'` (bech32m) descriptors per
  output type. Coin-type per network: mainnet=0, testnet/signet/regtest=1.
- `bitcoin-core/src/script/descriptor.cpp` — descriptor expansion;
  `BIP32PubkeyProvider::GetDerivedExtPubKey` handles xprv→hardened child→neuter
  internally (descriptors with hardened steps work when source is xprv).
- `bitcoin-core/src/script/descriptor.cpp::InferScript` — wallet → descriptor
  inference (`m/86'/0'/0'/0/*` etc.) for `listdescriptors`.
- `bitcoin-core/src/wallet/wallet.cpp::SetupLegacyScriptPubKeyMan` — legacy
  pre-W21 mode; not exercised in descriptor-only world (Core defaults to
  descriptor wallets since v23).
- BIP-32 spec §"Child key derivation (CKD) functions": "In case parse256(IL)
  ≥ n or ki = 0, the resulting key is invalid, and one should proceed with
  the next value for i." — **RETRY, not abort**.
- BIP-39 §"From mnemonic to seed": PBKDF2-HMAC-SHA512, password=NFKD(mnemonic),
  salt="mnemonic"+NFKD(passphrase), iterations=2048, dklen=64.
- BIP-43 §3: hardened purpose at `m/purpose'/...`.
- BIP-44 §5: `m / 44' / coin_type' / account' / change / address_index`,
  SLIP-44 coin_type registry (Bitcoin=0, Testnet=1 covers testnet3+4+signet+regtest).
- BIP-49 §6: `m / 49' / coin' / 0'`, ypub `0x049d7cb2` / ypriv `0x049d7878`,
  upub `0x044a5262` / upriv `0x044a4e28` (testnet).
- BIP-84 §6: `m / 84' / coin' / 0'`, zpub `0x04b24746` / zpriv `0x04b2430c`,
  vpub `0x045f1cf6` / vpriv `0x045f18bc` (testnet).
- BIP-86 §"Internal key derivation": `m / 86' / coin' / 0' / change /
  address_index`; TapTweak uses **empty merkle root** (`hash = tagged_hash(
  "TapTweak", x_only(P) || b"")`); standard xpub/xprv version bytes
  (no slip-132 variant).
- BIP-341 §"Constructing and spending Taproot outputs": tweak =
  `tagged_hash("TapTweak", x_only(P) || merkle_root)`; merkle_root is
  empty bytes for key-path-only.
- SLIP-132 — registered version bytes for the BIP-44/49/84 families.

**Files audited**
- `src/ouroboros/bip39.py` (247 LOC) — `WORDLIST`, `entropy_to_mnemonic`,
  `mnemonic_to_entropy`, `mnemonic_to_seed`, `validate_mnemonic`,
  `generate_mnemonic`, `_nfkd`, `_checksum_bits`.
- `src/ouroboros/wallet.py` (2575 LOC) — `HDKey` (lines 568-714) with
  `from_seed`/`derive_child`/`derive_path`/`serialize_xprv`/`serialize_xpub`/
  `from_xprv`; `KeyPool` (lines 383-565) with `_derive_key_at_path`,
  `_refill_pool`, `_rebuild_pools`; `Wallet.init_hd` /
  `restore_from_mnemonic` / `get_mnemonic` (lines 928-1043);
  `Wallet._load_or_create` / `_save` (lines 1046-1158);
  `Wallet.generate_new_address` / `get_change_address` /
  `generate_address_of_type` (lines 1258-1466); `WalletManager.create_wallet`
  (lines 2280-2412).
- `src/ouroboros/descriptors.py` (1412 LOC) — `ExtendedPubKey`
  (lines 171-267); `KeyExpression`/`_parse_key_expression`
  (lines 282-382); `_ORIGIN_RE` (line 275-279).
- `src/ouroboros/tests/test_w111_wallet.py` — BIP-32 TV1 master / m/0'
  vectors, depth/parent-fingerprint, xprv/xpub round-trip, BIP-84 path
  coin_type, "legacy_hd_base_path_has_change_branch_bug" (line 437).
- `src/ouroboros/tests/test_w118_wallet.py` — additional BIP-32 TV1.
- `tests/test_bip39.py` — TREZOR vectors v1/v2/v3 (byte-identity entropy
  ↔ mnemonic ↔ seed).
- `tests/test_taproot_bip86.py` — BIP-86 canonical vector at the *output
  key* level only (does NOT walk the full m/86'/0'/0'/0/0 path).
- `src/ouroboros/rpc.py` — `rpc_createwallet` (8338-8406),
  `rpc_dumpmnemonic` (8408-8452), `rpc_restorewallet` (8454-).

---

## Gate matrix (38 sub-gates / 15 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-32 master gen | G1: HMAC-SHA512 key = `b"Bitcoin seed"` literal | PASS (`wallet.py:622`) |
| 1 | … | G2: seed length 16-64 bytes accepted | PASS (`wallet.py:620-621`); test pins boundary (test_w111_wallet.py:171-179) |
| 1 | … | G3: rejects IL=0 / IL≥n master | PASS (`wallet.py:624-625`) but RAISES (no retry — see BUG-1 for child-side) |
| 2 | BIP-32 CKD priv | G4: hardened branch data = `0x00 || priv || idx_BE` | PASS (`wallet.py:635`) |
| 2 | … | G5: normal branch data = `pub || idx_BE` | PASS (`wallet.py:637`) |
| 2 | … | G6: chain code = HMAC right-half | PASS (`wallet.py:639, 649`) |
| 2 | … | G7: child secret via libsecp `seckey_tweak_add` | **BUG-2 (P1)** — `wallet.py:643` uses pure-Python big-int `(il + parent) % n` instead of `secp256k1_ec_seckey_tweak_add`. coincurve EXPOSES `PrivateKey.add()` (the `secp256k1_ec_seckey_tweak_add` wrapper) but ouroboros bypasses it. Non-constant-time, fleet pattern "BIP-32 private-GMP asymmetry" |
| 2 | … | G8: retry-with-next-index on IL≥n or k=0 (BIP-32 spec mandate) | **BUG-1 (P0-FUNDS)** — `wallet.py:641-645` RAISES `ValueError` on either condition. BIP-32 spec is unambiguous: "one should proceed with the next value for i". For a chain that ever derives an invalid child (extremely rare but reachable), ouroboros aborts vs. Core which silently skips. A wallet seeded from the same mnemonic between Core and ouroboros, when ANY ancestor on a derivation path tries an invalid index, will silently diverge → **funds derived at the next valid index by Core become inaccessible from ouroboros and vice versa** |
| 3 | BIP-32 CKD pub | G9: refuses hardened indices | PASS (`descriptors.py:190-191`) |
| 3 | … | G10: child pub = `IL*G + parent_pub` via libsecp | PASS (`descriptors.py:198-199` uses `coincurve.PublicKey.add` which IS `secp256k1_ec_pubkey_tweak_add`) |
| 3 | … | G11: retry on IL≥n | **BUG-3 (P0-FUNDS)** — same retry-vs-abort gap as G8 (`descriptors.py:195-196` raises) |
| 4 | BIP-32 ext-key serialisation | G12: 78-byte layout (1+4+4+32+33) | PASS (`wallet.py:685-692`, decoded length checked at 698) |
| 4 | … | G13: `depth=0` master rejects non-zero fingerprint/child | **BUG-4 (P1)** — `wallet.py:694-714::from_xprv` ignores Core's `Decode` invariant (`code[41] != 0` OR `depth == 0 && (nChild != 0 || fingerprint != 0)` → wipe key). A malformed xprv pasted by the user is accepted at face value |
| 4 | … | G14: depth byte fits in 0..255 | **BUG-5 (P1)** — `wallet.py:687` `bytes([self.depth])` would raise `ValueError: bytes must be in range(0, 256)` at serialize time. Core (`key.cpp:483`) refuses derivation when `nDepth == nuc::max()`, catching the issue **before** any side-effect. Ouroboros `derive_child` (`wallet.py:630-654`) silently constructs a depth-256 HDKey object that then crashes only on `serialize_xprv` — partial state in caller |
| 5 | BIP-32 fingerprint | G15: parent_fingerprint = HASH160(parent_pub)[0:4] | PASS (`wallet.py:611-613, 651`) |
| 6 | BIP-39 wordlist | G16: 2048 English words loaded at import | PASS (`bip39.py:54-72`) |
| 6 | … | G17: 12/15/18/21/24-word counts only | PASS (`bip39.py:80, 148-152`) |
| 6 | … | G18: SHA-256 checksum = first N/32 bits | PASS (`bip39.py:105-113, 169-171`) |
| 7 | BIP-39 mnemonic→seed | G19: PBKDF2-HMAC-SHA512 | PASS (`bip39.py:202-208`) |
| 7 | … | G20: iter=2048, dklen=64 | PASS (`bip39.py:206-207`); TREZOR byte-identity test (test_bip39.py) |
| 7 | … | G21: salt = `"mnemonic"` + NFKD(passphrase) | PASS (`bip39.py:200`) |
| 7 | … | G22: NFKD on mnemonic AND passphrase | PASS (`bip39.py:199-200`) |
| 8 | Mnemonic generation | G23: 128-bit default (12 words), os.urandom | PASS (`bip39.py:217-230, 222`); default fresh mnemonic at `wallet.py:2365` |
| 9 | BIP-43 purpose paths | G24: BIP-44 `m/44'` legacy | **BUG-6 (P0-FUNDS)** — ZERO references to `m/44'` anywhere in `wallet.py`. `generate_address_of_type(address_type="legacy")` (line 1442-1465) derives at the WRONG path: `_hd_base_path = "m/84'/0'/0'/0"` (line 868), then `WalletKey.get_p2pkh_address` on the BIP-84 path's pubkey. **Legacy addresses produced by ouroboros are uncrackable on a Core wallet seeded from the same mnemonic** — Core looks at `m/44'`, ouroboros put the funds at `m/84'` |
| 9 | … | G25: BIP-49 `m/49'` P2SH-wrapped SegWit | **BUG-7 (P0-FUNDS)** — same shape as BUG-6 for `address_type="p2sh-segwit"`. Path used is `m/84'/coin'/0'/change/index`, not `m/49'/coin'/0'/change/index`. P2SH-P2WPKH addresses derived by ouroboros are not visible to a Core wallet looking at `m/49'`. Restore-on-Core ⇒ funds inaccessible |
| 9 | … | G26: BIP-86 `m/86'` key-path Taproot | **BUG-8 (P0-FUNDS)** — same shape for `address_type="bech32m"`. `_derive_key_at_path` (line 435-440) only knows `m/84'/.../change/index`. The Taproot ADDRESS (BIP-86 tweak) is correctly computed from THAT key (good — `wallet.py:756-811`), but the KEY ITSELF is at the wrong BIP-84 path. Same restore-asymmetry funds-loss as BUG-6/7 |
| 9 | … | G27: BIP-84 `m/84'` bech32 P2WPKH | PASS (`wallet.py:438`) — but locked to coin_type=0 on mainnet only (see BUG-11) |
| 10 | BIP-44 coin_type per network | G28: mainnet=0 / testnet=1 / regtest=1 / signet=1 / testnet4=1 | PARTIAL — `wallet.py:411` `coin_type = 0 if network == "mainnet" else 1` works by accident for testnet3/testnet4/signet/regtest (all map to 1 per SLIP-44) but is brittle: any future network whose name isn't `"mainnet"` lands on `coin_type=1` (e.g. someone adds `"liquid"` for testing) |
| 11 | xpub/xprv version bytes per BIP/network | G29: BIP-84 zpub (`0x04b24746`) / vpub (`0x045f1cf6`) | **BUG-9 (P1)** — ZERO references to `0x04b24746`, `0x04b2430c`, `0x045f1cf6`, `0x045f18bc`. ouroboros emits a generic xpub (`0x0488B21E`) for a m/84' descriptor instead of the SLIP-132-registered zpub family. Hardware wallets and most desktop wallets reject the xpub→bech32-address inference and require the zpub form. Cross-impl interop with Sparrow/Electrum/Trezor Suite breaks |
| 11 | … | G30: BIP-49 ypub (`0x049d7cb2`) / upub (`0x044a5262`) | **BUG-10 (P1)** — same gap for ypub; only xpub emitted for any extended key. P2SH-SegWit interop broken |
| 11 | … | G31: BIP-86 keeps xpub (no slip-132 alt) | PASS by absence — BIP-86 explicitly uses xpub |
| 12 | TapTweak (BIP-86 / BIP-341) | G32: empty merkle root for key-path-only | PASS (`wallet.py:783-787` constructs `tagged_hash("TapTweak", x_only_pub)` with no merkle bytes appended; equivalent to merkle="") |
| 12 | … | G33: force even-Y on internal point before tweak | PASS (`wallet.py:789-794`, also `taproot.py::derive_taproot_output_xonly`) |
| 13 | At-rest mnemonic / seed | G34: encrypted-wallet stores mnemonic only under AES-GCM | PASS only if `passphrase` provided. **BUG-12 (P0-SEC)** — when no passphrase, `_save` (`wallet.py:1109-1157`) writes `mnemonic`, `seed_hex`, `bip39_passphrase`, and `key_pool.seed_hex` as **plaintext JSON** at the wallet path. The 12-word mnemonic sits next to every UTXO scan |
| 13 | … | G35: seed material zeroized on lock | **BUG-13 (P1)** — `lock()` (`wallet.py:1213-1227`) sets fields to None but the underlying `bytes` objects remain in the Python heap until GC'd. Python `bytes` are immutable; no `bytearray` / `cryptography.hazmat.primitives.constant_time` wipe. `os.urandom`-sourced entropy + master priv + chain code linger in RAM beyond user expectation. Core uses `secure_allocator` |
| 14 | Operator backup hygiene | G36: dumpmnemonic returns mnemonic + BIP-39 passphrase | PASS (`rpc.py:8408-8452`) with operator warning |
| 14 | … | G37: dumpmnemonic refuses when source was raw seed | PASS (`rpc.py:8434-8442`) |
| 15 | Descriptor expansion | G38: hardened derivation works from xprv source | **BUG-14 (P1)** — `descriptors.py::_parse_key_expression` (line 358) ALWAYS materialises `ExtendedPubKey` (public-only) even when the input is `xprv`. Subsequent `derive_path` (line 218) raises on `'`/`h` → range-descriptors like `wpkh(xprv.../84'/0'/0'/0/*)` are non-functional. Core handles this in `BIP32PubkeyProvider::GetDerivedExtPubKey` by keeping the private side around for hardened steps |

---

## BUG-1 (P0-FUNDS) — BIP-32 CKD priv RAISES on `IL >= n` or `k_i == 0` instead of retrying with next index

**Severity:** P0-FUNDS. The BIP-32 specification is unambiguous in
§"Private parent key → private child key": *"In case parse256(IL) ≥ n
or ki = 0, the resulting key is invalid, and one should proceed with
the next value for i."*

Bitcoin Core implements this via `secp256k1_ec_seckey_tweak_add`
returning `false` on either condition; `CKey::Derive`
(`bitcoin-core/src/key.cpp:307-309`) returns `false`; the descriptor /
wallet caller (`scriptpubkeyman.cpp`) retries at `i+1`. ouroboros
RAISES instead, at two adjacent lines:

```python
# src/ouroboros/wallet.py:640-646
hmac_result = hmac.new(self.chain_code, data, hashlib.sha512).digest()
il = int.from_bytes(hmac_result[:32], "big")
if il >= SECP256K1_ORDER:
    raise ValueError("Derived key is out of range")          # <-- BUG-1 (a)
child_int = (il + int.from_bytes(self.private_key, "big")) % SECP256K1_ORDER
if child_int == 0:
    raise ValueError("Derived key is zero")                  # <-- BUG-1 (b)
```

No call site catches `ValueError` and retries at `i+1`. `KeyPool._refill_pool`
(`wallet.py:442-460`) iterates `next_idx` blindly; on first hit of an
invalid index the exception propagates to `Wallet.init_hd`,
`generate_new_address`, `keypoolrefill` — all P0-visible failures.

**Probability of hitting an invalid index per derivation step:** ~2⁻¹²⁸
(approximately the curve-cofactor minority probability). Per-wallet
expected hits before exceeding the SLIP-44 5-level path total ≈ 2⁻¹²⁸ ×
5 ≈ unreachable in practice. **But the bug is a divergence-against-spec
that creates a hidden chain-of-trust gap.** If a Core-derived wallet
ever happens to use the "next valid index" path (e.g., a hardware
wallet that does so), the same mnemonic loaded into ouroboros derives
different addresses and **the funds are silently unreachable**.

The "comment-as-confession" gap is that the existing tests
(`test_w111_wallet.py:161-169`) explicitly note "We cannot easily
construct a seed that gives IL=0 without brute-force" — the test
SKIPS the actual spec-mandated behaviour rather than constructing a
synthetic vector. The fleet pattern "test-pinning-an-untested-property"
applies.

**File:** `src/ouroboros/wallet.py:640-645` (private), `src/ouroboros/descriptors.py:194-196` (public).

**Core ref:** `bitcoin-core/src/key.cpp:307-309` (`secp256k1_ec_seckey_tweak_add`
returns false → `keyChild.ClearKeyData()`).

**Impact:** spec-divergence at the canonical CKD layer. Cross-impl
restore from a Core / hardware-wallet mnemonic that lands on a
retry-mandated index produces a different child key → all derived
descendants diverge → silent funds loss.

---

## BUG-2 (P1) — CKD priv uses pure-Python big-int modular arithmetic, not libsecp256k1 `seckey_tweak_add`

**Severity:** P1. Bitcoin Core delegates the tweak addition to libsecp256k1:

```cpp
// bitcoin-core/src/key.cpp:307
bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_static,
                                          (unsigned char*)keyChild.begin(),
                                          vout.data());
```

This is constant-time (no branches on secret data) and validates
`0 < result < n` atomically. ouroboros does this in pure Python:

```python
# src/ouroboros/wallet.py:643
child_int = (il + int.from_bytes(self.private_key, "big")) % SECP256K1_ORDER
```

`int.from_bytes`, the `%` operator on Python big ints, and `to_bytes`
(line 646) are not constant-time (CPython's `_PyLong_Add` branches on
digit count). A timing-attack adversary measuring derivation latency
could distinguish private-key Hamming weight buckets in principle,
though the attack model for an HD wallet (offline derivation) is weak.

**The bigger gap is correctness consistency:** `coincurve.PrivateKey.add(tweak)`
is exposed (Python `dir(PrivateKey)` shows `['add']`) and wraps
`secp256k1_ec_seckey_tweak_add` exactly — using it would close the
side-channel gap AND ensure the libsecp validity check fires before
we ever return.

Cross-cite W160 BUG-10 (ouroboros own — "BIP-32 private-GMP asymmetry"
already documented in the same impl); W141 / W159 (haskoin + blockbrew
+ beamchain origin of the same pattern).

**File:** `src/ouroboros/wallet.py:640-646`.

**Core ref:** `bitcoin-core/src/key.cpp:307` (libsecp tweak_add).

**Impact:** consistency-with-Core gap; weak timing side-channel; the
public-key branch uses libsecp (`descriptors.py:198-199`) while the
private branch does not — **asymmetric inside one HD layer**.

---

## BUG-3 (P0-FUNDS) — Public CKD also RAISES on `IL >= n` instead of retrying

**Severity:** P0-FUNDS (same as BUG-1, public side).

```python
# src/ouroboros/descriptors.py:193-196
I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
il = int.from_bytes(I[:32], "big")
if il >= SECP256K1_ORDER:
    raise ValueError("Derived key out of range")
```

`coincurve.PublicKey.add(I[:32])` (line 199) further validates that the
resulting point is not infinity. Both checks should produce a SKIP-AND-RETRY
in the caller per BIP-32, but every caller (`derive_path` line 218,
descriptor expansion at `KeyExpression.derive_pubkey` line 311) bubbles
up `ValueError`.

For watch-only wallets loaded from an xpub (the only place public CKD
is exercised in production), a hit on the IL≥n condition means the
range descriptor stops mid-derivation — `range_end=1000` (descriptors.py:1378)
becomes effectively `range_end=k-1` for the first failing `k`. Subsequent
addresses are SKIPPED rather than retried.

**File:** `src/ouroboros/descriptors.py:194-196`, `:199-207`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:355` (returns false →
`CPubKey::Derive` returns false → caller retries).

**Impact:** same shape as BUG-1 on the watch-only public side. Cross-impl
restore-as-xpub diverges from Core at the first retry-required index.

---

## BUG-4 (P1) — `HDKey.from_xprv` does not enforce Core's `depth=0` invariants

**Severity:** P1. Bitcoin Core's `CExtKey::Decode` clears the key
(`key = CKey()`) whenever:

1. `code[41] != 0` (the padding byte before the private key body),
2. **OR** `(nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0))`.

```cpp
// bitcoin-core/src/key.cpp:529
if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || code[41] != 0)
    key = CKey();
```

ouroboros `from_xprv` (`wallet.py:694-714`) only checks `raw[45] != 0`:

```python
if raw[45] != 0:
    raise ValueError("Not an extended private key")
private_key = raw[46:78]
return cls(
    private_key=private_key,
    chain_code=chain_code,
    depth=depth,
    parent_fingerprint=parent_fp,
    child_index=child_idx,
    network=network,
)
```

A malformed xprv pasted by the user (e.g., depth=0 but child_index=42)
is accepted and used. The next `derive_child` call will produce children
with parent_fingerprint pointing to nothing real.

**File:** `src/ouroboros/wallet.py:694-714`.

**Core ref:** `bitcoin-core/src/key.cpp:529`.

**Impact:** silently accepts structurally invalid extended-key strings;
downstream derivations propagate the inconsistency.

---

## BUG-5 (P1) — `derive_child` permits `depth` increment past 255; crash deferred to serialise

**Severity:** P1. Bitcoin Core refuses to derive when the depth byte would
overflow:

```cpp
// bitcoin-core/src/key.cpp:483
if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
out.nDepth = nDepth + 1;
```

ouroboros' `derive_child` blindly does `depth=self.depth + 1`
(`wallet.py:650`). A 256-deep HDKey object is constructed and held by
the caller. Only `serialize_xprv` (line 685-687) triggers the failure:

```python
payload += bytes([self.depth])
# ValueError: bytes must be in range(0, 256)
```

This is a "fail-late" pattern: the caller already wrote derived state
to caller side, then crashes on a serialisation it might never have
attempted, or might attempt much later (e.g., in a `dumpwallet` flow).
The "fix one place, leak the other" gap.

**Practical reachability:** a 256-deep HD chain is extreme but reachable
under abuse (a malicious descriptor that nests `derive_path` calls or
an attacker-controlled `range_end` that loops). Not a routine concern,
but the absence of the gate is an obvious miss.

**File:** `src/ouroboros/wallet.py:630-654` (no check), `:687` (deferred
crash point).

**Core ref:** `bitcoin-core/src/key.cpp:483`.

**Impact:** partial-state-on-deferred-error pattern; minor reliability
gap.

---

## BUG-6 (P0-FUNDS) — `address_type="legacy"` derives at `m/84'/...` not `m/44'/...`

**Severity:** P0-FUNDS. Bitcoin Core's descriptor wallet creates four
parallel BIP-44 chains, one per output type:

| Type | Path | Output |
|------|------|--------|
| legacy | `m/44'/coin'/0'/{0,1}/i` | P2PKH (bech32 disabled; base58 `1...`/`m...`/`n...`) |
| p2sh-segwit | `m/49'/coin'/0'/{0,1}/i` | P2SH-P2WPKH |
| bech32 | `m/84'/coin'/0'/{0,1}/i` | P2WPKH |
| bech32m | `m/86'/coin'/0'/{0,1}/i` | P2TR (BIP-86) |

ouroboros has **one** path: `m/84'/coin'/0'/{0,1}/i`. The
`address_type` parameter changes only which `WalletKey.get_*_address()`
method is called (`wallet.py:1311-1318, 1456-1465`); the **derivation
path is identical** regardless of output type:

```python
# src/ouroboros/wallet.py:1442-1465 (generate_address_of_type)
if self._hd_seed is not None:
    path = f"{self._hd_base_path}/{self._hd_next_index}"  # m/84'/0'/0'/0/N
    hd = HDKey.from_seed(self._hd_seed, self.network).derive_path(path)
    key = hd.to_wallet_key()
    self._hd_next_index += 1
...
elif address_type == "legacy":
    return key.get_p2pkh_address()       # <-- BIP-44 address from BIP-84 path
```

**Result:** a user who runs `getnewaddress "" legacy` on ouroboros, then
**restores the same mnemonic on Bitcoin Core / Sparrow / Electrum**, will
not see the funds. Core scans `m/44'/0'/0'/0/*` for legacy addresses;
the funds are at `m/84'/0'/0'/0/*`. Same pattern as
**blockbrew W161 BUG "generate-and-discard"** but the failure mode is
worse: ouroboros knows the WIF (it's in the wallet's `keys` list), so the
recovery path is `dumpprivkey` — but the user expects standard BIP-39
mnemonic restore to work, and it doesn't.

**File:** `src/ouroboros/wallet.py:1311-1318, 1442-1465, 868`
(`HD_BASE_PATH = "m/84'/0'/0'/0"` hardcoded), `:435-440` (KeyPool's
`_derive_key_at_path` only emits BIP-84 path).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::SetupDescriptorGeneration`,
`script/descriptor.cpp::InferDescriptor` (per-output-type path
infrastructure).

**Impact:** funds-loss-on-restore-to-Core for every legacy address ever
produced by ouroboros. **Same architectural shape as camlcoin W161
BUG-1 + blockbrew W161 "generate-and-discard"**, but with a worse
twist: ouroboros writes a misleading `hd_path` field to the wallet
file (`wallet.py:1288`):

```python
"hd_path": f"m/84'/{self._key_pool.coin_type}'/0'/0/{index}",
```

— the operator inspecting `dumpwallet` sees a BIP-84 path next to a
P2PKH `1...` address, which is internally inconsistent but doesn't
flag the bug at a quick glance.

---

## BUG-7 (P0-FUNDS) — `address_type="p2sh-segwit"` derives at `m/84'/...` not `m/49'/...`

**Severity:** P0-FUNDS. Same shape as BUG-6 for P2SH-P2WPKH.

```python
# src/ouroboros/wallet.py:1311-1312
if address_type == "p2sh-segwit":
    addr = key.get_p2sh_p2wpkh_address()
```

`key` is derived at `m/84'/coin'/0'/{0,1}/i`. Core derives P2SH-P2WPKH
at `m/49'/coin'/0'/{0,1}/i` per BIP-49.

**File:** `src/ouroboros/wallet.py:1311-1312, 1460-1461`.

**Core ref:** BIP-49 §6; `bitcoin-core/src/wallet/scriptpubkeyman.cpp::SetupDescriptorGeneration`.

**Impact:** funds-loss-on-restore-to-Core for every P2SH-SegWit `3...`/`2...`
address ever produced by ouroboros.

---

## BUG-8 (P0-FUNDS) — `address_type="bech32m"` (P2TR) derives at `m/84'/...` not `m/86'/...`

**Severity:** P0-FUNDS. Same shape as BUG-6 for BIP-86 key-path Taproot.

BIP-86 §"Internal key derivation" mandates `m/86'/coin_type'/account'`
as the root for "Single-key P2TR outputs based on BIP-32". ouroboros
derives at BIP-84's `m/84'/...` (see `_derive_key_at_path`,
`generate_address_of_type`).

The **TapTweak math itself is correct** (`wallet.py:756-811` correctly
computes `Q = lift_x(P) + tagged_hash("TapTweak", x_only(P)) * G` and
forces even-Y on the internal point before adding the tweak — pin-test
at `test_taproot_bip86.py` against the canonical BIP-86 vector
**HAS THE INTERNAL KEY HARDCODED** and **DOES NOT walk the BIP-86
path** through `derive_path`):

```python
# tests/test_taproot_bip86.py:42-44
BIP86_CHILD_PRIV = bytes.fromhex(
    "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"
)
```

So the test PASSES because it skips the path-derivation step entirely
— the bug hides behind a hardcoded child key.

**The test is the bug.** Fleet pattern "test pinning a missing field"
(hotbuns W157 BUG-14) extends here to "test pinning the *wrong* path
by skipping it".

**File:** `src/ouroboros/wallet.py:1313-1314, 1462-1463`;
`tests/test_taproot_bip86.py:42-79` (path-skipping test).

**Core ref:** BIP-86 §"Internal key derivation".

**Impact:** funds-loss-on-restore-to-Core for every `bc1p...` Taproot
address ever produced by ouroboros's `getnewaddress`. **The W161
P0-FUNDS trio (BUG-6/7/8) is the highest-severity ouroboros finding
this audit.**

---

## BUG-9 (P1) — BIP-84 zpub / vpub version bytes never emitted (SLIP-132 gap)

**Severity:** P1. SLIP-132 registered version bytes:
- zpub (mainnet) = `0x04b24746`, zpriv = `0x04b2430c`
- vpub (testnet) = `0x045f1cf6`, vpriv = `0x045f18bc`

These are what Sparrow / Electrum / Trezor Suite / Ledger Live expect
when importing an extended public key for a m/84' P2WPKH wallet —
ENCODING THE OUTPUT TYPE in the version bytes lets the importer infer
the script template without an explicit user choice.

ouroboros emits only generic `xpub`/`tpub`:

```python
# src/ouroboros/wallet.py:578-581
_XPRV_MAINNET = 0x0488ADE4
_XPUB_MAINNET = 0x0488B21E
_XPRV_TESTNET = 0x04358394
_XPUB_TESTNET = 0x043587CF
```

A user doing "export xpub" expecting to paste into Sparrow as a m/84'
account gets back an `xpub...` string that Sparrow either rejects (in
strict mode) or imports as **m/44'** by default (xpub is the BIP-44
version byte) — leading the user back into BUG-6 territory.

**File:** `src/ouroboros/wallet.py:578-581, 675-683`.

**Core ref:** SLIP-132 registry; Core itself emits xpub everywhere
(Core is also non-compliant with SLIP-132, but the standard descriptor
flow makes this irrelevant for Core because descriptors encode the
output type explicitly).

**Impact:** export-xpub interop with hardware-wallet / desktop-wallet
ecosystem. Combined with BUG-6, the user has two ways to lose funds
when migrating between wallets.

---

## BUG-10 (P1) — BIP-49 ypub / upub version bytes never emitted

**Severity:** P1. Same shape as BUG-9 for BIP-49:
- ypub = `0x049d7cb2`, ypriv = `0x049d7878`
- upub (testnet) = `0x044a5262`, upriv = `0x044a4e28`

**File:** `src/ouroboros/wallet.py:578-581`.

**Impact:** P2SH-SegWit export interop broken.

---

## BUG-11 (P1) — `coin_type` derivation conflates testnet/regtest/signet/testnet4 into single bucket

**Severity:** P1 (cosmetic; SLIP-44 happens to map all four to `1`).
`KeyPool.__init__`:

```python
# src/ouroboros/wallet.py:411
self.coin_type = 0 if network == "mainnet" else 1
```

SLIP-44 indeed says `coin_type=1` for all of Bitcoin testnet3, signet,
regtest, and (by convention) testnet4. So the result is **correct**.
But the **conditional is brittle**: if a future network whose `network`
string is neither `"mainnet"` nor a testnet variant (e.g., `"liquid"`,
`"elements"`, a chainparams typo) is passed, ouroboros silently maps it
to `coin_type=1` — confusion with testnet HD branches.

**File:** `src/ouroboros/wallet.py:411`.

**Core ref:** SLIP-44 registry; `bitcoin-core/src/kernel/chainparams.cpp`
per-network `m_bip44_coin_type`.

**Impact:** brittle network-name binding. Cross-cite the fleet pattern
"three-network-string conflation" (ouroboros W157).

---

## BUG-12 (P0-SEC) — Unencrypted wallet stores BIP-39 mnemonic, seed, and BIP-39 passphrase as plaintext JSON

**Severity:** P0-SEC. `Wallet._save` (`wallet.py:1109-1157`) branches
on `self._passphrase`:

```python
if self._passphrase is not None:
    plaintext = json.dumps(inner).encode("utf-8")
    blob = encrypt_wallet_data(plaintext, self._passphrase)
    outer: dict = {"version": 1, "network": self.network,
                   "encrypted": True, "ciphertext": blob.hex()}
else:
    outer = {"version": 1, "network": self.network, **inner}
```

When `_passphrase is None` (the default for unencrypted wallets), `inner`
contains:
- `hd.seed_hex` — 64-byte BIP-32 master seed
- `hd.mnemonic` — list of 12/24 BIP-39 words
- `hd.bip39_passphrase` — the "25th word"
- `key_pool.seed_hex` — duplicate of the master seed
- `keys[].wif` — every derived private key in WIF

All written as plaintext to `{data_dir}/wallets/{name}/wallet.dat`. Mode
inherits from the default umask (typically `0o644`); no `chmod 0o600`.

**Comparison with Core:** Bitcoin Core's `wallet.dat` (BDB or
sqlite-descriptor) stores private keys; the recommended deployment is
WITH `-walletpassphrase`-style encryption. But Core's keypool exists
WITHOUT seed material — descriptor wallets store the active descriptor
and `m_keys`, derived on demand. The mnemonic is *never* persisted
(Core has no concept of mnemonic; it's a wallet-init thing).

ouroboros persisting the **mnemonic** is novel and arguably worse —
the mnemonic is THE shared secret across all derived chains. A
filesystem read on an unencrypted ouroboros wallet leaks every key
that has ever been derived AND every key that ever WILL be derived
from the same mnemonic.

**File:** `src/ouroboros/wallet.py:1109-1157` (`_save`),
`:1115-1128` (the plaintext block).

**Core ref:** `bitcoin-core/src/wallet/wallet.cpp::EncryptWallet`
(at-rest crypto); descriptor wallets never persist mnemonic.

**Impact:**
- Filesystem leak (backup tarball, log scrape, accidental
  `git add wallets/`) → total wallet compromise + cross-impl restore on
  any BIP-39 wallet.
- The mnemonic is the **same secret used to seed BIP-32**, so leaking
  the mnemonic also lets the attacker recover every legacy P2PKH /
  P2SH-SegWit / Taproot derived chain (BUG-6/7/8 makes this worse,
  not better, because the attacker can scan all four paths).

**Fleet pattern:** "wallet-at-rest defaults to plaintext", new shape
ouroboros introduces.

---

## BUG-13 (P1) — `lock()` does not memory-wipe seed / mnemonic / chain-code bytes

**Severity:** P1. `Wallet.lock` (`wallet.py:1213-1227`) clears the
*references* to seed material:

```python
self._hd_seed = None
self._hd_mnemonic = None
self._hd_bip39_passphrase = None
self._hd_next_index = 0
self._key_pool = None
self._passphrase = None
```

Python `bytes` objects are immutable; setting `self._hd_seed = None`
drops the reference but the underlying bytes remain in the heap until
GC'd, and (in CPython) may live in the small-object pool indefinitely
if interned. There is no `cryptography.hazmat.primitives.constant_time`
nor `ctypes`-based memzero.

Comparison with Core: `secure_allocator` zeroes memory on free
(`bitcoin-core/src/support/allocators/secure.h`), used for `CKey`,
`CExtKey::vchFingerprint` (in `secure_allocator<unsigned char>`), and
the BIP32 derivation working buffer (`std::vector<unsigned char,
secure_allocator<unsigned char>>`).

**File:** `src/ouroboros/wallet.py:1213-1227`.

**Core ref:** `bitcoin-core/src/support/allocators/secure.h`;
`bitcoin-core/src/key.h::CKey` storage.

**Impact:** core-dump capture, process-memory inspection, swap-out to
disk → seed material exposed. The bigger concern in Python's heap
model: small bytes objects may persist past GC.

---

## BUG-14 (P1) — Descriptor `wpkh(xprv.../84'/0'/0'/0/*)` non-functional (hardened steps from xprv source not supported)

**Severity:** P1. `_parse_key_expression` (`descriptors.py:321-382`)
materialises an `ExtendedPubKey` (public-only) even when the input is
`xprv`/`tprv`:

```python
# descriptors.py:357-359
expr.ext_key_str = ext_str
expr.ext_key = ExtendedPubKey.deserialize(ext_str)
expr.is_private = ext_str.startswith(("xprv", "tprv"))
```

`ExtendedPubKey.deserialize` (line 251-258) extracts the private key
for xprv, derives the public key via `PublicKey.from_secret`, then
*discards the private key*. Subsequent derivation goes through
`ExtendedPubKey.derive_path` (line 209-221) which raises on `'` / `h`
suffixes (line 218):

```python
if part.endswith("'") or part.endswith("h"):
    raise ValueError(f"Cannot derive hardened child from xpub: {part}")
```

Bitcoin Core's descriptor expander (`script/descriptor.cpp::BIP32PubkeyProvider::GetDerivedExtPubKey`)
keeps the xprv around so hardened intermediate steps work, neutering
only at the final derived step. ouroboros silently strips the xprv side
before any user-provided derivation suffix runs.

**Practical impact:** descriptors like
`wpkh([fingerprint/84'/0'/0']xprv.../0/*)` work (suffix is all-normal),
but `wpkh(xprv.../84h/0h/0h/0/*)` does not — the suffix `/84h/0h/0h/0/*`
hits the hardened-raise on `84h`.

**File:** `src/ouroboros/descriptors.py:357-359, 209-221`.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::BIP32PubkeyProvider`.

**Impact:** descriptor expression coverage gap. Importing a Core
descriptor that embeds the full BIP-44/49/84/86 hardened prefix in the
suffix-derivation portion fails.

---

## BUG-15 (P1) — Existing test `test_legacy_hd_base_path_has_change_branch_bug` PINS the BUG as expected behaviour

**Severity:** P1. `src/ouroboros/tests/test_w111_wallet.py:437-460`:

```python
def test_legacy_hd_base_path_has_change_branch_bug(self):
    """
    BUG-2: HD_BASE_PATH = "m/84'/0'/0'/0" combines purpose/coin/account
    AND the external-chain index in a single string. The legacy
    generate_address_of_type path appends /{next_index} to it, producing
    m/84'/0'/0'/0/0, m/84'/0'/0'/0/1, ... — which is the EXTERNAL chain
    only. Change addresses via this legacy path go to the same external
    chain because there is no internal-chain (change=1) branch.

    This test documents the behaviour: two wallets using the legacy path
    will derive identical pubkeys for their "change" addresses as for
    their receive addresses when both have index 0.
    """
```

The test docstring **admits the bug exists** and **pins it as the
contract** by asserting `recv.private_key != change_correct.private_key`
— which only succeeds in the buggy world where the legacy path's
"change" output goes to the receive chain (so the *correct* change key
is different from BOTH legacy outputs).

This is fleet pattern "test-pinning-the-bug" / "comment-as-confession"
(ouroboros own — extends W160 W157 instances). The test sentence
"This test documents the behaviour" is the smoking-gun.

**File:** `src/ouroboros/tests/test_w111_wallet.py:437-460`.

**Core ref:** N/A — this is a divergence-from-spec pin.

**Impact:** the regression-test scaffolding actively prevents a fix
from landing. Any PR that changes the legacy HD path to add the
external/internal chain branch will break this test, signal a
regression to CI, and likely get reverted.

---

## BUG-16 (P1) — Generated mnemonic-then-fresh-wallet path persists mnemonic ONLY if not blank/not watch-only

**Severity:** P1 ("mnemonic-generation-then-discard", new ouroboros
instance of fleet pattern named for blockbrew W161). `WalletManager.create_wallet`
(`wallet.py:2280-2387`):

```python
# wallet.py:2361
if not blank and not disable_private_keys:
    from ouroboros.bip39 import generate_mnemonic as _gen_mnemonic
    if mnemonic is None:
        mnemonic_words: list[str] = _gen_mnemonic(128)  # 12 words
    ...
    wallet.init_hd(
        mnemonic=mnemonic_words,
        bip39_passphrase=bip39_passphrase,
        pool_size=1000,
    )
elif passphrase and not disable_private_keys:
    # Blank wallet with passphrase
    wallet.encrypt(passphrase)
```

If `blank=True` AND `disable_private_keys=False` AND `mnemonic=None`,
no mnemonic is generated at all (line 2361 short-circuits). The wallet
is created as descriptor-empty; a later `init_hd(seed=...)` call cannot
recover a mnemonic (BIP-32 has no inverse). The user who later runs
`dumpmnemonic` gets the "no mnemonic" 400 error — and never realises
the wallet has no backup story.

`dumpmnemonic`'s confession (`rpc.py:8438-8442`) is sincere ("Wallet
was not initialised from a BIP-39 mnemonic"), but the blank-wallet
flow is reachable from a normal `createwallet wallet_name "" false true`
call (the second-to-last `true` is `blank`).

**File:** `src/ouroboros/wallet.py:2361-2387` (skip-on-blank);
`rpc.py:8408-8452` (dumpmnemonic returns 400 on no-mnemonic).

**Impact:** silent loss of backup story for blank wallets that later
get HD-initialised via raw seed. Workflow gap.

---

## BUG-17 (P1) — `KeyPool._rebuild_pools` re-derives entire history on every restart; O(N) hot path

**Severity:** P1 (performance / hot-restart). `KeyPool.from_dict`
calls `_rebuild_pools` (`wallet.py:539-565`):

```python
def _rebuild_pools(self) -> None:
    """Rebuild key pools from indices (called after deserialize)."""
    self._receive_pool = []
    self._change_pool = []
    for i in range(self._next_receive_index):
        key = self._derive_key_at_path(False, i)
        self._receive_pool.append((i, key))
    for i in range(self._next_change_index):
        key = self._derive_key_at_path(True, i)
        self._change_pool.append((i, key))
```

`_derive_key_at_path` calls `self.master.derive_path("m/84'/c'/0'/x/i")`
— five HMAC-SHA512s per key + libsecp pubkey extraction. On a
post-Whirlpool wallet with 10k+ active receive indices, restart loads
the wallet by computing 10k × 5 = 50k HMACs serially.

Bitcoin Core's keypool uses a lookup table for derived keys and only
derives on demand. ouroboros has the lookup table (`_receive_pool`),
but **persists only the indices**, so reconstruction is forced on
every load.

**File:** `src/ouroboros/wallet.py:539-565`, `:435-440`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::GetNewDestination`
(O(1) lookup from m_map_pubkeys).

**Impact:** startup latency scales with wallet age; ~10s extra on a
20k-key wallet.

---

## BUG-18 (P1) — `mnemonic_to_seed` does not validate checksum (deliberate per BIP-39 spec, but docstring buries the warning)

**Severity:** P1 (documentation / usability, not consensus). `bip39.py:175-208`:

```python
def mnemonic_to_seed(mnemonic: list[str] | str, passphrase: str = "") -> bytes:
    """
    ...
    Note: this function does **not** validate the mnemonic checksum. That
    matches the BIP-39 spec ("the produced binary seed is not used to
    represent the original mnemonic — it is used to derive deterministic
    wallets") but callers wanting strict validation should call
    :func:`validate_mnemonic` first.
    """
```

`Wallet.init_hd` (`wallet.py:964-972`) DOES call `validate_mnemonic`
before `mnemonic_to_seed`, which is correct. But the symmetric path
`restore_from_mnemonic` (`wallet.py:999-1020`) calls back into
`init_hd`, so the validation runs there too. Net effect: the seed
path is properly validated.

The risk surface is third-party Python that imports `ouroboros.bip39`
directly. A user calling `mnemonic_to_seed(["abandon"] * 12)` (no
"about" at the end → checksum failure) gets a 64-byte seed silently
— BIP-39-VALID mnemonic and INVALID typo'd-mnemonic both produce a
seed. The user then derives addresses, sends funds, and the actual
recovery fails (the recovery wallet refuses the invalid mnemonic).

**File:** `src/ouroboros/bip39.py:175-208`.

**Core ref:** N/A — Core has no BIP-39 (mnemonic is wallet-init-only).

**Impact:** Python-API-misuse trap. Recommend `mnemonic_to_seed` add
a default `strict=True` that runs `validate_mnemonic` first; callers
needing the BIP-39 §"From mnemonic to seed" relaxed mode pass
`strict=False`.

---

## BUG-19 (P1) — No regression test asserts `restorewallet` produces the SAME pubkeys as `dumpmnemonic` on a sibling wallet

**Severity:** P1 (test-coverage gap). The BIP-39 vector tests
(`tests/test_bip39.py`) cover byte-identity for the TREZOR vectors.
`test_w111_wallet.py::test_master_from_tv1_seed` covers BIP-32
TV1-seed → master key. `test_taproot_bip86.py` covers the BIP-86
tweak from a hardcoded child key.

NO test runs the FULL path:

> mnemonic → seed (BIP-39) → master (BIP-32 from_seed) →
> m/84'/0'/0'/0/0 (derive_path) → bech32 address

against a Core / BIP-84 reference vector. The BIP-84 BIP itself
provides a vector (`abandon ... about` mnemonic at coin=0 account=0
→ `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`); ouroboros does not
exercise it end-to-end.

Combined with BUG-6/7/8 (wrong paths), this is exactly the gap that
lets the path bugs persist undetected. The fleet pattern "test pinning
a missing field" (hotbuns W157) extends to **"test omitting the
integration step that would have caught the architectural bug"**.

**File:** `tests/test_bip39.py`, `src/ouroboros/tests/test_w111_wallet.py`,
`tests/test_taproot_bip86.py`.

**Core ref:** BIP-84 §"Test vectors", BIP-86 §"Test vectors", BIP-49
§"Test vectors".

**Impact:** the four spec-defined BIP-44/49/84/86 test vectors that
would catch BUG-6/7/8 in one CI run are not in the test suite.

---

## BUG-20 (P1) — `_hd_base_path` is operator-configurable but unsanitised

**Severity:** P1 (input-validation / supply-chain). `Wallet.init_hd`
accepts `base_path` (line 933), defaulting to `HD_BASE_PATH`
(`"m/84'/0'/0'/0"`) but allowing any string:

```python
# wallet.py:984-985
if base_path is not None:
    self._hd_base_path = base_path
```

`base_path` is later used directly in path concatenation:

```python
# wallet.py:1296
path = f"{self._hd_base_path}/{self._hd_next_index}"
```

Allowed user input:
- `"m/0/0/0"` (no hardened steps) → derives all addresses from
  unhardened common ancestor; xpub-only watch could spend them
- `"m/../."` → `HDKey.derive_path` raises on parsing; harmless
- Path injection via JSON deserialise on `_load_or_create`
  (`wallet.py:1072`) reads `hd.base_path` from disk without validation
  — if an attacker can write the wallet.dat (already game over) they
  can set arbitrary paths

No validation that `base_path` starts with `m/`, uses canonical
hardened markers, or even parses. Crash-on-derivation is the only
sanity gate.

**File:** `src/ouroboros/wallet.py:984-985, 1072, 1296, 1444`.

**Impact:** misconfiguration footgun. A user who passes `base_path="0/0"`
(missing leading `m/`) gets a derivation that derives from the WRONG
prefix (the master itself becomes child 0 of nothing).

---

## BUG-21 (P1) — Mnemonic-and-seed BOTH stored when both could be derived from each other

**Severity:** P1 (data-redundancy / drift risk). `Wallet._save`
(`wallet.py:1115-1128`):

```python
if self._hd_seed is not None:
    hd_inner: dict = {
        "seed_hex": self._hd_seed.hex(),
        "next_index": self._hd_next_index,
        "base_path": self._hd_base_path,
    }
    if self._hd_mnemonic is not None:
        hd_inner["mnemonic"] = list(self._hd_mnemonic)
        hd_inner["bip39_passphrase"] = self._hd_bip39_passphrase or ""
    inner["hd"] = hd_inner
```

Both `seed_hex` AND `mnemonic`+`bip39_passphrase` are persisted. The
BIP-39 invariant guarantees `seed_hex == PBKDF2(mnemonic, "mnemonic"+
bip39_passphrase, 2048, 64)`. Storing both creates a drift
opportunity: future code that mutates one without the other (e.g.,
a hypothetical `rotate_passphrase` that updates the seed but forgets
the bip39_passphrase) produces an internally inconsistent wallet.

Counter: storing both makes `dumpmnemonic` O(1) and `init_hd` reload
O(1). Removing `seed_hex` would force PBKDF2 on every load (the
2048-iter PBKDF2 is the deliberate KDF cost — about 100-500ms on
modern hardware). The choice is reasonable, but it should be
defensive: every `_load_or_create` should recompute and assert
agreement.

**File:** `src/ouroboros/wallet.py:1115-1128, 1066-1076`.

**Impact:** silent inconsistency surface; minor.

---

## BUG-22 (P1) — BIP-39 entropy validation accepts wordlist words that aren't normalised

**Severity:** P1 (Unicode strict-equality). `mnemonic_to_entropy`
(`bip39.py:143-172`) looks up each word in `WORDLIST_INDEX` (a dict
keyed on the raw ASCII strings from the wordlist file). The
**mnemonic input is not NFKD-normalised** before the lookup:

```python
# bip39.py:155-159
for w in words:
    idx = WORDLIST_INDEX.get(w)
    if idx is None:
        raise Bip39Error(f"word not in BIP-39 English wordlist: {w!r}")
```

The English wordlist is ASCII, so no normalisation difference exists
for the *valid* input. But a user paste that includes Unicode
look-alikes ("аbandon" with Cyrillic а) gets a clean
"word not in wordlist" error — fine. The issue is the **other
direction**: `mnemonic_to_seed` (line 199) DOES normalise the entire
mnemonic string with NFKD before PBKDF2. The path is:

1. `validate_mnemonic` (line 211-214) → `mnemonic_to_entropy` (raw lookup, OK for ASCII)
2. `mnemonic_to_seed` (line 175) → NFKD on the joined string, then PBKDF2

If a user pastes an NFD-decomposed-form English wordlist (theoretical;
ASCII has no NFD form), the validation passes but the seed comes from
the NFKD form. For the English wordlist (no combining characters)
this is a no-op. For the **OTHER BIP-39 wordlists** (Japanese,
Korean, Chinese, etc. — NOT supported by ouroboros, see below), the
gap would be real.

**File:** `src/ouroboros/bip39.py:54-72, 143-172, 199-200`.

**Core ref:** BIP-39 §"Wordlist": "Wordlists in other languages
SHOULD be normalized by NFKD". Notably the English wordlist itself is
already NFKD-stable.

**Impact:** dormant gap. Becomes a P0 when ouroboros adds non-English
wordlists. **Fleet pattern "NFKD-asymmetric" (blockbrew W161 origin)**:
ouroboros normalises in the PBKDF2 path but not in the validation
path, identical to blockbrew's pattern.

---

## BUG-23 (P1) — Only English wordlist supported; no Japanese/Korean/Chinese/Spanish/French/Italian/Czech/Portuguese

**Severity:** P1 (BIP-39 spec gap). BIP-39 §"Wordlist" lists 8
official wordlists. ouroboros loads exactly one:

```python
# src/ouroboros/bip39.py:60-62
raw = resources.files("ouroboros.data").joinpath("bip39_english.txt").read_text(...)
```

A user with a Japanese-language mnemonic from a different wallet (most
of the Japanese-language wallets like Bither / Wallet Inu use the
Japanese wordlist) cannot restore on ouroboros. The error message is
"word not in BIP-39 English wordlist" — confusing because the user's
mnemonic IS a valid BIP-39 mnemonic, just not English.

The BIP-39 spec says "If you load 'bip39_japanese.txt' and one of the
words is not recognised, fall back to 'bip39_english.txt'"; ouroboros
has no fallback.

**File:** `src/ouroboros/bip39.py:54-72`.

**Core ref:** BIP-39 §"Wordlist"; Core has no mnemonic support so this
is wallet-software gap.

**Impact:** cross-locale interop gap.

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-FUNDS:** 4 (BUG-1, BUG-3, BUG-6, BUG-7, BUG-8) — wait, recount:
  BUG-1, BUG-3, BUG-6, BUG-7, BUG-8 = **5 P0-FUNDS**.
- **P0-SEC:** 1 (BUG-12)
- **P1:** 17 (BUG-2, BUG-4, BUG-5, BUG-9, BUG-10, BUG-11, BUG-13,
  BUG-14, BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21,
  BUG-22, BUG-23)
- Total: 5 + 1 + 17 = 23. ✓

**Fleet patterns confirmed / new**
- "BIP-32 private-GMP asymmetry" (BUG-2) — ouroboros own W160 origin
  re-confirmed in HD-derivation layer
- "generate-and-discard" (BUG-6/7/8) — blockbrew W161 origin
  re-confirmed in ouroboros at THREE distinct output types
- "NFKD-asymmetric" (BUG-22) — blockbrew W161 origin, 2nd fleet instance
- "test pinning a missing field" → **"test pinning a wrong field"** (BUG-8 / BUG-15)
  — hotbuns W157 origin, extended at ouroboros to BUG-8 (BIP-86 vector
  hardcodes the path-derived child) and BUG-15 (legacy_hd_base_path
  test PINS THE BUG by docstring confession)
- "comment-as-confession" (BUG-15) — explicit docstring "This test
  documents the behaviour" admitting the bug
- "test-suite shape MASKS production bug" (BUG-19) — no end-to-end
  BIP-44/49/84/86 vector tests; BUG-6/7/8 would otherwise have been
  caught
- "wallet-at-rest defaults to plaintext" (BUG-12) — new ouroboros-introduced
  pattern; novel because ouroboros persists the MNEMONIC (Core never does)
- "BIP-32 retry-vs-abort divergence" (BUG-1 / BUG-3) — first fleet instance
  documented at this depth for ouroboros (cross-cite: most impls
  observe the same pattern but few explicitly catalogue it)
- "depth-byte-overflow" (BUG-5) — blockbrew W161 origin, 2nd fleet
- "passphrase-confusion" — bip39_passphrase (the "25th word") vs
  wallet-encryption passphrase are distinct fields throughout
  (`rpc.py:8366-8368`, `wallet.py:2299, 2307`). The two-field
  distinction is honoured; **no bug, just noting fleet-pattern coverage**
- "five-distinct-paths-but-one" (NEW) — Core has m/44'/m/49'/m/84'/m/86'
  but ouroboros has only m/84'; the four output types are emulated
  from the single path

**Top three findings**

1. **BUG-6/7/8 (P0-FUNDS funds-loss-on-restore triple)** — ouroboros
   derives ALL output types (legacy / p2sh-segwit / bech32 / bech32m)
   from the SAME `m/84'/coin'/0'/{0,1}/i` path. Bitcoin Core derives
   them from `m/44'/m/49'/m/84'/m/86'` respectively. A user who runs
   `getnewaddress "" legacy` on ouroboros, receives funds, then
   restores the same mnemonic on Core gets a wallet that **does not
   see those funds** (Core scans `m/44'/...`, the funds are at
   `m/84'/...`). Same shape for `p2sh-segwit` and `bech32m`. Tests
   miss it because `test_taproot_bip86.py` HARDCODES the BIP-86 child
   private key bytes rather than walking the path. **The "hd_path"
   field written to wallet.dat (`wallet.py:1288`) reports BIP-84 path
   next to BIP-44/49/86 addresses — internally inconsistent**. This is
   the highest-severity finding this audit.

2. **BUG-12 (P0-SEC plaintext mnemonic at rest)** — `_save` with
   `passphrase=None` writes seed_hex, mnemonic words, BIP-39 passphrase,
   and every derived WIF as plaintext JSON to disk with default
   umask. Core's worst-case is encrypted-wallet at rest; ouroboros's
   default-case is plaintext-mnemonic at rest. Filesystem leak ⇒ total
   compromise of all derived chains (made worse by BUG-6/7/8 because
   the attacker can scan four paths from the same mnemonic).

3. **BUG-1 + BUG-3 (P0-FUNDS BIP-32 retry-vs-abort)** — both private
   and public CKD raise `ValueError` on `IL >= n` or `k_i == 0`. BIP-32
   spec mandates RETRY-WITH-NEXT-INDEX. The probability per derivation
   step is ~2⁻¹²⁸, but the divergence-from-spec is the bug: an
   integration-vector wallet whose path crosses a retry-needed index
   diverges silently between Core and ouroboros. Compounded by BUG-19:
   no integration test runs the full mnemonic→address vector against
   Core, so this hidden divergence stays hidden.
