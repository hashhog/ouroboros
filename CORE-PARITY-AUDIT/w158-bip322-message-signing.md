# W158 — BIP-322 message signing (Legacy + Simple + Full virtual-tx modes) (ouroboros)

**Wave:** W158 — `MessageSign`, `MessageVerify`, `MessageHash`,
`MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (CompactSize-prefixed
via HashWriter `<<`), `SignCompact` / `RecoverCompact` (65-byte
`[header][r 32][s 32]` with header = `27 + recid + (fCompressed?4:0)`),
`signmessage` (wallet), `signmessagewithprivkey` (util), `verifymessage`
(util), `RegisterSignMessageRPCCommands`, `EnsureWalletIsUnlocked`,
`DecodeSecret` (network-scoped WIF parse),
`SigningResult::{OK,PRIVATE_KEY_NOT_AVAILABLE,SIGNING_FAILED}`,
`MessageVerificationResult::{ERR_INVALID_ADDRESS, ERR_ADDRESS_NO_KEY,
ERR_MALFORMED_SIGNATURE, ERR_PUBKEY_NOT_RECOVERED, ERR_NOT_SIGNED, OK}`,
BIP-322 modes (Legacy / Simple / Full): virtual-tx `to_spend` (1-input
null-prevout sequence=0, 1-output value=0 with scriptSig `OP_0
PUSH32 SHA256(tag || tag || msg)` where tag = `"BIP0322-signed-message"`)
+ virtual-tx `to_sign` (1-input prevOut=to_spend:0 sequence=0,
1-output value=0 OP_RETURN, witness/scriptSig signs sighash of to_sign),
BIP-143 sighash for segwit witness scripts, BIP-341 sighash for taproot
key-spend / script-path, NUMS-point fallback
(`H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`)
when there is no internal-key knowledge for a P2TR address.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp:24` — `MESSAGE_MAGIC =
  "Bitcoin Signed Message:\n"` (24 bytes; serialized via `HashWriter
  << MESSAGE_MAGIC` which emits `CompactSize(24) || bytes` — i.e.
  `0x18` length prefix + 24 bytes).
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash`:
  `HashWriter{} << MESSAGE_MAGIC << message` → `SHA256d` of the
  serialized stream.
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify`:
  1. `DecodeDestination(address)` → `ERR_INVALID_ADDRESS` if invalid.
  2. `std::get_if<PKHash>(&destination)` → `ERR_ADDRESS_NO_KEY` if not
     P2PKH (legacy only).
  3. `DecodeBase64(signature)` → `ERR_MALFORMED_SIGNATURE` on parse
     failure.
  4. `pubkey.RecoverCompact(MessageHash(message), *signature_bytes)`
     → `ERR_PUBKEY_NOT_RECOVERED` on failure.
  5. `PKHash(pubkey) == *std::get_if<PKHash>(&destination)` →
     `ERR_NOT_SIGNED` on mismatch.
  Critical: address parsed BEFORE signature.
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign`:
  `privkey.SignCompact(MessageHash(message), signature_bytes)` then
  `EncodeBase64`.
- `bitcoin-core/src/pubkey.cpp:300-318` — `CPubKey::RecoverCompact`:
  requires `vchSig.size() == COMPACT_SIGNATURE_SIZE` (65); decodes
  recid via `(vchSig[0] - 27) & 3` and compressed-flag via
  `((vchSig[0] - 27) & 4) != 0`. Core does **NOT** reject header bytes
  >34 — it MASKS via `& 3` / `& 4`.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: post-sign
  re-verification (`RecoverCompact` round-trip vs source pubkey) as a
  hardware-bitflip belt-and-suspenders gate.
- `bitcoin-core/src/key_io.cpp::DecodeSecret` — WIF decode is
  **network-scoped**: `Params().Base58Prefix(SECRET_KEY)` returns
  `0x80` on mainnet, `0xEF` on testnet/regtest/signet.
  Validates 33-byte form requires `data.back() == 0x01`;
  `CKey::Set` validates scalar ∈ `[1, n-1]`.
- `bitcoin-core/src/rpc/signmessage.cpp:17-60` — `verifymessage`
  (util) error map: `ERR_INVALID_ADDRESS` → `RPC_INVALID_ADDRESS_OR_KEY`
  (-5); `ERR_ADDRESS_NO_KEY` → `RPC_TYPE_ERROR` (-3);
  `ERR_MALFORMED_SIGNATURE` → `RPC_TYPE_ERROR` (-3); the
  recovery-fail / not-signed cases return **bool false** (NOT throw).
- `bitcoin-core/src/rpc/signmessage.cpp:62-101` — `signmessagewithprivkey`
  (util): both "Invalid private key" and "Sign failed" map to
  `RPC_INVALID_ADDRESS_OR_KEY` (-5).
- `bitcoin-core/src/rpc/signmessage.cpp:103-112` —
  `RegisterSignMessageRPCCommands`: BOTH `verifymessage` AND
  `signmessagewithprivkey` registered under the **`"util"`** category
  (NOT `"wallet"`).
- `bitcoin-core/src/wallet/rpc/signmessage.cpp:13-71` — wallet-side
  `signmessage`:
  - `GetWalletForJSONRPCRequest` returns `VNULL` if no wallet loaded
    (the caller is expected to detect VNULL and emit `RPC_WALLET_NOT_FOUND`).
  - `LOCK(pwallet->cs_wallet)` then `EnsureWalletIsUnlocked(*pwallet)`
    (throws `RPC_WALLET_UNLOCK_NEEDED` -13 if encrypted+locked).
  - `DecodeDestination` then `std::get_if<PKHash>(&dest)` →
    `RPC_INVALID_ADDRESS_OR_KEY` (-5) and `RPC_TYPE_ERROR` (-3)
    respectively.
  - `pwallet->SignMessage(...)` returns `SIGNING_FAILED` →
    `RPC_INVALID_ADDRESS_OR_KEY`; `PRIVATE_KEY_NOT_AVAILABLE` →
    `RPC_WALLET_ERROR` (-4).
- BIP-322 — Generic Signed Message Format:
  - **Tag** `"BIP0322-signed-message"`; BIP-340 tagged hash =
    `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
  - **`to_spend` virtual tx**: nVersion=0, nLockTime=0, 1 input
    `{prev_txid=0x00..00, prev_vout=0xFFFFFFFF, sequence=0, scriptSig=
    OP_0 PUSH32 <tagged_hash(msg)>}`, 1 output
    `{value=0, scriptPubKey=<address_spk>}`.
  - **`to_sign` virtual tx**: nVersion=0, nLockTime=0, 1 input
    `{prev_txid=to_spend.txid, prev_vout=0, sequence=0,
    scriptSig/witness from signer}`, 1 output
    `{value=0, scriptPubKey=OP_RETURN}`.
  - **Legacy** mode = today's `MessageSign` / `MessageVerify`.
  - **Simple** mode = serialize ONLY `to_sign.witness`. Base64-encode.
  - **Full** mode = serialize full `to_sign` tx (witness format).
  - **NUMS-point fallback** for Taproot key-spend when no key-path
    knowledge available: `0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`.

**Files audited**
- `src/ouroboros/rpc.py` — `_MESSAGE_MAGIC` constant (line 687),
  `_message_hash` (line 690-699), `_encode_varint` (line 535-543),
  `_dsha256` (line 531-532), `rpc_signmessage` (line 8071-8136 —
  wallet-side), `rpc_signmessagewithprivkey` (line 8138-8200 — util),
  `rpc_verifymessage` (line 8202-8269 — util),
  `_get_wallet_for_rpc` (line 965-1014), HTTPException→JSON-RPC
  conversion (line 1061-1066, code -32603), `rpc_walletpassphrase`
  (line 3810-3840 — uses JSON-RPC code -14/-15/-18 directly via
  `JSONRPCResponse`), `rpc_keypoolrefill` (line 3940-3960 — checks
  `wallet.is_locked`), `rpc_getrawchangeaddress` (line 3962-3983 —
  checks `wallet.is_locked`), `rpc_signrawtransactionwithwallet`
  (line 11835-11864 — checks `wallet.is_locked`).
- `src/ouroboros/wallet.py` — `WalletKey` struct (line 717-850),
  `WalletKey.from_wif` (line 838-844 — **no network gate**),
  `WalletKey.sign` (line 848-850 — DER, not used by signmessage),
  `Wallet.encrypt` (line 1171-1178), `Wallet.unlock` (line 1180-1211),
  `Wallet.lock` (line 1213-1227 — empties `keys` on lock),
  `Wallet.is_locked` (line 1166-1169), `_get_wallet_key`
  (line 1255-1256), `encrypt_wallet_data` / `decrypt_wallet_data`
  (line 76-104 — scrypt + AES-256-GCM, salt||nonce||ct on disk).
- `src/ouroboros/address.py` — `_decode_base58check` (line 37-44 —
  pure parse; no network gate).
- `src/ouroboros/validation.py` — `_build_signet_to_spend` /
  `_build_signet_to_sign` (line 1771-1824, BIP-325 signet challenge
  virtual-tx — structurally close to BIP-322 to_spend/to_sign but
  **not reused** for message-signing).
- `tests/test_rpc_signmessage.py` — test file pinning current
  behaviour, including the divergent "verify rejects segwit address"
  (line 194-202) and "P2WPKH→P2PKH cross-address sign" (line 146-157)
  shapes that codify the Core-divergence as expected.
- `ferrous-utils/common/src/crypto/secp.rs` — confirmed: no
  `signmessage` / `verifymessage` / `MessageVerify` / `MessageHash`
  primitives exposed (`verify_ecdsa_compact` / `verify_ecdsa_der` /
  `verify_schnorr` / `batch_verify_*` only). The signed-message
  surface lives **entirely** in Python.

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `MessageHash` parity | G1: magic prefix bytes = `"Bitcoin Signed Message:\n"` (24 bytes) | PASS (`rpc.py:687`) |
| 1 | … | G2: length-prefix is a CompactSize (matches `HashWriter << string`) | PASS (`rpc.py:696` — `_encode_varint(len(magic_bytes))`) |
| 1 | … | G3: message length is CompactSize (1/3/5/9 bytes) | PASS (`rpc.py:697`) — but **BUG-15 cross-cite** the test harness `test_rpc_signmessage.py:119` hard-codes a 1-byte length, pinning the bug to short-msg-only verification |
| 1 | … | G4: final hash is `sha256d` of the assembled buffer | PASS (`rpc.py:699`) |
| 1 | … | G5: UTF-8 byte-identical to Core's `std::string` (8-bit clean) | PASS (`rpc.py:693-694` use `.encode("utf-8")`); Core's `std::string` is also raw 8-bit |
| 2 | `signmessage` (wallet) parity | G6: `EnsureWalletIsUnlocked` precheck before reading key | **BUG-1 (P0-SEC)** — `rpc_signmessage` (`rpc.py:8071-8136`) NEVER checks `wallet.is_locked`. The 4 other wallet-key-using RPCs in the same file DO (`rpc.py:3439, 3952, 3977, 4170, 11863`). Locked-wallet `signmessage` returns "No wallet loaded" (because `wallet.keys = []` on lock) instead of Core's `RPC_WALLET_UNLOCK_NEEDED` (-13) with `"Error: Please enter the wallet passphrase with walletpassphrase first."` |
| 2 | … | G7: error-code parity with Core (-13 for locked) | **BUG-1 cross-cite** — even if the lock check existed, ouroboros's `HTTPException(status_code=500)` is converted by `_handle_rpc` to JSON-RPC code -32603 (Internal error), NOT Core's -13 (`RPC_WALLET_UNLOCK_NEEDED`). Other wallet handlers (`rpc_walletpassphrase` line 3810) emit -14/-15/-18 directly via `JSONRPCResponse` — `signmessage` does not |
| 2 | … | G8: P2PKH-only address acceptance | **BUG-2 (P0-CDIV)** — `rpc_signmessage` (`rpc.py:8104-8108`) accepts P2WPKH AND P2SH-P2WPKH addresses in addition to P2PKH. Inline comment `rpc.py:8097-8100` is a comment-as-confession: `"Core's signmessage only accepts P2PKH (legacy) addresses; we additionally accept P2WPKH because that's what ouroboros wallets produce by default — falls back to the P2PKH the same key would derive when signing."` The handler then emits a 65-byte compact-recoverable sig that legacy-BIP-137 `verifymessage` will only validate against the P2PKH form, so a Sparrow/Trezor client that calls `signmessage <P2WPKH-addr> <msg>` gets back a sig that doesn't verify with the address it requested. The output is functionally a Legacy-BIP-137 sig over the P2PKH form of the same key — silently "downgrading" the requested address type without informing the caller |
| 2 | … | G9: hardcodes compressed=true flag in header | **BUG-3 (P1)** — `rpc.py:8134` `header = bytes([27 + recid + 4])  # compressed pubkey`. Comment admits the hardcode. The parallel `rpc_signmessagewithprivkey` (line 8198) correctly threads `compressed` from the WIF — **two parallel implementations of the same primitive, one with the bug and one without**. **Two-pipeline guard 18th distinct ouroboros instance** (intra-file). On a wallet that ever loaded an uncompressed-pubkey legacy key (via `from_wif` accepting 32-byte payload without compressed-flag, `wallet.py:842`), the encoded signature would carry a header in the compressed range; `verifymessage` then recovers a compressed pubkey whose hash160 ≠ the requested address |
| 2 | … | G10: post-sign re-verification (Core key.cpp:263-269 corruption guard) | **BUG-4 (P1)** — `rpc_signmessage` does NOT recover the pubkey from the freshly signed sig and assert equality with the signing pubkey. Core's `CKey::SignCompact` does this as a hardware-bitflip / DRAM-error gate. Same gap in `rpc_signmessagewithprivkey` (`rpc.py:8186-8189`) |
| 3 | `signmessagewithprivkey` (util) parity | G11: WIF version-byte network-scoped | **BUG-5 (P0-CDIV)** — `rpc_signmessagewithprivkey` (`rpc.py:8164-8179`) strips the WIF version byte at line 8171 with **zero validation** against `self.node.network`. A mainnet WIF (`0x80` version) on a regtest/testnet node decodes successfully and signs. Core's `DecodeSecret` consults `Params().Base58Prefix(SECRET_KEY)` and rejects cross-network WIFs. Same shape as W158 clearbit BUG-6 / rustoshi BUG-1 — **fleet-wide network-air-gap pattern**. The companion handler `rpc_signmessage` indirectly depends on `WalletKey.from_wif` (`wallet.py:838-844`) which is **also** network-agnostic (strips version byte without check) |
| 3 | … | G12: WIF scalar validated in `[1, n-1]` | **BUG-6 (P1)** — `_PrivateKey(secret)` (line 8186) will raise if the scalar is invalid, but the resulting exception is caught at line 8188 and re-raised as `HTTPException(500, "Sign failed: {e}")` — Core's "Invalid private key" path (-5 `RPC_INVALID_ADDRESS_OR_KEY`) is reached only on base58check / length failure (line 8167, 8168, 8179), never on scalar-out-of-range. Operator UX divergence; same shape as clearbit BUG-7 |
| 3 | … | G13: error code -5 (`RPC_INVALID_ADDRESS_OR_KEY`) for both "Invalid private key" and "Sign failed" | **BUG-7 (P1)** — `rpc.py:8168` HTTP 400 → JSON-RPC -32603; `rpc.py:8189` HTTP 500 → JSON-RPC -32603. Core uses -5 for both. Fleet RPC-error-code parity gap |
| 3 | … | G14: rejects hex-only privkey (Core accepts only WIF) | PASS — `rpc.py:8166` calls `base58.b58decode_check` which rejects raw hex. Stricter than rustoshi (which accepts both); matches Core |
| 4 | `verifymessage` parity | G15: parse-order address FIRST then signature | PASS (`rpc.py:8226-8237` decodes address; then `:8240-8249` decodes signature). Matches Core's order |
| 4 | … | G16: bad base64 → `RPC_TYPE_ERROR` (-3) "Malformed base64 encoding" | **BUG-8 (P1)** — `rpc.py:8243-8245` HTTP 400 → JSON-RPC -32603; Core uses -3. Message text matches |
| 4 | … | G17: P2PKH-ONLY (legacy address) | PASS (`rpc.py:8232` rejects version != 0x00,0x6f) |
| 4 | … | G18: non-P2PKH → `RPC_TYPE_ERROR` (-3) "Address does not refer to key" | **BUG-9 (P1)** — `rpc.py:8232-8236` HTTP 400 → JSON-RPC -32603; Core uses -3. Message text "Address does not refer to key (P2PKH only)" diverges from Core's "Address does not refer to key" (extra parenthetical) |
| 4 | … | G19: invalid address → `RPC_INVALID_ADDRESS_OR_KEY` (-5) "Invalid address" | **BUG-10 (P1)** — `rpc.py:8228-8231` HTTP 400 → JSON-RPC -32603; Core uses -5 |
| 4 | … | G20: bad recovery / pubkey-mismatch → bool `false` (NOT error) | PASS (`rpc.py:8263-8264` returns False on `from_signature_and_message` exception; `:8269` returns False on hash160 mismatch) |
| 4 | … | G21: handle header bytes outside 27..=34 as Core does (MASK, not reject) | **BUG-11 (P1)** — `rpc.py:8252-8253` rejects `header < 27 or header > 34` (returns False). Core (`pubkey.cpp:303-304`) MASKS via `(vchSig[0] - 27) & 3` and `& 4`, accepting arbitrary upper bits. Stricter than Core, divergence in malformed-sig path. Same shape as rustoshi BUG-6 / clearbit BUG-13 — **fleet-wide pattern** |
| 4 | … | G22: strict base64 — reject whitespace / non-canonical padding | PASS (`rpc.py:8241` uses `base64.b64decode(signature, validate=True)`, strict). Stricter than Core's `DecodeBase64`; same observation as clearbit BUG-8 (Zig liberal). Listed here for fleet pattern continuity (ouroboros is on the strict side of the gap) |
| 4 | … | G23: decoded sig length must equal exactly 65 bytes | PASS (`rpc.py:8246-8249`) |
| 5 | Network gating | G24: address version byte must match active chain | **BUG-12 (P0-CDIV)** — `rpc_verifymessage` (`rpc.py:8232`) accepts **both** mainnet (`0x00`) and testnet (`0x6f`) versions on every node. A mainnet P2PKH address submitted to a regtest ouroboros decodes successfully and proceeds to recovery. Symmetric to BUG-5 for WIF; this is the address half of the same air-gap break. Combined with BUG-5: a wallet that ever loaded a mainnet WIF (possible via `from_wif` accepting any prefix `wallet.py:838-844`) on a regtest node can produce a valid mainnet signature on a node meant to be isolated to regtest — silently crossing an air-gap that Core enforces by construction |
| 6 | `signmessage` wallet resolution | G25: prefer `GetWalletForJSONRPCRequest` (multi-wallet routing) | **BUG-13 (P1)** — `rpc_signmessage` (`rpc.py:8088-8093`) tries `getattr(self.node, "wallet", None)` FIRST then falls back to `self._get_wallet_for_rpc()`. All OTHER wallet-key-using RPCs (`rpc.py:3348, 3407, 3436, 3458, 3516, 3752, 3790, 3816, 3846`) call `self._get_wallet_for_rpc()` FIRST. Result: on a multi-wallet setup where `node.wallet` is a stale legacy default, `signmessage` routes to the WRONG wallet (the legacy one), while every other RPC honours the `/wallet/<name>/` URL routing. **Two-pipeline guard 19th distinct ouroboros instance** — wallet-resolution duality coexists between `signmessage` and the other 9 handlers |
| 7 | `RegisterSignMessageRPCCommands` namespacing | G26: `signmessage` is wallet-side, `signmessagewithprivkey` + `verifymessage` are util-side | PARTIAL — ouroboros does not have explicit category labels (single dispatch via `getattr(self, 'rpc_<name>')` at `rpc.py:6396`), so category-correctness is N/A. But the wallet-vs-util boundary IS observable in the wallet-required check: `signmessage` requires a wallet (PASS), `signmessagewithprivkey` does NOT require a wallet (PASS via `rpc.py:8138-8200` having no wallet lookup), `verifymessage` does NOT require a wallet (PASS). Listed for traceability |
| 8 | BIP-322 Legacy mode | G27: signmessage's BIP-137 P2PKH path IS the de-facto Legacy mode | PASS (functional parity through G15-G23 modulo bugs) |
| 9 | **BIP-322 Simple mode** | G28: `to_spend` virtual-tx + `BIP0322-signed-message`-tagged scriptSig + witness-only serialization | **BUG-14 (P1 — entirely-missing-feature)** — ouroboros has **zero** BIP-322 implementation. Grep over `src/ouroboros/` for `BIP0322`/`BIP-322`/`BIP322`/`to_spend.*[mM]essage`/`to_sign.*[mM]essage`/`bip322`/`50929b74`/`NUMS` returns ZERO production hits. The only `to_spend`/`to_sign` are in `validation.py:1771-1824` — **signet BIP-325 challenge verification**, structurally adjacent (the virtual-tx shape is identical) but **NOT reused** for message signing |
| 9 | … | G29: SegWit v0 / v1 sig-format dispatch for `to_sign` witness | **BUG-14 cross-cite** — absent. P2WPKH/P2WSH/P2TR `signmessage` cannot produce a BIP-322-compatible sig |
| 10 | **BIP-322 Full mode** | G30: arbitrary `to_sign` (multi-in/multi-out) signer & verifier | **BUG-14 cross-cite** — absent |
| 11 | **BIP-322 Taproot NUMS-point fallback** | G31: NUMS-point internal-key constant available for script-path-only signing | **BUG-14 cross-cite** — no NUMS-point constant anywhere in `src/ouroboros/` |
| 11 | … | G32: BIP-340 tagged-hash construction (`SHA256(SHA256(tag) || SHA256(tag) || msg)`) reused | PARTIAL — `wallet.py:783-787` HAS the BIP-341 TapTweak tagged-hash; same construction would apply for `BIP0322-signed-message`. Code reuse possible but **not done**. Cross-cite BUG-14 |

---

## BUG-1 (P0-SEC) — `signmessage` does NOT check `wallet.is_locked` before reading the key

**Severity:** P0-SEC. Bitcoin Core's wallet-side `signmessage`
(`wallet/rpc/signmessage.cpp:42-44`) unconditionally invokes
`EnsureWalletIsUnlocked(*pwallet)` before any key access. If the
wallet is encrypted and currently locked, the call throws
`RPC_WALLET_UNLOCK_NEEDED` (-13).

ouroboros's `rpc_signmessage` (`src/ouroboros/rpc.py:8071-8136`):

```python
async def rpc_signmessage(self, address: str, message: str) -> str:
    ...
    # Resolve wallet (single-wallet legacy or multi-wallet manager).
    wallet = getattr(self.node, "wallet", None)
    if wallet is None:
        try:
            wallet = self._get_wallet_for_rpc()
        except Exception:
            wallet = None
    if wallet is None or not getattr(wallet, "keys", None):
        raise HTTPException(status_code=400, detail="No wallet loaded")
    # ... iterate wallet.keys finding hash160 match ...
```

There is no `wallet.is_locked` check. The 5 other wallet-key-using
RPCs in the same file DO check (`rpc.py:3439, 3952, 3977, 4170, 11863`),
making this an isolated omission, not a fleet-wide ouroboros gap.

Now examine what happens on a locked wallet. `Wallet.lock()`
(`wallet.py:1213-1227`) sets `self.keys = []` and `self._encrypted_blob
= <ciphertext>`. The post-lock state is:
- `wallet.is_locked == True` (via `wallet.py:1166-1169` — encrypted_blob
  not None AND passphrase is None),
- `wallet.keys == []`.

So the `if wallet is None or not getattr(wallet, "keys", None)` guard
at `rpc.py:8094-8095` evaluates `not []` → True → raises
`HTTPException(status_code=400, detail="No wallet loaded")`. The
operator-visible error is **"No wallet loaded"** — a flatly wrong
status (a wallet IS loaded; it is just encrypted-locked). Bitcoin
Core emits `RPC_WALLET_UNLOCK_NEEDED` (-13) with the canonical message
`"Error: Please enter the wallet passphrase with walletpassphrase
first."`.

**File:** `src/ouroboros/rpc.py:8071-8136`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:42-44`
(`EnsureWalletIsUnlocked(*pwallet)`).

**Cross-cite:** `rpc.py:3439, 3952, 3977, 4170, 11863` — 5 other
wallet-key-using RPCs that DO check `wallet.is_locked` (with the
canonical message `"Wallet is locked; unlock with walletpassphrase
first"`). Pure isolated omission.

**Impact:**
- Encrypted-locked ouroboros wallet returns wrong error class on
  `signmessage` (HTTP 400 / JSON-RPC -32603 vs. Core's -13).
- Operator tooling that branches on `error.code == -13` to prompt for
  the passphrase (Sparrow, Specter, bitcoin-cli wrappers) silently
  fails to recognise the lock state.
- Unlike clearbit W158 BUG-2, ouroboros does **NOT** have the
  catastrophic "ciphertext-as-scalar" leak (clearbit stores ciphertext
  in `KeyPair.secret_key`; ouroboros wipes `keys` on lock entirely),
  so this is only a UX / error-parity bug, not a key-leak primitive.

**Cross-cite clearbit W158 BUG-2 (encrypted-wallet-cipher-as-scalar):**
ouroboros does NOT have the same shape. The clearbit attack works
because `KeyPair.secret_key` field is overwritten with AES-256-GCM
ciphertext when the wallet is encrypted, and `handleSignMessage` reads
the field directly. ouroboros's `Wallet.lock()` empties `keys = []`
entirely, so the iterate-keys loop at `rpc.py:8102-8110` finds no key
and never feeds ciphertext into `sign_recoverable`. Defense-in-depth
saves us here.

---

## BUG-2 (P0-CDIV) — `signmessage` accepts P2WPKH and P2SH-P2WPKH addresses (comment-as-confession)

**Severity:** P0-CDIV. Bitcoin Core's wallet-side `signmessage`
(`wallet/rpc/signmessage.cpp:54-57`) takes
`std::get_if<PKHash>(&dest)` and throws `RPC_TYPE_ERROR` with
`"Address does not refer to key"` when the destination is NOT a
legacy P2PKH. The BIP-137 message-signing format is **P2PKH-only on
the verify side** (verifymessage recovers a pubkey from the
compact-recoverable sig and compares its hash160 against the address
payload). A SegWit address (`bc1q...`) has the same hash160 as the
underlying key but its scriptPubKey is `OP_0 PUSH20 <h160>` — the
BIP-137 verifier does not understand witness programs, so a sig
emitted for a SegWit address would be silently mis-attributed.

ouroboros's `rpc_signmessage` (`rpc.py:8097-8110`):

```python
# Find the matching key. Core's signmessage only accepts P2PKH (legacy)
# addresses; we additionally accept P2WPKH because that's what
# ouroboros wallets produce by default — falls back to the P2PKH
# the same key would derive when signing.
target_key = None
for kd in wallet.keys:
    k = wallet._get_wallet_key(kd)
    if address in (
        k.get_p2pkh_address(),
        k.get_p2wpkh_address(),
        k.get_p2sh_p2wpkh_address(),
    ):
        target_key = k
        break
```

The inline comment at line 8097-8100 is a **comment-as-confession**
(fleet pattern, **14th distinct ouroboros instance** per W141
running-count): "Core's signmessage only accepts P2PKH (legacy)
addresses; we additionally accept P2WPKH because that's what
ouroboros wallets produce by default — falls back to the P2PKH the
same key would derive when signing."

**Effect:** A wallet-tooling client (Sparrow, Specter, Trezor
companion, `bitcoin-cli signmessage`) that calls
`signmessage <P2WPKH-addr> <msg>` against ouroboros gets back a sig
that:
1. Was produced over `MessageHash(msg)` using the key whose hash160
   matches BOTH the P2PKH AND P2WPKH forms (same key, different
   address types).
2. The header byte encodes `compressed=true` (BUG-3 below) regardless
   of whether the address is P2PKH or SegWit.
3. When the same client then calls `verifymessage <P2WPKH-addr>
   <sig> <msg>`, ouroboros's `rpc_verifymessage` (`rpc.py:8232`)
   REJECTS the address as "Address does not refer to key (P2PKH only)".
4. The client gets a sig back from `signmessage` that ouroboros
   itself refuses to verify against the same address. Returning to
   the verify call with the equivalent P2PKH form (extra
   `address.zig`-equivalent legwork on the client) makes the verify
   succeed — but the client doesn't know to do that.

This is a **silent address-type downgrade**: ouroboros accepts the
sign request, produces a sig that's interpretable as a Legacy-BIP-137
sig over the P2PKH form of the same key, returns it to the client
without explaining what it just did. The Core-compatible behaviour
is to throw on the SegWit input.

The test file `tests/test_rpc_signmessage.py:146-157`
(`test_signmessage_via_p2wpkh_address`) **pins** this behaviour as
expected:

```python
async def test_signmessage_via_p2wpkh_address(rpc_with_wallet):
    """ouroboros allows signing by P2WPKH address (the wallet's default
    address type) — verifymessage still validates against the equivalent
    P2PKH legacy address derived from the same key."""
    p2wpkh = rpc_with_wallet.node.wallet._key.get_p2wpkh_address()
    p2pkh = rpc_with_wallet.node.wallet._key.get_p2pkh_address()
    msg = "ouroboros-segwit"
    sig = await rpc_with_wallet.rpc_signmessage(p2wpkh, msg)
    ok = await rpc_with_wallet.rpc_verifymessage(p2pkh, sig, msg)
    assert ok is True
```

This is the **"test-pins-bug" fleet pattern** (W158 NEW) — a test
codifies a Core-divergent behaviour as the expected output, which
makes any future Core-parity fix appear as a regression in the test
suite. Removing this test is a prerequisite to fixing BUG-2.

**File:** `src/ouroboros/rpc.py:8097-8110`; pinning test at
`tests/test_rpc_signmessage.py:146-157`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:54-57`
(`std::get_if<PKHash>(&dest)` reject).

**Impact:**
- Sign/verify round-trip via ouroboros is asymmetric: sign accepts
  the SegWit address, verify rejects it. The downstream client must
  know to re-derive the P2PKH form to verify — silent UX trap.
- Cross-impl divergence: a sig produced via ouroboros for a SegWit
  address is byte-identical to a sig produced via Core for the
  equivalent P2PKH address. Tools that hash-anchor sig text to
  "address that signed" (proof-of-reserves, LNURL-auth) treat the
  SegWit address as the source-of-truth, but the sig actually
  represents the P2PKH form — silently breaking proof contracts.
- Test-pins-bug: any Core-parity fix removes 1 test from the
  pinning suite; auditor pairs this with W158 (fleet pattern
  tracking) before landing the fix.

---

## BUG-3 (P1) — `signmessage` hardcodes `compressed=true` in the header byte; parallel `signmessagewithprivkey` does it correctly

**Severity:** P1. The compact-recoverable header byte format is
`27 + recid + (4 if compressed else 0)`. The compressed flag affects
how `verifymessage` re-derives the pubkey from the sig — a wrong
flag returns the wrong-shape pubkey, whose hash160 then mismatches
the address.

ouroboros's `rpc_signmessage` (`rpc.py:8133-8136`):

```python
recid = sig_bytes[64]
header = bytes([27 + recid + 4])  # compressed pubkey
compact = header + sig_bytes[:64]
return base64.b64encode(compact).decode("ascii")
```

The inline comment `# compressed pubkey` documents the hardcode.

The PARALLEL `rpc_signmessagewithprivkey` (`rpc.py:8197-8200`)
correctly threads the WIF-derived flag:

```python
recid = sig_bytes[64]
header = bytes([27 + recid + (4 if compressed else 0)])
compact = header + sig_bytes[:64]
return base64.b64encode(compact).decode("ascii")
```

Two parallel implementations of the same primitive, one with a
hardcode and one without. **Two-pipeline guard 18th distinct
ouroboros instance** (intra-file). The wallet-side
`WalletKey.from_wif` (`wallet.py:838-844`) silently strips a trailing
`0x01` byte from a 33-byte payload (`if len(key_bytes) == 33 and
key_bytes[-1] == 0x01: key_bytes = key_bytes[:-1]`) but does NOT
remember the compressed flag on the `WalletKey`. So a wallet that
ever loaded an uncompressed-pubkey legacy key (32-byte payload,
no compressed flag) would still emit a 33-byte compressed pubkey via
`self._privkey.public_key.format(compressed=True)` (`wallet.py:726`)
— and the hardcoded `27 + recid + 4` would be **accidentally correct
for the public-key bytes that ARE emitted**, but accidentally
**wrong for the WIF intent** if the operator imported an
uncompressed-WIF key meaning "use uncompressed pubkey for everything,
including the address hash160 calculation".

**File:** `src/ouroboros/rpc.py:8133-8134` (hardcoded compressed
flag); cross-file gap at `src/ouroboros/wallet.py:719-726` (`WalletKey`
struct does not carry a compressed flag).

**Core ref:** `bitcoin-core/src/key.cpp:259-261` —
`CKey::SignCompact` threads `fCompressed` from the source CKey.

**Impact:**
- Wallet that ever loaded an uncompressed-WIF key (legacy 2010-era
  P2PKH keys) and then sign-message-d through ouroboros: the sig
  header says "compressed pubkey", `verifymessage` recovers a
  compressed pubkey whose hash160 does NOT match the
  uncompressed-pubkey address payload. Verify returns false.
- Two-pipeline guard pattern: this is the 18th distinct ouroboros
  instance where two parallel implementations of one primitive
  diverge by an avoidable hardcode.

---

## BUG-4 (P1) — No post-sign re-verification step (Core's `CKey::SignCompact:263-269` corruption guard)

**Severity:** P1. Bitcoin Core's `CKey::SignCompact`
(`key.cpp:250-271`) signs the message, then **recovers** the pubkey
from the freshly produced compact sig and **asserts** equality with
the source pubkey. This catches hardware-induced bitflips on the sig
output buffer (cosmic rays, DRAM bit-errors on long-running nodes,
malicious code-cache poisoning).

ouroboros's `rpc_signmessage` (`rpc.py:8118-8136`) and
`rpc_signmessagewithprivkey` (`rpc.py:8184-8200`) both omit the
re-verify step. The sig is base64-encoded and returned to the caller
without integrity checking. Operator burden to detect.

**File:** `src/ouroboros/rpc.py:8118-8136`; `src/ouroboros/rpc.py:8184-8200`.

**Core ref:** `bitcoin-core/src/key.cpp:263-269`
(`RecoverCompact(hash, sig)` round-trip check).

**Impact:** rare hardware-bitflip on the sig output buffer goes
undetected. Fleet pattern: every other audited impl in W158 has the
same gap (rustoshi BUG-2, clearbit `crypto.zig:987-996` matches Core
because `secp256k1_ecdsa_sign_recoverable` is used directly without
the round-trip).

---

## BUG-5 (P0-CDIV) — `signmessagewithprivkey` accepts WIF from any network

**Severity:** P0-CDIV. Bitcoin Core's `signmessagewithprivkey`
(`rpc/signmessage.cpp:62-101`) calls `DecodeSecret(strPrivkey)` which
consults `Params().Base58Prefix(SECRET_KEY)` — `0x80` on mainnet,
`0xEF` on testnet/regtest/signet. A mainnet WIF on a regtest node is
rejected with `RPC_INVALID_ADDRESS_OR_KEY` (-5) "Invalid private key".

ouroboros's `rpc_signmessagewithprivkey` (`rpc.py:8164-8179`):

```python
# 1) WIF decode.
try:
    decoded = _base58.b58decode_check(privkey)
except Exception:
    raise HTTPException(status_code=400, detail="Invalid private key")

# decoded = version(1) + secret(32) [+ compressed_flag(1)]
payload = decoded[1:]   # strip version byte
if len(payload) == 33 and payload[-1] == 0x01:
    compressed = True
    secret = bytes(payload[:32])
elif len(payload) == 32:
    compressed = False
    secret = bytes(payload)
else:
    raise HTTPException(status_code=400, detail="Invalid private key")
```

The version byte at index 0 is silently stripped at line 8171
without any check against `self.node.network`. A mainnet WIF
(`5Hue...` / `K...` / `L...`) on a `--network regtest` ouroboros
decodes successfully and signs. Same shape as clearbit W158 BUG-6
and rustoshi BUG-1 — **fleet-wide network-air-gap pattern, now
confirmed in at least 3 of 10 impls** (audit-tracking memo).

Worse: combined with BUG-12 below, a wallet that ever loaded a
mainnet WIF onto a regtest ouroboros (via `wallet.py:838-844` which
is **also** network-agnostic — it strips the WIF version byte
without checking, and stores the resulting `WalletKey` with the node
network attached) can produce a valid mainnet-shaped P2PKH signature
on a node meant to be isolated to regtest. Air-gap broken in BOTH
directions.

**File:** `src/ouroboros/rpc.py:8164-8179`; cross-file gap at
`src/ouroboros/wallet.py:838-844` (`WalletKey.from_wif` also
network-agnostic).

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret`,
`bitcoin-core/src/chainparams.cpp::Params().Base58Prefix(SECRET_KEY)`.

**Impact:**
- Cross-network signing on isolated regtest/testnet/signet nodes.
- Fleet diff-testing harness produces a "matching" sig from
  ouroboros vs. an error from Core for the same input — silent
  divergence at the RPC layer.

---

## BUG-6 (P1) — `signmessagewithprivkey` does not validate WIF scalar ∈ [1, n-1]

**Severity:** P1. Core's `CKey::Set` validates the secp256k1 scalar
is in `[1, n-1]`. Out-of-range scalars are rejected pre-sign with
"Invalid private key" (-5).

ouroboros relies on coincurve's `PrivateKey(secret)` constructor
(`rpc.py:8186`) to reject out-of-range scalars. The exception is
caught at line 8188 and re-raised as `HTTPException(500, "Sign
failed: {e}")`. The "Invalid private key" path at line 8168, 8179
is only reached on base58check / length failure — never on
scalar-out-of-range. Error code divergence (-32603 vs. Core's -5);
error message divergence ("Sign failed: ..." vs. Core's "Invalid
private key").

**File:** `src/ouroboros/rpc.py:8186-8194`.

**Core ref:** `bitcoin-core/src/key.h::CKey::Set` (`vch_secret` →
`secp256k1_ec_seckey_verify`).

**Impact:** Cosmetic / error-parity. Same shape as clearbit BUG-7.

---

## BUG-7 (P1) — `signmessagewithprivkey` errors map to JSON-RPC -32603 (Internal error) instead of Core's -5

**Severity:** P1. Bitcoin Core's `signmessagewithprivkey` maps both
"Invalid private key" and "Sign failed" to `RPC_INVALID_ADDRESS_OR_KEY`
(-5). ouroboros raises `HTTPException(status_code=400)` (for invalid
WIF) and `HTTPException(status_code=500)` (for sign-fail); both
converted by `_handle_rpc` (`rpc.py:1061-1066`) into JSON-RPC code
-32603 (Internal error).

**File:** `src/ouroboros/rpc.py:8168, 8179, 8189, 8193` (4
HTTPException raises in `signmessagewithprivkey`); cross-cite
`rpc.py:1061-1066` (HTTP→JSON-RPC conversion).

**Core ref:** `bitcoin-core/src/rpc/protocol.h::RPC_INVALID_ADDRESS_OR_KEY`
= -5.

**Impact:** Operator tooling that branches on `error.code` cannot
distinguish "wrong-format privkey" from "RPC internal error". Fleet
RPC-error-code parity gap; symmetric with BUG-8/BUG-9/BUG-10 for
`verifymessage` and BUG-1 for `signmessage`. **5 of 5 sub-handlers
emit -32603 for distinct Core error codes.**

---

## BUG-8 (P1) — `verifymessage` "Malformed base64" maps to JSON-RPC -32603 instead of Core's -3 (`RPC_TYPE_ERROR`)

**Severity:** P1. Bitcoin Core's `verifymessage` maps
`ERR_MALFORMED_SIGNATURE` → `RPC_TYPE_ERROR` (-3). ouroboros raises
`HTTPException(status_code=400, detail="Malformed base64 encoding")`
at `rpc.py:8244, 8248`; converted to -32603.

**File:** `src/ouroboros/rpc.py:8243-8245, 8246-8249`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:48-49`.

**Impact:** Operator-error-code parity; cross-cite BUG-7.

---

## BUG-9 (P1) — `verifymessage` "Address does not refer to key" maps to JSON-RPC -32603 instead of Core's -3, and message text diverges

**Severity:** P1. Bitcoin Core's `verifymessage` maps
`ERR_ADDRESS_NO_KEY` → `RPC_TYPE_ERROR` (-3) with message `"Address
does not refer to key"`. ouroboros raises `HTTPException(400,
"Address does not refer to key (P2PKH only)")` at `rpc.py:8232-8236`
— extra `" (P2PKH only)"` text + code becomes -32603.

The extra text reveals an implementation detail (the validator
internally rejects non-P2PKH) that Core does not expose.

**File:** `src/ouroboros/rpc.py:8232-8236`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:46-47`.

**Impact:** Cosmetic + error-code parity.

---

## BUG-10 (P1) — `verifymessage` "Invalid address" maps to JSON-RPC -32603 instead of Core's -5

**Severity:** P1. Bitcoin Core's `verifymessage` maps
`ERR_INVALID_ADDRESS` → `RPC_INVALID_ADDRESS_OR_KEY` (-5). ouroboros
raises `HTTPException(400, "Invalid address")` at `rpc.py:8228-8231`
— converted to -32603.

**File:** `src/ouroboros/rpc.py:8228-8231`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:44-45`.

**Impact:** Cross-cite BUG-7/BUG-8/BUG-9.

---

## BUG-11 (P1) — `verifymessage` rejects header bytes outside 27..=34 (stricter than Core's mask)

**Severity:** P1. Bitcoin Core's `CPubKey::RecoverCompact`
(`pubkey.cpp:300-318`) does NOT reject header bytes > 34. It MASKS
via `(vchSig[0] - 27) & 3` (extracting recid) and
`((vchSig[0] - 27) & 4) != 0` (extracting compressed flag). Any
header byte ≥ 27 is interpreted; upper bits ignored.

ouroboros's `rpc_verifymessage` (`rpc.py:8251-8253`):

```python
header = sig[0]
if header < 27 or header > 34:
    return False
```

Returns False for header = 35..255 instead of masking. Strictly
stricter than Core; a malformed sig with a header byte beyond 34
returns False on ouroboros but might succeed on Core (because Core
would mask to a valid recid+compressed combination, attempt
recovery, get a different pubkey than expected, and return false
from the pubkey-hash mismatch gate — but NOT from the header-byte
gate).

**File:** `src/ouroboros/rpc.py:8251-8253`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:303-304`.

**Impact:** rare malformed-sig path divergence; fleet-wide pattern
(rustoshi BUG-6, clearbit BUG-13).

---

## BUG-12 (P0-CDIV) — `verifymessage` accepts address from any network (mainnet/testnet P2PKH version bytes both accepted)

**Severity:** P0-CDIV. Bitcoin Core's `verifymessage` calls
`DecodeDestination(address)` which consults
`Params().Base58Prefix(PUBKEY_ADDRESS)` to gate the version byte.
A mainnet address (`1...`, version `0x00`) on a regtest/testnet node
is rejected with `RPC_INVALID_ADDRESS_OR_KEY`.

ouroboros's `rpc_verifymessage` (`rpc.py:8232`):

```python
if version not in (0x00, 0x6f) or len(payload) != 20:
    raise HTTPException(
        status_code=400,
        detail="Address does not refer to key (P2PKH only)",
    )
```

The version-byte test is `0x00` OR `0x6f` — i.e. BOTH mainnet AND
testnet are accepted on every node, regardless of the active chain.
No consultation of `self.node.network`.

Combined with **BUG-5** (signmessagewithprivkey accepts any-network
WIF) and the cross-file gap in `WalletKey.from_wif`
(`wallet.py:838-844`, which also strips the WIF version byte without
checking), a wallet that ever loaded a mainnet WIF on a regtest
node can produce a valid mainnet-shaped signature. Air-gap broken in
BOTH directions: addresses + WIFs.

Worse: regtest's actual P2PKH version byte in Bitcoin Core is `0x6f`
(same as testnet). Signet's is also `0x6f`. So the `0x00 or 0x6f`
gate is effectively "any non-mainnet OR mainnet" — a wallet that
holds a `0x05` P2SH address is rejected (correct; it's not P2PKH),
but a `0x00` mainnet P2PKH on a regtest ouroboros decodes
successfully, and if the recovered pubkey's hash160 matches the
payload, verify returns True. **Mainnet signature accepted on regtest
node, vice versa.**

**File:** `src/ouroboros/rpc.py:8232`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeDestination`
(`Params()` network-scoped).

**Impact:**
- Network air-gap broken on the verify side. A signature collected
  from a mainnet `signmessage` exchange (e.g. proof-of-reserves)
  verifies "successfully" on a regtest node, defeating the operator's
  network isolation guarantee.
- Cross-impl divergence vs. Core diff-test: Core throws
  `RPC_INVALID_ADDRESS_OR_KEY` for cross-network inputs; ouroboros
  silently proceeds to verify. Fleet diff-test now systematically
  diverges on this case.
- Same shape as clearbit BUG-4 and rustoshi (implicit via
  `parse_address` no-network-check) — **fleet-wide network-air-gap
  pattern, at least 3 of 10 impls confirmed**.

---

## BUG-13 (P1) — `signmessage` wallet resolution flips the order vs. every other wallet-key-using RPC (two-pipeline guard 19th instance)

**Severity:** P1. Every other wallet-key-using RPC in
`src/ouroboros/rpc.py` resolves the wallet via:

```python
wallet = self._get_wallet_for_rpc()
if wallet is None:
    raise HTTPException(status_code=500, detail="No wallet loaded")
```

Confirmed sites: `rpc.py:3348, 3407, 3436, 3458, 3516, 3752, 3790,
3816, 3846, 3909, 3949, 3974, 4170, 11859`.

`rpc_signmessage` does the **inverse**: tries
`getattr(self.node, "wallet", None)` FIRST, then falls back to
`self._get_wallet_for_rpc()`:

```python
# Resolve wallet (single-wallet legacy or multi-wallet manager).
wallet = getattr(self.node, "wallet", None)
if wallet is None:
    try:
        wallet = self._get_wallet_for_rpc()
    except Exception:
        wallet = None
```

The `try / except Exception` also swallows multi-wallet routing
errors (e.g. "wallet not loaded by name"), masking them into a
generic "No wallet loaded" instead of bubbling the
HTTPException(404) from `_get_wallet_for_rpc`. On a multi-wallet
ouroboros where `node.wallet` is a stale legacy default and the
operator routes `/wallet/<other-name>/` for a `signmessage` call,
the request goes to the **wrong wallet** silently.

Comment on line 8087: `# Resolve wallet (single-wallet legacy or
multi-wallet manager).` — the comment **admits** the dual-pipeline
shape. **Two-pipeline guard 19th distinct ouroboros instance**
(intra-file). Comment-as-confession 15th distinct ouroboros instance
(W141+).

**File:** `src/ouroboros/rpc.py:8086-8093`.

**Core ref:** `bitcoin-core/src/wallet/rpc/util.cpp::GetWalletForJSONRPCRequest`
(single canonical resolver).

**Impact:**
- Multi-wallet setups silently route `signmessage` to the wrong
  wallet (the legacy default) instead of the URL-routed wallet.
- Bare `try / except Exception` swallows the 404
  "wallet not loaded" error from the multi-wallet resolver, turning
  it into the generic "No wallet loaded" — operator cannot
  distinguish "no wallet" from "wallet named X not loaded".
- Two-pipeline guard 19th instance; comment-as-confession 15th
  instance. Fleet pattern continuity.

---

## BUG-14 (P1 — entirely-missing-feature) — BIP-322 (Simple + Full + NUMS-point Taproot) entirely absent

**Severity:** P1 (entirely-missing-feature). ouroboros has **zero**
BIP-322 implementation. A grep over `src/ouroboros/` for
`BIP0322`/`BIP-322`/`BIP322`/`bip322`/`50929b74`/`NUMS`/`tagged_hash.*bip322`
returns ZERO production hits. Wallets that ship BIP-322-only proofs
(Sparrow ≥1.6, Trezor post-2023 firmware, Ledger post-2023 firmware,
miniscript proof tools, LNURL-auth implementations) cannot use
ouroboros to verify proofs.

The only `to_spend`/`to_sign` are in `src/ouroboros/validation.py:1771-1824`
— **signet BIP-325** block-challenge virtual-tx construction. The
shape is structurally identical to BIP-322's `to_spend`/`to_sign`
(1-in null-prevout, 1-out value=0 with custom scriptPubKey; second
tx spends first), but **NOT reused** for message signing. A future
fix would either: (a) factor the signet code into a reusable
virtual-tx helper, or (b) duplicate the construction inside
`signmessage` / `verifymessage`. Option (a) avoids three-pipeline
drift (which ouroboros is famously prone to — N-pipeline records in
W149+W150+W151+W156).

Additionally, the BIP-340 tagged-hash construction
(`SHA256(SHA256(tag) || SHA256(tag) || data)`) is **already
implemented** at `src/ouroboros/wallet.py:783-787` for BIP-341
TapTweak. The same construction with
`tag = b"BIP0322-signed-message"` would yield the BIP-322 message
commitment. Code reuse possible but not done.

**Files audited:** `src/ouroboros/` entire tree (zero BIP-322
production references).

**Core ref:** Not in Core trunk as of audit date (proposed in
bitcoin#24058 / external tooling like `bitcoin-signet`,
`proofofreserves`).

**Impact:**
- Modern wallets (Sparrow, Trezor, Ledger, all 2023+) emit
  BIP-322-only proofs by default for SegWit/Taproot addresses; these
  proofs cannot be verified by ouroboros.
- Proof-of-reserves verifiers that require BIP-322 (most modern
  implementations) cannot use ouroboros as the verifier node.
- Cross-fleet: fleet-wide gap (rustoshi BUG-8/9, clearbit BUG-9/10,
  camlcoin per its W158, blockbrew per its W158 — **at least 5 of 10
  impls confirmed missing BIP-322 entirely** as of this audit).

---

## BUG-15 (P1) — `_message_hash` is correctly varint-encoded but the test harness pins only short-message verification

**Severity:** P1 (test-coverage gap). The production
`_message_hash` (`rpc.py:690-699`) correctly uses
`_encode_varint(len(magic_bytes))` and `_encode_varint(len(msg_bytes))`
— so long messages (≥253 bytes) hash correctly per Core's
HashWriter-CompactSize semantics.

But the test harness `tests/test_rpc_signmessage.py:113-121`:

```python
def test_message_hash_matches_core_formula():
    """_message_hash must equal SHA256d(VarStr(MAGIC) || VarStr(message))."""
    from ouroboros.rpc import _message_hash, _MESSAGE_MAGIC
    msg = "ouroboros-vector"
    magic = _MESSAGE_MAGIC.encode()
    payload = bytes([len(magic)]) + magic + bytes([len(msg)]) + msg.encode()
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    assert _message_hash(msg) == expected
```

— hardcodes a 1-byte length prefix for the message (`bytes([len(msg)])`)
that **only works for messages shorter than 0xFD = 253 bytes**. The
test passes (msg = "ouroboros-vector", 16 chars), but does not
exercise the 3-byte (`0xFD` + uint16), 5-byte (`0xFE` + uint32), or
9-byte (`0xFF` + uint64) CompactSize encodings.

This is a **test-pins-bug-shape** (W158 NEW pattern) — the test
codifies a partial verification of Core parity. If a future refactor
of `_message_hash` substituted `bytes([len(msg_bytes)])` (the wrong
encoding) for `_encode_varint(...)` (the correct one), the test
would continue to pass for short messages, leaving the
long-message regression undetected. The test does NOT exercise
the actual Core-divergence-detection capability of varint encoding.

**File:** `tests/test_rpc_signmessage.py:113-121`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:73-79`
(HashWriter uses CompactSize via `<<` operator).

**Impact:** test coverage gap only; production code is correct.
Listed for fleet pattern continuity (`test-pins-bug` — W158 NEW; a
parallel of W152 / W155 test-coverage gaps).

---

## BUG-16 (P1) — `WalletKey.from_wif` is network-agnostic; cross-loads mainnet WIF onto regtest wallet (cross-cite BUG-5)

**Severity:** P1. `src/ouroboros/wallet.py:838-844`:

```python
@classmethod
def from_wif(cls, wif: str, network: str = "mainnet") -> "WalletKey":
    decoded = base58.b58decode_check(wif)
    key_bytes = decoded[1:]
    if len(key_bytes) == 33 and key_bytes[-1] == 0x01:
        key_bytes = key_bytes[:-1]
    return cls(bytes(key_bytes), network)
```

The version byte at `decoded[0]` is **silently stripped** without
checking it matches the requested `network`. A mainnet WIF (`0x80`)
imported onto a regtest wallet (`network="regtest"`) produces a
`WalletKey` whose `secret = <correct-32-bytes>` and
`network = "regtest"` — so `get_p2pkh_address()` then emits a
**regtest** P2PKH (`m...` / `n...`) for a key that the operator
believes is a mainnet (`1...`) key. The wallet effectively
"re-networks" any imported WIF without warning.

This is the wallet-side companion to BUG-5 (the RPC-side WIF
acceptance). Both gates need fixing in tandem.

**File:** `src/ouroboros/wallet.py:838-844`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret` (network-scoped).

**Impact:**
- Operator who pastes a `5Hue...` mainnet WIF into `importprivkey`
  on a regtest node gets a regtest-shaped address back. The key is
  the same secret; the addresses are different; funds at the
  mainnet address are NOT importable.
- Combined with BUG-12 (verifymessage accepts mainnet address on
  regtest node), the full attack surface: import mainnet WIF on
  regtest, `signmessage` on the equivalent regtest address, then
  `verifymessage` against the equivalent mainnet address on a
  DIFFERENT regtest node — verify returns True because both ends
  accept cross-network addresses. Mainnet signature attribution
  emerges from a fully regtest workflow.

---

## BUG-17 (P1) — `_dsha256` and `_encode_varint` are module-level helpers; the same helpers are duplicated inside `_parse_block_txs` and tests, fragmenting the wire-format source-of-truth

**Severity:** P1. `rpc.py:531-543` defines module-level `_dsha256`
and `_encode_varint`. These are imported and reused by
`_message_hash` (`rpc.py:690-699`), the merkle helpers (`rpc.py:566-571`),
the partial-merkle-tree code (`rpc.py:600-611`), and several other
sites.

But `_parse_block_txs` (`rpc.py:702-844`) inlines its OWN
`_read_cs` (`rpc.py:724-736`) and its own SegWit txid computation
(`rpc.py:789-833`) instead of reusing the module-level helpers. This
is structurally the same shape as ouroboros's **N-pipeline drift**
records in W149+W150+W151+W156 — multiple coexisting implementations
of the same wire-format primitive.

Specifically relevant to W158: a future BIP-322 implementation that
needs to serialize the `to_spend`/`to_sign` virtual transactions
would either (a) reuse `_parse_block_txs`'s inlined serializer
(adding a 4th copy), (b) reuse the module-level helpers (the
correct architectural choice), or (c) factor a new helper module
(the best choice). The current N-pipeline state makes (a) tempting
and (c) high-friction.

**File:** `src/ouroboros/rpc.py:702-844` (inlined wire-format
helpers); `src/ouroboros/rpc.py:531-543` (canonical module-level
helpers).

**Impact:** future-BIP-322 implementation friction; current
two-pipeline (soon-to-be-three-pipeline) for the wire-format layer
that `_message_hash` already correctly uses.

---

## BUG-18 (P2) — `signmessage` does not enforce `disable_private_keys` (watch-only) wallet flag

**Severity:** P2. Bitcoin Core's `signmessage` indirectly enforces
the watch-only flag: a watch-only wallet has no SPK manager that
`CanProvide` the private key for the address, so `pwallet->SignMessage`
returns `SigningResult::PRIVATE_KEY_NOT_AVAILABLE` →
`RPC_WALLET_ERROR` (-4) "Private key not available".

ouroboros's `Wallet` has a `_disable_private_keys` flag
(`wallet.py:920`) but `rpc_signmessage` does NOT check it. On a
watch-only wallet, `wallet.keys` is empty (no `wif` records) so the
iterate loop at `rpc.py:8102-8110` finds no key and returns
"Private key not available for given address" (`rpc.py:8113-8116`).
The end-user-facing error is acceptable, but the path to it
diverges from Core: Core throws `RPC_WALLET_ERROR` (-4), ouroboros
throws `HTTPException(400)` → -32603.

**File:** `src/ouroboros/rpc.py:8102-8116`; cross-cite
`src/ouroboros/wallet.py:920` (flag exists but signmessage doesn't
explicit-check it).

**Core ref:** `bitcoin-core/src/wallet/wallet.cpp:2254-2265`.

**Impact:** minor UX divergence; cross-cite BUG-7/BUG-8/BUG-9/BUG-10
fleet error-code parity gap.

---

## BUG-19 (P2) — `rpc_signmessage` calls `wallet._get_wallet_key(kd)` for EVERY key in the wallet to find a hash160 match

**Severity:** P2 (perf / cost). `rpc.py:8101-8110`:

```python
target_key = None
for kd in wallet.keys:
    k = wallet._get_wallet_key(kd)
    if address in (
        k.get_p2pkh_address(),
        k.get_p2wpkh_address(),
        k.get_p2sh_p2wpkh_address(),
    ):
        target_key = k
        break
```

For each `kd` in `wallet.keys`, the handler:
1. Calls `wallet._get_wallet_key(kd)` which constructs a `WalletKey`
   from the WIF (decodes base58check, instantiates coincurve
   `PrivateKey`, derives compressed pubkey).
2. Computes 3 address forms (P2PKH, P2WPKH, P2SH-P2WPKH) — each
   involves hash160 + base58check or bech32 encoding.
3. Compares the address string against each.

For a wallet with N keys, this is `O(N)` `PrivateKey` constructions
+ `O(3N)` address derivations + `O(3N)` string compares.

Bitcoin Core (`scriptpubkeyman.cpp::SignMessage`) does the inverse
lookup: it computes `PKHash(decoded_destination)` once, then looks
up the key by `KeyID` in the `mapKeys` hash table — `O(1)`. For a
wallet with 10k keys (post-keypool-refill at default size), the
ouroboros approach is ~30k hash160 computations + 10k base58check +
10k bech32 encodings per `signmessage` call.

**File:** `src/ouroboros/rpc.py:8101-8110`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp:1291-1307`
(O(1) hash-table lookup via `GetKey`).

**Impact:** quadratic-ish startup cost on signmessage for
keypool-refill wallets; minor in practice (default keypool is 1000,
but the W116 expansion to 10000 was discussed). No correctness
impact. Listed for fleet pattern continuity (the inverse-lookup
gap appears in other ouroboros key-resolution sites).

---

## BUG-20 (P1) — `rpc_signmessage` and `rpc_signmessagewithprivkey` produce different sig formats for the same key on the same message (header-byte hardcode divergence)

**Severity:** P1. Given the same secret `s` and message `m`:
- `rpc_signmessage`: header byte = `27 + recid + 4` (always compressed)
- `rpc_signmessagewithprivkey` with a compressed-WIF input
  (`<0x80><s><0x01>` mainnet form): header byte = `27 + recid + 4`
  (compressed) — agrees.
- `rpc_signmessagewithprivkey` with an uncompressed-WIF input
  (`<0x80><s>` mainnet form, 33-byte total after base58check): header
  byte = `27 + recid + 0` (uncompressed) — DISAGREES with
  `signmessage`.

A client that imports an uncompressed-WIF key into the ouroboros
wallet via `importprivkey`, then calls `signmessage <addr> <m>`,
gets back a sig with header in the compressed range (31..34). The
SAME client calling `signmessagewithprivkey <the-same-WIF> <m>`
gets back a sig with header in the uncompressed range (27..30).

The two sigs are over the same `MessageHash(m)` and the same private
scalar, so they differ ONLY in the header byte (the R||S bytes are
identical for the same RFC-6979 nonce). But a client that uses one
endpoint then the other for a sanity-check sees mismatched
signatures and would (correctly) suspect node compromise. This is
the "two-pipeline guard" pattern bearing on observable wire output,
not just internal state.

**File:** `src/ouroboros/rpc.py:8134` (signmessage hardcoded `+4`);
`src/ouroboros/rpc.py:8198` (signmessagewithprivkey conditional).

**Impact:** observable sig-output divergence between two endpoints
of the same node for the same key + message. Operator-confusion +
proof-of-ownership tooling that retries on different endpoints sees
different sigs that decode to different headers.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-SEC:** 1 (BUG-1)
- **P0-CDIV:** 3 (BUG-2, BUG-5, BUG-12)
- **P1:** 14 (BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10,
  BUG-11, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-20)
- **P2:** 2 (BUG-18, BUG-19)

Total: 1 + 3 + 14 + 2 = 20. ✓

**Fleet patterns confirmed:**
- **"BIP-322 entirely absent"** (BUG-14) — fleet-wide pattern, at
  least 5 of 10 impls confirmed (rustoshi W158 BUG-8/9, clearbit W158
  BUG-9/10, camlcoin W158, blockbrew W158, ouroboros W158 BUG-14).
- **"Network air-gap broken on both WIF and address"** (BUG-5 +
  BUG-12 + BUG-16) — 3+ impls confirmed (clearbit W158 BUG-4/BUG-6,
  rustoshi W158 BUG-1 implicit, ouroboros W158 BUG-5/BUG-12/BUG-16).
- **"comment-as-confession"** (BUG-2, BUG-13) — 14th and 15th
  distinct ouroboros instances per W141+ tracking. BUG-2 inline
  comment `"Core's signmessage only accepts P2PKH... we additionally
  accept P2WPKH"` directly admits the divergence; BUG-13 comment
  `"single-wallet legacy or multi-wallet manager"` admits the dual
  pipeline.
- **"two-pipeline guard 18th + 19th distinct ouroboros extensions"**
  (BUG-3 intra-file sign-vs-signwithprivkey header hardcode; BUG-13
  wallet-resolution order flip).
- **"test-pins-bug"** (BUG-2, BUG-15) — W158 NEW. BUG-2 pinned by
  `test_signmessage_via_p2wpkh_address` codifying the SegWit-accept
  divergence as expected; BUG-15 pinned by
  `test_message_hash_matches_core_formula` only exercising 1-byte
  CompactSize prefix.
- **"5 of 5 sub-handlers map distinct Core error codes to
  JSON-RPC -32603"** (BUG-1, BUG-7, BUG-8, BUG-9, BUG-10) — a
  cross-handler error-parity gap; all 5 distinct Core error codes
  (-3, -4, -5, -13) collapse to ouroboros's -32603 (Internal
  error). Operator tooling that branches on `error.code` is
  systematically blind across the whole signmessage surface area.
- **"hardware-bitflip post-sign re-verify gap"** (BUG-4) — both
  ouroboros endpoints lack the Core `CKey::SignCompact:263-269`
  round-trip check.
- **"N-pipeline drift candidate"** (BUG-17) — wire-format helpers
  fragmented across module-level + `_parse_block_txs` inlined +
  future BIP-322 likely to add a 3rd. Fits ouroboros's N-pipeline
  record pattern (W149+W150+W151+W156 hold 6/6/7/8-pipeline records
  in other layers).

**Cross-cite clearbit W158 BUG-2 verdict:** ouroboros does **NOT**
have the same shape (encrypted-wallet-cipher-as-scalar). clearbit's
catastrophic leak relies on `KeyPair.secret_key` being overwritten
in-place with AES-256-GCM ciphertext when the wallet is encrypted,
and the sign handler reading the field directly. ouroboros's
`Wallet.lock()` (`wallet.py:1213-1227`) sets `self.keys = []`
entirely on lock — there is no ciphertext-bearing seckey slot for
the sign handler to read. The clearbit attack does not port to
ouroboros. Defense-in-depth saves us here.

**Top three findings:**
1. **BUG-1 (P0-SEC) + BUG-2 (P0-CDIV) cluster** — `signmessage`
   bypasses both the canonical wallet-locked check AND the
   P2PKH-only address gate. The former silently misreports lock
   state (HTTP "No wallet loaded" instead of -13
   `RPC_WALLET_UNLOCK_NEEDED`); the latter silently downgrades
   SegWit address inputs to a Legacy-BIP-137 sig over the P2PKH
   form of the same key. Both are pinned by a test in the suite
   (`test_signmessage_via_p2wpkh_address`) so any Core-parity fix
   appears as a regression in CI. **Test-pins-bug** is a NEW W158
   pattern.
2. **BUG-5 (P0-CDIV) + BUG-12 (P0-CDIV) + BUG-16 (P1) network
   air-gap break cluster** — both the WIF parse path
   (`signmessagewithprivkey`, `WalletKey.from_wif`) and the address
   parse path (`verifymessage`) silently accept cross-network input.
   A mainnet WIF imported onto a regtest ouroboros produces a
   regtest-shaped address; a mainnet signature collected for that
   key verifies on a DIFFERENT regtest ouroboros. The air-gap that
   Core enforces by-construction (`Params().Base58Prefix(...)`) is
   broken in both directions across both code paths.
3. **BUG-14 (P1 BIP-322 entirely absent)** — fleet-wide pattern
   confirmed for at least 5 of 10 impls. The signet `to_spend` /
   `to_sign` virtual-tx code at `validation.py:1771-1824` is
   structurally one refactor away from a reusable BIP-322
   primitive. The BIP-340 tagged-hash construction is already
   implemented at `wallet.py:783-787`. ouroboros has the building
   blocks; they are not assembled. Combined with **BUG-2 (silently
   downgrade SegWit to P2PKH)** this is the architectural reason
   ouroboros punts on a real BIP-322: the current code path
   pretends to "support" SegWit signing by silently producing a
   Legacy sig over the equivalent P2PKH form.
