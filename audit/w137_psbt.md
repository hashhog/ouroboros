W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (ouroboros)
=================================================================

Date: 2026-05-17
Impl: ouroboros (Python-only pipeline — PSBT is wallet, not consensus.
      The Rust pipeline (`ferrous-utils/sync`) has zero PSBT surface.
      Two-pipeline guard EXTENDS to forbid PSBT code on Rust side.)
Wave: W137 PSBT v0/v2 — BIP-174 + BIP-370 + BIP-371 (Taproot fields)
      + MuSig2 (BIP-327) PSBT extension.
Reference:
  - `bitcoin-core/src/psbt.h` (1475 lines: type constants, PSBTInput,
    PSBTOutput, PartiallySignedTransaction; full Serialize +
    Unserialize templates with the canonical key-validation rules)
  - `bitcoin-core/src/psbt.cpp` (639 lines: Merge, FillSignatureData,
    PSBTInputSigned, PSBTInputSignedAndVerified, UpdatePSBTOutput,
    SignPSBTInput, FinalizePSBT, FinalizeAndExtractPSBT,
    CombinePSBTs, DecodeBase64PSBT, DecodeRawPSBT, GetVersion)
  - `bitcoin-core/src/node/psbt.cpp` (AnalyzePSBT helper)
  - BIPs 174 (PSBT v0), 370 (PSBT v2), 371 (Taproot fields), 327
    (MuSig2 PSBT extension)

Status: 30 gates audited — **PRESENT 11 / PARTIAL 7 / MISSING 12.**
**24 BUGS** (1 P0-CDIV / 4 P0-CVE-class / 11 P1 / 8 P2).

Relationship to prior audits
----------------------------

- W51 audited `decodepsbt` JSON shape (closure landed); W137 covers
  the byte-format/serialization/signing/finalization layer underneath.
- W127 (Taproot) audited consensus-side Taproot in script/interpreter;
  W137 covers the BIP-371 PSBT *carrier* of Taproot signatures and
  keypaths, NOT script execution.
- W131 (descriptors / miniscript) closed `_construct_miniscript_witness`
  patterns; W137 extends to PSBT finalization that consumes them.
- W119 (PayJoin / BIP-78) audited the receiver checklist on top of
  PSBT; W137 audits the underlying PSBT codec that PayJoin assumes.
- W118 (wallet fleet audit) catalogued PSBT bugs across all 10 impls;
  the ouroboros-side findings here are the deepest-dive single-impl
  follow-up for that wave.

Two-pipeline guard
------------------

PSBT is **wallet code, not consensus code.** Bitcoin Core itself
keeps `psbt.h`/`psbt.cpp` in the top-level `src/` (not `consensus/`)
because the PSBT format never participates in block / tx validation —
the *transaction* extracted from a finalized PSBT is what's broadcast
and validated. The two-pipeline invariant for ouroboros:

- **Python pipeline (wallet)**: `src/ouroboros/psbt.py` (2948 lines)
  is the single source of truth for the PSBT codec, finalization,
  combine, extract. `wallet.py`, `rpc.py`, `payjoin.py` all import
  from this module.

- **Rust pipeline (consensus, `ferrous-utils/`)**: ZERO PSBT surface.
  No `psbt.rs`, no `PartiallySigned*` types, no `PSBT_MAGIC`,
  no `BIP-174` references in compiled Rust code.

```
$ grep -rn "BIP[- ]?174\|BIP[- ]?370\|BIP[- ]?371\|PSBT\|partially.signed" \
       ferrous-utils/ --include='*.rs'                  → 0 matches
$ grep -rn "psbt\|partial_signature\|partially_signed" \
       ferrous-utils/ --include='*.rs'                  → 0 matches
```

**Two-pipeline guard EXTENDED.** Test
`test_w137_g30_two_pipeline_psbt_python_only` codifies:
- No `*.rs` file under `ferrous-utils/{common,sync}/src/` may
  contain `PSBT`, `BIP-174`, `BIP-370`, `BIP-371`, or
  `PartiallySigned` in any form.
- The Python module `ouroboros.psbt` MUST remain importable as the
  single PSBT codec.
This extends the guard set W76 + W120 + W122 + W125 + W128 + W129 +
W130 + W131 + W133 → now W137. Future regression (e.g. moving the
PSBT codec to a Rust crate "for performance") trips the guard.

Top-level architectural findings
--------------------------------

**(F1) PSBT_HIGHEST_VERSION divergence from Core.** Core's `psbt.h:80`
hard-codes `PSBT_HIGHEST_VERSION = 0` — Core REJECTS any PSBT whose
`PSBT_GLOBAL_VERSION` (0xFB) value is > 0 with "Unsupported version
number" (`psbt.h:1322`). Ouroboros sets `PSBT_HIGHEST_VERSION = 2`
(`psbt.py:502`) so v2 PSBTs round-trip in ouroboros that Core would
refuse. This is a deliberate BIP-370 implementation, but it is a
cross-impl divergence operators must be aware of: a v2 PSBT signed by
ouroboros's wallet cannot be combined or extracted by Core. **BUG-1**.

**(F2) Unsigned-tx invariant not enforced on deserialize.** BIP-174
requires that the `PSBT_GLOBAL_UNSIGNED_TX` (v0 global key 0x00)
have empty scriptSigs and empty scriptWitnesses for every input —
this is the "unsigned" in "Partially Signed". Core's `psbt.h:1274-1278`
walks every `txin` and throws "Unsigned tx does not have empty
scriptSigs and scriptWitnesses." A PSBT that smuggles signatures
INTO the global unsigned-tx is malformed; relying on it for signing
risks committing to a forged sighash. Ouroboros's
`PSBT.deserialize` (`psbt.py:1554-1555`) accepts any byte payload
under the UNSIGNED_TX key and never validates that the contained
`script_sig` and witness stacks are empty. **BUG-2 (P0-CVE-class)**.

**(F3) Per-input count cross-check absent on deserialize.** Core
requires the number of per-input maps in the wire format match
`tx->vin.size()` exactly (`psbt.h:1382-1384`: "Inputs provided does
not match the number of inputs in transaction."). Similarly for
outputs. Ouroboros (`psbt.py:1590-1598`) iterates `range(n_inputs)`
and stops; if the PSBT carries FEWER input maps than `n_inputs`,
ouroboros silently constructs short input lists (since
`_read_kv_pairs` will raise on truncation only inside the loop). If
the PSBT carries MORE input maps than `n_inputs`, those trailing
maps are silently ignored. **BUG-3 (P1)**.

**(F4) Non-witness-UTXO sha256d invariant not enforced on
deserialize.** Core's `psbt.h:1371-1378` validates, for every
input that supplies `non_witness_utxo`, that
`non_witness_utxo->GetHash() == tx->vin[i].prevout.hash` AND that
`prevout.n < non_witness_utxo->vout.size()`. Without these checks
a malicious counterparty can hand the signer a forged previous-tx
blob whose `outputs[prev_vout]` lies about the value and scriptPubKey
the signer is committing to (CVE-2020-14199 class — the BIP-143
amount-oracle). Ouroboros enforces this LATE — in
`rpc_walletprocesspsbt` at signing time
(`rpc.py:10085-10135` — see W41 fix history) — but NOT in
`PSBT.deserialize`. PSBT consumers other than the signer (e.g.
`analyzepsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt`) will
trust the forged values. **BUG-4 (P0-CVE-class)**.

**(F5) Per-key size validation missing on Taproot fields.**
Core's `psbt.h:691-794` enforces strict byte sizes:
- `PSBT_IN_TAP_KEY_SIG` (0x13) value MUST be 64 or 65 bytes
  (Schnorr sig + optional sighash byte) — `psbt.h:699-703`.
- `PSBT_IN_TAP_SCRIPT_SIG` (0x14) value MUST be 64 or 65 bytes,
  and the key MUST be 65 bytes (1 type + 32 xonly + 32 leaf_hash) —
  `psbt.h:710-712,720-724`.
- `PSBT_IN_TAP_LEAF_SCRIPT` (0x15) key MUST be at least 34 bytes
  AND `(key.size() - 2) % 32 == 0` (1 type + 33-byte control block
  baseline + N×32-byte path) — `psbt.h:732-736`. Value MUST be
  non-empty (script + 1 leaf-version byte).
- `PSBT_IN_TAP_BIP32_DERIVATION` (0x16) key MUST be 33 bytes
  (1 + xonly) — `psbt.h:752-754`.
- `PSBT_IN_TAP_INTERNAL_KEY` (0x17) value MUST be 32 bytes.
- `PSBT_IN_TAP_MERKLE_ROOT` (0x18) value MUST be 32 bytes.

Ouroboros's `PSBTInput.from_kv` (`psbt.py:1150-1171`) silently
stores `val` (or skips with `len(key_data) == 64`) without enforcing
size. A malformed PSBT that lies about Taproot field sizes is
silently round-tripped — the failure surfaces only at script-witness
construction time as a script-execution failure, by which point the
signer may have already emitted a partial sig over a forged
sighash. **BUG-5 (P0-CVE-class)**.

**(F6) DER+sighash byte validation on PARTIAL_SIG missing.** Core
(`psbt.h:540-549`) enforces:
- signature MUST be non-empty;
- `CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG |
  SCRIPT_VERIFY_STRICTENC, nullptr)` MUST pass (BIP-66 strict DER
  + sighash byte sanity).
- key.size() MUST be `CPubKey::SIZE + 1` (66, uncompressed) or
  `CPubKey::COMPRESSED_SIZE + 1` (34, compressed).
- The pubkey MUST be `IsFullyValid()` (on-curve).

Ouroboros's `PSBTInput.from_kv` (`psbt.py:1112-1113`) stores raw bytes
under `partial_sigs[key_data] = val` with zero validation. A malformed
PSBT with junk signature bytes passes deserialize cleanly. **BUG-6
(P0-CVE-class)** — see also FIX-recommendation in BUG-block; this
is the highest-priority correctness fix in the wave because the
forged partial-sig propagates through combinepsbt to other parties.

**(F7) global_xpub uniqueness not enforced.** Core enforces
"Duplicate Key, global xpub already provided" (`psbt.h:1293-1295`)
by checking the deserialized `CExtPubKey` is not already in a
session-local `global_xpubs` set. Ouroboros stores
`psbt.global_xpubs[key_data] = KeyOriginInfo.deserialize(val)`
(`psbt.py:1563-1564`) — duplicates would be implicitly deduplicated
at the dict-write step but the duplicate-key error Core throws is
never raised. The wire-level duplicate-key check in
`_read_kv_pairs` (`psbt.py:588-589`) catches dict-level dupes for
the SAME byte-equal key, but two different valid xpub serializations
of the same logical xpub (same fingerprint, same path) would be
silently merged. Cosmetic — well-behaved PSBT writers don't do
this — but a strict-mode parser MUST reject. **BUG-7 (P2)**.

**(F8) BIP-370 locktime derivation entirely missing.** BIP-370 §5
specifies that when a v2 PSBT carries any input-level
`PSBT_IN_REQUIRED_TIME_LOCKTIME` (0x11) or
`PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` (0x12), the actual
transaction-level `nLockTime` is the **maximum of the height
locktimes** (if any height locktimes are present) OR the
**maximum of the time locktimes** (if no input requires height
locktime, only time). If both are present and incompatible, the
signing combiner MUST reject the PSBT. Only when NO input requires
either does the `PSBT_GLOBAL_FALLBACK_LOCKTIME` (0x03) win.

Ouroboros's `_reconstruct_tx_from_v2` (`psbt.py:1615-1643`)
unconditionally uses `self.fallback_locktime or 0` as the
transaction locktime, ignoring every `required_*_locktime` per-input
constraint. A v2 PSBT that requires `nLockTime >= 750_000` (some
CLTV-locked HTLC) would be reconstructed with locktime=0 →
the extracted transaction would be invalid against the CLTV in the
input's script. **BUG-8 (P1)**.

**(F9) PSBT v2 finalization writes wrong global fields.** BIP-370
§4 says PSBT v2 finalize/extract MUST collapse the per-input
PSBT v2 fields (PREVIOUS_TXID, OUTPUT_INDEX, SEQUENCE) and per-output
fields (AMOUNT, SCRIPT) back into the unsigned-tx vin/vout for
extract. Ouroboros's `extract_transaction` (`psbt.py:2093-2121`)
uses `self.tx` which was reconstructed at deserialize time —
fine for v2 PSBTs that arrived with PREVIOUS_TXID + OUTPUT_INDEX
set, but the txid recomputation in `extract_transaction`
(`psbt.py:2118-2119`) doesn't account for the v2 case where the
`tx` was synthesized with a placeholder txid `b"\x00" * 32`
(`_reconstruct_tx_from_v2:1638`) — the recompute uses
`tx.serialize()` which the placeholder doesn't bind, so the
recompute IS correct, but the round-trip from
`serialize`→`from_base64`→`finalize`→`extract` for v2 emits a
transaction whose txid was never validated against any external
contract. **BUG-9 (P2)** — cosmetic but worth pinning.

**(F10) MuSig2 (BIP-327) pubnonce + partial-sig fields absent.**
Core's `psbt.h:56-58` defines:
- `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`
- `PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`
- `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c`

Ouroboros's `PSBTInputType` (`psbt.py:473-475`) defines these
constants — but `PSBTInput` (`psbt.py:962-1212`) has NO storage
fields for `m_musig2_participants` / `m_musig2_pubnonces` /
`m_musig2_partial_sigs` (Core's `psbt.h:285-289`). Wire-level
parsing falls through to the `unknown` bucket. A MuSig2-enabled
PSBT (BIP-327 v1) passes through ouroboros without parsing the
MuSig2 fields — combine and finalize cannot use them. Only the
PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08) on the **output**
side is parsed (`psbt.py:1320-1325`). **BUG-10 (P1)**.

**(F11) Empty separator-only PSBT (Core regression test)
silently passes.** A pathological PSBT with only the magic +
empty global map + empty per-input maps (≥0 inputs) + empty
per-output maps would still need to satisfy
`inputs.size() == tx->vin.size()` (Core `psbt.h:1382-1384`).
Ouroboros's deserialize falls through `range(n_inputs)` with
`n_inputs = len(psbt.tx.inputs)` so the loop iteration count
matches the tx, but the data-side `_read_kv_pairs` will raise
"PSBT truncated: missing trailing 0x00 separator" when the stream
runs out — which is actually correct behavior. **No BUG here**;
flag as PRESENT for G16.

**(F12) PSBT max-size limit equals Core's
MAX_FILE_SIZE_PSBT.** Core: 100,000,000 bytes (`psbt.h:77`).
Ouroboros: `MAX_PSBT_SIZE = 100_000_000` (`psbt.py:424`) — match.
PRESENT for G17.

**(F13) PSBT magic bytes pinned correctly.** Core: `psbt.h:28`
`{'p', 's', 'b', 't', 0xff}`. Ouroboros: `psbt.py:43`
`b"psbt\xff"` — match. PRESENT for G18.

**(F14) finalize() ladder coverage.** Ouroboros has 7 ordered
finalization branches (`psbt.py:1680-1700`): Taproot key-path,
Taproot script-path, P2WPKH, P2SH-P2WPKH, P2SH-P2WSH,
P2SH-multisig (legacy), P2PKH, P2WSH. Bare-multisig (non-segwit,
non-P2SH-wrapped) is the obvious gap — but Core's standard-policy
no longer allows bare multisig output broadcast, so the gap is
P2; recommend documenting. **BUG-11 (P2)**.

**(F15) RemoveUnnecessaryTransactions equivalent missing.**
Core's `RemoveUnnecessaryTransactions` (`psbt.cpp:514-549`)
drops `non_witness_utxo` fields from inputs once we know every
input is segwit v1 (Taproot) AND the sighash is not
SIGHASH_ANYONECANPAY. This trims wire size significantly for
multi-input Taproot PSBTs. Ouroboros has no equivalent —
non_witness_utxo is never dropped, so a PSBT pre-W127-fix wire
size carries the full prev-tx blob even on all-Taproot signing.
Cosmetic (no correctness issue) — but for the BIP-78 PayJoin
flow which round-trips a PSBT through a public coordinator,
wire size matters. **BUG-12 (P2)**.

**(F16) PSBTInputSignedAndVerified equivalent missing.**
Core's `PSBTInputSigned` (`psbt.cpp:320-323`) returns
"is finalized" — fine, ouroboros's `is_finalized` matches. But
Core's `PSBTInputSignedAndVerified` (`psbt.cpp:325-352`) does
the second-tier check: VerifyScript over
`(final_script_sig, utxo.scriptPubKey, final_script_witness)` with
STANDARD_SCRIPT_VERIFY_FLAGS. Without this, a finalized PSBT
that has structurally complete script_sig / witness but invalid
signatures passes ouroboros's "is_finalized" and is happily
extracted — the bad transaction then fails at broadcast time
(downstream node rejects). Adding script-verify here would catch
combiner-side forgeries early. **BUG-13 (P1)**.

**(F17) PSBT v0 global proprietary fields absent.** Core
(`psbt.h:34`) defines `PSBT_GLOBAL_PROPRIETARY = 0xFC`. Ouroboros
defines the enum (`psbt.py:440`) but the **input/output sides
have NO storage** for proprietary records — they fall through to
the `unknown` bucket which has different semantics (no
`PSBTProprietary` typed parsing of identifier/subtype/value).
Core's `psbt.h:838-851` parses identifier-prefixed proprietary
keys; ouroboros stores them as opaque bytes. Cosmetic but
trips byte-identity round-trip when the proprietary key was
emitted in a non-canonical order. **BUG-14 (P2)**.

**(F18) FALLBACK_LOCKTIME serialized as I (4-byte LE) — Core
expects compact-size-prefixed value.** This is actually correct:
Core's `psbt.h:1196` uses `SerializeToVector(s, *m_version)` for
the GLOBAL_VERSION (uint32, with length prefix), which gives
`04 <4 LE bytes>`. Ouroboros (`psbt.py:1493`) emits
`struct.pack("<I", self.version)` for the value bytes (4 LE) —
correct. FALLBACK_LOCKTIME (`psbt.py:1497`) is also 4 LE — correct.
PRESENT for G19 (no bug).

**(F19) BIP32 derivation: ouroboros emits length-prefixed value;
Core also does** (`psbt.h:184-188` — SerializeHDKeypath wraps in
CompactSize). Ouroboros `KeyOriginInfo.serialize` (`psbt.py:920-924`)
returns the fingerprint+path bytes WITHOUT a length prefix; the
prefix is added at kv-pair emit time
(`psbt.py:656-661` — `_write_compact_size(len(val))`). So the
wire format ends up identical. PRESENT for G20.

**(F20) Sequence handling on v2 reconstruct ignores
`required_*_locktime`.** Reuse of `psbt_in.sequence or 0xFFFFFFFF`
(`psbt.py:1625`) is correct in isolation but does NOT enforce the
BIP-65 (CLTV) requirement that any input requiring time/height
locktime has `sequence < 0xFFFFFFFE`. A v2 PSBT can specify
`REQUIRED_HEIGHT_LOCKTIME` AND `sequence = 0xFFFFFFFF` simultaneously
— ouroboros accepts both. The extracted transaction's CLTV check
would fail at script evaluation. **BUG-15 (P1)**.

Gate matrix
-----------

| Gate | Category                              | Status   | Bug    | Sev |
|------|---------------------------------------|----------|--------|-----|
| G1   | PSBT magic 'psbt\\xff' constant       | PRESENT  | —      | —   |
| G2   | PSBT_GLOBAL_UNSIGNED_TX (v0)          | PRESENT  | —      | —   |
| G3   | PSBT_GLOBAL_XPUB serialize/deserialize| PRESENT  | BUG-7  | P2  |
| G4   | PSBT_GLOBAL_VERSION (v2)              | PARTIAL  | BUG-1  | P0-CDIV |
| G5   | PSBT_GLOBAL_TX_VERSION (v2)           | PRESENT  | —      | —   |
| G6   | PSBT_GLOBAL_FALLBACK_LOCKTIME (v2)    | PARTIAL  | BUG-8  | P1  |
| G7   | PSBT_GLOBAL_INPUT_COUNT (v2)          | PARTIAL  | BUG-3  | P1  |
| G8   | PSBT_GLOBAL_OUTPUT_COUNT (v2)         | PARTIAL  | BUG-3  | P1  |
| G9   | PSBT_GLOBAL_TX_MODIFIABLE (v2)        | PRESENT  | —      | —   |
| G10  | PSBT_GLOBAL_PROPRIETARY               | MISSING  | BUG-14 | P2  |
| G11  | PSBT_IN_NON_WITNESS_UTXO sha256d chk  | MISSING  | BUG-4  | P0-CVE |
| G12  | PSBT_IN_WITNESS_UTXO round-trip       | PRESENT  | —      | —   |
| G13  | PSBT_IN_PARTIAL_SIG DER+sighash valid | MISSING  | BUG-6  | P0-CVE |
| G14  | PSBT_IN_PARTIAL_SIG pubkey valid+size | MISSING  | BUG-6  | P0-CVE |
| G15  | PSBT_IN_SIGHASH_TYPE deserialize      | PRESENT  | —      | —   |
| G16  | Per-map separator (0x00) trailing chk | PRESENT  | —      | —   |
| G17  | MAX_FILE_SIZE_PSBT = 100 MB           | PRESENT  | —      | —   |
| G18  | Unsigned-tx empty scriptSig invariant | MISSING  | BUG-2  | P0-CVE |
| G19  | Inputs/outputs count = vin/vout size  | MISSING  | BUG-3  | P1  |
| G20  | PSBT_IN_TAP_* size validation         | MISSING  | BUG-5  | P0-CVE |
| G21  | PSBT_IN_TAP_KEY_SIG size 64/65 byte   | MISSING  | BUG-5  | P0-CVE |
| G22  | PSBT_IN_TAP_LEAF_SCRIPT cb size %32   | MISSING  | BUG-5  | P0-CVE |
| G23  | BIP-370 locktime derivation rule      | MISSING  | BUG-8  | P1    |
| G24  | BIP-370 nSequence vs CLTV constraint  | MISSING  | BUG-15 | P1    |
| G25  | BIP-327 MuSig2 input storage fields   | MISSING  | BUG-10 | P1    |
| G26  | combinepsbt byte-identity (W46 sort)  | PRESENT  | —      | —   |
| G27  | RemoveUnnecessaryTransactions equiv   | MISSING  | BUG-12 | P2    |
| G28  | PSBTInputSignedAndVerified script-ver | MISSING  | BUG-13 | P1    |
| G29  | finalize() bare-multisig branch       | MISSING  | BUG-11 | P2    |
| G30  | Two-pipeline guard (psbt Python-only) | PRESENT  | —      | —   |

Bug inventory (24 bugs / 30 gates)
-----------------------------------

Severity legend: P0-CDIV=consensus-or-cross-impl-divergence;
P0-CVE-class=signer trust boundary the BIP-174 spec mandates;
P1=correctness or operator-functional; P2=cosmetic.

| Bug    | Gate    | Sev          | Description |
|--------|---------|--------------|-------------|
| BUG-1  | G4      | P0-CDIV      | `PSBT_HIGHEST_VERSION = 2` (`psbt.py:502`) diverges from Core's `PSBT_HIGHEST_VERSION = 0` (`psbt.h:80`). Ouroboros accepts v2 PSBTs that Core would reject with "Unsupported version number" (`psbt.h:1322`). A v2 PSBT produced by ouroboros's wallet cannot be combined or extracted by Core. This is a deliberate BIP-370 implementation, but cross-impl operators must be aware that ouroboros↔Core PSBT exchange is asymmetric. Fix: either (a) document the divergence as a deliberate BIP-370 implementation in `docs/CONSENSUS_DIVERGENCES.md`, or (b) gate v2 acceptance behind an `accept_psbt_v2=true` config flag (default false, matching Core). |
| BUG-2  | G18     | P0-CVE-class | `PSBT.deserialize` (`psbt.py:1554-1555`) does not validate that the unsigned tx contained in `PSBT_GLOBAL_UNSIGNED_TX` has empty scriptSig + empty witness on every input. Core (`psbt.h:1274-1278`) throws "Unsigned tx does not have empty scriptSigs and scriptWitnesses." A malformed PSBT smuggling signatures via the global tx bypasses every downstream consumer's "this PSBT is unsigned" assumption. Fix: after `_deserialize_tx(global_kv.pop(unsigned_tx_key))`, iterate `psbt.tx.inputs` and raise `ValueError` if any input has non-empty `script_sig` or non-None `witness`. |
| BUG-3  | G7,G8,G19 | P1         | `PSBT.deserialize` (`psbt.py:1591-1598`) doesn't validate input/output map count against tx vin/vout (Core `psbt.h:1382-1384,1394-1396`). If the PSBT carries fewer per-input maps than `len(tx.inputs)`, the trailing reads fail with a stream-truncation error (no useful diagnostic); if it carries more (impossible for v0, possible for v2 with corrupted INPUT_COUNT), they're silently ignored. For v2 also validate `input_count == len(parsed input maps)`. |
| BUG-4  | G11     | P0-CVE-class | Non-witness-UTXO sha256d invariant (Core `psbt.h:1371-1378`) NOT enforced at PSBT.deserialize. Currently enforced only inside `rpc_walletprocesspsbt` (W41 fix). Every other PSBT consumer (analyzepsbt, decodepsbt, combinepsbt, finalizepsbt) trusts the (potentially forged) `outputs[prev_vout]` of the non_witness_utxo. CVE-2020-14199 amount-oracle class. Fix: in `PSBT.deserialize` after parsing each `PSBTInput`, verify `sha256d(non_witness_utxo) == tx.inputs[i].prev_txid` and `prev_vout < len(non_witness_utxo.outputs)`, raising on mismatch. |
| BUG-5  | G20,G21,G22 | P0-CVE-class | PSBT_IN_TAP_* size validation entirely absent (`psbt.py:1150-1171`). Specifically (Core `psbt.h:691-794`): TAP_KEY_SIG MUST be 64 or 65 bytes; TAP_SCRIPT_SIG value 64-65 bytes + key MUST be exactly 65 bytes; TAP_LEAF_SCRIPT key MUST be ≥34 bytes AND `(key.size()-2) % 32 == 0` AND value ≥1 byte; TAP_BIP32_DERIVATION key MUST be 33 bytes; TAP_INTERNAL_KEY value MUST be 32 bytes; TAP_MERKLE_ROOT value MUST be 32 bytes. Without these, a forged PSBT slips through deserialize; downstream signer commits to a forged sighash. |
| BUG-6  | G13,G14 | P0-CVE-class | PSBT_IN_PARTIAL_SIG (`psbt.py:1112-1113`) takes raw bytes with NO validation. Core (`psbt.h:524-550`) enforces: signature non-empty + `CheckSignatureEncoding(sig, DERSIG\|STRICTENC, nullptr)` (BIP-66 strict DER), pubkey size 33/65, pubkey on-curve (`IsFullyValid()`). A malformed PSBT with a junk signature passes deserialize and propagates through `combinepsbt` to other parties (who in turn pass it to their signer, which may emit a sig over a forged sighash). This is the **highest-priority** correctness fix in the wave. |
| BUG-7  | G3      | P2           | global_xpub uniqueness not enforced. Core (`psbt.h:1293-1295`) throws "Duplicate key, global xpub already provided" on duplicate `CExtPubKey`. Ouroboros stores `psbt.global_xpubs[key_data] = ...` so byte-equal keys dedupe but two valid encodings of the same logical xpub silently merge. Cosmetic — well-behaved writers don't do this — but strict-mode Core rejects. |
| BUG-8  | G6,G23  | P1           | BIP-370 locktime derivation rule entirely missing. `_reconstruct_tx_from_v2` (`psbt.py:1615-1643`) uses `self.fallback_locktime or 0` unconditionally, ignoring every input's `required_time_locktime` / `required_height_locktime` (BIP-370 §5). The extracted tx may fail script-level CLTV. Fix: compute derived locktime per BIP-370 §5; if all inputs require height locktime, take max; if all time, take max time; if both AND incompatible, reject; otherwise use fallback. |
| BUG-9  | G6      | P2           | v2 PSBT `extract_transaction` recomputes txid from `tx.serialize()` (`psbt.py:2118-2119`) where `tx.txid` was synthesized with `b"\x00"*32` placeholder at `_reconstruct_tx_from_v2:1638`. Recompute is correct but the placeholder→recompute path is brittle: any future code path that reads `self.tx.txid` between deserialize and extract sees the placeholder. Defensive fix: compute the real txid inside `_reconstruct_tx_from_v2`. |
| BUG-10 | G25     | P1           | BIP-327 MuSig2 input storage fields absent. `PSBTInputType` defines MUSIG2_PARTICIPANT_PUBKEYS (0x1a), MUSIG2_PUB_NONCE (0x1b), MUSIG2_PARTIAL_SIG (0x1c) but `PSBTInput` has no storage. Wire-level parsing falls through to `unknown[key] = val`. Combine and finalize cannot use MuSig2 PSBTs. The PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08) on the OUTPUT side is parsed correctly (`psbt.py:1320-1325`); the input-side asymmetry is the gap. |
| BUG-11 | G29     | P2           | `finalize()` ladder (`psbt.py:1680-1700`) lacks a bare-multisig (non-P2SH-wrapped, non-segwit) branch. A bare `OP_M <pks> OP_N OP_CHECKMULTISIG` scriptPubKey is no longer standard-policy in Core (only allowed for testnet/regtest), so the gap is P2. Adding the branch would mirror `_try_finalize_p2sh_multisig` (`psbt.py:1877-1962`) without the redeemScript push. |
| BUG-12 | G27     | P2           | `RemoveUnnecessaryTransactions` equivalent missing. Core (`psbt.cpp:514-549`) drops `non_witness_utxo` from inputs once every input is segwit v1 AND sighash != ANYONECANPAY. Saves significant wire size for multi-input Taproot PSBTs. Matters most for BIP-78 PayJoin coordinators. |
| BUG-13 | G28     | P1           | `PSBTInputSignedAndVerified` (Core `psbt.cpp:325-352`) equivalent missing. `is_finalized` (`psbt.py:1000-1002`) checks structural completeness only. A combiner-forged PSBT with structurally complete script_sig/witness but invalid signatures slips through ouroboros's finalize/extract; the bad transaction fails at broadcast. Adding `VerifyScript` (over a PrecomputedTransactionData) here would catch upstream forgeries before they propagate. |
| BUG-14 | G10     | P2           | PSBT_GLOBAL_PROPRIETARY parsing falls through to `unknown[key]` as opaque bytes. Core (`psbt.h:838-851`, `psbt.h:1327-1340`) parses `PSBTProprietary {identifier, subtype, key, value}` typed records, sorts by `key`, and emits in canonical order. Ouroboros's `unknown` bucket has different semantics — round-trip can break canonical ordering when a proprietary record interleaves with other unknown keys. |
| BUG-15 | G24     | P1           | BIP-370 nSequence vs CLTV constraint not enforced. A v2 PSBT with `REQUIRED_*_LOCKTIME` set AND `sequence = 0xFFFFFFFF` (final sequence) on the same input is INVALID per BIP-65 (CLTV requires `sequence < 0xFFFFFFFE`). Ouroboros accepts both silently; the extracted tx fails at script verification. Fix: in `_reconstruct_tx_from_v2`, when any required locktime is set on an input, ensure that input's sequence is `< 0xFFFFFFFE`. |
| BUG-16 | (cross) | P2           | `_input_map_sort_key` (`psbt.py:594-633`) implements W46's HASH160-canonical sort for PARTIAL_SIG but ouroboros's `PSBTOutput` map serialize does NOT apply an output-side sort. Core `psbt.h:910` walks `std::map<CPubKey, KeyOriginInfo>` (lex-sorted by pubkey) for BIP32_DERIVATION which dict-insertion order happens to match. **But** PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08) emission (`psbt.py:not-emitted-yet`) would need similar canonicalization. Currently MuSig2 output fields parse but don't emit (`musig2_participants` is read into `from_kv` at 1320-1325 but never serialized back in `to_kv:1242-1280`). |
| BUG-17 | (G25)   | P1           | MuSig2 output fields parse-only — round-trip drops MuSig2 data. `PSBTOutput.from_kv` (`psbt.py:1320-1325`) reads `MUSIG2_PARTICIPANT_PUBKEYS` into `musig2_participants` but `PSBTOutput.to_kv` (`psbt.py:1242-1280`) does NOT emit them. A round-trip through `deserialize → serialize` silently loses the MuSig2 participants on the output side. Combined with BUG-10, ouroboros cannot round-trip any MuSig2-bearing PSBT. |
| BUG-18 | (G16)   | P1           | `_read_kv_pairs` (`psbt.py:566-591`) tolerates per-map `Duplicate key` only at the WIRE level (dict-based dedupe collision). Core's per-input `PSBTInput::Unserialize` (`psbt.h:507-509`) maintains a `key_lookup` set that throws "Duplicate Key, input non-witness utxo already provided" with a TYPED message per repeated single-byte type. Ouroboros falls back on dict-write semantics — a repeated KEY-byte-equal entry IS caught at line 589, but Core's typed messaging is missing. Operator diagnostics for malformed PSBTs are poor. Cosmetic-ish — but matters for the BIP-78 PayJoin "original-psbt-rejected" reason-string path which expects Core-compatible error strings. |
| BUG-19 | (G6)    | P1           | Reading `fallback_locktime` is unsafe-on-corruption: `struct.unpack("<I", val)` (`psbt.py:1568`) assumes `len(val) == 4`. A malformed PSBT with a 2-byte FALLBACK_LOCKTIME value crashes with `struct.error` instead of raising a clean PSBT-format error. Same issue for TX_VERSION (`psbt.py:1566`), INPUT_COUNT (uses _read_compact_size which IS safe), OUTPUT_COUNT (safe). Defensive fix: wrap each unpack with a length precondition + raise `ValueError("Invalid PSBT_GLOBAL_FALLBACK_LOCKTIME value length")`. |
| BUG-20 | (G15)   | P1           | PSBT_IN_SIGHASH_TYPE value MUST be 4 bytes (Core `psbt.h:558-560` reads `int sighash; UnserializeFromVector(s, sighash);` which is a length-prefixed 4-byte int). Ouroboros `struct.unpack("<I", val)` (`psbt.py:1115`) silently truncates or crashes on non-4-byte values. Same defensive-fix as BUG-19. |
| BUG-21 | (G3)    | P2           | PSBT_GLOBAL_XPUB key MUST be `BIP32_EXTKEY_WITH_VERSION_SIZE + 1` = 79 bytes (Core `psbt.h:1284-1286`: 1 type byte + 78-byte serialized CExtPubKey). Ouroboros (`psbt.py:1563-1564`) accepts any key length, stuffing the bytes into `global_xpubs[key_data]` regardless. A malformed PSBT with a short xpub key passes deserialize. Cosmetic but Core-divergent. |
| BUG-22 | (G3)    | P2           | PSBT_GLOBAL_XPUB CExtPubKey validity check missing. Core (`psbt.h:1288-1292`) calls `xpub.DecodeWithVersion(...)` + `if (!xpub.pubkey.IsFullyValid())` raise. Ouroboros stores any 78 bytes as an xpub. Pairs with BUG-21. |
| BUG-23 | (G2)    | P2           | TAP_TREE on output side (`psbt.py:1304-1313`) parses depth/leaf_ver as raw bytes but does NOT validate `0 <= depth <= 128` (Core's `taproot.h` Merkle-tree-depth limit). Same for leaf_ver (must be `0xc0` or one of a tiny set per BIP-341). Defensive but matters for malformed-PSBT fuzz. |
| BUG-24 | (G1)    | P2           | `PSBT.deserialize` doesn't enforce "extra data after PSBT" check (Core `psbt.cpp:622-625` raises if `!ss_data.empty()` after deserialize). Ouroboros reads as far as needed and ignores trailing bytes (`psbt.py:1530-1602`). A PSBT with garbage appended deserializes cleanly. Cosmetic but Core-divergent. |

P0 + P0-CVE-class summary
--------------------------

Five of the 24 bugs are P0-grade. **All except BUG-1 are wire-level
deserialize-time correctness gaps that signed-PSBT trust assumes
have been validated.** The CVE-2020-14199 amount-oracle class
(BUG-4) is the most cited PSBT signing trap; BUG-2 (unsigned-tx
not actually unsigned) is the second-most; BUG-6 (DER+sighash
on partial_sig) is third. BUG-5 (Taproot field size) is a broader
class of "signer commits to a forged sighash" bug.

- **BUG-1** (G4): v2 PSBT acceptance diverges from Core (P0-CDIV).
- **BUG-2** (G18): unsigned-tx empty-scriptSig invariant missing
  at deserialize (P0-CVE-class).
- **BUG-4** (G11): non_witness_utxo sha256d invariant missing at
  deserialize (P0-CVE-class — CVE-2020-14199 class).
- **BUG-5** (G20-G22): Taproot field sizes not validated at
  deserialize (P0-CVE-class).
- **BUG-6** (G13-G14): partial_sig DER + sighash byte + pubkey
  validation missing at deserialize (P0-CVE-class).

These should all be tractable as a single follow-up fix wave:
**FIX-XX (P0-CVE-class) "psbt deserialize hardening"** —
single-impl scope, ~5 invariants added in `PSBT.deserialize` and
`PSBTInput.from_kv`. Estimated ~1.5 hours.

Lower priorities (P1 = 11 bugs)
-------------------------------

The biggest functional cluster is around BIP-370 v2 (BUG-3, BUG-8,
BUG-15) — count cross-checks, locktime derivation, nSequence/CLTV
constraint. These would make ouroboros's v2-PSBT semantics actually
correct (right now v2 deserializes but mis-reconstructs the
extracted tx).

BIP-327 MuSig2 (BUG-10, BUG-17) is the next-biggest cluster —
input-side storage absent, output-side parse-only. Until both are
closed, ouroboros cannot round-trip any MuSig2 PSBT, blocking
participation in any MuSig2-based multisig scheme.

`PSBTInputSignedAndVerified` (BUG-13) — script-verify on
finalize — is the cheapest P1 win: one helper that calls into the
existing `ouroboros.script` interpreter over each finalized input.

Stable Core API gaps:
- `RemoveUnnecessaryTransactions` (BUG-12, P2 — wire-size only).
- Bare-multisig finalize (BUG-11, P2 — non-standard policy).
- Defensive unpack length checks (BUG-19, BUG-20 — crash hardening).
- xpub key length + validity checks (BUG-21, BUG-22).
- Tap-tree depth/leaf_ver validation (BUG-23).
- Extra-data-after-PSBT check (BUG-24).

P2 cluster (8 bugs)
-------------------

Mostly defensive validation + canonical-order details. BUG-7
(xpub uniqueness), BUG-9 (v2 extract-txid placeholder), BUG-11
(bare-multisig finalize), BUG-12 (RemoveUnnecessaryTransactions),
BUG-14 (proprietary canonical order), BUG-16 (MuSig2 emit-side
sort), BUG-21/22/23/24 (defensive parser hardening). None
consensus-affecting; some affect operator tools.

Closure plan (recommended sequence)
-----------------------------------

Three ordered closure recommendations:

**Phase A — P0-CVE-class hardening** (closes BUG-2/4/5/6):
1. In `PSBT.deserialize` after parsing the global unsigned tx:
   iterate `psbt.tx.inputs` and raise `ValueError` if any input
   has `script_sig != b""` or `witness is not None`.
2. After each `PSBTInput` is parsed: if `non_witness_utxo is not
   None`, verify `sha256d(non_witness_utxo) == prev_txid` and
   `prev_vout < len(decoded_prev_tx.outputs)`.
3. In `PSBTInput.from_kv`, add length precondition + DER strict
   check on `PARTIAL_SIG`; validate pubkey size (33/65) and
   on-curve via `coincurve.PublicKey.from_secret(...)` validity.
4. In `PSBTInput.from_kv`, add length preconditions on every
   TAP_* field per Core's `psbt.h:691-794` rules.
5. Add test corpus from Core's `src/test/data/rpc_psbt.json`
   (intentionally-malformed PSBTs) — every one should now raise.

Estimated: single-impl, ~1.5 hours.

**Phase B — BIP-370 v2 + BIP-327 MuSig2 correctness**
(closes BUG-3/8/10/15/17):
6. Add `m_musig2_participants`, `m_musig2_pubnonces`,
   `m_musig2_partial_sigs` to PSBTInput. Parse the three input-side
   types in `from_kv` per Core `psbt.h:791-836` (key-size rules,
   value-size rules, DeserializeMuSig2ParticipantDataIdentifier).
   Emit symmetrically in `to_kv`.
7. Add v2 input/output count cross-check at deserialize.
8. Implement BIP-370 locktime derivation in `_reconstruct_tx_from_v2`.
9. Enforce BIP-370 nSequence vs CLTV-required-locktime constraint.
10. Emit MuSig2 output participants from `PSBTOutput.to_kv`.

Estimated: single-impl, ~3 hours.

**Phase C — Defensive parser hardening + cosmetics**
(closes BUG-1/7/9/11/12/13/14/19/20/21/22/23/24):
11. Either document v2 acceptance as deliberate BIP-370 or gate
    behind `accept_psbt_v2` config flag.
12. Add `PSBTInputSignedAndVerified` helper that does VerifyScript
    over finalized inputs (single source of truth for "this PSBT
    is really signed").
13. Add `_remove_unnecessary_transactions` helper for wire-size.
14. Bare-multisig finalize branch (P2).
15. Length preconditions on every `struct.unpack` site
    (BUG-19, BUG-20).
16. Extra-data-after-PSBT check (BUG-24).

Estimated: single-impl, ~2 hours.

Total closure surface
---------------------

3 phases × ~6.5 hours = ~6.5 hours single-impl fix-wave work to
close ALL 24 bugs. P0-CVE-class subset (Phase A, BUG-2/4/5/6) is
the highest-leverage and should be sequenced first.

Test corpus
-----------

The discovery-side test file (`tests/test_w137_psbt.py`) installs
30 gates with xfail markers for every MISSING gate. The xfails
flip to XPASS the moment any of the above closure phases land,
giving free regression detection. PRESENT gates are plain asserts
that pin Core-parity wiring (e.g. `MAX_PSBT_SIZE = 100_000_000`,
`PSBT_MAGIC = b"psbt\\xff"`).

Cross-impl cross-reference
--------------------------

This audit covers ouroboros only. Cross-impl PSBT findings are
recorded in W118 wallet fleet audit (104 bugs / 10 impls,
2026-05-16). The single-impl deep-dive here is the deepest follow-up
for ouroboros's slice of W118; expect parallel discovery waves
for rustoshi/blockbrew/clearbit/nimrod/camlcoin/beamchain/hotbuns/
lunarblock/haskoin to surface analogous PSBT gaps in those impls
(many will share BUG-2/4/5/6 since the CVE-2020-14199 class is a
trap every PSBT implementation has fallen into at some point in
its history).
