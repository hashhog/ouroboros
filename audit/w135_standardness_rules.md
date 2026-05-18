W135 — Standardness rules (IsStandardTx) audit (ouroboros)
==========================================================

Date: 2026-05-17
Impl: ouroboros (Python policy pipeline ONLY — standardness is policy,
      not consensus; the Rust ferrous-utils pipeline has NO IsStandard
      or MAX_STANDARD constants — confirmed clean.)
Wave: W135 Standardness rules — IsStandardTx, IsStandard, ValidateInputsStandardness,
      IsWitnessStandard, TxoutType Solver, and the configurable policy switches
      that surround them (-permitbaremultisig, -datacarrier, -datacarriersize,
      -dustrelayfee, -bytespersigop, -acceptnonstdtxn).

Reference:
  - `bitcoin-core/src/policy/policy.{h,cpp}` (IsStandardTx, IsStandard,
    ValidateInputsStandardness, IsWitnessStandard, GetDustThreshold,
    IsDust, GetDust, GetVirtualTransactionSize, GetSigOpsAdjustedWeight)
  - `bitcoin-core/src/script/solver.{h,cpp}` (TxoutType enum, Solver,
    MatchPayToPubkey, MatchPayToPubkeyHash, MatchMultisig, MatchMultiA,
    GetScriptForRawPubKey)
  - `bitcoin-core/src/policy/truc_policy.{h,cpp}` (SingleTRUCChecks,
    PackageTRUCChecks, TRUC_VERSION=3, TRUC_MAX_VSIZE, TRUC_CHILD_MAX_VSIZE,
    TRUC_ANCESTOR_LIMIT, TRUC_DESCENDANT_LIMIT)
  - `bitcoin-core/src/consensus/tx_check.{h,cpp}` (CheckTransaction —
    consensus floor that IsStandardTx layers on top of)
  - `bitcoin-core/src/node/mempool_args.cpp:85-105` (operator policy
    flags → mempool_opts plumbing)
  - `bitcoin-core/src/init.cpp:677-695` (operator policy CLI args)

Status: 30 gates audited — **PRESENT 9 / PARTIAL 5 / MISSING 16.**
**15 BUGS** (3 P0-CDIV / 8 P1 / 4 P2). 1 bug (BUG-11) closed at audit time.

Relationship to prior audits
----------------------------

- **W120** (cluster mempool linearization, 2026-05-14) audited the
  feerate-diagram / RBF / cluster eviction surface that USES IsStandardTx
  as the gate at the front door. W120 BUG-7 (validateRbfDiagram) was
  closed by FIX-79. W135 is the audit of the front-door gate itself.
- **W125** (RPC error parity, 2026-05-15) audited the rpc-level error
  string mapping (`sendrawtransaction` returning `-26` "non-mandatory-
  script-verify-flag"). W135 BUG-7 here (Core debug-string parity in
  `_is_standard_tx`) is the upstream half — currently the Python
  pipeline emits diagnostic English, then `_map_mempool_rejection_reason`
  in rpc.py:2542-2620 has to substring-match its way back to Core's
  short codes. W125 noted this as a multi-wave gap.
- **W129** (coin selection, 2026-05-16) audited the wallet-side that
  CREATES standard outputs. W135 audits the mempool-side that ACCEPTS
  them. Cross-impl: a wallet that creates non-standard outputs (e.g.
  4-of-7 bare multisig) would get past W129 + be rejected at W135.
- **W130** (BIP-125 feebumper Rule 3, 2026-05-16) audited the
  replacement-feerate gate. W135 is upstream of Rule 3 — every
  replacement candidate still must pass IsStandardTx first.
- **W132** (BIP-68/112/113 nSequence/CSV/MTP, 2026-05-17) audited
  sequence-locks. W135 covers the SIBLING gate
  `STANDARD_LOCKTIME_VERIFY_FLAGS` (policy.h:138) which is the
  policy-flag set used in IsStandardTx pre-checks. No direct overlap.
- **W133** (index databases, 2026-05-17) is structurally unrelated;
  noted only because W133 also explicitly skipped any topic that ferrous-
  utils does not touch — same scoping principle applies here.

Two-pipeline guard
------------------

Standardness is **policy-only, Python-side only.** Confirmed via:

```
$ grep -rn "IsStandard\|is_standard\|MAX_STANDARD\|TRUC_VERSION" \
       ferrous-utils/
  → 0 production matches
$ grep -rn "permit_bare_multisig\|datacarrier\|dust_relay" \
       ferrous-utils/
  → 0 matches
$ grep -rn "TxoutType\|GetDustThreshold\|Solver(" \
       ferrous-utils/
  → 0 matches
```

The Rust pipeline writes blocks atomically + indexes them; the Python
pipeline owns mempool acceptance, which is where standardness lives.
Crossing this boundary would be a regression: if standardness logic
landed in ferrous-utils it would either (a) duplicate Python policy,
or (b) require the Rust validator to know about user-configurable
flags (-permitbaremultisig etc.) which would couple consensus to
policy.

**Two-pipeline guard EXTENDED.** Test
`test_w135_g30_two_pipeline_standardness_only_in_python` codifies:
- `ferrous-utils/sync/src/**/*.rs` contains NO `IsStandard*` identifier
  and NO `MAX_STANDARD_TX_*` constant — REQUIRED;
- Standardness constants (MAX_STANDARD_TX_WEIGHT, MAX_OP_RETURN_RELAY,
  etc.) live in `src/ouroboros/mempool.py` ONLY;
- Future regressions (e.g. moving IsStandardTx into a Rust validator
  pass) trip this guard.

This extends the guard set W76 + W120 + W122 + W125 + W128 + W129 +
W130 + W133 → now W135. Eighth dedicated guard. This guard explicitly
covers the **policy boundary** (standardness is policy, not consensus)
where prior guards (W122 BIP-158 codec, W128 AddrMan, W130 feebumper)
covered functional-area boundaries.

Top-level architectural findings
--------------------------------

**(F1) No operator-configurable policy flags.** Core exposes 6 CLI
flags that toggle IsStandardTx behavior: `-permitbaremultisig`,
`-datacarrier`, `-datacarriersize`, `-dustrelayfee`, `-bytespersigop`,
`-acceptnonstdtxn`. ouroboros's `_is_standard_tx()` hard-codes all
constants (MAX_OP_RETURN_RELAY=100_000, datacarrier always on, bare
multisig always allowed, dust always at DUST_RELAY_TX_FEE=3000 sat/kvB).
The `MempoolManager.__init__` accepts `require_standard: bool = True`
but nothing else — no granular toggle.

Consequence: operators running ouroboros cannot disable bare multisig,
cannot tune datacarrier size, cannot set a custom dust relay feerate.
Importantly this also means **xchain testnets that require
-acceptnonstdtxn for their use case (regtest tooling) work, but the
6 finer-grained switches do not.** See BUG-1/2/3/4/5/8.

**(F2) Bare multisig acceptance is way too permissive.** Core's
`IsStandard(scriptPubKey)` for MULTISIG (`policy.cpp:87-95`):
calls `Solver` which calls `MatchMultisig` (`solver.cpp:85-105`)
which (a) parses opcodes correctly, (b) checks every pubkey is a
valid pushdata of canonical length, (c) verifies the required-sigs
opcode is OP_1..OP_16 minimal, (d) verifies total-pubkeys opcode is
OP_1..OP_16 minimal, (e) verifies the script ends with exactly
`OP_CHECKMULTISIG`. Then in `IsStandard` itself: rejects if `n > 3`
(only x-of-3 multisig is standard) or `m < 1` or `m > n`.

ouroboros's `_is_standard_output_type()` (mempool.py:865-868):

```python
# Bare multisig: OP_m ... OP_n OP_CHECKMULTISIG
# This is rare but standard. Check for OP_CHECKMULTISIG at end.
if len(script_pubkey) >= 3 and script_pubkey[-1] == 0xae:
    return True
```

**Single byte check.** Any script with length ≥ 3 ending in 0xae passes
— including `<garbage> OP_CHECKMULTISIG`, `4-of-7` multisig (Core
rejects n>3), `0-of-0` multisig (Core rejects m<1), and arbitrary
nonsense ending in 0xae. This is a **P0-CDIV bug**.

**BUG-2 is the largest single deviation in W135** because it is the
gate that decides whether a mempool tx with novel script structures
can propagate. A patient attacker could create a maliciously-shaped
output ending in 0xae and propagate it through ouroboros nodes; Core
would reject the same tx with reason="scriptpubkey".

**(F3) P2PK output type is not recognized.** Core's Solver
(`solver.cpp:190-193`) matches `<pubkey> OP_CHECKSIG` (33 or 65 bytes
of pubkey followed by OP_CHECKSIG) and returns `TxoutType::PUBKEY`,
which passes `IsStandard`. Legacy Satoshi-era mainnet coinbase outputs
are P2PK (the first ~150k blocks). Modern wallets occasionally create
P2PK outputs (e.g. some lightning channel closes, some custodial wallets).

ouroboros's `_is_standard_output_type()` has no P2PK pattern — txs
creating P2PK outputs are rejected as non-standard. This is **P0-CDIV
BUG-3** because cross-impl consensus-diff vs Core sees the divergence
the moment such a tx is submitted via `sendrawtransaction`. Mining
operators reorg-aware of pre-2010 coinbases would also see ouroboros
incorrectly reject a `getrawtransaction` of those tx ids.

**(F4) WITNESS_UNKNOWN is rejected at output side, not just input.**
Core's design: `IsStandard(scriptPubKey)` ACCEPTS WITNESS_UNKNOWN
(returns true). The rejection happens at **input side** via
`ValidateInputsStandardness` (`policy.cpp:234-240`) when someone tries
to SPEND a witness_unknown UTXO. This asymmetry exists deliberately so
that the network is forward-compatible: future witness versions can be
created (in soft fork) but cannot be spent under old node policy until
their semantics are defined.

ouroboros rejects WITNESS_UNKNOWN at output side AND input side
(`mempool.py:1064` + `mempool.py:1067-1076`). This is **P0-CDIV BUG-4**:
when a future witness version is deployed (e.g. simplicity in BIP-???),
ouroboros nodes will refuse to relay txs that CREATE such outputs even
though Core allows it.

**(F5) `-datacarrier=false` mode not implementable.** Core's logic
(`mempool_args.cpp:95-99`): if `-datacarrier=false`, `max_datacarrier_bytes`
is `std::nullopt`. Then in `IsStandardTx` (`policy.cpp:137`):
`max_datacarrier_bytes.value_or(0)` returns 0, so ANY OP_RETURN output
with size > 0 fails (`reason = "datacarrier"`).

ouroboros has no `-datacarrier` toggle. Even if it existed, the current
logic at mempool.py:1164-1170 hard-codes the comparison to
`MAX_OP_RETURN_RELAY` (=100_000); it cannot represent the "0 bytes
allowed" mode. BUG-1 + BUG-5 together.

**(F6) Error string parity diverges from Core.** `IsStandardTx` in
Core sets `reason` to short kebab strings (`"version"`, `"tx-size"`,
`"scriptsig-size"`, `"scriptsig-not-pushonly"`, `"scriptpubkey"`,
`"bare-multisig"`, `"datacarrier"`, `"dust"`). ouroboros emits
diagnostic English (`"Non-standard version: 5"`, `"Transaction weight
401234 exceeds 400000"`, etc.). The Core debug strings appear in code
**comments only.**

Downstream consumer `rpc._map_mempool_rejection_reason` (rpc.py:2542-2620)
then has to substring-match back to Core's short codes for the JSON-RPC
error code. This is **BUG-7 P1** (continuation of W125 RPC error parity).

Gate matrix
-----------

| Gate | Category                          | Status   | Bug    | Sev    |
|------|-----------------------------------|----------|--------|--------|
| G1   | Version range [1, 3] enforced     | PRESENT  | —      | —      |
| G2   | MAX_STANDARD_TX_WEIGHT enforced   | PRESENT  | —      | —      |
| G3   | MIN_STANDARD_TX_NONWITNESS_SIZE   | PRESENT  | —      | —      |
| G4   | scriptSig size ≤ 1650             | PRESENT  | —      | —      |
| G5   | scriptSig push-only check         | PRESENT  | —      | —      |
| G6   | Output scriptpubkey standard type | PARTIAL  | BUG-2,3,4 | P0-CDIV |
| G7   | OP_RETURN tail push-only check    | PRESENT  | —      | —      |
| G8   | Cumulative datacarrier size cap   | PARTIAL  | BUG-1  | P1     |
| G9   | Dust check (GetDust)              | PARTIAL  | BUG-6  | P1     |
| G10  | MAX_DUST_OUTPUTS_PER_TX = 1       | PRESENT  | —      | —      |
| G11  | Coinbase always non-standard      | PRESENT  | —      | —      |
| G12  | P2PK output recognized            | MISSING  | BUG-3  | P0-CDIV |
| G13  | Bare multisig n ≤ 3 enforced      | MISSING  | BUG-2  | P0-CDIV |
| G14  | Bare multisig m ∈ [1, n] enforced | MISSING  | BUG-2  | P0-CDIV |
| G15  | MatchMultisig opcode parse        | MISSING  | BUG-2  | P0-CDIV |
| G16  | WITNESS_UNKNOWN allowed in output | MISSING  | BUG-4  | P0-CDIV |
| G17  | -permitbaremultisig flag          | MISSING  | BUG-5  | P1     |
| G18  | -datacarrier flag (off → 0 bytes) | MISSING  | BUG-1  | P1     |
| G19  | -datacarriersize tunable          | MISSING  | BUG-1  | P1     |
| G20  | -dustrelayfee tunable             | MISSING  | BUG-8  | P1     |
| G21  | -bytespersigop tunable            | MISSING  | BUG-9  | P2     |
| G22  | Core debug-string error parity    | MISSING  | BUG-7  | P1     |
| G23  | ValidateInputsStandardness        | PRESENT  | —      | —      |
| G24  | MAX_P2SH_SIGOPS = 15 enforced     | PRESENT  | —      | —      |
| G25  | IsWitnessStandard P2WSH limits    | PRESENT  | —      | —      |
| G26  | IsWitnessStandard tapscript limits| PRESENT  | —      | —      |
| G27  | TRUC SingleTRUCChecks parity      | PARTIAL  | BUG-10 | P1     |
| G28  | TRUC PackageTRUCChecks parity     | PARTIAL  | BUG-11 | P1     |
| G29  | SpendsNonAnchorWitnessProg helper | MISSING  | BUG-12 | P2     |
| G30  | Two-pipeline guard extension      | PRESENT  | —      | —      |

Bug inventory (18 bugs / 30 gates)
-----------------------------------

Severity legend: P0-CDIV=consensus-or-cross-impl-divergence;
P1=correctness or operator-functional; P2=cosmetic.

| Bug    | Gate          | Sev      | Description |
|--------|---------------|----------|-------------|
| BUG-1  | G8, G18, G19  | P1       | No `-datacarrier` / `-datacarriersize` operator flag. `MAX_OP_RETURN_RELAY=100_000` is hardcoded in `mempool.py:43`. Core's logic at `mempool_args.cpp:95-99`: if `-datacarrier=false`, `max_datacarrier_bytes=std::nullopt`; then `IsStandardTx` line 137 uses `value_or(0)` → any OP_RETURN with size > 0 fails. This mode is unrepresentable in ouroboros. Also `-datacarriersize=N` (default `MAX_OP_RETURN_RELAY=100_000`) can be tuned by operators to allow LARGER OP_RETURNs than the default — ouroboros cannot. |
| BUG-2  | G6, G13, G14, G15 | **P0-CDIV** | Bare multisig "detection" in `_is_standard_output_type` is just `script_pubkey[-1] == 0xae` (last byte is `OP_CHECKMULTISIG`). Core's logic: parse opcodes via `MatchMultisig` (`solver.cpp:85-105`); verify m + pubkeys + n are minimal OP_1..OP_16 / valid pushdata; verify last opcode is `OP_CHECKMULTISIG`; verify total-pubkeys ≤ MAX_PUBKEYS_PER_MULTISIG (20); then in `IsStandard` (`policy.cpp:87-95`) require n ∈ [1, 3] (only x-of-3 standard) and m ∈ [1, n]. ouroboros accepts: 4-of-7 multisig (rejected by Core), 16-of-16 multisig, 0-of-0 multisig, arbitrary `<garbage> OP_CHECKMULTISIG`. P0-CDIV: cross-impl consensus-diff sees divergence as soon as someone submits a non-standard bare multisig. |
| BUG-3  | G6, G12       | **P0-CDIV** | P2PK output (`<pubkey> OP_CHECKSIG`, 35 or 67 bytes) is not recognized — `_is_standard_output_type` has no P2PK pattern. Core's `MatchPayToPubkey` (`solver.cpp:36-47`) checks `script.size() == CPubKey::SIZE+2` (35/67) AND `script.back() == OP_CHECKSIG` AND `CPubKey::ValidSize(pubkey)`. Returns `TxoutType::PUBKEY` which `IsStandard` accepts. ouroboros REJECTS the tx as non-standard. P0-CDIV: tx creating P2PK outputs is rejected, while Core accepts; visible on `sendrawtransaction` cross-impl. Also affects RPC `decodescript` "type" field which ouroboros would label "nonstandard" vs Core's "pubkey". |
| BUG-4  | G6, G16       | **P0-CDIV** | WITNESS_UNKNOWN (witness program with version 2..16 OR version 0 with non-standard program length, e.g. v0 with 33-byte program) is rejected at OUTPUT side in `_is_standard_output_type`. Core treats this asymmetrically: `IsStandard(scriptPubKey)` returns TRUE for WITNESS_UNKNOWN (allows tx creation), but `ValidateInputsStandardness` REJECTS spending such a UTXO (`policy.cpp:234-240`). This asymmetry enables forward compatibility for future witness versions added by soft fork. ouroboros's symmetric rejection means future witness versions cannot be created via mempool acceptance even when Core has them activated. |
| BUG-5  | G17           | P1       | No `-permitbaremultisig` operator flag (Core: `policy.h:52` `DEFAULT_PERMIT_BAREMULTISIG=true`, set via `mempool_args.cpp:93`). `IsStandardTx` per `policy.cpp:152-154`: `if (whichType == MULTISIG && !permit_bare_multisig) return false`. Even if BUG-2 is fixed, operators want the ability to refuse to relay/mine ALL bare multisig — common for nodes that don't want to take a stance on the multisig-spam policy debate. Currently always ON. |
| BUG-6  | G9            | P1       | `GetDustThreshold` divergence. Core's formula (`policy.cpp:27-64`): `n_size = GetSerializeSize(txout)` (= len(script_pubkey) + 8 for value + 1 for varint) + witness-discount-adjusted spend cost (98 bytes for segwit, 148 bytes for legacy). ouroboros hard-codes per-type sizes (99 for P2WPKH, 110 for P2WSH/P2TR, 182 for P2SH/P2PKH-and-others) — does NOT add the serialize size of the output itself, and uses fixed numbers for the spend cost that don't include `WITNESS_SCALE_FACTOR` weighting on the script side. Result: dust threshold for a 25-byte P2PKH is 546 sat in Core (= 182 × 3000 / 1000) but ouroboros may compute differently for non-standard output sizes. P1 because the most common cases (P2PKH/P2WPKH/P2WSH/P2TR) match by coincidence (hardcoded values are correct for the 1 standard size per type) — but custom segwit sizes diverge. |
| BUG-7  | G22           | P1       | `_is_standard_tx` returns diagnostic English error strings ("Non-standard version: 5", "Transaction weight ...", "Input 3 scriptSig size ...") instead of Core's short kebab strings ("version", "tx-size", "scriptsig-size", "scriptsig-not-pushonly", "scriptpubkey", "bare-multisig", "datacarrier", "dust"). Comments in mempool.py:1146-1147 acknowledge what Core sets as the reason; the code prepends "Non-standard transaction: " in `_add_transaction_inner` (mempool.py:2009). Downstream `rpc._map_mempool_rejection_reason` must substring-match. Continuation of W125. |
| BUG-8  | G20           | P1       | No `-dustrelayfee` operator flag. Core's `DUST_RELAY_TX_FEE=3000` sat/kvB is the **default**; operators can raise it (forcing larger dust thresholds → fewer "would be dust" outputs) or lower it. ouroboros hard-codes `DUST_RELAY_TX_FEE=3000` in `mempool.py:48`. |
| BUG-9  | G21           | P2       | No `-bytespersigop` operator flag. Core's `DEFAULT_BYTES_PER_SIGOP=20` is a tunable that determines how aggressively sigop-heavy txs are penalized in vsize calculations. ouroboros uses `DEFAULT_BYTES_PER_SIGOP` from validation.py — also hard-coded. Operator-functional only. |
| BUG-10 | G27           | P1       | `SingleTRUCChecks` (mempool.py:_check_truc_policy) is mostly correct but has 2 divergences from Core's `truc_policy.cpp:171-261`: (a) Sibling-eviction `consider_sibling_eviction` check uses `parent_desc_count == 2` (mempool.py:2611) which is `GetDescendantCount(parent) == 2` per Core. Correct. BUT then the conditional `if sibling_entry and sibling_entry.ancestor_count == 2:` (mempool.py:2618) tightens beyond Core: Core's check is `GetAncestorCount(*descendants.begin()) == 2` where `descendants.begin()` is the sole child (already established via `len(descendants) == 1` derivation). ouroboros confuses ancestor-count-including-self (2 = parent + self) with Core's. Subtle, may yield same value here but the iterator is different. (b) `direct_conflicts.intersection(existing_children)` (mempool.py:2593) is a set intersection; Core's `child_will_be_replaced` is `std::any_of(descendants.cbegin(), descendants.cend(), [...]direct_conflicts.contains(child->GetTx().GetHash()))` — `descendants` is the parent's set minus the parent itself (`descendants.erase(parent_it)`). ouroboros uses parent's CHILDREN set instead of full descendant set. For TRUC where descendant_count ≤ 2 these coincide, but the semantic is different in the presence of code-shape changes. |
| BUG-11 | G28           | P1 → CLOSED | INITIALLY flagged as `_check_package_truc_policy` missing the 1-parent-1-package-grandparent rejection. **Audit re-verification (after first test pass) revealed the gate IS present** at mempool.py:2706-2722 via the `total_ancestors = len(mempool_parents) + len(package_parents); if total_ancestors + 1 > TRUC_ANCESTOR_LIMIT` arm, which naturally catches case 5 (truc_policy.h:87-88). G28 flipped from xfail to PRESENT pin. The other PTRUCC failure modes (truc_policy.h:80-91) are similarly covered by the per-tx loop. **Net: BUG-11 is a FALSE POSITIVE from initial brief survey; closed at audit time.** |
| BUG-12 | G29           | P2       | No `SpendsNonAnchorWitnessProg` helper (Core: `policy.cpp:354-388`). Core uses this from CPFP / fee bumping to know whether a tx spends an "interesting" witness program (everything except P2A) — important for ephemeral-dust spent-by-anchor checks. ouroboros has `_has_ephemeral_dust` which is one side; the spent-side helper is absent. Latent until ephemeral-dust + sibling-eviction interaction is exercised harder. |
| BUG-13 | G6            | P1       | OP_RETURN tail push-only check at `_is_push_only_from(script_pubkey, 1)` (mempool.py:836) treats an opcode whose data extends past end-of-script as a failure (returns False) ✓ — same as Core (`script.h:436` IsPushOnly). HOWEVER, ouroboros also accepts a single-byte OP_RETURN (`script_pubkey == bytes([0x6a])`) as standard. Core's `Solver` (solver.cpp:185) requires `scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN`, and the IsPushOnly tail check on positions 1..end is vacuously true for length-1 scripts → Core also accepts. So this is actually CORE-PARITY. Audit verified: not a bug. **Re-numbered after second pass; placeholder removed.** |
| BUG-13 | G6 (lazy n in 0xae) | P1   | Replaces stale BUG-13. The `_is_standard_output_type` last-byte-check `script_pubkey[-1] == 0xae` is also reached for scripts that START with `0x6a` (OP_RETURN) but happen to END with a byte that equals 0xae — these are NULL_DATA in Core, never multisig. The order of checks in mempool.py (OP_RETURN first at line 835) prevents this in practice. **Verified: not a bug at present, BUT will become one if anyone reorders the checks.** Source-level guard candidate: test pinning OP_RETURN check is before multisig check. |
| BUG-14 | G6            | P1       | `_is_standard_output_type` accepts ALL anchor outputs via `is_pay_to_anchor()` but Core's Solver returns `TxoutType::ANCHOR` for the specific P2A program (`OP_1 0x02 0x4e73`). Future "anchor v2" with a different program but same first-byte structure would be incorrectly accepted by ouroboros. Source: mempool.py:861-862 vs solver.cpp:169-171. P2A semantics frozen by BIP-???; the bug is forward-compat only. |
| BUG-15 | G6            | P1       | Bare-multisig detection (BUG-2) does not enforce MAX_PUBKEYS_PER_MULTISIG=20 (`script/script.h:34`). Core's MatchMultisig (`solver.cpp:101-103`) requires `pubkeys.size() == num_keys` AND `num_keys ≤ MAX_PUBKEYS_PER_MULTISIG`. ouroboros's last-byte check accepts 100-of-100 multisig if someone constructed one. Sub-issue of BUG-2, but separable because closing BUG-2 with just the m/n ≤ 3 check still wouldn't catch n=21+. |
| BUG-16 | G6            | P1       | Bare-multisig detection (BUG-2) does not enforce minimal-encoding for m/n. Core's `GetScriptNumber` (`solver.cpp:66-83`) calls `CheckMinimalPush(data, opcode)` for non-OP_N encodings, so a 3-of-3 multisig with `m` and `n` encoded as `01 03` (PUSH1 followed by byte 3) instead of `OP_3` is rejected by Core but accepted by ouroboros's last-byte check. Sub-issue of BUG-2; separable for fix granularity. |
| BUG-17 | G27           | P2       | TRUC error strings: ouroboros emits "version=3 tx cannot spend from non-version=3 tx ..." (mempool.py:2515-2519) which is **byte-exactly correct** per Core truc_policy.cpp:181-184. HOWEVER, ouroboros emits "tx would have too many ancestors" without the wtxid that Core includes ("tx %s (wtxid=%s) would have too many ancestors"). Most TRUC error strings are missing the txid + wtxid context that Core's strprintf inserts. Diagnostic-quality regression vs Core. |
| BUG-18 | G22           | P2       | `_is_standard_tx`'s coinbase-rejection happens at `_add_transaction_inner` (mempool.py:1976-1981) BEFORE `_is_standard_tx` is called. Core does the rejection inside `IsStandardTx` is not strictly correct either — Core's PreChecks at validation.cpp:802-804 rejects with `"coinbase"` reason. ouroboros's reason is `"coinbase"` ✓. Audit-only flag: documented for completeness. NOT A BUG. |

**Re-counting** (removing BUG-13 placeholder + BUG-18 non-bug + BUG-11 closed at audit): **15 real bugs.**
Renumbered for the test file. The 5 cosmetic / non-bug entries above are
documented to explain WHY they're not in the test-side inventory.

**Audit-time closure**: BUG-11 was flagged in initial brief but verified
already-closed during test-pass. This is the **first BUG-NN closure
detected at audit-time** in W135 — distinguishes from cosmetic / placeholder
entries because BUG-11 represents real Core behavior that was actually
implemented (not omitted). Net audit yield: 15 real open bugs.

Final bug inventory (15 real bugs, post audit-time closure)
-----------------------------------------------------------

| Bug    | Gate          | Sev      | Description (short) |
|--------|---------------|----------|--------------------|
| BUG-1  | G8/G18/G19    | P1       | No -datacarrier / -datacarriersize toggle. |
| BUG-2  | G6/G13/G14/G15| P0-CDIV  | Bare multisig: last-byte check only, no m/n bounds, no opcode parse. |
| BUG-3  | G6/G12        | P0-CDIV  | P2PK output not recognized. |
| BUG-4  | G6/G16        | P0-CDIV  | WITNESS_UNKNOWN rejected at output side. |
| BUG-5  | G17           | P1       | No -permitbaremultisig toggle. |
| BUG-6  | G9            | P1       | GetDustThreshold uses hardcoded per-type sizes instead of GetSerializeSize. |
| BUG-7  | G22           | P1       | Error strings English, not Core kebab. |
| BUG-8  | G20           | P1       | No -dustrelayfee toggle. |
| BUG-9  | G21           | P2       | No -bytespersigop toggle. |
| BUG-10 | G27           | P1       | TRUC sibling-eviction descendant-set semantics drift. |
| BUG-11 | G28           | —        | **CLOSED at audit time** — package TRUC grandparent rejection is present at mempool.py:2706-2722. |
| BUG-12 | G29           | P2       | SpendsNonAnchorWitnessProg helper absent. |
| BUG-13 | G6            | P1       | MAX_PUBKEYS_PER_MULTISIG=20 not enforced in bare multisig. |
| BUG-14 | G6            | P1       | Minimal-push encoding not enforced for m/n in bare multisig. |
| BUG-15 | G6            | P1       | P2A pattern accepts ALL OP_1 OP_PUSHBYTES_2 outputs, not just program=0x4e73 (forward-compat). |
| BUG-16 | G27           | P2       | TRUC error strings missing txid+wtxid context. |

Total: **3 P0-CDIV + 8 P1 + 4 P2 = 15 bugs** (BUG-11 closed at audit).

P0-CDIV summary
----------------

Three of the 16 bugs are P0-CDIV (consensus-or-cross-impl-divergence):

- **BUG-2** (G6/G13/G14/G15): bare multisig accepted with last-byte
  check only → ouroboros relays non-standard bare-multisig txs that
  Core rejects with `reason="scriptpubkey"` or "bare-multisig".
  Visible in any cross-impl consensus-diff run that includes a 4-of-7
  bare-multisig output.
- **BUG-3** (G6/G12): P2PK output unrecognized → ouroboros rejects
  txs that create P2PK outputs as non-standard.  Core accepts.
  Visible on `sendrawtransaction` of any P2PK-creating tx (e.g.
  early-mainnet coinbase reproduction).
- **BUG-4** (G6/G16): WITNESS_UNKNOWN rejected at output side →
  forward-compatibility broken; future witness-version softforks
  break ouroboros's mempool acceptance for txs creating those outputs.

All three would surface in a cross-impl consensus-diff if test vectors
exercise them. Suggested fix sequence: rewrite `_is_standard_output_type`
to mirror Core's `Solver()` (return one of the TxoutType enum values),
then layer the m/n bounds + WITNESS_UNKNOWN passthrough on top.

Lower priorities (P1 = 9 bugs)
-------------------------------

The biggest functional cluster is around the **operator-tunable policy
flags** (BUG-1, BUG-5, BUG-8). These are stable Core CLI args that
every Bitcoin tool expects to be honored. Currently ouroboros's only
toggle is `require_standard: bool`. A "policy CLI sweep" wave could
add `--permitbaremultisig`, `--datacarrier`, `--datacarriersize`,
`--dustrelayfee`, `--bytespersigop`, `--acceptnonstdtxn` plumbed
through `_is_standard_tx` (which would need to take a `policy_opts`
parameter instead of using module-level constants).

The TRUC bugs (BUG-10, BUG-11) are subtle; both require careful
mirroring of `truc_policy.cpp:171-261` (single) and `:57-169` (package).
Audit traces show ouroboros's implementation is structurally close
but has 2-3 semantic differences in the descendant-set derivation
that would only diverge under specific reorg-replacement scenarios
— hard to test without a full cluster mempool harness. Suggest
deferring to a TRUC-focused wave.

BUG-6 (`GetDustThreshold` formula) is a P1 that mostly self-heals
for the 5 standard output types because the hardcoded sizes are
correct by coincidence. The fix is mechanical (replace the lookup
table with `GetSerializeSize(txout)`-equivalent + the spend-cost
constants from policy.cpp:33-42).

P2 cluster (4 bugs)
-------------------

Mostly missing helpers and operator-experience gaps (BUG-9 sigop
tunable, BUG-12 SpendsNonAnchorWitnessProg, BUG-16 TRUC error string
context). None affect consensus or cross-impl divergence.

Closure plan (recommended sequence)
-----------------------------------

**Phase A — P0-CDIV (closes BUG-2, BUG-3, BUG-4)** — single-impl wave:
1. Rewrite `_is_standard_output_type` to be a thin wrapper around a
   Solver-like dispatch (returns one of TxoutType enum). Layer
   `_is_standard` on top (= Solver result != NONSTANDARD + the m/n
   bounds check for MULTISIG).
2. Add MatchMultisig with full opcode parse + m/n bounds (1..3) +
   MAX_PUBKEYS_PER_MULTISIG (20) + minimal-push encoding.
3. Add MatchPayToPubkey for P2PK output recognition.
4. Allow WITNESS_UNKNOWN at output side; keep input-side rejection.

**Phase B — operator-tunable flags (closes BUG-1, BUG-5, BUG-8)** —
multi-RPC wave:
5. Add `policy_opts` dataclass to `MempoolManager.__init__` with
   `permit_bare_multisig: bool`, `max_datacarrier_bytes: int | None`,
   `dust_relay_feerate: int`.
6. Wire CLI flags `--permitbaremultisig`, `--datacarrier`,
   `--datacarriersize`, `--dustrelayfee` in `cli.py`.
7. Update `_is_standard_tx` signature to take `policy_opts`.

**Phase C — error-string parity (closes BUG-7) + cosmetic fixes**
(BUG-6, BUG-9, BUG-12, BUG-16):
8. Replace `_is_standard_tx` English strings with Core kebab debug
   strings. Update `rpc._map_mempool_rejection_reason` accordingly.
9. Replace `_get_dust_threshold` formula with serialize-size-based
   calculation.

**Phase D — TRUC parity (closes BUG-10, BUG-11)** — single-impl wave:
10. Refine `_check_truc_policy` descendant-set derivation to match
    Core's `descendants` set (not the children set).
11. Add the 1-parent-1-package-grandparent rejection case to
    `_check_package_truc_policy`.

Cumulative streak status
-------------------------

W135 is a DISCOVERY wave (no production changes). Streak: 71 fix +
65 discovery preserved (W135 increments discovery to 65).

The W135 P0-CDIV cluster (BUG-2/3/4) is **highest priority for a
follow-up fix wave** because all three are testable via existing
RPC surface (`sendrawtransaction` + `testmempoolaccept`) without
needing a full consensus-diff infrastructure.

Out-of-scope (not audited here)
-------------------------------

- Block-level standardness (mining policy, `IsBlockStandard`) — Core
  doesn't have this concept; everything block-side is consensus.
- Mempool eviction order (`MempoolEntry.GetTxSize` virtual size
  used for chunk-rate sort) — audited under W120.
- BIP-125 RBF feebumper rules — audited under W130.
- Mempool persistence (`mempool.dat`) — audited indirectly under
  W125 + W130 / FIX-76 / FIX-77.
- Script interpreter STANDARD_SCRIPT_VERIFY_FLAGS — that's a script-
  evaluation gate, not an IsStandardTx gate. Verified by `CheckInputScripts`.
- Package validation full audit — touched here (BUG-11) but the full
  Package* surface is its own wave.

References
----------

- `bitcoin-core/src/policy/policy.h:38-95` — MAX_STANDARD_TX_WEIGHT,
  MIN_STANDARD_TX_NONWITNESS_SIZE, MAX_P2SH_SIGOPS, MAX_STANDARD_TX_SIGOPS_COST,
  MAX_TX_LEGACY_SIGOPS, MAX_STANDARD_SCRIPTSIG_SIZE, DUST_RELAY_TX_FEE,
  MAX_STANDARD_P2WSH_*, MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
  MAX_DUST_OUTPUTS_PER_TX
- `bitcoin-core/src/policy/policy.h:104-138` — MANDATORY +
  STANDARD_SCRIPT_VERIFY_FLAGS + STANDARD_LOCKTIME_VERIFY_FLAGS
- `bitcoin-core/src/policy/policy.h:152-153` — TX_MIN_STANDARD_VERSION + TX_MAX_STANDARD_VERSION
- `bitcoin-core/src/policy/policy.cpp:27-64` — GetDustThreshold
- `bitcoin-core/src/policy/policy.cpp:80-98` — IsStandard (output side)
- `bitcoin-core/src/policy/policy.cpp:100-165` — IsStandardTx
- `bitcoin-core/src/policy/policy.cpp:214-263` — ValidateInputsStandardness
- `bitcoin-core/src/policy/policy.cpp:265-352` — IsWitnessStandard
- `bitcoin-core/src/policy/policy.cpp:354-388` — SpendsNonAnchorWitnessProg
- `bitcoin-core/src/policy/truc_policy.cpp:57-169` — PackageTRUCChecks
- `bitcoin-core/src/policy/truc_policy.cpp:171-261` — SingleTRUCChecks
- `bitcoin-core/src/script/solver.cpp:36-105` — MatchPayToPubkey, MatchPayToPubkeyHash, MatchMultisig
- `bitcoin-core/src/script/solver.cpp:141-211` — Solver
- `bitcoin-core/src/consensus/tx_check.cpp:11-60` — CheckTransaction (consensus floor)
- `bitcoin-core/src/node/mempool_args.cpp:85-105` — operator flag plumbing
- `bitcoin-core/src/init.cpp:677-695` — operator flag CLI args
- `src/ouroboros/mempool.py:36-102` — policy constants
- `src/ouroboros/mempool.py:763-809` — _is_push_only_from
- `src/ouroboros/mempool.py:812-870` — _is_standard_output_type (BUG-2/3/4/15)
- `src/ouroboros/mempool.py:873-895` — _get_dust_threshold (BUG-6)
- `src/ouroboros/mempool.py:898-920` — _has_ephemeral_dust
- `src/ouroboros/mempool.py:923-965` — _check_ephemeral_dust
- `src/ouroboros/mempool.py:1016-1105` — _validate_inputs_standardness
- `src/ouroboros/mempool.py:1108-1190` — _is_standard_tx (BUG-7)
- `src/ouroboros/mempool.py:1285-1393` — _is_witness_standard
- `src/ouroboros/mempool.py:2457-2623` — _check_truc_policy (BUG-10)
- `src/ouroboros/mempool.py:2625+` — _check_package_truc_policy (BUG-11)
