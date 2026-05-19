# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (ouroboros)

**Wave:** W157 — `CheckSignetBlockSolution`, `FetchAndClearCommitmentSection`,
`SIGNET_HEADER` (`0xecc7daa2`), `SignetTxs::Create`, `SignetParams::signet_challenge`,
default-signet 1-of-2 multisig (`51 21 03ad… 21 0359… 52 ae`),
custom-signet `-signetchallenge=<hex>`, `consensus.signet_blocks`,
`consensus.enforce_BIP94`, `MAX_TIMEWARP=600` (`consensus/consensus.h:35`),
`GetMinimumTime(pindexPrev, interval)` (`node/miner.cpp:36-46`), `UpdateTime`,
`GetNextWorkRequired` BIP-94 branch (`pow.cpp:67-76`),
`fPowAllowMinDifficultyBlocks`, `fPowNoRetargeting`, `BLOCK_SCRIPT_VERIFY_FLAGS`
(`P2SH|WITNESS|DERSIG|NULLDUMMY`), `ComputeModifiedMerkleRoot`,
trivial-challenge fall-through (OP_TRUE), `pchMessageStart` derivation
(`sha256(signet_challenge)[:4]`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.h:21` — `bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)`.
- `bitcoin-core/src/signet.cpp:28` —
  `static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` —
  `BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY`.
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`
  walks pushdatas, finds the first push whose **first 4 bytes** equal
  `SIGNET_HEADER` AND whose length is **strictly greater than** the header
  length (i.e. a header-only push without trailing solution data is
  **stripped from the witness commitment** but does NOT count as a found
  solution), rebuilds the commitment script with the header push replaced
  by a header-only push, and returns the body.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot` rounds
  up leaves count to nearest even (`(vtx.size()+1)&~1ULL`), uses the
  **modified coinbase hash** (not wtxid) at leaf 0, then `tx.GetHash()`
  (txid, not wtxid) for indices 1..N.
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`:
  - `tx_to_spend.version = 0`, `nLockTime = 0`, single input
    `(COutPoint(), CScript(OP_0), nSequence=0)`, output value 0 with
    `scriptPubKey = challenge`.
  - `tx_spending.version = 0`, `nLockTime = 0`, single input
    `(COutPoint(), CScript(), nSequence=0)`, output value 0 with
    `scriptPubKey = CScript(OP_RETURN)` (a *bare* OP_RETURN, one byte 0x6a).
  - Rejects empty `block.vtx` returning `std::nullopt`.
  - Rejects missing witness-commitment via
    `GetWitnessCommitmentIndex(block) == NO_WITNESS_COMMITMENT` →
    `std::nullopt` (NO trivial-OP_TRUE fall-through to "accept anyway"!).
  - If no signet section is found, leaves both `scriptSig` and
    `scriptWitness` empty (fall-through is allowed only because the script
    interpreter will refuse to satisfy any non-trivial challenge — this is
    the OP_TRUE fall-through).
  - On signet-section present: `SpanReader` over the section bytes
    consuming `scriptSig`, then `scriptWitness.stack`; **trailing bytes
    are rejected** (`if (!v.empty()) return std::nullopt`); any exception
    → `std::nullopt`.
  - `block_data` (the 72-byte commit-payload) = version(4)
    || hashPrevBlock(32) || signet_merkle(32) || nTime(4); 4-byte nNonce
    and 4-byte nBits are NOT included — the signet signature
    intentionally excludes nNonce (so signet miners can grind nonce
    without re-signing) and nBits (so re-targets don't invalidate the
    signature).
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  - Genesis short-circuit: `block.GetHash() == consensusParams.hashGenesisBlock` → true.
  - Builds `challenge = CScript(signet_challenge.begin(), end())`,
    instantiates `PrecomputedTransactionData txdata` (NOT
    `MissingDataBehavior::FAIL` — `ASSERT_FAIL`!), calls
    `VerifyScript(scriptSig, prevSPK, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`.
- `bitcoin-core/src/consensus/params.h:118-141` —
  `bool enforce_BIP94;` ("Enforce BIP94 timewarp attack mitigation. On
  testnet4 this also enforces the block storm mitigation."),
  `bool signet_blocks{false}`, `std::vector<uint8_t> signet_challenge`.
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600`.
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired`:
  `fPowAllowMinDifficultyBlocks` exception fires when
  `pblock->GetBlockTime() > pindexLast->GetBlockTime() + nPowTargetSpacing*2`;
  otherwise on non-retarget block, returns `pindexLast->nBits`.
- `bitcoin-core/src/pow.cpp:50-85` — `CalculateNextWorkRequired`:
  `fPowNoRetargeting` short-circuit returns `pindexLast->nBits`; BIP-94
  branch `if (params.enforce_BIP94)` uses `pindexFirst->nBits` (the first
  block of the 2016-block period) as the base, otherwise
  `pindexLast->nBits`.
- `bitcoin-core/src/node/miner.cpp:36-46` —
  `int64_t GetMinimumTime(const CBlockIndex* pindexPrev, int64_t difficulty_adjustment_interval)`:
  `min_time = pindexPrev->GetMedianTimePast() + 1`; **on ALL networks**
  (no `enforce_BIP94` gate!), if
  `(pindexPrev->nHeight+1) % difficulty_adjustment_interval == 0`,
  `min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)`.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`:
  `nNewTime = max(GetMinimumTime(pindexPrev, interval), NodeClock::now())`;
  if `fPowAllowMinDifficultyBlocks`, recomputes `pblock->nBits = GetNextWorkRequired(...)`
  after the timestamp bump.
- `bitcoin-core/src/validation.cpp:4097-4105` —
  `ContextualCheckBlockHeader` BIP-94 gate: only fires on
  `consensusParams.enforce_BIP94`, at retarget-interval boundaries,
  rejecting `block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`
  with `BlockValidationResult::BLOCK_INVALID_HEADER` + reject reason
  `"time-timewarp-attack"`.
- `bitcoin-core/src/kernel/chainparams.cpp:411-516` — `SigNetParams`:
  default-signet challenge is the 1-of-2 multisig
  `51 21 03ad…be430 21 0359…f2e6c4 52 ae`; custom-signet uses
  `opts.challenge`; `consensus.signet_blocks = true`,
  `consensus.signet_challenge = bin`,
  `consensus.fPowAllowMinDifficultyBlocks = false`,
  `consensus.enforce_BIP94 = false`,
  `consensus.fPowNoRetargeting = false`,
  `consensus.powLimit = 0x00000377ae000000…`;
  `pchMessageStart[0..4] = sha256(signet_challenge)[0..4]` (custom signets
  get a unique p2p magic so they can't accidentally peer with default-signet).
- `bitcoin-core/src/kernel/chainparams.cpp:300-404` — `CTestNet4Params`:
  `enforce_BIP94 = true`, `fPowAllowMinDifficultyBlocks = true`.
- `bitcoin-core/src/kernel/chainparams.cpp:529-577` — `CRegTestParams`:
  `enforce_BIP94 = opts.enforce_bip94` (operator-settable so regtest can
  exercise BIP-94 in unit-test mode), `fPowNoRetargeting = true`,
  `fPowAllowMinDifficultyBlocks = true`, `signet_blocks = false`.

**Files audited**
- `src/ouroboros/validation.py` —
  `MAX_TIMEWARP = 600` (line 72), `SIGNET_HEADER` (line 79),
  `DEFAULT_SIGNET_CHALLENGE` (line 82-86), `SIGNET_SCRIPT_FLAGS`
  (line 89-94), `_get_pow_limit` (line 180-190), `_get_pow_limit_bits`
  (line 193-199), `permitted_difficulty_transition` (line 202-268),
  `BlockValidator.validate_block` (line 648-883), `_validate_header`
  (line 947-1048) — BIP-94 gate line 1000, `_get_expected_bits`
  (line 1050-1152) — BIP-94 branch line 1137,
  `_validate_signet_solution` (line 1554-1639), `_extract_signet_commitment`
  (line 1641-1682), `_parse_signet_solution` (line 1684-1713),
  `_compute_signet_merkle_root` (line 1715-1757),
  `_encode_signet_block_data` (line 1759-1768),
  `_build_signet_to_spend` (line 1770-1797),
  `_build_signet_to_sign` (line 1799-1824),
  `_SEGWIT_ACTIVATION` table (line 1306-1313),
  `_calculate_block_subsidy` (line 1520-1550).
- `ferrous-utils/sync/src/chain_params.rs` —
  `ConsensusParams` struct (line 12-41), `get_consensus_params`
  (line 44-98), `genesis_block_hash` (line 101-138) — incl. signet
  (line 129-134), `genesis_bits` (line 141-150), `minimum_chain_work`
  (line 280-314), `genesis_block_timestamp` (line 354-365),
  `genesis_nonce` (line 368-379), `bip_activation_heights`
  (line 385-418), `all_forks_active_from_genesis` (line 423-425),
  `subsidy_halving_interval` (line 454-461).
- `ferrous-utils/sync/src/validate/difficulty.rs` —
  `DIFFICULTY_ADJUSTMENT_INTERVAL = 2016` (line 14),
  `TARGET_TIMESPAN`/`TARGET_SPACING` (line 17/20),
  `get_next_work_required` (line 53-113), `calculate_next_work_required`
  (line 132-181) — BIP-94 branch line 159, `calculate_next_work_required_bip94`
  (deprecated thin-wrapper, line 202-211), `permitted_difficulty_transition`
  (line 225-275).
- `ferrous-utils/sync/src/validate/header.rs` —
  `HeaderValidator` (line 62-65), `validate_header` (line 81-110),
  `validate_timestamp` (line 203-233) — backward MTP check OPENLY
  disabled, `validate_version` (line 236-245), `validate_difficulty`
  (line 248-263) — body OPENLY disabled, `get_next_work_required`
  (line 168-200), `get_median_time_past` (line 145-163),
  `validate_chain_difficulty_adjustments` (line 266-294).
- `ferrous-utils/sync/src/validate/block.rs` —
  `BlockValidator::new` per-network `default_height` (line 137-141),
  `validate_block` (line 167-233), `validate_block_with_flags`
  (line 255-397), `calculate_block_subsidy` (line 786-793),
  `validate_block_subsidy` (line 753-770).
- `ferrous-utils/sync/src/validate/pow.rs` —
  `validate_pow` (line 17-30), `bits_to_target` (line 44-47),
  `calculate_next_difficulty` (line 64-89; legacy mainnet-only
  formula with `TARGET_TIMESPAN` hardcoded to mainnet 2-week value).
- `ferrous-utils/sync/src/lib.rs` —
  `connect_block_from_bytes` (line 3402-3946) — third pipeline:
  inline PoW + merkle + MTP + cb-length + witness-commitment +
  IsFinalTx, NO signet check, NO BIP-94 timewarp check;
  `validate_block_from_bytes` (line 3347+).
- `src/ouroboros/node.py` — `_init_genesis` per-network branch
  (line 800-897); signet genesis hex (line 814-815) — **31 bytes**,
  not 32.
- `src/ouroboros/rpc.py` — `_get_block_template` (line 5230-5332):
  `gbt_rules` line 5276 + signet append line 5278-5279; `mintime`
  line 5325 = `mtp_plus_one`; `network/is_regtest` test line 11343-11345.
- `src/ouroboros/cli.py` — `--network` Choice (line 115); no
  `--signetchallenge` / `--signetseednode` flag.
- `src/ouroboros/config.py` — `CHAIN_SECTIONS` (line 19); `is_test_chain`
  (line 480-482); no `signetchallenge` knob.
- `src/ouroboros/consensus.py` — `BURIED_DEPLOYMENTS["signet"]`
  (line 149-156), `BIP34_HASHES["signet"] = bytes(32)` (line 202),
  `BIP9_DEPLOYMENTS["signet"]` (line 322-341),
  `get_deployment_thresholds` (line 823-843) — signet returns
  `(2016, 1815)` per chainparams.cpp:472.
- `src/ouroboros/tests/test_w108_gbt.py` — G9 (line 296-309) and
  G13 (line 412-419) explicitly assert the BUGS as the current state
  ("regression contract") for both BIP-94 mintime and signet_challenge
  GBT pass-through.
- `src/ouroboros/tests/test_w123_mining_gbt.py` —
  `test_gbt_does_not_signal_signet_challenge_field` (line 302-309) and
  `test_bip94_max_timewarp_arm_not_wired` (line 318-324) similarly assert
  the missing behaviour as the contract.
- `src/ouroboros/tests/test_mtp_contextual.py` — covers the existing
  testnet4-only BIP-94 path (line 220+); incidentally documents that
  the gate is keyed by `self.network == "testnet4"` (line 223).
- `src/ouroboros/block_sync.py` — `_apply_new_block` Rust/Python dual
  route (line 1080-1265); orphan-process path
  (`validate_block` line 2205, 3095).

---

## Gate matrix (44 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CheckSignetBlockSolution present | G1: signet check called from at least one validate path | **PARTIAL** — Python `validate_block` calls `_validate_signet_solution` (validation.py:720). Rust `connect_block_from_bytes` and `validate_block_from_bytes` do NOT (lib.rs:3402+, see **BUG-1**). Three-pipeline divergence (continues N-pipeline drift record). |
| 1 | … | G2: genesis short-circuit (return true) | PASS (validation.py:1562-1563). |
| 1 | … | G3: empty `block.vtx` rejected | PARTIAL — implicit via `block.transactions[0]` IndexError (validation.py:1565), not a controlled reject. |
| 1 | … | G4: missing witness-commitment → reject | **BUG-2** — Python *does* reject (line 1583), but the inline comment (line 1581-1583) admits "check if the challenge is trivially satisfiable (e.g. OP_TRUE). Otherwise fail" — i.e. the OP_TRUE fall-through that Core implements is missing. |
| 1 | … | G5: SIGNET_HEADER recognized | PASS (`SIGNET_HEADER = bytes([0xEC, 0xC7, 0xDA, 0xA2])` line 79, used line 1679, 1733). |
| 1 | … | G6: header-only push (4 bytes, no body) is **stripped** but NOT counted as "found" | **BUG-3 (P0-CDIV)** — Python's `_extract_signet_commitment` (line 1679) tests `len(data) >= 4`, accepting a header-only push as a found solution (with body `b""`). Core (signet.cpp:43) tests `pushdata.size() > header.size()`, i.e. strictly greater — a header-only push does NOT count. ouroboros then runs the full signature verification with an empty scriptSig/witness, which will succeed only against OP_TRUE-trivial challenges and fail against the default 1-of-2 multisig — but the *path* taken differs (Core falls through with empty solution, ouroboros treats the empty push as a found solution and parses zero scriptSig bytes). Distinct CDIV on edge-case crafted coinbases. |
| 1 | … | G7: only FIRST header-found push counts (Core sets `found_header=true` and stops processing more) | **BUG-4** — Python loop has no `if found: break` after returning the first match; the function does early-return on match (line 1679-1680) so accidentally correct, BUT `_compute_signet_merkle_root` (line 1715-1757) does NOT use the Core algorithm at all — it rebuilds the commitment with `spk[:38] + bytes([4]) + SIGNET_HEADER`, which assumes there is EXACTLY ONE witness-commitment push and silently mishandles the case where there is a second commitment output (which Core's reverse-iteration `GetWitnessCommitmentIndex` would have picked instead). |
| 1 | … | G8: SpanReader extraneous-data check (`if !v.empty() return nullopt`) | **BUG-5** — Python's `_parse_signet_solution` (line 1684-1713) silently consumes everything it can, but does NOT reject when there are extra bytes after the witness stack (line 1711 just falls through), and does NOT reject when `n_items` is larger than what fits in the buffer (line 1706 silently `break`s out of the loop, returning a *truncated* witness — accepts a malformed solution that Core would reject with `std::nullopt`). |
| 2 | SIGNET_HEADER constant | G9: bytes `0xec 0xc7 0xda 0xa2` | PASS (line 79). |
| 3 | signet_challenge chain param | G10: per-network `signet_challenge` stored in chainparams | **BUG-6 (P0-CDIV)** — There is NO `signet_challenge` field on `ConsensusParams` (chain_params.rs:16-34), no `signet_challenge` key in any Python `BURIED_DEPLOYMENTS` / `BIP9_DEPLOYMENTS` entry, no `Node.signet_challenge` attribute (tests verify this in test_w123_mining_gbt.py:664-672), no `--signetchallenge` CLI flag in cli.py. The DEFAULT-signet challenge is hardcoded in validation.py:82-86 as a module constant (`DEFAULT_SIGNET_CHALLENGE`). Consequence: there is no way to run a **custom signet** ("test-only signet with own challenge") — the operator cannot configure `-signetchallenge=<hex>` and the validator will hard-reject any custom-signet block that doesn't satisfy the default Bitcoin Core public-signet multisig. |
| 3 | … | G11: default 1-of-2 multisig matches Core | PASS (validation.py:82-86 matches kernel/chainparams.cpp:418 byte-for-byte). |
| 4 | FetchAndClearCommitmentSection | G12: replacement script rebuilt with header-only push (commits to "I had a signet section but I'm not signing it anymore") | PARTIAL — Python rebuilds in `_compute_signet_merkle_root` (line 1731-1733) with `bytes([4]) + SIGNET_HEADER` (a 4-push of the 4-byte header — Core does the same), but only handles the FIRST matching output (line 1738 falls through for any non-matching output). A coinbase with TWO witness-commitment outputs would have both modified in Core's iteration (Core reads `cidx` once at line 91 then operates on that one — same shape, but `GetWitnessCommitmentIndex` returns the LAST one not the FIRST; see **BUG-7**). |
| 4 | … | G13: returns the **body** (bytes after the 4-byte header) | PASS (line 1680: `return data[4:]`). |
| 5 | BIP-94 enforce_BIP94 consensus param | G14: per-network bool wired through ConsensusParams | PARTIAL — Rust `ConsensusParams.enforce_bip94` (chain_params.rs:27) exists and is `true` only for testnet4 (line 66). Python has NO `enforce_bip94` attribute; the BIP-94 check at validation.py:1000 is hardcoded to `self.network == "testnet4"`. See **BUG-8**. |
| 5 | … | G15: regtest operator-knob `opts.enforce_bip94` plumbed | **BUG-9 (P1)** — Core lets the operator set `consensus.enforce_BIP94 = opts.enforce_bip94` on regtest via `-vbparams=...` / test-only options (chainparams.cpp:547). There is no analogue in ouroboros — neither Python (`enforce_bip94` not a field) nor Rust (`get_consensus_params(Regtest)` hardcodes `enforce_bip94: false` at chain_params.rs:74). Regtest-mode functional tests cannot exercise BIP-94. |
| 6 | MAX_TIMEWARP = 600 | G16: constant defined | PASS (Python `MAX_TIMEWARP = 600` validation.py:72). Rust has NO `MAX_TIMEWARP` constant anywhere in `ferrous-utils/sync/` — see **BUG-10**. |
| 6 | … | G17: enforced at retarget boundary in `ContextualCheckBlockHeader` | PARTIAL — Python `_validate_header` (line 1000-1003) gates on `self.network == "testnet4"` (NOT `enforce_BIP94`); the check exists but only on testnet4 (BUG-8). Rust `connect_block_from_bytes` (lib.rs:3539-3572) does NOT check BIP-94 timewarp — see **BUG-1**. Rust `HeaderValidator.validate_timestamp` (header.rs:203-233) explicitly does NOT check MTP at all (the backward-MTP check is commented-out as a "simplified version"). |
| 7 | GetMinimumTime miner-side clamp | G18: GBT `mintime` = `max(MTP+1, prev.GetBlockTime() - MAX_TIMEWARP)` at retarget boundary | **BUG-11 (P0-CDIV)** — rpc.py:5325 sets `"mintime": mtp_plus_one` unconditionally; no BIP-94 clamp. test_w108_gbt.py:296-309 / test_w123_mining_gbt.py:318-324 lock in the wrong behaviour as a regression contract (3rd-instance "test-asserts-the-bug" pattern this audit). Core fires this gate on **ALL networks** since v25 (`miner.cpp:43` — there is no `enforce_BIP94` gate around it). |
| 7 | … | G19: GBT `curtime` = `max(GetMinimumTime, NodeClock::now())` | PARTIAL (curtime is `max(MTP+1, now)` at line 5259 — uses `mtp_plus_one` not the BIP-94 clamp; same bug class as G18). |
| 7 | … | G20: UpdateTime recomputes `pblock->nBits` on min-difficulty networks after timestamp bump | N/A — ouroboros has no `UpdateTime` analog; miners use GBT-returned bits as-is. |
| 8 | enforce_BIP94 consensus param wiring | G21: validation.py reads `enforce_BIP94` from chain params | **BUG-12** — validation.py:1000 hardcodes `if self.network == "testnet4"` instead of consulting a `params.enforce_bip94` flag. Operator-set regtest BIP-94 (G15) cannot ever fire, even if `--enforce-bip94` were wired. |
| 9 | nVersion BIP-9 signaling | G22: GBT version computed for next block, not copied from prev | PARTIAL (rpc.py:5246-5249 calls `node.get_next_block_version`); but the dead-helper W154 BUG-3 fleet-wide pattern says the method is never implemented on `Node` → always falls back to `best_block.version | 0x20000000`. See **BUG-13** (carry-forward). |
| 9 | … | G23: BIP9 deployments STARTED/LOCKED_IN signal bits set | PARTIAL — `compute_block_version` in consensus.py:780-816 exists but the test (test_w108_gbt.py:331-339) locks in fallback behaviour. |
| 10 | target nBits encoding | G24: nBits compact format round-trip | PASS (`_bits_to_target` validation.py:121-154; `target_to_bits` line 316-331). |
| 11 | GetNextWorkRequired at retarget | G25: non-retarget block returns `prev_bits` (mainnet/signet) | PASS Python (line 1106); Rust difficulty.rs:99-100 same. |
| 11 | … | G26: retarget boundary uses BIP-94 `first_block.bits` when `enforce_BIP94` | PASS for testnet4 in both Python (line 1137-1141) and Rust (difficulty.rs:159-163). Regtest can never fire (G15/G21). |
| 11 | … | G27: every 2016-block boundary actually runs (carry-forward W154 BUG-3 P0-CDIV) | **BUG-13 (P0-CDIV cross-cite)** — W154 BUG-3 documented that `get_next_bits` / `get_next_block_version` are dead-helpers (never wired on `Node`); GBT therefore emits the **previous epoch's bits** at every 2016-block adjustment boundary. The W156 audit found this still unfixed; this audit confirms persistence. The carry-forward note in MEMORY.md cross-references: W154 BUG-3 → W156 → W157. |
| 12 | fPowAllowMinDifficultyBlocks (testnet) | G28: testnet 20-min min-diff exception | PASS Python (line 1085-1087); Rust difficulty.rs:75-80. |
| 12 | … | G29: walk-back to last non-min-difficulty block | PASS Python (line 1092-1104); Rust difficulty.rs:85-96. |
| 12 | … | G30: signet has NO min-difficulty exception (`fPowAllowMinDifficultyBlocks=false`) | PASS — Python `_POW_ALLOW_MIN_DIFFICULTY_NETWORKS` (line 71) correctly excludes signet; Rust `pow_allow_min_difficulty_blocks: false` for signet (chain_params.rs:80). |
| 13 | signet on regtest (`signet_blocks` flag on regtest = false) | G31: regtest never triggers signet validator | PASS (validation.py:1558 early-returns when `self.network != "signet"`). |
| 14 | default signet_challenge vs custom | G32: operator can override default with `-signetchallenge=<hex>` | **BUG-6 cross-cite** — no operator knob exists. |
| 14 | … | G33: custom-signet recomputes `pchMessageStart` = `sha256(challenge)[0:4]` | **BUG-14 (P0-CDIV)** — Core line 477-479: `HashWriter h{}; h << signet_challenge; uint256 hash = h.GetHash(); std::copy_n(hash.begin(), 4, pchMessageStart.begin())`. ouroboros has NO equivalent — the message-start magic for signet would be whatever is hardcoded in p2p.py / msg_version.go (out of scope here but cross-cited). Consequence: even if BUG-6 were fixed, a custom-signet node would still wire to public-signet because the wire magic isn't network-keyed. |
| 14 | … | G34: signet bech32 hrp = "tb" (matches testnet3) | **BUG-15 (P1)** — rpc.py:11343-11347 sets `is_regtest = (network in ("regtest", "signet"))` and then `bech32_hrp = "bc" if is_mainnet else ("bcrt" if is_regtest else "tb")` — signet falls into the `is_regtest` arm and gets `"bcrt"`. Core says `bech32_hrp = "tb"` for signet (chainparams.cpp:510). RPC `decodescript` / `validateaddress` on signet emit bech32 addresses with the WRONG hrp. |
| — | OUROBOROS_*_STOPGAP env-var for signet/BIP-94? | G35: none plumbed | PASS (correctly none; only `OUROBOROS_BIP68_STOPGAP` exists, validation.py:2189). |
| — | (additional gates below in dedicated BUG sections) | G36..G44 — see BUG-16..BUG-24 | — |

---

## BUG-1 (P0-CDIV) — Signet block-solution validation is Python-only; Rust `connect_block_from_bytes` and `validate_block_from_bytes` skip it entirely

**Severity:** P0-CDIV. Core treats `CheckSignetBlockSolution` as a
mandatory consensus gate that is called from
`CheckBlock`/`ContextualCheckBlock` whenever `consensus.signet_blocks`
is true. The check runs unconditionally — there is no fast-path that
bypasses it.

ouroboros has TWO Rust-language block-acceptance pipelines that share
none of the signet logic with the Python one:

1. `ferrous-utils/sync/src/lib.rs:3402-3946` — `connect_block_from_bytes`
   (the production hot-path that block_sync.py routes IBD through;
   see block_sync.py:1083-1093 — "by default Rust only"). Inline
   consensus checks: PoW (3416-3491), merkle (3493-3511), prev-link
   (3513-3537), MTP-of-11 (3539-3572), coinbase-scriptSig-len
   (3574-3592), witness-commitment recompute (3594-3665), IsFinalTx
   (3667-3699). **No signet block-solution check.**

2. `ferrous-utils/sync/src/lib.rs:3347+` — `validate_block_from_bytes`
   (the "validate-only, no apply" path used when re-checking after a
   cross-check mismatch). Same gates as above. No signet check.

3. `ferrous-utils/sync/src/validate/block.rs:167-233` — `validate_block`
   (`BlockValidator::validate_block`, used by `FastSync` and the
   non-FFI Rust callers). No signet check.

Python `BlockValidator._validate_signet_solution` (validation.py:1554-1639)
runs only when the orphan / reorg / non-Rust path in `block_sync.py`
falls through to `self.validator.validate_block(block)` (line 2205,
3095). The Python `validate_block` is the **only** caller — and on a
signet IBD that routes through `connect_block_from_bytes`, the signet
gate is **skipped entirely**.

**Consequence on signet:** an attacker who controls a signet-network
miner could submit a block with:
- a PoW-valid header below the network's powLimit (0x1e0377ae),
- a syntactically valid coinbase,
- a witness commitment that omits the signet signature **OR** carries
  an invalid signature against the chain's challenge,

and ouroboros's Rust IBD path would ACCEPT the block, while Bitcoin
Core (and every other implementation in the fleet that wires the
signet check into Rust/Go/etc.) would reject with
`bad-signet-blksig`.

**Files:**
- `ferrous-utils/sync/src/lib.rs:3402-3946` (production pipeline)
- `ferrous-utils/sync/src/lib.rs:3347+` (validate-only pipeline)
- `ferrous-utils/sync/src/validate/block.rs:167-233` (Rust BlockValidator)
- `src/ouroboros/validation.py:720` (only Python call site)

**Core ref:** `bitcoin-core/src/signet.h:21`,
`bitcoin-core/src/signet.cpp:126-153`,
`bitcoin-core/src/validation.cpp` (call sites in `CheckBlock`).

**Impact:** **Three-pipeline drift, signet-specific divergence.**
This is the **fourth distinct N-pipeline drift instance** in ouroboros
that this multi-wave audit series has documented (W149 pruning had 6
distinct pipelines, W150 ATMP had 6, W151 RBF had 7, W156 BIP-152 had
8; this is the first time the pipelines diverge on **signet
consensus** specifically). Same architectural antipattern, new
consensus surface.

**Cross-cite (fleet pattern):**
W143 BUG-9 (blockbrew CheckSignetBlockSolution entirely missing —
"accepts any PoW-valid block, forks off signet at block 1"); MEMORY.md
priority queue item 10 ("blockbrew W143 CheckSignetBlockSolution") was
the same shape on Go. ouroboros has it in Python but NOT in Rust,
which is functionally equivalent to "missing" because Rust is the
production hot-path.

---

## BUG-2 (P1) — Comment-as-confession: signet "trivial challenge / OP_TRUE" fall-through documented but not implemented

**Severity:** P1 (correctness for custom OP_TRUE-challenge signets).
Core (signet.cpp:99-100) explicitly supports the case where
`FetchAndClearCommitmentSection` returns false (no signet section in
commitment): it falls through with empty scriptSig and witness,
relying on the script interpreter to satisfy the challenge only when
it is trivial (e.g. `OP_TRUE`). The comment at signet.cpp:100 says:
"no signet solution -- allow this to support OP_TRUE as trivial block
challenge".

ouroboros's Python validation.py:1580-1583 documents this case **with
an inline comment** but then unconditionally rejects:

```python
if commitment_script is None:
    # No witness commitment — check if the challenge is trivially
    # satisfiable (e.g. OP_TRUE).  Otherwise fail.
    return False, "Signet: no witness commitment in coinbase"
```

The comment says "check if the challenge is trivially satisfiable"
but the code is unconditional `return False`. This is the
**14th distinct comment-as-confession** in ouroboros (MEMORY.md
fleet pattern, ouroboros now holds the comment-as-confession record).

**Files:** `src/ouroboros/validation.py:1580-1583`.

**Core ref:** `bitcoin-core/src/signet.cpp:99-100`.

**Impact:** custom test-signets that use `OP_TRUE` (1-byte challenge
`0x51`) as their challenge cannot mine valid blocks against ouroboros
— the very first block above genesis is rejected with "Signet: no
witness commitment in coinbase" even though Core would accept it. The
`signet_blocks` test infrastructure used by Bitcoin Core devs for
ad-hoc signets is unusable.

Note: the **actual case Core fall-throughs is** "commitment exists AND
no SIGNET_HEADER push within it" (signet.cpp:99 returns false from
`FetchAndClearCommitmentSection`), not "no commitment at all" — Core
ALSO rejects no-commitment-at-all blocks via line 92 `if (cidx ==
NO_WITNESS_COMMITMENT) return std::nullopt`. So the Python "no
commitment → reject" is actually correct for the no-commitment case;
the BUG is that the OP_TRUE fall-through after `_extract_signet_commitment`
returns `None` is handled differently — Python sets
`signet_solution = b""` (line 1592) and proceeds to verify against the
**hardcoded default 1-of-2 multisig** (line 1610) which will fail. The
operator cannot configure a custom challenge (BUG-6) so the
OP_TRUE-trivial test signet workflow is permanently broken.

---

## BUG-3 (P0-CDIV) — `_extract_signet_commitment` accepts header-only push as "found", diverging from Core's strictly-greater test

**Severity:** P0-CDIV. Core `FetchAndClearCommitmentSection`
(signet.cpp:43) uses:

```cpp
if (!found_header && pushdata.size() > header.size() &&
    std::ranges::equal(std::span{pushdata}.first(header.size()), header)) {
    // pushdata only counts if it has the header _and_ some data
    result.insert(result.end(), pushdata.begin() + header.size(), pushdata.end());
    pushdata.erase(pushdata.begin() + header.size(), pushdata.end());
    found_header = true;
}
```

— note the comment "pushdata only counts if it has the header _and_
some data" and the comparison `pushdata.size() > header.size()`
(strictly greater than 4).

ouroboros's `_extract_signet_commitment` (validation.py:1679) uses:

```python
if len(data) >= 4 and data[:4] == SIGNET_HEADER:
    return data[4:]  # everything after the header
```

— this **accepts a header-only push** (exactly 4 bytes equal to
`SIGNET_HEADER`), returning `data[4:]` = `b""` (empty solution).

The downstream effect: when a coinbase contains an
`OP_RETURN 0x24 <commitment> 0x04 0xec 0xc7 0xda 0xa2` pattern (the
post-modification shape that Core writes back into the witness commitment
**precisely to indicate "I had a signet section but I'm not signing it
anymore"** during merkle-root computation), Core would treat the inbound
block as "no signet solution" and fall through to the OP_TRUE path.
ouroboros would treat this as "found, with empty solution" and then
attempt signature verification of the default 1-of-2 multisig against
an empty scriptSig (which will fail with "Signet: block signature
verification failed").

The two implementations therefore disagree on the **categorical
classification** of the block: Core says "no signet section, try
trivial-challenge fall-through"; ouroboros says "found, with empty
body, attempt full verify".

**Files:** `src/ouroboros/validation.py:1679-1680`.

**Core ref:** `bitcoin-core/src/signet.cpp:42-48`.

**Impact:** edge-case but consensus-divergent. A signet network whose
miners chose to publish blocks with the header-only-push shape (which
is the canonical "I had a signet section but I'm not signing it" form
that Core produces during merkle-root recomputation) would be split
between Core and ouroboros at the block-accept layer. On default-signet
the impact is bounded by the multisig requirement, but on custom-signet
with OP_TRUE the divergence is full hard fork.

---

## BUG-4 (P1) — `_compute_signet_merkle_root` is not Core's `ComputeModifiedMerkleRoot`

**Severity:** P1. Core's `ComputeModifiedMerkleRoot` (signet.cpp:59-68):

```cpp
std::vector<uint256> leaves;
leaves.reserve((block.vtx.size() + 1) & ~1ULL); // capacity rounded up to even
leaves.push_back(cb.GetHash().ToUint256());
for (size_t s = 1; s < block.vtx.size(); ++s) {
    leaves.push_back(block.vtx[s]->GetHash().ToUint256());
}
return ComputeMerkleRoot(std::move(leaves));
```

Note: leaf 0 is the **modified coinbase**'s `GetHash()` (the txid, NOT
the wtxid). Leaves 1..N are each tx's `GetHash()` (txids, again NOT
wtxids).

ouroboros's `_compute_signet_merkle_root` (validation.py:1715-1757):
- Rebuilds the modified coinbase (line 1741-1748).
- Computes `cb_hash = sha256(sha256(modified_cb.serialize()))` (line
  1750-1751). **PROBLEM:** `modified_cb.serialize()` may include
  witness bytes (depends on the `Transaction.serialize()`
  implementation in database.py — if it emits BIP-141 format when
  `has_witness`, the hash will be the wtxid, not the txid).
- Builds `txids = [cb_hash] + [tx.get_txid() for tx in block.transactions[1:]]`
  (line 1753-1755) — uses `get_txid()` for non-coinbase, which by
  contract returns the **non-witness** txid, matching Core's `GetHash`.

The inconsistency is at leaf 0: Core unambiguously uses the txid
(non-witness hash) of the modified coinbase. ouroboros uses the
output of `sha256d(modified_cb.serialize())`, whose witness-bit
depends on the `Transaction.serialize()` implementation — which is
NOT visible from this file and may include or exclude witness bytes
depending on whether the modified coinbase carries witness data.

The coinbase always has a witness (the 32-byte nonce in
`witness[0]`), so if `serialize()` emits BIP-141 format, the hash
WILL include witness bytes and diverge from Core.

**Files:** `src/ouroboros/validation.py:1715-1757`.

**Core ref:** `bitcoin-core/src/signet.cpp:59-68`.

**Impact:** signet merkle-root divergence — every signet block above
the SegWit activation (which on signet is `BIP9 ALWAYS_ACTIVE` at
height 1) would compute a different `signet_merkle` between Core and
ouroboros, causing the `to_spend` virtual transaction's
`scriptSig` (= OP_0 PUSH72 <block_data>) to commit to different bytes,
causing `to_sign`'s sighash to differ, causing the multisig
verification to fail. Effectively: **all signet blocks fail signature
verification** on ouroboros even though they pass on Core.
(This may already be papered over by BUG-6: since there's no operator
knob and the path is Python-only — see BUG-1 — the path may simply
never be reached in production.)

---

## BUG-5 (P1) — `_parse_signet_solution` silently truncates malformed witness instead of rejecting

**Severity:** P1. Core (signet.cpp:104-109) reads:

```cpp
SpanReader v{signet_solution};
v >> tx_spending.vin[0].scriptSig;
v >> tx_spending.vin[0].scriptWitness.stack;
if (!v.empty()) return std::nullopt; // extraneous data encountered
```

— note both the unwrap-via-SpanReader (which `throw`s on truncation,
caught at signet.cpp:107 with `return std::nullopt`) AND the
extraneous-data check at line 106.

ouroboros's `_parse_signet_solution` (validation.py:1684-1713):
- Line 1706-1707 silently `break`s on truncation:
  ```python
  for _ in range(n_items):
      if offset >= len(solution):
          break
      item_len, consumed = _read_compact_size(solution, offset)
      ...
  ```
  Returns a witness shorter than `n_items` claims, instead of
  rejecting.
- No extraneous-data check after the witness loop — any trailing bytes
  are silently dropped.

**Files:** `src/ouroboros/validation.py:1684-1713`.

**Core ref:** `bitcoin-core/src/signet.cpp:101-109`.

**Impact:** malformed signet solutions that Core would reject with
`std::nullopt` (→ `CheckSignetBlockSolution` returns false → block
rejected with `bad-signet-blksig`) are silently parsed by ouroboros
into a truncated witness, then verified against the challenge — likely
failing for the same end-result, but the *categorical* classification
differs (Core: parse-fail; ouroboros: script-fail) which manifests as
different reject reasons reported to peers, and provides a malleability
surface (different bytes parse to the same effective solution).

---

## BUG-6 (P0-CDIV) — `signet_challenge` is NOT a chain parameter; custom signets unsupported

**Severity:** P0-CDIV ("operator-knob absence" fleet pattern; first
ouroboros instance for signet specifically). Core's
`SigNetParams(SigNetOptions opts)` (chainparams.cpp:411-516) takes the
challenge via `opts.challenge`:

```cpp
if (!options.challenge) {
    bin = "512103ad...430210359...c452ae"_hex_v_u8;  // default 1-of-2 multisig
    ...
} else {
    bin = *options.challenge;
    ...
    LogInfo("Signet with challenge %s", HexStr(bin));
}
...
consensus.signet_challenge.assign(bin.begin(), bin.end());
```

The operator sets the challenge via `-signetchallenge=<hex>` CLI flag
(init.cpp). The chain params then carry the (possibly-custom) challenge
through to `CheckSignetBlockSolution`.

In ouroboros:
- `ConsensusParams` (chain_params.rs:12-34) has NO `signet_challenge`
  field.
- The Python `BURIED_DEPLOYMENTS["signet"]` / `BIP9_DEPLOYMENTS["signet"]`
  tables (consensus.py:149-156, 322-341) have no challenge entry.
- `Node` (node.py) has NO `signet_challenge` attribute (test
  test_w123_mining_gbt.py:664-672 verifies this as a regression
  contract).
- `cli.py:115` lists `--network` choice but provides no
  `--signetchallenge` / `--signetseednode` flag.
- `validation.py:1610` hardcodes
  `challenge = DEFAULT_SIGNET_CHALLENGE` (the
  module-level Bitcoin Core public-signet multisig constant from
  line 82-86).

**Consequences:**
1. **Custom signets are unsupported.** An operator running their own
   private test-signet network with their own multisig challenge
   cannot configure ouroboros to validate against it. ouroboros will
   reject every block in the custom-signet chain because the
   chain's blocks are signed against a different challenge than the
   hardcoded default.
2. **No "test-only signet"** workflow (Bitcoin Core devs frequently
   spin up ad-hoc signets with OP_TRUE or single-pubkey challenges
   for testing soft-forks).
3. **`getblockchaininfo` / `getmininginfo` cannot report
   `signet_challenge`** — there's no field to read.
4. **GBT cannot pass `signet_challenge`** (BIP-22 extension; cross-cite
   test_w108_gbt.py:412-419) so signet miners using ouroboros as their
   GBT source cannot construct valid coinbase signet-commitment outputs.

**Files:**
- `ferrous-utils/sync/src/chain_params.rs:12-34` (ConsensusParams
  struct, no field)
- `ferrous-utils/sync/src/chain_params.rs:78-85` (Signet branch of
  `get_consensus_params`, no field set)
- `src/ouroboros/validation.py:82-86` (hardcoded default), line 1610
  (hardcoded use)
- `src/ouroboros/cli.py:115` (no flag)
- `src/ouroboros/config.py` (no parse)
- `src/ouroboros/node.py` (no attribute; test asserts absence)

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:411-453`
(SigNetParams), `bitcoin-core/src/kernel/chainparams.h::SigNetOptions`.

**Impact:** **custom signet entirely unusable**. Default-signet also
fragile because BUG-4 (modified merkle) and BUG-3
(extract-header-only-push) mean the hardcoded default may not even
verify against legitimate default-signet blocks.

---

## BUG-7 (P0-CDIV) — `_validate_signet_solution` reverse-scans for the first matching witness commitment instead of consulting `GetWitnessCommitmentIndex`

**Severity:** P0-CDIV. Core's `SignetTxs::Create` calls
`GetWitnessCommitmentIndex(block)` (signet.cpp:91), which returns the
index of the **LAST** output in the coinbase that matches the
witness-commitment pattern (consensus/validation.cpp's
`GetWitnessCommitmentIndex` scans `coinbase->vout` in reverse and
returns the first hit — so it picks the **last** matching output by
file order).

ouroboros's `_validate_signet_solution` (validation.py:1567-1578):

```python
commitment_script = None
for out in reversed(coinbase.outputs):
    spk = out.script_pubkey
    if (
        len(spk) >= 38
        and spk[0] == 0x6A          # OP_RETURN
        and spk[1] == 0x24          # push 36 bytes
        and spk[2:6] == self._WITNESS_COMMITMENT_MAGIC
    ):
        commitment_script = spk
        break
```

This iterates `reversed(coinbase.outputs)` and breaks on first match
— so it picks the same output Core would pick (the last by file
order). PASS for this iteration.

BUT `_compute_signet_merkle_root` (validation.py:1722-1738) iterates
the coinbase outputs in **forward** order and modifies the **first**
matching output (line 1722-1734 — `for out in coinbase.outputs`,
match-and-modify, append-modified-or-original). If the coinbase has
**two** witness-commitment outputs (rare but legal — pre-segwit
miners may have written multiple OP_RETURN outputs; Core's
`GetWitnessCommitmentIndex` defines "the right one" as the last):

- `_validate_signet_solution` (line 1568-1578) uses the LAST commitment
  output (correct).
- `_compute_signet_merkle_root` (line 1722-1738) modifies the FIRST
  commitment output (WRONG — leaves the LAST one unmodified, then
  computes a merkle root over coinbases where the signet section is
  still in the LAST output).

The two-pipeline divergence inside the same file recomputes
different modified merkle roots than Core, causing signature
verification to fail on the rare case of a coinbase with multiple
commitment outputs.

**Files:** `src/ouroboros/validation.py:1567-1578` (reverse, correct)
vs `src/ouroboros/validation.py:1722-1738` (forward, incorrect).

**Core ref:** `bitcoin-core/src/signet.cpp:91` (uses
GetWitnessCommitmentIndex — reverse iteration);
`bitcoin-core/src/consensus/validation.cpp::GetWitnessCommitmentIndex`.

**Impact:** **two-pipeline guard, 18th distinct ouroboros instance
this audit series.** The two halves of the same `_validate_signet_solution`
flow disagree on which commitment output to operate on. The bug is
latent on default-signet (which only emits one commitment) but
guaranteed-divergent on any block with multiple commitment outputs.

---

## BUG-8 (P0-CDIV) — BIP-94 timewarp gate hardcoded to `self.network == "testnet4"` instead of `enforce_BIP94` flag

**Severity:** P0-CDIV (consensus param wiring). Core's `enforce_BIP94`
is a per-network bool that can be SET on networks beyond testnet4:
- testnet4: `enforce_BIP94 = true` (chainparams.cpp:322)
- mainnet/testnet3/signet: `enforce_BIP94 = false` (chainparams.cpp:100, 223, 464)
- regtest: `enforce_BIP94 = opts.enforce_bip94` (chainparams.cpp:547) — **operator-settable**

The gate's location in `ContextualCheckBlockHeader` (validation.cpp:4097)
reads `consensusParams.enforce_BIP94` directly. Future networks (or a
hypothetical mainnet activation of BIP-94, which is being proposed for
2027+) would set the flag and have the gate fire without source
changes.

ouroboros's Python validation.py:1000-1003:

```python
if self.network == "testnet4" and height > 0:
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
        if block.timestamp < prev_block.timestamp - MAX_TIMEWARP:
            return False
```

The string-comparison gate `self.network == "testnet4"` means:
- regtest cannot exercise BIP-94 ever (even though Core supports it).
- If/when BIP-94 ships to mainnet (proposal exists per BIP-94 wiki),
  ouroboros would need a source change.
- Custom signets that opt-in to BIP-94 cannot do so.

The Rust path's `validate_block_from_bytes` / `connect_block_from_bytes`
(lib.rs:3402+) has NO BIP-94 timewarp check **at all**, regardless of
network — see BUG-1 / BUG-10.

**Files:**
- `src/ouroboros/validation.py:1000-1003`
- `ferrous-utils/sync/src/lib.rs:3402-3946` (no BIP-94 check)
- `ferrous-utils/sync/src/validate/header.rs:203-233`
  (`validate_timestamp` has no BIP-94 check either)

**Core ref:** `bitcoin-core/src/validation.cpp:4097-4105`;
`bitcoin-core/src/consensus/params.h:121`.

**Impact:** BIP-94 wiring is **soft-hardcoded** instead of consensus-
param-driven. The gate may fire on testnet4 today, but is
non-portable to any other network — including regtest functional tests
that exercise the BIP-94 mitigation, which CANNOT be written in
ouroboros today.

---

## BUG-9 (P1) — Regtest `opts.enforce_bip94` operator-knob absent

**Severity:** P1. Core lets the regtest operator opt INTO BIP-94 via
test-only options (chainparams.cpp:547:
`consensus.enforce_BIP94 = opts.enforce_bip94;`). The mechanism is
typically the `-vbparams` or `-testactivationheight` CLI flag set in
unit tests. This is how Core's functional-test suite exercises BIP-94
without needing testnet4 connectivity.

ouroboros:
- `chain_params.rs:70-77` hardcodes regtest `enforce_bip94: false`.
- `cli.py` does not surface any `--enforce-bip94` flag.
- The Python BIP-94 gate is keyed by `self.network` string (BUG-8), not
  a settable bool — so even if the Rust side were changed, the Python
  gate would still ignore it.

**Files:**
- `ferrous-utils/sync/src/chain_params.rs:70-77`
- `src/ouroboros/cli.py`
- `src/ouroboros/validation.py:1000`

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547`.

**Impact:** regtest functional tests cannot exercise BIP-94 timewarp
gate; cross-impl divergence in test capability.

---

## BUG-10 (P0-CDIV) — Rust path has no `MAX_TIMEWARP` constant and no BIP-94 enforcement

**Severity:** P0-CDIV. Grep over `ferrous-utils/sync/src/` for
`MAX_TIMEWARP` / `timewarp` / `BIP94` / `BIP-94` (excluding tests and
deprecated-wrapper comments) returns:
- `difficulty.rs:4` — comment.
- `difficulty.rs:119,127,153,158,195-203` — comments + the
  `calculate_next_work_required` BIP-94 base-bits branch (line 159).
- `chain_params.rs:27,66,478` — the `enforce_bip94: bool` field on
  ConsensusParams, set true for testnet4.

The **timewarp boundary check** (BIP-94 second-half: at retarget
boundary reject `block.time < prev.time - 600`) is NOT in any Rust
file. Only the **difficulty retarget base-bits** half is wired
(difficulty.rs:159). Both halves are required for BIP-94 to mitigate
the time-warp attack.

`connect_block_from_bytes` (the production hot-path) checks MTP-of-11
(lib.rs:3556-3565) but does NOT check `block.time < prev.time - 600`
at retarget boundaries on testnet4 OR any other network.

`HeaderValidator.validate_timestamp` (header.rs:203-233) has a
comment-as-confession (line 215-227) admitting it skips the backward
timestamp check entirely as a "simplified version" — even basic
MTP enforcement is missing from this path.

**Files:**
- `ferrous-utils/sync/src/lib.rs:3402-3946` (connect path)
- `ferrous-utils/sync/src/validate/header.rs:203-233` (header validator)
- `ferrous-utils/sync/src/validate/block.rs` (block validator, no
  timestamp gate beyond what header validator does)

**Core ref:** `bitcoin-core/src/validation.cpp:4097-4105`.

**Impact:** on testnet4 IBD through the Rust path, an attacker who
controls a min-difficulty miner can craft retarget-boundary blocks
with `block.time = prev.time - 601` (one second outside the BIP-94
window) and ouroboros's Rust path would accept them — exactly the
time-warp attack BIP-94 was designed to mitigate. Core would reject
with `time-timewarp-attack`. **Same severity as BUG-1** but specific
to the timewarp gate rather than the signet block solution.

---

## BUG-11 (P0-CDIV) — GBT `mintime` ignores BIP-94 boundary clamp

**Severity:** P0-CDIV. Core's `GetMinimumTime` (miner.cpp:36-46) — as
of v25 — clamps mintime at every retarget boundary on **ALL networks**
(no `enforce_BIP94` gate around the clamp; the gate is intentionally
absent so that the clamp is future-proof for any network that activates
BIP-94 later):

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

ouroboros's rpc.py:5258-5259:

```python
mtp_plus_one = block_mtp + 1
curtime = max(mtp_plus_one, int(_time.time()))
```

— and rpc.py:5325 emits `"mintime": mtp_plus_one`. No BIP-94 clamp on
any network.

This is asserted-as-regression-contract by **TWO** test files:
- `test_w108_gbt.py:296-309` (test name:
  `test_mintime_is_only_mtp_plus_one` — explicit asserts wrong
  behaviour, **3rd "test-asserts-the-bug" pattern this audit**).
- `test_w123_mining_gbt.py:318-324` (test name:
  `test_bip94_max_timewarp_arm_not_wired` — same shape, different
  file).

**Files:** `src/ouroboros/rpc.py:5258-5259, 5325`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-46`.

**Impact:** miners using ouroboros's GBT to construct testnet4 blocks
at retarget boundaries can receive a `mintime` that is below the
BIP-94 lower bound; the block they construct will then be rejected
by Core peers with `time-timewarp-attack`. **This is a miner-side
consensus failure** specific to testnet4 retarget boundaries (every
2016 blocks).

---

## BUG-12 (P0-CDIV) — `_validate_header` BIP-94 gate is keyed by `network` string, not by `enforce_BIP94`

**Severity:** P0-CDIV (carry-forward of BUG-8 wiring). The Python
validator's BIP-94 timewarp gate (validation.py:1000-1003):

```python
if self.network == "testnet4" and height > 0:
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
        if block.timestamp < prev_block.timestamp - MAX_TIMEWARP:
            return False
```

This is essentially **BUG-8 restated** but worth listing separately
because it concretely shows what BUG-8's architectural absence
(no `enforce_bip94` plumbed through Python) causes: any operator-set
BIP-94 on regtest (G15/G21) cannot fire here even if the Rust path
were updated. The gate cannot be turned on without source-modifying
this line.

**Files:** `src/ouroboros/validation.py:1000-1003`.

**Core ref:** `bitcoin-core/src/validation.cpp:4097`.

**Impact:** documented as a separate BUG to ensure the fix touches
both the consensus-param plumbing AND the gate site.

---

## BUG-13 (P0-CDIV cross-cite W154 BUG-3) — `get_next_bits` / `get_next_block_version` dead-helpers still unwired

**Severity:** P0-CDIV. W154 BUG-3 documented and W156 confirmed that:
- rpc.py:5246-5249 calls `node.get_next_block_version` if available.
- rpc.py invokes `node.get_next_bits` (per W154 audit; not directly
  visible in the excerpt read here, but the audit lineage is clear).
- The `Node` class never implements either method.
- The fallback path emits the **previous epoch's bits** at every
  2016-block adjustment boundary.

This audit cross-cites: the same dead-helper still flows into the
BIP-94 path (because the BIP-94 base-bits calculation needs to know
what `pindexFirst.bits` is, which is the same calculation path as
GBT's `bits` field). Until both helpers are wired, BIP-94's defense
against the time-warp attack is doubly broken: the miner-side GBT
(BUG-11) ships the wrong bits AND the wrong mintime simultaneously.

**Files (W154 → W156 → W157 carry-forward):**
- `src/ouroboros/rpc.py:5246-5252, 5320-5322`
- `src/ouroboros/node.py` (methods absent)

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1009` (uses
`GetNextWorkRequired`).

**Impact:** confirms the W154 finding remains unfixed across W155,
W156, W157 — **4-wave carry-forward** of the same P0-CDIV bug.

---

## BUG-14 (P0-CDIV) — Custom-signet `pchMessageStart` recomputation missing

**Severity:** P0-CDIV. Core (chainparams.cpp:475-479):

```cpp
// message start is defined as the first 4 bytes of the sha256d of the block script
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

Each custom signet derives its **own unique p2p message-start magic**
from `sha256(signet_challenge)[0..4]`. This is what prevents a
custom-signet node from accidentally peering with default-signet —
the wire-magic mismatch rejects the handshake at the very first
message.

ouroboros has no plumbing for either:
- a configurable `signet_challenge` (BUG-6), so per-challenge magic
  is meaningless without that knob,
- the recomputation function itself: there is no `derive_signet_magic(challenge)`
  helper in either chain_params.rs or any Python module.

The default-signet magic is presumably hardcoded somewhere in
`p2p.py` or `p2p_messages.py` (not surveyed in this audit; out of
scope for the signet-block-solution focus).

**Files:**
- `ferrous-utils/sync/src/chain_params.rs` (no derivation)
- `src/ouroboros/p2p.py` / `p2p_messages.py` (presumably hardcoded;
  cross-cite needed)

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:475-479`.

**Impact:** any future custom-signet support would need this missing
function. Until BUG-6 is fixed it's a latent gap; once BUG-6 is
fixed it becomes a P0-CDIV active gap.

---

## BUG-15 (P1) — `bech32_hrp` for signet incorrectly returns "bcrt" via `is_regtest` conflation

**Severity:** P1 (RPC interop). rpc.py:11343-11347:

```python
network = getattr(self.node, "network", "mainnet")
is_mainnet = (network == "mainnet")
is_regtest = (network in ("regtest", "signet"))     # <-- conflates signet with regtest
p2sh_ver = b"\x05" if is_mainnet else b"\xc4"
bech32_hrp = "bc" if is_mainnet else ("bcrt" if is_regtest else "tb")
```

Core says (chainparams.cpp:510): `bech32_hrp = "tb"` for signet.
ouroboros says "bcrt" because the `is_regtest` flag includes signet.

**Files:** `src/ouroboros/rpc.py:11343-11347`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:510`.

**Impact:** RPC `decodescript` / `validateaddress` on signet emit
bech32 addresses with the **wrong human-readable prefix**.
Wallet-software that calls these RPCs to derive watch-only addresses
will store unspendable bech32 strings (signet `tb1...` addresses
encoded as `bcrt1...`). End-user funds-loss risk on signet wallets that
rely on ouroboros's RPC for address derivation.

---

## BUG-16 (P0-CDIV) — Signet genesis hash hex string is **31 bytes**, not 32

**Severity:** P0-CDIV. node.py:814-815:

```python
'signet':   bytes.fromhex(
    'f61eee3b63a380a477a063af32b2bbc9f7990f1f2c4225e973988181080000'),
```

Hex-length check:

```
f61eee3b 63a380a4 77a063af 32b2bbc9 f7990f1f 2c4225e9 73988181 080000
8 chars   8 chars  8 chars  8 chars  8 chars  8 chars  8 chars  6 chars  = 62 chars = 31 bytes
```

Correct internal-byte-order signet genesis (Core display:
`00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`,
reversed):

```
f61eee3b 63a380a4 77a063af 32b2bbc9 7c9ff9f0 1f2c4225 e9739881 08000000
8 chars   8 chars  8 chars  8 chars  8 chars  8 chars  8 chars  8 chars  = 64 chars = 32 bytes
```

(Cross-check: the Rust value at `chain_params.rs:129-134` is the
correct 32-byte signet internal hash; the Python `GENESIS_HASHES`
table disagrees with the Rust table.)

The bug manifests during signet `_init_genesis`: `genesis_hash` is a
31-byte value passed to `self.db.update_best_block(genesis_hash, 0)`
(line 896). On a Rust DB implementation that requires `&[u8; 32]`,
this **panics on signet startup** with a slice-length mismatch
exception, taking down the node before any block is processed.

**Files:** `src/ouroboros/node.py:814-815`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:486` —
hash should be 32 bytes.

**Impact:** **signet startup is broken from day 1.** This audit is
the first to catch it; the path is only reached when an operator
attempts `--network signet`, which no fleet member has done in
production.

---

## BUG-17 (P1) — `_SEGWIT_ACTIVATION["signet"] = 0` diverges from Core's `SegwitHeight = 1`

**Severity:** P1. Core (chainparams.cpp:460): `consensus.SegwitHeight = 1`
for signet. The genesis block (height 0) does NOT have SegWit active;
SegWit is active for every block from height 1 onward.

ouroboros's `_SEGWIT_ACTIVATION["signet"] = 0` (validation.py:1311) means
witness commitments are required from height 0 — but the genesis
block has no witness commitment (Core's genesis is pre-segwit by
construction). The `_validate_witness_commitment` path (validation.py:1335)
gates on `height >= activation`, which with activation=0 would require
genesis to carry a commitment.

This bug is partially masked by the `_validate_signet_solution`
genesis short-circuit (line 1562-1563), but `_validate_witness_commitment`
runs FIRST (validation.py:715). On signet genesis, this will reject
the block with `unexpected-witness` if the genesis carries witness
data, or with the no-commitment branch if it doesn't.

**Cross-check:** `_SEGWIT_ACTIVATION["regtest"] = 0` is **also wrong**
per Core's `chainparams.cpp:642` which sets `SegwitHeight = 0` for
regtest (note: regtest is the ONE network where SegWit activates at
height 0 in Core's actual model — `chainparams.cpp` shows `SegwitHeight = 0`
explicitly). So regtest=0 is actually correct, but signet=0 is wrong
(should be 1).

`_SEGWIT_ACTIVATION["testnet4"] = 0` is also wrong (Core sets
`SegwitHeight = 1`, chainparams.cpp:316). Same shape as signet bug.

**Files:** `src/ouroboros/validation.py:1306-1313`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:316, 460, 642`.

**Impact:** signet and testnet4 genesis-block acceptance may fail.
Cross-cite W143's "reorg-skips-CheckBlock" pattern — this is the same
shape as a per-network constants table that disagrees with Core.

---

## BUG-18 (P1) — `validate_difficulty` in Rust `HeaderValidator` is body-empty (intentionally)

**Severity:** P1 (architectural admission). header.rs:248-263:

```rust
fn validate_difficulty(&self, header: &Header, prev_header: &Header) -> Result<()> {
    // For now, use simplified validation
    // In production, this would use get_next_work_required based on height

    let expected_bits = prev_header.bits.to_consensus();
    let actual_bits = header.bits.to_consensus();

    // Allow some tolerance for difficulty adjustments
    // This is a simplified check - real validation is more complex
    if actual_bits != expected_bits {
        // For testing purposes, accept the difficulty
        // In production, this would be much stricter
    }

    Ok(())
}
```

The body is a **no-op**. The comment explicitly says "For testing
purposes, accept the difficulty // In production, this would be much
stricter". This is the **15th distinct comment-as-confession** in
ouroboros (and counting — this audit alone has added 3).

Combined with:
- `validate_timestamp` skipping the backward-MTP check (header.rs:215-227)
- `validate_chain_difficulty_adjustments` using a "10% heuristic"
  instead of Core's strict `PermittedDifficultyTransition`
  (header.rs:282-289)

the entire `HeaderValidator` chain is effectively non-validating in
test mode and Core-divergent in production. The only saving grace
is that `connect_block_from_bytes` does its own inline PoW check
(lib.rs:3416-3491) — but it also has no difficulty-retarget gate, no
BIP-94 enforcement, no timewarp clamp, etc.

**Files:** `ferrous-utils/sync/src/validate/header.rs:215-227, 248-263, 282-289`.

**Core ref:** `bitcoin-core/src/pow.cpp:14-48` (GetNextWorkRequired),
`bitcoin-core/src/pow.cpp:89-136` (PermittedDifficultyTransition).

**Impact:** Rust `HeaderValidator` is **not consensus-grade**. The
production path side-steps it via `connect_block_from_bytes` direct
inline checks, but any code that calls `header_validator.validate_header`
directly (any future caller — e.g. headers-first sync, a parallel
header validator, etc.) inherits the no-op gate.

---

## BUG-19 (P1) — `calculate_next_difficulty` in pow.rs hardcodes mainnet `TARGET_TIMESPAN` and ignores signet/regtest

**Severity:** P1 (architectural drift). pow.rs:64-89:

```rust
pub fn calculate_next_difficulty(prev_bits: u32, actual_timespan: u32) -> u32 {
    // Constants for mainnet difficulty adjustment
    const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 2 weeks in seconds
    ...
}
```

The comment "Constants for mainnet difficulty adjustment" is itself a
**comment-as-confession**. The function is called from
`HeaderValidator.get_next_work_required` (header.rs:192) and is the
only difficulty-retarget path in the legacy Rust header validator.
It has no `network` / `params` argument, no BIP-94 branch, no
testnet min-difficulty walk-back.

`difficulty.rs::calculate_next_work_required` (the canonical
implementation, BIP-94-aware) is the **correct** function; this legacy
function should have been deleted years ago. It survives as
dead-code-but-called-by-the-legacy-header-validator.

**Files:** `ferrous-utils/sync/src/validate/pow.rs:64-89`.

**Core ref:** N/A (this is a Rust-side architectural drift between two
in-tree difficulty implementations).

**Impact:** the legacy header validator uses the wrong (mainnet-only)
difficulty calc; the Rust system has TWO difficulty-calc functions
that disagree on testnet/signet/BIP-94. Two-pipeline drift within
the Rust crate.

---

## BUG-20 (P1) — Custom signet `chainTxData` / `m_assumed_blockchain_size` zeroed; not configurable

**Severity:** P1. Core's `SigNetParams` (chainparams.cpp:434-445)
sets `chainTxData = ChainTxData{0, 0, 0}` when the operator passes
`opts.challenge`, and `m_assumed_blockchain_size = 0` /
`m_assumed_chain_state_size = 0`. This is the correct safe default
for an unknown custom signet (no progress estimation possible) and is
explicitly distinct from the default-signet path which carries real
counts.

ouroboros's per-network metadata is hardcoded in `consensus.py` /
`chain_params.rs` (no path for "this is a custom-signet, blank the
stats"). Once BUG-6 is fixed and custom signets are supported,
the `getblockchaininfo` `verificationprogress` math will report
nonsense values (likely 100% from block 1) because the metadata is
hardcoded for default-signet.

**Files:** `src/ouroboros/consensus.py`, `ferrous-utils/sync/src/chain_params.rs`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:434-445`.

**Impact:** latent (depends on BUG-6 fix); reported here for fleet-wide
custom-signet readiness.

---

## BUG-21 (P0-CDIV) — `BLOCK_SCRIPT_VERIFY_FLAGS` for signet is hardcoded but DERSIG/NULLDUMMY may differ from Core's evolving constant

**Severity:** P0-CDIV (constants drift). Core's
`BLOCK_SCRIPT_VERIFY_FLAGS` (signet.cpp:30) is currently
`P2SH | WITNESS | DERSIG | NULLDUMMY`. The constant is defined in
signet.cpp and is therefore version-coupled — Core devs can
expand the flag set in a future release (e.g. add TAPROOT to support
signets that use taproot script-path challenges).

ouroboros's `SIGNET_SCRIPT_FLAGS` (validation.py:89-94) is also
`P2SH | WITNESS | DERSIG | NULLDUMMY`. Matches today. But:
- The constant is defined inline in validation.py, not in a
  cross-impl constants file. Future Core changes will not propagate.
- There is no comment linking it to Core's `BLOCK_SCRIPT_VERIFY_FLAGS`
  in signet.cpp:30, so future maintainers may not realize the
  coupling.
- W144 documented that **9 of 10** fleet impls have
  `script_flag_exceptions` table absent/incomplete; this is a
  signet-specific instance of the same shape.

**Files:** `src/ouroboros/validation.py:89-94`.

**Core ref:** `bitcoin-core/src/signet.cpp:30`.

**Impact:** version-coupling bug. If/when Core extends
`BLOCK_SCRIPT_VERIFY_FLAGS` (e.g. for a future signet TAPROOT
challenge type), ouroboros will diverge silently.

---

## BUG-22 (P1) — Default-signet challenge constant duplicated between Python and (absent) Rust

**Severity:** P1 (code-duplication smell). The default signet challenge
1-of-2 multisig is defined as:

- Python: `DEFAULT_SIGNET_CHALLENGE` at validation.py:82-86.
- Rust: NOWHERE. `chain_params.rs::get_consensus_params(Signet)` does
  not carry the challenge; `BlockValidator` does not reference it.

If/when BUG-1 is fixed by wiring signet check into Rust, the constant
will need to be duplicated. Today's absence-by-omission already
documents the gap.

**Files:** `src/ouroboros/validation.py:82-86`,
`ferrous-utils/sync/src/chain_params.rs:78-85`.

**Impact:** when BUG-1 is fixed, two copies will exist; W142 audited
this exact "byte-identical helper" smell on beamchain merkle code as
BUG-class.

---

## BUG-23 (P1) — `validate_pow` uses `<=` (allowing hash == target) — correct, but documented inconsistently

**Severity:** P1 (documentation drift). pow.rs:17-30 — `validate_pow`
returns `hash_u256 <= target` (line 29). Comment at line 9 says "The
header hash must be less than or equal to the target". Comment at line
28 says "Header hash must be <= target". Both consistent.

Core (`pow.cpp:167`): `if (UintToArith256(hash) > bnTarget) return false`
— i.e. returns true on `<=`. **Match.**

Reported as a pseudo-bug because the inline `connect_block_from_bytes`
PoW check at lib.rs:3471-3490 reimplements the comparison and uses a
loop with `<` / `>` early-exits and an `if i == 0 { pow_ok = true }`
all-bytes-equal handler:

```rust
let hash_le = &block_hash;
let mut pow_ok = false;
for i in (0..32).rev() {
    if hash_le[i] < target[i] { pow_ok = true; break; }
    else if hash_le[i] > target[i] { break; }
    if i == 0 { pow_ok = true; }
}
```

This is correct and Core-equivalent, but it's a **second** PoW check
implementation (the first is `validate_pow` in pow.rs). Two
implementations of the same primitive that have to stay in sync.
Same shape as the difficulty-calc two-pipeline (BUG-19).

**Files:** `ferrous-utils/sync/src/validate/pow.rs:17-30`,
`ferrous-utils/sync/src/lib.rs:3416-3491`.

**Impact:** doubled maintenance surface; latent risk if one
implementation is updated without the other.

---

## BUG-24 (P1) — `_validate_header` `_get_expected_bits` regtest path returns hardcoded `0x207fffff` instead of `prev_block.bits`

**Severity:** P1 (regtest interop). validation.py:1067-1070:

```python
# fPowNoRetargeting: regtest always stays at the minimum difficulty.
# Ref: Bitcoin Core pow.cpp:52-53.
if self.network == "regtest":
    return 0x207fffff
```

Core's `fPowNoRetargeting` path (`pow.cpp:52-53`) returns
`pindexLast->nBits`, **not** `pow_limit`. On a regtest where the
operator has manually mined blocks with `bits` different from
`0x207fffff` (e.g. via `generatetoaddress` followed by a custom-bits
test scenario), ouroboros would over-restrict — `block.bits` must
equal `0x207fffff` even though Core would accept `prev_block.bits`
unchanged.

In practice all standard regtest blocks have `bits = 0x207fffff`
because `generatetoaddress` uses the pow_limit, so the bug is latent.
But functional tests that exercise non-pow-limit bits on regtest
(rare but valid) would diverge.

**Files:** `src/ouroboros/validation.py:1067-1070`.

**Core ref:** `bitcoin-core/src/pow.cpp:52-53`.

**Impact:** latent on standard regtest; active on
custom-difficulty regtest tests.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CDIV:** 10 (BUG-1, BUG-3, BUG-6, BUG-7, BUG-8, BUG-10, BUG-11,
  BUG-12, BUG-13, BUG-14, BUG-16, BUG-21) — recount: BUG-1, BUG-3,
  BUG-6, BUG-7, BUG-8, BUG-10, BUG-11, BUG-12, BUG-13, BUG-14, BUG-16,
  BUG-21 = **12**
- **P1:** 12 (BUG-2, BUG-4, BUG-5, BUG-9, BUG-15, BUG-17, BUG-18,
  BUG-19, BUG-20, BUG-22, BUG-23, BUG-24)
- **P0-CONS:** 0 (no full chain-split in production today because
  signet is not yet operationally deployed and Rust path absence is
  silent-accept rather than reject)

Total: 12 + 12 = **24**. ✓

**Fleet patterns confirmed:**

- **N-pipeline drift (4th distinct layer, 18+ ouroboros instances
  total)** — BUG-1 documents three separate Rust pipelines
  (`connect_block_from_bytes`, `validate_block_from_bytes`,
  `validate/block.rs::validate_block`) + one Python pipeline
  (`BlockValidator.validate_block`) on signet block-solution gating.
  Continues the W149 (6) → W150 (6) → W151 (7) → W156 (8) lineage.
  This audit also flags TWO additional intra-pipeline drifts:
  - BUG-7: `_validate_signet_solution` reverse-scan vs
    `_compute_signet_merkle_root` forward-scan (within same Python
    file).
  - BUG-19: `calculate_next_work_required` (difficulty.rs) vs
    `calculate_next_difficulty` (pow.rs) — two BIP-94-non-aware vs
    BIP-94-aware difficulty calcs in the same crate.
  - BUG-23: `validate_pow` (pow.rs) vs inline PoW check
    (connect_block_from_bytes) — two implementations of the same
    primitive.

- **Comment-as-confession (3 new instances this audit; ouroboros
  total ~16)** — BUG-2 ("trivial challenge / OP_TRUE comment but
  unconditional fail"), BUG-18 ("For testing purposes, accept the
  difficulty"), BUG-19 ("Constants for mainnet difficulty
  adjustment").

- **Test-asserts-the-bug as regression contract (3rd instance fleet-wide)**
  — BUG-11 has TWO test files (test_w108_gbt.py G9 +
  test_w123_mining_gbt.py) explicitly locking in the wrong BIP-94
  mintime behaviour. Same shape as W154 BUG-3.

- **Operator-knob absence** — BUG-6 (`-signetchallenge`), BUG-9
  (regtest `enforce_bip94`), BUG-13 (`get_next_bits` /
  `get_next_block_version` carry-forward W154).

- **Carry-forward multi-wave** — BUG-13 confirms W154 BUG-3 is still
  unfixed through W155, W156, **W157 → 4-wave streak**.

- **Three-network-string conflation** — BUG-15 (signet treated as
  regtest for bech32 hrp). Same shape as W144 fleet pattern
  "shape-gated NOT flag-gated".

- **Hash-length silent-truncation** — BUG-16 (31-byte signet genesis
  hex in node.py). First instance of this shape in the audit series.

- **Soft-hardcoded gates** — BUG-8 / BUG-12 (BIP-94 keyed by
  `network` string not `enforce_bip94` flag). Same shape as W144's
  "exception-map short-circuit elides Core's fall-through".

- **Dead-code-but-called** — BUG-19 (legacy
  `calculate_next_difficulty` in pow.rs called by legacy
  `HeaderValidator` despite the canonical
  `calculate_next_work_required` existing).

- **Constants-drift coupling** — BUG-21 (signet `BLOCK_SCRIPT_VERIFY_FLAGS`
  hardcoded, not linked to Core's evolving constant), BUG-22
  (default-signet challenge constant duplicated).

**Top three findings:**

1. **BUG-1 (P0-CDIV signet validation skipped in Rust)** —
   `CheckSignetBlockSolution` is implemented only in Python; the
   three production Rust paths (`connect_block_from_bytes`,
   `validate_block_from_bytes`, `validate/block.rs::validate_block`)
   all silently accept any PoW-valid signet block, even if the
   signet signature is missing or invalid. On a real signet IBD
   that routes through `connect_block_from_bytes` (the default per
   block_sync.py:1083-1093), the signet gate is **never run**.
   Same severity-class as W143 BUG-9 (blockbrew CheckSignetBlockSolution
   missing → forks off signet at block 1).

2. **BUG-10 + BUG-11 cluster (P0-CDIV BIP-94 timewarp missing across
   Rust + miner)** — BUG-10: Rust path has no `MAX_TIMEWARP` constant
   anywhere and no timewarp boundary check at retarget; BUG-11: GBT
   `mintime` ignores the BIP-94 clamp on ALL networks (Core fires it
   unconditionally since v25; ouroboros never fires it).
   Combined: the time-warp attack BIP-94 was designed to mitigate is
   functionally **unprotected on testnet4 IBD** (Rust path) and miners
   using ouroboros's GBT produce **invalid retarget-boundary blocks**
   that Core peers reject with `time-timewarp-attack`. Both halves
   asserted-as-regression-contract by two test files
   (test_w108_gbt.py + test_w123_mining_gbt.py).

3. **BUG-6 + BUG-14 + BUG-16 cluster (P0-CDIV signet operational
   gaps)** — BUG-6: `signet_challenge` is NOT a chain parameter
   anywhere (no Rust field, no Python attribute, no CLI flag, no
   config knob); custom signets are entirely unsupported and
   default-signet relies on a hardcoded module constant. BUG-14:
   the per-challenge `pchMessageStart` derivation
   (`sha256(challenge)[0..4]`) is missing — even if BUG-6 were fixed
   a custom-signet node would still accidentally peer with default-
   signet. BUG-16: the signet genesis hex in node.py is **31 bytes**
   not 32 — signet startup is broken from day 1 on any DB
   implementation that requires `&[u8; 32]`. Combined: signet is
   **categorically unsupported in production**, default-signet
   barely runs (due to BUG-3, BUG-4, BUG-7 modifying the actual
   verification path), and custom signets cannot be configured
   at all.

**Cross-cite to fleet priority queue:** MEMORY.md
"PRIORITY NEXT FIX WAVES" item 10 is "blockbrew W143
CheckSignetBlockSolution (P0-CONS signet split at block 1)". This
audit confirms the **same shape** exists in ouroboros, but split
across the Python/Rust pipeline boundary: BUG-1 documents that the
Python path has the check while the (default-active) Rust path
silently accepts everything. Recommended fleet-wide fix: a single
"signet block-solution check" architectural pass that wires it into
every production block-acceptance pipeline on every impl.
