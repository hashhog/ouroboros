# Ouroboros → Bitcoin Core Parity — Remaining Gaps & Tasks

> Generated from a deep comparison of ouroboros source against Bitcoin Core.
> Items marked ~~strikethrough~~ were initially flagged as gaps but found to be already implemented.

---

## Tier 1: Consensus Correctness (High Priority)

These affect whether ouroboros would accept/reject the same blocks as Bitcoin Core.

### 1.1 Per-Transaction Sigops Cost Limit

**Gap:** Bitcoin Core enforces `MAX_STANDARD_TX_SIGOPS_COST = 16,000` per transaction
during `ConnectBlock()`. Ouroboros only checks the block-level total (80,000) but
does not reject individual transactions that exceed 16,000 sigops cost.

**Files:** `src/ouroboros/validation.py`

**Steps:**
1. Add constant: `MAX_TX_SIGOPS_COST = 16_000`
2. In `_validate_block_limits()`, after computing each transaction's sigops cost
   (legacy + P2SH + witness), check if `tx_sigops_cost > MAX_TX_SIGOPS_COST`
3. Return failure if any single transaction exceeds the limit

**Prompt:**
> In validation.py, add a per-transaction sigops cost limit of 16,000 inside
> `_validate_block_limits()`. After computing the sigops cost for each transaction
> (legacy × 4 + P2SH × 4 + witness × 1), check if any single tx exceeds 16,000.
> If so, return `(False, "Transaction sigops cost {cost} exceeds {MAX_TX_SIGOPS_COST}")`.
> Add `MAX_TX_SIGOPS_COST = 16_000` as a module constant near the other limits.

**Verify:** Run `python -m pytest tests/ -v`

---

### ~~1.2 Coinbase Maturity Enforcement~~

~~Already implemented at validation.py:1248-1257. Checks `is_coinbase_utxo` and
requires `depth >= COINBASE_MATURITY (100)` before spending.~~

---

### ~~1.3 P2SH Sigops Counting~~

~~Already implemented. `_validate_block_limits()` (lines 646-654) calls
`_get_p2sh_sigops()` which extracts the P2SH redeem script and counts its sigops
at 4× weight. Witness sigops are counted separately at 1× weight (lines 656-666).~~

---

### ~~1.4 Block Template Topological Ordering~~

~~Already implemented. `rpc_getblocktemplate()` (lines 1551-1606) builds a
parent-dependency map and uses `_collect_ancestors()` with BFS to ensure parents
appear before children in the template.~~

---

### ~~1.5 Outbound Transaction Relay~~

~~Already implemented. `node.py:_make_tx_handler()` (lines 467-494) broadcasts
INV messages with `MSG_WITNESS_TX` type to all ready peers (except sender) after
successful mempool addition, respecting BIP 133 feefilter.~~

---

### ~~1.6 OP_CODESEPARATOR Tracking~~

~~Already implemented. `script.py:1041-1048` tracks `codesep_pos` and uses it in
sighash computation. Rejects OP_CODESEPARATOR in non-witness scripts when
`SCRIPT_VERIFY_CONST_SCRIPTCODE` flag is set.~~

---

## Tier 2: Block Template & Mining (High Priority)

### 2.1 Actual Sigops Counting in Block Template

**Gap:** `rpc_getblocktemplate()` returns `"sigops": 0` for every transaction entry
(hardcoded at rpc.py:1619). Miners need accurate sigop counts to stay under the
block sigops limit.

**Files:** `src/ouroboros/rpc.py`, `src/ouroboros/validation.py`

**Steps:**
1. Import the sigops counting helpers from validation.py into rpc.py (or make them
   accessible — `_count_legacy_sigops`, `_get_p2sh_sigops`, `_count_witness_sigops`)
2. For each transaction in the template, compute sigops cost the same way
   `_validate_block_limits()` does
3. Replace `"sigops": 0` with the actual value

**Prompt:**
> In rpc.py `rpc_getblocktemplate()`, the template entries have `"sigops": 0`
> hardcoded. Replace this with actual sigops cost computation.
>
> The sigops calculation should match `_validate_block_limits()` in validation.py:
> - Count legacy sigops (scriptPubKey + scriptSig) × WITNESS_SCALE_FACTOR
> - Count P2SH redeem script sigops × WITNESS_SCALE_FACTOR
> - Count witness sigops × 1
>
> Either refactor the counting functions in validation.py to be importable (e.g.
> make them module-level or static), or import the BlockValidator and call its
> methods. Replace the hardcoded 0 with the computed value.

**Verify:** Run `python -m pytest tests/ -v`. Check that getblocktemplate output
has non-zero sigops for transactions containing signature operations.

---

### 2.2 Ancestor Fee Rate Scoring for Template Ordering

**Gap:** Bitcoin Core's `BlockAssembler` uses "ancestor fee rate" (sum of ancestor
fees / sum of ancestor sizes) for transaction selection priority. Ouroboros uses
individual transaction fee rate. This means a low-fee parent with a high-fee child
gets deprioritized vs Bitcoin Core which would score them together.

**Files:** `src/ouroboros/rpc.py`

**Steps:**
1. Before selecting transactions, compute ancestor fee rate for each mempool entry:
   `ancestor_fee_rate = (entry.fee + sum(ancestor fees)) / (entry.size + sum(ancestor sizes))`
2. Sort candidates by ancestor fee rate (highest first) instead of individual fee rate
3. Keep the existing topological ordering logic for actual insertion

**Prompt:**
> In rpc.py `rpc_getblocktemplate()`, improve transaction selection to use
> ancestor fee rate instead of individual fee rate.
>
> For each mempool entry, compute:
> ```
> ancestor_fee = entry.fee + sum(snap_txs[a].fee for a in ancestors if a in snap_txs)
> ancestor_size = entry.size + sum(snap_txs[a].size for a in ancestors if a in snap_txs)
> ancestor_fee_rate = ancestor_fee / ancestor_size
> ```
>
> Sort the candidates by ancestor_fee_rate (descending) instead of using the
> mempool's by_fee_rate list. Keep the existing `_collect_ancestors()` and
> topological ordering logic for insertion.
>
> Reference: Bitcoin Core `BlockAssembler::addPackageTransactions()` in
> `node/miner.cpp` uses `mapModifiedTx` sorted by ancestor fee rate.

**Verify:** Create a test with a low-fee parent and high-fee child. Verify the
parent+child package is selected before a standalone tx with lower package fee rate.

---

## Tier 3: Mempool Policy (Medium Priority)

### 3.1 TRUC Transaction Policy (v3 Transactions)

**Gap:** Bitcoin Core implements TRUC (Topologically Restricted Until Confirmation)
rules for version 3 transactions (policy/truc_policy.cpp):
- v3 tx may have at most 1 unconfirmed ancestor
- v3 tx may have at most 1 unconfirmed descendant
- v3 tx that is a child of an unconfirmed v3 parent must be ≤ 10,000 vB
- A v3 parent can only be replaced by a v3 child's replacement

Ouroboros accepts v3 transactions but applies standard v1/v2 rules.

**Files:** `src/ouroboros/mempool.py`

**Steps:**
1. Add constant: `TX_V3_MAX_VSIZE = 10_000`
2. In `_add_transaction_inner()`, after standardness checks but before general
   ancestor/descendant limits, add v3-specific checks:
   - If `tx.version == 3`:
     a. Count unconfirmed ancestors → must be ≤ 1
     b. Check each unconfirmed parent — if parent is v3, child vsize must be ≤ 10,000
   - For existing v3 txs in mempool: if a new tx would be a descendant, check that
     the v3 tx has no other unconfirmed descendants
3. In `_try_replace_inner()`, enforce that v3 replacements follow TRUC rules

**Prompt:**
> Add TRUC (v3 transaction) policy enforcement to mempool.py, matching Bitcoin
> Core's `policy/truc_policy.cpp`.
>
> When `tx.version == 3`:
> 1. Max 1 unconfirmed ancestor (vs normal 25)
> 2. Max 1 unconfirmed descendant for any v3 parent
> 3. If child of unconfirmed v3 parent, child must be ≤ 10,000 vB
> 4. Only one unconfirmed child allowed per v3 parent
>
> Add these checks in `_add_transaction_inner()` after the `_is_standard_tx()`
> check. Add constant `TX_V3_MAX_VSIZE = 10_000`. When a v3 parent already has
> an unconfirmed child, the new tx must be a replacement (redirect to try_replace).
>
> Reference: Bitcoin Core `policy/truc_policy.cpp` functions:
> `CheckNewPackageForV3Violation()`, `CheckExistingPackageForV3Violation()`

**Verify:** Write tests: (1) v3 tx with 2 unconfirmed ancestors → reject,
(2) v3 child > 10,000 vB of v3 parent → reject, (3) second child of v3 parent → reject.

---

### 3.2 Ephemeral Dust Policy

**Gap:** Bitcoin Core allows zero-value outputs in v3 (TRUC) transactions if the
dust is spent within the same package. This enables anchor outputs for lightning
and other L2 protocols.

**Files:** `src/ouroboros/mempool.py`

**Steps:**
1. In `_is_standard_tx()`, when checking dust outputs, skip the dust check for
   v3 transactions (they use ephemeral dust rules instead)
2. In `_validate_package_inner()`, for v3 packages: verify that any zero-value
   outputs are spent by another transaction in the same package
3. Reject v3 txs with dust outputs when submitted individually (without package)

**Prompt:**
> Add ephemeral dust policy for v3 transactions in mempool.py.
>
> In `_is_standard_tx()`: if `tx.version == 3`, skip the normal dust threshold
> check for outputs. Instead, flag the tx as having "ephemeral dust" if any
> output has value below the dust threshold.
>
> In `_validate_package_inner()`: if a v3 tx in the package has ephemeral dust
> outputs, verify that each dust output is spent by another tx within the same
> package. If any dust output is unspent, reject the package.
>
> For individual v3 tx submission (not in a package): if the tx has ephemeral
> dust outputs, reject it — ephemeral dust is only valid in packages.
>
> Reference: Bitcoin Core `policy/ephemeral_policy.cpp`

**Verify:** Write tests: (1) v3 tx with zero-value output in package where child
spends it → accept, (2) v3 tx with zero-value output submitted alone → reject.

---

### 3.3 submitpackage RPC Endpoint

**Gap:** Bitcoin Core has `submitpackage` RPC that allows submitting a package of
transactions for CPFP evaluation. Ouroboros has `validate_package()` internally
but no RPC endpoint to access it.

**Files:** `src/ouroboros/rpc.py`

**Steps:**
1. Add new RPC endpoint `submitpackage` that:
   - Accepts a list of raw transaction hex strings
   - Deserializes each into a Transaction
   - Calls `mempool.validate_package(txs, height)`
   - Returns per-transaction results with txid, vsize, fees, and acceptance status

**Prompt:**
> Add a `submitpackage` RPC endpoint in rpc.py that wraps the existing
> `mempool.validate_package()` method.
>
> Signature: `async def rpc_submitpackage(self, package: List[str]) -> Dict`
> - `package`: list of raw transaction hex strings in topological order
> - Deserialize each hex into a Transaction using TxMessage.from_payload()
> - Call `self.node.mempool.validate_package(txs, best_height + 1)`
> - Return format matching Bitcoin Core:
>   ```json
>   {
>     "package_msg": "success" or error,
>     "tx-results": {
>       "<txid>": {
>         "txid": "...",
>         "vsize": 123,
>         "fees": {"base": 0.00001234}
>       }
>     }
>   }
>   ```
>
> Register the route as POST `/submitpackage`.

**Verify:** Submit a 2-tx package via RPC where child pays for parent (CPFP).

---

## Tier 4: RPC Completeness (Medium Priority)

### 4.1 getblockstats RPC

**Gap:** Bitcoin Core's `getblockstats` returns per-block statistics (fees, sizes,
utxo changes, etc.). Useful for chain analysis and monitoring.

**Files:** `src/ouroboros/rpc.py`

**Steps:**
1. Add `rpc_getblockstats(hash_or_height, stats=None)` endpoint
2. Fetch the block by hash or height
3. Compute statistics: avgfee, avgfeerate, avgtxsize, blockhash, height, ins, outs,
   maxfee, maxfeerate, maxtxsize, medianfee, mediantime, mediantxsize, minfee,
   minfeerate, mintxsize, subsidy, swtotal_size, swtotal_weight, swtxs, time,
   total_out, total_size, total_weight, totalfee, txs, utxo_increase,
   utxo_size_inc
4. If `stats` parameter provided, filter to only those stats

**Prompt:**
> Add a `getblockstats` RPC endpoint in rpc.py.
>
> Signature: `async def rpc_getblockstats(self, hash_or_height, stats=None)`
> - Accept either a block hash (hex string) or height (int)
> - Fetch the block and iterate all transactions to compute:
>   - txs: count of transactions
>   - total_size, total_weight: sum of sizes/weights
>   - totalfee: sum of all fees (inputs - outputs for non-coinbase)
>   - avgfee, minfee, maxfee, medianfee
>   - avgfeerate, minfeerate, maxfeerate
>   - avgtxsize, mintxsize, maxtxsize, mediantxsize
>   - ins, outs: total input/output counts
>   - subsidy: block subsidy at this height
>   - swtxs, swtotal_size, swtotal_weight: segwit tx stats
>   - utxo_increase: outputs created minus inputs spent
>   - time, mediantime, height, blockhash
> - If `stats` list provided, only return those keys
>
> Note: Fee computation requires UTXO lookups for input values. Use
> `db.get_utxo()` or the tx index to find input amounts.
>
> Register as GET `/getblockstats`.

**Verify:** Call getblockstats for a known block and verify fee/size calculations.

---

### 4.2 getchaintips RPC

**Gap:** Bitcoin Core's `getchaintips` returns information about all known branch
tips including the active chain and any orphan/fork chains. Useful for monitoring
reorg activity.

**Files:** `src/ouroboros/rpc.py`

**Steps:**
1. Add `rpc_getchaintips()` endpoint
2. Query the database for the best block (active tip)
3. Return at minimum the active chain tip with status "active"
4. Optionally track and return orphan chain tips if the block index stores them

**Prompt:**
> Add a `getchaintips` RPC endpoint in rpc.py.
>
> For now, return at minimum the active chain tip:
> ```json
> [
>   {
>     "height": 800000,
>     "hash": "000000000000000000...",
>     "branchlen": 0,
>     "status": "active"
>   }
> ]
> ```
>
> Get the best block via `self.node.db.get_best_block()` and
> `self.node.db.get_block_by_height(height)` for the hash.
>
> Future enhancement: track orphan/stale block headers to report fork tips with
> status "valid-fork", "valid-headers", or "headers-only".

**Verify:** Call getchaintips and verify it returns the current chain tip.

---

### 4.3 getmempoolentry / getmempoolancestors / getmempooldescendants RPCs

**Gap:** These mempool introspection RPCs exist in Bitcoin Core but may be
incomplete in ouroboros.

**Files:** `src/ouroboros/rpc.py`

**Steps:**
1. Verify `getmempoolentry` returns all expected fields (fees, vsize, weight,
   ancestor/descendant counts, depends list)
2. Verify `getmempoolancestors` and `getmempooldescendants` return correct results
3. Add `depends` field to mempool entries (list of unconfirmed parent txids)
4. Add `spentby` field (list of unconfirmed child txids)

**Prompt:**
> Review and complete the `getmempoolentry`, `getmempoolancestors`, and
> `getmempooldescendants` RPC endpoints in rpc.py.
>
> Each mempool entry should include:
> - `fees`: { base, modified, ancestor, descendant } (all in BTC)
> - `vsize`: virtual size
> - `weight`: weight units
> - `time`: unix timestamp when added
> - `height`: block height when added
> - `descendantcount`, `descendantsize`, `descendantfees`
> - `ancestorcount`, `ancestorsize`, `ancestorfees`
> - `depends`: list of unconfirmed parent txids (currently `[]`)
> - `spentby`: list of unconfirmed child txids (currently `[]`)
>
> The `depends` and `spentby` fields require iterating the mempool to find
> parent/child relationships. For `depends`: check each input's prev_txid — if
> it's in the mempool, it's a dependency. For `spentby`: check which mempool
> txs spend this tx's outputs.

**Verify:** Add a parent+child tx pair to mempool, then call getmempoolentry for
each and verify `depends`/`spentby` fields are populated correctly.

---

## Tier 5: Fee Estimation (Medium Priority)

### 5.1 Exponential Decay Fee Estimation

**Gap:** Bitcoin Core uses `CBlockPolicyEstimator` with exponential decay buckets
across fee rate ranges and confirmation targets. Ouroboros uses a simpler
percentile-based approach over the last 144 blocks, which is less accurate for
non-standard confirmation targets.

**Files:** `src/ouroboros/fee_estimator.py`

**Steps:**
1. Add fee rate buckets (logarithmic scale from 1 sat/vB to 10,000 sat/vB)
2. For each confirmed transaction, record which bucket it fell in and how many
   blocks it took to confirm
3. Apply exponential decay to historical data (decay factor per block)
4. For estimation: find the lowest fee rate bucket where the success probability
   for the target confirmation window exceeds a threshold (e.g., 85%)
5. Keep the existing simple estimator as a fallback

**Prompt:**
> Improve the fee estimator in fee_estimator.py to use exponential decay buckets,
> closer to Bitcoin Core's `CBlockPolicyEstimator`.
>
> Design:
> 1. Define ~40 fee rate buckets on a log scale: [1, 2, 3, 5, 7, 10, 15, 20, 30,
>    50, 75, 100, 150, 200, 300, 500, 750, 1000, ...] sat/vB
> 2. Track two arrays per bucket: `confirmed[bucket][target]` and
>    `total[bucket][target]` for confirmation targets 1-25
> 3. When a tx confirms in N blocks, increment `confirmed[bucket][N]` and
>    `total[bucket][1..N]` (it was unconfirmed for targets 1..N-1 too)
> 4. Apply decay factor 0.998 per block to all counters
> 5. To estimate for target T: find lowest bucket where
>    `confirmed[bucket][T] / total[bucket][T] >= 0.85`
> 6. Keep the old percentile method as fallback when bucket data is insufficient
>    (< 100 observations)
>
> Reference: Bitcoin Core `policy/fees.cpp`, `CBlockPolicyEstimator::processBlock()`
> and `CBlockPolicyEstimator::estimateSmartFee()`

**Verify:** Run the node for several hundred blocks and verify fee estimates are
reasonable. Compare against Bitcoin Core's `estimatesmartfee` for the same targets.

---

## Tier 6: Wallet (Medium Priority)

### 6.1 Fee Bumping (bumpfee RPC)

**Gap:** `wallet.py:bump_fee()` is a stub that returns None. Bitcoin Core supports
RBF fee bumping via `bumpfee` and `psbtbumpfee` RPCs.

**Files:** `src/ouroboros/wallet.py`, `src/ouroboros/rpc.py`

**Steps:**
1. Implement `bump_fee()` in wallet.py:
   - Find the original transaction in mempool by txid
   - Verify it signals RBF (sequence < 0xFFFFFFFE)
   - Create a new transaction with same inputs/outputs but higher fee
   - Reduce the change output (or add a new input if needed) to increase fee
   - Sign the new transaction
   - Submit to mempool via `try_replace()`
2. Add `bumpfee` RPC endpoint
3. Add `psbtbumpfee` variant that returns PSBT instead of broadcasting

**Prompt:**
> Implement fee bumping in wallet.py `bump_fee()` method (currently a stub).
>
> Steps:
> 1. Look up the original tx in mempool: `mempool.get_transaction(txid_bytes)`
> 2. Verify it signals replaceability: any input sequence < 0xFFFFFFFE
> 3. Calculate current fee and target fee at `new_fee_rate`
> 4. Determine fee increase needed: `new_fee = new_fee_rate * tx_vsize`
> 5. Reduce the change output to cover the fee increase
>    - If change output would go below dust, remove it and add a new input
> 6. Re-sign all inputs with the wallet's keys
> 7. Submit via `mempool.try_replace(new_tx, height)`
> 8. Return the new txid
>
> Also add `rpc_bumpfee(txid, options={})` in rpc.py that calls this method.
> `options` can include `fee_rate` (sat/vB) or `conf_target` (blocks).

**Verify:** Create a tx, bump its fee, verify new tx replaces old in mempool.

---

### 6.2 Coin Selection Improvements

**Gap:** Wallet has BnB, knapsack, and SRD, but lacks waste metric optimization
and doesn't account for current vs long-term fee rate in selection strategy.

**Files:** `src/ouroboros/wallet.py`

**Steps:**
1. Add waste metric calculation: `waste = selected_weight × (fee_rate - long_term_fee_rate) + change_cost`
2. Run all three algorithms and pick the one with lowest waste (not just the first
   that succeeds)
3. Add long-term fee rate parameter (default: 10 sat/vB)

**Prompt:**
> Improve coin selection in wallet.py to use waste metric optimization.
>
> Currently the code tries BnB → Knapsack → SRD and returns the first success.
> Instead:
> 1. Run all three algorithms
> 2. Compute waste for each result:
>    `waste = total_input_weight × (fee_rate - long_term_fee_rate) + change_cost`
>    where `change_cost = 0` if no change output (exact match),
>    `change_cost = CHANGE_COST (99 vB × fee_rate)` otherwise
> 3. Pick the result with the lowest waste
> 4. Add `long_term_fee_rate` parameter (default 10 sat/vB) to `_select_coins()`
>
> Reference: Bitcoin Core `wallet/coinselection.cpp` `GetSelectionWaste()`

**Verify:** Test that with high fee rate, BnB exact matches are preferred. With
low fee rate, solutions with fewer inputs are preferred.

---

## Tier 7: Indexing (Medium Priority)

### 7.1 Block Filter Index (BIP 157/158)

**Gap:** Bitcoin Core optionally builds compact block filters (BIP 157/158) that
allow light clients to efficiently determine if a block contains transactions
relevant to them. Ouroboros has no block filter support.

**Files:** New file `src/ouroboros/blockfilter.py`, `src/ouroboros/rpc.py`

**Steps:**
1. Implement basic GCS (Golomb-coded set) filter construction:
   - For each block, collect all scriptPubKeys from outputs and inputs
   - Build a GCS filter with P=19, M=784931 (BIP 158 parameters)
   - Store filters indexed by block hash/height
2. Add `getblockfilter` RPC endpoint
3. Optionally serve filters to peers via `getcfheaders`/`getcfilters` messages

**Prompt:**
> Implement BIP 158 basic block filters in a new file `src/ouroboros/blockfilter.py`.
>
> A basic block filter contains the set of all:
> - scriptPubKeys of all outputs created in the block
> - scriptPubKeys of all outputs spent by inputs in the block (from UTXO data)
>
> Encoded as a Golomb-coded set (GCS) with parameters:
> - P = 19 (Golomb parameter)
> - M = 784931 (false positive rate = M × 2^(-P))
>
> Construction:
> 1. For each item, compute SipHash-2-4(key, item) mod (N × M) where N = number
>    of items and key = first 16 bytes of block hash
> 2. Sort the hashed values
> 3. Compute deltas between consecutive values
> 4. Golomb-Rice encode each delta with parameter P
>
> Add `getblockfilter` RPC in rpc.py:
> ```
> GET /getblockfilter?blockhash=<hash>&filtertype=basic
> Returns: {"filter": "<hex>", "header": "<hex>"}
> ```
>
> Reference: BIP 158 (https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)

**Verify:** Compute filter for a known block, verify it matches Bitcoin Core's output.

---

## Tier 8: P2P Protocol (Low Priority)

### 8.1 Block-Relay-Only Connections

**Gap:** Bitcoin Core maintains 2 block-relay-only connections that don't
participate in transaction or address relay. This protects against eclipse attacks.

**Files:** `src/ouroboros/p2p.py`, `src/ouroboros/peer.py`

**Steps:**
1. Add `relay_type` field to Peer: `FULL_RELAY`, `BLOCK_RELAY_ONLY`
2. In PeerManager, maintain 2 block-relay-only outbound connections
3. Block-relay-only peers: don't send `sendcmpct`, `feefilter`, `mempool`,
   or relay transaction INVs
4. Don't send `addr`/`addrv2` to block-relay-only peers

**Prompt:**
> Add block-relay-only connection support to p2p.py and peer.py.
>
> In peer.py:
> - Add `relay_txs: bool = True` attribute to Peer
> - When `relay_txs=False`, skip sending feefilter, tx INVs, addr messages
>
> In p2p.py PeerManager:
> - Add `max_block_relay_only: int = 2` parameter
> - In `connect_to_peers()`: after filling full-relay slots, connect 2 additional
>   block-relay-only peers
> - For block-relay-only peers: skip `_register_addr_handlers()`, don't send
>   sendcmpct/feefilter/wtxidrelay, set `relay=False` in version message
>
> Reference: Bitcoin Core `MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2`

**Verify:** Connect to testnet, verify block-relay-only peers receive blocks but
not transaction INVs.

---

### 8.2 Peer Eviction Logic

**Gap:** Bitcoin Core protects certain inbound peers from eviction based on
netgroup diversity, latency, upload volume, and service flags. Ouroboros uses
simple FIFO (oldest gets evicted).

**Files:** `src/ouroboros/p2p.py`

**Steps:**
1. When inbound connection limit is reached, instead of rejecting, try to evict
   the worst inbound peer
2. Protect peers by: lowest latency (4), highest upload (4), most recent useful
   block relay (4), unique netgroups (up to 4), longest connected (4)
3. From unprotected peers, evict the one connected longest

**Prompt:**
> Improve inbound peer eviction in p2p.py `_handle_inbound_connection()`.
>
> When `len(self.inbound_peers) >= MAX_INBOUND`, instead of rejecting the new
> connection, try to evict the worst existing inbound peer:
>
> 1. Start with all inbound peers as candidates
> 2. Protect (remove from candidates): 4 with lowest latency
> 3. Protect: 4 with highest score (proxy for upload volume)
> 4. Protect: 4 with most recent block relay activity
> 5. Protect: up to 4 from unique /16 netgroups
> 6. Protect: 4 most recently connected
> 7. From remaining candidates, evict the one connected longest
> 8. If no candidates remain, reject the new connection
>
> Reference: Bitcoin Core `net.cpp` `SelectNodeToEvict()`

**Verify:** Fill inbound slots, verify low-latency and high-score peers are
protected from eviction.

---

### 8.3 Erlay Transaction Relay (BIP 330)

**Gap:** Bitcoin Core implements Erlay for efficient transaction relay using
set reconciliation (minisketch). This reduces bandwidth for tx relay by ~40%.

**Files:** `src/ouroboros/p2p.py`, new `src/ouroboros/minisketch.py`

**Steps:**
1. Implement minisketch-based set reconciliation
2. During version handshake, negotiate Erlay support via `sendtxrcncl` message
3. Instead of sending INV for every tx, periodically reconcile tx sets with peers
4. Only send INV for transactions the peer is missing after reconciliation

**Prompt:**
> This is a large feature. Implement BIP 330 (Erlay) for efficient transaction
> relay reconciliation.
>
> Phase 1: Add `sendtxrcncl` message to p2p_messages.py and negotiate during
> handshake. Track which peers support reconciliation.
>
> Phase 2: Implement minisketch-based set reconciliation in a new
> `src/ouroboros/minisketch.py`. This requires a BCH-based sketch that can
> find the symmetric difference of two sets.
>
> Phase 3: Periodically (every 1-2 seconds), reconcile the local tx inventory
> with each Erlay peer. Send INVs only for the difference.
>
> Reference: BIP 330, Bitcoin Core `net_processing.cpp` `ProcessTxRcncl()`

**Verify:** Connect two Erlay-capable nodes, verify tx relay works via
reconciliation with reduced INV messages.

---

## Tier 9: Network (Low Priority)

### 9.1 Tor/CJDNS Support

**Gap:** Bitcoin Core supports connecting to peers over Tor (.onion), I2P, and
CJDNS networks. Ouroboros is IPv4-only.

**Files:** `src/ouroboros/p2p.py`, `src/ouroboros/peer.py`

**Steps:**
1. Add SOCKS5 proxy support for outbound connections
2. Parse `.onion` addresses (v3 Tor) from addrv2 messages
3. Support `-proxy=` and `-onion=` configuration options
4. Connect to Tor peers via the SOCKS5 proxy

**Prompt:**
> Add Tor proxy support to peer.py and p2p.py.
>
> In peer.py `connect()`:
> - If a SOCKS5 proxy is configured and the host is a .onion address (or proxy
>   is set for all connections), connect through the SOCKS5 proxy
> - Implement SOCKS5 handshake: CONNECT command to target host:port
> - Use `asyncio.open_connection()` to the proxy, then perform SOCKS5 negotiation
>
> In p2p.py:
> - Add `proxy` parameter to PeerManager
> - In `_addr_bytes_to_host()`, handle net_id=4 (Tor v3, 32-byte address)
> - When proxy is configured, allow connecting to .onion addresses
>
> In config.py: add `proxy`, `onion`, `listen` options

**Verify:** Configure a SOCKS5 proxy (e.g. `tor`), connect to a .onion seed node.

---

## Tier 10: Advanced Wallet (Low Priority)

### 10.1 Descriptor Wallet Support

**Gap:** Bitcoin Core uses output descriptors (BIP 380+) as the primary wallet
model. Ouroboros stores raw WIF keys in JSON files.

**Files:** `src/ouroboros/wallet.py`, new `src/ouroboros/descriptors.py`

**Steps:**
1. Implement descriptor parsing: `wpkh(KEY)`, `pkh(KEY)`, `tr(KEY)`,
   `sh(wpkh(KEY))`, `multi(M, KEY, KEY, ...)`, `wsh(multi(...))`
2. Derive addresses from descriptors with range support
3. Store descriptors in wallet instead of individual keys
4. Support `importdescriptors` RPC

**Prompt:**
> Implement output descriptor support for the wallet.
>
> Create `src/ouroboros/descriptors.py` with:
> 1. Parser for descriptor strings: `wpkh([fingerprint/path]xpub/...)`,
>    `pkh(...)`, `tr(...)`, `sh(wpkh(...))`, `multi(M, ...)`
> 2. Address derivation with range: `wpkh(xpub.../0/*)#checksum` derives
>    addresses for index 0, 1, 2, ...
> 3. Checksum computation (descriptor checksum algorithm from BIP 380)
>
> In wallet.py:
> 4. Add `descriptors: List[DescriptorEntry]` storage alongside existing keys
> 5. `importdescriptors` method: parse, validate, and store descriptors
> 6. Address generation: derive from descriptors instead of raw keys
>
> Reference: BIP 380 (output script descriptors), BIP 381 (segwit descriptors),
> BIP 386 (taproot descriptors)

**Verify:** Import a wpkh descriptor with xpub, derive 20 addresses, verify they
match Bitcoin Core's output for the same descriptor.

---

## Summary

| Tier | Task | Priority | Complexity |
|------|------|----------|------------|
| 1.1 | Per-tx sigops limit | High | Small |
| 2.1 | Template sigops counting | High | Small |
| 2.2 | Ancestor fee rate scoring | High | Medium |
| 3.1 | TRUC v3 policy | Medium | Medium |
| 3.2 | Ephemeral dust policy | Medium | Small |
| 3.3 | submitpackage RPC | Medium | Small |
| 4.1 | getblockstats RPC | Medium | Medium |
| 4.2 | getchaintips RPC | Medium | Small |
| 4.3 | Mempool entry details | Medium | Small |
| 5.1 | Exponential decay fees | Medium | Large |
| 6.1 | Fee bumping (bumpfee) | Medium | Medium |
| 6.2 | Coin selection waste metric | Medium | Medium |
| 7.1 | Block filter index | Medium | Large |
| 8.1 | Block-relay-only connections | Low | Small |
| 8.2 | Peer eviction logic | Low | Medium |
| 8.3 | Erlay (BIP 330) | Low | Large |
| 9.1 | Tor/CJDNS support | Low | Medium |
| 10.1 | Descriptor wallets | Low | Large |
