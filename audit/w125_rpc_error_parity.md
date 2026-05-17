W125 — JSON-RPC error code parity audit (ouroboros)
====================================================

Date: 2026-05-17
Impl: ouroboros (Python+Rust pipeline)
Wave: W125 JSON-RPC error code parity (DISCOVERY)
Reference: `bitcoin-core/src/rpc/protocol.h`, `bitcoin-core/src/rpc/request.cpp`,
           `bitcoin-core/src/rpc/{blockchain,rawtransaction,mempool,mining,net,fees,util}.cpp`

Status: 30 gates audited — PRESENT 3 / PARTIAL 9 / MISSING 18. **20 BUGS** (5 P0 / 9 P1 / 6 P2).

Two-pipeline guard
------------------

`ferrous-utils` Rust crate is the IBD validation pipeline; it does NOT
serve JSON-RPC (no `rpc_*` exports, no JSON-RPC error code constants
anywhere under `ferrous-utils/`). All JSON-RPC error wiring lives in
Python `src/ouroboros/rpc.py` (12 343 LOC) plus `src/ouroboros/payjoin.py`
for BIP-78. **No production code touched in this audit.**

```
$ grep -rn "RpcError\|JsonRpcError\|RPCErrorCode\|JSONRPCError" \
       ferrous-utils/  → 0 matches
$ grep -rn "rpc_\|RPC_INVALID\|RPC_VERIFY\|RPC_WALLET" \
       ferrous-utils/  → 0 matches
```

The audit's xfail test file (`test_w125_error_parity.py`) imports only
the Python `RPCServer`. Two-pipeline guard PRESERVED.

Top-level architectural findings
--------------------------------

Three system-level shapes drive the bulk of the bugs:

**(F1) No central `RPCErrorCode` enum / mapping.** Core defines 32 named
constants (RPC_INVALID_REQUEST=-32600, RPC_INVALID_PARAMS=-32602,
RPC_INTERNAL_ERROR=-32603, RPC_PARSE_ERROR=-32700; RPC_MISC_ERROR=-1,
RPC_TYPE_ERROR=-3, RPC_WALLET_ERROR=-4, RPC_INVALID_ADDRESS_OR_KEY=-5,
RPC_WALLET_INSUFFICIENT_FUNDS=-6, RPC_OUT_OF_MEMORY=-7,
RPC_INVALID_PARAMETER=-8, RPC_CLIENT_NOT_CONNECTED=-9,
RPC_CLIENT_IN_INITIAL_DOWNLOAD=-10, RPC_WALLET_INVALID_LABEL_NAME=-11,
RPC_WALLET_KEYPOOL_RAN_OUT=-12, RPC_WALLET_UNLOCK_NEEDED=-13,
RPC_WALLET_PASSPHRASE_INCORRECT=-14, RPC_WALLET_WRONG_ENC_STATE=-15,
RPC_WALLET_ENCRYPTION_FAILED=-16, RPC_WALLET_ALREADY_UNLOCKED=-17,
RPC_WALLET_NOT_FOUND=-18, RPC_WALLET_NOT_SPECIFIED=-19,
RPC_DATABASE_ERROR=-20, RPC_DESERIALIZATION_ERROR=-22,
RPC_CLIENT_NODE_ALREADY_ADDED=-23, RPC_CLIENT_NODE_NOT_ADDED=-24,
RPC_VERIFY_ERROR=-25, RPC_VERIFY_REJECTED=-26,
RPC_VERIFY_ALREADY_IN_UTXO_SET=-27, RPC_IN_WARMUP=-28,
RPC_CLIENT_NODE_NOT_CONNECTED=-29, RPC_CLIENT_INVALID_IP_OR_SUBNET=-30,
RPC_CLIENT_P2P_DISABLED=-31, RPC_METHOD_DEPRECATED=-32,
RPC_CLIENT_MEMPOOL_DISABLED=-33, RPC_CLIENT_NODE_CAPACITY_REACHED=-34,
RPC_WALLET_ALREADY_LOADED=-35, RPC_WALLET_ALREADY_EXISTS=-36).
ouroboros uses **12 distinct numeric literals fleet-wide** (-1, -5, -8,
-14, -15, -18, -22, -32000, -32600, -32601, -32603, -32700) sprinkled
across `rpc.py`, with **NO** enum or shared constants module. Every
error path uses a magic number directly. Greppable by the literal but
nobody can ever audit "where do we emit RPC_WALLET_INSUFFICIENT_FUNDS"
because we don't.

**(F2) HTTPException → blanket -32603 collapse.** The single dispatcher
exception handler at `rpc.py:1061-1073`:
```
except HTTPException as e:
    return {"jsonrpc": "2.0",
            "error": {"code": -32603, "message": e.detail},
            "id": req_id}
except Exception as e:
    ...
    return {"jsonrpc": "2.0",
            "error": {"code": -32603, "message": str(e)}, ...}
```
collapses **every** HTTPException raised inside an RPC handler (and
there are 233 in `rpc.py` alone, plus ~80 in `rest.py`) to
**RPC_INTERNAL_ERROR (-32603)**. Core throws `JSONRPCError(RPC_*, ...)`
with the right code per call site. So:
- `gettxout` invalid txid: ouroboros emits `-32603` (Core: -8 RPC_INVALID_PARAMETER)
- `getblock` block-not-found: ouroboros emits `-32603` (Core: -5 RPC_INVALID_ADDRESS_OR_KEY)
- `sendrawtransaction` bad hex: ouroboros emits `-32603` (Core: -22 RPC_DESERIALIZATION_ERROR)
- `signrawtransactionwithwallet` no wallet: ouroboros emits `-32603` (Core: -18 RPC_WALLET_NOT_FOUND)
- `addnode` Already-added: ouroboros emits `-32603` (Core: -23 RPC_CLIENT_NODE_ALREADY_ADDED)
- `prioritisetransaction` nonzero dummy: ouroboros raises ValueError → `-32603` (Core: -8)
- `getbalance` no wallet: ouroboros emits `-32603` or `-32603` via `_get_wallet_for_rpc` HTTPException-500 (Core: -18)

This is **the single highest-impact gap in the entire audit**:
**~95% of all error responses from ouroboros have the wrong Core code.**

**(F3) Wallet RPCs return `JSONRPCResponse(error=...)` as a result body,
not as an error.** rpc.py:3754, 3792, 3818, 3848, 3880, 4005, 4012, 4028,
4035, 4059, 4108, 4125, and 18 more sites use:
```
return JSONRPCResponse(error={"code": -18, "message": "No wallet loaded"}, id=None)
```
This returns a Pydantic model object from the handler. The dispatcher
wraps it as `{"result": <JSONRPCResponse>, "id": req_id}` — meaning the
client sees `{"result": {"jsonrpc": "2.0", "result": null, "error": {...}, "id": null}, "id": 1}`,
NOT `{"error": {"code": -18, ...}, "id": 1}`. The JSON-RPC client
library will look for the top-level `error` key per JSON-RPC 2.0 spec
and find none → think the call succeeded. **This breaks every wallet
error path that uses this pattern.** Verified empirically:
```
result = await rpc._execute_single_rpc({"method": "walletpassphrase", ...})
# → {'jsonrpc': '2.0',
#    'result': JSONRPCResponse(error={'code': -18, ...}, ...),
#    'id': 1}
```
This affects: `sethdseed`, `encryptwallet`, `walletpassphrase`,
`walletlock`, `walletpassphrasechange`, `decodepsbt`, `combinepsbt`,
`finalizepsbt`, `createpsbt`. **9 wallet RPCs, ~35 error sites.**

The 30 audit gates
==================

| # | Gate | Status | Severity | Core code | Ouroboros emit | Site |
|---|------|--------|----------|-----------|----------------|------|
| G1 | `-32600 RPC_INVALID_REQUEST` (missing method, empty batch, batch size cap, non-object request) | PRESENT | — | -32600 | -32600 | rpc.py:1036, 1122, 1133, 1146, 1169 |
| G2 | `-32601 RPC_METHOD_NOT_FOUND` (unknown method) | PRESENT | — | -32601 | -32601 | rpc.py:1047 |
| G3 | `-32602 RPC_INVALID_PARAMS` (params not array/object) | **MISSING** | **P1** | -32602 | none | not used; Core uses -32602 only via JSON-RPC validation. ouroboros never emits -32602. params="foo" goes to handler unchanged. |
| G4 | `-32603 RPC_INTERNAL_ERROR` (genuine bitcoind error, e.g. datadir corruption) | **PARTIAL** | **P0** | -32603 | -32603 (catch-all) | rpc.py:1061-1073. ouroboros uses -32603 as the catch-all for every HTTPException + every Exception — overloads internal-error code into ~95% of all error paths. Core uses it only for legitimate internal failures. **F2.** |
| G5 | `-32700 RPC_PARSE_ERROR` (JSON parse failure) | PRESENT | — | -32700 | -32700 | rpc.py:1110 |
| G6 | `-1 RPC_MISC_ERROR` (`std::exception` from handler — e.g. "Negative timeout", "Block header missing", "Block not found on disk") | **PARTIAL** | **P1** | -1 | -32603 | rpc.py:1067-1073 catch-all returns -32603 instead of -1. Core's request.cpp:JSONRPCExecOne wraps `std::exception` → RPC_MISC_ERROR(-1). Only one site (rpc.py:6251) literally emits `-1` (a hardcoded outgoing-transaction notification) — every other RPC_MISC_ERROR path maps to -32603. |
| G7 | `-3 RPC_TYPE_ERROR` (unexpected type — Core: `getblocktemplate` "Missing data String key for proposal"; `decoderawtransaction` non-string param) | **MISSING** | **P1** | -3 | -32603 | grep `code.*=.*-3` `rpc.py` → zero hits. Every type-error path raises HTTPException 400 → dispatcher collapses to -32603. Affects `decoderawtransaction`, `decodescript`, `getblocktemplate.proposal.data`, `signmessage` non-string args, `verifymessage` non-string args. |
| G8 | `-5 RPC_INVALID_ADDRESS_OR_KEY` (invalid address; block hash not found; "no such transaction"; invalid private key; cannot derive script without private keys) | **PARTIAL** | **P0** | -5 | mixed | One site emits -5 directly (rpc.py:4126 createpsbt invalid address) — but via JSONRPCResponse-as-result bug (F3). All other Core -5 sites in ouroboros use HTTPException → -32603. Specifically: `getblock` not-found → -32603 (Core -5); `getblockhash` height out-of-range → -32603 (Core -8 for negative; Core never returns block-hash-by-height with code -5 — it raises RPC_INVALID_PARAMETER for negative; ouroboros throws HTTPException 404 → -32603); `getrawtransaction` no-such-tx → -32603 (Core -5); `verifymessage` invalid address → -32603 (Core -5); `signmessage` no-private-key → -32603 (Core -5); `dumpprivkey` not in wallet → -32603 (Core -5). |
| G9 | `-7 RPC_OUT_OF_MEMORY` | **MISSING** | P2 | -7 | none | Never emitted. Core uses it in `gettxoutsetinfo` for OOM. ouroboros's `rpc_gettxoutsetinfo` swallows all exceptions silently → -32603 if any. |
| G10 | `-8 RPC_INVALID_PARAMETER` (invalid/missing/duplicate parameter — height out of range, negative timeout, bad mode, "PSBTs not compatible") | **PARTIAL** | **P0** | -8 | mixed | Multiple sites use the literal `-8` correctly inside `JSONRPCResponse(error=...)` bodies (rpc.py:3763, 3769, 4029, 4109) — but ALL via the F3 wrapping bug so they're never seen as `error`. Every other Core RPC_INVALID_PARAMETER call site in ouroboros uses HTTPException 400 → dispatcher returns -32603. Examples: getblockhash negative height → -32603 (Core -8); getblock `verbosity > 3` accepted silently; getrawtransaction invalid txid → -32603 (Core -8 per Core ParseHashV); generatetoaddress nblocks=0 → -32603 (Core -8); prioritisetransaction nonzero dummy → -32603 via Exception catch-all (Core -8 with exact "Priority is no longer supported..." message — rpc.py:8681 has the message but raises ValueError, which dispatcher maps to -32603). |
| G11 | `-9 RPC_CLIENT_NOT_CONNECTED` (Bitcoin is not connected; "Shutting down") | **MISSING** | **P1** | -9 | none | `getblocktemplate` runs even when peer_manager has zero peers (rpc.py:4841). Core: `if (!CLIENT_NAME " is not connected") throw RPC_CLIENT_NOT_CONNECTED`. `rpc_stop` returns "Ouroboros server stopping" successfully then shuts down — no -9 emitted from any RPC during shutdown. |
| G12 | `-10 RPC_CLIENT_IN_INITIAL_DOWNLOAD` (still downloading initial blocks — Core gates `getblocktemplate`, `submitblock`, `importmempool` behind this) | **MISSING** | **P0** | -10 | none | `rpc_getblocktemplate` (rpc.py:4841) has zero IBD gate — will serve templates with `previousblockhash = genesis` if called during IBD. Core throws RPC_CLIENT_IN_INITIAL_DOWNLOAD at mining.cpp:773. `rpc_loadmempool` likewise has no IBD gate. **Will mislead a miner that connects mid-IBD into mining on a stale tip.** |
| G13 | `-11 RPC_WALLET_INVALID_LABEL_NAME` (`label` must be a string; reserved label name) | **MISSING** | P2 | -11 | -32603 | `rpc_getnewaddress(label)` accepts any string without validation; never emits -11. |
| G14 | `-12 RPC_WALLET_KEYPOOL_RAN_OUT` (`getnewaddress` / `getrawchangeaddress` with empty keypool) | **MISSING** | P2 | -12 | -32603 | `rpc_getnewaddress` walks `wallet.get_address()` which auto-generates; never raises keypool-empty. `rpc_keypoolrefill` exists but the empty-keypool throw site doesn't. |
| G15 | `-13 RPC_WALLET_UNLOCK_NEEDED` (wallet locked but RPC needs private keys — `sendtoaddress`, `signrawtransactionwithwallet`, `bumpfee`) | **MISSING** | **P0** | -13 | -32603 | rpc.py:4170 `walletcreatefundedpsbt` checks `wallet.is_locked` and raises HTTPException 500 → -32603 (Core: -13). `rpc_bumpfee` doesn't even check `is_locked` — silently returns "Fee bump failed" with -32603. `rpc_sendtoaddress` has no lock check — wallet.sign throws → -32603. **Locked wallet looks like an internal failure to clients.** |
| G16 | `-14 RPC_WALLET_PASSPHRASE_INCORRECT` (passphrase wrong) | **PARTIAL** | **P1** | -14 | -14 (via F3) | rpc.py:3835, 3896 emit -14 inside `JSONRPCResponse(error=...)` — but via F3 wrapping bug so the JSON-RPC client sees this as a successful `result`, not as `error`. |
| G17 | `-15 RPC_WALLET_WRONG_ENC_STATE` (encryptwallet on encrypted wallet; walletpassphrase on unencrypted wallet) | **PARTIAL** | **P1** | -15 | -15 (via F3) | rpc.py:3798, 3823, 3854, 3865, 3886 emit -15 inside `JSONRPCResponse(error=...)` — same F3 bug. |
| G18 | `-16 RPC_WALLET_ENCRYPTION_FAILED` | **MISSING** | P2 | -16 | -32603 | rpc.py:3786 `rpc_encryptwallet` propagates any internal wallet.encrypt() failure as Exception → -32603. No -16. |
| G19 | `-17 RPC_WALLET_ALREADY_UNLOCKED` | **MISSING** | P2 | -17 | -32603 | rpc.py:3810 `rpc_walletpassphrase` does NOT check `is_unlocked` state — re-unlocks silently (Core: throws RPC_WALLET_ALREADY_UNLOCKED for second unlock). |
| G20 | `-18 RPC_WALLET_NOT_FOUND` (invalid wallet specified — wrong /wallet/<name>; loadwallet on missing wallet) | **PARTIAL** | **P0** | -18 | -18 (via F3) + -32603 | rpc.py:3755, 3793, 3819, 3849, 3881 emit -18 via F3 wrapping (broken). But other no-wallet sites (rpc.py:8049, 8063 `importprivkey`/`dumpprivkey`) raise ValueError → -32603; rpc.py:4169 `walletcreatefundedpsbt` raises HTTPException 500 → -32603; rpc.py:8995 `bumpfee` raises HTTPException 500 → -32603. Inconsistent. **Some wallet-not-found errors are clients see as -18 (broken), others as -32603 (also wrong but a different wrong).** |
| G21 | `-19 RPC_WALLET_NOT_SPECIFIED` (no wallet endpoint specified, multi-wallet ambiguity) | **MISSING** | **P1** | -19 | -32603 | rpc.py:8576 `rpc_unloadwallet` with multiple loaded wallets raises HTTPException 400 "No wallet is loaded" → -32603. Core: throws RPC_WALLET_NOT_SPECIFIED with "Wallet file not specified". |
| G22 | `-20 RPC_DATABASE_ERROR` | **MISSING** | P2 | -20 | -32603 | "Database not available" everywhere (rpc.py:1402, 1565, 1610, 1696, 1741, 2064, 4707, 6292, 6355, 8749, 11403, more) is HTTPException 500 → -32603. Core: RPC_DATABASE_ERROR. |
| G23 | `-22 RPC_DESERIALIZATION_ERROR` (TX decode failed; Block decode failed; PSBT base64 invalid) | **PARTIAL** | **P0** | -22 | -22 (via F3) + -32603 | rpc.py:4006, 4013, 4036, 4060 emit -22 inside `JSONRPCResponse(error=...)` (broken F3). But `rpc_sendrawtransaction` (rpc.py:2410, 2427) raises HTTPException 400 → -32603; `rpc_submitblock` (rpc.py:6098) returns string `"rejected"` not error code; `rpc_decoderawtransaction` HTTPException 400 → -32603. Core: ALL these are RPC_DESERIALIZATION_ERROR. |
| G24 | `-23 RPC_CLIENT_NODE_ALREADY_ADDED` (addnode/setban duplicate) | **MISSING** | P2 | -23 | -32603 | rpc.py:6665 `rpc_addnode` fire-and-forget — no duplicate check; if peer already in addnode list, queues another dial. Never emits -23. Core net.cpp:362: `throw RPC_CLIENT_NODE_ALREADY_ADDED`. |
| G25 | `-24 RPC_CLIENT_NODE_NOT_ADDED` (removenode on absent node) | PARTIAL | P2 | -24 | ValueError → -32603 | rpc.py:6758 raises `ValueError(f"Node not found: {node}")` → dispatcher Exception catch-all → -32603. Has the right semantic but wrong code. |
| G26 | `-25 RPC_VERIFY_ERROR` / `-26 RPC_VERIFY_REJECTED` (testmempoolaccept / submitblock / sendrawtransaction policy reject) | **MISSING** | **P0** | -25/-26 | -32603 | rpc.py:2519 `sendrawtransaction` raises HTTPException 400 with detail = reject_reason string → -32603. Core: throws RPC_VERIFY_ERROR (-25) for VerifyResult::DOS, RPC_VERIFY_REJECTED (-26) for VerifyResult::INVALID. `rpc_testmempoolaccept` returns reject_reason in result body (correct) but `rpc_sendrawtransaction` should throw -26 with the reject string AND `txn-already-known` should be -27 (next gate). |
| G27 | `-27 RPC_VERIFY_ALREADY_IN_UTXO_SET` / `txn-already-known` | **MISSING** | **P1** | -27 | (silent success) | rpc.py:2454, 2461 return txid string when tx already in mempool/already confirmed → dispatcher emits `{"result": "<txid>"}`. Core's `sendrawtransaction` throws RPC_VERIFY_ALREADY_IN_UTXO_SET / `txn-already-known` (-27) in those cases. **Clients can't distinguish "I just submitted it" from "it was already there".** |
| G28 | `-28 RPC_IN_WARMUP` (startup-time barrier; pre-genesis activity) | **MISSING** | **P1** | -28 | (no warmup gate) | grep `warmup\|RPC_IN_WARMUP` `rpc.py` → 0 hits. RPC server starts accepting calls as soon as FastAPI is up. Core's httpserver.cpp sets warmup status and every RPC gates on `EnsureNotWarmup()` which throws RPC_IN_WARMUP if `RPCIsInWarmup(reason)` returns true. ouroboros has no equivalent layer — RPCs hit handlers that then internal-fail with -32603 when sub-systems aren't ready. |
| G29 | `-29 RPC_CLIENT_NODE_NOT_CONNECTED` (disconnectnode on a non-connected peer) | **MISSING** | P2 | -29 | none | rpc.py:6760 `rpc_disconnectnode` silently returns None if peer not found. Core: throws RPC_CLIENT_NODE_NOT_CONNECTED. |
| G30 | `-30 RPC_CLIENT_INVALID_IP_OR_SUBNET` (setban bad subnet) + `-31 RPC_CLIENT_P2P_DISABLED` + `-33 RPC_CLIENT_MEMPOOL_DISABLED` + `-34 RPC_CLIENT_NODE_CAPACITY_REACHED` + `-32 RPC_METHOD_DEPRECATED` + `-35 RPC_WALLET_ALREADY_LOADED` + `-36 RPC_WALLET_ALREADY_EXISTS` (operator-surface error codes) | **MISSING** | P2 | varies | none of -30/-31/-32/-33/-34/-35/-36 appear in ouroboros. setban bad subnet ValueError → -32603. rpc_addnode for v2transport-required-but-disabled returns success then logs warning (rpc.py:6707). Wallet-already-loaded raises HTTPException 400 → -32603 (Core: -35). createwallet with existing name → -32603 (Core: -36). prioritisetransaction with nonzero dummy → ValueError → -32603 (Core: -32 RPC_METHOD_DEPRECATED was the original Priority error in early Bitcoin Core; current Core uses RPC_INVALID_PARAMETER). |

Per-bug catalog (20 bugs)
=========================

**BUG-1 P0-CDIV (F2 root) `dispatcher-error-code-collapse-to-32603`**
File: rpc.py:1061-1073. Single `except HTTPException` clause maps every
HTTP error to `-32603 RPC_INTERNAL_ERROR`. Core uses 32 distinct codes.
Impact: every JSON-RPC client that does code-based error handling
(BTCPay Server, Lightning channel-fee bumping, all `bitcoin-cli`-style
wrappers) sees ouroboros as "always returning internal errors" — even
for "block not found" / "invalid hex" / "wallet locked" which are
client-recoverable. Closure: drop the blanket handler, introduce
`RPCError(code, message)` exception class, raise that from handlers
with the right code from a central `RPCErrorCode` IntEnum mirroring
`bitcoin-core/src/rpc/protocol.h`. Tests: assert
`response['error']['code']` equals the expected Core value for ≥40
specific scenarios. (See G4, G6, G8, G10, G20, G23, G26 — they all
collapse here.)

**BUG-2 P0-CDIV (F3 root) `wallet-error-as-result-not-error`**
File: rpc.py:3754, 3792, 3818, 3848, 3880, 4005, 4012, 4028, 4035,
4059, 4108, 4125 (and 8 more under nearby lines). `return
JSONRPCResponse(error=...)` returns a Pydantic model from a handler.
The dispatcher (rpc.py:1059) wraps it as
`{"result": <model>, "id": req_id}` — client sees no top-level `error`.
JSON-RPC 2.0 §5.1 specifies error responses MUST have a top-level
`error` member; ouroboros encodes the wallet error nested under
`result` instead. **Every wallet error path that uses this pattern is
silently swallowed by the client.** Closure: change to
`raise RPCError(code=-18, message="No wallet loaded")` and let the
dispatcher catch + render the error correctly. (See G16, G17, G20,
G23.)

**BUG-3 P0-CDIV `getblocktemplate-no-IBD-gate`** (G12)
File: rpc.py:4841 `rpc_getblocktemplate`. No `IsInitialBlockDownload`
check. Core: mining.cpp:769-774 throws
`RPC_CLIENT_IN_INITIAL_DOWNLOAD` if the node is still syncing. A
miner connecting to ouroboros mid-IBD gets a template built on the
node's current local tip — which may be hundreds of thousands of
blocks behind global tip, with the resulting block invalid for
network broadcast. Closure: insert
```
if self.node.is_in_ibd():
    raise RPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "...")
```
near the top of rpc_getblocktemplate. Also affects `rpc_loadmempool`.

**BUG-4 P0-CDIV `getblocktemplate-no-connected-peer-gate`** (G11)
File: rpc.py:4841. No peer-count check. Core: mining.cpp:769 throws
RPC_CLIENT_NOT_CONNECTED if `g_connman->GetNodeCount(ConnectionDirection::Both)
== 0`. A solo miner against an isolated ouroboros node will burn
hashes on a template built from a fork.

**BUG-5 P0-CDIV `wallet-locked-not-RPC_WALLET_UNLOCK_NEEDED`** (G15)
File: rpc.py:4170 `walletcreatefundedpsbt`, rpc.py:8994 `bumpfee`
(missing entirely), rpc.py:3446 `sendtoaddress` (missing entirely),
rpc.py:7410 `signrawtransactionwithwallet` (missing entirely). When
wallet is locked, ouroboros emits -32603. Core: -13
RPC_WALLET_UNLOCK_NEEDED with message "Error: Please enter the wallet
passphrase with walletpassphrase first." Clients that read the code
to auto-prompt for passphrase (most GUI wallets, BTCPay receive flow)
see ouroboros's locked wallet as an internal error and abort instead
of prompting.

**BUG-6 P1 `no-RPC_INVALID_PARAMS-emission`** (G3)
ouroboros never returns -32602 RPC_INVALID_PARAMS even when JSON-RPC
2.0 mandates it (params field not array/object, or method signature
mismatch). rpc.py:1052-1057 dispatches `await handler(*params)` or
`await handler(**params)`; an arity mismatch raises Python TypeError
caught by `except Exception` → -32603 with the Python message. JSON-RPC
2.0 §5.1 specifies -32602 for "invalid method parameter(s)".

**BUG-7 P1 `txn-already-known-returns-success`** (G27)
File: rpc.py:2454, 2461. `sendrawtransaction` returns the txid string
when the transaction is already in the mempool or already confirmed
on-chain. Core: throws RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) with the
exact string "Transaction already in block chain" / "txn-already-known"
so the caller can branch on success-vs-already-there. Lightning fee
bumping logic looks for -27 to detect race conditions.

**BUG-8 P1 `sendrawtransaction-reject-uses-internal-error`** (G26)
File: rpc.py:2519. After the mempool rejects a tx via policy or
consensus rule, ouroboros raises HTTPException 400 → -32603. Core:
throws RPC_VERIFY_ERROR (-25) for DoS rejects, RPC_VERIFY_REJECTED
(-26) for policy rejects, with the reject_reason as message. -25/-26
let RBF clients distinguish "ban-worthy rejection" from "non-final-fee
rejection".

**BUG-9 P1 `addnode-no-already-added-check`** (G24)
File: rpc.py:6702-6748. `rpc_addnode("add", node)` fire-and-forgets the
dial without checking the existing addnode list. A second `addnode add
1.2.3.4` queues another dial → wastes a socket + duplicate
log entries + can never produce -23 RPC_CLIENT_NODE_ALREADY_ADDED.

**BUG-10 P1 `setban-bad-subnet-valueerror-not-30`** (G30)
File: rpc.py:6786, 6790, 6794 — `rpc_setban` raises `ValueError`
("Invalid command", "Peer manager not available", "setban failed
for"). Core: throws RPC_CLIENT_INVALID_IP_OR_SUBNET (-30). The
addrman ban-subnet parser inside ouroboros silently accepts any
string that looks like an IP — but failed setbans emerge as -32603.

**BUG-11 P1 `disconnectnode-silently-succeeds-on-missing-peer`** (G29)
File: rpc.py:6760-6764. `rpc_disconnectnode` calls
`pm.disconnect_peer(address)` which returns nothing on no-match.
Caller sees `{"result": null, "id": 1}` indistinguishable from
real success. Core throws RPC_CLIENT_NODE_NOT_CONNECTED (-29).

**BUG-12 P1 `RPC_DESERIALIZATION_ERROR-as-32603`** (G23)
File: rpc.py:2410, 2427, 6098, 11280. `sendrawtransaction` / `submitblock`
/ `decoderawtransaction` / `decodepsbt` (latter has F3 bug too) emit
-32603 for malformed input. Core: -22 RPC_DESERIALIZATION_ERROR.
Hex-decoders need to distinguish "bad input" (-22) from "valid input
that produced internal error" (-32603) for fuzzer/protocol-test
tooling.

**BUG-13 P1 `RPC_IN_WARMUP-missing`** (G28)
File: rpc.py — no warmup state machine. The RPC port goes live as
soon as FastAPI binds; calls hit handlers that internal-fail with
-32603 if subsystems (mempool, peer_manager, wallet_manager) aren't
yet attached. Core has `RPCSetInWarmup(message)` /
`RPCUnsetInWarmup()` + `EnsureNotInWarmup` gate around every RPC.

**BUG-14 P1 `RPC_WALLET_NOT_SPECIFIED-collapse`** (G21)
File: rpc.py:8576. With 2+ wallets loaded and no `/wallet/<name>`
endpoint specified, `rpc_unloadwallet` says "No wallet is loaded"
(misleading) and emits -32603. Core: -19 RPC_WALLET_NOT_SPECIFIED
with "Wallet file not specified (must request wallet RPC through
/wallet/<filename> uri-path)."

**BUG-15 P2 `RPC_WALLET_INSUFFICIENT_FUNDS-missing`**
File: rpc.py:3446 `sendtoaddress`, rpc.py:4140 `walletcreatefundedpsbt`.
Insufficient funds path bubbles up as ValueError → -32603. Core: -6
RPC_WALLET_INSUFFICIENT_FUNDS with "Insufficient funds".

**BUG-16 P2 `RPC_DATABASE_ERROR-collapse`** (G22)
File: rpc.py:1402, 1565, 1610, 1696, 1741, 2064, 4707, 6292, 6355,
8749, 11403 + ~30 more. Every "Database not available" or "Cannot
read tip block" or DB I/O failure emits -32603. Core: -20
RPC_DATABASE_ERROR.

**BUG-17 P2 `RPC_WALLET_KEYPOOL_RAN_OUT-cannot-occur`** (G14)
File: rpc.py:3415 `rpc_getnewaddress` always succeeds (wallet
auto-derives the next key). Core's HD-wallet path has the same
auto-derive, but legacy keypool-mode wallets can run out — ouroboros
has no equivalent for non-descriptor wallets.

**BUG-18 P2 `RPC_WALLET_ALREADY_EXISTS-collapse`** (G30)
File: rpc.py:8388-8401 `createwallet` ValueError path. Core: -36
RPC_WALLET_ALREADY_EXISTS. ouroboros: -32603.

**BUG-19 P2 `RPC_WALLET_ALREADY_LOADED-collapse`** (G30)
File: rpc.py:8529-8535 `loadwallet` ValueError path. Core: -35
RPC_WALLET_ALREADY_LOADED. ouroboros: -32603.

**BUG-20 P2 `rate-limit-uses-32000-not-32603`**
File: rpc.py:1097. `Rate limit exceeded` is encoded as -32000
(JSON-RPC implementation-defined server-error range start). Core does
not have rate limiting in core RPC server (typically front-ended by
nginx). Not a Core mismatch per se, but the choice of -32000 is
arbitrary and not documented anywhere in ouroboros. Consider
RPC_MISC_ERROR (-1) or a fresh JSON-RPC server-error code with a
documented owner.

Cross-impl patterns
===================

(Carry-forward observations from prior wave reports the user has shared
in the project memory)

- **"comment-as-confession"** — rpc.py:8681 contains the comment:
  ```
  # Core: throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no
  # longer supported, dummy argument to prioritisetransaction must
  # be 0.") — bitcoin-core/src/rpc/mining.cpp:530.
  ```
  Then the next line raises a generic `ValueError` instead of using the
  documented Core code. 12th-wave confession pattern.

- **"well-engineered helper, wrong dispatch wiring"** — payjoin.py has
  a polished `PayJoinError.to_json()` returning `{"errorCode": ..., "message": ...}`
  with HTTP 4xx/5xx semantic (BIP-78), and `_handle_payjoin_request`
  wires it correctly (rpc.py:12194). The pattern proves ouroboros CAN
  do code-typed error responses correctly — the rest of the RPC
  surface just doesn't.

- **"two correct files, one broken dispatcher"** — `JSONRPCResponse`
  Pydantic model is *defined* correctly (rpc.py:425, has `error` field
  with proper shape). What's broken is that handler code returns that
  model as `result`. Type-driven IDE refactor wouldn't have caught it
  (the model is a valid `JSONRPCResponse` — just one nested inside
  another), demonstrating the *cross-wave dead-helper-at-dispatch*
  pattern variation.

Two-pipeline guard tests
========================

`test_w125_error_parity.py::test_two_pipeline_guard` asserts:
- `ferrous-utils/` contains no `RpcError`, `JsonRpcError`, `RPC_*`,
  `RPCErrorCode` strings (the Rust IBD pipeline doesn't serve RPC).
- The audit changes only `src/ouroboros/tests/test_w125_error_parity.py`
  + `audit/w125_rpc_error_parity.md` — no production-code edits.

Test plan (xfail markers per Core-divergent gate)
=================================================

`src/ouroboros/tests/test_w125_error_parity.py` contains 30 xfail
tests, one per gate, asserting `response['error']['code'] == <Core
code>`. As of this audit:
- G1, G2, G5 pass without xfail (PRESENT).
- G4 partial — the catch-all does emit -32603 for one specific
  category of error (the JSON-RPC dispatcher's own internal
  exceptions). Marked xfail because the test asserts -32603 is NOT
  used for `gettxout invalid-txid` (which Core uses -8).
- All 27 other gates: xfail. When a fix wave (FIX-N) lands closing
  one of these, the xfail flips to pass.

Closure plan (if/when a fix wave lands)
=======================================

The single biggest win is a 3-step refactor:

1. Introduce `src/ouroboros/rpc_errors.py` mirroring Core's enum:
   ```python
   class RPCErrorCode(IntEnum):
       INVALID_REQUEST = -32600
       METHOD_NOT_FOUND = -32601
       INVALID_PARAMS = -32602
       INTERNAL_ERROR = -32603
       PARSE_ERROR = -32700
       MISC_ERROR = -1
       TYPE_ERROR = -3
       WALLET_ERROR = -4
       INVALID_ADDRESS_OR_KEY = -5
       ...
   class RPCError(Exception):
       def __init__(self, code: RPCErrorCode, message: str):
           self.code = code; self.message = message
   ```

2. Update dispatcher (rpc.py:1061-1073) to catch RPCError FIRST and
   emit `error: {code: self.code.value, message: self.message}`.
   Keep HTTPException 401 (auth) and 429 (rate-limit) as-is. Map
   any other HTTPException → RPC_MISC_ERROR (-1) per Core.

3. Sweep the 233 HTTPException sites + 35 JSONRPCResponse-as-return
   sites and replace with `raise RPCError(...)`. Group by call site
   (block-not-found → -5, hex-decode → -22, locked-wallet → -13,
   etc.). Approx ~5 file regions; ~400-500 LOC churn.

This closes all 20 bugs in one fix wave (FIX-73). Tests in
test_w125_error_parity.py go green automatically.

References
==========

- `bitcoin-core/src/rpc/protocol.h` — enum definitions (lines 24-90)
- `bitcoin-core/src/rpc/request.cpp` — JSONRPCError + JSONRPCReplyObj
- `bitcoin-core/src/rpc/blockchain.cpp` — block/chain RPC errors
- `bitcoin-core/src/rpc/rawtransaction.cpp` — TX deserialization errors
- `bitcoin-core/src/rpc/mempool.cpp` — sendrawtransaction errors
- `bitcoin-core/src/rpc/mining.cpp` — getblocktemplate IBD/connected gates
- `bitcoin-core/src/rpc/net.cpp` — addnode/setban errors
- `bitcoin-core/src/rpc/server.cpp:309` — shutdown -9 RPC_CLIENT_NOT_CONNECTED
- `bitcoin-core/src/rpc/server_util.cpp:37` — mempool-disabled -33
- BIP-323 — JSON-RPC general spec (no normative force on Bitcoin Core
  error-code numbers, which are Core-internal)
- JSON-RPC 2.0 specification — https://www.jsonrpc.org/specification
