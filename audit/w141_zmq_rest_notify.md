W141 — ZMQ + REST + notification scripts audit (ouroboros)
==========================================================

Date: 2026-05-18
Impl: ouroboros (Python pipeline — external-facing surfaces.
      The Rust pipeline (`ferrous-utils/sync`) has zero ZMQ /
      HTTP / shell-script surface. Two-pipeline guard EXTENDS to
      forbid all three subsystems on the Rust side.)
Wave: W141 ZMQ + REST + notification scripts (bundled).

Reference:
  - `bitcoin-core/src/zmq/zmqnotificationinterface.cpp` (213 lines:
    Create, Initialize, Shutdown, UpdatedBlockTip,
    TransactionAddedToMempool, TransactionRemovedFromMempool,
    BlockConnected, BlockDisconnected — the kernel-side hooks
    that dispatch to per-topic notifiers).
  - `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (294 lines:
    CZMQAbstractPublishNotifier::Initialize/Shutdown/SendZmqMessage,
    the five MSG_* constants — `hashblock`, `hashtx`, `rawblock`,
    `rawtx`, `sequence` — and the `SendSequenceMsg` helper that
    encodes the 32-byte hash + 1-byte label + optional 8-byte LE
    mempool-sequence body).
  - `bitcoin-core/src/zmq/zmqabstractnotifier.h` (67 lines:
    `DEFAULT_ZMQ_SNDHWM = 1000`, the per-topic socket-options
    contract).
  - `bitcoin-core/src/rest.cpp` (1179 lines: 14 endpoint handlers,
    `ParseDataFormat`, `CheckWarmup`, and the
    `uri_prefixes[]` dispatch table at :1141-1158).
  - `bitcoin-core/src/init.cpp` (esp. :485 `-alertnotify`, :498
    `-blocknotify`, :2008-2018 the `block_notify` hook that
    wires the `uiInterface.NotifyBlockTip_connect` callback).
  - `bitcoin-core/src/node/kernel_notifications.cpp` :30-47:
    `AlertNotify` — uses `SanitizeString` + single-quote wrap +
    `ReplaceAll(strCmd, "%s", safeStatus)` then runs in a detached
    `std::thread`. `runCommand` in
    `bitcoin-core/src/common/system.cpp:50-61` is the actual
    `system(3)` shell call.
  - `bitcoin-core/src/util/strencodings.{h,cpp}`: `SanitizeString`,
    `SAFE_CHARS_DEFAULT`/`SAFE_CHARS_URI`, `ShellEscape`.
  - `bitcoin-core/src/wallet/init.cpp:75` and
    `bitcoin-core/src/wallet/wallet.cpp:1480/3069`: `-walletnotify`.

Status: 30 gates audited — **PRESENT 8 / PARTIAL 8 / MISSING 14.**
**21 BUGS** (4 P0-CDIV / 1 P0-CVE-class / 11 P1 / 5 P2).

Relationship to prior audits
----------------------------

- W124 (Operator experience) PRESENT-asserted `zmq_notifier.stop`
  wiring (LINGER=0 + `term()`) at G28; W141 is the deeper-dive
  on the ZMQ side that complements G28's lifecycle pin.
- W125 (RPC error parity) audited JSON-RPC error shapes; W141
  audits the REST error shapes (text/plain + `\r\n` in Core vs.
  FastAPI default JSON envelope).
- W133 (Index databases) covered the BIP-157 index side; W141
  audits the REST surface (`/rest/blockfilter`, `/rest/blockfilterheaders`)
  that exposes it.
- W134 (BIP-37 Bloom Filter) covered the P2P side; the REST
  audit here is the HTTP analog of "external-facing read API".
- W122/W128/W129/W130/W131/W133/W134/W135/W136/W137 — two-pipeline
  guard chain (PSBT, descriptors, etc.). W141 EXTENDS the guard
  to forbid Rust-side ZMQ / HTTP / shell-script execution.

Two-pipeline guard
------------------

ZMQ + REST + notification scripts are **external-facing I/O.**
The Rust pipeline (`ferrous-utils/`) does only block-/UTXO-/header-
crunching and exposes its surface to Python via PyO3. No HTTP
server, no socket bind, no `Command::new` shell invocation.

The Python pipeline owns:

- `src/ouroboros/zmq_notifier.py` (377 lines): per-topic
  ZMQNotifier with multi-topic socket sharing.
- `src/ouroboros/zmq_publisher.py` (130 lines): legacy single-
  endpoint publisher (kept for back-compat; superseded by
  zmq_notifier.py).
- `src/ouroboros/rest.py` (1330 lines): FastAPI router exposing
  10 REST endpoints under `/rest/*`.
- `src/ouroboros/daemon.py` (272 lines): sd_notify helpers
  (systemd integration; not the same surface as `-blocknotify`).

```
$ grep -rn "subprocess\|os\.system\|shell=True\|popen\|Command::new\|std::process::Command" \
        ferrous-utils/ --include='*.rs'    → 0 matches
$ grep -rn "zmq\|TcpListener\|HttpServer\|hyper::\|actix_web::\|axum::" \
        ferrous-utils/ --include='*.rs'    → 0 matches
$ grep -rn "blocknotify\|walletnotify\|alertnotify" \
        src/ouroboros/                                       → 0 matches
```

**Two-pipeline guard EXTENDED.** Tests
`test_w141_g28_two_pipeline_zmq_python_only`,
`test_w141_g29_two_pipeline_rest_python_only`,
`test_w141_g30_two_pipeline_no_rust_shell_exec` codify:

- No `*.rs` file under `ferrous-utils/{common,sync}/src/` may
  contain ZMQ / TcpListener / HTTP-server / shell-exec tokens.
- The Python `ouroboros.zmq_notifier`, `ouroboros.rest` MUST
  remain importable.

This extends the W76 + W120 + W122 + W125 + W128 + W129 + W130 +
W131 + W133 + W137 guard set → now W141. Future regression (e.g.
moving REST to a Rust crate "for performance") trips the guard.

Top-level architectural findings
--------------------------------

**(F1) `notify_transaction` call-site uses a non-existent
attribute.** `src/ouroboros/node.py:954-955`:

```py
if self.zmq_publisher:
    self.zmq_publisher.notify_transaction(tx)
```

The attribute is `self.zmq_notifier` (set at line 499); the
`self.zmq_publisher` attribute is never initialized. Result:
the `if self.zmq_publisher:` branch is **always false**, so
mempool-accept transactions are never published over `hashtx`
/ `rawtx` / `sequence` (label `'A'`) — Core's
`TransactionAddedToMempool` (`zmqnotificationinterface.cpp:161`)
fires unconditionally on every mempool acceptance. The legacy
attribute name was renamed (alias preserved at
`zmq_notifier.py:376`) but this single call site was missed.
**BUG-1 (P0-CDIV)** — every operator who wires `zmqpubhashtx`
gets a silent zero-message feed for mempool tx events.

**(F2) `set_zmq_notifier` method-name mismatch causes
`AttributeError` at startup.** `node.py:519`:

```py
self.block_sync.set_zmq_notifier(self.zmq_notifier)
```

…but `block_sync.py:400` defines `set_zmq_publisher`, not
`set_zmq_notifier`. The mismatched names mean that if **any**
of the five `zmqpub*` config options is non-empty,
`zmq_notifier._topic_endpoints` is non-empty
(node.py:516), `zmq_notifier.start()` succeeds (line 517), and
then line 519 raises `AttributeError: 'BlockSync' object has
no attribute 'set_zmq_notifier'`. This is caught by the
`except Exception` wrapper at `node.py:543-546` which calls
`self.stop()` and re-raises — i.e. the node **fails to start**
whenever a ZMQ endpoint is configured. **BUG-2 (P0-CDIV)** —
catastrophic. Trips on day-1 of any ZMQ-enabled mainnet rollout.

**(F3) No call site exists for
`NotifyBlockDisconnect` / `NotifyTransactionRemoval`.** Core's
`zmqnotificationinterface.cpp:198-211` calls
`NotifyBlockDisconnect` on every block disconnect (reorg) and
:170-178 `NotifyTransactionRemoval` on every mempool eviction.
Ouroboros's `ZMQNotifier` defines `notify_block_disconnect`
(zmq_notifier.py:236) and `notify_transaction_removed`
(:288) as public methods — but `grep -rn "notify_block_disconnect\|
notify_transaction_removed" src/ouroboros/` returns matches
ONLY inside `zmq_notifier.py` itself (the definitions). **Zero
production call sites.** Result: BIP-157 light clients and
block explorers using the `sequence` topic to drive reorg-aware
mempool views miss every disconnect + every eviction.
**BUG-3 (P0-CDIV)** — completes the `sequence`-topic feature
gap from BUG-1.

**(F4) `notify_block` skips IBD gate that Core enforces.**
Core's `UpdatedBlockTip` (`zmqnotificationinterface.cpp:151-159`)
explicitly returns early if `fInitialDownload ||
pindexNew == pindexFork` — i.e. ZMQ subscribers receive ZERO
block notifications during IBD. Ouroboros's
`block_sync.py:1380-1381` calls `notify_block(block)` on every
connected block, including during IBD. For a mainnet node syncing
~800k blocks, this floods the `hashblock` socket with
hundreds of thousands of messages an external consumer
(block explorer, mempool monitor) is not prepared to receive
during catch-up. **BUG-4 (P0-CDIV)** — operator-visible
divergence; explorers built against Core's `hashblock` behavior
won't receive an "I'm done" signal because they were never told
"I'm starting." Adding a `if not self.in_ibd:` guard at
block_sync.py:1380 closes this.

**(F5) ZMQ sequence number serialization width divergence.**
Core's `SendZmqMessage` (`zmqpublishnotifier.cpp:198-200`)
emits `nSequence` as `WriteLE32(msgseq, nSequence)` — a 32-bit
little-endian uint. Ouroboros (`zmq_notifier.py:202`):
`struct.pack("<I", seq)` — also LE u32. **Match.**
But the **mempool_sequence** field inside `sequence`-topic
messages is uint64 LE (`zmqpublishnotifier.cpp:263`
`WriteLE64(data + sizeof(hash) + sizeof(label), *sequence)`).
Ouroboros (`zmq_notifier.py:336`):
`struct.pack("<Q", mempool_sequence)` — also LE u64. **Match.**
G19 PRESENT.

**(F6) HWM is hardcoded to 1000 instead of per-topic
configurable.** Core's `zmqnotificationinterface.cpp:69` reads
`gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` — so the
operator can set `-zmqpubhashblockhwm=5000` etc. Ouroboros's
`zmq_notifier.py:148` hardcodes `socket.setsockopt(zmq.SNDHWM,
1000)`. The default matches Core's `DEFAULT_ZMQ_SNDHWM = 1000`,
but the config-knob is absent: `config.py:168-172` lacks the
five `zmqpub*hwm` options. **BUG-5 (P1)** — operator can't tune
HWM per-topic.

**(F7) Missing `TCP_KEEPALIVE` semantics divergence on shared
sockets.** Core's `Initialize` (zmqpublishnotifier.cpp:121-127)
sets `ZMQ_TCP_KEEPALIVE = 1` AND on shared sockets (multiple
topics, same endpoint) the second-and-subsequent notifiers
**reuse the existing socket** (zmqpublishnotifier.cpp:152-159)
without re-setting keepalive — because it was already set on
first bind. Ouroboros (`zmq_notifier.py:139-156`) groups topics
by endpoint into a per-endpoint socket map and only creates
the socket once per endpoint, so keepalive is set exactly once
per endpoint — **functionally equivalent**, PRESENT for G7.

**(F8) Missing `ZMQ_IPV6` opt-in for IPv6 endpoints.** Core's
`zmqpublishnotifier.cpp:82-93,130-135` parses the address
prefix (`tcp://`) and explicitly calls
`zmq_setsockopt(psocket, ZMQ_IPV6, &enable_ipv6, ...)` based on
whether the IP is IPv6. On some systems (esp. OpenBSD)
`ZMQ_IPV6=1` MUST NOT be set when binding to an IPv4 address.
Ouroboros's `zmq_notifier.py:144-152` never touches `ZMQ_IPV6`,
relying on pyzmq's default. This is a portability footgun on
systems where pyzmq's default is wrong; not a correctness bug
on Linux/macOS. **BUG-6 (P2)** — flagged for completeness.

**(F9) `unix://` address-scheme rewrite to `ipc://` missing.**
Core's `zmqnotificationinterface.cpp:62-64`:

```cpp
if (address.starts_with(ADDR_PREFIX_UNIX)) {
    address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC);
}
```

This transparently maps `unix://` (the more common docs
convention) to libzmq's actual `ipc://` prefix. Ouroboros's
`zmq_notifier.py:configure_endpoint` (line 115) passes the
endpoint through verbatim; an operator setting
`-zmqpubhashblock=unix:///var/run/btc.sock` gets a libzmq error
because pyzmq doesn't understand `unix://`. **BUG-7 (P1)** —
documentation footgun.

**(F10) `start()` is not idempotent + lacks reuse-address
detection.** Core's `Initialize` (zmqpublishnotifier.cpp:97-159)
uses `mapPublishNotifiers` (a static multimap) to detect
"this address is already bound" and reuse the existing socket.
Ouroboros's `start()` (zmq_notifier.py:130-159) silently
double-binds the same endpoint if `start()` is called twice on
the same `ZMQNotifier` instance — pyzmq raises
`zmq.error.ZMQError: Address already in use`. Re-binding to the
same address from a separate process gets the same error.
Not a security bug, but masks ops issues. **BUG-8 (P1)**.

**(F11) `Shutdown` path doesn't sync sequence counters across
shared sockets.** Core's per-notifier `nSequence` is incremented
inside `SendZmqMessage` (zmqpublishnotifier.cpp:205) — per-
notifier, NOT per-socket. Ouroboros's `_sequences` dict
(zmq_notifier.py:106-112) is keyed by **topic** which is
per-notifier, so this matches. PRESENT for G10.

**(F12) REST handler missing for `/rest/blockpart/` (BIP-30 block
fragment fetch).** Core's `rest.cpp:481-498` exposes
`rest_block_part` for fetching a sub-range of a block by
offset+size — used by lightweight clients to fetch just a
particular tx. Ouroboros has NO equivalent route in
`rest.py::_register_routes`. **BUG-9 (P1)** — light clients
relying on this REST endpoint get 404 from ouroboros.

**(F13) REST handler missing for `/rest/spenttxouts/`.** Core's
`rest.cpp:313-381` exposes per-block spent-outputs (the undo
data). Ouroboros: absent. **BUG-10 (P1)** — block explorers
that compute fees from spent UTXOs lose this fast-path and
must reconstruct per-input by querying `getutxos` per outpoint
in the parent tx.

**(F14) REST handler missing for `/rest/deploymentinfo`.**
Core's `rest.cpp:741-780` exposes `getdeploymentinfo` over
REST (no auth required). Ouroboros: absent.
**BUG-11 (P2)** — deployment-status monitors get JSON-RPC-only
access; not a security gap because they can use the
authenticated RPC endpoint instead.

**(F15) REST `/rest/getutxos` JSON `chaintipHash` is internal
byte-order, NOT display-order.** Core's
`rest.cpp:1062`: `objGetUTXOResponse.pushKV("chaintipHash",
active_hash.GetHex())` — `uint256::GetHex()` emits **reversed
(display-order)** hex. Ouroboros's `rest.py:1080`:

```py
"chaintipHash": best_hash.hex() if isinstance(best_hash, bytes) else str(best_hash),
```

`bytes.hex()` is **internal (little-endian)** byte order. Same
bug in `rest_chaininfo` (`rest.py:1229` `bestblockhash`) and
`rest_blockhash_by_height` JSON (`rest.py:1176`) and HEX
(`rest.py:1170`) responses. Every external consumer comparing
the REST response to a `getbestblockhash` JSON-RPC result (which
ouroboros emits display-order, per
`rpc.py::_chain_tip_to_json`) gets a mismatch. **BUG-12 (P0-CDIV)**
— block explorers querying both REST and RPC see disagreeing
tips on the same node.

**(F16) REST `_block_to_json` confusion: block's own `hash`
correctly reversed, but `nextblockhash` is also reversed,
while the block hash for `db.get_block(block_hash)` lookup
silently expects internal-order.** Re-read `rest.py:381,401,
408,716,820` — the byte-order convention is **inconsistent**
across endpoints. `rest_blockfilter` (`rest.py:706` line)
reverses `hash_be[::-1]` for the db lookup with a Pattern-C0
comment; `rest_tx` (`rest.py:911`) likewise reverses on parse.
But `rest_block` (`rest.py:302-310`) reads the user's hex
**without reversing** and passes to `db.get_block(block_hash)` —
which, depending on `db.get_block` semantics, may search by
display-order hash instead of internal. If `db.get_block`
returns nothing because the key convention is wrong, the user
sees 404 on a valid hash. **BUG-13 (P1)** — cross-endpoint
byte-order convention drift; needs single comment-pinned helper.

**(F17) REST 404 / 400 error replies are JSON envelopes, not
text/plain `<msg>\r\n`.** Core's `RESTERR`
(`rest.cpp:71-76`):

```cpp
req->WriteHeader("Content-Type", "text/plain");
req->WriteReply(status, message + "\r\n");
```

Every Core REST error response is `text/plain; charset=us-ascii`
with a trailing `\r\n`. Ouroboros uses FastAPI's default
`HTTPException`, which emits a JSON envelope
`{"detail": "..."}`. Block-explorer clients that parse error
bodies as text (e.g. for fallback messaging) get an unexpected
JSON object. **BUG-14 (P1)** — cosmetic but high-impact for
tooling parity.

**(F18) REST warmup check absent.** Core's `CheckWarmup`
(`rest.cpp:171-177`) is called at the entry of EVERY REST
handler and returns `HTTP_SERVICE_UNAVAILABLE` (503) if
`RPCIsInWarmup` is true — i.e. while the node is still loading.
Ouroboros's REST handlers (`rest.py:258-1329`) have NO warmup
gate. A client hitting `/rest/chaininfo.json` while ouroboros
is still booting (db not initialised, peer manager not running)
gets a `500 Database not available` from
`_get_db` (`rest.py:183-187`) — wrong status code, wrong
semantics. **BUG-15 (P1)** — REST clients have no way to tell
"node loading" from "node broken."

**(F19) REST `mempool_contents` `verbose` query-param accepts
any truthy/falsy.** Core (`rest.cpp:800-820`) enforces the
literal strings `"true"` or `"false"` — anything else returns
400. Ouroboros uses FastAPI's `bool` coercion which accepts
"1", "0", "yes", "no", "True", "False", "TRUE"…
**BUG-16 (P2)** — input-validation laxity; not a security
issue but trips parity tests.

**(F20) REST headers JSON omits `mediantime` field-name match.**
Core's `blockheaderToJSON` emits `time`, `mediantime`,
`nonce`, `bits`, `difficulty`, `chainwork`, `nTx`,
`previousblockhash`, `nextblockhash`. Ouroboros's
`rest.py:642-658` matches all these BUT the field
**`previousblockhash` is emitted as `None`** when there is no
previous (genesis). Core emits the **field absent** in that
case (not `null`). JSON consumers using `obj.has("previousblockhash")`
get different results. **BUG-17 (P2)** — cosmetic JSON shape
divergence.

**(F21) REST format-suffix parser at root URL not handled.** Core
parses `/rest/chaininfo` AND `/rest/chaininfo.json` (rest.cpp:1151,
1156). Ouroboros registers only `/rest/chaininfo.json` (rest.py:
164). Hitting `/rest/chaininfo` (no suffix) gets a 404 from
FastAPI's route table, not a `output format not found` text
reply. **BUG-18 (P2)** — minor cosmetic.

**(F22) No `-blocknotify` / `-alertnotify` / `-walletnotify`
support whatsoever.** Core's init.cpp:2008-2018 wires
`-blocknotify=<cmd>` to fire on every `NotifyBlockTip` outside
IBD; `node/kernel_notifications.cpp:30-47` wires `-alertnotify`
to fire on every alert raised; `wallet/init.cpp:75` wires
`-walletnotify` to fire on every wallet-tx change. Each
substitutes `%s` (block hash / tx ID / alert text) into the
shell command, single-quote-wraps the alert text, calls
`SanitizeString` on the alert (only — block-notify trusts
the block hash hex), and `runCommand(cmd)` in a detached
thread → `system(3)`.

Ouroboros has **zero** support for any of these:
`grep -rn "blocknotify\|walletnotify\|alertnotify"
src/ouroboros/` returns no matches. `config.py:155-193` does
not define them. The CLI parser does not parse them.

This is a **feature absence**, not a wire-protocol bug.
However:

(a) Operators migrating from Core lose script-driven workflows
    (block explorers that trigger re-indexing on new tips,
     CI hooks that fire on alerts). **BUG-19 (P1)**.

(b) **Shell-injection footgun:** if BUG-19 is ever closed by
    naively shelling out (`subprocess.run(cmd, shell=True)`
    with `cmd.replace("%s", block_hash_hex)`), the implementer
    MUST replicate Core's substitution model exactly:
    - **block hash:** hex output is `[0-9a-f]{64}`-only → safe
      to `%s`-substitute without sanitization;
      `runCommand("notify %s" % block_hash_hex)`.
    - **alert text / walletnotify %w wallet name:** UNTRUSTED
      → MUST be passed through `SanitizeString`
      (`strencodings.cpp:25` SAFE_CHARS_DEFAULT =
      alphanum + `" .,;-_/:?@()"`); then `ShellEscape`-quoted.
    A future contributor closing BUG-19 by templating untrusted
    strings (esp. wallet name `%w`, alert message) into a
    `shell=True` Popen WITHOUT sanitization opens a remote-shell-
    execution CVE. **BUG-20 (P0-CVE-class)** — pre-emptive
    guardrail; the test gate `test_w141_g30_no_shell_exec_with_user_input`
    forbids any future `subprocess.*shell=True` site in
    `ouroboros/` whose argv string contains a `.format(` /
    `%`-format / `f"..."` interpolation of node-state strings.

**(F23) ZMQ topic name divergence (legacy alias).**
`zmq_notifier.py:376` `ZMQPublisher = ZMQNotifier` keeps a
backward-compat alias. Code in `block_sync.py:236,400-402,
1380-1381` still uses `_zmq_publisher` / `set_zmq_publisher`
names — this is FINE (aliases preserved). But the
inconsistency between `node.py:954` (broken `zmq_publisher`
attribute access — BUG-1) and `block_sync.py:402` (correctly
stores via `set_zmq_publisher`) means the legacy path works
**inside `block_sync`** but is broken **inside `node`** —
which is the surface bug for BUG-1.

**(F24) `notify_block` for newly-mined (locally-found) blocks
absent.** Core's `BlockConnected`
(`zmqnotificationinterface.cpp:180-196`) fires on every block,
regardless of how it arrived (P2P or local). Ouroboros calls
`notify_block` only inside `block_sync._drain_block_buffer`
(`block_sync.py:1380`). The mining/submit-block path doesn't
notify (no obvious mining path on ouroboros; the gap is
theoretical until block-template submission lands).
**BUG-21 (P2)** — pre-emptive.

Gate matrix (30 gates)
----------------------

### ZMQ subsystem (G1-G10)

| Gate | Subject | Core ref | Ouroboros file:line | Status | Bug |
|------|---------|----------|---------------------|--------|-----|
| G1 | `hashblock` topic byte exact | zmqpublishnotifier.cpp:33,210-219 | zmq_notifier.py:87,211 | PRESENT | – |
| G2 | `hashtx` topic byte exact | zmqpublishnotifier.cpp:34,221-230 | zmq_notifier.py:88,254 | PARTIAL | BUG-1 |
| G3 | `rawblock` serialize-with-witness | zmqpublishnotifier.cpp:35,232-243 | zmq_notifier.py:89,225-230 | PRESENT | – |
| G4 | `rawtx` serialize-with-witness | zmqpublishnotifier.cpp:36,245-252 | zmq_notifier.py:90,273-278 | PARTIAL | BUG-1 |
| G5 | `sequence` accept label `'A'` + u64 mempool seq | zmqpublishnotifier.cpp:37,281-286 | zmq_notifier.py:91,281-286 | PARTIAL | BUG-1 |
| G5b | `sequence` removal label `'R'` + u64 | zmqpublishnotifier.cpp:288-293 | zmq_notifier.py:288-309 | PARTIAL | BUG-3 |
| G5c | `sequence` connect label `'C'` (no mempool seq) | zmqpublishnotifier.cpp:267-272 | zmq_notifier.py:233-234 | PRESENT | – |
| G5d | `sequence` disconnect label `'D'` (no mempool seq) | zmqpublishnotifier.cpp:274-279 | zmq_notifier.py:236-248 | PARTIAL | BUG-3 |
| G6 | `nSequence` LE32 per-topic counter | zmqpublishnotifier.cpp:199-205 | zmq_notifier.py:200-203 | PRESENT | – |
| G7 | `ZMQ_TCP_KEEPALIVE = 1` on bind | zmqpublishnotifier.cpp:121-127 | zmq_notifier.py:150 | PRESENT | – |
| G8 | `ZMQ_IPV6` opt-in for IPv6 addrs | zmqpublishnotifier.cpp:82-93,130-135 | absent | MISSING | BUG-6 |
| G9 | `unix://` → `ipc://` rewrite | zmqnotificationinterface.cpp:62-64 | absent | MISSING | BUG-7 |
| G10 | `DEFAULT_ZMQ_SNDHWM = 1000` | zmqabstractnotifier.h:22 | zmq_notifier.py:148 | PRESENT | – |
| G10b | per-topic `<topic>hwm` config option | zmqnotificationinterface.cpp:69 | absent | MISSING | BUG-5 |
| G11 | `notify_block` IBD-gated | zmqnotificationinterface.cpp:151-159 | block_sync.py:1380 ungated | MISSING | BUG-4 |
| G12 | `LINGER=0` + `term()` on stop | zmqpublishnotifier.cpp:185-188 + zmqnotificationinterface.cpp:127 | zmq_notifier.py:168,175 | PRESENT | – |

### REST subsystem (G13-G24)

| Gate | Subject | Core ref | Ouroboros file:line | Status | Bug |
|------|---------|----------|---------------------|--------|-----|
| G13 | `/rest/block/<h>.{bin,hex,json}` byte-exact | rest.cpp:389-469 | rest.py:258,293 | PARTIAL | BUG-13 |
| G14 | `/rest/block/notxdetails/<h>.<fmt>` | rest.cpp:476-479 | rest.py:278 | PRESENT | – |
| G15 | `/rest/headers/<h>.<fmt>?count=N` | rest.cpp:179-274 | rest.py:542 | PRESENT | – |
| G16 | `/rest/tx/<txid>.<fmt>` | rest.cpp:838-895 | rest.py:887 | PRESENT | – |
| G17 | `/rest/blockfilter/<type>/<h>.<fmt>` | rest.cpp:622-711 | rest.py:667 | PRESENT | – |
| G18 | `/rest/blockfilterheaders/<type>/...` | rest.cpp:500-620 | rest.py:747 | PRESENT | – |
| G19 | `/rest/chaininfo.json` byte order | rest.cpp:716-738 | rest.py:1184 | MISSING | BUG-12 |
| G20 | `/rest/getutxos[/checkmempool]/<txid>-<n>.<fmt>` | rest.cpp:897-1089 | rest.py:967 | PARTIAL | BUG-12 |
| G21 | `/rest/blockhashbyheight/<h>.<fmt>` | rest.cpp:1091-1139 | rest.py:1130 | MISSING | BUG-12 |
| G22 | `/rest/mempool/{info,contents}.json` query-param strict | rest.cpp:782-836 | rest.py:1264 | PARTIAL | BUG-16 |
| G23 | `/rest/blockpart/` block-fragment fetch | rest.cpp:481-498 | absent | MISSING | BUG-9 |
| G24 | `/rest/spenttxouts/<h>.<fmt>` undo | rest.cpp:313-381 | absent | MISSING | BUG-10 |
| G24b | `/rest/deploymentinfo[/<h>]` | rest.cpp:743-780 | absent | MISSING | BUG-11 |
| G24c | REST 4xx body `text/plain + \r\n` | rest.cpp:71-76 | FastAPI JSON | MISSING | BUG-14 |
| G24d | REST warmup gate (503) | rest.cpp:171-177 | absent | MISSING | BUG-15 |

### Notification-scripts subsystem (G25-G27)

| Gate | Subject | Core ref | Ouroboros file:line | Status | Bug |
|------|---------|----------|---------------------|--------|-----|
| G25 | `-blocknotify=<cmd>` argv | init.cpp:498,2008-2018 | absent | MISSING | BUG-19 |
| G26 | `-alertnotify=<cmd>` argv | init.cpp:485 + kernel_notifications.cpp:30-47 | absent | MISSING | BUG-19 |
| G27 | `-walletnotify=<cmd>` argv | wallet/init.cpp:75 | absent | MISSING | BUG-19 |

### Two-pipeline + shell-injection guards (G28-G30)

| Gate | Subject | Status | Bug |
|------|---------|--------|-----|
| G28 | ferrous-utils MUST NOT contain ZMQ bindings (`zmq`, `tmq`, `tokio_zmq`, etc.) | PRESENT | – |
| G29 | ferrous-utils MUST NOT contain HTTP server / REST bindings (`actix_web`, `axum`, `hyper::Server`, `warp`, `rocket`, `TcpListener`) | PRESENT | – |
| G30 | ouroboros/src/ MUST NOT contain `subprocess.*shell=True` with f-string / %-format / `.format(` interpolation of node state | PRESENT (pre-emptive guard against BUG-20) | – |

Status summary
--------------

PRESENT: 12 gates (G1, G3, G5c, G6, G7, G10, G12, G14-G18, G28, G29, G30).
PARTIAL: 8 gates (G2, G4, G5, G5b, G5d, G13, G20, G22).
MISSING: 14 gates (G8, G9, G10b, G11, G19, G21, G23, G24, G24b, G24c, G24d, G25, G26, G27).

Bug inventory (21 bugs)
-----------------------

**P0-CDIV (4)** — observable behavioral divergence from Core's
public API contract:

- **BUG-1 (P0-CDIV)** — `node.py:954` `self.zmq_publisher`
  attribute does not exist; mempool-accept ZMQ notifications
  never fire. Fix: `s/zmq_publisher/zmq_notifier/`.
- **BUG-2 (P0-CDIV)** — `node.py:519` calls
  `block_sync.set_zmq_notifier` but the method is named
  `set_zmq_publisher`; any non-empty `zmqpub*` config option
  crashes node startup with `AttributeError`. Fix: rename method
  in `block_sync.py:400` OR call the existing name from
  `node.py:519`.
- **BUG-3 (P0-CDIV)** — no production call sites for
  `notify_block_disconnect` / `notify_transaction_removed`;
  `sequence` topic labels `'R'` and `'D'` never fire. Fix: wire
  into reorg path in `block_sync.py` and mempool eviction in
  `mempool.py`.
- **BUG-4 (P0-CDIV)** — `notify_block` not IBD-gated; floods
  ZMQ during initial sync. Fix: `if not self.in_ibd:` guard at
  `block_sync.py:1380`.
- **BUG-12 (P0-CDIV)** — REST `chaintipHash` /
  `bestblockhash` / `blockhashbyheight` use internal byte-order
  hex; Core uses display-order. Fix: `.hex()` → `[::-1].hex()`
  at `rest.py:1080,1170,1176,1229`.

**P0-CVE-class (1)** — pre-emptive shell-injection guard:

- **BUG-20 (P0-CVE-class, pre-emptive)** — when BUG-19
  (`-blocknotify` / `-alertnotify` / `-walletnotify` support)
  lands, the implementer MUST sanitize untrusted strings
  (alert text, wallet name) per Core's
  `SanitizeString(rule=SAFE_CHARS_DEFAULT)` + `ShellEscape`
  pattern. Block-hash and txid `%s` are safe because they are
  already `[0-9a-f]{64}`-validated upstream. G30 codifies the
  guard.

**P1 (11)** — feature gap or operator-visible divergence that
isn't user-data corrupting:

- **BUG-5 (P1)** — per-topic HWM config option (`<topic>hwm`)
  absent.
- **BUG-7 (P1)** — `unix://` → `ipc://` address rewrite absent.
- **BUG-8 (P1)** — `start()` not idempotent; second call
  raises `Address already in use`.
- **BUG-9 (P1)** — `/rest/blockpart/` route absent.
- **BUG-10 (P1)** — `/rest/spenttxouts/` route absent.
- **BUG-13 (P1)** — REST cross-endpoint byte-order convention
  drift; needs a single comment-pinned helper.
- **BUG-14 (P1)** — REST 4xx bodies emit FastAPI JSON envelope
  instead of Core's `text/plain` + `\r\n`.
- **BUG-15 (P1)** — REST warmup gate (`503`) absent.
- **BUG-19 (P1)** — `-blocknotify` / `-alertnotify` /
  `-walletnotify` argv support absent.
- (BUG-2 above also counts as P1 architecturally — but
  promoted to P0-CDIV by severity of "node won't start.")
- (BUG-1 above also counts as P1 architecturally — but
  promoted to P0-CDIV by severity of "feature silently dead.")

**P2 (5)** — cosmetic / pre-emptive / portability:

- **BUG-6 (P2)** — `ZMQ_IPV6` opt-in for IPv6 addresses
  absent.
- **BUG-11 (P2)** — `/rest/deploymentinfo` route absent.
- **BUG-16 (P2)** — `/rest/mempool/contents` `verbose` accepts
  any FastAPI-coerced bool string.
- **BUG-17 (P2)** — REST headers JSON emits `previousblockhash:
  null` instead of omitting the field on genesis.
- **BUG-18 (P2)** — `/rest/chaininfo` (no `.json` suffix) gets
  FastAPI 404 not Core "output format not found" text.
- **BUG-21 (P2)** — `notify_block` doesn't fire on locally-
  mined blocks (no mining/submit path in ouroboros today, but
  pre-emptive).

Closure plan (recommended sequence)
-----------------------------------

**Phase A — P0-CDIV cascade closure (5 bugs).** Single fix-wave;
estimate ~1.5 hours.

1. `node.py:954`: `s/self\.zmq_publisher/self.zmq_notifier/`.
2. `node.py:519`: change to
   `self.block_sync.set_zmq_publisher(self.zmq_notifier)`
   (matches existing block_sync API).
3. `block_sync.py`: wire `notify_block_disconnect` at the
   block-disconnect callsite (search for "disconnect"). Wire
   `notify_transaction_removed` in `mempool.py` at every
   eviction-reason path.
4. `block_sync.py:1380`: gate
   `self._zmq_publisher.notify_block` behind `if not self.in_ibd:`.
5. `rest.py:1080,1170,1176,1229`: reverse `.hex()` for
   display-order hashes.

**Phase B — P0-CVE-class pre-emptive guard.** Already codified
by G30; no production code lands.

**Phase C — P1 feature closures (8 bugs).** Sequence:

6. Add `<topic>hwm` config keys (5 new keys in
   `config.py:168-172`) and read in `node.py:497-516`
   (BUG-5).
7. `zmq_notifier.py:configure_endpoint`: rewrite `unix://...`
   prefix to `ipc://...` (BUG-7).
8. `zmq_notifier.py:start`: idempotent guard `if self._started:
   return` (BUG-8).
9. `rest.py`: add `/rest/blockpart/`, `/rest/spenttxouts/`,
   warmup-gate, `text/plain` error replies, single helper for
   byte-order convention (BUG-9, BUG-10, BUG-13, BUG-14,
   BUG-15).
10. `cli.py` + `config.py`: add `-blocknotify`,
    `-alertnotify`, `-walletnotify` argv parsing and event
    wiring. Implementation MUST follow Core's sanitization
    contract exactly — see BUG-20 (BUG-19).

**Phase D — P2 cosmetics.** Defer until P0/P1 close.

Estimated full closure
----------------------

Phase A: ~1.5 hours.
Phase C: ~6 hours (largest item is BUG-19 — the three
notify-script hooks, each with proper sanitization).
Phase D: ~2 hours.

Total ~9.5 hours single-impl fix-wave work.

Test corpus
-----------

`tests/test_w141_zmq_rest_notify.py` installs 30 gates with
xfail markers for every MISSING / PARTIAL gate. xfails flip
to XPASS the moment any closure phase lands. PRESENT gates
are plain asserts that pin Core-parity wiring. Three dedicated
two-pipeline / shell-injection guards (G28, G29, G30) extend
the cumulative guard set.

Cross-impl cross-reference
--------------------------

ZMQ + REST are external-facing — their gaps are operator-visible
but not cross-impl-divergent in the consensus sense. Notification
scripts are operator-tooling; the same gap likely exists in every
other ouroboros-class implementation (Python/Bun/Go/Lua/Erlang
nodes). Future fleet-wide W### wave should catalogue these gaps
across rustoshi / blockbrew / clearbit / nimrod / camlcoin /
beamchain / hotbuns / lunarblock / haskoin.

The shell-injection footgun (BUG-20) is universal — any impl
that closes its `-blocknotify` gap by naively interpolating
untrusted strings into `system(3)` / `exec` / `subprocess
(shell=True)` opens an RCE. The G30 guard in this test file
is the model for those future audits.
