W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (ouroboros)
==========================================================================

Date: 2026-05-18
Impl: ouroboros (Python + Rust two-pipeline; HTTP/RPC is Python only)
Wave: W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (DISCOVERY)
Reference:
  - `bitcoin-core/src/httpserver.{cpp,h}` (HTTP, allow-list, work queue, threads)
  - `bitcoin-core/src/httprpc.cpp` (Basic auth, rpcauth, whitelist, batch)
  - `bitcoin-core/src/rpc/request.{cpp,h}` (`JSONRPCRequest::parse`, JSON-RPC 1/2, notifications, GenerateAuthCookie)
  - `bitcoin-core/src/rpc/server.cpp` + `rpc/protocol.h` (HTTP_* codes, error mapping)
  - `bitcoin-core/share/rpcauth/rpcauth.py` (rpcauth salt + HMAC-SHA256 string format)
  - `bitcoin-core/src/init.cpp` (boot order + warning surface)

Status: 30 gates audited — PRESENT 5 / PARTIAL 3 / MISSING 22. **23 BUGS** (6 P0-SEC / 2 P0 / 13 P1 / 2 P2).

Two-pipeline guard
------------------

HTTP / JSON-RPC / cookie auth is **Python only** on ouroboros. `ferrous-utils`
Rust crate is the IBD validation + RocksDB sync pipeline; it does NOT serve
HTTP, JSON-RPC, or authenticate anything. All bytes on the HTTP wire flow
through `src/ouroboros/rpc.py` (FastAPI / uvicorn) and
`src/ouroboros/cookie_auth.py`.

```
$ grep -rn "JsonRpc\|json_rpc\|httprpc\|HttpRpc\|http_rpc\|rpcauth\|RpcAuth\|cookie_auth\|CookieAuth\|RPCServer" \
       ferrous-utils/                       → 0 matches
$ grep -rn "WWW-Authenticate\|Basic realm\|fastapi\|uvicorn"  \
       ferrous-utils/                       → 0 matches
```

**Two-pipeline guard PRESERVED** and EXTENDED. W140's test file adds a
dedicated guard:
  - `test_w140_two_pipeline_http_rpc_python_only` — greps `ferrous-utils/` for
    `HTTPBasic`, `fastapi`, `uvicorn`, `rpcauth`, `cookie_auth`, `RPCServer`,
    `WWW-Authenticate`, `BasicAuth`, `evhttp`. Must return 0 matches across the
    full crate. This is the 6th dedicated two-pipeline guard added across
    W76 → W122 → W125 / W128 / W129 / W137 → W140 and the first targeting the
    HTTP/auth surface specifically.

The Python pipeline is the ONLY HTTP/RPC surface; every bug in this audit is
Python-side and changing `ferrous-utils` cannot regress them.

Scope
-----

Three system-level shapes drive the bulk of the bugs:

W125 already documented (a) the dispatcher's `HTTPException → -32603` collapse
(F2 in w125_rpc_error_parity.md) and (b) wallet-RPC error-as-result-not-error
(F3). W140 stays away from those error-code semantics and instead audits the
HTTP wire-layer + auth + dispatch shape that surrounds them: who can reach the
port, what credentials we accept, how we compare them, how we frame
responses, what HTTP status codes we emit, what we put in cookies, what we
log, and what we leak.

Top-level architectural findings
--------------------------------

**(F1) "Cookie OR plaintext, no rpcauth, no whitelist, no allow-list."**
Bitcoin Core supports three credential channels: (1) `.cookie` file
(`__cookie__:<hex>`), (2) `-rpcuser`/`-rpcpassword` (plaintext in config,
hashed at boot with random salt + HMAC-SHA256), (3) `-rpcauth=<user>:<salt>$<hex>`
lines (multiple users, pre-hashed credentials). Core ALSO supports a per-user
`-rpcwhitelist=<user>:<comma-method-list>` plus `-rpcwhitelistdefault`.
ouroboros supports only (1) and (2) — `-rpcauth` does not exist anywhere
under `src/ouroboros/`, and there is no whitelist mechanism (BUG-1, BUG-2).

**(F2) Single-user credential comparison uses `!=` instead of a constant-time
comparator** (BUG-3, P0-SEC). `_get_credentials` at `rpc.py:1274` does
`credentials.username != self.username or credentials.password != self.password`,
which short-circuits on the first mismatching byte. Combined with the
unconditional 250 ms Core sleep that ouroboros DOES NOT IMPLEMENT (BUG-4,
P0-SEC), an attacker on a low-latency LAN can timing-probe the password byte
by byte. Core's `CheckUserAuthorized` uses `TimingResistantEqual` for both the
username and the HMAC-SHA256 of the password (`httprpc.cpp:66-77`).

**(F3) IP allow-list is missing — only Core defaults are honored.**
Bitcoin Core's `ClientAllowed()` matches the client address against a
runtime-built list seeded with `127.0.0.1/8` + `::1` plus every
`-rpcallowip=` value (`httpserver.cpp:137-168`). When the allow-list is empty
AND `-rpcbind` is empty Core binds to localhost only and refuses everyone
else. ouroboros binds unconditionally to `127.0.0.1` (`rpc.py:1329`,
`rpc.py:1316`) ignoring the operator's `rpcbind`/`rpcallowip` config keys
entirely. The keys EXIST in the defaults (`config.py:150-151`) and are
plumbed into `to_dict()` (`config.py:315-316`) but **never read by the RPC
server** (BUG-5, P0-SEC; BUG-6, P1). Greppable evidence:

```
$ grep -n 'rpc_allow_ip\|rpc_bind' src/ouroboros/rpc.py    → 0 matches
$ grep -n 'rpc_allow_ip\|rpc_bind' src/ouroboros/node.py   → 0 matches
```

The bind-to-localhost default is correct accidentally; setting
`rpcbind=0.0.0.0` in `bitcoin.conf` does nothing and the operator's intent is
silently dropped. An operator who DOES want LAN-side RPC has no way to enable
it. Conversely, if a future refactor flips `host="127.0.0.1"` to anything
configurable, the allow-list enforcement gap becomes a remote-RPC
exposure.

**(F4) Cookie file format diverges from Core in a subtle way.**
Core writes the cookie atomically — open `<file>.tmp`, write, close, rename
over `<file>` (`request.cpp:113-128`). ouroboros writes directly with
`cookie_path.write_text(...)` (`cookie_auth.py:24`). A concurrent reader who
opens the file mid-write sees a truncated cookie (BUG-7, P1). Core also emits
the cookie at boot with a write-then-rename so partial reads are
structurally impossible; ouroboros has no such guarantee.

**(F5) Auth + dispatch interleave invites information leaks.**
`_handle_rpc_common` (`rpc.py:1081-1172`) runs auth → rate limit → JSON
parse → dispatch. Several leaks: (i) rate limit is checked AFTER auth and
keyed on `client_ip` only — an unauth'd attacker can still consume the
authenticated user's rate limit budget by sending arbitrary `X-Forwarded-For`
spoofed values that the server trusts unconditionally (`rpc.py:1284-1286`,
BUG-9, P0-SEC). (ii) Rate limit on auth failure does not exist — an attacker
gets infinite credential-guess attempts (Core has the 250 ms sleep AND
LogWarning of the source IP; ouroboros has neither, BUG-4 + BUG-10). (iii)
The `HTTPException` raised by `_get_credentials` propagates up; FastAPI emits
the response, BUT the rate-limit + JSON-parse paths emit JSON-RPC error
shapes that LEAK whether a method exists, batches are larger than expected,
etc. — to a caller who is not yet authenticated (BUG-11, P1).

**(F6) JSON-RPC framing does not implement JSON-RPC 2.0 V2 semantics.**
Core distinguishes V1_LEGACY vs V2 by the `"jsonrpc"` field on each request
(`request.cpp:213-230`). V2 requests with no `id` are NOTIFICATIONS and MUST
NOT receive a response (`request.h:66`); V2 requests with errors MUST return
HTTP 200 with the error in the body (`httprpc.cpp:163-165 catch_errors`); V1
returns HTTP 400/404/500 based on the inner code. ouroboros's `JSONRPCRequest`
Pydantic model has a `jsonrpc: str = "2.0"` default but the dispatcher (a)
NEVER inspects this field and (b) ALWAYS frames the response as
`{"jsonrpc": "2.0", "result": ..., "id": ...}` regardless of what the client
sent. So V1 clients see a `"jsonrpc": "2.0"` reply (wrong); V2 notifications
get a full response back (wrong, BUG-12 / BUG-13 / BUG-14, three P1).

**(F7) HTTP method enforcement, request-size limits, and content-type
enforcement are all FastAPI/uvicorn defaults — Core's tight rejection points
are missing.**
Core rejects (a) any method != POST with HTTP 400 (`httprpc.cpp:107-109`),
(b) max-headers > 8 KiB (`httpserver.cpp:51`), (c) max-body > MAX_SIZE
(0x02000000 = 32 MiB), (d) unknown HTTP methods with HTTP 405. ouroboros
inherits FastAPI's behavior which is generally HTTP 405 for unknown methods
on a registered path but DOES NOT cap header size or body size (BUG-15 + BUG-16
+ BUG-17). A malicious client can send a 10 GiB request body and consume the
node's memory.

Bug catalogue
-------------

Severity legend:
  - **P0-SEC** = security regression (credential exposure, remote access,
    timing leak, resource exhaustion via remote bytes).
  - **P0** = Core-divergent operator-facing behavior with no security impact.
  - **P1** = Core-divergent behavior, low operational impact.
  - **P2** = polish / hygiene.

### BUG-1 (P0) `-rpcauth` (hashed multi-user creds) is not implemented

Core supports zero-or-more `-rpcauth=<user>:<salt>$<hex>` lines via
`g_rpcauth` (`httprpc.cpp:36, 290-304`). The format is `user:hex(salt)$hex(hmac_sha256(salt, password))`
matching `share/rpcauth/rpcauth.py`. Each call iterates `g_rpcauth` and runs
HMAC-SHA256 of the supplied password against every stored salt, comparing
with `TimingResistantEqual`.

ouroboros has zero `rpcauth` surface. The `RPCServer` takes a single
`username` / `password` pair (`rpc.py:850-861`) compared via `!=`. Multi-user
deployments — common operationally for Lightning nodes, miners, monitoring
sidecars — cannot exist.

Reference: `bitcoin-core/src/httprpc.cpp::InitRPCAuthentication` lines 290-304.

### BUG-2 (P0) `-rpcwhitelist` per-user method ACL is not implemented

Core supports `-rpcwhitelist=<user>:<comma-method-list>` and
`-rpcwhitelistdefault=<bool>` (`httprpc.cpp:38-39, 306-326`). Authorized but
non-whitelisted users get HTTP 403 (`httprpc.cpp:148, 156, 187`). Both
singleton AND batch requests are pre-screened, so a batch with one
disallowed method is rejected wholesale.

ouroboros has no whitelist mechanism. Every authenticated user can call
every registered `rpc_*` method including `stop`, `dumpwallet`,
`importprivkey`, etc. Operationally critical for monitoring sidecars.

Reference: `bitcoin-core/src/httprpc.cpp` lines 144-191 + 306-326.

### BUG-3 (P0-SEC) Credential comparison is not constant-time

`rpc.py:1274`:
```python
if credentials.username != self.username or credentials.password != self.password:
```

Python's `str.__ne__` short-circuits on the first mismatching code point. An
attacker on a low-latency LAN (≤1 ms RTT to a Bitcoin RPC port) can binary-
probe the password byte-by-byte. Core uses `TimingResistantEqual` for both
fields (`httprpc.cpp:66, 77`). The standard library fix is
`secrets.compare_digest(a, b)`.

This is the single highest-severity bug in the audit because:
  (a) cookie-auth passwords are 32 random hex chars (256 bits entropy) and
      timing-probing a few bytes still leaves intractable brute-force, BUT
  (b) plaintext `-rpcpassword` configs in `bitcoin.conf` (BUG-1 makes
      `-rpcauth` unavailable so operators that want multi-user setups fall
      back to plaintext) are typically short/memorable and ARE probeable.

Reference: `bitcoin-core/src/httprpc.cpp::CheckUserAuthorized` line 66.

### BUG-4 (P0-SEC) No 250 ms anti-brute-force sleep on auth failure

`httprpc.cpp:128`:
```cpp
UninterruptibleSleep(std::chrono::milliseconds{250});
```

Core sleeps 250 ms inline on every auth failure to make brute-force
infeasible at any scale (4 attempts/sec/IP). ouroboros immediately raises
HTTP 401 — no sleep, no rate limit on the auth path. Combined with BUG-3
+ BUG-9 (X-Forwarded-For spoofing), an attacker can issue thousands of
credential attempts per second.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` lines 122-132.

### BUG-5 (P0-SEC) `-rpcallowip` is silently ignored

Operator sets `rpcallowip=192.168.1.0/24` in `bitcoin.conf`. Config plumbs
it through `Config.get('rpcallowip')` and `to_dict()` exposes `rpc_allow_ip`
(`config.py:315`). The RPC server never reads it; `_handle_rpc_common` does
NOT match `request.client.host` against any allow-list (`rpc.py:1081-1172`).
Net result: setting `rpcallowip` does nothing.

Today this is masked because the listener is hard-coded to `127.0.0.1` (BUG-6),
but the moment BUG-6 lands or the operator binds via a reverse proxy, the
absence of allow-list enforcement becomes an open RPC port to anyone who can
reach the proxy.

Reference: `bitcoin-core/src/httpserver.cpp::ClientAllowed` lines 137-145
+ `InitHTTPAllowList` lines 147-168.

### BUG-6 (P1) `-rpcbind` is silently ignored

`rpc.py:1316` and `rpc.py:1329` hard-code `127.0.0.1` for both the
port-already-in-use probe AND the uvicorn bind. The operator's `rpcbind`
config key (config.py:151, exposed in `to_dict()` as `rpc_bind`) is plumbed
but never consulted. Operators expecting `rpcbind=0.0.0.0` or
`rpcbind=192.168.1.5` to bind elsewhere get silent localhost binding with no
warning. Compare Core's loud `LogWarning("Option -rpcbind was ignored …")`
when `-rpcallowip` is missing (`httpserver.cpp:325-327`).

Reference: `bitcoin-core/src/httpserver.cpp::HTTPBindAddresses` lines 308-361.

### BUG-7 (P1) Cookie file write is not atomic

`cookie_auth.py:24`:
```python
cookie_path.write_text(f"{COOKIE_USER}:{password}")
```

`Path.write_text` opens, writes, closes. A reader (curl, monitoring sidecar)
that opens the file in the millisecond window between open and close sees an
empty or truncated cookie. Core opens `<file>.tmp`, writes, closes, then
`RenameOver` (`request.cpp:113-128`). The atomic rename is the contract
external readers depend on.

Reference: `bitcoin-core/src/rpc/request.cpp::GenerateAuthCookie` lines 112-128.

### BUG-8 (P1) Cookie permissions are 0600 unconditionally — `-rpccookieperms` is missing

Core supports `-rpccookieperms={owner,group,all}` (`httprpc.cpp:248-256`).
The default is no chmod, relying on the boot umask 0077
(`request.cpp:109-110`). Operators who want a `group` cookie (e.g.
LND/Eclair daemons running as a different unix user but the same group as
bitcoind) cannot.

`cookie_auth.py:26` always emits `chmod 0o600`. Catches the Windows case
with a `try/except OSError: pass` but loses the operator's intent.

Reference: `bitcoin-core/src/httprpc.cpp::InitRPCAuthentication` lines 247-256.

### BUG-9 (P0-SEC) `X-Forwarded-For` header is trusted unconditionally

`rpc.py:1284-1286`:
```python
forwarded = request.headers.get("X-Forwarded-For")
if forwarded:
    return forwarded.split(",")[0].strip()
```

Any client can send `X-Forwarded-For: 8.8.8.8` and impersonate that IP for
the rate-limit bookkeeping. There is no `--rpc-trust-proxy` toggle, no
proxy-IP allow-list, no documented invariant about which proxies are
authoritative. Result: a single attacker IP can bypass any rate limit by
rotating spoofed XFF values (the per-IP rate-limit dict grows unboundedly
— see BUG-23 below for the unbounded-dict DoS aspect).

Core does not consult `X-Forwarded-For` at all; `ClientAllowed` and
`peerAddr` use the TCP-layer source address exclusively
(`httpserver.cpp:217`, `httprpc.cpp:121`).

Reference: `bitcoin-core/src/httpserver.cpp::http_request_cb` line 217;
the absence of X-Forwarded-For parsing anywhere in `httpserver.cpp`.

### BUG-10 (P1) Failed auth attempts are not logged with the source IP

Core: `LogWarning("ThreadRPCServer incorrect password attempt from %s", jreq.peerAddr);`
(`httprpc.cpp:123`). ouroboros: silent failure. Operators have no
fail2ban-style log surface to detect brute-force attempts. Combined with
BUG-4 (no sleep) and BUG-9 (XFF spoof), brute-force is invisible.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` line 123.

### BUG-11 (P1) Unauth'd clients can probe rate-limit + JSON-parse paths

The dispatcher (`rpc.py:1081-1113`) order is:
  1. auth (`_get_credentials`)         — only when `self.security` is set
  2. rate-limit (`_check_rate_limit`)  — always
  3. body parse (`json.loads`)         — always

If `self.security` is None (auth disabled — also a config footgun, BUG-22),
steps 2 + 3 run unauthenticated. Worse, an attacker that sends a parse-error
body gets `{"error":{"code":-32700,"message":"Parse error: ..."}}` — useful
to fingerprint the server.

Core's pipeline rejects with HTTP 401 BEFORE any body parsing or rate
accounting (`httprpc.cpp:111-133`). Unauthenticated reqs never reach the
JSON parser, never consume rate-limit budget.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` lines 111-138.

### BUG-12 (P1) `jsonrpc` request field is never inspected

Core parses `"jsonrpc"` into a V1_LEGACY / V2 enum
(`request.cpp:213-230`). ouroboros has a `JSONRPCRequest` Pydantic model
with `jsonrpc: str = "2.0"` (`rpc.py:419`) but `_execute_single_rpc`
(`rpc.py:1011-1073`) and `_handle_rpc_common` (`rpc.py:1081-1172`) never
read the field. The framing is always V2-style regardless of input.

Reference: `bitcoin-core/src/rpc/request.cpp::JSONRPCRequest::parse` lines 213-230.

### BUG-13 (P1) V2 notifications (`id` missing AND `"jsonrpc":"2.0"`) get a full response

Core: V2 notifications return HTTP 204 No Content with no body
(`httprpc.cpp:167-171`). ouroboros at `rpc.py:1059-1073` returns
`{"jsonrpc": "2.0", "result": ..., "id": null}` for every request even
notifications, AND the batch path at `rpc.py:1153` filters notifications
based on `"id" in req` — but the singleton path
(`rpc.py:1160-1162`) does NOT.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` lines 167-171.

### BUG-14 (P1) V1 clients get a V2-shaped reply

Core's V1_LEGACY response includes BOTH `"result"` and `"error"` keys (one
non-null, the other null) and NO `"jsonrpc"` field (`request.cpp:51-66`).
ouroboros emits `"jsonrpc": "2.0"` unconditionally (`rpc.py:1035, 1046,
1059, 1063, 1070`). V1 clients (older curl examples, bitcoin-cli compatible
libraries) MUST tolerate this; tools that assert response shape will reject
the response.

Reference: `bitcoin-core/src/rpc/request.cpp::JSONRPCReplyObj` lines 51-68.

### BUG-15 (P1) Unknown HTTP methods do not return HTTP 405

Core's `http_request_cb` (`httpserver.cpp:225-229`) rejects unknown methods
with HTTP 400. JSON-RPC also rejects non-POST with HTTP 405
(`httprpc.cpp:107-109`). ouroboros relies on FastAPI's path-handler routing
which gives HTTP 405 for GET /wallet/foo (registered as POST) and HTTP 404
for completely-unknown paths. GET /, PUT /, DELETE / all return 405 but
the body / headers differ from Core in a way that breaks clients that
assert on the bytes.

Reference: `bitcoin-core/src/httpserver.cpp::http_request_cb` lines 224-230.

### BUG-16 (P1) No max-headers-size cap

Core caps HTTP headers at `MAX_HEADERS_SIZE = 8192` via
`evhttp_set_max_headers_size` (`httpserver.cpp:51, 409`). ouroboros / uvicorn
defaults to a much larger header allowance (16 KiB minimum, configurable up
to MAX_INT). An attacker can send 100 MiB of garbage headers to consume
memory.

Reference: `bitcoin-core/src/httpserver.cpp` lines 51 + 409.

### BUG-17 (P0-SEC) No max-body-size cap

Core caps body at `MAX_SIZE` (0x02000000 = 32 MiB) via
`evhttp_set_max_body_size` (`httpserver.cpp:410`). ouroboros / uvicorn
default is unlimited body size. `await http_request.body()` at
`rpc.py:1104` reads the full body into memory before any JSON parsing.
Result: a malicious client on a localhost socket can send a 10 GiB body
and OOM-kill the node.

Reference: `bitcoin-core/src/httpserver.cpp` line 410.

### BUG-18 (P1) Empty batch returns JSON error not HTTP 204

Core's V2 spec: empty batches return HTTP 204 No Content with no body
(`httprpc.cpp:220-223`). ouroboros returns HTTP 200 with
`{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request: empty batch"},"id":null}`
(`rpc.py:1117-1125`). This is a JSON-RPC 2.0 spec deviation Core specifically
calls out and preserves for compatibility.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` lines 213-223.

### BUG-19 (P1) Batches with `jsonrpc:"1.0"` requests in array don't degrade per-request

Core's batch path (`httprpc.cpp:194-210`) parses each request element
individually, allowing mixed V1/V2 batches; each response uses its
originating request's version. ouroboros's batch path
(`rpc.py:1140-1157`) frames every response as V2.

Reference: `bitcoin-core/src/httprpc.cpp::HTTPReq_JSONRPC` lines 174-223.

### BUG-20 (P2) CORS is wildcard-open by default

`rpc.py:904-910`:
```python
self.app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`allow_origins=["*"]` AND `allow_credentials=True` is a documented
mis-configuration — most browser implementations will refuse to send
credentials with a wildcard origin, but the policy advertised by the
server is "any origin can supply credentials". A user who navigates to a
malicious site while their `.cookie` is in browser scope (unusual but
possible via misconfigured proxies) could be tricked into issuing
authenticated RPCs.

Core has no CORS surface — clients are CLI / library callers that don't
care about CORS. The reasonable default in a JSON-RPC server is no CORS
headers at all.

Reference: `https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials`.

### BUG-21 (P2) `/health` and `/getblockstats` GET endpoints are unauthenticated

`rpc.py:1191-1194`:
```python
@self.app.get("/health")
async def health():
    return {"status": "healthy", "service": "bitcoin-rpc"}
```

Health and GET-style endpoints (also `/getblockstats`, `/getblockfilter`)
bypass auth. Core does not register any GET endpoint on the JSON-RPC port;
the REST interface is a SEPARATE listener (registered via
`RegisterHTTPHandler("/rest/", false, …)`) and is gated by `-rest=1` AND
its own port plumbing. Mixing JSON-RPC + REST on the same listener +
sharing the same auth/no-auth decision matrix invites confusion.

Reference: `bitcoin-core/src/httprpc.cpp::StartHTTPRPC` lines 337-341.

### BUG-22 (P0-SEC) Auth can be silently disabled with no warning

`rpc.py:914`:
```python
self.security = None
if username and password:
    self.security = HTTPBasic()
```

When `username` OR `password` is empty, `self.security` is None and the
auth check in `_handle_rpc_common` (`rpc.py:1087`) is skipped. Today
`node.py:189-192` guarantees a cookie is always generated if rpc_user/pass
is empty, so this path is masked in production. BUT:

  - A future refactor or operator override (env var, alternate entry point)
    could pass `username=None` to `RPCServer.__init__`.
  - There is no audit-time warning logged when `self.security is None`.

Core's `InitRPCAuthentication` returns FALSE and aborts node startup if no
credentials can be assembled (`httprpc.cpp:240-273`). ouroboros silently
opens the port with zero auth.

Reference: `bitcoin-core/src/httprpc.cpp::InitRPCAuthentication` lines 240-273.

### BUG-23 (P1) Per-IP rate-limit dict is unbounded

`rpc.py:120, 1296`:
```python
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
...
requests = _rate_limit_store[client_ip]
```

`defaultdict` adds a new entry on every previously-unseen IP. Combined
with BUG-9 (X-Forwarded-For spoofing), an attacker rotates 1M unique
`X-Forwarded-For: 10.x.y.z` values and grows the dict to 1M entries × N
floats each. No LRU, no max-entries cap, no periodic prune.

Core's rate limit is a work-queue depth cap (`g_max_queue_depth`,
`httpserver.cpp:79, 255-258`), bounded and shared across ALL clients.

Reference: `bitcoin-core/src/httpserver.cpp` lines 79 + 254-258.

Audit / behavior matrix (G1-G30)
--------------------------------

| Gate | Subsystem | Status | Bug |
|------|-----------|--------|-----|
| G1   | rpcauth (hashed multi-user) | MISSING | BUG-1 P0 |
| G2   | rpcwhitelist | MISSING | BUG-2 P0 |
| G3   | rpcwhitelistdefault | MISSING | BUG-2 P0 |
| G4   | Constant-time credential compare | MISSING | BUG-3 P0-SEC |
| G5   | 250 ms anti-brute-force sleep | MISSING | BUG-4 P0-SEC |
| G6   | -rpcallowip enforcement | MISSING | BUG-5 P0-SEC |
| G7   | -rpcbind enforcement | MISSING | BUG-6 P1 |
| G8   | Cookie atomic write (RenameOver) | MISSING | BUG-7 P1 |
| G9   | -rpccookieperms (owner/group/all) | MISSING | BUG-8 P1 |
| G10  | X-Forwarded-For ignored / trust-proxy | MISSING | BUG-9 P0-SEC |
| G11  | Auth-failure source-IP log | MISSING | BUG-10 P1 |
| G12  | Unauth req rejected before rate/parse | MISSING | BUG-11 P1 |
| G13  | jsonrpc field parsed (V1/V2 enum) | MISSING | BUG-12 P1 |
| G14  | V2 notifications → HTTP 204 | MISSING | BUG-13 P1 |
| G15  | V1 reply shape (result+error, no jsonrpc) | MISSING | BUG-14 P1 |
| G16  | Non-POST method → HTTP 405 | PARTIAL | BUG-15 P1 |
| G17  | Max headers size (8 KiB) | MISSING | BUG-16 P1 |
| G18  | Max body size (32 MiB) | MISSING | BUG-17 P0-SEC |
| G19  | Empty batch → HTTP 204 | MISSING | BUG-18 P1 |
| G20  | Mixed V1/V2 batches | MISSING | BUG-19 P1 |
| G21  | CORS not wildcard-open w/ credentials | MISSING | BUG-20 P2 |
| G22  | GET endpoints behind auth | MISSING | BUG-21 P2 |
| G23  | Auth required (no silent disable) | PARTIAL | BUG-22 P0-SEC |
| G24  | Per-IP rate-limit bounded | MISSING | BUG-23 P1 |
| G25  | Cookie filename (.cookie) | PRESENT  | – |
| G26  | Cookie user (__cookie__) | PRESENT  | – |
| G27  | Cookie deleted on shutdown | PRESENT  | – |
| G28  | WWW-Authenticate realm="jsonrpc" | PRESENT  | – |
| G29  | Batch size cap (max_batch_size=1000) | PARTIAL | – (sized but no Core parity) |
| G30  | Two-pipeline guard (Rust no HTTP) | PRESENT  | – (extended) |

(PRESENT = matches Core behavior. PARTIAL = present but diverges. MISSING =
absent. P0-SEC = security regression. P0 = Core-divergent operator-facing
behavior. P1 = lower-impact divergence. P2 = polish.)

Summary
-------

23 bugs catalogued (6 P0-SEC / 2 P0 / 13 P1 / 2 P2). Five orthogonal areas
drive the findings:

1. **Auth surface gaps** (BUG-1, BUG-2, BUG-3, BUG-4, BUG-10, BUG-22) — no
   `-rpcauth`, no `-rpcwhitelist`, non-constant-time compare, no
   anti-brute-force sleep, no source-IP logging, no fail-closed on missing
   creds.
2. **Network exposure surface gaps** (BUG-5, BUG-6, BUG-9, BUG-21) —
   `-rpcallowip` ignored, `-rpcbind` ignored, X-Forwarded-For trusted,
   unauth GET endpoints.
3. **Cookie hygiene** (BUG-7, BUG-8) — non-atomic write, hard-coded perms.
4. **JSON-RPC framing divergence** (BUG-12, BUG-13, BUG-14, BUG-18,
   BUG-19) — V1/V2 enum, notifications, empty-batch shape.
5. **Resource exhaustion surface** (BUG-15, BUG-16, BUG-17, BUG-20,
   BUG-23) — header cap, body cap, CORS, rate-limit dict bound.

**Priority closure recommendation** (security first):

  1. BUG-17 max-body cap — 5-line fix, prevents trivial OOM
  2. BUG-3 constant-time compare — 1-line `secrets.compare_digest` swap
  3. BUG-9 stop trusting X-Forwarded-For — 5-line removal of the
     `forwarded` branch in `_get_client_ip_from_request`
  4. BUG-22 fail-closed when creds empty — 3-line abort in `__init__`
  5. BUG-5 + BUG-6 honor `rpc_allow_ip` / `rpc_bind` — ~30-line listener
     refactor + ACL check in `_handle_rpc_common`
  6. BUG-4 250 ms sleep — 1-line `await asyncio.sleep(0.25)` on auth failure
  7. BUG-1 `-rpcauth` HMAC-SHA256 parser + verifier — single-file ~60 LOC
     addition, biggest operator-facing gap

A future FIX-W140 wave should close BUG-1 through BUG-9 + BUG-17 + BUG-22 as
a single P0-SEC bundle; the framing bugs (BUG-12 through BUG-19) are lower
priority and benefit from a coordinated V1_LEGACY / V2 enum on top.

Test file: `src/ouroboros/tests/test_w140_http_rpcauth.py` (30-gate
xfail / present mix; two-pipeline guard preserved + extended).

Source-of-truth: this audit; no production code touched.
