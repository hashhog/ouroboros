"""W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (ouroboros).

DISCOVERY wave: 30 gates audited against
  bitcoin-core/src/httpserver.{cpp,h}, httprpc.cpp,
  rpc/request.{cpp,h}, rpc/server.cpp, rpc/protocol.h,
  share/rpcauth/rpcauth.py, init.cpp.

This file contains an xfail test per Core-divergent gate; the xfails flip to
XPASS the moment a fix lands. PRESENT gates are plain asserts that pin the
current Core-parity wiring against regression.

Two-pipeline guard: HTTP / JSON-RPC / cookie auth is Python-only on
ouroboros. The Rust `ferrous-utils/` crate has no HTTP, no JSON-RPC, no
cookie auth surface — the dedicated guard test below (G30) enforces that
invariant.

Reference: ouroboros/audit/w140_http_rpcauth.md for the bug catalogue.

NO production code changes. NO behavior changes. Only audit + xfail tests.
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Bootstrap — tests/conftest.py installs the sync stub. We do the same
# import-once dance here so the file is self-contained when pytest collects
# it.
# ---------------------------------------------------------------------------
_src = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_src))

_tests_root = Path(__file__).resolve().parent.parent.parent.parent / "tests"
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))
try:
    import conftest  # noqa: E402,F401  - installs sync stub
except Exception:  # pragma: no cover
    pass

import ouroboros.cookie_auth as cookie_auth_mod  # noqa: E402
import ouroboros.rpc as rpc_mod  # noqa: E402
from ouroboros.cookie_auth import COOKIE_FILENAME, COOKIE_USER  # noqa: E402
from ouroboros.rpc import RPCServer  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"


# ===========================================================================
# Auth surface gates — G1-G5 (rpcauth, whitelist, constant-time, sleep)
# ===========================================================================


@pytest.mark.xfail(
    reason="W140 BUG-1 (P0): -rpcauth=<user>:<salt>$<hmac_sha256> is not "
           "implemented. Core's httprpc.cpp:36, 290-304 maintain g_rpcauth "
           "vector; ouroboros has no rpcauth parser or HMAC verifier.",
    strict=True,
)
def test_w140_g1_rpcauth_hashed_multiuser_credentials() -> None:
    """G1: ouroboros must support -rpcauth=<user>:<salt>$<hmac> lines.

    Core: each line is parsed, salt + HMAC-SHA256 stored, password is
    re-hashed on every auth attempt and compared time-resistantly. See
    `share/rpcauth/rpcauth.py` for the format. ouroboros currently takes
    a single plaintext (username, password) pair, no multi-user support,
    no hashed-credentials option.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    config_src = (SRC_OUROBOROS / "config.py").read_text(encoding="utf-8")
    assert "rpcauth" in src or "rpcauth" in config_src, (
        "G1: -rpcauth multi-user hashed-credential support must exist"
    )
    # HMAC-SHA256 password verification per Core httprpc.cpp:73-78.
    assert (
        re.search(r"hmac.*sha256", src, re.IGNORECASE)
        or re.search(r"HMAC.*SHA256", src)
    ), "G1: rpcauth verification must HMAC-SHA256 the supplied password"


@pytest.mark.xfail(
    reason="W140 BUG-2 (P0): -rpcwhitelist per-user method ACL is not "
           "implemented. Core: g_rpc_whitelist + g_rpc_whitelist_default "
           "(httprpc.cpp:38-39, 306-326). Authorized non-whitelisted users "
           "get HTTP 403.",
    strict=True,
)
def test_w140_g2_rpcwhitelist_per_user_method_acl() -> None:
    """G2: ouroboros must support -rpcwhitelist=<user>:<comma-methods>.

    Core's httprpc.cpp:144-191 rejects non-whitelisted methods with HTTP
    403 on both singleton and batch paths. ouroboros has no whitelist
    surface, so every authed user can call every rpc_* method
    (including stop, dumpwallet, importprivkey).
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    config_src = (SRC_OUROBOROS / "config.py").read_text(encoding="utf-8")
    has_whitelist = ("rpcwhitelist" in src or "rpcwhitelist" in config_src
                     or "rpc_whitelist" in src)
    assert has_whitelist, "G2: -rpcwhitelist surface must exist"


@pytest.mark.xfail(
    reason="W140 BUG-2 (P0): -rpcwhitelistdefault is not implemented.",
    strict=True,
)
def test_w140_g3_rpcwhitelistdefault_flag() -> None:
    """G3: ouroboros must support -rpcwhitelistdefault=<bool>.

    Core: g_rpc_whitelist_default toggles whether an unlisted user
    defaults to allow-all or deny-all (httprpc.cpp:39, 306).
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    config_src = (SRC_OUROBOROS / "config.py").read_text(encoding="utf-8")
    assert ("rpcwhitelistdefault" in src
            or "rpcwhitelistdefault" in config_src), (
        "G3: -rpcwhitelistdefault toggle must exist"
    )


@pytest.mark.xfail(
    reason="W140 BUG-3 (P0-SEC): credential compare uses `!=` short-circuit. "
           "Core uses TimingResistantEqual (httprpc.cpp:66, 77). Fix is "
           "secrets.compare_digest in rpc.py:1274.",
    strict=True,
)
def test_w140_g4_constant_time_credential_compare() -> None:
    """G4 (P0-SEC): credential comparison must be constant-time.

    Python's `str.__ne__` short-circuits on first mismatching byte. An
    attacker on a low-latency LAN (≤1 ms RTT) can binary-probe the
    password byte-by-byte. The fix is `secrets.compare_digest(a, b)`
    on BOTH username and password.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Look for compare_digest or hmac.compare_digest near _get_credentials.
    # Grab the function body and check for a constant-time comparator.
    m = re.search(
        r"async def _get_credentials.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_constant_time = (
        "compare_digest" in body
        or "TimingResistantEqual" in body
        or "constant_time" in body
    )
    assert has_constant_time, (
        "G4: _get_credentials must use secrets.compare_digest or "
        "hmac.compare_digest for both username and password"
    )


@pytest.mark.xfail(
    reason="W140 BUG-4 (P0-SEC): no 250 ms anti-brute-force sleep on auth "
           "failure. Core: UninterruptibleSleep(250ms) at httprpc.cpp:128.",
    strict=True,
)
def test_w140_g5_anti_bruteforce_sleep_250ms() -> None:
    """G5 (P0-SEC): a 250 ms sleep MUST follow every failed auth attempt.

    Without it, an attacker can attempt thousands of credentials per
    second against the RPC port. Core's 250 ms sleep makes
    brute-forcing infeasible at any scale.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"async def _get_credentials.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_sleep = (
        "asyncio.sleep(0.25" in body
        or "sleep(0.25" in body
        or "BRUTE_FORCE_SLEEP" in body
    )
    assert has_sleep, (
        "G5: _get_credentials must sleep ~250 ms on auth failure"
    )


# ===========================================================================
# Network exposure gates — G6-G11 (allow-ip, bind, cookie hygiene, XFF)
# ===========================================================================


@pytest.mark.xfail(
    reason="W140 BUG-5 (P0-SEC): -rpcallowip is silently ignored. Config key "
           "exists (config.py:150) but RPC server never reads it. Core: "
           "ClientAllowed + InitHTTPAllowList httpserver.cpp:137-168.",
    strict=True,
)
def test_w140_g6_rpcallowip_enforcement() -> None:
    """G6 (P0-SEC): RPC server must check client IP against -rpcallowip.

    Today the listener is hard-coded to 127.0.0.1 so the lack of ACL
    enforcement is masked. The moment binding becomes operator-controlled
    (BUG-6) or a reverse proxy fronts the node, the gap becomes an open
    RPC port.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    node_src = (SRC_OUROBOROS / "node.py").read_text(encoding="utf-8")
    # The Config key is plumbed but never used.  Look for a substantive
    # consumer: importing rpc_allow_ip OR rpcallowip and using it in an
    # ACL match (subnet match, IPv4Network in_subnet, etc.).
    has_acl = bool(
        re.search(r"rpc_allow_ip|rpcallowip", src)
        and re.search(r"ip_address|IPv4Network|IPv6Network|in_subnet|netaddr",
                      src)
    ) or bool(
        re.search(r"rpc_allow_ip|rpcallowip", node_src)
        and "allow_ip" in src
    )
    assert has_acl, (
        "G6: rpc.py must consult rpc_allow_ip / rpcallowip and match the "
        "client address against the allow-list"
    )


@pytest.mark.xfail(
    reason="W140 BUG-6 (P1): -rpcbind is silently ignored. rpc.py hard-codes "
           "host='127.0.0.1' at line 1329. Core: HTTPBindAddresses "
           "httpserver.cpp:308-361.",
    strict=True,
)
def test_w140_g7_rpcbind_enforcement() -> None:
    """G7: RPC server must bind to the operator-configured -rpcbind addr.

    The Config key `rpcbind` (default '127.0.0.1') is plumbed through
    `to_dict() -> rpc_bind` but RPCServer hard-codes `host='127.0.0.1'`
    on both the port-already-in-use probe (line 1316) AND the uvicorn
    bind config (line 1329).
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Look for a non-hard-coded host parameter in the listener config.
    # A correct fix passes a configured host/bind into Config(...).
    m = re.search(
        r'cfg_kwargs.*?host.*?(\"127\.0\.0\.1\"|self\.bind|self\.host)',
        src,
        re.DOTALL,
    )
    bind_is_config = bool(re.search(r'host.*=.*self\.(bind|host|rpc_bind)',
                                    src))
    assert bind_is_config, (
        "G7: uvicorn Config must take a configurable host (self.bind / "
        "self.host), not the literal '127.0.0.1'"
    )


@pytest.mark.xfail(
    reason="W140 BUG-7 (P1): cookie write is not atomic. Path.write_text "
           "opens+writes+closes without a tmp/rename dance. Core: "
           "filepath_tmp + RenameOver (request.cpp:113-128).",
    strict=True,
)
def test_w140_g8_cookie_atomic_write() -> None:
    """G8: cookie file write must be atomic (write to .tmp, then rename).

    A reader that opens the .cookie file mid-write sees a truncated
    cookie. Atomic rename closes the race.
    """
    src = (SRC_OUROBOROS / "cookie_auth.py").read_text(encoding="utf-8")
    has_atomic = (
        re.search(r"\.tmp.*?(rename|replace)", src, re.DOTALL)
        or "os.replace" in src
        or "Path.rename" in src
    )
    assert has_atomic, (
        "G8: generate_cookie must write to a .tmp path and rename atomically"
    )


@pytest.mark.xfail(
    reason="W140 BUG-8 (P1): -rpccookieperms is not supported; permissions "
           "are hard-coded 0o600. Core: cookie_perms_arg "
           "(httprpc.cpp:248-256).",
    strict=True,
)
def test_w140_g9_rpccookieperms_option() -> None:
    """G9: ouroboros must support -rpccookieperms={owner,group,all}.

    Lightning daemons + sidecars commonly run as separate unix users
    sharing a group; without -rpccookieperms=group the cookie cannot
    be shared.
    """
    src = (SRC_OUROBOROS / "cookie_auth.py").read_text(encoding="utf-8")
    config_src = (SRC_OUROBOROS / "config.py").read_text(encoding="utf-8")
    assert ("rpccookieperms" in src or "rpccookieperms" in config_src or
            "cookie_perms" in src), (
        "G9: -rpccookieperms operator option must exist"
    )


@pytest.mark.xfail(
    reason="W140 BUG-9 (P0-SEC): X-Forwarded-For header is trusted "
           "unconditionally. No --rpc-trust-proxy toggle. "
           "rpc.py:1284-1286.",
    strict=True,
)
def test_w140_g10_xforwarded_for_not_trusted_by_default() -> None:
    """G10 (P0-SEC): X-Forwarded-For must not be trusted by default.

    Core does not consult X-Forwarded-For at all. ouroboros's
    `_get_client_ip_from_request` returns the first XFF value
    unconditionally, allowing any client to spoof its source IP
    for rate-limit bookkeeping (and any future ACL check).
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"def _get_client_ip_from_request.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    # Either XFF is entirely absent or it is gated behind a trust-proxy flag.
    xff_referenced = "X-Forwarded-For" in body or "x-forwarded-for" in body.lower()
    trust_flag = ("trust_proxy" in body or "trust_xff" in body
                  or "trusted_proxies" in body)
    assert not xff_referenced or trust_flag, (
        "G10: X-Forwarded-For must be gated behind an explicit trust-proxy "
        "flag; default must use the TCP-layer source address"
    )


@pytest.mark.xfail(
    reason="W140 BUG-10 (P1): no LogWarning of source IP on auth failure. "
           "Core: 'incorrect password attempt from %s' httprpc.cpp:123.",
    strict=True,
)
def test_w140_g11_auth_failure_source_ip_logged() -> None:
    """G11: auth failure must log the source IP (fail2ban surface).

    Without a source-IP log line, brute-force attempts are invisible
    to operators. Pair with BUG-4 (sleep) for defence-in-depth.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"async def _get_credentials.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_log = (
        ("logger.warning" in body or "logger.info" in body
         or "logger.error" in body)
        and ("client" in body.lower() or "peer" in body.lower()
             or "ip" in body.lower())
    )
    assert has_log, (
        "G11: _get_credentials must log auth failures with the client IP"
    )


# ===========================================================================
# Dispatch order + framing gates — G12-G20
# ===========================================================================


@pytest.mark.xfail(
    reason="W140 BUG-11 (P1): when self.security is None, rate-limit and "
           "body-parse still run. Core's gate is unconditional — no creds "
           "means InitRPCAuthentication failed and the node never starts.",
    strict=True,
)
def test_w140_g12_unauth_rejected_before_parse() -> None:
    """G12: auth must be unconditionally invoked BEFORE rate-limit + parse.

    Today the dispatcher does `if self.security: await
    self._get_credentials(...)`. When security is None (BUG-22 path)
    the dispatcher continues into rate-limit + body parse for an
    unauthenticated client, leaking JSON-RPC parse errors and consuming
    rate-limit budget. Core has no analogous gate — the node refuses
    to start when no credentials can be assembled.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"async def _handle_rpc_common.*?(?=\n        @self\.app|\n    def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    # The bug: `if self.security:` makes auth optional. Core has no such
    # conditional. The fix is to either (a) drop the conditional entirely
    # because RPCServer.__init__ would have aborted (BUG-22), or
    # (b) keep the conditional AND skip the rest of the pipeline when
    # security is disabled.
    has_conditional_auth = bool(re.search(
        r"if self\.security:\s*\n\s+await self\._get_credentials",
        body,
    ))
    assert not has_conditional_auth, (
        "G12: auth must be unconditional — the `if self.security:` gate "
        "lets the rest of the pipeline run on an unauthenticated request"
    )


@pytest.mark.xfail(
    reason="W140 BUG-12 (P1): jsonrpc field is never inspected. Pydantic "
           "model has it (rpc.py:419) but dispatcher ignores it. Core: "
           "request.cpp:213-230 enum V1_LEGACY vs V2.",
    strict=True,
)
def test_w140_g13_jsonrpc_field_parsed() -> None:
    """G13: dispatcher must inspect the per-request jsonrpc version field.

    Core distinguishes V1_LEGACY vs V2 via the 'jsonrpc' field
    (request.cpp:213-230). The two differ in (a) notification handling,
    (b) error HTTP status codes, (c) reply object shape. ouroboros
    never reads the field.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"async def _execute_single_rpc.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    # Look for an actual read of the per-request 'jsonrpc' field as a
    # dispatch input — either explicitly via req_data.get("jsonrpc"),
    # a JSONRPCVersion enum branch, or an is_v2 / v1_legacy boolean.
    has_version_read = bool(
        re.search(r'req_data\.get\(\s*[\"\']jsonrpc[\"\']', body)
        or re.search(r'JSONRPCVersion\.(V1_LEGACY|V2)', body)
        or re.search(r'\bis_v2\b|\bv1_legacy\b', body)
    )
    assert has_version_read, (
        "G13: _execute_single_rpc must read the per-request jsonrpc field "
        "(req_data.get('jsonrpc') or JSONRPCVersion.V1_LEGACY / V2 enum) "
        "and dispatch on it"
    )


@pytest.mark.xfail(
    reason="W140 BUG-13 (P1): V2 notifications (no id, jsonrpc=2.0) return a "
           "full response. Core: HTTP 204 No Content (httprpc.cpp:167-171).",
    strict=True,
)
def test_w140_g14_v2_notification_returns_no_content() -> None:
    """G14: V2 notifications must return HTTP 204 with no body.

    A V2 notification has '"jsonrpc": "2.0"' AND missing 'id'. The
    server executes the method but MUST NOT respond. Today ouroboros
    returns {"jsonrpc":"2.0","result":...,"id":null}.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Need an HTTP-204 path keyed on notification semantics. Use a tight
    # regex to avoid matching unrelated 204* substrings (e.g. `2048`).
    has_204 = bool(
        re.search(r"\bHTTP_204\b|\bNO_CONTENT\b|status_code\s*=\s*204",
                  src)
    )
    has_notification_path = "notification" in src.lower() and (
        "v2" in src.lower() or "jsonrpc" in src.lower()
    )
    assert has_204 and has_notification_path, (
        "G14: V2 notification path must return HTTP 204 No Content "
        "(status_code=204) gated on the notification semantics"
    )


@pytest.mark.xfail(
    reason="W140 BUG-14 (P1): V1 clients see 'jsonrpc:2.0' in the reply. Core "
           "V1_LEGACY: result+error keys, no jsonrpc field (request.cpp:51-66).",
    strict=True,
)
def test_w140_g15_v1_reply_shape() -> None:
    """G15: V1 replies must include BOTH result and error, NO jsonrpc field.

    Core's JSONRPCReplyObj writes 'jsonrpc' only in V2 mode
    (request.cpp:55). V1 callers depending on the shape see a
    surprising '"jsonrpc": "2.0"' that breaks strict consumers.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Look for shape divergence by version inside _execute_single_rpc.
    m = re.search(
        r"async def _execute_single_rpc.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_v1_shape = (
        'V1_LEGACY' in body or 'v1_legacy' in body
        or ('"result"' in body and '"error"' in body
            and re.search(r"if\s+.*v(1|ersion)", body))
    )
    assert has_v1_shape, (
        "G15: V1 reply shape must include result+error and omit jsonrpc"
    )


@pytest.mark.xfail(
    reason="W140 BUG-15 (P1): non-POST methods rely on FastAPI defaults. "
           "Core: POST-only with HTTP 405 + 'JSONRPC server handles only POST "
           "requests' body (httprpc.cpp:107-109).",
    strict=True,
)
def test_w140_g16_non_post_rejected_with_405() -> None:
    """G16: GET/PUT/DELETE to / must return HTTP 405 with Core-shape body.

    Today FastAPI returns its own HTTP 405 with a different body and
    headers. Tools that assert on the exact response break.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Look for an explicit POST-only enforcement step distinct from FastAPI
    # decorator routing.
    has_method_guard = (
        "JSONRPC server handles only POST" in src
        or re.search(r"if\s+.*method\s*!=\s*[\"']POST[\"']", src)
    )
    assert has_method_guard, (
        "G16: non-POST requests must be rejected with the Core-shape body"
    )


@pytest.mark.xfail(
    reason="W140 BUG-16 (P1): max-headers-size cap is missing. Core: "
           "MAX_HEADERS_SIZE=8192 via evhttp_set_max_headers_size "
           "(httpserver.cpp:51, 409).",
    strict=True,
)
def test_w140_g17_max_headers_size_cap() -> None:
    """G17: HTTP headers must be capped (Core: 8 KiB).

    Without the cap an attacker can send 100 MiB of garbage headers
    and consume memory.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    has_cap = (
        "MAX_HEADERS" in src
        or "max_header" in src.lower()
        or "h11_max_incomplete_event_size" in src
    )
    assert has_cap, "G17: max-headers-size cap must exist"


@pytest.mark.xfail(
    reason="W140 BUG-17 (P0-SEC): max-body-size cap is missing. uvicorn "
           "default is unlimited. await request.body() reads the full body. "
           "Core: evhttp_set_max_body_size MAX_SIZE=32 MiB.",
    strict=True,
)
def test_w140_g18_max_body_size_cap() -> None:
    """G18 (P0-SEC): HTTP body must be capped (Core: 32 MiB).

    A malicious client on a localhost socket can send a 10 GiB body
    and OOM-kill the node.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    has_cap = (
        "MAX_BODY" in src
        or "max_body" in src.lower()
        or "max_request_size" in src
        or "h11_max_incomplete_event_size" in src
        or "Content-Length" in src and "max" in src.lower()
    )
    # Need both a constant AND its enforcement in body() pipeline.
    enforced = (
        "Content-Length" in src and ("413" in src or "Payload Too Large" in src)
        or "max_body" in src.lower()
    )
    assert has_cap and enforced, (
        "G18: max-body-size cap must exist AND be enforced before body() read"
    )


@pytest.mark.xfail(
    reason="W140 BUG-18 (P1): empty batch returns JSON error not HTTP 204. "
           "Core: HTTP 204 (httprpc.cpp:220-223).",
    strict=True,
)
def test_w140_g19_empty_batch_returns_204() -> None:
    """G19: empty batches must return HTTP 204 No Content.

    JSON-RPC 2.0 spec says empty batch is an error, but Core
    intentionally returns HTTP 204 for compatibility with older
    callers (comment at httprpc.cpp:211-219).
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    m = re.search(
        r"async def _handle_rpc_common.*?(?=\n        @self\.app)",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    # Look for HTTP 204 path on empty batch.
    has_204 = (
        ("204" in body or "NO_CONTENT" in body)
        and "empty" in body.lower()
    )
    assert has_204, (
        "G19: empty batch must return HTTP 204 No Content"
    )


@pytest.mark.xfail(
    reason="W140 BUG-19 (P1): batches always frame V2. Core: each response in "
           "a batch carries its originating request's version "
           "(httprpc.cpp:194-210).",
    strict=True,
)
def test_w140_g20_mixed_v1_v2_batch() -> None:
    """G20: batches must frame each response per its request's jsonrpc version.

    A batch with [{"jsonrpc":"1.0",...}, {"jsonrpc":"2.0",...}] today
    returns two V2-shaped responses. Mixed batches require per-request
    framing.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Find _execute_single_rpc and check it threads version through.
    m = re.search(
        r"async def _execute_single_rpc.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    threads_version = (
        "jsonrpc_version" in body or "v1_legacy" in body
        or "JSONRPCVersion" in body
    )
    assert threads_version, (
        "G20: _execute_single_rpc must thread jsonrpc version through to "
        "each response"
    )


# ===========================================================================
# Hygiene + resource exhaustion gates — G21-G24
# ===========================================================================


@pytest.mark.xfail(
    reason="W140 BUG-20 (P2): CORS is wildcard-open with credentials. "
           "rpc.py:904-910 allow_origins=['*'] AND allow_credentials=True.",
    strict=True,
)
def test_w140_g21_cors_not_wildcard_with_credentials() -> None:
    """G21: CORS must not advertise allow_origins=['*'] with credentials=True.

    Browser specs disallow that combination for safety, but the policy
    advertised by ouroboros invites mistakes. A JSON-RPC server's
    reasonable default is no CORS headers at all.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Match either no CORS middleware or a narrowed allow_origins list.
    has_wildcard_creds = bool(re.search(
        r'allow_origins\s*=\s*\[\s*"\*"\s*\]', src
    ) and re.search(r'allow_credentials\s*=\s*True', src))
    assert not has_wildcard_creds, (
        "G21: do not combine allow_origins=['*'] with allow_credentials=True"
    )


@pytest.mark.xfail(
    reason="W140 BUG-21 (P2): GET endpoints (/health, /getblockstats, "
           "/getblockfilter) bypass auth. Core: REST is a separate listener "
           "gated by -rest=1.",
    strict=True,
)
def test_w140_g22_get_endpoints_authenticated() -> None:
    """G22: GET endpoints on the JSON-RPC port must require auth.

    /health, /getblockstats, /getblockfilter are registered as @get
    decorators with no `await self._get_credentials(http_request)`
    call. An unauth'd client can probe block state and node health.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Scan /health declaration for an auth call inside its body.
    m = re.search(
        r'@self\.app\.get\("/health"\)\s*\n.*?(?=@self\.app\.|\nclass )',
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_auth = "_get_credentials" in body
    assert has_auth, (
        "G22: /health (and other GET endpoints) must run _get_credentials"
    )


@pytest.mark.xfail(
    reason="W140 BUG-22 (P0-SEC): when username OR password is empty "
           "self.security is None and auth is silently skipped. Core: aborts "
           "node startup when no credentials are configured "
           "(httprpc.cpp:240-273 returns false).",
    strict=True,
)
def test_w140_g23_auth_must_not_silently_disable() -> None:
    """G23 (P0-SEC): missing credentials must fail-closed, not silently open.

    Today RPCServer.__init__ sets self.security=None when username OR
    password is empty (rpc.py:914) and the dispatcher silently skips
    the auth check. node.py masks this in production by writing a
    cookie, but a future refactor / alt entry point could open an
    unauth'd port.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Look for an explicit failure path when both creds missing.
    m = re.search(
        r"def __init__\(\s*self,\s*node.*?(?=\n    (?:async )?def |\nclass )",
        src,
        re.DOTALL,
    )
    body = m.group(0) if m else ""
    has_fail_closed = (
        ("raise" in body and ("username" in body and "password" in body))
        and not re.search(
            r"self\.security\s*=\s*None\s*\n\s+if username and password:",
            body,
        )
    )
    assert has_fail_closed, (
        "G23: RPCServer.__init__ must fail-closed (raise) when both "
        "username AND password are empty / None"
    )


@pytest.mark.xfail(
    reason="W140 BUG-23 (P1): per-IP rate-limit dict grows unboundedly. "
           "defaultdict(list) at rpc.py:120 has no LRU / max-entries cap. "
           "Combined with BUG-9 (XFF spoof) this is a memory-DoS surface.",
    strict=True,
)
def test_w140_g24_rate_limit_bounded() -> None:
    """G24: rate-limit storage must be bounded.

    Core uses a global work-queue depth (g_max_queue_depth) that is
    bounded and shared across all clients. ouroboros's per-IP defaultdict
    grows without bound; an attacker rotating spoofed X-Forwarded-For
    values can balloon it.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    # Either an LRU cache, periodic prune in addition to per-IP append, or
    # a max-entries cap on the store.
    has_bound = (
        "LRU" in src or "lru_cache" in src
        or re.search(r"_rate_limit_max_entries|_rate_limit_max_clients", src)
        or re.search(r"if\s+len\(_rate_limit_store\)\s*>", src)
    )
    assert has_bound, (
        "G24: _rate_limit_store must have a documented entry cap and prune"
    )


# ===========================================================================
# PRESENT gates — pin existing Core-parity invariants (G25-G29)
# ===========================================================================


def test_w140_g25_cookie_filename_is_dot_cookie() -> None:
    """G25 (PRESENT): cookie file is named '.cookie' per Core.

    Bitcoin Core uses '.cookie' (request.cpp:83). bitcoin-cli and every
    third-party tooling key off that exact filename.
    """
    assert COOKIE_FILENAME == ".cookie", (
        "G25: COOKIE_FILENAME must be '.cookie' (Core parity, request.cpp:83)"
    )


def test_w140_g26_cookie_user_is_double_underscore_cookie() -> None:
    """G26 (PRESENT): cookie username is '__cookie__' per Core.

    Bitcoin Core uses '__cookie__' (request.cpp:81). Clients can rely
    on the constant name when parsing the cookie line.
    """
    assert COOKIE_USER == "__cookie__", (
        "G26: COOKIE_USER must be '__cookie__' (Core parity, request.cpp:81)"
    )


def test_w140_g27_cookie_deleted_on_shutdown() -> None:
    """G27 (PRESENT): delete_cookie is wired into the shutdown path.

    node.py:596 calls delete_cookie(self.data_dir) on clean shutdown.
    Matches Core's DeleteAuthCookie (request.cpp:167-178).
    """
    node_src = (SRC_OUROBOROS / "node.py").read_text(encoding="utf-8")
    assert "delete_cookie(self.data_dir)" in node_src, (
        "G27: shutdown path must call delete_cookie(data_dir)"
    )


def test_w140_g28_www_authenticate_realm_jsonrpc() -> None:
    """G28 (PRESENT): 401 responses include WWW-Authenticate: Basic realm='jsonrpc'.

    Matches Core's WWW_AUTH_HEADER_DATA (httprpc.cpp:33). Required so
    browser callers don't silently fall back to no-auth.
    """
    src = (SRC_OUROBOROS / "rpc.py").read_text(encoding="utf-8")
    assert 'Basic realm="jsonrpc"' in src or "Basic realm='jsonrpc'" in src, (
        "G28: WWW-Authenticate header must say Basic realm=\"jsonrpc\" "
        "(Core parity)"
    )


def test_w140_g29_batch_size_cap_present_but_diverges() -> None:
    """G29 (PARTIAL): batch size cap exists (1000) but Core has no hard cap.

    Core caps via work-queue depth + rpcservertimeout. ouroboros's
    explicit `max_batch_size=1000` is a defensive default; the value
    is undocumented vs Core but the cap-presence is fine.
    """
    sig = inspect.signature(RPCServer.__init__)
    assert "max_batch_size" in sig.parameters, (
        "G29: RPCServer must take max_batch_size parameter"
    )
    default = sig.parameters["max_batch_size"].default
    assert default == 1000, (
        f"G29: max_batch_size default must remain 1000 (got {default})"
    )


# ===========================================================================
# Two-pipeline guard — G30 (PRESENT, extends W125/W128/W129/W137)
# ===========================================================================


def test_w140_g30_two_pipeline_http_rpc_python_only() -> None:
    """G30 (PRESENT): ferrous_utils Rust crate must not implement HTTP / RPC /
    cookie auth.

    Bitcoin Core's HTTP listener + JSON-RPC dispatch + cookie auth is
    Python-only on ouroboros. The Rust crate is the IBD validation +
    RocksDB sync pipeline; reintroducing any HTTP / auth surface there
    would create a two-pipeline divergence.

    This guard EXTENDS the dedicated guards in W76 (priority API),
    W122 (BIP-158 codec), W125 (RPC error codes), W128 (addrman),
    W129 (coin selection), W137 (PSBT), with HTTP / auth coverage.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present in this environment")

    forbidden_identifiers = [
        # Auth + HTTP surface
        "WWW-Authenticate",
        "Basic realm",
        "HTTPBasic",
        "RPCServer",
        "JsonRpcServer",
        "JsonRpcError",
        "rpcauth",
        "RpcAuth",
        "cookie_auth",
        "CookieAuth",
        "__cookie__",
        # HTTP frameworks / TLS
        "fastapi",
        "uvicorn",
        "evhttp",
        "tokio_http",
        # JSON-RPC framing
        "JSONRPCVersion",
        "V1_LEGACY",
        "WWW_AUTH",
    ]

    offenders: list[tuple[str, str]] = []
    for path in FERROUS_UTILS.rglob("*"):
        # Limit grep to source files + skip build artefacts.
        if not path.is_file():
            continue
        if path.suffix not in (".rs", ".toml", ".lock"):
            continue
        # Skip lock + target.
        if "target" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for ident in forbidden_identifiers:
            if ident in text:
                offenders.append((str(path.relative_to(REPO_ROOT)), ident))
    assert not offenders, (
        f"G30: ferrous-utils must not implement HTTP / JSON-RPC / cookie "
        f"auth surface. Offenders: {offenders}"
    )


def test_w140_g30_no_python_rpc_in_rust_grep() -> None:
    """G30 (PRESENT, source grep): the inverse — no Python-RPC-shaped
    identifiers in the Rust crate.

    A future refactor that vends a Rust-side HTTP server would trip
    BOTH this test and the above. Both serve as defence-in-depth.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils tree not present in this environment")

    # If a Rust crate exists, its only allowed network-adjacent surface
    # is asmap parser (W115) and the RocksDB sync glue. Nothing here
    # should resemble JSON-RPC framing.
    forbidden = [
        "_get_credentials",
        "_check_rate_limit",
        "JSONRPCRequest",
        "JSONRPCResponse",
        "max_batch_size",
        "X-Forwarded-For",
        "WWW-Authenticate",
    ]
    offenders = []
    for path in FERROUS_UTILS.rglob("*.rs"):
        if "target" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for f in forbidden:
            if f in text:
                offenders.append((str(path.relative_to(REPO_ROOT)), f))
    assert not offenders, (
        f"G30: no JSON-RPC framing identifiers must appear in ferrous-utils: "
        f"{offenders}"
    )


# ===========================================================================
# Sanity: production helpers exist and have the documented contracts
# ===========================================================================


def test_w140_cookie_auth_module_surface() -> None:
    """The cookie_auth module must export the three documented helpers.

    A future refactor that renames generate_cookie / read_cookie /
    delete_cookie would silently break node startup and shutdown
    plumbing. This pin keeps the public surface stable while we
    iterate on the bug fixes above.
    """
    assert hasattr(cookie_auth_mod, "generate_cookie")
    assert hasattr(cookie_auth_mod, "read_cookie")
    assert hasattr(cookie_auth_mod, "delete_cookie")
    assert cookie_auth_mod.COOKIE_FILENAME == ".cookie"
    assert cookie_auth_mod.COOKIE_USER == "__cookie__"


def test_w140_rpc_server_constructor_surface() -> None:
    """RPCServer.__init__ keyword signature pin.

    A future refactor must not silently drop username/password (BUG-22
    would worsen) or rate_limit. This pin catches accidental signature
    drift.
    """
    sig = inspect.signature(RPCServer.__init__)
    for required in (
        "node", "port", "username", "password", "rate_limit",
        "max_batch_size", "enable_rest", "tls_certfile", "tls_keyfile",
    ):
        assert required in sig.parameters, (
            f"RPCServer.__init__ must accept '{required}' kwarg"
        )
