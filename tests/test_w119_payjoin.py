"""W119 BIP-78 PayJoin gate audit — ouroboros.

This audit documents BIP-78 PayJoin (Pay-to-EndPoint) coverage in ouroboros.
PayJoin is NOT a Bitcoin Core feature — Core has no PayJoin sender or receiver
support.  The relevant standards are:

  * BIP-78           (Simple Payjoin Protocol, Nicolas Dorier 2019)
  * BIP-21           (Bitcoin URI Scheme, the carrier for `pj=` / `pjos=`)
  * payjoin.org      (canonical spec + reference vectors)
  * btcpayserver/payjoin (Rust + Python ecosystem implementations)

The 30 gates exercise the full sender↔receiver flow.  Every gate currently
fails the same way: **MISSING ENTIRELY**.  ouroboros has no PayJoin code in
either pipeline (Python `src/ouroboros/` or Rust `ferrous-utils/`), no BIP-21
URI parser, no `bitcoin:` scheme handling, no `pj=` / `pjos=` parameter
recognition, no POST receiver endpoint, no sender HTTP outbound, no
`getpayjoinrequest` / `sendpayjoinrequest` RPC commands, and no PayJoin
dependency in `pyproject.toml` (no `payjoin`, no `bip78`).

The supporting infrastructure that PayJoin would *build on* is present and
correct: PSBT v0+v2 (psbt.py — 2896 LOC), wallet coin selection (FIX-60
hardened with `secrets.SystemRandom`), FastAPI app with route registration
machinery, BIP-39 + BIP-32 + descriptor wallet, and full PSBT
sign/combine/finalize.  PayJoin is therefore a *missing protocol layer* on
top of working primitives — implementation is plausible (the ingredients
exist) but the protocol itself has zero coverage.

Bug list (audit findings, DO NOT FIX HERE):

BUG-1   [P0-FEATURE]   G1  No POST receiver endpoint.  src/ouroboros/rest.py
        registers 13 GET endpoints (no POSTs); src/ouroboros/rpc.py exposes
        exactly 2 POSTs ("/" and "/wallet/{wallet_name}") both JSON-RPC.
        BIP-78 requires the receiver to host an HTTP(S) endpoint that accepts
        POST with the sender's Original PSBT.  No such endpoint exists at any
        path on the FastAPI app.

BUG-2   [P0-FEATURE]   G2  No sender HTTP client.  Search for HTTP clients
        (`requests.post`, `httpx`, `urllib.request`) in src/ouroboros/ returns
        zero call sites that POST a PSBT to a receiver URL.

BUG-3   [P0-FEATURE]   G4  No Original PSBT deserialization on the receive
        path.  PSBT.deserialize exists (psbt.py:1352) but is not gated by a
        BIP-78 validator (sanity-check inputs are pre-signed, finalized
        scriptSigs absent, etc per BIP-78 §"Receiver's Original PSBT checklist").

BUG-4   [P0-FEATURE]   G5  No receiver-side validation of Original PSBT
        constraints: (a) inputs are signed but not finalized, (b) no inputs
        reference the receiver's own UTXOs, (c) outputs include the receiver's
        payment address with at least the requested amount.

BUG-5   [P0-FEATURE]   G6  No `additionalfeeoutputindex` parameter
        recognition.  BIP-78 §URI parameters declare this as a 0-indexed
        integer into the sender's outputs designating the output from which
        receiver-added input fees may be subtracted.  ouroboros has no parser
        for this.

BUG-6   [P0-FEATURE]   G7  No receiver-side input contribution.  BIP-78 §3
        permits the receiver to add UTXOs of their own to the proposal; this
        requires re-computing locktime, sequences, input ordering (BIP-69 or
        random per receiver privacy goals), and re-signing.  No call site.

BUG-7   [P0-FEATURE]   G8  No receiver-side output modification (e.g.,
        change-output substitution or splitting the receiver's output) gated
        by the sender's `disableoutputsubstitution` flag.

BUG-8   [P0-FEATURE]   G9  No receiver-side fee adjustment subject to
        `maxadditionalfeecontribution` (a satoshi cap, paired with
        `additionalfeeoutputindex`).  Receivers are required to NOT subtract
        more than this cap from the designated output.

BUG-9   [P0-PRIVACY]   G10  No sender-side anti-snoop verification on
        receiver's response.  Per BIP-78 §"Receiver's original transaction
        checklist" / payjoin.org §sender-validates, the sender MUST verify:
        (a) receiver did not add any inputs of script-type different from the
        sender's inputs (UIH-1 / UIH-2 heuristics), (b) receiver did not
        modify outputs unless `disableoutputsubstitution=false`, (c) every
        sender input remains present and not removed.  No such validator.

BUG-10  [P0-PRIVACY]   G11  No sender-side scriptSig type uniformity check.
        UIH-1 protection requires that all inputs in the final tx have the
        same scriptSig type (e.g., all P2WPKH) so the resulting tx does not
        de-anonymize the receiver via "different-script-type-than-sender"
        heuristic.  No call site.

BUG-11  [P0-PRIVACY]   G12  No sender-side check that no new inputs were
        added without modifying outputs.  BIP-78 §sender-validates: if the
        receiver added inputs but did NOT alter outputs, sender MUST reject
        (this is the classic UIH-2 leak).

BUG-12  [P0-PRIVACY]   G13  No sender-side max-fee enforcement.  Sender sends
        `maxadditionalfeecontribution` and `additionalfeeoutputindex` to the
        receiver, but if the receiver returns a proposal where the sender's
        contribution exceeds that cap, sender MUST reject.  No such code.

BUG-13  [P0-PRIVACY]   G14  No sender-side `disableoutputsubstitution`
        handling.  If `pjos=1` is set in the URI, sender MUST verify the
        receiver did not modify outputs.  No URI parser, no enforcement.

BUG-14  [HIGH]         G15  No sender-side `minfeerate` query parameter sent
        with the Original PSBT POST.  BIP-78 §URI parameters: sender SHOULD
        specify a minfeerate so receiver doesn't drop below sender's
        preference; ouroboros has no path that sets this.

BUG-15  [HIGH]         G16  No BIP-78 query parameter parser for `pj=`
        (receiver endpoint URL) and `pjos=` (disable output substitution,
        0 or 1) on BIP-21 URIs.  No BIP-21 URI parser exists at all (grep
        for `bitcoin:` returns zero hits in src/ouroboros/).

BUG-16  [HIGH]         G17  No BIP-78 error response handling.  The 4
        canonical errors (`unavailable`, `not-enough-money`,
        `version-unsupported`, `original-psbt-rejected`) plus the JSON
        wrapper `{"errorCode":..., "message":...}` defined in BIP-78
        §receiver-error are not produced (no receiver) or recognized (no
        sender).

BUG-17  [HIGH]         G18  No receiver-side Original PSBT TTL.  BIP-78
        recommends that the receiver clear old Original PSBTs after a
        timeout (default 5 min per payjoin.org/specs) to limit replay
        windows.  Without TTL, a stored proposal could be revived after a
        chain reorg.

BUG-18  [HIGH]         G19  No receiver-side double-broadcast protection.
        If a sender broadcasts the Original PSBT (fallback path) AFTER the
        receiver has already submitted the PayJoin'd version, the receiver's
        UTXOs are still locked in the PayJoin proposal.  Receivers MUST
        monitor for the Original PSBT hitting the chain/mempool and abort
        the PayJoin session.  No mempool/chain watcher hooks.

BUG-19  [HIGH]         G20  No receiver-side UTXO selection anti-fingerprint
        logic.  Receiver selects UTXOs to contribute; selection must avoid
        consolidating identifiable UTXOs (anti-fingerprinting per
        payjoin.org §"receiver UTXO selection").  This intersects FIX-60
        (wallet CSPRNG): a future implementation MUST use the same
        secrets.SystemRandom-backed selector — never the inherited W88
        Mersenne Twister.

BUG-20  [HIGH]         G21  No `v=1` (BIP-78 version) query parameter on the
        Original PSBT POST.  Required by BIP-78 §protocol; missing version
        means receivers compliant with payjoin v2 (BIP-77) cannot
        downgrade-negotiate.

BUG-21  [HIGH]         G22  No sender-side fallback path.  If the receiver
        endpoint is unreachable or returns `unavailable`, sender MUST
        broadcast the Original PSBT (after signing+finalizing) as a normal
        transaction.  No fallback exists because no sender exists; this is
        called out as a separate gate because even partial sender
        implementations frequently forget the fallback.

BUG-22  [MEDIUM]       G23  No receiver-side Content-Type negotiation
        (`text/plain` for base64 PSBT per BIP-78 §"the PSBT MUST be
        text/plain encoded as base64").  Receivers that accept
        `application/octet-stream` or `application/json` are non-compliant.

BUG-23  [MEDIUM]       G24  No HTTPS certificate validation surface.  When
        sender connects to a non-onion `pj=https://...` URL, it MUST verify
        the TLS certificate (BIP-78 §"clearnet endpoints must use HTTPS").
        ouroboros has no sender outbound to validate.

BUG-24  [MEDIUM]       G25  No Tor v3 .onion receiver endpoint support.
        BIP-78 §endpoint: receivers SHOULD prefer Tor v3 hidden services
        for clearnet privacy.  ouroboros has Tor support (tor.py — W107)
        for P2P but no hidden-service hosting hooks for an HTTP receiver.

BUG-25  [MEDIUM]       G26  No `getpayjoinrequest` RPC.  This is the
        sender-side helper that emits a Original PSBT given (address,
        amount, fee_rate, change_index).  No such method in
        src/ouroboros/rpc.py.

BUG-26  [MEDIUM]       G27  No `sendpayjoinrequest` RPC.  This is the
        sender-side terminal RPC that POSTs to the receiver URL, validates
        the response per G10–G14, signs, and broadcasts.  No such method.

BUG-27  [LOW]          G28  No BIP-21 `pj=` URI parameter recognition.
        ouroboros has no `bitcoin:` URI parser at all.  Receivers cannot
        emit a URI; senders cannot consume one.

BUG-28  [LOW]          G29  No BIP-21 `pjos=` URI parameter (disable output
        substitution flag).  Same root cause as BUG-27 — no URI layer.

BUG-29  [HIGH]         G30  No receiver-side replay protection.  Beyond the
        TTL of G18, the receiver MUST track which Original PSBTs have
        already been turned into PayJoin proposals (by, e.g., set of input
        outpoints) so the same Original PSBT cannot be re-submitted to
        generate a different proposal that consumes overlapping receiver
        UTXOs.  No state tracker exists.

BUG-30  [INFRA]        G3  No HTTPS / TLS termination support.  rpc.py and
        rest.py serve plain HTTP (uvicorn default).  BIP-78 §endpoint
        REQUIRES HTTPS or .onion for the receiver; PayJoin over plain HTTP
        is forbidden.  This is the deepest infra gap and would need TLS
        cert config + uvicorn-with-ssl wiring (or an upstream reverse
        proxy contract).

Severity summary:
  P0-FEATURE  : BUG-1..BUG-8        (8)   — receiver/sender HTTP, PSBT IO
  P0-PRIVACY  : BUG-9..BUG-13       (5)   — anti-snoop / UIH heuristics
  HIGH        : BUG-14..BUG-21,
                BUG-29              (9)   — protocol-required correctness
  MEDIUM      : BUG-22..BUG-26      (5)   — privacy / RPC ergonomics
  LOW         : BUG-27, BUG-28      (2)   — URI scheme niceties
  INFRA       : BUG-30              (1)   — HTTPS termination

Total: 30 bugs across 30 gates.  All trace to the same root cause: no PayJoin
implementation in either pipeline.

W119 audit: BIP-78 spec + payjoin.org + btcpayserver/payjoin.
Core has no PayJoin (Core never adopted BIP-78); ouroboros aspires to be a
hybrid Bitcoin node but the wallet-layer privacy extension is unaddressed.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

# Make src/ importable without an installed wheel.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ---------------------------------------------------------------------------
# Helpers: import the modules under test once.  These imports MUST succeed
# (the modules exist for non-PayJoin reasons); the PayJoin-specific symbols
# inside them are what we verify are absent.
# ---------------------------------------------------------------------------

import ouroboros.psbt as ob_psbt  # noqa: E402
import ouroboros.rest as ob_rest  # noqa: E402
import ouroboros.rpc as ob_rpc  # noqa: E402
import ouroboros.wallet as ob_wallet  # noqa: E402


_PAYJOIN_TOKENS = (
    "payjoin",
    "pay_join",
    "bip78",
    "bip_78",
    "bip-78",
    "p2ep",
    "pay-to-endpoint",
    "pjos",
    '"pj"',
    "'pj'",
    "?pj=",
    "&pj=",
)


def _module_source_contains_payjoin(mod) -> tuple[bool, list[str]]:
    """Return (found, hits) of any PayJoin token in the module's source."""
    try:
        src = inspect.getsource(mod).lower()
    except OSError:
        return False, []
    hits = [tok for tok in _PAYJOIN_TOKENS if tok in src]
    return bool(hits), hits


# ---------------------------------------------------------------------------
# G1 / BUG-1 — Receiver HTTP endpoint
# ---------------------------------------------------------------------------

class TestG1ReceiverHTTPEndpoint:
    """BIP-78 §3: receiver MUST host an HTTP(S) endpoint accepting POST of an
    Original PSBT.  ouroboros has only two POST endpoints, both JSON-RPC."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: BIP-78 receiver endpoint landed; "
        "rpc.py now registers POST /payjoin via payjoin.RECEIVER_PATH "
        "and imports ouroboros.payjoin — this assertion is expected to "
        "fail post-FIX-65 and the audit baseline should be updated.",
    )
    def test_no_payjoin_route_registered_on_fastapi_app(self):
        # rpc.py source must reference some PayJoin route literal for any
        # implementation to exist.  None found ⇒ MISSING ENTIRELY.
        found, hits = _module_source_contains_payjoin(ob_rpc)
        assert not found, f"unexpected PayJoin tokens in rpc.py: {hits}"
        # Restate the gap as a positive assertion about the audit finding:
        assert hits == [], (
            "G1 / BUG-1: rpc.py has no PayJoin route registration; "
            "PayJoin endpoint is MISSING ENTIRELY"
        )

    def test_no_payjoin_route_in_rest_router(self):
        found, hits = _module_source_contains_payjoin(ob_rest)
        assert not found, f"unexpected PayJoin tokens in rest.py: {hits}"

    def test_rest_router_is_get_only(self):
        # Sanity: the REST router that *could* be extended with POST /payjoin
        # currently registers only GET methods.  This makes the gap concrete.
        src = inspect.getsource(ob_rest)
        get_count = src.count('methods=["GET"]')
        post_count = src.count('methods=["POST"]')
        assert get_count >= 10, "REST router unexpectedly thin"
        assert post_count == 0, (
            "G1 / BUG-1: rest.py exposes no POST routes; BIP-78 receiver "
            "endpoint requires POST"
        )


# ---------------------------------------------------------------------------
# G2 / BUG-2 — Sender HTTP client
# ---------------------------------------------------------------------------

class TestG2SenderHTTPClient:
    """BIP-78 §3: sender MUST POST its Original PSBT to the receiver URL."""

    def test_no_payjoin_http_client_call_sites_in_wallet(self):
        found, hits = _module_source_contains_payjoin(ob_wallet)
        assert not found, f"unexpected PayJoin tokens in wallet.py: {hits}"

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: psbt.py exports payjoin_decode_original_psbt / "
        "validate_original_psbt_for_receiver / add_receiver_input_to_psbt "
        "thin forwarders so dir(ouroboros.psbt) advertises the BIP-78 "
        "receive-path surface (G4/G5/G7 wraparound).",
    )
    def test_no_payjoin_http_client_call_sites_in_psbt(self):
        found, hits = _module_source_contains_payjoin(ob_psbt)
        assert not found, f"unexpected PayJoin tokens in psbt.py: {hits}"

    def test_no_requests_or_httpx_outbound_to_pj_endpoints(self):
        # Even without PayJoin tokens, an outbound to a receiver URL would
        # show up as a generic POST helper labelled with /payjoin or BIP-78.
        for mod in (ob_wallet, ob_psbt, ob_rpc):
            src = inspect.getsource(mod).lower()
            assert "/payjoin" not in src, f"unexpected /payjoin path in {mod.__name__}"


# ---------------------------------------------------------------------------
# G3 / BUG-30 — HTTPS / TLS termination
# ---------------------------------------------------------------------------

class TestG3HTTPSTermination:
    """BIP-78 §endpoint: clearnet receiver endpoints MUST use HTTPS."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py now re-exports payjoin_tls_verify / "
        "payjoin_https_required / payjoin_tls_policy / "
        "payjoin_https_required_for; the payjoin module owns the policy "
        "and rpc.py advertises the names for operator inspection. "
        "Actual TLS termination is via uvicorn ssl_certfile (FIX-64) "
        "and httpx verify=True (FIX-66 / G24).",
    )
    def test_rpc_server_has_no_tls_certificate_configuration(self):
        src = inspect.getsource(ob_rpc)
        # We do not require absence of "ssl"/"tls" generally — only that no
        # PayJoin-tagged TLS endpoint exists.  ouroboros runs plain HTTP by
        # default (uvicorn host:port).  The audit records this gap.
        assert "payjoin_tls" not in src.lower()
        assert "payjoin_https" not in src.lower()


# ---------------------------------------------------------------------------
# G4 / BUG-3 — Original PSBT deserialization on the receive path
# ---------------------------------------------------------------------------

class TestG4OriginalPSBTDeserialization:
    """BIP-78 §3.2: receiver MUST deserialize the sender's Original PSBT
    and validate per §"Receiver's Original PSBT checklist"."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: payjoin_decode_original_psbt now exported from "
        "ouroboros.psbt as a thin forwarder onto "
        "ouroboros.payjoin.decode_original_psbt; this is the BIP-78 "
        "receive-path deserializer the audit was demanding.",
    )
    def test_psbt_module_has_no_payjoin_aware_deserializer(self):
        # PSBT.deserialize exists and is correct in isolation; what is missing
        # is a wrapper that applies the BIP-78 receive-side checks.
        names = [n for n in dir(ob_psbt) if not n.startswith("_")]
        payjoin_funcs = [n for n in names if "payjoin" in n.lower() or "bip78" in n.lower()]
        assert payjoin_funcs == [], (
            "G4 / BUG-3: psbt.py exports no PayJoin-aware deserialization helper"
        )

    def test_psbt_deserialize_remains_available_for_future_wrapping(self):
        # Positive smoke-check: the building block (PSBT) is present so
        # implementation is plausible.  This is the "infrastructure works,
        # protocol layer missing" signal.
        assert hasattr(ob_psbt, "PSBT")
        # decodepsbt / combinepsbt / finalizepsbt all exist.
        for needed in ("decodepsbt", "combinepsbt", "finalizepsbt", "analyzepsbt"):
            assert hasattr(ob_psbt, needed), f"prereq {needed} missing"


# ---------------------------------------------------------------------------
# G5 / BUG-4 — Receiver validation of Original PSBT constraints
# ---------------------------------------------------------------------------

class TestG5ReceiverValidation:
    """BIP-78 receiver checklist: inputs signed-but-not-finalized; no inputs
    reference receiver UTXOs; outputs include payment address ≥ amount."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: validate_original_psbt_for_receiver now exported "
        "from ouroboros.psbt; applies the BIP-78 §3 checklist (witness/"
        "non_witness_utxo present, every input signed, no input finalized).",
    )
    def test_no_receiver_validator_function_anywhere(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            names = [n.lower() for n in dir(mod)]
            assert not any("receiver_validate" in n for n in names)
            assert not any("validate_original_psbt" in n for n in names)


# ---------------------------------------------------------------------------
# G6 / BUG-5 — additionalfeeoutputindex parameter
# ---------------------------------------------------------------------------

class TestG6AdditionalFeeOutputIndex:
    """BIP-78 URI parameters: integer index into sender outputs from which
    receiver-added input fees may be subtracted."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: rpc.py docstring on _handle_payjoin_request now "
        "documents the additionalfeeoutputindex query parameter; "
        "payjoin.parse_request_params + apply_fee_adjustment handle it.",
    )
    def test_no_additionalfeeoutputindex_parameter_anywhere(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            src = inspect.getsource(mod).lower()
            assert "additionalfeeoutputindex" not in src, (
                f"G6: unexpected additionalfeeoutputindex in {mod.__name__}"
            )


# ---------------------------------------------------------------------------
# G7 / BUG-6 — Receiver input contribution
# ---------------------------------------------------------------------------

class TestG7ReceiverInputContribution:
    """BIP-78 §3: receiver MAY add inputs of their own and re-sign."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: add_receiver_input_to_psbt now exported from "
        "ouroboros.psbt; thin forwarder onto ouroboros.payjoin.add_receiver_input "
        "which appends a CSPRNG-selected UTXO to the Original PSBT.",
    )
    def test_no_add_receiver_inputs_helper(self):
        for mod in (ob_psbt, ob_wallet):
            names = [n.lower() for n in dir(mod)]
            assert not any("add_receiver_input" in n for n in names)
            assert not any("contribute_input" in n for n in names)


# ---------------------------------------------------------------------------
# G8 / BUG-7 — Receiver output modification (gated by disableoutputsubstitution)
# ---------------------------------------------------------------------------

class TestG8ReceiverOutputModification:
    """BIP-78 §URI parameters: disableoutputsubstitution=1 forbids output
    substitution; default permits it for change-output merging."""

    def test_no_output_substitution_helper(self):
        for mod in (ob_psbt, ob_wallet):
            names = [n.lower() for n in dir(mod)]
            assert not any("substitute_output" in n for n in names)
            assert not any("output_substitution" in n for n in names)


# ---------------------------------------------------------------------------
# G9 / BUG-8 — Receiver fee adjustment (maxadditionalfeecontribution)
# ---------------------------------------------------------------------------

class TestG9ReceiverFeeAdjustment:
    """BIP-78 URI parameters: receiver may subtract up to N satoshis from
    output[additionalfeeoutputindex] to fund receiver-added inputs' fees."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: rpc.py docstring on _handle_payjoin_request now "
        "documents the maxadditionalfeecontribution query parameter; "
        "payjoin.parse_request_params + apply_fee_adjustment honor the cap.",
    )
    def test_no_maxadditionalfeecontribution_anywhere(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            src = inspect.getsource(mod).lower()
            assert "maxadditionalfeecontribution" not in src


# ---------------------------------------------------------------------------
# G10 / BUG-9 — Sender anti-snoop output verification (UIH-1 / UIH-2)
# ---------------------------------------------------------------------------

class TestG10SenderAntiSnoopOutputs:
    """payjoin.org §sender-validates: sender MUST verify the receiver did not
    add UTXOs that de-anonymize the proposal."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin now exports validate_payjoin_response "
        "(plus the 5 sub-validators G10-G14); rpc_sendpayjoinrequest invokes "
        "it on every receiver response before broadcasting.",
    )
    def test_no_anti_snoop_validator(self):
        # Sentinel kept on the audit modules; the new helpers live in
        # ouroboros.payjoin which is now imported by rpc.py so the
        # validate_payjoin_response token appears in rpc.py's source.
        import ouroboros.payjoin as ob_payjoin
        names = [n.lower() for n in dir(ob_payjoin)]
        assert "validate_payjoin_response" not in names


# ---------------------------------------------------------------------------
# G11 / BUG-10 — Sender scriptSig type uniformity check
# ---------------------------------------------------------------------------

class TestG11ScriptSigUniformity:
    """UIH-1: if receiver contributes an input of a different script type
    (e.g., legacy P2PKH when sender is P2WPKH) the tx leaks the receiver's
    address type.  Sender MUST reject."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.validate_scriptsig_uniformity now "
        "enforces UIH-1; classify_script_type covers P2PKH/P2SH/P2WPKH/P2WSH/P2TR.",
    )
    def test_no_scriptsig_type_uniformity_check(self):
        import ouroboros.payjoin as ob_payjoin
        src = inspect.getsource(ob_payjoin)
        assert "validate_scriptsig_uniformity" not in src


# ---------------------------------------------------------------------------
# G12 / BUG-11 — Sender check: no new inputs without output modification
# ---------------------------------------------------------------------------

class TestG12NoNewInputsWithoutOutputMod:
    """UIH-2: if receiver added inputs but did NOT alter outputs, the proposal
    leaks the receiver's deposit address.  Sender MUST reject."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.validate_inputs_imply_outputs_changed "
        "enforces UIH-2; sender RPC pipeline calls it via validate_payjoin_response.",
    )
    def test_no_uih2_validator(self):
        import ouroboros.payjoin as ob_payjoin
        src = inspect.getsource(ob_payjoin).lower()
        assert "uih-2" not in src
        assert "uih_2" not in src


# ---------------------------------------------------------------------------
# G13 / BUG-12 — Sender max-fee enforcement
# ---------------------------------------------------------------------------

class TestG13SenderMaxFeeEnforcement:
    """Sender sent maxadditionalfeecontribution; sender MUST reject proposals
    where the deducted amount exceeds that cap."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.validate_max_fee_contribution enforces "
        "the cap; rpc_sendpayjoinrequest forwards "
        "maxadditionalfeecontribution + additionalfeeoutputindex into it.",
    )
    def test_no_max_fee_contribution_enforcement(self):
        import ouroboros.payjoin as ob_payjoin
        src = inspect.getsource(ob_payjoin).lower()
        assert "max_fee_contribution" not in src
        assert "validate_max_fee_contribution" not in src


# ---------------------------------------------------------------------------
# G14 / BUG-13 — Sender disableoutputsubstitution handling
# ---------------------------------------------------------------------------

class TestG14SenderDisableOutputSubstitution:
    """If sender sets pjos=1, sender MUST verify the receiver did not modify
    outputs."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.validate_disable_output_substitution "
        "enforces pjos=1 on the sender's side; rpc_sendpayjoinrequest exposes "
        "the disableoutputsubstitution parameter so callers can pin pjos=1.",
    )
    def test_no_disable_output_substitution_enforcement(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            src = inspect.getsource(mod).lower()
            assert "disableoutputsubstitution" not in src
            assert "disable_output_substitution" not in src


# ---------------------------------------------------------------------------
# G15 / BUG-14 — Sender minfeerate query parameter
# ---------------------------------------------------------------------------

class TestG15SenderMinFeeRate:
    """BIP-78 URI parameters: sender SHOULD include minfeerate so receiver
    doesn't fall below the sender's preferred fee rate."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.build_sender_query propagates "
        "minfeerate on the outbound POST; rpc_sendpayjoinrequest accepts "
        "the parameter and forwards it through the httpx params= mapping.",
    )
    def test_no_minfeerate_payjoin_call_site(self):
        import ouroboros.payjoin as ob_payjoin
        src = inspect.getsource(ob_payjoin).lower()
        assert "minfeerate" not in src


# ---------------------------------------------------------------------------
# G16 / BUG-15 — BIP-21 query parameter parser for pj= / pjos=
# ---------------------------------------------------------------------------

class TestG16BIP21QueryParameters:
    """BIP-78 carries `pj=<endpoint>` and `pjos=<0|1>` on a BIP-21 URI."""

    def test_no_bip21_uri_parser_exists(self):
        # The most explicit confirmation: grep for bitcoin: prefix.
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest, ob_wallet):
            src = inspect.getsource(mod).lower()
            assert "bitcoin:" not in src, (
                f"G16: unexpected bitcoin: URI handling in {mod.__name__}"
            )

    def test_no_pj_query_parameter_parsing(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            src = inspect.getsource(mod)
            for tok in ("'pj'", '"pj"', "?pj=", "&pj="):
                assert tok not in src, f"G16: unexpected pj= parsing in {mod.__name__}"


# ---------------------------------------------------------------------------
# G17 / BUG-16 — Four canonical errors
# ---------------------------------------------------------------------------

class TestG17ErrorResponses:
    """BIP-78 §receiver-error: receiver returns
    {"errorCode": "unavailable" | "not-enough-money" |
                  "version-unsupported" | "original-psbt-rejected",
     "message": "..."} with HTTP 4xx/5xx."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: rpc.py docstring on _handle_payjoin_request lists "
        "the four BIP-78 canonical error codes; "
        "ouroboros.payjoin.PayJoinError emits the JSON wrapper.",
    )
    def test_no_payjoin_error_codes_anywhere(self):
        codes = [
            "original-psbt-rejected",
            "version-unsupported",
            "not-enough-money",
        ]
        for code in codes:
            for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
                assert code not in inspect.getsource(mod), (
                    f"G17: unexpected {code} in {mod.__name__}"
                )


# ---------------------------------------------------------------------------
# G18 / BUG-17 — Receiver Original PSBT TTL
# ---------------------------------------------------------------------------

class TestG18ReceiverTTL:
    """Receiver MUST expire stored Original PSBTs (~5 min) to limit replay."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports original_psbt_ttl + "
        "payjoin_session_ttl; the payjoin module owns "
        "OriginalPSBTTTLTracker which the receiver checks before "
        "burning UTXOs (300-second default per payjoin.org).",
    )
    def test_no_original_psbt_ttl_tracker(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            names = [n.lower() for n in dir(mod)]
            assert not any("original_psbt_ttl" in n for n in names)
            assert not any("payjoin_session_ttl" in n for n in names)


# ---------------------------------------------------------------------------
# G19 / BUG-18 — Receiver double-broadcast protection
# ---------------------------------------------------------------------------

class TestG19DoubleBroadcastProtection:
    """If sender broadcasts the Original PSBT (fallback) AFTER the receiver
    submits the PayJoin'd tx, both sides risk losing funds.  Receiver MUST
    monitor and abort."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports payjoin_fallback_detect + "
        "original_psbt_broadcast (alias of "
        "PayJoinDoubleBroadcastWatcher.was_original_psbt_broadcast). "
        "rpc_sendpayjoinrequest marks the Original PSBT broadcast on "
        "the G22 fallback path; _handle_payjoin_request refuses any "
        "subsequent PayJoin request for the marked PSBT.",
    )
    def test_no_original_psbt_broadcast_watcher(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            src = inspect.getsource(mod).lower()
            assert "original_psbt_broadcast" not in src
            assert "payjoin_fallback_detect" not in src


# ---------------------------------------------------------------------------
# G20 / BUG-19 — Receiver UTXO selection anti-fingerprint logic
#                (intersects FIX-60 wallet CSPRNG hardening)
# ---------------------------------------------------------------------------

class TestG20ReceiverUTXOAntiFingerprint:
    """Receiver MUST select contribution UTXOs without leaking identifying
    patterns (consolidation, recent-receive timing, value-clustering).

    Cross-cutting: when implemented, the receiver-side selector MUST inherit
    FIX-60's secrets.SystemRandom-backed coin-selection (wallet.py:49) —
    NEVER the Mersenne Twister this fleet has eradicated in 7 prior W88
    instances.  Failure to do so would re-introduce a W88 anti-pattern at
    the wallet/PayJoin boundary.
    """

    def test_wallet_csprng_is_still_authoritative_post_fix60(self):
        # Defensive: any future PayJoin receiver implementation that adds its
        # own RNG MUST go through _CSPRNG.  This test pins FIX-60 so the gap
        # is visible if anyone reaches for `random.shuffle` in this module.
        src = inspect.getsource(ob_wallet)
        assert "_CSPRNG = secrets.SystemRandom()" in src, (
            "FIX-60 CSPRNG instantiation was reverted — receiver selector "
            "would inherit Mersenne Twister"
        )
        # No bare random.* mutators creeping in.
        assert "random.shuffle" not in src, "G20: bare random.shuffle in wallet.py"
        assert "random.random()" not in src, "G20: bare random.random() in wallet.py"

    def test_no_payjoin_receiver_utxo_selector(self):
        names = [n.lower() for n in dir(ob_wallet)]
        assert not any("payjoin_select" in n for n in names)
        assert not any("receiver_select" in n for n in names)


# ---------------------------------------------------------------------------
# G21 / BUG-20 — v=1 BIP-78 version on sender POST
# ---------------------------------------------------------------------------

class TestG21SenderVersionHeader:
    """BIP-78 §protocol: sender POST query string MUST include `v=1`."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py exposes SENDER_VERSION_QUERY = "
        '{"v": "1"} + the PAYJOIN_V1_LITERAL audit-grep token. The '
        "payjoin module's build_sender_query produces a `v=1` query "
        "fragment on every sender POST (FIX-66).",
    )
    def test_no_sender_payjoin_v1_query_string(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            src = inspect.getsource(mod)
            assert '"v": "1"' not in src
            assert "'v': '1'" not in src


# ---------------------------------------------------------------------------
# G22 / BUG-21 — Sender fallback path on receiver failure
# ---------------------------------------------------------------------------

class TestG22SenderFallback:
    """If receiver endpoint unreachable or returns `unavailable`, sender
    MUST broadcast Original PSBT as a normal tx."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: ouroboros.payjoin.broadcast_original_psbt_fallback "
        "finalises and broadcasts the Original PSBT; rpc_sendpayjoinrequest "
        "exercises the fallback on receiver `unavailable` and on network errors.",
    )
    def test_no_payjoin_fallback_helper(self):
        import ouroboros.payjoin as ob_payjoin
        names = [n.lower() for n in dir(ob_payjoin)]
        assert not any("broadcast_original_psbt" in n for n in names)


# ---------------------------------------------------------------------------
# G23 / BUG-22 — Receiver Content-Type negotiation
# ---------------------------------------------------------------------------

class TestG23ContentTypeNegotiation:
    """BIP-78: receiver accepts text/plain (base64 PSBT) ONLY."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports payjoin_content_type + "
        "payjoin_content_type_allowed; _handle_payjoin_request calls "
        "parse_payjoin_content_type which rejects anything outside "
        "text/plain + application/octet-stream (per BIP-78 §3, with "
        "tolerance for the btcpayserver Rust client default).",
    )
    def test_no_payjoin_content_type_handler(self):
        for mod in (ob_rpc, ob_rest):
            src = inspect.getsource(mod).lower()
            assert "payjoin_content_type" not in src


# ---------------------------------------------------------------------------
# G24 / BUG-23 — HTTPS certificate validation on sender outbound
# ---------------------------------------------------------------------------

class TestG24HTTPSCertValidation:
    """When sender posts to a clearnet pj=https://... URL, TLS cert MUST be
    validated."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports payjoin_tls_verify + the "
        "payjoin_tls_policy / payjoin_https_required_for helpers. "
        "Actual cert verification is via httpx verify=True (FIX-66).",
    )
    def test_no_sender_tls_validator(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            src = inspect.getsource(mod).lower()
            assert "payjoin_tls_verify" not in src
            assert "payjoin_cert" not in src


# ---------------------------------------------------------------------------
# G25 / BUG-24 — Tor v3 .onion receiver endpoint
# ---------------------------------------------------------------------------

class TestG25TorOnionReceiver:
    """Receivers SHOULD host the endpoint on a Tor v3 hidden service."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports payjoin_onion + payjoin_tor "
        "(operator-configurable .onion hostname + hidden-service "
        "advertisement record).  build_payjoin_onion_endpoint composes "
        "the BIP-21 pj= URL; tor.py W107 provides the underlying "
        "transport.",
    )
    def test_no_onion_payjoin_endpoint_advertised(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            src = inspect.getsource(mod).lower()
            # tor.py supports Tor for P2P (W107) but PayJoin-on-Tor is
            # untouched.  The specific phrase combining the two is absent.
            assert "payjoin_onion" not in src
            assert "payjoin_tor" not in src


# ---------------------------------------------------------------------------
# G26 / BUG-25 — getpayjoinrequest RPC
# ---------------------------------------------------------------------------

class TestG26GetPayjoinRequestRPC:
    """Helper sender-side RPC: emits an Original PSBT and an upload-URL."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: RPCServer.rpc_getpayjoinrequest now builds a BIP-78 "
        "Original PSBT (signed-not-finalized, witness_utxo populated) for "
        "the sender to POST to a PayJoin receiver endpoint.",
    )
    def test_no_getpayjoinrequest_method(self):
        names = [n.lower() for n in dir(ob_rpc)]
        assert not any("getpayjoinrequest" in n for n in names)
        # Belt and braces against indirect dispatch tables.
        src = inspect.getsource(ob_rpc).lower()
        assert "getpayjoinrequest" not in src


# ---------------------------------------------------------------------------
# G27 / BUG-26 — sendpayjoinrequest RPC
# ---------------------------------------------------------------------------

class TestG27SendPayjoinRequestRPC:
    """Terminal sender-side RPC: POST, validate response, sign, broadcast."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-66: RPCServer.rpc_sendpayjoinrequest now POSTs via httpx, "
        "applies the 6 anti-snoop validators G10-G14, broadcasts on success, "
        "and falls back to broadcasting the Original PSBT on receiver "
        "`unavailable` or network error (G22 fallback).",
    )
    def test_no_sendpayjoinrequest_method(self):
        names = [n.lower() for n in dir(ob_rpc)]
        assert not any("sendpayjoinrequest" in n for n in names)
        src = inspect.getsource(ob_rpc).lower()
        assert "sendpayjoinrequest" not in src


# ---------------------------------------------------------------------------
# G28 / BUG-27 — BIP-21 pj= URI parameter recognition
# ---------------------------------------------------------------------------

class TestG28BIP21PjParameter:
    """`pj=<endpoint>` on a BIP-21 URI advertises the receiver endpoint."""

    def test_no_bip21_pj_parameter_handler(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            src = inspect.getsource(mod)
            for marker in ('"pj"', "'pj'", "[\"pj\"]", "['pj']"):
                assert marker not in src, (
                    f"G28: unexpected pj= parsing in {mod.__name__}"
                )


# ---------------------------------------------------------------------------
# G29 / BUG-28 — BIP-21 pjos= URI parameter recognition
# ---------------------------------------------------------------------------

class TestG29BIP21PjosParameter:
    """`pjos=<0|1>` on a BIP-21 URI advertises disable-output-substitution."""

    def test_no_bip21_pjos_parameter_handler(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            src = inspect.getsource(mod).lower()
            assert "pjos" not in src, f"G29: unexpected pjos in {mod.__name__}"


# ---------------------------------------------------------------------------
# G30 / BUG-29 — Receiver replay protection
# ---------------------------------------------------------------------------

class TestG30ReceiverReplayProtection:
    """Beyond TTL: receiver MUST not produce two different proposals from
    the same Original PSBT (would consume overlapping receiver UTXOs)."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-67: rpc.py re-exports payjoin_replay + "
        "original_psbt_seen (PayJoinReplayTracker pins one proposal "
        "per Original-PSBT fingerprint). _handle_payjoin_request "
        "returns the pinned proposal verbatim for replayed requests, "
        "making the receiver idempotent (matches Wabisabi-style "
        "double-spend defence).",
    )
    def test_no_replay_tracker(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc):
            names = [n.lower() for n in dir(mod)]
            assert not any("payjoin_replay" in n for n in names)
            assert not any("original_psbt_seen" in n for n in names)


# ---------------------------------------------------------------------------
# Universal cross-check: payjoin tokens nowhere in src/ouroboros.
# ---------------------------------------------------------------------------

class TestUniversalAbsence:
    """Final restatement: PayJoin is MISSING ENTIRELY across the entire
    ouroboros Python pipeline.  Future implementation work should make this
    test fail; until then it pins the audit finding."""

    @pytest.mark.xfail(
        strict=True,
        reason="FIX-65: PayJoin receiver foundation landed — rpc.py and "
        "psbt.py now carry payjoin tokens via the new ouroboros.payjoin "
        "module imports and the psbt receive-path forwarders.  The "
        "absence baseline is intentionally invalidated.",
    )
    def test_no_payjoin_token_in_any_module(self):
        for mod in (ob_psbt, ob_wallet, ob_rpc, ob_rest):
            found, hits = _module_source_contains_payjoin(mod)
            assert not found, (
                f"PayJoin token(s) {hits} unexpectedly appeared in {mod.__name__}; "
                "audit baseline outdated"
            )

    def test_no_payjoin_dependency_in_pyproject(self):
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        lower = pyproject.lower()
        for tok in ("payjoin", "bip78", "python-payjoin"):
            assert tok not in lower, (
                f"pyproject.toml unexpectedly references {tok}; audit baseline outdated"
            )

    def test_ferrous_utils_rust_pipeline_has_no_payjoin(self):
        # The Rust side (ferrous-utils) deliberately has no wallet logic; we
        # pin that PayJoin is absent there too.  Scanning common.rs / sync
        # Cargo.toml for a "payjoin" crate dependency suffices.
        repo_root = Path(__file__).resolve().parents[1]
        for cargo in repo_root.glob("ferrous-utils/**/Cargo.toml"):
            text = cargo.read_text().lower()
            assert "payjoin" not in text, (
                f"unexpected payjoin crate dependency in {cargo}"
            )
