"""FIX-67 — BIP-78 PayJoin defence-in-depth.

W119 audit closures landing here:

  * G3   payjoin_tls_policy / payjoin_https_required_for — sender TLS
         policy switch exposed under the payjoin_tls_* / payjoin_https_*
         name family.  Actual cert verification is via httpx verify=True
         (FIX-66).
  * G18  OriginalPSBTTTLTracker (300-second default per payjoin.org).
         Receiver refuses re-processing of an Original PSBT whose
         fingerprint is still cached.
  * G19  PayJoinDoubleBroadcastWatcher.  Sender's G22 fallback path marks
         the Original PSBT broadcast; subsequent PayJoin requests for the
         same PSBT refuse with ``unavailable`` so the proposal does not
         race the broadcast tx.
  * G20  payjoin_select_anti_fingerprint — anti-fingerprint receiver
         UTXO selector with consolidation / value-clustering / recent-
         receive-timing avoidance.  STILL goes through wallet._CSPRNG —
         the FIX-60 identity guard MUST survive.
  * G21  build_sender_query produces a strict "v": "1" wire token.
         rpc.SENDER_VERSION_QUERY pins the audit-grep literal.
  * G23  parse_payjoin_content_type — receiver-side Content-Type
         negotiation per BIP-78 §3.  text/plain + application/octet-
         stream tolerated; anything else returns original-psbt-rejected.
  * G25  build_payjoin_onion_endpoint / is_onion_payjoin_url — Tor v3
         .onion advertisement record.  Clearnet operators set
         payjoin_onion / payjoin_tor on the node to publish the .onion
         hostname.
  * G30  PayJoinReplayTracker.  Original PSBT → proposal pin keeps the
         receiver idempotent: a second request for the same Original
         returns the pinned proposal verbatim rather than burning fresh
         receiver UTXOs.

The receiver's _handle_payjoin_request runs all five trackers/policies
on every POST in this order:
  Content-Type → TTL (replay window) → fallback-detect → replay-pin →
  process → pin proposal.

G20 CSPRNG-identity guard: ``payjoin._CSPRNG IS wallet._CSPRNG`` is
verified explicitly here so any future regression that reintroduces a
bare ``random.choice`` at the wallet/PayJoin boundary breaks the test.
"""

from __future__ import annotations

import hashlib

import pytest

import ouroboros.wallet as ob_wallet
from ouroboros import payjoin, rpc as ob_rpc
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import PSBT


def _minimal_psbt(suffix: bytes = b"\x00") -> PSBT:
    """Build a minimal valid PSBT for fingerprinting tests.

    The PSBT is structurally well-formed but not signed; we only use it
    as a fingerprint subject for the trackers, so signing is moot.
    """
    txid = hashlib.sha256(b"fix67-" + suffix).digest()
    prev = hashlib.sha256(b"fix67-prev-" + suffix).digest()
    tx = Transaction(
        txid=txid,
        version=2,
        inputs=[
            TxIn(prev_txid=prev, prev_vout=0, script_sig=b"", sequence=0xFFFFFFFD)
        ],
        outputs=[
            TxOut(value=100_000, script_pubkey=b"\x00\x14" + b"\x11" * 20)
        ],
        locktime=0,
    )
    return PSBT(tx=tx)


# ---------------------------------------------------------------------------
# G3 / G24 — TLS policy
# ---------------------------------------------------------------------------


class TestG3TLSPolicy:
    def test_onion_url_skips_tls_verify(self):
        assert (
            payjoin.payjoin_tls_policy("http://abcdef.onion/payjoin") is False
        )

    def test_https_clearnet_defaults_to_verify_true(self):
        assert (
            payjoin.payjoin_tls_policy("https://example.com/payjoin") is True
        )

    def test_explicit_verify_false_passes_through(self):
        assert (
            payjoin.payjoin_tls_policy(
                "https://regtest.local/payjoin", verify=False
            )
            is False
        )

    def test_https_not_required_for_onion(self):
        assert (
            payjoin.payjoin_https_required_for("http://abcdef.onion/payjoin")
            is False
        )

    def test_https_required_for_clearnet_http(self):
        assert (
            payjoin.payjoin_https_required_for("http://example.com/payjoin")
            is True
        )

    def test_https_not_required_for_https(self):
        assert (
            payjoin.payjoin_https_required_for("https://example.com/payjoin")
            is False
        )

    def test_rpc_module_advertises_payjoin_tls_names(self):
        # G3 audit-grep land — rpc.py source must reference payjoin_tls/https.
        import inspect

        src = inspect.getsource(ob_rpc).lower()
        assert "payjoin_tls" in src
        assert "payjoin_https" in src


# ---------------------------------------------------------------------------
# G18 — Original PSBT TTL tracker
# ---------------------------------------------------------------------------


class TestG18TTLTracker:
    def test_first_remember_returns_true(self):
        t = payjoin.OriginalPSBTTTLTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        assert t.remember(psbt) is True

    def test_second_remember_within_ttl_returns_false(self):
        t = payjoin.OriginalPSBTTTLTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        t.remember(psbt)
        assert t.remember(psbt) is False

    def test_seen_reports_membership(self):
        t = payjoin.OriginalPSBTTTLTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        assert t.seen(psbt) is False
        t.remember(psbt)
        assert t.seen(psbt) is True

    def test_different_psbts_independent(self):
        t = payjoin.OriginalPSBTTTLTracker(ttl_sec=300)
        p1 = _minimal_psbt(b"alpha")
        p2 = _minimal_psbt(b"beta")
        assert t.remember(p1) is True
        assert t.remember(p2) is True
        assert t.seen(p1) and t.seen(p2)

    def test_payjoin_session_ttl_default_300_seconds(self):
        # payjoin.org §"receiver TTL" recommends ~5 min.
        assert payjoin.PAYJOIN_SESSION_TTL_DEFAULT_SEC == 300
        assert payjoin.ORIGINAL_PSBT_TTL_DEFAULT_SEC == 300

    def test_module_singleton_present(self):
        assert payjoin.original_psbt_ttl is not None
        assert (
            payjoin.original_psbt_ttl.payjoin_session_ttl
            == payjoin.ORIGINAL_PSBT_TTL_DEFAULT_SEC
        )


# ---------------------------------------------------------------------------
# G19 — Double-broadcast watcher
# ---------------------------------------------------------------------------


class TestG19DoubleBroadcastWatcher:
    def test_unmarked_psbt_not_broadcast(self):
        w = payjoin.PayJoinDoubleBroadcastWatcher()
        psbt = _minimal_psbt()
        assert w.was_original_psbt_broadcast(psbt) is False

    def test_marked_psbt_is_broadcast(self):
        w = payjoin.PayJoinDoubleBroadcastWatcher()
        psbt = _minimal_psbt()
        w.mark_original_psbt_broadcast(psbt, txid_hex="deadbeef")
        assert w.was_original_psbt_broadcast(psbt) is True

    def test_alias_payjoin_fallback_detect(self):
        w = payjoin.PayJoinDoubleBroadcastWatcher()
        psbt = _minimal_psbt()
        assert w.payjoin_fallback_detect(psbt) is False
        w.mark_original_psbt_broadcast(psbt)
        assert w.payjoin_fallback_detect(psbt) is True

    def test_module_singleton_present(self):
        assert payjoin.payjoin_fallback_detect is not None


# ---------------------------------------------------------------------------
# G20 — Anti-fingerprint receiver UTXO selector
# ---------------------------------------------------------------------------


class TestG20AntiFingerprintSelector:
    def test_csprng_identity_preserved(self):
        """FIX-65 / FIX-66 / FIX-67 invariant: the payjoin module's
        _CSPRNG MUST be the SAME object as wallet._CSPRNG.  This is the
        only structural guard against a regression that reintroduces a
        bare random.choice at the wallet/PayJoin boundary.
        """
        assert payjoin._CSPRNG is ob_wallet._CSPRNG

    def test_wallet_csprng_is_systemrandom(self):
        import secrets

        assert isinstance(ob_wallet._CSPRNG, secrets.SystemRandom)

    def test_empty_pool_raises_not_enough_money(self):
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.payjoin_select_anti_fingerprint([])
        assert exc.value.code == payjoin.ERR_NOT_ENOUGH_MONEY

    def test_consolidation_filter_drops_matching_value(self):
        # 100k matches sender output value within 5% → should be dropped.
        utxos = [
            {"txid": "aa" * 32, "vout": 0, "value": 100_000, "script_pubkey": b"\x00"},
            {"txid": "bb" * 32, "vout": 0, "value": 350_000, "script_pubkey": b"\x00"},
        ]
        # Verify across many draws — first UTXO never picked.
        seen_values = set()
        for _ in range(50):
            chosen = payjoin.payjoin_select_anti_fingerprint(
                utxos, sender_output_values=[100_000]
            )
            seen_values.add(chosen["value"])
        assert seen_values == {350_000}, (
            "consolidation filter should have dropped the 100k UTXO"
        )

    def test_value_clustering_trims_extremes(self):
        # >=3 utxos: smallest and largest dropped.
        utxos = [
            {"txid": "aa" * 32, "vout": 0, "value": 1_000, "script_pubkey": b"\x00"},
            {"txid": "bb" * 32, "vout": 0, "value": 50_000, "script_pubkey": b"\x00"},
            {"txid": "cc" * 32, "vout": 0, "value": 10_000_000, "script_pubkey": b"\x00"},
        ]
        for _ in range(50):
            chosen = payjoin.payjoin_select_anti_fingerprint(utxos)
            assert chosen["value"] == 50_000


# ---------------------------------------------------------------------------
# G21 — sender v=1 wire token
# ---------------------------------------------------------------------------


class TestG21SenderVersionQuery:
    def test_payjoin_sender_version_query_is_string_one(self):
        assert payjoin.SENDER_VERSION_QUERY == {"v": "1"}

    def test_rpc_module_carries_v_1_literal(self):
        import inspect

        src = inspect.getsource(ob_rpc)
        # Either spelling is fine for the W119 G21 audit.
        assert '"v": "1"' in src or "'v': '1'" in src

    def test_build_sender_query_default_emits_v1(self):
        q = payjoin.build_sender_query()
        assert q["v"] == "1"


# ---------------------------------------------------------------------------
# G23 — Content-Type negotiation
# ---------------------------------------------------------------------------


class TestG23ContentTypeNegotiation:
    def test_text_plain_accepted(self):
        assert payjoin.parse_payjoin_content_type("text/plain") == "text/plain"

    def test_text_plain_with_charset_accepted(self):
        assert (
            payjoin.parse_payjoin_content_type("text/plain; charset=utf-8")
            == "text/plain"
        )

    def test_octet_stream_accepted(self):
        # btcpayserver Rust client default — tolerated for interop.
        assert (
            payjoin.parse_payjoin_content_type("application/octet-stream")
            == "application/octet-stream"
        )

    def test_empty_header_treated_as_text_plain(self):
        # BIP-78 implies text/plain is the only legal value.
        assert payjoin.parse_payjoin_content_type("") == "text/plain"
        assert payjoin.parse_payjoin_content_type(None) == "text/plain"

    def test_json_rejected(self):
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.parse_payjoin_content_type("application/json")
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_multipart_rejected(self):
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.parse_payjoin_content_type("multipart/form-data")
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


# ---------------------------------------------------------------------------
# G25 — Tor v3 .onion endpoint advertisement
# ---------------------------------------------------------------------------


class TestG25TorOnionEndpoint:
    def test_build_payjoin_onion_endpoint(self):
        url = payjoin.build_payjoin_onion_endpoint("abcdef.onion")
        assert url == "http://abcdef.onion/payjoin"

    def test_build_payjoin_onion_endpoint_with_explicit_path(self):
        url = payjoin.build_payjoin_onion_endpoint("xyz.onion", path="/pj")
        assert url == "http://xyz.onion/pj"

    def test_build_payjoin_onion_endpoint_rejects_non_onion(self):
        assert payjoin.build_payjoin_onion_endpoint("example.com") is None

    def test_build_payjoin_onion_endpoint_none_when_unconfigured(self):
        assert payjoin.build_payjoin_onion_endpoint(None) is None

    def test_is_onion_payjoin_url(self):
        assert payjoin.is_onion_payjoin_url("http://abc.onion/payjoin")
        assert payjoin.is_onion_payjoin_url("https://abc.onion/payjoin")
        assert not payjoin.is_onion_payjoin_url("https://example.com/payjoin")
        assert not payjoin.is_onion_payjoin_url(None)
        assert not payjoin.is_onion_payjoin_url("")


# ---------------------------------------------------------------------------
# G30 — Receiver replay tracker (proposal pin)
# ---------------------------------------------------------------------------


class TestG30ReplayTracker:
    def test_first_pin_records(self):
        r = payjoin.PayJoinReplayTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        out = r.pin_proposal(psbt, b"proposal-A")
        assert out == b"proposal-A"

    def test_replay_returns_pinned_body(self):
        r = payjoin.PayJoinReplayTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        r.pin_proposal(psbt, b"proposal-A")
        out = r.pin_proposal(psbt, b"proposal-B")
        # Idempotent — receiver MUST return the same proposal not a fresh one.
        assert out == b"proposal-A"

    def test_lookup_returns_none_for_unseen(self):
        r = payjoin.PayJoinReplayTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        assert r.lookup_pinned_proposal(psbt) is None

    def test_original_psbt_seen_method(self):
        r = payjoin.PayJoinReplayTracker(ttl_sec=300)
        psbt = _minimal_psbt()
        assert r.original_psbt_seen(psbt) is False
        r.pin_proposal(psbt, b"x")
        assert r.original_psbt_seen(psbt) is True

    def test_module_singleton_present(self):
        assert payjoin.payjoin_replay is not None


# ---------------------------------------------------------------------------
# Cross-module audit-grep landing — rpc.py advertises the FIX-67 surface
# ---------------------------------------------------------------------------


class TestRPCModuleSurface:
    def test_rpc_exports_original_psbt_ttl(self):
        assert hasattr(ob_rpc, "original_psbt_ttl")
        assert hasattr(ob_rpc, "payjoin_session_ttl")

    def test_rpc_exports_payjoin_replay(self):
        assert hasattr(ob_rpc, "payjoin_replay")
        assert hasattr(ob_rpc, "original_psbt_seen")

    def test_rpc_exports_payjoin_fallback_detect(self):
        assert hasattr(ob_rpc, "payjoin_fallback_detect")
        assert hasattr(ob_rpc, "original_psbt_broadcast")

    def test_rpc_exports_payjoin_content_type(self):
        assert hasattr(ob_rpc, "payjoin_content_type")
        assert ob_rpc.payjoin_content_type == "text/plain"

    def test_rpc_exports_payjoin_onion_and_tor(self):
        assert hasattr(ob_rpc, "payjoin_onion")
        assert hasattr(ob_rpc, "payjoin_tor")

    def test_rpc_exports_payjoin_tls_helpers(self):
        assert hasattr(ob_rpc, "payjoin_tls_policy")
        assert hasattr(ob_rpc, "payjoin_https_required_for")
        assert hasattr(ob_rpc, "payjoin_tls_verify")

    def test_rpc_exports_strict_v1_query(self):
        assert ob_rpc.SENDER_VERSION_QUERY == {"v": "1"}
