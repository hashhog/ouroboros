"""FIX-66 — BIP-78 PayJoin sender + anti-snoop + 2 RPCs.

This suite exercises the sender half of the BIP-78 protocol landed in
FIX-66 on top of the FIX-65 receiver foundation:

  * **Round-trip** — sender ``send_payjoin_request`` POSTs to an
    in-process FIX-65 receiver via ``httpx.ASGITransport``; receiver
    appends a CSPRNG-selected UTXO; the response is decoded back into
    a PSBT and validated by all six sender-side anti-snoop checks.

  * **6 anti-snoop validators (G10–G15)**:
      - G10 ``validate_response_outputs`` — sender outputs preserved
      - G11 ``validate_scriptsig_uniformity`` — UIH-1 enforcement
      - G12 ``validate_inputs_imply_outputs_changed`` — UIH-2 enforcement
      - G13 ``validate_max_fee_contribution`` — cap enforcement
      - G14 ``validate_disable_output_substitution`` — pjos=1 strict mode
      - G15 ``build_sender_query`` — minfeerate propagated on wire

  * **G22 retry/fallback** — when the receiver returns ``unavailable``
    (transient) or is unreachable, the sender falls back to
    broadcasting the Original PSBT.

  * **2 RPCs** — ``rpc_getpayjoinrequest`` (sender helper that emits an
    Original PSBT) and ``rpc_sendpayjoinrequest`` (terminal RPC: POST +
    validate + broadcast).  Both are wired into the JSON-RPC dispatch.

  * **G20 CSPRNG identity guard** — FIX-65's
    ``payjoin._CSPRNG IS wallet._CSPRNG`` identity MUST survive FIX-66.
    Any future regression that reintroduces a bare ``random.choice`` at
    the wallet/PayJoin boundary breaks the test (it's the only
    structural guard against the W88 Mersenne Twister anti-pattern).

Specs:
  BIP-78  https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
  BIP-174 https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
  payjoin.org §Sender-validates / Receiver-error
"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from ouroboros import payjoin
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import PSBT, PSBT_VERSION_0
from ouroboros.rpc import RPCServer
from ouroboros.wallet import WalletKey, _CSPRNG, _hash160


# ---------------------------------------------------------------------------
# Helpers (parallel to test_fix65_payjoin_receiver.py)
# ---------------------------------------------------------------------------


def _make_key(seed: bytes) -> WalletKey:
    return WalletKey(hashlib.sha256(seed).digest(), network="regtest")


def _p2wpkh_script(key: WalletKey) -> bytes:
    return b"\x00\x14" + _hash160(key.pubkey)


def _p2pkh_script(key: WalletKey) -> bytes:
    return b"\x76\xa9\x14" + _hash160(key.pubkey) + b"\x88\xac"


def _build_original_psbt(
    sender_key: WalletKey,
    receiver_script: bytes,
    *,
    sender_amount: int = 100_000,
    pay_amount: int = 60_000,
    change_amount: int = 30_000,
    sign_input: bool = True,
) -> PSBT:
    """Build a sender Original PSBT satisfying BIP-78 §3 checklist."""
    fake_prev_txid = bytes(32)
    sender_input = TxIn(
        prev_txid=fake_prev_txid,
        prev_vout=0,
        script_sig=b"",
        sequence=0xFFFFFFFD,
    )
    payment_out = TxOut(value=pay_amount, script_pubkey=receiver_script)
    change_out = TxOut(
        value=change_amount,
        script_pubkey=_p2wpkh_script(sender_key),
    )
    tx = Transaction(
        txid=bytes(32),
        version=2,
        locktime=0,
        inputs=[sender_input],
        outputs=[payment_out, change_out],
        has_witness=False,
    )
    psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_0)
    inp = psbt.inputs[0]
    inp.witness_utxo = (sender_amount, _p2wpkh_script(sender_key))
    if sign_input:
        h = hashlib.sha256(b"sender-sighash").digest()
        sig_der = sender_key._privkey.sign(h, hasher=None)
        inp.partial_sigs[sender_key.pubkey] = sig_der + bytes([0x01])
    return psbt


def _make_receiver_ctx(
    receiver_key: WalletKey,
    *,
    utxos_value: list[int] | None = None,
    min_amount: int = 0,
) -> payjoin.ReceiverContext:
    """Mirror of the FIX-65 ctx helper, parameterised by value list."""
    if utxos_value is None:
        utxos_value = [50_000]
    spk = _p2wpkh_script(receiver_key)
    utxos = [
        {
            "txid": bytes([i + 1] * 32).hex(),
            "vout": 0,
            "value": v,
            "script_pubkey": spk,
        }
        for i, v in enumerate(utxos_value)
    ]

    def list_utxos():
        return utxos

    def get_key_for_script(s):
        if s == spk:
            return receiver_key
        return None

    return payjoin.ReceiverContext(
        list_utxos=list_utxos,
        get_key_for_script=get_key_for_script,
        receiver_script=spk,
        min_amount=min_amount,
    )


# ---------------------------------------------------------------------------
# In-process FastAPI fixture for round-trip via httpx
# ---------------------------------------------------------------------------


class _MockMempool:
    def get_all_txids(self):
        return []

    def size(self):
        return 0

    def bytes(self):
        return 0

    @property
    def max_size(self):
        return 300_000_000


class _MockDB:
    def get_best_block(self):
        return (b"\x00" * 32, 42)

    def get_block(self, *a, **kw):
        return None

    def get_block_by_height(self, *a, **kw):
        return None

    def list_unspent_by_address(self, *a, **kw):
        return []


class _MockWallet:
    def __init__(self, key: WalletKey, utxos: list[dict]) -> None:
        self.keys = [{"wif": key.to_wif(), "label": "test", "created": 0}]
        self._utxos = utxos

    def _collect_utxos(self):
        return list(self._utxos)


class _MockNode:
    def __init__(self, wallet=None, receive_script=None) -> None:
        self.db = _MockDB()
        self.network = "regtest"
        self.mempool = _MockMempool()
        self.wallet = wallet
        if receive_script is not None:
            self.payjoin_receive_script = receive_script
        self.payjoin_min_amount = 0


class _FastAPIBridgeTransport(httpx.BaseTransport):
    """Bridge synchronous httpx requests to a FastAPI ``TestClient``.

    httpx.ASGITransport is async-only; the production sender uses
    httpx.Client (sync) because it lives behind a synchronous RPC
    handler.  TestClient provides a *blocking* path into the FastAPI
    app via its own internal portal.  This transport forwards each
    sync ``handle_request`` call through TestClient so we can exercise
    the full sender→receiver round-trip without spinning up a real
    socket.
    """

    def __init__(self, app):
        self._client = TestClient(app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Translate the URL: TestClient is mounted at "/", so pass the
        # path-and-query verbatim.
        url_path = request.url.raw_path.decode("utf-8")
        method = request.method
        body = request.content
        headers = dict(request.headers)
        resp = self._client.request(
            method, url_path, content=body, headers=headers
        )
        return httpx.Response(
            status_code=resp.status_code,
            headers=resp.headers.items(),
            content=resp.content,
            request=request,
        )

    def close(self) -> None:
        # TestClient cleans up on app shutdown; nothing for us to do here.
        pass


@pytest.fixture
def receiver_app_url():
    """Spin up an in-process FIX-65 receiver + an httpx-compatible
    transport that routes through FastAPI's TestClient.  Returns the
    transport, the absolute URL the sender should POST to, the
    receiver key, and the receiver's payment script."""
    receiver = _make_key(b"fix66-route-receiver")
    recv_script = _p2wpkh_script(receiver)
    utxo = {
        "txid": "ab" * 32,
        "vout": 0,
        "value": 40_000,
        "script_pubkey": recv_script,
    }
    wallet = _MockWallet(receiver, [utxo])
    node = _MockNode(wallet=wallet, receive_script=recv_script)
    rpc = RPCServer(node, port=0)
    transport = _FastAPIBridgeTransport(rpc.get_app())
    url = "http://payjoin-receiver.localtest/payjoin"
    yield transport, url, receiver, recv_script


# ---------------------------------------------------------------------------
# Round-trip via httpx + in-process receiver
# ---------------------------------------------------------------------------


class TestSenderRoundTrip:
    """End-to-end: sender constructs Original PSBT, POSTs via httpx, decodes
    response, runs anti-snoop validators."""

    def test_round_trip_via_asgi_transport(self, receiver_app_url):
        transport, url, receiver, recv_script = receiver_app_url
        sender = _make_key(b"fix66-sender-1")

        original = _build_original_psbt(sender, recv_script)

        resp = payjoin.send_payjoin_request(
            url,
            original,
            verify=False,  # ASGI transport — no TLS
            transport=transport,
        )
        assert resp.is_success, (
            f"expected success; got {resp.error.code if resp.error else None}"
        )
        proposal = resp.psbt
        assert proposal is not None
        # +1 input vs sender (the receiver added one).
        assert len(proposal.tx.inputs) == 2
        # Sender's input preserved.
        assert proposal.inputs[0].partial_sigs[sender.pubkey] == (
            original.inputs[0].partial_sigs[sender.pubkey]
        )

    def test_round_trip_full_anti_snoop_pass(self, receiver_app_url):
        """Receiver's well-formed proposal MUST pass all 6 validators.

        The sender opts in to fee adjustment so the receiver's
        proposal changes an output amount (the canonical PayJoin
        shape).  Without opt-in the receiver would add an input
        without changing outputs, which the strict G12 / UIH-2
        validator correctly flags.
        """
        transport, url, receiver, recv_script = receiver_app_url
        sender = _make_key(b"fix66-sender-2")

        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        resp = payjoin.send_payjoin_request(
            url,
            original,
            additionalfeeoutputindex=1,
            maxadditionalfeecontribution=500,
            verify=False,
            transport=transport,
        )
        assert resp.is_success
        # No exception — every validator accepts.
        payjoin.validate_payjoin_response(
            original,
            resp.psbt,
            additionalfeeoutputindex=1,
            maxadditionalfeecontribution=500,
            disable_output_substitution=False,
        )

    def test_round_trip_with_fee_adjustment(self, receiver_app_url):
        """Sender opts in to fee adjustment — receiver applies it under cap."""
        transport, url, receiver, recv_script = receiver_app_url
        sender = _make_key(b"fix66-sender-3")

        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        resp = payjoin.send_payjoin_request(
            url,
            original,
            additionalfeeoutputindex=1,
            maxadditionalfeecontribution=500,
            verify=False,
            transport=transport,
        )
        assert resp.is_success
        # Receiver subtracted exactly the cap (500).
        assert resp.psbt.tx.outputs[1].value == 30_000 - 500
        # And max-fee-contribution validator accepts.
        payjoin.validate_max_fee_contribution(
            original,
            resp.psbt,
            additionalfeeoutputindex=1,
            maxadditionalfeecontribution=500,
        )


# ---------------------------------------------------------------------------
# G15 — minfeerate propagation on the wire
# ---------------------------------------------------------------------------


class TestG15MinFeeRatePropagation:
    """Sender SHOULD set ``minfeerate`` on the BIP-78 query string."""

    def test_build_sender_query_carries_minfeerate(self):
        q = payjoin.build_sender_query(minfeerate=12.5)
        assert q["minfeerate"] == "12.5"
        assert q["v"] == "1"

    def test_build_sender_query_omits_minfeerate_when_none(self):
        q = payjoin.build_sender_query()
        assert "minfeerate" not in q
        assert q["v"] == "1"

    def test_build_sender_query_rejects_negative_minfeerate(self):
        with pytest.raises(ValueError):
            payjoin.build_sender_query(minfeerate=-1.0)

    def test_build_sender_query_rejects_unpaired_fee_params(self):
        with pytest.raises(ValueError):
            payjoin.build_sender_query(additionalfeeoutputindex=1)
        with pytest.raises(ValueError):
            payjoin.build_sender_query(maxadditionalfeecontribution=100)

    def test_build_sender_query_propagates_pjos(self):
        q1 = payjoin.build_sender_query(disableoutputsubstitution=True)
        assert q1["disableoutputsubstitution"] == "1"
        q0 = payjoin.build_sender_query(disableoutputsubstitution=False)
        assert q0["disableoutputsubstitution"] == "0"
        qn = payjoin.build_sender_query()
        assert "disableoutputsubstitution" not in qn

    def test_send_payjoin_request_sends_minfeerate(self, receiver_app_url):
        """The receiver echoes back nothing about minfeerate (BIP-78 has no
        echo), so we verify propagation by inspecting the request body
        via a recording transport."""
        transport, _url, receiver, recv_script = receiver_app_url
        sender = _make_key(b"fix66-minfeerate")

        # Hand-roll a recording transport: wrap the ASGI transport and
        # capture the most recent request URL.
        captured: dict[str, Any] = {}

        class _Recording(httpx.BaseTransport):
            def __init__(self, inner: httpx.BaseTransport):
                self._inner = inner

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                captured["url"] = str(request.url)
                return self._inner.handle_request(request)

        original = _build_original_psbt(sender, recv_script)
        rec = _Recording(transport)
        resp = payjoin.send_payjoin_request(
            "http://payjoin-receiver.localtest/payjoin",
            original,
            minfeerate=3.0,
            verify=False,
            transport=rec,
        )
        assert resp.is_success
        # minfeerate is on the wire.
        assert "minfeerate=3.0" in captured["url"]
        assert "v=1" in captured["url"]


# ---------------------------------------------------------------------------
# G10 — sender output preservation (anti-snoop)
# ---------------------------------------------------------------------------


class TestG10ResponseOutputPreservation:
    def test_g10_accepts_unchanged_outputs(self):
        sender = _make_key(b"g10-1")
        receiver = _make_key(b"g10-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        # Identity case: proposal == original.
        proposal = _build_original_psbt(sender, recv_script)
        payjoin.validate_response_outputs(original, proposal)

    def test_g10_rejects_dropped_sender_output(self):
        sender = _make_key(b"g10-2")
        receiver = _make_key(b"g10-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # Receiver "stole" the sender's change output.
        proposal.tx.outputs.pop()
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_response_outputs(original, proposal)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g10_rejects_substituted_payment_script(self):
        sender = _make_key(b"g10-3")
        receiver = _make_key(b"g10-3r")
        attacker = _make_key(b"g10-3a")
        recv_script = _p2wpkh_script(receiver)
        attacker_script = _p2wpkh_script(attacker)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # Receiver redirects the payment output to themselves.
        proposal.tx.outputs[0].script_pubkey = attacker_script
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_response_outputs(original, proposal)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


# ---------------------------------------------------------------------------
# G11 — UIH-1 scriptSig type uniformity
# ---------------------------------------------------------------------------


class TestG11ScriptSigUniformity:
    def test_g11_accepts_same_script_type(self):
        sender = _make_key(b"g11-1")
        receiver = _make_key(b"g11-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # Receiver adds another P2WPKH input — uniform.
        proposal.tx.inputs.append(
            TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0xFFFFFFFD)
        )
        from ouroboros.psbt import PSBTInput

        new_in = PSBTInput()
        new_in.witness_utxo = (40_000, _p2wpkh_script(receiver))
        proposal.inputs.append(new_in)
        payjoin.validate_scriptsig_uniformity(original, proposal)

    def test_g11_rejects_mixed_script_types(self):
        """Sender is P2WPKH; receiver adds a P2PKH input — UIH-1 leak."""
        sender = _make_key(b"g11-2")
        receiver = _make_key(b"g11-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # Receiver contributes a P2PKH (legacy) input — script-type mismatch.
        proposal.tx.inputs.append(
            TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0xFFFFFFFD)
        )
        from ouroboros.psbt import PSBTInput

        new_in = PSBTInput()
        new_in.witness_utxo = (40_000, _p2pkh_script(receiver))
        proposal.inputs.append(new_in)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_scriptsig_uniformity(original, proposal)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g11_classify_script_type_covers_known_types(self):
        # P2PKH
        p2pkh = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        assert payjoin._classify_script_type(p2pkh) == "p2pkh"
        # P2SH
        p2sh = b"\xa9\x14" + b"\x00" * 20 + b"\x87"
        assert payjoin._classify_script_type(p2sh) == "p2sh"
        # P2WPKH
        p2wpkh = b"\x00\x14" + b"\x00" * 20
        assert payjoin._classify_script_type(p2wpkh) == "p2wpkh"
        # P2WSH
        p2wsh = b"\x00\x20" + b"\x00" * 32
        assert payjoin._classify_script_type(p2wsh) == "p2wsh"
        # P2TR
        p2tr = b"\x51\x20" + b"\x00" * 32
        assert payjoin._classify_script_type(p2tr) == "p2tr"
        # Unknown
        assert payjoin._classify_script_type(b"\xff\xff") == "unknown"


# ---------------------------------------------------------------------------
# G12 — UIH-2: new inputs without output modification
# ---------------------------------------------------------------------------


class TestG12UIH2NewInputsNoOutputChange:
    def test_g12_accepts_no_added_inputs(self):
        sender = _make_key(b"g12-1")
        receiver = _make_key(b"g12-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # No added inputs ⇒ UIH-2 N/A.
        payjoin.validate_inputs_imply_outputs_changed(original, proposal)

    def test_g12_accepts_inputs_added_with_output_change(self):
        sender = _make_key(b"g12-2")
        receiver = _make_key(b"g12-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        # Proposal with +1 input AND a different change amount.
        proposal = _build_original_psbt(sender, recv_script, change_amount=29_500)
        proposal.tx.inputs.append(
            TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0xFFFFFFFD)
        )
        from ouroboros.psbt import PSBTInput

        new_in = PSBTInput()
        new_in.witness_utxo = (40_000, _p2wpkh_script(receiver))
        proposal.inputs.append(new_in)
        payjoin.validate_inputs_imply_outputs_changed(original, proposal)

    def test_g12_rejects_inputs_added_without_output_change(self):
        """The canonical UIH-2 leak: outputs identical despite added inputs."""
        sender = _make_key(b"g12-3")
        receiver = _make_key(b"g12-3r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        # Add an input WITHOUT changing any output (script or amount).
        proposal.tx.inputs.append(
            TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0xFFFFFFFD)
        )
        from ouroboros.psbt import PSBTInput

        new_in = PSBTInput()
        new_in.witness_utxo = (40_000, _p2wpkh_script(receiver))
        proposal.inputs.append(new_in)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_inputs_imply_outputs_changed(original, proposal)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


# ---------------------------------------------------------------------------
# G13 — max-fee contribution cap
# ---------------------------------------------------------------------------


class TestG13MaxFeeContribution:
    def test_g13_accepts_within_cap(self):
        sender = _make_key(b"g13-1")
        receiver = _make_key(b"g13-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        proposal = _build_original_psbt(sender, recv_script, change_amount=29_500)
        # Subtracted 500, cap 1000 ⇒ OK.
        payjoin.validate_max_fee_contribution(
            original,
            proposal,
            additionalfeeoutputindex=1,
            maxadditionalfeecontribution=1000,
        )

    def test_g13_rejects_exceeded_cap(self):
        sender = _make_key(b"g13-2")
        receiver = _make_key(b"g13-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        proposal = _build_original_psbt(sender, recv_script, change_amount=28_000)
        # Subtracted 2000, cap 500 ⇒ reject.
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_max_fee_contribution(
                original,
                proposal,
                additionalfeeoutputindex=1,
                maxadditionalfeecontribution=500,
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g13_rejects_amount_increase(self):
        """Receiver pumping the designated output's amount = theft attempt."""
        sender = _make_key(b"g13-3")
        receiver = _make_key(b"g13-3r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        proposal = _build_original_psbt(sender, recv_script, change_amount=31_000)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_max_fee_contribution(
                original,
                proposal,
                additionalfeeoutputindex=1,
                maxadditionalfeecontribution=1000,
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g13_rejects_unauthorized_amount_change_when_no_opt_in(self):
        """Sender did not opt in to fee adjustment ⇒ no output amount may change."""
        sender = _make_key(b"g13-4")
        receiver = _make_key(b"g13-4r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        proposal = _build_original_psbt(sender, recv_script, change_amount=29_900)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_max_fee_contribution(
                original,
                proposal,
                additionalfeeoutputindex=None,
                maxadditionalfeecontribution=None,
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g13_accepts_no_opt_in_no_change(self):
        sender = _make_key(b"g13-5")
        receiver = _make_key(b"g13-5r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        payjoin.validate_max_fee_contribution(
            original,
            proposal,
            additionalfeeoutputindex=None,
            maxadditionalfeecontribution=None,
        )


# ---------------------------------------------------------------------------
# G14 — pjos=1 disableoutputsubstitution strict mode
# ---------------------------------------------------------------------------


class TestG14DisableOutputSubstitution:
    def test_g14_no_op_when_flag_off(self):
        sender = _make_key(b"g14-1")
        receiver = _make_key(b"g14-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script, change_amount=29_000)
        # pjos=0 ⇒ this validator is a no-op (G13 catches the cap miss).
        payjoin.validate_disable_output_substitution(
            original, proposal, disable_output_substitution=False
        )

    def test_g14_strict_match_passes_when_outputs_unchanged(self):
        sender = _make_key(b"g14-2")
        receiver = _make_key(b"g14-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        payjoin.validate_disable_output_substitution(
            original, proposal, disable_output_substitution=True
        )

    def test_g14_strict_rejects_output_count_change(self):
        sender = _make_key(b"g14-3")
        receiver = _make_key(b"g14-3r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        proposal = _build_original_psbt(sender, recv_script)
        proposal.tx.outputs.append(
            TxOut(value=100, script_pubkey=_p2wpkh_script(receiver))
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_disable_output_substitution(
                original, proposal, disable_output_substitution=True
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_g14_strict_rejects_amount_change(self):
        sender = _make_key(b"g14-4")
        receiver = _make_key(b"g14-4r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        proposal = _build_original_psbt(sender, recv_script, change_amount=29_500)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_disable_output_substitution(
                original, proposal, disable_output_substitution=True
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


# ---------------------------------------------------------------------------
# G22 — sender fallback path
# ---------------------------------------------------------------------------


class TestG22SenderFallback:
    def test_fallback_when_receiver_returns_unavailable(self):
        """Mock httpx transport returning 503 ``unavailable`` → SenderResponse
        marks the error transient."""
        sender = _make_key(b"g22-1")
        receiver = _make_key(b"g22-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)

        class _UnavailableTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    503,
                    json={"errorCode": "unavailable", "message": "down"},
                    request=request,
                )

        resp = payjoin.send_payjoin_request(
            "http://unreachable.invalid/payjoin",
            original,
            verify=False,
            transport=_UnavailableTransport(),
        )
        assert not resp.is_success
        assert resp.is_transient
        assert resp.error.code == payjoin.ERR_UNAVAILABLE

    def test_fallback_when_endpoint_unreachable(self):
        """ConnectError surfaces as transient ``unavailable``."""
        sender = _make_key(b"g22-2")
        receiver = _make_key(b"g22-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)

        class _ConnectErrorTransport(httpx.BaseTransport):
            def handle_request(self, request):
                raise httpx.ConnectError("nope", request=request)

        resp = payjoin.send_payjoin_request(
            "http://unreachable.invalid/payjoin",
            original,
            verify=False,
            transport=_ConnectErrorTransport(),
        )
        assert not resp.is_success
        assert resp.is_transient
        assert resp.error.code == payjoin.ERR_UNAVAILABLE

    def test_fallback_when_timeout(self):
        sender = _make_key(b"g22-3")
        receiver = _make_key(b"g22-3r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)

        class _TimeoutTransport(httpx.BaseTransport):
            def handle_request(self, request):
                raise httpx.ConnectTimeout("slow", request=request)

        resp = payjoin.send_payjoin_request(
            "http://slow.invalid/payjoin",
            original,
            verify=False,
            transport=_TimeoutTransport(),
        )
        assert not resp.is_success
        assert resp.is_transient

    def test_non_transient_error_not_treated_as_fallback(self):
        """``original-psbt-rejected`` is NOT transient — sender MUST NOT fall
        back; the sender PSBT was malformed and re-broadcasting it would
        fail the same way."""
        sender = _make_key(b"g22-4")
        receiver = _make_key(b"g22-4r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)

        class _RejectTransport(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(
                    400,
                    json={
                        "errorCode": "original-psbt-rejected",
                        "message": "malformed",
                    },
                    request=request,
                )

        resp = payjoin.send_payjoin_request(
            "http://x.invalid/payjoin",
            original,
            verify=False,
            transport=_RejectTransport(),
        )
        assert not resp.is_success
        assert not resp.is_transient
        assert resp.error.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


# ---------------------------------------------------------------------------
# G24 — HTTPS cert verification (httpx default verify=True)
# ---------------------------------------------------------------------------


class TestG24HTTPSVerification:
    def test_send_payjoin_request_defaults_verify_true(self):
        """The ``send_payjoin_request`` signature MUST default ``verify=True``
        so production callers cannot accidentally ship a build that
        ignores invalid TLS certificates."""
        sig = inspect.signature(payjoin.send_payjoin_request)
        assert sig.parameters["verify"].default is True

    def test_send_payjoin_request_accepts_verify_kwarg(self):
        """Tests + .onion endpoints need to opt out (Tor is encrypted at
        the layer below)."""
        sig = inspect.signature(payjoin.send_payjoin_request)
        assert sig.parameters["verify"].kind == inspect.Parameter.KEYWORD_ONLY


# ---------------------------------------------------------------------------
# 2 RPCs — rpc_getpayjoinrequest + rpc_sendpayjoinrequest
# ---------------------------------------------------------------------------


@pytest.fixture
def rpc_with_wallet():
    """Build an RPC server with a minimal wallet that has spendable UTXOs.

    The wallet fixture is parameterised to support ``send_transaction``
    and ``_collect_utxos`` calls that the new sender RPC depends on.
    """
    sender = _make_key(b"rpc-wallet-sender")
    spk = _p2wpkh_script(sender)
    utxo = {
        "txid": "cd" * 32,
        "vout": 0,
        "value": 100_000,
        "script_pubkey": spk,
        "_key": sender,
        "network": "regtest",
    }

    class _SendingWallet(_MockWallet):
        def __init__(self):
            super().__init__(sender, [utxo])
            self.db = _MockDB()
            self.network = "regtest"

        async def send_transaction(self, address, amount_sat, fee_rate):
            from ouroboros.address import address_to_script_pubkey
            from ouroboros.database import Transaction, TxIn, TxOut

            dest_spk = address_to_script_pubkey(address, "regtest")
            change_amt = utxo["value"] - amount_sat - 1_000
            outputs = [TxOut(value=amount_sat, script_pubkey=dest_spk)]
            if change_amt > 546:
                outputs.append(TxOut(value=change_amt, script_pubkey=spk))
            inputs = [
                TxIn(
                    prev_txid=bytes.fromhex(utxo["txid"]),
                    prev_vout=0,
                    script_sig=b"",
                    sequence=0xFFFFFFFD,
                )
            ]
            tx = Transaction(
                txid=bytes(32),
                version=2,
                locktime=0,
                inputs=inputs,
                outputs=outputs,
                has_witness=True,
            )
            # Sign the input (BIP-143 P2WPKH) — same path as
            # walletprocesspsbt / send_transaction.
            from ouroboros.segwit_v0 import bip143_sighash

            h160 = _hash160(sender.pubkey)
            script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
            sighash = bip143_sighash(
                tx, 0, script_code, utxo["value"], 0x01
            )
            sig = sender._privkey.sign(sighash, hasher=None) + b"\x01"
            tx.inputs[0].witness = [sig, sender.pubkey]
            return tx.serialize_with_witness().hex()

    w = _SendingWallet()
    node = _MockNode(wallet=w)
    rpc = RPCServer(node, port=0)
    return rpc, sender, w


class TestRPCGetPayjoinRequest:
    """G26 — sender helper that emits an Original PSBT."""

    @pytest.mark.asyncio
    async def test_rpc_returns_signed_not_finalized_psbt(self, rpc_with_wallet):
        rpc, sender, _wallet = rpc_with_wallet
        receiver = _make_key(b"rpc-getpayjoin-receiver")
        addr = receiver.get_p2wpkh_address()
        # 0.0005 BTC = 50_000 sat
        result = await rpc.rpc_getpayjoinrequest(addr, 0.0005, fee_rate=1)
        assert "psbt" in result
        psbt = PSBT.from_base64(result["psbt"])
        # 1 input, 2 outputs (payment + change).
        assert psbt.tx is not None
        assert len(psbt.tx.inputs) == 1
        assert len(psbt.tx.outputs) >= 1
        # Input is signed (has partial_sig) but not finalized.
        psbt_in = psbt.inputs[0]
        assert not psbt_in.is_finalized()
        assert len(psbt_in.partial_sigs) == 1
        assert psbt_in.witness_utxo is not None

    @pytest.mark.asyncio
    async def test_rpc_rejects_invalid_amount(self, rpc_with_wallet):
        rpc, sender, _wallet = rpc_with_wallet
        receiver = _make_key(b"rpc-getpayjoin-receiver-2")
        addr = receiver.get_p2wpkh_address()
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            await rpc.rpc_getpayjoinrequest(addr, 0.0)

    @pytest.mark.asyncio
    async def test_rpc_returns_amount_and_indices(self, rpc_with_wallet):
        rpc, sender, _wallet = rpc_with_wallet
        receiver = _make_key(b"rpc-getpayjoin-receiver-3")
        addr = receiver.get_p2wpkh_address()
        result = await rpc.rpc_getpayjoinrequest(addr, 0.0005, fee_rate=1)
        assert result["amount_sat"] == 50_000
        assert result["fee_rate"] == 1
        assert result["payment_output_index"] == 0


class TestRPCSendPayjoinRequest:
    """G27 — terminal sender RPC: POST + validate + broadcast."""

    @pytest.mark.asyncio
    async def test_rpc_falls_back_on_unavailable(self, rpc_with_wallet):
        """When the configured endpoint returns ``unavailable``, the RPC
        falls back to broadcasting the Original PSBT."""
        rpc, sender, _wallet = rpc_with_wallet

        # 1. Build the Original PSBT via the helper RPC.
        receiver = _make_key(b"rpc-send-rcv-1")
        addr = receiver.get_p2wpkh_address()
        original_result = await rpc.rpc_getpayjoinrequest(
            addr, 0.0005, fee_rate=1
        )
        psbt_b64 = original_result["psbt"]

        # 2. Monkey-patch ``send_payjoin_request`` to simulate the receiver
        #    returning ``unavailable``.  This is more reliable than
        #    spinning up a transient HTTP server.
        from ouroboros import payjoin as _payjoin

        recorded: dict[str, Any] = {}

        def fake_send(*a, **kw):
            return _payjoin.SenderResponse(
                error=_payjoin.err_unavailable("simulated")
            )

        # We also need ``sendrawtransaction`` to succeed; stub it.
        async def fake_sendraw(hexstring, maxfeerate=None):
            recorded["raw_hex"] = hexstring
            return "deadbeef" * 8

        original_send = _payjoin.send_payjoin_request
        original_sendraw = rpc.rpc_sendrawtransaction
        _payjoin.send_payjoin_request = fake_send  # type: ignore
        rpc.rpc_sendrawtransaction = fake_sendraw  # type: ignore
        try:
            result = await rpc.rpc_sendpayjoinrequest(
                endpoint_url="http://x.invalid/payjoin",
                psbt=psbt_b64,
                broadcast=True,
            )
        finally:
            _payjoin.send_payjoin_request = original_send  # type: ignore
            rpc.rpc_sendrawtransaction = original_sendraw  # type: ignore
        assert result["status"] == "fallback"
        assert result["txid"] is not None
        assert "simulated" in result["fallback_reason"]

    @pytest.mark.asyncio
    async def test_rpc_rejects_non_transient_error(self, rpc_with_wallet):
        """``original-psbt-rejected`` is NOT a fallback case — surface as HTTPException."""
        rpc, sender, _wallet = rpc_with_wallet
        receiver = _make_key(b"rpc-send-rcv-2")
        addr = receiver.get_p2wpkh_address()
        original_result = await rpc.rpc_getpayjoinrequest(
            addr, 0.0005, fee_rate=1
        )

        from ouroboros import payjoin as _payjoin
        from fastapi import HTTPException

        def fake_send(*a, **kw):
            return _payjoin.SenderResponse(
                error=_payjoin.err_original_psbt_rejected("malformed")
            )

        original_send = _payjoin.send_payjoin_request
        _payjoin.send_payjoin_request = fake_send  # type: ignore
        try:
            with pytest.raises(HTTPException) as exc:
                await rpc.rpc_sendpayjoinrequest(
                    endpoint_url="http://x.invalid/payjoin",
                    psbt=original_result["psbt"],
                )
            assert exc.value.status_code == 400
        finally:
            _payjoin.send_payjoin_request = original_send  # type: ignore

    @pytest.mark.asyncio
    async def test_rpc_rejects_invalid_psbt_input(self, rpc_with_wallet):
        rpc, _sender, _wallet = rpc_with_wallet
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await rpc.rpc_sendpayjoinrequest(
                endpoint_url="http://x.invalid/payjoin",
                psbt="not-valid-base64-PSBT",
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_rpc_validates_proposal_before_broadcast(self, rpc_with_wallet):
        """A receiver returning a UIH-2-leaking proposal MUST be rejected by
        the RPC before broadcast."""
        rpc, sender, _wallet = rpc_with_wallet
        receiver = _make_key(b"rpc-send-rcv-3")
        addr = receiver.get_p2wpkh_address()
        original_result = await rpc.rpc_getpayjoinrequest(
            addr, 0.0005, fee_rate=1
        )
        original_psbt = PSBT.from_base64(original_result["psbt"])

        # Forge a "proposal" that adds an input but doesn't change outputs
        # (canonical UIH-2 leak).
        from ouroboros.psbt import PSBTInput

        proposal = PSBT.from_base64(original_result["psbt"])
        proposal.tx.inputs.append(
            TxIn(prev_txid=bytes(32), prev_vout=1, script_sig=b"", sequence=0xFFFFFFFD)
        )
        new_in = PSBTInput()
        new_in.witness_utxo = (40_000, _p2wpkh_script(receiver))
        proposal.inputs.append(new_in)

        from ouroboros import payjoin as _payjoin
        from fastapi import HTTPException

        def fake_send(*a, **kw):
            return _payjoin.SenderResponse(psbt=proposal)

        original_send = _payjoin.send_payjoin_request
        _payjoin.send_payjoin_request = fake_send  # type: ignore
        try:
            with pytest.raises(HTTPException) as exc:
                await rpc.rpc_sendpayjoinrequest(
                    endpoint_url="http://x.invalid/payjoin",
                    psbt=original_result["psbt"],
                    broadcast=True,
                )
            assert exc.value.status_code == 400
            assert "anti-snoop" in exc.value.detail.lower()
        finally:
            _payjoin.send_payjoin_request = original_send  # type: ignore


# ---------------------------------------------------------------------------
# G20 CSPRNG identity preservation across FIX-66
# ---------------------------------------------------------------------------


class TestG20CSPRNGIdentityPreservation:
    """FIX-65 pinned ``payjoin._CSPRNG IS wallet._CSPRNG``.  FIX-66 adds
    sender code but MUST NOT bring its own RNG — anything that draws
    randomness in the sender path is non-cryptographic (or goes through
    the same _CSPRNG)."""

    def test_payjoin_csprng_identity_with_wallet_preserved(self):
        from ouroboros import wallet as ob_wallet

        # Identity check from FIX-65 — preserved through FIX-66.
        assert payjoin._CSPRNG is ob_wallet._CSPRNG
        assert payjoin._CSPRNG is _CSPRNG

    def test_no_bare_random_in_payjoin_after_fix66(self):
        src = inspect.getsource(payjoin)
        assert "\nimport random" not in src
        assert " random.shuffle(" not in src
        assert " random.random(" not in src
        assert " random.choice(" not in src

    def test_wallet_csprng_literal_still_present(self):
        from ouroboros import wallet as ob_wallet

        src = inspect.getsource(ob_wallet)
        assert "_CSPRNG = secrets.SystemRandom()" in src

    def test_select_contribution_utxo_csprng_call_chain(self):
        """Defensive: spot-check that the receiver UTXO picker still draws
        from the wallet's CSPRNG (FIX-60 forward-pin)."""
        from ouroboros.wallet import _CSPRNG as wallet_csprng

        assert payjoin._CSPRNG is wallet_csprng
        pool = [
            {"txid": "00" * 32, "vout": i, "value": 1000 + i, "script_pubkey": b""}
            for i in range(5)
        ]
        pick = payjoin.select_contribution_utxo(pool)
        assert pick in pool


# ---------------------------------------------------------------------------
# Sender response parser — exposed shape
# ---------------------------------------------------------------------------


class TestSenderResponseParsing:
    def test_parse_known_error_code(self):
        body = '{"errorCode": "version-unsupported", "message": "v=2"}'
        resp = payjoin._parse_receiver_response_body(
            status_code=400,
            body_text=body,
            content_type="application/json",
        )
        assert resp.error is not None
        assert resp.error.code == payjoin.ERR_VERSION_UNSUPPORTED
        assert not resp.is_transient

    def test_parse_unknown_error_code_is_treated_as_unavailable(self):
        body = '{"errorCode": "unrecognized", "message": "??"}'
        resp = payjoin._parse_receiver_response_body(
            status_code=500,
            body_text=body,
            content_type="application/json",
        )
        assert resp.error is not None
        assert resp.error.code == payjoin.ERR_UNAVAILABLE
        assert resp.is_transient

    def test_parse_non_json_error_body_is_unavailable(self):
        resp = payjoin._parse_receiver_response_body(
            status_code=502,
            body_text="<html>Bad Gateway</html>",
            content_type="text/html",
        )
        assert resp.is_transient

    def test_parse_200_with_bad_body_is_transient(self):
        """If the receiver claims 200 but the body is gibberish, treat as
        transient so the sender can fall back rather than dropping funds."""
        resp = payjoin._parse_receiver_response_body(
            status_code=200,
            body_text="not-a-psbt",
            content_type="text/plain",
        )
        assert resp.is_transient
