"""FIX-65 — BIP-78 PayJoin receiver foundation.

W119 audit closed the receiver-side gates for ouroboros.  This suite
exercises the new :mod:`ouroboros.payjoin` module and its FastAPI wiring
in :mod:`ouroboros.rpc`:

  * **Round-trip** — sender builds an Original PSBT, POSTs to the
    receiver endpoint, receiver appends a CSPRNG-selected UTXO, signs
    only the new input, returns the modified PSBT.  We verify shape:
    the returned PSBT has +1 input, the sender's inputs are untouched
    (their partial sigs survive), and the receiver's input has a fresh
    partial signature.

  * **Four BIP-78 canonical errors** — the receiver emits each of
    ``unavailable``, ``not-enough-money``, ``version-unsupported``,
    ``original-psbt-rejected`` as the
    ``{"errorCode": ..., "message": ...}`` JSON wrapper with the
    corresponding HTTP 4xx/5xx status.

  * **G20 CSPRNG regression guard** — receiver UTXO selection MUST
    still go through ``ouroboros.wallet._CSPRNG = secrets.SystemRandom()``
    (FIX-60).  No bare ``random.shuffle`` / ``random.random`` may
    creep into the wallet module.  This guards against re-introduction
    of the W88 Mersenne Twister anti-pattern at the wallet/PayJoin
    boundary.

Specs:
  BIP-78  https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
  BIP-174 https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

import hashlib
import inspect
import struct

import pytest
from fastapi.testclient import TestClient

from ouroboros import payjoin
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import (
    PSBT,
    PSBTInput,
    PSBT_VERSION_0,
    payjoin_decode_original_psbt,
    validate_original_psbt_for_receiver,
    add_receiver_input_to_psbt,
)
from ouroboros.rpc import RPCServer
from ouroboros.wallet import WalletKey, _CSPRNG, _hash160


# ---------------------------------------------------------------------------
# Test helpers — fixed-seed key + UTXO factory
# ---------------------------------------------------------------------------


def _make_key(seed: bytes) -> WalletKey:
    """Deterministic-from-seed key for predictable test vectors."""
    return WalletKey(hashlib.sha256(seed).digest(), network="regtest")


def _p2wpkh_script(key: WalletKey) -> bytes:
    """OP_0 <20> <pubkey_hash>."""
    return b"\x00\x14" + _hash160(key.pubkey)


def _build_unsigned_original_tx(
    sender_key: WalletKey,
    receiver_script: bytes,
    *,
    sender_amount: int = 100_000,
    pay_amount: int = 60_000,
    change_amount: int = 30_000,
) -> tuple[Transaction, bytes, int]:
    """Construct a sender-only unsigned tx + matching prev-tx for the input.

    Returns ``(tx, prev_tx_value_at_vout=sender_amount, sender_change_vout)``.
    The single sender input spends ``prev_tx[0]`` worth ``sender_amount``;
    outputs are [payment_to_receiver, sender_change].
    """
    # Fake prev-tx output that the sender's input references.
    fake_prev_txid = bytes(32)  # all zeros — fine for a test PSBT.

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
    return tx, sender_amount, 1


def _build_original_psbt(
    sender_key: WalletKey,
    receiver_script: bytes,
    *,
    sender_amount: int = 100_000,
    pay_amount: int = 60_000,
    change_amount: int = 30_000,
    finalized: bool = False,
    sign_input: bool = True,
) -> PSBT:
    """Build a sender Original PSBT that satisfies BIP-78 §3 checklist."""
    tx, sender_amount, _ = _build_unsigned_original_tx(
        sender_key,
        receiver_script,
        sender_amount=sender_amount,
        pay_amount=pay_amount,
        change_amount=change_amount,
    )
    psbt = PSBT.from_transaction(tx, version=PSBT_VERSION_0)
    inp = psbt.inputs[0]
    inp.witness_utxo = (sender_amount, _p2wpkh_script(sender_key))

    if sign_input:
        # Fake but well-shaped partial sig — BIP-78 only requires that the
        # input "is signed".  We do not need the sig to verify; the
        # receiver-side validator only checks for *presence*.  A 71-byte
        # DER-shaped sig (sequence(70)+two-30b-ints+sighash flag) is what
        # a real signer would emit; here we generate one via the key so
        # the partial_sig is plausibly shaped.
        h = hashlib.sha256(b"sender-sighash").digest()
        sig_der = sender_key._privkey.sign(h, hasher=None)
        inp.partial_sigs[sender_key.pubkey] = sig_der + bytes([0x01])

    if finalized:
        inp.final_script_witness = [
            inp.partial_sigs[sender_key.pubkey],
            sender_key.pubkey,
        ]
        inp.partial_sigs.clear()

    return psbt


def _make_receiver_ctx(
    receiver_key: WalletKey,
    *,
    utxos_value: list[int] | None = None,
    min_amount: int = 0,
) -> payjoin.ReceiverContext:
    """Build a :class:`payjoin.ReceiverContext` from in-memory data."""
    if utxos_value is None:
        utxos_value = [50_000]
    spk = _p2wpkh_script(receiver_key)
    utxos = [
        {
            "txid": bytes([i + 1] * 32).hex(),  # display order
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
# Round-trip — direct ouroboros.payjoin.process_payjoin_request call
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Sender PSBT goes in, receiver-modified PSBT comes out with +1 input
    and an untouched sender side."""

    def test_round_trip_adds_one_receiver_input(self):
        sender = _make_key(b"sender-1")
        receiver = _make_key(b"receiver-1")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        body_in = original.to_base64().encode("ascii")

        ctx = _make_receiver_ctx(receiver, utxos_value=[40_000])
        body_out = payjoin.process_payjoin_request(body_in, query={}, ctx=ctx)

        assert isinstance(body_out, bytes)
        proposal = PSBT.from_base64(body_out.decode("ascii"))
        assert proposal.tx is not None
        # +1 input vs sender's tx.
        assert len(proposal.tx.inputs) == 2, (
            f"expected +1 receiver input; got {len(proposal.tx.inputs)} total"
        )
        # +1 PSBTInput too.
        assert len(proposal.inputs) == 2

    def test_round_trip_preserves_sender_partial_sig(self):
        """The receiver MUST NOT touch the sender's inputs.  Sender's
        partial_sig survives unchanged into the proposal."""
        sender = _make_key(b"sender-2")
        receiver = _make_key(b"receiver-2")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        # Snapshot the sender's partial sig.
        sender_sig = original.inputs[0].partial_sigs[sender.pubkey]
        body_in = original.to_base64().encode("ascii")

        ctx = _make_receiver_ctx(receiver)
        body_out = payjoin.process_payjoin_request(body_in, query={}, ctx=ctx)
        proposal = PSBT.from_base64(body_out.decode("ascii"))

        assert proposal.inputs[0].partial_sigs[sender.pubkey] == sender_sig
        # And sender's witness_utxo is preserved.
        assert proposal.inputs[0].witness_utxo == original.inputs[0].witness_utxo

    def test_round_trip_receiver_input_is_signed(self):
        """The receiver-contributed input gets a fresh partial signature."""
        sender = _make_key(b"sender-3")
        receiver = _make_key(b"receiver-3")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        ctx = _make_receiver_ctx(receiver)
        body_out = payjoin.process_payjoin_request(
            original.to_base64().encode("ascii"),
            query={},
            ctx=ctx,
        )
        proposal = PSBT.from_base64(body_out.decode("ascii"))

        receiver_psbt_in = proposal.inputs[-1]
        # New input is signed by the receiver's pubkey.
        assert receiver.pubkey in receiver_psbt_in.partial_sigs, (
            "receiver MUST sign the input it contributed"
        )
        sig = receiver_psbt_in.partial_sigs[receiver.pubkey]
        assert len(sig) >= 9  # DER sig + sighash byte
        # SIGHASH_ALL trailer.
        assert sig[-1] == 0x01
        # witness_utxo set so the eventual finalizer has everything.
        assert receiver_psbt_in.witness_utxo is not None

    def test_round_trip_with_fee_adjustment(self):
        """If sender opts in to fee adjustment, receiver subtracts up to
        ``maxadditionalfeecontribution`` from the designated output."""
        sender = _make_key(b"sender-4")
        receiver = _make_key(b"receiver-4")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script, change_amount=30_000)
        original_change = original.tx.outputs[1].value  # sender change output
        body_in = original.to_base64().encode("ascii")

        # Sender designates output 1 (change) for fee deduction, cap 500 sat.
        query = {
            "additionalfeeoutputindex": "1",
            "maxadditionalfeecontribution": "500",
        }
        ctx = _make_receiver_ctx(receiver)
        body_out = payjoin.process_payjoin_request(body_in, query=query, ctx=ctx)
        proposal = PSBT.from_base64(body_out.decode("ascii"))

        # Receiver subtracts exactly maxadditionalfeecontribution (=500).
        # Payment output unchanged.
        assert proposal.tx.outputs[0].value == original.tx.outputs[0].value
        # Change reduced by the cap.
        assert proposal.tx.outputs[1].value == original_change - 500


# ---------------------------------------------------------------------------
# 4 BIP-78 canonical error paths
# ---------------------------------------------------------------------------


class TestErrorOriginalPsbtRejected:
    """``original-psbt-rejected`` is the catch-all for any malformed input
    from the sender (BIP-78 §"Receiver Error")."""

    def test_malformed_base64_body(self):
        receiver = _make_key(b"receiver-err-1")
        ctx = _make_receiver_ctx(receiver)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=b"not-a-psbt-!!!@@@",
                query={},
                ctx=ctx,
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED
        assert exc.value.http_status == 400

    def test_unsigned_sender_input(self):
        """BIP-78 receiver checklist: every input MUST be signed (but not
        finalized) before the sender POSTs."""
        sender = _make_key(b"sender-err-2")
        receiver = _make_key(b"receiver-err-2")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(
            sender, recv_script, sign_input=False,
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=_make_receiver_ctx(receiver),
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_finalized_sender_input(self):
        """A finalized input would make the tx broadcastable without the
        receiver — that defeats the PayJoin protocol."""
        sender = _make_key(b"sender-err-3")
        receiver = _make_key(b"receiver-err-3")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(
            sender, recv_script, finalized=True,
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=_make_receiver_ctx(receiver),
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_no_payment_output(self):
        """If the sender's outputs don't include the receiver's script with
        sufficient amount, reject."""
        sender = _make_key(b"sender-err-4")
        receiver = _make_key(b"receiver-err-4")
        recv_script = _p2wpkh_script(receiver)

        # Set min_amount higher than what the sender pays.
        original = _build_original_psbt(
            sender, recv_script, pay_amount=10_000,
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=_make_receiver_ctx(receiver, min_amount=50_000),
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_missing_witness_utxo(self):
        """BIP-78 §3 checklist (b): every input has a witness_utxo or
        non_witness_utxo."""
        sender = _make_key(b"sender-err-5")
        receiver = _make_key(b"receiver-err-5")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        original.inputs[0].witness_utxo = None  # blank out the UTXO field
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=_make_receiver_ctx(receiver),
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


class TestErrorVersionUnsupported:
    """``version-unsupported`` is reserved for the specific ``v=`` mismatch
    (BIP-78 §"Receiver Error")."""

    def test_unsupported_version(self):
        sender = _make_key(b"sender-v")
        receiver = _make_key(b"receiver-v")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={"v": "2"},  # BIP-77, not supported
                ctx=_make_receiver_ctx(receiver),
            )
        assert exc.value.code == payjoin.ERR_VERSION_UNSUPPORTED
        assert exc.value.http_status == 400

    def test_supported_version_default(self):
        """Omitting v= MUST be treated as v=1 (the only supported version)."""
        sender = _make_key(b"sender-vok")
        receiver = _make_key(b"receiver-vok")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        body_out = payjoin.process_payjoin_request(
            body=original.to_base64().encode("ascii"),
            query={},  # no v= at all
            ctx=_make_receiver_ctx(receiver),
        )
        assert isinstance(body_out, bytes)


class TestErrorNotEnoughMoney:
    """``not-enough-money`` is emitted when the receiver has no UTXOs to
    contribute (BIP-78 §"Receiver Error")."""

    def test_receiver_pool_empty(self):
        sender = _make_key(b"sender-nem")
        receiver = _make_key(b"receiver-nem")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)
        # ctx with NO UTXOs available.
        ctx = _make_receiver_ctx(receiver, utxos_value=[])
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=ctx,
            )
        assert exc.value.code == payjoin.ERR_NOT_ENOUGH_MONEY
        assert exc.value.http_status == 422


class TestErrorUnavailable:
    """``unavailable`` covers transient receiver issues — typically that the
    receiver is misconfigured (no key for the chosen UTXO) or hit an
    internal error."""

    def test_no_signing_key_for_selected_utxo(self):
        sender = _make_key(b"sender-unav")
        receiver = _make_key(b"receiver-unav")
        recv_script = _p2wpkh_script(receiver)

        original = _build_original_psbt(sender, recv_script)

        # Build a ctx whose UTXO has a scriptPubKey the get_key_for_script
        # function can't resolve — simulates a misconfigured wallet.
        bogus_spk = b"\x00\x14" + b"\xff" * 20
        utxo = {
            "txid": "00" * 32,
            "vout": 0,
            "value": 30_000,
            "script_pubkey": bogus_spk,
        }

        def list_utxos():
            return [utxo]

        def get_key_for_script(_s):
            return None  # always misses

        ctx = payjoin.ReceiverContext(
            list_utxos=list_utxos,
            get_key_for_script=get_key_for_script,
            receiver_script=recv_script,
            min_amount=0,
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.process_payjoin_request(
                body=original.to_base64().encode("ascii"),
                query={},
                ctx=ctx,
            )
        assert exc.value.code == payjoin.ERR_UNAVAILABLE
        assert exc.value.http_status == 503

    def test_error_json_wrapper_shape(self):
        """All four error codes serialize to {"errorCode": ..., "message": ...}."""
        for ctor, expected_code in (
            (payjoin.err_unavailable, payjoin.ERR_UNAVAILABLE),
            (payjoin.err_not_enough_money, payjoin.ERR_NOT_ENOUGH_MONEY),
            (payjoin.err_version_unsupported, payjoin.ERR_VERSION_UNSUPPORTED),
            (lambda: payjoin.err_original_psbt_rejected("X"),
             payjoin.ERR_ORIGINAL_PSBT_REJECTED),
        ):
            err = ctor()
            j = err.to_json()
            assert set(j.keys()) == {"errorCode", "message"}
            assert j["errorCode"] == expected_code
            assert isinstance(j["message"], str)


# ---------------------------------------------------------------------------
# FastAPI integration — POST /payjoin route lands and returns expected JSON
# on error / base64 PSBT on success.
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
    """Minimal Wallet stand-in for the route-level test.  Provides the
    `keys` list and `_collect_utxos()` the receiver path consults."""

    def __init__(self, key: WalletKey, utxos: list[dict]) -> None:
        self.keys = [
            {"wif": key.to_wif(), "label": "test", "created": 0}
        ]
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


@pytest.fixture
def route_test_client():
    """Return a TestClient bound to an RPCServer with PayJoin wired."""
    receiver = _make_key(b"route-receiver")
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
    client = TestClient(rpc.get_app())
    yield client, receiver, recv_script


def test_route_returns_modified_psbt_on_success(route_test_client):
    """POST /payjoin returns text/plain base64 PSBT on the happy path."""
    client, receiver, recv_script = route_test_client
    sender = _make_key(b"route-sender")
    original = _build_original_psbt(sender, recv_script)
    body = original.to_base64()

    response = client.post(
        "/payjoin",
        content=body,
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 200, response.text
    assert "text/plain" in response.headers.get("content-type", "")
    proposal = PSBT.from_base64(response.text)
    assert proposal.tx is not None
    assert len(proposal.tx.inputs) == 2  # sender + receiver


def test_route_returns_version_unsupported_json(route_test_client):
    client, receiver, recv_script = route_test_client
    sender = _make_key(b"route-sender-vu")
    original = _build_original_psbt(sender, recv_script)
    body = original.to_base64()

    response = client.post(
        "/payjoin?v=2",
        content=body,
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 400
    body_json = response.json()
    assert body_json["errorCode"] == payjoin.ERR_VERSION_UNSUPPORTED
    assert "message" in body_json


def test_route_returns_original_psbt_rejected_json(route_test_client):
    client, _receiver, _recv_script = route_test_client
    response = client.post(
        "/payjoin",
        content=b"not-base64-PSBT",
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 400
    body_json = response.json()
    assert body_json["errorCode"] == payjoin.ERR_ORIGINAL_PSBT_REJECTED


def test_route_returns_unavailable_when_no_wallet():
    """Server with no wallet returns ``unavailable`` per BIP-78."""
    node = _MockNode(wallet=None)
    rpc = RPCServer(node, port=0)
    client = TestClient(rpc.get_app())

    sender = _make_key(b"no-wallet-sender")
    receiver = _make_key(b"no-wallet-receiver")
    recv_script = _p2wpkh_script(receiver)
    original = _build_original_psbt(sender, recv_script)

    response = client.post(
        "/payjoin",
        content=original.to_base64(),
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 503
    body_json = response.json()
    assert body_json["errorCode"] == payjoin.ERR_UNAVAILABLE


# ---------------------------------------------------------------------------
# G20 CSPRNG regression guard — FIX-60 hardening MUST survive FIX-65
# ---------------------------------------------------------------------------


class TestG20CSPRNGRegressionGuard:
    """Cross-cutting: the receiver-side UTXO selector MUST use the
    secrets.SystemRandom() instance the wallet exposes (FIX-60).
    A bare ``random.shuffle`` or ``random.random()`` would re-introduce
    the W88 Mersenne Twister anti-pattern at the wallet/PayJoin
    boundary (W119 audit G20)."""

    def test_wallet_csprng_instance_still_present(self):
        """FIX-60's ``_CSPRNG = secrets.SystemRandom()`` literal MUST
        still appear in the wallet module source."""
        from ouroboros import wallet as ob_wallet

        src = inspect.getsource(ob_wallet)
        assert "_CSPRNG = secrets.SystemRandom()" in src, (
            "FIX-60 CSPRNG instantiation lost — receiver selector "
            "would inherit Mersenne Twister"
        )

    def test_no_bare_random_mutators_in_wallet(self):
        """No ``random.shuffle`` / ``random.random()`` in wallet — all
        randomness must go through ``_CSPRNG``."""
        from ouroboros import wallet as ob_wallet

        src = inspect.getsource(ob_wallet)
        assert "random.shuffle" not in src, (
            "G20 regression: bare random.shuffle re-appeared in wallet.py"
        )
        assert "random.random()" not in src, (
            "G20 regression: bare random.random() re-appeared in wallet.py"
        )

    def test_csprng_imported_into_payjoin(self):
        """The PayJoin module MUST import _CSPRNG from wallet — that's the
        single source of cryptographic randomness for receiver selection."""
        src = inspect.getsource(payjoin)
        assert "_CSPRNG" in src, (
            "ouroboros.payjoin does not import _CSPRNG; receiver UTXO "
            "selection would fall back to module-level random"
        )
        # The selector MUST be the wallet's instance, not a fresh one.
        assert "from ouroboros.wallet import" in src
        assert "_CSPRNG" in src

    def test_no_bare_random_calls_in_payjoin(self):
        """The PayJoin module MUST NOT call random.shuffle / random.choice
        / random.random — all randomness routes through _CSPRNG."""
        src = inspect.getsource(payjoin)
        # We allow `_CSPRNG.choice(...)`, `_CSPRNG.shuffle(...)` etc; we
        # forbid the module-level builtins.
        assert "\nimport random" not in src
        assert " random.shuffle(" not in src
        assert " random.random(" not in src
        assert " random.choice(" not in src

    def test_select_contribution_utxo_uses_csprng(self):
        """Direct API check: select_contribution_utxo returns a UTXO,
        and the call chain goes through the CSPRNG instance."""
        from ouroboros.wallet import _CSPRNG as wallet_csprng

        # Identity: payjoin's _CSPRNG IS wallet's _CSPRNG.
        assert payjoin._CSPRNG is wallet_csprng

        pool = [
            {"txid": "00" * 32, "vout": i, "value": 1000 + i, "script_pubkey": b""}
            for i in range(10)
        ]
        # Should always return one of the pool entries (CSPRNG never raises).
        pick = payjoin.select_contribution_utxo(pool)
        assert pick in pool

    def test_select_contribution_utxo_raises_not_enough_money_on_empty(self):
        """Empty pool → not-enough-money (BIP-78 §Receiver Error)."""
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.select_contribution_utxo([])
        assert exc.value.code == payjoin.ERR_NOT_ENOUGH_MONEY


# ---------------------------------------------------------------------------
# Forwarder smoke tests — ouroboros.psbt re-exports work
# ---------------------------------------------------------------------------


class TestPsbtForwarders:
    """The G4/G5/G7 audit closures are thin forwarders in
    :mod:`ouroboros.psbt`; verify they actually call into payjoin."""

    def test_psbt_payjoin_decode_forwards(self):
        sender = _make_key(b"forward-1")
        receiver = _make_key(b"forward-1r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        body = original.to_base64().encode("ascii")
        round_trip = payjoin_decode_original_psbt(body)
        assert round_trip.tx is not None
        assert len(round_trip.tx.outputs) == 2

    def test_psbt_validate_for_receiver_forwards(self):
        sender = _make_key(b"forward-2")
        receiver = _make_key(b"forward-2r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        # Should not raise on a well-formed signed-not-finalized PSBT.
        validate_original_psbt_for_receiver(original)

    def test_psbt_add_receiver_input_forwards(self):
        sender = _make_key(b"forward-3")
        receiver = _make_key(b"forward-3r")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        utxo = {
            "txid": "ab" * 32,
            "vout": 0,
            "value": 30_000,
            "script_pubkey": _p2wpkh_script(receiver),
        }
        out = add_receiver_input_to_psbt(original, utxo, receiver)
        assert len(out.tx.inputs) == 2
        assert out.inputs[1].witness_utxo == (30_000, _p2wpkh_script(receiver))
