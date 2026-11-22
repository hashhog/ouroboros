"""cffix-ouroboros-payjoin-credit-receiver -- the BIP-78 receiver must not
sign its coin into a transaction that pays it to someone else.

Before this fix ``process_payjoin_request`` appended a wallet UTXO and
signed it SIGHASH_ALL over the sender's outputs without (a) adding the
contributed value to the receiver's own payment output, (b) checking the
Original balances, or (c) testing that the Original is broadcastable.  An
unauthenticated ``POST /payjoin`` could therefore post an Original that
spends 50,000 sat into outputs [receiver: 546, attacker: 139,000]; the
receiver's 100,000-sat coin makes the transaction balance, and the
signed proposal pays it to the attacker.

BIP-78 receiver rules exercised here:
  * the receiver adds its input's value to its own output;
  * the Original must be broadcastable (testmempoolaccept) before signing;
  * the receiver never signs outputs that reduce its own payment.

Core has no PayJoin, so there is no Core behaviour to mirror.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ouroboros import payjoin
from ouroboros.database import Transaction, TxIn, TxOut
from ouroboros.psbt import PSBT
from ouroboros.rpc import RPCServer

try:
    # Collected as part of the ``tests`` package (tests/__init__.py).
    from tests.test_fix65_payjoin_receiver import (
        _MockDB,
        _MockMempool,
        _MockWallet,
        _build_original_psbt,
        _make_key,
        _make_receiver_ctx,
        _p2wpkh_script,
    )
except ImportError:  # pragma: no cover - direct-file invocation fallback
    from test_fix65_payjoin_receiver import (
        _MockDB,
        _MockMempool,
        _MockWallet,
        _build_original_psbt,
        _make_key,
        _make_receiver_ctx,
        _p2wpkh_script,
    )


RECEIVER_UTXO = 100_000


def _receiver_output_value(proposal: PSBT, recv_script: bytes) -> int:
    vals = [o.value for o in proposal.tx.outputs if o.script_pubkey == recv_script]
    assert len(vals) == 1
    return vals[0]


def _theft_original(sender, recv_script, attacker_script, *, claimed_in=50_000):
    """Original spending ``claimed_in`` sat into [receiver 546, attacker 139,000]."""
    psbt = _build_original_psbt(
        sender, recv_script,
        sender_amount=claimed_in, pay_amount=546, change_amount=139_000,
    )
    psbt.tx.outputs[1].script_pubkey = attacker_script
    return psbt


def _run(original, ctx, query=None):
    return payjoin.process_payjoin_request(
        original.to_base64().encode("ascii"), query=query or {}, ctx=ctx,
    )


class TestReceiverCredit:
    def test_theft_original_is_rejected_or_receiver_credited(self):
        """The item's repro: master returns a signed PSBT paying the
        receiver 546 sat for its 100,000-sat coin."""
        sender = _make_key(b"cf-pj-sender-1")
        receiver = _make_key(b"cf-pj-receiver-1")
        attacker = _make_key(b"cf-pj-attacker-1")
        recv_script = _p2wpkh_script(receiver)
        original = _theft_original(sender, recv_script, _p2wpkh_script(attacker))
        ctx = _make_receiver_ctx(receiver, utxos_value=[RECEIVER_UTXO])
        try:
            body = _run(original, ctx)
        except payjoin.PayJoinError as exc:
            assert exc.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED
            return
        proposal = PSBT.from_base64(body.decode("ascii"))
        assert _receiver_output_value(proposal, recv_script) >= 546 + RECEIVER_UTXO

    def test_unbalanced_original_rejected(self):
        sender = _make_key(b"cf-pj-sender-2")
        receiver = _make_key(b"cf-pj-receiver-2")
        original = _theft_original(
            sender, _p2wpkh_script(receiver), _p2wpkh_script(sender)
        )
        with pytest.raises(payjoin.PayJoinError) as exc:
            _run(original, _make_receiver_ctx(receiver, utxos_value=[RECEIVER_UTXO]))
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_lying_witness_utxo_still_credits_receiver(self):
        """A sender can overstate its witness_utxo so the Original appears
        to balance.  The receiver's output must still grow by the full
        contribution, so any transaction that verifies pays the receiver."""
        sender = _make_key(b"cf-pj-sender-3")
        receiver = _make_key(b"cf-pj-receiver-3")
        recv_script = _p2wpkh_script(receiver)
        original = _theft_original(
            sender, recv_script, _p2wpkh_script(sender), claimed_in=140_000,
        )
        body = _run(original, _make_receiver_ctx(receiver, utxos_value=[RECEIVER_UTXO]))
        proposal = PSBT.from_base64(body.decode("ascii"))
        assert _receiver_output_value(proposal, recv_script) == 546 + RECEIVER_UTXO

    def test_honest_original_credits_contribution(self):
        sender = _make_key(b"cf-pj-sender-4")
        receiver = _make_key(b"cf-pj-receiver-4")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)  # 100k -> 60k + 30k
        body = _run(original, _make_receiver_ctx(receiver, utxos_value=[40_000]))
        proposal = PSBT.from_base64(body.decode("ascii"))
        assert proposal.tx.outputs[0].value == 60_000 + 40_000
        # Sender change untouched without a fee-adjustment opt-in.
        assert proposal.tx.outputs[1].value == 30_000
        # Proposal balances: inputs 140k, outputs 130k, fee unchanged at 10k.
        assert sum(o.value for o in proposal.tx.outputs) == 130_000

    def test_credit_is_what_the_receiver_signed(self):
        """The SIGHASH_ALL signature must commit to the credited output:
        re-signing the returned tx reproduces the returned signature's
        sighash preimage only if outputs were credited before signing."""
        from ouroboros.segwit_v0 import bip143_sighash
        from ouroboros.wallet import _hash160
        from coincurve import PublicKey

        sender = _make_key(b"cf-pj-sender-5")
        receiver = _make_key(b"cf-pj-receiver-5")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        body = _run(original, _make_receiver_ctx(receiver, utxos_value=[40_000]))
        proposal = PSBT.from_base64(body.decode("ascii"))
        sig = proposal.inputs[-1].partial_sigs[receiver.pubkey]
        script_code = b"\x76\xa9\x14" + _hash160(receiver.pubkey) + b"\x88\xac"
        sighash = bip143_sighash(
            proposal.tx, len(proposal.tx.inputs) - 1, script_code, 40_000, 0x01
        )
        assert PublicKey(receiver.pubkey).verify(sig[:-1], sighash, hasher=None)
        assert proposal.tx.outputs[0].value == 100_000

    def test_fee_output_index_on_receiver_output_refused(self):
        """additionalfeeoutputindex naming the receiver's own output would
        let the sender's chosen cap claw the credit back."""
        sender = _make_key(b"cf-pj-sender-6")
        receiver = _make_key(b"cf-pj-receiver-6")
        recv_script = _p2wpkh_script(receiver)
        original = _build_original_psbt(sender, recv_script)
        query = {"additionalfeeoutputindex": "0",
                 "maxadditionalfeecontribution": "40000"}
        with pytest.raises(payjoin.PayJoinError) as exc:
            _run(original, _make_receiver_ctx(receiver, utxos_value=[40_000]), query)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


class TestOriginalAmounts:
    def test_negative_output_rejected(self):
        sender = _make_key(b"cf-pj-sender-7")
        receiver = _make_key(b"cf-pj-receiver-7")
        original = _build_original_psbt(sender, _p2wpkh_script(receiver))
        original.tx.outputs[1].value = -50_000
        with pytest.raises(payjoin.PayJoinError) as exc:
            _run(original, _make_receiver_ctx(receiver))
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED

    def test_non_witness_utxo_for_wrong_tx_rejected(self):
        """A non_witness_utxo must be the transaction the prevout names,
        else its (large) output value would be trusted for the balance."""
        from ouroboros.psbt import _serialize_tx_with_witness

        sender = _make_key(b"cf-pj-sender-8")
        receiver = _make_key(b"cf-pj-receiver-8")
        original = _build_original_psbt(
            sender, _p2wpkh_script(receiver),
            sender_amount=50_000, pay_amount=546, change_amount=139_000,
        )
        unrelated = Transaction(
            txid=bytes(32), version=2, locktime=0,
            inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=10_000_000, script_pubkey=_p2wpkh_script(sender))],
            has_witness=False,
        )
        original.inputs[0].witness_utxo = None
        original.inputs[0].non_witness_utxo = _serialize_tx_with_witness(unrelated)
        with pytest.raises(payjoin.PayJoinError) as exc:
            _run(original, _make_receiver_ctx(receiver, utxos_value=[RECEIVER_UTXO]))
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED


class TestBroadcastableHook:
    def test_hook_rejection_refuses_before_signing(self):
        sender = _make_key(b"cf-pj-sender-9")
        receiver = _make_key(b"cf-pj-receiver-9")
        original = _build_original_psbt(sender, _p2wpkh_script(receiver))
        ctx = _make_receiver_ctx(receiver)
        seen = []

        def reject(psbt):
            seen.append(len(psbt.tx.inputs))
            return "bad-txns-inputs-missingorspent"

        # Set after construction so the file imports and runs on a tree
        # whose ReceiverContext predates the field.
        ctx.check_broadcastable = reject
        with pytest.raises(payjoin.PayJoinError) as exc:
            _run(original, ctx)
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED
        assert seen == [1]  # tested the Original, before the receiver input


class _NoTestAcceptMempool(_MockMempool):
    """A mempool with no ``accept_to_memory_pool`` (node mid-init)."""

    def __getattribute__(self, name):
        if name == "accept_to_memory_pool":
            raise AttributeError(name)
        return super().__getattribute__(name)


class _AcceptMempool(_MockMempool):
    def __init__(self, accepted: bool) -> None:
        self.accepted = accepted
        self.calls = 0

    def accept_to_memory_pool(self, tx, height, test_accept=False):
        assert test_accept is True
        self.calls += 1
        if self.accepted:
            return {"accepted": True, "fee": 0, "vsize": 0}
        return {"accepted": False, "reject_reason": "missing-inputs"}


class _Node:
    def __init__(self, wallet, receive_script, mempool) -> None:
        self.db = _MockDB()
        self.network = "regtest"
        self.mempool = mempool
        self.wallet = wallet
        self.payjoin_receive_script = receive_script
        self.payjoin_min_amount = 0


def _route(mempool, seed):
    payjoin.original_psbt_ttl.clear()
    payjoin.payjoin_replay.clear()
    receiver = _make_key(seed)
    recv_script = _p2wpkh_script(receiver)
    utxo = {"txid": "cd" * 32, "vout": 0, "value": 40_000,
            "script_pubkey": recv_script}
    node = _Node(_MockWallet(receiver, [utxo]), recv_script, mempool)
    return TestClient(RPCServer(node, port=0).get_app()), recv_script


class TestRouteTestAccept:
    def test_route_refuses_original_the_mempool_rejects(self):
        mp = _AcceptMempool(accepted=False)
        client, recv_script = _route(mp, b"cf-pj-route-1")
        original = _build_original_psbt(_make_key(b"cf-pj-route-s1"), recv_script)
        r = client.post("/payjoin", content=original.to_base64(),
                        headers={"Content-Type": "text/plain"})
        assert r.status_code == 400, r.text
        assert r.json()["errorCode"] == payjoin.ERR_ORIGINAL_PSBT_REJECTED
        assert mp.calls == 1

    def test_route_unavailable_without_mempool_test_accept(self):
        client, recv_script = _route(_NoTestAcceptMempool(), b"cf-pj-route-2")
        original = _build_original_psbt(_make_key(b"cf-pj-route-s2"), recv_script)
        r = client.post("/payjoin", content=original.to_base64(),
                        headers={"Content-Type": "text/plain"})
        assert r.json().get("errorCode") == payjoin.ERR_UNAVAILABLE, r.text

    def test_route_credits_receiver_when_mempool_accepts(self):
        mp = _AcceptMempool(accepted=True)
        client, recv_script = _route(mp, b"cf-pj-route-3")
        original = _build_original_psbt(_make_key(b"cf-pj-route-s3"), recv_script)
        r = client.post("/payjoin", content=original.to_base64(),
                        headers={"Content-Type": "text/plain"})
        assert r.status_code == 200, r.text
        proposal = PSBT.from_base64(r.text)
        assert _receiver_output_value(proposal, recv_script) == 60_000 + 40_000
        assert mp.calls == 1


class TestSenderAcceptsReceiverCredit:
    """Our sender's G13 check must accept the receiver crediting its own
    output (BIP-78), or it refuses every compliant receiver -- including
    ours after this fix -- while still refusing any output that shrinks."""

    def _pair(self, seed, *, pay_out, change_out):
        sender = _make_key(seed + b"-s")
        recv_script = _p2wpkh_script(_make_key(seed + b"-r"))
        original = _build_original_psbt(sender, recv_script)  # 60k pay, 30k change
        proposal = _build_original_psbt(
            sender, recv_script, pay_amount=pay_out, change_amount=change_out,
        )
        return original, proposal

    def test_credit_accepted_without_fee_opt_in(self):
        original, proposal = self._pair(b"cf-g13-1", pay_out=100_000, change_out=30_000)
        payjoin.validate_max_fee_contribution(
            original, proposal,
            additionalfeeoutputindex=None, maxadditionalfeecontribution=None,
        )

    def test_credit_accepted_with_fee_opt_in(self):
        original, proposal = self._pair(b"cf-g13-2", pay_out=100_000, change_out=29_500)
        payjoin.validate_max_fee_contribution(
            original, proposal,
            additionalfeeoutputindex=1, maxadditionalfeecontribution=500,
        )

    def test_shrunk_non_designated_output_still_rejected(self):
        original, proposal = self._pair(b"cf-g13-3", pay_out=59_000, change_out=29_500)
        with pytest.raises(payjoin.PayJoinError) as exc:
            payjoin.validate_max_fee_contribution(
                original, proposal,
                additionalfeeoutputindex=1, maxadditionalfeecontribution=500,
            )
        assert exc.value.code == payjoin.ERR_ORIGINAL_PSBT_REJECTED
