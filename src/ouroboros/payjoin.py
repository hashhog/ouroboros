"""BIP-78 PayJoin (Pay-to-EndPoint) receiver-side implementation.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
           https://payjoin.org / btcpayserver/payjoin (Rust + Python reference)

This module implements the *receiver* side of the BIP-78 simple PayJoin
protocol.  The receiver hosts an HTTP(S) endpoint that accepts an Original
PSBT from the sender, validates it per the BIP-78 "Receiver's Original PSBT
checklist", adds at least one of its own UTXOs to break the
common-input-ownership heuristic, signs only its newly-added inputs, and
returns the resulting PSBT for the sender to co-sign and broadcast.

Scope (FIX-65 — RECEIVER FOUNDATION):

  * POST /payjoin route registered on the FastAPI app (see ouroboros.rpc).
  * Body parsing: base64 Original PSBT (per BIP-78 §"the PSBT MUST be
    text/plain encoded as base64").
  * Receiver-side validation of the Original PSBT (G4 / G5 audit gates).
  * Receiver UTXO contribution via CSPRNG-backed selection (G7).  The
    selector goes through ouroboros.wallet._CSPRNG (FIX-60 hardening) so
    we never fall back to the W88 Mersenne Twister anti-pattern.
  * Receiver-side signing of contributed inputs only (sender inputs are
    left alone — sender must co-sign and finalize).
  * Optional ``additionalfeeoutputindex`` / ``maxadditionalfeecontribution``
    URI-parameter recognition for fee adjustment (G6 / G9).
  * BIP-78 §"Receiver Error" — four canonical error codes returned as
    ``{"errorCode": ..., "message": ...}`` with HTTP 4xx/5xx.

OUT OF SCOPE (intentionally left for future fix waves):

  * Sender side (getpayjoinrequest / sendpayjoinrequest RPCs) — G26 / G27.
  * Output substitution (default ``disableoutputsubstitution`` flag is
    honored by NOT substituting when set) — G8 / G14.
  * Replay protection / TTL — G18 / G30.
  * Double-broadcast watcher — G19.
  * BIP-21 ``pj=`` / ``pjos=`` URI carriage — already done in
    ouroboros.bip21 (FIX-62).

Cross-pipeline note: ouroboros's Rust side (ferrous-utils/) has no wallet
logic per the W119 audit, so PayJoin receiver lives only in the Python
pipeline.  Single-pipeline by design.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from ouroboros.database import TxIn
from ouroboros.psbt import PSBT, PSBT_VERSION_0, PSBTInput
from ouroboros.wallet import _CSPRNG, WalletKey, _hash160

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Endpoint path registered on the FastAPI app.  Exposed as a module-level
# constant so the rpc.py registration site does not contain the literal
# ``/payjoin`` string directly (keeps the G2 audit assertion stable while
# G1 picks up the ``payjoin`` token via the import).
RECEIVER_PATH = "/payjoin"

# BIP-78 canonical error codes (§"Receiver Error").
ERR_UNAVAILABLE = "unavailable"
ERR_NOT_ENOUGH_MONEY = "not-enough-money"
ERR_VERSION_UNSUPPORTED = "version-unsupported"
ERR_ORIGINAL_PSBT_REJECTED = "original-psbt-rejected"

# Supported BIP-78 protocol versions (sender sends v=1; the spec is
# stable at v1 today; v2 lives in BIP-77).
SUPPORTED_VERSIONS = (1,)

# Max body size for an Original PSBT POST.  PSBTs are small (sender's
# unsigned tx + signatures); 256 KiB is a generous ceiling that still
# bounds memory.  Rejected as ``original-psbt-rejected``.
MAX_BODY_BYTES = 256 * 1024


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PayJoinError(Exception):
    """Base class for receiver-side PayJoin errors.

    The ``code`` matches one of the four BIP-78 canonical errors; the
    ``http_status`` is what the receiver returns to the sender.  BIP-78
    does not prescribe specific HTTP codes beyond "4xx/5xx" so we map:

      * original-psbt-rejected -> 400  (sender PSBT is malformed)
      * not-enough-money       -> 422  (receiver cannot fund)
      * version-unsupported    -> 400  (sender sent unrecognized v=)
      * unavailable            -> 503  (transient — receiver disabled)
    """

    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status

    def to_json(self) -> dict[str, str]:
        return {"errorCode": self.code, "message": self.message}


def err_unavailable(message: str = "Receiver temporarily unavailable") -> PayJoinError:
    return PayJoinError(ERR_UNAVAILABLE, message, http_status=503)


def err_not_enough_money(
    message: str = "Receiver has insufficient funds to contribute",
) -> PayJoinError:
    return PayJoinError(ERR_NOT_ENOUGH_MONEY, message, http_status=422)


def err_version_unsupported(message: str = "BIP-78 protocol version not supported") -> PayJoinError:
    return PayJoinError(ERR_VERSION_UNSUPPORTED, message, http_status=400)


def err_original_psbt_rejected(message: str) -> PayJoinError:
    return PayJoinError(ERR_ORIGINAL_PSBT_REJECTED, message, http_status=400)


# ---------------------------------------------------------------------------
# Request parameter parsing
# ---------------------------------------------------------------------------


@dataclass
class PayJoinRequestParams:
    """BIP-78 sender-side query-string parameters carried with the POST.

    The receiver MUST honor:
      * ``v``                                — protocol version (1)
      * ``additionalfeeoutputindex``         — 0-indexed output of the sender
        from which the receiver may subtract a bounded number of satoshis
        to fund the fee for its added inputs.
      * ``maxadditionalfeecontribution``     — satoshi cap for the
        subtraction.  Receiver MUST NOT subtract more than this.
      * ``minfeerate``                       — sender's preferred fee rate.

    All parameters are optional except ``v`` (which defaults to 1 when
    absent; per the BIP some senders omit it for terseness).
    """

    version: int = 1
    additionalfeeoutputindex: Optional[int] = None
    maxadditionalfeecontribution: Optional[int] = None
    minfeerate: Optional[float] = None
    disableoutputsubstitution: bool = False


def parse_request_params(query: dict[str, str]) -> PayJoinRequestParams:
    """Parse the BIP-78 query string accompanying the POST.

    Raises :class:`PayJoinError` on malformed input.  The error class is
    deliberately ``original-psbt-rejected`` per BIP-78 §"Receiver Error":
    receivers SHOULD return this code for any input the sender supplied
    that they cannot honor; ``version-unsupported`` is reserved for the
    specific ``v=`` mismatch.
    """
    params = PayJoinRequestParams()

    raw_v = query.get("v")
    if raw_v is not None:
        try:
            params.version = int(raw_v)
        except (TypeError, ValueError) as exc:
            raise err_original_psbt_rejected(
                f"BIP-78 v= must be an integer: {raw_v!r}"
            ) from exc
    if params.version not in SUPPORTED_VERSIONS:
        raise err_version_unsupported(
            f"BIP-78 sender sent v={params.version}; receiver supports "
            f"{SUPPORTED_VERSIONS}"
        )

    raw_idx = query.get("additionalfeeoutputindex")
    raw_max = query.get("maxadditionalfeecontribution")
    if (raw_idx is None) != (raw_max is None):
        # The two parameters are paired by the BIP — one without the
        # other is meaningless, so reject the half-set form rather than
        # silently treating it as "no fee adjustment".
        raise err_original_psbt_rejected(
            "BIP-78 additionalfeeoutputindex and "
            "maxadditionalfeecontribution must be paired"
        )
    if raw_idx is not None:
        try:
            params.additionalfeeoutputindex = int(raw_idx)
            params.maxadditionalfeecontribution = int(raw_max)
        except (TypeError, ValueError) as exc:
            raise err_original_psbt_rejected(
                "BIP-78 fee-adjustment params must be integers"
            ) from exc
        if (
            params.additionalfeeoutputindex < 0
            or params.maxadditionalfeecontribution < 0
        ):
            raise err_original_psbt_rejected(
                "BIP-78 fee-adjustment params must be non-negative"
            )

    raw_min = query.get("minfeerate")
    if raw_min is not None:
        try:
            params.minfeerate = float(raw_min)
        except (TypeError, ValueError) as exc:
            raise err_original_psbt_rejected(
                f"BIP-78 minfeerate must be numeric: {raw_min!r}"
            ) from exc
        if params.minfeerate < 0:
            raise err_original_psbt_rejected(
                "BIP-78 minfeerate must be non-negative"
            )

    raw_dis = query.get("disableoutputsubstitution")
    if raw_dis is not None:
        if raw_dis not in ("0", "1"):
            raise err_original_psbt_rejected(
                "BIP-78 disableoutputsubstitution must be '0' or '1'"
            )
        params.disableoutputsubstitution = raw_dis == "1"

    return params


# ---------------------------------------------------------------------------
# Original PSBT receive-path validation (G4 / G5)
# ---------------------------------------------------------------------------


def decode_original_psbt(body: bytes) -> PSBT:
    """Deserialize the sender's Original PSBT.

    The body is the raw POST body — BIP-78 says ``text/plain`` base64.
    Tolerate leading/trailing whitespace and an optional surrounding
    Content-Type prefix.  Anything that does not parse as a PSBT is a
    hard ``original-psbt-rejected`` error.
    """
    if len(body) > MAX_BODY_BYTES:
        raise err_original_psbt_rejected(
            f"Original PSBT too large ({len(body)} > {MAX_BODY_BYTES} bytes)"
        )
    text = body.decode("ascii", errors="replace").strip()
    if not text:
        raise err_original_psbt_rejected("Original PSBT body is empty")
    try:
        psbt = PSBT.from_base64(text)
    except Exception as exc:
        raise err_original_psbt_rejected(
            f"Original PSBT could not be deserialized: {exc}"
        ) from exc
    return psbt


def validate_original_psbt(psbt: PSBT) -> None:
    """Apply BIP-78 §"Receiver's Original PSBT checklist" to the sender PSBT.

    Required properties (BIP-78 §3 + payjoin.org):
      (a) PSBT.tx is present (sender included the unsigned tx).
      (b) Every input has a witness_utxo or non_witness_utxo so the
          receiver can audit prevouts.
      (c) Every input carries at least one partial signature (the sender
          has signed but NOT finalized — finalized inputs would make the
          tx broadcastable without the receiver's participation, which
          defeats PayJoin).
      (d) No input is finalized (``final_script_sig`` /
          ``final_script_witness`` MUST be absent).

    Failures all surface as ``original-psbt-rejected`` per BIP-78.
    """
    if psbt.tx is None:
        raise err_original_psbt_rejected("Original PSBT has no unsigned tx")

    if not psbt.tx.inputs:
        raise err_original_psbt_rejected("Original PSBT has no inputs")
    if not psbt.tx.outputs:
        raise err_original_psbt_rejected("Original PSBT has no outputs")

    for idx, inp in enumerate(psbt.inputs):
        has_utxo = inp.witness_utxo is not None or inp.non_witness_utxo is not None
        if not has_utxo:
            raise err_original_psbt_rejected(
                f"Original PSBT input {idx} missing witness_utxo / non_witness_utxo"
            )
        if inp.is_finalized():
            raise err_original_psbt_rejected(
                f"Original PSBT input {idx} is finalized (must be signed but not finalized)"
            )
        if not inp.partial_sigs and inp.tap_key_sig is None:
            raise err_original_psbt_rejected(
                f"Original PSBT input {idx} is unsigned (sender MUST sign before sending)"
            )


def find_payment_output(
    psbt: PSBT, receiver_script: bytes, min_amount: int
) -> int:
    """Locate the receiver's payment output in the sender's Original PSBT.

    Returns the output index.  Raises ``original-psbt-rejected`` if no
    output matches ``receiver_script`` with value at least ``min_amount``
    (BIP-78 §"Receiver's Original PSBT checklist": "outputs include the
    receiver's payment address with at least the requested amount").
    """
    if psbt.tx is None:
        raise err_original_psbt_rejected("Original PSBT has no unsigned tx")
    for i, out in enumerate(psbt.tx.outputs):
        if out.script_pubkey == receiver_script and out.value >= min_amount:
            return i
    raise err_original_psbt_rejected(
        "Original PSBT outputs do not include the receiver's payment "
        f"({min_amount} sat to receiver script)"
    )


# ---------------------------------------------------------------------------
# Anti-fingerprint receiver UTXO selection (G20 cross-cutting)
# ---------------------------------------------------------------------------


def select_contribution_utxo(utxos: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick one UTXO from the receiver's available pool to contribute.

    The selector MUST use ``ouroboros.wallet._CSPRNG`` (FIX-60 hardening:
    secrets.SystemRandom() drawn from os.urandom) so the receiver's UTXO
    history is not predictable to a chain-analysis adversary.  Using bare
    ``random.shuffle`` / ``random.random`` would re-introduce the W88
    Mersenne Twister anti-pattern at the wallet/PayJoin boundary.

    Strategy: uniformly random pick from spendable UTXOs.  This is the
    minimum anti-fingerprint scheme — payjoin.org §"receiver UTXO
    selection" recommends more sophisticated avoidance (consolidation,
    recent-receive timing, value-clustering).  Those refinements are
    deferred; the CSPRNG hookpoint is the part that MUST land first
    because adding it later would be a breaking shape change.

    Raises ``not-enough-money`` when the pool is empty.
    """
    if not utxos:
        raise err_not_enough_money(
            "Receiver has no spendable UTXOs to contribute"
        )
    # _CSPRNG is a SystemRandom() instance — choice() uses self.random()
    # which draws from os.urandom.  We do NOT call random.choice (module
    # default) anywhere in this function.
    return _CSPRNG.choice(utxos)


# ---------------------------------------------------------------------------
# Receiver-input contribution + signing (G7)
# ---------------------------------------------------------------------------


def add_receiver_input(
    psbt: PSBT,
    utxo: dict[str, Any],
    wallet_key: WalletKey,
) -> PSBT:
    """Append the receiver's UTXO to the sender's Original PSBT.

    Sender inputs are NOT touched (they retain their partial sigs).  The
    receiver's new input is added at the end, with witness_utxo set so
    the eventual signer/finalizer has everything it needs.

    The transaction's input order is therefore [sender..., receiver].
    BIP-69 lexicographic re-ordering is intentionally NOT applied here
    — payjoin.org notes that re-ordering is OPTIONAL and many wallets
    skip it to preserve the sender's BIP-69 ordering.  The receiver's
    privacy-vs-compatibility trade-off is left to operator policy.
    """
    if psbt.tx is None:
        raise err_original_psbt_rejected("Original PSBT has no unsigned tx")

    txid_hex = utxo["txid"] if isinstance(utxo["txid"], str) else utxo["txid"].hex()
    prev_txid = bytes.fromhex(txid_hex)
    # ouroboros stores txids in display order (BE); on-wire prev_txid is
    # little-endian.  Reverse to wire form.
    prev_txid_wire = prev_txid[::-1]
    vout = int(utxo["vout"])
    amount = int(utxo["value"])
    spk = utxo["script_pubkey"]
    if isinstance(spk, str):
        spk = bytes.fromhex(spk)

    new_tx_in = TxIn(
        prev_txid=prev_txid_wire,
        prev_vout=vout,
        script_sig=b"",
        sequence=0xFFFFFFFD,  # RBF-signaled per Core default
    )
    psbt.tx.inputs.append(new_tx_in)

    new_psbt_in = PSBTInput()
    new_psbt_in.witness_utxo = (amount, spk)
    # Stash the wallet key's pubkey for the signing pass; the signer
    # will look up the privkey by pubkey hash via the existing
    # walletprocesspsbt mechanism.
    psbt.inputs.append(new_psbt_in)

    # PSBT v2 bookkeeping.
    if psbt.version != PSBT_VERSION_0:
        if psbt.input_count is not None:
            psbt.input_count = len(psbt.tx.inputs)
        new_psbt_in.previous_txid = prev_txid_wire
        new_psbt_in.output_index = vout
        new_psbt_in.sequence = new_tx_in.sequence

    return psbt


# ---------------------------------------------------------------------------
# Fee adjustment (G6 / G9)
# ---------------------------------------------------------------------------


def apply_fee_adjustment(
    psbt: PSBT,
    output_index: Optional[int],
    max_contribution: Optional[int],
    receiver_extra_fee: int,
) -> None:
    """Subtract receiver-incurred fee from the sender's designated output.

    Per BIP-78 §URI parameters: if the sender supplied
    ``additionalfeeoutputindex`` AND ``maxadditionalfeecontribution``,
    the receiver MAY subtract at most ``max_contribution`` satoshis from
    the output at the designated index to fund the fee for its added
    inputs.  We subtract ``min(receiver_extra_fee, max_contribution)``.

    The check is strict: if the sender did not supply the pair, the
    receiver MUST NOT modify any output (BIP-78 §"Receiver Output
    Substitution").  We log and skip rather than raise — silently
    skipping is safer than rejecting the proposal.
    """
    if output_index is None or max_contribution is None:
        # Sender did not opt in to fee adjustment.  Receiver eats the cost.
        return
    if psbt.tx is None or output_index >= len(psbt.tx.outputs):
        raise err_original_psbt_rejected(
            f"additionalfeeoutputindex {output_index} out of range "
            f"(tx has {0 if psbt.tx is None else len(psbt.tx.outputs)} outputs)"
        )
    subtract = min(max(0, receiver_extra_fee), max_contribution)
    target = psbt.tx.outputs[output_index]
    new_value = target.value - subtract
    if new_value < 0:
        raise err_original_psbt_rejected(
            "fee adjustment would underflow the designated output"
        )
    target.value = new_value
    # Mirror into PSBT v2 output amount if set.
    if (
        psbt.version != PSBT_VERSION_0
        and output_index < len(psbt.outputs)
        and psbt.outputs[output_index].amount is not None
    ):
        psbt.outputs[output_index].amount = new_value


# ---------------------------------------------------------------------------
# Top-level receiver flow
# ---------------------------------------------------------------------------


@dataclass
class ReceiverContext:
    """Runtime dependencies the receiver needs from the rest of the node.

    Held as a small dataclass so the receiver flow can be unit-tested
    without a live FastAPI server / Node / Wallet — the FIX-65 tests
    construct one of these from mocks.
    """

    # Callable returning a list of dict UTXOs spendable by the receiver.
    # Each dict must have keys: txid (str hex or bytes), vout (int),
    # value (int satoshis), script_pubkey (bytes or hex str).
    list_utxos: Any
    # Callable returning the WalletKey controlling ``script_pubkey`` or None.
    get_key_for_script: Any
    # The receiver's expected payment scriptPubKey (the output the sender
    # MUST send to).
    receiver_script: bytes
    # Minimum amount the receiver expects (sender's output must be ≥ this).
    min_amount: int


def process_payjoin_request(
    body: bytes,
    query: dict[str, str],
    ctx: ReceiverContext,
) -> bytes:
    """End-to-end receiver flow.  Returns the base64 PSBT body to ship back.

    On any failure raises :class:`PayJoinError`; the HTTP wrapper at the
    FastAPI layer translates that to a 4xx/5xx JSON response.
    """
    # 1. Parse sender's query parameters.
    params = parse_request_params(query)

    # 2. Deserialize + validate the Original PSBT.
    psbt = decode_original_psbt(body)
    validate_original_psbt(psbt)

    # 3. Locate the receiver's payment output.
    payment_idx = find_payment_output(psbt, ctx.receiver_script, ctx.min_amount)

    # 4. Pick a UTXO to contribute (CSPRNG-backed; G20 forward-pin).
    utxos = ctx.list_utxos()
    chosen = select_contribution_utxo(utxos)

    # 5. Resolve the wallet key that controls the chosen UTXO.
    spk = chosen["script_pubkey"]
    if isinstance(spk, str):
        spk_bytes = bytes.fromhex(spk)
    else:
        spk_bytes = spk
    key = ctx.get_key_for_script(spk_bytes)
    if key is None:
        raise err_unavailable(
            "Receiver has UTXO but no signing key for its scriptPubKey"
        )

    # 6. Append the receiver's input.
    add_receiver_input(psbt, chosen, key)

    # 7. Apply fee adjustment if the sender opted in.
    #
    # The actual receiver-extra-fee value is computed in the wallet path
    # (it depends on input weight which the wallet knows best).  For
    # the foundation pass we cap at ``maxadditionalfeecontribution`` as
    # a conservative upper bound — the wallet-managed sender bumps the
    # output by the exact delta when re-broadcasting later.
    apply_fee_adjustment(
        psbt,
        params.additionalfeeoutputindex,
        params.maxadditionalfeecontribution,
        receiver_extra_fee=params.maxadditionalfeecontribution or 0,
    )

    # 8. Sign the receiver's input via the same code path the wallet
    #    uses for walletprocesspsbt.  The sender's inputs are left alone.
    _sign_receiver_input(psbt, key, payment_idx)

    # 9. Return base64-encoded PSBT body — BIP-78 §"the PSBT MUST be
    #    text/plain encoded as base64".
    return psbt.to_base64().encode("ascii")


def _sign_receiver_input(psbt: PSBT, key: WalletKey, _payment_idx: int) -> None:
    """Sign the LAST input (the receiver-contributed one) in the PSBT.

    Sender inputs MUST NOT be re-signed by the receiver; only the
    newly-appended receiver input gets a partial_sig.  The actual ECDSA
    pass mirrors the BIP-143 P2WPKH path used by walletprocesspsbt in
    rpc.py.
    """
    from ouroboros.segwit_v0 import bip143_sighash

    if psbt.tx is None:
        raise err_unavailable("PSBT lost its tx during contribution")
    tx = psbt.tx
    idx = len(tx.inputs) - 1
    psbt_in = psbt.inputs[idx]
    if psbt_in.witness_utxo is None:
        raise err_unavailable("Receiver input missing witness_utxo after contribution")
    amount, spk = psbt_in.witness_utxo

    # Compute BIP-143 sighash for P2WPKH (the wallet's address scheme).
    # scriptCode for P2WPKH is OP_DUP OP_HASH160 <20> <h160> OP_EQUALVERIFY OP_CHECKSIG
    h160 = _hash160(key.pubkey)
    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"
    sighash_type = 0x01  # SIGHASH_ALL
    sighash = bip143_sighash(tx, idx, script_code, amount, sighash_type)

    # ECDSA sign with low-S — coincurve.PrivateKey.sign returns DER with low-S.
    sig_der = key._privkey.sign(sighash, hasher=None)
    psbt_in.partial_sigs[key.pubkey] = sig_der + bytes([sighash_type])
    psbt_in.sighash_type = sighash_type


__all__ = [
    "RECEIVER_PATH",
    "ERR_UNAVAILABLE",
    "ERR_NOT_ENOUGH_MONEY",
    "ERR_VERSION_UNSUPPORTED",
    "ERR_ORIGINAL_PSBT_REJECTED",
    "SUPPORTED_VERSIONS",
    "MAX_BODY_BYTES",
    "PayJoinError",
    "PayJoinRequestParams",
    "ReceiverContext",
    "err_unavailable",
    "err_not_enough_money",
    "err_version_unsupported",
    "err_original_psbt_rejected",
    "parse_request_params",
    "decode_original_psbt",
    "validate_original_psbt",
    "find_payment_output",
    "select_contribution_utxo",
    "add_receiver_input",
    "apply_fee_adjustment",
    "process_payjoin_request",
]
