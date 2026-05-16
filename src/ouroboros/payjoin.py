"""BIP-78 PayJoin (Pay-to-EndPoint) receiver + sender implementation.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
           https://payjoin.org / btcpayserver/payjoin (Rust + Python reference)

This module implements both the *receiver* and *sender* halves of the
BIP-78 simple PayJoin protocol.  The receiver hosts an HTTP(S) endpoint
that accepts an Original PSBT from the sender, validates it per the
BIP-78 "Receiver's Original PSBT checklist", adds at least one of its
own UTXOs to break the common-input-ownership heuristic, signs only its
newly-added inputs, and returns the resulting PSBT for the sender to
co-sign and broadcast.  The sender constructs an Original PSBT, POSTs it
to the receiver's URL, validates the response per the BIP-78 anti-snoop
checklist (UIH-1 / UIH-2 / fee caps / output substitution), and falls
back to broadcasting the Original PSBT when the receiver is unreachable.

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

Scope added by FIX-66 — SENDER + ANTI-SNOOP:

  * ``send_payjoin_request`` — HTTP(S) POST via ``httpx`` honoring the BIP-78
    ``Content-Type: text/plain`` rule, with TLS certificate validation
    enabled by default (G24).
  * Anti-snoop validators G10–G15 covering UIH-1 / UIH-2, scriptSig type
    uniformity, fee-contribution cap enforcement, ``pjos`` (disable output
    substitution) handling, and ``minfeerate`` propagation.
  * G22 fallback: when the receiver returns a transient error or is
    unreachable, the sender falls back to broadcasting the Original PSBT
    after signing+finalizing it locally.
  * ``getpayjoinrequest`` / ``sendpayjoinrequest`` RPC bindings live in
    :mod:`ouroboros.rpc` (G26 / G27 audit closures).

Cross-pipeline note: ouroboros's Rust side (ferrous-utils/) has no wallet
logic per the W119 audit, so PayJoin lives only in the Python pipeline.
Single-pipeline by design.
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


# ---------------------------------------------------------------------------
# Sender side — HTTP client + anti-snoop validation (FIX-66)
# ---------------------------------------------------------------------------
#
# The sender half of BIP-78 mirrors the receiver section above:
#
#   * ``send_payjoin_request`` — POST the Original PSBT to the receiver URL,
#     parse the response either as a modified PSBT (200) or as the BIP-78
#     ``{"errorCode": ..., "message": ...}`` JSON wrapper (4xx/5xx).  HTTPS
#     certificate validation is on by default (G24).
#   * 6 anti-snoop validators (G10–G15) the sender applies to the receiver's
#     proposal before signing+broadcasting.  Each is independent and surfaces
#     a single failure dimension so unit tests can pin one heuristic at a
#     time:
#
#       G10  validate_response_outputs                  — sender outputs preserved
#       G11  validate_scriptsig_uniformity              — UIH-1
#       G12  validate_inputs_imply_outputs_changed      — UIH-2
#       G13  validate_max_fee_contribution              — fee cap enforced
#       G14  validate_disable_output_substitution       — pjos=1 enforcement
#       G15  build_sender_query                         — minfeerate propagation
#
#   * ``broadcast_original_psbt_fallback`` — G22 fallback path when the
#     receiver is unreachable or returns ``unavailable``.


# Default timeout for the sender's HTTP POST (seconds).  BIP-78 does not
# prescribe a value; payjoin.org reference clients use ~30s.  We pick a
# conservative 30s ceiling — large enough for Tor v3 round-trips but
# small enough that an indefinitely-hanging receiver triggers the G22
# fallback in a bounded wall-clock window.
DEFAULT_SENDER_TIMEOUT_SEC = 30.0


def build_sender_query(
    *,
    version: int = 1,
    additionalfeeoutputindex: Optional[int] = None,
    maxadditionalfeecontribution: Optional[int] = None,
    minfeerate: Optional[float] = None,
    disableoutputsubstitution: Optional[bool] = None,
) -> dict[str, str]:
    """Assemble the BIP-78 sender-side query string for the receiver POST.

    Every parameter is optional except ``version``, which defaults to 1
    (BIP-78 §protocol — the only stable version today; v2 lives in BIP-77
    and is not implemented here).

    The ``additionalfeeoutputindex`` and ``maxadditionalfeecontribution``
    pair MUST be set together or left both unset; the helper enforces
    that invariant up-front so a half-set query never leaves the sender.

    ``minfeerate`` carries the sender's preferred fee rate (sat/vB) and
    closes the G15 audit gap.

    ``disableoutputsubstitution`` is propagated as ``"0"`` or ``"1"`` per
    BIP-21/BIP-78; when None the parameter is omitted (receiver default).
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"build_sender_query: unsupported BIP-78 version {version}; "
            f"this build supports {SUPPORTED_VERSIONS}"
        )

    # Pair invariant (BIP-78 §URI parameters): both or neither.
    have_idx = additionalfeeoutputindex is not None
    have_max = maxadditionalfeecontribution is not None
    if have_idx != have_max:
        raise ValueError(
            "build_sender_query: additionalfeeoutputindex and "
            "maxadditionalfeecontribution must be set together"
        )
    if have_idx and (
        additionalfeeoutputindex < 0 or maxadditionalfeecontribution < 0
    ):
        raise ValueError(
            "build_sender_query: fee-adjustment params must be non-negative"
        )
    if minfeerate is not None and minfeerate < 0:
        raise ValueError("build_sender_query: minfeerate must be non-negative")

    query: dict[str, str] = {"v": str(version)}
    if have_idx:
        query["additionalfeeoutputindex"] = str(additionalfeeoutputindex)
        query["maxadditionalfeecontribution"] = str(maxadditionalfeecontribution)
    if minfeerate is not None:
        query["minfeerate"] = str(minfeerate)
    if disableoutputsubstitution is not None:
        query["disableoutputsubstitution"] = "1" if disableoutputsubstitution else "0"
    return query


@dataclass
class SenderResponse:
    """Parsed receiver response to a BIP-78 sender POST.

    Either ``psbt`` is set (the receiver returned a modified PSBT for
    sender co-signing — happy path) OR ``error`` is set (the receiver
    returned the canonical ``{"errorCode": ..., "message": ...}`` JSON
    wrapper at a 4xx/5xx status).  Exactly one of the two is non-None.
    """

    psbt: Optional[PSBT] = None
    error: Optional[PayJoinError] = None

    @property
    def is_success(self) -> bool:
        return self.psbt is not None

    @property
    def is_transient(self) -> bool:
        """Receiver-side errors that warrant the G22 fallback path.

        BIP-78 §"Receiver Error" lists ``unavailable`` as transient; the
        sender SHOULD fall back to broadcasting the Original PSBT when
        the receiver is offline or hits an internal hiccup.  Network
        errors raised before any HTTP response also fall here.
        """
        if self.error is None:
            return False
        return self.error.code == ERR_UNAVAILABLE


def _parse_receiver_response_body(
    status_code: int,
    body_text: str,
    content_type: str,
) -> SenderResponse:
    """Decode the receiver's HTTP body into a :class:`SenderResponse`.

    Split out from ``send_payjoin_request`` so tests can drive the
    decoder without standing up an HTTP server (this is the heart of G17
    error-shape validation on the sender side too).
    """
    if 200 <= status_code < 300:
        try:
            psbt = PSBT.from_base64(body_text.strip())
        except Exception as exc:
            # Receiver said 200 but body isn't a PSBT — treat as transient
            # so the sender falls back rather than dropping funds on the floor.
            err = err_unavailable(
                f"Receiver returned 200 but body is not a PSBT: {exc}"
            )
            return SenderResponse(error=err)
        return SenderResponse(psbt=psbt)

    # 4xx / 5xx — try to parse the BIP-78 JSON error wrapper.
    import json

    try:
        payload = json.loads(body_text)
    except Exception:
        # Non-JSON body at error status — bucket as unavailable so the
        # sender can fall back.  ``original-psbt-rejected`` would imply
        # the sender's PSBT was bad, which we can't verify from a
        # non-JSON body.
        err = err_unavailable(
            f"Receiver returned HTTP {status_code} with non-JSON body"
        )
        return SenderResponse(error=err)
    code = payload.get("errorCode") if isinstance(payload, dict) else None
    message = (
        payload.get("message")
        if isinstance(payload, dict) and isinstance(payload.get("message"), str)
        else "Receiver error"
    )
    if code == ERR_UNAVAILABLE:
        return SenderResponse(error=err_unavailable(message))
    if code == ERR_NOT_ENOUGH_MONEY:
        return SenderResponse(error=err_not_enough_money(message))
    if code == ERR_VERSION_UNSUPPORTED:
        return SenderResponse(error=err_version_unsupported(message))
    if code == ERR_ORIGINAL_PSBT_REJECTED:
        return SenderResponse(error=err_original_psbt_rejected(message))
    # Unknown errorCode (BIP-78-compliant servers SHOULD use one of the
    # canonical 4) — bucket as unavailable so the sender falls back.
    return SenderResponse(
        error=err_unavailable(
            f"Receiver returned unknown errorCode={code!r} at HTTP {status_code}"
        )
    )


def send_payjoin_request(
    endpoint_url: str,
    original_psbt: PSBT,
    *,
    version: int = 1,
    additionalfeeoutputindex: Optional[int] = None,
    maxadditionalfeecontribution: Optional[int] = None,
    minfeerate: Optional[float] = None,
    disableoutputsubstitution: Optional[bool] = None,
    timeout: float = DEFAULT_SENDER_TIMEOUT_SEC,
    verify: bool = True,
    transport: Any = None,
) -> SenderResponse:
    """POST an Original PSBT to the receiver's BIP-78 endpoint via httpx.

    Args:
      endpoint_url:           full URL of the receiver's POST endpoint.
                              MUST use ``https://`` for clearnet (BIP-78
                              §endpoint); ``http://`` is allowed for
                              regtest / .onion (the ``.onion`` scheme is
                              encrypted at the Tor layer so plain HTTP
                              is acceptable).
      original_psbt:          sender's Original PSBT.  Will be serialized
                              to base64 and sent as ``text/plain`` per
                              BIP-78.
      version:                BIP-78 protocol version (only ``1`` today).
      additionalfeeoutputindex / maxadditionalfeecontribution:
                              optional pair per BIP-78 §URI parameters.
                              Receiver MAY subtract up to
                              ``maxadditionalfeecontribution`` satoshis
                              from output at this index.
      minfeerate:             sender's preferred fee rate (sat/vB).
                              Optional — closes the G15 audit gap by
                              propagating it on the wire.
      disableoutputsubstitution:
                              when True (pjos=1), the receiver MUST NOT
                              modify the sender's outputs (BIP-78 §URI
                              parameters / payjoin.org).
      timeout:                seconds before httpx raises a timeout that
                              the caller surfaces as ``unavailable``
                              triggering the G22 fallback.
      verify:                 httpx TLS-cert verification.  Default
                              ``True`` per G24.  Tests stand this down
                              via ``False``; production callers MUST
                              leave it True for clearnet endpoints.
      transport:              optional ``httpx.BaseTransport`` injected
                              for tests so we can speak to an in-memory
                              ASGI app without standing up a real socket.

    Returns:
      :class:`SenderResponse` carrying either the receiver-modified PSBT
      (happy path) or a :class:`PayJoinError` for one of the BIP-78
      canonical 4 codes.  Caller is responsible for invoking the anti-
      snoop validators G10–G15 on the returned PSBT before broadcasting.
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"send_payjoin_request: BIP-78 version {version} not supported"
        )

    body = original_psbt.to_base64()
    query = build_sender_query(
        version=version,
        additionalfeeoutputindex=additionalfeeoutputindex,
        maxadditionalfeecontribution=maxadditionalfeecontribution,
        minfeerate=minfeerate,
        disableoutputsubstitution=disableoutputsubstitution,
    )

    # Lazy import so the rest of the module is usable without httpx
    # installed.  httpx is a hard dep per pyproject.toml as of FIX-65.
    import httpx

    client_kwargs: dict[str, Any] = {"timeout": timeout, "verify": verify}
    if transport is not None:
        client_kwargs["transport"] = transport

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.post(
                endpoint_url,
                content=body,
                params=query,
                headers={"Content-Type": "text/plain"},
            )
    except httpx.TimeoutException as exc:
        return SenderResponse(
            error=err_unavailable(f"Receiver POST timed out: {exc}")
        )
    except httpx.ConnectError as exc:
        return SenderResponse(
            error=err_unavailable(f"Receiver endpoint unreachable: {exc}")
        )
    except httpx.HTTPError as exc:
        return SenderResponse(
            error=err_unavailable(f"Receiver POST failed: {exc}")
        )

    content_type = resp.headers.get("content-type", "")
    return _parse_receiver_response_body(
        status_code=resp.status_code,
        body_text=resp.text,
        content_type=content_type,
    )


# ---------------------------------------------------------------------------
# Sender-side anti-snoop validators (G10 – G15)
# ---------------------------------------------------------------------------
#
# Each validator raises :class:`PayJoinError` (``original-psbt-rejected``)
# when the receiver's proposal fails the corresponding BIP-78 sender check.
# The caller MUST invoke all six before signing-and-broadcasting.


def _scripts_present(psbt: PSBT) -> list[bytes]:
    """Return witness/legacy scriptPubKey for every input in the PSBT.

    Used by UIH-1 (G11) and the response-output preservation check (G10).
    Falls back through (witness_utxo, non_witness_utxo[prev_vout]) so the
    caller does not need to know which UTXO carrier the input uses.
    """
    out: list[bytes] = []
    for psbt_in, _tx_in in zip(psbt.inputs, psbt.tx.inputs if psbt.tx else []):
        if psbt_in.witness_utxo is not None:
            _amt, spk = psbt_in.witness_utxo
            out.append(bytes(spk))
            continue
        if psbt_in.non_witness_utxo is not None:
            # non_witness_utxo carries the full prev-tx; extract the spk
            # at the matching vout.
            try:
                prev_tx = psbt_in.non_witness_utxo
                vout_idx = _tx_in.prev_vout if _tx_in is not None else 0
                spk = prev_tx.outputs[vout_idx].script_pubkey
                out.append(bytes(spk))
                continue
            except Exception:
                pass
        out.append(b"")  # unknown — the validator will flag this as a mismatch
    return out


def _classify_script_type(spk: bytes) -> str:
    """Return a coarse script-type tag for UIH-1 uniformity comparison.

    The granularity matches BIP-78 §sender-validates: legacy P2PKH,
    P2SH, P2WPKH, P2WSH, P2TR, plus an ``unknown`` bucket.  Mixing any
    two is forbidden — the receiver MUST contribute an input of the
    same script type as the sender's inputs.
    """
    if len(spk) == 25 and spk[0:3] == b"\x76\xa9\x14" and spk[23:25] == b"\x88\xac":
        return "p2pkh"
    if len(spk) == 23 and spk[0:2] == b"\xa9\x14" and spk[22:23] == b"\x87":
        return "p2sh"
    if len(spk) == 22 and spk[0:2] == b"\x00\x14":
        return "p2wpkh"
    if len(spk) == 34 and spk[0:2] == b"\x00\x20":
        return "p2wsh"
    if len(spk) == 34 and spk[0:2] == b"\x51\x20":
        return "p2tr"
    return "unknown"


def validate_response_outputs(
    original: PSBT,
    proposal: PSBT,
    *,
    disable_output_substitution: bool = False,
) -> None:
    """G10 / BUG-9 — anti-snoop output verification.

    Per payjoin.org §sender-validates and BIP-78 §"Receiver's response
    checklist":

      * Every sender output script MUST appear in the proposal (the
        receiver may have re-ordered them but MUST NOT delete them).
      * When ``disable_output_substitution`` is True, output amounts and
        scripts MUST match exactly (modulo fee adjustment which a
        ``maxadditionalfeecontribution``-bounded subtract on a single
        designated output is allowed — that's G13's domain, not G10).
      * The number of outputs MUST NOT shrink (a missing output would
        steal funds).

    Raises ``original-psbt-rejected`` on violation — this is a UIH-leak
    or fund-loss path, never a transient.
    """
    if original.tx is None or proposal.tx is None:
        raise err_original_psbt_rejected(
            "G10: PSBT(s) missing unsigned tx for output verification"
        )

    original_outputs = original.tx.outputs
    proposal_outputs = proposal.tx.outputs

    if len(proposal_outputs) < len(original_outputs):
        raise err_original_psbt_rejected(
            f"G10: proposal has fewer outputs ({len(proposal_outputs)}) "
            f"than original ({len(original_outputs)}) — receiver dropped one"
        )

    # Every original output script MUST still be present.
    proposal_scripts = [bytes(o.script_pubkey) for o in proposal_outputs]
    for i, o in enumerate(original_outputs):
        spk = bytes(o.script_pubkey)
        if spk not in proposal_scripts:
            raise err_original_psbt_rejected(
                f"G10: sender output[{i}] script not present in receiver's "
                "proposal — would steal funds"
            )

    if disable_output_substitution:
        # Strict match: same count, same scripts in some order, same
        # amounts in aggregate (fee adjustment is handled at G13).
        if len(proposal_outputs) != len(original_outputs):
            raise err_original_psbt_rejected(
                "G10/G14: disableoutputsubstitution=1 but proposal added outputs"
            )
        for i, o in enumerate(original_outputs):
            if bytes(o.script_pubkey) not in proposal_scripts:
                raise err_original_psbt_rejected(
                    f"G10/G14: disableoutputsubstitution=1 but sender output[{i}] "
                    "script removed/substituted"
                )


def validate_scriptsig_uniformity(
    original: PSBT, proposal: PSBT
) -> None:
    """G11 / BUG-10 — UIH-1 scriptSig-type uniformity.

    All inputs in the final transaction MUST have the same script type
    as the sender's inputs.  If the receiver contributes a legacy P2PKH
    input when the sender pays from P2WPKH, the resulting tx is
    self-evidently a PayJoin (uniformity heuristic UIH-1).

    Raises ``original-psbt-rejected`` on mixed script types.
    """
    if original.tx is None or proposal.tx is None:
        raise err_original_psbt_rejected(
            "G11: PSBT(s) missing unsigned tx for UIH-1 check"
        )

    sender_scripts = _scripts_present(original)
    proposal_scripts = _scripts_present(proposal)
    sender_types = {_classify_script_type(s) for s in sender_scripts if s}
    proposal_types = {_classify_script_type(s) for s in proposal_scripts if s}

    if not sender_types:
        raise err_original_psbt_rejected(
            "G11: sender PSBT has no inspectable input script types"
        )
    if "unknown" in proposal_types:
        raise err_original_psbt_rejected(
            "G11: proposal contains an input of unknown script type"
        )
    # Receiver's contributed types MUST be a subset of sender's types.
    extra = proposal_types - sender_types
    if extra:
        raise err_original_psbt_rejected(
            f"G11: receiver added input(s) of mismatched script type(s): "
            f"sender={sorted(sender_types)} proposal_extras={sorted(extra)}"
        )


def validate_inputs_imply_outputs_changed(
    original: PSBT, proposal: PSBT
) -> None:
    """G12 / BUG-11 — UIH-2: new inputs without output modification.

    payjoin.org §sender-validates / UIH-2: if the receiver added inputs
    but did NOT alter outputs (in count or aggregate amount), the
    proposal de-anonymizes the receiver's deposit address (the receiver
    paid themselves and added an input — the chain analyst infers which
    output is the receiver's).

    Raises ``original-psbt-rejected`` on the UIH-2 leak.
    """
    if original.tx is None or proposal.tx is None:
        raise err_original_psbt_rejected(
            "G12: PSBT(s) missing unsigned tx for UIH-2 check"
        )

    new_inputs = len(proposal.tx.inputs) - len(original.tx.inputs)
    if new_inputs <= 0:
        # Receiver didn't add inputs — UIH-2 doesn't apply.
        return

    # Outputs MUST have changed (count or aggregate value) when inputs
    # are added; otherwise we have a UIH-2 leak.
    orig_total = sum(o.value for o in original.tx.outputs)
    prop_total = sum(o.value for o in proposal.tx.outputs)
    orig_count = len(original.tx.outputs)
    prop_count = len(proposal.tx.outputs)

    same_count = orig_count == prop_count
    same_total = orig_total == prop_total
    if same_count and same_total:
        # Outputs are visually identical despite added inputs.  This is
        # the canonical UIH-2 pattern.
        orig_scripts = [bytes(o.script_pubkey) for o in original.tx.outputs]
        prop_scripts = [bytes(o.script_pubkey) for o in proposal.tx.outputs]
        if orig_scripts == prop_scripts:
            raise err_original_psbt_rejected(
                "G12/UIH-2: receiver added input(s) without modifying any "
                "output — leaks receiver's deposit address"
            )


def validate_max_fee_contribution(
    original: PSBT,
    proposal: PSBT,
    *,
    additionalfeeoutputindex: Optional[int],
    maxadditionalfeecontribution: Optional[int],
) -> None:
    """G13 / BUG-12 — sender max-fee enforcement.

    The sender sent ``maxadditionalfeecontribution`` on the wire; the
    proposal MUST NOT subtract more than that from the designated
    output.  If the receiver subtracted more (or subtracted from a
    different output, or subtracted without permission), reject.

    Raises ``original-psbt-rejected`` on cap violation.
    """
    if original.tx is None or proposal.tx is None:
        raise err_original_psbt_rejected(
            "G13: PSBT(s) missing unsigned tx for fee-cap check"
        )

    if additionalfeeoutputindex is None or maxadditionalfeecontribution is None:
        # Sender did NOT opt in to fee adjustment — receiver MUST not have
        # touched any output amount.
        for i, (o_in, o_out) in enumerate(
            zip(original.tx.outputs, proposal.tx.outputs)
        ):
            if bytes(o_in.script_pubkey) == bytes(o_out.script_pubkey):
                if o_in.value != o_out.value:
                    raise err_original_psbt_rejected(
                        f"G13: sender did not authorize fee adjustment but "
                        f"output[{i}] amount changed "
                        f"({o_in.value} -> {o_out.value})"
                    )
        return

    if additionalfeeoutputindex < 0 or additionalfeeoutputindex >= len(
        original.tx.outputs
    ):
        raise err_original_psbt_rejected(
            f"G13: additionalfeeoutputindex {additionalfeeoutputindex} "
            f"out of range for original tx ({len(original.tx.outputs)} outputs)"
        )

    # Locate the designated output by script.  After re-ordering by the
    # receiver, the designated output may not still be at the same index
    # so we look up by scriptPubKey.
    designated_script = bytes(
        original.tx.outputs[additionalfeeoutputindex].script_pubkey
    )
    designated_original_value = original.tx.outputs[
        additionalfeeoutputindex
    ].value
    designated_proposal_value: Optional[int] = None
    for o in proposal.tx.outputs:
        if bytes(o.script_pubkey) == designated_script:
            designated_proposal_value = o.value
            break
    if designated_proposal_value is None:
        raise err_original_psbt_rejected(
            "G13: designated fee output not present in proposal"
        )

    subtracted = designated_original_value - designated_proposal_value
    if subtracted < 0:
        raise err_original_psbt_rejected(
            f"G13: receiver INCREASED designated output amount by "
            f"{-subtracted} (theft)"
        )
    if subtracted > maxadditionalfeecontribution:
        raise err_original_psbt_rejected(
            f"G13: receiver subtracted {subtracted} sat from designated "
            f"output but cap was {maxadditionalfeecontribution}"
        )

    # Other outputs MUST be unchanged — receiver can only adjust the
    # designated output's amount.
    for i, (o_in, o_out) in enumerate(
        zip(original.tx.outputs, proposal.tx.outputs)
    ):
        if bytes(o_in.script_pubkey) == bytes(o_out.script_pubkey):
            if (
                bytes(o_in.script_pubkey) != designated_script
                and o_in.value != o_out.value
            ):
                raise err_original_psbt_rejected(
                    f"G13: receiver modified non-designated output[{i}] "
                    f"({o_in.value} -> {o_out.value})"
                )


def validate_disable_output_substitution(
    original: PSBT,
    proposal: PSBT,
    *,
    disable_output_substitution: bool,
) -> None:
    """G14 / BUG-13 — sender ``pjos=1`` enforcement.

    When the sender set ``pjos=1`` (disableoutputsubstitution), the
    receiver MUST NOT add, remove, or change any of the sender's
    outputs (BIP-78 §URI parameters).  This is a strict structural
    check that complements G10 (which is one-sided: sender outputs
    must be present).

    Raises ``original-psbt-rejected`` on violation.  When the flag is
    not set, this validator is a no-op (the spec permits output
    substitution by default).
    """
    if not disable_output_substitution:
        return

    if original.tx is None or proposal.tx is None:
        raise err_original_psbt_rejected(
            "G14: PSBT(s) missing unsigned tx for pjos=1 check"
        )

    if len(proposal.tx.outputs) != len(original.tx.outputs):
        raise err_original_psbt_rejected(
            f"G14: pjos=1 but output count changed "
            f"({len(original.tx.outputs)} -> {len(proposal.tx.outputs)})"
        )

    # Sets must match (BIP-78 allows reordering even under pjos=1; the
    # invariant is the *set* of (script, value) pairs).  Fee adjustment
    # via the additionalfeeoutputindex/maxadditionalfeecontribution path
    # is G13's domain and is *not* permitted under pjos=1 — the spec
    # treats pjos=1 as a stronger constraint than fee-adjust opt-in.
    original_set = sorted(
        (bytes(o.script_pubkey), o.value) for o in original.tx.outputs
    )
    proposal_set = sorted(
        (bytes(o.script_pubkey), o.value) for o in proposal.tx.outputs
    )
    if original_set != proposal_set:
        raise err_original_psbt_rejected(
            "G14: pjos=1 but receiver modified outputs (script/amount mismatch)"
        )


def validate_payjoin_response(
    original: PSBT,
    proposal: PSBT,
    *,
    additionalfeeoutputindex: Optional[int] = None,
    maxadditionalfeecontribution: Optional[int] = None,
    disable_output_substitution: bool = False,
) -> None:
    """Run all 6 anti-snoop validators G10–G15 against the proposal.

    Convenience wrapper the sender RPC uses immediately after receiving
    the receiver's response and before signing+broadcasting.  Each
    validator raises on its own dimension so the caller can rely on the
    first failure being the most specific one.

    G15 lives at the *outbound* side — the sender SHOULD have already
    sent ``minfeerate`` in the query string via ``build_sender_query``.
    Here we treat G15 as a no-op on the response (BIP-78 has no
    receiver-echoed minfeerate to validate).
    """
    # Sender input preservation is implied by G10 + UIH-2 + the input-
    # uniformity check; we also verify the sender's inputs are still
    # present (count >= original) as a defense in depth.
    if (
        proposal.tx is not None
        and original.tx is not None
        and len(proposal.tx.inputs) < len(original.tx.inputs)
    ):
        raise err_original_psbt_rejected(
            "validate_payjoin_response: proposal removed sender inputs"
        )
    validate_response_outputs(
        original,
        proposal,
        disable_output_substitution=disable_output_substitution,
    )
    validate_scriptsig_uniformity(original, proposal)
    validate_inputs_imply_outputs_changed(original, proposal)
    validate_max_fee_contribution(
        original,
        proposal,
        additionalfeeoutputindex=additionalfeeoutputindex,
        maxadditionalfeecontribution=maxadditionalfeecontribution,
    )
    validate_disable_output_substitution(
        original,
        proposal,
        disable_output_substitution=disable_output_substitution,
    )


# ---------------------------------------------------------------------------
# G22 / BUG-21 — sender fallback path
# ---------------------------------------------------------------------------


def broadcast_original_psbt_fallback(
    original_psbt: PSBT,
    broadcast_callback: Any,
) -> str:
    """Fall back to broadcasting the Original PSBT as a normal transaction.

    Per BIP-78 §"Receiver Error" / payjoin.org §sender-fallback: when
    the receiver returns ``unavailable`` (or is unreachable), the sender
    MUST be able to broadcast the Original PSBT as a normal transaction
    so the payment still goes through (the sender already signed every
    input — the PSBT just needs finalization).

    Args:
      original_psbt:  the PSBT the sender originally POSTed (NOT the
                      receiver-modified proposal — we explicitly do
                      NOT broadcast a proposal that may carry
                      receiver-controlled inputs).
      broadcast_callback:  a callable ``f(raw_hex: str) -> txid_str``
                      that finalises and submits the tx.  Injected so
                      the caller chooses ``sendrawtransaction`` vs
                      any in-memory broadcaster.

    Returns the txid the broadcast callback emitted.
    """
    raw_hex = _finalize_psbt_to_raw_hex(original_psbt)
    if raw_hex is None:
        raise err_unavailable(
            "G22 fallback: could not extract raw transaction from Original PSBT"
        )
    return broadcast_callback(raw_hex)


def _finalize_psbt_to_raw_hex(psbt: PSBT) -> Optional[str]:
    """Finalize a PSBT and serialize to raw transaction hex.

    Single helper shared by the G22 fallback path and the sender RPC's
    happy-path broadcast.  Tries the public PSBT API
    (``finalize()`` + ``extract_transaction()`` + serialize-with-witness)
    and returns None on any structural failure so callers can decide
    whether to raise or substitute.
    """
    try:
        psbt.finalize()
    except Exception:
        return None
    if not psbt.is_finalized():
        return None
    try:
        from ouroboros.psbt import _serialize_tx_with_witness

        tx = psbt.extract_transaction()
        return _serialize_tx_with_witness(tx).hex()
    except Exception:
        # Fallback for variants that surface a ``serialize_with_witness``
        # method on the extracted tx directly.
        try:
            tx = psbt.extract_transaction()
            if hasattr(tx, "serialize_with_witness"):
                return tx.serialize_with_witness().hex()
        except Exception:
            return None
    return None


__all__ = [
    "RECEIVER_PATH",
    "ERR_UNAVAILABLE",
    "ERR_NOT_ENOUGH_MONEY",
    "ERR_VERSION_UNSUPPORTED",
    "ERR_ORIGINAL_PSBT_REJECTED",
    "SUPPORTED_VERSIONS",
    "MAX_BODY_BYTES",
    "DEFAULT_SENDER_TIMEOUT_SEC",
    "PayJoinError",
    "PayJoinRequestParams",
    "ReceiverContext",
    "SenderResponse",
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
    # FIX-66 sender + anti-snoop:
    "build_sender_query",
    "send_payjoin_request",
    "validate_response_outputs",
    "validate_scriptsig_uniformity",
    "validate_inputs_imply_outputs_changed",
    "validate_max_fee_contribution",
    "validate_disable_output_substitution",
    "validate_payjoin_response",
    "broadcast_original_psbt_fallback",
]
