"""BIP-21 Bitcoin URI parser.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki

URI shape:
    bitcoin:<address>[?<param>=<value>(&<param>=<value>)*]

Parameter handling per spec:
  * ``amount``         -- decimal BTC value (Decimal preserved exactly).
  * ``label``          -- percent-decoded UTF-8 string.
  * ``message``        -- percent-decoded UTF-8 string.
  * ``lightning``      -- BOLT-11 fallback invoice (treated as opaque string).
  * ``pj``             -- BIP-78 PayJoin endpoint URL (opaque string).
  * ``pjos``           -- BIP-78 disable-output-substitution flag, ``"0"`` or ``"1"``.
  * ``req-<name>``     -- required parameter; parser rejects the URI when the
                          ``req-`` extension is not understood (BIP-21 §"req-").
  * any other key      -- accepted and surfaced via ``extras`` (parser ignores
                          unknown non-``req-`` parameters per BIP-21).

The scheme prefix ``bitcoin:`` is matched case-insensitively (RFC 3986 §3.1
schemes are case-insensitive).  Parameter names are matched case-insensitively
(per the BIP-78 reference implementations and the broader Bitcoin URI
ecosystem).

This module is *pure parsing* -- it does NOT initiate any network activity
(no PayJoin POST, no Lightning probe).  It validates the address against the
network's prefix rules by delegating to
:func:`ouroboros.address.address_to_script_pubkey`.

Pipeline note: ouroboros's Rust side (``ferrous-utils/``) has no wallet logic
(per the W119 audit), so BIP-21 URI parsing lives only in the Python pipeline.
Single-pipeline by design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Dict, Optional
from urllib.parse import parse_qsl, unquote

from ouroboros.address import address_to_script_pubkey

__all__ = [
    "Bip21Uri",
    "Bip21Error",
    "InvalidSchemeError",
    "InvalidAddressError",
    "InvalidAmountError",
    "UnknownRequiredParamError",
    "DuplicateParamError",
    "parse_bip21",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class Bip21Error(ValueError):
    """Base class for BIP-21 parse failures."""


class InvalidSchemeError(Bip21Error):
    """URI does not start with the case-insensitive ``bitcoin:`` scheme."""


class InvalidAddressError(Bip21Error):
    """Address portion is empty, malformed, or wrong-network for the parse."""


class InvalidAmountError(Bip21Error):
    """``amount`` parameter is not a non-negative decimal BTC value."""


class UnknownRequiredParamError(Bip21Error):
    """``req-<name>`` parameter present whose semantics we do not implement
    (BIP-21 §"Required") -- parsers MUST refuse such URIs."""


class DuplicateParamError(Bip21Error):
    """The same parameter name appeared more than once.  BIP-21 does not
    specify multi-value parameters; we treat duplicates as malformed."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class Bip21Uri:
    """Parsed representation of a ``bitcoin:`` URI.

    ``extras`` collects non-standard parameters whose name does not begin
    with ``req-`` (those MUST cause the URI to be rejected when unknown).
    Keys in ``extras`` are stored lowercase (the parser is case-insensitive).
    """

    address: str
    amount: Optional[Decimal] = None
    label: Optional[str] = None
    message: Optional[str] = None
    lightning: Optional[str] = None
    pj: Optional[str] = None
    pjos: Optional[bool] = None
    extras: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


_SCHEME = "bitcoin:"

# Known top-level (non req-) parameter names.  Anything outside this set that
# does NOT start with ``req-`` is stored in ``extras`` rather than rejected.
_KNOWN_KEYS = frozenset({"amount", "label", "message", "lightning", "pj", "pjos"})


def _strip_scheme(s: str) -> str:
    """Strip the case-insensitive ``bitcoin:`` prefix or raise."""
    if not isinstance(s, str):
        raise InvalidSchemeError(
            f"BIP-21 URI must be a string, got {type(s).__name__}"
        )
    if not s:
        raise InvalidSchemeError("BIP-21 URI is empty")
    # Scheme is case-insensitive per RFC 3986.
    if s[: len(_SCHEME)].lower() != _SCHEME:
        raise InvalidSchemeError(
            "BIP-21 URI must start with 'bitcoin:' (case-insensitive)"
        )
    return s[len(_SCHEME) :]


def _split_address_and_query(remainder: str) -> tuple[str, str]:
    """Split the post-scheme portion into ``(address, raw_query)``."""
    # BIP-21 ABNF:  bitcoinurn = "bitcoin:" bitcoinaddress [ "?" bitcoinparams ]
    # No fragment, no userinfo, no path beyond the address.
    if "?" in remainder:
        addr, _, query = remainder.partition("?")
    else:
        addr, query = remainder, ""
    return addr, query


def _parse_amount(raw: str) -> Decimal:
    """Parse the ``amount`` parameter.

    BIP-21 §"amount" says the value MUST be in decimal BTC.  We additionally
    require it to be finite and non-negative (zero is allowed -- "donation"
    forms in the wild use ``amount=0``).
    """
    # Reject obviously bogus shapes that ``Decimal`` would silently accept
    # (NaN, Infinity, scientific notation -- BIP-21 only blesses plain
    # decimal-fraction form).
    stripped = raw.strip()
    if not stripped:
        raise InvalidAmountError("BIP-21 amount is empty")
    # Disallow exponent / inf / nan -- the BIP says "decimal" and the wallet
    # ecosystem treats anything else as invalid.
    lower = stripped.lower()
    if "e" in lower or "inf" in lower or "nan" in lower:
        raise InvalidAmountError(f"BIP-21 amount must be decimal: {raw!r}")
    # Leading '+' or '-' is rejected: BIP-21 amounts are non-negative.
    if stripped.startswith(("+", "-")):
        raise InvalidAmountError(f"BIP-21 amount must be non-negative: {raw!r}")
    try:
        value = Decimal(stripped)
    except (InvalidOperation, ArithmeticError) as exc:
        raise InvalidAmountError(
            f"BIP-21 amount is not a valid decimal: {raw!r}"
        ) from exc
    if value < 0:
        raise InvalidAmountError(f"BIP-21 amount must be non-negative: {raw!r}")
    return value


def _parse_pjos(raw: str) -> bool:
    """Parse the BIP-78 ``pjos`` (disable-output-substitution) flag."""
    s = raw.strip()
    if s == "0":
        return False
    if s == "1":
        return True
    raise Bip21Error(f"BIP-78 pjos must be '0' or '1': {raw!r}")


def parse_bip21(uri: str, network: str = "mainnet") -> Bip21Uri:
    """Parse a BIP-21 ``bitcoin:`` URI and return a :class:`Bip21Uri`.

    Args:
        uri: The raw URI string.
        network: Bitcoin network for address validation -- one of
            ``"mainnet"``, ``"testnet"``, ``"testnet4"``, ``"regtest"``,
            ``"signet"``.  Forwarded to
            :func:`ouroboros.address.address_to_script_pubkey`.

    Raises:
        InvalidSchemeError: scheme prefix is missing or not ``bitcoin:``.
        InvalidAddressError: address is empty or fails network validation.
        InvalidAmountError: ``amount=`` is not a valid non-negative decimal.
        UnknownRequiredParamError: a ``req-<name>`` parameter is present
            whose semantics the parser does not understand.
        DuplicateParamError: the same parameter name appears more than once.
        Bip21Error: catch-all for other BIP-21 violations (e.g. malformed
            ``pjos``).
    """
    remainder = _strip_scheme(uri)
    raw_address, raw_query = _split_address_and_query(remainder)

    # Percent-decode the address (some wallets percent-encode the colon if
    # they re-wrap a URI, though BIP-21 does not require it).  Address
    # characters are ASCII-safe so this is a no-op for well-formed URIs.
    address = unquote(raw_address)
    if not address:
        raise InvalidAddressError("BIP-21 URI is missing the address")

    # Validate via the existing address parser -- raises on bad network /
    # checksum / unknown prefix.  We don't keep the scriptPubKey here; this
    # is purely validation.
    try:
        address_to_script_pubkey(address, network=network)
    except ValueError as exc:
        raise InvalidAddressError(
            f"BIP-21 address invalid for network={network!r}: {address!r}: {exc}"
        ) from exc

    # ``parse_qsl`` handles percent-decoding and ``+`` -> space; we want spec
    # behavior (``+`` is NOT a space in a URI's query unless application/x-
    # www-form-urlencoded; BIP-21 URIs use the generic URI query reading).
    # Decode manually so that ``+`` stays literal.
    parsed: list[tuple[str, str]] = []
    if raw_query:
        for chunk in raw_query.split("&"):
            if not chunk:
                # Tolerate leading/trailing/double ``&`` -- per RFC 3986 the
                # query is opaque, so we just skip empty chunks.
                continue
            key, sep, value = chunk.partition("=")
            if not sep:
                # ``key`` with no ``=`` -- treat as an empty-string value.
                value = ""
            parsed.append((unquote(key), unquote(value)))

    seen: Dict[str, str] = {}
    extras: Dict[str, str] = {}

    amount: Optional[Decimal] = None
    label: Optional[str] = None
    message: Optional[str] = None
    lightning: Optional[str] = None
    pj: Optional[str] = None
    pjos: Optional[bool] = None

    for raw_key, value in parsed:
        # Parameter names are case-insensitive (BIP-78 reference & wallet
        # ecosystem).  ``req-`` prefix matching is therefore done after
        # lowercasing.
        key = raw_key.lower()
        if key in seen:
            raise DuplicateParamError(
                f"BIP-21 parameter appears more than once: {raw_key!r}"
            )
        seen[key] = value

        if key == "amount":
            amount = _parse_amount(value)
        elif key == "label":
            label = value
        elif key == "message":
            message = value
        elif key == "lightning":
            lightning = value
        elif key == "pj":
            pj = value
        elif key == "pjos":
            pjos = _parse_pjos(value)
        elif key.startswith("req-"):
            # We currently understand no ``req-`` extensions.  Per BIP-21:
            # "If a parser does not implement a required parameter, it MUST
            # consider the entire URI invalid."
            raise UnknownRequiredParamError(
                f"BIP-21 required parameter not supported: {raw_key!r}"
            )
        else:
            # Unknown non-required parameter -- BIP-21 says ignore.  We
            # preserve the raw value in ``extras`` so callers (RPC, future
            # PayJoin glue) can still inspect them.  Keys in ``extras`` are
            # lowercase to match the case-insensitive matching above.
            extras[key] = value

    return Bip21Uri(
        address=address,
        amount=amount,
        label=label,
        message=message,
        lightning=lightning,
        pj=pj,
        pjos=pjos,
        extras=extras,
    )
