"""Regression test: bech32/bech32m 90-character CharLimit on decode.

Bitcoin Core (`bitcoin-core/src/bech32.cpp:378`) returns an empty result
when the input string is longer than ``CharLimit::BECH32`` (= 90, see
`bech32.h:38-40`). The BCH code's 4-error-detection guarantee only holds
up to 89 characters; beyond that a valid-looking checksum can no longer
be trusted, so an overlong string must be rejected on decode regardless
of whether its checksum happens to verify.

Ouroboros enforces this in :func:`ouroboros.address._bech32m_decode`
(``len(address) > 90`` short-circuit, applied before checksum
verification). This is a wallet / address-encoding path only — it is
*not* reachable from block or script validation (``script.py`` /
``validation.py`` / ``consensus.py`` never decode bech32) — so the check
is non-consensus.

Mutation note: deleting the ``len(address) > 90`` clause makes
``test_overlong_valid_checksum_rejected`` fail (a 99-char
valid-checksum string would decode successfully without the limit).
"""

from __future__ import annotations

from ouroboros.address import (
    _BECH32_CHARSET,
    _bech32m_create_checksum,
    _bech32m_decode,
)


def _make_valid_bech32(hrp: str, data: list[int]) -> str:
    """Build a syntactically valid bech32 string with a correct checksum."""
    checksum = _bech32m_create_checksum(hrp, data, "bech32")
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def test_overlong_valid_checksum_rejected():
    """A >90-char string with a VALID checksum must still decode to None.

    This is the load-bearing case: only the explicit length limit can
    reject it, since the checksum verifies. Without the ``len > 90``
    guard the decoder would happily return ``("bc", 0, [...])``.
    """
    # hrp(2) + '1'(1) + data(90) + checksum(6) = 99 chars.
    data = [0] + [0] * 89  # witness v0 + 89 zero symbols
    overlong = _make_valid_bech32("bc", data)
    assert len(overlong) == 99
    # Sanity: the checksum itself is valid (so only the length limit rejects).
    from ouroboros.address import _bech32m_verify_checksum

    five_bit = [_BECH32_CHARSET.find(c) for c in overlong[overlong.rfind("1") + 1:]]
    assert _bech32m_verify_checksum("bc", five_bit) == "bech32"
    # Decode must reject purely on length.
    assert _bech32m_decode(overlong) == (None, None, None)


def test_exactly_90_chars_not_length_rejected():
    """A 90-char string is at the limit — it must NOT be rejected for length.

    (It is still rejected by checksum here, but crucially the rejection
    reason is the checksum, not the length boundary — proving the limit
    is ``> 90`` and not ``>= 90``.)
    """
    s90 = "bc1" + "q" * 87  # length 3 + 87 = 90
    assert len(s90) == 90
    # rfind('1') etc. pass; it fails on checksum, not on the length clause.
    # If the limit were mistakenly ``>= 90`` this would short-circuit the
    # same way — so we assert the boundary by constructing a *valid* 90-char
    # string and confirming it decodes.
    data = [0] + [0] * 80  # total length = 2 + 1 + 81 + 6 = 90
    valid90 = _make_valid_bech32("bc", data)
    assert len(valid90) == 90
    hrp, ver, prog = _bech32m_decode(valid90)
    assert hrp == "bc"
    assert ver == 0


def test_91_chars_all_charset_rejected():
    """A 91-char string built only from charset chars decodes to None."""
    s91 = "bc1" + "q" * 88  # length 91
    assert len(s91) == 91
    assert _bech32m_decode(s91) == (None, None, None)
