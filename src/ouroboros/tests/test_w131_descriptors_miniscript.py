"""
W131 — Descriptors + Miniscript (BIP-380 / BIP-385) audit tests.

30-gate audit matrix; each gate is a pytest function so the discovery
inventory matches the audit md file 1:1. ``xfail`` is used for the bugs
catalogued in ``audit/w131_descriptors_miniscript.md`` so the test file
stays green while still pinning the divergent behavior.

See: ``audit/w131_descriptors_miniscript.md``
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

# Ensure src is on path + mock the Rust sync extension so descriptors module imports cleanly.
src_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_dir))
if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync

import pytest  # noqa: E402

from ouroboros.descriptors import (  # noqa: E402
    _INPUT_CHARSET,
    _CHECKSUM_CHARSET,
    _polymod,
    _parse_key_expression,
    descriptor_checksum,
    add_checksum,
    verify_checksum,
    parse_descriptor,
    ExtendedPubKey,
)
from ouroboros.miniscript import (  # noqa: E402
    Fragment,
    MiniscriptContext,
    MiniscriptNode,
    MiniscriptType,
    parse_miniscript,
    compile_miniscript,
    analyze_satisfaction,
    miniscript_to_str,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# BIP-32 test vector 1 master xpub (seed 000102030405060708090a0b0c0d0e0f)
_TEST_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)
_TEST_PUBKEY_HEX = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
# 32-byte x-only key whose first byte is 0x02 (to exercise BUG-6)
_TEST_XONLY_LEADS_02 = "02" + "a" * 62  # "02aa...aa" -> 32 bytes, first byte 0x02
_TEST_XONLY_LEADS_03 = "03" + "b" * 62
# Generic x-only (first byte non-02/03)
_TEST_XONLY_HEX = "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
# Uncompressed 65-byte key (Core accepts in TOP/P2SH)
_TEST_UNCOMPRESSED = (
    "04" + "a" * 64 + "b" * 64  # 04 + X + Y, 130 hex chars total
)


# ---------------------------------------------------------------------------
# Section A — BIP-380 checksum + charset (G1-G5)
# ---------------------------------------------------------------------------


def test_g1_polymod_constants_match_core():
    """G1: PolyMod generator constants identical to Core descriptor.cpp:94-103."""
    # _polymod is a free function in descriptors.py; we can test its low-level
    # behavior via descriptor_checksum on a known input.
    # Direct constant assertion via the function source:
    import inspect
    src = inspect.getsource(_polymod)
    for needle in ("0xF5DEE51989", "0xA9FDCA3312", "0x1BAB10E32D",
                   "0x3706B1677A", "0x644D626FFD"):
        assert needle in src, f"PolyMod missing constant {needle}"


def test_g2_input_charset_matches_core():
    """G2: INPUT_CHARSET is byte-identical to Core descriptor.cpp:121-124.

    Core's charset has 95 characters total: 32 + 32 + 31 (the third
    group is intentionally one short — it omits the corresponding
    32-symbol filler so the cls accumulator and `' '` trailing space
    align). We assert structure, not just bytes, so silent re-grouping
    is detected.
    """
    expected = (
        "0123456789()[],'/*abcdefgh@:$%{}"  # group 0 (32 chars)
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"  # group 1 (32 chars)
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "   # group 2 (31 chars — trailing space)
    )
    assert _INPUT_CHARSET == expected
    assert len(_INPUT_CHARSET) == 95
    # No duplicates: every char in INPUT_CHARSET maps to exactly one position.
    assert len(set(_INPUT_CHARSET)) == len(_INPUT_CHARSET), "duplicate chars in INPUT_CHARSET"


def test_g3_checksum_charset_is_bech32():
    """G3: CHECKSUM_CHARSET is bech32 alphabet."""
    assert _CHECKSUM_CHARSET == "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    assert len(_CHECKSUM_CHARSET) == 32


def test_g4_checksum_known_vectors():
    """G4: descriptor_checksum matches expected for canonical descriptors.

    Vectors collected from Bitcoin Core test_framework/descriptors.py /
    descriptor_tests.cpp (round-trip property — every descriptor that goes
    through ``getdescriptorinfo`` must round-trip).
    """
    # Round-trip property: verify_checksum(add_checksum(d)) is always True.
    samples = [
        f"pk({_TEST_PUBKEY_HEX})",
        f"pkh({_TEST_PUBKEY_HEX})",
        f"wpkh({_TEST_PUBKEY_HEX})",
        f"sh(wpkh({_TEST_PUBKEY_HEX}))",
        f"wsh(pkh({_TEST_PUBKEY_HEX}))",
        f"combo({_TEST_PUBKEY_HEX})",
        f"tr({_TEST_PUBKEY_HEX})",
        f"multi(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX})",
    ]
    for d in samples:
        cs = descriptor_checksum(d)
        assert len(cs) == 8, f"{d}: checksum {cs!r} not 8 chars"
        assert all(c in _CHECKSUM_CHARSET for c in cs), f"{d}: bad chars in {cs}"
        assert verify_checksum(f"{d}#{cs}"), f"{d}: round-trip fail"
        # Also verify a single-character corruption fails:
        corrupted = list(cs)
        corrupted[0] = _CHECKSUM_CHARSET[(_CHECKSUM_CHARSET.index(corrupted[0]) + 1) % 32]
        bad = "".join(corrupted)
        assert not verify_checksum(f"{d}#{bad}"), f"{d}: corruption not detected"


@pytest.mark.xfail(
    reason="BUG-1 (LOW): descriptor_checksum raises ValueError on unknown char; "
           "Core returns empty string (descriptor.cpp:134). Unreachable in practice "
           "since INPUT_CHARSET covers all bech32 + ASCII text we'd see, but the "
           "API contract diverges.",
    strict=True,
)
def test_g5_checksum_bad_char_returns_empty_not_raises():
    """G5: BUG-1. Bad char in input should yield empty string per Core."""
    # Unicode char outside INPUT_CHARSET — Core returns "", ouroboros raises.
    result = descriptor_checksum("pk(é)")
    assert result == "", "should match Core behaviour: empty string on bad input"


# ---------------------------------------------------------------------------
# Section B — Key expressions / KeyOrigin / xpub (G6-G10)
# ---------------------------------------------------------------------------


def test_g6_compressed_pubkey_accepted():
    """G6: 66-hex compressed pubkey with 02/03 prefix parses cleanly."""
    expr = _parse_key_expression(_TEST_PUBKEY_HEX)
    assert expr.hex_pubkey is not None
    assert len(expr.hex_pubkey) == 33
    assert expr.hex_pubkey[0] in (0x02, 0x03)


@pytest.mark.xfail(
    reason="BUG-2 (MED): x-only 32-byte hex accepted in ANY descriptor context, "
           "not just P2TR (Core descriptor.cpp:1907 only accepts in P2TR).",
    strict=True,
)
def test_g7_x_only_only_in_taproot_context():
    """G7: BUG-2. 32-byte x-only key must only parse in P2TR context."""
    # ouroboros accepts a 32-byte x-only via _parse_key_expression unconditionally,
    # but parse_descriptor("pkh(<x-only>)") should *reject* the construction.
    # Core would reject this; ouroboros accepts. We exhibit the divergence:
    desc_str = f"pkh({_TEST_XONLY_HEX})"
    with pytest.raises(ValueError):
        parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))


@pytest.mark.xfail(
    reason="BUG-3 (MED): ouroboros flat-rejects uncompressed (65-byte / 130-hex) "
           "pubkeys; Core accepts in TOP/P2SH (pk/pkh/sh).",
    strict=True,
)
def test_g8_uncompressed_pubkey_accepted_in_top_context():
    """G8: BUG-3. pk(04...) should parse — Core accepts uncompressed in TOP."""
    desc_str = f"pk({_TEST_UNCOMPRESSED})"
    desc = parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))
    assert desc.descriptor_type == "pk"


def test_g9_hybrid_pubkey_rejected():
    """G9: pubkey with 0x06/0x07 prefix is rejected (Core: ``Hybrid public keys are not allowed``)."""
    # Hybrid keys are 0x06 or 0x07 prefix + 64 bytes (130 hex)
    hybrid = "06" + "a" * 128
    with pytest.raises(ValueError):
        _parse_key_expression(hybrid)


def test_g10_xpub_roundtrip_preserves_all_fields():
    """G10: ExtendedPubKey.serialize / deserialize round-trips all 5 fields."""
    e = ExtendedPubKey.deserialize(_TEST_XPUB)
    assert e.depth == 0
    assert len(e.chain_code) == 32
    assert len(e.public_key) == 33
    assert e.serialize() == _TEST_XPUB


# ---------------------------------------------------------------------------
# Section C — Origin + derivation path (G11-G15)
# ---------------------------------------------------------------------------


def test_g11_origin_parse_fingerprint_and_path():
    """G11: [fingerprint/path] is parsed into KeyOrigin."""
    expr = _parse_key_expression(f"[deadbeef/44'/0'/0']{_TEST_PUBKEY_HEX}")
    assert expr.origin is not None
    assert expr.origin.fingerprint == "deadbeef"
    assert "44" in expr.origin.path


@pytest.mark.xfail(
    reason="BUG-4 (LOW): no normalized-form (' vs h) tracking on KeyOrigin; "
           "ToNormalizedString vs ToString(COMPAT) parity missing.",
    strict=True,
)
def test_g12_hardened_path_apostrophe_vs_h_normalized():
    """G12: BUG-4. Origin parsed with `h` should normalize to `'` for COMPAT form."""
    expr = _parse_key_expression(f"[deadbeef/44h/0h/0h]{_TEST_PUBKEY_HEX}")
    # ouroboros should expose an `apostrophe` flag or normalized-form method.
    assert hasattr(expr.origin, "apostrophe") or hasattr(expr.origin, "normalized_path")


@pytest.mark.xfail(
    reason="BUG-5 (LOW): origin-path hardened step values not bounds-checked.",
    strict=True,
)
def test_g13_origin_path_hardened_step_value_bounds():
    """G13: BUG-5. Step number >= 0x80000000 in origin should be rejected."""
    bad = f"[deadbeef/{0x80000000}h/0h/0h]{_TEST_PUBKEY_HEX}"
    with pytest.raises(ValueError):
        _parse_key_expression(bad)


def test_g14_wildcard_marks_is_range():
    """G14: `*` in derivation suffix sets is_range=True."""
    expr = _parse_key_expression(f"{_TEST_XPUB}/0/*")
    assert expr.is_range is True


@pytest.mark.xfail(
    reason="GAP-F (LOW): no hardened-ranged wildcard `*'` or `*h` support; "
           "Core supports it via DeriveType::HARDENED_RANGED.",
    strict=True,
)
def test_g15_hardened_ranged_wildcard():
    """G15: GAP-F. `*'` hardened wildcard should parse from xprv."""
    # We'd need an xprv to exercise hardened derivation; just check parse path:
    expr = _parse_key_expression(f"{_TEST_XPUB}/0/*'")
    assert expr.is_range is True
    # In Core this would set DeriveType::HARDENED_RANGED.
    assert getattr(expr, "is_hardened_range", False) is True


# ---------------------------------------------------------------------------
# Section D — Descriptor types (G16-G20)
# ---------------------------------------------------------------------------


def test_g16_all_top_level_descriptors_parse():
    """G16: All 16+ top-level descriptor names parse."""
    samples = [
        f"pk({_TEST_PUBKEY_HEX})",
        f"pkh({_TEST_PUBKEY_HEX})",
        f"wpkh({_TEST_PUBKEY_HEX})",
        f"sh(wpkh({_TEST_PUBKEY_HEX}))",
        f"wsh(pkh({_TEST_PUBKEY_HEX}))",
        f"combo({_TEST_PUBKEY_HEX})",
        f"multi(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX})",
        f"sortedmulti(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX})",
        f"sh(multi(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX}))",
        f"wsh(multi(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX}))",
        f"sh(wsh(multi(1,{_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX})))",
        f"tr({_TEST_PUBKEY_HEX})",
        f"rawtr({_TEST_XONLY_HEX})",
        # addr / raw need actual valid data:
        "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
        "raw(0014751e76e8199196d454941c45d1b3a323f1433bd6)",
    ]
    for d in samples:
        canonical = d + "#" + descriptor_checksum(d)
        desc = parse_descriptor(canonical)
        assert desc is not None
        assert desc.descriptor_type, f"empty type for {d}"


@pytest.mark.xfail(
    reason="GAP-A (INFO): musig() participant aggregation inside tr()/rawtr() "
           "not implemented (Core descriptor.cpp:596-790, 1964-2096).",
    strict=True,
)
def test_g17_musig_inside_tr():
    """G17: GAP-A. musig() should parse inside tr()/rawtr()."""
    desc_str = f"rawtr(musig({_TEST_PUBKEY_HEX},{_TEST_PUBKEY_HEX}))"
    desc = parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))
    assert desc.descriptor_type in ("rawtr", "tr-musig")


@pytest.mark.xfail(
    reason="GAP-B (INFO) / BUG-11 (MED): sortedmulti_a appears to parse "
           "(parse_descriptor returns descriptor_type='tr-script') but the "
           "inner expression is stored verbatim and is NOT a recognized "
           "miniscript node — any subsequent compile / derive call raises. "
           "Real Core sortedmulti_a parse path is missing AND the parser "
           "silently accepts unknown leaf miniscripts inside tr() script "
           "tree, deferring the error until use.",
    strict=True,
)
def test_g18_sortedmulti_a_inside_tr_compiles():
    """G18: GAP-B / BUG-11. sortedmulti_a should compile inside tr() — not silently accept-then-fail."""
    desc_str = (
        f"tr({_TEST_PUBKEY_HEX},sortedmulti_a(1,{_TEST_XONLY_HEX},{_TEST_XONLY_HEX}))"
    )
    desc = parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))
    # ouroboros stores the body verbatim → parse appears to succeed.
    # The real Core behaviour is either reject at parse-time (if sortedmulti_a
    # is unsupported) or compile cleanly to the expected script. Anything in
    # between (accept then crash) is the worst of both worlds.
    addr = desc.derive_address(0)
    assert addr.startswith("bc1p"), f"expected p2tr address, got {addr!r}"


@pytest.mark.xfail(
    reason="BUG-6 (MED): combo() gates segwit variants on raw prefix byte 02/03 "
           "instead of full-length compressed-pubkey check. A 32-byte x-only with "
           "first byte 0x02/0x03 produces malformed P2WPKH (Hash160 of 32 bytes).",
    strict=True,
)
def test_g19_combo_gates_segwit_on_full_compression_not_prefix_byte():
    """G19: BUG-6. combo() segwit variants must only fire for 33-byte compressed key."""
    # Build a combo() over a key whose hex_pubkey is 32 bytes (x-only) with leading 0x02.
    # ouroboros's hex_pubkey storage will be 32 bytes, prefix 02 — but it's NOT a
    # valid compressed key, just a coincidence of bytes.
    desc_str = f"combo({_TEST_XONLY_LEADS_02})"
    desc = parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))
    scripts = desc.derive_all_scripts(0)
    # Correct behavior: combo on 32-byte non-compressed must NOT include P2WPKH or P2SH-P2WPKH.
    # (Or, alternatively, the parse should have rejected it altogether.)
    assert len(scripts) == 2, f"combo should emit P2PK+P2PKH only for non-compressed, got {len(scripts)}"


@pytest.mark.xfail(
    reason="BUG-10 (MED): Descriptor.derive_script_pubkey() lacks an arm for "
           "rawtr — it raises ValueError('Unknown descriptor type: rawtr') even "
           "though derive_address() handles rawtr correctly. Asymmetric API: "
           "addresses work, scriptPubKeys don't.",
    strict=True,
)
def test_g20_rawtr_derive_script_pubkey():
    """G20: BUG-10. rawtr(X-ONLY) must produce OP_1 <32-byte> via derive_script_pubkey."""
    desc_str = f"rawtr({_TEST_XONLY_HEX})"
    desc = parse_descriptor(desc_str + "#" + descriptor_checksum(desc_str))
    # derive_address works:
    assert desc.derive_address(0).startswith("bc1p")
    # derive_script_pubkey must also work (currently raises):
    script = desc.derive_script_pubkey(0)
    # OP_1 (0x51) + push-32 (0x20) + 32-byte key, no tweak
    assert script[0] == 0x51
    assert script[1] == 0x20
    assert script[2:].hex() == _TEST_XONLY_HEX


# ---------------------------------------------------------------------------
# Section E — Miniscript fragments + type system (G21-G25)
# ---------------------------------------------------------------------------


def test_g21_all_25_fragments_present():
    """G21: Fragment enum has all 25 miniscript fragments per BIP-379."""
    expected = {
        "JUST_0", "JUST_1", "PK_K", "PK_H", "OLDER", "AFTER",
        "SHA256", "HASH256", "RIPEMD160", "HASH160",
        "WRAP_A", "WRAP_S", "WRAP_C", "WRAP_D", "WRAP_V", "WRAP_J", "WRAP_N",
        "AND_V", "AND_B", "OR_B", "OR_C", "OR_D", "OR_I", "ANDOR",
        "THRESH", "MULTI", "MULTI_A",
    }
    actual = {f.name for f in Fragment}
    missing = expected - actual
    assert not missing, f"missing fragments: {missing}"


def test_g22_older_after_value_bounds():
    """G22: older(n) and after(n) accept 1 <= n < 0x80000000 only."""
    # Lower bound
    with pytest.raises(ValueError):
        parse_miniscript("older(0)")
    with pytest.raises(ValueError):
        parse_miniscript("after(0)")
    # Upper bound (Core miniscript.cpp:51 CHECK_NONFATAL k < 0x80000000)
    with pytest.raises(ValueError):
        parse_miniscript(f"older({0x80000000})")
    with pytest.raises(ValueError):
        parse_miniscript(f"after({0x80000000})")
    # Valid edge cases parse:
    n = parse_miniscript("older(1)")
    assert n.fragment == Fragment.OLDER
    n = parse_miniscript(f"after({0x7fffffff})")
    assert n.fragment == Fragment.AFTER


def test_g23_locktime_type_flags():
    """G23: g/h/i/j type bits set correctly per LOCKTIME_THRESHOLD / SEQUENCE_LOCKTIME_TYPE_FLAG."""
    SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
    # older(n) with type-flag bit set → 'g' (time)
    n = parse_miniscript(f"older({SEQUENCE_LOCKTIME_TYPE_FLAG | 5})")
    assert "g" in n.get_type()
    # older(n) without type-flag bit → 'h' (height)
    n = parse_miniscript("older(100)")
    assert "h" in n.get_type()
    # after(n) >= LOCKTIME_THRESHOLD → 'i' (time)
    n = parse_miniscript("after(500000001)")
    assert "i" in n.get_type()
    # after(n) < LOCKTIME_THRESHOLD → 'j' (height)
    n = parse_miniscript("after(100)")
    assert "j" in n.get_type()


def test_g24_multi_caps_20_keys():
    """G24: multi(k, K1..K20) caps at MAX_PUBKEYS_PER_MULTISIG = 20."""
    keys21 = ",".join(_TEST_PUBKEY_HEX for _ in range(21))
    with pytest.raises(ValueError):
        parse_miniscript(f"multi(1,{keys21})")


@pytest.mark.xfail(
    reason="BUG-7 (MED): multi_a has no upper bound; Core caps at "
           "MAX_PUBKEYS_PER_MULTI_A=999 (script.h:37, miniscript.h:2418). "
           "ouroboros has no check at miniscript.py:1063, so a 1000-key "
           "multi_a parses fine and emits a standardness-violating script "
           "that mainnet relayers would drop.",
    strict=True,
)
def test_g25_multi_a_caps_999_keys():
    """G25: BUG-7. multi_a with > 999 keys should be rejected."""
    # The default key parser inside parse_miniscript only accepts 66-hex
    # compressed keys; supply a custom parser that accepts 64-hex x-only so
    # we can hit the real n_keys check, not get tripped on key encoding.
    def xonly_parser(s: str) -> bytes:
        s = s.strip()
        b = bytes.fromhex(s)
        if len(b) == 32:
            return b
        if len(b) == 33 and b[0] in (0x02, 0x03):
            return b
        raise ValueError(f"bad key: {s}")

    keys1000 = ",".join(_TEST_XONLY_HEX for _ in range(1000))
    with pytest.raises(ValueError):
        parse_miniscript(
            f"multi_a(1,{keys1000})",
            ctx=MiniscriptContext.TAPSCRIPT,
            key_parser=xonly_parser,
        )


# ---------------------------------------------------------------------------
# Section F — Type computation, compilation, round-trip (G26-G30)
# ---------------------------------------------------------------------------


def test_g26_type_computation_basic_fragments():
    """G26: type computation matches Core for canonical fragments."""
    # pk(K) = c:pk_k(K) → type B+u+s+m+x+...
    n = parse_miniscript(f"pk({_TEST_PUBKEY_HEX})")
    t = n.get_type()
    assert t.is_B
    assert "u" in t
    assert "s" in t
    # pkh(K) = c:pk_h(K) → type B+u+s+m+...
    n = parse_miniscript(f"pkh({_TEST_PUBKEY_HEX})")
    t = n.get_type()
    assert t.is_B
    assert "u" in t
    # and_v(pk(K), older(n)) → B + ...
    n = parse_miniscript(f"and_v(v:pk({_TEST_PUBKEY_HEX}),older(100))")
    t = n.get_type()
    assert t.is_B


@pytest.mark.xfail(
    reason="GAP-D (MED): no duplicate-key detection in miniscript (Core "
           "miniscript.h:1493-1549 DuplicateKeyCheck). ouroboros silently accepts "
           "redundant-key constructs Core would reject per BIP-379.",
    strict=True,
)
def test_g27_duplicate_key_detection():
    """G27: GAP-D. and_v(pk(K), pk(K)) with same K must be rejected."""
    # Same key twice — Core's DuplicateKeyCheck would catch this.
    n = parse_miniscript(
        f"and_v(v:pk({_TEST_PUBKEY_HEX}),pk({_TEST_PUBKEY_HEX}))"
    )
    # ouroboros has no duplicate-key check. Surface a property the audit
    # demands: there should be either a parse-time error OR a flag on the
    # node indicating duplicates.
    assert getattr(n, "has_duplicate_keys", True) is False, \
        "should detect duplicate keys per BIP-379 / Core DuplicateKeyCheck"


@pytest.mark.xfail(
    reason="BUG-9 (LOW): miniscript_to_str emits c:multi(...) for WRAP_C over MULTI, "
           "but multi already returns B (not K), so the c: wrapper is type-invalid "
           "and the output is unparseable.",
    strict=True,
)
def test_g28_miniscript_str_roundtrip_no_invalid_c_wrap():
    """G28: BUG-9. WRAP_C over MULTI must not be emitted as ``c:multi(...)``."""
    # Build a WRAP_C(MULTI) directly via the AST (parser wouldn't construct this,
    # but the printer must not generate invalid output).
    multi = MiniscriptNode(
        Fragment.MULTI,
        keys=[bytes.fromhex(_TEST_PUBKEY_HEX), bytes.fromhex(_TEST_PUBKEY_HEX)],
        k=1,
        _ctx=MiniscriptContext.P2WSH,
    )
    bad = MiniscriptNode(Fragment.WRAP_C, subs=[multi], _ctx=MiniscriptContext.P2WSH)
    s = miniscript_to_str(bad)
    # Round-trip should either parse cleanly or printer should refuse:
    assert not s.startswith("c:multi"), (
        f"emitted invalid wrap: {s} (multi has type B, c: needs K)"
    )


def test_g29_script_compilation_byte_equality_basic():
    """G29: canonical miniscripts compile to expected script bytes.

    Vectors hand-derived from the spec; for full Core-parity vectors see
    miniscript_tests.cpp.
    """
    # pk(K) = c:pk_k(K) → <K> OP_CHECKSIG
    n = parse_miniscript(f"pk({_TEST_PUBKEY_HEX})")
    script = compile_miniscript(n, MiniscriptContext.P2WSH)
    expected = bytes([33]) + bytes.fromhex(_TEST_PUBKEY_HEX) + bytes([0xAC])
    assert script == expected
    # older(100) → <100> OP_CHECKSEQUENCEVERIFY
    n = parse_miniscript("older(100)")
    script = compile_miniscript(n, MiniscriptContext.P2WSH)
    # 100 fits in 1 byte: push <0x01 0x64> OP_CSV(0xb2)
    assert script == bytes([0x01, 0x64, 0xB2])
    # sha256(<32 hex zeros>) → OP_SIZE OP_PUSH1(32) OP_EQUALVERIFY OP_SHA256 <h> OP_EQUAL
    h32 = "00" * 32
    n = parse_miniscript(f"sha256({h32})")
    script = compile_miniscript(n, MiniscriptContext.P2WSH)
    expected = (
        bytes([0x82])  # OP_SIZE
        + bytes([0x01, 0x20])  # push 32
        + bytes([0x88, 0xA8])  # OP_EQUALVERIFY OP_SHA256
        + bytes([32]) + bytes.fromhex(h32)
        + bytes([0x87])  # OP_EQUAL
    )
    assert script == expected


def test_g30_analyze_satisfaction_sizes_canonical():
    """G30: analyze_satisfaction sizes for canonical fragments.

    P2WSH context: sig=72 bytes (ECDSA max), pubkey=33 bytes.
    Tapscript context: sig=65 bytes (Schnorr), pubkey=32 bytes.
    """
    # pk(K) sat=1+sig=73 (P2WSH)
    n = parse_miniscript(f"pk({_TEST_PUBKEY_HEX})")
    info = analyze_satisfaction(n)
    assert info.sat_size == 1 + 72  # 73 bytes
    assert info.has_sig is True
    # pkh(K) sat=1+sig+1+pubkey=1+72+1+33=107
    n = parse_miniscript(f"pkh({_TEST_PUBKEY_HEX})")
    info = analyze_satisfaction(n)
    assert info.sat_size == 1 + 72 + 1 + 33
    # older(n) sat=0
    n = parse_miniscript("older(100)")
    info = analyze_satisfaction(n)
    assert info.sat_size == 0


# ---------------------------------------------------------------------------
# Two-pipeline drift guard
# ---------------------------------------------------------------------------


def test_two_pipeline_guard_descriptors_python_only():
    """Two-pipeline invariant: descriptor / miniscript code must remain Python.

    The wallet pipeline (descriptors, BIP-32, BIP-380, miniscript) is Python.
    The consensus pipeline (block / tx / chain validation) is in the
    ferrous-utils Rust crates. If descriptor or miniscript symbols ever appear
    on the Rust side, the two pipelines have crossed — flag immediately.

    Allowed: RocksDB's ``ColumnFamilyDescriptor`` symbol (unrelated to BIP-380).
    """
    ferrous = Path(__file__).resolve().parents[3] / "ferrous-utils"
    assert ferrous.exists(), f"ferrous-utils not found at {ferrous}"

    forbidden_needles = [
        r"\bBIP[- ]?380\b",
        r"\bBIP[- ]?381\b",
        r"\bBIP[- ]?385\b",
        r"\bBIP[- ]?386\b",
        r"\bBIP[- ]?379\b",  # Miniscript
        r"\bMiniscript\b",
        r"\bDescriptorChecksum\b",
        r"\bdescriptor_checksum\b",
        r"\bparse_descriptor\b",
        r"\bMiniscriptNode\b",
        r"\bMiniscriptType\b",
    ]
    forbidden_re = re.compile("|".join(forbidden_needles), re.IGNORECASE)

    hits: list[tuple[Path, str]] = []
    for root in (ferrous / "common" / "src", ferrous / "sync" / "src"):
        if not root.exists():
            continue
        for rs in root.rglob("*.rs"):
            text = rs.read_text(errors="ignore")
            for m in forbidden_re.finditer(text):
                # Exclude lines that are just "ColumnFamilyDescriptor" (RocksDB)
                line_start = text.rfind("\n", 0, m.start()) + 1
                line_end = text.find("\n", m.end())
                line = text[line_start:line_end if line_end != -1 else len(text)]
                if "ColumnFamilyDescriptor" in line or "cf_descriptors" in line:
                    continue
                hits.append((rs, m.group(0)))

    assert not hits, (
        "BIP-380 descriptor / BIP-379 miniscript code on Rust side — "
        f"two-pipeline drift detected: {hits}"
    )


# ---------------------------------------------------------------------------
# Audit-file presence sanity check (keeps the test file and audit md in sync)
# ---------------------------------------------------------------------------


def test_audit_md_exists_and_has_30_gates():
    """The audit markdown must accompany this test file with all 30 gates listed."""
    audit_md = Path(__file__).resolve().parents[3] / "audit" / "w131_descriptors_miniscript.md"
    assert audit_md.exists(), f"missing {audit_md}"
    text = audit_md.read_text()
    for i in range(1, 31):
        assert f"G{i}" in text, f"audit md missing gate G{i}"
