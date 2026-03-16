"""
Tests for miniscript parsing, compilation, and satisfaction analysis.
"""

import hashlib
import pytest

from ouroboros.miniscript import (
    Fragment,
    MiniscriptContext,
    MiniscriptNode,
    MiniscriptType,
    analyze_satisfaction,
    compile_miniscript,
    miniscript_to_str,
    parse_miniscript,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_pubkey1() -> bytes:
    """Sample compressed public key 1."""
    return bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )


@pytest.fixture
def sample_pubkey2() -> bytes:
    """Sample compressed public key 2."""
    return bytes.fromhex(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )


@pytest.fixture
def sample_pubkey3() -> bytes:
    """Sample compressed public key 3."""
    return bytes.fromhex(
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    )


# ---------------------------------------------------------------------------
# Type system tests
# ---------------------------------------------------------------------------


class TestMiniscriptType:
    """Tests for the miniscript type system."""

    def test_type_from_str(self):
        """Test creating types from string."""
        t = MiniscriptType.from_str("Bzonudems")
        assert t.is_B
        assert not t.is_V
        assert "z" in t
        assert "o" in t
        assert "n" in t

    def test_type_union(self):
        """Test type union operator."""
        t1 = MiniscriptType.from_str("Bz")
        t2 = MiniscriptType.from_str("om")
        t3 = t1 | t2
        assert "B" in t3
        assert "z" in t3
        assert "o" in t3
        assert "m" in t3

    def test_type_intersection(self):
        """Test type intersection operator."""
        t1 = MiniscriptType.from_str("Bzom")
        t2 = MiniscriptType.from_str("Bom")
        t3 = t1 & t2
        assert "B" in t3
        assert "o" in t3
        assert "m" in t3
        assert "z" not in t3

    def test_type_containment(self):
        """Test checking if type has properties."""
        t = MiniscriptType.from_str("Bzonudems")
        assert t.has("B")
        assert t.has("z")
        assert t.has("Bz")
        assert not t.has("V")

    def test_type_when(self):
        """Test conditional type."""
        t = MiniscriptType.from_str("Bz")
        assert t.when(True).has("Bz")
        assert not t.when(False).has("B")

    def test_type_validity(self):
        """Test type validity check."""
        valid = MiniscriptType.from_str("Bzonudems")
        assert valid.is_valid

        invalid = MiniscriptType.from_str("BV")  # Can't be both B and V
        assert not invalid.is_valid


# ---------------------------------------------------------------------------
# Parsing tests
# ---------------------------------------------------------------------------


class TestMiniscriptParsing:
    """Tests for miniscript parsing."""

    def test_parse_pk(self, sample_pubkey1):
        """Test parsing pk(KEY)."""
        expr = f"pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        # pk() is syntactic sugar for c:pk_k()
        assert node.fragment == Fragment.WRAP_C
        assert node.subs[0].fragment == Fragment.PK_K
        assert node.subs[0].keys[0] == sample_pubkey1

    def test_parse_pkh(self, sample_pubkey1):
        """Test parsing pkh(KEY)."""
        expr = f"pkh({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        # pkh() is syntactic sugar for c:pk_h()
        assert node.fragment == Fragment.WRAP_C
        assert node.subs[0].fragment == Fragment.PK_H

    def test_parse_older(self):
        """Test parsing older(N)."""
        node = parse_miniscript("older(1000)")
        assert node.fragment == Fragment.OLDER
        assert node.k == 1000

    def test_parse_after(self):
        """Test parsing after(N)."""
        node = parse_miniscript("after(500000)")
        assert node.fragment == Fragment.AFTER
        assert node.k == 500000

    def test_parse_sha256(self):
        """Test parsing sha256(H)."""
        h = "0" * 64
        node = parse_miniscript(f"sha256({h})")
        assert node.fragment == Fragment.SHA256
        assert node.data == bytes.fromhex(h)

    def test_parse_hash256(self):
        """Test parsing hash256(H)."""
        h = "1" * 64
        node = parse_miniscript(f"hash256({h})")
        assert node.fragment == Fragment.HASH256
        assert node.data == bytes.fromhex(h)

    def test_parse_ripemd160(self):
        """Test parsing ripemd160(H)."""
        h = "2" * 40
        node = parse_miniscript(f"ripemd160({h})")
        assert node.fragment == Fragment.RIPEMD160
        assert node.data == bytes.fromhex(h)

    def test_parse_hash160(self):
        """Test parsing hash160(H)."""
        h = "3" * 40
        node = parse_miniscript(f"hash160({h})")
        assert node.fragment == Fragment.HASH160
        assert node.data == bytes.fromhex(h)

    def test_parse_and_v(self, sample_pubkey1, sample_pubkey2):
        """Test parsing and_v(X, Y)."""
        expr = f"and_v(v:pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.AND_V
        assert len(node.subs) == 2

    def test_parse_and_b(self, sample_pubkey1, sample_pubkey2):
        """Test parsing and_b(X, Y)."""
        expr = f"and_b(pk({sample_pubkey1.hex()}),s:pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.AND_B
        assert len(node.subs) == 2

    def test_parse_or_b(self, sample_pubkey1, sample_pubkey2):
        """Test parsing or_b(X, Y)."""
        expr = f"or_b(pk({sample_pubkey1.hex()}),s:pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.OR_B
        assert len(node.subs) == 2

    def test_parse_or_c(self, sample_pubkey1, sample_pubkey2):
        """Test parsing or_c(X, Y)."""
        expr = f"or_c(pk({sample_pubkey1.hex()}),v:pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.OR_C
        assert len(node.subs) == 2

    def test_parse_or_d(self, sample_pubkey1, sample_pubkey2):
        """Test parsing or_d(X, Y)."""
        expr = f"or_d(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.OR_D
        assert len(node.subs) == 2

    def test_parse_or_i(self, sample_pubkey1, sample_pubkey2):
        """Test parsing or_i(X, Y)."""
        expr = f"or_i(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.OR_I
        assert len(node.subs) == 2

    def test_parse_andor(self, sample_pubkey1, sample_pubkey2, sample_pubkey3):
        """Test parsing andor(X, Y, Z)."""
        expr = f"andor(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}),pk({sample_pubkey3.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.ANDOR
        assert len(node.subs) == 3

    def test_parse_thresh(self, sample_pubkey1, sample_pubkey2, sample_pubkey3):
        """Test parsing thresh(k, X1, X2, ...)."""
        expr = f"thresh(2,pk({sample_pubkey1.hex()}),s:pk({sample_pubkey2.hex()}),s:pk({sample_pubkey3.hex()}))"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.THRESH
        assert node.k == 2
        assert len(node.subs) == 3

    def test_parse_multi(self, sample_pubkey1, sample_pubkey2):
        """Test parsing multi(k, key1, key2, ...)."""
        expr = f"multi(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr)
        assert node.fragment == Fragment.MULTI
        assert node.k == 2
        assert len(node.keys) == 2

    def test_parse_multi_a_tapscript(self, sample_pubkey1, sample_pubkey2):
        """Test parsing multi_a(k, key1, ...) in Tapscript context."""
        expr = f"multi_a(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr, MiniscriptContext.TAPSCRIPT)
        assert node.fragment == Fragment.MULTI_A
        assert node.k == 2
        assert len(node.keys) == 2

    def test_parse_wrappers(self, sample_pubkey1):
        """Test parsing wrapper prefixes."""
        # a: wrapper
        node = parse_miniscript(f"a:pk({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_A

        # s: wrapper
        node = parse_miniscript(f"s:pk({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_S

        # d: wrapper
        node = parse_miniscript(f"d:pk_h({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_D

        # v: wrapper
        node = parse_miniscript(f"v:pk({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_V

        # j: wrapper
        node = parse_miniscript(f"j:pk({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_J

        # n: wrapper
        node = parse_miniscript(f"n:pk({sample_pubkey1.hex()})")
        assert node.fragment == Fragment.WRAP_N

    def test_parse_sugar_and_n(self, sample_pubkey1, sample_pubkey2):
        """Test parsing and_n(X, Y) sugar."""
        expr = f"and_n(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        # and_n(X, Y) is andor(X, Y, 0)
        assert node.fragment == Fragment.ANDOR
        assert node.subs[2].fragment == Fragment.JUST_0

    def test_parse_sugar_t(self, sample_pubkey1):
        """Test parsing t:X sugar."""
        expr = f"t:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        # t:X is and_v(X, 1)
        assert node.fragment == Fragment.AND_V
        assert node.subs[1].fragment == Fragment.JUST_1

    def test_parse_sugar_l(self, sample_pubkey1):
        """Test parsing l:X sugar."""
        expr = f"l:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        # l:X is or_i(0, X)
        assert node.fragment == Fragment.OR_I
        assert node.subs[0].fragment == Fragment.JUST_0

    def test_parse_sugar_u(self, sample_pubkey1):
        """Test parsing u:X sugar."""
        expr = f"u:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        # u:X is or_i(X, 0)
        assert node.fragment == Fragment.OR_I
        assert node.subs[1].fragment == Fragment.JUST_0


# ---------------------------------------------------------------------------
# Compilation tests
# ---------------------------------------------------------------------------


class TestMiniscriptCompilation:
    """Tests for miniscript to Bitcoin Script compilation."""

    def test_compile_pk(self, sample_pubkey1):
        """Test compiling pk(KEY)."""
        node = parse_miniscript(f"pk({sample_pubkey1.hex()})")
        script = compile_miniscript(node)
        # pk() compiles to <pubkey> OP_CHECKSIG
        assert script == bytes([33]) + sample_pubkey1 + bytes([0xAC])

    def test_compile_pkh(self, sample_pubkey1):
        """Test compiling pkh(KEY)."""
        node = parse_miniscript(f"pkh({sample_pubkey1.hex()})")
        script = compile_miniscript(node)
        # pkh() compiles to OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY OP_CHECKSIG
        keyhash = hashlib.new("ripemd160", hashlib.sha256(sample_pubkey1).digest()).digest()
        expected = bytes([0x76, 0xA9, 20]) + keyhash + bytes([0x88, 0xAC])
        assert script == expected

    def test_compile_older(self):
        """Test compiling older(N)."""
        node = parse_miniscript("older(1000)")
        script = compile_miniscript(node)
        # older(1000) compiles to <1000> OP_CHECKSEQUENCEVERIFY
        assert script.endswith(bytes([0xB2]))  # OP_CHECKSEQUENCEVERIFY

    def test_compile_after(self):
        """Test compiling after(N)."""
        node = parse_miniscript("after(500000)")
        script = compile_miniscript(node)
        # after(500000) compiles to <500000> OP_CHECKLOCKTIMEVERIFY
        assert script.endswith(bytes([0xB1]))  # OP_CHECKLOCKTIMEVERIFY

    def test_compile_sha256(self):
        """Test compiling sha256(H)."""
        h = "0" * 64
        node = parse_miniscript(f"sha256({h})")
        script = compile_miniscript(node)
        # sha256(H) compiles to OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUAL
        assert bytes([0xA8]) in script  # OP_SHA256
        assert bytes([0x87]) in script  # OP_EQUAL

    def test_compile_and_v(self, sample_pubkey1, sample_pubkey2):
        """Test compiling and_v(X, Y)."""
        expr = f"and_v(v:pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        script = compile_miniscript(node)
        # Should contain both pubkeys
        assert sample_pubkey1 in script
        assert sample_pubkey2 in script

    def test_compile_or_i(self, sample_pubkey1, sample_pubkey2):
        """Test compiling or_i(X, Y)."""
        expr = f"or_i(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        script = compile_miniscript(node)
        # Should have OP_IF, OP_ELSE, OP_ENDIF structure
        assert bytes([0x63]) in script  # OP_IF
        assert bytes([0x67]) in script  # OP_ELSE
        assert bytes([0x68]) in script  # OP_ENDIF

    def test_compile_multi(self, sample_pubkey1, sample_pubkey2):
        """Test compiling multi(k, keys...)."""
        expr = f"multi(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr)
        script = compile_miniscript(node)
        # Should end with OP_CHECKMULTISIG
        assert script.endswith(bytes([0xAE]))
        # Should contain both pubkeys
        assert sample_pubkey1 in script
        assert sample_pubkey2 in script

    def test_compile_multi_a_tapscript(self, sample_pubkey1, sample_pubkey2):
        """Test compiling multi_a(k, keys...) for Tapscript."""
        expr = f"multi_a(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr, MiniscriptContext.TAPSCRIPT)
        script = compile_miniscript(node, MiniscriptContext.TAPSCRIPT)
        # Should contain OP_CHECKSIG, OP_CHECKSIGADD, and OP_NUMEQUAL
        assert bytes([0xAC]) in script  # OP_CHECKSIG
        assert bytes([0xBA]) in script  # OP_CHECKSIGADD
        assert bytes([0x9C]) in script  # OP_NUMEQUAL


# ---------------------------------------------------------------------------
# Roundtrip tests
# ---------------------------------------------------------------------------


class TestMiniscriptRoundtrip:
    """Tests for miniscript parsing and stringification roundtrip."""

    def test_roundtrip_pk(self, sample_pubkey1):
        """Test roundtrip for pk(KEY)."""
        expr = f"pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_older(self):
        """Test roundtrip for older(N)."""
        expr = "older(1000)"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_after(self):
        """Test roundtrip for after(N)."""
        expr = "after(500000)"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_and_n_sugar(self, sample_pubkey1, sample_pubkey2):
        """Test that and_n sugar is preserved."""
        expr = f"and_n(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_t_sugar(self, sample_pubkey1):
        """Test that t: sugar is preserved."""
        expr = f"t:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_l_sugar(self, sample_pubkey1):
        """Test that l: sugar is preserved."""
        expr = f"l:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr

    def test_roundtrip_u_sugar(self, sample_pubkey1):
        """Test that u: sugar is preserved."""
        expr = f"u:pk({sample_pubkey1.hex()})"
        node = parse_miniscript(expr)
        result = miniscript_to_str(node)
        assert result == expr


# ---------------------------------------------------------------------------
# Type checking tests
# ---------------------------------------------------------------------------


class TestMiniscriptTypes:
    """Tests for miniscript type computation."""

    def test_pk_type(self, sample_pubkey1):
        """Test that pk(KEY) has type Bsxdnumk (via c:pk_k which is Bonudemsxk)."""
        node = parse_miniscript(f"pk({sample_pubkey1.hex()})")
        t = node.get_type()
        assert t.is_B
        assert "s" in t  # safe (requires signature)
        assert "u" in t  # unit

    def test_older_type(self):
        """Test that older(N) has type Bzfmxhk or Bzfmxgk."""
        node = parse_miniscript("older(1000)")
        t = node.get_type()
        assert t.is_B
        assert "z" in t  # zero-arg
        assert "f" in t  # forced
        assert "m" in t  # nonmalleable

    def test_and_v_type(self, sample_pubkey1, sample_pubkey2):
        """Test and_v type computation."""
        expr = f"and_v(v:pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        t = node.get_type()
        # and_v(V, B) produces B
        assert t.is_B

    def test_or_i_type(self, sample_pubkey1, sample_pubkey2):
        """Test or_i type computation."""
        expr = f"or_i(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        t = node.get_type()
        # or_i(B, B) produces B
        assert t.is_B

    def test_multi_type(self, sample_pubkey1, sample_pubkey2):
        """Test multi type."""
        expr = f"multi(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr)
        t = node.get_type()
        assert t.is_B
        assert "n" in t  # nonzero
        assert "s" in t  # safe


# ---------------------------------------------------------------------------
# Satisfaction analysis tests
# ---------------------------------------------------------------------------


class TestMiniscriptSatisfaction:
    """Tests for miniscript satisfaction analysis."""

    def test_pk_satisfaction(self, sample_pubkey1):
        """Test satisfaction size for pk(KEY)."""
        node = parse_miniscript(f"pk({sample_pubkey1.hex()})")
        info = analyze_satisfaction(node)
        # P2WSH: 72-byte ECDSA signature + 1 byte length = 73
        assert info.sat_size == 73
        assert info.has_sig

    def test_pkh_satisfaction(self, sample_pubkey1):
        """Test satisfaction size for pkh(KEY)."""
        node = parse_miniscript(f"pkh({sample_pubkey1.hex()})")
        info = analyze_satisfaction(node)
        # sig + pubkey (73 + 34 = 107)
        assert info.sat_size == 73 + 34
        assert info.has_sig

    def test_multi_satisfaction(self, sample_pubkey1, sample_pubkey2):
        """Test satisfaction size for multi(2, K1, K2)."""
        expr = f"multi(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})"
        node = parse_miniscript(expr)
        info = analyze_satisfaction(node)
        # 2 signatures + dummy element for CHECKMULTISIG bug
        # 2 * 73 + 1 = 147
        assert info.sat_size == 147
        assert info.has_sig

    def test_older_satisfaction(self):
        """Test satisfaction size for older(N)."""
        node = parse_miniscript("older(1000)")
        info = analyze_satisfaction(node)
        # No witness data needed
        assert info.sat_size == 0
        # Cannot be dissatisfied
        assert info.dsat_size is None

    def test_or_i_satisfaction(self, sample_pubkey1, sample_pubkey2):
        """Test satisfaction size for or_i(X, Y)."""
        expr = f"or_i(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()}))"
        node = parse_miniscript(expr)
        info = analyze_satisfaction(node)
        # Minimum of two branches plus selector element
        # Either branch: 73 (sig) + 1 (selector) = 74 or 75
        assert info.sat_size is not None
        assert info.sat_size > 0


# ---------------------------------------------------------------------------
# Descriptor integration tests
# ---------------------------------------------------------------------------


class TestMiniscriptDescriptors:
    """Tests for miniscript integration with descriptors."""

    def test_wsh_miniscript_parse(self, sample_pubkey1):
        """Test parsing wsh(miniscript)."""
        from ouroboros.descriptors import parse_descriptor

        expr = f"wsh(pk({sample_pubkey1.hex()}))"
        desc = parse_descriptor(expr)
        assert desc.descriptor_type == "wsh-miniscript"
        assert desc.miniscript_expr is not None

    def test_wsh_miniscript_script(self, sample_pubkey1):
        """Test deriving scriptPubKey from wsh(miniscript)."""
        from ouroboros.descriptors import parse_descriptor

        expr = f"wsh(pk({sample_pubkey1.hex()}))"
        desc = parse_descriptor(expr)
        spk = desc.derive_script_pubkey()
        # P2WSH: OP_0 <32-byte hash>
        assert len(spk) == 34
        assert spk[0] == 0x00
        assert spk[1] == 0x20

    def test_wsh_and_v_miniscript(self, sample_pubkey1, sample_pubkey2):
        """Test wsh with and_v miniscript."""
        from ouroboros.descriptors import parse_descriptor

        expr = f"wsh(and_v(v:pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()})))"
        desc = parse_descriptor(expr)
        assert desc.descriptor_type == "wsh-miniscript"
        spk = desc.derive_script_pubkey()
        assert len(spk) == 34

    def test_wsh_or_miniscript(self, sample_pubkey1, sample_pubkey2):
        """Test wsh with or_i miniscript."""
        from ouroboros.descriptors import parse_descriptor

        expr = f"wsh(or_i(pk({sample_pubkey1.hex()}),pk({sample_pubkey2.hex()})))"
        desc = parse_descriptor(expr)
        assert desc.descriptor_type == "wsh-miniscript"
        spk = desc.derive_script_pubkey()
        assert len(spk) == 34

    def test_wsh_satisfaction_size(self, sample_pubkey1):
        """Test getting satisfaction size from descriptor."""
        from ouroboros.descriptors import parse_descriptor

        expr = f"wsh(pk({sample_pubkey1.hex()}))"
        desc = parse_descriptor(expr)
        size = desc.get_miniscript_satisfaction_size()
        assert size == 73  # 72-byte sig + 1 byte length


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestMiniscriptErrors:
    """Tests for miniscript error handling."""

    def test_invalid_older_value(self):
        """Test that older() rejects invalid values."""
        with pytest.raises(ValueError):
            parse_miniscript("older(0)")  # Must be >= 1

        with pytest.raises(ValueError):
            parse_miniscript("older(2147483648)")  # Must be < 0x80000000

    def test_invalid_after_value(self):
        """Test that after() rejects invalid values."""
        with pytest.raises(ValueError):
            parse_miniscript("after(0)")

    def test_invalid_multi_threshold(self, sample_pubkey1, sample_pubkey2):
        """Test that multi() rejects invalid thresholds."""
        with pytest.raises(ValueError):
            parse_miniscript(f"multi(0,{sample_pubkey1.hex()},{sample_pubkey2.hex()})")

        with pytest.raises(ValueError):
            parse_miniscript(f"multi(3,{sample_pubkey1.hex()},{sample_pubkey2.hex()})")

    def test_multi_in_tapscript(self, sample_pubkey1, sample_pubkey2):
        """Test that multi() is rejected in Tapscript context."""
        with pytest.raises(ValueError):
            parse_miniscript(
                f"multi(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})",
                MiniscriptContext.TAPSCRIPT
            )

    def test_multi_a_in_p2wsh(self, sample_pubkey1, sample_pubkey2):
        """Test that multi_a() is rejected in P2WSH context."""
        with pytest.raises(ValueError):
            parse_miniscript(
                f"multi_a(2,{sample_pubkey1.hex()},{sample_pubkey2.hex()})",
                MiniscriptContext.P2WSH
            )

    def test_invalid_hash_length(self):
        """Test that hash functions reject wrong-length hashes."""
        with pytest.raises(ValueError):
            parse_miniscript("sha256(abcd)")  # Too short

        with pytest.raises(ValueError):
            parse_miniscript("ripemd160(" + "0" * 64 + ")")  # Wrong length (32 vs 20)

    def test_unknown_fragment(self):
        """Test that unknown fragments are rejected."""
        with pytest.raises(ValueError):
            parse_miniscript("unknown()")
