"""
Functional test: script verification flags.

Tests that the script verification flag system correctly activates
rules at the right heights and enforces them properly.
"""

from ouroboros.script import (
    BIP16_ACTIVATION_HEIGHT,
    BIP65_ACTIVATION_HEIGHT,
    BIP66_ACTIVATION_HEIGHT,
    BIP68_ACTIVATION_HEIGHT,
    MAX_SCRIPT_ELEMENT_SIZE,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_SIGPUSHONLY,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_WITNESS,
    SEGWIT_ACTIVATION_HEIGHT,
    TAPROOT_ACTIVATION_HEIGHT,
    ScriptInterpreter,
    _check_der_signature,
    _is_push_only_simple,
    get_flags_for_height,
    get_standard_script_flags,
)


class TestFlagActivation:
    """
    Tests for get_flags_for_height() (consensus-only flags) and
    get_standard_script_flags() (mempool/policy flags).

    Ref: Bitcoin Core policy/policy.h:105-111 (MANDATORY) vs 119-132 (STANDARD).
    """

    def test_base_flags_are_unconditional(self):
        """P2SH | WITNESS | TAPROOT are seeded for EVERY block, height 0 included.

        UPDATED from `assert get_flags_for_height(0) == 0`, which encoded the
        pre-fix bug.  Core dropped BIP16Height and taprootHeight from
        GetBlockScriptFlags in v23: the base set at validation.cpp:2262 is
        unconditional, and the only two historical violators are handled by
        script_flag_exceptions instead.
        """
        flags = get_flags_for_height(0)
        assert flags == (
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
        )
        # The four height-gated flags are still off at height 0.
        assert not (flags & SCRIPT_VERIFY_DERSIG)
        assert not (flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
        assert not (flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
        assert not (flags & SCRIPT_VERIFY_NULLDUMMY)

    def test_p2sh_active(self):
        flags = get_flags_for_height(BIP16_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_P2SH
        # ...and also well before the old 173805 gate.
        assert get_flags_for_height(1) & SCRIPT_VERIFY_P2SH

    def test_dersig_active(self):
        # DERSIG is consensus; LOW_S is policy-only (not in consensus flags).
        flags = get_flags_for_height(BIP66_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_DERSIG
        assert not (flags & SCRIPT_VERIFY_LOW_S), (
            "LOW_S is policy-only and must NOT be in consensus flags"
        )

    def test_dersig_standard_includes_low_s(self):
        # LOW_S IS in the standard (mempool) flags.
        flags = get_standard_script_flags(BIP66_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_DERSIG
        assert flags & SCRIPT_VERIFY_LOW_S

    def test_cltv_active(self):
        flags = get_flags_for_height(BIP65_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY

    def test_csv_active(self):
        flags = get_flags_for_height(BIP68_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

    def test_segwit_consensus_flags(self):
        # Consensus: WITNESS + NULLDUMMY only.
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_WITNESS
        assert flags & SCRIPT_VERIFY_NULLDUMMY
        # Policy-only flags must NOT be present in consensus path.
        assert not (flags & SCRIPT_VERIFY_NULLFAIL), (
            "NULLFAIL is policy-only and must NOT be in consensus flags"
        )
        assert not (flags & SCRIPT_VERIFY_CLEANSTACK), (
            "CLEANSTACK is policy-only and must NOT be in consensus flags"
        )
        assert not (flags & SCRIPT_VERIFY_SIGPUSHONLY), (
            "SIGPUSHONLY is policy-only and must NOT be in consensus flags"
        )

    def test_segwit_standard_flags(self):
        # Standard (mempool) flags add policy bits on top.
        flags = get_standard_script_flags(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_WITNESS
        assert flags & SCRIPT_VERIFY_NULLDUMMY
        assert flags & SCRIPT_VERIFY_NULLFAIL
        assert flags & SCRIPT_VERIFY_CLEANSTACK
        assert flags & SCRIPT_VERIFY_SIGPUSHONLY

    def test_taproot_active(self):
        flags = get_flags_for_height(TAPROOT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_TAPROOT


class TestScriptFlagExceptions:
    """
    Bitcoin Core `GetBlockScriptFlags()` step 2/3 parity.

    Ref: bitcoin-core/src/validation.cpp:2249-2289 and the exception table at
    kernel/chainparams.cpp:85-88 (mainnet) / :210-211 (testnet3).
    """

    # Display (big-endian) hashes exactly as they appear in chainparams.cpp.
    BIP16_EXCEPTION = (
        "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
    )
    TAPROOT_EXCEPTION = (
        "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
    )
    TESTNET3_EXCEPTION = (
        "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
    )

    @staticmethod
    def _internal(display_hex: str) -> bytes:
        """Display hex -> internal (little-endian) bytes, matching Block.hash."""
        return bytes.fromhex(display_hex)[::-1]

    # -- acceptance criterion 1 ------------------------------------------
    def test_bip16_exception_block_170060_is_verify_none(self):
        """[170060] -> SCRIPT_VERIFY_NONE.

        The exception value is NONE and none of DERSIG/CLTV/CSV/NULLDUMMY are
        active at that height, so step 3 adds nothing.
        """
        flags = get_flags_for_height(
            170060, self._internal(self.BIP16_EXCEPTION), "mainnet"
        )
        assert flags == 0, f"expected SCRIPT_VERIFY_NONE, got {flags:#x}"

    # -- acceptance criterion 2 ------------------------------------------
    def test_taproot_exception_block_692261_keeps_height_gated_flags(self):
        """[692261] -> P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY, TAPROOT stripped.

        This is the regression guard for the early-return bug: returning the
        table value directly would drop all four height-gated flags, which are
        active at 692261, and false-accept scripts Core rejects under
        BIP-66/65/112/147.
        """
        flags = get_flags_for_height(
            692261, self._internal(self.TAPROOT_EXCEPTION), "mainnet"
        )

        expected = (
            SCRIPT_VERIFY_P2SH
            | SCRIPT_VERIFY_WITNESS
            | SCRIPT_VERIFY_DERSIG
            | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
            | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
            | SCRIPT_VERIFY_NULLDUMMY
        )
        assert flags == expected, f"got {flags:#x}, want {expected:#x}"
        assert not (flags & SCRIPT_VERIFY_TAPROOT), "exception must strip TAPROOT"
        assert flags & SCRIPT_VERIFY_DERSIG, "BIP66 is active at 692261"
        assert flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, "BIP65 is active at 692261"
        assert flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, "BIP112 is active at 692261"
        assert flags & SCRIPT_VERIFY_NULLDUMMY, "BIP147 is active at 692261"

    # -- acceptance criterion 3 (the control) -----------------------------
    def test_non_exception_hash_at_692261_keeps_taproot(self):
        """A NON-exception block at 692261 must KEEP TAPROOT.

        The exception is keyed by hash, not by height — a fork block at the
        same height gets no exemption.
        """
        h = bytearray(self._internal(self.TAPROOT_EXCEPTION))
        h[0] ^= 0x01
        flags = get_flags_for_height(692261, bytes(h), "mainnet")

        assert flags & SCRIPT_VERIFY_TAPROOT
        assert flags == (
            SCRIPT_VERIFY_P2SH
            | SCRIPT_VERIFY_WITNESS
            | SCRIPT_VERIFY_TAPROOT
            | SCRIPT_VERIFY_DERSIG
            | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
            | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
            | SCRIPT_VERIFY_NULLDUMMY
        )

    def test_no_block_hash_keeps_taproot_at_692261(self):
        """Omitting the hash skips step 2 entirely — TAPROOT stays on."""
        assert get_flags_for_height(692261, None, "mainnet") & SCRIPT_VERIFY_TAPROOT

    # -- byte-order negative control --------------------------------------
    def test_display_order_hash_does_not_hit_the_table(self):
        """The table is keyed in INTERNAL byte order; display order must miss.

        If someone "fixes" the keys to display order this test fails — and in
        production the real block hashes would stop matching, silently
        disabling both exceptions.
        """
        display_order = bytes.fromhex(self.TAPROOT_EXCEPTION)  # NOT reversed
        flags = get_flags_for_height(692261, display_order, "mainnet")
        assert flags & SCRIPT_VERIFY_TAPROOT, (
            "display-order hash must not hit the exception table"
        )

        display_order = bytes.fromhex(self.BIP16_EXCEPTION)
        assert get_flags_for_height(170060, display_order, "mainnet") != 0

    # -- per-network scoping ----------------------------------------------
    def test_exceptions_are_scoped_per_network(self):
        """testnet3's exception must not fire on mainnet, and vice versa."""
        testnet3_hash = self._internal(self.TESTNET3_EXCEPTION)
        assert get_flags_for_height(211_000, testnet3_hash, "mainnet") != 0

        assert get_flags_for_height(211_000, testnet3_hash, "testnet") == 0

        mainnet_hash = self._internal(self.BIP16_EXCEPTION)
        assert get_flags_for_height(170060, mainnet_hash, "testnet") != 0

    # -- no policy flags ever ---------------------------------------------
    def test_consensus_flags_never_contain_policy_flags(self):
        """STANDARD_SCRIPT_VERIFY_FLAGS must never leak into block validation.

        Ref: bitcoin-core/src/policy/policy.h:125.
        """
        from ouroboros.script import (
            SCRIPT_VERIFY_CONST_SCRIPTCODE,
            SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
            SCRIPT_VERIFY_MINIMALDATA,
            SCRIPT_VERIFY_MINIMALIF,
            SCRIPT_VERIFY_STRICTENC,
            SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
        )

        policy_only = (
            SCRIPT_VERIFY_NULLFAIL
            | SCRIPT_VERIFY_CLEANSTACK
            | SCRIPT_VERIFY_LOW_S
            | SCRIPT_VERIFY_STRICTENC
            | SCRIPT_VERIFY_MINIMALDATA
            | SCRIPT_VERIFY_MINIMALIF
            | SCRIPT_VERIFY_SIGPUSHONLY
            | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
            | SCRIPT_VERIFY_CONST_SCRIPTCODE
            | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
        )

        hashes = [
            None,
            self._internal(self.BIP16_EXCEPTION),
            self._internal(self.TAPROOT_EXCEPTION),
            self._internal(self.TESTNET3_EXCEPTION),
        ]
        for network in ("mainnet", "testnet", "testnet4", "signet", "regtest"):
            for height in (0, 1, 170060, 363725, 481824, 692261, 709632, 900_000):
                for block_hash in hashes:
                    flags = get_flags_for_height(height, block_hash, network)
                    leaked = flags & policy_only
                    assert leaked == 0, (
                        f"policy flags {leaked:#x} leaked at {network}/{height}"
                    )


class TestDERValidation:
    def test_valid_der(self):
        # Properly formed DER signature: 0x30 <len> 0x02 <r_len> <R> 0x02 <s_len> <S> <hashtype>
        r_bytes = bytes(range(1, 33))  # 32 bytes, no leading zero, high bit clear
        s_bytes = bytes(range(33, 65))  # 32 bytes, no leading zero, high bit clear
        inner = b'\x02\x20' + r_bytes + b'\x02\x20' + s_bytes
        sig = b'\x30' + bytes([len(inner)]) + inner + b'\x01'
        assert _check_der_signature(sig)

    def test_invalid_der_short(self):
        assert not _check_der_signature(b'\x30\x06\x02\x01\x01\x02\x01\x01')

    def test_empty_sig_invalid(self):
        assert not _check_der_signature(b'')


class TestPushOnly:
    def test_push_only(self):
        script = b'\x03\x01\x02\x03'  # push 3 bytes
        assert _is_push_only_simple(script)

    def test_non_push_only(self):
        script = b'\x76'  # OP_DUP
        assert not _is_push_only_simple(script)

    def test_op_0_is_push(self):
        script = b'\x00'  # OP_0
        assert _is_push_only_simple(script)

    def test_op_1_through_16(self):
        for op in range(0x51, 0x61):
            assert _is_push_only_simple(bytes([op]))


class TestPushDataLimit:
    def test_max_element_size(self):
        assert MAX_SCRIPT_ELEMENT_SIZE == 520

    def test_oversized_push_rejected(self):
        interp = ScriptInterpreter()
        from ouroboros.database import Transaction, TxIn, TxOut
        tx = Transaction(
            txid=bytes(32), version=2, locktime=0,
            inputs=[TxIn(prev_txid=bytes(32), prev_vout=0,
                         script_sig=b'', sequence=0xFFFFFFFF)],
            outputs=[TxOut(value=0, script_pubkey=b'')],
        )
        # Build a script that pushes 521 bytes
        script = bytes([0x4d]) + (521).to_bytes(2, 'little') + b'\x00' * 521
        try:
            interp._execute_script(script, tx, 0, b'')
            raise AssertionError("Should have raised ValueError")
        except ValueError as e:
            assert "520" in str(e) or "exceeds" in str(e).lower()
