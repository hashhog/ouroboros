"""
Functional test: script verification flags.

Tests that the script verification flag system correctly activates
rules at the right heights and enforces them properly.
"""

import pytest
from ouroboros.script import (
    get_flags_for_height,
    SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_NULLDUMMY, SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_CLEANSTACK, SCRIPT_VERIFY_SIGPUSHONLY, SCRIPT_VERIFY_TAPROOT,
    BIP16_ACTIVATION_HEIGHT, BIP65_ACTIVATION_HEIGHT, BIP66_ACTIVATION_HEIGHT,
    BIP68_ACTIVATION_HEIGHT, SEGWIT_ACTIVATION_HEIGHT, TAPROOT_ACTIVATION_HEIGHT,
    _check_der_signature, _check_low_s, _is_push_only_simple,
    MAX_SCRIPT_ELEMENT_SIZE,
    ScriptInterpreter,
)


class TestFlagActivation:
    def test_no_flags_before_p2sh(self):
        flags = get_flags_for_height(0)
        assert flags == 0

    def test_p2sh_active(self):
        flags = get_flags_for_height(BIP16_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_P2SH

    def test_dersig_active(self):
        flags = get_flags_for_height(BIP66_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_DERSIG
        assert flags & SCRIPT_VERIFY_LOW_S

    def test_cltv_active(self):
        flags = get_flags_for_height(BIP65_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY

    def test_csv_active(self):
        flags = get_flags_for_height(BIP68_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

    def test_segwit_flags(self):
        flags = get_flags_for_height(SEGWIT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_WITNESS
        assert flags & SCRIPT_VERIFY_NULLDUMMY
        assert flags & SCRIPT_VERIFY_NULLFAIL
        assert flags & SCRIPT_VERIFY_CLEANSTACK
        assert flags & SCRIPT_VERIFY_SIGPUSHONLY

    def test_taproot_active(self):
        flags = get_flags_for_height(TAPROOT_ACTIVATION_HEIGHT)
        assert flags & SCRIPT_VERIFY_TAPROOT


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
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "520" in str(e) or "exceeds" in str(e).lower()
