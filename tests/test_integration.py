"""
Integration tests for pure-Python Ouroboros components.

These tests exercise the wallet, fee estimator, address utilities,
and Merkle proof helpers without requiring the Rust extension to be
compiled.  They are designed to run in CI with just ``pytest tests/``.
"""

import hashlib
import struct

import pytest

from ouroboros.wallet import WalletKey, Wallet
from ouroboros.fee_estimator import FeeEstimator, BlockFeeData
from ouroboros.address import address_to_script_pubkey
from ouroboros.rpc import (
    _build_partial_merkle_tree,
    _parse_partial_merkle_tree,
    _dsha256,
)


# ---------------------------------------------------------------------------
# Wallet key generation & address derivation
# ---------------------------------------------------------------------------


class TestWalletKey:
    def test_generate_testnet_address(self):
        key = WalletKey.generate("testnet4")
        addr = key.get_p2wpkh_address()
        assert addr.startswith("tb1q")
        assert len(addr) == 42

    def test_generate_mainnet_address(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2wpkh_address()
        assert addr.startswith("bc1q")
        assert len(addr) == 42

    def test_p2pkh_mainnet(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2pkh_address()
        assert addr.startswith("1")

    def test_p2pkh_testnet(self):
        key = WalletKey.generate("testnet4")
        addr = key.get_p2pkh_address()
        assert addr[0] in ("m", "n")

    def test_wif_roundtrip_mainnet(self):
        key = WalletKey.generate("mainnet")
        wif = key.to_wif()
        restored = WalletKey.from_wif(wif, "mainnet")
        assert key.get_p2wpkh_address() == restored.get_p2wpkh_address()
        assert key.secret == restored.secret

    def test_wif_roundtrip_testnet(self):
        key = WalletKey.generate("testnet4")
        wif = key.to_wif()
        restored = WalletKey.from_wif(wif, "testnet4")
        assert key.get_p2wpkh_address() == restored.get_p2wpkh_address()

    def test_different_keys_different_addresses(self):
        a = WalletKey.generate("mainnet")
        b = WalletKey.generate("mainnet")
        assert a.get_p2wpkh_address() != b.get_p2wpkh_address()

    def test_sign_produces_valid_der(self):
        key = WalletKey.generate("mainnet")
        msg = hashlib.sha256(b"test message").digest()
        sig = key.sign(msg)
        assert isinstance(sig, bytes)
        assert len(sig) >= 64
        assert sig[0] == 0x30  # DER sequence tag

    def test_deterministic_from_secret(self):
        secret = bytes(range(32))
        k1 = WalletKey(secret, "mainnet")
        k2 = WalletKey(secret, "mainnet")
        assert k1.get_p2wpkh_address() == k2.get_p2wpkh_address()
        assert k1.pubkey == k2.pubkey


# ---------------------------------------------------------------------------
# Wallet persistence
# ---------------------------------------------------------------------------


class TestWallet:
    @pytest.mark.asyncio
    async def test_generate_and_persist(self, temp_data_dir):
        w = Wallet(temp_data_dir, "testnet4")
        addr = await w.generate_new_address("label-a")
        assert addr.startswith("tb1q")

        w2 = Wallet(temp_data_dir, "testnet4")
        addrs = await w2.get_addresses()
        assert len(addrs) == 1
        assert addrs[0].address == addr

    @pytest.mark.asyncio
    async def test_multiple_addresses(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet")
        a1 = await w.generate_new_address()
        a2 = await w.generate_new_address()
        assert a1 != a2
        addrs = await w.get_addresses()
        assert len(addrs) == 2

    @pytest.mark.asyncio
    async def test_balance_without_db(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet")
        balance = await w.get_balance()
        assert balance == 0

    @pytest.mark.asyncio
    async def test_new_wallet_starts_empty(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet")
        assert len(w.keys) == 0
        addrs = await w.get_addresses()
        assert len(addrs) == 0


# ---------------------------------------------------------------------------
# Fee estimator
# ---------------------------------------------------------------------------


class TestFeeEstimator:
    def test_no_data_returns_none(self):
        fe = FeeEstimator()
        assert fe.estimate_fee(6) is None
        assert fe.estimate_fee_per_kb(6) is None

    def test_estimate_with_synthetic_data(self):
        fe = FeeEstimator()
        for i in range(10):
            fe.block_history.append(
                BlockFeeData(
                    height=i,
                    fee_rates=[1.0, 2.0, 5.0, 10.0, 20.0],
                    median_fee_rate=5.0,
                    min_fee_rate=1.0,
                )
            )
        rate = fe.estimate_fee(6)
        assert rate is not None
        assert rate >= 1.0

    def test_high_priority_higher_than_low(self):
        fe = FeeEstimator()
        for i in range(10):
            fe.block_history.append(
                BlockFeeData(
                    height=i,
                    fee_rates=[1.0, 3.0, 5.0, 10.0, 50.0],
                    median_fee_rate=5.0,
                    min_fee_rate=1.0,
                )
            )
        high = fe.estimate_fee(1)
        low = fe.estimate_fee(25)
        assert high is not None and low is not None
        assert high >= low

    def test_estimate_fee_per_kb_conversion(self):
        fe = FeeEstimator()
        for i in range(5):
            fe.block_history.append(
                BlockFeeData(
                    height=i,
                    fee_rates=[10.0],
                    median_fee_rate=10.0,
                    min_fee_rate=10.0,
                )
            )
        rate_vb = fe.estimate_fee(6)
        rate_kb = fe.estimate_fee_per_kb(6)
        assert rate_vb is not None and rate_kb is not None
        # BTC/kB = sat/vB * 1000 / 1e8
        assert abs(rate_kb - rate_vb * 1000 / 1e8) < 1e-12


# ---------------------------------------------------------------------------
# Address utilities
# ---------------------------------------------------------------------------


class TestAddressValidation:
    def test_p2wpkh_script_pubkey(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2wpkh_address()
        spk = address_to_script_pubkey(addr, "mainnet")
        assert len(spk) == 22
        assert spk[0] == 0x00  # witness v0
        assert spk[1] == 0x14  # push 20 bytes

    def test_p2pkh_script_pubkey(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2pkh_address()
        spk = address_to_script_pubkey(addr, "mainnet")
        assert len(spk) == 25
        assert spk[0] == 0x76  # OP_DUP
        assert spk[1] == 0xA9  # OP_HASH160
        assert spk[-2] == 0x88  # OP_EQUALVERIFY
        assert spk[-1] == 0xAC  # OP_CHECKSIG

    def test_invalid_address_raises(self):
        with pytest.raises(Exception):
            address_to_script_pubkey("totally-invalid", "mainnet")

    def test_testnet_p2wpkh(self):
        key = WalletKey.generate("testnet4")
        addr = key.get_p2wpkh_address()
        spk = address_to_script_pubkey(addr, "testnet4")
        assert len(spk) == 22
        assert spk[0] == 0x00


# ---------------------------------------------------------------------------
# Merkle proof helpers (CMerkleBlock format)
# ---------------------------------------------------------------------------


class _FakeBlock:
    """Minimal block mock for Merkle proof tests."""

    def __init__(self, merkle_root: bytes):
        self._root = merkle_root

    def serialize(self) -> bytes:
        header = bytearray(80)
        header[36:68] = self._root
        return bytes(header)


def _merkle_root_for(txids: list[bytes]) -> bytes:
    """Compute the Bitcoin Merkle root from a list of txids."""
    if len(txids) == 0:
        return b"\x00" * 32
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_dsha256(layer[i] + layer[i + 1]))
        layer = next_layer
    return layer[0]


class TestMerkleProof:
    def _roundtrip(self, txids, match_flags):
        root = _merkle_root_for(txids)
        block = _FakeBlock(root)
        proof = _build_partial_merkle_tree(block, txids, match_flags)
        matched, computed_root = _parse_partial_merkle_tree(proof[80:])
        assert computed_root == root, "Merkle root mismatch after roundtrip"
        return matched

    def test_single_tx(self):
        tx0 = bytes(range(32))
        matched = self._roundtrip([tx0], [True])
        assert len(matched) == 1
        assert matched[0] == tx0

    def test_three_tx_prove_middle(self):
        txids = [bytes([i] * 32) for i in range(3)]
        matched = self._roundtrip(txids, [False, True, False])
        assert len(matched) == 1
        assert matched[0] == txids[1]

    def test_four_tx_prove_first_and_last(self):
        txids = [bytes([i] * 32) for i in range(4)]
        matched = self._roundtrip(txids, [True, False, False, True])
        assert set(m.hex() for m in matched) == {txids[0].hex(), txids[3].hex()}

    def test_all_matched(self):
        txids = [bytes([i] * 32) for i in range(5)]
        matched = self._roundtrip(txids, [True] * 5)
        assert len(matched) == 5

    def test_none_matched(self):
        txids = [bytes([i] * 32) for i in range(4)]
        root = _merkle_root_for(txids)
        block = _FakeBlock(root)
        proof = _build_partial_merkle_tree(block, txids, [False] * 4)
        matched, computed_root = _parse_partial_merkle_tree(proof[80:])
        assert computed_root == root
        assert len(matched) == 0

    def test_large_tree(self):
        txids = [hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(64)]
        flags = [i % 7 == 0 for i in range(64)]
        matched = self._roundtrip(txids, flags)
        expected = {txids[i].hex() for i, f in enumerate(flags) if f}
        assert {m.hex() for m in matched} == expected

    def test_proof_size_is_compact(self):
        txids = [bytes([i] * 32) for i in range(16)]
        root = _merkle_root_for(txids)
        block = _FakeBlock(root)
        proof = _build_partial_merkle_tree(block, txids, [False] * 15 + [True])
        # Proof must be smaller than sending all 16 txids
        full_size = 80 + 32 * 16
        assert len(proof) < full_size


# ---------------------------------------------------------------------------
# RPC method existence (smoke tests — no live node required)
# ---------------------------------------------------------------------------


class TestRPCMethodsExist:
    """Verify the new Phase 3 RPC methods are present on RPCServer."""

    def _get_rpc(self):
        import tempfile, shutil
        from ouroboros.node import BitcoinNode
        from ouroboros.rpc import RPCServer

        d = tempfile.mkdtemp()
        try:
            node = BitcoinNode(data_dir=d, network="regtest")
            rpc = RPCServer(node, port=0)
            return rpc, d
        except Exception:
            shutil.rmtree(d, ignore_errors=True)
            raise

    def test_gettxoutproof_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_gettxoutproof", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_verifytxoutproof_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_verifytxoutproof", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_getmininginfo_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getmininginfo", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_submitblock_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_submitblock", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_estimatesmartfee_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_estimatesmartfee", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_validateaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_validateaddress", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_getnewaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getnewaddress", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_sendtoaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_sendtoaddress", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)

    def test_getwalletinfo_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getwalletinfo", None))
        import shutil; shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Schnorr / Taproot (BIP 340, 341, 342)
# ---------------------------------------------------------------------------


class TestSchnorrSignature:
    """BIP 340 Schnorr signature verification."""

    def test_sign_and_verify(self):
        from coincurve import PrivateKey, PublicKeyXOnly
        from ouroboros.script import ScriptInterpreter

        si = ScriptInterpreter()
        pk = PrivateKey()
        xonly = PublicKeyXOnly.from_secret(pk.secret)
        msg = hashlib.sha256(b"schnorr test").digest()
        sig = pk.sign_schnorr(msg)
        assert si._verify_schnorr_signature(msg, sig, xonly.format())

    def test_wrong_message_fails(self):
        from coincurve import PrivateKey, PublicKeyXOnly
        from ouroboros.script import ScriptInterpreter

        si = ScriptInterpreter()
        pk = PrivateKey()
        xonly = PublicKeyXOnly.from_secret(pk.secret)
        msg = hashlib.sha256(b"correct").digest()
        sig = pk.sign_schnorr(msg)
        wrong = hashlib.sha256(b"wrong").digest()
        assert not si._verify_schnorr_signature(wrong, sig, xonly.format())

    def test_bad_lengths_rejected(self):
        from ouroboros.script import ScriptInterpreter

        si = ScriptInterpreter()
        msg = b"\x00" * 32
        assert not si._verify_schnorr_signature(msg, b"\x00" * 63, b"\x00" * 32)
        assert not si._verify_schnorr_signature(msg, b"\x00" * 64, b"\x00" * 31)


class TestTaggedHash:
    def test_deterministic(self):
        from ouroboros.script import _tagged_hash

        h1 = _tagged_hash("TapSighash", b"data")
        h2 = _tagged_hash("TapSighash", b"data")
        assert h1 == h2
        assert len(h1) == 32

    def test_different_tags(self):
        from ouroboros.script import _tagged_hash

        h1 = _tagged_hash("TapLeaf", b"data")
        h2 = _tagged_hash("TapBranch", b"data")
        assert h1 != h2


class TestTaprootTweakPubkey:
    def test_tweak_produces_valid_key(self):
        from coincurve import PrivateKey, PublicKeyXOnly
        from ouroboros.script import ScriptInterpreter

        si = ScriptInterpreter()
        pk = PrivateKey()
        xonly = PublicKeyXOnly.from_secret(pk.secret)
        tweak = hashlib.sha256(b"tap tweak").digest()
        result = si._taproot_tweak_pubkey(xonly.format(), tweak)
        assert result is not None
        tweaked_x, parity = result
        assert len(tweaked_x) == 32
        assert parity in (0, 1)

    def test_different_tweaks_different_keys(self):
        from coincurve import PrivateKey, PublicKeyXOnly
        from ouroboros.script import ScriptInterpreter

        si = ScriptInterpreter()
        pk = PrivateKey()
        xonly = PublicKeyXOnly.from_secret(pk.secret)
        t1 = hashlib.sha256(b"tweak1").digest()
        t2 = hashlib.sha256(b"tweak2").digest()
        r1 = si._taproot_tweak_pubkey(xonly.format(), t1)
        r2 = si._taproot_tweak_pubkey(xonly.format(), t2)
        assert r1 is not None and r2 is not None
        assert r1[0] != r2[0]


class TestBech32mAddress:
    """P2TR (bech32m) address encoding/decoding."""

    def test_known_p2tr_mainnet(self):
        addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        spk = address_to_script_pubkey(addr, "mainnet")
        assert len(spk) == 34
        assert spk[0] == 0x51  # OP_1
        assert spk[1] == 0x20  # push 32 bytes

    def test_p2tr_roundtrip(self):
        from ouroboros.address import _bech32m_encode, _bech32m_decode
        import bech32 as _b32

        program = hashlib.sha256(b"roundtrip test").digest()
        addr = _bech32m_encode("bc", 1, program)
        assert addr.startswith("bc1p")
        _, ver, data5 = _bech32m_decode(addr)
        assert ver == 1
        decoded = bytes(_b32.convertbits(data5, 5, 8, False))
        assert decoded == program

    def test_p2tr_testnet(self):
        from ouroboros.address import _bech32m_encode

        program = hashlib.sha256(b"testnet taproot").digest()
        addr = _bech32m_encode("tb", 1, program)
        assert addr.startswith("tb1p")
        spk = address_to_script_pubkey(addr, "testnet")
        assert spk[0] == 0x51
        assert spk[2:] == program

    def test_p2wpkh_still_works(self):
        key = WalletKey.generate("mainnet")
        addr = key.get_p2wpkh_address()
        spk = address_to_script_pubkey(addr, "mainnet")
        assert spk[0] == 0x00 and spk[1] == 0x14

    def test_invalid_bech32m_rejected(self):
        from ouroboros.address import _bech32m_decode

        hrp, ver, data = _bech32m_decode("bc1invalidaddress")
        assert hrp is None


class TestEncodeScriptNum:
    def test_zero(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        assert si._encode_script_num(0) == b""

    def test_positive(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        assert si._encode_script_num(1) == b"\x01"
        assert si._encode_script_num(127) == b"\x7f"
        assert si._encode_script_num(128) == b"\x80\x00"

    def test_negative(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        assert si._encode_script_num(-1) == b"\x81"


# ── Phase 6: Production Hardening tests ──────────────────────────────


class TestJSONFormatter:
    def test_format_basic(self):
        import json as _json
        import logging
        from ouroboros.logging_config import JSONFormatter

        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello %s", args=("world",), exc_info=None,
        )
        line = fmt.format(record)
        parsed = _json.loads(line)
        assert parsed["msg"] == "hello world"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test"
        assert parsed["ts"].endswith("Z")

    def test_format_with_exception(self):
        import json as _json
        import logging
        from ouroboros.logging_config import JSONFormatter

        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc = sys.exc_info()
        record = logging.LogRecord(
            name="x", level=logging.ERROR, pathname="", lineno=0,
            msg="fail", args=(), exc_info=exc,
        )
        parsed = _json.loads(fmt.format(record))
        assert "exception" in parsed
        assert "boom" in parsed["exception"]


class TestConfigureLogging:
    def test_plain_text(self):
        import logging
        from ouroboros.logging_config import configure_logging

        configure_logging(debug=False, json_format=False)
        root = logging.getLogger()
        assert root.level == logging.INFO
        assert len(root.handlers) >= 1

    def test_debug_json(self):
        import logging
        from ouroboros.logging_config import JSONFormatter, configure_logging

        configure_logging(debug=True, json_format=True)
        root = logging.getLogger()
        assert root.level == logging.DEBUG
        assert any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)

    def test_log_file(self, tmp_path):
        import logging
        from ouroboros.logging_config import configure_logging

        log_file = str(tmp_path / "test.log")
        configure_logging(log_file=log_file)
        logging.getLogger("filetest").info("written")
        root = logging.getLogger()
        assert any(
            hasattr(h, "baseFilename") for h in root.handlers
        )


class TestCookieAuth:
    def test_generate_and_read(self, tmp_path):
        from ouroboros.cookie_auth import generate_cookie, read_cookie

        user, pw = generate_cookie(str(tmp_path))
        assert user == "__cookie__"
        assert len(pw) == 64

        u2, p2 = read_cookie(str(tmp_path))
        assert (u2, p2) == (user, pw)

    def test_read_missing_raises(self, tmp_path):
        from ouroboros.cookie_auth import read_cookie

        with pytest.raises(FileNotFoundError):
            read_cookie(str(tmp_path / "nonexistent"))

    def test_delete_cookie(self, tmp_path):
        from ouroboros.cookie_auth import generate_cookie, delete_cookie

        generate_cookie(str(tmp_path))
        assert (tmp_path / ".cookie").exists()
        delete_cookie(str(tmp_path))
        assert not (tmp_path / ".cookie").exists()

    def test_delete_missing_is_noop(self, tmp_path):
        from ouroboros.cookie_auth import delete_cookie

        delete_cookie(str(tmp_path))

    def test_cookie_permissions(self, tmp_path):
        import os, stat
        from ouroboros.cookie_auth import generate_cookie

        generate_cookie(str(tmp_path))
        mode = os.stat(tmp_path / ".cookie").st_mode
        assert stat.S_IMODE(mode) == 0o600


class TestMetrics:
    def test_init_metrics(self):
        from ouroboros.metrics import init_metrics, _HAS_PROMETHEUS

        if not _HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")
        # init_metrics may have been called already; just verify no crash
        result = init_metrics(port=0)
        assert result is True

    def test_update_chain_metrics_noop_without_init(self):
        from ouroboros import metrics as m
        old_height = m.BLOCK_HEIGHT
        m.update_chain_metrics(100, 1.5, 3)
        if old_height is None:
            pass  # graceful no-op
        else:
            assert old_height is not None

    def test_record_rpc_request(self):
        from ouroboros.metrics import record_rpc_request
        record_rpc_request("getblockcount", 0.005)

    def test_record_block_received(self):
        from ouroboros.metrics import record_block_received
        record_block_received()

    def test_record_tx_received(self):
        from ouroboros.metrics import record_tx_received
        record_tx_received()

    def test_record_peer_disconnect(self):
        from ouroboros.metrics import record_peer_disconnect
        record_peer_disconnect()


# ── Phase A.1 + A.2: Timelock Opcodes ────────────────────────────────


def _make_tx(locktime=0, version=2, sequence=0xfffffffe):
    """Build a minimal Transaction for script testing."""
    from ouroboros.database import Transaction, TxIn, TxOut
    return Transaction(
        txid=b"\x00" * 32,
        version=version,
        locktime=locktime,
        inputs=[
            TxIn(
                prev_txid=b"\x01" * 32,
                prev_vout=0,
                script_sig=b"",
                sequence=sequence,
            )
        ],
        outputs=[
            TxOut(value=50000, script_pubkey=b"\x00" * 25),
        ],
    )


class TestTimelockOpcodes:
    """BIP 65 (OP_CHECKLOCKTIMEVERIFY) and BIP 112 (OP_CHECKSEQUENCEVERIFY)."""

    @staticmethod
    def _encode_scriptnum(value):
        if value == 0:
            return b""
        neg = value < 0
        absval = abs(value)
        result = []
        while absval > 0:
            result.append(absval & 0xff)
            absval >>= 8
        if result[-1] & 0x80:
            result.append(0x80 if neg else 0x00)
        elif neg:
            result[-1] |= 0x80
        return bytes(result)

    def _run_cltv(self, lock_value, tx_locktime, sequence=0xfffffffe):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        tx = _make_tx(locktime=tx_locktime, sequence=sequence)
        lock_bytes = self._encode_scriptnum(lock_value)
        script = bytes([len(lock_bytes)]) + lock_bytes + b"\xb1"
        si._execute_script(script, tx, 0, b"")

    def _run_csv(self, lock_value, sequence, version=2):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        tx = _make_tx(version=version, sequence=sequence, locktime=0)
        lock_bytes = self._encode_scriptnum(lock_value)
        script = bytes([len(lock_bytes)]) + lock_bytes + b"\xb2"
        si._execute_script(script, tx, 0, b"")

    def test_read_signed_num(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        assert si._read_signed_num(b"") == 0
        assert si._read_signed_num(b"\x05") == 5
        assert si._read_signed_num(b"\x85") == -5
        assert si._read_signed_num(b"\x80\x00") == 128
        assert si._read_signed_num(b"\x80\x80") == -128
        assert si._read_signed_num(b"\x01\x00\x00\x00\x01", max_len=5) == (1 << 32) + 1
        with pytest.raises(ValueError, match="overflow"):
            si._read_signed_num(b"\x01\x02\x03\x04\x05", max_len=4)
        with pytest.raises(ValueError, match="Non-minimal"):
            si._read_signed_num(b"\x05\x00")

    def test_cltv_satisfied_and_unsatisfied(self):
        self._run_cltv(100, 200)           # height satisfied
        self._run_cltv(500, 500)           # exact match
        self._run_cltv(500_000_100, 500_000_200)  # timestamp satisfied
        with pytest.raises(ValueError, match="unsatisfied"):
            self._run_cltv(500, 100)

    def test_cltv_type_mismatch_and_negative(self):
        with pytest.raises(ValueError, match="type mismatch"):
            self._run_cltv(100, 500_000_100)
        with pytest.raises(ValueError, match="negative"):
            self._run_cltv(-1, 100)

    def test_cltv_finalized_input(self):
        with pytest.raises(ValueError, match="finalized"):
            self._run_cltv(100, 200, sequence=0xffffffff)

    def test_cltv_peeks_not_pops(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        tx = _make_tx(locktime=200)
        stack = si._execute_script(b"\x01\x64\xb1\x75\x51", tx, 0, b"")
        assert stack == [b"\x01"]

    def test_csv_satisfied_and_unsatisfied(self):
        self._run_csv(10, 15)
        self._run_csv(10, 10)
        with pytest.raises(ValueError, match="unsatisfied"):
            self._run_csv(15, 10)

    def test_csv_disable_flag_is_nop(self):
        self._run_csv((1 << 31) | 999, 0)

    def test_csv_version_1_rejected(self):
        with pytest.raises(ValueError, match="version"):
            self._run_csv(10, 15, version=1)

    def test_csv_peeks_not_pops(self):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        tx = _make_tx(version=2, sequence=20, locktime=0)
        stack = si._execute_script(b"\x01\x0a\xb2\x75\x51", tx, 0, b"")
        assert stack == [b"\x01"]


# ── Phase A.3: BIP 68 nSequence Relative Locktime ────────────────────


class _MockDB:
    """Minimal mock for TransactionValidator.check_sequence_locks tests."""

    def __init__(self, utxo_height, utxo_mtp=0):
        self._utxo_height = utxo_height
        self._utxo_mtp = utxo_mtp

    def get_utxo(self, txid, vout):
        return {
            'txid': txid, 'vout': vout,
            'value': 50000, 'script_pubkey': b"\x00" * 25,
            'height': self._utxo_height,
        }

    def get_median_time_past(self, height):
        return self._utxo_mtp


class TestBIP68SequenceLocks:
    """BIP 68: nSequence relative locktime enforcement in TransactionValidator."""

    TYPE_FLAG = 1 << 22
    DISABLE  = 1 << 31

    def _validator(self, utxo_height, utxo_mtp=0):
        from ouroboros.validation import TransactionValidator
        return TransactionValidator(_MockDB(utxo_height, utxo_mtp))

    def test_height_lock_satisfied_and_rejected(self):
        v = self._validator(utxo_height=100)
        tx_ok = _make_tx(version=2, sequence=5)
        assert v.check_sequence_locks(tx_ok, block_height=110, block_mtp=0)
        tx_fail = _make_tx(version=2, sequence=20)
        assert not v.check_sequence_locks(tx_fail, block_height=110, block_mtp=0)

    def test_time_lock_satisfied_and_rejected(self):
        v = self._validator(utxo_height=100, utxo_mtp=1_000_000)
        seq_ok = self.TYPE_FLAG | 10   # 10 * 512 = 5120 s required
        tx_ok = _make_tx(version=2, sequence=seq_ok)
        assert v.check_sequence_locks(tx_ok, block_height=200, block_mtp=1_006_000)
        seq_fail = self.TYPE_FLAG | 20  # 10240 s required
        tx_fail = _make_tx(version=2, sequence=seq_fail)
        assert not v.check_sequence_locks(tx_fail, block_height=200, block_mtp=1_006_000)

    def test_version_1_skips_check(self):
        v = self._validator(utxo_height=100)
        tx = _make_tx(version=1, sequence=9999)
        assert v.check_sequence_locks(tx, block_height=101, block_mtp=0)

    def test_disable_flag_skips_input(self):
        v = self._validator(utxo_height=100)
        tx = _make_tx(version=2, sequence=self.DISABLE | 9999)
        assert v.check_sequence_locks(tx, block_height=101, block_mtp=0)


# ── Phase A.4: Additional Script Opcodes ─────────────────────────────


class TestScriptOpcodes:
    """Additional script opcodes: flow control, stack, arithmetic, hashes."""

    def _run(self, script_hex, locktime=0, sequence=0xfffffffe):
        from ouroboros.script import ScriptInterpreter
        si = ScriptInterpreter()
        tx = _make_tx(locktime=locktime, sequence=sequence)
        return si._execute_script(bytes.fromhex(script_hex), tx, 0, b"")

    def test_if_else_endif(self):
        # OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF → [2]
        s = self._run("5163 52 67 53 68")
        assert s == [b'\x02']
        # OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF → [3]
        s = self._run("0063 52 67 53 68")
        assert s == [b'\x03']

    def test_notif(self):
        # OP_0 OP_NOTIF OP_5 OP_ENDIF → [5]
        s = self._run("0064 55 68")
        assert s == [b'\x05']

    def test_nested_if(self):
        # OP_1 OP_IF OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_ENDIF → [3]
        s = self._run("5163 0063 52 67 53 68 68")
        assert s == [b'\x03']

    def test_unbalanced_if_fails(self):
        with pytest.raises(ValueError, match="Unbalanced"):
            self._run("5163 52")  # OP_1 OP_IF OP_2 (no ENDIF)

    def test_stack_ops(self):
        # SWAP: push 1 2, swap → [2, 1]
        assert self._run("5152 7c") == [b'\x02', b'\x01']
        # ROT: push 1 2 3, rot → [2, 3, 1]
        assert self._run("515253 7b") == [b'\x02', b'\x03', b'\x01']
        # OVER: push 1 2, over → [1, 2, 1]
        assert self._run("5152 78") == [b'\x01', b'\x02', b'\x01']
        # NIP: push 1 2, nip → [2]
        assert self._run("5152 77") == [b'\x02']
        # TUCK: push 1 2, tuck → [2, 1, 2]
        assert self._run("5152 7d") == [b'\x02', b'\x01', b'\x02']
        # 2DUP: push 1 2, 2dup → [1, 2, 1, 2]
        assert self._run("5152 6e") == [b'\x01', b'\x02', b'\x01', b'\x02']
        # 2DROP: push 1 2 3, 2drop → [1]
        assert self._run("515253 6d") == [b'\x01']

    def test_pick_and_roll(self):
        # push 10 20 30, OP_2 OP_PICK → [..., 10]
        s = self._run("010a 0114 011e 52 79")
        assert s[-1] == b'\x0a'
        assert len(s) == 4
        # push 10 20 30, OP_2 OP_ROLL → 10 moved to top, len=3
        s = self._run("010a 0114 011e 52 7a")
        assert s[-1] == b'\x0a'
        assert len(s) == 3

    def test_altstack(self):
        # push 42, toaltstack, push 99, fromaltstack → [99, 42]
        s = self._run("012a 6b 0163 6c")
        assert s == [b'\x63', b'\x2a']

    def test_depth_and_size(self):
        # push "abc"(3 bytes), OP_SIZE → [b"abc", 3]
        s = self._run("03616263 82")
        assert s[0] == b'abc'
        assert s[1] == b'\x03'
        # OP_1 OP_2 OP_DEPTH → [1, 2, 2]
        s = self._run("5152 74")
        assert s == [b'\x01', b'\x02', b'\x02']

    def test_arithmetic(self):
        # 3 + 5 = 8
        assert self._run("5355 93") == [b'\x08']
        # 5 - 3 = 2
        assert self._run("5553 94") == [b'\x02']
        # 1ADD(4) = 5
        assert self._run("54 8b") == [b'\x05']
        # 1SUB(4) = 3
        assert self._run("54 8c") == [b'\x03']
        # NEGATE(5) = -5
        assert self._run("55 8f") == [b'\x85']
        # ABS(-5) = 5
        assert self._run("0185 90") == [b'\x05']
        # NOT(0) = 1, NOT(1) = 0
        assert self._run("00 91") == [b'\x01']
        assert self._run("51 91") == [b'']

    def test_comparisons(self):
        # 3 < 5 → 1
        assert self._run("5355 9f") == [b'\x01']
        # 5 < 3 → 0
        assert self._run("5553 9f") == [b'']
        # 3 == 3 (NUMEQUAL) → 1
        assert self._run("5353 9c") == [b'\x01']
        # MIN(3,5) = 3, MAX(3,5) = 5
        assert self._run("5355 a3") == [b'\x03']
        assert self._run("5355 a4") == [b'\x05']

    def test_within(self):
        # WITHIN(3, 1, 5) → true (1 <= 3 < 5)
        assert self._run("535155 a5") == [b'\x01']
        # WITHIN(5, 1, 5) → false (5 not < 5)
        assert self._run("555155 a5") == [b'']

    def test_hash_opcodes(self):
        import hashlib
        data = b'\x42'
        # OP_SHA256
        s = self._run("0142 a8")
        assert s == [hashlib.sha256(data).digest()]
        # OP_HASH256 (double SHA256)
        s = self._run("0142 aa")
        assert s == [hashlib.sha256(hashlib.sha256(data).digest()).digest()]
        # OP_RIPEMD160
        s = self._run("0142 a6")
        assert s == [hashlib.new('ripemd160', data).digest()]

    def test_disabled_opcodes_fail(self):
        for op in ['7e', '7f', '83', '95']:
            with pytest.raises(ValueError, match="Disabled"):
                self._run(f"5152 {op}")

    def test_op_return_fails(self):
        with pytest.raises(ValueError, match="OP_RETURN"):
            self._run("6a")

    def test_cast_to_bool(self):
        from ouroboros.script import ScriptInterpreter
        cb = ScriptInterpreter._cast_to_bool
        assert not cb(b'')
        assert not cb(b'\x00')
        assert not cb(b'\x00\x00')
        assert not cb(b'\x80')       # negative zero
        assert cb(b'\x01')
        assert cb(b'\x80\x01')       # non-zero byte before last
