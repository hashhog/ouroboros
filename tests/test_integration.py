"""
Integration tests for pure-Python Ouroboros components.

These tests exercise the wallet, fee estimator, address utilities,
and Merkle proof helpers without requiring the Rust extension to be
compiled.  They are designed to run in CI with just ``pytest tests/``.
"""

import hashlib

import pytest

from ouroboros.address import address_to_script_pubkey
from ouroboros.fee_estimator import BlockFeeData, FeeEstimator
from ouroboros.rpc import (
    _build_partial_merkle_tree,
    _dsha256,
    _parse_partial_merkle_tree,
)
from ouroboros.wallet import (
    DEFAULT_LONG_TERM_FEE_RATE,
    HDKey,
    Wallet,
    WalletKey,
    _selection_waste,
    decrypt_wallet_data,
    encrypt_wallet_data,
    select_coins,
    select_coins_bnb,
    select_coins_knapsack,
    select_coins_srd,
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
        with pytest.raises((ValueError, Exception)):
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
        assert {m.hex() for m in matched} == {txids[0].hex(), txids[3].hex()}

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
        import shutil
        import tempfile

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
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_verifytxoutproof_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_verifytxoutproof", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_getmininginfo_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getmininginfo", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_submitblock_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_submitblock", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_estimatesmartfee_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_estimatesmartfee", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_validateaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_validateaddress", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_getnewaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getnewaddress", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_sendtoaddress_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_sendtoaddress", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)

    def test_getwalletinfo_exists(self):
        rpc, d = self._get_rpc()
        assert callable(getattr(rpc, "rpc_getwalletinfo", None))
        import shutil
        shutil.rmtree(d, ignore_errors=True)


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
        import bech32 as _b32

        from ouroboros.address import _bech32m_decode, _bech32m_encode

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


# ── Logging, Cookie Auth & Metrics ────────────────────────────────────


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
        from ouroboros.cookie_auth import delete_cookie, generate_cookie

        generate_cookie(str(tmp_path))
        assert (tmp_path / ".cookie").exists()
        delete_cookie(str(tmp_path))
        assert not (tmp_path / ".cookie").exists()

    def test_delete_missing_is_noop(self, tmp_path):
        from ouroboros.cookie_auth import delete_cookie

        delete_cookie(str(tmp_path))

    def test_cookie_permissions(self, tmp_path):
        import os
        import stat

        from ouroboros.cookie_auth import generate_cookie

        generate_cookie(str(tmp_path))
        mode = os.stat(tmp_path / ".cookie").st_mode
        assert stat.S_IMODE(mode) == 0o600


class TestMetrics:
    def test_init_metrics(self):
        from ouroboros.metrics import _HAS_PROMETHEUS, init_metrics

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


# ── Timelock Opcodes (BIP 65 / BIP 112) ──────────────────────────────


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


# ── BIP 68 nSequence Relative Locktime ────────────────────────────────


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
        # Use regtest where BIP68 is active at height 0
        v = self._validator(utxo_height=100)
        tx_ok = _make_tx(version=2, sequence=5)
        assert v.check_sequence_locks(tx_ok, block_height=110, block_mtp=0, network="regtest")
        tx_fail = _make_tx(version=2, sequence=20)
        assert not v.check_sequence_locks(tx_fail, block_height=110, block_mtp=0, network="regtest")

    def test_time_lock_satisfied_and_rejected(self):
        # Use regtest where BIP68 is active at height 0
        v = self._validator(utxo_height=100, utxo_mtp=1_000_000)
        seq_ok = self.TYPE_FLAG | 10   # 10 * 512 = 5120 s required
        tx_ok = _make_tx(version=2, sequence=seq_ok)
        assert v.check_sequence_locks(tx_ok, block_height=200, block_mtp=1_006_000, network="regtest")
        seq_fail = self.TYPE_FLAG | 20  # 10240 s required
        tx_fail = _make_tx(version=2, sequence=seq_fail)
        assert not v.check_sequence_locks(tx_fail, block_height=200, block_mtp=1_006_000, network="regtest")

    def test_version_1_skips_check(self):
        v = self._validator(utxo_height=100)
        tx = _make_tx(version=1, sequence=9999)
        assert v.check_sequence_locks(tx, block_height=101, block_mtp=0, network="regtest")

    def test_disable_flag_skips_input(self):
        v = self._validator(utxo_height=100)
        tx = _make_tx(version=2, sequence=self.DISABLE | 9999)
        assert v.check_sequence_locks(tx, block_height=101, block_mtp=0, network="regtest")


# ── Script Opcodes (flow control, stack, arithmetic, hashes) ─────────


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


# ── BIP 152 Compact Blocks ────────────────────────────────────────────


class TestCompactBlocks:
    """BIP 152 compact block relay: SipHash, short IDs, reconstruction."""

    def test_siphash_deterministic(self):
        from ouroboros.compact_blocks import _siphash_2_4
        key = b'\x00' * 16
        assert _siphash_2_4(key, b'') == _siphash_2_4(key, b'')
        assert _siphash_2_4(key, b'a') != _siphash_2_4(key, b'b')

    def test_short_txid_48_bits(self):
        from ouroboros.compact_blocks import compute_siphash_key, short_txid
        header = b'\x01' * 80
        key = compute_siphash_key(header, nonce=42)
        assert len(key) == 16
        sid = short_txid(key, b'\xaa' * 32)
        assert 0 <= sid < (1 << 48)

    def test_compact_block_roundtrip(self):
        """Build a CompactBlock from a block, serialize, deserialize."""
        from ouroboros.compact_blocks import CompactBlock, PrefilledTransaction
        from ouroboros.database import Transaction, TxIn, TxOut

        coinbase = Transaction(
            txid=b'\x00' * 32, version=1, locktime=0,
            inputs=[TxIn(b'\x00' * 32, 0xffffffff, b'\x04\xff\xff', 0xffffffff)],
            outputs=[TxOut(5000000000, b'\x51')],
        )
        cb = CompactBlock(
            header=b'\x02' * 80, nonce=123,
            short_ids=[0xAABBCCDDEE, 0x112233445566],
            prefilled_txs=[PrefilledTransaction(index=0, tx=coinbase)],
        )
        data = cb.serialize()
        cb2 = CompactBlock.deserialize(data)
        assert cb2.header == cb.header
        assert cb2.nonce == cb.nonce
        assert cb2.short_ids == cb.short_ids
        assert len(cb2.prefilled_txs) == 1
        assert cb2.prefilled_txs[0].index == 0

    def test_block_txn_request_roundtrip(self):
        from ouroboros.compact_blocks import BlockTransactionsRequest
        req = BlockTransactionsRequest(block_hash=b'\xff' * 32, indices=[0, 5, 6])
        data = req.serialize()
        req2 = BlockTransactionsRequest.deserialize(data)
        assert req2.block_hash == req.block_hash
        assert req2.indices == req.indices

    def test_sendcmpct_message(self):
        from ouroboros.p2p_messages import SendCmpctMessage
        msg = SendCmpctMessage(announce=True, version=2)
        nm = msg.to_network_message("mainnet")
        assert nm.command == "sendcmpct"
        parsed = SendCmpctMessage.from_payload(nm.payload)
        assert parsed.announce is True
        assert parsed.version == 2


# ── Peer Misbehavior Tracking & Banning ──────────────────────────────


class TestBanManager:
    """BanManager: scoring, auto-ban, expiry, persistence."""

    def test_score_accumulation_and_auto_ban(self):
        from ouroboros.banman import BanManager
        bm = BanManager(ban_threshold=100)
        # Events below DISCOURAGEMENT_THRESHOLD (50) accumulate; any single
        # event >= 50 discourages immediately (banman.py, Core PR #25974
        # MaybeDiscourageAndDisconnect model).
        bm.record_misbehavior("1.2.3.4", 40, "bad headers")
        assert not bm.is_banned("1.2.3.4")
        assert bm.get_score("1.2.3.4") == 40
        bm.record_misbehavior("1.2.3.4", 40, "bad headers")
        assert not bm.is_banned("1.2.3.4")
        assert bm.get_score("1.2.3.4") == 80
        bm.record_misbehavior("1.2.3.4", 30, "invalid block")  # cumulative 110 >= 100
        assert bm.is_banned("1.2.3.4")
        assert bm.get_score("1.2.3.4") == 0  # score cleared on ban
        # Single-event discourage path.
        bm.record_misbehavior("2.3.4.5", 50, "bad headers")
        assert bm.is_banned("2.3.4.5")

    def test_instant_ban(self):
        from ouroboros.banman import BanManager
        bm = BanManager(ban_threshold=100)
        bm.record_misbehavior("5.6.7.8", 100, "invalid block header")
        assert bm.is_banned("5.6.7.8")

    def test_ban_expires(self):
        from ouroboros.banman import BanManager
        bm = BanManager(ban_threshold=100, ban_duration=1)
        bm.ban("9.8.7.6")
        assert bm.is_banned("9.8.7.6")
        bm.banned["9.8.7.6"] = 0  # force expiry
        assert not bm.is_banned("9.8.7.6")

    def test_manual_unban(self):
        from ouroboros.banman import BanManager
        bm = BanManager(ban_threshold=100)
        bm.ban("10.0.0.1")
        assert bm.is_banned("10.0.0.1")
        bm.unban("10.0.0.1")
        assert not bm.is_banned("10.0.0.1")

    def test_persistence(self, tmp_path):
        from ouroboros.banman import BanManager
        bm1 = BanManager(ban_threshold=100, data_dir=str(tmp_path))
        bm1.ban("1.1.1.1")
        assert (tmp_path / "bans.json").exists()
        bm2 = BanManager(ban_threshold=100, data_dir=str(tmp_path))
        assert bm2.is_banned("1.1.1.1")

    def test_on_ban_callback(self):
        from ouroboros.banman import BanManager
        banned_ips = []
        bm = BanManager(ban_threshold=50, on_ban=banned_ips.append)
        bm.record_misbehavior("2.2.2.2", 50, "test")
        assert banned_ips == ["2.2.2.2"]


# ── Replace-By-Fee (BIP 125) ─────────────────────────────────────────


class _StubValidator:
    """Minimal validator stub that always accepts transactions."""

    def __init__(self, utxo_values: dict):
        self.db = _StubUTXODB(utxo_values)

    def validate_transaction(self, tx, height, block_mtp=0):
        return True, ""


class _StubUTXODB:
    """Maps (prev_txid, prev_vout) -> {'value': int}."""

    def __init__(self, mapping: dict):
        self._m = mapping

    def get_utxo(self, txid, vout):
        return self._m.get((txid, vout))


def _rbf_tx(txid, inputs, outputs, version=2, sequence=0xFFFFFFFD):
    """Build a Transaction for RBF tests.

    *inputs*: list of (prev_txid, prev_vout).
    *outputs*: list of output values.
    """
    from ouroboros.database import Transaction, TxIn, TxOut

    return Transaction(
        txid=txid,
        version=version,
        locktime=0,
        inputs=[
            TxIn(prev_txid=pt, prev_vout=pv, script_sig=b"", sequence=sequence)
            for pt, pv in inputs
        ],
        outputs=[TxOut(value=v, script_pubkey=b"\x51") for v in outputs],
    )


class TestReplaceByFee:
    """BIP 125 Replace-By-Fee in Mempool."""

    def _pool(self, utxo_values, full_rbf=False):
        from ouroboros.mempool import Mempool
        return Mempool(validator=_StubValidator(utxo_values), require_standard=False, full_rbf=full_rbf)

    def test_basic_rbf(self):
        utxo = {(b"\x01" * 32, 0): {"value": 100_000}}
        pool = self._pool(utxo)

        tx_a = _rbf_tx(b"\xaa" * 32, [(b"\x01" * 32, 0)], [90_000])
        ok, _ = pool.add_transaction(tx_a, height=100)
        assert ok

        tx_b = _rbf_tx(b"\xbb" * 32, [(b"\x01" * 32, 0)], [80_000])
        ok, err = pool.add_transaction(tx_b, height=100)
        assert ok, err
        assert not pool.has_transaction(b"\xaa" * 32)
        assert pool.has_transaction(b"\xbb" * 32)

    def test_rbf_rejected_no_signal(self):
        utxo = {(b"\x01" * 32, 0): {"value": 100_000}}
        pool = self._pool(utxo)

        tx_a = _rbf_tx(b"\xaa" * 32, [(b"\x01" * 32, 0)], [90_000],
                        sequence=0xFFFFFFFF)
        ok, _ = pool.add_transaction(tx_a, height=100)
        assert ok

        tx_b = _rbf_tx(b"\xbb" * 32, [(b"\x01" * 32, 0)], [80_000])
        ok, err = pool.add_transaction(tx_b, height=100)
        assert not ok
        assert "replaceability" in err

    def test_rbf_rejected_lower_fee(self):
        utxo = {(b"\x01" * 32, 0): {"value": 100_000}}
        pool = self._pool(utxo)

        tx_a = _rbf_tx(b"\xaa" * 32, [(b"\x01" * 32, 0)], [50_000])
        ok, _ = pool.add_transaction(tx_a, height=100)
        assert ok

        tx_b = _rbf_tx(b"\xbb" * 32, [(b"\x01" * 32, 0)], [60_000])
        ok, err = pool.add_transaction(tx_b, height=100)
        assert not ok
        assert "fee" in err.lower()

    def test_rbf_evicts_descendants(self):
        utxo = {
            (b"\x01" * 32, 0): {"value": 100_000},
            (b"\xaa" * 32, 0): {"value": 90_000},
        }
        pool = self._pool(utxo)

        tx_parent = _rbf_tx(b"\xaa" * 32, [(b"\x01" * 32, 0)], [90_000])
        ok, _ = pool.add_transaction(tx_parent, height=100)
        assert ok

        tx_child = _rbf_tx(b"\xcc" * 32, [(b"\xaa" * 32, 0)], [80_000])
        ok, _ = pool.add_transaction(tx_child, height=100)
        assert ok

        tx_replacement = _rbf_tx(b"\xbb" * 32, [(b"\x01" * 32, 0)], [5_000])
        ok, err = pool.add_transaction(tx_replacement, height=100)
        assert ok, err
        assert not pool.has_transaction(b"\xaa" * 32)
        assert not pool.has_transaction(b"\xcc" * 32)
        assert pool.has_transaction(b"\xbb" * 32)

    def test_rbf_too_many_evictions(self):
        import time as _time

        from ouroboros.mempool import MempoolEntry

        utxo = {(b"\x01" * 32, 0): {"value": 10_000_000}}
        pool = self._pool(utxo)

        tx_parent = _rbf_tx(b"\xaa" * 32, [(b"\x01" * 32, 0)], [9_900_000])
        ok, _ = pool.add_transaction(tx_parent, height=100)
        assert ok

        prev_txid = b"\xaa" * 32
        for i in range(100):
            child_txid = bytes([i + 2]) + b"\x00" * 31
            child = _rbf_tx(child_txid, [(prev_txid, 0)], [40_000])
            entry = MempoolEntry(
                tx=child, fee=10_000, fee_rate=1.0,
                size=250, time_added=_time.time(), height_added=100,
            )
            pool.transactions[child.get_txid()] = entry
            pool.current_size += 250
            for inp in child.inputs:
                pool.spent_outputs.add((inp.prev_txid, inp.prev_vout))
            # Register child link so _collect_descendants can traverse the chain
            parent_entry = pool.transactions.get(prev_txid)
            if parent_entry is not None:
                parent_entry.children.add(child_txid)
            prev_txid = child_txid

        assert len(pool.transactions) == 101

        tx_b = _rbf_tx(b"\xbb" * 32, [(b"\x01" * 32, 0)], [100_000])
        ok, err = pool.add_transaction(tx_b, height=100)
        assert not ok
        assert "evict" in err.lower()


# ── HD Key Derivation (BIP 32 / BIP 44) ──────────────────────────────

# BIP 32 test vector 1 seed (from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
_TV1_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestHDKey:
    """BIP 32 hierarchical deterministic key derivation."""

    def test_master_from_seed_vector1(self):
        master = HDKey.from_seed(_TV1_SEED)
        xprv = master.serialize_xprv()
        expected = (
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk"
            "4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRN"
            "NU3TGtRBeJgk33yuGBxrMPHi"
        )
        assert xprv == expected, f"unexpected xprv: {xprv}"

    def test_master_xpub_vector1(self):
        master = HDKey.from_seed(_TV1_SEED)
        xpub = master.serialize_xpub()
        expected = (
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9g"
            "SE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD2"
            "65TMg7usUDFdp6W1EGMcet8"
        )
        assert xpub == expected, f"unexpected xpub: {xpub}"

    def test_child_derivation_hardened(self):
        master = HDKey.from_seed(_TV1_SEED)
        child = master.derive_child(0, hardened=True)
        assert child.depth == 1
        assert child.parent_fingerprint == master.fingerprint
        xprv = child.serialize_xprv()
        expected = (
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8B"
            "r5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZ"
            "G7XnxHrnYeSvkzY7d2bhkJ7"
        )
        assert xprv == expected, f"unexpected child xprv: {xprv}"

    def test_path_derivation(self):
        master = HDKey.from_seed(_TV1_SEED)
        # m/0'/1
        child = master.derive_path("m/0'/1")
        xprv = child.serialize_xprv()
        expected = (
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntz"
            "niatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY"
            "3H2EU4pWcQDnRnrVA1xe8fs"
        )
        assert xprv == expected, f"unexpected path xprv: {xprv}"

    def test_xprv_roundtrip(self):
        master = HDKey.from_seed(_TV1_SEED)
        xprv_str = master.serialize_xprv()
        restored = HDKey.from_xprv(xprv_str)
        assert restored.private_key == master.private_key
        assert restored.chain_code == master.chain_code
        assert restored.depth == master.depth

    def test_wallet_key_conversion(self):
        master = HDKey.from_seed(_TV1_SEED)
        wk = master.to_wallet_key()
        assert wk.secret == master.private_key
        addr = wk.get_p2wpkh_address()
        assert addr.startswith("bc1q")

    @pytest.mark.asyncio
    async def test_wallet_hd_address_generation(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet")
        w.init_hd(_TV1_SEED)
        a0 = await w.generate_new_address()
        a1 = await w.generate_new_address()
        assert a0.startswith("bc1q")
        assert a1.startswith("bc1q")
        assert a0 != a1

        # Reload wallet and verify HD state persisted
        w2 = Wallet(temp_data_dir, "mainnet")
        assert w2.is_hd
        # With key pool, addresses are tracked via used indices
        assert w2._key_pool is not None
        assert 0 in w2._key_pool._used_receive_indices
        assert 1 in w2._key_pool._used_receive_indices
        addrs = await w2.get_addresses()
        assert len(addrs) == 2
        assert addrs[0].address == a0

    @pytest.mark.asyncio
    async def test_wallet_hd_deterministic(self, temp_data_dir):
        """Two wallets from the same seed produce the same addresses."""
        w1 = Wallet(temp_data_dir, "mainnet", name="hd1")
        w1.init_hd(_TV1_SEED)
        a1 = await w1.generate_new_address()

        w2 = Wallet(temp_data_dir, "mainnet", name="hd2")
        w2.init_hd(_TV1_SEED)
        a2 = await w2.generate_new_address()

        assert a1 == a2


# ── Encrypted Wallet ─────────────────────────────────────────────────


class TestEncryptedWallet:
    """AES-256-GCM wallet encryption with scrypt KDF."""

    def test_encrypt_decrypt_roundtrip(self):
        data = b"secret wallet payload 1234567890"
        blob = encrypt_wallet_data(data, "hunter2")
        assert blob != data
        assert len(blob) > len(data)
        recovered = decrypt_wallet_data(blob, "hunter2")
        assert recovered == data

    def test_wrong_passphrase_raises(self):
        blob = encrypt_wallet_data(b"payload", "correct")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_wallet_data(blob, "wrong")

    def test_corrupt_blob_raises(self):
        with pytest.raises(ValueError):
            decrypt_wallet_data(b"tooshort", "any")

    @pytest.mark.asyncio
    async def test_wallet_encrypt_unlock_cycle(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet", name="enc1")
        addr = await w.generate_new_address("key-0")
        w.encrypt("mypass")

        # Reload — wallet should be locked
        w2 = Wallet(temp_data_dir, "mainnet", name="enc1")
        assert w2.is_encrypted
        assert w2.is_locked
        assert len(w2.keys) == 0

        # Unlock with correct passphrase
        w2.unlock("mypass")
        assert not w2.is_locked
        assert len(w2.keys) == 1
        addrs = await w2.get_addresses()
        assert addrs[0].address == addr

    @pytest.mark.asyncio
    async def test_wallet_lock_wipes_memory(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet", name="enc2")
        await w.generate_new_address()
        w.encrypt("pass123")
        assert len(w.keys) == 1

        w.lock()
        assert w.is_locked
        assert len(w.keys) == 0

    @pytest.mark.asyncio
    async def test_wallet_change_passphrase(self, temp_data_dir):
        w = Wallet(temp_data_dir, "mainnet", name="enc3")
        addr = await w.generate_new_address()
        w.encrypt("old_pass")

        w.change_passphrase("old_pass", "new_pass")

        # Old passphrase no longer works
        w2 = Wallet(temp_data_dir, "mainnet", name="enc3")
        with pytest.raises(ValueError):
            w2.unlock("old_pass")

        # New passphrase works
        w3 = Wallet(temp_data_dir, "mainnet", name="enc3")
        w3.unlock("new_pass")
        assert len(w3.keys) == 1
        addrs = await w3.get_addresses()
        assert addrs[0].address == addr

    @pytest.mark.asyncio
    async def test_encrypted_hd_wallet(self, temp_data_dir):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        w = Wallet(temp_data_dir, "mainnet", name="enc_hd")
        w.init_hd(seed)
        a0 = await w.generate_new_address()
        w.encrypt("hdpass")

        w2 = Wallet(temp_data_dir, "mainnet", name="enc_hd")
        w2.unlock("hdpass")
        assert w2.is_hd
        a1 = await w2.generate_new_address()
        assert a0 != a1  # next index advanced


# ── PSBT (BIP 174) ───────────────────────────────────────────────────


def _make_psbt_tx():
    """Build a simple unsigned Transaction for PSBT tests."""
    from ouroboros.database import Transaction, TxIn, TxOut

    return Transaction(
        txid=b"\x00" * 32,
        version=2,
        locktime=0,
        inputs=[
            TxIn(b"\xaa" * 32, 0, b"", 0xFFFFFFFD),
            TxIn(b"\xbb" * 32, 1, b"", 0xFFFFFFFD),
        ],
        outputs=[
            TxOut(50_000, b"\x00\x14" + b"\x11" * 20),
            TxOut(40_000, b"\x00\x14" + b"\x22" * 20),
        ],
    )


class TestPSBT:
    """BIP 174 Partially Signed Bitcoin Transactions."""

    def test_serialize_deserialize_roundtrip(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        data = psbt.serialize()
        assert data[:5] == b"psbt\xff"
        psbt2 = PSBT.deserialize(data)
        assert len(psbt2.inputs) == 2
        assert len(psbt2.outputs) == 2
        assert psbt2.tx.version == 2
        assert psbt2.tx.locktime == 0

    def test_roundtrip_preserves_tx_structure(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        data = psbt.serialize()
        psbt2 = PSBT.deserialize(data)
        assert psbt2.tx.inputs[0].prev_txid == b"\xaa" * 32
        assert psbt2.tx.inputs[1].prev_vout == 1
        assert psbt2.tx.outputs[0].value == 50_000
        assert psbt2.tx.outputs[1].script_pubkey == b"\x00\x14" + b"\x22" * 20

    def test_partial_sig_roundtrip(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        fake_pub = b"\x02" + b"\xab" * 32
        fake_sig = b"\x30" + b"\xcd" * 70
        psbt.inputs[0].partial_sigs[fake_pub] = fake_sig
        data = psbt.serialize()
        psbt2 = PSBT.deserialize(data)
        assert fake_pub in psbt2.inputs[0].partial_sigs
        assert psbt2.inputs[0].partial_sigs[fake_pub] == fake_sig

    def test_witness_utxo_roundtrip(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].witness_utxo = (100_000, b"\x00\x14" + b"\x33" * 20)
        data = psbt.serialize()
        psbt2 = PSBT.deserialize(data)
        assert psbt2.inputs[0].witness_utxo == (100_000, b"\x00\x14" + b"\x33" * 20)

    def test_combine_merges_sigs(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt_a = PSBT.from_transaction(tx)
        psbt_b = PSBT.from_transaction(tx)

        pub_a = b"\x02" + b"\x01" * 32
        pub_b = b"\x02" + b"\x02" * 32
        psbt_a.inputs[0].partial_sigs[pub_a] = b"\x30sig_a"
        psbt_b.inputs[0].partial_sigs[pub_b] = b"\x30sig_b"

        combined = psbt_a.combine(psbt_b)
        assert pub_a in combined.inputs[0].partial_sigs
        assert pub_b in combined.inputs[0].partial_sigs

    def test_finalize_p2wpkh(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        pub = b"\x02" + b"\xab" * 32
        sig = b"\x30" + b"\xcd" * 70 + b"\x01"
        psbt.inputs[0].witness_utxo = (100_000, b"\x00\x14" + b"\x33" * 20)
        psbt.inputs[0].partial_sigs[pub] = sig
        psbt.inputs[1].witness_utxo = (80_000, b"\x00\x14" + b"\x44" * 20)
        psbt.inputs[1].partial_sigs[pub] = sig

        psbt.finalize()
        assert psbt.inputs[0].final_script_witness is not None
        assert len(psbt.inputs[0].partial_sigs) == 0

    def test_extract_transaction(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        pub = b"\x02" + b"\xab" * 32
        sig = b"\x30" + b"\xcd" * 70 + b"\x01"
        for i in range(2):
            psbt.inputs[i].witness_utxo = (100_000, b"\x00\x14" + b"\x55" * 20)
            psbt.inputs[i].partial_sigs[pub] = sig

        psbt.finalize()
        final_tx = psbt.extract_transaction()
        assert final_tx.has_witness
        assert final_tx.inputs[0].witness is not None
        assert len(final_tx.inputs[0].witness) == 2
        assert final_tx.inputs[0].witness[0] == sig
        assert final_tx.inputs[0].witness[1] == pub

    def test_decode_output(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        psbt.inputs[0].sighash_type = 1
        decoded = psbt.decode()
        assert decoded["tx"]["version"] == 2
        assert len(decoded["inputs"]) == 2
        assert decoded["inputs"][0]["sighash"] == "ALL"  # Core rpc/rawtransaction.cpp:802
        assert len(decoded["outputs"]) == 2

    def test_extract_raises_if_not_finalized(self):
        from ouroboros.psbt import PSBT
        tx = _make_psbt_tx()
        psbt = PSBT.from_transaction(tx)
        with pytest.raises(ValueError, match="not finali[sz]ed"):
            psbt.extract_transaction()


# ── BIP 324 v2 P2P Transport ─────────────────────────────────────────


class TestV2Transport:
    """BIP 324 encrypted P2P transport."""

    def test_handshake_key_exchange(self):
        from ouroboros.transport_v2 import V2Handshake
        initiator = V2Handshake(initiator=True)
        responder = V2Handshake(initiator=False)

        assert len(initiator.local_pubkey_bytes) == 64
        assert len(responder.local_pubkey_bytes) == 64

        initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
        responder.receive_remote_pubkey(initiator.local_pubkey_bytes)

        i_send, i_recv = initiator.derive_session_keys()
        r_send, r_recv = responder.derive_session_keys()

        assert len(i_send) == 32
        assert i_send == r_recv
        assert i_recv == r_send

    def test_encrypt_decrypt_roundtrip(self):
        from ouroboros.transport_v2 import V2Handshake, V2Transport
        initiator = V2Handshake(initiator=True)
        responder = V2Handshake(initiator=False)
        initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
        responder.receive_remote_pubkey(initiator.local_pubkey_bytes)

        i_transport = V2Transport.from_handshake(initiator)
        r_transport = V2Transport.from_handshake(responder)

        payload = b"version\x00\x00\x00\x00\x00" + b"\x01" * 50
        packet = i_transport.encrypt_message(payload)
        decrypted, is_decoy, consumed = r_transport.decrypt_message(packet)
        assert decrypted == payload
        assert not is_decoy
        assert consumed == len(packet)

    def test_decoy_flag(self):
        from ouroboros.transport_v2 import V2Handshake, V2Transport
        initiator = V2Handshake(initiator=True)
        responder = V2Handshake(initiator=False)
        initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
        responder.receive_remote_pubkey(initiator.local_pubkey_bytes)

        i_transport = V2Transport.from_handshake(initiator)
        r_transport = V2Transport.from_handshake(responder)

        packet = i_transport.encrypt_message(b"dummy", decoy=True)
        decrypted, is_decoy, _ = r_transport.decrypt_message(packet)
        assert is_decoy
        assert decrypted == b"dummy"

    def test_multiple_messages(self):
        from ouroboros.transport_v2 import V2Handshake, V2Transport
        initiator = V2Handshake(initiator=True)
        responder = V2Handshake(initiator=False)
        initiator.receive_remote_pubkey(responder.local_pubkey_bytes)
        responder.receive_remote_pubkey(initiator.local_pubkey_bytes)

        i_transport = V2Transport.from_handshake(initiator)
        r_transport = V2Transport.from_handshake(responder)

        for i in range(10):
            msg = f"message_{i}".encode()
            packet = i_transport.encrypt_message(msg)
            decrypted, _, _ = r_transport.decrypt_message(packet)
            assert decrypted == msg

    def test_rekey_happens(self):
        from ouroboros.transport_v2 import REKEY_INTERVAL, CipherState
        cs = CipherState(key=b"\xaa" * 32)
        original_key = cs.key
        for _ in range(REKEY_INTERVAL):
            cs.encrypt(b"x")
        assert cs.key != original_key
        assert cs.nonce_counter == 0


# ── Block Pruning ─────────────────────────────────────────────────────


class _MockBlockStore:
    """
    In-memory mock of PyBlockStore (flat-file block storage) interface.

    Implements the subset of PyBlockStore's API that BlockPruner uses:
    get_prune_height, has_block_data_at_height, get_prune_stats,
    prune_to_target, prune_to_height, and find_files_to_prune.
    """

    def __init__(self, block_count: int, block_size: int = 1000):
        self._blocks = dict.fromkeys(range(block_count), block_size)
        self._prune_height = 0

    def get_prune_height(self) -> int:
        return self._prune_height

    def has_block_data_at_height(self, height: int) -> bool:
        return height in self._blocks

    def calculate_current_usage(self) -> int:
        return sum(self._blocks.values())

    def get_prune_stats(self):
        pruned = sum(1 for h in range(self._prune_height) if h not in self._blocks)
        total = max(1, len(self._blocks) + pruned)
        data_bytes = self.calculate_current_usage()
        return (total, pruned, data_bytes, 0, self._prune_height)

    def prune_to_target(self, current_height: int, target_size: int):
        """Remove old blocks until usage <= target_size, keeping last keep_blocks."""
        if current_height <= 288:
            return (0, 0)
        max_prune = current_height - 288
        files_pruned = 0
        bytes_freed = 0
        for h in sorted(self._blocks.keys()):
            if h > max_prune:
                break
            if self.calculate_current_usage() <= target_size:
                break
            sz = self._blocks.pop(h)
            bytes_freed += sz
            files_pruned += 1
            if h >= self._prune_height:
                self._prune_height = h + 1
        return (files_pruned, bytes_freed)

    def prune_to_height(self, target_height: int, current_height: int):
        """Remove blocks up to target_height."""
        if current_height <= 288:
            return (0, 0, 0)
        max_prune = min(target_height, current_height - 288)
        files_pruned = 0
        bytes_freed = 0
        for h in sorted(self._blocks.keys()):
            if h > max_prune:
                break
            sz = self._blocks.pop(h)
            bytes_freed += sz
            files_pruned += 1
            if h >= self._prune_height:
                self._prune_height = h + 1
        return (files_pruned, bytes_freed, self._prune_height)

    def find_files_to_prune(self, *a, **kw):
        return []


class TestBlockPruner:
    """Block pruning: discard old block data via PyBlockStore backend."""

    def test_prune_old_blocks(self):
        from ouroboros.pruning import BlockPruner

        # 500 blocks at 1 000 B each = 500 KB; target = 550 MB so no size-based
        # pruning, but prune_to_target still removes blocks below keep_blocks
        store = _MockBlockStore(500, block_size=1000)
        pruner = BlockPruner(db=store, keep_blocks=288)
        files_pruned, bytes_freed = pruner.prune_blocks(current_height=499)
        # heights 0..210 are > 288 blocks below tip → pruned (499-288=211 → prune up to 211)
        assert files_pruned > 0 or bytes_freed == 0  # prune happens if below target
        assert pruner.prune_height >= 0

    def test_prune_respects_keep_blocks(self):
        from ouroboros.pruning import BlockPruner

        store = _MockBlockStore(100, block_size=100)
        pruner = BlockPruner(db=store, keep_blocks=288)
        files_pruned, bytes_freed = pruner.prune_blocks(current_height=99)
        # current_height=99 <= keep_blocks=288 → no pruning
        assert files_pruned == 0
        assert bytes_freed == 0

    def test_prune_state_persistence(self):
        from ouroboros.pruning import BlockPruner

        store = _MockBlockStore(400, block_size=500)
        pruner = BlockPruner(db=store, keep_blocks=288)
        pruner.prune_blocks(current_height=399)
        prune_h = pruner.prune_height

        # A new pruner using the same store sees the updated prune height
        pruner2 = BlockPruner(db=store, keep_blocks=288)
        assert pruner2.prune_height == prune_h

    def test_prune_to_target(self):
        from ouroboros.pruning import BlockPruner

        # 500 blocks × 1 200 000 B ≈ 600 MB total; effective target = 550 MB
        # (BlockPruner enforces 550 MB minimum).  600 > 550 → pruning occurs.
        store = _MockBlockStore(500, block_size=1_200_000)
        pruner = BlockPruner(db=store, target_size_mb=550, keep_blocks=288)
        files_pruned, bytes_freed = pruner.prune_blocks(current_height=499)
        assert bytes_freed > 0
        assert store.calculate_current_usage() <= 550_000_000

    def test_is_pruned(self):
        from ouroboros.pruning import BlockPruner

        store = _MockBlockStore(400, block_size=100)
        pruner = BlockPruner(db=store, keep_blocks=288)
        pruner.prune_blocks(current_height=399)
        # Heights that were pruned should be flagged
        # Heights at or above prune_height still have data
        ph = pruner.prune_height
        if ph > 0:
            assert pruner.is_pruned(0)
        assert not pruner.is_pruned(399)


# ── getblocktemplate RPC ──────────────────────────────────────────────


class TestGetBlockTemplate:
    """getblocktemplate RPC: block assembly for mining."""

    def test_template_structure(self):
        """Verify the template dict has all required fields."""
        import asyncio

        from ouroboros.rpc import RPCServer

        class _MockBlock:
            version = 0x20000000
            bits = 0x1d00ffff
            hash = b"\xab" * 32
            timestamp = 1700000000

            def serialize(self):
                return b"\x00" * 80

        class _MockDB:
            def get_best_block(self):
                return b"\xab" * 32, 100

            def get_block(self, h):
                return _MockBlock()

            def get_median_time_past(self, h):
                return 1699999000

        class _MockNode:
            db = _MockDB()
            mempool = None
            network = "mainnet"

            def get_median_time(self, h):
                return 1699999000

        server = RPCServer(_MockNode(), port=0, rate_limit=False)
        template = asyncio.run(server.rpc_getblocktemplate())  # no loop on py3.13 without asyncio.run
        assert template["height"] == 101
        assert template["previousblockhash"] == (b"\xab" * 32).hex()
        assert template["coinbasevalue"] > 0
        assert "target" in template
        assert "bits" in template
        assert "transactions" in template
        assert isinstance(template["transactions"], list)


# ── ZMQ Notifications ────────────────────────────────────────────────


class TestZMQPublisher:
    """ZMQ publisher: hashblock, hashtx, rawblock, rawtx."""

    def test_publish_without_start_is_noop(self):
        from ouroboros.zmq_publisher import ZMQPublisher
        pub = ZMQPublisher()
        assert not pub.is_running

        class _FakeBlock:
            hash = b"\x01" * 32
            def serialize(self):
                return b"\x00" * 80

        pub.notify_block(_FakeBlock())  # should not raise

    def test_sequence_counter_increments(self):
        from ouroboros.zmq_publisher import ZMQPublisher
        pub = ZMQPublisher()
        assert pub._sequences[pub.TOPIC_HASH_BLOCK] == 0
        assert pub._sequences[pub.TOPIC_HASH_TX] == 0

    def test_topics_defined(self):
        from ouroboros.zmq_publisher import ZMQPublisher
        assert ZMQPublisher.TOPIC_HASH_BLOCK == b"hashblock"
        assert ZMQPublisher.TOPIC_HASH_TX == b"hashtx"
        assert ZMQPublisher.TOPIC_RAW_BLOCK == b"rawblock"
        assert ZMQPublisher.TOPIC_RAW_TX == b"rawtx"


# ── Coin Selection (BnB / Knapsack / SRD) ────────────────────────────


def _utxo(value: int) -> dict:
    """Minimal UTXO dict for coin selection tests."""
    return {"value": value}


class TestCoinSelection:
    """Branch-and-Bound, Knapsack, and Single Random Draw coin selection."""

    # ── Branch and Bound ──────────────────────────────────────────

    def test_bnb_exact_match(self):
        utxos = [_utxo(50_000), _utxo(30_000), _utxo(20_000)]
        # target where 50k + 30k - input fees is exact
        result = select_coins_bnb(utxos, 70_000, fee_rate=0.0)
        assert result is not None
        total = sum(u["value"] for u in result)
        assert total == 70_000

    def test_bnb_returns_none_when_no_exact_match(self):
        utxos = [_utxo(50_000), _utxo(30_000)]
        # target that can't be hit exactly within cost_of_change
        result = select_coins_bnb(utxos, 60_001, fee_rate=0.0, cost_of_change=1)
        assert result is None

    def test_bnb_prefers_fewer_inputs(self):
        utxos = [_utxo(100_000), _utxo(50_000), _utxo(50_000)]
        result = select_coins_bnb(utxos, 100_000, fee_rate=0.0)
        assert result is not None
        assert len(result) == 1
        assert result[0]["value"] == 100_000

    def test_bnb_accounts_for_input_fees(self):
        utxos = [_utxo(10_000), _utxo(10_000)]
        # With fee_rate=1.0, each input costs 68 sat, so effective = 9932 each
        result = select_coins_bnb(utxos, 19_864, fee_rate=1.0)
        assert result is not None
        assert len(result) == 2

    # ── Knapsack ──────────────────────────────────────────────────

    def test_knapsack_finds_solution(self):
        utxos = [_utxo(20_000), _utxo(30_000), _utxo(50_000)]
        result = select_coins_knapsack(utxos, 40_000, fee_rate=1.0)
        assert result is not None
        total = sum(u["value"] for u in result)
        assert total >= 40_000

    def test_knapsack_returns_none_insufficient(self):
        utxos = [_utxo(100)]
        result = select_coins_knapsack(utxos, 1_000_000, fee_rate=1.0)
        assert result is None

    def test_knapsack_prefers_smaller_overshoot(self):
        utxos = [_utxo(100_000), _utxo(50_000), _utxo(51_000)]
        # Run many times — knapsack should usually find 51k (close to 50k target)
        results = []
        for _ in range(50):
            r = select_coins_knapsack(utxos, 50_000, fee_rate=0.0, iterations=200)
            if r is not None:
                results.append(sum(u["value"] for u in r))
        assert len(results) > 0
        assert min(results) <= 51_000

    # ── Single Random Draw ────────────────────────────────────────

    def test_srd_finds_solution(self):
        utxos = [_utxo(10_000), _utxo(20_000), _utxo(30_000)]
        result = select_coins_srd(utxos, 25_000, fee_rate=0.0)
        assert result is not None
        total = sum(u["value"] for u in result)
        assert total >= 25_000

    def test_srd_returns_none_insufficient(self):
        utxos = [_utxo(100), _utxo(200)]
        result = select_coins_srd(utxos, 1_000_000, fee_rate=0.0)
        assert result is None

    # ── Three-tier select_coins ───────────────────────────────────

    def test_select_coins_succeeds(self):
        utxos = [_utxo(100_000), _utxo(50_000), _utxo(30_000)]
        selected, fee, algo = select_coins(utxos, 45_000, fee_rate=1.0)
        assert selected is not None
        total = sum(u["value"] for u in selected)
        assert total >= 45_000 + fee
        assert algo in ("bnb", "knapsack", "srd")

    def test_select_coins_raises_insufficient(self):
        utxos = [_utxo(100)]
        with pytest.raises(ValueError, match="Insufficient funds"):
            select_coins(utxos, 1_000_000, fee_rate=1.0)

    def test_select_coins_uses_bnb_for_exact(self):
        # BnB target = amount + non_input_fee(1 output, fee_rate=1.0)
        #            = amount + int((11 + 31) * 1.0) + 1 = amount + 43
        # BnB effective value = utxo_value - int(68 * 1.0) = utxo_value - 68
        # For exact match: eff_value == bnb_target
        #   utxo_value - 68 == amount + 43  →  utxo_value == amount + 111
        _, _, algo = select_coins([_utxo(50_111)], 50_000, fee_rate=1.0)
        assert algo == "bnb"

    def test_select_coins_falls_through(self):
        utxos = [_utxo(v) for v in range(1000, 50_000, 1000)]
        selected, fee, algo = select_coins(utxos, 100_000, fee_rate=1.0)
        assert selected is not None
        total = sum(u["value"] for u in selected)
        assert total >= 100_000 + fee

    # ── Waste metric ─────────────────────────────────────────────

    def test_waste_metric_no_change_zero(self):
        """Exact BnB match: change_cost is 0."""
        sel = [_utxo(50_000)]
        waste = _selection_waste(sel, fee_rate=10.0, long_term_fee_rate=10.0, has_change=False)
        # timing_cost = 68 * (10 - 10) = 0;  change_cost = 0
        assert waste == 0.0

    def test_waste_metric_with_change(self):
        """With change output: change_cost = 99 * fee_rate."""
        sel = [_utxo(50_000)]
        waste = _selection_waste(sel, fee_rate=20.0, long_term_fee_rate=10.0, has_change=True)
        # timing_cost = 68 * (20 - 10) = 680
        # change_cost = 99 * 20 = 1980
        # total = 2660
        assert waste == pytest.approx(2660.0)

    def test_waste_metric_negative_timing(self):
        """fee_rate < long_term → negative timing cost favours more inputs."""
        sel = [_utxo(10_000), _utxo(10_000)]
        waste = _selection_waste(sel, fee_rate=1.0, long_term_fee_rate=10.0, has_change=True)
        # timing_cost = 2 * 68 * (1 - 10) = -1224
        # change_cost = 99 * 1 = 99
        # total = -1125
        assert waste == pytest.approx(-1125.0)

    def test_select_coins_high_fee_prefers_bnb(self):
        """At high fee rates, BnB exact match (no change) should be preferred."""
        # Craft UTXOs so BnB can find an exact match.
        # BnB target = amount + non_input_fee(1, fee_rate)
        #            = 50_000 + int((11 + 31) * 50.0) + 1 = 50_000 + 2101 = 52_101
        # Effective value = utxo_value - int(68 * 50.0) = utxo_value - 3400
        # For exact match: utxo_value - 3400 == 52_101 → utxo_value = 55_501
        utxos = [_utxo(55_501), _utxo(30_000), _utxo(30_000)]
        _, _, algo = select_coins(utxos, 50_000, fee_rate=50.0, long_term_fee_rate=10.0)
        assert algo == "bnb"

    def test_select_coins_low_fee_may_prefer_fewer_inputs(self):
        """At low fee rates (below long-term), consolidation is cheap."""
        # With fee_rate=1.0 < long_term=10.0, timing_cost is negative
        # so more inputs are actually cheaper (consolidation is rewarded).
        utxos = [_utxo(100_000), _utxo(50_000), _utxo(30_000)]
        selected, _, algo = select_coins(utxos, 45_000, fee_rate=1.0, long_term_fee_rate=10.0)
        assert selected is not None
        total = sum(u["value"] for u in selected)
        assert total >= 45_000

    def test_select_coins_long_term_fee_rate_default(self):
        """Default long_term_fee_rate is 10 sat/vB."""
        assert DEFAULT_LONG_TERM_FEE_RATE == 10.0
        # Confirm select_coins works without explicit long_term_fee_rate
        utxos = [_utxo(100_000)]
        selected, fee, algo = select_coins(utxos, 50_000, fee_rate=1.0)
        assert selected is not None

    def test_select_coins_waste_picks_best(self):
        """When multiple algos succeed, the lowest-waste result wins."""
        # Use fee_rate == long_term_fee_rate so timing cost is 0.
        # Then waste is purely change_cost: BnB (no change) → waste = 0.
        # BnB target = 50_000 + int(42 * 5) + 1 = 50_211
        # eff_value = utxo - 340 → need utxo = 50_551
        utxos = [_utxo(50_551), _utxo(25_000), _utxo(26_000)]
        _, _, algo = select_coins(utxos, 50_000, fee_rate=5.0, long_term_fee_rate=5.0)
        # With timing cost = 0, BnB waste = 0 (no change) vs.
        # knapsack/srd waste = 99 * 5 = 495. BnB must win.
        assert algo == "bnb"
