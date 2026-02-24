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
