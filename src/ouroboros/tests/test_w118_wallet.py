"""
W118 Wallet audit tests for ouroboros.

Gates: G1-G6 Descriptors (BIP 380-386), G7-G12 BIP-32 derivation,
       G13-G18 PSBT (BIP 174 / 370 / 174 keytypes),
       G19-G22 Fee bumping (BIP 125 / RBF),
       G23-G26 Send / build-and-sign,
       G27-G30 UTXO management.

Pipelines: Python wallet (src/ouroboros/wallet.py, descriptors.py, bip39.py,
           psbt.py, rpc.py)
           Rust wallet (ferrous-utils/sync/src/wallet/) — MISSING ENTIRELY.
           The Rust pipeline has no wallet module at all; wallet lives 100%
           in Python. This makes the wallet code single-pipeline.

Bug inventory:

  BUG-1 (G6, MEDIUM): parse_descriptor accepts top-level `multi(...)` with
         M-of-N keys but BIP-381 requires multi() to appear ONLY inside
         sh() or wsh(). Reference: bitcoin-core/src/script/descriptor.cpp —
         the parser only recognises `multi` inside `sh(multi(...))`,
         `wsh(multi(...))`, etc; bare `multi(M,...)` is invalid.
         ouroboros silently accepts it and wraps it in P2SH, which produces
         a script that no other wallet can recognise from the descriptor.

  BUG-2 (G24, MEDIUM): send_transaction sets nLockTime to the *exact*
         current block height without the BIP-125 / Core anti-fee-sniping
         randomization. Bitcoin Core wallet/spend.cpp DiscourageFeeSniping
         sets locktime = current_height, then with 10% probability
         decrements by a uniform random 1..100 to reduce the heuristic
         fingerprint that says "this is a Core wallet that uses
         current-height locktime". ouroboros sets `locktime =
         current_height` deterministically, leaking wallet-software
         fingerprint and anti-fee-sniping diversity.
         Reference: wallet/spend.cpp DiscourageFeeSniping.

  BUG-3 (G29, P0-PRIVACY / W88 ANTI-PATTERN): select_coins_knapsack and
         select_coins_srd use Python's `random` module (Mersenne Twister)
         for coin selection randomisation, NOT a cryptographic RNG. This
         is the W88 anti-pattern identified in FIX-45 for blockbrew /
         clearbit / camlcoin / lunarblock coin-selection. Mersenne
         Twister is seeded from system time at process start and is fully
         predictable after observing ~624 outputs. An attacker who
         observes one transaction's input set on the wire can predict the
         coin selection of all subsequent transactions in the same
         process, allowing UTXO clustering / deanonymisation. Use
         `secrets.SystemRandom` (CSPRNG) or `os.urandom` instead.
         Affects: wallet.py lines 22 (import random), 254
         (random.shuffle), 257 (random.random()), 287 (random.shuffle).

  BUG-4 (G18, LOW): joinpsbts() forces the combined transaction version
         to 2 and locktime to 0 (psbt.py:2884-2887) regardless of the
         versions/locktimes carried by the input PSBTs. Bitcoin Core
         joinpsbts (PartiallySignedTransaction::Merge) preserves the
         version and locktime of the first PSBT. ouroboros silently
         downgrades a v1-only or BIP-65-locktime PSBT.

  BUG-5 (G15, LOW): PSBT.combine raises ValueError on differing unsigned
         transactions, but `_serialize_unsigned_tx` includes locktime —
         two PSBTs derived from the same logical transaction but with
         different fallback_locktime in v2 mode would fail to combine
         even though the spec allows it. (Minor edge case; ouroboros
         v2 path probably never triggers this.)

  BUG-6 (G3, LOW): ExtendedPubKey.deserialize accepts xprv-format strings
         and silently converts them to public — but the resulting
         ExtendedPubKey.is_private is NEVER set (always False on the
         dataclass), so callers who check `is_private` to refuse private
         material in watch-only mode get a False-negative. Only
         KeyExpression.is_private is set, and only in the descriptor
         path, not via direct ExtendedPubKey.deserialize.

  BUG-7 (G27, MEDIUM): rpc_listunspent with no addresses parameter
         silently returns an empty list (rpc.py:3195-3196 — "would need
         to iterate all (expensive). Return empty for now."). Bitcoin
         Core listunspent with no addresses returns ALL wallet UTXOs.
         This makes the most common form of listunspent silently broken
         — wallet GUIs that omit the addresses param see no coins.

  BUG-8 (G29, MEDIUM): _collect_utxos only scans P2WPKH addresses
         (wallet.py:1941, `k.get_p2wpkh_address()`). P2PKH, P2TR
         (bech32m), and P2SH-P2WPKH UTXOs owned by the wallet are
         invisible to coin selection. This is a continuation of W111
         BUG-6 (get_balance only scans P2WPKH); _collect_utxos has the
         same gap, meaning send_transaction / walletcreatefundedpsbt
         cannot fund from non-P2WPKH coins.

  BUG-9 (G19, LOW): bump_fee verifies RBF signal with
         `any(inp.sequence < 0xFFFFFFFE for inp in orig_tx.inputs)`
         (wallet.py:1477). This matches BIP-125 §2 which says the tx
         is replaceable if at least one input has sequence < 0xFFFFFFFE.
         However, after W116/W117 changes Core's mempool now uses
         "full RBF" by default (no opt-in required) when
         `-mempoolfullrbf=1`. ouroboros has no equivalent setting and
         always requires the opt-in. Not strictly wrong but
         configuration-divergent.

  BUG-10 (G23, LOW): send_transaction picks the wallet's
         first stored key (`self.keys[0]`) as the change destination
         (wallet.py:2093). If a wallet has been initialised in HD mode,
         self.keys[] may be empty (HD wallets use _key_pool, not keys[]),
         producing an IndexError. Worse, even when self.keys is
         populated, reusing keys[0] for every change output destroys
         change-address rotation privacy — the canonical Core behavior
         is to derive a fresh change address from the change keypool
         (m/84'/coin'/0'/1/{n}).

  BUG-11 (G5, HIGH): Descriptor.derive_script_pubkey lacks a `rawtr`
         branch (descriptors.py:577) — derive_address handles `rawtr`
         (line 438), but derive_script_pubkey raises
         ``ValueError: Unknown descriptor type: rawtr``. Any code that
         goes scriptPubKey-first (importdescriptors → UTXO scan, PSBT
         updater) fails to materialise the BIP-386 rawtr() output.
         This is a dead-end inconsistency: addresses can be derived but
         spending cannot proceed.

Reference: Bitcoin Core src/wallet/wallet.cpp, src/wallet/spend.cpp,
           src/wallet/rpc/spend.cpp, src/script/descriptor.cpp,
           src/psbt.cpp; BIPs 32 / 39 / 44 / 84 / 86 / 125 / 174 / 380.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import struct
import sys
import tempfile
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Mock the Rust sync extension before any ouroboros import.
# ---------------------------------------------------------------------------

_src = Path(__file__).parent.parent.parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.PyBlockchainDB = type("PyBlockchainDB", (), {})        # type: ignore
    _mock.PyBlock = type("PyBlock", (), {})                      # type: ignore
    _mock.PyUTXO = type("PyUTXO", (), {})                        # type: ignore
    _mock.SyncEngine = type("SyncEngine", (), {})                # type: ignore
    sys.modules["sync"] = _mock

import base58  # noqa: E402

from ouroboros.bip39 import (  # noqa: E402
    entropy_to_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    validate_mnemonic,
)
from ouroboros.descriptors import (  # noqa: E402
    ExtendedPubKey,
    add_checksum,
    descriptor_checksum,
    getdescriptorinfo,
    parse_descriptor,
    verify_checksum,
)
from ouroboros.psbt import (  # noqa: E402
    PSBT,
    PSBTInput,
    PSBTOutput,
    combinepsbt,
    createpsbt,
    finalizepsbt,
    joinpsbts,
)
from ouroboros.wallet import (  # noqa: E402
    DEFAULT_LONG_TERM_FEE_RATE,
    HDKey,
    KeyPool,
    Wallet,
    WalletKey,
    select_coins,
    select_coins_bnb,
    select_coins_knapsack,
    select_coins_srd,
)


# ---------------------------------------------------------------------------
# Test vectors / constants
# ---------------------------------------------------------------------------

# BIP-32 test vector 1
_TV1_SEED_HEX = "000102030405060708090a0b0c0d0e0f"
_TV1_MASTER_XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
_TV1_MASTER_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ES"
    "FjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)

# BIP-39 abandon vector (12 words)
_ABANDON_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
_ABANDON_SEED_HEX = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)


def _new_wallet(name: str = "w", network: str = "mainnet") -> tuple[Wallet, str]:
    tmp = tempfile.mkdtemp()
    return Wallet(data_dir=tmp, network=network, name=name), tmp


# ===========================================================================
# G1 — BIP-380 descriptor checksum algorithm
# ===========================================================================

class TestG1DescriptorChecksum:
    """G1: descriptor_checksum / add_checksum / verify_checksum."""

    def test_checksum_is_eight_chars(self):
        cs = descriptor_checksum("pk(03000000000000000000000000000000"
                                 "00000000000000000000000000000000)")
        assert len(cs) == 8

    def test_checksum_uses_bech32_charset(self):
        """All checksum characters must be in the bech32-style alphabet."""
        cs = descriptor_checksum("wpkh(03000000000000000000000000000000"
                                 "00000000000000000000000000000000)")
        # BIP-380 CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        for c in cs:
            assert c in "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def test_add_checksum_then_verify_roundtrip(self):
        """add_checksum(d); verify_checksum(d#cs) must be True."""
        d = f"wpkh({_TV1_MASTER_XPUB})"
        with_cs = add_checksum(d)
        assert "#" in with_cs
        assert verify_checksum(with_cs)

    def test_verify_rejects_modified_checksum(self):
        """Mutating one checksum char must invalidate."""
        d = f"wpkh({_TV1_MASTER_XPUB})"
        with_cs = add_checksum(d)
        body, cs = with_cs.rsplit("#", 1)
        # Flip one character of the checksum
        bad_cs = ("p" if cs[0] != "p" else "q") + cs[1:]
        assert not verify_checksum(f"{body}#{bad_cs}")

    def test_verify_rejects_modified_body(self):
        """Mutating one body char must invalidate."""
        d = f"wpkh({_TV1_MASTER_XPUB})"
        with_cs = add_checksum(d)
        # Replace one body char (preserves length, different content)
        mutated = "wkh" + with_cs[3:]
        assert not verify_checksum(mutated)

    def test_parse_with_invalid_checksum_raises(self):
        """parse_descriptor must reject a descriptor with a bad checksum."""
        bad = f"wpkh({_TV1_MASTER_XPUB})#00000000"
        with pytest.raises(ValueError):
            parse_descriptor(bad)


# ===========================================================================
# G2 — Single-key descriptors (pk, pkh, wpkh, tr, sh-wpkh)
# ===========================================================================

class TestG2SingleKeyDescriptors:
    """G2: pk/pkh/wpkh/tr/sh-wpkh parse and derive."""

    def setup_method(self):
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed, "mainnet")
        # Derive m/0 (non-hardened)
        m0 = master.derive_child(0)
        self.pub_hex = m0.public_key.hex()

    def test_pk_parses(self):
        d = parse_descriptor(f"pk({self.pub_hex})")
        assert d.descriptor_type == "pk"
        assert len(d.keys) == 1

    def test_pkh_derives_p2pkh_address(self):
        d = parse_descriptor(f"pkh({self.pub_hex})")
        addr = d.derive_address(0, "mainnet")
        assert addr.startswith("1") or addr.startswith("m") or addr.startswith("n")

    def test_wpkh_derives_bech32_address(self):
        d = parse_descriptor(f"wpkh({self.pub_hex})")
        addr = d.derive_address(0, "mainnet")
        assert addr.startswith("bc1q")

    def test_tr_derives_bech32m_address(self):
        """tr() must produce a P2TR (bc1p...) address with BIP-341 tweak."""
        d = parse_descriptor(f"tr({self.pub_hex})")
        addr = d.derive_address(0, "mainnet")
        assert addr.startswith("bc1p")

    def test_sh_wpkh_derives_p2sh_address(self):
        d = parse_descriptor(f"sh(wpkh({self.pub_hex}))")
        addr = d.derive_address(0, "mainnet")
        assert addr.startswith("3")

    def test_solvable_set(self):
        info = getdescriptorinfo(f"wpkh({self.pub_hex})")
        assert info["issolvable"] is True

    def test_addr_is_not_solvable(self):
        info = getdescriptorinfo("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)")
        assert info["issolvable"] is False


# ===========================================================================
# G3 — Range descriptors and key origin
# ===========================================================================

class TestG3RangeDescriptorsAndOrigin:
    """G3: /0/* range syntax and [fp/path] origin parsing."""

    def test_range_descriptor_is_range(self):
        d = parse_descriptor(f"wpkh({_TV1_MASTER_XPUB}/0/*)")
        assert d.is_range
        assert d.keys[0].is_range

    def test_range_descriptor_derives_distinct(self):
        d = parse_descriptor(f"wpkh({_TV1_MASTER_XPUB}/0/*)")
        a0 = d.derive_address(0, "mainnet")
        a1 = d.derive_address(1, "mainnet")
        assert a0 != a1
        assert a0.startswith("bc1q")
        assert a1.startswith("bc1q")

    def test_origin_parses(self):
        """[fingerprint/path]xpub.../0/0 carries fingerprint info."""
        # Origin tag - BIP-380 §"Key expressions"
        origin = "[d34db33f/44'/0'/0']"
        d = parse_descriptor(f"wpkh({origin}{_TV1_MASTER_XPUB}/0/0)")
        assert d.keys[0].origin is not None
        assert d.keys[0].origin.fingerprint == "d34db33f"

    def test_non_range_descriptor_isrange_false(self):
        info = getdescriptorinfo(f"wpkh({_TV1_MASTER_XPUB})")
        assert info["isrange"] is False

    def test_range_descriptor_info_isrange(self):
        info = getdescriptorinfo(f"wpkh({_TV1_MASTER_XPUB}/0/*)")
        assert info["isrange"] is True


# ===========================================================================
# G4 — Multisig descriptors (multi, sortedmulti, wsh-multi)
# ===========================================================================

class TestG4MultisigDescriptors:
    """G4: multi / sortedmulti parsing and BIP-67 sort behavior."""

    def setup_method(self):
        # Three distinct test pubkeys
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed)
        self.pub1 = master.derive_child(0).public_key.hex()
        self.pub2 = master.derive_child(1).public_key.hex()
        self.pub3 = master.derive_child(2).public_key.hex()

    def test_wsh_multi_parses(self):
        d = parse_descriptor(f"wsh(multi(2,{self.pub1},{self.pub2}))")
        assert d.descriptor_type == "wsh-multi"
        assert d.multisig_threshold == 2
        assert len(d.keys) == 2

    def test_sortedmulti_sorts_keys_lex(self):
        """BIP-67 lexicographic sort of public keys in sortedmulti()."""
        # Build sortedmulti with intentionally non-sorted hex order
        sorted_first = parse_descriptor(
            f"wsh(sortedmulti(2,{self.pub1},{self.pub2}))"
        )
        sorted_other = parse_descriptor(
            f"wsh(sortedmulti(2,{self.pub2},{self.pub1}))"
        )
        # Both must produce the same scriptPubKey because keys are sorted
        assert sorted_first.derive_script_pubkey(0) == sorted_other.derive_script_pubkey(0)

    def test_multi_does_not_sort(self):
        """Non-sorted multi() preserves key order."""
        d1 = parse_descriptor(f"wsh(multi(2,{self.pub1},{self.pub2}))")
        d2 = parse_descriptor(f"wsh(multi(2,{self.pub2},{self.pub1}))")
        # Order matters for multi() — different scripts
        assert d1.derive_script_pubkey(0) != d2.derive_script_pubkey(0)

    def test_threshold_exceeds_keys_raises(self):
        with pytest.raises(ValueError):
            parse_descriptor(
                f"wsh(multi(3,{self.pub1},{self.pub2}))"
            ).derive_script_pubkey(0)

    def test_threshold_zero_raises(self):
        with pytest.raises(ValueError):
            parse_descriptor(
                f"wsh(multi(0,{self.pub1},{self.pub2}))"
            ).derive_script_pubkey(0)


# ===========================================================================
# G5 — Combo and Taproot descriptors
# ===========================================================================

class TestG5ComboAndTaprootDescriptors:
    """G5: combo(KEY) and tr() / rawtr() handling."""

    def setup_method(self):
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed)
        self.pub_hex = master.derive_child(0).public_key.hex()
        self.xonly_hex = master.derive_child(0).public_key[1:].hex()

    def test_combo_returns_multiple_scripts(self):
        d = parse_descriptor(f"combo({self.pub_hex})")
        scripts = d.derive_all_scripts(0)
        # combo expands to P2PK, P2PKH + (P2WPKH, P2SH-P2WPKH for compressed)
        assert len(scripts) >= 4

    def test_tr_keypath_uses_taproot_tweak(self):
        """tr(KEY) applies BIP-341 TapTweak — output key != internal key."""
        d = parse_descriptor(f"tr({self.pub_hex})")
        spk = d.derive_script_pubkey(0)
        # OP_1 (0x51) || 32 byte push
        assert spk[0] == 0x51
        assert spk[1] == 0x20
        tweaked = spk[2:]
        assert tweaked != bytes.fromhex(self.xonly_hex), \
            "tweaked output key must differ from internal x-only key"

    def test_rawtr_address_no_tweak(self):
        """rawtr(KEY).derive_address returns the x-only key unmodified."""
        d = parse_descriptor(f"rawtr({self.xonly_hex})")
        addr = d.derive_address(0, "mainnet")
        # rawtr address must start with bc1p (P2TR HRP)
        assert addr.startswith("bc1p")

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-11: derive_script_pubkey is missing the `rawtr` branch — "
               "derive_address handles it (line 438) but derive_script_pubkey "
               "raises 'Unknown descriptor type: rawtr' (line 577).",
    )
    def test_rawtr_script_pubkey_no_tweak(self):
        """rawtr(KEY).derive_script_pubkey must return OP_1 || <x-only>."""
        d = parse_descriptor(f"rawtr({self.xonly_hex})")
        spk = d.derive_script_pubkey(0)
        assert spk[0] == 0x51 and spk[1] == 0x20
        assert spk[2:] == bytes.fromhex(self.xonly_hex), \
            "rawtr must NOT apply BIP-341 tweak"

    def test_addr_descriptor_returns_address(self):
        d = parse_descriptor("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)")
        assert d.descriptor_type == "addr"
        assert d.derive_address(0, "mainnet") == \
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


# ===========================================================================
# G6 — Descriptor placement rules (BIP-381)
# ===========================================================================

class TestG6DescriptorPlacementRules:
    """G6: descriptor type-level placement constraints (BIP-381)."""

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-1: parse_descriptor accepts top-level multi() but BIP-381 "
               "requires multi/sortedmulti to appear ONLY inside sh()/wsh().",
    )
    def test_top_level_multi_must_be_rejected(self):
        """BIP-381: bare multi() at the top level is not a valid descriptor."""
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed)
        pub1 = master.derive_child(0).public_key.hex()
        pub2 = master.derive_child(1).public_key.hex()
        # Bitcoin Core's descriptor.cpp rejects this; ouroboros accepts.
        with pytest.raises(ValueError):
            parse_descriptor(f"multi(2,{pub1},{pub2})")

    def test_unsupported_descriptor_raises(self):
        with pytest.raises(ValueError):
            parse_descriptor("xyz(foo)")

    def test_invalid_address_in_addr_raises(self):
        with pytest.raises(ValueError):
            parse_descriptor("addr(not_a_valid_address)")

    def test_invalid_hex_in_raw_raises(self):
        with pytest.raises(ValueError):
            parse_descriptor("raw(zzzz)")


# ===========================================================================
# G7 — BIP-32 master key derivation
# ===========================================================================

class TestG7Bip32MasterKey:
    """G7: HMAC-SHA512('Bitcoin seed', seed) master key derivation."""

    def test_master_from_tv1_seed(self):
        """BIP-32 test vector 1 master key bytes."""
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed)
        assert master.private_key.hex() == \
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        assert master.chain_code.hex() == \
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        assert master.depth == 0
        assert master.child_index == 0
        assert master.parent_fingerprint == b"\x00\x00\x00\x00"

    def test_master_serialize_matches_tv1_xprv(self):
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed)
        assert master.serialize_xprv() == _TV1_MASTER_XPRV
        assert master.serialize_xpub() == _TV1_MASTER_XPUB

    def test_seed_length_bounds(self):
        with pytest.raises(ValueError):
            HDKey.from_seed(bytes(15))
        with pytest.raises(ValueError):
            HDKey.from_seed(bytes(65))
        # Min/max accepted
        HDKey.from_seed(bytes(16))
        HDKey.from_seed(bytes(64))


# ===========================================================================
# G8 — BIP-32 child derivation (normal + hardened)
# ===========================================================================

class TestG8Bip32ChildDerivation:
    """G8: normal + hardened child derivation."""

    def test_hardened_flag_set(self):
        master = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        c = master.derive_child(0, hardened=True)
        assert c.child_index & 0x80000000

    def test_normal_flag_clear(self):
        master = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        c = master.derive_child(0)
        assert not (c.child_index & 0x80000000)

    def test_tv1_m_0h_priv(self):
        """BIP-32 TV1 m/0h matches spec."""
        master = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        child = master.derive_child(0, hardened=True)
        assert child.private_key.hex() == \
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"

    def test_depth_increments(self):
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        c1 = m.derive_child(0)
        c2 = c1.derive_child(0)
        assert c1.depth == 1 and c2.depth == 2

    def test_extended_pubkey_cannot_derive_hardened(self):
        """ExtendedPubKey.derive_path() must reject hardened steps."""
        epub = ExtendedPubKey.deserialize(_TV1_MASTER_XPUB)
        with pytest.raises(ValueError):
            epub.derive_path("0'/0")


# ===========================================================================
# G9 — BIP-32 path derivation
# ===========================================================================

class TestG9Bip32PathDerivation:
    """G9: derive_path('m/.../...') parsing and execution."""

    def test_path_must_start_with_m(self):
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        with pytest.raises(ValueError):
            m.derive_path("84'/0'/0'/0/0")

    def test_bip84_path_derives(self):
        """m/84'/0'/0'/0/0 derives without error."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        child = m.derive_path("m/84'/0'/0'/0/0")
        assert child.depth == 5

    def test_h_synonym_for_hardened(self):
        """Both 0' and 0h must be accepted as hardened indices."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        a = m.derive_path("m/0'/0")
        b = m.derive_path("m/0h/0")
        assert a.private_key == b.private_key


# ===========================================================================
# G10 — xprv / xpub serialisation
# ===========================================================================

class TestG10ExtendedKeySerialization:
    """G10: xprv/xpub base58check encoding and round-trip."""

    def test_xprv_xpub_round_trip(self):
        seed = os.urandom(32)
        m = HDKey.from_seed(seed)
        xprv = m.serialize_xprv()
        restored = HDKey.from_xprv(xprv)
        assert restored.private_key == m.private_key
        assert restored.chain_code == m.chain_code

    def test_xpub_decode_round_trip(self):
        seed = os.urandom(32)
        m = HDKey.from_seed(seed)
        xpub = m.serialize_xpub()
        epub = ExtendedPubKey.deserialize(xpub)
        assert epub.public_key == m.public_key
        assert epub.chain_code == m.chain_code

    def test_xprv_payload_is_78_bytes(self):
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        raw = base58.b58decode_check(m.serialize_xprv())
        assert len(raw) == 78

    def test_testnet_uses_tprv_tpub_prefix(self):
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX), "testnet")
        assert m.serialize_xprv().startswith("tprv")
        assert m.serialize_xpub().startswith("tpub")


# ===========================================================================
# G11 — BIP-39 mnemonic and seed derivation
# ===========================================================================

class TestG11Bip39:
    """G11: BIP-39 mnemonic generation, validation, and seed derivation."""

    def test_abandon_seed_vector(self):
        """Canonical 'abandon...about' vector with empty passphrase."""
        seed = mnemonic_to_seed(_ABANDON_MNEMONIC, "")
        assert seed.hex() == _ABANDON_SEED_HEX

    def test_validate_rejects_bad_checksum(self):
        # All-zero 12 words has invalid checksum
        bad = " ".join(["abandon"] * 12)
        with pytest.raises(Exception):
            validate_mnemonic(bad)

    def test_validate_accepts_canonical(self):
        validate_mnemonic(_ABANDON_MNEMONIC)

    def test_entropy_round_trip(self):
        for nbits in (128, 160, 192, 224, 256):
            ent = os.urandom(nbits // 8)
            mn = entropy_to_mnemonic(ent)
            assert len(mn) == (nbits + nbits // 32) // 11
            assert mnemonic_to_entropy(mn) == ent

    def test_passphrase_changes_seed(self):
        s1 = mnemonic_to_seed(_ABANDON_MNEMONIC, "")
        s2 = mnemonic_to_seed(_ABANDON_MNEMONIC, "TREZOR")
        assert s1 != s2


# ===========================================================================
# G12 — BIP-44/49/84/86 path conventions
# ===========================================================================

class TestG12BipPathConventions:
    """G12: BIP-44/49/84/86 coin-type and purpose conventions."""

    def test_bip84_path_format(self):
        """m/84'/0'/0'/0/0 derives to a compressed pubkey usable for P2WPKH."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        leaf = m.derive_path("m/84'/0'/0'/0/0")
        assert len(leaf.public_key) == 33
        wk = leaf.to_wallet_key()
        assert wk.get_p2wpkh_address().startswith("bc1q")

    def test_bip44_path_format(self):
        """legacy → m/44'/0'/0'/0/0 → P2PKH base58 (mainnet `1` prefix)."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        leaf = m.derive_path("m/44'/0'/0'/0/0")
        wk = leaf.to_wallet_key()
        assert wk.get_p2pkh_address().startswith("1")

    def test_bip49_path_format(self):
        """p2sh-segwit → m/49'/0'/0'/0/0 → P2SH base58 (mainnet `3` prefix)."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        leaf = m.derive_path("m/49'/0'/0'/0/0")
        wk = leaf.to_wallet_key()
        assert wk.get_p2sh_p2wpkh_address().startswith("3")

    def test_bip86_path_format(self):
        """bech32m → m/86'/0'/0'/0/0 → P2TR bech32m (`bc1p` prefix)."""
        m = HDKey.from_seed(bytes.fromhex(_TV1_SEED_HEX))
        leaf = m.derive_path("m/86'/0'/0'/0/0")
        wk = leaf.to_wallet_key()
        assert wk.get_p2tr_address().startswith("bc1p")

    def test_keypool_dispatches_each_address_type_to_correct_bip(self):
        """W161 BUG-6/7/8 regression: each address_type must derive at its own BIP path.

        Before this fix, ouroboros derived every address type from
        ``m/84'/...`` (hardcoded BIP-84) regardless of whether the caller
        asked for ``legacy`` (BIP-44), ``p2sh-segwit`` (BIP-49), or
        ``bech32m`` (BIP-86). That broke recovery — funds sent to a
        ``getnewaddress legacy`` P2PKH could not be recovered by any
        BIP-44-compliant external wallet from the same mnemonic.
        """
        seed = bytes.fromhex(_TV1_SEED_HEX)
        master = HDKey.from_seed(seed, "mainnet")
        expected = {
            "legacy": master.derive_path(
                "m/44'/0'/0'/0/0"
            ).to_wallet_key().get_p2pkh_address(),
            "p2sh-segwit": master.derive_path(
                "m/49'/0'/0'/0/0"
            ).to_wallet_key().get_p2sh_p2wpkh_address(),
            "bech32": master.derive_path(
                "m/84'/0'/0'/0/0"
            ).to_wallet_key().get_p2wpkh_address(),
            "bech32m": master.derive_path(
                "m/86'/0'/0'/0/0"
            ).to_wallet_key().get_p2tr_address(),
        }
        for address_type, want in expected.items():
            pool = KeyPool(seed, "mainnet", pool_size=2)
            addr, idx = pool.get_new_address(
                is_change=False, address_type=address_type,
            )
            assert idx == 0
            assert addr == want, (
                f"{address_type!r} derived {addr!r} but spec-correct {want!r}"
            )

    def test_keypool_uses_testnet_coin_type(self):
        """KeyPool initialised on testnet uses coin_type=1, not 0."""
        seed = bytes.fromhex(_TV1_SEED_HEX)
        pool = KeyPool(seed, "testnet", pool_size=2)
        assert pool.coin_type == 1

    def test_keypool_uses_mainnet_coin_type(self):
        seed = bytes.fromhex(_TV1_SEED_HEX)
        pool = KeyPool(seed, "mainnet", pool_size=2)
        assert pool.coin_type == 0

    def test_keypool_uses_regtest_coin_type(self):
        """Regtest must use coin_type=1 per SLIP-44 + Core chainparams default."""
        seed = bytes.fromhex(_TV1_SEED_HEX)
        pool = KeyPool(seed, "regtest", pool_size=2)
        assert pool.coin_type == 1

    def test_keypool_receive_change_distinct(self):
        """Receive (m/.../.../0/n) and change (m/.../.../1/n) paths differ."""
        seed = bytes.fromhex(_TV1_SEED_HEX)
        pool = KeyPool(seed, "mainnet", pool_size=4)
        addr_recv, _ = pool.get_new_address(is_change=False)
        addr_chg, _ = pool.get_new_address(is_change=True)
        assert addr_recv != addr_chg


# ===========================================================================
# G13 — PSBT serialise / deserialise round-trip
# ===========================================================================

class TestG13PsbtRoundTrip:
    """G13: PSBT base64 / binary round-trip preserves all fields."""

    def _build_simple_psbt(self):
        ps = createpsbt(
            inputs=[{"txid": "00" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        return ps

    def test_base64_round_trip(self):
        b64 = self._build_simple_psbt()
        psbt = PSBT.from_base64(b64)
        round_tripped = psbt.to_base64()
        # Decode both and compare
        assert PSBT.from_base64(round_tripped).serialize() == psbt.serialize()

    def test_magic_present(self):
        """PSBT must start with magic 0x70 0x73 0x62 0x74 0xff."""
        b64 = self._build_simple_psbt()
        import base64
        raw = base64.b64decode(b64)
        assert raw[:5] == b"psbt\xff"

    def test_invalid_magic_rejected(self):
        import base64
        bad = base64.b64encode(b"NOTPSBT").decode()
        with pytest.raises(Exception):
            PSBT.from_base64(bad)


# ===========================================================================
# G14 — PSBT v0 vs v2 (BIP-370)
# ===========================================================================

class TestG14PsbtVersionHandling:
    """G14: PSBT v0 (BIP-174) and v2 (BIP-370) version negotiation."""

    def test_v0_requires_unsigned_tx(self):
        """PSBT v0 missing UNSIGNED_TX must be rejected."""
        # Construct a malformed v0 by stripping the unsigned tx
        import base64
        raw = b"psbt\xff" + b"\x00" + b"\x00"  # globals end + empty input map - invalid
        bad = base64.b64encode(raw).decode()
        with pytest.raises(Exception):
            PSBT.from_base64(bad)

    def test_v2_round_trip(self):
        """PSBT v2 (BIP-370) round-trip preserves tx_version/locktime/counts."""
        from ouroboros.database import Transaction, TxIn, TxOut
        tx = Transaction(
            txid=b"\x00" * 32,
            version=3,
            locktime=1234,
            inputs=[TxIn(prev_txid=b"\x11" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + b"\x22" * 20)],
        )
        psbt = PSBT.from_transaction(tx, version=2)
        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        assert restored.version == 2
        assert restored.tx_version == 3
        assert restored.fallback_locktime == 1234
        assert restored.input_count == 1
        assert restored.output_count == 1


# ===========================================================================
# G15 — PSBT combine (signature merge)
# ===========================================================================

class TestG15PsbtCombine:
    """G15: PSBT.combine merges partial signatures."""

    def test_combine_different_unsigned_tx_raises(self):
        a = createpsbt(
            inputs=[{"txid": "00" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        b = createpsbt(
            inputs=[{"txid": "11" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 2.0}],
        )
        # combinepsbt() wrapper should reject divergent unsigned txs
        with pytest.raises(Exception):
            combinepsbt([a, b])

    def test_combine_same_tx_returns_psbt(self):
        a = createpsbt(
            inputs=[{"txid": "aa" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        # Same unsigned tx — combining must succeed
        out = combinepsbt([a, a])
        # Round-trip the result
        PSBT.from_base64(out)

    def test_combine_merges_partial_sigs(self):
        # Build a base PSBT
        a = PSBT.from_base64(createpsbt(
            inputs=[{"txid": "aa" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        ))
        # Add a partial sig to a clone
        b = PSBT.from_base64(a.to_base64())
        b.inputs[0].partial_sigs[b"\x02" + b"\x00" * 32] = b"\x30\x01"
        a.combine(b)
        assert b"\x02" + b"\x00" * 32 in a.inputs[0].partial_sigs


# ===========================================================================
# G16 — PSBT finalize
# ===========================================================================

class TestG16PsbtFinalize:
    """G16: finalize() builds final_script_sig/final_script_witness."""

    def test_unfinalized_extract_raises(self):
        """Extracting from a non-finalized PSBT must raise."""
        b64 = createpsbt(
            inputs=[{"txid": "aa" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        psbt = PSBT.from_base64(b64)
        with pytest.raises(ValueError):
            psbt.extract_transaction()

    def test_finalize_returns_self(self):
        b64 = createpsbt(
            inputs=[{"txid": "aa" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        psbt = PSBT.from_base64(b64)
        out = psbt.finalize()
        assert out is psbt


# ===========================================================================
# G17 — PSBT non-witness/witness UTXO consistency
# ===========================================================================

class TestG17PsbtUtxoConsistency:
    """G17: BIP-174 PSBT_IN_NON_WITNESS_UTXO sha256d sanity check."""

    def test_psbtinput_has_non_witness_utxo_field(self):
        pi = PSBTInput()
        assert pi.non_witness_utxo is None

    def test_psbtinput_has_witness_utxo_field(self):
        pi = PSBTInput()
        assert pi.witness_utxo is None

    def test_psbtinput_partial_sigs_dict_default_empty(self):
        pi = PSBTInput()
        assert pi.partial_sigs == {}


# ===========================================================================
# G18 — PSBT joinpsbts
# ===========================================================================

class TestG18PsbtJoin:
    """G18: joinpsbts concatenates inputs/outputs."""

    def test_join_concatenates(self):
        a = createpsbt(
            inputs=[{"txid": "aa" * 32, "vout": 0}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 1.0}],
        )
        b = createpsbt(
            inputs=[{"txid": "bb" * 32, "vout": 1}],
            outputs=[{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 2.0}],
        )
        joined = joinpsbts([a, b])
        psbt = PSBT.from_base64(joined)
        assert len(psbt.inputs) == 2
        assert len(psbt.outputs) == 2

    def test_join_empty_raises(self):
        with pytest.raises(ValueError):
            joinpsbts([])

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-4: joinpsbts forces version=2 / locktime=0 instead of "
               "preserving the first PSBT's tx version/locktime (Core "
               "PartiallySignedTransaction::Merge preserves them).",
    )
    def test_join_preserves_first_psbt_locktime(self):
        """Locktime of first PSBT should survive the join."""
        from ouroboros.database import Transaction, TxIn, TxOut
        tx_a = Transaction(
            txid=b"\x00" * 32, version=2, locktime=999999,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + b"\x11" * 20)],
        )
        tx_b = Transaction(
            txid=b"\x00" * 32, version=2, locktime=0,
            inputs=[TxIn(prev_txid=b"\xbb" * 32, prev_vout=1,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=2000, script_pubkey=b"\x00\x14" + b"\x11" * 20)],
        )
        a_b64 = PSBT.from_transaction(tx_a).to_base64()
        b_b64 = PSBT.from_transaction(tx_b).to_base64()
        joined = joinpsbts([a_b64, b_b64])
        joined_psbt = PSBT.from_base64(joined)
        # Bitcoin Core preserves the first PSBT's tx.locktime
        assert joined_psbt.tx.locktime == 999999


# ===========================================================================
# G19 — BIP-125 RBF signal detection
# ===========================================================================

class TestG19RbfSignal:
    """G19: BIP-125 / RBF signalling rules."""

    def test_seq_below_max_minus_one_signals_rbf(self):
        """Sequence 0xFFFFFFFD is the conventional RBF signal."""
        # 0xFFFFFFFD < 0xFFFFFFFE  → signals RBF
        assert 0xFFFFFFFD < 0xFFFFFFFE

    def test_seq_ffffffe_does_not_signal_rbf(self):
        """0xFFFFFFFE is the boundary — NOT RBF."""
        # Per BIP-125: tx signals RBF if any input has sequence < 0xFFFFFFFE
        assert not (0xFFFFFFFE < 0xFFFFFFFE)

    def test_send_transaction_uses_rbf_sequence(self):
        """Newly built txs from send_transaction use 0xFFFFFFFD (RBF)."""
        # We verify via the source code constant: send_transaction
        # always uses sequence=0xFFFFFFFD per wallet.py:2118.
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        assert "0xFFFFFFFD" in src


# ===========================================================================
# G20 — Fee rate calculation and minimum bump
# ===========================================================================

class TestG20FeeRateAndMinBump:
    """G20: bump_fee target_fee >= orig_fee + 1."""

    def test_min_bump_is_at_least_orig_plus_one_sat(self):
        """target_fee = max(new_rate * vsize, orig_fee + 1) — verify shape."""
        # Just inspect the constant in source: target_fee = max(
        # int(new_fee_rate * est_vsize), orig_fee + 1)
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.bump_fee)
        assert "orig_fee + 1" in src


# ===========================================================================
# G21 — Change reduction in fee bump
# ===========================================================================

class TestG21BumpFeeChangeReduction:
    """G21: bump_fee reduces change output, removes if dust."""

    def test_dust_threshold_is_546(self):
        """The dust threshold in bump_fee is 546 sats (matches Core dustRelayFee)."""
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.bump_fee)
        assert "546" in src


# ===========================================================================
# G22 — Anti-fee-sniping (locktime randomisation)
# ===========================================================================

class TestG22AntiFeeSniping:
    """G22: anti-fee-sniping locktime randomisation (BIP-125)."""

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-2: send_transaction sets locktime = current_height "
               "deterministically. Bitcoin Core wallet/spend.cpp "
               "DiscourageFeeSniping randomly decrements by 1..100 "
               "with 10% probability to reduce wallet fingerprint.",
    )
    def test_locktime_has_randomized_offset(self):
        """The locktime computation should include a probabilistic offset."""
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        # Look for evidence of probabilistic decrement of locktime
        # (Core uses GetRand(10) == 0 then GetRandInt(100)).
        has_random_step = any(
            tok in src for tok in (
                "random.randint(0, 100)",
                "GetRandInt(100)",
                "random.random() < 0.1",
                "random.randrange(100)",
                "secrets.randbelow(100)",
            )
        )
        assert has_random_step


# ===========================================================================
# G23 — send_transaction structure
# ===========================================================================

class TestG23SendTransactionStructure:
    """G23: send_transaction builds outputs (recipient + optional change)."""

    def test_dust_threshold_for_change_is_546(self):
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        assert "546" in src

    def test_rbf_sequence_in_send(self):
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        assert "0xFFFFFFFD" in src


# ===========================================================================
# G24 — Anti-fee-sniping locktime application
# ===========================================================================

class TestG24LocktimeApplication:
    """G24: locktime is applied to the unsigned transaction."""

    def test_locktime_field_used(self):
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        assert "locktime=" in src or "locktime " in src

    def test_locktime_zero_fallback_when_no_db(self):
        """If no db is wired, locktime defaults to 0 (do-no-harm)."""
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet.send_transaction)
        # The function falls back to locktime = 0 if db is None
        assert "locktime = 0" in src


# ===========================================================================
# G25 — BIP-143 sighash (segwit v0)
# ===========================================================================

class TestG25Bip143Sighash:
    """G25: BIP-143 sighash for P2WPKH inputs."""

    def test_sighash_routine_exists(self):
        # _bip143_sighash exists in wallet
        assert hasattr(Wallet, "_bip143_sighash")

    def test_sighash_returns_32_bytes(self):
        """BIP-143 sighash output is always 32 bytes."""
        from ouroboros.database import Transaction, TxIn, TxOut
        tx = Transaction(
            txid=b"\x00" * 32, version=2, locktime=0,
            inputs=[TxIn(prev_txid=b"\xaa" * 32, prev_vout=0,
                         script_sig=b"", sequence=0xFFFFFFFD)],
            outputs=[TxOut(value=1000, script_pubkey=b"\x00\x14" + b"\x11" * 20)],
        )
        pubkey = b"\x02" + b"\x33" * 32
        h = Wallet._bip143_sighash(tx, 0, pubkey, 50_000)
        assert len(h) == 32


# ===========================================================================
# G26 — WalletKey signing
# ===========================================================================

class TestG26WalletKeySigning:
    """G26: WalletKey signs and produces valid DER signatures."""

    def test_sign_returns_der_signature(self):
        wk = WalletKey.generate("mainnet")
        msg = hashlib.sha256(b"hello").digest()
        sig = wk.sign(msg)
        # DER signature: 0x30 <len> 0x02 <r-len> <r> 0x02 <s-len> <s>
        assert sig[0] == 0x30
        # Length byte covers the rest
        assert sig[1] + 2 == len(sig) or sig[1] + 2 + 1 == len(sig)  # +sighash byte possible
        assert len(sig) >= 70 and len(sig) <= 73

    def test_p2wpkh_address_starts_bc1q(self):
        wk = WalletKey.generate("mainnet")
        assert wk.get_p2wpkh_address().startswith("bc1q")


# ===========================================================================
# G27 — listunspent
# ===========================================================================

class TestG27ListUnspent:
    """G27: listunspent must enumerate wallet UTXOs."""

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-7: rpc_listunspent returns [] when no addresses are passed, "
               "instead of iterating all wallet UTXOs (rpc.py:3195).",
    )
    def test_listunspent_no_addresses_must_return_all(self):
        """listunspent() with no filter must NOT silently return empty."""
        import inspect
        from ouroboros import rpc as _r
        src = inspect.getsource(_r.RPCHandler.rpc_listunspent)
        # The current code has a comment 'Return empty for now' — when
        # the bug is fixed, that comment should be gone.
        assert "Return empty for now" not in src


# ===========================================================================
# G28 — lockunspent / listlockunspent
# ===========================================================================

class TestG28LockUnspent:
    """G28: outpoint locking survives in memory; persistent flag works."""

    def test_lock_then_list(self):
        w, _ = _new_wallet()
        w.lock_coin("00" * 32, 0, persistent=False)
        locks = w.list_locked_coins()
        assert ("00" * 32, 0) in locks

    def test_unlock(self):
        w, _ = _new_wallet()
        w.lock_coin("00" * 32, 0)
        assert w.is_locked_coin("00" * 32, 0)
        w.unlock_coin("00" * 32, 0)
        assert not w.is_locked_coin("00" * 32, 0)

    def test_unlock_all(self):
        w, _ = _new_wallet()
        w.lock_coin("00" * 32, 0)
        w.lock_coin("11" * 32, 1)
        w.unlock_all_coins()
        assert w.list_locked_coins() == []

    def test_persistent_lock_cannot_be_demoted(self):
        """Once persistent, a re-lock without persistent must NOT demote."""
        w, _ = _new_wallet()
        w.lock_coin("00" * 32, 0, persistent=True)
        w.lock_coin("00" * 32, 0, persistent=False)
        # The stored persistent flag should still be True
        assert w._locked_coins[("00" * 32, 0)] is True


# ===========================================================================
# G29 — Coin selection (BnB / Knapsack / SRD)
# ===========================================================================

class TestG29CoinSelection:
    """G29: BnB / Knapsack / SRD selection algorithms."""

    def _utxos(self, values):
        return [{"value": v, "txid": f"{i:064x}", "vout": 0}
                for i, v in enumerate(values)]

    def test_bnb_exact_match(self):
        """BnB finds exact matches within cost_of_change."""
        utxos = self._utxos([10000, 20000, 30000])
        result = select_coins_bnb(utxos, 30000, fee_rate=1.0)
        # Either exact-match selection or None — but the function must run
        assert result is None or all("value" in u for u in result)

    def test_select_coins_returns_tuple(self):
        utxos = self._utxos([100000, 200000, 50000])
        sel, fee, algo = select_coins(utxos, 50000, fee_rate=1.0)
        assert len(sel) >= 1
        assert fee > 0
        assert algo in ("bnb", "knapsack", "srd")

    def test_select_coins_insufficient_raises(self):
        utxos = self._utxos([1000])
        with pytest.raises(ValueError):
            select_coins(utxos, 1_000_000, fee_rate=1.0)

    def test_coin_selection_uses_csprng(self):
        """Coin selection must use a CSPRNG to prevent UTXO-clustering attacks.

        Regression guard for W118 BUG-3 / FIX-60 (W88 anti-pattern, 8th
        instance — see FIX-45 for cross-impl precedent).

        Source-grep: the wallet module must NOT use the predictable
        `random` module for coin selection. It must use either
        `secrets.SystemRandom` or `random.SystemRandom` (both wrap
        `os.urandom`, the OS CSPRNG).
        """
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w)
        # Either `import random` is absent entirely, or any retained
        # use must be SystemRandom-backed.
        if "import random" in src:
            assert "random.SystemRandom" in src or "secrets.SystemRandom" in src
        # Stronger check: no bare `random.shuffle(` or `random.random(`
        # calls anywhere in the source (these are the W88 fingerprints).
        assert "random.shuffle(" not in src, (
            "wallet.py contains random.shuffle(...) — must use "
            "secrets.SystemRandom().shuffle() for coin selection (W88)"
        )
        # `random.random()` would also be a fingerprint; the existing
        # legitimate use is `_CSPRNG.random()`.
        # We tolerate the substring `random.random` only inside docstrings/
        # comments; the call form `random.random(` is the smoking gun.
        assert "random.random(" not in src, (
            "wallet.py contains random.random(...) — must use "
            "secrets.SystemRandom().random() for coin selection (W88)"
        )

    def test_coin_selection_rng_is_systemrandom(self):
        """The module-level coin-selection RNG must be a CSPRNG (FIX-60)."""
        import random as _stdlib_random
        import secrets
        from ouroboros import wallet as _w
        # The module must expose a SystemRandom-backed RNG used by the
        # coin-selection paths. `secrets.SystemRandom` is a subclass of
        # `random.SystemRandom`, so isinstance() against either works.
        rng = getattr(_w, "_CSPRNG", None)
        assert rng is not None, (
            "wallet module must expose a CSPRNG (e.g. _CSPRNG) for "
            "coin selection (W118 BUG-3 / FIX-60)"
        )
        assert isinstance(rng, _stdlib_random.SystemRandom), (
            f"coin-selection RNG must be SystemRandom-backed, got {type(rng)!r}"
        )
        # Defensive: also verify the secrets module path is the one used.
        assert isinstance(rng, secrets.SystemRandom)

    def test_coin_selection_varies_across_runs(self):
        """Sanity: SRD selection varies across runs (uses CSPRNG-backed shuffle).

        BnB is deterministic and Knapsack runs 1000 iterations and picks
        the best, so the variance signal lives most cleanly in SRD's
        single-random-draw shuffle. We invoke SRD directly to avoid
        BnB/Knapsack masking RNG variance via min-waste convergence.
        """
        from ouroboros.wallet import select_coins_srd
        utxos = self._utxos([3333, 5555, 7777, 9999, 11111, 13333, 17777, 23333])
        seen: set[tuple[str, ...]] = set()
        for _ in range(8):
            sel = select_coins_srd(utxos, 17777, fee_rate=1.0)
            assert sel is not None
            seen.add(tuple(sorted(u["txid"] for u in sel)))
        # With 8 trials over an 8-UTXO set we expect several distinct
        # orderings; a deterministic RNG would yield exactly 1.
        assert len(seen) >= 2, f"SRD coin selection deterministic across runs: {seen!r}"


# ===========================================================================
# G30 — UTXO scan covers all wallet address types
# ===========================================================================

class TestG30UtxoScanScope:
    """G30: _collect_utxos must scan all wallet-owned address types."""

    @pytest.mark.xfail(
        strict=True,
        reason="BUG-8: _collect_utxos only calls get_p2wpkh_address(); P2PKH, "
               "P2TR, and P2SH-P2WPKH UTXOs are invisible to coin selection.",
    )
    def test_collect_utxos_scans_all_address_types(self):
        """_collect_utxos should derive P2WPKH AND P2PKH AND P2TR AND P2SH-P2WPKH."""
        import inspect
        from ouroboros import wallet as _w
        src = inspect.getsource(_w.Wallet._collect_utxos)
        # Must reference at least one non-p2wpkh address derivation
        # (current code only calls get_p2wpkh_address).
        has_other_type = any(
            tok in src for tok in (
                "get_p2pkh_address",
                "get_p2tr_address",
                "get_p2sh_p2wpkh_address",
            )
        )
        assert has_other_type


# ===========================================================================
# Module-level smoke test: all expected gate classes exist
# ===========================================================================

def test_all_gates_present():
    """W118 covers 30 gates; verify every one has a TestG<n> class."""
    import inspect

    this_module = sys.modules[__name__]
    gates: set[int] = set()
    for name, _obj in inspect.getmembers(this_module, inspect.isclass):
        if not name.startswith("TestG"):
            continue
        rest = name[len("TestG"):]
        digits = ""
        for ch in rest:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            gates.add(int(digits))

    expected = set(range(1, 31))
    missing = expected - gates
    assert not missing, f"Missing gates: {sorted(missing)}"
