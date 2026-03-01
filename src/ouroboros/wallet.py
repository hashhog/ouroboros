"""
Bitcoin wallet: key management, address derivation, coin selection, and transaction signing.

Supports P2WPKH (bech32) and P2PKH (legacy) addresses. Keys are stored
as WIF in a JSON wallet file under {data_dir}/wallets/{name}.json.

BIP 32 hierarchical deterministic (HD) derivation and BIP 44/84
derivation paths are supported when the wallet is initialised from
a seed via ``Wallet.init_hd()``.

Output descriptor support (BIP 380–386) allows importing descriptors
such as ``wpkh(xpub.../0/*)``, ``pkh(...)``, ``tr(...)``, ``sh(wpkh(...))``,
``multi(M, ...)``, and ``wsh(multi(...))``.  Addresses are derived from
descriptors with range support via ``importdescriptors``.
"""

import hashlib
import hmac
import json
import logging
import os
import random
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import base58
import bech32
from coincurve import PrivateKey, PublicKey

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# secp256k1 curve order
SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


class AddressInfo(BaseModel):
    """Address information model."""

    address: str
    balance: int  # satoshis
    label: str | None = None


class TransactionInfo(BaseModel):
    """Transaction information model."""

    txid: str
    amount: int  # satoshis
    confirmations: int
    timestamp: int | None = None


# Wallet encryption (AES-256-GCM + scrypt)

def encrypt_wallet_data(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt wallet data with *passphrase* (scrypt + AES-256-GCM); output: salt(16)||nonce(12)||ct."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 18, r=8, p=1)
    key = kdf.derive(passphrase.encode("utf-8"))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_wallet_data(blob: bytes, passphrase: str) -> bytes:
    """Decrypt data produced by :func:`encrypt_wallet_data`; raises ValueError on wrong passphrase."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    if len(blob) < 28:
        raise ValueError("Encrypted blob too short")
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    kdf = Scrypt(salt=salt, length=32, n=2 ** 18, r=8, p=1)
    key = kdf.derive(passphrase.encode("utf-8"))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed (wrong passphrase or corrupt data)")


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# --- Coin Selection Algorithms ---
#
# Reference: bitcoin/src/wallet/coinselection.cpp
#
# Each function takes a list of UTXO dicts (must have "value": int)
# and a target amount (including fee).  They return a list of selected
# UTXOs or None on failure.
#
# P2WPKH cost model used throughout:
#   - Input cost:  68 vB
#   - Output cost: 31 vB
#   - Overhead:    11 vB (fixed)
#   - Cost of change = 31 (output) + 68 (later spending it) = 99 vB

INPUT_VBYTES = 68
OUTPUT_VBYTES = 31
OVERHEAD_VBYTES = 11
COST_OF_CHANGE_VBYTES = INPUT_VBYTES + OUTPUT_VBYTES  # 99 vB

# BnB search limit
BNB_MAX_TRIES = 100_000

# Default long-term fee rate (sat/vB) used by the waste metric.
# This represents the fee rate at which we'd ideally consolidate UTXOs.
DEFAULT_LONG_TERM_FEE_RATE = 10.0


def _estimate_fee(n_inputs: int, n_outputs: int, fee_rate: float) -> int:
    vsize = OVERHEAD_VBYTES + n_inputs * INPUT_VBYTES + n_outputs * OUTPUT_VBYTES
    return int(vsize * fee_rate) + 1


def select_coins_bnb(
    utxos: List[Dict],
    target: int,
    fee_rate: float,
    *,
    cost_of_change: Optional[int] = None,
) -> Optional[List[Dict]]:
    """
    Branch-and-Bound coin selection (exact match, no change output).

    Searches for a subset of UTXOs whose total value equals the target
    plus fees within [target, target + cost_of_change).  An exact match
    avoids creating a change output, saving ~99 vB.

    Returns selected UTXOs or None if no exact match is found within
    BNB_MAX_TRIES iterations.
    """
    if cost_of_change is None:
        cost_of_change = int(COST_OF_CHANGE_VBYTES * fee_rate) + 1

    sorted_utxos = sorted(utxos, key=lambda u: u["value"], reverse=True)
    n = len(sorted_utxos)
    if n == 0:
        return None

    best: Optional[List[int]] = None
    best_waste = float("inf")
    current: List[int] = []
    current_value = 0
    tries = 0

    # Effective values (value minus cost to spend the input)
    input_fee = int(INPUT_VBYTES * fee_rate)
    eff_values = [u["value"] - input_fee for u in sorted_utxos]

    # Pre-compute suffix sums of effective values for early pruning
    suffix_sum = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        suffix_sum[i] = suffix_sum[i + 1] + max(0, eff_values[i])

    def backtrack(idx: int) -> None:
        nonlocal current_value, best, best_waste, tries

        if tries >= BNB_MAX_TRIES:
            return

        if current_value >= target:
            waste = current_value - target
            if waste < cost_of_change and waste < best_waste:
                best_waste = waste
                best = list(current)
            return

        if idx >= n:
            return

        remaining = suffix_sum[idx]
        if current_value + remaining < target:
            return

        tries += 1

        # Include utxo[idx]
        ev = eff_values[idx]
        if ev > 0:
            current.append(idx)
            current_value += ev
            backtrack(idx + 1)
            current_value -= ev
            current.pop()

        # Exclude utxo[idx]
        backtrack(idx + 1)

    backtrack(0)

    if best is None:
        return None
    return [sorted_utxos[i] for i in best]


def select_coins_knapsack(
    utxos: List[Dict],
    target: int,
    fee_rate: float,
    *,
    iterations: int = 1000,
) -> Optional[List[Dict]]:
    """
    Knapsack coin selection (randomised approximation).

    Repeatedly performs a random pass over the UTXOs, including each
    with 50% probability.  Tracks the closest-to-target result that
    is >= target.  Falls back to the smallest single UTXO >= target
    if one exists and is better.

    Returns selected UTXOs or None if insufficient funds.
    """
    input_fee = int(INPUT_VBYTES * fee_rate)
    effective = [(u, u["value"] - input_fee) for u in utxos if u["value"] > input_fee]
    if not effective:
        return None

    total_eff = sum(ev for _, ev in effective)
    if total_eff < target:
        return None

    best_selection: Optional[List[Dict]] = None
    best_overshoot = float("inf")

    # Check if any single UTXO covers the target exactly or near-exactly
    for u, ev in effective:
        if ev >= target:
            overshoot = ev - target
            if overshoot < best_overshoot:
                best_overshoot = overshoot
                best_selection = [u]

    for _ in range(iterations):
        selected: List[Dict] = []
        selected_value = 0

        shuffled = list(effective)
        random.shuffle(shuffled)

        for u, ev in shuffled:
            if random.random() < 0.5:
                selected.append(u)
                selected_value += ev
                if selected_value >= target:
                    break

        if selected_value >= target:
            overshoot = selected_value - target
            if overshoot < best_overshoot:
                best_overshoot = overshoot
                best_selection = list(selected)

    return best_selection


def select_coins_srd(
    utxos: List[Dict],
    target: int,
    fee_rate: float,
) -> Optional[List[Dict]]:
    """
    Single Random Draw coin selection (last-resort fallback).

    Shuffles UTXOs and greedily adds them until the target is met.
    Simple but produces a valid selection when BnB and Knapsack fail.

    Returns selected UTXOs or None if insufficient funds.
    """
    input_fee = int(INPUT_VBYTES * fee_rate)
    pool = [u for u in utxos if u["value"] > input_fee]
    random.shuffle(pool)

    selected: List[Dict] = []
    total = 0
    for u in pool:
        selected.append(u)
        total += u["value"] - input_fee
        if total >= target:
            return selected

    return None


def _non_input_fee(n_outputs: int, fee_rate: float) -> int:
    return int((OVERHEAD_VBYTES + n_outputs * OUTPUT_VBYTES) * fee_rate) + 1


def _selection_waste(
    selected: List[Dict],
    fee_rate: float,
    long_term_fee_rate: float,
    has_change: bool,
) -> float:
    total_input_weight = len(selected) * INPUT_VBYTES
    timing_cost = total_input_weight * (fee_rate - long_term_fee_rate)
    change_cost = 0.0 if not has_change else COST_OF_CHANGE_VBYTES * fee_rate
    return timing_cost + change_cost


def select_coins(
    utxos: List[Dict],
    target_amount: int,
    fee_rate: float,
    *,
    long_term_fee_rate: float = DEFAULT_LONG_TERM_FEE_RATE,
) -> Tuple[List[Dict], int, str]:
    """Three-tier coin selection with waste-metric optimisation (BnB → Knapsack → SRD).

    Returns ``(selected_utxos, estimated_fee, algorithm_used)``; raises ValueError if funds
    are insufficient.
    """
    # Collect (result, fee, algo_name, has_change) for every algorithm
    # that returns a valid selection.
    candidates: List[Tuple[List[Dict], int, str, bool]] = []

    # BnB: target = amount + (overhead + 1 output fee).
    # BnB internally subtracts per-input cost from each UTXO's effective value.
    bnb_target = target_amount + _non_input_fee(1, fee_rate)
    result = select_coins_bnb(utxos, bnb_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 1, fee_rate)
        candidates.append((result, fee, "bnb", False))

    # Knapsack / SRD: target = amount + (overhead + 2 output fees).
    # Input fees are handled inside each algorithm via effective values.
    change_target = target_amount + _non_input_fee(2, fee_rate)

    result = select_coins_knapsack(utxos, change_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 2, fee_rate)
        candidates.append((result, fee, "knapsack", True))

    result = select_coins_srd(utxos, change_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 2, fee_rate)
        candidates.append((result, fee, "srd", True))

    if not candidates:
        raise ValueError(
            f"Insufficient funds: cannot cover {target_amount} sat + fees "
            f"at {fee_rate} sat/vB"
        )

    # Pick the candidate with the lowest waste.
    best = min(
        candidates,
        key=lambda c: _selection_waste(c[0], fee_rate, long_term_fee_rate, c[3]),
    )
    return best[0], best[1], best[2]


class HDKey:
    """
    BIP 32 extended key (private).

    Supports master-key generation from a seed, child derivation
    (normal and hardened), path-string parsing (e.g. ``m/84'/0'/0'/0/0``),
    and xprv / xpub serialisation.
    """

    # BIP 32 version bytes
    _XPRV_MAINNET = 0x0488ADE4
    _XPUB_MAINNET = 0x0488B21E
    _XPRV_TESTNET = 0x04358394
    _XPUB_TESTNET = 0x043587CF

    def __init__(
        self,
        private_key: bytes,
        chain_code: bytes,
        depth: int = 0,
        parent_fingerprint: bytes = b"\x00\x00\x00\x00",
        child_index: int = 0,
        network: str = "mainnet",
    ):
        if len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes")
        if len(chain_code) != 32:
            raise ValueError("chain_code must be 32 bytes")
        self.private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_index = child_index
        self.network = network

    # public key helpers

    @property
    def public_key(self) -> bytes:
        """Compressed SEC public key (33 bytes)."""
        return PublicKey.from_secret(self.private_key).format(compressed=True)

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of HASH160(pubkey) — used as parent id."""
        return _hash160(self.public_key)[:4]

    # BIP 32 master key

    @classmethod
    def from_seed(cls, seed: bytes, network: str = "mainnet") -> "HDKey":
        """Derive the BIP 32 master key from a binary seed (16-64 bytes)."""
        if not 16 <= len(seed) <= 64:
            raise ValueError("Seed must be 16–64 bytes")
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key = I[:32]
        if int.from_bytes(key, "big") == 0 or int.from_bytes(key, "big") >= SECP256K1_ORDER:
            raise ValueError("Invalid master key (out of range)")
        return cls(private_key=key, chain_code=I[32:], network=network)

    # child derivation

    def derive_child(self, index: int, hardened: bool = False) -> "HDKey":
        """Derive a child extended key at *index*."""
        if hardened:
            index |= 0x80000000
        if index & 0x80000000:
            data = b"\x00" + self.private_key + index.to_bytes(4, "big")
        else:
            data = self.public_key + index.to_bytes(4, "big")

        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        if il >= SECP256K1_ORDER:
            raise ValueError("Derived key is out of range")
        child_int = (il + int.from_bytes(self.private_key, "big")) % SECP256K1_ORDER
        if child_int == 0:
            raise ValueError("Derived key is zero")
        child_key = child_int.to_bytes(32, "big")
        return HDKey(
            private_key=child_key,
            chain_code=I[32:],
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_index=index,
            network=self.network,
        )

    # path derivation

    def derive_path(self, path: str) -> "HDKey":
        """Derive a child key from a BIP 32 path like ``"m/84'/0'/0'/0/0"`` (``'``/``h`` = hardened)."""
        parts = path.strip().split("/")
        if parts[0] != "m":
            raise ValueError(f"Path must start with 'm': {path}")
        node = self
        for part in parts[1:]:
            hardened = part.endswith("'") or part.endswith("h")
            idx = int(part.rstrip("'h"))
            node = node.derive_child(idx, hardened=hardened)
        return node

    def to_wallet_key(self) -> "WalletKey":
        return WalletKey(self.private_key, self.network)

    # xprv / xpub serialisation (BIP 32)

    def serialize_xprv(self) -> str:
        """Base58check-encoded extended private key (xprv / tprv)."""
        ver = self._XPRV_MAINNET if self.network == "mainnet" else self._XPRV_TESTNET
        return self._serialize_extended(ver, b"\x00" + self.private_key)

    def serialize_xpub(self) -> str:
        """Base58check-encoded extended public key (xpub / tpub)."""
        ver = self._XPUB_MAINNET if self.network == "mainnet" else self._XPUB_TESTNET
        return self._serialize_extended(ver, self.public_key)

    def _serialize_extended(self, version: int, key_data: bytes) -> str:
        payload = struct.pack(">I", version)
        payload += bytes([self.depth])
        payload += self.parent_fingerprint
        payload += struct.pack(">I", self.child_index)
        payload += self.chain_code
        payload += key_data
        return base58.b58encode_check(payload).decode()

    @classmethod
    def from_xprv(cls, xprv: str, network: str = "mainnet") -> "HDKey":
        """Deserialise a base58check xprv / tprv string."""
        raw = base58.b58decode_check(xprv)
        if len(raw) != 78:
            raise ValueError("Invalid extended key length")
        depth = raw[4]
        parent_fp = raw[5:9]
        child_idx = struct.unpack(">I", raw[9:13])[0]
        chain_code = raw[13:45]
        if raw[45] != 0:
            raise ValueError("Not an extended private key")
        private_key = raw[46:78]
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fp,
            child_index=child_idx,
            network=network,
        )


class WalletKey:
    """A single secp256k1 private/public key pair with address derivation."""

    def __init__(self, secret: bytes, network: str = "mainnet"):
        if len(secret) != 32:
            raise ValueError("Private key must be 32 bytes")
        self._privkey = PrivateKey(secret)
        self.secret = secret
        self.network = network
        self.pubkey = self._privkey.public_key.format(compressed=True)

    @classmethod
    def generate(cls, network: str = "mainnet") -> "WalletKey":
        return cls(os.urandom(32), network)

    # --- address derivation ---------------------------------------------------

    def get_p2wpkh_address(self) -> str:
        """Native SegWit bech32 P2WPKH address."""
        h160 = _hash160(self.pubkey)
        hrp = "bc" if self.network == "mainnet" else "tb"
        converted = bech32.convertbits(h160, 8, 5)
        return bech32.bech32_encode(hrp, [0] + converted)

    def get_p2pkh_address(self) -> str:
        """Legacy P2PKH address."""
        h160 = _hash160(self.pubkey)
        version = b"\x00" if self.network == "mainnet" else b"\x6f"
        payload = version + h160
        return base58.b58encode_check(payload).decode()

    def get_p2sh_p2wpkh_address(self) -> str:
        """P2SH-wrapped P2WPKH address (3xxx / 2xxx)."""
        h160 = _hash160(self.pubkey)
        redeem_script = b"\x00\x14" + h160
        script_hash = _hash160(redeem_script)
        version = b"\x05" if self.network == "mainnet" else b"\xc4"
        return base58.b58encode_check(version + script_hash).decode()

    def get_p2tr_address(self) -> str:
        """Taproot bech32m P2TR address (key-path only, no scripts)."""
        from ouroboros.address import _bech32m_encode

        x_only = self.pubkey[1:]  # drop the 0x02/0x03 prefix
        # Tweak with empty merkle root for key-path-only spending
        tweak = hashlib.sha256(
            hashlib.sha256(b"TapTweak").digest()
            + hashlib.sha256(b"TapTweak").digest()
            + x_only
        ).digest()
        # We need to compute P + t*G. Use coincurve for point arithmetic.
        try:
            from coincurve import PublicKey as CPublicKey
            pk = CPublicKey(self.pubkey)
            tweaked = pk.add(tweak)
            tweaked_x = tweaked.format(compressed=True)[1:]
        except Exception:
            tweaked_x = x_only

        hrp = "bc" if self.network == "mainnet" else "tb"
        return _bech32m_encode(hrp, 1, tweaked_x)

    def get_script_pubkey(self) -> bytes:
        """P2WPKH scriptPubKey: OP_0 <20-byte-hash>."""
        return b"\x00\x14" + _hash160(self.pubkey)

    def get_p2tr_script_pubkey(self) -> bytes:
        """P2TR scriptPubKey: OP_1 <32-byte-x-only-key>."""
        x_only = self.pubkey[1:]
        return b"\x51\x20" + x_only

    # --- WIF -------------------------------------------------------------------

    def to_wif(self) -> str:
        version = b"\x80" if self.network == "mainnet" else b"\xef"
        payload = version + self.secret + b"\x01"  # compressed flag
        return base58.b58encode_check(payload).decode()

    @classmethod
    def from_wif(cls, wif: str, network: str = "mainnet") -> "WalletKey":
        decoded = base58.b58decode_check(wif)
        key_bytes = decoded[1:]
        if len(key_bytes) == 33 and key_bytes[-1] == 0x01:
            key_bytes = key_bytes[:-1]
        return cls(bytes(key_bytes), network)

    # --- signing ---------------------------------------------------------------

    def sign(self, message_hash: bytes) -> bytes:
        """Sign a 32-byte hash, return DER-encoded signature."""
        return self._privkey.sign(message_hash, hasher=None)


class Wallet:
    """
    Bitcoin wallet with key management, coin selection, and transaction signing.

    Wallet file (JSON)::

        {
            "version": 1,
            "network": "mainnet",
            "keys": [{"wif": "...", "label": "...", "created": 123}],
            "descriptors": [{"desc": "wpkh(xpub.../0/*)#checksum", ...}]
        }
    """

    # Default BIP 84 derivation base for native SegWit
    HD_BASE_PATH = "m/84'/0'/0'/0"

    def __init__(
        self,
        data_dir: str,
        network: str = "mainnet",
        name: str = "default",
    ):
        self.data_dir = Path(data_dir).expanduser()
        self.network = network
        self.name = name
        self.wallet_path = self.data_dir / "wallets" / f"{name}.json"
        self.keys: List[Dict] = []
        self.descriptors: List = []  # List[DescriptorEntry]
        self.db = None  # set via set_database()
        self.mempool = None  # set via set_mempool()
        self._hd_seed: Optional[bytes] = None
        self._hd_next_index: int = 0
        self._hd_base_path: str = self.HD_BASE_PATH
        self._passphrase: Optional[str] = None
        self._encrypted_blob: Optional[bytes] = None
        self._load_or_create()

    # HD seed management #

    def init_hd(self, seed: bytes, base_path: Optional[str] = None) -> str:
        """Initialise the wallet in HD mode from a BIP 32 *seed*; returns the xprv of the master key."""
        master = HDKey.from_seed(seed, self.network)
        self._hd_seed = seed
        self._hd_next_index = 0
        if base_path is not None:
            self._hd_base_path = base_path
        self._save()
        logger.info(f"Wallet '{self.name}' initialised in HD mode")
        return master.serialize_xprv()

    @property
    def is_hd(self) -> bool:
        return self._hd_seed is not None

    def get_hd_master(self) -> Optional[HDKey]:
        if self._hd_seed is None:
            return None
        return HDKey.from_seed(self._hd_seed, self.network)

    # persistence

    def _load_or_create(self) -> None:
        from ouroboros.descriptors import DescriptorEntry

        if self.wallet_path.exists():
            with open(self.wallet_path) as f:
                data = json.load(f)
            if data.get("encrypted"):
                self._encrypted_blob = bytes.fromhex(data["ciphertext"])
                self.keys = []
                self.descriptors = []
                logger.info(
                    f"Loaded encrypted wallet '{self.name}' — "
                    "call unlock(passphrase) to decrypt"
                )
                return
            self._encrypted_blob = None
            self.keys = data.get("keys", [])
            # Load descriptors
            self.descriptors = [
                DescriptorEntry.from_dict(d)
                for d in data.get("descriptors", [])
            ]
            hd = data.get("hd")
            if hd:
                self._hd_seed = bytes.fromhex(hd["seed_hex"])
                self._hd_next_index = hd.get("next_index", 0)
                self._hd_base_path = hd.get("base_path", self.HD_BASE_PATH)
            logger.info(
                f"Loaded wallet '{self.name}' with {len(self.keys)} keys, "
                f"{len(self.descriptors)} descriptors"
                + (" (HD)" if self._hd_seed else "")
            )
        else:
            self._encrypted_blob = None
            self.wallet_path.parent.mkdir(parents=True, exist_ok=True)
            self._save()
            logger.info(f"Created new wallet '{self.name}'")

    def _save(self) -> None:
        inner: Dict = {
            "keys": self.keys,
        }
        if self.descriptors:
            inner["descriptors"] = [d.to_dict() for d in self.descriptors]
        if self._hd_seed is not None:
            inner["hd"] = {
                "seed_hex": self._hd_seed.hex(),
                "next_index": self._hd_next_index,
                "base_path": self._hd_base_path,
            }

        if self._passphrase is not None:
            plaintext = json.dumps(inner).encode("utf-8")
            blob = encrypt_wallet_data(plaintext, self._passphrase)
            outer: Dict = {
                "version": 1,
                "network": self.network,
                "encrypted": True,
                "ciphertext": blob.hex(),
            }
        else:
            outer = {"version": 1, "network": self.network, **inner}

        tmp = self.wallet_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(outer, f, indent=2)
        tmp.rename(self.wallet_path)

    # --- encryption / decryption ---

    @property
    def is_encrypted(self) -> bool:
        """True when the on-disk wallet is encrypted (may still be unlocked in memory)."""
        return self._encrypted_blob is not None or self._passphrase is not None

    @property
    def is_locked(self) -> bool:
        """True when the wallet is encrypted and has not been unlocked yet."""
        return self._encrypted_blob is not None and self._passphrase is None

    def encrypt(self, passphrase: str) -> None:
        """Encrypt the wallet with *passphrase* and persist; every subsequent save writes ciphertext."""
        if not passphrase:
            raise ValueError("Passphrase must not be empty")
        self._passphrase = passphrase
        self._encrypted_blob = None
        self._save()
        logger.info(f"Wallet '{self.name}' encrypted")

    def unlock(self, passphrase: str) -> None:
        """Decrypt an encrypted wallet that was loaded from disk."""
        from ouroboros.descriptors import DescriptorEntry

        if self._encrypted_blob is None:
            raise ValueError("Wallet is not encrypted")
        plaintext = decrypt_wallet_data(self._encrypted_blob, passphrase)
        data = json.loads(plaintext.decode("utf-8"))
        self.keys = data.get("keys", [])
        self.descriptors = [
            DescriptorEntry.from_dict(d)
            for d in data.get("descriptors", [])
        ]
        hd = data.get("hd")
        if hd:
            self._hd_seed = bytes.fromhex(hd["seed_hex"])
            self._hd_next_index = hd.get("next_index", 0)
            self._hd_base_path = hd.get("base_path", self.HD_BASE_PATH)
        self._passphrase = passphrase
        self._encrypted_blob = None
        logger.info(f"Wallet '{self.name}' unlocked")

    def lock(self) -> None:
        """Re-lock the wallet: save encrypted and wipe in-memory keys."""
        if self._passphrase is None:
            raise ValueError("Wallet is not unlocked")
        self._save()
        self._encrypted_blob = self._read_encrypted_blob()
        self.keys = []
        self.descriptors = []
        self._hd_seed = None
        self._hd_next_index = 0
        self._passphrase = None
        logger.info(f"Wallet '{self.name}' locked")

    def _read_encrypted_blob(self) -> Optional[bytes]:
        if self.wallet_path.exists():
            with open(self.wallet_path) as f:
                data = json.load(f)
            if data.get("encrypted"):
                return bytes.fromhex(data["ciphertext"])
        return None

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        """Re-encrypt the wallet with a new passphrase."""
        if not new_passphrase:
            raise ValueError("New passphrase must not be empty")
        if self._passphrase is None and self._encrypted_blob is not None:
            self.unlock(old_passphrase)
        self._passphrase = new_passphrase
        self._save()
        logger.info(f"Wallet '{self.name}' passphrase changed")

    def set_database(self, db) -> None:
        self.db = db

    def set_mempool(self, mempool) -> None:
        self.mempool = mempool

    # --- key / address operations ---------------------------------------------

    def _get_wallet_key(self, key_data: Dict) -> WalletKey:
        return WalletKey.from_wif(key_data["wif"], self.network)

    async def generate_new_address(self, label: str | None = None) -> str:
        if self._hd_seed is not None:
            path = f"{self._hd_base_path}/{self._hd_next_index}"
            hd = HDKey.from_seed(self._hd_seed, self.network).derive_path(path)
            key = hd.to_wallet_key()
            self._hd_next_index += 1
        else:
            key = WalletKey.generate(self.network)

        self.keys.append({
            "wif": key.to_wif(),
            "label": label or "",
            "created": int(time.time()),
        })
        self._save()
        addr = key.get_p2wpkh_address()
        logger.info(f"Generated new address {addr}")
        return addr

    async def get_balance(self, address: str | None = None) -> int:
        if self.db is None:
            return 0
        if address:
            return self.db.get_balance(address, self.network)
        total = 0
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            total += self.db.get_balance(k.get_p2wpkh_address(), self.network)
        return total

    async def get_addresses(self) -> list[AddressInfo]:
        result: list[AddressInfo] = []
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            addr = k.get_p2wpkh_address()
            balance = self.db.get_balance(addr, self.network) if self.db else 0
            result.append(AddressInfo(
                address=addr,
                balance=balance,
                label=kd.get("label"),
            ))
        # Include addresses from active descriptors
        for entry in self.descriptors:
            if not entry.active:
                continue
            end = max(entry.next_index, entry.range_start + 1)
            for i in range(entry.range_start, end):
                addr = entry.descriptor.derive_address(i, self.network)
                balance = self.db.get_balance(addr, self.network) if self.db else 0
                result.append(AddressInfo(
                    address=addr,
                    balance=balance,
                    label=entry.label or None,
                ))
        return result

    async def get_transactions(
        self, address: str | None = None
    ) -> list[TransactionInfo]:
        """Return transaction history for the wallet or a specific address."""
        if self.db is None:
            return []
        results: list[TransactionInfo] = []
        addresses = set()
        if address:
            addresses.add(address)
        else:
            for kd in self.keys:
                k = self._get_wallet_key(kd)
                addresses.add(k.get_p2wpkh_address())
                addresses.add(k.get_p2pkh_address())
        for addr in addresses:
            txs = self.db.get_transactions_for_address(addr, self.network)
            for tx_info in txs:
                results.append(TransactionInfo(
                    txid=tx_info.get('txid', ''),
                    amount=tx_info.get('amount', 0),
                    confirmations=tx_info.get('confirmations', 0),
                    timestamp=tx_info.get('timestamp'),
                ))
        return results

    async def generate_address_of_type(
        self, address_type: str = "bech32", label: str | None = None
    ) -> str:
        """Generate address of given type: bech32, legacy, p2sh-segwit, bech32m."""
        if self._hd_seed is not None:
            path = f"{self._hd_base_path}/{self._hd_next_index}"
            hd = HDKey.from_seed(self._hd_seed, self.network).derive_path(path)
            key = hd.to_wallet_key()
            self._hd_next_index += 1
        else:
            key = WalletKey.generate(self.network)

        self.keys.append({
            "wif": key.to_wif(),
            "label": label or "",
            "created": int(time.time()),
        })
        self._save()

        if address_type == "legacy":
            return key.get_p2pkh_address()
        elif address_type == "p2sh-segwit":
            return key.get_p2sh_p2wpkh_address()
        elif address_type == "bech32m":
            return key.get_p2tr_address()
        else:
            return key.get_p2wpkh_address()

    async def bump_fee(
        self, txid: str, new_fee_rate: int, *, sign: bool = True
    ) -> Optional[str]:
        """Create an RBF fee-bumped version of *txid* at *new_fee_rate* sat/vB.

        Verifies the original signals RBF (sequence < 0xFFFFFFFE), then reduces
        the change output (or adds a new input) to cover the higher fee.
        Returns signed tx hex when *sign=True*, unsigned hex otherwise, or None on failure.
        """
        from ouroboros.database import Transaction, TxIn, TxOut

        if self.db is None or self.mempool is None:
            logger.warning("bump_fee: database or mempool not available")
            return None

        # 1. Look up the original tx in mempool
        txid_bytes = bytes.fromhex(txid)
        entry = self.mempool.get_transaction_entry(txid_bytes)
        if entry is None:
            logger.warning("bump_fee: transaction %s not in mempool", txid)
            return None
        orig_tx = entry.tx
        orig_fee = entry.fee

        # 2. Verify RBF signal
        rbf_signaled = any(inp.sequence < 0xFFFFFFFE for inp in orig_tx.inputs)
        if not rbf_signaled:
            logger.warning(
                "bump_fee: transaction %s does not signal RBF "
                "(no input with sequence < 0xFFFFFFFE)",
                txid,
            )
            return None

        # 3. Gather input values and wallet keys
        # Build a lookup of wallet script_pubkeys → WalletKey
        wallet_spk_map: Dict[bytes, "WalletKey"] = {}
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            wallet_spk_map[k.get_script_pubkey()] = k

        input_values: List[int] = []
        input_keys: List[Optional["WalletKey"]] = []
        for inp in orig_tx.inputs:
            # Try UTXO set first (confirmed), then check mempool outputs
            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo is not None:
                input_values.append(utxo["value"])
                spk = utxo.get("script_pubkey", b"")
                if isinstance(spk, str):
                    spk = bytes.fromhex(spk)
                input_keys.append(wallet_spk_map.get(spk))
            else:
                # Parent might be in mempool
                parent_tx = self.mempool.get_transaction(inp.prev_txid)
                if parent_tx is not None and inp.prev_vout < len(parent_tx.outputs):
                    out = parent_tx.outputs[inp.prev_vout]
                    input_values.append(out.value)
                    input_keys.append(wallet_spk_map.get(out.script_pubkey))
                else:
                    logger.warning(
                        "bump_fee: cannot find value for input %s:%d",
                        inp.prev_txid.hex(),
                        inp.prev_vout,
                    )
                    return None

        total_input_value = sum(input_values)

        # 4. Calculate target fee
        # Start with the same outputs; adjust change later.
        new_outputs = [
            TxOut(value=out.value, script_pubkey=out.script_pubkey)
            for out in orig_tx.outputs
        ]
        new_inputs = [
            TxIn(
                prev_txid=inp.prev_txid,
                prev_vout=inp.prev_vout,
                script_sig=b"",
                sequence=0xFFFFFFFD,  # signal RBF
            )
            for inp in orig_tx.inputs
        ]

        # Estimate vsize with current input/output counts
        est_vsize = (
            OVERHEAD_VBYTES
            + len(new_inputs) * INPUT_VBYTES
            + len(new_outputs) * OUTPUT_VBYTES
        )
        target_fee = max(int(new_fee_rate * est_vsize), orig_fee + 1)

        total_output_value = sum(o.value for o in new_outputs)
        fee_increase_needed = target_fee - (total_input_value - total_output_value)

        # 5. Identify and reduce the change output
        # The change output is the one paying to a wallet address.
        change_idx: Optional[int] = None
        for i, out in enumerate(new_outputs):
            if out.script_pubkey in wallet_spk_map:
                change_idx = i
                break

        if fee_increase_needed > 0:
            if change_idx is not None:
                available_change = new_outputs[change_idx].value
                if available_change - fee_increase_needed > 546:
                    # Reduce change to cover increased fee
                    new_outputs[change_idx] = TxOut(
                        value=available_change - fee_increase_needed,
                        script_pubkey=new_outputs[change_idx].script_pubkey,
                    )
                elif available_change - fee_increase_needed >= 0:
                    # Change would become dust – remove it entirely
                    new_outputs.pop(change_idx)
                    # Recalculate since we removed an output
                    est_vsize = (
                        OVERHEAD_VBYTES
                        + len(new_inputs) * INPUT_VBYTES
                        + len(new_outputs) * OUTPUT_VBYTES
                    )
                    target_fee = max(
                        int(new_fee_rate * est_vsize), orig_fee + 1
                    )
                else:
                    # Need to add a new input to cover the fee
                    if not self._add_input_for_fee(
                        new_inputs,
                        new_outputs,
                        input_values,
                        input_keys,
                        wallet_spk_map,
                        new_fee_rate,
                        target_fee,
                        total_input_value,
                        orig_fee,
                    ):
                        logger.warning(
                            "bump_fee: insufficient funds to bump fee"
                        )
                        return None
            else:
                # No change output exists; must add a new input
                if not self._add_input_for_fee(
                    new_inputs,
                    new_outputs,
                    input_values,
                    input_keys,
                    wallet_spk_map,
                    new_fee_rate,
                    target_fee,
                    total_input_value,
                    orig_fee,
                ):
                    logger.warning(
                        "bump_fee: insufficient funds to bump fee"
                    )
                    return None

        # 6. Build the new transaction
        new_tx = Transaction(
            txid=b"\x00" * 32,
            version=orig_tx.version,
            locktime=orig_tx.locktime,
            inputs=new_inputs,
            outputs=new_outputs,
            has_witness=True,
        )

        if sign:
            # 7. Sign all inputs
            for i, inp in enumerate(new_inputs):
                if i < len(input_keys) and input_keys[i] is not None:
                    key = input_keys[i]
                    sighash = self._bip143_sighash(
                        new_tx, i, key.pubkey, input_values[i]
                    )
                    sig = key.sign(sighash) + b"\x01"  # SIGHASH_ALL
                    new_tx.inputs[i].witness = [sig, key.pubkey]
                else:
                    logger.warning(
                        "bump_fee: cannot sign input %d – key not in wallet", i
                    )
                    return None

            # Compute real txid
            new_tx.txid = _dsha256(new_tx.serialize())

            # 8. Submit via mempool.try_replace()
            _, best_height = self.db.get_best_block()
            success, error = self.mempool.try_replace(new_tx, best_height)
            if not success:
                logger.warning("bump_fee: mempool rejected replacement: %s", error)
                return None

            new_txid = new_tx.txid.hex()
            logger.info(
                "bump_fee: replaced %s with %s (fee_rate=%d sat/vB)",
                txid,
                new_txid,
                new_fee_rate,
            )
            return new_txid
        else:
            # Return unsigned raw hex for PSBT workflow
            return new_tx.serialize_with_witness().hex()

    def _add_input_for_fee(
        self,
        new_inputs: list,
        new_outputs: list,
        input_values: list,
        input_keys: list,
        wallet_spk_map: Dict[bytes, "WalletKey"],
        new_fee_rate: int,
        target_fee: int,
        total_input_value: int,
        orig_fee: int,
    ) -> bool:
        """Add a new wallet UTXO to cover the fee increase when the change."""
        from ouroboros.database import TxIn, TxOut

        # Collect UTXOs not already used by the transaction
        used_outpoints = {
            (inp.prev_txid, inp.prev_vout) for inp in new_inputs
        }
        available = [
            u
            for u in self._collect_utxos()
            if (
                (bytes.fromhex(u["txid"]) if isinstance(u["txid"], str) else u["txid"]),
                u["vout"],
            )
            not in used_outpoints
        ]
        if not available:
            return False

        # Sort descending by value for a greedy pick
        available.sort(key=lambda u: u["value"], reverse=True)

        total_output_value = sum(o.value for o in new_outputs)
        needed = target_fee - (total_input_value - total_output_value)

        for utxo in available:
            utxo_txid = (
                bytes.fromhex(utxo["txid"])
                if isinstance(utxo["txid"], str)
                else utxo["txid"]
            )
            new_inputs.append(
                TxIn(
                    prev_txid=utxo_txid,
                    prev_vout=utxo["vout"],
                    script_sig=b"",
                    sequence=0xFFFFFFFD,
                )
            )
            input_values.append(utxo["value"])
            key = utxo.get("_key")
            input_keys.append(key)

            total_input_value += utxo["value"]

            # Recalculate fee with new input (and possibly new change output)
            est_vsize = (
                OVERHEAD_VBYTES
                + len(new_inputs) * INPUT_VBYTES
                + (len(new_outputs) + 1) * OUTPUT_VBYTES  # +1 for potential change
            )
            target_fee = max(int(new_fee_rate * est_vsize), orig_fee + 1)
            change = total_input_value - total_output_value - target_fee

            if change > 546:
                # Add change output
                change_key = self._get_wallet_key(self.keys[0])
                new_outputs.append(
                    TxOut(
                        value=change,
                        script_pubkey=change_key.get_script_pubkey(),
                    )
                )
                return True
            elif change >= 0:
                # No change needed (dust absorbed into fee)
                return True
            # else: keep trying with another UTXO (rare)

        return False

    # --- descriptor operations ---------------------------------------------------

    def importdescriptors(
        self, requests: List[Dict]
    ) -> List[Dict]:
        """
        Import one or more output descriptors into the wallet.

        Each element of *requests* is a dict in the ``importdescriptors``
        RPC format::

            {
                "desc": "wpkh(xpub.../0/*)#checksum",
                "active": true,            # optional, default true
                "range": [0, 1000],         # optional, default [0, 1000]
                "next_index": 0,            # optional, default 0
                "timestamp": "now"|int,     # optional
                "internal": false,          # optional
                "label": ""                 # optional
            }

        Returns a list of result dicts, one per request, each containing
        ``{"success": true}`` or ``{"success": false, "error": {...}}``.
        """
        from ouroboros.descriptors import (
            DescriptorEntry,
            add_checksum,
            parse_descriptor,
            verify_checksum,
        )

        results: List[Dict] = []

        for req in requests:
            try:
                desc_str = req.get("desc", "")
                if not desc_str:
                    raise ValueError("Missing 'desc' field")

                # Validate / add checksum
                if "#" in desc_str:
                    if not verify_checksum(desc_str):
                        raise ValueError(f"Invalid checksum in: {desc_str}")
                else:
                    desc_str = add_checksum(desc_str)

                descriptor = parse_descriptor(desc_str)

                # Resolve timestamp
                ts = req.get("timestamp", "now")
                if ts == "now":
                    ts = int(time.time())
                elif isinstance(ts, str):
                    ts = int(ts)

                # Range
                rng = req.get("range", [0, 1000])
                if isinstance(rng, int):
                    rng = [0, rng]

                entry = DescriptorEntry(
                    descriptor=descriptor,
                    desc_string=desc_str,
                    timestamp=ts,
                    active=req.get("active", True),
                    range_start=rng[0],
                    range_end=rng[1],
                    next_index=req.get("next_index", 0),
                    internal=req.get("internal", False),
                    label=req.get("label", ""),
                )

                # Replace existing descriptor with same desc string, or append
                replaced = False
                for i, existing in enumerate(self.descriptors):
                    if existing.desc_string == desc_str:
                        self.descriptors[i] = entry
                        replaced = True
                        break
                if not replaced:
                    self.descriptors.append(entry)

                results.append({"success": True})
                logger.info(
                    "Imported descriptor: %s (range %d–%d)",
                    descriptor.descriptor_type,
                    rng[0],
                    rng[1],
                )

            except Exception as exc:
                results.append({
                    "success": False,
                    "error": {
                        "code": -5,
                        "message": str(exc),
                    },
                })
                logger.warning("Failed to import descriptor: %s", exc)

        self._save()
        return results

    def listdescriptors(self) -> List[Dict]:
        """Return all imported descriptors in JSON-serialisable form."""
        return [d.to_dict() for d in self.descriptors]

    def deriveaddresses(
        self, desc_str: str, range_param: Optional[List[int]] = None
    ) -> List[str]:
        """Derive addresses from *desc_str*; *range_param* is ``[start, end]`` (inclusive) or None for non-range descriptors."""
        from ouroboros.descriptors import parse_descriptor, add_checksum

        if "#" not in desc_str:
            desc_str = add_checksum(desc_str)

        descriptor = parse_descriptor(desc_str)

        if descriptor.is_range:
            if range_param is None:
                range_param = [0, 0]
            start = range_param[0]
            end = range_param[1]
            return [
                descriptor.derive_address(i, self.network)
                for i in range(start, end + 1)  # inclusive end
            ]
        else:
            if range_param is not None:
                raise ValueError(
                    "Range should not be specified for un-ranged descriptors"
                )
            return [descriptor.derive_address(0, self.network)]

    def get_descriptor_addresses(self) -> List[str]:
        """Return all addresses derived from active descriptors up to next_index."""
        addrs: List[str] = []
        for entry in self.descriptors:
            if not entry.active:
                continue
            desc = entry.descriptor
            end = max(entry.next_index, entry.range_start + 1)
            for i in range(entry.range_start, end):
                addrs.append(desc.derive_address(i, self.network))
        return addrs

    def generate_descriptor_address(
        self, desc_index: int = 0, label: str | None = None
    ) -> str:
        """Derive the next address from descriptor *desc_index* (default: first active external) and advance its index."""
        # Find the target descriptor
        active_external = [
            d for d in self.descriptors
            if d.active and not d.internal
        ]
        if not active_external:
            raise ValueError("No active external descriptors in wallet")
        if desc_index >= len(active_external):
            raise ValueError(
                f"Descriptor index {desc_index} out of range "
                f"(have {len(active_external)} active external descriptors)"
            )

        entry = active_external[desc_index]
        idx = entry.next_index
        addr = entry.descriptor.derive_address(idx, self.network)
        entry.next_index = idx + 1
        self._save()
        logger.info("Generated descriptor address %s (index %d)", addr, idx)
        return addr

    def backup(self, backup_path: str) -> str:
        """Create a backup of the wallet file."""
        import shutil
        dest = Path(backup_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.wallet_path, dest)
        logger.info(f"Wallet backed up to {dest}")
        return str(dest)

    def restore_from_backup(self, backup_path: str) -> None:
        """Restore wallet from a backup file."""
        import shutil
        src = Path(backup_path)
        if not src.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        shutil.copy2(src, self.wallet_path)
        self._load_or_create()
        logger.info(f"Wallet restored from {src}")

    # --- UTXO helpers ----------------------------------------------------------

    def _collect_utxos(self) -> List[Dict]:
        if self.db is None:
            return []
        utxos: List[Dict] = []
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            addr = k.get_p2wpkh_address()
            for u in self.db.list_unspent_by_address(addr, self.network):
                u["_key"] = k
                utxos.append(u)
        return utxos

    # --- coin selection --------------------------------------------------------

    def _select_coins(
        self,
        amount: int,
        fee_rate: float,
        long_term_fee_rate: float = DEFAULT_LONG_TERM_FEE_RATE,
    ) -> Tuple[List[Dict], int]:
        all_utxos = self._collect_utxos()
        selected, est_fee, _algo = select_coins(
            all_utxos, amount, fee_rate,
            long_term_fee_rate=long_term_fee_rate,
        )
        return selected, est_fee

    # --- BIP 143 sighash -------------------------------------------------------

    @staticmethod
    def _bip143_sighash(
        tx,
        input_index: int,
        pubkey: bytes,
        value: int,
    ) -> bytes:
        """Compute BIP 143 signature hash for a P2WPKH input."""
        pubkey_hash = _hash160(pubkey)
        # scriptCode = OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
        script_code_with_len = bytes([len(script_code)]) + script_code

        # hashPrevouts
        prevouts = b""
        for inp in tx.inputs:
            prevouts += inp.prev_txid + struct.pack("<I", inp.prev_vout)
        hash_prevouts = _dsha256(prevouts)

        # hashSequence
        sequences = b""
        for inp in tx.inputs:
            sequences += struct.pack("<I", inp.sequence)
        hash_sequence = _dsha256(sequences)

        # hashOutputs
        outputs = b""
        for out in tx.outputs:
            outputs += struct.pack("<q", out.value)
            outputs += _encode_varint(len(out.script_pubkey))
            outputs += out.script_pubkey
        hash_outputs = _dsha256(outputs)

        inp = tx.inputs[input_index]
        preimage = struct.pack("<i", tx.version)
        preimage += hash_prevouts
        preimage += hash_sequence
        preimage += inp.prev_txid + struct.pack("<I", inp.prev_vout)
        preimage += script_code_with_len
        preimage += struct.pack("<q", value)
        preimage += struct.pack("<I", inp.sequence)
        preimage += hash_outputs
        preimage += struct.pack("<I", tx.locktime)
        preimage += struct.pack("<I", 1)  # SIGHASH_ALL

        return _dsha256(preimage)

    # --- send ------------------------------------------------------------------

    async def send_transaction(
        self,
        to_address: str,
        amount: int,
        fee_rate: int | None = None,
    ) -> str:
        """Build, sign, and return a raw transaction hex sending *amount* sats to *to_address* at *fee_rate* sat/vB."""
        from ouroboros.address import address_to_script_pubkey
        from ouroboros.database import Transaction, TxIn, TxOut

        if fee_rate is None:
            fee_rate = 2

        selected, est_fee = self._select_coins(amount, fee_rate)
        total_in = sum(u["value"] for u in selected)
        change = total_in - amount - est_fee

        # Build outputs
        dest_spk = address_to_script_pubkey(to_address, self.network)
        outputs = [TxOut(value=amount, script_pubkey=dest_spk)]

        if change > 546:  # dust threshold
            change_key = self._get_wallet_key(self.keys[0])
            change_spk = change_key.get_script_pubkey()
            outputs.append(TxOut(value=change, script_pubkey=change_spk))

        # Build unsigned inputs
        inputs: List[TxIn] = []
        for utxo in selected:
            txid_bytes = bytes.fromhex(utxo["txid"]) if isinstance(utxo["txid"], str) else utxo["txid"]
            inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=utxo["vout"],
                script_sig=b"",
                sequence=0xFFFFFFFD,
            ))

        tx = Transaction(
            txid=b"\x00" * 32,
            version=2,
            locktime=0,
            inputs=inputs,
            outputs=outputs,
            has_witness=True,
        )

        # Sign each input
        for i, utxo in enumerate(selected):
            key: WalletKey = utxo["_key"]
            sighash = self._bip143_sighash(tx, i, key.pubkey, utxo["value"])
            sig = key.sign(sighash) + b"\x01"  # SIGHASH_ALL
            tx.inputs[i].witness = [sig, key.pubkey]

        # Compute real txid from non-witness serialization
        tx.txid = _dsha256(tx.serialize())

        raw_hex = tx.serialize_with_witness().hex()
        logger.info(
            f"Built transaction {tx.txid.hex()[:16]}... "
            f"sending {amount} sat to {to_address}, fee ~{est_fee} sat"
        )
        return raw_hex


def _encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    elif value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    elif value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    else:
        return b"\xff" + value.to_bytes(8, "little")
