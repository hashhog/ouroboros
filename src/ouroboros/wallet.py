"""
Bitcoin wallet: key management, address derivation, coin selection, and transaction signing.

Supports P2WPKH (bech32) and P2PKH (legacy) addresses. Keys are stored
as WIF in a JSON wallet file under {data_dir}/wallets/{name}.json.

BIP 32 hierarchical deterministic (HD) derivation and BIP 44/84
derivation paths are supported when the wallet is initialised from
a seed via ``Wallet.init_hd()``.
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


# ── Wallet encryption (AES-256-GCM + scrypt) ─────────────────────────

def encrypt_wallet_data(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt arbitrary wallet data with a passphrase.

    Layout: salt(16) || nonce(12) || ciphertext+tag(...)

    KDF: scrypt  (N=2^18, r=8, p=1, dkLen=32)
    AEAD: AES-256-GCM
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 18, r=8, p=1)
    key = kdf.derive(passphrase.encode("utf-8"))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_wallet_data(blob: bytes, passphrase: str) -> bytes:
    """
    Decrypt data produced by :func:`encrypt_wallet_data`.

    Raises ``ValueError`` on wrong passphrase or corrupt data.
    """
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


# ── Coin Selection Algorithms ─────────────────────────────────────────
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
# ──────────────────────────────────────────────────────────────────────

INPUT_VBYTES = 68
OUTPUT_VBYTES = 31
OVERHEAD_VBYTES = 11
COST_OF_CHANGE_VBYTES = INPUT_VBYTES + OUTPUT_VBYTES  # 99 vB

# BnB search limit (matches Bitcoin Core)
BNB_MAX_TRIES = 100_000


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
    """Fee for overhead + outputs only (inputs are accounted by effective value)."""
    return int((OVERHEAD_VBYTES + n_outputs * OUTPUT_VBYTES) * fee_rate) + 1


def select_coins(
    utxos: List[Dict],
    target_amount: int,
    fee_rate: float,
) -> Tuple[List[Dict], int, str]:
    """
    Three-tier coin selection matching Bitcoin Core's strategy.

    1. Branch-and-Bound — try for an exact match (no change)
    2. Knapsack — randomised approximation
    3. Single Random Draw — last-resort shuffle-and-grab

    Args:
        utxos: Available UTXOs (each must have ``"value": int``).
        target_amount: Destination amount in satoshis.
        fee_rate: Fee rate in sat/vB.

    Returns:
        (selected_utxos, estimated_fee, algorithm_used)

    Raises:
        ValueError: Insufficient funds across all strategies.
    """
    # BnB: target = amount + (overhead + 1 output fee).
    # BnB internally subtracts per-input cost from each UTXO's effective value.
    bnb_target = target_amount + _non_input_fee(1, fee_rate)
    result = select_coins_bnb(utxos, bnb_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 1, fee_rate)
        return result, fee, "bnb"

    # Knapsack / SRD: target = amount + (overhead + 2 output fees).
    # Input fees are handled inside each algorithm via effective values.
    change_target = target_amount + _non_input_fee(2, fee_rate)

    result = select_coins_knapsack(utxos, change_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 2, fee_rate)
        return result, fee, "knapsack"

    result = select_coins_srd(utxos, change_target, fee_rate)
    if result is not None:
        fee = _estimate_fee(len(result), 2, fee_rate)
        return result, fee, "srd"

    raise ValueError(
        f"Insufficient funds: cannot cover {target_amount} sat + fees "
        f"at {fee_rate} sat/vB"
    )


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

    # ── public key helpers ────────────────────────────────────────────

    @property
    def public_key(self) -> bytes:
        """Compressed SEC public key (33 bytes)."""
        return PublicKey.from_secret(self.private_key).format(compressed=True)

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of HASH160(pubkey) — used as parent id."""
        return _hash160(self.public_key)[:4]

    # ── BIP 32 master key ─────────────────────────────────────────────

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

    # ── child derivation ──────────────────────────────────────────────

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

    # ── path derivation ───────────────────────────────────────────────

    def derive_path(self, path: str) -> "HDKey":
        """
        Derive from a BIP 32 path string, e.g. ``"m/84'/0'/0'/0/0"``.

        ``'`` or ``h`` marks hardened derivation.
        """
        parts = path.strip().split("/")
        if parts[0] != "m":
            raise ValueError(f"Path must start with 'm': {path}")
        node = self
        for part in parts[1:]:
            hardened = part.endswith("'") or part.endswith("h")
            idx = int(part.rstrip("'h"))
            node = node.derive_child(idx, hardened=hardened)
        return node

    # ── conversion to WalletKey ───────────────────────────────────────

    def to_wallet_key(self) -> "WalletKey":
        return WalletKey(self.private_key, self.network)

    # ── xprv / xpub serialisation (BIP 32) ────────────────────────────

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

    def get_script_pubkey(self) -> bytes:
        """P2WPKH scriptPubKey: OP_0 <20-byte-hash>."""
        return b"\x00\x14" + _hash160(self.pubkey)

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

    Wallet file (JSON):
    {
        "version": 1,
        "network": "mainnet",
        "keys": [{"wif": "...", "label": "...", "created": 123}]
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
        self.db = None  # set via set_database()
        self._hd_seed: Optional[bytes] = None
        self._hd_next_index: int = 0
        self._hd_base_path: str = self.HD_BASE_PATH
        self._passphrase: Optional[str] = None
        self._encrypted_blob: Optional[bytes] = None
        self._load_or_create()

    # ── HD seed management ────────────────────────────────────────────

    def init_hd(self, seed: bytes, base_path: Optional[str] = None) -> str:
        """
        Initialise the wallet in HD mode from a BIP 32 seed.

        Returns the xprv of the master key.
        """
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

    # ── persistence ───────────────────────────────────────────────────

    def _load_or_create(self) -> None:
        if self.wallet_path.exists():
            with open(self.wallet_path) as f:
                data = json.load(f)
            if data.get("encrypted"):
                self._encrypted_blob = bytes.fromhex(data["ciphertext"])
                self.keys = []
                logger.info(
                    f"Loaded encrypted wallet '{self.name}' — "
                    "call unlock(passphrase) to decrypt"
                )
                return
            self._encrypted_blob = None
            self.keys = data.get("keys", [])
            hd = data.get("hd")
            if hd:
                self._hd_seed = bytes.fromhex(hd["seed_hex"])
                self._hd_next_index = hd.get("next_index", 0)
                self._hd_base_path = hd.get("base_path", self.HD_BASE_PATH)
            logger.info(
                f"Loaded wallet '{self.name}' with {len(self.keys)} keys"
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

    # ── encryption / decryption ──────────────────────────────────────

    @property
    def is_encrypted(self) -> bool:
        """True when the on-disk wallet is encrypted (may still be unlocked in memory)."""
        return self._encrypted_blob is not None or self._passphrase is not None

    @property
    def is_locked(self) -> bool:
        """True when the wallet is encrypted and has not been unlocked yet."""
        return self._encrypted_blob is not None and self._passphrase is None

    def encrypt(self, passphrase: str) -> None:
        """
        Encrypt the wallet with *passphrase* and persist.

        After this call every subsequent ``_save()`` writes ciphertext.
        """
        if not passphrase:
            raise ValueError("Passphrase must not be empty")
        self._passphrase = passphrase
        self._encrypted_blob = None
        self._save()
        logger.info(f"Wallet '{self.name}' encrypted")

    def unlock(self, passphrase: str) -> None:
        """Decrypt an encrypted wallet that was loaded from disk."""
        if self._encrypted_blob is None:
            raise ValueError("Wallet is not encrypted")
        plaintext = decrypt_wallet_data(self._encrypted_blob, passphrase)
        data = json.loads(plaintext.decode("utf-8"))
        self.keys = data.get("keys", [])
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
        return result

    async def get_transactions(
        self, address: str | None = None
    ) -> list[TransactionInfo]:
        return []

    # --- UTXO helpers ----------------------------------------------------------

    def _collect_utxos(self) -> List[Dict]:
        """Collect all spendable UTXOs across wallet keys."""
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
        self, amount: int, fee_rate: float
    ) -> Tuple[List[Dict], int]:
        """
        Select UTXOs to fund a transaction.

        Uses Bitcoin Core's three-tier strategy:
        1. Branch-and-Bound (exact match, avoids change)
        2. Knapsack (randomised approximation)
        3. Single Random Draw (greedy fallback)

        Returns (selected_utxos, estimated_fee).
        Raises ValueError on insufficient funds.
        """
        all_utxos = self._collect_utxos()
        selected, est_fee, _algo = select_coins(all_utxos, amount, fee_rate)
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
        """
        Build, sign, and return a raw transaction hex.

        Args:
            to_address: Destination address
            amount: Amount in satoshis
            fee_rate: Fee rate in sat/vB (default 2)

        Returns:
            Raw transaction hex ready for broadcast via sendrawtransaction
        """
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
