"""
Bitcoin wallet: key management, address derivation, coin selection, and transaction signing.

Supports P2PKH (legacy), P2SH-P2WPKH (p2sh-segwit), P2WPKH (bech32),
and P2TR keypath (bech32m) addresses. Keys are stored as WIF in a JSON
wallet file under {data_dir}/wallets/{name}.json.

BIP-32 hierarchical-deterministic (HD) derivation is supported when the
wallet is initialised from a seed via ``Wallet.init_hd()``. The BIP-43
purpose code is dispatched from the requested address type per spec:

  - legacy        → BIP-44   m/44'/coin'/0'/change/index
  - p2sh-segwit   → BIP-49   m/49'/coin'/0'/change/index
  - bech32        → BIP-84   m/84'/coin'/0'/change/index
  - bech32m       → BIP-86   m/86'/coin'/0'/change/index

coin_type follows SLIP-44: 0 on mainnet, 1 on every non-mainnet chain
(testnet / testnet4 / signet / regtest).

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
import secrets
import struct
import time
from pathlib import Path
from typing import Any

import base58
import bech32
from coincurve import PrivateKey, PublicKey
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Cryptographically-secure RNG for coin-selection randomisation.
#
# Python's default ``random`` module uses the Mersenne Twister, which is
# fully predictable after roughly 624 observed 32-bit outputs. Using it
# for coin selection is the W88 anti-pattern: a chain-analysis adversary
# who observes the wallet's UTXO usage history can predict which UTXOs
# will be selected next, enabling UTXO-clustering / amount-correlation
# attacks. Bitcoin Core uses ``FastRandomContext`` (seeded from the OS
# CSPRNG) in ``wallet/coinselection.cpp`` and ``wallet/spend.cpp``.
#
# ``secrets.SystemRandom`` is a ``random.Random`` subclass that draws all
# entropy from ``os.urandom`` (the OS CSPRNG), so the standard
# ``shuffle`` / ``random`` API is preserved while the underlying source
# is cryptographically secure.
_CSPRNG = secrets.SystemRandom()

# secp256k1 curve order
SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

# BIP-32 hardened-index threshold (children >= 2^31 are hardened).
_BIP32_HARDENED_BIT = 0x80000000
# Maximum representable BIP-32 child index (32-bit field).
_BIP32_MAX_INDEX = 0x100000000  # exclusive upper bound (2**32)
# Maximum representable BIP-32 depth byte (one octet in the xprv/xpub layout).
_BIP32_MAX_DEPTH = 0xFF


class BIP32MaxDepthError(ValueError):
    """Raised when child derivation would push the depth byte past 0xFF.

    Bitcoin Core (`bitcoin-core/src/key.cpp:483`) refuses to derive when
    ``nDepth == std::numeric_limits<unsigned char>::max()``. Ouroboros
    historically deferred the failure to ``_serialize_extended`` (BUG-5
    in W161 audit) — this class is raised eagerly inside
    :meth:`HDKey.derive_child` and :meth:`ExtendedPubKey.derive_child`
    so callers see the failure before any partial state escapes.
    """


class BIP32IndexExhaustedError(ValueError):
    """Raised when BIP-32 retry-on-invalid-IL exhausts the available range.

    BIP-32 spec §"Child key derivation" mandates: "In case parse256(IL) >= n
    or k_i == 0, the resulting key is invalid, and one should proceed with
    the next value for i." Ouroboros honours this by retrying internally
    (BUG-1 / BUG-3 in W161 audit). The retry must never cross the
    hardened/non-hardened boundary (a normal index incrementing past
    2**31 would silently change soft to hard), and must never wrap past
    2**32. This exception fires in the (cryptographically impossible
    in practice) edge case where the entire remaining sub-range is
    exhausted.
    """


class WalletRpcError(Exception):
    """Wallet-layer failure carrying an explicit JSON-RPC error code.

    ``importdescriptors`` per-element failures must distinguish Core's
    RPC_INVALID_ADDRESS_OR_KEY (-5, e.g. "Missing checksum" —
    wallet/rpc/backup.cpp:158-161) from RPC_WALLET_ERROR (-4, "Cannot import
    private keys to a wallet with private keys disabled" —
    backup.cpp:224-226). The except-handler emits
    ``getattr(exc, "code", -5)`` so plain exceptions keep the historical -5.
    """

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = int(code)


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
        raise ValueError("Decryption failed (wrong passphrase or corrupt data)") from None


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
    utxos: list[dict],
    target: int,
    fee_rate: float,
    *,
    cost_of_change: int | None = None,
) -> list[dict] | None:
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

    best: list[int] | None = None
    best_waste = float("inf")
    current: list[int] = []
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
    utxos: list[dict],
    target: int,
    fee_rate: float,
    *,
    iterations: int = 1000,
) -> list[dict] | None:
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

    best_selection: list[dict] | None = None
    best_overshoot = float("inf")

    # Check if any single UTXO covers the target exactly or near-exactly
    for u, ev in effective:
        if ev >= target:
            overshoot = ev - target
            if overshoot < best_overshoot:
                best_overshoot = overshoot
                best_selection = [u]

    for _ in range(iterations):
        selected: list[dict] = []
        selected_value = 0

        shuffled = list(effective)
        _CSPRNG.shuffle(shuffled)

        for u, ev in shuffled:
            if _CSPRNG.random() < 0.5:
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
    utxos: list[dict],
    target: int,
    fee_rate: float,
) -> list[dict] | None:
    """
    Single Random Draw coin selection (last-resort fallback).

    Shuffles UTXOs and greedily adds them until the target is met.
    Simple but produces a valid selection when BnB and Knapsack fail.

    Returns selected UTXOs or None if insufficient funds.
    """
    input_fee = int(INPUT_VBYTES * fee_rate)
    pool = [u for u in utxos if u["value"] > input_fee]
    _CSPRNG.shuffle(pool)

    selected: list[dict] = []
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
    selected: list[dict],
    fee_rate: float,
    long_term_fee_rate: float,
    has_change: bool,
) -> float:
    total_input_weight = len(selected) * INPUT_VBYTES
    timing_cost = total_input_weight * (fee_rate - long_term_fee_rate)
    change_cost = 0.0 if not has_change else COST_OF_CHANGE_VBYTES * fee_rate
    return timing_cost + change_cost


def select_coins(
    utxos: list[dict],
    target_amount: int,
    fee_rate: float,
    *,
    long_term_fee_rate: float = DEFAULT_LONG_TERM_FEE_RATE,
) -> tuple[list[dict], int, str]:
    """Three-tier coin selection with waste-metric optimisation (BnB → Knapsack → SRD).

    Returns ``(selected_utxos, estimated_fee, algorithm_used)``; raises ValueError if funds
    are insufficient.
    """
    # Collect (result, fee, algo_name, has_change) for every algorithm
    # that returns a valid selection.
    candidates: list[tuple[list[dict], int, str, bool]] = []

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


# ---------------------------------------------------------------------------
# BIP-43 purpose-code dispatch
# ---------------------------------------------------------------------------
#
# Each on-disk address type lives under a *different* BIP-43 purpose so that
# external wallets following BIP-44 / BIP-49 / BIP-84 / BIP-86 can recover
# the same funds from the same mnemonic. Historically W161 BUG-6/7/8 found
# that ouroboros derived *every* address type at ``m/84'/...``, so a user
# calling ``getnewaddress legacy`` would receive a P2PKH whose privkey lives
# at the BIP-84 (not BIP-44) path — unrecoverable by any spec-compliant
# external wallet.
#
# Reference:
#   - BIP-43 purpose-code dispatch:
#       https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
#   - BIP-44 / BIP-49 / BIP-84 / BIP-86 paths.
#   - SLIP-44 coin types (mainnet BTC=0, testnet BTC=1, regtest treated as
#     testnet=1 to match Bitcoin Core's chainparams default).
#       https://github.com/satoshilabs/slips/blob/master/slip-0044.md
PURPOSE_FOR_ADDRESS_TYPE: dict[str, int] = {
    "legacy": 44,        # BIP-44   m/44'/coin'/0'/change/index   → P2PKH
    "p2sh-segwit": 49,   # BIP-49   m/49'/coin'/0'/change/index   → P2SH-P2WPKH
    "bech32": 84,        # BIP-84   m/84'/coin'/0'/change/index   → P2WPKH
    "bech32m": 86,       # BIP-86   m/86'/coin'/0'/change/index   → P2TR keypath
}

# Default address type when the caller is silent. Matches Bitcoin Core's
# ``-addresstype=bech32`` default and the prior ouroboros behaviour.
DEFAULT_ADDRESS_TYPE: str = "bech32"


def purpose_for_address_type(address_type: str) -> int:
    """Map an address-type string to its BIP-43 purpose code.

    Falls back to BIP-84 for unknown types to preserve the historical
    "bech32 by default" behaviour rather than raising mid-derivation.
    """
    return PURPOSE_FOR_ADDRESS_TYPE.get(address_type, 84)


def coin_type_for_network(network: str) -> int:
    """SLIP-44 coin type per network.

    - mainnet → 0 (Bitcoin)
    - testnet / testnet4 / signet / regtest → 1 (Testnet (all coins))

    Bitcoin Core uses coin_type=1 for every non-mainnet chain by SLIP-44
    convention; mismatching this would break recovery on every other wallet.
    """
    return 0 if network == "mainnet" else 1


class KeyPool:
    """
    BIP-32 HD key pool with per-purpose pre-generated keys.

    Maintains independent sub-pools keyed on (purpose, is_change) so that
    BIP-44 (P2PKH), BIP-49 (P2SH-P2WPKH), BIP-84 (P2WPKH), and BIP-86
    (P2TR) addresses each derive at their spec-mandated path:

      - BIP-44: m/44'/coin'/0'/change/index  (legacy / P2PKH)
      - BIP-49: m/49'/coin'/0'/change/index  (p2sh-segwit)
      - BIP-84: m/84'/coin'/0'/change/index  (bech32 / P2WPKH)
      - BIP-86: m/86'/coin'/0'/change/index  (bech32m / P2TR keypath)

    Pre-generates keys (default 1000) and auto-refills when pool drops below
    threshold. The BIP-84 sub-pool is exposed via the legacy attributes
    ``_receive_pool``/``_change_pool``/``_used_*_indices``/``_next_*_index``
    so older callers and tests continue to work; new code should use
    :meth:`get_new_address` with the ``address_type`` argument.

    Reference: Bitcoin Core wallet/scriptpubkeyman.cpp TopUp(),
    GetNewDestination(); BIPs 32/43/44/49/84/86.
    """

    DEFAULT_POOL_SIZE = 1000
    REFILL_THRESHOLD = 100

    def __init__(
        self,
        seed: bytes,
        network: str = "mainnet",
        pool_size: int = DEFAULT_POOL_SIZE,
    ):
        self.seed = seed
        self.network = network
        self.pool_size = pool_size

        # SLIP-44 coin type: 0 for mainnet, 1 for every other chain.
        self.coin_type = coin_type_for_network(network)

        # Per-(purpose, is_change) state. Keys are (purpose:int, is_change:bool).
        # Each entry is a list of (index, WalletKey) tuples. The BIP-84
        # entries are aliased to the legacy ``_receive_pool``/``_change_pool``
        # attributes below for backward compatibility.
        self._pools: dict[tuple[int, bool], list[tuple[int, WalletKey]]] = {}
        self._next_indices: dict[tuple[int, bool], int] = {}
        self._used_indices: dict[tuple[int, bool], set[int]] = {}
        for purpose in PURPOSE_FOR_ADDRESS_TYPE.values():
            for is_change in (False, True):
                self._pools[(purpose, is_change)] = []
                self._next_indices[(purpose, is_change)] = 0
                self._used_indices[(purpose, is_change)] = set()

        # Master key derived once
        self._master: HDKey | None = None

    # ------------------------------------------------------------------
    # Legacy BIP-84-only attribute shims.
    #
    # Older callers (and tests in test_w111_wallet) reach into
    # ``_receive_pool`` / ``_change_pool`` / ``_used_*_indices`` directly.
    # They predate per-purpose sub-pools and assume "the pool" == BIP-84.
    # Map those names to the BIP-84 sub-pool so legacy code keeps working.
    # ------------------------------------------------------------------
    @property
    def _receive_pool(self) -> list[tuple[int, "WalletKey"]]:
        return self._pools[(84, False)]

    @_receive_pool.setter
    def _receive_pool(self, value: list[tuple[int, "WalletKey"]]) -> None:
        self._pools[(84, False)] = value

    @property
    def _change_pool(self) -> list[tuple[int, "WalletKey"]]:
        return self._pools[(84, True)]

    @_change_pool.setter
    def _change_pool(self, value: list[tuple[int, "WalletKey"]]) -> None:
        self._pools[(84, True)] = value

    @property
    def _next_receive_index(self) -> int:
        return self._next_indices[(84, False)]

    @_next_receive_index.setter
    def _next_receive_index(self, value: int) -> None:
        self._next_indices[(84, False)] = value

    @property
    def _next_change_index(self) -> int:
        return self._next_indices[(84, True)]

    @_next_change_index.setter
    def _next_change_index(self, value: int) -> None:
        self._next_indices[(84, True)] = value

    @property
    def _used_receive_indices(self) -> set[int]:
        return self._used_indices[(84, False)]

    @_used_receive_indices.setter
    def _used_receive_indices(self, value: set[int]) -> None:
        self._used_indices[(84, False)] = set(value)

    @property
    def _used_change_indices(self) -> set[int]:
        return self._used_indices[(84, True)]

    @_used_change_indices.setter
    def _used_change_indices(self, value: set[int]) -> None:
        self._used_indices[(84, True)] = set(value)

    @property
    def master(self) -> "HDKey":
        """Lazily derive the master key."""
        if self._master is None:
            self._master = HDKey.from_seed(self.seed, self.network)
        return self._master

    @staticmethod
    def path_for(purpose: int, coin_type: int, is_change: bool, index: int) -> str:
        """Return the BIP-43/44 derivation path string for the given params."""
        change_flag = 1 if is_change else 0
        return f"m/{purpose}'/{coin_type}'/0'/{change_flag}/{index}"

    def _derive_key_at_path(
        self,
        is_change: bool,
        index: int,
        purpose: int = 84,
    ) -> "WalletKey":
        """Derive a key at the BIP-43 path: m/<purpose>'/coin'/0'/change/index.

        The default ``purpose=84`` preserves the historical contract of
        callers that predate per-purpose dispatch (``_rebuild_pools`` from
        old wallet files, the legacy receive-key tests in W111). New code
        should pass an explicit purpose code corresponding to the requested
        address type.
        """
        path = self.path_for(purpose, self.coin_type, is_change, index)
        hd_key = self.master.derive_path(path)
        return hd_key.to_wallet_key()

    def _refill_pool(self, is_change: bool, purpose: int = 84) -> None:
        """Pre-generate keys to fill the (purpose, is_change) pool up to pool_size."""
        key_tuple = (purpose, is_change)
        pool = self._pools[key_tuple]
        next_idx = self._next_indices[key_tuple]
        used_indices = self._used_indices[key_tuple]

        # Calculate how many keys to generate
        current_unused = len([k for k in pool if k[0] not in used_indices])
        needed = self.pool_size - current_unused

        for _ in range(max(0, needed)):
            key = self._derive_key_at_path(is_change, next_idx, purpose=purpose)
            pool.append((next_idx, key))
            next_idx += 1

        self._next_indices[key_tuple] = next_idx

    def get_new_address(
        self,
        is_change: bool = False,
        address_type: str = DEFAULT_ADDRESS_TYPE,
    ) -> tuple[str, int]:
        """
        Get the next unused address from the (address-type-specific) pool.

        Each address_type uses its own BIP-43 sub-pool: ``legacy`` derives at
        ``m/44'/...``, ``p2sh-segwit`` at ``m/49'/...``, ``bech32`` at
        ``m/84'/...``, and ``bech32m`` at ``m/86'/...``. Indices are tracked
        per (purpose, is_change) so different address types never overlap.

        Returns (address, index). Refills pool if below threshold.
        """
        purpose = purpose_for_address_type(address_type)
        key_tuple = (purpose, is_change)
        pool = self._pools[key_tuple]
        used_indices = self._used_indices[key_tuple]

        # Refill if needed
        unused_count = len([k for k in pool if k[0] not in used_indices])
        if unused_count < self.REFILL_THRESHOLD:
            self._refill_pool(is_change, purpose=purpose)
            pool = self._pools[key_tuple]

        # Find next unused key
        for idx, key in pool:
            if idx not in used_indices:
                used_indices.add(idx)
                if address_type == "p2sh-segwit":
                    addr = key.get_p2sh_p2wpkh_address()
                elif address_type == "bech32m":
                    addr = key.get_p2tr_address()
                elif address_type == "legacy":
                    addr = key.get_p2pkh_address()
                else:
                    addr = key.get_p2wpkh_address()
                return (addr, idx)

        # Pool exhausted; generate one more
        self._refill_pool(is_change, purpose=purpose)
        return self.get_new_address(is_change, address_type)

    def get_key_at_index(
        self,
        index: int,
        is_change: bool = False,
        purpose: int = 84,
    ) -> "WalletKey":
        """Get or derive the key at a specific (purpose, is_change, index)."""
        pool = self._pools[(purpose, is_change)]

        # Check if already in pool
        for idx, key in pool:
            if idx == index:
                return key

        # Derive on demand
        return self._derive_key_at_path(is_change, index, purpose=purpose)

    def get_all_keys(self, include_change: bool = True) -> list["WalletKey"]:
        """Return all keys across every (purpose, is_change) sub-pool.

        Used for address scanning — a single wallet that has called both
        ``getnewaddress legacy`` and ``getnewaddress bech32`` will have
        produced keys under both BIP-44 and BIP-84, and the UTXO scanner
        must consider all of them.
        """
        keys: list["WalletKey"] = []
        for (_purpose, change_flag), pool in self._pools.items():
            if not include_change and change_flag:
                continue
            keys.extend(k for _, k in pool)
        return keys

    def top_up(self) -> int:
        """Ensure every (purpose, is_change) sub-pool is filled.

        Returns the total number of keys generated across all sub-pools.
        """
        before_total = sum(len(pool) for pool in self._pools.values())
        for (purpose, is_change) in self._pools:
            self._refill_pool(is_change, purpose=purpose)
        after_total = sum(len(pool) for pool in self._pools.values())
        return after_total - before_total

    def to_dict(self) -> dict:
        """Serialize key pool state for persistence.

        Persists the per-(purpose, is_change) index/used-set mapping in
        addition to the legacy BIP-84 ``next_receive_index`` /
        ``next_change_index`` / ``used_*_indices`` keys so wallets written
        before the BIP-43 dispatch fix still load correctly.
        """
        purpose_state: dict[str, dict[str, list[int] | int]] = {}
        for (purpose, is_change), next_idx in self._next_indices.items():
            slot = "change" if is_change else "receive"
            purpose_state.setdefault(str(purpose), {})[f"next_{slot}_index"] = next_idx
            purpose_state[str(purpose)][f"used_{slot}_indices"] = list(
                self._used_indices[(purpose, is_change)]
            )

        return {
            "seed_hex": self.seed.hex(),
            "network": self.network,
            "pool_size": self.pool_size,
            "coin_type": self.coin_type,
            # Legacy BIP-84-only keys (kept for backwards-compatible load).
            "next_receive_index": self._next_indices[(84, False)],
            "next_change_index": self._next_indices[(84, True)],
            "used_receive_indices": list(self._used_indices[(84, False)]),
            "used_change_indices": list(self._used_indices[(84, True)]),
            # Per-purpose state (BIP-43 dispatch fix).
            "purpose_state": purpose_state,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyPool":
        """Deserialize key pool from persisted state."""
        pool = cls(
            seed=bytes.fromhex(data["seed_hex"]),
            network=data.get("network", "mainnet"),
            pool_size=data.get("pool_size", cls.DEFAULT_POOL_SIZE),
        )
        pool.coin_type = data.get("coin_type", pool.coin_type)

        # Load legacy BIP-84-only fields first so pre-fix wallets restore.
        pool._next_indices[(84, False)] = data.get("next_receive_index", 0)
        pool._next_indices[(84, True)] = data.get("next_change_index", 0)
        pool._used_indices[(84, False)] = set(data.get("used_receive_indices", []))
        pool._used_indices[(84, True)] = set(data.get("used_change_indices", []))

        # Overlay per-purpose state if present (post-fix wallets).
        for purpose_str, state in data.get("purpose_state", {}).items():
            purpose = int(purpose_str)
            for is_change, slot in ((False, "receive"), (True, "change")):
                if f"next_{slot}_index" in state:
                    pool._next_indices[(purpose, is_change)] = state[f"next_{slot}_index"]
                if f"used_{slot}_indices" in state:
                    pool._used_indices[(purpose, is_change)] = set(state[f"used_{slot}_indices"])

        # Rebuild pools up to the next indices
        pool._rebuild_pools()
        return pool

    def _rebuild_pools(self) -> None:
        """Rebuild every (purpose, is_change) sub-pool from indices (post-deserialize)."""
        for (purpose, is_change), next_idx in self._next_indices.items():
            rebuilt: list[tuple[int, WalletKey]] = []
            for i in range(next_idx):
                key = self._derive_key_at_path(is_change, i, purpose=purpose)
                rebuilt.append((i, key))
            self._pools[(purpose, is_change)] = rebuilt


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
        hmac_result = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key = hmac_result[:32]
        if int.from_bytes(key, "big") == 0 or int.from_bytes(key, "big") >= SECP256K1_ORDER:
            raise ValueError("Invalid master key (out of range)")
        return cls(private_key=key, chain_code=hmac_result[32:], network=network)

    # child derivation

    def derive_child(self, index: int, hardened: bool = False) -> "HDKey":
        """Derive a child extended key at *index*.

        Implements the BIP-32 spec retry rule: if ``parse256(IL) >= n``
        or the resulting child key is zero, the function transparently
        retries at ``index + 1`` (BUG-1 in W161 audit). The hardened bit
        is never crossed by this retry — a non-hardened index that would
        increment past ``2**31`` raises :class:`BIP32IndexExhaustedError`
        rather than silently switching to hardened derivation.

        Refuses to derive when the resulting depth byte would overflow
        the BIP-32 single-octet field (BUG-5 in W161 audit), surfacing
        :class:`BIP32MaxDepthError` before any partial state is built.
        Mirrors `bitcoin-core/src/key.cpp::CExtKey::Derive` lines 482-489.
        """
        # BUG-5 guard: refuse depth overflow up front, matching Core
        # ``if (nDepth == std::numeric_limits<unsigned char>::max()) return false;``
        if self.depth >= _BIP32_MAX_DEPTH:
            raise BIP32MaxDepthError(
                f"BIP-32 depth byte would overflow (current depth={self.depth})"
            )
        if hardened:
            index |= _BIP32_HARDENED_BIT
        if index < 0 or index >= _BIP32_MAX_INDEX:
            raise ValueError(f"BIP-32 child index out of range: {index}")

        # Cache the initial hardened-ness so the retry loop cannot cross
        # the soft/hard boundary while incrementing on IL>=n / k_i==0.
        is_hardened = bool(index & _BIP32_HARDENED_BIT)
        # Upper bound (exclusive) for the retry range, anchored to the
        # same half (hardened or non-hardened) as the initial index.
        retry_ceiling = _BIP32_MAX_INDEX if is_hardened else _BIP32_HARDENED_BIT

        current_index = index
        # BUG-1 spec mandate: retry-with-next-index on invalid IL / zero
        # child. Bounded by the same hardened/non-hardened half.
        while current_index < retry_ceiling:
            if is_hardened:
                data = b"\x00" + self.private_key + current_index.to_bytes(4, "big")
            else:
                data = self.public_key + current_index.to_bytes(4, "big")

            hmac_result = hmac.new(self.chain_code, data, hashlib.sha512).digest()
            il = int.from_bytes(hmac_result[:32], "big")
            if il >= SECP256K1_ORDER:
                current_index += 1
                continue
            child_int = (
                il + int.from_bytes(self.private_key, "big")
            ) % SECP256K1_ORDER
            if child_int == 0:
                current_index += 1
                continue
            child_key = child_int.to_bytes(32, "big")
            return HDKey(
                private_key=child_key,
                chain_code=hmac_result[32:],
                depth=self.depth + 1,
                parent_fingerprint=self.fingerprint,
                child_index=current_index,
                network=self.network,
            )

        raise BIP32IndexExhaustedError(
            "BIP-32 retry exhausted the "
            f"{'hardened' if is_hardened else 'non-hardened'} child range "
            f"starting at index {index}"
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
        # Defence-in-depth (BUG-5): refuse to emit an xprv/xpub whose
        # depth byte would not fit. ``HDKey.derive_child`` enforces this
        # eagerly, but ``HDKey.from_xprv`` and direct construction can
        # in principle install a depth > 0xFF, so we re-check here to
        # avoid the historical ``ValueError: bytes must be in range``
        # crash leaking out of base58 encoding.
        if not 0 <= self.depth <= _BIP32_MAX_DEPTH:
            raise BIP32MaxDepthError(
                f"BIP-32 depth byte out of range: {self.depth} "
                f"(expected 0..{_BIP32_MAX_DEPTH})"
            )
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
        from ouroboros.address import _network_hrp
        h160 = _hash160(self.pubkey)
        hrp = _network_hrp(self.network)
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
        """Taproot bech32m P2TR address (BIP-86 key-path only, no scripts).

        Per BIP-341 the on-chain output key is::

            Q = lift_x(P) + tagged_hash("TapTweak", x_only(P)) * G

        i.e. the internal pubkey is forced to even-Y before adding the
        tweak. ``coincurve.PublicKey(self.pubkey).add(tweak)`` would use
        the *actual* parity of ``self.pubkey``, producing a different Q
        when the internal Y is odd; force even-Y by re-prefixing.

        Any failure here MUST be raised — never fall back to the
        untweaked key, which would produce a valid-looking but
        unspendable address.
        """
        from ouroboros.address import _bech32m_encode

        if not isinstance(self.pubkey, (bytes, bytearray)) or len(
            self.pubkey
        ) != 33 or self.pubkey[0] not in (0x02, 0x03):
            raise ValueError(
                "BIP-86 address derive: invalid 33-byte compressed pubkey"
            )

        x_only = self.pubkey[1:]
        # BIP-341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
        tweak = hashlib.sha256(
            hashlib.sha256(b"TapTweak").digest()
            + hashlib.sha256(b"TapTweak").digest()
            + x_only
        ).digest()

        # Force even-Y on the internal point before the tweak (BIP-341).
        even_y_compressed = b"\x02" + x_only
        try:
            from coincurve import PublicKey as CPublicKey
            pk = CPublicKey(even_y_compressed)
            tweaked = pk.add(tweak)
            tweaked_x = tweaked.format(compressed=True)[1:]
        except Exception as e:
            # Do NOT silently fall back to the untweaked x-only key:
            # that would yield a valid-looking address whose funds are
            # unspendable by this wallet.
            raise ValueError(
                f"Failed to derive BIP-86 tweaked Taproot address: {e}"
            ) from e

        if len(tweaked_x) != 32:
            raise ValueError(
                f"Tweaked Taproot output key has wrong length: "
                f"{len(tweaked_x)}"
            )

        from ouroboros.address import _network_hrp
        hrp = _network_hrp(self.network)
        return _bech32m_encode(hrp, 1, tweaked_x)

    def get_script_pubkey(self) -> bytes:
        """P2WPKH scriptPubKey: OP_0 <20-byte-hash>."""
        return b"\x00\x14" + _hash160(self.pubkey)

    def get_p2tr_script_pubkey(self) -> bytes:
        """P2TR scriptPubKey: ``OP_1 <32-byte-tweaked-output-x>``.

        The 32-byte program is the BIP-341 *output* key (internal
        pubkey + TapTweak), NOT the internal x-only key. Returning the
        internal x-only would emit a scriptPubKey that does not match
        the address ``get_p2tr_address`` produces, leaving funds
        invisible to the wallet's UTXO scanner.
        """
        from ouroboros.taproot import derive_taproot_output_xonly

        tweaked_x = derive_taproot_output_xonly(self.pubkey, None)
        return b"\x51\x20" + tweaked_x

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
        wallet_dir: str | None = None,
    ):
        """
        Initialize a wallet.

        Args:
            data_dir: Base data directory for the node
            network: Bitcoin network
            name: Wallet name
            wallet_dir: Optional explicit wallet directory path. If not provided,
                        uses legacy single-file format at ``<datadir>/wallets/<name>.json``.
                        For multi-wallet support, set to ``<datadir>/wallets/<name>/``
                        and wallet will be stored at ``wallet.dat`` inside that directory.
        """
        self.data_dir = Path(data_dir).expanduser()
        self.network = network
        self.name = name

        # Wallet path: new directory format or legacy single-file
        if wallet_dir is not None:
            self.wallet_dir = Path(wallet_dir)
            self.wallet_path = self.wallet_dir / "wallet.dat"
        else:
            # Legacy format for backwards compatibility
            self.wallet_dir = None
            self.wallet_path = self.data_dir / "wallets" / f"{name}.json"

        self.keys: list[dict] = []
        self.descriptors: list = []  # List[DescriptorEntry]
        self.db = None  # set via set_database()
        self.mempool = None  # set via set_mempool()
        self._hd_seed: bytes | None = None
        # Optional BIP-39 metadata. When the wallet was initialised from a
        # mnemonic (via init_hd or restore_from_mnemonic), we persist the
        # mnemonic and the BIP-39 passphrase used to derive the seed so
        # that dumpmnemonic can later return them. The BIP-39 passphrase
        # is wallet-encryption-orthogonal (BIP-39 §"From mnemonic to seed"),
        # so it is stored under the same encrypted blob as the seed.
        self._hd_mnemonic: list[str] | None = None
        self._hd_bip39_passphrase: str | None = None
        self._hd_next_index: int = 0
        self._hd_base_path: str = self.HD_BASE_PATH
        self._passphrase: str | None = None
        self._encrypted_blob: bytes | None = None
        self._key_pool: KeyPool | None = None  # BIP84 key pool
        self._disable_private_keys: bool = False  # watch-only mode
        # Locked outpoints — see Bitcoin Core wallet/wallet.cpp LockCoin/IsLockedCoin.
        # Stored as {(txid_hex, vout): persistent_bool}. Persistent locks survive
        # restart (written to disk); non-persistent locks are memory-only and
        # cleared on _load_or_create().
        self._locked_coins: dict[tuple[str, int], bool] = {}
        # --- Wallet transaction history (Core CWallet::mapWallet) -------------
        # Populated by the block-connect scan (scan_block_connect) as each
        # connected block is walked: every tx that credits a wallet script
        # (receive / coinbase) or debits a wallet-owned outpoint (send) gets a
        # record here, keyed by display-order (big-endian hex) txid. Surfaced
        # via listtransactions / gettransaction. In-memory only (Core rebuilds
        # mapWallet from a rescan on load); reorg-safe via scan_block_disconnect.
        # Each value is a dict (see scan_block_connect for the shape).
        self._tx_history: dict[str, dict] = {}
        # Outpoints this wallet owns (created by a credit) -> the spent value
        # and script, so a later block that spends one can be attributed as a
        # debit (send) without needing the already-deleted UTXO. Keyed by
        # (txid_display_hex, vout). Mirrors which coins are "from me".
        self._owned_outpoints: dict[tuple[str, int], dict] = {}
        # Highest chain height this wallet has scanned (persisted in
        # wallet.dat as "best_scanned_height").  The wallet's Core-parity
        # "locator": reconcile_on_load rescans only the gap ABOVE this
        # height instead of genesis..tip (CWallet::AttachChain rescans from
        # the stored locator, never the whole chain).  None = legacy wallet
        # file with no marker.
        self._best_scanned_height: int | None = None
        # Cache for _descriptor_script_map(): script_pubkey -> address over
        # every imported descriptor entry. Invalidated whenever the
        # descriptor set changes (importdescriptors / wallet load). Mirrors
        # Core DescriptorScriptPubKeyMan::m_map_script_pub_keys.
        self._descriptor_spk_cache: dict[bytes, str] | None = None
        self._load_or_create()

    # HD seed management #

    def init_hd(
        self,
        seed: bytes | None = None,
        base_path: str | None = None,
        pool_size: int = KeyPool.DEFAULT_POOL_SIZE,
        *,
        mnemonic: list[str] | str | None = None,
        bip39_passphrase: str = "",
    ) -> str:
        """
        Initialise the wallet in HD mode.

        Either provide a raw BIP-32 *seed* (16-64 bytes) or a BIP-39
        *mnemonic* (12/15/18/21/24 words). When a mnemonic is supplied
        the seed is derived via PBKDF2-HMAC-SHA512(*mnemonic*,
        ``"mnemonic" + bip39_passphrase``, 2048 iters, 64-byte dklen) per
        BIP-39, and the mnemonic + passphrase are persisted alongside the
        seed so that ``dumpmnemonic`` can later return them.

        Creates a BIP84 key pool with pre-generated keys (default 1000).
        Returns the xprv of the master key.

        Reference:
          Bitcoin Core wallet/scriptpubkeyman.cpp SetupDescriptorGeneration()
          BIP-39 https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
        """
        from ouroboros.bip39 import (
            mnemonic_to_seed as _bip39_mnemonic_to_seed,
            validate_mnemonic as _bip39_validate_mnemonic,
        )

        if (seed is None) == (mnemonic is None):
            raise ValueError("init_hd requires exactly one of seed= or mnemonic=")

        if mnemonic is not None:
            # Normalise + validate the mnemonic before deriving the seed.
            if isinstance(mnemonic, str):
                words = mnemonic.split()
            else:
                words = list(mnemonic)
            _bip39_validate_mnemonic(words)
            seed = _bip39_mnemonic_to_seed(words, bip39_passphrase)
            self._hd_mnemonic = words
            self._hd_bip39_passphrase = bip39_passphrase
        else:
            # Raw-seed path. Clear any previous BIP-39 metadata to avoid a
            # stale (mnemonic, seed) pair drifting out of sync.
            self._hd_mnemonic = None
            self._hd_bip39_passphrase = None

        assert seed is not None
        master = HDKey.from_seed(seed, self.network)
        self._hd_seed = seed
        self._hd_next_index = 0
        if base_path is not None:
            self._hd_base_path = base_path

        # Initialize key pool with BIP84 paths
        self._key_pool = KeyPool(seed, self.network, pool_size)
        self._key_pool.top_up()

        self._save()
        logger.info(
            f"Wallet '{self.name}' initialised in HD mode with "
            f"{pool_size} key pool size"
            + (" (BIP-39 mnemonic)" if self._hd_mnemonic else "")
        )
        return master.serialize_xprv()

    def restore_from_mnemonic(
        self,
        mnemonic: list[str] | str,
        bip39_passphrase: str = "",
        base_path: str | None = None,
        pool_size: int = KeyPool.DEFAULT_POOL_SIZE,
    ) -> str:
        """
        Restore wallet HD state from a BIP-39 *mnemonic* + optional
        *bip39_passphrase*. Convenience wrapper around
        :meth:`init_hd(mnemonic=...)`. Returns the xprv of the master key.

        WARNING: this overwrites any existing HD seed / key pool. Callers
        should refuse to restore over a non-empty wallet at a higher
        layer (the RPC handler does this).
        """
        return self.init_hd(
            mnemonic=mnemonic,
            bip39_passphrase=bip39_passphrase,
            base_path=base_path,
            pool_size=pool_size,
        )

    def get_mnemonic(self) -> tuple[list[str] | None, str | None]:
        """
        Return ``(mnemonic_words, bip39_passphrase)`` if the wallet was
        initialised from a mnemonic, else ``(None, None)``.

        Wallets initialised from a raw seed (legacy path) cannot return a
        mnemonic — there is no inverse for ``HDKey.from_seed``.
        """
        return (
            list(self._hd_mnemonic) if self._hd_mnemonic else None,
            self._hd_bip39_passphrase,
        )

    @property
    def is_hd(self) -> bool:
        return self._hd_seed is not None

    def get_hd_master(self) -> HDKey | None:
        if self._hd_seed is None:
            return None
        return HDKey.from_seed(self._hd_seed, self.network)

    # persistence

    def _load_or_create(self) -> None:
        if not self.wallet_path.exists():
            self._encrypted_blob = None
            # Create parent directory (either wallet_dir or wallets/)
            self.wallet_path.parent.mkdir(parents=True, exist_ok=True)
            self._save()
            logger.info(f"Created new wallet '{self.name}'")
            return

        # --- Fault-tolerant parse -------------------------------------------
        # A wallet.dat can be partial / torn / zero-length after an unclean
        # shutdown (especially before fsync-on-save landed). Core never crashes
        # the node on a damaged wallet — it reports a load error. Here we MUST
        # also never crash node startup: an unreadable file is quarantined to a
        # ``.corrupt-<ts>`` sidecar and a fresh wallet is created in its place,
        # so the node always comes up. The user can recover funds from the
        # sidecar (or via mnemonic) without losing the original bytes.
        try:
            raw = self.wallet_path.read_text()
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("wallet file is not a JSON object")
        except (OSError, ValueError, json.JSONDecodeError) as e:
            self._quarantine_corrupt_wallet(e)
            self._encrypted_blob = None
            self._save()
            return

        try:
            self._populate_from_data(data)
        except Exception as e:
            # The JSON parsed but a field was structurally invalid (e.g. a
            # truncated hex seed, a malformed key pool). Treat it the same as a
            # corrupt file rather than letting the exception escape and crash
            # the node.
            self._reset_in_memory_state()
            self._quarantine_corrupt_wallet(e)
            self._encrypted_blob = None
            self._save()

    def _reset_in_memory_state(self) -> None:
        """Reset all loadable in-memory wallet state to empty defaults.

        Called before re-creating a quarantined wallet so a partially-applied
        load does not leave half-populated fields behind.
        """
        self.keys = []
        self.descriptors = []
        self._descriptor_spk_cache = None
        self._hd_seed = None
        self._hd_mnemonic = None
        self._hd_bip39_passphrase = None
        self._hd_next_index = 0
        self._hd_base_path = self.HD_BASE_PATH
        self._key_pool = None
        self._disable_private_keys = False
        self._locked_coins = {}
        self._encrypted_blob = None
        self._passphrase = None

    def _quarantine_corrupt_wallet(self, error: Exception) -> None:
        """Move a damaged wallet.dat aside so node startup can proceed.

        Never raises — quarantine is best-effort. The original bytes are
        preserved under ``<wallet.dat>.corrupt-<unixtime>`` for manual
        recovery; if even the move fails we log and continue (a fresh
        ``_save`` will overwrite the bad file).
        """
        logger.error(
            f"Wallet '{self.name}' at {self.wallet_path} is unreadable "
            f"({error!r}); quarantining and creating a fresh wallet. "
            "Original bytes preserved for recovery."
        )
        try:
            if self.wallet_path.exists():
                sidecar = self.wallet_path.with_name(
                    f"{self.wallet_path.name}.corrupt-{int(time.time())}"
                )
                os.replace(self.wallet_path, sidecar)
                logger.error(f"Corrupt wallet preserved at {sidecar}")
        except OSError as move_err:
            logger.error(
                f"Could not move corrupt wallet aside: {move_err!r}; "
                "it will be overwritten by a fresh save"
            )

    def _populate_from_data(self, data: dict) -> None:
        """Populate in-memory wallet state from a parsed wallet-file dict.

        Shared by :meth:`_load_or_create` and :meth:`unlock` (which passes the
        decrypted inner dict). Raises on structurally-invalid fields so the
        caller can decide whether to quarantine.
        """
        from ouroboros.descriptors import DescriptorEntry

        self._descriptor_spk_cache = None
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
        bsh = data.get("best_scanned_height")
        self._best_scanned_height = int(bsh) if bsh is not None else None
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
            mnemonic = hd.get("mnemonic")
            if mnemonic:
                self._hd_mnemonic = list(mnemonic)
                self._hd_bip39_passphrase = hd.get("bip39_passphrase", "")
        # Load key pool if present
        key_pool_data = data.get("key_pool")
        if key_pool_data:
            self._key_pool = KeyPool.from_dict(key_pool_data)
        elif self._hd_seed is not None:
            # Create key pool from existing HD seed for backwards compatibility
            self._key_pool = KeyPool(self._hd_seed, self.network)
            self._key_pool.top_up()
        # Load wallet flags
        self._disable_private_keys = data.get("disable_private_keys", False)
        # Load persistent lockunspent entries (memory-only locks are dropped
        # by virtue of process exit; see Core wallet.cpp LockCoin docs).
        for entry in data.get("locked_coins", []):
            try:
                txid = str(entry["txid"])
                vout = int(entry["vout"])
                self._locked_coins[(txid, vout)] = True
            except (KeyError, ValueError, TypeError):
                continue
        logger.info(
            f"Loaded wallet '{self.name}' with {len(self.keys)} keys, "
            f"{len(self.descriptors)} descriptors"
            + (" (HD)" if self._hd_seed else "")
            + (" (watch-only)" if self._disable_private_keys else "")
        )

    def _save(self) -> None:
        inner: dict = {
            "keys": self.keys,
        }
        if self._best_scanned_height is not None:
            inner["best_scanned_height"] = int(self._best_scanned_height)
        if self.descriptors:
            inner["descriptors"] = [d.to_dict() for d in self.descriptors]
        if self._hd_seed is not None:
            hd_inner: dict = {
                "seed_hex": self._hd_seed.hex(),
                "next_index": self._hd_next_index,
                "base_path": self._hd_base_path,
            }
            # BIP-39 metadata only present if the wallet was created from
            # a mnemonic. We persist the mnemonic words and the BIP-39
            # passphrase so dumpmnemonic can reproduce the exact source
            # the user wrote down.
            if self._hd_mnemonic is not None:
                hd_inner["mnemonic"] = list(self._hd_mnemonic)
                hd_inner["bip39_passphrase"] = self._hd_bip39_passphrase or ""
            inner["hd"] = hd_inner
        if self._key_pool is not None:
            inner["key_pool"] = self._key_pool.to_dict()
        if self._disable_private_keys:
            inner["disable_private_keys"] = True
        # Persist only the persistent locks (matches Core's wallet-db semantics).
        persistent_locks = [
            {"txid": txid, "vout": vout}
            for (txid, vout), persistent in self._locked_coins.items()
            if persistent
        ]
        if persistent_locks:
            inner["locked_coins"] = persistent_locks

        if self._passphrase is not None:
            plaintext = json.dumps(inner).encode("utf-8")
            blob = encrypt_wallet_data(plaintext, self._passphrase)
            outer: dict = {
                "version": 1,
                "network": self.network,
                "encrypted": True,
                "ciphertext": blob.hex(),
            }
        else:
            outer = {"version": 1, "network": self.network, **inner}

        # Durable atomic write (mirror snapshot.py:1574-1584 and Bitcoin
        # Core wallet DB flush semantics): write the full serialization to a
        # sibling temp file, flush the user-space buffer, fsync the fd so the
        # bytes are on stable storage, then atomically rename over the live
        # wallet. Without the fsync a power loss between rename and dirty-page
        # writeback can leave a zero-length / torn ``wallet.dat`` visible —
        # exactly the corruption the fault-tolerant loader must also survive.
        # ``os.replace`` is used (not Path.rename) for explicit atomic-replace
        # semantics across platforms.
        self.wallet_path.parent.mkdir(parents=True, exist_ok=True)
        # Per-instance temp name keeps concurrent saves of *different* wallets
        # (each its own path) independent; same-wallet saves are not
        # re-entrant. Suffix ".tmp" matches the historical name.
        tmp = self.wallet_path.with_name(self.wallet_path.name + ".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(outer, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.wallet_path)
        except BaseException:
            # Best-effort cleanup so a failed/interrupted save does not leave a
            # stale temp behind; the live wallet.dat is untouched (the rename
            # is the only mutation and it is atomic).
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            raise

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
            mnemonic = hd.get("mnemonic")
            if mnemonic:
                self._hd_mnemonic = list(mnemonic)
                self._hd_bip39_passphrase = hd.get("bip39_passphrase", "")
        # Load key pool
        key_pool_data = data.get("key_pool")
        if key_pool_data:
            self._key_pool = KeyPool.from_dict(key_pool_data)
        elif self._hd_seed is not None:
            self._key_pool = KeyPool(self._hd_seed, self.network)
            self._key_pool.top_up()
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
        self._descriptor_spk_cache = None
        self._hd_seed = None
        self._hd_mnemonic = None
        self._hd_bip39_passphrase = None
        self._hd_next_index = 0
        self._key_pool = None
        self._passphrase = None
        logger.info(f"Wallet '{self.name}' locked")

    def _read_encrypted_blob(self) -> bytes | None:
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

    def _get_wallet_key(self, key_data: dict) -> WalletKey:
        return WalletKey.from_wif(key_data["wif"], self.network)

    async def generate_new_address(
        self,
        label: str | None = None,
        address_type: str = DEFAULT_ADDRESS_TYPE,
    ) -> str:
        """
        Generate a new receiving address from the key pool.

        Args:
            label: Optional label for the address
            address_type: One of "bech32" (P2WPKH, BIP-84), "p2sh-segwit"
                          (P2SH-P2WPKH, BIP-49), "bech32m" (P2TR, BIP-86),
                          or "legacy" (P2PKH, BIP-44). Address-type → BIP-43
                          purpose dispatch is per spec; see
                          :data:`PURPOSE_FOR_ADDRESS_TYPE`.

        Returns:
            The new address string

        Reference: Bitcoin Core wallet/scriptpubkeyman.cpp GetNewDestination()
        """
        # Use key pool if available (HD wallet)
        if self._key_pool is not None:
            purpose = purpose_for_address_type(address_type)
            addr, index = self._key_pool.get_new_address(
                is_change=False,
                address_type=address_type,
            )
            # Also store in keys list for compatibility
            key = self._key_pool.get_key_at_index(
                index, is_change=False, purpose=purpose,
            )
            self.keys.append({
                "wif": key.to_wif(),
                "label": label or "",
                "created": int(time.time()),
                "hd_path": KeyPool.path_for(
                    purpose, self._key_pool.coin_type, False, index,
                ),
            })
            self._save()
            logger.info(f"Generated new address {addr} (pool index {index})")
            return addr

        # Legacy HD mode (backwards compatibility)
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

        # Return address of requested type
        if address_type == "p2sh-segwit":
            addr = key.get_p2sh_p2wpkh_address()
        elif address_type == "bech32m":
            addr = key.get_p2tr_address()
        elif address_type == "legacy":
            addr = key.get_p2pkh_address()
        else:
            addr = key.get_p2wpkh_address()

        logger.info(f"Generated new address {addr}")
        return addr

    async def get_change_address(self, address_type: str = DEFAULT_ADDRESS_TYPE) -> str:
        """
        Generate a new change (internal) address from the key pool.

        Change addresses use the per-purpose internal path
        ``m/<purpose>'/coin'/0'/1/index``, where the purpose is dispatched
        from ``address_type`` per BIP-43/44/49/84/86. Hardcoding to BIP-84
        for non-bech32 change outputs was W161 BUG-6.

        Reference: Bitcoin Core wallet/scriptpubkeyman.cpp GetReservedDestination()
        """
        if self._key_pool is not None:
            addr, index = self._key_pool.get_new_address(
                is_change=True,
                address_type=address_type,
            )
            logger.info(f"Generated change address {addr} (pool index {index})")
            return addr

        # Fallback: use regular address generation
        return await self.generate_new_address(address_type=address_type)

    def get_keypool_size(self) -> int:
        """Return the number of unused keys in the pool."""
        if self._key_pool is None:
            return 0
        receive_unused = len([
            k for k in self._key_pool._receive_pool
            if k[0] not in self._key_pool._used_receive_indices
        ])
        change_unused = len([
            k for k in self._key_pool._change_pool
            if k[0] not in self._key_pool._used_change_indices
        ])
        return receive_unused + change_unused

    def keypoolrefill(self, new_size: int = KeyPool.DEFAULT_POOL_SIZE) -> int:
        """
        Refill the key pool to the specified size.

        Returns the number of new keys generated.

        Reference: Bitcoin Core RPC keypoolrefill
        """
        if self._key_pool is None:
            if self._hd_seed is None:
                raise ValueError("Wallet is not HD; cannot refill key pool")
            # Create key pool from seed
            self._key_pool = KeyPool(self._hd_seed, self.network, new_size)

        self._key_pool.pool_size = new_size
        generated = self._key_pool.top_up()
        self._save()
        logger.info(f"Key pool refilled with {generated} new keys")
        return generated

    # Coinbase maturity (Core consensus.h COINBASE_MATURITY). A coinbase UTXO
    # mined at ``coin_height`` is spendable only once it has 100 confirmations.
    # Core's wallet treats a coin as mature when
    #   GetDepthInMainChain() = tip - coin_height + 1 >= COINBASE_MATURITY + 1,
    # i.e. coin_height <= tip - COINBASE_MATURITY. At tip 101 only the height-1
    # coinbase qualifies (50 BTC), matching the reference spend cell.
    COINBASE_MATURITY = 100

    def _tip_height(self) -> int:
        if self.db is None:
            return 0
        try:
            _, h = self.db.get_best_block()
            return int(h)
        except Exception:
            return 0

    def _is_spendable_utxo(self, u: dict, tip_height: int) -> bool:
        """Return True unless *u* is an immature coinbase output.

        Mirrors Bitcoin Core's CWalletTx::IsImmatureCoinBase /
        GetBlocksToMaturity. Non-coinbase coins are always spendable once
        in the chainstate; coinbase coins need COINBASE_MATURITY confirmations.
        """
        if not u.get("is_coinbase", False):
            return True
        coin_height = u.get("height", 0) or 0
        # confirmations = tip - coin_height + 1; mature when >= MATURITY + 1.
        return (tip_height - coin_height + 1) >= (self.COINBASE_MATURITY + 1)

    async def get_balance(self, address: str | None = None) -> int:
        if self.db is None:
            return 0
        tip = self._tip_height()
        if address:
            return sum(
                u["value"]
                for u in self.db.list_unspent_by_address(address, self.network)
                if self._is_spendable_utxo(u, tip)
            )
        total = 0
        counted: set[str] = set()
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            # Count EVERY script type the key owns (p2wpkh, p2pkh, p2sh-p2wpkh,
            # p2tr), matching listunspent + Core GetBalance. Scanning only the
            # p2wpkh address stranded taproot/legacy/nested coinbase credits at
            # a reported balance of 0.
            for addr in self._key_script_addresses(k):
                counted.add(addr)
                for u in self.db.list_unspent_by_address(addr, self.network):
                    if self._is_spendable_utxo(u, tip):
                        total += u["value"]
        # Imported descriptors (watch-only included) count toward the wallet
        # balance: Core's GetBalance walks every ISMINE script
        # (DescriptorScriptPubKeyMan::IsMine is privkey-free script-set
        # membership). De-duplicated against the key addresses above.
        for daddr in set(self._descriptor_script_map().values()):
            if not daddr or daddr in counted:
                continue
            try:
                utxos = self.db.list_unspent_by_address(daddr, self.network)
            except Exception:
                continue
            for u in utxos:
                if self._is_spendable_utxo(u, tip):
                    total += u["value"]
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
        """Return transaction history for the wallet, newest first.

        Reads the in-memory history built by the block-connect scan
        (``scan_block_connect``) rather than a (never-implemented) DB method.
        Net amount per tx is credits-to-wallet minus debits-from-wallet.
        """
        tip = self._tip_height()
        results: list[TransactionInfo] = []
        for rec in self._sorted_history():
            net = rec["credit"] - rec["debit"]
            results.append(TransactionInfo(
                txid=rec["txid"],
                amount=net,
                confirmations=self._confirmations(rec, tip),
                timestamp=rec.get("time"),
            ))
        return results

    # --- Wallet transaction history (Core CWallet::mapWallet) ---------------
    # Reference: Bitcoin Core wallet/wallet.cpp (AddToWalletIfInvolvingMe,
    # transactionAddedToMempool / blockConnected) and wallet/rpc/transactions.cpp
    # (ListTransactions, WalletTxToJSON, gettransaction).

    def _owned_script_set(self) -> dict[bytes, str]:
        """Map every script_pubkey this wallet owns -> its display address.

        Covers all four script types per key (legacy/p2sh-segwit/bech32/
        bech32m), mirroring what ``list_unspent_by_address`` matches against.
        """
        from ouroboros.address import address_to_script_pubkey

        out: dict[bytes, str] = {}
        for kd in self.keys:
            try:
                k = self._get_wallet_key(kd)
            except Exception:
                continue
            for addr in (
                k.get_p2wpkh_address(),
                k.get_p2pkh_address(),
                k.get_p2sh_p2wpkh_address(),
            ):
                try:
                    out[address_to_script_pubkey(addr, self.network)] = addr
                except Exception:
                    continue
            # bech32m / Taproot derivation can raise on a malformed pubkey;
            # guard it independently so the other three still register.
            try:
                taddr = k.get_p2tr_address()
                out[address_to_script_pubkey(taddr, self.network)] = taddr
            except Exception:
                pass
        # Imported descriptors (including watch-only addr()/xpub entries) are
        # ISMINE by script-set membership — Core
        # DescriptorScriptPubKeyMan::IsMine (scriptpubkeyman.cpp:863-867);
        # private keys play no role. Keys win on (unlikely) overlap.
        for spk, addr in self._descriptor_script_map().items():
            out.setdefault(spk, addr)
        return out

    def _descriptor_script_map(self) -> dict[bytes, str]:
        """Map script_pubkey -> display address for every imported descriptor.

        This is what makes imported (watch-only) descriptors ISMINE for the
        history/balance/listunspent scans, mirroring Bitcoin Core
        DescriptorScriptPubKeyMan::IsMine — pure script-set membership over
        ``m_map_script_pub_keys`` (scriptpubkeyman.cpp:863-867). Ranged
        entries expand over ``[range_start, range_end]``; non-ranged entries
        (addr(), raw(), single-key) derive index 0 only. Cached; the cache is
        invalidated whenever the descriptor set changes (importdescriptors /
        wallet load / lock).
        """
        cached = self._descriptor_spk_cache
        if cached is not None:
            return cached

        from ouroboros.address import script_pubkey_to_address

        out: dict[bytes, str] = {}
        for entry in self.descriptors:
            desc = entry.descriptor
            try:
                if getattr(desc, "is_range", False):
                    lo = int(entry.range_start)
                    hi = int(entry.range_end)
                    indices = range(lo, hi + 1)
                else:
                    indices = range(0, 1)
                for i in indices:
                    # derive_all_scripts covers combo() expansion; for every
                    # other type it is the single canonical script.
                    scripts = desc.derive_all_scripts(i)
                    try:
                        addr = desc.derive_address(i, self.network)
                    except Exception:
                        addr = None
                    for spk in scripts:
                        spk_b = bytes(spk)
                        a = addr
                        if a is None:
                            try:
                                a = script_pubkey_to_address(
                                    spk_b, self.network
                                ) or ""
                            except Exception:
                                a = ""
                        out[spk_b] = a
            except Exception:
                # One malformed entry must not hide the others.
                continue
        self._descriptor_spk_cache = out
        return out

    # --- Chain rescan (Core CWallet::ScanForWalletTransactions) -------------
    # Reference: bitcoin-core/src/wallet/wallet.cpp ScanForWalletTransactions
    # and wallet/rpc/transactions.cpp rescanblockchain. The backward counterpart
    # of the block-connect scan (scan_block_connect): walk an EXISTING height
    # range, find outputs paying scripts this wallet can DERIVE (not just keys
    # it has already handed out), adopt those keys so the global-chainstate
    # balance/listunspent scan finds them, and build the history records.

    # How many indices per (purpose, is_change) sub-pool to probe during a
    # rescan. Covers the highest already-used index plus this much look-ahead,
    # mirroring Bitcoin Core's keypool gap-limit. Bounded so a Python rescan of
    # a fresh wallet stays fast: 4 purposes x 2 (receive/change) x this many
    # key derivations. 200 comfortably covers any hand-issued address in a test
    # or light wallet while keeping a regtest rescan sub-second.
    RESCAN_GAP_LIMIT = 200

    def _rescan_candidate_scripts(self) -> dict[bytes, dict]:
        """Map every script_pubkey this wallet can DERIVE -> its key metadata.

        Unlike :meth:`_owned_script_set` (which only covers keys already in
        ``self.keys``), this enumerates the HD key pool across every
        (purpose, is_change) sub-pool and derives ``RESCAN_GAP_LIMIT`` extra
        indices of look-ahead, so a freshly-restored wallet that has never
        called ``getnewaddress`` still rediscovers the funds at the addresses
        the same seed produced. Each value is::

            {"key": WalletKey, "purpose": int, "is_change": bool,
             "index": int, "address": str, "address_type": str}

        keyed by the canonical script_pubkey for that purpose's address type.
        Returns an empty map for non-HD (imported-only) wallets — those are
        already fully covered by ``self.keys`` + ``_owned_script_set``.
        """
        from ouroboros.address import address_to_script_pubkey

        # purpose-code -> (address_type, key.address-method-name)
        purpose_meta = {
            44: ("legacy", "get_p2pkh_address"),
            49: ("p2sh-segwit", "get_p2sh_p2wpkh_address"),
            84: ("bech32", "get_p2wpkh_address"),
            86: ("bech32m", "get_p2tr_address"),
        }

        out: dict[bytes, dict] = {}
        kp = self._key_pool
        if kp is None:
            return out

        for (purpose, is_change) in list(kp._pools.keys()):
            meta = purpose_meta.get(purpose)
            if meta is None:
                continue
            address_type, addr_method = meta
            # Probe from index 0 up to the highest already-used index plus a
            # bounded gap-limit look-ahead. ``_used_indices`` tracks the
            # addresses actually handed out (empty on a fresh restore), so a
            # restored-but-unused wallet still probes the full gap-limit window.
            used = kp._used_indices.get((purpose, is_change), set())
            top_used = max(used) if used else 0
            hi = top_used + self.RESCAN_GAP_LIMIT
            for index in range(0, hi):
                try:
                    k = kp.get_key_at_index(
                        index, is_change=is_change, purpose=purpose
                    )
                    addr = getattr(k, addr_method)()
                    spk = address_to_script_pubkey(addr, self.network)
                except Exception:
                    continue
                # First writer wins; receive sub-pools are enumerated before
                # change for the same purpose, matching get_new_address order.
                out.setdefault(spk, {
                    "key": k,
                    "purpose": purpose,
                    "is_change": is_change,
                    "index": index,
                    "address": addr,
                    "address_type": address_type,
                })
        return out

    def _adopt_key(self, info: dict) -> bool:
        """Adopt a derived key discovered during a rescan into ``self.keys``.

        Adds the key's WIF to ``self.keys`` (so the chainstate balance /
        listunspent scan, which iterates ``self.keys``, credits it) and marks
        the corresponding key-pool index used so the address is not later
        re-handed-out by ``getnewaddress``. Idempotent — a WIF already present
        is not duplicated. Returns True iff a new key was added.

        Mirrors Bitcoin Core CWallet::MarkReserveKeysAsUsed during a rescan.
        """
        k = info["key"]
        try:
            wif = k.to_wif()
        except Exception:
            return False
        for kd in self.keys:
            if kd.get("wif") == wif:
                added = False
                break
        else:
            self.keys.append({
                "wif": wif,
                "label": "",
                "created": int(time.time()),
                "hd_path": KeyPool.path_for(
                    info["purpose"], self._key_pool.coin_type,
                    info["is_change"], info["index"],
                ) if self._key_pool is not None else None,
            })
            added = True
        # Mark the pool index used regardless, so the address won't be re-issued.
        kp = self._key_pool
        if kp is not None:
            try:
                kp._used_indices.setdefault(
                    (info["purpose"], info["is_change"]), set()
                ).add(int(info["index"]))
                # Advance next_index past the discovered index so look-ahead
                # stays ahead of used addresses (Core keypool top-up).
                cur = kp._next_indices.get((info["purpose"], info["is_change"]), 0)
                if info["index"] >= cur:
                    kp._next_indices[(info["purpose"], info["is_change"])] = \
                        int(info["index"]) + 1
            except Exception:
                pass
        return added

    def rescan_chain(
        self, start_height: int = 0, stop_height: int | None = None
    ) -> dict:
        """Scan the EXISTING chain ``[start_height .. stop_height]`` for funds.

        For every block in the range, classify each output against the scripts
        this wallet can derive (key pool + gap-limit look-ahead). When an output
        pays a derivable script, adopt that key into ``self.keys`` so the
        chainstate balance scan credits it, then record the wallet-history
        entry via :meth:`scan_block_connect`. Persists once at the end.

        Returns ``{"start_height": s, "stop_height": e}`` (Core rescanblockchain
        shape). Reference: bitcoin-core CWallet::ScanForWalletTransactions +
        wallet/rpc/transactions.cpp rescanblockchain.
        """
        if self.db is None:
            return {"start_height": int(start_height), "stop_height": int(start_height)}

        tip = self._tip_height()
        start = max(0, int(start_height))
        stop = tip if stop_height is None else min(int(stop_height), tip)
        if stop < start:
            stop = start

        candidates = self._rescan_candidate_scripts()
        owned_keys_changed = False

        # Keyless-wallet fast path: with no candidate scripts AND no owned
        # outpoints, no block can possibly match — the walk is a provable
        # no-op.  Without this, reconcile_on_load's rescan_chain(0, None)
        # deserialized the ENTIRE chain in Python on every boot even for the
        # empty default wallet (2026-07-19: 434k blocks on genesis-ouroboros,
        # a GIL-hogging thread that starved the event loop for hours — slow
        # header batches, >30s block-delivery processing, timeout churn, and
        # the downstream self-ban).  Core equivalent: a fresh wallet's
        # birthday/locator short-circuits ScanForWalletTransactions.
        if not candidates and not self._owned_outpoints:
            logger.info(
                "rescan_chain: wallet '%s' has no keys/scripts/outpoints — "
                "skipping no-op scan of heights %d..%d",
                getattr(self, "name", "?"), start, stop,
            )
            return {"start_height": start, "stop_height": stop}

        for height in range(start, stop + 1):
            try:
                block = self.db.get_block_by_height(height)
            except Exception:
                block = None
            if block is None:
                continue

            # 1. Adopt any derivable key funded by an output in this block, so
            #    the chainstate balance/listunspent scan (over self.keys) sees
            #    it. We must adopt BEFORE the history scan so scan_block_connect
            #    (which reads _owned_script_set over self.keys) classifies the
            #    output as a credit.
            for tx in getattr(block, "transactions", None) or []:
                for out in tx.outputs:
                    info = candidates.get(bytes(out.script_pubkey))
                    if info is not None:
                        if self._adopt_key(info):
                            owned_keys_changed = True

            # 2. Build the history records for this block (idempotent per txid).
            try:
                self.scan_block_connect(block, height)
            except Exception:
                pass

        # Advance the persisted scan locator: this wallet has now seen
        # everything up to `stop` (Core: WalletBatch::WriteBestBlock after
        # ScanForWalletTransactions).
        if self._best_scanned_height is None or stop > self._best_scanned_height:
            self._best_scanned_height = stop
            owned_keys_changed = True

        if owned_keys_changed:
            try:
                self._save()
            except Exception:
                pass

        return {"start_height": start, "stop_height": stop}

    def scan_block_connect(self, block, height: int) -> None:
        """Record wallet-relevant txs from a freshly-connected *block*.

        Walks each tx; a tx is wallet-relevant when it either (a) creates an
        output paying one of our scripts (credit) or (b) spends an outpoint we
        previously credited (debit). Builds/extends a per-tx history record and
        tracks newly-owned + newly-spent outpoints so a later block's spend is
        correctly attributed. Idempotent per (txid, height) — re-connecting the
        same block (e.g. reorg replay) overwrites rather than double-counts.

        Mirrors Bitcoin Core CWallet::blockConnected ->
        AddToWalletIfInvolvingMe.
        """
        owned = self._owned_script_set()
        # Live tip-follow keeps the scan locator current in memory; it is
        # persisted on the wallet's existing _save() cadence (rescan end,
        # key changes, unload).
        if self._best_scanned_height is None or height > self._best_scanned_height:
            self._best_scanned_height = height
        block_hash = getattr(block, "hash", None)
        block_hash_hex = (
            bytes(block_hash)[::-1].hex() if block_hash is not None else None
        )
        block_time = int(getattr(block, "timestamp", 0) or 0)
        txs = getattr(block, "transactions", None) or []

        for tx in txs:
            # txid is stored internal (wire) byte order; display is reversed.
            raw_txid = tx.get_txid()
            txid_hex = bytes(raw_txid)[::-1].hex()
            is_coinbase = bool(getattr(tx, "is_coinbase", False))

            # --- Debit: total value of inputs spending outpoints we own ------
            # Mirrors Core CachedTxGetDebit. nDebit > 0 ⇒ "we sent this tx".
            debit = 0
            if not is_coinbase:
                for inp in tx.inputs:
                    # input prev_txid is internal byte order -> display hex.
                    prev_txid_hex = bytes(inp.prev_txid)[::-1].hex()
                    spent = self._owned_outpoints.get(
                        (prev_txid_hex, int(inp.prev_vout))
                    )
                    if spent is not None:
                        debit += int(spent["value"])
            is_from_me = debit > 0

            # --- Per-output classification (Core CachedTxGetAmounts) ---------
            # For each output: when we sent the tx (nDebit>0) every output is a
            # "send" entry EXCEPT change/owned outputs (listtransactions uses
            # include_change=false). When an output pays us it is a "receive".
            sent_details: list[dict] = []
            recv_details: list[dict] = []
            credit = 0
            for vout_i, out in enumerate(tx.outputs):
                addr = owned.get(bytes(out.script_pubkey))
                ismine = addr is not None
                if ismine:
                    credit += int(out.value)
                    recv_details.append({
                        "address": addr,
                        "vout": int(vout_i),
                        "value": int(out.value),
                    })
                    # Track the new owned outpoint so a future spend resolves it.
                    self._owned_outpoints[(txid_hex, vout_i)] = {
                        "value": int(out.value),
                        "address": addr,
                        "script_pubkey": bytes(out.script_pubkey),
                    }
                elif is_from_me:
                    # Non-owned output of a tx we funded ⇒ a real payment out.
                    from ouroboros.address import script_pubkey_to_address
                    try:
                        out_addr = script_pubkey_to_address(
                            bytes(out.script_pubkey), self.network
                        ) or ""
                    except Exception:
                        out_addr = ""
                    sent_details.append({
                        "address": out_addr,
                        "vout": int(vout_i),
                        "value": int(out.value),
                    })

            if not recv_details and not sent_details:
                continue  # not ours

            # Fee (Core: nFee = nDebit - GetValueOut, positive sats paid).
            # The wallet only knows the value of the inputs it owns; on a
            # wallet-funded spend that is the full input set, so this equals
            # the real fee.
            fee = 0
            if is_from_me:
                total_out = sum(int(o.value) for o in tx.outputs)
                fee = debit - total_out

            self._tx_history[txid_hex] = {
                "txid": txid_hex,
                "height": int(height),
                "blockhash": block_hash_hex,
                "blocktime": block_time,
                "time": block_time,
                "is_coinbase": is_coinbase,
                "is_from_me": is_from_me,
                "credit": int(credit),
                "debit": int(debit),
                "fee": int(fee),
                "recv": recv_details,
                "sent": sent_details,
                "hex": tx.serialize_with_witness().hex(),
            }

    def scan_block_disconnect(self, height: int) -> None:
        """Reverse :meth:`scan_block_connect` for the block at *height*.

        Drops every history record (and the owned-outpoint bookkeeping for
        outputs created) at that height, so a reorg can't leave stale send/
        receive entries. Mirrors Core CWallet::blockDisconnected.
        """
        drop = [
            txid for txid, rec in self._tx_history.items()
            if int(rec.get("height", -1)) == int(height)
        ]
        for txid in drop:
            rec = self._tx_history.pop(txid)
            for d in rec.get("recv", []):
                self._owned_outpoints.pop((txid, int(d["vout"])), None)

    def _confirmations(self, rec: dict, tip: int) -> int:
        h = int(rec.get("height", 0) or 0)
        if h <= 0:
            return 0
        return max(0, tip - h + 1)

    def _sorted_history(self) -> list[dict]:
        """History records sorted newest-first (by height, then time)."""
        return sorted(
            self._tx_history.values(),
            key=lambda r: (int(r.get("height", 0) or 0), int(r.get("time", 0) or 0)),
            reverse=True,
        )

    def _category_for(self, rec: dict, tip: int) -> str:
        """Receive-side category per Core ListTransactions."""
        if not rec.get("is_coinbase"):
            return "receive"
        confs = self._confirmations(rec, tip)
        if confs < 1:
            return "orphan"
        if confs < (self.COINBASE_MATURITY + 1):
            return "immature"
        return "generate"

    def _wallet_tx_common(self, rec: dict, tip: int) -> dict:
        """Fields shared by every list entry (Core WalletTxToJSON)."""
        common: dict = {
            "confirmations": self._confirmations(rec, tip),
            "blockhash": rec.get("blockhash"),
            "blockheight": int(rec.get("height", 0) or 0),
            "blocktime": int(rec.get("blocktime", 0) or 0),
            "txid": rec["txid"],
            "time": int(rec.get("time", 0) or 0),
            "timereceived": int(rec.get("time", 0) or 0),
            "bip125-replaceable": "no",
        }
        if rec.get("is_coinbase"):
            common["generated"] = True
        return common

    def listtransactions_entries(
        self, label: str = "*", count: int = 10, skip: int = 0
    ) -> list[dict]:
        """Build Core-shaped listtransactions entries, newest-first.

        One entry per send-output (category 'send', negative amount + fee) and
        one per receive-output (category receive/generate/immature). Returns
        the most recent *count* entries after skipping *skip*.

        Reference: Bitcoin Core wallet/rpc/transactions.cpp ListTransactions.
        """
        tip = self._tip_height()
        entries: list[dict] = []
        for rec in self._sorted_history():
            common = self._wallet_tx_common(rec, tip)
            fee_btc = -rec.get("fee", 0) / 1e8  # Core: negative fee on sends

            # Sent entries first (matches Core ordering within a tx).
            for d in rec.get("sent", []):
                e = {
                    "address": d.get("address", ""),
                    "category": "send",
                    "amount": -d["value"] / 1e8,   # negative for send
                    "vout": int(d["vout"]),
                    "fee": fee_btc,
                    "abandoned": False,
                }
                e.update(common)
                entries.append(e)

            # Received entries.
            for d in rec.get("recv", []):
                e = {
                    "address": d.get("address", ""),
                    "category": self._category_for(rec, tip),
                    "amount": d["value"] / 1e8,    # positive for receive
                    "vout": int(d["vout"]),
                    "abandoned": False,
                }
                e.update(common)
                entries.append(e)

        return entries[skip:skip + count] if count >= 0 else entries[skip:]

    def gettransaction_entry(self, txid_display_hex: str) -> dict | None:
        """Build the Core-shaped gettransaction object for *txid* (display hex).

        Returns None when the txid is not a wallet transaction (caller raises
        the RPC error). Reference: Bitcoin Core wallet/rpc/transactions.cpp
        gettransaction.
        """
        rec = self._tx_history.get(txid_display_hex.lower())
        if rec is None:
            return None
        tip = self._tip_height()
        credit = int(rec.get("credit", 0))
        debit = int(rec.get("debit", 0))
        net = credit - debit
        is_from_me = bool(rec.get("is_from_me"))
        fee = int(rec.get("fee", 0))

        # Core: amount = nNet - nFee where nFee = GetValueOut() - nDebit (a
        # NEGATIVE quantity when a fee was paid). Our ``fee`` is the positive
        # sats paid, i.e. nFee == -fee, so amount = nNet - (-fee) = nNet + fee.
        # Identity check: net + fee == credit - debit + (debit - total_out)
        #               == credit - total_out == Core's nCredit - GetValueOut().
        amount = (net + fee) / 1e8

        out: dict = {
            "amount": amount,
            "confirmations": self._confirmations(rec, tip),
            "blockhash": rec.get("blockhash"),
            "blockheight": int(rec.get("height", 0) or 0),
            "blocktime": int(rec.get("blocktime", 0) or 0),
            "txid": rec["txid"],
            "time": int(rec.get("time", 0) or 0),
            "timereceived": int(rec.get("time", 0) or 0),
            "bip125-replaceable": "no",
            "hex": rec.get("hex", ""),
        }
        if rec.get("is_coinbase"):
            out["generated"] = True
        if is_from_me:
            out["fee"] = -fee / 1e8   # negative, BTC

        # details[] mirrors ListTransactions(fLong=false) for this one tx.
        details: list[dict] = []
        for d in rec.get("sent", []):
            details.append({
                "address": d.get("address", ""),
                "category": "send",
                "amount": -d["value"] / 1e8,
                "vout": int(d["vout"]),
                "fee": -fee / 1e8,
                "abandoned": False,
            })
        for d in rec.get("recv", []):
            details.append({
                "address": d.get("address", ""),
                "category": self._category_for(rec, tip),
                "amount": d["value"] / 1e8,
                "vout": int(d["vout"]),
                "abandoned": False,
            })
        out["details"] = details
        return out

    async def generate_address_of_type(
        self, address_type: str = DEFAULT_ADDRESS_TYPE, label: str | None = None
    ) -> str:
        """Generate address of given type: bech32, legacy, p2sh-segwit, bech32m.

        When a key pool is configured (the normal HD path), defers to
        :meth:`generate_new_address` so the BIP-43 purpose dispatch is
        applied (legacy→44, p2sh-segwit→49, bech32→84, bech32m→86).
        Otherwise falls back to the legacy ``_hd_base_path`` for callers
        that have an old single-path HD seed but no key pool.
        """
        # Prefer the keypool path so the BIP-43 dispatch (W161 BUG-6/7/8)
        # applies. ``generate_new_address`` already writes the right
        # ``hd_path`` into ``self.keys`` for each purpose.
        if self._key_pool is not None:
            return await self.generate_new_address(
                label=label, address_type=address_type,
            )

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
    ) -> str | None:
        """Create an RBF fee-bumped version of *txid* at *new_fee_rate* sat/vB.

        Verifies the original signals RBF (sequence < 0xFFFFFFFE), then reduces
        the change output (or adds a new input) to cover the higher fee.
        Returns signed tx hex when *sign=True*, unsigned hex otherwise, or None on failure.
        """
        from ouroboros.database import Transaction, TxIn, TxOut

        if self.db is None or self.mempool is None:
            logger.warning("bump_fee: database or mempool not available")
            return None

        # 1. Look up the original tx in mempool.
        # txid arrives in display order (BE hex); mempool keys are LE. W69.
        txid_bytes = bytes.fromhex(txid)[::-1]
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
        wallet_spk_map: dict[bytes, WalletKey] = {}
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            wallet_spk_map[k.get_script_pubkey()] = k

        input_values: list[int] = []
        input_keys: list[WalletKey | None] = []
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
        change_idx: int | None = None
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
            for i, _ in enumerate(new_inputs):
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
        wallet_spk_map: dict[bytes, "WalletKey"],
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
        target_fee - (total_input_value - total_output_value)

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
        self, requests: list[dict]
    ) -> list[dict]:
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
            parse_descriptor,
            verify_checksum,
        )

        results: list[dict] = []

        for req in requests:
            try:
                desc_str = req.get("desc", "")
                if not desc_str:
                    raise ValueError("Missing 'desc' field")

                # Checksum gate FIRST (Core wallet/rpc/backup.cpp:158-161
                # calls Parse(..., require_checksum=true)): a descriptor
                # without "#..." fails -5 with EXACTLY "Missing checksum"
                # (descriptor.cpp:2845-2846) before any other validation.
                if "#" not in desc_str:
                    raise WalletRpcError(-5, "Missing checksum")
                if not verify_checksum(desc_str):
                    raise WalletRpcError(
                        -5, f"Invalid checksum in: {desc_str}"
                    )

                descriptor = parse_descriptor(desc_str)

                # Private-key gate AFTER the parse/checksum gate (ordering is
                # part of the Core contract — backup.cpp:224-226): a
                # well-formed descriptor containing private key material
                # (WIF / xprv / tprv) cannot be imported into a
                # disable_private_keys wallet. RPC_WALLET_ERROR = -4.
                if self._disable_private_keys and any(
                    getattr(k, "is_private", False)
                    for k in (descriptor.keys or [])
                ):
                    raise WalletRpcError(
                        -4,
                        "Cannot import private keys to a wallet with "
                        "private keys disabled",
                    )

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
                        # WalletRpcError carries the Core code (-4 for the
                        # privkey-into-dpk gate); anything else keeps the
                        # historical -5 (RPC_INVALID_ADDRESS_OR_KEY).
                        "code": getattr(exc, "code", -5),
                        "message": str(exc),
                    },
                })
                logger.warning("Failed to import descriptor: %s", exc)

        self._descriptor_spk_cache = None
        self._save()
        return results

    def listdescriptors(self) -> list[dict]:
        """Return all imported descriptors in JSON-serialisable form."""
        return [d.to_dict() for d in self.descriptors]

    def deriveaddresses(
        self, desc_str: str, range_param: list[int] | None = None
    ) -> list[str]:
        """Derive addresses from *desc_str*; *range_param* is ``[start, end]`` (inclusive) or None for non-range descriptors."""
        from ouroboros.descriptors import add_checksum, parse_descriptor

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

    def get_descriptor_addresses(self) -> list[str]:
        """Return all addresses derived from active descriptors up to next_index."""
        addrs: list[str] = []
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

    @staticmethod
    def _key_script_addresses(k) -> list[str]:
        """Every standard address type key *k* controls (p2wpkh, p2pkh,
        p2sh-p2wpkh, p2tr), de-duplicated.

        Mirrors the enumeration ``rpc_listunspent`` already uses so that
        BALANCE and COIN SELECTION see every script type the key owns — not
        just P2WPKH. Previously ``get_balance`` / ``_collect_utxos`` scanned
        ONLY ``get_p2wpkh_address()``, so coins received on a taproot (or
        legacy / nested-segwit) address were invisible to the balance and
        UNSPENDABLE by coin selection even though ``listunspent`` showed them
        — funds effectively stranded. Reference: Bitcoin Core
        wallet/spend.cpp AvailableCoins() / wallet.cpp GetBalance() walk every
        ISMINE script, not one canonical type.
        """
        addrs: list[str] = []
        for fn in (
            k.get_p2wpkh_address,
            k.get_p2pkh_address,
            k.get_p2sh_p2wpkh_address,
            k.get_p2tr_address,
        ):
            try:
                a = fn()
            except Exception:
                continue
            if a and a not in addrs:
                addrs.append(a)
        return addrs

    def _collect_utxos(self) -> list[dict]:
        if self.db is None:
            return []
        tip = self._tip_height()
        utxos: list[dict] = []
        for kd in self.keys:
            k = self._get_wallet_key(kd)
            for addr in self._key_script_addresses(k):
                for u in self.db.list_unspent_by_address(addr, self.network):
                    # Skip immature coinbase: selecting one would build a tx the
                    # node rejects as bad-txns-premature-spend-of-coinbase.
                    # Reference: Bitcoin Core wallet/spend.cpp AvailableCoins()
                    # only offers coins with GetBlocksToMaturity() == 0.
                    if not self._is_spendable_utxo(u, tip):
                        continue
                    # Honor lockunspent — skip coins the user explicitly locked.
                    # Reference: Bitcoin Core wallet/spend.cpp AvailableCoins().
                    txid_field = u.get("txid", "")
                    txid_str = txid_field if isinstance(txid_field, str) else txid_field.hex()
                    if self.is_locked_coin(txid_str, int(u.get("vout", 0))):
                        continue
                    u["_key"] = k
                    utxos.append(u)
        return utxos

    # --- lockunspent / listlockunspent -----------------------------------------
    # Reference: Bitcoin Core wallet/wallet.cpp::LockCoin / UnlockCoin /
    # ListLockedCoins / IsLockedCoin and wallet/rpc/coins.cpp::lockunspent.

    def is_locked_coin(self, txid: str, vout: int) -> bool:
        """Return True if (txid, vout) is currently locked (persistent or not)."""
        return (txid.lower(), int(vout)) in self._locked_coins

    def lock_coin(self, txid: str, vout: int, persistent: bool = False) -> None:
        """Lock the outpoint so coin selection skips it.

        ``persistent=True`` means the lock is written to the wallet database
        and survives restart, matching Core's persistent-lock semantics.
        """
        key = (txid.lower(), int(vout))
        existing = self._locked_coins.get(key)
        # Once persistent, stay persistent — Core's LockCoin does the same:
        # an upgrade from in-memory → persistent persists, but a transient
        # re-lock never demotes a persistent lock.
        new_persistent = bool(persistent or existing)
        if self._locked_coins.get(key) == new_persistent and key in self._locked_coins:
            return
        self._locked_coins[key] = new_persistent
        if persistent:
            self._save()

    def unlock_coin(self, txid: str, vout: int) -> bool:
        """Unlock the outpoint. Returns True if the entry was removed."""
        key = (txid.lower(), int(vout))
        was_persistent = self._locked_coins.pop(key, None)
        if was_persistent:
            self._save()
            return True
        return was_persistent is not None

    def unlock_all_coins(self) -> bool:
        """Unlock every coin. Returns True (Core's UnlockAllCoins always does)."""
        had_persistent = any(p for p in self._locked_coins.values())
        self._locked_coins.clear()
        if had_persistent:
            self._save()
        return True

    def list_locked_coins(self) -> list[tuple[str, int]]:
        """Return all currently-locked outpoints as ``(txid, vout)`` tuples."""
        return [(txid, vout) for (txid, vout) in self._locked_coins]

    # --- coin selection --------------------------------------------------------

    def _select_coins(
        self,
        amount: int,
        fee_rate: float,
        long_term_fee_rate: float = DEFAULT_LONG_TERM_FEE_RATE,
    ) -> tuple[list[dict], int]:
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
        """Build, sign, and return a raw transaction hex sending *amount* sats to *to_address* at *fee_rate* sat/vB.

        Anti-fee-sniping: Sets nLockTime to the current block height to
        discourage miners from reorganizing old blocks to claim high-fee
        transactions. Reference: Bitcoin Core wallet/spend.cpp DiscourageFeeSniping().
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

        # Anti-fee-sniping: set nLockTime to current block height
        # This makes the transaction invalid for older blocks, discouraging
        # miners from fee-sniping by reorganizing to claim high-fee txs.
        # Reference: Bitcoin Core wallet/spend.cpp DiscourageFeeSniping()
        locktime = 0
        if self.db is not None:
            try:
                _, current_height = self.db.get_best_block()
                locktime = current_height
            except Exception:
                locktime = 0

        # Build unsigned inputs
        # Use sequence 0xFFFFFFFD to signal RBF and enable locktime
        inputs: list[TxIn] = []
        for utxo in selected:
            # ``utxo["txid"]`` is the display (big-endian) hex from the DB
            # layer (Core/JSON convention).  The wire ``prev_txid`` must be
            # internal (little-endian) byte order, so reverse the decoded
            # bytes.  (Previously this consumed the txid as-is, which only
            # ever "worked" because the demo UTXO stub never matched a real
            # coin and the spend path was unreachable.)
            if isinstance(utxo["txid"], str):
                txid_bytes = bytes.fromhex(utxo["txid"])[::-1]
            else:
                txid_bytes = bytes(utxo["txid"])
            inputs.append(TxIn(
                prev_txid=txid_bytes,
                prev_vout=utxo["vout"],
                script_sig=b"",
                sequence=0xFFFFFFFD,  # RBF signal + enables locktime
            ))

        tx = Transaction(
            txid=b"\x00" * 32,
            version=2,
            locktime=locktime,
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


class WalletManager:
    """
    Manages multiple wallets loaded simultaneously.

    Each wallet is stored in its own directory under ``<datadir>/wallets/<name>/``.
    Wallets can be dynamically created, loaded, and unloaded via RPC.

    Reference: Bitcoin Core wallet/wallet.cpp (LoadWallet, CreateWallet, UnloadWallet)
    """

    def __init__(self, data_dir: str, network: str = "mainnet"):
        """
        Initialize the wallet manager.

        Args:
            data_dir: Base data directory for the node
            network: Bitcoin network (mainnet, testnet, regtest, etc.)
        """
        self.data_dir = Path(data_dir).expanduser()
        self.network = network
        self.wallets_dir = self.data_dir / "wallets"
        self.wallets_dir.mkdir(parents=True, exist_ok=True)

        # Loaded wallets: name -> Wallet instance
        self._wallets: dict[str, Wallet] = {}

        # Default wallet (first loaded wallet)
        self._default_wallet_name: str | None = None

        # Database and mempool references (shared across wallets)
        self._db = None
        self._mempool = None

        # Wallet load callbacks
        self._load_callbacks: list = []

        logger.info(f"WalletManager initialized at {self.wallets_dir}")

    def set_database(self, db) -> None:
        """Set the blockchain database for all wallets."""
        self._db = db
        for wallet in self._wallets.values():
            wallet.set_database(db)

    def set_mempool(self, mempool) -> None:
        """Set the mempool for all wallets."""
        self._mempool = mempool
        for wallet in self._wallets.values():
            wallet.set_mempool(mempool)

    # --- Chain notifications (Core CValidationInterface fan-out) -----------
    #
    # The node's block-connect loop (BlockSync) holds a single reference to
    # this manager as its ``wallet_notifier`` and calls these on every
    # canonically-connected / disconnected block. The manager fans the
    # notification out to every loaded wallet so each keeps its in-memory
    # transaction history + owned-outpoint set in lock-step with the chain.
    # Without this wiring P2P-synced funds are invisible until a manual
    # ``rescanblockchain`` RPC.

    def notify_block_connected(self, block, height: int) -> None:
        """Fan a block-connect out to all loaded (unlocked) wallets.

        Per-wallet errors are swallowed so one wallet's fault never stalls the
        connect loop for the whole fleet (and never aborts IBD on the caller
        side). Mirrors Bitcoin Core CWallet::blockConnected.
        """
        for wallet in list(self._wallets.values()):
            try:
                # A locked encrypted wallet has no scripts in memory; skip it
                # (it will be reconciled on unlock/rescan).
                if getattr(wallet, "is_locked", False):
                    continue
                wallet.scan_block_connect(block, height)
            except Exception as e:
                logger.warning(
                    f"wallet '{getattr(wallet, 'name', '?')}' "
                    f"scan_block_connect failed at height {height}: {e}"
                )

    def notify_block_disconnected(self, height: int) -> None:
        """Fan a block-disconnect out to all loaded wallets (reorg rollback)."""
        for wallet in list(self._wallets.values()):
            try:
                if getattr(wallet, "is_locked", False):
                    continue
                wallet.scan_block_disconnect(height)
            except Exception as e:
                logger.warning(
                    f"wallet '{getattr(wallet, 'name', '?')}' "
                    f"scan_block_disconnect failed at height {height}: {e}"
                )

    def reconcile_on_load(self) -> None:
        """Rebuild every loaded wallet's in-memory history from the chain.

        Called once at node startup after the database is attached. The wallet
        file persists keys / HD seed / key pool / descriptors durably, but the
        per-tx history (``_tx_history``) and owned-outpoint set are in-memory
        only (Core rebuilds ``mapWallet`` from a rescan on load). A rescan over
        the whole active chain repopulates them so listtransactions / balance
        are correct immediately after a restart instead of empty until a manual
        rescanblockchain. Best-effort and bounded by the current tip; per-wallet
        errors are swallowed so a wallet fault never blocks node startup.
        Mirrors Bitcoin Core CWallet::AttachChain / ScanForWalletTransactions.
        """
        if self._db is None:
            return
        for wallet in list(self._wallets.values()):
            try:
                if getattr(wallet, "is_locked", False):
                    # Encrypted-and-locked: nothing derivable in memory yet.
                    continue
                # Core-parity locator semantics (CWallet::AttachChain): rescan
                # only the gap ABOVE the wallet's persisted scan marker — never
                # the whole chain.  The prior unconditional rescan_chain(0,
                # None) Python-deserialized EVERY block at EVERY boot
                # (2026-07-19: 434k blocks on genesis-ouroboros, a GIL-hogging
                # thread that starved sync for hours and cascaded into the
                # timeout/self-ban wedge).
                marker = getattr(wallet, "_best_scanned_height", None)
                if marker is None:
                    # Legacy wallet file with no marker: adopt "born now" (a
                    # fresh Core wallet's birthday is its creation tip; it
                    # never auto-rescans history).  A restored-from-seed
                    # wallet with real history needs an explicit
                    # rescanblockchain — same as Core.
                    tip = wallet._tip_height()
                    wallet._best_scanned_height = tip
                    try:
                        wallet._save()
                    except Exception:
                        pass
                    logger.warning(
                        "wallet '%s' has no scan marker — adopting birthday at "
                        "current tip %s (Core AttachChain parity). If this "
                        "wallet may have historical activity, run "
                        "rescanblockchain 0.",
                        getattr(wallet, "name", "?"), tip,
                    )
                    continue
                wallet.rescan_chain(marker + 1, None)
            except Exception as e:
                logger.warning(
                    f"wallet '{getattr(wallet, 'name', '?')}' "
                    f"startup reconcile failed: {e}"
                )

    def _wallet_dir(self, name: str) -> Path:
        """Get the directory path for a wallet."""
        return self.wallets_dir / name

    def _wallet_file(self, name: str) -> Path:
        """Get the wallet.dat path for a wallet."""
        return self._wallet_dir(name) / "wallet.dat"

    def wallet_exists(self, name: str) -> bool:
        """Check if a wallet exists on disk."""
        return self._wallet_file(name).exists()

    def is_loaded(self, name: str) -> bool:
        """Check if a wallet is currently loaded."""
        return name in self._wallets

    def list_loaded_wallets(self) -> list[str]:
        """Return list of loaded wallet names."""
        return list(self._wallets.keys())

    def list_wallet_dir(self) -> list[dict[str, str]]:
        """
        List all wallets in the wallet directory (loaded or not).

        Returns list of dicts with 'name' key.
        Reference: Bitcoin Core listwalletdir RPC
        """
        result = []
        if not self.wallets_dir.exists():
            return result

        for entry in self.wallets_dir.iterdir():
            if entry.is_dir():
                wallet_file = entry / "wallet.dat"
                if wallet_file.exists():
                    result.append({"name": entry.name})
        return result

    def get_wallet(self, name: str | None = None) -> Wallet | None:
        """
        Get a loaded wallet by name.

        If name is None, returns the default wallet (first loaded).
        Returns None if no matching wallet is loaded.
        """
        if name is None:
            if self._default_wallet_name is None:
                return None
            return self._wallets.get(self._default_wallet_name)
        return self._wallets.get(name)

    def get_default_wallet(self) -> Wallet | None:
        """Get the default wallet (first loaded wallet)."""
        return self.get_wallet(None)

    def create_wallet(
        self,
        name: str,
        disable_private_keys: bool = False,
        blank: bool = False,
        passphrase: str | None = None,
        avoid_reuse: bool = False,
        descriptors: bool = True,
        load_on_startup: bool | None = None,
        mnemonic: list[str] | str | None = None,
        bip39_passphrase: str = "",
    ) -> tuple[Wallet | None, list[str]]:
        """
        Create a new wallet.

        Args:
            name: Wallet name (cannot be empty)
            disable_private_keys: Create watch-only wallet
            blank: Create wallet without keys
            passphrase: Encryption passphrase (optional)
            avoid_reuse: Enable coin reuse tracking (not implemented)
            descriptors: Must be True (legacy wallets not supported)
            load_on_startup: Add to auto-load list
            mnemonic: BIP-39 mnemonic (12/15/18/21/24 words). If None and
                the wallet is non-blank, a fresh 12-word mnemonic is
                generated via :func:`bip39.generate_mnemonic`. Pass a
                list/str to restore from an existing seed phrase.
            bip39_passphrase: BIP-39 passphrase ("25th word"). Distinct
                from *passphrase* (which encrypts the wallet at rest).

        Returns:
            (wallet, warnings) tuple. wallet is None on error.

        Reference: Bitcoin Core wallet/wallet.cpp CreateWallet
        """
        warnings: list[str] = []

        # Validate name
        if not name:
            raise ValueError("Wallet name cannot be empty")

        # Only descriptor wallets supported
        if not descriptors:
            raise ValueError("Legacy wallets are not supported; descriptors must be True")

        # Check if already loaded
        if name in self._wallets:
            raise ValueError(f"Wallet '{name}' is already loaded")

        # Check if exists on disk
        wallet_dir = self._wallet_dir(name)
        wallet_file = self._wallet_file(name)
        if wallet_file.exists():
            raise ValueError(f"Wallet '{name}' already exists")

        # Passphrase validation
        if passphrase is not None and disable_private_keys:
            raise ValueError("Cannot encrypt a watch-only wallet")
        if passphrase == "":
            warnings.append("Empty passphrase provided; wallet will not be encrypted")
            passphrase = None

        # Create wallet directory
        wallet_dir.mkdir(parents=True, exist_ok=True)

        # Create wallet instance with new-style directory path
        wallet = Wallet(
            data_dir=str(self.data_dir),
            network=self.network,
            name=name,
            wallet_dir=str(wallet_dir),
        )

        # Set disable_private_keys flag
        wallet._disable_private_keys = disable_private_keys

        # Initialize HD seed if not blank and not watch-only.
        # As of W21, fresh wallets are seeded from a BIP-39 mnemonic by
        # default — this lets users dumpmnemonic for backup. Restoring
        # from an existing mnemonic is also supported via the *mnemonic*
        # argument.
        if not blank and not disable_private_keys:
            from ouroboros.bip39 import generate_mnemonic as _gen_mnemonic

            if mnemonic is None:
                mnemonic_words: list[str] = _gen_mnemonic(128)  # 12 words
            elif isinstance(mnemonic, str):
                mnemonic_words = mnemonic.split()
            else:
                mnemonic_words = list(mnemonic)

            if passphrase:
                # For encrypted wallets, create blank first then encrypt
                wallet.encrypt(passphrase)
                wallet.unlock(passphrase)
                wallet.init_hd(
                    mnemonic=mnemonic_words,
                    bip39_passphrase=bip39_passphrase,
                    pool_size=1000,
                )
                wallet.lock()
                wallet.unlock(passphrase)  # Keep unlocked for use
            else:
                wallet.init_hd(
                    mnemonic=mnemonic_words,
                    bip39_passphrase=bip39_passphrase,
                    pool_size=1000,
                )
        elif passphrase and not disable_private_keys:
            # Blank wallet with passphrase
            wallet.encrypt(passphrase)

        # Set database and mempool
        if self._db:
            wallet.set_database(self._db)
        if self._mempool:
            wallet.set_mempool(self._mempool)

        # Add to loaded wallets
        self._wallets[name] = wallet

        # Set as default if first wallet
        if self._default_wallet_name is None:
            self._default_wallet_name = name

        # Save load_on_startup setting
        if load_on_startup is not None:
            self._update_load_on_startup(name, load_on_startup)

        logger.info(f"Created wallet '{name}'")
        return wallet, warnings

    def load_wallet(
        self,
        name: str,
        load_on_startup: bool | None = None,
    ) -> tuple[Wallet | None, list[str]]:
        """
        Load an existing wallet.

        Args:
            name: Wallet name to load
            load_on_startup: Update auto-load setting

        Returns:
            (wallet, warnings) tuple. wallet is None on error.

        Reference: Bitcoin Core wallet/wallet.cpp LoadWallet
        """
        warnings: list[str] = []

        # Check if already loaded
        if name in self._wallets:
            raise ValueError(f"Wallet '{name}' is already loaded")

        # Check if exists
        wallet_dir = self._wallet_dir(name)
        wallet_file = self._wallet_file(name)

        if not wallet_file.exists():
            # Try legacy path (old single-file wallets)
            legacy_path = self.wallets_dir / f"{name}.json"
            if legacy_path.exists():
                # Migrate to new directory structure
                wallet_dir.mkdir(parents=True, exist_ok=True)
                legacy_path.rename(wallet_file)
                warnings.append(f"Migrated wallet '{name}' to new directory format")
            else:
                raise ValueError(f"Wallet '{name}' not found")

        # Load wallet
        wallet = Wallet(
            data_dir=str(self.data_dir),
            network=self.network,
            name=name,
            wallet_dir=str(wallet_dir),
        )

        # Set database and mempool
        if self._db:
            wallet.set_database(self._db)
        if self._mempool:
            wallet.set_mempool(self._mempool)

        # Add to loaded wallets
        self._wallets[name] = wallet

        # Set as default if first wallet
        if self._default_wallet_name is None:
            self._default_wallet_name = name

        # Update load_on_startup setting
        if load_on_startup is not None:
            self._update_load_on_startup(name, load_on_startup)

        logger.info(f"Loaded wallet '{name}'")
        return wallet, warnings

    def unload_wallet(
        self,
        name: str,
        load_on_startup: bool | None = None,
    ) -> list[str]:
        """
        Unload a wallet from memory.

        Args:
            name: Wallet name to unload
            load_on_startup: Update auto-load setting (False to remove from list)

        Returns:
            List of warnings

        Reference: Bitcoin Core wallet/wallet.cpp UnloadWallet
        """
        warnings: list[str] = []

        if name not in self._wallets:
            raise ValueError(f"Wallet '{name}' is not loaded")

        wallet = self._wallets[name]

        # Save wallet state before unloading
        wallet._save()

        # Remove from loaded wallets
        del self._wallets[name]

        # Update default wallet if needed
        if self._default_wallet_name == name:
            if self._wallets:
                self._default_wallet_name = next(iter(self._wallets.keys()))
            else:
                self._default_wallet_name = None

        # Update load_on_startup setting
        if load_on_startup is not None:
            self._update_load_on_startup(name, load_on_startup)

        logger.info(f"Unloaded wallet '{name}'")
        return warnings

    def _update_load_on_startup(self, name: str, enabled: bool) -> None:
        """Update the load_on_startup setting for a wallet."""
        settings_file = self.wallets_dir / "settings.json"
        settings: dict[str, Any] = {}

        if settings_file.exists():
            try:
                with open(settings_file) as f:
                    settings = json.load(f)
            except Exception:
                pass

        if "load_on_startup" not in settings:
            settings["load_on_startup"] = []

        wallets_list = settings["load_on_startup"]

        if enabled:
            if name not in wallets_list:
                wallets_list.append(name)
        else:
            if name in wallets_list:
                wallets_list.remove(name)

        with open(settings_file, "w") as f:
            json.dump(settings, f, indent=2)

    def get_load_on_startup_wallets(self) -> list[str]:
        """Get list of wallets configured to load on startup."""
        settings_file = self.wallets_dir / "settings.json"
        if not settings_file.exists():
            return []

        try:
            with open(settings_file) as f:
                settings = json.load(f)
            return settings.get("load_on_startup", [])
        except Exception:
            return []

    def load_startup_wallets(self) -> None:
        """Load all wallets configured for startup loading."""
        wallets_to_load = self.get_load_on_startup_wallets()
        for name in wallets_to_load:
            try:
                self.load_wallet(name)
            except Exception as e:
                logger.warning(f"Failed to load wallet '{name}' on startup: {e}")

    def get_wallet_info(self, name: str) -> dict[str, Any]:
        """Get wallet information dict for RPC."""
        if name not in self._wallets:
            raise ValueError(f"Wallet '{name}' is not loaded")
        return {"name": name}
