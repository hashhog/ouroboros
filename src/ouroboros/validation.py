"""Block and transaction validation logic."""

import hashlib
import logging
import os
import struct
import time as _time

from ouroboros.database import Block, BlockchainDatabase, Transaction, TxIn, TxOut
from ouroboros.script import (
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NONE,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS,
    ScriptInterpreter,
    get_flags_for_height,
)
from ouroboros.sig_cache import SigCache
from ouroboros.consensus import (
    BURIED_DEPLOYMENTS,
    BIP34_HASHES,
    BIP30_REPEAT_EXCEPTIONS,
    is_buried_deployment_active,
)

logger = logging.getLogger(__name__)

# Try to import the Rust sync module for assume-valid / checkpoint skipping
try:
    import sync as _sync_module
    _has_sync_module = True
except ImportError:
    _sync_module = None
    _has_sync_module = False

# Global signature cache instance (50,000 entries ~ Bitcoin Core default)
SIG_CACHE = SigCache(max_entries=50_000)

COINBASE_MATURITY = 100

# Block limits
# References: bitcoin-core/src/consensus/consensus.h:15-24
MAX_BLOCK_WEIGHT = 4_000_000
MAX_BLOCK_SIGOPS_COST = 80_000
MAX_TX_SIGOPS_COST = 16_000
WITNESS_SCALE_FACTOR = 4
# MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60 (consensus.h:23)
MIN_TRANSACTION_WEIGHT = 240
# MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10 (consensus.h:24)
MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40

# Difficulty / PoW constants #
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016
POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60
POW_TARGET_SPACING = 10 * 60
# Per-network PoW limits (maximum target / minimum difficulty).
# Ref: Bitcoin Core kernel/chainparams.cpp
#   mainnet / testnet3 / testnet4: 0x00000000ffff...  → bits 0x1d00ffff
#   signet:                        0x00000377ae00...  → stricter than mainnet
#   regtest:                       0x7fffffff...      → bits 0x207fffff
POW_LIMIT_MAINNET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
POW_LIMIT_BITS_MAINNET = 0x1d00ffff
POW_LIMIT_SIGNET = 0x00000377AE000000000000000000000000000000000000000000000000000000
POW_LIMIT_BITS_SIGNET = 0x1e0377ae
POW_LIMIT_REGTEST = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
POW_LIMIT_BITS_REGTEST = 0x207fffff
# Networks where fPowAllowMinDifficultyBlocks = true (Core chainparams.cpp).
# Mainnet: false, signet: false, regtest: true, testnet3/testnet4: true.
# Ref: Bitcoin Core kernel/chainparams.cpp lines 99, 222, 321, 463, 546.
_POW_ALLOW_MIN_DIFFICULTY_NETWORKS = {"testnet", "testnet3", "testnet4", "regtest"}
MAX_TIMEWARP = 600  # BIP94: max seconds a diff-adjustment block can precede prev
# Maximum seconds a block timestamp may exceed the current wall-clock time.
# Ref: Bitcoin Core chain.h:29 — static constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60  # 7200 seconds
MAX_MONEY = 21_000_000 * 100_000_000  # 2,100,000,000,000,000 satoshis

# --- Signet (BIP 325) ---
SIGNET_HEADER = bytes([0xEC, 0xC7, 0xDA, 0xA2])

# Default signet challenge: 1-of-2 multisig (Bitcoin Core kernel/chainparams.cpp)
DEFAULT_SIGNET_CHALLENGE = bytes.fromhex(
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430"
    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c45"
    "2ae"
)

# Script verification flags for signet block validation
SIGNET_SCRIPT_FLAGS = (
    SCRIPT_VERIFY_P2SH
    | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_NULLDUMMY
)


def _encode_bip34_height(height: int) -> bytes:
    """Return the canonical BIP-34 byte encoding for a block height.

    Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448):
      height == 0  → b'\\x00'        (OP_0, single byte)
      1..16        → b'\\x51'..b'\\x60'  (OP_1..OP_16, single byte)
      otherwise    → length-prefixed sign-magnitude CScriptNum
    """
    if height == 0:
        return b"\x00"  # OP_0
    if 1 <= height <= 16:
        return bytes([0x50 + height])  # OP_1..OP_16
    # CScriptNum: minimal little-endian sign-magnitude with length prefix.
    le = []
    h = height
    while h > 0:
        le.append(h & 0xFF)
        h >>= 8
    # If high bit of last byte is set, append zero sign byte.
    if le[-1] & 0x80:
        le.append(0x00)
    return bytes([len(le)]) + bytes(le)


def _bits_to_target(bits: int) -> int:
    """Convert compact nBits to a 256-bit target integer.

    Mirrors arith_uint256::SetCompact (Bitcoin Core arith_uint256.cpp:176).
    Returns 0 for negative or overflow inputs — callers that need the full
    validity breakdown should use _bits_to_target_checked().
    """
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF

    # Strip the negative-sign flag from mantissa before computing the value
    # (same shift-right path as SetCompact does for the word).
    word = mantissa
    if exponent <= 3:
        word >>= 8 * (3 - exponent)
    else:
        word <<= 8 * (exponent - 3)

    # Negative flag: sign bit in mantissa set AND word is non-zero.
    # Ref: arith_uint256.cpp:188.
    is_negative = (mantissa != 0) and ((bits & 0x00800000) != 0)
    # Overflow flag: word is non-zero AND (exponent > 34, or mantissa > 0xff
    # and exponent > 33, or mantissa > 0xffff and exponent > 32).
    # Ref: arith_uint256.cpp:190-192.
    is_overflow = (mantissa != 0) and (
        (exponent > 34)
        or (mantissa > 0xFF and exponent > 33)
        or (mantissa > 0xFFFF and exponent > 32)
    )

    if is_negative or is_overflow:
        return 0

    return word


def _bits_to_target_checked(bits: int) -> tuple[int, bool, bool]:
    """Convert compact nBits, returning (target, is_negative, is_overflow).

    Ref: arith_uint256::SetCompact (Bitcoin Core arith_uint256.cpp:176-193).
    Used by CheckProofOfWork / DeriveTarget to validate the nBits field.
    """
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF

    if exponent <= 3:
        word = mantissa >> (8 * (3 - exponent))
    else:
        word = mantissa << (8 * (exponent - 3))

    is_negative = (mantissa != 0) and ((bits & 0x00800000) != 0)
    is_overflow = (mantissa != 0) and (
        (exponent > 34)
        or (mantissa > 0xFF and exponent > 33)
        or (mantissa > 0xFFFF and exponent > 32)
    )
    return word, is_negative, is_overflow


def _get_pow_limit(network: str) -> int:
    """Return the proof-of-work limit (max target) for the given network.

    Ref: Bitcoin Core kernel/chainparams.cpp — powLimit per network.
    """
    if network == "signet":
        return POW_LIMIT_SIGNET
    if network in ("regtest",):
        return POW_LIMIT_REGTEST
    # mainnet, testnet, testnet3, testnet4 all share the same powLimit.
    return POW_LIMIT_MAINNET


def _get_pow_limit_bits(network: str) -> int:
    """Return the compact nBits encoding of the pow_limit for the network."""
    if network == "signet":
        return POW_LIMIT_BITS_SIGNET
    if network in ("regtest",):
        return POW_LIMIT_BITS_REGTEST
    return POW_LIMIT_BITS_MAINNET


def permitted_difficulty_transition(
    network: str, height: int, old_bits: int, new_bits: int
) -> bool:
    """Check that a difficulty transition between two consecutive blocks is valid.

    Mirrors Bitcoin Core PermittedDifficultyTransition() (pow.cpp:89-136).

    Rules:
    * On networks with fPowAllowMinDifficultyBlocks (testnet/testnet4/regtest):
      always return True (any transition is permitted).
    * At a difficulty adjustment boundary (height % 2016 == 0): new_bits must
      be within the 4× / ¼× clamp of old_bits, after round-tripping through
      compact form (as Core does).
    * Otherwise: old_bits == new_bits required.

    Args:
        network:  Network name (mainnet, testnet, testnet3, testnet4, regtest,
                  signet).
        height:   Height of the *new* block being validated.
        old_bits: nBits of the previous block.
        new_bits: nBits of the new block.

    Returns:
        True if the transition is permitted.
    """
    # fPowAllowMinDifficultyBlocks: testnets allow any transition.
    # Ref: pow.cpp:91.
    if network in _POW_ALLOW_MIN_DIFFICULTY_NETWORKS:
        return True

    pow_limit = _get_pow_limit(network)

    if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
        smallest_timespan = POW_TARGET_TIMESPAN // 4
        largest_timespan = POW_TARGET_TIMESPAN * 4

        old_target = _bits_to_target(old_bits)
        observed_new_target = _bits_to_target(new_bits)

        # Calculate the largest difficulty value possible (easiest target).
        # Ref: pow.cpp:101-108.
        largest_difficulty_target = old_target * largest_timespan // POW_TARGET_TIMESPAN
        if largest_difficulty_target > pow_limit:
            largest_difficulty_target = pow_limit
        # Round-trip through compact form to match Core's comparison.
        # Ref: pow.cpp:113-115.
        maximum_new_target = _bits_to_target(_target_to_bits(largest_difficulty_target))
        if maximum_new_target < observed_new_target:
            return False

        # Calculate the smallest difficulty value possible (hardest target).
        # Ref: pow.cpp:117-124.
        smallest_difficulty_target = old_target * smallest_timespan // POW_TARGET_TIMESPAN
        if smallest_difficulty_target > pow_limit:
            smallest_difficulty_target = pow_limit
        # Round-trip through compact form.
        # Ref: pow.cpp:129-131.
        minimum_new_target = _bits_to_target(_target_to_bits(smallest_difficulty_target))
        if minimum_new_target > observed_new_target:
            return False
    else:
        # Non-adjustment block: bits must be unchanged.
        # Ref: pow.cpp:132-133.
        if old_bits != new_bits:
            return False

    return True


def _count_legacy_sigops(script: bytes, accurate: bool = False) -> int:
    """Count legacy signature operations in a script.

    When *accurate* is False (default), OP_CHECKMULTISIG always counts as 20
    sigops (matching Bitcoin Core ``GetSigOpCount(false)``).

    When *accurate* is True, OP_CHECKMULTISIG counts the actual number of
    public keys if preceded by an OP_1..OP_16 push (matching Bitcoin Core
    ``GetSigOpCount(true)``).  This is used for P2SH redeem scripts.
    """
    count = 0
    i = 0
    last_opcode = 0xFF  # OP_INVALIDOPCODE
    while i < len(script):
        op = script[i]
        if op in (0xAC, 0xAD):  # OP_CHECKSIG, OP_CHECKSIGVERIFY
            count += 1
        elif op in (0xAE, 0xAF):  # OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
            if accurate and 0x51 <= last_opcode <= 0x60:
                # OP_1 (0x51) .. OP_16 (0x60) — decode to 1..16
                count += last_opcode - 0x50
            else:
                count += 20
        elif 1 <= op <= 0x4B:
            i += op
        elif op == 0x4C:
            if i + 1 < len(script):
                i += 1 + script[i + 1]
            else:
                i += 1
        elif op == 0x4D:
            if i + 2 < len(script):
                i += 2 + int.from_bytes(script[i + 1 : i + 3], "little")
            else:
                i += 2
        elif op == 0x4E:
            if i + 4 < len(script):
                i += 4 + int.from_bytes(script[i + 1 : i + 5], "little")
            else:
                i += 4
        last_opcode = op
        i += 1
    return count


def _target_to_bits(target: int) -> int:
    if target == 0:
        return 0
    # Convert to bytes, big-endian, strip leading zeros
    target_bytes = target.to_bytes(32, "big").lstrip(b"\x00")
    size = len(target_bytes)
    if size <= 3:
        compact = int.from_bytes(target_bytes.ljust(3, b"\x00"), "big")
    else:
        compact = int.from_bytes(target_bytes[:3], "big")
    # If the sign bit (0x800000) is set, shift right and increase size
    # to avoid encoding a negative number.
    if compact & 0x800000:
        compact >>= 8
        size += 1
    return (size << 24) | compact


def _is_p2sh(script: bytes) -> bool:
    return (
        len(script) == 23
        and script[0] == 0xA9
        and script[1] == 0x14
        and script[22] == 0x87
    )


_MAX_COMPACT_SIZE = 0x02000000  # Bitcoin Core serialize.h MAX_SIZE


def _compact_size_len(n: int) -> int:
    """Byte length of the CompactSize encoding of *n* (the block tx-count prefix)."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def block_weight(transactions: list) -> int:
    """Block weight per Bitcoin Core consensus/validation.h::GetBlockWeight:
    GetSerializeSize(TX_NO_WITNESS(block)) * (WSF-1) + GetSerializeSize(TX_WITH_WITNESS(block)).
    This serializes the WHOLE block, which prepends an 80-byte header and a
    CompactSize transaction count to the transactions. Both are witness-free, so
    they appear in both serializations and count at the full WITNESS_SCALE_FACTOR:
    weight = (80 + compact_size_len(n)) * WSF + sum(per-tx weight). Summing only
    the per-tx weights under-counts by (80 + varint) * WSF (324 for a 1-byte
    varint, up to 332), which false-accepts a block whose true Core weight is in
    (MAX_BLOCK_WEIGHT, MAX_BLOCK_WEIGHT + that gap] -- Core rejects it as
    bad-blk-weight, so accepting it is a chain split.
    """
    n = len(transactions)
    weight = (80 + _compact_size_len(n)) * WITNESS_SCALE_FACTOR
    for tx in transactions:
        weight += tx.get_weight()
    return weight


def _read_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode CompactSize at *offset* in *data*; returns (value, bytes_consumed).

    Raises ValueError on truncated input, non-canonical encodings, or values
    exceeding MAX_SIZE (0x02000000) per Bitcoin Core serialize.h.
    """
    if offset >= len(data):
        raise ValueError("Truncated CompactSize: no data at offset")
    first = data[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        if offset + 3 > len(data):
            raise ValueError("Truncated CompactSize<u16>")
        value = int.from_bytes(data[offset + 1:offset + 3], "little")
        if value < 0xFD:
            raise ValueError(f"Non-canonical CompactSize: 0xfd prefix with value {value} < 0xfd")
        bytes_consumed = 3
    elif first == 0xFE:
        if offset + 5 > len(data):
            raise ValueError("Truncated CompactSize<u32>")
        value = int.from_bytes(data[offset + 1:offset + 5], "little")
        if value < 0x10000:
            raise ValueError(f"Non-canonical CompactSize: 0xfe prefix with value {value} < 0x10000")
        bytes_consumed = 5
    else:
        if offset + 9 > len(data):
            raise ValueError("Truncated CompactSize<u64>")
        value = int.from_bytes(data[offset + 1:offset + 9], "little")
        if value < 0x100000000:
            raise ValueError(f"Non-canonical CompactSize: 0xff prefix with value {value} < 0x100000000")
        bytes_consumed = 9
    if value > _MAX_COMPACT_SIZE:
        raise ValueError(f"CompactSize value {value} exceeds MAX_SIZE ({_MAX_COMPACT_SIZE})")
    return value, bytes_consumed


def _get_last_push(script_sig: bytes) -> bytes | None:
    """Extract the last data-push item from a push-only scriptSig."""
    last_push = None
    i = 0
    n = len(script_sig)
    while i < n:
        op = script_sig[i]
        i += 1
        if 1 <= op <= 0x4B:
            end = i + op
            if end > n:
                return None
            last_push = script_sig[i:end]
            i = end
        elif op == 0x4C:  # OP_PUSHDATA1
            if i >= n:
                return None
            length = script_sig[i]
            i += 1
            end = i + length
            if end > n:
                return None
            last_push = script_sig[i:end]
            i = end
        elif op == 0x4D:  # OP_PUSHDATA2
            if i + 2 > n:
                return None
            length = int.from_bytes(script_sig[i:i + 2], "little")
            i += 2
            end = i + length
            if end > n:
                return None
            last_push = script_sig[i:end]
            i = end
        elif op == 0x4E:  # OP_PUSHDATA4
            if i + 4 > n:
                return None
            length = int.from_bytes(script_sig[i:i + 4], "little")
            i += 4
            end = i + length
            if end > n:
                return None
            last_push = script_sig[i:end]
            i = end
        elif op == 0x00:  # OP_0
            last_push = b""
        elif 0x51 <= op <= 0x60:  # OP_1 .. OP_16
            last_push = bytes([op - 0x50])
        elif op == 0x4F:  # OP_1NEGATE
            last_push = b"\x81"
        else:
            # Non-push opcode — not push-only, stop
            return None
    return last_push


def _get_witness_version_and_program(script: bytes):
    if len(script) < 4 or len(script) > 42:
        return None
    version_op = script[0]
    if version_op == 0x00:
        version = 0
    elif 0x51 <= version_op <= 0x60:
        version = version_op - 0x50
    else:
        return None
    prog_len = script[1]
    if prog_len + 2 != len(script):
        return None
    if prog_len < 2 or prog_len > 40:
        return None
    return (version, script[2:])


def _count_witness_sigops(prev_script_pubkey: bytes, witness: list | None) -> int:
    wp = _get_witness_version_and_program(prev_script_pubkey)
    if wp is None:
        return 0
    version, program = wp
    if version == 0:
        if len(program) == 20:  # P2WPKH → always 1 sigop
            return 1
        if len(program) == 32:  # P2WSH → count from witness script
            if witness and len(witness) > 0:
                witness_script = witness[-1]
                # BIP141: witness scripts use accurate multisig counting
                # (matches Bitcoin Core WitnessSigOps: subscript.GetSigOpCount(true)
                # in script/interpreter.cpp).  Using inaccurate (default) counting
                # here over-counts P2WSH N-of-M multisigs as 20 each instead of N,
                # which can push valid blocks over MAX_BLOCK_SIGOPS_COST (80_000)
                # and cause spurious rejections (e.g. mainnet block 713465 with
                # raw cost 119681 after over-count vs. correct cost under 80000).
                return _count_legacy_sigops(witness_script, accurate=True)
    elif version == 1:
        # Taproot key-path: 1 sigop; script-path: counted via sigops budget
        # during execution, not here.  Bitcoin Core counts 0 at this level.
        return 0
    return 0


def _get_p2sh_sigops(script_sig: bytes, prev_script_pubkey: bytes) -> int:
    if not _is_p2sh(prev_script_pubkey):
        return 0
    redeem_script = _get_last_push(script_sig)
    if redeem_script is None:
        return 0
    # P2SH redeem scripts use accurate sigop counting (fAccurate=true in
    # Bitcoin Core), where multisig counts actual keys instead of 20.
    # Ref: Bitcoin Core script/script.cpp CScript::GetSigOpCount(const CScript&)
    return _count_legacy_sigops(redeem_script, accurate=True)


# ─────────────────────────────────────────────────────────────────────────────
# BIP-141 weight / vsize utilities
# References:
#   bitcoin-core/src/policy/policy.cpp:390-407
#   bitcoin-core/src/policy/policy.h:182-198
#   bitcoin-core/src/consensus/validation.h:132-144
# ─────────────────────────────────────────────────────────────────────────────

# DEFAULT_BYTES_PER_SIGOP (policy/policy.h:50): the sigop→byte exchange rate
# used when computing the sigop-adjusted vsize for mempool fee-rate checks.
# A tx with high sigop cost is treated as heavier than its raw byte weight.
DEFAULT_BYTES_PER_SIGOP = 20


def get_sigops_adjusted_weight(weight: int, sigop_cost: int, bytes_per_sigop: int = DEFAULT_BYTES_PER_SIGOP) -> int:
    """Return the sigop-adjusted weight unit count.

    Mirrors Bitcoin Core policy/policy.cpp GetSigOpsAdjustedWeight():
        return std::max(weight, sigop_cost * bytes_per_sigop);

    Args:
        weight: BIP-141 weight units (stripped_size * 3 + total_size).
        sigop_cost: BIP-141-weighted sigop cost of the transaction.
        bytes_per_sigop: Exchange rate, default DEFAULT_BYTES_PER_SIGOP (20).

    Returns:
        int: max(weight, sigop_cost * bytes_per_sigop).
    """
    return max(weight, sigop_cost * bytes_per_sigop)


def get_virtual_transaction_size(weight: int, sigop_cost: int = 0, bytes_per_sigop: int = DEFAULT_BYTES_PER_SIGOP) -> int:
    """Compute the virtual transaction size (vsize) in bytes.

    Mirrors Bitcoin Core policy/policy.cpp GetVirtualTransactionSize():
        return (GetSigOpsAdjustedWeight(weight, sigop_cost, bytes_per_sigop)
                + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;

    When sigop_cost=0 and bytes_per_sigop=0 (or default 20 with sigop_cost=0),
    this reduces to ceil(weight / 4) — the plain BIP-141 vsize.

    Args:
        weight: BIP-141 weight units.
        sigop_cost: BIP-141-weighted sigop cost (0 for consensus weight only).
        bytes_per_sigop: Exchange rate, default DEFAULT_BYTES_PER_SIGOP (20).

    Returns:
        int: ceil(sigop_adjusted_weight / WITNESS_SCALE_FACTOR).
    """
    adj = get_sigops_adjusted_weight(weight, sigop_cost, bytes_per_sigop)
    return (adj + WITNESS_SCALE_FACTOR - 1) // WITNESS_SCALE_FACTOR


class BlockValidator:
    """Validates new blocks"""

    def __init__(
        self,
        db: BlockchainDatabase,
        network: str = "mainnet",
        snapshot_manager: "SnapshotManager | None" = None,
    ):
        self.db = db
        self.network = network
        self.tx_validator = TransactionValidator(db, network, snapshot_manager=snapshot_manager)
        # Snapshot manager is consulted when prev_block lookup misses --
        # it lets the validator synthesize the snapshot tip's prev block
        # from the persisted 80-byte header so the FIRST block above the
        # snapshot tip can validate without requiring its prev block's
        # bytes (matching Core's `LookupBlockIndex(snap_hash)` flow,
        # which returns the in-memory CBlockIndex even when full block
        # bytes are pruned).  May be None for unit tests.
        self.snapshot_manager = snapshot_manager

    def _synthesize_snapshot_prev_block(
        self, prev_blockhash: bytes
    ) -> "Block | None":
        """Return a synthetic Block for ``prev_blockhash`` if it is the
        snapshot base tip, else ``None``.

        Reads the persisted ``base_blockheader`` (80 bytes, written at
        snapshot load time) and constructs a ``Block`` with empty
        ``transactions`` -- this is sufficient to satisfy the prev-block
        accesses in ``validate_block`` (only ``timestamp`` and ``bits``
        are read on mainnet, plus ``height`` which we derive from the
        snapshot manager's known tip).

        Returns ``None`` if:
        - no snapshot manager is wired (e.g. unit-test path)
        - no snapshot has been loaded
        - ``prev_blockhash`` doesn't match the snapshot base hash
        - the chainparams entry for this snapshot height has no
          ``base_header`` provisioned (testnet snapshots, for now)
        """
        sm = self.snapshot_manager
        if sm is None:
            return None
        try:
            snap_hash = sm.read_snapshot_base_blockhash()
        except Exception:
            return None
        if snap_hash is None or snap_hash != prev_blockhash:
            return None
        try:
            header = sm.read_snapshot_base_blockheader()
        except Exception:
            return None
        if header is None or len(header) != 80:
            return None
        # Parse the 80-byte header and build a synthetic Block. The
        # ``transactions`` list is empty because the snapshot wire format
        # does not carry the tip block's tx data; the validator never
        # touches it for a prev block (we only read .timestamp / .bits /
        # .height / .prev_blockhash).
        version = int.from_bytes(header[0:4], "little", signed=True)
        prev_prev = header[4:36]
        merkle_root = header[36:68]
        timestamp = int.from_bytes(header[68:72], "little")
        bits = int.from_bytes(header[72:76], "little")
        nonce = int.from_bytes(header[76:80], "little")
        # Verify the header round-trips to ``prev_blockhash`` -- defends
        # against an on-disk header that doesn't match the stored hash
        # (e.g. corrupted file, mismatched chainparams).
        recomputed = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        if recomputed != prev_blockhash:
            logger.warning(
                "[snapshot-prev] base_blockheader hashes to "
                f"{recomputed[::-1].hex()}, expected "
                f"{prev_blockhash[::-1].hex()} -- ignoring"
            )
            return None
        # Snapshot tip height comes from the manager's metadata; if it is
        # unset (e.g. process just restarted and load_snapshot hasn't
        # been re-driven), derive from the database tip -- which is the
        # snapshot tip itself when no blocks have been connected yet.
        snap_height = sm.snapshot_height
        if snap_height is None:
            try:
                _, snap_height = self.db.get_best_block()
            except Exception:
                snap_height = None
        return Block(
            version=version,
            prev_blockhash=prev_prev,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
            transactions=[],
            hash=prev_blockhash,
            height=snap_height,
        )

    def _snapshot_base_blockheader_ts(self) -> int | None:
        """Timestamp of the assumeUTXO snapshot base block, or None.

        Reads the persisted 80-byte base header (bytes [68:72] little-endian)
        when present; falls back to the hardcoded chainparams
        ``AssumeutxoData.base_header`` resolved via the on-disk
        ``base_blockhash``.  The result is the snapshot base block's own
        ``time`` field, which is the conservative upper bound used as the
        MTP proxy for the heights immediately above the snapshot (see
        ``_snapshot_base_mtp_fallback``).
        """
        sm = self.snapshot_manager
        if sm is None:
            return None
        # Preferred source: the persisted 80-byte header sibling file.
        try:
            header = sm.read_snapshot_base_blockheader()
        except Exception:
            header = None
        if header is not None and len(header) == 80:
            ts = int.from_bytes(header[68:72], "little")
            if ts > 0:
                return ts
        # Fallback source: hardcoded chainparams base_header (resolved by
        # the on-disk base_blockhash via the assumeUTXO table).  Needed when
        # the snapshot was loaded by an older build that did not persist the
        # header sibling file but the chainparams entry carries base_header.
        try:
            base_hash = sm.read_snapshot_base_blockhash()
        except Exception:
            base_hash = None
        if not base_hash:
            return None
        try:
            from ouroboros.snapshot import get_assumeutxo_by_hash
            au = get_assumeutxo_by_hash(self.network, base_hash)
        except Exception:
            au = None
        if au is None or getattr(au, "base_header", None) is None:
            return None
        bh = au.base_header
        if bh is None or len(bh) != 80:
            return None
        ts = int.from_bytes(bh[68:72], "little")
        return ts if ts > 0 else None

    def _resolve_snapshot_height(self) -> int | None:
        """Height of the assumeUTXO snapshot base block, or None.

        Mirrors the height resolution already used by
        ``_synthesize_snapshot_prev_block`` (which trusts
        ``SnapshotManager.snapshot_height`` and falls back to the DB best
        block when the manager's in-memory field is unset -- e.g. the
        process restarted and ``load_snapshot`` has not been re-driven, in
        which case the DB tip IS the snapshot base until the first
        post-snapshot block connects).

        This helper was referenced by ``_snapshot_base_mtp_fallback`` (the
        broadened MTP-window band) but never defined, so every attempt to
        connect the first block above the snapshot (mainnet 944184) raised
        ``AttributeError`` inside ``validate_block`` and the block was
        dropped -- wedging forward-sync at the snapshot base (944183).
        """
        sm = self.snapshot_manager
        if sm is None:
            return None
        snap_height = getattr(sm, "snapshot_height", None)
        if isinstance(snap_height, int) and snap_height > 0:
            return snap_height
        # Manager field unset (post-restart, pre-reload): the DB tip is the
        # snapshot base until the first post-snapshot block connects.
        try:
            _, tip_height = self.db.get_best_block()
        except Exception:
            return None
        if isinstance(tip_height, int) and tip_height > 0:
            return tip_height
        return None

    def _snapshot_base_mtp_fallback(
        self, prev_block: "Block", expected_height: int
    ) -> int | None:
        """MTP fallback for the first blocks above an assumeUTXO snapshot.

        ``get_median_time_past`` returns None when the 11-block window dips
        below the snapshot base (those pre-snapshot blocks were never
        downloaded).  In that case Bitcoin Core would still have the real
        MTP because it ships the full header chain back to genesis (headers
        are tiny and synced before the snapshot load); ouroboros only
        persists the single base header.  We approximate the prev block's
        MTP with the snapshot base block's own timestamp, which is a tight
        upper bound on the real MTP (the median of the 11 headers ending at
        any height ``<= base`` is ``<=`` the base header's own time, because
        Bitcoin block times are very close together near the tip and the
        base time dominates a window mostly below it).  This keeps
        genuinely-final time-locked transactions final (matching Core's
        accept) and is consistent with the assumeUTXO trust model: the
        snapshot block and everything below it is assumed-valid until
        background validation backfills.

        The window for ``prev_height`` is incomplete-below-base whenever
        ``prev_height - 10 < base_height`` -- i.e. for ``prev_height`` in
        ``[base_height .. base_height + 10]``, which is block heights
        ``[base+1 .. base+11]`` (mainnet 944184..944194 for the 944183
        snapshot).  The earlier narrow fix only fired when ``prev`` WAS the
        base (height base+1 only), which advanced past 944184 but then
        stalled at 944185: heights 944185..944194 still have windows that
        reach below 944183 (944173..944183 have no per-height index
        metadata), so ``get_median_time_past`` still returned None -> 0 ->
        ``bad-txns-nonfinal`` on the next time-locked tx.  We now fire for
        the whole ``[base+1 .. base+11]`` band; once enough real
        post-base blocks connect the window completes on its own,
        ``get_median_time_past`` returns a real value, and this path is
        never taken.

        Returns the base block timestamp when ``prev_height`` falls in the
        incomplete-window band above the snapshot base, else None (the
        caller then falls back to 0 -- the historical behaviour for any
        other incomplete-window cause).
        """
        sm = self.snapshot_manager
        if sm is None:
            return None

        base_height = self._resolve_snapshot_height()
        if base_height is None:
            return None

        # Determine prev_height.  Prefer the height carried on the prev block
        # (the synthetic snapshot-base prev block sets it; real connected
        # blocks carry it too); fall back to expected_height - 1.
        prev_height = getattr(prev_block, "height", None)
        if not isinstance(prev_height, int):
            prev_height = expected_height - 1

        # Only fire inside the incomplete-window band above the snapshot
        # base: prev_height in [base .. base+10].  Below the base we have no
        # business validating (assume-valid region); above base+10 the
        # 11-block window [prev-10 .. prev] is fully populated by real
        # post-base blocks, so get_median_time_past returns a real value and
        # this fallback must not mask it.
        if prev_height < base_height or prev_height > base_height + 10:
            return None

        base_ts = self._snapshot_base_blockheader_ts()
        # When prev IS the base and we couldn't read the header timestamp,
        # the synthetic prev block's own timestamp is the base timestamp.
        if base_ts is None and prev_height == base_height:
            prev_ts = getattr(prev_block, "timestamp", None)
            if isinstance(prev_ts, int) and prev_ts > 0:
                base_ts = prev_ts
        if base_ts is None or base_ts <= 0:
            return None

        logger.info(
            "[snapshot-mtp] MTP window for height %d incomplete below "
            "snapshot base %d; using base block timestamp %d as "
            "nLockTimeCutoff MTP (assumeUTXO fallback)",
            prev_height,
            base_height,
            base_ts,
        )
        return base_ts

    def validate_block(
        self,
        block: Block,
        known_height: int = 0,
        skip_pow: bool = False,
        force_check_scripts: bool = False,
        current_time: int = 0,
    ) -> tuple[bool, str]:
        """Fully validate *block* (header, merkle root, weight, scripts); returns ``(ok, error_message)``.

        *known_height*: if >0, use this as the block's height instead of
        deriving it from the previous block in the DB.  This avoids
        incorrect height=1 when the DB doesn't store height on Block objects.

        *skip_pow*: when True, skip ONLY the proof-of-work hash<=target gate in
        the header check (every other header rule — bad-diffbits, time-too-old,
        time-too-new, bad-version, the nBits range/overflow decode — still
        runs).  This is a faithful parity with Bitcoin Core's
        ``CheckBlock(..., fCheckPOW)`` / ``CheckBlockHeader(..., fCheckPOW)``
        gate (validation.cpp: CheckBlockHeader takes ``fCheckPOW`` and only
        calls ``CheckProofOfWork`` when it is true; ConnectBlock revalidation of
        an already-PoW-checked block passes ``fCheckPOW=false``).  Default
        False preserves the current production behaviour (PoW always checked).

        *force_check_scripts*: when True, override the assume-valid /
        checkpoint script-skip heuristic and ALWAYS run full script
        verification regardless of height.  Default False preserves the current
        production behaviour (script skip governed by
        ``sync.can_skip_scripts_for_block``).  Used by the differential
        validate-only checkblock harness so a dead script-gate cannot mask a
        consensus divergence below the assume-valid cut.

        *current_time*: when > 0, use this Unix timestamp as the "now" the
        time-too-new gate compares against, instead of the wall-clock
        ``time.time()``.  Default 0 (the sentinel) preserves the current
        production behaviour BYTE-FOR-BYTE — the wall clock is read exactly as
        before.  This is a faithful parity with Bitcoin Core's
        ``NodeClock::now()`` (validation.cpp:4108), which is the system clock in
        production but is injectable/mockable in Core's tests
        (``SetMockTime``).  Used by the differential header-level reject harness
        so the time-too-new boundary (``> now + MAX_FUTURE_BLOCK_TIME``) can be
        probed deterministically without depending on the test machine's clock.
        """
        # 1. Get previous block.
        #
        # If the prev block is the snapshot base tip, BLOCKS_CF has no
        # entry for it (the snapshot wire format doesn't carry block
        # bytes -- only the UTXO set + base_blockhash).  Fall back to a
        # synthetic prev block reconstructed from the 80-byte header
        # persisted at snapshot load.  This mirrors Bitcoin Core's
        # `LookupBlockIndex(snap_hash)` returning the in-memory
        # CBlockIndex from the header sync that runs before snapshot
        # load -- the full block bytes are not required for the
        # prev-link header check.
        prev_block = self.db.get_block(block.prev_blockhash)
        if not prev_block:
            prev_block = self._synthesize_snapshot_prev_block(block.prev_blockhash)
        if not prev_block:
            return False, "Previous block not found"

        # Calculate expected height
        if known_height > 0:
            expected_height = known_height
        else:
            prev_height = prev_block.height
            if prev_height is None:
                # Fall back to the chain tip height (best effort)
                _, tip_height = self.db.get_best_block()
                prev_height = tip_height
            expected_height = (prev_height or 0) + 1

        # 2. Compute median-time-past (needed for header validation and BIP 68)
        #
        # ``get_median_time_past`` returns None when the 11-block window
        # [h-10 .. h] is incomplete.  After an assumeUTXO snapshot load that
        # is exactly the situation for the FIRST block above the snapshot:
        # only the snapshot base block (h=snap) is in the index; the 10
        # blocks below it were never downloaded, so the window for h=snap is
        # incomplete and MTP comes back None -> 0.
        #
        # MTP == 0 is catastrophic for the nLockTimeCutoff finality check: a
        # transaction with a time-based nLockTime (>= LOCKTIME_THRESHOLD) is
        # final iff its locktime < MTP.  With MTP == 0 every such tx looks
        # non-final, so the first post-snapshot block that carries a
        # time-locked tx (mainnet 944184 carries two — locktimes 538446226
        # and 500196371) is rejected forever with "bad-txns-nonfinal",
        # wedging IBD one block above the snapshot.
        #
        # Bitcoin Core never hits this because its assumeUTXO snapshot ships
        # with the full header chain back to genesis (headers are tiny and
        # synced before the snapshot load), so its 11-header MTP window is
        # always complete.  ouroboros only persists the single base header,
        # so we approximate: when the window dips below the snapshot base and
        # the prev block IS that base, use the base block's own timestamp as
        # the MTP fallback.  The base block's timestamp is a tight upper
        # bound on the real MTP (real MTP = median of the 11 headers ending
        # at the base, which is <= the base header's own time), so it keeps
        # genuinely-final time-locked txs final (matching Core's accept) and
        # is consistent with the assumeUTXO trust model: the snapshot block
        # and everything below it is assumed-valid until background
        # validation backfills.  Cross-checked against Core: at h=944183 the
        # real MTP is 1775650208 and the base timestamp is 1775651930 (gap
        # 1722s); both time-locked txs in 944184 are final under either, and
        # zero txs sit in the [realMTP, baseTime) over-accept window.
        block_mtp = self.db.get_median_time_past(expected_height - 1)
        if block_mtp is None:
            block_mtp = self._snapshot_base_mtp_fallback(prev_block, expected_height) or 0

        # 2b. Compute nLockTimeCutoff per Bitcoin Core validation.cpp:4135-4142.
        #
        # Before CSV (BIP-113) activation Core uses block.GetBlockTime() as the
        # time comparison value in IsFinalTx().  After CSV activation it uses the
        # median-time-past (MTP) of the previous block.
        #
        # Ref: Bitcoin Core validation.cpp:4135-4142
        #   if (DeploymentActiveAfter(pindexPrev, Consensus::DEPLOYMENT_CSV))
        #       enforce_locktime_median_time_past = true;
        #   nLockTimeCutoff = enforce_locktime_median_time_past
        #       ? pindexPrev->GetMedianTimePast()
        #       : block.GetBlockTime();
        csv_active = is_buried_deployment_active("csv", expected_height, self.network)
        nLockTimeCutoff: int = block_mtp if csv_active else block.timestamp

        # 3. Validate header (including difficulty retarget)
        if not self._validate_header(
            block, prev_block, block_mtp, expected_height, skip_pow=skip_pow,
            current_time=current_time,
        ):
            return False, "Invalid header"

        # 4. Verify merkle root
        if not self._verify_merkle_root(block):
            return False, "Invalid merkle root"

        # 5. Validate block weight and sigops limits
        valid, error = self._validate_block_limits(block)
        if not valid:
            return False, error

        # 6. Validate witness commitment (SegWit)
        valid, error = self._validate_witness_commitment(block, expected_height)
        if not valid:
            return False, error

        # 6b. Validate signet block signature (BIP 325, signet only)
        valid, error = self._validate_signet_solution(block, expected_height)
        if not valid:
            return False, error

        # 7. BIP30: reject duplicate txids against unspent outputs.
        #
        # Reference: Bitcoin Core validation.cpp:2392-2476 (ConnectBlock).
        #
        # Gate A — IsBIP30Repeat (validation.cpp:6189-6193):
        #   Two historical mainnet blocks (91842 and 91880) are exempted from
        #   the BIP30 check because they ARE the duplicate coinbase blocks.
        #   The exemption is keyed by BOTH height AND block hash — a fork at
        #   the same height does NOT receive the exception.
        #
        # Gate B — BIP34 suppresses BIP30 for the canonical chain:
        #   Once BIP34 is active and the block at the BIP34 activation height
        #   matches the canonical hash, coinbase uniqueness is guaranteed by
        #   construction, so the UTXO-collision scan can be skipped.
        #   Verified via: pindexBIP34height->GetBlockHash() == BIP34Hash.
        #   For testnet4/signet/regtest BIP34Hash is all-zeros, which can never
        #   match a real block hash, so BIP30 is always enforced on those nets.
        #   (validation.cpp:2459-2462)
        #
        # Gate C — BIP34_IMPLIES_BIP30_LIMIT (1,983,702):
        #   Above this height, even if BIP34 suppressed BIP30 earlier, we must
        #   re-enable BIP30 because pre-BIP34 coinbases exist with indicated
        #   heights that reach this far.  (validation.cpp:2430, 2467)
        #
        # Error code matches Core: "bad-txns-BIP30" (validation.cpp:2471).

        _BIP30_RECHECK_HEIGHT = 1_983_702

        # Gate A: IsBIP30Repeat — must match both height and hash.
        block_hash_bytes = (
            block.hash if isinstance(block.hash, bytes) else bytes.fromhex(block.hash)
        )
        repeat_hash = BIP30_REPEAT_EXCEPTIONS.get(expected_height)
        enforce_bip30 = (repeat_hash is None) or (block_hash_bytes != repeat_hash)

        # Gate B: BIP34 suppresses BIP30 if we are on the canonical chain.
        if enforce_bip30:
            bip34_dep = BURIED_DEPLOYMENTS.get(self.network, {}).get("bip34")
            bip34_height = bip34_dep.height if bip34_dep is not None else 227_931
            bip34_canon_hash = BIP34_HASHES.get(self.network, bytes(32))
            # We can skip BIP30 only when:
            #   (a) we are at or above the BIP34 activation height, AND
            #   (b) the block stored at BIP34Height has the canonical hash.
            # Condition (b) is approximated here by checking whether our
            # ancestor's hash record matches — the database callback
            # db.get_block_hash_at_height provides this lookup.
            # If the DB cannot supply the hash, we conservatively keep BIP30.
            if expected_height >= bip34_height:
                ancestor_hash: bytes | None = None
                if hasattr(self.db, "get_block_hash_at_height"):
                    try:
                        ancestor_hash = self.db.get_block_hash_at_height(bip34_height)
                    except Exception:
                        ancestor_hash = None
                # Only suppress BIP30 when the canonical hash is non-zero AND
                # the stored ancestor hash matches it.
                if (
                    bip34_canon_hash != bytes(32)
                    and ancestor_hash is not None
                    and ancestor_hash == bip34_canon_hash
                ):
                    enforce_bip30 = False

        # Gate C: always re-enable BIP30 at height >= 1,983,702.
        if expected_height >= _BIP30_RECHECK_HEIGHT:
            enforce_bip30 = True

        if enforce_bip30:
            for tx in block.transactions:
                txid = tx.get_txid()
                for vout_idx in range(len(tx.outputs)):
                    if self.db.get_utxo(txid, vout_idx) is not None:
                        return False, "bad-txns-BIP30"

        # 8. Validate coinbase position and uniqueness
        if not block.transactions:
            return False, "Block has no transactions"
        if not block.transactions[0].is_coinbase:
            return False, "First transaction must be coinbase"
        for i, tx in enumerate(block.transactions[1:], 1):
            if tx.is_coinbase:
                return False, f"Transaction {i} is an unexpected coinbase"

        # Determine if script validation can be skipped (assume-valid).
        # During IBD, blocks below the last checkpoint have their PoW and
        # merkle root already verified above — script verification is the
        # dominant cost and can be safely skipped.
        skip_scripts = False
        if force_check_scripts:
            # Differential validate-only harness: never skip scripts, regardless
            # of the assume-valid / checkpoint cut, so the script gate is live.
            skip_scripts = False
        elif _has_sync_module:
            try:
                block_hash_bytes = block.hash if isinstance(block.hash, bytes) else bytes.fromhex(block.hash)
                skip_scripts = _sync_module.can_skip_scripts_for_block(
                    self.network, expected_height, block_hash_bytes
                )
                if skip_scripts and expected_height % 10000 == 0:
                    logger.info(
                        f"Assume-valid: skipping script verification at height {expected_height}"
                    )
            except Exception:
                skip_scripts = False

        # 9. Validate all transactions.
        # Build a temporary view of outputs created by earlier txs in this
        # block so that intra-block dependencies (tx N spending tx M's
        # output where M < N) can be resolved.
        intra_block_utxos: dict[tuple[bytes, int], dict] = {}
        total_fees = 0
        for i, tx in enumerate(block.transactions):
            # IsFinalTx check applies to ALL transactions including coinbase.
            # Ref: Bitcoin Core validation.cpp:4144-4148 — iterates block.vtx
            # (all txs) with nLockTimeCutoff, not just non-coinbase.
            if not self.tx_validator._is_final_tx(tx, expected_height, nLockTimeCutoff):
                return False, "bad-txns-nonfinal"

            if i == 0:  # Coinbase
                if not self._validate_coinbase(tx, expected_height):
                    return False, "Invalid coinbase"
            else:
                # Capture the fee from validate_transaction directly to avoid
                # re-fetching every input UTXO in _calculate_tx_fee (was doing
                # ~6000 extra individual FFI calls per block at height 800k).
                tx_fees: list[int] = []
                valid, error = self.tx_validator.validate_transaction(
                    tx, expected_height, nLockTimeCutoff,
                    block_hash=block.hash,
                    intra_block_utxos=intra_block_utxos,
                    skip_scripts=skip_scripts,
                    fees_out=tx_fees,
                )
                if not valid:
                    return False, f"Transaction {i} invalid: {error}"
                total_fees += tx_fees[0] if tx_fees else 0
                # Accumulated block fee must stay in MoneyRange.
                # Ref: Bitcoin Core validation.cpp:2543-2547
                #   ("bad-txns-accumulated-fee-outofrange")
                if total_fees < 0 or total_fees > MAX_MONEY:
                    return False, "bad-txns-accumulated-fee-outofrange"

            # Register this tx's outputs in the intra-block view for
            # subsequent transactions.
            txid = tx.get_txid()
            for vout_idx, out in enumerate(tx.outputs):
                intra_block_utxos[(txid, vout_idx)] = {
                    'txid': txid,
                    'vout': vout_idx,
                    'value': out.value,
                    'script_pubkey': out.script_pubkey,
                    'height': expected_height,
                    'is_coinbase': (i == 0),
                }

        # 8. Verify coinbase amount
        if not self._verify_coinbase_amount(
            block.transactions[0],
            expected_height,
            total_fees
        ):
            return False, "Coinbase amount invalid"

        return True, ""

    def apply_block(self, block: Block) -> None:
        """Apply *block*'s UTXO effects to the database (spend inputs, create outputs).

        DEAD-CODE PATH (W23 belt-and-suspenders).

        In production, every IBD / orphan / reorg call site in
        ``block_sync.py`` reaches the database through the Rust FFI
        ``connect_block_from_bytes`` (defined unconditionally on
        ``BlockchainDatabase``); the ``else`` branches that call this
        method only fire if the Rust extension is missing, which is
        not a supported configuration. The method itself is also
        broken downstream — ``self.db.update_utxo_set`` does not exist
        on ``BlockchainDatabase`` and would raise ``AttributeError``
        before any UTXO write — so even a hypothetical activation
        would crash before mutating the chainstate.

        We keep the method (rather than deleting it) because the
        unconditional call site at ``_process_orphans`` (block_sync.py)
        is structurally reachable, and removing it without rewriting
        that handler is out of scope for this wave.

        BIP-30 / Core ``ConnectBlock`` (validation.cpp:2337-2343)
        special-cases the genesis block: its coinbase outputs are
        intentionally excluded from the UTXO set. Add a defensive
        early-return so that if this path is ever revived, it cannot
        accidentally insert genesis coinbase outputs into the
        chainstate (which would corrupt UTXO-set hashes and break
        consensus with Core).
        """
        # Genesis special-case (Core validation.cpp:2337-2343): the
        # genesis coinbase is unspendable and not added to the UTXO
        # set. Match that behavior here as belt-and-suspenders.
        height = getattr(block, "height", None)
        if height == 0:
            return

        spent = []
        created = []

        # Collect spent and created UTXOs
        for tx in block.transactions:
            # Spent outputs (except coinbase)
            if not tx.is_coinbase:
                for tx_in in tx.inputs:
                    spent.append((tx_in.prev_txid, tx_in.prev_vout))

            # Created outputs
            for i, tx_out in enumerate(tx.outputs):
                created.append({
                    'txid': tx.get_txid(),
                    'vout': i,
                    'value': tx_out.value,
                    'script_pubkey': tx_out.script_pubkey,
                })

        # Atomic update
        self.db.update_utxo_set(spent, created)
        # Note: Blocks are stored via the Rust API during sync (FastSync/BlockSync).
        # The Python store_block() method is not implemented because it requires
        # reconstructing the Rust BlockWrapper, which is complex. Blocks are
        # automatically stored when syncing via the Rust layer.

    def _validate_header(
        self,
        block: Block,
        prev_block: Block,
        block_mtp: int = 0,
        height: int = 0,
        skip_pow: bool = False,
        current_time: int = 0,
    ) -> bool:
        """Validate block header contextually (ContextualCheckBlockHeader analog).

        Gates (mirrors Bitcoin Core validation.cpp:4080-4121):

        1. bad-diffbits    — block.bits must equal GetNextWorkRequired().
                             Ref: validation.cpp:4088-4089.
        2. time-too-old    — block.timestamp must be strictly greater than MTP of
                             the previous 11 blocks.
                             Ref: validation.cpp:4092-4093, chain.h:233-245.
        3. time-timewarp-attack — on testnet4 (enforce_BIP94=true), at each
                             difficulty adjustment boundary the block timestamp
                             must not precede the previous block by > MAX_TIMEWARP.
                             Ref: validation.cpp:4097-4105, consensus/consensus.h:35.
        4. time-too-new    — block.timestamp must not exceed now + MAX_FUTURE_BLOCK_TIME.
                             Ref: validation.cpp:4108-4110, chain.h:29.
        5. bad-version     — version < 2 after BIP34, < 3 after BIP66 (DERSIG),
                             < 4 after BIP65 (CLTV).
                             Ref: validation.cpp:4113-4118.
        """
        # 1. bad-diffbits: block.bits must match GetNextWorkRequired.
        # Check bits is non-zero (cheaply filter obviously invalid before the
        # more expensive _get_expected_bits call).
        if block.bits == 0:
            return False

        # Verify difficulty retarget — block.bits must match expected value.
        # Ref: validation.cpp:4088-4089 ("bad-diffbits").
        if height > 0:
            expected_bits = self._get_expected_bits(height, prev_block, block)
            if expected_bits is not None and block.bits != expected_bits:
                return False

        # 2. time-too-old: timestamp must strictly exceed MTP of previous 11 blocks.
        # Guard on height > 0: genesis (height 0) has no pindexPrev in Core,
        # so the check is never reached for genesis.
        # Bug-fix: was `block_mtp > 0` which incorrectly skips the check when
        # MTP is legitimately 0.  Use `height > 0` (structural), not a runtime
        # value guard.
        # Ref: validation.cpp:4092-4093, chain.h:233-245.
        if height > 0 and block.timestamp <= block_mtp:
            return False

        # 3. time-timewarp-attack: BIP94 (testnet4 enforce_BIP94=true).
        # At difficulty adjustment boundaries the block timestamp must not
        # precede the previous block's timestamp by more than MAX_TIMEWARP (600s).
        # Ref: validation.cpp:4097-4105, consensus/consensus.h:35.
        if self.network == "testnet4" and height > 0:
            if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
                if block.timestamp < prev_block.timestamp - MAX_TIMEWARP:
                    return False

        # 4. time-too-new: block timestamp must not exceed now + MAX_FUTURE_BLOCK_TIME.
        # Ref: validation.cpp:4108-4110, chain.h:29 (MAX_FUTURE_BLOCK_TIME = 7200s).
        # Core compares against NodeClock::now() (the wall clock in production,
        # but injectable via SetMockTime in tests). The *current_time* parameter
        # mirrors that: when > 0 it overrides the wall clock for deterministic
        # testing; the default sentinel 0 reads time.time() exactly as before,
        # so production behaviour is byte-identical (default-preserving).
        now = current_time if current_time > 0 else int(_time.time())
        if block.timestamp > now + MAX_FUTURE_BLOCK_TIME:
            return False

        # 5. bad-version: reject blocks with outdated version numbers once the
        # corresponding soft fork has activated.
        #   - version < 2 after BIP34 (DEPLOYMENT_HEIGHTINCB) activation
        #   - version < 3 after BIP66 (DEPLOYMENT_DERSIG) activation
        #   - version < 4 after BIP65 (DEPLOYMENT_CLTV) activation
        # Ref: validation.cpp:4113-4118.
        if height > 0:
            if (block.version < 2 and
                    is_buried_deployment_active("bip34", height, self.network)):
                return False
            if (block.version < 3 and
                    is_buried_deployment_active("bip66", height, self.network)):
                return False
            if (block.version < 4 and
                    is_buried_deployment_active("bip65", height, self.network)):
                return False

        # Check version is not negative or zero (minimum sanity check).
        if block.version < 1:
            return False

        # Proof-of-work: block hash must meet difficulty target.
        # Mirrors Bitcoin Core pow.cpp::CheckProofOfWorkImpl / DeriveTarget:
        #   1. Decode nBits; reject if negative, overflow, zero, or > powLimit.
        #   2. Hash must be <= target.
        # Ref: Bitcoin Core pow.cpp:146-170.
        target, is_negative, is_overflow = _bits_to_target_checked(block.bits)
        pow_limit = _get_pow_limit(self.network)
        if is_negative or is_overflow or target == 0 or target > pow_limit:
            return False

        # The hash<=target comparison is the actual proof-of-work gate. Bitcoin
        # Core threads an fCheckPOW flag through CheckBlockHeader and only calls
        # CheckProofOfWork when it is true (validation.cpp CheckBlockHeader;
        # ConnectBlock revalidation passes fCheckPOW=false). skip_pow mirrors
        # fCheckPOW=false: the nBits range/overflow decode above still runs (so a
        # malformed-bits block is still rejected), only the hash comparison is
        # skipped. Default skip_pow=False keeps PoW always checked in production.
        if not skip_pow:
            header = block.serialize()[:80]
            block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
            hash_as_int = int.from_bytes(block_hash, "little")
            if hash_as_int > target:
                return False

        return True

    def _get_expected_bits(
        self, height: int, prev_block: Block, block: Block
    ) -> int | None:
        """Calculate expected nBits for a block at *height*.

        Mirrors Bitcoin Core GetNextWorkRequired() + CalculateNextWorkRequired()
        in pow.cpp.

        Args:
            height:     Height of the block being validated (the new block).
            prev_block: The block at height-1 (pindexLast in Core).
            block:      The block being validated (only timestamp used).

        Returns:
            Expected nBits, or None if the ancestor block needed for the
            calculation is unavailable (cannot verify at this time).
        """
        # fPowNoRetargeting: regtest always stays at the minimum difficulty.
        # Ref: Bitcoin Core pow.cpp:52-53.
        if self.network == "regtest":
            return 0x207fffff

        # Per-network pow_limit in compact bits form.
        pow_limit_bits = _get_pow_limit_bits(self.network)

        # Non-retarget block (height is not a multiple of 2016).
        # Ref: Bitcoin Core pow.cpp:20-38.
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0:
            # fPowAllowMinDifficultyBlocks: testnet / testnet4 min-difficulty
            # exception.  If the new block's timestamp is more than 2×
            # target-spacing (20 minutes) after the previous block, the block
            # MUST use the minimum difficulty (pow_limit).
            # Signet does NOT have this exception (fPowAllowMinDifficultyBlocks
            # is false on signet — Bitcoin Core chainparams.cpp:463).
            # Ref: Bitcoin Core pow.cpp:22-36.
            if self.network in _POW_ALLOW_MIN_DIFFICULTY_NETWORKS:
                if block.timestamp > prev_block.timestamp + POW_TARGET_SPACING * 2:
                    return pow_limit_bits
                # Otherwise walk back to find last non-min-difficulty block.
                # Walk stops at: height 0, a retarget boundary, or a block
                # with real difficulty.
                # Ref: Bitcoin Core pow.cpp:31-36.
                walk_height = height - 1
                pindex = prev_block
                while (
                    pindex
                    and walk_height > 0
                    and walk_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
                    and pindex.bits == pow_limit_bits
                ):
                    pindex = self.db.get_block(pindex.prev_blockhash)
                    walk_height -= 1
                if pindex:
                    return pindex.bits
                return prev_block.bits
            # All other networks (mainnet, signet): return previous block's bits.
            return prev_block.bits

        # Difficulty adjustment boundary (height % 2016 == 0).
        # Go back by DifficultyAdjustmentInterval - 1 blocks from pindexLast
        # (= the previous block, at height-1).
        # nHeightFirst = pindexLast->nHeight - (DifficultyAdjustmentInterval()-1)
        #              = (height-1) - (2016-1)
        #              = height - 2016
        # Ref: Bitcoin Core pow.cpp:42-47.
        first_height = height - DIFFICULTY_ADJUSTMENT_INTERVAL
        first_block = self.db.get_block_by_height(first_height)
        if first_block is None:
            return None  # cannot verify — missing ancestor

        actual_timespan = prev_block.timestamp - first_block.timestamp

        # Clamp to [targetTimespan/4 .. targetTimespan*4]
        # Ref: Bitcoin Core pow.cpp:57-60.
        if actual_timespan < POW_TARGET_TIMESPAN // 4:
            actual_timespan = POW_TARGET_TIMESPAN // 4
        if actual_timespan > POW_TARGET_TIMESPAN * 4:
            actual_timespan = POW_TARGET_TIMESPAN * 4

        # BIP94 (testnet4): use nBits from the FIRST block of the current
        # difficulty period as the base, not the last block's nBits.
        # The first block cannot use the min-difficulty exception, so this
        # preserves the real difficulty and blocks the time-warp attack.
        # nHeightFirst here matches the outer lookup above:
        #   pindexLast->nHeight - (DifficultyAdjustmentInterval()-1)
        #   = (height-1) - 2015 = height - 2016 = first_height
        # Ref: Bitcoin Core pow.cpp:67-76 (enforce_BIP94 branch).
        if self.network == "testnet4":
            period_start_block = self.db.get_block_by_height(first_height)
            if period_start_block is None:
                return None
            old_target = _bits_to_target(period_start_block.bits)
        else:
            old_target = _bits_to_target(prev_block.bits)
        new_target = old_target * actual_timespan // POW_TARGET_TIMESPAN

        # Clamp to network-specific proof-of-work limit.
        # Ref: Bitcoin Core pow.cpp:81-82.
        pow_limit = _get_pow_limit(self.network)
        if new_target > pow_limit:
            new_target = pow_limit

        return _target_to_bits(new_target)

    def _verify_merkle_root(self, block: Block) -> bool:
        txids = [tx.get_txid() for tx in block.transactions]
        root, mutated = self._calculate_merkle_root_checked(txids)
        if mutated:
            return False
        valid = root == block.merkle_root
        return valid

    def _calculate_merkle_root_checked(
        self, txids: list[bytes]
    ) -> tuple:
        """Calculate merkle root and detect malleation."""
        if not txids:
            return bytes(32), False

        if len(txids) == 1:
            return txids[0], False

        mutated = False
        level = list(txids)

        # Check for duplicate txids at the leaf level
        seen = set()
        for t in level:
            key = bytes(t)
            if key in seen:
                mutated = True
                break
            seen.add(key)

        while len(level) > 1:
            next_level = []

            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = level[i] + level[i + 1]
                else:
                    # Odd count: duplicate the last element — flag mutation
                    # if the last two are already identical.
                    combined = level[i] + level[i]

                hash1 = hashlib.sha256(combined).digest()
                hash2 = hashlib.sha256(hash1).digest()
                next_level.append(hash2)

            level = next_level

        return level[0], mutated

    def _calculate_merkle_root(self, txids: list[bytes]) -> bytes:
        root, _ = self._calculate_merkle_root_checked(txids)
        return root

    # Block weight / sigops
    def _validate_block_limits(self, block: Block) -> tuple[bool, str]:
        """Validate block weight and sigops cost limits.

        Includes the two early-exit size checks from Bitcoin Core CheckBlock()
        (validation.cpp:3947) that fire before per-transaction accounting:

          1. block.vtx.empty() → bad-blk-length  (checked in validate_block)
          2. block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
          3. GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT

        These catch malicious blocks with pathological tx counts or stripped
        serialization before the more expensive per-tx weight summation.
        Reference: bitcoin-core/src/validation.cpp:3947
        """
        # Early check 1: tx count overflow guard
        # `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`
        # A block with > 1,000,000 transactions would be invalid even if each
        # transaction were the minimum possible 1 byte (which is impossible,
        # but this is a cheap pre-filter).
        if len(block.transactions) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
            return False, (
                f"bad-blk-length: tx count {len(block.transactions)} × "
                f"{WITNESS_SCALE_FACTOR} exceeds MAX_BLOCK_WEIGHT"
            )

        # Early check 2: stripped (no-witness) block serialization guard.
        # Approximation: sum the stripped size of all transactions.  Core
        # uses TX_NO_WITNESS serializer on the whole block.
        stripped_block_size = sum(len(tx.serialize()) for tx in block.transactions)
        if stripped_block_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
            return False, (
                f"bad-blk-length: stripped block size {stripped_block_size} × "
                f"{WITNESS_SCALE_FACTOR} exceeds MAX_BLOCK_WEIGHT"
            )

        # Core GetBlockWeight: the whole-block weight (80-byte header + CompactSize
        # tx-count counted at WITNESS_SCALE_FACTOR, on top of the per-tx weights).
        # See block_weight(); the old per-tx-only sum under-counted by ~324-332 WU
        # and false-accepted a marginally overweight block Core rejects bad-blk-weight.
        total_weight = block_weight(block.transactions)
        total_sigops_cost = 0

        for tx in block.transactions:
            tx_sigops_cost = 0

            # --- Legacy sigops (outputs + inputs) × WITNESS_SCALE_FACTOR ---
            # Core's GetLegacySigOpCount() counts scriptSig sigops for ALL
            # transactions including coinbase (Bitcoin Core consensus/tx_verify.cpp:112-124).
            # The coinbase scriptSig rarely contains OP_CHECKSIG in practice,
            # but we must count it to remain spec-compliant.
            legacy_sigops = 0
            for out in tx.outputs:
                legacy_sigops += _count_legacy_sigops(out.script_pubkey)
            for inp in tx.inputs:
                legacy_sigops += _count_legacy_sigops(inp.script_sig)
            tx_sigops_cost += legacy_sigops * WITNESS_SCALE_FACTOR

            # --- P2SH sigops × WITNESS_SCALE_FACTOR ---
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
                    if utxo is None:
                        continue
                    prev_spk = bytes(utxo["script_pubkey"])
                    p2sh_sigops = _get_p2sh_sigops(inp.script_sig, prev_spk)
                    tx_sigops_cost += p2sh_sigops * WITNESS_SCALE_FACTOR

                    # --- Witness sigops × 1 ---
                    witness_spk = prev_spk
                    witness_data = inp.witness
                    # For P2SH-wrapped witness, use the redeem script
                    if _is_p2sh(prev_spk):
                        redeem = _get_last_push(inp.script_sig)
                        if redeem is not None:
                            witness_spk = redeem
                    tx_sigops_cost += _count_witness_sigops(
                        witness_spk, witness_data
                    )

            # NOTE: MAX_TX_SIGOPS_COST (16,000) is a mempool policy limit
            # (MAX_STANDARD_TX_SIGOPS_COST in Bitcoin Core), NOT a consensus
            # rule.  It must NOT be enforced during block validation — only
            # the per-block limit (MAX_BLOCK_SIGOPS_COST) is consensus.
            # Ref: Bitcoin Core policy/policy.h, validation.cpp AcceptToMemoryPool

            total_sigops_cost += tx_sigops_cost

        if total_weight > MAX_BLOCK_WEIGHT:
            return False, f"Block weight {total_weight} exceeds {MAX_BLOCK_WEIGHT}"

        if total_sigops_cost > MAX_BLOCK_SIGOPS_COST:
            return False, (
                f"Block sigops cost {total_sigops_cost} exceeds "
                f"{MAX_BLOCK_SIGOPS_COST}"
            )

        return True, ""

    # Witness commitment (SegWit)
    # Activation heights per network
    _SEGWIT_ACTIVATION = {
        "mainnet": 481_824,
        "testnet": 834_624,
        "testnet3": 834_624,
        "testnet4": 0,
        "signet": 0,
        "regtest": 0,
    }

    _WITNESS_COMMITMENT_MAGIC = bytes.fromhex("aa21a9ed")

    def _find_witness_commitment(self, coinbase_tx: Transaction) -> bytes | None:
        for out in reversed(coinbase_tx.outputs):
            spk = out.script_pubkey
            if (
                len(spk) >= 38
                and spk[0] == 0x6A           # OP_RETURN
                and spk[1] == 0x24           # push 36 bytes
                and spk[2:6] == self._WITNESS_COMMITMENT_MAGIC
            ):
                return spk[6:38]
        return None

    def _calculate_witness_merkle_root(self, block: Block) -> bytes:
        wtxids: list[bytes] = [bytes(32)]  # coinbase → null hash
        for tx in block.transactions[1:]:
            wtxids.append(tx.get_wtxid())
        return self._calculate_merkle_root(wtxids)

    def _validate_witness_commitment(
        self, block: Block, height: int
    ) -> tuple[bool, str]:
        """Validate the SegWit witness commitment in the coinbase.

        Mirrors Bitcoin Core CheckWitnessMalleation() in validation.cpp:3870.

        Gates (in Core order):
          G1  SegWit active → look for commitment in last matching coinbase output.
          G2  Commitment found → nonce size: coinbase scriptWitness must be exactly
              one 32-byte stack item ("bad-witness-nonce-size").
          G3  Commitment found → SHA256d(witness_root || nonce) must match the
              32 bytes at scriptPubKey[6..38] ("bad-witness-merkle-match").
          G4  Commitment found AND all gates pass → return OK (skip G5).
          G5  SegWit active but NO commitment found OR SegWit inactive →
              any tx with witness data → "unexpected-witness".
        """
        activation = self._SEGWIT_ACTIVATION.get(self.network, 481_824)
        segwit_active = height >= activation

        if segwit_active:
            # G1: locate the witness commitment (last output in coinbase that
            # matches OP_RETURN 0x24 0xaa21a9ed; -1 if absent).
            commitment = self._find_witness_commitment(block.transactions[0])

            if commitment is not None:
                # G2: coinbase scriptWitness must be exactly one 32-byte item.
                # Core ref: validation.cpp:3880-3885
                coinbase_input = block.transactions[0].inputs[0]
                witness = coinbase_input.witness or []
                if len(witness) != 1 or len(witness[0]) != 32:
                    logger.error(
                        "[diag] _validate_witness_commitment FAIL h=%d: coinbase witness "
                        "len=%d (expected 1), item0_len=%d (expected 32)",
                        height,
                        len(witness),
                        len(witness[0]) if witness else -1,
                    )
                    return False, "bad-witness-nonce-size"

                # G3: SHA256d(witness_root || nonce) must equal the committed value.
                # Core ref: validation.cpp:3890-3898
                nonce = witness[0]
                witness_root = self._calculate_witness_merkle_root(block)
                expected_commitment = hashlib.sha256(
                    hashlib.sha256(witness_root + nonce).digest()
                ).digest()
                if expected_commitment != commitment:
                    wtxids_preview = [
                        bytes(32).hex() if i == 0
                        else block.transactions[i].get_wtxid().hex()
                        for i in range(min(5, len(block.transactions)))
                    ]
                    witness_summary = []
                    for i, tx in enumerate(block.transactions[:5]):
                        if tx.has_witness:
                            per_input = [
                                f"items={len(tin.witness or [])} "
                                f"bytes={sum(len(w) for w in (tin.witness or []))}"
                                for tin in tx.inputs
                            ]
                            witness_summary.append(f"tx{i}:[{','.join(per_input)}]")
                        else:
                            witness_summary.append(f"tx{i}:none")
                    logger.error(
                        "[diag] _validate_witness_commitment FAIL h=%d: "
                        "commitment_in_coinbase=%s computed=%s witness_root=%s "
                        "nonce=%s n_tx=%d wtxids[:5]=%s witness[:5]=%s",
                        height,
                        commitment.hex(),
                        expected_commitment.hex(),
                        witness_root.hex(),
                        nonce.hex(),
                        len(block.transactions),
                        wtxids_preview,
                        witness_summary,
                    )
                    return False, "bad-witness-merkle-match"

                # G4: commitment present and valid — return OK.
                # Core ref: validation.cpp:3900-3902
                return True, ""

            # G5 (segwit active, no commitment): fall through to unexpected-witness
            # check below.  Core ref: validation.cpp:3905-3913.

        # G5: no commitment found (or SegWit not yet active) — reject any block
        # that carries witness data.  Core rejects with "unexpected-witness".
        # Core ref: validation.cpp:3905-3913
        for tx in block.transactions:
            if tx.has_witness:
                return False, "unexpected-witness"

        return True, ""

    def _validate_coinbase(self, tx: Transaction, height: int) -> bool:
        """Validate coinbase transaction."""
        # Check it's actually a coinbase
        if not tx.is_coinbase:
            logger.error(
                "[diag] _validate_coinbase FAIL h=%d: tx.is_coinbase=False "
                "(n_inputs=%d, first.prev_txid=%s)",
                height,
                len(tx.inputs),
                tx.inputs[0].prev_txid.hex() if tx.inputs else "<no inputs>",
            )
            return False

        # Check coinbase input
        if len(tx.inputs) != 1:
            logger.error(
                "[diag] _validate_coinbase FAIL h=%d: n_inputs=%d (expected 1)",
                height,
                len(tx.inputs),
            )
            return False

        coinbase_input = tx.inputs[0]
        if coinbase_input.prev_txid != bytes(32):
            logger.error(
                "[diag] _validate_coinbase FAIL h=%d: prev_txid=%s (expected all-zero)",
                height,
                coinbase_input.prev_txid.hex(),
            )
            return False

        # Check coinbase has at least one output
        if len(tx.outputs) == 0:
            logger.error(
                "[diag] _validate_coinbase FAIL h=%d: zero outputs", height
            )
            return False

        # Coinbase scriptSig must be 2-100 bytes (consensus rule)
        sig_len = len(coinbase_input.script_sig)
        if sig_len < 2 or sig_len > 100:
            logger.error(
                "[diag] _validate_coinbase FAIL h=%d: scriptSig len=%d (must be 2..100), "
                "scriptSig=%s",
                height,
                sig_len,
                coinbase_input.script_sig.hex(),
            )
            return False

        # BIP34: coinbase scriptSig must start with the byte-exact canonical
        # encoding of the block height.
        # Bitcoin Core validation.cpp:4151-4159:
        #   CScript expect = CScript() << nHeight;
        #   sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
        #
        # Activation height is per-network (NOT hardcoded to mainnet 227931).
        # testnet4/signet/regtest all have bip34_height=1.
        bip34_deployment = BURIED_DEPLOYMENTS.get(self.network, {}).get("bip34")
        bip34_activation = bip34_deployment.height if bip34_deployment is not None else 227_931
        if height >= bip34_activation:
            script = coinbase_input.script_sig
            expect = _encode_bip34_height(height)
            n = len(expect)
            if len(script) < n or script[:n] != expect:
                logger.error(
                    "[diag] _validate_coinbase FAIL h=%d: BIP34 bad encoding "
                    "expected_prefix=%s scriptSig=%s",
                    height,
                    expect.hex(),
                    script.hex(),
                )
                return False

        return True

    def _verify_coinbase_amount(
        self,
        coinbase_tx: Transaction,
        height: int,
        total_fees: int
    ) -> bool:
        block_subsidy = self._calculate_block_subsidy(height)
        expected_amount = block_subsidy + total_fees

        total_output = sum(out.value for out in coinbase_tx.outputs)

        # Coinbase amount must not exceed subsidy + fees (miners may underpay)
        return total_output <= expected_amount

    def _calculate_block_subsidy(self, height: int) -> int:
        """Compute block subsidy in satoshis at *height*.

        Mirrors Bitcoin Core ``GetBlockSubsidy`` (validation.cpp:1839-…):

            int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
            if (halvings >= 64) return 0;
            CAmount nSubsidy = 50 * COIN;
            nSubsidy >>= halvings;

        ``nSubsidyHalvingInterval`` is **per-network**: 210_000 on
        mainnet / testnet / testnet4 / signet, but **150 on regtest**
        (``kernel/chainparams.cpp:535``).

        W93 fix: prior implementation hardcoded 210_000 for every network,
        which over-estimates the regtest subsidy after the 150-block
        halving and could let a coinbase pay too much (``bad-cb-amount``
        consensus split vs Core on regtest functional tests).
        """
        # Regtest is the only network with a non-default halving interval.
        # Hardcoded here to avoid a new chain_params import cycle —
        # `self.network` is the network string passed to the validator.
        # Use getattr() so call sites that bypass __init__ (e.g. tests
        # that do ``BlockValidator.__new__(BlockValidator)._calculate_block_subsidy``)
        # still get the canonical mainnet behaviour.
        network = getattr(self, "network", "mainnet")
        interval = 150 if network == "regtest" else 210_000
        halvings = height // interval
        if halvings >= 64:
            return 0
        return 50 * 100_000_000 >> halvings

    # Signet block solution (BIP 325)

    def _validate_signet_solution(
        self, block: Block, height: int
    ) -> tuple[bool, str]:
        """Validate the signet block signature (BIP 325)."""
        if self.network != "signet":
            return True, ""

        # Genesis block has no signature
        if height == 0:
            return True, ""

        coinbase = block.transactions[0]

        # 1. Find the witness commitment output
        commitment_script = None
        for out in reversed(coinbase.outputs):
            spk = out.script_pubkey
            if (
                len(spk) >= 38
                and spk[0] == 0x6A          # OP_RETURN
                and spk[1] == 0x24          # push 36 bytes
                and spk[2:6] == self._WITNESS_COMMITMENT_MAGIC
            ):
                commitment_script = spk
                break

        if commitment_script is None:
            # No witness commitment — check if the challenge is trivially
            # satisfiable (e.g. OP_TRUE).  Otherwise fail.
            return False, "Signet: no witness commitment in coinbase"

        # 2. Extract signet commitment from the witness commitment script.
        #    The commitment script may contain extra pushes after the
        #    38-byte witness commitment.  We look for a push starting
        #    with SIGNET_HEADER (0xecc7daa2).
        signet_solution = self._extract_signet_commitment(commitment_script)
        if signet_solution is None:
            # Empty solution — only valid if challenge is trivially true.
            signet_solution = b""

        # 3. Parse scriptSig and witness from the solution.
        solution_script_sig, solution_witness = (
            self._parse_signet_solution(signet_solution)
        )

        # 4. Compute the modified merkle root.
        #    Replace the actual coinbase with a version whose witness
        #    commitment has the signet commitment stripped (replaced with
        #    SIGNET_HEADER + no data).
        modified_merkle = self._compute_signet_merkle_root(block)

        # 5. Build virtual transactions.
        #    to_spend: input is null, scriptSig = OP_0 <72-byte block_data>,
        #              output scriptPubKey = challenge
        #    to_sign:  spends to_spend, scriptSig/witness from solution,
        #              output = OP_RETURN
        challenge = DEFAULT_SIGNET_CHALLENGE
        block_data = self._encode_signet_block_data(
            block, modified_merkle
        )

        # Build to_spend as a minimal Transaction
        to_spend = self._build_signet_to_spend(block_data, challenge)

        # Build to_sign that spends to_spend
        to_sign = self._build_signet_to_sign(
            to_spend, solution_script_sig, solution_witness
        )

        # 6. Verify
        interp = ScriptInterpreter()
        try:
            ok = interp.verify(
                solution_script_sig,
                challenge,
                to_sign,
                input_index=0,
                flags=SIGNET_SCRIPT_FLAGS,
                amount=0,
            )
        except Exception as e:
            return False, f"Signet: script verification error: {e}"

        if not ok:
            return False, "Signet: block signature verification failed"
        return True, ""

    @staticmethod
    def _extract_signet_commitment(commitment_script: bytes) -> bytes | None:
        """Extract signet data from the witness commitment scriptPubKey."""
        # The commitment script starts with OP_RETURN (0x6a), then various
        # push opcodes.  Walk through the pushes looking for SIGNET_HEADER.
        i = 1  # skip OP_RETURN
        while i < len(commitment_script):
            op = commitment_script[i]
            i += 1
            # Determine push length
            if 0x01 <= op <= 0x4B:
                push_len = op
            elif op == 0x4C:  # OP_PUSHDATA1
                if i >= len(commitment_script):
                    break
                push_len = commitment_script[i]
                i += 1
            elif op == 0x4D:  # OP_PUSHDATA2
                if i + 1 >= len(commitment_script):
                    break
                push_len = int.from_bytes(
                    commitment_script[i:i + 2], "little"
                )
                i += 2
            elif op == 0x4E:  # OP_PUSHDATA4
                if i + 3 >= len(commitment_script):
                    break
                push_len = int.from_bytes(
                    commitment_script[i:i + 4], "little"
                )
                i += 4
            else:
                # Not a push opcode — skip
                continue

            data = commitment_script[i:i + push_len]
            i += push_len

            if len(data) >= 4 and data[:4] == SIGNET_HEADER:
                return data[4:]  # everything after the header

        return None

    @staticmethod
    def _parse_signet_solution(
        solution: bytes,
    ) -> tuple[bytes, list[bytes]]:
        """Parse scriptSig and witness stack from a signet solution."""
        if not solution:
            return b"", []

        offset = 0

        # Read scriptSig (compact-size prefixed)
        sig_len, consumed = _read_compact_size(solution, offset)
        offset += consumed
        script_sig = solution[offset:offset + sig_len]
        offset += sig_len

        # Read witness stack
        witness: list[bytes] = []
        if offset < len(solution):
            n_items, consumed = _read_compact_size(solution, offset)
            offset += consumed
            for _ in range(n_items):
                if offset >= len(solution):
                    break
                item_len, consumed = _read_compact_size(solution, offset)
                offset += consumed
                witness.append(solution[offset:offset + item_len])
                offset += item_len

        return script_sig, witness

    def _compute_signet_merkle_root(self, block: Block) -> bytes:
        """Compute the modified merkle root for signet signing."""
        coinbase = block.transactions[0]

        # Build the modified coinbase witness commitment output:
        # keep the original 38-byte commitment, replace the signet push
        # with header-only.
        modified_outputs = []
        for out in coinbase.outputs:
            spk = out.script_pubkey
            if (
                len(spk) >= 38
                and spk[0] == 0x6A
                and spk[1] == 0x24
                and spk[2:6] == self._WITNESS_COMMITMENT_MAGIC
            ):
                # Rebuild: keep first 38 bytes (OP_RETURN + commitment),
                # then add a 4-byte push of SIGNET_HEADER with no data.
                new_spk = spk[:38] + bytes([4]) + SIGNET_HEADER
                modified_outputs.append(
                    TxOut(value=out.value, script_pubkey=new_spk)
                )
            else:
                modified_outputs.append(out)

        # Build a modified coinbase Transaction
        modified_cb = Transaction(
            version=coinbase.version,
            inputs=coinbase.inputs,
            outputs=modified_outputs,
            locktime=coinbase.locktime,
            txid=b"",  # will be recomputed
            is_coinbase=True,
        )
        # Compute its txid
        cb_data = modified_cb.serialize()
        cb_hash = hashlib.sha256(hashlib.sha256(cb_data).digest()).digest()

        txids = [cb_hash]
        for tx in block.transactions[1:]:
            txids.append(tx.get_txid())

        return self._calculate_merkle_root(txids)

    @staticmethod
    def _encode_signet_block_data(
        block: Block, modified_merkle: bytes
    ) -> bytes:
        data = bytearray()
        data.extend(struct.pack("<i", block.version))        # 4 bytes
        data.extend(block.prev_blockhash)                     # 32 bytes
        data.extend(modified_merkle)                           # 32 bytes
        data.extend(struct.pack("<I", block.timestamp))       # 4 bytes
        return bytes(data)

    @staticmethod
    def _build_signet_to_spend(
        block_data: bytes, challenge: bytes
    ) -> Transaction:
        """Build the virtual *to_spend* transaction for signet."""
        # scriptSig: OP_0 PUSH72 <block_data>
        sig_script = bytes([0x00, len(block_data)]) + block_data

        inp = TxIn(
            prev_txid=bytes(32),
            prev_vout=0xFFFFFFFF,
            script_sig=sig_script,
            sequence=0,
        )
        out = TxOut(value=0, script_pubkey=challenge)

        tx = Transaction(
            version=0,
            inputs=[inp],
            outputs=[out],
            locktime=0,
            txid=b"",
            is_coinbase=False,
        )
        # Compute and set txid
        tx_data = tx.serialize()
        tx.txid = hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()
        return tx

    @staticmethod
    def _build_signet_to_sign(
        to_spend: Transaction,
        solution_script_sig: bytes,
        solution_witness: list[bytes],
    ) -> Transaction:
        inp = TxIn(
            prev_txid=to_spend.get_txid(),
            prev_vout=0,
            script_sig=solution_script_sig,
            sequence=0,
        )
        if solution_witness:
            inp.witness = solution_witness

        out = TxOut(value=0, script_pubkey=bytes([0x6A]))  # OP_RETURN

        tx = Transaction(
            version=0,
            inputs=[inp],
            outputs=[out],
            locktime=0,
            txid=b"",
            is_coinbase=False,
        )
        return tx

    def _calculate_tx_fee(self, tx: Transaction, intra_block_utxos=None) -> int:
        total_input = 0
        for tx_in in tx.inputs:
            utxo = self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
            if utxo is None and intra_block_utxos:
                utxo = intra_block_utxos.get((tx_in.prev_txid, tx_in.prev_vout))
            if utxo:
                total_input += utxo['value']

        total_output = sum(out.value for out in tx.outputs)
        fee = total_input - total_output
        if fee < 0 or fee > MAX_MONEY:
            return 0
        return fee


class TransactionValidator:
    """Validates transactions for mempool and new blocks"""

    def __init__(
        self,
        db: BlockchainDatabase,
        network: str = "mainnet",
        snapshot_manager: "SnapshotManager | None" = None,
    ):
        self.db = db
        self.network = network
        self.script_interpreter = ScriptInterpreter()
        # Snapshot manager is consulted by the BIP-68 stopgap path
        # (check_sequence_locks) to detect inputs whose prev block is
        # below the snapshot height -- those prev blocks have no header
        # bytes loaded, so we can't compute their MTP for time-based
        # locks, and depth-based locks may not be enforceable either if
        # the snapshot import elided per-coin height for any subset of
        # coins.  When OUROBOROS_BIP68_STOPGAP=1 is set, we skip BIP-68
        # for those inputs and emit a WARN.
        self.snapshot_manager = snapshot_manager
        # De-dupe state for the BIP-68 stopgap WARN: one log line per
        # (block_height, prevout) avoids drowning the live log when a
        # block has many pre-snapshot inputs.
        self._bip68_stopgap_warned: set[tuple[int, bytes, int]] = set()
        # Cache the resolved snapshot height so the env-flag fast path
        # doesn't re-read the on-disk base_blockhash on every input.
        # ``None`` means "no snapshot loaded" (or "unable to resolve"),
        # which is the expected state for genesis-IBD nodes.  ``-1``
        # is a sentinel meaning "not yet probed this process".
        self._cached_snapshot_height: int | None = -1

    def validate_transaction(
        self, tx: Transaction, height: int, block_mtp: int = 0,
        block_hash: bytes | None = None,
        intra_block_utxos: dict | None = None,
        skip_scripts: bool = False,
        fees_out: list | None = None,
        extra_script_flags: int = 0,
    ) -> tuple[bool, str]:
        """Validate *tx* at *height* (structure, inputs, locktime, scripts); returns ``(ok, error_message)``.

        When *skip_scripts* is True (assume-valid during IBD), signature and
        script verification is skipped.  UTXO existence, amounts, coinbase
        maturity, locktime, and BIP 68 checks are still enforced.

        *extra_script_flags* is OR'd into the consensus flag set before script
        verification.  Mempool callers pass the policy-only delta returned by
        ``get_standard_script_flags() & ~get_flags_for_height()`` so that the
        STANDARD verification flags (NULLFAIL, LOW_S, CLEANSTACK, MINIMALDATA,
        MINIMALIF, WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_NOPS, etc.) are
        enforced for relay acceptance.  Block validation passes 0 here so only
        consensus-mandatory flags are enforced.  Mirrors Bitcoin Core's split
        between STANDARD_SCRIPT_VERIFY_FLAGS (PolicyScriptChecks) and the
        per-height MANDATORY_SCRIPT_VERIFY_FLAGS (ConsensusScriptChecks /
        CheckInputScripts in ConnectBlock).
        """
        flags = get_flags_for_height(height, block_hash, self.network)
        flags |= int(extra_script_flags)

        # 1. Check structure
        if not self._check_structure(tx):
            return False, "Invalid structure"

        # 2. IsFinalTx — complete locktime validation
        if not self._is_final_tx(tx, height, block_mtp):
            return False, "Transaction is not final (locktime not satisfied)"

        # 3. Gather ALL input UTXOs first — Taproot sighash (BIP 341)
        #    needs the complete list of input amounts and scriptPubKeys
        #    before verifying ANY individual input.
        #
        #    Use batch lookup when all inputs come from the persistent UTXO set
        #    (no intra-block dependency) to reduce Python→Rust FFI round-trips.
        #    N individual get_utxo() calls → 1 get_utxo_batch() call, cutting
        #    GIL re-acquisition overhead that caused p95 latency spikes during IBD.
        total_input = 0
        input_utxos: list[dict] = []
        input_amounts: list[int] = []
        input_script_pubkeys: list[bytes] = []

        # Phase 1.3: always batch-fetch all inputs from the DB in one FFI call,
        # then overlay intra_block_utxos for any that come from earlier txs in
        # the same block.  Prior code gated batch on `not needs_intra`, which
        # forced every tx that followed an intra-block dep onto the per-input
        # slow path even though most of its inputs still came from the DB.
        if hasattr(self.db, 'get_utxo_batch') and tx.inputs:
            outpoints = [(tx_in.prev_txid, tx_in.prev_vout) for tx_in in tx.inputs]
            batch = self.db.get_utxo_batch(outpoints)
            for i, (tx_in, utxo) in enumerate(zip(tx.inputs, batch)):
                if utxo is None and intra_block_utxos:
                    utxo = intra_block_utxos.get((tx_in.prev_txid, tx_in.prev_vout))
                if utxo is None:
                    return False, f"Input not found: {tx_in.prev_txid.hex()}:{tx_in.prev_vout}"
                input_utxos.append(utxo)
                input_amounts.append(utxo['value'])
                input_script_pubkeys.append(bytes(utxo['script_pubkey']))
        else:
            # Fallback for test doubles that don't implement get_utxo_batch.
            for tx_in in tx.inputs:
                utxo = self.db.get_utxo(tx_in.prev_txid, tx_in.prev_vout)
                if utxo is None and intra_block_utxos:
                    utxo = intra_block_utxos.get((tx_in.prev_txid, tx_in.prev_vout))
                if not utxo:
                    return False, f"Input not found: {tx_in.prev_txid.hex()}:{tx_in.prev_vout}"
                input_utxos.append(utxo)
                input_amounts.append(utxo['value'])
                input_script_pubkeys.append(bytes(utxo['script_pubkey']))

        # Now verify each input with the COMPLETE amounts/spk lists
        for i, tx_in in enumerate(tx.inputs):
            utxo = input_utxos[i]

            # Coinbase maturity: coinbase outputs need COINBASE_MATURITY confirmations
            # Ref: Bitcoin Core consensus/tx_verify.cpp:179-182
            #   ("bad-txns-premature-spend-of-coinbase")
            # If utxo_height is None (e.g. pre-snapshot coins), treat it as 0
            # so the depth check is conservative rather than silently skipping.
            utxo_height = utxo.get('height')
            is_coinbase_utxo = utxo.get('is_coinbase', False)
            if is_coinbase_utxo:
                coin_height = utxo_height if utxo_height is not None else 0
                depth = height - coin_height
                if depth < COINBASE_MATURITY:
                    return False, (
                        f"bad-txns-premature-spend-of-coinbase: "
                        f"tried to spend coinbase at depth {depth}"
                    )

            # Per-coin MoneyRange check.
            # Ref: Bitcoin Core consensus/tx_verify.cpp:185-188
            #   ("bad-txns-inputvalues-outofrange")
            # A coin value out of range in the UTXO set indicates database
            # corruption; reject the tx rather than silently trusting it.
            coin_value = utxo['value']
            if coin_value < 0 or coin_value > MAX_MONEY:
                return False, "bad-txns-inputvalues-outofrange"
            total_input += coin_value
            if total_input < 0 or total_input > MAX_MONEY:
                return False, "bad-txns-inputvalues-outofrange"

            # Verify signatures with proper flags (skip during assume-valid IBD)
            if not skip_scripts:
                if not self._verify_input_signature(
                    tx, tx_in, utxo, i, flags, input_amounts, input_script_pubkeys
                ):
                    return False, f"Invalid signature for input {i}"

        # 4. Check amounts (consensus: inputs must cover outputs)
        # Ref: Bitcoin Core consensus/tx_verify.cpp:195-199
        #   ("bad-txns-in-belowout")
        total_output = sum(out.value for out in tx.outputs)
        if total_input < total_output:
            return False, f"bad-txns-in-belowout: value in ({total_input}) < value out ({total_output})"

        # Fee MoneyRange check.
        # Ref: Bitcoin Core consensus/tx_verify.cpp:202-209 ("bad-txns-fee-outofrange")
        txfee = total_input - total_output
        if txfee < 0 or txfee > MAX_MONEY:
            return False, "bad-txns-fee-outofrange"

        # 5. BIP 68 relative lock-time
        if not self.check_sequence_locks(tx, height, block_mtp, network=self.network, intra_block_utxos=intra_block_utxos):
            return False, "BIP 68 sequence lock not satisfied"

        # Phase 1.2: surface the fee to the caller so block-validate doesn't
        # need to re-fetch UTXOs via _calculate_tx_fee (~6000 redundant
        # per-input FFI calls per block).
        if fees_out is not None:
            fees_out.append(txfee)
        return True, ""

    @staticmethod
    def _is_final_tx(tx: Transaction, block_height: int, block_mtp: int) -> bool:
        # Prefer the Rust is_final_tx implementation when available — it has
        # no special-case fallbacks and mirrors Core's IsFinalTx exactly.
        # Ref: Bitcoin Core consensus/tx_verify.cpp:17-37
        try:
            from sync import is_final_tx as _rust_is_final_tx
            sequences = [inp.sequence for inp in tx.inputs]
            return _rust_is_final_tx(tx.locktime, sequences, block_height, block_mtp)
        except ImportError:
            pass

        # Pure-Python fallback (used only when Rust sync module unavailable).
        # Mirrors Core IsFinalTx exactly — no silent-accept on missing MTP.
        # Ref: Bitcoin Core consensus/tx_verify.cpp:17-37
        LOCKTIME_THRESHOLD = 500_000_000

        if tx.locktime == 0:
            return True

        # All inputs SEQUENCE_FINAL (0xffffffff) → nLockTime is disabled
        # Ref: Core tx_verify.cpp:32-35 (the last for-loop)
        if all(inp.sequence == 0xFFFFFFFF for inp in tx.inputs):
            return True

        # Determine the comparison value based on locktime type
        if tx.locktime < LOCKTIME_THRESHOLD:
            # Height-based locktime: final when locktime < block_height
            return tx.locktime < block_height
        else:
            # Time-based locktime (BIP 113): final when locktime < MTP of prev block
            # block_mtp == 0 only at genesis (height 0, no prev block).  For
            # genesis the coinbase locktime is always 0 (handled above), so
            # block_mtp == 0 here means MTP is truly unavailable.  Reject
            # rather than silently accept — better to surface the caller bug.
            if block_mtp <= 0:
                return False  # BIP-113: MTP unavailable → cannot confirm finality
            return tx.locktime < block_mtp

    def _check_structure(self, tx: Transaction) -> bool:
        """Check basic transaction structure.

        Mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction.
        Ref: tx_check.cpp:11-59.
        """
        # Tx version is NOT a consensus check per Bitcoin Core
        # (consensus/tx_check.cpp::CheckTransaction has no nVersion check —
        # the version is mempool/relay policy only, enforced by
        # validation.cpp::IsStandardTx). Block consensus accepts any
        # nVersion value (including v3 BIP-431 TRUC, which is policy at
        # the relay layer). The pre-fix `version < 1 or version > 2` check
        # rejected mainnet block 944,184 tx 217 which has version=3 and
        # is consensus-valid.

        # Check we have at least one input (unless coinbase)
        # Ref: tx_check.cpp:14-16 ("bad-txns-vin-empty")
        if len(tx.inputs) == 0:
            return False

        # Check we have at least one output
        # Ref: tx_check.cpp:17-18 ("bad-txns-vout-empty")
        if len(tx.outputs) == 0:
            return False

        # Check locktime is valid
        if tx.locktime < 0 or tx.locktime > 0xffffffff:
            return False

        # Oversize check (non-witness serialized size).
        # Ref: tx_check.cpp:19-21 ("bad-txns-oversize"):
        #   GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        # Transaction.serialize() returns the non-witness form.
        if len(tx.serialize()) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
            return False

        # Check all outputs have valid values and total doesn't overflow.
        # out.value is deserialized as unsigned (int.from_bytes without signed=True);
        # a negative wire value (-1 = 0xffffffffffffffff) arrives as a large positive
        # integer with the high bit set.  Reinterpret as signed before the negative check
        # so we produce the correct BIP-22 error string.
        # Mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction (negative first).
        # Ref: tx_check.cpp:27-33 (CVE-2010-5139: "bad-txns-vout-negative",
        #      "bad-txns-vout-toolarge", "bad-txns-txouttotal-toolarge").
        INT64_MAX = 0x7FFFFFFFFFFFFFFF
        total_out = 0
        for out in tx.outputs:
            signed_value = out.value - (1 << 64) if out.value > INT64_MAX else out.value
            if signed_value < 0:
                return False
            if out.value > MAX_MONEY:
                return False
            total_out += out.value
            if total_out > MAX_MONEY:
                return False

        # Check for duplicate inputs (CVE-2018-17144)
        # Ref: tx_check.cpp:36-44 ("bad-txns-inputs-duplicate")
        seen_inputs = set()
        for tx_in in tx.inputs:
            outpoint = (tx_in.prev_txid, tx_in.prev_vout)
            if outpoint in seen_inputs:
                return False
            seen_inputs.add(outpoint)

        # Coinbase vs non-coinbase prevout rules.
        # Ref: tx_check.cpp:47-57. Core's if/else: a coinbase tx must have a
        # scriptSig (coinbase data) of length in [2, 100] inclusive
        # ("bad-cb-length"); a non-coinbase tx may not reference a null prevout
        # ("bad-txns-prevout-null"). Coinbase identity matches the rest of this
        # method (tx.is_coinbase: single input with an all-zero prev_txid).
        if tx.is_coinbase:
            # The coinbase scriptSig length must be 2..100 inclusive.
            # Ref: tx_check.cpp:49-50 ("bad-cb-length"):
            #   tx.vin[0].scriptSig.size() < 2 || > 100
            cb_script_len = len(tx.inputs[0].script_sig)
            if cb_script_len < 2 or cb_script_len > 100:
                return False
        else:
            # Ref: tx_check.cpp:54-56 ("bad-txns-prevout-null")
            _null_txid = bytes(32)
            for tx_in in tx.inputs:
                if tx_in.prev_txid == _null_txid and tx_in.prev_vout == 0xFFFFFFFF:
                    return False

        return True

    def _verify_input_signature(
        self,
        tx: Transaction,
        tx_in: TxIn,
        utxo: dict,
        input_index: int,
        flags: int = SCRIPT_VERIFY_NONE,
        input_amounts: list[int] = None,
        input_script_pubkeys: list[bytes] = None,
    ) -> bool:
        # Build SigCache key from a true sighash-class commitment so that
        # forged-witness spends (e.g. Taproot key-path with empty script_sig)
        # cannot replay a cached valid-verification result.
        #
        # Per Core sigcache.cpp:39-50, the cache key is hashed over the actual
        # 32-byte sighash + pubkey + sig. ouroboros previously keyed on
        # (txid + input_index + script_pubkey + script_sig) which omits ALL
        # witness data; for SegWit / Taproot inputs `script_sig` is empty so
        # the cache key carried no witness-bearing material at all and any
        # forged-witness spend on the same (txid, input_index, flags) tuple
        # replayed the cached True. W159 BUG-13 / W160 BUG-9.
        #
        # Since the script interpreter computes the *actual* sighash inside
        # each CHECKSIG op (and a single script may invoke multiple sighash
        # types), we cannot extract one canonical "sighash" at the input level.
        # Instead we build a 32-byte commitment that covers every byte the
        # interpreter could possibly hash into a sighash:
        #   - serialize_with_witness(): full BIP141 wire bytes — commits to
        #     every input's outpoint+script_sig+witness+sequence, every
        #     output, version, locktime. Any forged-witness spend changes
        #     this serialisation and therefore changes the commitment.
        #   - input_index: identifies WHICH input this verification covers.
        #   - script_pubkey + amount: the prevout binding, BIP143-essential.
        #   - flags: script-verify flags affect the sighash via sig_version.
        # Two distinct sighashes that the interpreter would compute over this
        # input therefore cannot collide on the cache key — the wire bytes
        # they hash over differ.
        #
        # The per-process nonce inside SIG_CACHE prevents key prediction.
        import struct as _struct
        pubkey_bytes = bytes(utxo['script_pubkey'])
        sig_bytes = bytes(tx_in.script_sig)
        # Sighash commitment: hash of the full witness-bearing tx envelope
        # plus the per-input prevout binding. This is what the script
        # interpreter would feed (in pieces) into every CHECKSIG it runs.
        amount_bytes = _struct.pack("<q", int(utxo['value']))
        sighash_material = hashlib.sha256(
            tx.serialize_with_witness()
            + _struct.pack("<I", input_index)
            + pubkey_bytes
            + amount_bytes
        ).digest()

        # Check cache first - only successful verifications are cached
        if SIG_CACHE.lookup(sighash_material, pubkey_bytes, sig_bytes, flags):
            return True

        # Cache miss - perform verification
        result = self.script_interpreter.verify(
            tx_in.script_sig,
            bytes(utxo['script_pubkey']),
            tx,
            input_index,
            flags=flags,
            amount=utxo['value'],
            input_amounts=input_amounts,
            input_script_pubkeys=input_script_pubkeys,
        )

        # Cache successful verifications only
        if result:
            SIG_CACHE.insert(sighash_material, pubkey_bytes, sig_bytes, flags)

        return result

    # BIP 68 constants
    SEQUENCE_DISABLE = 1 << 31       # 0x80000000
    SEQUENCE_TYPE    = 1 << 22       # 0x00400000  (time-based if set)
    SEQUENCE_MASK    = 0x0000ffff

    # Env-flag for the BIP-68 stopgap (see ``_resolve_snapshot_height``).
    # When set to a truthy value, BIP-68 is skipped for any input whose
    # prevout was confirmed at or below the snapshot height (i.e. the
    # prevout is "pre-snapshot" -- we lack the prior 11 headers needed
    # to compute its MTP, and depth-based locks crossing the snapshot
    # boundary are also unverifiable in any meaningful sense).
    _BIP68_STOPGAP_ENV = "OUROBOROS_BIP68_STOPGAP"

    def _bip68_stopgap_enabled(self) -> bool:
        """Return True if the operator has opted in to the BIP-68 stopgap.

        Treats common true-ish values (``1`` / ``true`` / ``yes`` / ``on``,
        case-insensitive) as enabled; everything else (including empty
        string and "0") is disabled.  Read on every call so the env-var
        can be flipped without a process restart for soak/diagnostic
        runs.
        """
        v = os.environ.get(self._BIP68_STOPGAP_ENV, "")
        return v.strip().lower() in {"1", "true", "yes", "on"}

    def _resolve_snapshot_height(self) -> int | None:
        """Return the snapshot tip height when an assumeUTXO snapshot has
        been loaded into this datadir, else ``None``.

        Two sources, in order:
          1. ``snapshot_manager.snapshot_height`` -- set when this
             process performed the load itself (cheap, in-RAM).
          2. The on-disk ``chainstate_snapshot/base_blockhash`` file
             plus a ``get_assumeutxo_by_hash`` lookup against the
             chainparams table -- needed across restarts because
             ``snapshot_height`` is *not* repopulated when the loader
             takes the early-return "snapshot already exists" path
             (see ``node.py:577``).

        The resolved value is cached on the validator for the rest of
        the process so we don't pay the file read on every input.
        ``-1`` is the "not probed yet" sentinel; once probed we store
        either an int or ``None``.
        """
        if self._cached_snapshot_height != -1:
            return self._cached_snapshot_height  # type: ignore[return-value]

        sm = self.snapshot_manager
        if sm is None:
            self._cached_snapshot_height = None
            return None

        # Cheap in-RAM source: set by load_snapshot() during this process.
        if getattr(sm, "snapshot_height", None) is not None:
            self._cached_snapshot_height = int(sm.snapshot_height)
            return self._cached_snapshot_height

        # Cross-restart source: re-derive from the on-disk base_blockhash
        # via the chainparams table.  Lazy-import to avoid a circular
        # dependency at module load.
        try:
            base_hash = sm.read_snapshot_base_blockhash()
        except Exception:
            base_hash = None
        if not base_hash:
            self._cached_snapshot_height = None
            return None
        try:
            from ouroboros.snapshot import get_assumeutxo_by_hash
            au = get_assumeutxo_by_hash(self.network, base_hash)
        except Exception:
            au = None
        if au is None:
            self._cached_snapshot_height = None
            return None
        self._cached_snapshot_height = int(au.height)
        return self._cached_snapshot_height

    def _is_pre_snapshot_prevout(self, utxo_height: int | None) -> bool:
        """True iff ``utxo_height`` is at or below the snapshot tip.

        Used by the BIP-68 stopgap to decide whether to skip relative
        locktime enforcement on a given input.  Returns False when no
        snapshot has been loaded -- the stopgap is a no-op for
        genesis-IBD nodes.
        """
        if utxo_height is None:
            return False
        snap_h = self._resolve_snapshot_height()
        if snap_h is None:
            return False
        return int(utxo_height) <= snap_h

    def _log_bip68_stopgap_skip(
        self, block_height: int, inp: TxIn, utxo_height: int
    ) -> None:
        """Emit a single WARN per (block_height, prevout) for the stopgap.

        Without de-duping, the live mainnet log gets one line per input
        per retry of a wedged block, drowning out everything else.  The
        ``_bip68_stopgap_warned`` set is per-process and bounded; we
        cap it at 4096 entries and reset when full so RAM is bounded
        across a long-running soak.
        """
        key = (int(block_height), bytes(inp.prev_txid), int(inp.prev_vout))
        if key in self._bip68_stopgap_warned:
            return
        if len(self._bip68_stopgap_warned) > 4096:
            self._bip68_stopgap_warned.clear()
        self._bip68_stopgap_warned.add(key)
        snap_h = self._resolve_snapshot_height()
        is_time = bool(inp.sequence & self.SEQUENCE_TYPE)
        kind = "time" if is_time else "height"
        masked = inp.sequence & self.SEQUENCE_MASK
        logger.warning(
            "[BIP68-STOPGAP] block=%d skipping %s-based seqlock for "
            "input %s:%d (utxo_height=%d snapshot_height=%s seq=0x%08x mask=%d) -- "
            "%s. TODO: replace with backwards-header-sync (Option 1).",
            int(block_height),
            kind,
            bytes(inp.prev_txid)[::-1].hex(),
            int(inp.prev_vout),
            int(utxo_height),
            "?" if snap_h is None else str(snap_h),
            int(inp.sequence),
            masked,
            "OUROBOROS_BIP68_STOPGAP=1 (operator-acknowledged consensus relaxation)",
        )

    def check_sequence_locks(
        self, tx: Transaction, block_height: int, block_mtp: int,
        network: str = "mainnet",
        intra_block_utxos: dict | None = None,
    ) -> bool:
        """
        BIP 68: verify relative lock-time constraints on every input.

        Called before a v2+ transaction is accepted into a block.
        For each input whose disable flag is NOT set:
          - height-based: UTXO must be buried by at least (sequence & MASK) blocks
          - time-based:   MTP must exceed UTXO's MTP by (sequence & MASK) * 512 s

        Uses Rust implementation via PyO3 for performance and consistency.

        STOPGAP: when ``OUROBOROS_BIP68_STOPGAP=1`` is set in the
        environment AND a UTXO snapshot has been loaded, inputs whose
        ``prev_height <= snapshot_height`` are treated as if their
        sequence's DISABLE bit were set (i.e. BIP-68 is skipped for
        those inputs).  This is **not consensus-correct in the strict
        sense** -- it papers over the structural gap that ouroboros's
        snapshot loader does not import the prior 11 headers needed for
        MTP computation.  See ``_log_bip68_stopgap_skip``.  Long-term
        fix is Option 1 (backwards-header-sync after snapshot load).
        """
        # BIP68 only applies to version 2+ transactions
        if tx.version < 2:
            return True

        # Check if BIP68 is active at this height
        try:
            from sync import check_sequence_locks as rust_check_sequence_locks
            from sync import is_bip68_active
            enforce_bip68 = is_bip68_active(block_height, network)
        except ImportError:
            # Pure-Python fallback: use the buried-deployment table so that
            # non-mainnet networks (testnet4/regtest/signet, active from
            # genesis) get the correct activation height rather than the
            # hardcoded mainnet value 419328.
            # Ref: Bitcoin Core kernel/chainparams.cpp CSV heights
            from ouroboros.consensus import is_buried_deployment_active
            enforce_bip68 = is_buried_deployment_active("csv", block_height, network)

        if not enforce_bip68:
            return True

        # Build input info for Rust: list of (sequence, prev_height, prev_median_time)
        input_infos = []
        stopgap_enabled = self._bip68_stopgap_enabled()
        for inp in tx.inputs:
            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo is None and intra_block_utxos:
                utxo = intra_block_utxos.get((inp.prev_txid, inp.prev_vout))
            if utxo is None:
                return False

            utxo_height = utxo.get('height')
            if utxo_height is None:
                # No height metadata — treat as disabled (skip this input)
                # This matches assumevalid-era UTXO handling
                input_infos.append((inp.sequence | self.SEQUENCE_DISABLE, 0, 0))
                continue

            # BIP-68 stopgap (OUROBOROS_BIP68_STOPGAP=1): skip enforcement
            # when the prevout was confirmed at or below the snapshot tip.
            # Pre-snapshot blocks have no header bytes loaded post-
            # assumeutxo (Core would have headers from genesis-first sync;
            # ouroboros's snapshot loader does not require that), so
            # ``get_median_time_past(utxo_height-1)`` returns ``None`` and
            # time-based locks fall back to coin_time=0 -- which makes
            # them silently pass.  Height-based locks crossing the
            # snapshot boundary are similarly unverifiable.  The stopgap
            # makes that "we cannot verify, so we skip" explicit and
            # logged, instead of relying on the silent ``utxo_mtp = 0``
            # fallback.  See block_sync wedge at h=944,184 / tx 920 on
            # 2026-05-02 for the live failure mode.
            if (
                stopgap_enabled
                and not (inp.sequence & self.SEQUENCE_DISABLE)
                and self._is_pre_snapshot_prevout(utxo_height)
            ):
                self._log_bip68_stopgap_skip(
                    block_height, inp, utxo_height,
                )
                input_infos.append((inp.sequence | self.SEQUENCE_DISABLE, 0, 0))
                continue

            # Get the median time past of the block before the UTXO's confirmation
            # (coin time is MTP of block at height-1)
            # Ref: Bitcoin Core consensus/tx_verify.cpp:74
            #   nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
            utxo_mtp = self.db.get_median_time_past(max(utxo_height - 1, 0))
            if utxo_mtp is None:
                utxo_mtp = 0  # Fallback

            input_infos.append((inp.sequence, utxo_height, utxo_mtp))

        # Use Rust implementation if available
        try:
            return rust_check_sequence_locks(
                tx.version,
                input_infos,
                block_height,
                block_mtp,
                enforce_bip68,
            )
        except (ImportError, NameError):
            # Fall back to Python implementation, passing intra_block_utxos so
            # transactions that spend outputs of earlier txs in the same block
            # can be resolved (previously the fallback re-fetched from DB only,
            # causing false "UTXO not found" failures for intra-block deps).
            return self._check_sequence_locks_py(
                tx, block_height, block_mtp, intra_block_utxos=intra_block_utxos
            )

    def _check_sequence_locks_py(
        self,
        tx: Transaction,
        block_height: int,
        block_mtp: int,
        intra_block_utxos: dict | None = None,
    ) -> bool:
        """Pure-Python fallback for BIP 68 sequence lock checking.

        Parameters
        ----------
        tx:
            The transaction being validated.
        block_height:
            Height of the block that would contain *tx*.
        block_mtp:
            Median-time-past of block.pprev — the *previous* block's MTP.
            Ref: Bitcoin Core EvaluateSequenceLocks / BIP 113.
        intra_block_utxos:
            Outputs created by earlier transactions in the same block.
            Required to resolve inputs that spend intra-block outputs;
            without this, such inputs would falsely fail with "UTXO not found".
        """
        if tx.version < 2:
            return True

        stopgap_enabled = self._bip68_stopgap_enabled()
        for inp in tx.inputs:
            if inp.sequence & self.SEQUENCE_DISABLE:
                continue

            # Look up UTXO in the persistent set first, then overlay
            # intra-block outputs (same lookup order as validate_transaction).
            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo is None and intra_block_utxos:
                utxo = intra_block_utxos.get((inp.prev_txid, inp.prev_vout))
            if utxo is None:
                return False

            utxo_height = utxo.get('height')
            if utxo_height is None:
                continue  # no height metadata — skip (assumevalid-era UTXO)

            # BIP-68 stopgap: see check_sequence_locks() for rationale.
            if stopgap_enabled and self._is_pre_snapshot_prevout(utxo_height):
                self._log_bip68_stopgap_skip(block_height, inp, utxo_height)
                continue

            if inp.sequence & self.SEQUENCE_TYPE:
                # Time-based lock: lock_value units of 512 seconds each.
                # min_time = coin_time + (lock_value * 512) - 1
                # Fail if block_mtp <= min_time, i.e. block_mtp - coin_time < lock * 512
                # Ref: Bitcoin Core tx_verify.cpp:88, EvaluateSequenceLocks:101
                required = (inp.sequence & self.SEQUENCE_MASK) * 512
                utxo_mtp = self.db.get_median_time_past(max(utxo_height - 1, 0))
                if utxo_mtp is None:
                    # No MTP available for coin block — cannot verify time-based
                    # lock.  Treat as 0 (same as the Rust path's None→0 fallback)
                    # so the lock is effectively skipped.  The BIP-68 stopgap
                    # (OUROBOROS_BIP68_STOPGAP=1) is the recommended guard for
                    # post-snapshot nodes.
                    continue
                if block_mtp - utxo_mtp < required:
                    return False
            else:
                # Height-based lock: depth must be >= lock_value.
                # min_height = utxo_height + lock_value - 1
                # Fail if block_height <= min_height, i.e. depth < lock_value
                # Ref: Bitcoin Core tx_verify.cpp:90, EvaluateSequenceLocks:101
                required = inp.sequence & self.SEQUENCE_MASK
                depth = block_height - utxo_height
                if depth < required:
                    return False

        return True

    def _calculate_min_fee(self, tx: Transaction) -> int:
        # Get transaction size in bytes
        tx_size = len(tx.serialize())

        # Minimum fee: 1 satoshi per vbyte
        # For simplicity, we use bytes (vbytes would require segwit calculation)
        min_fee = tx_size  # 1 sat/vbyte

        # Minimum fee floor (dust threshold)
        if min_fee < 1000:  # 1000 satoshis minimum
            min_fee = 1000

        return min_fee


class ValidationError(Exception):
    """Raised when validation fails."""

    pass
