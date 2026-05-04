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
from ouroboros.consensus import BURIED_DEPLOYMENTS

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
MAX_BLOCK_WEIGHT = 4_000_000
MAX_BLOCK_SIGOPS_COST = 80_000
MAX_TX_SIGOPS_COST = 16_000
WITNESS_SCALE_FACTOR = 4

# Difficulty / PoW constants #
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016
POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60
POW_TARGET_SPACING = 10 * 60
POW_LIMIT_MAINNET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
POW_LIMIT_BITS_MAINNET = 0x1d00ffff
MAX_TIMEWARP = 600  # BIP94: max seconds a diff-adjustment block can precede prev
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
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF

    if mantissa == 0:
        return 0

    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


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


def _read_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        return 0, 0
    first = data[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1:offset + 3], "little"), 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1:offset + 5], "little"), 5
    return int.from_bytes(data[offset + 1:offset + 9], "little"), 9


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

    def validate_block(self, block: Block, known_height: int = 0) -> tuple[bool, str]:
        """Fully validate *block* (header, merkle root, weight, scripts); returns ``(ok, error_message)``.

        *known_height*: if >0, use this as the block's height instead of
        deriving it from the previous block in the DB.  This avoids
        incorrect height=1 when the DB doesn't store height on Block objects.
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
        block_mtp = self.db.get_median_time_past(expected_height - 1) or 0

        # 3. Validate header (including difficulty retarget)
        if not self._validate_header(block, prev_block, block_mtp, expected_height):
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

        # 7. BIP30: reject duplicate txids against unspent outputs
        #    Two historical exceptions on mainnet at heights 91842 and 91880
        #    (IsBIP30Repeat in Bitcoin Core's validation.cpp). These blocks
        #    contain coinbase txids that duplicate earlier blocks' coinbases.
        #    After BIP34 activation (height 227,931), coinbase txids include the
        #    block height, making duplicates impossible until height 1,983,702.
        _BIP34_HEIGHT = 227_931
        _BIP30_RECHECK_HEIGHT = 1_983_702
        enforce_bip30 = expected_height not in (91842, 91880)
        if enforce_bip30 and _BIP34_HEIGHT <= expected_height < _BIP30_RECHECK_HEIGHT:
            enforce_bip30 = False
        if enforce_bip30:
            for tx in block.transactions:
                txid = tx.get_txid()
                for vout_idx in range(len(tx.outputs)):
                    if self.db.get_utxo(txid, vout_idx) is not None:
                        return False, (
                            f"BIP30: duplicate txid {txid.hex()} with "
                            f"unspent output at vout {vout_idx}"
                        )

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
        if _has_sync_module:
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
            if i == 0:  # Coinbase
                if not self._validate_coinbase(tx, expected_height):
                    return False, "Invalid coinbase"
            else:
                # Capture the fee from validate_transaction directly to avoid
                # re-fetching every input UTXO in _calculate_tx_fee (was doing
                # ~6000 extra individual FFI calls per block at height 800k).
                tx_fees: list[int] = []
                valid, error = self.tx_validator.validate_transaction(
                    tx, expected_height, block_mtp,
                    block_hash=block.hash,
                    intra_block_utxos=intra_block_utxos,
                    skip_scripts=skip_scripts,
                    fees_out=tx_fees,
                )
                if not valid:
                    return False, f"Transaction {i} invalid: {error}"
                total_fees += tx_fees[0] if tx_fees else 0

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
        """Apply *block*'s UTXO effects to the database (spend inputs, create outputs)."""
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
    ) -> bool:
        """Validate block header."""
        # Block timestamp must exceed the median-time-past of previous 11 blocks
        if block_mtp > 0 and block.timestamp <= block_mtp:
            return False

        # BIP94 timewarp protection (testnet4 only):
        # At difficulty adjustment boundaries, the block timestamp must not
        # precede the previous block's timestamp by more than MAX_TIMEWARP (600s).
        # Ref: Bitcoin Core validation.cpp:4146-4154.
        if self.network == "testnet4" and height > 0:
            if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
                if block.timestamp < prev_block.timestamp - MAX_TIMEWARP:
                    return False

        # Check timestamp is not too far in the future (2 hours)
        current_time = int(_time.time())
        if block.timestamp > current_time + 2 * 3600:
            return False

        # Check version is valid
        if block.version < 1:
            return False

        # Check bits is valid (difficulty target)
        if block.bits == 0:
            return False

        # Verify difficulty retarget — block.bits must match expected value
        if height > 0:
            expected_bits = self._get_expected_bits(height, prev_block, block)
            if expected_bits is not None and block.bits != expected_bits:
                return False

        # Proof-of-work: block hash must meet difficulty target
        # Ref: bitcoin/src/pow.cpp CheckProofOfWork
        header = block.serialize()[:80]
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        hash_as_int = int.from_bytes(block_hash, "little")
        target = _bits_to_target(block.bits)
        if hash_as_int > target:
            return False

        return True

    def _get_expected_bits(
        self, height: int, prev_block: Block, block: Block
    ) -> int | None:
        """Calculate expected nBits for a block at *height*."""
        # Regtest: no retargeting — always use regtest min-difficulty (0x207fffff)
        if self.network == "regtest":
            return 0x207fffff

        # Non-retarget block
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0:
            # Testnet / testnet4 min-difficulty exception:
            # If new block timestamp > prev + 20 minutes, allow min difficulty.
            if self.network in ("testnet", "testnet3", "testnet4", "signet"):
                if block.timestamp > prev_block.timestamp + POW_TARGET_SPACING * 2:
                    return POW_LIMIT_BITS_MAINNET
                # Otherwise walk back to find last non-min-difficulty block.
                # Track height manually since get_block() may not set it.
                walk_height = height - 1
                pindex = prev_block
                while (
                    pindex
                    and walk_height > 0
                    and walk_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0
                    and pindex.bits == POW_LIMIT_BITS_MAINNET
                ):
                    pindex = self.db.get_block(pindex.prev_blockhash)
                    walk_height -= 1
                if pindex:
                    return pindex.bits
                return prev_block.bits
            return prev_block.bits

        first_height = height - DIFFICULTY_ADJUSTMENT_INTERVAL
        first_block = self.db.get_block_by_height(first_height)
        if first_block is None:
            return None  # cannot verify — missing ancestor

        actual_timespan = prev_block.timestamp - first_block.timestamp

        # Clamp to [targetTimespan/4 .. targetTimespan*4]
        if actual_timespan < POW_TARGET_TIMESPAN // 4:
            actual_timespan = POW_TARGET_TIMESPAN // 4
        if actual_timespan > POW_TARGET_TIMESPAN * 4:
            actual_timespan = POW_TARGET_TIMESPAN * 4

        # new_target = old_target * actual_timespan / target_timespan
        # BIP94 (testnet4): use nBits from the FIRST block of the current
        # difficulty period (height - 2015) so that the real difficulty is
        # always preserved — the first block cannot use the min-difficulty
        # exception.
        # Ref: Bitcoin Core pow.cpp:66-76 (enforce_BIP94 branch).
        if self.network == "testnet4":
            period_start_height = height - (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
            period_start_block = self.db.get_block_by_height(period_start_height)
            if period_start_block is None:
                return None
            old_target = _bits_to_target(period_start_block.bits)
        else:
            old_target = _bits_to_target(prev_block.bits)
        new_target = old_target * actual_timespan // POW_TARGET_TIMESPAN

        # Clamp to proof-of-work limit
        if new_target > POW_LIMIT_MAINNET:
            new_target = POW_LIMIT_MAINNET

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
        """Validate block weight and sigops cost limits."""
        total_weight = 0
        total_sigops_cost = 0

        for tx in block.transactions:
            total_weight += tx.get_weight()

            tx_sigops_cost = 0

            # --- Legacy sigops (outputs + inputs) × WITNESS_SCALE_FACTOR ---
            legacy_sigops = 0
            for out in tx.outputs:
                legacy_sigops += _count_legacy_sigops(out.script_pubkey)
            if not tx.is_coinbase:
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
        """Validate the SegWit witness commitment in the coinbase."""
        activation = self._SEGWIT_ACTIVATION.get(self.network, 481_824)
        if height < activation:
            return True, ""

        has_witness = any(tx.has_witness for tx in block.transactions)
        commitment = self._find_witness_commitment(block.transactions[0])

        if has_witness and commitment is None:
            logger.error(
                "[diag] _validate_witness_commitment FAIL h=%d: has_witness=True but "
                "no OP_RETURN+0xaa21a9ed commitment found in coinbase outputs "
                "(coinbase has %d outputs)",
                height,
                len(block.transactions[0].outputs),
            )
            return False, "Block has witness data but no witness commitment"

        if commitment is not None and has_witness:
            # Coinbase must have exactly one 32-byte witness item (the nonce)
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
                return False, "Coinbase witness nonce must be a single 32-byte item"

            nonce = witness[0]
            witness_root = self._calculate_witness_merkle_root(block)
            expected = hashlib.sha256(
                hashlib.sha256(witness_root + nonce).digest()
            ).digest()
            if expected != commitment:
                # Diagnostic: dump expected vs computed and the first few wtxids/witness
                # summaries so the next IBD pass surfaces the actual divergence.
                wtxids_preview = [
                    bytes(32).hex() if i == 0 else block.transactions[i].get_wtxid().hex()
                    for i in range(min(5, len(block.transactions)))
                ]
                witness_summary = []
                for i, tx in enumerate(block.transactions[:5]):
                    if tx.has_witness:
                        per_input = []
                        for tin in tx.inputs:
                            wlist = tin.witness or []
                            per_input.append(
                                f"items={len(wlist)} bytes={sum(len(w) for w in wlist)}"
                            )
                        witness_summary.append(f"tx{i}:[{','.join(per_input)}]")
                    else:
                        witness_summary.append(f"tx{i}:none")
                logger.error(
                    "[diag] _validate_witness_commitment FAIL h=%d: "
                    "commitment_in_coinbase=%s computed=%s witness_root=%s "
                    "nonce=%s n_tx=%d wtxids[:5]=%s witness[:5]=%s",
                    height,
                    commitment.hex(),
                    expected.hex(),
                    witness_root.hex(),
                    nonce.hex(),
                    len(block.transactions),
                    wtxids_preview,
                    witness_summary,
                )
                return False, "Witness commitment mismatch"

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
        halvings = height // 210000
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
    ) -> tuple[bool, str]:
        """Validate *tx* at *height* (structure, inputs, locktime, scripts); returns ``(ok, error_message)``.

        When *skip_scripts* is True (assume-valid during IBD), signature and
        script verification is skipped.  UTXO existence, amounts, coinbase
        maturity, locktime, and BIP 68 checks are still enforced.
        """
        flags = get_flags_for_height(height, block_hash, self.network)

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
            utxo_height = utxo.get('height')
            is_coinbase_utxo = utxo.get('is_coinbase', False)
            if is_coinbase_utxo and utxo_height is not None:
                depth = height - utxo_height
                if depth < COINBASE_MATURITY:
                    return False, (
                        f"Coinbase maturity not met for input {i}: "
                        f"depth {depth} < {COINBASE_MATURITY}"
                    )

            # Verify signatures with proper flags (skip during assume-valid IBD)
            if not skip_scripts:
                if not self._verify_input_signature(
                    tx, tx_in, utxo, i, flags, input_amounts, input_script_pubkeys
                ):
                    return False, f"Invalid signature for input {i}"

            total_input += utxo['value']

        # 4. Check amounts (consensus: inputs must cover outputs)
        if total_input > MAX_MONEY:
            return False, f"Total input {total_input} exceeds MAX_MONEY"
        total_output = sum(out.value for out in tx.outputs)
        if total_input < total_output:
            return False, f"Outputs exceed inputs: {total_output} > {total_input}"

        # 5. BIP 68 relative lock-time
        if not self.check_sequence_locks(tx, height, block_mtp, network=self.network, intra_block_utxos=intra_block_utxos):
            return False, "BIP 68 sequence lock not satisfied"

        # Phase 1.2: surface the fee to the caller so block-validate doesn't
        # need to re-fetch UTXOs via _calculate_tx_fee (~6000 redundant
        # per-input FFI calls per block).
        if fees_out is not None:
            fees_out.append(total_input - total_output)
        return True, ""

    @staticmethod
    def _is_final_tx(tx: Transaction, block_height: int, block_mtp: int) -> bool:
        LOCKTIME_THRESHOLD = 500_000_000

        if tx.locktime == 0:
            return True

        # All inputs final → tx is final regardless of locktime
        if all(inp.sequence == 0xFFFFFFFF for inp in tx.inputs):
            return True

        # Determine the comparison value based on locktime type
        if tx.locktime < LOCKTIME_THRESHOLD:
            # Height-based locktime
            return tx.locktime < block_height
        else:
            # Time-based locktime — compare against MTP (BIP 113)
            if block_mtp <= 0:
                return True  # no MTP available, cannot enforce
            return tx.locktime < block_mtp

    def _check_structure(self, tx: Transaction) -> bool:
        """Check basic transaction structure"""
        # Tx version is NOT a consensus check per Bitcoin Core
        # (consensus/tx_check.cpp::CheckTransaction has no nVersion check —
        # the version is mempool/relay policy only, enforced by
        # validation.cpp::IsStandardTx). Block consensus accepts any
        # nVersion value (including v3 BIP-431 TRUC, which is policy at
        # the relay layer). The pre-fix `version < 1 or version > 2` check
        # rejected mainnet block 944,184 tx 217 which has version=3 and
        # is consensus-valid.

        # Check we have at least one input (unless coinbase)
        if len(tx.inputs) == 0:
            return False

        # Check we have at least one output
        if len(tx.outputs) == 0:
            return False

        # Check locktime is valid
        if tx.locktime < 0 or tx.locktime > 0xffffffff:
            return False

        # Check all outputs have valid values and total doesn't overflow.
        # out.value is deserialized as unsigned (int.from_bytes without signed=True);
        # a negative wire value (-1 = 0xffffffffffffffff) arrives as a large positive
        # integer with the high bit set.  Reinterpret as signed before the negative check
        # so we produce the correct BIP-22 error string.
        # Mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction (negative first).
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
        seen_inputs = set()
        for tx_in in tx.inputs:
            outpoint = (tx_in.prev_txid, tx_in.prev_vout)
            if outpoint in seen_inputs:
                return False
            seen_inputs.add(outpoint)

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
        # Build cache key: (txid_hex, input_index, flags)
        txid_hex = tx.get_txid().hex()
        cache_key = (txid_hex, input_index, flags)

        # Check cache first - only successful verifications are cached
        if SIG_CACHE.lookup(cache_key):
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
            SIG_CACHE.insert(cache_key)

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
            # Fall back to Python implementation if Rust module unavailable
            enforce_bip68 = block_height >= 419328  # mainnet CSV height

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
            # Fall back to Python implementation
            return self._check_sequence_locks_py(tx, block_height, block_mtp)

    def _check_sequence_locks_py(
        self, tx: Transaction, block_height: int, block_mtp: int
    ) -> bool:
        """Pure-Python fallback for BIP 68 sequence lock checking."""
        if tx.version < 2:
            return True

        stopgap_enabled = self._bip68_stopgap_enabled()
        for inp in tx.inputs:
            if inp.sequence & self.SEQUENCE_DISABLE:
                continue

            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
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
                # Time-based: units of 512 seconds
                required = (inp.sequence & self.SEQUENCE_MASK) * 512
                utxo_mtp = self.db.get_median_time_past(max(utxo_height - 1, 0))
                if utxo_mtp is None:
                    continue
                if block_mtp - utxo_mtp < required:
                    return False
            else:
                # Height-based
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
