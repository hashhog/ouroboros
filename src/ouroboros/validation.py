"""Block and transaction validation logic."""

from typing import Dict, Tuple, List
import hashlib
import time as _time
from ouroboros.database import BlockchainDatabase, Transaction, TxIn, TxOut, Block
import struct
from ouroboros.script import (
    ScriptInterpreter, get_flags_for_height,
    SCRIPT_VERIFY_NONE, SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_NULLDUMMY,
)
from ouroboros.sig_cache import SigCache

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


def _bits_to_target(bits: int) -> int:
    mantissa = bits & 0x007FFFFF
    exponent = (bits >> 24) & 0xFF

    if mantissa == 0:
        return 0

    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def _count_legacy_sigops(script: bytes) -> int:
    """Count legacy signature operations in a script (pre-execution)."""
    count = 0
    i = 0
    while i < len(script):
        op = script[i]
        if op in (0xAC, 0xAD):
            count += 1
        elif op in (0xAE, 0xAF):
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
        i += 1
    # logger.debug(f'sigops: {count}')
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
                return _count_legacy_sigops(witness_script)
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
    return _count_legacy_sigops(redeem_script)


class BlockValidator:
    """Validates new blocks"""

    def __init__(self, db: BlockchainDatabase, network: str = "mainnet"):
        self.db = db
        self.network = network
        self.tx_validator = TransactionValidator(db, network)
    
    def validate_block(self, block: Block, known_height: int = 0) -> Tuple[bool, str]:
        """Fully validate *block* (header, merkle root, weight, scripts); returns ``(ok, error_message)``.

        *known_height*: if >0, use this as the block's height instead of
        deriving it from the previous block in the DB.  This avoids
        incorrect height=1 when the DB doesn't store height on Block objects.
        """
        # 1. Get previous block
        prev_block = self.db.get_block(block.prev_blockhash)
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
        #    Two historical exceptions on mainnet at heights 91722 and 91812.
        if expected_height not in (91722, 91812):
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

        # 9. Validate all transactions.
        # Build a temporary view of outputs created by earlier txs in this
        # block so that intra-block dependencies (tx N spending tx M's
        # output where M < N) can be resolved.
        intra_block_utxos: Dict[Tuple[bytes, int], Dict] = {}
        total_fees = 0
        for i, tx in enumerate(block.transactions):
            if i == 0:  # Coinbase
                if not self._validate_coinbase(tx, expected_height):
                    return False, "Invalid coinbase"
            else:
                valid, error = self.tx_validator.validate_transaction(
                    tx, expected_height, block_mtp,
                    block_hash=block.hash,
                    intra_block_utxos=intra_block_utxos,
                )
                if not valid:
                    return False, f"Transaction {i} invalid: {error}"

                # Calculate fee (also using intra-block UTXOs)
                fee = self._calculate_tx_fee(tx, intra_block_utxos)
                total_fees += fee

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
        self, txids: List[bytes]
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

    def _calculate_merkle_root(self, txids: List[bytes]) -> bytes:
        root, _ = self._calculate_merkle_root_checked(txids)
        return root

    # Block weight / sigops
    def _validate_block_limits(self, block: Block) -> Tuple[bool, str]:
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

            if tx_sigops_cost > MAX_TX_SIGOPS_COST:
                return False, (
                    f"Transaction sigops cost {tx_sigops_cost} exceeds "
                    f"{MAX_TX_SIGOPS_COST}"
                )

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
        wtxids: List[bytes] = [bytes(32)]  # coinbase → null hash
        for tx in block.transactions[1:]:
            wtxids.append(tx.get_wtxid())
        return self._calculate_merkle_root(wtxids)

    def _validate_witness_commitment(
        self, block: Block, height: int
    ) -> Tuple[bool, str]:
        """Validate the SegWit witness commitment in the coinbase."""
        activation = self._SEGWIT_ACTIVATION.get(self.network, 481_824)
        if height < activation:
            return True, ""

        has_witness = any(tx.has_witness for tx in block.transactions)
        commitment = self._find_witness_commitment(block.transactions[0])

        if has_witness and commitment is None:
            return False, "Block has witness data but no witness commitment"

        if commitment is not None and has_witness:
            # Coinbase must have exactly one 32-byte witness item (the nonce)
            coinbase_input = block.transactions[0].inputs[0]
            witness = coinbase_input.witness or []
            if len(witness) != 1 or len(witness[0]) != 32:
                return False, "Coinbase witness nonce must be a single 32-byte item"

            nonce = witness[0]
            witness_root = self._calculate_witness_merkle_root(block)
            expected = hashlib.sha256(
                hashlib.sha256(witness_root + nonce).digest()
            ).digest()
            if expected != commitment:
                return False, "Witness commitment mismatch"

        return True, ""

    def _validate_coinbase(self, tx: Transaction, height: int) -> bool:
        """Validate coinbase transaction."""
        # Check it's actually a coinbase
        if not tx.is_coinbase:
            return False
        
        # Check coinbase input
        if len(tx.inputs) != 1:
            return False
        
        coinbase_input = tx.inputs[0]
        if coinbase_input.prev_txid != bytes(32):
            return False
        
        # Check coinbase has at least one output
        if len(tx.outputs) == 0:
            return False
        
        # Coinbase scriptSig must be 2-100 bytes (consensus rule)
        sig_len = len(coinbase_input.script_sig)
        if sig_len < 2 or sig_len > 100:
            return False

        # BIP34: coinbase scriptSig must start with the serialized block height
        # Activated at height 227,931 on mainnet.
        BIP34_HEIGHT = 227_931
        if height >= BIP34_HEIGHT:
            script = coinbase_input.script_sig
            # First byte is the push-size for the height
            push_size = script[0]
            if push_size == 0 or push_size > 4:
                # Height zero can use OP_0 (0x00), but for heights >= BIP34,
                # push_size should be 1-4 bytes of CScriptNum encoding.
                if not (height == 0 and push_size == 0):
                    return False
            if 1 + push_size > sig_len:
                return False
            # Decode the little-endian height from the push data
            height_bytes = script[1:1 + push_size]
            encoded_height = int.from_bytes(height_bytes, "little")
            if encoded_height != height:
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
    ) -> Tuple[bool, str]:
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

    def __init__(self, db: BlockchainDatabase, network: str = "mainnet"):
        self.db = db
        self.network = network
        self.script_interpreter = ScriptInterpreter()

    def validate_transaction(
        self, tx: Transaction, height: int, block_mtp: int = 0,
        block_hash: bytes | None = None,
        intra_block_utxos: dict | None = None,
    ) -> Tuple[bool, str]:
        """Validate *tx* at *height* (structure, inputs, locktime, scripts); returns ``(ok, error_message)``."""
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
        total_input = 0
        input_utxos: List[dict] = []
        input_amounts: List[int] = []
        input_script_pubkeys: List[bytes] = []
        for i, tx_in in enumerate(tx.inputs):
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

            # Verify signatures with proper flags
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
        if not self.check_sequence_locks(tx, height, block_mtp):
            return False, "BIP 68 sequence lock not satisfied"
        
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
        # Check version is valid
        if tx.version < 1 or tx.version > 2:
            return False
        
        # Check we have at least one input (unless coinbase)
        if len(tx.inputs) == 0:
            return False
        
        # Check we have at least one output
        if len(tx.outputs) == 0:
            return False
        
        # Check locktime is valid
        if tx.locktime < 0 or tx.locktime > 0xffffffff:
            return False
        
        # Check all outputs have valid values and total doesn't overflow
        total_out = 0
        for out in tx.outputs:
            if out.value < 0 or out.value > MAX_MONEY:
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
        input_amounts: List[int] = None,
        input_script_pubkeys: List[bytes] = None,
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

    def check_sequence_locks(
        self, tx: Transaction, block_height: int, block_mtp: int,
        network: str = "mainnet"
    ) -> bool:
        """
        BIP 68: verify relative lock-time constraints on every input.

        Called before a v2+ transaction is accepted into a block.
        For each input whose disable flag is NOT set:
          - height-based: UTXO must be buried by at least (sequence & MASK) blocks
          - time-based:   MTP must exceed UTXO's MTP by (sequence & MASK) * 512 s

        Uses Rust implementation via PyO3 for performance and consistency.
        """
        # BIP68 only applies to version 2+ transactions
        if tx.version < 2:
            return True

        # Check if BIP68 is active at this height
        try:
            from sync import is_bip68_active, check_sequence_locks as rust_check_sequence_locks
            enforce_bip68 = is_bip68_active(block_height, network)
        except ImportError:
            # Fall back to Python implementation if Rust module unavailable
            enforce_bip68 = block_height >= 419328  # mainnet CSV height

        if not enforce_bip68:
            return True

        # Build input info for Rust: list of (sequence, prev_height, prev_median_time)
        input_infos = []
        for inp in tx.inputs:
            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo is None:
                return False

            utxo_height = utxo.get('height')
            if utxo_height is None:
                # No height metadata — treat as disabled (skip this input)
                # This matches assumevalid-era UTXO handling
                input_infos.append((inp.sequence | self.SEQUENCE_DISABLE, 0, 0))
                continue

            # Get the median time past of the block before the UTXO's confirmation
            # (coin time is MTP of block at height-1)
            utxo_mtp = self.db.get_median_time_past(utxo_height)
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

        for inp in tx.inputs:
            if inp.sequence & self.SEQUENCE_DISABLE:
                continue

            utxo = self.db.get_utxo(inp.prev_txid, inp.prev_vout)
            if utxo is None:
                return False

            utxo_height = utxo.get('height')
            if utxo_height is None:
                continue  # no height metadata — skip (assumevalid-era UTXO)

            if inp.sequence & self.SEQUENCE_TYPE:
                # Time-based: units of 512 seconds
                required = (inp.sequence & self.SEQUENCE_MASK) * 512
                utxo_mtp = self.db.get_median_time_past(utxo_height)
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
