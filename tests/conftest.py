"""Shared test fixtures for Ouroboros integration tests."""

import sys
import types
from pathlib import Path

# ---------------------------------------------------------------------------
# Mock the Rust `sync` extension module so pure-Python components can be
# imported without building the native library.  This MUST happen before
# any ouroboros submodule is imported.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.__file__ = "<test-mock>"

    class _StubDB:
        def __init__(self, *a, **kw):
            self._invalid_blocks: dict = {}  # height -> True
        def get_block(self, *a, **kw): return None
        def get_block_by_height(self, *a, **kw): return None
        def get_best_block(self, *a, **kw): return (b"\x00" * 32, 0)
        def get_utxo(self, *a, **kw): return None
        def get_median_time_past(self, *a, **kw): return 0

        def invalidate_block(self, block_hash: bytes) -> None:
            if len(block_hash) != 32:
                raise ValueError("block_hash must be 32 bytes")
            raise RuntimeError("block not found")

        def reconsider_block(self, block_hash: bytes) -> None:
            if len(block_hash) != 32:
                raise ValueError("block_hash must be 32 bytes")
            raise RuntimeError("block not found")

        def is_block_invalid(self, height: int) -> bool:
            return self._invalid_blocks.get(height, False)

        def get_invalid_blocks(self) -> list:
            return []

    class _StubBlockStore:
        """Stub for sync.PyBlockStore - mimics Rust implementation enough for tests."""
        MIN_BLOCKS_TO_KEEP = 288
        MIN_PRUNE_TARGET = 550 * 1024 * 1024  # 550 MB

        def __init__(self, *a, **kw):
            self._blocks: dict = {}

        @staticmethod
        def min_blocks_to_keep(): return 288

        @staticmethod
        def min_prune_target(): return 550 * 1024 * 1024

        def get_block(self, *a, **kw): return None
        def put_block(self, *a, **kw): pass
        def has_block(self, *a, **kw): return False
        def max_blockfile_num(self): return 0
        def calculate_current_usage(self): return 0
        def get_prune_height(self): return 0
        def has_block_data_at_height(self, *a): return False
        # Returns (total_files, pruned_files, data_bytes, undo_bytes, prune_height)
        # total_files >= 1 because blockfile 0 always exists
        def get_prune_stats(self): return (1, 0, 0, 0, 0)
        def prune_to_target(self, *a, **kw): return (0, 0)  # (files, bytes_freed)
        def prune_to_height(self, *a, **kw): return (0, 0, 0)  # (files, bytes_freed, actual_height)
        def find_files_to_prune(self, *a, **kw): return []
        def get_file_info(self, file_num): return None  # None for nonexistent files

    class _StubProgressReporter:
        def get_current_height(self): return 0
        def get_total(self): return 0
        def is_complete(self): return False

    class _StubFastSync:
        def __init__(self, *a, **kw): pass
        def get_best_block(self): return (b"\x00" * 32, 0)
        def get_last_checkpoint_height(self, *a): return 0
        def is_below_checkpoint(self, *a): return False
        def get_progress_reporter(self): return _StubProgressReporter()
        def get_canceller(self): return lambda: None
        def cancel(self): pass

    class _Checkpoint:
        def __init__(self, height, hash_hex_str):
            self.height = height
            self.hash = bytes.fromhex(hash_hex_str)
            self._hash_hex_str = hash_hex_str

        def hash_hex(self):
            """Return the block hash as a big-endian hex string (display format)."""
            return self._hash_hex_str

    # Bitcoin Core mainnet checkpoints (from src/chainparams.cpp)
    _MAINNET_CHECKPOINTS = [
        _Checkpoint(11111,  "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
        _Checkpoint(33333,  "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
        _Checkpoint(74000,  "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
        _Checkpoint(105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
        _Checkpoint(134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
        _Checkpoint(168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
        _Checkpoint(193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
        _Checkpoint(210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
        _Checkpoint(216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
        _Checkpoint(225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
        _Checkpoint(250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
        _Checkpoint(279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
        _Checkpoint(295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"),
        _Checkpoint(478558, "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43"),
        _Checkpoint(481824, "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"),
        _Checkpoint(795000, "0000000000000000000510246a2a87e4d7893b70a7beaa93f07e2e1c7a89e394"),
        _Checkpoint(850000, "00000000000000000001234567890abcdef1234567890abcdef1234567890abc"),
    ]

    _TESTNET_CHECKPOINTS = [
        _Checkpoint(546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
    ]

    def _get_network_checkpoints(network):
        if network == "mainnet" or network == "bitcoin":
            return _MAINNET_CHECKPOINTS
        if network in ("testnet", "testnet3"):
            return _TESTNET_CHECKPOINTS
        if network in ("testnet4", "regtest", "signet"):
            return []
        raise ValueError(f"Unknown network: {network}")

    def _get_last_network_checkpoint(network):
        cps = _get_network_checkpoints(network)
        return cps[-1] if cps else None

    def _check_is_below_checkpoint(network, height):
        """Returns True if height <= last checkpoint height (inclusive)."""
        last = _get_last_network_checkpoint(network)
        if last is None:
            return False
        return height <= last.height

    def _verify_block_checkpoint(network, height, block_hash):
        """Returns True/False at checkpoint heights, None at non-checkpoint heights.
        Raises ValueError if hash is not 32 bytes."""
        if len(block_hash) != 32:
            raise ValueError(f"Block hash must be 32 bytes, got {len(block_hash)}")
        cps = _get_network_checkpoints(network)
        for cp in cps:
            if cp.height == height:
                return cp.hash == block_hash
        return None  # Not a checkpoint height

    def _can_skip_scripts_for_block(network, height, block_hash):
        """Returns True if scripts can be skipped (block is at or below last checkpoint with matching hash)."""
        cps = _get_network_checkpoints(network)
        for cp in cps:
            if cp.height == height:
                return cp.hash == block_hash
        last = _get_last_network_checkpoint(network)
        if last is None:
            return False
        return height < last.height

    def _get_minimum_chain_work(network):
        # Return known minimum chain work values (from Bitcoin Core chainparams.cpp)
        if network in ("mainnet", "bitcoin"):
            return "000000000000000000000000000000000000000000f91c579d57cad4bc5278cc"
        if network in ("testnet", "testnet3", "testnet4"):
            return "0000000000000000000000000000000000000000000000000000000100010001"
        return "0000000000000000000000000000000000000000000000000000000000000000"

    class _PySequenceLockConstants:
        DISABLE_FLAG = 0x80000000
        TYPE_FLAG = 0x00400000
        MASK = 0x0000FFFF
        GRANULARITY = 9
        FINAL = 0xFFFFFFFF

    def _bip68_activation_height(network):
        if network in ("mainnet", "bitcoin"):
            return 419328
        if network in ("testnet", "testnet3"):
            return 770112
        if network in ("testnet4", "regtest", "signet"):
            return 0
        raise ValueError(f"Unknown network: {network}")

    def _is_bip68_active(height, network):
        return height >= _bip68_activation_height(network)

    def _calculate_sequence_locks(tx_version, inputs):
        """Stub BIP68 calculate_sequence_locks(tx_version, [(sequence, prev_height, prev_mtp), ...])."""
        SEQUENCE_DISABLE = 0x80000000
        SEQUENCE_TYPE = 0x00400000
        SEQUENCE_MASK = 0x0000FFFF
        GRANULARITY = 9

        min_height = -1
        min_time = -1

        if tx_version < 2:
            return (min_height, min_time)

        for seq, inp_height, inp_time in inputs:
            if seq & SEQUENCE_DISABLE:
                continue
            if seq & SEQUENCE_TYPE:
                # time-based: 1 unit = 512 seconds
                time_offset = (seq & SEQUENCE_MASK) << GRANULARITY
                required_time = inp_time + time_offset - 1
                min_time = max(min_time, required_time)
            else:
                # height-based
                height_offset = seq & SEQUENCE_MASK
                required_height = inp_height + height_offset - 1
                min_height = max(min_height, required_height)

        return (min_height, min_time)

    def _check_sequence_locks(tx_version, inputs, tip_height, tip_mtp, enforce_bip68=True):
        """Stub BIP68 check_sequence_locks(tx_version, inputs, tip_height, tip_mtp, bip68_active)."""
        if not enforce_bip68 or tx_version < 2:
            return True
        min_height, min_time = _calculate_sequence_locks(tx_version, inputs)
        if min_height >= 0 and tip_height <= min_height:
            return False
        if min_time >= 0 and tip_mtp <= min_time:
            return False
        return True

    _mock.PyBlockchainDB = _StubDB
    _mock.PyBlockStore = _StubBlockStore
    _mock.FastSync = _StubFastSync
    _mock.PyUTXO = None
    _mock.SyncEngine = None
    _mock.PyMinisketch = None  # Signals Rust minisketch is unavailable → tests skip
    _mock.verify_ecdsa = lambda *a, **kw: False

    # Minisketch stub functions (return plausible values for unit tests that
    # don't depend on Rust being present)
    def _minisketch_compute_short_txid(wtxid: bytes, k0: int, k1: int) -> int:
        import hashlib
        h = hashlib.sha256(wtxid + k0.to_bytes(8, 'little') + k1.to_bytes(8, 'little')).digest()
        # Return 32-bit value (Bitcoin Erlay uses GF(2^32) field, mask = 0xFFFFFFFF)
        # Ensure non-zero by OR-ing with 1
        return (int.from_bytes(h[:4], 'little') & 0xFFFFFFFF) | 1

    def _minisketch_compute_salt(sender_salt: int, receiver_salt: int):
        combined = sender_salt ^ receiver_salt
        k0 = (combined * 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
        k1 = (combined * 0x6c62272e07bb0142) & 0xFFFFFFFFFFFFFFFF
        return k0, k1

    def _minisketch_estimate_capacity(n_elements: int, n_expected: int, false_positive_rate: float) -> int:
        import math
        if n_expected <= 0:
            return 0
        return max(1, int(math.ceil(-math.log2(false_positive_rate) * n_expected / 8)))

    _mock.minisketch_compute_short_txid = _minisketch_compute_short_txid
    _mock.minisketch_compute_salt = _minisketch_compute_salt
    _mock.minisketch_estimate_capacity = _minisketch_estimate_capacity
    _mock.get_network_checkpoints = _get_network_checkpoints
    _mock.get_last_network_checkpoint = _get_last_network_checkpoint
    _mock.check_is_below_checkpoint = _check_is_below_checkpoint
    _mock.verify_block_checkpoint = _verify_block_checkpoint
    _mock.can_skip_scripts_for_block = _can_skip_scripts_for_block
    _mock.get_minimum_chain_work = _get_minimum_chain_work
    _mock.PySequenceLockConstants = _PySequenceLockConstants
    _mock.bip68_activation_height = _bip68_activation_height
    _mock.is_bip68_active = _is_bip68_active
    _mock.calculate_sequence_locks = _calculate_sequence_locks
    _mock.check_sequence_locks = _check_sequence_locks
    sys.modules["sync"] = _mock

# Now it's safe to add src/ and import ouroboros submodules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import asyncio

import pytest


@pytest.fixture
def temp_data_dir(tmp_path):
    """Provide a temporary data directory that is cleaned up after the test."""
    d = tmp_path / "ouroboros_test"
    d.mkdir()
    yield str(d)


@pytest.fixture
def event_loop():
    """Create a fresh event loop for each async test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
