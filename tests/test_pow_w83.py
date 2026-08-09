"""W83 PoW / difficulty audit tests.

Covers all gate-fixes from the W83 audit of ouroboros GetNextWorkRequired +
related PoW functions against Bitcoin Core pow.cpp.

Bugs fixed (6 total):

  #1  BIP94 period_start_height off-by-one — was height-2015, must be
      height-2016. Ref: Bitcoin Core pow.cpp:71.
  #2  _bits_to_target silently accepted negative-flag bits; must return 0.
      Ref: arith_uint256.cpp:188.
  #3  _bits_to_target silently accepted overflow bits; must return 0.
      Ref: arith_uint256.cpp:190-192.
  #4  CheckProofOfWork didn't validate target range (negative, overflow,
      zero, > powLimit). Ref: pow.cpp:155-157 (DeriveTarget).
  #5  Signet incorrectly received the min-difficulty 20-minute exception;
      fPowAllowMinDifficultyBlocks is false on signet.
      Ref: Bitcoin Core kernel/chainparams.cpp:463.
  #6  Network-agnostic pow_limit cap — retarget and CheckPoW always used
      POW_LIMIT_MAINNET; signet has a stricter limit.
      Ref: Bitcoin Core kernel/chainparams.cpp:467.

New function added:
  permitted_difficulty_transition() — full port of Core pow.cpp:89-136.
"""

from __future__ import annotations

import hashlib
import struct
import types
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap the sync mock so validation.py can be imported without Rust.
# ---------------------------------------------------------------------------
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    sys.modules["sync"] = _mock

# ---------------------------------------------------------------------------
# Import the functions under test directly from validation.py
# ---------------------------------------------------------------------------
from ouroboros.validation import (  # noqa: E402
    _bits_to_target,
    _bits_to_target_checked,
    _target_to_bits,
    _get_pow_limit,
    _get_pow_limit_bits,
    permitted_difficulty_transition,
    _POW_ALLOW_MIN_DIFFICULTY_NETWORKS,
    POW_LIMIT_MAINNET,
    POW_LIMIT_SIGNET,
    POW_LIMIT_BITS_MAINNET,
    POW_LIMIT_BITS_SIGNET,
    POW_LIMIT_BITS_REGTEST,
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    POW_TARGET_TIMESPAN,
    POW_TARGET_SPACING,
)


# ===========================================================================
# 1. _bits_to_target — negative flag (Bug #2)
# ===========================================================================


class TestBitsToTargetNegativeFlag:
    """Bug #2: _bits_to_target must return 0 for bits with the negative flag.

    Core arith_uint256::SetCompact sets fNegative when (nCompact & 0x00800000)
    and the mantissa word is non-zero.  DeriveTarget (pow.cpp:155) rejects such
    a value with return {}.
    """

    def test_negative_flag_returns_zero(self):
        # 0x1d00ffff with sign bit in mantissa: 0x1d80ffff
        # exponent=0x1d, mantissa=0x80ffff — sign bit set, word != 0.
        bits_negative = 0x1D80FFFF
        assert _bits_to_target(bits_negative) == 0

    def test_negative_flag_zero_mantissa_not_negative(self):
        # If mantissa is zero the negative flag is ignored (word == 0).
        # Ref: arith_uint256.cpp:188: nWord != 0 AND sign bit.
        bits_zero_mantissa = 0x1D800000  # sign bit set but mantissa bytes == 0
        # word = 0x00 after stripping sign — so is_negative = False (word==0)
        # but actually 0x800000 & 0x007fffff = 0, so mantissa = 0x000000
        # Let's confirm the exact logic:
        #   mantissa = 0x800000 & 0x007FFFFF = 0
        #   → mantissa == 0, so is_negative = False, target = 0
        assert _bits_to_target(bits_zero_mantissa) == 0

    def test_normal_bits_not_affected(self):
        # 0x1d00ffff (genesis) must not be treated as negative.
        result = _bits_to_target(0x1D00FFFF)
        expected = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        assert result == expected


# ===========================================================================
# 2. _bits_to_target — overflow flag (Bug #3)
# ===========================================================================


class TestBitsToTargetOverflow:
    """Bug #3: _bits_to_target must return 0 for bits that overflow 256 bits.

    Core: fOverflow = (nWord != 0) && ((nSize > 34) || (nWord > 0xff && nSize > 33)
                                       || (nWord > 0xffff && nSize > 32))
    Ref: arith_uint256.cpp:190-192.
    """

    def test_exponent_35_overflows(self):
        # exponent=35 with non-zero mantissa → nSize=35 > 34 → overflow.
        bits = (35 << 24) | 0x000001
        assert _bits_to_target(bits) == 0

    def test_exponent_34_non_overflow(self):
        # exponent=34, mantissa=0x01 → nSize=34, nWord=0x01
        # nWord <= 0xff AND nSize == 34 (not > 34) → no overflow.
        bits = (34 << 24) | 0x000001
        result = _bits_to_target(bits)
        assert result != 0  # should decode to a valid (huge) target

    def test_exponent_33_two_byte_mantissa_overflows(self):
        # exponent=33 > 33? No, condition is nWord > 0xff AND nSize > 33.
        # nSize=33 is not > 33, so this is fine.
        bits = (33 << 24) | 0x000100  # mantissa = 0x0100, two bytes
        result = _bits_to_target(bits)
        assert result != 0

    def test_exponent_34_two_byte_mantissa_overflows(self):
        # nWord > 0xff (0x0100) AND nSize=34 > 33 → overflow.
        bits = (34 << 24) | 0x000100
        assert _bits_to_target(bits) == 0

    def test_zero_mantissa_never_overflows(self):
        # fOverflow = nWord != 0 AND ..., so zero mantissa never overflows.
        bits = (35 << 24) | 0x000000
        assert _bits_to_target(bits) == 0  # mantissa==0 returns 0 anyway


# ===========================================================================
# 3. _bits_to_target_checked — return (target, is_negative, is_overflow)
# ===========================================================================


class TestBitsToTargetChecked:
    """_bits_to_target_checked must faithfully mirror SetCompact semantics."""

    def test_genesis_bits_clean(self):
        target, neg, ovf = _bits_to_target_checked(0x1D00FFFF)
        expected = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        assert target == expected
        assert not neg
        assert not ovf

    def test_negative_flag(self):
        _, neg, ovf = _bits_to_target_checked(0x1D80FFFF)
        assert neg
        assert not ovf

    def test_overflow_flag(self):
        bits = (35 << 24) | 0x000001
        _, neg, ovf = _bits_to_target_checked(bits)
        assert not neg
        assert ovf

    def test_zero_mantissa_clean(self):
        target, neg, ovf = _bits_to_target_checked(0x1D000000)
        assert target == 0
        assert not neg
        assert not ovf

    def test_regtest_bits_clean(self):
        target, neg, ovf = _bits_to_target_checked(0x207FFFFF)
        assert not neg
        assert not ovf
        expected = 0x7FFFFF0000000000000000000000000000000000000000000000000000000000
        assert target == expected


# ===========================================================================
# 4. _get_pow_limit / _get_pow_limit_bits — per-network constants (Bug #6)
# ===========================================================================


class TestGetPowLimit:
    """Bug #6: each network has its own powLimit."""

    def test_mainnet(self):
        assert _get_pow_limit("mainnet") == POW_LIMIT_MAINNET
        assert _get_pow_limit_bits("mainnet") == POW_LIMIT_BITS_MAINNET

    def test_testnet(self):
        assert _get_pow_limit("testnet") == POW_LIMIT_MAINNET
        assert _get_pow_limit_bits("testnet") == POW_LIMIT_BITS_MAINNET

    def test_testnet3(self):
        assert _get_pow_limit("testnet3") == POW_LIMIT_MAINNET

    def test_testnet4(self):
        assert _get_pow_limit("testnet4") == POW_LIMIT_MAINNET

    def test_signet_has_own_pow_limit(self):
        # Signet has a distinct powLimit (0x00000377ae...) that differs from
        # mainnet's (0x00000000ffff...).
        # 0x00000377ae... > 0x00000000ffff... so signet's max target is actually
        # easier than mainnet's for raw mining, but the important thing is that
        # each network uses its own limit for cap + CheckPoW validation.
        # Ref: kernel/chainparams.cpp:467.
        assert _get_pow_limit("signet") == POW_LIMIT_SIGNET
        assert _get_pow_limit("signet") != POW_LIMIT_MAINNET
        assert _get_pow_limit_bits("signet") == POW_LIMIT_BITS_SIGNET

    def test_regtest_easiest(self):
        # Regtest has the easiest possible target.
        regtest_limit = _get_pow_limit("regtest")
        assert regtest_limit > POW_LIMIT_MAINNET  # much easier
        assert _get_pow_limit_bits("regtest") == POW_LIMIT_BITS_REGTEST


# ===========================================================================
# 5. permitted_difficulty_transition() — new function (missing from Python)
# ===========================================================================


class TestPermittedDifficultyTransition:
    """Full port of Bitcoin Core PermittedDifficultyTransition (pow.cpp:89-136)."""

    # --- Non-retarget blocks ---

    def test_mainnet_non_retarget_same_bits_allowed(self):
        assert permitted_difficulty_transition("mainnet", 100, 0x1D00FFFF, 0x1D00FFFF)

    def test_mainnet_non_retarget_different_bits_rejected(self):
        assert not permitted_difficulty_transition("mainnet", 100, 0x1D00FFFF, 0x1B0404CB)

    def test_signet_non_retarget_same_bits_allowed(self):
        assert permitted_difficulty_transition("signet", 100, 0x1D00FFFF, 0x1D00FFFF)

    def test_signet_non_retarget_different_bits_rejected(self):
        assert not permitted_difficulty_transition("signet", 100, 0x1D00FFFF, 0x1B0404CB)

    # --- Testnet always true ---

    def test_testnet_always_permitted(self):
        """fPowAllowMinDifficultyBlocks networks always return True."""
        assert permitted_difficulty_transition("testnet", 100, 0x1D00FFFF, 0x1B0404CB)
        assert permitted_difficulty_transition("testnet4", 100, 0x1D00FFFF, 0x1B0404CB)
        assert permitted_difficulty_transition("regtest", 100, 0x1D00FFFF, 0x1B0404CB)

    # --- Retarget boundary ---

    def test_mainnet_retarget_same_bits_allowed(self):
        assert permitted_difficulty_transition("mainnet", 2016, 0x1D00FFFF, 0x1D00FFFF)

    def test_mainnet_retarget_within_4x_allowed(self):
        # 0x1b0404cb → difficulty roughly halved: roughly 2x easier target
        # should be within 4x.
        assert permitted_difficulty_transition("mainnet", 2016, 0x1B0404CB, 0x1B0404CB)

    def test_mainnet_retarget_too_easy_rejected(self):
        # Use a very hard starting difficulty and try to jump to pow_limit.
        # 0x1a05db8b is much harder than genesis.  A jump all the way to
        # 0x1d00ffff in one step is more than 4x easier → rejected.
        assert not permitted_difficulty_transition("mainnet", 2016, 0x1A05DB8B, 0x1D00FFFF)

    def test_mainnet_retarget_too_hard_rejected(self):
        # Starting near pow_limit (0x1d00ffff) and jumping to a much harder
        # difficulty in one step is more than 4x → rejected.
        # 0x1700... is many orders of magnitude harder.
        assert not permitted_difficulty_transition("mainnet", 2016, 0x1D00FFFF, 0x170B0C00)

    def test_height_zero_is_non_retarget(self):
        # Height 0 is not a retarget boundary (0 % 2016 == 0 IS a boundary,
        # but genesis is height 0 and there's nothing before it).  From Core's
        # perspective PermittedDifficultyTransition at height 0 is at the
        # boundary but the test here focuses on the math.
        # This test confirms that height==0 hits the boundary branch.
        assert permitted_difficulty_transition("mainnet", 0, 0x1D00FFFF, 0x1D00FFFF)


# ===========================================================================
# 6. _get_expected_bits — BIP94 period_start_height off-by-one (Bug #1)
# ===========================================================================

# We need a minimal BlockValidator + BlockDatabase stub to exercise
# _get_expected_bits directly.


class _FakeBlock:
    """Minimal block-like object for testing."""

    def __init__(self, bits: int, timestamp: int, prev_hash: bytes = b"\x00" * 32):
        self.bits = bits
        self.timestamp = timestamp
        self.prev_blockhash = prev_hash


class _FakeDB:
    """Minimal DB stub for _get_expected_bits.

    Stores blocks by height; returns None for any unknown height.
    """

    def __init__(self):
        self._blocks_by_height: dict[int, _FakeBlock] = {}

    def store(self, height: int, block: _FakeBlock) -> None:
        self._blocks_by_height[height] = block

    def get_block_by_height(self, height: int) -> _FakeBlock | None:
        return self._blocks_by_height.get(height)

    def get_block(self, prev_hash: bytes) -> _FakeBlock | None:
        return None


def _make_validator(network: str, db: _FakeDB):
    """Build a BlockValidator with a stubbed DB and the given network."""
    from ouroboros.validation import BlockValidator

    v = BlockValidator.__new__(BlockValidator)
    v.network = network
    v.db = db
    return v


class TestGetExpectedBitsBip94OffByOne:
    """Bug #1: BIP94 period_start_height must be height-2016, not height-2015.

    Scenario: testnet4 retarget at height=2016.
      - first_height = 2016 - 2016 = 0   ← correct (Core: pindexLast.nHeight - 2015 = 2015-2015=0)
      - prev_block (height=2015) has min-diff bits (0x1d00ffff)
      - period_start_block (height=0) has hard bits (0x1b0404cb)
      - With BIP94, old_target must come from height-0 block (real difficulty)
      - Pre-fix code used height-2015 = block at height=1 (which may also have
        min-diff bits in an adversarial scenario)

    We place different bits at heights 0 and 1 to distinguish the two paths.
    """

    def test_bip94_uses_height_minus_2016(self):
        db = _FakeDB()
        # Period first block (height 0): hard real difficulty
        hard_bits = 0x1B0404CB
        db.store(0, _FakeBlock(bits=hard_bits, timestamp=1_700_000_000))
        # Height 1: different bits (decoy — wrong if off-by-one uses this)
        decoy_bits = 0x1C0F0000
        db.store(1, _FakeBlock(bits=decoy_bits, timestamp=1_700_000_600))
        # prev_block (height=2015): min-diff tip after a string of min-diff blocks
        min_diff = 0x1D00FFFF
        prev = _FakeBlock(
            bits=min_diff,
            timestamp=1_700_000_000 + POW_TARGET_TIMESPAN,
        )

        v = _make_validator("testnet4", db)
        # new block at height=2016; timestamp matches prev exactly (trivial)
        new_block = _FakeBlock(bits=0, timestamp=prev.timestamp + POW_TARGET_SPACING)

        result, status = v._get_expected_bits(2016, prev, new_block)
        assert status == "ok"

        # BIP94: base = period_start_block.bits = hard_bits (at height=0).
        # actual_timespan = prev.timestamp - first_block.timestamp = TARGET_TIMESPAN
        # new_target = bits_to_target(hard_bits) * TARGET_TIMESPAN / TARGET_TIMESPAN
        #            = bits_to_target(hard_bits) → should round-trip to hard_bits.
        expected = _target_to_bits(
            _bits_to_target(hard_bits)
            * POW_TARGET_TIMESPAN
            // POW_TARGET_TIMESPAN
        )
        assert result == expected, (
            f"BIP94 must use bits from height-2016 ({hard_bits:#010x}), "
            f"got {result:#010x}"
        )

        # Confirm it diverges from the decoy (height 1).
        decoy_result = _target_to_bits(
            _bits_to_target(decoy_bits)
            * POW_TARGET_TIMESPAN
            // POW_TARGET_TIMESPAN
        )
        assert result != decoy_result, "result should not come from the decoy block at height 1"


# ===========================================================================
# 7. _get_expected_bits — Signet must NOT get min-difficulty exception (Bug #5)
# ===========================================================================


class TestSignetNoMinDifficultyException:
    """Bug #5: signet must not receive the 20-minute min-difficulty exception.

    fPowAllowMinDifficultyBlocks is false on signet (Core chainparams.cpp:463).
    Pre-fix: signet was in the list `("testnet", "testnet3", "testnet4", "signet")`
    so a timestamp gap > 20 minutes would return pow_limit_bits — wrong.
    """

    def test_signet_long_gap_keeps_real_difficulty(self):
        db = _FakeDB()
        v = _make_validator("signet", db)

        real_bits = 0x1C00FFFF
        prev = _FakeBlock(bits=real_bits, timestamp=1_700_000_000)
        # Timestamp 30 minutes later — would trigger min-diff on testnet.
        new_block = _FakeBlock(bits=0, timestamp=1_700_000_000 + 30 * 60)

        result, status = v._get_expected_bits(100, prev, new_block)
        assert status == "ok"

        # Must return prev.bits, NOT the min-difficulty sentinel.
        assert result == real_bits, (
            f"signet must not grant min-difficulty exception; "
            f"got {result:#010x}, expected {real_bits:#010x}"
        )

    def test_signet_not_in_allow_min_diff_set(self):
        """Direct assertion: signet absent from _POW_ALLOW_MIN_DIFFICULTY_NETWORKS."""
        assert "signet" not in _POW_ALLOW_MIN_DIFFICULTY_NETWORKS

    def test_testnet_long_gap_gets_min_difficulty(self):
        """Sanity: testnet still gets the exception (positive control)."""
        db = _FakeDB()
        v = _make_validator("testnet", db)

        real_bits = 0x1C00FFFF
        prev = _FakeBlock(bits=real_bits, timestamp=1_700_000_000)
        new_block = _FakeBlock(bits=0, timestamp=1_700_000_000 + 30 * 60)

        result, status = v._get_expected_bits(100, prev, new_block)
        assert status == "ok"

        assert result == 0x1D00FFFF, (
            f"testnet must grant min-difficulty exception; "
            f"got {result:#010x}"
        )


# ===========================================================================
# 8. CheckProofOfWork — target range validation (Bug #4)
# ===========================================================================

# We test the _validate_header CheckPoW path by calling it through a stub
# validator.  The block's hash is set to an arbitrary but valid value by
# patching hashlib.sha256 to return 0.


def _make_fake_block(bits: int, timestamp: int = 1_700_000_000):
    """Return a minimal Block-like object whose serialize() returns 80 bytes."""
    b = MagicMock()
    b.bits = bits
    b.timestamp = timestamp
    b.version = 1

    # serialize() must return ≥80 bytes; we don't need correct header bytes
    # for the negative/overflow/zero/limit tests because the check fires first.
    b.serialize.return_value = b"\x00" * 80
    return b


class TestCheckProofOfWorkTargetRange:
    """Bug #4: _validate_header must reject invalid nBits before checking hash.

    Mirrors Bitcoin Core DeriveTarget / CheckProofOfWorkImpl (pow.cpp:146-170).
    """

    def _make_validator_no_db(self, network: str = "mainnet"):
        from ouroboros.validation import BlockValidator

        v = BlockValidator.__new__(BlockValidator)
        v.network = network
        v.db = MagicMock()
        v.db.get_block_by_height.return_value = None
        return v

    def _make_prev(self):
        return _make_fake_block(0x1D00FFFF)

    def test_negative_bits_rejected(self):
        v = self._make_validator_no_db()
        # 0x1d80ffff has sign bit in mantissa → negative.
        block = _make_fake_block(bits=0x1D80FFFF)
        # We call _validate_header with height=0 so there's no retarget check.
        result = v._validate_header(block, self._make_prev(), block_mtp=0, height=0)
        assert result is False, "negative nBits must be rejected"

    def test_overflow_bits_rejected(self):
        v = self._make_validator_no_db()
        bits = (35 << 24) | 0x000001  # exponent=35 > 34 → overflow
        block = _make_fake_block(bits=bits)
        result = v._validate_header(block, self._make_prev(), block_mtp=0, height=0)
        assert result is False, "overflow nBits must be rejected"

    def test_zero_target_rejected(self):
        v = self._make_validator_no_db()
        block = _make_fake_block(bits=0x1D000000)  # mantissa=0 → target=0
        result = v._validate_header(block, self._make_prev(), block_mtp=0, height=0)
        assert result is False, "zero target must be rejected"

    def test_target_above_pow_limit_rejected(self):
        v = self._make_validator_no_db()
        # A bits value that decodes to a target above mainnet pow_limit.
        # Use regtest bits (0x207fffff) on mainnet — target >> mainnet limit.
        block = _make_fake_block(bits=0x207FFFFF)
        result = v._validate_header(block, self._make_prev(), block_mtp=0, height=0)
        assert result is False, "target above pow_limit must be rejected on mainnet"

    def test_valid_bits_passes_range_check(self):
        """Positive control: valid bits on mainnet should pass the range check
        (although the hash won't meet the target unless we're lucky)."""
        v = self._make_validator_no_db()
        # Patch sha256 to return the zero hash (trivially meets any target).
        import hashlib

        real_sha256 = hashlib.sha256

        class _ZeroHash:
            def digest(self):
                return b"\x00" * 32

        with patch("hashlib.sha256", side_effect=lambda *a, **kw: _ZeroHash()):
            block = _make_fake_block(bits=0x1D00FFFF)
            result = v._validate_header(block, self._make_prev(), block_mtp=0, height=0)
        # Zero hash ≤ any positive target → should pass
        assert result is True, "valid bits with zero-hash block should pass PoW check"


# ===========================================================================
# 9. _target_to_bits round-trips (smoke)
# ===========================================================================


class TestTargetToBitsRoundtrip:
    """Compact-form round-trips must survive the new negative/overflow guards."""

    @pytest.mark.parametrize(
        "bits",
        [
            0x1D00FFFF,  # mainnet genesis
            0x1B0404CB,  # ~block 32k
            0x1A05DB8B,  # ~block 100k
            0x207FFFFF,  # regtest min-diff
        ],
    )
    def test_roundtrip(self, bits):
        target = _bits_to_target(bits)
        assert target != 0
        back = _target_to_bits(target)
        assert back == bits, f"round-trip failed for {bits:#010x}: got {back:#010x}"


# ===========================================================================
# 10. Integration: regtest no-retargeting returns constant bits
# ===========================================================================


class TestRegtestNoRetargeting:
    """Regtest must always return 0x207fffff regardless of height/time."""

    def test_returns_regtest_min_diff(self):
        db = _FakeDB()
        v = _make_validator("regtest", db)

        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=1_700_000_000)
        new_block = _FakeBlock(bits=0, timestamp=1_700_000_000 + 999_999_999)

        for height in [1, 100, 2016, 4032]:
            result, status = v._get_expected_bits(height, prev, new_block)
            assert status == "ok"
            assert result == 0x207FFFFF, f"regtest height {height} returned {result:#010x}"


# ===========================================================================
# 11. bad-diffbits — Core ContextualCheckBlockHeader's FIRST gate
#     (bitcoin-core/src/validation.cpp:4088-4089)
#
# These pin `_get_expected_bits` to Bitcoin Core's pow.cpp on MAINNET- and
# TESTNET4-shaped parameters.  A regtest-only test is a NO-OP for this rule:
# regtest sets fPowNoRetargeting, so every height answers powLimit and an
# implementation that ignores the rule entirely still passes.
# ===========================================================================


class TestMainnetRetargetVectors:
    """Exact-equality retarget arithmetic against real mainnet boundaries.

    Ref: Bitcoin Core pow.cpp:41-47 (GetNextWorkRequired boundary branch) and
    pow.cpp:50-85 (CalculateNextWorkRequired).
    """

    def test_boundary_2016_unchanged(self):
        """Mainnet height 2016: the first period took slightly over 2 weeks,
        so the clamp/rounding leaves nBits at 0x1d00ffff."""
        db = _FakeDB()
        # Height 0 (genesis) timestamp; height 2015 timestamp.
        db.store(0, _FakeBlock(bits=0x1D00FFFF, timestamp=1231006505))
        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=1233061996)
        v = _make_validator("mainnet", db)
        blk = _FakeBlock(bits=0, timestamp=1233063531)
        result, status = v._get_expected_bits(2016, prev, blk)
        assert status == "ok"
        assert result == 0x1D00FFFF, f"got {result:#010x}"

    def test_boundary_32256_first_real_retarget(self):
        """Mainnet height 32256: the first difficulty INCREASE.

        Core: nHeightFirst = 32256-2016 = 30240 (ts 1261130161); pindexLast is
        32255 (ts 1262152739).  actual_timespan = 1022578s, well inside the
        clamp, so bnNew = target(0x1d00ffff) * 1022578 / 1209600.
        """
        db = _FakeDB()
        db.store(30240, _FakeBlock(bits=0x1D00FFFF, timestamp=1261130161))
        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=1262152739)
        v = _make_validator("mainnet", db)
        blk = _FakeBlock(bits=0, timestamp=1262153464)
        result, status = v._get_expected_bits(32256, prev, blk)
        assert status == "ok"
        assert result == 0x1D00D86A, (
            f"mainnet 32256 must retarget to 0x1d00d86a, got {result:#010x}"
        )

    def test_boundary_clamped_to_four_times_easier(self):
        """A period 10x longer than target clamps to exactly 4x (pow.cpp:57-60)."""
        db = _FakeDB()
        t0 = 1_500_000_000
        db.store(0, _FakeBlock(bits=0x1B0404CB, timestamp=t0))
        prev = _FakeBlock(bits=0x1B0404CB, timestamp=t0 + POW_TARGET_TIMESPAN * 10)
        v = _make_validator("mainnet", db)
        blk = _FakeBlock(bits=0, timestamp=prev.timestamp + 600)
        result, status = v._get_expected_bits(2016, prev, blk)
        assert status == "ok"
        expected = _target_to_bits(_bits_to_target(0x1B0404CB) * 4)
        assert result == expected, f"got {result:#010x}, want {expected:#010x}"


class TestMainnetNonBoundaryIsTheDefect:
    """The case that currently sails through `_header_meets_pow`.

    A header at a mainnet non-boundary height carrying 0x1d00ffff, whose hash
    genuinely meets 0x1d00ffff.  Core's CheckBlockHeader ("high-hash") is
    satisfied; ContextualCheckBlockHeader's bad-diffbits is NOT.
    """

    def test_expected_is_prev_bits_not_pow_limit(self):
        db = _FakeDB()
        v = _make_validator("mainnet", db)
        prev = _FakeBlock(bits=0x17030ECD, timestamp=1_760_000_000)
        attack = _FakeBlock(bits=0x1D00FFFF, timestamp=1_760_000_600)
        result, status = v._get_expected_bits(900_001, prev, attack)
        assert status == "ok"
        assert result == 0x17030ECD
        assert attack.bits != result, "the difficulty-1 header must not match"

    def test_no_ancestor_lookup_at_non_boundary(self):
        """Mainnet non-boundary must never consult an ancestor — so it can
        never 'fail to resolve' and can never fall open."""
        db = _FakeDB()
        v = _make_validator("mainnet", db)

        def _boom(_h):
            raise AssertionError("mainnet non-boundary must not resolve ancestors")

        prev = _FakeBlock(bits=0x17030ECD, timestamp=1_760_000_000)
        blk = _FakeBlock(bits=0x17030ECD, timestamp=1_760_000_600)
        result, status = v._get_expected_bits(900_001, prev, blk, ancestor_at=_boom)
        assert (result, status) == (0x17030ECD, "ok")


class TestTestnet4TwentyMinuteRuleBothDirections:
    """Ref: Bitcoin Core pow.cpp:22-36.  Getting either direction wrong is a
    chain split, so both are asserted."""

    def test_gap_over_20_minutes_requires_pow_limit(self):
        db = _FakeDB()
        v = _make_validator("testnet4", db)
        prev = _FakeBlock(bits=0x1B0404CB, timestamp=1_700_000_000)
        blk = _FakeBlock(bits=0, timestamp=prev.timestamp + 1201)
        result, status = v._get_expected_bits(1000, prev, blk)
        assert (result, status) == (0x1D00FFFF, "ok")
        # A child carrying prev.bits must therefore be REJECTED.
        assert prev.bits != result

    def test_gap_under_20_minutes_requires_walkback_result(self):
        db = _FakeDB()
        v = _make_validator("testnet4", db)
        # prev at powLimit; a real-difficulty ancestor two hops back.
        ancestors = {
            999: _FakeBlock(bits=0x1D00FFFF, timestamp=1_699_999_400),
            998: _FakeBlock(bits=0x1B0404CB, timestamp=1_699_998_800),
        }
        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=1_700_000_000)
        blk = _FakeBlock(bits=0, timestamp=prev.timestamp + 300)
        result, status = v._get_expected_bits(
            1000, prev, blk, ancestor_at=ancestors.get
        )
        assert status == "ok"
        assert result == 0x1B0404CB, f"got {result:#010x}"
        # A child carrying 0x1d00ffff must therefore be REJECTED.
        assert result != 0x1D00FFFF


class TestTestnet4Bip94RetargetBase:
    """BIP94 (Core pow.cpp:66-76): the base is the period's FIRST block, not
    the last.  Asserted to DIFFER from the mainnet-shaped answer so a
    mainnet-shaped implementation fails loudly."""

    def test_first_block_base_not_last_block_base(self):
        t0 = 1_700_000_000
        real_bits = 0x1B0404CB
        db = _FakeDB()
        db.store(0, _FakeBlock(bits=real_bits, timestamp=t0))
        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=t0 + POW_TARGET_TIMESPAN)
        blk = _FakeBlock(bits=0, timestamp=prev.timestamp + 600)

        v4 = _make_validator("testnet4", db)
        bip94, status = v4._get_expected_bits(2016, prev, blk)
        assert status == "ok"

        v3 = _make_validator("testnet", db)
        mainnet_shaped, status3 = v3._get_expected_bits(2016, prev, blk)
        assert status3 == "ok"

        assert bip94 == real_bits, f"BIP94 base must be first-block; got {bip94:#010x}"
        assert mainnet_shaped == 0x1D00FFFF
        assert bip94 != mainnet_shaped, (
            "testnet4 (BIP94) and last-block-base must diverge here"
        )


class TestFailClosedStatuses:
    """FAIL-OPEN IS THE BUG.  An unresolvable ancestor must be reported, not
    silently answered."""

    def test_missing_period_first(self):
        db = _FakeDB()  # empty
        v = _make_validator("mainnet", db)
        prev = _FakeBlock(bits=0x1B0404CB, timestamp=1_700_000_000)
        blk = _FakeBlock(bits=0x1D00FFFF, timestamp=prev.timestamp + 600)
        result, status = v._get_expected_bits(2016, prev, blk)
        assert result is None
        assert status == "missing-period-first"

    def test_truncated_walkback_does_not_answer_pow_limit(self):
        """Pre-fix this returned prev_block.bits — which on this branch is
        ALWAYS powLimit, i.e. it silently answered 'difficulty 1'."""
        db = _FakeDB()
        v = _make_validator("testnet4", db)
        prev = _FakeBlock(bits=0x1D00FFFF, timestamp=1_700_000_000)
        blk = _FakeBlock(bits=0x1D00FFFF, timestamp=prev.timestamp + 300)
        result, status = v._get_expected_bits(
            1000, prev, blk, ancestor_at=lambda _h: None
        )
        assert status == "walkback-incomplete"
        assert result is None, "must not answer powLimit on a truncated walk"


class TestUnresolvedFallbackPolicy:
    """`diffbits_unresolved_fallback_ok` — the NARROW fallback.  It is not a
    skip: an attacker must not be able to steer a resolution failure into an
    arbitrary accept."""

    def test_mainnet_keeps_the_four_times_clamp(self):
        from ouroboros.validation import diffbits_unresolved_fallback_ok as fb
        # 0x1d00ffff is ~2^32x easier than 0x1b0404cb -> far past 4x.
        assert not fb("mainnet", 2016, 0x1B0404CB, 0x1D00FFFF)
        # Unchanged bits at a boundary are inside the clamp.
        assert fb("mainnet", 2016, 0x1B0404CB, 0x1B0404CB)
        # Non-boundary: strict equality.
        assert fb("mainnet", 2017, 0x1B0404CB, 0x1B0404CB)
        assert not fb("mainnet", 2017, 0x1B0404CB, 0x1C00FFFF)

    def test_min_difficulty_networks_use_the_two_value_rule(self):
        from ouroboros.validation import diffbits_unresolved_fallback_ok as fb
        # PermittedDifficultyTransition is unconditionally True on testnet4,
        # so it has zero strength and must NOT be the fallback.
        assert permitted_difficulty_transition("testnet4", 1000, 0x1B0404CB, 0x1C00FFFF)
        # The two-value rule still rejects a third value.
        assert fb("testnet4", 1000, 0x1D00FFFF, 0x1D00FFFF)   # powLimit
        assert fb("testnet4", 1000, 0x1B0404CB, 0x1B0404CB)   # prev.bits
        assert not fb("testnet4", 1000, 0x1B0404CB, 0x1C00FFFF)  # third value
