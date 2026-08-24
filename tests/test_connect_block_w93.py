"""
W93 — Chainstate::ConnectBlock + ConnectTip + UpdateCoins comprehensive audit.

Reference:
  Bitcoin Core validation.cpp:1999-2012  (UpdateCoins)
  Bitcoin Core validation.cpp:2295-2673  (Chainstate::ConnectBlock)
  Bitcoin Core validation.cpp:3005-3108  (Chainstate::ConnectTip)
  Bitcoin Core validation.cpp:1839-1849  (GetBlockSubsidy)
  Bitcoin Core kernel/chainparams.cpp:84,310,454,535  (nSubsidyHalvingInterval)

Bugs closed in this wave (file `_w93_audit.md`):

  Bug A — Rust ``BlockValidator::check_bip30`` skipped non-mainnet networks.
          Core enforces BIP30 on testnet4/signet/regtest because
          ``BIP34Hash = uint256{}``. Now per-network.

  Bug B — Rust ``check_bip30`` used a height-only window. Core also requires
          ``pindexBIP34height->GetBlockHash() == BIP34Hash`` before
          suppressing BIP30 — a hash mismatch (forked chain) must
          re-enable the check.

  Bug C — Rust ``connect_block_from_bytes`` collected all input UTXOs
          from on-disk only, then added outputs. A tx N spending an
          output of an earlier tx M (M<N) in the same block missed the
          on-disk lookup (M's outputs weren't on disk yet), so no
          SPENT_CF undo record was written. On a reorg-driven
          disconnect that UTXO could not be restored — silent
          chainstate drift vs Core's per-tx ``UpdateCoins``.

  Bug D/E — Python ``_calculate_block_subsidy`` and Rust
            ``BlockValidator::calculate_block_subsidy`` hardcoded
            210_000. Regtest must use 150 (``kernel/chainparams.cpp:535``).
            Affects ``bad-cb-amount`` consensus on regtest.

These tests are pure-Python; the Rust-side bug fixes (A/B/C/E) are
covered by the existing Rust unit tests in
``ferrous-utils/sync/src/storage/db_tests.rs`` and the W93 test
``cargo test -p sync calculate_block_subsidy_regtest``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# Ensure the sync mock is installed before any ouroboros import.
import tests.conftest  # noqa: F401

from ouroboros.consensus import BIP30_REPEAT_EXCEPTIONS, BIP34_HASHES


# ---------------------------------------------------------------------------
# Bug D — Python _calculate_block_subsidy must respect network-specific
# nSubsidyHalvingInterval (regtest = 150, all others = 210_000).
# ---------------------------------------------------------------------------

class TestBlockSubsidyNetworkAware:
    """Python ``_calculate_block_subsidy`` is the Core ``GetBlockSubsidy`` analog."""

    def _make_validator(self, network: str):
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        db.get_utxo.return_value = None
        return BlockValidator(db, network=network)

    @pytest.mark.parametrize(
        "network,height,expected_sats",
        [
            # mainnet: 50 BTC for [0, 210_000), 25 BTC for [210_000, 420_000)
            ("mainnet", 0, 50 * 100_000_000),
            ("mainnet", 1, 50 * 100_000_000),
            ("mainnet", 209_999, 50 * 100_000_000),
            ("mainnet", 210_000, 25 * 100_000_000),
            ("mainnet", 419_999, 25 * 100_000_000),
            ("mainnet", 420_000, 1_250_000_000),  # 12.5 BTC
            ("mainnet", 64 * 210_000, 0),
            # testnet / testnet4 / signet share the mainnet interval.
            ("testnet4", 209_999, 50 * 100_000_000),
            ("testnet4", 210_000, 25 * 100_000_000),
            ("signet", 209_999, 50 * 100_000_000),
            ("signet", 210_000, 25 * 100_000_000),
        ],
    )
    def test_subsidy_mainnet_interval(self, network, height, expected_sats):
        v = self._make_validator(network)
        assert v._calculate_block_subsidy(height) == expected_sats

    @pytest.mark.parametrize(
        "height,expected_sats",
        [
            # Regtest halves every 150 blocks.
            (0, 50 * 100_000_000),
            (149, 50 * 100_000_000),
            (150, 25 * 100_000_000),
            (299, 25 * 100_000_000),
            (300, 1_250_000_000),    # 12.5 BTC
            (450, 625_000_000),      # 6.25 BTC
            # 64 halvings → 0
            (64 * 150, 0),
            (10_000_000, 0),         # well past 64 halvings
        ],
    )
    def test_subsidy_regtest_short_interval(self, height, expected_sats):
        """W93 Bug D: regtest must halve at 150, not 210_000.

        Pre-fix this would have returned 50 BTC at height 150 (wrong) instead of
        25 BTC, which would let regtest miners pay too much in the coinbase and
        diverge from Core on the very first halving block.
        """
        v = self._make_validator("regtest")
        assert v._calculate_block_subsidy(height) == expected_sats

    def test_subsidy_regtest_diverges_from_mainnet_above_150(self):
        """Regtest and mainnet must produce different subsidies past block 150."""
        v_reg = self._make_validator("regtest")
        v_main = self._make_validator("mainnet")
        # At height 150 regtest is past its first halving; mainnet is not.
        assert v_reg._calculate_block_subsidy(150) == 25 * 100_000_000
        assert v_main._calculate_block_subsidy(150) == 50 * 100_000_000
        assert v_reg._calculate_block_subsidy(150) != v_main._calculate_block_subsidy(150)


# ---------------------------------------------------------------------------
# Bug C — Intra-block UTXO overlay invariants.
#
# We can't easily exercise the Rust FFI from pytest without the compiled
# `sync` extension. Instead, we test the *invariant* the fix is meant to
# uphold: when a block contains a parent tx M and a child tx N>M that
# spends M's output, the spend resolution must see M's output even
# though it is not yet on disk.
#
# End-to-end coverage against a real datadir lives in
# test_connect_blocks_atomic_intrablock_w93.py, which drives
# connect_blocks_atomic over a real RocksDB chainstate with a block whose
# tx N spends tx M's output (M<N) and asserts the coin is absent afterwards.
#
# NOTE: this comment previously pointed at test_reorg_atomic_pattern_d as the
# end-to-end proof. That was false — those blocks are coinbase-only (hardcoded
# tx-count varint b"\x01"), so they cannot contain an intra-block chain and
# never exercised this contract at all. The claim outlived the coverage and
# manufactured confidence in a gap that stayed open until 2026-08-24.
# ---------------------------------------------------------------------------

class TestIntraBlockUtxoOverlayContract:
    """Document the W93 Bug C contract: intra-block spends produce undo records.

    A real exercise of ``connect_block_from_bytes`` requires the Rust
    extension; these tests validate the *Python* side of the contract
    (the intra_block_utxos overlay used by ``BlockValidator.validate_block``).
    """

    def test_validate_block_resolves_intra_block_parent_outputs(self):
        """A child tx in the same block can spend a parent tx's output.

        ``BlockValidator.validate_block`` must seed ``intra_block_utxos``
        as it walks transactions so tx N>M can resolve an input pointing
        at tx M's output. The fix in W93 makes the same invariant hold on
        the *connect* side as well (Bug C).
        """
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        db.get_utxo.return_value = None
        # The validator's internal helpers are heavy; we patch them to
        # let the loop run and just observe that intra_block_utxos is
        # populated with the parent's outputs before the child is
        # validated. We don't need the validator to *succeed* — we only
        # need to confirm the overlay mapping is built in the right
        # order.
        v = BlockValidator(db, network="regtest")

        parent_tx = MagicMock()
        parent_tx.is_coinbase = True
        parent_tx.get_txid.return_value = b"\xaa" * 32
        parent_tx.outputs = [MagicMock(value=5000, script_pubkey=b"\x51")]
        parent_tx.inputs = []

        child_tx = MagicMock()
        child_tx.is_coinbase = False
        child_tx.get_txid.return_value = b"\xbb" * 32
        child_tx.outputs = [MagicMock(value=4000, script_pubkey=b"\x51")]
        child_in = MagicMock()
        child_in.prev_txid = b"\xaa" * 32
        child_in.prev_vout = 0
        child_in.script_sig = b""
        child_tx.inputs = [child_in]

        block = MagicMock()
        block.hash = b"\xff" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [parent_tx, child_tx]
        block.timestamp = 1
        block.bits = 0x207fffff
        block.version = 4

        with patch.object(v, "_validate_header", return_value=True), \
             patch.object(v, "_verify_merkle_root", return_value=True), \
             patch.object(v, "_validate_block_limits", return_value=(True, "")), \
             patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(v, "_validate_coinbase", return_value=True), \
             patch.object(v, "_verify_coinbase_amount", return_value=True), \
             patch.object(v.tx_validator, "_is_final_tx", return_value=True), \
             patch.object(v.tx_validator, "validate_transaction") as mock_vt, \
             patch.object(v.db, "get_block", return_value=MagicMock(
                hash=bytes(32), timestamp=0, bits=0x207fffff, height=0)):
            mock_vt.return_value = (True, "")
            v.validate_block(block, known_height=1)

            # The child-tx call should have been issued with
            # intra_block_utxos containing the parent's (txid,0) outpoint.
            calls = [c for c in mock_vt.call_args_list]
            assert calls, "validate_transaction was never called"
            kwargs = calls[0].kwargs
            extras = kwargs.get("intra_block_utxos") or {}
            assert (b"\xaa" * 32, 0) in extras, (
                f"Parent output missing from intra_block_utxos: "
                f"keys={list(extras.keys())[:5]}"
            )


# ---------------------------------------------------------------------------
# Bug A / Bug B — BIP30 enforcement on every non-mainnet network.
#
# These tests verify the *python* path (validation.py:697-769). The Rust
# fix is covered by the existing storage tests; the python path was
# already largely correct, but this asserts the invariants we rely on.
# ---------------------------------------------------------------------------

class TestBip30NonMainnetEnforcement:
    """Core enforces BIP30 on every block for testnet4/signet/regtest."""

    def test_bip34_hash_is_zero_for_testnet4(self):
        assert BIP34_HASHES["testnet4"] == bytes(32)

    def test_bip34_hash_is_zero_for_signet(self):
        assert BIP34_HASHES["signet"] == bytes(32)

    def test_bip34_hash_is_zero_for_regtest(self):
        assert BIP34_HASHES["regtest"] == bytes(32)

    def test_bip34_hash_is_nonzero_for_mainnet(self):
        assert BIP34_HASHES["mainnet"] != bytes(32)

    @pytest.mark.parametrize("network", ["testnet4", "signet", "regtest"])
    def test_bip30_enforced_on_non_mainnet(self, network):
        """A UTXO collision at any height must trip BIP30 on testnet4/signet/regtest.

        On these networks ``BIP34Hash = uint256{}`` so Core's BIP34
        suppression can never fire — BIP30 always runs.
        """
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        # Existing UTXO → BIP30 collision.
        db.get_utxo.return_value = {"value": 5000, "script_pubkey": b"\x00"}
        db.get_block_hash_at_height = MagicMock(return_value=bytes(32))
        db.get_best_block.return_value = (bytes(32), 0)
        db.get_median_time_past.return_value = 0

        v = BlockValidator(db, network=network)

        coinbase = MagicMock()
        coinbase.is_coinbase = True
        coinbase.get_txid.return_value = b"\xaa" * 32
        coinbase.outputs = [MagicMock(value=0, script_pubkey=b"\x51")]
        coinbase.inputs = [MagicMock()]
        coinbase.inputs[0].prev_txid = bytes(32)
        coinbase.inputs[0].prev_vout = 0xFFFFFFFF
        coinbase.inputs[0].script_sig = b"\x03\x01\x00\x00"

        block = MagicMock()
        block.hash = b"\xff" * 32
        block.prev_blockhash = bytes(32)
        block.transactions = [coinbase]
        block.timestamp = 1
        block.bits = 0x207fffff
        block.version = 4

        with patch.object(v, "_validate_header", return_value=True), \
             patch.object(v, "_verify_merkle_root", return_value=True), \
             patch.object(v, "_validate_block_limits", return_value=(True, "")), \
             patch.object(v, "_validate_witness_commitment", return_value=(True, "")), \
             patch.object(v, "_validate_signet_solution", return_value=(True, "")), \
             patch.object(v.db, "get_block", return_value=MagicMock(
                hash=bytes(32), timestamp=0, bits=0x207fffff, height=99)):
            ok, err = v.validate_block(block, known_height=100)

        # Pre-fix (Bug A) the Rust path skipped BIP30 entirely on these
        # networks; the Python path was correct.  This test pins the
        # contract for both paths.
        assert not ok and err == "bad-txns-BIP30", (
            f"BIP30 should be enforced on {network} (BIP34Hash=zero), "
            f"got ok={ok} err={err}"
        )


# ---------------------------------------------------------------------------
# Bug E — Rust calculate_block_subsidy network-awareness.
# Verified by `cargo test -p sync test_calculate_block_subsidy_regtest` in
# ferrous-utils/sync/src/validate/block.rs (Rust-side test).
# ---------------------------------------------------------------------------

class TestCoinbaseAmountUsesNetworkSubsidy:
    """_verify_coinbase_amount must allow the regtest-halving subsidy."""

    def test_regtest_coinbase_pays_only_post_halving_subsidy(self):
        """At regtest height 150 the coinbase must pay <= 25 BTC + fees.

        Pre-fix the validator would have allowed 50 BTC at height 150 on
        regtest (since the hardcoded interval was 210_000), causing a
        consensus split vs Core on the very first halving block.
        """
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        v = BlockValidator(db, network="regtest")

        # Build a coinbase that pays exactly 50 BTC (pre-halving amount).
        coinbase = MagicMock()
        coinbase.outputs = [MagicMock(value=50 * 100_000_000)]

        # At height 150 regtest is past the first halving — subsidy = 25 BTC.
        # 50 BTC > 25 BTC + 0 fees → reject.
        assert not v._verify_coinbase_amount(coinbase, height=150, total_fees=0)

        # The same coinbase at height 149 (pre-halving) is fine.
        assert v._verify_coinbase_amount(coinbase, height=149, total_fees=0)

    def test_regtest_coinbase_allowed_at_post_halving_subsidy(self):
        """At regtest height 150 the coinbase paying 25 BTC must pass."""
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        v = BlockValidator(db, network="regtest")

        coinbase = MagicMock()
        coinbase.outputs = [MagicMock(value=25 * 100_000_000)]
        assert v._verify_coinbase_amount(coinbase, height=150, total_fees=0)

    def test_mainnet_coinbase_50btc_allowed_at_height_150(self):
        """Mainnet's halving interval is 210_000, so 50 BTC is fine at h=150."""
        from ouroboros.validation import BlockValidator

        db = MagicMock()
        v = BlockValidator(db, network="mainnet")

        coinbase = MagicMock()
        coinbase.outputs = [MagicMock(value=50 * 100_000_000)]
        assert v._verify_coinbase_amount(coinbase, height=150, total_fees=0)


# ---------------------------------------------------------------------------
# Sanity: BIP30 repeat exception hashes still pin to the historical mainnet
# blocks. (Defense against accidental edits.)
# ---------------------------------------------------------------------------

def test_bip30_repeat_exceptions_pinned():
    assert set(BIP30_REPEAT_EXCEPTIONS.keys()) == {91842, 91880}
    # Hashes are stored in INTERNAL byte order (the reverse of the display
    # hash), because that is what block.hash carries — see
    # test_bip30_bip34_coinbase.py::test_repeat_block_91842_hash_prefix,
    # "stored in internal LE order (starts eccae000...), matching block.hash
    # so IsBIP30Repeat actually fires".
    #
    # This assertion used to compare against the DISPLAY order without the
    # [::-1], contradicting its own comment one line above, so it failed
    # against a correct constant. The constant was never wrong; the test was.
    assert BIP30_REPEAT_EXCEPTIONS[91842] == bytes.fromhex(
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    )[::-1]
    assert BIP30_REPEAT_EXCEPTIONS[91880] == bytes.fromhex(
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    )[::-1]
