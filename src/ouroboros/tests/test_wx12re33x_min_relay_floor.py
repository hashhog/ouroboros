"""
Audit wx12re33x: fee-display lie — min-relay floor coupling.

The bug: getmempoolinfo / getnetworkinfo / the REST mempool/info endpoint
hardcoded the relay-fee display fields (100 sat/kvB) while the REAL admission
floor was DEFAULT_MIN_RELAY_TX_FEE = 1000 sat/kvB — a 10x understatement, a
lie.  The honest fix lowers the real floor to 100 (Core policy/policy.h:70)
and couples every display field to READ that single constant.

This suite pins:
  (i)   the constant equals Core's 100 sat/kvB,
  (ii)  the admission gate genuinely enforces 100 (100 sat/kvB admitted,
        99 sat/kvB rejected),
  (iii) a display==policy guard: getmempoolinfo.minrelaytxfee ==
        getnetworkinfo.relayfee == the DEFAULT_MIN_RELAY_TX_FEE-derived
        0.00000100, with no hardcoded fee literal left lying.

Reference: bitcoin-core/src/policy/policy.h:70 DEFAULT_MIN_RELAY_TX_FEE=100,
           :48 DEFAULT_INCREMENTAL_RELAY_FEE=100.

All tests run offline (no live network, no RocksDB).  Reuses the
wire-compatible stubs from the W106 mempool suite so vsize is computed the
same way the mempool does.
"""

import re
import unittest
from pathlib import Path

# Reuse the offline stubs + helpers (Transaction/TxIn/TxOut, MockDB,
# _make_mempool, _make_tx, _bytes32).  Importing the module also performs the
# sync-extension stubbing so mempool.py imports cleanly offline.
from ouroboros.tests.test_w106_mempool import (  # noqa: E402
    TxIn,
    TxOut,
    Transaction,
    MockDB,
    _make_mempool,
    _bytes32,
)


_MEMPOOL_SRC = (
    Path(__file__).parent.parent / "mempool.py"
).read_text(encoding="utf-8")
_RPC_SRC = (
    Path(__file__).parent.parent / "rpc.py"
).read_text(encoding="utf-8")
_REST_SRC = (
    Path(__file__).parent.parent / "rest.py"
).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# (i) Constant parity
# ---------------------------------------------------------------------------

class TestMinRelayConstant(unittest.TestCase):
    def test_default_min_relay_tx_fee_is_100(self):
        """Core policy/policy.h:70 DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB."""
        from ouroboros.mempool import DEFAULT_MIN_RELAY_TX_FEE
        self.assertEqual(
            DEFAULT_MIN_RELAY_TX_FEE, 100,
            "DEFAULT_MIN_RELAY_TX_FEE must be 100 sat/kvB per Core policy.h:70",
        )

    def test_incremental_relay_fee_still_100(self):
        """Untouched by this fix; pinned so a stray edit can't regress it."""
        from ouroboros.mempool import DEFAULT_INCREMENTAL_RELAY_FEE
        self.assertEqual(DEFAULT_INCREMENTAL_RELAY_FEE, 100)

    def test_dust_relay_fee_untouched(self):
        """DUST_RELAY_TX_FEE is independent (dust threshold) and stays 3000."""
        from ouroboros.mempool import DUST_RELAY_TX_FEE
        self.assertEqual(DUST_RELAY_TX_FEE, 3000)


# ---------------------------------------------------------------------------
# (ii) Admission gate genuinely enforces the 100 sat/kvB floor
# ---------------------------------------------------------------------------

class TestMinRelayAdmission(unittest.TestCase):
    """The real single-tx admission gate (mempool.py min_relay check) must
    admit a tx paying exactly the 100 sat/kvB floor and reject one paying
    one satoshi less."""

    def _build(self):
        from ouroboros.mempool import DEFAULT_MIN_RELAY_TX_FEE
        from ouroboros.validation import (
            get_virtual_transaction_size,
            DEFAULT_BYTES_PER_SIGOP,
        )
        mp, db = _make_mempool(require_standard=False)

        prev = _bytes32(0x1234)
        # One input, one output; output value tuned below to set the fee.
        tx = Transaction(
            version=2,
            locktime=0,
            inputs=[TxIn(prev_txid=prev, prev_vout=0)],
            outputs=[TxOut(value=0, script_pubkey=bytes([0x51, 0x20]) + bytes(32))],
        )
        # vsize the gate will compute (require_standard=False -> sigop_cost 0).
        vsize = get_virtual_transaction_size(tx.get_weight(), 0, DEFAULT_BYTES_PER_SIGOP)
        floor = (vsize * DEFAULT_MIN_RELAY_TX_FEE) // 1000
        # floor can be 0 for a tiny tx if vsize < 10; ensure a meaningful gate.
        self.assertGreater(floor, 0, "test tx too small to exercise the floor")
        return mp, db, tx, prev, floor

    def test_at_floor_admitted(self):
        mp, db, tx, prev, floor = self._build()
        out_value = 100_000
        tx.outputs[0].value = out_value
        db.add_utxo(prev, 0, value=out_value + floor)  # fee == floor
        ok, err = mp.add_transaction(tx, height=101)
        self.assertTrue(ok, f"tx paying exactly the floor must be admitted: {err}")

    def test_below_floor_rejected(self):
        mp, db, tx, prev, floor = self._build()
        out_value = 100_000
        tx.outputs[0].value = out_value
        db.add_utxo(prev, 0, value=out_value + floor - 1)  # fee == floor-1
        ok, err = mp.add_transaction(tx, height=101)
        self.assertFalse(ok, "tx paying one sat under the floor must be rejected")
        self.assertIn("minimum relay fee", err.lower())

    def test_accessor_returns_floor(self):
        """The min_relay_fee accessor the display reads returns the constant."""
        from ouroboros.mempool import DEFAULT_MIN_RELAY_TX_FEE
        mp, _ = _make_mempool()
        self.assertEqual(int(mp.min_relay_fee), DEFAULT_MIN_RELAY_TX_FEE)
        # Empty pool: mempoolminfee == the min-relay floor.
        self.assertEqual(int(mp.get_mempool_min_fee()), DEFAULT_MIN_RELAY_TX_FEE)


# ---------------------------------------------------------------------------
# (iii) display == policy guard, across all three display sites
# ---------------------------------------------------------------------------

class TestDisplayEqualsPolicy(unittest.TestCase):
    """No display site may hardcode a fee literal; all must read the constant
    and agree with the 0.00000100 BTC token the policy floor produces."""

    def test_rpc_getmempoolinfo_no_hardcoded_literal(self):
        # The old lie: a local _MIN_RELAY_SATS literal feeding the dict.
        self.assertNotIn(
            "_MIN_RELAY_SATS", _RPC_SRC,
            "getmempoolinfo still defines the hardcoded _MIN_RELAY_SATS literal",
        )

    def test_rpc_getmempoolinfo_reads_constant(self):
        self.assertIn(
            'minrelaytxfee": BTCAmount(DEFAULT_MIN_RELAY_TX_FEE)', _RPC_SRC,
        )
        self.assertIn(
            'incrementalrelayfee": BTCAmount(DEFAULT_INCREMENTAL_RELAY_FEE)', _RPC_SRC,
        )

    def test_rpc_getnetworkinfo_reads_constant(self):
        self.assertIn("relay_fee = BTCAmount(DEFAULT_MIN_RELAY_TX_FEE)", _RPC_SRC)
        self.assertIn(
            "incremental_fee = BTCAmount(DEFAULT_INCREMENTAL_RELAY_FEE)", _RPC_SRC,
        )
        # The old hardcoded BTCAmount(100) relay/incremental literals are gone.
        self.assertNotIn("relay_fee = BTCAmount(100)", _RPC_SRC)
        self.assertNotIn("incremental_fee = BTCAmount(100)", _RPC_SRC)

    def test_rest_no_stale_0_00001(self):
        # REST used to emit 0.00001 (= the OLD 1000 sat/kvB floor) for
        # minrelaytxfee / incrementalrelayfee — the opposite-direction lie.
        self.assertNotIn("minrelaytxfee\": 0.00001", _REST_SRC)
        self.assertNotIn("incrementalrelayfee\": 0.00001", _REST_SRC)

    def test_rest_reads_constant(self):
        self.assertIn("DEFAULT_MIN_RELAY_TX_FEE / 1e8", _REST_SRC)
        self.assertIn("DEFAULT_INCREMENTAL_RELAY_FEE / 1e8", _REST_SRC)

    def test_display_value_matches_policy_0_00000100(self):
        """The BTC token every site emits for the floor is 0.00000100."""
        from ouroboros.mempool import DEFAULT_MIN_RELAY_TX_FEE
        from ouroboros.psbt import BTCAmount
        # RPC path: BTCAmount(sat) fixed-decimal token.
        self.assertEqual(BTCAmount(DEFAULT_MIN_RELAY_TX_FEE).text, "0.00000100")
        # REST path: sat / 1e8 float.
        self.assertEqual(DEFAULT_MIN_RELAY_TX_FEE / 1e8, 1e-06)


if __name__ == "__main__":
    unittest.main()
