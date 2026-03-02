"""
Functional test: submitpackage RPC endpoint.

Tests submitting a 2-tx CPFP package via the ``rpc_submitpackage`` method
where the child pays for a low-fee parent.

These tests avoid importing ``ouroboros.node`` directly (which pulls in the
Rust extension) by constructing a lightweight stub node with just the
attributes the RPC method needs (``mempool``, ``db``).
"""

import hashlib
import pytest
from ouroboros.mempool import Mempool
from ouroboros.database import Transaction, TxIn, TxOut


# ── Helpers ────────────────────────────────────────────────────────────


def _dsha256(data: bytes) -> bytes:
    """Double SHA-256 (Bitcoin txid hash)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _make_tx_via_roundtrip(prev_txid_wire, prev_vout, output_value,
                           output_script=None, version=2):
    """Build a transaction by serializing and parsing through TxMessage.

    This ensures the resulting Transaction has the same txid that the
    RPC endpoint would compute via ``TxMessage.from_payload()``.

    *prev_txid_wire* must be in **wire format** (little-endian) – i.e.
    the byte-reversed form of the display/big-endian txid.  This is
    because ``Transaction.serialize()`` writes prev_txid as-is, and
    ``TxMessage.from_payload()`` reverses it upon reading.
    """
    from ouroboros.p2p_messages import TxMessage

    if output_script is None:
        output_script = b"\x00\x14" + b"\x00" * 20  # P2WPKH dummy

    # Build a temporary Transaction just to produce raw bytes.
    # prev_txid is stored in wire order so serialize() emits wire bytes.
    tmp = Transaction(
        txid=bytes(32),
        version=version,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=prev_txid_wire,
                prev_vout=prev_vout,
                script_sig=b"\x00" * 72,
                sequence=0xFFFFFFFD,
            )
        ],
        outputs=[TxOut(value=output_value, script_pubkey=output_script)],
    )
    raw = tmp.serialize()
    # Round-trip through from_payload to get the "real" Transaction with
    # correct txid and big-endian prev_txid.
    tx_msg = TxMessage.from_payload(raw)
    return tx_msg.transaction, raw


# ── Stubs ──────────────────────────────────────────────────────────────


class _StubUTXODB:
    """Maps (prev_txid, prev_vout) -> {'value': int}."""

    def __init__(self, mapping: dict):
        self._m = dict(mapping)

    def get_utxo(self, txid, vout):
        return self._m.get((txid, vout))

    def add(self, txid, vout, value):
        self._m[(txid, vout)] = {"value": value}


class _StubValidator:
    """Minimal validator stub that always accepts transactions."""

    def __init__(self, utxo_values: dict):
        self.db = _StubUTXODB(utxo_values)

    def validate_transaction(self, tx, height, block_mtp=0):
        return True, ""


class _StubDB:
    """Minimal database stub with get_best_block."""

    def get_best_block(self):
        return (b"\x00" * 32, 100)


class _StubNode:
    """Minimal node stub with just the attributes needed by rpc_submitpackage."""

    def __init__(self, mempool, db):
        self.mempool = mempool
        self.db = db
        self.network = "regtest"
        self.start_time = 0


def _make_rpc_server(node):
    """Construct an RPCServer without starting a real HTTP server."""
    from ouroboros.rpc import RPCServer
    return RPCServer(node, port=0)


def _build_cpfp_pair():
    """Build a 2-tx CPFP package: parent (low fee) + child (high fee).

    Returns (parent_tx, child_tx, parent_raw, child_raw,
             confirmed_txid_be, confirmed_value) where ``*_tx`` are
    fully parsed Transaction objects with correct txids and ``*_raw``
    are the hex-ready wire bytes.
    """
    # Confirmed UTXO funding the parent.
    # We use a symmetric txid so that wire (LE) == display (BE).
    confirmed_txid_wire = b"\x01" * 32  # wire order (LE)
    confirmed_value = 100_000

    # Parent: spends confirmed UTXO, pays 1 sat fee
    parent_tx, parent_raw = _make_tx_via_roundtrip(
        prev_txid_wire=confirmed_txid_wire,
        prev_vout=0,
        output_value=confirmed_value - 1,  # 1 sat fee
    )

    # The parent's txid (big-endian) as stored internally:
    parent_txid_be = parent_tx.get_txid()
    # Convert to wire format (LE) for use in the child's prev_txid
    parent_txid_wire = parent_txid_be[::-1]

    # Child: spends parent output, pays 9,999 sat fee
    child_tx, child_raw = _make_tx_via_roundtrip(
        prev_txid_wire=parent_txid_wire,
        prev_vout=0,
        output_value=confirmed_value - 1 - 9_999,  # child fee = 9,999 sats
    )

    # confirmed_txid in big-endian (what from_payload produces):
    # Since b"\x01"*32 is symmetric, wire == be
    confirmed_txid_be = confirmed_txid_wire[::-1]

    return parent_tx, child_tx, parent_raw, child_raw, confirmed_txid_be, confirmed_value


def _setup_env():
    """Set up stubs, mempool, and RPC server with a CPFP pair."""
    parent_tx, child_tx, parent_raw, child_raw, confirmed_txid_be, confirmed_value = (
        _build_cpfp_pair()
    )

    # The confirmed UTXO is looked up by (prev_txid, prev_vout).
    # validate_package resolves UTXOs via the parent tx's input prev_txid
    # which, after from_payload() reversal, is in big-endian format.
    utxos = {(confirmed_txid_be, 0): {"value": confirmed_value}}
    validator = _StubValidator(utxos)
    mempool = Mempool(validator=validator, require_standard=False)
    db = _StubDB()
    node = _StubNode(mempool, db)
    rpc = _make_rpc_server(node)
    return rpc, mempool, parent_tx, child_tx, parent_raw, child_raw


# ── Tests ──────────────────────────────────────────────────────────────


class TestSubmitPackageCPFP:
    """Submit a 2-tx CPFP package via submitpackage RPC."""

    @pytest.mark.asyncio
    async def test_cpfp_package_accepted(self):
        """A 2-tx package where the child pays for the parent should succeed."""
        rpc, _, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        result = await rpc.rpc_submitpackage(
            [parent_raw.hex(), child_raw.hex()]
        )

        assert result["package_msg"] == "success"
        assert "tx-results" in result
        assert len(result["tx-results"]) == 2

    @pytest.mark.asyncio
    async def test_cpfp_result_contains_txids(self):
        """Per-tx results should be keyed by the real computed txid."""
        rpc, _, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        result = await rpc.rpc_submitpackage(
            [parent_raw.hex(), child_raw.hex()]
        )

        parent_txid = parent_tx.get_txid().hex()
        child_txid = child_tx.get_txid().hex()
        assert parent_txid in result["tx-results"]
        assert child_txid in result["tx-results"]

    @pytest.mark.asyncio
    async def test_cpfp_result_has_vsize(self):
        """Each tx result should contain a positive vsize."""
        rpc, _, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        result = await rpc.rpc_submitpackage(
            [parent_raw.hex(), child_raw.hex()]
        )

        for _txid, entry in result["tx-results"].items():
            assert "vsize" in entry
            assert entry["vsize"] > 0

    @pytest.mark.asyncio
    async def test_cpfp_result_has_fees(self):
        """Each tx result should report correct fees in BTC."""
        rpc, _, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        result = await rpc.rpc_submitpackage(
            [parent_raw.hex(), child_raw.hex()]
        )

        parent_txid = parent_tx.get_txid().hex()
        child_txid = child_tx.get_txid().hex()

        parent_fees = result["tx-results"][parent_txid]["fees"]
        child_fees = result["tx-results"][child_txid]["fees"]

        # Parent: 1 sat fee -> 0.00000001 BTC
        assert abs(parent_fees["base"] - 1 / 1e8) < 1e-12
        # Child: 9,999 sat fee -> 0.00009999 BTC
        assert abs(child_fees["base"] - 9_999 / 1e8) < 1e-12

    @pytest.mark.asyncio
    async def test_cpfp_txs_in_mempool(self):
        """After a successful submitpackage, both txs should be in mempool."""
        rpc, mempool, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        await rpc.rpc_submitpackage(
            [parent_raw.hex(), child_raw.hex()]
        )

        assert mempool.get_transaction(parent_tx.get_txid()) is not None
        assert mempool.get_transaction(child_tx.get_txid()) is not None


class TestSubmitPackageErrors:
    """Error handling for submitpackage RPC."""

    @pytest.mark.asyncio
    async def test_empty_package_rejected(self):
        """An empty package list should be rejected with HTTP 400."""
        from fastapi import HTTPException
        rpc, _, _, _, _, _ = _setup_env()

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_submitpackage([])
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_hex_rejected(self):
        """Invalid hex strings should be rejected with HTTP 400."""
        from fastapi import HTTPException
        rpc, _, _, _, _, _ = _setup_env()

        with pytest.raises(HTTPException) as exc_info:
            await rpc.rpc_submitpackage(["not_valid_hex"])
        assert exc_info.value.status_code == 400
        assert "Invalid hex" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_missing_utxo_returns_error(self):
        """A package spending non-existent UTXOs should fail validation."""
        validator = _StubValidator({})  # no UTXOs
        mempool = Mempool(validator=validator, require_standard=False)
        node = _StubNode(mempool, _StubDB())
        rpc = _make_rpc_server(node)

        tx, raw = _make_tx_via_roundtrip(
            prev_txid_wire=b"\xFF" * 32,
            prev_vout=0,
            output_value=50_000,
        )

        result = await rpc.rpc_submitpackage([raw.hex()])
        assert result["package_msg"] != "success"
        assert result["tx-results"] == {}

    @pytest.mark.asyncio
    async def test_wrong_topological_order_rejected(self):
        """A package with child before parent (wrong order) should fail."""
        rpc, _, parent_tx, child_tx, parent_raw, child_raw = _setup_env()

        # Submit in wrong order: child before parent
        result = await rpc.rpc_submitpackage(
            [child_raw.hex(), parent_raw.hex()]
        )
        assert result["package_msg"] != "success"
