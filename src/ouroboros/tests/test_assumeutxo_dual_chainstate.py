"""AssumeUTXO REAL dual-chainstate background validation (ouroboros pilot).

This is the gate test for replacing ouroboros's COUNTER LOOP with a genuine
second (background) chainstate, mirroring Bitcoin Core's two-chainstate
assumeUTXO handshake:

  * ActivateSnapshot (validation.cpp:5588) loads the snapshot into the ACTIVE
    chainstate (served while UNVALIDATED);
  * AddChainstate (:6170) keeps a SECOND, genesis-rooted BACKGROUND chainstate
    with its OWN coins DB;
  * MaybeValidateSnapshot (:5967): once the background chainstate has
    re-connected every block genesis->base into its own store, recompute the
    HASH_SERIALIZED over THAT store and compare to au_data.hash_serialized.
    MATCH -> VALIDATED + retire; MISMATCH -> INVALID + AbortNode (never a
    silent accept).

The defect this replaces (snapshot.py): start_background_validation was a
``for height in range(target+1)`` counter that then re-hashed self.db (the
SAME store the snapshot was loaded into) = a tautological hash-of-self.

Four assertions (mirroring camlcoin test_loadtxoutset_live a39dd42 +
nimrod test_assumeutxo_dual_chainstate a8fee4b):

  (a) SEPARATE store — an active-store write is NOT visible in the bg store
      (aliasing falsification);
  (b) REAL connect genesis->base — the bg store equals an INDEPENDENTLY
      computed UTXO set, not empty and not a counter;
  (c) ACCEPT — a snapshot committing to the correct genesis->base hash is
      VALIDATED (validated=true);
  (d) REJECT — a deliberately bg-inconsistent snapshot that commits to its OWN
      (file) hash (so it passes the load-time content gate) is caught by the
      background re-derivation: validated=false / snapshot INVALID.

Unique tmp dirs per case; the runtime regtest assumeUTXO whitelist is cleared
in teardown so no probe state leaks across runs.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import path (ouroboros src on sys.path).
# ---------------------------------------------------------------------------
SRC = Path(__file__).resolve().parents[2]
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ouroboros.database import Block, Transaction, TxIn, TxOut  # noqa: E402
from ouroboros.muhash import coin_element  # noqa: E402
from ouroboros.p2p_messages import encode_varint  # noqa: E402
from ouroboros.snapshot import (  # noqa: E402
    AssumeutxoData,
    BackgroundCoinsStore,
    HashWriter,
    SnapshotManager,
    SnapshotValidationResult,
    _write_compact_size,
    clear_regtest_assumeutxo,
    compute_utxo_hash,
    register_regtest_assumeutxo,
    serialize_coin,
)

REGTEST_MAGIC = bytes([0xFA, 0xBF, 0xB5, 0xDA])
SNAPSHOT_MAGIC = b"utxo\xff"
SNAPSHOT_VERSION = 2

OP_TRUE = bytes([0x51])
OP_RETURN = bytes([0x6A])


# ---------------------------------------------------------------------------
# Block-building helpers — produce raw consensus bytes that round-trip cleanly
# through Block.deserialize (so the txids/hashes my test computes match exactly
# what the background store recomputes).
# ---------------------------------------------------------------------------
def _txid(tx: Transaction) -> bytes:
    raw = tx.serialize()
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def _coinbase(height: int, value: int, spk: bytes) -> Transaction:
    # BIP34 height-in-coinbase scriptSig (regtest enforces it from h=1).
    script_sig = bytes([0x03]) + height.to_bytes(3, "little")
    return Transaction(
        txid=None,
        version=1,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=b"\x00" * 32,
                prev_vout=0xFFFFFFFF,
                script_sig=script_sig,
                sequence=0xFFFFFFFF,
                witness=[],
            )
        ],
        outputs=[TxOut(value=value, script_pubkey=spk)],
        has_witness=False,
    )


def _spend(prev_txid: bytes, prev_vout: int, value: int, spk: bytes) -> Transaction:
    return Transaction(
        txid=None,
        version=1,
        locktime=0,
        inputs=[
            TxIn(
                prev_txid=prev_txid,
                prev_vout=prev_vout,
                script_sig=OP_TRUE,  # spends an OP_TRUE output
                sequence=0xFFFFFFFF,
                witness=[],
            )
        ],
        outputs=[TxOut(value=value, script_pubkey=spk)],
        has_witness=False,
    )


def _block_bytes(prev_hash: bytes, txs: list[Transaction], ts: int) -> bytes:
    # Merkle root: single tx -> its txid; multi -> a real merkle root, but we
    # never validate the root here (Block.deserialize doesn't), so for >1 tx we
    # still compute it properly for realism.
    txids = [_txid(t) for t in txs]
    merkle = _merkle_root(txids)
    hdr = (
        struct.pack("<i", 0x20000000)
        + prev_hash
        + merkle
        + struct.pack("<I", ts)
        + struct.pack("<I", 0x207FFFFF)
        + struct.pack("<I", 0)
    )
    body = encode_varint(len(txs))
    for t in txs:
        body += t.serialize()
    return hdr + body


def _merkle_root(txids: list[bytes]) -> bytes:
    if not txids:
        return b"\x00" * 32
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(
                hashlib.sha256(
                    hashlib.sha256(layer[i] + layer[i + 1]).digest()
                ).digest()
            )
        layer = nxt
    return layer[0]


def _block_hash(block_bytes: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(block_bytes[:80]).digest()).digest()


# ---------------------------------------------------------------------------
# A small regtest chain genesis(0)..base(3) WITH A REAL SPEND.
#
#   h0 genesis: coinbase -> OP_TRUE (UNSPENDABLE per Core; never in UTXO set)
#   h1: coinbase A -> OP_TRUE 50
#   h2: coinbase B -> OP_TRUE 50
#   h3 (base): coinbase C -> OP_TRUE 50  AND  a spend of A:0 -> OP_TRUE 49
#
# Expected base UTXO set (genesis coinbase excluded):
#   B:0 (h2, coinbase), C:0 (h3, coinbase), spend:0 (h3, non-coinbase)
#   A:0 is SPENT, so absent.
# ---------------------------------------------------------------------------
BASE_HEIGHT = 3


def _build_chain() -> tuple[list[bytes], list[bytes], list[tuple]]:
    """Return (block_bytes_by_height, block_hashes_by_height, expected_coins).

    expected_coins is a list of (txid, vout, amount, spk, height, is_coinbase)
    describing the UTXO set at the base — computed INDEPENDENTLY of the
    background store (so the test's "real connect" assertion is non-circular).
    """
    blocks: list[bytes] = []
    hashes: list[bytes] = []
    ts0 = 1700000000

    # h0 genesis.
    cb0 = _coinbase(0, 50 * 10**8, OP_TRUE)
    g_bytes = _block_bytes(b"\x00" * 32, [cb0], ts0)
    blocks.append(g_bytes)
    hashes.append(_block_hash(g_bytes))

    # h1: coinbase A.
    cbA = _coinbase(1, 50 * 10**8, OP_TRUE)
    b1 = _block_bytes(hashes[0], [cbA], ts0 + 600)
    blocks.append(b1)
    hashes.append(_block_hash(b1))
    txid_A = _txid(cbA)

    # h2: coinbase B.
    cbB = _coinbase(2, 50 * 10**8, OP_TRUE)
    b2 = _block_bytes(hashes[1], [cbB], ts0 + 1200)
    blocks.append(b2)
    hashes.append(_block_hash(b2))
    txid_B = _txid(cbB)

    # h3 (base): coinbase C + a real spend of A:0.
    cbC = _coinbase(3, 50 * 10**8, OP_TRUE)
    spend = _spend(txid_A, 0, 49 * 10**8, OP_TRUE)
    b3 = _block_bytes(hashes[2], [cbC, spend], ts0 + 1800)
    blocks.append(b3)
    hashes.append(_block_hash(b3))
    txid_C = _txid(cbC)
    txid_spend = _txid(spend)

    expected = [
        (txid_B, 0, 50 * 10**8, OP_TRUE, 2, True),
        (txid_C, 0, 50 * 10**8, OP_TRUE, 3, True),
        (txid_spend, 0, 49 * 10**8, OP_TRUE, 3, False),
    ]
    return blocks, hashes, expected


def _hash_serialized_of(coins: list[tuple]) -> bytes:
    """HASH_SERIALIZED (SHA256d over canonical-order TxOutSer) for a coin list."""
    hasher = HashWriter()
    for txid, vout, amount, spk, height, is_cb in sorted(
        coins, key=lambda c: (c[0], c[1])
    ):
        hasher.update(
            coin_element(
                txid=txid,
                vout=vout,
                height=height,
                is_coinbase=is_cb,
                amount=amount,
                script_pubkey=spk,
            )
        )
    return hasher.digest()


def _write_snapshot(path: str, base_hash: bytes, coins: list[tuple]) -> None:
    """Write a Core-format snapshot file committing the given coin set."""
    # Group by txid (sorted), then by vout.
    groups: dict[bytes, list[tuple]] = {}
    for c in coins:
        groups.setdefault(c[0], []).append(c)
    with open(path, "wb") as f:
        f.write(SNAPSHOT_MAGIC)
        f.write(struct.pack("<H", SNAPSHOT_VERSION))
        f.write(REGTEST_MAGIC)
        f.write(base_hash)
        f.write(struct.pack("<Q", len(coins)))
        for txid in sorted(groups.keys()):
            entries = sorted(groups[txid], key=lambda c: c[1])
            f.write(txid)
            _write_compact_size(f, len(entries))
            for _txid_, vout, amount, spk, height, is_cb in entries:
                _write_compact_size(f, vout)
                serialize_coin(f, height=height, is_coinbase=is_cb, amount=amount, script=spk)


# ---------------------------------------------------------------------------
# A minimal in-memory ACTIVE store satisfying the load_snapshot API. This is
# DISTINCT from BackgroundCoinsStore — its sole role is to be the "active /
# snapshot chainstate" the snapshot is loaded into, so the test can prove the
# background store does NOT alias it.
# ---------------------------------------------------------------------------
class _FakeActiveDB:
    def __init__(self):
        self._coins: dict[tuple[bytes, int], dict] = {}
        self._best: tuple[bytes, int] | None = None

    # load_snapshot legacy (no FFI) path uses these two:
    def add_utxo_raw(self, *, txid, vout, amount, script_pubkey, height, is_coinbase):
        self._coins[(bytes(txid), int(vout))] = {
            "amount": amount,
            "script_pubkey": bytes(script_pubkey),
            "height": height,
            "is_coinbase": is_coinbase,
        }

    def update_best_block(self, block_hash, height):
        self._best = (bytes(block_hash), int(height))

    def get_best_block(self):
        if self._best is None:
            raise RuntimeError("no best block")
        return self._best


@pytest.fixture()
def chain():
    return _build_chain()


@pytest.fixture(autouse=True)
def _clean_whitelist():
    clear_regtest_assumeutxo()
    yield
    clear_regtest_assumeutxo()


# ---------------------------------------------------------------------------
# (b) + (a): a real genesis->base connection into a SEPARATE store.
# ---------------------------------------------------------------------------
def test_background_store_is_separate_and_real_connect(chain):
    blocks, hashes, expected = chain

    bg = BackgroundCoinsStore("regtest")
    for h in range(BASE_HEIGHT + 1):
        bg.connect_block_bytes(blocks[h], h)

    # (b) REAL connect: bg store == independently-computed expected set.
    got = {
        (c.txid, c.vout): (c.amount, c.script_pubkey, c.height, c.is_coinbase)
        for c in bg.iter_utxos()
    }
    want = {
        (txid, vout): (amount, spk, height, is_cb)
        for (txid, vout, amount, spk, height, is_cb) in expected
    }
    assert got == want, "background store UTXO set must equal the independent set"
    assert bg.utxo_count() == 3
    # Genesis coinbase must NOT be present (Core: unspendable).
    g_block = Block.deserialize(blocks[0])
    assert bg.get_utxo(g_block.transactions[0].txid, 0) is None
    # The spent coin (A:0) must be absent.
    b1 = Block.deserialize(blocks[1])
    assert bg.get_utxo(b1.transactions[0].txid, 0) is None

    # (a) ALIASING falsification: a write to a DIFFERENT (active) store is NOT
    # visible in the bg store, and vice-versa.
    active = BackgroundCoinsStore("regtest")
    active.connect_block_bytes(blocks[0], 0)  # only genesis
    active._coins[(b"\x99" * 32, 0)] = type(next(iter(bg.iter_utxos())))(
        txid=b"\x99" * 32, vout=0, amount=1, script_pubkey=OP_TRUE,
        height=0, is_coinbase=False,
    )
    assert bg.get_utxo(b"\x99" * 32, 0) is None, "active write leaked into bg store"
    assert active.get_utxo(expected[0][0], 0) is None, "bg write leaked into active"
    assert active is not bg


# ---------------------------------------------------------------------------
# (c) ACCEPT: a correct snapshot is VALIDATED by the background re-derivation.
# ---------------------------------------------------------------------------
def test_accept_correct_snapshot(chain, tmp_path):
    blocks, hashes, expected = chain
    base_hash = hashes[BASE_HEIGHT]
    correct_hash = _hash_serialized_of(expected)

    # Register the regtest assumeUTXO entry committing to the CORRECT hash.
    register_regtest_assumeutxo(
        AssumeutxoData(
            height=BASE_HEIGHT,
            block_hash=base_hash,
            hash_serialized=correct_hash,
            chain_tx_count=5,
        )
    )

    snap_path = str(tmp_path / "good.dat")
    _write_snapshot(snap_path, base_hash, expected)

    data_dir = str(tmp_path / "accept_datadir")  # pytest auto-cleans tmp_path
    sm = SnapshotManager(_FakeActiveDB(), "regtest", data_dir)
    sm.load_snapshot(snap_path)  # passes the load-time content-hash gate
    assert sm.snapshot_loaded
    assert sm.snapshot_height == BASE_HEIGHT

    result = sm.run_background_validation_sync(lambda h: blocks[h])
    assert result == SnapshotValidationResult.VALID
    status = sm.get_status()
    assert status["background_validated"] is True
    assert status["snapshot_invalid"] is False
    # getchainstates-facing logic: validated true only on a clean match.
    assert (status["background_validated"] and not status["snapshot_invalid"]) is True


# ---------------------------------------------------------------------------
# (d) REJECT: a bg-inconsistent snapshot that commits to its OWN file hash
# passes the load gate but is caught by the independent re-derivation.
# ---------------------------------------------------------------------------
def test_reject_inconsistent_snapshot(chain, tmp_path):
    blocks, hashes, expected = chain
    base_hash = hashes[BASE_HEIGHT]

    # Tamper: change one coin's amount. This snapshot is INTERNALLY consistent
    # (its file commits to ITS OWN hash, so the load-time gate passes) but is
    # INCONSISTENT with the genesis->base replay (the real chain produces the
    # untampered amount).
    tampered = list(expected)
    t0 = tampered[0]
    tampered[0] = (t0[0], t0[1], t0[2] + 7, t0[3], t0[4], t0[5])  # amount + 7
    tampered_hash = _hash_serialized_of(tampered)
    assert tampered_hash != _hash_serialized_of(expected)

    # Register the regtest entry committing to the TAMPERED hash (so load
    # passes) — exactly the camlcoin test_loadtxoutset_live reject construction.
    register_regtest_assumeutxo(
        AssumeutxoData(
            height=BASE_HEIGHT,
            block_hash=base_hash,
            hash_serialized=tampered_hash,
            chain_tx_count=5,
        )
    )

    snap_path = str(tmp_path / "bad.dat")
    _write_snapshot(snap_path, base_hash, tampered)

    data_dir = str(tmp_path / "reject_datadir")  # pytest auto-cleans tmp_path
    sm = SnapshotManager(_FakeActiveDB(), "regtest", data_dir)
    # Load gate PASSES (file commits to its own hash).
    sm.load_snapshot(snap_path)
    assert sm.snapshot_loaded

    # Background re-derivation connects the REAL chain (untampered) -> its hash
    # differs from the tampered commitment -> INVALID.
    result = sm.run_background_validation_sync(lambda h: blocks[h])
    assert result == SnapshotValidationResult.INVALID
    status = sm.get_status()
    assert status["background_validated"] is False
    assert status["snapshot_invalid"] is True
    # getchainstates-facing logic: validated must be FALSE after a mismatch
    # (never a silent accept).
    assert (status["background_validated"] and not status["snapshot_invalid"]) is False


# ---------------------------------------------------------------------------
# Aliasing guard at the manager level: run_background_validation_sync builds a
# store that is NOT self.db.
# ---------------------------------------------------------------------------
def test_manager_bg_store_not_aliasing_active(chain, tmp_path):
    blocks, hashes, expected = chain
    base_hash = hashes[BASE_HEIGHT]
    register_regtest_assumeutxo(
        AssumeutxoData(
            height=BASE_HEIGHT,
            block_hash=base_hash,
            hash_serialized=_hash_serialized_of(expected),
            chain_tx_count=5,
        )
    )
    snap_path = str(tmp_path / "ok.dat")
    _write_snapshot(snap_path, base_hash, expected)

    data_dir = str(tmp_path / "alias_datadir")  # pytest auto-cleans tmp_path
    active = _FakeActiveDB()
    sm = SnapshotManager(active, "regtest", data_dir)
    sm.load_snapshot(snap_path)
    sm.run_background_validation_sync(lambda h: blocks[h])
    # The bg store object created during validation is never the active db.
    assert sm._background_store is not None
    assert sm._background_store is not active
    # And the recomputed hash over the bg store matches the commitment.
    assert compute_utxo_hash(sm._background_store, "hash_serialized") == _hash_serialized_of(
        expected
    )
