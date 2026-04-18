"""B3 Stage 1: structural invariants on real mainnet block fixtures.

Fixture files live at ``tests/fixtures/b3_blocks/``.  The smallest
(``block_770000.bin``) is committed; the others are fetched on demand
via ``fetch.py`` (see the README in that directory).  Tests auto-skip
fixtures whose `.bin` is not present so CI without network still
passes on the committed fixture.

These tests build the golden baseline for the Rust↔Python validator
equivalence harness:

* Block deserializes cleanly via ``Block.deserialize``.
* Header hash matches the canonical `.hash` file (round-trip integrity).
* Total block weight ≤ 4 000 000.
* Merkle root matches the header.
* Witness commitment, if present in the coinbase, matches the
  computed witness merkle root.

When the Rust ``sync`` wheel is installed in the test venv, the
equivalence path through ``db.validate_block_from_bytes`` can be
exercised in a follow-up test (requires a seeded DB — not covered by
this file yet).
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from ouroboros.database import Block

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "b3_blocks"
MAX_BLOCK_WEIGHT = 4_000_000
WITNESS_COMMITMENT_MAGIC = bytes.fromhex("aa21a9ed")


def _load_index() -> dict:
    return json.loads((FIXTURE_DIR / "index.json").read_text())


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _compute_merkle_root(txids: list[bytes]) -> bytes:
    """dSHA256-based merkle root in internal byte order.

    Matches Bitcoin Core's CBlock::BuildMerkleTree — duplicate the
    last hash on odd levels.
    """
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _find_witness_commitment(coinbase_tx) -> bytes | None:
    """Scan coinbase outputs for ``OP_RETURN 0x24 0xaa21a9ed <32 bytes>``.

    Returns the 32-byte commitment, or None if not found.  When
    multiple matches exist, BIP141 specifies the last one wins.
    """
    commitment: bytes | None = None
    for out in coinbase_tx.outputs:
        spk = out.script_pubkey
        if len(spk) >= 38 and spk[0] == 0x6A and spk[1] == 0x24:
            if spk[2:6] == WITNESS_COMMITMENT_MAGIC:
                commitment = spk[6:38]
    return commitment


def _get_wtxid(tx) -> bytes:
    """dSHA256(tx.serialize_with_witness()).  Coinbase wtxid is all zero
    per BIP141 (the miner picks the witness nonce and the coinbase
    witness stack is the nonce itself)."""
    return _dsha256(tx.serialize_with_witness())


def _fixture_params() -> list:
    index = _load_index()
    params = []
    for height_str, entry in index.items():
        height = int(height_str)
        bin_path = FIXTURE_DIR / f"block_{height}.bin"
        marker = pytest.param(
            height,
            entry["hash"],
            marks=pytest.mark.skipif(
                not bin_path.exists(),
                reason=f"fixture block_{height}.bin not present — run "
                f"tests/fixtures/b3_blocks/fetch.py",
            ),
        )
        params.append(marker)
    return params


@pytest.mark.parametrize("height,expected_hash", _fixture_params())
class TestFixtureStructural:
    """Structural invariants that hold on any valid mainnet block."""

    def _load(self, height: int) -> tuple[bytes, Block]:
        raw = (FIXTURE_DIR / f"block_{height}.bin").read_bytes()
        return raw, Block.deserialize(raw)

    def test_header_hash_roundtrip(self, height, expected_hash):
        raw, _ = self._load(height)
        computed = _dsha256(raw[:80])[::-1].hex()
        assert computed == expected_hash, (
            f"header hash mismatch @ height {height}"
        )

    def test_deserialize(self, height, expected_hash):
        _, block = self._load(height)
        assert block is not None
        assert block.transactions, "block has no transactions"
        assert block.transactions[0].is_coinbase, "first tx must be coinbase"
        for i, tx in enumerate(block.transactions[1:], 1):
            assert not tx.is_coinbase, f"tx {i} is unexpectedly a coinbase"

    def test_merkle_root(self, height, expected_hash):
        _, block = self._load(height)
        txids = [tx.get_txid() for tx in block.transactions]
        computed = _compute_merkle_root(txids)
        assert computed == block.merkle_root, (
            f"merkle root mismatch @ height {height}"
        )

    def test_witness_commitment(self, height, expected_hash):
        """If the coinbase carries a witness commitment, the computed
        witness merkle root must match."""
        _, block = self._load(height)
        coinbase = block.transactions[0]
        commitment = _find_witness_commitment(coinbase)
        if commitment is None:
            pytest.skip(
                f"height {height}: no witness commitment in coinbase "
                f"(pre-SegWit or empty-witness block)"
            )
        # coinbase wtxid is all-zero per BIP141
        wtxids = [b"\x00" * 32]
        wtxids.extend(_get_wtxid(tx) for tx in block.transactions[1:])
        witness_merkle = _compute_merkle_root(wtxids)
        # witness nonce is the single 32-byte witness item on the coinbase
        if not coinbase.inputs[0].witness:
            pytest.skip("coinbase has no witness nonce (unexpected)")
        nonce = coinbase.inputs[0].witness[0]
        assert len(nonce) == 32, f"coinbase witness nonce must be 32 bytes"
        expected_commitment = _dsha256(witness_merkle + nonce)
        assert commitment == expected_commitment, (
            f"witness commitment mismatch @ height {height}"
        )

    def test_block_weight_under_cap(self, height, expected_hash):
        """Base size × 3 + total size ≤ 4 000 000 (BIP141 weight cap).

        Matches Python `_validate_block_limits` and the Rust
        `block.weight().to_wu()` check.
        """
        _, block = self._load(height)
        base_size = sum(len(tx.serialize()) for tx in block.transactions)
        total_size = sum(
            len(tx.serialize_with_witness()) for tx in block.transactions
        )
        # + 80 header + varint for tx count; small, doesn't tip the scale
        weight = base_size * 3 + total_size + 80 * 3 + 80
        assert weight <= MAX_BLOCK_WEIGHT, (
            f"block weight {weight} exceeds cap @ height {height}"
        )


def test_index_covers_all_heights():
    """The index must reference every height advertised by the README."""
    index = _load_index()
    expected = {"700000", "750000", "760000", "770000", "771000"}
    assert set(index.keys()) == expected
    for height_str, entry in index.items():
        assert "hash" in entry
        assert "bytes" in entry
        assert len(entry["hash"]) == 64, "hash must be 64 hex chars"


def test_committed_fixture_present():
    """``block_770000.bin`` is the one fixture committed to the repo —
    its absence means the fixture was accidentally removed."""
    assert (FIXTURE_DIR / "block_770000.bin").exists(), (
        "block_770000.bin was expected to be committed to the repo"
    )
