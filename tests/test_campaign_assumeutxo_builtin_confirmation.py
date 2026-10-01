"""HASHHOG_CAMPAIGN_ASSUMEUTXO entry at a BUILT-IN assumeUTXO height.

R4 slice 910000-920000 was BLOCKED because the campaign fixture for base
910,000 (minted by dumping a Core clone at that height) carries exactly the
commitment Core hardcodes there (kernel/chainparams.cpp m_assumeutxo_data,
mirrored in ``_MAINNET_ASSUMEUTXO``), and the loader refused ANY same-height
entry as a collision:

    ValueError: [CAMPAIGN-ASSUMEUTXO] .../soak-910000/campaign-entry.json:
    entry 0 (height=910000, ...) collides with a builtin assumeUTXO entry

Semantics pinned here:

* an entry whose commitment (height, blockhash, hash_serialized,
  m_chain_tx_count) is IDENTICAL to a built-in one is a confirmation: accepted,
  the built-in commitment is kept, and supplemental fields the built-in row
  lacks (``chainwork``) are filled in -- the 910000 built-in has no chainwork,
  which the snapshot base's persisted BlockMetadata needs;
* every disagreement is still refused: a different hash_serialized, blockhash
  or m_chain_tx_count at the same height, the built-in blockhash at another
  height, a base_header/chainwork contradicting the built-in row, or a
  base_header that does not hash to the blockhash;
* a duplicate within the campaign file is still refused.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ouroboros import snapshot

H910 = 910_000
BLOCKHASH = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
HASH_SERIALIZED = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
CHAIN_TX_COUNT = 1_226_586_151
BASE_HEADER = (
    "00a0572be06d4f01a2ed2228dec965539cc8b96512ccde7d2824010000000000000000006f28"
    "c30dc748f6b1430fb2b9a5a94b5b34a5df6e318c6cc5c310a1a35b432b59a3ab9d68b32c0217"
    "19d103e9"
)
CHAINWORK = "0000000000000000000000000000000000000000da15bcbf68ad7fed795c504f"

META_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tools/boundary-blocks/soak-910000/campaign-entry.json"
)


def _entry(**over):
    e = {
        "height": H910,
        "blockhash": BLOCKHASH,
        "hash_serialized": HASH_SERIALIZED,
        "m_chain_tx_count": CHAIN_TX_COUNT,
        "base_header": BASE_HEADER,
        "chainwork": CHAINWORK,
    }
    for k, v in over.items():
        if v is None:
            e.pop(k, None)
        else:
            e[k] = v
    return e


@pytest.fixture
def load(tmp_path, monkeypatch):
    def _load(entries, path=None):
        if path is None:
            path = tmp_path / "campaign-entry.json"
            path.write_text(json.dumps(entries))
        monkeypatch.setenv("HASHHOG_CAMPAIGN_ASSUMEUTXO", str(path))
        monkeypatch.setattr(snapshot, "_CAMPAIGN_ASSUMEUTXO_LOADED", False)
        monkeypatch.setattr(snapshot, "_CAMPAIGN_ASSUMEUTXO_ENTRIES", [])
        return snapshot.get_assumeutxo_params("mainnet")

    yield _load
    # Never leak a loaded campaign table into other tests.
    snapshot._CAMPAIGN_ASSUMEUTXO_LOADED = False
    snapshot._CAMPAIGN_ASSUMEUTXO_ENTRIES = []


def _builtin_910():
    return next(d for d in snapshot._MAINNET_ASSUMEUTXO if d.height == H910)


def test_builtin_header_hashes_to_blockhash():
    # Sanity on the test data itself (a negative control for the hash gate
    # below would be meaningless if BASE_HEADER were wrong).
    raw = bytes.fromhex(BASE_HEADER)
    assert hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex() == BLOCKHASH
    assert _builtin_910().base_header == raw


def test_identical_entry_is_accepted_as_a_confirmation(load):
    params = load([_entry()])
    rows = [d for d in params if d.height == H910]
    assert len(rows) == 1, "a confirmation must not add a second row at the height"
    row = rows[0]
    b = _builtin_910()
    assert row.block_hash == b.block_hash
    assert row.hash_serialized == b.hash_serialized
    assert row.chain_tx_count == b.chain_tx_count
    assert row.base_header == b.base_header
    # The built-in row has no chainwork; the confirmation fills it.
    assert b.chainwork_hex is None
    assert row.chainwork_hex == CHAINWORK
    # Lookups the import path uses resolve to the merged row.
    assert snapshot.get_assumeutxo_by_hash("mainnet", b.block_hash).chainwork_hex == CHAINWORK
    assert snapshot.get_assumeutxo_data("mainnet", H910).chainwork_hex == CHAINWORK
    # The production table object itself is not mutated.
    assert _builtin_910().chainwork_hex is None


def test_identical_entry_without_supplemental_fields_is_accepted(load):
    params = load([_entry(base_header=None, chainwork=None)])
    assert [d.height for d in params].count(H910) == 1


def test_real_soak_910000_fixture_loads(load):
    if not META_FIXTURE.exists():
        pytest.skip(f"meta-repo fixture {META_FIXTURE} not present")
    params = load(None, path=META_FIXTURE)
    row = next(d for d in params if d.height == H910)
    assert row.hash_serialized == _builtin_910().hash_serialized
    assert row.chainwork_hex == CHAINWORK


# --- negative controls: every disagreement is still fatal -------------------


@pytest.mark.parametrize(
    "over",
    [
        {"hash_serialized": "11" * 32},
        {"blockhash": "00" * 31 + "01", "base_header": None},
        {"m_chain_tx_count": CHAIN_TX_COUNT + 1},
        {"height": H910 + 1, "base_header": None},
    ],
    ids=["hash_serialized", "blockhash", "m_chain_tx_count", "blockhash-other-height"],
)
def test_conflicting_entry_is_refused(load, over):
    with pytest.raises(ValueError, match="collides with a builtin assumeUTXO entry"):
        load([_entry(**over)])


def test_contradicting_chainwork_is_refused(load, monkeypatch):
    b = _builtin_910()
    pinned = snapshot.AssumeutxoData(
        height=b.height,
        block_hash=b.block_hash,
        hash_serialized=b.hash_serialized,
        chain_tx_count=b.chain_tx_count,
        base_header=b.base_header,
        chainwork_hex="00" * 31 + "01",
    )
    table = [pinned if d.height == H910 else d for d in snapshot._MAINNET_ASSUMEUTXO]
    monkeypatch.setattr(snapshot, "_MAINNET_ASSUMEUTXO", table)
    with pytest.raises(ValueError, match="contradicts"):
        load([_entry()])


def test_contradicting_base_header_is_refused(load):
    # Same commitment, but a base_header that is not the built-in one (and so
    # does not hash to the blockhash either).
    bad = BASE_HEADER[:-2] + ("00" if BASE_HEADER[-2:] != "00" else "01")
    with pytest.raises(ValueError, match="contradicts|does not hash"):
        load([_entry(base_header=bad)])


def test_base_header_must_hash_to_blockhash_when_builtin_has_none(load, monkeypatch):
    b = _builtin_910()
    bare = snapshot.AssumeutxoData(
        height=b.height,
        block_hash=b.block_hash,
        hash_serialized=b.hash_serialized,
        chain_tx_count=b.chain_tx_count,
    )
    table = [bare if d.height == H910 else d for d in snapshot._MAINNET_ASSUMEUTXO]
    monkeypatch.setattr(snapshot, "_MAINNET_ASSUMEUTXO", table)
    bad = BASE_HEADER[:-2] + ("00" if BASE_HEADER[-2:] != "00" else "01")
    with pytest.raises(ValueError, match="does not hash"):
        load([_entry(base_header=bad)])
    # ...and a correct one fills the gap.
    params = load([_entry()])
    assert next(d for d in params if d.height == H910).base_header == bytes.fromhex(BASE_HEADER)


def test_duplicate_within_file_is_still_refused(load):
    with pytest.raises(ValueError, match="duplicates another entry"):
        load([_entry(), _entry()])
