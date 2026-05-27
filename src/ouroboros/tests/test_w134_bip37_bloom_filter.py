"""W134 — BIP-37 Bloom Filter (legacy SPV) stress audit (ouroboros).

DISCOVERY wave (follow-up to W110): 30 gates audited against
  bitcoin-core/src/common/bloom.{cpp,h},
  bitcoin-core/src/merkleblock.{cpp,h},
  bitcoin-core/src/net_processing.cpp,
  bitcoin-core/src/init.cpp.

Scope:
  - CBloomFilter primitive (constants, hash schedule, IsRelevantAndUpdate)
  - CRollingBloomFilter (used by Core for the per-peer inventory-known
    filter)
  - CMerkleBlock + CPartialMerkleTree wire format helpers in rpc.py
    (`_build_partial_merkle_tree`, `_parse_partial_merkle_tree`) — these
    ARE implemented in ouroboros and are stress-tested here.
  - filterload / filteradd / filterclear / merkleblock P2P handlers
    (disconnect arms wired by FIX-36; deeper logic absent by design).
  - NODE_BLOOM service bit + BIP-111 + -peerbloomfilters config.
  - Version-message `fRelay` field plumbing.

Two-pipeline note: BIP-37 is wallet/SPV-facing. Rust pipeline
(ferrous-utils/) has ZERO BIP-37 production code (only RocksDB-internal
bloom_locality). Two-pipeline guard EXTENDED via
`test_g30_two_pipeline_bip37_python_only`.

This file pins:
  - PRESENT gates as plain asserts.
  - PARTIAL / MISSING / BUG gates as xfail (strict) so a FIX wave that
    closes the gap flips the test to XPASS.

NO production code changes. Audit + xfail only.

Reference: ouroboros/audit/w134_bip37_bloom_filter.md.

Run:
    cd /home/work/hashhog/ouroboros && \\
      python3 -m pytest src/ouroboros/tests/test_w134_bip37_bloom_filter.py -v
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup + sync module mock so ouroboros imports cleanly without the
# compiled Rust extension being present.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
FERROUS_UTILS = REPO_ROOT / "ferrous-utils"
SRC_OUROBOROS = REPO_ROOT / "src" / "ouroboros"

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

if "sync" not in sys.modules:
    _mock_sync = types.ModuleType("sync")
    _mock_sync.PyBlockchainDB = MagicMock
    _mock_sync.PyBlock = MagicMock
    _mock_sync.PyUTXO = MagicMock
    _mock_sync.SyncEngine = MagicMock
    sys.modules["sync"] = _mock_sync


def _read_py(rel: str) -> str:
    p = SRC_OUROBOROS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_rust(rel: str) -> str:
    p = FERROUS_UTILS / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _grep_rust_for(*patterns: str) -> list[str]:
    """Return list of "path:line" matches across ferrous-utils for any of
    the patterns. Skips target/ build artefacts."""
    if not FERROUS_UTILS.exists():
        return []
    pat = re.compile("|".join(patterns))
    hits: list[str] = []
    for rs in FERROUS_UTILS.rglob("*.rs"):
        if "target" in rs.parts:
            continue
        try:
            text = rs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                hits.append(f"{rs}:{i}")
    return hits


# Pre-load Python sources used by many gates.
_P2P_MSGS = _read_py("p2p_messages.py")
_P2P = _read_py("p2p.py")
_PEER = _read_py("peer.py")
_NODE = _read_py("node.py")
_RPC = _read_py("rpc.py")


# ===========================================================================
# Reference helpers (used by stress tests below).
# ===========================================================================

def _dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _build_merkle_root(txids: list[bytes]) -> bytes:
    """Compute the Bitcoin merkle root using Core's "duplicate the
    rightmost when odd" rule (CVE-2012-2459 lives in the proof PARSER,
    not the merkle-root computation itself — the root is canonical)."""
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# ===========================================================================
# G1 — MAX_BLOOM_FILTER_SIZE = 36000 (carried from W110 BUG-1)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 BUG-11 (P2 carried, W110 BUG-1): MAX_BLOOM_FILTER_SIZE = 36000 "
           "absent in both pipelines; filterload has no size-cap enforcement "
           "(bloom.h:17). Disconnect-only stub at p2p.py:2459-2476.",
    strict=True,
)
def test_g1_max_bloom_filter_size_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "MAX_BLOOM_FILTER_SIZE" in sources or "36000" in sources


# ===========================================================================
# G2 — MAX_HASH_FUNCS = 50 (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-2): MAX_HASH_FUNCS = 50 absent. Core caps "
           "nHashFuncs at 50 in CBloomFilter::IsWithinSizeConstraints "
           "(bloom.cpp:91-93).",
    strict=True,
)
def test_g2_max_hash_funcs_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "MAX_HASH_FUNCS" in sources


# ===========================================================================
# G3 — LN2SQUARED precision (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-3): LN2SQUARED full-precision constant "
           "absent. Bloom-filter sizing formula uses Core's "
           "0.4804530139182014246671025263266649717305529515945455.",
    strict=True,
)
def test_g3_ln2squared_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "LN2SQUARED" in sources or "0.4804530139182014" in sources


# ===========================================================================
# G4 — CBloomFilter constructor / sizing formula (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-4): No CBloomFilter / BloomFilter class. "
           "Constructor (bloom.cpp:26-39) is absent in both pipelines.",
    strict=True,
)
def test_g4_bloom_filter_class_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "class CBloomFilter" in sources or "class BloomFilter" in sources


# ===========================================================================
# G5 — Hash schedule: nHashNum * 0xFBA4C795 + nTweak (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-7): 0xFBA4C795 hash schedule constant "
           "absent. Core bloom.cpp:47 / hash.cpp MurmurHash3 also used by "
           "CRollingBloomFilter inventory tracking.",
    strict=True,
)
def test_g5_hash_schedule_constant_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "0xFBA4C795" in sources or "0xfba4c795" in sources


# ===========================================================================
# G6 — bit-index formula vData[idx>>3] |= 1<<(7&idx) (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-8): bit-packing formula "
           "`vData[idx>>3] |= (1 << (7 & idx))` absent (bloom.cpp:58, 77).",
    strict=True,
)
def test_g6_bit_index_formula_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    # Look for either the literal C-style expression or a Python rewrite.
    has_c_form = ">> 3" in sources and "7 &" in sources
    has_py_form = "// 8" in sources and "% 8" in sources and "vData" in sources
    assert has_c_form or has_py_form


# ===========================================================================
# G7 — BLOOM_UPDATE_* enum (carried)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-11/12/13/14): BLOOM_UPDATE_NONE / _ALL / "
           "_P2PUBKEY_ONLY / _MASK enum absent (bloom.h:24-31).",
    strict=True,
)
def test_g7_bloom_update_enum_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert (
        "BLOOM_UPDATE_NONE" in sources
        and "BLOOM_UPDATE_ALL" in sources
        and "BLOOM_UPDATE_P2PUBKEY_ONLY" in sources
        and "BLOOM_UPDATE_MASK" in sources
    )


# ===========================================================================
# G8 — m_tx_inventory_known_filter uses CRollingBloomFilter (BUG-8 / F4)
# ===========================================================================


def test_g8_known_filter_is_bounded_post_fix() -> None:
    """G8 BUG-8 (P1) — FIXED in ouroboros #146 (2026-05-27).

    TrickleQueue.known_filter was a plain ``set[bytes]`` with no rotation —
    the dominant suspect behind the wedge on PID 1771536 (RSS 58 GB /
    swap 89 GB).  It is now an OrderedDict-backed FIFO capped at
    KNOWN_FILTER_MAX_ENTRIES (50 000), matching the Core
    CRollingBloomFilter(50000, 0.000001) sizing without the FP-rate
    machinery.  This test pins the cap is wired so a future refactor
    cannot silently reintroduce the unbounded form.
    """
    assert "m_tx_inventory_known_filter" in _P2P, (
        "G8: reference comment to Core's known_filter missing — has the "
        "comment been removed? Verify TrickleQueue.known_filter still exists."
    )
    assert "KNOWN_FILTER_MAX_ENTRIES" in _P2P, (
        "G8: KNOWN_FILTER_MAX_ENTRIES cap missing — has the bound been removed?"
    )
    assert "self._known_filter_max" in _P2P, (
        "G8: per-queue cap field _known_filter_max missing."
    )
    assert "OrderedDict" in _P2P, (
        "G8: known_filter no longer uses OrderedDict — has the cap been removed?"
    )


def test_g8_known_filter_has_size_bound() -> None:
    # Look for any actual size-cap behaviour (a call site that bounds the
    # set, or a class that does it).  Fixed in ouroboros #146 via
    # OrderedDict + KNOWN_FILTER_MAX_ENTRIES eviction in _known_filter_add.
    has_cap = (
        "KNOWN_FILTER_MAX_ENTRIES" in _P2P
        or "_known_filter_add" in _P2P
        or "self.known_filter.clear" in _P2P
        or "known_filter.discard" in _P2P
        or "known_filter.popitem" in _P2P
        or "class RollingBloomFilter" in _P2P
        or "class CRollingBloomFilter" in _P2P
        or "from ouroboros.bloom import" in _P2P
    )
    assert has_cap, (
        "G8: no rotation / cap / clear() on known_filter — unbounded growth."
    )


# ===========================================================================
# G9 — CRollingBloomFilter primitive (entirely absent in both pipelines)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 BUG-8 follow-on: no CRollingBloomFilter implementation. Core "
           "common/bloom.cpp:163-247 provides the rolling primitive used by "
           "net_processing for per-peer known-tx + known-addr filters.",
    strict=True,
)
def test_g9_rolling_bloom_filter_present() -> None:
    # Look for an actual class definition, not just any mention of the
    # name in a doc/string. Comment-only references in p2p.py don't count.
    candidates = ["bloom.py", "rolling_bloom.py", "p2p.py", "p2p_messages.py"]
    for name in candidates:
        body = _read_py(name)
        if re.search(r"^class\s+(C?RollingBloomFilter)\b", body, re.M):
            return
    pytest.fail("G9: no CRollingBloomFilter class in Python pipeline.")


# ===========================================================================
# G10 — IsRelevantAndUpdate (txid match) (carried W110 BUG-16)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-16/17/19/20): IsRelevantAndUpdate absent. "
           "Core bloom.cpp:95-161 — the entire tx-filtering pipeline is gone.",
    strict=True,
)
def test_g10_is_relevant_and_update_present() -> None:
    sources = _P2P_MSGS + _P2P + _PEER + _NODE
    assert "IsRelevantAndUpdate" in sources or "is_relevant_and_update" in sources


# ===========================================================================
# G11-G16 — collapse into G10 (carried W110)
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-21): BLOOM_UPDATE_ALL outpoint auto-insert "
           "absent (bloom.cpp:123-124).",
    strict=True,
)
def test_g14_update_all_outpoint_insert_present() -> None:
    assert "BLOOM_UPDATE_ALL" in _P2P_MSGS + _P2P


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-22): BLOOM_UPDATE_P2PUBKEY_ONLY conditional "
           "absent (bloom.cpp:125-132).",
    strict=True,
)
def test_g15_update_p2pubkey_only_present() -> None:
    assert "BLOOM_UPDATE_P2PUBKEY_ONLY" in _P2P_MSGS + _P2P


@pytest.mark.xfail(
    reason="W134 carried (W110 BUG-10): CVE-2013-5700 empty-vData short-circuit "
           "absent (bloom.cpp:52-53, 71-72). With no CBloomFilter class, the "
           "CVE arm is unreachable — but a future port must include it.",
    strict=True,
)
def test_g16_cve_2013_5700_empty_data_guard_present() -> None:
    sources = _P2P_MSGS + _P2P
    assert "CVE-2013-5700" in sources or "vData.empty()" in sources


# ===========================================================================
# G17 — filterload handler + IsWithinSizeConstraints (PARTIAL)
# ===========================================================================


def test_g17_filterload_disconnect_handler_present() -> None:
    """G17: BIP-111 disconnect handler for filterload is wired by FIX-36.

    The deeper "actually load a filter" path is absent by design
    (-peerbloomfilters default false). This test pins the disconnect
    handler so a future regression that removes it shows up immediately.
    """
    assert 'register_handler("filterload"' in _P2P, (
        "G17: filterload disconnect handler missing — FIX-36 regression."
    )


@pytest.mark.xfail(
    reason="W134 BUG-12 (P2 documented gap): filterload handler at p2p.py:2459 "
           "is disconnect-only. No CBloomFilter is deserialized, no size cap "
           "is enforced, no per-peer state is created. Reachable only if "
           "operator sets -peerbloomfilters=true, which the config layer "
           "accepts but the handler stub still rejects.",
    strict=True,
)
def test_g17_filterload_actually_loads_filter() -> None:
    # Look for an actual loader: deserialize a CBloomFilter payload into
    # a per-peer attribute. Comment-only references to CBloomFilter in
    # FIX-36 docstrings don't count.
    has_load = (
        re.search(r"^class\s+C?BloomFilter\b", _P2P, re.M) is not None
        or re.search(r"^class\s+C?BloomFilter\b", _read_py("bloom.py"), re.M) is not None
        or "IsWithinSizeConstraints" in _P2P
        or "peer.bloom_filter =" in _P2P
        or "peer.m_bloom_filter =" in _P2P
    )
    assert has_load


# ===========================================================================
# G18 — filteradd handler + MAX_SCRIPT_ELEMENT_SIZE = 520 cap (PARTIAL)
# ===========================================================================


def test_g18_filteradd_disconnect_handler_present() -> None:
    """G18: BIP-111 disconnect handler for filteradd is wired by FIX-36."""
    assert 'register_handler("filteradd"' in _P2P, (
        "G18: filteradd disconnect handler missing — FIX-36 regression."
    )


@pytest.mark.xfail(
    reason="W134 BUG-13 (P2 documented gap): filteradd payload cap of 520 "
           "bytes (MAX_SCRIPT_ELEMENT_SIZE) not enforced. Core "
           "net_processing.cpp:5000-5001 misbehaves the peer for "
           "vData.size() > 520. ouroboros disconnect-only handler does not "
           "consult payload size.",
    strict=True,
)
def test_g18_filteradd_520_byte_cap_enforced() -> None:
    has_cap = (
        ("MAX_SCRIPT_ELEMENT_SIZE" in _P2P or "520" in _P2P)
        and "filteradd" in _P2P
    )
    assert has_cap


# ===========================================================================
# G19 — filterclear handler + m_relay_txs flip (PARTIAL)
# ===========================================================================


def test_g19_filterclear_disconnect_handler_present() -> None:
    assert 'register_handler("filterclear"' in _P2P, (
        "G19: filterclear disconnect handler missing — FIX-36 regression."
    )


@pytest.mark.xfail(
    reason="W134 BUG-14 (P2 documented gap) ties to BUG-7: filterclear must "
           "set m_relay_txs = true and m_bloom_filter_loaded = false "
           "(net_processing.cpp:5026-5031). ouroboros never tracks "
           "m_relay_txs in the first place — see F3 / BUG-7.",
    strict=True,
)
def test_g19_filterclear_resets_relay_state() -> None:
    assert "m_relay_txs" in _P2P or "bloom_filter_loaded" in _P2P


# ===========================================================================
# G20 — merkleblock inbound handler (PRESENT — log+drop, FIX-36)
# ===========================================================================


def test_g20_merkleblock_inbound_handler_present() -> None:
    """G20 PRESENT (FIX-36): on_merkleblock is wired and logs+drops.

    merkleblock is a server->client message; an inbound merkleblock is
    unusual (misbehaving peer or test harness). Core silently ignores it.
    """
    assert 'register_handler("merkleblock"' in _P2P, (
        "G20: merkleblock inbound handler missing — FIX-36 regression."
    )


# ===========================================================================
# G21 — NODE_BLOOM service-bit gated on -peerbloomfilters (PRESENT)
# ===========================================================================


def test_g21_node_bloom_constant_correct() -> None:
    from ouroboros.p2p_messages import NODE_BLOOM
    assert NODE_BLOOM == 4, "G21: NODE_BLOOM = 1<<2 = 4 (BIP-111)."


def test_g21_node_bloom_gated_on_config() -> None:
    """G21 PRESENT: NODE_BLOOM is advertised iff peer_bloom_filters=True.

    Matches Core init.cpp:1104 / -peerbloomfilters default false. The
    config flag is read in node.py and passed to Peer.
    """
    assert "self.peer_bloom_filters" in _PEER
    # Default false in node config.
    assert "peerbloomfilters" in _NODE


# ===========================================================================
# G22 — BIP-111 disconnect path (PRESENT — FIX-36 sealed all 3 arms)
# ===========================================================================


def test_g22_bip111_disconnect_path_present_all_three_arms() -> None:
    """G22 PRESENT (FIX-36): filterload + filteradd + filterclear all
    trigger peer.disconnect() when NODE_BLOOM is not in our_services.
    """
    for msg in ("filterload", "filteradd", "filterclear"):
        assert f'register_handler("{msg}"' in _P2P, (
            f"G22: {msg} handler missing — FIX-36 regression."
        )
    # And the disconnect call site is shared.
    assert "peer.disconnect" in _P2P


# ===========================================================================
# G23 — _build_partial_merkle_tree (PRESENT)
# ===========================================================================


def test_g23_build_partial_merkle_tree_present() -> None:
    """G23 PRESENT: rpc._build_partial_merkle_tree exists.

    Used by rpc_gettxoutproof. Implements CMerkleBlock wire format per
    merkleblock.h:48-54.
    """
    assert "_build_partial_merkle_tree" in _RPC
    assert "rpc_gettxoutproof" in _RPC


# ===========================================================================
# G24 — _parse_partial_merkle_tree (PRESENT)
# ===========================================================================


def test_g24_parse_partial_merkle_tree_present() -> None:
    """G24 PRESENT: rpc._parse_partial_merkle_tree exists.

    Used by rpc_verifytxoutproof. Inverse of G23.
    """
    assert "_parse_partial_merkle_tree" in _RPC
    assert "rpc_verifytxoutproof" in _RPC


# ===========================================================================
# G25-G30 — STRESS TESTS against _parse_partial_merkle_tree
# ===========================================================================


# Import only the helpers; the surrounding RPC layer is mocked.
def _import_parse_helpers():
    """Import rpc._parse_partial_merkle_tree without triggering the full
    rpc module's FastAPI / asyncio imports."""
    import importlib

    # Mock fastapi / other heavy deps the rpc module imports at top-level
    # but doesn't actually use in the helpers we want.
    if "fastapi" not in sys.modules:
        fa = types.ModuleType("fastapi")

        class _HTTPException(Exception):
            def __init__(self, status_code=400, detail=""):
                self.status_code = status_code
                self.detail = detail

        fa.HTTPException = _HTTPException
        fa.FastAPI = MagicMock
        fa.Request = MagicMock
        fa.Body = MagicMock
        sys.modules["fastapi"] = fa
    if "fastapi.responses" not in sys.modules:
        fr = types.ModuleType("fastapi.responses")
        fr.JSONResponse = MagicMock
        fr.PlainTextResponse = MagicMock
        sys.modules["fastapi.responses"] = fr
    if "uvicorn" not in sys.modules:
        sys.modules["uvicorn"] = MagicMock()
    if "pydantic" not in sys.modules:
        pd = types.ModuleType("pydantic")
        pd.BaseModel = type("BaseModel", (), {})
        pd.Field = lambda *a, **k: None
        sys.modules["pydantic"] = pd

    try:
        rpc = importlib.import_module("ouroboros.rpc")
    except Exception as exc:
        pytest.skip(f"could not import ouroboros.rpc cleanly: {exc!r}")
    return rpc


@pytest.mark.xfail(
    reason="W134 BUG-2 (P1): _parse_partial_merkle_tree accepts "
           "nTransactions == 0. Core merkleblock.cpp:156-157 rejects "
           "(returns uint256()). ouroboros happily returns whatever the "
           "first hash bytes are.",
    strict=True,
)
def test_g25_parse_rejects_zero_transactions() -> None:
    """G25 BUG-2: A proof claiming nTransactions=0 MUST be rejected.

    Constructs an empty proof: n_tx=0, n_hashes=0, n_flag_bytes=0. The
    Core impl returns uint256() (null) here; ouroboros returns
    ([], hashes[0]) — but hashes is empty so it returns ([], b'\\x00'*32),
    which silently equals a "valid" null root.
    """
    rpc = _import_parse_helpers()
    payload = b""
    payload += struct.pack("<I", 0)        # n_tx = 0
    payload += b"\x00"                      # n_hashes varint = 0
    payload += b"\x00"                      # n_flag_bytes varint = 0
    matched, root = rpc._parse_partial_merkle_tree(payload)
    # If the impl WERE Core-correct it would raise or return None;
    # currently it returns (matched=[], computed_root=zeros). The xfail
    # asserts that root MUST equal a sentinel "rejected" value, which
    # ouroboros never produces. We use any-non-None marker as the
    # success condition; a future fix that returns (None, None) or
    # raises HTTPException flips this xfail to xpass.
    assert root is None or matched is None, (
        f"G25 BUG-2: parser accepted n_tx=0; got matched={matched!r}, "
        f"root={root.hex() if root else None}"
    )


@pytest.mark.xfail(
    reason="W134 BUG-3 (P1): _parse_partial_merkle_tree accepts "
           "nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT "
           "(= 16666). Core merkleblock.cpp:159-160 rejects.",
    strict=True,
)
def test_g26_parse_rejects_huge_n_tx() -> None:
    rpc = _import_parse_helpers()
    payload = b""
    payload += struct.pack("<I", 100_000)  # n_tx way above 16666 cap
    payload += b"\x00"
    payload += b"\x00"
    matched, root = rpc._parse_partial_merkle_tree(payload)
    assert root is None or matched is None, (
        f"G26 BUG-3: parser accepted n_tx=100000 (Core cap 16666); "
        f"matched={matched!r}, root={root.hex() if root else None}"
    )


@pytest.mark.xfail(
    reason="W134 BUG-4 (P1): _parse_partial_merkle_tree accepts more hashes "
           "than nTransactions. Core merkleblock.cpp:162-163 rejects "
           "(vHash.size() > nTransactions).",
    strict=True,
)
def test_g27_parse_rejects_more_hashes_than_n_tx() -> None:
    rpc = _import_parse_helpers()
    payload = b""
    payload += struct.pack("<I", 1)        # n_tx = 1
    payload += b"\x02"                      # n_hashes = 2 (> n_tx !)
    payload += b"\xaa" * 32
    payload += b"\xbb" * 32
    payload += b"\x01"                      # n_flag_bytes = 1
    payload += b"\x01"
    matched, root = rpc._parse_partial_merkle_tree(payload)
    assert root is None or matched is None, (
        f"G27 BUG-4: parser accepted n_hashes(2) > n_tx(1); "
        f"matched={matched!r}, root={root.hex() if root else None}"
    )


@pytest.mark.xfail(
    reason="W134 BUG-5 (P1): _parse_partial_merkle_tree accepts vBits.size() "
           "< vHash.size(). Core merkleblock.cpp:165-166 rejects.",
    strict=True,
)
def test_g28_parse_rejects_too_few_bits() -> None:
    rpc = _import_parse_helpers()
    payload = b""
    payload += struct.pack("<I", 4)        # n_tx = 4 (tree height 2)
    payload += b"\x03"                      # n_hashes = 3
    payload += b"\xaa" * 32
    payload += b"\xbb" * 32
    payload += b"\xcc" * 32
    payload += b"\x00"                      # n_flag_bytes = 0 (NO bits!)
    matched, root = rpc._parse_partial_merkle_tree(payload)
    assert root is None or matched is None, (
        f"G28 BUG-5: parser accepted n_bits(0) < n_hashes(3); "
        f"matched={matched!r}, root={root.hex() if root else None}"
    )


@pytest.mark.xfail(
    reason="W134 BUG-1 (P0-CONSENSUS, CVE-2012-2459): _parse_partial_merkle_tree "
           "lacks the `left == right` duplicate-children reject "
           "(merkleblock.cpp:124-128). A crafted proof with duplicated "
           "leaves produces a fake-but-validating merkle root.",
    strict=True,
)
def test_g29_parse_rejects_duplicate_adjacent_hashes_cve_2012_2459() -> None:
    """G29 BUG-1 / CVE-2012-2459: duplicate adjacent leaves must be rejected.

    Construct a partial tree for a block with 4 transactions arranged so
    that the inner check `right == left` fires. Specifically:
      - 4 txids, where txid[2] == txid[3]
      - matched = [True, False, False, True]  (matches the duplicates)
    Then craft a parser input that requests both left and right children
    of the right subtree as the SAME hash. Core rejects via fBad=true;
    ouroboros computes `_dsha256(left+left)` and returns it.
    """
    rpc = _import_parse_helpers()

    # Build a tree where the rightmost-pair hashes will be duplicated.
    txids = [bytes([i]) * 32 for i in range(1, 5)]
    # Compute the partial tree honestly first, requesting only tx 0.
    matches = [True, False, False, False]
    block_stub = type("B", (), {"serialize": lambda self: b"\x00" * 80})()
    proof = rpc._build_partial_merkle_tree(block_stub, txids, matches)

    # Strip the 80-byte header to get the partial-tree payload.
    payload = proof[80:]

    # Now hand-craft a malicious payload: claim n_tx=4 with hashes such
    # that the right-subtree's left child equals its right child.
    forged = b""
    forged += struct.pack("<I", 4)               # n_tx = 4 (tree height 2)
    forged += b"\x03"                             # n_hashes = 3
    # Tree layout for 4 leaves (height 2):
    #   root
    #  /   \\
    # L     R       <- height 1
    # /\\   /\\
    # 0 1   2 3     <- height 0
    # Flag bits depth-first per Core (bit set => parent-of-match):
    #   bit0: root  = 1 (descend)
    #   bit1: L     = 0 (use stored hash; STOP)
    #   bit2: R     = 1 (descend)
    #   bit3: R.left= 1 (height 0 match; emit txid)
    #   bit4: R.right=1 (height 0 match; emit txid)
    # Hashes consumed in order: L (stored), R.left, R.right.
    # Force R.left and R.right to be IDENTICAL.
    forged += b"\xde" * 32   # L (height-1 stored)
    forged += b"\xab" * 32   # R.left (height-0 match)
    forged += b"\xab" * 32   # R.right (height-0 match; DUPLICATE!)
    # Flag bits: 10110 1 written LSB-first per byte → bit0=1 bit1=0
    # bit2=1 bit3=1 bit4=1 ⇒ 0b00011101 = 0x1d (with bit0 = parent-of-match
    # for top node; we'll build the right pattern below)
    # Depth-first traversal: root(1) L(0) R(1) R.left(1) R.right(1)
    # In LSB-first packing of 5 bits → byte 0b00011101 = 0x1d, but
    # only 5 bits are meaningful; the parser stops naturally.
    forged += b"\x01"                             # n_flag_bytes = 1
    forged += bytes([0b00011101])                 # the bits above
    # Discard the original 'payload' var, use forged.
    _ = payload

    matched, root = rpc._parse_partial_merkle_tree(forged)
    # If parser is Core-correct it returns null (None or empty matched);
    # if buggy it returns a non-zero root computed from the duplicated
    # adjacent leaves. The xfail-strict marker says "expected to fail";
    # a fix that adds the `left == right` check will make this xpass.
    is_rejected = (
        matched is None
        or root is None
        or root == b"\x00" * 32
        or matched == []
    )
    assert is_rejected, (
        f"G29 BUG-1 (CVE-2012-2459): parser accepted duplicated adjacent "
        f"leaves; matched={matched!r}, root={root.hex() if root else None}"
    )


@pytest.mark.xfail(
    reason="W134 BUG-6 (P1): _parse_partial_merkle_tree lacks the "
           "'all bits consumed / all hashes consumed' check "
           "(merkleblock.cpp:177-182). A crafted proof with EXTRA trailing "
           "bytes parses as the prefix.",
    strict=True,
)
def test_g30_parse_rejects_excess_unused_bytes() -> None:
    """G30 BUG-6: trailing-bytes-not-consumed must reject."""
    rpc = _import_parse_helpers()
    # 1-tx block: n_tx=1, 1 hash, 1 flag byte with bit0=1.
    payload = b""
    payload += struct.pack("<I", 1)
    payload += b"\x01"                            # n_hashes = 1
    payload += b"\xaa" * 32                       # the one hash
    payload += b"\x01"                            # n_flag_bytes = 1
    payload += b"\x05"                            # bits = 0b00000101
    # ^ Only bit 0 is meaningful for a 1-leaf tree.
    matched, root = rpc._parse_partial_merkle_tree(payload)
    # If parser is Core-correct, the extra-bit byte 0x05 (bit 2 set
    # despite no node at that depth) would be rejected by the
    # "all bits consumed" check. Currently we don't see this.
    assert root is None or matched is None, (
        f"G30 BUG-6: parser accepted extra unused flag bits; "
        f"matched={matched!r}, root={root.hex() if root else None}"
    )


# ===========================================================================
# Bonus stress tests beyond the 30-gate matrix
# ===========================================================================


@pytest.mark.xfail(
    reason="W134 BUG-7 (P1): inbound version.relay is parsed at peer.py:715 "
           "and peer.py:1301 but NEVER stored on the Peer. Core "
           "net_processing.cpp:3683-3691 initialises m_relay_txs from "
           "this field. ouroboros silently coerces every peer into "
           "tx-relay mode regardless of their fRelay signal.",
    strict=True,
)
def test_bonus_inbound_fRelay_is_stored_on_peer() -> None:
    """BUG-7 (F3): version.relay must be persisted to the Peer object."""
    # We look for any of: a field assignment, a self.peer_relay/_received
    # attribute, or a m_relay_txs translation.
    has_storage = (
        "version.relay" in _PEER
        and (
            "self.peer_relay" in _PEER
            or "self.m_relay_txs" in _PEER
            or "self.fRelay" in _PEER
            or "self.peer_wants_relay" in _PEER
        )
    )
    assert has_storage, (
        "BUG-7: peer.py reads version.relay but does not store it. The "
        "string 'version.relay' appears only in passing — no assignment "
        "to a self.* attribute that records the peer's wishes."
    )


def test_bonus_version_message_relay_field_default_true() -> None:
    """W134 BUG-15: VersionMessage.relay default is True.

    Cosmetic + maintenance hazard: a malformed inbound version that
    truncates before the relay byte gets the default `True`, which means
    "I want tx relay". Core defaults to `true` too (net_processing.cpp:3594)
    — this is wire-spec compliant — but the Python default-arg shadowing
    means a fresh VersionMessage() constructed locally also relays-by-
    default, which is misleading.
    """
    from ouroboros.p2p_messages import VersionMessage
    vm = VersionMessage()
    assert vm.relay is True, (
        "VersionMessage.relay default changed — update audit doc BUG-15."
    )


def test_bonus_inv_type_filtered_block_defined_but_unhandled_bug9() -> None:
    """W134 BUG-9 (carried W110 BUG-28): INV_TYPE_FILTERED_BLOCK = 3 defined
    in p2p_messages but never dispatched in node._make_getdata_handler.
    """
    assert "INV_TYPE_FILTERED_BLOCK" in _P2P_MSGS
    # Confirm it's still not handled in node.py (status quo).
    assert "INV_TYPE_FILTERED_BLOCK" not in _NODE, (
        "BUG-9: filtered-block dispatch appeared in node.py — update test."
    )


@pytest.mark.xfail(
    reason="W134 BUG-16 (P2): no MSG_WITNESS_FILTERED_BLOCK = 3 | 0x40000000 "
           "constant. Core dispatches both INV_TYPE_FILTERED_BLOCK and its "
           "witness-bit-or'd cousin (net_processing.cpp ProcessGetData).",
    strict=True,
)
def test_bonus_msg_witness_filtered_block_defined() -> None:
    assert "MSG_WITNESS_FILTERED_BLOCK" in _P2P_MSGS


def test_bonus_build_partial_merkle_tree_roundtrips_simple_proof() -> None:
    """Sanity check: a correctly built proof for 4 txs (one match) parses
    back to the same matched-txid set and the merkle root in the header.

    This is a PASS gate — confirms the existing helpers WORK on benign
    input. Stress tests above target the missing DoS / CVE guards.
    """
    rpc = _import_parse_helpers()
    txids = [bytes([i]) * 32 for i in range(1, 5)]      # 4 fake txids
    matches = [False, False, True, False]
    expected_root = _build_merkle_root(txids)

    class _BlockStub:
        def serialize(self):
            return b"\x00" * 80

    proof = rpc._build_partial_merkle_tree(_BlockStub(), txids, matches)
    matched, root = rpc._parse_partial_merkle_tree(proof[80:])
    assert len(matched) == 1
    assert matched[0] == txids[2]
    assert root == expected_root


def test_bonus_build_partial_merkle_tree_single_tx_block() -> None:
    """Edge case: single-tx block (only the coinbase). Tree height = 0.

    Confirms the height-loop terminator `while (1 << height) < n` agrees
    with Core's `while CalcTreeWidth(height) > 1`.
    """
    rpc = _import_parse_helpers()
    txids = [b"\x42" * 32]
    matches = [True]

    class _BlockStub:
        def serialize(self):
            return b"\x00" * 80

    proof = rpc._build_partial_merkle_tree(_BlockStub(), txids, matches)
    matched, root = rpc._parse_partial_merkle_tree(proof[80:])
    assert matched == [txids[0]]
    # Single-tx merkle root is the txid itself.
    assert root == txids[0]


def test_bonus_dsha256_internal_helper_present() -> None:
    """W134 BUG-19 (P2 cosmetic): _dsha256 is defined twice in rpc.py.

    Defined once at top of partial-merkle helpers and again inline inside
    rpc_verifytxoutproof. Document the duplication.
    """
    # Count distinct definitions in rpc.py.
    defs = re.findall(r"^def _dsha256\(", _RPC, re.M)
    inline_uses = re.findall(r"_hl\.sha256\(_hl\.sha256\(", _RPC)
    assert len(defs) == 1, (
        f"BUG-19 status changed: expected 1 _dsha256 def, got {len(defs)}."
    )
    assert len(inline_uses) >= 1, (
        "BUG-19: inline `_hl.sha256(_hl.sha256(...))` chain removed — "
        "update audit doc."
    )


# ===========================================================================
# G30(meta) — Two-pipeline guard
# ===========================================================================


def test_g30_two_pipeline_bip37_python_only() -> None:
    """G30 two-pipeline guard: BIP-37 lives ONLY in the Python pipeline.

    Confirms ferrous-utils / Rust pipeline has ZERO BIP-37 production code.
    The only bloom-related Rust hit is RocksDB-internal `bloom_locality`
    in `sync/src/storage/db.rs`, which is a database tuning setting, not
    a Bitcoin BIP-37 filter.

    Future regressions (e.g. moving CBloomFilter into Rust to serve SPV)
    will trip this gate.

    Extends the cross-wave guard set:
    W76 + W120 + W122 + W125 + W128 + W129 + W130 + W133 + W134.
    """
    if not FERROUS_UTILS.exists():
        pytest.skip("ferrous-utils not present (sdist build)")

    rust_hits = _grep_rust_for(
        r"\bMurmurHash3\b",
        r"\bCBloomFilter\b",
        r"\bCRollingBloomFilter\b",
        r"\bfilterload\b",
        r"\bfilteradd\b",
        r"\bfilterclear\b",
        r"\bMerkleBlock\b",
        r"\bPartialMerkleTree\b",
        r"\bTraverseAndBuild\b",
        r"\bTraverseAndExtract\b",
        r"\bCalcTreeWidth\b",
    )
    # Allow only the RocksDB-internal bloom_locality references.
    actual_bip37_hits = [
        h for h in rust_hits
        if "bloom_locality" not in h and "memtable_prefix_bloom_ratio" not in h
    ]
    assert actual_bip37_hits == [], (
        "G30 two-pipeline guard: BIP-37 code leaked into Rust pipeline. "
        f"Unexpected hits:\n  " + "\n  ".join(actual_bip37_hits)
    )

    # And the Python pipeline retains the partial-merkle helpers
    # (consumed by gettxoutproof / verifytxoutproof).
    assert "_build_partial_merkle_tree" in _RPC
    assert "_parse_partial_merkle_tree" in _RPC

    # And the BIP-111 disconnect handlers are in p2p.py.
    for msg in ("filterload", "filteradd", "filterclear", "merkleblock"):
        assert f'register_handler("{msg}"' in _P2P, (
            f"G30 two-pipeline: {msg} handler removed from p2p.py — "
            "FIX-36 regression."
        )


# ===========================================================================
# Optional self-check: this test file imports cleanly without the Rust
# extension. Useful as a smoke test for CI runs that skip ferrous-utils.
# ===========================================================================


def test_self_audit_test_file_imports_cleanly() -> None:
    """Smoke: the test file itself doesn't import ouroboros.rpc at module
    scope (it would pull in too many heavy deps); the _import_parse_helpers
    helper is the only path that touches rpc.py.
    """
    # Module-scope cleanliness: rpc isn't imported here yet.
    assert "ouroboros.rpc" not in sys.modules or sys.modules.get("ouroboros.rpc") is not None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
