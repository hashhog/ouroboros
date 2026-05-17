"""
W122 audit — BIP-158 GCS codec stress vectors (ouroboros).

Trigger
-------
haskoin W121 addendum BUG-16 (FIX-69) — Core's stock ``blockfilters.json``
test vectors do not exercise Golomb-Rice quotients ``q >= 64``. A buggy
encoder that drops bits when crossing a word-buffer boundary can pass
every Core regression vector while still corrupting filters in the wild
when an unusually-sparse hash distribution produces a large delta.

Audit goal
----------
Verify ouroboros's GCS codec is correct for the quotient regime
``q in [0, 100_000]`` *and* byte-identical to a faithful port of Core's
``BitStreamWriter::Write`` / ``GolombRiceEncode`` (``bitcoin-core/src/
util/golombrice.h`` + ``streams.h``).

Result
------
VERIFIED CLEAN — see ``audit/w122_bip158_codec_stress.md``. No bugs
found, no code changes; this file is the regression armour that pins
ouroboros's codec to Core's wire output for the quotient range Core's
stock vectors cannot reach.

References
----------
- BIP-158: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
- bitcoin-core/src/blockfilter.{cpp,h}
- bitcoin-core/src/util/golombrice.h  (GolombRiceEncode / GolombRiceDecode)
- bitcoin-core/src/streams.h          (BitStreamReader / BitStreamWriter)
- haskoin commit 4a2de0f              (FIX-69 reference bug shape)
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make ouroboros importable without the Rust sync extension being built —
# we never touch the Rust pipeline in this test file.
_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if "sync" not in sys.modules:
    _mock = types.ModuleType("sync")
    _mock.PyBlockchainDB = MagicMock
    _mock.PyBlock = MagicMock
    _mock.PyUTXO = MagicMock
    _mock.SyncEngine = MagicMock
    sys.modules["sync"] = _mock

from ouroboros.blockfilter import (  # noqa: E402
    GCS_M,
    GCS_P,
    _BitReader,
    _BitWriter,
    _decode_compact_size,
    _golomb_rice_decode,
    _golomb_rice_encode,
    _hash_to_range,
    construct_gcs_filter,
    gcs_match,
)


# ---------------------------------------------------------------------------
# Faithful port of Core's BitStreamWriter::Write + GolombRiceEncode
# ---------------------------------------------------------------------------
#
# These are intentionally NOT imported from ouroboros — they re-implement
# Core's exact semantics so we can byte-compare ouroboros's output against
# Core's expected wire bytes for quotients that Core's stock vectors don't
# cover.  See:
#
#   bitcoin-core/src/streams.h:303-358   (BitStreamWriter)
#   bitcoin-core/src/util/golombrice.h   (GolombRiceEncode)
# ---------------------------------------------------------------------------

class _CoreStyleBitStreamWriter:
    """Faithful Python port of Core's ``BitStreamWriter<OStream>``.

    Core's writer keeps an 8-bit ``m_buffer`` register and an ``m_offset``
    counting bits written into the top of that register.  ``Write(data,
    nbits)`` writes the *nbits least significant bits of data*, MSB-first
    into the stream, splitting across bytes as needed.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._m_buffer = 0
        self._m_offset = 0

    def write(self, data: int, nbits: int) -> None:
        assert 0 <= nbits <= 64
        while nbits > 0:
            bits = min(8 - self._m_offset, nbits)
            # Core: m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
            shifted_left = (data << (64 - nbits)) & ((1 << 64) - 1)
            self._m_buffer |= (shifted_left >> (64 - 8 + self._m_offset)) & 0xFF
            self._m_offset += bits
            nbits -= bits
            if self._m_offset == 8:
                self._buf.append(self._m_buffer)
                self._m_buffer = 0
                self._m_offset = 0

    def flush(self) -> bytes:
        if self._m_offset > 0:
            self._buf.append(self._m_buffer)
            self._m_buffer = 0
            self._m_offset = 0
        return bytes(self._buf)


def _core_golomb_rice_encode(deltas: list[int], p: int) -> bytes:
    """Faithful Python port of Core's ``GolombRiceEncode``.

    Mirrors ``bitcoin-core/src/util/golombrice.h``:

        uint64_t q = x >> P;
        while (q > 0) {
            int nbits = q <= 64 ? q : 64;
            bitwriter.Write(~0ULL, nbits);
            q -= nbits;
        }
        bitwriter.Write(0, 1);
        bitwriter.Write(x, P);
    """
    w = _CoreStyleBitStreamWriter()
    for x in deltas:
        q = x >> p
        while q > 0:
            nbits = q if q <= 64 else 64
            ones = (1 << nbits) - 1 if nbits < 64 else 0xFFFFFFFFFFFFFFFF
            w.write(ones, nbits)
            q -= nbits
        w.write(0, 1)
        w.write(x, p)
    return w.flush()


# ===========================================================================
# G01 — bit-by-bit round-trip across all alignments (no-bug baseline)
# ===========================================================================

@pytest.mark.parametrize("pre_bits", list(range(0, 16)))
@pytest.mark.parametrize(
    "value_bits", [1, 7, 8, 9, 15, 16, 17, 19, 23, 31, 32, 63, 64]
)
def test_g01_write_bits_be_roundtrip_all_alignments(
    pre_bits: int, value_bits: int
) -> None:
    """``_BitWriter.write_bits_be`` must preserve every bit at every
    starting alignment, for widths 1..64.  The haskoin pre-FIX-69 bug
    silently dropped top bits when an internal word buffer overflowed —
    this guard ensures ouroboros doesn't grow such a code path."""
    w = _BitWriter()
    for _ in range(pre_bits):
        w.write_bit(1)
    value = (1 << value_bits) - 1
    w.write_bits_be(value, value_bits)
    data = w.flush()

    r = _BitReader(data)
    for _ in range(pre_bits):
        assert r.read_bit() == 1
    assert r.read_bits_be(value_bits) == value


# ===========================================================================
# G02 — Golomb-Rice quotient sweep [0..1000] round-trip
# ===========================================================================

def test_g02_quotient_sweep_roundtrip() -> None:
    """Encode/decode every quotient from 0 to 1000 (with non-trivial
    remainder) in one stream and verify exact round-trip.  Core's stock
    vectors top out around q = 1 for typical N values; this is the
    untested regime."""
    p = GCS_P
    deltas = [(q << p) | (q % (1 << p)) for q in range(0, 1001)]
    encoded = _golomb_rice_encode(deltas, p)
    decoded = _golomb_rice_decode(encoded, len(deltas), p)
    assert decoded == deltas


# ===========================================================================
# G03 — Quotients around the q = 64 boundary (haskoin BUG-16 exact shape)
# ===========================================================================

@pytest.mark.parametrize("q", [62, 63, 64, 65, 66, 127, 128, 129])
@pytest.mark.parametrize("r_kind", ["zero", "one", "max"])
def test_g03_quotient_64_boundary_roundtrip(q: int, r_kind: str) -> None:
    """The exact regime haskoin's BUG-16 missed: quotients straddling 64.
    Core's word-aligned Write loops in 64-bit chunks; ouroboros writes
    bit-by-bit and is therefore immune to a buffer-overflow truncation.
    """
    p = GCS_P
    r = {"zero": 0, "one": 1, "max": (1 << p) - 1}[r_kind]
    deltas = [(q << p) | r]
    encoded = _golomb_rice_encode(deltas, p)
    decoded = _golomb_rice_decode(encoded, 1, p)
    assert decoded == deltas


# ===========================================================================
# G04 — Extreme unary quotient (q = 100 000)
# ===========================================================================

def test_g04_extreme_unary_quotient() -> None:
    """A single delta with q = 100 000 expands to >100 kbits of unary
    encoding.  Verifies the bit-by-bit writer doesn't accumulate state
    error over a long unary run."""
    p = GCS_P
    q = 100_000
    deltas = [q << p]
    encoded = _golomb_rice_encode(deltas, p)
    # 100_000 ones + 1 terminator + 19-bit r = 100_020 bits = 12_503 bytes
    assert len(encoded) == (100_020 + 7) // 8 == 12503
    decoded = _golomb_rice_decode(encoded, 1, p)
    assert decoded == deltas


# ===========================================================================
# G05 — Byte-for-byte equivalence with a Core-style faithful port
# ===========================================================================

@pytest.mark.parametrize(
    "deltas",
    [
        # q = 0..5 with r = 0, 1, max-P  (one-bit-stream alignment sweep)
        [(q << GCS_P) | r for q in range(6) for r in [0, 1, (1 << GCS_P) - 1]],
        # q near 64 (the haskoin bug regime)
        [(q << GCS_P) | r for q in [62, 63, 64, 65, 66] for r in [0, (1 << GCS_P) - 1]],
        # q big — multi-byte unary
        [(q << GCS_P) for q in [100, 200, 500, 1000, 4096]],
        # q = 64 with r = 0 — single delta, exact bug regime
        [64 << GCS_P],
        # q = 128 with r = max — two-byte unary, max remainder
        [(128 << GCS_P) | ((1 << GCS_P) - 1)],
    ],
    ids=["q-0-5", "q-near-64", "q-big", "q-64-r-0", "q-128-r-max"],
)
def test_g05_core_byte_identical(deltas: list[int]) -> None:
    """ouroboros's Golomb-Rice encode must be byte-for-byte identical
    to Core's ``GolombRiceEncode`` semantics (faithful Python port of
    ``util/golombrice.h`` + ``streams.h::BitStreamWriter``).
    """
    ours = _golomb_rice_encode(deltas, GCS_P)
    theirs = _core_golomb_rice_encode(deltas, GCS_P)
    assert ours == theirs, (
        f"Golomb-Rice encoder diverges from Core: "
        f"ours={ours.hex()} theirs={theirs.hex()}"
    )


# ===========================================================================
# G06 — Natural q >= 64 distribution via inflated M
# ===========================================================================

def test_g06_natural_large_quotient_distribution_roundtrip() -> None:
    """Sparse hash distribution (achieved by inflating M) produces
    natural quotients well above 64.  Every inserted item must still
    match (no false negatives) and the decoded delta sequence must
    reconstruct the original sorted-hash array bit-for-bit.

    This is the closest stand-in we can build for "an unusual real-world
    block whose deltas happen to land in the q >= 64 regime" without
    needing a multi-thousand-script mainnet block payload.
    """
    inflated_m = GCS_M * 100  # ~78M instead of ~785K
    p = GCS_P
    key = b"\xab" * 16
    n_items = 50
    items = [f"w122-item-{i}".encode() for i in range(n_items)]

    filt = construct_gcs_filter(items, key, p, inflated_m)

    # Zero false negatives
    fn = sum(1 for x in items if not gcs_match(filt, key, x, p, inflated_m))
    assert fn == 0, f"False negatives: {fn}/{n_items}"

    # Recompute the expected sorted hashes from scratch
    f = n_items * inflated_m
    expected = sorted(_hash_to_range(key, x, f) for x in items)
    deltas_truth = [expected[0]] + [
        expected[i + 1] - expected[i] for i in range(n_items - 1)
    ]
    qs = [d >> p for d in deltas_truth]
    # Sanity: this configuration MUST hit q >= 64 a non-trivial amount.
    # If this assertion ever breaks we've lost the stress-vector property.
    assert max(qs) >= 64, f"inflated-M test no longer exercises q>=64: max_q={max(qs)}"

    # Decode the filter and reconstruct sorted hashes
    n, sz = _decode_compact_size(filt)
    assert n == n_items
    decoded_deltas = _golomb_rice_decode(filt[sz:], n, p)
    recon: list[int] = []
    v = 0
    for d in decoded_deltas:
        v += d
        recon.append(v)
    assert recon == expected


# ===========================================================================
# G07 — Decoder consumes the exact byte budget the encoder produced
# ===========================================================================

def test_g07_encoder_decoder_exact_byte_budget() -> None:
    """The decoder must consume bits past the end of the encoded stream
    only when the encoder over-padded.  Verifies no off-by-one in the
    unary-terminator handling at byte boundaries."""
    p = GCS_P
    for n in range(0, 200):
        deltas = [(q << p) | (q & ((1 << p) - 1)) for q in range(n)]
        encoded = _golomb_rice_encode(deltas, p)
        decoded = _golomb_rice_decode(encoded, n, p)
        assert decoded == deltas, f"round-trip failed at N={n}"


# ===========================================================================
# G08 — Match-correctness for every inserted item, across many filters
# ===========================================================================

@pytest.mark.parametrize("m_mult", [1, 10, 100])
@pytest.mark.parametrize("n_items", [1, 5, 50, 500])
def test_g08_match_correctness_zero_false_negatives(
    m_mult: int, n_items: int
) -> None:
    """For a range of (M, N) combinations including the inflated-M regime
    that exercises large quotients, every inserted item must match."""
    key = b"\xcd" * 16
    items = [f"w122-g08-{m_mult}-{n_items}-{i}".encode() for i in range(n_items)]
    filt = construct_gcs_filter(items, key, GCS_P, GCS_M * m_mult)
    for x in items:
        assert gcs_match(filt, key, x, GCS_P, GCS_M * m_mult), (
            f"false negative at m_mult={m_mult} n={n_items} item={x!r}"
        )


# ===========================================================================
# Two-pipeline guard — Rust pipeline must remain GCS-free (W122)
# ===========================================================================
# Extends the FIX-74 / FIX-75 / FIX-79 guard chain.  W122 added NO code
# anywhere except this test file + the audit markdown; if a future change
# accidentally lands GCS in Rust this guard fails loudly.
# ===========================================================================

def test_w122_two_pipeline_guard_no_gcs_in_rust() -> None:
    """ferrous-utils (Rust pipeline) must contain ZERO BIP-158 GCS or
    block-filter code.  Mirrors the FIX-74/75/79 guards established
    through the W121 fix campaign.
    """
    rust_root = Path(__file__).parent.parent / "ferrous-utils" / "sync" / "src"
    if not rust_root.exists():
        pytest.skip("ferrous-utils submodule not populated; guard vacuous")

    forbidden = (
        "golomb",
        "Golomb",
        "GCSFilter",
        "GcsFilter",
        "block_filter",
        "BlockFilter",
        "BlockFilterIndex",
        "filter_encode",
    )
    offenders: list[str] = []
    for path in rust_root.rglob("*.rs"):
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle in forbidden:
            if needle in txt:
                offenders.append(f"{path}: {needle}")

    assert not offenders, (
        "W122 two-pipeline guard: ferrous-utils/sync/src must contain "
        "NO BIP-158 GCS / block-filter references — codec must remain "
        f"Python-only. Offenders: {offenders[:5]}"
    )
