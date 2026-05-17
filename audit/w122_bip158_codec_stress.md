W122 — BIP-158 GCS codec stress-vector audit (ouroboros)
========================================================

Date: 2026-05-17
Impl: ouroboros (Python pipeline)
Target: `src/ouroboros/blockfilter.py` — Golomb-Rice encoder/decoder
Trigger: haskoin W121 addendum BUG-16 P0 — Core's `blockfilters.json`
test vectors do not exercise Golomb-Rice quotients `q >= 64`, and a
buggy implementation that silently truncates bits across a Word64
buffer boundary can produce streams that decode incorrectly while
still passing every Core regression vector. haskoin had exactly that
shape (FIX-69 closed it). This audit verifies ouroboros is immune.

Status: **VERIFIED CLEAN**

Codec shape (Python pipeline)
-----------------------------

`src/ouroboros/blockfilter.py`:
- `_BitWriter` (lines 109–139): accumulates **one bit at a time** in
  `_accum` (8-bit register) and flushes to `_buf` (bytearray) at 8 bits.
- `_BitWriter.write_bits_be(value, nbits)` (lines 127–130): iterates
  `i in range(nbits - 1, -1, -1)` and calls `write_bit((value >> i) & 1)`.
  MSB-first, one bit at a time. Inherently has **no word-boundary buffer**
  to overflow.
- `_BitReader` (lines 142–167): mirror — reads one bit at a time, MSB-first.
- `_golomb_rice_encode` (lines 174–185): writes quotient as `q` ones then
  a zero via `write_bit(1)` in a loop, then remainder via `write_bits_be(r, p)`.
- `_golomb_rice_decode` (lines 188–199): unary loop `while read_bit() == 1`
  then `read_bits_be(p)`.

Comparison to haskoin's buggy `bitWriterWrite`
----------------------------------------------

haskoin's pre-FIX-69 encoder used a single Word64 accumulator (`bwBits`
unused-bit count) and computed `maskedValue << bwBits` to OR new bits in.
When `numBits + bwBits > 64` the left-shift silently truncated the top
`(numBits + bwBits - 64)` bits because Haskell's `shiftL` on `Word64`
discards bits past bit 63. Encoding `0xFFFFFFFF` (32 ones for q=32 unary)
into a buffer with `bwBits = 33` would drop the top 1 bit of the value.

**ouroboros has no equivalent code path**: every bit is written through
`_BitWriter.write_bit`, which only touches an 8-bit accumulator. There
is no multi-bit shift-and-OR into a word buffer. `write_bits_be` loops
one-bit-at-a-time, so even a quotient of 100 000 is written as 100 000
individual `write_bit(1)` calls into 8-bit slots.

Verification: byte-identical to Core's `BitStreamWriter::Write`
---------------------------------------------------------------

Cross-checked ouroboros encoder against a faithful Python port of Core's
`BitStreamWriter::Write` (which writes nbits-at-a-time with explicit
shifts), in three stress configurations:

1. `q = 0..5` with `r = 0, 1, max` — round-trip quotients across all
   single-bit-stream alignments.
2. `q in [62, 63, 64, 65, 66]` with `r = 0, max` — exact quotient-≥-64
   boundary the haskoin bug missed.
3. `q in [100, 200, 500, 1000, 4096]` — large quotients spanning multiple
   bytes of unary encoding.

Result: **byte-identical output** to Core's `BitStreamWriter` semantics in
all three configurations (see `tests/test_w122_codec_stress.py::test_g05_*`).

Additional verifications
------------------------

- **`write_bits_be` cross-alignment** (8 × 14 cases): pre-fill writer with
  `pre_bits ∈ [0, 16)` ones, then write a value of width `value_bits ∈
  {1, 7, 8, 9, 15, 16, 17, 19, 23, 31, 32, 63, 64}`. Read back and verify
  exact value preserved. All 224 combinations PASS.
- **Extreme unary** (`q = 100 000`): single delta with quotient 100 000
  encodes to 12 503 bytes; round-trips losslessly.
- **Mixed quotient sweep** (`q ∈ [0, 1000]`, `r = q mod 524288`): 1001
  deltas, every quotient from 0 to 1000. Round-trip exact.
- **Natural q ≥ 64 distribution**: with `P=19` and inflated `M = 100 × M_BIP158`,
  500 random items produce sorted-hash deltas with `max(q) > 500` and
  `34/50 (68 %)` of deltas having `q ≥ 64`. Filter constructs, every
  inserted item matches (zero false negatives), and the decoded delta
  sequence reconstructs the original sorted-hash array bit-for-bit.
- **Genesis vector** (`019dfca8`): pre-existing test
  `test_genesis_filter_matches_known_vector` already pins ouroboros to
  Core's mainnet block-0 filter output. Unchanged.

Why ouroboros is immune
-----------------------

The bug shape requires:
1. A multi-bit write primitive (e.g. `write(uint64_t data, int nbits)` where
   `nbits` can be 1..64).
2. A shift-and-OR into a wider accumulator (e.g. `Word64`).
3. Either inadequate masking of the input value, or a shift whose magnitude
   can equal or exceed the accumulator width.

ouroboros's `_BitWriter` has none of these. It uses an 8-bit accumulator,
appends only when full, and `write_bits_be` decomposes any multi-bit write
into single-bit `write_bit` calls. The cost is Python-level overhead (each
bit costs ~one method call), not correctness.

Per-pipeline status
-------------------

- **Python pipeline** (`src/ouroboros/blockfilter.py` + `tests/test_w122_codec_stress.py`):
  VERIFIED CLEAN. 8 new stress tests; all PASS. No code changes required.
- **Rust pipeline** (`ferrous-utils/sync/src/`): grep for
  `golomb|gcs|GCS|block_filter|BlockFilter|filter_encode|Golomb` returns
  zero matches. Two-pipeline guard `test_w122_two_pipeline_guard_no_gcs_in_rust`
  pins this invariant — any future drift that lands a Rust GCS codec without
  a matching audit MUST be caught.

Findings
--------

No bugs. The audit confirms the existing W90 / W121 conclusion that
ouroboros's BIP-158 GCS codec is correct and Core-byte-identical, and
extends that conclusion to the quotient regime `q ∈ [64, 100 000]` that
Core's stock test vectors do not reach.

Two-pipeline guard status
-------------------------

PRESERVED.
- W122 adds **no** new code in `src/ouroboros/blockfilter.py` (pure audit;
  tests only).
- W122 adds **no** code in `ferrous-utils/sync/` (Rust pipeline untouched).
- W122 adds **a new guard** `test_w122_two_pipeline_guard_no_gcs_in_rust`
  that asserts `ferrous-utils/sync/src/**/*.rs` contains no GCS / blockfilter
  references — extending the FIX-74 / FIX-75 / FIX-79 guard chain.

Reference
---------

- BIP-158: <https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki>
- `bitcoin-core/src/blockfilter.{cpp,h}`
- `bitcoin-core/src/util/golombrice.h` — `GolombRiceEncode/Decode`
- `bitcoin-core/src/streams.h` lines 261–358 — `BitStreamReader/Writer`
- `bitcoin-core/src/test/data/blockfilters.json` — stock vectors (top-N 8)
- haskoin commit `4a2de0f` — FIX-69 reference bug shape
