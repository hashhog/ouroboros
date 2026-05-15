# PSBT v2 (BIP-370) status in ouroboros

**Status:** PRESENT (ouroboros is ahead of Bitcoin Core on PSBT v2 support).

**Reference module:** `src/ouroboros/psbt.py` (2896 LOC, `wc -l`).

**Verified:** 2026-05-15, FIX-63.

## Background

The W119 PayJoin audit (commit `bcc619f`) flagged ouroboros as having
`PSBT v0+v2 (~2896 LOC)`. The W118 wallet audit (commit `553d701`)
listed ouroboros under "PSBT v2 (BIP-370) MISSING ENTIRELY -- 8+/10"
but qualified the entry as *"(not flagged but likely missing)"* --
i.e. the W118 agent did not actually look at ouroboros's PSBT
module. FIX-63 resolves the contradiction by inspecting the source.

## Ground-truth grep evidence

| Constant / type / function | Location | Spec |
|---|---|---|
| `PSBT_HIGHEST_VERSION = 2` | `psbt.py:502` | BIP-370 |
| `PSBT_VERSION_2 = 2` | `psbt.py:501` | BIP-370 |
| `PSBT_VERSION_0 = 0` | `psbt.py:500` | BIP-174 |
| `PSBTGlobalType.TX_VERSION = 0x02` | `psbt.py:434` | BIP-370 §3 |
| `PSBTGlobalType.FALLBACK_LOCKTIME = 0x03` | `psbt.py:435` | BIP-370 §3 |
| `PSBTGlobalType.INPUT_COUNT = 0x04` | `psbt.py:436` | BIP-370 §3 |
| `PSBTGlobalType.OUTPUT_COUNT = 0x05` | `psbt.py:437` | BIP-370 §3 |
| `PSBTGlobalType.TX_MODIFIABLE = 0x06` | `psbt.py:438` | BIP-370 §3 |
| `PSBTInputType.PREVIOUS_TXID = 0x0E` | `psbt.py:462` | BIP-370 §4 |
| `PSBTInputType.OUTPUT_INDEX = 0x0F` | `psbt.py:463` | BIP-370 §4 |
| `PSBTInputType.SEQUENCE = 0x10` | `psbt.py:464` | BIP-370 §4 |
| `PSBTInputType.REQUIRED_TIME_LOCKTIME = 0x11` | `psbt.py:465` | BIP-370 §4 |
| `PSBTInputType.REQUIRED_HEIGHT_LOCKTIME = 0x12` | `psbt.py:466` | BIP-370 §4 |
| `PSBTOutputType.AMOUNT = 0x03` | `psbt.py:487` | BIP-370 §5 |
| `PSBTOutputType.SCRIPT = 0x04` | `psbt.py:488` | BIP-370 §5 |
| `PSBTInput.previous_txid / output_index / sequence / required_time_locktime / required_height_locktime` | `psbt.py:983-987` | BIP-370 |
| `PSBTOutput.amount / script` | `psbt.py:1227-1228` | BIP-370 |
| `PSBT.tx_version / fallback_locktime / input_count / output_count / tx_modifiable` | `psbt.py:1369-1373` | BIP-370 |
| `PSBT.from_transaction(tx, version=PSBT_VERSION_2)` | `psbt.py:1380-1411` | constructor |
| `PSBT.serialize()` branches on `self.version == PSBT_VERSION_0` else writes v2 globals | `psbt.py:1487-1503` | round-trip |
| `PSBT.deserialize()` reads `PSBTGlobalType.VERSION`, accepts up to `PSBT_HIGHEST_VERSION` | `psbt.py:1543-1548` | round-trip |
| `PSBT._reconstruct_tx_from_v2()` rebuilds `Transaction` from per-i/o v2 fields | `psbt.py:1615-1643` | constructor |

## Reference position

Bitcoin Core's own `psbt.h` line 80 has:

```cpp
static constexpr uint32_t PSBT_HIGHEST_VERSION = 0;
```

Core has not shipped PSBT v2 wallet support yet. ouroboros's
`PSBT_HIGHEST_VERSION = 2` therefore makes ouroboros **ahead of Core**
on this particular feature.

## Test coverage

Existing v2 tests (all PASS, 2026-05-15):

- `tests/test_psbt.py::TestPSBTOutput::test_psbt_v2_fields`
- `tests/test_psbt.py::TestPSBTSerialization::test_round_trip_v2`
- `tests/test_psbt.py::TestPSBTV2::test_v2_global_fields`
- `tests/test_psbt.py::TestPSBTV2::test_v2_per_input_fields`
- `tests/test_psbt.py::TestPSBTV2::test_v2_per_output_fields`
- `tests/test_psbt.py::TestPSBTV2::test_v2_reconstruct_tx`

FIX-63 adds `tests/test_fix63_psbt_v2_status.py` -- mechanical
source-grep regression guards + reinforced round-trip + cross-version
isolation tests, so that any future regression of `PSBT_HIGHEST_VERSION`
or removal of v2 field types or v2 reconstructor surfaces immediately
in CI.

## What's NOT here

PSBT v2 *protocol* support is present. Wallet workflow integration
(``createpsbt`` RPC accepting v=2, ``walletprocesspsbt`` writing v2,
``utxoupdatepsbt`` preserving v2 fields, fee-bumping flows producing
v2 output) is out of scope for FIX-63 and remains a future wave item
if/when downstream consumers request it.

## Cross-reference

- W118 audit: `project_w118_wallet.md` -- BUG-3 "PSBT v2 MISSING 8+/10".
  After FIX-63 the count drops by 1 (ouroboros recategorized to PRESENT).
- W119 audit: `project_w119_payjoin.md` -- "ouroboros PSBT v2
  candidate-contradiction" subsection. FIX-63 closes that
  candidate-contradiction with Outcome A: ouroboros has v2; W118 was
  wrong about ouroboros specifically.
- BIP-370: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
- Bitcoin Core reference: `bitcoin-core/src/psbt.h:80`
  (`PSBT_HIGHEST_VERSION = 0`).
