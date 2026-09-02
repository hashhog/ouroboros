# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-beta1`:

- 8743575 fix: honour -assumevalid=0 on the submitblock path, not only the P2P drain
- a044971 test: follow deliberate ouroboros design changes the tests predated
- e770882 test: assert Core's reject tokens / response shapes instead of pre-parity wording
- ea389cd test: bring stub/mock fixtures up to the production interfaces they stand in for
- c759449 fix(mempool): WITNESS_UNKNOWN input gate was dead code — spends of v2+ witness programs passed ValidateInputsStandardness
- f8aad1d docs: LICENSE, SECURITY.md, toolchain versions (release hygiene)
- b715fa7 fix(rpc): validate argument COUNT centrally, as Core does (#103)
- 5ffa5ac fix(banman): a failed unban must report failure — the RPC's -30 was dead code
- 5ef55fa fix(rpc): the integer conversion runs before the lookup, and setban matches Core
- 83726ef fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 76293db feat(rpc): implement createrawtransaction's `version` argument
- a69ecde fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- b84c33a fix(rpc): createrawtransaction honours Core's replaceable/sequence contradiction check
- fe6a1d1 fix(rpc): createrawtransaction argument domains match Core; no Python exception text on the wire
- 05de3fa fix(block_sync): the tip-stall watchdog now ACTS, not only warns (#77A)
- 973c9f8 fix(banman): every ban must log WHY (#77B)
- bbee224 fix(validation): refuse coinbase spends with unknown coin height (audit coin-height-0 row)
- 83bbd5b fix(consensus): refuse metadata-less coins instead of fabricating is_coinbase=False (#53f)
- 0bff1ed fix(consensus): submitblock side-branch and bridge re-check select on WORK only (#49)
- 7378138 fix(consensus): refuse height-based reorg when the chainwork basis is unavailable (#49)
- ba43197 fix(p2p): inv-triggered getdata reverts requested_blocks on send failure (#74)
- 269edd4 fix(consensus): seed backfill chainwork from the anchor row, never from zero
- 50c3b47 fix(rpc): get_median_time must not answer a named height with the wall clock
- 8bba046 fix(consensus): walk THROUGH the anchor height — off-by-one refused the commit (#52)
- 3cc53ce fix(consensus): find the index GAP, not a floor — the backfill shipped inert (#52)
- bd6431e feat(consensus): wire the pre-snapshot header backfill into block_sync (#52)
- aaaad6b feat(consensus): HeaderBackfill driver — genesis-to-floor walk, all-or-nothing (#52)
- a79b378 fix(sync): block locator walked the whole chain when the index is sparse
- 12ec7f1 feat(consensus): header-metadata backfill core for pre-snapshot heights (#52)
- 096d63c test: fix the BIP-30 byte-order assertion and a false coverage claim
- 78fc20f fix(sync): interleave spends and outputs per tx in connect_blocks_atomic
- fbd9209 fix(p2p): #24 — remove fossil TimeoutError-continue arm in Peer.listen (OOM engine)
- 80b4f13 diag(node): capture running loop so the off-thread task census can target it
- 7c2d6ff diag(node): asyncio task census in the leak emitter — name the #24 retainer

