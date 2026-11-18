#!/usr/bin/env python3
"""Bench: online index header fill on N synthetic header-less entries.

Writes N rows the way the #52 backfill does (store_block_metadata_raw: no
header, no body; regtest-style headers chained by prev hash), then runs the
fill with a fake peer that answers each getheaders with up to 2000 headers.
Reports the worst wall time of one local step and of one attach (the time the
node holds the chain lock per tick) and the total.

Usage: PYTHONPATH=<src>:<sync site> python3 tools/index_header_fill/bench.py <empty datadir> <N>
"""
import hashlib
import struct
import sys
import time

import sync
from ouroboros import index_header_fill as ihf


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


path, n = sys.argv[1], int(sys.argv[2])
db = sync.PyBlockchainDB(path)
headers, hashes, prev = [], [], b"\0" * 32
t0 = time.time()
for h in range(n):
    hdr = (struct.pack("<i", 0x20000000) + prev + dsha(struct.pack("<I", h))
           + struct.pack("<III", 1296688602 + h * 600, 0x207FFFFF, h))
    bh = dsha(hdr)
    db.store_block_metadata_raw(h, bh, h, ((h + 1) * 2).to_bytes(32, "big"), 1296688602 + h * 600)
    headers.append(hdr)
    hashes.append(bh)
    prev = bh
db.update_best_block(hashes[-1], n - 1)
print(f"setup {n} header-less entries in {time.time() - t0:.1f}s; summary={db.block_index_summary()}")
idx = {k: i for i, k in enumerate(hashes)}
fill = ihf.IndexHeaderFill(db)
steps = accepts = 0
worst_step = worst_accept = 0.0
t0 = time.time()
while not fill.is_complete():
    s = time.perf_counter()
    fill.step()
    worst_step = max(worst_step, time.perf_counter() - s)
    steps += 1
    if fill.waiting_on_peer():
        loc = fill.locator()
        start = idx[loc[0]] + 1 if loc else 0
        s = time.perf_counter()
        fill.accept(headers[start:start + (2000 if loc else 1)])
        worst_accept = max(worst_accept, time.perf_counter() - s)
        accepts += 1
print(f"fill: steps={steps} accepts={accepts} worst_step_ms={worst_step * 1e3:.1f} "
      f"worst_accept_ms={worst_accept * 1e3:.1f} total_s={time.time() - t0:.1f} "
      f"attached={fill.counts['attached']}")
print(f"summary after={db.block_index_summary()}")
