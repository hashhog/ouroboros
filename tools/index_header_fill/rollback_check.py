#!/usr/bin/env python3
"""Steps of rollback_check.sh; each runs under ONE build (its PYTHONPATH).

  dump  <db>              every active entry's (hash, height, chainwork, time,
                          status, height-row chainwork) + the index summary, JSON
  make  <db> <fixture>    the #52 shape: header_backfill.backfill_metadata rows
                          for the Core fixture chain (no header, no body)
  fill  <db> <fixture>    run the online index header fill, headers served
                          from the fixture the way a peer serves them
  write <db> <h>          rewrite the row at height h with the #52 writer
                          (store_block_metadata_raw, timestamp + 1)
"""
import json
import sys

import sync

step, path = sys.argv[1], sys.argv[2]


def chain(fixture):
    c = json.load(open(fixture))["chain"]
    return [bytes.fromhex(x["header_hex"]) for x in c], [bytes.fromhex(x["hash"])[::-1] for x in c]


if step == "make":
    from ouroboros.database import BlockchainDatabase
    from ouroboros.header_backfill import backfill_metadata

    H, K = chain(sys.argv[3])
    b = BlockchainDatabase(path)
    backfill_metadata(b, H, start_height=0, anchor_hash=K[-1], network="regtest")
    b._db.update_best_block(K[-1], len(K) - 1)
    print("old build wrote #52 rows:", b._db.block_index_summary())
    sys.exit(0)

db = sync.PyBlockchainDB(path)
if step == "dump":
    tip = db.get_best_block()[1]
    out = {}
    for h in range(tip + 1):
        bh = bytes(db.get_block_hash_by_height(h))
        e = db.get_block_index_entry(bh)
        out[h] = [bh.hex(), e[0], bytes(e[1]).hex(), e[2], e[3], str(db.get_chainwork_by_height(h))]
    print(json.dumps({"tip": tip, "entries": out, "summary": db.block_index_summary()}))
elif step == "fill":
    from ouroboros import index_header_fill as ihf

    H, K = chain(sys.argv[3])
    f = ihf.IndexHeaderFill(db)
    while not f.is_complete():
        f.step()
        if f.waiting_on_peer():
            loc = f.locator()
            s = K.index(loc[0]) + 1 if loc else 0
            f.accept(H[s:s + (2000 if loc else 1)])
    print("new build filled", f.counts["attached"], db.block_index_summary())
elif step == "write":
    h = int(sys.argv[3])
    bh = bytes(db.get_block_hash_by_height(h))
    e = db.get_block_index_entry(bh)
    db.store_block_metadata_raw(h, bh, h, bytes(e[1]), e[2] + 1)
    e2 = db.get_block_index_entry(bh)
    kept = e[4] is not None and e2[4] is not None and bytes(e2[4]) == bytes(e[4])
    print(f"old build rewrote h{h}: " + (f"header kept={kept}" if e[4] is not None else "(legacy entry)"))
