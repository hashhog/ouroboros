#!/usr/bin/env python3
"""Read-only dry run of the block index v2 migration on an existing datadir.

The first open of a build that carries block index v2 (ouroboros#146) rewrites
every BLOCK_INDEX_BY_HASH_CF entry it can find a header for, and logs

    block index v2 migration: scanned=.. already_v2=.. from_headers=..
    from_body=.. no_header=N hash_mismatch=.. malformed=..

This tool prints those same counts for a datadir WITHOUT changing it, so an
operator can know them before the deploy.  It opens the RocksDB as a
*secondary* instance (``PyBlockchainDB.open_secondary``): no lock is taken on
the datadir, nothing is written to it, and RocksDB refuses any write through
the handle.  The secondary keeps its own small state (an info log, a few KB)
in ``--secondary-dir``, which must be outside the datadir.  It is safe whether
or not the node is running; with the node running, the counts are as of the
moment the tool opened the datadir.

The scan is the migration's own (``BlockchainDB::scan_block_index_v2``), with
the writes replaced by counting, so the counts are the ones the migration would
log on a datadir in this state.

Usage:
    python3 tools/block_index_v2_dryrun.py --datadir DIR --secondary-dir SCRATCH [--json]

Exit status: 0 on a completed scan, 2 on a refused argument, 1 on an error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time


def _inside(child: str, parent: str) -> bool:
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    return child == parent or child.startswith(parent + os.sep)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--datadir", required=True,
                    help="the RocksDB directory the node opens (its --data-dir; holds CURRENT)")
    ap.add_argument("--secondary-dir", required=True,
                    help="scratch directory for the secondary instance, outside the datadir")
    ap.add_argument("--json", action="store_true", help="print one JSON object")
    args = ap.parse_args(argv)

    if not os.path.isfile(os.path.join(args.datadir, "CURRENT")):
        print(f"REFUSED: {args.datadir} has no CURRENT file; not a RocksDB directory",
              file=sys.stderr)
        return 2
    if _inside(args.secondary_dir, args.datadir):
        print("REFUSED: --secondary-dir must be outside the datadir", file=sys.stderr)
        return 2

    try:
        import sync  # the compiled ferrous-utils extension
    except ImportError as e:
        print(f"ERROR: the compiled sync extension is not importable: {e}", file=sys.stderr)
        return 1
    if not hasattr(sync.PyBlockchainDB, "open_secondary"):
        print("ERROR: this sync build has no PyBlockchainDB.open_secondary", file=sys.stderr)
        return 1

    t0 = time.monotonic()
    try:
        db = sync.PyBlockchainDB.open_secondary(args.datadir, args.secondary_dir)
        t_open = time.monotonic() - t0
        r = dict(db.dry_run_block_index_v2())
    except Exception as e:  # noqa: BLE001 - report and exit non-zero
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    t_scan = time.monotonic() - t0 - t_open
    del db

    r["open_seconds"] = round(t_open, 3)
    r["scan_seconds"] = round(t_scan, 3)
    if args.json:
        print(json.dumps(r, sort_keys=True))
        return 0
    upgraded = r["from_headers"] + r["from_body"]
    print("block index v2 dry run (nothing written)")
    print(f"  datadir             {args.datadir}")
    print(f"  marker present      {'yes (a v2 open would not scan)' if r['migrated'] else 'no'}")
    print(f"  nTx reconciled      {'yes' if r['ntx_reconciled'] else 'no (the open runs it first)'}")
    print(f"  scanned             {r['scanned']}")
    print(f"  already_v2          {r['already_v2']}")
    print(f"  would upgrade       {upgraded} (from_headers={r['from_headers']} from_body={r['from_body']})")
    print(f"  no_header           {r['no_header']} (stay legacy, 44 bytes)")
    print(f"  hash_mismatch       {r['hash_mismatch']}")
    print(f"  malformed           {r['malformed']}")
    print(f"  extra_bytes         {r['extra_bytes']} (uncompressed)")
    print(f"  open / scan seconds {r['open_seconds']} / {r['scan_seconds']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
