#!/usr/bin/env python3
"""Read-only dry run of the online index header fill on an existing datadir.

A build with ``ouroboros.index_header_fill`` fills the 80-byte header into
every BLOCK_INDEX_BY_HASH_CF entry that lacks one (the assumeUTXO header
backfill's rows below the snapshot base), from a verified local store or from
peers.  This tool counts what that fill would do WITHOUT changing the datadir:

    fillable_local   entries a local store (HEADERS_CF, or a body that parses
                     and matches its merkle root) would fill
    need_peer        active-chain entries whose header must come from a peer
    no_source        off-chain entries nothing can fill (stay legacy)
    hash_mismatch / corrupt_body / unlinked / malformed
                     entries the fill would refuse and leave unchanged

It opens the RocksDB as a *secondary* instance (``PyBlockchainDB.open_secondary``,
as ``tools/block_index_v2_dryrun.py`` does): no lock on the datadir, nothing
written to it, RocksDB refuses any write through the handle.  The secondary's
own few-KB state goes to ``--secondary-dir``, which must be outside the
datadir.  Safe with the node running or stopped.

The counts come from the fill's own steps (``fill_index_headers_by_height`` /
``fill_index_headers_by_hash``) run with ``write=False``.

Usage:
    python3 tools/index_header_fill_dryrun.py --datadir DIR --secondary-dir SCRATCH [--json]

Exit status: 0 on a completed scan, 2 on a refused argument, 1 on an error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

# This checkout's ouroboros package, ahead of any installed one (the venv's
# may be the deployed tree, which has no index_header_fill).
_SRC = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
if os.path.isdir(_SRC):
    sys.path.insert(0, _SRC)


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
    if not hasattr(sync.PyBlockchainDB, "open_secondary") or not hasattr(
            sync.PyBlockchainDB, "fill_index_headers_by_height"):
        print("ERROR: this sync build has no index header fill API "
              "(PyBlockchainDB.fill_index_headers_by_height)", file=sys.stderr)
        return 1
    from ouroboros.index_header_fill import dry_run

    t0 = time.monotonic()
    try:
        db = sync.PyBlockchainDB.open_secondary(args.datadir, args.secondary_dir)
        t_open = time.monotonic() - t0
        tip = db.get_best_block()[1]
        r = dry_run(db)
    except Exception as e:  # noqa: BLE001 - report and exit non-zero
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    del db

    r["tip_height"] = int(tip)
    r["sync_module"] = getattr(sync, "__file__", "?")
    r["open_seconds"] = round(t_open, 3)
    if args.json:
        print(json.dumps(r, sort_keys=True))
        return 0
    print("index header fill dry run (nothing written)")
    print(f"  datadir             {args.datadir}")
    print(f"  sync build          {r['sync_module']}")
    print(f"  tip height          {r['tip_height']}")
    print(f"  index entries       {r['index_entries']} ({r['index_legacy']} without a header)")
    print(f"  active heights      {r['active_scanned']} ({r['active_already_v2']} with a header)")
    print(f"  fillable_local      {r['fillable_local']}")
    print(f"  need_peer           {r['need_peer']}")
    print(f"  no_source           {r['no_source']} (off-chain, stay legacy)")
    print(f"  hash_mismatch       {r['hash_mismatch']}")
    print(f"  corrupt_body        {r['corrupt_body']}")
    print(f"  unlinked            {r['unlinked']}")
    print(f"  malformed           {r['malformed']}")
    print(f"  no_entry            {r['no_entry']} (heights without an index row)")
    print(f"  open / scan seconds {r['open_seconds']} / {r['seconds']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
