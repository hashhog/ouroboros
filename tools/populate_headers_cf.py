#!/usr/bin/env python3
"""DISARMED. This tool used to fill HEADERS_CF from Bitcoin Core's RPC.

It walked Core's getblockhash + getblockheader and wrote the 80-byte header
together with Core's ``nTx`` into ouroboros's header store. The header is
proof-of-work self-verifying; ``nTx`` is not. A node that serves another
node's transaction counts as its own fails R3 (answer only from own state),
and nothing in the datadir records which entries came from where.

The store is now reconciled once at database open
(``BlockchainDB::reconcile_headers_ntx_provenance``, marker
``headers_ntx_reconciled_v1``): nTx is kept only for blocks this node holds
the body or undo data for, and reset to 0 (Core's "transactions never
received") otherwise. Headers for pre-snapshot heights come from P2P via
``header_backfill.py``, which verifies them.

This script refuses to run and exits non-zero.
"""

import sys

REFUSAL = (
    "populate_headers_cf.py is disarmed: it wrote Bitcoin Core's nTx into "
    "ouroboros's HEADERS_CF, which is not this node's own data (R3). "
    "Pre-snapshot headers come from P2P via header_backfill.py."
)


def main() -> int:
    print(f"REFUSED: {REFUSAL}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
