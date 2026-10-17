#!/usr/bin/env python3
"""DISARMED. This tool used to seed HEADERS_CF for five corpus blocks from
Bitcoin Core's getblockheader RPC.

Besides the header it stored Core's ``nTx``, ``chainwork``, ``height``,
``mediantime`` and ``nextblockhash`` in the extended 156-byte record, and
getblockheader then served them as ouroboros's own answer. None of those is
proof-of-work self-verifying, so serving them fails R3 (answer only from own
state).

The store is now reconciled once at database open
(``BlockchainDB::reconcile_headers_ntx_provenance``, marker
``headers_ntx_reconciled_v1``): extended records are cut back to the
84-byte header+nTx form and nTx is kept only for blocks this node holds the
body or undo data for.

This script refuses to run and exits non-zero.
"""

import sys

REFUSAL = (
    "populate_corpus_headers.py is disarmed: it wrote Bitcoin Core's nTx, "
    "chainwork, height, mediantime and nextblockhash into ouroboros's "
    "HEADERS_CF, which is not this node's own data (R3)."
)


def main() -> int:
    print(f"REFUSED: {REFUSAL}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
