#!/usr/bin/env python3
"""Download missing B3 fixture block bodies from blockstream.info.

Idempotent: skips fixtures whose `.bin` already exists and whose
header hash matches the sibling `.hash` file.  Safe to re-run.

Bitcoin block data is public, so fetching from a public explorer is
equivalent to fetching from your own node — pick whichever is easier.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

BS_BASE = "https://blockstream.info/api"
HERE = Path(__file__).parent


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def main() -> int:
    index = json.loads((HERE / "index.json").read_text())
    missing_or_bad: list[tuple[int, str]] = []

    for height_str, entry in index.items():
        height = int(height_str)
        block_hash = entry["hash"]
        bin_path = HERE / f"block_{height}.bin"
        if bin_path.exists():
            raw = bin_path.read_bytes()
            header_hash = dsha256(raw[:80])[::-1].hex()
            if header_hash == block_hash:
                print(f"height={height} OK (cached)")
                continue
            print(f"height={height} stale cache — refetching", file=sys.stderr)
        missing_or_bad.append((height, block_hash))

    if not missing_or_bad:
        print("all fixtures present")
        return 0

    for height, block_hash in missing_or_bad:
        url = f"{BS_BASE}/block/{block_hash}/raw"
        print(f"fetching height={height} from blockstream ...")
        with urllib.request.urlopen(url, timeout=30) as r:
            raw = r.read()
        header_hash = dsha256(raw[:80])[::-1].hex()
        if header_hash != block_hash:
            print(
                f"INTEGRITY FAIL @{height}: got {header_hash} "
                f"expected {block_hash}",
                file=sys.stderr,
            )
            return 2
        (HERE / f"block_{height}.bin").write_bytes(raw)
        print(f"height={height} {len(raw)} bytes written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
