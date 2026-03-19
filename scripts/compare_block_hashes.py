#!/usr/bin/env python3
"""
Compare block hashes between Ouroboros and Bitcoin Core (testnet4).
Usage:
  python scripts/compare_block_hashes.py --ouroboros-dir .ouroboros-testnet4-compare \
    --bitcoin-cli bitcoin/build/bin/bitcoin-cli --bitcoin-datadir bitcoin/testnet4_sync_data --testnet4

Run from project root. Bitcoin Core (bitcoind) must be running for bitcoin-cli to work.
"""
import argparse
import subprocess
import sys
from pathlib import Path

# Add project root so we can import ouroboros
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def bytes_to_display_hex(b: bytes) -> str:
    """Convert 32-byte internal hash to Bitcoin display hex (reversed byte order)."""
    if len(b) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(b)}")
    return b[::-1].hex()


def get_ouroboros_hash(data_dir: str, height: int) -> str | None:
    """Get block hash at height from Ouroboros DB. Returns display-format hex or None."""
    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase(data_dir)
    h = db.get_block_hash_by_height(height)
    if h is None:
        return None
    return bytes_to_display_hex(h)


def get_ouroboros_tip(data_dir: str) -> int | None:
    """Get best block height from Ouroboros."""
    from ouroboros.database import BlockchainDatabase

    db = BlockchainDatabase(data_dir)
    try:
        _, height = db.get_best_block()
        return height
    except Exception:
        return None


def get_bitcoin_hash(bitcoin_cli: str, datadir: str, testnet4: bool, height: int) -> str | None:
    """Get block hash at height from Bitcoin Core via RPC. Returns display-format hex or None."""
    cmd = [bitcoin_cli, "-datadir=" + datadir]
    if testnet4:
        cmd.insert(1, "-testnet4")
    cmd.extend(["getblockhash", str(height)])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return out.stdout.strip() if out.stdout else None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_bitcoin_tip(bitcoin_cli: str, datadir: str, testnet4: bool) -> int | None:
    """Get best block height from Bitcoin Core."""
    cmd = [bitcoin_cli, "-datadir=" + datadir]
    if testnet4:
        cmd.insert(1, "-testnet4")
    cmd.append("getblockcount")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return int(out.stdout.strip()) if out.stdout.strip().isdigit() else None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, FileNotFoundError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare block hashes between Ouroboros and Bitcoin Core")
    ap.add_argument("--ouroboros-dir", required=True, help="Ouroboros data directory")
    ap.add_argument("--bitcoin-cli", required=True, help="Path to bitcoin-cli")
    ap.add_argument("--bitcoin-datadir", required=True, help="Bitcoin Core data directory")
    ap.add_argument("--testnet4", action="store_true", help="Use testnet4 for Bitcoin Core")
    ap.add_argument("--heights", default="0,1000,10000,50000,100000,tip",
                    help="Comma-separated heights to check (default: 0,1000,10000,50000,100000,tip)")
    args = ap.parse_args()

    # Resolve paths relative to project root
    ouroboros_dir = (PROJECT_ROOT / args.ouroboros_dir).resolve()
    bitcoin_cli = Path(args.bitcoin_cli)
    if not bitcoin_cli.is_absolute():
        bitcoin_cli = (PROJECT_ROOT / args.bitcoin_cli).resolve()
    bitcoin_datadir = (PROJECT_ROOT / args.bitcoin_datadir).resolve()

    if not ouroboros_dir.exists():
        print(f"Error: Ouroboros data dir does not exist: {ouroboros_dir}", file=sys.stderr)
        return 1
    if not bitcoin_cli.exists():
        print(f"Error: bitcoin-cli not found: {bitcoin_cli}", file=sys.stderr)
        return 1
    if not bitcoin_datadir.exists():
        print(f"Error: Bitcoin data dir does not exist: {bitcoin_datadir}", file=sys.stderr)
        return 1

    # Resolve tip heights
    ouroboros_tip = get_ouroboros_tip(str(ouroboros_dir))
    bitcoin_tip = get_bitcoin_tip(str(bitcoin_cli), str(bitcoin_datadir), args.testnet4)

    if ouroboros_tip is None:
        print("Error: Could not get Ouroboros best block (sync may not be complete)", file=sys.stderr)
        return 1
    if bitcoin_tip is None:
        print("Error: Could not get Bitcoin best block (is bitcoind running?)", file=sys.stderr)
        return 1

    print(f"Ouroboros tip: {ouroboros_tip}  |  Bitcoin tip: {bitcoin_tip}")
    if ouroboros_tip < bitcoin_tip:
        print(f"Warning: Ouroboros behind Bitcoin by {bitcoin_tip - ouroboros_tip} blocks", file=sys.stderr)

    # Parse heights
    heights_raw = [h.strip() for h in args.heights.split(",")]
    heights: list[int] = []
    for h in heights_raw:
        if h.lower() == "tip":
            heights.append(min(ouroboros_tip, bitcoin_tip))
        else:
            try:
                heights.append(int(h))
            except ValueError:
                print(f"Invalid height: {h}", file=sys.stderr)
                return 1

    errors = 0
    for height in heights:
        oh = get_ouroboros_hash(str(ouroboros_dir), height)
        bh = get_bitcoin_hash(str(bitcoin_cli), str(bitcoin_datadir), args.testnet4, height)

        if oh is None:
            print(f"height {height}: Ouroboros=MISSING  Bitcoin={bh or 'N/A'}  [MISMATCH]")
            errors += 1
        elif bh is None:
            print(f"height {height}: Ouroboros={oh}  Bitcoin=MISSING  [MISMATCH]")
            errors += 1
        elif oh.lower() == bh.lower():
            print(f"height {height}: Ouroboros={oh}  Bitcoin={bh}  [MATCH]")
        else:
            print(f"height {height}: Ouroboros={oh}  Bitcoin={bh}  [MISMATCH]")
            errors += 1

    if errors:
        print(f"\n{errors} mismatch(es). Exit 1.", file=sys.stderr)
        return 1
    print("\nAll hashes match. Exit 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
