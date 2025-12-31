"""Bitcoin node main class."""

# Try to import Rust extension for fast syncing
try:
    from sync import SyncEngine

    _RUST_EXTENSION_AVAILABLE = True
except ImportError:
    _RUST_EXTENSION_AVAILABLE = False
    SyncEngine = None  # type: ignore


class BitcoinNode:
    """Main Bitcoin node implementation."""

    def __init__(self, config: dict | None = None):
        """Initialize the Bitcoin node.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}

        # Initialize Rust sync engine if available
        if _RUST_EXTENSION_AVAILABLE and SyncEngine is not None:
            self.sync_engine = SyncEngine()
            print("✓ Using Rust extension for fast blockchain synchronization")
        else:
            self.sync_engine = None
            print("⚠ Rust extension not available, using Python-only implementation")

    async def start(self) -> None:
        """Start the Bitcoin node."""
        # TODO: Implement node startup
        pass

    async def stop(self) -> None:
        """Stop the Bitcoin node."""
        # TODO: Implement node shutdown
        pass

    async def run(self) -> None:
        """Run the Bitcoin node (start and keep running)."""
        await self.start()
        # TODO: Implement main loop
        pass

    def sync_blocks_rust(self, blocks: list[bytes]) -> int:
        """Sync blocks using the Rust extension (if available).

        Args:
            blocks: List of block data as bytes

        Returns:
            Number of blocks synced

        Raises:
            RuntimeError: If Rust extension is not available
        """
        if self.sync_engine is None:
            raise RuntimeError("Rust extension not available")

        # Convert bytes to list of lists (Vec<Vec<u8>>)
        blocks_data = [list(block) for block in blocks]
        return self.sync_engine.sync_blocks(blocks_data)
