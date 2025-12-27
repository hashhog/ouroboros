"""Bitcoin node main class."""

from typing import Optional


class BitcoinNode:
    """Main Bitcoin node implementation."""

    def __init__(self, config: Optional[dict] = None):
        """Initialize the Bitcoin node."""
        self.config = config or {}
        # TODO: Initialize components

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

