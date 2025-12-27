"""Database layer using LevelDB."""

import asyncio
from pathlib import Path
from typing import Optional, Any, Union
from concurrent.futures import ThreadPoolExecutor

try:
    import plyvel
    _LEVELDB_AVAILABLE = True
except ImportError:
    _LEVELDB_AVAILABLE = False
    plyvel = None  # type: ignore


class Database:
    """LevelDB database wrapper."""

    def __init__(self, db_path: Union[str, Path], create_if_missing: bool = True) -> None:
        """Initialize the database.
        
        Args:
            db_path: Path to the LevelDB database directory
            create_if_missing: Create database if it doesn't exist
            
        Raises:
            ImportError: If plyvel package is not available
        """
        if not _LEVELDB_AVAILABLE:
            raise ImportError(
                "plyvel package is not available. "
                "Please install it with: pip install plyvel"
            )
        
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        self.create_if_missing = create_if_missing
        
        # Use thread pool executor for async operations
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.db: Optional[Any] = None

    async def open(self) -> None:
        """Open the database connection."""
        loop = asyncio.get_event_loop()
        self.db = await loop.run_in_executor(
            self.executor,
            plyvel.DB,
            str(self.db_path),
            create_if_missing=self.create_if_missing
        )

    async def close(self) -> None:
        """Close the database connection."""
        if self.db:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, self._close_db)
            self.executor.shutdown(wait=True)

    def _close_db(self) -> None:
        """Close the database (called from executor)."""
        if self.db:
            self.db.close()
            self.db = None

    async def get(self, key: bytes) -> Optional[bytes]:
        """Get a value by key.
        
        Args:
            key: Database key
            
        Returns:
            Value if found, None otherwise
        """
        if not self.db:
            raise RuntimeError("Database not open")
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self.db.get, key)

    async def put(self, key: bytes, value: bytes) -> None:
        """Store a key-value pair.
        
        Args:
            key: Database key
            value: Value to store
        """
        if not self.db:
            raise RuntimeError("Database not open")
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self.db.put, key, value)

    async def delete(self, key: bytes) -> None:
        """Delete a key-value pair.
        
        Args:
            key: Database key
        """
        if not self.db:
            raise RuntimeError("Database not open")
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self.db.delete, key)

    async def write_batch(self, updates: dict[bytes, Optional[bytes]]) -> None:
        """Write multiple key-value pairs atomically.
        
        Args:
            updates: Dictionary mapping keys to values (None means delete)
        """
        if not self.db:
            raise RuntimeError("Database not open")
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.executor,
            self._write_batch_sync,
            updates
        )

    def _write_batch_sync(self, updates: dict[bytes, Optional[bytes]]) -> None:
        """Write batch synchronously (called from executor)."""
        if not self.db:
            return
        
        with self.db.write_batch() as batch:
            for key, value in updates.items():
                if value is None:
                    batch.delete(key)
                else:
                    batch.put(key, value)
