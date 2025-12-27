"""Database layer using RocksDB."""

import asyncio
from pathlib import Path
from typing import Optional, Any, Union
import rocksdb
from concurrent.futures import ThreadPoolExecutor


class Database:
    """RocksDB database wrapper."""

    def __init__(self, db_path: Union[str, Path], max_open_files: int = 3000) -> None:
        """Initialize the database.
        
        Args:
            db_path: Path to the RocksDB database directory
            max_open_files: Maximum number of open files
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        opts = rocksdb.Options()
        opts.create_if_missing = True
        opts.max_open_files = max_open_files
        
        # Use thread pool executor for async operations
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.db: Optional[rocksdb.DB] = None

    async def open(self) -> None:
        """Open the database connection."""
        loop = asyncio.get_event_loop()
        self.db = await loop.run_in_executor(
            self.executor,
            rocksdb.DB,
            str(self.db_path),
            rocksdb.Options(create_if_missing=True, max_open_files=3000)
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
        try:
            return await loop.run_in_executor(self.executor, self.db.get, key)
        except rocksdb.errors.NotFoundError:
            return None

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
        
        batch = rocksdb.WriteBatch()
        for key, value in updates.items():
            if value is None:
                batch.delete(key)
            else:
                batch.put(key, value)
        
        self.db.write(batch)

