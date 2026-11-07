"""On-disk mirror of the submitblock / fork side-branch buffer.

Bitcoin Core stores every block it accepts, side branches included:
``ChainstateManager::AcceptBlock`` (validation.cpp) writes the block with
``WriteBlock`` and keeps its ``CBlockIndex`` with ``BLOCK_HAVE_DATA``, and
``LoadBlockIndex`` reloads every entry at startup.  After a restart Core
therefore still lists such a block in getchaintips and can still reorg onto
it when a child makes its branch the most-work chain.

ouroboros's block store is height-keyed, so a block off the active chain lives
in ``RPCServer._side_branch_blocks`` (hash -> ``(prev, height, raw)``), which
was memory only: a restart dropped every side-branch block.
``SideBranchBuffer`` is that same dict, with each insertion written to
``<dir>/<hash hex>.blk`` and each removal unlinking the file; the files are
read back when the buffer is opened.

What is reloaded is only what the buffer held before the restart, and
nothing more is trusted: an entry is reloaded only if its file parses, the
whole block's sha256 matches the one recorded when it was written (so a
truncated or bit-flipped body is never mistaken for the block), the header
hashes to the file's key, and the header's prev field matches the recorded
parent; anything else is skipped with a warning.  A skipped entry is simply
absent, as before this store existed: a child of it is an orphan, never a
failure verdict.  A reloaded block reaches the active chain only through the
reorg path, which runs the full ConnectBlock on it.

Each insert writes (and fsyncs) the block synchronously; side-branch blocks
are rare and bounded by the buffer's cap, so this is a small cost next to
the validation that precedes every insert.

Disk errors never change the in-memory behaviour: a failed write or unlink
is logged and the dict operation still happens.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from typing import Any, Iterable

logger = logging.getLogger(__name__)

_MAGIC = b"OBSB1\x00"
_HEADER = struct.Struct("<6s32sI32s")  # magic, parent hash, height, sha256(raw)
_SUFFIX = ".blk"


def _block_hash(raw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()


class SideBranchBuffer(dict):
    """``dict[bytes, tuple[bytes, int, bytes]]`` mirrored to ``directory``.

    Insertion order (the FIFO the eviction cap relies on) is restored from
    the files' modification times.
    """

    def __init__(self, directory: str) -> None:
        super().__init__()
        self._dir = directory
        os.makedirs(directory, exist_ok=True)
        self._load()

    @property
    def directory(self) -> str:
        return self._dir

    # -- persistence -----------------------------------------------------

    def _path(self, key: bytes) -> str:
        return os.path.join(self._dir, bytes(key).hex() + _SUFFIX)

    def _write(self, key: Any, value: Any) -> None:
        try:
            prev, height, raw = value
            raw = bytes(raw)
            payload = _HEADER.pack(
                _MAGIC, bytes(prev), int(height), hashlib.sha256(raw).digest()
            ) + raw
            path = self._path(key)
            tmp = path + ".tmp"
            try:
                # Overwriting a key keeps its dict position; keep the file's
                # mtime too, so the reload order (the eviction FIFO) matches.
                old_times = os.stat(path)
            except FileNotFoundError:
                old_times = None
            with open(tmp, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            if old_times is not None:
                os.utime(tmp, ns=(old_times.st_atime_ns, old_times.st_mtime_ns))
            os.replace(tmp, path)
        except Exception as e:  # never break the in-memory buffer
            logger.warning("side-branch store: could not persist %s: %s",
                           bytes(key).hex()[:16] if isinstance(key, (bytes, bytearray)) else key, e)

    def _unlink(self, key: Any) -> None:
        try:
            os.unlink(self._path(key))
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("side-branch store: could not remove %s: %s",
                           bytes(key).hex()[:16] if isinstance(key, (bytes, bytearray)) else key, e)

    def _load(self) -> None:
        try:
            names = os.listdir(self._dir)
        except OSError as e:
            logger.warning("side-branch store: cannot list %s: %s", self._dir, e)
            return
        found: list[tuple[int, str]] = []
        for name in names:
            path = os.path.join(self._dir, name)
            if name.endswith(_SUFFIX + ".tmp"):
                # A write interrupted before its rename: never a complete entry.
                try:
                    os.unlink(path)
                except OSError:
                    pass
                continue
            if not name.endswith(_SUFFIX):
                continue
            try:
                found.append((os.stat(path).st_mtime_ns, name))
            except OSError:
                continue
        skipped = 0
        for _mtime, name in sorted(found):
            entry = self._read(name)
            if entry is None:
                skipped += 1
                continue
            key, value = entry
            dict.__setitem__(self, key, value)
        if found:
            logger.info("side-branch store: reloaded %d block(s) from %s (%d skipped)",
                        len(self), self._dir, skipped)

    def _read(self, name: str) -> tuple[bytes, tuple[bytes, int, bytes]] | None:
        try:
            key = bytes.fromhex(name[: -len(_SUFFIX)])
        except ValueError:
            return None
        if len(key) != 32:
            return None
        try:
            with open(os.path.join(self._dir, name), "rb") as f:
                data = f.read()
        except OSError:
            return None
        if len(data) < _HEADER.size + 80:
            return None
        magic, prev, height, digest = _HEADER.unpack_from(data)
        raw = data[_HEADER.size:]
        if (magic != _MAGIC or hashlib.sha256(raw).digest() != digest
                or raw[4:36] != prev or _block_hash(raw) != key):
            logger.warning("side-branch store: ignoring %s (does not match its key)", name)
            return None
        return key, (prev, int(height), raw)

    # -- dict mutators ---------------------------------------------------

    def __setitem__(self, key: bytes, value: tuple[bytes, int, bytes]) -> None:
        dict.__setitem__(self, key, value)
        self._write(key, value)

    def __delitem__(self, key: bytes) -> None:
        dict.__delitem__(self, key)
        self._unlink(key)

    _MISSING = object()

    def pop(self, key: Any, default: Any = _MISSING) -> Any:
        if key in self:
            value = dict.pop(self, key)
            self._unlink(key)
            return value
        if default is SideBranchBuffer._MISSING:
            raise KeyError(key)
        return default

    def popitem(self) -> tuple[Any, Any]:
        key, value = dict.popitem(self)
        self._unlink(key)
        return key, value

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self:
            self[key] = default
        return dict.__getitem__(self, key)

    def update(self, other: Any = (), **kwargs: Any) -> None:
        items: Iterable = other.items() if hasattr(other, "items") else other
        for key, value in items:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    def clear(self) -> None:
        for key in list(self.keys()):
            self._unlink(key)
        dict.clear(self)
