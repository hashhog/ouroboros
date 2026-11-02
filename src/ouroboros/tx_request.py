"""Per-peer transaction-announcement tracking (Core TxRequestTracker subset).

Before this module ``BlockSync.handle_inv`` put every unknown txid from any
peer into one global ``dict[hash, request_time]`` with a 60 s TTL, sent a
getdata for every one of them at once, and rebuilt the whole dict on every
inv to expire old entries.  One peer sending 50,000-hash invs grew that dict
to millions of entries, and each later inv paid a full scan of it on the
event loop (security audit 2026-10-30, H3).

This tracker keeps Core's per-peer accounting from txdownloadman.h:

* ``MAX_PEER_TX_ANNOUNCEMENTS`` (5000): announcements tracked per peer.
  Past that, further announcements from the peer are ignored, as Core's
  ``TxDownloadManagerImpl::AddTxAnnouncement`` does.
* ``MAX_PEER_TX_REQUEST_IN_FLIGHT`` (100): getdata requests outstanding per
  peer.  Core delays a request to an overloaded peer; here the rest of the
  peer's announcements wait in its queue and are requested as answers
  (tx / notfound) or expiry free slots.
* ``GETDATA_TX_INTERVAL`` (60 s): a request or queued announcement older
  than this is dropped.

Entries live in one ``OrderedDict`` kept in time order (an entry moves to
the end when it is requested), so expiry pops from the front and costs
O(expired), not O(tracked).  Callers must pass a non-decreasing clock
(``time.monotonic()``).
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Hashable

MAX_PEER_TX_ANNOUNCEMENTS = 5000
MAX_PEER_TX_REQUEST_IN_FLIGHT = 100
GETDATA_TX_INTERVAL = 60.0


class _Entry:
    __slots__ = ("peer", "t", "item", "in_flight")

    def __init__(self, peer: Hashable, t: float, item: Any) -> None:
        self.peer = peer
        self.t = t
        self.item = item
        self.in_flight = False


class _PeerState:
    __slots__ = ("queued", "in_flight")

    def __init__(self) -> None:
        # hash -> getdata item, in announcement order.
        self.queued: OrderedDict[bytes, Any] = OrderedDict()
        self.in_flight: set[bytes] = set()

    def count(self) -> int:
        return len(self.queued) + len(self.in_flight)


class TxRequestTracker:
    def __init__(
        self,
        max_announcements: int = MAX_PEER_TX_ANNOUNCEMENTS,
        max_in_flight: int = MAX_PEER_TX_REQUEST_IN_FLIGHT,
        interval: float = GETDATA_TX_INTERVAL,
    ) -> None:
        self.max_announcements = max_announcements
        self.max_in_flight = max_in_flight
        self.interval = interval
        self._entries: OrderedDict[bytes, _Entry] = OrderedDict()
        self._peers: dict[Hashable, _PeerState] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, h: object) -> bool:
        return h in self._entries

    def peer_count(self, peer: Hashable) -> int:
        """Announcements tracked for *peer* (queued + in flight)."""
        st = self._peers.get(peer)
        return st.count() if st is not None else 0

    def in_flight_count(self, peer: Hashable) -> int:
        st = self._peers.get(peer)
        return len(st.in_flight) if st is not None else 0

    def _detach(self, h: bytes, entry: _Entry) -> None:
        st = self._peers.get(entry.peer)
        if st is None:
            return
        if entry.in_flight:
            st.in_flight.discard(h)
        else:
            st.queued.pop(h, None)
        if not st.queued and not st.in_flight:
            del self._peers[entry.peer]

    def expire(self, now: float) -> int:
        """Drop entries older than ``interval``.  Returns how many."""
        n = 0
        entries = self._entries
        while entries:
            h, entry = next(iter(entries.items()))
            if now - entry.t <= self.interval:
                break
            entries.popitem(last=False)
            self._detach(h, entry)
            n += 1
        return n

    def announce(self, peer: Hashable, h: bytes, item: Any, now: float) -> bool:
        """Record that *peer* announced *h*.  False if already tracked
        (from any peer) or the peer is at its announcement cap."""
        if h in self._entries:
            return False
        st = self._peers.get(peer)
        if st is None:
            st = self._peers[peer] = _PeerState()
        elif st.count() >= self.max_announcements:
            return False
        self._entries[h] = _Entry(peer, now, item)
        st.queued[h] = item
        return True

    def pop_requests(self, peer: Hashable, now: float) -> list[Any]:
        """Move queued announcements of *peer* to in flight, up to the
        in-flight cap, and return their getdata items."""
        st = self._peers.get(peer)
        if st is None:
            return []
        out = []
        while st.queued and len(st.in_flight) < self.max_in_flight:
            h, item = st.queued.popitem(last=False)
            entry = self._entries[h]
            entry.in_flight = True
            entry.t = now
            self._entries.move_to_end(h)
            st.in_flight.add(h)
            out.append(item)
        return out

    def received(self, h: bytes) -> bool:
        """The announcement for *h* was answered (tx or notfound)."""
        entry = self._entries.pop(h, None)
        if entry is None:
            return False
        self._detach(h, entry)
        return True

    def forget_peer(self, peer: Hashable) -> None:
        """Drop everything tracked for a disconnected peer."""
        st = self._peers.pop(peer, None)
        if st is None:
            return
        for h in st.queued:
            self._entries.pop(h, None)
        for h in st.in_flight:
            self._entries.pop(h, None)
