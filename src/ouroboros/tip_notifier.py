"""Tip-change notification primitive for the wait-family RPCs.

Bitcoin Core registers a ``WaitTipChanged`` condition variable (kernel
``Notifications`` / ``KernelNotifications::blockTip``) that is signalled on
every active-chain tip update.  The ``waitfornewblock`` / ``waitforblock`` /
``waitforblockheight`` RPCs (``rpc/blockchain.cpp``) block on it with a
deadline, re-checking their predicate (new tip / hash match / height >=) after
each wake and returning the current tip ``{hash, height}`` on match OR timeout.

``TipNotifier`` is the ouroboros analogue.  It is deliberately tiny and
self-contained so the same shape can be ported to the other nine nodes — the
only per-node variable is *where* the tip-advance happens (the connect /
reorg chokepoint that must call :meth:`notify`).

Design notes
------------
* The waiter's predicate is always evaluated against the **authoritative**
  database tip (``db.get_best_block()``), never against state carried inside
  this object.  The notifier only provides a prompt wake-up; correctness does
  not depend on a notify ever firing for a specific tip value.  This makes the
  primitive robust to coalesced / missed notifications (e.g. two blocks
  connected back-to-back before a waiter wakes): the waiter re-reads the real
  tip after every wake and after the timeout, exactly like Core.

* A monotonically increasing ``generation`` counter lets a waiter detect a tip
  change that happened *between* its predicate check and its ``wait`` call
  (the classic lost-wakeup race).  A waiter captures the generation, checks its
  predicate, then awaits a generation bump — so a notify that races in after
  the check but before the await is not lost.

* ``asyncio.Event`` is the wake mechanism.  ``notify`` is safe to call from any
  coroutine running on the notifier's event loop; it bumps the generation and
  pulses the event (set-then-clear) so all current waiters wake.
"""

from __future__ import annotations

import asyncio


class TipNotifier:
    """Wake-on-tip-advance primitive shared by the wait-family RPCs."""

    def __init__(self) -> None:
        self._event = asyncio.Event()
        # Monotonic counter bumped on every notify().  Waiters snapshot it
        # before checking their predicate so a notify that races in between
        # the check and the await is observed (no lost wakeup).
        self._generation = 0

    @property
    def generation(self) -> int:
        """Current tip-change generation (bumped on every :meth:`notify`)."""
        return self._generation

    def notify(self) -> None:
        """Signal that the active-chain tip advanced.

        Bumps the generation counter and pulses the wake event so every
        coroutine currently in :meth:`wait` re-evaluates its predicate.  Safe
        to call from any connect / reorg chokepoint on the event loop.
        """
        self._generation += 1
        # set() then clear() so the event acts as an edge-triggered pulse:
        # all currently-waiting coroutines are released, and a *future*
        # wait() call blocks again (it must observe a generation bump, not a
        # stale set flag).
        self._event.set()
        self._event.clear()

    async def wait(self, last_generation: int, timeout: float | None) -> bool:
        """Await the next tip change after *last_generation*.

        Args:
            last_generation: The generation observed by the caller *before* it
                last checked its predicate.  If the generation has already
                advanced past this (a notify raced in), return immediately.
            timeout: Seconds to wait, or ``None`` to wait indefinitely.

        Returns:
            ``True`` if a tip change was observed within the deadline,
            ``False`` if the wait timed out.  Either way the caller must
            re-evaluate its predicate against the authoritative DB tip.
        """
        # Fast path: a notify already raced in since the caller's snapshot.
        if self._generation != last_generation:
            return True
        try:
            if timeout is None:
                await self._event.wait()
            else:
                await asyncio.wait_for(self._event.wait(), timeout)
            return True
        except TimeoutError:
            return False
