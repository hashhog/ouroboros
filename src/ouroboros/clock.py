"""Process-wide mockable clock, the analogue of Bitcoin Core's ``GetTime()`` /
``SetMockTime()`` (util/time.cpp).

Production reads the system clock.  The regtest-only ``setmocktime`` RPC pins
it to a fixed Unix timestamp; ``0`` returns to the system clock.
"""

import time

_mock_time: int = 0


def set_mock_time(seconds: int) -> None:
    global _mock_time
    _mock_time = int(seconds)


def get_mock_time() -> int:
    return _mock_time


def now() -> float:
    """Current Unix time in seconds: the mock time if set, else ``time.time()``."""
    return float(_mock_time) if _mock_time else time.time()
