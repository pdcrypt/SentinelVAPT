from collections.abc import Callable


class RateLimiter:
    """Spaces requests at least `min_interval` seconds apart.

    The clock (monotonic seconds) and sleep are injectable so tests are
    deterministic.
    """

    def __init__(
        self,
        min_interval: float,
        *,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        self.min_interval = min_interval
        self.clock = clock
        self.sleep = sleep
        self._next_allowed: float | None = None

    def acquire(self) -> float:
        """Block until the next request may be sent; return seconds waited."""
        now = self.clock()
        waited = 0.0
        if self._next_allowed is not None and now < self._next_allowed:
            waited = self._next_allowed - now
            self.sleep(waited)
            now = self._next_allowed
        self._next_allowed = now + self.min_interval
        return waited
