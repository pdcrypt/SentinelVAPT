from collections.abc import Callable
from datetime import UTC, datetime

# Services take a clock instead of calling datetime.now() so time-dependent
# rules (authorization windows) are testable.
Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)
