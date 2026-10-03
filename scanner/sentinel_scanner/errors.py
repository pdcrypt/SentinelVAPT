"""Scanner exceptions.

Two families:
- Refusals (GrantRejected): the scan is not permitted at all; nothing is sent.
- Per-request outcomes (ScopeViolation, RequestFailed): one request is blocked
  or fails, the scan continues.
- Stops (ScanStopped and subclasses): the scan must end now.
"""


class ScannerError(Exception):
    """Base class for all scanner errors."""


class GrantRejected(ScannerError):  # a refusal, not a malfunction
    """The scan grant does not permit scanning. Raised before any network I/O."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ScopeViolation(ScannerError):
    """A URL or resolved address is outside the authorized scope. The request
    was not sent."""

    def __init__(self, code: str, message: str, url: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.url = url


class RequestFailed(ScannerError):
    """A permitted request failed (connection error, timeout, protocol error)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ScanStopped(ScannerError):
    """The scan must stop. `reason` is a StopReason value."""

    reason = "stopped"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RequestLimitReached(ScanStopped):
    reason = "request_limit"


class TimeBudgetExhausted(ScanStopped):
    reason = "time_budget"


class AuthorizationExpired(ScanStopped):
    reason = "authorization_expired"


class ScanCancelled(ScanStopped):
    reason = "cancelled"
