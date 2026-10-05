"""Domain exceptions and their HTTP mapping.

Services raise these; only this module knows about status codes. Responses
have the shape {"detail": str, "code": str, "field": str | null}.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.core.authz import AuthorizationConfigError

logger = logging.getLogger(__name__)


class DomainError(Exception):
    status_code = 400
    code = "domain_error"

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"


class ConflictError(DomainError):
    status_code = 409
    code = "conflict"


class DomainValidationError(DomainError):
    status_code = 422
    code = "validation_error"


class TargetAuthorizationError(DomainError):
    """The target's testing authorization does not permit the requested action."""

    status_code = 409
    code = "target_authorization_invalid"


class InvalidStateTransitionError(DomainError):
    status_code = 409
    code = "invalid_state_transition"


class ScanNotAllowedError(DomainError):
    """A scan may not be created or run. `reason` says which rule refused it
    (e.g. authorization_superseded, assessment_not_in_progress)."""

    status_code = 409
    code = "scan_not_allowed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, field=None)
        self.reason = reason


class ReportNotAllowedError(DomainError):
    """A report may not be generated from the requested scan. `reason` says
    which rule refused it (e.g. scan_not_completed, assessment_not_completed)."""

    status_code = 409
    code = "report_not_allowed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, field=None)
        self.reason = reason


class RetestNotAllowedError(DomainError):
    """A retest may not be created (e.g. parent_not_completed, scope_expanded)."""

    status_code = 409
    code = "retest_not_allowed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, field=None)
        self.reason = reason


class ComparisonNotAllowedError(DomainError):
    """A comparison may not be requested (e.g. not_a_retest, analysis_not_completed)."""

    status_code = 409
    code = "comparison_not_allowed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, field=None)
        self.reason = reason


class RetestReportNotAllowedError(DomainError):
    """A retest report may not be created (e.g. comparison_not_completed)."""

    status_code = 409
    code = "retest_report_not_allowed"

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, field=None)
        self.reason = reason


class AuthenticationError(DomainError):
    """No valid session (missing, unknown, revoked, expired or disabled user).
    Deliberately uniform: the response never says which."""

    status_code = 401
    code = "unauthenticated"

    def __init__(self) -> None:
        super().__init__("Authentication required.")


class InvalidCredentialsError(DomainError):
    """A failed login. Unknown user, wrong password, disabled account and
    throttling all produce exactly this error (ADR 0014)."""

    status_code = 401
    code = "invalid_credentials"

    def __init__(self) -> None:
        super().__init__("Invalid username or password.")


class InvalidCurrentPasswordError(DomainError):
    """A password change whose current password did not verify (or that was
    throttled). Not 401: the session itself is still valid."""

    status_code = 403
    code = "invalid_current_password"

    def __init__(self) -> None:
        super().__init__("The current password is incorrect.", field="current_password")


class ForbiddenError(DomainError):
    """A project member whose role lacks the required permission (or a
    principal lacking a global permission). Non-members get 404 instead."""

    status_code = 403
    code = "forbidden"

    def __init__(self) -> None:
        super().__init__("You do not have permission to do this.")


class PasswordChangeRequiredError(DomainError):
    """The principal must change their password before anything else."""

    status_code = 403
    code = "password_change_required"

    def __init__(self) -> None:
        super().__init__("Change your password to continue.")


def _body(detail: str, code: str, field: str | None = None) -> dict[str, str | None]:
    return {"detail": detail, "code": code, "field": field}


async def _domain_error_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, DomainError)  # noqa: S101  # registered for DomainError only
    content: dict[str, str | None] = _body(exc.message, exc.code, exc.field)
    if isinstance(
        exc,
        ScanNotAllowedError
        | ReportNotAllowedError
        | RetestNotAllowedError
        | ComparisonNotAllowedError
        | RetestReportNotAllowedError,
    ):
        content["reason"] = exc.reason
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    return JSONResponse(status_code=exc.status_code, content=content, headers=headers)


# Fields whose submitted values must never be echoed back in a 422 response.
_SECRET_FIELD_HINTS = ("password", "token", "secret")


def _is_secret_field(loc: object) -> bool:
    return isinstance(loc, list | tuple) and any(
        isinstance(part, str) and any(hint in part.lower() for hint in _SECRET_FIELD_HINTS)
        for part in loc
    )


async def _request_validation_handler(_: Request, exc: Exception) -> JSONResponse:
    """FastAPI's default 422 body, except that the submitted value of a
    password or token field is never echoed back."""
    assert isinstance(exc, RequestValidationError)  # noqa: S101  # registered for it only
    errors = []
    for error in exc.errors():
        item = dict(error)
        if _is_secret_field(item.get("loc")):
            item.pop("input", None)
            item.pop("ctx", None)
        errors.append(item)
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


async def _authorization_config_handler(_: Request, exc: Exception) -> JSONResponse:
    """An authorization declaration that cannot be evaluated is a defect: log
    it and fail closed. The details stay in the log."""
    logger.error("Authorization configuration error: %s", exc)
    return JSONResponse(
        status_code=500,
        content=_body("The request could not be authorized.", "authorization_error"),
    )


async def _integrity_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # Backstop for races the service-level checks cannot rule out. The raw
    # database message is logged, never returned.
    logger.warning("Integrity error: %s", exc)
    return JSONResponse(
        status_code=409,
        content=_body("The request conflicts with existing data.", "integrity_error"),
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, _domain_error_handler)
    app.add_exception_handler(RequestValidationError, _request_validation_handler)
    app.add_exception_handler(AuthorizationConfigError, _authorization_config_handler)
    app.add_exception_handler(IntegrityError, _integrity_error_handler)
