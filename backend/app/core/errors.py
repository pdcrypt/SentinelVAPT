"""Domain exceptions and their HTTP mapping.

Services raise these; only this module knows about status codes. Responses
have the shape {"detail": str, "code": str, "field": str | null}.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

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


def _body(detail: str, code: str, field: str | None = None) -> dict[str, str | None]:
    return {"detail": detail, "code": code, "field": field}


async def _domain_error_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, DomainError)  # noqa: S101  # registered for DomainError only
    return JSONResponse(
        status_code=exc.status_code, content=_body(exc.message, exc.code, exc.field)
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
    app.add_exception_handler(IntegrityError, _integrity_error_handler)
