import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.api.authz import public
from app.db.session import get_engine, ping
from app.schemas.health import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", dependencies=[Depends(public())], response_model=HealthResponse)
def liveness() -> HealthResponse:
    """The process is up. Does not touch dependencies."""
    return HealthResponse(status="ok", version=__version__)


@router.get("/ready", dependencies=[Depends(public())], response_model=HealthResponse)
def readiness(engine: Annotated[Engine, Depends(get_engine)]) -> HealthResponse:
    """The API can serve traffic: the database is reachable."""
    try:
        ping(engine)
    except SQLAlchemyError:
        logger.exception("Database readiness check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unavailable",
        ) from None
    return HealthResponse(status="ok", version=__version__)
