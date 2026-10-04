import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.config import AppEnv, Settings, get_settings
from app.core.errors import register_error_handlers
from app.db.session import make_engine, make_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    """App factory. Run with: uvicorn --factory app.main:create_app"""
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level.upper())

    # Creating the engine does not connect; connections open on first use.
    engine = make_engine(settings.database_url.get_secret_value())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    is_prod = settings.app_env is AppEnv.PRODUCTION
    app = FastAPI(
        title="SentinelVAPT API",
        version=__version__,
        # Interactive docs are handy locally but not exposed in production.
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.settings = settings
    app.state.session_factory = make_session_factory(engine)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "Authorization"],
        )

    register_error_handlers(app)
    app.include_router(api_router)
    return app
