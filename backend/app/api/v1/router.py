from fastapi import APIRouter

from app.api.v1.routers import health

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
