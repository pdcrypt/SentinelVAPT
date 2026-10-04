from fastapi import APIRouter

from app.api.v1.routers import assessments, health, projects, targets

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(projects.router)
api_router.include_router(targets.router)
api_router.include_router(assessments.router)
