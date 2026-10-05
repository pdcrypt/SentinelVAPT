from fastapi import APIRouter, Depends

from app.api.authz import require_access_descriptor
from app.api.v1.routers import (
    assessments,
    audit,
    auth,
    findings,
    health,
    members,
    projects,
    reports,
    retest_reports,
    retests,
    scans,
    targets,
    users,
)

# Default deny (ADR 0014): every route must declare exactly one access
# descriptor (public, authenticated, global or project permission) on the
# route itself, or the request fails closed with a logged 500.
api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_access_descriptor)])
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(projects.router)
api_router.include_router(targets.router)
api_router.include_router(assessments.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(retests.router)
api_router.include_router(retest_reports.router)
api_router.include_router(audit.router)
api_router.include_router(users.router)
api_router.include_router(members.router)
api_router.include_router(members.self_router)
