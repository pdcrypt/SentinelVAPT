"""Phase 9 M4 route inventory: every route of the production app declares
exactly one access descriptor, the expected one, on the route itself, and runs
behind the default-deny guard. A new route fails these tests until it is
classified here."""

import re
from collections.abc import Iterator

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from app.api.authz import is_guarded, iter_api_routes, route_descriptors
from app.api.v1.router import api_router
from app.core.authz import (
    AccessDescriptor,
    Authenticated,
    GlobalAccess,
    Permission,
    ProjectAccess,
    Public,
    ResourceType,
)
from app.core.config import Settings
from app.main import create_app

P = Permission
R = ResourceType


def project(permission: Permission, resource: ResourceType, *params: str) -> ProjectAccess:
    """A project descriptor whose single id is the route's only id parameter."""
    (param,) = params
    return ProjectAccess(permission, resource, {"id": param})


READ = P.PROJECT_READ
AUTH_SESSION = Authenticated(allow_password_change_pending=True)
EXPECTED: dict[tuple[str, str], AccessDescriptor] = {
    # public
    ("GET", "/api/v1/health"): Public(),
    ("GET", "/api/v1/health/ready"): Public(),
    ("POST", "/api/v1/auth/login"): Public(),
    # authenticated (account and session routes stay open while a password change is pending)
    ("POST", "/api/v1/auth/logout"): AUTH_SESSION,
    ("GET", "/api/v1/auth/me"): AUTH_SESSION,
    ("POST", "/api/v1/auth/password"): AUTH_SESSION,
    ("GET", "/api/v1/projects"): Authenticated(),  # filtered by membership
    # global permissions
    ("POST", "/api/v1/projects"): GlobalAccess(P.PROJECT_CREATE),
    ("GET", "/api/v1/rules"): GlobalAccess(P.CATALOG_READ),
    ("GET", "/api/v1/report-templates"): GlobalAccess(P.CATALOG_READ),
    ("GET", "/api/v1/retest-report-templates"): GlobalAccess(P.CATALOG_READ),
    ("GET", "/api/v1/audit-events"): GlobalAccess(P.AUDIT_READ_GLOBAL),  # M6: global admins
    # projects
    ("GET", "/api/v1/projects/{project_id}"): project(READ, R.PROJECT, "project_id"),
    ("PATCH", "/api/v1/projects/{project_id}"): project(P.PROJECT_UPDATE, R.PROJECT, "project_id"),
    ("DELETE", "/api/v1/projects/{project_id}"): project(P.PROJECT_DELETE, R.PROJECT, "project_id"),
    ("GET", "/api/v1/projects/{project_id}/assessments"): project(READ, R.PROJECT, "project_id"),
    ("GET", "/api/v1/projects/{project_id}/targets"): project(READ, R.PROJECT, "project_id"),
    ("GET", "/api/v1/projects/{project_id}/audit-events"): project(
        P.AUDIT_READ_PROJECT, R.PROJECT, "project_id"
    ),
    ("POST", "/api/v1/projects/{project_id}/targets"): project(
        P.TARGET_MANAGE, R.PROJECT, "project_id"
    ),
    # targets
    ("GET", "/api/v1/targets/{target_id}"): project(READ, R.TARGET, "target_id"),
    ("PATCH", "/api/v1/targets/{target_id}"): project(P.TARGET_MANAGE, R.TARGET, "target_id"),
    ("DELETE", "/api/v1/targets/{target_id}"): project(P.TARGET_MANAGE, R.TARGET, "target_id"),
    ("GET", "/api/v1/targets/{target_id}/authorizations"): project(READ, R.TARGET, "target_id"),
    ("GET", "/api/v1/targets/{target_id}/assessments"): project(READ, R.TARGET, "target_id"),
    ("POST", "/api/v1/targets/{target_id}/assessments"): project(
        P.ASSESSMENT_WRITE, R.TARGET, "target_id"
    ),
    # assessments
    ("GET", "/api/v1/assessments/{assessment_id}"): project(READ, R.ASSESSMENT, "assessment_id"),
    ("PATCH", "/api/v1/assessments/{assessment_id}"): project(
        P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"
    ),
    ("DELETE", "/api/v1/assessments/{assessment_id}"): project(
        P.ASSESSMENT_DELETE, R.ASSESSMENT, "assessment_id"
    ),
    **{
        ("POST", f"/api/v1/assessments/{{assessment_id}}/{action}"): project(
            P.ASSESSMENT_WRITE, R.ASSESSMENT, "assessment_id"
        )
        for action in ("start", "complete", "cancel")
    },
    ("POST", "/api/v1/assessments/{assessment_id}/scans"): project(
        P.SCAN_RUN, R.ASSESSMENT, "assessment_id"
    ),
    ("POST", "/api/v1/assessments/{assessment_id}/reports"): project(
        P.REPORT_REQUEST, R.ASSESSMENT, "assessment_id"
    ),
    ("POST", "/api/v1/assessments/{assessment_id}/retests"): project(
        P.RETEST_WRITE, R.ASSESSMENT, "assessment_id"
    ),
    ("POST", "/api/v1/assessments/{assessment_id}/comparisons"): project(
        P.RETEST_WRITE, R.ASSESSMENT, "assessment_id"
    ),
    **{
        ("GET", f"/api/v1/assessments/{{assessment_id}}/{sub}"): project(
            READ, R.ASSESSMENT, "assessment_id"
        )
        for sub in (
            "scans",
            "reports",
            "retests",
            "lineage",
            "comparisons",
            "retest-reports",
            "findings/summary",
        )
    },
    (
        "POST",
        "/api/v1/assessments/{assessment_id}/comparisons/{comparison_id}/reports",
    ): ProjectAccess(
        P.REPORT_REQUEST,
        R.ASSESSMENT_COMPARISON,
        {"assessment_id": "assessment_id", "comparison_id": "comparison_id"},
    ),
    # scans and their results
    ("GET", "/api/v1/scans/{scan_id}"): project(READ, R.SCAN, "scan_id"),
    ("POST", "/api/v1/scans/{scan_id}/cancel"): project(P.SCAN_RUN, R.SCAN, "scan_id"),
    **{
        ("GET", f"/api/v1/scans/{{scan_id}}/{sub}"): project(READ, R.SCAN, "scan_id")
        for sub in (
            "logs",
            "assets",
            "endpoints",
            "evidence",
            "findings",
            "findings/summary",
            "analysis",
        )
    },
    ("GET", "/api/v1/evidence/{evidence_id}"): project(READ, R.EVIDENCE, "evidence_id"),
    # findings
    ("GET", "/api/v1/findings/{finding_id}"): project(READ, R.FINDING, "finding_id"),
    ("GET", "/api/v1/findings/{finding_id}/evidence"): project(READ, R.FINDING, "finding_id"),
    ("GET", "/api/v1/findings/{finding_id}/history"): project(READ, R.FINDING, "finding_id"),
    ("POST", "/api/v1/findings/{finding_id}/triage"): project(
        P.FINDING_TRIAGE, R.FINDING, "finding_id"
    ),
    # reports (artifacts and previews resolve through their owning report)
    **{
        ("GET", f"/api/v1/reports/{{report_id}}{sub}"): project(READ, R.REPORT, "report_id")
        for sub in ("", "/artifacts", "/artifacts/{fmt}", "/preview")
    },
    **{
        ("GET", f"/api/v1/retest-reports/{{report_id}}{sub}"): project(
            READ, R.RETEST_REPORT, "report_id"
        )
        for sub in ("", "/artifacts", "/artifacts/{fmt}", "/preview")
    },
    # comparisons
    ("GET", "/api/v1/comparisons/{comparison_id}"): project(READ, R.COMPARISON, "comparison_id"),
    ("GET", "/api/v1/comparisons/{comparison_id}/records"): project(
        READ, R.COMPARISON, "comparison_id"
    ),
    ("GET", "/api/v1/comparisons/{comparison_id}/records/{fingerprint}"): ProjectAccess(
        READ, R.COMPARISON_RECORD, {"comparison_id": "comparison_id", "fingerprint": "fingerprint"}
    ),
}

# Path parameters that select a representation of an authorized resource
# rather than identify a resource: the report format (the artifact is looked
# up under the authorized report by the service).
NON_RESOURCE_PARAMS = {"fmt"}

PUBLIC = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/health/ready"),
    ("POST", "/api/v1/auth/login"),
}
PENDING_ALLOWED = {
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/auth/me"),
    ("POST", "/api/v1/auth/password"),
}


@pytest.fixture(scope="module")
def production_app() -> FastAPI:
    return create_app()


def routes(app: FastAPI) -> Iterator[tuple[str, str, object]]:
    for context in iter_api_routes(app):
        for method in sorted(context.methods or ()):
            yield method, str(context.path), context


def test_every_route_is_classified_exactly_once(production_app: FastAPI) -> None:
    seen = {(m, p) for m, p, _ in routes(production_app)}
    assert seen == set(EXPECTED), (
        f"unclassified: {sorted(seen - set(EXPECTED))}; gone: {sorted(set(EXPECTED) - seen)}"
    )
    assert len(seen) == 68
    for method, path, context in routes(production_app):
        descriptors = route_descriptors(context)
        assert descriptors == [EXPECTED[(method, path)]], (method, path, descriptors)


def test_every_route_runs_behind_the_default_deny_guard(production_app: FastAPI) -> None:
    for method, path, context in routes(production_app):
        assert is_guarded(context), (method, path)  # type: ignore[arg-type]


def test_public_and_pending_password_routes_are_exactly_the_allowed_ones() -> None:
    assert {k for k, d in EXPECTED.items() if isinstance(d, Public)} == PUBLIC
    pending = {
        k
        for k, d in EXPECTED.items()
        if isinstance(d, Authenticated) and d.allow_password_change_pending
    }
    assert pending == PENDING_ALLOWED


def test_every_path_resource_parameter_is_covered(production_app: FastAPI) -> None:
    for method, path, _ in routes(production_app):
        params = set(re.findall(r"{(\w+)}", path))
        descriptor = EXPECTED[(method, path)]
        if isinstance(descriptor, ProjectAccess):
            covered = set(descriptor.key.values())
            assert covered <= params, (method, path)
            assert params - covered <= NON_RESOURCE_PARAMS, (method, path, params - covered)
        else:
            assert not params, (method, path)


def test_project_routes_never_use_global_admin_permissions() -> None:
    for key, descriptor in EXPECTED.items():
        if isinstance(descriptor, GlobalAccess):
            allowed = {P.PROJECT_CREATE, P.CATALOG_READ}
            if key == ("GET", "/api/v1/audit-events"):
                allowed = {P.AUDIT_READ_GLOBAL}  # the one global admin route
            assert descriptor.permission in allowed, key
        if key[1].startswith(("/api/v1/projects/", "/api/v1/targets/")):
            assert isinstance(descriptor, ProjectAccess), key


@pytest.fixture
def rogue_route() -> Iterator[None]:
    """Temporarily adds unclassified routes to the production API router."""
    rogue = APIRouter()

    @rogue.get("/m4-rogue/plain")
    def plain() -> dict[str, str]:
        return {"leaked": "yes"}

    before = list(api_router.routes)
    api_router.include_router(rogue)
    try:
        yield
    finally:
        api_router.routes[:] = before


def test_an_unclassified_production_route_fails_closed(
    rogue_route: None, settings: Settings
) -> None:
    app = create_app(settings)
    rogue = [c for c in iter_api_routes(app) if "m4-rogue" in str(c.path)]
    assert rogue and route_descriptors(rogue[0]) == [] and is_guarded(rogue[0])
    with TestClient(app) as client:
        resp = client.get("/api/v1/m4-rogue/plain")
    assert resp.status_code == 500
    assert resp.json()["code"] == "authorization_error"
    assert "leaked" not in resp.text
