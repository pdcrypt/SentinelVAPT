"""Phase 9 M3 authorization machinery against PostgreSQL: project resolution
for every resource type, IDOR and error semantics through a probe router, the
password-change gate, default deny, admin isolation and membership changes
under concurrency.

The probe router exists only in these tests: M3 attaches nothing to the
product routes (M4 does)."""

import logging
import threading
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.api.authz import (
    ACCESS_ATTR,
    authenticated,
    authorize,
    is_guarded,
    iter_api_routes,
    public,
    require_access_descriptor,
    require_global,
    route_descriptors,
)
from app.api.deps import get_project_service, get_report_service
from app.core.authz import (
    AccessDecision,
    Authenticated,
    GlobalAccess,
    Permission,
    ProjectAccess,
    Public,
    ResourceType,
)
from app.core.clock import utc_now
from app.core.errors import ForbiddenError, NotFoundError
from app.models.enums import GlobalRole, ProjectRole
from app.repositories.authz import RESOLVERS, ProjectResolver, Resolution
from app.schemas.project import ProjectCreate
from app.schemas.report import ReportCreate
from app.services.access import AccessService
from app.services.auth import Principal
from tests.integration.auth_support import Live, bearer, live, login
from tests.integration.scan_support import ScanEnv, purge_project
from tests.integration.test_retest_reports import (  # fixtures, re-exported below
    baseline,
    chain,
    committed_api,
    completed,
    render_worker,
)

pytestmark = pytest.mark.integration

__all__ = ["baseline", "chain", "committed_api", "completed", "live"]

P = Permission
R = ResourceType
PROBE = "/api/v1/m3-probe"


# --- probe router ----------------------------------------------------------------------------


def _forged() -> None:
    return None


setattr(_forged, ACCESS_ATTR, object())  # a "descriptor" of an unknown kind


def probe_router() -> APIRouter:
    router = APIRouter(prefix="/m3-probe", dependencies=[Depends(require_access_descriptor)])

    def decision_body(decision: AccessDecision) -> dict[str, Any]:
        return {
            "project_id": str(decision.project_id),
            "role": decision.role,
            "permission": decision.permission,
        }

    @router.get("/public", dependencies=[Depends(public())])
    def open_route() -> dict[str, str]:
        return {"ok": "public"}

    @router.get("/me")
    def me(who: Annotated[Principal, Depends(authenticated())]) -> dict[str, str]:
        return {"user": who.username}

    @router.get("/me-pending")
    def me_pending(
        who: Annotated[Principal, Depends(authenticated(allow_password_change_pending=True))],
    ) -> dict[str, str]:
        return {"user": who.username}

    @router.get("/admin")
    def admin(
        d: Annotated[AccessDecision, Depends(require_global(P.USER_ADMIN))],
    ) -> dict[str, Any]:
        return {"permission": d.permission}

    @router.get("/targets/{target_id}")
    def read_target(
        d: Annotated[AccessDecision, Depends(authorize(P.PROJECT_READ, R.TARGET, "target_id"))],
    ) -> dict[str, Any]:
        return decision_body(d)

    @router.post("/targets/{target_id}/manage")
    def manage_target(
        d: Annotated[AccessDecision, Depends(authorize(P.TARGET_MANAGE, R.TARGET, "target_id"))],
    ) -> dict[str, Any]:
        return decision_body(d)

    @router.post("/targets/{target_id}/scan")
    def scan_target(
        d: Annotated[AccessDecision, Depends(authorize(P.SCAN_RUN, R.TARGET, "target_id"))],
    ) -> dict[str, Any]:
        return decision_body(d)

    @router.get("/projects/{project_id}")
    def read_project(
        d: Annotated[AccessDecision, Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))],
    ) -> dict[str, Any]:
        return decision_body(d)

    @router.get("/undeclared")
    def undeclared() -> dict[str, str]:
        return {"ok": "leaked"}

    @router.get("/double", dependencies=[Depends(public()), Depends(authenticated())])
    def double() -> dict[str, str]:
        return {"ok": "leaked"}

    @router.get("/forged", dependencies=[Depends(_forged)])
    def forged() -> dict[str, str]:
        return {"ok": "leaked"}

    return router


# --- world: two projects, one user per role -----------------------------------------------------


@dataclass
class World:
    live: Live
    env: ScanEnv
    client: TestClient
    p1: uuid.UUID
    p2: uuid.UUID
    target1: uuid.UUID
    target2: uuid.UUID
    users: dict[str, Any] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)

    def get(self, path: str, who: str | None = None) -> Any:
        headers = bearer(self.tokens[who]) if who else {}
        return self.client.get(f"{PROBE}{path}", headers=headers)

    def post(self, path: str, who: str | None = None) -> Any:
        headers = bearer(self.tokens[who]) if who else {}
        return self.client.post(f"{PROBE}{path}", headers=headers)


def add_member(engine: Engine, project: uuid.UUID, user: uuid.UUID, role: ProjectRole) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, :r)"),
            {"p": project, "u": user, "r": role.value},
        )


def remove_members(engine: Engine, projects: list[uuid.UUID]) -> None:
    """Test cleanup only: removing every owner is refused normally."""
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text("DELETE FROM project_members WHERE project_id = ANY(:p)"), {"p": projects}
        )


def new_project(env: ScanEnv) -> uuid.UUID:
    with env.factory() as s:
        return (
            get_project_service(s)
            .create(ProjectCreate(name=f"m3-{uuid.uuid4()}"), owner_id=None)
            .id
        )


@pytest.fixture
def world(live: Live, scan_env: ScanEnv, engine: Engine) -> Iterator[World]:
    p2 = new_project(scan_env)
    try:
        target1 = scan_env.target()
        target2 = ScanEnv(scan_env.factory, scan_env.site, p2).target()
        client = live.client()
        client.app.include_router(probe_router(), prefix="/api/v1")  # type: ignore[attr-defined]
        w = World(live, scan_env, client, scan_env.project_id, p2, target1, target2)
        roles = {
            "owner": ProjectRole.OWNER,
            "operator": ProjectRole.OPERATOR,
            "viewer": ProjectRole.VIEWER,
            "pending": ProjectRole.OWNER,
        }
        for name in ("owner", "operator", "viewer", "pending", "outsider", "admin", "nobody"):
            global_role = GlobalRole.ADMIN if name == "admin" else GlobalRole.USER
            w.users[name] = live.user(f"{name}-{uuid.uuid4().hex[:6]}", role=global_role)
        for name, project_role in roles.items():
            add_member(engine, w.p1, w.users[name].id, project_role)
        add_member(engine, p2, w.users["outsider"].id, ProjectRole.OWNER)
        for name, user in w.users.items():
            w.tokens[name] = login(client, user.username).json()["token"]
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET must_change_password = true WHERE id = :u"),
                {"u": w.users["pending"].id},
            )
        yield w
    finally:
        remove_members(engine, [scan_env.project_id, p2])
        purge_project(scan_env.factory, p2)


# --- error semantics and IDOR ------------------------------------------------------------------


def test_anonymous_requests_get_401_before_anything_else(world: World) -> None:
    for path in (
        "/me",
        "/me-pending",
        "/admin",
        f"/targets/{world.target1}",
        f"/targets/{uuid.uuid4()}",
        "/targets/not-a-uuid",
    ):
        resp = world.get(path)
        assert resp.status_code == 401, path
        assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert world.get("/public").json() == {"ok": "public"}


def test_members_get_their_role_and_project(world: World) -> None:
    for who, role in (("owner", "owner"), ("operator", "operator"), ("viewer", "viewer")):
        resp = world.get(f"/targets/{world.target1}", who)
        assert resp.status_code == 200, who
        assert resp.json() == {
            "project_id": str(world.p1),
            "role": role,
            "permission": "project.read",
        }
    assert world.get(f"/projects/{world.p1}", "viewer").status_code == 200
    assert world.get(f"/targets/{world.target2}", "outsider").json()["project_id"] == str(world.p2)


def test_missing_cross_project_and_non_member_are_one_404(world: World) -> None:
    expected = {"detail": "target not found", "code": "not_found", "field": None}
    cases = [
        ("owner", f"/targets/{uuid.uuid4()}"),  # nonexistent
        ("owner", "/targets/not-a-uuid"),  # malformed
        ("owner", f"/targets/{world.target2}"),  # exists in another project
        ("outsider", f"/targets/{world.target1}"),  # member elsewhere only
        ("nobody", f"/targets/{world.target1}"),  # member nowhere
        ("admin", f"/targets/{world.target1}"),  # global admin, no membership
    ]
    for who, path in cases:
        resp = world.get(path, who)
        assert (resp.status_code, resp.json()) == (404, expected), (who, path)
        assert "WWW-Authenticate" not in resp.headers
    # The same holds for writes, before any permission check: no 403 leaks existence.
    for who, target in (
        ("viewer", world.target2),
        ("outsider", world.target1),
        ("admin", world.target1),
    ):
        resp = world.post(f"/targets/{target}/manage", who)
        assert (resp.status_code, resp.json()) == (404, expected), who
    project_404 = world.get(f"/projects/{world.p2}", "owner")
    assert (project_404.status_code, project_404.json()["detail"]) == (404, "project not found")


def test_client_supplied_project_ids_are_ignored(world: World) -> None:
    """The project comes from the resource's own rows: a project id in the
    query, a header or a body never steers resolution."""
    for who, target, claimed in (
        ("outsider", world.target1, world.p2),
        ("owner", world.target2, world.p1),
    ):
        resp = world.client.get(
            f"{PROBE}/targets/{target}",
            params={"project_id": str(claimed)},
            headers={**bearer(world.tokens[who]), "X-Project-Id": str(claimed)},
        )
        assert resp.status_code == 404, who
    resp = world.client.get(
        f"{PROBE}/targets/{world.target1}",
        params={"project_id": str(world.p2)},
        headers=bearer(world.tokens["viewer"]),
    )
    assert resp.json()["project_id"] == str(world.p1)


def test_members_without_the_permission_get_403(world: World) -> None:
    forbidden = {
        "detail": "You do not have permission to do this.",
        "code": "forbidden",
        "field": None,
    }
    for who in ("viewer", "operator"):
        resp = world.post(f"/targets/{world.target1}/manage", who)
        assert (resp.status_code, resp.json()) == (403, forbidden), who
    assert world.post(f"/targets/{world.target1}/scan", "viewer").status_code == 403
    assert world.post(f"/targets/{world.target1}/scan", "operator").status_code == 200
    assert world.post(f"/targets/{world.target1}/manage", "owner").status_code == 200


def test_admin_has_global_permissions_and_no_project_access(world: World) -> None:
    assert world.get("/admin", "admin").json() == {"permission": "user.admin"}
    assert world.get("/admin", "owner").status_code == 403
    for path in (f"/targets/{world.target1}", f"/targets/{world.target2}", f"/projects/{world.p1}"):
        assert world.get(path, "admin").status_code == 404, path
    for action in ("manage", "scan"):
        assert world.post(f"/targets/{world.target1}/{action}", "admin").status_code == 404
    # Membership, not the global role, is what grants project access.
    add_member(world.live.engine, world.p1, world.users["admin"].id, ProjectRole.VIEWER)
    assert world.get(f"/targets/{world.target1}", "admin").json()["role"] == "viewer"
    assert world.post(f"/targets/{world.target1}/manage", "admin").status_code == 403


# --- password-change gate -------------------------------------------------------------------------


def test_password_change_gate_runs_before_resolution(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    original = ProjectResolver.resolve

    def spy(self: ProjectResolver, *args: Any, **kwargs: Any) -> Resolution | None:
        calls.append(args)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ProjectResolver, "resolve", spy)
    gate = {
        "detail": "Change your password to continue.",
        "code": "password_change_required",
        "field": None,
    }
    for path in (
        f"/targets/{world.target1}",
        f"/targets/{uuid.uuid4()}",
        f"/targets/{world.target2}",
        "/targets/not-a-uuid",
        "/me",
        "/admin",
    ):
        resp = world.get(path, "pending")
        assert (resp.status_code, resp.json()) == (403, gate), path
    assert world.post(f"/targets/{world.target1}/manage", "pending").json() == gate
    assert calls == []  # nothing was looked up for the gated principal
    assert world.get("/me-pending", "pending").json() == {"user": world.users["pending"].username}
    # The same member without the flag is an owner again.
    with world.live.engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET must_change_password = false WHERE id = :u"),
            {"u": world.users["pending"].id},
        )
    assert world.get(f"/targets/{world.target1}", "pending").json()["role"] == "owner"
    assert calls


def test_auth_session_routes_stay_open_to_pending_principals(world: World) -> None:
    token = world.tokens["pending"]
    me = world.client.get("/api/v1/auth/me", headers=bearer(token))
    assert me.status_code == 200
    assert me.json()["user"]["must_change_password"] is True


# --- default deny --------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/undeclared", "/double", "/forged"])
@pytest.mark.parametrize("who", [None, "owner", "admin"])
def test_routes_without_exactly_one_known_descriptor_fail_closed(
    world: World, path: str, who: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="app.core.errors"):
        resp = world.get(path, who)
    assert resp.status_code == 500
    assert resp.json() == {
        "detail": "The request could not be authorized.",
        "code": "authorization_error",
        "field": None,
    }
    assert "leaked" not in resp.text
    assert "access descriptors" in caplog.text


def test_route_descriptors_are_discoverable(world: World) -> None:
    app = world.client.app
    contexts = iter_api_routes(app)  # type: ignore[arg-type]
    routes = {r.path: r for r in contexts if r.path and r.path.startswith(PROBE)}
    assert all(is_guarded(r) for r in routes.values())
    assert route_descriptors(routes[f"{PROBE}/public"]) == [Public()]
    assert route_descriptors(routes[f"{PROBE}/me"]) == [Authenticated(False)]
    assert route_descriptors(routes[f"{PROBE}/me-pending"]) == [Authenticated(True)]
    assert route_descriptors(routes[f"{PROBE}/admin"]) == [GlobalAccess(P.USER_ADMIN)]
    assert route_descriptors(routes[f"{PROBE}/targets/{{target_id}}/manage"]) == [
        ProjectAccess(P.TARGET_MANAGE, R.TARGET, {"id": "target_id"})
    ]
    assert route_descriptors(routes[f"{PROBE}/undeclared"]) == []
    assert len(route_descriptors(routes[f"{PROBE}/double"])) == 2


def test_a_descriptor_naming_a_missing_path_parameter_fails_closed(world: World) -> None:
    router = APIRouter(dependencies=[Depends(require_access_descriptor)])

    @router.get(
        "/m3-probe/misnamed/{target_id}",
        dependencies=[Depends(authorize(P.PROJECT_READ, R.TARGET, "tid"))],
    )
    def misnamed() -> dict[str, str]:
        return {"ok": "leaked"}

    world.client.app.include_router(router, prefix="/api/v1")  # type: ignore[attr-defined]
    resp = world.get(f"/misnamed/{world.target1}", "owner")
    assert resp.status_code == 500 and resp.json()["code"] == "authorization_error"


# --- resolution for every resource type --------------------------------------------------------


def one(env: ScanEnv, sql: str, **params: Any) -> Any:
    with env.factory() as s:
        row = s.execute(text(sql), params).first()
    assert row is not None, sql
    return row


def resource_keys(env: ScanEnv, c: Mapping[str, Any]) -> dict[ResourceType, dict[str, str]]:
    scan, report = c["scan_a"], c["phase5_report"]
    rr = c["report"]
    keys: dict[ResourceType, dict[str, Any]] = {
        R.PROJECT: {"id": env.project_id},
        R.TARGET: {"id": c["target"]},
        R.TARGET_AUTHORIZATION: {
            "id": one(
                env, "SELECT id FROM target_authorizations WHERE target_id = :t", t=c["target"]
            )[0]
        },
        R.ASSESSMENT: {"id": c["a"]},
        R.RETEST_ASSESSMENT: {"id": c["b"]},
        R.SCAN: {"id": scan},
        R.REPORT: {"id": report},
        R.COMPARISON: {"id": c["cmp_b"]},
        R.ASSESSMENT_COMPARISON: {"assessment_id": c["b"], "comparison_id": c["cmp_b"]},
        R.RETEST_REPORT: {"id": rr},
    }
    for resource, table in (
        (R.SCAN_LOG, "scan_logs"),
        (R.ASSET, "assets"),
        (R.ENDPOINT, "endpoints"),
        (R.EVIDENCE, "evidence"),
        (R.ANALYSIS_RUN, "analysis_runs"),
        (R.FINDING, "findings"),
    ):
        keys[resource] = {"id": one(env, f"SELECT id FROM {table} WHERE scan_id = :s", s=scan)[0]}  # noqa: S608
    fmt = one(env, "SELECT format FROM report_artifacts WHERE report_id = :r", r=report)[0]
    keys[R.REPORT_ARTIFACT] = {"report_id": report, "format": fmt}
    keys[R.REPORT_FINDING] = {
        "report_id": report,
        "finding_id": one(
            env, "SELECT finding_id FROM report_findings WHERE report_id = :r", r=report
        )[0],
    }
    keys[R.REPORT_EVIDENCE] = {
        "report_id": report,
        "evidence_id": one(
            env, "SELECT evidence_id FROM report_evidence WHERE report_id = :r", r=report
        )[0],
    }
    keys[R.COMPARISON_RECORD] = {
        "comparison_id": c["cmp_b"],
        "fingerprint": one(
            env, "SELECT fingerprint FROM comparison_records WHERE comparison_id = :c", c=c["cmp_b"]
        )[0],
    }
    cov = one(
        env,
        "SELECT comparison_id, fingerprint, evidence_id FROM "
        "comparison_coverage_evidence WHERE comparison_id IN (:b, :c)",
        b=c["cmp_b"],
        c=c["cmp_c"],
    )
    keys[R.COMPARISON_COVERAGE_EVIDENCE] = {
        "comparison_id": cov[0],
        "fingerprint": cov[1],
        "evidence_id": cov[2],
    }
    keys[R.RETEST_REPORT_ARTIFACT] = {
        "report_id": rr,
        "format": one(env, "SELECT format FROM retest_report_artifacts WHERE report_id = :r", r=rr)[
            0
        ],
    }
    ev = one(env, "SELECT role, evidence_id FROM retest_report_evidence WHERE report_id = :r", r=rr)
    keys[R.RETEST_REPORT_EVIDENCE] = {"report_id": rr, "role": ev[0], "evidence_id": ev[1]}
    return {resource: {k: str(v) for k, v in key.items()} for resource, key in keys.items()}


@pytest.fixture
def full_chain(
    scan_env: ScanEnv, completed: dict[str, Any], live: Live, engine: Engine
) -> Iterator[dict[str, Any]]:
    """Every resource type, in one project, plus a member, a non-member and a
    second project with its own target."""
    with scan_env.factory() as s:
        report = (
            get_report_service(s, utc_now)
            .create(
                completed["a"],
                ReportCreate.model_validate(
                    {
                        "scan_id": str(completed["scan_a"]),
                        "kind": "final",
                        "title": "A",
                        "prepared_by": "T",
                        "formats": ["json", "html"],
                    }
                ),
            )
            .id
        )
    assert render_worker(scan_env).run_once()
    p2 = new_project(scan_env)
    chief, member, stranger = live.user("chief"), live.user("member"), live.user("stranger")
    try:
        add_member(engine, scan_env.project_id, chief.id, ProjectRole.OWNER)
        add_member(engine, scan_env.project_id, member.id, ProjectRole.OPERATOR)
        add_member(engine, p2, stranger.id, ProjectRole.OWNER)
        other_target = ScanEnv(scan_env.factory, scan_env.site, p2).target()
        yield {
            **completed,
            "phase5_report": report,
            "member": member.id,
            "stranger": stranger.id,
            "p2": p2,
            "other_target": other_target,
        }
    finally:
        remove_members(engine, [scan_env.project_id, p2])
        purge_project(scan_env.factory, p2)


def test_every_resource_type_resolves_to_its_own_project(
    scan_env: ScanEnv, full_chain: dict[str, Any]
) -> None:
    keys = resource_keys(scan_env, full_chain)
    assert set(keys) == set(ResourceType)
    with scan_env.factory() as s:
        resolver = ProjectResolver(s)
        for resource, key in keys.items():
            member = resolver.resolve(resource, key, full_chain["member"])
            assert member == Resolution(scan_env.project_id, ProjectRole.OPERATOR), resource
            # A member of another project sees the resource's real project, no role.
            stranger = resolver.resolve(resource, key, full_chain["stranger"])
            assert stranger == Resolution(scan_env.project_id, None), resource
            # Any other or malformed id in any key component: not found.
            for name in RESOLVERS[resource].uuid_keys:
                for bad in (str(uuid.uuid4()), "not-a-uuid"):
                    assert (
                        resolver.resolve(resource, {**key, name: bad}, full_chain["member"]) is None
                    ), (resource, name)
        other = resolver.resolve(
            R.TARGET, {"id": str(full_chain["other_target"])}, full_chain["member"]
        )
        assert other == Resolution(full_chain["p2"], None)


def test_wrong_parent_and_wrong_kind_never_resolve(
    scan_env: ScanEnv, full_chain: dict[str, Any]
) -> None:
    keys = resource_keys(scan_env, full_chain)
    member = full_chain["member"]
    rr, report = keys[R.RETEST_REPORT]["id"], keys[R.REPORT]["id"]
    with scan_env.factory() as s:
        resolver = ProjectResolver(s)
        wrong = [
            # A child named under a parent it does not belong to.
            (R.REPORT_ARTIFACT, {**keys[R.REPORT_ARTIFACT], "report_id": rr}),
            (R.RETEST_REPORT_ARTIFACT, {**keys[R.RETEST_REPORT_ARTIFACT], "report_id": report}),
            (R.REPORT_EVIDENCE, {**keys[R.REPORT_EVIDENCE], "report_id": rr}),
            (R.RETEST_REPORT_EVIDENCE, {**keys[R.RETEST_REPORT_EVIDENCE], "report_id": report}),
            (R.RETEST_REPORT_EVIDENCE, {**keys[R.RETEST_REPORT_EVIDENCE], "role": "nonsense"}),
            (R.REPORT_ARTIFACT, {**keys[R.REPORT_ARTIFACT], "format": "exe"}),
            (R.COMPARISON_RECORD, {**keys[R.COMPARISON_RECORD], "fingerprint": "f" * 64}),
            # An id of one kind presented as another.
            (R.RETEST_ASSESSMENT, {"id": keys[R.ASSESSMENT]["id"]}),
            (
                R.ASSESSMENT_COMPARISON,
                {**keys[R.ASSESSMENT_COMPARISON], "assessment_id": keys[R.ASSESSMENT]["id"]},
            ),
            (R.REPORT, {"id": rr}),
            (R.RETEST_REPORT, {"id": report}),
            (R.SCAN, {"id": keys[R.FINDING]["id"]}),
            (R.FINDING, {"id": keys[R.EVIDENCE]["id"]}),
            (R.TARGET, {"id": keys[R.PROJECT]["id"]}),
            (R.PROJECT, {"id": keys[R.TARGET]["id"]}),
            (R.SCAN, {"id": "not-a-uuid"}),
        ]
        for resource, key in wrong:
            assert resolver.resolve(resource, key, member) is None, (resource, key)
        access = AccessService(resolver)
        principal = _principal(member)
        for resource, key in wrong:
            with pytest.raises(NotFoundError):
                access.authorize_project(principal, P.PROJECT_READ, resource, key)


def _principal(user_id: uuid.UUID, role: GlobalRole = GlobalRole.USER) -> Principal:
    now = utc_now()
    return Principal(user_id, "x", "x", role, False, uuid.uuid4(), now, now, now)


# --- membership changes and concurrency --------------------------------------------------------


def test_membership_changes_take_effect_on_the_next_request(world: World) -> None:
    engine, viewer = world.live.engine, world.users["viewer"].id
    path = f"/targets/{world.target1}"
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE project_members SET role = 'operator' WHERE user_id = :u"), {"u": viewer}
        )
    assert world.post(f"{path}/scan", "viewer").status_code == 200
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE project_members SET role = 'viewer' WHERE user_id = :u"), {"u": viewer}
        )
    assert world.post(f"{path}/scan", "viewer").status_code == 403
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM project_members WHERE user_id = :u"), {"u": viewer})
    assert world.get(path, "viewer").status_code == 404
    # An uncommitted grant is invisible to authorization.
    conn = engine.connect()
    try:
        tx = conn.begin()
        conn.execute(
            text(
                "INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, 'owner')"
            ),
            {"p": world.p1, "u": viewer},
        )
        assert world.get(path, "viewer").status_code == 404
        tx.rollback()
    finally:
        conn.close()
    assert world.get(path, "viewer").status_code == 404


def test_authorization_during_concurrent_membership_changes(world: World) -> None:
    """Readers racing a writer that keeps adding, re-roling and removing a
    membership only ever see a committed state: allowed with a real role,
    403 for a viewer, or 404. Never an error, never a stale grant after the
    final removal."""
    engine, user = world.live.engine, world.users["viewer"].id
    factory = world.env.factory
    key = {"id": str(world.target1)}
    stop = threading.Event()
    outcomes: list[str] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def writer() -> None:
        try:
            for i in range(30):
                role = ("operator", "viewer", "owner")[i % 3]
                with engine.begin() as conn:
                    conn.execute(
                        text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
                        {"p": world.p1, "u": user},
                    )
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT INTO project_members (project_id, user_id, role) "
                            "VALUES (:p, :u, :r)"
                        ),
                        {"p": world.p1, "u": user, "r": role},
                    )
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
                    {"p": world.p1, "u": user},
                )
        except BaseException as exc:  # reported by the main thread
            errors.append(exc)
        finally:
            stop.set()

    def reader() -> None:
        who = _principal(user)
        try:
            while not stop.is_set():
                with factory() as s:
                    try:
                        d = AccessService(ProjectResolver(s)).authorize_project(
                            who, P.SCAN_RUN, R.TARGET, key
                        )
                        result = f"allowed:{d.role}"
                    except ForbiddenError:
                        result = "forbidden"
                    except NotFoundError:
                        result = "not_found"
                with lock:
                    outcomes.append(result)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer)] + [
        threading.Thread(target=reader) for _ in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert outcomes
    assert set(outcomes) <= {"allowed:operator", "allowed:owner", "forbidden", "not_found"}
    with factory() as s, pytest.raises(NotFoundError):
        AccessService(ProjectResolver(s)).authorize_project(
            _principal(user), P.PROJECT_READ, R.TARGET, key
        )


def test_membership_filter_lists_only_member_projects(world: World) -> None:
    with world.env.factory() as s:
        for who, expected in (
            ("owner", {world.p1}),
            ("outsider", {world.p2}),
            ("admin", set()),
            ("nobody", set()),
        ):
            user = world.users[who].id
            ids = set(s.scalars(ProjectResolver.member_projects(user)).all())
            assert ids == expected, who
            visible = {p.id for p in s.scalars(ProjectResolver(s).visible_projects(user)).all()}
            assert visible == expected, who
