"""Phase 9 M4 world: two fully populated projects, A and B, each with a
target, a baseline assessment and scan, findings and evidence, a Phase 5
report, a retest chain A -> B -> C with completed comparisons and a completed
retest report; users with real sessions (no principal override):

    owner_a, operator_a, viewer_a     members of A
    owner_b, operator_b, viewer_b     members of B
    admin                             global admin, member of nothing
    pending                           owner of A who must change their password

Built once per test module (scans run against a 127.0.0.1 lab site) and
removed afterwards.
"""

import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sentinel_analysis import analyze
from sqlalchemy import Engine, text
from sqlalchemy.orm import sessionmaker

from app.api.deps import get_project_service, get_report_service
from app.core.clock import utc_now
from app.core.config import AppEnv, Settings
from app.models.enums import GlobalRole, ProjectRole
from app.schemas.project import ProjectCreate
from app.schemas.report import ReportCreate
from app.services import analysis as analysis_service
from tests.integration.auth_support import Live, _cleanup, auth_settings, bearer, login
from tests.integration.conftest import FrozenClock
from tests.integration.lab_site import LabSite
from tests.integration.scan_support import ScanEnv, lab_actor, purge_project, remove_lab_user
from tests.integration.test_retest_reports import compute, render_worker, request_report
from tests.integration.test_retests import (
    broken_rule,
    complete,
    create_retest,
    mark_false_positive,
    narrow_scope,
    request_comparison,
    run_scan,
    site_a,
    site_b,
    site_c,
    start,
)

MEMBERS = {
    "owner_a": ("a", ProjectRole.OWNER),
    "operator_a": ("a", ProjectRole.OPERATOR),
    "viewer_a": ("a", ProjectRole.VIEWER),
    "pending": ("a", ProjectRole.OWNER),
    "owner_b": ("b", ProjectRole.OWNER),
    "operator_b": ("b", ProjectRole.OPERATOR),
    "viewer_b": ("b", ProjectRole.VIEWER),
}
ACTORS = [*MEMBERS, "admin"]


def first(env: ScanEnv, sql: str, **params: Any) -> Any:
    with env.factory() as s:
        row = s.execute(text(sql), params).first()
    assert row is not None, sql
    return row


def build_chain(env: ScanEnv) -> dict[str, str]:
    """The Phase 6/7 golden chain plus a Phase 5 report, and the ids of one
    instance of every resource type."""
    site_a(env.site)
    target = env.target()
    a = env.started_assessment(target)
    scan_a = run_scan(env, a)
    complete(env, a)
    with env.factory() as s:
        report = (
            get_report_service(s, utc_now)
            .create(
                a,
                ReportCreate.model_validate(
                    {
                        "scan_id": str(scan_a),
                        "kind": "final",
                        "title": "A",
                        "formats": ["json", "html"],
                    }
                ),
                actor=env.actor,
            )
            .id
        )
    assert render_worker(env).run_once()
    mark_false_positive(env, scan_a, "SV-COR-001")
    b = create_retest(env, a, name="Retest B")
    start(env, b)
    site_b(env.site)
    scan_b = run_scan(env, b)
    complete(env, b)
    cmp_b, _ = request_comparison(env, b, scan_b)
    compute(env)
    narrow_scope(env, target, ["/admin", "/error"])
    c = create_retest(env, b, name="Retest C")
    start(env, c)
    site_c(env.site)
    with pytest.MonkeyPatch.context() as m:
        m.setattr(analysis_service, "analyze", lambda obs: analyze(obs, broken_rule("SV-CKE-001")))
        scan_c = run_scan(env, c)
    complete(env, c)
    cmp_c, _ = request_comparison(env, c, scan_c)
    compute(env)
    retest_report, _ = request_report(env, b, cmp_b.id)
    assert render_worker(env).run_once()

    ids: dict[str, Any] = {
        "project": env.project_id,
        "target": target,
        "assessment": a,
        "retest": b,
        "retest_c": c,
        "scan": scan_a,
        "scan_b": scan_b,
        "report": report,
        "comparison": cmp_b.id,
        "comparison_c": cmp_c.id,
        "retest_report": retest_report,
    }
    ids["target_authorization"] = first(
        env, "SELECT id FROM target_authorizations WHERE target_id = :t", t=target
    )[0]
    for name, table in (
        ("scan_log", "scan_logs"),
        ("asset", "assets"),
        ("endpoint", "endpoints"),
        ("evidence", "evidence"),
        ("analysis_run", "analysis_runs"),
    ):
        ids[name] = first(env, f"SELECT id FROM {table} WHERE scan_id = :s", s=scan_a)[0]  # noqa: S608
    open_findings = first(
        env,
        "SELECT array_agg(id ORDER BY id) FROM findings WHERE scan_id = :s AND status = 'open'",
        s=scan_a,
    )[0]
    assert len(open_findings) >= 2
    ids["finding"], ids["finding_2"] = open_findings[0], open_findings[1]
    ids["report_evidence"] = first(
        env, "SELECT evidence_id FROM report_evidence WHERE report_id = :r", r=report
    )[0]
    ids["fingerprint"] = first(
        env, "SELECT fingerprint FROM comparison_records WHERE comparison_id = :c", c=cmp_b.id
    )[0]
    cov = first(
        env,
        "SELECT comparison_id, fingerprint, evidence_id FROM "
        "comparison_coverage_evidence WHERE comparison_id IN (:b, :c)",
        b=cmp_b.id,
        c=cmp_c.id,
    )
    ids["coverage_comparison"], ids["coverage_fingerprint"], ids["coverage_evidence"] = cov
    ev = first(
        env,
        "SELECT role, evidence_id FROM retest_report_evidence WHERE report_id = :r",
        r=retest_report,
    )
    ids["retest_report_evidence_role"], ids["retest_report_evidence"] = ev
    return {k: str(v) for k, v in ids.items()}


@dataclass
class World:
    live: Live
    client: TestClient
    site: LabSite
    env: dict[str, ScanEnv]
    ids: dict[str, dict[str, str]]  # "a" / "b" -> resource name -> id
    created_projects: list[uuid.UUID] = field(default_factory=list)  # removed afterwards
    users: dict[str, Any] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)

    def request(
        self, actor: str | None, method: str, path: str, body: Any = None, **kw: Any
    ) -> Any:
        headers = bearer(self.tokens[actor]) if actor else {}
        headers.update(kw.pop("headers", {}))
        if body is None:
            return self.client.request(method, path, headers=headers, **kw)
        return self.client.request(method, path, headers=headers, json=body, **kw)

    def project(self, side: str) -> uuid.UUID:
        return uuid.UUID(self.ids[side]["project"])

    def add_member(self, side: str, user_id: uuid.UUID, role: ProjectRole) -> None:
        with self.live.engine.begin() as conn:
            conn.execute(
                text("INSERT INTO project_members (project_id, user_id, role) VALUES (:p, :u, :r)"),
                {"p": self.project(side), "u": user_id, "r": role.value},
            )

    def set_role(self, side: str, user_id: uuid.UUID, role: ProjectRole | None) -> None:
        with self.live.engine.begin() as conn:
            if role is None:
                conn.execute(
                    text("DELETE FROM project_members WHERE project_id = :p AND user_id = :u"),
                    {"p": self.project(side), "u": user_id},
                )
            else:
                conn.execute(
                    text(
                        "UPDATE project_members SET role = :r WHERE project_id = :p "
                        "AND user_id = :u"
                    ),
                    {"p": self.project(side), "u": user_id, "r": role.value},
                )


def module_settings() -> Settings:
    return auth_settings(
        Settings(
            app_env=AppEnv.TEST,
            database_url=SecretStr("postgresql+psycopg://test:test@localhost:5432/test"),
            cors_origins=["http://localhost:3000"],
        )
    )


@pytest.fixture(scope="module")
def world(engine: Engine) -> Iterator[World]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    _cleanup(engine)
    live = Live(engine, factory, module_settings(), FrozenClock(utc_now()))
    projects: list[uuid.UUID] = []
    created: list[uuid.UUID] = []
    lab = lab_actor(factory)
    with LabSite() as site:
        try:
            envs: dict[str, ScanEnv] = {}
            for side in ("a", "b"):
                with factory() as s:
                    project = get_project_service(s).create(
                        ProjectCreate(name=f"m4-{side}-{uuid.uuid4()}"), owner_id=None
                    )
                projects.append(project.id)
                envs[side] = ScanEnv(factory, site, project.id, lab)
            ids = {side: build_chain(envs[side]) for side in ("a", "b")}
            client = live.client()
            w = World(live, client, site, envs, ids, created_projects=created)
            for name in ACTORS:
                global_role = GlobalRole.ADMIN if name == "admin" else GlobalRole.USER
                w.users[name] = live.user(
                    f"m4{name.replace('_', '')}{uuid.uuid4().hex[:6]}", role=global_role
                )
            # Owners first: a project with members always keeps an owner.
            for name, (side, project_role) in sorted(
                MEMBERS.items(), key=lambda kv: kv[1][1] != ProjectRole.OWNER
            ):
                w.add_member(side, w.users[name].id, project_role)
            for name, user in w.users.items():
                resp = login(client, user.username)
                assert resp.status_code == 200, resp.text
                w.tokens[name] = resp.json()["token"]
            with engine.begin() as conn:
                conn.execute(
                    text("UPDATE users SET must_change_password = true WHERE id = :u"),
                    {"u": w.users["pending"].id},
                )
            yield w
        finally:
            for client_ in live.clients:
                client_.__exit__(None, None, None)
            for project_id in [*projects, *created]:
                purge_project(factory, project_id)
            remove_lab_user(factory, lab.user_id)
            _cleanup(engine)


def not_found(detail: str) -> dict[str, Any]:
    return {"detail": detail, "code": "not_found", "field": None}


FORBIDDEN = {"detail": "You do not have permission to do this.", "code": "forbidden", "field": None}
PASSWORD_CHANGE = {
    "detail": "Change your password to continue.",
    "code": "password_change_required",
    "field": None,
}


def as_uuid(values: Mapping[str, str], name: str) -> uuid.UUID:
    return uuid.UUID(values[name])
