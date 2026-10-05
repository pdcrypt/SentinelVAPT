"""Support for worker and scan tests that need committed data.

The worker opens its own sessions, so these tests cannot use the rolled-back
per-test transaction. Each test gets a uniquely named project and everything
under it is deleted afterwards.
"""

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import (
    get_assessment_service,
    get_project_service,
    get_scan_service,
    get_target_service,
)
from app.core.actors import UserActor
from app.core.clock import utc_now
from app.models import Scan, User
from app.schemas.assessment import AssessmentCreate
from app.schemas.project import ProjectCreate
from app.schemas.scan import ScanCreate
from app.schemas.target import TargetCreate, TargetUpdate
from app.worker import ScannerRunner, Worker
from sentinel_scanner import (
    CancellationToken,
    DiscoveryConfig,
    DiscoveryResult,
    ScanLimits,
    run_discovery,
)
from sentinel_scanner.grant import ScanGrant
from sentinel_scanner.models import ScanEvent
from sentinel_scanner.resolver import StaticResolver
from tests.integration.lab_site import LabSite

RESOLVER = StaticResolver({"lab.test": ["127.0.0.1"]})


def lab_runner(
    *,
    hook: Callable[[ScanGrant, DiscoveryConfig], None] | None = None,
) -> ScannerRunner:
    """The real scanner, resolving lab.test to 127.0.0.1. Only the request rate
    is raised for test speed; every other limit stays at the scanner default."""

    def run(
        grant: ScanGrant,
        config: DiscoveryConfig,
        *,
        cancel: CancellationToken,
        on_event: Callable[[ScanEvent], None],
    ) -> DiscoveryResult:
        if hook is not None:
            hook(grant, config)
        fast = DiscoveryConfig(
            limits=ScanLimits(max_requests_per_second=20),
            crawl=config.crawl,
            verify_tls=config.verify_tls,
        )
        return run_discovery(grant, fast, cancel=cancel, on_event=on_event, resolver=RESOLVER)

    return run


def authorization(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "authorized_by": "Lab Owner",
        "reference": "LAB-SCAN",
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(hours=1)).isoformat(),
        "acknowledge": True,
    }
    values.update(overrides)
    return values


@dataclass
class ScanEnv:
    """Creates committed projects/targets/assessments/scans through the real
    services, and builds workers bound to the test database."""

    factory: sessionmaker[Session]
    site: LabSite
    project_id: uuid.UUID
    actor: UserActor  # the lab user every human action of these helpers is attributed to

    def target(self, *, name: str | None = None, **auth: Any) -> uuid.UUID:
        name = name or f"Lab {uuid.uuid4().hex[:8]}"
        with self.factory() as s:
            created = get_target_service(s, utc_now).create(
                self.project_id,
                TargetCreate.model_validate(
                    {
                        "name": name,
                        "base_url": self.site.url("/"),
                        "environment": "local_lab",
                        "in_scope_hosts": ["lab.test"],
                        "excluded_paths": ["/admin"],
                        "authorization": authorization(**auth),
                    }
                ),
                actor=self.actor,
            )
            return created.id

    def started_assessment(self, target_id: uuid.UUID) -> uuid.UUID:
        with self.factory() as s:
            service = get_assessment_service(s, utc_now)
            assessment = service.create(
                target_id, AssessmentCreate(name="Assessment"), actor=self.actor
            )
            service.start(assessment.id, actor=self.actor)
            return assessment.id

    def scan(self, assessment_id: uuid.UUID, *, allow_untrusted_tls: bool = False) -> uuid.UUID:
        with self.factory() as s:
            scan = get_scan_service(s, utc_now).create(
                assessment_id,
                ScanCreate(allow_untrusted_tls=allow_untrusted_tls),
                actor=self.actor,
            )
            return scan.id

    def queued_scan(self) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        target_id = self.target()
        assessment_id = self.started_assessment(target_id)
        return target_id, assessment_id, self.scan(assessment_id)

    def reauthorize(self, target_id: uuid.UUID, **auth: Any) -> None:
        with self.factory() as s:
            get_target_service(s, utc_now).update(
                target_id,
                TargetUpdate.model_validate({"authorization": authorization(**auth)}),
                actor=self.actor,
            )

    def cancel_assessment(self, assessment_id: uuid.UUID) -> None:
        with self.factory() as s:
            get_assessment_service(s, utc_now).cancel(assessment_id, actor=self.actor)

    def cancel_scan(self, scan_id: uuid.UUID) -> None:
        with self.factory() as s:
            get_scan_service(s, utc_now).cancel(scan_id, actor=self.actor)

    def get_scan(self, scan_id: uuid.UUID) -> Scan:
        with self.factory() as s:
            scan = s.get(Scan, scan_id)
            assert scan is not None
            s.expunge(scan)
            return scan

    def count(self, table: str, scan_id: uuid.UUID) -> int:
        column = (
            "endpoint_id IN (SELECT id FROM endpoints WHERE scan_id = :s)"
            if (table == "endpoint_cookies")
            else "scan_id = :s"
        )
        with self.factory() as s:
            # Table names come from the tests themselves, never from input.
            sql = f"SELECT count(*) FROM {table} WHERE {column}"  # noqa: S608
            return int(s.scalar(text(sql), {"s": scan_id}))

    def all_text(self, scan_id: uuid.UUID) -> str:
        """Every persisted row of this scan, as JSON text (for secret checks)."""
        queries = [
            "SELECT row_to_json(x)::text FROM scans x WHERE id = :s",
            "SELECT row_to_json(x)::text FROM scan_logs x WHERE scan_id = :s",
            "SELECT row_to_json(x)::text FROM assets x WHERE scan_id = :s",
            "SELECT row_to_json(x)::text FROM endpoints x WHERE scan_id = :s",
            "SELECT row_to_json(x)::text FROM evidence x WHERE scan_id = :s",
            "SELECT row_to_json(c)::text FROM endpoint_cookies c "
            "JOIN endpoints e ON e.id = c.endpoint_id WHERE e.scan_id = :s",
            "SELECT row_to_json(x)::text FROM analysis_runs x WHERE scan_id = :s",
            "SELECT row_to_json(x)::text FROM findings x WHERE scan_id = :s",
            "SELECT row_to_json(h)::text FROM finding_status_changes h "
            "JOIN findings f ON f.id = h.finding_id WHERE f.scan_id = :s",
        ]
        with self.factory() as s:
            return "\n".join(
                row for q in queries for row in s.scalars(text(q), {"s": scan_id}).all()
            )

    def worker(self, name: str = "worker-a", **kwargs: Any) -> Worker:
        kwargs.setdefault("runner", lab_runner())
        kwargs.setdefault("heartbeat_interval", 60.0)
        return Worker(self.factory, worker_id=name, **kwargs)


def purge_project(factory: sessionmaker[Session], project_id: uuid.UUID) -> None:
    scans = (
        "SELECT s.id FROM scans s JOIN assessments a ON a.id = s.assessment_id "
        "JOIN targets t ON t.id = a.target_id WHERE t.project_id = :p"
    )
    with factory() as s:
        # Reports, comparisons and their links are permanent records, and a
        # retest's links to its parent are immutable: the database refuses to
        # delete or clear them (ADR 0010, 0011). Test cleanup alone bypasses
        # those triggers, for this transaction only, with the superuser-only
        # replication role; production code has no such path. The role is reset
        # before anything that relies on ON DELETE CASCADE (which replica mode
        # would also skip).
        s.execute(text("SET LOCAL session_replication_role = replica"))
        for table in ("report_artifacts", "report_findings", "report_evidence"):
            s.execute(
                text(  # table names are constants of this function
                    f"DELETE FROM {table} WHERE report_id IN "  # noqa: S608
                    f"(SELECT id FROM reports WHERE scan_id IN ({scans}))"
                ),
                {"p": project_id},
            )
        s.execute(text(f"DELETE FROM reports WHERE scan_id IN ({scans})"), {"p": project_id})  # noqa: S608  # constant SQL
        retest_reports = f"SELECT id FROM retest_reports WHERE current_scan_id IN ({scans})"  # noqa: S608
        for table in ("retest_report_artifacts", "retest_report_evidence"):
            s.execute(
                text(f"DELETE FROM {table} WHERE report_id IN ({retest_reports})"),  # noqa: S608
                {"p": project_id},
            )
        s.execute(
            text(f"DELETE FROM retest_reports WHERE id IN ({retest_reports})"),  # noqa: S608
            {"p": project_id},
        )
        comparisons = f"SELECT id FROM comparisons WHERE current_scan_id IN ({scans})"  # noqa: S608
        for table in ("comparison_coverage_evidence", "comparison_records"):
            s.execute(
                text(f"DELETE FROM {table} WHERE comparison_id IN ({comparisons})"),  # noqa: S608
                {"p": project_id},
            )
        s.execute(text(f"DELETE FROM comparisons WHERE id IN ({comparisons})"), {"p": project_id})  # noqa: S608  # constant SQL
        s.execute(
            text(
                "UPDATE assessments SET retest_of_assessment_id = NULL, baseline_scan_id = NULL "
                "WHERE target_id IN (SELECT id FROM targets WHERE project_id = :p)"
            ),
            {"p": project_id},
        )
        s.execute(text("SET LOCAL session_replication_role = origin"))
        # Findings and analysis runs RESTRICT scan deletion (ADR 0009); rule
        # versions are global and immutable, so they stay.
        s.execute(text(f"DELETE FROM findings WHERE scan_id IN ({scans})"), {"p": project_id})  # noqa: S608  # constant SQL
        s.execute(text(f"DELETE FROM analysis_runs WHERE scan_id IN ({scans})"), {"p": project_id})  # noqa: S608  # constant SQL
        s.execute(
            text(
                "DELETE FROM scans WHERE assessment_id IN (SELECT a.id FROM assessments a "
                "JOIN targets t ON t.id = a.target_id WHERE t.project_id = :p)"
            ),
            {"p": project_id},
        )
        s.execute(
            text(
                "DELETE FROM assessments WHERE target_id IN "
                "(SELECT id FROM targets WHERE project_id = :p)"
            ),
            {"p": project_id},
        )
        s.execute(text("DELETE FROM targets WHERE project_id = :p"), {"p": project_id})
        s.execute(text("DELETE FROM projects WHERE id = :p"), {"p": project_id})
        # The project's audit trail is append-only; test cleanup alone removes it.
        s.execute(text("SET LOCAL session_replication_role = replica"))
        s.execute(text("DELETE FROM audit_events WHERE project_id = :p"), {"p": project_id})
        s.commit()


def lab_actor(factory: sessionmaker[Session], display_name: str = "Tester") -> UserActor:
    """A committed platform user standing for the human behind the helpers'
    actions (Phase 9 M5: every acknowledgment, scan request, triage and report
    request names its user). Removed with remove_lab_user."""
    with factory() as s:
        user = User(username=f"lab-{uuid.uuid4().hex[:12]}", display_name=display_name)
        s.add(user)
        s.commit()
        return UserActor(user_id=user.id, label=user.display_name)


def remove_lab_user(factory: sessionmaker[Session], user_id: uuid.UUID) -> None:
    """Test cleanup only, after the user's projects are purged: users cannot be
    deleted normally (ADR 0014), so this bypasses the triggers."""
    with factory() as s:
        s.execute(text("SET LOCAL session_replication_role = replica"))
        for table, column in (
            ("finding_status_changes", "changed_by_user_id"),
            ("project_members", "user_id"),
            ("audit_events", "actor_user_id"),
        ):
            s.execute(text(f"DELETE FROM {table} WHERE {column} = :u"), {"u": user_id})  # noqa: S608
        s.execute(text("DELETE FROM users WHERE id = :u"), {"u": user_id})
        s.commit()


@pytest.fixture
def scan_env(engine: Engine) -> Iterator[ScanEnv]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    actor = lab_actor(factory)
    with factory() as s:
        project = get_project_service(s).create(
            ProjectCreate(name=f"scan-{uuid.uuid4()}"), owner=None
        )
    with LabSite() as site:
        site.html(
            "/",
            '<title>Home</title><a href="/about">About</a><a href="/admin">Admin</a>'
            '<a href="/logout">Logout</a><form action="/login" method="post"></form>',
            headers=[
                ("Server", "nginx/1.25"),
                ("Set-Cookie", "SESSIONID=LAB-SESSION-SECRET; Path=/; HttpOnly"),
            ],
        )
        site.html(
            "/about",
            '<title>About</title><input type="hidden" name="csrf_token" value="LAB-CSRF-SECRET">',
        )
        try:
            yield ScanEnv(factory, site, project.id, actor)
        finally:
            purge_project(factory, project.id)
            remove_lab_user(factory, actor.user_id)
