"""M11: the security posture dashboard (ADR 0015) against real scans,
analyses, comparisons and reports on a 127.0.0.1 lab site."""

import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sentinel_analysis import analyze
from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from app.api.deps import (
    get_finding_service,
    get_principal,
    get_project_service,
    get_report_service,
    get_retest_report_service,
)
from app.core.clock import utc_now
from app.core.config import Settings
from app.db.session import get_session
from app.main import create_app
from app.models import ComparisonRecord, Finding, ProjectMember, Scan, User
from app.models.enums import FindingStatus, GlobalRole, ProjectRole, ScanStatus
from app.repositories.posture import RECENT_SCANS, PostureRepository
from app.schemas.project import ProjectCreate
from app.schemas.report import ReportCreate
from app.schemas.retest_report import RetestReportCreate
from app.services import analysis as analysis_service
from app.services.posture import SEVERITY_ORDER, STATE_ORDER, STATUS_ORDER
from app.worker import WorkerRole
from tests.integration.conftest import principal_for, session_row
from tests.integration.scan_support import ScanEnv, purge_project
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

pytestmark = pytest.mark.integration

API = "/api/v1"
HOSTILE = "<img src=x onerror=alert(1)>‮M11"

Client = Callable[..., tuple[TestClient, uuid.UUID]]


# --- people and projects ------------------------------------------------------------------------


@pytest.fixture
def person(settings: Settings, scan_env: ScanEnv) -> Iterator[Client]:
    """make(role, project=None, global_role=USER) -> (client, user id): a
    committed user, a member of `project` (default: the scan_env project) with
    `role`, or of nothing when role is None."""
    users: list[uuid.UUID] = []
    clients: list[TestClient] = []

    def session() -> Iterator[Session]:
        with scan_env.factory() as s:
            yield s

    def make(
        role: ProjectRole | None,
        project: uuid.UUID | None = None,
        global_role: GlobalRole = GlobalRole.USER,
    ) -> tuple[TestClient, uuid.UUID]:
        with scan_env.factory() as s:
            user = User(
                username=f"m11-{uuid.uuid4().hex[:12]}",
                display_name="M11 person",
                global_role=global_role,
            )
            s.add(user)
            s.flush()
            if role is not None:
                s.add(
                    ProjectMember(
                        project_id=project or scan_env.project_id, user_id=user.id, role=role
                    )
                )
            session_id = session_row(s, user.id)
            s.commit()
            s.expunge(user)
        app = create_app(settings)
        app.dependency_overrides[get_principal] = lambda: principal_for(user, session_id)
        app.dependency_overrides[get_session] = session
        client = TestClient(app)
        client.__enter__()
        users.append(user.id)
        clients.append(client)
        return client, user.id

    yield make
    for client in clients:
        client.__exit__(None, None, None)
    with scan_env.factory() as s:
        # Test cleanup only (users cannot be deleted normally).
        s.execute(text("SET LOCAL session_replication_role = replica"))
        for table, column in (
            ("project_members", "user_id"),
            ("audit_events", "actor_user_id"),
            ("sessions", "user_id"),
            ("users", "id"),
        ):
            s.execute(text(f"DELETE FROM {table} WHERE {column} = ANY(:u)"), {"u": users})  # noqa: S608
        s.commit()


@pytest.fixture
def other_project(scan_env: ScanEnv) -> Iterator[ScanEnv]:
    """A second project on the same lab site, with its own analysed scan."""
    with scan_env.factory() as s:
        project = get_project_service(s).create(
            ProjectCreate(name=f"other-{uuid.uuid4()}"), owner=None
        )
    env = ScanEnv(scan_env.factory, scan_env.site, project.id, scan_env.actor)
    try:
        yield env
    finally:
        purge_project(scan_env.factory, project.id)


def add_member(env: ScanEnv, project_id: uuid.UUID, user_id: uuid.UUID, role: ProjectRole) -> None:
    with env.factory() as s:
        s.add(ProjectMember(project_id=project_id, user_id=user_id, role=role))
        s.commit()


def get(client: TestClient, path: str, **params: Any) -> Any:
    resp = client.get(f"{API}{path}", params=params)
    return resp


# --- independent oracles (ORM rows, not the posture SQL) ---------------------------------------


def expected_counts(env: ScanEnv, scan_ids: list[uuid.UUID]) -> dict[str, Any]:
    with env.factory() as s:
        rows = s.scalars(select(Finding).where(Finding.scan_id.in_(scan_ids))).all()
    active = [f for f in rows if f.status is not FindingStatus.FALSE_POSITIVE]
    severities = Counter(f.severity for f in active)
    statuses = Counter(str(f.status) for f in rows)
    return {
        "total": len(rows),
        "active": len(active),
        "open": sum(1 for f in rows if f.status is FindingStatus.OPEN),
        "by_severity": {s: severities.get(s, 0) for s in SEVERITY_ORDER},
        "by_status": {s: statuses.get(s, 0) for s in STATUS_ORDER},
    }


def expected_states(env: ScanEnv, comparison_id: uuid.UUID) -> dict[str, int]:
    with env.factory() as s:
        rows = s.scalars(
            select(ComparisonRecord.state).where(ComparisonRecord.comparison_id == comparison_id)
        ).all()
    states = Counter(str(state) for state in rows)
    return {state: states.get(state, 0) for state in STATE_ORDER}


def audit_count(env: ScanEnv) -> int:
    with env.factory() as s:
        return int(s.scalar(text("SELECT count(*) FROM audit_events")))


@contextmanager
def counting_queries(env: ScanEnv) -> Iterator[list[str]]:
    statements: list[str] = []
    engine = env.factory.kw["bind"]

    def record(*args: Any) -> None:
        statements.append(str(args[2]))

    event.listen(engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", record)


def triage(env: ScanEnv, scan_id: uuid.UUID, statuses: list[FindingStatus]) -> None:
    """Give the scan's first findings these triage statuses (in rule order)."""
    with env.factory() as s:
        findings = s.scalars(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.rule_id, Finding.id)
        ).all()
        service = get_finding_service(s, utc_now)
        for finding, status in zip(findings, statuses, strict=False):
            service.triage(finding.id, status, "m11 triage", actor=env.actor)


# --- authorization -------------------------------------------------------------------------------


def test_project_posture_follows_project_visibility(
    scan_env: ScanEnv, person: Client, settings: Settings
) -> None:
    owner, _ = person(ProjectRole.OWNER)
    viewer, _ = person(ProjectRole.VIEWER)
    outsider, _ = person(None)
    admin, _ = person(None, global_role=GlobalRole.ADMIN)
    pid = scan_env.project_id
    for client, role in ((owner, "owner"), (viewer, "viewer")):
        resp = get(client, f"/projects/{pid}/posture")
        assert resp.status_code == 200, resp.text
        assert resp.json()["role"] == role
        assert resp.json()["project_id"] == str(pid)
    for client in (outsider, admin):
        assert get(client, f"/projects/{pid}/posture").status_code == 404
        assert get(client, "/posture").json() == []
    for bad in ("not-a-uuid", str(uuid.uuid4())):
        assert get(owner, f"/projects/{bad}/posture").status_code == 404
    anonymous = TestClient(create_app(settings))
    assert anonymous.get(f"{API}/projects/{pid}/posture").status_code == 401
    assert anonymous.get(f"{API}/posture").status_code == 401
    # Reading posture is not security history.
    before = audit_count(scan_env)
    get(owner, f"/projects/{pid}/posture")
    get(owner, "/posture")
    assert audit_count(scan_env) == before


def test_an_empty_project_and_an_empty_membership(scan_env: ScanEnv, person: Client) -> None:
    owner, _ = person(ProjectRole.OWNER)
    target = scan_env.target(name="Untouched")
    body = get(owner, f"/projects/{scan_env.project_id}/posture").json()
    assert body["findings"]["total"] == 0
    assert body["findings"]["by_severity"] == dict.fromkeys(SEVERITY_ORDER, 0)
    assert body["findings"]["by_status"] == dict.fromkeys(STATUS_ORDER, 0)
    assert body["targets"] == [
        {
            "target_id": str(target),
            "target_name": "Untouched",
            "latest_scan": None,
            "findings": body["findings"],
        }
    ]
    assert body["targets_truncated"] is False
    assert body["latest_comparison"] is None
    assert body["latest_report"] is None and body["latest_retest_report"] is None
    assert body["recent_scans"] == []
    nobody, _ = person(None)
    assert get(nobody, "/posture").json() == []


# --- latest analysed scan ------------------------------------------------------------------------


def test_the_latest_analysed_scan_is_selected(scan_env: ScanEnv, person: Client) -> None:
    owner, _ = person(ProjectRole.OWNER)
    site_a(scan_env.site)
    target = scan_env.target()
    a = scan_env.started_assessment(target)
    older = run_scan(scan_env, a)
    newer = run_scan(scan_env, a)
    # Completed, but its analysis has not run: never the posture.
    unanalysed = scan_env.scan(a)
    worker = scan_env.worker(role=WorkerRole.SCANS)
    claimed = worker.claim()
    assert claimed is not None and claimed.scan_id == unanalysed
    worker.execute(claimed)
    # Cancelled: never the posture either.
    cancelled = scan_env.scan(a)
    scan_env.cancel_scan(cancelled)
    assert scan_env.get_scan(unanalysed).status is ScanStatus.COMPLETED
    assert scan_env.get_scan(cancelled).status is ScanStatus.CANCELLED

    body = get(owner, f"/projects/{scan_env.project_id}/posture").json()
    (row,) = body["targets"]
    assert row["latest_scan"]["scan_id"] == str(newer)
    assert row["findings"] == expected_counts(scan_env, [newer])
    assert body["findings"] == expected_counts(scan_env, [newer])
    summary = get(owner, "/posture").json()[0]
    assert summary["targets_with_analysed_scan"] == 1
    assert summary["findings"] == body["findings"]
    assert summary["latest_scan_finished_at"] == row["latest_scan"]["finished_at"]

    # Equal finish times: the larger id wins, every time.
    with scan_env.factory() as s:
        s.execute(text("SET LOCAL session_replication_role = replica"))
        s.execute(
            text("UPDATE scans SET finished_at = (SELECT finished_at FROM scans WHERE id = :n) "
                 "WHERE id = :o"),
            {"n": newer, "o": older},
        )  # fmt: skip
        s.commit()
    winner = str(max(older, newer))
    for _ in range(3):
        again = get(owner, f"/projects/{scan_env.project_id}/posture").json()
        assert again["targets"][0]["latest_scan"]["scan_id"] == winner

    # Recent scans: newest first, bounded, findings only for analysed scans.
    recent = body["recent_scans"]
    assert [r["scan_id"] for r in recent] == [str(x) for x in (cancelled, unanalysed, newer, older)]
    assert [r["analysed"] for r in recent] == [False, False, True, True]
    assert recent[0]["findings_total"] is None and recent[1]["findings_total"] is None
    assert recent[2]["findings_total"] == expected_counts(scan_env, [newer])["total"]


def test_recent_scan_history_is_bounded(scan_env: ScanEnv, person: Client) -> None:
    owner, _ = person(ProjectRole.OWNER)
    target = scan_env.target()
    a = scan_env.started_assessment(target)
    made = []
    for _ in range(RECENT_SCANS + 3):
        scan_id = scan_env.scan(a)
        scan_env.cancel_scan(scan_id)
        made.append(scan_id)
    with scan_env.factory() as s:
        order = [
            str(x)
            for x in s.scalars(
                select(Scan.id)
                .where(Scan.id.in_(made))
                .order_by(Scan.created_at.desc(), Scan.id.desc())
            )
        ]
    recent = get(owner, f"/projects/{scan_env.project_id}/posture").json()["recent_scans"]
    assert len(recent) == RECENT_SCANS
    assert [r["scan_id"] for r in recent] == order[:RECENT_SCANS]


# --- finding counts ------------------------------------------------------------------------------


def test_counts_follow_persisted_findings_and_triage(scan_env: ScanEnv, person: Client) -> None:
    owner, _ = person(ProjectRole.OWNER)
    site_a(scan_env.site)
    t1, t2 = scan_env.target(name="One"), scan_env.target(name="Two")
    scans = []
    for target in (t1, t2):
        a = scan_env.started_assessment(target)
        scans.append(run_scan(scan_env, a))
    triage(
        scan_env,
        scans[0],
        [
            FindingStatus.CONFIRMED,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.FALSE_POSITIVE,
        ],
    )
    body = get(owner, f"/projects/{scan_env.project_id}/posture").json()
    expected = expected_counts(scan_env, scans)
    assert body["findings"] == expected
    assert expected["by_status"]["false_positive"] == 2
    assert expected["by_status"]["confirmed"] == 1 and expected["by_status"]["accepted_risk"] == 1
    # Open is exactly triage status "open"; active excludes only false positives.
    assert expected["open"] == expected["by_status"]["open"]
    assert expected["active"] == expected["total"] - 2
    assert sum(expected["by_severity"].values()) == expected["active"]
    by_target = {t["target_name"]: t["findings"] for t in body["targets"]}
    assert by_target == {
        "One": expected_counts(scan_env, [scans[0]]),
        "Two": expected_counts(scan_env, [scans[1]]),
    }
    assert list(body["findings"]["by_severity"]) == list(SEVERITY_ORDER)
    assert list(body["findings"]["by_status"]) == list(STATUS_ORDER)


def test_status_order_matches_the_triage_enum() -> None:
    assert set(STATUS_ORDER) == {s.value for s in FindingStatus}


# --- cross-project isolation ---------------------------------------------------------------------


def test_nothing_crosses_project_boundaries(
    scan_env: ScanEnv, other_project: ScanEnv, person: Client
) -> None:
    site_a(scan_env.site)
    mine = run_scan(scan_env, scan_env.started_assessment(scan_env.target(name="Mine")))
    hidden_name = f"Hidden {HOSTILE}"
    theirs = run_scan(
        other_project, other_project.started_assessment(other_project.target(name=hidden_name))
    )
    with scan_env.factory() as s:
        s.execute(
            text("UPDATE projects SET name = :n WHERE id = :p"),
            {"n": f"Secret {HOSTILE}", "p": other_project.project_id},
        )
        s.commit()
    owner, _ = person(ProjectRole.OWNER)
    stranger, stranger_id = person(ProjectRole.OWNER, project=other_project.project_id)
    both, both_id = person(ProjectRole.VIEWER)
    add_member(scan_env, other_project.project_id, both_id, ProjectRole.VIEWER)

    # Naming the other project in the request changes nothing: the overview
    # has no project parameter, membership alone decides.
    overview = get(owner, "/posture", project_id=str(other_project.project_id))
    assert [p["project_id"] for p in overview.json()] == [str(scan_env.project_id)]
    assert overview.json()[0]["findings"] == expected_counts(scan_env, [mine])
    for secret in ("Secret", "Hidden", str(other_project.project_id), str(theirs)):
        assert secret not in overview.text
    project = get(owner, f"/projects/{scan_env.project_id}/posture")
    assert project.json()["findings"] == expected_counts(scan_env, [mine])
    for secret in ("Secret", "Hidden", str(theirs)):
        assert secret not in project.text
    assert get(owner, f"/projects/{other_project.project_id}/posture").status_code == 404
    assert get(stranger, f"/projects/{scan_env.project_id}/posture").status_code == 404
    # The repository itself counts only what it is asked about (defence in
    # depth: the service never sees another scan's or project's groups).
    with scan_env.factory() as s:
        repo = PostureRepository(s)
        assert {g.scan_id for g in repo.finding_counts([mine])} == {mine}
        assert repo.finding_counts([]) == []
        assert {x.project_id for x in repo.latest_scans([scan_env.project_id])} == {
            scan_env.project_id
        }
        assert repo.comparison_state_counts([uuid.uuid4()]) == []

    # A member of both sees both, each with its own counts; ids are never trusted
    # from the request (there is no parameter to name a project).
    rows = {p["project_id"]: p for p in get(both, "/posture", project_id=str(uuid.uuid4())).json()}
    assert set(rows) == {str(scan_env.project_id), str(other_project.project_id)}
    assert rows[str(other_project.project_id)]["findings"] == expected_counts(
        other_project, [theirs]
    )
    assert rows[str(other_project.project_id)]["project_name"] == f"Secret {HOSTILE}"
    assert rows[str(scan_env.project_id)]["role"] == "viewer"
    # Pagination is the API's own (GET /projects order).
    assert len(get(both, "/posture", limit=1).json()) == 1
    assert get(both, "/posture", limit=1, offset=2).json() == []
    assert get(both, "/posture", limit=101).status_code == 422
    del stranger_id


def test_the_overview_uses_a_fixed_number_of_queries(
    scan_env: ScanEnv, other_project: ScanEnv, person: Client
) -> None:
    site_a(scan_env.site)
    run_scan(scan_env, scan_env.started_assessment(scan_env.target()))
    run_scan(other_project, other_project.started_assessment(other_project.target()))
    client, user = person(ProjectRole.OWNER)
    with counting_queries(scan_env) as one:
        assert len(get(client, "/posture").json()) == 1
    add_member(scan_env, other_project.project_id, user, ProjectRole.OWNER)
    with counting_queries(scan_env) as two:
        first = get(client, "/posture").json()
        assert len(first) == 2
    assert len(two) == len(one)  # no per-project queries
    assert get(client, "/posture").json() == first  # deterministic
    with counting_queries(scan_env) as project_queries:
        get(client, f"/projects/{scan_env.project_id}/posture")
    assert len(project_queries) <= 12


# --- retests and reports: the A -> B -> C chain ---------------------------------------------------


def test_retest_outcome_and_reports_follow_persisted_records(
    scan_env: ScanEnv, person: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = scan_env
    owner, _ = person(ProjectRole.OWNER)
    viewer, _ = person(ProjectRole.VIEWER)
    pid = env.project_id

    site_a(env.site)
    target = env.target()
    a = env.started_assessment(target)
    scan_a = run_scan(env, a)
    complete(env, a)
    with env.factory() as s:
        report_a = get_report_service(s, utc_now).create(
            a,
            ReportCreate.model_validate(
                {"scan_id": str(scan_a), "kind": "final", "title": f"A {HOSTILE}",
                 "formats": ["json"]}
            ),
            actor=env.actor,
        ).id  # fmt: skip
    assert env.worker(role=WorkerRole.REPORTS).run_once()
    body = get(owner, f"/projects/{pid}/posture").json()
    assert body["latest_comparison"] is None
    assert body["latest_report"]["report_id"] == str(report_a)
    assert body["latest_report"]["title"] == f"A {HOSTILE}"
    assert body["latest_retest_report"] is None

    mark_false_positive(env, scan_a, "SV-COR-001")
    b = create_retest(env, a, name="Retest B")
    start(env, b)
    site_b(env.site)
    scan_b = run_scan(env, b)
    complete(env, b)
    comparison_b, _ = request_comparison(env, b, scan_b)
    assert env.worker(role=WorkerRole.SCANS).run_once()

    states_b = expected_states(env, comparison_b.id)
    after_b = get(viewer, f"/projects/{pid}/posture").json()
    assert after_b["latest_comparison"]["comparison_id"] == str(comparison_b.id)
    assert after_b["latest_comparison"]["by_state"] == states_b
    assert after_b["latest_comparison"]["current_scan_id"] == str(scan_b)
    assert {k for k, v in states_b.items() if v} == {
        "new", "still_open", "unchanged", "fixed", "dismissed",
    }  # fmt: skip
    # The posture is the retest scan now (the target's latest analysed scan).
    assert after_b["targets"][0]["latest_scan"]["scan_id"] == str(scan_b)
    assert after_b["findings"] == expected_counts(env, [scan_b])

    with env.factory() as s:
        retest_report, _ = get_retest_report_service(s, utc_now).create(
            b,
            comparison_b.id,
            RetestReportCreate.model_validate({"title": "Retest B report", "formats": ["json"]}),
            actor=env.actor,
        )
        retest_report_id = retest_report.id
    assert env.worker(role=WorkerRole.REPORTS).run_once()

    narrow_scope(env, target, ["/admin", "/error"])
    c = create_retest(env, b, name="Retest C")
    start(env, c)
    site_c(env.site)
    with monkeypatch.context() as m:
        m.setattr(analysis_service, "analyze", lambda obs: analyze(obs, broken_rule("SV-CKE-001")))
        scan_c = run_scan(env, c)
    complete(env, c)
    comparison_c, _ = request_comparison(env, c, scan_c)
    assert env.worker(role=WorkerRole.SCANS).run_once()

    states_c = expected_states(env, comparison_c.id)
    after_c = get(owner, f"/projects/{pid}/posture").json()
    assert after_c["latest_comparison"]["comparison_id"] == str(comparison_c.id)
    assert after_c["latest_comparison"]["by_state"] == states_c
    assert {k for k, v in states_c.items() if v} == {
        "reopened", "not_comparable", "not_retested", "unchanged",
    }  # fmt: skip
    # Across B and C every cmp-1 state appears, each counted from its records.
    assert {k for k, v in states_b.items() if v} | {k for k, v in states_c.items() if v} == set(
        STATE_ORDER
    )
    assert list(after_c["latest_comparison"]["by_state"]) == list(STATE_ORDER)
    # Records, not findings: the counts equal the stored records exactly, even
    # though scan C has fewer findings than records.
    with env.factory() as s:
        records = s.scalar(
            select(func.count()).where(ComparisonRecord.comparison_id == comparison_c.id)
        )
    assert sum(after_c["latest_comparison"]["by_state"].values()) == records
    # The repository counts only the comparison it is asked about, though B's
    # records exist too.
    with env.factory() as s:
        groups = PostureRepository(s).comparison_state_counts([comparison_c.id])
    assert {g.comparison_id for g in groups} == {comparison_c.id}
    assert sum(g.count for g in groups) == records
    assert after_c["findings"]["total"] != records

    assert after_c["latest_report"]["report_id"] == str(report_a)
    assert after_c["latest_retest_report"]["report_id"] == str(retest_report_id)
    overview = get(owner, "/posture").json()[0]
    assert overview["latest_comparison"] == after_c["latest_comparison"]
    assert overview["latest_report"] == after_c["latest_report"]
    assert overview["latest_retest_report"] == after_c["latest_retest_report"]
    assert [r["scan_id"] for r in after_c["recent_scans"]][:3] == [
        str(scan_c), str(scan_b), str(scan_a),
    ]  # fmt: skip
