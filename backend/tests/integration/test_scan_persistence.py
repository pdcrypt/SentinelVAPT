"""DiscoveryResult -> normalized rows: mapping, determinism, idempotency."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from app.repositories import ScanResultRepository
from app.services.scan_results import (
    LogEntry,
    endpoint_fingerprint,
    persist_discovery_result,
)
from sentinel_scanner.models import (
    CookieObservation,
    DiscoveredEndpoint,
    DiscoveryResult,
    EndpointSource,
    EventLevel,
    Evidence,
    PageObservation,
    ScanEvent,
    SkipReason,
    StopReason,
    TechHint,
)
from tests.integration.conftest import (
    create_assessment,
    create_project,
    create_target,
    open_session,
)

pytestmark = pytest.mark.integration

AT = datetime(2026, 10, 4, 12, tzinfo=UTC)
BASE = "http://lab.test:8080/"


def _evidence(url: str, method: str = "GET", status: int = 200) -> Evidence:
    return Evidence(
        id=str(uuid.uuid4()),
        method=method,
        url=url,
        request_headers=[("Host", "lab.test:8080"), ("User-Agent", "SentinelVAPT/0.2.0")],
        status=status,
        response_headers=[("Set-Cookie", "SESSIONID=[REDACTED]; Path=/; HttpOnly; SameSite=Lax")],
        body_excerpt="<title>Home</title>",
        body_sha256="0" * 64,
        body_bytes_captured=20,
        truncated=False,
        peer="127.0.0.1",
        redactions=["response_header:Set-Cookie"],
    )


def _page(url: str, evidence: Evidence, method: str = "GET", **extra: Any) -> PageObservation:
    values: dict[str, Any] = {
        "url": url,
        "method": method,
        "status": evidence.status,
        "depth": 0,
        "content_type": "text/html",
        "declared_length": 20,
        "body_bytes": 20,
        "truncated": False,
        "elapsed_ms": 3,
        "title": "Home",
        "redirect_location": None,
        "allowed_methods": None,
        "cookies": [],
        "hints": [],
        "evidence_id": evidence.id,
    }
    values.update(extra)
    return PageObservation(**values)


def sample_result() -> DiscoveryResult:
    """A small but representative result, as the scanner returns it (redacted)."""
    home_ev, options_ev, about_ev = (
        _evidence(BASE),
        _evidence(BASE, "OPTIONS"),
        _evidence(BASE + "about"),
    )
    cookie = CookieObservation("SESSIONID", False, True, "Lax", None, "/", False)
    return DiscoveryResult(
        target_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        authorization_id=uuid.uuid4(),
        authorization_version=1,
        started_at=AT,
        finished_at=AT,
        stop_reason=StopReason.COMPLETED,
        requests_sent=3,
        pages=[
            _page(
                BASE, home_ev, cookies=[cookie, cookie], hints=[TechHint("header:server", "nginx")]
            ),
            _page(BASE, options_ev, method="OPTIONS", allowed_methods=["GET", "OPTIONS"]),
            _page(BASE + "about", about_ev, depth=1, title="About"),
        ],
        endpoints=[
            DiscoveredEndpoint(BASE, "GET", EndpointSource.BASE, None, True),
            DiscoveredEndpoint(BASE + "about", "GET", EndpointSource.LINK, BASE, True),
            DiscoveredEndpoint(
                BASE + "logout", "GET", EndpointSource.LINK, BASE, False, SkipReason.RISKY_PATH
            ),
            DiscoveredEndpoint(
                BASE + "login",
                "POST",
                EndpointSource.FORM,
                BASE,
                False,
                SkipReason.FORM_NOT_SUBMITTED,
            ),
            DiscoveredEndpoint(
                "http://evil.test/",
                "GET",
                EndpointSource.LINK,
                BASE,
                False,
                SkipReason.OUT_OF_SCOPE,
            ),
            DiscoveredEndpoint(
                BASE + "item?id=1&token=[REDACTED]",
                "GET",
                EndpointSource.LINK,
                BASE,
                False,
                SkipReason.QUERY_STRING,
                ["id", "token"],
            ),
        ],
        events=[
            ScanEvent(AT, EventLevel.INFO, "scan_started", "discovery scan started"),
            ScanEvent(AT, EventLevel.BLOCKED, "host_out_of_scope", "blocked", "http://evil.test/"),
            ScanEvent(AT, EventLevel.INFO, "scan_finished", "done"),
        ],
        evidence=[home_ev, options_ev, about_ev],
    )


@pytest.fixture
def scan_id(api: Any, db_connection: Connection) -> uuid.UUID:
    project = create_project(api)
    target = create_target(api, project["id"])
    assessment = create_assessment(api, target["id"])
    api.post(f"/api/v1/assessments/{assessment['id']}/start")
    resp = api.post(f"/api/v1/assessments/{assessment['id']}/scans")
    assert resp.status_code == 201, resp.text
    return uuid.UUID(resp.json()["id"])


def _counts(session: Session, scan_id: uuid.UUID) -> dict[str, int]:
    counts = {}
    for table in ("scan_logs", "assets", "endpoints", "evidence"):
        counts[table] = session.scalar(
            text(f"SELECT count(*) FROM {table} WHERE scan_id = :s"),  # noqa: S608  # fixed names
            {"s": scan_id},
        )
    counts["endpoint_cookies"] = session.scalar(
        text(
            "SELECT count(*) FROM endpoint_cookies WHERE endpoint_id IN "
            "(SELECT id FROM endpoints WHERE scan_id = :s)"
        ),
        {"s": scan_id},
    )
    return counts


def test_result_is_normalized(db_connection: Connection, scan_id: uuid.UUID) -> None:
    result = sample_result()
    with open_session(db_connection) as session:
        repo = ScanResultRepository(session)
        before = [LogEntry(AT, "info", "scan_claimed", "claimed")]
        counts = persist_discovery_result(repo, scan_id, result, before=before)
        session.commit()

        assert (counts.logs, counts.assets, counts.endpoints, counts.evidence) == (4, 1, 7, 3)
        assert _counts(session, scan_id) == {
            "scan_logs": 4,
            "assets": 1,
            "endpoints": 7,  # 6 discovered + the OPTIONS probe
            "evidence": 3,
            "endpoint_cookies": 1,  # duplicate cookie on one response stored once
        }
        codes = session.scalars(
            text("SELECT code FROM scan_logs WHERE scan_id = :s ORDER BY sequence"), {"s": scan_id}
        ).all()
        assert list(codes) == ["scan_claimed", "scan_started", "host_out_of_scope", "scan_finished"]

        rows = {
            (r.method, r.url): r
            for r in session.execute(
                text("SELECT * FROM endpoints WHERE scan_id = :s"), {"s": scan_id}
            )
        }
        home = rows[("GET", BASE)]
        assert (home.fetched, home.status_code, home.title, home.asset_id is not None) == (
            True,
            200,
            "Home",
            True,
        )
        assert home.fingerprint == endpoint_fingerprint("GET", BASE)
        assert home.tech_hints == [{"source": "header:server", "value": "nginx"}]
        probe = rows[("OPTIONS", BASE)]
        assert (probe.source, probe.allowed_methods) == ("probe", ["GET", "OPTIONS"])
        external = rows[("GET", "http://evil.test/")]
        assert (external.asset_id, external.skip_reason) == (None, "out_of_scope")
        assert rows[("POST", BASE + "login")].skip_reason == "form_not_submitted"
        assert rows[("GET", BASE + "item?id=1&token=[REDACTED]")].query_param_names == [
            "id",
            "token",
        ]

        linked = session.scalar(
            text(
                "SELECT count(*) FROM evidence v JOIN endpoints e ON e.id = v.endpoint_id "
                "WHERE v.scan_id = :s AND e.method = v.method AND e.url = v.url"
            ),
            {"s": scan_id},
        )
        assert linked == 3


def test_persisting_twice_changes_nothing(db_connection: Connection, scan_id: uuid.UUID) -> None:
    result = sample_result()
    with open_session(db_connection) as session:
        repo = ScanResultRepository(session)
        persist_discovery_result(repo, scan_id, result)
        session.commit()
        first = _counts(session, scan_id)
        ids = sorted(
            map(
                str,
                session.scalars(
                    text("SELECT id FROM endpoints WHERE scan_id = :s"), {"s": scan_id}
                ),
            )
        )

        persist_discovery_result(repo, scan_id, result)
        session.commit()
        assert _counts(session, scan_id) == first
        assert (
            sorted(
                map(
                    str,
                    session.scalars(
                        text("SELECT id FROM endpoints WHERE scan_id = :s"), {"s": scan_id}
                    ),
                )
            )
            == ids
        )


def test_results_are_scoped_to_their_scan(db_connection: Connection, scan_id: uuid.UUID) -> None:
    """Another scan's results with identical URLs are separate rows."""
    result = sample_result()
    with open_session(db_connection) as session:
        repo = ScanResultRepository(session)
        persist_discovery_result(repo, scan_id, result)
        session.commit()
        other_assessment = session.execute(
            text("SELECT assessment_id, target_id, authorization_id FROM scans WHERE id = :s"),
            {"s": scan_id},
        ).one()
        session.execute(
            text("UPDATE scans SET status = 'cancelled', finished_at = now() WHERE id = :s"),
            {"s": scan_id},
        )
        other = uuid.uuid4()
        session.execute(
            text(
                "INSERT INTO scans (id, assessment_id, target_id, authorization_id, config) "
                "VALUES (:id, :a, :t, :z, '{}')"
            ),
            {
                "id": other,
                "a": other_assessment.assessment_id,
                "t": other_assessment.target_id,
                "z": other_assessment.authorization_id,
            },
        )
        persist_discovery_result(repo, other, result)
        session.commit()
        assert _counts(session, other)["endpoints"] == _counts(session, scan_id)["endpoints"] == 7
