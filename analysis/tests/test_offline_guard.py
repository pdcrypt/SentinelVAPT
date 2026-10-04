"""Runtime guard: a full analysis completes with every way of opening a
network connection made to fail (complements the static import checks)."""

import socket
from typing import Any

import pytest
from sentinel_analysis import analyze

from tests.builders import Page, build, cookie, tls_event


class NetworkUsed(AssertionError):
    pass


def _refuse(*_: Any, **__: Any) -> Any:
    raise NetworkUsed("analysis attempted network access")


def test_analysis_runs_with_networking_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, _refuse)
    observations = build(
        [
            Page("http://127.0.0.1:8080/", headers=[("Server", "nginx/1.25")]),
            Page("https://127.0.0.1:8443/", cookies=[cookie("sessionid")]),
            Page("http://127.0.0.1:8080/x", method="OPTIONS", headers=[("Allow", "GET, PUT")]),
        ],
        events=[tls_event("https://127.0.0.1:9443/")],
    )
    result = analyze(observations)
    assert result.rule_errors == ()
    assert {c.rule_id for c in result.candidates} >= {"SV-TRN-001", "SV-TRN-002", "SV-INF-001"}
    # Coverage and comparison (ADR 0011) run under the same guard.
    from sentinel_analysis import CurrentRun, FindingSnapshot, classify, coverage

    cov = coverage(observations)
    snapshots = [
        FindingSnapshot(
            finding_id=c.fingerprint[:8],
            fingerprint=c.fingerprint,
            rule_id=c.rule_id,
            rule_version=c.rule_version,
            subject_type=c.subject_type.value,
            subject_key=c.subject_key,
            discriminator=c.discriminator,
            severity=c.severity.value,
            confidence=c.confidence.value,
            detection_type=c.detection_type.value,
            details=c.details,
            triage_status="open",
        )
        for c in result.candidates
    ]
    run = CurrentRun(
        evaluated_rules={r: 1 for r in cov.rules}, coverage=cov.keys, coverage_rules=cov.rules
    )
    records = classify(snapshots, snapshots, run, {})
    assert len(records) == len(snapshots)
