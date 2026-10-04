"""Valid report snapshots for tests, built the way the backend builds them."""

import copy
import hashlib
import uuid
from typing import Any

from sentinel_reports import BODY_SHA256_LABEL, SEVERITY_ORDER

T0 = "2026-10-04T12:00:00+00:00"


def uid(n: int) -> str:
    return str(uuid.UUID(int=n))


def fp(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def rule(rule_id: str, severity: str = "low", **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": rule_id,
        "version": 1,
        "title": f"Title of {rule_id}",
        "category": "headers",
        "severity": severity,
        "confidence": "high",
        "detection_type": "automated_detection",
        "subject_type": "origin",
        "description": f"Description of {rule_id}.",
        "proves": "What it proves.",
        "does_not_prove": "What it does not prove.",
        "remediation": "How to fix it.",
        "owasp_top10": [{"id": "A02:2025", "title": "Security Misconfiguration"}],
        "wstg": [
            {
                "id": "WSTG-CONF-07",
                "title": "Test HTTP Strict Transport Security",
                "url": "https://wstg.owasp.org/v4.2/x",
            }
        ],
        "cwe": [
            {
                "id": 319,
                "title": "Cleartext Transmission of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/319.html",
            }
        ],
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
    }
    values.update(overrides)
    return values


def instance(n: int, evidence: list[str], **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": uid(1000 + n),
        "fingerprint": fp(f"finding-{n}"),
        "subject_type": "origin",
        "subject_key": f"http://lab.test:{8000 + n}",
        "discriminator": "",
        "severity": "low",
        "confidence": "high",
        "detection_type": "automated_detection",
        "details": {"header": "server", "value": "nginx/1.25"},
        "affected_count": 1,
        "status": "open",
        "status_reason": None,
        "status_changed_by": None,
        "status_changed_at": None,
        "evidence_ids": evidence,
    }
    values.update(overrides)
    return values


def evidence(n: int, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": uid(2000 + n),
        "method": "GET",
        "url": f"http://lab.test:8080/page{n:03d}",
        "status_code": 200,
        "peer": "127.0.0.1",
        "body_sha256": fp(f"body-{n}"),
        "body_sha256_label": BODY_SHA256_LABEL,
        "body_bytes_captured": 512,
        "truncated": False,
        "headers": [["content-type", "text/html"], ["set-cookie", "SESSIONID=[REDACTED]; Path=/"]],
        "headers_truncated": False,
        "excerpt": None,
        "excerpt_truncated": False,
    }
    values.update(overrides)
    return values


def snapshot(**overrides: Any) -> dict[str, Any]:
    ev = [evidence(1), evidence(2)]
    issues = [
        {
            "rule": rule("SV-HDR-002"),
            "instances": [instance(1, [ev[0]["id"]])],
        },
        {
            "rule": rule("SV-INF-001", "informational"),
            "instances": [
                instance(2, [ev[1]["id"]], severity="informational"),
                instance(3, [ev[1]["id"]], severity="informational", status="false_positive",
                         status_reason="Lab banner", status_changed_by="Lead",
                         status_changed_at="2026-10-04T12:30:00+00:00"),
            ],
        },
    ]  # fmt: skip
    values: dict[str, Any] = {
        "schema_version": "sentinelvapt.report/1",
        "document": {
            "report_id": uid(1),
            "number": "SV-R-000001",
            "title": "Lab assessment report",
            "kind": "draft",
            "classification": "confidential",
            "prepared_by": "Tester",
            "reviewed_by": None,
            "created_at": "2026-10-04T13:00:00+00:00",
            "template": {"id": "sv-standard", "version": 1},
        },
        "inputs": {"executive_summary_note": None, "scope_note": None},
        "engagement": {
            "project": {"id": uid(2), "name": "Lab project"},
            "target": {"id": uid(3), "name": "Lab target"},
            "assessment": {
                "id": uid(4),
                "name": "Assessment",
                "description": None,
                "status": "in_progress",
                "started_at": T0,
                "completed_at": None,
            },
            "authorization": {
                "id": uid(5),
                "version": 1,
                "authorized_by": "Lab Owner",
                "reference": "LAB-1",
                "valid_from": T0,
                "valid_until": "2026-10-05T12:00:00+00:00",
                "acknowledged_by": "Tester",
                "acknowledged_at": T0,
            },
        },
        "scope": {
            "base_url": "http://lab.test:8080/",
            "environment": "local_lab",
            "in_scope_hosts": ["lab.test"],
            "allowed_ports": [8080],
            "in_scope_path_prefixes": ["/"],
            "excluded_paths": ["/admin"],
        },
        "methodology": {
            "scanner_version": "0.1.0",
            "verify_tls": True,
            "limits": {"max_requests": 100, "request_timeout_s": 10.0},
            "crawl": {"fetch_robots": True},
            "ruleset_version": "rs-0123456789abcdef",
            "analysis_run_id": uid(6),
            "analysis_finished_at": "2026-10-04T12:10:00+00:00",
            "rules_evaluated": 2,
            "rules_available": True,
            "rules": [
                {
                    "id": "SV-HDR-002",
                    "version": 1,
                    "title": "Title of SV-HDR-002",
                    "category": "headers",
                    "severity": "low",
                    "detection_type": "automated_detection",
                    "wstg": [],
                },
                {
                    "id": "SV-INF-001",
                    "version": 1,
                    "title": "Title of SV-INF-001",
                    "category": "disclosure",
                    "severity": "informational",
                    "detection_type": "automated_detection",
                    "wstg": ["WSTG-INFO-02"],
                },
            ],
        },
        "scan": {
            "id": uid(7),
            "status": "completed",
            "stop_reason": "completed",
            "started_at": "2026-10-04T12:01:00+00:00",
            "finished_at": "2026-10-04T12:05:00+00:00",
            "requests_sent": 10,
            "pages_count": 5,
            "endpoints_count": 8,
            "events_count": 12,
            "evidence_count": 10,
            "coverage_notes": [],
            "rule_errors": [],
        },
        "taxonomy_editions": {
            "owasp_top10": "OWASP Top 10:2025",
            "wstg": "OWASP WSTG v4.2",
            "cwe": "CWE 4.20",
        },
        "issues": issues,
        "evidence": ev,
        "timeline": {
            "truncated": False,
            "entries": [
                {"at": T0, "kind": "assessment_started", "detail": "Assessment started"},
                {"at": "2026-10-04T12:01:00+00:00", "kind": "scan_started", "detail": "Scan"},
            ],
        },
    }
    values.update(overrides)
    return values


def with_text_everywhere(text: str) -> dict[str, Any]:
    """A snapshot whose every free-text field (user input, target data,
    finding details, evidence) carries `text`."""
    s = snapshot()
    s = copy.deepcopy(s)
    s["document"]["title"] = text[:200]
    s["document"]["prepared_by"] = text[:200]
    s["document"]["reviewed_by"] = text[:200]
    s["inputs"] = {"executive_summary_note": text, "scope_note": text}
    s["engagement"]["project"]["name"] = text[:200]
    s["engagement"]["target"]["name"] = text[:200]
    s["engagement"]["assessment"]["name"] = text[:200]
    s["engagement"]["assessment"]["description"] = text
    s["engagement"]["authorization"]["authorized_by"] = text[:200]
    s["engagement"]["authorization"]["reference"] = text[:200]
    s["scope"]["base_url"] = text[:2048]
    s["scope"]["in_scope_hosts"] = [text[:255]]
    s["scope"]["excluded_paths"] = [text]
    s["methodology"]["limits"]["note"] = text[:200]
    for issue in s["issues"]:
        for inst in issue["instances"]:
            inst["details"] = {"value": text[:300], "header": text[:300]}
            inst["discriminator"] = text[:255]
            inst["status_reason"] = text
    for ev in s["evidence"]:
        ev["headers"] = [[text[:128], text[:1024]]]
        ev["excerpt"] = text[:1024]
    s["timeline"]["entries"][0]["detail"] = text[:600]
    # Instances are ordered by (subject_key, discriminator, fingerprint); the
    # discriminator change keeps that order because subject keys differ.
    return s


__all__ = ["SEVERITY_ORDER", "evidence", "instance", "rule", "snapshot", "uid"]
