"""Valid retest report snapshots for tests, built the way the backend builds
them: one record per comparison state by default."""

import copy
import hashlib
import uuid
from typing import Any

from sentinel_reports import BODY_SHA256_LABEL
from sentinel_reports.retest import STATES, evidence_entry_sha256, records_sha256
from sentinel_reports.retest.snapshot import evidence_sort_key

T0 = "2026-10-04T12:00:00+00:00"
BASE_SCAN = str(uuid.UUID(int=101))
CUR_SCAN = str(uuid.UUID(int=102))
ORIGIN = "http://lab.test:8080"


def uid(n: int) -> str:
    return str(uuid.UUID(int=n))


def fp(n: int) -> str:
    return f"{n:064x}"


def rule(rule_id: str, version: int = 1, **kw: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": rule_id,
        "version": version,
        "title": f"Title of {rule_id}",
        "category": "headers",
        "severity": "low",
        "confidence": "high",
        "detection_type": "automated_detection",
        "subject_type": "origin",
        "description": "Description.",
        "proves": "Proves.",
        "does_not_prove": f"Does not prove ({rule_id}).",
        "remediation": "Fix it.",
        "owasp_top10": [],
        "wstg": [],
        "cwe": [],
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
    }
    values.update(kw)
    return values


def view(n: int, evidence: list[str], **kw: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": uid(1000 + n),
        "rule_version": 1,
        "subject_type": "origin",
        "subject_key": ORIGIN,
        "discriminator": "",
        "severity": "low",
        "confidence": "high",
        "detection_type": "automated_detection",
        "details": {"responses_checked": 3, "value": "nginx/1.25"},
        "affected_count": 1,
        "evidence_ids": evidence,
    }
    values.update(kw)
    return values


def evidence(role: str, n: int, **kw: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": uid(2000 + n),
        "role": role,
        "scan_id": BASE_SCAN if role == "baseline" else CUR_SCAN,
        "method": "GET",
        "url": f"{ORIGIN}/page{n:03d}",
        "status_code": 200,
        "peer": "127.0.0.1",
        "body_sha256": hashlib.sha256(f"body-{n}".encode()).hexdigest(),
        "body_sha256_label": BODY_SHA256_LABEL,
        "body_bytes_captured": 100,
        "truncated": False,
        "headers": [["content-type", "text/html"], ["set-cookie", "SID=[REDACTED]"]],
        "headers_truncated": False,
        "excerpt": None,
        "excerpt_truncated": False,
    }
    values.update(kw)
    values["entry_sha256"] = evidence_entry_sha256(values)
    return values


def record(n: int, state: str, *, base: Any = None, cur: Any = None, **kw: Any) -> dict[str, Any]:
    triage_b = None if base is None else ("false_positive" if state == "dismissed" else "open")
    triage_c = None if cur is None else "open"
    values: dict[str, Any] = {
        "fingerprint": fp(n),
        "rule_id": "SV-HDR-002",
        "state": state,
        "reasons": [],
        "baseline": base,
        "current": cur,
        "triage_when_compared": {"baseline": triage_b, "current": triage_c},
        "triage_when_reported": {"baseline": triage_b, "current": triage_c},
        "coverage_evidence_ids": [],
        "history": None,
    }
    values.update(kw)
    return values


def side(n: int, scan: str, name: str) -> dict[str, Any]:
    return {
        "assessment": {
            "id": uid(300 + n),
            "name": name,
            "status": "completed",
            "started_at": T0,
            "completed_at": T0,
        },
        "scan": {
            "id": scan,
            "started_at": T0,
            "finished_at": T0,
            "stop_reason": "completed",
            "scanner_version": "0.1.0",
            "verify_tls": True,
            "limits": {"max_requests": 100},
            "requests_sent": 10,
            "pages_count": 5,
            "endpoints_count": 8,
            "evidence_count": 10,
        },
        "run": {
            "id": uid(400 + n),
            "ruleset_version": "rs-0123456789abcdef",
            "rule_versions": [{"rule_id": "SV-HDR-002", "version": 1}],
            "coverage_notes": [],
            "rule_errors": [],
            "finished_at": T0,
        },
    }


def authorization(n: int, **scope: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "base_url": f"{ORIGIN}/",
        "environment": "local_lab",
        "in_scope_hosts": ["lab.test"],
        "allowed_ports": [8080],
        "in_scope_path_prefixes": ["/"],
        "excluded_paths": ["/admin"],
    }
    values.update(scope)
    return {
        "id": uid(500 + n),
        "version": n,
        "authorized_by": "Lab Owner",
        "reference": f"LAB-{n}",
        "valid_from": T0,
        "valid_until": "2026-10-05T12:00:00+00:00",
        "acknowledged_by": "Tester",
        "acknowledged_at": T0,
        "scope": values,
    }


def prune_evidence(s: dict[str, Any]) -> dict[str, Any]:
    """Keep only the evidence entries the records still cite."""
    cited: set[tuple[str, str]] = set()
    for r in s["records"]:
        for role in ("baseline", "current"):
            if r[role] is not None:
                cited.update((role, i) for i in r[role]["evidence_ids"])
        cited.update(("current", i) for i in r["coverage_evidence_ids"])
    s["evidence"] = [e for e in s["evidence"] if (e["role"], e["id"]) in cited]
    return s


def finalize(s: dict[str, Any]) -> dict[str, Any]:
    """Recompute the derived parts (order, counts, digests) after a change."""
    s["records"].sort(key=lambda r: r["fingerprint"])
    for entry in s["evidence"]:
        entry["entry_sha256"] = evidence_entry_sha256(entry)
    s["evidence"].sort(key=evidence_sort_key)
    counts = {state: 0 for state in STATES}
    for r in s["records"]:
        counts[r["state"]] += 1
    s["comparison"]["summary"] = counts
    s["comparison"]["records_sha256"] = records_sha256(s["records"])
    s["lineage"][-1]["comparison"]["summary"] = counts
    return s


def snapshot(**overrides: Any) -> dict[str, Any]:
    b = [evidence("baseline", i) for i in range(1, 7)]
    c = [evidence("current", i) for i in range(11, 18)]
    bid = [e["id"] for e in b]
    cid = [e["id"] for e in c]
    records = [
        record(1, "new", cur=view(1, [cid[0]]), reasons=["first_observed"]),
        record(
            2,
            "reopened",
            cur=view(2, [cid[1]]),
            reasons=["previously_fixed"],
            history={
                "comparison_id": uid(901),
                "assessment_id": uid(302),
                "assessment_name": "Retest B",
                "state": "fixed",
            },
        ),
        record(
            3,
            "still_open",
            base=view(3, [bid[0]], severity="low"),
            cur=view(3, [cid[2]], severity="informational", details={"value": "nginx/1.27"}),
            reasons=["details_changed", "severity_changed"],
        ),
        record(4, "unchanged", base=view(4, [bid[1]]), cur=view(4, [cid[3]])),
        record(
            5,
            "fixed",
            base=view(5, [bid[2]]),
            coverage_evidence_ids=[cid[4], cid[5]],
            reasons=["examined_condition_absent"],
        ),
        record(
            6,
            "dismissed",
            base=view(6, [bid[3]]),
            coverage_evidence_ids=[cid[6]],
            reasons=["baseline_false_positive", "examined_condition_absent"],
        ),
        record(7, "not_retested", base=view(7, [bid[4]]), reasons=["out_of_scope"]),
        record(8, "not_comparable", base=view(8, [bid[5]]), reasons=["rule_version_changed"]),
    ]
    values: dict[str, Any] = {
        "schema_version": "sentinelvapt.retest-report/1",
        "document": {
            "report_id": uid(1),
            "number": "SV-RT-000001",
            "title": "Retest report",
            "kind": "final",
            "classification": "confidential",
            "prepared_by": "Tester",
            "reviewed_by": None,
            "created_at": "2026-10-04T13:00:00+00:00",
            "template": {"id": "sv-retest", "version": 1},
        },
        "inputs": {"executive_summary_note": None, "scope_note": None},
        "comparison": {
            "id": uid(902),
            "policy_version": "cmp-1",
            "created_at": T0,
            "finished_at": T0,
            "previous_comparison_id": uid(901),
            "summary": {},
            "records_sha256": "0" * 64,
        },
        "engagement": {
            "project": {"id": uid(2), "name": "Lab project"},
            "target": {"id": uid(3), "name": "Lab target"},
            "baseline": side(2, BASE_SCAN, "Retest B"),
            "retest": side(3, CUR_SCAN, "Retest C"),
        },
        "authorization": {
            "retest": authorization(2, excluded_paths=["/admin", "/error"]),
            "baseline": authorization(1),
        },
        "scope_change": {
            "narrower": True,
            "hosts_removed": [],
            "ports_removed": [],
            "path_prefixes_removed": [],
            "path_prefixes_added": [],
            "exclusions_added": ["/error"],
        },
        "lineage": [
            {
                "position": 0,
                "assessment": {
                    "id": uid(301),
                    "name": "Baseline A",
                    "status": "completed",
                    "completed_at": T0,
                },
                "baseline_scan_id": None,
                "comparison": None,
            },
            {
                "position": 1,
                "assessment": {
                    "id": uid(302),
                    "name": "Retest B",
                    "status": "completed",
                    "completed_at": T0,
                },
                "baseline_scan_id": uid(100),
                "comparison": {"id": uid(901), "summary": {s: 0 for s in STATES}},
            },
            {
                "position": 2,
                "assessment": {
                    "id": uid(303),
                    "name": "Retest C",
                    "status": "completed",
                    "completed_at": T0,
                },
                "baseline_scan_id": BASE_SCAN,
                "comparison": {"id": uid(902), "summary": {}},
            },
        ],
        "rules": {"SV-HDR-002@1": rule("SV-HDR-002")},
        "records": records,
        "evidence": b + c,
        "limitations": ["scope_narrowed", "no_fuzzy_matching", "passive_testing_only"],
        "taxonomy_editions": {
            "owasp_top10": "OWASP Top 10:2025",
            "wstg": "OWASP WSTG v4.2",
            "cwe": "CWE 4.20",
        },
    }
    values.update(overrides)
    return finalize(values)


def with_text_everywhere(text: str) -> dict[str, Any]:
    s = copy.deepcopy(snapshot())
    s["document"]["title"] = text[:200]
    s["document"]["prepared_by"] = text[:200]
    s["inputs"] = {"executive_summary_note": text, "scope_note": text}
    s["engagement"]["target"]["name"] = text[:200]
    s["engagement"]["baseline"]["assessment"]["name"] = text[:200]
    s["engagement"]["retest"]["assessment"]["name"] = text[:200]
    s["authorization"]["retest"]["reference"] = text[:200]
    s["authorization"]["retest"]["scope"]["excluded_paths"] = [text]
    for r in s["records"]:
        for v in (r["baseline"], r["current"]):
            if v is not None:
                v["details"] = {"value": text[:300]}
                v["discriminator"] = text[:255]
        if r["history"] is not None:
            r["history"]["assessment_name"] = text[:200]
    for e in s["evidence"]:
        e["headers"] = [[text[:128], text[:1024]]]
        e["excerpt"] = text[:1024]
    s["rules"]["SV-HDR-002@1"]["title"] = text[:4000]
    return finalize(s)
