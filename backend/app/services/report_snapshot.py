"""Builds the immutable report snapshot from persisted rows (ADR 0010).

This is the only place that turns database rows into report content, and it
copies an explicit allowlist of fields:

- No raw response bodies, request headers, scan logs, error messages, grant
  snapshots or authorization notes are copied.
- Evidence carries response headers (already redacted by the scanner, bounded),
  the body hash, and a short excerpt (already redacted, bounded) only for
  issues whose evidence is body text (EXCERPT_RULES).
- Rule text and taxonomy ids come from the stored rule version that produced
  each finding, never from the current rule registry. Display titles for those
  verified ids are resolved here, from the analysis package's taxonomy, and
  frozen into the snapshot, so the report renderer never needs the analysis
  package.

The output is ordered canonically, so the same data always gives the same
snapshot.
"""

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinel_analysis import REGISTRY, RULESET_VERSION
from sentinel_analysis.taxonomy import (
    CWE,
    CWE_VERSION,
    OWASP_TOP10_2025,
    OWASP_TOP10_EDITION,
    WSTG_EDITION,
    WSTG_V42,
)

from app.models import (
    AnalysisRun,
    Assessment,
    Evidence,
    Finding,
    FindingStatusChange,
    Project,
    RuleVersion,
    Scan,
    Target,
    TargetAuthorization,
)
from sentinel_reports import BODY_SHA256_LABEL, SCHEMA_VERSION, SEVERITY_ORDER

# Rules whose findings are about response body content: their evidence gets a
# bounded, already-redacted excerpt. Every other issue is shown from headers.
EXCERPT_RULES = frozenset({"SV-INF-002", "SV-INF-003"})

MAX_EXCERPT = 1024
MAX_HEADERS = 100
MAX_HEADER_NAME = 128
MAX_HEADER_VALUE = 1024
MAX_TIMELINE = 2000
MAX_DETAIL = 600


@dataclass(frozen=True)
class ReportRequest:
    report_id: uuid.UUID
    number: str
    title: str
    kind: str
    classification: str
    prepared_by: str
    reviewed_by: str | None
    created_at: datetime
    template_id: str
    template_version: int
    executive_summary_note: str | None
    scope_note: str | None


@dataclass(frozen=True)
class SnapshotSources:
    project: Project
    target: Target
    assessment: Assessment
    authorization: TargetAuthorization
    scan: Scan
    run: AnalysisRun
    findings: Sequence[Finding]
    rule_versions: Mapping[tuple[str, int], RuleVersion]
    evidence_links: Mapping[uuid.UUID, Sequence[uuid.UUID]]
    evidence: Sequence[Evidence]
    status_changes: Sequence[FindingStatusChange]


def iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat()


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _settings(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(k): (list(v) if isinstance(v, tuple) else v)
        for k, v in value.items()
        if isinstance(k, str)
    }


def _taxonomy(metadata: Mapping[str, Any]) -> dict[str, Any]:
    top10 = [
        {"id": tid, "title": OWASP_TOP10_2025.get(tid)} for tid in metadata.get("owasp_top10", [])
    ]
    wstg = []
    for wid in metadata.get("wstg", []):
        entry = WSTG_V42.get(wid)
        wstg.append(
            {
                "id": wid,
                "title": entry.title if entry else None,
                "url": entry.source if entry else None,
            }
        )
    cwe = []
    for cid in metadata.get("cwe", []):
        entry = CWE.get(int(cid))
        cwe.append(
            {
                "id": int(cid),
                "title": entry.title if entry else None,
                "url": entry.source if entry else None,
            }
        )
    return {"owasp_top10": top10, "wstg": wstg, "cwe": cwe}


def _rule(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": metadata["id"],
        "version": metadata["version"],
        "title": metadata["title"],
        "category": metadata["category"],
        "severity": metadata["severity"],
        "confidence": metadata["confidence"],
        "detection_type": metadata["detection_type"],
        "subject_type": metadata["subject_type"],
        "description": metadata["description"],
        "proves": metadata["proves"],
        "does_not_prove": metadata["does_not_prove"],
        "remediation": metadata["remediation"],
        **_taxonomy(metadata),
        "references": [r for r in metadata.get("references", []) if str(r).startswith("https://")],
    }


def _methodology_rules(sources: SnapshotSources) -> tuple[bool, list[dict[str, Any]]]:
    """The rules the run evaluated. The ruleset version is a digest of every
    rule's id, version and metadata hash, so when it equals this deployment's
    ruleset the registry names exactly those rules; their text still comes
    from the stored rule versions. Otherwise the list is reported as not
    available rather than guessed."""
    if sources.run.ruleset_version != RULESET_VERSION:
        return False, []
    rules = []
    for registered in REGISTRY:
        stored = sources.rule_versions.get((registered.meta.id, registered.meta.version))
        if stored is None:
            return False, []
        m = stored.rule_metadata
        rules.append(
            {
                "id": m["id"],
                "version": m["version"],
                "title": m["title"],
                "category": m["category"],
                "severity": m["severity"],
                "detection_type": m["detection_type"],
                "wstg": list(m.get("wstg", [])),
            }
        )
    return True, sorted(rules, key=lambda r: r["id"])


def methodology_rule_keys() -> list[tuple[str, int]]:
    return [(r.meta.id, r.meta.version) for r in REGISTRY]


def _instance(finding: Finding, evidence_ids: Sequence[uuid.UUID]) -> dict[str, Any]:
    return {
        "finding_id": str(finding.id),
        "fingerprint": finding.fingerprint,
        "subject_type": finding.subject_type,
        "subject_key": finding.subject_key,
        "discriminator": finding.discriminator,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "detection_type": finding.detection_type,
        "details": dict(finding.details),
        "affected_count": finding.affected_count,
        "status": str(finding.status),
        "status_reason": finding.status_reason,
        "status_changed_by": finding.status_changed_by,
        "status_changed_at": iso(finding.status_changed_at),
        "evidence_ids": sorted(str(e) for e in evidence_ids),
    }


def _evidence(record: Evidence, with_excerpt: bool) -> dict[str, Any]:
    raw_headers = [h for h in record.response_headers if isinstance(h, list) and len(h) == 2]
    headers = [
        [_clip(str(name), MAX_HEADER_NAME), _clip(str(value), MAX_HEADER_VALUE)]
        for name, value in raw_headers[:MAX_HEADERS]
    ]
    headers_truncated = len(raw_headers) > MAX_HEADERS or any(
        len(str(n)) > MAX_HEADER_NAME or len(str(v)) > MAX_HEADER_VALUE
        for n, v in raw_headers[:MAX_HEADERS]
    )
    excerpt = record.body_excerpt if with_excerpt else None
    body_hash = record.body_sha256 if len(record.body_sha256) == 64 else None
    return {
        "id": str(record.id),
        "method": record.method,
        "url": record.url,
        "status_code": record.status_code,
        "peer": record.peer,
        "body_sha256": body_hash,
        "body_sha256_label": BODY_SHA256_LABEL,
        "body_bytes_captured": record.body_bytes_captured,
        "truncated": record.truncated,
        "headers": headers,
        "headers_truncated": headers_truncated,
        "excerpt": None if excerpt is None else excerpt[:MAX_EXCERPT],
        "excerpt_truncated": excerpt is not None and len(excerpt) > MAX_EXCERPT,
    }


def _timeline(sources: SnapshotSources, findings: Mapping[uuid.UUID, Finding]) -> dict[str, Any]:
    a, scan, auth = sources.assessment, sources.scan, sources.authorization
    base: list[dict[str, str]] = [
        {
            "at": _iso(auth.acknowledged_at),
            "kind": "authorization_acknowledged",
            "detail": _clip(
                f"Authorization version {auth.version} ({auth.reference}) acknowledged by "
                f"{auth.acknowledged_by}",
                MAX_DETAIL,
            ),
        }
    ]
    if a.started_at is not None:
        base.append(
            {"at": _iso(a.started_at), "kind": "assessment_started", "detail": "Assessment started"}
        )
    if a.completed_at is not None:
        base.append(
            {
                "at": _iso(a.completed_at),
                "kind": "assessment_completed",
                "detail": "Assessment completed",
            }
        )
    if scan.started_at is not None:
        base.append(
            {
                "at": _iso(scan.started_at),
                "kind": "scan_started",
                "detail": "Discovery scan started",
            }
        )
    if scan.finished_at is not None:
        base.append(
            {
                "at": _iso(scan.finished_at),
                "kind": "scan_finished",
                "detail": f"Discovery scan {scan.status} "
                f"(stop reason: {scan.stop_reason or 'none'})",
            }
        )
    if sources.run.finished_at is not None:
        base.append(
            {
                "at": _iso(sources.run.finished_at),
                "kind": "analysis_completed",
                "detail": f"Analysis completed with ruleset {sources.run.ruleset_version}",
            }
        )
    triage = []
    for change in sources.status_changes:
        finding = findings.get(change.finding_id)
        if finding is None:
            continue
        subject = finding.subject_key + (
            f" {finding.discriminator}" if finding.discriminator else ""
        )
        triage.append(
            {
                "at": _iso(change.changed_at),
                "kind": "finding_triaged",
                "detail": _clip(
                    f"{finding.rule_id} {subject}: {change.from_status} -> {change.to_status} "
                    f"by {change.changed_by}",
                    MAX_DETAIL,
                ),
            }
        )
    room = MAX_TIMELINE - len(base)
    truncated = len(triage) > room
    if truncated:  # keep the most recent triage entries
        triage = sorted(triage, key=lambda e: (e["at"], e["detail"]))[-room:]
    entries = sorted(base + triage, key=lambda e: (e["at"], e["kind"], e["detail"]))
    return {"entries": entries, "truncated": truncated}


def build_snapshot(request: ReportRequest, sources: SnapshotSources) -> dict[str, Any]:
    rank = {severity: i for i, severity in enumerate(SEVERITY_ORDER)}
    findings = {f.id: f for f in sources.findings}

    groups: dict[str, list[Finding]] = {}
    for finding in sources.findings:
        groups.setdefault(finding.rule_id, []).append(finding)

    issues: list[dict[str, Any]] = []
    cited: dict[uuid.UUID, bool] = {}  # evidence id -> needs an excerpt
    for rule_id, members in groups.items():
        versions = {f.rule_version for f in members}
        stored = sources.rule_versions[(rule_id, members[0].rule_version)]
        if len(versions) != 1:  # pragma: no cover  # one run evaluates one version
            raise ValueError("findings of one rule with several versions")
        instances = []
        for finding in members:
            links = list(sources.evidence_links.get(finding.id, ()))
            for evidence_id in links:
                cited[evidence_id] = cited.get(evidence_id, False) or rule_id in EXCERPT_RULES
            instances.append(_instance(finding, links))
        instances.sort(key=lambda i: (i["subject_key"], i["discriminator"], i["fingerprint"]))
        issues.append({"rule": _rule(stored.rule_metadata), "instances": instances})
    issues.sort(key=lambda i: (rank[i["rule"]["severity"]], i["rule"]["id"]))

    evidence = [
        _evidence(record, cited[record.id]) for record in sources.evidence if record.id in cited
    ]
    evidence.sort(key=lambda e: (e["url"], e["method"], e["id"]))

    a, auth, scan, run = sources.assessment, sources.authorization, sources.scan, sources.run
    config = scan.config or {}
    rules_available, rules = _methodology_rules(sources)
    assert run.finished_at is not None  # noqa: S101  # completed runs are finished
    assert scan.started_at is not None and scan.finished_at is not None  # noqa: S101

    return {
        "schema_version": SCHEMA_VERSION,
        "document": {
            "report_id": str(request.report_id),
            "number": request.number,
            "title": request.title,
            "kind": request.kind,
            "classification": request.classification,
            "prepared_by": request.prepared_by,
            "reviewed_by": request.reviewed_by,
            "created_at": _iso(request.created_at),
            "template": {"id": request.template_id, "version": request.template_version},
        },
        "inputs": {
            "executive_summary_note": request.executive_summary_note,
            "scope_note": request.scope_note,
        },
        "engagement": {
            "project": {"id": str(sources.project.id), "name": sources.project.name},
            "target": {"id": str(sources.target.id), "name": sources.target.name},
            "assessment": {
                "id": str(a.id),
                "name": a.name,
                "description": a.description,
                "status": str(a.status),
                "started_at": iso(a.started_at),
                "completed_at": iso(a.completed_at),
            },
            "authorization": {
                "id": str(auth.id),
                "version": auth.version,
                "authorized_by": auth.authorized_by,
                "reference": auth.reference,
                "valid_from": _iso(auth.valid_from),
                "valid_until": _iso(auth.valid_until),
                "acknowledged_by": auth.acknowledged_by,
                "acknowledged_at": _iso(auth.acknowledged_at),
            },
        },
        "scope": {
            "base_url": auth.base_url,
            "environment": str(auth.environment),
            "in_scope_hosts": list(auth.in_scope_hosts),
            "allowed_ports": list(auth.allowed_ports),
            "in_scope_path_prefixes": list(auth.in_scope_path_prefixes),
            "excluded_paths": list(auth.excluded_paths),
        },
        "methodology": {
            "scanner_version": scan.scanner_version,
            "verify_tls": config.get("allow_untrusted_tls") is not True,
            "limits": _settings(config.get("limits")),
            "crawl": _settings(config.get("crawl")),
            "ruleset_version": run.ruleset_version,
            "analysis_run_id": str(run.id),
            "analysis_finished_at": _iso(run.finished_at),
            "rules_evaluated": run.rules_evaluated,
            "rules_available": rules_available,
            "rules": rules,
        },
        "scan": {
            "id": str(scan.id),
            "status": str(scan.status),
            "stop_reason": scan.stop_reason,
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "requests_sent": scan.requests_sent,
            "pages_count": scan.pages_count,
            "endpoints_count": scan.endpoints_count,
            "events_count": scan.events_count,
            "evidence_count": scan.evidence_count,
            "coverage_notes": sorted(set(run.coverage_notes)),
            "rule_errors": sorted(
                ({"rule_id": e["rule_id"], "error": e["error"]} for e in run.rule_errors),
                key=lambda e: (e["rule_id"], e["error"]),
            ),
        },
        "taxonomy_editions": {
            "owasp_top10": OWASP_TOP10_EDITION,
            "wstg": WSTG_EDITION,
            "cwe": CWE_VERSION,
        },
        "issues": issues,
        "evidence": evidence,
        "timeline": _timeline(sources, findings),
    }
