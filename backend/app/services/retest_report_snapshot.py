"""Builds the immutable retest report snapshot (sentinelvapt.retest-report/1,
ADR 0012) from persisted rows.

An explicit allowlist of fields is copied. Comparison states, reasons and
coverage evidence are copied exactly as the completed comparison stored them;
nothing is reclassified. Two triage statuses are frozen per finding and kept
apart from the comparison state: the one captured when the comparison ran, and
the one current when the report is requested (read under a share lock).

Rule text comes from the stored rule version of each finding, with verified
taxonomy titles resolved here (reusing the Phase 5 snapshot builder's helpers,
which are not changed). Evidence entries reuse the Phase 5 evidence allowlist
and add the scan role, the scan id and an entry digest.

Bounds are enforced, never silently applied: more than 25 evidence records on
a finding, or more than 5000 evidence entries in total, refuse the snapshot.
"""

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel_analysis.taxonomy import CWE_VERSION, OWASP_TOP10_EDITION, WSTG_EDITION

from app.models import (
    AnalysisRun,
    Assessment,
    Comparison,
    ComparisonRecord,
    Evidence,
    Finding,
    Project,
    RuleVersion,
    Scan,
    Target,
    TargetAuthorization,
)
from app.services.report_snapshot import EXCERPT_RULES, _evidence, _iso, _rule, _settings, iso
from sentinel_reports import SnapshotInvalid
from sentinel_reports.retest import (
    RETEST_SCHEMA_VERSION,
    STATES,
    evidence_entry_sha256,
    records_sha256,
)
from sentinel_reports.retest.snapshot import evidence_sort_key

MAX_EVIDENCE_PER_VIEW = 25
MAX_EVIDENCE_ENTRIES = 5000
LIMITATION_ORDER = (
    "scope_narrowed",
    "partial_scan",
    "tls_trust_not_evaluated",
    "observations_truncated",
    "rule_errors",
    "rule_versions_unknown",
    "rule_versions_differ",
    "no_fuzzy_matching",
    "passive_testing_only",
)
HISTORY_REASONS = frozenset(
    {
        "previously_fixed",
        "previously_dismissed",
        "previously_not_retested",
        "previously_not_comparable",
        "previously_observed",
    }
)


@dataclass(frozen=True)
class RetestReportRequest:
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
class Side:
    assessment: Assessment
    scan: Scan
    run: AnalysisRun
    authorization: TargetAuthorization


@dataclass(frozen=True)
class LineageEntry:
    assessment: Assessment
    comparison: Comparison | None
    summary: Mapping[str, int] | None


@dataclass(frozen=True)
class RetestSources:
    project: Project
    target: Target
    comparison: Comparison
    baseline: Side
    retest: Side
    records: Sequence[ComparisonRecord]
    coverage: Mapping[str, Sequence[uuid.UUID]]
    findings: Mapping[uuid.UUID, Finding]
    finding_evidence: Mapping[uuid.UUID, Sequence[uuid.UUID]]
    evidence: Mapping[str, Mapping[uuid.UUID, Evidence]]  # role -> id -> row
    rule_versions: Mapping[tuple[str, int], RuleVersion]
    lineage: Sequence[LineageEntry]
    history: Mapping[str, Mapping[str, Any]]  # fingerprint -> history entry


def _state_counts(summary: Mapping[str, int] | None) -> dict[str, int]:
    return {state: int((summary or {}).get(state, 0)) for state in STATES}


def _side(side: Side) -> dict[str, Any]:
    a, scan, run = side.assessment, side.scan, side.run
    config = scan.config or {}
    assert scan.started_at is not None and scan.finished_at is not None  # noqa: S101
    assert run.finished_at is not None  # noqa: S101  # completed runs are finished
    return {
        "assessment": {
            "id": str(a.id),
            "name": a.name,
            "status": str(a.status),
            "started_at": iso(a.started_at),
            "completed_at": iso(a.completed_at),
        },
        "scan": {
            "id": str(scan.id),
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "stop_reason": scan.stop_reason,
            "scanner_version": scan.scanner_version,
            "verify_tls": config.get("allow_untrusted_tls") is not True,
            "limits": _settings(config.get("limits")),
            "requests_sent": scan.requests_sent,
            "pages_count": scan.pages_count,
            "endpoints_count": scan.endpoints_count,
            "evidence_count": scan.evidence_count,
        },
        "run": {
            "id": str(run.id),
            "ruleset_version": run.ruleset_version,
            "rule_versions": None
            if run.rule_versions is None
            else sorted(
                (
                    {"rule_id": str(r["rule_id"]), "version": int(r["version"])}
                    for r in run.rule_versions
                ),
                key=lambda r: (r["rule_id"], r["version"]),
            ),
            "coverage_notes": sorted(set(run.coverage_notes)),
            "rule_errors": sorted(
                ({"rule_id": e["rule_id"], "error": e["error"]} for e in run.rule_errors),
                key=lambda e: (e["rule_id"], e["error"]),
            ),
            "finished_at": _iso(run.finished_at),
        },
    }


def _authorization(auth: TargetAuthorization) -> dict[str, Any]:
    return {
        "id": str(auth.id),
        "version": auth.version,
        "authorized_by": auth.authorized_by,
        "reference": auth.reference,
        "valid_from": _iso(auth.valid_from),
        "valid_until": _iso(auth.valid_until),
        "acknowledged_by": auth.acknowledged_by,
        "acknowledged_at": _iso(auth.acknowledged_at),
        "scope": {
            "base_url": auth.base_url,
            "environment": str(auth.environment),
            "in_scope_hosts": sorted(auth.in_scope_hosts),
            "allowed_ports": sorted(auth.allowed_ports),
            "in_scope_path_prefixes": sorted(auth.in_scope_path_prefixes),
            "excluded_paths": sorted(auth.excluded_paths),
        },
    }


def scope_change(retest: TargetAuthorization, baseline: TargetAuthorization) -> dict[str, Any]:
    """How the retest's scope differs from the baseline's. Phase 6 guarantees
    containment, so any difference narrows the scope."""
    new_hosts = {h.lower() for h in retest.in_scope_hosts}
    change = {
        "hosts_removed": sorted(
            h for h in {h.lower() for h in baseline.in_scope_hosts} - new_hosts
        ),
        "ports_removed": sorted(set(baseline.allowed_ports) - set(retest.allowed_ports)),
        "path_prefixes_removed": sorted(
            p for p in baseline.in_scope_path_prefixes if p not in retest.in_scope_path_prefixes
        ),
        "path_prefixes_added": sorted(
            p for p in retest.in_scope_path_prefixes if p not in baseline.in_scope_path_prefixes
        ),
        "exclusions_added": sorted(
            e for e in retest.excluded_paths if e not in baseline.excluded_paths
        ),
    }
    return {"narrower": any(change.values()), **change}


def _limitations(src: RetestSources, narrower: bool) -> list[str]:
    run_b, run_r = src.baseline.run, src.retest.run
    codes = {"no_fuzzy_matching", "passive_testing_only"}
    if narrower:
        codes.add("scope_narrowed")
    codes.update(n for n in run_r.coverage_notes if n in LIMITATION_ORDER)
    if run_r.rule_errors:
        codes.add("rule_errors")
    if run_b.rule_versions is None or run_r.rule_versions is None:
        codes.add("rule_versions_unknown")
    else:
        old = {(r["rule_id"], r["version"]) for r in run_b.rule_versions}
        new = {(r["rule_id"], r["version"]) for r in run_r.rule_versions}
        if old != new:
            codes.add("rule_versions_differ")
    return [code for code in LIMITATION_ORDER if code in codes]


def build_retest_snapshot(request: RetestReportRequest, src: RetestSources) -> dict[str, Any]:
    cited: dict[tuple[str, uuid.UUID], bool] = {}  # (role, id) -> needs an excerpt
    rule_keys: set[tuple[str, int]] = set()

    def view(finding_id: uuid.UUID | None, role: str) -> dict[str, Any] | None:
        if finding_id is None:
            return None
        finding = src.findings[finding_id]
        ids = list(src.finding_evidence.get(finding_id, ()))
        if len(ids) > MAX_EVIDENCE_PER_VIEW:
            raise SnapshotInvalid("a finding cites more than 25 evidence records")
        for evidence_id in ids:
            key = (role, evidence_id)
            cited[key] = cited.get(key, False) or finding.rule_id in EXCERPT_RULES
        rule_keys.add((finding.rule_id, finding.rule_version))
        return {
            "finding_id": str(finding.id),
            "rule_version": finding.rule_version,
            "subject_type": finding.subject_type,
            "subject_key": finding.subject_key,
            "discriminator": finding.discriminator,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "detection_type": finding.detection_type,
            "details": dict(finding.details),
            "affected_count": finding.affected_count,
            "evidence_ids": sorted(str(i) for i in ids),
        }

    def reported(finding_id: uuid.UUID | None) -> str | None:
        return None if finding_id is None else str(src.findings[finding_id].status)

    records: list[dict[str, Any]] = []
    for r in src.records:
        coverage = list(src.coverage.get(r.fingerprint, ()))
        for evidence_id in coverage:
            key = ("current", evidence_id)
            cited[key] = cited.get(key, False) or r.rule_id in EXCERPT_RULES
        state = str(r.state)
        history = None
        if state in ("new", "reopened") and set(r.reasons) & HISTORY_REASONS:
            history = dict(src.history[r.fingerprint]) if r.fingerprint in src.history else None
        records.append(
            {
                "fingerprint": r.fingerprint,
                "rule_id": r.rule_id,
                "state": state,
                "reasons": list(r.reasons),
                "baseline": view(r.baseline_finding_id, "baseline"),
                "current": view(r.current_finding_id, "current"),
                "triage_when_compared": {
                    "baseline": r.baseline_triage,
                    "current": r.current_triage,
                },
                "triage_when_reported": {
                    "baseline": reported(r.baseline_finding_id),
                    "current": reported(r.current_finding_id),
                },
                "coverage_evidence_ids": sorted(str(i) for i in coverage),
                "history": history,
            }
        )
    records.sort(key=lambda rec: rec["fingerprint"])

    if len(cited) > MAX_EVIDENCE_ENTRIES:
        raise SnapshotInvalid("more than 5000 evidence entries")
    scans = {"baseline": src.baseline.scan.id, "current": src.retest.scan.id}
    evidence = []
    for (role, evidence_id), with_excerpt in cited.items():
        row = src.evidence[role].get(evidence_id)
        if row is None or row.scan_id != scans[role]:
            raise SnapshotInvalid("cited evidence is missing from its scan")
        entry = {**_evidence(row, with_excerpt), "role": role, "scan_id": str(row.scan_id)}
        entry["entry_sha256"] = evidence_entry_sha256(entry)
        evidence.append(entry)
    evidence.sort(key=evidence_sort_key)

    rules = {}
    for rule_id, version in sorted(rule_keys):
        stored = src.rule_versions.get((rule_id, version))
        if stored is None:  # pragma: no cover  # findings reference rule_versions
            raise SnapshotInvalid("rule metadata missing")
        rules[f"{rule_id}@{version}"] = _rule(stored.rule_metadata)

    counts = {state: 0 for state in STATES}
    for rec in records:
        counts[rec["state"]] += 1
    change = scope_change(src.retest.authorization, src.baseline.authorization)
    comparison = src.comparison
    assert comparison.finished_at is not None  # noqa: S101  # completed comparisons
    lineage = []
    for position, step in enumerate(src.lineage):
        lineage.append(
            {
                "position": position,
                "assessment": {
                    "id": str(step.assessment.id),
                    "name": step.assessment.name,
                    "status": str(step.assessment.status),
                    "completed_at": iso(step.assessment.completed_at),
                },
                "baseline_scan_id": None
                if step.assessment.baseline_scan_id is None
                else str(step.assessment.baseline_scan_id),
                "comparison": None
                if step.comparison is None
                else {"id": str(step.comparison.id), "summary": _state_counts(step.summary)},
            }
        )

    return {
        "schema_version": RETEST_SCHEMA_VERSION,
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
        "comparison": {
            "id": str(comparison.id),
            "policy_version": comparison.policy_version,
            "created_at": _iso(comparison.created_at),
            "finished_at": _iso(comparison.finished_at),
            "previous_comparison_id": None
            if comparison.previous_comparison_id is None
            else str(comparison.previous_comparison_id),
            "summary": counts,
            "records_sha256": records_sha256(records),
        },
        "engagement": {
            "project": {"id": str(src.project.id), "name": src.project.name},
            "target": {"id": str(src.target.id), "name": src.target.name},
            "baseline": _side(src.baseline),
            "retest": _side(src.retest),
        },
        "authorization": {
            "retest": _authorization(src.retest.authorization),
            "baseline": _authorization(src.baseline.authorization),
        },
        "scope_change": change,
        "lineage": lineage,
        "rules": rules,
        "records": records,
        "evidence": evidence,
        "limitations": _limitations(src, change["narrower"]),
        "taxonomy_editions": {
            "owasp_top10": OWASP_TOP10_EDITION,
            "wstg": WSTG_EDITION,
            "cwe": CWE_VERSION,
        },
    }
