"""Phase 4 analysis (ADR 0009): persisted scan data -> rule engine -> findings.

The rule engine (sentinel_analysis) is offline and database-free. This module
is the only place that turns database rows into its input (ScanObservations)
and its output (FindingCandidates) back into rows. Nothing here re-contacts the
target: analysis reads only what Phase 3 stored, already redacted.

Persistence is idempotent: findings are keyed on (scan_id, fingerprint),
evidence links on (finding_id, evidence_id) and rule versions on
(rule_id, version), so re-running a run's writes leaves the database unchanged
and never overwrites triage.
"""

import uuid
from datetime import datetime

from sentinel_analysis import (
    REGISTRY,
    RULESET_VERSION,
    AnalysisResult,
    AssetObs,
    CookieObs,
    EndpointObs,
    EventObs,
    ResponseObs,
    ScanInfo,
    ScanObservations,
    analyze,
)
from sentinel_analysis.parsing import origin_key

from app.models import AnalysisRun, Scan
from app.models.enums import AnalysisStatus, ScanStatus
from app.repositories.analysis import AnalysisRepository

ANALYSABLE_SCAN_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.CANCELLED})


class AnalysisError(Exception):
    """A run that cannot be completed. `code` is stored on the run; it never
    contains target data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def build_observations(repo: AnalysisRepository, scan: Scan) -> ScanObservations:
    allow_untrusted = (scan.config or {}).get("allow_untrusted_tls") is True
    return ScanObservations(
        scan=ScanInfo(str(scan.id), scan.stop_reason, allow_untrusted),
        assets=tuple(AssetObs(str(a.id), a.scheme, a.host, a.port) for a in repo.assets(scan.id)),
        endpoints=tuple(
            EndpointObs(
                id=str(e.id),
                asset_id=str(e.asset_id) if e.asset_id else None,
                method=e.method,
                url=e.url,
                source=e.source,
                fetched=e.fetched,
                status=e.status_code,
                content_type=e.content_type,
                title=e.title,
            )
            for e in repo.endpoints(scan.id)
        ),
        responses=tuple(
            ResponseObs(
                evidence_id=str(ev.id),
                endpoint_id=str(ev.endpoint_id) if ev.endpoint_id else None,
                method=ev.method,
                url=ev.url,
                status=ev.status_code,
                headers=tuple(
                    (str(h[0]), str(h[1]))
                    for h in ev.response_headers
                    if isinstance(h, list) and len(h) == 2  # name, value
                ),
                body_excerpt=ev.body_excerpt,
                truncated=ev.truncated,
            )
            for ev in repo.evidence(scan.id)
        ),
        cookies=tuple(
            CookieObs(str(c.endpoint_id), c.name, c.secure, c.http_only, c.same_site)
            for c in repo.cookies(scan.id)
        ),
        events=tuple(
            EventObs(log.level, log.code, log.message, log.url) for log in repo.logs(scan.id)
        ),
    )


def _asset_key(scheme: str, host: str, port: int) -> str | None:
    bracketed = f"[{host}]" if ":" in host else host
    return origin_key(f"{scheme}://{bracketed}:{port}")


def record_rule_versions(repo: AnalysisRepository) -> None:
    """Insert each current rule version's metadata once. If a stored version
    has different metadata, the code changed a rule without bumping its version:
    refuse rather than attach findings to text that does not describe them."""
    for rule in REGISTRY:
        expected = rule.meta.metadata_hash()
        stored = repo.insert_rule_version(
            rule.meta.id, rule.meta.version, expected, rule.meta.to_dict()
        )
        if stored != expected:
            raise AnalysisError("rule_metadata_conflict")


def persist_result(
    repo: AnalysisRepository, scan: Scan, run: AnalysisRun, result: AnalysisResult
) -> int:
    asset_ids = {
        key: a.id for a in repo.assets(scan.id) if (key := _asset_key(a.scheme, a.host, a.port))
    }
    for candidate in result.candidates:
        finding_id = repo.insert_finding(
            {
                "scan_id": scan.id,
                "assessment_id": scan.assessment_id,
                "target_id": scan.target_id,
                "analysis_run_id": run.id,
                "rule_id": candidate.rule_id,
                "rule_version": candidate.rule_version,
                "category": candidate.category.value,
                "severity": candidate.severity.value,
                "confidence": candidate.confidence.value,
                "detection_type": candidate.detection_type.value,
                "subject_type": candidate.subject_type.value,
                "subject_key": candidate.subject_key,
                "discriminator": candidate.discriminator,
                "asset_id": asset_ids.get(candidate.origin) if candidate.origin else None,
                "endpoint_id": uuid.UUID(candidate.endpoint_id) if candidate.endpoint_id else None,
                "fingerprint": candidate.fingerprint,
                "details": dict(candidate.details),
                "affected_count": candidate.affected_count,
            }
        )
        repo.link_evidence(finding_id, scan.id, [uuid.UUID(e) for e in candidate.evidence_ids])
    return len(result.candidates)


def execute_run(
    repo: AnalysisRepository, scan: Scan | None, run: AnalysisRun, now: datetime
) -> None:
    """Analyse one locked, queued run and complete it. Raises AnalysisError
    for conditions that must fail the run; the caller decides the transaction."""
    if run.ruleset_version != RULESET_VERSION:
        raise AnalysisError("ruleset_version_mismatch")
    if scan is None or scan.status not in ANALYSABLE_SCAN_STATUSES:
        raise AnalysisError("scan_not_analysable")
    record_rule_versions(repo)
    result = analyze(build_observations(repo, scan))
    run.findings_count = persist_result(repo, scan, run, result)
    run.rules_evaluated = len(result.rules_evaluated)
    # The exact rule versions evaluated, so a later comparison can tell whether
    # an absent finding was looked for by the same rule version (ADR 0011).
    versions = {rule.meta.id: rule.meta.version for rule in REGISTRY}
    run.rule_versions = [
        {"rule_id": rule_id, "version": versions[rule_id]}
        for rule_id in sorted(result.rules_evaluated)
        if rule_id in versions
    ]
    run.coverage_notes = list(result.coverage_notes)
    run.rule_errors = [{"rule_id": e.rule_id, "error": e.error} for e in result.rule_errors]
    run.status = AnalysisStatus.COMPLETED
    run.finished_at = now
    repo.flush()


def fail_run(run: AnalysisRun, code: str, now: datetime) -> None:
    run.status = AnalysisStatus.FAILED
    run.error_code = code[:64]
    run.finished_at = now
