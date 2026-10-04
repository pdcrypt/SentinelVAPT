"""Retest comparisons (ADR 0011).

A comparison measures a retest's scan against the baseline scan its retest
assessment pinned, under comparison policy cmp-1. Requesting one only queues
it; the scans/analysis worker computes it in a single transaction from
persisted findings and evidence (no network, no scanner), and stores immutable
records. Nothing here changes a finding, its triage history or any report.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sentinel_analysis import (
    POLICY_VERSION,
    REGISTRY,
    RULESET_VERSION,
    CurrentRun,
    FindingSnapshot,
    State,
    classify,
    coverage,
)
from sentinel_analysis.comparison import ComparisonRecord as ComparisonRecordOut
from sentinel_analysis.comparison import summarize
from sqlalchemy.orm import Session

from app.core.errors import ComparisonNotAllowedError, NotFoundError
from app.models import AnalysisRun, Assessment, Comparison, ComparisonRecord, Finding, Scan
from app.models.comparison import MAX_COVERAGE_EVIDENCE
from app.models.enums import ComparisonStatus, ScanStatus
from app.repositories import (
    AnalysisRepository,
    AssessmentRepository,
    ComparisonRepository,
    ScanRepository,
)
from app.services.analysis import build_observations
from app.services.base import UnitOfWork
from app.services.scope import DEFAULT_PORTS, path_matches


class ComparisonError(Exception):
    """Fails a queued comparison with a code (never target data)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --- requests and reads ---------------------------------------------------------------------


class ComparisonService:
    def __init__(
        self,
        comparisons: ComparisonRepository,
        assessments: AssessmentRepository,
        scans: ScanRepository,
        uow: UnitOfWork,
    ) -> None:
        self.comparisons = comparisons
        self.assessments = assessments
        self.scans = scans
        self.uow = uow

    def request(self, assessment_id: uuid.UUID, scan_id: uuid.UUID) -> tuple[Comparison, bool]:
        """Queue the comparison of a retest scan. Idempotent per (scan, policy):
        returns (comparison, created)."""
        assessment = self.assessments.get(assessment_id)
        if assessment is None:
            raise NotFoundError("assessment not found")
        if assessment.retest_of_assessment_id is None or assessment.baseline_scan_id is None:
            raise ComparisonNotAllowedError(
                "not_a_retest", "only a retest assessment can be compared with its baseline"
            )
        scan = self.scans.get(scan_id)
        if scan is None or scan.assessment_id != assessment.id:
            raise NotFoundError("scan not found in this assessment", field="scan_id")

        existing = self.comparisons.for_scan(scan.id, POLICY_VERSION)
        if existing is not None:
            return existing, False

        if scan.status is not ScanStatus.COMPLETED:
            raise ComparisonNotAllowedError("scan_not_completed", "the scan did not complete")
        current_run = self.comparisons.completed_run(scan.id, prefer_ruleset=RULESET_VERSION)
        if current_run is None:
            raise ComparisonNotAllowedError(
                "analysis_not_completed", "the scan has no completed analysis run"
            )
        baseline_run = self.comparisons.completed_run(
            assessment.baseline_scan_id, prefer_ruleset=current_run.ruleset_version
        )
        if baseline_run is None:  # pragma: no cover  # checked when the retest was created
            raise ComparisonNotAllowedError(
                "baseline_not_analysed", "the baseline scan has no completed analysis"
            )
        parent = self.assessments.get(assessment.retest_of_assessment_id)
        assert parent is not None  # noqa: S101  # foreign key
        previous_id: uuid.UUID | None = None
        if parent.retest_of_assessment_id is not None:
            # Chain: the parent's own comparison of the scan this retest is
            # measured against must exist and be complete (REOPENED needs it).
            previous = self.comparisons.for_scan(assessment.baseline_scan_id, POLICY_VERSION)
            if previous is None:
                raise ComparisonNotAllowedError(
                    "previous_comparison_missing",
                    "compare the parent retest's baseline scan first",
                )
            if previous.status is not ComparisonStatus.COMPLETED:
                raise ComparisonNotAllowedError(
                    "previous_comparison_not_completed",
                    "the parent retest's comparison has not completed",
                )
            previous_id = previous.id

        new_id = self.comparisons.queue(
            {
                "target_id": assessment.target_id,
                "baseline_assessment_id": parent.id,
                "baseline_scan_id": assessment.baseline_scan_id,
                "baseline_run_id": baseline_run.id,
                "current_assessment_id": assessment.id,
                "current_scan_id": scan.id,
                "current_run_id": current_run.id,
                "previous_comparison_id": previous_id,
                "policy_version": POLICY_VERSION,
            }
        )
        self.uow.commit()
        comparison = self.comparisons.for_scan(scan.id, POLICY_VERSION)
        assert comparison is not None  # noqa: S101  # inserted or already present
        return comparison, new_id is not None

    def get(self, comparison_id: uuid.UUID) -> Comparison:
        comparison = self.comparisons.get(comparison_id)
        if comparison is None:
            raise NotFoundError("comparison not found")
        return comparison

    def list_for_assessment(self, assessment_id: uuid.UUID) -> Sequence[Comparison]:
        if self.assessments.get(assessment_id) is None:
            raise NotFoundError("assessment not found")
        return self.comparisons.list_for_assessment(assessment_id)

    def records(
        self,
        comparison_id: uuid.UUID,
        *,
        state: str | None,
        rule_id: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        comparison = self._completed(comparison_id)
        rows = self.comparisons.records(
            comparison.id, state=state, rule_id=rule_id, limit=limit, offset=offset
        )
        return self._expand(comparison, rows)

    def record(self, comparison_id: uuid.UUID, fingerprint: str) -> dict[str, Any]:
        comparison = self._completed(comparison_id)
        row = self.comparisons.record(comparison.id, fingerprint)
        if row is None:
            raise NotFoundError("comparison record not found")
        return self._expand(comparison, [row])[0]

    def _completed(self, comparison_id: uuid.UUID) -> Comparison:
        comparison = self.get(comparison_id)
        if comparison.status is not ComparisonStatus.COMPLETED:
            from app.core.errors import InvalidStateTransitionError

            raise InvalidStateTransitionError(
                f"the comparison is {comparison.status}; records exist only once completed",
                field="status",
            )
        return comparison

    def _expand(
        self, comparison: Comparison, rows: Sequence[ComparisonRecord]
    ) -> list[dict[str, Any]]:
        coverage_ids = self.comparisons.coverage_evidence(
            comparison.id, (r.fingerprint for r in rows)
        )
        finding_ids = [r.baseline_finding_id for r in rows] + [r.current_finding_id for r in rows]
        evidence = self.comparisons.finding_evidence(i for i in finding_ids if i is not None)
        return [
            {
                "fingerprint": r.fingerprint,
                "rule_id": r.rule_id,
                "state": r.state,
                "reasons": list(r.reasons),
                "baseline_finding_id": r.baseline_finding_id,
                "baseline_triage": r.baseline_triage,
                "baseline_evidence_ids": evidence.get(r.baseline_finding_id, [])
                if r.baseline_finding_id
                else [],
                "current_finding_id": r.current_finding_id,
                "current_triage": r.current_triage,
                "current_evidence_ids": evidence.get(r.current_finding_id, [])
                if r.current_finding_id
                else [],
                "coverage_evidence_ids": coverage_ids.get(r.fingerprint, []),
            }
            for r in rows
        ]


# --- execution (worker) ----------------------------------------------------------------------


def _snapshot(finding: Finding) -> FindingSnapshot:
    return FindingSnapshot(
        finding_id=str(finding.id),
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        subject_type=finding.subject_type,
        subject_key=finding.subject_key,
        discriminator=finding.discriminator,
        severity=finding.severity,
        confidence=finding.confidence,
        detection_type=finding.detection_type,
        details=dict(finding.details),
        triage_status=str(finding.status),
    )


def _evaluated_rules(run: AnalysisRun) -> dict[str, int] | None:
    """The rule versions the current run evaluated, or None if that cannot be
    established (a run recorded before Phase 6 with a different ruleset)."""
    if run.rule_versions is not None:
        return {str(r["rule_id"]): int(r["version"]) for r in run.rule_versions}
    if run.ruleset_version == RULESET_VERSION:
        # The ruleset digest covers every rule's id, version and metadata, so
        # equal digests mean exactly this registry's rule versions.
        return {rule.meta.id: rule.meta.version for rule in REGISTRY}
    return None


def _in_scope(subject_type: str, subject_key: str, scope: Any) -> bool:
    """Whether a finding's subject lies inside an authorization record's scope."""
    url = subject_key.split(" ", 1)[1] if subject_type == "endpoint" else subject_key
    try:
        parts = urlsplit(url)
        port = parts.port or DEFAULT_PORTS.get(parts.scheme)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if host not in {h.lower() for h in scope.in_scope_hosts} or port not in scope.allowed_ports:
        return False
    if subject_type != "endpoint":
        return True
    path = parts.path or "/"
    if any(path_matches(path, excluded) for excluded in scope.excluded_paths):
        return False
    return any(path_matches(path, prefix) for prefix in scope.in_scope_path_prefixes)


def compute_records(session: Session, comparison: Comparison) -> tuple[ComparisonRecordOut, ...]:
    """Classify a comparison from persisted data only, without writing. The
    run's findings are share-locked while read (see findings_for_run)."""
    repo = ComparisonRepository(session)
    baseline_run = session.get(AnalysisRun, comparison.baseline_run_id)
    current_run = session.get(AnalysisRun, comparison.current_run_id)
    current_scan = session.get(Scan, comparison.current_scan_id)
    current_assessment = session.get(Assessment, comparison.current_assessment_id)
    if (
        baseline_run is None
        or current_run is None
        or str(baseline_run.status) != "completed"
        or str(current_run.status) != "completed"
    ):
        raise ComparisonError("analysis_not_completed")
    if current_scan is None or current_assessment is None:  # pragma: no cover  # foreign keys
        raise ComparisonError("inputs_missing")

    baseline = repo.findings_for_run(comparison.baseline_scan_id, baseline_run.id)
    current = repo.findings_for_run(comparison.current_scan_id, current_run.id)

    observations = build_observations(AnalysisRepository(session), current_scan)
    cov = coverage(observations)
    scope = current_assessment.authorization
    run = CurrentRun(
        evaluated_rules=_evaluated_rules(current_run),
        rule_errors=frozenset(str(e["rule_id"]) for e in current_run.rule_errors),
        coverage=cov.keys,
        coverage_rules=cov.rules,
        coverage_notes=frozenset(current_run.coverage_notes),
        out_of_scope=frozenset(
            f.fingerprint for f in baseline if not _in_scope(f.subject_type, f.subject_key, scope)
        ),
    )
    history = {
        fp: State(state)
        for fp, state in repo.chain_history(comparison.previous_comparison_id).items()
    }
    return classify([_snapshot(f) for f in baseline], [_snapshot(f) for f in current], run, history)


def execute_comparison(session: Session, comparison: Comparison, now: datetime) -> None:
    """Compute a locked, queued comparison and complete it. Raises
    ComparisonError for conditions that must fail it; the caller owns the
    transaction (the worker runs this inside a savepoint)."""
    repo = ComparisonRepository(session)
    records = compute_records(session, comparison)
    repo.add_records(
        [
            {
                "comparison_id": comparison.id,
                "fingerprint": r.fingerprint,
                "baseline_scan_id": comparison.baseline_scan_id,
                "current_scan_id": comparison.current_scan_id,
                "rule_id": r.rule_id,
                "state": r.state.value,
                "reasons": list(r.reasons),
                "baseline_finding_id": uuid.UUID(r.baseline.finding_id) if r.baseline else None,
                "current_finding_id": uuid.UUID(r.current.finding_id) if r.current else None,
                "baseline_triage": r.baseline.triage_status if r.baseline else None,
                "current_triage": r.current.triage_status if r.current else None,
            }
            for r in records
        ]
    )
    repo.add_coverage(
        [
            {
                "comparison_id": comparison.id,
                "fingerprint": r.fingerprint,
                "current_scan_id": comparison.current_scan_id,
                "evidence_id": uuid.UUID(evidence_id),
            }
            for r in records
            for evidence_id in r.coverage_evidence[:MAX_COVERAGE_EVIDENCE]
        ]
    )
    comparison.summary = {"policy_version": comparison.policy_version, "states": summarize(records)}
    comparison.status = ComparisonStatus.COMPLETED
    comparison.finished_at = now
    session.flush()


def fail_comparison(comparison: Comparison, code: str, now: datetime) -> None:
    comparison.status = ComparisonStatus.FAILED
    comparison.error_code = code[:64]
    comparison.finished_at = now
