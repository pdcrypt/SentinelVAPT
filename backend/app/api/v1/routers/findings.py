import uuid
from collections.abc import Sequence
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sentinel_analysis import REGISTRY, RULESET_VERSION

from app.api.deps import FindingServiceDep, Limit, Offset
from app.models import AnalysisRun, Evidence, Finding, FindingStatusChange
from app.models.enums import FindingStatus
from app.schemas.finding import (
    AnalysisRunRead,
    CategoryLiteral,
    ConfidenceLiteral,
    DetectionTypeLiteral,
    FindingDetail,
    FindingRead,
    FindingStatusChangeRead,
    FindingSummary,
    FindingTriage,
    RuleCatalog,
    RuleIdStr,
    SeverityLiteral,
)
from app.schemas.scan import EvidenceRead
from app.services.findings import FindingService

router = APIRouter(tags=["findings"])


def _columns(finding: Finding) -> dict[str, Any]:
    return {c.key: getattr(finding, c.key) for c in Finding.__table__.columns}


def _read(service: FindingService, finding: Finding) -> FindingRead:
    title = str(service.rule_metadata(finding)["title"])
    return FindingRead.model_validate({**_columns(finding), "title": title})


def _detail(service: FindingService, finding: Finding) -> FindingDetail:
    rule = service.rule_metadata(finding)
    return FindingDetail.model_validate(
        {
            **_columns(finding),
            "title": str(rule["title"]),
            "rule": rule,
            "evidence_ids": [e.id for e in service.evidence(finding.id)],
        }
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingRead])
def list_scan_findings(
    scan_id: uuid.UUID,
    service: FindingServiceDep,
    limit: Limit = 50,
    offset: Offset = 0,
    severity: SeverityLiteral | None = None,
    confidence: ConfidenceLiteral | None = None,
    detection_type: DetectionTypeLiteral | None = None,
    category: CategoryLiteral | None = None,
    rule_id: Annotated[RuleIdStr | None, Query()] = None,
    status: FindingStatus | None = None,
) -> list[FindingRead]:
    filters = {
        name: str(value)
        for name, value in {
            "severity": severity,
            "confidence": confidence,
            "detection_type": detection_type,
            "category": category,
            "rule_id": rule_id,
            "status": status.value if status else None,
        }.items()
        if value is not None
    }
    findings = service.list_for_scan(scan_id, filters, limit=limit, offset=offset)
    return [_read(service, f) for f in findings]


@router.get("/scans/{scan_id}/findings/summary", response_model=FindingSummary)
def scan_findings_summary(scan_id: uuid.UUID, service: FindingServiceDep) -> dict[str, Any]:
    return service.summary_for_scan(scan_id)


@router.get("/assessments/{assessment_id}/findings/summary", response_model=FindingSummary)
def assessment_findings_summary(
    assessment_id: uuid.UUID, service: FindingServiceDep
) -> dict[str, Any]:
    return service.summary_for_assessment(assessment_id)


@router.get("/scans/{scan_id}/analysis", response_model=list[AnalysisRunRead])
def list_analysis_runs(scan_id: uuid.UUID, service: FindingServiceDep) -> Sequence[AnalysisRun]:
    return service.analysis_runs(scan_id)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: uuid.UUID, service: FindingServiceDep) -> FindingDetail:
    return _detail(service, service.get(finding_id))


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceRead])
def list_finding_evidence(finding_id: uuid.UUID, service: FindingServiceDep) -> Sequence[Evidence]:
    return service.evidence(finding_id)


@router.get("/findings/{finding_id}/history", response_model=list[FindingStatusChangeRead])
def list_finding_history(
    finding_id: uuid.UUID, service: FindingServiceDep
) -> Sequence[FindingStatusChange]:
    return service.history(finding_id)


@router.post("/findings/{finding_id}/triage", response_model=FindingDetail)
def triage_finding(
    finding_id: uuid.UUID, data: FindingTriage, service: FindingServiceDep
) -> FindingDetail:
    finding = service.triage(finding_id, data.status, data.reason, data.triaged_by)
    return _detail(service, finding)


@router.get("/rules", response_model=RuleCatalog)
def list_rules() -> RuleCatalog:
    """The rules this deployment evaluates (static; no database access)."""
    return RuleCatalog(
        ruleset_version=RULESET_VERSION, rules=[rule.meta.to_dict() for rule in REGISTRY]
    )
