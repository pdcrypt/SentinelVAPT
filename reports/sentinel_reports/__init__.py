"""SentinelVAPT report generation (ADR 0010).

Renders reports from an immutable snapshot of an assessment's persisted,
redacted data. Rendering is offline and deterministic: a pure function of the
snapshot, the template version and the renderer version. This package never
contacts a target, never imports the backend, the scanner or the analysis
engine, and never modifies findings.
"""

from sentinel_reports.canonical import canonical_json, sha256_hex
from sentinel_reports.derive import derive
from sentinel_reports.errors import (
    ArtifactTooLarge,
    HtmlPolicyViolation,
    PdfResourceBlocked,
    PdfUnavailable,
    ReportError,
    SnapshotInvalid,
    TemplateMismatch,
)
from sentinel_reports.render import (
    FORMATS,
    MAX_ARTIFACT_BYTES,
    MEDIA_TYPES,
    Artifact,
    render_report,
)
from sentinel_reports.snapshot import (
    BODY_SHA256_LABEL,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    content_digest,
    snapshot_digest,
    validate_snapshot,
)
from sentinel_reports.templates import DEFAULT_TEMPLATE, TEMPLATES, Template, get_template
from sentinel_reports.version import __version__

__all__ = [
    "BODY_SHA256_LABEL",
    "DEFAULT_TEMPLATE",
    "FORMATS",
    "MAX_ARTIFACT_BYTES",
    "MEDIA_TYPES",
    "SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "TEMPLATES",
    "Artifact",
    "ArtifactTooLarge",
    "HtmlPolicyViolation",
    "PdfResourceBlocked",
    "PdfUnavailable",
    "ReportError",
    "SnapshotInvalid",
    "Template",
    "TemplateMismatch",
    "__version__",
    "canonical_json",
    "content_digest",
    "derive",
    "get_template",
    "render_report",
    "sha256_hex",
    "snapshot_digest",
    "validate_snapshot",
]
