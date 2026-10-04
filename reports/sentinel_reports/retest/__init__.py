"""Retest reports (ADR 0012): one completed comparison, frozen into an
immutable snapshot (sentinelvapt.retest-report/1) and rendered offline into
JSON, HTML and PDF with the Phase 5 security machinery.

Separate from the Phase 5 assessment report: its own schema, template registry
and lockfile, so Phase 5 reports, templates and behavior are untouched.
"""

from sentinel_reports.retest.derive import derive_retest
from sentinel_reports.retest.render import (
    DEFAULT_RETEST_TEMPLATE,
    RETEST_DOCUMENT_SCHEMA_VERSION,
    RETEST_TEMPLATES,
    get_retest_template,
    render_retest_report,
    verified_retest_hash,
)
from sentinel_reports.retest.snapshot import (
    RETEST_SCHEMA_VERSION,
    STATES,
    evidence_entry_sha256,
    records_sha256,
    retest_content_digest,
    retest_snapshot_digest,
    validate_retest_snapshot,
)

__all__ = [
    "DEFAULT_RETEST_TEMPLATE",
    "RETEST_DOCUMENT_SCHEMA_VERSION",
    "RETEST_SCHEMA_VERSION",
    "RETEST_TEMPLATES",
    "STATES",
    "derive_retest",
    "evidence_entry_sha256",
    "get_retest_template",
    "records_sha256",
    "render_retest_report",
    "retest_content_digest",
    "retest_snapshot_digest",
    "validate_retest_snapshot",
    "verified_retest_hash",
]
