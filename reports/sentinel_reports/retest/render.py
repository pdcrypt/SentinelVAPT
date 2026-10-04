"""Retest report rendering: snapshot -> artifacts (ADR 0012).

A pure function of (snapshot, template version, renderer version), like the
Phase 5 renderer whose security machinery it reuses unchanged: the sandboxed,
autoescaping, StrictUndefined Jinja2 environment with control/bidi
neutralization, the post-render HTML allowlist check, the deny-all PDF engine,
canonical JSON and the artifact size cap.

Retest templates have their own registry and lockfile, so the Phase 5 template
registry (and what a Phase 5 report request may select) is unchanged.
"""

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from sentinel_reports.canonical import canonical_json
from sentinel_reports.errors import SnapshotInvalid, TemplateMismatch
from sentinel_reports.html import CSP, HTML_RENDERER, _environment, check_html_policy
from sentinel_reports.pdf import pdf_renderer_name, render_pdf
from sentinel_reports.render import FORMATS, MAX_ARTIFACT_BYTES, Artifact, _artifact
from sentinel_reports.retest.derive import derive_retest
from sentinel_reports.retest.snapshot import (
    RETEST_SCHEMA_VERSION,
    STATES,
    retest_content_digest,
    retest_snapshot_digest,
    validate_retest_snapshot,
)
from sentinel_reports.templates import Template, compute_hash
from sentinel_reports.version import __version__

RETEST_DOCUMENT_SCHEMA_VERSION = "sentinelvapt.retest-report-document/1"
JSON_RENDERER = f"sentinel-reports/{__version__}"
RETEST_LOCKFILE = Path(__file__).resolve().parent.parent / "retest-templates.lock.json"

RETEST_TEMPLATES: dict[tuple[str, int], Template] = {
    ("sv-retest", 1): Template(
        "sv-retest",
        1,
        "SentinelVAPT retest report",
        "Executive summary, retest scope and authorization, baseline vs retest overview, "
        "remediation summary, one section per comparison state, evidence, rule-version "
        "differences, limitations, lineage and methodology.",
    ),
}
DEFAULT_RETEST_TEMPLATE = RETEST_TEMPLATES[("sv-retest", 1)]


def get_retest_template(template_id: str, version: int) -> Template:
    template = RETEST_TEMPLATES.get((template_id, version))
    if template is None:
        raise TemplateMismatch("unknown retest template")
    return template


def retest_locked_hashes() -> dict[str, str]:
    data: dict[str, str] = json.loads(RETEST_LOCKFILE.read_text(encoding="utf-8"))
    return data


def verified_retest_hash(template: Template) -> str:
    actual = compute_hash(template)
    if retest_locked_hashes().get(template.key) != actual:
        raise TemplateMismatch(f"{template.key} does not match retest-templates.lock.json")
    return actual


def retest_integrity(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    ref = snapshot["document"]["template"]
    template = get_retest_template(ref["id"], ref["version"])
    return {
        "snapshot_sha256": retest_snapshot_digest(snapshot),
        "content_sha256": retest_content_digest(snapshot),
        "records_sha256": snapshot["comparison"]["records_sha256"],
        "template": {
            "id": template.id,
            "version": template.version,
            "sha256": verified_retest_hash(template),
        },
        "renderer_version": __version__,
    }


def _html(
    template: Template,
    snapshot: Mapping[str, Any],
    derived: Mapping[str, Any],
    integrity: Mapping[str, Any],
) -> bytes:
    page = _environment(template).get_template("report.html.j2")
    html = page.render(
        r=snapshot,
        d=derived,
        integrity=integrity,
        states=STATES,
        csp=CSP,
        rules=snapshot["rules"],
        evidence_by_id={(e["role"], e["id"]): e for e in snapshot["evidence"]},
    )
    check_html_policy(html)
    return html.encode("utf-8")


def render_retest_report(
    snapshot: Mapping[str, Any],
    formats: Iterable[str] = FORMATS,
    *,
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
) -> tuple[Artifact, ...]:
    wanted = set(formats)
    if not wanted or not wanted <= set(FORMATS):
        raise SnapshotInvalid("unsupported formats")
    validate_retest_snapshot(snapshot)
    ref = snapshot["document"]["template"]
    template = get_retest_template(ref["id"], ref["version"])
    integrity = retest_integrity(snapshot)
    derived = derive_retest(snapshot)

    artifacts: list[Artifact] = []
    if "json" in wanted:
        document = {
            "schema_version": RETEST_DOCUMENT_SCHEMA_VERSION,
            "snapshot_schema_version": RETEST_SCHEMA_VERSION,
            "report": snapshot,
            "derived": {
                "total_records": derived["total_records"],
                "counts": derived["counts"],
                "baseline_active": derived["baseline_active"],
                "metrics": derived["metrics"],
            },
            "integrity": integrity,
        }
        artifacts.append(
            _artifact("json", canonical_json(document), JSON_RENDERER, max_artifact_bytes)
        )
    html: bytes | None = None
    if wanted & {"html", "pdf"}:
        html = _html(template, snapshot, derived, integrity)
    if "html" in wanted and html is not None:
        artifacts.append(_artifact("html", html, HTML_RENDERER, max_artifact_bytes))
    if "pdf" in wanted and html is not None:
        identifier = bytes.fromhex(integrity["snapshot_sha256"])[:16]
        pdf = render_pdf(html, identifier=identifier)
        artifacts.append(_artifact("pdf", pdf, pdf_renderer_name(), max_artifact_bytes))
    return tuple(artifacts)
