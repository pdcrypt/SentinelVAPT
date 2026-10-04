"""Report rendering: snapshot -> artifacts.

A pure function of (snapshot, template version, renderer version): no clock,
no randomness, no database, no network. The request time shown in a report
comes from the snapshot, which was frozen when the report was requested.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sentinel_reports.canonical import canonical_json, sha256_hex
from sentinel_reports.derive import derive
from sentinel_reports.errors import ArtifactTooLarge, SnapshotInvalid
from sentinel_reports.html import HTML_RENDERER, render_html
from sentinel_reports.pdf import pdf_renderer_name, render_pdf
from sentinel_reports.snapshot import (
    SCHEMA_VERSION,
    content_digest,
    snapshot_digest,
    validate_snapshot,
)
from sentinel_reports.templates import get_template, verified_hash
from sentinel_reports.version import __version__

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
FORMATS = ("json", "html", "pdf")
MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}
JSON_RENDERER = f"sentinel-reports/{__version__}"
DOCUMENT_SCHEMA_VERSION = "sentinelvapt.report-document/1"


@dataclass(frozen=True)
class Artifact:
    format: str
    media_type: str
    content: bytes
    sha256: str
    renderer: str

    @property
    def size(self) -> int:
        return len(self.content)


def _artifact(fmt: str, content: bytes, renderer: str, limit: int) -> Artifact:
    if len(content) > limit:
        raise ArtifactTooLarge(fmt)
    return Artifact(fmt, MEDIA_TYPES[fmt], content, sha256_hex(content), renderer)


def integrity_block(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    template_ref = snapshot["document"]["template"]
    template = get_template(template_ref["id"], template_ref["version"])
    return {
        "snapshot_sha256": snapshot_digest(snapshot),
        "content_sha256": content_digest(snapshot),
        "template": {
            "id": template.id,
            "version": template.version,
            "sha256": verified_hash(template),
        },
        "renderer_version": __version__,
    }


def render_report(
    snapshot: Mapping[str, Any],
    formats: Iterable[str] = FORMATS,
    *,
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
) -> tuple[Artifact, ...]:
    wanted = set(formats)
    if not wanted or not wanted <= set(FORMATS):
        raise SnapshotInvalid("unsupported formats")
    validate_snapshot(snapshot)
    template_ref = snapshot["document"]["template"]
    template = get_template(template_ref["id"], template_ref["version"])
    integrity = integrity_block(snapshot)
    derived = derive(snapshot)

    artifacts: list[Artifact] = []
    if "json" in wanted:
        document = {
            "schema_version": DOCUMENT_SCHEMA_VERSION,
            "snapshot_schema_version": SCHEMA_VERSION,
            "report": snapshot,
            "derived": derived,
            "integrity": integrity,
        }
        artifacts.append(
            _artifact("json", canonical_json(document), JSON_RENDERER, max_artifact_bytes)
        )
    html: bytes | None = None
    if wanted & {"html", "pdf"}:
        html = render_html(template, snapshot, derived, integrity)
    if "html" in wanted and html is not None:
        artifacts.append(_artifact("html", html, HTML_RENDERER, max_artifact_bytes))
    if "pdf" in wanted and html is not None:
        # The PDF file identifier is derived from the snapshot, so it is
        # reproducible rather than random.
        identifier = bytes.fromhex(integrity["snapshot_sha256"])[:16]
        pdf = render_pdf(html, identifier=identifier)
        artifacts.append(_artifact("pdf", pdf, pdf_renderer_name(), max_artifact_bytes))
    return tuple(artifacts)
