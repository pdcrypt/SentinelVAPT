import json
import socket
from typing import Any

import pytest

from sentinel_reports import (
    ArtifactTooLarge,
    SnapshotInvalid,
    canonical_json,
    content_digest,
    render_report,
    sha256_hex,
    snapshot_digest,
    validate_snapshot,
)
from sentinel_reports.render import DOCUMENT_SCHEMA_VERSION
from tests.factory import snapshot


def test_json_artifact_is_canonical_and_complete() -> None:
    s = snapshot()
    (artifact,) = render_report(s, ["json"])
    document = json.loads(artifact.content)
    assert artifact.content == canonical_json(document)
    assert set(document) == {
        "schema_version",
        "snapshot_schema_version",
        "report",
        "derived",
        "integrity",
    }
    assert document["schema_version"] == DOCUMENT_SCHEMA_VERSION
    assert document["report"] == s
    validate_snapshot(document["report"])
    assert document["integrity"]["snapshot_sha256"] == snapshot_digest(s)
    assert document["integrity"]["content_sha256"] == content_digest(s)
    assert artifact.sha256 == sha256_hex(artifact.content)
    assert artifact.media_type == "application/json"


def test_rendering_is_deterministic() -> None:
    first = render_report(snapshot(), ["json", "html"])
    second = render_report(snapshot(), ["json", "html"])
    assert [(a.format, a.sha256) for a in first] == [(a.format, a.sha256) for a in second]


def test_only_time_dependent_metadata_changes_between_reports_of_the_same_data() -> None:
    a = snapshot()
    b = snapshot()
    b["document"].update(number="SV-R-000002", created_at="2026-10-05T09:00:00+00:00")
    ja = json.loads(render_report(a, ["json"])[0].content)
    jb = json.loads(render_report(b, ["json"])[0].content)
    assert ja["integrity"]["content_sha256"] == jb["integrity"]["content_sha256"]
    assert ja["derived"] == jb["derived"]
    ja["report"]["document"].update(number=None, created_at=None)
    jb["report"]["document"].update(number=None, created_at=None)
    assert ja["report"] == jb["report"]


def test_invalid_snapshots_do_not_render() -> None:
    s = snapshot()
    s["evidence"].pop()
    with pytest.raises(SnapshotInvalid):
        render_report(s, ["json"])


@pytest.mark.parametrize("formats", [[], ["docx"], ["json", "exe"]])
def test_unsupported_formats(formats: list[str]) -> None:
    with pytest.raises(SnapshotInvalid):
        render_report(snapshot(), formats)


def test_artifact_size_limit() -> None:
    with pytest.raises(ArtifactTooLarge):
        render_report(snapshot(), ["html"], max_artifact_bytes=1000)
    (small,) = render_report(snapshot(), ["json"], max_artifact_bytes=1_000_000)
    assert small.size < 1_000_000


def test_rendering_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    artifacts = render_report(snapshot(), ["json", "html"])
    assert [a.format for a in artifacts] == ["json", "html"]
