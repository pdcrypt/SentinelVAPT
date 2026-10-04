"""PDF rendering through WeasyPrint. Needs the Pango system libraries: skipped
locally if they are missing, required in CI and in the Docker test run."""

import io
import re
import socket
from typing import Any

import pytest

from sentinel_reports import PdfResourceBlocked, render_report
from sentinel_reports.html import LINK_HOSTS
from sentinel_reports.pdf import render_pdf
from tests.factory import snapshot, with_text_everywhere

pytestmark = pytest.mark.pdf

FORBIDDEN_PDF_KEYS = (
    "/JavaScript",
    "/JS",
    "/Launch",
    "/EmbeddedFile",
    "/OpenAction",
    "/AA",
    "/SubmitForm",
    "/ImportData",
    "/RichMedia",
)


def pdf_of(s: dict[str, Any]) -> bytes:
    (artifact,) = render_report(s, ["pdf"])
    assert artifact.media_type == "application/pdf"
    return artifact.content


def _reader(pdf: bytes) -> Any:
    from pypdf import PdfReader

    return PdfReader(io.BytesIO(pdf))


def _text(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in _reader(pdf).pages)


def _all_objects(pdf: bytes) -> list[Any]:
    reader = _reader(pdf)
    objects = []
    for number in range(1, len(reader.xref_objStm) + 10_000):
        try:
            obj = reader.get_object(number)
        except Exception:  # noqa: S112  # sparse object numbers
            continue
        if obj is None:
            continue
        objects.append(obj)
        if len(objects) > 50_000:
            break
    return objects


def test_pdf_is_valid_and_contains_the_report() -> None:
    pdf = pdf_of(snapshot())
    assert pdf.startswith(b"%PDF-")
    reader = _reader(pdf)
    assert len(reader.pages) >= 3
    text = _text(pdf)
    assert "SV-R-000001" in text
    assert "Title of SV-HDR-002" in text
    assert "SHA-256 of the unredacted captured response" in text
    metadata = reader.metadata
    assert metadata is not None and metadata.get("/CreationDate", "").startswith("D:20261004")


def test_pdf_has_no_active_content_and_only_allowlisted_links() -> None:
    pdf = pdf_of(with_text_everywhere("javascript:alert(1) <a href='https://evil.example'>x</a>"))
    uris: list[str] = []
    for obj in _all_objects(pdf):
        if hasattr(obj, "keys"):
            keys = set(obj.keys())
            assert not keys & set(FORBIDDEN_PDF_KEYS), keys
            action = obj.get("/A")
            if action is not None:
                action = action.get_object()
                assert action.get("/S") in ("/URI", "/GoTo", None), action
                if action.get("/S") == "/URI":
                    uris.append(str(action.get("/URI")))
    external = [u for u in uris if not u.startswith("#")]
    hosts = {re.sub(r"^https://([^/]+)/.*$", r"\1", u) for u in external}
    assert hosts <= LINK_HOSTS, hosts
    assert all(u.startswith("https://") for u in external)


def test_pdf_rendering_is_deterministic() -> None:
    assert pdf_of(snapshot()) == pdf_of(snapshot())


@pytest.mark.parametrize(
    "resource",
    [
        '<img src="http://127.0.0.1:9/x.png">',
        '<img src="https://example.invalid/x.png">',
        '<img src="file:///etc/passwd">',
        '<link rel="stylesheet" href="file:///etc/hosts">',
        "<style>body { background: url(http://127.0.0.1:9/x) }</style>",
        '<link rel="attachment" href="file:///etc/passwd">',
        '<img src="data:image/png;base64,iVBORw0KGgo=">',
    ],
)
def test_the_pdf_engine_refuses_every_resource_fetch(resource: str) -> None:
    html = f"<html><head></head><body><p>x</p>{resource}</body></html>".encode()
    with pytest.raises(PdfResourceBlocked):
        render_pdf(html, identifier=b"0" * 16)


def test_pdf_rendering_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    assert pdf_of(snapshot()).startswith(b"%PDF-")


def test_injected_markup_appears_as_text_in_the_pdf() -> None:
    text = _text(pdf_of(with_text_everywhere("<b>bold?</b> {{ 7*7 }}")))
    assert "<b>bold?</b>" in text
    assert "{{ 7*7 }}" in text
