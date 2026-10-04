import os

import pytest

from sentinel_reports import PdfUnavailable
from sentinel_reports.pdf import pdf_renderer_name


def _pdf_available() -> bool:
    try:
        pdf_renderer_name()
    except PdfUnavailable:
        return False
    return True


PDF_AVAILABLE = _pdf_available()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """PDF tests need WeasyPrint's system libraries. Locally they are skipped
    if those are missing; in CI (and the Docker test run) they must run."""
    if PDF_AVAILABLE:
        return
    if os.environ.get("CI") or os.environ.get("REQUIRE_PDF"):
        raise pytest.UsageError("WeasyPrint system libraries are required (CI / REQUIRE_PDF)")
    skip = pytest.mark.skip(reason="WeasyPrint system libraries not installed")
    for item in items:
        if "pdf" in item.keywords:
            item.add_marker(skip)
