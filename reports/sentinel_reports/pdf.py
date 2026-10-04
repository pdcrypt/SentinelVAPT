"""PDF rendering: the HTML artifact, printed by WeasyPrint.

WeasyPrint is given a fetcher that refuses every URL (http, https, file, data,
anything) and stops the render on the first attempt, and no base URL. The
report HTML references nothing external, so a fetch attempt means something
unexpected reached the document: the render fails instead of continuing.

WeasyPrint is imported lazily: it needs the Pango system libraries, which only
the PDF path requires.
"""

from typing import Any

from sentinel_reports.errors import PdfResourceBlocked, PdfUnavailable
from sentinel_reports.version import __version__


def _weasyprint() -> Any:
    try:
        import weasyprint
    except OSError as exc:  # Pango or its dependencies are not installed
        raise PdfUnavailable(type(exc).__name__) from None
    return weasyprint


def pdf_renderer_name() -> str:
    return f"sentinel-reports/{__version__} weasyprint/{_weasyprint().__version__}"


def deny_all_fetcher() -> Any:
    """A WeasyPrint URL fetcher that refuses every URL and aborts rendering."""
    from weasyprint.urls import FatalURLFetchingError, URLFetcher

    class Blocked(FatalURLFetchingError):  # type: ignore[misc]  # untyped library base
        pass

    class DenyAllFetcher(URLFetcher):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__(fail_on_errors=True, allowed_protocols=(), allow_redirects=False)
            self.attempts = 0

        def fetch(self, url: str, headers: Any = None) -> Any:
            self.attempts += 1
            raise Blocked("resource fetching is disabled for reports")

    return DenyAllFetcher()


def render_pdf(html: bytes, *, identifier: bytes) -> bytes:
    weasyprint = _weasyprint()
    fetcher = deny_all_fetcher()
    try:
        document = weasyprint.HTML(string=html.decode("utf-8"), base_url=None, url_fetcher=fetcher)
        pdf: bytes = document.write_pdf(
            pdf_identifier=identifier,
            attachments=None,
            pdf_forms=False,
            presentational_hints=False,
            custom_metadata=False,
        )
    except BaseException:
        if fetcher.attempts:
            raise PdfResourceBlocked("a resource fetch was attempted") from None
        raise
    if fetcher.attempts:  # pragma: no cover  # the fetcher aborts on the first attempt
        raise PdfResourceBlocked("a resource fetch was attempted")
    return pdf
