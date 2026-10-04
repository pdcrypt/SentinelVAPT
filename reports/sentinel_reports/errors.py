"""Report errors carry a short code. The code is what the backend stores on a
failed report; messages never include snapshot or target data."""


class ReportError(Exception):
    code = "report_error"

    def __init__(self, detail: str = "") -> None:
        super().__init__(f"{self.code}: {detail}" if detail else self.code)
        self.detail = detail


class SnapshotInvalid(ReportError):
    code = "snapshot_invalid"


class TemplateMismatch(ReportError):
    """A template's files no longer match templates.lock.json: it was edited
    without a version bump, so it may not render reports."""

    code = "template_mismatch"


class HtmlPolicyViolation(ReportError):
    """The rendered HTML contains something the output policy forbids (script,
    event handler, external resource, link outside the allowlist)."""

    code = "html_policy_violation"


class PdfResourceBlocked(ReportError):
    code = "pdf_resource_blocked"


class PdfUnavailable(ReportError):
    code = "pdf_unavailable"


class ArtifactTooLarge(ReportError):
    code = "artifact_too_large"
