// Generated report HTML is untrusted artifact content (ADR 0013). It is
// never placed in the application document: it loads only inside an iframe
// with an empty sandbox attribute (no scripts, no same-origin access, so no
// window.parent, cookies, storage or application DOM), from a /artifacts/
// route that also sends the API's sandboxing Content-Security-Policy.

export function previewPath(kind: "reports" | "retest-reports", reportId: string): string {
  return `/artifacts/${kind}/${reportId}/preview`;
}

export function ReportPreview({
  kind,
  reportId,
  title,
}: {
  kind: "reports" | "retest-reports";
  reportId: string;
  title: string;
}) {
  return (
    <iframe
      className="preview"
      src={previewPath(kind, reportId)}
      sandbox=""
      referrerPolicy="no-referrer"
      title={title}
      data-testid="report-preview"
    />
  );
}
