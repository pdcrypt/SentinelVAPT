# Reports

How SentinelVAPT turns an analysed scan into a VAPT report. The design and its
reasoning are in [ADR 0010](adr/0010-evidence-backed-reporting.md).

## Requesting a report

```http
POST /api/v1/assessments/{assessment_id}/reports
{
  "scan_id": "…",                       // a completed scan of this assessment with a completed analysis
  "kind": "draft",                      // or "final" (requires a completed assessment)
  "formats": ["json", "html", "pdf"],   // must include json
  "title": "Lab assessment report",
  "reviewed_by": "Lead",                // optional
  "classification": "confidential",     // internal | confidential | restricted
  "template": "sv-standard@1",          // optional; see GET /report-templates
  "executive_summary_note": "…",        // optional, max 4000 characters
  "scope_note": "…"                     // optional, max 4000 characters
}
```

There is no `prepared_by` field: since Phase 9 M5 the API records the
signed-in user who requested the report (`requested_by_user_id`) and stores
their display name as `prepared_by`. A request naming it is refused (422).

The response is `202` with the report in `queued` state. Its snapshot is
frozen at this moment: triage changes made after the request do not change it.

**Refusals** come back as `409 report_not_allowed`, with one of these `reason`
values:

- `scan_not_completed`;
- `analysis_not_completed`;
- `assessment_not_completed` (final reports only);
- `snapshot_invalid` (the data exceeds a schema bound).

**Lifecycle:**

- `queued → generating → completed`, or
- `queued | generating → failed`, with an `error_code`:
  - `render_error`;
  - `artifact_too_large`;
  - `pdf_unavailable`;
  - `pdf_resource_blocked`;
  - `html_policy_violation`;
  - `template_mismatch`;
  - `snapshot_invalid`;
  - `worker_lost`.

Failed reports are not retried: request a new one.

## Reading a report

| Endpoint | Returns |
| -------- | ------- |
| `GET /reports/{id}` | Status, kind, template, digests, artifact list (format, size, SHA-256, renderer) |
| `GET /reports/{id}/artifacts/json` | The canonical JSON document |
| `GET /reports/{id}/artifacts/html` | Self-contained HTML (download) |
| `GET /reports/{id}/artifacts/pdf` | PDF |
| `GET /reports/{id}/preview` | The HTML inline, under a sandboxing CSP |

## What a report contains (template `sv-standard@1`)

1. **Cover and document control:**
   - report number, title, kind (drafts carry a watermark);
   - classification, prepared and reviewed by, request time;
   - table of contents.
2. **Executive summary:**
   - counts and the highest severity, without CVSS;
   - findings that still require verification;
   - coverage caveats;
   - the assessor's note.
3. **Engagement and authorization:** the authorization record the scan ran
   under: who authorized it, reference, version, validity window, and who
   acknowledged it.
4. **Scope:** the acknowledged allowlist from that same record.
5. **Methodology:**
   - passive testing only;
   - scanner version and the effective limits;
   - whether TLS verification was on;
   - ruleset and the rules evaluated, with their WSTG ids;
   - an explicit statement of what was not tested.
6. **Scan summary and coverage:** timings, counts, coverage notes explained, and
   rule errors.
7. **Findings summary:** a severity chart, tables by severity and by triage
   status, and the list of issues.
8. **Detailed findings, by issue:**
   - severity, confidence, detection type, rule version;
   - OWASP Top 10:2025, WSTG v4.2 and CWE 4.20 mappings with titles;
   - description, what the evidence proves and what it does not prove;
   - remediation and references;
   - every affected instance with its triage status, reason and evidence
     references.
9. **Findings marked as false positives,** with their reasons.
10. **Evidence appendix:**
    - request line, status and peer;
    - captured size;
    - the body SHA-256, labelled as the hash of the unredacted captured bytes;
    - redacted response headers;
    - a short redacted excerpt for body-content issues.
11. **Timeline:** authorization, assessment, scan, analysis and triage events.
12. **Limitations.**
13. **Integrity:** the snapshot and content SHA-256, the template id, version
    and hash, the renderer version, and the snapshot schema.

## Determinism and verification

- **Pure rendering.** Rendering is a pure function of the snapshot, the
  template version and the renderer version. Re-rendering a stored snapshot
  gives the same JSON and HTML bytes, and in the same image the same PDF
  bytes.
- **Two digests.**
  - `snapshot_sha256` identifies the exact snapshot.
  - `content_sha256` leaves out the report's identity and request time, so two
    reports of unchanged data with the same inputs have the same content
    digest.
- **Artifact hashes.** Each artifact's SHA-256 is stored and checked by the
  database against the stored bytes. It is also sent as the download's `ETag`.

## Security properties

- No network access while rendering:
  - the PDF engine's fetcher refuses every URL and aborts the render;
  - the report worker has no route to anything but the database.
- No secrets:
  - the snapshot copies an allowlist of fields, all already redacted by the
    scanner;
  - response bodies are never copied, apart from ≤ 1 KB redacted excerpts for
    SV-INF-002 and SV-INF-003.
- No injection:
  - autoescaping, `StrictUndefined`, Jinja2's sandbox, and control-character
    replacement;
  - a post-render HTML allowlist check;
  - link allowlisting;
  - CSP on the document, the preview and downloads;
  - PDF without JavaScript, actions, forms or attachments.
- Immutable records: database triggers keep reports, artifacts and their links
  from changing once written.

## Adding or changing a template

1. Copy the latest template to a new version directory and edit it.
2. Register it in `sentinel_reports/templates.py`.
3. Regenerate `templates.lock.json`. Existing versions must stay byte-identical,
   or they refuse to render.
4. The template-safety tests (no `|safe`, no scripts, no style attributes, no
   external resources) apply to every template.
