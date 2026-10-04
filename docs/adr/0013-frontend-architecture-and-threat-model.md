# 0013: Frontend architecture and threat model

- Status: accepted
- Date: 2026-10-04
- Builds on: [ADR 0005](0005-localhost-only-until-auth.md), [ADR 0010](0010-evidence-backed-reporting.md), [ADR 0011](0011-retesting-and-scan-comparison.md), [ADR 0012](0012-retest-reporting.md)

## Context

Phases 1–7 expose the whole workflow through a REST API. Phase 8 adds an
operator console for it, without changing the backend, the database, the
scanner, the analysis rules or the report renderers. There is still no
platform login (ADR 0005): the stack is bound to 127.0.0.1, and every name
typed into a form is self-asserted.

The console displays data that is hostile by construction. Target names,
URLs, page titles, response headers and bodies come from the systems being
assessed. Report HTML is generated from them. A browser-facing UI with no
login can also be driven by other pages the operator visits, through CSRF
or DNS rebinding.

## Decision

### The browser talks only to the Next.js server

- Pages are server components. They call a typed, `server-only` API client
  (`src/lib/api`) at `API_INTERNAL_URL`, which never reaches the browser.
- Writes are Server Actions on the Next.js server; report downloads and
  previews are route handlers under `/artifacts/`.
- No `NEXT_PUBLIC_*` variable exists. A lint rule forbids one, a unit test
  scans the source, and an e2e test scans the built client chunks for the
  API address.
- Request and response types are generated from the API's OpenAPI document
  (`openapi-typescript`, a development dependency). `npm run api:check`
  detects drift.
- No backend endpoint was added. Index pages (reports, retests, retest
  reports, findings) walk projects → assessments using the API's existing
  page limits.

### The API stays authoritative

- The UI never computes a finding, severity, fingerprint, comparison state
  or remediation result.
- Comparison states are shown exactly as stored, in upper case (`FIXED`,
  `NOT_RETESTED`).
- Triage is a separate badge, always labelled "Triage" or "Triage status
  (when compared)". It never appears in a comparison-state cell.
- Descriptions of states and reason codes are documentation; the stored code
  is always visible next to them.
- The API's error shape `{detail, code, field, reason}` is mapped to
  messages:
  - documented 4xx codes show the API's message, with 409 reason codes
    explained;
  - anything else (5xx, unknown codes, non-JSON bodies, network errors)
    shows a generic message. Response bodies of failed requests are never
    kept.

### Hostile data is inert

- Every API value is rendered as React text through `SafeText`:
  - wrapped in `<bdi>`;
  - control, bidi and invisible characters (U+202E, NUL, zero-width and so
    on) become visible `⟨U+XXXX⟩` markers instead of being dropped.
- URLs are text, never links.
- No raw HTML. ESLint forbids `dangerouslySetInnerHTML`, `srcDoc`,
  `innerHTML`/`outerHTML` assignment, `insertAdjacentHTML`,
  `document.write`, and any `<iframe>` without `sandbox`. A unit test proves
  each of these rules fires.
- Charts are SVG rendered on the server, with no scripts, no inline styles
  and accessible text.

### Report previews are sandboxed

- Report HTML is only ever shown in `<iframe sandbox="">`: no scripts and an
  opaque origin, so no `window.parent`, cookies, storage or application DOM.
- The iframe loads `/artifacts/{reports|retest-reports}/{id}/preview`. That
  route passes on the API's sandboxing CSP, refuses to serve (502) if that
  CSP lacks `sandbox`, and allows framing by the same origin only.
- Downloads are always `Content-Disposition: attachment`, with a sandboxing
  CSP. The `ETag` is the artifact's SHA-256.
- Only an allowlist of upstream headers is forwarded.

### Content-Security-Policy

`src/proxy.ts` sets a fresh nonce per request:

```
script-src 'self' 'nonce-…' 'strict-dynamic'
```

There is no `'unsafe-inline'` for scripts or styles, and `'unsafe-eval'`
only on the development server. The full policy also sets
`frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'` and
`form-action 'self'`. Next.js applies the nonce to its own scripts, and every
page renders per request.

### Host and Origin checks (CSRF and DNS rebinding)

- **Proxy.** `src/proxy.ts` refuses with 421 any request whose `Host` is not
  allowlisted (`FRONTEND_ALLOWED_HOSTS`, default
  `localhost:3000,127.0.0.1:3000`), and any request whose `X-Forwarded-Host`
  differs from its `Host`.
- **Writes.** Every POST, PUT, PATCH and DELETE must carry
  `Origin: http://<Host>`, and `Sec-Fetch-Site`, when sent, must be
  `same-origin`; otherwise 403.
- **Server Actions.** Every Server Action calls `assertWriteAllowed()` first,
  repeating the same decision, so a matcher change cannot silently drop it. A
  unit test enforces that each action starts with it.

### Out of scope

- Authentication, users, roles, sessions, rate limiting.
- Any backend, database or migration change.
- External targets: the target form creates only `local_lab` targets.
- WebSockets: status pages refresh by re-rendering on the server.

## Consequences

- The console demonstrates the whole Phase 1–7 workflow, with no change to
  backend behaviour or data.
- Platform authentication (a later phase) can attach a session in one
  place: the server-side API client and the Server Action guard.
- **Pre-existing backend behaviour, not fixed here:** text containing NUL
  makes the API return a plain 500. The console shows a generic error for
  it.
- **Index-page cost:** the index pages issue one API call per project and
  per assessment, which is acceptable for a local lab.
