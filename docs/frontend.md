# Operator console (frontend)

The Next.js operator console for the whole SentinelVAPT workflow. The design
and threat model are in
[ADR 0013](adr/0013-frontend-architecture-and-threat-model.md).

## Ground rules

- **Localhost-only and authorized local lab use only.**
  - The console (port 3000) and the API (port 8000) are bound to 127.0.0.1
    ([ADR 0005](adr/0005-localhost-only-until-auth.md)).
  - Only `local_lab` targets can be created and scanned. Checks are passive
    and non-destructive.
- **No authentication yet.** Names typed into forms (who authorized testing,
  who triaged, who prepared a report) are **self-asserted (no platform login
  yet)**. The UI labels every such name that way.
- **The platform records an authorization; it does not verify it.** It
  enforces the window and scope on every scan, but it cannot check that the
  authorization is genuine.
- **The browser talks only to the console.** The FastAPI API stays
  server-side; the browser never learns its address.
- **The backend is authoritative.** Findings, severities, fingerprints and
  comparison states come from the API and are shown as stored.
- **Comparison state and triage are distinct.**
  - Comparison states appear in upper case (`FIXED`, `DISMISSED`,
    `NOT_RETESTED`, …).
  - Triage appears only as "Triage: …" or "Triage status (when compared)".
  - Triage never changes a comparison already made.
- **No AI.** The deterministic pipeline (scanner, rules, comparison,
  reports) does not use or need an AI service.

## Architecture

```
browser ──HTTP (127.0.0.1:3000)──▶ Next.js (proxy.ts: Host/Origin checks, nonce CSP)
                                     ├─ server components ──▶ src/lib/api (server-only)
                                     ├─ Server Actions (assertWriteAllowed) ──▶ src/lib/api
                                     └─ /artifacts/* routes (downloads, sandboxed previews)
                                                         │
                                                         ▼ API_INTERNAL_URL
                                               FastAPI /api/v1 (compose network)
```

| Path | Purpose |
|---|---|
| `src/proxy.ts` | Host allowlist, Origin check on writes, per-request nonce CSP |
| `src/lib/api/` | Typed server-only client, endpoint functions, error mapping, generated types |
| `src/lib/actions/` | Server Actions (each starts with `assertWriteAllowed()`) |
| `src/lib/artifacts.ts` | Download and preview responses for report artifacts |
| `src/components/` | `SafeText`, badges, evidence viewer, report preview, SVG charts, forms |
| `src/app/` | Pages (below) |

### Pages

| Route | Contents |
|---|---|
| `/projects`, `/projects/[id]` | Projects, their targets and assessments; create a project |
| `/projects/[id]/targets` | Targets; create a local lab target with its authorization |
| `/projects/[id]/assessments` | The project's assessments |
| `/targets/[id]` | Scope, current authorization and window, authorization history, assessments, re-authorization |
| `/assessments/[id]` | Lifecycle (start, complete, cancel), scans and scan launch, findings summary, scan reports, retests |
| `/scans/[id]` | Status (auto-refreshing), cancel, analysis runs, grant, logs, assets, endpoints, evidence |
| `/evidence/[id]` | One captured exchange, as inert text |
| `/findings`, `/findings?scan=…` | Findings by assessment; findings of a scan with filters and sorting |
| `/findings/[id]` | Rule result, rule metadata, evidence, triage with history |
| `/reports`, `/reports/[id]` | Scan reports: status, metadata, artifacts, downloads, sandboxed preview |
| `/retests`, `/retests/[id]` | Retests: baseline relationship, lineage, scope differences, comparisons, retest reports |
| `/comparisons/[id]` | Summary, state chart, one section per stored state, rule/version and scope differences, retest report request |
| `/comparisons/[id]/records/[fingerprint]` | One record with baseline/retest findings and coverage evidence |
| `/retest-reports`, `/retest-reports/[id]` | Retest reports: status, artifacts, downloads, sandboxed preview |
| `/rules` | The rule catalog this deployment evaluates |

## Security model

| Threat | Control |
|---|---|
| XSS through target data, names or report metadata | React text only, through `SafeText`; ESLint bans raw-HTML APIs; nonce CSP without `unsafe-inline` |
| Bidi/control-character spoofing (U+202E, NUL, zero-width) | `<bdi>` isolation, visible `⟨U+XXXX⟩` markers; nothing silently removed |
| Malicious report HTML | Only in `<iframe sandbox="">` from `/artifacts/…/preview`, with the API's sandboxing CSP (refused without it) |
| Downloads rendered by the browser | Always `attachment`, sandboxing CSP, `nosniff` |
| CSRF from another site | Origin must equal `http://<Host>` on every write; `Sec-Fetch-Site` must be `same-origin` (proxy and every Server Action) |
| DNS rebinding | Host allowlist (421), forged `X-Forwarded-Host` refused |
| API address or internals leaking | `server-only` client; no `NEXT_PUBLIC_*`; generic messages for non-documented errors |
| Clickable target URLs | URLs are displayed as text only |

Configuration (server-side environment only):

| Variable | Default | Meaning |
|---|---|---|
| `API_INTERNAL_URL` | `http://localhost:8000` (compose: `http://backend:8000`) | Where the console reaches the API |
| `FRONTEND_ALLOWED_HOSTS` | `localhost:3000,127.0.0.1:3000` | Accepted `Host` values (plain `host:port` only) |

## Local lab usage

1. Start the stack and the bundled lab target:

   ```sh
   docker compose up -d --build
   docker compose --profile lab up -d lab-target
   ```

2. Open <http://localhost:3000>.
3. **Projects:** create a project.
4. **Add target:**
   - Base URL `http://lab-target/` and in-scope host `lab-target`.
   - Fill in the authorization (who authorized it, the reference, the
     window) and tick the acknowledgement.
5. **Plan an assessment:** on the target page, then **Start assessment** and
   **Launch passive scan**. The scan page refreshes until the scan and its
   analysis have completed.
6. **Findings:** open them from the assessment or scan page, inspect the
   evidence, and record triage decisions.
7. **Request a scan report:** download JSON, HTML or PDF, or preview the HTML
   in the sandbox.
8. **Complete the assessment, then Create a retest.** Start it, scan again,
   and on the retest page **Request comparison**.
9. **Comparison page:** review every state with its reasons and coverage
   evidence, then **Request retest report**.

## Development and tests

```sh
cd frontend
npm run lint && npm run typecheck && npm run format:check
npm run test:unit                # Vitest: guards, client, rendering, charts, lint rules
npm run api:check                # generated API types match openapi/sentinelvapt.openapi.json
E2E_BASE_URL=http://localhost:3000 npx playwright test   # needs the compose stack and Docker
```

Since Phase 9 M4 the API requires a session and project membership. The
console cannot sign in until M8 (ADR 0014), so until then it receives 401
from the API, and the live-stack workflow spec is skipped (it runs only with
`E2E_BROWSER_SESSIONS` set). The other specs and checks are unaffected.

Since M5 the forms no longer ask who acknowledged an authorization,
prepared a report or made a triage. The server records the signed-in
user, and the pages show the stored labels.

The end-to-end suite runs the whole workflow (A → B → C) through the UI
against a temporary nginx lab target it starts on the compose network
(`tests/e2e/support/lab.ts`). It also runs the browser-facing security
checks (`tests/e2e/security.spec.ts`).
