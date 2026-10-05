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
- **Signed in, with the API as the authority** (Phase 9 M8, see
  [Sign-in and browser sessions](#sign-in-and-browser-sessions)). Every page
  except sign-in requires a session. Who acted is recorded by the API from
  that session and labelled "signed-in user"; older records are labelled
  *self-asserted*. Who authorized testing is still what the operator enters.
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

The live-stack specs (`E2E_BASE_URL` set) sign in with real accounts made by
the platform's own mechanisms (`tests/e2e/support/accounts.ts`): the first
administrator comes from `python -m app.cli create-admin` run in the backend
container (or from `E2E_ADMIN_USERNAME` / `E2E_ADMIN_PASSWORD` when the stack
already has one), and every other account is created by that administrator
through the account API with a random temporary password. The generated
administrator's credentials are kept in `frontend/.e2e/` (git- and
docker-ignored). The `setup` project signs an operator in through the UI,
completes the required password change and saves the browser state (the
opaque cookie only) for the workflow spec. Without `E2E_BASE_URL`, only the
specs that need no account run.

Since M5 the forms no longer ask who acknowledged an authorization,
prepared a report or made a triage. The server records the signed-in
user, and the pages show the stored labels.

The end-to-end suite runs the whole workflow (A → B → C) through the UI
against a temporary nginx lab target it starts on the compose network
(`tests/e2e/support/lab.ts`). It also runs the browser-facing security
checks (`tests/e2e/security.spec.ts`).

## Sign-in and browser sessions

Phase 9 M8 ([ADR 0014](adr/0014-authentication-and-authorization.md)).

```
browser ──(opaque HttpOnly cookie)──▶ Next.js server ──(Authorization: Bearer <token>)──▶ FastAPI
                                       └─ in-memory session store: cookie id → API token
```

- **Sign-in** (`/login`, a Server Action) sends the username and password to
  `POST /api/v1/auth/login` from the server. The API checks the password,
  throttles and audits; every failure gets the same message. The token it
  returns stays in the Next.js server's memory. The browser gets a cookie
  holding a fresh random id (never the token), and a redirect.
- **The cookie**: `__Host-sv_session`, `HttpOnly`, `Secure`,
  `SameSite=Strict`, `Path=/`, no `Domain`, expiring with the API session's
  absolute expiry. `SESSION_COOKIE_INSECURE=1` drops `Secure` (and the
  `__Host-` prefix) on a development server only; production ignores it.
- **Every API call** adds `Authorization: Bearer <token>` in
  `lib/api/client.ts`, the only place the token is read. Nothing else
  identifies the user: no identity headers, no actor fields.
- **Protected pages.** The proxy sends requests without a session cookie to
  `/login` (writes get 401). The console layout asks `GET /auth/me` on every
  page load, so a revoked or expired session is noticed at once. Which
  projects and records a user sees is decided by the API: non-members get
  "Not found", a role without the permission gets "Not permitted", and a
  global administrator is not a member of every project.
- **Password change.** A user with `must_change_password` (new accounts,
  administrator resets) can reach only `/account/password`; the API refuses
  everything else with `password_change_required`, which the console turns
  into that page. The policy is the API's. A successful change ends every
  session of the user and the console switches to the new one.
- **Ended sessions.** A 401 from the API (idle or absolute expiry, sign-out
  elsewhere, disabled user, password reset) drops the server-side entry and
  sends the browser through `/session/end`, which clears the stale cookie and
  shows the sign-in page. Nothing is retried.
- **Sign-out** (a POST) forgets the session, clears the cookie and revokes the
  API session; it works the same if the API session had already ended.
- **CSRF.** Every state-changing request must come from this origin (Host
  allowlist, exact `Origin`, `Sec-Fetch-Site`), in the proxy and again in each
  Server Action; the cookie is also `SameSite=Strict`. Sign-in is protected
  the same way (no login CSRF).
- **Restarting the console** signs everyone out (the store is in memory); the
  orphaned API sessions expire on their idle timeout and no one holds their
  tokens.

## Administration (Phase 9 M9)

The console exposes the M6/M7 administration API. The API decides every
permission; the console only shows what the API returns, or its refusal.

| Page | API | Who the API allows |
|---|---|---|
| `/account`: your account and this session; link to the password change | `GET /auth/me` | anyone signed in |
| `/admin/users`: accounts (status and role filters, pages of 50), create an account | `GET`/`POST /users` | global administrators (`user.admin`) |
| `/admin/users/{id}`: an account; reset its password; disable it or enable it again; change its global role | `GET /users/{id}`, `POST …/password-reset`, `POST …/disable`, `POST …/enable`, `PATCH …/global-role` | global administrators |
| `/admin/audit`: the platform audit log, with the API's filters and pages | `GET /audit-events` | global administrators (`audit.read_global`) |
| `/projects/{id}/members`: members; add, change role, remove | `GET`/`POST /projects/{id}/members`, `PATCH`/`DELETE …/{user_id}` | project owners (`membership.manage`) |
| `/projects/{id}/audit`: the project's audit log | `GET /projects/{id}/audit-events` | project owners (`audit.read_project`) |
| `/projects/{id}/settings`: rename, delete | `PATCH`/`DELETE /projects/{id}` | project owners (`project.update`, `project.delete`) |

- **Data first, controls second.** Each page asks the API for its data on the
  server. Controls are rendered only when that data loads: a member who is
  not an owner sees "Not permitted" (the API's 403) and no forms, and a
  non-member sees "Not found" (404), including a global administrator, who is
  not a member of every project. A 401 ends the session (M8).
- **Navigation is display only.** "Accounts" and "Platform audit log" appear
  for global administrators (from `/auth/me`). Each project page asks
  `GET /projects/{id}/membership/me` (M10) for the signed-in user's own role,
  shows it ("Your role: Owner"), and offers the Members, Audit log and
  Settings tabs and the settings forms to owners only. That endpoint returns
  only the caller's own project id, user id and role, records nothing, and
  never asks an owner-only endpoint. An unknown role is treated as the least
  privileged, never as an owner. None of this authorizes anything: the API
  decides every request, and a direct visit to an owner page shows its
  refusal.
- **Changes** go through Server Actions with the Host/Origin guard. The API
  enforces every rule and its refusals are shown as given: no self-disable,
  an active administrator always remains, a project always keeps an owner,
  unknown or disabled users cannot be added. After a change the page reloads
  from the API; nothing is shown as done that the API did not confirm.
  Identifiers are path parameters validated as UUIDs; requests carry no
  actor, owner or project fields, and no identity headers.
- **Passwords.** Temporary passwords (new accounts, resets) are typed by the
  administrator, sent once to the API and never shown, stored or logged; the
  password policy is the API's. Disabling, enabling, changing a global role
  and removing a member need a confirmation tick.
- **Accounts (M10).** A disabled account offers "Enable account"; it then
  signs in with its existing password (a pending password change stays
  pending) and its old sessions stay ended. "Change global role" makes an
  account an administrator or a user; its sessions end, and project
  memberships do not change. Your own account offers no self-administration
  (the API refuses it too), a disabled account cannot be promoted, and the
  last active administrator cannot be demoted or disabled.
- **Audit logs are read-only.** Filters (action, outcome, actor type, actor,
  resource, time range, and project on the platform log) are a GET form whose
  values are checked against the API's vocabulary before they are sent; the
  project log is always scoped by its path. Actor labels are the names the
  API stored at the time. Metadata, usernames and project names are shown as
  inert text with control and bidi characters made visible. Links are built
  only from validated UUIDs. Session identifiers are not shown.
- **Not available because the API has no such operation:** deleting
  accounts and editing or deleting audit events (both by design).
