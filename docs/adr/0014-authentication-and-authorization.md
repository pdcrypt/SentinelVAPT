# 0014: Authentication and authorization

- Status: accepted. M1 (schema foundation), M2 (authentication core), M3 (authorization machinery), M4 (authorization enforcement), M5 (trusted actor identity), M6 (audit logging), M7 (user and membership administration) and M8 (browser sessions and frontend login) are implemented; M9 follows.
- Date: 2026-10-04
- Builds on: [ADR 0005](0005-localhost-only-until-auth.md), [ADR 0006](0006-append-only-target-authorizations.md), [ADR 0013](0013-frontend-architecture-and-threat-model.md)

## Context

Phases 1–8 run as a single-operator, localhost-only application with no
platform login. Every actor field is free text supplied by the client
("self-asserted"), and anyone who can reach the console can do anything.
Phase 9 turns SentinelVAPT into an authenticated, multi-user platform. It must
not weaken any existing safety property:

- localhost binding (ADR 0005);
- `local_lab`-only scanning and scope enforcement;
- append-only authorization history;
- immutable reports and comparisons;
- the Phase 8 browser protections.

## Three separate concepts

| Concept | Answers | Stored in | Who changes it |
|---|---|---|---|
| **Platform identity** | Who is signed in? | `users`, `user_credentials`, `sessions` | The user (password), admins (accounts) |
| **Project membership** | What may this user do in this project? | `project_members` | Project owners |
| **Target authorization** | May this target be tested at all, within which scope and window? | `target_authorizations` (Phase 1, unchanged) | Project owners, by recording and acknowledging an authorization |

None implies another:

- **Signing in grants nothing.** A user can only reach projects they are a
  member of.
- **Membership does not authorize testing.** Every scan still requires the
  target's current, active, `local_lab` authorization and scope, checked by the
  API, the worker and the scanner exactly as in Phases 1–3. Platform
  authentication never implies target authorization.
- **The global `admin` role grants no project access** (see "Admin and
  project access").

## Decision

### Authentication boundary and sessions

```
browser ──(HttpOnly session cookie)──▶ Next.js ──(Authorization: Bearer <opaque token>)──▶ FastAPI ──▶ PostgreSQL
```

- **Login.** Next.js calls `POST /api/v1/auth/login` server-side. The
  returned token stays on the Next.js server; the browser gets an `HttpOnly`,
  `SameSite=Strict`, `Path=/` cookie that holds only an opaque reference to
  it (amended in M8: the cookie was first planned to hold the token itself).
  - Name `__Host-sv_session`, with `Secure`. Browsers treat
    `http://localhost` as secure.
  - Only a development server can drop `Secure` (and the prefix), explicitly.
- **Forwarding.** Next.js forwards the token as a bearer token from its
  server-only API client. The token never reaches client JavaScript, client
  bundles or RSC payloads.
- **FastAPI never accepts cookies as credentials.** It authenticates every
  request from the `Authorization` header itself. Because the browser never
  sends a credential that FastAPI accepts, a cross-site request cannot carry
  one, so FastAPI is not CSRF-able.
- **Next.js holds no service credential.** It can only act as the signed-in
  user, which rules out a confused deputy.
- **Server-side sessions** (`sessions` table):
  - Tokens are 256-bit random, opaque and shown once; only their SHA-256 is
    stored.
  - Idle expiry is 30 minutes (`idle_expires_at`, moved forward by activity)
    and absolute expiry 12 hours (`expires_at`, fixed). Both are configurable
    with hard maxima.
  - A new session is always issued at login; presented cookies are never
    adopted, which prevents fixation.
  - All of a user's sessions are revoked on password change, disable and
    global-role change. Logout revokes one.
  - Revocation is final.
- **Passwords:**
  - Argon2id via `argon2-cffi`, at or above the OWASP baseline, rehashed on
    login when parameters change.
  - There is no self-registration. The first admin is created by CLI, then
    admins create users. Password reset is admin-initiated and sets
    `must_change_password`. There is no email.
- **Login responses.** Unknown user, wrong password, disabled user and
  throttled attempts all get the same 401. Unknown users are verified against
  a dummy hash, so timing matches.
- **Throttling.** Per-account exponential backoff and a per-source token
  bucket, both in PostgreSQL. There is no permanent lockout.

**Why not JWT or OIDC now.**

- JWT: revocation and disabled users need server state anyway, and
  revocation and role changes would otherwise lag.
- OIDC/SSO: disproportionate for a localhost tool. It is a Phase 10 candidate
  that would still issue local sessions.
- `fastapi-users`: assumes async SQLAlchemy (conflicts with ADR 0004).

The implementation uses only vetted primitives (`argon2-cffi`, `secrets`,
`hashlib`, `hmac.compare_digest`).

### Global roles

`users.global_role` is one of **`admin`** or **`user`** (CHECK constraint).
There are no other values and no hidden superuser.

- **`admin`:** manages accounts (create, disable, enable, reset password,
  change global role) and reads the global audit log.
- **`user`:** everything else comes from project membership.

#### Admin and project access

The global `admin` role grants **no** implicit project, target, scan,
finding, evidence or report access. An admin who needs project access must
be added as a member by one of the project's owners, like anyone else
(M7 decided against a separate administrator self-grant). There is no code
path where "is admin" substitutes for membership. A test enumerates every project-scoped
route as an admin who is not a member and expects 404.

### Project roles and ownership

`project_members(project_id, user_id, role)` has one row per user and project.
`role` is one of **`owner`**, **`operator`** or **`viewer`**.

| Action | owner | operator | viewer | non-member |
|---|---|---|---|---|
| Read project data, including evidence and report downloads | ✓ | ✓ | ✓ | 404 |
| Update or delete the project | ✓ | 403 | 403 | 404 |
| Manage members | ✓ | 403 | 403 | 404 |
| Create, update or delete targets; record or acknowledge an authorization | ✓ | 403 | 403 | 404 |
| Plan, start, complete or cancel assessments; launch or cancel scans | ✓ | ✓ | 403 | 404 |
| Triage findings; request reports, retests, comparisons and retest reports | ✓ | ✓ | 403 | 404 |
| Read the project audit log | ✓ | 403 | 403 | 404 |

- **Creating a project** makes the creator its owner, in the same
  transaction.
- **Owners add existing users** by username. There are no invitations.
- **At least one owner.** Once a project has members it keeps at least one
  owner until the project is deleted. This is enforced in the database by a
  deferred constraint trigger, serialized per project, so concurrent removals
  cannot leave it ownerless.
- **Acknowledgment is owner-only.** Acknowledging a target authorization is a
  legal attestation, so only owners may do it, and it remains subject to every
  Phase 1 rule (window, scope validation, append-only history).

### Authorization model (FastAPI is the boundary)

- **Default deny.** `get_principal` is attached to the whole API router.
  Exemptions are explicit and minimal: health, readiness, login. Failure is a
  uniform 401.
- **Permissions.** A closed `Permission` enum and one role-to-permission table
  in a single module.
- **Resolving to a project.** Every resource resolves to its project through
  `target_id → targets.project_id`. The resolver and the membership check run
  in one query, with the resource identified by the route's path parameter,
  never by client-supplied project IDs.
- **Response codes.** Not a member (or the resource doesn't exist) gives 404.
  A member without the permission gets 403. Denials are audited.
- **Lists** are filtered by membership in the repositories.
- **Meta-tests** assert that every route declares exactly one permission or
  an explicit exemption.
- **Workers are unchanged.** Authorization happens when work is requested.

### Actor identity

Historical actor text is never rewritten:

| Kind | How it is recognised |
|---|---|
| Authenticated actor | A `*_user_id` column set by the server (M5); the text column is filled with the user's display name, never from the request |
| Historical self-asserted actor | `*_user_id` is NULL on a row from before `platform_settings.authentication_enforced_at`; shown as "self-asserted (before sign-in existed)" |
| System or worker actor | The existing `claimed_by` worker IDs; `actor_type = 'system'` in audit events |

- **Third-party authorizer.** `target_authorizations.authorized_by` names the
  third party who authorized testing. It is not a platform user and stays
  free text.
- **Report authors.** `prepared_by` and `reviewed_by` stay editorial text,
  frozen in report snapshots. The authenticated requester is recorded on the
  report row (`requested_by_user_id`), never in the snapshot, so snapshot
  schemas, digests and byte identity do not change.
- **Request fields removed.** `acknowledged_by` and `triaged_by` are removed
  from requests; the server sets them.
- **M5 migration.** M5 adds the nullable `*_user_id` columns in its own
  migration and extends the existing immutability triggers to freeze them,
  keeping every existing protection verbatim.

### Audit log

`audit_events` is append-only. A trigger refuses `UPDATE`, `DELETE` and
`TRUNCATE`.

| Field | Contents |
|---|---|
| Time | Database time (`occurred_at`, forced) |
| Correlation | `request_id` |
| Actor | `actor_type` (`user`, `system`, `anonymous`); `actor_user_id` (required exactly when the actor type is `user`); `actor_label` |
| Session | `session_id`: the session row's ID, never the token, and not a foreign key so sessions can be pruned |
| Action | `action` (`area.verb`) |
| Outcome | `success`, `denied` or `failure` |
| Target of the action | `project_id`, `resource_type` and `resource_id`. These are historical identifiers, not foreign keys, so the trail outlives deleted projects. |
| Metadata | Constrained (below) |

**Metadata** must be a flat JSON object:

- keys are `lower_snake_case`;
- values are scalars, with strings of at most 256 characters;
- the whole object is at most 4 KB;
- keys naming secrets or captured content (`password`, `token`, `secret`,
  `cookie`, `authorization`, `credential`, `api_key`, `private_key`, `body`,
  `header`) are refused by the database.

**Never logged:** passwords, tokens, cookies, Authorization headers, request
bodies or evidence. Failed logins never store the attempted username string.

**Events written** (M6): login, logout and failed login; user and role
changes; project and membership changes; target changes and authorization
acknowledgment; the assessment lifecycle; scan launch and cancel; triage;
report, retest, comparison and retest-report requests; denied access.

**Atomicity.** Success events are written in the same transaction as the
action.

**Retention** is indefinite. Export, retention policy and hash-chaining are
Phase 10.

### Legacy data

- **No rewrite.** Existing projects and historical records are not rewritten,
  not assigned and not attributed to users. The migration creates no users and
  no memberships.
- **Fail closed.** Once authorization is enforced (M4), projects without
  members are invisible to everyone, including admins.
- **Claiming.** An admin runs a deliberate, idempotent command,
  `python -m app.cli assign-legacy-projects --owner <username> [--project <id>]...` (M7):
  - it assigns an owner only to projects that have **no** members;
  - re-running it changes nothing;
  - each assignment writes `membership.added` with `metadata.legacy_claim = true`.
- **Historical actor text** stays as recorded and is labelled as
  self-asserted.
- **Unchanged:** report snapshots, artifacts, fingerprints, comparisons and
  authorization history.

### Migration strategy

**M1 (revision `e3a7c1f9b2d4`)** is additive:

- it creates `users`, `user_credentials`, `sessions`, `project_members`,
  `audit_events` and `platform_settings` with their constraints and triggers;
- the one change to an existing table replaces the global `uq_projects_name`
  unique constraint with a plain index `ix_projects_name`.

Project names are labels, not identifiers. Global uniqueness would let one
user learn the names of other users' projects. Until M4 the service keeps
returning 409 for a duplicate name, so Phase 1 behaviour is unchanged.
Whether names become unique per owner is decided in M4; nothing in the
schema assumes it.

The downgrade drops the new tables (and their contents) and restores
`uq_projects_name`. It refuses with a clear error if duplicate names exist
by then.

**Later milestones** add their columns in their own additive migrations. M5
adds the actor-identity columns, extending the existing trigger functions
verbatim plus the new frozen columns.

#### `platform_settings`

One typed row (`id = 1`), not a key/value store. It holds
`authentication_enforced_at`, NULL until authentication is enforced (M4/M8)
and then set exactly once. It is the boundary that keeps historical
self-asserted actor values distinguishable from authenticated ones without
rewriting them.

### Database guarantees added in M1

| Table | Guarantees |
|---|---|
| `users` | UUID PK; username unique case-insensitively (`lower(username)`) and matching `^[A-Za-z0-9._-]{3,64}$`; `global_role` IN (`admin`, `user`); `is_active` exactly when `disabled_at` is NULL; never deleted; `id`, `username` and `created_at` frozen |
| `user_credentials` | One per user; only `$argon2id$…` strings of at most 512 characters accepted (plaintext cannot be stored); never deleted; owner frozen |
| `sessions` | `token_sha256` is unique, 64 lowercase hex characters, and is the only token-derived value stored. `expires_at > created_at`. `idle_expires_at` lies after `created_at` and at or before `expires_at`. Identity, token hash, lifetime, user agent and address are frozen. `last_seen_at` and `idle_expires_at` only move forward. Revocation needs a reason, happens once and is final. Only revoked or expired sessions can be deleted. |
| `project_members` | PK `(project_id, user_id)`; `role` IN (`owner`, `operator`, `viewer`); foreign keys to `projects` (CASCADE, only on project deletion) and `users` (RESTRICT); only `role` (and `updated_at`) can change; deferred constraint trigger: a project keeps at least one owner (advisory lock per project) |
| `audit_events` | Append-only (`UPDATE`, `DELETE` and `TRUNCATE` refused); database timestamp; actor consistency; `action` and `resource_type` formats; resource type exactly when resource ID; constrained metadata |
| `platform_settings` | Singleton; cutover set once; never deleted |

### Authentication core (implemented in M2)

M2 establishes **who** the platform user is. It adds no route authorization:
every existing route works exactly as before until M3/M4. It never touches
project membership or target authorization.

#### Endpoints

| Method and path | Result |
|---|---|
| `POST /api/v1/auth/login` | `{username, password}` → 200 with `token`, `token_type: "bearer"`, `user` and `session`; any failure → the uniform 401 |
| `POST /api/v1/auth/logout` | Bearer token → 204; revokes this session (reason `logout`); a second logout → 401 |
| `GET /api/v1/auth/me` | Bearer token → the user and session expiries; no token, no project information |
| `POST /api/v1/auth/password` | Bearer token plus `{current_password, new_password}` → 200 with a **fresh** session token |

- Auth responses carry `Cache-Control: no-store`.
- `401` responses send `WWW-Authenticate: Bearer` with one of two bodies:
  - `{code: "invalid_credentials"}` for logins;
  - `{code: "unauthenticated"}` for sessions.
- A wrong current password is `403 invalid_current_password`. It is not 401,
  because the session is still valid.
- Password-policy violations are `422`, with the field named and the value
  never echoed.
- **No other endpoints:** there is no registration, password reset, user
  administration or membership endpoint.

#### Passwords

- **Hashing:** Argon2id via `argon2-cffi`.
  - Defaults: t=3, m=64 MiB, p=4 (RFC 9106's second recommendation).
  - Settings cannot go below t=2, m=19 MiB, p=1 (the OWASP minimum).
  - Hashes using other parameters are rehashed at the next successful login.
- **Policy:**
  - NFKC-normalized;
  - 12–256 characters, refused rather than truncated above 256;
  - no control characters, not only whitespace;
  - not the username;
  - no composition rules.
- **Unknown users:** login verifies against a dummy hash generated once per
  process with the current parameters, so it costs the same Argon2 work as a
  real account. A test asserts that every login path performs exactly one
  verification.

#### Sessions

- **Tokens:** `secrets.token_urlsafe(32)` (256 bits), generated only after a
  successful login or password change. Only `sha256(token)` is stored, and a
  presented token is never adopted.
- **Expiry:**
  - The absolute expiry is 12 hours, fixed at login.
  - The idle expiry is 30 minutes. It moves forward on use (at most once a
    minute) and never past the absolute expiry or backwards.
- **Validation** rejects:
  - unknown tokens;
  - revoked sessions;
  - sessions of inactive users;
  - idle-expired sessions;
  - absolutely expired sessions.

  All five give the same 401. Only the `Authorization: Bearer` header is
  read; cookies and query parameters never authenticate.
- **Password change** revokes every session of the user, **including the
  current one** (reason `password_changed`), and returns a fresh session. No
  token from before the change keeps working.
- **Disabling a user** (service operation; the admin API is M7) marks them
  inactive and revokes all their sessions (reason `user_disabled`) in one
  transaction. Validation also refuses sessions of inactive users on its own.
- **Lock order:** session rows are locked (`FOR UPDATE`) by validation,
  logout and password change. User rows are locked `FOR NO KEY UPDATE`, so the
  foreign-key checks of concurrent audit inserts never deadlock against
  session locks.

#### Throttling (no extra state table)

Failed attempts are recorded as `audit_events` (`auth.login_failed`,
`auth.password_change_failed`). Each is committed before the uniform failure
is returned. These events are the throttle record, so no second
authentication-state table is needed. Counting is insert-only, so concurrent
failures cannot corrupt a counter. Attempts for one account name are
serialized with a transaction advisory lock.

| | Rule |
|---|---|
| **Per account** | Failures since the account's last successful login or password change, within a 15-minute window. From the 5th failure, each attempt must wait `1 s × 2^(n−5)` after the latest failure, capped at 15 minutes. There is no permanent lockout. |
| **Per source** | 50 failed logins from one address within the window throttle that source. A success does not reset it, so a valid account cannot be used to reset an attacker's source. |

- A throttled attempt is verified like any other, recorded with reason
  `throttled`, and refused with the same 401, even when the password is
  correct.
- Unknown usernames are never stored: only `reason` and the source address.
- The source is the direct peer address. Trusted forwarding of the browser's
  address from the Next.js server was planned for M8 and is deferred (see
  "Not in M8").
- All thresholds are settings with bounds.

#### Bootstrap

```
python -m app.cli create-admin --username <name> --display-name "<name>"
```

- The password comes from a hidden prompt, entered twice, or as one line on
  standard input with `--password-stdin` for automation. It is never accepted
  as an argument and never printed.
- The command refuses if any administrator exists. An advisory lock makes
  concurrent bootstraps safe.
- It enforces the username format and the password policy, and records a
  `user.created` audit event (actor `system`, label `cli:create-admin`).

#### Leak prevention added in M2

- **SQL parameters.** The database engine is created with
  `hide_parameters=True`. Error messages, which are logged, never contain
  bound values such as password or token hashes.
- **422 echoes.** Request-validation responses never echo the submitted value
  of a password or token field. FastAPI's default 422 body includes the
  input; it is removed for these fields.

#### Deferred from M2

| Deferred item | Milestone |
|---|---|
| Route authorization and project membership | M3/M4 |
| Enforcing `must_change_password` on other routes | M3/M4 |
| Recording `authentication_enforced_at` | M4 |
| Remaining audit events and read endpoints | M6 |
| User administration API (create, disable, enable, reset) | M7 |
| Trusted client-address forwarding | Deferred (not in M8; see M8) |
| Browser cookie handling | M8 (implemented) |
| Pruning expired sessions | Later (expired and revoked rows can already be deleted) |

### Authorization machinery (implemented in M3)

M3 adds the machinery only. **No existing route uses it yet**: every route
still behaves as before, and the OpenAPI document is unchanged. M4 attaches it.

#### Modules

| Module | Contents |
|---|---|
| `app/core/authz.py` | `Permission`, the role tables, `ResourceType`, `AccessDecision`, the route descriptors, `AuthorizationConfigError` |
| `app/repositories/authz.py` | `ProjectResolver`: one resolver spec per resource type, the membership filter for lists |
| `app/services/access.py` | `AccessService.authorize_project` / `authorize_global` |
| `app/api/authz.py` | Dependency factories, the default-deny guard, route inventory helpers |
| `app/core/errors.py` | `ForbiddenError` (403 `forbidden`), `PasswordChangeRequiredError` (403 `password_change_required`), the 500 handler for configuration defects |

#### Permissions

Seventeen permissions in two disjoint sets. Unknown or wrong-kind values raise;
they never answer "allowed".

| Permission | viewer | operator | owner |
|---|:-:|:-:|:-:|
| `project.read` | ✓ | ✓ | ✓ |
| `assessment.write` | | ✓ | ✓ |
| `scan.run` | | ✓ | ✓ |
| `finding.triage` | | ✓ | ✓ |
| `report.request` | | ✓ | ✓ |
| `retest.write` | | ✓ | ✓ |
| `project.update`, `project.delete` | | | ✓ |
| `target.manage`, `target.authorize` | | | ✓ |
| `assessment.delete` | | | ✓ |
| `membership.manage`, `audit.read_project` | | | ✓ |

| Global permission | user | admin |
|---|:-:|:-:|
| `project.create`, `catalog.read` | ✓ | ✓ |
| `user.admin`, `audit.read_global` | | ✓ |

The global role grants no project permission, and nothing in project
authorization reads the global role. `scan.run` lets a member request a scan.
It does not authorize the target: the Phase 1 target authorization and the
worker's grant re-validation still decide that.

#### Resolution

Each `ResourceType` has a fixed resolver spec. The spec joins the resource's
own rows to `targets.project_id`, and the same query LEFT JOINs
`project_members` for the caller. Composite resources, such as report
artifacts, comparison records and retest report evidence, are matched on
their full key through their parent, so a child named under the wrong parent
does not exist. A retest assessment resolves only if
`retest_of_assessment_id` is set. Ids come from path parameters only. A
project id in a query string, header or body is never consulted. A malformed
id is "not found", not a 422. More than one row for a key is a defect, and
fails closed.

#### Decision order

1. **No valid session:** 401 with `WWW-Authenticate: Bearer` (M2).
2. **`must_change_password`:** 403 `password_change_required`. This is
   checked before any lookup, so a gated principal learns nothing about
   resources. Only descriptors declared `authenticated(allow_password_change_pending=True)`
   are exempt; M4 gives that to `GET /auth/me`, `POST /auth/logout` and
   `POST /auth/password`.
3. **Missing resource, resource in another project, or caller not a member:**
   404 with the existing body (`"scan not found"`). These three cases are
   indistinguishable.
4. **Member whose role lacks the permission:** 403 `forbidden`.
5. **Lifecycle and target-authorization rules:** the existing 409/422 from
   the services, unchanged.

#### Declaring access (default deny)

Each route declares exactly one descriptor, through `public()`,
`authenticated(...)`, `require_global(permission)` or
`authorize(permission, resource_type, "path_param")`. Composite resources use
`key={...}`. Factories validate their arguments when the route is declared.

The guard `require_access_descriptor` is attached to protected routers. When a
route has no descriptor, more than one, or one of an unknown kind, the guard
raises `AuthorizationConfigError`. That error is logged and answered with a
500 `authorization_error`, never with the endpoint's response.

Descriptors must be declared on the route itself. FastAPI exposes the
declared route at request time, so a descriptor passed to `include_router`
is not seen and the request fails closed.

#### Lists

`ProjectResolver.member_projects(user_id)` and `visible_projects(user_id)`
are the membership filter that M4 applies to `GET /projects`. They have no
global-role branch.

#### Not in M3

The following are deferred to later milestones:

- attaching descriptors and the guard to the existing routes, and route
  meta-tests over the product app (M4);
- auditing denials (M6), as this ADR's "Denials are audited" is not
  implemented yet;
- membership and user administration (M7);
- browser plumbing (M8).

No migration was needed. Composite foreign keys already keep every chain on
one target.

### Authorization enforcement (implemented in M4)

M4 attaches the M3 machinery to every product route. The FastAPI backend is
the authorization boundary. The browser and the Next.js server are not.

#### Route classification

All 66 operations declare exactly one descriptor on the route itself. The
default-deny guard sits on the top-level `/api/v1` router.

| Kind | Count | Routes |
|---|---:|---|
| Public | 3 | `GET /health`, `GET /health/ready`, `POST /auth/login` |
| Authenticated | 4 | `GET /auth/me`, `POST /auth/logout`, `POST /auth/password` (allowed while a password change is pending); `GET /projects` (membership-filtered) |
| Global permission | 4 | `POST /projects` (`project.create`); `GET /rules`, `/report-templates`, `/retest-report-templates` (`catalog.read`) |
| Project permission | 55 | Everything else |

`tests/unit/test_route_inventory.py` holds the expected descriptor of every
operation and checks it against the production app. The test fails on any new
route until that route is classified.

#### Permissions by route family

| Routes | Permission (resource resolved) |
|---|---|
| All reads (details, lists, logs, assets, endpoints, evidence, findings, reports, artifacts, previews, comparisons, records, lineage) | `project.read` |
| `PATCH` / `DELETE /projects/{id}` | `project.update` / `project.delete` |
| `POST /projects/{id}/targets`, `PATCH` / `DELETE /targets/{id}` | `target.manage`, and also `target.authorize` whenever the body acknowledges an authorization (always on create) |
| `POST /targets/{id}/assessments`, `PATCH /assessments/{id}`, start, complete, cancel | `assessment.write` |
| `DELETE /assessments/{id}` | `assessment.delete` |
| `POST /assessments/{id}/scans`, `POST /scans/{id}/cancel` | `scan.run` |
| `POST /findings/{id}/triage` | `finding.triage` |
| `POST /assessments/{id}/reports`, `POST /assessments/{a}/comparisons/{c}/reports` | `report.request` |
| `POST /assessments/{id}/retests`, `POST /assessments/{id}/comparisons` | `retest.write` |

- **Nested ids.** `POST /assessments/{a}/comparisons/{c}/reports` resolves
  the new composite resource `assessment_comparison`. The comparison exists
  only under its own current (retest) assessment.
- **Composite ids.** `GET /comparisons/{c}/records/{fingerprint}` resolves
  the record through its comparison.
- **Representation selectors.** Artifacts and previews resolve through their
  owning report. The format (`{fmt}`) only selects a representation.
- **Ids in request bodies.** Ids such as `scan_id` and `baseline_scan_id`
  are never authorization claims. The services keep checking that they
  belong to the authorized assessment, and a foreign id gets the same 404 as
  a nonexistent one. A `project_id`, owner or role in a body is refused as
  an unknown field.

#### Order of checks

The checks run in this order:

1. session (401);
2. password-change gate (403 `password_change_required`);
3. resource resolution and membership (404);
4. permission (403);
5. the existing service, with its lifecycle and target-authorization rules
   (409/422).

Authorization dependencies run before FastAPI validates path, query and body
parameters. As a result, a malformed id, or one that cannot exist (such as
`/records/xyz`), is now a 404 instead of a 422. A request about a resource
the caller cannot see is a 404 whatever its query or body contains.
Validation errors are only returned to callers who may use the route.

#### Projects

- **Creation.** `POST /projects` makes the authenticated user the first
  owner in the same transaction (`created_by_user_id` is the user). The body
  cannot name an owner, a creator or a role.
- **Listing.** `GET /projects` lists only the caller's member projects. An
  admin without memberships sees an empty list.
- **Names.** Names are unique among the projects of the acting user, under a
  per-user advisory lock. A conflict never reveals the name of a project the
  caller cannot see. Different users may use the same name.

#### Target authorization stays separate

Membership never stands in for the acknowledgment, and `scan.run` never
bypasses the scan grant. A scan launch still fails for:

- an assessment that is not in progress;
- a missing, expired, not-yet-valid or superseded authorization;
- a target that is not `local_lab`;
- an invalid scope;
- another active scan.

Text in an authorization record grants no platform access. Workers are
unchanged:

- They act on persisted, authorized work.
- They revalidate the grant themselves.
- They keep the Phase 3 lock order and never look at memberships.

So removing a member does not cancel work they already queued.

#### Actor identity

Where a service already took an explicit actor, the actor is now the
authenticated user. In M4 that is finding triage: `changed_by` and
`status_changed_by` record the username. The body's `triaged_by` is still
accepted, so the schema is unchanged, but it is ignored.

Self-asserted body fields stay as they are until M5:

- report `prepared_by`;
- authorization `authorized_by` and `acknowledged_by`.

No historical text is rewritten.

#### Legacy projects and the cutover

Projects that predate memberships (or that a server-side command created)
have no members, so nobody sees them, admins included. An operator of the
host claims one explicitly:

```sh
python -m app.cli list-unclaimed-projects
python -m app.cli claim-project --project <uuid> --username <name>
python -m app.cli enforce-authentication
```

`claim-project` makes one active user the first owner (`created_by_user_id`
NULL, a server-side command).

- It is idempotent for the same owner.
- It refuses a project that has members, since that is membership
  management (M7).
- It serializes on the same per-project lock as the last-owner trigger.
- It records a `project.claim` audit event. It never touches historical
  text.

`enforce-authentication` sets `platform_settings.authentication_enforced_at`
to the database time once, and records `platform.auth_enforced`. The M1
trigger refuses any later change. Enforcement itself does not depend on the
timestamp: routes are protected from the moment M4 is deployed. Run the
command at deployment. Actor text written before the recorded time is
treated as self-asserted (M5); text from between deployment and the command
is classified conservatively in the same way. No migration was needed.

#### API contract and frontend

- **OpenAPI.** The only change is `security: HTTPBearer` on the 60 newly
  protected operations, plus two descriptions. No schema changed.
- **Frontend.** The console has no browser session yet, so it receives 401
  until M8. The live-stack Playwright workflow is skipped until M8 provides
  sessions. The other frontend checks are unchanged.

#### Not in M4

| Deferred | Milestone |
|---|---|
| Actor columns; server-set `prepared_by`, `acknowledged_by`; removing `triaged_by` from the schema | M5 |
| Auditing access denials and every state change; audit read endpoints | M6 |
| Membership and user administration APIs; ownership transfer API | M7 |
| Browser login, session cookie held by the Next.js server, 401/403 handling in the console | M8 |

### Trusted actor identity (implemented in M5)

**Client input never determines who performed a security-sensitive
action.** Four questions stay separate:

- authentication: who is calling (the session);
- authorization: may they do it (M3/M4);
- actor identity: who is recorded as having done it (M5);
- target authorization: may the target be tested at all (Phase 1).

#### The actor model (`app/core/actors.py`)

- **`UserActor(user_id, label)`** is built only from the authenticated
  Principal, with `UserActor.of(principal)`.
  - `user_id` is the durable identity.
  - `label` is the display name at the time of the action. It is descriptive
    only and never used to identify anyone.
- **`SystemActor`** (`system:worker`, `system:command`) is a fixed value, not
  a user row. It cannot log in, hold memberships or be named by a client.
- **Workers** record themselves in `claimed_by`, their instance id. They
  never write the requester columns and never stand in for the requester.
- **Service methods** take `actor: UserActor` as an explicit keyword argument
  with no default. `require_user_actor` refuses anything else, including a
  system actor. Nothing is read from global or request-local state.

#### Actor columns

Migration `b8d2f4a6c1e3` is one additive revision. Each new column is a
nullable foreign key to `users`, `ON DELETE RESTRICT`. Users are never
deleted, only disabled; disabled users stay valid actors.

| Operation | Canonical actor (new) | Descriptive text (existing) |
|---|---|---|
| Acknowledge a target authorization (create, re-authorize) | `target_authorizations.acknowledged_by_user_id` | `acknowledged_by` = the actor's display name |
| Create an assessment or a retest | `assessments.created_by_user_id` | none (`created_by` is unused legacy text) |
| Request a scan | `scans.requested_by_user_id` | none; the worker that runs it is `claimed_by` |
| Triage a finding | `finding_status_changes.changed_by_user_id`, `findings.status_changed_by_user_id` | `changed_by`, `status_changed_by` = display name |
| Request a report / retest report | `reports.requested_by_user_id`, `retest_reports.requested_by_user_id` | `prepared_by` = display name (also in the snapshot) |

The trigger `enforce_actor_column(column)` makes the database refuse:

- a new row without its actor;
- any later change of the actor, including a change to NULL.

The exception is `findings.status_changed_by_user_id`, which follows the
latest triage; a triage (a new `status_changed_at`) must name its user.

Rows written before M5 keep NULL. Their text was self-asserted, and no user
is derived from it, because that would be a guess. The text is untouched.
The downgrade drops the columns and their values.

Operations without a durable actor column keep their provenance elsewhere:

- **Projects:** the first owner's membership records the creator.
- **Lifecycle transitions** (start, complete, cancel), **scan cancellation**,
  **comparison requests** (derived data, shared between identical requests)
  and **deletions** have no actor column. Their actors become audit events
  in M6.
- **Password change and logout** act only on the caller's own account and
  session, and already record the session's user in `audit_events` (M2).

#### API contract

The request fields `acknowledged_by`, `prepared_by` and `triaged_by` are
removed. A body naming any actor-like field is refused with 422, whatever
the value: another user's id or username, an admin, a nonexistent id, the
system actor, null or empty, top-level or nested. Duplicate keys are refused
too. Authorization runs first, so a caller without access still gets 404 or
403.

Identity headers (`X-User`, `X-User-Id`, `X-Actor` and similar) are never
read. Responses expose the canonical ids: `acknowledged_by_user_id`,
`created_by_user_id`, `requested_by_user_id`, `changed_by_user_id` and
`status_changed_by_user_id`.

Two client-supplied texts remain, because they name people who are not
platform actors:

- `authorized_by`: the external party granting permission to test;
- `reviewed_by`: the reviewer named on a report.

There is no review workflow yet, so `reviewed_by` is an unverified label.

#### Reports

The snapshot schema, templates, renderers and artifact bytes are unchanged.
New reports carry the requester's display name as `prepared_by`.
Retest-report deduplication still compares content, which includes
`prepared_by`. So identical requests from two users with the same display
name return the first report, which keeps its original requester.

#### Not in M5

| Deferred | Milestone |
|---|---|
| Audit events for every state change and for denials; audit read endpoints | M6 |
| User and membership administration (display-name changes, disabling through the API) | M7 |
| Browser sessions; the console sends no actor fields any more and shows the stored labels | M8 |

### Audit logging and integrity (implemented in M6)

The audit log is the platform's security history. It records:

- **who** acted;
- **when** they acted;
- **what** they did;
- **which** project and resource it concerned;
- **whether** the action was allowed, denied or failed;
- **through which** authenticated session.

Only the server writes it. M6 builds on the M1 `audit_events` table and the
M2 recorder rather than adding a second system.

#### Trust model

- **Who writes events:** the server, from trusted context only. No endpoint
  creates, changes or deletes an event.
- **Human actor:** `actor_user_id` comes from the authenticated Principal
  (`UserActor`). `session_id` is that Principal's session row (never a
  token). `actor_label` is the display name at the time.
- **System actor:** `actor_type = system`. `actor_label` is the worker's id or
  the server command. No user and no session.
- **Anonymous actor:** failed sign-ins and rejected sessions. No user and no
  session; the account or session concerned is the event's resource.
- **Project:** `project_id` is derived from the resource's own rows by the M3
  resolver, never supplied by the caller.
- **Identity input:** request bodies and headers never contribute identity.
  M5 refuses actor fields, and no code reads identity headers.

#### Event taxonomy

The vocabulary is closed: `AuditAction` in `app/core/audit.py`, which is also
the `audit_actions` table. `audit_events.action` is a foreign key to that
table, so an unknown action cannot be stored. The vocabulary is insert-only
and is extended by migrations.

| Area | Actions |
|---|---|
| Authentication | `auth.login`, `auth.login_failed`, `auth.logout`, `auth.password_changed`, `auth.password_change_failed`, `auth.session_rejected`, `auth.password_change_required` |
| Accounts and platform | `user.created`, `user.disabled`, `platform.auth_enforced` |
| Authorization | `authz.denied` |
| Projects | `project.created`, `project.updated`, `project.deleted`, `project.claim` |
| Targets | `target.created`, `target.updated`, `target.deleted`, `target_authorization.created` |
| Assessments | `assessment.created`, `.updated`, `.deleted`, `.started`, `.start_refused`, `.completed`, `.cancelled`; `retest.created` |
| Scans | `scan.requested`, `scan.request_refused`, `scan.cancel_requested` (users); `scan.refused`, `scan.started`, `scan.completed`, `scan.cancelled`, `scan.failed` (workers); `analysis.completed`, `analysis.failed` |
| Findings | `finding.triaged` (from/to status; false positives included) |
| Comparisons and reports | `comparison.requested` / `.completed` / `.failed`; `report.requested` / `.completed` / `.failed`; `retest_report.requested` / `.completed` / `.failed` |

The `.requested` events of idempotent requests (comparisons, retest reports)
are recorded every time, with `created` saying whether anything new was
made. Membership and user administration events arrive with their APIs (M7).

#### Coverage policy (what is not recorded)

These are not recorded:

- successful reads;
- polling and heartbeats;
- analysis progress;
- report claiming (only the outcome is recorded);
- refused lifecycle steps (409);
- validation errors (422);
- anonymous 401s for missing or unknown tokens;
- naturally expired sessions;
- requests for resources that do not exist.

#### Denials

These refusals are recorded with outcome `denied`:

| Refusal | Event | Status | Metadata |
|---|---|---|---|
| A member whose role lacks the permission | `authz.denied` | 403 | permission, reason `insufficient_role`, role |
| A non-member, including a global admin, reaching for a resource that exists in another project | `authz.denied` | 404 | reason `not_member` |
| A missing global permission | `authz.denied` | 403 | reason `insufficient_global_role` |
| A request blocked by the password-change gate | `auth.password_change_required` | 403 | none |
| A scan request refused (target authorization, lifecycle or an active scan) | `scan.request_refused` | 409 | reason |
| An assessment start refused because its target authorization is not usable | `assessment.start_refused` | 409 | reason |
| A worker's claim-time grant check refusing a queued scan | `scan.refused` (system actor) | none | reason |
| A revoked session, or one of a disabled account, presented | `auth.session_rejected` (anonymous actor) | 401 | reason |

A `not_member` denial is filed under the probed resource's project, so that
project's owners see probes of their project. The prober sees nothing.

#### Integrity (database-enforced)

From M1:

- `audit_events` refuses UPDATE, DELETE and TRUNCATE;
- the database sets `occurred_at` itself;
- metadata must be a flat object of scalars, at most 4 KB, with strings of at
  most 256 characters and without secret-like keys.

Added by M6 (migration `c4f7a2e9d1b6`):

- the vocabulary foreign key;
- `session_id` only on human events;
- system events must name their actor;
- the trigger `check_audit_event_actor`: a human event's user must be active,
  and its session must exist and belong to that user.

The service adds a per-action metadata allowlist, which rejects unknown keys,
nested values, control characters and long strings. It also refuses events
from disabled users, checked under a share lock so that it serializes with
disabling the account.

#### Transactions

- **Successful changes:** a change and its event are flushed into the same
  session and committed by the operation's own commit, so they commit
  together or not at all. If the event cannot be written, the change is
  rolled back (fail closed).
- **Denials:** a denial rolls back any unfinished work and commits the event
  alone, then raises, as M2 does for failed logins.
- **Workers:** worker events share the transaction of the transition they
  record.
- **Locks:** no new lock order is introduced. The share lock on the acting
  user is taken last; workers take no user locks.

#### Visibility

| Endpoint | Who | Scope |
|---|---|---|
| `GET /projects/{id}/audit-events` | project owners (`audit.read_project`) | always that project; operators, viewers, non-members and admins without membership are refused as for any project resource; no `session_id` |
| `GET /audit-events` | global admins (`audit.read_global`) | all events, optional `project_id` filter; includes `session_id` |

- **Filters:** action, outcome, actor type, actor user, resource type,
  resource id and a time range. All are typed and closed; unknown values are
  422.
- **Ordering:** time then id, descending.
- **Pagination:** `limit` is at most 100.
- **No counts:** totals are never returned.

#### History

Existing events are never rewritten, and no actor or session is invented for
them. The migration only adds the vocabulary, constraints and a trigger. An
upgrade, downgrade and upgrade leaves every row identical.

### User and membership administration (implemented in M7)

M7 adds the administration APIs on top of M1–M6. It introduces no new
authorization, actor or audit mechanism.

#### Account administration (global admins: `user.admin`)

| Route | Behavior |
|---|---|
| `POST /users` | Create an account (username, display name, temporary password, global role `user` or `admin`). The password is checked by the M2 policy and hashed with Argon2id; the account must change it at first sign-in. |
| `GET /users` | List accounts by username, filtered by `active` and `global_role`, at most 100 per page. |
| `GET /users/{user_id}` | One account. A malformed or unknown id is `404 user not found`. |
| `POST /users/{user_id}/disable` | Disable the account and revoke all its sessions (`user_disabled`) in one transaction. Accounts are never deleted. |
| `POST /users/{user_id}/password-reset` | Replace the credential with a temporary password, revoke all sessions (`revoked_by_admin`) and require a change at the next sign-in. |

Responses carry identity only: id, username, display name, global role,
active and disabled time, password-change flag, last sign-in and creation
time. They never include a password, hash or token, and 422 responses never
echo a password.

**Refusals (409, recorded):**

- an already disabled account;
- disabling or resetting oneself (administrators change their own password
  through `/auth/password`);
- resetting a disabled account;
- a username already taken (case-insensitive);
- disabling the last active administrator.

**The last active administrator.** The platform keeps at least one active
administrator. The service checks under the advisory lock `platform:admins`.
A deferred constraint trigger (`users_keep_admin`, migration `d2b8e6f3a5c7`)
refuses any transaction that disables or demotes the last one, whoever writes
it, including concurrent disables of two administrators.

**Not in M7:**

- enabling a disabled account;
- changing an account's global role;
- an administrator self-grant to projects.

#### Membership administration (project owners: `membership.manage`)

| Route | Behavior |
|---|---|
| `GET /projects/{id}/members` | The project's members (user, display name, role, active, added by, added at). |
| `POST /projects/{id}/members` | Add an active user by username, with role `owner`, `operator` or `viewer`. |
| `PATCH /projects/{id}/members/{user_id}` | Change a member's role. Setting the same role changes and records nothing. |
| `DELETE /projects/{id}/members/{user_id}` | Remove a member. |

- **Resolution.** Member routes resolve the new resource type
  `project_member` from its own row `(project_id, user_id)`. A user of
  another project, or a malformed id, is therefore an ordinary 404.
- **Request bodies.** A body can never name the project, the actor or who
  added the member; such fields are refused as unknown.
- **Access.** Operators and viewers get 403. Non-members, and global admins
  who are not members, get 404.
- **Admin access.** There is no administrator shortcut. A global admin joins
  a project only when one of its owners adds them, which this ADR earlier
  planned as `membership.self_grant` and M7 decided against.

**Ownership invariants.**

- A project with members always keeps an owner. Every change takes the
  per-project advisory lock of M1's deferred last-owner trigger (and of the
  M4 claim command) and then locks the membership row, so a demotion or
  removal of the last owner is refused with a recorded 409, even when
  requests race.
- The trigger remains the backstop for any writer.
- An owner may demote or remove themselves while another owner remains.
  Operators and viewers cannot leave a project by themselves; an owner
  removes them.
- **Refusals (recorded):**
  - an unknown username (404);
  - a disabled user (409);
  - an existing member (409);
  - the last owner (409).

#### Disabled users

A disabled account cannot sign in, and its sessions are revoked. Its
memberships remain and are shown as inactive. It remains the actor of its
history and cannot become the actor of anything new, as enforced by the M6
audit rules.

#### Audit

Actions added to the closed vocabulary:

- `user.password_reset`;
- `user.change_refused` (operation, reason);
- `membership.added` (user, role);
- `membership.role_changed` (user, from, to);
- `membership.removed` (user, role);
- `membership.change_refused` (operation, reason, user).

Account creation and disabling reuse `user.created` (`bootstrap: false`) and
`user.disabled`, now with the administrator as the user actor and their
session. Membership events are filed under the project, so its owners see
them in the project audit log.

As in M6:

- a change and its event commit together, and a failed event rolls the change
  back;
- refusals are committed before the error is raised;
- the migration's vocabulary insert is idempotent, and a downgrade keeps
  every action that an event already uses.

### Browser sessions and frontend login (implemented in M8)

The operator console signs users in with the M2 endpoints and holds their
sessions server-side. FastAPI stays the only authority: it checks passwords,
issues and validates sessions, enforces the password-change gate and decides
every project and resource permission. The console only knows whether the
browser has a session, and shows what the API returns.

#### Architecture

```
browser ──(__Host-sv_session: opaque id)──▶ Next.js server ──(Authorization: Bearer <token>)──▶ FastAPI
                                             └─ session store (memory): SHA-256(id) → token, absolute expiry
```

- **The token never reaches the browser.** The store maps a random 256-bit id
  (the cookie value) to the API token. Not in a cookie, HTML, RSC payload,
  client bundle, URL or browser storage. Keys are the SHA-256 of the id, so
  the store holds no usable cookie value. `lib/api/client.ts` is the only
  code that reads the token and adds `Authorization: Bearer`; source guards
  enforce this and keep every auth module `server-only`.
- **Why not the token in the cookie** (the original plan): an `HttpOnly`
  cookie already keeps it from scripts, but any copy of the cookie (a
  browser profile, a proxy log, a HAR file) would then be an API credential
  usable from anywhere until it expires. An opaque id is useless without
  this server, can be revoked here without the API, and leaks nothing.
- **Why in memory.** The console is one local process (ADR 0005); no second
  session database is introduced. Restarting the console signs everyone out
  and nobody holds the orphaned API tokens, which then expire on their idle
  timeout. A multi-instance deployment would need a shared store; that is
  out of scope.
- **The cookie.** `HttpOnly`, `Secure` (always in production;
  `SESSION_COOKIE_INSECURE=1` drops it on a development server only),
  `SameSite=Strict`, `Path=/`, no `Domain`, `Max-Age` up to the API session's
  absolute expiry (24 hours at most). It is removed with the same attributes.

#### Flows

- **Login** (`/login`, a Server Action): the Host/Origin guard, a size check,
  then `POST /auth/login` anonymously. Every failure (unknown user, wrong
  password, disabled, throttled, malformed) gets the one message "Invalid
  username or password.". On success a fresh id is created, whatever cookie
  the browser sent (no fixation); a session it replaces is revoked. Users
  with `must_change_password` go to `/account/password`.
- **Current user**: the console layout calls `GET /auth/me` on every page load
  and shows the username and an "administrator" label for global admins
  (display only). It never receives ids, tokens or session details.
- **Password change** (`/account/password`): the only page a user with a
  pending change can open; elsewhere the layout and the API's
  `password_change_required` both lead back to it. The form posts to
  `POST /auth/password`; the API's policy and messages apply unchanged (the
  console checks only that the confirmation matches). The API ends every
  session of the user and returns a new one, which replaces the browser
  session under a new id.
- **Logout** (a POST): the entry is removed and the cookie cleared first, then
  `POST /auth/logout` revokes the API session. It succeeds the same way when
  the API session had already ended or the API is unreachable.
- **Ended sessions**: any 401 from the API (idle or absolute expiry, logout
  elsewhere, disabled user, password reset, unknown token) removes the entry,
  is never retried, and sends the browser to `/session/end`, which clears a
  stale cookie and shows the sign-in page. `/session/end` is a GET that never
  touches a live session. A 403 or 404 stays what the API said: "Not
  permitted" or "Not found".

#### Route protection

- The proxy, after its Host and Origin checks, redirects requests without a
  session cookie to `/login` (303) and refuses writes with 401. Public: only
  `/login`, `/session/end` and framework files.
- The `(console)` layout validates the session with the API before rendering;
  without one, no page data can be fetched at all, since the API client has
  no token to send.
- Project access is not checked in the console. A non-member, including a
  global admin, sees "Not found"; a viewer's write shows "Not permitted".

#### CSRF

The browser authenticates with a cookie, so every state-changing request to
the console must prove it comes from the console. The Phase 8 defence is kept
and now also covers sign-in, sign-out and password change:

- the Host must be allowlisted, the `Origin` must be exactly this origin and
  `Sec-Fetch-Site` (when sent) `same-origin`, in the proxy and again as the
  first statement of every Server Action (a source guard checks this);
- the session cookie is `SameSite=Strict`, so a cross-site request does not
  carry it at all;
- GET requests change nothing (`/session/end` only clears a cookie whose
  session is already gone).

Origin verification is a standard CSRF defence when the server requires the
header on every write, as it does here. A synchronizer token would add a
second, competing mechanism without closing a gap.

#### Not in M8

| Deferred | Why |
|---|---|
| Account, member and audit pages in the console | The APIs exist (M6/M7) and are the authority; the console pages are UI work for a later milestone. |
| Trusted client-address forwarding to the API | All browser logins reach the API from the console's address, so the per-source login throttle (50 failures in 15 minutes) applies to the console as a whole. Forwarding the browser's address needs a backend trust setting; M8 makes no backend change. The per-account throttle is unaffected. |
| A shared session store | Single local instance (ADR 0005). |
| A return-to URL after sign-in | Avoids an open redirect; sign-in always lands on the overview. |

No backend, database or OpenAPI change was needed.

### Security boundaries preserved

Phase 9 does not change:

- localhost-only binding;
- `local_lab`-only targets and scope enforcement;
- authorization windows;
- append-only authorization history;
- scanner behaviour;
- analysis rules and fingerprints;
- comparison semantics;
- report snapshot schemas, templates and renderers (byte identity);
- the Phase 8 browser protections (Host allowlist, Origin checks, nonce CSP,
  sandboxed previews, hostile-data rendering, server-only API client).

### Milestones

| Milestone | Scope |
|---|---|
| M1 | This ADR and the schema foundation (implemented) |
| M2 | Identity core: Argon2id, admin CLI, login, logout, `me`, password change, sessions, throttling (implemented) |
| M3 | Authorization machinery: `Permission`, role tables, `ResourceType`, resolver, access service, dependencies, password-change gate, default-deny guard (implemented; attached to no route) |
| M4 | Enforcement on all 66 routes, route inventory meta-tests, 404/403, membership-filtered lists, IDOR and role-matrix suites, legacy claim and cutover commands, per-member project names (implemented) |
| M5 | Server-owned actor identity: `*_user_id` columns with write-once triggers, actor fields refused, workers as system actors (implemented) |
| M6 | Audit emission for state changes, denials and worker transitions; closed vocabulary; database-enforced integrity; owner/admin read endpoints (implemented) |
| M7 | Account administration (create, list, disable, password reset) and owner-managed membership with the last-owner and last-admin invariants; legacy claim command since M4 (implemented) |
| M8 | Browser sessions (opaque cookie, server-held token), login, logout, current user, required password change, route protection, 401/403 handling, CSRF review (implemented; account, member and audit pages deferred) |
| M9 | Mutation suite, full regression, live Compose as owner, operator and viewer, documentation |

## Non-goals (Phase 9)

- External targets, active exploitation, AI, CVSS, new scanner capabilities or
  rules, fuzzy identity, cumulative retesting, report signing.
- SSO/OIDC, MFA, email (invitations, reset links), self-registration, API
  tokens.
- Network exposure beyond localhost, SaaS or cloud deployment.
- A least-privilege database role, audit hash-chaining and export.
- Unrelated UI redesign.

## Consequences

- **Phase 9 work is safe to land in pieces.** Every later milestone builds on
  constraints the database already enforces, so even a buggy service cannot
  store a plaintext password or raw token, rewrite an audit event, or leave a
  project ownerless.
- **Legacy projects need a deliberate admin action** after authentication is
  enforced. Until then they are inaccessible by design.
- **Duplicate project names become possible** at the database level. The
  service still refuses them until M4 redefines the rule. In the meantime two
  simultaneous creates with the same name could both succeed, which is
  harmless because names are not identifiers.
