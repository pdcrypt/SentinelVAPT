# Local lab target

A static site for **manual** end-to-end scans inside Docker Compose. Most
automated suites do not use it; they start their own servers on 127.0.0.1. The
pages contain no real data; the hidden form value is a fake used to show that
redaction works.

The worker reaches the site as `http://lab-target/` on the compose network, a
private address, so the scanner's lab-only policy allows it. Its host port is
bound to `127.0.0.1:8081` only.

## Header variants (lab only)

So that a retest has something to compare, the lab can serve three sets of
response headers, from read-only files in [variants/](variants/):

| Variant | Headers | Meant as |
|---|---|---|
| `a` (default) | `X-Powered-By: PHP/8.1.0` | the baseline |
| `b` | `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-AspNet-Version: 4.0.30319` | "remediated", with one new disclosure |
| `c` | `X-AspNet-Version: 4.0.30319` | a regression |

Every variant also sends `X-Lab-Variant: a|b|c` (no rule reads it) and nginx's
own `Server: nginx/…` header.

**Lab-only controls.** These change the lab site, never SentinelVAPT. The
active variant is kept in a tmpfs inside the container, so nothing in the
repository or on the host changes:

```powershell
docker compose exec lab-target sh /lab/lab-variant.sh b   # switch (waits until nginx serves it)
docker compose exec lab-target sh /lab/lab-variant.sh     # print the active variant
curl.exe -sI http://127.0.0.1:8081/                       # check: X-Lab-Variant shows it
```

In Git Bash, prefix `docker compose exec` with `MSYS_NO_PATHCONV=1`, or Git
Bash rewrites `/lab/...` into a Windows path.

The scanner stays passive. It follows the lab target's recorded authorization
and scope like any other target, and only reads the headers.

## Retest walkthrough: FIXED, NEW, DISMISSED, REOPENED

**Prerequisites.**

- The stack is running, with the lab profile: `docker compose --profile lab up -d`.
- You are signed in to http://localhost:3000. The first administrator comes
  from `create-admin` in the main README.
- The lab serves variant `a`. Recreating the container always starts with `a`:
  `docker compose --profile lab up -d --force-recreate lab-target`.

Steps marked **(lab)** change the lab site. All other steps are ordinary use
of the console.

1. **Baseline.**
   1. **Projects:** create a project.
   2. **Add target:**
      - name of your choice, base URL `http://lab-target/`, in-scope host
        `lab-target`;
      - record the authorization and tick the acknowledgement.
   3. On the target, plan an assessment, **start** it and **launch a scan**.
      Wait until the scan and its analysis complete.
2. **Triage one finding.** Open the scan's findings and record a triage of
   **SV-HDR-004** (`X-Content-Type-Options: nosniff missing`) as **False
   positive**, with any reason. **Complete** the assessment.
3. **(lab) Remediate:** `docker compose exec lab-target sh /lab/lab-variant.sh b`.
4. **Retest B.**
   1. On the completed assessment, **create a retest**, start it and launch a
      scan.
   2. When the analysis completes, **complete** the retest and **request a
      comparison**.
5. **(lab) Regress:** `docker compose exec lab-target sh /lab/lab-variant.sh c`.
6. **Retest C.** On retest B, **create a retest**, start it, scan, complete,
   and request a comparison.
7. **(lab) Restore:** `docker compose exec lab-target sh /lab/lab-variant.sh a`.

## What you should see

These are the comparison records the procedure produced. Each row is a stored
record on the comparison page, with its reasons; nothing is inferred.

| Rule (subject) | Retest B vs A | Retest C vs B |
|---|---|---|
| SV-HDR-002 CSP missing | **FIXED** (`examined_condition_absent`) | **REOPENED** (`previously_fixed`) |
| SV-HDR-003 framing protection missing | **FIXED** | **REOPENED** (`previously_fixed`) |
| SV-INF-001 `x-powered-by` | **FIXED** | (absent in both; no record) |
| SV-INF-001 `x-aspnet-version` | **NEW** (`first_observed`) | UNCHANGED |
| SV-HDR-004 nosniff missing (false positive in A) | **DISMISSED** (`baseline_false_positive`), never FIXED | **NEW** (`previously_dismissed`) |
| SV-INF-001 `server` | UNCHANGED | UNCHANGED |
| SV-TRN-001 cleartext HTTP | UNCHANGED | UNCHANGED |

**Where to check:**

- **Comparison pages:** each state has its own section, listing the records
  and their reasons.
- **Project page (posture dashboard):** the latest retest outcome shows the
  latest comparison's counts (after step 6, C's: 2 REOPENED, 1 NEW, 3
  UNCHANGED). It links to that comparison. Earlier comparisons remain on their
  own pages.
- **Overview page:** the project's latest retest shows the same counts.

**Not produced by this lab:** STILL_OPEN, NOT_RETESTED and NOT_COMPARABLE.
They need a changed finding detail, a narrowed scope or a rule failure,
respectively. Narrowing a target's scope is ordinary application use, but this
walkthrough does not rely on it.

## Verifying the walkthrough automatically

`frontend/tests/e2e/lab-retest.spec.ts` follows these exact steps through the
API, as a new signed-in account. It switches variants with the same command
and checks:

- the B and C records above;
- the dashboard's counts (API and page) for the latest comparison;
- that the lab is restored to variant `a`.

It is opt-in, because it changes the shared lab target while it runs and adds
a project to the database:

```powershell
docker compose --profile lab up -d
cd frontend
$env:E2E_BASE_URL = "http://localhost:3000"; $env:E2E_LAB_RETEST = "1"
npx playwright test tests/e2e/lab-retest.spec.ts
Remove-Item Env:E2E_BASE_URL, Env:E2E_LAB_RETEST
```

Like the other live specs, it needs an administrator it can sign in as.
Without `E2E_ADMIN_USERNAME` and `E2E_ADMIN_PASSWORD`, it can bootstrap one
only while no administrator exists yet (see [docs/frontend.md](../../docs/frontend.md)).
