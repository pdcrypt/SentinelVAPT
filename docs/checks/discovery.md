# Discovery scan (Phase 2)

Passive discovery of an authorized lab target. Not a vulnerability check: it
records what the target exposes and makes no judgements.

## Requests it sends

| Request | Why |
| ------- | --- |
| `OPTIONS <base_url>` (once) | Read the `Allow` header |
| `GET <base_url>` | Starting page |
| `GET /robots.txt`, `GET /sitemap.xml` (if in scope) | Published lists of paths |
| `GET` on in-scope links found in pages, robots.txt or sitemaps | Map reachable pages |
| Redirect hops (each checked as a new request) | Follow in-scope redirects |

Every request uses the fixed headers `User-Agent: SentinelVAPT/<version>
(authorized-assessment)`, `Accept`, `Accept-Encoding: identity` and
`Connection: close`. No cookies, credentials, request bodies or custom
payloads are ever sent.

## Why it is non-destructive

- Only `GET`, `HEAD` and `OPTIONS` exist in the transport API.
- Forms are recorded (action and method) and never submitted.
- Links with query strings are recorded but not requested (configurable).
- Paths containing words such as `logout`, `delete`, `remove`, `destroy`,
  `reset`, `unsubscribe`, `revoke` or `disable` are recorded but not requested,
  so even a badly designed GET endpoint is not triggered.
- Scripts, images and stylesheets are recorded but not downloaded.
- Hard limits on request count (default 100), rate (default 5/s), response
  size (1 MiB), per-request time (10 s, wall clock), redirects (5), depth (3),
  pages (50) and total time (5 min); configuration cannot exceed the hard caps.

## How it is run

Through the platform only: `POST /api/v1/assessments/{id}/scans` queues a scan
for an in-progress assessment, and the worker builds the scanner's grant from
the database when it claims it (ADR 0008). The only per-scan option is
`allow_untrusted_tls` (below); limits are always the defaults listed above.

## TLS certificate verification

Verification is **on by default** (`DiscoveryConfig.verify_tls = True`): the
certificate must chain to a trusted CA and match the target's hostname, which
is sent as SNI even though the connection is pinned to a checked IP. A lab
target with a self-signed certificate is therefore refused (`tls_error`) unless
the caller explicitly passes `DiscoveryConfig(verify_tls=False)`; through the
API, that is a scan requested with `{"allow_untrusted_tls": true}`, which is
recorded in the scan's `config`.

Security implication of turning it off: the scanner can no longer tell the
real lab target from anything else answering on that address, so a
man-in-the-middle on the lab network could impersonate it and receive the
scanner's requests or feed it fabricated responses. Scope enforcement is
unaffected (hosts, ports, paths and resolved addresses are still checked), and
the scanner sends no credentials, so nothing secret is exposed by the requests
themselves; the risk is to the integrity of the results. Only disable
verification for lab targets on a network you control, and record that it was
disabled alongside the results.

## What it records

Per page: URL, status, depth, content type, sizes, truncation, timing, title,
redirect target, allowed methods (OPTIONS), cookie names and security flags
(never values), and technology hints (`Server`, `X-Powered-By`, meta generator,
well-known session cookie names). Per endpoint: URL, method, where it was
found, whether it was requested and, if not, why. Every exchange produces a
redacted `Evidence` record (headers, a body excerpt of at most 2 KiB, and a
SHA-256 of the captured body).

## Findings

None. Discovery results do not have a `detection_type`; findings
(`automated_detection` / `manual_verification_required`) come from detection
rules in a later phase, which will run on these results.
