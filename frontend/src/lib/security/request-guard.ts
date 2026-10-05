// Host and Origin checks for the Next.js boundary (ADR 0013).
//
// The operator UI is localhost-only (ADR 0005) and its session is a cookie
// (Phase 9 M8), so any page on another origin that the operator visits could
// try to drive it:
// cross-site form posts (CSRF) or DNS rebinding (a hostile name resolving to
// 127.0.0.1, which makes the browser send that name as the Host). Every
// request must therefore carry an allowlisted Host, and every state-changing
// request an Origin that is exactly this server's own origin.
//
// Pure functions: used by src/proxy.ts and by the guard inside every Server
// Action, and unit-tested directly.

export const DEFAULT_ALLOWED_HOSTS = ["localhost:3000", "127.0.0.1:3000"] as const;

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const HOST_PATTERN = /^[a-z0-9.-]+(:[0-9]{1,5})?$/;

/** Allowed Host header values, from FRONTEND_ALLOWED_HOSTS (comma-separated
 *  host:port) or the localhost defaults. Values are lower-cased; anything
 *  that is not a plain host[:port] is dropped, so a wildcard or URL in the
 *  configuration can never widen the allowlist. */
export function allowedHosts(
  raw: string | undefined = process.env.FRONTEND_ALLOWED_HOSTS,
): string[] {
  const values = (raw ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter((value) => HOST_PATTERN.test(value));
  return values.length > 0 ? values : [...DEFAULT_ALLOWED_HOSTS];
}

export function isWriteMethod(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

export function isAllowedHost(host: string | null, allowed: readonly string[]): boolean {
  if (host === null) return false;
  return allowed.includes(host.trim().toLowerCase());
}

/** A write is same-origin only if its Origin is exactly http://<Host> and
 *  that Host is allowlisted. A missing Origin is rejected: browsers send it
 *  on every POST, PUT, PATCH and DELETE. */
export function isAllowedOrigin(
  origin: string | null,
  host: string | null,
  allowed: readonly string[],
): boolean {
  if (origin === null || host === null || !isAllowedHost(host, allowed)) return false;
  return origin.toLowerCase() === `http://${host.trim().toLowerCase()}`;
}

export type GuardResult =
  | { ok: true }
  | { ok: false; status: 403 | 421; reason: "host_not_allowed" | "cross_origin_write" };

/** The decision for one request, from its method and headers. */
export function checkRequest(
  method: string,
  headers: { get(name: string): string | null },
  allowed: readonly string[],
): GuardResult {
  const host = headers.get("host");
  const forwardedHost = headers.get("x-forwarded-host");
  if (!isAllowedHost(host, allowed) || (forwardedHost !== null && forwardedHost !== host)) {
    return { ok: false, status: 421, reason: "host_not_allowed" };
  }
  if (isWriteMethod(method)) {
    const fetchSite = headers.get("sec-fetch-site");
    if (
      !isAllowedOrigin(headers.get("origin"), host, allowed) ||
      (fetchSite !== null && fetchSite !== "same-origin")
    ) {
      return { ok: false, status: 403, reason: "cross_origin_write" };
    }
  }
  return { ok: true };
}
