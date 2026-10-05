// Which browser requests need a signed-in session (ADR 0014, Phase 9 M8).
//
// Pure functions: used by src/proxy.ts and unit-tested directly. The proxy
// only checks that a session cookie is present, a cheap early redirect; the
// session itself is validated on the server by the console layout
// (lib/auth/user.ts) and on every API call (lib/api/client.ts), so a forged
// or stale cookie gets no further than this.

export const LOGIN_PATH = "/login";
export const PASSWORD_PATH = "/account/password";
/** Clears a cookie whose server-side session has already ended. */
export const SESSION_END_PATH = "/session/end";

/** Pages reachable without a session. Everything else is protected. */
const PUBLIC_PATHS: ReadonlySet<string> = new Set([LOGIN_PATH, SESSION_END_PATH]);

/** Framework internals that carry no application data. */
const FRAMEWORK_PREFIXES = ["/_next/", "/__nextjs"] as const;

export function isPublicPath(pathname: string): boolean {
  return (
    PUBLIC_PATHS.has(pathname) || FRAMEWORK_PREFIXES.some((prefix) => pathname.startsWith(prefix))
  );
}

export type GateDecision =
  | { ok: true }
  | { ok: false; action: "redirect_to_login" }
  | { ok: false; action: "unauthenticated" };

/** The decision for a request without a valid-looking session cookie:
 *  page loads go to the login page, anything else is refused with 401. */
export function gate(method: string, pathname: string, hasSessionCookie: boolean): GateDecision {
  if (hasSessionCookie || isPublicPath(pathname)) return { ok: true };
  const read = ["GET", "HEAD"].includes(method.toUpperCase());
  return read
    ? { ok: false, action: "redirect_to_login" }
    : { ok: false, action: "unauthenticated" };
}

/** Where an API failure must send the browser, if anywhere: a 401 means the
 *  backend session is gone (expired, revoked, logged out, user disabled or
 *  password reset); a 403 password_change_required means the user may do
 *  nothing but change their password. Other errors are shown on the page. */
export function authRedirect(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const { status, code } = error as { status?: unknown; code?: unknown };
  if (status === 401 && code === "unauthenticated") return SESSION_END_PATH;
  if (status === 403 && code === "password_change_required") return PASSWORD_PATH;
  return null;
}
