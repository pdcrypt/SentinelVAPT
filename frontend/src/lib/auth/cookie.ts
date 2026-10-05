// The browser session cookie (ADR 0014, Phase 9 M8).
//
// Its value is an opaque, random reference to a session held in the Next.js
// server's memory (lib/auth/store.ts); it never contains the API's bearer
// token, a user id or anything else meaningful. HttpOnly keeps it from
// JavaScript, SameSite=Strict keeps it off cross-site requests, Path=/ with
// no Domain plus the __Host- prefix pins it to this exact origin.
//
// Secure is always on in production. Browsers treat http://localhost as a
// secure context, so the local stack works with it. Only a development server
// can turn it off, and only explicitly (SESSION_COOKIE_INSECURE=1), for a
// browser that refuses Secure cookies over plain HTTP.

export const SECURE_COOKIE_NAME = "__Host-sv_session";
export const INSECURE_COOKIE_NAME = "sv_session";
/** The API's hard maximum absolute session lifetime (24 hours). */
export const MAX_COOKIE_SECONDS = 24 * 3600;

type Env = Readonly<Record<string, string | undefined>>;

export function cookieSecure(env: Env = process.env): boolean {
  if (env.NODE_ENV === "production") return true;
  return env.SESSION_COOKIE_INSECURE !== "1";
}

export function cookieName(secure: boolean): string {
  return secure ? SECURE_COOKIE_NAME : INSECURE_COOKIE_NAME;
}

export type CookieOptions = {
  httpOnly: true;
  secure: boolean;
  sameSite: "strict";
  path: "/";
  maxAge: number;
};

/** Options for a cookie that lives until the API session's absolute expiry
 *  (bounded, never negative). */
export function cookieOptions(secure: boolean, expiresAt: Date, now: Date): CookieOptions {
  const seconds = Math.floor((expiresAt.getTime() - now.getTime()) / 1000);
  return {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
    maxAge: Math.max(0, Math.min(seconds, MAX_COOKIE_SECONDS)),
  };
}

/** A Set-Cookie value that removes the cookie (same attributes, Max-Age=0:
 *  a __Host- cookie can only be replaced by one that is also Secure). */
export function expiredCookieHeader(secure: boolean): string {
  return [
    `${cookieName(secure)}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    ...(secure ? ["Secure"] : []),
    "SameSite=Strict",
  ].join("; ");
}
