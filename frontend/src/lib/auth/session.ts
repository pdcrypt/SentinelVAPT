import "server-only";

import { cookies } from "next/headers";

import { cookieName, cookieOptions, cookieSecure } from "@/lib/auth/cookie";
import { sessionStore } from "@/lib/auth/store";

// The current request's browser session (ADR 0014, Phase 9 M8). Reading works
// everywhere on the server; starting and ending a session set cookies, which
// Next.js allows only in Server Actions and Route Handlers.

async function sessionId(): Promise<string | null> {
  return (await cookies()).get(cookieName(cookieSecure()))?.value ?? null;
}

/** The API bearer token for this request, or null without a live session.
 *  Server-only: the token is used by lib/api/client.ts and nowhere else. */
export async function currentToken(): Promise<string | null> {
  return sessionStore().get(await sessionId())?.token ?? null;
}

/** Whether this request has a live browser session (says nothing about the
 *  API session behind it, which the API checks on every call). */
export async function hasSession(): Promise<boolean> {
  return (await currentToken()) !== null;
}

/** Drops this request's server-side session (the API refused its token).
 *  The cookie is left to /session/end, which can clear it. */
export async function forgetCurrentSession(): Promise<void> {
  sessionStore().delete(await sessionId());
}

/** A session the API just issued (login, password change): stored under a
 *  fresh id that replaces whatever cookie the browser presented, so a planted
 *  cookie is never adopted. Returns the token of the session it replaced. */
export async function startSession(token: string, expiresAt: string): Promise<string | null> {
  const jar = await cookies();
  const secure = cookieSecure();
  const previous = sessionStore().delete(jar.get(cookieName(secure))?.value);
  const expiry = new Date(expiresAt);
  const id = sessionStore().create(token, expiry.getTime());
  jar.set(cookieName(secure), id, cookieOptions(secure, expiry, new Date()));
  return previous?.token ?? null;
}

/** Ends this browser session: removes it from the store and expires the
 *  cookie. Returns the API token it held, if any, so the caller can revoke it. */
export async function endSession(): Promise<string | null> {
  const jar = await cookies();
  const secure = cookieSecure();
  const previous = sessionStore().delete(jar.get(cookieName(secure))?.value);
  jar.set(cookieName(secure), "", { ...cookieOptions(secure, new Date(0), new Date()), maxAge: 0 });
  return previous?.token ?? null;
}
