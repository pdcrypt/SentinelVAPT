import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cookieName,
  cookieOptions,
  cookieSecure,
  expiredCookieHeader,
  INSECURE_COOKIE_NAME,
  MAX_COOKIE_SECONDS,
  SECURE_COOKIE_NAME,
} from "@/lib/auth/cookie";
import {
  authRedirect,
  gate,
  isPublicPath,
  LOGIN_PATH,
  PASSWORD_PATH,
  SESSION_END_PATH,
} from "@/lib/auth/paths";
import { MAX_SESSIONS, SessionStore, sessionStore } from "@/lib/auth/store";

// The pure parts of the browser session (ADR 0014, Phase 9 M8).

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("session cookie", () => {
  it("is always Secure in production, whatever the configuration says", () => {
    expect(cookieSecure({ NODE_ENV: "production" })).toBe(true);
    expect(cookieSecure({ NODE_ENV: "production", SESSION_COOKIE_INSECURE: "1" })).toBe(true);
  });

  it("is Secure in development unless explicitly turned off", () => {
    expect(cookieSecure({ NODE_ENV: "development" })).toBe(true);
    expect(cookieSecure({ NODE_ENV: "development", SESSION_COOKIE_INSECURE: "true" })).toBe(true);
    expect(cookieSecure({ NODE_ENV: "development", SESSION_COOKIE_INSECURE: "1" })).toBe(false);
  });

  it("uses the __Host- prefix whenever it is Secure", () => {
    expect(cookieName(true)).toBe("__Host-sv_session");
    expect(SECURE_COOKIE_NAME.startsWith("__Host-")).toBe(true);
    expect(cookieName(false)).toBe(INSECURE_COOKIE_NAME);
  });

  it("is HttpOnly, SameSite=Strict, host-only, Path=/ and bounded", () => {
    const now = new Date("2026-10-05T10:00:00Z");
    const options = cookieOptions(true, new Date("2026-10-05T22:00:00Z"), now);
    expect(options).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: 12 * 3600,
    });
    expect(options).not.toHaveProperty("domain");
    expect(cookieOptions(false, new Date("2026-10-05T22:00:00Z"), now).secure).toBe(false);
    // Never longer than the API's hard maximum, never negative.
    expect(cookieOptions(true, new Date("2027-10-05T10:00:00Z"), now).maxAge).toBe(
      MAX_COOKIE_SECONDS,
    );
    expect(cookieOptions(true, new Date("2026-10-04T10:00:00Z"), now).maxAge).toBe(0);
  });

  it("is removed with the same attributes it was set with", () => {
    expect(expiredCookieHeader(true)).toBe(
      "__Host-sv_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
    );
    expect(expiredCookieHeader(false)).toBe(
      "sv_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
    );
  });
});

describe("protected routes", () => {
  it("leaves only sign-in, the stale-cookie cleanup and framework files public", () => {
    for (const path of [LOGIN_PATH, SESSION_END_PATH, "/_next/static/chunks/a.js"]) {
      expect(isPublicPath(path), path).toBe(true);
    }
    for (const path of [
      "/",
      "/projects",
      "/projects/1",
      PASSWORD_PATH,
      "/artifacts/reports/x/json",
      "/login/x",
      "/loginx",
      "/session",
      "/session/end/x",
      "/rules",
    ]) {
      expect(isPublicPath(path), path).toBe(false);
    }
  });

  it("sends page loads without a session cookie to sign in and refuses other requests", () => {
    expect(gate("GET", "/projects", false)).toEqual({ ok: false, action: "redirect_to_login" });
    expect(gate("HEAD", "/", false)).toEqual({ ok: false, action: "redirect_to_login" });
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(gate(method, "/projects", false)).toEqual({ ok: false, action: "unauthenticated" });
    }
    expect(gate("GET", PASSWORD_PATH, false).ok).toBe(false);
  });

  it("lets requests with a session cookie through to the server-side checks", () => {
    expect(gate("GET", "/projects", true)).toEqual({ ok: true });
    expect(gate("POST", "/projects", true)).toEqual({ ok: true });
    expect(gate("GET", LOGIN_PATH, false)).toEqual({ ok: true });
    expect(gate("POST", LOGIN_PATH, false)).toEqual({ ok: true });
  });

  it("maps only an ended session and a required password change to a redirect", () => {
    expect(authRedirect({ status: 401, code: "unauthenticated" })).toBe(SESSION_END_PATH);
    expect(authRedirect({ status: 403, code: "password_change_required" })).toBe(PASSWORD_PATH);
    // Everything else keeps the API's meaning and is shown on the page.
    expect(authRedirect({ status: 403, code: "forbidden" })).toBeNull();
    expect(authRedirect({ status: 404, code: "not_found" })).toBeNull();
    expect(authRedirect({ status: 401, code: "invalid_credentials" })).toBeNull();
    expect(authRedirect(new Error("boom"))).toBeNull();
    expect(authRedirect(null)).toBeNull();
  });
});

describe("session store", () => {
  it("hands out random, unguessable ids that are not the token", () => {
    const store = new SessionStore();
    const a = store.create("api-token-a", Date.now() + 60_000);
    const b = store.create("api-token-a", Date.now() + 60_000);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain("api-token-a");
    expect(store.get(a)?.token).toBe("api-token-a");
  });

  it("never stores a usable cookie value", () => {
    const store = new SessionStore();
    const id = store.create("t", Date.now() + 60_000);
    const keys = [...(store as unknown as { entries: Map<string, unknown> }).entries.keys()];
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toBe(id);
    expect(keys[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ignores unknown, malformed and missing ids", () => {
    const store = new SessionStore();
    store.create("t", Date.now() + 60_000);
    for (const id of [null, undefined, "", "x", "a".repeat(43), "../../etc", "a".repeat(44)]) {
      expect(store.get(id), String(id)).toBeNull();
    }
  });

  it("forgets a session at its absolute expiry", () => {
    let now = 1_000_000;
    const store = new SessionStore(() => now);
    const id = store.create("t", now + 1000);
    expect(store.get(id)).not.toBeNull();
    now += 1000;
    expect(store.get(id)).toBeNull();
    expect(store.size).toBe(0);
  });

  it("deletes exactly once and returns what it held", () => {
    const store = new SessionStore();
    const id = store.create("t", Date.now() + 60_000);
    expect(store.delete(id)?.token).toBe("t");
    expect(store.delete(id)).toBeNull();
    expect(store.get(id)).toBeNull();
  });

  it("is bounded: the session closest to expiry makes room", () => {
    const store = new SessionStore(Date.now, 3);
    const base = Date.now() + 60_000;
    const soonest = store.create("a", base + 1);
    const others = [store.create("b", base + 5), store.create("c", base + 3)];
    const newest = store.create("d", base + 9);
    expect(store.size).toBe(3);
    expect(store.get(soonest)).toBeNull();
    for (const id of [...others, newest]) expect(store.get(id)).not.toBeNull();
    expect(MAX_SESSIONS).toBeGreaterThanOrEqual(100);
  });

  it("is one store per server process", () => {
    expect(sessionStore()).toBe(sessionStore());
  });
});
