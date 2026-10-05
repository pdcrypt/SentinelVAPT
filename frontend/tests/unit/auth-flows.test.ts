import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Sign-in, sign-out, password change, the authenticated API client and route
// protection (ADR 0014, Phase 9 M8), with Next.js' request APIs replaced by
// an in-memory cookie jar and a fake API.

const env = vi.hoisted(() => {
  class Redirect extends Error {
    constructor(readonly to: string) {
      super(`redirect to ${to}`);
    }
  }
  type Set = { name: string; value: string; options: Record<string, unknown> };
  return {
    Redirect,
    jar: new Map<string, string>(),
    sets: [] as Set[],
    request: new Map<string, string>(),
  };
});

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      env.jar.has(name) ? { name, value: env.jar.get(name) as string } : undefined,
    set: (name: string, value: string, options: Record<string, unknown>) => {
      env.sets.push({ name, value, options });
      if (options.maxAge === 0) env.jar.delete(name);
      else env.jar.set(name, value);
    },
  }),
  headers: async () => ({ get: (name: string) => env.request.get(name.toLowerCase()) ?? null }),
}));

vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new env.Redirect(to);
  },
}));

const { changePasswordAction, loginAction, logoutAction } = await import("@/lib/actions/auth");
const { failed, IDLE } = await import("@/lib/actions/state");
const { ApiError, apiGet, apiWrite } = await import("@/lib/api/client");
const { load } = await import("@/lib/load");
const { downloadArtifact } = await import("@/lib/artifacts");
const { requireUser } = await import("@/lib/auth/user");
const { sessionStore } = await import("@/lib/auth/store");
const { SECURE_COOKIE_NAME } = await import("@/lib/auth/cookie");
const { LOGIN_PATH, PASSWORD_PATH, SESSION_END_PATH } = await import("@/lib/auth/paths");
const { GET: sessionEnd } = await import("@/app/session/end/route");
const { proxy } = await import("@/proxy");
const { WriteRefusedError } = await import("@/lib/security/action-guard");

const COOKIE = SECURE_COOKIE_NAME;
const TOKEN = "api-session-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW_TOKEN = "api-session-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PASSWORD = "correct horse battery staple";
const EXPIRES = new Date(Date.now() + 12 * 3600 * 1000).toISOString();

type Call = { url: string; method: string; headers: Record<string, string>; body: unknown };
let calls: Call[] = [];
type Reply = (call: Call) => Response;
let replies: Record<string, Reply> = {};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function user(overrides: Record<string, unknown> = {}) {
  return {
    id: "6f1c0e3a-1111-4222-8333-444455556666",
    username: "alice",
    display_name: "Alice",
    global_role: "user",
    must_change_password: false,
    ...overrides,
  };
}

function issued(token: string, overrides: Record<string, unknown> = {}) {
  const now = new Date().toISOString();
  return {
    user: user(overrides),
    session: { created_at: now, idle_expires_at: now, expires_at: EXPIRES },
    token,
    token_type: "bearer",
  };
}

const UNAUTHENTICATED = () =>
  json(401, { detail: "Authentication required.", code: "unauthenticated", field: null });

function form(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [k, v] of Object.entries(values)) data.set(k, v);
  return data;
}

/** A browser session as login would leave it. */
function signedIn(token = TOKEN): string {
  const id = sessionStore().create(token, Date.parse(EXPIRES));
  env.jar.set(COOKIE, id);
  return id;
}

async function redirected(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof env.Redirect) return error.to;
    throw error;
  }
  throw new Error("expected a redirect");
}

beforeEach(() => {
  delete (globalThis as Record<symbol, unknown>)[Symbol.for("sentinelvapt.browserSessions")];
  env.jar.clear();
  env.sets.length = 0;
  env.request.clear();
  env.request.set("host", "localhost:3000");
  env.request.set("origin", "http://localhost:3000");
  env.request.set("sec-fetch-site", "same-origin");
  calls = [];
  replies = {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const call: Call = {
        url,
        method: init.method ?? "GET",
        headers: { ...(init.headers as Record<string, string>) },
        body: init.body ? JSON.parse(init.body as string) : undefined,
      };
      calls.push(call);
      const path = new URL(url).pathname.replace(/^\/api\/v1/, "");
      const reply = replies[`${call.method} ${path}`];
      if (!reply) throw new Error(`unexpected API call ${call.method} ${path}`);
      return reply(call);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sign-in", () => {
  it("keeps the API token on the server and gives the browser an opaque HttpOnly cookie", async () => {
    replies["POST /auth/login"] = () => json(200, issued(TOKEN));
    const to = await redirected(loginAction(IDLE, form({ username: "alice", password: PASSWORD })));
    expect(to).toBe("/");

    // FastAPI did the authentication, anonymously, with the password as typed.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers).not.toHaveProperty("Authorization");
    expect(calls[0]!.body).toEqual({ username: "alice", password: PASSWORD });

    const [cookie] = env.sets;
    expect(cookie!.name).toBe("__Host-sv_session");
    expect(cookie!.options).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
    });
    expect(cookie!.options).not.toHaveProperty("domain");
    expect(cookie!.options.maxAge).toBeGreaterThan(11 * 3600);
    expect(cookie!.options.maxAge).toBeLessThanOrEqual(12 * 3600);
    // The cookie is a reference, not the credential.
    expect(cookie!.value).not.toContain(TOKEN);
    expect(cookie!.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sessionStore().get(cookie!.value)?.token).toBe(TOKEN);
  });

  it("sends a user who must change their password to the password change", async () => {
    replies["POST /auth/login"] = () => json(200, issued(TOKEN, { must_change_password: true }));
    const to = await redirected(loginAction(IDLE, form({ username: "alice", password: PASSWORD })));
    expect(to).toBe(PASSWORD_PATH);
    expect(sessionStore().size).toBe(1);
  });

  it("gives every failed sign-in the same answer, without echoing anything", async () => {
    const outcomes: unknown[] = [];
    for (const reply of [
      // wrong password, unknown user, disabled account, throttled: all one 401
      () => json(401, { detail: "Invalid username or password.", code: "invalid_credentials" }),
      () => json(422, { detail: [{ loc: ["body", "password"], msg: "too long" }] }),
    ]) {
      replies["POST /auth/login"] = reply;
      const state = await loginAction(IDLE, form({ username: "alice", password: PASSWORD }));
      outcomes.push(state);
      expect(state.status).toBe("error");
      expect(JSON.stringify(state)).not.toContain(PASSWORD);
      expect(JSON.stringify(state)).not.toContain("alice");
    }
    expect(outcomes[0]).toEqual(outcomes[1]);
    expect(JSON.stringify(outcomes[0])).toContain("Invalid username or password.");
    expect(env.sets).toEqual([]);
    expect(sessionStore().size).toBe(0);
  });

  it("answers an empty or oversized form the same way, without calling the API", async () => {
    replies["POST /auth/login"] = () => json(200, issued(TOKEN));
    for (const values of [
      { username: "", password: PASSWORD },
      { username: "alice", password: "" },
      { username: "a".repeat(257), password: PASSWORD },
      { username: "alice", password: "p".repeat(1025) },
    ]) {
      const state = await loginAction(IDLE, form(values));
      expect(JSON.stringify(state)).toContain("Invalid username or password.");
    }
    expect(calls).toEqual([]);
  });

  it("never trims a password", async () => {
    replies["POST /auth/login"] = () => json(200, issued(TOKEN));
    await redirected(loginAction(IDLE, form({ username: " alice ", password: ` ${PASSWORD} ` })));
    expect(calls[0]!.body).toEqual({ username: "alice", password: ` ${PASSWORD} ` });
  });

  it("never adopts the browser's cookie and revokes the session it replaces", async () => {
    const planted = signedIn("older-token");
    replies["POST /auth/login"] = () => json(200, issued(TOKEN));
    replies["POST /auth/logout"] = () => new Response(null, { status: 204 });
    await redirected(loginAction(IDLE, form({ username: "alice", password: PASSWORD })));
    const id = env.jar.get(COOKIE);
    expect(id).not.toBe(planted);
    expect(sessionStore().get(planted)).toBeNull();
    expect(sessionStore().get(id)?.token).toBe(TOKEN);
    expect(calls[1]).toMatchObject({
      method: "POST",
      headers: { Authorization: "Bearer older-token" },
    });
    expect(calls[1]!.url).toMatch(/\/api\/v1\/auth\/logout$/);
  });

  it("shows an unreachable API as such, and stores nothing", async () => {
    replies["POST /auth/login"] = () => {
      throw new TypeError("fetch failed");
    };
    const state = await loginAction(IDLE, form({ username: "alice", password: PASSWORD }));
    expect(state).toMatchObject({ status: "error", error: { code: "api_unreachable" } });
    expect(sessionStore().size).toBe(0);
  });

  it("is refused from another origin before anything is sent (CSRF, login CSRF)", async () => {
    replies["POST /auth/login"] = () => json(200, issued(TOKEN));
    for (const [name, value] of [
      ["origin", "http://evil.example"],
      ["origin", "null"],
      ["sec-fetch-site", "cross-site"],
      ["host", "evil.example"],
    ] as const) {
      env.request.set("host", "localhost:3000");
      env.request.set("origin", "http://localhost:3000");
      env.request.set("sec-fetch-site", "same-origin");
      env.request.set(name, value);
      await expect(
        loginAction(IDLE, form({ username: "alice", password: PASSWORD })),
      ).rejects.toBeInstanceOf(WriteRefusedError);
    }
    env.request.delete("origin");
    await expect(logoutAction()).rejects.toBeInstanceOf(WriteRefusedError);
    await expect(changePasswordAction(IDLE, form({}))).rejects.toBeInstanceOf(WriteRefusedError);
    expect(calls).toEqual([]);
    expect(env.sets).toEqual([]);
  });
});

describe("sign-out", () => {
  it("revokes the API session, forgets it and clears the cookie", async () => {
    const id = signedIn();
    replies["POST /auth/logout"] = () => new Response(null, { status: 204 });
    expect(await redirected(logoutAction())).toBe(LOGIN_PATH);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(sessionStore().get(id)).toBeNull();
    expect(env.jar.has(COOKIE)).toBe(false);
    const cleared = env.sets.at(-1)!;
    expect(cleared).toMatchObject({
      name: COOKIE,
      value: "",
      options: { maxAge: 0, httpOnly: true, secure: true, sameSite: "strict", path: "/" },
    });
  });

  it("still signs out when the API session has already ended or the API is down", async () => {
    for (const reply of [UNAUTHENTICATED, () => json(503, {})]) {
      const id = signedIn();
      replies["POST /auth/logout"] = reply;
      expect(await redirected(logoutAction())).toBe(LOGIN_PATH);
      expect(sessionStore().get(id)).toBeNull();
      expect(env.jar.has(COOKIE)).toBe(false);
    }
  });

  it("is harmless without a session", async () => {
    expect(await redirected(logoutAction())).toBe(LOGIN_PATH);
    expect(calls).toEqual([]);
    expect(env.jar.has(COOKIE)).toBe(false);
  });
});

describe("password change", () => {
  const values = {
    current_password: PASSWORD,
    new_password: "a brand new passphrase",
    confirm_password: "a brand new passphrase",
  };

  it("replaces the browser session with the fresh one the API issues", async () => {
    const old = signedIn();
    replies["POST /auth/password"] = () => json(200, issued(NEW_TOKEN));
    expect(await redirected(changePasswordAction(IDLE, form(values)))).toBe("/");
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]!.body).toEqual({
      current_password: PASSWORD,
      new_password: "a brand new passphrase",
    });
    const id = env.jar.get(COOKIE);
    expect(id).not.toBe(old);
    expect(sessionStore().get(old)).toBeNull();
    expect(sessionStore().get(id)?.token).toBe(NEW_TOKEN);
  });

  it("shows the API's refusal and keeps the session", async () => {
    const id = signedIn();
    replies["POST /auth/password"] = () =>
      json(403, {
        detail: "The current password is incorrect.",
        code: "invalid_current_password",
        field: "current_password",
      });
    const state = await changePasswordAction(IDLE, form(values));
    expect(state).toMatchObject({
      status: "error",
      error: { status: 403, message: "The current password is incorrect." },
    });
    expect(JSON.stringify(state)).not.toContain(PASSWORD);
    expect(JSON.stringify(state)).not.toContain(values.new_password);
    expect(sessionStore().get(id)?.token).toBe(TOKEN);
  });

  it("shows the API's password policy, which it does not duplicate", async () => {
    signedIn();
    replies["POST /auth/password"] = () =>
      json(422, {
        detail: "The password must be at least 12 characters long.",
        code: "validation_error",
        field: "new_password",
      });
    const state = await changePasswordAction(
      IDLE,
      form({ ...values, new_password: "short", confirm_password: "short" }),
    );
    expect(JSON.stringify(state)).toContain("at least 12 characters");
    expect(JSON.stringify(state)).not.toContain('"short"');
  });

  it("checks the confirmation before calling the API", async () => {
    signedIn();
    const state = await changePasswordAction(IDLE, form({ ...values, confirm_password: "x" }));
    expect(state).toMatchObject({ status: "error", error: { status: 422 } });
    expect(calls).toEqual([]);
  });

  it("sends a user whose session ended to sign in", async () => {
    const id = signedIn();
    replies["POST /auth/password"] = UNAUTHENTICATED;
    expect(await redirected(changePasswordAction(IDLE, form(values)))).toBe(SESSION_END_PATH);
    expect(sessionStore().get(id)).toBeNull();
  });
});

describe("authenticated API client", () => {
  it("acts as the signed-in user with a bearer token and no other identity", async () => {
    signedIn();
    replies["GET /projects"] = () => json(200, []);
    replies["POST /projects"] = () => json(201, { id: "p" });
    await apiGet("/projects");
    await apiWrite("POST", "/projects", { name: "x" });
    for (const call of calls) {
      expect(call.headers.Authorization).toBe(`Bearer ${TOKEN}`);
      const names = Object.keys(call.headers).map((h) => h.toLowerCase());
      expect(names).not.toContain("cookie");
      expect(names.some((h) => /^x-(user|actor)/.test(h))).toBe(false);
    }
  });

  it("sends nothing without a session", async () => {
    await expect(apiGet("/projects")).rejects.toMatchObject({
      status: 401,
      code: "unauthenticated",
    });
    env.jar.set(COOKIE, "forged-or-stale-cookie-value-that-maps-to-nothing");
    await expect(apiGet("/projects")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toEqual([]);
  });

  it("forgets a session the API no longer accepts, and never retries it", async () => {
    const id = signedIn();
    replies["GET /projects"] = UNAUTHENTICATED;
    await expect(apiGet("/projects")).rejects.toMatchObject({ status: 401 });
    expect(sessionStore().get(id)).toBeNull();
    await expect(apiGet("/projects")).rejects.toMatchObject({ status: 401 });
    expect(calls).toHaveLength(1);
  });

  it("keeps the session on 403 and 404: those are about the resource", async () => {
    const id = signedIn();
    replies["GET /projects/x"] = () =>
      json(403, { detail: "You do not have permission to do this.", code: "forbidden" });
    replies["GET /projects/y"] = () => json(404, { detail: "Not found.", code: "not_found" });
    await expect(apiGet("/projects/x")).rejects.toMatchObject({ status: 403 });
    await expect(apiGet("/projects/y")).rejects.toMatchObject({ status: 404 });
    expect(sessionStore().get(id)?.token).toBe(TOKEN);
  });
});

describe("protected pages", () => {
  it("require a live API session", async () => {
    expect(await redirected(requireUser())).toBe(SESSION_END_PATH);
    expect(calls).toEqual([]);

    const id = signedIn();
    replies["GET /auth/me"] = UNAUTHENTICATED; // revoked, expired, disabled, reset
    expect(await redirected(requireUser())).toBe(SESSION_END_PATH);
    expect(sessionStore().get(id)).toBeNull();
  });

  it("keep a user who must change their password on the password change", async () => {
    signedIn();
    replies["GET /auth/me"] = () =>
      json(200, { ...issued(""), token: undefined, user: user({ must_change_password: true }) });
    expect(await redirected(requireUser())).toBe(PASSWORD_PATH);
    expect(await requireUser({ allowPasswordChange: true })).toMatchObject({
      must_change_password: true,
    });
  });

  it("learn only what they display about the user", async () => {
    signedIn();
    replies["GET /auth/me"] = () =>
      json(200, { user: user({ global_role: "admin" }), session: issued("").session });
    const current = await requireUser();
    expect(current).toEqual({
      username: "alice",
      display_name: "Alice",
      global_role: "admin",
      must_change_password: false,
    });
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("turn an ended session into sign-in and a pending password change into that page", async () => {
    signedIn();
    replies["GET /projects"] = UNAUTHENTICATED;
    expect(await redirected(load(() => apiGet("/projects")))).toBe(SESSION_END_PATH);
    signedIn();
    replies["GET /projects"] = () =>
      json(403, { detail: "Change your password to continue.", code: "password_change_required" });
    expect(await redirected(load(() => apiGet("/projects")))).toBe(PASSWORD_PATH);
  });

  it("keep the API's 403 and 404 as they are", async () => {
    signedIn();
    replies["GET /projects/x"] = () =>
      json(403, { detail: "You do not have permission to do this.", code: "forbidden" });
    replies["GET /projects/y"] = () => json(404, { detail: "Not found.", code: "not_found" });
    expect(await load(() => apiGet("/projects/x"))).toMatchObject({
      ok: false,
      error: {
        status: 403,
        title: "Not permitted",
        message: "You do not have permission to do this.",
      },
    });
    expect(await load(() => apiGet("/projects/y"))).toMatchObject({
      ok: false,
      error: { status: 404 },
    });
  });

  it("send Server Actions whose session ended to sign in", () => {
    expect(() => failed(new ApiError(401, "unauthenticated", null))).toThrow(env.Redirect);
    expect(() => failed(new ApiError(403, "password_change_required", null))).toThrow(env.Redirect);
    expect(
      failed(new ApiError(403, "forbidden", "You do not have permission to do this.")),
    ).toMatchObject({ status: "error", error: { status: 403 } });
  });

  it("send artifact downloads whose session ended to sign in, and keep 403", async () => {
    const reportId = "6f1c0e3a-1111-4222-8333-444455556666";
    const response = await downloadArtifact("reports", reportId, "json");
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(SESSION_END_PATH);
    signedIn();
    replies[`GET /reports/${reportId}/artifacts/json`] = () =>
      json(403, { detail: "You do not have permission to do this.", code: "forbidden" });
    expect((await downloadArtifact("reports", reportId, "json")).status).toBe(403);
  });
});

describe("/session/end", () => {
  it("clears a cookie whose session has ended and goes to sign in", async () => {
    env.jar.set(COOKIE, "a".repeat(43));
    const response = await sessionEnd();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(`${LOGIN_PATH}?session=expired`);
    expect(response.headers.get("set-cookie")).toBe(
      "__Host-sv_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("never ends a live session (it is a GET)", async () => {
    const id = signedIn();
    const response = await sessionEnd();
    expect(response.headers.get("location")).toBe("/");
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(sessionStore().get(id)?.token).toBe(TOKEN);
  });
});

describe("proxy", () => {
  function request(method: string, path: string, headers: Record<string, string> = {}) {
    return new NextRequest(`http://localhost:3000${path}`, {
      method,
      headers: { host: "localhost:3000", ...headers },
    });
  }
  const sameOrigin = { origin: "http://localhost:3000", "sec-fetch-site": "same-origin" };

  it("redirects page loads without a session cookie to sign in", () => {
    for (const path of [
      "/",
      "/projects",
      "/projects/x?y=1",
      PASSWORD_PATH,
      "/artifacts/reports/x/json",
    ]) {
      const response = proxy(request("GET", path));
      expect(response.status, path).toBe(303);
      expect(new URL(response.headers.get("location")!).pathname).toBe(LOGIN_PATH);
      expect(new URL(response.headers.get("location")!).search).toBe("");
    }
  });

  it("refuses writes without a session cookie", () => {
    const response = proxy(request("POST", "/projects", sameOrigin));
    expect(response.status).toBe(401);
  });

  it("still refuses forged hosts and cross-origin writes first", () => {
    expect(proxy(request("GET", "/login", { host: "evil.example" })).status).toBe(421);
    expect(proxy(request("POST", "/login", { origin: "http://evil.example" })).status).toBe(403);
    expect(
      proxy(request("POST", "/projects", { origin: "http://evil.example", cookie: `${COOKIE}=x` }))
        .status,
    ).toBe(403);
  });

  it("serves the sign-in page and passes cookie-bearing requests on with security headers", () => {
    for (const response of [
      proxy(request("GET", LOGIN_PATH)),
      proxy(request("POST", LOGIN_PATH, sameOrigin)),
      proxy(request("GET", "/projects", { cookie: `${COOKIE}=x` })),
    ]) {
      expect(response.status).toBe(200);
      expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("x-frame-options")).toBe("DENY");
    }
  });
});
