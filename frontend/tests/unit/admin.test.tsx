import type { ReactElement, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The administration console (Phase 9 M9): account, accounts, members, audit
// logs and project settings. The API is faked; Next.js request APIs are
// replaced as in auth-flows.test.ts.

const env = vi.hoisted(() => {
  class Redirect extends Error {
    constructor(readonly to: string) {
      super(`redirect to ${to}`);
    }
  }
  class NotFound extends Error {}
  return {
    Redirect,
    NotFound,
    jar: new Map<string, string>(),
    request: new Map<string, string>(),
    refreshes: 0,
    pathname: "/",
  };
});

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      env.jar.has(name) ? { name, value: env.jar.get(name) as string } : undefined,
    set: () => undefined,
  }),
  headers: async () => ({ get: (name: string) => env.request.get(name.toLowerCase()) ?? null }),
}));
vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new env.Redirect(to);
  },
  notFound: () => {
    throw new env.NotFound();
  },
  usePathname: () => env.pathname,
}));
vi.mock("next/cache", () => ({
  refresh: () => {
    env.refreshes += 1;
  },
}));
vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

const actions = await import("@/lib/actions/admin");
const { IDLE } = await import("@/lib/actions/state");
const { auditFilters, pageHref, userFilters, PAGE_SIZE } = await import("@/lib/admin/filters");
const { sessionStore } = await import("@/lib/auth/store");
const { SECURE_COOKIE_NAME } = await import("@/lib/auth/cookie");
const { SESSION_END_PATH } = await import("@/lib/auth/paths");
const { Nav } = await import("@/components/nav");
const { AuditTable } = await import("@/components/admin");
type AuditEvent = import("@/lib/api/types").AuditEvent;
const UsersPage = (await import("@/app/(console)/admin/users/page")).default;
const UserPage = (await import("@/app/(console)/admin/users/[userId]/page")).default;
const GlobalAuditPage = (await import("@/app/(console)/admin/audit/page")).default;
const MembersPage = (await import("@/app/(console)/projects/[projectId]/members/page")).default;
const ProjectAuditPage = (await import("@/app/(console)/projects/[projectId]/audit/page")).default;
const SettingsPage = (await import("@/app/(console)/projects/[projectId]/settings/page")).default;
const AccountPage = (await import("@/app/(console)/account/page")).default;
const { WriteRefusedError } = await import("@/lib/security/action-guard");
const ProjectPage = (await import("@/app/(console)/projects/[projectId]/page")).default;
const { ProjectNav } = await import("@/components/project-nav");
const { myProjectRole } = await import("@/lib/project-role");

const TOKEN = "api-session-token-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
const PROJECT = "11111111-1111-4111-8111-111111111111";
const USER = "22222222-2222-4222-8222-222222222222";
const OTHER = "33333333-3333-4333-8333-333333333333";
const PASSWORD = "a temporary passphrase";
const HOSTILE = '<img src=x onerror="alert(1)">‮evil\u0007';
const NOW = "2026-10-05T10:00:00Z";

type Call = {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: unknown;
};
let calls: Call[] = [];
let replies: Record<string, () => Response> = {};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
const error =
  (status: number, code: string, detail: string, field: string | null = null) =>
  () =>
    json(status, { detail, code, field });
const FORBIDDEN = error(403, "forbidden", "You do not have permission to do this.");
const NOT_FOUND = error(404, "not_found", "project not found");
const UNAUTHENTICATED = error(401, "unauthenticated", "Authentication required.");

function form(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [k, v] of Object.entries(values)) data.set(k, v);
  return data;
}

const html = (node: ReactElement) => renderToStaticMarkup(node);

async function page(render: Promise<ReactElement>): Promise<string> {
  return html(await render);
}

async function outcome(promise: Promise<unknown>): Promise<string> {
  try {
    const result = await promise;
    // Pages signal "not found" while rendering (<PageError>).
    if (result && typeof result === "object" && "type" in result) html(result as ReactElement);
  } catch (e) {
    if (e instanceof env.Redirect) return `redirect ${e.to}`;
    if (e instanceof env.NotFound) return "not found";
    throw e;
  }
  return "rendered";
}

const user = (overrides: Record<string, unknown> = {}) => ({
  id: USER,
  username: "alice",
  display_name: "Alice",
  global_role: "user",
  is_active: true,
  disabled_at: null,
  must_change_password: true,
  last_login_at: null,
  created_at: NOW,
  ...overrides,
});
const project = { id: PROJECT, name: "Lab", description: null, created_at: NOW, updated_at: NOW };
const member = (overrides: Record<string, unknown> = {}) => ({
  user_id: USER,
  username: "alice",
  display_name: "Alice",
  role: "owner",
  is_active: true,
  created_by_user_id: null,
  created_at: NOW,
  ...overrides,
});
const event = (overrides: Record<string, unknown> = {}) => ({
  id: "44444444-4444-4444-8444-444444444444",
  occurred_at: NOW,
  request_id: null,
  actor_type: "user",
  actor_user_id: USER,
  actor_label: "Alice",
  action: "membership.added",
  outcome: "success",
  project_id: PROJECT,
  resource_type: "project",
  resource_id: PROJECT,
  metadata: { user_id: OTHER, role: "viewer" },
  session_id: "55555555-5555-4555-8555-555555555555",
  ...overrides,
});

beforeEach(() => {
  delete (globalThis as Record<symbol, unknown>)[Symbol.for("sentinelvapt.browserSessions")];
  env.jar.clear();
  env.request.clear();
  env.request.set("host", "localhost:3000");
  env.request.set("origin", "http://localhost:3000");
  env.request.set("sec-fetch-site", "same-origin");
  env.refreshes = 0;
  env.pathname = "/";
  env.jar.set(SECURE_COOKIE_NAME, sessionStore().create(TOKEN, Date.now() + 3_600_000));
  calls = [];
  replies = {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const u = new URL(url);
      const call: Call = {
        method: init.method ?? "GET",
        path: u.pathname.replace(/^\/api\/v1/, ""),
        query: u.search,
        headers: { ...(init.headers as Record<string, string>) },
        body: init.body ? JSON.parse(init.body as string) : undefined,
      };
      calls.push(call);
      const reply = replies[`${call.method} ${call.path}`];
      if (!reply) throw new Error(`unexpected API call ${call.method} ${call.path}`);
      return reply();
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function expectOnlySessionIdentity() {
  for (const call of calls) {
    expect(call.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    const names = Object.keys(call.headers).map((h) => h.toLowerCase());
    expect(names.some((h) => /^x-(user|actor)|^cookie$/.test(h))).toBe(false);
    if (call.body && typeof call.body === "object") {
      for (const key of Object.keys(call.body)) {
        expect(key).not.toMatch(/actor|_by|user_id|owner|project_id/);
      }
    }
  }
}

describe("account administration (actions)", () => {
  const values = {
    username: "bob",
    display_name: "Bob",
    global_role: "user",
    password: PASSWORD,
    confirm_password: PASSWORD,
  };

  it("creates an account with the typed temporary password and opens it", async () => {
    replies["POST /users"] = () => json(201, user({ id: OTHER, username: "bob" }));
    const to = await outcome(actions.createUserAction(IDLE, form(values)));
    expect(to).toBe(`redirect /admin/users/${OTHER}?created=1`);
    expect(calls[0]!.body).toEqual({
      username: "bob",
      display_name: "Bob",
      password: PASSWORD,
      global_role: "user",
    });
    expect(to).not.toContain(PASSWORD);
    expectOnlySessionIdentity();
  });

  it("checks the confirmation and the role before calling the API", async () => {
    for (const bad of [
      { ...values, confirm_password: "different" },
      { ...values, global_role: "superuser" },
      { ...values, password: "" },
    ]) {
      const state = await actions.createUserAction(IDLE, form(bad));
      expect(state).toMatchObject({ status: "error", error: { status: 422 } });
      expect(JSON.stringify(state)).not.toContain(PASSWORD);
    }
    expect(calls).toEqual([]);
  });

  it("shows the API's refusals as they are: 409, 422, 403", async () => {
    for (const [reply, status, text] of [
      [error(409, "conflict", "that username is already taken", "username"), 409, "already taken"],
      [
        error(
          422,
          "validation_error",
          "The password must be at least 12 characters long.",
          "password",
        ),
        422,
        "at least 12",
      ],
      [FORBIDDEN, 403, "You do not have permission to do this."],
    ] as const) {
      replies["POST /users"] = reply;
      const state = await actions.createUserAction(IDLE, form(values));
      expect(state).toMatchObject({ status: "error", error: { status } });
      expect(JSON.stringify(state)).toContain(text);
      expect(JSON.stringify(state)).not.toContain(PASSWORD);
    }
    expect(env.refreshes).toBe(0);
  });

  it("disables an account only when confirmed, then reloads", async () => {
    replies[`POST /users/${USER}/disable`] = () => json(200, user({ is_active: false }));
    expect(await actions.disableUserAction(USER, IDLE, form({}))).toMatchObject({
      status: "error",
    });
    expect(calls).toEqual([]);
    const state = await actions.disableUserAction(USER, IDLE, form({ confirm: "true" }));
    expect(state).toMatchObject({ status: "ok" });
    expect(calls[0]).toMatchObject({ method: "POST", path: `/users/${USER}/disable` });
    expect(calls[0]!.body).toBeUndefined();
    expect(env.refreshes).toBe(1);
    expectOnlySessionIdentity();
  });

  it("shows the self and last-administrator refusals without reloading", async () => {
    for (const detail of [
      "administrators cannot disable themselves",
      "the platform must keep an active administrator",
    ]) {
      replies[`POST /users/${USER}/disable`] = error(409, "conflict", detail);
      const state = await actions.disableUserAction(USER, IDLE, form({ confirm: "true" }));
      expect(state).toMatchObject({ status: "error", error: { status: 409, message: detail } });
    }
    expect(env.refreshes).toBe(0);
  });

  it("resets a password without echoing it", async () => {
    replies[`POST /users/${USER}/password-reset`] = () => json(200, user());
    const state = await actions.resetPasswordAction(
      USER,
      IDLE,
      form({ new_password: PASSWORD, confirm_password: PASSWORD }),
    );
    expect(state).toMatchObject({ status: "ok" });
    expect(JSON.stringify(state)).not.toContain(PASSWORD);
    expect(calls[0]!.body).toEqual({ new_password: PASSWORD });
    replies[`POST /users/${USER}/password-reset`] = error(409, "conflict", "the user is disabled");
    expect(
      await actions.resetPasswordAction(
        USER,
        IDLE,
        form({ new_password: PASSWORD, confirm_password: PASSWORD }),
      ),
    ).toMatchObject({ status: "error", error: { status: 409, message: "the user is disabled" } });
  });

  it("never calls the API with a tampered identifier", async () => {
    for (const bad of ["../../auth/me", `${USER}/x`, "me", ""]) {
      const state = await actions.disableUserAction(bad, IDLE, form({ confirm: "true" }));
      expect(state.status).toBe("error");
    }
    expect(calls).toEqual([]);
  });

  it("sends a user whose session ended to sign in", async () => {
    replies[`POST /users/${USER}/disable`] = UNAUTHENTICATED;
    expect(await outcome(actions.disableUserAction(USER, IDLE, form({ confirm: "true" })))).toBe(
      `redirect ${SESSION_END_PATH}`,
    );
  });

  it("is refused from another origin before anything is sent", async () => {
    env.request.set("origin", "http://evil.example");
    for (const call of [
      actions.createUserAction(IDLE, form(values)),
      actions.disableUserAction(USER, IDLE, form({ confirm: "true" })),
      actions.addMemberAction(PROJECT, IDLE, form({ username: "bob", role: "viewer" })),
      actions.removeMemberAction(PROJECT, USER, IDLE, form({ confirm: "true" })),
      actions.deleteProjectAction(PROJECT, IDLE, form({ confirm: "true" })),
    ]) {
      await expect(call).rejects.toBeInstanceOf(WriteRefusedError);
    }
    expect(calls).toEqual([]);
  });
});

describe("membership administration (actions)", () => {
  it("adds a member by username and role, under the project in the path", async () => {
    replies[`POST /projects/${PROJECT}/members`] = () => json(201, member({ role: "viewer" }));
    const state = await actions.addMemberAction(
      PROJECT,
      IDLE,
      form({ username: "alice", role: "viewer" }),
    );
    expect(state).toMatchObject({ status: "ok" });
    expect(calls[0]!.body).toEqual({ username: "alice", role: "viewer" });
    expect(env.refreshes).toBe(1);
    expectOnlySessionIdentity();
  });

  it("acts on the project and member of the page, never ids from the form", async () => {
    replies[`POST /projects/${PROJECT}/members`] = () => json(201, member());
    replies[`PATCH /projects/${PROJECT}/members/${USER}`] = () => json(200, member());
    const smuggled = { project_id: OTHER, user_id: OTHER, actor_user_id: OTHER, owner: "me" };
    await actions.addMemberAction(
      PROJECT,
      IDLE,
      form({ username: "a", role: "viewer", ...smuggled }),
    );
    await actions.changeMemberRoleAction(
      PROJECT,
      USER,
      IDLE,
      form({ role: "viewer", ...smuggled }),
    );
    expect(calls.map((c) => c.path)).toEqual([
      `/projects/${PROJECT}/members`,
      `/projects/${PROJECT}/members/${USER}`,
    ]);
    expect(JSON.stringify(calls.map((c) => c.body))).not.toContain(OTHER);
  });

  it("refuses roles that do not exist before calling the API", async () => {
    for (const role of ["admin", "OWNER", "", "owner,viewer"]) {
      const state = await actions.addMemberAction(PROJECT, IDLE, form({ username: "a", role }));
      expect(state).toMatchObject({ status: "error", error: { status: 422 } });
      const change = await actions.changeMemberRoleAction(PROJECT, USER, IDLE, form({ role }));
      expect(change.status).toBe("error");
    }
    expect(calls).toEqual([]);
  });

  it("shows unknown users and duplicates as the API reports them", async () => {
    replies[`POST /projects/${PROJECT}/members`] = error(
      404,
      "not_found",
      "user not found",
      "username",
    );
    expect(
      await actions.addMemberAction(PROJECT, IDLE, form({ username: "ghost", role: "viewer" })),
    ).toMatchObject({ status: "error", error: { status: 404, message: "user not found" } });
    replies[`POST /projects/${PROJECT}/members`] = error(
      409,
      "conflict",
      "the user is already a member",
    );
    expect(
      await actions.addMemberAction(PROJECT, IDLE, form({ username: "alice", role: "viewer" })),
    ).toMatchObject({ status: "error", error: { status: 409 } });
    expect(env.refreshes).toBe(0);
  });

  it("changes a role and removes a member through the member's own path", async () => {
    replies[`PATCH /projects/${PROJECT}/members/${USER}`] = () =>
      json(200, member({ role: "operator" }));
    replies[`DELETE /projects/${PROJECT}/members/${USER}`] = () =>
      new Response(null, { status: 204 });
    expect(
      await actions.changeMemberRoleAction(PROJECT, USER, IDLE, form({ role: "operator" })),
    ).toMatchObject({ status: "ok" });
    expect(calls[0]!.body).toEqual({ role: "operator" });
    expect(await actions.removeMemberAction(PROJECT, USER, IDLE, form({}))).toMatchObject({
      status: "error",
    });
    expect(
      await actions.removeMemberAction(PROJECT, USER, IDLE, form({ confirm: "true" })),
    ).toMatchObject({ status: "ok" });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `PATCH /projects/${PROJECT}/members/${USER}`,
      `DELETE /projects/${PROJECT}/members/${USER}`,
    ]);
    expect(env.refreshes).toBe(2);
  });

  it("never claims success when the last owner is protected", async () => {
    const lastOwner = error(409, "conflict", "a project must keep at least one owner");
    replies[`PATCH /projects/${PROJECT}/members/${USER}`] = lastOwner;
    replies[`DELETE /projects/${PROJECT}/members/${USER}`] = lastOwner;
    for (const state of [
      await actions.changeMemberRoleAction(PROJECT, USER, IDLE, form({ role: "viewer" })),
      await actions.removeMemberAction(PROJECT, USER, IDLE, form({ confirm: "true" })),
    ]) {
      expect(state).toMatchObject({
        status: "error",
        error: { status: 409, message: "a project must keep at least one owner" },
      });
    }
    expect(env.refreshes).toBe(0);
  });

  it("keeps 403 (not an owner) apart from 404 (not visible)", async () => {
    replies[`PATCH /projects/${PROJECT}/members/${USER}`] = FORBIDDEN;
    expect(
      await actions.changeMemberRoleAction(PROJECT, USER, IDLE, form({ role: "viewer" })),
    ).toMatchObject({ error: { status: 403, title: "Not permitted" } });
    replies[`PATCH /projects/${PROJECT}/members/${USER}`] = NOT_FOUND;
    expect(
      await actions.changeMemberRoleAction(PROJECT, USER, IDLE, form({ role: "viewer" })),
    ).toMatchObject({ error: { status: 404, title: "Not found" } });
  });
});

describe("project settings (actions)", () => {
  it("updates through the API and deletes only when confirmed", async () => {
    replies[`PATCH /projects/${PROJECT}`] = () => json(200, project);
    replies[`DELETE /projects/${PROJECT}`] = error(
      409,
      "conflict",
      "project still has targets; delete them first",
    );
    expect(
      await actions.updateProjectAction(PROJECT, IDLE, form({ name: "New", description: "" })),
    ).toMatchObject({ status: "ok" });
    expect(calls[0]!.body).toEqual({ name: "New", description: null });
    expect(await actions.deleteProjectAction(PROJECT, IDLE, form({}))).toMatchObject({
      status: "error",
    });
    expect(
      await actions.deleteProjectAction(PROJECT, IDLE, form({ confirm: "true" })),
    ).toMatchObject({
      error: { status: 409, message: "project still has targets; delete them first" },
    });
    replies[`DELETE /projects/${PROJECT}`] = () => new Response(null, { status: 204 });
    expect(
      await outcome(actions.deleteProjectAction(PROJECT, IDLE, form({ confirm: "true" }))),
    ).toBe("redirect /projects");
  });
});

describe("filters", () => {
  it("pass only known audit filters with valid values", () => {
    const { query, filters, offset } = auditFilters(
      {
        action: "membership.added",
        outcome: "denied",
        actor_type: "user",
        actor_user_id: USER.toUpperCase(),
        resource_type: "project_member",
        resource_id: "not-a-uuid",
        occurred_from: "2026-10-01T08:30",
        occurred_to: "yesterday",
        project_id: PROJECT,
        limit: "100000",
        token: "x",
        offset: "100",
      },
      false,
    );
    expect(query).toEqual({
      action: "membership.added",
      outcome: "denied",
      actor_type: "user",
      actor_user_id: USER,
      resource_type: "project_member",
      occurred_from: "2026-10-01T08:30:00.000Z",
      limit: PAGE_SIZE,
      offset: 100,
    });
    expect(filters.occurred_from).toBe("2026-10-01T08:30");
    expect(offset).toBe(100);
    expect(auditFilters({ project_id: PROJECT }, true).query.project_id).toBe(PROJECT);
  });

  it("refuse unknown actions, outcomes and odd offsets", () => {
    const { query } = auditFilters(
      { action: "audit.deleted", outcome: "ok", actor_type: "admin", offset: "7" },
      true,
    );
    expect(query).toEqual({ limit: PAGE_SIZE, offset: 0 });
    expect(auditFilters({ offset: "999999950" }, true).offset).toBe(0);
    expect(auditFilters({ offset: ["50", "100"] }, true).offset).toBe(50);
  });

  it("pass only known account filters", () => {
    expect(userFilters({ active: "false", global_role: "admin", is_active: "1" }).query).toEqual({
      active: false,
      global_role: "admin",
      limit: PAGE_SIZE,
      offset: 0,
    });
    expect(userFilters({ active: "yes", global_role: "root" }).query).toEqual({
      limit: PAGE_SIZE,
      offset: 0,
    });
  });

  it("build page links on the same route, keeping filters", () => {
    expect(pageHref("/admin/audit", { action: "auth.login" }, 50)).toBe(
      "/admin/audit?action=auth.login&offset=50",
    );
    expect(pageHref("/admin/audit", {}, 0)).toBe("/admin/audit");
  });
});

describe("pages", () => {
  it("show global administrators the accounts, safely rendered", async () => {
    replies["GET /users"] = () =>
      json(200, [
        user({ username: HOSTILE, display_name: HOSTILE }),
        user({ id: "../../account/password" }),
      ]);
    const out = await page(UsersPage({ searchParams: Promise.resolve({ active: "true" }) }));
    expect(calls[0]!.query).toBe(`?active=true&limit=${PAGE_SIZE}&offset=0`);
    expect(out).toContain('data-testid="users-table"');
    expect(out).toContain('data-testid="create-user"');
    expect(out).not.toContain("<img");
    expect(out).toContain("⟨U+202E RLO⟩");
    expect(out).toContain(`href="/admin/users/${USER}"`);
    expect(out).not.toContain("/admin/users/../"); // links only to validated ids
    expect(out).not.toContain(TOKEN);
  });

  it("show anyone else the API's refusal and no controls", async () => {
    replies["GET /users"] = FORBIDDEN;
    const out = await page(UsersPage({ searchParams: Promise.resolve({}) }));
    expect(out).toContain("Not permitted");
    expect(out).not.toContain('data-testid="create-user"');
    expect(out).not.toContain('data-testid="users-table"');
  });

  it("show one account with reset and disable for active accounts only", async () => {
    replies[`GET /users/${USER}`] = () => json(200, user());
    let out = await page(
      UserPage({ params: Promise.resolve({ userId: USER }), searchParams: Promise.resolve({}) }),
    );
    expect(out).toContain('data-testid="reset-password"');
    expect(out).toContain('data-testid="disable-user"');
    replies[`GET /users/${USER}`] = () => json(200, user({ is_active: false, disabled_at: NOW }));
    out = await page(
      UserPage({ params: Promise.resolve({ userId: USER }), searchParams: Promise.resolve({}) }),
    );
    expect(out).not.toContain('data-testid="disable-user"');
    expect(out).not.toContain('data-testid="reset-password"');
    expect(
      await outcome(
        UserPage({ params: Promise.resolve({ userId: "x" }), searchParams: Promise.resolve({}) }),
      ),
    ).toBe("not found");
  });

  it("give project owners the member controls", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, { ...project, name: HOSTILE });
    replies[`GET /projects/${PROJECT}/members`] = () =>
      json(200, [member(), member({ user_id: OTHER, username: HOSTILE, role: "viewer" })]);
    const out = await page(MembersPage({ params: Promise.resolve({ projectId: PROJECT }) }));
    expect(out).toContain('data-testid="members-table"');
    expect(out).toContain('data-testid="add-member"');
    expect(out).toContain('data-testid="role-alice"');
    expect(out).not.toContain("<img");
  });

  it("give other members the API's 403 and no controls, and non-members 404", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, project);
    replies[`GET /projects/${PROJECT}/members`] = FORBIDDEN;
    const out = await page(MembersPage({ params: Promise.resolve({ projectId: PROJECT }) }));
    expect(out).toContain("Not permitted");
    expect(out).not.toContain('data-testid="add-member"');
    expect(out).not.toContain('data-testid="members-table"');
    replies[`GET /projects/${PROJECT}`] = NOT_FOUND;
    expect(await outcome(MembersPage({ params: Promise.resolve({ projectId: PROJECT }) }))).toBe(
      "not found",
    );
    expect(await outcome(MembersPage({ params: Promise.resolve({ projectId: "../users" }) }))).toBe(
      "not found",
    );
  });

  it("show a project's audit log to owners, scoped by the path", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, project);
    replies[`GET /projects/${PROJECT}/audit-events`] = () =>
      json(200, [event({ actor_label: HOSTILE, metadata: { reason: HOSTILE, n: 2 } })]);
    const out = await page(
      ProjectAuditPage({
        params: Promise.resolve({ projectId: PROJECT }),
        searchParams: Promise.resolve({ project_id: OTHER, action: "membership.added" }),
      }),
    );
    const auditCall = calls.find((c) => c.path.endsWith("/audit-events"))!;
    expect(auditCall.path).toBe(`/projects/${PROJECT}/audit-events`);
    expect(auditCall.query).not.toContain(OTHER); // the path decides the project
    expect(out).toContain('data-testid="audit-table"');
    expect(out).toContain("membership.added");
    expect(out).not.toContain("<img");
    expect(out).toContain("⟨U+0007⟩");
    // Read-only: no forms that post anywhere.
    expect(out).not.toMatch(/method="post"/i);
  });

  it("show other members the API's refusal of the project audit log", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, project);
    replies[`GET /projects/${PROJECT}/audit-events`] = FORBIDDEN;
    const out = await page(
      ProjectAuditPage({
        params: Promise.resolve({ projectId: PROJECT }),
        searchParams: Promise.resolve({}),
      }),
    );
    expect(out).toContain("Not permitted");
    expect(out).not.toContain('data-testid="audit-table"');
  });

  it("show the platform audit log to global administrators only", async () => {
    replies["GET /audit-events"] = () =>
      json(200, [event(), event({ id: "6", project_id: "../admin/users" })]);
    let out = await page(GlobalAuditPage({ searchParams: Promise.resolve({}) }));
    expect(out).toContain(`href="/projects/${PROJECT}"`);
    expect(out).not.toContain("/projects/../"); // links only to validated ids
    expect(out).not.toContain("55555555-5555"); // the session row id is not shown
    replies["GET /audit-events"] = FORBIDDEN;
    out = await page(GlobalAuditPage({ searchParams: Promise.resolve({}) }));
    expect(out).toContain("Not permitted");
    expect(out).not.toContain('data-testid="audit-table"');
  });

  it("send the browser to sign in when the session ended", async () => {
    replies["GET /audit-events"] = UNAUTHENTICATED;
    expect(await outcome(GlobalAuditPage({ searchParams: Promise.resolve({}) }))).toBe(
      `redirect ${SESSION_END_PATH}`,
    );
  });

  it("offer the project settings forms to owners; the API decides each change", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, project);
    replies[`GET /projects/${PROJECT}/membership/me`] = () =>
      json(200, { project_id: PROJECT, user_id: USER, role: "owner" });
    const out = await page(SettingsPage({ params: Promise.resolve({ projectId: PROJECT }) }));
    expect(out).toContain('data-testid="update-project"');
    expect(out).toContain('data-testid="delete-project"');
  });

  it("show the account without ids, tokens or session identifiers", async () => {
    replies["GET /auth/me"] = () =>
      json(200, {
        user: {
          id: USER,
          username: HOSTILE,
          display_name: "Alice",
          global_role: "admin",
          must_change_password: false,
        },
        session: { created_at: NOW, idle_expires_at: NOW, expires_at: NOW },
      });
    const out = await page(AccountPage());
    expect(out).toContain("Administrator");
    expect(out).toContain("⟨U+202E RLO⟩");
    expect(out).not.toContain(USER);
    expect(out).not.toContain(TOKEN);
    expect(out).not.toContain("<img");
  });
});

describe("navigation", () => {
  it("shows administration links to global administrators only (display only)", () => {
    const admin = html(<Nav admin />);
    const user = html(<Nav />);
    for (const href of ["/admin/users", "/admin/audit"]) {
      expect(admin).toContain(`href="${href}"`);
      expect(user).not.toContain(`href="${href}"`);
    }
    expect(user).toContain('href="/account"');
  });
});

describe("audit table", () => {
  it("never renders the audit metadata as markup", () => {
    const out = html(
      <AuditTable
        events={[
          event({
            metadata: { x: HOSTILE, nested: { a: "<b>" } },
            resource_type: HOSTILE,
          }) as unknown as AuditEvent,
        ]}
        global={false}
      />,
    );
    expect(out).not.toContain("<img");
    expect(out).not.toContain("<b>");
    expect(out).toContain("&lt;img");
    // Control and bidi characters never reach the page raw, only as markers.
    expect(out).not.toMatch(/[‮]/);
    expect(out).toContain("⟨U+202E RLO⟩");
  });
});

// --- Phase 9 M10 ------------------------------------------------------------------------

const mine = (role: unknown) => () => json(200, { project_id: PROJECT, user_id: USER, role });

describe("enabling accounts and global roles (actions)", () => {
  it("enables an account only when confirmed, through the account's own path", async () => {
    replies[`POST /users/${USER}/enable`] = () => json(200, user());
    expect(await actions.enableUserAction(USER, IDLE, form({}))).toMatchObject({
      status: "error",
    });
    expect(calls).toEqual([]);
    const state = await actions.enableUserAction(
      USER,
      IDLE,
      form({ confirm: "true", user_id: OTHER }),
    );
    expect(state).toMatchObject({ status: "ok" });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([`POST /users/${USER}/enable`]);
    expect(calls[0]!.body).toBeUndefined();
    expect(env.refreshes).toBe(1);
    expectOnlySessionIdentity();
  });

  it("shows the API's refusals of enabling as they are", async () => {
    for (const [reply, status] of [
      [error(409, "conflict", "the user is already active"), 409],
      [FORBIDDEN, 403],
      [error(404, "not_found", "user not found"), 404],
    ] as const) {
      replies[`POST /users/${USER}/enable`] = reply;
      expect(await actions.enableUserAction(USER, IDLE, form({ confirm: "true" }))).toMatchObject({
        status: "error",
        error: { status },
      });
    }
    expect(env.refreshes).toBe(0);
    replies[`POST /users/${USER}/enable`] = UNAUTHENTICATED;
    expect(await outcome(actions.enableUserAction(USER, IDLE, form({ confirm: "true" })))).toBe(
      `redirect ${SESSION_END_PATH}`,
    );
  });

  it("changes a global role only to a known role, when confirmed", async () => {
    replies[`PATCH /users/${USER}/global-role`] = () => json(200, user({ global_role: "admin" }));
    const attempts: Record<string, string>[] = [
      { global_role: "root", confirm: "true" },
      { global_role: "standard", confirm: "true" },
      { global_role: "", confirm: "true" },
      { global_role: "admin" },
    ];
    for (const values of attempts) {
      const state = await actions.changeGlobalRoleAction(USER, IDLE, form(values));
      expect(state.status).toBe("error");
    }
    expect(calls).toEqual([]);
    const state = await actions.changeGlobalRoleAction(
      USER,
      IDLE,
      form({ global_role: "admin", confirm: "true", user_id: OTHER, is_admin: "true" }),
    );
    expect(state).toMatchObject({ status: "ok" });
    // The account is the bound one; the body says only which role.
    expect(calls[0]!.path).toBe(`/users/${USER}/global-role`);
    expect(calls[0]!.body).toEqual({ global_role: "admin" });
    expectOnlySessionIdentity();
  });

  it("shows self, last-administrator and disabled refusals without reloading", async () => {
    for (const detail of [
      "administrators cannot change their own global role",
      "the platform must keep an active administrator",
      "a disabled account cannot become an administrator",
    ]) {
      replies[`PATCH /users/${USER}/global-role`] = error(409, "conflict", detail);
      const state = await actions.changeGlobalRoleAction(
        USER,
        IDLE,
        form({ global_role: "user", confirm: "true" }),
      );
      expect(state).toMatchObject({ status: "error", error: { status: 409, message: detail } });
    }
    replies[`PATCH /users/${USER}/global-role`] = FORBIDDEN;
    const refused = await actions.changeGlobalRoleAction(
      USER,
      IDLE,
      form({ global_role: "admin", confirm: "true" }),
    );
    expect(refused).toMatchObject({ error: { status: 403, title: "Not permitted" } });
    expect(env.refreshes).toBe(0);
  });

  it("never calls the API with a tampered account id", async () => {
    for (const bad of ["../../users", `${USER}/enable`, "me"]) {
      await actions.enableUserAction(bad, IDLE, form({ confirm: "true" }));
      await actions.changeGlobalRoleAction(
        bad,
        IDLE,
        form({ global_role: "admin", confirm: "true" }),
      );
    }
    expect(calls).toEqual([]);
  });
});

describe("account page controls (M10)", () => {
  const me = (id: string) => () =>
    json(200, {
      user: {
        id,
        username: "root",
        display_name: "Root",
        global_role: "admin",
        must_change_password: false,
      },
      session: { created_at: NOW, idle_expires_at: NOW, expires_at: NOW },
    });
  const render = () =>
    page(
      UserPage({ params: Promise.resolve({ userId: USER }), searchParams: Promise.resolve({}) }),
    );

  it("offers re-enabling for a disabled account, and disabling for an active one", async () => {
    replies["GET /auth/me"] = me(OTHER);
    replies[`GET /users/${USER}`] = () =>
      json(
        200,
        user({ is_active: false, disabled_at: NOW, global_role: "admin", username: HOSTILE }),
      );
    let out = await render();
    expect(out).toContain('data-testid="enable-user"');
    expect(out).toContain('data-testid="change-global-role"'); // demoting is allowed
    expect(out).not.toContain('data-testid="disable-user"');
    expect(out).not.toContain('data-testid="reset-password"');
    expect(out).not.toContain("<img");
    replies[`GET /users/${USER}`] = () => json(200, user({ is_active: false, disabled_at: NOW }));
    out = await render();
    expect(out).toContain("A disabled account cannot become an administrator.");
    expect(out).not.toContain('data-testid="change-global-role"');
    replies[`GET /users/${USER}`] = () => json(200, user());
    out = await render();
    for (const id of ["disable-user", "reset-password", "change-global-role"]) {
      expect(out).toContain(`data-testid="${id}"`);
    }
    expect(out).not.toContain('data-testid="enable-user"');
    // Both privileged forms need an explicit tick.
    expect(out.match(/<input type="checkbox"[^>]*name="confirm"/g)?.length).toBe(2);
    expect(out.match(/<input type="checkbox"[^>]*required=""[^>]*name="confirm"/g)?.length).toBe(2);
  });

  it("offers no self-administration (the API refuses it anyway)", async () => {
    replies["GET /auth/me"] = me(USER);
    replies[`GET /users/${USER}`] = () => json(200, user({ global_role: "admin" }));
    const out = await render();
    expect(out).toContain("This is your own account.");
    for (const id of ["disable-user", "reset-password", "change-global-role", "enable-user"]) {
      expect(out).not.toContain(`data-testid="${id}"`);
    }
  });
});

describe("project role (M10)", () => {
  it("is read from the caller's own membership and only trusted when known", async () => {
    const cases: [() => Response, string | null][] = [
      [mine("owner"), "owner"],
      [mine("operator"), "operator"],
      [mine("viewer"), "viewer"],
      [mine("admin"), null],
      [mine(undefined), null],
      [() => json(200, {}), null],
      [NOT_FOUND, null],
      [FORBIDDEN, null],
    ];
    for (const [reply, expected] of cases) {
      replies[`GET /projects/${PROJECT}/membership/me`] = reply;
      expect(await myProjectRole(PROJECT)).toBe(expected);
    }
    expect(new Set(calls.map((c) => c.path))).toEqual(
      new Set([`/projects/${PROJECT}/membership/me`]),
    );
    expect(calls.every((c) => c.query === "")).toBe(true); // no user id is ever sent
  });

  it("decides the project tabs: owners get administration, others do not", () => {
    const owner = html(<ProjectNav projectId={PROJECT} current="" role="owner" />);
    for (const suffix of ["/members", "/audit", "/settings"]) {
      expect(owner).toContain(`href="/projects/${PROJECT}${suffix}"`);
    }
    expect(owner).toContain("Your role: Owner");
    for (const role of ["operator", "viewer", null] as const) {
      const out = html(<ProjectNav projectId={PROJECT} current="" role={role} />);
      for (const suffix of ["/members", "/audit", "/settings"]) {
        expect(out).not.toContain(`href="/projects/${PROJECT}${suffix}"`);
      }
      expect(out).toContain(`href="/projects/${PROJECT}/targets"`);
    }
    expect(html(<ProjectNav projectId={PROJECT} current="" role="viewer" />)).toContain(
      "Your role: Viewer",
    );
    expect(html(<ProjectNav projectId={PROJECT} current="" role={null} />)).toContain(
      "Your role: unknown",
    );
  });

  it("never asks an owner-only endpoint to find the role", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, { ...project, name: HOSTILE });
    // Since M11 the project page learns the role with its posture (project.read).
    const zero = { total: 0, active: 0, open: 0, by_severity: {}, by_status: {} };
    replies[`GET /projects/${PROJECT}/posture`] = () =>
      json(200, {
        project_id: PROJECT,
        project_name: HOSTILE,
        role: "operator",
        findings: zero,
        targets: [],
        targets_truncated: false,
        latest_comparison: null,
        latest_report: null,
        latest_retest_report: null,
        recent_scans: [],
      });
    replies[`GET /projects/${PROJECT}/targets`] = () => json(200, []);
    replies[`GET /projects/${PROJECT}/assessments`] = () => json(200, []);
    const out = await page(ProjectPage({ params: Promise.resolve({ projectId: PROJECT }) }));
    expect(out).toContain("Your role: Operator");
    expect(out).not.toContain(`href="/projects/${PROJECT}/members"`);
    expect(out).not.toContain("<img");
    expect(calls.some((c) => c.path.endsWith("/members") || c.path.endsWith("/audit-events"))).toBe(
      false,
    );
  });

  it("hides the settings forms from non-owners and from an unknown role", async () => {
    replies[`GET /projects/${PROJECT}`] = () => json(200, project);
    for (const reply of [mine("viewer"), mine("operator"), () => json(200, {}), NOT_FOUND]) {
      replies[`GET /projects/${PROJECT}/membership/me`] = reply;
      const out = await page(SettingsPage({ params: Promise.resolve({ projectId: PROJECT }) }));
      expect(out).toContain("Only project owners can change these settings.");
      expect(out).not.toContain('data-testid="update-project"');
      expect(out).not.toContain('data-testid="delete-project"');
    }
  });

  it("still lets the API decide when the console believes the user is an owner", async () => {
    replies[`PATCH /projects/${PROJECT}`] = FORBIDDEN;
    replies[`GET /projects/${PROJECT}/membership/me`] = mine("owner");
    const state = await actions.updateProjectAction(
      PROJECT,
      IDLE,
      form({ name: "x", role: "owner" }),
    );
    expect(state).toMatchObject({
      status: "error",
      error: { status: 403, title: "Not permitted" },
    });
    // The action asks nothing about roles: it sends the change and shows the answer.
    expect(calls.map((c) => c.path)).toEqual([`/projects/${PROJECT}`]);
    expect(env.refreshes).toBe(0);
  });
});
