import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

import {
  activate,
  adminAccount,
  adminToken,
  api,
  createAccount,
  type Account,
} from "./support/accounts";
import { LIVE, LIVE_ONLY, sessionCookie, signIn } from "./support/session";

// Phase 9 M10 against the live stack: enabling accounts, global roles, the
// caller's own project role, and path authority, through the console.

test.describe.configure({ mode: "serial" });
test.skip(!LIVE, LIVE_ONLY);

const RUN = Date.now().toString(36);

const people: Record<string, Account> = {};
const tokens: Record<string, string> = {};
const state = { project: "", other: "" };

async function as(
  browser: Browser,
  account: { username: string; password: string },
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, account);
  return { context, page };
}

async function tryLogin(account: { username: string; password: string }): Promise<number> {
  return (
    await api("POST", "/auth/login", {
      body: { username: account.username, password: account.password },
    })
  ).status;
}

async function auditFor(
  userId: string,
  action: string,
): Promise<{ metadata: Record<string, unknown>; outcome: string }[]> {
  const { body } = await api<{ metadata: Record<string, unknown>; outcome: string }[]>(
    "GET",
    `/audit-events?resource_id=${userId}&action=${action}&limit=100`,
    { token: await adminToken() },
  );
  return body;
}

test.beforeAll(async () => {
  for (const name of ["owner", "operator", "viewer", "outsider", "subject"]) {
    people[name] = await createAccount(`m10${name}`);
    tokens[name] = await activate(people[name]);
  }
  const project = await api<{ id: string }>("POST", "/projects", {
    token: tokens.owner,
    body: { name: `M10 project ${RUN}` },
  });
  state.project = project.body.id;
  const other = await api<{ id: string }>("POST", "/projects", {
    token: tokens.owner,
    body: { name: `M10 other ${RUN}` },
  });
  state.other = other.body.id;
  for (const [name, role] of [
    ["operator", "operator"],
    ["viewer", "viewer"],
    ["subject", "viewer"],
  ] as const) {
    for (const pid of [state.project, state.other]) {
      const added = await api("POST", `/projects/${pid}/members`, {
        token: tokens.owner,
        body: { username: people[name]!.username, role },
      });
      expect(added.status).toBe(201);
    }
  }
});

async function membersOf(projectId: string): Promise<Record<string, string>> {
  const { body } = await api<{ username: string; role: string }[]>(
    "GET",
    `/projects/${projectId}/members`,
    { token: tokens.owner },
  );
  return Object.fromEntries(body.map((m) => [m.username, m.role]));
}

async function openAccount(page: Page, account: Account): Promise<void> {
  await page.goto(`/admin/users/${account.id}`);
  await expect(page.locator("h1")).toContainText(account.username);
}

test("an administrator disables and re-enables an account", async ({ browser }) => {
  const subject = people.subject!;
  const user = await as(browser, subject);
  await expect(user.page.getByTestId("current-username")).toHaveText(subject.username);
  const admin = await as(browser, adminAccount());

  await openAccount(admin.page, subject);
  const disable = admin.page.getByTestId("disable-user");
  await disable.locator('[name="confirm"]').check();
  await disable.getByRole("button", { name: "Disable account" }).click();
  await expect(admin.page.getByTestId("enable-user")).toBeVisible();
  expect(await tryLogin(subject)).toBe(401);
  const stale = (await sessionCookie(user.context))!;

  // Enabling needs the tick, then works; the old session does not come back.
  const enable = admin.page.getByTestId("enable-user");
  await enable.getByRole("button", { name: "Enable account" }).click();
  expect(
    await enable.locator('[name="confirm"]').evaluate((el: HTMLInputElement) => el.validity.valid),
  ).toBe(false);
  await enable.locator('[name="confirm"]').check();
  await enable.getByRole("button", { name: "Enable account" }).click();
  await expect(admin.page.getByTestId("disable-user")).toBeVisible();
  await expect(admin.page.locator("main")).toContainText("Active");

  await user.context.addCookies([stale]);
  await user.page.goto("/projects");
  await expect(user.page).toHaveURL(/\/login\?session=expired$/);
  // Same password as before, nothing reset.
  await signIn(user.page, subject);
  await expect(user.page.getByTestId("current-username")).toHaveText(subject.username);
  await user.context.close();

  const enabled = await auditFor(subject.id, "user.enabled");
  expect(enabled.length).toBe(1);
  await admin.context.close();
});

test("an administrator promotes and demotes; memberships never change", async ({ browser }) => {
  const subject = people.subject!;
  const before = [await membersOf(state.project), await membersOf(state.other)];
  const admin = await as(browser, adminAccount());
  const user = await as(browser, subject);
  const nav = (p: Page) => p.getByRole("navigation", { name: "Main" });
  await expect(nav(user.page).getByRole("link", { name: "Accounts" })).toHaveCount(0);

  const change = async (role: "admin" | "user") => {
    await openAccount(admin.page, subject);
    const form = admin.page.getByTestId("change-global-role");
    await form.locator('[name="global_role"]').selectOption(role);
    await form.locator('[name="confirm"]').check();
    await form.getByRole("button", { name: "Change global role" }).click();
    await expect(admin.page.getByTestId("global-role")).toHaveText(role);
  };

  await change("admin");
  // The subject's session ended with the change; signed in again, they administer.
  await user.page.reload();
  await expect(user.page).toHaveURL(/\/login\?session=expired$/);
  await signIn(user.page, subject);
  await expect(nav(user.page).getByRole("link", { name: "Accounts" })).toBeVisible();
  await user.page.goto("/admin/users");
  await expect(user.page.getByTestId("users-table")).toBeVisible();
  // ...yet being an administrator adds no project: their role is unchanged.
  await user.page.goto(`/projects/${state.project}`);
  await expect(user.page.getByTestId("project-role")).toHaveText("Your role: Viewer");

  await change("user");
  await user.page.reload();
  await expect(user.page).toHaveURL(/\/login\?session=expired$/);
  await signIn(user.page, subject);
  await expect(nav(user.page).getByRole("link", { name: "Accounts" })).toHaveCount(0);
  await user.page.goto("/admin/users");
  await expect(user.page.locator(".panel-error").first()).toContainText("Not permitted");

  expect([await membersOf(state.project), await membersOf(state.other)]).toEqual(before);
  const events = await auditFor(subject.id, "user.global_role_changed");
  expect(events.map((e) => `${e.metadata.from_role}->${e.metadata.to_role}`).sort()).toEqual([
    "admin->user",
    "user->admin",
  ]);
  await user.context.close();
  await admin.context.close();
});

test("an administrator cannot demote or disable themselves", async ({ browser }) => {
  const admin = await as(browser, adminAccount());
  const { body: me } = await api<{ user: { id: string } }>("GET", "/auth/me", {
    token: await adminToken(),
  });
  await admin.page.goto(`/admin/users/${me.user.id}`);
  await expect(admin.page.getByText("This is your own account.")).toBeVisible();
  for (const id of ["change-global-role", "disable-user", "reset-password"]) {
    await expect(admin.page.getByTestId(id)).toHaveCount(0);
  }
  // Straight at the API: refused, audited, unchanged.
  const demote = await api("PATCH", `/users/${me.user.id}/global-role`, {
    token: await adminToken(),
    body: { global_role: "user" },
  });
  expect(demote.status).toBe(409);
  const refused = await auditFor(me.user.id, "user.change_refused");
  expect(refused.some((e) => e.metadata.operation === "change_global_role")).toBe(true);
  const after = await api<{ global_role: string; is_active: boolean }>(
    "GET",
    `/users/${me.user.id}`,
    {
      token: await adminToken(),
    },
  );
  expect(after.body).toMatchObject({ global_role: "admin", is_active: true });
  await admin.context.close();
});

test("each member sees their own role, and only what it allows", async ({ browser }) => {
  for (const [name, label, ownerTabs] of [
    ["owner", "Owner", true],
    ["operator", "Operator", false],
    ["viewer", "Viewer", false],
  ] as const) {
    const { context, page } = await as(browser, people[name]!);
    await page.goto(`/projects/${state.project}`);
    await expect(page.getByTestId("project-role")).toHaveText(`Your role: ${label}`);
    const tabs = page.getByRole("navigation", { name: "Project" });
    for (const tab of ["Members", "Audit log", "Settings"]) {
      await expect(tabs.getByRole("link", { name: tab }), `${name} ${tab}`).toHaveCount(
        ownerTabs ? 1 : 0,
      );
    }
    if (!ownerTabs) {
      // Nothing about the other members is on the page.
      for (const other of ["owner", "operator", "viewer", "subject"]) {
        if (other !== name) {
          await expect(page.locator("body")).not.toContainText(people[other]!.username);
        }
      }
    }
    await context.close();
  }
  const outsider = await as(browser, people.outsider!);
  await outsider.page.goto(`/projects/${state.project}`);
  await expect(outsider.page.getByRole("heading", { name: "Not found" })).toBeVisible();
  await outsider.context.close();
  // Reading one's role is not security history: the members' visits
  // recorded no refusal (the outsider's 404 is, as it should be).
  const denied = await api<{ actor_user_id: string | null }[]>(
    "GET",
    `/audit-events?project_id=${state.project}&action=authz.denied&limit=100`,
    { token: await adminToken() },
  );
  const members = new Set(["owner", "operator", "viewer"].map((n) => people[n]!.id));
  expect(denied.body.filter((e) => e.actor_user_id && members.has(e.actor_user_id))).toEqual([]);
  expect(denied.body.some((e) => e.actor_user_id === people.outsider!.id)).toBe(true);
});

test("hidden form fields cannot retarget an account or a project", async ({ browser }) => {
  const subject = people.subject!;
  const outsider = people.outsider!;
  const admin = await as(browser, adminAccount());
  await openAccount(admin.page, subject);
  const form = admin.page.getByTestId("change-global-role");
  await form.evaluate((el, other) => {
    for (const [name, value] of [
      ["user_id", other],
      ["userId", other],
      ["username", "e2e-admin"],
    ]) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name!;
      input.value = value!;
      el.appendChild(input);
    }
  }, outsider.id);
  await form.locator('[name="global_role"]').selectOption("admin");
  await form.locator('[name="confirm"]').check();
  await form.getByRole("button", { name: "Change global role" }).click();
  await expect(admin.page.getByTestId("global-role")).toHaveText("admin");
  const target = await api<{ global_role: string }>("GET", `/users/${subject.id}`, {
    token: await adminToken(),
  });
  const bystander = await api<{ global_role: string }>("GET", `/users/${outsider.id}`, {
    token: await adminToken(),
  });
  expect([target.body.global_role, bystander.body.global_role]).toEqual(["admin", "user"]);
  // Back to a user for the rest of the suite.
  await api("PATCH", `/users/${subject.id}/global-role`, {
    token: await adminToken(),
    body: { global_role: "user" },
  });
  await admin.context.close();

  // A member role change on project A with project B smuggled in changes A only.
  const owner = await as(browser, people.owner!);
  const before = await membersOf(state.other);
  await owner.page.goto(`/projects/${state.project}/members`);
  const role = owner.page.getByTestId(`role-${people.viewer!.username}`);
  await role.evaluate((el, other) => {
    for (const [name, value] of [
      ["project_id", other],
      ["projectId", other],
    ]) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name!;
      input.value = value!;
      el.appendChild(input);
    }
  }, state.other);
  await role.locator('[name="role"]').selectOption("operator");
  await role.getByRole("button", { name: "Change role" }).click();
  const table = owner.page.getByTestId("members-table");
  await expect(table.locator(`tr[data-username="${people.viewer!.username}"]`)).toHaveAttribute(
    "data-role",
    "operator",
  );
  expect(await membersOf(state.other)).toEqual(before);
  expect((await membersOf(state.project))[people.viewer!.username]).toBe("operator");
  await owner.context.close();
});

test("the new administration pages keep the token out of the browser", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const urls: string[] = [];
  const bodies: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  page.on("response", async (r) => {
    try {
      bodies.push(await r.text());
    } catch {
      // redirects have no body
    }
  });
  await signIn(page, adminAccount());
  await openAccount(page, people.subject!);
  await page.goto(`/admin/audit?action=user.global_role_changed`);
  await expect(page.getByTestId("audit-table")).toBeVisible();
  for (const body of bodies) expect(body).not.toMatch(/"token"\s*:|token_type|Bearer |\$argon2/);
  for (const url of urls) {
    expect(url.startsWith("http://localhost:3000/") || url.startsWith("data:"), url).toBe(true);
    expect(new URL(url).search, url).not.toMatch(/token|password|user_id=/i);
  }
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  const direct = await page.evaluate(() =>
    fetch("http://localhost:8000/api/v1/users").then(
      () => "reached",
      () => "blocked",
    ),
  );
  expect(direct).toBe("blocked");
  await context.close();
});
