import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

import {
  activate,
  adminAccount,
  createAccount,
  newPassword,
  type Account,
} from "./support/accounts";
import { LIVE, LIVE_ONLY, signIn } from "./support/session";

// The administration console (Phase 9 M9) against the live stack, through the
// UI only: a global administrator manages accounts and reads the platform
// audit log; a project owner manages members and reads the project audit
// log; a viewer and a non-member are refused exactly as the API decides.

test.describe.configure({ mode: "serial" });
test.skip(!LIVE, LIVE_ONLY);

const RUN = Date.now().toString(36);
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const XSS = '<img src=x onerror="window.__xss=1">';

const people: Record<string, Account> = {};
const state: Record<string, string> = {};

async function as(
  browser: Browser,
  account: { username: string; password: string },
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, account);
  return { context, page };
}

async function noScriptRan(page: Page): Promise<void> {
  expect(
    await page.evaluate(() => (window as unknown as { __xss?: number }).__xss),
  ).toBeUndefined();
}

const alertIn = (page: Page, testId: string) => page.getByTestId(testId).getByRole("alert");
const statusIn = (page: Page, testId: string) => page.getByTestId(testId).getByRole("status");

test.beforeAll(async () => {
  for (const name of ["owner", "viewer", "colleague", "outsider"]) {
    people[name] = await createAccount(`m9${name}`);
    await activate(people[name]);
  }
});

test("a global administrator manages accounts through the console", async ({ browser }) => {
  const { context, page } = await as(browser, adminAccount());

  // Account page and role-aware navigation.
  await page.goto("/account");
  await expect(page.locator("h1")).toBeVisible();
  await expect(page.getByText("Administrator (manages accounts")).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Accounts" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Platform audit log" })).toBeVisible();

  // Create an account with a temporary password.
  await nav.getByRole("link", { name: "Accounts" }).click();
  await expect(page.getByTestId("users-table")).toBeVisible();
  const username = `e2e-m9ui-${RUN}`;
  const temporary = newPassword();
  const create = page.getByTestId("create-user");
  await create.locator('[name="username"]').fill(username);
  await create.locator('[name="display_name"]').fill(`M9 ${XSS}`);
  await create.locator('[name="password"]').fill(temporary);
  await create.locator('[name="confirm_password"]').fill(temporary);
  await create.getByRole("button", { name: "Create account" }).click();
  await page.waitForURL(new RegExp(`/admin/users/${UUID}\\?created=1$`));
  state.created = new RegExp(`/admin/users/(${UUID})`).exec(page.url())![1]!;
  expect(page.url()).not.toContain(temporary);
  await expect(page.getByText("Account created.")).toBeVisible();
  await expect(page.locator("main")).toContainText(XSS); // shown as text
  await expect(page.locator("main")).not.toContainText(temporary);
  await noScriptRan(page);

  // The new user signs in with it and must change it.
  const created = { username, password: temporary };
  const user = await as(browser, created);
  await expect(user.page).toHaveURL(/\/account\/password$/);

  // Reset: their session ends, and only the new temporary password works.
  const reset = newPassword();
  const resetForm = page.getByTestId("reset-password");
  await resetForm.locator('[name="new_password"]').fill(reset);
  await resetForm.locator('[name="confirm_password"]').fill(reset);
  await resetForm.getByRole("button", { name: "Reset password" }).click();
  await expect(statusIn(page, "reset-password")).toContainText("Password reset.");
  await expect(page.locator("main")).not.toContainText(reset);
  await user.page.reload();
  await expect(user.page).toHaveURL(/\/login\?session=expired$/);
  await signIn(user.page, { username, password: reset });
  await expect(user.page).toHaveURL(/\/account\/password$/);

  // Disable: the account cannot sign in any more.
  const disable = page.getByTestId("disable-user");
  await disable.getByRole("button", { name: "Disable account" }).click(); // unconfirmed
  expect(
    await disable.locator('[name="confirm"]').evaluate((el: HTMLInputElement) => el.validity.valid),
  ).toBe(false);
  await disable.locator('[name="confirm"]').check();
  await disable.getByRole("button", { name: "Disable account" }).click();
  // The page reloads from the API: the account is now shown as disabled.
  await expect(page.locator("main")).toContainText("This account is disabled.");
  await expect(page.getByTestId("disable-user")).toHaveCount(0);
  await user.page.reload();
  await expect(user.page).toHaveURL(/\/login\?session=expired$/);
  await user.page.getByTestId("login-form").getByLabel("Username").fill(username);
  await user.page.getByTestId("login-form").locator('[name="password"]').fill(reset);
  await user.page.getByTestId("login-form").getByRole("button", { name: "Sign in" }).click();
  await expect(alertIn(user.page, "login-form")).toContainText("Invalid username or password.");
  await user.context.close();

  // Your own account offers no self-administration (M10); the API refuses
  // it anyway (backend tests and m10.spec.ts).
  await page.goto(`/admin/users?global_role=admin`);
  await page
    .getByTestId("users-table")
    .getByRole("link", { name: adminAccount().username, exact: true })
    .click();
  await expect(page.getByText("This is your own account.")).toBeVisible();
  await expect(page.getByTestId("disable-user")).toHaveCount(0);

  // The platform audit log shows what happened, filtered through the form.
  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "Platform audit log" })
    .click();
  const filters = page.getByTestId("audit-filters");
  await filters.locator('[name="action"]').selectOption("user.disabled");
  await filters.getByRole("button", { name: "Filter" }).click();
  await expect(page).toHaveURL(/action=user\.disabled/);
  const rows = page.getByTestId("audit-table").locator("tbody tr");
  await expect(rows.first()).toHaveAttribute("data-action", "user.disabled");
  for (const action of ["user.created", "user.password_reset", "user.disabled"]) {
    await page.goto(`/admin/audit?action=${action}`);
    await expect(
      page.getByTestId("audit-table").locator(`tr[data-action="${action}"]`).first(),
    ).toBeVisible();
  }
  await context.close();
});

test("a project owner manages members, and the project keeps an owner", async ({ browser }) => {
  const { context, page } = await as(browser, people.owner!);
  await page.goto("/projects");
  const name = `M9 project ${RUN} ${XSS}`;
  await page.getByTestId("create-project").locator('[name="name"]').fill(name);
  await page.getByTestId("create-project").locator('button[type="submit"]').click();
  await page.waitForURL(new RegExp(`/projects/${UUID}$`));
  state.project = new RegExp(`/projects/(${UUID})`).exec(page.url())![1]!;

  await page
    .getByRole("navigation", { name: "Project" })
    .getByRole("link", { name: "Members" })
    .click();
  await expect(page).toHaveURL(new RegExp(`/projects/${state.project}/members$`));
  const table = page.getByTestId("members-table");
  await expect(table.locator(`tr[data-username="${people.owner!.username}"]`)).toHaveAttribute(
    "data-role",
    "owner",
  );

  const add = page.getByTestId("add-member");
  for (const name of ["colleague", "viewer"]) {
    await add.locator('[name="username"]').fill(people[name]!.username);
    await add.locator('[name="role"]').selectOption("viewer");
    await add.getByRole("button", { name: "Add member" }).click();
    await expect(table.locator(`tr[data-username="${people[name]!.username}"]`)).toHaveAttribute(
      "data-role",
      "viewer",
    );
  }
  // Unknown users are refused by the API, not by guesswork.
  await add.locator('[name="username"]').fill(`e2e-nobody-${RUN}`);
  await add.getByRole("button", { name: "Add member" }).click();
  await expect(alertIn(page, "add-member")).toContainText("user not found");

  const colleague = people.colleague!.username;
  const role = page.getByTestId(`role-${colleague}`);
  await role.locator('[name="role"]').selectOption("operator");
  await role.getByRole("button", { name: "Change role" }).click();
  await expect(table.locator(`tr[data-username="${colleague}"]`)).toHaveAttribute(
    "data-role",
    "operator",
  );
  const remove = page.getByTestId(`remove-${colleague}`);
  await remove.locator('[name="confirm"]').check();
  await remove.getByRole("button", { name: "Remove" }).click();
  await expect(table.locator(`tr[data-username="${colleague}"]`)).toHaveCount(0);

  // The last owner can neither step down nor leave.
  const owner = people.owner!.username;
  const own = page.getByTestId(`role-${owner}`);
  await own.locator('[name="role"]').selectOption("viewer");
  await own.getByRole("button", { name: "Change role" }).click();
  await expect(alertIn(page, `role-${owner}`)).toContainText(
    "a project must keep at least one owner",
  );
  const leave = page.getByTestId(`remove-${owner}`);
  await leave.locator('[name="confirm"]').check();
  await leave.getByRole("button", { name: "Remove" }).click();
  await expect(alertIn(page, `remove-${owner}`)).toContainText(
    "a project must keep at least one owner",
  );
  await page.reload();
  await expect(table.locator(`tr[data-username="${owner}"]`)).toHaveAttribute("data-role", "owner");
  await noScriptRan(page);

  // The project audit log has every change and every refusal.
  await page
    .getByRole("navigation", { name: "Project" })
    .getByRole("link", { name: "Audit log" })
    .click();
  const audit = page.getByTestId("audit-table");
  for (const action of [
    "project.created",
    "membership.added",
    "membership.role_changed",
    "membership.removed",
    "membership.change_refused",
  ]) {
    await expect(audit.locator(`tr[data-action="${action}"]`).first()).toBeVisible();
  }
  await expect(audit.locator('tr[data-outcome="denied"]').first()).toBeVisible();
  await page.goto(`/projects/${state.project}/audit?action=membership.role_changed`);
  await expect(audit.locator("tbody tr")).toHaveCount(1);
  await context.close();

  // The platform log has them too, for the administrator.
  const admin = await as(browser, adminAccount());
  await admin.page.goto(`/admin/audit?project_id=${state.project}&action=membership.added`);
  await expect(admin.page.getByTestId("audit-table").locator("tbody tr")).toHaveCount(2);
  // ...yet the administrator is not a member of the project.
  await admin.page.goto(`/projects/${state.project}/members`);
  await expect(admin.page.getByRole("heading", { name: "Not found" })).toBeVisible();
  await admin.context.close();
});

test("a viewer sees the project but none of its administration", async ({ browser }) => {
  const { context, page } = await as(browser, people.viewer!);
  await page.goto(`/projects/${state.project}`);
  await expect(page.locator("h1")).toContainText(`M9 project ${RUN}`);
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "Accounts" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Platform audit log" })).toHaveCount(0);

  for (const path of [
    `/projects/${state.project}/members`,
    `/projects/${state.project}/audit`,
    "/admin/users",
    "/admin/audit",
    `/admin/users/${state.created}`,
  ]) {
    await page.goto(path);
    await expect(page.locator(".panel-error").first(), path).toContainText("Not permitted");
    for (const control of [
      "add-member",
      "members-table",
      "audit-table",
      "users-table",
      "create-user",
      "disable-user",
      "reset-password",
    ]) {
      await expect(page.getByTestId(control), `${path} ${control}`).toHaveCount(0);
    }
  }
  // Owner-only settings: not offered to a viewer (M10 role), and the project
  // tabs show only what a viewer may use.
  await page.goto(`/projects/${state.project}/settings`);
  await expect(page.getByText("Only project owners can change these settings.")).toBeVisible();
  await expect(page.getByTestId("update-project")).toHaveCount(0);
  await page.goto(`/projects/${state.project}`);
  await expect(page.getByTestId("project-role")).toHaveText("Your role: Viewer");
  const tabs = page.getByRole("navigation", { name: "Project" });
  for (const tab of ["Members", "Audit log", "Settings"]) {
    await expect(tabs.getByRole("link", { name: tab })).toHaveCount(0);
  }
  await expect(page.locator("h1")).toContainText(`M9 project ${RUN}`);
  await context.close();
});

test("a non-member cannot tell the project exists", async ({ browser }) => {
  const { context, page } = await as(browser, people.outsider!);
  for (const suffix of ["", "/members", "/audit", "/settings"]) {
    await page.goto(`/projects/${state.project}${suffix}`);
    await expect(page.getByRole("heading", { name: "Not found" }), suffix).toBeVisible();
    await expect(page.locator("body")).not.toContainText(`M9 project ${RUN}`);
  }
  await context.close();
});

test("administration pages keep the API and its token out of the browser", async ({ browser }) => {
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
  for (const path of [
    "/account",
    "/admin/users",
    `/admin/users/${state.created}`,
    "/admin/audit",
  ]) {
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
  }
  for (const body of bodies) expect(body).not.toMatch(/"token"\s*:|token_type|Bearer |\$argon2/);
  for (const url of urls) {
    expect(url.startsWith("http://localhost:3000/") || url.startsWith("data:"), url).toBe(true);
    expect(new URL(url).search, url).not.toMatch(/token|password/i);
  }
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  expect(await page.evaluate(() => document.cookie)).toBe("");
  const direct = await page.evaluate(() =>
    fetch("http://localhost:8000/api/v1/users").then(
      () => "reached",
      () => "blocked",
    ),
  );
  expect(direct).toBe("blocked");
  await context.close();
});
