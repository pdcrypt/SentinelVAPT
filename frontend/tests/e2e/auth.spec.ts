import { expect, test, type Page } from "@playwright/test";

import {
  activate,
  adminAccount,
  api,
  auditActions,
  createAccount,
  disable,
  newPassword,
  resetPassword,
  type Account,
} from "./support/accounts";
import { changePassword, COOKIE, LIVE, LIVE_ONLY, sessionCookie, signIn } from "./support/session";

// Browser sessions and sign-in (ADR 0014, Phase 9 M8), against the running
// server. The first group needs only the Next.js server; the rest use real
// accounts on the live compose stack (tests/e2e/support/accounts.ts).

const BASE = new URL(process.env.E2E_BASE_URL ?? "http://localhost:3000");
const SAME_ORIGIN = { Origin: BASE.origin, "Sec-Fetch-Site": "same-origin" };

/** An account that has already replaced its temporary password. */
async function ready(prefix: string): Promise<Account> {
  const account = await createAccount(prefix);
  await activate(account);
  return account;
}

async function storage(page: Page): Promise<number> {
  return page.evaluate(() => localStorage.length + sessionStorage.length);
}

test.describe("without a session", () => {
  test("protected pages redirect to sign-in and reveal nothing", async ({ page, request }) => {
    for (const path of [
      "/",
      "/projects",
      "/findings",
      "/reports",
      "/rules",
      "/account/password",
      "/projects/00000000-0000-4000-8000-000000000000",
      "/artifacts/reports/00000000-0000-4000-8000-000000000000/json",
    ]) {
      const res = await request.get(path, { maxRedirects: 0 });
      expect(res.status(), path).toBe(303);
      expect(new URL(res.headers()["location"]!, BASE).pathname, path).toBe("/login");
      expect(res.headers()["cache-control"]).toContain("no-store");
      expect(await res.text(), path).not.toMatch(/<|project|finding|report/i);
    }
    await page.goto("/projects?view=x");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  });

  test("a stale or forged cookie gets no further than sign-in", async ({ page, context }) => {
    await context.addCookies([
      {
        name: COOKIE,
        value: "a".repeat(43),
        domain: BASE.hostname,
        path: "/",
        secure: true,
        httpOnly: true,
        sameSite: "Strict",
      },
    ]);
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/login\?session=expired$/);
    await expect(page.getByText("Your session has ended.")).toBeVisible();
    expect(await sessionCookie(context)).toBeUndefined(); // cleared by /session/end
  });

  test("the sign-in page is public, labelled and stores nothing", async ({ page, context }) => {
    const res = await page.goto("/login");
    expect(res?.status()).toBe(200);
    expect(res?.headers()["cache-control"]).toContain("no-store");
    const username = page.getByLabel("Username");
    const password = page.locator('input[name="password"]');
    await expect(username).toHaveAttribute("autocomplete", "username");
    await expect(password).toHaveAttribute("type", "password");
    await expect(password).toHaveAttribute("autocomplete", "current-password");
    await expect(page.getByLabel(/^Password/)).toBeVisible();
    // Keyboard only: type, tab, type, Enter submits.
    await username.focus();
    await page.keyboard.type("nobody-here");
    await page.keyboard.press("Tab");
    await expect(password).toBeFocused();
    expect(await storage(page)).toBe(0);
    expect(await sessionCookie(context)).toBeUndefined();
  });

  test("writes without a session are refused", async ({ request }) => {
    const res = await request.post("/projects", {
      headers: { ...SAME_ORIGIN, "Content-Type": "application/x-www-form-urlencoded" },
      data: "name=anonymous",
      maxRedirects: 0,
    });
    expect(res.status()).toBe(401);
  });
});

test.describe("signed in", () => {
  test.skip(!LIVE, LIVE_ONLY);

  test("a failed sign-in says nothing about why", async ({ page, context }) => {
    const disabled = await ready("disabled");
    await disable(disabled);
    const known = await ready("known");
    for (const attempt of [
      { username: `e2e-nobody-${Date.now()}`, password: newPassword() },
      { username: known.username, password: newPassword() },
      { username: disabled.username, password: disabled.password },
    ]) {
      await signInExpectingFailure(page, attempt);
      const alert = page.getByTestId("login-form").getByRole("alert");
      await expect(alert).toContainText("Invalid username or password.");
      await expect(page.locator("body")).not.toContainText(attempt.password);
      await expect(page.locator('input[name="password"]')).toHaveValue("");
      expect(page.url()).toBe(`${BASE.origin}/login`);
      expect(await sessionCookie(context)).toBeUndefined();
    }
  });

  test("sign-in keeps the API token on the server", async ({ page, context }) => {
    const account = await ready("cookie");
    const bodies: string[] = [];
    const urls: string[] = [];
    page.on("request", (r) => urls.push(r.url()));
    page.on("response", async (r) => {
      try {
        bodies.push(await r.text());
      } catch {
        // redirects and aborted requests have no body
      }
    });
    await signIn(page, account);
    await expect(page.getByTestId("current-username")).toHaveText(account.username);
    for (const path of ["/projects", "/findings", "/rules"]) {
      await page.goto(path);
      await expect(page.locator("h1")).toBeVisible();
    }

    const cookie = await sessionCookie(context);
    expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/" });
    expect(cookie!.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const hours = (cookie!.expires * 1000 - Date.now()) / 3_600_000;
    expect(hours).toBeGreaterThan(1);
    expect(hours).toBeLessThanOrEqual(24);
    // Only cookie on the origin, invisible to scripts, nothing in storage.
    expect((await context.cookies()).map((c) => c.name)).toEqual([COOKIE]);
    expect(await page.evaluate(() => document.cookie)).toBe("");
    expect(await storage(page)).toBe(0);
    // The cookie is a reference: the API does not accept it as a credential.
    expect((await api("GET", "/auth/me", { token: cookie!.value })).status).toBe(401);
    // No page, payload or URL carries a token or the cookie value.
    for (const body of bodies) {
      expect(body).not.toMatch(/"token"\s*:|token_type|Bearer /);
      expect(body).not.toContain(cookie!.value);
    }
    for (const url of urls) {
      // Nothing secret in any query string (paths like /account/password are fine).
      expect(new URL(url).search, url).not.toMatch(/token|password|secret|session=(?!expired)/i);
      expect(url).not.toContain(cookie!.value);
      expect(url.startsWith(`${BASE.origin}/`) || url.startsWith("data:"), url).toBe(true);
    }
  });

  test("a new account must change its password before anything else", async ({ page }) => {
    const account = await createAccount("newcomer");
    await signIn(page, account);
    await expect(page).toHaveURL(/\/account\/password$/);
    await expect(page.getByText("Choose a new one to continue.")).toBeVisible();
    // No way around it: every console page leads back here.
    for (const path of ["/", "/projects", "/rules"]) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/account\/password$/);
    }
    const form = page.getByTestId("password-form");
    const attempt = async (current: string, next: string, confirm: string) => {
      await form.locator('[name="current_password"]').fill(current);
      await form.locator('[name="new_password"]').fill(next);
      await form.locator('[name="confirm_password"]').fill(confirm);
      await form.getByRole("button", { name: "Change password" }).click();
    };
    const wrong = newPassword();
    await attempt(wrong, newPassword(), "different");
    await expect(form.getByRole("alert")).toContainText("The new passwords do not match.");
    await attempt(wrong, "abc123", "abc123");
    await expect(form.getByRole("alert")).toContainText("The current password is incorrect.");
    await attempt(account.password, "short", "short");
    await expect(form.getByRole("alert")).toContainText("at least 12 characters");
    await expect(page.locator("body")).not.toContainText(account.password);
    await expect(page.locator("body")).not.toContainText(wrong);
    expect(page.url()).toBe(`${BASE.origin}/account/password`);

    const next = newPassword();
    await changePassword(page, account.password, next);
    await expect(page.getByTestId("current-username")).toHaveText(account.username);
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/projects$/);
    expect(await auditActions(account)).toContain("auth.password_changed");
  });

  test("signing out revokes the API session and clears the cookie", async ({ page, context }) => {
    const account = await ready("signout");
    await signIn(page, account);
    const before = (await sessionCookie(context))!;
    await page.getByTestId("sign-out").click();
    await expect(page).toHaveURL(/\/login$/);
    expect(await sessionCookie(context)).toBeUndefined();
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/login$/);
    // Replaying the old cookie does nothing: the server forgot it.
    await context.addCookies([{ ...before }]);
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/login\?session=expired$/);
    expect(await auditActions(account)).toContain("auth.logout");
  });

  test("disabling a user ends their browser session", async ({ page, context }) => {
    const account = await ready("disable");
    await signIn(page, account);
    await expect(page.getByTestId("current-username")).toHaveText(account.username);
    await disable(account);
    await page.reload();
    await expect(page).toHaveURL(/\/login\?session=expired$/);
    await expect(page.getByText("Your session has ended.")).toBeVisible();
    expect(await sessionCookie(context)).toBeUndefined();
    await signInExpectingFailure(page, account);
    await expect(page.getByTestId("login-form").getByRole("alert")).toContainText(
      "Invalid username or password.",
    );
  });

  test("an administrator's password reset ends the user's sessions", async ({ page, context }) => {
    const account = await ready("reset");
    await signIn(page, account);
    await page.goto("/projects");
    await resetPassword(account);
    await page.getByRole("link", { name: "Rule catalog" }).click(); // a client navigation
    await expect(page).toHaveURL(/\/login\?session=expired$/);
    expect(await sessionCookie(context)).toBeUndefined();
    await signIn(page, account); // the temporary password from the reset
    await expect(page).toHaveURL(/\/account\/password$/);
  });

  test("project access still follows membership in the API", async ({ browser }) => {
    const owner = await createAccount("owner");
    const ownerToken = await activate(owner);
    const viewer = await ready("viewer");
    const outsider = await ready("outsider");
    const name = `M8 membership ${Date.now()}`;
    const project = await api<{ id: string }>("POST", "/projects", {
      token: ownerToken,
      body: { name },
    });
    expect(project.status).toBe(201);
    const added = await api("POST", `/projects/${project.body.id}/members`, {
      token: ownerToken,
      body: { username: viewer.username, role: "viewer" },
    });
    expect(added.status).toBe(201);

    async function as(account: { username: string; password: string }) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await signIn(page, account);
      return { context, page };
    }

    // The viewer sees the project and is refused (403) when writing.
    const v = await as(viewer);
    await v.page.goto(`/projects/${project.body.id}`);
    await expect(v.page.locator("h1")).toContainText(name);
    await v.page.goto(`/projects/${project.body.id}/targets`);
    const form = v.page.getByTestId("create-target");
    await form.locator('[name="name"]').fill("viewer target");
    await form.locator('[name="base_url"]').fill("http://sv-e2e-lab/");
    await form.locator('[name="in_scope_hosts"]').fill("sv-e2e-lab");
    await form.locator('[name="authorized_by"]').fill("Lab Owner");
    await form.locator('[name="reference"]').fill("LAB-M8");
    await form.locator('[name="acknowledge"]').check();
    await form.locator('button[type="submit"]').click();
    const alert = form.getByRole("alert");
    await expect(alert).toContainText("Not permitted");
    await expect(alert).toContainText("You do not have permission to do this.");
    await v.context.close();

    // A signed-in non-member, and a global administrator who is not a
    // member, get "not found": being an administrator grants no project.
    for (const account of [outsider, adminAccount()]) {
      const o = await as(account);
      await o.page.goto(`/projects/${project.body.id}`);
      await expect(o.page.getByRole("heading", { name: "Not found" })).toBeVisible();
      await expect(o.page.locator("body")).not.toContainText(name);
      await o.page.goto("/projects");
      await expect(o.page.locator("body")).not.toContainText(name);
      await o.context.close();
    }
  });

  test("cross-site requests cannot act for a signed-in user", async ({ page }) => {
    const account = await ready("csrf");
    await signIn(page, account);
    const name = `csrf-${Date.now()}`;
    // Another origin (about:blank posts with Origin "null"), same browser,
    // signed in to the console.
    await page.goto("about:blank");
    await page.setContent(
      `<form id="f" method="post" action="${BASE.origin}/projects">` +
        `<input name="name" value="${name}"></form>`,
    );
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().startsWith(`${BASE.origin}/projects`) && r.request().method() === "POST",
      ),
      page.evaluate(() => (document.getElementById("f") as HTMLFormElement).submit()),
    ]);
    expect(response.status()).toBe(403);
    await page.waitForURL(`${BASE.origin}/projects`); // the refusal page
    await page.goto("/projects");
    await expect(page.getByTestId("current-username")).toHaveText(account.username);
    await expect(page.locator("body")).not.toContainText(name);
  });

  test("the browser cannot reach the API itself", async ({ page }) => {
    const account = await ready("direct");
    await signIn(page, account);
    const outcome = await page.evaluate(() =>
      fetch("http://localhost:8000/api/v1/health").then(
        () => "reached",
        () => "blocked",
      ),
    );
    expect(outcome).toBe("blocked"); // CSP connect-src 'self'
  });
});

async function signInExpectingFailure(
  page: Page,
  account: { username: string; password: string },
): Promise<void> {
  await page.goto("/login");
  const form = page.getByTestId("login-form");
  await form.getByLabel("Username").fill(account.username);
  await form.locator('[name="password"]').fill(account.password);
  await form.getByRole("button", { name: "Sign in" }).click();
  await expect(form.getByRole("alert")).toBeVisible();
}
