import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

import { activate, adminAccount, api, createAccount, type Account } from "./support/accounts";
import { LIVE, LIVE_ONLY, signIn } from "./support/session";

// M11 security posture dashboard against the live stack: who sees which
// projects, with which role, rendered safely. The A → B → C counts (FIXED,
// then REOPENED) are checked against the comparison and findings pages in
// workflow.spec.ts, which owns the lab target.

test.describe.configure({ mode: "serial" });
test.skip(!LIVE, LIVE_ONLY);

const RUN = Date.now().toString(36);
const XSS = '<img src=x onerror="window.__xss=1">';

const people: Record<string, Account> = {};
const tokens: Record<string, string> = {};
const projects: Record<string, string> = {};

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

test.beforeAll(async () => {
  for (const name of ["owner", "viewer", "outsider"]) {
    people[name] = await createAccount(`m11${name}`);
    tokens[name] = await activate(people[name]);
  }
  for (const name of ["shared", "private"]) {
    const created = await api<{ id: string }>("POST", "/projects", {
      token: tokens.owner,
      body: { name: `M11 ${name} ${RUN} ${XSS}` },
    });
    expect(created.status).toBe(201);
    projects[name] = created.body.id;
  }
  const added = await api("POST", `/projects/${projects.shared}/members`, {
    token: tokens.owner,
    body: { username: people.viewer!.username, role: "viewer" },
  });
  expect(added.status).toBe(201);
});

test("the overview lists exactly the projects each person may see", async ({ browser }) => {
  const expectations: [string, string[], string[]][] = [
    ["owner", [projects.shared!, projects.private!], []],
    ["viewer", [projects.shared!], [projects.private!]],
    ["outsider", [], [projects.shared!, projects.private!]],
  ];
  for (const [name, visible, hidden] of expectations) {
    const { context, page } = await as(browser, people[name]!);
    await page.goto("/");
    const table = page.getByTestId("posture-overview");
    for (const id of visible)
      await expect(table.locator(`tr[data-project="${id}"]`)).toHaveCount(1);
    for (const id of hidden) {
      await expect(page.locator(`[data-project="${id}"]`)).toHaveCount(0);
      expect(await page.content()).not.toContain(id);
    }
    if (visible.length === 0) {
      await expect(page.getByText("You are not a member of any project yet.")).toBeVisible();
    } else {
      await expect(table).toContainText(XSS); // inert text
    }
    await noScriptRan(page);
    await context.close();
  }
});

test("a global administrator who is not a member sees neither project", async ({ browser }) => {
  const { context, page } = await as(browser, adminAccount());
  await page.goto("/");
  for (const id of Object.values(projects)) {
    await expect(page.locator(`[data-project="${id}"]`)).toHaveCount(0);
    await page.goto(`/projects/${id}`);
    await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
    await page.goto("/");
  }
  await context.close();
});

test("owner and viewer see the project posture; only the owner may change it", async ({
  browser,
}) => {
  for (const [name, role] of [
    ["owner", "Owner"],
    ["viewer", "Viewer"],
  ] as const) {
    const { context, page } = await as(browser, people[name]!);
    await page.goto(`/projects/${projects.shared}`);
    await expect(page.getByTestId("project-role")).toHaveText(`Your role: ${role}`);
    await expect(page.locator("h1")).toContainText(XSS);
    // A project without scans: honest empty states, no invented numbers.
    await expect(page.getByText("No findings:")).toBeVisible();
    await expect(page.getByText("No completed comparison yet.")).toBeVisible();
    await expect(page.getByText("No scans yet.")).toBeVisible();
    await expect(page.getByTestId("latest-reports")).toContainText("none completed yet");
    const tabs = page.getByRole("navigation", { name: "Project" });
    await expect(tabs.getByRole("link", { name: "Settings" })).toHaveCount(
      name === "owner" ? 1 : 0,
    );
    if (name === "viewer") {
      await page.goto(`/projects/${projects.shared}/settings`);
      await expect(page.getByTestId("update-project")).toHaveCount(0);
      await page.goto(`/projects/${projects.shared}/members`);
      await expect(page.locator(".panel-error").first()).toContainText("Not permitted");
    }
    await noScriptRan(page);
    await context.close();
  }
  const { context, page } = await as(browser, people.outsider!);
  for (const id of Object.values(projects)) {
    await page.goto(`/projects/${id}`);
    await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(`${RUN}`);
  }
  await context.close();
});

test("the dashboard keeps the API and its token out of the browser", async ({ browser }) => {
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
  await signIn(page, people.owner!);
  for (const path of ["/", `/projects/${projects.shared}`, "/findings"]) {
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
  }
  for (const body of bodies) expect(body).not.toMatch(/"token"\s*:|token_type|Bearer /);
  for (const url of urls) {
    expect(url.startsWith("http://localhost:3000/") || url.startsWith("data:"), url).toBe(true);
    expect(new URL(url).search, url).not.toMatch(/token|password/i);
  }
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  const direct = await page.evaluate(() =>
    fetch("http://localhost:8000/api/v1/posture").then(
      () => "reached",
      () => "blocked",
    ),
  );
  expect(direct).toBe("blocked");
  await context.close();
});
