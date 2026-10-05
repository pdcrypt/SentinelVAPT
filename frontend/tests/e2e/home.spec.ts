import { expect, test } from "@playwright/test";

import { activate, createAccount } from "./support/accounts";
import { LIVE, LIVE_ONLY, signIn } from "./support/session";

test("the console starts at sign-in", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
});

test("home page renders and reports API status once signed in", async ({ page }) => {
  test.skip(!LIVE, LIVE_ONLY);
  const account = await createAccount("home");
  await activate(account);
  await signIn(page, account);
  await expect(page.getByRole("heading", { level: 1, name: "SentinelVAPT" })).toBeVisible();
  await expect(page.getByTestId("api-status")).toHaveText(/API: online/);
});

test("security headers are set", async ({ request }) => {
  const res = await request.get("/");
  const headers = res.headers();
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["cache-control"]).toContain("no-store");
  expect(headers["x-powered-by"]).toBeUndefined();
});
