import { expect, test } from "@playwright/test";

test("home page renders and reports API status", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "SentinelVAPT" })).toBeVisible();
  // Online or unavailable depending on whether the backend is running; it must
  // render either way rather than crash.
  await expect(page.getByTestId("api-status")).toHaveText(/API: (online|unavailable)/);
});

test("security headers are set", async ({ request }) => {
  const res = await request.get("/");
  const headers = res.headers();
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["x-powered-by"]).toBeUndefined();
});
