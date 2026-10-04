import { request as httpRequest } from "node:http";

import { expect, test } from "@playwright/test";

// Browser-facing security controls of the operator console (ADR 0013),
// checked against the running server.

const BASE = new URL(process.env.E2E_BASE_URL ?? "http://localhost:3000");

/** A raw HTTP request, so Host/Origin can be set to anything (browsers and
 *  fetch do not allow forging them). */
function raw(
  method: string,
  path: string,
  headers: Record<string, string>,
  body = "",
): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: BASE.hostname,
        port: BASE.port,
        method,
        path,
        headers: { ...headers, "Content-Length": String(Buffer.byteLength(body)) },
        setHost: false,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("application pages carry a per-request nonce CSP without unsafe-inline scripts", async ({
  request,
}) => {
  const first = await request.get("/projects");
  const second = await request.get("/projects");
  const csp = first.headers()["content-security-policy"] ?? "";
  const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
  expect(nonce).toBeTruthy();
  expect(second.headers()["content-security-policy"]).not.toContain(`'nonce-${nonce}'`);
  const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
  expect(scriptSrc).toContain("'strict-dynamic'");
  expect(scriptSrc).not.toContain("'unsafe-inline'");
  expect(csp).not.toContain("'unsafe-eval'"); // production build
  expect(csp).toContain("frame-ancestors 'none'");
  expect(first.headers()["x-frame-options"]).toBe("DENY");
  expect(first.headers()["x-content-type-options"]).toBe("nosniff");
  const html = await first.text();
  const scripts = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
  expect(scripts.length).toBeGreaterThan(0);
  for (const tag of scripts) expect(tag).toContain(`nonce="${nonce}"`);
});

test("the application runs under its CSP without violations", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (/Content Security Policy|Refused to (execute|load|apply)/i.test(msg.text())) {
      violations.push(msg.text());
    }
  });
  for (const path of [
    "/",
    "/projects",
    "/findings",
    "/reports",
    "/retests",
    "/retest-reports",
    "/rules",
  ]) {
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
  }
  // Client navigation works (scripts loaded with the nonce).
  await page.getByRole("link", { name: "Projects" }).first().click();
  await expect(page).toHaveURL(/\/projects$/);
  expect(violations).toEqual([]);
});

test("forged or unexpected Host headers are refused (DNS rebinding)", async () => {
  for (const host of ["evil.example", "evil.example:3000", "localhost:3000.evil.example", ""]) {
    const res = await raw("GET", "/projects", { Host: host });
    expect(res.status, host).toBe(421);
    expect(res.body).not.toContain("<html");
  }
  const forwarded = await raw("GET", "/projects", {
    Host: `${BASE.host}`,
    "X-Forwarded-Host": "evil.example",
  });
  expect(forwarded.status).toBe(421);
  expect((await raw("GET", "/projects", { Host: BASE.host })).status).toBe(200);
});

test("cross-site writes are refused", async () => {
  const cases: Record<string, string>[] = [
    { Host: BASE.host, Origin: "http://evil.example" },
    { Host: BASE.host, Origin: "null" },
    { Host: BASE.host }, // no Origin
    { Host: BASE.host, Origin: BASE.origin, "Sec-Fetch-Site": "cross-site" },
  ];
  for (const headers of cases) {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const res = await raw(
        method,
        "/projects",
        {
          ...headers,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        "name=csrf",
      );
      expect(res.status, `${method} ${JSON.stringify(headers)}`).toBe(403);
    }
  }
});

test("a cross-site form in a real browser cannot create anything", async ({ page, request }) => {
  const name = `csrf-${Date.now()}`;
  // A page on another origin (about:blank → Origin "null") posting to the console.
  await page.setContent(
    `<form id="f" method="post" action="${BASE.origin}/projects">` +
      `<input name="name" value="${name}"></form>`,
  );
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url().startsWith(`${BASE.origin}/projects`)),
    page.evaluate(() => (document.getElementById("f") as HTMLFormElement).submit()),
  ]);
  expect(response.status()).toBe(403);
  const list = await (await request.get("/projects")).text();
  expect(list).not.toContain(name);
});

test("the client bundle never contains the API address", async ({ request }) => {
  const html = await (await request.get("/")).text();
  expect(html).not.toMatch(/:8000|API_INTERNAL_URL|backend:8000/);
  const chunks = [
    ...new Set([...html.matchAll(/\/_next\/static\/[^"'\s)]+\.js/g)].map((m) => m[0])),
  ];
  expect(chunks.length).toBeGreaterThan(0);
  for (const chunk of chunks) {
    const js = await (await request.get(chunk)).text();
    expect(js, chunk).not.toMatch(/API_INTERNAL_URL|backend:8000|127\.0\.0\.1:8000|localhost:8000/);
    expect(js, chunk).not.toContain("NEXT_PUBLIC_");
  }
});

test("artifact routes validate identifiers and never render inline downloads", async ({
  request,
}) => {
  for (const path of [
    "/artifacts/reports/not-a-uuid/json",
    "/artifacts/reports/00000000-0000-4000-8000-000000000000/docx",
    "/artifacts/retest-reports/..%2f..%2fhealth/preview",
  ]) {
    const res = await request.get(path);
    expect([404]).toContain(res.status());
    expect(res.headers()["content-security-policy"]).toContain("sandbox");
  }
});

test("a NUL character is rejected as a validation error, without server internals", async ({
  page,
}) => {
  test.skip(!process.env.E2E_BASE_URL, "needs the API (set E2E_BASE_URL)");
  await page.goto("/projects");
  const form = page.getByTestId("create-project");
  await form.locator('[name="name"]').evaluate((el: HTMLInputElement) => {
    el.value = "nul\u0000name";
  });
  await form.locator('button[type="submit"]').click();
  const alert = form.getByRole("alert");
  await expect(alert).toBeVisible();
  // The API refuses NUL with a 422 validation error (PostgreSQL text cannot hold it).
  await expect(alert).toContainText("Check the form");
  await expect(alert).toContainText("Text must not contain NUL (U+0000) characters");
  await expect(alert).not.toContainText(/Traceback|Internal Server Error|psycopg|DataError/);
});
