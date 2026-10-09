import { execFileSync } from "node:child_process";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import { activate, api, createAccount, type Account } from "./support/accounts";
import { LIVE, signIn } from "./support/session";

// Verifies the manual retest procedure of tests/lab/README.md, exactly as
// documented: the compose lab target (`--profile lab`), the documented
// variant switch (`lab-variant.sh`), and the platform's ordinary API as a
// signed-in owner. Lab-only and opt-in: it changes the shared lab target's
// variant (restored to A afterwards) and adds a project to the live database.
//
//   docker compose --profile lab up -d
//   $env:E2E_BASE_URL = "http://localhost:3000"; $env:E2E_LAB_RETEST = "1"
//   npx playwright test tests/e2e/lab-retest.spec.ts

test.describe.configure({ mode: "serial" });
test.skip(!LIVE || !process.env.E2E_LAB_RETEST, "set E2E_BASE_URL and E2E_LAB_RETEST=1 (lab only)");

const ROOT = join(process.cwd(), "..");
const TIMEOUT = 240_000;

function labVariant(variant: "a" | "b" | "c"): void {
  // The documented command (tests/lab/README.md).
  execFileSync(
    "docker",
    ["compose", "exec", "-T", "lab-target", "sh", "/lab/lab-variant.sh", variant],
    {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
}

async function until<T>(read: () => Promise<T | null>, what: string): Promise<T> {
  const end = Date.now() + TIMEOUT;
  while (Date.now() < end) {
    const value = await read();
    if (value !== null) return value;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`timed out waiting for ${what}`);
}

type Record_ = {
  rule_id: string;
  state: string;
  reasons: string[];
  current_finding_id: string | null;
  baseline_finding_id: string | null;
};

const owner: { account?: Account; token?: string } = {};
const ids: Record<string, string> = {};

async function call<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const { status, body: out } = await api<T>(method, path, { token: owner.token!, body });
  expect(status, `${method} ${path}`).toBeLessThan(300);
  return out;
}

/** Start the assessment, scan the lab, wait for the scan and its analysis. */
async function scanned(assessment: string): Promise<string> {
  const scan = await call<{ id: string }>("POST", `/assessments/${assessment}/scans`, {});
  await until(async () => {
    const s = await call<{ status: string }>("GET", `/scans/${scan.id}`);
    if (s.status === "failed" || s.status === "cancelled") throw new Error(`scan ${s.status}`);
    if (s.status !== "completed") return null;
    const runs = await call<{ status: string }[]>("GET", `/scans/${scan.id}/analysis`);
    return runs.some((r) => r.status === "completed") ? true : null;
  }, "the scan and its analysis");
  return scan.id;
}

/** Comparison records keyed "rule" or "rule[discriminator]" -> state. */
async function compare(
  retest: string,
  scan: string,
): Promise<{ id: string; states: Record<string, string>; reasons: Record<string, string[]> }> {
  const comparison = await call<{ id: string }>("POST", `/assessments/${retest}/comparisons`, {
    scan_id: scan,
  });
  await until(async () => {
    const c = await call<{ status: string }>("GET", `/comparisons/${comparison.id}`);
    if (c.status === "failed") throw new Error("comparison failed");
    return c.status === "completed" ? true : null;
  }, "the comparison");
  const records = await call<Record_[]>("GET", `/comparisons/${comparison.id}/records?limit=100`);
  const states: Record<string, string> = {};
  const reasons: Record<string, string[]> = {};
  for (const r of records) {
    const finding = await call<{ discriminator: string }>(
      "GET",
      `/findings/${r.current_finding_id ?? r.baseline_finding_id}`,
    );
    const key = finding.discriminator ? `${r.rule_id}[${finding.discriminator}]` : r.rule_id;
    states[key] = r.state;
    reasons[key] = r.reasons;
  }
  return { id: comparison.id, states, reasons };
}

test.beforeAll(async () => {
  labVariant("a");
  owner.account = await createAccount("labretest");
  owner.token = await activate(owner.account);
});

test.afterAll(() => {
  labVariant("a"); // the documented restore step
});

test("baseline A, retest B (FIXED, NEW, DISMISSED) and retest C (REOPENED)", async ({ page }) => {
  test.setTimeout(15 * 60_000);
  // Ordinary application use: project, authorized lab target, assessment.
  const project = await call<{ id: string }>("POST", "/projects", {
    name: `Lab retest ${Date.now()}`,
  });
  ids.project = project.id;
  const now = Date.now();
  const target = await call<{ id: string }>("POST", `/projects/${project.id}/targets`, {
    name: "Lab target",
    base_url: "http://lab-target/",
    environment: "local_lab",
    in_scope_hosts: ["lab-target"],
    authorization: {
      authorized_by: "Lab owner",
      reference: "LAB-RETEST",
      valid_from: new Date(now - 60_000).toISOString(),
      valid_until: new Date(now + 24 * 3600_000).toISOString(),
      acknowledge: true,
    },
  });
  const a = await call<{ id: string }>("POST", `/targets/${target.id}/assessments`, {
    name: "Baseline A",
  });
  await call("POST", `/assessments/${a.id}/start`);
  const scanA = await scanned(a.id);
  // A human decision: X-Content-Type-Options is judged a false positive.
  const [nosniff] = await call<{ id: string }[]>(
    "GET",
    `/scans/${scanA}/findings?rule_id=SV-HDR-004`,
  );
  expect(nosniff).toBeTruthy();
  await call("POST", `/findings/${nosniff!.id}/triage`, {
    status: "false_positive",
    reason: "Lab demo",
  });
  await call("POST", `/assessments/${a.id}/complete`);

  // Lab-only step, then retest B.
  labVariant("b");
  const b = await call<{ id: string }>("POST", `/assessments/${a.id}/retests`, {
    name: "Retest B",
  });
  await call("POST", `/assessments/${b.id}/start`);
  const scanB = await scanned(b.id);
  await call("POST", `/assessments/${b.id}/complete`);
  const cmpB = await compare(b.id, scanB);
  expect(cmpB.states).toMatchObject({
    "SV-HDR-002": "fixed",
    "SV-HDR-003": "fixed",
    "SV-INF-001[x-powered-by]": "fixed",
    "SV-INF-001[x-aspnet-version]": "new",
    "SV-HDR-004": "dismissed",
    "SV-INF-001[server]": "unchanged",
    "SV-TRN-001": "unchanged",
  });

  // Lab-only step, then retest C (a retest of B).
  labVariant("c");
  const c = await call<{ id: string }>("POST", `/assessments/${b.id}/retests`, {
    name: "Retest C",
  });
  await call("POST", `/assessments/${c.id}/start`);
  const scanC = await scanned(c.id);
  await call("POST", `/assessments/${c.id}/complete`);
  const cmpC = await compare(c.id, scanC);
  expect(cmpC.states).toMatchObject({
    "SV-HDR-002": "reopened",
    "SV-HDR-003": "reopened",
    "SV-HDR-004": "new",
    "SV-INF-001[x-aspnet-version]": "unchanged",
    "SV-INF-001[server]": "unchanged",
    "SV-TRN-001": "unchanged",
  });
  expect(cmpC.reasons["SV-HDR-002"]).toContain("previously_fixed");
  expect(cmpC.reasons["SV-HDR-004"]).toContain("previously_dismissed");
  // Nothing else appeared that the documentation does not mention.
  for (const states of [cmpB.states, cmpC.states]) {
    for (const [key, state] of Object.entries(states)) {
      if (!/^SV-(HDR-00[234]|INF-001|TRN-001)/.test(key)) expect(state, key).toBe("unchanged");
    }
  }

  // The dashboard shows the latest comparison (C) counted from its records.
  const posture = await call<{
    latest_comparison: { comparison_id: string; by_state: Record<string, number> };
  }>("GET", `/projects/${project.id}/posture`);
  expect(posture.latest_comparison.comparison_id).toBe(cmpC.id);
  const counted: Record<string, number> = {};
  for (const state of Object.values(cmpC.states)) counted[state] = (counted[state] ?? 0) + 1;
  for (const [state, n] of Object.entries(posture.latest_comparison.by_state)) {
    expect(n, state).toBe(counted[state] ?? 0);
  }
  await signIn(page, owner.account!);
  await page.goto(`/projects/${project.id}`);
  const table = page.getByTestId("state-counts");
  await expect(table.locator('tr[data-key="reopened"]')).toHaveAttribute(
    "data-value",
    String(counted.reopened),
  );
  await expect(
    page.getByTestId("retest-outcome").locator(`a[href="/comparisons/${cmpC.id}"]`),
  ).toBeVisible();
});
