import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { ReactElement, ReactNode } from "react";
import { renderToReadableStream, renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The security posture dashboard (ADR 0015, M11). The console is presentation
// only: these tests feed it API answers (including deliberately inconsistent
// ones) and check it shows exactly what the API said, never a value it worked
// out itself, and never anything the API did not return.

const env = vi.hoisted(() => {
  class Redirect extends Error {
    constructor(readonly to: string) {
      super(`redirect to ${to}`);
    }
  }
  class NotFound extends Error {}
  return { Redirect, NotFound, jar: new Map<string, string>() };
});

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      env.jar.has(name) ? { name, value: env.jar.get(name) as string } : undefined,
    set: () => undefined,
  }),
  headers: async () => ({ get: () => null }),
}));
vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new env.Redirect(to);
  },
  notFound: () => {
    throw new env.NotFound();
  },
  usePathname: () => "/",
}));
vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

const { sessionStore } = await import("@/lib/auth/store");
const { SECURE_COOKIE_NAME } = await import("@/lib/auth/cookie");
const { SESSION_END_PATH } = await import("@/lib/auth/paths");
const HomePage = (await import("@/app/(console)/page")).default;
const ProjectPage = (await import("@/app/(console)/projects/[projectId]/page")).default;
const FindingsPage = (await import("@/app/(console)/findings/page")).default;
const { ProjectPostureView, PostureOverview } = await import("@/components/posture");

const TOKEN = "api-session-token-posture-xxxxxxxxxxxxxxxxxxxxxxxxx";
const P1 = "11111111-1111-4111-8111-111111111111";
const P2 = "22222222-2222-4222-8222-222222222222";
const T1 = "33333333-3333-4333-8333-333333333333";
const S1 = "44444444-4444-4444-8444-444444444444";
const S2 = "55555555-5555-4555-8555-555555555555";
const C1 = "66666666-6666-4666-8666-666666666666";
const R1 = "77777777-7777-4777-8777-777777777777";
const NOW = "2026-10-06T10:00:00Z";
const HOSTILE = '<img src=x onerror="alert(1)">‮evil';

type Call = { method: string; path: string; query: string };
let calls: Call[] = [];
let replies: Record<string, () => Response> = {};

const json = (status: number, body: unknown) => () =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const html = (node: ReactElement) => renderToStaticMarkup(node);

/** Renders a tree containing async server components (streaming waits for them). */
async function streamed(node: ReactElement): Promise<string> {
  const stream = await renderToReadableStream(node);
  await stream.allReady;
  return new Response(stream).text();
}

async function outcome(promise: Promise<ReactElement>): Promise<string> {
  try {
    return html(await promise);
  } catch (e) {
    if (e instanceof env.Redirect) return `redirect ${e.to}`;
    if (e instanceof env.NotFound) return "not found";
    throw e;
  }
}

const SEVERITY = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
const STATUS = { open: 0, confirmed: 0, accepted_risk: 0, false_positive: 0 };
const STATES = {
  new: 0,
  reopened: 0,
  unchanged: 0,
  still_open: 0,
  fixed: 0,
  dismissed: 0,
  not_retested: 0,
  not_comparable: 0,
};

/** Deliberately inconsistent: the API's own `open` (2) and `active` (7) differ
 *  from what by_status would suggest, so a console that recomputed them would
 *  show other numbers. */
const counts = {
  total: 9,
  active: 7,
  open: 2,
  by_severity: { ...SEVERITY, low: 4, informational: 3 },
  by_status: { ...STATUS, open: 5, confirmed: 1, false_positive: 3 },
};

const comparison = {
  comparison_id: C1,
  target_id: T1,
  target_name: HOSTILE,
  baseline_scan_id: S1,
  current_scan_id: S2,
  current_assessment_id: P2,
  finished_at: NOW,
  by_state: { ...STATES, fixed: 3, new: 1, reopened: 2, dismissed: 1 },
};

function posture(overrides: Record<string, unknown> = {}) {
  return {
    project_id: P1,
    project_name: HOSTILE,
    role: "viewer",
    findings: counts,
    targets: [
      {
        target_id: T1,
        target_name: HOSTILE,
        latest_scan: { scan_id: S1, assessment_id: P2, assessment_name: HOSTILE, finished_at: NOW },
        findings: counts,
      },
    ],
    targets_truncated: false,
    latest_comparison: comparison,
    latest_report: { report_id: R1, number: 4, kind: "final", title: HOSTILE, finished_at: NOW },
    latest_retest_report: null,
    // A newer analysed scan in the history: the API chose S1 as the target's
    // latest, and the console must not second-guess it.
    recent_scans: [
      {
        scan_id: S2,
        assessment_id: P2,
        assessment_name: "B",
        target_id: T1,
        target_name: HOSTILE,
        status: "completed",
        created_at: NOW,
        finished_at: NOW,
        analysed: true,
        findings_total: 99,
      },
    ],
    ...overrides,
  };
}

const summary = (overrides: Record<string, unknown> = {}) => ({
  project_id: P1,
  project_name: HOSTILE,
  role: "owner",
  findings: counts,
  targets_with_analysed_scan: 1,
  latest_scan_finished_at: NOW,
  latest_comparison: comparison,
  latest_report: null,
  latest_retest_report: { report_id: R1, number: 2, kind: "draft", title: "R", finished_at: NOW },
  ...overrides,
});

beforeEach(() => {
  delete (globalThis as Record<symbol, unknown>)[Symbol.for("sentinelvapt.browserSessions")];
  env.jar.clear();
  env.jar.set(SECURE_COOKIE_NAME, sessionStore().create(TOKEN, Date.now() + 3_600_000));
  calls = [];
  replies = {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      const u = new URL(url);
      const call = {
        method: init.method ?? "GET",
        path: u.pathname.replace(/^\/api\/v1/, ""),
        query: u.search,
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

describe("cross-project overview", () => {
  it("shows exactly the projects the API returned, in one request", async () => {
    replies["GET /posture"] = json(200, [
      summary(),
      summary({ project_id: P2, project_name: "Two", role: "viewer" }),
    ]);
    const out = await outcome(HomePage({ searchParams: Promise.resolve({}) }));
    expect(calls.map((c) => c.path)).toEqual(["/posture"]); // no fan-out
    expect(calls[0]!.query).toBe("?limit=50&offset=0");
    expect(out.match(/data-project="/g)?.length).toBe(2);
    expect(out).toContain(`href="/projects/${P1}"`);
    expect(out).toContain(`href="/projects/${P2}"`);
    expect(out).not.toContain("<img");
    expect(out).toContain("⟨U+202E RLO⟩");
    expect(out).toContain(`href="/comparisons/${C1}"`);
    expect(out).toContain(`href="/retest-reports/${R1}"`);
    expect(out).not.toContain(TOKEN);
  });

  it("uses the API's own open and active counts, never recomputed", async () => {
    replies["GET /posture"] = json(200, [summary()]);
    const out = await outcome(HomePage({ searchParams: Promise.resolve({}) }));
    expect(out).toMatch(/data-testid="overview-open">2</);
    expect(out).toContain("<strong>7</strong>");
    expect(out).toContain("FIXED 3");
    expect(out).toContain("REOPENED 2");
    expect(out).not.toContain("UNCHANGED 0");
  });

  it("filters nothing and adds nothing: an empty answer is an empty state", async () => {
    replies["GET /posture"] = json(200, []);
    const out = await outcome(HomePage({ searchParams: Promise.resolve({ project_id: P2 }) }));
    expect(out).toContain("You are not a member of any project yet.");
    expect(out).not.toContain(P2);
    expect(calls[0]!.query).not.toContain(P2); // no project id is ever sent
  });

  it("never links an unvalidated id", () => {
    const out = html(
      <PostureOverview
        projects={
          [
            summary({
              project_id: "../admin/users",
              latest_comparison: { ...comparison, comparison_id: "javascript:alert(1)" },
            }),
          ] as never
        }
      />,
    );
    expect(out).not.toContain("/projects/../");
    expect(out).not.toContain('href="/comparisons/javascript');
  });

  it("sends an ended session to sign in", async () => {
    replies["GET /posture"] = json(401, {
      detail: "Authentication required.",
      code: "unauthenticated",
    });
    expect(await outcome(HomePage({ searchParams: Promise.resolve({}) }))).toBe(
      `redirect ${SESSION_END_PATH}`,
    );
  });
});

describe("project dashboard", () => {
  function project() {
    replies[`GET /projects/${P1}`] = json(200, {
      id: P1,
      name: HOSTILE,
      description: null,
      created_at: NOW,
      updated_at: NOW,
    });
    replies[`GET /projects/${P1}/targets`] = json(200, []);
    replies[`GET /projects/${P1}/assessments`] = json(200, []);
  }

  it("renders the API's posture, safely, with the caller's role", async () => {
    project();
    replies[`GET /projects/${P1}/posture`] = json(200, posture());
    const out = await outcome(ProjectPage({ params: Promise.resolve({ projectId: P1 }) }));
    expect(out).toContain("Your role: Viewer");
    expect(out).not.toContain(`href="/projects/${P1}/members"`); // not an owner
    expect(out).toMatch(/data-testid="count-open">2</);
    expect(out).toMatch(/data-testid="count-active">7</);
    expect(out).toMatch(/data-testid="count-total">9</);
    // The target's latest scan is the API's choice (S1), not the newer S2.
    expect(out).toContain(`href="/findings?scan=${S1}"`);
    expect(out).not.toContain(`href="/findings?scan=${S2}"`);
    // Comparison states exactly as stored, in the table (not just the chart).
    const table = out.slice(out.indexOf('data-testid="state-counts"'));
    const stateTable = table.slice(0, table.indexOf("</table>"));
    for (const [state, n] of Object.entries(comparison.by_state)) {
      expect(stateTable).toContain(
        `<tr data-key="${state}" data-value="${n}"><th scope="row">${state.toUpperCase()}</th><td>${n}</td></tr>`,
      );
    }
    expect(out).toContain(`href="/comparisons/${C1}"`);
    expect(out).toContain(`href="/reports/${R1}"`);
    expect(out).not.toContain("<img");
    expect(out).toContain("⟨U+202E RLO⟩");
    // Accessible charts with text equivalents.
    for (const id of ["posture-severity", "posture-triage", "posture-states"]) {
      expect(out).toContain(`aria-labelledby="${id}-title ${id}-desc"`);
    }
    expect(out).toContain('data-testid="severity-counts"');
    expect(out).toContain('data-testid="state-counts"');
    expect(out).not.toContain(TOKEN);
  });

  it("offers owner tabs only when the API says owner; an unknown role is not an owner", async () => {
    project();
    replies[`GET /projects/${P1}/posture`] = json(200, posture({ role: "owner" }));
    expect(await outcome(ProjectPage({ params: Promise.resolve({ projectId: P1 }) }))).toContain(
      `href="/projects/${P1}/members"`,
    );
    for (const reply of [
      json(200, posture({ role: undefined })),
      json(200, posture({ role: "admin" })),
      json(500, {}),
    ]) {
      replies[`GET /projects/${P1}/posture`] = reply;
      const out = await outcome(ProjectPage({ params: Promise.resolve({ projectId: P1 }) }));
      expect(out).not.toContain(`href="/projects/${P1}/members"`);
      expect(out).not.toContain(`href="/projects/${P1}/settings"`);
    }
  });

  it("shows honest empty states", () => {
    const out = html(
      <ProjectPostureView
        posture={
          posture({
            findings: { ...counts, total: 0, active: 0, open: 0 },
            targets: [],
            latest_comparison: null,
            latest_report: null,
            recent_scans: [],
          }) as never
        }
      />,
    );
    expect(out).toContain("No completed comparison yet.");
    expect(out).toContain("No targets yet.");
    expect(out).toContain("No scans yet.");
    expect(out).toContain("none completed yet");
    expect(out).toContain("No findings:");
  });

  it("keeps the API's 404 for non-members", async () => {
    replies[`GET /projects/${P1}`] = json(404, { detail: "project not found", code: "not_found" });
    expect(await outcome(ProjectPage({ params: Promise.resolve({ projectId: P1 }) }))).toBe(
      "not found",
    );
    expect(calls.some((c) => c.path.endsWith("/posture"))).toBe(false);
  });
});

describe("findings overview", () => {
  it("uses the posture summary instead of walking every assessment", async () => {
    replies["GET /posture"] = json(200, [summary()]);
    const out = await streamed(await FindingsPage({ searchParams: Promise.resolve({}) }));
    expect(calls.map((c) => c.path)).toEqual(["/posture"]);
    expect(out).toContain('data-testid="findings-overview"');
    expect(out).toContain(`href="/projects/${P1}#posture"`);
    expect(out).not.toContain("<img");
  });
});

describe("source", () => {
  it("never computes posture semantics in the console", () => {
    for (const file of ["src/components/posture.tsx", "src/app/(console)/page.tsx"]) {
      const source = readFileSync(join(process.cwd(), file), "utf8");
      expect(source, file).not.toMatch(
        /false_positive|status\s*===|\.status\s*!==|finished_at\s*[<>]|Math\.max\(/,
      );
      expect(source, file).not.toMatch(/^["']use client["'];/m);
    }
  });
});
