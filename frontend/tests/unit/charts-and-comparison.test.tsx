import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

import { LineageChart, SeverityChart, StateChart } from "@/components/charts";
import { RecordsTable, ScopeDifferences } from "@/components/comparison";
import { COMPARISON_STATES, type ComparisonRecord, type LineageEntry } from "@/lib/api/types";

const html = (node: ReactElement) => renderToStaticMarkup(node);

function bars(svg: string): Record<string, string> {
  return Object.fromEntries(
    [...svg.matchAll(/data-key="([^"]+)" data-value="(\d+)"/g)].map((m) => [m[1], m[2]]),
  );
}

describe("SVG charts", () => {
  it("renders severity counts exactly as given, with accessible text and no script", () => {
    const svg = html(<SeverityChart counts={{ low: 3, informational: 2, high: 0 }} />);
    expect(svg).toMatch(/^<svg[^>]*role="img"/);
    expect(svg).toContain("<title");
    expect(svg).toContain("Findings by severity (total 5)");
    expect(svg).toContain("Low: 3; Informational: 2");
    expect(bars(svg)).toEqual({
      critical: "0",
      high: "0",
      medium: "0",
      low: "3",
      informational: "2",
    });
    expect(svg).not.toMatch(/<script|on[a-z]+=|style=/i);
  });

  it("shows every stored comparison state under its stored name", () => {
    const counts = { fixed: 3, unchanged: 3, reopened: 2, not_retested: 1 };
    const svg = html(<StateChart counts={counts} />);
    const shown = bars(svg);
    expect(Object.keys(shown)).toEqual([...COMPARISON_STATES]);
    expect(shown).toMatchObject({
      fixed: "3",
      unchanged: "3",
      reopened: "2",
      not_retested: "1",
      new: "0",
    });
    for (const state of COMPARISON_STATES) expect(svg).toContain(`>${state.toUpperCase()}<`);
    expect(svg).not.toMatch(/<script|on[a-z]+=|style=/i);
  });

  it("draws the lineage with hostile names as inert, marked text", () => {
    const entries: LineageEntry[] = [
      {
        position: 0,
        assessment_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        name: "<script>alert(1)</script>",
        status: "completed",
        authorization_id: "x",
        retest_of_assessment_id: null,
        baseline_scan_id: null,
        comparisons: [],
      },
      {
        position: 1,
        assessment_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        name: "Retest‮ B",
        status: "completed",
        authorization_id: "x",
        retest_of_assessment_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        baseline_scan_id: "s",
        comparisons: [
          { id: "c", current_scan_id: "s2", status: "completed", policy_version: "cmp-1" },
        ],
      },
    ];
    const svg = html(<LineageChart entries={entries} currentId={entries[1]!.assessment_id} />);
    expect(svg).not.toMatch(/<script/);
    expect(svg).toContain("&lt;script&gt;");
    expect(svg).toContain("⟨U+202E RLO⟩");
    expect(svg).not.toContain("‮");
    expect(svg).toContain('href="/assessments/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"');
    expect(svg).toContain('href="/retests/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"');
    expect(svg).toContain("node node-current");
    expect(svg).toContain("Original");
  });
});

describe("comparison records", () => {
  const record = (over: Partial<ComparisonRecord>): ComparisonRecord => ({
    fingerprint: "f".repeat(64),
    rule_id: "SV-COR-001",
    state: "dismissed",
    reasons: ["baseline_false_positive", "subject_not_observed"],
    baseline_finding_id: "11111111-1111-4111-8111-111111111111",
    baseline_triage: "false_positive",
    baseline_evidence_ids: [],
    current_finding_id: null,
    current_triage: null,
    current_evidence_ids: [],
    coverage_evidence_ids: [],
    ...over,
  });

  it("shows the stored state as the comparison state and triage only as triage", () => {
    const out = html(<RecordsTable comparisonId="c" records={[record({})]} />);
    const stateCells = [...out.matchAll(/data-kind="comparison-state"[^>]*>([^<]*)</g)].map(
      (m) => m[1],
    );
    expect(stateCells).toEqual(["DISMISSED"]);
    const triageCells = [...out.matchAll(/data-kind="triage"[^>]*>([^<]*)</g)].map((m) => m[1]);
    expect(triageCells).toEqual(["Triage: False positive"]);
    expect(out).toContain("Triage status (when compared)");
    expect(out).toContain("baseline_false_positive");
    expect(out).toContain("not in retest");
  });

  it("never shows a triage value in a comparison-state cell", () => {
    for (const triage of ["open", "confirmed", "false_positive", "accepted_risk"]) {
      const out = html(
        <RecordsTable
          comparisonId="c"
          records={[
            record({ state: "fixed", baseline_triage: triage, coverage_evidence_ids: ["e"] }),
          ]}
        />,
      );
      const stateCells = [...out.matchAll(/data-kind="comparison-state"[^>]*>([^<]*)</g)].map(
        (m) => m[1],
      );
      expect(stateCells).toEqual(["FIXED"]);
    }
  });

  it("says None for an empty state", () => {
    expect(html(<RecordsTable comparisonId="c" records={[]} />)).toContain("None.");
  });

  it("lists scope values present on only one side", () => {
    const base = {
      in_scope_hosts: ["lab"],
      allowed_ports: [80],
      in_scope_path_prefixes: [],
      excluded_paths: ["/admin"],
    };
    const same = html(<ScopeDifferences baseline={base} retest={base} />);
    expect(same).toContain("same scope");
    const narrowed = html(
      <ScopeDifferences
        baseline={base}
        retest={{ ...base, excluded_paths: ["/admin", "/error"] }}
      />,
    );
    expect(narrowed).toContain("/error");
    expect(narrowed).toContain("NOT_RETESTED");
  });
});
