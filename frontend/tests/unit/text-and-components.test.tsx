import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

import { ComparisonStateBadge, SeverityBadge, StatusBadge, TriageBadge } from "@/components/badges";
import { EvidenceView } from "@/components/evidence";
import { ReportPreview } from "@/components/report-preview";
import { SafeBlock, SafeText, SafeUrl } from "@/components/safe-text";
import { Actor, ErrorPanel } from "@/components/ui";
import { mapApiError } from "@/lib/api/errors";
import { COMPARISON_STATES, type Evidence } from "@/lib/api/types";
import { hasHiddenCharacters, segmentText } from "@/lib/text";

const html = (node: ReactElement) => renderToStaticMarkup(node);

const XSS = [
  "<script>alert(1)</script>",
  '"><img src=x onerror=alert(1)>',
  "<svg onload=alert(1)>",
  "javascript:alert(1)",
  "</bdi><iframe src=//evil.example>",
];

describe("visible control characters", () => {
  it("marks U+202E and NUL instead of hiding or dropping them", () => {
    expect(segmentText("invoice‮txt.exe")).toEqual([
      { kind: "text", value: "invoice" },
      { kind: "control", code: "U+202E RLO" },
      { kind: "text", value: "txt.exe" },
    ]);
    expect(segmentText("a\u0000b")).toEqual([
      { kind: "text", value: "a" },
      { kind: "control", code: "U+0000 NUL" },
      { kind: "text", value: "b" },
    ]);
    expect(hasHiddenCharacters("plain text")).toBe(false);
    expect(hasHiddenCharacters("zero​width")).toBe(true);
  });

  it("keeps line breaks only in multi-line text", () => {
    expect(segmentText("a\nb", true)).toEqual([{ kind: "text", value: "a\nb" }]);
    expect(segmentText("a\nb")[1]).toEqual({ kind: "control", code: "U+000A" });
  });

  it("renders markers inside an isolating <bdi>", () => {
    const out = html(<SafeText value={"evil‮\u0000name"} />);
    expect(out).toContain("<bdi>");
    expect(out).toContain("⟨U+202E RLO⟩");
    expect(out).toContain("⟨U+0000 NUL⟩");
    expect(out).not.toContain("‮");
    expect(out).not.toContain("\u0000");
  });
});

describe("untrusted values render as inert text", () => {
  it.each(XSS)("escapes %s", (payload) => {
    for (const out of [
      html(<SafeText value={payload} />),
      html(<SafeUrl value={payload} />),
      html(<SafeBlock value={payload} label="x" />),
      html(<Actor name={payload} />),
    ]) {
      expect(out).not.toMatch(/<(script|img|svg|iframe)\b/i);
      expect(out).not.toMatch(/<a\b/);
    }
  });

  it("never turns a URL into a link", () => {
    const out = html(<SafeUrl value="http://lab-target/admin?x=1" />);
    expect(out).not.toContain("<a");
    expect(out).not.toContain("href");
    expect(out).toContain("http://lab-target/admin?x=1");
  });

  it("labels actors recorded from a session apart from self-asserted names", () => {
    expect(html(<Actor name="Alice" />)).toContain("self-asserted");
    expect(html(<Actor name="Alice" userId={null} />)).toContain("self-asserted");
    const signedIn = html(<Actor name="Alice" userId="6f1c0e3a-1111-4222-8333-444455556666" />);
    expect(signedIn).toContain("signed-in user");
    expect(signedIn).not.toContain("self-asserted");
    // The label is display only: the id itself is never rendered.
    expect(signedIn).not.toContain("6f1c0e3a");
  });
});

describe("comparison state and triage are distinct", () => {
  it.each(COMPARISON_STATES)("shows the stored state %s verbatim in upper case", (state) => {
    const out = html(<ComparisonStateBadge state={state} />);
    expect(out).toContain(`>${state.toUpperCase()}<`);
    expect(out).toContain('data-kind="comparison-state"');
    expect(out).toContain(`state-${state}`);
    expect(out).not.toContain("Triage");
  });

  it("always labels triage as triage, never as a comparison state", () => {
    const out = html(<TriageBadge status="false_positive" />);
    expect(out).toContain('data-kind="triage"');
    expect(out).toContain("Triage: False positive");
    expect(out).not.toContain("comparison-state");
    expect(out).not.toMatch(/class="state/);
  });

  it("does not build classes from unknown values", () => {
    const out = html(<ComparisonStateBadge state={'x" onmouseover="alert(1)'} />);
    expect(out).toContain('class="state"');
    expect(out).not.toContain('onmouseover="');
    expect(html(<SeverityBadge severity="<b>" />)).toContain('class="sev"');
    expect(html(<StatusBadge status="completed" />)).toContain("Completed");
  });
});

describe("report preview", () => {
  it("is an iframe with an empty sandbox attribute pointing at the artifact route", () => {
    const out = html(<ReportPreview kind="reports" reportId="r1" title="Preview" />);
    expect(out).toMatch(/<iframe[^>]* sandbox=""/);
    expect(out).toContain('src="/artifacts/reports/r1/preview"');
    expect(out).not.toMatch(/allow-(scripts|same-origin)/);
    expect(out).not.toContain("srcdoc");
  });
});

describe("evidence view", () => {
  const evidence: Evidence = {
    id: "11111111-1111-4111-8111-111111111111",
    scan_id: "s",
    endpoint_id: null,
    method: "GET",
    url: "http://lab-target/<script>alert(1)</script>",
    request_headers: [["User-Agent", "SentinelVAPT"]],
    status_code: 200,
    response_headers: [
      ["X-Lab", '<img src=x onerror="alert(1)">'],
      ["X-Bidi", "abc‮def"],
    ],
    body_excerpt: "<html><script>alert(document.cookie)</script>\u0000</html>",
    body_sha256: "a".repeat(64),
    body_bytes_captured: 10,
    truncated: false,
    peer: "127.0.0.1:80",
    redactions: [],
    created_at: "2026-10-04T00:00:00Z",
  };

  it("shows headers, URL and body as inert text with visible control characters", () => {
    const out = html(<EvidenceView evidence={evidence} />);
    expect(out).not.toMatch(/<(script|img)\b/i);
    expect(out).toContain("&lt;script&gt;alert(document.cookie)&lt;/script&gt;");
    expect(out).toContain("⟨U+202E RLO⟩");
    expect(out).toContain("⟨U+0000 NUL⟩");
    expect(out).not.toContain('href="http://lab-target');
  });
});

describe("error panel", () => {
  it("shows the mapped message and reason code as text", () => {
    const out = html(
      <ErrorPanel
        error={mapApiError({
          status: 409,
          code: "comparison_not_allowed",
          detail: "x",
          reason: "previous_comparison_missing",
        })}
      />,
    );
    expect(out).toContain('role="alert"');
    expect(out).toContain("previous_comparison_missing");
    expect(out).toContain("has not been compared yet");
  });
});
