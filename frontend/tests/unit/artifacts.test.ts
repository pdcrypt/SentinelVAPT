import { afterEach, describe, expect, it, vi } from "vitest";

import { downloadArtifact, previewArtifact } from "@/lib/artifacts";

// Requests act as a signed-in user (lib/auth/session.ts is covered by
// auth-flows.test.ts).
vi.mock("@/lib/auth/session", () => ({
  currentToken: async () => "test-session-token",
  forgetCurrentSession: async () => undefined,
}));

const REPORT = "22222222-2222-4222-8222-222222222222";
const SANDBOX_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; " +
  "form-action 'none'; frame-ancestors 'self'; sandbox";

function upstream(body: string, headers: Record<string, string>, status = 200): Response {
  return new Response(body, { status, headers });
}

afterEach(() => vi.unstubAllGlobals());

describe("preview route", () => {
  it("keeps the API's sandboxing CSP and allows same-origin framing only", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        upstream("<html>report</html>", {
          "content-type": "text/html",
          "content-security-policy": SANDBOX_CSP,
          etag: '"abc"',
          "set-cookie": "leak=1",
          server: "uvicorn",
        }),
      ),
    );
    const res = await previewArtifact("reports", REPORT);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toBe(SANDBOX_CSP);
    expect(res.headers.get("x-frame-options")).toBe("SAMEORIGIN");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-disposition")).toBe("inline");
    expect(res.headers.get("etag")).toBe('"abc"');
    // Only allowlisted upstream headers are forwarded.
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.headers.get("server")).toBeNull();
  });

  it("fails closed when the upstream CSP has no sandbox directive", async () => {
    for (const csp of ["default-src 'none'", "", "default-src 'none'; sandbox-ish"]) {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          upstream("<script>alert(1)</script>", {
            "content-type": "text/html",
            "content-security-policy": csp,
          }),
        ),
      );
      const res = await previewArtifact("retest-reports", REPORT);
      expect(res.status).toBe(502);
      expect(await res.text()).not.toContain("<script>");
    }
  });

  it("validates the report id before calling the API", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect((await previewArtifact("reports", "../../health")).status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("download route", () => {
  it("is always an attachment with a sandboxing CSP", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        upstream("<html></html>", {
          "content-type": "text/html; charset=utf-8",
          "content-disposition": "inline",
          etag: '"h"',
        }),
      ),
    );
    const res = await downloadArtifact("reports", REPORT, "html");
    expect(res.headers.get("content-disposition")).toBe('attachment; filename="report.html"');
    expect(res.headers.get("content-security-policy")).toContain("sandbox");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });

  it("keeps the API's attachment filename and ETag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        upstream("{}", {
          "content-type": "application/json",
          "content-disposition": 'attachment; filename="SV-RT-000001.json"',
          etag: '"deadbeef"',
        }),
      ),
    );
    const res = await downloadArtifact("retest-reports", REPORT, "json");
    expect(res.headers.get("content-disposition")).toBe('attachment; filename="SV-RT-000001.json"');
    expect(res.headers.get("etag")).toBe('"deadbeef"');
  });

  it("maps API failures to short plain-text responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        upstream(
          JSON.stringify({ detail: "x", code: "conflict" }),
          { "content-type": "application/json" },
          409,
        ),
      ),
    );
    expect((await downloadArtifact("reports", REPORT, "pdf")).status).toBe(409);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => upstream("Traceback secret", {}, 500)),
    );
    const res = await downloadArtifact("reports", REPORT, "pdf");
    expect(res.status).toBe(502);
    expect(await res.text()).not.toContain("Traceback");
    expect((await downloadArtifact("reports", REPORT, "docx")).status).toBe(404);
  });
});
