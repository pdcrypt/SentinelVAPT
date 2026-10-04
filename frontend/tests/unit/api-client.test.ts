import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiGet, apiWrite, buildPath, toApiError } from "@/lib/api/client";
import { id } from "@/lib/api/endpoints";
import { mapApiError, toUiError } from "@/lib/api/errors";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("paths and identifiers", () => {
  it("builds /api/v1 paths with encoded query values", () => {
    expect(buildPath("/projects", { limit: 100, offset: 0, empty: "", none: undefined })).toBe(
      "/api/v1/projects?limit=100&offset=0",
    );
    expect(buildPath("/scans/x/findings", { rule_id: "SV-HDR-001&x=1" })).toBe(
      "/api/v1/scans/x/findings?rule_id=SV-HDR-001%26x%3D1",
    );
  });

  it("refuses path traversal", () => {
    expect(() => buildPath("/projects/../admin")).toThrow();
    expect(() => buildPath("//evil.example/x")).toThrow();
    expect(() => buildPath("projects")).toThrow();
  });

  it("only accepts UUIDs as path identifiers", () => {
    expect(id("0D3E5C8A-1111-4222-8333-444455556666")).toBe("0d3e5c8a-1111-4222-8333-444455556666");
    for (const bad of ["../health", "1 OR 1=1", "", "x/y", "0d3e5c8a-1111-4222-8333-44445555666"]) {
      expect(() => id(bad)).toThrow("invalid identifier");
    }
  });
});

describe("toApiError", () => {
  it("keeps only the documented error fields", async () => {
    const error = await toApiError(
      json(409, {
        detail: "the comparison has not completed",
        code: "retest_report_not_allowed",
        field: null,
        reason: "comparison_not_completed",
        trace: "Traceback (most recent call last) ...",
      }),
    );
    expect(error).toMatchObject({
      status: 409,
      code: "retest_report_not_allowed",
      detail: "the comparison has not completed",
      reason: "comparison_not_completed",
    });
    expect(JSON.stringify(error)).not.toContain("Traceback");
  });

  it("turns FastAPI validation errors into field errors", async () => {
    const error = await toApiError(
      json(422, {
        detail: [{ loc: ["body", "authorization", "acknowledge"], msg: "Field required" }],
      }),
    );
    expect(error.code).toBe("validation_error");
    expect(error.fieldErrors).toEqual([
      { field: "authorization.acknowledge", message: "Field required" },
    ]);
  });

  it("drops non-JSON and unexpected bodies entirely", async () => {
    const html = new Response("<html>Internal Server Error: password=hunter2</html>", {
      status: 500,
      headers: { "content-type": "text/html" },
    });
    const error = await toApiError(html);
    expect(error).toMatchObject({ status: 500, code: "unexpected_response", detail: null });
    const weird = await toApiError(json(500, { detail: "psycopg.errors.DataError: secret" }));
    expect(weird.code).toBe("unexpected_response");
    expect(weird.detail).toBeNull();
  });
});

describe("requests", () => {
  it("calls the internal API address server-side and parses JSON", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://backend:8000");
    const fetchMock = vi.fn(async () => json(200, [{ id: "p" }]));
    vi.stubGlobal("fetch", fetchMock);
    await expect(apiGet("/projects", { limit: 100 })).resolves.toEqual([{ id: "p" }]);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://backend:8000/api/v1/projects?limit=100");
    expect(init).toMatchObject({ method: "GET", cache: "no-store", redirect: "error" });
  });

  it("returns the status so 202 (new) and 200 (existing) can be told apart", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(200, { id: "existing" })),
    );
    await expect(apiWrite("POST", "/assessments/x/comparisons", { scan_id: "s" })).resolves.toEqual(
      {
        status: 200,
        data: { id: "existing" },
      },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(202, { id: "new" })),
    );
    await expect(apiWrite("POST", "/assessments/x/comparisons", {})).resolves.toMatchObject({
      status: 202,
    });
  });

  it("reports an unreachable API without leaking the address", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://backend:8000");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed: connect ECONNREFUSED backend:8000");
      }),
    );
    const error = await apiGet("/projects").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 503, code: "api_unreachable" });
    const ui = toUiError(error);
    expect(ui.title).toBe("API unavailable");
    expect(JSON.stringify(ui)).not.toContain("backend:8000");
  });
});

describe("mapApiError", () => {
  it("shows documented messages and explains 409 reason codes", () => {
    const ui = mapApiError({
      status: 409,
      code: "scan_not_allowed",
      detail: "the authorization has expired",
      reason: "authorization_expired",
    });
    expect(ui).toMatchObject({ title: "Not allowed right now", reason: "authorization_expired" });
    expect(ui.message).toBe("The target's recorded authorization has expired.");
    const plain = mapApiError({ status: 404, code: "not_found", detail: "project not found" });
    expect(plain.message).toBe("project not found");
  });

  it("never passes raw server errors to the user", () => {
    for (const error of [
      { status: 500, code: "unexpected_response", detail: "Traceback: KeyError secret" },
      { status: 500, code: "not_found", detail: "Traceback: KeyError secret" }, // 5xx is never trusted
      { status: 418, code: "made_up", detail: "<script>x</script>" },
      { status: 502, code: "bad_gateway", detail: "nginx upstream 10.0.0.5" },
    ]) {
      const ui = mapApiError(error);
      expect(ui.code).toBe("unexpected_error");
      expect(ui.message).not.toContain(error.detail);
      expect(JSON.stringify(ui)).not.toMatch(/Traceback|script|10\.0\.0\.5/);
    }
  });

  it("maps anything that is not an API error to a generic error", () => {
    const ui = toUiError(new Error("ECONNRESET at db.internal:5432 password=x"));
    expect(ui.code).toBe("unexpected_error");
    expect(JSON.stringify(ui)).not.toContain("db.internal");
  });
});
