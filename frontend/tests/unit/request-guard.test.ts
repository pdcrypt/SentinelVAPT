import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { proxy } from "@/proxy";
import { buildCsp } from "@/lib/security/csp";
import {
  allowedHosts,
  checkRequest,
  isAllowedHost,
  isAllowedOrigin,
  isWriteMethod,
} from "@/lib/security/request-guard";

const ALLOWED = allowedHosts(undefined);

function req(method: string, url: string, headers: Record<string, string>): NextRequest {
  return new NextRequest(url, { method, headers });
}

describe("Host allowlist", () => {
  it("defaults to localhost on port 3000", () => {
    expect(ALLOWED).toEqual(["localhost:3000", "127.0.0.1:3000"]);
  });

  it("accepts only exact allowlisted hosts", () => {
    expect(isAllowedHost("localhost:3000", ALLOWED)).toBe(true);
    expect(isAllowedHost("LOCALHOST:3000", ALLOWED)).toBe(true);
    expect(isAllowedHost("127.0.0.1:3000", ALLOWED)).toBe(true);
    expect(isAllowedHost("evil.example:3000", ALLOWED)).toBe(false); // DNS rebinding
    expect(isAllowedHost("localhost:3000.evil.example", ALLOWED)).toBe(false);
    expect(isAllowedHost("localhost", ALLOWED)).toBe(false);
    expect(isAllowedHost("", ALLOWED)).toBe(false);
    expect(isAllowedHost(null, ALLOWED)).toBe(false);
  });

  it("ignores configuration values that are not plain host:port", () => {
    expect(allowedHosts("*, http://x.example, ,localhost:3001")).toEqual(["localhost:3001"]);
    expect(allowedHosts("*")).toEqual(["localhost:3000", "127.0.0.1:3000"]);
  });
});

describe("Origin check for writes", () => {
  it("treats every method except GET, HEAD and OPTIONS as a write", () => {
    for (const m of ["POST", "PUT", "PATCH", "DELETE", "post"]) expect(isWriteMethod(m)).toBe(true);
    for (const m of ["GET", "HEAD", "OPTIONS"]) expect(isWriteMethod(m)).toBe(false);
  });

  it("requires Origin to equal this server's own origin", () => {
    expect(isAllowedOrigin("http://localhost:3000", "localhost:3000", ALLOWED)).toBe(true);
    expect(isAllowedOrigin("http://127.0.0.1:3000", "localhost:3000", ALLOWED)).toBe(false);
    expect(isAllowedOrigin("https://localhost:3000", "localhost:3000", ALLOWED)).toBe(false);
    expect(isAllowedOrigin("http://evil.example", "localhost:3000", ALLOWED)).toBe(false);
    expect(isAllowedOrigin("null", "localhost:3000", ALLOWED)).toBe(false);
    expect(isAllowedOrigin(null, "localhost:3000", ALLOWED)).toBe(false);
  });
});

describe("request decisions", () => {
  const headers = (h: Record<string, string>) => new Headers(h);

  it("allows same-origin reads and writes", () => {
    expect(checkRequest("GET", headers({ host: "localhost:3000" }), ALLOWED)).toEqual({ ok: true });
    expect(
      checkRequest(
        "POST",
        headers({
          host: "localhost:3000",
          origin: "http://localhost:3000",
          "sec-fetch-site": "same-origin",
        }),
        ALLOWED,
      ),
    ).toEqual({ ok: true });
  });

  it("refuses forged or missing Host headers with 421", () => {
    const forged: Record<string, string>[] = [
      {},
      { host: "evil.example" },
      { host: "attacker.test:3000" },
    ];
    for (const h of forged) {
      expect(checkRequest("GET", headers(h), ALLOWED)).toMatchObject({ ok: false, status: 421 });
    }
    expect(
      checkRequest(
        "GET",
        headers({ host: "localhost:3000", "x-forwarded-host": "evil.example" }),
        ALLOWED,
      ),
    ).toMatchObject({ ok: false, status: 421 });
  });

  it("refuses cross-site writes with 403", () => {
    const cases: Record<string, string>[] = [
      { host: "localhost:3000" }, // no Origin
      { host: "localhost:3000", origin: "http://evil.example" },
      { host: "localhost:3000", origin: "null" },
      { host: "localhost:3000", origin: "http://localhost:3000", "sec-fetch-site": "cross-site" },
      { host: "localhost:3000", origin: "http://localhost:3000", "sec-fetch-site": "same-site" },
    ];
    for (const h of cases) {
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        expect(checkRequest(method, headers(h), ALLOWED)).toMatchObject({
          ok: false,
          status: 403,
          reason: "cross_origin_write",
        });
      }
    }
  });
});

describe("proxy", () => {
  it("rejects a forged Host before rendering anything", () => {
    const res = proxy(
      req("GET", "http://localhost:3000/projects", { host: "rebind.example:3000" }),
    );
    expect(res.status).toBe(421);
    expect(res.headers.get("content-security-policy")).toBeNull();
  });

  it("rejects a cross-site POST", () => {
    const res = proxy(
      req("POST", "http://localhost:3000/projects", {
        host: "localhost:3000",
        origin: "http://evil.example",
      }),
    );
    expect(res.status).toBe(403);
  });

  it("sets a fresh nonce CSP on application pages", () => {
    // A signed-in page load (the session cookie) and the public sign-in page.
    const signedIn = { host: "localhost:3000", cookie: "__Host-sv_session=x" };
    const a = proxy(req("GET", "http://localhost:3000/projects", signedIn));
    const b = proxy(req("GET", "http://localhost:3000/login", { host: "localhost:3000" }));
    const cspA = a.headers.get("content-security-policy") ?? "";
    const cspB = b.headers.get("content-security-policy") ?? "";
    const nonceA = /'nonce-([^']+)'/.exec(cspA)?.[1];
    const nonceB = /'nonce-([^']+)'/.exec(cspB)?.[1];
    expect(nonceA).toBeTruthy();
    expect(nonceA).not.toEqual(nonceB);
    const scriptSrc = cspA.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
    expect(scriptSrc).toContain(`'nonce-${nonceA}'`);
    expect(scriptSrc).toContain("'strict-dynamic'");
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(cspA).toContain("frame-ancestors 'none'");
    expect(cspA).toContain("object-src 'none'");
    // Browser code may only fetch from this origin, never the API (Phase 9 M8)
    // and forms may only post here.
    expect(cspA.split("; ")).toContain("connect-src 'self'");
    expect(cspA.split("; ")).toContain("form-action 'self'");
    expect(a.headers.get("x-frame-options")).toBe("DENY");
    // The nonce is passed to the renderer through the request headers.
    expect(a.headers.get("x-middleware-request-x-nonce")).toBe(nonceA);
  });

  it("leaves report artifacts to their own sandboxing headers", () => {
    const res = proxy(
      req("GET", "http://localhost:3000/artifacts/reports/x/preview", {
        host: "localhost:3000",
        cookie: "__Host-sv_session=x",
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toBeNull();
  });
});

describe("CSP builder", () => {
  it("never allows inline scripts and only allows eval in development", () => {
    for (const dev of [false, true]) {
      const csp = buildCsp("abc", dev);
      expect(csp).not.toContain("unsafe-inline");
      expect(csp.includes("unsafe-eval")).toBe(dev);
      expect(csp).toContain("script-src 'self' 'nonce-abc' 'strict-dynamic'");
    }
  });
});
