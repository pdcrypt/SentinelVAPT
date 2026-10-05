import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

// Static guarantees about the source tree (ADR 0013).

const SRC = join(process.cwd(), "src");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

const SOURCES = files(SRC).filter((f) => /\.(ts|tsx)$/.test(f) && !f.endsWith("schema.d.ts"));
const read = (f: string) => readFileSync(f, "utf8");
const rel = (f: string) => relative(SRC, f).replace(/\\/g, "/");

describe("source tree", () => {
  it("never renders raw HTML", () => {
    for (const file of SOURCES) {
      expect(read(file), rel(file)).not.toMatch(
        /dangerouslySetInnerHTML|srcDoc|insertAdjacentHTML/,
      );
    }
  });

  it("never exposes configuration to the browser bundle", () => {
    for (const file of SOURCES) {
      expect(read(file), rel(file)).not.toMatch(/NEXT_PUBLIC_/);
    }
  });

  it("keeps the API client and every module using it server-only", () => {
    for (const name of [
      "lib/api/client.ts",
      "lib/api/endpoints.ts",
      "lib/artifacts.ts",
      "lib/load.ts",
    ]) {
      expect(read(join(SRC, name))).toMatch(/^import "server-only";/m);
    }
    for (const file of SOURCES) {
      if (!/^["']use client["'];/m.test(read(file))) continue;
      expect(read(file), rel(file)).not.toMatch(
        /from "@\/lib\/(api\/(client|endpoints)|artifacts|load)"/,
      );
      expect(read(file), rel(file)).not.toMatch(/API_INTERNAL_URL/);
    }
  });

  it("keeps the browser session and the API token server-only (Phase 9 M8)", () => {
    for (const name of ["lib/auth/session.ts", "lib/auth/store.ts", "lib/auth/user.ts"]) {
      expect(read(join(SRC, name)), name).toMatch(/^import "server-only";/m);
    }
    expect(read(join(SRC, "lib/actions/auth.ts"))).toMatch(/^"use server";/);
    const clientFiles = SOURCES.filter((f) => /^["']use client["'];/m.test(read(f)));
    expect(clientFiles.length).toBeGreaterThan(0);
    for (const file of clientFiles) {
      expect(read(file), rel(file)).not.toMatch(/from "@\/lib\/auth\/(session|store|user)"/);
      expect(read(file), rel(file)).not.toMatch(/\btoken\b|SessionResponse|Authorization/);
    }
    // The token is read in exactly one place and sent from exactly one place.
    const tokenReaders = SOURCES.filter((f) => /\bcurrentToken\(|\.token\b/.test(read(f)));
    for (const file of tokenReaders) {
      const source = read(file);
      expect(
        /^import "server-only";/m.test(source) || /^"use server";/.test(source),
        rel(file),
      ).toBe(true);
    }
    const bearer = SOURCES.filter((f) => /Bearer /.test(read(f))).map(rel);
    expect(bearer).toEqual(["lib/api/client.ts"]);
  });

  it("never keeps anything in browser storage or script-readable cookies", () => {
    for (const file of SOURCES) {
      expect(read(file), rel(file)).not.toMatch(
        /localStorage|sessionStorage|indexedDB|document\.cookie/,
      );
    }
  });

  it("only the server talks to the API, and never with identity headers", () => {
    for (const file of SOURCES) {
      const source = read(file);
      expect(source, rel(file)).not.toMatch(/["'`]X-(User|User-Id|Actor|Username)["'`]/i);
      if (/\bfetch\(/.test(source)) {
        expect(["lib/api/client.ts", "lib/api/health.ts"], rel(file)).toContain(rel(file));
        expect(source, rel(file)).toMatch(/^import "server-only";/m);
      }
    }
  });

  it("starts every Server Action with the Host/Origin guard", () => {
    const actionFiles = SOURCES.filter((f) => /^["']use server["'];/m.test(read(f)));
    expect(actionFiles.length).toBeGreaterThan(0);
    for (const file of actionFiles) {
      const source = read(file);
      const actions = [
        ...source.matchAll(/export async function (\w+)\([^)]*\)[^{]*\{\s*([^\n]*)/g),
      ];
      expect(actions.length, rel(file)).toBeGreaterThan(0);
      for (const [, name, firstLine] of actions) {
        expect(firstLine, `${rel(file)}: ${name}`).toContain("await assertWriteAllowed()");
      }
    }
  });
});

describe("ESLint security rules", () => {
  const eslint = new ESLint({ cwd: process.cwd() });

  async function messages(code: string): Promise<string[]> {
    const [result] = await eslint.lintText(code, { filePath: "src/components/probe.tsx" });
    return (result?.messages ?? []).map((m) => `${m.ruleId}: ${m.message}`);
  }

  it.each([
    [
      "dangerouslySetInnerHTML",
      "export const X = () => <div dangerouslySetInnerHTML={{ __html: 'x' }} />;\n",
    ],
    ["srcDoc", 'export const X = () => <iframe sandbox="" srcDoc="<p>x</p>" />;\n'],
    ["innerHTML", "export function x(el: HTMLElement) {\n  el.innerHTML = 'x';\n}\n"],
    [
      "insertAdjacentHTML",
      "export function x(el: HTMLElement) {\n  el.insertAdjacentHTML('beforeend', 'x');\n}\n",
    ],
    ["document.write", "export function x() {\n  document.write('x');\n}\n"],
    ["NEXT_PUBLIC_", "export const u = process.env.NEXT_PUBLIC_API_INTERNAL_URL;\n"],
    ["unsandboxed iframe", 'export const X = () => <iframe src="/x" title="x" />;\n'],
  ])("rejects %s", async (_name, code) => {
    const found = await messages(code);
    expect(found.some((m) => /no-restricted-syntax|react\/no-danger/.test(m))).toBe(true);
  });

  it("accepts the safe equivalents", async () => {
    const found = await messages(
      'export const X = ({ v }: { v: string }) => (\n  <>\n    <bdi>{v}</bdi>\n    <iframe sandbox="" src="/artifacts/reports/x/preview" title="p" />\n  </>\n);\n',
    );
    expect(found.filter((m) => /no-restricted-syntax|no-danger/.test(m))).toEqual([]);
  });
});
