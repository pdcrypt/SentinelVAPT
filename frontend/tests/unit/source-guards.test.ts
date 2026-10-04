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
