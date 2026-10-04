// A temporary local lab target for the end-to-end tests: nginx on the compose
// network (reachable by the worker as http://sv-e2e-lab/, never published to
// the host), whose response headers are swapped between scans so a retest
// has something to compare. Requires Docker and the running compose stack.

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const LAB_HOST = "sv-e2e-lab";
export const LAB_URL = `http://${LAB_HOST}/`;
const NETWORK = process.env.E2E_COMPOSE_NETWORK ?? "sentinel-vapt_default";
const HERE = join(process.cwd(), "tests", "e2e", "lab");

/** Baseline A: version disclosure plus a hostile header value. */
export const HEADERS_A =
  'add_header X-Powered-By "PHP/8.1.0" always;\n' +
  'add_header X-Lab-Note "<script>window.__xss=1</script>" always;\n';
/** Retest B: remediated (CSP with frame-ancestors, no version header). */
export const HEADERS_B =
  "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'\" always;\n" +
  'add_header X-Lab-Note "<script>window.__xss=1</script>" always;\n';
/** Retest C: regression (no security headers at all). */
export const HEADERS_C = "";

let confDir: string | null = null;

function docker(...args: string[]): string {
  return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

export function startLab(): void {
  stopLab();
  confDir = mkdtempSync(join(tmpdir(), "sv-e2e-lab-"));
  copyFileSync(join(HERE, "default.conf"), join(confDir, "default.conf"));
  writeFileSync(join(confDir, "headers.inc"), HEADERS_A);
  docker(
    "run", "-d", "--rm", "--name", LAB_HOST, "--network", NETWORK, "--network-alias", LAB_HOST,
    "-v", `${join(HERE, "site")}:/usr/share/nginx/html:ro`,
    "-v", `${confDir}:/etc/nginx/conf.d:ro`,
    "nginx:1.27-alpine",
  ); // prettier-ignore
}

export function setLabHeaders(content: string): void {
  if (confDir === null) throw new Error("lab not started");
  writeFileSync(join(confDir, "headers.inc"), content);
  docker("exec", LAB_HOST, "nginx", "-s", "reload");
}

export function stopLab(): void {
  try {
    docker("rm", "-f", LAB_HOST);
  } catch {
    // not running
  }
}
