// Test accounts for the live-stack end-to-end tests (Phase 9 M8).
//
// Uses only the platform's supported mechanisms, from the test harness (never
// from the browser under test):
//   - the first administrator comes from the documented bootstrap command
//     (`python -m app.cli create-admin`) run in the backend container, or from
//     E2E_ADMIN_USERNAME / E2E_ADMIN_PASSWORD for a stack that already has one;
//   - every other account is created by that administrator through the M7
//     account API, with a temporary password the user must change.
// Passwords are random per run. The generated administrator's credentials are
// kept in frontend/.e2e/ (git- and docker-ignored) so later runs can sign in;
// nothing is hard-coded or committed. The harness calls the API on its
// published loopback port; the browser never does.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const API_URL = process.env.E2E_API_URL ?? "http://127.0.0.1:8000";
export const STATE_DIR = join(process.cwd(), ".e2e");
const ADMIN_FILE = join(STATE_DIR, "admin.json");

export type Credentials = { username: string; password: string };
export type Account = Credentials & { id: string };

export const RUN = Date.now().toString(36);

/** A random password that satisfies the API's policy (12+ characters). */
export function newPassword(): string {
  return `e2e-${randomBytes(18).toString("base64url")}`;
}

export async function api<T = unknown>(
  method: string,
  path: string,
  options: { token?: string; body?: unknown } = {},
): Promise<{ status: number; body: T }> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${API_URL}/api/v1${path}`, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
}

function adminCredentials(): Credentials {
  const { E2E_ADMIN_USERNAME: username, E2E_ADMIN_PASSWORD: password } = process.env;
  if (username && password) return { username, password };
  if (existsSync(ADMIN_FILE)) return JSON.parse(readFileSync(ADMIN_FILE, "utf8")) as Credentials;
  const created = { username: "e2e-admin", password: newPassword() };
  try {
    execFileSync(
      "docker",
      [
        "compose", "exec", "-T", "backend", "python", "-m", "app.cli", "create-admin",
        "--username", created.username, "--display-name", "E2E administrator", "--password-stdin",
      ],
      { cwd: join(process.cwd(), ".."), input: `${created.password}\n`, stdio: ["pipe", "pipe", "pipe"] },
    ); // prettier-ignore
  } catch {
    throw new Error(
      "Could not bootstrap an e2e administrator (the stack already has one?). " +
        "Set E2E_ADMIN_USERNAME and E2E_ADMIN_PASSWORD.",
    );
  }
  mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(ADMIN_FILE, JSON.stringify(created), { mode: 0o600 });
  return created;
}

/** The administrator's credentials (to sign in through the UI). */
export function adminAccount(): Credentials {
  return adminCredentials();
}

let adminTokenCache: string | null = null;

/** An administrator API session for the harness. */
export async function adminToken(): Promise<string> {
  if (adminTokenCache) return adminTokenCache;
  const { status, body } = await api<{ token: string }>("POST", "/auth/login", {
    body: adminCredentials(),
  });
  if (status !== 200) throw new Error(`e2e administrator sign-in failed (${status})`);
  adminTokenCache = body.token;
  return body.token;
}

/** A new account with a temporary password (must be changed at sign-in). */
export async function createAccount(prefix: string): Promise<Account> {
  const username = `e2e-${prefix}-${RUN}-${randomBytes(3).toString("hex")}`;
  const password = newPassword();
  const { status, body } = await api<{ id: string }>("POST", "/users", {
    token: await adminToken(),
    body: { username, display_name: `E2E ${prefix}`, password },
  });
  if (status !== 201) throw new Error(`could not create ${username} (${status})`);
  return { id: body.id, username, password };
}

/** Signs in through the API and changes the temporary password, so the
 *  account can be used directly. Returns its API token. */
export async function activate(account: Account): Promise<string> {
  const login = await api<{ token: string }>("POST", "/auth/login", {
    body: { username: account.username, password: account.password },
  });
  if (login.status !== 200) throw new Error(`could not sign in ${account.username}`);
  const next = newPassword();
  const changed = await api<{ token: string }>("POST", "/auth/password", {
    token: login.body.token,
    body: { current_password: account.password, new_password: next },
  });
  if (changed.status !== 200) throw new Error(`could not activate ${account.username}`);
  account.password = next;
  return changed.body.token;
}

export async function disable(account: Account): Promise<void> {
  const { status } = await api("POST", `/users/${account.id}/disable`, {
    token: await adminToken(),
  });
  if (status !== 200) throw new Error(`could not disable ${account.username} (${status})`);
}

export async function resetPassword(account: Account): Promise<void> {
  account.password = newPassword();
  const { status } = await api("POST", `/users/${account.id}/password-reset`, {
    token: await adminToken(),
    body: { new_password: account.password },
  });
  if (status !== 200) throw new Error(`could not reset ${account.username} (${status})`);
}

export async function auditActions(account: Account): Promise<string[]> {
  const { body } = await api<{ action: string }[]>(
    "GET",
    `/audit-events?actor_user_id=${account.id}&limit=100`,
    { token: await adminToken() },
  );
  return body.map((event) => event.action);
}
