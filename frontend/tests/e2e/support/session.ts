// Browser sign-in helpers for the end-to-end tests (Phase 9 M8).

import { join } from "node:path";

import { expect, type BrowserContext, type Page } from "@playwright/test";

import { STATE_DIR, type Credentials } from "./accounts";

/** The signed-in operator's browser state (opaque cookie only), written by
 *  auth.setup.ts and used by the workflow. */
export const OPERATOR_STATE = join(STATE_DIR, "operator.json");
export const COOKIE = "__Host-sv_session";
export const LIVE = !!process.env.E2E_BASE_URL;
export const LIVE_ONLY = "needs the running compose stack (set E2E_BASE_URL)";

/** Signs in through the login form, as a person would. */
export async function signIn(page: Page, account: Credentials): Promise<void> {
  await page.goto("/login");
  const form = page.getByTestId("login-form");
  await form.getByLabel("Username").fill(account.username);
  await form.locator('[name="password"]').fill(account.password);
  await form.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => url.pathname !== "/login");
}

/** Completes the password change a new account must make. */
export async function changePassword(page: Page, current: string, next: string): Promise<void> {
  await expect(page).toHaveURL(/\/account\/password$/);
  const form = page.getByTestId("password-form");
  await form.locator('[name="current_password"]').fill(current);
  await form.locator('[name="new_password"]').fill(next);
  await form.locator('[name="confirm_password"]').fill(next);
  await form.getByRole("button", { name: "Change password" }).click();
  await page.waitForURL((url) => url.pathname === "/");
}

export async function sessionCookie(context: BrowserContext) {
  return (await context.cookies()).find((cookie) => cookie.name === COOKIE);
}
