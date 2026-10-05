"use server";

import { redirect } from "next/navigation";

import { ApiError } from "@/lib/api/client";
import { changePassword, login, logout } from "@/lib/api/endpoints";
import { mapApiError, toUiError } from "@/lib/api/errors";
import { failed, invalid, text, type ActionState } from "@/lib/actions/state";
import { LOGIN_PATH, PASSWORD_PATH } from "@/lib/auth/paths";
import { endSession, startSession } from "@/lib/auth/session";
import { assertWriteAllowed } from "@/lib/security/action-guard";

// Sign-in, sign-out and password change (ADR 0014, Phase 9 M8). The API is
// the authority for all three: passwords are checked, hashed and judged
// against the password policy only there. These actions pass the form on,
// keep the session token they receive on this server (lib/auth/session.ts)
// and give the browser nothing but an opaque cookie and a redirect.
// Passwords are never trimmed, logged, echoed or put in a URL.

/** The API's request bounds (schemas/auth.py): a size limit, not a policy. */
const MAX_USERNAME = 256;
const MAX_PASSWORD = 1024;

/** A password field exactly as typed (never trimmed). */
function secret(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

/** One answer for every failed sign-in, whatever the reason (unknown user,
 *  wrong password, disabled account, throttling), as the API gives. */
const SIGN_IN_FAILED: ActionState = {
  status: "error",
  error: mapApiError({
    status: 401,
    code: "invalid_credentials",
    detail: "Invalid username or password.",
  }),
};

/** Revokes an API session this server no longer holds. Best effort: if it
 *  has already ended, there is nothing left to revoke. */
async function revoke(token: string): Promise<void> {
  try {
    await logout(token);
  } catch {
    // Already revoked or expired (401), or the API is unreachable: the token
    // has been dropped from the store either way, so nothing can use it.
  }
}

export async function loginAction(_: ActionState, form: FormData): Promise<ActionState> {
  await assertWriteAllowed();
  const username = text(form, "username");
  const password = secret(form, "password");
  if (!username || !password || username.length > MAX_USERNAME || password.length > MAX_PASSWORD) {
    return SIGN_IN_FAILED;
  }
  let mustChangePassword: boolean;
  try {
    const { data } = await login({ username, password });
    if (data === null) throw new ApiError(502, "unexpected_response", null);
    // A fresh session id, whatever cookie the browser sent (no fixation).
    const replaced = await startSession(data.token, data.session.expires_at);
    if (replaced !== null) await revoke(replaced);
    mustChangePassword = data.user.must_change_password;
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 422)) {
      return SIGN_IN_FAILED;
    }
    return { status: "error", error: toUiError(error) };
  }
  redirect(mustChangePassword ? PASSWORD_PATH : "/");
}

export async function logoutAction(): Promise<void> {
  await assertWriteAllowed();
  // Removed here first, so the browser is signed out even if the API cannot
  // be reached; then the API session itself is revoked.
  const token = await endSession();
  if (token !== null) await revoke(token);
  redirect(LOGIN_PATH);
}

export async function changePasswordAction(_: ActionState, form: FormData): Promise<ActionState> {
  await assertWriteAllowed();
  const current = secret(form, "current_password");
  const next = secret(form, "new_password");
  if (!current) return invalid("current_password", "Enter your current password.");
  if (!next) return invalid("new_password", "Enter a new password.");
  if (current.length > MAX_PASSWORD || next.length > MAX_PASSWORD) {
    return invalid("new_password", "The password is too long.");
  }
  // A typing check only; the password policy is the API's.
  if (next !== secret(form, "confirm_password")) {
    return invalid("confirm_password", "The new passwords do not match.");
  }
  try {
    const { data } = await changePassword({ current_password: current, new_password: next });
    if (data === null) throw new ApiError(502, "unexpected_response", null);
    // The API ended every session of the user, this one included, and
    // issued a new one: it replaces this browser session under a new id.
    await startSession(data.token, data.session.expires_at);
  } catch (error) {
    return failed(error);
  }
  redirect("/");
}
