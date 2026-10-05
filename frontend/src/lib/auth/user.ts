import "server-only";

import { redirect } from "next/navigation";

import { getMe } from "@/lib/api/endpoints";
import type { CurrentUser } from "@/lib/api/types";
import { authRedirect, PASSWORD_PATH, SESSION_END_PATH } from "@/lib/auth/paths";
import { hasSession } from "@/lib/auth/session";

// The signed-in user, as the API reports it right now (ADR 0014, Phase 9 M8).
// Asked of the API on every server render of a protected layout, so a session
// that was revoked, expired or belongs to a disabled user is noticed at once.
// The frontend only learns *who* is signed in; what they may see or do is
// decided by the API on every request (project membership, roles).

export type SessionUser = Pick<
  CurrentUser,
  "username" | "display_name" | "global_role" | "must_change_password"
>;

/** The signed-in user, or a redirect: to sign in (via /session/end, which
 *  clears a stale cookie) without a live session, and to the password change
 *  while one is required (unless this page is that change). */
export async function requireUser(
  options: { allowPasswordChange?: boolean } = {},
): Promise<SessionUser> {
  if (!(await hasSession())) redirect(SESSION_END_PATH);
  let user: CurrentUser;
  try {
    user = (await getMe()).user;
  } catch (error) {
    const to = authRedirect(error);
    if (to !== null) redirect(to);
    throw error;
  }
  if (user.must_change_password && !options.allowPasswordChange) redirect(PASSWORD_PATH);
  // Only what the console displays: never ids, tokens or session details.
  return {
    username: user.username,
    display_name: user.display_name,
    global_role: user.global_role,
    must_change_password: user.must_change_password,
  };
}
