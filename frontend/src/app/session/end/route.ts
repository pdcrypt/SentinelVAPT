import { cookies } from "next/headers";

import { cookieName, cookieSecure, expiredCookieHeader } from "@/lib/auth/cookie";
import { LOGIN_PATH } from "@/lib/auth/paths";
import { sessionStore } from "@/lib/auth/store";

// Where the browser is sent when its API session has ended (expired,
// revoked, signed out elsewhere, user disabled, password reset): server
// renders cannot set cookies, so this route clears the stale cookie and
// continues to the sign-in page. It never ends a live session: a cookie that
// still has one is left alone, so a cross-site link to this URL can at most
// tidy up a cookie that no longer works. Signing out is a POST (logoutAction).

const HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export async function GET(): Promise<Response> {
  const secure = cookieSecure();
  const id = (await cookies()).get(cookieName(secure))?.value;
  if (id !== undefined && sessionStore().get(id) !== null) {
    return new Response(null, { status: 303, headers: { ...HEADERS, Location: "/" } });
  }
  return new Response(null, {
    status: 303,
    headers: {
      ...HEADERS,
      Location: `${LOGIN_PATH}?session=expired`,
      ...(id !== undefined ? { "Set-Cookie": expiredCookieHeader(secure) } : {}),
    },
  });
}
