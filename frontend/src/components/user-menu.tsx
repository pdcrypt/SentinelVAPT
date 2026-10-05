import Link from "next/link";

import { SafeText } from "@/components/safe-text";
import { logoutAction } from "@/lib/actions/auth";
import { PASSWORD_PATH } from "@/lib/auth/paths";
import type { SessionUser } from "@/lib/auth/user";

/** The signed-in user and the sign-out control. The role label is display
 *  only: a global administrator still sees only the projects they belong to. */
export function UserMenu({ user }: { user: SessionUser }) {
  return (
    <span className="user-menu" data-testid="current-user">
      <span>
        Signed in as{" "}
        <Link href="/account" data-testid="current-username">
          <SafeText value={user.username} />
        </Link>
        {user.global_role === "admin" && <span className="role-label">administrator</span>}
      </span>
      <Link href={PASSWORD_PATH} className="small">
        Change password
      </Link>
      <form action={logoutAction} className="inline-form">
        <button type="submit" className="btn btn-secondary btn-small" data-testid="sign-out">
          Sign out
        </button>
      </form>
    </span>
  );
}
