import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { PasswordField } from "@/components/fields";
import { Notice } from "@/components/ui";
import { changePasswordAction, logoutAction } from "@/lib/actions/auth";
import { requireUser } from "@/lib/auth/user";

export const metadata: Metadata = { title: "Change password" };

/** The only page a user who must change their password can reach (the API
 *  refuses everything else with password_change_required until they do).
 *  The password policy is the API's; its message is shown as given. */
export default async function ChangePasswordPage() {
  const user = await requireUser({ allowPasswordChange: true });
  return (
    <>
      <h1>Change password</h1>
      {user.must_change_password ? (
        <Notice tone="warn">
          Your password was set by an administrator. Choose a new one to continue.
        </Notice>
      ) : (
        <p>
          <Link href="/">Back to the console</Link>
        </p>
      )}
      <ActionForm
        action={changePasswordAction}
        submitLabel="Change password"
        pendingLabel="Changing…"
        testId="password-form"
      >
        <PasswordField
          name="current_password"
          label="Current password"
          autoComplete="current-password"
        />
        <PasswordField name="new_password" label="New password" autoComplete="new-password" />
        <PasswordField
          name="confirm_password"
          label="Confirm new password"
          autoComplete="new-password"
        />
      </ActionForm>
      <p className="muted small">
        Changing your password signs out every other session of your account.
      </p>
      <form action={logoutAction} className="inline-form">
        <button type="submit" className="btn btn-secondary" data-testid="sign-out">
          Sign out
        </button>
      </form>
    </>
  );
}
