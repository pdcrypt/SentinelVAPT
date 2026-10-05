import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { PasswordField, TextField } from "@/components/fields";
import { Notice } from "@/components/ui";
import { loginAction } from "@/lib/actions/auth";
import { hasSession } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Sign in" };

/** Public. Credentials are posted to this server only (a Server Action); it
 *  asks the API to sign in and keeps the session token to itself. */
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  if (await hasSession()) redirect("/");
  const expired = (await searchParams).session === "expired";
  return (
    <>
      <h1>Sign in</h1>
      {expired && <Notice tone="info">Your session has ended. Sign in again to continue.</Notice>}
      <ActionForm
        action={loginAction}
        submitLabel="Sign in"
        pendingLabel="Signing in…"
        testId="login-form"
      >
        <TextField
          name="username"
          label="Username"
          required
          maxLength={256}
          autoComplete="username"
        />
        <PasswordField name="password" label="Password" autoComplete="current-password" />
      </ActionForm>
      <p className="muted small">
        Accounts are created by an administrator. There is no self-registration.
      </p>
    </>
  );
}
