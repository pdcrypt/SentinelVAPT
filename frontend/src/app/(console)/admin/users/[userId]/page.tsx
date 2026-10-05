import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AccountStatus } from "@/components/admin";
import { CheckboxField, PasswordField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { KeyValues, Mono, Notice, PageHeader, Section } from "@/components/ui";
import { disableUserAction, resetPasswordAction } from "@/lib/actions/admin";
import { getUser } from "@/lib/api/endpoints";
import { load, param } from "@/lib/load";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Account" };

/** One account (M7 API, `user.admin`). Disabling and password resets are
 *  refused by the API for your own account and, for disabling, for the last
 *  active administrator; those refusals are shown as given. */
export default async function UserPage({
  params,
  searchParams,
}: {
  params: Promise<{ userId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { userId } = await params;
  const created = param((await searchParams).created) === "1";
  const user = await load(() => getUser(userId));
  if (!user.ok) return <PageError error={user.error} />;
  const u = user.data;
  return (
    <>
      <PageHeader kicker="Account" title={<SafeText value={u.username} />}>
        <Link href="/admin/users">All accounts</Link>
      </PageHeader>
      {created && (
        <Notice tone="info">
          Account created. Give the user their temporary password yourself; they must replace it at
          their first sign-in.
        </Notice>
      )}
      <Section title="Details">
        <KeyValues
          rows={[
            ["Username", <SafeText key="u" value={u.username} />],
            ["Display name", <SafeText key="d" value={u.display_name} />],
            ["Global role", u.global_role],
            ["Status", <AccountStatus key="s" user={u} />],
            ["Disabled at (UTC)", formatTime(u.disabled_at)],
            ["Password change due", u.must_change_password ? "Yes" : "No"],
            ["Last sign-in (UTC)", formatTime(u.last_login_at)],
            ["Created (UTC)", formatTime(u.created_at)],
            ["User ID", <Mono key="id">{u.id}</Mono>],
          ]}
        />
      </Section>
      {u.is_active ? (
        <>
          <Section title="Reset password">
            <p className="small">
              Sets a temporary password, ends all of the user&apos;s sessions and requires a new
              password at their next sign-in. Your own password is changed from your account page.
            </p>
            <ActionForm
              action={resetPasswordAction.bind(null, u.id)}
              submitLabel="Reset password"
              pendingLabel="Resetting…"
              testId="reset-password"
            >
              <PasswordField
                name="new_password"
                label="Temporary password"
                autoComplete="new-password"
              />
              <PasswordField
                name="confirm_password"
                label="Confirm temporary password"
                autoComplete="new-password"
              />
            </ActionForm>
          </Section>
          <Section title="Disable account">
            <p className="small">
              A disabled account cannot sign in and all of its sessions end at once. Accounts are
              never deleted, and their history is kept.
            </p>
            <ActionForm
              action={disableUserAction.bind(null, u.id)}
              submitLabel="Disable account"
              pendingLabel="Disabling…"
              variant="danger"
              testId="disable-user"
            >
              <CheckboxField name="confirm" required>
                I want to disable <SafeText value={u.username} />.
              </CheckboxField>
            </ActionForm>
          </Section>
        </>
      ) : (
        <Notice tone="warn">
          This account is disabled. It cannot sign in, and the platform offers no way to enable it
          again.
        </Notice>
      )}
    </>
  );
}
