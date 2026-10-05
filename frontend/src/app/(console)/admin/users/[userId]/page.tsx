import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AccountStatus } from "@/components/admin";
import { CheckboxField, PasswordField, SelectField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { KeyValues, Mono, Notice, PageHeader, Section } from "@/components/ui";
import {
  changeGlobalRoleAction,
  disableUserAction,
  enableUserAction,
  resetPasswordAction,
} from "@/lib/actions/admin";
import { getMe, getUser } from "@/lib/api/endpoints";
import type { UserRead } from "@/lib/api/types";
import { load, param } from "@/lib/load";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Account" };

const ROLE_LABEL = {
  admin: "Administrator: manages accounts, reads the platform audit log; no project access",
  user: "User: project access through membership only",
} as const;

function GlobalRoleSection({ u }: { u: UserRead }) {
  const promotable = u.is_active || u.global_role === "admin";
  return (
    <Section title="Global role">
      <p className="small">
        Currently <strong>{u.global_role}</strong>. Changing it ends all of the account&apos;s
        sessions. It never adds or removes project memberships: an administrator still sees only the
        projects they are a member of. The platform always keeps an active administrator.
      </p>
      {promotable ? (
        <ActionForm
          action={changeGlobalRoleAction.bind(null, u.id)}
          submitLabel="Change global role"
          pendingLabel="Changing…"
          variant="danger"
          testId="change-global-role"
        >
          <SelectField
            name="global_role"
            label="New global role"
            options={[
              ["user", ROLE_LABEL.user],
              ["admin", ROLE_LABEL.admin],
            ]}
            defaultValue={u.global_role === "admin" ? "user" : "admin"}
          />
          <CheckboxField name="confirm" required>
            I want to change the global role of <SafeText value={u.username} />.
          </CheckboxField>
        </ActionForm>
      ) : (
        <p className="small muted">A disabled account cannot become an administrator.</p>
      )}
    </Section>
  );
}

/** One account (M7/M10 API, `user.admin`). The API refuses, and the page shows
 *  as given: disabling, resetting or changing the role of your own account,
 *  removing the last active administrator, promoting a disabled account. */
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
  // Display only: the API refuses self-administration whatever this says.
  const me = await load(() => getMe());
  const self = me.ok && me.data.user.id === u.id;
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
            [
              "Global role",
              <span key="r" data-testid="global-role">
                {u.global_role}
              </span>,
            ],
            ["Status", <AccountStatus key="s" user={u} />],
            ["Disabled at (UTC)", formatTime(u.disabled_at)],
            ["Password change due", u.must_change_password ? "Yes" : "No"],
            ["Last sign-in (UTC)", formatTime(u.last_login_at)],
            ["Created (UTC)", formatTime(u.created_at)],
            ["User ID", <Mono key="id">{u.id}</Mono>],
          ]}
        />
      </Section>
      {self ? (
        <Notice tone="info">
          This is your own account. Change your password from{" "}
          <Link href="/account">your account page</Link>; another administrator changes your role or
          disables it.
        </Notice>
      ) : u.is_active ? (
        <>
          <Section title="Reset password">
            <p className="small">
              Sets a temporary password, ends all of the user&apos;s sessions and requires a new
              password at their next sign-in.
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
          <GlobalRoleSection u={u} />
          <Section title="Disable account">
            <p className="small">
              A disabled account cannot sign in and all of its sessions end at once. Accounts are
              never deleted, and their history is kept. A disabled account can be enabled again.
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
        <>
          <Notice tone="warn">This account is disabled. It cannot sign in.</Notice>
          <Section title="Enable account">
            <p className="small">
              The account signs in again with its existing password (and must still change it if a
              change was due). Sessions that ended when it was disabled stay ended.
            </p>
            <ActionForm
              action={enableUserAction.bind(null, u.id)}
              submitLabel="Enable account"
              pendingLabel="Enabling…"
              testId="enable-user"
            >
              <CheckboxField name="confirm" required>
                I want to enable <SafeText value={u.username} /> again.
              </CheckboxField>
            </ActionForm>
          </Section>
          <GlobalRoleSection u={u} />
        </>
      )}
    </>
  );
}
