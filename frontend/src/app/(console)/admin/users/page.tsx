import type { Metadata } from "next";

import { ActionForm } from "@/components/action-form";
import { Pager, UserFiltersForm, UsersTable } from "@/components/admin";
import { PasswordField, SelectField, TextField } from "@/components/fields";
import { ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { createUserAction } from "@/lib/actions/admin";
import { userFilters } from "@/lib/admin/filters";
import { listUsers } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Accounts" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

/** Account administration (M7 API, `user.admin`). The page asks the API for
 *  the list first: for anyone who is not a global administrator the API
 *  refuses (403) and the page shows that refusal and no forms. */
export default async function UsersPage({ searchParams }: { searchParams: SearchParams }) {
  const { filters, query, offset } = userFilters(await searchParams);
  const users = await load(() => listUsers(query));
  return (
    <>
      <PageHeader kicker="Administration" title="Accounts" />
      {!users.ok ? (
        <ErrorPanel error={users.error} />
      ) : (
        <>
          <Section title="Accounts">
            <UserFiltersForm filters={filters} />
            <UsersTable users={users.data} />
            <Pager
              path="/admin/users"
              filters={filters}
              offset={offset}
              count={users.data.length}
            />
          </Section>
          <Section title="Create an account">
            <Notice tone="info">
              There is no self-registration. Choose a temporary password and give it to the user
              yourself: they must replace it at their first sign-in. It is not shown again.
            </Notice>
            <ActionForm
              action={createUserAction}
              submitLabel="Create account"
              pendingLabel="Creating…"
              testId="create-user"
            >
              <TextField
                name="username"
                label="Username"
                required
                maxLength={64}
                hint="3–64 characters: letters, digits, '.', '_' or '-'. Unique, ignoring case."
              />
              <TextField name="display_name" label="Display name" required />
              <SelectField
                name="global_role"
                label="Global role"
                options={[
                  ["user", "User (project access through membership only)"],
                  ["admin", "Administrator (accounts and platform audit log; no project access)"],
                ]}
                defaultValue="user"
              />
              <PasswordField
                name="password"
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
        </>
      )}
    </>
  );
}
