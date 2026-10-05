import type { Metadata } from "next";
import Link from "next/link";

import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { KeyValues, Notice, PageHeader, Section } from "@/components/ui";
import { getMe } from "@/lib/api/endpoints";
import { PASSWORD_PATH } from "@/lib/auth/paths";
import { load } from "@/lib/load";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Account" };

/** The signed-in account, as the API reports it (GET /auth/me). Shows who you
 *  are and when this session ends; never ids, tokens or credential data. */
export default async function AccountPage() {
  const me = await load(() => getMe());
  if (!me.ok) return <PageError error={me.error} />;
  const { user, session } = me.data;
  return (
    <>
      <PageHeader kicker="Account" title={<SafeText value={user.display_name} />} />
      <Section title="Your account">
        <KeyValues
          rows={[
            ["Username", <SafeText key="u" value={user.username} />],
            ["Display name", <SafeText key="d" value={user.display_name} />],
            ["Status", "Active"],
            [
              "Global role",
              user.global_role === "admin"
                ? "Administrator (manages accounts and reads the platform audit log)"
                : "User",
            ],
            ["Password change due", user.must_change_password ? "Yes" : "No"],
          ]}
        />
        <Notice tone="info">
          Project access comes from project membership only: an administrator is not a member of
          every project. Your role in each project is shown to project owners on its Members page.
        </Notice>
      </Section>
      <Section title="This session">
        <KeyValues
          rows={[
            ["Signed in (UTC)", formatTime(session.created_at)],
            ["Ends if idle until (UTC)", formatTime(session.idle_expires_at)],
            ["Ends at the latest (UTC)", formatTime(session.expires_at)],
          ]}
        />
      </Section>
      <Section title="Password">
        <p>Changing your password ends every session of your account, including other browsers.</p>
        <p>
          <Link className="btn btn-secondary" href={PASSWORD_PATH}>
            Change password
          </Link>
        </p>
      </Section>
    </>
  );
}
