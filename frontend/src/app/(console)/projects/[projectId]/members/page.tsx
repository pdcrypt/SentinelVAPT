import type { Metadata } from "next";

import { ActionForm } from "@/components/action-form";
import { TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { ProjectNav } from "@/components/project-nav";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { addMemberAction, changeMemberRoleAction, removeMemberAction } from "@/lib/actions/admin";
import { getProject, isUuid, listMembers } from "@/lib/api/endpoints";
import { PROJECT_ROLES, type Member, type ProjectRole } from "@/lib/api/types";
import { load } from "@/lib/load";
import { myProjectRole } from "@/lib/project-role";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Members" };

const ROLE_HELP: Record<ProjectRole, string> = {
  owner: "everything, including members, settings and the audit log",
  operator: "targets' assessments, scans, triage, reports and retests",
  viewer: "read only",
};

function RoleSelect({ id, value }: { id: string; value?: ProjectRole }) {
  return (
    <select id={id} name="role" defaultValue={value ?? "viewer"} aria-label="Role">
      {PROJECT_ROLES.map((role) => (
        <option key={role} value={role}>
          {role}
        </option>
      ))}
    </select>
  );
}

function MemberRow({ projectId, member }: { projectId: string; member: Member }) {
  const key = member.user_id;
  return (
    <tr data-username={member.username} data-role={member.role}>
      <td>
        <SafeText value={member.username} />
        {!member.is_active && <span className="muted small"> (disabled)</span>}
      </td>
      <td>
        <SafeText value={member.display_name} />
      </td>
      <td>
        <span className="mono">{member.role}</span>
      </td>
      <td className="mono small">{formatTime(member.created_at)}</td>
      <td>
        <ActionForm
          action={changeMemberRoleAction.bind(null, projectId, key)}
          submitLabel="Change role"
          variant="secondary"
          className="inline-form"
          testId={`role-${member.username}`}
        >
          <RoleSelect id={`role-${key}`} value={member.role} />
        </ActionForm>
      </td>
      <td>
        <ActionForm
          action={removeMemberAction.bind(null, projectId, key)}
          submitLabel="Remove"
          variant="danger"
          className="inline-form"
          testId={`remove-${member.username}`}
        >
          <label className="checkbox small">
            <input type="checkbox" name="confirm" value="true" required /> confirm
          </label>
        </ActionForm>
      </td>
    </tr>
  );
}

/** Project members (M7 API, `membership.manage`: project owners). The API
 *  is asked for the members list; owners get it and the controls, other
 *  members get its refusal (403) and no controls, non-members "Not found".
 *  Every change is made and checked by the API (a project always keeps an
 *  owner), and the list is then reloaded from it. */
export default async function MembersPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const role = await myProjectRole(project.data.id);
  const p = project.data;
  const members = await load(() => listMembers(p.id));
  return (
    <>
      <PageHeader kicker="Project members" title={<SafeText value={p.name} />} />
      <ProjectNav projectId={p.id} current="/members" role={role} />
      {!members.ok ? (
        <ErrorPanel error={members.error} />
      ) : (
        <>
          <Section title="Members">
            {members.data.length === 0 ? (
              <EmptyState>No members.</EmptyState>
            ) : (
              <div className="table-wrap">
                <table className="table" data-testid="members-table">
                  <thead>
                    <tr>
                      <th>Username</th>
                      <th>Display name</th>
                      <th>Role</th>
                      <th>Member since (UTC)</th>
                      <th>Change role</th>
                      <th>Remove</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.data
                      .filter((m) => isUuid(m.user_id))
                      .map((m) => (
                        <MemberRow key={m.user_id} projectId={p.id} member={m} />
                      ))}
                  </tbody>
                </table>
              </div>
            )}
            <Notice tone="info">
              A project always keeps at least one owner: the last owner cannot be removed or given
              another role. A global administrator is not a member unless added here.
            </Notice>
          </Section>
          <Section title="Add a member">
            <ActionForm
              action={addMemberAction.bind(null, p.id)}
              submitLabel="Add member"
              pendingLabel="Adding…"
              testId="add-member"
            >
              <TextField name="username" label="Username" required maxLength={64} />
              <div className="field">
                <label htmlFor="add-role">Role</label>
                <RoleSelect id="add-role" />
                <span className="hint">
                  {PROJECT_ROLES.map((role) => `${role}: ${ROLE_HELP[role]}`).join(" · ")}
                </span>
              </div>
            </ActionForm>
          </Section>
        </>
      )}
    </>
  );
}
