import type { Metadata } from "next";

import { ActionForm } from "@/components/action-form";
import { CheckboxField, TextArea, TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { ProjectNav } from "@/components/project-nav";
import { SafeText } from "@/components/safe-text";
import { Notice, PageHeader, Section } from "@/components/ui";
import { deleteProjectAction, updateProjectAction } from "@/lib/actions/admin";
import { getProject } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { myProjectRole } from "@/lib/project-role";

export const metadata: Metadata = { title: "Project settings" };

/** Renaming and deleting a project (`project.update`, `project.delete`:
 *  project owners). The forms are offered to owners only (from their role,
 *  M10); that is display, not permission: the API decides each change and its
 *  refusal is shown. A project with targets cannot be deleted. */
export default async function ProjectSettingsPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const role = await myProjectRole(project.data.id);
  const p = project.data;
  return (
    <>
      <PageHeader kicker="Project settings" title={<SafeText value={p.name} />} />
      <ProjectNav projectId={p.id} current="/settings" role={role} />
      {role !== "owner" ? (
        <Notice tone="info">Only project owners can change these settings.</Notice>
      ) : (
        <>
          <Section title="Name and description">
            <ActionForm
              action={updateProjectAction.bind(null, p.id)}
              submitLabel="Save"
              testId="update-project"
            >
              <TextField name="name" label="Name" required defaultValue={p.name} />
              <TextArea
                name="description"
                label="Description"
                maxLength={2000}
                defaultValue={p.description ?? ""}
              />
            </ActionForm>
          </Section>
          <Section title="Delete project">
            <p className="small">
              Deleting is refused while the project still has targets. Its audit history is kept.
            </p>
            <ActionForm
              action={deleteProjectAction.bind(null, p.id)}
              submitLabel="Delete project"
              variant="danger"
              testId="delete-project"
            >
              <CheckboxField name="confirm" required>
                I want to delete this project.
              </CheckboxField>
            </ActionForm>
          </Section>
        </>
      )}
    </>
  );
}
