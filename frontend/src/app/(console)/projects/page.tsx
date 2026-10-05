import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { TextArea, TextField } from "@/components/fields";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, PageHeader, Section } from "@/components/ui";
import { createProjectAction } from "@/lib/actions/projects";
import { allPages, listProjects } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Projects" };

export default async function ProjectsPage() {
  const projects = await load(() => allPages((offset) => listProjects(offset)));
  return (
    <>
      <PageHeader kicker="Engagements" title="Projects" />
      <Section title="All projects" id="projects">
        {!projects.ok ? (
          <ErrorPanel error={projects.error} />
        ) : projects.data.length === 0 ? (
          <EmptyState>No projects yet. Create one below.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table" data-testid="projects-table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Description</th>
                  <th scope="col">Created (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {projects.data.map((project) => (
                  <tr key={project.id}>
                    <td>
                      <Link href={`/projects/${project.id}`}>
                        <SafeText value={project.name} />
                      </Link>
                    </td>
                    <td className="wrap">
                      <SafeText value={project.description} />
                    </td>
                    <td className="mono">{formatTime(project.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      <Section title="New project" id="new-project">
        <ActionForm
          action={createProjectAction}
          submitLabel="Create project"
          testId="create-project"
        >
          <TextField name="name" label="Name" required />
          <TextArea name="description" label="Description" />
        </ActionForm>
      </Section>
    </>
  );
}
