import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AuthorizationFields } from "@/components/authorization";
import { TextField } from "@/components/fields";
import { SafeText } from "@/components/safe-text";
import { TargetsTable } from "@/components/tables";
import { ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { createTargetAction } from "@/lib/actions/projects";
import { getProject, listTargets } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { PageError } from "@/components/page-error";
import { ProjectNav } from "@/components/project-nav";

export const metadata: Metadata = { title: "Targets" };

export default async function TargetsPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const targets = await load(() => listTargets(projectId));
  return (
    <>
      <PageHeader
        kicker="Targets"
        title={
          <>
            Targets of <SafeText value={project.data.name} />
          </>
        }
      >
        <Link href={`/projects/${project.data.id}`}>Back to project</Link>
      </PageHeader>
      <ProjectNav projectId={project.data.id} current="/targets" />
      <Section title="Targets">
        {targets.ok ? (
          <TargetsTable targets={targets.data} />
        ) : (
          <ErrorPanel error={targets.error} />
        )}
      </Section>
      <Section title="New local lab target" id="new-target">
        <Notice>
          Only <code>local_lab</code> targets can be created here and scanned: loopback or private
          addresses and lab hostnames on the compose network (for example <code>lab-target</code>).
          Public or external systems are not supported.
        </Notice>
        <ActionForm
          action={createTargetAction.bind(null, project.data.id)}
          submitLabel="Create target and record authorization"
          testId="create-target"
        >
          <fieldset>
            <legend>Target and scope</legend>
            <TextField name="name" label="Name" required />
            <TextField
              name="base_url"
              label="Base URL"
              required
              placeholder="http://lab-target/"
              maxLength={2048}
            />
            <TextField
              name="in_scope_hosts"
              label="In-scope hosts"
              required
              hint="Comma-separated; must include the base URL's host."
              maxLength={2000}
            />
            <TextField
              name="allowed_ports"
              label="Allowed ports"
              hint="Optional; defaults to the base URL's port."
            />
            <TextField
              name="in_scope_path_prefixes"
              label="In-scope path prefixes"
              hint="Optional, comma-separated (e.g. /app/)."
              maxLength={2000}
            />
            <TextField
              name="excluded_paths"
              label="Excluded paths"
              hint="Optional, comma-separated; never requested."
              maxLength={2000}
            />
          </fieldset>
          <AuthorizationFields />
        </ActionForm>
      </Section>
    </>
  );
}
