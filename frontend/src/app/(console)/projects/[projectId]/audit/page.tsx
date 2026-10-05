import type { Metadata } from "next";

import { AuditFiltersForm, AuditTable, Pager } from "@/components/admin";
import { PageError } from "@/components/page-error";
import { ProjectNav } from "@/components/project-nav";
import { SafeText } from "@/components/safe-text";
import { ErrorPanel, PageHeader, Section } from "@/components/ui";
import { auditFilters } from "@/lib/admin/filters";
import { getProject, listProjectAuditEvents } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Project audit log" };

/** One project's security history (M6 API, `audit.read_project`: project
 *  owners). Scoped by the path; other members get the API's refusal and
 *  non-members "Not found". Read-only. */
export default async function ProjectAuditPage({
  params,
  searchParams,
}: {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const p = project.data;
  const { filters, query, offset } = auditFilters(await searchParams, false);
  const events = await load(() => listProjectAuditEvents(p.id, query));
  const path = `/projects/${p.id}/audit`;
  return (
    <>
      <PageHeader kicker="Project audit log" title={<SafeText value={p.name} />} />
      <ProjectNav projectId={p.id} current="/audit" />
      {!events.ok ? (
        <ErrorPanel error={events.error} />
      ) : (
        <Section title="Events (newest first)">
          <AuditFiltersForm path={path} filters={filters} global={false} />
          <AuditTable events={events.data} global={false} />
          <Pager path={path} filters={filters} offset={offset} count={events.data.length} />
        </Section>
      )}
    </>
  );
}
