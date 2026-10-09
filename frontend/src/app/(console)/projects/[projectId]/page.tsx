import type { Metadata } from "next";
import Link from "next/link";

import { SafeText } from "@/components/safe-text";
import { AssessmentsTable, TargetsTable } from "@/components/tables";
import { ErrorPanel, KeyValues, Mono, PageHeader, Section } from "@/components/ui";
import {
  getProject,
  getProjectPosture,
  listProjectAssessments,
  listTargets,
} from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { PageError } from "@/components/page-error";
import { ProjectPostureView } from "@/components/posture";
import { ProjectNav } from "@/components/project-nav";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Project" };

export default async function ProjectPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const [posture, targets, assessments] = await Promise.all([
    load(() => getProjectPosture(project.data.id)),
    load(() => listTargets(projectId)),
    load(() => listProjectAssessments(projectId)),
  ]);
  // The caller's own role, as the API reports it with the posture (display
  // only; an unknown role is treated as the least privileged).
  const role = posture.ok ? posture.data.role : null;
  const p = project.data;
  return (
    <>
      <PageHeader kicker="Project" title={<SafeText value={p.name} />} />
      <ProjectNav projectId={p.id} current="" role={role} />
      <Section title="Details">
        <KeyValues
          rows={[
            ["Project ID", <Mono key="id">{p.id}</Mono>],
            ["Description", <SafeText key="d" value={p.description} />],
            ["Created (UTC)", formatTime(p.created_at)],
          ]}
        />
      </Section>
      {posture.ok ? (
        <ProjectPostureView posture={posture.data} />
      ) : (
        <Section title="Current posture">
          <ErrorPanel error={posture.error} />
        </Section>
      )}
      <Section
        title="Targets"
        id="targets"
        actions={
          <Link className="btn btn-secondary" href={`/projects/${p.id}/targets`}>
            Add target
          </Link>
        }
      >
        {targets.ok ? (
          <TargetsTable targets={targets.data} />
        ) : (
          <ErrorPanel error={targets.error} />
        )}
      </Section>
      <Section
        title="Assessments"
        id="assessments"
        actions={
          <Link className="btn btn-secondary" href={`/projects/${p.id}/assessments`}>
            All assessments
          </Link>
        }
      >
        {assessments.ok ? (
          <AssessmentsTable assessments={assessments.data} />
        ) : (
          <ErrorPanel error={assessments.error} />
        )}
      </Section>
    </>
  );
}
