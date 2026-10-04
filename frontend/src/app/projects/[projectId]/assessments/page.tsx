import type { Metadata } from "next";
import Link from "next/link";

import { SafeText } from "@/components/safe-text";
import { AssessmentsTable } from "@/components/tables";
import { ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { getProject, listProjectAssessments } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { PageError } from "@/components/page-error";

export const metadata: Metadata = { title: "Assessments" };

export default async function ProjectAssessmentsPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const project = await load(() => getProject(projectId));
  if (!project.ok) return <PageError error={project.error} />;
  const assessments = await load(() => listProjectAssessments(projectId));
  return (
    <>
      <PageHeader
        kicker="Assessments"
        title={
          <>
            Assessments of <SafeText value={project.data.name} />
          </>
        }
      >
        <Link href={`/projects/${project.data.id}`}>Back to project</Link>
      </PageHeader>
      <Notice>
        Assessments are created from a target, under that target&apos;s current authorization.
      </Notice>
      <Section title="All assessments">
        {assessments.ok ? (
          <AssessmentsTable assessments={assessments.data} />
        ) : (
          <ErrorPanel error={assessments.error} />
        )}
      </Section>
    </>
  );
}
