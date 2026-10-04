import "server-only";

import { allPages, listProjectAssessments, listProjects } from "@/lib/api/endpoints";
import type { Assessment, Project } from "@/lib/api/types";

// The API has no global lists of reports, retests or retest reports: they
// belong to assessments. Index pages walk projects → assessments (bounded by
// the API's page size) instead of inventing backend endpoints.

export type AssessmentWithProject = Assessment & { project: Project };

export async function allAssessments(): Promise<AssessmentWithProject[]> {
  const projects = await allPages((offset) => listProjects(offset), 5);
  const lists = await Promise.all(
    projects.map(async (project) =>
      (await listProjectAssessments(project.id)).map((a) => ({ ...a, project })),
    ),
  );
  return lists.flat();
}

/** Runs `read` for every assessment and keeps (assessment, rows) pairs that
 *  have rows. */
export async function perAssessment<R>(
  assessments: AssessmentWithProject[],
  read: (assessment: AssessmentWithProject) => Promise<R[]>,
): Promise<{ assessment: AssessmentWithProject; rows: R[] }[]> {
  const results = await Promise.all(
    assessments.map(async (assessment) => ({ assessment, rows: await read(assessment) })),
  );
  return results.filter((r) => r.rows.length > 0);
}
