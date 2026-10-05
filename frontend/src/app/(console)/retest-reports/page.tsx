import type { Metadata } from "next";
import Link from "next/link";

import { RetestReportsTable } from "@/components/report-tables";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, PageHeader, Section } from "@/components/ui";
import { allAssessments, perAssessment } from "@/lib/aggregate";
import { listRetestReports } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Retest reports" };

export default async function RetestReportsPage() {
  const groups = await load(async () =>
    perAssessment(
      (await allAssessments()).filter((a) => a.retest_of_assessment_id),
      (a) => listRetestReports(a.id),
    ),
  );
  return (
    <>
      <PageHeader kicker="Reporting" title="Retest reports" />
      <p className="muted small">
        Evidence-backed reports of one completed comparison (template <code>sv-retest@1</code>).
        Comparison states are copied exactly from the stored comparison. Request one from a
        comparison&apos;s page.
      </p>
      {!groups.ok ? (
        <ErrorPanel error={groups.error} />
      ) : groups.data.length === 0 ? (
        <EmptyState>No retest reports yet.</EmptyState>
      ) : (
        groups.data.map(({ assessment, rows }) => (
          <Section
            key={assessment.id}
            title={
              <>
                <SafeText value={assessment.project.name} /> / <SafeText value={assessment.name} />
              </>
            }
            actions={<Link href={`/retests/${assessment.id}`}>Retest</Link>}
          >
            <RetestReportsTable reports={rows} />
          </Section>
        ))
      )}
    </>
  );
}
