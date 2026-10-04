import type { Metadata } from "next";
import Link from "next/link";

import { ReportsTable } from "@/components/report-tables";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, PageHeader, Section } from "@/components/ui";
import { allAssessments, perAssessment } from "@/lib/aggregate";
import { listReports } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Scan reports" };

export default async function ReportsPage() {
  const groups = await load(async () =>
    perAssessment(await allAssessments(), (a) => listReports(a.id)),
  );
  return (
    <>
      <PageHeader kicker="Reporting" title="Scan reports" />
      <p className="muted small">
        Evidence-backed reports of one analysed scan (template <code>sv-standard@1</code>). Request
        one from an assessment&apos;s page.
      </p>
      {!groups.ok ? (
        <ErrorPanel error={groups.error} />
      ) : groups.data.length === 0 ? (
        <EmptyState>No scan reports yet.</EmptyState>
      ) : (
        groups.data.map(({ assessment, rows }) => (
          <Section
            key={assessment.id}
            title={
              <>
                <SafeText value={assessment.project.name} /> / <SafeText value={assessment.name} />
              </>
            }
            actions={<Link href={`/assessments/${assessment.id}#reports`}>Assessment</Link>}
          >
            <ReportsTable reports={rows} />
          </Section>
        ))
      )}
    </>
  );
}
