import type { Metadata } from "next";
import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, Mono, PageHeader, Section } from "@/components/ui";
import { allAssessments } from "@/lib/aggregate";
import { load } from "@/lib/load";
import { formatTime, shortId } from "@/lib/text";

export const metadata: Metadata = { title: "Retests" };

export default async function RetestsPage() {
  const assessments = await load(() => allAssessments());
  const byId = new Map(assessments.ok ? assessments.data.map((a) => [a.id, a]) : []);
  const retests = assessments.ok ? assessments.data.filter((a) => a.retest_of_assessment_id) : [];
  return (
    <>
      <PageHeader kicker="Retesting" title="Retests" />
      <p className="muted small">
        A retest is a new assessment of the same target, compared against an analysed scan of a
        completed assessment. Create one from the completed assessment&apos;s page.
      </p>
      <Section title="All retests">
        {!assessments.ok ? (
          <ErrorPanel error={assessments.error} />
        ) : retests.length === 0 ? (
          <EmptyState>No retests yet.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table" data-testid="retests-table">
              <thead>
                <tr>
                  <th scope="col">Retest</th>
                  <th scope="col">Project</th>
                  <th scope="col">Status</th>
                  <th scope="col">Retest of</th>
                  <th scope="col">Baseline scan</th>
                  <th scope="col">Created (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {retests.map((r) => {
                  const parent = byId.get(r.retest_of_assessment_id ?? "");
                  return (
                    <tr key={r.id}>
                      <td>
                        <Link href={`/retests/${r.id}`}>
                          <SafeText value={r.name} />
                        </Link>
                      </td>
                      <td>
                        <SafeText value={r.project.name} />
                      </td>
                      <td>
                        <StatusBadge status={r.status} />
                      </td>
                      <td>
                        {parent ? (
                          <Link href={`/assessments/${parent.id}`}>
                            <SafeText value={parent.name} />
                          </Link>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td>
                        {r.baseline_scan_id ? (
                          <Link href={`/scans/${r.baseline_scan_id}`}>
                            <Mono>{shortId(r.baseline_scan_id)}</Mono>
                          </Link>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="mono">{formatTime(r.created_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
