import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AutoRefresh } from "@/components/auto-refresh";
import { StatusBadge } from "@/components/badges";
import { LineageChart } from "@/components/charts";
import { ComparisonsTable, ScopeDifferences } from "@/components/comparison";
import { SelectField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { RetestReportsTable } from "@/components/report-tables";
import { SafeText } from "@/components/safe-text";
import { isAnalysed, scanLabel, withAnalysis } from "@/components/scans";
import {
  EmptyState,
  ErrorPanel,
  KeyValues,
  Mono,
  Notice,
  PageHeader,
  Section,
} from "@/components/ui";
import { requestComparisonAction } from "@/lib/actions/reports";
import {
  getAssessment,
  getLineage,
  listComparisons,
  listRetestReports,
  listScans,
} from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { retestScopes } from "@/lib/scopes";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Retest" };

export default async function RetestPage({
  params,
}: {
  params: Promise<{ assessmentId: string }>;
}) {
  const { assessmentId } = await params;
  const retest = await load(() => getAssessment(assessmentId));
  if (!retest.ok) return <PageError error={retest.error} />;
  const r = retest.data;
  if (!r.retest_of_assessment_id) {
    return (
      <>
        <PageHeader kicker="Retest" title={<SafeText value={r.name} />} />
        <Notice>
          This assessment is not a retest. <Link href={`/assessments/${r.id}`}>Open it</Link> to
          create a retest once it is completed.
        </Notice>
      </>
    );
  }
  const parentId = r.retest_of_assessment_id;
  const [parent, lineage, comparisons, scans, reports] = await Promise.all([
    load(() => getAssessment(parentId)),
    load(() => getLineage(r.id)),
    load(() => listComparisons(r.id)),
    load(async () => withAnalysis(await listScans(r.id))),
    load(() => listRetestReports(r.id)),
  ]);
  const scopes = parent.ok ? await load(() => retestScopes(parent.data, r)) : null;
  const analysed = scans.ok ? scans.data.filter(isAnalysed) : [];
  const queued = comparisons.ok && comparisons.data.some((c) => c.status === "queued");
  return (
    <>
      <PageHeader kicker="Retest" title={<SafeText value={r.name} />}>
        <StatusBadge status={r.status} />
        <Link href={`/assessments/${r.id}`}>Assessment page (scans, lifecycle)</Link>
        <AutoRefresh active={queued} />
      </PageHeader>

      <Section title="Baseline relationship" id="baseline">
        <KeyValues
          rows={[
            [
              "Retest of",
              parent.ok ? (
                <Link key="p" href={`/assessments/${parent.data.id}`}>
                  <SafeText value={parent.data.name} />
                </Link>
              ) : (
                <Mono key="p">{parentId}</Mono>
              ),
            ],
            [
              "Baseline scan",
              r.baseline_scan_id ? (
                <Link key="b" href={`/scans/${r.baseline_scan_id}`}>
                  <Mono>{r.baseline_scan_id}</Mono>
                </Link>
              ) : (
                "—"
              ),
            ],
            ["Retest status", <StatusBadge key="s" status={r.status} />],
            ["Created (UTC)", formatTime(r.created_at)],
          ]}
        />
      </Section>

      <Section title="Lineage" id="lineage">
        {!lineage.ok ? (
          <ErrorPanel error={lineage.error} />
        ) : (
          <>
            <LineageChart entries={lineage.data} currentId={r.id} />
            <table className="table" data-testid="lineage-table">
              <thead>
                <tr>
                  <th scope="col">#</th>
                  <th scope="col">Assessment</th>
                  <th scope="col">Status</th>
                  <th scope="col">Comparisons</th>
                </tr>
              </thead>
              <tbody>
                {lineage.data.map((e) => (
                  <tr key={e.assessment_id}>
                    <td>{e.position}</td>
                    <td>
                      <Link
                        href={
                          e.retest_of_assessment_id
                            ? `/retests/${e.assessment_id}`
                            : `/assessments/${e.assessment_id}`
                        }
                      >
                        <SafeText value={e.name} />
                      </Link>
                    </td>
                    <td>
                      <StatusBadge status={e.status} />
                    </td>
                    <td>
                      {e.comparisons.length === 0
                        ? "—"
                        : e.comparisons.map((c) => (
                            <Link key={c.id} href={`/comparisons/${c.id}`}>
                              <StatusBadge status={c.status} />{" "}
                            </Link>
                          ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Section>

      <Section title="Scope differences" id="scope">
        {scopes === null || !scopes.ok || scopes.data === null ? (
          <EmptyState>The recorded scopes could not be loaded.</EmptyState>
        ) : (
          <ScopeDifferences baseline={scopes.data.baseline} retest={scopes.data.retest} />
        )}
      </Section>

      <Section title="Comparisons" id="comparisons">
        {comparisons.ok ? (
          <ComparisonsTable comparisons={comparisons.data} />
        ) : (
          <ErrorPanel error={comparisons.error} />
        )}
        <h3>Compare a retest scan with the baseline</h3>
        {analysed.length === 0 ? (
          <EmptyState>
            A comparison needs a completed, analysed scan of this retest.{" "}
            <Link href={`/assessments/${r.id}#scans`}>Launch one</Link>.
          </EmptyState>
        ) : (
          <ActionForm
            action={requestComparisonAction.bind(null, r.id)}
            submitLabel="Request comparison"
            testId="request-comparison"
          >
            <SelectField
              name="scan_id"
              label="Retest scan"
              options={analysed.map((s) => [s.id, scanLabel(s)] as const)}
            />
          </ActionForm>
        )}
      </Section>

      <Section title="Retest reports" id="retest-reports">
        {reports.ok ? (
          <RetestReportsTable reports={reports.data} />
        ) : (
          <ErrorPanel error={reports.error} />
        )}
        <p className="muted small">Request a retest report from a completed comparison.</p>
      </Section>
    </>
  );
}
