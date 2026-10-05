import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AutoRefresh } from "@/components/auto-refresh";
import { ComparisonStateBadge, StatusBadge } from "@/components/badges";
import { StateChart } from "@/components/charts";
import { RecordsTable, ScopeDifferences } from "@/components/comparison";
import { PageError } from "@/components/page-error";
import { ReportRequestFields } from "@/components/report-fields";
import { RetestReportsTable } from "@/components/report-tables";
import {
  EmptyState,
  ErrorPanel,
  KeyValues,
  Mono,
  Notice,
  PageHeader,
  Section,
} from "@/components/ui";
import { requestRetestReportAction } from "@/lib/actions/reports";
import {
  allPages,
  getAssessment,
  getComparison,
  listComparisonRecords,
  listRetestReports,
} from "@/lib/api/endpoints";
import { COMPARISON_STATES, type ComparisonRecord } from "@/lib/api/types";
import { STATE_TEXT, UNVERIFIED_STATES } from "@/lib/comparison-text";
import { load, param } from "@/lib/load";
import { retestScopes } from "@/lib/scopes";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Comparison" };

export default async function ComparisonPage({
  params,
  searchParams,
}: {
  params: Promise<{ comparisonId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { comparisonId } = await params;
  const existing = param((await searchParams).existing) === "1";
  const comparison = await load(() => getComparison(comparisonId));
  if (!comparison.ok) return <PageError error={comparison.error} />;
  const c = comparison.data;
  const completed = c.status === "completed";
  const [records, baseline, retest, reports] = await Promise.all([
    completed
      ? load(() => allPages((offset) => listComparisonRecords(c.id, {}, offset)))
      : Promise.resolve(null),
    load(() => getAssessment(c.baseline_assessment_id)),
    load(() => getAssessment(c.current_assessment_id)),
    load(() => listRetestReports(c.current_assessment_id)),
  ]);
  const scopes =
    baseline.ok && retest.ok ? await load(() => retestScopes(baseline.data, retest.data)) : null;
  const stored = (c.summary?.states ?? {}) as Record<string, unknown>;
  const byState = new Map<string, ComparisonRecord[]>();
  if (records?.ok) {
    for (const r of records.data) byState.set(r.state, [...(byState.get(r.state) ?? []), r]);
  }
  const versionChanges = records?.ok
    ? records.data.filter((r) => r.reasons.includes("rule_version_changed"))
    : [];
  const ruleErrors = records?.ok
    ? records.data.filter((r) =>
        r.reasons.some((x) => x === "rule_error" || x === "rule_not_evaluated"),
      )
    : [];
  const ownReports = reports.ok ? reports.data.filter((r) => r.comparison_id === c.id) : [];

  return (
    <>
      <PageHeader kicker={`Comparison · policy ${c.policy_version}`} title={<Mono>{c.id}</Mono>}>
        <StatusBadge status={c.status} />
        <Link href={`/retests/${c.current_assessment_id}`}>Retest</Link>
        <AutoRefresh active={c.status === "queued"} />
      </PageHeader>

      {existing && (
        <Notice>
          This scan had already been compared, so the API returned the existing comparison (HTTP
          200) instead of creating a new one.
        </Notice>
      )}
      {c.status === "failed" && (
        <Notice tone="warn">
          The comparison failed (<Mono>{c.error_code ?? "unknown"}</Mono>). Nothing was classified.
        </Notice>
      )}

      <Section title="Summary" id="summary">
        <p className="muted small">
          Comparison states are computed by the API from stored findings and evidence and shown here
          exactly as stored. Triage is a separate human decision, listed per record as it was when
          compared.
        </p>
        <KeyValues
          rows={[
            [
              "Baseline",
              <span key="b">
                {baseline.ok ? (
                  <Link href={`/assessments/${baseline.data.id}`}>assessment</Link>
                ) : (
                  "assessment"
                )}{" "}
                · scan{" "}
                <Link href={`/scans/${c.baseline_scan_id}`}>
                  <Mono>{c.baseline_scan_id}</Mono>
                </Link>
              </span>,
            ],
            [
              "Retest",
              <span key="r">
                <Link href={`/retests/${c.current_assessment_id}`}>assessment</Link> · scan{" "}
                <Link href={`/scans/${c.current_scan_id}`}>
                  <Mono>{c.current_scan_id}</Mono>
                </Link>
              </span>,
            ],
            [
              "Previous comparison",
              c.previous_comparison_id ? (
                <Link key="p" href={`/comparisons/${c.previous_comparison_id}`}>
                  <Mono>{c.previous_comparison_id}</Mono>
                </Link>
              ) : (
                "— (first retest in the chain)"
              ),
            ],
            ["Policy", <Mono key="pol">{c.policy_version}</Mono>],
            ["Requested (UTC)", formatTime(c.created_at)],
            ["Finished (UTC)", formatTime(c.finished_at)],
          ]}
        />
        {completed && <StateChart counts={stored} />}
      </Section>

      {completed && (
        <>
          {!records?.ok
            ? records && <ErrorPanel error={records.error} />
            : COMPARISON_STATES.map((state) => {
                const rows = byState.get(state) ?? [];
                return (
                  <Section
                    key={state}
                    id={`state-${state}`}
                    title={
                      <>
                        <ComparisonStateBadge state={state} /> {rows.length}
                      </>
                    }
                  >
                    <p className="muted small">{STATE_TEXT[state]}</p>
                    {UNVERIFIED_STATES.includes(state) && rows.length > 0 && (
                      <Notice tone="warn">
                        Unverified, not remediated: these findings may still exist.
                      </Notice>
                    )}
                    <RecordsTable comparisonId={c.id} records={rows} />
                  </Section>
                );
              })}

          <Section title="Rule and version differences" id="rule-versions">
            {versionChanges.length === 0 && ruleErrors.length === 0 ? (
              <EmptyState>
                None. Both analyses evaluated the same rule versions without errors.
              </EmptyState>
            ) : (
              <>
                <p className="muted small">
                  Records whose stored reasons say the rule version changed, or that the rule failed
                  or was not evaluated in the retest analysis.
                </p>
                <RecordsTable
                  comparisonId={c.id}
                  records={[
                    ...new Map(
                      [...versionChanges, ...ruleErrors].map((x) => [x.fingerprint, x]),
                    ).values(),
                  ]}
                />
              </>
            )}
          </Section>
        </>
      )}

      <Section title="Scope differences" id="scope">
        {scopes === null || !scopes.ok || scopes.data === null ? (
          <EmptyState>The recorded scopes could not be loaded.</EmptyState>
        ) : (
          <ScopeDifferences baseline={scopes.data.baseline} retest={scopes.data.retest} />
        )}
      </Section>

      <Section title="Retest reports" id="retest-reports">
        <RetestReportsTable reports={ownReports} />
        {completed ? (
          <>
            <h3>Request a retest report</h3>
            <ActionForm
              action={requestRetestReportAction.bind(null, c.current_assessment_id, c.id)}
              submitLabel="Request retest report"
              testId="request-retest-report"
            >
              <ReportRequestFields
                defaultTitle={`Retest report${retest.ok ? `: ${retest.data.name}` : ""}`.slice(
                  0,
                  200,
                )}
              />
            </ActionForm>
          </>
        ) : (
          <p className="muted small">Retest reports require a completed comparison.</p>
        )}
      </Section>
    </>
  );
}
