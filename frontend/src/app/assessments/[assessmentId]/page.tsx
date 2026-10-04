import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AuthorizationSummaryView, ScopeView } from "@/components/authorization";
import { AutoRefresh } from "@/components/auto-refresh";
import { StatusBadge } from "@/components/badges";
import { SelectField, TextArea, TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { ReportRequestFields } from "@/components/report-fields";
import { ReportsTable } from "@/components/report-tables";
import { SafeText } from "@/components/safe-text";
import { isAnalysed, scanLabel, ScansTable, withAnalysis } from "@/components/scans";
import { SeverityChart } from "@/components/charts";
import { AssessmentsTable } from "@/components/tables";
import {
  EmptyState,
  ErrorPanel,
  KeyValues,
  Mono,
  Notice,
  PageHeader,
  Section,
} from "@/components/ui";
import { startScanAction, transitionAssessmentAction } from "@/lib/actions/assessments";
import { createRetestAction, requestReportAction } from "@/lib/actions/reports";
import {
  getAssessment,
  getAssessmentFindingSummary,
  getTarget,
  listReports,
  listRetests,
  listScans,
} from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { formatTime, shortId } from "@/lib/text";

export const metadata: Metadata = { title: "Assessment" };

const ACTIVE_SCAN = new Set(["queued", "running"]);

export default async function AssessmentPage({
  params,
}: {
  params: Promise<{ assessmentId: string }>;
}) {
  const { assessmentId } = await params;
  const assessment = await load(() => getAssessment(assessmentId));
  if (!assessment.ok) return <PageError error={assessment.error} />;
  const a = assessment.data;
  const [target, scans, summary, reports, retests] = await Promise.all([
    load(() => getTarget(a.target_id)),
    load(async () => withAnalysis(await listScans(a.id))),
    load(() => getAssessmentFindingSummary(a.id)),
    load(() => listReports(a.id)),
    load(() => listRetests(a.id)),
  ]);
  const analysed = scans.ok ? scans.data.filter(isAnalysed) : [];
  const scanActive = scans.ok && scans.data.some((s) => ACTIVE_SCAN.has(s.status));
  const reportActive =
    reports.ok && reports.data.some((r) => r.status === "queued" || r.status === "generating");
  const authorizationCurrent = target.ok && target.data.authorization.id === a.authorization_id;

  return (
    <>
      <PageHeader kicker="Assessment" title={<SafeText value={a.name} />}>
        <StatusBadge status={a.status} />
        {target.ok && (
          <Link href={`/targets/${target.data.id}`}>
            Target: <SafeText value={target.data.name} />
          </Link>
        )}
        {a.retest_of_assessment_id && (
          <Link href={`/retests/${a.id}`}>Retest workflow (comparisons)</Link>
        )}
        <AutoRefresh active={scanActive || reportActive} />
      </PageHeader>

      <Section title="Lifecycle" id="lifecycle">
        <KeyValues
          rows={[
            ["Assessment ID", <Mono key="id">{a.id}</Mono>],
            ["Status", <StatusBadge key="s" status={a.status} />],
            ["Description", <SafeText key="d" value={a.description} />],
            ["Started (UTC)", formatTime(a.started_at)],
            ["Completed (UTC)", formatTime(a.completed_at)],
            [
              "Retest of",
              a.retest_of_assessment_id ? (
                <Link key="r" href={`/assessments/${a.retest_of_assessment_id}`}>
                  <Mono>{a.retest_of_assessment_id}</Mono>
                </Link>
              ) : (
                "—"
              ),
            ],
            [
              "Baseline scan",
              a.baseline_scan_id ? (
                <Link key="b" href={`/scans/${a.baseline_scan_id}`}>
                  <Mono>{a.baseline_scan_id}</Mono>
                </Link>
              ) : (
                "—"
              ),
            ],
          ]}
        />
        <div className="actions">
          {a.status === "planned" && (
            <ActionForm
              action={transitionAssessmentAction.bind(null, a.id, "start")}
              submitLabel="Start assessment"
              className="inline-form"
              testId="start-assessment"
            />
          )}
          {a.status === "in_progress" && (
            <ActionForm
              action={transitionAssessmentAction.bind(null, a.id, "complete")}
              submitLabel="Complete assessment"
              className="inline-form"
              testId="complete-assessment"
            />
          )}
          {(a.status === "planned" || a.status === "in_progress") && (
            <ActionForm
              action={transitionAssessmentAction.bind(null, a.id, "cancel")}
              submitLabel="Cancel assessment"
              variant="danger"
              className="inline-form"
              testId="cancel-assessment"
            />
          )}
        </div>
      </Section>

      {target.ok && (
        <div className="grid-2">
          <Section title="Target scope" id="scope">
            <ScopeView scope={target.data} />
          </Section>
          <Section title="Authorization window" id="authorization">
            {authorizationCurrent ? (
              <p className="small muted">
                This assessment was planned under the target&apos;s current authorization.
              </p>
            ) : (
              <Notice tone="warn">
                The target has been re-authorized since this assessment was planned (authorization{" "}
                <Mono>{shortId(a.authorization_id)}</Mono>). It can no longer start scans; plan a
                new assessment.
              </Notice>
            )}
            <AuthorizationSummaryView auth={target.data.authorization} />
          </Section>
        </div>
      )}

      <Section
        title="Scans"
        id="scans"
        actions={
          a.status === "in_progress" && !scanActive ? (
            <ActionForm
              action={startScanAction.bind(null, a.id)}
              submitLabel="Launch passive scan"
              className="inline-form"
              testId="launch-scan"
            />
          ) : undefined
        }
      >
        {a.status !== "in_progress" && (
          <p className="muted small">Scans can be launched while the assessment is in progress.</p>
        )}
        {scans.ok ? <ScansTable scans={scans.data} /> : <ErrorPanel error={scans.error} />}
      </Section>

      <Section title="Findings" id="findings">
        <p className="muted small">
          Severity and confidence are results of SentinelVAPT&apos;s deterministic rule engine for
          this assessment&apos;s analysed scans.
        </p>
        {!summary.ok ? (
          <ErrorPanel error={summary.error} />
        ) : summary.data.total === 0 ? (
          <EmptyState>No findings recorded.</EmptyState>
        ) : (
          <SeverityChart counts={summary.data.by_severity} />
        )}
        {analysed.length > 0 && (
          <ul className="small">
            {analysed.map((scan) => (
              <li key={scan.id}>
                <Link href={`/findings?scan=${scan.id}`}>Findings of {scanLabel(scan)}</Link>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Scan reports" id="reports">
        {reports.ok ? (
          <ReportsTable reports={reports.data} />
        ) : (
          <ErrorPanel error={reports.error} />
        )}
        <h3>Request a scan report</h3>
        {analysed.length === 0 ? (
          <EmptyState>A report needs a completed, analysed scan.</EmptyState>
        ) : (
          <ActionForm
            action={requestReportAction.bind(null, a.id)}
            submitLabel="Request report"
            testId="request-report"
          >
            <SelectField
              name="scan_id"
              label="Scan"
              options={analysed.map((s) => [s.id, scanLabel(s)] as const)}
            />
            <ReportRequestFields defaultTitle={`Security assessment: ${a.name}`.slice(0, 200)} />
          </ActionForm>
        )}
      </Section>

      <Section title="Retests" id="retests">
        {retests.ok ? (
          <AssessmentsTable assessments={retests.data} showRetest={false} />
        ) : (
          <ErrorPanel error={retests.error} />
        )}
        {a.status === "completed" && analysed.length > 0 ? (
          <>
            <h3>Create a retest</h3>
            <p className="muted small">
              A retest is a new assessment of the same target, compared against one of this
              assessment&apos;s analysed scans. Its scope must stay within this assessment&apos;s
              scope.
            </p>
            <ActionForm
              action={createRetestAction.bind(null, a.id)}
              submitLabel="Create retest"
              testId="create-retest"
            >
              <TextField name="name" label="Name" required />
              <TextArea name="description" label="Description" />
              <SelectField
                name="baseline_scan_id"
                label="Baseline scan"
                options={analysed.map((s) => [s.id, scanLabel(s)] as const)}
              />
            </ActionForm>
          </>
        ) : (
          <p className="muted small">
            Retests can be created once this assessment is completed and has an analysed scan.
          </p>
        )}
      </Section>
    </>
  );
}
