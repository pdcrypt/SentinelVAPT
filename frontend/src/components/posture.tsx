import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { SeverityChart, StateChart, TriageStatusChart } from "@/components/charts";
import { SafeText } from "@/components/safe-text";
import { EmptyState, Notice, Section } from "@/components/ui";
import { isUuid } from "@/lib/api/endpoints";
import type {
  ComparisonSummary,
  FindingCounts,
  ProjectPosture,
  ProjectPostureSummary,
  RecentScan,
  ReportRef,
  TargetPosture,
} from "@/lib/api/types";
import { formatTime, humanize, shortId } from "@/lib/text";

// The security posture dashboard (ADR 0015). Presentation only: every count,
// every "latest", what is open or active and every comparison state comes from
// the API, which computes them from persisted records. Nothing here filters,
// classifies or scores. API strings are rendered with <SafeText>, and links
// are built only from validated UUIDs.

function idLink(prefix: string, id: string | null | undefined, label: React.ReactNode) {
  return id && isUuid(id) ? <Link href={`${prefix}/${id}`}>{label}</Link> : label;
}

/** "label n" pairs, in the API's order, for a compact text summary. */
function pairs(counts: Record<string, number>, onlyNonZero = false): string {
  const entries = Object.entries(counts).filter(([, n]) => !onlyNonZero || n > 0);
  return entries.length === 0 ? "none" : entries.map(([k, n]) => `${humanize(k)} ${n}`).join(" · ");
}

export function CountsStrip({ findings }: { findings: FindingCounts }) {
  return (
    <dl className="counts" data-testid="posture-counts">
      <div>
        <dt>Active findings</dt>
        <dd data-testid="count-active">{findings.active}</dd>
      </div>
      <div>
        <dt>Open</dt>
        <dd data-testid="count-open">{findings.open}</dd>
      </div>
      <div>
        <dt>All findings</dt>
        <dd data-testid="count-total">{findings.total}</dd>
      </div>
    </dl>
  );
}

function CountsTable({
  counts,
  caption,
  testId,
}: {
  counts: Record<string, number>;
  caption: string;
  testId: string;
}) {
  return (
    <table className="table table-compact" data-testid={testId}>
      <caption className="sr-only">{caption}</caption>
      <tbody>
        {Object.entries(counts).map(([key, n]) => (
          <tr key={key} data-key={key} data-value={n}>
            <th scope="row">{humanize(key)}</th>
            <td>{n}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function FindingsPosture({ findings }: { findings: FindingCounts }) {
  if (findings.total === 0) {
    return (
      <EmptyState>
        No findings: no target has a completed, analysed scan with findings yet.
      </EmptyState>
    );
  }
  return (
    <>
      <CountsStrip findings={findings} />
      <div className="grid-2">
        <div>
          <SeverityChart
            counts={findings.by_severity}
            id="posture-severity"
            title="Active findings by severity"
          />
          <CountsTable
            counts={findings.by_severity}
            caption="Active findings by severity"
            testId="severity-counts"
          />
        </div>
        <div>
          <TriageStatusChart counts={findings.by_status} id="posture-triage" />
          <CountsTable
            counts={findings.by_status}
            caption="Findings by triage status"
            testId="status-counts"
          />
        </div>
      </div>
      <p className="muted small">
        From the latest completed, analysed scan of each target. Active means every triage status
        except false positive (as in reports); open means triage status “open”. Severity is the
        rule&apos;s own rating, not CVSS. There is no overall score.
      </p>
    </>
  );
}

export function TargetsPosture({
  targets,
  truncated,
}: {
  targets: TargetPosture[];
  truncated: boolean;
}) {
  if (targets.length === 0) return <EmptyState>No targets yet.</EmptyState>;
  return (
    <>
      <div className="table-wrap">
        <table className="table" data-testid="posture-targets">
          <thead>
            <tr>
              <th>Target</th>
              <th>Latest analysed scan</th>
              <th>Finished (UTC)</th>
              <th>Active</th>
              <th>Open</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.target_id} data-target={t.target_id}>
                <td>{idLink("/targets", t.target_id, <SafeText value={t.target_name} />)}</td>
                <td>
                  {t.latest_scan ? (
                    <>
                      {idLink(
                        "/scans",
                        t.latest_scan.scan_id,
                        <span className="mono">{shortId(t.latest_scan.scan_id)}</span>,
                      )}{" "}
                      <span className="muted small">
                        (<SafeText value={t.latest_scan.assessment_name} />)
                      </span>
                    </>
                  ) : (
                    <span className="muted">None yet</span>
                  )}
                </td>
                <td className="mono small">{formatTime(t.latest_scan?.finished_at)}</td>
                <td>
                  {t.latest_scan && isUuid(t.latest_scan.scan_id) ? (
                    <Link href={`/findings?scan=${t.latest_scan.scan_id}`}>
                      {t.findings.active}
                    </Link>
                  ) : (
                    "—"
                  )}
                </td>
                <td>{t.latest_scan ? t.findings.open : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {truncated && (
        <Notice tone="info">
          Only the first 100 targets are listed; the counts above include all.
        </Notice>
      )}
    </>
  );
}

export function RetestOutcome({ comparison }: { comparison: ComparisonSummary | null }) {
  if (!comparison) {
    return (
      <EmptyState>
        No completed comparison yet. Retest an assessment and request a comparison to see what was
        fixed, what is new and what reopened.
      </EmptyState>
    );
  }
  return (
    <div data-testid="retest-outcome">
      <p>
        {idLink("/comparisons", comparison.comparison_id, "Latest comparison")} on{" "}
        <SafeText value={comparison.target_name} />, finished{" "}
        <span className="mono">{formatTime(comparison.finished_at)}</span>. States are the stored
        comparison records (policy cmp-1), not recomputed.
      </p>
      <StateChart counts={comparison.by_state} id="posture-states" />
      <table className="table table-compact" data-testid="state-counts">
        <caption className="sr-only">Comparison records by state</caption>
        <tbody>
          {Object.entries(comparison.by_state).map(([state, n]) => (
            <tr key={state} data-key={state} data-value={n}>
              <th scope="row">{state.toUpperCase()}</th>
              <td>{n}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReportLink({
  report,
  prefix,
  label,
}: {
  report: ReportRef | null;
  prefix: string;
  label: string;
}) {
  return (
    <li>
      <strong>{label}:</strong>{" "}
      {report ? (
        <>
          {idLink(prefix, report.report_id, <SafeText value={report.title} />)}{" "}
          <span className="muted small">
            ({report.kind}, #{report.number}, {formatTime(report.finished_at)})
          </span>
        </>
      ) : (
        <span className="muted">none completed yet</span>
      )}
    </li>
  );
}

export function LatestReports({
  report,
  retestReport,
}: {
  report: ReportRef | null;
  retestReport: ReportRef | null;
}) {
  return (
    <ul className="plain" data-testid="latest-reports">
      <ReportLink report={report} prefix="/reports" label="Scan report" />
      <ReportLink report={retestReport} prefix="/retest-reports" label="Retest report" />
    </ul>
  );
}

export function RecentScans({ scans }: { scans: RecentScan[] }) {
  if (scans.length === 0) return <EmptyState>No scans yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="recent-scans">
        <thead>
          <tr>
            <th>Scan</th>
            <th>Target</th>
            <th>Assessment</th>
            <th>Status</th>
            <th>Created (UTC)</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.scan_id} data-scan={s.scan_id}>
              <td>
                {idLink("/scans", s.scan_id, <span className="mono">{shortId(s.scan_id)}</span>)}
              </td>
              <td>
                <SafeText value={s.target_name} />
              </td>
              <td>
                {idLink("/assessments", s.assessment_id, <SafeText value={s.assessment_name} />)}
              </td>
              <td>
                <StatusBadge status={s.status} />
              </td>
              <td className="mono small">{formatTime(s.created_at)}</td>
              <td>
                {s.findings_total === null ? (
                  <span className="muted">not analysed</span>
                ) : (
                  s.findings_total
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The project page's dashboard. */
export function ProjectPostureView({ posture }: { posture: ProjectPosture }) {
  return (
    <>
      <Section title="Current posture" id="posture">
        <FindingsPosture findings={posture.findings} />
      </Section>
      <Section title="Latest analysed scan per target">
        <TargetsPosture targets={posture.targets} truncated={posture.targets_truncated} />
      </Section>
      <div className="grid-2">
        <Section title="Latest retest outcome">
          <RetestOutcome comparison={posture.latest_comparison} />
        </Section>
        <Section title="Latest reports">
          <LatestReports
            report={posture.latest_report}
            retestReport={posture.latest_retest_report}
          />
        </Section>
      </div>
      <Section title="Recent scans">
        <RecentScans scans={posture.recent_scans} />
        <p className="muted small">The 10 most recent scans of this project, in any state.</p>
      </Section>
    </>
  );
}

/** One row per project the API says the user may see. */
export function PostureOverview({ projects }: { projects: ProjectPostureSummary[] }) {
  if (projects.length === 0) {
    return (
      <EmptyState>
        You are not a member of any project yet. Create one, or ask a project owner to add you.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table" data-testid="posture-overview">
        <thead>
          <tr>
            <th>Project</th>
            <th>Your role</th>
            <th>Latest analysed scan (UTC)</th>
            <th>Active findings by severity</th>
            <th>Open</th>
            <th>Latest retest</th>
            <th>Latest reports</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((p) => (
            <tr key={p.project_id} data-project={p.project_id}>
              <td>{idLink("/projects", p.project_id, <SafeText value={p.project_name} />)}</td>
              <td>{humanize(p.role)}</td>
              <td className="mono small">
                {formatTime(p.latest_scan_finished_at)}
                {p.targets_with_analysed_scan > 0 && (
                  <span className="muted">
                    {" "}
                    ({p.targets_with_analysed_scan} target
                    {p.targets_with_analysed_scan === 1 ? "" : "s"})
                  </span>
                )}
              </td>
              <td className="small" data-testid="overview-severity">
                {p.findings.active === 0 ? (
                  <span className="muted">none</span>
                ) : (
                  <>
                    <strong>{p.findings.active}</strong> · {pairs(p.findings.by_severity, true)}
                  </>
                )}
              </td>
              <td data-testid="overview-open">{p.findings.open}</td>
              <td className="small" data-testid="overview-retest">
                {p.latest_comparison ? (
                  idLink(
                    "/comparisons",
                    p.latest_comparison.comparison_id,
                    Object.entries(p.latest_comparison.by_state)
                      .filter(([, n]) => n > 0)
                      .map(([state, n]) => `${state.toUpperCase()} ${n}`)
                      .join(" · ") || "no records",
                  )
                ) : (
                  <span className="muted">none</span>
                )}
              </td>
              <td className="small">
                {p.latest_report
                  ? idLink("/reports", p.latest_report.report_id, `Scan #${p.latest_report.number}`)
                  : null}
                {p.latest_report && p.latest_retest_report ? " · " : null}
                {p.latest_retest_report
                  ? idLink(
                      "/retest-reports",
                      p.latest_retest_report.report_id,
                      `Retest #${p.latest_retest_report.number}`,
                    )
                  : null}
                {!p.latest_report && !p.latest_retest_report && <span className="muted">none</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
