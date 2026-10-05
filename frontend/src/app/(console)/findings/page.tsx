import type { Metadata } from "next";
import Link from "next/link";

import { ConfidenceBadge, SeverityBadge, StatusBadge, TriageBadge } from "@/components/badges";
import { SeverityChart } from "@/components/charts";
import { SelectField, TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, Mono, Notice, PageHeader, Section } from "@/components/ui";
import {
  allPages,
  getAssessmentFindingSummary,
  getScan,
  getScanFindingSummary,
  listFindings,
  listProjectAssessments,
  listProjects,
  type FindingFilters,
} from "@/lib/api/endpoints";
import { SEVERITIES, type Finding } from "@/lib/api/types";
import { load, param } from "@/lib/load";
import { formatTime, humanize, shortId } from "@/lib/text";

export const metadata: Metadata = { title: "Findings" };

type Search = Record<string, string | string[] | undefined>;

const FILTER_KEYS = [
  "severity",
  "confidence",
  "status",
  "detection_type",
  "category",
  "rule_id",
] as const;
const SORTS = {
  severity: "Severity (highest first)",
  rule: "Rule",
  status: "Triage status",
  subject: "Affected subject",
} as const;
type Sort = keyof typeof SORTS;

const SEVERITY_RANK: Record<string, number> = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

/** Ordering of rows already returned by the API (display only). */
function sortFindings(rows: Finding[], sort: Sort): Finding[] {
  const bySubject = (a: Finding, b: Finding) =>
    a.subject_key.localeCompare(b.subject_key) || a.fingerprint.localeCompare(b.fingerprint);
  const compare: Record<Sort, (a: Finding, b: Finding) => number> = {
    severity: (a, b) =>
      (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99) ||
      a.rule_id.localeCompare(b.rule_id) ||
      bySubject(a, b),
    rule: (a, b) => a.rule_id.localeCompare(b.rule_id) || bySubject(a, b),
    status: (a, b) => a.status.localeCompare(b.status) || bySubject(a, b),
    subject: bySubject,
  };
  return [...rows].sort(compare[sort]);
}

async function Overview() {
  const assessments = await load(async () => {
    const projects = await allPages((offset) => listProjects(offset), 5);
    const lists = await Promise.all(projects.map((p) => listProjectAssessments(p.id)));
    return lists.flat();
  });
  if (!assessments.ok) return <ErrorPanel error={assessments.error} />;
  if (assessments.data.length === 0) return <EmptyState>No assessments yet.</EmptyState>;
  const summaries = await Promise.all(
    assessments.data.map(async (a) => ({
      a,
      summary: await load(() => getAssessmentFindingSummary(a.id)),
    })),
  );
  return (
    <div className="table-wrap">
      <table className="table" data-testid="findings-overview">
        <thead>
          <tr>
            <th scope="col">Assessment</th>
            <th scope="col">Status</th>
            <th scope="col">Findings</th>
            {SEVERITIES.map((s) => (
              <th key={s} scope="col">
                {humanize(s)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {summaries.map(({ a, summary }) => (
            <tr key={a.id}>
              <td>
                <Link href={`/assessments/${a.id}#findings`}>
                  <SafeText value={a.name} />
                </Link>
              </td>
              <td>
                <StatusBadge status={a.status} />
              </td>
              <td>{summary.ok ? summary.data.total : "—"}</td>
              {SEVERITIES.map((s) => (
                <td key={s}>
                  {summary.ok && typeof summary.data.by_severity[s] === "number"
                    ? String(summary.data.by_severity[s])
                    : "0"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

async function ScanFindings({ scanId, search }: { scanId: string; search: Search }) {
  const scan = await load(() => getScan(scanId));
  if (!scan.ok) return <PageError error={scan.error} />;
  const filters: FindingFilters = {};
  for (const key of FILTER_KEYS) {
    const value = param(search[key]);
    if (value) filters[key] = value;
  }
  const requestedSort = param(search.sort) ?? "severity";
  const sort: Sort = requestedSort in SORTS ? (requestedSort as Sort) : "severity";
  const [summary, findings] = await Promise.all([
    load(() => getScanFindingSummary(scanId)),
    load(() => allPages((offset) => listFindings(scanId, filters, offset))),
  ]);
  const rows = findings.ok ? sortFindings(findings.data, sort) : [];
  const option = (v: string): readonly [string, string] => [v, humanize(v)];
  return (
    <>
      <Notice>
        Scan <Mono>{scan.data.id}</Mono> of{" "}
        <Link href={`/assessments/${scan.data.assessment_id}`}>its assessment</Link>. Severity and
        confidence are results of SentinelVAPT&apos;s deterministic rule engine; triage status is a
        separate human decision.
      </Notice>
      <Section title="Summary" id="summary">
        {summary.ok ? (
          <SeverityChart counts={summary.data.by_severity} />
        ) : (
          <ErrorPanel error={summary.error} />
        )}
      </Section>
      <Section title="Findings" id="findings">
        <form method="get" action="/findings" className="filters" aria-label="Filter findings">
          <input type="hidden" name="scan" value={scanId} />
          <SelectField
            name="severity"
            label="Severity"
            options={[["", "Any"], ...SEVERITIES.map(option)]}
            defaultValue={filters.severity ?? ""}
          />
          <SelectField
            name="confidence"
            label="Confidence"
            options={[["", "Any"], ...["high", "medium", "low"].map(option)]}
            defaultValue={filters.confidence ?? ""}
          />
          <SelectField
            name="status"
            label="Triage status"
            options={[
              ["", "Any"],
              ...["open", "confirmed", "false_positive", "accepted_risk"].map(option),
            ]}
            defaultValue={filters.status ?? ""}
          />
          <SelectField
            name="detection_type"
            label="Detection type"
            options={[
              ["", "Any"],
              ...["automated_detection", "manual_verification_required"].map(option),
            ]}
            defaultValue={filters.detection_type ?? ""}
          />
          <TextField name="rule_id" label="Rule ID" defaultValue={filters.rule_id} maxLength={40} />
          <SelectField
            name="sort"
            label="Sort by"
            options={Object.entries(SORTS)}
            defaultValue={sort}
          />
          <button type="submit" className="btn btn-secondary">
            Apply
          </button>
        </form>
        {!findings.ok ? (
          <ErrorPanel error={findings.error} />
        ) : rows.length === 0 ? (
          <EmptyState>No findings match.</EmptyState>
        ) : (
          <div className="table-wrap">
            <p className="muted small">{rows.length} finding(s)</p>
            <table className="table" data-testid="findings-table">
              <thead>
                <tr>
                  <th scope="col">Severity</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Title</th>
                  <th scope="col">Affected</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Triage</th>
                  <th scope="col">Found (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id} data-rule={f.rule_id}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <Mono>{f.rule_id}</Mono>
                    </td>
                    <td className="wrap">
                      <Link href={`/findings/${f.id}`}>
                        <SafeText value={f.title} />
                      </Link>
                    </td>
                    <td className="wrap small">
                      <SafeText value={f.subject_key} className="mono" />
                      {f.affected_count > 1 && ` (+${f.affected_count - 1})`}
                    </td>
                    <td>
                      <ConfidenceBadge confidence={f.confidence} />
                    </td>
                    <td>
                      <TriageBadge status={f.status} />
                    </td>
                    <td className="mono small">{formatTime(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}

export default async function FindingsPage({ searchParams }: { searchParams: Promise<Search> }) {
  const search = await searchParams;
  const scanId = param(search.scan);
  return (
    <>
      <PageHeader kicker="Findings" title={scanId ? "Findings of a scan" : "Findings"}>
        {scanId && <Link href="/findings">All assessments</Link>}
        {scanId && <span className="muted small">Scan {shortId(scanId)}</span>}
      </PageHeader>
      {scanId ? (
        <ScanFindings scanId={scanId} search={search} />
      ) : (
        <Section title="Findings by assessment" id="overview">
          <p className="muted small">
            Findings belong to analysed scans. Open an assessment to choose a scan.
          </p>
          <Overview />
        </Section>
      )}
    </>
  );
}
