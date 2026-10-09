import type { Metadata } from "next";
import Link from "next/link";

import { ConfidenceBadge, SeverityBadge, TriageBadge } from "@/components/badges";
import { SeverityChart } from "@/components/charts";
import { SelectField, TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { EmptyState, ErrorPanel, Mono, Notice, PageHeader, Section } from "@/components/ui";
import {
  allPages,
  getScan,
  getScanFindingSummary,
  isUuid,
  listFindings,
  listPosture,
  type FindingFilters,
} from "@/lib/api/endpoints";
import { Pager } from "@/components/admin";
import { offsetOf } from "@/lib/admin/filters";
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

/** One row per project the API says you may see, from the posture summary
 *  (ADR 0015): the findings of each target's latest analysed scan, counted by
 *  the API. One request, instead of walking every project and assessment. */
async function Overview({ offset }: { offset: number }) {
  const posture = await load(() => listPosture(offset));
  if (!posture.ok) return <ErrorPanel error={posture.error} />;
  if (posture.data.length === 0) return <EmptyState>No projects yet.</EmptyState>;
  return (
    <>
      <div className="table-wrap">
        <table className="table" data-testid="findings-overview">
          <thead>
            <tr>
              <th scope="col">Project</th>
              <th scope="col">Active</th>
              <th scope="col">Open</th>
              {SEVERITIES.map((s) => (
                <th key={s} scope="col">
                  {humanize(s)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {posture.data.map((p) => (
              <tr key={p.project_id}>
                <td>
                  {isUuid(p.project_id) ? (
                    <Link href={`/projects/${p.project_id}#posture`}>
                      <SafeText value={p.project_name} />
                    </Link>
                  ) : (
                    <SafeText value={p.project_name} />
                  )}
                </td>
                <td>{p.findings.active}</td>
                <td>{p.findings.open}</td>
                {SEVERITIES.map((s) => (
                  <td key={s}>{String(p.findings.by_severity[s] ?? 0)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager path="/findings" filters={{}} offset={offset} count={posture.data.length} />
    </>
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
        {scanId && <Link href="/findings">All projects</Link>}
        {scanId && <span className="muted small">Scan {shortId(scanId)}</span>}
      </PageHeader>
      {scanId ? (
        <ScanFindings scanId={scanId} search={search} />
      ) : (
        <Section title="Current findings by project" id="overview">
          <p className="muted small">
            The findings of each target&apos;s latest completed, analysed scan, counted by the API
            (active means every triage status except false positive). Open a project to see each
            target&apos;s latest scan and its findings.
          </p>
          <Overview offset={offsetOf(search)} />
        </Section>
      )}
    </>
  );
}
