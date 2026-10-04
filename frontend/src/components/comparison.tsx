import Link from "next/link";

import { ComparisonStateBadge, StatusBadge, TriageBadge } from "@/components/badges";
import { EvidenceLinks } from "@/components/evidence";
import { SafeText } from "@/components/safe-text";
import { EmptyState, Mono } from "@/components/ui";
import type { Comparison, ComparisonRecord, TargetAuthorization } from "@/lib/api/types";
import { REASON_TEXT } from "@/lib/comparison-text";
import { formatTime, shortId } from "@/lib/text";

// Comparison display (ADR 0013): the comparison state is the stored one
// (ComparisonStateBadge); the triage statuses recorded at comparison time are
// labelled "Triage status (when compared)" and shown with TriageBadge.

export function Reasons({ reasons }: { reasons: readonly string[] }) {
  if (reasons.length === 0) return <span className="muted">—</span>;
  return (
    <ul className="small reasons">
      {reasons.map((reason) => (
        <li key={reason}>
          <SafeText value={reason} className="mono" />
          {REASON_TEXT[reason] && <span className="muted"> · {REASON_TEXT[reason]}</span>}
        </li>
      ))}
    </ul>
  );
}

export function TriageWhenCompared({ record }: { record: ComparisonRecord }) {
  return (
    <span className="small">
      {record.baseline_finding_id !== null && (
        <span>
          baseline <TriageBadge status={record.baseline_triage} />{" "}
        </span>
      )}
      {record.current_finding_id !== null && (
        <span>
          retest <TriageBadge status={record.current_triage} />
        </span>
      )}
    </span>
  );
}

export function RecordsTable({
  comparisonId,
  records,
}: {
  comparisonId: string;
  records: ComparisonRecord[];
}) {
  if (records.length === 0) return <EmptyState>None.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="comparison-records">
        <thead>
          <tr>
            <th scope="col">Identity</th>
            <th scope="col">Rule</th>
            <th scope="col">Comparison state</th>
            <th scope="col">Reasons</th>
            <th scope="col">Findings</th>
            <th scope="col">Triage status (when compared)</th>
            <th scope="col">Coverage evidence</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => (
            <tr key={r.fingerprint} data-state={r.state} data-rule={r.rule_id}>
              <td>
                <Link href={`/comparisons/${comparisonId}/records/${r.fingerprint}`}>
                  <Mono>{r.fingerprint.slice(0, 12)}</Mono>
                </Link>
              </td>
              <td>
                <Mono>{r.rule_id}</Mono>
              </td>
              <td>
                <ComparisonStateBadge state={r.state} />
              </td>
              <td>
                <Reasons reasons={r.reasons} />
              </td>
              <td className="small">
                {r.baseline_finding_id ? (
                  <Link href={`/findings/${r.baseline_finding_id}`}>baseline</Link>
                ) : (
                  <span className="muted">no baseline</span>
                )}
                {" · "}
                {r.current_finding_id ? (
                  <Link href={`/findings/${r.current_finding_id}`}>retest</Link>
                ) : (
                  <span className="muted">not in retest</span>
                )}
              </td>
              <td>
                <TriageWhenCompared record={r} />
              </td>
              <td>
                <EvidenceLinks ids={r.coverage_evidence_ids} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ComparisonsTable({ comparisons }: { comparisons: Comparison[] }) {
  if (comparisons.length === 0) return <EmptyState>No comparisons yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="comparisons-table">
        <thead>
          <tr>
            <th scope="col">Comparison</th>
            <th scope="col">Status</th>
            <th scope="col">Policy</th>
            <th scope="col">Retest scan</th>
            <th scope="col">Requested (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {comparisons.map((c) => (
            <tr key={c.id}>
              <td>
                <Link href={`/comparisons/${c.id}`}>
                  <Mono>{shortId(c.id)}</Mono>
                </Link>
              </td>
              <td>
                <StatusBadge status={c.status} />
              </td>
              <td>
                <Mono>{c.policy_version}</Mono>
              </td>
              <td>
                <Link href={`/scans/${c.current_scan_id}`}>
                  <Mono>{shortId(c.current_scan_id)}</Mono>
                </Link>
              </td>
              <td className="mono">{formatTime(c.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type Scope = Pick<
  TargetAuthorization,
  "in_scope_hosts" | "allowed_ports" | "in_scope_path_prefixes" | "excluded_paths"
>;

/** The baseline's and the retest's recorded scopes side by side. Values
 *  present in one and not the other are listed (display of stored data; the
 *  API enforced containment when the retest was created). */
export function ScopeDifferences({ baseline, retest }: { baseline: Scope; retest: Scope }) {
  const rows: [string, (string | number)[], (string | number)[]][] = [
    ["In-scope hosts", baseline.in_scope_hosts, retest.in_scope_hosts],
    ["Allowed ports", baseline.allowed_ports, retest.allowed_ports],
    ["In-scope path prefixes", baseline.in_scope_path_prefixes, retest.in_scope_path_prefixes],
    ["Excluded paths", baseline.excluded_paths, retest.excluded_paths],
  ];
  const show = (values: (string | number)[]) =>
    values.length === 0 ? (
      <span className="muted">None</span>
    ) : (
      <SafeText value={values.join(", ")} className="mono" />
    );
  const only = (a: (string | number)[], b: (string | number)[]) =>
    a.filter((v) => !b.map(String).includes(String(v)));
  const changed = rows.some(([, b, r]) => only(b, r).length > 0 || only(r, b).length > 0);
  return (
    <>
      {!changed && <p className="small">The retest used the same scope as the baseline.</p>}
      <table className="table" data-testid="scope-differences">
        <thead>
          <tr>
            <th scope="col">Scope</th>
            <th scope="col">Baseline</th>
            <th scope="col">Retest</th>
            <th scope="col">Only in baseline</th>
            <th scope="col">Only in retest</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, b, r]) => (
            <tr key={label}>
              <th scope="row">{label}</th>
              <td>{show(b)}</td>
              <td>{show(r)}</td>
              <td>{show(only(b, r))}</td>
              <td>{show(only(r, b))}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {changed && (
        <p className="muted small">
          Baseline findings outside the retest&apos;s scope are reported as{" "}
          <Mono>NOT_RETESTED</Mono>: that is not remediation.
        </p>
      )}
    </>
  );
}
