import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { SafeText, SafeUrl } from "@/components/safe-text";
import { EmptyState, Mono } from "@/components/ui";
import type { Assessment, Target } from "@/lib/api/types";
import { formatTime, shortId } from "@/lib/text";

export function TargetsTable({ targets }: { targets: Target[] }) {
  if (targets.length === 0) return <EmptyState>No targets yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="targets-table">
        <thead>
          <tr>
            <th scope="col">Target</th>
            <th scope="col">Base URL</th>
            <th scope="col">Environment</th>
            <th scope="col">Authorization</th>
            <th scope="col">Valid until (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {targets.map((target) => (
            <tr key={target.id}>
              <td>
                <Link href={`/targets/${target.id}`}>
                  <SafeText value={target.name} />
                </Link>
              </td>
              <td className="wrap">
                <SafeUrl value={target.base_url} />
              </td>
              <td>
                <Mono>{target.environment}</Mono>
              </td>
              <td>
                v{target.authorization.version} <StatusBadge status={target.authorization.status} />
              </td>
              <td className="mono">{formatTime(target.authorization.valid_until)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AssessmentsTable({
  assessments,
  showRetest = true,
}: {
  assessments: Assessment[];
  showRetest?: boolean;
}) {
  if (assessments.length === 0) return <EmptyState>No assessments yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="assessments-table">
        <thead>
          <tr>
            <th scope="col">Assessment</th>
            <th scope="col">Status</th>
            {showRetest && <th scope="col">Retest of</th>}
            <th scope="col">Started (UTC)</th>
            <th scope="col">Completed (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {assessments.map((a) => (
            <tr key={a.id}>
              <td>
                <Link href={`/assessments/${a.id}`}>
                  <SafeText value={a.name} />
                </Link>
              </td>
              <td>
                <StatusBadge status={a.status} />
              </td>
              {showRetest && (
                <td>
                  {a.retest_of_assessment_id ? (
                    <Link href={`/assessments/${a.retest_of_assessment_id}`}>
                      <Mono>{shortId(a.retest_of_assessment_id)}</Mono>
                    </Link>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              )}
              <td className="mono">{formatTime(a.started_at)}</td>
              <td className="mono">{formatTime(a.completed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
