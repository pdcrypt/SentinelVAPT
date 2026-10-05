import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { SafeText } from "@/components/safe-text";
import { Actor, EmptyState, Mono } from "@/components/ui";
import type { Artifact, Report, RetestReport } from "@/lib/api/types";
import { formatTime } from "@/lib/text";

type AnyReport = Report | RetestReport;

function ReportRows({ reports, base }: { reports: AnyReport[]; base: string }) {
  return (
    <>
      {reports.map((r) => (
        <tr key={r.id}>
          <td>
            <Link href={`/${base}/${r.id}`}>
              <Mono>{r.number}</Mono>
            </Link>
          </td>
          <td className="wrap">
            <SafeText value={r.title} />
          </td>
          <td>{r.kind}</td>
          <td>
            <StatusBadge status={r.status} />
          </td>
          <td className="small">
            <Actor name={r.prepared_by} userId={r.requested_by_user_id} />
          </td>
          <td className="mono">{formatTime(r.created_at)}</td>
        </tr>
      ))}
    </>
  );
}

function Head() {
  return (
    <thead>
      <tr>
        <th scope="col">Number</th>
        <th scope="col">Title</th>
        <th scope="col">Kind</th>
        <th scope="col">Status</th>
        <th scope="col">Prepared by</th>
        <th scope="col">Requested (UTC)</th>
      </tr>
    </thead>
  );
}

export function ReportsTable({ reports }: { reports: Report[] }) {
  if (reports.length === 0) return <EmptyState>No scan reports yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="reports-table">
        <Head />
        <tbody>
          <ReportRows reports={reports} base="reports" />
        </tbody>
      </table>
    </div>
  );
}

export function RetestReportsTable({ reports }: { reports: RetestReport[] }) {
  if (reports.length === 0) return <EmptyState>No retest reports yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="retest-reports-table">
        <Head />
        <tbody>
          <ReportRows reports={reports} base="retest-reports" />
        </tbody>
      </table>
    </div>
  );
}

/** Artifacts of a completed report: download links to this origin's
 *  /artifacts routes (attachments), with the stored SHA-256 to verify. */
export function ArtifactsTable({
  kind,
  reportId,
  artifacts,
}: {
  kind: "reports" | "retest-reports";
  reportId: string;
  artifacts: Artifact[];
}) {
  if (artifacts.length === 0) return <EmptyState>No artifacts yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="artifacts-table">
        <thead>
          <tr>
            <th scope="col">Format</th>
            <th scope="col">Size</th>
            <th scope="col">SHA-256</th>
            <th scope="col">Renderer</th>
            <th scope="col">Download</th>
          </tr>
        </thead>
        <tbody>
          {artifacts.map((a) => (
            <tr key={a.format} data-format={a.format}>
              <td>
                <Mono>{a.format.toUpperCase()}</Mono>
              </td>
              <td>{a.size_bytes.toLocaleString("en-US")} B</td>
              <td className="mono wrap small" data-testid={`sha256-${a.format}`}>
                {a.sha256}
              </td>
              <td className="small">
                <SafeText value={a.renderer} />
              </td>
              <td>
                <a
                  href={`/artifacts/${kind}/${reportId}/${a.format}`}
                  download
                  data-testid={`download-${a.format}`}
                >
                  Download {a.format.toUpperCase()}
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
