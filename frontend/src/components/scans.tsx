import "server-only";

import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { EmptyState } from "@/components/ui";
import { listAnalysisRuns } from "@/lib/api/endpoints";
import type { Scan } from "@/lib/api/types";
import { formatTime, shortId } from "@/lib/text";

export type ScanWithAnalysis = Scan & { analysis: string | null };

/** Scans with the status of their latest analysis run (a scan can be
 *  reported on, compared or retested only once analysis has completed). */
export async function withAnalysis(scans: Scan[]): Promise<ScanWithAnalysis[]> {
  return Promise.all(
    scans.map(async (scan) => {
      if (scan.status !== "completed") return { ...scan, analysis: null };
      try {
        const runs = await listAnalysisRuns(scan.id);
        return { ...scan, analysis: runs.at(-1)?.status ?? null }; // oldest first
      } catch {
        return { ...scan, analysis: null };
      }
    }),
  );
}

export const isAnalysed = (scan: ScanWithAnalysis) =>
  scan.status === "completed" && scan.analysis === "completed";

export function scanLabel(scan: Scan): string {
  return `Scan ${shortId(scan.id)} · ${formatTime(scan.finished_at ?? scan.created_at)}`;
}

export function ScansTable({ scans }: { scans: ScanWithAnalysis[] }) {
  if (scans.length === 0) return <EmptyState>No scans yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="scans-table">
        <thead>
          <tr>
            <th scope="col">Scan</th>
            <th scope="col">Status</th>
            <th scope="col">Analysis</th>
            <th scope="col">Requests</th>
            <th scope="col">Endpoints</th>
            <th scope="col">Evidence</th>
            <th scope="col">Started (UTC)</th>
            <th scope="col">Finished (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <Link href={`/scans/${scan.id}`}>
                  <code>{shortId(scan.id)}</code>
                </Link>
              </td>
              <td>
                <StatusBadge status={scan.status} />
              </td>
              <td>{scan.analysis ? <StatusBadge status={scan.analysis} /> : "—"}</td>
              <td>{scan.requests_sent}</td>
              <td>{scan.endpoints_count}</td>
              <td>{scan.evidence_count}</td>
              <td className="mono">{formatTime(scan.started_at)}</td>
              <td className="mono">{formatTime(scan.finished_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
