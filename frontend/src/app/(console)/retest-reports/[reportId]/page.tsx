import type { Metadata } from "next";
import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { PageError } from "@/components/page-error";
import { ReportDetail } from "@/components/report-detail";
import { SafeText } from "@/components/safe-text";
import { Mono, PageHeader } from "@/components/ui";
import { getRetestReport } from "@/lib/api/endpoints";
import { load, param } from "@/lib/load";

export const metadata: Metadata = { title: "Retest report" };

export default async function RetestReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ reportId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { reportId } = await params;
  const existing = param((await searchParams).existing) === "1";
  const report = await load(() => getRetestReport(reportId));
  if (!report.ok) return <PageError error={report.error} />;
  const r = report.data;
  return (
    <>
      <PageHeader kicker={`Retest report ${r.number}`} title={<SafeText value={r.title} />}>
        <StatusBadge status={r.status} />
        <Link href={`/comparisons/${r.comparison_id}`}>Comparison</Link>
        <Link href={`/retests/${r.current_assessment_id}`}>Retest</Link>
      </PageHeader>
      <ReportDetail
        kind="retest-reports"
        report={r}
        existing={existing}
        context={[
          [
            "Comparison",
            <Link key="c" href={`/comparisons/${r.comparison_id}`}>
              <Mono>{r.comparison_id}</Mono>
            </Link>,
          ],
          [
            "Baseline scan",
            <Link key="b" href={`/scans/${r.baseline_scan_id}`}>
              <Mono>{r.baseline_scan_id}</Mono>
            </Link>,
          ],
          [
            "Retest scan",
            <Link key="s" href={`/scans/${r.current_scan_id}`}>
              <Mono>{r.current_scan_id}</Mono>
            </Link>,
          ],
        ]}
      />
    </>
  );
}
