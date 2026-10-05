import type { Metadata } from "next";
import Link from "next/link";

import { StatusBadge } from "@/components/badges";
import { PageError } from "@/components/page-error";
import { ReportDetail } from "@/components/report-detail";
import { SafeText } from "@/components/safe-text";
import { Mono, PageHeader } from "@/components/ui";
import { getReport } from "@/lib/api/endpoints";
import { load, param } from "@/lib/load";

export const metadata: Metadata = { title: "Scan report" };

export default async function ReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ reportId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { reportId } = await params;
  const existing = param((await searchParams).existing) === "1";
  const report = await load(() => getReport(reportId));
  if (!report.ok) return <PageError error={report.error} />;
  const r = report.data;
  return (
    <>
      <PageHeader kicker={`Scan report ${r.number}`} title={<SafeText value={r.title} />}>
        <StatusBadge status={r.status} />
        <Link href={`/assessments/${r.assessment_id}#reports`}>Assessment</Link>
      </PageHeader>
      <ReportDetail
        kind="reports"
        report={r}
        existing={existing}
        context={[
          [
            "Scan",
            <Link key="scan" href={`/scans/${r.scan_id}`}>
              <Mono>{r.scan_id}</Mono>
            </Link>,
          ],
          ["Analysis run", <Mono key="run">{r.analysis_run_id}</Mono>],
        ]}
      />
    </>
  );
}
