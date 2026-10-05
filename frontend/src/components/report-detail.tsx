import type { ReactNode } from "react";

import { AutoRefresh } from "@/components/auto-refresh";
import { StatusBadge } from "@/components/badges";
import { ReportPreview } from "@/components/report-preview";
import { ArtifactsTable } from "@/components/report-tables";
import { SafeText } from "@/components/safe-text";
import { Actor, KeyValues, Mono, Notice, Section } from "@/components/ui";
import type { Report, RetestReport } from "@/lib/api/types";
import { formatTime } from "@/lib/text";

export function ReportDetail({
  kind,
  report,
  context,
  existing,
}: {
  kind: "reports" | "retest-reports";
  report: Report | RetestReport;
  context: [string, ReactNode][];
  existing: boolean;
}) {
  const working = report.status === "queued" || report.status === "generating";
  const artifacts = report.artifacts ?? [];
  return (
    <>
      {existing && (
        <Notice>
          An identical report (same inputs and content) already existed, so the API returned it
          (HTTP 200) instead of creating a new one.
        </Notice>
      )}
      <Section title="Status" id="status" actions={<AutoRefresh active={working} />}>
        {report.status === "failed" && (
          <Notice tone="warn">
            Generation failed (<Mono>{report.error_code ?? "unknown"}</Mono>). The frozen snapshot
            is kept; request a new report to try again.
          </Notice>
        )}
        <KeyValues
          rows={[
            ["Number", <Mono key="n">{report.number}</Mono>],
            ["Status", <StatusBadge key="s" status={report.status} />],
            ["Kind", report.kind],
            ["Title", <SafeText key="t" value={report.title} />],
            ["Classification", report.classification],
            [
              "Prepared by",
              <Actor key="p" name={report.prepared_by} userId={report.requested_by_user_id} />,
            ],
            ["Reviewed by", report.reviewed_by ? <Actor key="r" name={report.reviewed_by} /> : "—"],
            ...context,
            [
              "Template",
              <Mono key="tpl">{`${report.template_id}@${report.template_version} · ${report.template_hash}`}</Mono>,
            ],
            ["Snapshot schema", <Mono key="sch">{report.schema_version}</Mono>],
            ["Snapshot SHA-256", <Mono key="ss">{report.snapshot_sha256}</Mono>],
            ["Content SHA-256", <Mono key="cs">{report.content_sha256}</Mono>],
            ["Formats", report.formats.join(", ")],
            ["Requested (UTC)", formatTime(report.created_at)],
            ["Finished (UTC)", formatTime(report.finished_at)],
          ]}
        />
      </Section>
      <Section title="Artifacts" id="artifacts">
        <p className="muted small">
          Downloads are served by this console from the stored artifact (never re-rendered). Each
          download&apos;s ETag is its SHA-256, so it can be checked against the value below.
        </p>
        <ArtifactsTable kind={kind} reportId={report.id} artifacts={artifacts} />
      </Section>
      {report.status === "completed" && report.formats.includes("html") && (
        <Section title="Preview" id="preview">
          <p className="muted small">
            The generated HTML is shown in a sandbox with no scripts and no access to this
            application (opaque origin: no cookies, storage or page access).
          </p>
          <ReportPreview kind={kind} reportId={report.id} title={`Preview of ${report.number}`} />
        </Section>
      )}
    </>
  );
}
