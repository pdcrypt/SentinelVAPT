import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AutoRefresh } from "@/components/auto-refresh";
import { StatusBadge } from "@/components/badges";
import { EvidenceLinks, EvidenceView } from "@/components/evidence";
import { PageError } from "@/components/page-error";
import { SafeBlock, SafeText, SafeUrl } from "@/components/safe-text";
import {
  EmptyState,
  ErrorPanel,
  KeyValues,
  Mono,
  Notice,
  PageHeader,
  Section,
} from "@/components/ui";
import { cancelScanAction } from "@/lib/actions/assessments";
import {
  getScan,
  listAnalysisRuns,
  listAssets,
  listEndpoints,
  listScanEvidence,
  listScanLogs,
} from "@/lib/api/endpoints";
import { load, param } from "@/lib/load";
import { formatTime, humanize } from "@/lib/text";

export const metadata: Metadata = { title: "Scan" };

const TABS = ["overview", "logs", "assets", "endpoints", "evidence"] as const;
type Tab = (typeof TABS)[number];

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function Tabs({ scanId, tab }: { scanId: string; tab: Tab }) {
  return (
    <nav aria-label="Scan sections" className="actions">
      {TABS.map((t) => (
        <Link
          key={t}
          href={`/scans/${scanId}?tab=${t}`}
          className={t === tab ? "btn" : "btn btn-secondary"}
          aria-current={t === tab ? "page" : undefined}
        >
          {humanize(t)}
        </Link>
      ))}
    </nav>
  );
}

async function Overview({ scanId }: { scanId: string }) {
  const runs = await load(() => listAnalysisRuns(scanId));
  return (
    <Section title="Analysis" id="analysis">
      {!runs.ok ? (
        <ErrorPanel error={runs.error} />
      ) : runs.data.length === 0 ? (
        <EmptyState>Not analysed yet. Analysis runs after the scan completes.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table" data-testid="analysis-runs">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Status</th>
                <th scope="col">Ruleset</th>
                <th scope="col">Rules evaluated</th>
                <th scope="col">Findings</th>
                <th scope="col">Coverage notes</th>
                <th scope="col">Rule errors</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((run) => (
                <tr key={run.id}>
                  <td>
                    <Mono>{run.id.slice(0, 8)}</Mono>
                  </td>
                  <td>
                    <StatusBadge status={run.status} />
                  </td>
                  <td>
                    <Mono>{run.ruleset_version}</Mono>
                  </td>
                  <td>{run.rules_evaluated}</td>
                  <td>
                    <Link href={`/findings?scan=${scanId}`}>{run.findings_count}</Link>
                  </td>
                  <td className="small">
                    <SafeText value={run.coverage_notes.join(", ")} />
                  </td>
                  <td className="small">
                    {run.rule_errors.length === 0 ? (
                      "None"
                    ) : (
                      <SafeText value={JSON.stringify(run.rule_errors)} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

async function Logs({ scanId }: { scanId: string }) {
  const logs = await load(() => listScanLogs(scanId));
  if (!logs.ok) return <ErrorPanel error={logs.error} />;
  if (logs.data.length === 0) return <EmptyState>No log entries.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table compact" data-testid="scan-logs">
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">Time (UTC)</th>
            <th scope="col">Level</th>
            <th scope="col">Code</th>
            <th scope="col">Message</th>
            <th scope="col">URL</th>
          </tr>
        </thead>
        <tbody>
          {logs.data.map((log) => (
            <tr key={log.sequence}>
              <td>{log.sequence}</td>
              <td className="mono small">{formatTime(log.at)}</td>
              <td>
                <Mono>{log.level}</Mono>
              </td>
              <td>
                <SafeText value={log.code} className="mono" />
              </td>
              <td className="wrap">
                <SafeText value={log.message} />
              </td>
              <td className="wrap">
                <SafeUrl value={log.url} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {logs.data.length === 100 && <p className="muted small">Showing the first 100 entries.</p>}
    </div>
  );
}

async function Assets({ scanId }: { scanId: string }) {
  const assets = await load(() => listAssets(scanId));
  if (!assets.ok) return <ErrorPanel error={assets.error} />;
  if (assets.data.length === 0) return <EmptyState>No assets recorded.</EmptyState>;
  return (
    <table className="table" data-testid="scan-assets">
      <thead>
        <tr>
          <th scope="col">Scheme</th>
          <th scope="col">Host</th>
          <th scope="col">Port</th>
          <th scope="col">Resolved addresses</th>
        </tr>
      </thead>
      <tbody>
        {assets.data.map((asset) => (
          <tr key={asset.id}>
            <td>
              <Mono>{asset.scheme}</Mono>
            </td>
            <td>
              <SafeText value={asset.host} className="mono" />
            </td>
            <td>{asset.port}</td>
            <td>
              <SafeText value={asset.ip_addresses.join(", ")} className="mono" />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

async function Endpoints({ scanId }: { scanId: string }) {
  const endpoints = await load(() => listEndpoints(scanId));
  if (!endpoints.ok) return <ErrorPanel error={endpoints.error} />;
  if (endpoints.data.length === 0) return <EmptyState>No endpoints recorded.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table compact" data-testid="scan-endpoints">
        <thead>
          <tr>
            <th scope="col">Method</th>
            <th scope="col">URL</th>
            <th scope="col">Source</th>
            <th scope="col">Fetched</th>
            <th scope="col">Status</th>
            <th scope="col">Content type</th>
            <th scope="col">Title</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.data.map((e) => (
            <tr key={e.id}>
              <td>
                <Mono>{e.method}</Mono>
              </td>
              <td className="wrap">
                <SafeUrl value={e.url} />
              </td>
              <td className="small">
                <SafeText value={e.source} />
              </td>
              <td className="small">
                {e.fetched ? "yes" : <SafeText value={`no (${e.skip_reason ?? "—"})`} />}
              </td>
              <td>{e.status_code ?? "—"}</td>
              <td className="small">
                <SafeText value={e.content_type} />
              </td>
              <td className="wrap">
                <SafeText value={e.title} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {endpoints.data.length === 100 && (
        <p className="muted small">Showing the first 100 endpoints.</p>
      )}
    </div>
  );
}

async function EvidenceTab({ scanId }: { scanId: string }) {
  const evidence = await load(() => listScanEvidence(scanId));
  if (!evidence.ok) return <ErrorPanel error={evidence.error} />;
  if (evidence.data.length === 0) return <EmptyState>No evidence captured.</EmptyState>;
  return (
    <>
      <p className="muted small">
        Captured responses, redacted by the scanner before storage, shown as inert text. Index:{" "}
        <EvidenceLinks ids={evidence.data.map((e) => e.id)} />
      </p>
      {evidence.data.slice(0, 10).map((e) => (
        <EvidenceView key={e.id} evidence={e} />
      ))}
      {evidence.data.length > 10 && (
        <p className="muted small">The first 10 are shown in full; open the others above.</p>
      )}
    </>
  );
}

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ scanId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { scanId } = await params;
  const requested = param((await searchParams).tab);
  const tab: Tab = (TABS as readonly string[]).includes(requested ?? "")
    ? (requested as Tab)
    : "overview";
  const scan = await load(() => getScan(scanId));
  if (!scan.ok) return <PageError error={scan.error} />;
  const s = scan.data;
  const active = s.status === "queued" || s.status === "running";
  return (
    <>
      <PageHeader kicker="Scan" title={<Mono>{s.id}</Mono>}>
        <StatusBadge status={s.status} />
        <Link href={`/assessments/${s.assessment_id}`}>Assessment</Link>
        <Link href={`/findings?scan=${s.id}`}>Findings</Link>
        <AutoRefresh active={active} />
      </PageHeader>

      <Section
        title="Status"
        id="status"
        actions={
          active && !s.cancel_requested ? (
            <ActionForm
              action={cancelScanAction.bind(null, s.id)}
              submitLabel="Cancel scan"
              variant="danger"
              className="inline-form"
              testId="cancel-scan"
            />
          ) : undefined
        }
      >
        {s.status === "failed" && (
          <Notice tone="warn">
            The scan failed (<Mono>{s.error_code ?? "unknown"}</Mono>).
          </Notice>
        )}
        <KeyValues
          rows={[
            ["Status", <StatusBadge key="s" status={s.status} />],
            ["Stop reason", <SafeText key="r" value={s.stop_reason} />],
            [
              "Cancellation",
              s.cancel_requested ? (
                <SafeText key="c" value={s.cancel_reason ?? "requested"} />
              ) : (
                "—"
              ),
            ],
            ["Error", <SafeText key="e" value={s.error_message} />],
            ["Requests sent", s.requests_sent],
            ["Pages / endpoints", `${s.pages_count} / ${s.endpoints_count}`],
            ["Events / evidence", `${s.events_count} / ${s.evidence_count}`],
            ["Scanner version", <SafeText key="v" value={s.scanner_version} />],
            ["Queued (UTC)", formatTime(s.created_at)],
            ["Started (UTC)", formatTime(s.started_at)],
            ["Finished (UTC)", formatTime(s.finished_at)],
            ["Last heartbeat (UTC)", formatTime(s.heartbeat_at)],
          ]}
        />
      </Section>

      <Tabs scanId={s.id} tab={tab} />

      {tab === "overview" && (
        <>
          <Overview scanId={s.id} />
          <Section title="Scanner grant (frozen when the scan was claimed)" id="grant">
            <SafeBlock value={s.grant_snapshot ? pretty(s.grant_snapshot) : null} label="Grant" />
          </Section>
          <Section title="Configuration" id="config">
            <SafeBlock value={pretty(s.config)} label="Configuration" />
          </Section>
        </>
      )}
      {tab === "logs" && (
        <Section title="Scan log" id="logs">
          <Logs scanId={s.id} />
        </Section>
      )}
      {tab === "assets" && (
        <Section title="Assets" id="assets">
          <Assets scanId={s.id} />
        </Section>
      )}
      {tab === "endpoints" && (
        <Section title="Endpoints" id="endpoints">
          <Endpoints scanId={s.id} />
        </Section>
      )}
      {tab === "evidence" && (
        <Section title="Evidence" id="evidence">
          <EvidenceTab scanId={s.id} />
        </Section>
      )}
    </>
  );
}
