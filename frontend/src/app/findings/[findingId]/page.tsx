import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { ConfidenceBadge, SeverityBadge, TriageBadge } from "@/components/badges";
import { EvidenceView } from "@/components/evidence";
import { SelectField, TextArea, TextField } from "@/components/fields";
import { PageError } from "@/components/page-error";
import { RuleView } from "@/components/rule";
import { SafeBlock, SafeText } from "@/components/safe-text";
import {
  Actor,
  EmptyState,
  ErrorPanel,
  KeyValues,
  Mono,
  Notice,
  PageHeader,
  Section,
} from "@/components/ui";
import { triageAction } from "@/lib/actions/reports";
import { getFinding, listFindingEvidence, listFindingHistory } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { formatTime, humanize } from "@/lib/text";

export const metadata: Metadata = { title: "Finding" };

const TRIAGE_OPTIONS = ["open", "confirmed", "false_positive", "accepted_risk"] as const;

export default async function FindingPage({ params }: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await params;
  const finding = await load(() => getFinding(findingId));
  if (!finding.ok) return <PageError error={finding.error} />;
  const f = finding.data;
  const [history, evidence] = await Promise.all([
    load(() => listFindingHistory(findingId)),
    load(() => listFindingEvidence(findingId)),
  ]);
  return (
    <>
      <PageHeader
        kicker={`Finding · ${f.rule_id} v${f.rule_version}`}
        title={<SafeText value={f.title} />}
      >
        <SeverityBadge severity={f.severity} />
        <ConfidenceBadge confidence={f.confidence} />
        <TriageBadge status={f.status} />
        <Link href={`/findings?scan=${f.scan_id}`}>Findings of this scan</Link>
      </PageHeader>

      <Section title="Rule-engine result" id="result">
        <p className="muted small">
          Produced by SentinelVAPT&apos;s deterministic rule engine from the scan&apos;s stored,
          redacted evidence. Severity and confidence are the rule&apos;s, not a CVSS score.
        </p>
        <KeyValues
          rows={[
            ["Rule", <Mono key="r">{`${f.rule_id} (version ${f.rule_version})`}</Mono>],
            ["Severity", <SeverityBadge key="s" severity={f.severity} />],
            ["Confidence", <ConfidenceBadge key="c" confidence={f.confidence} />],
            ["Detection type", humanize(f.detection_type)],
            ["Category", <SafeText key="cat" value={f.category} />],
            [
              "Subject",
              <SafeText key="sub" value={`${f.subject_type}: ${f.subject_key}`} className="mono" />,
            ],
            ["Discriminator", <SafeText key="d" value={f.discriminator} className="mono" />],
            ["Affected count", f.affected_count],
            ["Asset", f.asset_id ? <Mono key="a">{f.asset_id}</Mono> : "—"],
            ["Endpoint", f.endpoint_id ? <Mono key="e">{f.endpoint_id}</Mono> : "—"],
            ["Fingerprint (identity)", <Mono key="fp">{f.fingerprint}</Mono>],
            [
              "Scan",
              <Link key="scan" href={`/scans/${f.scan_id}`}>
                <Mono>{f.scan_id}</Mono>
              </Link>,
            ],
            ["Found (UTC)", formatTime(f.created_at)],
          ]}
        />
        <h4>Details recorded by the rule</h4>
        <SafeBlock value={JSON.stringify(f.details, null, 2)} label="Finding details" />
      </Section>

      <Section title="Rule" id="rule">
        <RuleView rule={f.rule as Record<string, unknown>} />
      </Section>

      <Section title="Triage" id="triage">
        <Notice>
          Triage records a human decision about this finding. It is separate from any retest{" "}
          <strong>comparison state</strong>: it never changes a comparison already made (each
          comparison stores the triage status it saw), and it never changes the evidence.
        </Notice>
        <KeyValues
          rows={[
            ["Triage status", <TriageBadge key="t" status={f.status} />],
            ["Reason", <SafeText key="r" value={f.status_reason} />],
            [
              "Changed by",
              f.status_changed_by ? <Actor key="b" name={f.status_changed_by} /> : "—",
            ],
            ["Changed at (UTC)", formatTime(f.status_changed_at)],
          ]}
        />
        <h3>Record a triage decision</h3>
        <ActionForm
          action={triageAction.bind(null, f.id)}
          submitLabel="Record triage"
          testId="triage"
        >
          <SelectField
            name="status"
            label="Triage status"
            options={TRIAGE_OPTIONS.filter((s) => s !== f.status).map(
              (s) => [s, humanize(s)] as const,
            )}
          />
          <TextArea name="reason" label="Reason" maxLength={2000} />
          <TextField
            name="triaged_by"
            label="Triaged by"
            required
            hint="Self-asserted: there is no platform login yet."
          />
        </ActionForm>
        <h3>Triage history</h3>
        {!history.ok ? (
          <ErrorPanel error={history.error} />
        ) : history.data.length === 0 ? (
          <EmptyState>No triage changes yet.</EmptyState>
        ) : (
          <table className="table" data-testid="triage-history">
            <thead>
              <tr>
                <th scope="col">When (UTC)</th>
                <th scope="col">From</th>
                <th scope="col">To</th>
                <th scope="col">Reason</th>
                <th scope="col">By</th>
              </tr>
            </thead>
            <tbody>
              {history.data.map((h) => (
                <tr key={h.id}>
                  <td className="mono small">{formatTime(h.changed_at)}</td>
                  <td>
                    <TriageBadge status={h.from_status} />
                  </td>
                  <td>
                    <TriageBadge status={h.to_status} />
                  </td>
                  <td className="wrap">
                    <SafeText value={h.reason} />
                  </td>
                  <td>
                    <Actor name={h.changed_by} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title={`Evidence (${f.evidence_ids.length})`} id="evidence">
        {!evidence.ok ? (
          <ErrorPanel error={evidence.error} />
        ) : evidence.data.length === 0 ? (
          <EmptyState>No evidence linked.</EmptyState>
        ) : (
          evidence.data.map((e) => <EvidenceView key={e.id} evidence={e} />)
        )}
      </Section>
    </>
  );
}
