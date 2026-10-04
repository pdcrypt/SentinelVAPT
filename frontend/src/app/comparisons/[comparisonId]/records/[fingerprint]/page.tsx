import type { Metadata } from "next";
import Link from "next/link";

import { ComparisonStateBadge, SeverityBadge, TriageBadge } from "@/components/badges";
import { Reasons, TriageWhenCompared } from "@/components/comparison";
import { EvidenceLinks, EvidenceView } from "@/components/evidence";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { EmptyState, KeyValues, Mono, Notice, PageHeader, Section } from "@/components/ui";
import { getComparisonRecord, getEvidence, getFinding } from "@/lib/api/endpoints";
import type { FindingDetail } from "@/lib/api/types";
import { STATE_TEXT } from "@/lib/comparison-text";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Comparison record" };

function FindingSide({ title, finding }: { title: string; finding: FindingDetail | null }) {
  return (
    <Section title={title}>
      {finding === null ? (
        <EmptyState>No finding on this side.</EmptyState>
      ) : (
        <KeyValues
          rows={[
            [
              "Finding",
              <Link key="f" href={`/findings/${finding.id}`}>
                <SafeText value={finding.title} />
              </Link>,
            ],
            ["Rule version", <Mono key="v">{`${finding.rule_id} v${finding.rule_version}`}</Mono>],
            ["Severity", <SeverityBadge key="s" severity={finding.severity} />],
            ["Subject", <SafeText key="sub" value={finding.subject_key} className="mono" />],
            ["Triage status now", <TriageBadge key="t" status={finding.status} />],
            ["Evidence", <EvidenceLinks key="e" ids={finding.evidence_ids} />],
          ]}
        />
      )}
    </Section>
  );
}

export default async function RecordPage({
  params,
}: {
  params: Promise<{ comparisonId: string; fingerprint: string }>;
}) {
  const { comparisonId, fingerprint } = await params;
  const record = await load(() => getComparisonRecord(comparisonId, fingerprint));
  if (!record.ok) return <PageError error={record.error} />;
  const r = record.data;
  const [baseline, current, coverage] = await Promise.all([
    r.baseline_finding_id ? load(() => getFinding(r.baseline_finding_id!)) : null,
    r.current_finding_id ? load(() => getFinding(r.current_finding_id!)) : null,
    Promise.all(r.coverage_evidence_ids.slice(0, 5).map((id) => load(() => getEvidence(id)))),
  ]);
  return (
    <>
      <PageHeader kicker={`Comparison record · ${r.rule_id}`} title={<Mono>{r.fingerprint}</Mono>}>
        <ComparisonStateBadge state={r.state} />
        <Link href={`/comparisons/${comparisonId}#state-${r.state}`}>Back to comparison</Link>
      </PageHeader>
      <Section title="Classification (as stored)">
        <KeyValues
          rows={[
            ["Comparison state", <ComparisonStateBadge key="s" state={r.state} />],
            ["Meaning", STATE_TEXT[r.state]],
            ["Reasons", <Reasons key="r" reasons={r.reasons} />],
            ["Triage status (when compared)", <TriageWhenCompared key="t" record={r} />],
            ["Coverage evidence", <EvidenceLinks key="c" ids={r.coverage_evidence_ids} />],
          ]}
        />
        <Notice>
          The triage status shown &quot;now&quot; on each finding may differ from the triage status
          when compared: later triage never changes this comparison.
        </Notice>
      </Section>
      <div className="grid-2">
        <FindingSide
          title="Baseline finding"
          finding={baseline && baseline.ok ? baseline.data : null}
        />
        <FindingSide title="Retest finding" finding={current && current.ok ? current.data : null} />
      </div>
      {coverage.length > 0 && (
        <Section title="Retest evidence showing the subject was examined" id="coverage">
          {coverage.map((e, i) =>
            e.ok ? <EvidenceView key={e.data.id} evidence={e.data} /> : <PageErrorInline key={i} />,
          )}
          {r.coverage_evidence_ids.length > 5 && (
            <p className="muted small">The first 5 are shown in full.</p>
          )}
        </Section>
      )}
    </>
  );
}

function PageErrorInline() {
  return <p className="muted small">An evidence record could not be loaded.</p>;
}
