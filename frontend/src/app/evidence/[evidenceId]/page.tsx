import type { Metadata } from "next";
import Link from "next/link";

import { EvidenceView } from "@/components/evidence";
import { PageError } from "@/components/page-error";
import { PageHeader, Section } from "@/components/ui";
import { getEvidence } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { shortId } from "@/lib/text";

export const metadata: Metadata = { title: "Evidence" };

export default async function EvidencePage({
  params,
}: {
  params: Promise<{ evidenceId: string }>;
}) {
  const { evidenceId } = await params;
  const evidence = await load(() => getEvidence(evidenceId));
  if (!evidence.ok) return <PageError error={evidence.error} />;
  return (
    <>
      <PageHeader kicker="Evidence" title={`E-${shortId(evidence.data.id)}`}>
        <Link href={`/scans/${evidence.data.scan_id}?tab=evidence`}>Scan evidence</Link>
      </PageHeader>
      <Section title="Captured exchange">
        <p className="muted small">
          Redacted by the scanner before storage. Everything below came from the target and is shown
          as inert text; URLs are not links.
        </p>
        <EvidenceView evidence={evidence.data} />
      </Section>
    </>
  );
}
