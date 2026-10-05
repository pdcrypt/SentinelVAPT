import type { Metadata } from "next";

import { AuditFiltersForm, AuditTable, Pager } from "@/components/admin";
import { ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { auditFilters } from "@/lib/admin/filters";
import { listAuditEvents } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

export const metadata: Metadata = { title: "Platform audit log" };

/** The whole platform's security history (M6 API, `audit.read_global`:
 *  global administrators). Anyone else gets the API's refusal. Read-only. */
export default async function GlobalAuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { filters, query, offset } = auditFilters(await searchParams, true);
  const events = await load(() => listAuditEvents(query));
  return (
    <>
      <PageHeader kicker="Administration" title="Platform audit log" />
      {!events.ok ? (
        <ErrorPanel error={events.error} />
      ) : (
        <Section title="Events (newest first)">
          <Notice tone="info">
            Recorded by the API as things happen; this page only reads them. Actor labels are the
            names stored at the time.
          </Notice>
          <AuditFiltersForm path="/admin/audit" filters={filters} global />
          <AuditTable events={events.data} global />
          <Pager path="/admin/audit" filters={filters} offset={offset} count={events.data.length} />
        </Section>
      )}
    </>
  );
}
