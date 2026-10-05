import type { Metadata } from "next";

import { SeverityBadge } from "@/components/badges";
import { PageError } from "@/components/page-error";
import { SafeText } from "@/components/safe-text";
import { Mono, PageHeader, Section } from "@/components/ui";
import { getRules } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { humanize } from "@/lib/text";

export const metadata: Metadata = { title: "Rule catalog" };

const s = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");

export default async function RulesPage() {
  const catalog = await load(() => getRules());
  if (!catalog.ok) return <PageError error={catalog.error} />;
  const rules = catalog.data.rules as Record<string, unknown>[];
  return (
    <>
      <PageHeader kicker="Analysis" title="Rule catalog">
        <span>
          Ruleset <Mono>{catalog.data.ruleset_version}</Mono> · {rules.length} passive rules
        </span>
      </PageHeader>
      <Section title="Rules this deployment evaluates">
        <p className="muted small">
          Deterministic, offline rules over stored, redacted scan data. No active checks and no AI.
        </p>
        <div className="table-wrap">
          <table className="table" data-testid="rules-table">
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Title</th>
                <th scope="col">Severity</th>
                <th scope="col">Detection</th>
                <th scope="col">Proves</th>
                <th scope="col">Does not prove</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={s(r.id)}>
                  <td>
                    <Mono>{`${s(r.id)} v${s(r.version)}`}</Mono>
                  </td>
                  <td className="wrap">
                    <SafeText value={s(r.title)} />
                  </td>
                  <td>
                    <SeverityBadge severity={s(r.severity)} />
                  </td>
                  <td className="small">{humanize(s(r.detection_type))}</td>
                  <td className="wrap small">
                    <SafeText value={s(r.proves)} />
                  </td>
                  <td className="wrap small">
                    <SafeText value={s(r.does_not_prove)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}
