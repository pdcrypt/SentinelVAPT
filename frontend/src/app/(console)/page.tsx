import Link from "next/link";

import { Pager } from "@/components/admin";
import { PostureOverview } from "@/components/posture";
import { ErrorPanel, Section } from "@/components/ui";
import { offsetOf } from "@/lib/admin/filters";
import { listPosture } from "@/lib/api/endpoints";
import { load } from "@/lib/load";

const WORKFLOW = [
  ["Project", "Group the work for one engagement."],
  ["Target + authorization", "Record who authorized testing, the scope and the window."],
  ["Assessment", "Plan an assessment under the current authorization, then start it."],
  ["Scan", "Passive discovery of the lab target; results are redacted and stored."],
  ["Findings + triage", "Rule-engine findings with evidence; triage records a human decision."],
  ["Scan report", "Freeze a snapshot of an analysed scan into JSON, HTML and PDF."],
  ["Retest", "After remediation, retest under a contained scope."],
  ["Comparison", "Classify every finding against the baseline from stored evidence."],
  ["Retest report", "Freeze the comparison into an evidence-backed retest report."],
] as const;

/** The cross-project security posture (ADR 0015): one row per project the API
 *  says you are a member of, with counts it computed from persisted records. */
export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const offset = offsetOf(await searchParams);
  const posture = await load(() => listPosture(offset));
  return (
    <>
      <header className="page-header">
        <p className="kicker">Operator console</p>
        <h1>SentinelVAPT</h1>
        <p className="muted">
          Authorized web application security assessment and reporting, for local labs and
          explicitly authorized targets only.
        </p>
      </header>

      <Section title="Security posture" id="posture">
        {!posture.ok ? (
          <ErrorPanel error={posture.error} />
        ) : (
          <>
            <PostureOverview projects={posture.data} />
            <Pager path="/" filters={{}} offset={offset} count={posture.data.length} />
            <p className="muted small">
              For each of your projects: findings of the latest completed, analysed scan of each
              target; the latest completed comparison (stored states); the latest completed reports.
              Counts only; there is no score.
            </p>
          </>
        )}
      </Section>

      <div className="grid-2">
        <Section title="Workflow">
          <ol className="small">
            {WORKFLOW.map(([step, text]) => (
              <li key={step}>
                <strong>{step}</strong>: {text}
              </li>
            ))}
          </ol>
          <p>
            <Link className="btn" href="/projects">
              Go to projects
            </Link>
          </p>
        </Section>

        <Section title="Safety model">
          <ul className="small">
            <li>Localhost-only: this console and the API are bound to 127.0.0.1.</li>
            <li>
              You are signed in: the API records who performed each action from your session, never
              from a name in a form. Who authorized testing is still what you enter; the platform
              cannot verify that an authorization is genuine.
            </li>
            <li>
              Only <code>local_lab</code> targets can be scanned. Checks are passive and
              non-destructive.
            </li>
            <li>Your browser talks only to this console; the API stays server-side.</li>
            <li>
              Everything captured from targets is shown as inert text. Report previews run in a
              sandbox with no scripts.
            </li>
            <li>
              Comparison states (e.g. <code>FIXED</code>) come from stored evidence and are shown
              exactly as stored. Triage is a separate human decision.
            </li>
          </ul>
        </Section>
      </div>
    </>
  );
}
