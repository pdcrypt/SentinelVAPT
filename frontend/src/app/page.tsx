import Link from "next/link";

import { SafeText } from "@/components/safe-text";
import { ErrorPanel, Section } from "@/components/ui";
import { listProjects } from "@/lib/api/endpoints";
import { formatTime } from "@/lib/text";
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

export default async function HomePage() {
  const projects = await load(() => listProjects());
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
              No platform login yet. Names entered in forms (authorizer, triager, report author) are{" "}
              <strong>self-asserted</strong>; the platform does not verify who you are or whether an
              authorization is genuine.
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

      <Section title="Recent projects">
        {!projects.ok ? (
          <ErrorPanel error={projects.error} />
        ) : projects.data.length === 0 ? (
          <p className="empty">
            No projects yet. <Link href="/projects">Create the first one.</Link>
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Project</th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.slice(0, 8).map((project) => (
                <tr key={project.id}>
                  <td>
                    <Link href={`/projects/${project.id}`}>
                      <SafeText value={project.name} />
                    </Link>
                  </td>
                  <td className="mono">{formatTime(project.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
