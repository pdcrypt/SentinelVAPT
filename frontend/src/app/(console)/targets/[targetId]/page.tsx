import type { Metadata } from "next";
import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import {
  AuthorizationFields,
  AuthorizationSummaryView,
  ScopeView,
} from "@/components/authorization";
import { StatusBadge } from "@/components/badges";
import { TextArea, TextField } from "@/components/fields";
import { SafeText } from "@/components/safe-text";
import { AssessmentsTable } from "@/components/tables";
import { Actor, EmptyState, ErrorPanel, Notice, PageHeader, Section } from "@/components/ui";
import { createAssessmentAction } from "@/lib/actions/assessments";
import { reauthorizeTargetAction } from "@/lib/actions/projects";
import { getTarget, listAuthorizations, listTargetAssessments } from "@/lib/api/endpoints";
import { load } from "@/lib/load";
import { PageError } from "@/components/page-error";
import { formatTime } from "@/lib/text";

export const metadata: Metadata = { title: "Target" };

export default async function TargetPage({ params }: { params: Promise<{ targetId: string }> }) {
  const { targetId } = await params;
  const target = await load(() => getTarget(targetId));
  if (!target.ok) return <PageError error={target.error} />;
  const t = target.data;
  const [history, assessments] = await Promise.all([
    load(() => listAuthorizations(targetId)),
    load(() => listTargetAssessments(targetId)),
  ]);
  const scannable = t.environment === "local_lab" && t.authorization.status === "active";
  return (
    <>
      <PageHeader kicker="Target" title={<SafeText value={t.name} />}>
        <Link href={`/projects/${t.project_id}`}>Back to project</Link>
        <StatusBadge status={t.authorization.status} />
      </PageHeader>

      {!scannable && (
        <Notice tone="warn">
          {t.environment !== "local_lab"
            ? "This target is not a local lab target: SentinelVAPT refuses to scan it."
            : `The current authorization is ${t.authorization.status}: assessments cannot start until a valid authorization is recorded.`}
        </Notice>
      )}

      <div className="grid-2">
        <Section title="Scope" id="scope">
          <ScopeView scope={t} />
        </Section>
        <Section title="Current authorization" id="authorization">
          <AuthorizationSummaryView auth={t.authorization} />
        </Section>
      </div>

      <Section title="Assessments" id="assessments">
        {assessments.ok ? (
          <AssessmentsTable assessments={assessments.data} />
        ) : (
          <ErrorPanel error={assessments.error} />
        )}
        <h3>Plan an assessment</h3>
        <p className="muted small">
          The assessment is planned under the current authorization (v{t.authorization.version}). It
          can only start while that authorization is current and active.
        </p>
        <ActionForm
          action={createAssessmentAction.bind(null, t.id)}
          submitLabel="Create assessment"
          testId="create-assessment"
        >
          <TextField name="name" label="Name" required />
          <TextArea name="description" label="Description" />
        </ActionForm>
      </Section>

      <Section title="Authorization history" id="history">
        <p className="muted small">
          Append-only: every acknowledgement is kept with the exact scope it covered.
        </p>
        {!history.ok ? (
          <ErrorPanel error={history.error} />
        ) : history.data.length === 0 ? (
          <EmptyState>No authorization records.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table" data-testid="authorization-history">
              <thead>
                <tr>
                  <th scope="col">Version</th>
                  <th scope="col">Status</th>
                  <th scope="col">Window (UTC)</th>
                  <th scope="col">Authorized by</th>
                  <th scope="col">Reference</th>
                  <th scope="col">Acknowledged</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((a) => (
                  <tr key={a.id}>
                    <td>
                      v{a.version}
                      {a.is_current && <span className="pill"> current</span>}
                    </td>
                    <td>
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="mono small">
                      {formatTime(a.valid_from)} → {formatTime(a.valid_until)}
                    </td>
                    <td>
                      <SafeText value={a.authorized_by} />
                    </td>
                    <td className="wrap">
                      <SafeText value={a.reference} />
                    </td>
                    <td className="small">
                      <Actor name={a.acknowledged_by} userId={a.acknowledged_by_user_id} />
                      <br />
                      <span className="mono">{formatTime(a.acknowledged_at)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Record a new authorization" id="reauthorize">
        <p className="muted small">
          Records a new authorization version for the same scope. Assessments planned under an
          earlier version can no longer start scans.
        </p>
        <ActionForm
          action={reauthorizeTargetAction.bind(null, t.id)}
          submitLabel="Record authorization"
          variant="secondary"
          testId="reauthorize"
        >
          <AuthorizationFields />
        </ActionForm>
      </Section>
    </>
  );
}
