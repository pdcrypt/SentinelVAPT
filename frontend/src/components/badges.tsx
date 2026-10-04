import { COMPARISON_STATES, SEVERITIES } from "@/lib/api/types";
import { humanize } from "@/lib/text";

// Status indicators. Each kind has its own component, label and style so they
// cannot be confused (ADR 0013):
// - ComparisonStateBadge: the persisted comparison state, exactly as stored
//   (upper case: FIXED, NOT_RETESTED, ...). The UI never derives a state.
// - TriageBadge: a finding's triage status, always prefixed "Triage". It is a
//   human decision and never a comparison state.
// - SeverityBadge / ConfidenceBadge: SentinelVAPT rule-engine results.
// Class names are only built from known values; anything else is shown as
// text with a neutral style.

function known(values: readonly string[], value: string): boolean {
  return values.includes(value);
}

export function ComparisonStateBadge({ state }: { state: string }) {
  const cls = known(COMPARISON_STATES, state) ? `state state-${state}` : "state";
  return (
    <span className={cls} data-kind="comparison-state" title="Comparison state (as stored)">
      {state.toUpperCase()}
    </span>
  );
}

const TRIAGE = ["open", "confirmed", "false_positive", "accepted_risk"];

export function TriageBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="muted">—</span>;
  const cls = known(TRIAGE, status) ? `triage triage-${status}` : "triage";
  return (
    <span className={cls} data-kind="triage" title="Triage status (a human decision)">
      Triage: {humanize(status)}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = known(SEVERITIES, severity) ? `sev sev-${severity}` : "sev";
  return (
    <span className={cls} data-kind="severity" title="Severity assigned by the SentinelVAPT rule">
      {humanize(severity)}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  return (
    <span className="pill" data-kind="confidence" title="Confidence assigned by the rule">
      {humanize(confidence)}
    </span>
  );
}

const LIFECYCLE_TONE: Record<string, string> = {
  planned: "neutral",
  queued: "neutral",
  pending: "neutral",
  in_progress: "active",
  running: "active",
  generating: "active",
  active: "good",
  completed: "good",
  failed: "bad",
  cancelled: "muted",
  expired: "bad",
};

/** Lifecycle status of an assessment, scan, analysis run, report or
 *  comparison job (not a security result). */
export function StatusBadge({ status }: { status: string }) {
  const tone = LIFECYCLE_TONE[status] ?? "neutral";
  return (
    <span className={`status status-${tone}`} data-kind="status">
      {humanize(status)}
    </span>
  );
}
