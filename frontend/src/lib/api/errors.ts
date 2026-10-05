// Maps API errors to messages a page can show (ADR 0013). Known, documented
// API errors keep their message (it is written for API clients and never
// contains internals); anything else gets a generic message so that stack
// traces, SQL errors or proxy pages can never reach the UI.

import type { FieldError } from "@/lib/api/client";

export type UiError = {
  title: string;
  message: string;
  status: number;
  code: string;
  reason: string | null;
  field: string | null;
  fieldErrors: FieldError[];
};

type ErrorLike = {
  status: number;
  code: string;
  detail: string | null;
  field?: string | null;
  reason?: string | null;
  fieldErrors?: FieldError[];
};

/** Error codes the API documents; only these may show the API's message. */
const DOCUMENTED_CODES = new Set([
  "not_found",
  "conflict",
  "validation_error",
  "invalid_state_transition",
  "target_authorization_invalid",
  "scan_not_allowed",
  "report_not_allowed",
  "retest_not_allowed",
  "comparison_not_allowed",
  "retest_report_not_allowed",
  "integrity_error",
  // Authentication and authorization (Phase 9): uniform messages that never
  // say which check failed.
  "forbidden",
  "invalid_credentials",
  "invalid_current_password",
]);

/** Plain-language explanations of the API's 409 refusal reasons. */
export const REASON_TEXT: Record<string, string> = {
  active_scan_exists: "This assessment already has a scan that is queued or running.",
  analysis_not_completed: "The scan's analysis has not completed yet.",
  assessment_not_completed: "A final report requires the assessment to be completed first.",
  assessment_not_in_progress: "Scans can only run while the assessment is in progress.",
  authorization_expired: "The target's recorded authorization has expired.",
  authorization_not_active: "The target's recorded authorization is not active.",
  authorization_not_local_lab: "Only local lab targets can be scanned.",
  authorization_superseded:
    "The target was re-authorized after this assessment was planned; create a new assessment.",
  baseline_not_analysed: "The baseline scan has not been analysed.",
  baseline_not_completed: "The baseline scan has not completed.",
  comparison_not_completed: "The comparison has not completed yet.",
  environment_not_supported: "Only local lab targets are supported.",
  inconsistent_state: "The records are in an inconsistent state; nothing was changed.",
  not_a_retest: "This assessment is not a retest.",
  parent_not_completed: "A retest requires the original assessment to be completed.",
  previous_comparison_missing: "The previous retest in this chain has not been compared yet.",
  previous_comparison_not_completed: "The previous retest's comparison has not completed yet.",
  retest_exists: "This assessment already has a live retest.",
  scan_not_completed: "The scan has not completed.",
  scope_expanded: "A retest's scope must stay within the original assessment's scope.",
  snapshot_invalid: "The data could not be frozen consistently for a report.",
};

const STATUS_TITLES: Record<number, string> = {
  401: "Sign-in failed",
  403: "Not permitted",
  404: "Not found",
  409: "Not allowed right now",
  421: "Request refused",
  422: "Check the form",
};

export function mapApiError(error: ErrorLike): UiError {
  const documented = DOCUMENTED_CODES.has(error.code) && error.status < 500;
  if (!documented) {
    const unreachable = error.code === "api_unreachable";
    return {
      title: unreachable ? "API unavailable" : "Something went wrong",
      message: unreachable
        ? "The SentinelVAPT API could not be reached. Check that the backend is running."
        : "The request could not be completed. Nothing in the response is shown here; see the backend logs.",
      status: error.status,
      code: unreachable ? "api_unreachable" : "unexpected_error",
      reason: null,
      field: null,
      fieldErrors: [],
    };
  }
  const reasonText = error.reason ? REASON_TEXT[error.reason] : undefined;
  return {
    title: STATUS_TITLES[error.status] ?? "Request failed",
    message:
      reasonText ??
      error.detail ??
      (error.code === "validation_error" ? "Some fields are invalid." : "The request was refused."),
    status: error.status,
    code: error.code,
    reason: error.reason ?? null,
    field: error.field ?? null,
    fieldErrors: error.fieldErrors ?? [],
  };
}

/** For a caught value of unknown type (Server Actions, pages). */
export function toUiError(value: unknown): UiError {
  if (value && typeof value === "object" && "status" in value && "code" in value) {
    const e = value as ErrorLike;
    if (typeof e.status === "number" && typeof e.code === "string") {
      return mapApiError({ ...e, detail: typeof e.detail === "string" ? e.detail : null });
    }
  }
  return mapApiError({ status: 500, code: "unexpected_error", detail: null });
}
