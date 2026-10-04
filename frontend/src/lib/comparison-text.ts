// Explanations of comparison states and reason codes (comparison policy
// cmp-1), worded as in the sv-retest@1 retest report. Documentation only: the
// UI displays the state and reasons the API stored and never derives them.

import type { ComparisonState } from "@/lib/api/types";

export const STATE_TEXT: Record<ComparisonState, string> = {
  new: "Present in the retest scan with no finding of the same identity in the baseline scan.",
  reopened: "Present again after an earlier comparison in this retest chain recorded it as fixed.",
  still_open: "Present in both scans with a meaningful difference (see the reasons).",
  unchanged: "Present in both scans with no meaningful difference.",
  fixed:
    "Absent from the retest scan, and the same rule version examined the subject and found the condition absent. The retest evidence showing the examination is listed.",
  dismissed:
    "Triaged as a false positive at comparison time and absent from the retest scan. Dismissed is not fixed: this is not a remediation result.",
  not_retested:
    "Absent from the retest scan because the retest did not examine the subject. Unverified, not a remediation result: the issue may still exist.",
  not_comparable:
    "Absent from the retest scan where the analysis context does not allow a safe comparison. Unverified, not a remediation result: the issue may still exist.",
};

export const REASON_TEXT: Record<string, string> = {
  first_observed: "Not seen earlier in this retest chain.",
  previously_fixed: "Recorded as fixed by an earlier comparison in this retest chain.",
  previously_dismissed: "Previously dismissed (triaged as a false positive) in this retest chain.",
  previously_not_retested: "Previously not retested in this retest chain.",
  previously_not_comparable: "Previously not comparable in this retest chain.",
  previously_observed: "Previously observed in this retest chain.",
  rule_version_changed: "The rule version differs between the baseline and the retest analysis.",
  severity_changed: "The severity changed.",
  confidence_changed: "The confidence changed.",
  detection_type_changed: "The detection type changed.",
  details_changed: "Meaningful finding details changed.",
  baseline_false_positive: "The baseline finding was triaged as a false positive when compared.",
  examined_condition_absent:
    "The retest examined the subject with the same rule version and found the condition absent.",
  subject_not_observed: "The retest scan did not examine this subject.",
  out_of_scope: "The subject lies outside the retest's authorized scope.",
  rule_not_evaluated: "The rule was not evaluated in the retest analysis.",
  rule_error: "The rule failed during the retest analysis.",
  coverage_unavailable: "No coverage definition exists for the rule version used in the retest.",
  partial_scan: "The retest scan stopped before completing its crawl.",
  tls_trust_not_evaluated:
    "The retest accepted untrusted TLS, so certificate trust was not evaluated.",
  observations_truncated: "The retest produced more observations than the analysis limits allow.",
};

/** States whose result is not a verified remediation. */
export const UNVERIFIED_STATES: readonly ComparisonState[] = ["not_retested", "not_comparable"];
