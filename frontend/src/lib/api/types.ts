// Response and request types generated from the API's OpenAPI document
// (openapi/sentinelvapt.openapi.json → schema.d.ts; `npm run api:types`).
import type { components } from "@/lib/api/schema";

type S = components["schemas"];

export type Project = S["ProjectRead"];
export type ProjectCreate = S["ProjectCreate"];
export type Target = S["TargetRead"];
export type TargetCreate = S["TargetCreate"];
export type TargetUpdate = S["TargetUpdate"];
export type TargetAuthorization = S["TargetAuthorizationRead"];
export type AuthorizationIn = S["TargetAuthorizationIn"];
export type Assessment = S["AssessmentRead"];
export type AssessmentCreate = S["AssessmentCreate"];
export type Scan = S["ScanRead"];
export type ScanLog = S["ScanLogRead"];
export type Asset = S["AssetRead"];
export type Endpoint = S["EndpointRead"];
export type Evidence = S["EvidenceRead"];
export type Finding = S["FindingRead"];
export type FindingDetail = S["FindingDetail"];
export type FindingSummary = S["FindingSummary"];
export type FindingStatusChange = S["FindingStatusChangeRead"];
export type FindingStatus = S["FindingStatus"];
export type AnalysisRun = S["AnalysisRunRead"];
export type RuleCatalog = S["RuleCatalog"];
export type Report = S["ReportRead"];
export type ReportCreate = S["ReportCreate"];
export type Artifact = S["ArtifactRead"];
export type ReportTemplate = S["ReportTemplateRead"];
export type LineageEntry = S["LineageEntry"];
export type Comparison = S["ComparisonRead"];
export type ComparisonRecord = S["ComparisonRecordRead"];
export type ComparisonState = S["ComparisonState"];
export type RetestReport = S["RetestReportRead"];
export type RetestReportCreate = S["RetestReportCreate"];
export type AssessmentStatus = S["AssessmentStatus"];
export type ScanStatus = S["ScanStatus"];
export type ReportStatus = S["ReportStatus"];
export type HealthResponse = S["HealthResponse"];
export type LoginRequest = S["LoginRequest"];
export type PasswordChangeRequest = S["PasswordChangeRequest"];
export type CurrentUser = S["CurrentUser"];
export type MeResponse = S["MeResponse"];
/** Carries the API session token: server-only (lib/actions/auth.ts). */
export type SessionResponse = S["SessionResponse"];
export type ProjectUpdate = S["ProjectUpdate"];
export type GlobalRole = S["GlobalRole"];
export type ProjectRole = S["ProjectRole"];
export type UserRead = S["UserRead"];
export type UserCreate = S["UserCreate"];
export type PasswordReset = S["PasswordReset"];
export type Member = S["MemberRead"];
export type MemberAdd = S["MemberAdd"];
export type MemberUpdate = S["MemberUpdate"];
export type MembershipSelf = S["MembershipSelfRead"];
export type GlobalRoleUpdate = S["GlobalRoleUpdate"];
/** Security posture (ADR 0015): counts of persisted facts, computed by the API. */
export type ProjectPosture = S["ProjectPostureRead"];
export type ProjectPostureSummary = S["ProjectPostureSummary"];
export type FindingCounts = S["FindingCounts"];
export type ComparisonSummary = S["ComparisonSummary"];
export type ReportRef = S["ReportRef"];
export type RecentScan = S["RecentScan"];
export type TargetPosture = S["TargetPosture"];
export type AuditEvent = S["AuditEventRead"];
export type ProjectAuditEvent = S["ProjectAuditEventRead"];
export type AuditAction = S["AuditAction"];
export type AuditOutcome = S["AuditOutcome"];
export type AuditActorType = S["AuditActorType"];

export const PROJECT_ROLES: readonly ProjectRole[] = ["owner", "operator", "viewer"];
export const GLOBAL_ROLES: readonly GlobalRole[] = ["user", "admin"];
export const AUDIT_OUTCOMES: readonly AuditOutcome[] = ["success", "denied", "failure"];
export const AUDIT_ACTOR_TYPES: readonly AuditActorType[] = ["user", "system", "anonymous"];

/** The API's closed audit vocabulary (ADR 0014, M6/M7), for the filter. */
export const AUDIT_ACTIONS = [
  "auth.login",
  "auth.login_failed",
  "auth.logout",
  "auth.password_changed",
  "auth.password_change_failed",
  "auth.session_rejected",
  "auth.password_change_required",
  "user.created",
  "user.disabled",
  "user.password_reset",
  "user.change_refused",
  "user.enabled",
  "user.global_role_changed",
  "platform.auth_enforced",
  "authz.denied",
  "project.created",
  "project.updated",
  "project.deleted",
  "project.claim",
  "membership.added",
  "membership.role_changed",
  "membership.removed",
  "membership.change_refused",
  "target.created",
  "target.updated",
  "target.deleted",
  "target_authorization.created",
  "assessment.created",
  "assessment.updated",
  "assessment.deleted",
  "assessment.started",
  "assessment.start_refused",
  "assessment.completed",
  "assessment.cancelled",
  "retest.created",
  "scan.requested",
  "scan.request_refused",
  "scan.cancel_requested",
  "scan.refused",
  "scan.started",
  "scan.completed",
  "scan.cancelled",
  "scan.failed",
  "analysis.completed",
  "analysis.failed",
  "finding.triaged",
  "comparison.requested",
  "comparison.completed",
  "comparison.failed",
  "report.requested",
  "report.completed",
  "report.failed",
  "retest_report.requested",
  "retest_report.completed",
  "retest_report.failed",
] as const satisfies readonly AuditAction[];

// Compile-time check that the list above is the whole vocabulary: a new API
// action makes this line fail to type-check until it is added.
export const AUDIT_ACTIONS_COMPLETE: [AuditAction] extends [(typeof AUDIT_ACTIONS)[number]]
  ? true
  : never = true;

/** The eight persisted comparison states (comparison policy cmp-1), in the
 *  order the retest report presents them. Display only: the UI never
 *  derives a state. */
export const COMPARISON_STATES: readonly ComparisonState[] = [
  "new",
  "reopened",
  "still_open",
  "unchanged",
  "fixed",
  "dismissed",
  "not_retested",
  "not_comparable",
];

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
