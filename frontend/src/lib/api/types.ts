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
