import "server-only";

import { apiGet, apiWrite } from "@/lib/api/client";
import type * as T from "@/lib/api/types";

// One function per API operation the UI uses. Identifiers that go into a
// path are validated first, so a crafted route parameter can never change
// which API path is called.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FINGERPRINT = /^[0-9a-f]{64}$/; // SHA-256 hex (analysis/fingerprint.py)
export const PAGE = 100; // the API's maximum page size

export function id(value: string): string {
  if (!UUID.test(value)) throw new Error("invalid identifier");
  return value.toLowerCase();
}

export function isUuid(value: string): boolean {
  return UUID.test(value);
}

// --- authentication (ADR 0014, Phase 9 M8) ---------------------------------------------
// Sign-in is the only anonymous call. Sign-out names the session to revoke
// explicitly: by then it has already been removed from the session store.

export const login = (body: T.LoginRequest) =>
  apiWrite<T.SessionResponse>("POST", "/auth/login", body, "anonymous");
export const logout = (token: string) =>
  apiWrite<null>("POST", "/auth/logout", undefined, { token });
export const getMe = () => apiGet<T.MeResponse>("/auth/me");
export const changePassword = (body: T.PasswordChangeRequest) =>
  apiWrite<T.SessionResponse>("POST", "/auth/password", body);

// --- health ----------------------------------------------------------------------------

export const getReadiness = () => apiGet<T.HealthResponse>("/health/ready");

// --- projects and targets --------------------------------------------------------------

export const listProjects = (offset = 0) =>
  apiGet<T.Project[]>("/projects", { limit: PAGE, offset });
export const getProject = (projectId: string) => apiGet<T.Project>(`/projects/${id(projectId)}`);
export const createProject = (body: T.ProjectCreate) =>
  apiWrite<T.Project>("POST", "/projects", body);

export const listTargets = (projectId: string) =>
  apiGet<T.Target[]>(`/projects/${id(projectId)}/targets`, { limit: PAGE });
export const getTarget = (targetId: string) => apiGet<T.Target>(`/targets/${id(targetId)}`);
export const createTarget = (projectId: string, body: T.TargetCreate) =>
  apiWrite<T.Target>("POST", `/projects/${id(projectId)}/targets`, body);
export const updateTarget = (targetId: string, body: T.TargetUpdate) =>
  apiWrite<T.Target>("PATCH", `/targets/${id(targetId)}`, body);
export const listAuthorizations = (targetId: string) =>
  apiGet<T.TargetAuthorization[]>(`/targets/${id(targetId)}/authorizations`, { limit: PAGE });

// --- assessments -----------------------------------------------------------------------

export const listProjectAssessments = (projectId: string) =>
  apiGet<T.Assessment[]>(`/projects/${id(projectId)}/assessments`, { limit: PAGE });
export const listTargetAssessments = (targetId: string) =>
  apiGet<T.Assessment[]>(`/targets/${id(targetId)}/assessments`, { limit: PAGE });
export const getAssessment = (assessmentId: string) =>
  apiGet<T.Assessment>(`/assessments/${id(assessmentId)}`);
export const createAssessment = (targetId: string, body: T.AssessmentCreate) =>
  apiWrite<T.Assessment>("POST", `/targets/${id(targetId)}/assessments`, body);
export const transitionAssessment = (
  assessmentId: string,
  action: "start" | "complete" | "cancel",
) => apiWrite<T.Assessment>("POST", `/assessments/${id(assessmentId)}/${action}`);

// --- scans -----------------------------------------------------------------------------

export const listScans = (assessmentId: string) =>
  apiGet<T.Scan[]>(`/assessments/${id(assessmentId)}/scans`, { limit: PAGE });
export const getScan = (scanId: string) => apiGet<T.Scan>(`/scans/${id(scanId)}`);
export const startScan = (assessmentId: string) =>
  apiWrite<T.Scan>("POST", `/assessments/${id(assessmentId)}/scans`, {});
export const cancelScan = (scanId: string) =>
  apiWrite<T.Scan>("POST", `/scans/${id(scanId)}/cancel`);
export const listScanLogs = (scanId: string, offset = 0) =>
  apiGet<T.ScanLog[]>(`/scans/${id(scanId)}/logs`, { limit: PAGE, offset });
export const listAssets = (scanId: string) =>
  apiGet<T.Asset[]>(`/scans/${id(scanId)}/assets`, { limit: PAGE });
export const listEndpoints = (scanId: string, offset = 0) =>
  apiGet<T.Endpoint[]>(`/scans/${id(scanId)}/endpoints`, { limit: PAGE, offset });
export const listScanEvidence = (scanId: string, offset = 0) =>
  apiGet<T.Evidence[]>(`/scans/${id(scanId)}/evidence`, { limit: PAGE, offset });
export const getEvidence = (evidenceId: string) =>
  apiGet<T.Evidence>(`/evidence/${id(evidenceId)}`);
export const listAnalysisRuns = (scanId: string) =>
  apiGet<T.AnalysisRun[]>(`/scans/${id(scanId)}/analysis`);

// --- findings --------------------------------------------------------------------------

export type FindingFilters = {
  severity?: string;
  confidence?: string;
  detection_type?: string;
  category?: string;
  rule_id?: string;
  status?: string;
};

export const listFindings = (scanId: string, filters: FindingFilters = {}, offset = 0) =>
  apiGet<T.Finding[]>(`/scans/${id(scanId)}/findings`, { limit: PAGE, offset, ...filters });
export const getScanFindingSummary = (scanId: string) =>
  apiGet<T.FindingSummary>(`/scans/${id(scanId)}/findings/summary`);
export const getAssessmentFindingSummary = (assessmentId: string) =>
  apiGet<T.FindingSummary>(`/assessments/${id(assessmentId)}/findings/summary`);
export const getFinding = (findingId: string) =>
  apiGet<T.FindingDetail>(`/findings/${id(findingId)}`);
export const listFindingEvidence = (findingId: string) =>
  apiGet<T.Evidence[]>(`/findings/${id(findingId)}/evidence`);
export const listFindingHistory = (findingId: string) =>
  apiGet<T.FindingStatusChange[]>(`/findings/${id(findingId)}/history`);
export const triageFinding = (
  findingId: string,
  body: { status: T.FindingStatus; reason: string | null },
) => apiWrite<T.FindingDetail>("POST", `/findings/${id(findingId)}/triage`, body);
export const getRules = () => apiGet<T.RuleCatalog>("/rules");

// --- scan reports (Phase 5) ------------------------------------------------------------

export const listReports = (assessmentId: string) =>
  apiGet<T.Report[]>(`/assessments/${id(assessmentId)}/reports`, { limit: PAGE });
export const getReport = (reportId: string) => apiGet<T.Report>(`/reports/${id(reportId)}`);
export const requestReport = (assessmentId: string, body: T.ReportCreate) =>
  apiWrite<T.Report>("POST", `/assessments/${id(assessmentId)}/reports`, body);
export const listReportTemplates = () => apiGet<T.ReportTemplate[]>("/report-templates");

// --- retests and comparisons (Phase 6) -------------------------------------------------

export const listRetests = (assessmentId: string) =>
  apiGet<T.Assessment[]>(`/assessments/${id(assessmentId)}/retests`);
export const createRetest = (
  assessmentId: string,
  body: { name: string; description: string | null; baseline_scan_id: string | null },
) => apiWrite<T.Assessment>("POST", `/assessments/${id(assessmentId)}/retests`, body);
export const getLineage = (assessmentId: string) =>
  apiGet<T.LineageEntry[]>(`/assessments/${id(assessmentId)}/lineage`);
export const listComparisons = (assessmentId: string) =>
  apiGet<T.Comparison[]>(`/assessments/${id(assessmentId)}/comparisons`);
export const requestComparison = (assessmentId: string, scanId: string) =>
  apiWrite<T.Comparison>("POST", `/assessments/${id(assessmentId)}/comparisons`, {
    scan_id: id(scanId),
  });
export const getComparison = (comparisonId: string) =>
  apiGet<T.Comparison>(`/comparisons/${id(comparisonId)}`);
export const listComparisonRecords = (
  comparisonId: string,
  filters: { state?: string; rule_id?: string } = {},
  offset = 0,
) =>
  apiGet<T.ComparisonRecord[]>(`/comparisons/${id(comparisonId)}/records`, {
    limit: PAGE,
    offset,
    ...filters,
  });
export const getComparisonRecord = (comparisonId: string, fingerprint: string) => {
  if (!FINGERPRINT.test(fingerprint)) throw new Error("invalid fingerprint");
  return apiGet<T.ComparisonRecord>(`/comparisons/${id(comparisonId)}/records/${fingerprint}`);
};

// --- retest reports (Phase 7) ----------------------------------------------------------

export const listRetestReports = (assessmentId: string) =>
  apiGet<T.RetestReport[]>(`/assessments/${id(assessmentId)}/retest-reports`, { limit: PAGE });
export const getRetestReport = (reportId: string) =>
  apiGet<T.RetestReport>(`/retest-reports/${id(reportId)}`);
export const requestRetestReport = (
  assessmentId: string,
  comparisonId: string,
  body: T.RetestReportCreate,
) =>
  apiWrite<T.RetestReport>(
    "POST",
    `/assessments/${id(assessmentId)}/comparisons/${id(comparisonId)}/reports`,
    body,
  );

/** Fetches every page of a paginated list (bounded: at most `maxPages`). */
export async function allPages<R>(
  fetchPage: (offset: number) => Promise<R[]>,
  maxPages = 20,
): Promise<R[]> {
  const out: R[] = [];
  for (let page = 0; page < maxPages; page++) {
    const rows = await fetchPage(page * PAGE);
    out.push(...rows);
    if (rows.length < PAGE) break;
  }
  return out;
}
