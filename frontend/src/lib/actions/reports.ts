"use server";

import { redirect } from "next/navigation";

import {
  createRetest,
  requestComparison,
  requestReport,
  requestRetestReport,
  triageFinding,
} from "@/lib/api/endpoints";
import type { FindingStatus, ReportCreate } from "@/lib/api/types";
import { failed, invalid, ok, optionalText, text, type ActionState } from "@/lib/actions/state";
import { assertWriteAllowed } from "@/lib/security/action-guard";
import { refresh } from "next/cache";

const FORMATS = ["json", "html", "pdf"] as const;
const KINDS = new Set(["draft", "final"]);
const CLASSIFICATIONS = new Set(["internal", "confidential", "restricted"]);
const TRIAGE = new Set<FindingStatus>(["open", "confirmed", "false_positive", "accepted_risk"]);

/** Report request fields shared by scan reports and retest reports. */
function reportFields(
  form: FormData,
  template: "sv-standard@1" | "sv-retest@1",
): Omit<ReportCreate, "scan_id"> | ActionState {
  const formats = form
    .getAll("formats")
    .filter((v): v is (typeof FORMATS)[number] => (FORMATS as readonly unknown[]).includes(v));
  if (!formats.includes("json")) return invalid("formats", "JSON is always generated.");
  const kind = text(form, "kind");
  const classification = text(form, "classification");
  if (!KINDS.has(kind)) return invalid("kind", "Choose draft or final.");
  if (!CLASSIFICATIONS.has(classification)) {
    return invalid("classification", "Choose a classification.");
  }
  return {
    template,
    kind: kind as "draft" | "final",
    formats,
    title: text(form, "title"),
    prepared_by: text(form, "prepared_by"),
    reviewed_by: optionalText(form, "reviewed_by"),
    classification: classification as "internal" | "confidential" | "restricted",
    executive_summary_note: optionalText(form, "executive_summary_note"),
    scope_note: optionalText(form, "scope_note"),
  };
}

export async function requestReportAction(
  assessmentId: string,
  _state: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const fields = reportFields(form, "sv-standard@1");
  if ("status" in fields) return fields;
  const scanId = text(form, "scan_id");
  if (!scanId) return invalid("scan_id", "Choose an analysed scan.");
  let reportId: string;
  try {
    const { data } = await requestReport(assessmentId, { ...fields, scan_id: scanId });
    reportId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/reports/${reportId}`);
}

export async function requestRetestReportAction(
  assessmentId: string,
  comparisonId: string,
  _state: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const fields = reportFields(form, "sv-retest@1");
  if ("status" in fields) return fields;
  let target: string;
  try {
    // 202: a new report was queued; 200: an identical report already exists.
    const { status, data } = await requestRetestReport(assessmentId, comparisonId, fields);
    target = `/retest-reports/${data!.id}${status === 200 ? "?existing=1" : ""}`;
  } catch (error) {
    return failed(error);
  }
  redirect(target);
}

export async function createRetestAction(
  assessmentId: string,
  _state: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  let retestId: string;
  try {
    const { data } = await createRetest(assessmentId, {
      name: text(form, "name"),
      description: optionalText(form, "description"),
      baseline_scan_id: optionalText(form, "baseline_scan_id"),
    });
    retestId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/retests/${retestId}`);
}

export async function requestComparisonAction(
  assessmentId: string,
  _state: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const scanId = text(form, "scan_id");
  if (!scanId) return invalid("scan_id", "Choose an analysed scan of this retest.");
  let target: string;
  try {
    // 202: queued now; 200: this scan was already compared.
    const { status, data } = await requestComparison(assessmentId, scanId);
    target = `/comparisons/${data!.id}${status === 200 ? "?existing=1" : ""}`;
  } catch (error) {
    return failed(error);
  }
  redirect(target);
}

export async function triageAction(
  findingId: string,
  _state: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const status = text(form, "status") as FindingStatus;
  if (!TRIAGE.has(status)) return invalid("status", "Choose a triage status.");
  try {
    await triageFinding(findingId, {
      status,
      reason: optionalText(form, "reason"),
      triaged_by: text(form, "triaged_by"),
    });
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Triage recorded. It does not change any comparison already made.");
}
