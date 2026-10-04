"use server";

import { refresh } from "next/cache";
import { redirect } from "next/navigation";

import { cancelScan, createAssessment, startScan, transitionAssessment } from "@/lib/api/endpoints";
import { failed, ok, optionalText, text, type ActionState } from "@/lib/actions/state";
import { assertWriteAllowed } from "@/lib/security/action-guard";

export async function createAssessmentAction(
  targetId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  let assessmentId: string;
  try {
    const { data } = await createAssessment(targetId, {
      name: text(form, "name"),
      description: optionalText(form, "description"),
    });
    assessmentId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/assessments/${assessmentId}`);
}

const TRANSITIONS = new Set(["start", "complete", "cancel"]);

export async function transitionAssessmentAction(
  assessmentId: string,
  transition: string,
  _: ActionState,
  __: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  if (!TRANSITIONS.has(transition)) return failed(null);
  try {
    const { data } = await transitionAssessment(
      assessmentId,
      transition as "start" | "complete" | "cancel",
    );
    refresh();
    return ok(`Assessment is now ${data!.status.replace("_", " ")}.`);
  } catch (error) {
    return failed(error);
  }
}

export async function startScanAction(
  assessmentId: string,
  _: ActionState,
  __: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  let scanId: string;
  try {
    const { data } = await startScan(assessmentId);
    scanId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/scans/${scanId}`);
}

export async function cancelScanAction(
  scanId: string,
  _: ActionState,
  __: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  try {
    await cancelScan(scanId);
    refresh();
    return ok("Cancellation requested. The worker stops the scan at its next check.");
  } catch (error) {
    return failed(error);
  }
}
