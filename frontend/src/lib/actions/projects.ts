"use server";

import { redirect } from "next/navigation";

import { createProject, createTarget, updateTarget } from "@/lib/api/endpoints";
import type { AuthorizationIn } from "@/lib/api/types";
import {
  failed,
  invalid,
  list,
  optionalText,
  text,
  utcDateTime,
  type ActionState,
} from "@/lib/actions/state";
import { assertWriteAllowed } from "@/lib/security/action-guard";

export async function createProjectAction(_: ActionState, form: FormData): Promise<ActionState> {
  await assertWriteAllowed();
  let projectId: string;
  try {
    const { data } = await createProject({
      name: text(form, "name"),
      description: optionalText(form, "description"),
    });
    projectId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/projects/${projectId}`);
}

/** The authorization block shared by target creation and re-authorization.
 *  The platform records it; it cannot verify it (ADR 0005). */
function authorization(form: FormData): AuthorizationIn | ActionState {
  const validFrom = utcDateTime(form, "valid_from");
  const validUntil = utcDateTime(form, "valid_until");
  if (validFrom === null)
    return invalid("authorization.valid_from", "Enter a valid date and time.");
  if (validUntil === null) {
    return invalid("authorization.valid_until", "Enter a valid date and time.");
  }
  return {
    authorized_by: text(form, "authorized_by"),
    reference: text(form, "reference"),
    notes: optionalText(form, "notes"),
    valid_from: validFrom,
    valid_until: validUntil,
    acknowledge: form.get("acknowledge") === "true",
  };
}

function ports(form: FormData): number[] | null | "invalid" {
  const values = list(form, "allowed_ports");
  if (values.length === 0) return null;
  if (!values.every((v) => /^\d{1,5}$/.test(v))) return "invalid";
  return values.map(Number);
}

export async function createTargetAction(
  projectId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const auth = authorization(form);
  if ("status" in auth) return auth;
  const allowedPorts = ports(form);
  if (allowedPorts === "invalid") return invalid("allowed_ports", "Ports must be numbers.");
  const prefixes = list(form, "in_scope_path_prefixes");
  let targetId: string;
  try {
    const { data } = await createTarget(projectId, {
      name: text(form, "name"),
      base_url: text(form, "base_url"),
      // Only local lab targets can be scanned; this console creates no others.
      environment: "local_lab",
      in_scope_hosts: list(form, "in_scope_hosts"),
      allowed_ports: allowedPorts,
      // Omitted when blank, so the API applies its default ("/").
      ...(prefixes.length > 0 ? { in_scope_path_prefixes: prefixes } : {}),
      excluded_paths: list(form, "excluded_paths"),
      authorization: auth,
    });
    targetId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/targets/${targetId}`);
}

export async function reauthorizeTargetAction(
  targetId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const auth = authorization(form);
  if ("status" in auth) return auth;
  try {
    await updateTarget(targetId, { authorization: auth });
  } catch (error) {
    return failed(error);
  }
  redirect(`/targets/${targetId}`);
}
