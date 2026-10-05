"use server";

import { refresh } from "next/cache";
import { redirect } from "next/navigation";

import {
  addMember,
  changeMemberRole,
  createUser,
  deleteProject,
  disableUser,
  removeMember,
  resetUserPassword,
  updateProject,
} from "@/lib/api/endpoints";
import { GLOBAL_ROLES, PROJECT_ROLES, type GlobalRole, type ProjectRole } from "@/lib/api/types";
import { failed, invalid, ok, optionalText, text, type ActionState } from "@/lib/actions/state";
import { assertWriteAllowed } from "@/lib/security/action-guard";

// Account, membership and project administration (ADR 0014; M7 API, M9
// console). Each action passes the form to the API, which decides whether the
// signed-in user may do it (user.admin, membership.manage, project.update,
// project.delete) and enforces every rule (no self-disable, an active
// administrator and a project owner always remain). Refusals are shown as the
// API gives them; nothing here works around one or claims a success the API
// did not confirm. After a change the page is reloaded from the API.
//
// Identifiers bound into these actions are validated as UUIDs before any call
// (lib/api/endpoints.ts) and are only ever path parameters: the API authorizes
// the path, so a tampered id reaches nothing the user could not reach anyway.
// No action sends an actor, a role for the caller, or any identity header.

/** The API's request bound for passwords (schemas/auth.py), not a policy. */
const MAX_PASSWORD = 1024;

/** A password field exactly as typed (never trimmed, never echoed). */
function secret(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

/** Two typed copies of a new password; the policy itself is the API's. */
function newPassword(form: FormData, name: string, confirm: string): string | ActionState {
  const value = secret(form, name);
  if (!value) return invalid(name, "Enter a password.");
  if (value.length > MAX_PASSWORD) return invalid(name, "The password is too long.");
  if (value !== secret(form, confirm)) return invalid(confirm, "The passwords do not match.");
  return value;
}

// --- accounts (global administrators) ------------------------------------------------

export async function createUserAction(_: ActionState, form: FormData): Promise<ActionState> {
  await assertWriteAllowed();
  const role = text(form, "global_role");
  if (!(GLOBAL_ROLES as readonly string[]).includes(role)) {
    return invalid("global_role", "Choose a global role.");
  }
  const password = newPassword(form, "password", "confirm_password");
  if (typeof password !== "string") return password;
  let userId: string;
  try {
    const { data } = await createUser({
      username: text(form, "username"),
      display_name: text(form, "display_name"),
      password,
      global_role: role as GlobalRole,
    });
    userId = data!.id;
  } catch (error) {
    return failed(error);
  }
  redirect(`/admin/users/${userId}?created=1`);
}

export async function disableUserAction(
  userId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  if (form.get("confirm") !== "true") {
    return invalid("confirm", "Tick the box to confirm disabling this account.");
  }
  try {
    await disableUser(userId);
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Account disabled. All of its sessions have ended.");
}

export async function resetPasswordAction(
  userId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const password = newPassword(form, "new_password", "confirm_password");
  if (typeof password !== "string") return password;
  try {
    await resetUserPassword(userId, { new_password: password });
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok(
    "Password reset. All of the user's sessions have ended, and they must choose a new " +
      "password at their next sign-in. Give them the temporary password yourself.",
  );
}

// --- project members (project owners) ------------------------------------------------

function projectRole(form: FormData): ProjectRole | null {
  const role = text(form, "role");
  return (PROJECT_ROLES as readonly string[]).includes(role) ? (role as ProjectRole) : null;
}

export async function addMemberAction(
  projectId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const role = projectRole(form);
  if (role === null) return invalid("role", "Choose a role.");
  const username = text(form, "username");
  if (!username) return invalid("username", "Enter a username.");
  try {
    await addMember(projectId, { username, role });
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Member added.");
}

export async function changeMemberRoleAction(
  projectId: string,
  userId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  const role = projectRole(form);
  if (role === null) return invalid("role", "Choose a role.");
  try {
    await changeMemberRole(projectId, userId, { role });
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Role updated.");
}

export async function removeMemberAction(
  projectId: string,
  userId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  if (form.get("confirm") !== "true") {
    return invalid("confirm", "Tick the box to confirm removing this member.");
  }
  try {
    await removeMember(projectId, userId);
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Member removed.");
}

// --- project settings (project owners) -------------------------------------------------

export async function updateProjectAction(
  projectId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  try {
    await updateProject(projectId, {
      name: text(form, "name"),
      description: optionalText(form, "description"),
    });
  } catch (error) {
    return failed(error);
  }
  refresh();
  return ok("Project updated.");
}

export async function deleteProjectAction(
  projectId: string,
  _: ActionState,
  form: FormData,
): Promise<ActionState> {
  await assertWriteAllowed();
  if (form.get("confirm") !== "true") {
    return invalid("confirm", "Tick the box to confirm deleting this project.");
  }
  try {
    await deleteProject(projectId);
  } catch (error) {
    return failed(error);
  }
  redirect("/projects");
}
