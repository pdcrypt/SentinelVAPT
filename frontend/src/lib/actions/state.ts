// Result of a Server Action, rendered by <ActionForm>. Never contains raw
// API responses: errors go through mapApiError (lib/api/errors.ts).
import { redirect } from "next/navigation";

import { mapApiError, toUiError, type UiError } from "@/lib/api/errors";
import { authRedirect } from "@/lib/auth/paths";

export type ActionState =
  { status: "idle" } | { status: "ok"; message: string } | { status: "error"; error: UiError };

export const IDLE: ActionState = { status: "idle" };

export function ok(message: string): ActionState {
  return { status: "ok", message };
}

/** A failed API call. If the session ended (401) or a password change is
 *  due, the browser is sent there instead of seeing an error. */
export function failed(error: unknown): ActionState {
  const to = authRedirect(error);
  if (to !== null) redirect(to);
  return { status: "error", error: toUiError(error) };
}

/** A problem found in the form before anything was sent to the API. */
export function invalid(field: string, message: string): ActionState {
  return {
    status: "error",
    error: mapApiError({
      status: 422,
      code: "validation_error",
      detail: null,
      fieldErrors: [{ field, message }],
    }),
  };
}

export function text(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value.trim() : "";
}

export function optionalText(form: FormData, name: string): string | null {
  const value = text(form, name);
  return value === "" ? null : value;
}

/** A list typed as comma-, space- or newline-separated values. */
export function list(form: FormData, name: string): string[] {
  return text(form, name)
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

/** A <input type="datetime-local"> value, interpreted as UTC (the form says
 *  so), as an ISO-8601 string; null if it is not a valid date. */
export function utcDateTime(form: FormData, name: string): string | null {
  const value = text(form, name);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null;
  const date = new Date(`${value.length === 16 ? `${value}:00` : value}Z`);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** "YYYY-MM-DDTHH:MM" in UTC, for datetime-local default values. */
export function toDateTimeLocal(date: Date): string {
  return date.toISOString().slice(0, 16);
}
