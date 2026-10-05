import "server-only";

import { redirect } from "next/navigation";

import { mapApiError, toUiError, type UiError } from "@/lib/api/errors";
import { authRedirect } from "@/lib/auth/paths";

export type Loaded<T> = { ok: true; data: T } | { ok: false; error: UiError };

/** Runs an API read for a page and turns any failure into a UiError the page
 *  renders with <ErrorPanel> (never the raw error). */
export async function load<T>(read: () => Promise<T>): Promise<Loaded<T>> {
  try {
    return { ok: true, data: await read() };
  } catch (error) {
    // The session ended or a password change is due: no page renders.
    const to = authRedirect(error);
    if (to !== null) redirect(to);
    if (error instanceof Error && /^invalid (identifier|fingerprint)$/.test(error.message)) {
      return {
        ok: false,
        error: mapApiError({ status: 404, code: "not_found", detail: "Not found." }),
      };
    }
    return { ok: false, error: toUiError(error) };
  }
}

/** Search-parameter value as a single string (Next passes string | string[]). */
export function param(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
