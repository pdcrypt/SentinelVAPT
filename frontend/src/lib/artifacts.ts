import "server-only";

import { ApiError, apiArtifact } from "@/lib/api/client";
import { isUuid } from "@/lib/api/endpoints";
import { authRedirect } from "@/lib/auth/paths";

// Report artifacts, passed from the API to the browser under the same origin
// as the UI, so the browser never calls the API (ADR 0013). Only an allowlist
// of upstream headers is forwarded.
//
// - Downloads are always attachments (never rendered by the browser), with
//   the API's sandboxing CSP.
// - Previews are HTML rendered only inside <iframe sandbox="">: the API's
//   CSP (which must contain "sandbox") is kept, and framing is limited to
//   this origin.

export type ArtifactKind = "reports" | "retest-reports";
export const FORMATS = new Set(["json", "html", "pdf"]);

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function plain(status: number, message: string): Response {
  return new Response(`${message}\n`, {
    status,
    headers: {
      ...BASE_HEADERS,
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; sandbox",
    },
  });
}

function failure(error: unknown): Response {
  const to = authRedirect(error);
  if (to !== null) {
    return new Response(null, { status: 303, headers: { ...BASE_HEADERS, Location: to } });
  }
  if (error instanceof ApiError && error.status === 404) return plain(404, "Not found.");
  if (error instanceof ApiError && error.status === 403) {
    return plain(403, "You do not have permission to do this.");
  }
  if (error instanceof ApiError && error.status === 409) {
    return plain(409, "This report has no artifacts yet.");
  }
  return plain(502, "The artifact could not be retrieved.");
}

export async function downloadArtifact(
  kind: ArtifactKind,
  reportId: string,
  fmt: string,
): Promise<Response> {
  if (!isUuid(reportId) || !FORMATS.has(fmt)) return plain(404, "Not found.");
  try {
    const { body, headers } = await apiArtifact(
      `/${kind}/${reportId.toLowerCase()}/artifacts/${fmt}`,
    );
    const disposition = headers.get("content-disposition") ?? "";
    return new Response(body, {
      status: 200,
      headers: {
        ...BASE_HEADERS,
        "Content-Type": headers.get("content-type") ?? "application/octet-stream",
        // Never inline: a downloaded artifact is not rendered by the browser.
        "Content-Disposition": disposition.toLowerCase().startsWith("attachment")
          ? disposition
          : `attachment; filename="report.${fmt}"`,
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Frame-Options": "DENY",
        ETag: headers.get("etag") ?? "",
      },
    });
  } catch (error) {
    return failure(error);
  }
}

export async function previewArtifact(kind: ArtifactKind, reportId: string): Promise<Response> {
  if (!isUuid(reportId)) return plain(404, "Not found.");
  try {
    const { body, headers } = await apiArtifact(`/${kind}/${reportId.toLowerCase()}/preview`);
    const csp = headers.get("content-security-policy") ?? "";
    const directives = csp.split(";").map((d) => d.trim().toLowerCase());
    if (!directives.includes("sandbox")) {
      // Fail closed: never serve report HTML without the sandbox directive.
      return plain(502, "The preview could not be served safely.");
    }
    return new Response(body, {
      status: 200,
      headers: {
        ...BASE_HEADERS,
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": "inline",
        "Content-Security-Policy": csp,
        "X-Frame-Options": "SAMEORIGIN",
        ETag: headers.get("etag") ?? "",
      },
    });
  } catch (error) {
    return failure(error);
  }
}
