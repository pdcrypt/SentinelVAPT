import "server-only";

// The only code that talks to the SentinelVAPT API (ADR 0013). It runs on the
// Next.js server: the browser never learns API_INTERNAL_URL and never calls
// the API. Responses are parsed defensively and errors are reduced to the
// API's documented error shape ({detail, code, field, reason}); response
// bodies of unexpected errors are never kept, so they cannot reach a page.

const TIMEOUT_MS = 15_000;

function baseUrl(): string {
  return process.env.API_INTERNAL_URL ?? "http://localhost:8000";
}

export type FieldError = { field: string; message: string };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string | null,
    readonly field: string | null = null,
    readonly reason: string | null = null,
    readonly fieldErrors: FieldError[] = [],
  ) {
    super(`API error ${status} (${code})`);
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function buildPath(path: string, query?: Query): string {
  if (!path.startsWith("/") || path.includes("..") || path.includes("//")) {
    throw new Error("invalid API path");
  }
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return `/api/v1${path}${qs ? `?${qs}` : ""}`;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Turns an error response into an ApiError, keeping only the documented
 *  fields. Exported for unit tests. */
export async function toApiError(response: Response): Promise<ApiError> {
  let body: unknown = null;
  if ((response.headers.get("content-type") ?? "").includes("application/json")) {
    try {
      body = await response.json();
    } catch {
      body = null;
    }
  }
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const record = body as Record<string, unknown>;
    // FastAPI request validation: {"detail": [{"loc": [...], "msg": "..."}]}
    if (Array.isArray(record.detail)) {
      const fieldErrors = record.detail
        .filter((item): item is Record<string, unknown> => !!item && typeof item === "object")
        .map((item) => ({
          field: Array.isArray(item.loc)
            ? item.loc.filter((part) => part !== "body").join(".")
            : "",
          message: asString(item.msg) ?? "Invalid value",
        }));
      return new ApiError(response.status, "validation_error", null, null, null, fieldErrors);
    }
    const code = asString(record.code);
    if (code !== null) {
      return new ApiError(
        response.status,
        code,
        asString(record.detail),
        asString(record.field),
        asString(record.reason),
      );
    }
  }
  return new ApiError(response.status, "unexpected_response", null);
}

async function send(
  method: string,
  path: string,
  options: { query?: Query; body?: unknown } = {},
): Promise<Response> {
  const init: RequestInit = {
    method,
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { Accept: "application/json" },
  };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
    init.headers = { ...init.headers, "Content-Type": "application/json" };
  }
  let response: Response;
  try {
    response = await fetch(`${baseUrl()}${buildPath(path, options.query)}`, init);
  } catch {
    throw new ApiError(503, "api_unreachable", null);
  }
  if (!response.ok) throw await toApiError(response);
  return response;
}

export async function apiGet<T>(path: string, query?: Query): Promise<T> {
  const response = await send("GET", path, { query });
  return (await response.json()) as T;
}

/** A write; returns the parsed body and the status, so callers can tell a
 *  new resource (201/202) from an existing identical one (200). */
export async function apiWrite<T>(
  method: "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<{ status: number; data: T | null }> {
  const response = await send(method, path, { body });
  if (response.status === 204) return { status: 204, data: null };
  return { status: response.status, data: (await response.json()) as T };
}

/** A binary artifact for the /artifacts routes, with only the headers they
 *  may pass on. */
export async function apiArtifact(path: string): Promise<{ body: ArrayBuffer; headers: Headers }> {
  const response = await send("GET", path);
  return { body: await response.arrayBuffer(), headers: response.headers };
}
