import "server-only";

export type ApiStatus = { reachable: true; version: string } | { reachable: false };

// Server-side only: the browser never learns the internal API address.
const API_INTERNAL_URL = process.env.API_INTERNAL_URL ?? "http://localhost:8000";

export async function getApiStatus(): Promise<ApiStatus> {
  try {
    const res = await fetch(`${API_INTERNAL_URL}/api/v1/health/ready`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return { reachable: false };
    const body = (await res.json()) as { version: string };
    return { reachable: true, version: body.version };
  } catch {
    return { reachable: false };
  }
}
