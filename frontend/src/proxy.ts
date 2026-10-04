import { NextResponse, type NextRequest } from "next/server";

import { buildCsp, generateNonce, isArtifactPath } from "@/lib/security/csp";
import { allowedHosts, checkRequest } from "@/lib/security/request-guard";

// The Next.js boundary (ADR 0013): every request must carry an allowlisted
// Host (DNS-rebinding defence) and every state-changing request a same-origin
// Origin (CSRF defence). Application pages get a fresh CSP nonce. Server
// Actions repeat the Host/Origin check themselves (lib/security/action-guard)
// so a matcher change can never silently remove it.

export function proxy(request: NextRequest): NextResponse {
  const decision = checkRequest(request.method, request.headers, allowedHosts());
  if (!decision.ok) {
    return new NextResponse(
      decision.status === 421 ? "Misdirected request.\n" : "Cross-origin request refused.\n",
      {
        status: decision.status,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    );
  }

  // Report artifacts set their own sandboxing headers (app/artifacts).
  if (isArtifactPath(request.nextUrl.pathname)) {
    return NextResponse.next();
  }

  const nonce = generateNonce();
  const csp = buildCsp(nonce, process.env.NODE_ENV === "development");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  // Everything except immutable build assets, which carry no data.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
