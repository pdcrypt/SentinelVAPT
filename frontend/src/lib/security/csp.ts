// Content-Security-Policy for application pages (ADR 0013).
//
// Scripts run only with this request's nonce ('strict-dynamic' lets those
// scripts load the framework chunks they need); there is no 'unsafe-inline'
// for scripts. Next.js reads the nonce from the request's CSP header and adds
// it to its own scripts and styles. 'unsafe-eval' is added only for the
// development server, which React needs for its debugging stack traces.
//
// Report artifacts are not application pages: /artifacts/* responses carry
// the API's sandboxing CSP instead (see app/artifacts).

export const ARTIFACT_PREFIX = "/artifacts/";

export function generateNonce(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function buildCsp(nonce: string, isDev: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export function isArtifactPath(pathname: string): boolean {
  return pathname.startsWith(ARTIFACT_PREFIX);
}
