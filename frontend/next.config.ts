import type { NextConfig } from "next";

// Static security headers for every response. The Content-Security-Policy
// (with a per-request nonce) and X-Frame-Options are set by src/proxy.ts for
// application pages; report artifacts under /artifacts/ set their own
// sandboxing headers, so those two are deliberately not set here (a second,
// stricter frame-ancestors would stop the sandboxed preview from loading).
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
