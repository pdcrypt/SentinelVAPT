import type { Metadata } from "next";
import { connection } from "next/server";
import type { ReactNode } from "react";

import { Nav } from "@/components/nav";
import { getApiStatus } from "@/lib/api/health";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "SentinelVAPT", template: "%s · SentinelVAPT" },
  description: "Authorized web application security assessment and reporting",
  robots: { index: false, follow: false },
};

async function ApiStatus() {
  const status = await getApiStatus();
  return (
    <span className="api-status" data-testid="api-status">
      API:{" "}
      {status.reachable ? (
        <span className="ok">online (v{status.version})</span>
      ) : (
        <span className="bad">unavailable</span>
      )}
    </span>
  );
}

export default async function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  // Every page renders per request: the CSP nonce is per request (ADR 0013)
  // and all data is live API state.
  await connection();
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#content">
          Skip to content
        </a>
        <div className="shell">
          <aside className="sidebar">
            <div className="brand">
              <span className="brand-mark" aria-hidden="true">
                SV
              </span>
              <span>
                <strong>SentinelVAPT</strong>
                <span className="brand-sub">Operator console</span>
              </span>
            </div>
            <Nav />
            <p className="sidebar-note">
              Localhost-only · no platform login yet · names you enter are self-asserted.
            </p>
          </aside>
          <div className="main">
            <div className="topbar" role="region" aria-label="Environment">
              <span className="scope-banner">
                Authorized local lab use only. Passive, non-destructive checks.
              </span>
              <ApiStatus />
            </div>
            <main id="content" className="content">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
