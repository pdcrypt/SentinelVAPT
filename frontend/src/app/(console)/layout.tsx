import type { ReactNode } from "react";

import { Nav } from "@/components/nav";
import { UserMenu } from "@/components/user-menu";
import { getApiStatus } from "@/lib/api/health";
import { requireUser } from "@/lib/auth/user";

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

/** Every console page requires a signed-in user whose password is current
 *  (ADR 0014, Phase 9 M8). Checked with the API on the server before anything
 *  renders; without a session the browser goes to the sign-in page. Which
 *  projects and records the user may see is still decided by the API on
 *  every request, never here. */
export default async function ConsoleLayout({ children }: Readonly<{ children: ReactNode }>) {
  const user = await requireUser();
  return (
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
        <p className="sidebar-note">Localhost-only · you see the projects you are a member of.</p>
      </aside>
      <div className="main">
        <div className="topbar" role="region" aria-label="Environment">
          <span className="scope-banner">
            Authorized local lab use only. Passive, non-destructive checks.
          </span>
          <span className="topbar-end">
            <ApiStatus />
            <UserMenu user={user} />
          </span>
        </div>
        <main id="content" className="content">
          {children}
        </main>
      </div>
    </div>
  );
}
