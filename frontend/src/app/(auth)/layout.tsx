import type { ReactNode } from "react";

/** Sign-in and password change: no console navigation, no project data. */
export default function AuthLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <div className="auth-shell">
      <main id="content" className="auth-card">
        <div className="brand auth-brand">
          <span className="brand-mark" aria-hidden="true">
            SV
          </span>
          <span>
            <strong>SentinelVAPT</strong>
            <span className="brand-sub">Operator console</span>
          </span>
        </div>
        {children}
        <p className="muted small">Authorized local lab use only.</p>
      </main>
    </div>
  );
}
