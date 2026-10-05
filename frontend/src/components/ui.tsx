import Link from "next/link";
import type { ReactNode } from "react";

import { SafeText } from "@/components/safe-text";
import type { UiError } from "@/lib/api/errors";

/** A person named in a record. Since Phase 9 M5 the API records the
 *  signed-in user who acted (`userId`) and stores their name as a label;
 *  records made before that, and names typed into a form, are self-asserted
 *  (ADR 0014). Display only: the label is never used to decide anything. */
export function Actor({
  name,
  userId,
}: {
  name: string | null | undefined;
  userId?: string | null;
}) {
  return (
    <span className="actor">
      <SafeText value={name} />{" "}
      {userId ? (
        <span className="signed-in">signed-in user</span>
      ) : (
        <span className="self-asserted">self-asserted</span>
      )}
    </span>
  );
}

export function ErrorPanel({ error }: { error: UiError }) {
  return (
    <div className="panel panel-error" role="alert" data-error-code={error.code}>
      <strong>{error.title}</strong>
      <p>
        <SafeText value={error.message} />
      </p>
      {error.reason && (
        <p className="muted small">
          Reason code: <code>{error.reason}</code>
        </p>
      )}
      {error.fieldErrors.length > 0 && (
        <ul className="small">
          {error.fieldErrors.map((fe, index) => (
            <li key={index}>
              <code>{fe.field || "request"}</code>: <SafeText value={fe.message} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warn";
}) {
  return <div className={`panel panel-${tone}`}>{children}</div>;
}

export function PageHeader({
  kicker,
  title,
  children,
}: {
  kicker?: string;
  title: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className="page-header">
      {kicker && <p className="kicker">{kicker}</p>}
      <h1>{title}</h1>
      {children && <div className="page-header-meta">{children}</div>}
    </header>
  );
}

export function Section({
  title,
  id,
  children,
  actions,
}: {
  title: ReactNode;
  id?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="section" id={id} aria-labelledby={id ? `${id}-title` : undefined}>
      <div className="section-head">
        <h2 id={id ? `${id}-title` : undefined}>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function KeyValues({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([key, value]) => (
        <div key={key} className="kv-row">
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Internal navigation to another page of this application (never to a
 *  target): the href is built from validated identifiers only. */
export function AppLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link href={href}>{children}</Link>;
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono">{children}</code>;
}
