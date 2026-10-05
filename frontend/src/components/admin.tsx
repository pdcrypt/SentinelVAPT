import Link from "next/link";

import { SafeText } from "@/components/safe-text";
import { EmptyState, Mono } from "@/components/ui";
import { pageHref, PAGE_SIZE, type Filters } from "@/lib/admin/filters";
import { isUuid } from "@/lib/api/endpoints";
import {
  AUDIT_ACTIONS,
  AUDIT_ACTOR_TYPES,
  AUDIT_OUTCOMES,
  type AuditEvent,
  type ProjectAuditEvent,
  type UserRead,
} from "@/lib/api/types";
import { formatTime, humanize, shortId } from "@/lib/text";

// Read-only views of accounts and the audit log (Phase 9 M9). Every string
// comes from the API and is rendered with <SafeText>: React escapes it, and
// control and bidi characters are shown as markers. Links are built only
// from validated UUIDs and this application's own routes.

/** Previous / next page links. The API returns no total, so "next" is shown
 *  when this page is full. */
export function Pager({
  path,
  filters,
  offset,
  count,
}: {
  path: string;
  filters: Filters;
  offset: number;
  count: number;
}) {
  const previous = offset > 0;
  const next = count >= PAGE_SIZE;
  if (!previous && !next) return null;
  return (
    <nav className="pager" aria-label="Pages">
      {previous && (
        <Link href={pageHref(path, filters, Math.max(0, offset - PAGE_SIZE))} rel="prev">
          ← Previous
        </Link>
      )}
      <span className="muted small">
        Rows {offset + 1}–{offset + count}
      </span>
      {next && (
        <Link href={pageHref(path, filters, offset + PAGE_SIZE)} rel="next">
          Next →
        </Link>
      )}
    </nav>
  );
}

function Select({
  name,
  label,
  value,
  options,
}: {
  name: string;
  label: string;
  value: string | undefined;
  options: readonly string[];
}) {
  return (
    <div className="field">
      <label htmlFor={`filter-${name}`}>{label}</label>
      <select id={`filter-${name}`} name={name} defaultValue={value ?? ""}>
        <option value="">Any</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </div>
  );
}

function Input({
  name,
  label,
  value,
  type = "text",
}: {
  name: string;
  label: string;
  value: string | undefined;
  type?: "text" | "datetime-local";
}) {
  return (
    <div className="field">
      <label htmlFor={`filter-${name}`}>{label}</label>
      <input
        id={`filter-${name}`}
        name={name}
        type={type}
        defaultValue={value ?? ""}
        maxLength={64}
        autoComplete="off"
        spellCheck={false}
      />
    </div>
  );
}

/** Filters for an audit log: a GET form, so the filters live in the URL
 *  (they are not sensitive) and the server loads the page with them. */
export function AuditFiltersForm({
  path,
  filters,
  global,
}: {
  path: string;
  filters: Filters;
  global: boolean;
}) {
  return (
    <form method="get" action={path} className="filters" data-testid="audit-filters">
      <Select name="action" label="Action" value={filters.action} options={AUDIT_ACTIONS} />
      <Select name="outcome" label="Outcome" value={filters.outcome} options={AUDIT_OUTCOMES} />
      <Select
        name="actor_type"
        label="Actor type"
        value={filters.actor_type}
        options={AUDIT_ACTOR_TYPES}
      />
      <Input name="actor_user_id" label="Actor user ID" value={filters.actor_user_id} />
      <Input name="resource_type" label="Resource type" value={filters.resource_type} />
      <Input name="resource_id" label="Resource ID" value={filters.resource_id} />
      {global && <Input name="project_id" label="Project ID" value={filters.project_id} />}
      <Input
        name="occurred_from"
        label="From (UTC)"
        value={filters.occurred_from}
        type="datetime-local"
      />
      <Input
        name="occurred_to"
        label="To (UTC)"
        value={filters.occurred_to}
        type="datetime-local"
      />
      <div className="actions">
        <button type="submit" className="btn btn-secondary">
          Filter
        </button>
        <Link href={path} className="small">
          Clear
        </Link>
      </div>
    </form>
  );
}

/** A metadata value: the API keeps these to a small allowlisted set of keys
 *  per action; values are shown as text, never interpreted. */
function MetadataValue({ value }: { value: unknown }) {
  if (typeof value === "string") return <SafeText value={value} />;
  return <SafeText value={JSON.stringify(value)} className="mono" />;
}

export function AuditMetadata({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata);
  if (entries.length === 0) return <span className="muted">—</span>;
  return (
    <dl className="metadata">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>
            <SafeText value={key} />
          </dt>
          <dd>
            <MetadataValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Who acted, as the API recorded it (M5/M6): a user (with the label stored
 *  at the time), a worker or command, or an anonymous request. Never
 *  re-derived from the current account. */
function AuditActor({ event }: { event: ProjectAuditEvent }) {
  return (
    <span className="actor">
      <SafeText value={event.actor_label} />{" "}
      <span className="muted small">
        {event.actor_type === "user" && event.actor_user_id
          ? `user ${shortId(event.actor_user_id)}`
          : event.actor_type}
      </span>
    </span>
  );
}

export function AuditTable({
  events,
  global,
}: {
  events: (ProjectAuditEvent | AuditEvent)[];
  global: boolean;
}) {
  if (events.length === 0) return <EmptyState>No audit events match.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="audit-table">
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Outcome</th>
            {global && <th>Project</th>}
            <th>Resource</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} data-action={event.action} data-outcome={event.outcome}>
              <td className="mono small">{formatTime(event.occurred_at)}</td>
              <td>
                <AuditActor event={event} />
              </td>
              <td>
                <Mono>{event.action}</Mono>
              </td>
              <td>
                <span className={`outcome outcome-${event.outcome}`}>{event.outcome}</span>
              </td>
              {global && (
                <td>
                  {event.project_id && isUuid(event.project_id) ? (
                    <Link href={`/projects/${event.project_id}`} className="mono small">
                      {shortId(event.project_id)}
                    </Link>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              )}
              <td className="small">
                {event.resource_type ? (
                  <>
                    <SafeText value={humanize(event.resource_type)} />
                    {event.resource_id && (
                      <>
                        {" "}
                        <Mono>{shortId(event.resource_id)}</Mono>
                      </>
                    )}
                  </>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td className="small">
                <AuditMetadata metadata={event.metadata} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function UserFiltersForm({ filters }: { filters: Filters }) {
  return (
    <form method="get" action="/admin/users" className="filters" data-testid="user-filters">
      <div className="field">
        <label htmlFor="filter-active">Status</label>
        <select id="filter-active" name="active" defaultValue={filters.active ?? ""}>
          <option value="">Any</option>
          <option value="true">Active</option>
          <option value="false">Disabled</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="filter-global_role">Global role</label>
        <select id="filter-global_role" name="global_role" defaultValue={filters.global_role ?? ""}>
          <option value="">Any</option>
          <option value="user">user</option>
          <option value="admin">admin</option>
        </select>
      </div>
      <div className="actions">
        <button type="submit" className="btn btn-secondary">
          Filter
        </button>
        <Link href="/admin/users" className="small">
          Clear
        </Link>
      </div>
    </form>
  );
}

export function AccountStatus({ user }: { user: Pick<UserRead, "is_active"> }) {
  return user.is_active ? (
    <span className="status status-good">Active</span>
  ) : (
    <span className="status status-muted">Disabled</span>
  );
}

export function UsersTable({ users }: { users: UserRead[] }) {
  if (users.length === 0) return <EmptyState>No accounts match.</EmptyState>;
  return (
    <div className="table-wrap">
      <table className="table" data-testid="users-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Display name</th>
            <th>Global role</th>
            <th>Status</th>
            <th>Password change due</th>
            <th>Last sign-in (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id} data-username={user.username}>
              <td>
                {isUuid(user.id) ? (
                  <Link href={`/admin/users/${user.id}`}>
                    <SafeText value={user.username} />
                  </Link>
                ) : (
                  <SafeText value={user.username} />
                )}
              </td>
              <td>
                <SafeText value={user.display_name} />
              </td>
              <td>{user.global_role}</td>
              <td>
                <AccountStatus user={user} />
              </td>
              <td>{user.must_change_password ? "Yes" : "No"}</td>
              <td className="mono small">{formatTime(user.last_login_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
