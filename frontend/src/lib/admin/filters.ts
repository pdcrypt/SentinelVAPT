// Search parameters of the administration pages (Phase 9 M9), turned into the
// query the API accepts. Pure functions, unit-tested directly.
//
// Only known parameters with well-formed values are passed on; anything else
// is dropped, so a crafted URL can neither add API parameters nor smuggle a
// value past the form. The API validates everything again and decides what
// the caller may see: these filters narrow a result, they never widen access.

import { utcDateTimeValue } from "@/lib/actions/state";
import { AUDIT_ACTIONS, AUDIT_ACTOR_TYPES, AUDIT_OUTCOMES, GLOBAL_ROLES } from "@/lib/api/types";

export const PAGE_SIZE = 50;
/** Deep paging has no use here and only costs the database. */
export const MAX_OFFSET = 10_000;

type Params = Record<string, string | string[] | undefined>;
type Query = Record<string, string | number | boolean>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RESOURCE_TYPE = /^[a-z_]{1,32}$/; // the API's own pattern
const DATETIME_LOCAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;

function one(params: Params, name: string): string {
  const value = params[name];
  return (Array.isArray(value) ? value[0] : value)?.trim() ?? "";
}

/** The page offset: a multiple of the page size within bounds, else 0. */
export function offsetOf(params: Params): number {
  const raw = one(params, "offset");
  if (!/^\d{1,6}$/.test(raw)) return 0;
  const value = Number(raw);
  return value <= MAX_OFFSET && value % PAGE_SIZE === 0 ? value : 0;
}

export type Filters = Record<string, string>;
export type Parsed = { filters: Filters; query: Query; offset: number };

const AUDIT_FIELDS = [
  "action",
  "outcome",
  "actor_type",
  "actor_user_id",
  "resource_type",
  "resource_id",
  "occurred_from",
  "occurred_to",
] as const;

/** Audit log filters. `global` adds the project filter of the global log;
 *  a project's own log is always scoped by its path. */
export function auditFilters(params: Params, global: boolean): Parsed {
  const filters: Filters = {};
  const query: Query = {};
  const keep = (name: string, value: string, sent: string | null = value) => {
    if (sent === null) return;
    filters[name] = value;
    query[name] = sent;
  };
  for (const name of global ? [...AUDIT_FIELDS, "project_id"] : AUDIT_FIELDS) {
    const value = one(params, name);
    if (!value) continue;
    switch (name) {
      case "action":
        if ((AUDIT_ACTIONS as readonly string[]).includes(value)) keep(name, value);
        break;
      case "outcome":
        if ((AUDIT_OUTCOMES as readonly string[]).includes(value)) keep(name, value);
        break;
      case "actor_type":
        if ((AUDIT_ACTOR_TYPES as readonly string[]).includes(value)) keep(name, value);
        break;
      case "actor_user_id":
      case "resource_id":
      case "project_id":
        if (UUID.test(value)) keep(name, value.toLowerCase());
        break;
      case "resource_type":
        if (RESOURCE_TYPE.test(value)) keep(name, value);
        break;
      case "occurred_from":
      case "occurred_to":
        if (DATETIME_LOCAL.test(value)) keep(name, value, utcDateTimeValue(value));
        break;
    }
  }
  const offset = offsetOf(params);
  return { filters, query: { ...query, limit: PAGE_SIZE, offset }, offset };
}

/** Account list filters. */
export function userFilters(params: Params): Parsed {
  const filters: Filters = {};
  const query: Query = {};
  const active = one(params, "active");
  if (active === "true" || active === "false") {
    filters.active = active;
    query.active = active === "true";
  }
  const role = one(params, "global_role");
  if ((GLOBAL_ROLES as readonly string[]).includes(role)) {
    filters.global_role = role;
    query.global_role = role;
  }
  const offset = offsetOf(params);
  return { filters, query: { ...query, limit: PAGE_SIZE, offset }, offset };
}

/** A link to another page of the same list, keeping the filters. `path` is
 *  always one of this application's own routes. */
export function pageHref(path: string, filters: Filters, offset: number): string {
  const params = new URLSearchParams(filters);
  if (offset > 0) params.set("offset", String(offset));
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}
