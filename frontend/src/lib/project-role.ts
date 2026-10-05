import "server-only";

import { getMyMembership } from "@/lib/api/endpoints";
import { PROJECT_ROLES, type ProjectRole } from "@/lib/api/types";
import { load } from "@/lib/load";

/** The signed-in user's role in a project (GET …/membership/me, M10), for
 *  display: which tabs to offer and the "your role" label. It never
 *  authorizes anything: every request is decided by the API on its own. Any
 *  failure or unexpected value means "unknown", which the console treats like
 *  the least-privileged role, never as an owner. */
export async function myProjectRole(projectId: string): Promise<ProjectRole | null> {
  const mine = await load(() => getMyMembership(projectId));
  if (!mine.ok) return null;
  const role: unknown = mine.data?.role;
  return typeof role === "string" && (PROJECT_ROLES as readonly string[]).includes(role)
    ? (role as ProjectRole)
    : null;
}
