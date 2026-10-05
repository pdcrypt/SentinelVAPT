import Link from "next/link";

import type { ProjectRole } from "@/lib/api/types";

// The sections of one project, by the signed-in user's role in it (from
// GET …/membership/me, M10, which reveals nothing about anyone else and
// records nothing). Owners get the administration tabs; operators and viewers
// do not, so no one is offered a page the API would refuse them. This is
// navigation only: the API still decides every request, and a direct visit to
// an owner page by anyone else shows the API's refusal. An unknown role is
// treated as the least privileged, never as an owner.

const TABS = [
  ["", "Overview"],
  ["/targets", "Targets"],
  ["/assessments", "Assessments"],
] as const;
const OWNER_TABS = [
  ["/members", "Members"],
  ["/audit", "Audit log"],
  ["/settings", "Settings"],
] as const;

export const ROLE_NAMES: Record<ProjectRole, string> = {
  owner: "Owner",
  operator: "Operator",
  viewer: "Viewer",
};

export function ProjectNav({
  projectId,
  current,
  role,
}: {
  projectId: string;
  current: string;
  role: ProjectRole | null;
}) {
  const tabs = role === "owner" ? [...TABS, ...OWNER_TABS] : TABS;
  return (
    <nav aria-label="Project" className="project-nav">
      {tabs.map(([suffix, label]) => (
        <Link
          key={suffix}
          href={`/projects/${projectId}${suffix}`}
          aria-current={suffix === current ? "page" : undefined}
        >
          {label}
        </Link>
      ))}
      <span className="project-role" data-testid="project-role">
        Your role: {role ? ROLE_NAMES[role] : "unknown"}
      </span>
    </nav>
  );
}
