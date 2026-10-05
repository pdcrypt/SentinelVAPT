import Link from "next/link";

// The sections of one project. Every member sees every link: the console does
// not know the user's role in the project, and asking an owner-only endpoint
// just to hide a link would record a refusal in the audit log on every visit.
// The pages themselves load their data from the API, which shows owners the
// members, audit log and settings, and everyone else its refusal.

const TABS = [
  ["", "Overview"],
  ["/targets", "Targets"],
  ["/assessments", "Assessments"],
  ["/members", "Members"],
  ["/audit", "Audit log"],
  ["/settings", "Settings"],
] as const;

export function ProjectNav({ projectId, current }: { projectId: string; current: string }) {
  return (
    <nav aria-label="Project" className="tabs project-nav">
      {TABS.map(([suffix, label]) => (
        <Link
          key={suffix}
          href={`/projects/${projectId}${suffix}`}
          aria-current={suffix === current ? "page" : undefined}
        >
          {label}
        </Link>
      ))}
    </nav>
  );
}
