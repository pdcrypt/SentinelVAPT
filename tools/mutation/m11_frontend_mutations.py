"""M11 frontend mutation harness (m8_mutations.py mechanics)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m8_mutations as h  # noqa: E402

POSTURE = "src/components/posture.tsx"
PROJECT = "src/app/(console)/projects/[projectId]/page.tsx"
HOME = "src/app/(console)/page.tsx"

P = "posture.test.tsx > "

MUTATIONS = [
    ("01 assume owner when the posture says nothing",
     [(PROJECT, "  const role = posture.ok ? posture.data.role : null;", '  const role = posture.ok ? posture.data.role ?? "owner" : "owner";')],
     [P + "project dashboard offers owner tabs only when the API says owner"]),
    ("02 calculate 'open' in the console",
     [(POSTURE, '<dd data-testid="count-open">{findings.open}</dd>', '<dd data-testid="count-open">{findings.by_status.open}</dd>')],
     [P + "project dashboard renders the API's posture"]),
    ("03 calculate a comparison state in the console",
     [(POSTURE, "            <tr key={state} data-key={state} data-value={n}>",
       '            <tr key={state} data-key={state} data-value={state === "fixed" ? n + (comparison.by_state.dismissed ?? 0) : n}>')],
     [P + "project dashboard renders the API's posture"]),
    ("04 display a project the API did not return",
     [(HOME, "            <PostureOverview projects={posture.data} />",
       "            <PostureOverview projects={posture.data} />\n"
       "            {(await searchParams).project_id ? <a href={`/projects/${(await searchParams).project_id}`}>project</a> : null}")],
     [P + "cross-project overview filters nothing and adds nothing"]),
    ("05 pick the latest scan in the console",
     [(POSTURE, "        <TargetsPosture targets={posture.targets} truncated={posture.targets_truncated} />",
       "        <TargetsPosture targets={posture.targets.map((t) => ({ ...t, latest_scan: t.latest_scan && "
       "{ ...t.latest_scan, scan_id: posture.recent_scans.find((r) => r.analysed && r.target_id === t.target_id)?.scan_id ?? t.latest_scan.scan_id } }))} truncated={posture.targets_truncated} />")],
     [P + "project dashboard renders the API's posture"]),
    ("06 render project names without the hostile-text treatment",
     [(POSTURE, '<td>{idLink("/projects", p.project_id, <SafeText value={p.project_name} />)}</td>',
       '<td>{idLink("/projects", p.project_id, <span>{p.project_name}</span>)}</td>')],
     [P + "cross-project overview shows exactly the projects the API returned"]),
    ("07 fan out instead of using the posture summary",
     [(HOME, "  const posture = await load(() => listPosture(offset));",
       "  const posture = await load(async () => {\n"
       '    const { listProjects } = await import("@/lib/api/endpoints");\n'
       "    await listProjects();\n"
       "    return listPosture(offset);\n"
       "  });")],
     [P + "cross-project overview shows exactly the projects the API returned"]),
]

if __name__ == "__main__":
    h.MUTATIONS = MUTATIONS
    sys.exit(h.main())
