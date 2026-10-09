"""Phase 9 M10 frontend mutation harness (m8_mutations.py mechanics)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m8_mutations as h  # noqa: E402

ACTIONS = "src/lib/actions/admin.ts"
ROLE = "src/lib/project-role.ts"
NAV = "src/components/project-nav.tsx"
SETTINGS = "src/app/(console)/projects/[projectId]/settings/page.tsx"
USER_PAGE = "src/app/(console)/admin/users/[userId]/page.tsx"
ENDPOINTS = "src/lib/api/endpoints.ts"

A = "admin.test.tsx > "
R = A + "project role (M10) "
G = A + "enabling accounts and global roles (actions) "
P = A + "account page controls (M10) "

MUTATIONS = [
    ("01 assume owner when the role is unknown",
     [(ROLE, "    ? (role as ProjectRole)\n    : null;", '    ? (role as ProjectRole)\n    : "owner";')],
     [R + "is read from the caller's own membership"]),
    ("02 show owner tabs to every member",
     [(NAV, '  const tabs = role === "owner" ? [...TABS, ...OWNER_TABS] : TABS;', "  const tabs = [...TABS, ...OWNER_TABS];")],
     [R + "decides the project tabs"]),
    ("03 show the settings forms to non-owners",
     [(SETTINGS, '      {role !== "owner" ? (', "      {false ? (")],
     [R + "hides the settings forms"]),
    ("04 let the console's role data authorize a change",
     [(ACTIONS, "  try {\n    await updateProject(projectId, {",
       '  if ((await import("@/lib/project-role").then((m) => m.myProjectRole(projectId))) === "owner") {\n'
       '    refresh();\n    return ok("Project updated.");\n  }\n  try {\n    await updateProject(projectId, {')],
     [R + "still lets the API decide"]),
    ("05 trust a hidden form field naming the account",
     [(ACTIONS, "    await changeGlobalRole(userId, { global_role: role as GlobalRole });",
       '    await changeGlobalRole(text(form, "user_id") || userId, { global_role: role as GlobalRole });')],
     [G + "changes a global role only to a known role"]),
    ("06 enable without confirmation",
     [(ACTIONS, '  if (form.get("confirm") !== "true") {\n    return invalid("confirm", "Tick the box to confirm enabling this account.");',
       '  if (form.get("confirm") === "never") {\n    return invalid("confirm", "Tick the box to confirm enabling this account.");')],
     [G + "enables an account only when confirmed"]),
    ("07 send any global role the form names",
     [(ACTIONS, '''  const role = text(form, "global_role");
  if (!(GLOBAL_ROLES as readonly string[]).includes(role)) {
    return invalid("global_role", "Choose a global role.");
  }
  if (form.get("confirm") !== "true") {''', '''  const role = text(form, "global_role");
  if (!role) {
    return invalid("global_role", "Choose a global role.");
  }
  if (form.get("confirm") !== "true") {''')],
     [G + "changes a global role only to a known role"]),
    ("08 send a user id when asking for one's own role",
     [(ENDPOINTS, "  apiGet<T.MembershipSelf>(`/projects/${id(projectId)}/membership/me`);",
       "  apiGet<T.MembershipSelf>(`/projects/${id(projectId)}/membership/me`, { user_id: \"me\" });")],
     [R + "is read from the caller's own membership"]),
    ("09 probe an owner-only endpoint to find the role",
     [(ROLE, "  const mine = await load(() => getMyMembership(projectId));",
       "  const mine = await load(() =>\n    listMembers(projectId).then((m) => ({ role: m[0]?.role })),\n  );"),
      (ROLE, 'import { getMyMembership } from "@/lib/api/endpoints";',
       'import { getMyMembership, listMembers } from "@/lib/api/endpoints";\nvoid getMyMembership;')],
     [R + "is read from the caller's own membership", R + "never asks an owner-only endpoint"]),
    ("10 offer self-administration",
     [(USER_PAGE, "  const self = me.ok && me.data.user.id === u.id;", "  const self = me.ok && false;")],
     [P + "offers no self-administration"]),
    ("11 offer disabling for a disabled account",
     [(USER_PAGE, "      ) : u.is_active ? (", "      ) : true ? (")],
     [P + "offers re-enabling for a disabled account"]),
]

if __name__ == "__main__":
    h.MUTATIONS = MUTATIONS
    sys.exit(h.main())
