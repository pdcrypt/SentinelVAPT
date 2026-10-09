"""Phase 9 M9 mutation harness (administration console). Same mechanics as
m8_mutations.py: a mutation is CAUGHT only if a named test fails; files are
restored byte for byte and the tree is verified unchanged at the end."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m8_mutations as h  # noqa: E402

ACTIONS = "src/lib/actions/admin.ts"
COMPONENTS = "src/components/admin.tsx"
FILTERS = "src/lib/admin/filters.ts"
USERS_PAGE = "src/app/(console)/admin/users/page.tsx"
GLOBAL_AUDIT = "src/app/(console)/admin/audit/page.tsx"
MEMBERS_PAGE = "src/app/(console)/projects/[projectId]/members/page.tsx"
PROJECT_AUDIT = "src/app/(console)/projects/[projectId]/audit/page.tsx"
ACCOUNT_PAGE = "src/app/(console)/account/page.tsx"
NAV = "src/components/nav.tsx"
PAGE_ERROR = "src/components/page-error.tsx"
ERRORS = "src/lib/api/errors.ts"

A = "admin.test.tsx > "
G = "source-guards.test.ts > "

MUTATIONS = [
    ("01 show account controls without the API's user.admin answer",
     [(USERS_PAGE, "      {!users.ok ? (", "      {false && !users.ok ? (")],
     [A + "pages show anyone else the API's refusal"]),
    ("02 show member controls without the API's membership.manage answer",
     [(MEMBERS_PAGE, "      {!members.ok ? (", "      {false && !members.ok ? (")],
     [A + "pages give other members the API's 403"]),
    ("03 show the platform audit log without the API's audit.read_global answer",
     [(GLOBAL_AUDIT, "      {!events.ok ? (", "      {false && !events.ok ? (")],
     [A + "pages show the platform audit log to global administrators only"]),
    ("04 show the project audit log without the API's audit.read_project answer",
     [(PROJECT_AUDIT, "      {!events.ok ? (", "      {false && !events.ok ? (")],
     [A + "pages show other members the API's refusal of the project audit log"]),
    ("05 show administration links to everyone",
     [(NAV, "  const links = admin ? [...LINKS, ...ADMIN_LINKS] : LINKS;", "  const links = [...LINKS, ...ADMIN_LINKS];")],
     [A + "navigation shows administration links"]),
    ("06 trust a client-supplied project role",
     [(ACTIONS, "  return (PROJECT_ROLES as readonly string[]).includes(role) ? (role as ProjectRole) : null;",
       "  return role ? (role as ProjectRole) : null;")],
     [A + "membership administration (actions) refuses roles"]),
    ("07 trust a client-supplied global role",
     [(ACTIONS, '''  if (!(GLOBAL_ROLES as readonly string[]).includes(role)) {
    return invalid("global_role", "Choose a global role.");
  }
  const password''',
       '''  if (!role) {
    return invalid("global_role", "Choose a global role.");
  }
  const password''')],
     [A + "account administration (actions) checks the confirmation and the role"]),
    ("08 trust a client-supplied project id over the route",
     [(ACTIONS, "    await addMember(projectId, { username, role });",
       '    await addMember(text(form, "project_id") || projectId, { username, role });')],
     [A + "membership administration (actions) acts on the project and member of the page"]),
    ("09 let the project audit page take the project from the query",
     [(PROJECT_AUDIT, "auditFilters(await searchParams, false);", "auditFilters(await searchParams, true);")],
     [A + "pages show a project's audit log to owners, scoped by the path"]),
    ("10 echo a reset password",
     [(ACTIONS, '      "password at their next sign-in. Give them the temporary password yourself.",',
       '      "password at their next sign-in. Give them the temporary password yourself: " + password,')],
     [A + "account administration (actions) resets a password without echoing it"]),
    ("11 show the user id on the account page",
     [(ACCOUNT_PAGE, '            ["Username", <SafeText key="u" value={user.username} />],',
       '            ["Username", <SafeText key="u" value={user.username} />],\n            ["ID", user.id],')],
     [A + "pages show the account without ids"]),
    ("12 show audit session identifiers",
     [(COMPONENTS, "                <AuditMetadata metadata={event.metadata} />",
       '                <AuditMetadata metadata={event.metadata} />\n                {"session_id" in event ? String(event.session_id) : null}')],
     [A + "pages show the platform audit log to global administrators only"]),
    ("13 render audit metadata without the hostile-text treatment",
     [(COMPONENTS, '  if (typeof value === "string") return <SafeText value={value} />;', '  if (typeof value === "string") return <span>{value}</span>;')],
     [A + "pages show a project's audit log to owners", A + "audit table never renders the audit metadata"]),
    ("14 render usernames without the hostile-text treatment",
     [(COMPONENTS, "                    <SafeText value={user.username} />\n                  </Link>", "                    {user.username}\n                  </Link>"),
      (COMPONENTS, "                <SafeText value={user.display_name} />", "                {user.display_name}")],
     [A + "pages show global administrators the accounts, safely rendered"]),
    ("15 link to unvalidated account ids",
     [(COMPONENTS, "                {isUuid(user.id) ? (", "                {user.id ? (")],
     [A + "pages show global administrators the accounts, safely rendered"]),
    ("16 link to unvalidated project ids from the audit log",
     [(COMPONENTS, "{event.project_id && isUuid(event.project_id) ? (", "{event.project_id ? (")],
     [A + "pages show the platform audit log to global administrators only"]),
    ("17 turn a 404 into a visible page (no 'not found')",
     [(PAGE_ERROR, "  if (error.status === 404) notFound();", "  if (error.status === 999) notFound();")],
     [A + "pages give other members the API's 403 and no controls, and non-members 404"]),
    ("18 blur 403 into a generic failure",
     [(ERRORS, '  403: "Not permitted",\n', "")],
     [A + "pages show anyone else the API's refusal", A + "membership administration (actions) keeps 403"]),
    ("19 claim success after a last-owner refusal",
     [(ACTIONS, "    await changeMemberRole(projectId, userId, { role });\n  } catch (error) {\n    return failed(error);\n  }",
       "    await changeMemberRole(projectId, userId, { role });\n  } catch {\n    refresh();\n    return ok(\"Role updated.\");\n  }")],
     [A + "membership administration (actions) never claims success when the last owner is protected"]),
    ("20 disable accounts without confirmation",
     [(ACTIONS, '  if (form.get("confirm") !== "true") {\n    return invalid("confirm", "Tick the box to confirm disabling this account.");',
       '  if (form.get("confirm") === "never") {\n    return invalid("confirm", "Tick the box to confirm disabling this account.");')],
     [A + "account administration (actions) disables an account only when confirmed"]),
    ("21 forward unknown audit actions",
     [(FILTERS, "        if ((AUDIT_ACTIONS as readonly string[]).includes(value)) keep(name, value);", "        keep(name, value);")],
     [A + "filters refuse unknown actions"]),
    ("22 accept any page offset",
     [(FILTERS, "  return value <= MAX_OFFSET && value % PAGE_SIZE === 0 ? value : 0;", "  return value;")],
     [A + "filters refuse unknown actions"]),
    ("23 move the administration UI into browser code",
     [(COMPONENTS, 'import Link from "next/link";', '"use client";\n\nimport Link from "next/link";')],
     [G + "source tree renders the administration pages on the server only"]),
    ("24 skip the CSRF guard in a membership action",
     [(ACTIONS, '): Promise<ActionState> {\n  await assertWriteAllowed();\n  const role = projectRole(form);\n  if (role === null) return invalid("role", "Choose a role.");\n  const username',
       '): Promise<ActionState> {\n  const role = projectRole(form);\n  if (role === null) return invalid("role", "Choose a role.");\n  const username')],
     [A + "account administration (actions) is refused from another origin", G + "source tree starts every Server Action"]),
    ("25 log the temporary password",
     [(ACTIONS, '  const password = newPassword(form, "password", "confirm_password");\n  if (typeof password !== "string") return password;\n  let userId',
       '  const password = newPassword(form, "password", "confirm_password");\n  if (typeof password !== "string") return password;\n  console.info("created with", password);\n  let userId')],
     [G + "source tree never logs"]),
]

if __name__ == "__main__":
    h.MUTATIONS = MUTATIONS
    sys.exit(h.main())
