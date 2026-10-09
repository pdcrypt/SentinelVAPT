"""Phase 9 M8 mutation harness: each mutation weakens one browser-session
security control; it is CAUGHT only if a named test fails. Files are restored
after every mutation and the tree is verified unchanged at the end."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "frontend")
os.chdir(ROOT)

COOKIE = "src/lib/auth/cookie.ts"
PATHS = "src/lib/auth/paths.ts"
STORE = "src/lib/auth/store.ts"
SESSION = "src/lib/auth/session.ts"
USER = "src/lib/auth/user.ts"
ACTIONS = "src/lib/actions/auth.ts"
CLIENT = "src/lib/api/client.ts"
END = "src/app/session/end/route.ts"
GUARD = "src/lib/security/request-guard.ts"
ACTION_GUARD = "src/lib/security/action-guard.ts"
CSP = "src/lib/security/csp.ts"
LOAD = "src/lib/load.ts"
STATE = "src/lib/actions/state.ts"
ARTIFACTS = "src/lib/artifacts.ts"
ERRORS = "src/lib/api/errors.ts"
FORM = "src/components/action-form.tsx"
NAV = "src/components/nav.tsx"

CORE = "auth-core.test.ts > "
FLOWS = "auth-flows.test.ts > "
GUARDS = "source-guards.test.ts > "
REQ = "request-guard.test.ts > "

MUTATIONS = [
    ("01 remove HttpOnly", [(COOKIE, "    httpOnly: true,\n    secure,", "    httpOnly: false as true,\n    secure,")],
     [CORE + "session cookie is HttpOnly", FLOWS + "sign-in keeps the API token on the server"]),
    ("02 remove Secure in production", [(COOKIE, 'if (env.NODE_ENV === "production") return true;', 'if (env.NODE_ENV === "production") return false;')],
     [CORE + "session cookie is always Secure in production"]),
    ("03 weaken SameSite to Lax", [(COOKIE, '    sameSite: "strict",', '    sameSite: "lax" as "strict",')],
     [CORE + "session cookie is HttpOnly", FLOWS + "sign-in keeps the API token on the server"]),
    ("04 put the bearer token in the browser cookie", [(SESSION, "  jar.set(cookieName(secure), id, cookieOptions(secure, expiry, new Date()));",
      "  void id;\n  jar.set(cookieName(secure), token, cookieOptions(secure, expiry, new Date()));")],
     [FLOWS + "sign-in keeps the API token on the server"]),
    ("05 expose the whole API user (ids) to pages", [(USER, "  return {\n    username: user.username,", "  return {\n    ...user,\n    username: user.username,")],
     [FLOWS + "protected pages learn only what they display"]),
    ("06 bypass the protected-route redirect (proxy)", [(PATHS, "  if (hasSessionCookie || isPublicPath(pathname)) return { ok: true };", "  return { ok: true };")],
     [CORE + "protected routes sends page loads", FLOWS + "proxy redirects page loads"]),
    ("07 make every path public", [(PATHS, "    PUBLIC_PATHS.has(pathname) || FRAMEWORK_PREFIXES", "    pathname.startsWith(\"/\") || FRAMEWORK_PREFIXES")],
     [CORE + "protected routes leaves only"]),
    ("08 bypass CSRF in Server Actions", [(ACTION_GUARD, "  if (!decision.ok) throw new WriteRefusedError(decision.reason);", "  void decision;")],
     [FLOWS + "sign-in is refused from another origin"]),
    ("09 accept an invalid Origin", [(GUARD, "  return origin.toLowerCase() === `http://${host.trim().toLowerCase()}`;", "  return origin.length > 0;")],
     [REQ, FLOWS + "sign-in is refused from another origin"]),
    ("10 skip the backend logout", [(ACTIONS, "  if (token !== null) await revoke(token);\n  redirect(LOGIN_PATH);", "  void token;\n  redirect(LOGIN_PATH);")],
     [FLOWS + "sign-out revokes the API session"]),
    ("11 keep sessions the API rejected (401)", [(CLIENT, "    if (auth === \"session\" && error.status === 401) await forgetCurrentSession();\n", "")],
     [FLOWS + "authenticated API client forgets a session", FLOWS + "protected pages require a live API session"]),
    ("12 never expire stored sessions", [(STORE, "    if (entry.expiresAt <= this.now()) {", "    if (entry.expiresAt < 0) {")],
     [CORE + "session store forgets a session at its absolute expiry"]),
    ("13 let must-change-password users into normal pages", [(USER, "  if (user.must_change_password && !options.allowPasswordChange) redirect(PASSWORD_PATH);", "")],
     [FLOWS + "protected pages keep a user who must change their password"]),
    ("14 ignore the API's password_change_required", [(PATHS, '  if (status === 403 && code === "password_change_required") return PASSWORD_PATH;\n', "")],
     [CORE + "protected routes maps only", FLOWS + "protected pages turn an ended session"]),
    ("15 store the token in browser storage", [(FORM, "  const [state, formAction, pending] = useActionState(action, IDLE);",
      "  const [state, formAction, pending] = useActionState(action, IDLE);\n  if (typeof window !== \"undefined\") window.localStorage.setItem(\"sv\", \"token\");")],
     [GUARDS + "source tree never keeps anything in browser storage"]),
    ("16 call the API directly from browser code", [(NAV, 'import Link from "next/link";', 'import Link from "next/link";\n\nexport const probe = () => fetch("http://localhost:8000/api/v1/auth/me");')],
     [GUARDS + "source tree only the server talks to the API"]),
    ("17 let browser scripts connect anywhere (CSP)", [(CSP, '    "connect-src \'self\'",', '    "connect-src *",')],
     [REQ + "proxy sets a fresh nonce CSP"]),
    ("18 adopt the browser's cookie on sign-in (fixation)", [(SESSION, "  const previous = sessionStore().delete(jar.get(cookieName(secure))?.value);\n  const expiry",
      "  const previous = sessionStore().get(jar.get(cookieName(secure))?.value);\n  const expiry")],
     [FLOWS + "sign-in never adopts the browser's cookie"]),
    ("19 keep the session a sign-in replaced", [(ACTIONS, "    if (replaced !== null) await revoke(replaced);\n", "")],
     [FLOWS + "sign-in never adopts the browser's cookie"]),
    ("20 tell failed sign-ins apart", [(ACTIONS, "    if (error instanceof ApiError && (error.status === 401 || error.status === 422)) {",
      "    if (error instanceof ApiError && error.status === 401) {")],
     [FLOWS + "sign-in gives every failed sign-in the same answer"]),
    ("21 trim passwords", [(ACTIONS, '  return typeof value === "string" ? value : "";', '  return typeof value === "string" ? value.trim() : "";')],
     [FLOWS + "sign-in never trims a password"]),
    ("22 let /session/end end a live session", [(END, "  if (id !== undefined && sessionStore().get(id) !== null) {", "  if (id === \"never\") {")],
     [FLOWS + "/session/end never ends a live session"]),
    ("23 keep the old session after a password change", [(ACTIONS, "    await startSession(data.token, data.session.expires_at);\n  } catch (error) {\n    return failed(error);",
      "    void data;\n  } catch (error) {\n    return failed(error);")],
     [FLOWS + "password change replaces the browser session"]),
    ("24 render pages after the session ended", [(LOAD, "    if (to !== null) redirect(to);\n", "")],
     [FLOWS + "protected pages turn an ended session"]),
    ("25 show Server Actions an ended session as an error", [(STATE, "  if (to !== null) redirect(to);\n", "")],
     [FLOWS + "protected pages send Server Actions"]),
    ("26 serve artifacts without redirecting an ended session", [(ARTIFACTS, "  if (to !== null) {\n    return new Response", "  if (to === \"never\") {\n    return new Response")],
     [FLOWS + "protected pages send artifact downloads"]),
    ("27 send the API token on sign-in", [(CLIENT, '  if (auth !== "anonymous") {', "  if (true) {")],
     [FLOWS + "sign-in keeps the API token on the server"]),
    ("28 unbounded cookie lifetime", [(COOKIE, "    maxAge: Math.max(0, Math.min(seconds, MAX_COOKIE_SECONDS)),", "    maxAge: Math.max(0, seconds),")],
     [CORE + "session cookie is HttpOnly"]),
    ("29 accept writes without a session cookie (proxy)", [(PATHS, '  const read = ["GET", "HEAD"].includes(method.toUpperCase());', '  const read = true;')],
     [CORE + "protected routes sends page loads", FLOWS + "proxy refuses writes without a session cookie"]),
    ("30 key the store by the raw cookie value", [(STORE, '  return createHash("sha256").update(id).digest("hex");', "  return id;")],
     [CORE + "session store never stores a usable cookie value"]),
    ("31 hide the API's 403 message", [(ERRORS, '  "forbidden",\n', "")],
     [FLOWS + "protected pages keep the API's 403 and 404"]),
    ("32 convert 401 to 403 for the browser", [(PATHS, '  if (status === 401 && code === "unauthenticated") return SESSION_END_PATH;', '  if (status === 401 && code === "unauthenticated") return null;')],
     [CORE + "protected routes maps only", FLOWS + "protected pages require a live API session"]),
]


def tree_hash() -> str:
    out = subprocess.run(["git", "diff", "HEAD", "--", "."], capture_output=True, text=True, encoding="utf-8").stdout
    untracked = subprocess.run(["git", "ls-files", "-o", "--exclude-standard"], capture_output=True, text=True).stdout
    h = hashlib.sha256(out.encode())
    for f in sorted(untracked.split()):
        h.update(f.encode())
        h.update(open(f, "rb").read())
    return h.hexdigest()


def failed_tests() -> list[str]:
    report = os.path.join(tempfile.gettempdir(), "m8-vitest.json")
    if os.path.exists(report):
        os.remove(report)
    subprocess.run(
        "npx vitest run --reporter=json --outputFile=" + report,
        shell=True, capture_output=True, text=True, timeout=900,
    )
    data = json.load(open(report, encoding="utf-8"))
    names = []
    for result in data["testResults"]:
        file = os.path.basename(result["name"])
        if result.get("status") == "failed" and not result["assertionResults"]:
            names.append(file + " > (file failed to load)")
        for a in result["assertionResults"]:
            if a["status"] == "failed":
                names.append(file + " > " + " ".join(a["ancestorTitles"] + [a["title"]]))
    return names


def clean_tree() -> bool:
    """Mutations edit tracked files in place and restore them afterwards. A
    clean tree guarantees `git checkout -- frontend` can always undo a run that
    was killed before it could restore."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--", "src", "tests"],
        capture_output=True, text=True, check=True,
    ).stdout
    return out.strip() == ""


def main() -> int:
    if not clean_tree():
        print("refusing to run: frontend/src or tests have uncommitted changes")
        return 2
    wanted = {int(a) for a in sys.argv[1:]}
    before = tree_hash()
    caught = 0
    run = 0
    for name, edits, tests in MUTATIONS:
        if wanted and int(name.split()[0]) not in wanted:
            continue
        run += 1
        originals = {}
        try:
            for path, old, new in edits:
                text = originals.get(path) or open(path, encoding="utf-8", newline="").read()
                originals.setdefault(path, text)
                current = open(path, encoding="utf-8", newline="").read()
                assert current.count(old) == 1, f"anchor not unique in {path}: {old!r}"
                open(path, "w", encoding="utf-8", newline="").write(current.replace(old, new))
            failures = failed_tests()
        finally:
            for path, text in originals.items():
                open(path, "w", encoding="utf-8", newline="").write(text)
        hits = [f for f in failures if any(f.startswith(t) for t in tests)]
        if hits:
            caught += 1
            print(f"CAUGHT    {name}", flush=True)
            for h in hits[:3]:
                print(f"            failed: {h}", flush=True)
        else:
            print(f"SURVIVED  {name}", flush=True)
            for f in failures[:5]:
                print(f"            (other failure: {f})", flush=True)
    restored = tree_hash() == before
    print(f"tree restored: {restored}")
    print(f"{caught}/{run} caught")
    return 0 if restored and caught == run else 1


if __name__ == "__main__":
    sys.exit(main())
