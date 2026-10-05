"""Administrative commands: python -m app.cli <command>

create-admin   Create the first administrator (ADR 0014). There is no public
               registration: this is the only way to create the first account.

    python -m app.cli create-admin --username alice --display-name "Alice Admin"

The password is never taken from the command line (it would end up in shell
history and process listings). It is read from a hidden prompt and confirmed,
or, for automation, as one line from standard input with --password-stdin:

    printf '%s\\n' "$PASSWORD" | python -m app.cli create-admin --username alice \\
        --display-name "Alice Admin" --password-stdin

The command refuses if any administrator already exists, enforces the password
policy, and never prints the password. Exit codes: 0 created, 1 refused or
invalid input, 2 usage error.

Authentication cutover (Phase 9 M4). Project access now requires membership,
so projects created before it have no members and are visible to nobody:

list-unclaimed-projects   Projects without members (id and name).
claim-project             Make one named, active user the first owner of a
                          project without members. Idempotent; refuses a
                          project that already has other members.

    python -m app.cli claim-project --project <uuid> --username alice

enforce-authentication    Record when authentication became enforced
                          (platform_settings.authentication_enforced_at),
                          once. Actor text written before it is self-asserted.

Each records an audit event. Exit codes: 0 done (or nothing to do), 1 refused.
"""

import argparse
import getpass
import logging
import sys
import uuid
from collections.abc import Callable
from typing import TextIO

from app.api.deps import get_passwords
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.errors import DomainError
from app.db.session import make_engine, make_session_factory
from app.services.audit import AuditContext
from app.services.auth import AuthService
from app.services.platform import ClaimOutcome, PlatformService


def _read_password(from_stdin: bool, stdin: TextIO, prompt: Callable[[str], str]) -> str | None:
    if from_stdin:
        line = stdin.readline()
        return line[:-1] if line.endswith("\n") else line
    first = prompt("Password: ")
    second = prompt("Confirm password: ")
    if first != second:
        print("The passwords do not match.", file=sys.stderr)
        return None
    return first


def create_admin(
    args: argparse.Namespace,
    settings: Settings,
    *,
    stdin: TextIO = sys.stdin,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    password = _read_password(args.password_stdin, stdin, prompt)
    if password is None:
        return 1
    engine = make_engine(settings.database_url.get_secret_value())
    try:
        with make_session_factory(engine)() as session:
            service = AuthService(session, settings, utc_now, get_passwords(settings))
            try:
                user = service.create_first_admin(
                    args.username,
                    args.display_name,
                    password,
                    AuditContext(request_id=None, source="cli"),
                    actor="cli:create-admin",
                )
            except DomainError as exc:
                print(f"Refused: {exc.message}", file=sys.stderr)
                return 1
    finally:
        engine.dispose()
    print(f"Created administrator '{user.username}' ({user.id}).")
    return 0


CLI = AuditContext(request_id=None, source="cli")


def list_unclaimed_projects(_: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url.get_secret_value())
    try:
        with make_session_factory(engine)() as session:
            projects = PlatformService(session).unclaimed_projects()
            for project in projects:
                print(f"{project.id}  {project.name}")
    finally:
        engine.dispose()
    print(f"{len(projects)} project(s) without members.", file=sys.stderr)
    return 0


def claim_project(args: argparse.Namespace, settings: Settings) -> int:
    try:
        project_id = uuid.UUID(args.project)
    except ValueError:
        print("Refused: --project must be a project id.", file=sys.stderr)
        return 1
    engine = make_engine(settings.database_url.get_secret_value())
    try:
        with make_session_factory(engine)() as session:
            try:
                outcome = PlatformService(session).claim_project(
                    project_id, args.username, CLI, actor="cli:claim-project"
                )
            except DomainError as exc:
                print(f"Refused: {exc.message}", file=sys.stderr)
                return 1
    finally:
        engine.dispose()
    if outcome is ClaimOutcome.ALREADY_OWNER:
        print(f"'{args.username}' already owns project {project_id}; nothing changed.")
    else:
        print(f"'{args.username}' is now the owner of project {project_id}.")
    return 0


def enforce_authentication(_: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database_url.get_secret_value())
    try:
        with make_session_factory(engine)() as session:
            cutover = PlatformService(session).record_authentication_cutover(
                CLI, actor="cli:enforce-authentication"
            )
    finally:
        engine.dispose()
    when = cutover.enforced_at.isoformat()
    if cutover.newly_recorded:
        print(f"Recorded the authentication cutover at {when}.")
    else:
        print(f"The authentication cutover was already recorded at {when}; nothing changed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="create the first administrator")
    admin.add_argument("--username", required=True)
    admin.add_argument("--display-name", required=True)
    admin.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password as one line from standard input (no prompt)",
    )
    commands.add_parser("list-unclaimed-projects", help="list projects without members")
    claim = commands.add_parser("claim-project", help="make a user the owner of a legacy project")
    claim.add_argument("--project", required=True, help="project id")
    claim.add_argument("--username", required=True)
    commands.add_parser("enforce-authentication", help="record the authentication cutover")
    args = parser.parse_args(argv)
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper())
    if args.command == "create-admin":
        return create_admin(args, settings)
    handlers = {
        "list-unclaimed-projects": list_unclaimed_projects,
        "claim-project": claim_project,
        "enforce-authentication": enforce_authentication,
    }
    if args.command in handlers:
        return handlers[args.command](args, settings)
    return 2  # pragma: no cover  # argparse rejects unknown commands


if __name__ == "__main__":
    sys.exit(main())
