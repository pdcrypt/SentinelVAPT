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
"""

import argparse
import getpass
import logging
import sys
from collections.abc import Callable
from typing import TextIO

from app.api.deps import get_passwords
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.errors import DomainError
from app.db.session import make_engine, make_session_factory
from app.services.audit import AuditContext
from app.services.auth import AuthService


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
    args = parser.parse_args(argv)
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper())
    if args.command == "create-admin":
        return create_admin(args, settings)
    return 2  # pragma: no cover  # argparse rejects unknown commands


if __name__ == "__main__":
    sys.exit(main())
