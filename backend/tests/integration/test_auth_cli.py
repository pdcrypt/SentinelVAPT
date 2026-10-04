"""The first-admin bootstrap command: python -m app.cli create-admin."""

import argparse
import io
import threading

import pytest
from pydantic import SecretStr

from app.cli import create_admin, main
from app.core.config import Settings
from app.models.enums import GlobalRole
from tests.integration.auth_support import PREFIX, Live, live, login
from tests.integration.conftest import _test_database_url

pytestmark = pytest.mark.integration

__all__ = ["live"]

ADMIN_PASSWORD = "bootstrap-passphrase-2026"  # noqa: S105  # test fixture


def cli_settings(live: Live) -> Settings:
    url = _test_database_url().render_as_string(hide_password=False)
    return live.settings.model_copy(update={"database_url": SecretStr(url)})


def args(username: str, *, stdin: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        command="create-admin",
        username=username,
        display_name="Lab Administrator",
        password_stdin=stdin,
    )


def admins(live: Live) -> list[str]:
    return [r[0] for r in live.rows("SELECT username FROM users WHERE global_role = 'admin'")]


def test_creates_the_first_admin_from_stdin(live: Live, capsys: pytest.CaptureFixture[str]) -> None:
    assert admins(live) == []
    code = create_admin(
        args(f"{PREFIX}root"), cli_settings(live), stdin=io.StringIO(ADMIN_PASSWORD + "\n")
    )
    out = capsys.readouterr()
    assert code == 0
    assert f"Created administrator '{PREFIX}root'" in out.out
    assert ADMIN_PASSWORD not in out.out + out.err
    assert admins(live) == [f"{PREFIX}root"]
    stored = live.scalar(
        "SELECT c.password_hash FROM user_credentials c JOIN users u ON u.id = c.user_id "
        "WHERE u.username = :u",
        u=f"{PREFIX}root",
    )
    assert stored.startswith("$argon2id$") and ADMIN_PASSWORD not in stored
    event = live.rows(
        "SELECT actor_type, actor_label, metadata::text FROM audit_events "
        "WHERE action = 'user.created'"
    )
    assert len(event) == 1 and event[0][0] == "system" and event[0][1] == "cli:create-admin"
    assert ADMIN_PASSWORD not in event[0][2]
    # The new administrator can log in.
    assert login(live.client(), f"{PREFIX}root", ADMIN_PASSWORD).status_code == 200


def test_interactive_prompt_requires_confirmation(
    live: Live, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter([ADMIN_PASSWORD, ADMIN_PASSWORD + "typo"])
    code = create_admin(args(f"{PREFIX}typo", stdin=False), cli_settings(live),
                        prompt=lambda _: next(answers))  # fmt: skip
    assert code == 1
    assert "do not match" in capsys.readouterr().err
    assert admins(live) == []
    answers = iter([ADMIN_PASSWORD, ADMIN_PASSWORD])
    code = create_admin(args(f"{PREFIX}prompted", stdin=False), cli_settings(live),
                        prompt=lambda _: next(answers))  # fmt: skip
    assert code == 0 and admins(live) == [f"{PREFIX}prompted"]


def test_refuses_once_an_admin_exists(live: Live, capsys: pytest.CaptureFixture[str]) -> None:
    live.user("existing-admin", role=GlobalRole.ADMIN)
    code = create_admin(
        args(f"{PREFIX}second"), cli_settings(live), stdin=io.StringIO(ADMIN_PASSWORD)
    )
    assert code == 1
    assert "already exists" in capsys.readouterr().err
    assert admins(live) == [f"{PREFIX}existing-admin"]


@pytest.mark.parametrize(
    ("username", "password", "message"),
    [
        (f"{PREFIX}weak", "short", "at least 12"),
        (f"{PREFIX}weak", "", "must not be empty"),
        (f"{PREFIX}same-as-username", f"{PREFIX}same-as-username", "not be the username"),
        ("bad name!", ADMIN_PASSWORD, "Usernames are 3-64"),
        ("ab", ADMIN_PASSWORD, "Usernames are 3-64"),
    ],
)
def test_rejects_invalid_input(
    live: Live, capsys: pytest.CaptureFixture[str], username: str, password: str, message: str
) -> None:
    code = create_admin(args(username), cli_settings(live), stdin=io.StringIO(password + "\n"))
    err = capsys.readouterr().err
    assert code == 1 and message in err
    if password:
        assert password not in err or password == username
    assert admins(live) == []


def test_passwords_cannot_be_given_as_arguments() -> None:
    with pytest.raises(SystemExit) as info:
        main(["create-admin", "--username", "x", "--display-name", "y", "--password", "z"])
    assert info.value.code == 2


def test_concurrent_bootstraps_create_one_admin(live: Live) -> None:
    settings = cli_settings(live)
    barrier = threading.Barrier(3)
    codes: list[int] = []
    lock = threading.Lock()

    def run(i: int) -> None:
        barrier.wait()
        code = create_admin(args(f"{PREFIX}racer-{i}"), settings,
                            stdin=io.StringIO(ADMIN_PASSWORD))  # fmt: skip
        with lock:
            codes.append(code)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert sorted(codes) == [0, 1, 1]
    assert len(admins(live)) == 1
