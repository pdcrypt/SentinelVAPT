"""Argon2id hashing, verification, rehash detection, dummy hash and the
password policy (app/core/passwords.py)."""

import pytest
from argon2 import PasswordHasher

from app.core.config import AppEnv, Settings
from app.core.passwords import (
    MAX_LENGTH,
    Argon2Parameters,
    PasswordPolicyError,
    Passwords,
    check_policy,
    normalize,
)

FLOOR = Argon2Parameters(time_cost=2, memory_kib=19456, parallelism=1)
PASSWORD = "correct horse battery staple"  # noqa: S105  # test fixture


@pytest.fixture(scope="module")
def passwords() -> Passwords:
    return Passwords(FLOOR)


def test_hashes_are_argon2id_with_the_configured_parameters(passwords: Passwords) -> None:
    stored = passwords.hash(PASSWORD)
    assert stored.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert PASSWORD not in stored
    assert passwords.hash(PASSWORD) != stored  # salted


def test_verification(passwords: Passwords) -> None:
    stored = passwords.hash(PASSWORD)
    assert passwords.verify(stored, PASSWORD)
    assert not passwords.verify(stored, PASSWORD + " ")
    assert not passwords.verify(stored, PASSWORD.upper())
    assert not passwords.verify(stored, "")
    for malformed in ["", "plaintext", "$argon2id$garbage", "$2b$12$bcrypt"]:
        assert not passwords.verify(malformed, PASSWORD)  # never raises


def test_unicode_passwords_and_normalization(passwords: Passwords) -> None:
    composed = "p\u00e4ssw\u00f6rd-\u6771\u4eac-\U0001f510"
    decomposed = "pa\u0308ssw\u00f6rd-\u6771\u4eac-\U0001f510"
    assert normalize(composed) == normalize(decomposed)
    stored = passwords.hash(composed)
    assert passwords.verify(stored, decomposed)  # canonically equivalent input
    assert not passwords.verify(stored, "passwordtokyo")
    check_policy(composed)


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("", "must not be empty"),
        ("            ", "must not be empty"),
        ("short-pw", "at least 12"),
        ("a" * (MAX_LENGTH + 1), "at most 256"),
        ("with\x00nul-character", "control characters"),
        ("with\nnewline-inside", "control characters"),
        ("tab\tseparated-password", "control characters"),
        ("Alice.Example", "not be the username"),
    ],
)
def test_policy_rejections(password: str, message: str) -> None:
    with pytest.raises(PasswordPolicyError, match=message) as info:
        check_policy(password, username="alice.example")
    if password.strip():
        assert password not in str(info.value)  # never echoed


def test_policy_accepts_long_and_spaced_passphrases_without_truncation(
    passwords: Passwords,
) -> None:
    exact = "x" * MAX_LENGTH
    check_policy(exact)
    check_policy("four plain words here")
    stored = passwords.hash(exact)
    # No silent truncation: a password that only shares a long prefix fails.
    assert not passwords.verify(stored, exact[:-1])
    assert not passwords.verify(passwords.hash(exact[:72] + "a"), exact[:72] + "b")


def test_rehash_is_needed_for_weaker_or_foreign_hashes(passwords: Passwords) -> None:
    current = passwords.hash(PASSWORD)
    weaker = Passwords(Argon2Parameters(time_cost=1, memory_kib=8192, parallelism=1)).hash(PASSWORD)
    assert not passwords.needs_rehash(current)
    assert passwords.needs_rehash(weaker)
    assert passwords.verify(weaker, PASSWORD)  # still verifies, then gets upgraded
    stronger = Passwords(Argon2Parameters(3, 65536, 4))
    assert stronger.needs_rehash(current)
    assert passwords.needs_rehash("not-a-hash")


def test_dummy_hash(passwords: Passwords) -> None:
    dummy = passwords.dummy_hash
    assert dummy.startswith("$argon2id$v=19$m=19456,t=2,p=1$")  # same cost as real hashes
    assert passwords.dummy_hash == dummy  # constant for the process
    assert Passwords(FLOOR).dummy_hash == dummy
    for guess in ["", PASSWORD, "dummy", "password"]:
        assert not passwords.verify(dummy, guess)
    assert not passwords.needs_rehash(dummy)


def test_settings_cannot_weaken_hashing_below_the_floor() -> None:
    base = {"app_env": AppEnv.TEST, "database_url": "postgresql+psycopg://x:y@h/db"}
    for field, value in [
        ("auth_argon2_time_cost", 1),
        ("auth_argon2_memory_kib", 8192),
        ("auth_argon2_parallelism", 0),
    ]:
        with pytest.raises(ValueError, match=field):
            Settings(**base, **{field: value})  # type: ignore[arg-type]
    defaults = Settings(**base)  # type: ignore[arg-type]
    hasher = PasswordHasher()
    assert (
        defaults.auth_argon2_time_cost,
        defaults.auth_argon2_memory_kib,
        defaults.auth_argon2_parallelism,
    ) == (hasher.time_cost, hasher.memory_cost, hasher.parallelism)  # RFC 9106 profile
    assert (defaults.auth_session_idle_minutes, defaults.auth_session_absolute_hours) == (30, 12)
