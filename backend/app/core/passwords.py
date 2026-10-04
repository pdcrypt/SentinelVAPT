"""Password hashing and policy (ADR 0014, Phase 9 M2).

Hashing is Argon2id through argon2-cffi; nothing here implements cryptography.
Parameters come from Settings, whose bounds enforce the OWASP minimum
(m=19 MiB, t=2, p=1); defaults are RFC 9106's second recommendation
(t=3, m=64 MiB, p=4).

Unknown users are verified against a dummy hash made with the *current*
parameters (once per process), so a login for an account that does not exist
costs the same Argon2 work as one that does.

Password policy (no composition rules; NIST SP 800-63B style):
- normalized to Unicode NFKC before hashing and verifying, so canonically
  equivalent input (e.g. composed vs decomposed accents) is the same password;
- 12 to 256 characters after normalization; longer input is refused, never
  truncated;
- no control characters, and not only whitespace;
- not the same as the username (ignoring case).

Passwords never appear in exceptions, logs or return values.
"""

import secrets
import threading
import unicodedata
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 256


@dataclass(frozen=True)
class Argon2Parameters:
    time_cost: int
    memory_kib: int
    parallelism: int


class PasswordPolicyError(ValueError):
    """The password does not meet the policy. The message never contains it."""


def normalize(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def check_policy(password: str, *, username: str | None = None) -> None:
    value = normalize(password)
    if not value or not value.strip():
        raise PasswordPolicyError("The password must not be empty.")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise PasswordPolicyError("The password must not contain control characters.")
    if len(value) < MIN_LENGTH:
        raise PasswordPolicyError(f"The password must be at least {MIN_LENGTH} characters long.")
    if len(value) > MAX_LENGTH:
        raise PasswordPolicyError(f"The password must be at most {MAX_LENGTH} characters long.")
    if username is not None and value.casefold() == normalize(username).casefold():
        raise PasswordPolicyError("The password must not be the username.")


_dummy_lock = threading.Lock()
_dummy_hashes: dict[Argon2Parameters, str] = {}


class Passwords:
    def __init__(self, params: Argon2Parameters) -> None:
        self.params = params
        self._hasher = PasswordHasher(
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            type=Type.ID,
        )

    def hash(self, password: str) -> str:
        """Argon2id hash of the normalized password (call check_policy first
        for new passwords)."""
        return self._hasher.hash(normalize(password))

    def verify(self, stored_hash: str, password: str) -> bool:
        """True only for a matching password. Never raises for a wrong or
        malformed input; always performs the Argon2 work for a valid hash."""
        try:
            return self._hasher.verify(stored_hash, normalize(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """True when the stored hash uses other (e.g. weaker) parameters."""
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    @property
    def dummy_hash(self) -> str:
        """A hash of a random, discarded secret with the current parameters;
        nothing can ever verify against it."""
        with _dummy_lock:
            if self.params not in _dummy_hashes:
                _dummy_hashes[self.params] = self._hasher.hash(secrets.token_urlsafe(32))
            return _dummy_hashes[self.params]
