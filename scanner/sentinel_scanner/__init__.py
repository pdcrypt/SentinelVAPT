"""SentinelVAPT scanner engine.

A standalone package: it receives a scan request (scope + enabled checks) and
returns finding candidates and log events. It must not import from the backend,
touch the database, or read secrets from the environment.

Scope enforcement, the safe HTTP client, the check interface and the first
checks arrive in Phase 2.
"""

__version__ = "0.1.0"
