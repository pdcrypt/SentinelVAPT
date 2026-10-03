"""Guards architectural rules at the source level:

1. The scanner stays independent of the backend, web framework and database.
2. Third-party HTTP clients are not used.
3. Only transport.py and resolver.py may touch the network, so every request
   goes through SafeHttpClient's checks.
"""

import ast
from pathlib import Path

import sentinel_scanner

PACKAGE_DIR = Path(sentinel_scanner.__file__).parent

FORBIDDEN_ANYWHERE = {
    "app",
    "fastapi",
    "starlette",
    "sqlalchemy",
    "alembic",
    "psycopg",
    "pydantic",
    "requests",
    "httpx",
    "httpx2",
    "urllib3",
    "aiohttp",
    "urllib.request",
    "http.server",
    "ftplib",
    "smtplib",
    "telnetlib",
    "subprocess",
}
NETWORK_MODULES = {"socket", "ssl", "http.client", "asyncio"}
NETWORK_ALLOWED_IN = {"transport.py", "resolver.py"}


def _imports(path: Path) -> set[str]:
    """Fully qualified absolute imports, plus each of their parent packages."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        for module in modules:
            parts = module.split(".")
            names.update(".".join(parts[: i + 1]) for i in range(len(parts)))
    return names


def _sources() -> list[Path]:
    return sorted(PACKAGE_DIR.rglob("*.py"))


def test_no_forbidden_imports() -> None:
    offenders = {
        str(p.relative_to(PACKAGE_DIR)): sorted(bad)
        for p in _sources()
        if (bad := _imports(p) & FORBIDDEN_ANYWHERE)
    }
    assert offenders == {}


def test_only_the_transport_layer_touches_the_network() -> None:
    offenders = {
        str(p.relative_to(PACKAGE_DIR)): sorted(bad)
        for p in _sources()
        if p.name not in NETWORK_ALLOWED_IN and (bad := _imports(p) & NETWORK_MODULES)
    }
    assert offenders == {}


def test_version_exposed() -> None:
    assert sentinel_scanner.__version__
