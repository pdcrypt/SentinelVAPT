"""The analysis package is pure: no network, database, web framework, scanner
or backend imports, and no process spawning (ADR 0009)."""

import ast
from pathlib import Path

import sentinel_analysis

PACKAGE_DIR = Path(sentinel_analysis.__file__).parent

FORBIDDEN = {
    "socket",
    "ssl",
    "http",
    "http.client",
    "urllib.request",
    "asyncio",
    "selectors",
    "requests",
    "httpx",
    "httpx2",
    "urllib3",
    "aiohttp",
    "sqlalchemy",
    "psycopg",
    "alembic",
    "fastapi",
    "starlette",
    "pydantic",
    "app",
    "sentinel_scanner",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "openai",
    "anthropic",
}


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules = [node.module]
        for module in modules:
            parts = module.split(".")
            names.update(".".join(parts[: i + 1]) for i in range(len(parts)))
    return names


def test_no_forbidden_imports() -> None:
    offenders = {
        p.relative_to(PACKAGE_DIR).as_posix(): sorted(bad)
        for p in PACKAGE_DIR.rglob("*.py")
        if (bad := _imports(p) & FORBIDDEN)
    }
    assert offenders == {}


def test_no_dynamic_code_execution() -> None:
    for path in PACKAGE_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not calls & {"eval", "exec", "compile", "__import__"}, path
