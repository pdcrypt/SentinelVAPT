"""sentinel_reports is offline and independent (ADR 0010): it imports no
network, process, database or web-framework module, nothing from the backend,
scanner or analysis engine, and no AI client."""

import ast
from pathlib import Path

import sentinel_reports

PACKAGE_DIR = Path(sentinel_reports.__file__).parent

FORBIDDEN_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib.request",
    "requests",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "sqlalchemy",
    "psycopg",
    "fastapi",
    "starlette",
    "pydantic",
    "app",
    "sentinel_scanner",
    "sentinel_analysis",
    "openai",
    "anthropic",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _forbidden(name: str) -> bool:
    return any(name == f or name.startswith(f + ".") for f in FORBIDDEN_MODULES)


def test_no_forbidden_imports() -> None:
    offenders = {
        f"{p.relative_to(PACKAGE_DIR).as_posix()}: {name}"
        for p in PACKAGE_DIR.rglob("*.py")
        for name in _imports(p)
        if _forbidden(name)
    }
    assert offenders == set()


def test_no_dynamic_code_execution() -> None:
    offenders = []
    for path in PACKAGE_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in FORBIDDEN_CALLS
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_templates_are_package_data() -> None:
    assert (PACKAGE_DIR / "templates" / "sv-standard" / "1" / "report.html.j2").is_file()
    assert (PACKAGE_DIR / "schema" / "report-snapshot.schema.json").is_file()
    assert (PACKAGE_DIR / "templates.lock.json").is_file()
