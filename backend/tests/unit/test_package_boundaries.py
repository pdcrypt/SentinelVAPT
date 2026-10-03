"""Backend/scanner boundary (ADR 0001, 0008).

- The scanner never imports backend code (enforced in scanner/tests too).
- Inside the backend, only the grant builder, result persistence and the
  worker import the scanner; API routers and other services do not.
- The scanner is installed from this repository, not declared as a package
  dependency that pip could resolve from a public index.
"""

import ast
import tomllib
from pathlib import Path

import app
import sentinel_scanner

APP_DIR = Path(app.__file__).parent
SCANNER_DIR = Path(sentinel_scanner.__file__).parent
BACKEND_DIR = APP_DIR.parent

ALLOWED_SCANNER_IMPORTERS = {
    "services/scan_grants.py",
    "services/scan_results.py",
    "worker/core.py",
}


def _top_level_imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_only_designated_backend_modules_import_the_scanner() -> None:
    importers = {
        p.relative_to(APP_DIR).as_posix()
        for p in APP_DIR.rglob("*.py")
        if "sentinel_scanner" in _top_level_imports(p)
    }
    assert importers == ALLOWED_SCANNER_IMPORTERS


def test_scanner_does_not_import_the_backend() -> None:
    offenders = {
        p.relative_to(SCANNER_DIR).as_posix()
        for p in SCANNER_DIR.rglob("*.py")
        if _top_level_imports(p) & {"app", "sqlalchemy", "fastapi", "psycopg"}
    }
    assert offenders == set()


def test_scanner_is_not_a_declared_index_dependency() -> None:
    pyproject = tomllib.loads((BACKEND_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    declared = " ".join(pyproject["project"]["dependencies"]).lower()
    assert "sentinel" not in declared
