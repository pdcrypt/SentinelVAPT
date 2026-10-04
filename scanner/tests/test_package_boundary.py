"""Guards the architectural rule that the scanner stays independent."""

import ast
from pathlib import Path

import sentinel_scanner

FORBIDDEN_IMPORTS = {"app", "fastapi", "sqlalchemy", "alembic", "psycopg"}
PACKAGE_DIR = Path(sentinel_scanner.__file__).parent


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_scanner_does_not_import_backend_or_db_libraries() -> None:
    offenders = {
        str(path.relative_to(PACKAGE_DIR)): bad
        for path in PACKAGE_DIR.rglob("*.py")
        if (bad := _top_level_imports(path) & FORBIDDEN_IMPORTS)
    }
    assert offenders == {}


def test_version_exposed() -> None:
    assert sentinel_scanner.__version__
