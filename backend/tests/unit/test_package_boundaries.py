"""Backend/scanner, backend/analysis and backend/reports boundaries
(ADR 0001, 0008, 0009, 0010).

- The scanner never imports backend code (enforced in scanner/tests too).
- Inside the backend, only the grant builder, result persistence and the
  worker import the scanner; API routers and other services do not.
- Only the analysis service, the worker and the findings router import the
  rule engine; the rule engine imports neither the backend nor the scanner.
- Only the report service, the snapshot builder and the worker import the
  report renderer; the renderer imports neither the backend, the scanner nor
  the rule engine.
- The scanner, the rule engine and the report renderer are installed from this
  repository, not declared as package dependencies that pip could resolve
  from a public index.
"""

import ast
import tomllib
from pathlib import Path

import sentinel_analysis

import app
import sentinel_reports
import sentinel_scanner

APP_DIR = Path(app.__file__).parent
SCANNER_DIR = Path(sentinel_scanner.__file__).parent
ANALYSIS_DIR = Path(sentinel_analysis.__file__).parent
REPORTS_DIR = Path(sentinel_reports.__file__).parent
BACKEND_DIR = APP_DIR.parent

ALLOWED_SCANNER_IMPORTERS = {
    "services/scan_grants.py",
    "services/scan_results.py",
    "worker/core.py",
}

ALLOWED_ANALYSIS_IMPORTERS = {
    "api/v1/routers/findings.py",  # the static rule catalog (GET /rules)
    "services/analysis.py",
    # Builds coverage and classifies findings for retest comparisons (ADR 0011).
    "services/comparisons.py",
    # Resolves display titles of verified taxonomy ids into the frozen report
    # snapshot, so the report renderer never needs the rule engine.
    "services/report_snapshot.py",
    "worker/core.py",
}

ALLOWED_REPORTS_IMPORTERS = {
    "services/report_snapshot.py",
    "services/reports.py",
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


def test_only_designated_backend_modules_import_the_rule_engine() -> None:
    importers = {
        p.relative_to(APP_DIR).as_posix()
        for p in APP_DIR.rglob("*.py")
        if "sentinel_analysis" in _top_level_imports(p)
    }
    assert importers == ALLOWED_ANALYSIS_IMPORTERS


def test_rule_engine_imports_neither_backend_nor_scanner() -> None:
    offenders = {
        p.relative_to(ANALYSIS_DIR).as_posix()
        for p in ANALYSIS_DIR.rglob("*.py")
        if _top_level_imports(p)
        & {"app", "sentinel_scanner", "sqlalchemy", "fastapi", "psycopg", "pydantic"}
    }
    assert offenders == set()


def test_rule_engine_is_not_a_declared_index_dependency() -> None:
    pyproject = tomllib.loads((BACKEND_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    declared = " ".join(
        [
            *pyproject["project"]["dependencies"],
            *pyproject["project"]["optional-dependencies"]["dev"],
        ]
    ).lower()
    assert "sentinel" not in declared


def test_only_designated_backend_modules_import_the_report_renderer() -> None:
    importers = {
        p.relative_to(APP_DIR).as_posix()
        for p in APP_DIR.rglob("*.py")
        if "sentinel_reports" in _top_level_imports(p)
    }
    assert importers == ALLOWED_REPORTS_IMPORTERS


def test_report_renderer_imports_neither_backend_scanner_nor_rule_engine() -> None:
    offenders = {
        p.relative_to(REPORTS_DIR).as_posix()
        for p in REPORTS_DIR.rglob("*.py")
        if _top_level_imports(p)
        & {"app", "sentinel_scanner", "sentinel_analysis", "sqlalchemy", "fastapi", "psycopg"}
    }
    assert offenders == set()


def test_severity_order_matches_between_rule_engine_and_reports() -> None:
    from sentinel_analysis import Severity

    # Reports list the most severe first; the rule engine ranks severities.
    most_severe_first = tuple(s.value for s in sorted(Severity, key=lambda s: -s.rank))
    assert most_severe_first == sentinel_reports.SEVERITY_ORDER
