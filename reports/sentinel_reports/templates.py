"""Versioned report templates.

A template is a directory sentinel_reports/templates/<id>/<version>/. Its
files are hashed (line endings normalized) and the hash must match
templates.lock.json: changing a template's files requires a new version, so
a stored report's template version identifies the exact wording and layout
that rendered it. A template that does not match the lockfile does not render.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from sentinel_reports.errors import TemplateMismatch

TEMPLATES_DIR = Path(__file__).parent / "templates"
LOCKFILE = Path(__file__).parent / "templates.lock.json"


@dataclass(frozen=True)
class Template:
    id: str
    version: int
    title: str
    description: str

    @property
    def key(self) -> str:
        return f"{self.id}@{self.version}"

    @property
    def path(self) -> Path:
        return TEMPLATES_DIR / self.id / str(self.version)


TEMPLATES: dict[tuple[str, int], Template] = {
    ("sv-standard", 1): Template(
        "sv-standard",
        1,
        "SentinelVAPT standard assessment report",
        "Document control, executive summary, engagement and authorization, scope, "
        "methodology, scan summary and coverage, findings by issue, evidence appendix, "
        "timeline, limitations and integrity data.",
    ),
}
DEFAULT_TEMPLATE = TEMPLATES[("sv-standard", 1)]


def get_template(template_id: str, version: int) -> Template:
    template = TEMPLATES.get((template_id, version))
    if template is None:
        raise TemplateMismatch("unknown template")
    return template


def compute_hash(template: Template) -> str:
    digest = hashlib.sha256()
    for file in sorted(p for p in template.path.rglob("*") if p.is_file()):
        relative = file.relative_to(template.path).as_posix()
        content = file.read_bytes().replace(b"\r\n", b"\n")
        digest.update(f"{relative}\0{hashlib.sha256(content).hexdigest()}\n".encode())
    return digest.hexdigest()


def locked_hashes() -> dict[str, str]:
    data: dict[str, str] = json.loads(LOCKFILE.read_text(encoding="utf-8"))
    return data


def verified_hash(template: Template) -> str:
    """The template's hash if it matches the lockfile; otherwise refuse."""
    actual = compute_hash(template)
    if locked_hashes().get(template.key) != actual:
        raise TemplateMismatch(f"{template.key} does not match templates.lock.json")
    return actual
