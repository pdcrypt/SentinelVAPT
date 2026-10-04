import re
import shutil
from pathlib import Path

import pytest

from sentinel_reports import TemplateMismatch, render_report, templates
from sentinel_reports.templates import TEMPLATES, compute_hash, locked_hashes, verified_hash
from tests.factory import snapshot


def test_every_template_matches_the_lockfile() -> None:
    locked = locked_hashes()
    assert set(locked) == {t.key for t in TEMPLATES.values()}
    for template in TEMPLATES.values():
        assert verified_hash(template) == locked[template.key], (
            f"{template.key} changed: bump its version instead of editing it"
        )


def test_an_edited_template_refuses_to_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shutil.copytree(templates.TEMPLATES_DIR, tmp_path / "templates")
    css = tmp_path / "templates" / "sv-standard" / "1" / "print.css"
    css.write_text(css.read_text(encoding="utf-8") + "\n/* edited */\n", encoding="utf-8")
    monkeypatch.setattr(templates, "TEMPLATES_DIR", tmp_path / "templates")
    with pytest.raises(TemplateMismatch):
        render_report(snapshot(), ["json"])


def test_hash_ignores_line_ending_style(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    template = TEMPLATES[("sv-standard", 1)]
    expected = compute_hash(template)
    shutil.copytree(templates.TEMPLATES_DIR, tmp_path / "templates")
    for file in (tmp_path / "templates").rglob("*.*"):
        file.write_bytes(file.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    monkeypatch.setattr(templates, "TEMPLATES_DIR", tmp_path / "templates")
    assert compute_hash(template) == expected


def test_unknown_template_is_refused() -> None:
    s = snapshot()
    s["document"]["template"] = {"id": "sv-standard", "version": 99}
    with pytest.raises(TemplateMismatch):
        render_report(s, ["json"])


def _template_files() -> list[Path]:
    return [p for p in templates.TEMPLATES_DIR.rglob("*") if p.is_file()]


@pytest.mark.parametrize(
    "forbidden",
    [
        r"\|\s*safe\b",
        r"\bMarkup\b",
        r"autoescape\s+false",
        r"<script",
        r"\son[a-z]+\s*=",
        r"\sstyle\s*=",
        r"url\(",
        r"@import",
        r"@font-face",
        r"\{%\s*raw",
        r"\bsrc\s*=",
    ],
)
def test_templates_contain_no_unsafe_constructs(forbidden: str) -> None:
    for file in _template_files():
        assert not re.search(forbidden, file.read_text(encoding="utf-8"), re.IGNORECASE), (
            f"{file.name}: {forbidden}"
        )


def test_stylesheet_has_no_jinja_delimiters() -> None:
    # The stylesheet is included as template source; it must not contain
    # anything Jinja would interpret.
    css = (templates.TEMPLATES_DIR / "sv-standard" / "1" / "print.css").read_text(encoding="utf-8")
    assert not re.search(r"\{[{%#]", css)
