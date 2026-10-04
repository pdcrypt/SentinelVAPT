"""Guards that ordinary rendering never exercises: each test proves a safety
mechanism is actually in the render path, not just available."""

import json
import shutil
from pathlib import Path

import jinja2
import pytest

from sentinel_reports import HtmlPolicyViolation, canonical_json, render_report, templates
from sentinel_reports.html import _environment
from sentinel_reports.templates import DEFAULT_TEMPLATE, compute_hash
from tests.factory import snapshot


def test_undefined_template_values_are_errors() -> None:
    env = _environment(DEFAULT_TEMPLATE)
    with pytest.raises(jinja2.UndefinedError):
        env.from_string("{{ missing }}").render()
    with pytest.raises(jinja2.UndefinedError):
        env.from_string("{{ r.document.nope }}").render(r={"document": {}})


def test_the_sandbox_blocks_unsafe_attribute_access() -> None:
    env = _environment(DEFAULT_TEMPLATE)
    with pytest.raises(jinja2.exceptions.SecurityError):
        env.from_string("{{ ''.__class__.__mro__ }}").render()


def test_autoescape_is_on_for_every_value() -> None:
    env = _environment(DEFAULT_TEMPLATE)
    assert env.from_string("{{ v }}").render(v="<b>") == "&lt;b&gt;"


def test_the_html_policy_runs_on_rendered_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A template that emitted a script (e.g. a careless edit) is refused at
    render time even if its hash were accepted."""
    shutil.copytree(templates.TEMPLATES_DIR, tmp_path / "templates")
    page = tmp_path / "templates" / "sv-standard" / "1" / "report.html.j2"
    page.write_text(
        page.read_text(encoding="utf-8").replace("</body>", "<script>x()</script></body>"),
        encoding="utf-8",
    )
    monkeypatch.setattr(templates, "TEMPLATES_DIR", tmp_path / "templates")
    monkeypatch.setattr(
        templates, "locked_hashes", lambda: {DEFAULT_TEMPLATE.key: compute_hash(DEFAULT_TEMPLATE)}
    )
    with pytest.raises(HtmlPolicyViolation):
        render_report(snapshot(), ["html"])


def test_canonical_json_sorts_keys_and_is_compact() -> None:
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": "é"}]}) == (
        '{"a":[1,{"c":"é","d":2}],"b":1}'.encode()
    )
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_json_artifact_key_order_does_not_depend_on_input_order() -> None:
    s = snapshot()
    reordered = json.loads(json.dumps(s, sort_keys=True))
    reordered = dict(reversed(list(reordered.items())))
    (a,) = render_report(s, ["json"])
    (b,) = render_report(reordered, ["json"])
    assert a.content == b.content
