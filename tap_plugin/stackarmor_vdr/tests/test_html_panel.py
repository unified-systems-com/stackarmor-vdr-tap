"""The stackarmor_html panel type (`req-stackarmor-vdr-panel-html`).

Pure tests: the context is built without a database and the template is rendered with a standalone Django ``Engine`` over the
plugin's own templates (autoescape on, as the project's engine)."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from django.template import Context, Engine
from tap_plugin.stackarmor_vdr import htmlsafe
from tap_plugin.stackarmor_vdr.panels import html_panel as hp

PACKAGE = Path(hp.__file__).resolve().parents[1]
TEMPLATE = PACKAGE / "templates" / "stackarmor_vdr" / "panels" / "html.html"
CSS = PACKAGE / "static" / "stackarmor_vdr" / "css" / "html.css"
ENGINE = Engine(dirs=[str(PACKAGE / "templates")])
MARKUP = '<h2>Title</h2><p class="sa-lead">Lead <a href="https://ok.example/">link</a></p><script>alert(1)</script><p onclick="x">text</p>'


def render(config: dict[str, Any], rows: list[dict[str, Any]] | None = None) -> str:
    context = hp.html_context(config, rows)
    template = ENGINE.from_string(TEMPLATE.read_text(encoding="utf-8"))
    return template.render(Context({"panel": SimpleNamespace(config={"hide_header": True, **config}, name="P"), **context}))


@pytest.mark.spec("req-stackarmor-vdr-panel-html-1")
def test_registered_with_a_described_config() -> None:
    schema = hp.HTML_PANEL_CONFIG_SCHEMA
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False and schema["oneOf"] == [{"required": ["html"]}, {"required": ["field"]}]
    assert all(p.get("description") for p in schema["properties"].values())
    assert hp.StackarmorHtmlPanelType.slug == "stackarmor_html"
    assert "StackarmorHtmlPanelType" in (PACKAGE / "apps.py").read_text(encoding="utf-8")
    assert hp.validate_config({"html": "<p>x</p>"}) is None and hp.validate_config({"field": "body"}) is None
    for bad in ({}, {"html": "x", "field": "y"}, {"html": "x", "extra": 1}, {"html": "x" * (htmlsafe.MAX_BYTES_CEILING + 1)},
                {"html": "x", "features": ["script"]}, {"html": "x", "link_schemes": ["javascript"]}, {"html": "x", "max_bytes": 0}):
        assert hp.validate_config(bad), bad


@pytest.mark.spec("req-stackarmor-vdr-panel-html-2")
def test_the_rendered_panel_holds_only_allowed_markup() -> None:
    html = render({"html": MARKUP})
    inner = html.split('<div class="sa-html">', 1)[1].rsplit("</div>", 1)[0]
    assert "<script" not in inner and "onclick" not in inner and "<h2>Title</h2>" in inner and 'class="sa-lead"' in inner
    assert 'rel="noopener noreferrer nofollow"' in inner


@pytest.mark.spec("req-stackarmor-vdr-panel-html-10")
def test_cleaned_every_render_and_nothing_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    first = render({"html": "<p>one</p>"})
    real = htmlsafe.clean
    monkeypatch.setattr(hp.htmlsafe, "clean", lambda src, policy=None: real(src.replace("one", "two"), policy))
    assert "one" in first and "two" in render({"html": "<p>one</p>"})
    assert "cleaned" not in hp.HTML_PANEL_CONFIG_SCHEMA["properties"]  # no field to hold a cleaned copy


@pytest.mark.spec("req-stackarmor-vdr-panel-html-11")
def test_fails_closed_without_raw_or_escaped_markup(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = "<p>SECRET-MARKER</p>"
    monkeypatch.setitem(sys.modules, "nh3", None)
    out = render({"html": marker})
    assert "cannot be shown" in out and "SECRET-MARKER" not in out and "&lt;p&gt;" not in out
    monkeypatch.undo()
    monkeypatch.setattr(hp.htmlsafe, "clean", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = render({"html": marker})
    assert "cannot be shown" in out and "SECRET-MARKER" not in out and "boom" not in out


@pytest.mark.spec("req-stackarmor-vdr-panel-html-9")
def test_a_refused_document_shows_a_message_and_no_content() -> None:
    out = render({"html": "<div>" * 40 + "SECRET-MARKER"})
    assert "was refused" in out and "SECRET-MARKER" not in out


@pytest.mark.spec("req-stackarmor-vdr-panel-html-12")
def test_one_trusted_step() -> None:
    uses = [p for p in PACKAGE.rglob("*.py") if "tests" not in p.parts and "mark_safe(" in p.read_text(encoding="utf-8")]
    assert [p.name for p in uses] == ["html_panel.py"]
    source = uses[0].read_text(encoding="utf-8")
    assert source.count("mark_safe(") == 1 and "def _safe" in source
    templates = "".join(p.read_text(encoding="utf-8") for p in (PACKAGE / "templates").rglob("*.html"))
    assert "|safe" not in templates and "autoescape off" not in templates and "{% autoescape" not in templates


@pytest.mark.spec("req-stackarmor-vdr-panel-html-13")
def test_the_same_from_both_sources() -> None:
    from_config = render({"html": MARKUP})
    from_row = render({"field": "body"}, [{"body": MARKUP}])
    assert from_config.split('<div class="sa-html">', 1)[1] == from_row.split('<div class="sa-html">', 1)[1]
    assert from_config == render({"field": "body", "row": 1}, [{"body": "x"}, {"body": MARKUP}])


@pytest.mark.spec("req-stackarmor-vdr-panel-html-14")
def test_search_failures_are_shown_not_raised() -> None:
    assert "could not be read" in render({"field": "body"}, None)
    assert "No content" in render({"field": "body"}, [])
    assert "No content" in render({"field": "body"}, [{"other": "x"}])
    assert "not text" in render({"field": "body"}, [{"body": {"a": 1}}])
    panel = SimpleNamespace(config={"html": "x", "features": ["nope"]}, name="P")
    assert hp.StackarmorHtmlPanelType.get_view_context(panel, None)["state"] == "bad_config"  # type: ignore[arg-type]


@pytest.mark.spec("req-stackarmor-vdr-panel-html-15")
def test_needs_no_script_or_inline_style() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "<script" not in source and "<style" not in source and "style=" not in source
    assert "<script" not in render({"html": MARKUP}) and "style=" not in render({"html": MARKUP})


@pytest.mark.spec("req-stackarmor-vdr-panel-html-16")
def test_stylesheet_uses_theme_tokens_only_and_is_scoped() -> None:
    css = CSS.read_text(encoding="utf-8")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(\s*\d", css) and "var(--tap-" in css or "rgb(var(--tap-" in css
    rules = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    selectors = [s.strip() for block in re.findall(r"([^{}]+)\{", rules) for s in block.split(",")]
    assert all(s.startswith(".tap-panel--sa-html") or s.startswith("@") or not s for s in selectors), [s for s in selectors if not s.startswith(".tap-panel--sa-html")]
    assert "@media print" in css


@pytest.mark.spec("req-stackarmor-vdr-panel-html-19")
def test_panel_features_narrow_the_rendered_output() -> None:
    page = "<h2>H</h2><p>p</p><table><tr><td>cell</td></tr></table>"
    out = render({"html": page, "features": ["headings"]})
    assert "<h2>" in out and "<table" not in out and "cell" in out
    out = render({"html": '<img src="/static/a.png"><a href="https://ok.example/">x</a>', "features": ["images"]})
    assert "<img" in out and "<a " not in out
