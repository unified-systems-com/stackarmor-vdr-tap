"""The stackarmor_prose panel type (`req-stackarmor-vdr-panel-prose`).

Pure tests: the parsing is Django-free, and the template is rendered with a standalone Django ``Engine`` over the
plugin's own templates directory (autoescape on, as the project's engine), so no settings or database are needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from django.template import Context, Engine
from tap_plugin.stackarmor_vdr.panels import prose

PACKAGE = Path(prose.__file__).resolve().parents[1]
TEMPLATE = PACKAGE / "templates" / "stackarmor_vdr" / "panels" / "prose.html"
CSS = PACKAGE / "static" / "stackarmor_vdr" / "css" / "prose.css"
ENGINE = Engine(dirs=[str(PACKAGE / "templates")])

METHOD = (
    "Impact C, I, A (CVSS): None 0, Low 0.22, High 0.56.\nRequirement CR, IR, AR (the asset): Low 0.5, Medium 1.0, High 1.5.\n\n"
    "U = 1 - (1 - C x CR)(1 - I x IR)(1 - A x AR).\nD_H = 0.995904 (the largest U possible).\nS = U / D_H.\n\n"
    "Word: Minimal below U 0.28; Narrow below U 0.56.\n\nNothing is lowered without evidence: a missing CVSS vector counts as High."
)
STEPS = (
    "1. A scanner finding concerns a vulnerability (CONCERNS_COMPLIANCE_VULNERABILITY).\n"
    "2. The owner: the base reach names the program that owns the component.\n"
    "3. Impact: C, I and A come from the vector.\n"
    "Run by the Searches stackarmor-pain; computed on read."
)


def render(config: dict[str, Any]) -> str:
    panel = SimpleNamespace(config={"hide_header": True, **config}, name="P")
    context = prose.StackarmorProsePanelType.get_view_context(panel, None)  # type: ignore[arg-type]
    return ENGINE.get_template(prose.StackarmorProsePanelType.view).render(Context({**context, "panel": panel}))


def words(text: str) -> list[str]:
    return re.sub(r"<[^>]+>", " ", text).replace("&#x27;", "'").replace("&amp;", "&").replace(":", "").split()


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-1")
def test_registered_with_a_described_config() -> None:
    t = prose.StackarmorProsePanelType
    assert t.slug == "stackarmor_prose" and t.view == "stackarmor_vdr/panels/prose.html" and t.css == ["stackarmor_vdr/css/prose.css"]
    assert TEMPLATE.is_file() and CSS.is_file()
    schema = prose.PROSE_PANEL_CONFIG_SCHEMA
    assert schema["description"] and all(p["description"] for p in schema["properties"].values())
    assert schema["required"] == ["text"] and schema["additionalProperties"] is False
    apps = (PACKAGE / "apps.py").read_text(encoding="utf-8")
    assert "panel_type_registry.register(StackarmorProsePanelType.slug, StackarmorProsePanelType)" in apps
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"text": "x", "colour": "red"}, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"variant": "plain"}, schema)


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-2")
def test_variant_is_an_allowlist_and_the_default_is_plain() -> None:
    for variant in ("plain", "method", "steps"):
        assert prose.validate_config({"text": "x", "variant": variant}) is None
    for bad in ("fancy", "", "METHOD", None):
        assert prose.validate_config({"text": "x", "variant": bad})
    assert "sa-prose--plain" in render({"text": "one\n\ntwo"})
    ctx = prose.StackarmorProsePanelType.get_view_context(SimpleNamespace(config={"text": "a"}), None)  # type: ignore[arg-type]
    assert ctx["variant"] == "plain"


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-3")
@pytest.mark.parametrize("variant", ["plain", "method", "steps"])
def test_text_is_escaped(variant: str) -> None:
    hostile = '1. <script>alert(1)</script>: <b onclick="x()">bold</b> & "q"\n\nLabel: <img src=x onerror=alert(2)>'
    html = render({"text": hostile, "variant": variant})
    assert "<script" not in html and "<img" not in html and "<b onclick" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html or "&lt;script&gt;" in html
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "|safe" not in source and "autoescape off" not in source and "mark_safe" not in (PACKAGE / "panels" / "prose.py").read_text(encoding="utf-8")


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-4")
def test_steps_are_parsed() -> None:
    ctx = prose.steps_context(STEPS)
    assert [s["title"] for s in ctx["steps"]] == ["", "The owner", "Impact"]
    assert ctx["steps"][0]["body"].startswith("A scanner finding concerns")
    assert ctx["steps"][1]["body"] == "the base reach names the program that owns the component."
    assert ctx["notes"] == ["Run by the Searches stackarmor-pain; computed on read."] and ctx["intro"] == []
    dashed = prose.steps_context("Intro line.\n- First: one\n- Second: two")
    assert dashed["intro"] == ["Intro line."] and [s["title"] for s in dashed["steps"]] == ["First", "Second"]
    blocks = prose.steps_context("Alpha: a\nmore\n\nBeta: b")
    assert [(s["title"], s["body"]) for s in blocks["steps"]] == [("Alpha", "a more"), ("Beta", "b")]
    html = render({"text": STEPS, "variant": "steps"})
    assert html.count("<li ") == 3 and "<ol " in html and "sa-steps__item--bare" in html


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-5")
def test_method_is_parsed() -> None:
    paras = prose.method_context(METHOD)["paragraphs"]
    assert [len(p["lines"]) for p in paras] == [2, 3, 1, 1]
    assert paras[0]["lines"][0]["label"] == "Impact C, I, A (CVSS)" and paras[0]["lines"][0]["text"].startswith("None 0")
    assert paras[1]["formula"] and not paras[0]["formula"] and not paras[2]["formula"]
    assert paras[3]["lines"][0]["label"] == "Nothing is lowered without evidence"
    assert prose.split_label("http://example.org is a url") == ("", "http://example.org is a url")
    assert prose.split_label("x" * 41 + ": y")[0] == ""
    html = render({"text": METHOD, "variant": "method"})
    assert "sa-prose__p--lead" in html and "sa-prose__p--formula" in html and html.count("sa-prose__label") == 4


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-6")
@pytest.mark.parametrize(("variant", "text"), [("method", METHOD), ("steps", STEPS), ("plain", METHOD)])
def test_every_word_survives(variant: str, text: str) -> None:
    expected = words(re.sub(r"(?m)^\d+\. ", "", text) if variant == "steps" else text)
    assert words(render({"text": text, "variant": variant})) == expected


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-7")
def test_stylesheet_uses_theme_tokens_only() -> None:
    css = CSS.read_text(encoding="utf-8")
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", body) and "rgb(" not in re.sub(r"rgb\(var\(--tap-[a-z0-9-]+\)\)", "", body)
    assert "var(--tap-" in body


@pytest.mark.spec("req-stackarmor-vdr-panel-prose-8")
def test_bad_config_is_shown_not_raised() -> None:
    html = render({"text": "x", "variant": "fancy"})
    assert "Panel config invalid" in html
    panel = SimpleNamespace(config=None, name="P")
    assert prose.StackarmorProsePanelType.get_view_context(panel, None)["state"] == "bad_config"  # type: ignore[arg-type]


def test_playground_config_round_trips() -> None:
    config = json.loads(json.dumps({"variant": "steps", "hide_header": False, "text": STEPS}))
    assert prose.validate_config(config) is None
