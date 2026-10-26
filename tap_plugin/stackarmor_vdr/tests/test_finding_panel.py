"""The stackarmor_finding panel type (`req-stackarmor-vdr-panel-finding`).

Pure tests: the shaping is Django-free, and the template is rendered with a standalone Django ``Engine`` over the plugin's own
templates directory (autoescape on), so no settings or database are needed.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from django.template import Context, Engine
from tap_plugin.stackarmor_vdr.panels import finding
from tap_plugin.stackarmor_vdr.tests.test_walkthrough import PARAMS, build, extra, row_for

PACKAGE = Path(finding.__file__).resolve().parents[1]
TEMPLATE = PACKAGE / "templates" / "stackarmor_vdr" / "panels" / "finding.html"
CSS = PACKAGE / "static" / "stackarmor_vdr" / "css" / "finding.css"
ENGINE = Engine(dirs=[str(PACKAGE / "templates")])


def rows() -> list[dict[str, Any]]:
    built = build(row_for("high high high".split(), "medium medium medium".split(), 1), extra(), PARAMS)  # type: ignore[arg-type]
    return [{"kind": "breakdown", **b} for b in built["breakdown"]] + [{"kind": "step", **s} for s in built["steps"]]


def render(part: str, data: list[dict[str, Any]] | None) -> str:
    context = finding.finding_context(part, data)
    template = ENGINE.from_string(TEMPLATE.read_text(encoding="utf-8"))
    return template.render(Context({"panel": SimpleNamespace(config={"hide_header": True}, name="P"), **context}))


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-1")
def test_registered_with_a_described_config() -> None:
    schema = finding.FINDING_PANEL_CONFIG_SCHEMA
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["required"] == ["part"] and schema["additionalProperties"] is False
    assert all(p.get("description") for p in schema["properties"].values())
    assert finding.StackarmorFindingPanelType.slug == "stackarmor_finding"
    assert finding.validate_config({"part": "breakdown"}) is None
    for bad in ({}, {"part": "other"}, {"part": "breakdown", "x": 1}):
        assert finding.validate_config(bad)
    assert "stackarmor_finding" in (PACKAGE / "apps.py").read_text(encoding="utf-8") or "StackarmorFindingPanelType" in (PACKAGE / "apps.py").read_text(encoding="utf-8")


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-2")
def test_one_line_to_a_field_and_no_table() -> None:
    html = render("breakdown", rows())
    assert html.count('class="sa-find-line"') == 10 and "<table" not in html and "<td" not in html
    assert html.index(">Profile<") < html.index(">Impact<") < html.index(">Deadline<")


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-3")
def test_values_jump_to_a_step_that_exists_once() -> None:
    top, walk = render("breakdown", rows()), render("walkthrough", rows())
    targets = set(re.findall(r'href="#(step-\d+)"', top))
    assert targets and all(walk.count(f'id="{t}"') == 1 for t in targets)


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-4")
def test_two_columns_in_step_order() -> None:
    html = render("walkthrough", rows())
    assert html.count('class="sa-find-step__desc"') == 12 and html.count('class="sa-find-step__values"') == 12
    assert [int(n) for n in re.findall(r'sa-find-step__n">(\d+)<', html)] == list(range(1, 13))
    css = CSS.read_text(encoding="utf-8")
    assert "grid-template-columns" in css and "@container" in css


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-5")
def test_detail_is_a_closed_details_element() -> None:
    html = render("walkthrough", rows())
    assert html.count("<details") == 12 and " open" not in html.split("<details")[1].split(">")[0]
    assert "<script" not in html


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-6")
def test_assumed_is_marked_in_words() -> None:
    data = rows()
    for r in data:
        if r.get("key") == "impact":
            r["assumed"] = True
    assert ">assumed<" in render("breakdown", data)
    assert ">assumed<" not in render("breakdown", [dict(r, assumed=False) for r in data])


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-7")
def test_text_is_escaped() -> None:
    data = rows()
    data[0]["value"] = "<script>alert(1)</script>"
    data[-1]["summary"] = "<img src=x onerror=1>"
    data[-1]["inputs"] = [{"label": "<b>", "value": "<i>", "assumed": False}]
    html = render("breakdown", data) + render("walkthrough", data)
    assert "<script>" not in html and "<img" not in html and "<b>" not in html and "&lt;script&gt;" in html
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "|safe" not in source and "autoescape off" not in source


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-8")
def test_the_panel_does_no_arithmetic() -> None:
    source = TEMPLATE.read_text(encoding="utf-8") + Path(finding.__file__).read_text(encoding="utf-8")
    assert not re.search(r"\|\s*(add|floatformat|divisibleby)\b|Decimal|float\(|round\(", source)
    shown = render("walkthrough", rows())
    assert all(step["summary"] in shown.replace("&amp;", "&") for step in [r for r in rows() if r["kind"] == "step"])


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-9")
def test_failure_and_not_found_are_shown_not_raised() -> None:
    assert "could not be read" in render("breakdown", None)
    assert "No finding matches" in render("walkthrough", [])
    panel = SimpleNamespace(config={"part": "nope"}, name="P")
    assert finding.StackarmorFindingPanelType.get_view_context(panel, None)["state"] == "bad_config"  # type: ignore[arg-type]


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-10")
def test_stylesheet_uses_theme_tokens_only() -> None:
    css = CSS.read_text(encoding="utf-8")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(\s*\d", css)
    assert "var(--tap-" in css


@pytest.mark.spec("req-stackarmor-vdr-panel-finding-11")
def test_prints_without_splitting_a_step() -> None:
    css = CSS.read_text(encoding="utf-8")
    assert "@media print" in css and "break-inside: avoid" in css.split("@media print")[1]
