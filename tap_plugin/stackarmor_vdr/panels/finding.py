"""stackarmor_finding: the walk-through of one finding, drawn from `stackarmor-finding` (`req-stackarmor-vdr-panel-finding`).

The panel runs the one Search it is linked to by a ``USES_SEARCH`` edge, with the page's query parameters as inputs, and
draws its rows: ``part: breakdown`` is one line per field, each value a link to the step that explains it, and
``part: walkthrough`` is one band per step, the description at the left and the values at the right. It computes nothing and
writes no markup: every string reaches the template as text and Django's autoescaping shows it as text.

The shaping (`finding_context`) is Django-free, so it is testable without settings or a database.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar

import jsonschema

from .linked import run_linked_search

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_web.models import Panel

logger = logging.getLogger(__name__)

PARTS = ("breakdown", "walkthrough")

FINDING_PANEL_CONFIG_SCHEMA: dict[str, Any] = {
    "description": (
        "Config of a stackarmor_finding panel: which part of the finding's walk-through it draws. The panel reads the one "
        "stackarmor-finding Search it is linked to by a USES_SEARCH edge; the page passes finding_id, component_id, owner_id "
        "and container_id in its query string."
    ),
    "type": "object",
    "additionalProperties": False,
    "required": ["part"],
    "properties": {
        "part": {
            "description": "breakdown: one line per field, each value linked to its step. walkthrough: one band per step.",
            "type": "string",
            "enum": list(PARTS),
        },
        "hide_header": {"description": "True hides the panel header bar.", "type": "boolean"},
    },
}


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _items(value: Any) -> list[dict[str, Any]]:
    out = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict):
            out.append({"label": _text(item.get("label")), "value": _text(item.get("value")), "assumed": item.get("assumed") is True})
    return out


def finding_context(part: str, rows: list[dict[str, Any]] | None) -> dict[str, Any]:
    """The template context for ``part`` from the Search's rows; ``None`` rows mean the Search failed."""
    if rows is None:
        return {"state": "failed"}
    breakdown = [
        {
            "label": _text(r.get("label")),
            "value": _text(r.get("value")),
            "assumed": r.get("assumed") is True,
            "step": r.get("step") if isinstance(r.get("step"), int) else None,
        }
        for r in rows
        if r.get("kind") == "breakdown"
    ]
    steps = [
        {
            "number": r.get("step") if isinstance(r.get("step"), int) else 0,
            "anchor": f"step-{r['step']}" if isinstance(r.get("step"), int) else "",
            "title": _text(r.get("title")),
            "summary": _text(r.get("summary")),
            "detail": _text(r.get("detail")),
            "inputs": _items(r.get("inputs")),
            "results": _items(r.get("results")),
        }
        for r in rows
        if r.get("kind") == "step"
    ]
    if not breakdown and not steps:
        return {"state": "not_found"}
    return {"state": "ok", "part": part, "breakdown": breakdown, "steps": steps}


def validate_config(config: Any) -> str | None:
    try:
        jsonschema.validate(config, FINDING_PANEL_CONFIG_SCHEMA)
    except jsonschema.ValidationError as exc:
        return exc.message
    return None


class StackarmorFindingPanelType:
    slug: ClassVar[str] = "stackarmor_finding"
    label: ClassVar[str] = "StackArmor Finding"
    view: ClassVar[str] = "stackarmor_vdr/panels/finding.html"
    css: ClassVar[list[str]] = ["stackarmor_vdr/css/finding.css"]
    js: ClassVar[list[str]] = []
    editor_view: ClassVar[str] = ""
    config_defaults: ClassVar[dict[str, Any]] = {}

    @classmethod
    def get_view_context(cls, panel: Panel, request: HttpRequest) -> dict[str, Any]:
        config = panel.config if isinstance(panel.config, dict) else {}
        problem = validate_config(config)
        if problem:
            return {"state": "bad_config", "detail": problem}
        return finding_context(config["part"], run_linked_search(panel, request, logger, "5b2e"))
