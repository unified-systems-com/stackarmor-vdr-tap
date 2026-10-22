"""stackarmor_prose: styled prose from config text (``req-stackarmor-vdr-panel-prose``).

The panel reads only its own config, runs no Search and writes no markup: the text is parsed here into plain
strings and the template renders them with Django's autoescaping, so a ``<script>`` in the text stays text.

Variants:

- ``plain`` (the default): each blank-line-separated block is a paragraph, its lines kept.
- ``method``: a magazine-style explanation. The first block is the lead; a line shaped ``Label: text`` runs the
  label in as a small head; a line with no label that holds `` = `` is a formula; a block of formulas is set apart.
- ``steps``: a numbered vertical stepper. Lines shaped ``1. Title: description``, ``2) Title: description`` or
  ``- Title: description`` are the steps; text before the first step is an intro and text after the last is a note.
  With no such lines every blank-line-separated block is a step.

This module imports no Django, so the parsing and the schema are testable without it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

import jsonschema

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_web.models import Panel

VARIANTS = ("plain", "method", "steps")
DEFAULT_VARIANT = "plain"

PROSE_PANEL_CONFIG_SCHEMA: dict[str, Any] = {
    "description": (
        "Config of a stackarmor_prose panel: the text to set and how to set it. The text is escaped on render; "
        "markup in it is shown as text, never run."
    ),
    "type": "object",
    "additionalProperties": False,
    "required": ["text"],
    "properties": {
        "text": {
            "description": (
                "The prose. Blank lines separate blocks. In the steps variant, lines such as '1. Title: description' "
                "or '- Title: description' are the steps."
            ),
            "type": "string",
        },
        "variant": {
            "description": "How the text is set: plain (paragraphs), method (a lead and run-in heads) or steps (a numbered stepper). Default plain.",
            "type": "string",
            "enum": list(VARIANTS),
        },
        "hide_header": {
            "description": "True hides the panel header bar.",
            "type": "boolean",
        },
    },
}

_ITEM_PREFIX = re.compile(r"^(?:\d{1,3}[.)]|[-*•])\s+")
_LABELLED = re.compile(r"^([^:]{1,40}?):\s+(\S.*)$")
_BLOCK_SPLIT = re.compile(r"\n[ \t]*\n")


def split_blocks(text: str) -> list[list[str]]:
    """Blank-line-separated blocks, each a list of its non-empty stripped lines."""
    blocks = []
    for raw in _BLOCK_SPLIT.split(text.replace("\r\n", "\n").replace("\r", "\n")):
        lines = [line.strip() for line in raw.split("\n") if line.strip()]
        if lines:
            blocks.append(lines)
    return blocks


def split_label(line: str) -> tuple[str, str]:
    """``("Label", "rest")`` for a line shaped ``Label: rest`` (label at most 40 characters), else ``("", line)``."""
    found = _LABELLED.match(line)
    return (found.group(1), found.group(2)) if found else ("", line)


def plain_context(text: str) -> dict[str, Any]:
    return {"paragraphs": split_blocks(text)}


def method_context(text: str) -> dict[str, Any]:
    paragraphs = []
    for lines in split_blocks(text):
        rows = []
        for line in lines:
            label, rest = split_label(line)
            rows.append({"label": label, "text": rest, "formula": not label and " = " in line})
        paragraphs.append({"lines": rows, "formula": all(row["formula"] for row in rows)})
    return {"paragraphs": paragraphs}


def steps_context(text: str) -> dict[str, Any]:
    blocks = split_blocks(text)
    lines = [line for block in blocks for line in block]
    intro: list[str] = []
    steps: list[dict[str, str]] = []
    notes: list[str] = []
    if any(_ITEM_PREFIX.match(line) for line in lines):
        for line in lines:
            if _ITEM_PREFIX.match(line):
                title, body = split_label(_ITEM_PREFIX.sub("", line, count=1))
                steps.append({"title": title, "body": body})
            elif steps:
                notes.append(line)
            else:
                intro.append(line)
    else:
        for block in blocks:
            title, body = split_label(" ".join(block))
            steps.append({"title": title, "body": body})
    return {"intro": intro, "steps": steps, "notes": notes}


_BUILDERS = {"plain": plain_context, "method": method_context, "steps": steps_context}


def validate_config(config: Any) -> str | None:
    """None when the config is valid, else the first problem as a short sentence."""
    try:
        jsonschema.validate(config, PROSE_PANEL_CONFIG_SCHEMA)
    except jsonschema.ValidationError as exc:
        where = "/".join(str(p) for p in exc.absolute_path)
        return f"{where}: {exc.message}" if where else exc.message
    return None


class StackarmorProsePanelType:
    slug = "stackarmor_prose"
    label = "StackArmor Prose"
    view = "stackarmor_vdr/panels/prose.html"
    css: ClassVar[list[str]] = ["stackarmor_vdr/css/prose.css"]
    js: ClassVar[list[str]] = []
    editor_view = ""
    config_defaults: ClassVar[dict[str, Any]] = {}

    @classmethod
    def get_view_context(cls, panel: Panel, request: HttpRequest) -> dict[str, Any]:
        config = panel.config if isinstance(panel.config, dict) else {}
        problem = validate_config(config)
        if problem:
            return {"state": "bad_config", "detail": problem}
        variant = config.get("variant", DEFAULT_VARIANT)
        return {"state": "ok", "variant": variant, **_BUILDERS[variant](config["text"])}
