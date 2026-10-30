"""stackarmor_html: cleaned, styled HTML from config or from a field of a linked Search (`req-stackarmor-vdr-panel-html`).

The markup is untrusted wherever it comes from, so it is cleaned on every render by `htmlsafe` against a policy built from this
panel's config (a closed vocabulary of named features: the config can only narrow it). The cleaned string is marked safe in
exactly one place, `_safe`, below. If cleaning fails for any reason the panel shows a message and no content, never the
original markup and never an escaped copy of it. This module names nothing of the StackArmor method.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar

import jsonschema
from django.utils.safestring import mark_safe

from .. import htmlsafe
from .linked import run_linked_search

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_web.models import Panel

logger = logging.getLogger(__name__)

HTML_PANEL_CONFIG_SCHEMA: dict[str, Any] = {
    "description": (
        "Config of a stackarmor_html panel: where the markup comes from and which features of the closed HTML vocabulary it may "
        "use. Exactly one of html and field. The markup is cleaned on every render; the settings below can only narrow what "
        "the vocabulary allows. Script, style, forms, frames, SVG and MathML cannot be enabled."
    ),
    "type": "object",
    "additionalProperties": False,
    "oneOf": [{"required": ["html"]}, {"required": ["field"]}],
    "properties": {
        "html": {"description": "The markup, written in the config.", "type": "string", "maxLength": htmlsafe.MAX_BYTES_CEILING},
        "field": {"description": "The row field of the linked Search that holds the markup.", "type": "string", "minLength": 1, "maxLength": 100},
        "row": {"description": "Index of the row to read with field. Default 0.", "type": "integer", "minimum": 0},
        "features": {
            "description": "Features allowed, from the vocabulary; text is always on. Default: every feature but images.",
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "enum": sorted(htmlsafe.FEATURES)},
        },
        "classes": {
            "description": "Style classes that survive, from the plugin's list. Default: all of them.",
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "enum": sorted(htmlsafe.CLASSES)},
        },
        "link_schemes": {
            "description": "URL schemes a link may use besides paths on this site. Default: http, https and mailto.",
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "enum": list(htmlsafe.SCHEMES)},
        },
        "link_hosts": {
            "description": "Host names an http or https link may point at. Default: any host.",
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "pattern": htmlsafe.HOST_RE.pattern},
        },
        "image_prefixes": {
            "description": "Path prefixes on this site an image may come from. Default: /static/.",
            "type": "array",
            "maxItems": 10,
            "items": {"type": "string", "pattern": htmlsafe.PATH_PREFIX_RE.pattern},
        },
        "max_bytes": {
            "description": "Largest document accepted, in bytes.",
            "type": "integer",
            "minimum": 1,
            "maximum": htmlsafe.MAX_BYTES_CEILING,
        },
        "hide_header": {"description": "True hides the panel header bar.", "type": "boolean"},
    },
}


def validate_config(config: Any) -> str | None:
    try:
        jsonschema.validate(config, HTML_PANEL_CONFIG_SCHEMA)
        htmlsafe.Policy.from_config(config)
    except jsonschema.ValidationError as exc:
        return exc.message
    except ValueError as exc:
        return str(exc)
    return None


def _safe(cleaned: str) -> Any:
    """The one place markup is marked safe: the output of `htmlsafe.clean`, and nothing else."""
    return mark_safe(cleaned)  # noqa: S308


def html_context(config: dict[str, Any], rows: list[dict[str, Any]] | None) -> dict[str, Any]:
    """The template context. ``rows`` is the linked Search's rows (None when it failed), used only with ``field``."""
    if "html" in config:
        source: Any = config["html"]
    else:
        if rows is None:
            return {"state": "failed"}
        index = config.get("row", 0)
        row = rows[index] if 0 <= index < len(rows) else None
        source = row.get(config["field"]) if row else None
        if source is None:
            return {"state": "empty"}
        if not isinstance(source, str):
            return {"state": "not_text"}
    if not source.strip():
        return {"state": "empty"}
    try:
        cleaned = htmlsafe.clean(source, htmlsafe.Policy.from_config(config))
    except htmlsafe.CleanerUnavailable:
        logger.error("[8c41] html panel: the cleaner is not installed")
        return {"state": "unavailable"}
    except htmlsafe.HtmlRefused as exc:
        return {"state": "refused", "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.error("[8c42] html panel: cleaning failed (%s)", type(exc).__name__)
        return {"state": "unavailable"}
    return {"state": "ok", "content": _safe(cleaned.html), "removed": cleaned.removed}


class StackarmorHtmlPanelType:
    slug: ClassVar[str] = "stackarmor_html"
    label: ClassVar[str] = "StackArmor HTML"
    view: ClassVar[str] = "stackarmor_vdr/panels/html.html"
    css: ClassVar[list[str]] = ["stackarmor_vdr/css/html.css"]
    js: ClassVar[list[str]] = []
    editor_view: ClassVar[str] = ""
    config_defaults: ClassVar[dict[str, Any]] = {}

    @classmethod
    def get_view_context(cls, panel: Panel, request: HttpRequest) -> dict[str, Any]:
        config = panel.config if isinstance(panel.config, dict) else {}
        problem = validate_config(config)
        if problem:
            return {"state": "bad_config", "detail": problem}
        rows = run_linked_search(panel, request, logger, "8c43") if "field" in config else None
        return html_context(config, rows)
