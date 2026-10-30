"""Run the one Search a panel is linked to by a ``USES_SEARCH`` edge (shared by the plugin's panels that read a Search)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_web.models import Panel


def run_linked_search(panel: Panel, request: HttpRequest | None, logger: logging.Logger, tag: str) -> list[dict[str, Any]] | None:
    """The rows of the linked Search, or None when it could not run; the error text is logged by class only."""
    from tap_grid.models import Edge, Search
    from tap_grid.search import execute_search, inputs_from_query

    targets = sorted(
        str(t) for t in Edge.objects.filter(from_entity=panel.entity, edge_type="USES_SEARCH").values_list("to_entity_id", flat=True)
    )
    search = Search.objects.filter(entity_id__in=targets).order_by("entity_id").first() if targets else None
    if search is None:
        return None
    try:
        inputs = inputs_from_query(search, request.GET) if request is not None else {}
        result = execute_search(search, inputs or None, layer="extended")
    except Exception as exc:  # noqa: BLE001
        logger.error("[%s] panel search %s failed (%s)", tag, getattr(search, "entity_id", "?"), type(exc).__name__)
        return None
    envelope = result["results"] if "results" in result else result
    return [r for r in (envelope.get("rows") or []) if isinstance(r, dict)]
