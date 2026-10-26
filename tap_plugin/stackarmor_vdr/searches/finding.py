"""`stackarmor-finding`: one finding on one component under one owner, explained step by step (`req-stackarmor-vdr-finding`).

The row is `stackarmor-pain`'s own (`pain_rows`), found by its key, so no number here is computed a second time. What the row
does not carry (the programs behind a container, the vulnerability's readings, the evidenced factors) is read through the same
reads `stackarmor-pain` uses, and the words and steps are built by the Django-free `walkthrough`. Rows only; nothing is written.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors
from tap_plugin.fedramp_20x_vdr.searches.reach import reach_rows

from ..walkthrough import build
from . import pain

if TYPE_CHECKING:
    from tap_grid.models import Search

KEY_INPUTS = ("finding_id", "component_id", "owner_id")
INPUT_SCHEMA: dict[str, Any] = {
    **pain.INPUT_SCHEMA,
    "required": list(KEY_INPUTS),
    "properties": {
        **{k: v for k, v in pain.INPUT_SCHEMA["properties"].items() if k not in ("entity_id", "vuln_id", "max_results")},
        "finding_id": {"type": "string", "minLength": 1, "description": "The finding (required)."},
        "component_id": {"type": "string", "minLength": 1, "description": "The component it is on (required)."},
        "owner_id": {"type": "string", "minLength": 1, "description": "The owner: a program or a container (required)."},
        "container_id": {"type": "string", "description": "The container, when one owner is reached through several."},
    },
}


def _matches(row: dict[str, Any], inputs: dict[str, Any]) -> bool:
    return (
        row["finding_id"] == inputs["finding_id"]
        and row["component_id"] == inputs["component_id"]
        and row["owner_id"] == inputs["owner_id"]
        and (not inputs.get("container_id") or row["container_id"] == inputs["container_id"])
    )


def stackarmor_finding(
    search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full"
) -> dict[str, Any]:
    """The breakdown and the twelve steps of one row, as rows told apart by `kind`.

    req-stackarmor-vdr-finding
    """
    props = INPUT_SCHEMA["properties"]
    unknown = sorted(set(inputs) - set(props))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    for key in KEY_INPUTS:
        if not isinstance(inputs.get(key), str) or not inputs[key]:
            raise ValueError(f"{key} must be given")
    scoring = {k: v for k, v in inputs.items() if k in pain.INPUT_SCHEMA["properties"]}
    p = pain._with_defaults({**scoring, "entity_id": inputs["finding_id"]})  # noqa: SLF001
    matched = [r for r in pain.pain_rows(p, db_alias=db_alias) if _matches(r, inputs)]
    if not matched:
        return {
            "nodes": [], "edges": [], "rows": [],
            "info": {"row_count": 0},
            "warnings": {"not_found": ["no stackarmor-pain row matches this finding, component and owner"]},
        }  # fmt: skip
    row = matched[0]
    reach = next(
        r
        for r in reach_rows({"entity_id": inputs["finding_id"]}, db_alias=db_alias)
        if r["component_id"] == row["component_id"]
        and r["owner_id"] == row["owner_id"]
        and r["container_id"] == row["container_id"]
    )
    program_ids = [prog["id"] for prog in reach["programs"]]
    resolved = pain.resolve_programs(program_ids, p["scheme"], db_alias=db_alias)
    vuln = pain._vulnerabilities([row["vuln_id"]], db_alias=db_alias).get(row["vuln_id"])  # noqa: SLF001
    factors = backed_factors([row["finding_id"]], scheme=p["evaluation_scheme"], db_alias=db_alias)[row["finding_id"]]
    extra = {
        "vuln": {
            "title": getattr(vuln, "title", None),
            "kev": getattr(vuln, "kev", None),
            "epss": getattr(vuln, "epss_score", None),
            "vector": getattr(vuln, "cvss_vector", None) or None,
            "version": getattr(vuln, "cvss_version", None) or None,
        },
        "programs": [
            {"name": prog["name"], "levels": resolved[prog["id"]][0], "source": resolved[prog["id"]][1], "m": resolved[prog["id"]][3]}
            for prog in reach["programs"]
        ],
        "factors": factors,
    }
    built = build(row, extra, p)
    out = [{"kind": "breakdown", **b} for b in built["breakdown"]] + [{"kind": "step", **s} for s in built["steps"]]
    return {"nodes": [], "edges": [], "rows": out, "info": {"row_count": len(out)}, "warnings": {}}
