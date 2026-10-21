"""The stackArmor PAIN Searches, as `module` Search runners (`req-stackarmor-vdr-search`).

`stackarmor-pain` scores every open vulnerability finding the base's reach (`fedramp_20x_vdr`) ties to an owner: it reads the
profile stamps of the programs involved, reduces them with the base's reducer, then computes the impact, the score, the
exposure and the deadline. `stackarmor-assets` shows the profile each node resolves to, from the programs it runs. Both read
through `tap_grid.gryphon.read_scope` with the caller's `db_alias`, return rows and write nothing; the Search nodes that point
at them are the instance's.

A row whose `profile_source` is `unclassified` or `container`, or whose `multi_agency_source` is `assumed`, is the
conservative compatibility result and is not an evidenced, agency-specific derivation of the method.

Parameters live in ``INPUT_SCHEMA``, once: a Search node copies it as its ``input_schema`` and the runner fills any missing
input from it, so a caller that passes nothing gets the same answer as the Search. The archetype catalog is not here; it is
the `archetype` nodes.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from typing import Any

from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.fedramp_20x_vdr.deadlines import deadline_hours
from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors
from tap_plugin.fedramp_20x_vdr.levels import exposure_column, reduce_profiles
from tap_plugin.fedramp_20x_vdr.searches.reach import reach_rows

from tap_grid.gryphon import read_scope
from tap_grid.models import Search

from ..exposure import likely_exploitable
from ..impact import parse_impact
from ..models.archetype import Archetype
from ..models.asset_profile import AssetProfile
from ..score import score

PROFILES_EDGE = "PROFILES_PROGRAM__stackarmor_vdr"
ARCHETYPE_EDGE = "USES_ARCHETYPE__stackarmor_vdr"
RUNS_PROGRAM_EDGE = "RUNS_PROGRAM__computing_core"
DEFAULT_MAX_RESULTS = 1000
MAX_RESULTS = 5000
_NUMBER: dict[str, Any] = {"type": "number", "minimum": 0}

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "impact_weights": {
            "type": "object",
            "description": "CVSS impact weights by level.",
            "default": {"none": 0, "low": 0.22, "high": 0.56},
            "required": ["none", "low", "high"],
            "additionalProperties": False,
            "properties": {"none": _NUMBER, "low": _NUMBER, "high": _NUMBER},
        },
        "requirement_weights": {
            "type": "object",
            "description": "Security requirement weights by level.",
            "default": {"low": 0.5, "medium": 1.0, "high": 1.5},
            "required": ["low", "medium", "high"],
            "additionalProperties": False,
            "properties": {"low": _NUMBER, "medium": _NUMBER, "high": _NUMBER},
        },
        "u1": {**_NUMBER, "default": 0.28, "description": "U below this is Minimal (the memo's theta1 times D_H)."},
        "u2": {**_NUMBER, "default": 0.56, "description": "U below this is Narrow (the memo's theta2 times D_H)."},
        "theta3": {
            **_NUMBER,
            "default": 0.933,
            "description": "S below this is Disruptive, at or above it Debilitating.",
        },
        "epss_irv": {**_NUMBER, "default": 0.20, "description": "EPSS threshold for an internet-reachable row."},
        "epss_non_irv": {**_NUMBER, "default": 0.55, "description": "EPSS threshold for a row that is not."},
        "multi_agency": {"type": "integer", "enum": [0, 1], "default": 1, "description": "The affected-agency flag m."},
        "fedramp_class": {"type": "string", "enum": ["a", "b", "c", "d"], "default": "d"},
        "scheme": {"type": "string", "minLength": 1, "default": "stackarmor", "description": "Stamp scheme to read."},
        "evaluation_scheme": {
            "type": "string",
            "minLength": 1,
            "default": "max",
            "description": "Evaluation scheme to read.",
        },
        "entity_id": {
            "type": "string",
            "description": "One finding (stackarmor-pain) or one node (stackarmor-assets).",
        },
        "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "default": DEFAULT_MAX_RESULTS},
    },
}

_UNSTAMPED = (None, None, None)


def _with_defaults(inputs: dict[str, Any]) -> dict[str, Any]:
    props = INPUT_SCHEMA["properties"]
    unknown = sorted(set(inputs) - set(props))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    merged = {key: sub["default"] for key, sub in props.items() if "default" in sub}
    merged.update({k: v for k, v in inputs.items() if v is not None})
    return merged


def _fmt(value: Decimal) -> str:
    return f"{value:.6f}"


def _stamp_triples(
    program_ids: list[str], scheme: str, *, db_alias: str
) -> dict[str, list[tuple[tuple[str | None, ...], tuple[str, ...]]]]:
    """For each program, one `(levels, origins)` per stamp of the scheme.

    ``levels`` is the stamp's value per objective (an explicit value, else the highest value of the archetypes it names,
    else None), and ``origins`` is `explicit`, `archetype` or `none` for each.
    """
    scope = read_scope.DEFAULT_SCOPE
    edges = read_scope.edge_relation(scope, db_alias=db_alias)
    pairs = list(
        edges.filter(edge_type=PROFILES_EDGE, to_entity_id__in=program_ids).values_list(
            "from_entity_id", "to_entity_id"
        )
    )
    stamp_ids = sorted({str(stamp) for stamp, _ in pairs})
    stamps = {
        str(row.entity_id): row
        for row in read_scope.node_relation(scope, AssetProfile, db_alias=db_alias).filter(
            entity_id__in=stamp_ids, scheme=scheme
        )
    }
    names: dict[str, list[str]] = defaultdict(list)  # stamp -> archetype ids
    for stamp, archetype in edges.filter(edge_type=ARCHETYPE_EDGE, from_entity_id__in=sorted(stamps)).values_list(
        "from_entity_id", "to_entity_id"
    ):
        names[str(stamp)].append(str(archetype))
    archetypes = {
        str(row.entity_id): (row.cr, row.ir, row.ar)
        for row in read_scope.node_relation(scope, Archetype, db_alias=db_alias).filter(
            entity_id__in=sorted({a for ids in names.values() for a in ids})
        )
    }
    out: dict[str, list[tuple[tuple[str | None, ...], tuple[str, ...]]]] = defaultdict(list)
    for stamp, program in pairs:
        row = stamps.get(str(stamp))
        if row is None:
            continue  # another scheme, or tombstoned
        named = [archetypes[a] for a in names.get(str(stamp), []) if a in archetypes]
        from_archetype = reduce_profiles(named) if named else _UNSTAMPED
        levels: list[str | None] = []
        origins: list[str] = []
        for explicit, inherited in zip((row.cr, row.ir, row.ar), from_archetype, strict=True):
            if explicit:
                levels.append(explicit)
                origins.append("explicit")
            elif inherited:
                levels.append(inherited)
                origins.append("archetype")
            else:
                levels.append(None)
                origins.append("none")
        out[str(program)].append((tuple(levels), tuple(origins)))
    return out


def resolve_programs(
    program_ids: list[str], scheme: str, *, db_alias: str
) -> dict[str, tuple[tuple[str, str, str], str, bool]]:
    """`{program: ((cr, ir, ar), profile_source, stamped)}`; an unstamped program is High and `unclassified`."""
    stamps = _stamp_triples(sorted(set(program_ids)), scheme, db_alias=db_alias)
    out: dict[str, tuple[tuple[str, str, str], str, bool]] = {}
    for program in set(program_ids):
        found = stamps.get(program, [])
        profile = reduce_profiles([levels for levels, _ in found])
        origins = {origin for _, got in found for origin in got}
        if not found or "none" in origins:
            source = "unclassified"
        elif "archetype" in origins:
            source = "archetype"
        else:
            source = "override"
        out[program] = (profile, source, bool(found))
    return out


def _vulnerabilities(vuln_ids: list[str], *, db_alias: str) -> dict[str, Any]:
    return {
        str(row.entity_id): row
        for row in read_scope.node_relation(
            read_scope.DEFAULT_SCOPE, ComplianceVulnerability, db_alias=db_alias
        ).filter(entity_id__in=sorted(set(vuln_ids)))
    }


def stackarmor_pain(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per open finding per owner per container, each with the score and every input behind it.

    req-stackarmor-vdr-search-1
    """
    p = _with_defaults(inputs)
    reach = reach_rows({"entity_id": p["entity_id"]} if p.get("entity_id") else {}, db_alias=db_alias)
    program_ids = [prog["id"] for row in reach for prog in row["programs"]]
    resolved = resolve_programs(program_ids, p["scheme"], db_alias=db_alias)
    vulns = _vulnerabilities([row["vuln_id"] for row in reach], db_alias=db_alias)
    backed = backed_factors([row["finding_id"] for row in reach], scheme=p["evaluation_scheme"], db_alias=db_alias)
    rows: list[dict[str, Any]] = []
    for r in reach:
        if r["owner_kind"] == "program":
            cr_ir_ar, profile_source, _ = resolved[r["owner_id"]]
        else:
            # A container (or an owner the grid could not name) is the reduction of the programs involved.
            cr_ir_ar = reduce_profiles([resolved[prog["id"]][0] for prog in r["programs"]])
            profile_source = "container"
        vuln = vulns.get(r["vuln_id"])
        impact = parse_impact(getattr(vuln, "cvss_vector", None), getattr(vuln, "cvss_version", None))
        result = score(
            impact.vector,
            cr_ir_ar,
            p["multi_agency"],
            impact_weights=p["impact_weights"],
            requirement_weights=p["requirement_weights"],
            u1=p["u1"],
            u2=p["u2"],
            theta3=p["theta3"],
        )
        factors = backed[r["finding_id"]]
        irv = factors["internet_reachable"] is not False
        lev = likely_exploitable(
            factors["likely_exploitable"],
            getattr(vuln, "kev", None),
            getattr(vuln, "epss_score", None),
            internet_reachable=irv,
            epss_irv=p["epss_irv"],
            epss_non_irv=p["epss_non_irv"],
        )
        column = exposure_column(lev, factors["internet_reachable"])
        rows.append(
            {
                "finding_id": r["finding_id"],
                "vuln_id": r["vuln_id"],
                "component": r["component"],
                "component_id": r["component_id"],
                "container_id": r["container_id"],
                "container": r["container"],
                "owner_kind": r["owner_kind"],
                "owner_id": r["owner_id"],
                "owner": r["owner"],
                "scheme": p["scheme"],
                "profile_source": profile_source,
                "impact_source": impact.source,
                "c": impact.c,
                "i": impact.i,
                "a": impact.a,
                "subsequent": list(impact.subsequent) if impact.subsequent else None,
                "cr": cr_ir_ar[0],
                "ir": cr_ir_ar[1],
                "ar": cr_ir_ar[2],
                "u": _fmt(result.u),
                "s": _fmt(result.s),
                "word": result.word,
                "m": p["multi_agency"],
                "multi_agency_source": "assumed",
                "pain": result.pain,
                "lev": lev,
                "irv": irv,
                "column": column,
                "fedramp_class": p["fedramp_class"],
                "deadline_hours": deadline_hours(p["fedramp_class"], result.pain, column, db_alias=db_alias),
            }
        )
    return _envelope(rows, p["max_results"])


def stackarmor_assets(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per node that runs programs: the reduction of their resolved profiles, nothing stamped on the node.

    Row: `asset_id`, `asset`, `scheme`, `programs`, `classified`, `cr`, `ir`, `ar`.
    """
    p = _with_defaults(inputs)
    scope = read_scope.DEFAULT_SCOPE
    runs: dict[str, set[str]] = defaultdict(set)
    edges = read_scope.edge_relation(scope, db_alias=db_alias).filter(edge_type=RUNS_PROGRAM_EDGE)
    if p.get("entity_id"):
        edges = edges.filter(from_entity_id=p["entity_id"])
    for asset, program in edges.values_list("from_entity_id", "to_entity_id"):
        runs[str(asset)].add(str(program))
    resolved = resolve_programs([prog for ps in runs.values() for prog in ps], p["scheme"], db_alias=db_alias)
    names = {
        str(pk): name or ""
        for pk, name in read_scope.node_relation(scope, None, db_alias=db_alias)
        .filter(pk__in=sorted(runs))
        .values_list("pk", "name")
    }
    rows = []
    for asset in sorted(runs):
        programs = sorted(runs[asset])
        cr, ir, ar = reduce_profiles([resolved[prog][0] for prog in programs])
        rows.append(
            {
                "asset_id": asset,
                "asset": names.get(asset, ""),
                "scheme": p["scheme"],
                "programs": len(programs),
                "classified": sum(1 for prog in programs if resolved[prog][1] != "unclassified"),
                "cr": cr,
                "ir": ir,
                "ar": ar,
            }
        )
    return _envelope(rows, p["max_results"])


def _envelope(everything: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    rows = everything[:limit]
    warnings: dict[str, Any] = {}
    if len(everything) > len(rows):
        warnings["rows_omitted"] = [
            f"{len(everything) - len(rows)} of {len(everything)} rows were left out; max_results is {limit}"
        ]
    return {
        "nodes": [],
        "edges": [],
        "rows": rows,
        "info": {"row_count": len(rows), "total_rows": len(everything)},
        "warnings": warnings,
    }
