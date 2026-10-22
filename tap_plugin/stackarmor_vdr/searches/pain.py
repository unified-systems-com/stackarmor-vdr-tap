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

from collections import Counter, defaultdict
from decimal import Decimal
from typing import Any

from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.fedramp_20x_vdr.deadlines import deadline_hours
from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors
from tap_plugin.fedramp_20x_vdr.levels import exposure_column, reduce_profiles
from tap_plugin.fedramp_20x_vdr.searches.reach import reach_rows

from tap_grid.grift.subgraph import serialize_edge_full, serialize_edge_lite, serialize_node_full, serialize_node_lite
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
        "vuln_id": {"type": "string", "description": "Only the rows of one vulnerability (stackarmor-pain)."},
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
) -> dict[str, list[tuple[tuple[str | None, ...], tuple[str, ...], int | None]]]:
    """For each program, one `(levels, origins, multi_agency)` per stamp of the scheme.

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
    out: dict[str, list[tuple[tuple[str | None, ...], tuple[str, ...], int | None]]] = defaultdict(list)
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
        out[str(program)].append((tuple(levels), tuple(origins), row.multi_agency))
    return out


def resolve_programs(
    program_ids: list[str], scheme: str, *, db_alias: str
) -> dict[str, tuple[tuple[str, str, str], str, bool, int | None]]:
    """`{program: ((cr, ir, ar), profile_source, stamped, multi_agency)}`.

    An unstamped program is High and `unclassified`. `multi_agency` is the highest value any of the program's stamps states
    (1 beats 0), or None when no stamp states one.
    """
    stamps = _stamp_triples(sorted(set(program_ids)), scheme, db_alias=db_alias)
    out: dict[str, tuple[tuple[str, str, str], str, bool, int | None]] = {}
    for program in set(program_ids):
        found = stamps.get(program, [])
        profile = reduce_profiles([levels for levels, _, _ in found])
        origins = {origin for _, got, _ in found for origin in got}
        if not found or "none" in origins:
            source = "unclassified"
        elif "archetype" in origins:
            source = "archetype"
        else:
            source = "override"
        stated = [m for _, _, m in found if m is not None]
        out[program] = (profile, source, bool(found), max(stated) if stated else None)
    return out


def _vulnerabilities(vuln_ids: list[str], *, db_alias: str) -> dict[str, Any]:
    return {
        str(row.entity_id): row
        for row in read_scope.node_relation(
            read_scope.DEFAULT_SCOPE, ComplianceVulnerability, db_alias=db_alias
        ).filter(entity_id__in=sorted(set(vuln_ids)))
    }


def pain_rows(p: dict[str, Any], *, db_alias: str) -> list[dict[str, Any]]:
    """Every scored row for already-defaulted inputs `p`; the one computation both Search runners share."""
    reach = reach_rows({"entity_id": p["entity_id"]} if p.get("entity_id") else {}, db_alias=db_alias)
    program_ids = [prog["id"] for row in reach for prog in row["programs"]]
    resolved = resolve_programs(program_ids, p["scheme"], db_alias=db_alias)
    vulns = _vulnerabilities([row["vuln_id"] for row in reach], db_alias=db_alias)
    backed = backed_factors([row["finding_id"] for row in reach], scheme=p["evaluation_scheme"], db_alias=db_alias)
    rows: list[dict[str, Any]] = []
    for r in reach:
        if r["owner_kind"] == "program":
            cr_ir_ar, profile_source, _, stated = resolved[r["owner_id"]]
            stated_all = [stated]
        else:
            # A container (or an owner the grid could not name) is the reduction of the programs involved.
            cr_ir_ar = reduce_profiles([resolved[prog["id"]][0] for prog in r["programs"]])
            profile_source = "container"
            stated_all = [resolved[prog["id"]][3] for prog in r["programs"]] or [None]
        # The flag: what the stamps say, the higher value winning; a program that says nothing counts as the input default.
        multi_agency = max(p["multi_agency"] if m is None else m for m in stated_all)
        multi_agency_source = "stamp" if all(m is not None for m in stated_all) else "assumed"
        vuln = vulns.get(r["vuln_id"])
        impact = parse_impact(getattr(vuln, "cvss_vector", None), getattr(vuln, "cvss_version", None))
        result = score(
            impact.vector,
            cr_ir_ar,
            multi_agency,
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
                "m": multi_agency,
                "multi_agency_source": multi_agency_source,
                "pain": result.pain,
                "pain_rank": int(result.pain[1:]),
                "lev": lev,
                "irv": irv,
                "column": column,
                "fedramp_class": p["fedramp_class"],
                "deadline_hours": deadline_hours(p["fedramp_class"], result.pain, column, db_alias=db_alias),
            }
        )
    return rows


def stackarmor_pain(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per open finding per owner per container, each with the score and every input behind it.

    req-stackarmor-vdr-search-1
    """
    p = _with_defaults(inputs)
    rows = pain_rows(p, db_alias=db_alias)
    if p.get("vuln_id"):
        rows = [r for r in rows if r["vuln_id"] == p["vuln_id"]]
    return _envelope(rows, p["max_results"])


SUMMARY_VIEWS = ("by_pain", "assumptions")
SUMMARY_INPUT_SCHEMA: dict[str, Any] = {
    **INPUT_SCHEMA,
    "properties": {
        **{k: v for k, v in INPUT_SCHEMA["properties"].items() if k not in ("entity_id", "vuln_id", "max_results")},
        "view": {"type": "string", "enum": list(SUMMARY_VIEWS), "default": "by_pain"},
    },
}


def stackarmor_summary(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """Counts of the `stackarmor-pain` rows, for charts and cards (`req-stackarmor-vdr-summary`).

    `by_pain`: one row for each N-level N1 to N5 (`pain`, `rows`, `percent`). `assumptions`: one row of counts
    (`rows`, `unclassified`, `container_owned`, `archetype`, `override`, `assumed_impact`, `assumed_agency`,
    `stamped_agency`), so a reader sees how much of the result is the conservative result.
    """
    props = SUMMARY_INPUT_SCHEMA["properties"]
    unknown = sorted(set(inputs) - set(props))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    view = inputs.get("view", props["view"]["default"])
    if view not in SUMMARY_VIEWS:
        raise ValueError(f"view must be one of {', '.join(SUMMARY_VIEWS)}")
    p = _with_defaults({k: v for k, v in inputs.items() if k != "view"})
    rows = pain_rows(p, db_alias=db_alias)
    if view == "by_pain":
        counts = Counter(r["pain"] for r in rows)
        out = [
            {
                "pain": level,
                "rows": counts.get(level, 0),
                "percent": round(100 * counts.get(level, 0) / len(rows), 1) if rows else None,
            }
            for level in ("N1", "N2", "N3", "N4", "N5")
        ]
    else:
        source = Counter(r["profile_source"] for r in rows)
        out = [
            {
                "rows": len(rows),
                "unclassified": source.get("unclassified", 0),
                "container_owned": source.get("container", 0),
                "archetype": source.get("archetype", 0),
                "override": source.get("override", 0),
                "assumed_impact": sum(1 for r in rows if r["impact_source"] == "assumed"),
                "assumed_agency": sum(1 for r in rows if r["multi_agency_source"] == "assumed"),
                "stamped_agency": sum(1 for r in rows if r["multi_agency_source"] == "stamp"),
            }
        ]
    return {"nodes": [], "edges": [], "rows": out, "info": {"row_count": len(out)}, "warnings": {}}


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


RUNS_PACKAGE_EDGE = "RUNS_PACKAGE__computing_core"
TRACE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "entity_id": {"type": "string", "description": "The finding whose objects are shown (required)."},
        "scheme": {"type": "string", "minLength": 1, "default": "stackarmor", "description": "Stamp scheme to read."},
    },
}


def stackarmor_trace(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """The objects behind one finding's score, as a graph: the finding, its vulnerability, the component, the owner and
    container, the programs involved, their stamps and the archetypes the stamps name, with the edges among them.

    Returns `nodes` and `edges` (no rows). The component's route to the program is shown only as far as the grid's own edges
    between these objects go (the program's `RUNS_PACKAGE` roots are included); a longer dependency route is not drawn.

    req-stackarmor-vdr-trace
    """
    unknown = sorted(set(inputs) - set(TRACE_INPUT_SCHEMA["properties"]))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    finding = inputs.get("entity_id")
    if not isinstance(finding, str) or not finding:
        raise ValueError("entity_id must be the id of a finding")
    scheme = inputs.get("scheme", TRACE_INPUT_SCHEMA["properties"]["scheme"]["default"])
    scope = read_scope.DEFAULT_SCOPE
    reach = reach_rows({"entity_id": finding}, db_alias=db_alias)
    ids: set[str] = {finding}
    programs: set[str] = set()
    for r in reach:
        ids.update(x for x in (r["vuln_id"], r["component_id"], r["owner_id"], r["container_id"]) if x)
        programs.update(prog["id"] for prog in r["programs"])
    ids.update(programs)
    edges_rel = read_scope.edge_relation(scope, db_alias=db_alias)
    ids.update(
        str(t)
        for t in edges_rel.filter(edge_type=RUNS_PACKAGE_EDGE, from_entity_id__in=sorted(programs)).values_list(
            "to_entity_id", flat=True
        )
    )
    stamp_ids = {
        str(f)
        for f in edges_rel.filter(edge_type=PROFILES_EDGE, to_entity_id__in=sorted(programs)).values_list(
            "from_entity_id", flat=True
        )
    }
    stamps = {
        str(row.entity_id)
        for row in read_scope.node_relation(scope, AssetProfile, db_alias=db_alias).filter(
            entity_id__in=sorted(stamp_ids), scheme=scheme
        )
    }
    ids.update(stamps)
    ids.update(
        str(a)
        for a in edges_rel.filter(edge_type=ARCHETYPE_EDGE, from_entity_id__in=sorted(stamps)).values_list(
            "to_entity_id", flat=True
        )
    )
    entities = list(read_scope.node_relation(scope, None, db_alias=db_alias).filter(pk__in=sorted(ids)))
    live = {str(e.pk) for e in entities}
    edge_rows = list(edges_rel.filter(from_entity_id__in=sorted(live), to_entity_id__in=sorted(live)))
    nodes = [serialize_node_lite(e) if layer == "lite" else serialize_node_full(e) for e in entities]
    edges = [serialize_edge_lite(e) if layer == "lite" else serialize_edge_full(e) for e in edge_rows]
    return {
        "nodes": nodes,
        "edges": edges,
        "rows": [],
        "info": {"node_count": len(nodes), "edge_count": len(edges)},
        "warnings": {}
        if reach
        else {"no_owner": ["the grid ties this finding to no owner, so only the finding is shown"]},
    }
