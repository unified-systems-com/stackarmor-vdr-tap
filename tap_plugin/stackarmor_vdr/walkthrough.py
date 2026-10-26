"""The walk-through of one scored row (`req-stackarmor-vdr-finding`). Pure and Django-free.

`build` takes the `stackarmor-pain` row, what the row does not carry (`extra`) and the scoring parameters, and returns the
breakdown and the twelve steps. Every figure is the row's own; the only numbers computed here are the per-dimension
products, which are intermediates of the row's `u` and are checked against it in the tests. The words are this plugin's:
each step's detail cites the stackArmor memo section it follows and names a local choice where the plugin departs from it.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from .score import d_h

MEMO = "the stackArmor memo"
LEVEL = {"none": "None", "low": "Low", "medium": "Medium", "high": "High"}
SOURCE_TEXT = {
    "override": "the stamp's own values",
    "archetype": "the archetype its stamp names",
    "container": "the programs the container runs",
    "unclassified": "no stamp, so the conservative default",
}


def _lv(level: str) -> str:
    return LEVEL.get(level, str(level))


def _item(label: str, value: Any, assumed: bool = False) -> dict[str, Any]:
    return {"label": label, "value": "" if value is None else str(value), "assumed": assumed}


def _fmt(value: Decimal) -> str:
    return f"{value:.6f}"


def _hours_text(hours: int | None, pain: str) -> str:
    if hours is None:
        return f"none ({pain} carries no timeframe)"
    days = Decimal(hours) / 24
    return f"{hours} hours ({days:.1f} days)"


def _assumptions(row: dict[str, Any], extra: dict[str, Any]) -> list[tuple[str, str]]:
    """`(short name, why)` for each value resting on a default."""
    out: list[tuple[str, str]] = []
    programs = extra["programs"]
    if row["profile_source"] == "unclassified" or any(p["source"] == "unclassified" for p in programs):
        out.append(("the profile", "an unclassified program counts as High on all three"))
    if row["impact_source"] == "assumed":
        out.append(("the impact", "no readable CVSS vector counts as High on all three"))
    if row["multi_agency_source"] == "assumed":
        out.append(("the agency flag", "the input default, not a stamp"))
    vuln = extra["vuln"]
    if vuln["kev"] is None or vuln["epss"] is None:
        out.append(("likelihood", "a missing KEV or EPSS reading counts as likely exploitable"))
    if extra["factors"]["internet_reachable"] is None:
        out.append(("reachability", "no evidence, so internet-reachable"))
    out.append(("the class", "the FedRAMP class is the Search input, not read from the system"))
    return out


def _bound_text(row: dict[str, Any], params: dict[str, Any]) -> str:
    u1, u2, theta3 = params["u1"], params["u2"], params["theta3"]
    word = row["word"]
    if word == "Minimal":
        return f"U is below {u1}"
    if word == "Narrow":
        return f"U is at least {u1} and below {u2}"
    if word == "Disruptive":
        return f"U is at least {u2} and S is below {theta3}"
    return f"U is at least {u2} and S is at least {theta3}"


def _setters(programs: list[dict[str, Any]], reduced: tuple[str, str, str]) -> list[str]:
    names = ("confidentiality", "integrity", "availability")
    out = []
    for position, name in enumerate(names):
        who = [p["name"] for p in programs if p["levels"][position] == reduced[position]]
        out.append(f"{name} {_lv(reduced[position])} from {', '.join(who) if who else 'no stamp'}")
    return out


def build(row: dict[str, Any], extra: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """`{"breakdown": [...], "steps": [...]}` for one `stackarmor-pain` row."""
    vuln, programs, factors = extra["vuln"], extra["programs"], extra["factors"]
    iw, rw = params["impact_weights"], params["requirement_weights"]
    ceiling = d_h(iw, rw)
    impact = (row["c"], row["i"], row["a"])
    req = (row["cr"], row["ir"], row["ar"])
    products = [Decimal(str(iw[a])) * Decimal(str(rw[b])) for a, b in zip(impact, req, strict=True)]
    container_owner = row["owner_kind"] == "container"
    assumed_list = _assumptions(row, extra)
    profile_assumed = row["profile_source"] in ("unclassified",) or any(p["source"] == "unclassified" for p in programs)
    impact_assumed = row["impact_source"] == "assumed"
    agency_assumed = row["multi_agency_source"] == "assumed"
    lev_assumed = vuln["kev"] is None or vuln["epss"] is None
    irv_assumed = factors["internet_reachable"] is None
    hours = _hours_text(row["deadline_hours"], row["pain"])
    cve = row.get("cve") or row["vuln_id"]
    yes = "yes" if row["lev"] else "no"
    reach = "internet-reachable" if row["irv"] else "not internet-reachable"
    profile_text = f"{_lv(row['cr'])} / {_lv(row['ir'])} / {_lv(row['ar'])}"
    impact_text = f"{_lv(row['c'])} / {_lv(row['i'])} / {_lv(row['a'])}"

    steps: list[dict[str, Any]] = []

    def step(title: str, summary: str, detail: str, inputs: list, results: list) -> None:
        n = len(steps) + 1
        steps.append(
            {"step": n, "anchor": f"step-{n}", "title": title, "summary": summary, "detail": detail,
             "inputs": inputs, "results": results}
        )  # fmt: skip

    step(
        "The Finding",
        f"{cve} is a flaw in {row['component']} ({row.get('component_type') or 'component'}). This page follows that one flaw on that one component under {row['owner']}.",
        "A finding is one vulnerability observed on one component. The same flaw on another component, or the same component under another owner, is a different row with its own answer, so the unit of measurement here is the vulnerability, the component and the owner together. Nothing on this page is stored: the Search computes it when the page loads.",
        [_item("Vulnerability", cve), _item("Title", vuln.get("title")), _item("Component", row["component"]),
         _item("Component type", row.get("component_type"))],
        [_item("Finding on component", f"{cve} on {row['component']}")],
    )  # fmt: skip
    step(
        "The Owner",
        (f"No single program owns the component here, so the owner is the container {row['owner']}, standing for {len(programs)} programs."
         if container_owner else f"{row['owner']} is a program that runs the component, so its profile decides the requirements."),
        "The grid ties a component to a program that loads or requires it. Where it ties the component only to the container that runs it, the container is the owner and the requirements are taken from every program the container runs (step 3). The owner is a fact read from the grid, not a judgement.",
        [_item("Owner", row["owner"]), _item("Owner kind", row["owner_kind"]), _item("Container", row.get("container"))],
        [_item("Programs behind the owner", ", ".join(p["name"] for p in programs) or "none")],
    )  # fmt: skip
    step(
        "The Profile",
        f"The owner is rated for how much it needs secrecy, correctness and uptime: {profile_text}, from {SOURCE_TEXT.get(row['profile_source'], row['profile_source'])}.",
        f"CR, IR and AR are the system's confidentiality, integrity and availability requirements ({MEMO}, section 7). A stamp states them directly or points at an archetype; a program with no stamp counts as High on all three, because missing classification must not lower PAIN (section 8). "
        + ("For a container, each requirement is the highest of its programs: " + "; ".join(_setters(programs, req)) + "." if container_owner else "")
        + " Weights: " + " / ".join(f"{k.title()} {v}" for k, v in rw.items()) + ".",
        [_item(p["name"], f"{_lv(p['levels'][0])} / {_lv(p['levels'][1])} / {_lv(p['levels'][2])} ({p['source']})", p["source"] == "unclassified") for p in programs]
        or [_item("Stamp", "none", True)],
        [_item("CR / IR / AR", profile_text, profile_assumed), _item("Requirements from", row["profile_source"], profile_assumed)],
    )  # fmt: skip
    step(
        "The Impact",
        ("The CVSS vector costs this flaw " + f"{_lv(row['c'])} secrecy, {_lv(row['i'])} integrity and {_lv(row['a'])} availability."
         if not impact_assumed else "No readable CVSS vector, so impact is assumed High on all three."),
        f"C, I and A come from the Base metrics of the vulnerability's CVSS vector: None, Low or High (section 7). A missing, malformed or incomplete vector is High on all three, because missing data must not lower PAIN (section 8). Weights: {' / '.join(f'{k.title()} {v}' for k, v in iw.items())}."
        + (f" CVSS 4.0 subsequent-system impact ({'/'.join(_lv(x) for x in row['subsequent'])}) is shown as evidence and not scored." if row.get("subsequent") else ""),
        [_item("CVSS vector", vuln.get("vector") or "none", impact_assumed), _item("CVSS version", vuln.get("version"))],
        [_item("C / I / A", impact_text, impact_assumed), _item("Impact from", row["impact_source"], impact_assumed)],
    )  # fmt: skip
    step(
        "The Products",
        f"Each impact is multiplied by the requirement of its own dimension: {_fmt(products[0])}, {_fmt(products[1])} and {_fmt(products[2])}.",
        f"For each of confidentiality, integrity and availability the impact weight is multiplied by the requirement weight ({MEMO}, section 7). Each product is the share of that dimension that this flaw can damage on this system.",
        [_item("C / I / A", impact_text, impact_assumed), _item("CR / IR / AR", profile_text, profile_assumed)],
        [_item("C x CR", _fmt(products[0])), _item("I x IR", _fmt(products[1])), _item("A x AR", _fmt(products[2]))],
    )  # fmt: skip
    step(
        "The Score",
        f"The three combine as U = 1 - (1 - {_fmt(products[0])})(1 - {_fmt(products[1])})(1 - {_fmt(products[2])}) = {row['u']}. Dividing by the largest possible U, {_fmt(ceiling)}, gives S = {row['s']}.",
        f"U combines the three dimensions into one pre-cap damage aggregate: U = 1 - (1 - C x CR)(1 - I x IR)(1 - A x AR) ({MEMO}, equations 2 to 4). D_H is U for all-High impact at all-High requirements, so S = U / D_H is U rescaled to a range of 0 to 1. Both are exact decimals, shown to six places.",
        [_item("Products", f"{_fmt(products[0])} / {_fmt(products[1])} / {_fmt(products[2])}"), _item("D_H", _fmt(ceiling))],
        [_item("U", row["u"]), _item("S", row["s"])],
    )  # fmt: skip
    step(
        "The Word",
        f"U = {row['u']} and S = {row['s']} fall in {row['word']}, because {_bound_text(row, params)}.",
        f"The word is the plain-English band the score falls in: Minimal below U {params['u1']}, Narrow below U {params['u2']}, Disruptive below S {params['theta3']}, Debilitating from there. The thresholds are Search inputs with the memo's values as defaults, so a different policy is visible rather than buried.",
        [_item("U", row["u"]), _item("S", row["s"]), _item("u1 / u2 / theta3", f"{params['u1']} / {params['u2']} / {params['theta3']}")],
        [_item("Word", row["word"])],
    )  # fmt: skip
    step(
        "The Agency Flag",
        (f"The flag m is {row['m']}, " + ("assumed from the Search input because no stamp states it." if agency_assumed else "stated by the stamp.")),
        "m says whether the system serves several agencies (1) or one (0). It moves Disruptive between N3 and N4 and Debilitating between N4 and N5. The program's stamp states it; where none does, the Search input applies, which is the worst case unless set. A program's stamp is a baseline: two findings on one program may have different real blast radii.",
        [_item("Stamped value", "none" if agency_assumed else row["m"], agency_assumed), _item("Input default", params["multi_agency"])],
        [_item("m", row["m"], agency_assumed), _item("Agencies from", row["multi_agency_source"], agency_assumed)],
    )  # fmt: skip
    step(
        "The PAIN Level",
        f"{row['word']} with m = {row['m']} is {row['pain']}.",
        "The word and the flag select the level: Minimal is N1, Narrow N2, Disruptive N3 (one agency) or N4 (several), Debilitating N4 (one agency) or N5 (several). This is the memo's level, before any intended-use ceiling: the plugin does not apply the ceiling, so every result is the uncapped, conservative subset.",
        [_item("Word", row["word"]), _item("m", row["m"], agency_assumed)],
        [_item("PAIN", row["pain"], profile_assumed or impact_assumed or agency_assumed)],
    )  # fmt: skip
    step(
        "Likely Exploitable",
        f"Likely exploitable is {yes} and the finding is {reach}, so it sits in the {row['column']} column.",
        f"A finding is likely exploitable when the CVE is on the CISA KEV list, or its EPSS reading is at or above {params['epss_irv']} when internet-reachable or {params['epss_non_irv']} when not; an absent reading counts as likely ({MEMO}, section 9). Evidence in an evaluation overrides this either way. That override is a local choice: the memo reads KEV or EPSS only.",
        [_item("KEV", {True: "yes", False: "no", None: "not observed"}[vuln["kev"]], vuln["kev"] is None),
         _item("EPSS", "not observed" if vuln["epss"] is None else vuln["epss"], vuln["epss"] is None),
         _item("Evidenced exploitable", {True: "yes", False: "no", None: "no evidence"}[factors["likely_exploitable"]]),
         _item("Evidenced reachable", {True: "yes", False: "no", None: "no evidence"}[factors["internet_reachable"]], irv_assumed)],
        [_item("Likely exploitable", yes, lev_assumed), _item("Internet-reachable", "yes" if row["irv"] else "no", irv_assumed), _item("Column", row["column"], lev_assumed or irv_assumed)],
    )  # fmt: skip
    step(
        "The Deadline",
        (f"Class {row['fedramp_class'].upper()}, {row['pain']} and the {row['column']} column give {hours} in the remediation table."
         if row["deadline_hours"] is not None else f"{row['pain']} carries no FedRAMP remediation timeframe."),
        "The VDR-TFR-PVR matrix gives the hours a class has to remediate at a PAIN level in an exposure column. The figure is the table's allowance, not a due date or a verdict on whether an SLA was met: the clock anchor and any separate KEV obligation are outside this row.",
        [_item("Class", row["fedramp_class"].upper(), True), _item("PAIN", row["pain"]), _item("Column", row["column"])],
        [_item("Deadline", hours)],
    )  # fmt: skip
    step(
        "What Is Assumed",
        (f"{'One value rests' if len(assumed_list) == 1 else f'{len(assumed_list)} values rest'} on a default: " + ", ".join(a for a, _ in assumed_list) + ". The result is uncapped: no intended-use ceiling is applied.")
        if assumed_list else "Nothing here rests on a default. The result is still uncapped: the intended-use ceiling is not applied.",
        "An assumed value is the conservative one, never a guess in the safe direction. The intended-use ceiling, the mitigation ladder and per-finding agency scope are not implemented, so a fully stamped row is the memo's compatibility result, not an agency-specific derivation. Local choices: an evidence-backed 'not exploitable' overrides KEV; the agency flag is stamped per program.",
        [_item(a, why, True) for a, why in assumed_list] or [_item("Assumed", "nothing")],
        [_item("Uncapped", "yes", True)],
    )  # fmt: skip
    assert len(steps) == 12

    breakdown = [
        _bd("profile", "Profile", f"{profile_text} ({row['profile_source']})", 3, profile_assumed),
        _bd("impact", "Impact", impact_text, 4, impact_assumed),
        _bd("u", "U", row["u"], 6, False),
        _bd("s", "S", row["s"], 6, False),
        _bd("word", "Word", row["word"], 7, False),
        _bd("m", "Agency Flag", f"{row['m']} ({row['multi_agency_source']})", 8, agency_assumed),
        _bd("pain", "PAIN", row["pain"], 9, profile_assumed or impact_assumed or agency_assumed),
        _bd("lev", "Likely Exploitable", yes, 10, lev_assumed),
        _bd("column", "Exposure Column", row["column"], 10, lev_assumed or irv_assumed),
        _bd("deadline", "Deadline", hours, 11, True),
    ]
    return {"breakdown": breakdown, "steps": steps}


def _bd(key: str, label: str, value: Any, step: int, assumed: bool) -> dict[str, Any]:
    return {"key": key, "label": label, "value": str(value), "assumed": assumed, "step": step}
