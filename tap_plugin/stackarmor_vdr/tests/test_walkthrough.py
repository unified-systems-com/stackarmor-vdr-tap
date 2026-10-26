"""The walk-through builder, from a row and the facts beside it (`req-stackarmor-vdr-finding`). Django-free."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

import pytest
from tap_plugin.stackarmor_vdr import score
from tap_plugin.stackarmor_vdr.walkthrough import build

H, M, L, N = "high", "medium", "low", "none"
PARAMS = {
    "impact_weights": {"none": 0, "low": 0.22, "high": 0.56},
    "requirement_weights": {"low": 0.5, "medium": 1.0, "high": 1.5},
    "u1": 0.28, "u2": 0.56, "theta3": 0.933, "epss_irv": 0.2, "epss_non_irv": 0.55, "multi_agency": 1,
}  # fmt: skip


def row_for(impact: tuple[str, str, str], req: tuple[str, str, str], m: int, **over: Any) -> dict[str, Any]:
    result = score.score(
        impact, req, m, impact_weights=PARAMS["impact_weights"], requirement_weights=PARAMS["requirement_weights"],
        u1=PARAMS["u1"], u2=PARAMS["u2"], theta3=PARAMS["theta3"],
    )  # fmt: skip
    row = {
        "cve": "CVE-2026-1", "vuln_id": "v", "component": "libfoo", "component_type": "package", "owner": "app",
        "owner_kind": "program", "container": "c", "c": impact[0], "i": impact[1], "a": impact[2], "impact_source": "vector",
        "subsequent": None, "cr": req[0], "ir": req[1], "ar": req[2], "profile_source": "archetype",
        "u": f"{result.u:.6f}", "s": f"{result.s:.6f}", "word": result.word, "m": m, "multi_agency_source": "stamp",
        "pain": result.pain, "lev": True, "irv": True, "column": "lev_irv", "fedramp_class": "d", "deadline_hours": 168,
        "uncapped": True,
    }  # fmt: skip
    return {**row, **over}


def extra(**over: Any) -> dict[str, Any]:
    base = {
        "vuln": {"title": "t", "kev": True, "epss": 0.9, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"},
        "programs": [{"name": "app", "levels": (M, M, M), "source": "archetype", "m": 1}],
        "factors": {"likely_exploitable": None, "internet_reachable": True},
    }  # fmt: skip
    return {**base, **over}


def words(text: str) -> int:
    return len(text.split())


def sentences(text: str) -> int:
    return len(re.findall(r"[.!?](?:\s|$)", text.strip()))


class TestShape:
    @pytest.mark.spec("req-stackarmor-vdr-finding-3")
    def test_twelve_steps_in_order_with_anchors(self) -> None:
        steps = build(row_for((H, H, H), (M, M, M), 1), extra(), PARAMS)["steps"]
        assert [s["step"] for s in steps] == list(range(1, 13))
        assert [s["anchor"] for s in steps] == [f"step-{n}" for n in range(1, 13)]

    @pytest.mark.spec("req-stackarmor-vdr-finding-3")
    def test_values_carry_down(self) -> None:
        steps = {s["title"]: s for s in build(row_for((H, H, H), (M, M, M), 1), extra(), PARAMS)["steps"]}
        results = lambda t: {i["label"]: i["value"] for i in steps[t]["results"]}  # noqa: E731
        inputs = lambda t: {i["label"]: i["value"] for i in steps[t]["inputs"]}  # noqa: E731
        assert inputs("The Products")["C / I / A"] == results("The Impact")["C / I / A"]
        assert inputs("The Products")["CR / IR / AR"] == results("The Profile")["CR / IR / AR"]
        assert inputs("The Word")["U"] == results("The Score")["U"] and inputs("The Word")["S"] == results("The Score")["S"]
        assert inputs("The PAIN Level")["Word"] == results("The Word")["Word"]
        assert inputs("The Deadline")["PAIN"] == results("The PAIN Level")["PAIN"]
        assert inputs("The Deadline")["Column"] == results("Likely Exploitable")["Column"]

    @pytest.mark.spec("req-stackarmor-vdr-finding-6")
    def test_every_breakdown_row_names_a_step_and_the_lists_are_in_order(self) -> None:
        built = build(row_for((H, H, H), (M, M, M), 1), extra(), PARAMS)
        numbers = [b["step"] for b in built["breakdown"]]
        assert numbers == sorted(numbers) and set(numbers) <= {s["step"] for s in built["steps"]}

    @pytest.mark.spec("req-stackarmor-vdr-finding-2")
    @pytest.mark.parametrize(
        ("impact", "req", "m"),
        [((H, H, H), (H, H, H), 1), ((H, H, H), (M, M, M), 1), ((H, H, H), (L, L, L), 0), ((N, N, H), (M, M, H), 0), ((H, N, N), (L, M, M), 0)],
    )
    def test_the_products_rebuild_the_rows_u_and_the_memo_examples_walk_through(self, impact, req, m) -> None:  # type: ignore[no-untyped-def]
        """The five memo examples (the same five as `req-stackarmor-vdr-score`) through the builder; U, S, word and PAIN are the row's."""
        row = row_for(impact, req, m)
        steps = {s["title"]: s for s in build(row, extra(), PARAMS)["steps"]}
        products = [Decimal(i["value"]) for i in steps["The Products"]["results"]]
        survive = Decimal(1)
        for product in products:
            survive *= 1 - product
        assert f"{1 - survive:.6f}" == row["u"]
        shown = {i["label"]: i["value"] for i in steps["The Score"]["results"]}
        assert (shown["U"], shown["S"]) == (row["u"], row["s"])
        assert steps["The Word"]["results"][0]["value"] == row["word"] and steps["The PAIN Level"]["results"][0]["value"] == row["pain"]


class TestText:
    @pytest.mark.spec("req-stackarmor-vdr-finding-7")
    @pytest.mark.parametrize("variant", ["program", "container", "assumed"])
    def test_the_summaries_fit_one_page(self, variant: str) -> None:
        row = row_for((H, H, H), (M, M, M), 1)
        ex = extra()
        if variant == "container":
            row["owner_kind"] = "container"
            row["profile_source"] = "container"
            ex["programs"] = [{"name": f"prog{n}", "levels": (M, M, M), "source": "archetype", "m": 1} for n in range(3)]
        if variant == "assumed":
            row.update(impact_source="assumed", multi_agency_source="assumed", profile_source="unclassified")
            ex["vuln"] = {**ex["vuln"], "kev": None, "epss": None, "vector": None}
            ex["factors"] = {"likely_exploitable": None, "internet_reachable": None}
        steps = build(row, ex, PARAMS)["steps"]
        assert sum(words(s["summary"]) for s in steps) <= 550
        for s in steps:
            assert sentences(s["summary"]) <= 2 and words(s["summary"]) <= 45, (s["title"], s["summary"])

    @pytest.mark.spec("req-stackarmor-vdr-finding-8")
    def test_every_detail_is_longer_than_its_summary(self) -> None:
        for s in build(row_for((H, H, H), (M, M, M), 1), extra(), PARAMS)["steps"]:
            assert words(s["detail"]) > words(s["summary"]), s["title"]

    @pytest.mark.spec("req-stackarmor-vdr-finding-4")
    def test_a_container_lists_its_programs_and_who_set_each_requirement(self) -> None:
        row = row_for((H, H, H), (H, M, M), 1, owner_kind="container", profile_source="container")
        ex = extra(programs=[
            {"name": "web", "levels": (H, L, M), "source": "archetype", "m": 1},
            {"name": "db", "levels": (M, M, L), "source": "override", "m": 1},
        ])  # fmt: skip
        step = build(row, ex, PARAMS)["steps"][2]
        assert [i["label"] for i in step["inputs"]] == ["web", "db"]
        assert "confidentiality High from web" in step["detail"] and "integrity Medium from db" in step["detail"]

    @pytest.mark.spec("req-stackarmor-vdr-finding-5")
    def test_assumed_is_marked_and_listed_and_a_clean_row_says_so(self) -> None:
        row = row_for((H, H, H), (M, M, M), 1, impact_source="assumed", multi_agency_source="assumed")
        built = build(row, extra(), PARAMS)
        marked = {b["key"] for b in built["breakdown"] if b["assumed"]}
        assert {"impact", "m", "pain", "deadline"} <= marked and "profile" not in marked
        assert "impact" in built["steps"][11]["summary"] and "agency flag" in built["steps"][11]["summary"]
        clean = build(row_for((H, H, H), (M, M, M), 1), extra(), PARAMS)["steps"][11]
        assert "the class" in clean["summary"]  # the class is always an input default
