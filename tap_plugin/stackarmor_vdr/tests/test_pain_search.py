"""The PAIN Searches (`req-stackarmor-vdr-search`, `-stamp-3/4/7`, `-archetypes-2/3/6`, `-exposure-3/4`).

Each test builds a small estate through the service layer with computing_core's real types: a program with a root package, an
image host that installs it, a container that runs the program, and a finding on the package.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr as base_package
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
import tap_plugin.stackarmor_vdr.models as sa  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr.deadlines import deadline_hours
from tap_plugin.stackarmor_vdr.searches import pain

from tap_grid.grift import grift_import
from tap_grid.models import Entity, Search
from tap_grid.search import execute_search
from tap_grid.services import create_edge, create_node, delete_node, patch_node

FINDING = "compliance_core__compliance_finding"
VULN = "compliance_core__compliance_vulnerability"
C = "computing_core__"
PACKAGE = Path(pain.__file__).parents[1]
SEEDS = (
    PACKAGE / "grift" / "archetypes.grift.json",
    Path(base_package.__file__).parent / "grift" / "timeframes.grift.json",
)
HHH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


def _node(type_slug: str, payload: dict[str, Any]) -> Entity:
    made = create_node(type_slug, payload)
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def _edge(src: Entity, name: str, dst: Entity) -> None:
    create_edge(src, dst, f"{name}__computing_core")


@pytest.fixture(autouse=True)
def seeded() -> None:
    for path in SEEDS:
        result = grift_import(json.loads(path.read_text(encoding="utf-8")))
        assert result.success, result.errors


class Estate:
    def __init__(self, *, vector: str | None = HHH, kev: bool | None = False, epss: float | None = 0.0) -> None:
        payload: dict[str, Any] = {"vuln_id": "CVE-2026-1", "title": "t", "kev": kev, "epss_score": epss}
        if vector:
            payload.update(cvss_vector=vector, cvss_version="3.1")
        self.vuln = _node(VULN, payload)
        self.root = _node(C + "package", {"ecosystem": "pypi", "name": "app", "version": "1.0"})
        self.dep = _node(C + "package", {"ecosystem": "pypi", "name": "lib", "version": "1.0"})
        _edge(self.root, "REQUIRES_PACKAGE", self.dep)
        self.program = _node(C + "program", {"program_name": "app"})
        _edge(self.program, "RUNS_PACKAGE", self.root)
        self.image = _node(C + "host", {"realm": "assert", "stable_id": "image", "kind": "container"})
        for package in (self.root, self.dep):
            _edge(self.image, "INSTALLS_PACKAGE", package)
        self.container = _node(C + "host", {"realm": "assert", "stable_id": "container", "kind": "container"})
        _edge(self.container, "RUNS_IMAGE", self.image)
        _edge(self.container, "RUNS_PROGRAM", self.program)
        self.finding = self.finding_on(self.dep, "f1")

    def finding_on(self, package: Entity, key: str) -> Entity:
        finding = _node(FINDING, {"source": "t", "source_key": key, "name": key, "status": "open"})
        create_edge(finding, self.vuln, "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core")
        create_edge(package, finding, "CARRIES_COMPLIANCE_FINDING__compliance_core")
        return finding

    def stamp(
        self, key: str = "s1", *, archetype: str | None = None, scheme: str = "stackarmor", **levels: str
    ) -> Entity:
        stamp = _node(
            "stackarmor_vdr__asset_profile",
            {"source": "test", "stamp_key": key, "scheme": scheme, "rationale": "because", **levels},
        )
        create_edge(stamp, self.program, "PROFILES_PROGRAM__stackarmor_vdr")
        if archetype:
            self.name(stamp, archetype)
        return stamp

    @staticmethod
    def name(stamp: Entity, archetype: str) -> None:
        node = sa.Archetype.objects.live().get(name=archetype)
        create_edge(stamp, Entity.objects.get(pk=node.entity_id), "USES_ARCHETYPE__stackarmor_vdr")


def run(**inputs: Any) -> list[dict[str, Any]]:
    return pain.stackarmor_pain(None, inputs, db_alias="default")["rows"]  # type: ignore[arg-type]


def one(**inputs: Any) -> dict[str, Any]:
    (row,) = run(**inputs)
    return row


def levels(row: dict[str, Any]) -> tuple[str, str, str]:
    return (row["cr"], row["ir"], row["ar"])


class TestRow:
    @pytest.mark.spec("req-stackarmor-vdr-search-2")
    def test_the_row_carries_every_input_and_intermediate(self) -> None:
        estate = Estate()
        estate.stamp(archetype="app_tier")
        row = one()
        assert set(row) >= {
            "finding_id", "vuln_id", "component", "component_id", "container_id", "container", "owner_kind", "owner_id",
            "owner", "scheme", "profile_source", "impact_source", "c", "i", "a", "cr", "ir", "ar", "u", "s", "word", "m",
            "multi_agency_source", "pain", "lev", "irv", "column", "fedramp_class", "deadline_hours", "uncapped",
        }  # fmt: skip
        assert (row["owner_kind"], row["owner_id"], row["container_id"]) == (
            "program", str(estate.program.pk), str(estate.container.pk),
        )  # fmt: skip
        assert row["uncapped"] is True  # `search-15`: even a fully stamped row is the uncapped subset
        assert (row["c"], row["i"], row["a"]) == ("high", "high", "high")
        assert levels(row) == ("medium", "medium", "medium")
        assert (row["u"], row["word"], row["pain"]) == ("0.914816", "Disruptive", "N4")
        assert row["pain_rank"] == 4
        assert row["cve"] == "CVE-2026-1" and row["vuln_id"] != row["cve"]
        assert (row["owner_type"], row["component_type"], row["container_type"]) == (
            "computing_core__program",
            "computing_core__package",
            "computing_core__host",
        )
        assert row["profile_source"] == "archetype" and row["scheme"] == "stackarmor"

    @pytest.mark.spec("req-stackarmor-vdr-search-1")
    def test_the_deadline_is_the_bases_for_the_column_and_class(self) -> None:
        Estate(kev=True).stamp(archetype="app_tier")
        row = one(fedramp_class="b")
        assert (row["lev"], row["irv"], row["column"]) == (True, True, "lev_irv")
        assert row["deadline_hours"] == deadline_hours("b", row["pain"], "lev_irv")

    @pytest.mark.spec("req-stackarmor-vdr-search-4")
    def test_the_agency_flag_is_an_input_and_assumed_visibly(self) -> None:
        Estate().stamp(archetype="app_tier")
        assert (one()["m"], one()["multi_agency_source"]) == (1, "assumed")
        assert (one(multi_agency=0)["m"], one(multi_agency=0)["pain"]) == (0, "N3")

    @pytest.mark.spec("req-stackarmor-vdr-search-10")
    def test_the_row_carries_the_scheme_asked_for(self) -> None:
        Estate().stamp(scheme="other", archetype="app_tier")
        assert one(scheme="other")["scheme"] == "other"


class TestProfiles:
    @pytest.mark.spec("req-stackarmor-vdr-stamp-3")
    @pytest.mark.spec("req-stackarmor-vdr-archetypes-3")
    def test_a_program_with_no_stamp_is_high_and_unclassified(self) -> None:
        Estate()
        row = one()
        assert (levels(row), row["profile_source"]) == (("high", "high", "high"), "unclassified")

    @pytest.mark.spec("req-stackarmor-vdr-stamp-3")
    def test_a_stamp_that_says_nothing_is_unclassified(self) -> None:
        Estate().stamp()
        assert one()["profile_source"] == "unclassified"

    @pytest.mark.spec("req-stackarmor-vdr-stamp-4")
    def test_an_explicit_objective_beats_the_archetype_and_leaves_the_others(self) -> None:
        Estate().stamp(archetype="app_tier", cr="low")
        row = one()
        assert (levels(row), row["profile_source"]) == (("low", "medium", "medium"), "archetype")

    @pytest.mark.spec("req-stackarmor-vdr-stamp-4")
    def test_explicit_on_all_three_is_an_override(self) -> None:
        Estate().stamp(cr="low", ir="low", ar="medium")
        row = one()
        assert (levels(row), row["profile_source"]) == (("low", "low", "medium"), "override")

    @pytest.mark.spec("req-stackarmor-vdr-stamp-4")
    def test_one_explicit_objective_alone_leaves_the_rest_high_and_unclassified(self) -> None:
        Estate().stamp(cr="low")
        row = one()
        assert (levels(row), row["profile_source"]) == (("low", "high", "high"), "unclassified")

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-6")
    def test_several_archetypes_take_the_per_objective_maximum(self) -> None:
        estate = Estate()
        stamp = estate.stamp(archetype="internal_tooling")  # L/L/L
        estate.name(stamp, "platform_foundation")  # L/H/H
        assert levels(one()) == ("low", "high", "high")

    @pytest.mark.spec("req-stackarmor-vdr-stamp-7")
    def test_a_second_stamp_never_lowers(self) -> None:
        estate = Estate()
        estate.stamp("a", archetype="data_sensitive")  # H/H/H
        estate.stamp("b", archetype="dev_test")  # L/L/L
        assert levels(one()) == ("high", "high", "high")

    @pytest.mark.spec("req-stackarmor-vdr-search-9")
    def test_only_stamps_of_the_searchs_scheme_count(self) -> None:
        Estate().stamp("a", scheme="other", archetype="dev_test")
        assert one(scheme="stackarmor")["profile_source"] == "unclassified"
        assert one(scheme="other")["profile_source"] == "archetype"

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-2")
    def test_the_values_come_from_the_node_so_an_edit_changes_the_result(self) -> None:
        Estate().stamp(archetype="app_tier")
        node = sa.Archetype.objects.live().get(name="app_tier")
        assert patch_node(node.entity_id, {"cr": "low", "ir": "low", "ar": "low"}).success
        assert levels(one()) == ("low", "low", "low")

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-3")
    def test_a_tombstoned_archetype_is_unclassified_not_low(self) -> None:
        Estate().stamp(archetype="app_tier")
        delete_node(sa.Archetype.objects.live().get(name="app_tier").entity_id)
        row = one()
        assert (levels(row), row["profile_source"]) == (("high", "high", "high"), "unclassified")


class TestAgencyFlag:
    @pytest.mark.spec("req-stackarmor-vdr-stamp-9")
    def test_a_stamp_states_the_flag_and_the_row_says_where_it_came_from(self) -> None:
        Estate().stamp(archetype="app_tier", multi_agency=0)
        row = one()
        assert (row["m"], row["multi_agency_source"], row["pain"]) == (0, "stamp", "N3")  # the same score at m=1 is N4

    @pytest.mark.spec("req-stackarmor-vdr-stamp-9")
    def test_a_program_that_states_nothing_uses_the_input_default_and_says_assumed(self) -> None:
        Estate().stamp(archetype="app_tier")
        assert (one()["m"], one()["multi_agency_source"]) == (1, "assumed")
        assert (one(multi_agency=0)["m"], one(multi_agency=0)["multi_agency_source"]) == (0, "assumed")

    @pytest.mark.spec("req-stackarmor-vdr-stamp-9")
    def test_several_stamps_never_lower_the_flag(self) -> None:
        estate = Estate()
        estate.stamp("a", archetype="app_tier", multi_agency=0)
        estate.stamp("b", archetype="app_tier", multi_agency=1)
        assert one()["m"] == 1

    @pytest.mark.spec("req-stackarmor-vdr-stamp-9")
    def test_a_container_row_takes_the_highest_flag_of_its_programs_counting_silence_at_the_default(self) -> None:
        estate = Estate()
        estate.stamp(archetype="dev_test", multi_agency=0)
        orphan = _node(C + "package", {"ecosystem": "apk", "name": "musl", "version": "1"})
        _edge(estate.image, "INSTALLS_PACKAGE", orphan)
        finding = estate.finding_on(orphan, "f2")
        row = next(r for r in run() if r["finding_id"] == str(finding.pk))
        assert (row["owner_kind"], row["m"], row["multi_agency_source"]) == ("container", 0, "stamp")
        second = _node(C + "program", {"program_name": "sidecar"})
        _edge(estate.container, "RUNS_PROGRAM", second)  # a second program that states nothing
        row = next(r for r in run() if r["finding_id"] == str(finding.pk))
        assert (row["m"], row["multi_agency_source"]) == (1, "assumed")

    @pytest.mark.spec("req-stackarmor-vdr-score-2")
    @pytest.mark.parametrize(
        ("levels", "flag", "u", "pain"),
        [
            ({"cr": "low", "ir": "low", "ar": "low"}, 0, "0.626752", "N3"),  # the memo's example 3 on this system
            ({"cr": "medium", "ir": "medium", "ar": "medium"}, 1, "0.914816", "N4"),  # example 2
            ({"cr": "high", "ir": "high", "ar": "high"}, 1, "0.995904", "N5"),  # example 1
        ],
    )
    def test_stamps_reproduce_the_memos_worked_examples_end_to_end(
        self, levels: dict[str, str], flag: int, u: str, pain: str
    ) -> None:
        Estate().stamp(multi_agency=flag, **levels)
        row = one()
        assert (row["u"], row["pain"], row["profile_source"]) == (u, pain, "override")


class TestVulnerabilityFilter:
    @pytest.mark.spec("req-stackarmor-vdr-search-11")
    def test_vuln_id_limits_the_rows_to_one_vulnerability(self) -> None:
        estate = Estate()
        estate.stamp(archetype="app_tier")
        other = _node(VULN, {"vuln_id": "CVE-2026-2", "title": "t2", "cvss_vector": HHH, "cvss_version": "3.1"})
        finding = _node(FINDING, {"source": "t", "source_key": "f9", "name": "f9", "status": "open"})
        create_edge(finding, other, "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core")
        create_edge(estate.dep, finding, "CARRIES_COMPLIANCE_FINDING__compliance_core")
        assert len(run()) == 2
        assert [r["vuln_id"] for r in run(vuln_id=str(other.pk))] == [str(other.pk)]


class TestSummary:
    @pytest.mark.spec("req-stackarmor-vdr-summary-1")
    def test_by_pain_lists_every_level_and_the_counts_match_the_rows(self) -> None:
        Estate().stamp(archetype="app_tier")
        out = pain.stackarmor_summary(None, {"view": "by_pain"}, db_alias="default")["rows"]  # type: ignore[arg-type]
        assert [r["pain"] for r in out] == ["N1", "N2", "N3", "N4", "N5"]
        assert sum(r["rows"] for r in out) == len(run()) == 1
        assert {r["pain"]: r["rows"] for r in out}["N4"] == 1

    @pytest.mark.spec("req-stackarmor-vdr-summary-1")
    def test_with_no_rows_every_level_is_zero_and_the_percent_is_null(self) -> None:
        out = pain.stackarmor_summary(None, {}, db_alias="default")["rows"]  # type: ignore[arg-type]
        assert [(r["rows"], r["percent"]) for r in out] == [(0, None)] * 5

    @pytest.mark.spec("req-stackarmor-vdr-summary-2")
    def test_assumptions_are_counted_from_the_same_rows(self) -> None:
        Estate(vector=None)  # no stamp, no vector
        (row,) = pain.stackarmor_summary(None, {"view": "assumptions"}, db_alias="default")["rows"]  # type: ignore[arg-type]
        assert (
            row["rows"],
            row["unclassified"],
            row["assumed_impact"],
            row["assumed_agency"],
            row["stamped_agency"],
        ) == (1, 1, 1, 1, 0)

    @pytest.mark.spec("req-stackarmor-vdr-summary-3")
    def test_it_is_registered_and_writes_nothing(self) -> None:
        from tap_grid.registry import get_search_runner

        assert (
            get_search_runner("tap_plugin.stackarmor_vdr.searches.pain:stackarmor-summary") is pain.stackarmor_summary
        )
        Estate().stamp(archetype="app_tier")
        before = Entity.objects.count()
        pain.stackarmor_summary(None, {}, db_alias="default")  # type: ignore[arg-type]
        assert Entity.objects.count() == before

    @pytest.mark.spec("req-stackarmor-vdr-summary-4")
    @pytest.mark.parametrize("bad", [{"view": "nope"}, {"bogus": 1}, {"entity_id": "x"}])
    def test_bad_input_is_refused(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            pain.stackarmor_summary(None, bad, db_alias="default")  # type: ignore[arg-type]


class TestTrace:
    @pytest.mark.spec("req-stackarmor-vdr-trace-1")
    def test_it_returns_the_objects_behind_a_finding_and_the_edges_among_them(self) -> None:
        estate = Estate()
        stamp = estate.stamp(archetype="app_tier")
        out = pain.stackarmor_trace(None, {"entity_id": str(estate.finding.pk)}, db_alias="default")  # type: ignore[arg-type]
        types = {n["entity_type"] for n in out["nodes"]}
        assert {
            "compliance_core__compliance_finding",
            "compliance_core__compliance_vulnerability",
            "computing_core__package",
            "computing_core__program",
            "computing_core__host",
            "stackarmor_vdr__asset_profile",
            "stackarmor_vdr__archetype",
        } <= types
        edge_types = {e["data"]["edge_type"] for e in out["edges"]}
        assert {
            "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core",
            "CARRIES_COMPLIANCE_FINDING__compliance_core",
            "RUNS_PROGRAM__computing_core",
            "PROFILES_PROGRAM__stackarmor_vdr",
            "USES_ARCHETYPE__stackarmor_vdr",
        } <= edge_types
        assert str(stamp.pk) in {n["entity_id"] for n in out["nodes"]}
        ends = {n["entity_id"] for n in out["nodes"]}
        assert all(e["data"]["from_entity_id"] in ends and e["data"]["to_entity_id"] in ends for e in out["edges"])

    @pytest.mark.spec("req-stackarmor-vdr-trace-2")
    def test_only_stamps_of_the_scheme_are_shown(self) -> None:
        estate = Estate()
        estate.stamp("a", scheme="other", archetype="dev_test")
        out = pain.stackarmor_trace(None, {"entity_id": str(estate.finding.pk)}, db_alias="default")  # type: ignore[arg-type]
        assert "stackarmor_vdr__asset_profile" not in {n["entity_type"] for n in out["nodes"]}

    @pytest.mark.spec("req-stackarmor-vdr-trace-3")
    def test_a_finding_with_no_owner_shows_itself_and_says_so(self) -> None:
        lone = _node(FINDING, {"source": "t", "source_key": "lone", "name": "lone", "status": "open"})
        out = pain.stackarmor_trace(None, {"entity_id": str(lone.pk)}, db_alias="default")  # type: ignore[arg-type]
        assert [n["entity_id"] for n in out["nodes"]] == [str(lone.pk)] and out["edges"] == []
        assert "no_owner" in out["warnings"]

    @pytest.mark.spec("req-stackarmor-vdr-trace-4")
    @pytest.mark.parametrize("bad", [{}, {"entity_id": ""}, {"entity_id": 5}, {"entity_id": "x", "bogus": 1}])
    def test_bad_input_is_refused(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            pain.stackarmor_trace(None, bad, db_alias="default")  # type: ignore[arg-type]

    @pytest.mark.spec("req-stackarmor-vdr-trace-5")
    def test_it_is_registered_and_writes_nothing(self) -> None:
        from tap_grid.registry import get_search_runner

        assert get_search_runner("tap_plugin.stackarmor_vdr.searches.pain:stackarmor-trace") is pain.stackarmor_trace
        estate = Estate()
        estate.stamp(archetype="app_tier")
        before = Entity.objects.count()
        pain.stackarmor_trace(None, {"entity_id": str(estate.finding.pk)}, db_alias="default")  # type: ignore[arg-type]
        assert Entity.objects.count() == before


class TestContainer:
    @pytest.mark.spec("req-stackarmor-vdr-search-1")
    def test_a_container_owned_row_reduces_the_programs_involved(self) -> None:
        estate = Estate()
        estate.stamp(archetype="dev_test")
        orphan = _node(C + "package", {"ecosystem": "apk", "name": "musl", "version": "1"})
        _edge(estate.image, "INSTALLS_PACKAGE", orphan)  # installed here, required by no program
        finding = estate.finding_on(orphan, "f2")
        row = next(r for r in run() if r["finding_id"] == str(finding.pk))
        assert (row["owner_kind"], row["profile_source"]) == ("container", "container")
        assert levels(row) == ("low", "low", "low")


class TestImpactAndExposure:
    @pytest.mark.spec("req-stackarmor-vdr-impact-3")
    def test_a_missing_vector_is_high_and_assumed(self) -> None:
        Estate(vector=None).stamp(archetype="dev_test")
        row = one()
        assert (row["c"], row["i"], row["a"], row["impact_source"]) == ("high", "high", "high", "assumed")

    @pytest.mark.spec("req-stackarmor-vdr-exposure-1")
    def test_low_epss_and_no_kev_is_not_likely_and_takes_the_nlev_column(self) -> None:
        Estate(kev=False, epss=0.01).stamp(archetype="app_tier")
        row = one()
        assert (row["lev"], row["column"]) == (False, "nlev")

    @pytest.mark.spec("req-stackarmor-vdr-exposure-2")
    def test_the_epss_thresholds_are_inputs(self) -> None:
        Estate(kev=False, epss=0.30).stamp(archetype="app_tier")
        assert one()["lev"] is True
        assert one(epss_irv=0.9)["lev"] is False

    @pytest.mark.spec("req-stackarmor-vdr-exposure-3")
    @pytest.mark.spec("req-stackarmor-vdr-exposure-4")
    @pytest.mark.parametrize("backed", [True, False])
    def test_an_evidenced_factor_overrides_kev_and_epss_for_the_evaluation_scheme(
        self, backed: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Estate(kev=not backed, epss=0.0 if backed else 0.99).stamp(archetype="app_tier")
        seen: dict[str, Any] = {}

        def fake(ids: Any, *, scheme: str, db_alias: str) -> dict[str, dict[str, bool | None]]:
            seen["scheme"] = scheme
            return {str(i): {"likely_exploitable": backed, "internet_reachable": None} for i in ids}

        monkeypatch.setattr(pain, "backed_factors", fake)
        assert one(evaluation_scheme="algo2")["lev"] is backed
        assert seen["scheme"] == "algo2"


class TestAssets:
    @pytest.mark.spec("req-stackarmor-vdr-search-5")
    def test_one_row_per_node_that_runs_programs_computed_on_read(self) -> None:
        estate = Estate()
        estate.stamp(archetype="app_tier")
        before = Entity.objects.count()
        (row,) = pain.stackarmor_assets(None, {}, db_alias="default")["rows"]  # type: ignore[arg-type]
        assert Entity.objects.count() == before
        assert row["asset_id"] == str(estate.container.pk)
        assert (row["programs"], row["classified"], levels(row)) == (1, 1, ("medium", "medium", "medium"))


class TestSurface:
    @pytest.mark.spec("req-stackarmor-vdr-search-5")
    def test_the_pain_runner_writes_nothing(self) -> None:
        Estate().stamp(archetype="app_tier")
        before = Entity.objects.count()
        run()
        assert Entity.objects.count() == before

    @pytest.mark.spec("req-stackarmor-vdr-search-7")
    def test_the_runners_are_registered_under_the_keys_the_searches_name(self) -> None:
        from tap_grid.registry import get_search_runner

        assert get_search_runner("tap_plugin.stackarmor_vdr.searches.pain:stackarmor-pain") is pain.stackarmor_pain
        assert get_search_runner("tap_plugin.stackarmor_vdr.searches.pain:stackarmor-assets") is pain.stackarmor_assets

    @pytest.mark.spec("req-stackarmor-vdr-search-3")
    def test_it_runs_through_the_search_service_with_the_schema_defaults(self) -> None:
        Estate().stamp(archetype="app_tier")
        search = Search(
            search_type="module",
            root="node",
            name="stackarmor-pain",
            definition={"runner_key": "tap_plugin.stackarmor_vdr.searches.pain:stackarmor-pain"},
            input_schema=pain.INPUT_SCHEMA,
        )
        envelope = execute_search(search, {})
        assert envelope["nodes"] == [] and len(envelope["rows"]) == 1

    @pytest.mark.spec("req-stackarmor-vdr-search-3")
    def test_the_defaults_are_the_memos_and_no_pure_module_repeats_them(self) -> None:
        props = pain.INPUT_SCHEMA["properties"]
        assert props["impact_weights"]["default"] == {"none": 0, "low": 0.22, "high": 0.56}
        assert props["requirement_weights"]["default"] == {"low": 0.5, "medium": 1.0, "high": 1.5}
        assert (props["u1"]["default"], props["u2"]["default"], props["theta3"]["default"]) == (0.28, 0.56, 0.933)
        assert (props["epss_irv"]["default"], props["epss_non_irv"]["default"]) == (0.20, 0.55)
        assert (props["multi_agency"]["default"], props["fedramp_class"]["default"]) == (1, "d")
        assert (props["scheme"]["default"], props["evaluation_scheme"]["default"]) == ("stackarmor", "max")
        for module in ("score.py", "exposure.py", "impact.py"):
            text = (PACKAGE / module).read_text(encoding="utf-8")
            assert "0.933" not in text and "1.5" not in text and "0.22" not in text, module

    @pytest.mark.spec("req-stackarmor-vdr-search-3")
    def test_an_unknown_input_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown input"):
            run(bogus=1)

    @pytest.mark.spec("req-stackarmor-vdr-search-8")
    def test_the_manifest_and_ci_record_pin_the_floors(self) -> None:
        manifest = (PACKAGE / "tap-plugin.toml").read_text(encoding="utf-8")
        for slug in ("fedramp_20x_vdr", "computing_core", "compliance_core"):
            assert f'slug = "{slug}"' in manifest
        ci = json.loads((PACKAGE / "boot" / "ci.boot.json").read_text(encoding="utf-8"))
        revs = {p["slug"]: p["source"]["rev"] for p in ci["install"]["plugins"]}
        assert (revs["fedramp_20x_vdr"], revs["computing_core"], revs["compliance_core"]) == (
            "v0.1.2",
            "v0.10.2",
            "v0.8.7",
        )


class TestParametersValidated:
    @pytest.mark.spec("req-stackarmor-vdr-search-14")
    @pytest.mark.parametrize(
        "inputs",
        [
            {"impact_weights": {"none": 0, "low": 0, "high": 0}},
            {"impact_weights": {"none": 0, "low": 0.22, "high": 1.0}, "requirement_weights": {"low": 1, "medium": 2, "high": 3}},
        ],
    )
    def test_a_weight_set_outside_the_domain_is_refused_before_any_row(self, inputs: dict[str, Any]) -> None:
        Estate()
        with pytest.raises(ValueError, match="must"):
            run(**inputs)


class TestFindingWalkthrough:
    @staticmethod
    def keys(row: dict[str, Any]) -> dict[str, Any]:
        return {"finding_id": row["finding_id"], "component_id": row["component_id"], "owner_id": row["owner_id"]}

    @staticmethod
    def walk(**inputs: Any) -> dict[str, Any]:
        from tap_plugin.stackarmor_vdr.searches import finding

        return finding.stackarmor_finding(None, inputs, db_alias="default")  # type: ignore[arg-type]

    @pytest.mark.spec("req-stackarmor-vdr-finding-1")
    @pytest.mark.spec("req-stackarmor-vdr-finding-2")
    def test_the_walkthrough_is_the_rows_own_numbers(self) -> None:
        estate = Estate()
        estate.stamp(archetype="app_tier")
        row = one()
        out = self.walk(**self.keys(row))
        steps = {r["title"]: r for r in out["rows"] if r["kind"] == "step"}
        shown = {i["label"]: i["value"] for i in steps["The Score"]["results"]}
        assert (shown["U"], shown["S"]) == (row["u"], row["s"])
        assert steps["The PAIN Level"]["results"][0]["value"] == row["pain"]
        assert steps["The Word"]["results"][0]["value"] == row["word"]
        assert len([r for r in out["rows"] if r["kind"] == "step"]) == 12 and out["rows"][0]["kind"] == "breakdown"

    @pytest.mark.spec("req-stackarmor-vdr-finding-9")
    def test_a_key_that_matches_no_row_is_not_found_and_bad_input_is_refused(self) -> None:
        estate = Estate()
        estate.stamp(archetype="app_tier")
        row = one()
        out = self.walk(**{**self.keys(row), "owner_id": "00000000-0000-0000-0000-000000000000"})
        assert out["rows"] == [] and "not_found" in out["warnings"]
        with pytest.raises(ValueError, match="owner_id"):
            self.walk(finding_id=row["finding_id"], component_id=row["component_id"])
        with pytest.raises(ValueError, match="unknown input"):
            self.walk(**self.keys(row), bogus=1)

    @pytest.mark.spec("req-stackarmor-vdr-finding-10")
    def test_registered_and_read_only(self) -> None:
        from tap_grid.registry import get_search_runner
        from tap_plugin.stackarmor_vdr.searches import finding

        assert get_search_runner("tap_plugin.stackarmor_vdr.searches.finding:stackarmor-finding") is finding.stackarmor_finding
        estate = Estate()
        estate.stamp(archetype="app_tier")
        before = Entity.objects.count()
        self.walk(**self.keys(one()))
        assert Entity.objects.count() == before
