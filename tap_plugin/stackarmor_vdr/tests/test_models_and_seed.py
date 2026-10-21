"""The stamp, the archetype, their two edges and the sixteen-archetype seed (`req-stackarmor-vdr-stamp`, `-archetypes`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 - trigger model registration
import tap_plugin.stackarmor_vdr.models as sa  # noqa: F401 - trigger model registration

from tap_grid.grift import grift_import
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, patch_node

PACKAGE = Path(__file__).resolve().parents[1]
PROFILE = "stackarmor_vdr__asset_profile"
ARCHETYPE = "stackarmor_vdr__archetype"
PROFILES = "PROFILES_PROGRAM__stackarmor_vdr"
USES = "USES_ARCHETYPE__stackarmor_vdr"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])

MEMO = {
    "cicd_pipeline": "HHH", "orchestrator": "HHH", "config_actuation": "HHH", "identity_secrets": "HHH",
    "security_tooling": "HHM", "change_record": "MMM", "platform_foundation": "LHH", "data_sensitive": "HHH",
    "data_backbone": "HHH", "telemetry_backbone": "MMM", "app_tier": "MMM", "batch_analytics": "MML",
    "public_edge": "MMH", "passthrough_edge": "LLH", "internal_tooling": "LLL", "dev_test": "LLL",
}  # fmt: skip
WORD = {"L": "low", "M": "medium", "H": "high"}


def _node(type_slug: str, payload: dict[str, Any]) -> Entity:
    made = create_node(type_slug, payload)
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def _document() -> dict[str, Any]:
    return json.loads((PACKAGE / "grift" / "archetypes.grift.json").read_text(encoding="utf-8"))


def _stamp(**extra: Any) -> dict[str, Any]:
    return {"source": "test", "stamp_key": "s1", "scheme": "stackarmor", "rationale": "because", **extra}


class TestSeed:
    @pytest.mark.spec("req-stackarmor-vdr-archetypes-1")
    def test_the_sixteen_are_seeded_with_the_memo_values_and_a_reseed_adds_none(self) -> None:
        for _ in range(2):
            result = grift_import(_document())
            assert result.success, result.errors
        rows = {r.name: r for r in get_model_class(ARCHETYPE).objects.live()}
        assert {n: (r.cr, r.ir, r.ar) for n, r in rows.items()} == {
            n: tuple(WORD[c] for c in code) for n, code in MEMO.items()
        }
        assert all(r.description for r in rows.values())

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-7")
    def test_a_reseed_leaves_an_edited_archetype_as_the_instance_has_it(self) -> None:
        grift_import(_document())
        model = get_model_class(ARCHETYPE)
        edited = model.objects.live().get(name="app_tier")
        assert patch_node(edited.entity_id, {"cr": "high"}).success
        grift_import(_document())
        assert model.objects.live().get(name="app_tier").cr == "high"
        assert model.objects.live().count() == 16


class TestArchetype:
    @pytest.mark.spec("req-stackarmor-vdr-archetypes-4")
    @pytest.mark.parametrize(
        "bad",
        [
            {"name": "App-Tier"}, {"name": "app tier"}, {"name": ""}, {"name": "_x"},
            {"cr": "critical"}, {"ir": None}, {"ar": "High"}, {"description": ""},
        ],
    )  # fmt: skip
    def test_bad_values_are_refused(self, bad: dict[str, Any]) -> None:
        payload = {"name": "app_tier", "cr": "low", "ir": "low", "ar": "low", "description": "d", **bad}
        assert not create_node(ARCHETYPE, payload).success

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-4")
    @pytest.mark.parametrize("missing", ["name", "cr", "ir", "ar", "description"])
    def test_every_field_is_required(self, missing: str) -> None:
        payload = {"name": "app_tier", "cr": "low", "ir": "low", "ar": "low", "description": "d"}
        del payload[missing]
        assert not create_node(ARCHETYPE, payload).success

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-4")
    def test_the_name_is_the_identity(self) -> None:
        assert get_model_class(ARCHETYPE).NATURAL_KEY == ("name",)
        assert get_model_class(ARCHETYPE).DEFAULT_DIMENSIONS == {"fedramp.rule": "vdr"}


class TestStamp:
    @pytest.mark.spec("req-stackarmor-vdr-stamp-1")
    def test_the_key_is_source_and_stamp_key_and_both_are_required(self) -> None:
        assert get_model_class(PROFILE).NATURAL_KEY == ("source", "stamp_key")
        for missing in ("source", "stamp_key"):
            payload = _stamp()
            del payload[missing]
            assert not create_node(PROFILE, payload).success

    @pytest.mark.spec("req-stackarmor-vdr-stamp-2")
    @pytest.mark.parametrize("field", ["cr", "ir", "ar"])
    def test_levels_outside_low_medium_high_and_null_are_refused(self, field: str) -> None:
        assert not create_node(PROFILE, _stamp(**{field: "critical"})).success
        assert create_node(PROFILE, _stamp(**{field: None})).success

    @pytest.mark.spec("req-stackarmor-vdr-stamp-2")
    @pytest.mark.parametrize("missing", ["rationale", "scheme"])
    def test_rationale_and_scheme_are_required(self, missing: str) -> None:
        payload = _stamp()
        del payload[missing]
        assert not create_node(PROFILE, payload).success

    @pytest.mark.spec("req-stackarmor-vdr-stamp-5")
    def test_a_stamp_points_at_a_program_and_not_at_a_host(self) -> None:
        stamp = _node(PROFILE, _stamp())
        program = _node("computing_core__program", {"program_name": "p"})
        host = _node("computing_core__host", {"realm": "assert", "stable_id": "h", "kind": "container"})
        create_edge(stamp, program, PROFILES)
        with pytest.raises(Exception):  # noqa: B017, PT011 - the grid's refusal type is not public; the stamp declares its targets
            create_edge(stamp, host, PROFILES)

    @pytest.mark.spec("req-stackarmor-vdr-archetypes-5")
    def test_a_stamp_names_an_archetype_and_nothing_else(self) -> None:
        stamp = _node(PROFILE, _stamp())
        archetype = _node(ARCHETYPE, {"name": "x", "cr": "low", "ir": "low", "ar": "low", "description": "d"})
        create_edge(stamp, archetype, USES)
        with pytest.raises(Exception):  # noqa: B017, PT011 - the grid's refusal type is not public; the archetype declares no outbound edge
            create_edge(archetype, stamp, USES)

    @pytest.mark.spec("req-stackarmor-vdr-stamp-6")
    @pytest.mark.spec("req-stackarmor-vdr-archetypes-5")
    @pytest.mark.parametrize("slug", [PROFILES, USES])
    def test_the_edges_are_plain_references(self, slug: str) -> None:
        definition = json.loads((PACKAGE / "edges" / f"{slug}.edge.json").read_text(encoding="utf-8"))
        assert definition["identity"] == {"discriminators": []}
        assert "property_schema" not in definition
        assert definition["default_dimensions"] == {"fedramp.rule": "vdr"}
        for model in (sa.AssetProfile, sa.Archetype):
            assert slug not in model.CONTAINMENT_EDGES

    @pytest.mark.spec("req-stackarmor-vdr-stamp-8")
    def test_the_plugin_ships_no_model_or_edge_beyond_the_two_and_the_two(self) -> None:
        manifest = (PACKAGE / "tap-plugin.toml").read_text(encoding="utf-8")
        assert manifest.count("stackarmor_vdr__") == 2
        assert sorted(p.name for p in (PACKAGE / "edges").iterdir()) == sorted(
            [f"{PROFILES}.edge.json", f"{USES}.edge.json"]
        )
