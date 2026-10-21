"""Archetype: a named set of requirements a stamp can point at (`req-stackarmor-vdr-archetypes`)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_LEVEL: dict[str, Any] = {"type": "string", "enum": ["low", "medium", "high"]}
_NAME: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-z][a-z0-9]*(_[a-z0-9]+)*$"}


class Archetype(BaseModel):
    """One archetype of the memo's catalog: a lower-case name with its CR, IR and AR.

    The provider owns and justifies its own mapping, so the catalog is data a provider reads and changes by editing a node.

    Spec: specs/spec-stackarmor-vdr-v0.md (req-stackarmor-vdr-archetypes).
    """

    ENTITY_TYPE: ClassVar[str] = "stackarmor_vdr__archetype"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("name",)
    ENTITY_NAME: ClassVar[str] = "StackArmor Archetype"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A named set of confidentiality, integrity and availability requirements that a stackArmor asset profile can take."
    )
    ENTITY_ICON: ClassVar[str] = "archetype"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"fedramp.rule": "vdr"}

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "stackarmor_vdr__asset_profile"}],
            "edges": [{"type": "USES_ARCHETYPE__stackarmor_vdr"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "name": _NAME,
        "cr": _LEVEL,
        "ir": _LEVEL,
        "ar": _LEVEL,
        "description": {"type": "string", "minLength": 1},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["name", "cr", "ir", "ar", "description"]

    name = models.CharField(
        max_length=64, blank=True, default="", help_text="Lower-case with underscores. The identity."
    )
    cr = models.CharField(
        max_length=6, blank=True, default="", help_text="Confidentiality requirement: low, medium or high."
    )
    ir = models.CharField(max_length=6, blank=True, default="", help_text="Integrity requirement: low, medium or high.")
    ar = models.CharField(
        max_length=6, blank=True, default="", help_text="Availability requirement: low, medium or high."
    )
    description = models.TextField(blank=True, default="", help_text="Typical members and why this mapping.")

    class Meta(BaseModel.Meta):
        db_table = "stackarmor_vdr__archetype"

    def get_name(self) -> str:
        return self.name or ""

    def __str__(self) -> str:
        return self.get_name()
