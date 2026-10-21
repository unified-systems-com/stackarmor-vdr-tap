"""Asset profile: the stackArmor method's stamp on one program (`req-stackarmor-vdr-stamp`)."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_LEVEL: dict[str, Any] = {"type": ["string", "null"], "enum": ["low", "medium", "high", None]}


class AssetProfile(BaseModel):
    """What one program requires of confidentiality, integrity and availability, by the method's judgment.

    A stamp is a node of its own that points at the program it describes (`PROFILES_PROGRAM`), so adding the method changes
    no node or edge that describes the system. It may name an archetype (`USES_ARCHETYPE`) and may carry explicit values
    that beat the archetype's, objective by objective. A stamp that says nothing reads as unclassified, High on all three.

    Spec: specs/spec-stackarmor-vdr-v0.md (req-stackarmor-vdr-stamp).
    """

    ENTITY_TYPE: ClassVar[str] = "stackarmor_vdr__asset_profile"
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("source", "stamp_key")
    ENTITY_NAME: ClassVar[str] = "StackArmor Asset Profile"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "The stackArmor method's stamp on a program: an archetype it follows and any explicit confidentiality, "
        "integrity and availability requirement that overrides it, with the rationale."
    )
    ENTITY_ICON: ClassVar[str] = "asset-profile"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"fedramp.rule": "vdr"}

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "computing_core__program"}],
            "edges": [{"type": "PROFILES_PROGRAM__stackarmor_vdr"}],
        },
        {
            "nodes": [{"type": "stackarmor_vdr__archetype"}],
            "edges": [{"type": "USES_ARCHETYPE__stackarmor_vdr"}],
        },
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "source": {"type": "string", "minLength": 1, "maxLength": 128},
        "stamp_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "scheme": {"type": "string", "minLength": 1, "maxLength": 64},
        "cr": _LEVEL,
        "ir": _LEVEL,
        "ar": _LEVEL,
        "rationale": {"type": "string", "minLength": 1},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["source", "stamp_key", "scheme", "rationale"]

    source = models.CharField(
        max_length=128, blank=True, default="", help_text="Who made the stamp. Half of the identity."
    )
    stamp_key = models.CharField(
        max_length=512,
        blank=True,
        default="",
        db_index=True,
        help_text="The source's own name for the stamp. Other half.",
    )
    scheme = models.CharField(
        max_length=64,
        blank=True,
        default="stackarmor",
        db_index=True,
        help_text="The evaluation scheme the stamp serves.",
    )
    cr = models.CharField(  # noqa: DJ001
        max_length=6,
        null=True,
        blank=True,
        default=None,
        help_text="Explicit confidentiality requirement. Null = none stated.",
    )
    ir = models.CharField(  # noqa: DJ001
        max_length=6,
        null=True,
        blank=True,
        default=None,
        help_text="Explicit integrity requirement. Null = none stated.",
    )
    ar = models.CharField(  # noqa: DJ001
        max_length=6,
        null=True,
        blank=True,
        default=None,
        help_text="Explicit availability requirement. Null = none stated.",
    )
    rationale = models.TextField(
        blank=True, default="", help_text="Why this profile; the memo asks for it to be retained."
    )

    class Meta(BaseModel.Meta):
        db_table = "stackarmor_vdr__asset_profile"

    def get_name(self) -> str:
        return f"Profile {self.stamp_key}"

    def __str__(self) -> str:
        return self.get_name()
