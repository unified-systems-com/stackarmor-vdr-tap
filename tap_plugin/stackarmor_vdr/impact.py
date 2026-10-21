"""C, I and A from a CVSS vector (`req-stackarmor-vdr-impact`). Pure and Django-free.

CVSS 3.0 and 3.1 give ``C``, ``I`` and ``A`` as None, Low or High. CVSS 4.0 gives ``VC``, ``VI`` and ``VA`` (the memo's
limited compatibility path); the Subsequent-System metrics ``SC``, ``SI`` and ``SA`` are returned as evidence and not
scored. A missing or unparseable vector is High on all three with source ``assumed``, because missing data must not lower
PAIN.
"""

from __future__ import annotations

from dataclasses import dataclass

LEVEL = {"N": "none", "L": "low", "H": "high"}
HIGH = ("high", "high", "high")


@dataclass(frozen=True)
class Impact:
    c: str
    i: str
    a: str
    source: str  # "vector" or "assumed"
    subsequent: tuple[str, str, str] | None = None  # CVSS 4.0 SC, SI, SA: evidence only

    @property
    def vector(self) -> tuple[str, str, str]:
        return (self.c, self.i, self.a)


def _metrics(vector: str) -> dict[str, str] | None:
    parts = vector.strip().split("/")
    out: dict[str, str] = {}
    for part in parts[1:]:  # parts[0] is the CVSS:x.y prefix
        key, sep, value = part.partition(":")
        if not sep or not key or key in out:
            return None
        out[key] = value
    return out


def _levels(metrics: dict[str, str], keys: tuple[str, str, str]) -> tuple[str, str, str] | None:
    found = tuple(LEVEL.get(metrics.get(key, "")) for key in keys)
    if any(level is None for level in found):
        return None
    return found  # type: ignore[return-value]


def parse_impact(cvss_vector: str | None, cvss_version: str | None) -> Impact:
    assumed = Impact(*HIGH, source="assumed")
    if not isinstance(cvss_vector, str) or not cvss_vector.strip():
        return assumed
    metrics = _metrics(cvss_vector)
    if metrics is None:
        return assumed
    prefix = cvss_vector.strip().split("/", 1)[0]
    version = prefix.removeprefix("CVSS:") if prefix.startswith("CVSS:") else (cvss_version or "")
    if version in ("3.0", "3.1"):
        base = _levels(metrics, ("C", "I", "A"))
        return Impact(*base, source="vector") if base else assumed
    if version == "4.0":
        base = _levels(metrics, ("VC", "VI", "VA"))
        if not base:
            return assumed
        return Impact(*base, source="vector", subsequent=_levels(metrics, ("SC", "SI", "SA")))
    return assumed
