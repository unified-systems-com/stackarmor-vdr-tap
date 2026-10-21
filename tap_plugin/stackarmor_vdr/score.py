"""The stackArmor score, a pure function (`req-stackarmor-vdr-score`).

Django-free and reading no node: the impact vector (C, I, A), the effective requirement vector (CR, IR, AR) and the
affected-agency flag ``m`` in, every intermediate value out. The weights and the thresholds are parameters, never
constants here: they are the Search's governed inputs (`req-stackarmor-vdr-search-3`). The arithmetic is
``decimal.Decimal`` because the memo's worked example 5 sits exactly on the first boundary.

    U   = 1 - (1 - C*CR) * (1 - I*IR) * (1 - A*AR)
    D_H = 1 - (1 - max_impact * max_requirement) ** 3        (computed from the weights)
    S   = U / D_H

The first two boundaries are compared as ``U`` against ``u1`` and ``u2`` (the memo's 0.28 and 0.56, which are
``theta1 * D_H`` and ``theta2 * D_H``), never as a rounded decimal ``theta``; the third is ``S`` against ``theta3``.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

WORDS = ("Minimal", "Narrow", "Disruptive", "Debilitating")


@dataclass(frozen=True)
class Score:
    u: Decimal
    s: Decimal
    d_h: Decimal
    word: str
    pain: str


def _d(value: Any) -> Decimal:
    return Decimal(str(value))


def d_h(impact_weights: dict[str, Any], requirement_weights: dict[str, Any]) -> Decimal:
    """The maximum of ``U`` (all-High impact at all-High requirements), from the weights."""
    top = _d(impact_weights["high"]) * _d(requirement_weights["high"])
    return 1 - (1 - top) ** 3


def word_for(u: Decimal, s: Decimal, *, u1: Decimal, u2: Decimal, theta3: Decimal) -> str:
    if u < u1:
        return "Minimal"
    if u < u2:
        return "Narrow"
    if s < theta3:
        return "Disruptive"
    return "Debilitating"


def pain_for(word: str, multi_agency: int) -> str:
    """N-level from the word and the affected-agency flag (`req-stackarmor-vdr-score-5`)."""
    if word == "Minimal":
        return "N1"
    if word == "Narrow":
        return "N2"
    if word == "Disruptive":
        return "N4" if multi_agency else "N3"
    return "N5" if multi_agency else "N4"


def score(
    impact: tuple[str, str, str],
    requirement: tuple[str, str, str],
    multi_agency: int,
    *,
    impact_weights: dict[str, Any],
    requirement_weights: dict[str, Any],
    u1: Any,
    u2: Any,
    theta3: Any,
) -> Score:
    """Score one impact vector at one requirement vector; the keys of the weight maps are lower-case levels."""
    survive = Decimal(1)
    for imp, req in zip(impact, requirement, strict=True):
        survive *= 1 - _d(impact_weights[imp.lower()]) * _d(requirement_weights[req.lower()])
    u = 1 - survive
    denominator = d_h(impact_weights, requirement_weights)
    s = u / denominator
    word = word_for(u, s, u1=_d(u1), u2=_d(u2), theta3=_d(theta3))
    return Score(u=u, s=s, d_h=denominator, word=word, pain=pain_for(word, multi_agency))
