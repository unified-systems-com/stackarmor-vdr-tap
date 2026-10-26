"""The domain of the scoring parameters (`req-stackarmor-vdr-search-14`). Pure and Django-free.

The schema bounds every weight and threshold to a number of at least 0, which is not enough for the score to mean anything:
all-zero impact weights divide 0 by 0, and an impact weight times a requirement weight above 1 makes ``U`` negative. A caller
may still pass its own weights (a what-if run), but only inside the domain the method is defined on, so a bad set is refused
before any row is scored, never scored into a wrong N-level.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from .score import d_h


class PolicyError(ValueError):
    """A scoring parameter set outside the domain the method is defined on."""


def _d(value: Any) -> Decimal:
    return Decimal(str(value))


def validate_policy(p: dict[str, Any]) -> None:
    """Raise `PolicyError` naming the first rule `p` (defaulted inputs) breaks."""
    impact, req = p["impact_weights"], p["requirement_weights"]
    none, low, high = (_d(impact[k]) for k in ("none", "low", "high"))
    if not 0 <= none < low < high <= 1:
        raise PolicyError("impact_weights must satisfy 0 <= none < low < high <= 1")
    r_low, r_med, r_high = (_d(req[k]) for k in ("low", "medium", "high"))
    if not 0 < r_low <= r_med <= r_high:
        raise PolicyError("requirement_weights must satisfy 0 < low <= medium <= high")
    if high * r_high > 1:
        raise PolicyError("impact_weights.high times requirement_weights.high must not exceed 1, or U goes negative")
    ceiling = d_h(impact, req)
    u1, u2, theta3 = _d(p["u1"]), _d(p["u2"]), _d(p["theta3"])
    if not 0 < u1 < u2 <= ceiling:
        raise PolicyError(f"u1 and u2 must satisfy 0 < u1 < u2 <= D_H ({ceiling:.6f})")
    if not 0 < theta3 <= 1:
        raise PolicyError("theta3 must satisfy 0 < theta3 <= 1")
    for key in ("epss_irv", "epss_non_irv"):
        if not 0 <= _d(p[key]) <= 1:
            raise PolicyError(f"{key} must be between 0 and 1")
