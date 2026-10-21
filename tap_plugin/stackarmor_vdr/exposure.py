"""Likely exploitable, for one row (`req-stackarmor-vdr-exposure`). Pure and Django-free.

In order: an evidence-backed evaluation factor decides (true or false); otherwise true when KEV is true, or EPSS is at or
above the threshold for the row's reachability; and true when neither reading exists. An absent reading is not evidence of
safety: unless both KEV and EPSS were observed and both say no, the row is likely exploitable (the spec text covers "both
unobserved"; one absent is read the same way).
"""

from __future__ import annotations

from decimal import Decimal


def likely_exploitable(
    backed: bool | None,
    kev: bool | None,
    epss: float | Decimal | None,
    *,
    internet_reachable: bool,
    epss_irv: float | Decimal,
    epss_non_irv: float | Decimal,
) -> bool:
    if backed is not None:
        return backed
    if kev is True:
        return True
    if epss is not None:
        threshold = Decimal(str(epss_irv if internet_reachable else epss_non_irv))
        if Decimal(str(epss)) >= threshold:
            return True
    # Neither reading says likely: false only when both were observed and both say no.
    return kev is None or epss is None
