"""The pure score, impact and exposure modules (`req-stackarmor-vdr-score`, `-impact`, `-exposure`)."""

from __future__ import annotations

import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from tap_plugin.stackarmor_vdr import exposure, impact, score

PACKAGE = Path(__file__).resolve().parents[1]
IMPACT_W = {"none": 0, "low": 0.22, "high": 0.56}
REQ_W = {"low": 0.5, "medium": 1.0, "high": 1.5}
KW = {"impact_weights": IMPACT_W, "requirement_weights": REQ_W, "u1": 0.28, "u2": 0.56, "theta3": 0.933}
H, M, L, N = "high", "medium", "low", "none"


def run(c_i_a: tuple[str, str, str], cr_ir_ar: tuple[str, str, str], m: int) -> score.Score:
    return score.score(c_i_a, cr_ir_ar, m, **KW)


class TestScore:
    @pytest.mark.spec("req-stackarmor-vdr-score-1")
    def test_it_imports_and_runs_with_django_blocked(self) -> None:
        code = (
            "import importlib.abc, importlib.util, sys\n"
            "class Block(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] in ('django', 'tap_grid', 'tap_plugin'):\n"
            "            raise ImportError('blocked: ' + name)\n"
            "sys.meta_path.insert(0, Block())\n"
            f"spec = importlib.util.spec_from_file_location('score', {str(PACKAGE / 'score.py')!r})\n"
            "m = importlib.util.module_from_spec(spec); sys.modules['score'] = m; spec.loader.exec_module(m)\n"
            "r = m.score(('high',)*3, ('high',)*3, 1, impact_weights={'none':0,'low':0.22,'high':0.56},"
            " requirement_weights={'low':0.5,'medium':1.0,'high':1.5}, u1=0.28, u2=0.56, theta3=0.933)\n"
            "print(r.pain, r.s)\n"
        )
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
        assert out.stdout.split() == ["N5", "1"]

    @pytest.mark.spec("req-stackarmor-vdr-score-2")
    @pytest.mark.parametrize(
        ("c_i_a", "cr_ir_ar", "m", "u", "pain"),
        [
            ((H, H, H), (H, H, H), 1, "0.995904", "N5"),  # example 1
            ((H, H, H), (M, M, M), 1, "0.914816", "N4"),  # example 2
            ((H, H, H), (L, L, L), 0, "0.626752", "N3"),  # example 3
            ((N, N, H), (M, M, H), 0, "0.840000", "N3"),  # example 4
            ((H, N, N), (L, M, M), 0, "0.280000", "N2"),  # example 5
        ],
    )
    def test_the_memos_five_worked_examples(
        self, c_i_a: tuple[str, str, str], cr_ir_ar: tuple[str, str, str], m: int, u: str, pain: str
    ) -> None:
        """U is computed from the spec's formula; the memo's printed numbers were not compared (the N-levels are its)."""
        result = run(c_i_a, cr_ir_ar, m)
        assert f"{result.u:.6f}" == u
        assert result.pain == pain

    @pytest.mark.spec("req-stackarmor-vdr-score-3")
    def test_exact_boundaries(self) -> None:
        at_u1 = run((H, N, N), (L, L, L), 0)
        at_u2 = run((H, N, N), (M, L, L), 0)
        assert at_u1.u == Decimal("0.28") and at_u1.word == "Narrow"
        assert at_u2.u == Decimal("0.56") and at_u2.word == "Disruptive"

    @pytest.mark.spec("req-stackarmor-vdr-score-3")
    def test_a_rounded_decimal_threshold_would_flip_example_5(self) -> None:
        """S at example 5 is 0.28 / D_H; theta1 as a rounded decimal (0.2812) would put it in Minimal."""
        example5 = run((H, N, N), (L, M, M), 0)
        assert example5.word == "Narrow"
        assert example5.s < Decimal("0.2812")

    @pytest.mark.spec("req-stackarmor-vdr-score-4")
    def test_the_maximum_is_d_h_and_all_high_scores_one(self) -> None:
        assert score.d_h(IMPACT_W, REQ_W) == Decimal("0.995904")
        top = run((H, H, H), (H, H, H), 1)
        assert top.s == 1 and top.word == "Debilitating"

    @pytest.mark.spec("req-stackarmor-vdr-score-5")
    @pytest.mark.parametrize(
        ("word", "m", "pain"),
        [
            ("Minimal", 0, "N1"),
            ("Minimal", 1, "N1"),
            ("Narrow", 0, "N2"),
            ("Narrow", 1, "N2"),
            ("Disruptive", 0, "N3"),
            ("Disruptive", 1, "N4"),
            ("Debilitating", 0, "N4"),
            ("Debilitating", 1, "N5"),
        ],
    )
    def test_n_level_from_word_and_flag(self, word: str, m: int, pain: str) -> None:
        assert score.pain_for(word, m) == pain

    @pytest.mark.spec("req-stackarmor-vdr-score-1")
    def test_no_impact_at_all_is_minimal(self) -> None:
        result = run((N, N, N), (H, H, H), 1)
        assert (result.u, result.word, result.pain) == (0, "Minimal", "N1")


class TestImpact:
    @pytest.mark.spec("req-stackarmor-vdr-impact-1")
    @pytest.mark.parametrize("version", ["3.0", "3.1"])
    def test_version_3(self, version: str) -> None:
        got = impact.parse_impact(f"CVSS:{version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", version)
        assert (got.vector, got.source) == (("high", "low", "none"), "vector")

    @pytest.mark.spec("req-stackarmor-vdr-impact-2")
    def test_version_4_scores_vulnerable_system_only(self) -> None:
        got = impact.parse_impact("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:H/SA:H", "4.0")
        assert got.vector == ("low", "high", "none")
        assert got.subsequent == ("high", "high", "high")

    @pytest.mark.spec("req-stackarmor-vdr-impact-3")
    @pytest.mark.parametrize(
        "vector",
        [
            None,
            "",
            "garbage",
            "CVSS:3.1/AV:N",
            "CVSS:3.1/C:X/I:H/A:H",
            "CVSS:2.0/AV:N/C:P/I:P/A:P",
            "CVSS:3.1/C:H/C:L/I:H/A:H",
        ],
    )
    def test_missing_or_unparseable_is_high_and_assumed(self, vector: str | None) -> None:
        got = impact.parse_impact(vector, "3.1")
        assert (got.vector, got.source) == (("high", "high", "high"), "assumed")


class TestExposure:
    KW = {"epss_irv": 0.20, "epss_non_irv": 0.55}

    @pytest.mark.spec("req-stackarmor-vdr-exposure-1")
    @pytest.mark.parametrize(
        ("kev", "epss", "irv", "expected"),
        [
            (True, 0.0, True, True),
            (False, 0.20, True, True),
            (False, 0.19, True, False),
            (False, 0.54, False, False),
            (False, 0.55, False, True),
            (None, None, True, True),
            (False, None, True, True),
            (None, 0.01, False, True),
        ],
    )
    def test_kev_or_epss(self, kev: bool | None, epss: float | None, irv: bool, expected: bool) -> None:
        assert exposure.likely_exploitable(None, kev, epss, internet_reachable=irv, **self.KW) is expected

    @pytest.mark.spec("req-stackarmor-vdr-exposure-3")
    @pytest.mark.parametrize("backed", [True, False])
    def test_an_evidenced_factor_overrides_both_ways(self, backed: bool) -> None:
        kev = not backed
        assert (
            exposure.likely_exploitable(backed, kev, 0.99 if kev else 0.0, internet_reachable=True, **self.KW) is backed
        )
