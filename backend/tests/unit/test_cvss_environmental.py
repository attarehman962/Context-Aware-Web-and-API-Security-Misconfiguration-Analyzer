"""Context-aware CVSS v3.1 environmental scoring (Atta Prompt 6).

The scorer uses the ``cvss`` library; this test re-derives every number with an
independent implementation of the FIRST v3.1 equations (spec sections 7.1 and
7.3), so a library bug or a wrong mapping can't pass silently.
"""

from __future__ import annotations

import itertools
import math
from pathlib import Path

import pytest
from cvss import CVSS3

from app.config import settings
from app.core.checks.registry import RawFinding
from app.core.contracts import BodySignal, EndpointInfo, SensitivityClass
from app.core.cvss import ContextScore, environmental_score, score_finding, severity_bucket
from app.core.specs import load_checks
from app.db.models.enums import Severity

CHECKS = load_checks(Path(settings.CONFIG_DIR) / "checks.yaml").checks
VECTORS = sorted({c.base_cvss_vector for c in CHECKS})
CLASSES = [
    SensitivityClass.LOW,
    SensitivityClass.MEDIUM,
    SensitivityClass.HIGH,
    SensitivityClass.CRITICAL,
]
SIGNAL_SETS = [
    set(s) for n in range(len(BodySignal) + 1) for s in itertools.combinations(BodySignal, n)
]


# --------------------------------------------- independent FIRST oracle

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
    "REQ": {"L": 0.5, "M": 1.0, "H": 1.5, "X": 1.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def oracle_environmental(vector: str) -> float:
    """FIRST CVSS v3.1 environmental score; modified base metrics = base metrics."""
    m = dict(part.split(":") for part in vector.split("/")[1:])
    changed = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
    miss = min(
        1
        - (1 - _W["REQ"][m.get("CR", "X")] * _W["CIA"][m["C"]])
        * (1 - _W["REQ"][m.get("IR", "X")] * _W["CIA"][m["I"]])
        * (1 - _W["REQ"][m.get("AR", "X")] * _W["CIA"][m["A"]]),
        0.915,
    )
    impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13 if changed else 6.42 * miss
    exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploit) if changed else impact + exploit
    return _roundup(_roundup(min(total, 10)))  # temporal metrics X -> x1


# ------------------------------------------------------------- examples


@pytest.mark.parametrize(
    "vector, base",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # CVE-2014-0160 Heartbleed
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # CVE-2014-6271 Shellshock
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # CVE-2013-1937 phpMyAdmin XSS
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ],
)
def test_first_reference_base_scores(vector, base):
    result = environmental_score(vector, SensitivityClass.LOW, set())
    assert result.base_score == base


def test_every_check_and_context_matches_the_first_equations():
    for vector, cls, signals in itertools.product(VECTORS, CLASSES, SIGNAL_SETS):
        result = environmental_score(vector, cls, signals)
        assert result.final_score == oracle_environmental(result.vector), (vector, cls, signals)


# ---------------------------------------------------------- properties


def test_higher_sensitivity_never_lowers_the_score():
    for vector, signals in itertools.product(VECTORS, SIGNAL_SETS):
        scores = [environmental_score(vector, cls, signals).final_score for cls in CLASSES]
        assert scores == sorted(scores), (vector, signals, scores)


def test_signals_only_raise_never_lower():
    for vector, cls in itertools.product(VECTORS, CLASSES):
        plain = environmental_score(vector, cls, set()).final_score
        for signals in SIGNAL_SETS:
            assert environmental_score(vector, cls, signals).final_score >= plain


def test_vectors_round_trip_to_the_same_scores():
    for vector, cls, signals in itertools.product(VECTORS, CLASSES, SIGNAL_SETS[:4]):
        result = environmental_score(vector, cls, signals)
        parsed = CVSS3(result.vector)
        assert float(parsed.base_score) == result.base_score
        assert float(parsed.environmental_score) == result.final_score
        assert result.vector.startswith(vector + "/CR:")


def test_only_security_requirements_are_added():
    result = environmental_score(
        CHECKS[0].base_cvss_vector, SensitivityClass.CRITICAL, {BodySignal.CREDENTIALS}
    )
    added = result.vector[len(CHECKS[0].base_cvss_vector) + 1 :].split("/")
    assert [m.split(":")[0] for m in added] == ["CR", "IR", "AR"]  # no MAV, MAC, ...


@pytest.mark.parametrize(
    "score, bucket, name",
    [
        (0.0, Severity.INFO, "None"),
        (0.1, Severity.LOW, "Low"),
        (3.9, Severity.LOW, "Low"),
        (4.0, Severity.MEDIUM, "Medium"),
        (6.9, Severity.MEDIUM, "Medium"),
        (7.0, Severity.HIGH, "High"),
        (8.9, Severity.HIGH, "High"),
        (9.0, Severity.CRITICAL, "Critical"),
        (10.0, Severity.CRITICAL, "Critical"),
    ],
)
def test_severity_buckets_follow_the_v31_ranges(score, bucket, name):
    assert severity_bucket(score) == (bucket, name)


# ------------------------------------------------- reasons + findings


def test_score_reasons_say_where_each_requirement_came_from():
    # Asim's mapping: HIGH -> CR:H IR:M AR:M; PII -> CR:H; CREDENTIALS -> CR:H IR:H AR:M.
    result = environmental_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        SensitivityClass.HIGH,
        {BodySignal.CREDENTIALS},
    )
    assert result.requirements == {"CR": "H", "IR": "H", "AR": "M"}
    assert result.score_reasons[:2] == ["sensitivity:HIGH", "signal:CREDENTIALS"]
    assert "IR:H<-signal:CREDENTIALS" in result.score_reasons
    assert "CR:H<-sensitivity:HIGH+signal:CREDENTIALS" in result.score_reasons
    assert result.score_reasons[-1] == f"environmental:{result.final_score}"


def test_public_endpoint_without_signals_keeps_the_base_score():
    result = environmental_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", SensitivityClass.LOW, set()
    )
    assert result.final_score == result.base_score == 5.4
    assert "no-context-change" in result.score_reasons


def test_score_finding_uses_the_checks_yaml_vector():
    finding = RawFinding(
        "HDR-001",
        EndpointInfo("https://shop.example.com/login", "/login"),
        {"text": "Missing HSTS"},
    )
    result = score_finding(finding, SensitivityClass.HIGH, set())
    spec_vector = next(c.base_cvss_vector for c in CHECKS if c.check_id == "HDR-001")
    assert isinstance(result, ContextScore) and result.vector.startswith(spec_vector)
    assert result.base_score == float(CVSS3(spec_vector).base_score)


def test_rejects_vectors_that_already_carry_environmental_metrics():
    with pytest.raises(ValueError, match="base vector"):
        environmental_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:H", SensitivityClass.LOW, set()
        )
