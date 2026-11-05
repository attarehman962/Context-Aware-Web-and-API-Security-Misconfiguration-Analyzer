"""CVSS v3.1 vector parsing and base scores against FIRST reference values."""

from __future__ import annotations

import pytest

from app.core.cvss31 import CvssVectorError, base_score, parse_base_vector, roundup


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),  # PR:L with scope change
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_reference_scores(vector, expected):
    assert base_score(vector) == expected


def test_roundup_is_float_safe():
    assert roundup(4.000000001) == 4.0  # float noise is not rounded up (spec App. A)
    assert roundup(4.0) == 4.0
    assert roundup(4.02) == 4.1


@pytest.mark.parametrize(
    "vector, message",
    [
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "must start with"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "must start with"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "missing base metric"),
        ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "invalid value"),
        ("CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "appears twice"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P", "not a CVSS v3.1 base metric"),
        ("CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H", "must be in order"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A", "malformed"),
    ],
)
def test_rejects_invalid_vectors(vector, message):
    with pytest.raises(CvssVectorError, match=message):
        parse_base_vector(vector)
