import pytest

from sutra_scan.cvss import base_score, rating


@pytest.mark.parametrize(("vector", "score"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 7.7),  # the vector on RLSA-2019:0975; worked by hand from the specification
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
])
def test_known_scores(vector, score):
    assert base_score(vector) == score


@pytest.mark.parametrize("bad", ["", "AV:N/AC:L", "CVSS:2.0/AV:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                 "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L"])
def test_unscorable(bad):
    assert base_score(bad) is None


def test_rating_bands():
    assert [rating(x) for x in (None, 0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)] == [
        "", "info", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]
