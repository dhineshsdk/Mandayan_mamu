from __future__ import annotations

from datetime import date, datetime

import pytest
from conftest import IST

from sutra_compliance import Duration, add_months


@pytest.mark.parametrize("start, months, expected", [
    (date(2027, 5, 10), 1, date(2027, 6, 10)),
    (date(2027, 1, 31), 1, date(2027, 2, 28)),
    (date(2028, 1, 31), 1, date(2028, 2, 29)),
    (date(2027, 11, 30), 3, date(2028, 2, 29)),
    (date(2027, 12, 15), 1, date(2028, 1, 15)),
    (date(2027, 4, 5), 6, date(2027, 10, 5)),
    (date(2027, 8, 31), 6, date(2028, 2, 29)),
])
def test_add_months_clamps_to_month_end(start, months, expected):
    assert add_months(start, months) == expected


def test_weeks_and_days():
    assert Duration(weeks=6).after(date(2027, 4, 5)) == date(2027, 5, 17)
    assert Duration(days=30).after(date(2027, 1, 31)) == date(2027, 3, 2)


def test_hours_need_a_datetime():
    with pytest.raises(ValueError):
        Duration(hours=6).after(date(2027, 4, 5))
    with pytest.raises(TypeError):
        Duration(days=1).after(datetime(2027, 4, 5, tzinfo=IST))
    assert Duration(hours=6).after_datetime(datetime(2027, 4, 5, 22, 0, tzinfo=IST)) == \
        datetime(2027, 4, 6, 4, 0, tzinfo=IST)


def test_naive_datetime_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        Duration(hours=6).after_datetime(datetime(2027, 4, 5, 10))


@pytest.mark.parametrize("raw", [{}, {"months": 0}, {"months": -1}, {"months": 1.5}, {"months": True},
                                 {"years": 1}])
def test_invalid_durations(raw):
    with pytest.raises(ValueError):
        Duration.from_mapping(raw)


def test_str():
    assert str(Duration(months=1)) == "1 month"
    assert str(Duration(weeks=6)) == "6 weeks"
    assert str(Duration(months=1, days=2)) == "1 month, 2 days"
