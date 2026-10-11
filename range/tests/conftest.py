import pytest

from sutra_range import runner


@pytest.fixture(scope="session")
def score():
    return runner.run()
