"""Tests never fetch the live threat-intel feeds in the background: that would change exploitation states mid-test.
``tests/test_intel.py`` refreshes them by hand against a fake CISA and FIRST."""

import os

os.environ["SUTRA_INTEL_REFRESH"] = "0"
