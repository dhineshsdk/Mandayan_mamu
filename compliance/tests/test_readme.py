"""Keep the README example runnable."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from sutra_compliance import EntityStatus, FindingState, verify_audit_pack


def test_readme_example_runs():
    text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    code = re.search(r"```python\n(.*?)```", text, re.S).group(1)
    ns: dict = {}
    exec(compile(code, "README.md", "exec"), ns)
    result = ns["result"]
    assert result.status is EntityStatus.ATTENTION
    finding = result.audits[0].findings[0]
    assert finding.due_on == date(2027, 6, 10)
    assert finding.state is FindingState.OVERDUE_COMPENSATED
    assert verify_audit_pack(ns["audit_pack"].to_json())
