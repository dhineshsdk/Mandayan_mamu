"""Uploaded files are untrusted: XML entity tricks in a .nessus file must be refused, not expanded."""

import pytest
from defusedxml import DTDForbidden, EntitiesForbidden

from sutra import ingest

BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<NessusClientData_v2><Report name="x"><ReportHost name="10.0.0.1"><HostProperties/>
<ReportItem port="0" severity="3" pluginID="1" pluginName="&lol2;"/></ReportHost></Report></NessusClientData_v2>
"""


def test_entity_expansion_in_nessus_is_refused(tmp_path):
    path = tmp_path / "bomb.nessus"
    path.write_text(BOMB)
    with pytest.raises((EntitiesForbidden, DTDForbidden)):
        ingest.load_nessus(path)
