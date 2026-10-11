"""Read-only API connectors that pull findings and hosts from vulnerability scanners into Sutra.

Connectors: :class:`QualysConnector` (Qualys VMDR), :class:`TenableVMConnector` (Tenable Vulnerability Management,
formerly Tenable.io), :class:`TenableSCConnector` (Tenable Security Center), :class:`CrowdStrikeConnector`
(CrowdStrike Falcon Spotlight), :class:`AwsInspectorConnector` (Amazon Inspector) and
:class:`AzureDefenderConnector` (Microsoft Defender for Cloud) and :class:`NozomiConnector` (Nozomi Networks Guardian
or CMC, for OT networks). Each yields
:class:`~sutra_connectors.models.ScannerFinding` and :class:`~sutra_connectors.models.ScannerHost` records;
:func:`~sutra_connectors.state.sync` runs incremental pulls with checkpoints, and
:mod:`sutra_connectors.sutra_rows` feeds the results to Sutra's ingest pipeline.

Configuration collectors (read-only, secrets masked at source; see :mod:`sutra_connectors.netdevices`):
:class:`FortiGateCollector` (FortiOS REST API), :class:`PanOsCollector` (PAN-OS XML API) and
:class:`CiscoIosCollector` (Cisco IOS and IOS-XE over SSH). Each returns a
:class:`~sutra_connectors.netdevices.DeviceSnapshot`.
"""

__version__ = "0.1.0"

from .aws_inspector import AwsInspectorConnector  # noqa: E402
from .azure_defender import AzureDefenderConnector  # noqa: E402
from .cisco_ios import CiscoIosCollector  # noqa: E402
from .crowdstrike import CrowdStrikeConnector  # noqa: E402
from .fortigate import FortiGateCollector  # noqa: E402
from .models import ScannerFinding, ScannerHost  # noqa: E402
from .netdevices import DeviceSnapshot  # noqa: E402
from .nozomi import NozomiConnector  # noqa: E402
from .panos import PanOsCollector  # noqa: E402
from .qualys import QualysConnector  # noqa: E402
from .tenable_sc import TenableSCConnector  # noqa: E402
from .tenable_vm import TenableVMConnector  # noqa: E402

__all__ = ["AwsInspectorConnector", "AzureDefenderConnector", "CiscoIosCollector", "CrowdStrikeConnector",
           "DeviceSnapshot", "FortiGateCollector", "NozomiConnector", "PanOsCollector", "QualysConnector",
           "ScannerFinding", "ScannerHost", "TenableSCConnector", "TenableVMConnector", "__version__"]
