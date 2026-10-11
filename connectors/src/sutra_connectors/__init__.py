"""Read-only API connectors that pull findings and hosts from vulnerability scanners into Sutra.

Connectors: :class:`QualysConnector` (Qualys VMDR), :class:`TenableVMConnector` (Tenable Vulnerability Management,
formerly Tenable.io), :class:`TenableSCConnector` (Tenable Security Center), :class:`CrowdStrikeConnector`
(CrowdStrike Falcon Spotlight), :class:`AwsInspectorConnector` (Amazon Inspector) and
:class:`AzureDefenderConnector` (Microsoft Defender for Cloud). Each yields
:class:`~sutra_connectors.models.ScannerFinding` and :class:`~sutra_connectors.models.ScannerHost` records;
:func:`~sutra_connectors.state.sync` runs incremental pulls with checkpoints, and
:mod:`sutra_connectors.sutra_rows` feeds the results to Sutra's ingest pipeline.
"""

__version__ = "0.1.0"

from .aws_inspector import AwsInspectorConnector  # noqa: E402
from .azure_defender import AzureDefenderConnector  # noqa: E402
from .crowdstrike import CrowdStrikeConnector  # noqa: E402
from .models import ScannerFinding, ScannerHost  # noqa: E402
from .qualys import QualysConnector  # noqa: E402
from .tenable_sc import TenableSCConnector  # noqa: E402
from .tenable_vm import TenableVMConnector  # noqa: E402

__all__ = ["AwsInspectorConnector", "AzureDefenderConnector", "CrowdStrikeConnector", "QualysConnector",
           "ScannerFinding", "ScannerHost", "TenableSCConnector", "TenableVMConnector", "__version__"]
