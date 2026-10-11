"""Read-only API connectors that pull findings and hosts from vulnerability scanners into Sutra.

Connectors: :class:`QualysConnector` (Qualys VMDR), :class:`TenableVMConnector` (Tenable Vulnerability Management,
formerly Tenable.io), :class:`TenableSCConnector` (Tenable Security Center) and :class:`CrowdStrikeConnector`
(CrowdStrike Falcon Spotlight). Each yields
:class:`~sutra_connectors.models.ScannerFinding` and :class:`~sutra_connectors.models.ScannerHost` records;
:func:`~sutra_connectors.state.sync` runs incremental pulls with checkpoints, and
:mod:`sutra_connectors.sutra_rows` feeds the results to Sutra's ingest pipeline.
"""

__version__ = "0.1.0"

from .crowdstrike import CrowdStrikeConnector  # noqa: E402
from .models import ScannerFinding, ScannerHost  # noqa: E402
from .qualys import QualysConnector  # noqa: E402
from .tenable_sc import TenableSCConnector  # noqa: E402
from .tenable_vm import TenableVMConnector  # noqa: E402

__all__ = ["CrowdStrikeConnector", "QualysConnector", "ScannerFinding", "ScannerHost", "TenableSCConnector",
           "TenableVMConnector", "__version__"]
