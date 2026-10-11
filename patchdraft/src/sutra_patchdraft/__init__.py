"""Sutra patch-job drafting: from a root cause and its hosts to a checked, cited patch-job draft.

    from sutra_patchdraft import PatchDrafter, from_sutra
    draft = PatchDrafter().draft(from_sutra(rc, hosts, findings, as_of))

With ``ANTHROPIC_API_KEY`` set and the ``anthropic`` package installed, drafts come from Claude; otherwise, or when a
model draft fails the checks, they come from rule-based templates. Either way the draft has passed the same
validation, and it never carries an approval route.
"""

from .draft import Citation, PatchJobDraft, Ring, Step
from .drafter import DEFAULT_MODEL, DrafterConfig, PatchDrafter, draft_patch_job, template_only
from .inputs import DraftInput, FindingInput, HostInput, InputError, MaintenancePolicy, RootCauseInput, from_sutra

__all__ = [
    "Citation", "DEFAULT_MODEL", "DraftInput", "DrafterConfig", "FindingInput", "HostInput", "InputError",
    "MaintenancePolicy", "PatchDrafter", "PatchJobDraft", "Ring", "RootCauseInput", "Step", "draft_patch_job",
    "from_sutra", "template_only",
]
