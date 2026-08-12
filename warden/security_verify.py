"""The security half of step 4's output-verification (ROADMAP step 4,
`~/dev/cagetheagent/ROADMAP.md`): does the build's artifact *hide* something bad — an injected
dependency, a backdoor, a package-squat, a vuln? A canon-verified ThreatForest (attack-tree
analysis over the produced code) is the design; this module is its interface, not its
implementation.

**Honestly not built.** The roadmap names canon's own open gaps here — a semantic verifier,
justification-as-fold, calibrated numbers — and this module does not pretend around them. It
mirrors `report.py`'s `canon_emit.CANON_AVAILABLE` / `verdicts_unavailable_reason` discipline:
canon's absence is a stated fact carried on the result, never worked around and never faked as an
empty-but-present pass. A clean `SecurityVerdict` (`findings=()`) would be indistinguishable from
"checked and found nothing" — exactly the completion theater this module exists to refuse. So
`verify_security` returns `available=False` with a reason, unconditionally, until a real
integration lands and flips `THREATFOREST_AVAILABLE`.

Once built, canon stamps this low-tier regardless (ROADMAP step 4): VM-root's process trust is
already forgeable, so the security half carries real governance weight, and canon's own guarantee
tiers say so explicitly rather than letting a pass here read as more assurance than it is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

#: Flips to True the day a real canon-ThreatForest integration lands here. False, unconditionally,
#: until then — see the module docstring. Not a config toggle a caller can set: there is no partial
#: or best-effort mode for a security check, only "ran" or "did not."
THREATFOREST_AVAILABLE = False


@dataclass(frozen=True)
class SecurityVerdict:
    available: bool
    reason: Optional[str]
    #: Populated only when `available` is True — never `()` standing in for "not run".
    findings: Optional[tuple[str, ...]]
    #: canon's guarantee tier for this verdict (e.g. "well_formed"). None while unavailable.
    guarantee_tier: Optional[str]


def verify_security(artifact_sha256: Optional[str]) -> SecurityVerdict:
    """The stub every caller gets today. Takes the artifact's hash (not the bytes) because even a
    "not run" verdict should be tied to *which* artifact it was not run against — the same
    provenance discipline `output_verify.ArtifactCheck.sha256` already carries.
    """
    if not THREATFOREST_AVAILABLE:
        return SecurityVerdict(
            available=False,
            reason=(
                "canon-ThreatForest security verification is not built (ROADMAP step 4) — "
                "canon's semantic-verifier / justification-as-fold / calibrated-numbers gaps are "
                "open upstream. Stated absence, not a pass: no artifact has been checked for "
                "hidden backdoors, injected dependencies, package-squats, or vulnerabilities."
            ),
            findings=None,
            guarantee_tier=None,
        )
    raise NotImplementedError(  # pragma: no cover - unreachable while THREATFOREST_AVAILABLE is False
        "THREATFOREST_AVAILABLE is True but verify_security has no real implementation yet"
    )
