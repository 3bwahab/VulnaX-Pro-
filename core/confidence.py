"""Multi-stage confidence scoring shared across detection & correlation.

Confidence rises with corroborating evidence, independent sources, fingerprint
agreement, and response consistency; it falls with weak/conflicting signals.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence, Evidence

# Named confidence levels (the prompt's four bands).
CRITICAL_CONFIDENCE = 0.9
HIGH_CONFIDENCE = 0.75
MEDIUM_CONFIDENCE = 0.5
LOW_CONFIDENCE = 0.25


def level_name(score: float) -> str:
    if score >= CRITICAL_CONFIDENCE:
        return "critical"
    if score >= HIGH_CONFIDENCE:
        return "high"
    if score >= MEDIUM_CONFIDENCE:
        return "medium"
    return "low"


@dataclass
class ConfidenceSignals:
    base: float = 0.5             # detector's intrinsic confidence
    evidence_count: int = 1       # number of evidence items
    independent_sources: int = 1  # distinct tools/engines that agree
    fingerprint_match: bool = False
    response_consistent: bool = True
    conflicting: bool = False


def score_confidence(sig: ConfidenceSignals) -> Confidence:
    score = sig.base
    # Corroboration: each extra evidence item / independent source nudges up.
    score += 0.06 * max(sig.evidence_count - 1, 0)
    score += 0.10 * max(sig.independent_sources - 1, 0)
    if sig.fingerprint_match:
        score += 0.08
    if not sig.response_consistent:
        score -= 0.15
    if sig.conflicting:
        score -= 0.25
    score = max(0.05, min(0.99, score))
    signals = sig.evidence_count + (sig.independent_sources - 1)
    rationale = (
        f"{level_name(score)} confidence: {sig.evidence_count} evidence item(s), "
        f"{sig.independent_sources} independent source(s)"
        + (", fingerprint match" if sig.fingerprint_match else "")
        + ("" if sig.response_consistent else ", inconsistent responses")
        + (", conflicting signals" if sig.conflicting else "")
    )
    return Confidence(score=round(score, 2), rationale=rationale, signals=signals)


def merge_confidence(existing: Confidence, extra_evidence: list[Evidence]) -> Confidence:
    """Raise confidence when an independent source corroborates a finding."""
    new_score = min(0.99, existing.score + 0.05 * len(extra_evidence))
    return Confidence(
        score=round(new_score, 2),
        rationale=existing.rationale + " | corroborated",
        signals=existing.signals + len(extra_evidence),
    )
