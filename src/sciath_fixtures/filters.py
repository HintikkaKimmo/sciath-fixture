"""Filters for controlling which labels make it into the fixture output.

- max-labels: cap total labels with deterministic sort order
- exclude-native: remove native/cross/nativesdk recipes
- min-cvss: filter by CVSS score (requires --cve-metadata)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Sort priority for deterministic --max-labels selection.
# Lower number = higher priority (kept first).
_STATUS_PRIORITY = {
    "affected": 0,     # Unpatched — most interesting for validation
    "not_affected": 1,  # Kconfig/DTB overrides — the money labels
    "fixed": 2,         # Patched — good but less novel
    "unknown": 3,
}


@dataclass
class LabelCandidate:
    cve_id: str
    component_name: str
    component_version: str
    true_status: str
    justification_category: str
    justification_text: str
    evidence: list[str]
    confidence: str
    cvss_score: float | None = None


def apply_max_labels(
    labels: list[LabelCandidate], max_labels: int
) -> list[LabelCandidate]:
    """Cap labels with deterministic ordering.

    Priority: affected > not_affected > fixed > unknown.
    Within same status: sorted by CVE ID (alphabetical) for reproducibility.
    """
    if len(labels) <= max_labels:
        return labels

    sorted_labels = sorted(
        labels,
        key=lambda lbl: (_STATUS_PRIORITY.get(lbl.true_status, 99), lbl.cve_id),
    )
    logger.info(
        "Capping labels from %d to %d (--max-labels)", len(labels), max_labels
    )
    return sorted_labels[:max_labels]


def apply_min_cvss(
    labels: list[LabelCandidate], min_cvss: float
) -> list[LabelCandidate]:
    """Filter out labels below a CVSS threshold.

    Labels without a CVSS score are kept (conservative — don't drop unknowns).
    """
    has_scores = any(lbl.cvss_score is not None for lbl in labels)
    if not has_scores:
        logger.warning(
            "--min-cvss specified but no CVSS scores available. "
            "Provide --cve-metadata to enable CVSS filtering. "
            "Keeping all labels."
        )
        return labels

    result = [lbl for lbl in labels if lbl.cvss_score is None or lbl.cvss_score >= min_cvss]
    dropped = len(labels) - len(result)
    if dropped:
        logger.info("Dropped %d labels below CVSS %.1f", dropped, min_cvss)
    return result
