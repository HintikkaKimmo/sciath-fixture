"""CVE classification logic for ground truth fixture generation.

Determines the true_status of each CVE based on cve-check status,
kconfig settings, and DTB hardware presence.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sciath_fixtures.dtb_parser import DTBNode
from sciath_fixtures.filters import LabelCandidate
from sciath_fixtures.mappings import (
    PERIPHERAL_TO_SYMBOL,
    SUBSYSTEM_TO_SYMBOL,
    _get_subsystem_tags,
)

if TYPE_CHECKING:
    from sciath_fixtures.cve_check_parser import CveEntry
    from sciath_fixtures.fixture_builder import CveMetadata

logger = logging.getLogger(__name__)


def _check_kconfig_suppression(
    cve_id: str,
    subsystem_tags: list[str],
    kconfig: dict[str, str],
) -> str | None:
    """Check if a CVE is suppressed by kconfig settings.

    Returns the suppressing symbol name, or None if not suppressed.
    """
    for tag in subsystem_tags:
        symbol = SUBSYSTEM_TO_SYMBOL.get(tag)
        if symbol and symbol in kconfig:
            value = kconfig[symbol]
            if value == "n":
                return symbol
    return None


def _check_dtb_suppression(
    subsystem_tags: list[str],
    dtb_nodes: list[DTBNode],
) -> str | None:
    """Check if a CVE is suppressed by DTB (hardware not present).

    Returns the peripheral type if suppressed, or None.
    """
    for tag in subsystem_tags:
        symbol = SUBSYSTEM_TO_SYMBOL.get(tag)
        if not symbol:
            continue
        peripheral_key = None
        for ptype, sym in PERIPHERAL_TO_SYMBOL.items():
            if sym == symbol:
                peripheral_key = ptype
                break
        if not peripheral_key:
            continue
        # Check if any DTB node of this type exists and is enabled.
        matching_nodes = [n for n in dtb_nodes if n.peripheral_type == peripheral_key]
        if matching_nodes and all(not n.is_enabled for n in matching_nodes):
            return peripheral_key
    return None


def _classify_cve(
    entry: CveEntry,
    component_name: str,
    component_version: str,
    kconfig: dict[str, str] | None,
    dtb_nodes: list[DTBNode] | None,
    metadata: dict[str, CveMetadata] | None,
) -> LabelCandidate | None:
    """Classify a single CVE entry into a ground truth label.

    Suppression precedence: kconfig > DTB > default (affected).
    When both kconfig and DTB could suppress a CVE, kconfig wins because
    it represents a compile-time decision (feature compiled out) which is
    more definitive than DTB (hardware not present but code still exists).
    """
    cvss = None
    if metadata and entry.cve_id in metadata:
        cvss = metadata[entry.cve_id].cvss_score or None

    if entry.status == "Patched":
        return LabelCandidate(
            cve_id=entry.cve_id,
            component_name=component_name,
            component_version=component_version,
            true_status="fixed",
            justification_category="patched_backport",
            justification_text=(
                f"Yocto cve-check reports {entry.cve_id} as Patched "
                f"for {component_name} {component_version}."
            ),
            evidence=["cve-check: status=Patched"],
            confidence="high",
            cvss_score=cvss,
        )

    if entry.status == "Unpatched":
        subsystem_tags = _get_subsystem_tags(entry.cve_id, metadata)

        # Check kconfig suppression (only for kernel CVEs with kconfig data).
        if kconfig and component_name == "linux-kernel" and subsystem_tags:
            symbol = _check_kconfig_suppression(
                entry.cve_id, subsystem_tags, kconfig
            )
            if symbol:
                return LabelCandidate(
                    cve_id=entry.cve_id,
                    component_name=component_name,
                    component_version=component_version,
                    true_status="not_affected",
                    justification_category="kconfig_disabled",
                    justification_text=(
                        f"Kernel subsystem disabled: CONFIG_{symbol}=n. "
                        f"{entry.cve_id} requires this subsystem."
                    ),
                    evidence=[
                        "cve-check: status=Unpatched",
                        f"kconfig: CONFIG_{symbol}=n",
                        f"subsystem: {', '.join(subsystem_tags)}",
                    ],
                    confidence="high",
                    cvss_score=cvss,
                )

        # Check DTB suppression.
        if dtb_nodes and component_name == "linux-kernel" and subsystem_tags:
            ptype = _check_dtb_suppression(subsystem_tags, dtb_nodes)
            if ptype:
                return LabelCandidate(
                    cve_id=entry.cve_id,
                    component_name=component_name,
                    component_version=component_version,
                    true_status="not_affected",
                    justification_category="hw_not_present",
                    justification_text=(
                        f"Hardware peripheral '{ptype}' is disabled in device tree. "
                        f"{entry.cve_id} requires this hardware."
                    ),
                    evidence=[
                        "cve-check: status=Unpatched",
                        f"dtb: {ptype} peripheral disabled",
                        f"subsystem: {', '.join(subsystem_tags)}",
                    ],
                    confidence="high",
                    cvss_score=cvss,
                )

        # Default: genuinely affected.
        return LabelCandidate(
            cve_id=entry.cve_id,
            component_name=component_name,
            component_version=component_version,
            true_status="affected",
            justification_category="confirmed_affected",
            justification_text=(
                f"Yocto cve-check reports {entry.cve_id} as Unpatched "
                f"for {component_name} {component_version}."
            ),
            evidence=["cve-check: status=Unpatched"],
            confidence="high",
            cvss_score=cvss,
        )

    if entry.status == "Ignored":
        detail_lower = entry.detail.lower() if entry.detail else ""
        if "not-applicable" in detail_lower or "not applicable" in detail_lower:
            return LabelCandidate(
                cve_id=entry.cve_id,
                component_name=component_name,
                component_version=component_version,
                true_status="not_affected",
                justification_category="version_not_affected",
                justification_text=(
                    f"Yocto cve-check marks {entry.cve_id} as Ignored "
                    f"(not-applicable) for {component_name} {component_version}."
                ),
                evidence=[
                    "cve-check: status=Ignored",
                    f"detail: {entry.detail}",
                ],
                confidence="high",
                cvss_score=cvss,
            )
        # Ambiguous Ignored -- skip.
        logger.debug(
            "Skipping ambiguous Ignored CVE %s for %s: %s",
            entry.cve_id, component_name, entry.detail,
        )
        return None

    logger.warning("Unknown cve-check status '%s' for %s", entry.status, entry.cve_id)
    return None


def _dedup_labels(labels: list[LabelCandidate]) -> list[LabelCandidate]:
    """Deduplicate labels by (cve_id, component_name).

    Precedence: fixed > not_affected > affected > unknown.
    """
    priority = {"fixed": 0, "not_affected": 1, "affected": 2, "unknown": 3}
    best: dict[tuple[str, str], LabelCandidate] = {}

    for label in labels:
        key = (label.cve_id, label.component_name)
        existing = best.get(key)
        if existing is None:
            best[key] = label
        else:
            existing_prio = priority.get(existing.true_status, 99)
            new_prio = priority.get(label.true_status, 99)
            if new_prio < existing_prio:
                logger.info(
                    "Dedup conflict for %s/%s: %s wins over %s",
                    label.cve_id, label.component_name,
                    label.true_status, existing.true_status,
                )
                best[key] = label

    return list(best.values())
