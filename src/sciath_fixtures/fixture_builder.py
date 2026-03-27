"""Assemble a Sciath-compatible ground truth fixture JSON.

Combines parsed cve-check data, name mappings, kconfig overlay, DTB overlay,
and filters into a single fixture file loadable by Sciath's load_ground_truth.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sciath_fixtures.cve_check_parser import CveCheckReport, CveEntry
from sciath_fixtures.dtb_parser import DTBNode
from sciath_fixtures.filters import LabelCandidate, apply_max_labels, apply_min_cvss
from sciath_fixtures.name_mapper import map_recipe

logger = logging.getLogger(__name__)

# Known CVE → subsystem mappings for offline kconfig overlay.
# These are well-known kernel CVEs where the subsystem is unambiguous.
# Used when --cve-metadata is not provided.
KNOWN_CVE_SUBSYSTEMS: dict[str, list[str]] = {
    # Bluetooth
    "CVE-2020-12351": ["bluetooth"],  # BleedingTooth
    "CVE-2020-12352": ["bluetooth"],  # BleedingTooth info leak
    "CVE-2021-3564": ["bluetooth"],   # double free in hci_sock
    "CVE-2021-3573": ["bluetooth"],   # use-after-free in hci_sock
    "CVE-2022-42896": ["bluetooth"],  # L2CAP use-after-free
    # WiFi
    "CVE-2022-41674": ["wifi"],  # cfg80211 buffer overflow
    "CVE-2022-42719": ["wifi"],  # mac80211 use-after-free
    "CVE-2022-42720": ["wifi"],  # mac80211 use-after-free
    "CVE-2022-42721": ["wifi"],  # mac80211 list corruption
    # USB
    "CVE-2023-1829": ["usb"],  # USB subsystem
    # NFC
    "CVE-2021-3587": ["nfc"],  # nfc use-after-free
    "CVE-2022-1974": ["nfc"],  # nfc use-after-free
    "CVE-2022-1975": ["nfc"],  # nfc sleep-in-atomic
    # CAN
    "CVE-2022-3545": ["can"],  # CAN BCM
    # InfiniBand
    "CVE-2021-3714": ["infiniband"],
}

# Subsystem tag → kconfig symbol mapping.
SUBSYSTEM_TO_SYMBOL: dict[str, str] = {
    "bluetooth": "BT",
    "wifi": "WLAN",
    "wireless": "WLAN",
    "802.11": "WLAN",
    "mac80211": "MAC80211",
    "cfg80211": "CFG80211",
    "usb": "USB",
    "spi": "SPI",
    "i2c": "I2C",
    "can": "CAN",
    "nfc": "NFC",
    "thunderbolt": "THUNDERBOLT",
    "infiniband": "INFINIBAND",
}

# DTB peripheral type → kconfig-like symbol for rule generation.
PERIPHERAL_TO_SYMBOL: dict[str, str] = {
    "spi": "SPI",
    "i2c": "I2C",
    "usb_host": "USB",
    "bluetooth": "BT",
    "wifi": "WLAN",
    "can": "CAN",
    "ethernet": "NET",
    "pcie": "PCI",
}

# Valid Sciath enum values.
VALID_TRUE_STATUS = {"affected", "not_affected", "fixed", "unknown"}
VALID_JUSTIFICATION = {
    "kconfig_disabled",
    "hw_not_present",
    "patched_backport",
    "version_not_affected",
    "component_not_present",
    "confirmed_affected",
    "insufficient_evidence",
}
VALID_CONFIDENCE = {"verified", "high", "medium"}
VALID_SOURCE = {"synthetic", "public", "customer", "adversarial"}


@dataclass
class CveMetadata:
    """Optional enriched CVE data from --cve-metadata file."""

    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cpe_list: list[str] = field(default_factory=list)
    subsystem_tags: list[str] = field(default_factory=list)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _get_subsystem_tags(
    cve_id: str, metadata: dict[str, CveMetadata] | None
) -> list[str]:
    """Get subsystem tags for a CVE from metadata or known mappings."""
    if metadata and cve_id in metadata:
        tags = metadata[cve_id].subsystem_tags
        if tags:
            return tags
    return KNOWN_CVE_SUBSYSTEMS.get(cve_id, [])


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
    """Classify a single CVE entry into a ground truth label."""
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
            evidence=[f"cve-check: status=Patched"],
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
                        f"cve-check: status=Unpatched",
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
                        f"cve-check: status=Unpatched",
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
            evidence=[f"cve-check: status=Unpatched"],
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
                    f"cve-check: status=Ignored",
                    f"detail: {entry.detail}",
                ],
                confidence="high",
                cvss_score=cvss,
            )
        # Ambiguous Ignored — skip.
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


def load_cve_metadata(path: Path) -> dict[str, CveMetadata]:
    """Load optional CVE metadata from a JSON file.

    Expected format: list of objects with cve_id, description,
    cvss_score, cpe_list, subsystem_tags.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"Expected JSON array in {path}")

    result: dict[str, CveMetadata] = {}
    for entry in raw:
        if not isinstance(entry, dict) or "cve_id" not in entry:
            continue
        result[entry["cve_id"]] = CveMetadata(
            cve_id=entry["cve_id"],
            description=entry.get("description", ""),
            cvss_score=entry.get("cvss_score", 0.0),
            cvss_vector=entry.get("cvss_vector", ""),
            cpe_list=entry.get("cpe_list", []),
            subsystem_tags=entry.get("subsystem_tags", []),
        )
    return result


def build_fixture(
    report: CveCheckReport,
    name: str,
    source: str,
    kconfig: dict[str, str] | None = None,
    dtb_nodes: list[DTBNode] | None = None,
    metadata: dict[str, CveMetadata] | None = None,
    exclude_native: bool = True,
    max_labels: int | None = None,
    min_cvss: float | None = None,
    notes: str = "",
    input_files: dict[str, Path] | None = None,
) -> dict:
    """Build a complete Sciath fixture JSON dict from parsed data."""
    if source not in VALID_SOURCE:
        raise ValueError(f"Invalid source '{source}', must be one of {VALID_SOURCE}")

    # Collect labels and SBOM components.
    labels: list[LabelCandidate] = []
    components: dict[str, dict] = {}  # keyed by (name, version)

    for pkg in report.packages:
        canonical = map_recipe(pkg.name)
        if canonical is None:
            if exclude_native:
                continue
            canonical = pkg.name

        comp_key = f"{canonical}:{pkg.version}"
        if comp_key not in components:
            comp_type = (
                "operating-system" if canonical == "linux-kernel" else "library"
            )
            components[comp_key] = {
                "name": canonical,
                "version": pkg.version,
                "purl": f"pkg:generic/{canonical}@{pkg.version}",
                "component_type": comp_type,
            }

        for cve_entry in pkg.cves:
            label = _classify_cve(
                cve_entry,
                canonical,
                pkg.version,
                kconfig,
                dtb_nodes,
                metadata,
            )
            if label:
                labels.append(label)

    # Deduplicate.
    labels = _dedup_labels(labels)

    # Apply filters.
    if min_cvss is not None:
        labels = apply_min_cvss(labels, min_cvss)
    if max_labels is not None:
        labels = apply_max_labels(labels, max_labels)

    # Build enriched_cves section.
    enriched_cves = []
    seen_cves: set[str] = set()
    for label in labels:
        if label.cve_id in seen_cves:
            continue
        seen_cves.add(label.cve_id)
        cve_data: dict = {
            "cve_id": label.cve_id,
            "description": "",
            "cvss_score": label.cvss_score or 7.5,
            "cvss_vector": "",
            "cpe_list": [],
            "affected_versions": [],
            "subsystem_tags": _get_subsystem_tags(label.cve_id, metadata),
            "sources": ["ground_truth"],
        }
        if metadata and label.cve_id in metadata:
            meta = metadata[label.cve_id]
            cve_data["description"] = meta.description
            cve_data["cvss_score"] = meta.cvss_score or 7.5
            cve_data["cvss_vector"] = meta.cvss_vector
            cve_data["cpe_list"] = meta.cpe_list
        enriched_cves.append(cve_data)

    # Build kconfig_rules section for kconfig-suppressed labels.
    kconfig_rules = []
    seen_rules: set[str] = set()
    for label in labels:
        if label.justification_category != "kconfig_disabled":
            continue
        tags = _get_subsystem_tags(label.cve_id, metadata)
        for tag in tags:
            symbol = SUBSYSTEM_TO_SYMBOL.get(tag)
            if not symbol:
                continue
            rule_key = f"{symbol}:{label.cve_id}"
            if rule_key in seen_rules:
                continue
            seen_rules.add(rule_key)
            subsystem_name = tag.capitalize()
            kconfig_rules.append({
                "symbol": symbol,
                "subsystem": subsystem_name,
                "cve_match_type": "exact",
                "cve_match_value": label.cve_id,
                "required_state": "enabled",
                "confidence": "high",
                "justification_template": (
                    f"Kernel {subsystem_name} subsystem disabled "
                    f"via CONFIG_{{{symbol}}}."
                ),
            })

    # Build dtb_rules section for DTB-suppressed labels.
    dtb_rules = []
    seen_dtb_rules: set[str] = set()
    for label in labels:
        if label.justification_category != "hw_not_present":
            continue
        tags = _get_subsystem_tags(label.cve_id, metadata)
        for tag in tags:
            symbol = SUBSYSTEM_TO_SYMBOL.get(tag)
            if not symbol:
                continue
            ptype = None
            for pt, sym in PERIPHERAL_TO_SYMBOL.items():
                if sym == symbol:
                    ptype = pt
                    break
            if not ptype:
                continue
            rule_key = f"{ptype}:{label.cve_id}"
            if rule_key in seen_dtb_rules:
                continue
            seen_dtb_rules.add(rule_key)
            dtb_rules.append({
                "peripheral_type": ptype,
                "cve_match_type": "exact",
                "cve_match_value": label.cve_id,
                "required_compatible": "",
                "confidence": "high",
                "justification_template": (
                    f"No enabled {ptype} peripheral in device tree."
                ),
            })

    # Build dtb_nodes section.
    dtb_nodes_out = []
    if dtb_nodes:
        for node in dtb_nodes:
            dtb_nodes_out.append({
                "path": node.path,
                "compatible": node.compatible,
                "status": node.status,
                "peripheral_type": node.peripheral_type,
            })

    # Assemble fixture.
    fixture: dict = {
        "name": name,
        "source": source,
        "notes": notes or f"Auto-generated from Yocto cve-check output.",
        "sbom": list(components.values()),
        "labels": [
            {
                "cve_id": l.cve_id,
                "component_name": l.component_name,
                "component_version": l.component_version,
                "true_status": l.true_status,
                "justification_category": l.justification_category,
                "justification_text": l.justification_text,
                "evidence": l.evidence,
                "confidence": l.confidence,
            }
            for l in labels
        ],
    }

    # Optional sections — only include if non-empty.
    if kconfig:
        fixture["kconfig"] = kconfig
    if enriched_cves:
        fixture["enriched_cves"] = enriched_cves
    if kconfig_rules:
        fixture["kconfig_rules"] = kconfig_rules
    if dtb_nodes_out:
        fixture["dtb_nodes"] = dtb_nodes_out
    if dtb_rules:
        fixture["dtb_rules"] = dtb_rules

    # Provenance metadata.
    if input_files:
        fixture["_provenance"] = {
            k: _sha256_file(v) for k, v in input_files.items()
        }

    return fixture


def validate_fixture(fixture: dict) -> list[str]:
    """Validate a fixture dict against Sciath's expected schema.

    Returns a list of error strings (empty = valid).
    """
    errors: list[str] = []

    if not isinstance(fixture, dict):
        return ["Root must be a JSON object"]

    for field_name in ("name", "source", "sbom", "labels"):
        if field_name not in fixture:
            errors.append(f"Missing required field: {field_name}")

    if fixture.get("source") not in VALID_SOURCE:
        errors.append(
            f"'source' must be one of {VALID_SOURCE}, got '{fixture.get('source')}'"
        )

    sbom = fixture.get("sbom")
    if sbom is not None and not isinstance(sbom, list):
        errors.append("'sbom' must be a list of components")

    for i, label in enumerate(fixture.get("labels", [])):
        if not isinstance(label, dict):
            errors.append(f"labels[{i}]: must be an object")
            continue
        for req in ("cve_id", "component_name", "true_status", "justification_category"):
            if req not in label:
                errors.append(f"labels[{i}]: missing {req}")
        if label.get("true_status") not in VALID_TRUE_STATUS:
            errors.append(
                f"labels[{i}]: true_status must be one of {VALID_TRUE_STATUS}"
            )
        if label.get("justification_category") not in VALID_JUSTIFICATION:
            errors.append(
                f"labels[{i}]: justification_category must be one of "
                f"{VALID_JUSTIFICATION}"
            )
        conf = label.get("confidence")
        if conf is not None and conf not in VALID_CONFIDENCE:
            errors.append(
                f"labels[{i}]: confidence must be one of {VALID_CONFIDENCE}"
            )

    return errors
