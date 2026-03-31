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
from typing import Any

from sciath_fixtures.classifier import _classify_cve, _dedup_labels
from sciath_fixtures.cve_check_parser import CveCheckReport
from sciath_fixtures.dtb_parser import DTBNode
from sciath_fixtures.filters import LabelCandidate, apply_max_labels, apply_min_cvss
from sciath_fixtures.mappings import (
    PERIPHERAL_TO_SYMBOL,
    SUBSYSTEM_TO_SYMBOL,
    _get_subsystem_tags,
)
from sciath_fixtures.name_mapper import map_recipe

logger = logging.getLogger(__name__)

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
) -> dict[str, Any]:
    """Build a complete Sciath fixture JSON dict from parsed data."""
    if source not in VALID_SOURCE:
        raise ValueError(f"Invalid source '{source}', must be one of {VALID_SOURCE}")

    # Collect labels and SBOM components.
    labels: list[LabelCandidate] = []
    components: dict[str, dict[str, Any]] = {}  # keyed by (name, version)

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
        cve_data: dict[str, Any] = {
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
    fixture: dict[str, Any] = {
        "name": name,
        "schema_version": "1.0",
        "source": source,
        "notes": notes or "Auto-generated from Yocto cve-check output.",
        "sbom": list(components.values()),
        "labels": [
            {
                "cve_id": lbl.cve_id,
                "component_name": lbl.component_name,
                "component_version": lbl.component_version,
                "true_status": lbl.true_status,
                "justification_category": lbl.justification_category,
                "justification_text": lbl.justification_text,
                "evidence": lbl.evidence,
                "confidence": lbl.confidence,
            }
            for lbl in labels
        ],
    }

    # Optional sections -- only include if non-empty.
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


def validate_fixture(fixture: dict[str, Any]) -> list[str]:
    """Validate a fixture dict against Sciath's expected schema.

    Returns a list of error strings (empty = valid).
    """
    errors: list[str] = []

    if not isinstance(fixture, dict):
        return ["Root must be a JSON object"]

    for field_name in ("name", "source", "sbom", "labels"):
        if field_name not in fixture:
            errors.append(f"Missing required field: {field_name}")

    # schema_version is optional (old fixtures may not have it).
    sv = fixture.get("schema_version")
    if sv is not None and sv != "1.0":
        errors.append(f"Unsupported schema_version: {sv}")

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


# Backward-compatible re-exports (moved to separate modules)
from sciath_fixtures.classifier import _check_dtb_suppression as _check_dtb_suppression  # noqa: E402
from sciath_fixtures.classifier import _check_kconfig_suppression as _check_kconfig_suppression  # noqa: E402
from sciath_fixtures.mappings import KNOWN_CVE_SUBSYSTEMS as KNOWN_CVE_SUBSYSTEMS  # noqa: E402
