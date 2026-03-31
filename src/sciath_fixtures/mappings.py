"""Subsystem-to-kconfig/DTB mappings for CVE classification.

Constants and lookup functions that map CVE subsystem tags to kernel
config symbols and DTB peripheral types.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sciath_fixtures.fixture_builder import CveMetadata

_DATA_DIR = Path(__file__).parent / "data"


def _load_known_cve_subsystems() -> dict[str, list[str]]:
    path = _DATA_DIR / "known_cve_subsystems.json"
    with open(path) as f:
        return json.load(f)  # type: ignore[no-any-return]


KNOWN_CVE_SUBSYSTEMS: dict[str, list[str]] = _load_known_cve_subsystems()

# Subsystem tag -> kconfig symbol mapping.
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

# DTB peripheral type -> kconfig-like symbol for rule generation.
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


def _get_subsystem_tags(
    cve_id: str, metadata: dict[str, CveMetadata] | None
) -> list[str]:
    """Get subsystem tags for a CVE from metadata or known mappings."""
    if metadata and cve_id in metadata:
        tags = metadata[cve_id].subsystem_tags
        if tags:
            return tags
    return KNOWN_CVE_SUBSYSTEMS.get(cve_id, [])
