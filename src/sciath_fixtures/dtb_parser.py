"""Parse device tree source (.dts/.dtsi) files into node structures.

Extracts nodes with their compatible strings, status, and inferred
peripheral type. This is a best-effort parser for DTS text format —
it handles the common patterns but not the full DTS grammar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Peripheral type inference from compatible strings and node names.
_PERIPHERAL_PATTERNS: list[tuple[str, str]] = [
    ("spi", "spi"),
    ("i2c", "i2c"),
    ("uart", "uart"),
    ("serial", "uart"),
    ("usb", "usb_host"),
    ("ehci", "usb_host"),
    ("xhci", "usb_host"),
    ("ohci", "usb_host"),
    ("dwc3", "usb_host"),
    ("ethernet", "ethernet"),
    ("mdio", "ethernet"),
    ("fec", "ethernet"),
    ("gmac", "ethernet"),
    ("wifi", "wifi"),
    ("wlan", "wifi"),
    ("brcmf", "wifi"),
    ("bluetooth", "bluetooth"),
    ("bt", "bluetooth"),
    ("hci", "bluetooth"),
    ("can", "can"),
    ("mcan", "can"),
    ("flexcan", "can"),
    ("sdio", "sdio"),
    ("mmc", "sdio"),
    ("sdhci", "sdio"),
    ("pcie", "pcie"),
    ("pci", "pcie"),
    ("gpu", "gpu"),
    ("dsi", "dsi"),
    ("csi", "csi"),
    ("audio", "audio"),
    ("i2s", "audio"),
    ("sai", "audio"),
    ("crypto", "crypto"),
    ("caam", "crypto"),
    ("watchdog", "watchdog"),
    ("wdt", "watchdog"),
    ("gpio", "gpio"),
    ("pwm", "pwm"),
    ("adc", "adc"),
    ("dma", "dma"),
]


@dataclass
class DTBNode:
    path: str
    compatible: list[str] = field(default_factory=list)
    status: str = "okay"  # "okay", "disabled", "reserved", "fail"
    peripheral_type: str = "other"

    @property
    def is_enabled(self) -> bool:
        return self.status != "disabled"


def _infer_peripheral_type(path: str, compatible: list[str]) -> str:
    """Infer peripheral type from node path and compatible strings."""
    search_text = path.lower() + " " + " ".join(c.lower() for c in compatible)
    for keyword, ptype in _PERIPHERAL_PATTERNS:
        if keyword in search_text:
            return ptype
    return "other"


def parse_dtb(path: Path) -> list[DTBNode]:
    """Parse a DTS file and extract nodes with status and compatible info.

    This is a simplified parser that extracts top-level and second-level
    nodes with their compatible and status properties.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    nodes: list[DTBNode] = []

    # Track brace depth and current node path.
    current_path_parts: list[str] = []
    brace_depth = 0
    current_compatible: list[str] = []
    current_status = "okay"
    node_start_depth = -1

    for line in text.splitlines():
        stripped = line.strip()

        # Skip preprocessor and comments.
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue

        # Node opening: "name@addr {" or "name {"
        node_match = re.match(r"^([a-zA-Z_][\w@,.-]*)\s*\{", stripped)
        if node_match and brace_depth >= 0:
            node_name = node_match.group(1)
            current_path_parts.append(node_name)
            brace_depth += 1
            if brace_depth <= 3:  # Track up to 3 levels deep
                node_start_depth = brace_depth
                current_compatible = []
                current_status = "okay"
            continue

        # Bare opening brace (continuation of a node def on previous line).
        if stripped == "{":
            brace_depth += 1
            continue

        # Compatible property.
        compat_match = re.match(r'compatible\s*=\s*"([^"]*)"', stripped)
        if compat_match and brace_depth == node_start_depth:
            # Handle multiple compatible strings.
            all_compat = re.findall(r'"([^"]*)"', stripped)
            current_compatible = all_compat

        # Status property.
        status_match = re.match(r'status\s*=\s*"([^"]*)"', stripped)
        if status_match and brace_depth == node_start_depth:
            current_status = status_match.group(1)

        # Closing brace.
        if "}" in stripped:
            close_count = stripped.count("}")
            for _ in range(close_count):
                if brace_depth == node_start_depth and current_path_parts:
                    node_path = "/" + "/".join(current_path_parts)
                    if current_compatible:
                        ptype = _infer_peripheral_type(node_path, current_compatible)
                        nodes.append(DTBNode(
                            path=node_path,
                            compatible=current_compatible,
                            status=current_status,
                            peripheral_type=ptype,
                        ))
                    current_compatible = []
                    current_status = "okay"
                    node_start_depth = brace_depth - 1

                brace_depth -= 1
                if current_path_parts:
                    current_path_parts.pop()

    return nodes
