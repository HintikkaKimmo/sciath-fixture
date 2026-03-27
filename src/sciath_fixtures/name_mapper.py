"""Map Yocto recipe names to canonical component names.

Mirrors the logic in Sciath's engine/identity/resolver.py but as a
standalone dict + heuristic, no database required.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Explicit recipe → canonical name mappings.
# None means "skip this recipe" (build-only, not deployed).
RECIPE_TO_CANONICAL: dict[str, str | None] = {
    # Kernel variants → linux-kernel
    "linux-yocto": "linux-kernel",
    "linux-raspberrypi": "linux-kernel",
    "linux-imx": "linux-kernel",
    "linux-ti": "linux-kernel",
    "linux-stm32": "linux-kernel",
    # Common recipes
    "openssl": "openssl",
    "curl": "curl",
    "busybox": "busybox",
    "util-linux": "util-linux",
    "glib-2.0": "glib",
    "glibc": "glibc",
    "binutils": "binutils",
    "gcc": "gcc",
    "python3": "python",
    # Explicit skips (build-only)
    "openssl-native": None,
    "curl-native": None,
    "nativesdk-openssl": None,
}

# Patterns for recipes that should be skipped (build-time only, not deployed).
_SKIP_PATTERNS = [
    re.compile(r"-native$"),
    re.compile(r"^nativesdk-"),
    re.compile(r"-cross(-|$)"),
    re.compile(r"-crosssdk(-|$)"),
]

# BSP vendor suffixes to strip.
_BSP_SUFFIXES = ["-imx", "-ti", "-stm32", "-rpi", "-toradex", "-rockchip"]

# Package namespace prefixes to strip.
_NAMESPACE_PREFIXES = ["python3-", "python-", "perl-module-", "lib"]


def map_recipe(name: str) -> str | None:
    """Map a Yocto recipe name to a canonical component name.

    Returns:
        Canonical name string, or None if the recipe should be skipped.
    """
    # Check explicit mapping first.
    if name in RECIPE_TO_CANONICAL:
        return RECIPE_TO_CANONICAL[name]

    # Check skip patterns.
    for pattern in _SKIP_PATTERNS:
        if pattern.search(name):
            logger.debug("Skipping build-only recipe: %s", name)
            return None

    # Strip BSP vendor suffixes (e.g., u-boot-imx → u-boot).
    canonical = name
    for suffix in _BSP_SUFFIXES:
        if canonical.endswith(suffix):
            canonical = canonical[: -len(suffix)]
            break

    # Strip namespace prefixes (e.g., python3-cryptography → cryptography).
    for prefix in _NAMESPACE_PREFIXES:
        if canonical.startswith(prefix) and len(canonical) > len(prefix) + 2:
            canonical = canonical[len(prefix):]
            break

    return canonical


def should_skip_recipe(name: str) -> bool:
    """Check if a recipe should be skipped (native/cross/nativesdk)."""
    return map_recipe(name) is None
