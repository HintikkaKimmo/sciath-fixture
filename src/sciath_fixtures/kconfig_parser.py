"""Parse Linux kernel .config files into a symbol → value dict.

Supports both full and trimmed .config formats:
  CONFIG_BT=y          → {"BT": "y"}
  CONFIG_BT=m          → {"BT": "m"}
  CONFIG_BT=0x1000     → {"BT": "0x1000"}
  CONFIG_DEFAULT="foo" → {"DEFAULT": "foo"}
  # CONFIG_BT is not set → {"BT": "n"}
"""

from __future__ import annotations

import re
from pathlib import Path

# CONFIG_SYMBOL=value
_SET_RE = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.+)$")

# # CONFIG_SYMBOL is not set
_NOT_SET_RE = re.compile(r"^#\s*CONFIG_([A-Za-z0-9_]+)\s+is not set")


def parse_kconfig(path: Path) -> dict[str, str]:
    """Parse a kernel .config file into a {symbol: value} dict.

    Strips CONFIG_ prefix. Unquotes string values.
    """
    result: dict[str, str] = {}

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()

        # CONFIG_X=value
        m = _SET_RE.match(line)
        if m:
            symbol, value = m.group(1), m.group(2)
            # Strip surrounding quotes from string values.
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            result[symbol] = value
            continue

        # # CONFIG_X is not set
        m = _NOT_SET_RE.match(line)
        if m:
            result[m.group(1)] = "n"

    return result
