"""Parse Yocto cve-check JSON output into structured data."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CveEntry:
    cve_id: str
    status: str  # "Patched", "Unpatched", "Ignored"
    link: str = ""
    detail: str = ""  # For Ignored, may contain reason like "not-applicable-config"


@dataclass
class PackageEntry:
    name: str
    version: str
    layer: str = ""
    cves: list[CveEntry] = field(default_factory=list)


@dataclass
class CveCheckReport:
    packages: list[PackageEntry] = field(default_factory=list)

    @property
    def total_cves(self) -> int:
        return sum(len(p.cves) for p in self.packages)

    @property
    def total_packages(self) -> int:
        return len(self.packages)


def parse_cve_check(path: Path) -> CveCheckReport:
    """Parse a Yocto cve-check JSON report file.

    Expected format:
    {
      "package": [
        {
          "name": "openssl",
          "version": "3.0.19",
          "layer": "openembedded-core",
          "issue": [
            {"id": "CVE-2022-1292", "status": "Patched", "link": "..."}
          ]
        }
      ]
    }
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(raw).__name__}")

    packages_raw = raw.get("package", [])
    if not isinstance(packages_raw, list):
        raise ValueError(f"Expected 'package' to be a list in {path}")

    packages: list[PackageEntry] = []
    for pkg_data in packages_raw:
        if not isinstance(pkg_data, dict):
            continue

        name = pkg_data.get("name", "")
        version = pkg_data.get("version", "")
        if not name:
            continue

        cves: list[CveEntry] = []
        for issue in pkg_data.get("issue", []):
            if not isinstance(issue, dict):
                continue
            cve_id = issue.get("id", "")
            if not cve_id:
                continue
            cves.append(CveEntry(
                cve_id=cve_id,
                status=issue.get("status", ""),
                link=issue.get("link", ""),
                detail=issue.get("detail", ""),
            ))

        packages.append(PackageEntry(
            name=name,
            version=version,
            layer=pkg_data.get("layer", ""),
            cves=cves,
        ))

    return CveCheckReport(packages=packages)
