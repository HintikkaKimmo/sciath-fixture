"""Shared test fixtures for sciath-fixtures tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def tmp_cve_check(tmp_path: Path) -> Path:
    """A minimal valid cve-check JSON file."""
    data = {
        "package": [
            {
                "name": "openssl",
                "version": "3.0.19",
                "layer": "openembedded-core",
                "issue": [
                    {
                        "id": "CVE-2022-1292",
                        "status": "Patched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-1292",
                    },
                    {
                        "id": "CVE-2024-9143",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-9143",
                    },
                ],
            },
            {
                "name": "linux-yocto",
                "version": "5.15.150",
                "layer": "openembedded-core",
                "issue": [
                    {
                        "id": "CVE-2020-12351",
                        "status": "Unpatched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-12351",
                    },
                    {
                        "id": "CVE-2023-1234",
                        "status": "Patched",
                        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                    },
                ],
            },
            {
                "name": "openssl-native",
                "version": "3.0.19",
                "layer": "openembedded-core",
                "issue": [
                    {
                        "id": "CVE-2022-1292",
                        "status": "Patched",
                    },
                ],
            },
            {
                "name": "curl",
                "version": "8.5.0",
                "layer": "openembedded-core",
                "issue": [
                    {
                        "id": "CVE-2023-9999",
                        "status": "Ignored",
                        "detail": "not-applicable-config: version not in range",
                    },
                    {
                        "id": "CVE-2023-8888",
                        "status": "Ignored",
                        "detail": "upstream-wontfix",
                    },
                ],
            },
        ],
    }
    path = tmp_path / "cve-check-report.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def tmp_kconfig(tmp_path: Path) -> Path:
    """A minimal .config file with BT disabled."""
    content = """\
#
# Automatically generated file; DO NOT EDIT.
# Linux/arm64 5.15.150 Kernel Configuration
#
CONFIG_NET=y
CONFIG_INET=y
# CONFIG_BT is not set
CONFIG_USB=y
CONFIG_SPI=y
# CONFIG_I2C is not set
CONFIG_DEFAULT_HOSTNAME="yocto"
"""
    path = tmp_path / "dot-config"
    path.write_text(content)
    return path


@pytest.fixture
def tmp_dtb(tmp_path: Path) -> Path:
    """A minimal DTS file with a disabled SPI controller."""
    content = """\
/dts-v1/;

/ {
    model = "Test Board";
    compatible = "test,board";

    soc {
        spi@48030000 {
            compatible = "ti,omap4-mcspi", "ti,omap3-mcspi";
            status = "disabled";
        };

        i2c@44e0b000 {
            compatible = "ti,omap4-i2c";
            status = "okay";
        };

        usb@47400000 {
            compatible = "ti,musb-am33xx";
            status = "okay";
        };
    };
};
"""
    path = tmp_path / "device-tree.dts"
    path.write_text(content)
    return path
