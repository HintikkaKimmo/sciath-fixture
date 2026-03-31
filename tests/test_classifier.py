"""Unit tests for _classify_cve() function in isolation."""

from __future__ import annotations

from sciath_fixtures.cve_check_parser import CveEntry
from sciath_fixtures.dtb_parser import DTBNode
from sciath_fixtures.fixture_builder import CveMetadata, _classify_cve


def test_unpatched_with_kconfig_suppression():
    """Unpatched bluetooth CVE + CONFIG_BT=n -> not_affected / kconfig_disabled."""
    entry = CveEntry(cve_id="CVE-2020-12351", status="Unpatched")
    kconfig = {"BT": "n", "NET": "y"}

    result = _classify_cve(
        entry,
        component_name="linux-kernel",
        component_version="5.15.0",
        kconfig=kconfig,
        dtb_nodes=None,
        metadata=None,
    )

    assert result is not None
    assert result.true_status == "not_affected"
    assert result.justification_category == "kconfig_disabled"
    assert "CONFIG_BT=n" in result.justification_text


def test_unpatched_with_dtb_suppression():
    """Unpatched bluetooth CVE + BT peripheral disabled in DTB -> hw_not_present."""
    entry = CveEntry(cve_id="CVE-2020-12351", status="Unpatched")
    dtb_nodes = [
        DTBNode(
            path="/soc/bluetooth@12340000",
            compatible=["ti,bt-hci"],
            status="disabled",
            peripheral_type="bluetooth",
        ),
    ]

    result = _classify_cve(
        entry,
        component_name="linux-kernel",
        component_version="5.15.0",
        kconfig=None,
        dtb_nodes=dtb_nodes,
        metadata=None,
    )

    assert result is not None
    assert result.true_status == "not_affected"
    assert result.justification_category == "hw_not_present"
    assert "bluetooth" in result.justification_text


def test_kconfig_takes_precedence_over_dtb():
    """When both kconfig and DTB would suppress, kconfig wins (checked first)."""
    entry = CveEntry(cve_id="CVE-2020-12351", status="Unpatched")
    kconfig = {"BT": "n"}
    dtb_nodes = [
        DTBNode(
            path="/soc/bluetooth@12340000",
            compatible=["ti,bt-hci"],
            status="disabled",
            peripheral_type="bluetooth",
        ),
    ]

    result = _classify_cve(
        entry,
        component_name="linux-kernel",
        component_version="5.15.0",
        kconfig=kconfig,
        dtb_nodes=dtb_nodes,
        metadata=None,
    )

    assert result is not None
    assert result.true_status == "not_affected"
    assert result.justification_category == "kconfig_disabled"


def test_unpatched_no_suppression_is_affected():
    """Unpatched CVE with no kconfig/DTB suppression -> affected."""
    entry = CveEntry(cve_id="CVE-2024-9143", status="Unpatched")

    result = _classify_cve(
        entry,
        component_name="openssl",
        component_version="3.0.19",
        kconfig=None,
        dtb_nodes=None,
        metadata=None,
    )

    assert result is not None
    assert result.true_status == "affected"
    assert result.justification_category == "confirmed_affected"


def test_metadata_subsystem_tags_used():
    """Subsystem tags from metadata dict are used for kconfig suppression."""
    # CVE-9999-0001 is NOT in KNOWN_CVE_SUBSYSTEMS, so tags must come from metadata.
    entry = CveEntry(cve_id="CVE-9999-0001", status="Unpatched")
    kconfig = {"WLAN": "n"}
    metadata = {
        "CVE-9999-0001": CveMetadata(
            cve_id="CVE-9999-0001",
            subsystem_tags=["wifi"],
        ),
    }

    result = _classify_cve(
        entry,
        component_name="linux-kernel",
        component_version="5.15.0",
        kconfig=kconfig,
        dtb_nodes=None,
        metadata=metadata,
    )

    assert result is not None
    assert result.true_status == "not_affected"
    assert result.justification_category == "kconfig_disabled"
    assert "CONFIG_WLAN=n" in result.justification_text
