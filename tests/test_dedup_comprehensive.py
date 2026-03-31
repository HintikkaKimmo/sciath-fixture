"""Comprehensive tests for _dedup_labels() function."""

from __future__ import annotations

from sciath_fixtures.filters import LabelCandidate
from sciath_fixtures.fixture_builder import _dedup_labels


def _make_label(
    cve_id: str = "CVE-2023-0001",
    component: str = "linux-kernel",
    status: str = "affected",
    justification: str = "confirmed_affected",
) -> LabelCandidate:
    return LabelCandidate(
        cve_id=cve_id,
        component_name=component,
        component_version="5.15.0",
        true_status=status,
        justification_category=justification,
        justification_text="test",
        evidence=["test"],
        confidence="high",
    )


def test_fixed_beats_not_affected():
    """fixed > not_affected for same (cve_id, component)."""
    labels = [
        _make_label(status="not_affected", justification="kconfig_disabled"),
        _make_label(status="fixed", justification="patched_backport"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_fixed_beats_affected():
    """fixed > affected for same (cve_id, component)."""
    labels = [
        _make_label(status="affected", justification="confirmed_affected"),
        _make_label(status="fixed", justification="patched_backport"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_not_affected_beats_affected():
    """not_affected > affected for same (cve_id, component)."""
    labels = [
        _make_label(status="affected", justification="confirmed_affected"),
        _make_label(status="not_affected", justification="kconfig_disabled"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "not_affected"


def test_not_affected_beats_unknown():
    """not_affected > unknown for same (cve_id, component)."""
    labels = [
        _make_label(status="unknown", justification="insufficient_evidence"),
        _make_label(status="not_affected", justification="kconfig_disabled"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "not_affected"


def test_affected_beats_unknown():
    """affected > unknown for same (cve_id, component)."""
    labels = [
        _make_label(status="unknown", justification="insufficient_evidence"),
        _make_label(status="affected", justification="confirmed_affected"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "affected"


def test_triple_duplicate():
    """Three entries for same pair -> highest priority wins."""
    labels = [
        _make_label(status="unknown", justification="insufficient_evidence"),
        _make_label(status="affected", justification="confirmed_affected"),
        _make_label(status="fixed", justification="patched_backport"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_no_duplicates_preserved():
    """Different (cve_id, component) pairs are all preserved."""
    labels = [
        _make_label(cve_id="CVE-2023-0001", component="openssl", status="affected"),
        _make_label(cve_id="CVE-2023-0002", component="openssl", status="fixed"),
        _make_label(cve_id="CVE-2023-0001", component="curl", status="not_affected",
                    justification="kconfig_disabled"),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 3
    result_keys = {(r.cve_id, r.component_name) for r in result}
    assert result_keys == {
        ("CVE-2023-0001", "openssl"),
        ("CVE-2023-0002", "openssl"),
        ("CVE-2023-0001", "curl"),
    }
