"""Comprehensive tests for _dedup_labels() function."""

from __future__ import annotations

from sciath_fixtures.fixture_builder import _dedup_labels
from tests.conftest import _make_label

# Shared overrides so dedup tests use a consistent (cve_id, component_name) pair.
_KW = dict(component_name="linux-kernel", component_version="5.15.0",
           evidence=["test"])


def test_fixed_beats_not_affected():
    """fixed > not_affected for same (cve_id, component)."""
    labels = [
        _make_label("CVE-2023-0001", "not_affected",
                    justification_category="kconfig_disabled", **_KW),
        _make_label("CVE-2023-0001", "fixed",
                    justification_category="patched_backport", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_fixed_beats_affected():
    """fixed > affected for same (cve_id, component)."""
    labels = [
        _make_label("CVE-2023-0001", "affected", **_KW),
        _make_label("CVE-2023-0001", "fixed",
                    justification_category="patched_backport", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_not_affected_beats_affected():
    """not_affected > affected for same (cve_id, component)."""
    labels = [
        _make_label("CVE-2023-0001", "affected", **_KW),
        _make_label("CVE-2023-0001", "not_affected",
                    justification_category="kconfig_disabled", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "not_affected"


def test_not_affected_beats_unknown():
    """not_affected > unknown for same (cve_id, component)."""
    labels = [
        _make_label("CVE-2023-0001", "unknown",
                    justification_category="insufficient_evidence", **_KW),
        _make_label("CVE-2023-0001", "not_affected",
                    justification_category="kconfig_disabled", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "not_affected"


def test_affected_beats_unknown():
    """affected > unknown for same (cve_id, component)."""
    labels = [
        _make_label("CVE-2023-0001", "unknown",
                    justification_category="insufficient_evidence", **_KW),
        _make_label("CVE-2023-0001", "affected", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "affected"


def test_triple_duplicate():
    """Three entries for same pair -> highest priority wins."""
    labels = [
        _make_label("CVE-2023-0001", "unknown",
                    justification_category="insufficient_evidence", **_KW),
        _make_label("CVE-2023-0001", "affected", **_KW),
        _make_label("CVE-2023-0001", "fixed",
                    justification_category="patched_backport", **_KW),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 1
    assert result[0].true_status == "fixed"


def test_no_duplicates_preserved():
    """Different (cve_id, component) pairs are all preserved."""
    labels = [
        _make_label("CVE-2023-0001", "affected",
                    component_name="openssl", component_version="5.15.0",
                    evidence=["test"]),
        _make_label("CVE-2023-0002", "fixed",
                    component_name="openssl", component_version="5.15.0",
                    justification_category="patched_backport", evidence=["test"]),
        _make_label("CVE-2023-0001", "not_affected",
                    component_name="curl", component_version="5.15.0",
                    justification_category="kconfig_disabled", evidence=["test"]),
    ]
    result = _dedup_labels(labels)
    assert len(result) == 3
    result_keys = {(r.cve_id, r.component_name) for r in result}
    assert result_keys == {
        ("CVE-2023-0001", "openssl"),
        ("CVE-2023-0002", "openssl"),
        ("CVE-2023-0001", "curl"),
    }
