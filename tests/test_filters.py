"""Tests for filters module."""

from sciath_fixtures.filters import apply_max_labels, apply_min_cvss
from tests.conftest import _make_label


def test_max_labels_caps():
    labels = [_make_label(f"CVE-{i:04d}", "affected") for i in range(10)]
    result = apply_max_labels(labels, 5)
    assert len(result) == 5


def test_max_labels_no_cap_needed():
    labels = [_make_label(f"CVE-{i:04d}", "affected") for i in range(3)]
    result = apply_max_labels(labels, 10)
    assert len(result) == 3


def test_max_labels_deterministic_order():
    labels = [
        _make_label("CVE-0003", "fixed"),
        _make_label("CVE-0001", "affected"),
        _make_label("CVE-0002", "not_affected"),
    ]
    result = apply_max_labels(labels, 2)
    # affected (priority 0) first, then not_affected (priority 1)
    assert result[0].cve_id == "CVE-0001"
    assert result[1].cve_id == "CVE-0002"


def test_max_labels_same_status_sorted_by_cve_id():
    labels = [
        _make_label("CVE-0003", "affected"),
        _make_label("CVE-0001", "affected"),
        _make_label("CVE-0002", "affected"),
    ]
    result = apply_max_labels(labels, 2)
    assert result[0].cve_id == "CVE-0001"
    assert result[1].cve_id == "CVE-0002"


def test_min_cvss_filters():
    labels = [
        _make_label("CVE-0001", "affected", cvss_score=9.8),
        _make_label("CVE-0002", "affected", cvss_score=3.1),
        _make_label("CVE-0003", "affected", cvss_score=7.5),
    ]
    result = apply_min_cvss(labels, 4.0)
    assert len(result) == 2
    assert all(lbl.cvss_score >= 4.0 for lbl in result)


def test_min_cvss_keeps_no_score():
    """Labels without CVSS scores should be kept (conservative)."""
    labels = [
        _make_label("CVE-0001", "affected", cvss_score=9.8),
        _make_label("CVE-0002", "affected", cvss_score=None),
        _make_label("CVE-0003", "affected", cvss_score=2.0),
    ]
    result = apply_min_cvss(labels, 4.0)
    assert len(result) == 2
    cve_ids = {lbl.cve_id for lbl in result}
    assert "CVE-0001" in cve_ids
    assert "CVE-0002" in cve_ids  # None score → kept


def test_min_cvss_no_scores_noop():
    """When no labels have CVSS scores, filter is a no-op."""
    labels = [
        _make_label("CVE-0001", "affected"),
        _make_label("CVE-0002", "affected"),
    ]
    result = apply_min_cvss(labels, 4.0)
    assert len(result) == 2
