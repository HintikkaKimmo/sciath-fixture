"""Tests for filters module."""

from sciath_fixtures.filters import LabelCandidate, apply_max_labels, apply_min_cvss


def _make_label(cve_id: str, status: str, cvss: float | None = None) -> LabelCandidate:
    return LabelCandidate(
        cve_id=cve_id,
        component_name="test",
        component_version="1.0",
        true_status=status,
        justification_category="confirmed_affected",
        justification_text="test",
        evidence=[],
        confidence="high",
        cvss_score=cvss,
    )


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
        _make_label("CVE-0001", "affected", cvss=9.8),
        _make_label("CVE-0002", "affected", cvss=3.1),
        _make_label("CVE-0003", "affected", cvss=7.5),
    ]
    result = apply_min_cvss(labels, 4.0)
    assert len(result) == 2
    assert all(l.cvss_score >= 4.0 for l in result)


def test_min_cvss_keeps_no_score():
    """Labels without CVSS scores should be kept (conservative)."""
    labels = [
        _make_label("CVE-0001", "affected", cvss=9.8),
        _make_label("CVE-0002", "affected", cvss=None),
        _make_label("CVE-0003", "affected", cvss=2.0),
    ]
    result = apply_min_cvss(labels, 4.0)
    assert len(result) == 2
    cve_ids = {l.cve_id for l in result}
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
