"""Tests for cve_check_parser module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sciath_fixtures.cve_check_parser import parse_cve_check


def test_parse_valid(tmp_cve_check: Path):
    report = parse_cve_check(tmp_cve_check)
    assert report.total_packages == 4
    assert report.total_cves == 7


def test_parse_patched_status(tmp_cve_check: Path):
    report = parse_cve_check(tmp_cve_check)
    openssl = next(p for p in report.packages if p.name == "openssl")
    patched = next(c for c in openssl.cves if c.cve_id == "CVE-2022-1292")
    assert patched.status == "Patched"


def test_parse_unpatched_status(tmp_cve_check: Path):
    report = parse_cve_check(tmp_cve_check)
    openssl = next(p for p in report.packages if p.name == "openssl")
    unpatched = next(c for c in openssl.cves if c.cve_id == "CVE-2024-9143")
    assert unpatched.status == "Unpatched"


def test_parse_ignored_with_detail(tmp_cve_check: Path):
    report = parse_cve_check(tmp_cve_check)
    curl = next(p for p in report.packages if p.name == "curl")
    ignored = next(c for c in curl.cves if c.cve_id == "CVE-2023-9999")
    assert ignored.status == "Ignored"
    assert "not-applicable" in ignored.detail


def test_parse_empty_packages(tmp_path: Path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"package": []}))
    report = parse_cve_check(path)
    assert report.total_packages == 0
    assert report.total_cves == 0


def test_parse_malformed_json(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("not json at all")
    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_cve_check(path)


def test_parse_wrong_type(tmp_path: Path):
    path = tmp_path / "array.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="Expected JSON object"):
        parse_cve_check(path)


def test_parse_missing_issue_field(tmp_path: Path):
    """Packages without 'issue' field should parse with empty CVEs."""
    data = {"package": [{"name": "busybox", "version": "1.36.1"}]}
    path = tmp_path / "no-issues.json"
    path.write_text(json.dumps(data))
    report = parse_cve_check(path)
    assert report.total_packages == 1
    assert report.total_cves == 0
