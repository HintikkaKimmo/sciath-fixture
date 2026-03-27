"""Tests for the CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sciath_fixtures.cli import app

runner = CliRunner()


def test_generate_basic(tmp_cve_check: Path, tmp_path: Path):
    out_dir = tmp_path / "out"
    result = runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_cve_check),
        "--name", "test_basic",
        "--source", "public",
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0, result.output
    out_file = out_dir / "test_basic.json"
    assert out_file.exists()

    data = json.loads(out_file.read_text())
    assert data["name"] == "test_basic"
    assert data["source"] == "public"
    assert len(data["labels"]) > 0


def test_generate_with_kconfig(
    tmp_cve_check: Path, tmp_kconfig: Path, tmp_path: Path
):
    out_dir = tmp_path / "out"
    result = runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_cve_check),
        "--kconfig", str(tmp_kconfig),
        "--name", "test_kconfig",
        "--source", "public",
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0, result.output
    out_file = out_dir / "test_kconfig.json"
    data = json.loads(out_file.read_text())

    # Should have kconfig data and at least one kconfig_disabled label.
    assert "kconfig" in data
    kconfig_labels = [
        l for l in data["labels"]
        if l["justification_category"] == "kconfig_disabled"
    ]
    assert len(kconfig_labels) >= 1


def test_generate_with_dtb(
    tmp_cve_check: Path, tmp_dtb: Path, tmp_path: Path
):
    out_dir = tmp_path / "out"
    result = runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_cve_check),
        "--dtb", str(tmp_dtb),
        "--name", "test_dtb",
        "--source", "public",
        "--output", str(out_dir),
    ])
    assert result.exit_code == 0, result.output
    out_file = out_dir / "test_dtb.json"
    data = json.loads(out_file.read_text())
    assert "dtb_nodes" in data


def test_generate_missing_input(tmp_path: Path):
    result = runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_path / "nonexistent.json"),
        "--name", "test",
        "--output", str(tmp_path),
    ])
    assert result.exit_code != 0


def test_validate_valid(tmp_cve_check: Path, tmp_path: Path):
    # First generate a fixture.
    out_dir = tmp_path / "out"
    runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_cve_check),
        "--name", "valid_test",
        "--source", "public",
        "--output", str(out_dir),
    ])

    # Then validate it.
    result = runner.invoke(app, [
        "validate", str(out_dir / "valid_test.json"),
    ])
    assert result.exit_code == 0


def test_validate_invalid(tmp_path: Path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps({"no_name": True}))
    result = runner.invoke(app, ["validate", str(bad_file)])
    assert result.exit_code != 0


def test_stats(tmp_cve_check: Path, tmp_path: Path):
    out_dir = tmp_path / "out"
    runner.invoke(app, [
        "generate",
        "--cve-check", str(tmp_cve_check),
        "--name", "stats_test",
        "--source", "public",
        "--output", str(out_dir),
    ])

    result = runner.invoke(app, [
        "stats", str(out_dir / "stats_test.json"),
    ])
    assert result.exit_code == 0
