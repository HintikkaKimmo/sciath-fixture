"""Tests for dtb_parser module."""

from pathlib import Path

from sciath_fixtures.dtb_parser import parse_dtb


def test_parse_finds_nodes(tmp_dtb: Path):
    nodes = parse_dtb(tmp_dtb)
    assert len(nodes) >= 2  # spi and i2c at minimum


def test_parse_spi_disabled(tmp_dtb: Path):
    nodes = parse_dtb(tmp_dtb)
    spi_nodes = [n for n in nodes if n.peripheral_type == "spi"]
    assert len(spi_nodes) >= 1
    assert spi_nodes[0].status == "disabled"
    assert not spi_nodes[0].is_enabled


def test_parse_i2c_okay(tmp_dtb: Path):
    nodes = parse_dtb(tmp_dtb)
    i2c_nodes = [n for n in nodes if n.peripheral_type == "i2c"]
    assert len(i2c_nodes) >= 1
    assert i2c_nodes[0].status == "okay"
    assert i2c_nodes[0].is_enabled


def test_parse_peripheral_type_inference(tmp_dtb: Path):
    nodes = parse_dtb(tmp_dtb)
    types = {n.peripheral_type for n in nodes}
    assert "spi" in types
    assert "i2c" in types


def test_parse_empty_file(tmp_path: Path):
    path = tmp_path / "empty.dts"
    path.write_text("")
    nodes = parse_dtb(path)
    assert nodes == []
