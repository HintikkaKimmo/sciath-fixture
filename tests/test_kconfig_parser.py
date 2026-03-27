"""Tests for kconfig_parser module."""

from pathlib import Path

from sciath_fixtures.kconfig_parser import parse_kconfig


def test_parse_standard_config(tmp_kconfig: Path):
    result = parse_kconfig(tmp_kconfig)
    assert result["NET"] == "y"
    assert result["INET"] == "y"
    assert result["USB"] == "y"
    assert result["SPI"] == "y"


def test_parse_not_set(tmp_kconfig: Path):
    result = parse_kconfig(tmp_kconfig)
    assert result["BT"] == "n"
    assert result["I2C"] == "n"


def test_parse_string_value(tmp_kconfig: Path):
    result = parse_kconfig(tmp_kconfig)
    assert result["DEFAULT_HOSTNAME"] == "yocto"


def test_parse_comments_ignored(tmp_kconfig: Path):
    result = parse_kconfig(tmp_kconfig)
    # Should not contain entries from pure comment lines.
    assert "Automatically" not in result


def test_parse_empty_file(tmp_path: Path):
    path = tmp_path / "empty.config"
    path.write_text("")
    result = parse_kconfig(path)
    assert result == {}


def test_parse_module_value(tmp_path: Path):
    path = tmp_path / "module.config"
    path.write_text("CONFIG_WLAN=m\nCONFIG_BT=m\n")
    result = parse_kconfig(path)
    assert result["WLAN"] == "m"
    assert result["BT"] == "m"


def test_parse_hex_value(tmp_path: Path):
    path = tmp_path / "hex.config"
    path.write_text("CONFIG_PAGE_OFFSET=0xC0000000\n")
    result = parse_kconfig(path)
    assert result["PAGE_OFFSET"] == "0xC0000000"
