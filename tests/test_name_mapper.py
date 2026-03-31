"""Tests for name_mapper module."""

import pytest

from sciath_fixtures.name_mapper import map_recipe, should_skip_recipe


@pytest.mark.parametrize("recipe,expected", [
    ("openssl", "openssl"),
    ("curl", "curl"),
    ("busybox", "busybox"),
])
def test_known_recipe(recipe: str, expected: str):
    assert map_recipe(recipe) == expected


@pytest.mark.parametrize("recipe", [
    "linux-yocto",
    "linux-raspberrypi",
    "linux-imx",
    "linux-ti",
])
def test_kernel_variants(recipe: str):
    assert map_recipe(recipe) == "linux-kernel"


def test_native_skip():
    assert map_recipe("openssl-native") is None
    assert map_recipe("curl-native") is None


def test_nativesdk_skip():
    assert map_recipe("nativesdk-openssl") is None


def test_cross_skip():
    assert map_recipe("gcc-cross-aarch64") is None
    assert map_recipe("binutils-cross-arm") is None


def test_unknown_recipe_passthrough():
    assert map_recipe("somepackage") == "somepackage"


def test_python3_prefix():
    assert map_recipe("python3-cryptography") == "cryptography"
    assert map_recipe("python3-requests") == "requests"


def test_bsp_suffix_strip():
    assert map_recipe("u-boot-imx") == "u-boot"
    assert map_recipe("u-boot-ti") == "u-boot"


def test_lib_prefix_strip():
    assert map_recipe("libxml2") == "xml2"


def test_should_skip_recipe():
    assert should_skip_recipe("openssl-native") is True
    assert should_skip_recipe("nativesdk-glib") is True
    assert should_skip_recipe("openssl") is False


def test_dynamic_native_pattern():
    """Any recipe ending in -native should be skipped, even if not in the dict."""
    assert map_recipe("zlib-native") is None
    assert map_recipe("glib-2.0-native") is None
