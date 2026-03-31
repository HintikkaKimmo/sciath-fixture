"""Golden file snapshot test for build_fixture() output stability."""

from __future__ import annotations

import json
from pathlib import Path

from sciath_fixtures.cve_check_parser import parse_cve_check
from sciath_fixtures.fixture_builder import build_fixture

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
REFERENCE_FILE = SNAPSHOT_DIR / "reference_fixture.json"

# The same input data used to generate the reference snapshot.
# Matches conftest.py's tmp_cve_check fixture exactly.
_CVE_CHECK_DATA = {
    "package": [
        {
            "name": "openssl",
            "version": "3.0.19",
            "layer": "openembedded-core",
            "issue": [
                {
                    "id": "CVE-2022-1292",
                    "status": "Patched",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-1292",
                },
                {
                    "id": "CVE-2024-9143",
                    "status": "Unpatched",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-9143",
                },
            ],
        },
        {
            "name": "linux-yocto",
            "version": "5.15.150",
            "layer": "openembedded-core",
            "issue": [
                {
                    "id": "CVE-2020-12351",
                    "status": "Unpatched",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-12351",
                },
                {
                    "id": "CVE-2023-1234",
                    "status": "Patched",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                },
            ],
        },
        {
            "name": "openssl-native",
            "version": "3.0.19",
            "layer": "openembedded-core",
            "issue": [
                {
                    "id": "CVE-2022-1292",
                    "status": "Patched",
                },
            ],
        },
        {
            "name": "curl",
            "version": "8.5.0",
            "layer": "openembedded-core",
            "issue": [
                {
                    "id": "CVE-2023-9999",
                    "status": "Ignored",
                    "detail": "not-applicable-config: version not in range",
                },
                {
                    "id": "CVE-2023-8888",
                    "status": "Ignored",
                    "detail": "upstream-wontfix",
                },
            ],
        },
    ],
}


def test_fixture_output_matches_snapshot(tmp_path: Path):
    """Build a fixture and verify it matches the reference golden file."""
    # Write input to temp file and parse.
    input_path = tmp_path / "cve-check-report.json"
    input_path.write_text(json.dumps(_CVE_CHECK_DATA))
    report = parse_cve_check(input_path)

    # Build fixture with same parameters used to generate the reference.
    fixture = build_fixture(report, name="snapshot-test", source="synthetic")

    # Normalize both to sorted-key JSON for stable comparison.
    actual = json.loads(json.dumps(fixture, sort_keys=True))
    expected = json.loads(REFERENCE_FILE.read_text(encoding="utf-8"))

    assert actual == expected, (
        "Fixture output has diverged from the reference snapshot.\n"
        "If the change is intentional, regenerate the snapshot:\n"
        "  cd tests && python -c \"\n"
        "    import json; from pathlib import Path\n"
        "    # ... regenerate reference_fixture.json\n"
        "  \"\n"
        f"Diff (actual keys): {set(actual.keys()) ^ set(expected.keys())}"
    )
