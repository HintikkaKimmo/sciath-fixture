# Changelog

All notable changes to sciath-fixture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Split fixture_builder.py** — extracted `mappings.py` (subsystem constants) and `classifier.py` (CVE classification logic) for better maintainability
- **Data-driven subsystem mappings** — `KNOWN_CVE_SUBSYSTEMS` moved to `data/known_cve_subsystems.json`
- **Schema versioning** — fixture output now includes `schema_version: "1.0"`
- **Documented suppression precedence** — kconfig > DTB > default (affected), with rationale
- **Expanded test coverage** — added `test_classifier.py` (kconfig/DTB suppression, precedence), `test_dedup_comprehensive.py` (full priority matrix), `test_fixture_output_snapshot.py` (golden file regression test)
- **Updated CLAUDE.md** — new module responsibilities table, suppression precedence docs, schema versioning section, updated project structure
- **Updated README.md** — updated example paths (removed references to deleted `sources/kirkstone-rpi4/`)
- **Removed empty `sources/kirkstone-rpi4/`** — tests use `tmp_path` fixtures, no static test data needed

### Added

- **Initial fixtures CLI.** Ground truth fixture generation tooling for Sciath's
  zero-false-negatives validation engine. Generates labeled synthetic SBOMs with
  known CVE outcomes.
- **CI workflow.** GitHub Actions for linting (ruff), type checking (mypy), and tests.
  Pre-commit hooks configured.
- **SECURITY.md, CODEOWNERS.** Semgrep scanning, SHA-pinned GitHub Actions.
- **Conventional commit enforcement** via pre-commit hook and CI.

[Unreleased]: https://github.com/HintikkaKimmo/sciath-fixture/commits/main
