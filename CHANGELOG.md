# Changelog

All notable changes to sciath-fixture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Initial fixtures CLI.** Ground truth fixture generation tooling for Sciath's
  zero-false-negatives validation engine. Generates labeled synthetic SBOMs with
  known CVE outcomes.
- **CI workflow.** GitHub Actions for linting (ruff), type checking (mypy), and tests.
  Pre-commit hooks configured.
- **SECURITY.md, CODEOWNERS.** Semgrep scanning, SHA-pinned GitHub Actions.
- **Conventional commit enforcement** via pre-commit hook and CI.

[Unreleased]: https://github.com/HintikkaKimmo/sciath-fixture/commits/main
