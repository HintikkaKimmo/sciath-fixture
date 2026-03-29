# sciath-fixture — Claude Context

## What is this?

CLI tool for generating ground truth test fixtures from real Yocto `cve-check`
output. These fixtures feed Sciath's zero-false-negatives validation engine.

**Core purpose:** Convert real build artifacts (cve-check JSON, kernel .config,
device tree .dts) into labeled fixture JSON that Sciath's `load_ground_truth`
command can ingest.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| CLI | Typer + Rich |
| Packaging | Hatchling (pyproject.toml, `src/` layout) |
| Testing | pytest |
| Linting | ruff, mypy (strict mode), bandit |
| Security | gitleaks, semgrep, pip-audit |
| Task runner | uv |

---

## Project structure

```
sciath-fixture/
├── src/sciath_fixtures/
│   ├── cli.py              — Typer CLI: generate, validate, stats commands
│   ├── cve_check_parser.py — Parse Yocto cve-check JSON reports
│   ├── kconfig_parser.py   — Parse kernel .config files
│   ├── dtb_parser.py       — Parse device tree .dts files
│   ├── filters.py          — Label classification logic
│   ├── fixture_builder.py  — Build fixture JSON from parsed data
│   └── name_mapper.py      — Package name normalisation
├── sources/                — Raw input artifacts (cve-check, .config, .dts)
│   └── kirkstone-rpi4/     — Kirkstone RPi4 build artifacts
├── output/                 — Generated fixture JSON files
├── tests/                  — pytest test suite
└── pyproject.toml          — Package config, dependencies, tool settings
```

---

## How it works

```
Yocto cve-check JSON + (optional) kernel .config + (optional) .dts
         │
         ▼  sciath-fixtures generate
  1. Parse cve-check report → packages + CVE statuses
  2. Parse kconfig → enabled/disabled kernel symbols
  3. Parse DTB → hardware nodes present on device
  4. Apply label classification rules (see README table)
  5. Build fixture JSON with SBOM, intelligence data, and labels
         │
         ▼  output/{name}.json
  Copy to Sciath: validation/fixtures/{source}/
  Load:  python manage.py load_ground_truth --fixture {name}
  Test:  python manage.py run_validation --verbose
```

---

## Label classification

| cve-check status | true_status | justification | confidence |
|-----------------|-------------|---------------|------------|
| Patched | fixed | patched_backport | high |
| Unpatched | affected | confirmed_affected | high |
| Unpatched + kconfig disabled | not_affected | kconfig_disabled | high |
| Unpatched + DTB disabled | not_affected | hw_not_present | high |
| Ignored (not-applicable) | not_affected | version_not_affected | high |
| Ignored (other) | skipped | — | — |

---

## Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint + type check
ruff check src/
mypy src/sciath_fixtures/
```

---

## Pre-commit hooks

| Hook | What it checks |
|------|---------------|
| `trailing-whitespace` | Removes trailing whitespace |
| `end-of-file-fixer` | Ensures files end with newline |
| `check-yaml` | Validates YAML syntax |
| `check-added-large-files` | Blocks large binary blobs |
| `detect-private-key` | Blocks committed private keys |
| `bandit` | Python security linter on `src/` |
| `gitleaks` | Scans for leaked secrets |
| `semgrep` | SAST security scanner |
| `ruff` | Python linter (via `uv run`) |
| `pytest` | Full test suite |
| `mypy` | Strict type checking on `src/sciath_fixtures/` |

---

## CHANGELOG and VERSION — update on every commit

**Every commit that changes functionality must update `CHANGELOG.md`.**

- Add a bullet under `## [Unreleased]` in the appropriate section (`Added`, `Changed`, `Fixed`).
- Use the same voice as existing entries: bold lead phrase, then one-sentence description.
- `VERSION` is only bumped when cutting a release, not on every commit.

**Exceptions:** Pure docs changes, CI config tweaks, and dependency-only updates
do not need a CHANGELOG entry.

---

## Relationship to other repos

| Repo | What it is | When to look there |
|------|-----------|-------------------|
| [sciath](https://github.com/HintikkaKimmo/sciath) | Backend + engine | `validation/` dir, `load_ground_truth` command, fixture JSON schema |
| [sciath-cli](https://github.com/HintikkaKimmo/sciath-cli) | CLI tool | Not directly related |
| [sciath-meta](https://github.com/HintikkaKimmo/sciath-meta) | Yocto bbclass | Produces the cve-check output that this tool consumes |
| **This repo** | Fixture generator | Converts build artifacts → labeled test fixtures |

The fixture JSON schema is defined by what `load_ground_truth` expects. If the
Sciath backend changes the schema, update `fixture_builder.py` to match.
