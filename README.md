# sciath-fixtures

Generate ground-truth fixture JSON from Yocto `cve-check` reports for the Sciath
embedded-Linux compliance validation format. Generation, validation, and statistics
run locally without a backend. This is not the AI-agent debugging product.

The repository is named `sciath-fixture`; the Python package and command are
`sciath-fixtures`.

## Install

Requires Python 3.10 or newer. Install from a checkout:

```bash
git clone https://github.com/HintikkaKimmo/sciath-fixture.git
cd sciath-fixture
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Generate a fixture

```bash
# Basic: from cve-check only
sciath-fixtures generate \
  --cve-check /path/to/cve-check-report.json \
  --name kirkstone_rpi4_cvecheck \
  --source public \
  --output output/

# With a kernel-configuration overlay
sciath-fixtures generate \
  --cve-check /path/to/cve-check-report.json \
  --kconfig /path/to/dot-config \
  --name kirkstone_rpi4_kconfig \
  --source public \
  --output output/

# With DTB overlay
sciath-fixtures generate \
  --cve-check /path/to/cve-check-report.json \
  --kconfig /path/to/dot-config \
  --dtb /path/to/device-tree.dts \
  --name kirkstone_rpi4_full \
  --source public \
  --output output/
```

### Options

| Flag | Description |
|------|------------|
| `--cve-check` | Path to Yocto cve-check JSON report (required) |
| `--name` | Fixture name (required) |
| `--source` | `public`, `synthetic`, `customer`, or `adversarial` (default: `public`) |
| `--output` | Output directory (default: `output/`) |
| `--kconfig` | Kernel .config file for kconfig overlay |
| `--dtb` | Device tree source (.dts) for DTB overlay |
| `--cve-metadata` | CVE metadata JSON for CVSS filtering and subsystem tags |
| `--max-labels N` | Cap total labels (deterministic selection) |
| `--min-cvss N` | Skip CVEs below CVSS score (requires `--cve-metadata`) |
| `--exclude-native` / `--include-native` | Skip build-only recipes (default: exclude) |
| `--notes` | Description text for the fixture |

### Validate a fixture

```bash
sciath-fixtures validate output/kirkstone_rpi4_kconfig.json
```

### View fixture stats

```bash
sciath-fixtures stats output/kirkstone_rpi4_kconfig.json
```

## Output and backend integration

Each invocation writes `<output>/<name>.json` with schema version 1.0, components,
classification labels, optional configuration/device-tree rules, and provenance
hashes. `--dtb` takes a textual `.dts` file, not a compiled `.dtb` binary.

Loading fixtures into a service requires a compatible compliance validation
backend. That service is not included in this repository. The current private
`sciath` repository has a different product scope; its current checkout is not
assumed to provide the former `load_ground_truth` management command.

## Label classification

| cve-check status | true_status | justification | confidence |
|-----------------|-------------|---------------|------------|
| Patched | fixed | patched_backport | high |
| Unpatched | affected | confirmed_affected | high |
| Unpatched + kconfig disabled | not_affected | kconfig_disabled | high |
| Unpatched + DTB disabled | not_affected | hw_not_present | high |
| Ignored (not-applicable) | not_affected | version_not_affected | high |
| Ignored (other) | skipped | — | — |

## Development and checks

The committed `uv.lock` gives a reproducible development environment:

```bash
uv sync --frozen --extra dev
uv run pytest tests/
uv run ruff check .
uv run mypy src/sciath_fixtures/
uv run pip-audit
uv build
```

## Producing input

Enable Yocto's `cve-check` class in a local build with `INHERIT += "cve-check"`
and supply its JSON report to `--cve-check`. Build duration and report location
depend on your image and Yocto configuration. The repository's `tests/` contains
small inputs for automated tests. Labels reflect the source report and the
configured overlays; they are not independent proof that a vulnerability is
absent.

## License

[PolyForm Shield 1.0.0](LICENSE.md). Copyright 2026 Kimmo Hintikka;
see [NOTICE](NOTICE). This is source-available software, not OSI-approved open
source. The license permits noncompeting uses, including commercial uses, and
restricts competing uses as defined in its terms. Contact the licensor for
permission for uses outside those terms. Third-party dependencies retain their
own licenses.
