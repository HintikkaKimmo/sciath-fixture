# sciath-fixtures

Generate ground truth fixture JSON from Yocto cve-check output for [Sciath](https://github.com/HintikkaKimmo/sciath) validation.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Generate a fixture

```bash
# Basic: from cve-check only
sciath-fixtures generate \
  --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --name kirkstone_rpi4_cvecheck \
  --source public \
  --output output/

# With kconfig overlay (the value-add — proves Sciath's hardware-aware suppression)
sciath-fixtures generate \
  --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --kconfig sources/kirkstone-rpi4/dot-config \
  --name kirkstone_rpi4_kconfig \
  --source public \
  --output output/

# With DTB overlay
sciath-fixtures generate \
  --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --kconfig sources/kirkstone-rpi4/dot-config \
  --dtb sources/kirkstone-rpi4/device-tree.dts \
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

## Loading into Sciath

```bash
# Copy generated fixture to Sciath
cp output/kirkstone_rpi4_kconfig.json ~/workspace/Sciath/validation/fixtures/public/

# Load and validate
cd ~/workspace/Sciath
./venv/bin/python manage.py load_ground_truth --fixture kirkstone_rpi4_kconfig
./venv/bin/python manage.py run_validation --verbose
```

## Label classification

| cve-check status | true_status | justification | confidence |
|-----------------|-------------|---------------|------------|
| Patched | fixed | patched_backport | high |
| Unpatched | affected | confirmed_affected | high |
| Unpatched + kconfig disabled | not_affected | kconfig_disabled | high |
| Unpatched + DTB disabled | not_affected | hw_not_present | high |
| Ignored (not-applicable) | not_affected | version_not_affected | high |
| Ignored (other) | skipped | — | — |

## Tests

```bash
pytest tests/ -v
```

## Where to get cve-check input

1. **Yocto autobuilder QA** — published artifacts at autobuilder.yocto.io
2. **Local build** — `kas build` with `INHERIT += "cve-check"` (~2h)
3. **meta-security CI** — published cve-check results
