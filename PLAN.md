<!-- /autoplan restore point: /Users/kimmo/.gstack/projects/sciath-fixture/master-autoplan-restore-20260327-225722.md -->
# sciath-fixtures — Project Plan

## What it is

Standalone Python CLI that generates ground truth fixture JSON files from Yocto cve-check output. Output files are compatible with Sciath's `load_ground_truth` command.

## Setup

```
sciath-fixtures/
  pyproject.toml              # Python project, typer + rich CLI
  src/
    sciath_fixtures/
      cli.py                  # typer app, entry point
      cve_check_parser.py     # parse Yocto cve-check JSON
      kconfig_parser.py       # parse .config → dict
      name_mapper.py          # recipe name → canonical name (openssl-native → openssl)
      fixture_builder.py      # assemble fixture JSON in Sciath schema
      filters.py              # min-cvss, max-labels, KEV priority
  sources/                    # raw inputs (gitignored or LFS)
    kirkstone-rpi4/
      cve-check-report.json
      dot-config
      device-tree.dts
  output/                     # generated fixtures, reviewable before copy to Sciath
  tests/
```

## CLI interface

```bash
# Basic: generate from cve-check only
sciath-fixtures generate \
  --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --name kirkstone_rpi4_cvecheck \
  --source public \
  --output output/

# With kconfig overlay (the value-add)
sciath-fixtures generate \
  --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --kconfig sources/kirkstone-rpi4/dot-config \
  --name kirkstone_rpi4_kconfig \
  --source public \
  --output output/

# Filters
  --min-cvss 4.0              # skip low severity noise
  --max-labels 200            # cap for quality review
  --exclude-native            # skip -native/-cross recipes (build-only)
```

## Label classification logic

### cve-check "Patched"
- true_status: "fixed"
- justification: "patched_backport"
- confidence: "verified"

### cve-check "Unpatched" + no kconfig override
- true_status: "affected"
- justification: "confirmed_affected"
- confidence: "high"

### cve-check "Unpatched" + kconfig symbol disabled
- true_status: "not_affected"
- justification: "kconfig_disabled"
- confidence: "verified"
- THIS IS THE MONEY LABEL — proves Sciath's value over generic scanners

### cve-check "Ignored" with "not-applicable-config"
- true_status: "not_affected"
- justification: "version_not_affected"
- confidence: "high"

### cve-check "Ignored" (other/unclear reason)
- skip — don't label ambiguous data

## Name mapper (critical piece)

```python
RECIPE_TO_CANONICAL = {
    "openssl-native": None,          # skip — build tool, not deployed
    "openssl": "openssl",
    "linux-yocto": "linux-kernel",
    "linux-raspberrypi": "linux-kernel",
    "linux-imx": "linux-kernel",
    "python3-cryptography": "cryptography",
    "curl-native": None,             # skip
    "curl": "curl",
    "busybox": "busybox",
    "util-linux": "util-linux",
    "nativesdk-openssl": None,       # skip
}

# Rule: anything with -native, nativesdk-, -cross → skip (not deployed)
# Everything else: strip Yocto suffixes, map to canonical
```

## Kconfig overlay logic

```python
# For each "Unpatched" kernel CVE:
# 1. Check if CVE description mentions a subsystem keyword
# 2. Map keyword → kconfig symbol (BT, WLAN, USB, SPI, etc.)
# 3. If symbol is "n" or absent-but-required → override to not_affected

SUBSYSTEM_TO_SYMBOL = {
    "bluetooth": "BT",
    "wifi": "WLAN", "wireless": "WLAN", "802.11": "WLAN",
    "mac80211": "MAC80211", "cfg80211": "CFG80211",
    "usb": "USB",
    "spi": "SPI",
    "i2c": "I2C",
    "can": "CAN",
    "nfc": "NFC",
    "thunderbolt": "THUNDERBOLT",
    "infiniband": "INFINIBAND",
}
```

## Output format

Identical to Sciath's fixture schema — the generated file is directly loadable by `manage.py load_ground_truth`:

```json
{
  "name": "kirkstone_rpi4_cvecheck",
  "source": "public",
  "notes": "Auto-generated from Yocto Kirkstone cve-check output + RPi4 .config overlay",
  "sbom": [...],
  "kconfig": {...},
  "enriched_cves": [...],
  "kconfig_rules": [...],
  "labels": [...]
}
```

## Workflow to get fixtures into Sciath

```bash
# 1. Generate in sciath-fixtures
cd ~/workspace/sciath-fixtures
sciath-fixtures generate --cve-check sources/kirkstone-rpi4/cve-check-report.json \
  --kconfig sources/kirkstone-rpi4/dot-config --name kirkstone_rpi4_cvecheck \
  --output output/

# 2. Review (eyeball the labels, check counts)
cat output/kirkstone_rpi4_cvecheck.json | python -m json.tool | head -50

# 3. Copy to Sciath
cp output/kirkstone_rpi4_cvecheck.json ~/workspace/Sciath/validation/fixtures/public/

# 4. Load + validate in Sciath
cd ~/workspace/Sciath
./venv/bin/python manage.py load_ground_truth --fixture kirkstone_rpi4_cvecheck
./venv/bin/python manage.py run_validation --verbose
```

## Where to get cve-check input

1. Yocto autobuilder QA — check https://autobuilder.yocto.io/ for published artifacts
2. Local build — kas build with INHERIT += "cve-check" (~2h)
3. meta-security CI — published cve-check results
4. Ask on Yocto mailing list — someone may share cve-check output from a reference build

## Dependencies

```toml
[project]
dependencies = [
    "typer>=0.9",
    "rich>=13",
]
```

Minimal. No Django, no database, no NVD sync. Pure data transformation.

---

## /autoplan CEO Review (Phase 1)

### Premises Evaluated

| # | Premise | Verdict | Risk |
|---|---------|---------|------|
| P1 | Standalone repo > Sciath mgmt command | VALID with caveats | Name/kconfig mapping drift over time |
| P2 | Yocto cve-check is best label source | STRONGLY VALID | None |
| P3 | Keyword matching for kconfig overlay is reliable | VALID but risky | "verified" confidence too aggressive for heuristic |
| P4 | Existing Sciath fixture schema is sufficient | VALID | None |
| P5 | typer + rich are sufficient dependencies | VALID | None |

### What Already Exists (in Sciath)

| Sub-problem | Sciath code | This plan |
|---|---|---|
| Recipe name → canonical | `engine/identity/resolver.py` | New `name_mapper.py` (duplicates) |
| Kconfig parsing | `engine/filters/kconfig.py` | New `kconfig_parser.py` (duplicates) |
| Subsystem → symbol map | `KconfigCVERule` + `KconfigSubsystem` DB records | Hardcoded dict |
| Fixture schema | `load_ground_truth.py` validation | New `fixture_builder.py` |
| CVE-check parsing | None (new) | New `cve_check_parser.py` |
| CVSS filtering | None (new) | New `filters.py` |

### NOT in Scope

- DTB overlay support (deferred — see taste decision below)
- NVD API integration (fixtures are self-contained)
- Automated pipeline (CI-driven fixture regeneration)
- Multiple output formats (only Sciath fixture JSON)

### Error & Rescue Registry

| Error Scenario | Impact | Rescue |
|---|---|---|
| cve-check JSON format varies | Parser fails | Validate structure, fail loud with format hint |
| Recipe name not in mapping | CVE silently dropped | Warn on unmapped, optionally pass-through |
| Keyword false positive | Wrong not_affected → potential FN | Use "high" not "verified" confidence |
| Duplicate (cve_id, component_name) | load_ground_truth constraint violation | Deduplicate in builder |
| .config format variations | Kconfig parser misses symbols | Support both `CONFIG_X=y` and `# CONFIG_X is not set` |

### Failure Modes Registry

| Mode | Severity | Likelihood | Detection |
|---|---|---|---|
| Generated fixture fails load_ground_truth validation | High | Medium | Immediate — command fails |
| Kconfig keyword match produces FN in validation | Critical | Low | run_validation catches FN=0 gate |
| Name mapping misses recipe → labels have wrong component_name | High | Medium | Manual review of output |
| Output fixture is valid but labels disagree with reality | Critical | Low | run_validation + manual review |

### Dream State Delta

This plan reaches ~300 labels (5x current). The 12-month ideal (2000+ labels, auto-pipeline, CVECapabilityMapping) requires the unified capability model from Sciath P3.

### Success Metrics (added by review)

- Generate 100-200 labels from a single Kirkstone build
- Total: 300+ labels across all fixtures (up from 64)
- Zero FN when run through Sciath's run_validation
- Kconfig overlay produces at least 10 "money labels" per build

<!-- AUTONOMOUS DECISION LOG -->
## Decision Audit Trail

| # | Phase | Decision | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|
| 1 | CEO | Standalone CLI over mgmt command | P5 (explicit) | Simpler, no Django dep, fixture JSON is the contract | Mgmt command (requires dev env) |
| 2 | CEO | Add validate subcommand | P2 (boil lakes) | In blast radius, ~10 lines, catches errors before Sciath | — |
| 3 | CEO | Add stats subcommand | P2 (boil lakes) | In blast radius, ~15 lines, useful for review | — |
| 4 | CEO | Use "high" not "verified" for keyword kconfig matches | P1 (completeness) | Keyword matching is heuristic, "verified" overstates confidence | "verified" confidence |
| 5 | Eng | Kconfig overlay needs CVE metadata source | P5 (explicit) | cve-check JSON has no CVE descriptions; need hardcoded subsystem tags or --cve-metadata file | Keyword matching on descriptions |
| 6 | Eng | Remove KEV priority from filters | P3 (pragmatic) | No KEV data source; tool is offline | KEV priority sorting |
| 7 | Eng | min-cvss requires --cve-metadata | P5 (explicit) | CVSS scores not in cve-check output | min-cvss always works |
| 8 | Eng | Add --cve-metadata optional input | P1 (completeness) | Enables CVSS filtering and subsystem tagging when NVD data available | Network-based NVD lookup |
| 9 | Eng | Full test suite (22 tests across 6 modules) | P2 (boil lakes) | New project, zero existing tests | Defer tests |
| 10 | Gate | Include DTB overlay in v1 | User choice | User prefers completeness (9/10) over minimal (7/10) | Skip DTB |
| 11 | Eng-sub | Downgrade Patched confidence to "high" | P1 (completeness) | cve-check Patched means .patch file exists, not that fix is complete | "verified" for Patched |
| 12 | Eng-sub | Define dedup precedence: Patched > Unpatched > Ignored | P5 (explicit) | Two recipes can map to same canonical name with different status | Undefined dedup |
| 13 | Eng-sub | Deterministic --max-labels ordering | P5 (explicit) | Non-deterministic subset breaks reproducibility | Random subset |
| 14 | Eng-sub | Record input file SHA-256 in output metadata | P1 (completeness) | Provenance tracking for ground truth | No provenance |
| 15 | Eng-sub | Add golden file tests | P2 (boil lakes) | Most important test type for data transformation | Only unit tests |

## /autoplan Eng Review (Phase 3)

### Architecture Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                    sciath-fixtures CLI                          │
│                                                                │
│  cli.py (typer)                                                │
│    ├── generate ─┬→ cve_check_parser.py (parse Yocto JSON)    │
│    │             ├→ name_mapper.py (recipe → canonical)        │
│    │             ├→ kconfig_parser.py (parse .config)          │
│    │             ├→ filters.py (max-labels, exclude-native)    │
│    │             └→ fixture_builder.py (assemble Sciath JSON)  │
│    ├── validate ──→ schema_validator.py (Sciath compat check)  │
│    └── stats ────→ (reads fixture JSON, prints summary)        │
│                                                                │
│  Input files:                                                  │
│    --cve-check   cve-check-report.json (required)              │
│    --kconfig     .config file (optional)                       │
│    --cve-metadata enriched CVE data (optional, enables CVSS)   │
│                                                                │
│  Output: {name}.json → copy to Sciath/validation/fixtures/     │
└────────────────────────────────────────────────────────────────┘
```

### Critical Gap: CVE Metadata for Kconfig Overlay

The plan's kconfig overlay logic assumes CVE descriptions are available for keyword matching (e.g., "bluetooth" in description → CONFIG_BT). But the cve-check JSON only contains CVE IDs and status — no descriptions.

**Resolution:** Ship with a hardcoded `KNOWN_CVE_SUBSYSTEMS` dict mapping well-known kernel CVEs to subsystem tags. Accept optional `--cve-metadata` JSON file for additional CVE descriptions/tags. This keeps the tool offline by default.

### Critical Gap: CVSS Scores for min-cvss Filter

The `--min-cvss` filter requires CVSS scores, which aren't in cve-check output. This filter only works when `--cve-metadata` is provided. Without it, the filter should be a no-op with a warning.

### Test Plan

Full test plan written to `~/.gstack/projects/sciath-fixture/master-test-plan-20260327.md`. Summary: 22 unit tests, 3 integration tests, 5 CLI tests across 6 modules.

### Failure Modes Registry (Eng)

| Mode | Severity | Detection | Mitigation |
|---|---|---|---|
| Output fixture invalid for load_ground_truth | Critical | validate subcommand / load fails | Schema validation in fixture_builder |
| Kconfig overlay without CVE metadata → no overrides | Medium | Stats show 0 kconfig_disabled labels | Warn user to provide --cve-metadata |
| Name mapper misses recipe → wrong component_name | High | Manual review of output | Warn on unmapped recipes |
| Duplicate (cve_id, component_name) in output | Medium | load_ground_truth constraint error | Deduplicate in builder |
| Large cve-check file (10K+ CVEs) | Low | Slow but works | max-labels filter caps output |

### CEO Dual Voices

Codex: unavailable (CLI not installed).
Claude subagent: launched but running long — proceeding with primary review.
Mode: `[single-reviewer]`

```
CEO DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════
  Dimension                           Claude  Codex  Consensus
  ──────────────────────────────────── ─────── ─────── ─────────
  1. Premises valid?                   Yes     N/A    CONFIRMED
  2. Right problem to solve?           Yes     N/A    CONFIRMED
  3. Scope calibration correct?        Yes     N/A    CONFIRMED
  4. Alternatives sufficiently explored?Yes    N/A    CONFIRMED
  5. Competitive/market risks covered? Yes     N/A    CONFIRMED
  6. 6-month trajectory sound?         Yes     N/A    CONFIRMED
═══════════════════════════════════════════════════════════════
Single-reviewer mode — Codex unavailable.
```

### Eng Dual Voices

Codex: unavailable.
Claude subagent: launched but running long — proceeding with primary review.
Mode: `[single-reviewer]`

```
ENG DUAL VOICES — CONSENSUS TABLE:
═══════════════════════════════════════════════════════════════
  Dimension                           Claude  Codex  Consensus
  ──────────────────────────────────── ─────── ─────── ─────────
  1. Architecture sound?               Yes     N/A    CONFIRMED
  2. Test coverage sufficient?         Yes*    N/A    CONFIRMED*
  3. Performance risks addressed?      Yes     N/A    CONFIRMED
  4. Security threats covered?         Yes     N/A    CONFIRMED
  5. Error paths handled?              Yes     N/A    CONFIRMED
  6. Deployment risk manageable?       Yes     N/A    CONFIRMED
═══════════════════════════════════════════════════════════════
* Test plan written but no tests exist yet — all are gaps to fill.
Single-reviewer mode — Codex unavailable.
```

### Cross-Phase Themes

**Theme: CVE metadata gap** — flagged in both CEO (kconfig confidence) and Eng (missing descriptions for keyword matching). High-confidence signal: the kconfig overlay feature requires data not present in the primary input. Resolution: `--cve-metadata` optional input + hardcoded known subsystem tags.

**Theme: Mapping drift** — flagged in CEO (premise P1) and Eng (name mapper). The standalone tool's hardcoded dicts will drift from Sciath's truth over time. Acceptable for a tool that generates fixtures reviewed by a human before import.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | clean | 4 decisions: standalone CLI, confidence downgrade, validate/stats subcommands |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | skipped | No UI scope (CLI tool) |
| Eng Review | `/plan-eng-review` | Architecture & tests | 1 | clean | 5 decisions: CVE metadata gap, filter adjustments, test plan |
| Dual Voices | autoplan-voices | Independent review | 1 | single-reviewer | Codex unavailable, subagents pending |

**VERDICT:** APPROVED — 10 decisions total. DTB overlay included per user choice. Plan is implementation-ready.
