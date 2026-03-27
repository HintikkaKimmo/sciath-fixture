"""sciath-fixtures CLI — generate ground truth fixtures from Yocto cve-check output."""

from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sciath_fixtures.cve_check_parser import parse_cve_check
from sciath_fixtures.dtb_parser import parse_dtb
from sciath_fixtures.fixture_builder import (
    build_fixture,
    load_cve_metadata,
    validate_fixture,
)
from sciath_fixtures.kconfig_parser import parse_kconfig

app = typer.Typer(
    name="sciath-fixtures",
    help="Generate ground truth fixture JSON from Yocto cve-check output.",
    no_args_is_help=True,
)
console = Console(stderr=True)


@app.command()
def generate(
    cve_check: Path = typer.Option(
        ..., "--cve-check", help="Path to Yocto cve-check JSON report",
        exists=True, readable=True,
    ),
    name: str = typer.Option(
        ..., "--name", help="Fixture name (e.g., kirkstone_rpi4_cvecheck)",
    ),
    source: str = typer.Option(
        "public", "--source", help="Fixture source: public, synthetic, customer, adversarial",
    ),
    output: Path = typer.Option(
        Path("output"), "--output", help="Output directory for generated fixture",
    ),
    kconfig: Path | None = typer.Option(
        None, "--kconfig", help="Path to kernel .config file for kconfig overlay",
        exists=True, readable=True,
    ),
    dtb: Path | None = typer.Option(
        None, "--dtb", help="Path to device tree source (.dts) for DTB overlay",
        exists=True, readable=True,
    ),
    cve_metadata: Path | None = typer.Option(
        None, "--cve-metadata",
        help="Path to CVE metadata JSON (enables CVSS filtering and subsystem tags)",
        exists=True, readable=True,
    ),
    max_labels: int | None = typer.Option(
        None, "--max-labels", help="Cap total labels (deterministic selection)",
    ),
    min_cvss: float | None = typer.Option(
        None, "--min-cvss", help="Skip CVEs below this CVSS score (requires --cve-metadata)",
    ),
    exclude_native: bool = typer.Option(
        True, "--exclude-native/--include-native",
        help="Skip -native/-cross/nativesdk- recipes (build-only)",
    ),
    notes: str = typer.Option(
        "", "--notes", help="Description of what this fixture covers",
    ),
) -> None:
    """Generate a ground truth fixture JSON from Yocto cve-check output."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Parse inputs.
    console.print(f"[bold]Parsing cve-check report:[/] {cve_check}")
    report = parse_cve_check(cve_check)
    console.print(
        f"  Found {report.total_packages} packages, {report.total_cves} CVE entries"
    )

    kconfig_data = None
    if kconfig:
        console.print(f"[bold]Parsing kconfig:[/] {kconfig}")
        kconfig_data = parse_kconfig(kconfig)
        console.print(f"  Found {len(kconfig_data)} config symbols")

    dtb_nodes = None
    if dtb:
        console.print(f"[bold]Parsing device tree:[/] {dtb}")
        dtb_nodes = parse_dtb(dtb)
        console.print(f"  Found {len(dtb_nodes)} DTB nodes")

    metadata = None
    if cve_metadata:
        console.print(f"[bold]Loading CVE metadata:[/] {cve_metadata}")
        metadata = load_cve_metadata(cve_metadata)
        console.print(f"  Loaded {len(metadata)} CVE records")

    # Track input files for provenance.
    input_files: dict[str, Path] = {"cve_check": cve_check}
    if kconfig:
        input_files["kconfig"] = kconfig
    if dtb:
        input_files["dtb"] = dtb
    if cve_metadata:
        input_files["cve_metadata"] = cve_metadata

    # Build fixture.
    console.print("[bold]Building fixture...[/]")
    fixture = build_fixture(
        report=report,
        name=name,
        source=source,
        kconfig=kconfig_data,
        dtb_nodes=dtb_nodes,
        metadata=metadata,
        exclude_native=exclude_native,
        max_labels=max_labels,
        min_cvss=min_cvss,
        notes=notes,
        input_files=input_files,
    )

    # Validate.
    errors = validate_fixture(fixture)
    if errors:
        console.print("[bold red]Validation errors:[/]")
        for err in errors:
            console.print(f"  [red]- {err}[/]")
        raise typer.Exit(code=1)

    # Write output.
    output.mkdir(parents=True, exist_ok=True)
    out_path = output / f"{name}.json"
    out_path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")
    console.print(f"[bold green]Written:[/] {out_path}")

    # Print summary.
    labels = fixture["labels"]
    status_counts = Counter(l["true_status"] for l in labels)
    justification_counts = Counter(l["justification_category"] for l in labels)

    table = Table(title="Fixture Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Name", name)
    table.add_row("Components", str(len(fixture["sbom"])))
    table.add_row("Total labels", str(len(labels)))
    for status, count in sorted(status_counts.items()):
        table.add_row(f"  {status}", str(count))
    if fixture.get("kconfig_rules"):
        table.add_row("Kconfig rules", str(len(fixture["kconfig_rules"])))
    if fixture.get("dtb_rules"):
        table.add_row("DTB rules", str(len(fixture["dtb_rules"])))
    console.print(table)

    kconfig_labels = justification_counts.get("kconfig_disabled", 0)
    dtb_labels = justification_counts.get("hw_not_present", 0)
    if kconfig_labels:
        console.print(
            f"[bold cyan]Kconfig overlay:[/] {kconfig_labels} labels "
            f"overridden to not_affected (kconfig_disabled)"
        )
    if dtb_labels:
        console.print(
            f"[bold cyan]DTB overlay:[/] {dtb_labels} labels "
            f"overridden to not_affected (hw_not_present)"
        )


@app.command()
def validate(
    fixture_path: Path = typer.Argument(
        ..., help="Path to fixture JSON file to validate",
        exists=True, readable=True,
    ),
) -> None:
    """Validate a fixture JSON file against Sciath's expected schema."""
    try:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Invalid JSON:[/] {e}")
        raise typer.Exit(code=1)

    errors = validate_fixture(data)
    if errors:
        console.print(f"[bold red]Validation failed ({len(errors)} errors):[/]")
        for err in errors:
            console.print(f"  [red]- {err}[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold green]Valid:[/] {fixture_path}")
    console.print(
        f"  {len(data.get('labels', []))} labels, "
        f"{len(data.get('sbom', []))} components"
    )


@app.command()
def stats(
    fixture_path: Path = typer.Argument(
        ..., help="Path to fixture JSON file",
        exists=True, readable=True,
    ),
) -> None:
    """Show statistics for a fixture JSON file."""
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    labels = data.get("labels", [])

    # Status breakdown.
    table = Table(title=f"Stats: {data.get('name', fixture_path.name)}")
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right")

    table.add_row("Components", "", str(len(data.get("sbom", []))))
    table.add_row("Total labels", "", str(len(labels)))

    status_counts = Counter(l.get("true_status") for l in labels)
    for status, count in sorted(status_counts.items()):
        table.add_row("Status", status, str(count))

    justification_counts = Counter(l.get("justification_category") for l in labels)
    for just, count in sorted(justification_counts.items()):
        table.add_row("Justification", just, str(count))

    confidence_counts = Counter(l.get("confidence", "high") for l in labels)
    for conf, count in sorted(confidence_counts.items()):
        table.add_row("Confidence", conf, str(count))

    # Component breakdown.
    comp_counts = Counter(l.get("component_name") for l in labels)
    for comp, count in comp_counts.most_common(10):
        table.add_row("Component", comp, str(count))

    console.print(table)

    if data.get("kconfig_rules"):
        console.print(f"Kconfig rules: {len(data['kconfig_rules'])}")
    if data.get("dtb_rules"):
        console.print(f"DTB rules: {len(data['dtb_rules'])}")
    if data.get("_provenance"):
        console.print("Provenance hashes recorded: yes")


if __name__ == "__main__":
    app()
