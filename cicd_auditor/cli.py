"""
cli.py
------
Command-line interface for the CI/CD Audit Framework.

Built with Click — the industry standard for Python CLIs.
Click gives us: automatic --help generation, type validation,
coloured output, and easy subcommand extension.

COMMANDS
    cicd-audit run  [REPO_PATH]   → audit a repo and generate a report
    cicd-audit version            → print version

USAGE EXAMPLES
    # Audit the current directory
    cicd-audit run .

    # Audit a specific repo, save report to custom location
    cicd-audit run /path/to/client-repo --output /tmp/client-report.html

    # Show only findings above a severity threshold
    cicd-audit run . --min-severity HIGH

    # Fail with exit code 1 if score drops below threshold (for CI use)
    cicd-audit run . --fail-below 80
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import click

from . import Auditor, __version__, render_html
from .models import Severity

# Severity ordering for --min-severity filtering
_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
}

_SEV_COLOURS = {
    Severity.CRITICAL: "red",
    Severity.HIGH:     "yellow",
    Severity.MEDIUM:   "bright_yellow",
    Severity.LOW:      "green",
}


@click.group()
def cli():
    """
    \b
    ╔═══════════════════════════════════════╗
    ║   CI/CD Pipeline Audit Framework      ║
    ║   Scan · Score · Remediate            ║
    ╚═══════════════════════════════════════╝

    Scans GitHub Actions and GitLab CI pipeline files for security
    vulnerabilities and efficiency issues, then produces a scored
    HTML report you can hand to clients.
    """
    pass


@cli.command()
@click.argument("repo_path", default=".", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    default=None,
    help="Output path for the HTML report. Defaults to ./audit-report-<timestamp>.html",
)
@click.option(
    "--min-severity", "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Only display findings at or above this severity in the terminal.",
)
@click.option(
    "--fail-below", "-f",
    type=click.IntRange(0, 100),
    default=None,
    help="Exit with code 1 if the security score is below this threshold. "
         "Useful for blocking CI on low scores.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Also write a machine-readable JSON summary alongside the HTML report.",
)
@click.option(
    "--no-report",
    is_flag=True,
    default=False,
    help="Skip writing the HTML report (print terminal summary only).",
)
def run(repo_path, output, min_severity, fail_below, output_json, no_report):
    """
    Audit pipeline files in REPO_PATH and generate a report.

    REPO_PATH defaults to the current directory.
    """
    repo_path = str(Path(repo_path).resolve())

    click.echo()
    click.secho("  🔍  CI/CD Audit Framework", bold=True)
    click.secho(f"  📁  Scanning: {repo_path}", fg="cyan")
    click.echo()

    # ── Run the audit ──────────────────────────────────────────────────
    auditor = Auditor(repo_path)
    report  = auditor.run()

    # ── Determine output path ──────────────────────────────────────────
    if output is None:
        ts     = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        output = f"audit-report-{ts}.html"

    # ── Print terminal summary ─────────────────────────────────────────
    _print_summary(report, min_severity)

    # ── Write HTML report ──────────────────────────────────────────────
    if not no_report:
        out_path = render_html(report, output)
        click.echo()
        click.secho(f"  📄  Report written → {out_path}", fg="bright_cyan", bold=True)

    # ── Write JSON summary ─────────────────────────────────────────────
    if output_json:
        json_path = output.replace(".html", ".json")
        _write_json(report, json_path)
        click.secho(f"  📊  JSON written  → {json_path}", fg="cyan")

    # ── Exit code for CI integration ───────────────────────────────────
    if fail_below is not None and report.score < fail_below:
        click.echo()
        click.secho(
            f"  ✗  Score {report.score} is below the required threshold of {fail_below}. "
            "Pipeline blocked.",
            fg="red", bold=True,
        )
        sys.exit(1)

    click.echo()


@cli.command()
def version():
    """Print the tool version and exit."""
    click.echo(f"cicd-audit-framework v{__version__}")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _print_summary(report, min_severity: str) -> None:
    """Print a coloured terminal summary of the audit results."""
    min_order = _SEV_ORDER[min_severity.upper()]

    # Score line
    score_colour = (
        "green"  if report.score >= 90 else
        "cyan"   if report.score >= 75 else
        "yellow" if report.score >= 60 else
        "red"
    )
    click.secho(
        f"  Score: {report.score}/100   Grade: {report.grade} – {report.grade_label}",
        fg=score_colour, bold=True,
    )
    s = report.summary
    click.echo(
        f"  Findings: {s['total']} total  "
        f"({s['critical']} critical · {s['high']} high · "
        f"{s['medium']} medium · {s['low']} low)"
    )
    click.echo(f"  Files audited: {len(report.audited_files)}")
    click.echo()

    if not report.findings:
        click.secho("  ✅  No issues found. Clean pipeline!", fg="green", bold=True)
        return

    # Filtered findings
    filtered = [
        f for f in report.findings
        if _SEV_ORDER.get(f.severity, 99) <= min_order
    ]

    if not filtered:
        click.secho(
            f"  (No findings at or above {min_severity} — use --min-severity LOW to see all)",
            fg="cyan",
        )
        return

    for finding in filtered:
        colour = _SEV_COLOURS.get(finding.severity, "white")
        loc = f"  {finding.file_path}"
        if finding.line_number:
            loc += f":{finding.line_number}"

        click.echo()
        click.secho(f"  [{finding.check_id}] {finding.title}", fg=colour, bold=True)
        click.echo(loc)
        click.secho(f"  Severity: {finding.severity}  (−{finding.weight} pts)", fg=colour)
        click.echo(f"  {finding.detail[:140]}{'...' if len(finding.detail) > 140 else ''}")
        if finding.evidence:
            click.secho(f"  ▶  {finding.evidence[:120]}", fg="bright_black")


def _write_json(report, path: str) -> None:
    """Write a machine-readable JSON summary of the report."""
    data = {
        "score":         report.score,
        "grade":         report.grade,
        "grade_label":   report.grade_label,
        "repo_path":     report.repo_path,
        "audited_files": report.audited_files,
        "generated_at":  report.generated_at.isoformat(),
        "summary":       report.summary,
        "findings": [
            {
                "check_id":    f.check_id,
                "title":       f.title,
                "severity":    f.severity,
                "weight":      f.weight,
                "file_path":   f.file_path,
                "line_number": f.line_number,
                "detail":      f.detail,
                "remediation": f.remediation,
                "evidence":    f.evidence,
            }
            for f in report.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# Allow running as `python -m cicd_auditor`
if __name__ == "__main__":
    cli()
