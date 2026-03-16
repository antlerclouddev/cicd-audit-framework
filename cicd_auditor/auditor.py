"""
auditor.py
----------
The Auditor class: discovers pipeline files and orchestrates all checks.

FLOW
    1. Receive a repo path
    2. Walk the directory for known pipeline file paths
    3. For each file: parse YAML, run every registered check
    4. Collect all Findings into an AuditReport and return it

PIPELINE FILE DISCOVERY
    GitHub Actions: .github/workflows/*.yml and *.yaml
    GitLab CI:      .gitlab-ci.yml  (single file at repo root)

ERROR HANDLING PHILOSOPHY
    We never let a single bad file crash the entire audit.
    YAML parse errors produce a Finding (ENG-000) rather than an exception.
    This matters in production: client repos may have partially-written files.
"""

import glob
from pathlib import Path

import yaml

from .checks import ALL_CHECKS
from .models import AuditReport, Finding, Severity

# File globs we consider pipeline files, in priority order
_GITHUB_GLOB  = ".github/workflows/*.y*ml"
_GITLAB_FILE  = ".gitlab-ci.yml"


class Auditor:
    """
    Discovers and audits CI/CD pipeline files in a local repository.

    Usage
    -----
        auditor = Auditor("/path/to/client-repo")
        report  = auditor.run()
    """

    def __init__(self, repo_path: str) -> None:
        self.repo_path = Path(repo_path).resolve()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def run(self) -> AuditReport:
        pipeline_files = self._discover_files()
        report = AuditReport(
            repo_path     = str(self.repo_path),
            audited_files = [str(f) for f in pipeline_files],
        )

        if not pipeline_files:
            report.findings.append(Finding(
                check_id    = "SYS-000",
                title       = "No Pipeline Files Found",
                severity    = Severity.HIGH,
                file_path   = str(self.repo_path),
                detail      = (
                    "No GitHub Actions workflows (.github/workflows/*.yml) or "
                    "GitLab CI file (.gitlab-ci.yml) were found in this repository."
                ),
                remediation = (
                    "Create at least one CI/CD pipeline configuration file.  "
                    "See the `samples/after/` directory for a secure starter template."
                ),
            ))
            return report

        for file_path in pipeline_files:
            findings = self._audit_file(file_path)
            report.findings.extend(findings)

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
        }
        report.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        return report

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _discover_files(self) -> list[Path]:
        """Return absolute paths to all pipeline files found in the repo."""
        files: list[Path] = []

        # GitHub Actions
        pattern = str(self.repo_path / _GITHUB_GLOB)
        for path_str in glob.glob(pattern):
            files.append(Path(path_str))

        # GitLab CI
        gitlab_file = self.repo_path / _GITLAB_FILE
        if gitlab_file.exists():
            files.append(gitlab_file)

        return sorted(set(files))   # deduplicate and sort for deterministic output

    def _audit_file(self, file_path: Path) -> list[Finding]:
        """Parse one pipeline file and run all checks against it."""
        rel_path = str(file_path.relative_to(self.repo_path))

        # Read raw text
        try:
            raw_text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            return [Finding(
                check_id    = "SYS-001",
                title       = "Pipeline File Unreadable",
                severity    = Severity.HIGH,
                file_path   = rel_path,
                detail      = f"Could not read file: {exc}",
                remediation = "Check file permissions and encoding.",
            )]

        # Parse YAML
        try:
            # Use safe_load — never load untrusted YAML with full Loader
            parsed = yaml.safe_load(raw_text) or {}
        except yaml.YAMLError as exc:
            return [Finding(
                check_id    = "SYS-002",
                title       = "YAML Parse Error",
                severity    = Severity.HIGH,
                file_path   = rel_path,
                detail      = f"Pipeline file contains invalid YAML: {exc}",
                remediation = (
                    "Fix the YAML syntax error.  Use a linter like `yamllint` locally:\n"
                    "    pip install yamllint && yamllint " + rel_path
                ),
                evidence    = str(exc)[:200],
            )]

        # Run every registered check
        findings: list[Finding] = []
        for check in ALL_CHECKS:
            try:
                results = check.run(rel_path, raw_text, parsed)
                findings.extend(results)
            except Exception as exc:          # pragma: no cover — safety net
                findings.append(Finding(
                    check_id    = "SYS-003",
                    title       = f"Check {check.ID} Crashed",
                    severity    = Severity.LOW,
                    file_path   = rel_path,
                    detail      = f"Internal error in check {check.ID}: {exc}",
                    remediation = "Please report this as a bug in the audit framework.",
                ))

        return findings
