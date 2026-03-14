"""
tests/test_auditor_integration.py
-----------------------------------
Integration tests for the Auditor class end-to-end.

Unlike unit tests, these tests:
    • Create real temporary directories and files on disk
    • Run the full Auditor.run() pipeline
    • Assert on the AuditReport produced

This verifies that file discovery, YAML parsing, check dispatch,
and report assembly all work together correctly.
"""

import os
import pytest
from pathlib import Path
from cicd_auditor.auditor import Auditor
from cicd_auditor.models import Severity

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    """Return a helper that writes workflow files into a temp repo directory."""
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    class RepoHelper:
        root = tmp_path

        def write_workflow(self, name: str, content: str) -> Path:
            path = workflows_dir / name
            path.write_text(content, encoding="utf-8")
            return path

        def audit(self) -> object:
            return Auditor(str(tmp_path)).run()

    return RepoHelper()


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: no pipeline files at all
# ─────────────────────────────────────────────────────────────────────────────

def test_no_pipeline_files(tmp_path):
    report = Auditor(str(tmp_path)).run()
    assert report.score <= 85          # penalty for missing pipeline
    assert any(f.check_id == "SYS-000" for f in report.findings)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: clean / near-perfect pipeline
# ─────────────────────────────────────────────────────────────────────────────

CLEAN_WORKFLOW = """
name: Clean CI
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    name: Test
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4.1.7
      - run: pytest tests/

  build:
    name: Build
    runs-on: ubuntu-latest
    timeout-minutes: 20
    needs: [test]
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4.1.7
      - run: make build
"""

def test_clean_pipeline_high_score(repo):
    repo.write_workflow("ci.yml", CLEAN_WORKFLOW)
    report = repo.audit()
    # A clean pipeline should score 75+ (some low-severity findings are OK)
    assert report.score >= 75
    # Must have no CRITICAL findings
    assert report.summary["critical"] == 0
    # Must have no HIGH findings
    assert report.summary["high"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: insecure pipeline (mirrors samples/before/)
# ─────────────────────────────────────────────────────────────────────────────

INSECURE_WORKFLOW = """
name: Insecure CI
on:
  push:
    branches: ["*"]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: |
          export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
          aws s3 sync . s3://bucket
  deploy:
    runs-on: ubuntu-latest
    needs: build
    permissions: write-all
    steps:
      - uses: actions/checkout@latest
      - run: ./deploy.sh
"""

def test_insecure_pipeline_low_score(repo):
    repo.write_workflow("ci.yml", INSECURE_WORKFLOW)
    report = repo.audit()
    # Many issues → low score
    assert report.score < 60
    # Must detect secrets
    assert report.summary["critical"] >= 1
    # Must detect unversioned actions
    sec002_findings = [f for f in report.findings if f.check_id == "SEC-002"]
    assert len(sec002_findings) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: multiple workflow files
# ─────────────────────────────────────────────────────────────────────────────

def test_multiple_workflow_files_discovered(repo):
    repo.write_workflow("ci.yml", CLEAN_WORKFLOW)
    repo.write_workflow("release.yml", CLEAN_WORKFLOW.replace("Clean CI", "Release"))
    report = repo.audit()
    assert len(report.audited_files) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: invalid YAML
# ─────────────────────────────────────────────────────────────────────────────

def test_invalid_yaml_produces_finding(repo):
    repo.write_workflow("broken.yml", "key: [\nunclosed bracket")
    report = repo.audit()
    assert any(f.check_id == "SYS-002" for f in report.findings)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: score and grade consistency
# ─────────────────────────────────────────────────────────────────────────────

def test_score_grade_consistency(repo):
    repo.write_workflow("ci.yml", CLEAN_WORKFLOW)
    report = repo.audit()
    score = report.score
    grade = report.grade

    if score >= 90:
        assert grade == "A"
    elif score >= 75:
        assert grade == "B"
    elif score >= 60:
        assert grade == "C"
    elif score >= 40:
        assert grade == "D"
    else:
        assert grade == "F"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: findings are sorted by severity
# ─────────────────────────────────────────────────────────────────────────────

_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

def test_findings_sorted_by_severity(repo):
    repo.write_workflow("ci.yml", INSECURE_WORKFLOW)
    report = repo.audit()
    severities = [_ORDER[f.severity] for f in report.findings]
    assert severities == sorted(severities)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario: HTML report renders without error
# ─────────────────────────────────────────────────────────────────────────────

def test_html_report_renders(repo, tmp_path):
    from cicd_auditor.reporter import render_html
    repo.write_workflow("ci.yml", INSECURE_WORKFLOW)
    report = repo.audit()
    out = str(tmp_path / "report.html")
    render_html(report, out)
    assert os.path.exists(out)
    html = open(out).read()
    assert "CI/CD Audit Report" in html
    assert str(report.score) in html
