"""
tests/test_secrets.py
---------------------
Unit tests for the SecretsCheck (SEC-001).

TESTING PHILOSOPHY
    Each test is a small, isolated scenario that proves ONE behaviour.
    We test both the happy path (no findings on safe files) and all
    the bad patterns we claim to detect.

    We never test against live repos — all inputs are inline strings
    so tests run instantly and offline.
"""

import pytest
from cicd_auditor.checks.secrets import SecretsCheck
from cicd_auditor.models import Severity

check = SecretsCheck()


def run(yaml_text: str):
    """Helper: parse YAML inline and run the check."""
    import yaml
    parsed = yaml.safe_load(yaml_text) or {}
    return check.run("test.yml", yaml_text, parsed)


# ─────────────────────────────────────────────────────────────────────────────
# Clean files — must produce ZERO findings
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanFiles:
    def test_secrets_from_store_github(self):
        """Referencing ${{ secrets.X }} should never trigger."""
        yaml_text = """
jobs:
  deploy:
    steps:
      - name: Configure AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: aws s3 sync . s3://bucket
"""
        assert run(yaml_text) == []

    def test_shell_env_var_reference(self):
        """$VAR shell references should not trigger."""
        yaml_text = """
jobs:
  build:
    steps:
      - run: echo "token is $API_TOKEN"
"""
        assert run(yaml_text) == []

    def test_placeholder_values(self):
        """Placeholder values like <YOUR_KEY> should be ignored."""
        yaml_text = """
jobs:
  build:
    steps:
      - run: |
          export API_KEY=<YOUR_API_KEY_HERE>
          export PASSWORD=changeme
"""
        assert run(yaml_text) == []

    def test_empty_workflow(self):
        yaml_text = "name: Empty\non:\n  push:\n    branches: [main]\n"
        assert run(yaml_text) == []


# ─────────────────────────────────────────────────────────────────────────────
# Dirty files — must produce findings
# ─────────────────────────────────────────────────────────────────────────────

class TestDirtyFiles:
    def test_aws_access_key_id(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: |
          export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
          aws s3 ls
"""
        findings = run(yaml_text)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].check_id == "SEC-001"

    def test_hardcoded_password(self):
        yaml_text = """
jobs:
  db:
    steps:
      - run: psql -U admin -p SuperSecret123 mydb
        env:
          DB_PASSWORD: SuperSecret123
"""
        findings = run(yaml_text)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_slack_webhook(self):
        yaml_text = """
jobs:
  notify:
    steps:
      - run: |
          curl -X POST https://hooks.example.com/services/TXXXXXXXXX/BXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX
"""
        findings = run(yaml_text)
        assert len(findings) >= 1

    def test_github_pat(self):
        yaml_text = """
jobs:
  release:
    steps:
      - run: gh release create v1.0
        env:
          GH_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz1234567890
"""
        findings = run(yaml_text)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_database_connection_string(self):
        yaml_text = """
jobs:
  migrate:
    steps:
      - run: |
          python manage.py migrate
        env:
          DATABASE_URL: postgres://admin:s3cr3tpassword@db.example.com:5432/prod
"""
        findings = run(yaml_text)
        assert len(findings) >= 1

    def test_evidence_is_redacted(self):
        """The Finding.evidence must NOT contain the full secret value."""
        yaml_text = """
jobs:
  build:
    steps:
      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
"""
        findings = run(yaml_text)
        assert findings
        # The full key should not appear in evidence
        for f in findings:
            if f.evidence:
                assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence

    def test_line_number_populated(self):
        """line_number should be set when a secret is found."""
        yaml_text = (
            "name: test\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        findings = run(yaml_text)
        assert findings
        # The finding should know roughly which line it's on
        line_numbers = [f.line_number for f in findings if f.line_number]
        assert line_numbers  # at least one finding has a line number
