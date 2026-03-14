"""
tests/test_action_versions.py
------------------------------
Unit tests for ActionVersionsCheck (SEC-002).
"""

import yaml
import pytest
from cicd_auditor.checks.action_versions import ActionVersionsCheck
from cicd_auditor.models import Severity

check = ActionVersionsCheck()


def run(yaml_text: str):
    parsed = yaml.safe_load(yaml_text) or {}
    return check.run("test.yml", yaml_text, parsed)


class TestSafeRefs:
    def test_sha_pin_is_safe(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
        assert run(yaml_text) == []

    def test_exact_semver_is_safe(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4.1.7
"""
        assert run(yaml_text) == []

    def test_major_version_tag_is_safe(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
"""
        assert run(yaml_text) == []

    def test_local_action_is_skipped(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: ./my-local-action
"""
        assert run(yaml_text) == []

    def test_non_github_actions_file(self):
        """GitLab CI files should be skipped (no 'jobs' key)."""
        yaml_text = """
stages: [build]
build:
  script: echo hello
"""
        assert run(yaml_text) == []


class TestUnsafeRefs:
    def test_main_branch_ref(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@main
"""
        findings = run(yaml_text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].check_id == "SEC-002"

    def test_master_branch_ref(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@master
"""
        findings = run(yaml_text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_latest_ref(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@latest
"""
        findings = run(yaml_text)
        assert len(findings) == 1

    def test_no_version_at_all(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout
"""
        findings = run(yaml_text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_multiple_unversioned_actions(self):
        """Each bad action should produce its own finding."""
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-python@master
      - uses: actions/upload-artifact@latest
"""
        findings = run(yaml_text)
        assert len(findings) == 3

    def test_mixed_good_and_bad(self):
        """Only the bad action should appear in findings."""
        yaml_text = """
jobs:
  build:
    steps:
      - uses: actions/checkout@v4          # good
      - uses: actions/setup-python@main    # bad
      - uses: actions/cache@v4.0.2         # good
"""
        findings = run(yaml_text)
        assert len(findings) == 1
        assert "setup-python" in findings[0].evidence

    def test_evidence_contains_action_ref(self):
        yaml_text = """
jobs:
  build:
    steps:
      - uses: myorg/myaction@dev
"""
        findings = run(yaml_text)
        assert findings
        assert "myorg/myaction@dev" in findings[0].evidence
