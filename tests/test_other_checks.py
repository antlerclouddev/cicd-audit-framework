"""
tests/test_other_checks.py
--------------------------
Tests for TestGatesCheck, PermissionsCheck, and TimeoutsCheck.
"""

import yaml
import pytest
from cicd_auditor.checks.test_gates   import TestGatesCheck
from cicd_auditor.checks.permissions  import PermissionsCheck
from cicd_auditor.checks.timeouts     import TimeoutsCheck
from cicd_auditor.models import Severity


def run_check(check, yaml_text: str):
    parsed = yaml.safe_load(yaml_text) or {}
    return check.run("test.yml", yaml_text, parsed)


# ─────────────────────────────────────────────────────────────────────────────
# TestGatesCheck (EFF-001)
# ─────────────────────────────────────────────────────────────────────────────

class TestTestGatesCheck:
    check = TestGatesCheck()

    def run(self, yaml_text):
        return run_check(self.check, yaml_text)

    def test_pytest_command_detected(self):
        yaml_text = """
jobs:
  test:
    steps:
      - run: pytest tests/
"""
        assert self.run(yaml_text) == []

    def test_jest_command_detected(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: npm test
"""
        assert self.run(yaml_text) == []

    def test_test_job_name_detected(self):
        yaml_text = """
jobs:
  unit-tests:
    steps:
      - run: echo "running tests"
"""
        assert self.run(yaml_text) == []

    def test_go_test_detected(self):
        yaml_text = """
jobs:
  ci:
    steps:
      - run: go test ./...
"""
        assert self.run(yaml_text) == []

    def test_missing_test_gate_flagged(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: pip install -r requirements.txt
  deploy:
    steps:
      - run: ./deploy.sh
"""
        findings = self.run(yaml_text)
        assert len(findings) == 1
        assert findings[0].check_id == "EFF-001"
        assert findings[0].severity == Severity.HIGH

    def test_gitlab_pytest(self):
        yaml_text = """
stages:
  - test
  - deploy

run_tests:
  stage: test
  script:
    - pytest
"""
        assert self.run(yaml_text) == []

    def test_gitlab_no_test(self):
        yaml_text = """
stages:
  - build
  - deploy

build_app:
  stage: build
  script:
    - make build
"""
        findings = self.run(yaml_text)
        assert len(findings) == 1


# ─────────────────────────────────────────────────────────────────────────────
# PermissionsCheck (SEC-003)
# ─────────────────────────────────────────────────────────────────────────────

class TestPermissionsCheck:
    check = PermissionsCheck()

    def run(self, yaml_text):
        return run_check(self.check, yaml_text)

    def test_minimal_permissions_clean(self):
        yaml_text = """
permissions:
  contents: read
jobs:
  build:
    steps:
      - run: echo hello
"""
        assert self.run(yaml_text) == []

    def test_missing_permissions_flagged(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: echo hello
"""
        findings = self.run(yaml_text)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_write_all_flagged(self):
        yaml_text = """
permissions: write-all
jobs:
  build:
    steps:
      - run: echo hello
"""
        findings = self.run(yaml_text)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_job_level_write_all_flagged(self):
        yaml_text = """
permissions:
  contents: read
jobs:
  deploy:
    permissions: write-all
    steps:
      - run: ./deploy.sh
"""
        findings = self.run(yaml_text)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_read_all_is_safe(self):
        yaml_text = """
permissions: read-all
jobs:
  build:
    steps:
      - run: echo hello
"""
        # read-all is acceptable (still a specific value, not write)
        findings = self.run(yaml_text)
        assert not any(f.severity == Severity.HIGH for f in findings)

    def test_non_github_file_skipped(self):
        yaml_text = """
stages: [build]
build:
  script: echo hi
"""
        assert self.run(yaml_text) == []


# ─────────────────────────────────────────────────────────────────────────────
# TimeoutsCheck (EFF-002)
# ─────────────────────────────────────────────────────────────────────────────

class TestTimeoutsCheck:
    check = TimeoutsCheck()

    def run(self, yaml_text):
        return run_check(self.check, yaml_text)

    def test_timeout_present_clean(self):
        yaml_text = """
jobs:
  build:
    timeout-minutes: 15
    steps:
      - run: make build
"""
        assert self.run(yaml_text) == []

    def test_missing_timeout_flagged(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: make build
"""
        findings = self.run(yaml_text)
        assert len(findings) == 1
        assert findings[0].check_id == "EFF-002"

    def test_multiple_jobs_all_missing(self):
        yaml_text = """
jobs:
  build:
    steps:
      - run: make build
  test:
    steps:
      - run: pytest
  deploy:
    steps:
      - run: ./deploy.sh
"""
        findings = self.run(yaml_text)
        assert len(findings) == 3

    def test_partial_timeouts(self):
        """Only the job without timeout should be flagged."""
        yaml_text = """
jobs:
  build:
    timeout-minutes: 20
    steps:
      - run: make build
  test:
    steps:
      - run: pytest
"""
        findings = self.run(yaml_text)
        assert len(findings) == 1
        assert "test" in findings[0].evidence

    def test_non_github_file_skipped(self):
        yaml_text = """
stages: [build]
build:
  script: echo hi
"""
        assert self.run(yaml_text) == []
