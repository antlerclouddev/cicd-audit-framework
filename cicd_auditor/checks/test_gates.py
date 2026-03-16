"""
checks/test_gates.py
---------------------
EFF-001 · Missing Test Gate in Pipeline

WHAT IT DOES
    Checks whether the pipeline has at least one job or step that runs
    automated tests.  It uses a two-phase heuristic:

        Phase 1 — Job-name scan
            Looks for jobs whose `name` or key contains words like
            "test", "spec", "lint", "check", "quality", "verify".

        Phase 2 — Command scan
            Walks every `run:` block and looks for common test runner
            invocations: pytest, jest, go test, cargo test, npm test,
            mvn test, gradle test, etc.

WHY THIS MATTERS
    A CI pipeline without tests is just a build pipeline — it gives you
    a green checkmark with zero quality signal.  Deploying from an
    untested pipeline is a leading cause of production incidents.

WHAT COUNTS AS A TEST GATE
    ✅  A job named "test", "unit-tests", "run-specs"
    ✅  A step that runs `pytest`, `jest`, `go test ./...`, `npm test`
    ✅  A job named "lint" (catches basic correctness issues)
    ✅  A job that uses a test-runner action like `actions/setup-python`
        followed by a `pytest` run step

WHAT DOES NOT COUNT
    ❌  A build step that happens to run `echo "tests pass"`
    ❌  A security scan step (those are separate concerns)
"""

import re
from typing import Any

from ..models import Finding, Severity
from .base import BaseCheck

_TEST_JOB_KEYWORDS = re.compile(
    r'\b(test|spec|lint|check|quality|verify|validation|coverage|unit|integration|e2e|qa)\b',
    re.IGNORECASE,
)

_TEST_COMMANDS = re.compile(
    r'\b('
    r'pytest|py\.test|unittest|nose2|tox'           # Python
    r'|jest|mocha|jasmine|vitest|cypress|playwright' # JS/TS
    r'|go\s+test'                                    # Go
    r'|cargo\s+test'                                 # Rust
    r'|mvn\s+(test|verify)'                          # Maven
    r'|gradle\s+(test|check)'                        # Gradle
    r'|dotnet\s+test'                                # .NET
    r'|rspec|ruby\s+.*spec'                          # Ruby
    r'|phpunit'                                      # PHP
    r'|npm\s+(test|run\s+test)'                      # npm
    r'|yarn\s+(test|run\s+test)'                     # yarn
    r'|pnpm\s+(test|run\s+test)'                     # pnpm
    r'|bun\s+test'                                   # Bun
    r')\b',
    re.IGNORECASE,
)


def _has_test_gate_github(parsed: dict) -> bool:
    """Return True if the GitHub Actions workflow has a recognisable test gate."""
    jobs = parsed.get("jobs", {}) or {}
    for job_key, job in jobs.items():
        if not isinstance(job, dict):
            continue
        # Check the job key and its optional name field
        job_name = job.get("name", job_key)
        if _TEST_JOB_KEYWORDS.search(str(job_name)) or _TEST_JOB_KEYWORDS.search(job_key):
            return True

        # Check every run: command in the job's steps
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run_cmd = step.get("run", "")
            if run_cmd and _TEST_COMMANDS.search(str(run_cmd)):
                return True

    return False


def _has_test_gate_gitlab(parsed: dict) -> bool:
    """Return True if the GitLab CI config has a recognisable test gate."""
    for key, value in parsed.items():
        if key.startswith(".") or not isinstance(value, dict):
            continue  # skip hidden/anchor jobs and non-job keys
        # Job key itself
        if _TEST_JOB_KEYWORDS.search(key):
            return True
        # stage: field
        stage = value.get("stage", "")
        if stage and _TEST_JOB_KEYWORDS.search(str(stage)):
            return True
        # script: lines
        for cmd in value.get("script", []) or []:
            if _TEST_COMMANDS.search(str(cmd)):
                return True

    return False


class TestGatesCheck(BaseCheck):
    ID          = "EFF-001"
    TITLE       = "No Test Gate Found in Pipeline"
    DESCRIPTION = (
        "Verifies that at least one pipeline job or step executes an automated "
        "test suite, ensuring code quality signals before merging or deploying."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        # Determine pipeline type
        is_github = "jobs" in parsed
        is_gitlab = "stages" in parsed or any(
            isinstance(v, dict) and "script" in v for v in parsed.values()
        )

        if is_github:
            has_tests = _has_test_gate_github(parsed)
        elif is_gitlab:
            has_tests = _has_test_gate_gitlab(parsed)
        else:
            return []  # Unknown format — skip

        if has_tests:
            return []

        return [Finding(
            check_id    = self.ID,
            title       = self.TITLE,
            severity    = Severity.HIGH,
            file_path   = file_path,
            line_number = None,
            detail      = (
                "No automated test job or test-runner command was detected in this pipeline. "
                "Without a test gate, code defects can merge undetected and be deployed "
                "directly to production."
            ),
            remediation = (
                "Add a dedicated test job.  Minimal example for GitHub Actions:\n\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: pip install -r requirements.txt && pytest\n\n"
                "Ensure downstream jobs use `needs: [test]` so deployment is gated."
            ),
            evidence = None,
        )]
