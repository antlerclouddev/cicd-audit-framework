"""
checks/timeouts.py
-------------------
EFF-002 · Missing Job Timeout

WHAT IT DOES
    Checks that every job in a GitHub Actions workflow defines a
    `timeout-minutes:` value.

WHY THIS MATTERS
    Without a timeout, a hung test, an infinite loop, or a stalled
    network call can keep a runner occupied for GitHub's hard maximum
    of 6 hours (360 minutes), consuming paid runner minutes and
    blocking other PRs in the queue.

    Setting an explicit timeout ensures:
        • Developers get fast feedback when something hangs
        • Runner costs stay predictable
        • The PR queue doesn't back up due to one bad run

RECOMMENDED VALUES
        Unit-test job    :   10–15 min
        Integration tests:   20–30 min
        Build + package  :   15–30 min
        Full deploy      :   30–60 min

    When in doubt, set timeout-minutes to 2× your median run time.
"""

from typing import Any
from .base import BaseCheck
from ..models import Finding, Severity

# Jobs whose names suggest they are allowed to run long (optional exception list)
_LONG_RUNNING_KEYWORDS = {"deploy", "release", "publish", "migration"}


class TimeoutsCheck(BaseCheck):
    ID          = "EFF-002"
    TITLE       = "Job Missing timeout-minutes"
    DESCRIPTION = (
        "Ensures every CI job defines a timeout so hung runners are "
        "automatically cancelled, protecting compute costs and queue health."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        if "jobs" not in parsed:
            return []

        findings: list[Finding] = []

        for job_key, job in (parsed.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("timeout-minutes") is not None:
                continue  # ✅ Already set

            job_name = str(job.get("name", job_key)).lower()

            # Slightly higher severity for jobs that don't obviously need long windows
            is_long_running = any(kw in job_name or kw in job_key for kw in _LONG_RUNNING_KEYWORDS)
            severity = Severity.MEDIUM if not is_long_running else Severity.LOW

            findings.append(Finding(
                check_id    = self.ID,
                title       = self.TITLE,
                severity    = severity,
                file_path   = file_path,
                line_number = self.line_of(raw_text, job_key + ":"),
                detail      = (
                    f"Job `{job_key}` does not define `timeout-minutes`. "
                    "If this job hangs it will run for up to 6 hours (GitHub's hard limit), "
                    "wasting runner minutes and blocking other pipeline runs."
                ),
                remediation = (
                    f"Add a timeout to job `{job_key}`:\n\n"
                    f"  {job_key}:\n"
                    f"    timeout-minutes: 15   # adjust to ~2× your median run time\n"
                    f"    runs-on: ubuntu-latest\n"
                    f"    steps: ..."
                ),
                evidence = f"jobs.{job_key}  (no timeout-minutes key)",
            ))

        return findings
