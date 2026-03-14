"""
checks/permissions.py
----------------------
SEC-003 · Overly Broad Workflow Permissions

WHAT IT DOES
    Examines the `permissions:` block in GitHub Actions workflows.
    Flags two bad patterns:

        1. write-all / write at the top level
           `permissions: write-all` gives every token scope, which is
           almost never needed and violates least-privilege.

        2. No permissions block at all
           Without an explicit `permissions:` key, GitHub grants the
           default permissions defined at the organisation / repo level.
           Best practice is to declare permissions explicitly so the
           intent is clear and auditable.

        3. `contents: write` at any level — allows force-pushing commits.

    Does NOT flag legitimate scoped writes like `packages: write`,
    `id-token: write`, `security-events: write` which are common minimal
    needs for specific job types.

WHY THIS MATTERS
    The principle of least privilege:  a compromised workflow step
    should be able to do as little damage as possible.  Over-privileged
    tokens have been used in attacks to push malicious commits, create
    releases, or exfiltrate data via the GitHub API.

REFERENCE
    https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
"""

from typing import Any
from .base import BaseCheck
from ..models import Finding, Severity


_WRITE_SHORTHAND = {"write-all", "write", "admin"}

_RECOMMENDED_PERMS = (
    "  permissions:\n"
    "    contents: read\n"
    "    # add only the scopes your workflow actually needs, e.g.:\n"
    "    # pull-requests: write   # to post PR comments\n"
    "    # packages: write        # to push to GHCR\n"
    "    # id-token: write        # for OIDC-based cloud auth"
)


def _check_perms_value(perms: Any, context: str) -> str | None:
    """
    Return a problem description if `perms` is genuinely over-privileged, else None.

    Flags:
        - "write-all" / "write" / "admin" string shorthands
        - `contents: write` in any block (allows pushing commits)

    Does NOT flag scoped writes like `packages: write` or `id-token: write`
    which are legitimate minimal-privilege choices for specific job needs.
    """
    if perms is None:
        return None  # handled by the missing-block check

    if isinstance(perms, str):
        if perms.lower() in _WRITE_SHORTHAND:
            return f"`permissions: {perms}` at {context} grants all token scopes"
        return None  # e.g. "read-all" is fine

    if isinstance(perms, dict):
        # Only flag `contents: write` — allows pushing commits, a high-risk scope
        # that is frequently over-granted but rarely needed in CI.
        contents_val = str(perms.get("contents", "")).lower()
        if contents_val in {"write", "admin"}:
            return (
                f"`contents: write` at {context} allows pushing commits and tags. "
                "This should only be set when the job explicitly needs to push code. "
                "Prefer `contents: read`."
            )

    return None


class PermissionsCheck(BaseCheck):
    ID          = "SEC-003"
    TITLE       = "Overly Broad Workflow Permissions"
    DESCRIPTION = (
        "Checks that GitHub Actions workflows follow the principle of least "
        "privilege by declaring minimal, explicit `permissions:` blocks."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        if "jobs" not in parsed:
            return []   # Not a GitHub Actions file

        findings: list[Finding] = []

        # 1. Workflow-level permissions
        top_perms = parsed.get("permissions")

        if top_perms is None:
            findings.append(Finding(
                check_id    = self.ID,
                title       = "Missing Top-Level Permissions Block",
                severity    = Severity.MEDIUM,
                file_path   = file_path,
                line_number = None,
                detail      = (
                    "No `permissions:` block is defined at the workflow level. "
                    "Without explicit permissions, GitHub uses the repository default "
                    "(often `write` to contents), which may be broader than needed."
                ),
                remediation = (
                    "Add a top-level permissions block with the minimum required scopes:\n\n"
                    + _RECOMMENDED_PERMS
                ),
                evidence = None,
            ))
        else:
            problem = _check_perms_value(top_perms, "workflow level")
            if problem:
                findings.append(Finding(
                    check_id    = self.ID,
                    title       = self.TITLE,
                    severity    = Severity.HIGH,
                    file_path   = file_path,
                    line_number = self.line_of(raw_text, "permissions:"),
                    detail      = problem,
                    remediation = (
                        "Replace the broad permission with fine-grained scopes:\n\n"
                        + _RECOMMENDED_PERMS
                    ),
                    evidence = f"permissions: {top_perms}",
                ))

        # 2. Per-job permissions
        for job_key, job in (parsed.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if job_perms is None:
                continue
            problem = _check_perms_value(job_perms, f"job `{job_key}`")
            if problem:
                findings.append(Finding(
                    check_id    = self.ID,
                    title       = self.TITLE,
                    severity    = Severity.HIGH,
                    file_path   = file_path,
                    line_number = self.line_of(raw_text, job_key + ":"),
                    detail      = problem,
                    remediation = (
                        f"Restrict permissions for job `{job_key}` to only what it needs."
                    ),
                    evidence = f"jobs.{job_key}.permissions: {job_perms}",
                ))

        return findings
