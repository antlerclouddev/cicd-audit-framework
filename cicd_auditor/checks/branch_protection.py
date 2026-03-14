"""
checks/branch_protection.py
----------------------------
SEC-004 · Missing Branch Protection Signals

WHAT IT DOES
    Inspects the workflow's `on:` trigger configuration to detect patterns
    that suggest branch protections are NOT being enforced at the pipeline level.

    Specifically, it flags:

        1. Workflows that run on `push` to main/master without a required
           status check — meaning code can land in the default branch without
           CI passing.

        2. Pull-request workflows that run with `pull_request_target` without
           an explicit allowlist of safe conditions. `pull_request_target` runs
           in the context of the BASE branch (with secrets), so an untrusted
           fork PR can exfiltrate secrets if the workflow isn't carefully guarded.

        3. Workflows with no PR trigger at all — suggesting every push goes
           directly to the default branch with no review gate.

NOTE ON SCOPE
    Full branch protection (require PR, require reviews, require status checks)
    is configured in GitHub Settings, not in workflow files.  This check can
    only observe what the workflow DOES, not what GitHub ENFORCES.  It will
    report a warning and link to the docs for the Settings configuration.

WHY THIS MATTERS
    Without branch protections:
        • Developers can force-push over main and destroy history
        • Broken code can land without CI passing
        • `pull_request_target` bugs have led to secret exfiltration in OSS projects
"""

from typing import Any
from .base import BaseCheck
from ..models import Finding, Severity


_DEFAULT_BRANCHES = {"main", "master", "trunk", "develop", "production"}


class BranchProtectionCheck(BaseCheck):
    ID          = "SEC-004"
    TITLE       = "Branch Protection Signal Missing"
    DESCRIPTION = (
        "Analyses workflow triggers to detect missing branch-protection patterns "
        "such as unguarded pull_request_target usage or no PR trigger on the default branch."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        on_block = parsed.get("on") or parsed.get(True)  # YAML parses `on` as True
        if not on_block or "jobs" not in parsed:
            return []

        findings: list[Finding] = []

        # ── 1. pull_request_target without explicit safety checks ──────────
        if "pull_request_target" in (on_block or {}):
            prt = on_block.get("pull_request_target") or {}
            # Dangerous if env or secrets are used without a caller check
            findings.append(Finding(
                check_id    = self.ID,
                title       = "Dangerous pull_request_target Trigger",
                severity    = Severity.HIGH,
                file_path   = file_path,
                line_number = self.line_of(raw_text, "pull_request_target"),
                detail      = (
                    "`pull_request_target` executes in the context of the BASE branch "
                    "and has access to secrets, even for PRs from untrusted forks. "
                    "If the workflow checks out or executes any code from the PR branch, "
                    "an attacker can exfiltrate all repository secrets."
                ),
                remediation = (
                    "Prefer the safer `pull_request` trigger unless you specifically need "
                    "write permissions from a fork PR.  If you must use "
                    "`pull_request_target`, ensure you NEVER check out the PR head code "
                    "and that you validate the actor with an if: condition, e.g.:\n\n"
                    "  if: github.event.pull_request.head.repo.full_name == github.repository"
                ),
                evidence = "on: pull_request_target",
            ))

        # ── 2. No pull_request trigger  ────────────────────────────────────
        pr_triggers = {"pull_request", "pull_request_target", "pull_request_review"}
        if not any(t in (on_block or {}) for t in pr_triggers):
            findings.append(Finding(
                check_id    = self.ID,
                title       = "No Pull-Request Trigger Defined",
                severity    = Severity.MEDIUM,
                file_path   = file_path,
                line_number = None,
                detail      = (
                    "This workflow has no `pull_request` trigger.  Without CI running on PRs, "
                    "there is no automated quality gate before code is merged into the "
                    "default branch."
                ),
                remediation = (
                    "Add a pull_request trigger so CI runs on every proposed change:\n\n"
                    "  on:\n"
                    "    pull_request:\n"
                    "      branches: [main]\n"
                    "    push:\n"
                    "      branches: [main]"
                ),
                evidence = None,
            ))

        # ── 3. Advisory: remind about Settings-level branch protection ─────
        push_block = (on_block or {}).get("push") or {}
        pushed_branches = push_block.get("branches", []) if isinstance(push_block, dict) else []
        if any(b in _DEFAULT_BRANCHES for b in (pushed_branches or [])):
            findings.append(Finding(
                check_id    = self.ID,
                title       = "Verify Repository Branch Protection Rules",
                severity    = Severity.LOW,
                file_path   = file_path,
                line_number = self.line_of(raw_text, "push:"),
                detail      = (
                    "This workflow runs on pushes to the default branch.  Ensure that "
                    "GitHub repository Settings → Branches → Branch protection rules "
                    "require: (a) PRs before merging, (b) passing status checks, and "
                    "(c) no force-pushes."
                ),
                remediation = (
                    "Navigate to: Settings → Branches → Add rule → select your default branch.\n"
                    "Enable: ✅ Require a pull request  ✅ Require status checks  "
                    "✅ Require branches to be up to date  ✅ Restrict force pushes"
                ),
                evidence = f"push branches: {pushed_branches}",
            ))

        return findings
