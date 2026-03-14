"""
checks/action_versions.py
--------------------------
SEC-002 · Unversioned / Mutable Action References

WHAT IT DOES
    Scans GitHub Actions `uses:` fields to ensure every external action is
    pinned to an immutable reference — either a full SHA-256 commit hash
    (most secure) or a semantically versioned tag like @v3 or @v3.1.2.

    Flags three categories of bad references:
        1. @main / @master / @HEAD   → mutable branch — supply-chain attack risk
        2. No version at all         → defaults to whatever HEAD is
        3. @latest                   → semantic alias, not a real tag

WHY THIS MATTERS (Supply-Chain Attack)
    The SolarWinds and codecov attacks showed that a compromised action can
    exfiltrate secrets, modify build artefacts, or inject malicious code.
    Pinning to a SHA means you get exactly the code you reviewed, forever.

GOOD REFERENCES
    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683   ← SHA pin (best)
    uses: actions/checkout@v4.1.1                                      ← exact semver tag (good)
    uses: actions/checkout@v4                                          ← major-version tag (acceptable)

BAD REFERENCES
    uses: actions/checkout@main      ← mutable branch
    uses: actions/checkout           ← no version
    uses: actions/checkout@latest    ← ambiguous alias
"""

import re
from typing import Any
from .base import BaseCheck
from ..models import Finding, Severity


# Matches a SHA-256 commit hash (40 hex chars)
_SHA_RE   = re.compile(r'^[0-9a-f]{40}$')
# Matches a semver-ish tag:  v3 / v3.1 / v3.1.2
_SEMVER_RE = re.compile(r'^v\d+(\.\d+){0,2}$')
# Mutable refs we explicitly flag
_MUTABLE   = {"main", "master", "HEAD", "latest", "dev", "develop", "trunk"}


def _ref_is_safe(ref: str | None) -> bool:
    if ref is None:
        return False
    return bool(_SHA_RE.match(ref) or _SEMVER_RE.match(ref))


def _walk_steps(parsed: dict) -> list[dict]:
    """Recursively collect all step dicts from a GitHub Actions workflow."""
    steps = []
    jobs = parsed.get("jobs", {}) or {}
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if isinstance(step, dict):
                steps.append(step)
    return steps


class ActionVersionsCheck(BaseCheck):
    ID          = "SEC-002"
    TITLE       = "Unversioned or Mutable Action Reference"
    DESCRIPTION = (
        "Checks that every `uses:` reference in a GitHub Actions workflow is "
        "pinned to an immutable commit SHA or an exact semver tag, preventing "
        "supply-chain attacks via compromised actions."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        # Only applicable to GitHub Actions workflows
        if "jobs" not in parsed:
            return []

        findings: list[Finding] = []

        for step in _walk_steps(parsed):
            uses = step.get("uses")
            if not uses or not isinstance(uses, str):
                continue

            # Skip local actions (./path/to/action) — they're version-controlled inline
            if uses.startswith("./") or uses.startswith("../"):
                continue

            # Parse  owner/repo@ref   or   owner/repo/subdir@ref
            if "@" in uses:
                action, ref = uses.rsplit("@", 1)
            else:
                action, ref = uses, None

            if _ref_is_safe(ref):
                continue   # ✅ Pinned properly

            # Determine which flavour of bad this is
            if ref is None:
                problem   = "no version tag at all"
                severity  = Severity.HIGH
                fix_hint  = f"uses: {action}@v<LATEST_VERSION>  # or pin to a SHA"
            elif ref in _MUTABLE:
                problem   = f"mutable branch reference '@{ref}'"
                severity  = Severity.HIGH
                fix_hint  = (
                    f"uses: {action}@<SHA>  # find the SHA on the action's releases page"
                )
            else:
                problem   = f"non-standard ref '@{ref}'"
                severity  = Severity.MEDIUM
                fix_hint  = f"uses: {action}@v<LATEST_TAG>"

            findings.append(Finding(
                check_id    = self.ID,
                title       = self.TITLE,
                severity    = severity,
                file_path   = file_path,
                line_number = self.line_of(raw_text, uses),
                detail      = (
                    f"Action `{uses}` uses {problem}. If the upstream action is "
                    "compromised or its history is rewritten, your workflow will "
                    "silently execute malicious code."
                ),
                remediation = (
                    f"Pin to an immutable reference. Recommended fix:\n    {fix_hint}\n"
                    "Use a tool like `pinact` or Dependabot to keep pins up-to-date."
                ),
                evidence = uses,
            ))

        return findings
