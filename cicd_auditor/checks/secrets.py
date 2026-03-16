"""
checks/secrets.py
-----------------
SEC-001 · Hardcoded Secret Detection

WHAT IT DOES
    Scans every line of the pipeline file for patterns that look like
    hardcoded credentials — API keys, tokens, passwords, connection strings.
    It uses a curated list of regex patterns similar to what tools like
    Gitleaks and TruffleHog use, tuned for CI/CD files.

WHY THIS MATTERS
    A hardcoded secret in a workflow file is immediately available to anyone
    who can read the repo (even in private repos if they have read access).
    Secrets should always live in GitHub/GitLab secret stores and be
    referenced via ${{ secrets.MY_SECRET }} or $MY_VAR.

FALSE POSITIVE HANDLING
    We skip lines that already reference the secrets store:
        ${{ secrets.* }}   — GitHub Actions
        $CI_*              — GitLab CI built-in variables
        ${VAR}             — Shell variable reference
    We also skip YAML comments (#) and template placeholder patterns
    like <YOUR_KEY_HERE>.

EVIDENCE REDACTION
    We never emit the actual secret value in a Finding.  Instead we show
    the key name and a redacted value, e.g.:
        API_KEY=sk-ant-**REDACTED**
"""

import re
from typing import Any

from ..models import Finding, Severity
from .base import BaseCheck

# ---------------------------------------------------------------------------
# Pattern registry
# Each entry: (label, compiled_regex)
# The regex should match the *value*, not just the key name, to reduce FPs.
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Generic high-entropy assignments  (key=value where value looks like a token)
    ("Generic API key assignment",
     re.compile(
         r'(?i)(api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key|auth[_\-]?token'
         r'|private[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9+/\-_]{20,})["\']?'
     )),

    # AWS Access Key ID
    ("AWS Access Key ID",
     re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])')),

    # AWS Secret Access Key (40 chars, base62)
    ("AWS Secret Access Key",
     re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?')),

    # GitHub Personal Access Token (classic ghp_ and fine-grained github_pat_)
    ("GitHub Personal Access Token",
     re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})')),

    # Slack bot/app tokens  (xoxb-..., xoxp-..., xoxa-..., etc.)
    ("Slack Token",
     re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),

    # Slack Incoming Webhook URLs
    ("Slack Webhook URL",
     re.compile(r'hooks\.[a-z]+\.com/services/[A-Z0-9]{6,12}/[A-Z0-9]{6,12}/[A-Za-z0-9]{20,}')),

    # Generic password field
    ("Hardcoded password",
     re.compile(
         r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?(?!(\$\{|\$\{\{|<|your|example|changeme|placeholder|dummy|test|xxx))[A-Za-z0-9!@#$%^&*()_+\-=]{8,}["\']?'
     )),

    # Database connection strings with embedded creds
    ("Database connection string with credentials",
     re.compile(
         r'(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@\s]{6,}@'
     )),

    # Generic Bearer / Authorization header value
    ("Hardcoded Bearer token",
     re.compile(r'(?i)(authorization|bearer)\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]+=*["\']?')),
]

# Lines that are definitely safe references (check the whole line)
_SAFE_ALWAYS = [
    re.compile(r'\$\{\{\s*secrets\.',   re.IGNORECASE),   # GitHub secrets store
    re.compile(r'\$[A-Z_]{2,}'),                          # Shell env-var reference
    re.compile(r'<[A-Z_\-]+>'),                           # Placeholder <MY_KEY>
    re.compile(r'^\s*#'),                                  # YAML comment line
]

# Words in the VALUE part (after : or =) that indicate a placeholder
# We only check the VALUE, not the key name, to avoid matching "AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE"
# where "EXAMPLE" is part of the actual fake key we want to catch.
_PLACEHOLDER_VALUE_RE = re.compile(
    r'[:=]\s*["\']?(?:your[_\-]|<|changeme|placeholder|dummy|fake_|insert_)',
    re.IGNORECASE,
)


def _is_safe_line(line: str) -> bool:
    if any(p.search(line) for p in _SAFE_ALWAYS):
        return True
    return bool(_PLACEHOLDER_VALUE_RE.search(line))


def _redact(value: str) -> str:
    """Keep first 4 chars of a matched value for debugging, mask the rest."""
    if len(value) <= 4:
        return "**REDACTED**"
    return value[:4] + "**REDACTED**"


class SecretsCheck(BaseCheck):
    ID          = "SEC-001"
    TITLE       = "Hardcoded Secret Detected"
    DESCRIPTION = (
        "Scans pipeline files for hardcoded credentials, API keys, and tokens "
        "that should instead be stored in the secret manager."
    )

    def run(self, file_path: str, raw_text: str, parsed: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        lines = raw_text.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if _is_safe_line(line):
                continue

            for label, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue

                # Grab the last capture group as the "value" to redact
                value = match.group(match.lastindex) if match.lastindex else match.group(0)
                redacted_line = line.replace(value, _redact(value)).strip()

                findings.append(Finding(
                    check_id    = self.ID,
                    title       = self.TITLE,
                    severity    = Severity.CRITICAL,
                    file_path   = file_path,
                    line_number = lineno,
                    detail      = (
                        f"Possible {label} found on line {lineno}. "
                        "Embedding secrets directly in workflow files exposes them to anyone "
                        "with read access to the repository, including forks."
                    ),
                    remediation = (
                        "Move the value to GitHub Settings → Secrets and variables → Actions "
                        "(or GitLab CI/CD → Variables) and reference it as "
                        "${{ secrets.MY_SECRET }} in your workflow."
                    ),
                    evidence = redacted_line,
                ))
                break  # one finding per line is enough

        return findings
