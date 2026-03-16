# cicd-audit-framework

**Automated security and efficiency auditor for GitHub Actions and GitLab CI pipelines.**

Run it against a client's repo, hand them the scored HTML report, fix the issues, profit.

```
Score: 12/100  Grade: F – Critical Risk
Issues: 11 total (2 critical · 5 high · 3 medium · 1 low)

  [CRITICAL] SEC-001 - Hardcoded Secret Detected
             AWS_ACCESS_KEY_ID: AKIA**REDACTED**  · line 39
  [HIGH    ] SEC-002 - Unversioned or Mutable Action Reference
             actions/checkout@main
  [HIGH    ] EFF-001 - No Test Gate Found in Pipeline
  ...
```

---

## What It Detects

| Check ID | Category | What It Flags | Severity |
|----------|----------|---------------|----------|
| SEC-001 | Security | Hardcoded secrets, API keys, tokens, passwords | CRITICAL |
| SEC-002 | Security | Unversioned / mutable action refs (`@main`, `@latest`, no tag) | HIGH |
| SEC-003 | Security | Missing or over-broad `permissions:` block (`write-all`) | HIGH/MEDIUM |
| SEC-004 | Security | No PR trigger, dangerous `pull_request_target` usage | HIGH/MEDIUM |
| EFF-001 | Efficiency | No test gate (no pytest/jest/go test/etc. in any job) | HIGH |
| EFF-002 | Efficiency | Jobs with no `timeout-minutes` (can run for 6 hours) | MEDIUM |

**Scoring:** Start at 100. Each finding deducts points by severity (CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3). Score is floored at 0.

---

## Quickstart (Fedora 43)

### 1. Prerequisites

```bash
# Python 3.11+ is required (Fedora 43 ships 3.12)
python3 --version          # should print 3.11 or higher

# Git (to clone the repo)
sudo dnf install git -y
```

### 2. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/cicd-audit-framework.git
cd cicd-audit-framework
```

### 3. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # activates the venv (do this every session)
```

### 4. Install the package

```bash
# Install in editable mode with all dev tools
pip install -e ".[dev]"

# Verify the CLI is available
cicd-audit --help
```

### 5. Run your first audit

```bash
# Audit a repo in the current directory
cicd-audit run .

# Audit a specific repo
cicd-audit run /path/to/client-repo

# Audit with a custom output path
cicd-audit run /path/to/repo --output ~/reports/client-report.html

# Also produce a JSON summary alongside the HTML
cicd-audit run . --output report.html --json

# Block CI if score drops below 80 (useful in GitHub Actions)
cicd-audit run . --fail-below 80

# Show only HIGH and above in the terminal (still writes all to HTML)
cicd-audit run . --min-severity HIGH
```

### 6. View the report

```bash
# Open in Firefox (Fedora default)
xdg-open audit-report-*.html

# Or serve it locally
python3 -m http.server 8080
# then open http://localhost:8080/audit-report-*.html
```

---

## Try the Sample Pipelines

The repo ships with an intentionally broken "before" pipeline and a fixed "after" pipeline:

```bash
# Insecure pipeline — should score near 0
cicd-audit run samples/before --output before-report.html
xdg-open before-report.html

# Secure pipeline — should score 90+
cicd-audit run samples/after --output after-report.html
xdg-open after-report.html
```

The delta between these two reports is your client deliverable: "here's where you were, here's where you are now."

---

## Running the Tests

```bash
# With pytest (installed via pip install -e ".[dev]")
pytest tests/ -v

# Without pytest (built-in runner, no dependencies)
python3 run_tests.py
```

Expected output:
```
── Secrets (SEC-001) ──────────────────────────────────────────────────
  ✅  secrets: GitHub secrets store ref is safe
  ✅  secrets: AWS access key ID detected
  ...
Results: 36 passed, 0 failed out of 36 tests
```

---

## Project Structure

```
cicd-audit-framework/
│
├── cicd_auditor/                   # Main Python package
│   ├── __init__.py                 # Public API: Auditor, render_html
│   ├── models.py                   # Data classes: Finding, AuditReport, Severity
│   ├── auditor.py                  # Orchestrator: discovers files, runs all checks
│   ├── cli.py                      # Click CLI entry point (`cicd-audit` command)
│   │
│   ├── checks/                     # One file per check — easy to extend
│   │   ├── __init__.py             # ALL_CHECKS registry
│   │   ├── base.py                 # BaseCheck abstract class
│   │   ├── secrets.py              # SEC-001: hardcoded secrets
│   │   ├── action_versions.py      # SEC-002: unversioned actions
│   │   ├── permissions.py          # SEC-003: over-broad permissions
│   │   ├── branch_protection.py    # SEC-004: branch protection signals
│   │   ├── test_gates.py           # EFF-001: no test job
│   │   └── timeouts.py             # EFF-002: missing timeout
│   │
│   └── reporter/
│       ├── __init__.py
│       ├── html_reporter.py        # Jinja2 HTML report renderer
│       └── templates/
│           └── report.html.j2      # Dark-mode HTML report template
│
├── tests/                          # pytest test suite
│   ├── conftest.py
│   ├── test_secrets.py
│   ├── test_action_versions.py
│   ├── test_other_checks.py
│   └── test_auditor_integration.py
│
├── samples/
│   ├── before/                     # ❌ Intentionally insecure pipeline
│   │   └── .github/workflows/ci.yml
│   └── after/                      # ✅ Remediated secure pipeline
│       └── .github/workflows/ci.yml
│
├── .github/
│   └── workflows/
│       └── audit.yml               # Self-auditing GitHub Action (runs on every PR)
│
├── run_tests.py                    # Dependency-free test runner
└── pyproject.toml                  # Modern Python packaging config
```

---

## Extending the Framework

Adding a new check takes about 15 minutes:

### Step 1 — Create the check file

```python
# cicd_auditor/checks/my_new_check.py
from .base import BaseCheck
from ..models import Finding, Severity

class MyNewCheck(BaseCheck):
    ID          = "SEC-005"
    TITLE       = "My New Check"
    DESCRIPTION = "Describes what this check looks for."

    def run(self, file_path, raw_text, parsed):
        findings = []
        # ... your detection logic ...
        if something_is_wrong:
            findings.append(Finding(
                check_id    = self.ID,
                title       = self.TITLE,
                severity    = Severity.HIGH,
                file_path   = file_path,
                line_number = self.line_of(raw_text, "some snippet"),
                detail      = "What is wrong and why it matters.",
                remediation = "Concrete steps to fix it.",
                evidence    = "The offending snippet (redact secrets!).",
            ))
        return findings
```

### Step 2 — Register the check

```python
# cicd_auditor/checks/__init__.py
from .my_new_check import MyNewCheck

ALL_CHECKS = [
    ...
    MyNewCheck(),   # add here
]
```

That's it. The orchestrator picks it up automatically.

---

## GitHub Action (Self-Audit)

The included `.github/workflows/audit.yml` runs the auditor against this repo on every PR. It:

- Installs `cicd-audit-framework` from source
- Runs the audit with `--fail-below 70` (blocks merges if the score regresses)
- Uploads the HTML + JSON report as a workflow artifact (downloadable from the Actions tab)
- Prints a score summary to the job logs

Copy this workflow into any client repo to give them ongoing audit monitoring.

---

## Python API

You can use the framework programmatically — useful for building dashboards or integrating with Slack/Jira:

```python
from cicd_auditor import Auditor, render_html

# Run audit
report = Auditor("/path/to/repo").run()

# Inspect results
print(f"Score: {report.score}/100  Grade: {report.grade}")
print(f"Critical findings: {report.summary['critical']}")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.check_id}: {finding.title}")
    print(f"  File: {finding.file_path}:{finding.line_number}")
    print(f"  Fix:  {finding.remediation}\n")

# Generate HTML report
render_html(report, "output/report.html")

# Exit with non-zero if score is too low (for CI integration)
import sys
if report.score < 70:
    sys.exit(1)
```

---

## Configuration Reference

```
cicd-audit run [OPTIONS] [REPO_PATH]

Arguments:
  REPO_PATH   Path to the local git repository to audit. Defaults to '.'

Options:
  -o, --output PATH         Output path for the HTML report.
                            Default: ./audit-report-<timestamp>.html
  -s, --min-severity LEVEL  Only print findings at/above this level in the
                            terminal. [CRITICAL|HIGH|MEDIUM|LOW]  Default: LOW
  -f, --fail-below INT      Exit code 1 if score drops below this threshold.
                            Range: 0–100. Useful for CI pipeline gates.
  --json                    Write a machine-readable JSON file alongside HTML.
  --no-report               Skip HTML output (terminal summary only).
  --help                    Show this message and exit.

cicd-audit version          Print version and exit.
```

---

## Roadmap

- [ ] `--format sarif` output for GitHub Code Scanning integration
- [ ] GitLab CI: `include:` and `extends:` chain analysis
- [ ] Check for missing Dependabot config (`.github/dependabot.yml`)
- [ ] Check for CODEOWNERS file
- [ ] Runner pinning check (self-hosted vs GitHub-hosted)
- [ ] `cicd-audit fix` command — apply auto-remediations where safe
- [ ] Web dashboard mode (`cicd-audit serve`)

---

## License

MIT — use it, sell services with it, extend it.
