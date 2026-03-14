# Complete Beginner Workflow — cicd-audit-framework on Fedora 43

This guide walks you through everything from a fresh Fedora 43 machine to
running your first audit and reading the report. Every command is shown
exactly as you would type it in a terminal.

---

## PHASE 0 — Understanding What You're About to Do

Before touching the keyboard, here is the big picture:

```
Your Fedora 43 machine
│
├── You download the project (the audit tool)
├── You install Python dependencies (PyYAML, Jinja2, Click)
├── You run the tool against a pipeline file
└── The tool writes an HTML report you open in Firefox
```

The audit tool lives in a folder called `cicd-audit-framework`.
It reads `.github/workflows/*.yml` files (GitHub Actions pipelines) and
`.gitlab-ci.yml` files, checks them for problems, and produces a scored
HTML report you can give to a client.

---

## PHASE 1 — Open a Terminal

1. Press the **Super key** (Windows key) to open the Activities overview
2. Type `terminal` and press Enter
3. A black window opens — this is your command prompt

You will see something like:
```
[yourname@fedora ~]$
```

The `~` means you are in your home directory (`/home/yourname`).
Every command below is typed here and confirmed with Enter.

---

## PHASE 2 — Check That Python Is Installed

Fedora 43 ships with Python 3.12. Verify it:

```bash
python3 --version
```

Expected output:
```
Python 3.12.x
```

If you see `command not found`, install it:
```bash
sudo dnf install python3 -y
```

---

## PHASE 3 — Get the Project Files

You have two options. Use Option A (unzip) since you already downloaded
the zip file from this conversation.

### Option A — Unzip the downloaded file (recommended for beginners)

The zip file (`cicd-audit-framework.zip`) was downloaded via this chat.
It is probably in your `~/Downloads` folder.

```bash
# 1. Go to your home directory
cd ~

# 2. Make a folder for your projects
mkdir -p projects
cd projects

# 3. Copy the zip here and unzip it
cp ~/Downloads/cicd-audit-framework.zip .
unzip cicd-audit-framework.zip

# 4. Enter the project folder
cd cicd-audit-framework

# 5. Confirm you are in the right place
ls
```

You should see:
```
cicd_auditor/  pyproject.toml  README.md  run_tests.py  samples/  tests/
```

### Option B — Clone from GitHub (once you push it there)

```bash
cd ~/projects
git clone https://github.com/YOUR_USERNAME/cicd-audit-framework.git
cd cicd-audit-framework
```

---

## PHASE 4 — Create a Virtual Environment

A virtual environment is an isolated Python installation just for this
project. It keeps the project's dependencies separate from the rest of
your system so nothing breaks.

```bash
# Make sure you are inside the project folder first
pwd
# Should print: /home/yourname/projects/cicd-audit-framework

# Create the virtual environment (this makes a .venv folder)
python3 -m venv .venv

# Activate it (you must do this every time you open a new terminal)
source .venv/bin/activate
```

After activation your prompt changes to show `(.venv)`:
```
(.venv) [yourname@fedora cicd-audit-framework]$
```

That `(.venv)` prefix means the virtual environment is active.
All `pip` and `python` commands now use the isolated environment.

**IMPORTANT:** Every time you open a new terminal window and want to work
on this project, you must run `source .venv/bin/activate` again.

---

## PHASE 5 — Install the Project and Its Dependencies

With the virtual environment active, install everything:

```bash
pip install -e ".[dev]"
```

What this does:
- `-e` means "editable install" — changes to the code take effect immediately
- `".[dev]"` installs the project itself PLUS developer tools (pytest, ruff)
- pip reads `pyproject.toml` to know what to install

You will see a lot of output ending with something like:
```
Successfully installed PyYAML-6.0.2 Jinja2-3.1.4 click-8.1.7 cicd-audit-framework-1.0.0 ...
```

Verify the CLI tool is now available:
```bash
cicd-audit --help
```

Expected output:
```
Usage: cicd-audit [OPTIONS] COMMAND [ARGS]...

  ╔═══════════════════════════════════════╗
  ║   CI/CD Pipeline Audit Framework      ║
  ...
```

---

## PHASE 6 — Run the Tests (Verify Everything Works)

Before touching any client repo, confirm the tool itself is healthy:

```bash
# Option A — with pytest (installed in Phase 5)
pytest tests/ -v

# Option B — no-dependency runner (works without pytest)
python3 run_tests.py
```

Expected output (last few lines):
```
Results: 36 passed, 0 failed out of 36 tests
```

If any test fails, something went wrong with the installation.
Check that `(.venv)` is still showing in your prompt.

---

## PHASE 7 — Run Your First Audit (the Sample Pipelines)

The project ships with two sample pipelines:

| Folder | What it is | Expected Score |
|--------|-----------|----------------|
| `samples/before/` | Intentionally broken — hardcoded secrets, no tests, mutable actions | ~0/100 |
| `samples/after/` | Fully remediated secure pipeline | ~97/100 |

### Audit the BEFORE (broken) pipeline

```bash
cicd-audit run samples/before --output report-before.html
```

You will see terminal output like:
```
  🔍  CI/CD Audit Framework
  📁  Scanning: /home/yourname/projects/cicd-audit-framework/samples/before

  Score: 0/100   Grade: F – Critical Risk
  Findings: 11 total (2 critical · 5 high · 3 medium · 1 low)

  [SEC-001] Hardcoded Secret Detected
  ...
  📄  Report written → report-before.html
```

### Open the HTML report in Firefox

```bash
xdg-open report-before.html
```

You will see a dark-mode report with:
- A circular score gauge (0/100, red)
- Severity pills (2 CRITICAL, 5 HIGH, etc.)
- Expandable finding cards — click any row to see the full detail and fix

### Audit the AFTER (secure) pipeline

```bash
cicd-audit run samples/after --output report-after.html
xdg-open report-after.html
```

Expected: 97/100, Grade A, zero critical or high findings.

---

## PHASE 8 — Audit a Real Client Repo

This is the actual use case. The client gives you read access to their repo.

### Step 1 — Clone the client's repo

```bash
# Go to a safe working area
cd ~/projects

# Clone their repo (replace with real URL)
git clone https://github.com/client-company/their-repo.git

# Enter the repo
cd their-repo
```

### Step 2 — Run the audit

```bash
# Go back to your tool's directory
cd ~/projects/cicd-audit-framework

# Activate venv if not already active
source .venv/bin/activate

# Run the audit against the client's repo
# Replace the path with wherever you cloned their repo
cicd-audit run ~/projects/their-repo --output ~/Desktop/client-audit-$(date +%Y%m%d).html
```

Breaking down that last command:
- `cicd-audit run` — the command
- `~/projects/their-repo` — where their code is
- `--output ~/Desktop/client-audit-20250314.html` — save the report to your Desktop with today's date

### Step 3 — Also generate a JSON file (useful for notes)

```bash
cicd-audit run ~/projects/their-repo \
  --output ~/Desktop/client-audit.html \
  --json
```

This writes both `client-audit.html` AND `client-audit.json`.
The JSON is a machine-readable version — useful if you want to paste
findings into a spreadsheet or email.

### Step 4 — Open and review the report before sending

```bash
xdg-open ~/Desktop/client-audit.html
```

Read every finding. Click each card to expand the full detail and remediation.
Delete or note any false positives (rare, but possible).

### Step 5 — Deliver the report

The HTML file is completely self-contained. You can:
- Email it as an attachment
- Upload it to a shared Google Drive folder
- Host it on any simple web server

The client opens it in any browser — no server, no login, no account needed.

---

## PHASE 9 — Fix the Issues and Re-Audit (Optional "Full Service")

After delivering the initial report, you can fix the pipeline and show
the before/after improvement as proof of work.

```bash
# You already have the client repo cloned
cd ~/projects/their-repo

# Make fixes (edit the workflow files)
# For example, replace @main with @v4 in a workflow
nano .github/workflows/ci.yml    # or use VS Code: code .

# Re-run the audit to confirm score improved
cd ~/projects/cicd-audit-framework
cicd-audit run ~/projects/their-repo --output ~/Desktop/client-audit-FIXED.html
xdg-open ~/Desktop/client-audit-FIXED.html
```

---

## PHASE 10 — Set Up the Self-Auditing GitHub Action (Optional)

This makes the tool run itself on every pull request to your own
`cicd-audit-framework` repository, so you always know the tool's
own pipeline is healthy.

```bash
# 1. Initialise git in the project (if not done)
cd ~/projects/cicd-audit-framework
git init
git add .
git commit -m "Initial commit"

# 2. Create a repo on GitHub (go to github.com → New repository)
#    Name it: cicd-audit-framework
#    Leave it empty (no README, no .gitignore)

# 3. Push your code
git remote add origin https://github.com/YOUR_USERNAME/cicd-audit-framework.git
git branch -M main
git push -u origin main
```

GitHub will automatically find `.github/workflows/audit.yml` and run it
on every push. Go to `github.com/YOUR_USERNAME/cicd-audit-framework/actions`
to watch it run. The HTML report will be available as a downloadable
artifact after each run.

---

## Daily Workflow Cheatsheet

Once everything is set up, your daily routine for auditing a client is:

```bash
# 1. Open terminal
# 2. Navigate to the tool
cd ~/projects/cicd-audit-framework

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Clone client repo (first time only)
git clone https://github.com/client/repo.git ~/projects/client-repo

# 5. Run audit
cicd-audit run ~/projects/client-repo --output ~/Desktop/client-report.html --json

# 6. Open report
xdg-open ~/Desktop/client-report.html

# 7. When done, deactivate venv (optional)
deactivate
```

---

## Troubleshooting

### "command not found: cicd-audit"
The virtual environment is not active. Run:
```bash
source .venv/bin/activate
```

### "No pipeline files found" in the report
The client's repo uses a different location or filename. Check:
```bash
ls ~/projects/their-repo/.github/workflows/
ls ~/projects/their-repo/.gitlab-ci.yml
```

### pip install fails with network errors
You are behind a proxy or have no internet. Try:
```bash
pip install --no-index --find-links /path/to/local/wheels -e ".[dev]"
```
Or contact your network admin.

### "Permission denied" when running a command
You probably forgot `sudo` for a system-level install, or you are
trying to write to a directory you don't own. Keep all your work
inside `~/projects/` to avoid this.

### The virtual environment is not showing `(.venv)` in my prompt
Activate it again:
```bash
source ~/projects/cicd-audit-framework/.venv/bin/activate
```

### I closed the terminal — how do I get back to work?
```bash
cd ~/projects/cicd-audit-framework
source .venv/bin/activate
# You're back. Carry on from wherever you left off.
```

---

## Glossary

| Term | What it means |
|------|---------------|
| Terminal | The black text window where you type commands |
| `~` | Your home directory, e.g. `/home/yourname` |
| Virtual environment (venv) | An isolated Python installation for one project |
| `source .venv/bin/activate` | Turns the venv on for the current terminal session |
| `pip install` | Downloads and installs a Python package |
| `cicd-audit run` | The main command that runs the audit |
| HTML report | The self-contained webpage with your audit results |
| Finding | One specific problem the tool detected |
| Severity | How bad the problem is: CRITICAL → HIGH → MEDIUM → LOW |
| Score | 0–100, starts at 100, each finding deducts points |
| Grade | A/B/C/D/F derived from the score |
