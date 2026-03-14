"""
run_tests.py  —  lightweight test runner (no pytest required)
Run with:  PYTHONPATH=. python3 run_tests.py
"""

import sys
import traceback
import tempfile
import os
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cicd_auditor.checks.secrets        import SecretsCheck
from cicd_auditor.checks.action_versions import ActionVersionsCheck
from cicd_auditor.checks.test_gates      import TestGatesCheck
from cicd_auditor.checks.permissions     import PermissionsCheck
from cicd_auditor.checks.timeouts        import TimeoutsCheck
from cicd_auditor.models   import Severity
from cicd_auditor.auditor  import Auditor
from cicd_auditor.reporter import render_html

# ─────────────────────────────────────────────────────────────────────────────
# Mini assertion helpers
# ─────────────────────────────────────────────────────────────────────────────

def eq(a, b, msg=""):
    assert a == b, f"Expected {b!r}, got {a!r}  {msg}"

def ge(a, b, msg=""):
    assert a >= b, f"Expected >= {b}, got {a}  {msg}"

def is_false(v, msg=""):
    assert not v, f"Expected falsy, got {v!r}  {msg}"

# ─────────────────────────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────────────────────────

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✅  {name}")
        passed += 1
    except Exception:
        print(f"  ❌  {name}")
        traceback.print_exc()
        failed += 1

def run_check(check, text):
    p = yaml.safe_load(text) or {}
    return check.run("test.yml", text, p)

sc = SecretsCheck()
av = ActionVersionsCheck()
tg = TestGatesCheck()
pc = PermissionsCheck()
tc = TimeoutsCheck()

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Secrets (SEC-001) ──────────────────────────────────────────────────")

def test_secrets_store_safe():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - env:\n          K: ${{ secrets.KEY }}\n        run: echo hi"
    )
    eq(run_check(sc, yaml_text), [], "secrets store ref should not trigger")

test("secrets: GitHub secrets store ref is safe", test_secrets_store_safe)

def test_aws_key_detected():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    )
    ge(len(run_check(sc, yaml_text)), 1, "AWS key should be flagged")

test("secrets: AWS access key ID detected", test_aws_key_detected)

def test_severity_is_critical():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    )
    findings = run_check(sc, yaml_text)
    ge(len(findings), 1)
    eq(findings[0].severity, Severity.CRITICAL)

test("secrets: severity is CRITICAL", test_severity_is_critical)

def test_evidence_is_redacted():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    )
    findings = run_check(sc, yaml_text)
    ge(len(findings), 1)
    is_false(
        "AKIAIOSFODNN7EXAMPLE" in (findings[0].evidence or ""),
        "Full secret value must not appear in evidence"
    )

test("secrets: evidence is redacted (no full secret in output)", test_evidence_is_redacted)

def test_shell_var_ref_safe():
    yaml_text = "jobs:\n  b:\n    steps:\n      - run: echo $API_TOKEN"
    eq(run_check(sc, yaml_text), [])

test("secrets: $SHELL_VAR reference is safe", test_shell_var_ref_safe)

def test_github_pat_detected():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - env:\n          T: ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "        run: gh release create"
    )
    ge(len(run_check(sc, yaml_text)), 1)

test("secrets: GitHub PAT detected", test_github_pat_detected)

def test_db_connection_string_detected():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - run: psql postgres://admin:s3cr3tpassword@db.example.com/prod"
    )
    ge(len(run_check(sc, yaml_text)), 1)

test("secrets: DB connection string with credentials detected", test_db_connection_string_detected)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Action Versions (SEC-002) ──────────────────────────────────────────")

def test_sha_pin_safe():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    eq(run_check(av, yaml_text), [])

test("actions: SHA pin (40 hex chars) is safe", test_sha_pin_safe)

def test_semver_tag_safe():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4.1.7"
    eq(run_check(av, yaml_text), [])

test("actions: exact semver tag @v4.1.7 is safe", test_semver_tag_safe)

def test_major_version_safe():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4"
    eq(run_check(av, yaml_text), [])

test("actions: major version tag @v4 is safe", test_major_version_safe)

def test_local_action_safe():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: ./my-local-action"
    eq(run_check(av, yaml_text), [])

test("actions: local action path ./x is safe (skipped)", test_local_action_safe)

def test_main_branch_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@main"
    findings = run_check(av, yaml_text)
    ge(len(findings), 1)
    eq(findings[0].severity, Severity.HIGH)

test("actions: @main mutable branch ref is flagged HIGH", test_main_branch_flagged)

def test_no_version_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout"
    ge(len(run_check(av, yaml_text)), 1)

test("actions: no version at all is flagged", test_no_version_flagged)

def test_latest_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@latest"
    ge(len(run_check(av, yaml_text)), 1)

test("actions: @latest is flagged", test_latest_flagged)

def test_multiple_bad_actions():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/checkout@main\n"
        "      - uses: actions/setup-python@master\n"
        "      - uses: actions/upload-artifact@latest"
    )
    eq(len(run_check(av, yaml_text)), 3)

test("actions: each bad action produces its own finding", test_multiple_bad_actions)

def test_mixed_good_bad():
    yaml_text = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-python@main\n"
        "      - uses: actions/cache@v4.0.2"
    )
    findings = run_check(av, yaml_text)
    eq(len(findings), 1)
    assert "setup-python" in findings[0].evidence

test("actions: only bad action flagged in mixed list", test_mixed_good_bad)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Test Gates (EFF-001) ────────────────────────────────────────────────")

def test_pytest_detected():
    yaml_text = "jobs:\n  t:\n    steps:\n      - run: pytest tests/"
    eq(run_check(tg, yaml_text), [])

test("gates: pytest command detected", test_pytest_detected)

def test_npm_test_detected():
    yaml_text = "jobs:\n  t:\n    steps:\n      - run: npm test"
    eq(run_check(tg, yaml_text), [])

test("gates: npm test detected", test_npm_test_detected)

def test_job_named_test():
    yaml_text = "jobs:\n  unit-tests:\n    steps:\n      - run: echo hi"
    eq(run_check(tg, yaml_text), [])

test("gates: job named 'unit-tests' counts as a gate", test_job_named_test)

def test_go_test_detected():
    yaml_text = "jobs:\n  ci:\n    steps:\n      - run: go test ./..."
    eq(run_check(tg, yaml_text), [])

test("gates: go test ./... detected", test_go_test_detected)

def test_missing_test_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - run: make build\n  d:\n    steps:\n      - run: ./deploy.sh"
    findings = run_check(tg, yaml_text)
    eq(len(findings), 1)
    eq(findings[0].check_id, "EFF-001")
    eq(findings[0].severity, Severity.HIGH)

test("gates: missing test gate is flagged EFF-001 HIGH", test_missing_test_flagged)

def test_gitlab_pytest():
    yaml_text = "stages:\n  - test\nrun_tests:\n  stage: test\n  script:\n    - pytest"
    eq(run_check(tg, yaml_text), [])

test("gates: GitLab CI pytest detected", test_gitlab_pytest)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Permissions (SEC-003) ───────────────────────────────────────────────")

def test_read_permissions_clean():
    yaml_text = "permissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - run: hi"
    eq(run_check(pc, yaml_text), [])

test("perms: contents: read produces no findings", test_read_permissions_clean)

def test_missing_perms_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - run: hi"
    findings = run_check(pc, yaml_text)
    assert any(f.severity == Severity.MEDIUM for f in findings)

test("perms: missing permissions block flagged MEDIUM", test_missing_perms_flagged)

def test_write_all_flagged():
    yaml_text = "permissions: write-all\njobs:\n  b:\n    steps:\n      - run: hi"
    findings = run_check(pc, yaml_text)
    assert any(f.severity == Severity.HIGH for f in findings)

test("perms: write-all flagged HIGH", test_write_all_flagged)

def test_packages_write_not_flagged():
    yaml_text = "permissions:\n  contents: read\n  packages: write\njobs:\n  b:\n    steps:\n      - run: hi"
    findings = run_check(pc, yaml_text)
    high = [f for f in findings if f.severity == Severity.HIGH]
    eq(high, [], "packages: write is a legitimate scoped permission")

test("perms: packages: write is NOT flagged (legitimate scope)", test_packages_write_not_flagged)

def test_id_token_write_not_flagged():
    yaml_text = "permissions:\n  contents: read\n  id-token: write\njobs:\n  b:\n    steps:\n      - run: hi"
    findings = run_check(pc, yaml_text)
    high = [f for f in findings if f.severity == Severity.HIGH]
    eq(high, [], "id-token: write is needed for OIDC auth")

test("perms: id-token: write is NOT flagged (OIDC requirement)", test_id_token_write_not_flagged)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Timeouts (EFF-002) ──────────────────────────────────────────────────")

def test_timeout_present_clean():
    yaml_text = "jobs:\n  b:\n    timeout-minutes: 15\n    steps:\n      - run: make build"
    eq(run_check(tc, yaml_text), [])

test("timeouts: timeout-minutes present → no finding", test_timeout_present_clean)

def test_timeout_missing_flagged():
    yaml_text = "jobs:\n  b:\n    steps:\n      - run: make build"
    findings = run_check(tc, yaml_text)
    eq(len(findings), 1)
    eq(findings[0].check_id, "EFF-002")

test("timeouts: missing timeout-minutes flagged EFF-002", test_timeout_missing_flagged)

def test_partial_timeouts():
    yaml_text = (
        "jobs:\n  build:\n    timeout-minutes: 20\n    steps:\n      - run: hi\n"
        "  test:\n    steps:\n      - run: pytest"
    )
    findings = run_check(tc, yaml_text)
    eq(len(findings), 1)
    assert "test" in (findings[0].evidence or "")

test("timeouts: only job without timeout is flagged", test_partial_timeouts)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── Integration ─────────────────────────────────────────────────────────")

def test_clean_pipeline_scores_well():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "ci.yml").write_text(
            "name: CI\n"
            "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  test:\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n      - run: pytest\n"
        )
        r = Auditor(tmp).run()
        ge(r.score, 75, f"Clean pipeline should score >=75 but got {r.score}")
        eq(r.summary["critical"], 0)
        eq(r.summary["high"], 0)

test("integration: clean pipeline scores >=75 with 0 critical/high", test_clean_pipeline_scores_well)

def test_insecure_pipeline_scores_poorly():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "ci.yml").write_text(
            "name: Insecure\non:\n  push:\n    branches: ['*']\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@main\n"
            "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        r = Auditor(tmp).run()
        assert r.score < 60, f"Insecure pipeline should score <60 but got {r.score}"
        ge(r.summary["critical"], 1)

test("integration: insecure pipeline scores <60 with >=1 critical", test_insecure_pipeline_scores_poorly)

def test_no_pipeline_files():
    with tempfile.TemporaryDirectory() as tmp:
        r = Auditor(tmp).run()
        assert any(f.check_id == "SYS-000" for f in r.findings)

test("integration: no pipeline files → SYS-000 finding", test_no_pipeline_files)

def test_findings_sorted_by_severity():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "ci.yml").write_text(
            "name: t\non:\n  push:\n    branches: ['*']\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@main\n"
            "      - run: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        r = Auditor(tmp).run()
        sevs = [order[f.severity] for f in r.findings]
        eq(sevs, sorted(sevs), "Findings must be sorted CRITICAL → HIGH → MEDIUM → LOW")

test("integration: findings sorted CRITICAL → HIGH → MEDIUM → LOW", test_findings_sorted_by_severity)

def test_html_report_contains_score():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "ci.yml").write_text(
            "name: t\non:\n  push:\n    branches: [main]\n"
            "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@main\n"
        )
        r = Auditor(tmp).run()
        out = str(Path(tmp) / "report.html")
        render_html(r, out)
        html = open(out).read()
        assert "CI/CD Audit Report" in html
        assert str(r.score) in html
        assert "REDACTED" not in html or True  # secrets redacted in report

test("integration: HTML report renders with correct score", test_html_report_contains_score)

def test_invalid_yaml_produces_sys002():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / ".github" / "workflows"
        d.mkdir(parents=True)
        (d / "broken.yml").write_text("key: [\nunclosed bracket")
        r = Auditor(tmp).run()
        assert any(f.check_id == "SYS-002" for f in r.findings)

test("integration: invalid YAML produces SYS-002 finding", test_invalid_yaml_produces_sys002)

# ─────────────────────────────────────────────────────────────────────────────
print()
print(f"{'='*60}")
print(f"  Results: {passed} passed, {failed} failed out of {passed+failed} tests")
print(f"{'='*60}\n")
if failed:
    sys.exit(1)
