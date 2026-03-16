"""
models.py
---------
Pure data structures for the audit framework.
Using Python dataclasses keeps things lightweight — no ORM, no dependencies.

Design choice: Severity as a plain string enum-like constant rather than Python's
enum.Enum makes JSON serialisation trivial and avoids import boilerplate in checks.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


# ---------------------------------------------------------------------------
# Severity levels — higher weight = more points deducted from the score
# ---------------------------------------------------------------------------
class Severity:
    CRITICAL = "CRITICAL"   # e.g. hardcoded secret in plaintext
    HIGH     = "HIGH"       # e.g. unversioned external action
    MEDIUM   = "MEDIUM"     # e.g. missing timeout on a job
    LOW      = "LOW"        # e.g. missing description comment

    # Points deducted per finding at each severity level
    WEIGHTS = {
        CRITICAL: 25,
        HIGH:     15,
        MEDIUM:    8,
        LOW:       3,
    }


@dataclass
class Finding:
    """
    A single security or efficiency issue found in a pipeline file.

    Attributes
    ----------
    check_id   : Short machine-readable identifier, e.g. "SEC-001"
    title      : Human-readable one-liner, shown in the report table
    severity   : One of Severity.{CRITICAL,HIGH,MEDIUM,LOW}
    file_path  : The pipeline file where the issue was found
    line_number: Line number (1-based) of the offending line, if known
    detail     : Longer explanation of exactly what was found
    remediation: Concrete fix the developer should apply
    evidence   : The offending snippet (redacted for secrets)
    """
    check_id:    str
    title:       str
    severity:    str
    file_path:   str
    detail:      str
    remediation: str
    line_number: int | None = None
    evidence:    str | None = None

    @property
    def weight(self) -> int:
        """Points this finding deducts from the total score."""
        return Severity.WEIGHTS.get(self.severity, 0)


@dataclass
class AuditReport:
    """
    The complete result of auditing one or more pipeline files.

    The score is calculated as:
        score = max(0, 100 - sum(finding.weight for finding in findings))

    A perfect pipeline scores 100.  Each finding deducts points according
    to its severity weight, floored at 0.
    """
    repo_path:    str
    audited_files: list[str]
    findings:     list[Finding] = field(default_factory=list)
    generated_at: datetime      = field(default_factory=lambda: datetime.now(UTC))

    # ------------------------------------------------------------------ #
    #  Computed properties (not stored — always derived from findings)    #
    # ------------------------------------------------------------------ #

    @property
    def score(self) -> int:
        deductions = sum(f.weight for f in self.findings)
        return max(0, 100 - deductions)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    @property
    def grade_label(self) -> str:
        return {
            "A": "Excellent",
            "B": "Good",
            "C": "Needs Improvement",
            "D": "Poor",
            "F": "Critical Risk",
        }[self.grade]

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def summary(self) -> dict:
        return {
            "total":    len(self.findings),
            "critical": len(self.findings_by_severity(Severity.CRITICAL)),
            "high":     len(self.findings_by_severity(Severity.HIGH)),
            "medium":   len(self.findings_by_severity(Severity.MEDIUM)),
            "low":      len(self.findings_by_severity(Severity.LOW)),
        }
