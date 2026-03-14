"""
cicd_auditor
============
CI/CD Pipeline Audit Framework

Public API:
    from cicd_auditor import Auditor, render_html
"""

from .auditor          import Auditor
from .reporter         import render_html
from .models           import AuditReport, Finding, Severity

__version__ = "1.0.0"
__all__     = ["Auditor", "render_html", "AuditReport", "Finding", "Severity"]
